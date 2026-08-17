mod bot;
mod bridge_client;
mod chat_authority;
mod config;
mod credentials;
mod keychain;
mod llm;
mod storage;
mod websocket;
mod xrpc_client;

use std::sync::Arc;
use tracing_subscriber::EnvFilter;

use crate::chat_authority::{AuthorityError, AuthoritySnapshot, AuthorityState, NestClient};
use crate::config::{data_dir, load_config, load_secrets};
use crate::credentials::FileCredentialStore;
use crate::keychain::FileKeychain;
use crate::storage::SqliteStorage;
use crate::xrpc_client::BirdApiClient;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use catbird_mls::orchestrator::credentials::CredentialStore;
use catbird_mls::orchestrator::{
    CanonicalOperation, CleanChatSigningContext, MLSOrchestrator, OrchestratorConfig,
};
use catbird_mls::MLSContext;
use chrono::{SecondsFormat, Utc};
use serde_json::json;
use sha2::Digest as _;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Init tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    tracing::info!("BIRD Daemon starting...");

    // Load config
    let config = load_config()?;
    let secrets = load_secrets()?;
    tracing::info!("Handle: {}", config.handle);
    tracing::info!("LLM: {} at {}", config.llm_model, config.llm_base_url);

    // Authenticate with Bluesky via jacquard (legacy app password)
    tracing::info!("Authenticating as {}...", config.handle);

    let (session, atp_session) = jacquard::client::MemoryCredentialSession::authenticated(
        jacquard_common::CowStr::from(config.handle.clone()),
        jacquard_common::CowStr::from(secrets.app_password.clone()),
        None,
        None,
    )
    .await
    .map_err(|e| anyhow::anyhow!("Authentication failed: {}", e))?;

    let did = atp_session.did.to_string();
    let pds_endpoint = session.endpoint().await.to_string();
    let session = Arc::new(session);

    tracing::info!("Authenticated! DID: {}", did);
    tracing::info!("PDS endpoint: {}", pds_endpoint);

    let data_dir = data_dir();
    std::fs::create_dir_all(&data_dir)?;
    let creds_path = data_dir.join("credentials.json");
    let credentials = Arc::new(FileCredentialStore::new(creds_path));

    // The Jacquard session remains available for legacy non-chat identity
    // resolution only. Clean-chat calls are wired to the opaque Nest session
    // below and never use this bearer.
    let invalidation_credentials = credentials.clone();
    let invalidation_did = did.clone();
    let authority_state = Arc::new(AuthorityState::with_invalidation_hook(Arc::new(
        move || {
            invalidation_credentials
                .clear_clean_chat_authority(&invalidation_did)
                .map_err(|_| AuthorityError::Unavailable)
        },
    )));
    let nest = match std::env::var("BIRD_NEST_BASE_URL") {
        Ok(base_url) => {
            Some(Arc::new(NestClient::new(&base_url).map_err(|_| {
                anyhow::anyhow!("BIRD_NEST_BASE_URL is invalid")
            })?))
        }
        Err(_) => None,
    };
    let api_client = BirdApiClient::new(
        pds_endpoint.clone(),
        session,
        did.clone(),
        config.handle.clone(),
        secrets.app_password.clone(),
    );
    let api_client = if let Some(nest) = &nest {
        Arc::new(api_client.with_chat_authority(nest.clone(), authority_state.clone()))
    } else {
        Arc::new(api_client)
    };

    // Create MLS state directory
    let mls_state_dir = data_dir.join("mls-state");
    std::fs::create_dir_all(&mls_state_dir)?;

    // Create keychain
    let keychain_path = data_dir.join("keychain.json");
    let keychain = FileKeychain::new(keychain_path);

    // Create MLS crypto context
    // Use a sanitized DID for the database filename (replace : and . with _)
    let did_sanitized = did.replace(':', "_").replace('.', "_");
    let mls_db_path = mls_state_dir.join(format!("{}.db", did_sanitized));
    // Use app password as encryption key (it's already a secret)
    let mls_context = MLSContext::new(
        mls_db_path.to_string_lossy().to_string(),
        secrets.app_password.clone(),
        Box::new(keychain),
    )
    .map_err(|e| anyhow::anyhow!("Failed to create MLS context: {}", e))?;

    // Create storage backend
    let storage_db_path = data_dir.join("bird.db");
    let storage = Arc::new(SqliteStorage::new(storage_db_path)?);

    // Create orchestrator
    let orchestrator = Arc::new(MLSOrchestrator::new(
        mls_context,
        storage,
        api_client.clone(),
        credentials.clone(),
        OrchestratorConfig::default(),
    ));

    // Initialize orchestrator with user DID
    tracing::info!("Initializing MLS orchestrator...");
    orchestrator
        .initialize(&did)
        .await
        .map_err(|e| anyhow::anyhow!("Orchestrator init failed: {}", e))?;
    tracing::info!("Orchestrator initialized");

    let Some(nest) = nest else {
        tracing::warn!(
            "Clean-chat authority disabled: BIRD_NEST_BASE_URL is not configured; chat bot loop will not start"
        );
        return Ok(());
    };
    match establish_or_restore_authority(
        nest,
        authority_state,
        &did,
        &config.handle,
        &orchestrator,
        &credentials,
    )
    .await
    {
        Ok(()) => tracing::info!(
            "Clean-chat authority established; Task 4 leaves the chat bot loop disabled until Task 10"
        ),
        Err(error) => tracing::warn!(
            error = %error,
            "Clean-chat authority unavailable; chat bot loop disabled"
        ),
    }

    Ok(())
}

type BirdOrchestrator =
    MLSOrchestrator<SqliteStorage, BirdApiClient, FileCredentialStore, MLSContext>;

/// Restore only a protected opaque Nest session after restart, and admit it
/// only after both `/auth/session` and `getOwnDevices` prove the exact tuple.
/// Any mismatch clears the local authority and starts a fresh purpose-bound
/// browser enrollment; it never falls back to Jacquard bearer auth.
async fn establish_or_restore_authority(
    nest: Arc<NestClient>,
    authority_state: Arc<AuthorityState>,
    did: &str,
    handle: &str,
    orchestrator: &Arc<BirdOrchestrator>,
    credentials: &Arc<FileCredentialStore>,
) -> anyhow::Result<()> {
    if let (Some(session), Some((device_id, dpop_jkt, Some(generation)))) = (
        credentials.get_opaque_chat_session(did)?,
        credentials.get_clean_chat_binding(did)?,
    ) {
        if let Ok(snapshot) = admit_existing_session(
            &nest,
            &session,
            did,
            &device_id,
            &dpop_jkt,
            generation,
            credentials,
        )
        .await
        {
            authority_state.install(snapshot);
            return Ok(());
        }
        credentials.delete_opaque_chat_session(did)?;
        credentials.clear_clean_chat_binding(did)?;
    }

    let session = nest
        .establish_session(handle)
        .await
        .map_err(|_| anyhow::anyhow!("purpose-bound Nest browser enrollment failed"))?;
    let session_info = nest
        .session_info(&session)
        .await
        .map_err(|_| anyhow::anyhow!("Nest session admission failed"))?;
    if session_info.did != did {
        return Err(anyhow::anyhow!(
            "Nest browser account does not match daemon DID"
        ));
    }

    // The v2 device identifier is fresh for every enrollment attempt. It is
    // never read from or reused from the legacy mlsChat credential map.
    let device_id = uuid::Uuid::new_v4().to_string();
    let key_package = orchestrator
        .mls_context()
        .create_key_package(did.as_bytes().to_vec())
        .map_err(|e| anyhow::anyhow!("failed to create v2 key package: {e}"))?;
    if credentials.get_signing_key(did).await?.is_none() {
        let key_data = orchestrator
            .mls_context()
            .export_identity_key(did.to_owned())
            .map_err(|e| anyhow::anyhow!("failed to export existing signer material: {e}"))?;
        credentials.store_signing_key(did, &key_data).await?;
    }
    let signer_handle = crate::chat_authority::derive_key_id(&key_package.signature_public_key);
    let dpop_jkt = nest
        .preflight(&session, &device_id)
        .await
        .map_err(|_| anyhow::anyhow!("Nest device-key preflight failed"))?;
    credentials.set_clean_chat_binding(did, &device_id, &dpop_jkt, None)?;

    let enrollment_body = enrollment_body(did, &device_id, &dpop_jkt, &signer_handle, &key_package);
    let prepared = orchestrator
        .prepare_clean_chat_signed_request(
            CleanChatSigningContext {
                actor_did: did.to_owned(),
                device_id: device_id.clone(),
                dpop_jkt: dpop_jkt.clone(),
                auth_generation: None,
            },
            CanonicalOperation::EnrollDevice,
            enrollment_body,
        )
        .await
        .map_err(|_| anyhow::anyhow!("Task 1 refused the v2 enrollment transcript"))?;
    if !prepared.authorization.is_empty() || !prepared.dpop.is_empty() {
        return Err(anyhow::anyhow!(
            "signed enrollment unexpectedly exported downstream authentication material"
        ));
    }
    let body = prepared
        .body
        .ok_or_else(|| anyhow::anyhow!("Task 1 returned an empty enrollment body"))?;
    nest.post_signed_enrollment(&session, &device_id, body, &dpop_jkt)
        .await
        .map_err(|_| anyhow::anyhow!("Nest rejected the v2 device enrollment"))?;

    let devices = nest
        .own_devices(&session, &device_id, Some(&dpop_jkt))
        .await
        .map_err(|_| anyhow::anyhow!("Nest getOwnDevices admission failed"))?;
    let admitted = AuthoritySnapshot::admit(
        session,
        &session_info,
        did,
        &devices,
        &device_id,
        &dpop_jkt,
        devices
            .iter()
            .find(|device| device.device_id == device_id)
            .map(|device| device.auth_generation)
            .ok_or_else(|| anyhow::anyhow!("Nest did not return the newly enrolled device"))?,
        signer_handle,
        &key_package.signature_public_key,
        1,
    )
    .map_err(|_| anyhow::anyhow!("Nest device tuple could not be admitted"))?;
    credentials.set_clean_chat_binding(
        did,
        admitted.device_id(),
        admitted.dpop_jkt(),
        Some(admitted.auth_generation()),
    )?;
    credentials.store_opaque_chat_session(did, admitted.session_handle())?;
    authority_state.install(admitted);
    Ok(())
}

async fn admit_existing_session(
    nest: &NestClient,
    session: &str,
    did: &str,
    device_id: &str,
    dpop_jkt: &str,
    generation: i64,
    credentials: &Arc<FileCredentialStore>,
) -> Result<AuthoritySnapshot, AuthorityError> {
    let session_info = nest.session_info(session).await?;
    let devices = nest.own_devices(session, device_id, Some(dpop_jkt)).await?;
    let signer = credentials
        .get_signing_key(did)
        .await
        .map_err(|_| AuthorityError::Unavailable)?
        .and_then(|key| {
            serde_json::from_slice::<openmls_basic_credential::SignatureKeyPair>(&key).ok()
        })
        .ok_or(AuthorityError::Unavailable)?;
    let signer_handle = crate::chat_authority::derive_key_id(signer.public());
    let signer_public_key = signer.public().to_vec();
    AuthoritySnapshot::admit(
        session.to_owned(),
        &session_info,
        did,
        &devices,
        device_id,
        dpop_jkt,
        generation,
        signer_handle,
        &signer_public_key,
        1,
    )
}

fn enrollment_body(
    did: &str,
    device_id: &str,
    dpop_jkt: &str,
    signer_handle: &str,
    key_package: &catbird_mls::KeyPackageResult,
) -> Vec<u8> {
    let package_sha256 = sha2::Sha256::digest(&key_package.key_package_data);
    let body = json!({
        "$type": "blue.catbird.chat.defs#deviceEnrollmentBody",
        "signatureDomain": "CATBIRD-CHAT-DEVICE-ENROLL\u{0000}",
        "actorDid": did,
        "deviceId": device_id,
        "deviceName": "BIRDaemon",
        "keyId": signer_handle,
        "signaturePublicKey": {"$bytes": B64.encode(&key_package.signature_public_key)},
        "dpopJkt": dpop_jkt,
        "expectedAuthGeneration": 0,
        "capability": {
            "protocolVersion": "1",
            "mlsVersion": "1.0",
            "cipherSuite": "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519",
            "credentialType": "basic",
            "addByValue": "supported",
            "updatePath": "supported",
            "removeByValue": "supported",
            "ratchetTreeGroupInfo": "supported",
            "externalPubGroupInfo": "presentButExternalCommitsForbidden",
            "applicationFrameProfile": "dagCborApplication1",
            "controlProfile": "publicGroup1",
            "attachmentProfile": "aes256GcmBlob1",
            "metadataProfile": "exporterAes256Gcm1",
            "typingProfile": "signedClearEphemeral1"
        },
        "keyPackages": [{
            "framing": "mlsMessage",
            "contentType": "keyPackage",
            "bytes": {"$bytes": B64.encode(&key_package.key_package_data)},
            "sha256": {"$bytes": B64.encode(package_sha256)},
            "keyPackageRef": {"$bytes": B64.encode(&key_package.hash_ref)}
        }],
        "idempotencyKey": uuid::Uuid::new_v4().to_string(),
        "signedAt": Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
    });
    serde_json::to_vec(&body).expect("enrollment body serialization cannot fail")
}
