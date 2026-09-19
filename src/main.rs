mod bot;
mod bridge_client;
mod chat_authority;
mod config;
mod credentials;
mod keychain;
mod request_policy;

mod storage;
mod websocket;
mod xrpc_client;

#[cfg(test)]
mod canonical_runtime_tests;

use std::sync::Arc;
use tracing_subscriber::EnvFilter;

use crate::chat_authority::{AuthorityError, AuthoritySnapshot, AuthorityState, NestClient};
use crate::config::{data_dir, load_config, load_secrets};
use crate::credentials::{FileCredentialStore, PendingEnrollment};
use crate::keychain::FileKeychain;
use crate::storage::SqliteStorage;
use crate::xrpc_client::BirdApiClient;

use catbird_atproto::blue_catbird::chat::{
    enroll_device::EnrollDeviceOutput, DeviceCapability, DeviceEnrollmentBody, KeyPackageArtifact,
};
use catbird_mls::orchestrator::credentials::CredentialStore;
use catbird_mls::orchestrator::{
    CanonicalOperation, CleanChatSigningContext, MLSOrchestrator, OrchestratorConfig,
};
use catbird_mls::MLSContext;
use chrono::{SecondsFormat, Utc};
use sha2::Digest as _;
use std::str::FromStr;

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
        &config.handle,
        &secrets.app_password,
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
    let credentials = Arc::new(
        FileCredentialStore::new(creds_path)
            .map_err(|e| anyhow::anyhow!("Failed to open MLS credentials: {e}"))?,
    );

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
        Arc::new(api_client.with_chat_authority(
            nest.clone(),
            authority_state.clone(),
            credentials.clone(),
        ))
    } else {
        Arc::new(api_client)
    };

    // Create MLS state directory
    let mls_state_dir = data_dir.join("mls-state");
    std::fs::create_dir_all(&mls_state_dir)?;

    // Create keychain
    let keychain_path = data_dir.join("keychain.json");
    let keychain = FileKeychain::new(keychain_path)
        .map_err(|e| anyhow::anyhow!("Failed to open MLS keychain: {e}"))?;
    let epoch_secret_storage = keychain
        .with_epoch_secret_owner(&did)
        .map_err(|e| anyhow::anyhow!("Failed to scope MLS epoch-secret storage: {e}"))?;

    // Create MLS crypto context
    // Use a sanitized DID for the database filename (replace : and . with _)
    let did_sanitized = did.replace([':', '.'], "_");
    let mls_db_path = mls_state_dir.join(format!("{}.db", did_sanitized));
    let mls_db_key =
        get_or_create_mls_db_key(&mls_state_dir, &did_sanitized, &secrets.app_password)?;
    let mls_context = MLSContext::new(
        mls_db_path.to_string_lossy().to_string(),
        mls_db_key,
        Box::new(keychain),
    )
    .map_err(|e| anyhow::anyhow!("Failed to create MLS context: {}", e))?;
    mls_context
        .set_epoch_secret_storage(Box::new(epoch_secret_storage))
        .map_err(|e| anyhow::anyhow!("Failed to install MLS epoch-secret storage: {e}"))?;

    // Create storage backend
    let storage_db_path = data_dir.join("bird.db");
    let storage = Arc::new(SqliteStorage::new(storage_db_path, did.clone())?);

    // Create orchestrator
    let orchestrator = Arc::new(MLSOrchestrator::new(
        mls_context,
        storage,
        api_client.clone(),
        credentials.clone(),
        OrchestratorConfig::default(),
    ));
    api_client.set_signer(orchestrator.clone());

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
        Ok(()) => {
            tracing::info!("Clean-chat authority established; starting BIRD bot loop");
            let llm = crate::bridge_client::BridgeClient::new("http://127.0.0.1:8789");
            let bot = crate::bot::BirdBot::new(
                did.clone(),
                api_client.clone(),
                orchestrator.clone(),
                llm,
                config.clone(),
            );
            bot.run().await?;
        }
        Err(error) => tracing::warn!(
            error = %error,
            "Clean-chat authority unavailable; chat bot loop disabled"
        ),
    }

    Ok(())
}

fn get_or_create_mls_db_key(
    dir: &std::path::Path,
    did_sanitized: &str,
    fallback_app_password: &str,
) -> anyhow::Result<String> {
    let key_path = dir.join(format!("{}.key", did_sanitized));
    let db_path = dir.join(format!("{}.db", did_sanitized));
    if key_path.exists() {
        let key = std::fs::read_to_string(&key_path)?;
        let trimmed = key.trim().to_string();
        if !trimmed.is_empty() {
            return Ok(trimmed);
        }
    }
    // Backward compatibility: if the database existed before independent keying, reuse the app password
    let hex_key = if db_path.exists() {
        fallback_app_password.to_string()
    } else {
        use rand::RngCore;
        let mut raw = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut raw);
        hex::encode(raw)
    };
    let tmp = key_path.with_extension("key.tmp");
    std::fs::write(&tmp, &hex_key)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    }
    std::fs::rename(&tmp, &key_path)?;
    Ok(hex_key)
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
    let persisted_session = credentials.get_opaque_chat_session(did)?;
    let persisted_tuple = credentials.get_admitted_device_tuple(did);
    let pending_enrollment = credentials.get_pending_enrollment(did);
    if let (Some(session), Ok(Some(tuple)), Ok(None)) =
        (&persisted_session, &persisted_tuple, &pending_enrollment)
    {
        if let Ok(snapshot) = admit_existing_session(
            &nest,
            session,
            did,
            &tuple.device_uuid,
            tuple.auth_generation,
            credentials,
        )
        .await
        {
            authority_state.install(snapshot);
            prepare_admitted_device_runtime(orchestrator, credentials, did).await?;
            return Ok(());
        }
    }
    if let (Some(session), Ok(None), Ok(Some(pending))) =
        (&persisted_session, &persisted_tuple, &pending_enrollment)
    {
        if pending.prepared_body.is_some() {
            let snapshot =
                reconcile_pending_enrollment(&nest, session, did, pending, credentials).await?;
            authority_state.install(snapshot);
            prepare_admitted_device_runtime(orchestrator, credentials, did).await?;
            return Ok(());
        }
    }
    if persisted_session.is_some()
        || !matches!(persisted_tuple, Ok(None))
        || !matches!(pending_enrollment, Ok(None))
    {
        // A session without one complete admitted tuple (or vice versa) has no
        // authority after restart. Clear both halves before a new enrollment.
        credentials.clear_clean_chat_authority(did)?;
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
    credentials.store_opaque_chat_session(did, &session)?;

    // The v2 device identifier is fresh for every enrollment attempt. It is
    // never read from or reused from the legacy mlsChat credential map.
    let device_id = uuid::Uuid::new_v4().to_string();
    let mls_did = format!("{did}#{device_id}");
    let key_package = orchestrator
        .mls_context()
        .create_key_package(mls_did.as_bytes().to_vec())
        .map_err(|e| anyhow::anyhow!("failed to create v2 key package: {e}"))?;
    let key_data = orchestrator
        .mls_context()
        .export_identity_key(mls_did.clone())
        .map_err(|e| anyhow::anyhow!("failed to export device-scoped signer material: {e}"))?;
    credentials.store_signing_key(did, &key_data).await?;
    let signer_handle = crate::chat_authority::derive_key_id(&key_package.signature_public_key);
    let idempotency_key = uuid::Uuid::new_v4().to_string();
    credentials.begin_pending_enrollment(did, &device_id, &mls_did, &idempotency_key)?;

    let enrollment_body = enrollment_body(
        did,
        &device_id,
        &signer_handle,
        &idempotency_key,
        &key_package,
    )?;
    let prepared = orchestrator
        .prepare_clean_chat_signed_request(
            CleanChatSigningContext {
                actor_did: did.to_owned(),
                device_id: device_id.clone(),
                auth_generation: None,
            },
            CanonicalOperation::EnrollDevice,
            enrollment_body,
        )
        .await
        .map_err(|_| anyhow::anyhow!("Task 1 refused the v2 enrollment transcript"))?;
    if prepared.operation != CanonicalOperation::EnrollDevice
        || prepared.method != "POST"
        || prepared.path != CanonicalOperation::EnrollDevice.path()
    {
        return Err(anyhow::anyhow!(
            "Task 1 returned a noncanonical enrollment request target"
        ));
    }
    let body = prepared
        .body
        .ok_or_else(|| anyhow::anyhow!("Task 1 returned an empty enrollment body"))?;
    let typed: catbird_atproto::blue_catbird::chat::enroll_device::EnrollDevice<String> =
        serde_json::from_slice(&body).map_err(|error| {
            anyhow::anyhow!("prepared enrollment is not generated DTO JSON: {error}")
        })?;
    if typed.signed_request.body.idempotency_key.as_str() != idempotency_key
        || typed.signed_request.body.actor_did.as_str() != did
        || typed.signed_request.body.device_id.as_str() != device_id
    {
        return Err(anyhow::anyhow!(
            "prepared enrollment escaped its durable account/device/idempotency binding"
        ));
    }
    credentials.finalize_pending_enrollment(did, &idempotency_key, &body)?;
    let pending = credentials
        .get_pending_enrollment(did)?
        .ok_or_else(|| anyhow::anyhow!("pending enrollment disappeared before submission"))?;
    let admitted =
        reconcile_pending_enrollment(&nest, &session, did, &pending, credentials).await?;
    authority_state.install(admitted);
    prepare_admitted_device_runtime(orchestrator, credentials, did).await?;
    Ok(())
}

async fn prepare_admitted_device_runtime(
    orchestrator: &Arc<BirdOrchestrator>,
    credentials: &Arc<FileCredentialStore>,
    did: &str,
) -> anyhow::Result<()> {
    let admitted = credentials
        .get_admitted_device_tuple(did)?
        .ok_or_else(|| anyhow::anyhow!("admitted clean-chat device tuple disappeared"))?;
    let orchestrator_identity = orchestrator
        .ensure_device_registered()
        .await
        .map_err(|error| anyhow::anyhow!("admitted MLS device readiness failed: {error}"))?;
    if orchestrator_identity != admitted.mls_did {
        return Err(anyhow::anyhow!(
            "shared orchestrator selected a different MLS device identity"
        ));
    }
    orchestrator
        .replenish_if_needed()
        .await
        .map_err(|error| anyhow::anyhow!("device-scoped key-package replenishment failed: {error}"))
}

pub(crate) async fn admit_existing_session(
    nest: &NestClient,
    session: &str,
    did: &str,
    device_id: &str,
    generation: i64,
    credentials: &Arc<FileCredentialStore>,
) -> Result<AuthoritySnapshot, AuthorityError> {
    let session_info = nest.session_info(session).await?;
    let devices = nest.own_devices(session, device_id).await?;
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
        generation,
        signer_handle,
        &signer_public_key,
        1,
    )
}

async fn reconcile_pending_enrollment(
    nest: &NestClient,
    session: &str,
    did: &str,
    pending: &PendingEnrollment,
    credentials: &Arc<FileCredentialStore>,
) -> anyhow::Result<AuthoritySnapshot> {
    let body = pending
        .prepared_body
        .clone()
        .ok_or_else(|| anyhow::anyhow!("pending enrollment has no prepared request bytes"))?;
    let response = nest
        .post_signed_enrollment(session, &pending.device_uuid, body)
        .await
        .map_err(|error| anyhow::anyhow!("Nest enrollment transport failed: {error}"))?;
    if !(200..300).contains(&response.status) {
        return Err(anyhow::anyhow!(
            "Nest enrollment returned HTTP {}: {}",
            response.status,
            String::from_utf8_lossy(&response.body)
        ));
    }
    if response
        .content_type
        .as_deref()
        .is_some_and(|content_type| {
            !content_type
                .to_ascii_lowercase()
                .starts_with("application/json")
        })
    {
        return Err(anyhow::anyhow!(
            "Nest enrollment returned non-JSON content type"
        ));
    }
    let output: EnrollDeviceOutput<String> = serde_json::from_slice(&response.body)
        .map_err(|error| anyhow::anyhow!("Nest enrollment response is invalid: {error}"))?;
    if output.device.device_id.as_str() != pending.device_uuid
        || output.device.auth_generation < 1
        || output.device.status.as_str() != "active"
    {
        return Err(anyhow::anyhow!(
            "Nest enrollment response does not admit the pending device"
        ));
    }

    let session_info = nest
        .session_info(session)
        .await
        .map_err(|error| anyhow::anyhow!("Nest session reconciliation failed: {error}"))?;
    let devices = nest
        .own_devices(session, &pending.device_uuid)
        .await
        .map_err(|error| anyhow::anyhow!("Nest getOwnDevices reconciliation failed: {error}"))?;
    let signer = credentials
        .get_signing_key(did)
        .await?
        .and_then(|key| {
            serde_json::from_slice::<openmls_basic_credential::SignatureKeyPair>(&key).ok()
        })
        .ok_or_else(|| anyhow::anyhow!("pending enrollment signer is unavailable"))?;
    let signer_handle = crate::chat_authority::derive_key_id(signer.public());
    let signer_public_key = signer.public().to_vec();
    if output.device.key_id.as_str() != signer_handle
        || output.device.signature_public_key.as_ref() != signer_public_key
    {
        return Err(anyhow::anyhow!(
            "Nest enrollment response signer does not match the pending identity"
        ));
    }
    let admitted = AuthoritySnapshot::admit(
        session.to_owned(),
        &session_info,
        did,
        &devices,
        &pending.device_uuid,
        output.device.auth_generation,
        signer_handle,
        &signer_public_key,
        1,
    )
    .map_err(|error| anyhow::anyhow!("Nest device tuple could not be admitted: {error}"))?;
    credentials.install_admitted_device_tuple(
        did,
        admitted.device_id(),
        &pending.mls_did,
        admitted.auth_generation(),
    )?;
    Ok(admitted)
}

fn enrollment_body(
    did: &str,
    device_id: &str,
    signer_handle: &str,
    idempotency_key: &str,
    key_package: &catbird_mls::KeyPackageResult,
) -> anyhow::Result<Vec<u8>> {
    let package_sha256 = sha2::Sha256::digest(&key_package.key_package_data);
    let signed_at = catbird_atproto::blue_catbird::chat::CanonicalDatetime::from_str(
        &Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
    )
    .map_err(|error| anyhow::anyhow!("failed to construct canonical enrollment time: {error}"))?;
    let body = DeviceEnrollmentBody::<String> {
        actor_did: catbird_atproto::types::string::Did::<String>::new(did.to_owned())
            .map_err(|error| anyhow::anyhow!("invalid enrollment actor DID: {error}"))?,
        capability: DeviceCapability {
            direct_request_profile: Some("encryptedIntroduction1".into()),
            add_by_value: "supported".into(),
            application_frame_profile: "dagCborApplication1".into(),
            attachment_profile: "aes256GcmBlob1".into(),
            cipher_suite: "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519".into(),
            control_profile: "publicGroup1".into(),
            credential_type: "basic".into(),
            external_pub_group_info: "presentButExternalCommitsForbidden".into(),
            metadata_profile: "exporterAes256Gcm1".into(),
            mls_version: "1.0".into(),
            protocol_version: "1".into(),
            ratchet_tree_group_info: "supported".into(),
            remove_by_value: "supported".into(),
            typing_profile: "signedClearEphemeral1".into(),
            update_path: "supported".into(),
            extra_data: None,
        },
        device_id: device_id.to_owned(),
        device_name: "BIRDaemon".into(),
        expected_auth_generation: 0,
        idempotency_key: idempotency_key.to_owned(),
        key_id: signer_handle.to_owned(),
        key_packages: vec![KeyPackageArtifact {
            bytes: key_package.key_package_data.clone().into(),
            content_type: "keyPackage".into(),
            framing: "mlsMessage".into(),
            key_package_ref: key_package.hash_ref.clone().into(),
            sha256: package_sha256.to_vec().into(),
            extra_data: None,
        }],
        signature_domain: "CATBIRD-CHAT-DEVICE-ENROLL\0".into(),
        signature_public_key: key_package.signature_public_key.clone().into(),
        signed_at,
        extra_data: None,
    };
    serde_json::to_vec(&body)
        .map_err(|error| anyhow::anyhow!("failed to serialize generated enrollment DTO: {error}"))
}
