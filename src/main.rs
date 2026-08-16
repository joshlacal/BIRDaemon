mod bot;
mod bridge_client;
mod config;
mod credentials;
mod keychain;
mod llm;
mod storage;
mod websocket;
mod xrpc_client;

use std::sync::Arc;
use tracing_subscriber::EnvFilter;

use crate::bot::BirdBot;
use crate::bridge_client::BridgeClient;
use crate::config::{data_dir, load_config, load_secrets};
use crate::credentials::FileCredentialStore;
use crate::keychain::FileKeychain;
use crate::storage::SqliteStorage;
use crate::xrpc_client::BirdApiClient;

use catbird_mls::orchestrator::credentials::CredentialStore;
use catbird_mls::orchestrator::{MLSOrchestrator, OrchestratorConfig};
use catbird_mls::MLSContext;

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

    // Create API client — uses jacquard session for token lifecycle. The
    // daemon has no platform-owned DPoP key/JKT or auth-generation source, so
    // canonical clean-chat reads and sends remain explicitly unavailable
    // instead of silently using legacy bearer-only clean-chat endpoints.
    let api_client = Arc::new(BirdApiClient::new(
        pds_endpoint.clone(),
        session,
        did.clone(),
        config.handle.clone(),
        secrets.app_password.clone(),
    ));
    tracing::warn!(
        "Canonical clean-chat transport unavailable: daemon lacks device-bound DPoP/JKT authority"
    );

    // Create data directory paths
    let data_dir = data_dir();
    std::fs::create_dir_all(&data_dir)?;

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

    // Create credential store
    let creds_path = data_dir.join("credentials.json");
    let credentials = Arc::new(FileCredentialStore::new(creds_path));

    // Create orchestrator
    let credentials_ref = credentials.clone();
    let orchestrator = Arc::new(MLSOrchestrator::new(
        mls_context,
        storage,
        api_client.clone(),
        credentials,
        OrchestratorConfig::default(),
    ));

    // Initialize orchestrator with user DID
    tracing::info!("Initializing MLS orchestrator...");
    orchestrator
        .initialize(&did)
        .await
        .map_err(|e| anyhow::anyhow!("Orchestrator init failed: {}", e))?;
    tracing::info!("Orchestrator initialized");

    // Clean up old devices if at limit, then register
    tracing::info!("Registering device with MLS delivery service...");
    match orchestrator.ensure_device_registered().await {
        Ok(mls_did) => tracing::info!(mls_did = %mls_did, "Device registered"),
        Err(e) => {
            tracing::warn!("Device registration failed: {}, attempting cleanup...", e);
            // If device limit reached, remove oldest devices and retry
            if let Ok(devices) = orchestrator.list_devices().await {
                tracing::info!(
                    "Found {} registered devices, removing old ones",
                    devices.len()
                );
                // Remove all devices to make room (they're from previous runs)
                for dev in &devices {
                    if let Err(e) = orchestrator.remove_device(&dev.device_id).await {
                        tracing::warn!("Failed to remove device {}: {}", dev.device_id, e);
                    } else {
                        tracing::info!("Removed device {}", dev.device_id);
                    }
                }
                // Retry registration
                match orchestrator.ensure_device_registered().await {
                    Ok(mls_did) => {
                        tracing::info!(mls_did = %mls_did, "Device registered after cleanup")
                    }
                    Err(e2) => {
                        tracing::error!("Device registration still failed after cleanup: {}", e2)
                    }
                }
            }
        }
    }

    // Publish device record to ATProto repo so other clients can verify our key packages.
    // This writes a blue.catbird.mlsChat.device record containing our signature public key.
    // Without this, Catbird iOS rejects our key packages as unauthorized.
    tracing::info!("Ensuring device record is published to ATProto repo...");
    if let Ok(Some(sig_key)) = credentials_ref.get_signing_key(&did).await {
        match api_client.ensure_device_record_published(&sig_key).await {
            Ok(()) => tracing::info!("Device record OK"),
            Err(e) => tracing::warn!("Device record publish failed (non-fatal): {}", e),
        }
    } else {
        tracing::warn!("No signing key in credential store — skipping device record publish");
    }

    // Publish key packages so we can be added to groups via Welcome messages
    tracing::info!("Checking key package levels...");
    match orchestrator.replenish_if_needed().await {
        Ok(()) => tracing::info!("Key packages OK"),
        Err(e) => tracing::warn!("Key package replenishment failed (non-fatal): {}", e),
    }

    // Create bridge client (routes messages to mls-chat-channel for Claude Code)
    let llm_client = BridgeClient::new("http://127.0.0.1:8789");

    // Create and run bot
    let bot = BirdBot::new(did, api_client, orchestrator, llm_client, config);
    bot.run().await?;

    Ok(())
}
