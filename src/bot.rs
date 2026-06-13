//! Bot logic: ties together MLS orchestrator, WebSocket, LLM client, and event loop.

use base64::Engine;
use chrono::Utc;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::Instant;

use catbird_mls::blob_crypto::decrypt_blob;
use catbird_mls::orchestrator::{IncomingEnvelope, MLSOrchestrator, MLSStorageBackend};
use catbird_mls::MLSContext;

use crate::bridge_client::BridgeClient;
use crate::config::BirdConfig;
use crate::credentials::FileCredentialStore;
use crate::storage::SqliteStorage;
use crate::websocket::{MlsEvent, MlsWebSocket};
use crate::xrpc_client::BirdApiClient;
use tokio::sync::Notify;

/// Type alias for our concrete orchestrator (generic params: S, A, C).
type BirdOrchestrator =
    MLSOrchestrator<SqliteStorage, BirdApiClient, FileCredentialStore, MLSContext>;

/// Cooldown period after a rejoin before allowing another rejoin for the same conversation.
/// This prevents infinite rejoin loops when the sender hasn't caught up yet.
const REJOIN_COOLDOWN: std::time::Duration = std::time::Duration::from_secs(60);

/// Number of past epochs OpenMLS retains keys for (matches GroupConfig::default().max_past_epochs).
/// Messages within this window can still be decrypted even if the sender is behind.
const MAX_PAST_EPOCHS: u64 = 5;

/// The BIRD bot daemon.
pub struct BirdBot {
    did: String,
    api_client: Arc<BirdApiClient>,
    orchestrator: Arc<BirdOrchestrator>,
    llm: Arc<BridgeClient>,
    config: BirdConfig,
    /// Tracks when we last rejoined each conversation to prevent rejoin storms.
    recent_rejoins: Arc<Mutex<HashMap<String, Instant>>>,
}

impl BirdBot {
    pub fn new(
        did: String,
        api_client: Arc<BirdApiClient>,
        orchestrator: Arc<BirdOrchestrator>,
        llm: BridgeClient,
        config: BirdConfig,
    ) -> Self {
        Self {
            did,
            api_client,
            orchestrator,
            llm: Arc::new(llm),
            config,
            recent_rejoins: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Run the main event loop.
    ///
    /// Subscribes to WebSocket events, decrypts incoming messages via the MLS
    /// orchestrator, generates LLM responses, and encrypts + sends replies.
    pub async fn run(&self) -> anyhow::Result<()> {
        tracing::info!("BIRD bot starting for DID: {}", self.did);

        // Initial sync to catch up on any missed state
        tracing::info!("Running initial sync with server...");
        if let Err(e) = self.orchestrator.sync_with_server(true).await {
            tracing::warn!("Initial sync failed (non-fatal): {}", e);
        }

        // Log epoch gaps for observability. We do NOT proactively rejoin here —
        // External Commits advance the group epoch, pushing the bot ahead of other
        // participants who haven't processed the commit yet. Instead, we rely on the
        // reactive rejoin in handle_message which only fires when decryption actually fails.
        self.log_epoch_gaps().await;

        // Create shutdown signal
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        // Start WebSocket subscription
        let ws = MlsWebSocket::new(self.api_client.clone());
        let ws_reconnect = ws.reconnect_handle();
        let mut events = ws.subscribe(shutdown_rx);

        // Periodic sync timer (every 30 seconds)
        let mut sync_interval = tokio::time::interval(std::time::Duration::from_secs(30));
        sync_interval.tick().await; // Skip the first immediate tick

        tracing::info!("Bot event loop running. Waiting for messages...");

        loop {
            tokio::select! {
                // WebSocket events
                Some(event) = events.recv() => {
                    match event {
                        MlsEvent::Message {
                            id,
                            conversation_id,
                            ciphertext,
                            epoch,
                            created_at,
                            ..
                        } => {
                            // Spawn message handling as a background task so the
                            // event loop stays responsive during LLM calls (up to 300s).
                            let did = self.did.clone();
                            let api_client = Arc::clone(&self.api_client);
                            let orchestrator = Arc::clone(&self.orchestrator);
                            let llm = Arc::clone(&self.llm);
                            let recent_rejoins = Arc::clone(&self.recent_rejoins);
                            tokio::spawn(async move {
                                handle_message_bg(
                                    &did,
                                    &api_client,
                                    &orchestrator,
                                    &llm,
                                    &recent_rejoins,
                                    &id,
                                    &conversation_id,
                                    ciphertext,
                                    epoch,
                                    &created_at,
                                )
                                .await;
                            });
                        }
                        MlsEvent::GroupReset {
                            conversation_id,
                            new_group_id,
                            reset_generation,
                        } => {
                            tracing::info!(
                                convo = %conversation_id,
                                new_group_id = %new_group_id,
                                reset_generation,
                                "Group reset event received — adopting RESET_PENDING"
                            );
                            self.recent_rejoins.lock().await.remove(&conversation_id);
                            match hex::decode(&new_group_id) {
                                Ok(new_group_id_bytes) => {
                                    // Spec §8.5 Phase 1: persist-only path. The
                                    // 30s sync loop drives `join_or_rejoin` (now
                                    // including first-responder bootstrap) — never
                                    // run External Commits inline from event
                                    // handlers (April 2026 epoch-inflation class).
                                    if let Err(e) = self
                                        .orchestrator
                                        .record_group_reset(
                                            &conversation_id,
                                            new_group_id_bytes,
                                            reset_generation,
                                        )
                                        .await
                                    {
                                        tracing::error!(
                                            convo = %conversation_id,
                                            error = %e,
                                            "Failed to adopt group reset"
                                        );
                                    }
                                }
                                Err(e) => {
                                    tracing::error!(
                                        convo = %conversation_id,
                                        new_group_id = %new_group_id,
                                        error = %e,
                                        "Ignoring malformed group reset newGroupId"
                                    );
                                }
                            }
                        }
                        MlsEvent::Connected => {
                            tracing::info!("WebSocket connected");
                        }
                        MlsEvent::Disconnected => {
                            tracing::warn!("WebSocket disconnected, will reconnect");
                        }
                        MlsEvent::Info { info, .. } => {
                            tracing::debug!("Info event: {}", info);
                        }
                    }
                }

                // Periodic sync
                _ = sync_interval.tick() => {
                    self.sync_and_reconnect_if_needed(&ws_reconnect).await;
                }

                // Ctrl+C shutdown
                _ = tokio::signal::ctrl_c() => {
                    tracing::info!("Shutdown signal received");
                    let _ = shutdown_tx.send(true);
                    self.orchestrator.shutdown().await;
                    break;
                }
            }
        }

        tracing::info!("BIRD bot shut down");
        Ok(())
    }

    // handle_message is now the free function handle_message_bg() below

    async fn begin_typing_signal(
        &self,
        conversation_id: &str,
    ) -> Option<tokio::task::JoinHandle<()>> {
        if let Err(e) = self
            .api_client
            .send_typing_indicator(conversation_id, true)
            .await
        {
            tracing::debug!("Failed to send typing start: {}", e);
        }

        let api_client = Arc::clone(&self.api_client);
        let convo_id = conversation_id.to_string();
        Some(tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                if let Err(e) = api_client.send_typing_indicator(&convo_id, true).await {
                    tracing::debug!("Failed to send typing heartbeat: {}", e);
                }
            }
        }))
    }

    async fn end_typing_signal(
        &self,
        conversation_id: &str,
        heartbeat: Option<tokio::task::JoinHandle<()>>,
    ) {
        if let Some(handle) = heartbeat {
            handle.abort();
        }

        if let Err(e) = self
            .api_client
            .send_typing_indicator(conversation_id, false)
            .await
        {
            tracing::debug!("Failed to send typing stop: {}", e);
        }
    }

    /// Download an encrypted image blob and decrypt it.
    async fn download_and_decrypt_image(
        &self,
        image: &catbird_mls::orchestrator::types::MLSImageEmbed,
    ) -> anyhow::Result<Vec<u8>> {
        tracing::info!(blob_id = %image.blob_id, "Downloading image blob");
        let encrypted = self.api_client.get_blob(&image.blob_id).await?;
        let plaintext = decrypt_blob(&encrypted, &image.key, &image.iv, &image.sha256)?;
        tracing::info!(
            blob_id = %image.blob_id,
            size = plaintext.len(),
            "Image blob decrypted"
        );
        Ok(plaintext)
    }

    /// Run periodic sync and trigger WebSocket reconnect if new conversations are discovered.
    async fn sync_and_reconnect_if_needed(&self, ws_reconnect: &Arc<Notify>) {
        let count_before = self.orchestrator.conversations().lock().await.len();

        if let Err(e) = self.orchestrator.sync_with_server(false).await {
            tracing::warn!("Periodic sync failed: {}", e);
            return;
        }

        let count_after = self.orchestrator.conversations().lock().await.len();

        if count_after > count_before {
            tracing::info!(
                before = count_before,
                after = count_after,
                new = count_after - count_before,
                "New conversations discovered during sync — triggering WebSocket reconnect"
            );
            ws_reconnect.notify_one();
        }
    }

    /// Log conversations with epoch gaps at startup for observability.
    ///
    /// We intentionally do NOT force-rejoin here. External Commits advance the
    /// group epoch, which pushes the bot ahead of participants who haven't yet
    /// processed the commit. The reactive rejoin in `handle_message` is the
    /// correct recovery path — it only triggers when decryption actually fails.
    async fn log_epoch_gaps(&self) {
        let conversations = self.orchestrator.conversations().lock().await.clone();
        let group_states = self.orchestrator.group_states().lock().await.clone();

        let mut behind = 0u32;
        let mut ahead = 0u32;
        for (convo_id, convo) in &conversations {
            let local_epoch = group_states.get(convo_id).map(|gs| gs.epoch).unwrap_or(0);

            if convo.epoch > local_epoch {
                behind += 1;
                tracing::info!(
                    convo = %convo_id,
                    local_epoch,
                    server_epoch = convo.epoch,
                    gap = convo.epoch - local_epoch,
                    "Bot behind server (will rejoin reactively on decrypt failure)"
                );
            } else if local_epoch > convo.epoch {
                ahead += 1;
                tracing::warn!(
                    convo = %convo_id,
                    local_epoch,
                    server_epoch = convo.epoch,
                    gap = local_epoch - convo.epoch,
                    "Bot ahead of server (may drop old-epoch messages beyond retention window)"
                );
            }
        }

        if behind == 0 && ahead == 0 {
            tracing::info!("All conversations at matching epochs");
        } else {
            tracing::info!(
                behind,
                ahead,
                total = conversations.len(),
                "Epoch gap summary"
            );
        }
    }
}

// ── Background message handler (spawned per-message, never blocks event loop) ──

async fn handle_message_bg(
    did: &str,
    api_client: &Arc<BirdApiClient>,
    orchestrator: &Arc<BirdOrchestrator>,
    llm: &Arc<BridgeClient>,
    recent_rejoins: &Arc<Mutex<HashMap<String, Instant>>>,
    id: &str,
    conversation_id: &str,
    ciphertext: Vec<u8>,
    msg_epoch: u64,
    created_at: &str,
) {
    let local_epoch = orchestrator
        .group_states()
        .lock()
        .await
        .get(conversation_id)
        .map(|gs| gs.epoch)
        .unwrap_or(0);

    tracing::info!(
        id = %id,
        convo = %conversation_id,
        ct_len = ciphertext.len(),
        msg_epoch,
        local_epoch,
        "Received encrypted message"
    );

    if msg_epoch > 0 && local_epoch > MAX_PAST_EPOCHS && msg_epoch < local_epoch - MAX_PAST_EPOCHS {
        tracing::warn!(
            convo = %conversation_id,
            msg_epoch,
            local_epoch,
            epoch_gap = local_epoch - msg_epoch,
            "Dropping message from epoch beyond retention window (sender needs to sync)"
        );
        return;
    }

    let timestamp = created_at.parse().unwrap_or_else(|_| Utc::now());
    let envelope = IncomingEnvelope {
        conversation_id: conversation_id.to_string(),
        sender_did: String::new(),
        ciphertext,
        timestamp,
        server_message_id: Some(id.to_string()),
    };

    let decrypted = match orchestrator.process_incoming(&envelope).await {
        Ok(Some(msg)) => msg,
        Ok(None) => {
            tracing::debug!("Message deduplicated or own echo");
            return;
        }
        Err(e) => {
            // Per spec: DO NOT perform External Commit in send/receive path.
            // Flag for deferred recovery instead — the periodic sync loop
            // handles the actual External Commit.
            let within_cooldown = {
                let rejoins = recent_rejoins.lock().await;
                match rejoins.get(conversation_id) {
                    Some(last) => last.elapsed() < REJOIN_COOLDOWN,
                    None => false,
                }
            };

            if msg_epoch >= local_epoch && !within_cooldown {
                tracing::warn!(
                    convo = %conversation_id,
                    msg_epoch,
                    local_epoch,
                    "Decrypt failed (we may be behind), flagging NEEDS_REJOIN for deferred recovery: {}", e
                );
                if let Err(mark_err) = orchestrator
                    .storage()
                    .mark_needs_rejoin(conversation_id)
                    .await
                {
                    tracing::error!(
                        convo = %conversation_id,
                        "Failed to mark NEEDS_REJOIN: {}", mark_err
                    );
                }
                recent_rejoins
                    .lock()
                    .await
                    .insert(conversation_id.to_string(), Instant::now());
            } else {
                tracing::debug!(
                    convo = %conversation_id,
                    msg_epoch,
                    local_epoch,
                    "Decrypt failed, skipping rejoin flag (sender behind or cooldown active): {}", e
                );
            }
            return;
        }
    };

    if decrypted.is_own {
        tracing::debug!("Skipping own message");
        return;
    }

    if !decrypted.has_displayable_body() {
        tracing::debug!("Skipping non-displayable message (likely control)");
        return;
    }

    tracing::info!(
        sender = %decrypted.sender_did,
        text = %decrypted.text,
        has_image = decrypted.image_embed().is_some(),
        "Decrypted message"
    );

    // Start typing indicator
    if let Err(e) = api_client
        .send_typing_indicator(conversation_id, true)
        .await
    {
        tracing::debug!("Failed to send typing start: {}", e);
    }
    let typing_api = Arc::clone(api_client);
    let typing_convo = conversation_id.to_string();
    let typing_handle = tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            if let Err(e) = typing_api.send_typing_indicator(&typing_convo, true).await {
                tracing::debug!("Failed to send typing heartbeat: {}", e);
            }
        }
    });

    // Download and decrypt image if present
    let image_data = if let Some(image) = decrypted.image_embed() {
        tracing::info!(blob_id = %image.blob_id, "Downloading image blob");
        match api_client.get_blob(&image.blob_id).await {
            Ok(encrypted) => match decrypt_blob(&encrypted, &image.key, &image.iv, &image.sha256) {
                Ok(plaintext) => {
                    tracing::info!(blob_id = %image.blob_id, size = plaintext.len(), "Image blob decrypted");
                    Some((plaintext, image.content_type.clone()))
                }
                Err(e) => {
                    tracing::warn!("Failed to decrypt image blob: {}", e);
                    None
                }
            },
            Err(e) => {
                tracing::warn!("Failed to fetch image blob: {}", e);
                None
            }
        }
    } else {
        None
    };

    let image_b64 = image_data.as_ref().map(|(data, content_type)| {
        (
            base64::engine::general_purpose::STANDARD.encode(data),
            content_type.clone(),
        )
    });
    let image_param = image_b64
        .as_ref()
        .map(|(b64, ct)| (b64.as_str(), ct.as_str()));

    let embed_context = decrypted.payload().and_then(|payload| {
        payload.embed.as_ref().and_then(|embed| {
            if embed.kind == "image" {
                None
            } else {
                Some(format!(
                    "[attachment type={}, data={}]",
                    embed.kind, embed.data
                ))
            }
        })
    });
    let embed_ctx_ref = embed_context.as_deref();

    tracing::info!("Calling OpenClaw for conversation {}", conversation_id);
    let response = match llm
        .generate(
            conversation_id,
            &decrypted.sender_did,
            &decrypted.text,
            image_param,
            embed_ctx_ref,
        )
        .await
    {
        Ok(resp) => resp,
        Err(e) => {
            tracing::error!("LLM call failed: {}", e);
            typing_handle.abort();
            let _ = api_client
                .send_typing_indicator(conversation_id, false)
                .await;
            return;
        }
    };

    if response.is_empty() {
        tracing::warn!("LLM returned empty response, not sending");
        typing_handle.abort();
        let _ = api_client
            .send_typing_indicator(conversation_id, false)
            .await;
        return;
    }

    tracing::info!(
        convo = %conversation_id,
        response_len = response.len(),
        "Sending LLM response"
    );

    // Stop typing before sending
    typing_handle.abort();
    let _ = api_client
        .send_typing_indicator(conversation_id, false)
        .await;

    match orchestrator.send_message(conversation_id, &response).await {
        Ok(_msg) => {
            tracing::info!("Response sent successfully to {}", conversation_id);
        }
        Err(e) => {
            tracing::error!("Failed to send response: {}", e);
        }
    }
}
