//! Bot logic: ties together MLS orchestrator, WebSocket, LLM client, and event loop.

use base64::Engine;
use chrono::Utc;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::Instant;

use catbird_mls::blob_crypto::decrypt_blob;
use catbird_mls::orchestrator::{IncomingEnvelope, MLSOrchestrator, MLSStorageBackend};
use catbird_mls::MLSContext;

use crate::bridge_client::BridgeClient;
use crate::config::BirdConfig;
use crate::credentials::FileCredentialStore;
use crate::request_policy::{request_key_action, RequestAction, RequestKeyAction, RequestPolicy};
use crate::storage::SqliteStorage;
use crate::websocket::{MlsEvent, MlsWebSocket};
use crate::xrpc_client::BirdApiClient;
use catbird_mls::orchestrator::MlsCryptoContext;
use catbird_mls::orchestrator::{RequestConsent, RequestCrypto, RequestPreview};
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
    config: std::sync::RwLock<BirdConfig>,
    effect_slots: Arc<tokio::sync::Semaphore>,
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
            config: std::sync::RwLock::new(config),
            effect_slots: Arc::new(tokio::sync::Semaphore::new(4)),
            recent_rejoins: Arc::new(Mutex::new(HashMap::new())),
        }
    }
    pub fn request_policy(&self) -> RequestPolicy {
        self.config.read().unwrap().request_policy()
    }

    pub fn request_delivery_enabled(&self) -> bool {
        self.config.read().unwrap().request_delivery_enabled()
    }

    pub fn max_reply_characters(&self) -> u32 {
        self.config.read().unwrap().max_reply_characters
    }

    pub fn set_accept_chat_requests(&self, accept: bool) {
        self.config.write().unwrap().accept_chat_requests = accept;
    }

    /// Run the main event loop.
    ///
    /// Subscribes to WebSocket events, decrypts incoming messages via the MLS
    /// orchestrator, generates LLM responses, and encrypts + sends replies.
    pub async fn run(&self) -> anyhow::Result<()> {
        tracing::info!("BIRD bot starting for DID: {}", self.did);

        self.maintain_request_keys().await;

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
        self.handle_request_views().await;

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
                            let policy = self.request_policy();
                            let did = self.did.clone();
                            let api_client = Arc::clone(&self.api_client);
                            let orchestrator = Arc::clone(&self.orchestrator);
                            let llm = Arc::clone(&self.llm);
                            let recent_rejoins = Arc::clone(&self.recent_rejoins);
                            let slots = self.effect_slots.clone();
                            tokio::spawn(async move {
                                let Ok(_permit) = slots.acquire_owned().await else { return; };
                                handle_message_bg(
                                    &did,
                                    &api_client,
                                    &orchestrator,
                                    &llm,
                                    &recent_rejoins,
                                    policy,
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
                        MlsEvent::CanonicalHint => {
                            // A notification is scheduling only; sync verifies current authority.
                            self.sync_and_reconnect_if_needed(&ws_reconnect).await;
                        }
                        MlsEvent::Connected => {
                            tracing::info!("WebSocket connected");
                        }
                        MlsEvent::Disconnected => {
                            tracing::warn!("WebSocket disconnected, will reconnect");
                        }
                        MlsEvent::Info { info, .. } => {
                            let _ = info; // Never log an untrusted event body.
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

    pub(crate) async fn maintain_request_keys(&self) {
        // Delivery is an explicit configuration choice, separate from consent.
        let current = match self.orchestrator.get_direct_request_delivery_enabled().await {
            Ok(current) => current,
            Err(error) => {
                tracing::warn!(%error, "Request delivery preference read failed");
                return;
            }
        };
        let result = match request_key_action(self.request_delivery_enabled(), current) {
            RequestKeyAction::Enable => self.orchestrator.set_direct_request_delivery_enabled(true).await,
            RequestKeyAction::Disable => self.orchestrator.set_direct_request_delivery_enabled(false).await,
            RequestKeyAction::Replenish => self.orchestrator.replenish_direct_request_keys_if_needed().await,
            RequestKeyAction::None => Ok(()),
        };
        if let Err(error) = result {
            tracing::warn!(%error, "Request key maintenance failed");
        }
    }

    /// Distinct request path: only a freshly verified accepted projection can
    /// release an introduction to the bridge. Pending text stays in native SQLCipher.
    pub(crate) async fn handle_request_views(&self) {
        let Ok(views) = self.orchestrator.list_direct_request_views().await else {
            return;
        };
        for retained in views {
            let Ok(mut view) = self
                .orchestrator
                .refresh_request_preview(&retained.conversation_id)
                .await
            else {
                continue;
            };
            if view
                .introduction
                .as_ref()
                .is_none_or(|intro| intro.sender_did == self.did)
            {
                continue;
            }
            if self.request_policy().action(&view) == RequestAction::Accept {
                if self
                    .orchestrator
                    .accept_conversation(&view.conversation_id)
                    .await
                    .is_err()
                {
                    continue;
                }
                let Ok(accepted) = self
                    .orchestrator
                    .refresh_request_preview(&view.conversation_id)
                    .await
                else {
                    continue;
                };
                view = accepted;
            }
            if self.request_policy().action(&view) != RequestAction::Reply {
                continue;
            }
            let (Some(message_id), Some(intro), Some(RequestPreview::Ready { text, .. })) = (
                view.first_message_id.as_ref(),
                view.introduction.as_ref(),
                view.preview.as_ref(),
            ) else {
                continue;
            };
            let _ = message_id;
            if !crate::request_policy::claim_request_effect(
                self.request_policy(),
                &view,
                self.orchestrator.storage().as_ref(),
            ) {
                continue;
            }
            // The same ordinary gate is applied after the durable dedup claim.
            if !ordinary_effects_allowed(
                &self.orchestrator,
                &self.did,
                &view.conversation_id,
                self.request_policy(),
            )
            .await
            {
                continue;
            }
            let (did, cid, sender, text, policy, max_chars) = (
                self.did.clone(),
                view.conversation_id.clone(),
                intro.sender_did.clone(),
                text.clone(),
                self.request_policy(),
                self.max_reply_characters(),
            );
            let orchestrator = self.orchestrator.clone();
            let llm = self.llm.clone();
            let slots = self.effect_slots.clone();
            tokio::spawn(async move {
                let Ok(_permit) = slots.acquire_owned().await else {
                    return;
                };
                if !ordinary_effects_allowed(&orchestrator, &did, &cid, policy).await {
                    return;
                }
                if let Ok(response) = llm.generate(&cid, &sender, &text, None, None).await {
                    if !response.is_empty()
                        && ordinary_effects_allowed(&orchestrator, &did, &cid, policy).await
                    {
                        let response: String = response.chars().take(max_chars as usize).collect();
                        let _ = orchestrator.send_message(&cid, &response).await;
                    }
                }
            });
        }
    }

    /// Run periodic sync and trigger WebSocket reconnect if new conversations are discovered.
    async fn sync_and_reconnect_if_needed(&self, ws_reconnect: &Arc<Notify>) {
        let known: Vec<_> = self
            .orchestrator
            .conversations()
            .lock()
            .await
            .keys()
            .cloned()
            .collect();
        let count_before = known.len();
        let mut previous = HashSet::new();
        for cid in known {
            let Ok(messages) = self
                .orchestrator
                .storage()
                .get_messages(&cid, 100, None)
                .await
            else {
                return;
            };
            previous.extend(messages.into_iter().map(|message| message.id));
        }
        if let Err(e) = self.orchestrator.sync_with_server(false).await {
            tracing::warn!("Periodic sync failed: {}", e);
            return;
        }

        self.maintain_request_keys().await;
        self.handle_request_views().await;
        let current: Vec<_> = self
            .orchestrator
            .conversations()
            .lock()
            .await
            .keys()
            .cloned()
            .collect();
        let count_after = current.len();
        for cid in current {
            if !ordinary_effects_allowed(
                &self.orchestrator,
                &self.did,
                &cid,
                self.request_policy(),
            )
            .await
            {
                continue;
            }
            let Ok(messages) = self
                .orchestrator
                .storage()
                .get_messages(&cid, 100, None)
                .await
            else {
                continue;
            };
            for message in messages
                .into_iter()
                .rev()
                .filter(|message| !previous.contains(&message.id))
            {
                let did = self.did.clone();
                let api = self.api_client.clone();
                let orchestrator = self.orchestrator.clone();
                let llm = self.llm.clone();
                let policy = self.request_policy();
                let slots = self.effect_slots.clone();
                tokio::spawn(async move {
                    let Ok(_permit) = slots.acquire_owned().await else {
                        return;
                    };
                    handle_decrypted_message(&did, &api, &orchestrator, &llm, policy, message)
                        .await;
                });
            }
        }

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
    policy: RequestPolicy,
    id: &str,
    conversation_id: &str,
    ciphertext: Vec<u8>,
    msg_epoch: u64,
    created_at: &str,
) {
    if !ordinary_effects_allowed(orchestrator, did, conversation_id, policy).await {
        return;
    }
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
        canonical_entry_json: None,
        conversation_id: conversation_id.to_string(),
        sender_did: String::new(),
        ciphertext,
        timestamp,
        server_message_id: Some(id.to_string()),
        server_epoch: Some(msg_epoch),
        server_sequence: None,
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

    handle_decrypted_message(did, api_client, orchestrator, llm, policy, decrypted).await;
}

async fn handle_decrypted_message(
    did: &str,
    api_client: &Arc<BirdApiClient>,
    orchestrator: &Arc<BirdOrchestrator>,
    llm: &Arc<BridgeClient>,
    policy: RequestPolicy,
    decrypted: catbird_mls::orchestrator::Message,
) {
    let conversation_id = decrypted.conversation_id.as_str();
    if decrypted.is_own {
        tracing::debug!("Skipping own message");
        return;
    }

    if !decrypted.has_displayable_body() {
        tracing::debug!("Skipping non-displayable message (likely control)");
        return;
    }

    if !ordinary_effects_allowed(orchestrator, did, conversation_id, policy).await
        || !orchestrator
            .storage()
            .claim_bot_effect(conversation_id, &decrypted.id)
            .unwrap_or(false)
    {
        return;
    }

    tracing::info!(
        sender = %decrypted.sender_did,
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
    let typing_orchestrator = orchestrator.clone();
    let typing_did = did.to_string();
    let typing_handle = tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            if !ordinary_effects_allowed(&typing_orchestrator, &typing_did, &typing_convo, policy)
                .await
            {
                break;
            }
            if let Err(e) = typing_api.send_typing_indicator(&typing_convo, true).await {
                tracing::debug!("Failed to send typing heartbeat: {}", e);
            }
        }
    });

    // Download and decrypt image if present
    let image_data = if let Some(image) = decrypted.image_embed() {
        if !ordinary_effects_allowed(orchestrator, did, conversation_id, policy).await {
            typing_handle.abort();
            return;
        }
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

    if !ordinary_effects_allowed(orchestrator, did, conversation_id, policy).await {
        typing_handle.abort();
        return;
    }
    tracing::info!("Calling bridge for conversation {}", conversation_id);
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

    if !ordinary_effects_allowed(orchestrator, did, conversation_id, policy).await {
        return;
    }
    match orchestrator.send_message(conversation_id, &response).await {
        Ok(_msg) => {
            tracing::info!("Response sent successfully to {}", conversation_id);
        }
        Err(e) => {
            tracing::error!("Failed to send response: {}", e);
        }
    }
}

/// Missing, malformed, pending or closed authority fails closed before effects.
async fn ordinary_effects_allowed(
    orchestrator: &BirdOrchestrator,
    did: &str,
    cid: &str,
    policy: RequestPolicy,
) -> bool {
    if !policy.reply {
        return false;
    }
    let Ok(requests) = orchestrator.list_direct_request_views().await else {
        return false;
    };
    if requests.iter().any(|view| view.conversation_id == cid) {
        return orchestrator
            .refresh_request_preview(cid)
            .await
            .is_ok_and(|view| {
                view.consent == RequestConsent::Accepted
                    && view.crypto == RequestCrypto::Ready
                    && view.capabilities.can_send
            });
    }
    // A list miss cannot classify a conversation. Require the shared core's
    // protected, verified retained policy for this exact account and UUID.
    let Ok(Some(state)) = orchestrator.mls_context().get_conversation_policy(did, cid) else {
        return false;
    };
    crate::request_policy::legacy_effects_allowed(&state, did)
}
