//! MLSAPIClient implementation using PDS atproto-proxy.
//!
//! Routes MLS calls through the PDS with the atproto-proxy header.
//! Uses jacquard session for automatic token refresh on expiry.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use catbird_mls::orchestrator::{
    decode_clean_chat_response, CanonicalOperation, CleanChatSigningContext, GatewayResponse,
    PreparedRequest,
};
use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::json;
use sha2::Digest as _;

use catbird_mls::orchestrator::error::{OrchestratorError, Result};
use catbird_mls::orchestrator::types::*;
use catbird_mls::orchestrator::MLSAPIClient;

use crate::chat_authority::{
    derive_key_id, AuthorityError, AuthoritySnapshot, AuthorityState, CleanChatHttpResponse,
    InvalidationReason, NestClient,
};
use crate::credentials::FileCredentialStore;

/// Jacquard session type alias.
type Session = jacquard::client::MemoryCredentialSession;

/// Trait for preparing signed clean-chat requests without leaking credentials.
#[async_trait]
pub trait CleanChatRequestSigner: Send + Sync {
    async fn prepare_signed_request(
        &self,
        binding: CleanChatSigningContext,
        operation: CanonicalOperation,
        body_json: Vec<u8>,
    ) -> std::result::Result<catbird_mls::orchestrator::PreparedRequest, OrchestratorError>;
}

#[async_trait]
impl<S, A, C, M> CleanChatRequestSigner for catbird_mls::orchestrator::MLSOrchestrator<S, A, C, M>
where
    S: catbird_mls::orchestrator::storage::MLSStorageBackend + 'static,
    A: catbird_mls::orchestrator::MLSAPIClient + 'static,
    C: catbird_mls::orchestrator::credentials::CredentialStore + 'static,
    M: catbird_mls::orchestrator::MlsCryptoContext + 'static,
{
    async fn prepare_signed_request(
        &self,
        binding: CleanChatSigningContext,
        operation: CanonicalOperation,
        body_json: Vec<u8>,
    ) -> std::result::Result<catbird_mls::orchestrator::PreparedRequest, OrchestratorError> {
        self.prepare_clean_chat_signed_request(binding, operation, body_json)
            .await
            .map_err(|e| {
                OrchestratorError::Api(format!("prepare_clean_chat_signed_request failed: {e}"))
            })
    }
}

/// XRPC client that routes MLS calls through the PDS via atproto-proxy.
/// Token lifecycle is managed by the jacquard session: on expired token errors,
/// the client refreshes via `com.atproto.server.refreshSession` and retries.
/// If the refresh token is also expired, it falls back to full re-authentication
/// with the app password.
pub struct BirdApiClient {
    http: reqwest::Client,
    pds_endpoint: String,
    session: Arc<Session>,
    did: String,
    /// Clean-chat requests use only this opaque Nest session and immutable
    /// actor/device/generation/signer snapshot. Jacquard is never used for this
    /// namespace.
    nest: Option<Arc<NestClient>>,
    authority: Option<Arc<AuthorityState>>,
    signer: Arc<Mutex<Option<Arc<dyn CleanChatRequestSigner>>>>,
    inventory: Arc<Mutex<Option<InventoryFence>>>,
    pending_welcomes: Arc<Mutex<HashMap<String, CachedPendingWelcome>>>,
    cached_coordinates:
        Arc<Mutex<HashMap<String, catbird_atproto::blue_catbird::chat::ConversationCoordinates>>>,
    /// Stored for re-authentication when refresh token also expires.
    handle: String,
    app_password: String,
    /// Debug-only counters at the real outbound effect boundaries, so live
    /// qualification observes attempts rather than inferring them.
    #[cfg(debug_assertions)]
    effect_probe: Arc<EffectProbe>,
}

#[cfg(debug_assertions)]
#[derive(Debug, Default)]
pub struct EffectProbe {
    pub typing_attempts: std::sync::atomic::AtomicUsize,
    pub blob_downloads: std::sync::atomic::AtomicUsize,
}

#[derive(Debug, Clone)]
struct CachedPendingWelcome {
    authority: AuthoritySnapshot,
    welcome_id: String,
    transition_seq: i64,
    coordinates: catbird_atproto::blue_catbird::chat::ConversationCoordinates<String>,
    opaque_welcome: Vec<u8>,
    acknowledgement_idempotency_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct InventoryFence {
    authority: AuthoritySnapshot,
    inventory_session_id: String,
    event_cursor: String,
}

#[derive(Clone)]
struct CallAuthority {
    nest: Arc<NestClient>,
    state: Arc<AuthorityState>,
    snapshot: AuthoritySnapshot,
}

impl BirdApiClient {
    pub fn new(
        pds_endpoint: String,
        session: Arc<Session>,
        did: String,
        handle: String,
        app_password: String,
    ) -> Self {
        Self {
            http: reqwest::Client::new(),
            pds_endpoint,
            session,
            did,
            nest: None,
            authority: None,
            signer: Arc::new(Mutex::new(None)),
            inventory: Arc::new(Mutex::new(None)),
            pending_welcomes: Arc::new(Mutex::new(HashMap::new())),
            cached_coordinates: Arc::new(Mutex::new(HashMap::new())),
            handle,
            app_password,
            #[cfg(debug_assertions)]
            effect_probe: Arc::new(EffectProbe::default()),
        }
    }

    pub fn with_chat_authority(
        mut self,
        nest: Arc<NestClient>,
        authority: Arc<AuthorityState>,
        _credentials: Arc<FileCredentialStore>,
    ) -> Self {
        self.nest = Some(nest);
        self.authority = Some(authority);
        self
    }
    #[cfg(debug_assertions)]
    pub fn with_http_client(mut self, http: reqwest::Client) -> Self {
        self.http = http;
        self
    }
    #[cfg(debug_assertions)]
    pub fn effect_probe(&self) -> Arc<EffectProbe> {
        self.effect_probe.clone()
    }

    pub fn set_signer(&self, signer: Arc<dyn CleanChatRequestSigner>) {
        let mut s = self.signer.lock().unwrap();
        *s = Some(signer);
    }

    fn xrpc_url(&self, nsid: &str) -> String {
        format!("{}/xrpc/{}", self.pds_endpoint, nsid)
    }

    /// Get current access JWT from the jacquard session.
    async fn get_jwt(&self) -> Result<String> {
        match self.session.access_token().await {
            Some(token) => Ok(Self::extract_jwt(token)),
            None => {
                // Session state lost — try to recover
                tracing::warn!("No access token in session, attempting refresh");
                self.refresh_jwt().await
            }
        }
    }

    /// Refresh the access token. Tries jacquard's refreshSession first,
    /// falls back to full re-login with app password if that also fails.
    async fn refresh_jwt(&self) -> Result<String> {
        match self.session.refresh().await {
            Ok(token) => {
                tracing::info!("Session token refreshed successfully");
                Ok(Self::extract_jwt(token))
            }
            Err(e) => {
                tracing::warn!(
                    "Token refresh failed ({}), re-authenticating with app password",
                    e
                );
                self.session
                    .login(&self.handle, &self.app_password, None, None, None, None)
                    .await
                    .map_err(|e| {
                        OrchestratorError::Api(format!("Re-authentication failed: {e}"))
                    })?;
                tracing::info!("Re-authenticated successfully");
                self.session
                    .access_token()
                    .await
                    .map(Self::extract_jwt)
                    .ok_or_else(|| {
                        OrchestratorError::Api("No token after re-authentication".into())
                    })
            }
        }
    }

    fn extract_jwt(token: jacquard_common::AuthorizationToken) -> String {
        match token {
            jacquard_common::AuthorizationToken::Bearer(s) => s.to_string(),
            jacquard_common::AuthorizationToken::Dpop(s) => s.to_string(),
            jacquard_common::AuthorizationToken::Delegation(s) => s.to_string(),
        }
    }

    /// Get a v2 subscription ticket through Nest. The returned endpoint is
    /// opened directly by the WebSocket client; Nest explicitly refuses to
    /// proxy `subscribeEvents` upgrades.
    pub async fn get_subscription_ticket(&self) -> Result<(String, String, String)> {
        let call = self.authority_for_call()?;
        let (inventory_session_id, event_cursor) = self.inventory_for_call(&call)?;
        let response = call
            .nest
            .get_subscription_ticket_response(&call.snapshot, &inventory_session_id, &event_cursor)
            .await
            .map_err(|error| self.map_authority_error(&call, error))?;
        self.observe_remote_binding_failure(&call, &response);
        let body = Self::require_successful_response(
            "getSubscriptionTicket",
            GatewayResponse {
                status: response.status,
                content_type: response.content_type,
                body: response.body,
            },
        )?;
        let value: serde_json::Value = serde_json::from_slice(&body).map_err(|_| {
            OrchestratorError::Serialization("invalid getSubscriptionTicket response".into())
        })?;
        let ticket = value
            .get("ticket")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| OrchestratorError::Serialization("missing subscription ticket".into()))?
            .to_owned();
        let endpoint = value
            .get("endpoint")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                OrchestratorError::Serialization("missing subscription endpoint".into())
            })?
            .to_owned();
        Ok((ticket, endpoint, event_cursor))
    }

    fn authority_for_call(&self) -> Result<CallAuthority> {
        let nest = self.nest.clone().ok_or_else(|| {
            OrchestratorError::Api("clean-chat Nest transport is not configured".into())
        })?;
        let authority = self
            .authority
            .clone()
            .ok_or_else(|| OrchestratorError::Api("clean-chat authority is not admitted".into()))?;
        let snapshot = authority
            .snapshot()
            .ok_or_else(|| OrchestratorError::Api("clean-chat authority is not admitted".into()))?;
        if snapshot.actor_did() != self.did {
            return Err(OrchestratorError::Api(
                "clean-chat caller scope does not match the admitted account".into(),
            ));
        }
        Ok(CallAuthority {
            nest,
            state: authority,
            snapshot,
        })
    }

    fn inventory_for_call(&self, call: &CallAuthority) -> Result<(String, String)> {
        let inventory = self.inventory.lock().unwrap();
        let fence = inventory.as_ref().ok_or_else(|| {
            OrchestratorError::Api(
                "operation requires a current device-scoped inventory session and cursor".into(),
            )
        })?;
        if fence.authority != call.snapshot {
            return Err(OrchestratorError::Credential(
                "retained inventory session does not belong to the admitted caller scope".into(),
            ));
        }
        Ok((
            fence.inventory_session_id.clone(),
            fence.event_cursor.clone(),
        ))
    }

    fn map_authority_error(
        &self,
        call: &CallAuthority,
        error: AuthorityError,
    ) -> OrchestratorError {
        let reason = match error {
            AuthorityError::AccountMismatch => InvalidationReason::AccountChanged,
            AuthorityError::GenerationMismatch => InvalidationReason::GenerationChanged,
            AuthorityError::DeviceMismatch | AuthorityError::DeviceNotActive => {
                InvalidationReason::Revoked
            }
            _ => {
                return OrchestratorError::Api(format!(
                    "clean-chat Nest authority request failed: {error}"
                ))
            }
        };
        if let Err(error) = call.state.invalidate_if_matches(&call.snapshot, reason) {
            tracing::error!(error = %error, "Failed to persist clean-chat invalidation");
        }
        OrchestratorError::Api("clean-chat authority was invalidated".into())
    }

    fn observe_remote_binding_failure(
        &self,
        call: &CallAuthority,
        response: &CleanChatHttpResponse,
    ) {
        let is_typed_xrpc_response = response
            .content_type
            .as_deref()
            .and_then(|content_type| content_type.split(';').next())
            .is_some_and(|media_type| media_type.trim().eq_ignore_ascii_case("application/json"));
        if !is_typed_xrpc_response {
            return;
        }
        let error_code = serde_json::from_slice::<serde_json::Value>(&response.body)
            .ok()
            .and_then(|value| {
                value
                    .get("error")
                    .and_then(serde_json::Value::as_str)
                    .map(ToOwned::to_owned)
            });
        let reason = match (response.status, error_code.as_deref()) {
            (401, Some("AccountSessionExpired")) => Some(InvalidationReason::LoggedOut),
            (401, Some("DeviceBindingMismatch")) => Some(InvalidationReason::DeviceBindingChanged),
            (401, Some("DeviceNotRegistered")) | (401, Some("DeviceRevoked")) => {
                Some(InvalidationReason::Revoked)
            }
            (400, Some("AuthenticationGenerationConflict")) => {
                Some(InvalidationReason::GenerationChanged)
            }
            _ => None,
        };
        if let Some(reason) = reason {
            if let Err(error) = call.state.invalidate_if_matches(&call.snapshot, reason) {
                tracing::error!(error = %error, "Failed to persist clean-chat invalidation");
            }
        }
    }

    async fn canonical_get_response(
        &self,
        call: &CallAuthority,
        path: &str,
    ) -> Result<GatewayResponse> {
        let response = call
            .nest
            .get_clean_chat_response(&call.snapshot, path)
            .await
            .map_err(|error| self.map_authority_error(call, error))?;
        self.observe_remote_binding_failure(call, &response);
        Ok(GatewayResponse {
            status: response.status,
            content_type: response.content_type,
            body: response.body,
        })
    }

    fn require_successful_response(operation: &str, response: GatewayResponse) -> Result<Vec<u8>> {
        if !(200..300).contains(&response.status) {
            return Err(OrchestratorError::ServerError {
                status: response.status,
                body: String::from_utf8_lossy(&response.body).into_owned(),
            });
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
            return Err(OrchestratorError::Api(format!(
                "Canonical {operation} returned a non-JSON content type"
            )));
        }
        Ok(response.body)
    }

    async fn get_own_devices_all(
        &self,
        call: &CallAuthority,
    ) -> Result<Vec<catbird_atproto::blue_catbird::chat::DeviceView<String>>> {
        const MAX_DEVICE_PAGES: usize = 32;
        let mut devices = Vec::new();
        let mut cursor: Option<String> = None;
        let mut seen_cursors = std::collections::HashSet::new();
        let mut seen_device_ids = std::collections::HashSet::new();
        let mut snapshot_expires_at: Option<String> = None;
        for _ in 0..MAX_DEVICE_PAGES {
            let path =
                canonical_get_own_devices_path(call.snapshot.device_id(), 100, cursor.as_deref());
            let response = self.canonical_get_response(call, &path).await?;
            let body = Self::require_successful_response("getOwnDevices", response)?;
            let decoded =
                decode_clean_chat_response(CanonicalOperation::GetOwnDevices.into(), body)
                    .map_err(|e| {
                        OrchestratorError::Api(format!("Canonical getOwnDevices decode: {e}"))
                    })?;
            let output: catbird_atproto::blue_catbird::chat::get_own_devices::GetOwnDevicesOutput<
                String,
            > = serde_json::from_slice(&decoded).map_err(|e| {
                OrchestratorError::Api(format!("Canonical getOwnDevices JSON: {e}"))
            })?;
            let page_snapshot_expires_at = output.snapshot_expires_at.to_string();
            if snapshot_expires_at
                .as_ref()
                .is_some_and(|expected| expected != &page_snapshot_expires_at)
            {
                return Err(OrchestratorError::Api(
                    "getOwnDevices pagination escaped its inventory snapshot".into(),
                ));
            }
            snapshot_expires_at.get_or_insert(page_snapshot_expires_at);
            for item in output.items {
                validate_device_inventory_item(&item.device)?;
                if !seen_device_ids.insert(item.device.device_id.to_string()) {
                    return Err(OrchestratorError::Api(
                        "authoritative device inventory contains duplicate device IDs".into(),
                    ));
                }
                devices.push(item.device);
            }
            if !output.has_more {
                if output.next_page_cursor.is_some() {
                    return Err(OrchestratorError::Api(
                        "getOwnDevices returned a terminal page with a cursor".into(),
                    ));
                }
                return Ok(devices);
            }
            let next = output.next_page_cursor.ok_or_else(|| {
                OrchestratorError::Api("getOwnDevices hasMore page omitted its cursor".into())
            })?;
            if next.is_empty() || next.len() > 512 {
                return Err(OrchestratorError::Api(
                    "getOwnDevices returned an invalid pagination cursor".into(),
                ));
            }
            if !seen_cursors.insert(next.clone()) {
                return Err(OrchestratorError::Api(
                    "getOwnDevices pagination cursor repeated".into(),
                ));
            }
            cursor = Some(next);
        }
        Err(OrchestratorError::Api(format!(
            "getOwnDevices exceeded the {MAX_DEVICE_PAGES}-page safety bound"
        )))
    }

    async fn fetch_pending_welcome(
        &self,
        call: &CallAuthority,
        conversation_id: &str,
    ) -> Result<Vec<u8>> {
        const MAX_WELCOME_PAGES: usize = 32;
        validate_stable_conversation_id(conversation_id)?;
        let (inventory_session_id, snapshot_event_cursor) = self.inventory_for_call(call)?;
        let mut cursor: Option<String> = None;
        let mut seen_cursors = std::collections::HashSet::new();
        let mut matched: Option<CachedPendingWelcome> = None;
        let mut complete = false;
        let mut snapshot_expires_at: Option<String> = None;
        for _ in 0..MAX_WELCOME_PAGES {
            let path = canonical_get_pending_welcomes_path(
                call.snapshot.device_id(),
                &inventory_session_id,
                100,
                cursor.as_deref(),
            );
            let response = self.canonical_get_response(call, &path).await?;
            let body = Self::require_successful_response("getPendingWelcomes", response)?;
            let decoded =
                decode_clean_chat_response(CanonicalOperation::GetPendingWelcomes.into(), body)
                    .map_err(|e| {
                        OrchestratorError::Api(format!("Canonical getPendingWelcomes decode: {e}"))
                    })?;
            let output: catbird_atproto::blue_catbird::chat::get_pending_welcomes::GetPendingWelcomesOutput<
                String,
            > = serde_json::from_slice(&decoded).map_err(|e| {
                OrchestratorError::Api(format!("Canonical getPendingWelcomes JSON: {e}"))
            })?;
            if output.inventory_session_id.as_str() != inventory_session_id
                || output.snapshot_event_cursor.as_str() != snapshot_event_cursor
            {
                return Err(OrchestratorError::Api(
                    "getPendingWelcomes response escaped its retained inventory fence".into(),
                ));
            }
            let page_snapshot_expires_at = output.snapshot_expires_at.to_string();
            if snapshot_expires_at
                .as_ref()
                .is_some_and(|expected| expected != &page_snapshot_expires_at)
            {
                return Err(OrchestratorError::Api(
                    "getPendingWelcomes pagination escaped its inventory snapshot".into(),
                ));
            }
            snapshot_expires_at.get_or_insert(page_snapshot_expires_at);
            for item in output.items {
                use catbird_atproto::blue_catbird::chat::get_pending_welcomes::GetPendingWelcomesOutputItemsItem;
                let welcome = match item {
                    GetPendingWelcomesOutputItemsItem::WelcomeView(welcome) => welcome,
                    GetPendingWelcomesOutputItemsItem::DirectRequestWelcomeView(welcome) => {
                        // Native request refresh owns verification, custody and ACK.
                        // Never route a bootstrap through the ordinary Welcome join.
                        if welcome.recipient_did.as_str() != call.snapshot.actor_did()
                            || welcome.recipient_device_id.as_str() != call.snapshot.device_id()
                        {
                            return Err(OrchestratorError::Credential(
                                "request Welcome audience mismatch".into(),
                            ));
                        }
                        continue;
                    }
                };
                if welcome.recipient_did.as_str() != call.snapshot.actor_did()
                    || welcome.recipient_device_id.as_str() != call.snapshot.device_id()
                    || welcome.status.as_str() != "pending"
                    || welcome.coordinates.conversation_id.as_str()
                        != welcome.conversation_id.as_str()
                {
                    return Err(OrchestratorError::Credential(
                        "pending Welcome inventory escaped the admitted account/device/conversation scope"
                            .into(),
                    ));
                }
                validate_stable_conversation_id(welcome.conversation_id.as_str())?;
                if welcome.transition_seq < 0
                    || welcome.coordinates.epoch < 0
                    || welcome.coordinates.generation < 0
                    || welcome.coordinates.state_version < 0
                    || welcome.coordinates.group_id.is_empty()
                {
                    return Err(OrchestratorError::Serialization(
                        "pending Welcome contains invalid lifecycle coordinates".into(),
                    ));
                }
                if welcome.conversation_id.as_str() != conversation_id {
                    continue;
                }
                let opaque_welcome = welcome.opaque_welcome.to_vec();
                if opaque_welcome.is_empty() {
                    return Err(OrchestratorError::Serialization(
                        "pending Welcome artifact is empty".into(),
                    ));
                }
                let digest = sha2::Sha256::digest(&opaque_welcome);
                if digest.as_slice() != welcome.sha256.as_ref() {
                    return Err(OrchestratorError::Serialization(
                        "pending Welcome artifact hash does not match its bytes".into(),
                    ));
                }
                let candidate = CachedPendingWelcome {
                    authority: call.snapshot.clone(),
                    welcome_id: welcome.welcome_id.to_string(),
                    transition_seq: welcome.transition_seq,
                    coordinates: welcome.coordinates,
                    opaque_welcome,
                    acknowledgement_idempotency_key: uuid::Uuid::new_v4().to_string(),
                };
                if matched.replace(candidate).is_some() {
                    return Err(OrchestratorError::Api(
                        "multiple pending Welcomes matched one conversation and device".into(),
                    ));
                }
            }
            if !output.has_more {
                if output.next_page_cursor.is_some() {
                    return Err(OrchestratorError::Api(
                        "getPendingWelcomes returned a terminal page with a cursor".into(),
                    ));
                }
                complete = true;
                break;
            }
            let next = output.next_page_cursor.ok_or_else(|| {
                OrchestratorError::Api("getPendingWelcomes hasMore page omitted its cursor".into())
            })?;
            if next.is_empty() || next.len() > 512 {
                return Err(OrchestratorError::Api(
                    "getPendingWelcomes returned an invalid pagination cursor".into(),
                ));
            }
            if !seen_cursors.insert(next.clone()) {
                return Err(OrchestratorError::Api(
                    "getPendingWelcomes pagination cursor repeated".into(),
                ));
            }
            cursor = Some(next);
        }
        if !complete {
            return Err(OrchestratorError::Api(format!(
                "getPendingWelcomes exceeded the {MAX_WELCOME_PAGES}-page safety bound"
            )));
        }
        let welcome = matched.ok_or_else(|| {
            OrchestratorError::Api(format!(
                "device-scoped inventory contains no pending Welcome for conversation {conversation_id}"
            ))
        })?;
        let mut cache = self.pending_welcomes.lock().unwrap();
        if let Some(existing) = cache.get(conversation_id) {
            if existing.authority != welcome.authority
                || existing.welcome_id != welcome.welcome_id
                || existing.transition_seq != welcome.transition_seq
                || existing.coordinates != welcome.coordinates
                || existing.opaque_welcome != welcome.opaque_welcome
            {
                return Err(OrchestratorError::Api(
                    "pending Welcome changed after it was cached for post-join disposition".into(),
                ));
            }
            return Ok(existing.opaque_welcome.clone());
        }
        let bytes = welcome.opaque_welcome.clone();
        cache.insert(conversation_id.to_owned(), welcome);
        Ok(bytes)
    }

    async fn get_canonical_conversations(
        &self,
        limit: u32,
        cursor: Option<&str>,
    ) -> Result<ConversationListPage> {
        let call = self.authority_for_call()?;
        self.get_canonical_conversations_with_call(&call, limit, cursor)
            .await
    }

    async fn get_canonical_conversations_with_call(
        &self,
        call: &CallAuthority,
        limit: u32,
        cursor: Option<&str>,
    ) -> Result<ConversationListPage> {
        if limit == 0 || limit > 100 {
            return Err(OrchestratorError::Api(
                "getConversations limit must be between 1 and 100".into(),
            ));
        }
        let path = canonical_get_conversations_path(call.snapshot.device_id(), limit, cursor);
        let response = self.canonical_get_response(call, &path).await?;
        let body = Self::require_successful_response("getConversations", response)?;
        let output =
            catbird_mls::orchestrator::canonical_transport::decode_conversations_inventory(&body)
                .map_err(|error| {
                OrchestratorError::Api(format!("Canonical getConversations decode: {error}"))
            })?;

        let response_inventory = InventoryFence {
            authority: call.snapshot.clone(),
            inventory_session_id: output.inventory_session_id.to_string(),
            event_cursor: output.snapshot_event_cursor.to_string(),
        };
        if response_inventory.inventory_session_id.is_empty()
            || response_inventory.event_cursor.is_empty()
            || output.has_more != output.next_page_cursor.is_some()
            || output
                .next_page_cursor
                .as_ref()
                .is_some_and(|cursor| cursor.is_empty() || cursor.len() > 512)
        {
            return Err(OrchestratorError::Api(
                "getConversations returned an invalid inventory or pagination fence".into(),
            ));
        }
        {
            let mut inventory = self.inventory.lock().unwrap();
            match (cursor, inventory.as_ref()) {
                (None, _) => *inventory = Some(response_inventory.clone()),
                (Some(_), Some(current)) if current == &response_inventory => {}
                (Some(_), Some(_)) => {
                    return Err(OrchestratorError::Api(
                        "getConversations pagination escaped its retained inventory fence".into(),
                    ))
                }
                (Some(_), None) => {
                    return Err(OrchestratorError::Api(
                        "getConversations continuation requires a retained inventory session"
                            .into(),
                    ))
                }
            }
        }
        {
            let mut coords_map = self.cached_coordinates.lock().unwrap();
            if cursor.is_none() {
                coords_map.clear();
                self.pending_welcomes.lock().unwrap().clear();
            }
            for item in &output.items {
                if let catbird_atproto::blue_catbird::chat::ConversationInventoryItem::ConversationInventoryState(
                    item,
                ) = item
                {
                    coords_map.insert(
                        item.state.coordinates.conversation_id.to_string(),
                        item.state.coordinates.clone(),
                    );
                }
            }
        }
        let conversations = output
            .items
            .into_iter()
            .filter_map(|item| match item {
                catbird_atproto::blue_catbird::chat::ConversationInventoryItem::ConversationInventoryState(
                    item,
                ) => Some(canonical_conversation_view(&item.state)),
                _ => None,
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(ConversationListPage {
            conversations,
            cursor: output.next_page_cursor.map(|value| value.to_string()),
        })
    }

    async fn get_canonical_entries(
        &self,
        convo_id: &str,
        cursor: Option<&str>,
        limit: u32,
        message_type: Option<&str>,
        from_epoch: Option<u32>,
        to_epoch: Option<u32>,
    ) -> Result<(Vec<IncomingEnvelope>, Option<String>)> {
        const MAX_ENTRY_PAGES: usize = 32;
        validate_stable_conversation_id(convo_id)?;
        let mut after_seq = parse_entry_cursor(cursor)?;
        if !matches!(message_type, None | Some("app") | Some("commit")) {
            return Err(OrchestratorError::InvalidInput(
                "getEntries message type must be app, commit, or absent".into(),
            ));
        }
        if from_epoch.zip(to_epoch).is_some_and(|(from, to)| from > to) {
            return Err(OrchestratorError::InvalidInput(
                "getEntries epoch range is inverted".into(),
            ));
        }
        if limit == 0 || limit > 100 {
            return Err(OrchestratorError::Api(
                "getEntries limit must be between 1 and 100".into(),
            ));
        }
        let call = self.authority_for_call()?;
        let mut envelopes = Vec::new();
        for _ in 0..MAX_ENTRY_PAGES {
            let remaining = limit.saturating_sub(envelopes.len() as u32).max(1);
            let path = canonical_get_entries_path(
                call.snapshot.device_id(),
                convo_id,
                after_seq,
                remaining,
            );
            let response = self.canonical_get_response(&call, &path).await?;
            let body = Self::require_successful_response("getEntries", response)?;
            let decoded = decode_clean_chat_response(CanonicalOperation::GetEntries.into(), body)
                .map_err(|e| {
                OrchestratorError::Api(format!("Canonical getEntries decode: {e}"))
            })?;
            let output: catbird_atproto::blue_catbird::chat::get_entries::GetEntriesOutput<String> =
                serde_json::from_slice(&decoded).map_err(|e| {
                    OrchestratorError::Api(format!("Canonical getEntries JSON: {e}"))
                })?;
            let next_after_seq = output.next_after_seq;
            if next_after_seq < after_seq
                || (output.has_more && next_after_seq == after_seq)
                || next_after_seq > 9_007_199_254_740_991
            {
                return Err(OrchestratorError::Api(
                    "getEntries returned a non-progressing or invalid cursor".into(),
                ));
            }
            if output.entries.len() > remaining as usize {
                return Err(OrchestratorError::Api(
                    "getEntries returned more entries than the requested page limit".into(),
                ));
            }
            let mut last_page_seq = after_seq;
            for entry in output.entries {
                let entry_seq = canonical_entry_sequence(&entry);
                if entry_seq <= last_page_seq
                    || entry_seq > next_after_seq
                    || entry_seq > 9_007_199_254_740_991
                {
                    return Err(OrchestratorError::Api(
                        "getEntries returned entries outside its monotonic cursor window".into(),
                    ));
                }
                last_page_seq = entry_seq;
                let Some((kind, envelope)) = canonical_entry_envelope(entry, convo_id)? else {
                    continue;
                };
                let type_matches = match message_type {
                    Some("app") => kind == CanonicalEntryKind::Application,
                    Some("commit") => kind == CanonicalEntryKind::Commit,
                    _ => true,
                };
                let epoch_matches = from_epoch
                    .is_none_or(|epoch| envelope.server_epoch.unwrap_or_default() >= epoch as u64)
                    && to_epoch.is_none_or(|epoch| {
                        envelope.server_epoch.unwrap_or_default() <= epoch as u64
                    });
                if type_matches && epoch_matches {
                    envelopes.push(envelope);
                }
            }
            after_seq = next_after_seq;
            if !output.has_more || envelopes.len() >= limit as usize {
                return Ok((envelopes, Some(after_seq.to_string())));
            }
        }
        Err(OrchestratorError::Api(format!(
            "getEntries exceeded the {MAX_ENTRY_PAGES}-page safety bound"
        )))
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────

fn validate_device_inventory_item(
    device: &catbird_atproto::blue_catbird::chat::DeviceView<String>,
) -> Result<()> {
    let parsed = uuid::Uuid::parse_str(device.device_id.as_str()).map_err(|_| {
        OrchestratorError::Api("device inventory contains an invalid device UUID".into())
    })?;
    let package_total = device
        .available_package_count
        .checked_add(device.reserved_package_count);
    if parsed.get_version() != Some(uuid::Version::Random)
        || parsed.get_variant() != uuid::Variant::RFC4122
        || parsed.to_string() != device.device_id.as_str()
        || device.auth_generation < 1
        || device.status.is_empty()
        || device.signature_public_key.len() != 32
        || derive_key_id(device.signature_public_key.as_ref()) != device.key_id.as_str()
        || device.available_package_count < 0
        || device.reserved_package_count < 0
        || package_total.is_none_or(|total| total > 1_000)
    {
        return Err(OrchestratorError::Api(
            "device inventory contains invalid identity or package-count data".into(),
        ));
    }
    Ok(())
}

fn validate_prepared_request_scope(
    request: &PreparedRequest,
    snapshot: &AuthoritySnapshot,
) -> Result<()> {
    let expected_method = match request.operation {
        CanonicalOperation::GetConversations
        | CanonicalOperation::GetBlob
        | CanonicalOperation::GetBlobUsage
        | CanonicalOperation::GetConversationState
        | CanonicalOperation::GetDevices
        | CanonicalOperation::GetDeviceKey
        | CanonicalOperation::GetDirectRequestOutcome
        | CanonicalOperation::GetEntries
        | CanonicalOperation::GetLeafRecoveryInbox
        | CanonicalOperation::GetOwnDevices
        | CanonicalOperation::GetPendingWelcomes => "GET",
        CanonicalOperation::SubscribeEvents | CanonicalOperation::UploadBlob => {
            return Err(OrchestratorError::InvalidInput(
                "streaming and octet-stream operations cannot use the prepared JSON gateway".into(),
            ));
        }
        _ => "POST",
    };
    if request.method != expected_method {
        return Err(OrchestratorError::InvalidInput(format!(
            "prepared request method does not match {:?}",
            request.operation
        )));
    }
    if !request.path.starts_with('/')
        || request.path.starts_with("//")
        || request.path.contains(['#', '\\'])
        || request.path.chars().any(char::is_control)
    {
        return Err(OrchestratorError::InvalidInput(
            "prepared XRPC target must be a relative canonical path".into(),
        ));
    }
    let base = url::Url::parse("https://nest.invalid/")
        .map_err(|_| OrchestratorError::InvalidInput("invalid validation origin".into()))?;
    let url = url::Url::options()
        .base_url(Some(&base))
        .parse(&request.path)
        .map_err(|_| OrchestratorError::InvalidInput("prepared XRPC path is invalid".into()))?;
    if url.scheme() != "https"
        || url.host_str() != Some("nest.invalid")
        || url.port().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.path() != request.operation.path()
    {
        return Err(OrchestratorError::InvalidInput(
            "prepared XRPC target does not match the declared operation".into(),
        ));
    }
    let mut query_device_id: Option<String> = None;
    for (name, value) in url.query_pairs() {
        if name == "actorDeviceId" && query_device_id.replace(value.into_owned()).is_some() {
            return Err(OrchestratorError::Credential(
                "prepared request contains duplicate caller device scope".into(),
            ));
        }
    }
    if query_device_id
        .as_deref()
        .is_some_and(|device_id| device_id != snapshot.device_id())
    {
        return Err(OrchestratorError::Credential(
            "prepared request caller scope does not match admitted device".into(),
        ));
    }
    if expected_method == "GET" && query_device_id.as_deref() != Some(snapshot.device_id()) {
        return Err(OrchestratorError::Credential(
            "prepared GET request omitted the admitted caller device scope".into(),
        ));
    }
    if let Some(body) = request.body.as_deref() {
        let value: serde_json::Value = serde_json::from_slice(body).map_err(|_| {
            OrchestratorError::Serialization("prepared XRPC body is not valid JSON".into())
        })?;
        let signed_body = value
            .pointer("/directRequest/body")
            .or_else(|| value.pointer("/directRequest/signedRequest/body"))
            .or_else(|| value.pointer("/signedRequest/body"))
            .unwrap_or(&value);
        let actor_did = signed_body
            .get("actorDid")
            .and_then(serde_json::Value::as_str);
        if actor_did.is_some_and(|actor_did| actor_did != snapshot.actor_did()) {
            return Err(OrchestratorError::Credential(
                "prepared request caller scope does not match admitted account".into(),
            ));
        }
        let actor_device_id = signed_body
            .get("actorDeviceId")
            .and_then(serde_json::Value::as_str);
        let enrollment_device_id = signed_body
            .get("deviceId")
            .and_then(serde_json::Value::as_str);
        if [actor_device_id, enrollment_device_id]
            .into_iter()
            .flatten()
            .any(|device_id| device_id != snapshot.device_id())
        {
            return Err(OrchestratorError::Credential(
                "prepared request caller scope does not match admitted device".into(),
            ));
        }
        let device_id = actor_device_id.or(enrollment_device_id);
        if expected_method == "POST"
            && request.operation != CanonicalOperation::GetSubscriptionTicket
            && (actor_did != Some(snapshot.actor_did()) || device_id != Some(snapshot.device_id()))
        {
            return Err(OrchestratorError::Credential(
                "prepared POST request omitted the admitted caller scope".into(),
            ));
        }
    } else if expected_method == "POST" {
        return Err(OrchestratorError::Credential(
            "prepared POST request omitted its caller-scoped body".into(),
        ));
    }
    Ok(())
}

fn validate_stable_conversation_id(conversation_id: &str) -> Result<()> {
    let parsed = uuid::Uuid::parse_str(conversation_id).map_err(|_| {
        OrchestratorError::InvalidInput(
            "public clean-chat routes require a stable conversation UUID".into(),
        )
    })?;
    if parsed.get_version() != Some(uuid::Version::Random)
        || parsed.get_variant() != uuid::Variant::RFC4122
        || parsed.to_string() != conversation_id
    {
        return Err(OrchestratorError::InvalidInput(
            "public clean-chat routes require a canonical lowercase UUIDv4 conversation ID".into(),
        ));
    }
    Ok(())
}

fn parse_entry_cursor(cursor: Option<&str>) -> Result<i64> {
    let Some(cursor) = cursor else {
        return Ok(0);
    };
    let value = cursor.parse::<i64>().map_err(|_| {
        OrchestratorError::InvalidInput("getEntries cursor is not a nonnegative integer".into())
    })?;
    if !(0..=9_007_199_254_740_991).contains(&value) || value.to_string() != cursor {
        return Err(OrchestratorError::InvalidInput(
            "getEntries cursor is not canonical or is outside the safe-integer range".into(),
        ));
    }
    Ok(value)
}

fn canonical_get_conversations_path(
    actor_device_id: &str,
    limit: u32,
    cursor: Option<&str>,
) -> String {
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    query.append_pair("actorDeviceId", actor_device_id);
    query.append_pair("limit", &limit.to_string());
    query.append_pair("supportedProtocolVersions", "1");
    query.append_pair("supportedProtocolVersions", "2");
    if let Some(cursor) = cursor {
        query.append_pair("pageCursor", cursor);
    }
    format!(
        "/xrpc/blue.catbird.chat.getConversations?{}",
        query.finish()
    )
}

fn canonical_get_entries_path(
    actor_device_id: &str,
    convo_id: &str,
    after_seq: i64,
    limit: u32,
) -> String {
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    query.append_pair("actorDeviceId", actor_device_id);
    query.append_pair("afterSeq", &after_seq.to_string());
    query.append_pair("conversationId", convo_id);
    query.append_pair("limit", &limit.to_string());
    format!("/xrpc/blue.catbird.chat.getEntries?{}", query.finish())
}

fn canonical_get_own_devices_path(
    actor_device_id: &str,
    limit: u32,
    cursor: Option<&str>,
) -> String {
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    query.append_pair("actorDeviceId", actor_device_id);
    query.append_pair("limit", &limit.to_string());
    if let Some(cursor) = cursor {
        query.append_pair("pageCursor", cursor);
    }
    format!("/xrpc/blue.catbird.chat.getOwnDevices?{}", query.finish())
}

fn canonical_get_pending_welcomes_path(
    actor_device_id: &str,
    inventory_session_id: &str,
    limit: u32,
    cursor: Option<&str>,
) -> String {
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    query.append_pair("actorDeviceId", actor_device_id);
    query.append_pair("inventorySessionId", inventory_session_id);
    query.append_pair("supportedProtocolVersions", "1");
    query.append_pair("supportedProtocolVersions", "2");
    query.append_pair("limit", &limit.to_string());
    if let Some(cursor) = cursor {
        query.append_pair("pageCursor", cursor);
    }
    format!(
        "/xrpc/blue.catbird.chat.getPendingWelcomes?{}",
        query.finish()
    )
}

fn canonical_conversation_view(
    state: &catbird_atproto::blue_catbird::chat::ConversationState,
) -> Result<ConversationView> {
    let coordinates = &state.coordinates;
    let conversation_id = coordinates.conversation_id.to_string();
    validate_stable_conversation_id(&conversation_id)?;
    let epoch = u64::try_from(coordinates.epoch).map_err(|_| {
        OrchestratorError::Api("getConversations returned a negative conversation epoch".into())
    })?;
    if coordinates.group_id.is_empty()
        || coordinates.generation < 0
        || coordinates.state_version < 0
    {
        return Err(OrchestratorError::Api(
            "getConversations returned invalid conversation coordinates".into(),
        ));
    }
    let members = state
        .participants
        .iter()
        .map(|participant| MemberView {
            did: participant.user_did.to_string(),
            role: if participant.role.eq_ignore_ascii_case("admin") {
                MemberRole::Admin
            } else {
                MemberRole::Member
            },
        })
        .collect();
    Ok(ConversationView {
        canonical_state: Some(state.clone()),
        group_id: hex::encode(coordinates.group_id.as_ref()),
        conversation_id,
        epoch,
        members,
        metadata: None,
        created_at: None,
        updated_at: None,
        sequencer_did: None,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CanonicalEntryKind {
    Application,
    Commit,
}

fn canonical_entry_sequence(
    entry: &catbird_atproto::blue_catbird::chat::ConversationEntry<String>,
) -> i64 {
    use catbird_atproto::blue_catbird::chat::ConversationEntry;
    match entry {
        ConversationEntry::DirectRequestEntry(entry) => entry.seq,
        ConversationEntry::DirectRequestAcceptanceEntry(entry) => entry.seq,
        ConversationEntry::ApplicationEntry(entry) => entry.seq,
        ConversationEntry::CommitEntry(entry) => entry.seq,
        ConversationEntry::PolicyEntry(entry) => entry.seq,
        ConversationEntry::MetadataEntry(entry) => entry.seq,
        ConversationEntry::CreationEntry(entry) => entry.seq,
        ConversationEntry::ParticipantAcceptanceEntry(entry) => entry.seq,
        ConversationEntry::ConversationCloseEntry(entry) => entry.seq,
        ConversationEntry::ResetRequestEntry(entry) => entry.seq,
        ConversationEntry::ResetActivationEntry(entry) => entry.seq,
        ConversationEntry::LeafRecoveryFulfillmentEntry(entry) => entry.seq,
        ConversationEntry::LeaveRequestEntry(entry) => entry.seq,
        ConversationEntry::ZeroLeafLeaveEntry(entry) => entry.seq,
        ConversationEntry::LeaveCancellationEntry(entry) => entry.seq,
        ConversationEntry::LeaveCommitFulfillmentEntry(entry) => entry.seq,
    }
}

fn canonical_entry_envelope(
    entry: catbird_atproto::blue_catbird::chat::ConversationEntry<String>,
    requested_convo_id: &str,
) -> Result<Option<(CanonicalEntryKind, IncomingEnvelope)>> {
    use catbird_atproto::blue_catbird::chat::ConversationEntry;
    let kind = match &entry {
        ConversationEntry::ApplicationEntry(_) => CanonicalEntryKind::Application,
        ConversationEntry::CommitEntry(_)
        | ConversationEntry::LeafRecoveryFulfillmentEntry(_)
        | ConversationEntry::LeaveCommitFulfillmentEntry(_) => CanonicalEntryKind::Commit,
        _ => return Ok(None),
    };
    let row =
        serde_json::to_value(entry).map_err(|error| OrchestratorError::Api(error.to_string()))?;
    Ok(
        IncomingEnvelope::from_canonical_entry(&row, requested_convo_id)?
            .map(|envelope| (kind, envelope)),
    )
}

fn parse_dt(s: &str) -> Option<DateTime<Utc>> {
    s.parse::<DateTime<Utc>>().ok().or_else(|| {
        DateTime::parse_from_rfc3339(s)
            .ok()
            .map(|dt| dt.with_timezone(&Utc))
    })
}

// ── MLSAPIClient implementation ─────────────────────────────────────────

#[async_trait]
impl MLSAPIClient for BirdApiClient {
    async fn is_authenticated_as(&self, did: &str) -> bool {
        self.did == did
    }

    async fn current_did(&self) -> Option<String> {
        Some(self.did.clone())
    }

    async fn submit_prepared_request(&self, request: PreparedRequest) -> Result<GatewayResponse> {
        let call = self.authority_for_call()?;
        validate_prepared_request_scope(&request, &call.snapshot)?;
        let PreparedRequest {
            method, path, body, ..
        } = request;

        let response = match method.as_str() {
            "GET" => {
                if body.is_some() {
                    return Err(OrchestratorError::Api(
                        "prepared GET request unexpectedly contained a body".into(),
                    ));
                }
                call.nest
                    .get_clean_chat_response(&call.snapshot, &path)
                    .await
                    .map_err(|error| self.map_authority_error(&call, error))?
            }
            "POST" => call
                .nest
                .post_clean_chat_signed_response(
                    &call.snapshot,
                    &path,
                    body.ok_or_else(|| {
                        OrchestratorError::Api(
                            "prepared POST request did not contain a body".into(),
                        )
                    })?,
                )
                .await
                .map_err(|error| self.map_authority_error(&call, error))?,
            other => {
                return Err(OrchestratorError::Api(format!(
                    "unsupported prepared request method: {other}"
                )))
            }
        };
        self.observe_remote_binding_failure(&call, &response);
        Ok(GatewayResponse {
            status: response.status,
            content_type: response.content_type,
            body: response.body,
        })
    }

    async fn get_conversations(
        &self,
        limit: u32,
        cursor: Option<&str>,
    ) -> Result<ConversationListPage> {
        self.get_canonical_conversations(limit, cursor).await
    }

    async fn get_messages(
        &self,
        convo_id: &str,
        cursor: Option<&str>,
        limit: u32,
        message_type: Option<&str>,
        from_epoch: Option<u32>,
        to_epoch: Option<u32>,
    ) -> Result<(Vec<IncomingEnvelope>, Option<String>)> {
        self.get_canonical_entries(convo_id, cursor, limit, message_type, from_epoch, to_epoch)
            .await
    }

    async fn get_key_packages(
        &self,
        actor_device_id: &str,
        _dids: &[String],
    ) -> Result<Vec<KeyPackageRef>> {
        let call = self.authority_for_call()?;
        if actor_device_id != call.snapshot.device_id() {
            return Err(OrchestratorError::Credential(
                "key-package caller scope does not match admitted authority".into(),
            ));
        }
        Err(OrchestratorError::Api(
            "canonical raw key-package lookup is unsupported: getDevices exposes addressability and counts but never exports reserved KeyPackage bytes"
                .into(),
        ))
    }

    async fn get_key_package_stats(&self) -> Result<KeyPackageStats> {
        let call = self.authority_for_call()?;
        let devices = self.get_own_devices_all(&call).await?;
        let mut own = devices
            .into_iter()
            .filter(|device| device.device_id.as_str() == call.snapshot.device_id());
        let device = own.next().ok_or_else(|| {
            OrchestratorError::Credential(
                "admitted device is absent from authoritative device inventory".into(),
            )
        })?;
        if own.next().is_some() {
            return Err(OrchestratorError::Api(
                "authoritative device inventory contains duplicate device IDs".into(),
            ));
        }
        if device.auth_generation != call.snapshot.auth_generation()
            || device.status.as_str() != "active"
            || device.key_id.as_str() != call.snapshot.signer_handle()
            || device.signature_public_key.as_ref() != call.snapshot.signer_public_key()
        {
            return Err(OrchestratorError::Credential(
                "authoritative device inventory does not match the admitted signer generation"
                    .into(),
            ));
        }
        let available = u32::try_from(device.available_package_count).map_err(|_| {
            OrchestratorError::Api("device inventory contains a negative package count".into())
        })?;
        let reserved = u32::try_from(device.reserved_package_count).map_err(|_| {
            OrchestratorError::Api("device inventory contains a negative package count".into())
        })?;
        let total = available.checked_add(reserved).ok_or_else(|| {
            OrchestratorError::Api("device inventory package count overflowed".into())
        })?;
        Ok(KeyPackageStats { available, total })
    }

    async fn sync_key_packages(
        &self,
        _local_hashes: &[String],
        device_id: &str,
    ) -> Result<KeyPackageSyncResult> {
        let call = self.authority_for_call()?;
        if device_id != call.snapshot.device_id() {
            return Err(OrchestratorError::Credential(
                "key-package sync caller scope does not match admitted authority".into(),
            ));
        }
        Err(OrchestratorError::Api(
            "canonical key-package hash reconciliation is unsupported: the clean-chat protocol exposes no syncKeyPackages mutation"
                .into(),
        ))
    }

    async fn list_devices(&self, actor_device_id: &str) -> Result<Vec<DeviceInfo>> {
        let call = self.authority_for_call()?;
        if actor_device_id != call.snapshot.device_id() {
            return Err(OrchestratorError::Credential(
                "device-list caller scope does not match admitted authority".into(),
            ));
        }
        self.get_own_devices_all(&call)
            .await?
            .into_iter()
            .map(|device| {
                Ok(DeviceInfo {
                    device_id: device.device_id.to_string(),
                    mls_did: format!("{}#{}", self.did, device.device_id),
                    device_uuid: device.device_id.to_string(),
                    created_at: parse_dt(&device.created_at.to_string()),
                    key_id: Some(device.key_id.to_string()),
                    signature_public_key: Some(device.signature_public_key.to_vec()),
                    auth_generation: Some(device.auth_generation),
                    status: Some(device.status.to_string()),
                    available_package_count: Some(
                        u32::try_from(device.available_package_count).map_err(|_| {
                            OrchestratorError::Api(
                                "device inventory contains a negative package count".into(),
                            )
                        })?,
                    ),
                    reserved_package_count: Some(
                        u32::try_from(device.reserved_package_count).map_err(|_| {
                            OrchestratorError::Api(
                                "device inventory contains a negative package count".into(),
                            )
                        })?,
                    ),
                })
            })
            .collect()
    }

    async fn get_group_info(&self, convo_id: &str) -> Result<Vec<u8>> {
        validate_stable_conversation_id(convo_id)?;
        Err(OrchestratorError::Api(
            "canonical GroupInfo retrieval is unsupported: getConversationState carries public coordinates but no GroupInfo artifact"
                .into(),
        ))
    }

    async fn get_welcome(&self, convo_id: &str) -> Result<Vec<u8>> {
        let call = self.authority_for_call()?;
        let _ = self.fetch_pending_welcome(&call, convo_id).await?;
        Err(OrchestratorError::Api(
            "pending Welcome is cached but cannot be delivered: shared core has no post-join acknowledgement hook, and acknowledging before durable MLS join is forbidden"
                .into(),
        ))
    }

    async fn get_group_metadata_blob(
        &self,
        convo_id: &str,
        _group_id_hex: &str,
        blob_locator: &str,
    ) -> Result<Vec<u8>> {
        validate_stable_conversation_id(convo_id)?;
        self.get_blob(blob_locator).await
    }
}

impl BirdApiClient {
    /// Acknowledge exactly the pending Welcome previously fetched for this
    /// device, but only after the caller has successfully processed and
    /// durably stored the MLS join. The shared orchestrator currently lacks
    /// that post-join hook, so this method is intentionally not called from
    /// `get_welcome` and must never be moved there.
    pub(crate) async fn acknowledge_cached_welcome_after_join(
        &self,
        conversation_id: &str,
    ) -> Result<()> {
        validate_stable_conversation_id(conversation_id)?;
        let call = self.authority_for_call()?;
        let cached = self
            .pending_welcomes
            .lock()
            .unwrap()
            .get(conversation_id)
            .cloned()
            .ok_or_else(|| {
                OrchestratorError::InvalidInput(
                    "no fetched pending Welcome is available to acknowledge".into(),
                )
            })?;
        if cached.coordinates.conversation_id.as_str() != conversation_id {
            return Err(OrchestratorError::Credential(
                "cached Welcome acknowledgement escaped its conversation scope".into(),
            ));
        }
        if cached.authority != call.snapshot {
            return Err(OrchestratorError::Credential(
                "cached Welcome does not belong to the admitted caller authority".into(),
            ));
        }
        let body = json!({
            "$type": "blue.catbird.chat.defs#welcomeAcknowledgementBody",
            "signatureDomain": "CATBIRD-CHAT-WELCOME-ACK\u{0000}",
            "welcomeId": cached.welcome_id,
            "transitionSeq": cached.transition_seq,
            "coordinates": cached.coordinates,
            "actorDid": call.snapshot.actor_did(),
            "actorDeviceId": call.snapshot.device_id(),
            "keyId": call.snapshot.signer_handle(),
            "authGeneration": call.snapshot.auth_generation(),
            "idempotencyKey": cached.acknowledgement_idempotency_key,
            "signedAt": Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
        });
        let signer =
            self.signer.lock().unwrap().clone().ok_or_else(|| {
                OrchestratorError::Credential("clean-chat signer is absent".into())
            })?;
        let prepared = signer
            .prepare_signed_request(
                CleanChatSigningContext {
                    actor_did: call.snapshot.actor_did().to_owned(),
                    device_id: call.snapshot.device_id().to_owned(),
                    auth_generation: Some(call.snapshot.auth_generation()),
                },
                CanonicalOperation::AcknowledgeWelcome,
                serde_json::to_vec(&body).map_err(|error| {
                    OrchestratorError::Serialization(format!(
                        "serialize Welcome acknowledgement: {error}"
                    ))
                })?,
            )
            .await?;
        validate_prepared_request_scope(&prepared, &call.snapshot)?;
        let request_body = prepared.body.ok_or_else(|| {
            OrchestratorError::Serialization(
                "prepared Welcome acknowledgement omitted its body".into(),
            )
        })?;
        let response = call
            .nest
            .post_clean_chat_signed_response(
                &call.snapshot,
                "/xrpc/blue.catbird.chat.acknowledgeWelcome",
                request_body,
            )
            .await
            .map_err(|error| self.map_authority_error(&call, error))?;
        self.observe_remote_binding_failure(&call, &response);
        let response = Self::require_successful_response(
            "acknowledgeWelcome",
            GatewayResponse {
                status: response.status,
                content_type: response.content_type,
                body: response.body,
            },
        )?;
        decode_clean_chat_response(CanonicalOperation::AcknowledgeWelcome.into(), response)
            .map_err(|error| {
                OrchestratorError::Serialization(format!("decode Welcome acknowledgement: {error}"))
            })?;
        self.pending_welcomes
            .lock()
            .unwrap()
            .remove(conversation_id);
        Ok(())
    }

    /// Send an already-encrypted application payload through the canonical
    /// Nest endpoint.
    ///
    /// The orchestrator's current API intentionally owns message composition;
    /// BIRDaemon has no active conversation-creation path, so this remains an
    /// inherent compatibility helper for the daemon's receive/reply loop and
    /// runtime tests. It is deliberately not part of `MLSAPIClient`, and it
    /// keeps the stable conversation ID separate from the MLS group ID.
    pub async fn send_message_with_id(
        &self,
        convo_id: &str,
        ciphertext: &[u8],
        epoch: u64,
        msg_id: &str,
    ) -> Result<SendMessageResponse> {
        validate_stable_conversation_id(convo_id)?;
        let call = self.authority_for_call()?;
        let snapshot = &call.snapshot;
        let signer = {
            let s = self.signer.lock().unwrap();
            s.clone().ok_or_else(|| {
                OrchestratorError::Credential("Signer not configured for clean chat".into())
            })?
        };

        // Coordinates are indexed by the stable conversation ID. A group ID
        // is only signed as MLS state and is never used as the conversation
        // identity or as a fallback when the IDs differ.
        let coords = {
            let map = self.cached_coordinates.lock().unwrap();
            map.get(convo_id).cloned()
        };
        let coords = match coords {
            Some(c) => c,
            None => {
                let _ = self
                    .get_canonical_conversations_with_call(&call, 50, None)
                    .await?;
                let map = self.cached_coordinates.lock().unwrap();
                map.get(convo_id).cloned().ok_or_else(|| {
                    OrchestratorError::Api(format!(
                        "Conversation coordinates not found for {convo_id}"
                    ))
                })?
            }
        };

        let body_bytes = build_application_send_body(
            snapshot.actor_did(),
            snapshot.device_id(),
            snapshot.signer_handle(),
            snapshot.auth_generation(),
            convo_id,
            msg_id,
            &coords.group_id,
            epoch,
            coords.state_version,
            &coords.confirmation_tag,
            &coords.group_context_hash,
            ciphertext,
        )?;

        let signing_context = CleanChatSigningContext {
            actor_did: snapshot.actor_did().to_string(),
            device_id: snapshot.device_id().to_string(),
            auth_generation: Some(snapshot.auth_generation()),
        };
        let prepared_request = signer
            .prepare_signed_request(signing_context, CanonicalOperation::SendMessage, body_bytes)
            .await?;
        validate_prepared_request_scope(&prepared_request, snapshot)?;
        let request_body = prepared_request
            .body
            .ok_or_else(|| OrchestratorError::Api("Empty signed request body".into()))?;

        let response = call
            .nest
            .post_clean_chat_signed_response(
                snapshot,
                "/xrpc/blue.catbird.chat.sendMessage",
                request_body,
            )
            .await
            .map_err(|error| self.map_authority_error(&call, error))?;
        self.observe_remote_binding_failure(&call, &response);
        let response_bytes = Self::require_successful_response(
            "sendMessage",
            GatewayResponse {
                status: response.status,
                content_type: response.content_type,
                body: response.body,
            },
        )?;
        let decoded =
            decode_clean_chat_response(CanonicalOperation::SendMessage.into(), response_bytes)
                .map_err(|e| OrchestratorError::Api(format!("decode sendMessage response: {e}")))?;
        let output: catbird_atproto::blue_catbird::chat::send_message::SendMessageOutput<String> =
            serde_json::from_slice(&decoded)
                .map_err(|e| OrchestratorError::Api(format!("parse sendMessage output: {e}")))?;

        let seq = u64::try_from(output.entry.seq).map_err(|_| {
            OrchestratorError::Api("sendMessage returned a negative sequence number".into())
        })?;
        let epoch = u64::try_from(output.entry.signed_request.body.prior.epoch).map_err(|_| {
            OrchestratorError::Api("sendMessage returned a negative MLS epoch".into())
        })?;
        Ok(SendMessageResponse {
            message_id: output.entry.entry_id.to_string(),
            seq,
            epoch,
        })
    }

    /// Download an encrypted blob by ID from the canonical Nest proxy.
    pub async fn get_blob(&self, blob_id: &str) -> Result<Vec<u8>> {
        #[cfg(debug_assertions)]
        self.effect_probe
            .blob_downloads
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let call = self.authority_for_call()?;
        let response = call
            .nest
            .get_blob(&call.snapshot, blob_id)
            .await
            .map_err(|error| self.map_authority_error(&call, error))?;
        self.observe_remote_binding_failure(&call, &response);
        if !(200..300).contains(&response.status) {
            return Err(OrchestratorError::ServerError {
                status: response.status,
                body: String::from_utf8_lossy(&response.body).into_owned(),
            });
        }
        if response
            .content_type
            .as_deref()
            .is_some_and(|content_type| {
                !content_type
                    .to_ascii_lowercase()
                    .starts_with("application/octet-stream")
            })
        {
            return Err(OrchestratorError::Api(
                "Canonical getBlob returned a non-octet-stream content type".into(),
            ));
        }
        Ok(response.body)
    }

    // ── Device Record Publishing (ATProto repo records) ────────────────

    /// Publish a `blue.catbird.chat.device` record to the user's ATProto repo.
    /// This allows other clients to verify that key packages belong to an authorized device.
    /// Mirrors `MLSDeviceRecordService.ensureDeviceRecordPublished` in CatbirdMLSCore.
    pub async fn ensure_device_record_published(&self, signature_public_key: &[u8]) -> Result<()> {
        // Check if a device record with this key already exists
        let existing = self.list_repo_records("blue.catbird.chat.device").await?;
        let our_key_b64 = B64.encode(signature_public_key);

        for record in &existing {
            if let Some(value) = record.get("value") {
                // Check if mlsSignaturePublicKey.$bytes matches our key
                if let Some(key_obj) = value.get("mlsSignaturePublicKey") {
                    let key_b64 = key_obj.get("$bytes").and_then(|v| v.as_str()).unwrap_or("");
                    if key_b64 == our_key_b64 {
                        tracing::info!("Device record already published");
                        return Ok(());
                    }
                }
            }
        }

        // Publish new device record
        let now = Utc::now().to_rfc3339();
        self.create_repo_record(
            "blue.catbird.chat.device",
            &json!({
                "$type": "blue.catbird.chat.device",
                "mlsSignaturePublicKey": { "$bytes": our_key_b64 },
                "algorithm": "ed25519",
                "createdAt": now,
            }),
        )
        .await?;

        tracing::info!("Published device record to ATProto repo");
        Ok(())
    }

    /// List records in the user's repo for a given collection.
    async fn list_repo_records(&self, collection: &str) -> Result<Vec<serde_json::Value>> {
        let output = self
            .raw_get_no_proxy(
                "com.atproto.repo.listRecords",
                &[
                    ("repo", &self.did),
                    ("collection", collection),
                    ("limit", "50"),
                ],
                &self.get_jwt().await?,
            )
            .await?;

        Ok(output
            .get("records")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default())
    }

    /// Create a record in the user's ATProto repo (no atproto-proxy, goes direct to PDS).
    async fn create_repo_record(
        &self,
        collection: &str,
        record: &serde_json::Value,
    ) -> Result<serde_json::Value> {
        let body = json!({
            "repo": self.did,
            "collection": collection,
            "validate": false,
            "record": record,
        });
        self.raw_post_no_proxy(
            "com.atproto.repo.createRecord",
            &body,
            &self.get_jwt().await?,
        )
        .await
    }

    /// GET without atproto-proxy header (direct PDS call).
    async fn raw_get_no_proxy(
        &self,
        nsid: &str,
        params: &[(&str, &str)],
        jwt: &str,
    ) -> Result<serde_json::Value> {
        let resp = self
            .http
            .get(self.xrpc_url(nsid))
            .header("Authorization", format!("Bearer {}", jwt))
            .query(params)
            .send()
            .await
            .map_err(|e| OrchestratorError::Api(format!("HTTP error: {e}")))?;

        let status = resp.status().as_u16();
        if status >= 400 {
            let body_text = resp.text().await.unwrap_or_default();
            return Err(OrchestratorError::ServerError {
                status,
                body: body_text,
            });
        }

        resp.json()
            .await
            .map_err(|e| OrchestratorError::Api(format!("JSON decode: {e}")))
    }

    /// POST without atproto-proxy header (direct PDS call).
    async fn raw_post_no_proxy(
        &self,
        nsid: &str,
        body: &serde_json::Value,
        jwt: &str,
    ) -> Result<serde_json::Value> {
        let resp = self
            .http
            .post(self.xrpc_url(nsid))
            .header("Authorization", format!("Bearer {}", jwt))
            .json(body)
            .send()
            .await
            .map_err(|e| OrchestratorError::Api(format!("HTTP error: {e}")))?;

        let status = resp.status().as_u16();
        if status >= 400 {
            let body_text = resp.text().await.unwrap_or_default();
            return Err(OrchestratorError::ServerError {
                status,
                body: body_text,
            });
        }

        resp.json()
            .await
            .map_err(|e| OrchestratorError::Api(format!("JSON decode: {e}")))
    }

    pub async fn send_typing_indicator(&self, _convo_id: &str, _is_typing: bool) -> Result<()> {
        #[cfg(debug_assertions)]
        self.effect_probe
            .typing_attempts
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        // Typing is a clean-chat operation, not a legacy sendMessage variant.
        // BIRDaemon currently has no canonical device-auth/MLS typing-payload
        // adapter, so never transmit fabricated ciphertext. The caller treats
        // this as a best-effort UX signal and continues with the real message.
        Err(typing_transport_unavailable())
    }
}

fn typing_transport_unavailable() -> OrchestratorError {
    OrchestratorError::Api(
        "MLS-encrypted typing payload adapter is not available in BIRDaemon".into(),
    )
}

/// Build the JSON body posted to `blue.catbird.chat.requestLeafRecovery`.
///
/// `epochAuthenticator` (ADR-002 / spec §8.6) and `failureMode` (ADR-008 D1 /
/// spec §8.6.1) are only included when present so pre-A7 / pre-D1 servers
/// continue to accept the call.
fn build_application_send_body(
    actor_did: &str,
    actor_device_id: &str,
    key_id: &str,
    auth_generation: i64,
    convo_id: &str,
    message_id: &str,
    group_id: &[u8],
    epoch: u64,
    state_version: i64,
    confirmation_tag: &[u8],
    group_context_hash: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    use sha2::Digest;
    validate_stable_conversation_id(convo_id)?;
    let convo_uuid = uuid::Uuid::parse_str(convo_id)
        .map_err(|e| OrchestratorError::Api(format!("invalid conversationId UUID: {e}")))?;
    let msg_uuid = uuid::Uuid::parse_str(message_id)
        .map_err(|e| OrchestratorError::Api(format!("invalid messageId UUID: {e}")))?;
    if msg_uuid.get_version() != Some(uuid::Version::Random)
        || msg_uuid.get_variant() != uuid::Variant::RFC4122
        || msg_uuid.to_string() != message_id
        || group_id.is_empty()
        || confirmation_tag.len() != 32
        || group_context_hash.len() != 32
        || ciphertext.is_empty()
        || auth_generation < 1
        || state_version < 0
    {
        return Err(OrchestratorError::InvalidInput(
            "application send coordinates are not canonical".into(),
        ));
    }
    let ciphertext_sha256 = sha2::Sha256::digest(ciphertext);

    let body = json!({
        "$type": "blue.catbird.chat.defs#applicationSendBody",
        "signatureDomain": "CATBIRD-CHAT-MESSAGE\u{0000}",
        "actorDid": actor_did,
        "actorDeviceId": actor_device_id,
        "keyId": key_id,
        "messageId": msg_uuid.to_string(),
        "authGeneration": auth_generation,
        "blobBindings": [],
        "aad": {
            "conversationId": B64.encode(convo_uuid.as_bytes()),
            "generation": 0,
            "messageId": B64.encode(msg_uuid.as_bytes()),
            "prior": {
                "confirmationTag": {"$bytes": B64.encode(confirmation_tag)},
                "conversationId": B64.encode(convo_uuid.as_bytes()),
                "epoch": epoch,
                "generation": 0,
                "groupContextHash": {"$bytes": B64.encode(group_context_hash)},
                "groupId": {"$bytes": B64.encode(group_id)},
                "lifecycle": "active",
                "stateVersion": state_version
            },
            "protocolVersion": "1"
        },
        "applicationMessage": {
            "bytes": {"$bytes": B64.encode(ciphertext)},
            "contentType": "privateMessageApplication",
            "framing": "mlsMessage",
            "sha256": {"$bytes": B64.encode(ciphertext_sha256)}
        },
        "prior": {
            "confirmationTag": {"$bytes": B64.encode(confirmation_tag)},
            "conversationId": convo_uuid.to_string(),
            "epoch": epoch,
            "generation": 0,
            "groupContextHash": {"$bytes": B64.encode(group_context_hash)},
            "groupId": {"$bytes": B64.encode(group_id)},
            "lifecycle": "active",
            "stateVersion": state_version
        },
        "signedAt": Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
    });

    serde_json::to_vec(&body)
        .map_err(|e| OrchestratorError::Api(format!("serialize applicationSendBody: {e}")))
}

#[cfg(test)]
mod tests {
    use super::{
        build_application_send_body, canonical_entry_envelope, canonical_get_conversations_path,
        canonical_get_entries_path, parse_entry_cursor, typing_transport_unavailable,
        validate_prepared_request_scope, validate_stable_conversation_id,
    };
    use crate::chat_authority::{derive_key_id, AuthoritySnapshot};
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    use catbird_mls::orchestrator::{CanonicalOperation, PreparedRequest};
    use serde_json::json;

    #[test]
    fn typing_transport_is_explicitly_unavailable_without_mls_payload() {
        let error = typing_transport_unavailable();
        assert!(
            matches!(error, catbird_mls::orchestrator::error::OrchestratorError::Api(message) if message.contains("MLS-encrypted typing payload"))
        );
    }

    #[test]
    fn canonical_read_path_contains_only_query_parameters() {
        let path = canonical_get_conversations_path("device-1", 25, Some("cursor"));
        assert_eq!(
            path,
            "/xrpc/blue.catbird.chat.getConversations?actorDeviceId=device-1&limit=25&supportedProtocolVersions=1&supportedProtocolVersions=2&pageCursor=cursor"
        );
    }

    #[test]
    fn canonical_entry_path_is_device_scoped_and_uses_stable_conversation_id() {
        let path =
            canonical_get_entries_path("device-1", "11111111-1111-4111-9111-111111111111", 8, 25);
        assert_eq!(
            path,
            "/xrpc/blue.catbird.chat.getEntries?actorDeviceId=device-1&afterSeq=8&conversationId=11111111-1111-4111-9111-111111111111&limit=25"
        );
    }

    #[test]
    fn entry_cursor_is_canonical_and_never_rewinds_on_invalid_input() {
        assert_eq!(parse_entry_cursor(None).unwrap(), 0);
        assert_eq!(parse_entry_cursor(Some("42")).unwrap(), 42);
        for invalid in ["", "01", "-1", "+1", "not-a-cursor", "9007199254740992"] {
            assert!(
                parse_entry_cursor(Some(invalid)).is_err(),
                "accepted {invalid}"
            );
        }
    }

    #[test]
    fn public_routes_reject_group_aliases_and_noncanonical_uuid_spellings() {
        assert!(validate_stable_conversation_id("11111111-1111-4111-9111-111111111111").is_ok());
        let uppercase = "aaaaaaaa-aaaa-4aaa-9aaa-aaaaaaaaaaaa".to_ascii_uppercase();
        for invalid in [
            "0202020202020202020202020202020202020202020202020202020202020202",
            uppercase.as_str(),
            "11111111-1111-1111-9111-111111111111",
        ] {
            assert!(validate_stable_conversation_id(invalid).is_err());
        }
    }

    #[test]
    fn prepared_requests_require_one_exact_immutable_caller_scope() {
        let public_key = vec![7_u8; 32];
        let snapshot = AuthoritySnapshot::new(
            "opaque-session".into(),
            "did:plc:alicefixtureaaaaaaaaaaaa".into(),
            "70707070-7070-4070-b070-707070707070".into(),
            7,
            derive_key_id(&public_key),
            public_key,
            1,
        )
        .unwrap();
        let request = |operation: CanonicalOperation,
                       method: &str,
                       path: &str,
                       body: Option<serde_json::Value>| PreparedRequest {
            operation,
            method: method.into(),
            path: path.into(),
            body: body.map(|body| serde_json::to_vec(&body).unwrap()),
        };

        for operation in [
            CanonicalOperation::GetDeviceKey,
            CanonicalOperation::GetDirectRequestOutcome,
        ] {
            let path = format!(
                "{}?actorDeviceId={}",
                operation.path(),
                snapshot.device_id()
            );
            assert!(validate_prepared_request_scope(
                &request(operation, "GET", &path, None),
                &snapshot
            )
            .is_ok());
            assert!(validate_prepared_request_scope(
                &request(operation, "POST", &path, None),
                &snapshot
            )
            .is_err());
        }

        assert!(validate_prepared_request_scope(
            &request(
                CanonicalOperation::GetConversations,
                "GET",
                "/xrpc/blue.catbird.chat.getConversations?actorDeviceId=70707070-7070-4070-b070-707070707070",
                None,
            ),
            &snapshot,
        )
        .is_ok());
        for path in [
            "/xrpc/blue.catbird.chat.getConversations",
            "/xrpc/blue.catbird.chat.getConversations?actorDeviceId=80808080-8080-4080-b080-808080808080",
            "/xrpc/blue.catbird.chat.getConversations?actorDeviceId=70707070-7070-4070-b070-707070707070&actorDeviceId=70707070-7070-4070-b070-707070707070",
        ] {
            assert!(validate_prepared_request_scope(
                &request(CanonicalOperation::GetConversations, "GET", path, None),
                &snapshot
            )
            .is_err());
        }

        assert!(validate_prepared_request_scope(
            &request(
                CanonicalOperation::GetEntries,
                "GET",
                "/xrpc/blue.catbird.chat.getConversations?actorDeviceId=70707070-7070-4070-b070-707070707070",
                None,
            ),
            &snapshot,
        )
        .is_err());
        for escaped in [
            "https://attacker.invalid/xrpc/blue.catbird.chat.getConversations?actorDeviceId=70707070-7070-4070-b070-707070707070",
            "//attacker.invalid/xrpc/blue.catbird.chat.getConversations?actorDeviceId=70707070-7070-4070-b070-707070707070",
            "/xrpc/blue.catbird.chat.getConversations?actorDeviceId=70707070-7070-4070-b070-707070707070#fragment",
        ] {
            assert!(validate_prepared_request_scope(
                &request(CanonicalOperation::GetConversations, "GET", escaped, None),
                &snapshot,
            )
            .is_err());
        }

        let valid_body = json!({
            "signedRequest": {"body": {
                "actorDid": "did:plc:alicefixtureaaaaaaaaaaaa",
                "actorDeviceId": "70707070-7070-4070-b070-707070707070",
            }}
        });
        assert!(validate_prepared_request_scope(
            &request(
                CanonicalOperation::SendMessage,
                "POST",
                "/xrpc/blue.catbird.chat.sendMessage",
                Some(valid_body)
            ),
            &snapshot,
        )
        .is_ok());
        assert!(validate_prepared_request_scope(
            &request(
                CanonicalOperation::SendMessage,
                "POST",
                "/xrpc/blue.catbird.chat.sendMessage",
                Some(json!({"signedRequest": {"body": {
                    "actorDeviceId": "70707070-7070-4070-b070-707070707070",
                }}})),
            ),
            &snapshot,
        )
        .is_err());
        assert!(validate_prepared_request_scope(
            &request(
                CanonicalOperation::SendMessage,
                "POST",
                "/xrpc/blue.catbird.chat.sendMessage",
                Some(json!({"signedRequest": {"body": {
                    "actorDid": "did:plc:alicefixtureaaaaaaaaaaaa",
                    "actorDeviceId": "70707070-7070-4070-b070-707070707070",
                    "deviceId": "80808080-8080-4080-b080-808080808080",
                }}})),
            ),
            &snapshot,
        )
        .is_err());
        assert!(validate_prepared_request_scope(
            &request(
                CanonicalOperation::GetConversations,
                "POST",
                "/xrpc/blue.catbird.chat.getConversations",
                Some(json!({"signedRequest": {"body": {
                    "actorDid": "did:plc:alicefixtureaaaaaaaaaaaa",
                    "actorDeviceId": "70707070-7070-4070-b070-707070707070",
                }}})),
            ),
            &snapshot,
        )
        .is_err());
    }

    #[test]
    fn application_send_body_keeps_stable_conversation_and_group_ids_distinct() {
        let conversation_id = "11111111-1111-4111-9111-111111111111";
        let message_id = "22222222-2222-4222-9222-222222222222";
        let body = build_application_send_body(
            "did:plc:alicefixtureaaaaaaaaaaaa",
            "70707070-7070-4070-b070-707070707070",
            "key-1",
            7,
            conversation_id,
            message_id,
            &[2; 32],
            4,
            9,
            &[3; 32],
            &[4; 32],
            b"ciphertext",
        )
        .expect("canonical application body");
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(body["prior"]["conversationId"], conversation_id);
        assert_eq!(body["prior"]["groupId"]["$bytes"], B64.encode([2; 32]));
        assert_eq!(
            body["aad"]["conversationId"],
            B64.encode(uuid::Uuid::parse_str(conversation_id).unwrap().as_bytes())
        );
        assert_ne!(
            body["prior"]["conversationId"],
            body["prior"]["groupId"]["$bytes"]
        );
    }

    #[test]
    fn canonical_entry_epoch_is_propagated_to_incoming_envelope() {
        let wire = json!({
            "$type": "blue.catbird.chat.defs#applicationEntry",
            "conversationId": "11111111-1111-4111-8111-111111111111",
            "entryId": "22222222-2222-4222-8222-222222222222",
            "receivedAt": "2026-08-16T00:00:00.000Z",
            "seq": 1,
            "signedRequest": {
                "body": {
                    "aad": {
                        "conversationId": "AA==",
                        "generation": 7,
                        "messageId": "AA==",
                        "prior": {
                            "confirmationTag": {"$bytes": "AA=="},
                            "conversationId": "11111111-1111-4111-8111-111111111111",
                            "epoch": 42,
                            "generation": 7,
                            "groupContextHash": {"$bytes": "AA=="},
                            "groupId": {"$bytes": "AA=="},
                            "lifecycle": "active",
                            "stateVersion": 1
                        },
                        "protocolVersion": "mls-v1"
                    },
                    "actorDeviceId": "11111111-1111-4111-8111-111111111111",
                    "actorDid": "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa",
                    "applicationMessage": {
                        "bytes": {"$bytes": "AQID"},
                        "contentType": "application/octet-stream",
                        "framing": "mls",
                        "sha256": "AA=="
                    },
                    "authGeneration": 7,
                    "blobBindings": [],
                    "keyId": "key-1",
                    "messageId": "33333333-3333-4333-8333-333333333333",
                    "prior": {
                        "confirmationTag": {"$bytes": "AA=="},
                        "conversationId": "11111111-1111-4111-8111-111111111111",
                        "epoch": 42,
                        "generation": 7,
                        "groupContextHash": {"$bytes": "AA=="},
                        "groupId": {"$bytes": "AA=="},
                        "lifecycle": "active",
                        "stateVersion": 1
                    },
                    "signatureDomain": "CATBIRD-CHAT-MESSAGE",
                    "signedAt": "2026-08-16T00:00:00Z"
                },
                "signature": {"$bytes": "AA=="}
            }
        });
        let entry = serde_json::from_str::<
            catbird_atproto::blue_catbird::chat::ConversationEntry<String>,
        >(&wire.to_string())
        .expect("generated application entry fixture");

        let (_, envelope) = canonical_entry_envelope(entry, "11111111-1111-4111-8111-111111111111")
            .expect("application entry is valid")
            .expect("application entry maps to envelope");
        assert_eq!(envelope.server_epoch, Some(42));
        assert_eq!(envelope.server_sequence, Some(1));
        assert_eq!(envelope.ciphertext, vec![1, 2, 3]);

        let mut mismatched_wire = wire;
        mismatched_wire["conversationId"] = json!("44444444-4444-4444-8444-444444444444");
        let mismatched_entry = serde_json::from_str::<
            catbird_atproto::blue_catbird::chat::ConversationEntry<String>,
        >(&mismatched_wire.to_string())
        .expect("generated mismatched entry fixture");
        let error =
            canonical_entry_envelope(mismatched_entry, "11111111-1111-4111-8111-111111111111")
                .unwrap_err();
        assert!(error.to_string().contains("conversation binding"));
    }
}

#[cfg(test)]
mod canonical_admission_projection_tests {
    use super::*;
    use catbird_mls::orchestrator::canonical_transport::{
        decode_conversation_state, decode_conversations_inventory, encode_conversation_state,
    };

    fn inventory(wire: serde_json::Value) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "items": [{"$type": "blue.catbird.chat.defs#conversationInventoryState", "state": wire}],
            "hasMore": true, "nextPageCursor": "page-2", "inventorySessionId": "inventory-session",
            "snapshotEventCursor": "event-fence", "snapshotExpiresAt": "2026-09-05T12:00:00.000Z"
        })).unwrap()
    }

    #[test]
    fn canonical_pending_and_accepted_leafless_views_keep_exact_snapshot() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../tests/fixtures/canonical-conversation-state.json"
        ))
        .unwrap();
        for (status, version) in [("pending", 41), ("active", 42)] {
            let mut wire = fixture.clone();
            wire["participants"][1]["status"] = serde_json::json!(status);
            wire["coordinates"]["stateVersion"] = serde_json::json!(version);
            wire["snapshotSeq"] = serde_json::json!(version + 4);
            let expected = decode_conversation_state(wire.to_string().as_bytes()).unwrap();
            let mut page = decode_conversations_inventory(&inventory(wire)).unwrap();
            assert_eq!(page.next_page_cursor.as_deref(), Some("page-2"));
            assert_eq!(page.inventory_session_id, "inventory-session");
            assert_eq!(page.snapshot_event_cursor, "event-fence");
            let catbird_atproto::blue_catbird::chat::ConversationInventoryItem::ConversationInventoryState(item) = page.items.remove(0) else { panic!("missing canonical state") };
            let state = item.state;
            assert_eq!(state, expected);
            let view = canonical_conversation_view(&state).unwrap();
            assert_eq!(view.canonical_state.as_ref(), Some(&state));
            assert_eq!(view.epoch, state.coordinates.epoch as u64);
            assert_eq!(
                view.group_id,
                hex::encode(state.coordinates.group_id.as_ref())
            );
            let persisted: ConversationView =
                serde_json::from_slice(&serde_json::to_vec(&view).unwrap()).unwrap();
            let retained = persisted.canonical_state.unwrap();
            assert_eq!(
                decode_conversation_state(&encode_conversation_state(&retained).unwrap()).unwrap(),
                state
            );
            assert_eq!(retained.participants[1].status, status);
            assert_eq!(retained.participants[1].leaf_count, 0);
            assert_eq!(
                retained.participants[1].invitation_provenance,
                state.participants[1].invitation_provenance
            );
            assert!(view.created_at.is_none());
            assert!(view.metadata.is_none());
        }
    }

    #[test]
    fn legacy_view_is_unknown_and_malformed_canonical_state_is_rejected() {
        let mut wire: serde_json::Value = serde_json::from_str(include_str!(
            "../tests/fixtures/canonical-conversation-state.json"
        ))
        .unwrap();
        let state = decode_conversation_state(wire.to_string().as_bytes()).unwrap();
        let view = canonical_conversation_view(&state).unwrap();
        let mut old_view = serde_json::to_value(view).unwrap();
        assert!(old_view
            .as_object_mut()
            .unwrap()
            .remove("canonicalState")
            .is_some());
        let legacy: ConversationView = serde_json::from_value(old_view).unwrap();
        assert!(legacy.canonical_state.is_none());
        wire["participants"][1]["status"] = serde_json::json!("unknown");
        assert!(decode_conversations_inventory(&inventory(wire)).is_err());
    }
}
