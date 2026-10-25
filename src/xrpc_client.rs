//! MLS gateway using opaque Nest authority for canonical chat requests.
//!
//! Prepared device-signed requests retain their exact bytes. The separate
//! AT Protocol repository helpers use the Jacquard session for PDS access.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use catbird_mls::orchestrator::{
    decode_clean_chat_response, CanonicalOperation, CleanChatAuthContext, CleanChatSigningContext,
    GatewayResponse, PreparedRequest,
};
use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::json;

use catbird_mls::orchestrator::error::{OrchestratorError, Result};
use catbird_mls::orchestrator::types::*;
use catbird_mls::orchestrator::MLSAPIClient;

use crate::chat_authority::{
    AuthorityError, AuthoritySnapshot, AuthorityState, InvalidationReason, NestClient,
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
    proxy_did: String,
    /// Optional clean-chat transport context. BIRDaemon's default jacquard
    /// session is bearer-only, so canonical reads remain fail-closed until
    /// the daemon receives the device-bound DPoP context.
    canonical_auth: Option<CleanChatAuthContext>,
    /// Clean-chat requests use only this opaque Nest session and immutable
    /// actor/device/JKT/generation snapshot. Jacquard is never used for this
    /// namespace.
    nest: Option<Arc<NestClient>>,
    authority: Option<Arc<AuthorityState>>,
    credentials: Option<Arc<FileCredentialStore>>,
    signer: Arc<Mutex<Option<Arc<dyn CleanChatRequestSigner>>>>,
    cached_coordinates:
        Arc<Mutex<HashMap<String, catbird_atproto::blue_catbird::chat::ConversationCoordinates>>>,
    /// Stored for re-authentication when refresh token also expires.
    handle: String,
    app_password: String,
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
            proxy_did: "did:web:mlschat.catbird.blue#atproto_mls".to_string(),
            canonical_auth: None,
            nest: None,
            authority: None,
            credentials: None,
            signer: Arc::new(Mutex::new(None)),
            cached_coordinates: Arc::new(Mutex::new(HashMap::new())),
            handle,
            app_password,
        }
    }

    /// Attach the platform-owned clean-chat authentication context.
    ///
    /// The daemon startup path currently has no DPoP key/JKT or auth-generation
    /// source. Without this context, canonical reads fail closed rather than
    /// silently falling back to legacy bearer-only reads.
    pub fn with_canonical_auth(mut self, auth: CleanChatAuthContext) -> Self {
        self.canonical_auth = Some(auth);
        self
    }

    pub fn with_chat_authority(
        mut self,
        nest: Arc<NestClient>,
        authority: Arc<AuthorityState>,
        credentials: Arc<FileCredentialStore>,
    ) -> Self {
        self.nest = Some(nest);
        self.authority = Some(authority);
        self.credentials = Some(credentials);
        self
    }

    pub fn set_signer(&self, signer: Arc<dyn CleanChatRequestSigner>) {
        let mut s = self.signer.lock().unwrap();
        *s = Some(signer);
    }

    pub fn clear_chat_authority(&self, reason: InvalidationReason) {
        if let Some(authority) = &self.authority {
            if let Err(error) = authority.invalidate(reason) {
                tracing::error!(error = %error, "Failed to persist clean-chat invalidation");
            }
        }
    }

    fn xrpc_url(&self, nsid: &str) -> String {
        format!("{}/xrpc/{}", self.pds_endpoint, nsid)
    }

    /// Get current access JWT from the jacquard session.
    async fn get_jwt(&self) -> Result<String> {
        match self.session.access_token().await {
            Some(token) => Self::extract_jwt(token),
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
                Self::extract_jwt(token)
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
                    .transpose()?
                    .ok_or_else(|| {
                        OrchestratorError::Api("No token after re-authentication".into())
                    })
            }
        }
    }

    fn extract_jwt(token: jacquard_common::AuthorizationToken) -> Result<String> {
        match token {
            jacquard_common::AuthorizationToken::Bearer(token) => Ok(token.to_string()),
            jacquard_common::AuthorizationToken::Dpop(_)
            | jacquard_common::AuthorizationToken::Delegation(_) => {
                Err(OrchestratorError::Credential(
                    "PDS repository helpers require a bearer credential session".into(),
                ))
            }
        }
    }

    fn is_token_error(status: u16, body: &str) -> bool {
        (status == 400 || status == 401)
            && (body.contains("ExpiredToken") || body.contains("InvalidToken"))
    }

    // ── Request methods with automatic token refresh ─────────────────────

    /// POST an XRPC procedure, return parsed JSON.
    async fn post(&self, nsid: &str, body: &serde_json::Value) -> Result<serde_json::Value> {
        let jwt = self.get_jwt().await?;
        let result = self.raw_post(nsid, body, &jwt).await;
        match &result {
            Err(OrchestratorError::ServerError {
                status,
                body: resp_body,
            }) if Self::is_token_error(*status, resp_body) => {
                let jwt = self.refresh_jwt().await?;
                self.raw_post(nsid, body, &jwt).await
            }
            _ => result,
        }
    }

    /// POST but discard the response body.
    async fn post_void(&self, nsid: &str, body: &serde_json::Value) -> Result<()> {
        let jwt = self.get_jwt().await?;
        let result = self.raw_post_void(nsid, body, &jwt).await;
        match &result {
            Err(OrchestratorError::ServerError {
                status,
                body: resp_body,
            }) if Self::is_token_error(*status, resp_body) => {
                let jwt = self.refresh_jwt().await?;
                self.raw_post_void(nsid, body, &jwt).await
            }
            _ => result,
        }
    }

    /// GET an XRPC query, return parsed JSON.
    async fn get(&self, nsid: &str, params: &[(&str, &str)]) -> Result<serde_json::Value> {
        let jwt = self.get_jwt().await?;
        let result = self.raw_get(nsid, params, &jwt).await;
        match &result {
            Err(OrchestratorError::ServerError {
                status,
                body: resp_body,
            }) if Self::is_token_error(*status, resp_body) => {
                let jwt = self.refresh_jwt().await?;
                self.raw_get(nsid, params, &jwt).await
            }
            _ => result,
        }
    }

    // ── Raw HTTP helpers (no retry) ──────────────────────────────────────

    async fn raw_post(
        &self,
        nsid: &str,
        body: &serde_json::Value,
        jwt: &str,
    ) -> Result<serde_json::Value> {
        let resp = self
            .http
            .post(self.xrpc_url(nsid))
            .header("Authorization", format!("Bearer {}", jwt))
            .header("atproto-proxy", &self.proxy_did)
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

    async fn raw_post_void(&self, nsid: &str, body: &serde_json::Value, jwt: &str) -> Result<()> {
        let resp = self
            .http
            .post(self.xrpc_url(nsid))
            .header("Authorization", format!("Bearer {}", jwt))
            .header("atproto-proxy", &self.proxy_did)
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
        Ok(())
    }

    async fn raw_get(
        &self,
        nsid: &str,
        params: &[(&str, &str)],
        jwt: &str,
    ) -> Result<serde_json::Value> {
        let resp = self
            .http
            .get(self.xrpc_url(nsid))
            .header("Authorization", format!("Bearer {}", jwt))
            .header("atproto-proxy", &self.proxy_did)
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

    fn authority_for_call(
        &self,
    ) -> Result<(Arc<NestClient>, Arc<AuthorityState>, AuthoritySnapshot)> {
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
        Ok((nest, authority, snapshot))
    }

    fn map_authority_error(
        &self,
        authority: &AuthorityState,
        snapshot: &AuthoritySnapshot,
        error: AuthorityError,
    ) -> OrchestratorError {
        let reason = match error {
            AuthorityError::JktMismatch => InvalidationReason::JktChanged,
            AuthorityError::AccountMismatch => InvalidationReason::AccountChanged,
            AuthorityError::GenerationMismatch => InvalidationReason::GenerationChanged,
            AuthorityError::Remote => InvalidationReason::Unauthorized,
            _ => return OrchestratorError::Api("clean-chat Nest authority request failed".into()),
        };
        if let Err(error) = authority.invalidate_if_matches(snapshot, reason) {
            tracing::error!(error = %error, "Failed to persist clean-chat invalidation");
        }
        OrchestratorError::Api("clean-chat authority was invalidated".into())
    }

    async fn canonical_get_response(
        &self,
        expected: &AuthoritySnapshot,
        path: &str,
    ) -> Result<Vec<u8>> {
        let (nest, authority, snapshot) = self.authority_for_call()?;
        if &snapshot != expected {
            return Err(OrchestratorError::Credential(
                "clean-chat authority changed before read".into(),
            ));
        }
        let body = nest
            .get_clean_chat_bytes(&snapshot, path)
            .await
            .map_err(|error| self.map_authority_error(&authority, &snapshot, error))?;
        if authority.snapshot().as_ref() != Some(&snapshot) {
            return Err(OrchestratorError::Credential(
                "clean-chat authority changed during read".into(),
            ));
        }
        Ok(body)
    }

    async fn get_canonical_conversations(
        &self,
        limit: u32,
        cursor: Option<&str>,
    ) -> Result<ConversationListPage> {
        if limit == 0 {
            return Err(OrchestratorError::Api(
                "getConversations limit must be positive".into(),
            ));
        }
        let (_, _, snapshot) = self.authority_for_call()?;
        let path = canonical_get_conversations_path(snapshot.device_id(), limit, cursor);
        let body = self.canonical_get_response(&snapshot, &path).await?;
        let decoded = decode_clean_chat_response(CanonicalOperation::GetConversations.into(), body)
            .map_err(|e| {
                OrchestratorError::Api(format!("Canonical getConversations decode: {e}"))
            })?;
        let output: catbird_atproto::blue_catbird::chat::get_conversations::GetConversationsOutput =
            serde_json::from_slice(&decoded).map_err(|e| {
                OrchestratorError::Api(format!("Canonical getConversations JSON: {e}"))
            })?;

        {
            let mut coords_map = self.cached_coordinates.lock().unwrap();
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
            cursor: output.next_page_cursor.map(|cursor| cursor.to_string()),
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
        let after_seq = cursor
            .and_then(|value| value.parse::<i64>().ok())
            .unwrap_or(0);
        if limit == 0 {
            return Err(OrchestratorError::Api(
                "getEntries limit must be positive".into(),
            ));
        }
        let (_, _, snapshot) = self.authority_for_call()?;
        let path = canonical_get_entries_path(snapshot.device_id(), convo_id, after_seq, limit);
        let body = self.canonical_get_response(&snapshot, &path).await?;
        let decoded = decode_clean_chat_response(CanonicalOperation::GetEntries.into(), body)
            .map_err(|e| OrchestratorError::Api(format!("Canonical getEntries decode: {e}")))?;
        let output: catbird_atproto::blue_catbird::chat::get_entries::GetEntriesOutput<String> =
            serde_json::from_slice(&decoded)
                .map_err(|e| OrchestratorError::Api(format!("Canonical getEntries JSON: {e}")))?;

        let envelopes = output
            .entries
            .into_iter()
            .map(|entry| canonical_entry_envelope(entry, convo_id))
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .flatten()
            .filter(|(kind, envelope)| {
                let type_matches = match message_type {
                    Some("app") => *kind == CanonicalEntryKind::Application,
                    Some("commit") => *kind == CanonicalEntryKind::Commit,
                    Some("control") => *kind == CanonicalEntryKind::Control,
                    _ => true,
                };
                let epoch_matches = from_epoch
                    .is_none_or(|epoch| envelope.server_epoch.unwrap_or_default() >= epoch as u64)
                    && to_epoch.is_none_or(|epoch| {
                        envelope.server_epoch.unwrap_or_default() <= epoch as u64
                    });
                type_matches && epoch_matches && envelope.conversation_id == convo_id
            })
            .map(|(_, envelope)| envelope)
            .collect();
        Ok((envelopes, Some(output.next_after_seq.to_string())))
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────

fn canonical_get_conversations_path(
    actor_device_id: &str,
    limit: u32,
    cursor: Option<&str>,
) -> String {
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    query.append_pair("limit", &limit.to_string());
    query.append_pair("actorDeviceId", actor_device_id);
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
    query.append_pair("afterSeq", &after_seq.to_string());
    query.append_pair("actorDeviceId", actor_device_id);
    query.append_pair("conversationId", convo_id);
    query.append_pair("limit", &limit.to_string());
    format!("/xrpc/blue.catbird.chat.getEntries?{}", query.finish())
}

fn canonical_conversation_view(
    state: &catbird_atproto::blue_catbird::chat::ConversationState,
) -> Result<ConversationView> {
    let coordinates = &state.coordinates;
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
        conversation_id: coordinates.conversation_id.to_string(),
        epoch: coordinates.epoch.max(0) as u64,
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
    Control,
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
        _ => CanonicalEntryKind::Control,
    };
    let value = serde_json::to_value(entry)
        .map_err(|error| OrchestratorError::Api(format!("encode canonical entry: {error}")))?;
    IncomingEnvelope::from_canonical_entry(&value, requested_convo_id)
        .map(|envelope| envelope.map(|envelope| (kind, envelope)))
}
#[cfg(test)]
fn canonical_entry_server_epoch(value: &serde_json::Value) -> Option<u64> {
    value
        .pointer("/signedRequest/body/prior/epoch")
        .or_else(|| value.pointer("/signedRequest/body/next/epoch"))
        .or_else(|| value.get("serverEpoch"))
        .or_else(|| value.get("epoch"))
        .and_then(|epoch| {
            epoch
                .as_u64()
                .or_else(|| epoch.as_i64().map(|v| v.max(0) as u64))
        })
}

fn parse_dt(s: &str) -> Option<DateTime<Utc>> {
    s.parse::<DateTime<Utc>>().ok().or_else(|| {
        DateTime::parse_from_rfc3339(s)
            .ok()
            .map(|dt| dt.with_timezone(&Utc))
    })
}

fn parse_u64(v: &serde_json::Value, key: &str) -> u64 {
    v.get(key)
        .and_then(|v| {
            v.as_u64()
                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        })
        .unwrap_or(0)
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
        let expected_path = request.operation.path();
        if request.path.split('?').next() != Some(expected_path) {
            return Err(OrchestratorError::Api(
                "prepared clean-chat route mismatch".into(),
            ));
        }
        let expected_method = match request.operation {
            CanonicalOperation::SubscribeEvents | CanonicalOperation::UploadBlob => {
                return Err(OrchestratorError::Api(
                    "operation requires its dedicated streaming transport".into(),
                ));
            }
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
            _ => "POST",
        };
        if request.method != expected_method
            || (expected_method == "POST" && request.body.is_none())
            || (expected_method == "GET" && request.body.is_some())
        {
            return Err(OrchestratorError::Api(
                "prepared clean-chat method/body mismatch".into(),
            ));
        }
        let (nest, authority, snapshot) = self.authority_for_call()?;
        let method = if expected_method == "GET" {
            reqwest::Method::GET
        } else {
            reqwest::Method::POST
        };
        let response = nest
            .submit_clean_chat_request(&snapshot, method, &request.path, request.body)
            .await
            .map_err(|error| self.map_authority_error(&authority, &snapshot, error))?;
        if matches!(response.status, 401 | 403) {
            authority
                .invalidate_if_matches(&snapshot, InvalidationReason::Unauthorized)
                .map_err(|_| {
                    OrchestratorError::Credential("could not persist authority invalidation".into())
                })?;
        } else if authority.snapshot().as_ref() != Some(&snapshot) {
            return Err(OrchestratorError::Credential(
                "clean-chat authority changed during request".into(),
            ));
        }
        Ok(response)
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
        _actor_device_id: &str,
        _dids: &[String],
    ) -> Result<Vec<KeyPackageRef>> {
        Err(OrchestratorError::Api(
            "raw KeyPackage lookup is unavailable in the canonical chat protocol".into(),
        ))
    }

    async fn get_key_package_stats(&self) -> Result<KeyPackageStats> {
        let (_, _, snapshot) = self.authority_for_call()?;
        let devices = self.list_devices(snapshot.device_id()).await?;
        let device = devices
            .iter()
            .find(|device| device.device_id == snapshot.device_id())
            .ok_or_else(|| {
                OrchestratorError::Api("admitted device missing from own-device inventory".into())
            })?;
        let available = device.available_package_count.ok_or_else(|| {
            OrchestratorError::Api("own-device inventory is missing key-package counts".into())
        })?;
        let reserved = device.reserved_package_count.ok_or_else(|| {
            OrchestratorError::Api("own-device inventory is missing key-package counts".into())
        })?;
        Ok(KeyPackageStats {
            available,
            total: available.saturating_add(reserved),
        })
    }

    async fn sync_key_packages(
        &self,
        _local_hashes: &[String],
        _device_id: &str,
    ) -> Result<KeyPackageSyncResult> {
        Err(OrchestratorError::Api(
            "key-package hash reconciliation is unavailable in the canonical chat protocol".into(),
        ))
    }

    async fn list_devices(&self, actor_device_id: &str) -> Result<Vec<DeviceInfo>> {
        let (_, _, snapshot) = self.authority_for_call()?;
        if snapshot.device_id() != actor_device_id {
            return Err(OrchestratorError::Credential(
                "own-device query does not match admitted device".into(),
            ));
        }
        let mut devices = Vec::new();
        let mut cursor: Option<String> = None;
        let mut seen_cursors = std::collections::HashSet::new();
        loop {
            let path = {
                let mut query = url::form_urlencoded::Serializer::new(String::new());
                query
                    .append_pair("actorDeviceId", actor_device_id)
                    .append_pair("limit", "100");
                if let Some(cursor) = &cursor {
                    query.append_pair("pageCursor", cursor);
                }
                format!("/xrpc/blue.catbird.chat.getOwnDevices?{}", query.finish())
            };
            let body = self.canonical_get_response(&snapshot, &path).await?;
            let output: catbird_atproto::blue_catbird::chat::get_own_devices::GetOwnDevicesOutput<
                String,
            > = serde_json::from_slice(&body)
                .map_err(|e| OrchestratorError::Api(format!("decode own-device inventory: {e}")))?;
            for item in output.items {
                let device = item.device;
                let available = u32::try_from(device.available_package_count).map_err(|_| {
                    OrchestratorError::Api("invalid available key-package count".into())
                })?;
                let reserved = u32::try_from(device.reserved_package_count).map_err(|_| {
                    OrchestratorError::Api("invalid reserved key-package count".into())
                })?;
                if available
                    .checked_add(reserved)
                    .is_none_or(|total| total > 1000)
                {
                    return Err(OrchestratorError::Api(
                        "own-device key-package counts exceed the protocol limit".into(),
                    ));
                }
                devices.push(DeviceInfo {
                    device_id: device.device_id.to_string(),
                    mls_did: format!("{}#{}", snapshot.actor_did(), device.device_id),
                    device_uuid: device.device_id.to_string(),
                    created_at: parse_dt(&device.created_at.to_string()),
                    key_id: Some(device.key_id.to_string()),
                    signature_public_key: Some(device.signature_public_key.to_vec()),
                    auth_generation: Some(device.auth_generation),
                    status: Some(device.status.to_string()),
                    available_package_count: Some(available),
                    reserved_package_count: Some(reserved),
                });
            }
            if !output.has_more {
                break;
            }
            let next = output.next_page_cursor.ok_or_else(|| {
                OrchestratorError::Api("own-device inventory omitted continuation cursor".into())
            })?;
            if !seen_cursors.insert(next.clone()) {
                return Err(OrchestratorError::Api(
                    "own-device inventory repeated continuation cursor".into(),
                ));
            }
            cursor = Some(next);
        }
        Ok(devices)
    }

    async fn get_group_info(&self, _convo_id: &str) -> Result<Vec<u8>> {
        Err(OrchestratorError::Api(
            "raw GroupInfo lookup is unavailable in the canonical chat protocol".into(),
        ))
    }

    async fn get_welcome(&self, _convo_id: &str) -> Result<Vec<u8>> {
        Err(OrchestratorError::Api(
            "Welcome consumption requires a durable join and canonical acknowledgement".into(),
        ))
    }

    async fn get_group_metadata_blob(
        &self,
        _convo_id: &str,
        _group_id_hex: &str,
        blob_locator: &str,
    ) -> Result<Vec<u8>> {
        self.get_blob(blob_locator).await
    }
}

impl BirdApiClient {
    #[cfg(test)]
    pub(crate) async fn send_message_with_id(
        &self,
        convo_id: &str,
        ciphertext: &[u8],
        epoch: u64,
        msg_id: &str,
    ) -> Result<SendMessageResponse> {
        let (_, _, snapshot) = self.authority_for_call()?;
        let signer = {
            let s = self.signer.lock().unwrap();
            s.clone().ok_or_else(|| {
                OrchestratorError::Credential("Signer not configured for clean chat".into())
            })?
        };

        // Look up cached coordinates for convo_id; refresh if missing.
        let coords = {
            let map = self.cached_coordinates.lock().unwrap();
            map.get(convo_id).cloned()
        };
        let coords = match coords {
            Some(c) => c,
            None => {
                let _ = self.get_canonical_conversations(50, None).await?;
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

        let response = self.submit_prepared_request(prepared_request).await?;
        if !(200..300).contains(&response.status) {
            return Err(OrchestratorError::ServerError {
                status: response.status,
                body: String::from_utf8_lossy(&response.body).into_owned(),
            });
        }
        let response_bytes = response.body;

        let decoded =
            decode_clean_chat_response(CanonicalOperation::SendMessage.into(), response_bytes)
                .map_err(|e| OrchestratorError::Api(format!("decode sendMessage response: {e}")))?;

        let output: catbird_atproto::blue_catbird::chat::send_message::SendMessageOutput<String> =
            serde_json::from_slice(&decoded)
                .map_err(|e| OrchestratorError::Api(format!("parse sendMessage output: {e}")))?;

        Ok(SendMessageResponse {
            message_id: output.entry.entry_id.to_string(),
            seq: output.entry.seq as u64,
            epoch: output.entry.signed_request.body.prior.epoch.max(0) as u64,
        })
    }
}

impl BirdApiClient {
    /// Download an encrypted blob by ID from the canonical Nest proxy.
    pub async fn get_blob(&self, blob_id: &str) -> Result<Vec<u8>> {
        let (nest, authority, snapshot) = self.authority_for_call()?;
        nest.get_blob(&snapshot, blob_id)
            .await
            .map_err(|error| self.map_authority_error(&authority, &snapshot, error))
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
fn send_transport_unavailable() -> OrchestratorError {
    OrchestratorError::Api(
        "MLS-encrypted send payload adapter is not available in BIRDaemon".into(),
    )
}

/// Build the JSON body posted to `blue.catbird.chat.requestLeafRecovery`.
///
/// `epochAuthenticator` (ADR-002 / spec §8.6) and `failureMode` (ADR-008 D1 /
/// spec §8.6.1) are only included when present so pre-A7 / pre-D1 servers
/// continue to accept the call.
fn build_report_recovery_failure_body(
    convo_id: &str,
    failure_type: &str,
    epoch_authenticator: Option<&str>,
    failure_mode: Option<&str>,
) -> serde_json::Value {
    let mut body = json!({
        "convoId": convo_id,
        "failureType": failure_type,
    });
    if let Some(auth) = epoch_authenticator {
        body["epochAuthenticator"] = serde_json::Value::String(auth.to_string());
    }
    if let Some(mode) = failure_mode {
        body["failureMode"] = serde_json::Value::String(mode.to_string());
    }
    body
}

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
    let convo_uuid = uuid::Uuid::parse_str(convo_id)
        .map_err(|e| OrchestratorError::Api(format!("invalid conversationId UUID: {e}")))?;
    let msg_uuid = uuid::Uuid::parse_str(message_id)
        .map_err(|e| OrchestratorError::Api(format!("invalid messageId UUID: {e}")))?;
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
        "applicationMessage": {
            "bytes": {"$bytes": B64.encode(ciphertext)},
            "sha256": {"$bytes": B64.encode(ciphertext_sha256)},
            "framing": "mlsMessage",
            "contentType": "privateMessageApplication"
        },
        "prior": {
            "conversationId": convo_uuid.to_string(),
            "groupId": {"$bytes": B64.encode(group_id)},
            "epoch": epoch as i64,
            "generation": auth_generation,
            "stateVersion": state_version,
            "lifecycle": "active",
            "confirmationTag": {"$bytes": B64.encode(confirmation_tag)},
            "groupContextHash": {"$bytes": B64.encode(group_context_hash)}
        },
        "aad": {
            "protocolVersion": "1",
            "conversationId": {"$bytes": B64.encode(convo_uuid.as_bytes())},
            "generation": auth_generation,
            "messageId": {"$bytes": B64.encode(msg_uuid.as_bytes())},
            "prior": {
                "conversationId": {"$bytes": B64.encode(convo_uuid.as_bytes())},
                "groupId": {"$bytes": B64.encode(group_id)},
                "epoch": epoch as i64,
                "generation": auth_generation,
                "stateVersion": state_version,
                "lifecycle": "active",
                "confirmationTag": {"$bytes": B64.encode(confirmation_tag)},
                "groupContextHash": {"$bytes": B64.encode(group_context_hash)}
            }
        },
        "signedAt": Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
    });

    serde_json::to_vec(&body)
        .map_err(|e| OrchestratorError::Api(format!("serialize applicationSendBody: {e}")))
}

#[cfg(test)]
mod tests {
    use super::{
        build_report_recovery_failure_body, canonical_entry_envelope,
        canonical_get_conversations_path, send_transport_unavailable, typing_transport_unavailable,
    };
    use serde_json::json;

    #[test]
    fn body_contains_required_fields() {
        let body =
            build_report_recovery_failure_body("convo-x", "external_commit_exhausted", None, None);
        assert_eq!(body["convoId"], "convo-x");
        assert_eq!(body["failureType"], "external_commit_exhausted");
        assert!(body.get("epochAuthenticator").is_none());
        assert!(body.get("failureMode").is_none());
    }

    #[test]
    fn body_includes_optional_fields_when_present() {
        let body = build_report_recovery_failure_body(
            "convo-y",
            "remote_data_error",
            Some("deadbeef"),
            Some("group_state_unrecoverable"),
        );
        assert_eq!(body["convoId"], "convo-y");
        assert_eq!(body["failureType"], "remote_data_error");
        assert_eq!(body["epochAuthenticator"], "deadbeef");
        assert_eq!(body["failureMode"], "group_state_unrecoverable");
    }

    #[test]
    fn body_omits_only_missing_optional_fields() {
        let body = build_report_recovery_failure_body(
            "convo-z",
            "external_commit_exhausted",
            Some("cafebabe"),
            None,
        );
        assert_eq!(body["epochAuthenticator"], "cafebabe");
        assert!(body.get("failureMode").is_none());
    }

    #[test]
    fn typing_transport_is_explicitly_unavailable_without_mls_payload() {
        let error = typing_transport_unavailable();
        assert!(
            matches!(error, catbird_mls::orchestrator::error::OrchestratorError::Api(message) if message.contains("MLS-encrypted typing payload"))
        );
    }

    #[test]
    fn send_transport_is_explicitly_unavailable_without_mls_payload() {
        let error = send_transport_unavailable();
        assert!(
            matches!(error, catbird_mls::orchestrator::error::OrchestratorError::Api(message) if message.contains("MLS-encrypted send payload"))
        );
    }

    #[test]
    fn repository_helpers_never_relabel_proof_bound_tokens_as_bearer() {
        use jacquard_common::AuthorizationToken;
        assert_eq!(
            super::BirdApiClient::extract_jwt(AuthorizationToken::Bearer("fixture-token".into()))
                .unwrap(),
            "fixture-token"
        );
        for token in [
            AuthorizationToken::Dpop("fixture-token".into()),
            AuthorizationToken::Delegation("fixture-token".into()),
        ] {
            assert!(matches!(
                super::BirdApiClient::extract_jwt(token),
                Err(catbird_mls::orchestrator::error::OrchestratorError::Credential(_))
            ));
        }
    }

    #[test]
    fn canonical_read_path_contains_only_query_parameters() {
        let path = canonical_get_conversations_path(
            "11111111-1111-4111-8111-111111111111",
            25,
            Some("cursor"),
        );
        assert_eq!(
            path,
            "/xrpc/blue.catbird.chat.getConversations?limit=25&actorDeviceId=11111111-1111-4111-8111-111111111111&pageCursor=cursor"
        );
    }

    #[test]
    fn canonical_entry_epoch_is_propagated_to_incoming_envelope() {
        use base64::Engine as _;
        use sha2::Digest as _;
        let bytes = |value: &[u8]| json!({"$bytes": super::B64.encode(value)});
        let conversation_id =
            uuid::Uuid::parse_str("11111111-1111-4111-8111-111111111111").unwrap();
        let message_id = uuid::Uuid::parse_str("33333333-3333-4333-8333-333333333333").unwrap();
        // This fixture checks typed entry projection; it does not claim valid MLS ciphertext/signatures.
        let wire = json!({
            "$type": "blue.catbird.chat.defs#applicationEntry",
            "conversationId": "11111111-1111-4111-8111-111111111111",
            "entryId": "22222222-2222-4222-8222-222222222222",
            "receivedAt": "2026-08-16T00:00:00.000Z",
            "seq": 1,
            "signedRequest": {
                "body": {
                    "$type": "blue.catbird.chat.defs#applicationSendBody",
                    "aad": {
                        "conversationId": bytes(conversation_id.as_bytes()),
                        "generation": 7,
                        "messageId": bytes(message_id.as_bytes()),
                        "prior": {
                            "confirmationTag": bytes(&[1; 32]),
                            "conversationId": bytes(conversation_id.as_bytes()),
                            "epoch": 42,
                            "generation": 7,
                            "groupContextHash": bytes(&[2; 32]),
                            "groupId": bytes(&[3; 32]),
                            "lifecycle": "active",
                            "stateVersion": 1
                        },
                        "protocolVersion": "1"
                    },
                    "actorDeviceId": "11111111-1111-4111-8111-111111111111",
                    "actorDid": "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa",
                    "applicationMessage": {
                        "bytes": {"$bytes": "AQID"},
                        "contentType": "privateMessageApplication",
                        "framing": "mlsMessage",
                        "sha256": bytes(&sha2::Sha256::digest([1, 2, 3]))
                    },
                    "authGeneration": 7,
                    "blobBindings": [],
                    "keyId": crate::chat_authority::derive_key_id(&[4; 32]),
                    "messageId": "33333333-3333-4333-8333-333333333333",
                    "prior": {
                        "confirmationTag": bytes(&[1; 32]),
                        "conversationId": "11111111-1111-4111-8111-111111111111",
                        "epoch": 42,
                        "generation": 7,
                        "groupContextHash": bytes(&[2; 32]),
                        "groupId": bytes(&[3; 32]),
                        "lifecycle": "active",
                        "stateVersion": 1
                    },
                    "signatureDomain": "CATBIRD-CHAT-MESSAGE\u{0000}",
                    "signedAt": "2026-08-16T00:00:00.000Z"
                },
                "signature": bytes(&[0; 64])
            }
        });
        let response = json!({"entries": [wire], "nextAfterSeq": 1, "hasMore": false});
        let decoded = super::decode_clean_chat_response(
            super::CanonicalOperation::GetEntries.into(),
            serde_json::to_vec(&response).unwrap(),
        )
        .expect("shared response decoder accepts canonical bytes");
        let output: catbird_atproto::blue_catbird::chat::get_entries::GetEntriesOutput<String> =
            serde_json::from_slice(&decoded)
                .expect("shared decoded bytes retain the generated DTO presentation");
        assert_eq!(output.next_after_seq, 1);
        let entry = output.entries.into_iter().next().unwrap();

        let (_, envelope) = canonical_entry_envelope(entry, "11111111-1111-4111-8111-111111111111")
            .expect("valid canonical entry")
            .expect("application entry maps to envelope");
        assert_eq!(envelope.server_epoch, Some(42));
        assert_eq!(envelope.server_sequence, Some(1));
        assert_eq!(envelope.ciphertext, vec![1, 2, 3]);
    }
}
