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
    decode_clean_chat_response, CanonicalOperation, CleanChatAuthContext, CleanChatSigningContext,
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
    inventory: Arc<Mutex<Option<(String, String)>>>,
    cached_coordinates: Arc<
        Mutex<
            HashMap<String, catbird_atproto::blue_catbird::chat::ConversationCoordinates<String>>,
        >,
    >,
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
            inventory: Arc::new(Mutex::new(None)),
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
                    .login(
                        jacquard_common::CowStr::from(self.handle.clone()),
                        jacquard_common::CowStr::from(self.app_password.clone()),
                        None,
                        None,
                        None,
                        None,
                    )
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

    fn extract_jwt(token: jacquard_common::AuthorizationToken<'_>) -> String {
        match token {
            jacquard_common::AuthorizationToken::Bearer(s) => s.to_string(),
            jacquard_common::AuthorizationToken::Dpop(s) => s.to_string(),
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

    /// Get a v2 subscription ticket through Nest. The returned endpoint is
    /// opened directly by the WebSocket client; Nest explicitly refuses to
    /// proxy `subscribeEvents` upgrades.
    pub async fn get_subscription_ticket(&self) -> Result<(String, String)> {
        let (inventory_session_id, event_cursor) =
            self.inventory.lock().unwrap().clone().ok_or_else(|| {
                OrchestratorError::Api(
                    "v2 subscription ticket requires a current inventory session and cursor".into(),
                )
            })?;
        let (nest, authority, snapshot) = self.authority_for_call()?;
        nest.get_subscription_ticket(&snapshot, &inventory_session_id, &event_cursor)
            .await
            .map_err(|error| self.map_authority_error(&authority, &snapshot, error))
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

    async fn canonical_get_response(&self, path: &str) -> Result<Vec<u8>> {
        let (nest, authority, snapshot) = self.authority_for_call()?;
        nest.get_clean_chat_bytes(&snapshot, path)
            .await
            .map_err(|error| self.map_authority_error(&authority, &snapshot, error))
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
        let path = canonical_get_conversations_path(limit, cursor);
        let body = self.canonical_get_response(&path).await?;
        let decoded = decode_clean_chat_response(CanonicalOperation::GetConversations.into(), body)
            .map_err(|e| {
                OrchestratorError::Api(format!("Canonical getConversations decode: {e}"))
            })?;
        let output: catbird_atproto::blue_catbird::chat::get_conversations::GetConversationsOutput<
            String,
        > = serde_json::from_slice(&decoded)
            .map_err(|e| OrchestratorError::Api(format!("Canonical getConversations JSON: {e}")))?;

        {
            let mut inventory = self.inventory.lock().unwrap();
            *inventory = Some((
                output.inventory_session_id.to_string(),
                output.snapshot_event_cursor.to_string(),
            ));
        }
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
            cursor: output.next_page_cursor,
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
        let path = canonical_get_entries_path(convo_id, after_seq, limit);
        let body = self.canonical_get_response(&path).await?;
        let decoded = decode_clean_chat_response(CanonicalOperation::GetEntries.into(), body)
            .map_err(|e| OrchestratorError::Api(format!("Canonical getEntries decode: {e}")))?;
        let output: catbird_atproto::blue_catbird::chat::get_entries::GetEntriesOutput<String> =
            serde_json::from_slice(&decoded)
                .map_err(|e| OrchestratorError::Api(format!("Canonical getEntries JSON: {e}")))?;

        let envelopes = output
            .entries
            .into_iter()
            .filter_map(|entry| canonical_entry_envelope(entry, convo_id))
            .filter(|(kind, envelope)| {
                let type_matches = match message_type {
                    Some("app") => *kind == CanonicalEntryKind::Application,
                    Some("commit") => *kind == CanonicalEntryKind::Commit,
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

fn canonical_get_conversations_path(limit: u32, cursor: Option<&str>) -> String {
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    query.append_pair("limit", &limit.to_string());
    if let Some(cursor) = cursor {
        query.append_pair("pageCursor", cursor);
    }
    format!(
        "/xrpc/blue.catbird.chat.getConversations?{}",
        query.finish()
    )
}

fn canonical_get_entries_path(convo_id: &str, after_seq: i64, limit: u32) -> String {
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    query.append_pair("afterSeq", &after_seq.to_string());
    query.append_pair("conversationId", convo_id);
    query.append_pair("limit", &limit.to_string());
    format!("/xrpc/blue.catbird.chat.getEntries?{}", query.finish())
}

fn canonical_conversation_view(
    state: &catbird_atproto::blue_catbird::chat::ConversationState<String>,
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
}

fn canonical_entry_envelope(
    entry: catbird_atproto::blue_catbird::chat::ConversationEntry<String>,
    requested_convo_id: &str,
) -> Option<(CanonicalEntryKind, IncomingEnvelope)> {
    match entry {
        catbird_atproto::blue_catbird::chat::ConversationEntry::ApplicationEntry(entry) => {
            let body = &entry.signed_request.body;
            Some((
                CanonicalEntryKind::Application,
                IncomingEnvelope {
                    conversation_id: entry.conversation_id.to_string(),
                    sender_did: body.actor_did.to_string(),
                    ciphertext: body.application_message.bytes.to_vec(),
                    timestamp: parse_dt(&entry.received_at.to_string()).unwrap_or_else(Utc::now),
                    server_message_id: Some(entry.entry_id.to_string()),
                    server_epoch: Some(body.prior.epoch.max(0) as u64),
                },
            ))
        }
        catbird_atproto::blue_catbird::chat::ConversationEntry::CommitEntry(entry) => {
            let body = &entry.signed_request.body;
            Some((
                CanonicalEntryKind::Commit,
                IncomingEnvelope {
                    conversation_id: entry.conversation_id.to_string(),
                    sender_did: body.actor_did.to_string(),
                    ciphertext: body.commit.bytes.to_vec(),
                    timestamp: parse_dt(&entry.received_at.to_string()).unwrap_or_else(Utc::now),
                    server_message_id: Some(entry.entry_id.to_string()),
                    server_epoch: Some(body.next.epoch.max(0) as u64),
                },
            ))
        }
        _ => {
            tracing::debug!(
                conversation_id = requested_convo_id,
                "Ignoring canonical control entry without MLS ciphertext"
            );
            None
        }
    }
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

fn parse_conversation(v: &serde_json::Value) -> ConversationView {
    let members = v
        .get("members")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|m| {
                    let did = m
                        .get("did")
                        .or(m.get("userDid"))
                        .and_then(|v| v.as_str())?
                        .to_string();
                    let is_admin = m.get("isAdmin").and_then(|v| v.as_bool()).unwrap_or(false);
                    Some(MemberView {
                        did,
                        role: if is_admin {
                            MemberRole::Admin
                        } else {
                            MemberRole::Member
                        },
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    let metadata_obj = v.get("metadata");
    let name = metadata_obj
        .and_then(|m| m.get("name"))
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let description = metadata_obj
        .and_then(|m| m.get("description"))
        .and_then(|v| v.as_str())
        .map(str::to_string);

    let metadata = if name.is_some() || description.is_some() {
        Some(ConversationMetadata {
            name,
            description,
            avatar_url: None,
        })
    } else {
        None
    };

    let group_id = v
        .get("groupId")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let conversation_id = v
        .get("conversationId")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| group_id.clone());

    ConversationView {
        group_id,
        conversation_id,
        epoch: parse_u64(v, "epoch"),
        members,
        metadata,
        created_at: v
            .get("createdAt")
            .and_then(|v| v.as_str())
            .and_then(parse_dt),
        updated_at: v
            .get("updatedAt")
            .and_then(|v| v.as_str())
            .and_then(parse_dt),
        // WS-4 rung 2 (ADR-010 D4): optional on the wire; older servers omit it.
        sequencer_did: v
            .get("sequencerDid")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
    }
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

    async fn get_conversations(
        &self,
        limit: u32,
        cursor: Option<&str>,
    ) -> Result<ConversationListPage> {
        self.get_canonical_conversations(limit, cursor).await
    }

    async fn create_conversation(
        &self,
        group_id: &str,
        initial_members: Option<&[String]>,
        metadata: Option<&ConversationMetadata>,
        _commit_data: Option<&[u8]>,
        welcome_data: Option<&[u8]>,
    ) -> Result<CreateConversationResult> {
        let mut input = json!({
            "groupId": group_id,
            "cipherSuite": "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519",
            "idempotencyKey": uuid::Uuid::new_v4().to_string(),
        });
        if let Some(members) = initial_members {
            input["initialMembers"] =
                serde_json::Value::Array(members.iter().map(|d| json!(d)).collect());
        }
        if let Some(m) = metadata {
            let mut meta = serde_json::Map::new();
            if let Some(name) = &m.name {
                meta.insert("name".into(), json!(name));
            }
            if let Some(desc) = &m.description {
                meta.insert("description".into(), json!(desc));
            }
            input["metadata"] = serde_json::Value::Object(meta);
        }
        if let Some(welcome) = welcome_data {
            input["welcomeMessage"] = json!(B64.encode(welcome));
        }

        let output = self
            .post("blue.catbird.chat.createConversation", &input)
            .await?;

        Ok(CreateConversationResult {
            conversation: parse_conversation(&output),
            commit_data: None,
            welcome_data: None,
        })
    }

    async fn leave_conversation(&self, convo_id: &str) -> Result<()> {
        self.post_void(
            "blue.catbird.chat.requestLeave",
            &json!({ "convoId": convo_id }),
        )
        .await
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

    async fn add_members(
        &self,
        convo_id: &str,
        member_dids: &[String],
        commit_data: &[u8],
        welcome_data: Option<&[u8]>,
    ) -> Result<AddMembersServerResult> {
        let mut input = json!({
            "action": "addMembers",
            "convoId": convo_id,
            "memberDids": member_dids,
            "commit": B64.encode(commit_data),
            "idempotencyKey": uuid::Uuid::new_v4().to_string(),
        });
        if let Some(welcome) = welcome_data {
            input["welcome"] = json!(B64.encode(welcome));
        }

        let output = self
            .post("blue.catbird.chat.submitTransition", &input)
            .await?;

        Ok(AddMembersServerResult {
            success: output
                .get("success")
                .and_then(|v| v.as_bool())
                .unwrap_or(true),
            new_epoch: parse_u64(&output, "newEpoch"),
            receipt: None,
        })
    }

    async fn remove_members(
        &self,
        convo_id: &str,
        member_dids: &[String],
        commit_data: &[u8],
    ) -> Result<()> {
        for did in member_dids {
            self.post_void(
                "blue.catbird.chat.requestLeave",
                &json!({
                    "convoId": convo_id,
                    "commit": B64.encode(commit_data),
                    "targetDid": did,
                }),
            )
            .await?;
        }
        Ok(())
    }
    async fn send_message(
        &self,
        convo_id: &str,
        ciphertext: &[u8],
        epoch: u64,
    ) -> Result<SendMessageResponse> {
        let msg_id = uuid::Uuid::new_v4().to_string();
        self.send_message_with_id(convo_id, ciphertext, epoch, &msg_id)
            .await
    }

    async fn send_message_with_id(
        &self,
        convo_id: &str,
        ciphertext: &[u8],
        epoch: u64,
        msg_id: &str,
    ) -> Result<SendMessageResponse> {
        let (nest, authority, snapshot) = self.authority_for_call()?;
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
            dpop_jkt: snapshot.dpop_jkt().to_string(),
            auth_generation: Some(snapshot.auth_generation()),
        };

        let prepared_request = signer
            .prepare_signed_request(signing_context, CanonicalOperation::SendMessage, body_bytes)
            .await?;

        let request_body = prepared_request
            .body
            .ok_or_else(|| OrchestratorError::Api("Empty signed request body".into()))?;

        let response_bytes = nest
            .post_clean_chat_signed_request(
                &snapshot,
                "/xrpc/blue.catbird.chat.sendMessage",
                request_body,
            )
            .await
            .map_err(|error| self.map_authority_error(&authority, &snapshot, error))?;

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

    async fn publish_key_package(
        &self,
        key_package: &[u8],
        cipher_suite: &str,
        expires_at: &str,
        device_id: Option<&str>,
    ) -> Result<()> {
        use catbird_atproto::blue_catbird::chat::replenish_key_packages;

        let body = json!({
            "keyPackages": [{
                "cipherSuite": cipher_suite,
                "expiresAt": expires_at,
                "data": B64.encode(key_package),
            }],
            "deviceId": device_id,
        });

        self.post_void("blue.catbird.chat.replenishKeyPackages", &body)
            .await
    }

    async fn get_key_packages(&self, dids: &[String]) -> Result<Vec<KeyPackageRef>> {
        let dids_str = dids.join(",");
        let output = self
            .get(
                "blue.catbird.chat.getKeyPackages",
                &[("dids", dids_str.as_str())],
            )
            .await?;

        let kps = output
            .get("keyPackages")
            .and_then(|v| v.as_array())
            .ok_or_else(|| OrchestratorError::Api("missing keyPackages".into()))?;

        Ok(kps
            .iter()
            .filter_map(|kp| {
                let did = kp.get("did").and_then(|v| v.as_str())?.to_string();
                let kp_data = B64
                    .decode(kp.get("keyPackage").and_then(|v| v.as_str())?)
                    .ok()?;
                let hash = kp
                    .get("keyPackageHash")
                    .and_then(|v| v.as_str())
                    .map(str::to_string);
                let cipher_suite = kp
                    .get("cipherSuite")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                Some(KeyPackageRef {
                    did,
                    key_package_data: kp_data,
                    hash,
                    cipher_suite,
                })
            })
            .collect())
    }

    async fn get_key_package_stats(&self) -> Result<KeyPackageStats> {
        let output = self
            .get(
                "blue.catbird.chat.getDevices",
                &[("include", "stats")],
            )
            .await?;

        let stats = output
            .get("stats")
            .and_then(|v| v.as_object())
            .ok_or_else(|| OrchestratorError::Api("missing stats".into()))?;

        let parse_u32 = |key: &str| -> u32 {
            stats
                .get(key)
                .and_then(|v| {
                    v.as_u64()
                        .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
                })
                .unwrap_or(0) as u32
        };

        let available = parse_u32("available");
        let total = if parse_u32("total") > 0 {
            parse_u32("total")
        } else {
            parse_u32("published").max(available)
        };

        Ok(KeyPackageStats { available, total })
    }

    async fn sync_key_packages(
        &self,
        _local_hashes: &[String],
        _device_id: &str,
    ) -> Result<KeyPackageSyncResult> {
        // Not implemented on server yet
        Ok(KeyPackageSyncResult {
            orphaned_count: 0,
            deleted_count: 0,
        })
    }

    async fn register_device(
        &self,
        device_uuid: &str,
        device_name: &str,
        _mls_did: &str,
        signature_key: &[u8],
        key_packages: &[Vec<u8>],
    ) -> Result<DeviceInfo> {
        use catbird_atproto::blue_catbird::chat::enroll_device;

        let kp_items: Vec<serde_json::Value> = key_packages
            .iter()
            .map(|kp| {
                let expires_str = (Utc::now() + chrono::Duration::days(90)).to_rfc3339();
                json!({
                    "cipherSuite": "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519",
                    "expiresAt": expires_str,
                    "data": B64.encode(kp),
                })
            })
            .collect();

        let body = json!({
            "deviceUuid": device_uuid,
            "deviceName": device_name,
            "signaturePublicKey": { "$bytes": B64.encode(signature_key) },
            "keyPackages": kp_items,
        });

        let output = self
            .post("blue.catbird.chat.enrollDevice", &body)
            .await?;

        Ok(DeviceInfo {
            device_id: output
                .get("deviceId")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            mls_did: output
                .get("mlsDid")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            device_uuid: device_uuid.to_string(),
            created_at: None,
        })
    }

    async fn list_devices(&self) -> Result<Vec<DeviceInfo>> {
        let output = self.get("blue.catbird.chat.getDevices", &[]).await?;

        let devices = output
            .get("devices")
            .and_then(|v| v.as_array())
            .ok_or_else(|| OrchestratorError::Api("missing devices".into()))?;

        Ok(devices
            .iter()
            .map(|d| DeviceInfo {
                device_id: d
                    .get("deviceId")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                mls_did: d
                    .get("credentialDid")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                device_uuid: d
                    .get("deviceUuid")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                created_at: d
                    .get("registeredAt")
                    .and_then(|v| v.as_str())
                    .and_then(parse_dt),
            })
            .collect())
    }

    async fn remove_device(&self, device_id: &str) -> Result<()> {
        use catbird_atproto::blue_catbird::chat::revoke_device;

        let body = json!({
            "deviceId": device_id,
        });

        self.post_void("blue.catbird.chat.revokeDevice", &body)
            .await
    }

    async fn publish_group_info(&self, convo_id: &str, group_info: &[u8]) -> Result<()> {
        self.post_void(
            "blue.catbird.chat.submitTransition",
            &json!({
                "action": "updateGroupInfo",
                "convoId": convo_id,
                "groupInfo": B64.encode(group_info),
            }),
        )
        .await
    }

    async fn get_group_info(&self, convo_id: &str) -> Result<Vec<u8>> {
        let output = self
            .get(
                "blue.catbird.chat.getConversationState",
                &[("convoId", convo_id), ("include", "groupInfo,epoch")],
            )
            .await?;

        let b64 = output
            .get("groupInfo")
            .and_then(|v| v.as_str())
            .ok_or_else(|| OrchestratorError::Api("missing groupInfo".into()))?;
        B64.decode(b64)
            .map_err(|e| OrchestratorError::Api(e.to_string()))
    }

    async fn get_welcome(&self, convo_id: &str) -> Result<Vec<u8>> {
        let output = self
            .get(
                "blue.catbird.chat.getConversationState",
                &[("convoId", convo_id), ("include", "welcome")],
            )
            .await?;

        let b64 = output
            .get("welcome")
            .and_then(|v| v.as_str())
            .ok_or_else(|| OrchestratorError::ServerError {
                status: 404,
                body: "No welcome available for this conversation".to_string(),
            })?;
        B64.decode(b64)
            .map_err(|e| OrchestratorError::Api(e.to_string()))
    }

    async fn report_recovery_failure(
        &self,
        convo_id: &str,
        failure_type: &str,
        epoch_authenticator: Option<&str>,
        failure_mode: Option<&str>,
    ) -> Result<()> {
        let body = build_report_recovery_failure_body(
            convo_id,
            failure_type,
            epoch_authenticator,
            failure_mode,
        );

        self.post_void("blue.catbird.chat.requestLeafRecovery", &body)
            .await
    }

    async fn process_external_commit(
        &self,
        convo_id: &str,
        commit_data: &[u8],
        group_info: Option<&[u8]>,
        confirmation_tag: Option<&str>,
    ) -> Result<ProcessExternalCommitResult> {
        let mut input = json!({
            "action": "externalCommit",
            "convoId": convo_id,
            "commit": B64.encode(commit_data),
        });
        if let Some(gi) = group_info {
            input["groupInfo"] = json!(B64.encode(gi));
        }
        if let Some(tag) = confirmation_tag {
            input["confirmationTag"] = json!(tag);
        }

        let output = self
            .post("blue.catbird.chat.submitTransition", &input)
            .await?;

        Ok(ProcessExternalCommitResult {
            epoch: parse_u64(&output, "newEpoch"),
            rejoined_at: output
                .get("rejoinedAt")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            receipt: None,
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
        let existing = self
            .list_repo_records("blue.catbird.chat.device")
            .await?;
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
            "sha256": ciphertext_sha256.to_vec(),
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
            "conversationId": convo_uuid.as_bytes().to_vec(),
            "generation": auth_generation,
            "messageId": msg_uuid.as_bytes().to_vec(),
            "prior": {
                "conversationId": convo_uuid.as_bytes().to_vec(),
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
    fn canonical_read_path_contains_only_query_parameters() {
        let path = canonical_get_conversations_path(25, Some("cursor"));
        assert_eq!(
            path,
            "/xrpc/blue.catbird.chat.getConversations?limit=25&pageCursor=cursor"
        );
    }

    #[test]
    fn canonical_entry_epoch_is_propagated_to_incoming_envelope() {
        let wire = json!({
            "$type": "blue.catbird.chat.defs#applicationEntry",
            "conversationId": "11111111-1111-4111-8111-111111111111",
            "entryId": "22222222-2222-4222-8222-222222222222",
            "receivedAt": "2026-08-16T00:00:00Z",
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
            .expect("application entry maps to envelope");
        assert_eq!(envelope.server_epoch, Some(42));
        assert_eq!(envelope.ciphertext, vec![1, 2, 3]);
    }
}
