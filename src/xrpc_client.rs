//! MLSAPIClient implementation using PDS atproto-proxy.
//!
//! Routes MLS calls through the PDS with the atproto-proxy header.
//! Uses jacquard session for automatic token refresh on expiry.

use std::sync::Arc;

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use catbird_mls::orchestrator::{
    decode_clean_chat_response, prepare_get_conversations, prepare_get_entries, CanonicalOperation,
    CleanChatAuthContext, PreparedRequest,
};
use chrono::{DateTime, Utc};
use serde_json::json;

use catbird_mls::orchestrator::error::{OrchestratorError, Result};
use catbird_mls::orchestrator::types::*;
use catbird_mls::orchestrator::MLSAPIClient;

/// Jacquard session type alias.
type Session = jacquard::client::MemoryCredentialSession;

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


    /// Get a subscription ticket for WebSocket authentication.
    /// POST blue.catbird.mlsChat.getSubscriptionTicket via PDS proxy.
    /// Returns (ticket_jwt, websocket_endpoint).
    pub async fn get_subscription_ticket(&self) -> Result<(String, String)> {
        let body = serde_json::json!({}); // Subscribe to all conversations
        let resp = self
            .post("blue.catbird.mlsChat.getSubscriptionTicket", &body)
            .await?;
        let ticket = resp["ticket"]
            .as_str()
            .ok_or_else(|| {
                OrchestratorError::Api("No ticket in getSubscriptionTicket response".into())
            })?
            .to_string();
        let endpoint = resp["endpoint"]
            .as_str()
            .ok_or_else(|| {
                OrchestratorError::Api("No endpoint in getSubscriptionTicket response".into())
            })?
            .to_string();
        Ok((ticket, endpoint))
    }
    async fn canonical_get_response(&self, request: PreparedRequest) -> Result<Vec<u8>> {
        let url = format!(
            "{}{}",
            self.pds_endpoint.trim_end_matches('/'),
            request.path
        );
        let mut builder = self
            .http
            .get(url)
            .header("Authorization", request.authorization);
        if !request.dpop.trim().is_empty() {
            builder = builder.header("DPoP", request.dpop);
        }
        let response = builder
            .send()
            .await
            .map_err(|e| OrchestratorError::Api(format!("HTTP error: {e}")))?;
        let status = response.status().as_u16();
        let body = response
            .bytes()
            .await
            .map_err(|e| OrchestratorError::Api(format!("Read bytes: {e}")))?;
        if status >= 400 {
            return Err(OrchestratorError::ServerError {
                status,
                body: String::from_utf8_lossy(&body).into_owned(),
            });
        }
        Ok(body.to_vec())
    }

    async fn get_canonical_conversations(
        &self,
        limit: u32,
        cursor: Option<&str>,
    ) -> Result<ConversationListPage> {
        let auth = self.canonical_auth.as_ref().ok_or_else(|| {
            OrchestratorError::Api(
                "canonical clean-chat reads require daemon device-bound auth context".into(),
            )
        })?;
        let request = canonical_get_conversations_request(auth, limit, cursor)?;
        let body = self.canonical_get_response(request).await?;
        let decoded =
            decode_clean_chat_response(CanonicalOperation::GetConversations.into(), body).map_err(
                |e| OrchestratorError::Api(format!("Canonical getConversations decode: {e}")),
            )?;
        let output: catbird_atproto::blue_catbird::chat::get_conversations::GetConversationsOutput<
            String,
        > = serde_json::from_slice(&decoded)
            .map_err(|e| OrchestratorError::Api(format!("Canonical getConversations JSON: {e}")))?;

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
        let auth = self.canonical_auth.as_ref().ok_or_else(|| {
            OrchestratorError::Api(
                "canonical clean-chat reads require daemon device-bound auth context".into(),
            )
        })?;
        let after_seq = cursor.and_then(|value| value.parse::<i64>().ok()).unwrap_or(0);
        let request = canonical_get_entries_request(auth, convo_id, after_seq, limit)?;
        let body = self.canonical_get_response(request).await?;
        let decoded =
            decode_clean_chat_response(CanonicalOperation::GetEntries.into(), body).map_err(|e| {
                OrchestratorError::Api(format!("Canonical getEntries decode: {e}"))
            })?;
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

fn canonical_get_conversations_request(
    auth: &CleanChatAuthContext,
    limit: u32,
    cursor: Option<&str>,
) -> Result<PreparedRequest> {
    prepare_get_conversations(auth, i64::from(limit), cursor)
        .map_err(|e| OrchestratorError::Api(format!("Canonical getConversations request: {e}")))
}

fn canonical_get_entries_request(
    auth: &CleanChatAuthContext,
    convo_id: &str,
    after_seq: i64,
    limit: u32,
) -> Result<PreparedRequest> {
    prepare_get_entries(auth, convo_id, after_seq, i64::from(limit))
        .map_err(|e| OrchestratorError::Api(format!("Canonical getEntries request: {e}")))
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
        .and_then(|epoch| epoch.as_u64().or_else(|| epoch.as_i64().map(|v| v.max(0) as u64)))
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
            .post("blue.catbird.mlsChat.createConvo", &input)
            .await?;

        Ok(CreateConversationResult {
            conversation: parse_conversation(&output),
            commit_data: None,
            welcome_data: None,
        })
    }

    async fn leave_conversation(&self, convo_id: &str) -> Result<()> {
        self.post_void(
            "blue.catbird.mlsChat.leaveConvo",
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
        self.get_canonical_entries(
            convo_id,
            cursor,
            limit,
            message_type,
            from_epoch,
            to_epoch,
        )
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
            .post("blue.catbird.mlsChat.commitGroupChange", &input)
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
                "blue.catbird.mlsChat.leaveConvo",
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
        _convo_id: &str,
        _ciphertext: &[u8],
        _epoch: u64,
    ) -> Result<SendMessageResponse> {
        Err(send_transport_unavailable())
    }

    async fn send_message_with_id(
        &self,
        _convo_id: &str,
        _ciphertext: &[u8],
        _epoch: u64,
        _msg_id: &str,
    ) -> Result<SendMessageResponse> {
        Err(send_transport_unavailable())
    }


    async fn publish_key_package(
        &self,
        key_package: &[u8],
        cipher_suite: &str,
        expires_at: &str,
        device_id: Option<&str>,
    ) -> Result<()> {
        use catbird_atproto::catbird::mls_chat::publish_key_packages;

        let kp_item: publish_key_packages::KeyPackageItem =
            publish_key_packages::KeyPackageItemData {
                cipher_suite: cipher_suite.to_string(),
                expires: expires_at.parse().unwrap(),
                key_package: key_package.to_vec(),
            }
            .into();

        let input: publish_key_packages::Input = publish_key_packages::InputData {
            action: "publish".to_string(),
            convo_id: None,
            device_id: device_id.map(str::to_string),
            key_packages: Some(vec![kp_item]),
            local_hashes: None,
            reason: None,
            target_dids: None,
        }
        .into();

        let body = serde_json::to_value(&input)
            .map_err(|e| OrchestratorError::Api(format!("Serialize error: {e}")))?;

        self.post_void("blue.catbird.mlsChat.publishKeyPackages", &body)
            .await
    }

    async fn get_key_packages(&self, dids: &[String]) -> Result<Vec<KeyPackageRef>> {
        let dids_str = dids.join(",");
        let output = self
            .get(
                "blue.catbird.mlsChat.getKeyPackages",
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
                "blue.catbird.mlsChat.getKeyPackageStatus",
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
        use catbird_atproto::catbird::mls_chat::register_device;

        let kp_items: Vec<register_device::KeyPackageItem> = key_packages
            .iter()
            .map(|kp| {
                let expires_str = (Utc::now() + chrono::Duration::days(90)).to_rfc3339();
                register_device::KeyPackageItemData {
                    cipher_suite: "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519".to_string(),
                    expires: expires_str.parse().unwrap(),
                    key_package: kp.clone(),
                }
                .into()
            })
            .collect();

        let input: register_device::Input = register_device::InputData {
            device_uuid: Some(device_uuid.to_string()),
            device_name: device_name.to_string(),
            signature_public_key: signature_key.to_vec(),
            key_packages: kp_items,
        }
        .into();

        let body = serde_json::to_value(&input)
            .map_err(|e| OrchestratorError::Api(format!("Serialize error: {e}")))?;

        let output = self
            .post("blue.catbird.mlsChat.registerDevice", &body)
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
        let output = self.get("blue.catbird.mlsChat.listDevices", &[]).await?;

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
        use catbird_atproto::catbird::mls_chat::register_device;

        // Build a valid RegisterDevice input with action=delete.
        // The server requires all fields even for delete action.
        let input: register_device::Input = register_device::InputData {
            device_uuid: None,
            device_name: "delete".to_string(),
            signature_public_key: vec![0u8; 32],
            key_packages: vec![],
        }
        .into();

        let mut body = serde_json::to_value(&input)
            .map_err(|e| OrchestratorError::Api(format!("Serialize error: {e}")))?;
        body["action"] = json!("delete");
        body["deviceId"] = json!(device_id);

        self.post_void("blue.catbird.mlsChat.registerDevice", &body)
            .await
    }

    async fn publish_group_info(&self, convo_id: &str, group_info: &[u8]) -> Result<()> {
        self.post_void(
            "blue.catbird.mlsChat.commitGroupChange",
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
                "blue.catbird.mlsChat.getGroupState",
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
                "blue.catbird.mlsChat.getGroupState",
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

        self.post_void("blue.catbird.mlsChat.reportRecoveryFailure", &body)
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
            .post("blue.catbird.mlsChat.commitGroupChange", &input)
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
    /// Download an encrypted blob by ID from the MLS blob store.
    pub async fn get_blob(&self, blob_id: &str) -> Result<Vec<u8>> {
        let jwt = self.get_jwt().await?;
        let resp = self
            .http
            .get(self.xrpc_url("blue.catbird.mlsChat.getBlob"))
            .header("Authorization", format!("Bearer {}", jwt))
            .header("atproto-proxy", &self.proxy_did)
            .query(&[("blobId", blob_id)])
            .send()
            .await
            .map_err(|e| OrchestratorError::Api(format!("HTTP error: {e}")))?;

        let status = resp.status().as_u16();
        if status >= 400 {
            let body_text = resp.text().await.unwrap_or_default();
            if Self::is_token_error(status, &body_text) {
                let jwt = self.refresh_jwt().await?;
                let resp = self
                    .http
                    .get(self.xrpc_url("blue.catbird.mlsChat.getBlob"))
                    .header("Authorization", format!("Bearer {}", jwt))
                    .header("atproto-proxy", &self.proxy_did)
                    .query(&[("blobId", blob_id)])
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
                return resp
                    .bytes()
                    .await
                    .map(|b| b.to_vec())
                    .map_err(|e| OrchestratorError::Api(format!("Read bytes: {e}")));
            }
            return Err(OrchestratorError::ServerError {
                status,
                body: body_text,
            });
        }

        resp.bytes()
            .await
            .map(|b| b.to_vec())
            .map_err(|e| OrchestratorError::Api(format!("Read bytes: {e}")))
    }

    // ── Device Record Publishing (ATProto repo records) ────────────────

    /// Publish a `blue.catbird.mlsChat.device` record to the user's ATProto repo.
    /// This allows other clients to verify that key packages belong to an authorized device.
    /// Mirrors `MLSDeviceRecordService.ensureDeviceRecordPublished` in CatbirdMLSCore.
    pub async fn ensure_device_record_published(&self, signature_public_key: &[u8]) -> Result<()> {
        // Check if a device record with this key already exists
        let existing = self
            .list_repo_records("blue.catbird.mlsChat.device")
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
            "blue.catbird.mlsChat.device",
            &json!({
                "$type": "blue.catbird.mlsChat.device",
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


/// Build the JSON body posted to `blue.catbird.mlsChat.reportRecoveryFailure`.
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

#[cfg(test)]
mod tests {
    use super::{
        build_report_recovery_failure_body, canonical_entry_envelope,
        canonical_get_conversations_request, send_transport_unavailable,
        typing_transport_unavailable,
    };
    use catbird_mls::orchestrator::{CanonicalOperation, CleanChatAuthContext};
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
    fn canonical_read_request_binds_device_and_generation_context() {
        let auth = CleanChatAuthContext::new(
            "Bearer daemon-token".into(),
            "signed-dpop-proof".into(),
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
            "11111111-1111-4111-8111-111111111111".into(),
        )
        .with_auth_generation(7);

        assert_eq!(auth.auth_generation, Some(7));

        let request = canonical_get_conversations_request(&auth, 25, Some("cursor"))
            .expect("canonical request prepares");
        assert_eq!(request.operation, CanonicalOperation::GetConversations);
        assert_eq!(
            request.path,
            "/xrpc/blue.catbird.chat.getConversations?limit=25&pageCursor=cursor"
        );
        assert_eq!(request.authorization, "Bearer daemon-token");
        assert_eq!(request.dpop, "signed-dpop-proof");

        let missing_jkt = CleanChatAuthContext::new(
            "Bearer daemon-token".into(),
            "signed-dpop-proof".into(),
            String::new(),
            "11111111-1111-4111-8111-111111111111".into(),
        );
        assert!(matches!(
            canonical_get_conversations_request(&missing_jkt, 25, None),
            Err(catbird_mls::orchestrator::error::OrchestratorError::Api(message))
                if message.contains("device binding is missing")
        ));

        let invalid_device = CleanChatAuthContext::new(
            "Bearer daemon-token".into(),
            "signed-dpop-proof".into(),
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
            "not-a-uuid".into(),
        );
        let invalid_result = canonical_get_conversations_request(&invalid_device, 25, None);
        assert!(invalid_result.is_err(), "{invalid_result:?}");
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

        let (_, envelope) =
            canonical_entry_envelope(entry, "11111111-1111-4111-8111-111111111111")
                .expect("application entry maps to envelope");
        assert_eq!(envelope.server_epoch, Some(42));
        assert_eq!(envelope.ciphertext, vec![1, 2, 3]);
    }
}
