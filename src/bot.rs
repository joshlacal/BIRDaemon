//! Clean-slate federated `BIRDaemon` bot runtime (`Spec §3 G3`, `G2`, `I15`, `I16`).
//!
//! Operates directly against the bot's home `mls-ds` + ATProto PDS Spaces (`com.atproto.space.*`)
//! via `catbird_mls::CatbirdMlsClient` and standard ATProto service auth / PDS OAuth tokens,
//! with zero `nest` dependency, URL, or session coupling.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use catbird_mls::client::{
    evaluate_spaces_eligibility, CatbirdMlsClient, CatbirdMlsClientConfig, EnrollmentReceipt,
    LabyrinthBackupStatus, PlatformChangeEvent, PlatformChangeObserver, PlatformHttpHeader,
    PlatformHttpRequest, PlatformHttpResponse, PlatformKeyStore, PlatformTransport,
    SpacesEligibilityInput,
};
use catbird_mls::storage::{ConversationRow, MessageRow};
use catbird_mls::MLSError;
use rand::RngCore;

/// Pluggable LLM responder trait for generating bot replies to `@mention` / DM messages.
#[async_trait::async_trait]
pub trait BotLlmResponder: Send + Sync {
    async fn generate_reply(&self, sender_did: &str, text: &str) -> anyhow::Result<String>;
}

/// OpenAI-compatible HTTP chat-completions responder.
pub struct HttpLlmResponder {
    http: reqwest::Client,
    base_url: String,
    api_key: String,
    model: String,
    system_prompt: String,
}

impl HttpLlmResponder {
    pub fn new(
        base_url: String,
        api_key: String,
        model: String,
        system_prompt: String,
    ) -> anyhow::Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(45))
            .build()?;
        Ok(Self {
            http,
            base_url,
            api_key,
            model,
            system_prompt,
        })
    }
}

#[async_trait::async_trait]
impl BotLlmResponder for HttpLlmResponder {
    async fn generate_reply(&self, sender_did: &str, text: &str) -> anyhow::Result<String> {
        let endpoint = format!(
            "{}/v1/chat/completions",
            self.base_url.trim_end_matches('/')
        );
        let payload = serde_json::json!({
            "model": self.model,
            "messages": [
                { "role": "system", "content": self.system_prompt },
                { "role": "user", "content": format!("[from {sender_did}]: {text}") }
            ]
        });
        let resp = self
            .http
            .post(&endpoint)
            .bearer_auth(&self.api_key)
            .json(&payload)
            .send()
            .await?;
        let status = resp.status();
        let val: serde_json::Value = resp.json().await?;
        if !status.is_success() {
            anyhow::bail!("LLM endpoint returned HTTP {status}: {val}");
        }
        let content = val
            .pointer("/choices/0/message/content")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("missing /choices/0/message/content in LLM response"))?;
        Ok(content.trim().to_string())
    }
}

/// Configuration for a federated `BIRDaemon` instance (`G3`: zero `nest` fields).
#[derive(Debug, Clone)]
pub struct FederatedBotConfig {
    pub storage_root: PathBuf,
    pub bot_did: String,
    pub bot_handle: String,
    pub device_id: String,
    pub home_ds_did: String,
    pub home_ds_endpoint: String,
    pub pds_endpoint: String,
    pub pds_supports_spaces: bool,
    pub granted_oauth_scopes: Vec<String>,
    pub accept_chat_requests: bool,
    pub reply_to_all_messages: bool,
    pub max_reply_characters: u32,
}

/// Owner-only (`0600`) file-backed + in-memory `PlatformKeyStore` for headless bot daemons.
pub struct BirdKeyStore {
    keystore_dir: PathBuf,
    dpop_cache: Mutex<HashMap<String, (String, i64)>>,
}

impl BirdKeyStore {
    pub fn new(storage_root: &std::path::Path) -> anyhow::Result<Self> {
        let keystore_dir = storage_root.join("keystore");
        std::fs::create_dir_all(&keystore_dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&keystore_dir, std::fs::Permissions::from_mode(0o700));
        }
        Ok(Self {
            keystore_dir,
            dpop_cache: Mutex::new(HashMap::new()),
        })
    }

    fn secret_path(&self, raw_id: &str) -> PathBuf {
        let safe_name: String = raw_id
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        self.keystore_dir.join(format!("{safe_name}.key"))
    }

    fn write_restricted(&self, path: &std::path::Path, bytes: &[u8]) -> Result<(), MLSError> {
        let encoded = BASE64_STANDARD.encode(bytes);
        std::fs::write(path, encoded.as_bytes())
            .map_err(|e| MLSError::Internal(format!("write keystore file: {e}")))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }
}

impl PlatformKeyStore for BirdKeyStore {
    fn load_or_create_db_key(&self, account_did_hash: String) -> Result<Vec<u8>, MLSError> {
        let path = self.secret_path(&format!("db-{account_did_hash}"));
        if path.exists() {
            let b64 = std::fs::read_to_string(&path)
                .map_err(|e| MLSError::Internal(format!("read db key: {e}")))?;
            let decoded = BASE64_STANDARD
                .decode(b64.trim())
                .map_err(|e| MLSError::Internal(format!("decode db key: {e}")))?;
            if decoded.len() == 32 {
                return Ok(decoded);
            }
        }
        let mut fresh = vec![0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut fresh);
        self.write_restricted(&path, &fresh)?;
        Ok(fresh)
    }

    fn load_signature_keypair(&self, key_id: String) -> Result<Option<Vec<u8>>, MLSError> {
        let path = self.secret_path(&format!("sig-{key_id}"));
        if !path.exists() {
            return Ok(None);
        }
        let b64 = std::fs::read_to_string(&path)
            .map_err(|e| MLSError::Internal(format!("read signer key: {e}")))?;
        let decoded = BASE64_STANDARD
            .decode(b64.trim())
            .map_err(|e| MLSError::Internal(format!("decode signer key: {e}")))?;
        Ok(Some(decoded))
    }

    fn store_signature_keypair(
        &self,
        key_id: String,
        keypair_bytes: Vec<u8>,
    ) -> Result<(), MLSError> {
        let path = self.secret_path(&format!("sig-{key_id}"));
        self.write_restricted(&path, &keypair_bytes)
    }

    fn delete_account_keys(&self, account_did_hash: String) -> Result<(), MLSError> {
        let db_path = self.secret_path(&format!("db-{account_did_hash}"));
        let sig_path = self.secret_path(&format!("sig-mls-signer:{account_did_hash}"));
        let _ = std::fs::remove_file(db_path);
        let _ = std::fs::remove_file(sig_path);
        if let Ok(mut guard) = self.dpop_cache.lock() {
            guard.remove(&account_did_hash);
        }
        Ok(())
    }

    fn load_cached_chat_dpop_token(
        &self,
        account_did_hash: String,
    ) -> Result<Option<String>, MLSError> {
        let now_ms = chrono::Utc::now().timestamp_millis();
        let guard = self
            .dpop_cache
            .lock()
            .map_err(|_| MLSError::Internal("dpop_cache mutex poisoned".to_string()))?;
        Ok(guard.get(&account_did_hash).and_then(|(tok, exp)| {
            if *exp > now_ms {
                Some(tok.clone())
            } else {
                None
            }
        }))
    }

    fn store_cached_chat_dpop_token(
        &self,
        account_did_hash: String,
        token: String,
        expires_at_ms: i64,
    ) -> Result<(), MLSError> {
        let mut guard = self
            .dpop_cache
            .lock()
            .map_err(|_| MLSError::Internal("dpop_cache mutex poisoned".to_string()))?;
        guard.insert(account_did_hash, (token, expires_at_ms));
        Ok(())
    }
}

fn percent_encode_component(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len() + 8);
    for &b in raw.as_bytes() {
        if matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Whether `url` is `base` or lies under it: the same scheme, host and port after URL parsing,
/// and a path equal to `base`'s or continuing it after a `/`. A raw string prefix would also
/// accept `https://pds.example.evil`, `https://pds.example:4433` or `https://host/pds-other`.
fn endpoint_contains(base: &url::Url, url: &url::Url) -> bool {
    base.scheme() == url.scheme()
        && base.host() == url.host()
        && base.port_or_known_default() == url.port_or_known_default()
        && url
            .path()
            .strip_prefix(base.path().trim_end_matches('/'))
            .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
}

/// Direct ATProto PDS + federated `mls-ds` transport (`G3`: zero `nest` proxy).
/// Preserves `Atproto-Space-Mac` and `Atproto-Space-Credential` headers end-to-end (`Gate 7`).
/// Attaches the PDS bearer only to the PDS endpoint and the service-auth bearer only to the home
/// `mls-ds` endpoint ([`endpoint_contains`]); any other target gets no bearer.
pub struct BirdPlatformTransport {
    http: reqwest::Client,
    service_auth_token: RwLock<Option<String>>,
    pds_oauth_token: RwLock<Option<String>>,
    pds_endpoint: String,
    pds_base: Option<url::Url>,
    home_ds_base: Option<url::Url>,
    bot_did: Option<String>,
    home_ds_did: Option<String>,
}

impl BirdPlatformTransport {
    /// A transport that knows only its PDS endpoint: it never attaches the service-auth bearer.
    pub fn new(pds_endpoint: String) -> Self {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self {
            http,
            service_auth_token: RwLock::new(None),
            pds_oauth_token: RwLock::new(None),
            pds_base: url::Url::parse(&pds_endpoint).ok(),
            pds_endpoint,
            home_ds_base: None,
            bot_did: None,
            home_ds_did: None,
        }
    }

    pub fn with_identity(
        pds_endpoint: String,
        home_ds_endpoint: String,
        bot_did: String,
        home_ds_did: String,
    ) -> Self {
        let mut s = Self::new(pds_endpoint);
        s.home_ds_base = url::Url::parse(&home_ds_endpoint).ok();
        s.bot_did = Some(bot_did);
        s.home_ds_did = Some(home_ds_did);
        s
    }

    pub fn set_tokens(&self, service_auth: Option<String>, pds_oauth: Option<String>) {
        if let Ok(mut guard) = self.service_auth_token.write() {
            *guard = service_auth;
        }
        if let Ok(mut guard) = self.pds_oauth_token.write() {
            *guard = pds_oauth;
        }
    }
}

impl PlatformTransport for BirdPlatformTransport {
    fn execute_http(&self, request: PlatformHttpRequest) -> Result<PlatformHttpResponse, MLSError> {
        let is_local = request.url.starts_with("http://127.0.0.1")
            || request.url.starts_with("http://localhost");
        let is_spaces_probe = request.url.contains("/xrpc/com.atproto.space.getSpace");

        let http = self.http.clone();
        let pds_base = self.pds_endpoint.trim_end_matches('/').to_string();
        let target = url::Url::parse(&request.url).ok();
        let within = |base: &Option<url::Url>| match (base, &target) {
            (Some(base), Some(target)) => endpoint_contains(base, target),
            _ => false,
        };
        let is_pds_target = within(&self.pds_base);
        let is_home_ds_target = !is_pds_target && within(&self.home_ds_base);
        let pds_bearer = self.pds_oauth_token.read().ok().and_then(|g| g.clone());
        let ds_bearer = self.service_auth_token.read().ok().and_then(|g| g.clone());
        let bot_did = self.bot_did.clone();
        let home_ds_did = self.home_ds_did.clone();
        let req_clone = request;

        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| MLSError::Internal(format!("build transport runtime: {e}")))?;
            rt.block_on(async move {
                let method = reqwest::Method::from_bytes(req_clone.method.as_bytes())
                    .map_err(|e| MLSError::invalid_input(format!("invalid HTTP method: {e}")))?;
                let mut builder = http.request(method, &req_clone.url);
                let mut has_auth = false;
                for h in &req_clone.headers {
                    if h.name.eq_ignore_ascii_case("authorization") {
                        has_auth = true;
                    }
                    builder = builder.header(&h.name, &h.value);
                }
                if !has_auth {
                    if is_pds_target {
                        let effective_pds_tok = if is_spaces_probe {
                            pds_bearer.clone()
                        } else {
                            pds_bearer
                                .clone()
                                .or_else(|| is_local.then(|| "bot-pds-oauth".to_string()))
                        };
                        if let Some(tok) = effective_pds_tok {
                            builder = builder.bearer_auth(tok);
                        }
                    } else if is_home_ds_target {
                        let mut effective_ds_tok = ds_bearer.clone();
                        let has_jwt = effective_ds_tok
                            .as_deref()
                            .is_some_and(|t| t.matches('.').count() == 2);
                        if !has_jwt && req_clone.url.contains("/xrpc/blue.catbird.") {
                            if let (Some(iss), Some(ds_did)) = (&bot_did, &home_ds_did) {
                                if let Some(after_xrpc) = req_clone.url.split("/xrpc/").nth(1) {
                                    let nsid = after_xrpc.split('?').next().unwrap_or(after_xrpc);
                                    let ds_base = ds_did.split('#').next().unwrap_or(ds_did);
                                    let aud = format!("{ds_base}#atproto_mls");
                                    let sa_url = format!(
                                        "{pds_base}/xrpc/com.atproto.server.getServiceAuth?aud={}&lxm={}&iss={}",
                                        percent_encode_component(&aud),
                                        percent_encode_component(nsid),
                                        percent_encode_component(iss),
                                    );
                                    let sa_resp = http
                                        .get(&sa_url)
                                        .bearer_auth(
                                            pds_bearer.as_deref().unwrap_or("bot-pds-oauth"),
                                        )
                                        .send()
                                        .await
                                        .map_err(|e| {
                                            MLSError::Internal(format!(
                                                "mint getServiceAuth `{nsid}` failed: {e}"
                                            ))
                                        })?;
                                    if sa_resp.status().is_success() {
                                        if let Ok(val) = sa_resp.json::<serde_json::Value>().await {
                                            if let Some(t) =
                                                val.get("token").and_then(|v| v.as_str())
                                            {
                                                effective_ds_tok = Some(t.to_string());
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        if let Some(tok) = effective_ds_tok {
                            builder = builder.bearer_auth(tok);
                        }
                    }
                }
                if let Some(body) = req_clone.body {
                    builder = builder.body(body);
                }
                // A network failure or timeout is not a response: the request may or may not
                // have reached the server, so surface an error and let the core keep its
                // journaled request for its own retry. Real HTTP statuses (including 5xx)
                // pass through unchanged for the core's transient/terminal classification.
                let resp = builder
                    .send()
                    .await
                    .map_err(|e| MLSError::Internal(format!("HTTP transport failed: {e}")))?;
                let status = resp.status().as_u16();
                let headers = resp
                    .headers()
                    .iter()
                    .filter_map(|(k, v)| {
                        v.to_str().ok().map(|val| PlatformHttpHeader {
                            name: k.as_str().to_string(),
                            value: val.to_string(),
                        })
                    })
                    .collect();
                let body = resp
                    .bytes()
                    .await
                    .map_err(|e| MLSError::Internal(format!("read HTTP body: {e}")))?
                    .to_vec();
                Ok(PlatformHttpResponse {
                    status,
                    headers,
                    body,
                })
            })
        })
        .join()
        .map_err(|_| MLSError::Internal("HTTP transport thread panicked".to_string()))?
    }

    fn connect_realtime_stream(
        &self,
        _home_ds_endpoint: String,
        _cursor_seq: Option<i64>,
    ) -> Result<(), MLSError> {
        Ok(())
    }

    fn disconnect_realtime_stream(&self) -> Result<(), MLSError> {
        Ok(())
    }
}

struct NoopBotObserver;

impl PlatformChangeObserver for NoopBotObserver {
    fn on_change(&self, _event: PlatformChangeEvent) {}
}

fn extract_plaintext_body(plaintext_json: &str) -> String {
    if let Ok(val) = serde_json::from_str::<serde_json::Value>(plaintext_json) {
        if let Some(t) = val.get("text").and_then(|v| v.as_str()) {
            return t.to_string();
        }
    }
    plaintext_json.to_string()
}

/// Clean-slate federated `BIRDaemon` bot (`G3`).
pub struct FederatedBirdBot {
    config: FederatedBotConfig,
    client: Arc<CatbirdMlsClient>,
    transport: Arc<BirdPlatformTransport>,
    responder: Arc<dyn BotLlmResponder>,
    enrollment: EnrollmentReceipt,
    replied_message_ids: Mutex<std::collections::HashSet<String>>,
}

impl FederatedBirdBot {
    /// Open the per-account encrypted SQLCipher DB, verify `I15` Spaces + OAuth scope
    /// eligibility, and enroll `MLS_256_XWING` KeyPackages + `D4` Labyrinth default-on backup
    /// with zero `nest` dependency (`G3`).
    pub fn open_and_enroll(
        config: FederatedBotConfig,
        responder: Arc<dyn BotLlmResponder>,
    ) -> anyhow::Result<Self> {
        Self::open_and_enroll_with_tokens(config, responder, None, None)
    }

    /// Open and enroll with pre-configured `mls-ds` service-auth and PDS OAuth/session tokens.
    pub fn open_and_enroll_with_tokens(
        config: FederatedBotConfig,
        responder: Arc<dyn BotLlmResponder>,
        service_auth: Option<String>,
        pds_oauth: Option<String>,
    ) -> anyhow::Result<Self> {
        let precheck = evaluate_spaces_eligibility(&SpacesEligibilityInput {
            account_did: config.bot_did.clone(),
            pds_endpoint: config.pds_endpoint.clone(),
            pds_supports_spaces: config.pds_supports_spaces,
            granted_oauth_scopes: config.granted_oauth_scopes.clone(),
        });
        if !precheck.eligible {
            anyhow::bail!(
                "Spaces gate blocked bot enrollment: {}",
                precheck.user_message
            );
        }

        let keystore = Arc::new(BirdKeyStore::new(&config.storage_root)?);
        let transport = Arc::new(BirdPlatformTransport::with_identity(
            config.pds_endpoint.clone(),
            config.home_ds_endpoint.clone(),
            config.bot_did.clone(),
            config.home_ds_did.clone(),
        ));
        transport.set_tokens(service_auth, pds_oauth);
        let observer: Arc<dyn PlatformChangeObserver> = Arc::new(NoopBotObserver);

        let sdk_cfg = CatbirdMlsClientConfig {
            storage_root: config.storage_root.to_string_lossy().to_string(),
            account_did: config.bot_did.clone(),
            device_id: config.device_id.clone(),
            home_ds_did: config.home_ds_did.clone(),
            home_ds_endpoint: config.home_ds_endpoint.clone(),
            pds_endpoint: config.pds_endpoint.clone(),
        };

        let client = CatbirdMlsClient::open(
            sdk_cfg,
            keystore,
            Arc::clone(&transport) as Arc<dyn PlatformTransport>,
            Some(observer),
        )?;
        let enrollment = client.enroll_device(&config.granted_oauth_scopes)?;

        Ok(Self {
            config,
            client,
            transport,
            responder,
            enrollment,
            replied_message_ids: Mutex::new(std::collections::HashSet::new()),
        })
    }

    pub fn set_auth_tokens(&self, service_auth: Option<String>, pds_oauth: Option<String>) {
        self.transport.set_tokens(service_auth, pds_oauth);
    }

    pub fn account_did(&self) -> &str {
        self.client.account_did()
    }

    pub fn enrollment_receipt(&self) -> &EnrollmentReceipt {
        &self.enrollment
    }

    pub fn sdk_client(&self) -> &Arc<CatbirdMlsClient> {
        &self.client
    }

    pub fn labyrinth_status(&self) -> anyhow::Result<LabyrinthBackupStatus> {
        Ok(self.client.labyrinth_status()?)
    }

    pub fn create_group(
        &self,
        conversation_id: &str,
        member_dids: Vec<String>,
        title: Option<String>,
    ) -> anyhow::Result<ConversationRow> {
        Ok(self.client.create_group(
            conversation_id,
            &self.config.home_ds_did,
            member_dids,
            title,
            None,
        )?)
    }

    pub fn list_messages(
        &self,
        conversation_id: &str,
        limit: u32,
    ) -> anyhow::Result<Vec<MessageRow>> {
        Ok(self.client.list_messages(conversation_id, None, limit)?)
    }

    pub fn sync(&self) -> anyhow::Result<u32> {
        Ok(self.client.sync()?)
    }

    pub fn accept_pending_requests(&self) -> anyhow::Result<usize> {
        if !self.config.accept_chat_requests {
            return Ok(0);
        }
        let pending = self.client.list_requests(Some("pending"))?;
        let mut accepted = 0usize;
        for req in pending {
            self.client.accept_direct_request(&req.request_id)?;
            accepted += 1;
        }
        Ok(accepted)
    }

    /// Synchronize Welcomes, direct requests, leaf recovery inbox, and conversation entries
    /// from the bot's home `mls-ds`, accept pending chat requests when enabled, and generate +
    /// post encrypted MLS replies to any newly arrived `@mention` messages.
    pub async fn sync_and_reply(&self) -> anyhow::Result<Vec<MessageRow>> {
        let sdk = Arc::clone(&self.client);
        let accept = self.config.accept_chat_requests;
        let convos =
            tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<ConversationRow>> {
                sdk.sync()?;
                if accept {
                    for req in sdk.list_requests(Some("pending"))? {
                        sdk.accept_direct_request(&req.request_id)?;
                    }
                }
                Ok(sdk.list_conversations(None, 200)?)
            })
            .await??;

        let mut sent_replies = Vec::new();
        for convo in convos {
            let sdk = Arc::clone(&self.client);
            let cid = convo.conversation_id.clone();
            let mut msgs =
                tokio::task::spawn_blocking(move || sdk.list_messages(&cid, None, 50)).await??;
            msgs.reverse();
            for msg in msgs {
                if msg.is_own || msg.sender_did == self.client.account_did() {
                    continue;
                }
                {
                    let guard = self
                        .replied_message_ids
                        .lock()
                        .map_err(|_| anyhow::anyhow!("replied_message_ids mutex poisoned"))?;
                    if guard.contains(&msg.message_id) {
                        continue;
                    }
                }
                let text = extract_plaintext_body(&msg.plaintext_json);
                if let Some(reply_row) = self
                    .handle_incoming_group_text(&convo.conversation_id, &msg.sender_did, &text)
                    .await?
                {
                    if let Ok(mut guard) = self.replied_message_ids.lock() {
                        guard.insert(msg.message_id.clone());
                    }
                    sent_replies.push(reply_row);
                }
            }
        }
        Ok(sent_replies)
    }

    fn should_reply_to(&self, sender_did: &str, text: &str) -> bool {
        if sender_did == self.client.account_did() {
            return false;
        }
        if self.config.reply_to_all_messages {
            return true;
        }
        let mention_token = format!("@{}", self.config.bot_handle.trim_start_matches('@'));
        let lower_text = text.to_ascii_lowercase();
        lower_text.contains(&mention_token.to_ascii_lowercase())
            || lower_text.contains(&self.client.account_did().to_ascii_lowercase())
    }

    /// Process an inbound decrypted group/DM text message, generating an LLM reply and
    /// encrypting + sending an `MLS_256_XWING` reply message when addressed to the bot.
    pub async fn handle_incoming_group_text(
        &self,
        conversation_id: &str,
        sender_did: &str,
        text: &str,
    ) -> anyhow::Result<Option<MessageRow>> {
        if !self.should_reply_to(sender_did, text) {
            return Ok(None);
        }

        let mut reply = self.responder.generate_reply(sender_did, text).await?;
        let max_chars = self.config.max_reply_characters as usize;
        if max_chars > 0 && reply.chars().count() > max_chars {
            reply = reply.chars().take(max_chars).collect();
        }

        let message_id = uuid::Uuid::new_v4().to_string();
        let sdk = Arc::clone(&self.client);
        let cid = conversation_id.to_string();
        let row = tokio::task::spawn_blocking(move || sdk.send_message(&cid, &message_id, &reply))
            .await??;
        Ok(Some(row))
    }

    pub fn flush_labyrinth_queue(&self) -> anyhow::Result<u32> {
        Ok(self.client.flush_labyrinth_queue()?)
    }
}

#[cfg(test)]
mod tests {
    use super::endpoint_contains;

    fn url(raw: &str) -> url::Url {
        url::Url::parse(raw).unwrap()
    }

    #[test]
    fn endpoint_contains_rejects_suffix_port_scheme_userinfo_and_path_confusion() {
        let origin = url("https://pds.example");
        for inside in [
            "https://pds.example",
            "https://pds.example/xrpc/com.atproto.repo.getRecord?repo=x",
            "https://PDS.Example:443/xrpc/com.atproto.repo.getRecord",
        ] {
            assert!(endpoint_contains(&origin, &url(inside)), "{inside}");
        }
        for outside in [
            "https://pds.example.evil.com/xrpc/com.atproto.repo.getRecord",
            "https://pds.examplex/xrpc/com.atproto.repo.getRecord",
            "https://pds.example:4443/xrpc/com.atproto.repo.getRecord",
            "http://pds.example/xrpc/com.atproto.repo.getRecord",
            "https://pds.example@evil.com/xrpc/com.atproto.repo.getRecord",
            "https://evil.com/https://pds.example/xrpc/com.atproto.repo.getRecord",
        ] {
            assert!(!endpoint_contains(&origin, &url(outside)), "{outside}");
        }

        let based = url("https://host.example/pds/");
        for inside in [
            "https://host.example/pds",
            "https://host.example/pds/xrpc/x",
        ] {
            assert!(endpoint_contains(&based, &url(inside)), "{inside}");
        }
        for outside in [
            "https://host.example/pds-other/xrpc/x",
            "https://host.example/pdsx",
            "https://host.example/xrpc/x",
            "https://host.example/pds/../other/xrpc/x",
            "https://host.example/pds/%2e%2e/other/xrpc/x",
        ] {
            assert!(!endpoint_contains(&based, &url(outside)), "{outside}");
        }
    }
}
