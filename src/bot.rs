//! Clean-slate federated `BIRDaemon` bot runtime (`Spec §3 G3`, `G2`, `I15`, `I16`).
//!
//! Operates directly against the bot's home `mls-ds` + ATProto PDS Spaces (`com.atproto.space.*`)
//! via `catbird_mls::CatbirdMlsClient` and standard ATProto service auth / PDS OAuth tokens,
//! with zero `nest` dependency, URL, or session coupling.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::{STANDARD as BASE64_STANDARD, URL_SAFE_NO_PAD};
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

const SERVICE_AUTH_MAX_LIFETIME_SECONDS: i64 = 60;

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

fn parse_base_url(raw: &str, label: &str, allow_test_loopback: bool) -> Result<url::Url, MLSError> {
    let parsed = url::Url::parse(raw)
        .map_err(|e| MLSError::invalid_input(format!("invalid {label} URL: {e}")))?;
    if parsed.cannot_be_a_base()
        || parsed.host().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(MLSError::invalid_input(format!(
            "{label} must be an origin/base URL without credentials, query, or fragment"
        )));
    }
    let allow_test_loopback = test_loopback_allowed(allow_test_loopback);
    if parsed.scheme() != "https" && !(allow_test_loopback && parsed.scheme() == "http") {
        return Err(MLSError::invalid_input(format!("{label} must use HTTPS")));
    }
    Ok(parsed)
}

fn service_audience(home_ds_did: &str) -> Result<String, MLSError> {
    let (bare, fragment) = match home_ds_did.split_once('#') {
        Some((bare, fragment)) => (bare, Some(fragment)),
        None => (home_ds_did, None),
    };
    let Some((method, identifier)) = bare
        .strip_prefix("did:")
        .and_then(|value| value.split_once(':'))
    else {
        return Err(MLSError::invalid_input("home DS DID must be a DID"));
    };
    if method.is_empty()
        || !method
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        || identifier.is_empty()
        || identifier
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || matches!(byte, b'/' | b'?' | b'#'))
    {
        return Err(MLSError::invalid_input("home DS DID must be a DID"));
    }
    if fragment.is_some_and(|fragment| fragment != "atproto_mls") {
        return Err(MLSError::invalid_input(
            "home DS DID fragment must be #atproto_mls",
        ));
    }
    Ok(format!("{bare}#atproto_mls"))
}

fn xrpc_nsid(base: &url::Url, target: &url::Url) -> Option<String> {
    if !endpoint_contains(base, target) {
        return None;
    }
    let relative = target
        .path()
        .strip_prefix(base.path().trim_end_matches('/'))?;
    let nsid = relative.strip_prefix("/xrpc/")?;
    if nsid.is_empty()
        || nsid.starts_with('.')
        || nsid.ends_with('.')
        || nsid.contains("..")
        || !nsid.contains('.')
        || !nsid
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
    {
        return None;
    }
    Some(nsid.to_string())
}

fn has_xrpc_path(base: &url::Url, target: &url::Url) -> bool {
    endpoint_contains(base, target)
        && target
            .path()
            .strip_prefix(base.path().trim_end_matches('/'))
            .is_some_and(|relative| relative.starts_with("/xrpc/"))
}

fn forbidden_outbound_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            ip.is_loopback()
                || ip.is_private()
                || ip.is_link_local()
                || ip.is_multicast()
                || ip.is_unspecified()
                || a == 0
                || (a == 100 && (64..=127).contains(&b))
                || (a == 192 && b == 0 && c == 0)
                || (a == 192 && b == 0 && c == 2)
                || (a == 192 && b == 88 && c == 99)
                || (a == 198 && (b == 18 || b == 19))
                || (a == 198 && b == 51 && c == 100)
                || (a == 203 && b == 0 && c == 113)
                || a >= 240
        }
        IpAddr::V6(ip) => {
            let segments = ip.segments();
            ip.is_loopback()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
                || ip.is_multicast()
                || ip.is_unspecified()
                || (segments[0] & 0xffc0) == 0xfec0
                || (segments[0] & 0xe000) != 0x2000
                || (segments[0] == 0x2001 && segments[1] == 0x0db8)
                || segments[0] == 0x2002
                || (segments[0] == 0x3fff && segments[1] < 0x1000)
                || ip
                    .to_ipv4_mapped()
                    .is_some_and(|mapped| forbidden_outbound_ip(IpAddr::V4(mapped)))
        }
    }
}

fn test_loopback_allowed(requested: bool) -> bool {
    #[cfg(any(test, feature = "test-support"))]
    {
        requested
    }
    #[cfg(not(any(test, feature = "test-support")))]
    {
        let _ = requested;
        false
    }
}

fn client_pinned_to(
    target: &url::Url,
    addresses: &[SocketAddr],
    allow_test_loopback: bool,
) -> Result<reqwest::Client, MLSError> {
    let allow_test_loopback = test_loopback_allowed(allow_test_loopback);
    if addresses.is_empty() {
        return Err(MLSError::invalid_input(
            "outbound host resolved no addresses",
        ));
    }
    let all_loopback = addresses.iter().all(|address| address.ip().is_loopback());
    if target.scheme() != "https"
        && !(allow_test_loopback && target.scheme() == "http" && all_loopback)
    {
        return Err(MLSError::invalid_input(
            "outbound HTTP transport requires HTTPS",
        ));
    }
    for address in addresses {
        if forbidden_outbound_ip(address.ip())
            && !(allow_test_loopback && address.ip().is_loopback())
        {
            return Err(MLSError::invalid_input(format!(
                "outbound address class refused: {}",
                address.ip()
            )));
        }
    }
    let host = match target.host() {
        Some(url::Host::Domain(domain)) => std::borrow::Cow::Borrowed(domain),
        Some(url::Host::Ipv4(ip)) => std::borrow::Cow::Owned(ip.to_string()),
        Some(url::Host::Ipv6(ip)) => std::borrow::Cow::Owned(ip.to_string()),
        None => return Err(MLSError::invalid_input("outbound URL has no host")),
    };
    reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .resolve_to_addrs(host.as_ref(), addresses)
        .build()
        .map_err(|e| MLSError::Internal(format!("build pinned HTTP client: {e}")))
}

async fn hardened_client(
    target: &url::Url,
    allow_test_loopback: bool,
) -> Result<reqwest::Client, MLSError> {
    if !target.username().is_empty() || target.password().is_some() {
        return Err(MLSError::invalid_input(
            "outbound URL credentials are forbidden",
        ));
    }
    let allow_test_loopback = test_loopback_allowed(allow_test_loopback);
    if target.scheme() != "https" && !(allow_test_loopback && target.scheme() == "http") {
        return Err(MLSError::invalid_input(
            "outbound HTTP transport requires HTTPS",
        ));
    }

    let port = target
        .port_or_known_default()
        .ok_or_else(|| MLSError::invalid_input("outbound URL has no known port"))?;
    let addresses: Vec<SocketAddr> = match target.host() {
        Some(url::Host::Domain(domain)) => tokio::time::timeout(
            Duration::from_secs(15),
            tokio::net::lookup_host((domain, port)),
        )
        .await
        .map_err(|_| MLSError::Internal("outbound DNS resolution timed out".to_string()))?
        .map_err(|e| MLSError::Internal(format!("outbound DNS resolution failed: {e}")))?
        .collect(),
        Some(url::Host::Ipv4(ip)) => vec![SocketAddr::new(IpAddr::V4(ip), port)],
        Some(url::Host::Ipv6(ip)) => vec![SocketAddr::new(IpAddr::V6(ip), port)],
        None => return Err(MLSError::invalid_input("outbound URL has no host")),
    };
    client_pinned_to(target, &addresses, allow_test_loopback)
}

fn mint_error(nsid: &str, detail: impl std::fmt::Display) -> MLSError {
    MLSError::Internal(format!(
        "retryable service-auth mint `{nsid}` failed before DS send: {detail}"
    ))
}

fn validate_service_auth_token(
    token: &str,
    expected_issuer: &str,
    expected_audience: &str,
    expected_lxm: &str,
) -> Result<(), String> {
    let mut segments = token.split('.');
    let header_segment = segments.next().unwrap_or_default();
    let claims_segment = segments.next().unwrap_or_default();
    let signature_segment = segments.next().unwrap_or_default();
    if header_segment.is_empty()
        || claims_segment.is_empty()
        || signature_segment.is_empty()
        || segments.next().is_some()
    {
        return Err("token is not a three-segment JWT".to_string());
    }
    let header_bytes = URL_SAFE_NO_PAD
        .decode(header_segment)
        .map_err(|_| "JWT header is not base64url".to_string())?;
    let header: serde_json::Value =
        serde_json::from_slice(&header_bytes).map_err(|_| "JWT header is not JSON".to_string())?;
    if header.get("alg").and_then(|value| value.as_str()) != Some("ES256") {
        return Err("JWT algorithm must be ES256".to_string());
    }
    let signature = URL_SAFE_NO_PAD
        .decode(signature_segment)
        .map_err(|_| "JWT signature is not base64url".to_string())?;
    if signature.len() != 64 {
        return Err("JWT ES256 signature must be 64 bytes".to_string());
    }
    let claims_bytes = URL_SAFE_NO_PAD
        .decode(claims_segment)
        .map_err(|_| "JWT claims are not base64url".to_string())?;
    let claims: serde_json::Value =
        serde_json::from_slice(&claims_bytes).map_err(|_| "JWT claims are not JSON".to_string())?;
    if claims.get("iss").and_then(|value| value.as_str()) != Some(expected_issuer) {
        return Err("JWT issuer does not match the authenticated bot DID".to_string());
    }
    if claims.get("aud").and_then(|value| value.as_str()) != Some(expected_audience) {
        return Err("JWT audience does not match the home DS service".to_string());
    }
    if claims.get("lxm").and_then(|value| value.as_str()) != Some(expected_lxm) {
        return Err("JWT lxm does not match the exact XRPC method".to_string());
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock precedes the Unix epoch".to_string())?
        .as_secs() as i64;
    let expiry = claims
        .get("exp")
        .and_then(|value| value.as_i64())
        .ok_or_else(|| "JWT exp is missing or not an integer".to_string())?;
    if expiry <= now {
        return Err("JWT is expired".to_string());
    }
    if expiry > now + SERVICE_AUTH_MAX_LIFETIME_SECONDS {
        return Err("JWT lifetime exceeds 60 seconds".to_string());
    }
    if let Some(not_before) = claims.get("nbf") {
        let not_before = not_before
            .as_i64()
            .ok_or_else(|| "JWT nbf is not an integer".to_string())?;
        if not_before > now {
            return Err("JWT is not yet valid".to_string());
        }
    }
    Ok(())
}

async fn mint_service_auth_token(
    pds_base: &url::Url,
    pds_bearer: Option<&str>,
    issuer: &str,
    audience: &str,
    nsid: &str,
    allow_test_loopback: bool,
) -> Result<String, MLSError> {
    let pds_bearer = pds_bearer
        .filter(|token| !token.is_empty())
        .ok_or_else(|| mint_error(nsid, "missing PDS OAuth/session token"))?;
    let mut mint_url = pds_base.clone();
    let path = format!(
        "{}/xrpc/com.atproto.server.getServiceAuth",
        pds_base.path().trim_end_matches('/')
    );
    mint_url.set_path(&path);
    mint_url.set_query(None);
    mint_url
        .query_pairs_mut()
        .append_pair("aud", audience)
        .append_pair("lxm", nsid);

    let client = hardened_client(&mint_url, allow_test_loopback)
        .await
        .map_err(|error| mint_error(nsid, error))?;
    let response = client
        .get(mint_url)
        .bearer_auth(pds_bearer)
        .send()
        .await
        .map_err(|error| mint_error(nsid, error))?;
    let status = response.status();
    let body = response
        .bytes()
        .await
        .map_err(|error| mint_error(nsid, format!("response body read failed: {error}")))?;
    if !status.is_success() {
        return Err(mint_error(nsid, format!("PDS returned HTTP {status}")));
    }
    let value: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|error| mint_error(nsid, format!("response JSON invalid: {error}")))?;
    let token = value
        .get("token")
        .and_then(|value| value.as_str())
        .filter(|token| !token.is_empty())
        .ok_or_else(|| mint_error(nsid, "response token missing or empty"))?;
    if token == pds_bearer {
        return Err(mint_error(
            nsid,
            "PDS returned the account token instead of a service-auth token",
        ));
    }
    validate_service_auth_token(token, issuer, audience, nsid)
        .map_err(|error| mint_error(nsid, error))?;
    Ok(token.to_string())
}

/// Direct ATProto PDS + federated `mls-ds` transport (`G3`: zero `nest` proxy).
/// Preserves `Atproto-Space-Mac` and `Atproto-Space-Credential` headers end-to-end (`Gate 7`).
/// PDS and freshly minted method-bound service bearers remain confined to their configured parsed
/// origin and base-path boundary ([`endpoint_contains`]); any other target gets no bearer.
pub struct BirdPlatformTransport {
    pds_oauth_token: RwLock<Option<String>>,
    pds_base: url::Url,
    home_ds_base: Option<url::Url>,
    bot_did: Option<String>,
    home_ds_audience: Option<String>,
    allow_test_loopback: bool,
}

impl BirdPlatformTransport {
    fn new_with_policy(pds_endpoint: String, allow_test_loopback: bool) -> Result<Self, MLSError> {
        Ok(Self {
            pds_oauth_token: RwLock::new(None),
            pds_base: parse_base_url(&pds_endpoint, "PDS endpoint", allow_test_loopback)?,
            home_ds_base: None,
            bot_did: None,
            home_ds_audience: None,
            allow_test_loopback: test_loopback_allowed(allow_test_loopback),
        })
    }

    fn with_identity_policy(
        pds_endpoint: String,
        home_ds_endpoint: String,
        bot_did: String,
        home_ds_did: String,
        allow_test_loopback: bool,
    ) -> Result<Self, MLSError> {
        if !bot_did.starts_with("did:") {
            return Err(MLSError::invalid_input("bot identity must be a DID"));
        }
        let mut transport = Self::new_with_policy(pds_endpoint, allow_test_loopback)?;
        transport.home_ds_base = Some(parse_base_url(
            &home_ds_endpoint,
            "home DS endpoint",
            allow_test_loopback,
        )?);
        transport.bot_did = Some(bot_did);
        transport.home_ds_audience = Some(service_audience(&home_ds_did)?);
        Ok(transport)
    }

    /// Production transport: HTTPS and public addresses only.
    pub fn new(pds_endpoint: String) -> Result<Self, MLSError> {
        Self::new_with_policy(pds_endpoint, false)
    }

    /// Production transport with home-DS service-auth identity.
    pub fn with_identity(
        pds_endpoint: String,
        home_ds_endpoint: String,
        bot_did: String,
        home_ds_did: String,
    ) -> Result<Self, MLSError> {
        Self::with_identity_policy(pds_endpoint, home_ds_endpoint, bot_did, home_ds_did, false)
    }

    /// Local fixture transport. This API does not exist without a unit-test build or the
    /// non-default `test-support` feature.
    #[cfg(any(test, feature = "test-support"))]
    pub fn new_for_test(pds_endpoint: String) -> Result<Self, MLSError> {
        Self::new_with_policy(pds_endpoint, true)
    }

    /// Local fixture transport with home-DS identity.
    #[cfg(any(test, feature = "test-support"))]
    pub fn with_identity_for_test(
        pds_endpoint: String,
        home_ds_endpoint: String,
        bot_did: String,
        home_ds_did: String,
    ) -> Result<Self, MLSError> {
        Self::with_identity_policy(pds_endpoint, home_ds_endpoint, bot_did, home_ds_did, true)
    }

    pub fn set_pds_oauth_token(&self, pds_oauth: Option<String>) -> Result<(), MLSError> {
        *self
            .pds_oauth_token
            .write()
            .map_err(|_| MLSError::lock_poisoned("PDS OAuth token"))? = pds_oauth;
        Ok(())
    }
}

impl PlatformTransport for BirdPlatformTransport {
    fn execute_http(&self, request: PlatformHttpRequest) -> Result<PlatformHttpResponse, MLSError> {
        let target = url::Url::parse(&request.url)
            .map_err(|error| MLSError::invalid_input(format!("invalid outbound URL: {error}")))?;
        let method = reqwest::Method::from_bytes(request.method.as_bytes())
            .map_err(|error| MLSError::invalid_input(format!("invalid HTTP method: {error}")))?;
        let is_pds_target = endpoint_contains(&self.pds_base, &target);
        let pds_nsid = xrpc_nsid(&self.pds_base, &target);
        let home_match = self
            .home_ds_base
            .as_ref()
            .is_some_and(|base| endpoint_contains(base, &target));
        let home_nsid = self
            .home_ds_base
            .as_ref()
            .and_then(|base| xrpc_nsid(base, &target));
        if home_match
            && home_nsid.is_none()
            && self
                .home_ds_base
                .as_ref()
                .is_some_and(|base| has_xrpc_path(base, &target))
        {
            return Err(mint_error(
                "<invalid-nsid>",
                "home DS request has no exact XRPC NSID",
            ));
        }
        let pds_path_len = self.pds_base.path().trim_end_matches('/').len();
        let home_path_len = self
            .home_ds_base
            .as_ref()
            .map(|base| base.path().trim_end_matches('/').len())
            .unwrap_or_default();
        let is_home_ds_target = home_match
            && home_nsid.as_deref().is_some_and(|nsid| {
                !is_pds_target
                    || home_path_len > pds_path_len
                    || (home_path_len == pds_path_len && !nsid.starts_with("com.atproto."))
            });
        let is_pds_authenticated_target = is_pds_target
            && pds_nsid
                .as_deref()
                .is_some_and(|nsid| nsid.starts_with("com.atproto."));
        if is_pds_target
            && !is_home_ds_target
            && has_xrpc_path(&self.pds_base, &target)
            && !is_pds_authenticated_target
        {
            return Err(mint_error(
                pds_nsid.as_deref().unwrap_or("<invalid-nsid>"),
                "request is outside the configured home DS endpoint",
            ));
        }
        let pds_base = self.pds_base.clone();
        let pds_bearer = self
            .pds_oauth_token
            .read()
            .map_err(|_| MLSError::lock_poisoned("PDS OAuth token"))?
            .clone();
        let bot_did = self.bot_did.clone();
        let home_ds_audience = self.home_ds_audience.clone();
        let allow_test_loopback = self.allow_test_loopback;

        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| MLSError::Internal(format!("build transport runtime: {error}")))?;
            runtime.block_on(async move {
                let http = hardened_client(&target, allow_test_loopback).await?;
                let mut builder = http.request(method, target);
                for header in &request.headers {
                    if !header.name.eq_ignore_ascii_case("authorization")
                        && !header.name.eq_ignore_ascii_case("host")
                    {
                        builder = builder.header(&header.name, &header.value);
                    }
                }
                if is_home_ds_target {
                    let nsid = home_nsid
                        .as_deref()
                        .ok_or_else(|| MLSError::invalid_input("home DS XRPC NSID missing"))?;
                    let issuer = bot_did
                        .as_deref()
                        .ok_or_else(|| mint_error(nsid, "bot DID missing"))?;
                    let audience = home_ds_audience
                        .as_deref()
                        .ok_or_else(|| mint_error(nsid, "home DS audience missing"))?;
                    let token = mint_service_auth_token(
                        &pds_base,
                        pds_bearer.as_deref(),
                        issuer,
                        audience,
                        nsid,
                        allow_test_loopback,
                    )
                    .await?;
                    builder = builder.bearer_auth(token);
                } else if is_pds_authenticated_target {
                    if let Some(token) = pds_bearer.as_deref().filter(|token| !token.is_empty()) {
                        builder = builder.bearer_auth(token);
                    }
                }
                if let Some(body) = request.body {
                    builder = builder.body(body);
                }
                // Exactly one target request is attempted. A network error leaves the core's
                // exact journal bytes untouched; real HTTP statuses pass through unchanged.
                let response = builder.send().await.map_err(|error| {
                    MLSError::Internal(format!("HTTP transport failed: {error}"))
                })?;
                let status = response.status().as_u16();
                let headers = response
                    .headers()
                    .iter()
                    .filter_map(|(name, value)| {
                        value.to_str().ok().map(|value| PlatformHttpHeader {
                            name: name.as_str().to_string(),
                            value: value.to_string(),
                        })
                    })
                    .collect();
                let body = response
                    .bytes()
                    .await
                    .map_err(|error| MLSError::Internal(format!("read HTTP body: {error}")))?
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

#[cfg(test)]
mod transport_security_tests {
    use super::{client_pinned_to, forbidden_outbound_ip, BirdPlatformTransport};
    use std::io::{Read as _, Write as _};
    use std::net::{IpAddr, SocketAddr, TcpListener};

    #[test]
    fn test_support_does_not_weaken_default_constructors() {
        let loopback = "http://127.0.0.1:1".to_string();
        assert!(BirdPlatformTransport::new(loopback.clone()).is_err());
        assert!(BirdPlatformTransport::with_identity(
            loopback.clone(),
            loopback.clone(),
            "did:plc:testbot".to_string(),
            "did:web:test-ds.invalid".to_string(),
        )
        .is_err());

        let production = BirdPlatformTransport::new("https://pds.example.com".to_string()).unwrap();
        assert!(!production.allow_test_loopback);
        let fixture = BirdPlatformTransport::new_for_test(loopback).unwrap();
        assert!(fixture.allow_test_loopback);
    }

    #[test]
    fn production_policy_refuses_non_https_and_non_public_address_classes() {
        for raw in [
            "127.0.0.1",
            "10.0.0.1",
            "169.254.169.254",
            "224.0.0.1",
            "100.100.100.200",
            "192.0.2.1",
            "198.18.0.1",
            "203.0.113.1",
            "240.0.0.1",
            "0.0.0.0",
            "::1",
            "fc00::1",
            "fe80::1",
            "ff02::1",
            "::",
            "::ffff:127.0.0.1",
            "2001:db8::1",
            "2002:7f00:1::1",
            "3fff::1",
        ] {
            let ip: IpAddr = raw.parse().unwrap();
            assert!(forbidden_outbound_ip(ip), "{raw} must be refused");
            let url = url::Url::parse("https://target.invalid/xrpc/example.method").unwrap();
            assert!(client_pinned_to(&url, &[SocketAddr::new(ip, 443)], false).is_err());
        }
        for raw in ["8.8.8.8", "93.184.216.34", "2606:4700:4700::1111"] {
            let ip: IpAddr = raw.parse().unwrap();
            assert!(!forbidden_outbound_ip(ip), "{raw} must remain reachable");
        }

        let cleartext = url::Url::parse("http://target.invalid/xrpc/example.method").unwrap();
        let public = "93.184.216.34:80".parse().unwrap();
        assert!(client_pinned_to(&cleartext, &[public], false).is_err());
    }

    #[tokio::test]
    async fn validated_dns_address_is_pinned_and_mixed_rebind_answer_is_rejected() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0u8; 1024];
            let _ = stream.read(&mut request);
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
                .unwrap();
        });
        // `.invalid` cannot be resolved by the system. Success proves reqwest used only the
        // already-validated address rather than performing a second, rebindable lookup.
        let target =
            url::Url::parse(&format!("http://rebind.invalid:{}/pinned", address.port())).unwrap();
        let response = client_pinned_to(&target, &[address], true)
            .unwrap()
            .get(target)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        server.join().unwrap();

        let target = url::Url::parse("https://rebind.invalid/xrpc/example.method").unwrap();
        let public = "93.184.216.34:443".parse().unwrap();
        let rebound_private = "10.0.0.1:443".parse().unwrap();
        assert!(client_pinned_to(&target, &[public, rebound_private], false).is_err());
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
    /// Open the per-account encrypted SQLCipher DB, verify Spaces eligibility, and enroll with the
    /// PDS OAuth/session token used to mint a fresh, exact-lxm service token before each home-DS
    /// request.
    pub fn open_and_enroll_with_pds_token(
        config: FederatedBotConfig,
        responder: Arc<dyn BotLlmResponder>,
        pds_oauth: Option<String>,
    ) -> anyhow::Result<Self> {
        Self::open_and_enroll_with_policy(config, responder, pds_oauth, false)
    }

    /// Local-fixture variant, absent unless unit tests or the non-default `test-support` feature
    /// are compiled.
    #[cfg(any(test, feature = "test-support"))]
    pub fn open_and_enroll_with_pds_token_for_test(
        config: FederatedBotConfig,
        responder: Arc<dyn BotLlmResponder>,
        pds_oauth: Option<String>,
    ) -> anyhow::Result<Self> {
        Self::open_and_enroll_with_policy(config, responder, pds_oauth, true)
    }

    fn open_and_enroll_with_policy(
        config: FederatedBotConfig,
        responder: Arc<dyn BotLlmResponder>,
        pds_oauth: Option<String>,
        allow_test_loopback: bool,
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
        let transport = Arc::new(BirdPlatformTransport::with_identity_policy(
            config.pds_endpoint.clone(),
            config.home_ds_endpoint.clone(),
            config.bot_did.clone(),
            config.home_ds_did.clone(),
            allow_test_loopback,
        )?);
        transport.set_pds_oauth_token(pds_oauth)?;
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

    pub fn set_pds_oauth_token(&self, pds_oauth: Option<String>) -> Result<(), MLSError> {
        self.transport.set_pds_oauth_token(pds_oauth)
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
