//! Task 4 clean-chat authority boundary.
//!
//! This module deliberately keeps the Nest session opaque.  It owns the
//! loopback enrollment ceremony and the immutable actor/device/generation
//! snapshot used by every Nest-proxied request.  Downstream DPoP material is
//! never represented here.

use std::fmt;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD};
use base64::Engine as _;
use rand::RngCore;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::timeout;
use url::Url;

pub(crate) const CHAT_DEVICE_HEADER: &str = "x-catbird-chat-device-id";
const CALLBACK_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_CALLBACK_REQUEST: usize = 16 * 1024;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub(crate) enum AuthorityError {
    #[error("clean-chat authority is unavailable")]
    Unavailable,
    #[error("clean-chat callback route does not match the active enrollment")]
    CallbackRouteMismatch,
    #[error("clean-chat callback request is malformed")]
    CallbackMalformed,
    #[error("clean-chat enrollment was cancelled")]
    CallbackCancelled,
    #[error("clean-chat authorization code was replayed")]
    CodeReplay,
    #[error("clean-chat authorization code expired")]
    CodeExpired,
    #[error("clean-chat session is empty")]
    EmptySession,
    #[error("clean-chat session DID does not match the authenticated account")]
    AccountMismatch,
    #[error("clean-chat device does not match the admitted device")]
    DeviceMismatch,
    #[error("clean-chat authentication generation does not match the admitted device")]
    GenerationMismatch,
    #[error("clean-chat device is not active")]
    DeviceNotActive,
    #[error("clean-chat callback timed out")]
    CallbackTimedOut,
    #[error("clean-chat Nest request failed")]
    Transport,
    #[error("clean-chat Nest rejected the authority request")]
    Remote,
    #[error("clean-chat URL is invalid")]
    InvalidUrl,
    #[error("clean-chat session response is invalid")]
    InvalidSessionResponse,
    #[error("clean-chat device response is invalid")]
    InvalidDeviceResponse,
}

/// Session data returned by `/auth/session`. The session handle itself is kept
/// separately and is never included in Debug output or error messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SessionInfo {
    pub(crate) did: String,
    pub(crate) handle: String,
}

impl SessionInfo {
    pub(crate) fn new(did: String, handle: String) -> Self {
        Self { did, handle }
    }
}

/// The exact device binding returned by `getOwnDevices`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DeviceView {
    pub(crate) device_id: String,
    pub(crate) auth_generation: i64,
    pub(crate) status: String,
    pub(crate) key_id: String,
    pub(crate) signature_public_key: Vec<u8>,
}

impl DeviceView {
    pub(crate) fn new(device_id: String, auth_generation: i64) -> Self {
        Self {
            device_id,
            auth_generation,
            status: "active".into(),
            signature_public_key: vec![0; 32],
            key_id: derive_key_id(&[0; 32]),
        }
    }
}

/// Immutable, per-call clean-chat authority. The session handle is opaque: it
/// is valid only as a Nest bearer and is never parsed, refreshed, or forwarded
/// to the delivery service.
pub(crate) struct AuthoritySnapshot {
    session_handle: String,
    actor_did: String,
    device_id: String,
    auth_generation: i64,
    signer_handle: String,
    signer_public_key: Vec<u8>,
    signer_version: u64,
}

impl Clone for AuthoritySnapshot {
    fn clone(&self) -> Self {
        Self {
            session_handle: self.session_handle.clone(),
            actor_did: self.actor_did.clone(),
            device_id: self.device_id.clone(),
            auth_generation: self.auth_generation,
            signer_handle: self.signer_handle.clone(),
            signer_public_key: self.signer_public_key.clone(),
            signer_version: self.signer_version,
        }
    }
}

impl PartialEq for AuthoritySnapshot {
    fn eq(&self, other: &Self) -> bool {
        self.session_handle == other.session_handle
            && self.actor_did == other.actor_did
            && self.device_id == other.device_id
            && self.auth_generation == other.auth_generation
            && self.signer_handle == other.signer_handle
            && self.signer_public_key == other.signer_public_key
            && self.signer_version == other.signer_version
    }
}

impl Eq for AuthoritySnapshot {}

impl fmt::Debug for AuthoritySnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthoritySnapshot")
            .field("session_handle", &"<redacted>")
            .field("actor_did", &self.actor_did)
            .field("device_id", &self.device_id)
            .field("auth_generation", &self.auth_generation)
            .field("signer_handle", &self.signer_handle)
            .field("signer_public_key", &"<redacted>")
            .field("signer_version", &self.signer_version)
            .finish()
    }
}

impl AuthoritySnapshot {
    pub(crate) fn new(
        session_handle: String,
        actor_did: String,
        device_id: String,
        auth_generation: i64,
        signer_handle: String,
        signer_public_key: Vec<u8>,
        signer_version: u64,
    ) -> Result<Self, AuthorityError> {
        if session_handle.trim().is_empty() {
            return Err(AuthorityError::EmptySession);
        }
        validate_device_id(&device_id)?;
        if auth_generation < 1 {
            return Err(AuthorityError::GenerationMismatch);
        }
        if signer_handle.trim().is_empty() {
            return Err(AuthorityError::Unavailable);
        }
        if signer_public_key.len() != 32 || derive_key_id(&signer_public_key) != signer_handle {
            return Err(AuthorityError::Unavailable);
        }
        Ok(Self {
            session_handle,
            actor_did,
            device_id,
            auth_generation,
            signer_handle,
            signer_public_key,
            signer_version,
        })
    }

    /// Admit only after `/auth/session` and `getOwnDevices` have both proved
    /// the same DID/device/generation/signer tuple.
    pub(crate) fn admit(
        session_handle: String,
        session: &SessionInfo,
        expected_did: &str,
        devices: &[DeviceView],
        device_id: &str,
        auth_generation: i64,
        signer_handle: String,
        signer_public_key: &[u8],
        signer_version: u64,
    ) -> Result<Self, AuthorityError> {
        if session_handle.trim().is_empty() {
            return Err(AuthorityError::EmptySession);
        }
        if session.did != expected_did {
            return Err(AuthorityError::AccountMismatch);
        }
        let mut matching_devices = devices
            .iter()
            .filter(|device| device.device_id == device_id);
        let device = matching_devices
            .next()
            .ok_or(AuthorityError::DeviceMismatch)?;
        if matching_devices.next().is_some() {
            return Err(AuthorityError::InvalidDeviceResponse);
        }
        if device.auth_generation != auth_generation {
            return Err(AuthorityError::GenerationMismatch);
        }
        if device.key_id != signer_handle || device.signature_public_key != signer_public_key {
            return Err(AuthorityError::Unavailable);
        }
        if device.status != "active" {
            return Err(AuthorityError::DeviceNotActive);
        }
        Self::new(
            session_handle,
            session.did.clone(),
            device_id.into(),
            auth_generation,
            signer_handle,
            signer_public_key.to_vec(),
            signer_version,
        )
    }

    pub(crate) fn session_handle(&self) -> &str {
        &self.session_handle
    }

    pub(crate) fn actor_did(&self) -> &str {
        &self.actor_did
    }

    pub(crate) fn device_id(&self) -> &str {
        &self.device_id
    }

    pub(crate) fn auth_generation(&self) -> i64 {
        self.auth_generation
    }

    pub(crate) fn signer_handle(&self) -> &str {
        &self.signer_handle
    }

    pub(crate) fn signer_public_key(&self) -> &[u8] {
        &self.signer_public_key
    }

    pub(crate) fn signer_version(&self) -> u64 {
        self.signer_version
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InvalidationReason {
    AccountChanged,
    LoggedOut,
    Revoked,
    DeviceBindingChanged,
    GenerationChanged,
    Unauthorized,
    Forbidden,
}

/// Shared state whose lock protects replacement and invalidation. A caller
/// clones one snapshot before starting a request; later revocation cannot
/// mutate that in-flight request's tuple.
#[derive(Clone, Default)]
pub(crate) struct AuthorityState {
    current: Arc<RwLock<Option<AuthoritySnapshot>>>,
    invalidation_hook: Option<Arc<dyn Fn() -> Result<(), AuthorityError> + Send + Sync>>,
}

impl AuthorityState {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn with_invalidation_hook(
        hook: Arc<dyn Fn() -> Result<(), AuthorityError> + Send + Sync>,
    ) -> Self {
        Self {
            current: Arc::new(RwLock::new(None)),
            invalidation_hook: Some(hook),
        }
    }

    pub(crate) fn install(&self, snapshot: AuthoritySnapshot) {
        *self.current.write().expect("authority state poisoned") = Some(snapshot);
    }

    pub(crate) fn snapshot(&self) -> Option<AuthoritySnapshot> {
        self.current
            .read()
            .expect("authority state poisoned")
            .clone()
    }

    pub(crate) fn invalidate(&self, _reason: InvalidationReason) -> Result<(), AuthorityError> {
        *self.current.write().expect("authority state poisoned") = None;
        self.persist_invalidation()
    }

    pub(crate) fn invalidate_if_matches(
        &self,
        expected: &AuthoritySnapshot,
        reason: InvalidationReason,
    ) -> Result<bool, AuthorityError> {
        let mut current = self.current.write().expect("authority state poisoned");
        if current.as_ref() == Some(expected) {
            *current = None;
            drop(current);
            self.persist_invalidation()?;
            tracing::warn!(reason = ?reason, "Invalidated clean-chat authority");
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn persist_invalidation(&self) -> Result<(), AuthorityError> {
        if let Some(hook) = &self.invalidation_hook {
            hook()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CallbackRoute {
    port: u16,
    path: String,
}

impl CallbackRoute {
    pub(crate) fn new(port: u16, path: &str) -> Result<Self, AuthorityError> {
        if port == 0 || !path.starts_with('/') || path.contains('?') || path.contains('#') {
            return Err(AuthorityError::InvalidUrl);
        }
        Ok(Self {
            port,
            path: path.to_owned(),
        })
    }

    pub(crate) fn origin(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    pub(crate) fn redirect_uri(&self) -> String {
        format!("{}{}", self.origin(), self.path)
    }

    fn host(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CallbackResult {
    pub(crate) code: Option<String>,
    pub(crate) error: Option<String>,
}

pub(crate) fn parse_callback_request(
    request: &str,
    expected: &CallbackRoute,
) -> Result<CallbackResult, AuthorityError> {
    if request.len() > MAX_CALLBACK_REQUEST {
        return Err(AuthorityError::CallbackMalformed);
    }
    let mut lines = request.split("\r\n");
    let request_line = lines.next().ok_or(AuthorityError::CallbackMalformed)?;
    let mut request_parts = request_line.split_ascii_whitespace();
    if request_parts.next() != Some("GET") {
        return Err(AuthorityError::CallbackMalformed);
    }
    let target = request_parts
        .next()
        .ok_or(AuthorityError::CallbackMalformed)?;
    let version = request_parts.next();
    if !matches!(version, Some("HTTP/1.1") | Some("HTTP/1.0")) {
        return Err(AuthorityError::CallbackMalformed);
    }
    let mut host = None;
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("host") {
                host = Some(value.trim());
            }
        }
    }
    if host != Some(expected.host().as_str()) {
        return Err(AuthorityError::CallbackRouteMismatch);
    }
    let url = Url::parse(&format!("{}{}", expected.origin(), target))
        .map_err(|_| AuthorityError::CallbackMalformed)?;
    if url.path() != expected.path {
        return Err(AuthorityError::CallbackRouteMismatch);
    }
    let mut code = None;
    let mut error = None;
    for (name, value) in url.query_pairs() {
        match name.as_ref() {
            "code" if code.is_none() => code = Some(value.into_owned()),
            "error" if error.is_none() => error = Some(value.into_owned()),
            "code" | "error" => return Err(AuthorityError::CallbackMalformed),
            _ => {}
        }
    }
    if let Some(error) = error {
        return Ok(CallbackResult {
            code: None,
            error: Some(error),
        });
    }
    let Some(code) = code else {
        return Err(AuthorityError::CallbackMalformed);
    };
    validate_exchange_code(&code)?;
    Ok(CallbackResult {
        code: Some(code),
        error: None,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OneUseCode {
    code: String,
    expires_at: u64,
    used: bool,
}

impl OneUseCode {
    pub(crate) fn new(code: &str, expires_at: u64) -> Self {
        Self {
            code: code.to_owned(),
            expires_at,
            used: false,
        }
    }

    pub(crate) fn redeem(&mut self, candidate: &str, now: u64) -> Result<(), AuthorityError> {
        if self.used || candidate != self.code {
            return Err(AuthorityError::CodeReplay);
        }
        if now >= self.expires_at {
            return Err(AuthorityError::CodeExpired);
        }
        self.used = true;
        Ok(())
    }
}

fn validate_exchange_code(code: &str) -> Result<(), AuthorityError> {
    if code.len() != 43
        || !code
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(AuthorityError::CallbackMalformed);
    }
    Ok(())
}

fn validate_device_id(device_id: &str) -> Result<(), AuthorityError> {
    let parsed = uuid::Uuid::parse_str(device_id).map_err(|_| AuthorityError::DeviceMismatch)?;
    if parsed.get_version() != Some(uuid::Version::Random)
        || parsed.get_variant() != uuid::Variant::RFC4122
        || parsed.to_string() != device_id
    {
        return Err(AuthorityError::DeviceMismatch);
    }
    Ok(())
}

pub(crate) fn derive_key_id(public_key: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(public_key))
}

pub(crate) fn random_browser_nonce() -> String {
    let mut nonce = [0_u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    URL_SAFE_NO_PAD.encode(nonce)
}

pub(crate) fn redact_secrets(input: &str) -> String {
    let lower = input.to_ascii_lowercase();
    let labels = [
        "session",
        "code",
        "ticket",
        "dpop",
        "proof",
        "authorization",
    ];
    let mut output = input.to_owned();
    let mut positions = labels
        .iter()
        .flat_map(|label| {
            lower
                .match_indices(label)
                .filter_map(|(index, _)| input[index..].find('=').map(|offset| index + offset + 1))
        })
        .collect::<Vec<_>>();
    positions.sort_unstable_by(|a, b| b.cmp(a));
    for start in positions {
        let end = output[start..]
            .find([';', ',', '&', ' ', '\n', '\r'])
            .map(|offset| start + offset)
            .unwrap_or(output.len());
        output.replace_range(start..end, "<redacted>");
    }
    output
}

#[derive(Clone)]
pub(crate) struct NestClient {
    http: reqwest::Client,
    base_url: Url,
}

/// Lossless clean-chat response returned by Nest. HTTP protocol failures are
/// data at this boundary, not transport errors: the shared orchestrator needs
/// the exact status, media type, and body to classify typed XRPC outcomes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CleanChatHttpResponse {
    pub(crate) status: u16,
    pub(crate) content_type: Option<String>,
    pub(crate) body: Vec<u8>,
}

impl NestClient {
    pub(crate) fn new(base_url: &str) -> Result<Self, AuthorityError> {
        let base_url = Url::parse(base_url).map_err(|_| AuthorityError::InvalidUrl)?;
        if !matches!(base_url.scheme(), "http" | "https")
            || base_url.host_str().is_none()
            || !base_url.username().is_empty()
            || base_url.password().is_some()
            || base_url.query().is_some()
            || base_url.fragment().is_some()
        {
            return Err(AuthorityError::InvalidUrl);
        }
        Ok(Self {
            http: reqwest::Client::new(),
            base_url,
        })
    }

    fn endpoint(&self, path: &str) -> Result<Url, AuthorityError> {
        if !path.starts_with('/')
            || path.starts_with("//")
            || path.contains(['#', '\\'])
            || path.chars().any(char::is_control)
        {
            return Err(AuthorityError::InvalidUrl);
        }
        let (route, query) = path
            .split_once('?')
            .map_or((path, None), |(route, query)| (route, Some(query)));
        if route.contains('?') || query.is_some_and(|query| query.contains('?')) {
            return Err(AuthorityError::InvalidUrl);
        }
        let mut endpoint = self.base_url.clone();
        endpoint.set_path(route);
        endpoint.set_query(query);
        endpoint.set_fragment(None);
        Ok(endpoint)
    }

    pub(crate) fn login_url(
        &self,
        identifier: &str,
        route: &CallbackRoute,
        browser_nonce: &str,
    ) -> Result<Url, AuthorityError> {
        let mut url = self.endpoint("/auth/login")?;
        url.query_pairs_mut()
            .append_pair("identifier", identifier)
            .append_pair("client", "default")
            .append_pair("redirect_to", &route.redirect_uri())
            .append_pair("browser_nonce", browser_nonce);
        Ok(url)
    }

    /// Start a purpose-bound browser authorization and exchange its callback
    /// code exactly once. The browser nonce and redirect origin are kept local
    /// to this flow and are never logged.
    pub(crate) async fn establish_session(
        &self,
        identifier: &str,
    ) -> Result<String, AuthorityError> {
        self.establish_session_with(identifier, |url| {
            #[cfg(target_os = "macos")]
            {
                let status = std::process::Command::new("open")
                    .arg(url)
                    .status()
                    .map_err(|_| AuthorityError::Transport)?;
                if !status.success() {
                    return Err(AuthorityError::Transport);
                }
                Ok(())
            }
            #[cfg(not(target_os = "macos"))]
            {
                let _ = url;
                Err(AuthorityError::Transport)
            }
        })
        .await
    }

    pub(crate) async fn establish_session_with<F>(
        &self,
        identifier: &str,
        open_browser: F,
    ) -> Result<String, AuthorityError>
    where
        F: FnOnce(&str) -> Result<(), AuthorityError>,
    {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|_| AuthorityError::Transport)?;
        let port = listener
            .local_addr()
            .map_err(|_| AuthorityError::Transport)?
            .port();
        let path = format!("/callback/{}", uuid::Uuid::new_v4().simple());
        let route = CallbackRoute::new(port, &path)?;
        let browser_nonce = random_browser_nonce();
        let login_url = self.login_url(identifier, &route, &browser_nonce)?;
        let code_expires_at = unix_now().saturating_add(CALLBACK_TIMEOUT.as_secs());
        // Never print login_url: it contains a flow-bound browser nonce.
        open_browser(login_url.as_str())?;

        let deadline = tokio::time::Instant::now() + CALLBACK_TIMEOUT;
        let code = loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(AuthorityError::CallbackTimedOut);
            }
            let (mut stream, _) = timeout(remaining, listener.accept())
                .await
                .map_err(|_| AuthorityError::CallbackTimedOut)?
                .map_err(|_| AuthorityError::Transport)?;
            let mut bytes = vec![0u8; MAX_CALLBACK_REQUEST];
            let read = timeout(remaining, stream.read(&mut bytes))
                .await
                .map_err(|_| AuthorityError::CallbackTimedOut)?
                .map_err(|_| AuthorityError::Transport)?;
            bytes.truncate(read);
            let request = String::from_utf8(bytes).map_err(|_| AuthorityError::CallbackMalformed);
            match request.and_then(|request| parse_callback_request(&request, &route)) {
                Ok(callback) if callback.error.is_some() => {
                    let _ = write_callback_response(&mut stream, 200, "Sign-in cancelled").await;
                    return Err(AuthorityError::CallbackCancelled);
                }
                Ok(callback) => {
                    let _ = write_callback_response(&mut stream, 200, "Sign-in complete").await;
                    break callback.code.ok_or(AuthorityError::CallbackMalformed)?;
                }
                Err(_) => {
                    let _ = write_callback_response(&mut stream, 400, "Invalid callback").await;
                }
            }
        };
        let mut one_use_code = OneUseCode::new(&code, code_expires_at);
        one_use_code.redeem(&code, unix_now())?;
        self.exchange_code(&route, &browser_nonce, &code).await
    }

    async fn exchange_code(
        &self,
        route: &CallbackRoute,
        browser_nonce: &str,
        code: &str,
    ) -> Result<String, AuthorityError> {
        let response = self
            .http
            .post(self.endpoint("/auth/exchange")?)
            .header("Origin", route.origin())
            .json(&serde_json::json!({
                "code": code,
                "browser_nonce": browser_nonce,
            }))
            .send()
            .await
            .map_err(|_| AuthorityError::Transport)?;
        if !response.status().is_success() {
            return Err(AuthorityError::Remote);
        }
        let value: serde_json::Value = response
            .json()
            .await
            .map_err(|_| AuthorityError::InvalidSessionResponse)?;
        value
            .get("session_id")
            .and_then(serde_json::Value::as_str)
            .filter(|session| !session.is_empty())
            .map(ToOwned::to_owned)
            .ok_or(AuthorityError::InvalidSessionResponse)
    }

    async fn clean_chat_request(
        &self,
        session_handle: &str,
        device_id: &str,
        method: reqwest::Method,
        path: &str,
        body: Option<Vec<u8>>,
        query: Option<&[(&str, String)]>,
    ) -> Result<reqwest::Response, AuthorityError> {
        let mut request = self
            .http
            .request(method, self.endpoint(path)?)
            .header("Authorization", format!("Bearer {session_handle}"))
            .header(CHAT_DEVICE_HEADER, device_id);
        if let Some(query) = query {
            request = request.query(query);
        }
        if let Some(body) = body {
            request = request
                .header("Content-Type", "application/json")
                .body(body);
        }
        request.send().await.map_err(|_| AuthorityError::Transport)
    }

    /// Execute one ordinary clean-chat call through Nest. Nest's downstream
    /// service token and proof never leave this method.
    pub(crate) async fn get_clean_chat_response(
        &self,
        snapshot: &AuthoritySnapshot,
        path: &str,
    ) -> Result<CleanChatHttpResponse, AuthorityError> {
        let response = self
            .clean_chat_request(
                snapshot.session_handle(),
                snapshot.device_id(),
                reqwest::Method::GET,
                path,
                None,
                None,
            )
            .await?;
        clean_chat_http_response(response, snapshot).await
    }

    pub(crate) async fn session_info(
        &self,
        session_handle: &str,
    ) -> Result<SessionInfo, AuthorityError> {
        if session_handle.is_empty() {
            return Err(AuthorityError::EmptySession);
        }
        let response = self
            .http
            .get(self.endpoint("/auth/session")?)
            .header("Authorization", format!("Bearer {session_handle}"))
            .send()
            .await
            .map_err(|_| AuthorityError::Transport)?;
        if !response.status().is_success() {
            return Err(AuthorityError::Remote);
        }
        let value: serde_json::Value = response
            .json()
            .await
            .map_err(|_| AuthorityError::InvalidSessionResponse)?;
        let did = value
            .get("did")
            .and_then(serde_json::Value::as_str)
            .filter(|did| !did.is_empty())
            .ok_or(AuthorityError::InvalidSessionResponse)?;
        let handle = value
            .get("handle")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        Ok(SessionInfo::new(did.into(), handle.into()))
    }

    pub(crate) async fn post_signed_enrollment(
        &self,
        session_handle: &str,
        device_id: &str,
        request_body: Vec<u8>,
    ) -> Result<CleanChatHttpResponse, AuthorityError> {
        validate_device_id(device_id)?;
        let response = self
            .clean_chat_request(
                session_handle,
                device_id,
                reqwest::Method::POST,
                "/xrpc/blue.catbird.chat.enrollDevice",
                Some(request_body),
                None,
            )
            .await?;
        lossless_http_response(response).await
    }

    pub(crate) async fn own_devices(
        &self,
        session_handle: &str,
        device_id: &str,
    ) -> Result<Vec<DeviceView>, AuthorityError> {
        const MAX_DEVICE_PAGES: usize = 32;
        validate_device_id(device_id)?;
        let mut devices = Vec::new();
        let mut cursor: Option<String> = None;
        let mut seen_cursors = std::collections::HashSet::new();
        let mut seen_device_ids = std::collections::HashSet::new();
        let mut snapshot_expires_at: Option<String> = None;
        let captured_at = chrono::Utc::now();
        for _ in 0..MAX_DEVICE_PAGES {
            let request =
                catbird_atproto::blue_catbird::chat::get_own_devices::GetOwnDevices::<String> {
                    actor_device_id: device_id.to_owned(),
                    limit: Some(100),
                    page_cursor: cursor.clone(),
                };
            let mut query = vec![
                ("actorDeviceId", request.actor_device_id),
                ("limit", request.limit.expect("fixed limit").to_string()),
            ];
            if let Some(cursor) = request.page_cursor {
                query.push(("pageCursor", cursor));
            }
            let response = self
                .clean_chat_request(
                    session_handle,
                    device_id,
                    reqwest::Method::GET,
                    "/xrpc/blue.catbird.chat.getOwnDevices",
                    None,
                    Some(&query),
                )
                .await?;
            let response = lossless_http_response(response).await?;
            if !(200..300).contains(&response.status) {
                return Err(AuthorityError::Remote);
            }
            let output: catbird_atproto::blue_catbird::chat::get_own_devices::GetOwnDevicesOutput<
                String,
            > = serde_json::from_slice(&response.body)
                .map_err(|_| AuthorityError::InvalidDeviceResponse)?;
            let expiry = output.snapshot_expires_at.to_string();
            let parsed_expiry = chrono::DateTime::parse_from_rfc3339(&expiry)
                .map_err(|_| AuthorityError::InvalidDeviceResponse)?
                .with_timezone(&chrono::Utc);
            if parsed_expiry <= captured_at
                || snapshot_expires_at
                    .as_ref()
                    .is_some_and(|expected| expected != &expiry)
            {
                return Err(AuthorityError::InvalidDeviceResponse);
            }
            snapshot_expires_at.get_or_insert(expiry);
            for item in output.items {
                let device = parse_device_view(item.device)?;
                if !seen_device_ids.insert(device.device_id.clone()) {
                    return Err(AuthorityError::InvalidDeviceResponse);
                }
                devices.push(device);
            }
            if !output.has_more {
                if output.next_page_cursor.is_some() {
                    return Err(AuthorityError::InvalidDeviceResponse);
                }
                return Ok(devices);
            }
            let next_cursor = output
                .next_page_cursor
                .filter(|value| !value.is_empty() && value.len() <= 512)
                .ok_or(AuthorityError::InvalidDeviceResponse)?;
            if !seen_cursors.insert(next_cursor.clone()) {
                return Err(AuthorityError::InvalidDeviceResponse);
            }
            cursor = Some(next_cursor);
        }
        Err(AuthorityError::InvalidDeviceResponse)
    }

    pub(crate) async fn get_subscription_ticket_response(
        &self,
        snapshot: &AuthoritySnapshot,
        inventory_session_id: &str,
        event_cursor: &str,
    ) -> Result<CleanChatHttpResponse, AuthorityError> {
        let body = serde_json::to_vec(&serde_json::json!({
            "inventorySessionId": inventory_session_id,
            "eventCursor": event_cursor,
        }))
        .map_err(|_| AuthorityError::InvalidDeviceResponse)?;
        let response = self
            .clean_chat_request(
                snapshot.session_handle(),
                snapshot.device_id(),
                reqwest::Method::POST,
                "/xrpc/blue.catbird.chat.getSubscriptionTicket",
                Some(body),
                None,
            )
            .await?;
        clean_chat_http_response(response, snapshot).await
    }

    pub(crate) async fn post_clean_chat_signed_response(
        &self,
        snapshot: &AuthoritySnapshot,
        path: &str,
        request_body: Vec<u8>,
    ) -> Result<CleanChatHttpResponse, AuthorityError> {
        let response = self
            .clean_chat_request(
                snapshot.session_handle(),
                snapshot.device_id(),
                reqwest::Method::POST,
                path,
                Some(request_body),
                None,
            )
            .await?;
        clean_chat_http_response(response, snapshot).await
    }

    pub(crate) async fn get_blob(
        &self,
        snapshot: &AuthoritySnapshot,
        blob_id: &str,
    ) -> Result<CleanChatHttpResponse, AuthorityError> {
        let query = [("blobId", blob_id.to_string())];
        let response = self
            .clean_chat_request(
                snapshot.session_handle(),
                snapshot.device_id(),
                reqwest::Method::GET,
                "/xrpc/blue.catbird.chat.getBlob",
                None,
                Some(&query),
            )
            .await?;
        clean_chat_http_response(response, snapshot).await
    }
}

async fn clean_chat_http_response(
    response: reqwest::Response,
    _snapshot: &AuthoritySnapshot,
) -> Result<CleanChatHttpResponse, AuthorityError> {
    lossless_http_response(response).await
}

async fn lossless_http_response(
    response: reqwest::Response,
) -> Result<CleanChatHttpResponse, AuthorityError> {
    let status = response.status().as_u16();
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned);
    let body = response
        .bytes()
        .await
        .map_err(|_| AuthorityError::Transport)?
        .to_vec();
    Ok(CleanChatHttpResponse {
        status,
        content_type,
        body,
    })
}

fn parse_device_view(
    device: catbird_atproto::blue_catbird::chat::DeviceView<String>,
) -> Result<DeviceView, AuthorityError> {
    validate_device_id(device.device_id.as_str())?;
    let signature_public_key = device.signature_public_key.to_vec();
    let package_total = device
        .available_package_count
        .checked_add(device.reserved_package_count);
    if device.auth_generation < 1
        || device.status.is_empty()
        || signature_public_key.len() != 32
        || derive_key_id(&signature_public_key) != device.key_id.as_str()
        || device.available_package_count < 0
        || device.reserved_package_count < 0
        || package_total.is_none_or(|total| total > 1_000)
    {
        return Err(AuthorityError::InvalidDeviceResponse);
    }
    Ok(DeviceView {
        device_id: device.device_id,
        auth_generation: device.auth_generation,
        status: device.status,
        key_id: device.key_id,
        signature_public_key,
    })
}

async fn write_callback_response(
    stream: &mut tokio::net::TcpStream,
    status: u16,
    body: &str,
) -> Result<(), std::io::Error> {
    let response = format!(
        "HTTP/1.1 {status} OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).await
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    const DID: &str = "did:plc:z72i7hdynmk67x4h5wqf3s6a";
    const DEVICE: &str = "11111111-1111-4111-8111-111111111111";
    fn snapshot(session: &str, did: &str, device: &str, generation: i64) -> AuthoritySnapshot {
        AuthoritySnapshot::new(
            session.into(),
            did.into(),
            device.into(),
            generation,
            derive_key_id(&[0; 32]),
            vec![0; 32],
            1,
        )
        .unwrap()
    }

    #[test]
    fn callback_accepts_only_the_exact_random_loopback_route() {
        let expected = CallbackRoute::new(43127, "/callback/nonce-path").unwrap();
        let request = "GET /callback/nonce-path?code=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ HTTP/1.1\r\nHost: 127.0.0.1:43127\r\n\r\n";
        let callback = parse_callback_request(request, &expected).unwrap();
        assert_eq!(
            callback.code.as_deref(),
            Some("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ")
        );

        let wrong_path = request.replace("/callback/nonce-path", "/callback/other");
        assert!(matches!(
            parse_callback_request(&wrong_path, &expected),
            Err(AuthorityError::CallbackRouteMismatch)
        ));
        let wrong_host = request.replace("127.0.0.1:43127", "127.0.0.1:43128");
        assert!(matches!(
            parse_callback_request(&wrong_host, &expected),
            Err(AuthorityError::CallbackRouteMismatch)
        ));
    }

    #[test]
    fn callback_cancellation_is_terminal_and_never_redeems_a_code() {
        let expected = CallbackRoute::new(43127, "/callback/nonce-path").unwrap();
        let request = "GET /callback/nonce-path?error=access_denied HTTP/1.1\r\nHost: 127.0.0.1:43127\r\n\r\n";
        let callback = parse_callback_request(request, &expected).unwrap();
        assert_eq!(callback.error.as_deref(), Some("access_denied"));
        assert!(callback.code.is_none());
    }

    #[test]
    fn one_use_code_rejects_replay_and_expiry() {
        let mut code = OneUseCode::new("code-1", 100);
        assert!(code.redeem("code-1", 99).is_ok());
        assert!(matches!(
            code.redeem("code-1", 99),
            Err(AuthorityError::CodeReplay)
        ));

        let mut expired = OneUseCode::new("code-2", 100);
        assert!(matches!(
            expired.redeem("code-2", 100),
            Err(AuthorityError::CodeExpired)
        ));
    }

    #[test]
    fn browser_nonce_is_32_random_bytes_in_canonical_base64url() {
        let nonce = random_browser_nonce();
        assert_eq!(nonce.len(), 43);
        let decoded = URL_SAFE_NO_PAD.decode(&nonce).unwrap();
        assert_eq!(decoded.len(), 32);
        assert_eq!(URL_SAFE_NO_PAD.encode(decoded), nonce);
    }

    #[test]
    fn login_url_uses_standard_appview_parameters_and_random_loopback_origin() {
        let nest = NestClient::new("https://nest.example/").unwrap();
        let route = CallbackRoute::new(43127, "/callback/random-path").unwrap();
        let url = nest
            .login_url("alice.test", &route, "browser-nonce")
            .unwrap();
        let query = url
            .query_pairs()
            .collect::<std::collections::HashMap<_, _>>();
        assert!(!query.contains_key("chat_purpose"));
        assert_eq!(
            query.get("redirect_to").map(|value| value.as_ref()),
            Some("http://127.0.0.1:43127/callback/random-path")
        );
        assert_eq!(
            query.get("browser_nonce").map(|value| value.as_ref()),
            Some("browser-nonce")
        );
    }

    #[tokio::test]
    async fn own_devices_accepts_the_generated_jkt_free_response_shape() {
        let key_id = derive_key_id(&[0; 32]);
        let body = serde_json::json!({
            "hasMore": false,
            "items": [{"device": {
                "authGeneration": 7,
                "availablePackageCount": 1,
                "createdAt": "2026-08-23T12:00:00.000Z",
                "deviceId": DEVICE,
                "keyId": key_id,
                "reservedPackageCount": 0,
                "signaturePublicKey": {"$bytes": B64.encode([0_u8; 32])},
                "status": "active",
                "updatedAt": "2026-08-23T12:00:00.000Z"
            }}],
            "snapshotExpiresAt": "2099-08-23T12:05:00.000Z"
        })
        .to_string();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let nest = NestClient::new(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
        let server = tokio::spawn(http_fixture(listener, "200 OK", body));

        let devices = nest
            .own_devices("opaque-session", DEVICE)
            .await
            .unwrap();
        server.await.unwrap();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].device_id, DEVICE);
        assert_eq!(devices[0].auth_generation, 7);
    }

    async fn http_fixture(listener: TcpListener, status: &str, body: String) {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = [0_u8; 4096];
        let read = stream.read(&mut request).await.unwrap();
        let request = String::from_utf8_lossy(&request[..read]);
        assert!(request.contains("/xrpc/blue.catbird.chat.getOwnDevices"));
        assert!(request.contains("x-catbird-chat-device-id"));
        let response = format!(
            "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(response.as_bytes()).await.unwrap();
    }

    #[tokio::test]
    async fn own_devices_rejects_http_failure_without_jkt_headers() {
        let key_id = derive_key_id(&[0; 32]);
        let body = serde_json::json!({
            "hasMore": false,
            "items": [{"device": {
                "authGeneration": 7,
                "availablePackageCount": 1,
                "createdAt": "2026-08-23T12:00:00.000Z",
                "deviceId": DEVICE,
                "keyId": key_id,
                "reservedPackageCount": 0,
                "signaturePublicKey": {"$bytes": B64.encode([0_u8; 32])},
                "status": "active",
                "updatedAt": "2026-08-23T12:00:00.000Z"
            }}],
            "snapshotExpiresAt": "2099-08-23T12:05:00.000Z"
        })
        .to_string();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}/", listener.local_addr().unwrap());
        let nest = NestClient::new(&base).unwrap();
        let port = tokio::spawn(http_fixture(listener, "200 OK", body));
        let devices = nest.own_devices("opaque-session", DEVICE).await.unwrap();
        port.await.unwrap();
        assert_eq!(devices[0].key_id, key_id);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let nest = NestClient::new(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
        let port = tokio::spawn(http_fixture(listener, "401 Unauthorized", "{}".into()));
        assert!(matches!(
            nest.own_devices("opaque-session", DEVICE).await,
            Err(AuthorityError::Remote)
        ));
        port.await.unwrap();
    }

    #[tokio::test]
    async fn own_devices_paginates_before_restart_admission() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let nest = NestClient::new(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
        let key_id = derive_key_id(&[0; 32]);
        let server = tokio::spawn(async move {
            for (page, has_more, next_cursor) in [
                (
                    serde_json::json!({
                        "device": {
                            "authGeneration": 3,
                            "availablePackageCount": 1,
                            "createdAt": "2026-08-23T12:00:00.000Z",
                            "deviceId": "80808080-8080-4080-b080-808080808080",
                            "keyId": key_id,
                            "reservedPackageCount": 0,
                            "signaturePublicKey": {"$bytes": B64.encode([0_u8; 32])},
                            "status": "active",
                            "updatedAt": "2026-08-23T12:00:00.000Z"
                        }
                    }),
                    true,
                    Some("page-2"),
                ),
                (
                    serde_json::json!({
                        "device": {
                            "authGeneration": 7,
                            "availablePackageCount": 1,
                            "createdAt": "2026-08-23T12:00:00.000Z",
                            "deviceId": DEVICE,
                            "keyId": key_id,
                            "reservedPackageCount": 0,
                            "signaturePublicKey": {"$bytes": B64.encode([0_u8; 32])},
                            "status": "active",
                            "updatedAt": "2026-08-23T12:00:00.000Z"
                        }
                    }),
                    false,
                    None,
                ),
            ] {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = [0_u8; 4096];
                let read = stream.read(&mut request).await.unwrap();
                let request = String::from_utf8_lossy(&request[..read]);
                assert!(request.contains("getOwnDevices"));
                if next_cursor.is_none() {
                    assert!(request.contains("pageCursor=page-2"));
                }
                let body = serde_json::json!({
                    "items": [page],
                    "hasMore": has_more,
                    "nextPageCursor": next_cursor,
                    "snapshotExpiresAt": "2099-08-23T12:05:00.000Z",
                })
                .to_string();
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            }
        });

        let devices = nest.own_devices("opaque-session", DEVICE).await.unwrap();
        server.await.unwrap();
        assert_eq!(devices.len(), 2);
        assert_eq!(devices[1].device_id, DEVICE);
    }

    #[test]
    fn authority_admission_requires_exact_account_device_generation_and_signer() {
        let session = SessionInfo::new(DID.into(), "alice.test".into());
        let device = DeviceView::new(DEVICE.into(), 7);
        let admitted = AuthoritySnapshot::admit(
            "opaque-session".into(),
            &session,
            DID,
            &[device.clone()],
            DEVICE,
            7,
            derive_key_id(&[0; 32]),
            &[0; 32],
            1,
        )
        .unwrap();
        assert_eq!(admitted.actor_did(), DID);
        assert!(matches!(
            AuthoritySnapshot::admit(
                "opaque-session".into(),
                &session,
                DID,
                &[device.clone(), device.clone()],
                DEVICE,
                7,
                derive_key_id(&[0; 32]),
                &[0; 32],
                1
            ),
            Err(AuthorityError::InvalidDeviceResponse)
        ));

        let wrong_did = SessionInfo::new(
            "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa".into(),
            "other.test".into(),
        );
        assert!(matches!(
            AuthoritySnapshot::admit(
                "opaque-session".into(),
                &wrong_did,
                DID,
                &[device.clone()],
                DEVICE,
                7,
                derive_key_id(&[0; 32]),
                &[0; 32],
                1
            ),
            Err(AuthorityError::AccountMismatch)
        ));
        assert!(matches!(
            AuthoritySnapshot::admit(
                "opaque-session".into(),
                &session,
                DID,
                &[device.clone()],
                DEVICE,
                8,
                derive_key_id(&[0; 32]),
                &[0; 32],
                1
            ),
            Err(AuthorityError::GenerationMismatch)
        ));
        assert!(matches!(
            AuthoritySnapshot::admit(
                "opaque-session".into(),
                &session,
                DID,
                &[],
                DEVICE,
                7,
                derive_key_id(&[0; 32]),
                &[0; 32],
                1
            ),
            Err(AuthorityError::DeviceMismatch)
        ));
        let mut signer_mismatch = DeviceView::new(DEVICE.into(), 7);
        signer_mismatch.key_id = "wrong-key-id".into();
        assert!(matches!(
            AuthoritySnapshot::admit(
                "opaque-session".into(),
                &session,
                DID,
                &[signer_mismatch],
                DEVICE,
                7,
                derive_key_id(&[0; 32]),
                &[0; 32],
                1
            ),
            Err(AuthorityError::Unavailable)
        ));
    }

    #[test]
    fn state_snapshot_is_immutable_per_call_and_invalidation_is_tuple_bound() {
        let state = AuthorityState::new();
        let first = snapshot("opaque-a", DID, DEVICE, 7);
        state.install(first.clone());
        let in_flight = state.snapshot().unwrap();
        let replacement = snapshot("opaque-b", DID, DEVICE, 8);
        state.install(replacement.clone());
        assert_eq!(in_flight.session_handle(), "opaque-a");
        assert_eq!(state.snapshot().unwrap().auth_generation(), 8);
        assert!(!state
            .invalidate_if_matches(&first, InvalidationReason::GenerationChanged)
            .unwrap());
        assert!(state.snapshot().is_some());
        assert!(state
            .invalidate_if_matches(&replacement, InvalidationReason::Revoked)
            .unwrap());
        assert!(state.snapshot().is_none());
    }

    #[test]
    fn invalidation_clears_persistence_hook_before_restart_admission() {
        let persisted = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let persisted_for_hook = persisted.clone();
        let state = AuthorityState::with_invalidation_hook(Arc::new(move || {
            persisted_for_hook.store(false, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }));
        state.install(snapshot("opaque-a", DID, DEVICE, 7));
        state.invalidate(InvalidationReason::Unauthorized).unwrap();
        assert!(!persisted.load(std::sync::atomic::Ordering::SeqCst));
        assert!(state.snapshot().is_none());
    }

    #[test]
    fn secret_safe_logging_redacts_session_code_ticket_and_dpop_proof() {
        let input = "session=opaque-session-code; code=authorization-code-1; ticket=ticket-secret; DPoP=proof-secret";
        let redacted = redact_secrets(input);
        assert!(!redacted.contains("opaque-session-code"));
        assert!(!redacted.contains("authorization-code-1"));
        assert!(!redacted.contains("ticket-secret"));
        assert!(!redacted.contains("proof-secret"));
        assert!(redacted.contains("<redacted>"));
    }

    #[test]
    fn restart_admission_does_not_accept_a_stale_device_tuple() {
        let session = SessionInfo::new(DID.into(), "alice.test".into());
        let stale = DeviceView::new(DEVICE.into(), 7);
        assert!(AuthoritySnapshot::admit(
            "opaque-session".into(),
            &session,
            DID,
            &[stale],
            DEVICE,
            8,
            derive_key_id(&[0; 32]),
            &[0; 32],
            1
        )
        .is_err());
        let fresh = DeviceView::new(DEVICE.into(), 8);
        assert!(AuthoritySnapshot::admit(
            "opaque-session".into(),
            &session,
            DID,
            &[fresh],
            DEVICE,
            8,
            derive_key_id(&[0; 32]),
            &[0; 32],
            2
        )
        .is_ok());
    }
}
