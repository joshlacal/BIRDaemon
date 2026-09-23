//! Debug-only adapter for the local client runtime gateway.
//!
//! This module never changes process-wide DNS or trust. It builds one isolated
//! HTTP client from the gateway's retained manifest and exposes only the
//! selected synthetic account/session to the daemon runtime.

#![cfg(debug_assertions)]

use anyhow::{ensure, Context, Result};
use base64::Engine;
use catbird_mls::orchestrator::credentials::CredentialStore;
use reqwest::redirect::Policy;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::SocketAddr,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    time::Duration,
};
use url::Url;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct DebugFixtureRunConfig {
    pub(crate) manifest_path: PathBuf,
    pub(crate) sessions_path: PathBuf,
    pub(crate) account_label: String,
    pub(crate) data_dir: PathBuf,
    #[serde(alias = "bridgeURL")]
    pub(crate) bridge_url: String,
    #[serde(default)]
    pub(crate) receive_chat_requests: bool,
    #[serde(default)]
    pub(crate) accept_chat_requests: bool,
    #[serde(default)]
    pub(crate) reply_to_all_messages: bool,
    #[serde(default = "default_max_reply_characters")]
    pub(crate) max_reply_characters: u32,
}

fn default_max_reply_characters() -> u32 {
    1000
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Manifest {
    fixture_only: bool,
    origin: String,
    cors_origin: String,
    ca_pem: PathBuf,
    #[serde(default)]
    tls_certificate_pem: Option<PathBuf>,
    #[serde(default)]
    tls_spki_sha256: Option<String>,
    hosts: BTreeMap<String, String>,
    accounts: Vec<PublicAccount>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PublicAccount {
    label: String,
    did: String,
    device_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProtectedSessions {
    accounts: Vec<ProtectedAccount>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProtectedAccount {
    label: String,
    did: String,
    device_id: String,
    session: String,
}

#[derive(Clone, Debug)]
pub(crate) struct DebugFixtureContext {
    pub(crate) config: DebugFixtureRunConfig,
    pub(crate) origin: String,
    pub(crate) did: String,
    pub(crate) handle: String,
    pub(crate) reserved_device_id: String,
    pub(crate) session: String,
    pub(crate) http: reqwest::Client,
}

impl DebugFixtureContext {
    pub(crate) fn load(path: &Path) -> Result<Self> {
        ensure!(path.is_absolute(), "debug fixture run config must be absolute");
        let config: DebugFixtureRunConfig = serde_json::from_slice(
            &std::fs::read(path).context("read debug fixture run config")?,
        )
        .context("decode debug fixture run config")?;
        for candidate in [
            &config.manifest_path,
            &config.sessions_path,
            &config.data_dir,
        ] {
            ensure!(candidate.is_absolute(), "debug fixture paths must be absolute");
        }
        ensure!(
            config.manifest_path != config.sessions_path,
            "manifest and protected sessions must be distinct"
        );
        ensure!(
            (1..=16_384).contains(&config.max_reply_characters),
            "max reply characters must be bounded"
        );
        let bridge = Url::parse(&config.bridge_url).context("invalid bridge URL")?;
        ensure!(
            bridge.scheme() == "http"
                && matches!(bridge.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"))
                && bridge.username().is_empty()
                && bridge.password().is_none()
                && bridge.query().is_none()
                && bridge.fragment().is_none()
                && bridge.path() == "/",
            "debug bridge must be one exact loopback HTTP origin"
        );
        validate_private_file(&config.sessions_path)?;
        let manifest: Manifest = serde_json::from_slice(
            &std::fs::read(&config.manifest_path).context("read gateway manifest")?,
        )
        .context("decode gateway manifest")?;
        ensure!(manifest.fixture_only, "gateway manifest is not fixture-only");
        let origin = Url::parse(&manifest.origin).context("invalid gateway origin")?;
        ensure!(
            origin.scheme() == "https"
                && origin.username().is_empty()
                && origin.password().is_none()
                && origin.query().is_none()
                && origin.fragment().is_none()
                && origin.path() == "/",
            "gateway origin must be one exact HTTPS origin"
        );
        let origin_host = origin.host_str().context("gateway origin omitted host")?;
        ensure!(
            manifest.hosts.contains_key(origin_host),
            "gateway origin is absent from its host map"
        );
        let cors = Url::parse(&manifest.cors_origin).context("invalid manifest CORS origin")?;
        ensure!(
            matches!(cors.scheme(), "http" | "https")
                && matches!(cors.host_str(), Some("127.0.0.1" | "localhost" | "[::1]")),
            "manifest CORS origin is not loopback"
        );
        ensure!(manifest.ca_pem.is_absolute(), "fixture CA path must be absolute");
        if let Some(certificate) = &manifest.tls_certificate_pem {
            ensure!(certificate.is_absolute(), "fixture certificate path must be absolute");
        }
        if let Some(spki) = &manifest.tls_spki_sha256 {
            ensure!(!spki.is_empty(), "fixture SPKI digest is empty");
        }
        let protected: ProtectedSessions = serde_json::from_slice(
            &std::fs::read(&config.sessions_path).context("read protected gateway sessions")?,
        )
        .context("decode protected gateway sessions")?;
        let public = exactly_one(
            manifest
                .accounts
                .iter()
                .filter(|account| account.label == config.account_label),
            "public account label",
        )?;
        let secret = exactly_one(
            protected
                .accounts
                .iter()
                .filter(|account| account.label == config.account_label),
            "protected account label",
        )?;
        ensure!(
            public.did == secret.did && public.device_id == secret.device_id,
            "public and protected account coordinates differ"
        );
        ensure!(
            !secret.session.is_empty() && secret.session.len() <= 4096,
            "fixture session is absent or unbounded"
        );
        let did_host = public
            .did
            .strip_prefix("did:web:")
            .context("fixture account is not did:web")?;
        ensure!(
            manifest.hosts.contains_key(did_host),
            "fixture account host is absent from the host map"
        );
        let parsed_device = uuid::Uuid::parse_str(&public.device_id)
            .context("fixture reserved device ID is not a UUID")?;
        ensure!(
            parsed_device.get_version() == Some(uuid::Version::Random)
                && parsed_device.to_string() == public.device_id,
            "fixture reserved device ID is not canonical v4"
        );
        let mut addresses = BTreeSet::new();
        let mut resolved = Vec::new();
        for (host, raw_address) in &manifest.hosts {
            ensure!(
                !host.is_empty()
                    && !host.contains(['/', ':'])
                    && host == &host.to_ascii_lowercase(),
                "fixture host map contains an invalid hostname"
            );
            let address: SocketAddr = raw_address
                .parse()
                .with_context(|| format!("invalid fixture address for {host}"))?;
            ensure!(
                address.ip().is_loopback() && address.port() != 0,
                "fixture host map escaped loopback"
            );
            addresses.insert(address);
            resolved.push((host.clone(), address));
        }
        ensure!(
            addresses.len() == 1,
            "fixture hosts must share one exact loopback TLS endpoint"
        );
        ensure!(
            !config.data_dir.exists() || config.data_dir.is_dir(),
            "debug data path is not a directory"
        );
        let mut builder = reqwest::Client::builder()
            .no_proxy()
            .redirect(Policy::none())
            .timeout(Duration::from_secs(45))
            .add_root_certificate(reqwest::Certificate::from_pem(
                &std::fs::read(&manifest.ca_pem).context("read fixture CA")?,
            )?);
        for (host, address) in resolved {
            builder = builder.resolve(&host, address);
        }
        let http = builder.build().context("build isolated fixture HTTP client")?;
        Ok(Self {
            handle: did_host.to_owned(),
            origin: manifest.origin,
            did: public.did.clone(),
            reserved_device_id: public.device_id.clone(),
            session: secret.session.clone(),
            config,
            http,
        })
    }
}

pub(crate) fn required_config_path() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("BIRD_RUNTIME_FIXTURE_CONFIG") {
        let path = PathBuf::from(path);
        if !path.as_os_str().is_empty() {
            return Ok(path);
        }
    }
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--fixture" {
            if let Some(path) = args.next() {
                if !path.is_empty() {
                    return Ok(PathBuf::from(path));
                }
            }
        }
    }
    anyhow::bail!("Fixture binary requires BIRD_RUNTIME_FIXTURE_CONFIG; production profile fallback is forbidden")
}

pub(crate) async fn preseed_native_authority(
    context: &DebugFixtureContext,
    mls_context: &catbird_mls::MLSContext,
    credentials: &crate::credentials::FileCredentialStore,
) -> Result<()> {
    let mls_did = format!("{}#{}", context.did, context.reserved_device_id);
    if mls_context.identity_public_key(mls_did.clone()).is_err() {
        mls_context
            .create_key_package(mls_did.as_bytes().to_vec())
            .map_err(|e| anyhow::anyhow!("Cannot initialize protected fixture identity: {e}"))?;
    }
    let private = mls_context
        .export_identity_key(mls_did.clone())
        .map_err(|e| anyhow::anyhow!("Cannot export native identity key: {e}"))?;
    mls_context
        .import_identity_key(context.did.clone(), private.clone())
        .map_err(|e| anyhow::anyhow!("Cannot restore native compatibility identity: {e}"))?;
    credentials.store_signing_key(&context.did, &private).await?;
    credentials.store_opaque_chat_session(&context.did, &context.session)?;
    credentials.install_admitted_device_tuple(
        &context.did,
        &context.reserved_device_id,
        &mls_did,
        1,
    )?;
    let public = mls_context.identity_public_key(mls_did)?;
    let response = context
        .http
        .post(format!("{}/fixture/enroll", context.origin))
        .bearer_auth(&context.session)
        .json(&serde_json::json!({
            "device_id": context.reserved_device_id,
            "signature_public_key": base64::engine::general_purpose::STANDARD.encode(public),
        }))
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("Native public-key fixture preseed failed: {e}"))?;
    ensure!(
        response.status().is_success(),
        "Native fixture preseed rejected: {}",
        response.status()
    );
    Ok(())
}

pub(crate) struct DebugFixtureRuntime {
    pub(crate) context: DebugFixtureContext,
    pub(crate) bot: std::sync::Arc<crate::bot::BirdBot>,
    pub(crate) orchestrator: std::sync::Arc<crate::BirdOrchestrator>,
    pub(crate) storage: std::sync::Arc<crate::storage::SqliteStorage>,
    pub(crate) credentials: std::sync::Arc<crate::credentials::FileCredentialStore>,
    pub(crate) api_client: std::sync::Arc<crate::xrpc_client::BirdApiClient>,
    pub(crate) authority_state: std::sync::Arc<crate::chat_authority::AuthorityState>,
    pub(crate) nest: std::sync::Arc<crate::chat_authority::NestClient>,
}

pub(crate) async fn assemble_runtime(context: DebugFixtureContext) -> Result<DebugFixtureRuntime> {
    let data_dir = &context.config.data_dir;
    std::fs::create_dir_all(data_dir)?;
    let creds_path = data_dir.join("credentials.json");
    let credentials = std::sync::Arc::new(
        crate::credentials::FileCredentialStore::new(creds_path)
            .map_err(|e| anyhow::anyhow!("Failed to open MLS credentials: {e}"))?,
    );
    let invalidation_credentials = credentials.clone();
    let invalidation_did = context.did.clone();
    let authority_state = std::sync::Arc::new(crate::chat_authority::AuthorityState::with_invalidation_hook(std::sync::Arc::new(
        move || {
            invalidation_credentials
                .clear_clean_chat_authority(&invalidation_did)
                .map_err(|_| crate::chat_authority::AuthorityError::Unavailable)
        },
    )));
    let nest = std::sync::Arc::new(crate::chat_authority::NestClient::new_with_client(&context.origin, context.http.clone()).map_err(|_| {
        anyhow::anyhow!("fixture Nest base URL is invalid")
    })?);
    let session = std::sync::Arc::new(jacquard::client::MemoryCredentialSession::unauthenticated());
    let api_client = crate::xrpc_client::BirdApiClient::new(
        context.origin.clone(),
        session,
        context.did.clone(),
        context.handle.clone(),
        String::new(),
    )
    .with_http_client(context.http.clone())
    .with_chat_authority(nest.clone(), authority_state.clone(), credentials.clone());
    let api_client = std::sync::Arc::new(api_client);

    let mls_state_dir = data_dir.join("mls-state");
    std::fs::create_dir_all(&mls_state_dir)?;
    let keychain_path = data_dir.join("keychain.json");
    let keychain = crate::keychain::FileKeychain::new(keychain_path)
        .map_err(|e| anyhow::anyhow!("Failed to open MLS keychain: {e}"))?;
    let epoch_secret_storage = keychain
        .with_epoch_secret_owner(&context.did)
        .map_err(|e| anyhow::anyhow!("Failed to scope MLS epoch-secret storage: {e}"))?;

    let did_sanitized = context.did.replace([':', '.'], "_");
    let mls_db_path = mls_state_dir.join(format!("{}.db", did_sanitized));
    let mls_db_key = crate::get_or_create_mls_db_key(&mls_state_dir, &did_sanitized, "fixture-password")?;
    let mls_context = catbird_mls::MLSContext::new(
        mls_db_path.to_string_lossy().to_string(),
        mls_db_key,
        Box::new(keychain),
    )
    .map_err(|e| anyhow::anyhow!("Failed to create MLS context: {e}"))?;
    mls_context
        .set_epoch_secret_storage(Box::new(epoch_secret_storage))
        .map_err(|e| anyhow::anyhow!("Failed to install MLS epoch-secret storage: {e}"))?;

    preseed_native_authority(&context, &mls_context, &credentials).await?;

    let storage_db_path = data_dir.join("bird.db");
    let storage = std::sync::Arc::new(crate::storage::SqliteStorage::new(storage_db_path, context.did.clone())?);

    let orchestrator = std::sync::Arc::new(catbird_mls::orchestrator::MLSOrchestrator::new(
        mls_context,
        storage.clone(),
        api_client.clone(),
        credentials.clone(),
        catbird_mls::orchestrator::OrchestratorConfig::default(),
    ));
    api_client.set_signer(orchestrator.clone());

    orchestrator
        .initialize(&context.did)
        .await
        .map_err(|e| anyhow::anyhow!("Orchestrator init failed: {e}"))?;

    let snapshot = crate::admit_existing_session(
        &nest,
        &context.session,
        &context.did,
        &context.reserved_device_id,
        1,
        &credentials,
    )
    .await
    .map_err(|e| anyhow::anyhow!("Failed to admit fixture session: {e}"))?;
    authority_state.install(snapshot);
    crate::prepare_admitted_device_runtime(&orchestrator, &credentials, &context.did).await?;

    let llm = crate::bridge_client::BridgeClient::new(&context.config.bridge_url);
    let bird_config = crate::config::BirdConfig {
        handle: context.handle.clone(),
        llm_backend: "bridge".into(),
        llm_base_url: context.config.bridge_url.clone(),
        llm_api_key: String::new(),
        llm_model: "fixture".into(),
        system_prompt: "fixture".into(),
        max_reply_characters: context.config.max_reply_characters,
        receive_chat_requests: context.config.receive_chat_requests,
        accept_chat_requests: context.config.accept_chat_requests,
        reply_to_all_messages: context.config.reply_to_all_messages,
    };
    let bot = std::sync::Arc::new(crate::bot::BirdBot::new(
        context.did.clone(),
        api_client.clone(),
        orchestrator.clone(),
        llm,
        bird_config,
    ));

    Ok(DebugFixtureRuntime {
        context,
        bot,
        orchestrator,
        storage,
        credentials,
        api_client,
        authority_state,
        nest,
    })
}

pub(crate) async fn run(path: &Path) -> Result<()> {
    let context = DebugFixtureContext::load(path)?;
    let runtime = assemble_runtime(context).await?;
    runtime.bot.run().await
}

fn validate_private_file(path: &Path) -> Result<()> {
    let metadata = std::fs::metadata(path).context("stat protected fixture sessions")?;
    ensure!(metadata.is_file(), "protected sessions path is not a file");
    ensure!(
        metadata.mode() & 0o077 == 0,
        "protected fixture sessions are readable outside their owner"
    );
    Ok(())
}

fn exactly_one<'a, T>(mut values: impl Iterator<Item = &'a T>, label: &str) -> Result<&'a T> {
    let value = values.next().with_context(|| format!("missing {label}"))?;
    ensure!(values.next().is_none(), "duplicate {label}");
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    struct TempDir(PathBuf);
    impl TempDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "bird-debug-fixture-{}",
                uuid::Uuid::new_v4()
            ));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn fixture(remote: bool, sessions_mode: u32) -> (TempDir, PathBuf) {
        let dir = TempDir::new();
        let ca = dir.path().join("ca.pem");
        std::fs::write(&ca, b"not-a-certificate").unwrap();
        let sessions = dir.path().join("sessions.json");
        std::fs::write(
            &sessions,
            br#"{"accounts":[{"label":"bob","did":"did:web:bob.fixture","deviceId":"11111111-2222-4333-8444-555555555555","session":"opaque"}]}"#,
        )
        .unwrap();
        std::fs::set_permissions(&sessions, std::fs::Permissions::from_mode(sessions_mode))
            .unwrap();
        let manifest = dir.path().join("manifest.json");
        let address = if remote { "192.0.2.1:443" } else { "127.0.0.1:443" };
        std::fs::write(
            &manifest,
            serde_json::to_vec(&serde_json::json!({
                "fixtureOnly":true,
                "origin":"https://gateway.fixture",
                "corsOrigin":"http://127.0.0.1:5173",
                "caPem":ca,
                "hosts":{"gateway.fixture":address,"bob.fixture":address},
                "accounts":[{"label":"bob","did":"did:web:bob.fixture","deviceId":"11111111-2222-4333-8444-555555555555"}]
            }))
            .unwrap(),
        )
        .unwrap();
        let run = dir.path().join("run.json");
        std::fs::write(
            &run,
            serde_json::to_vec(&serde_json::json!({
                "manifestPath":manifest,
                "sessionsPath":sessions,
                "accountLabel":"bob",
                "dataDir":dir.path().join("state"),
                "bridgeURL":"http://127.0.0.1:8789"
            }))
            .unwrap(),
        )
        .unwrap();
        (dir, run)
    }

    #[test]
    fn fixture_rejects_remote_transport_before_building_client() {
        let (_dir, run) = fixture(true, 0o600);
        assert!(DebugFixtureContext::load(&run)
            .unwrap_err()
            .to_string()
            .contains("loopback"));
    }

    #[test]
    fn fixture_rejects_exposed_sessions() {
        let (_dir, run) = fixture(false, 0o644);
        assert!(DebugFixtureContext::load(&run)
            .unwrap_err()
            .to_string()
            .contains("readable outside"));
    }

    #[test]
    fn fixture_refuses_without_config() {
        std::env::remove_var("BIRD_RUNTIME_FIXTURE_CONFIG");
        assert!(required_config_path()
            .unwrap_err()
            .to_string()
            .contains("production profile fallback is forbidden"));
    }
}
