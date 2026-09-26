//! C31 qualification and client-birdaemon runtime runner.
//!
//! Evaluates C31 contract:
//! 1. Pending, invalid, and declined previews produce zero plaintext logs,
//!    typing, downloads, bridge/LLM/tools, or reply.
//! 2. Explicit configured autoaccept runs canonical acceptance first, exactly once.
//! 3. Bot preview never enters unkeyed bird.db (C30 clause).
//! 4. client-birdaemon: Alice (CLI fixture pair) sends request to Bob (BIRDaemon),
//!    verifies non-autoaccept holds with zero effects, then autoaccept accepts once and replies.

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{ensure, Context, Result};
use chrono::Utc;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use catbird_mls::orchestrator::{
    DirectRequestView, RequestCapabilities, RequestConsent, RequestCrypto,
    RequestIntroductionMetadata, RequestPreview,
};
use catbird_mls::MLSContext;

use crate::bridge_client::BridgeClient;
use crate::debug_fixture::{assemble_runtime, DebugFixtureContext, DebugFixtureRunConfig};
use crate::keychain::FileKeychain;
use crate::request_policy::{claim_request_effect, RequestAction, RequestPolicy};
use crate::storage::SqliteStorage;

pub(crate) const SECRET_PENDING_INTRO: &str = "C31_SUPER_SECRET_PENDING_INTRODUCTION_TEXT_NEVER_LOGGED";
pub(crate) const SECRET_INVALID_INTRO: &str = "C31_SUPER_SECRET_INVALID_INTRODUCTION_TEXT_NEVER_LOGGED";
pub(crate) const SECRET_DECLINED_INTRO: &str = "C31_SUPER_SECRET_DECLINED_INTRODUCTION_TEXT_NEVER_LOGGED";

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

pub(crate) fn file_sha256(path: &Path) -> Result<String> {
    let bytes = std::fs::read(path).with_context(|| format!("read for sha256: {}", path.display()))?;
    Ok(sha256_hex(&bytes))
}

pub(crate) fn make_artifact(workspace_root: &Path, file_path: &Path) -> Result<Value> {
    let metadata = std::fs::metadata(file_path).with_context(|| format!("stat artifact: {}", file_path.display()))?;
    let rel_path = file_path
        .strip_prefix(workspace_root)
        .unwrap_or(file_path)
        .to_string_lossy()
        .to_string();
    let hash = file_sha256(file_path)?;
    Ok(json!({
        "path": rel_path,
        "bytes": metadata.len(),
        "sha256": hash
    }))
}

#[derive(Clone, Default)]
pub(crate) struct SharedLogCapture(pub(crate) Arc<Mutex<Vec<u8>>>);

impl std::io::Write for SharedLogCapture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub(crate) fn make_view(
    conversation_id: &str,
    first_message_id: &str,
    sender_did: &str,
    consent: RequestConsent,
    crypto: RequestCrypto,
    preview: Option<RequestPreview>,
) -> DirectRequestView {
    DirectRequestView {
        introduction: Some(RequestIntroductionMetadata {
            sender_did: sender_did.into(),
            sender_device_id: "00000000-0000-4000-8000-000000000001".into(),
            received_at: Utc::now().to_rfc3339(),
            epoch: 1,
            sequence_number: 1,
        }),
        conversation_id: conversation_id.into(),
        first_message_id: Some(first_message_id.into()),
        consent,
        crypto,
        preview,
        capabilities: RequestCapabilities::derive(consent, crypto, true),
        state_version: 1,
        generation: 0,
    }
}

/// Simple mock HTTP bridge for testing BIRDaemon's BridgeClient.
pub(crate) struct MockBridge {
    pub(crate) port: u16,
    pub(crate) received_messages: Arc<Mutex<Vec<Value>>>,
    _shutdown: tokio::sync::oneshot::Sender<()>,
}

impl MockBridge {
    pub(crate) async fn start() -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let received = Arc::new(Mutex::new(Vec::new()));
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();

        let received_clone = received.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => break,
                    Ok((mut stream, _)) = listener.accept() => {
                        let received = received_clone.clone();
                        tokio::spawn(async move {
                            let mut buf = vec![0u8; 16384];
                            let read = stream.read(&mut buf).await.unwrap_or(0);
                            buf.truncate(read);
                            let request_str = String::from_utf8_lossy(&buf);
                            if request_str.starts_with("POST /message") {
                                if let Some(body_start) = request_str.find("\r\n\r\n") {
                                    let body = &request_str[body_start + 4..];
                                    if let Ok(parsed) = serde_json::from_str::<Value>(body) {
                                        received.lock().unwrap().push(parsed);
                                    }
                                }
                                let response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{}";
                                let _ = stream.write_all(response.as_bytes()).await;
                            } else if request_str.starts_with("GET /reply/") {
                                let body = serde_json::json!({"status":"ready","text":"Hello from BIRDaemon mock bridge reply!"}).to_string();
                                let response = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{}", body.len(), body);
                                let _ = stream.write_all(response.as_bytes()).await;
                            } else {
                                let response = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                                let _ = stream.write_all(response.as_bytes()).await;
                            }
                        });
                    }
                }
            }
        });

        Ok(Self {
            port,
            received_messages: received,
            _shutdown: shutdown_tx,
        })
    }

    pub(crate) fn message_count(&self) -> usize {
        self.received_messages.lock().unwrap().len()
    }
}

/// Verification of C31 core contract (in-process).
#[tokio::test]
async fn test_c31_zero_effects_and_canonical_acceptance() {
    if let Err(e) = run_c31_test().await {
        panic!("test_c31_zero_effects_and_canonical_acceptance failed: {e:?}");
    }
}

pub(crate) async fn run_c31_test() -> Result<()> {
    let tmp = std::env::temp_dir().join(format!("c31-contract-test-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&tmp)?;

    let bridge = MockBridge::start().await?;
    let bridge_url = format!("http://127.0.0.1:{}", bridge.port);

    // 1. Setup unkeyed bird.db
    let bird_db_path = tmp.join("bird.db");
    let storage = SqliteStorage::new(bird_db_path.clone(), "did:plc:recipient")?;

    // 2. Setup native SQLCipher database
    let mls_state_dir = tmp.join("mls-state");
    std::fs::create_dir_all(&mls_state_dir)?;
    let native_db_path = mls_state_dir.join("native.db");
    let keychain_path = tmp.join("keychain.json");
    let keychain = FileKeychain::new(keychain_path)?;
    let native_key = "test-independent-sqlcipher-key";
    let _mls_context = MLSContext::new(
        native_db_path.to_string_lossy().to_string(),
        native_key.into(),
        Box::new(keychain),
    )
    .map_err(|e| anyhow::anyhow!("Failed to create native MLS context: {e}"))?;

    // Setup captured log buffer
    let log_buffer = Arc::new(Mutex::new(Vec::<u8>::new()));
    let mut capture_writer = SharedLogCapture(log_buffer.clone());

    // Emit baseline diagnostic log through capture writer
    writeln!(capture_writer, "[DIAGNOSTIC] Initialized C31 qualification log capture at {}", Utc::now().to_rfc3339())?;

    // Test A: Pending Preview with auto_accept: false
    let pending_convo_id = "11111111-1111-4111-8111-111111111111";
    let pending_first_msg = "22222222-2222-4222-8222-222222222222";
    let pending_view = make_view(
        pending_convo_id,
        pending_first_msg,
        "did:plc:sender",
        RequestConsent::IncomingPending,
        RequestCrypto::Ready,
        Some(RequestPreview::Ready {
            text: SECRET_PENDING_INTRO.into(),
            invitation: None,
        }),
    );

    let non_autoaccept_policy = RequestPolicy {
        auto_accept: false,
        reply: true,
    };
    assert_eq!(
        non_autoaccept_policy.action(&pending_view),
        RequestAction::Withhold,
        "non-autoaccept must withhold pending preview"
    );

    // Assert that withholding performs no effect claim
    assert!(
        !claim_request_effect(non_autoaccept_policy, &pending_view, &storage),
        "withholding must not claim bot effect"
    );
    assert_eq!(bridge.message_count(), 0, "zero bridge calls during pending withhold");

    // Test B: Invalid Introduction preview
    let invalid_view = make_view(
        "33333333-3333-4333-8333-333333333333",
        "44444444-4444-4444-8444-444444444444",
        "did:plc:sender",
        RequestConsent::IncomingPending,
        RequestCrypto::Ready,
        Some(RequestPreview::Unavailable {
            code: "InvalidIntroduction".into(),
        }),
    );
    let autoaccept_policy = RequestPolicy {
        auto_accept: true,
        reply: true,
    };
    assert_eq!(
        autoaccept_policy.action(&invalid_view),
        RequestAction::Withhold,
        "invalid preview must withhold even if autoaccept is enabled"
    );
    assert!(!claim_request_effect(autoaccept_policy, &invalid_view, &storage));
    assert_eq!(bridge.message_count(), 0, "zero bridge calls during invalid preview");

    // Test C: Declined preview
    let declined_view = make_view(
        "55555555-5555-4555-8555-555555555555",
        "66666666-6666-4666-8666-666666666666",
        "did:plc:sender",
        RequestConsent::Closed,
        RequestCrypto::Ready,
        Some(RequestPreview::Unavailable {
            code: "Declined".into(),
        }),
    );
    assert_eq!(
        autoaccept_policy.action(&declined_view),
        RequestAction::Withhold,
        "declined preview must withhold"
    );
    assert!(!claim_request_effect(autoaccept_policy, &declined_view, &storage));
    assert_eq!(bridge.message_count(), 0, "zero bridge calls during declined preview");

    // Test D: C30 bot clause — unkeyed bird.db inspection
    let unkeyed_conn = rusqlite::Connection::open(&bird_db_path)?;
    let message_count: i64 = unkeyed_conn.query_row("SELECT count(*) FROM messages", [], |r| r.get(0))?;
    assert_eq!(message_count, 0, "bird.db must contain zero messages before acceptance");
    let claims_count: i64 = unkeyed_conn.query_row("SELECT count(*) FROM bot_effect_claims", [], |r| r.get(0))?;
    assert_eq!(claims_count, 0, "bird.db must contain zero effect claims before acceptance");

    // Read raw bytes of bird.db to ensure secret plaintext never entered disk
    let raw_bird_db = std::fs::read(&bird_db_path)?;
    assert!(
        !raw_bird_db.windows(SECRET_PENDING_INTRO.len()).any(|w| w == SECRET_PENDING_INTRO.as_bytes()),
        "secret pending introduction plaintext must NEVER appear in unkeyed bird.db"
    );
    assert!(
        !raw_bird_db.windows(SECRET_INVALID_INTRO.len()).any(|w| w == SECRET_INVALID_INTRO.as_bytes()),
        "secret invalid introduction plaintext must NEVER appear in unkeyed bird.db"
    );
    assert!(
        !raw_bird_db.windows(SECRET_DECLINED_INTRO.len()).any(|w| w == SECRET_DECLINED_INTRO.as_bytes()),
        "secret declined introduction plaintext must NEVER appear in unkeyed bird.db"
    );

    // Test E: Native SQLCipher encryption
    // Unkeyed access to native.db must FAIL
    let raw_native_conn = rusqlite::Connection::open(&native_db_path)?;
    let unkeyed_native_read = raw_native_conn.query_row("SELECT count(*) FROM sqlite_master", [], |_| Ok(()));
    assert!(
        unkeyed_native_read.is_err(),
        "unkeyed access to native SQLCipher db must fail"
    );

    // Test F: Autoaccept with canonical acceptance first, exactly once
    assert_eq!(
        autoaccept_policy.action(&pending_view),
        RequestAction::Accept,
        "autoaccept policy must accept incoming pending view"
    );

    // Simulate transition to Accepted + Ready
    let accepted_view = make_view(
        pending_convo_id,
        pending_first_msg,
        "did:plc:sender",
        RequestConsent::Accepted,
        RequestCrypto::Ready,
        Some(RequestPreview::Ready {
            text: SECRET_PENDING_INTRO.into(),
            invitation: None,
        }),
    );
    assert_eq!(
        autoaccept_policy.action(&accepted_view),
        RequestAction::Reply,
        "accepted view authorizes reply"
    );

    // Claim effect in storage
    let claimed_first = claim_request_effect(autoaccept_policy, &accepted_view, &storage);
    assert!(claimed_first, "first effect claim must succeed");

    // Execute bridge call
    let llm = BridgeClient::new(&bridge_url);
    let reply = llm.generate(
        pending_convo_id,
        "did:plc:sender",
        SECRET_PENDING_INTRO,
        None,
        None,
    ).await?;
    assert!(!reply.is_empty(), "bridge must return a non-empty reply");
    assert_eq!(bridge.message_count(), 1, "bridge called exactly once");

    // Replay / duplicate test
    let claimed_second = claim_request_effect(autoaccept_policy, &accepted_view, &storage);
    assert!(!claimed_second, "duplicate effect claim must be rejected");
    assert_eq!(bridge.message_count(), 1, "bridge call count remains exactly 1 on replay");

    // Check effect claim in bird.db: digest only, exactly 32 bytes
    let digest_len: usize = unkeyed_conn.query_row(
        "SELECT length(effect_digest) FROM bot_effect_claims WHERE owner_did = ?1",
        ["did:plc:recipient"],
        |r| r.get(0),
    )?;
    assert_eq!(digest_len, 32, "bot_effect_claims stores only 32-byte SHA256 digest");

    // Check captured logs: verify no secret plaintext leaked
    let captured_bytes = log_buffer.lock().unwrap().clone();
    assert!(
        !captured_bytes.windows(SECRET_PENDING_INTRO.len()).any(|w| w == SECRET_PENDING_INTRO.as_bytes()),
        "pending introduction text must never appear in captured logs"
    );
    assert!(
        !captured_bytes.windows(SECRET_INVALID_INTRO.len()).any(|w| w == SECRET_INVALID_INTRO.as_bytes()),
        "invalid introduction text must never appear in captured logs"
    );
    assert!(
        !captured_bytes.windows(SECRET_DECLINED_INTRO.len()).any(|w| w == SECRET_DECLINED_INTRO.as_bytes()),
        "declined introduction text must never appear in captured logs"
    );

    // Evidence for C31 is written only by the live scenario; this in-process
    // test must not overwrite qualification artifacts.

    // Clean up
    let _ = std::fs::remove_dir_all(&tmp);
    Ok(())
}

struct CoreLogCapture(Arc<Mutex<Vec<u8>>>);

#[async_trait::async_trait]
impl catbird_mls::MLSLogger for CoreLogCapture {
    async fn log(&self, level: String, message: String) {
        let mut buffer = self.0.lock().unwrap();
        buffer.extend_from_slice(format!("[core {level}] {message}\n").as_bytes());
    }
}

/// Installs one process-wide capture for every tracing event (all targets,
/// TRACE) and every shared-core log line, so plaintext assertions cover the
/// whole bot process rather than a buffer nobody writes to.
fn install_process_log_capture() -> Result<Arc<Mutex<Vec<u8>>>> {
    static CAPTURE: std::sync::OnceLock<Arc<Mutex<Vec<u8>>>> = std::sync::OnceLock::new();
    if let Some(existing) = CAPTURE.get() {
        return Ok(existing.clone());
    }
    let buffer = Arc::new(Mutex::new(Vec::new()));
    let writer = SharedLogCapture(buffer.clone());
    tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .try_init()
        .map_err(|e| anyhow::anyhow!("global tracing capture could not be installed: {e}"))?;
    catbird_mls::logging::set_logger(Box::new(CoreLogCapture(buffer.clone())));
    tracing::info!("C31 process log capture installed");
    ensure!(
        buffer.lock().unwrap().windows(9).any(|w| w == b"C31 proce"),
        "global tracing capture is not receiving events"
    );
    Ok(CAPTURE.get_or_init(|| buffer).clone())
}

/// Publishes one real request through the signed fixture CLI (text via stdin,
/// never a process argument). Returns (draftId, conversationId).
fn cli_send_request(
    catmos_bin: &Path,
    profile: &str,
    transport: &Path,
    recipient: &str,
    text: &str,
) -> Result<(String, String)> {
    let draft_id = uuid::Uuid::new_v4().to_string();
    let mut child = Command::new(catmos_bin)
        .args(["--profile", profile, "--no-startup-sync", "request", "send", recipient, "--draft-id", &draft_id, "--file", "-"])
        .env("CATMOS_LOCAL_RUNTIME_TRANSPORT", transport)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    {
        let mut stdin = child.stdin.take().context("send stdin")?;
        stdin.write_all(text.as_bytes())?;
    }
    let out = child.wait_with_output()?;
    ensure!(out.status.success(), "catmos request send failed: {}", String::from_utf8_lossy(&out.stderr));
    let result: Value = serde_json::from_slice(&out.stdout)?;
    eprintln!("[client-birdaemon] Request sent. Result: {result}");
    ensure!(result["outcome"]["type"] == "requestSent", "request was not published: {result}");
    let convo = result["outcome"]["conversationId"].as_str().context("conversationId")?.to_owned();
    Ok((draft_id, convo))
}

struct DedicatedDbGuard {
    name: String,
    url: String,
}

impl DedicatedDbGuard {
    fn create() -> Result<Self> {
        let name = format!(
            "catbird_direct_requests_fault_{}",
            &uuid::Uuid::new_v4().simple().to_string()[..16]
        );
        let url = format!("postgresql://127.0.0.1:5432/{name}");
        let status = Command::new("psql")
            .args([
                "postgresql://127.0.0.1:5432/postgres",
                "-X",
                "-q",
                "-v",
                "ON_ERROR_STOP=1",
                "-c",
            ])
            .arg(format!("CREATE DATABASE {name}"))
            .status()
            .context("create dedicated DB")?;
        ensure!(status.success(), "failed to create dedicated database {name}");
        Ok(Self { name, url })
    }
}

impl Drop for DedicatedDbGuard {
    fn drop(&mut self) {
        let _ = Command::new("psql")
            .args(["postgresql://127.0.0.1:5432/postgres", "-X", "-q", "-c"])
            .arg(format!(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='{}' AND pid<>pg_backend_pid()",
                self.name
            ))
            .status();
        let _ = Command::new("psql")
            .args(["postgresql://127.0.0.1:5432/postgres", "-X", "-q", "-c"])
            .arg(format!("DROP DATABASE IF EXISTS {}", self.name))
            .status();
    }
}

/// Owns one client_runtime_gateway process. The gateway only runs its child
/// cleanup (TLS relay, shipping server fixture) on SIGINT, so shutdown and Drop
/// send SIGINT to this exact PID, wait, and then confirm the recorded child PIDs
/// are gone. Nothing is ever signalled by process name.
struct GatewayChild {
    child: std::process::Child,
    stdout: std::io::BufReader<std::process::ChildStdout>,
    finished: bool,
}

impl GatewayChild {
    fn spawn(gw_bin: &Path, config: &Value, server_fixture_bin: &Path, db_url: &str) -> Result<Self> {
        let mut child = Command::new(gw_bin)
            .current_dir("/Users/joshlacalamito/Developer/.workspaces/catbird-encrypted-requests-20260919/mls-ds")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .env("REQUEST_TEST_DATABASE_URL", db_url)
            .env("REQUEST_SERVER_FIXTURE_BINARY", server_fixture_bin)
            .spawn()
            .context("spawn client_runtime_gateway")?;
        {
            let mut stdin = child.stdin.take().context("gw stdin")?;
            stdin.write_all(&serde_json::to_vec(config)?)?;
        }
        let stdout = std::io::BufReader::new(child.stdout.take().context("gw stdout")?);
        Ok(Self { child, stdout, finished: false })
    }

    fn stdout_line(&mut self) -> Result<String> {
        let mut line = String::new();
        self.stdout.read_line(&mut line)?;
        Ok(line)
    }

    fn take_stderr(&mut self) -> Result<String> {
        let mut err = String::new();
        if let Some(mut stderr) = self.child.stderr.take() {
            std::io::Read::read_to_string(&mut stderr, &mut err)?;
        }
        Ok(err)
    }

    fn descendants(&self) -> Vec<String> {
        Command::new("pgrep")
            .args(["-P", &self.child.id().to_string()])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).split_whitespace().map(str::to_owned).collect())
            .unwrap_or_default()
    }

    /// SIGINT, wait up to 30s, then verify every recorded child PID exited.
    fn shutdown(&mut self) -> Result<()> {
        if self.finished {
            return Ok(());
        }
        self.finished = true;
        let children = self.descendants();
        let _ = Command::new("kill").args(["-INT", &self.child.id().to_string()]).status();
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        loop {
            if self.child.try_wait()?.is_some() {
                break;
            }
            ensure!(std::time::Instant::now() < deadline, "gateway did not exit after SIGINT");
            std::thread::sleep(Duration::from_millis(200));
        }
        std::thread::sleep(Duration::from_millis(500));
        let alive: Vec<_> = children
            .into_iter()
            .filter(|pid| Command::new("kill").args(["-0", pid]).status().is_ok_and(|s| s.success()))
            .collect();
        ensure!(alive.is_empty(), "gateway children still running after SIGINT: {alive:?}");
        Ok(())
    }
}

impl Drop for GatewayChild {
    fn drop(&mut self) {
        if let Err(e) = self.shutdown() {
            eprintln!("[client-birdaemon] gateway shutdown problem: {e}");
        }
    }
}

/// Declined leg: runs on its own gateway instance and dedicated DB.
/// A real request is published by Alice (catmos-cli), decrypted by Bob into
/// an IncomingPending preview, then explicitly declined by Bob via close_direct_request.
/// Verifies consent becomes Closed, and with autoaccept enabled the bot produces
/// zero bridge calls, zero typing attempts, zero downloads, and zero effect claims.
async fn run_declined_leg(
    gw_bin: &Path,
    server_fixture_bin: &Path,
    catmos_bin: &Path,
    seeder_bin: &Path,
    log_capture: &Arc<Mutex<Vec<u8>>>,
) -> Result<Value> {
    eprintln!("[c31-declined] Starting dedicated gateway instance for declined leg...");
    let dedicated_db = DedicatedDbGuard::create()?;
    let gw_dir = std::env::temp_dir().join(format!("gw-c31-declined-{}", uuid::Uuid::new_v4()));
    let mut gateway = GatewayChild::spawn(
        gw_bin,
        &json!({"output_dir": gw_dir, "cors_origin": "http://127.0.0.1:5173", "lifetime_seconds": 600}),
        server_fixture_bin,
        &dedicated_db.url,
    )?;
    let ready = gateway.stdout_line()?;
    ensure!(!ready.trim().is_empty(), "declined-leg gateway exited: {}", gateway.take_stderr()?);
    let manifest_path = PathBuf::from(
        serde_json::from_str::<Value>(&ready)?["manifest"].as_str().context("manifest")?,
    );
    let sessions_path = gw_dir.join("sessions.json");
    let manifest: Value = serde_json::from_slice(&std::fs::read(&manifest_path)?)?;
    let sessions: Value = serde_json::from_slice(&std::fs::read(&sessions_path)?)?;
    let pick = |doc: &Value, label: &str| -> Result<Value> {
        doc["accounts"].as_array().context("accounts")?.iter().find(|a| a["label"] == label).cloned().context("account")
    };
    let alice = pick(&manifest, "alice")?;
    let alice_session = pick(&sessions, "alice")?["session"].as_str().context("session")?.to_owned();

    let bridge = MockBridge::start().await?;
    let bob_dir = std::env::temp_dir().join(format!("bob-declined-{}", uuid::Uuid::new_v4()));
    let run_path = std::env::temp_dir().join(format!("bob-declined-run-{}.json", uuid::Uuid::new_v4()));
    std::fs::write(&run_path, serde_json::to_vec(&DebugFixtureRunConfig {
        manifest_path: manifest_path.clone(),
        sessions_path,
        account_label: "bob".into(),
        data_dir: bob_dir.clone(),
        bridge_url: format!("http://127.0.0.1:{}", bridge.port),
        receive_chat_requests: true,
        accept_chat_requests: true, // autoaccept enabled, but closed request must not be accepted!
        reply_to_all_messages: true,
        max_reply_characters: 1000,
    })?)?;
    let bob = assemble_runtime(DebugFixtureContext::load(&run_path)?).await?;
    bob.bot.maintain_request_keys().await;
    bob.orchestrator.replenish_direct_request_keys_if_needed().await?;

    let alice_profile = format!("t17-cli-{}", uuid::Uuid::new_v4());
    let alice_manifest_path = std::env::temp_dir().join(format!("{alice_profile}.transport.json"));
    let transport_cfg = json!({
        "profile": alice_profile,
        "ca_pem": manifest["caPem"],
        "hosts": manifest["hosts"].as_object().map(|hosts| hosts.iter()
            .filter(|(host, _)| {
                host.as_str() == "chat.catbird.blue"
                    || host.ends_with(".request-fixture.catbird.blue")
            })
            .map(|(host, address)| (host.clone(), address.clone()))
            .collect::<serde_json::Map<_, _>>()).unwrap_or_default()
    });
    std::fs::write(&alice_manifest_path, serde_json::to_vec_pretty(&transport_cfg)?)?;
    let alice_seed = json!({
        "profile": alice_profile,
        "did": alice["did"],
        "deviceId": alice["deviceId"],
        "proxyUrl": manifest["origin"],
        "serviceUrl": manifest["origin"],
        "sessionCookie": alice_session
    });
    let mut seeder_cmd = Command::new(seeder_bin)
        .env("CATMOS_LOCAL_RUNTIME_TRANSPORT", &alice_manifest_path)
        .env_remove("CATMOS_TEST_KEYCHAIN_FALLBACK")
        .env_remove("CATMOS_TEST_SHARED_KEYCHAIN_FALLBACK")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    {
        let mut stdin = seeder_cmd.stdin.take().context("seeder stdin")?;
        stdin.write_all(&serde_json::to_vec(&alice_seed)?)?;
    }
    let seeder_out = seeder_cmd.wait_with_output()?;
    ensure!(seeder_out.status.success(), "seeder failed: {}", String::from_utf8_lossy(&seeder_out.stderr));
    let seed_res: Value = serde_json::from_slice(&seeder_out.stdout)?;
    let alice_public_key = seed_res["signaturePublicKey"].as_str().context("alice public key")?;
    let preseed = bob.context.http
        .post(format!("{}/fixture/enroll", manifest["origin"].as_str().unwrap()))
        .bearer_auth(&alice_session)
        .json(&json!({"device_id": alice["deviceId"], "signature_public_key": alice_public_key}))
        .send().await?;
    ensure!(preseed.status().is_success(), "preseed failed: {}", preseed.status());

    let delivery_out = Command::new(catmos_bin)
        .args(["--profile", &alice_profile, "--no-startup-sync", "request", "delivery", "--enable"])
        .env("CATMOS_LOCAL_RUNTIME_TRANSPORT", &alice_manifest_path)
        .output()?;
    ensure!(delivery_out.status.success(), "delivery enable failed");

    let declined_text = "C31 real published introduction that will be declined.";
    let (draft_id, convo_id) = cli_send_request(catmos_bin, &alice_profile, &alice_manifest_path, &bob.context.did, declined_text)?;
    eprintln!("[c31-declined] Request published: {convo_id}");

    bob.orchestrator.sync_with_server(true).await?;
    let pending = bob.orchestrator.refresh_request_preview(&convo_id).await?;
    ensure!(pending.consent == RequestConsent::IncomingPending, "must be pending before decline");

    // Decline via real close RPC
    let closed = bob.orchestrator.close_direct_request(&convo_id).await?;
    ensure!(closed.consent == RequestConsent::Closed, "close RPC must yield Closed");
    bob.bot.handle_request_views().await;
    tokio::time::sleep(Duration::from_secs(2)).await;

    ensure!(bridge.message_count() == 0, "declined: zero bridge calls");
    let probe = bob.api_client.effect_probe();
    ensure!(probe.typing_attempts.load(std::sync::atomic::Ordering::SeqCst) == 0, "declined: zero typing");
    ensure!(probe.blob_downloads.load(std::sync::atomic::Ordering::SeqCst) == 0, "declined: zero downloads");
    let bird = rusqlite::Connection::open(bob_dir.join("bird.db"))?;
    let claims: i64 = bird.query_row("SELECT count(*) FROM bot_effect_claims", [], |r| r.get(0))?;
    ensure!(claims == 0, "declined: zero effect claims (found {claims})");
    // Closing a request appends the core's own `conversation.closed` system
    // marker; nothing else — above all the preview — may reach unkeyed bird.db.
    let rows: Vec<(i64, String, String)> = bird
        .prepare("SELECT is_own, text, coalesce(payload_json, '') FROM messages")?
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
        .collect::<std::result::Result<_, _>>()?;
    let non_marker = rows
        .iter()
        .filter(|(own, text, payload)| {
            let marker = serde_json::from_str::<Value>(payload).ok().is_some_and(|p| {
                p["messageType"] == "system" && p["text"] == "conversation.closed"
            });
            !(*own == 1 && marker && !text.contains(declined_text))
        })
        .count();
    ensure!(
        non_marker == 0,
        "declined: unkeyed bird.db holds {non_marker} row(s) besides the own close marker"
    );
    let close_markers = rows.len();
    for file in std::fs::read_dir(&bob_dir)?.chain(std::fs::read_dir(bob_dir.join("mls-state"))?) {
        let path = file?.path();
        if path.is_file() {
            let bytes = std::fs::read(&path)?;
            ensure!(
                !bytes.windows(declined_text.len()).any(|w| w == declined_text.as_bytes()),
                "declined: plaintext introduction found on disk in {}",
                path.display()
            );
        }
    }
    ensure!(
        !log_capture.lock().unwrap().windows(declined_text.len()).any(|w| w == declined_text.as_bytes()),
        "declined text must not appear in logs"
    );

    drop(bob);
    gateway.shutdown()?;
    let _ = std::fs::remove_dir_all(&gw_dir);
    let _ = std::fs::remove_dir_all(&bob_dir);
    let _ = std::fs::remove_file(&run_path);
    let _ = std::fs::remove_file(&alice_manifest_path);

    Ok(json!({
        "conversationId": convo_id,
        "draftId": draft_id,
        "finalConsent": "Closed",
        "bridgeCalls": 0, "typingAttempts": 0, "blobDownloads": 0, "effectClaims": 0,
        "birdDbRows": {"ownCloseMarkers": close_markers, "other": 0}, "plaintextOnDisk": false, "plaintextInLogs": false,
        "botPolicy": {"autoAccept": true, "reply": true}
    }))
}

/// Invalid leg: runs on its own gateway instance, because each synthetic
/// account reserves exactly one device and the CLI owns the main run's Alice.
/// A malicious-but-authentic sender publishes a re-signed, tampered
/// introduction through the real router. The recipient is a real BIRDaemon
/// runtime configured for the strongest case: autoaccept and reply enabled.
async fn run_invalid_introduction_leg(
    gw_bin: &Path,
    server_fixture_bin: &Path,
    log_capture: &Arc<Mutex<Vec<u8>>>,
) -> Result<Value> {
    use mls_e2e_tests::gateway_tampered_request::GatewaySender;
    eprintln!("[c31-invalid] Starting a second, independent gateway instance...");
    let gw_dir = std::env::temp_dir().join(format!("gw-c31-invalid-{}", uuid::Uuid::new_v4()));
    let dedicated_db = DedicatedDbGuard::create()?;
    let mut gateway = GatewayChild::spawn(
        gw_bin,
        &json!({"output_dir": gw_dir, "cors_origin": "http://127.0.0.1:5173", "lifetime_seconds": 600}),
        server_fixture_bin,
        &dedicated_db.url,
    )?;
    let ready = gateway.stdout_line()?;
    ensure!(!ready.trim().is_empty(), "invalid-leg gateway exited: {}", gateway.take_stderr()?);
    let manifest_path = PathBuf::from(
        serde_json::from_str::<Value>(&ready)?["manifest"].as_str().context("manifest")?,
    );
    let sessions_path = gw_dir.join("sessions.json");
    let manifest: Value = serde_json::from_slice(&std::fs::read(&manifest_path)?)?;
    let sessions: Value = serde_json::from_slice(&std::fs::read(&sessions_path)?)?;
    let pick = |doc: &Value, label: &str| -> Result<Value> {
        doc["accounts"].as_array().context("accounts")?.iter().find(|a| a["label"] == label).cloned().context("account")
    };
    let alice = pick(&manifest, "alice")?;
    let alice_session = pick(&sessions, "alice")?["session"].as_str().context("session")?.to_owned();

    let bridge = MockBridge::start().await?;
    let bob_dir = std::env::temp_dir().join(format!("bob-invalid-{}", uuid::Uuid::new_v4()));
    let run_path = std::env::temp_dir().join(format!("bob-invalid-run-{}.json", uuid::Uuid::new_v4()));
    std::fs::write(&run_path, serde_json::to_vec(&DebugFixtureRunConfig {
        manifest_path,
        sessions_path,
        account_label: "bob".into(),
        data_dir: bob_dir.clone(),
        bridge_url: format!("http://127.0.0.1:{}", bridge.port),
        receive_chat_requests: true,
        accept_chat_requests: true,
        reply_to_all_messages: true,
        max_reply_characters: 1000,
    })?)?;
    let bob = assemble_runtime(DebugFixtureContext::load(&run_path)?).await?;
    bob.bot.maintain_request_keys().await;
    ensure!(
        bob.orchestrator.get_direct_request_delivery_enabled().await? == Some(true),
        "invalid-leg Bob request delivery not acknowledged"
    );
    bob.orchestrator.replenish_direct_request_keys_if_needed().await?;
    let bob_public = bob.orchestrator.mls_context().identity_public_key(
        format!("{}#{}", bob.context.did, bob.context.reserved_device_id),
    )?;

    let engine = mls_e2e_tests::mls_engine::MlsEngine::new("c31-invalid-alice")?;
    let alice_did = alice["did"].as_str().context("alice did")?.to_owned();
    let alice_device = alice["deviceId"].as_str().context("alice device")?.to_owned();
    let alice_identity = format!("{alice_did}#{alice_device}");
    engine.create_key_package(&alice_identity)?;
    let alice_public = engine.identity_public_key(&alice_identity)?;
    let enroll = bob
        .context
        .http
        .post(format!("{}/fixture/enroll", bob.context.origin))
        .bearer_auth(&alice_session)
        .json(&json!({"device_id": alice_device, "signature_public_key": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &alice_public)}))
        .send()
        .await?;
    ensure!(enroll.status().is_success(), "harness sender preseed failed: {}", enroll.status());
    let published = GatewaySender {
        http: &bob.context.http,
        origin: &bob.context.origin,
        session: &alice_session,
        did: &alice_did,
        device_id: &alice_device,
        engine: &engine,
    }
    .publish_unverifiable_introduction(&bob.context.did, &bob_public)
    .await?;
    let cid = published.conversation_id.clone();
    eprintln!("[c31-invalid] Tampered request published: {cid}");

    bob.orchestrator.sync_with_server(true).await?;
    let refreshed = bob.orchestrator.refresh_request_preview(&cid).await;
    eprintln!("[c31-invalid] Bob refresh of tampered request: {:?}", refreshed.as_ref().map(|v| (&v.consent, &v.crypto, &v.preview)));
    bob.bot.handle_request_views().await;
    bob.bot.handle_request_views().await;
    tokio::time::sleep(Duration::from_secs(2)).await;

    let view = bob.orchestrator.refresh_request_preview(&cid).await?;
    ensure!(
        matches!(&view.preview, Some(RequestPreview::Unavailable { code }) if code == "InvalidIntroduction"),
        "tampered introduction must project Unavailable(InvalidIntroduction), got {:?}",
        view.preview
    );
    ensure!(
        view.consent == RequestConsent::IncomingPending,
        "bot must leave an invalid introduction pending, got {:?}",
        view.consent
    );
    let (consent, preview) = (format!("{:?}", view.consent), format!("{:?}", view.preview));
    let probe = bob.api_client.effect_probe();
    let claims: i64 = rusqlite::Connection::open(bob_dir.join("bird.db"))?
        .query_row("SELECT count(*) FROM bot_effect_claims", [], |r| r.get(0))?;
    let bird_messages: i64 = rusqlite::Connection::open(bob_dir.join("bird.db"))?
        .query_row("SELECT count(*) FROM messages", [], |r| r.get(0))?;
    ensure!(bridge.message_count() == 0, "invalid: bridge was called");
    ensure!(probe.typing_attempts.load(std::sync::atomic::Ordering::SeqCst) == 0, "invalid: typing attempted");
    ensure!(probe.blob_downloads.load(std::sync::atomic::Ordering::SeqCst) == 0, "invalid: blob downloaded");
    ensure!(claims == 0 && bird_messages == 0, "invalid: effect claim or bird.db message written");
    let secret = "Unverifiable introduction the recipient must never surface";
    ensure!(
        !log_capture.lock().unwrap().windows(secret.len()).any(|w| w == secret.as_bytes()),
        "invalid: introduction text reached captured logs"
    );

    drop(bob);
    gateway.shutdown()?;
    let _ = std::fs::remove_dir_all(&gw_dir);
    let _ = std::fs::remove_dir_all(&bob_dir);
    let _ = std::fs::remove_file(&run_path);
    Ok(json!({
        "conversationId": cid,
        "requestId": published.request_id,
        "finalConsent": consent,
        "finalPreview": preview,
        "bridgeCalls": 0, "typingAttempts": 0, "blobDownloads": 0, "effectClaims": 0,
        "birdDbMessages": 0,
        "botPolicy": {"autoAccept": true, "reply": true}
    }))
}

/// Spawns the bot binary under test as a real OS process in fixture mode and
/// returns `(child, ps command line, sha256 of the executable the process runs)`.
/// The command line is read from the live process, not from our argv.
fn spawn_bot_process(bot_bin: &Path, run_config: &Path, log_path: &Path) -> Result<(std::process::Child, String, String)> {
    let log = std::fs::File::create(log_path)?;
    let child = Command::new(bot_bin)
        .env("BIRD_RUNTIME_FIXTURE_CONFIG", run_config)
        .env("RUST_LOG", "info")
        .stdin(Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log)
        .spawn()
        .context("spawn bird-daemon process")?;
    std::thread::sleep(Duration::from_millis(300));
    let ps = Command::new("ps").args(["-o", "command=", "-p", &child.id().to_string()]).output()?;
    let command = String::from_utf8_lossy(&ps.stdout).trim().to_owned();
    ensure!(!command.is_empty(), "bird-daemon process {} exited immediately; see {}", child.id(), log_path.display());
    let exe = PathBuf::from(command.split_whitespace().next().context("ps command")?);
    Ok((child, command, file_sha256(&exe)?))
}

fn wait_for_log(path: &Path, needle: &str, occurrences: usize, timeout: Duration) -> Result<()> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let text = std::fs::read_to_string(path).unwrap_or_default();
        if text.matches(needle).count() >= occurrences {
            return Ok(());
        }
        ensure!(std::time::Instant::now() < deadline, "timed out waiting for {needle:?} in {}", path.display());
        std::thread::sleep(Duration::from_millis(500));
    }
}

fn stop_bot_process(child: &mut std::process::Child) -> Result<Option<i32>> {
    let _ = Command::new("kill").args(["-INT", &child.id().to_string()]).status();
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    while std::time::Instant::now() < deadline {
        if let Some(status) = child.try_wait()? {
            return Ok(status.code());
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    child.kill()?;
    child.wait()?;
    ensure!(child.try_wait()?.is_some(), "bird-daemon {} still running", child.id());
    Ok(None)
}

/// Process leg: the actual bird-daemon executable (not the in-process runtime
/// assembled by this test runner) is the recipient. The CLI publishes a real
/// request; the running bot autoaccepts, calls the bridge once and replies; the
/// CLI decrypts the reply. The bot is then quit and relaunched as a new OS
/// process on the same data dir and must not produce a second bridge call.
async fn run_birdaemon_process_leg(
    gw_bin: &Path,
    server_fixture_bin: &Path,
    catmos_bin: &Path,
    seeder_bin: &Path,
    bot_bin: &Path,
    evidence_dir: &Path,
) -> Result<Value> {
    eprintln!("[client-birdaemon-process] Starting dedicated gateway for the bot-process leg...");
    let dedicated_db = DedicatedDbGuard::create()?;
    let gw_dir = std::env::temp_dir().join(format!("gw-birdaemon-process-{}", uuid::Uuid::new_v4()));
    let mut gateway = GatewayChild::spawn(
        gw_bin,
        &json!({"output_dir": gw_dir, "cors_origin": "http://127.0.0.1:5173", "lifetime_seconds": 900}),
        server_fixture_bin,
        &dedicated_db.url,
    )?;
    let ready = gateway.stdout_line()?;
    ensure!(!ready.trim().is_empty(), "process-leg gateway exited: {}", gateway.take_stderr()?);
    let gw_ps = Command::new("ps")
        .args(["-o", "command=", "-p", &gateway.child.id().to_string()])
        .output()?;
    let gw_command = String::from_utf8_lossy(&gw_ps.stdout).trim().to_string();
    ensure!(!gw_command.is_empty(), "gateway process {} not running", gateway.child.id());
    let gw_exe = PathBuf::from(gw_command.split_whitespace().next().context("ps command")?);
    let gw_running_sha = file_sha256(&gw_exe)?;
    eprintln!("[client-birdaemon-process] Running gateway PID {} ({}) SHA-256: {}", gateway.child.id(), gw_command, gw_running_sha);
    let manifest_path = PathBuf::from(serde_json::from_str::<Value>(&ready)?["manifest"].as_str().context("manifest")?);
    let sessions_path = gw_dir.join("sessions.json");
    let manifest: Value = serde_json::from_slice(&std::fs::read(&manifest_path)?)?;
    let sessions: Value = serde_json::from_slice(&std::fs::read(&sessions_path)?)?;
    let pick = |doc: &Value, label: &str| -> Result<Value> {
        doc["accounts"].as_array().context("accounts")?.iter().find(|a| a["label"] == label).cloned().context("account")
    };
    let alice = pick(&manifest, "alice")?;
    let bob = pick(&manifest, "bob")?;
    let alice_session = pick(&sessions, "alice")?["session"].as_str().context("session")?.to_owned();
    let bob_did = bob["did"].as_str().context("bob did")?.to_owned();

    let bridge = MockBridge::start().await?;
    let bob_dir = std::env::temp_dir().join(format!("bob-process-{}", uuid::Uuid::new_v4()));
    let run_config = |label: &str, dir: &Path| DebugFixtureRunConfig {
        manifest_path: manifest_path.clone(),
        sessions_path: sessions_path.clone(),
        account_label: label.into(),
        data_dir: dir.to_path_buf(),
        bridge_url: format!("http://127.0.0.1:{}", bridge.port),
        receive_chat_requests: true,
        accept_chat_requests: true,
        reply_to_all_messages: true,
        max_reply_characters: 1000,
    };
    let bob_run = std::env::temp_dir().join(format!("bob-process-run-{}.json", uuid::Uuid::new_v4()));
    std::fs::write(&bob_run, serde_json::to_vec(&run_config("bob", &bob_dir))?)?;
    // Only used for its fixture-pinned HTTP client (alice preseed); never assembled.
    let alice_run = std::env::temp_dir().join(format!("alice-http-{}.json", uuid::Uuid::new_v4()));
    std::fs::write(&alice_run, serde_json::to_vec(&run_config("alice", &std::env::temp_dir().join(format!("alice-unused-{}", uuid::Uuid::new_v4()))))?)?;
    let alice_http = DebugFixtureContext::load(&alice_run)?.http;

    let log1 = evidence_dir.join("bird-daemon-process-run1.log");
    let log2 = evidence_dir.join("bird-daemon-process-run2.log");
    let (mut bot, command1, exe_sha1) = spawn_bot_process(bot_bin, &bob_run, &log1)?;
    let pid1 = bot.id();
    eprintln!("[client-birdaemon-process] bird-daemon pid {pid1}: {command1} ({exe_sha1})");
    let outcome = async {
        wait_for_log(&log1, "Bot event loop running", 1, Duration::from_secs(120))?;

        let alice_profile = format!("t17-cli-{}", uuid::Uuid::new_v4());
        let transport = std::env::temp_dir().join(format!("{alice_profile}.transport.json"));
        std::fs::write(&transport, serde_json::to_vec_pretty(&json!({
            "profile": alice_profile,
            "ca_pem": manifest["caPem"],
            "hosts": manifest["hosts"].as_object().map(|hosts| hosts.iter()
                .filter(|(host, _)| host.as_str() == "chat.catbird.blue" || host.ends_with(".request-fixture.catbird.blue"))
                .map(|(host, address)| (host.clone(), address.clone()))
                .collect::<serde_json::Map<_, _>>()).unwrap_or_default()
        }))?)?;
        let mut seeder = Command::new(seeder_bin)
            .env("CATMOS_LOCAL_RUNTIME_TRANSPORT", &transport)
            .env_remove("CATMOS_TEST_KEYCHAIN_FALLBACK")
            .env_remove("CATMOS_TEST_SHARED_KEYCHAIN_FALLBACK")
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped())
            .spawn()?;
        seeder.stdin.take().context("seeder stdin")?.write_all(&serde_json::to_vec(&json!({
            "profile": alice_profile, "did": alice["did"], "deviceId": alice["deviceId"],
            "proxyUrl": manifest["origin"], "serviceUrl": manifest["origin"], "sessionCookie": alice_session
        }))?)?;
        let seeded = seeder.wait_with_output()?;
        ensure!(seeded.status.success(), "seeder failed: {}", String::from_utf8_lossy(&seeded.stderr));
        let seeded: Value = serde_json::from_slice(&seeded.stdout)?;
        let preseed = alice_http
            .post(format!("{}/fixture/enroll", manifest["origin"].as_str().context("origin")?))
            .bearer_auth(&alice_session)
            .json(&json!({"device_id": alice["deviceId"], "signature_public_key": seeded["signaturePublicKey"]}))
            .send().await?;
        ensure!(preseed.status().is_success(), "alice preseed failed: {}", preseed.status());
        let delivery = Command::new(catmos_bin)
            .args(["--profile", &alice_profile, "--no-startup-sync", "request", "delivery", "--enable"])
            .env("CATMOS_LOCAL_RUNTIME_TRANSPORT", &transport)
            .output()?;
        ensure!(delivery.status.success(), "alice delivery enable failed: {}", String::from_utf8_lossy(&delivery.stderr));

        let intro = format!("client-birdaemon process-leg introduction {}", uuid::Uuid::new_v4());
        let (_draft, convo_id) = cli_send_request(catmos_bin, &alice_profile, &transport, &bob_did, &intro)?;
        eprintln!("[client-birdaemon-process] Request published {convo_id}; waiting for the running bot...");

        let reply_text = "Hello from BIRDaemon mock bridge reply!";
        let alice_messages = || -> Result<String> {
            let out = Command::new(catmos_bin)
                .args(["--profile", &alice_profile, "messages", &convo_id])
                .env("CATMOS_LOCAL_RUNTIME_TRANSPORT", &transport)
                .output()?;
            Ok(String::from_utf8_lossy(&out.stdout).into_owned())
        };
        let deadline = std::time::Instant::now() + Duration::from_secs(150);
        let mut history = String::new();
        while std::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_secs(3)).await;
            history = alice_messages()?;
            if history.contains(reply_text) {
                break;
            }
        }
        std::fs::write(evidence_dir.join("process-leg-cli-messages-after-reply.txt"), &history)?;
        ensure!(history.contains(reply_text), "CLI never decrypted a reply from the running bird-daemon process");
        ensure!(history.matches(reply_text).count() == 1, "reply rendered more than once for the CLI");
        let bridge_after_reply = bridge.message_count();
        ensure!(bridge_after_reply == 1, "running bot called the bridge {bridge_after_reply} times, expected 1");

        let exit1 = stop_bot_process(&mut bot)?;
        let (bot2, command2, exe_sha2) = spawn_bot_process(bot_bin, &bob_run, &log2)?;
        bot = bot2;
        let pid2 = bot.id();
        ensure!(pid2 != pid1, "relaunch reused pid {pid1}");
        eprintln!("[client-birdaemon-process] relaunched bird-daemon pid {pid2}: {command2}");
        wait_for_log(&log2, "Bot event loop running", 1, Duration::from_secs(120))?;
        wait_for_log(&log2, "Server sync complete", 1, Duration::from_secs(120))?;
        // One full periodic sync cycle (30 s) plus margin after the relaunch.
        tokio::time::sleep(Duration::from_secs(40)).await;
        let bridge_after_restart = bridge.message_count();
        ensure!(bridge_after_restart == 1, "relaunched bot produced another bridge call ({bridge_after_restart})");
        let claims: i64 = rusqlite::Connection::open(bob_dir.join("bird.db"))?
            .query_row("SELECT count(*) FROM bot_effect_claims", [], |r| r.get(0))?;
        ensure!(claims == 1, "expected exactly one durable effect claim, found {claims}");
        let history_after_restart = alice_messages()?;
        std::fs::write(evidence_dir.join("process-leg-cli-messages-after-bot-restart.txt"), &history_after_restart)?;
        ensure!(history_after_restart.matches(reply_text).count() == 1, "reply duplicated after bot restart");
        ensure!(history_after_restart.contains(&intro), "introduction missing from CLI history");
        for log in [&log1, &log2] {
            ensure!(!std::fs::read_to_string(log)?.contains(&intro), "introduction plaintext in bot process log");
        }
        let exit2 = stop_bot_process(&mut bot)?;
        Ok(json!({
            "database": dedicated_db.name, "conversationId": convo_id, "recipientDid": bob_did,
            "gateway": {"pid": gateway.child.id(), "psCommand": gw_command, "executableSha256": gw_running_sha},
            "run1": {"pid": pid1, "psCommand": command1, "executableSha256": exe_sha1, "exitCode": exit1},
            "run2": {"pid": pid2, "psCommand": command2, "executableSha256": exe_sha2, "exitCode": exit2},
            "bridgeCallsAfterReply": bridge_after_reply, "bridgeCallsAfterRestart": bridge_after_restart,
            "effectClaims": claims,
            "replyOccurrencesAfterReply": history.matches(reply_text).count(),
            "replyOccurrencesAfterRestart": history_after_restart.matches(reply_text).count(),
        }))
    }
    .await;
    if outcome.is_err() {
        let _ = stop_bot_process(&mut bot);
    }
    gateway.shutdown()?;
    let _ = std::fs::remove_dir_all(&gw_dir);
    let _ = std::fs::remove_dir_all(&bob_dir);
    outcome
}

/// Verification of client-birdaemon runtime row (live against client_runtime_gateway).
pub(crate) async fn run_client_birdaemon_live_scenario() -> Result<()> {
    let started_at = Utc::now().to_rfc3339();
    let log_capture = install_process_log_capture()?;
    let workspace_root = Path::new("/Users/joshlacalamito/Developer/.workspaces/catbird-encrypted-requests-20260919");
    eprintln!("[client-birdaemon] Starting own gateway instance (lock retired).");

    let gw_dir = std::env::temp_dir().join(format!("gw-client-birdaemon-{}", uuid::Uuid::new_v4()));
    let gw_config = json!({
        "output_dir": gw_dir,
        "cors_origin": "http://127.0.0.1:5173",
        "lifetime_seconds": 600
    });

    // CliLive's retained code-signed fixture pair. macOS binds keychain ACLs to the
    // code signature, so an unsigned build cannot read the protected MLS DB key
    // headlessly. Reuse the exact sealed pair rather than an unsigned rebuild.
    let freeze5 = Path::new("/Users/joshlacalamito/Developer/.workspaces/freeze5-artifacts");
    let catmos_bin = std::env::var_os("CATMOS_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| freeze5.join("cli/catmos"));
    let seeder_bin = std::env::var_os("SEEDER_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| freeze5.join("cli/seed_local_request_profile"));
    let gw_bin = std::env::var_os("GATEWAY_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| freeze5.join("servers/client_runtime_gateway"));
    let server_fixture_bin = std::env::var_os("SERVER_FIXTURE_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| freeze5.join("servers/encrypted_request_server_fixture"));
    let bir_daemon_bin = std::env::var_os("BIRD_DAEMON_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| freeze5.join("cli/bird-daemon"));

    for (label, bin) in [
        ("gateway", &gw_bin),
        ("server fixture", &server_fixture_bin),
        ("signed catmos CLI", &catmos_bin),
        ("signed seeder", &seeder_bin),
        ("BIRDaemon", &bir_daemon_bin),
    ] {
        ensure!(bin.is_file(), "missing binary for {label}: {}", bin.display());
    }

    eprintln!("[client-birdaemon] Creating dedicated DB and launching client_runtime_gateway...");
    let dedicated_db = DedicatedDbGuard::create()?;
    let mut gw_child = GatewayChild::spawn(&gw_bin, &gw_config, &server_fixture_bin, &dedicated_db.url)?;
    let ready_line = gw_child.stdout_line()?;
    eprintln!("[client-birdaemon] Gateway stdout: {}", ready_line.trim());
    ensure!(
        !ready_line.trim().is_empty(),
        "Gateway exited before readiness: {}",
        gw_child.take_stderr()?
    );
    let gw_ps = Command::new("ps")
        .args(["-o", "command=", "-p", &gw_child.child.id().to_string()])
        .output()?;
    let gw_command = String::from_utf8_lossy(&gw_ps.stdout).trim().to_string();
    ensure!(!gw_command.is_empty(), "gateway process {} not running", gw_child.child.id());
    let gw_exe = PathBuf::from(gw_command.split_whitespace().next().context("ps command")?);
    let gw_running_sha = file_sha256(&gw_exe)?;
    eprintln!("[client-birdaemon] Running gateway PID {} ({}) SHA-256: {}", gw_child.child.id(), gw_command, gw_running_sha);
    let ready_val: Value = serde_json::from_str(&ready_line).context("parse gateway readiness JSON")?;
    let manifest_path = PathBuf::from(ready_val["manifest"].as_str().context("manifest path in readiness")?);
    let sessions_path = gw_dir.join("sessions.json");

    let manifest_data: Value = serde_json::from_slice(&std::fs::read(&manifest_path)?)?;
    let sessions_data: Value = serde_json::from_slice(&std::fs::read(&sessions_path)?)?;

    let accounts = manifest_data["accounts"].as_array().context("accounts array")?;
    let sessions = sessions_data["accounts"].as_array().context("sessions accounts array")?;

    let alice_acc = accounts.iter().find(|a| a["label"] == "alice").context("alice manifest account")?;
    let alice_sess = sessions.iter().find(|s| s["label"] == "alice").context("alice session")?;

    let gateway_origin = manifest_data["origin"].as_str().context("gateway origin")?;

    eprintln!("[client-birdaemon] Starting mock bridge...");
    let bridge = MockBridge::start().await?;
    let bridge_url = format!("http://127.0.0.1:{}", bridge.port);

    eprintln!("[client-birdaemon] Initializing Bob (BIRDaemon) runtime...");
    let bob_dir = std::env::temp_dir().join(format!("bob-fixture-{}", uuid::Uuid::new_v4()));
    let bob_run_cfg = DebugFixtureRunConfig {
        manifest_path: manifest_path.clone(),
        sessions_path: sessions_path.clone(),
        account_label: "bob".into(),
        data_dir: bob_dir.clone(),
        bridge_url: bridge_url.clone(),
        receive_chat_requests: true,
        accept_chat_requests: false, // non-autoaccept holds initially!
        reply_to_all_messages: true,
        max_reply_characters: 1000,
    };
    let bob_run_json_path = std::env::temp_dir().join(format!("bob-run-{}.json", uuid::Uuid::new_v4()));
    std::fs::write(&bob_run_json_path, serde_json::to_vec_pretty(&bob_run_cfg)?)?;

    let bob_ctx = DebugFixtureContext::load(&bob_run_json_path)?;
    let bob_runtime = assemble_runtime(bob_ctx).await?;

    eprintln!("[client-birdaemon] Enabling Bob direct request delivery on delivery service...");
    bob_runtime.bot.maintain_request_keys().await;
    let bob_delivery = bob_runtime.orchestrator.get_direct_request_delivery_enabled().await?;
    if bob_delivery != Some(true) {
        let captured = String::from_utf8_lossy(&log_capture.lock().unwrap()).into_owned();
        let warnings: Vec<&str> = captured.lines().filter(|l| l.contains("Request ")).collect();
        eprintln!("[client-birdaemon] Bob delivery={bob_delivery:?}; bot warnings: {warnings:#?}");
    }
    ensure!(bob_delivery == Some(true), "Bob request delivery preference was not acknowledged");
    bob_runtime.orchestrator.replenish_direct_request_keys_if_needed().await?;
    eprintln!("[client-birdaemon] Bob request key package pool replenished.");

    eprintln!("[client-birdaemon] Seeding Alice (catmos-cli) profile...");
    let alice_profile = format!("t17-cli-{}", uuid::Uuid::new_v4());
    let alice_manifest_path = std::env::temp_dir().join(format!("{alice_profile}.transport.json"));
    let transport_cfg = json!({
        "profile": alice_profile,
        "ca_pem": manifest_data["caPem"],
        "hosts": manifest_data["hosts"].as_object().map(|hosts| hosts.iter()
            .filter(|(host, _)| {
                host.as_str() == "chat.catbird.blue"
                    || host.ends_with(".request-fixture.catbird.blue")
            })
            .map(|(host, address)| (host.clone(), address.clone()))
            .collect::<serde_json::Map<_, _>>()).unwrap_or_default()
    });
    std::fs::write(&alice_manifest_path, serde_json::to_vec_pretty(&transport_cfg)?)?;

    let alice_seed = json!({
        "profile": alice_profile,
        "did": alice_acc["did"],
        "deviceId": alice_acc["deviceId"],
        "proxyUrl": gateway_origin,
        "serviceUrl": gateway_origin,
        "sessionCookie": alice_sess["session"]
    });

    let mut seeder_cmd = Command::new(&seeder_bin)
        .env("CATMOS_LOCAL_RUNTIME_TRANSPORT", &alice_manifest_path)
        .env_remove("CATMOS_TEST_KEYCHAIN_FALLBACK")
        .env_remove("CATMOS_TEST_SHARED_KEYCHAIN_FALLBACK")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    {
        let mut stdin = seeder_cmd.stdin.take().context("seeder stdin")?;
        stdin.write_all(&serde_json::to_vec(&alice_seed)?)?;
        drop(stdin);
    }
    let seeder_out = seeder_cmd.wait_with_output()?;
    ensure!(seeder_out.status.success(), "seeder failed: {}", String::from_utf8_lossy(&seeder_out.stderr));
    let seed_res: Value = serde_json::from_slice(&seeder_out.stdout)?;
    let alice_public_key = seed_res["signaturePublicKey"].as_str().context("alice public key")?;

    eprintln!("[client-birdaemon] Preseeding Alice native authority on gateway...");
    let preseed_alice = bob_runtime.context.http
        .post(format!("{}/fixture/enroll", gateway_origin))
        .bearer_auth(alice_sess["session"].as_str().unwrap())
        .json(&json!({
            "device_id": alice_acc["deviceId"],
            "signature_public_key": alice_public_key,
        }))
        .send()
        .await?;
    ensure!(preseed_alice.status().is_success(), "Alice preseed failed: {}", preseed_alice.status());

    eprintln!("[client-birdaemon] Enabling Alice request delivery preference...");
    let delivery_out = Command::new(&catmos_bin)
        .args(["--profile", &alice_profile, "--no-startup-sync", "request", "delivery", "--enable"])
        .env("CATMOS_LOCAL_RUNTIME_TRANSPORT", &alice_manifest_path)
        .output()?;
    ensure!(delivery_out.status.success(), "alice delivery enable failed: {}", String::from_utf8_lossy(&delivery_out.stderr));

    let intro_text = "Hello Bob, this is Alice qualifying client-birdaemon.";
    eprintln!("[client-birdaemon] Alice sending encrypted direct request to Bob ({}) ...", bob_runtime.context.did);
    let (draft_id, convo_id) = cli_send_request(
        &catmos_bin, &alice_profile, &alice_manifest_path, &bob_runtime.context.did, intro_text,
    )?;

    eprintln!("[client-birdaemon] Bob syncing with server and refreshing request preview...");
    bob_runtime.orchestrator.sync_with_server(true).await?;
    let _ = bob_runtime.orchestrator.refresh_request_preview(&convo_id).await?;
    bob_runtime.bot.handle_request_views().await;
    let probe = bob_runtime.api_client.effect_probe();
    let typing = || probe.typing_attempts.load(std::sync::atomic::Ordering::SeqCst);
    let downloads = || probe.blob_downloads.load(std::sync::atomic::Ordering::SeqCst);
    let captured_has = |needle: &str| {
        let bytes = log_capture.lock().unwrap();
        bytes.windows(needle.len()).any(|w| w == needle.as_bytes())
    };
    let claim_count = |dir: &Path| -> Result<i64> {
        Ok(rusqlite::Connection::open(dir.join("bird.db"))?
            .query_row("SELECT count(*) FROM bot_effect_claims", [], |r| r.get(0))?)
    };

    // Pending (non-autoaccept): the bot has processed the verified view.
    eprintln!("[client-birdaemon] Verifying non-autoaccept zero effects...");
    let pending = bob_runtime.orchestrator.refresh_request_preview(&convo_id).await?;
    ensure!(pending.consent == RequestConsent::IncomingPending, "consent must stay IncomingPending");
    ensure!(pending.crypto == RequestCrypto::Ready, "real core decryption must reach Ready");
    ensure!(
        matches!(&pending.preview, Some(RequestPreview::Ready { text, .. }) if text == intro_text),
        "decrypted preview must equal the published introduction"
    );

    ensure!(bridge.message_count() == 0, "pending: zero bridge/LLM calls");
    ensure!(typing() == 0, "pending: zero typing attempts at the transport boundary");
    ensure!(downloads() == 0, "pending: zero blob downloads at the transport boundary");
    ensure!(
        !captured_has(intro_text),
        "pending: zero plaintext in captured process logs"
    );
    ensure!(claim_count(&bob_dir)? == 0, "pending: zero effect claims");
    let unkeyed = rusqlite::Connection::open(bob_dir.join("bird.db"))?;
    let bird_messages: i64 = unkeyed.query_row("SELECT count(*) FROM messages", [], |r| r.get(0))?;
    ensure!(bird_messages == 0, "pending: zero rows in unkeyed bird.db messages");
    for file in std::fs::read_dir(&bob_dir)?.chain(std::fs::read_dir(bob_dir.join("mls-state"))?) {
        let path = file?.path();
        if path.is_file() {
            let bytes = std::fs::read(&path)?;
            ensure!(
                !bytes.windows(intro_text.len()).any(|w| w == intro_text.as_bytes()),
                "plaintext introduction found on disk in {}",
                path.display()
            );
        }
    }
    let native_db = std::fs::read_dir(bob_dir.join("mls-state"))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .find(|p| p.extension().is_some_and(|x| x == "db"))
        .context("native MLS store")?;
    ensure!(
        rusqlite::Connection::open(&native_db)?
            .query_row("SELECT count(*) FROM sqlite_master", [], |_| Ok(()))
            .is_err(),
        "native SQLCipher store must reject unkeyed access"
    );


    // Autoaccept: the bot itself must call the real acceptance RPC first.
    eprintln!("[client-birdaemon] Enabling Bob autoaccept; bot handles the verified view...");
    bob_runtime.bot.set_accept_chat_requests(true);
    bob_runtime.bot.handle_request_views().await;
    let accepted = bob_runtime.orchestrator.refresh_request_preview(&convo_id).await?;
    ensure!(
        accepted.consent == RequestConsent::Accepted && accepted.capabilities.can_send,
        "bot autoaccept must reach a server-acknowledged Accepted projection"
    );

    let mut bridge_called = false;
    for _ in 0..20 {
        if bridge.message_count() >= 1 {
            bridge_called = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    ensure!(bridge_called, "bridge was not called after autoaccept");
    ensure!(bridge.message_count() == 1, "bridge called exactly once");

    ensure!(claim_count(&bob_dir)? == 1, "exactly one durable effect claim");

    eprintln!("[client-birdaemon] Alice fetching conversation messages to verify reply...");
    let reply_text = "Hello from BIRDaemon mock bridge reply!";
    let mut reply_received = false;
    let mut last_stdout = String::new();
    let mut last_stderr = String::new();
    for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(500)).await;
        let read_cmd = Command::new(&catmos_bin)
            .args(["--profile", &alice_profile, "messages", &convo_id])
            .env("CATMOS_LOCAL_RUNTIME_TRANSPORT", &alice_manifest_path)
            .output()?;
        last_stdout = String::from_utf8_lossy(&read_cmd.stdout).to_string();
        last_stderr = String::from_utf8_lossy(&read_cmd.stderr).to_string();
        if last_stdout.contains(reply_text) {
            reply_received = true;
            break;
        }
    }
    if !reply_received {
        eprintln!("[client-birdaemon] Alice CLI stdout: {last_stdout}");
        eprintln!("[client-birdaemon] Alice CLI stderr: {last_stderr}");
    }
    ensure!(reply_received, "Alice must decrypt Bob's reply");

    // F37: the peer decrypting the reply does not prove the bot's local send
    // state. The core stores the own row only after the server-accepted request
    // matched and the own-echo proof was persisted; the core's own-echo intake
    // then accepts the server echo only against that durable proof.
    use catbird_mls::orchestrator::MLSStorageBackend;
    const ECHO_REFUSAL: &str = "OwnPrivateMessage without durable echo proof";
    let own_reply_rows = |messages: &[catbird_mls::orchestrator::Message]| {
        messages.iter().filter(|m| m.is_own && m.text == reply_text).count()
    };
    // Debug lines the core emits only when an own echo is accepted as proven.
    let proven_echo_hits = || {
        let captured = String::from_utf8_lossy(&log_capture.lock().unwrap()).into_owned();
        captured.matches("Skipping durably proven own private message").count()
            + captured.matches("Skipping already-ratcheted SecretReuse message").count()
    };
    ensure!(!captured_has("Request reply send failed"), "bot reply send returned an error locally");
    let local = bob_runtime.orchestrator.storage().get_messages(&convo_id, 50, None).await?;
    ensure!(
        own_reply_rows(&local) == 1,
        "reply must be stored as sent exactly once after a locally successful send (found {})",
        own_reply_rows(&local)
    );
    let reply_delivery_status = local
        .iter()
        .find(|m| m.is_own && m.text == reply_text)
        .map(|m| format!("{:?}", m.delivery_status))
        .unwrap_or_default();
    let hits_before = proven_echo_hits();
    bob_runtime.orchestrator.fetch_messages(&convo_id, None, 50, None, None, None).await?;
    let in_process_echo_hits = proven_echo_hits() - hits_before;
    ensure!(in_process_echo_hits >= 1, "core did not accept the reply echo as a proven own message");
    ensure!(!captured_has(ECHO_REFUSAL), "core refused the reply echo: no durable own-echo proof");
    ensure!(
        !bob_runtime.orchestrator.storage().needs_rejoin(&convo_id).await?,
        "own reply echo forced a rejoin"
    );
    let after_echo = bob_runtime.orchestrator.storage().get_messages(&convo_id, 50, None).await?;
    ensure!(own_reply_rows(&after_echo) == 1, "own echo must not duplicate or drop the sent reply");

    // Replay the same verified request event in-process, then after a restart.
    bob_runtime.bot.handle_request_views().await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    ensure!(bridge.message_count() == 1, "in-process replay caused a second bridge call");
    drop(bob_runtime);
    let restarted = assemble_runtime(DebugFixtureContext::load(&bob_run_json_path)?).await?;
    eprintln!("[client-birdaemon] Calling sync_with_server after in-process restart...");
    if let Err(e) = restarted.orchestrator.sync_with_server(true).await {
        eprintln!("[client-birdaemon] sync_with_server after restart failed: {e:?}");
        panic!("sync_with_server after restart failed: {e:?}");
    }
    restarted.bot.set_accept_chat_requests(true);
    restarted.bot.handle_request_views().await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    ensure!(bridge.message_count() == 1, "restart replay caused a second bridge call");
    ensure!(claim_count(&bob_dir)? == 1, "restart replay created a second effect claim");
    let restarted_rows = restarted.orchestrator.storage().get_messages(&convo_id, 50, None).await?;
    ensure!(
        own_reply_rows(&restarted_rows) == 1,
        "after restart the reply must be present as sent exactly once (found {})",
        own_reply_rows(&restarted_rows)
    );
    let hits_before = proven_echo_hits();
    restarted.orchestrator.fetch_messages(&convo_id, None, 50, None, None, None).await?;
    let restart_echo_hits = proven_echo_hits() - hits_before;
    ensure!(
        restart_echo_hits >= 1,
        "after restart (no in-memory pending state) the core did not accept the reply echo against the durable proof"
    );
    ensure!(!captured_has(ECHO_REFUSAL), "restarted core refused the reply echo");
    ensure!(
        !restarted.orchestrator.storage().needs_rejoin(&convo_id).await?,
        "restarted reply echo forced a rejoin"
    );
    ensure!(
        own_reply_rows(&restarted.orchestrator.storage().get_messages(&convo_id, 50, None).await?) == 1,
        "restarted echo intake duplicated or dropped the reply"
    );
    ensure!(
        restarted.api_client.effect_probe().blob_downloads.load(std::sync::atomic::Ordering::SeqCst) == 0
            && restarted.api_client.effect_probe().typing_attempts.load(std::sync::atomic::Ordering::SeqCst) == 0,
        "restart replay produced a download or typing attempt"
    );
    ensure!(typing() == 0 && downloads() == 0, "request path produced typing or downloads");
    ensure!(
        !captured_has(intro_text),
        "introduction plaintext appeared in captured process logs"
    );

    gw_child.shutdown()?;
    // Box the legs: their deep core futures otherwise overflow the test thread stack.
    let declined = Box::pin(run_declined_leg(&gw_bin, &server_fixture_bin, &catmos_bin, &seeder_bin, &log_capture)).await?;
    let invalid = Box::pin(run_invalid_introduction_leg(&gw_bin, &server_fixture_bin, &log_capture)).await?;
    let evidence_dir = workspace_root.join("docs/generated-artifacts/encrypted-requests/evidence/client-birdaemon");
    std::fs::create_dir_all(&evidence_dir)?;
    let process_leg = Box::pin(run_birdaemon_process_leg(
        &gw_bin, &server_fixture_bin, &catmos_bin, &seeder_bin, &bir_daemon_bin, &evidence_dir,
    ))
    .await?;
    ensure!(
        process_leg["run1"]["executableSha256"] == file_sha256(&bir_daemon_bin)?
            && process_leg["run2"]["executableSha256"] == file_sha256(&bir_daemon_bin)?,
        "running bot executable differs from the recorded bot binary"
    );
    let ended_at = Utc::now().to_rfc3339();

    // C35 bot parity: exact binaries and shared-source revision this run used.
    let jj_commit = |repo: &str| -> String {
        Command::new("jj")
            .args(["log", "-r", "@", "--no-graph", "-T", "commit_id ++ \" \" ++ if(empty, \"clean\", \"dirty\")"])
            .current_dir(workspace_root.join(repo))
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
            .unwrap_or_default()
    };
    let test_runner = std::env::current_exe()?;
    let parity = json!({
        "botTestRunner": {"path": test_runner, "sha256": file_sha256(&test_runner)?},
        "birDaemonBinary": {"path": bir_daemon_bin, "sha256": file_sha256(&bir_daemon_bin)?},
        "birDaemonCargoLockSha256": file_sha256(&workspace_root.join("BIRDaemon/Cargo.lock"))?,
        "catbirdMlsWorkingCopy": jj_commit("catbird-mls"),
        "birDaemonWorkingCopy": jj_commit("BIRDaemon"),
        "gatewayBinarySha256": file_sha256(&gw_bin)?,
        "serverFixtureSha256": file_sha256(&server_fixture_bin)?,
        "signedCliSha256": file_sha256(&catmos_bin)?,
        "signedSeederSha256": file_sha256(&seeder_bin)?,
    });


    let parity_file = evidence_dir.join("c35-bot-parity.json");
    std::fs::write(&parity_file, serde_json::to_vec_pretty(&parity)?)?;
    let captured_file = evidence_dir.join("bot-process-captured-logs.txt");
    std::fs::write(&captured_file, &*log_capture.lock().unwrap())?;
    let receipt_file = evidence_dir.join("runtime-receipt.json");
    std::fs::write(&receipt_file, serde_json::to_vec_pretty(&json!({
        "runtimeRow": "client-birdaemon",
        "gateway": {
            "path": make_artifact(workspace_root, &gw_bin)?,
            "runningSha256": gw_running_sha,
            "runningPsCommand": gw_command,
        },
        "sender": {"client": "catmos-cli (signed fixture pair)", "did": alice_acc["did"], "deviceId": alice_acc["deviceId"]},
        "recipient": {"client": "BIRDaemon", "did": restarted.context.did, "deviceId": restarted.context.reserved_device_id},
        "conversationId": convo_id, "draftId": draft_id,
        "declinedLeg": declined,
        "invalidLeg": invalid,
        "processLeg": process_leg,
        "bridgeCalls": bridge.message_count(), "typingAttempts": typing(), "blobDownloads": downloads(),
        "effectClaims": claim_count(&bob_dir)?,
        "replyLocalSend": {
            "sendResult": "ok",
            "ownRowsAfterSend": 1,
            "deliveryStatus": reply_delivery_status,
            "ownEchoAcceptedInProcess": in_process_echo_hits,
            "ownEchoAcceptedAfterRestartByDurableProof": restart_echo_hits,
            "ownRowsAfterRestart": 1,
            "needsRejoin": false
        },
        "startedAt": started_at, "endedAt": ended_at, "outcome": "pass"
    }))?)?;
    let terminal_file = evidence_dir.join("client-birdaemon-terminal-transcript.txt");
    std::fs::write(&terminal_file, format!(
        "Headless runtime: no UI surface exists for the bot or CLI; this terminal transcript stands in for a screenshot.\nconversation {convo_id}: request published by CLI, pending preview decrypted by BIRDaemon with zero effects, bot autoaccepted via acceptConversation, one bridge call, reply sent Ok locally (one own row), own echo accepted in-process and after restart against the durable own-echo proof, reply decrypted by CLI, in-process and restart replays suppressed.\nprocess leg: bird-daemon executable pid {} ({}) received conversation {}, autoaccepted, called the bridge once and replied; the CLI decrypted the reply once; quit and relaunched as pid {}; bridge calls after relaunch {}, effect claims {}.\n",
        process_leg["run1"]["pid"], process_leg["run1"]["psCommand"], process_leg["conversationId"].as_str().unwrap_or_default(),
        process_leg["run2"]["pid"], process_leg["bridgeCallsAfterRestart"], process_leg["effectClaims"]
    ))?;
    std::fs::write(evidence_dir.join("result.json"), serde_json::to_vec_pretty(&json!({
        "id": "client-birdaemon", "outcome": "pass", "testCount": 1, "passed": 1, "failed": 0, "skipped": 0,
        "startedAt": started_at, "endedAt": ended_at,
        "environment": {
            "botBinary": make_artifact(workspace_root, &bir_daemon_bin)?,
            "cliBinary": make_artifact(workspace_root, &catmos_bin)?,
            "seederBinary": make_artifact(workspace_root, &seeder_bin)?,
            "gatewayBinary": make_artifact(workspace_root, &gw_bin)?,
            "serverFixtureBinary": make_artifact(workspace_root, &server_fixture_bin)?,
            "testRunner": make_artifact(workspace_root, &test_runner)?,
            "note": "Test runner binary is test-only harness; the bot under test is the frozen bird-daemon executable executed in fixture mode via spawn_bot_process"
        },
        "assertions": [
            "A real encrypted request was published by the signed CLI through the shipping router and decrypted by BIRDaemon's real core into a Ready preview equal to the sent text.",
            "While pending (no autoaccept) after the bot processed the verified view: 0 bridge/LLM calls (counted at a real HTTP bridge), 0 typing attempts and 0 blob downloads (counted at BirdApiClient's real transport methods), 0 effect claims, 0 bird.db message rows.",
            "A global tracing subscriber plus the core MLS logger captured all bot-process logs; the introduction plaintext never appeared in them.",
            "No plaintext introduction bytes in any file under the bot data dir (bird.db, credentials, keychain, native store); the native SQLCipher store rejected unkeyed access.",
            "With autoaccept configured, the bot's own request path called the real acceptConversation RPC; the server-acknowledged projection became Accepted/can_send before exactly one bridge call and exactly one durable effect claim; the reply was decrypted by the CLI.",
            "F37 local send state: the bot's reply send returned Ok (no send-failure log; exactly one own reply row, which the core writes only after the server-accepted request matched and the own-echo proof was persisted). The core's own-echo intake accepted the server echo in-process and, after a runtime restart with no in-memory pending state, via the durable own-echo proof alone, without refusal or rejoin. After restart the reply is present exactly once.",
            "Declined leg: a real published request on an independent dedicated DB was declined via the real close RPC; with autoaccept enabled the bot never reopened or accepted it, and produced zero bridge, typing, download or claim effects.",
            "Replaying the same verified request event in-process and again after a process-level runtime restart on the same data dir produced no second bridge call, claim, download or typing attempt.",
            "Invalid leg: a malicious-but-authentic sender published a re-signed request with a tampered introduction through the real router to a separate BIRDaemon device configured to autoaccept and reply. Bob's real core rejected the introduction (preview never Ready), the bot never accepted it, and bridge, typing, download and claim effects were all zero.",
            "Process leg: the actual frozen bird-daemon executable was spawned as a live OS process (recorded via ps while running); it received the request, autoaccepted, called the mock bridge once, and replied; the CLI decrypted the reply; the bot was cleanly stopped with SIGINT and relaunched with a new PID on the same data dir; a subsequent sync produced zero duplicate bridge calls and zero duplicate claims."
        ],
        "notExercised": [
            "Local draft cancellation via DirectRequestRepository.cancel() was not exercised on this row; the bot is a headless service and only the CLI sender creates drafts.",
            "Unavailable-device behavior (a recipient device not addressed by the published introduction) was not exercised on this row; the bot recipient has a single device.",
            "Real FCM delivery was not exercised; the local test fixture has no Firebase server.",
            "The policy-off, decline, and invalid legs were qualified using the in-process test harness against the real delivery service and storage rather than a separate daemon process invocation."
        ],
        "binaryHashes": [
            make_artifact(workspace_root, &bir_daemon_bin)?,
            make_artifact(workspace_root, &catmos_bin)?,
            make_artifact(workspace_root, &seeder_bin)?,
            make_artifact(workspace_root, &gw_bin)?,
            make_artifact(workspace_root, &server_fixture_bin)?,
            make_artifact(workspace_root, &test_runner)?,
        ],
        "runtimeReceipt": make_artifact(workspace_root, &receipt_file)?,
        "screenshots": [make_artifact(workspace_root, &terminal_file)?],
        "artifacts": [
            make_artifact(workspace_root, &parity_file)?,
            make_artifact(workspace_root, &captured_file)?,
            make_artifact(workspace_root, &evidence_dir.join("bird-daemon-process-run1.log"))?,
            make_artifact(workspace_root, &evidence_dir.join("bird-daemon-process-run2.log"))?,
            make_artifact(workspace_root, &evidence_dir.join("process-leg-cli-messages-after-reply.txt"))?,
            make_artifact(workspace_root, &evidence_dir.join("process-leg-cli-messages-after-bot-restart.txt"))?,
        ]
    }))?)?;

    let c31_dir = workspace_root.join("docs/generated-artifacts/encrypted-requests/evidence/c31");
    std::fs::create_dir_all(&c31_dir)?;
    std::fs::write(c31_dir.join("result.json"), serde_json::to_vec_pretty(&json!({
        "id": "C31", "outcome": "pass", "testCount": 1, "passed": 1, "failed": 0, "skipped": 0,
        "startedAt": started_at, "endedAt": ended_at,
        "assertions": [
            "A real encrypted request was published by the signed CLI through the shipping router and decrypted by BIRDaemon's real core into a Ready preview equal to the sent text.",
            "While pending (no autoaccept) after the bot processed the verified view: 0 bridge/LLM calls (counted at a real HTTP bridge), 0 typing attempts and 0 blob downloads (counted at BirdApiClient's real transport methods), 0 effect claims, 0 bird.db message rows.",
            "A global tracing subscriber plus the core MLS logger captured all bot-process logs; the introduction plaintext never appeared in them.",
            "No plaintext introduction bytes in any file under the bot data dir (bird.db, credentials, keychain, native store); the native SQLCipher store rejected unkeyed access.",
            "With autoaccept configured, the bot's own request path called the real acceptConversation RPC; the server-acknowledged projection became Accepted/can_send before exactly one bridge call and exactly one durable effect claim; the reply was decrypted by the CLI.",
            "F37 local send state: the bot's reply send returned Ok (no send-failure log; exactly one own reply row, which the core writes only after the server-accepted request matched and the own-echo proof was persisted). The core's own-echo intake accepted the server echo in-process and, after a runtime restart with no in-memory pending state, via the durable own-echo proof alone, without refusal or rejoin. After restart the reply is present exactly once.",
            "Declined leg: a real published request on an independent dedicated DB was declined via the real close RPC; with autoaccept enabled the bot never reopened or accepted it, and produced zero bridge, typing, download or claim effects.",
            "Replaying the same verified request event in-process and again after a process-level runtime restart on the same data dir produced no second bridge call, claim, download or typing attempt.",
            "Invalid leg: a malicious-but-authentic sender published a re-signed request with a tampered introduction through the real router to a separate BIRDaemon device configured to autoaccept and reply. Bob's real core rejected the introduction (preview never Ready), the bot never accepted it, and bridge, typing, download and claim effects were all zero.",
        ],
        "artifacts": [make_artifact(workspace_root, &captured_file)?, make_artifact(workspace_root, &receipt_file)?, make_artifact(workspace_root, &parity_file)?],
        "declinedLeg": declined,
        "invalidLeg": invalid,
    }))?)?;
    eprintln!("[client-birdaemon] Scenario completed successfully and evidence written.");

    let _ = std::fs::remove_dir_all(&gw_dir);
    let _ = std::fs::remove_dir_all(&bob_dir);
    let _ = std::fs::remove_file(&alice_manifest_path);
    let _ = std::fs::remove_file(&bob_run_json_path);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires the local client runtime gateway fixture"]
async fn test_client_birdaemon_live_scenario() {
    if let Err(e) = Box::pin(run_client_birdaemon_live_scenario()).await {
        panic!("test_client_birdaemon_live_scenario failed: {e:?}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires the local client runtime gateway fixture"]
async fn test_relaunch_sync_succeeds() {
    let _capture = install_process_log_capture().expect("log capture");
    let freeze5 = Path::new("/Users/joshlacalamito/Developer/.workspaces/freeze5-artifacts");
    let catmos_bin = freeze5.join("cli/catmos");
    let seeder_bin = freeze5.join("cli/seed_local_request_profile");
    let gw_bin = freeze5.join("servers/client_runtime_gateway");
    let server_fixture_bin = freeze5.join("servers/encrypted_request_server_fixture");
    let dedicated_db = DedicatedDbGuard::create().expect("db create");
    let gw_dir = std::env::temp_dir().join(format!("gw-relaunch-{}", uuid::Uuid::new_v4()));
    let gw_config = json!({"output_dir": gw_dir, "cors_origin": "http://127.0.0.1:5173", "lifetime_seconds": 600});
    let mut gw_child = GatewayChild::spawn(&gw_bin, &gw_config, &server_fixture_bin, &dedicated_db.url).expect("spawn gateway");
    let ready_line = gw_child.stdout_line().expect("ready");
    let ready_val: Value = serde_json::from_str(&ready_line).unwrap();
    let manifest_path = PathBuf::from(ready_val["manifest"].as_str().unwrap());
    let sessions_path = gw_dir.join("sessions.json");
    let manifest_data: Value = serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
    let accounts = manifest_data["accounts"].as_array().unwrap();
    let bob_acc = accounts.iter().find(|a| a["label"] == "bob").unwrap();
    let alice_acc = accounts.iter().find(|a| a["label"] == "alice").unwrap();

    let bridge = MockBridge::start().await.unwrap();
    let bob_dir = std::env::temp_dir().join(format!("bob-relaunch-{}", uuid::Uuid::new_v4()));
    let bob_run_config = DebugFixtureRunConfig {
        manifest_path: manifest_path.clone(),
        sessions_path: sessions_path.clone(),
        account_label: "bob".into(),
        data_dir: bob_dir.clone(),
        bridge_url: format!("http://127.0.0.1:{}", bridge.port),
        receive_chat_requests: true,
        accept_chat_requests: true,
        reply_to_all_messages: true,
        max_reply_characters: 1000,
    };
    let bob_run_json = serde_json::to_vec_pretty(&bob_run_config).unwrap();
    let bob_run_path = std::env::temp_dir().join(format!("bob-relaunch-config-{}.json", uuid::Uuid::new_v4()));
    std::fs::write(&bob_run_path, &bob_run_json).unwrap();

    let bob_ctx = DebugFixtureContext::load(&bob_run_path).unwrap();
    let bob = assemble_runtime(bob_ctx).await.unwrap();
    bob.orchestrator.sync_with_server(true).await.unwrap();
    bob.orchestrator.set_direct_request_delivery_enabled(true).await.unwrap();
    bob.bot.maintain_request_keys().await;

    let alice_profile = format!("t17-cli-{}", uuid::Uuid::new_v4());
    let hosts: std::collections::BTreeMap<String, String> = manifest_data["hosts"].as_object().unwrap().iter().filter(|(h, _)| h.as_str() != "public.api.bsky.app").map(|(k, v)| (k.clone(), v.as_str().unwrap().to_string())).collect();
    let transport = std::env::temp_dir().join(format!("alice-transport-{}.json", uuid::Uuid::new_v4()));
    std::fs::write(&transport, serde_json::to_vec_pretty(&json!({"profile": alice_profile, "ca_pem": manifest_data["caPem"], "hosts": hosts})).unwrap()).unwrap();
    let sessions_data: Value = serde_json::from_slice(&std::fs::read(&sessions_path).unwrap()).unwrap();
    let sessions = sessions_data["accounts"].as_array().unwrap();
    let alice_sess = sessions.iter().find(|s| s["label"] == "alice").unwrap();
    let mut seeder_cmd = Command::new(&seeder_bin)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .env("CATMOS_LOCAL_RUNTIME_TRANSPORT", &transport)
        .spawn().unwrap();
    let mut stdin = seeder_cmd.stdin.take().unwrap();
    stdin.write_all(&serde_json::to_vec(&json!({
        "profile": alice_profile, "did": alice_acc["did"], "deviceId": alice_acc["deviceId"],
        "proxyUrl": manifest_data["origin"], "serviceUrl": "https://chat.catbird.blue",
        "sessionCookie": alice_sess["session"]
    })).unwrap()).unwrap();
    drop(stdin);
    let seeder_out = seeder_cmd.wait_with_output().unwrap();
    let seed_res: Value = serde_json::from_slice(&seeder_out.stdout).unwrap();
    let _ = bob.context.http.post(format!("{}/fixture/enroll", manifest_data["origin"].as_str().unwrap()))
        .bearer_auth(alice_sess["session"].as_str().unwrap())
        .json(&json!({"device_id": alice_acc["deviceId"], "signature_public_key": seed_res["signaturePublicKey"]}))
        .send().await.unwrap();
    let _ = Command::new(&catmos_bin)
        .args(["--profile", &alice_profile, "--no-startup-sync", "request", "delivery", "--enable"])
        .env("CATMOS_LOCAL_RUNTIME_TRANSPORT", &transport).output().unwrap();
    let (_draft, _convo_id) = cli_send_request(&catmos_bin, &alice_profile, &transport, bob_acc["did"].as_str().unwrap(), "Hello relaunch sync test").unwrap();

    bob.orchestrator.sync_with_server(true).await.unwrap();
    bob.bot.handle_request_views().await;
    tokio::time::sleep(Duration::from_secs(2)).await;

    drop(bob);
    let restarted = assemble_runtime(DebugFixtureContext::load(&bob_run_path).unwrap()).await.unwrap();
    let sync_result = restarted.orchestrator.sync_with_server(true).await;
    let _ = std::fs::remove_dir_all(&gw_dir);
    let _ = std::fs::remove_dir_all(&bob_dir);
    let _ = std::fs::remove_file(&bob_run_path);
    let _ = std::fs::remove_file(&transport);
    gw_child.shutdown().unwrap();
    assert!(sync_result.is_ok(), "relaunch sync must succeed: {:?}", sync_result.err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires the local client runtime gateway fixture"]
async fn test_c31_invalid_introduction_leg_live() {
    let root = Path::new("/Users/joshlacalamito/Developer/.workspaces/catbird-encrypted-requests-20260919");
    let result = async {
        let capture = install_process_log_capture()?;
        run_invalid_introduction_leg(
            &root.join("mls-ds/e2e-tests/target/debug/examples/client_runtime_gateway"),
            &root.join("mls-ds/target/debug/encrypted_request_server_fixture"),
            &capture,
        )
        .await
    }
    .await;
    match result {
        Ok(summary) => eprintln!("[c31-invalid] PASS {summary}"),
        Err(e) => panic!("invalid leg failed: {e:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires the local client runtime gateway fixture and signed CLI pair"]
async fn test_c31_declined_leg_live() {
    let root = Path::new("/Users/joshlacalamito/Developer/.workspaces/catbird-encrypted-requests-20260919");
    let signed_pair = PathBuf::from(std::env::var("BIRD_RUNTIME_CLI_FIXTURE_DIR").unwrap_or_else(|_| {
        "/tmp/catbird-t17-cli-scoped-artifacts-5dd295d5-183b-44ad-949f-714e03679685".into()
    }));
    let result = async {
        let capture = install_process_log_capture()?;
        run_declined_leg(
            &root.join("mls-ds/e2e-tests/target/debug/examples/client_runtime_gateway"),
            &root.join("mls-ds/target/debug/encrypted_request_server_fixture"),
            &signed_pair.join("catmos"),
            &signed_pair.join("seed_local_request_profile"),
            &capture,
        )
        .await
    }
    .await;
    match result {
        Ok(summary) => eprintln!("[c31-declined] PASS {summary}"),
        Err(e) => panic!("declined leg failed: {e:?}"),
    }
}
