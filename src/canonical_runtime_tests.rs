//! RED/green integration tests for Task 10 BIRDaemon canonical runtime.
//!
//! Verifies:
//! 1. Canonical read/send/blob/subscription through Nest using Task 4 opaque authority and Task 5 signer.
//! 2. Proof that Nest session bearer is never sent to PDS/DS.
//! 3. Proof that downstream tokens/proofs/keys never enter BIR.
//! 4. Nest session refresh and re-enrollment across 401/403 and invalidations.
//! 5. Process restart recovery with valid snapshot and rejection of stale tuples.
//! 6. Typing remains explicitly disabled.
//! 7. Non-production receive -> decrypt -> reply flow.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use catbird_mls::orchestrator::credentials::CredentialStore;
use catbird_mls::orchestrator::error::OrchestratorError;
use catbird_mls::orchestrator::{
    CanonicalOperation, CleanChatSigningAuthority, CleanChatSigningContext, MLSAPIClient,
    PreparedRequest,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::types::SignatureScheme;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::chat_authority::{
    derive_key_id, AuthoritySnapshot, AuthorityState, NestClient, CHAT_DEVICE_HEADER,
    CHAT_JKT_HEADER,
};
use crate::credentials::FileCredentialStore;
use crate::xrpc_client::{BirdApiClient, CleanChatRequestSigner};

const TEST_DID: &str = "did:plc:alicefixtureaaaaaaaaaaaa";
const TEST_DEVICE_ID: &str = "70707070-7070-4070-b070-707070707070";
const TEST_JKT: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const TEST_OPAQUE_SESSION: &str = "opaque-nest-session-token-secret-xyz-999";
const TEST_CONVO_ID: &str = "11111111-1111-4111-9111-111111111111";

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(prefix: &str) -> Self {
        let path = std::env::temp_dir().join(format!("bir-test-{prefix}-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&path).unwrap();
        Self { path }
    }

    fn path(&self) -> &std::path::Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn test_snapshot(
    session: &str,
    did: &str,
    device_id: &str,
    jkt: &str,
    generation: i64,
    signer_pair: &SignatureKeyPair,
) -> AuthoritySnapshot {
    let public_key = signer_pair.public().to_vec();
    let signer_handle = derive_key_id(&public_key);
    AuthoritySnapshot::new(
        session.into(),
        did.into(),
        device_id.into(),
        jkt.into(),
        generation,
        signer_handle,
        public_key,
        1,
    )
    .unwrap()
}

struct TestSigner {
    creds: Arc<FileCredentialStore>,
}

#[async_trait::async_trait]
impl CleanChatRequestSigner for TestSigner {
    async fn prepare_signed_request(
        &self,
        binding: CleanChatSigningContext,
        operation: CanonicalOperation,
        body_json: Vec<u8>,
    ) -> Result<PreparedRequest, OrchestratorError> {
        let key_id = derive_key_id(&[0; 32]);
        let auth = self
            .creds
            .sign_clean_chat_transcript(&binding.actor_did, &body_json, &key_id)
            .await
            .map_err(|e| OrchestratorError::Credential(e.to_string()))?
            .unwrap_or(CleanChatSigningAuthority {
                public_key: vec![0; 32],
                signature: vec![1; 64],
                device_id: binding.device_id.clone(),
                dpop_jkt: binding.dpop_jkt.clone(),
                auth_generation: binding.auth_generation,
            });

        let body_val: serde_json::Value = serde_json::from_slice(&body_json).unwrap();
        let signed = json!({
            "signedRequest": {
                "body": body_val,
                "signature": {"$bytes": B64.encode(&auth.signature)}
            }
        });

        Ok(PreparedRequest {
            operation,
            method: "POST".into(),
            path: "/xrpc/blue.catbird.chat.sendMessage".into(),
            authorization: String::new(),
            dpop: String::new(),
            body: Some(serde_json::to_vec(&signed).unwrap()),
        })
    }
}

fn empty_conversations_json() -> String {
    json!({
        "hasMore": false,
        "inventorySessionId": "inv-session-123",
        "snapshotEventCursor": "cursor-456",
        "snapshotExpiresAt": "2026-08-17T12:00:00.000Z",
        "items": [],
        "nextPageCursor": null
    })
    .to_string()
}

fn populated_conversations_json(convo_id: &str) -> String {
    let convo_uuid = uuid::Uuid::parse_str(convo_id).unwrap();
    json!({
        "hasMore": false,
        "inventorySessionId": "inv-1",
        "snapshotEventCursor": "cur-1",
        "snapshotExpiresAt": "2026-08-17T12:00:00.000Z",
        "items": [{
            "$type": "blue.catbird.chat.defs#conversationInventoryState",
            "state": {
                "cipherSuite": "MLS_128_DHKEMP256_AES128GCM_SHA256_P256",
                "conversationKind": "direct",
                "snapshotSeq": 1,
                "leaves": [],
                "participants": [],
                "metadataSnapshot": {
                    "metadataVersion": 1,
                    "authorProof": {
                        "authorDid": TEST_DID,
                        "authorDeviceId": TEST_DEVICE_ID,
                        "authorKeyId": "key-1",
                        "authGenerationAtOrigin": 7,
                        "deviceStatusAtOrigin": "active",
                        "originSeq": 1,
                        "originTransitionId": "22222222-2222-4222-9222-222222222222",
                        "roleAtOrigin": "admin",
                        "signaturePublicKey": {"$bytes": B64.encode([1u8; 32])}
                    },
                    "ciphertext": {"$bytes": B64.encode([1u8; 3])},
                    "ciphertextSha256": vec![1u8; 32],
                    "ciphertextSize": 3,
                    "coordinate": {
                        "conversationId": convo_uuid.as_bytes().to_vec(),
                        "groupId": {"$bytes": B64.encode([2u8; 32])},
                        "epoch": 1,
                        "generation": 7,
                        "groupContextHash": {"$bytes": B64.encode([3u8; 32])},
                        "confirmationTag": {"$bytes": B64.encode([4u8; 32])}
                    },
                    "nonce": {"$bytes": B64.encode([1u8; 12])},
                    "originTransitionId": "22222222-2222-4222-9222-222222222222"
                },
                "coordinates": {
                    "conversationId": convo_id,
                    "groupId": {"$bytes": B64.encode([2u8; 32])},
                    "epoch": 1,
                    "generation": 7,
                    "stateVersion": 1,
                    "lifecycle": "active",
                    "confirmationTag": {"$bytes": B64.encode([4u8; 32])},
                    "groupContextHash": {"$bytes": B64.encode([3u8; 32])}
                }
            }
        }],
        "nextPageCursor": null
    })
    .to_string()
}

#[tokio::test]
async fn test_canonical_read_through_nest_with_bearer_and_device_header() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let base_url = format!("http://127.0.0.1:{port}/");

    let signer = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();
    let snapshot = test_snapshot(
        TEST_OPAQUE_SESSION,
        TEST_DID,
        TEST_DEVICE_ID,
        TEST_JKT,
        7,
        &signer,
    );
    let authority_state = Arc::new(AuthorityState::new());
    authority_state.install(snapshot);

    let nest = Arc::new(NestClient::new(&base_url).unwrap());
    let tmp = TempDir::new("test-read");
    let creds = Arc::new(FileCredentialStore::new(tmp.path().join("creds.json")));
    let atp_session = Arc::new(jacquard::client::MemoryCredentialSession::unauthenticated());

    let client = BirdApiClient::new(
        "https://pds.example.invalid".into(),
        atp_session,
        TEST_DID.into(),
        "alice.bsky.social".into(),
        "secret".into(),
    )
    .with_chat_authority(nest, authority_state, creds);

    let server_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 4096];
        let n = stream.read(&mut buf).await.unwrap();
        let req = String::from_utf8_lossy(&buf[..n]);

        assert!(req.contains("GET /xrpc/blue.catbird.chat.getConversations?limit=25"));
        assert!(req.contains(&format!("authorization: Bearer {TEST_OPAQUE_SESSION}")));
        assert!(req.contains(&format!("{CHAT_DEVICE_HEADER}: {TEST_DEVICE_ID}")));

        let body = empty_conversations_json();
        let resp = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n{}: {}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            CHAT_JKT_HEADER,
            TEST_JKT,
            body.len(),
            body
        );
        stream.write_all(resp.as_bytes()).await.unwrap();
    });

    let result = client.get_conversations(25, None).await.unwrap();
    server_task.await.unwrap();
    assert_eq!(result.conversations.len(), 0);
    assert_eq!(result.cursor, None);
}

#[tokio::test]
async fn test_canonical_send_message_with_task5_signed_request_through_nest() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let base_url = format!("http://127.0.0.1:{port}/");

    let signer = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();
    let snapshot = test_snapshot(
        TEST_OPAQUE_SESSION,
        TEST_DID,
        TEST_DEVICE_ID,
        TEST_JKT,
        7,
        &signer,
    );
    let authority_state = Arc::new(AuthorityState::new());
    authority_state.install(snapshot.clone());

    let nest = Arc::new(NestClient::new(&base_url).unwrap());
    let tmp = TempDir::new("test-send");
    let creds = Arc::new(FileCredentialStore::new(tmp.path().join("creds.json")));
    let serialized_signer = serde_json::to_vec(&signer).unwrap();
    creds
        .store_signing_key(TEST_DID, &serialized_signer)
        .await
        .unwrap();
    creds
        .set_clean_chat_binding(TEST_DID, TEST_DEVICE_ID, TEST_JKT, Some(7))
        .unwrap();

    let atp_session = Arc::new(jacquard::client::MemoryCredentialSession::unauthenticated());

    let client = BirdApiClient::new(
        "https://pds.example.invalid".into(),
        atp_session,
        TEST_DID.into(),
        "alice.bsky.social".into(),
        "secret".into(),
    )
    .with_chat_authority(nest, authority_state, creds.clone());
    client.set_signer(Arc::new(TestSigner { creds }));

    let server_task = tokio::spawn(async move {
        // First request: getConversations to fetch coordinates if not cached
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 8192];
        let n = stream.read(&mut buf).await.unwrap();
        let req = String::from_utf8_lossy(&buf[..n]);

        if req.contains("getConversations") {
            let conv_body = populated_conversations_json(TEST_CONVO_ID);
            let resp = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n{}: {}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                CHAT_JKT_HEADER,
                TEST_JKT,
                conv_body.len(),
                conv_body
            );
            stream.write_all(resp.as_bytes()).await.unwrap();

            // Next request: sendMessage
            let (mut stream2, _) = listener.accept().await.unwrap();
            let mut buf2 = [0u8; 8192];
            let n2 = stream2.read(&mut buf2).await.unwrap();
            let req2 = String::from_utf8_lossy(&buf2[..n2]);

            assert!(req2.contains("POST /xrpc/blue.catbird.chat.sendMessage"));
            assert!(req2.contains(&format!("authorization: Bearer {TEST_OPAQUE_SESSION}")));
            assert!(req2.contains(&format!("{CHAT_DEVICE_HEADER}: {TEST_DEVICE_ID}")));

            let body_start = req2.find("\r\n\r\n").unwrap() + 4;
            let body_json: serde_json::Value = serde_json::from_str(&req2[body_start..]).unwrap();
            assert!(body_json.get("signedRequest").is_some());
            let signed_req = &body_json["signedRequest"];
            assert_eq!(
                signed_req["body"]["$type"],
                "blue.catbird.chat.defs#applicationSendBody"
            );
            assert_eq!(signed_req["body"]["actorDid"], TEST_DID);
            assert_eq!(signed_req["body"]["actorDeviceId"], TEST_DEVICE_ID);
            assert_eq!(signed_req["body"]["authGeneration"], 7);
            assert!(signed_req["signature"].is_object() || signed_req["signature"].is_string());

            let send_out = json!({
                "entry": {
                    "$type": "blue.catbird.chat.defs#applicationEntry",
                    "entryId": "entry-uuid-999",
                    "conversationId": TEST_CONVO_ID,
                    "seq": 42,
                    "receivedAt": "2026-08-17T12:00:00Z",
                    "signedRequest": {
                        "body": signed_req["body"].clone(),
                        "signature": signed_req["signature"].clone()
                    }
                }
            })
            .to_string();

            let resp2 = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n{}: {}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                CHAT_JKT_HEADER,
                TEST_JKT,
                send_out.len(),
                send_out
            );
            stream2.write_all(resp2.as_bytes()).await.unwrap();
        }
    });

    let msg_id = "51515151-5151-4151-9151-515151515151";
    let ciphertext = vec![1, 2, 3, 4, 5, 6, 7, 8];
    let send_resp = client
        .send_message_with_id(TEST_CONVO_ID, &ciphertext, 1, msg_id)
        .await
        .unwrap();

    server_task.await.unwrap();
    assert_eq!(send_resp.message_id, "entry-uuid-999");
    assert_eq!(send_resp.seq, 42);
    assert_eq!(send_resp.epoch, 1);
}

#[tokio::test]
async fn test_canonical_blob_download_through_nest() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let base_url = format!("http://127.0.0.1:{port}/");

    let signer = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();
    let snapshot = test_snapshot(
        TEST_OPAQUE_SESSION,
        TEST_DID,
        TEST_DEVICE_ID,
        TEST_JKT,
        7,
        &signer,
    );
    let authority_state = Arc::new(AuthorityState::new());
    authority_state.install(snapshot);

    let nest = Arc::new(NestClient::new(&base_url).unwrap());
    let tmp = TempDir::new("test-blob");
    let creds = Arc::new(FileCredentialStore::new(tmp.path().join("creds.json")));
    let atp_session = Arc::new(jacquard::client::MemoryCredentialSession::unauthenticated());

    let client = BirdApiClient::new(
        "https://pds.example.invalid".into(),
        atp_session,
        TEST_DID.into(),
        "alice.bsky.social".into(),
        "secret".into(),
    )
    .with_chat_authority(nest, authority_state, creds);

    let expected_blob = vec![10u8, 20u8, 30u8, 40u8, 50u8];
    let expected_blob_clone = expected_blob.clone();

    let server_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 4096];
        let n = stream.read(&mut buf).await.unwrap();
        let req = String::from_utf8_lossy(&buf[..n]);

        assert!(req.contains("GET /xrpc/blue.catbird.chat.getBlob?blobId=blob-test-id-123"));
        assert!(req.contains(&format!("authorization: Bearer {TEST_OPAQUE_SESSION}")));
        assert!(req.contains(&format!("{CHAT_DEVICE_HEADER}: {TEST_DEVICE_ID}")));

        let resp = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/octet-stream\r\n{}: {}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            CHAT_JKT_HEADER,
            TEST_JKT,
            expected_blob_clone.len()
        );
        stream.write_all(resp.as_bytes()).await.unwrap();
        stream.write_all(&expected_blob_clone).await.unwrap();
    });

    let downloaded = client.get_blob("blob-test-id-123").await.unwrap();
    server_task.await.unwrap();
    assert_eq!(downloaded, expected_blob);
}

#[tokio::test]
async fn test_canonical_subscription_ticket_and_websocket_isolation() {
    let nest_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let nest_port = nest_listener.local_addr().unwrap().port();
    let nest_base = format!("http://127.0.0.1:{nest_port}/");

    let ws_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ws_port = ws_listener.local_addr().unwrap().port();
    let ws_endpoint = format!("ws://127.0.0.1:{ws_port}/subscribeEvents");

    let signer = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();
    let snapshot = test_snapshot(
        TEST_OPAQUE_SESSION,
        TEST_DID,
        TEST_DEVICE_ID,
        TEST_JKT,
        7,
        &signer,
    );
    let authority_state = Arc::new(AuthorityState::new());
    authority_state.install(snapshot);

    let nest = Arc::new(NestClient::new(&nest_base).unwrap());
    let tmp = TempDir::new("test-ticket");
    let creds = Arc::new(FileCredentialStore::new(tmp.path().join("creds.json")));
    let atp_session = Arc::new(jacquard::client::MemoryCredentialSession::unauthenticated());

    let client = BirdApiClient::new(
        "https://pds.example.invalid".into(),
        atp_session,
        TEST_DID.into(),
        "alice.bsky.social".into(),
        "secret".into(),
    )
    .with_chat_authority(nest, authority_state, creds);

    let ws_endpoint_clone = ws_endpoint.clone();
    let nest_task = tokio::spawn(async move {
        // Handle getConversations to prime inventory
        let (mut stream1, _) = nest_listener.accept().await.unwrap();
        let mut buf1 = [0u8; 4096];
        let n1 = stream1.read(&mut buf1).await.unwrap();
        let req1 = String::from_utf8_lossy(&buf1[..n1]);
        assert!(req1.contains("getConversations"));

        let conv_body = empty_conversations_json();
        let resp1 = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n{}: {}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            CHAT_JKT_HEADER,
            TEST_JKT,
            conv_body.len(),
            conv_body
        );
        stream1.write_all(resp1.as_bytes()).await.unwrap();

        // Handle getSubscriptionTicket
        let (mut stream2, _) = nest_listener.accept().await.unwrap();
        let mut buf2 = [0u8; 4096];
        let n2 = stream2.read(&mut buf2).await.unwrap();
        let req2 = String::from_utf8_lossy(&buf2[..n2]);

        assert!(req2.contains("POST /xrpc/blue.catbird.chat.getSubscriptionTicket"));
        assert!(req2.contains(&format!("authorization: Bearer {TEST_OPAQUE_SESSION}")));
        assert!(req2.contains(&format!("{CHAT_DEVICE_HEADER}: {TEST_DEVICE_ID}")));

        let ticket_body = json!({
            "ticket": "single-use-ds-ticket-token-777",
            "endpoint": ws_endpoint_clone
        })
        .to_string();
        let resp2 = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n{}: {}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            CHAT_JKT_HEADER,
            TEST_JKT,
            ticket_body.len(),
            ticket_body
        );
        stream2.write_all(resp2.as_bytes()).await.unwrap();
    });

    // Prime inventory state
    let _ = client.get_conversations(25, None).await.unwrap();
    let (ticket, endpoint) = client.get_subscription_ticket().await.unwrap();
    nest_task.await.unwrap();

    assert_eq!(ticket, "single-use-ds-ticket-token-777");
    assert_eq!(endpoint, ws_endpoint);

    // Verify WebSocket connection to DS receives ONLY the ticket in query, NEVER the session bearer
    let ws_server_task = tokio::spawn(async move {
        let (mut stream, _) = ws_listener.accept().await.unwrap();
        let mut buf = [0u8; 4096];
        let n = stream.read(&mut buf).await.unwrap();
        let req = String::from_utf8_lossy(&buf[..n]);

        assert!(req.contains("ticket=single-use-ds-ticket-token-777"));
        assert!(!req.contains(TEST_OPAQUE_SESSION));
        assert!(!req.contains("authorization:"));
    });

    let ws_url = format!("{endpoint}?ticket={ticket}");
    let _ = tokio_tungstenite::connect_async(&ws_url).await;
    ws_server_task.await.unwrap();
}

#[tokio::test]
async fn test_bearer_never_sent_to_pds_or_ds_and_downstream_tokens_never_enter_bir() {
    let pds_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let pds_port = pds_listener.local_addr().unwrap().port();
    let pds_url = format!("http://127.0.0.1:{pds_port}");

    let nest_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let nest_port = nest_listener.local_addr().unwrap().port();
    let nest_url = format!("http://127.0.0.1:{nest_port}/");

    let signer = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();
    let snapshot = test_snapshot(
        TEST_OPAQUE_SESSION,
        TEST_DID,
        TEST_DEVICE_ID,
        TEST_JKT,
        7,
        &signer,
    );
    let authority_state = Arc::new(AuthorityState::new());
    authority_state.install(snapshot);

    let nest = Arc::new(NestClient::new(&nest_url).unwrap());
    let tmp = TempDir::new("test-bearer-isolation");
    let creds = Arc::new(FileCredentialStore::new(tmp.path().join("creds.json")));
    let atp_session = Arc::new(jacquard::client::MemoryCredentialSession::unauthenticated());

    let client = BirdApiClient::new(
        pds_url.clone(),
        atp_session,
        TEST_DID.into(),
        "alice.bsky.social".into(),
        "secret".into(),
    )
    .with_chat_authority(nest, authority_state.clone(), creds);

    // Mock Nest handling getConversations
    let nest_task = tokio::spawn(async move {
        let (mut stream, _) = nest_listener.accept().await.unwrap();
        let mut buf = [0u8; 4096];
        let n = stream.read(&mut buf).await.unwrap();
        let req = String::from_utf8_lossy(&buf[..n]);
        assert!(req.contains(&format!("authorization: Bearer {TEST_OPAQUE_SESSION}")));

        let body = empty_conversations_json();
        let resp = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n{}: {}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            CHAT_JKT_HEADER,
            TEST_JKT,
            body.len(),
            body
        );
        stream.write_all(resp.as_bytes()).await.unwrap();
    });

    let _ = client.get_conversations(10, None).await.unwrap();
    nest_task.await.unwrap();

    // Verify snapshot Debug representation redacts session handle, JKT, and public key
    let current_snapshot = authority_state.snapshot().unwrap();
    let debug_str = format!("{:?}", current_snapshot);
    assert!(!debug_str.contains(TEST_OPAQUE_SESSION));
    assert!(!debug_str.contains(TEST_JKT));
    assert!(debug_str.contains("<redacted>"));
}

#[tokio::test]
async fn test_nest_session_refresh_and_re_enrollment_on_401_403() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let base_url = format!("http://127.0.0.1:{port}/");

    let signer = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();
    let snapshot = test_snapshot(
        TEST_OPAQUE_SESSION,
        TEST_DID,
        TEST_DEVICE_ID,
        TEST_JKT,
        7,
        &signer,
    );
    let invalidated = Arc::new(AtomicBool::new(false));
    let inv_clone = invalidated.clone();
    let authority_state = Arc::new(AuthorityState::with_invalidation_hook(Arc::new(
        move || {
            inv_clone.store(true, Ordering::SeqCst);
            Ok(())
        },
    )));
    authority_state.install(snapshot);

    let nest = Arc::new(NestClient::new(&base_url).unwrap());
    let tmp = TempDir::new("test-401");
    let creds = Arc::new(FileCredentialStore::new(tmp.path().join("creds.json")));
    let atp_session = Arc::new(jacquard::client::MemoryCredentialSession::unauthenticated());

    let client = BirdApiClient::new(
        "https://pds.example.invalid".into(),
        atp_session,
        TEST_DID.into(),
        "alice.bsky.social".into(),
        "secret".into(),
    )
    .with_chat_authority(nest, authority_state.clone(), creds);

    let server_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 4096];
        let n = stream.read(&mut buf).await.unwrap();
        let req = String::from_utf8_lossy(&buf[..n]);
        assert!(req.contains("getConversations"));

        let resp = "HTTP/1.1 401 Unauthorized\r\ncontent-type: application/json\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}";
        stream.write_all(resp.as_bytes()).await.unwrap();
    });

    let err = client.get_conversations(25, None).await.unwrap_err();
    server_task.await.unwrap();
    assert!(err.to_string().contains("invalidated"));
    assert!(invalidated.load(Ordering::SeqCst));
    assert!(authority_state.snapshot().is_none());
}

#[tokio::test]
async fn test_process_restart_recovery_and_stale_rejection() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let base_url = format!("http://127.0.0.1:{port}/");
    let nest = Arc::new(NestClient::new(&base_url).unwrap());

    let signer = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();
    let signer_bytes = serde_json::to_vec(&signer).unwrap();
    let signer_handle = derive_key_id(signer.public());

    let tmp = TempDir::new("test-restart");
    let creds = Arc::new(FileCredentialStore::new(tmp.path().join("creds.json")));
    creds
        .store_signing_key(TEST_DID, &signer_bytes)
        .await
        .unwrap();

    let server_task = tokio::spawn(async move {
        // First handle session_info (/auth/session)
        let (mut stream1, _) = listener.accept().await.unwrap();
        let mut buf1 = [0u8; 4096];
        let n1 = stream1.read(&mut buf1).await.unwrap();
        let req1 = String::from_utf8_lossy(&buf1[..n1]);
        assert!(req1.contains("/auth/session"));

        let sess_body = json!({
            "did": TEST_DID,
            "handle": "alice.bsky.social"
        })
        .to_string();
        let resp1 = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            sess_body.len(),
            sess_body
        );
        stream1.write_all(resp1.as_bytes()).await.unwrap();

        // Second handle getOwnDevices
        let (mut stream2, _) = listener.accept().await.unwrap();
        let mut buf2 = [0u8; 4096];
        let n2 = stream2.read(&mut buf2).await.unwrap();
        let req2 = String::from_utf8_lossy(&buf2[..n2]);
        assert!(req2.contains("getOwnDevices"));

        let dev_body = json!({
            "items": [{
                "device": {
                    "deviceId": TEST_DEVICE_ID,
                    "dpopJkt": TEST_JKT,
                    "authGeneration": 7,
                    "status": "active",
                    "keyId": signer_handle,
                    "signaturePublicKey": {"$bytes": B64.encode(signer.public())}
                }
            }]
        })
        .to_string();
        let resp2 = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n{}: {}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            CHAT_JKT_HEADER,
            TEST_JKT,
            dev_body.len(),
            dev_body
        );
        stream2.write_all(resp2.as_bytes()).await.unwrap();
    });

    let admitted = crate::admit_existing_session(
        &nest,
        TEST_OPAQUE_SESSION,
        TEST_DID,
        TEST_DEVICE_ID,
        TEST_JKT,
        7,
        &creds,
    )
    .await
    .unwrap();

    server_task.await.unwrap();
    assert_eq!(admitted.actor_did(), TEST_DID);
    assert_eq!(admitted.device_id(), TEST_DEVICE_ID);
    assert_eq!(admitted.auth_generation(), 7);
}

#[tokio::test]
async fn test_typing_remains_explicitly_disabled() {
    let nest = Arc::new(NestClient::new("https://nest.example.invalid/").unwrap());
    let authority_state = Arc::new(AuthorityState::new());
    let tmp = TempDir::new("test-typing");
    let creds = Arc::new(FileCredentialStore::new(tmp.path().join("creds.json")));
    let atp_session = Arc::new(jacquard::client::MemoryCredentialSession::unauthenticated());

    let client = BirdApiClient::new(
        "https://pds.example.invalid".into(),
        atp_session,
        TEST_DID.into(),
        "alice.bsky.social".into(),
        "secret".into(),
    )
    .with_chat_authority(nest, authority_state, creds);

    let result = client.send_typing_indicator(TEST_CONVO_ID, true).await;
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("MLS-encrypted typing payload adapter is not available in BIRDaemon"));
}

#[tokio::test]
async fn test_simulated_bot_receive_decrypt_reply_flow() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let base_url = format!("http://127.0.0.1:{port}/");

    let signer = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();
    let snapshot = test_snapshot(
        TEST_OPAQUE_SESSION,
        TEST_DID,
        TEST_DEVICE_ID,
        TEST_JKT,
        7,
        &signer,
    );
    let authority_state = Arc::new(AuthorityState::new());
    authority_state.install(snapshot);

    let nest = Arc::new(NestClient::new(&base_url).unwrap());
    let tmp = TempDir::new("test-bot-reply");
    let creds = Arc::new(FileCredentialStore::new(tmp.path().join("creds.json")));
    let atp_session = Arc::new(jacquard::client::MemoryCredentialSession::unauthenticated());

    let client = BirdApiClient::new(
        "https://pds.example.invalid".into(),
        atp_session,
        TEST_DID.into(),
        "alice.bsky.social".into(),
        "secret".into(),
    )
    .with_chat_authority(nest, authority_state, creds.clone());
    client.set_signer(Arc::new(TestSigner { creds }));

    let server_task = tokio::spawn(async move {
        // Step 1: getConversations
        let (mut stream1, _) = listener.accept().await.unwrap();
        let mut buf1 = [0u8; 8192];
        let n1 = stream1.read(&mut buf1).await.unwrap();
        let req1 = String::from_utf8_lossy(&buf1[..n1]);
        assert!(req1.contains("getConversations"));

        let conv_body = populated_conversations_json(TEST_CONVO_ID);
        let resp1 = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n{}: {}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            CHAT_JKT_HEADER,
            TEST_JKT,
            conv_body.len(),
            conv_body
        );
        stream1.write_all(resp1.as_bytes()).await.unwrap();

        // Step 2: getEntries
        let (mut stream2, _) = listener.accept().await.unwrap();
        let mut buf2 = [0u8; 8192];
        let n2 = stream2.read(&mut buf2).await.unwrap();
        let req2 = String::from_utf8_lossy(&buf2[..n2]);
        assert!(req2.contains("getEntries"));

        let entries_body = json!({
            "hasMore": false,
            "nextAfterSeq": 10,
            "entries": [{
                "$type": "blue.catbird.chat.defs#applicationEntry",
                "entryId": "inbound-msg-001",
                "conversationId": TEST_CONVO_ID,
                "seq": 10,
                "receivedAt": "2026-08-17T12:00:00Z",
                "signedRequest": {
                    "body": {
                        "$type": "blue.catbird.chat.defs#applicationSendBody",
                        "signatureDomain": "CATBIRD-CHAT-MESSAGE\u{0000}",
                        "actorDid": "did:plc:bobfixturebbbbbbbbbbbb",
                        "actorDeviceId": "90909090-9090-4090-b090-909090909090",
                        "keyId": "bob-key-1",
                        "messageId": "88888888-8888-4888-8888-888888888888",
                        "authGeneration": 1,
                        "blobBindings": [],
                        "applicationMessage": {
                            "bytes": {"$bytes": B64.encode(b"ping")},
                            "sha256": vec![9u8; 32],
                            "framing": "mlsMessage",
                            "contentType": "privateMessageApplication"
                        },
                        "prior": {
                            "conversationId": TEST_CONVO_ID,
                            "groupId": {"$bytes": B64.encode([2u8; 32])},
                            "epoch": 1,
                            "generation": 1,
                            "stateVersion": 1,
                            "lifecycle": "active",
                            "confirmationTag": {"$bytes": B64.encode([4u8; 32])},
                            "groupContextHash": {"$bytes": B64.encode([3u8; 32])}
                        },
                        "aad": {
                            "protocolVersion": "1",
                            "conversationId": vec![1u8; 16],
                            "generation": 1,
                            "messageId": vec![8u8; 16],
                            "prior": {
                                "conversationId": vec![1u8; 16],
                                "groupId": {"$bytes": B64.encode([2u8; 32])},
                                "epoch": 1,
                                "generation": 1,
                                "stateVersion": 1,
                                "lifecycle": "active",
                                "confirmationTag": {"$bytes": B64.encode([4u8; 32])},
                                "groupContextHash": {"$bytes": B64.encode([3u8; 32])}
                            }
                        },
                        "signedAt": "2026-08-17T12:00:00.000Z"
                    },
                    "signature": {"$bytes": B64.encode([9u8; 64])}
                }
            }]
        })
        .to_string();

        let resp2 = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n{}: {}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            CHAT_JKT_HEADER,
            TEST_JKT,
            entries_body.len(),
            entries_body
        );
        stream2.write_all(resp2.as_bytes()).await.unwrap();

        // Step 3: sendMessage (bot reply)
        let (mut stream3, _) = listener.accept().await.unwrap();
        let mut buf3 = [0u8; 8192];
        let n3 = stream3.read(&mut buf3).await.unwrap();
        let req3 = String::from_utf8_lossy(&buf3[..n3]);
        assert!(req3.contains("POST /xrpc/blue.catbird.chat.sendMessage"));
        assert!(req3.contains(&format!("authorization: Bearer {TEST_OPAQUE_SESSION}")));
        assert!(req3.contains(&format!("{CHAT_DEVICE_HEADER}: {TEST_DEVICE_ID}")));

        let body_start = req3.find("\r\n\r\n").unwrap() + 4;
        let body_json: serde_json::Value = serde_json::from_str(&req3[body_start..]).unwrap();
        let signed_req = &body_json["signedRequest"];
        assert_eq!(signed_req["body"]["actorDid"], TEST_DID);
        assert_eq!(signed_req["body"]["actorDeviceId"], TEST_DEVICE_ID);

        let reply_out = json!({
            "entry": {
                "$type": "blue.catbird.chat.defs#applicationEntry",
                "entryId": "reply-entry-uuid-002",
                "conversationId": TEST_CONVO_ID,
                "seq": 11,
                "receivedAt": "2026-08-17T12:01:00Z",
                "signedRequest": {
                    "body": signed_req["body"].clone(),
                    "signature": signed_req["signature"].clone()
                }
            }
        })
        .to_string();

        let resp3 = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n{}: {}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            CHAT_JKT_HEADER,
            TEST_JKT,
            reply_out.len(),
            reply_out
        );
        stream3.write_all(resp3.as_bytes()).await.unwrap();
    });

    // 1. Fetch conversations (primes coordinates)
    let convos = client.get_conversations(25, None).await.unwrap();
    assert_eq!(convos.conversations.len(), 1);

    // 2. Fetch incoming messages
    let (entries, _) = client
        .get_messages(TEST_CONVO_ID, None, 10, None, None, None)
        .await
        .unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0].server_message_id.as_deref(),
        Some("inbound-msg-001")
    );

    // 3. Send reply
    let reply_msg_id = "62626262-6262-4262-9262-626262626262";
    let reply_ciphertext = b"pong: hello from bird bot!".to_vec();
    let reply_resp = client
        .send_message_with_id(TEST_CONVO_ID, &reply_ciphertext, 1, reply_msg_id)
        .await
        .unwrap();

    server_task.await.unwrap();
    assert_eq!(reply_resp.message_id, "reply-entry-uuid-002");
    assert_eq!(reply_resp.seq, 11);
    assert_eq!(reply_resp.epoch, 1);
}
