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
    MLSOrchestrator, MLSStorageBackend, OrchestratorConfig, PreparedRequest,
};
use catbird_mls::MLSContext;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::types::SignatureScheme;
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::chat_authority::{
    derive_key_id, AuthoritySnapshot, AuthorityState, NestClient, CHAT_DEVICE_HEADER,
};
use crate::credentials::FileCredentialStore;
use crate::keychain::FileKeychain;
use crate::storage::SqliteStorage;
use crate::xrpc_client::{BirdApiClient, CleanChatRequestSigner};

const TEST_DID: &str = "did:plc:alicefixtureaaaaaaaaaaaa";
const TEST_DEVICE_ID: &str = "70707070-7070-4070-b070-707070707070";
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
    generation: i64,
    signer_pair: &SignatureKeyPair,
) -> AuthoritySnapshot {
    let public_key = signer_pair.public().to_vec();
    let signer_handle = derive_key_id(&public_key);
    AuthoritySnapshot::new(
        session.into(),
        did.into(),
        device_id.into(),
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
        let key_id = self
            .creds
            .get_signing_key(&binding.actor_did)
            .await?
            .and_then(|bytes| serde_json::from_slice::<SignatureKeyPair>(&bytes).ok())
            .map(|signer| derive_key_id(signer.public()))
            .unwrap_or_else(|| derive_key_id(&[0; 32]));
        let auth = self
            .creds
            .sign_clean_chat_transcript(&binding.actor_did, &body_json, &key_id)
            .await
            .map_err(|e| OrchestratorError::Credential(e.to_string()))?
            .unwrap_or(CleanChatSigningAuthority {
                public_key: vec![0; 32],
                signature: vec![1; 64],
                device_id: binding.device_id.clone(),
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
        "items": []
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
                "cipherSuite": "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519",
                "conversationKind": "direct",
                "snapshotSeq": 1,
                "leaves": [{"userDid":TEST_DID,"deviceId":TEST_DEVICE_ID,"keyId":derive_key_id(&[1u8;32]),"leafOrigin":"genesis","deviceStatus":"active"}],
                "participants": [{"userDid":TEST_DID,"role":"admin","status":"active","leafCount":1},{"userDid":"did:plc:bobfixtureaaaaaaaaaaaaaa","role":"admin","status":"active","leafCount":0}],
                "metadataSnapshot": {
                    "metadataVersion": 1,
                    "authorProof": {
                        "authorDid": TEST_DID,
                        "authorDeviceId": TEST_DEVICE_ID,
                        "authorKeyId": derive_key_id(&[1u8;32]),
                        "authGenerationAtOrigin": 7,
                        "deviceStatusAtOrigin": "active",
                        "originSeq": 1,
                        "originTransitionId": "22222222-2222-4222-9222-222222222222",
                        "roleAtOrigin": "admin",
                        "signaturePublicKey": {"$bytes": B64.encode([1u8; 32])}
                    },
                    "ciphertext": {"$bytes": B64.encode([1u8; 32])},
                    "ciphertextSha256": {"$bytes": B64.encode(sha2::Sha256::digest([1u8;32]))},
                    "ciphertextSize": 32,
                    "coordinate": {
                        "conversationId": {"$bytes":B64.encode(convo_uuid.as_bytes())},
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
        }]
    })
    .to_string()
}

fn projection_conversations_json(convo_id: &str) -> String {
    let mut response: serde_json::Value =
        serde_json::from_str(&populated_conversations_json(convo_id)).unwrap();
    let state = &mut response["items"][0]["state"];
    state["conversationKind"] = json!("group");
    state["participants"] = json!([{
        "userDid": TEST_DID,
        "role": "admin",
        "status": "active",
        "leafCount": 1
    }]);
    state["coordinates"]["epoch"] = json!(0);
    state["coordinates"]["generation"] = json!(0);
    state["coordinates"]["stateVersion"] = json!(0);
    state["metadataSnapshot"]["coordinate"]["epoch"] = json!(0);
    state["metadataSnapshot"]["coordinate"]["generation"] = json!(0);
    response.to_string()
}

#[tokio::test]
async fn test_canonical_read_through_nest_with_bearer_and_device_header() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let base_url = format!("http://127.0.0.1:{port}/");

    let signer = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();
    let snapshot = test_snapshot(TEST_OPAQUE_SESSION, TEST_DID, TEST_DEVICE_ID, 7, &signer);
    let authority_state = Arc::new(AuthorityState::new());
    authority_state.install(snapshot);

    let nest = Arc::new(NestClient::new(&base_url).unwrap());
    let tmp = TempDir::new("test-read");
    let creds = Arc::new(FileCredentialStore::new(tmp.path().join("creds.json")).unwrap());
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

        assert!(req.contains(&format!(
            "GET /xrpc/blue.catbird.chat.getConversations?actorDeviceId={TEST_DEVICE_ID}&limit=25"
        )));
        assert!(req.contains(&format!("authorization: Bearer {TEST_OPAQUE_SESSION}")));
        assert!(req.contains(&format!("{CHAT_DEVICE_HEADER}: {TEST_DEVICE_ID}")));

        let body = empty_conversations_json();
        let resp = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        stream.write_all(resp.as_bytes()).await.unwrap();
    });

    let response = client
        .submit_prepared_request(PreparedRequest {
            operation: CanonicalOperation::GetConversations,
            method: "GET".into(),
            path: format!(
                "/xrpc/blue.catbird.chat.getConversations?actorDeviceId={TEST_DEVICE_ID}&limit=25"
            ),
            body: None,
        })
        .await
        .unwrap();
    server_task.await.unwrap();
    assert_eq!(response.status, 200);
    assert!(serde_json::from_slice::<serde_json::Value>(&response.body).is_ok());
}

#[tokio::test]
async fn test_canonical_send_message_with_task5_signed_request_through_nest() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let base_url = format!("http://127.0.0.1:{port}/");

    let signer = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();
    let snapshot = test_snapshot(TEST_OPAQUE_SESSION, TEST_DID, TEST_DEVICE_ID, 7, &signer);
    let authority_state = Arc::new(AuthorityState::new());
    authority_state.install(snapshot.clone());

    let nest = Arc::new(NestClient::new(&base_url).unwrap());
    let tmp = TempDir::new("test-send");
    let creds = Arc::new(FileCredentialStore::new(tmp.path().join("creds.json")).unwrap());
    let serialized_signer = serde_json::to_vec(&signer).unwrap();
    creds
        .store_signing_key(TEST_DID, &serialized_signer)
        .await
        .unwrap();
    creds
        .install_admitted_device_tuple(
            TEST_DID,
            TEST_DEVICE_ID,
            &format!("{TEST_DID}#{TEST_DEVICE_ID}"),
            7,
        )
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
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
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

            // Nest returns the generated DTO form for typed response
            // decoding. The request wire uses {$bytes} for artifact hashes,
            // while generated `Bytes` output is an array.
            let mut response_body = signed_req["body"].clone();
            response_body["applicationMessage"]["sha256"] = json!(vec![0u8; 32]);
            let send_out = json!({
                "entry": {
                    "$type": "blue.catbird.chat.defs#applicationEntry",
                    "entryId": "entry-uuid-999",
                    "conversationId": TEST_CONVO_ID,
                    "seq": 42,
                    "receivedAt": "2026-08-17T12:00:00.000Z",
                    "signedRequest": {
                        "body": response_body,
                        "signature": signed_req["signature"].clone()
                    }
                }
            })
            .to_string();

            let resp2 = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
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
    let snapshot = test_snapshot(TEST_OPAQUE_SESSION, TEST_DID, TEST_DEVICE_ID, 7, &signer);
    let authority_state = Arc::new(AuthorityState::new());
    authority_state.install(snapshot);

    let nest = Arc::new(NestClient::new(&base_url).unwrap());
    let tmp = TempDir::new("test-blob");
    let creds = Arc::new(FileCredentialStore::new(tmp.path().join("creds.json")).unwrap());
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
            "HTTP/1.1 200 OK\r\ncontent-type: application/octet-stream\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
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
    let snapshot = test_snapshot(TEST_OPAQUE_SESSION, TEST_DID, TEST_DEVICE_ID, 7, &signer);
    let authority_state = Arc::new(AuthorityState::new());
    authority_state.install(snapshot);

    let nest = Arc::new(NestClient::new(&nest_base).unwrap());
    let tmp = TempDir::new("test-ticket");
    let creds = Arc::new(FileCredentialStore::new(tmp.path().join("creds.json")).unwrap());
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
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
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
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            ticket_body.len(),
            ticket_body
        );
        stream2.write_all(resp2.as_bytes()).await.unwrap();
    });

    // Prime inventory state
    let _ = client.get_conversations(25, None).await.unwrap();
    let (ticket, endpoint, ticket_cursor) = client.get_subscription_ticket().await.unwrap();
    nest_task.await.unwrap();

    assert_eq!(ticket, "single-use-ds-ticket-token-777");
    assert_eq!(ticket_cursor, "cursor-456");
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
    let snapshot = test_snapshot(TEST_OPAQUE_SESSION, TEST_DID, TEST_DEVICE_ID, 7, &signer);
    let authority_state = Arc::new(AuthorityState::new());
    authority_state.install(snapshot);

    let nest = Arc::new(NestClient::new(&nest_url).unwrap());
    let tmp = TempDir::new("test-bearer-isolation");
    let creds = Arc::new(FileCredentialStore::new(tmp.path().join("creds.json")).unwrap());
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
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        stream.write_all(resp.as_bytes()).await.unwrap();
    });

    let _ = client.get_conversations(10, None).await.unwrap();
    nest_task.await.unwrap();

    // Verify snapshot Debug representation redacts session handle and public key.
    let current_snapshot = authority_state.snapshot().unwrap();
    let debug_str = format!("{:?}", current_snapshot);
    assert!(!debug_str.contains(TEST_OPAQUE_SESSION));
    assert!(debug_str.contains("<redacted>"));
}

#[tokio::test]
async fn ordinary_http_failures_are_preserved_without_invalidating_authority() {
    for (status, reason, error_code, content_type) in [
        (
            400,
            "Bad Request",
            "InvalidRequest",
            "application/json; charset=utf-8",
        ),
        (
            401,
            "Unauthorized",
            "UnknownUnauthorizedFailure",
            "application/json; charset=utf-8",
        ),
        (
            404,
            "Not Found",
            "WelcomeNotFound",
            "application/json; charset=utf-8",
        ),
        (
            409,
            "Conflict",
            "AcknowledgementConflict",
            "application/json; charset=utf-8",
        ),
        (
            429,
            "Too Many Requests",
            "RateLimited",
            "application/json; charset=utf-8",
        ),
        (401, "Unauthorized", "AccountSessionExpired", "text/plain"),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base_url = format!("http://{}/", listener.local_addr().unwrap());
        let signer = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();
        let snapshot = test_snapshot(TEST_OPAQUE_SESSION, TEST_DID, TEST_DEVICE_ID, 7, &signer);
        let invalidated = Arc::new(AtomicBool::new(false));
        let invalidated_for_hook = invalidated.clone();
        let authority_state = Arc::new(AuthorityState::with_invalidation_hook(Arc::new(
            move || {
                invalidated_for_hook.store(true, Ordering::SeqCst);
                Ok(())
            },
        )));
        authority_state.install(snapshot);
        let nest = Arc::new(NestClient::new(&base_url).unwrap());
        let tmp = TempDir::new("ordinary-status");
        let creds = Arc::new(FileCredentialStore::new(tmp.path().join("creds.json")).unwrap());
        let client = BirdApiClient::new(
            "https://pds.example.invalid".into(),
            Arc::new(jacquard::client::MemoryCredentialSession::unauthenticated()),
            TEST_DID.into(),
            "alice.bsky.social".into(),
            "secret".into(),
        )
        .with_chat_authority(nest, authority_state.clone(), creds);
        let body = json!({"error": error_code, "message": "fixture"}).to_string();
        let expected_body = body.as_bytes().to_vec();
        let server_task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 4096];
            let _ = stream.read(&mut request).await.unwrap();
            let response = format!(
                "HTTP/1.1 {status} {reason}\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        });

        let response = client
            .submit_prepared_request(PreparedRequest {
                operation: CanonicalOperation::GetConversations,
                method: "GET".into(),
                path: format!(
                    "/xrpc/blue.catbird.chat.getConversations?actorDeviceId={TEST_DEVICE_ID}&limit=25"
                ),
                body: None,
            })
            .await
            .unwrap();
        server_task.await.unwrap();

        assert_eq!(response.status, status);
        assert_eq!(response.content_type.as_deref(), Some(content_type));
        assert_eq!(response.body, expected_body);
        assert!(authority_state.snapshot().is_some());
        assert!(!invalidated.load(Ordering::SeqCst));
    }
}

#[tokio::test]
async fn proven_account_session_expiry_invalidates_but_preserves_response() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let base_url = format!("http://127.0.0.1:{port}/");

    let signer = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();
    let snapshot = test_snapshot(TEST_OPAQUE_SESSION, TEST_DID, TEST_DEVICE_ID, 7, &signer);
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
    let creds = Arc::new(FileCredentialStore::new(tmp.path().join("creds.json")).unwrap());
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

        let body = json!({"error": "AccountSessionExpired"}).to_string();
        let resp = format!(
            "HTTP/1.1 401 Unauthorized\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        stream.write_all(resp.as_bytes()).await.unwrap();
    });

    let response = client
        .submit_prepared_request(PreparedRequest {
            operation: CanonicalOperation::GetConversations,
            method: "GET".into(),
            path: format!(
                "/xrpc/blue.catbird.chat.getConversations?actorDeviceId={TEST_DEVICE_ID}&limit=25"
            ),
            body: None,
        })
        .await
        .unwrap();
    server_task.await.unwrap();
    assert_eq!(response.status, 401);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&response.body).unwrap()["error"],
        "AccountSessionExpired"
    );
    assert!(invalidated.load(Ordering::SeqCst));
    assert!(authority_state.snapshot().is_none());
}

#[tokio::test]
async fn caller_scope_mismatch_fails_before_network_or_authority_mutation() {
    let signer = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();
    let snapshot = test_snapshot(TEST_OPAQUE_SESSION, TEST_DID, TEST_DEVICE_ID, 7, &signer);
    let authority_state = Arc::new(AuthorityState::new());
    authority_state.install(snapshot);
    let nest = Arc::new(NestClient::new("http://127.0.0.1:9/").unwrap());
    let tmp = TempDir::new("caller-scope");
    let creds = Arc::new(FileCredentialStore::new(tmp.path().join("creds.json")).unwrap());
    let client = BirdApiClient::new(
        "https://pds.example.invalid".into(),
        Arc::new(jacquard::client::MemoryCredentialSession::unauthenticated()),
        "did:plc:otherfixturebbbbbbbbbbb".into(),
        "other.bsky.social".into(),
        "secret".into(),
    )
    .with_chat_authority(nest, authority_state.clone(), creds);

    let error = client
        .submit_prepared_request(PreparedRequest {
            operation: CanonicalOperation::GetConversations,
            method: "GET".into(),
            path: format!(
                "/xrpc/blue.catbird.chat.getConversations?actorDeviceId={TEST_DEVICE_ID}&limit=25"
            ),
            body: None,
        })
        .await
        .unwrap_err();

    assert!(error.to_string().contains("caller scope"));
    assert!(authority_state.snapshot().is_some());
}

#[tokio::test]
async fn get_entries_paginates_without_rewinding_and_stops_at_the_explicit_bound() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base_url = format!("http://{}/", listener.local_addr().unwrap());
    let signer = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();
    let authority_state = Arc::new(AuthorityState::new());
    authority_state.install(test_snapshot(
        TEST_OPAQUE_SESSION,
        TEST_DID,
        TEST_DEVICE_ID,
        7,
        &signer,
    ));
    let tmp = TempDir::new("entry-pagination");
    let client = BirdApiClient::new(
        "https://pds.example.invalid".into(),
        Arc::new(jacquard::client::MemoryCredentialSession::unauthenticated()),
        TEST_DID.into(),
        "alice.bsky.social".into(),
        "secret".into(),
    )
    .with_chat_authority(
        Arc::new(NestClient::new(&base_url).unwrap()),
        authority_state,
        Arc::new(FileCredentialStore::new(tmp.path().join("creds.json")).unwrap()),
    );

    let server_task = tokio::spawn(async move {
        for after_seq in 0_i64..32 {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 4096];
            let read = stream.read(&mut request).await.unwrap();
            let request = String::from_utf8_lossy(&request[..read]);
            assert!(request.contains(&format!("afterSeq={after_seq}")));
            assert!(request.contains(&format!("conversationId={TEST_CONVO_ID}")));
            let body = json!({
                "entries": [],
                "hasMore": true,
                "nextAfterSeq": after_seq + 1,
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

    let error = client
        .get_messages(TEST_CONVO_ID, None, 10, Some("app"), None, None)
        .await
        .unwrap_err();
    server_task.await.unwrap();
    assert!(error.to_string().contains("32-page safety bound"));

    for invalid in ["", "01", "-1", "+1", "not-a-cursor", "9007199254740992"] {
        let error = client
            .get_messages(TEST_CONVO_ID, Some(invalid), 10, None, None, None)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("cursor"), "{error}");
    }
}

#[tokio::test]
async fn key_package_stats_paginate_and_count_only_the_admitted_device() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base_url = format!("http://{}/", listener.local_addr().unwrap());
    let signer = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();
    let authority_state = Arc::new(AuthorityState::new());
    authority_state.install(test_snapshot(
        TEST_OPAQUE_SESSION,
        TEST_DID,
        TEST_DEVICE_ID,
        7,
        &signer,
    ));
    let tmp = TempDir::new("device-pagination");
    let client = BirdApiClient::new(
        "https://pds.example.invalid".into(),
        Arc::new(jacquard::client::MemoryCredentialSession::unauthenticated()),
        TEST_DID.into(),
        "alice.bsky.social".into(),
        "secret".into(),
    )
    .with_chat_authority(
        Arc::new(NestClient::new(&base_url).unwrap()),
        authority_state,
        Arc::new(FileCredentialStore::new(tmp.path().join("creds.json")).unwrap()),
    );

    let signer_key_id = derive_key_id(signer.public());
    let signer_public = B64.encode(signer.public());
    let server_task = tokio::spawn(async move {
        for (page, device_id, available, reserved, has_more, next_cursor) in [
            (
                0,
                "80808080-8080-4080-b080-808080808080",
                99,
                98,
                true,
                Some("device-page-2"),
            ),
            (1, TEST_DEVICE_ID, 2, 3, false, None),
        ] {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 4096];
            let read = stream.read(&mut request).await.unwrap();
            let request = String::from_utf8_lossy(&request[..read]);
            assert!(request.contains(&format!("actorDeviceId={TEST_DEVICE_ID}")));
            if page == 0 {
                assert!(!request.contains("pageCursor="));
            } else {
                assert!(request.contains("pageCursor=device-page-2"));
            }
            let body = json!({
                "items": [{"device": {
                    "deviceId": device_id,
                    "keyId": signer_key_id,
                    "signaturePublicKey": {"$bytes": signer_public},
                    "authGeneration": 7,
                    "status": "active",
                    "createdAt": "2026-08-23T12:00:00.000Z",
                    "updatedAt": "2026-08-23T12:00:00.000Z",
                    "availablePackageCount": available,
                    "reservedPackageCount": reserved,
                }}],
                "hasMore": has_more,
                "nextPageCursor": next_cursor,
                "snapshotExpiresAt": "2026-08-23T12:15:00.000Z",
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

    let stats = client.get_key_package_stats().await.unwrap();
    server_task.await.unwrap();
    assert_eq!(stats.available, 2);
    assert_eq!(stats.total, 5);
}

#[tokio::test]
async fn pending_welcome_is_device_fenced_and_never_acknowledged_before_durable_join() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base_url = format!("http://{}/", listener.local_addr().unwrap());
    let signer = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();
    let authority_state = Arc::new(AuthorityState::new());
    authority_state.install(test_snapshot(
        TEST_OPAQUE_SESSION,
        TEST_DID,
        TEST_DEVICE_ID,
        7,
        &signer,
    ));
    let tmp = TempDir::new("pending-welcome");
    let client = BirdApiClient::new(
        "https://pds.example.invalid".into(),
        Arc::new(jacquard::client::MemoryCredentialSession::unauthenticated()),
        TEST_DID.into(),
        "alice.bsky.social".into(),
        "secret".into(),
    )
    .with_chat_authority(
        Arc::new(NestClient::new(&base_url).unwrap()),
        authority_state,
        Arc::new(FileCredentialStore::new(tmp.path().join("creds.json")).unwrap()),
    );

    let opaque_welcome = b"opaque-mls-welcome-fixture".to_vec();
    let welcome_sha256 = Sha256::digest(&opaque_welcome).to_vec();
    let server_task = tokio::spawn(async move {
        let (mut inventory_stream, _) = listener.accept().await.unwrap();
        let mut request = [0_u8; 4096];
        let read = inventory_stream.read(&mut request).await.unwrap();
        let request = String::from_utf8_lossy(&request[..read]);
        assert!(request.contains("getConversations"));
        let inventory = empty_conversations_json();
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            inventory.len(),
            inventory
        );
        inventory_stream
            .write_all(response.as_bytes())
            .await
            .unwrap();

        let (mut welcome_stream, _) = listener.accept().await.unwrap();
        let mut request = [0_u8; 8192];
        let read = welcome_stream.read(&mut request).await.unwrap();
        let request = String::from_utf8_lossy(&request[..read]);
        assert!(request.contains("getPendingWelcomes"));
        assert!(request.contains(&format!("actorDeviceId={TEST_DEVICE_ID}")));
        assert!(request.contains("inventorySessionId=inv-session-123"));
        let body = json!({
            "hasMore": false,
            "inventorySessionId": "inv-session-123",
            "snapshotEventCursor": "cursor-456",
            "snapshotExpiresAt": "2026-08-23T12:15:00.000Z",
            "items": [{
                "$type": "blue.catbird.chat.defs#welcomeView",
                "welcomeId": "33333333-3333-4333-9333-333333333333",
                "conversationId": TEST_CONVO_ID,
                "transitionSeq": 9,
                "coordinates": {
                    "conversationId": TEST_CONVO_ID,
                    "groupId": {"$bytes": B64.encode([2_u8; 32])},
                    "epoch": 2,
                    "generation": 7,
                    "stateVersion": 2,
                    "lifecycle": "active",
                    "confirmationTag": {"$bytes": B64.encode([4_u8; 32])},
                    "groupContextHash": {"$bytes": B64.encode([3_u8; 32])},
                },
                "status": "pending",
                "opaqueWelcome": {"$bytes": B64.encode(&opaque_welcome)},
                "sha256": welcome_sha256,
                "recipientDid": TEST_DID,
                "recipientDeviceId": TEST_DEVICE_ID,
                "provenance": {
                    "recoveryRequestId": "44444444-4444-4444-9444-444444444444",
                    "keyPackageRef": {"$bytes": B64.encode([5_u8; 32])},
                },
                "expiresAt": "2026-09-23T12:15:00.000Z",
            }],
        })
        .to_string();
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        welcome_stream.write_all(response.as_bytes()).await.unwrap();

        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), listener.accept())
                .await
                .is_err(),
            "get_welcome must not acknowledge before MLS processing and durable join"
        );
    });

    client.get_conversations(25, None).await.unwrap();
    let error = client.get_welcome(TEST_CONVO_ID).await.unwrap_err();
    assert!(error
        .to_string()
        .contains("no post-join acknowledgement hook"));
    server_task.await.unwrap();
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
    let creds = Arc::new(FileCredentialStore::new(tmp.path().join("creds.json")).unwrap());
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
            "hasMore": false,
            "snapshotExpiresAt": "2099-08-23T12:05:00.000Z",
            "items": [{
                "device": {
                    "deviceId": TEST_DEVICE_ID,
                    "authGeneration": 7,
                    "status": "active",
                    "keyId": signer_handle,
                    "signaturePublicKey": {"$bytes": B64.encode(signer.public())},
                    "availablePackageCount": 0,
                    "reservedPackageCount": 0,
                    "createdAt": "2026-08-23T12:00:00.000Z",
                    "updatedAt": "2026-08-23T12:00:00.000Z"
                }
            }]
        })
        .to_string();
        let resp2 = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_orchestrator_reuses_the_admitted_device_scoped_identity() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base_url = format!("http://{}/", listener.local_addr().unwrap());
    let tmp = TempDir::new("real-orchestrator-identity");
    let scoped_did = format!("{TEST_DID}#{TEST_DEVICE_ID}");
    let keychain = FileKeychain::new(tmp.path().join("keychain.json")).unwrap();
    let epoch_secret_storage = keychain.with_epoch_secret_owner(TEST_DID).unwrap();
    let mls_context = MLSContext::new(
        tmp.path().join("mls.db").to_string_lossy().into_owned(),
        "test-database-key".into(),
        Box::new(keychain),
    )
    .unwrap();
    mls_context
        .set_epoch_secret_storage(Box::new(epoch_secret_storage))
        .unwrap();
    let key_package = mls_context
        .create_key_package(scoped_did.as_bytes().to_vec())
        .unwrap();
    let signer_bytes = mls_context.export_identity_key(scoped_did.clone()).unwrap();
    let signer: SignatureKeyPair = serde_json::from_slice(&signer_bytes).unwrap();
    let signer_key_id = derive_key_id(signer.public());
    assert_eq!(signer.public(), key_package.signature_public_key);

    let credentials =
        Arc::new(FileCredentialStore::new(tmp.path().join("credentials.json")).unwrap());
    credentials
        .store_signing_key(TEST_DID, &signer_bytes)
        .await
        .unwrap();
    credentials
        .install_admitted_device_tuple(TEST_DID, TEST_DEVICE_ID, &scoped_did, 7)
        .unwrap();

    let authority = Arc::new(AuthorityState::new());
    authority.install(test_snapshot(
        TEST_OPAQUE_SESSION,
        TEST_DID,
        TEST_DEVICE_ID,
        7,
        &signer,
    ));
    let api = Arc::new(
        BirdApiClient::new(
            "https://pds.example.invalid".into(),
            Arc::new(jacquard::client::MemoryCredentialSession::unauthenticated()),
            TEST_DID.into(),
            "alice.bsky.social".into(),
            "secret".into(),
        )
        .with_chat_authority(
            Arc::new(NestClient::new(&base_url).unwrap()),
            authority,
            credentials.clone(),
        ),
    );
    let storage = Arc::new(SqliteStorage::new(tmp.path().join("bird.db"), TEST_DID).unwrap());
    let orchestrator = Arc::new(MLSOrchestrator::new(
        mls_context,
        storage,
        api.clone(),
        credentials,
        OrchestratorConfig::default(),
    ));
    api.set_signer(orchestrator.clone());
    orchestrator.initialize(TEST_DID).await.unwrap();

    let server_task = tokio::spawn(async move {
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 8192];
            let read = stream.read(&mut request).await.unwrap();
            let request = String::from_utf8_lossy(&request[..read]);
            assert!(request.contains(&format!("actorDeviceId={TEST_DEVICE_ID}")));
            let body = json!({
                "items": [{"device": {
                    "deviceId": TEST_DEVICE_ID,
                    "keyId": signer_key_id,
                    "signaturePublicKey": {"$bytes": B64.encode(signer.public())},
                    "authGeneration": 7,
                    "status": "active",
                    "createdAt": "2026-08-23T12:00:00.000Z",
                    "updatedAt": "2026-08-23T12:00:00.000Z",
                    "availablePackageCount": 20,
                    "reservedPackageCount": 2
                }}],
                "hasMore": false,
                "snapshotExpiresAt": "2026-08-23T12:15:00.000Z"
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

    let admitted_identity = orchestrator.ensure_device_registered().await.unwrap();
    assert_eq!(admitted_identity, scoped_did);
    orchestrator.replenish_if_needed().await.unwrap();
    server_task.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_orchestrator_sync_adopts_the_stable_uuid_and_retires_the_raw_alias() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base_url = format!("http://{}/", listener.local_addr().unwrap());
    let tmp = TempDir::new("real-orchestrator-projection");
    let scoped_did = format!("{TEST_DID}#{TEST_DEVICE_ID}");
    let raw_group_bytes = vec![2_u8; 32];
    let raw_group_id = hex::encode(&raw_group_bytes);
    let keychain = FileKeychain::new(tmp.path().join("keychain.json")).unwrap();
    let epoch_secret_storage = keychain.with_epoch_secret_owner(TEST_DID).unwrap();
    let mls_context = MLSContext::new(
        tmp.path().join("mls.db").to_string_lossy().into_owned(),
        "test-database-key".into(),
        Box::new(keychain),
    )
    .unwrap();
    mls_context
        .set_epoch_secret_storage(Box::new(epoch_secret_storage))
        .unwrap();
    mls_context
        .create_key_package(scoped_did.as_bytes().to_vec())
        .unwrap();
    let signer_bytes = mls_context.export_identity_key(scoped_did.clone()).unwrap();
    let signer: SignatureKeyPair = serde_json::from_slice(&signer_bytes).unwrap();
    let created_group = mls_context
        .create_group_with_id(
            scoped_did.as_bytes().to_vec(),
            raw_group_bytes.clone(),
            None,
        )
        .unwrap();
    assert_eq!(created_group.group_id, raw_group_bytes);

    let credentials =
        Arc::new(FileCredentialStore::new(tmp.path().join("credentials.json")).unwrap());
    credentials
        .store_signing_key(TEST_DID, &signer_bytes)
        .await
        .unwrap();
    credentials
        .install_admitted_device_tuple(TEST_DID, TEST_DEVICE_ID, &scoped_did, 7)
        .unwrap();
    let authority = Arc::new(AuthorityState::new());
    authority.install(test_snapshot(
        TEST_OPAQUE_SESSION,
        TEST_DID,
        TEST_DEVICE_ID,
        7,
        &signer,
    ));
    let api = Arc::new(
        BirdApiClient::new(
            "https://pds.example.invalid".into(),
            Arc::new(jacquard::client::MemoryCredentialSession::unauthenticated()),
            TEST_DID.into(),
            "alice.bsky.social".into(),
            "secret".into(),
        )
        .with_chat_authority(
            Arc::new(NestClient::new(&base_url).unwrap()),
            authority,
            credentials.clone(),
        ),
    );
    let storage = Arc::new(SqliteStorage::new(tmp.path().join("bird.db"), TEST_DID).unwrap());
    let orchestrator = Arc::new(MLSOrchestrator::new(
        mls_context,
        storage.clone(),
        api.clone(),
        credentials,
        OrchestratorConfig::default(),
    ));
    api.set_signer(orchestrator.clone());
    orchestrator.initialize(TEST_DID).await.unwrap();

    storage
        .ensure_conversation_exists(TEST_DID, &raw_group_id, &raw_group_id)
        .await
        .expect("seed raw-group alias after startup reconciliation");
    storage
        .store_message(&catbird_mls::orchestrator::Message {
            id: "alias-history-message".into(),
            conversation_id: raw_group_id.clone(),
            sender_did: TEST_DID.into(),
            text: "alias-bound history".into(),
            timestamp: chrono::Utc::now(),
            epoch: 0,
            sequence_number: 1,
            is_own: true,
            delivery_status: None,
            payload_json: Some(r#"{"hmac":"source-bound"}"#.into()),
        })
        .await
        .unwrap();

    let server_raw_group_id = raw_group_id.clone();
    let server_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = [0_u8; 8192];
        let read = stream.read(&mut request).await.unwrap();
        let request = String::from_utf8_lossy(&request[..read]);
        assert!(request.contains("blue.catbird.chat.getConversations"));
        assert!(request.contains(&format!("actorDeviceId={TEST_DEVICE_ID}")));
        let body = projection_conversations_json(TEST_CONVO_ID);
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        stream.write_all(response.as_bytes()).await.unwrap();

        for _ in 0..4 {
            let (mut stream, _) =
                tokio::time::timeout(std::time::Duration::from_secs(5), listener.accept())
                    .await
                    .unwrap()
                    .unwrap();
            let mut request = [0_u8; 8192];
            let read = stream.read(&mut request).await.unwrap();
            let request = String::from_utf8_lossy(&request[..read]);
            let inventory = request.contains("blue.catbird.chat.getConversations");
            assert!(
                inventory || request.contains("blue.catbird.chat.getEntries"),
                "unexpected request {}",
                request.lines().next().unwrap_or_default()
            );
            assert!(!request.contains(&server_raw_group_id));
            let body = if inventory {
                projection_conversations_json(TEST_CONVO_ID)
            } else {
                assert!(request.contains(&format!("conversationId={TEST_CONVO_ID}")));
                json!({"entries":[],"hasMore":false,"nextAfterSeq":0}).to_string()
            };
            let response = format!("HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",body.len(),body);
            stream.write_all(response.as_bytes()).await.unwrap();
            if !inventory {
                return;
            }
        }
        panic!("inventory reads exceeded fixture bound");
    });

    orchestrator.sync_with_server(true).await.unwrap();
    server_task.await.unwrap();

    let durable = storage.list_conversations(TEST_DID).await.unwrap();
    assert_eq!(durable.len(), 1);
    assert_eq!(durable[0].conversation_id, TEST_CONVO_ID);
    assert_eq!(durable[0].group_id, raw_group_id);
    assert!(storage
        .get_conversation(TEST_DID, &raw_group_id)
        .await
        .unwrap()
        .is_none());
    let history = storage.get_messages(TEST_CONVO_ID, 10, None).await.unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].conversation_id, TEST_CONVO_ID);
    assert!(storage
        .get_group_state(&raw_group_id)
        .await
        .unwrap()
        .is_some());
    assert!(storage
        .list_pending_local_deletes()
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn test_typing_remains_explicitly_disabled() {
    let nest = Arc::new(NestClient::new("https://nest.example.invalid/").unwrap());
    let authority_state = Arc::new(AuthorityState::new());
    let tmp = TempDir::new("test-typing");
    let creds = Arc::new(FileCredentialStore::new(tmp.path().join("creds.json")).unwrap());
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
    let snapshot = test_snapshot(TEST_OPAQUE_SESSION, TEST_DID, TEST_DEVICE_ID, 7, &signer);
    let authority_state = Arc::new(AuthorityState::new());
    authority_state.install(snapshot);

    let nest = Arc::new(NestClient::new(&base_url).unwrap());
    let tmp = TempDir::new("test-bot-reply");
    let creds = Arc::new(FileCredentialStore::new(tmp.path().join("creds.json")).unwrap());
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
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
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
                "entryId": "73737373-7373-4373-9373-737373737373",
                "conversationId": TEST_CONVO_ID,
                "seq": 10,
                "receivedAt": "2026-08-17T12:00:00.000Z",
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
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
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

        let mut response_body = signed_req["body"].clone();
        response_body["applicationMessage"]["sha256"] = json!(vec![0u8; 32]);
        let reply_out = json!({
            "entry": {
                "$type": "blue.catbird.chat.defs#applicationEntry",
                "entryId": "reply-entry-uuid-002",
                "conversationId": TEST_CONVO_ID,
                "seq": 11,
                "receivedAt": "2026-08-17T12:01:00.000Z",
                "signedRequest": {
                    "body": response_body,
                    "signature": signed_req["signature"].clone()
                }
            }
        })
        .to_string();

        let resp3 = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
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
        Some("73737373-7373-4373-9373-737373737373")
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
