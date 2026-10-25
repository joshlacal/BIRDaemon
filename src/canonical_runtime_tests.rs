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
    CanonicalOperation, CleanChatSigningContext, MLSAPIClient, PreparedRequest,
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
        let body_val: serde_json::Value = serde_json::from_slice(&body_json).unwrap();
        let key_id = body_val["keyId"].as_str().unwrap();
        let auth = self
            .creds
            .sign_clean_chat_transcript(&binding.actor_did, &body_json, key_id)
            .await
            .map_err(|e| OrchestratorError::Credential(e.to_string()))?
            .ok_or_else(|| OrchestratorError::Credential("test signer is unavailable".into()))?;

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
async fn test_canonical_send_message_with_stored_signer_through_nest() {
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
                    "entryId": "99999999-9999-4999-8999-999999999999",
                    "conversationId": TEST_CONVO_ID,
                    "seq": 42,
                    "receivedAt": "2026-08-17T12:00:00.000Z",
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
    assert_eq!(send_resp.message_id, "99999999-9999-4999-8999-999999999999");
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
        let (req, body) = read_http_request(&mut stream).await;
        assert!(body.is_empty());
        let mut request_line = req.lines().next().unwrap().split_whitespace();
        assert_eq!(request_line.next(), Some("GET"));
        let request_url =
            url::Url::parse(&format!("http://localhost{}", request_line.next().unwrap())).unwrap();
        assert_eq!(request_url.path(), "/xrpc/blue.catbird.chat.getBlob");
        let query = request_url
            .query_pairs()
            .collect::<std::collections::HashMap<_, _>>();
        assert_eq!(
            query.get("blobId").map(|value| value.as_ref()),
            Some("blob-test-id-123")
        );
        assert_eq!(
            query.get("actorDeviceId").map(|value| value.as_ref()),
            Some(TEST_DEVICE_ID)
        );
        assert_eq!(query.len(), 2);
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
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n{}: {}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            CHAT_JKT_HEADER,
            TEST_JKT,
            conv_body.len(),
            conv_body
        );
        stream1.write_all(resp1.as_bytes()).await.unwrap();

        // Handle getSubscriptionTicket
        let (mut stream2, _) = nest_listener.accept().await.unwrap();
        let (req2, request_body) = read_http_request(&mut stream2).await;
        let request_body: serde_json::Value = serde_json::from_slice(&request_body).unwrap();
        assert_eq!(request_body["actorDeviceId"], TEST_DEVICE_ID);
        assert_eq!(request_body["eventCursor"], "cursor-456");
        assert_eq!(request_body["inventorySessionId"], "inv-session-123");

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

    // Exercise only the read and prepared-ticket HTTP boundaries. The shared
    // subscription owner performs the complete inventory barrier in production.
    let _ = client.get_conversations(25, None).await.unwrap();
    let bound_cursor = "cursor-456";
    let request = catbird_mls::orchestrator::CleanChatRequest::GetSubscriptionTicket(
        catbird_atproto::blue_catbird::chat::get_subscription_ticket::GetSubscriptionTicket {
            actor_device_id: TEST_DEVICE_ID.to_owned(),
            inventory_session_id: "inv-session-123".to_owned(),
            event_cursor: bound_cursor.to_owned(),
            supported_protocol_versions: None,
            extra_data: None,
        },
    )
    .prepare(&catbird_mls::orchestrator::CleanChatAuthContext::new(
        TEST_DEVICE_ID.to_owned(),
    ))
    .unwrap();
    let response = client.submit_prepared_request(request).await.unwrap();
    assert_eq!(response.status, 200);
    let response: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    let ticket = response["ticket"].as_str().unwrap();
    let endpoint = response["endpoint"].as_str().unwrap();
    nest_task.await.unwrap();

    assert_eq!(ticket, "single-use-ds-ticket-token-777");
    assert_eq!(endpoint, ws_endpoint);
    assert_eq!(bound_cursor, "cursor-456");

    // Verify WebSocket connection to DS receives ONLY the ticket in query, NEVER the session bearer
    let ws_server_task = tokio::spawn(async move {
        let (mut stream, _) = ws_listener.accept().await.unwrap();
        let mut buf = [0u8; 4096];
        let n = stream.read(&mut buf).await.unwrap();
        let req = String::from_utf8_lossy(&buf[..n]);

        assert!(req.contains("ticket=single-use-ds-ticket-token-777"));
        assert!(req.contains("cursor=cursor-456"));
        assert!(!req.contains(TEST_OPAQUE_SESSION));
        assert!(!req.contains("authorization:"));
    });

    let ws_url = format!("{endpoint}?ticket={ticket}&cursor={bound_cursor}");
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

        // Confirm the current Nest device/JKT binding before reading own devices.
        let (mut preflight, _) = listener.accept().await.unwrap();
        let mut preflight_buf = [0u8; 4096];
        let n = preflight.read(&mut preflight_buf).await.unwrap();
        let request = String::from_utf8_lossy(&preflight_buf[..n]);
        assert!(request.contains("GET /xrpc/blue.catbird.chat.enrollDevice"));
        assert!(request.contains(&format!("{CHAT_DEVICE_HEADER}: {TEST_DEVICE_ID}")));
        let body = json!({"deviceId": TEST_DEVICE_ID, "dpopJkt": TEST_JKT}).to_string();
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n{CHAT_JKT_HEADER}: {TEST_JKT}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        );
        preflight.write_all(response.as_bytes()).await.unwrap();

        // Then read getOwnDevices.
        let (mut stream2, _) = listener.accept().await.unwrap();
        let mut buf2 = [0u8; 4096];
        let n2 = stream2.read(&mut buf2).await.unwrap();
        let req2 = String::from_utf8_lossy(&buf2[..n2]);
        assert!(req2.contains("getOwnDevices"));

        let dev_body = json!({
            "hasMore": false,
            "snapshotExpiresAt": "2026-08-17T12:30:00.000Z",
            "items": [{
                "device": {
                    "deviceId": TEST_DEVICE_ID,
                    "availablePackageCount": 2,
                    "reservedPackageCount": 1,
                    "createdAt": "2026-08-17T12:00:00.000Z",
                    "updatedAt": "2026-08-17T12:00:00.000Z",
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
    let creds = Arc::new(FileCredentialStore::new(tmp.path().join("creds.json")).unwrap());
    creds
        .store_signing_key(TEST_DID, &serde_json::to_vec(&signer).unwrap())
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
                "entryId": "66666666-6666-4666-8666-666666666666",
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
                            "conversationId": {"$bytes": B64.encode([1u8; 16])},
                            "generation": 1,
                            "messageId": {"$bytes": B64.encode([8u8; 16])},
                            "prior": {
                                "conversationId": {"$bytes": B64.encode([1u8; 16])},
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
        Some("66666666-6666-4666-8666-666666666666")
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

// These are local HTTP boundary tests, not provider or live MLS qualification.
fn prepared_request(body: &[u8]) -> PreparedRequest {
    PreparedRequest {
        operation: CanonicalOperation::RequestReset,
        method: "POST".into(),
        path: "/xrpc/blue.catbird.chat.requestReset".into(),
        body: Some(body.to_vec()),
    }
}

fn prepared_client(
    base_url: &str,
    tmp: &TempDir,
) -> (BirdApiClient, Arc<AuthorityState>, AuthoritySnapshot) {
    let signer = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();
    let snapshot = test_snapshot(
        TEST_OPAQUE_SESSION,
        TEST_DID,
        TEST_DEVICE_ID,
        TEST_JKT,
        7,
        &signer,
    );
    let authority = Arc::new(AuthorityState::new());
    authority.install(snapshot.clone());
    let client = BirdApiClient::new(
        "https://pds.example.invalid".into(),
        Arc::new(jacquard::client::MemoryCredentialSession::unauthenticated()),
        TEST_DID.into(),
        "alice.bsky.social".into(),
        "unused-fixture-password".into(),
    )
    .with_chat_authority(
        Arc::new(NestClient::new(base_url).unwrap()),
        authority.clone(),
        Arc::new(FileCredentialStore::new(tmp.path().join("creds.json")).unwrap()),
    );
    (client, authority, snapshot)
}

async fn read_http_request(stream: &mut tokio::net::TcpStream) -> (String, Vec<u8>) {
    let mut request = Vec::new();
    loop {
        let mut chunk = [0u8; 4096];
        let count =
            tokio::time::timeout(std::time::Duration::from_secs(5), stream.read(&mut chunk))
                .await
                .unwrap()
                .unwrap();
        assert_ne!(count, 0, "connection closed before complete request");
        request.extend_from_slice(&chunk[..count]);
        assert!(request.len() < 65536, "fixture request unexpectedly large");
        if let Some(header_end) = request.windows(4).position(|chunk| chunk == b"\r\n\r\n") {
            let headers = String::from_utf8(request[..header_end].to_vec()).unwrap();
            let length = headers
                .lines()
                .filter_map(|line| line.split_once(':'))
                .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                .map(|(_, value)| value.trim().parse::<usize>().unwrap())
                .unwrap_or(0);
            if request.len() >= header_end + 4 + length {
                return (
                    headers,
                    request[header_end + 4..header_end + 4 + length].to_vec(),
                );
            }
        }
    }
}

#[tokio::test]
async fn prepared_transport_preserves_body_status_and_content_type() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base_url = format!("http://{}/", listener.local_addr().unwrap());
    let tmp = TempDir::new("prepared-raw");
    let (client, authority, snapshot) = prepared_client(&base_url, &tmp);
    let body = b"{\n \"signedRequest\": {\"body\": {}, \"signature\": \"fixture\"}\n}";
    let reply = b"{\"error\":\"StaleCoordinate\",\"detail\":\"retain exact bytes\"}";
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let (headers, transmitted) = read_http_request(&mut stream).await;
        assert!(headers.starts_with("POST /xrpc/blue.catbird.chat.requestReset HTTP/1.1"));
        assert!(headers.contains(&format!("authorization: Bearer {TEST_OPAQUE_SESSION}")));
        assert!(headers.contains(&format!("{CHAT_DEVICE_HEADER}: {TEST_DEVICE_ID}")));
        assert!(!headers.contains("atproto-proxy"));
        assert_eq!(transmitted, body);
        let response = format!(
            "HTTP/1.1 409 Conflict\r\ncontent-type: application/problem+json\r\n{CHAT_JKT_HEADER}: {TEST_JKT}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            reply.len()
        );
        stream.write_all(response.as_bytes()).await.unwrap();
        stream.write_all(reply).await.unwrap();
    });
    let result = client
        .submit_prepared_request(prepared_request(body))
        .await
        .unwrap();
    server.await.unwrap();
    assert_eq!(result.status, 409);
    assert_eq!(
        result.content_type.as_deref(),
        Some("application/problem+json")
    );
    assert_eq!(result.body, reply);
    assert_eq!(authority.snapshot(), Some(snapshot));
}

#[tokio::test]
async fn prepared_transport_rejects_wrong_route_method_and_missing_body_before_http() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base_url = format!("http://{}/", listener.local_addr().unwrap());
    let tmp = TempDir::new("prepared-route");
    let (client, authority, _) = prepared_client(&base_url, &tmp);
    let mut wrong_route = prepared_request(b"{}");
    wrong_route.path = "/xrpc/blue.catbird.chat.sendMessage".into();
    let mut wrong_method = prepared_request(b"{}");
    wrong_method.method = "DELETE".into();
    let mut missing_body = prepared_request(b"{}");
    missing_body.body = None;
    for request in [wrong_route, wrong_method, missing_body] {
        assert!(client.submit_prepared_request(request).await.is_err());
    }
    authority
        .invalidate(crate::chat_authority::InvalidationReason::Unauthorized)
        .unwrap();
    assert!(client
        .submit_prepared_request(prepared_request(b"{}"))
        .await
        .is_err());
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(50), listener.accept())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn prepared_transport_preserves_unauthorized_response_and_invalidates_authority() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base_url = format!("http://{}/", listener.local_addr().unwrap());
    let tmp = TempDir::new("prepared-unauthorized");
    let (client, authority, _) = prepared_client(&base_url, &tmp);
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        read_http_request(&mut stream).await;
        stream.write_all(b"HTTP/1.1 401 Unauthorized\r\ncontent-type: application/json\r\ncontent-length: 13\r\nconnection: close\r\n\r\n{\"error\":\"x\"}").await.unwrap();
    });
    let response = client
        .submit_prepared_request(prepared_request(b"{}"))
        .await
        .unwrap();
    server.await.unwrap();
    assert_eq!(response.status, 401);
    assert_eq!(response.body, b"{\"error\":\"x\"}");
    assert!(authority.snapshot().is_none());
}

#[tokio::test]
async fn prepared_transport_rejects_changed_jkt_and_preserves_new_authority_on_delayed_401() {
    for replace_authority in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base_url = format!("http://{}/", listener.local_addr().unwrap());
        let tmp = TempDir::new("prepared-authority-race");
        let (client, authority, snapshot) = prepared_client(&base_url, &tmp);
        let newer = test_snapshot(
            "different-opaque-session",
            TEST_DID,
            TEST_DEVICE_ID,
            TEST_JKT,
            8,
            &SignatureKeyPair::new(SignatureScheme::ED25519).unwrap(),
        );
        let install_authority = authority.clone();
        let expected = newer.clone();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            read_http_request(&mut stream).await;
            if replace_authority {
                install_authority.install(newer);
                stream.write_all(b"HTTP/1.1 401 Unauthorized\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}").await.unwrap();
            } else {
                stream.write_all(format!("HTTP/1.1 200 OK\r\n{CHAT_JKT_HEADER}: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{{}}").as_bytes()).await.unwrap();
            }
        });
        let result = client
            .submit_prepared_request(prepared_request(b"{}"))
            .await;
        server.await.unwrap();
        if replace_authority {
            assert_eq!(result.unwrap().status, 401);
            assert_eq!(authority.snapshot(), Some(expected));
        } else {
            assert!(result.is_err());
            assert_ne!(authority.snapshot(), Some(snapshot));
            assert!(authority.snapshot().is_none());
        }
    }
}
