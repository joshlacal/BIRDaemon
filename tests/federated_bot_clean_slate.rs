use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use bird_daemon::bot::{
    BirdKeyStore, BirdPlatformTransport, BotLlmResponder, FederatedBirdBot, FederatedBotConfig,
};
use catbird_mls::client::{
    CatbirdMlsClient, CatbirdMlsClientConfig, PlatformTransport, REQUIRED_LABYRINTH_OAUTH_SCOPES,
};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

struct EchoResponder {
    seen_prompts: Mutex<Vec<String>>,
}

#[async_trait::async_trait]
impl BotLlmResponder for EchoResponder {
    async fn generate_reply(&self, sender_did: &str, text: &str) -> anyhow::Result<String> {
        self.seen_prompts
            .lock()
            .unwrap()
            .push(format!("{sender_did}:{text}"));
        Ok(format!("chirp reply to: {text}"))
    }
}

#[derive(Default)]
struct LocalLiveDsState {
    pds_records: BTreeMap<(String, String, String), Value>,
    convo_kps: BTreeMap<(String, String), Vec<Value>>,
    dr_keys: BTreeMap<String, Vec<(String, Value, Value)>>,
    conversations: BTreeMap<String, Value>,
    entries: BTreeMap<String, Vec<Value>>,
    pending_welcomes: BTreeMap<(String, String), Vec<Value>>,
    leaf_recovery_inbox: BTreeMap<String, Vec<Value>>,
    acked_welcomes: Vec<String>,
}

fn pct_decode(s: &str) -> String {
    let mut out = Vec::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(hex_str) = std::str::from_utf8(&bytes[i + 1..i + 3]) {
                if let Ok(b) = u8::from_str_radix(hex_str, 16) {
                    out.push(b);
                    i += 3;
                    continue;
                }
            }
        }
        out.push(if bytes[i] == b'+' { b' ' } else { bytes[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn query_map(target: &str) -> BTreeMap<String, String> {
    let Some((_, q)) = target.split_once('?') else {
        return BTreeMap::new();
    };
    q.split('&')
        .filter(|p| !p.is_empty())
        .filter_map(|p| {
            let (k, v) = p.split_once('=')?;
            Some((pct_decode(k), pct_decode(v)))
        })
        .collect()
}

fn handle_ds_http(
    state: &Mutex<LocalLiveDsState>,
    ds_did: &str,
    base_url: &str,
    target: &str,
    body: &[u8],
) -> (u16, Value) {
    let q = query_map(target);
    let body_json: Value = serde_json::from_slice(body).unwrap_or_else(|_| json!({}));

    if target.contains("/xrpc/com.atproto.identity.resolveDid") {
        let did = q.get("did").cloned().unwrap_or_default();
        return (
            200,
            json!({
                "didDoc": {
                    "id": did,
                    "service": [{
                        "id": "#atproto_pds",
                        "type": "AtprotoPersonalDataServer",
                        "serviceEndpoint": base_url,
                    }]
                }
            }),
        );
    }

    let mut g = state.lock().unwrap();

    if target.contains("/xrpc/com.atproto.space.getSpace")
        || target.contains("/xrpc/com.atproto.space.putSpace")
    {
        return (
            200,
            json!({ "uri": q.get("space").cloned().unwrap_or_default() }),
        );
    }
    if target.contains("/xrpc/com.atproto.space.uploadBlob") {
        return (
            200,
            json!({
                "blob": {
                    "$type": "blob",
                    "ref": { "$link": "bafkreimockspaceblob00000000000000000000" },
                    "mimeType": "application/octet-stream",
                    "size": body.len(),
                }
            }),
        );
    }
    if target.contains("/xrpc/com.atproto.space.applyWrites") {
        return (
            200,
            json!({ "commit": { "rev": "3kzzzzzzzzzzz", "cid": "bafyreispace" } }),
        );
    }
    if target.contains("/xrpc/com.atproto.repo.putRecord") {
        let repo = body_json["repo"].as_str().unwrap_or_default().to_string();
        let coll = body_json["collection"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        let rkey = body_json["rkey"].as_str().unwrap_or_default().to_string();
        g.pds_records.insert(
            (repo.clone(), coll.clone(), rkey.clone()),
            body_json["record"].clone(),
        );
        return (
            200,
            json!({ "uri": format!("at://{repo}/{coll}/{rkey}"), "cid": "bafyreimock" }),
        );
    }
    if target.contains("/xrpc/com.atproto.repo.listRecords") {
        let repo = q.get("repo").cloned().unwrap_or_default();
        let coll = q.get("collection").cloned().unwrap_or_default();
        let records: Vec<Value> = g
            .pds_records
            .iter()
            .filter(|((r, c, _), _)| r == &repo && c == &coll)
            .map(|((r, c, rk), val)| {
                json!({ "uri": format!("at://{r}/{c}/{rk}"), "cid": "bafyreimock", "value": val })
            })
            .collect();
        return (200, json!({ "records": records }));
    }
    if target.contains("/xrpc/blue.catbird.chat.enrollDevice") {
        let b = &body_json["signedRequest"]["body"];
        let did = b["actorDid"].as_str().unwrap().to_string();
        let dev = b["deviceId"].as_str().unwrap().to_string();
        let kps = b["keyPackages"].as_array().cloned().unwrap_or_default();
        g.convo_kps.entry((did, dev)).or_default().extend(kps);
        return (200, json!({ "device": { "authGeneration": 1 } }));
    }
    if target.contains("/xrpc/blue.catbird.chat.replenishKeyPackages") {
        let b = &body_json["signedRequest"]["body"];
        let did = b["actorDid"].as_str().unwrap().to_string();
        let dev = b["actorDeviceId"].as_str().unwrap().to_string();
        let kps = b["keyPackages"].as_array().cloned().unwrap_or_default();
        g.convo_kps.entry((did, dev)).or_default().extend(kps);
        return (200, json!({ "acceptedCount": 4 }));
    }
    if target.contains("/xrpc/blue.catbird.chat.publishDirectRequestKeys") {
        let b = &body_json["signedRequest"]["body"];
        let did = b["actorDid"].as_str().unwrap().to_string();
        let dev = b["actorDeviceId"].as_str().unwrap().to_string();
        let mut list = Vec::new();
        for item in b["keys"].as_array().cloned().unwrap_or_default() {
            list.push((
                dev.clone(),
                item["keyPackage"].clone(),
                item["grant"].clone(),
            ));
        }
        g.dr_keys.insert(did, list);
        return (200, json!({ "published": true }));
    }
    if target.contains("/xrpc/blue.catbird.chat.createConversation") {
        let sr = body_json["signedRequest"].clone();
        let b = &sr["body"];
        let cid = b["conversationId"].as_str().unwrap().to_string();
        let coords = b["next"].clone();
        let parts = b["manifest"]["participants"].clone();
        g.conversations.insert(
            cid.clone(),
            json!({
                "conversationKind": "group",
                "sequencerDid": ds_did,
                "coordinates": coords.clone(),
                "participants": parts,
            }),
        );
        g.entries.entry(cid).or_default().push(json!({
            "$type": "blue.catbird.chat.defs#creationEntry",
            "seq": 1,
            "coordinates": coords.clone(),
            "signedRequest": sr,
        }));
        return (200, json!({ "seq": 1, "state": { "coordinates": coords } }));
    }
    if target.contains("/xrpc/blue.catbird.chat.acceptConversation") {
        let sr = body_json["signedRequest"].clone();
        let b = &sr["body"];
        let cid = b["next"]["conversationId"].as_str().unwrap().to_string();
        let next_coords = b["next"].clone();
        let invitee_did = b["actorDid"].as_str().unwrap().to_string();
        let invitee_dev = b["actorDeviceId"].as_str().unwrap().to_string();
        let inviter_did = b["invitationProvenance"]["invitedByDid"]
            .as_str()
            .unwrap()
            .to_string();
        let rec_req_id = b["recoveryRequestId"].as_str().unwrap().to_string();
        let kp = g
            .convo_kps
            .get_mut(&(invitee_did.clone(), invitee_dev.clone()))
            .and_then(|v| v.pop())
            .expect("invitee must have conversation KP");
        if let Some(st) = g.conversations.get_mut(&cid) {
            st["coordinates"] = next_coords.clone();
            if let Some(arr) = st["participants"].as_array_mut() {
                for p in arr {
                    if p["userDid"].as_str() == Some(&invitee_did) {
                        p["status"] = json!("active");
                    }
                }
            }
        }
        let entries = g.entries.entry(cid.clone()).or_default();
        let next_seq = (entries.len() as i64) + 1;
        entries.push(json!({
            "$type": "blue.catbird.chat.defs#participantAcceptanceEntry",
            "seq": next_seq,
            "coordinates": next_coords.clone(),
            "signedRequest": sr,
        }));
        g.leaf_recovery_inbox
            .entry(inviter_did)
            .or_default()
            .push(json!({
                "conversationId": cid,
                "recoveryRequestId": rec_req_id,
                "userDid": invitee_did,
                "deviceId": invitee_dev,
                "keyPackage": kp,
                "coordinates": next_coords,
            }));
        return (200, json!({ "seq": next_seq }));
    }
    if target.contains("/xrpc/blue.catbird.chat.submitTransition") {
        let sr = body_json["signedRequest"].clone();
        let b = &sr["body"];
        let btype = b["$type"].as_str().unwrap_or("");
        let cid = b["next"]["conversationId"].as_str().unwrap().to_string();
        let next_coords = b["next"].clone();
        let next_seq = (g.entries.get(&cid).map(|v| v.len()).unwrap_or(0) as i64) + 1;
        if btype.ends_with("leafRecoveryFulfillmentBody") {
            let wb = &b["manifest"]["welcomeBundle"];
            let welcome_id = wb["welcomeId"].as_str().unwrap().to_string();
            let opaque = wb["opaqueWelcome"].clone();
            let snap = b["metadataSnapshot"].clone();
            for del in wb["deliveries"].as_array().cloned().unwrap_or_default() {
                let r_did = del["recipientDid"].as_str().unwrap().to_string();
                let r_dev = del["recipientDeviceId"].as_str().unwrap().to_string();
                g.pending_welcomes
                    .entry((r_did, r_dev))
                    .or_default()
                    .push(json!({
                        "welcomeId": welcome_id,
                        "conversationId": cid,
                        "sequencerDid": ds_did,
                        "transitionSeq": next_seq,
                        "coordinates": next_coords,
                        "opaqueWelcome": opaque,
                        "metadataSnapshot": snap,
                    }));
            }
        }
        g.entries.entry(cid.clone()).or_default().push(json!({
            "seq": next_seq,
            "coordinates": next_coords.clone(),
            "signedRequest": sr,
        }));
        if let Some(st) = g.conversations.get_mut(&cid) {
            st["coordinates"] = next_coords.clone();
        }
        return (
            200,
            json!({ "seq": next_seq, "state": { "coordinates": next_coords } }),
        );
    }
    if target.contains("/xrpc/blue.catbird.chat.sendMessage") {
        let sr = body_json["signedRequest"].clone();
        let b = &sr["body"];
        let cid = b["prior"]["conversationId"].as_str().unwrap().to_string();
        let msg_id = b["messageId"].as_str().unwrap().to_string();
        let seq = (g.entries.get(&cid).map(|v| v.len()).unwrap_or(0) as i64) + 1;
        g.entries.entry(cid).or_default().push(json!({
            "$type": "blue.catbird.chat.defs#applicationMessageEntry",
            "seq": seq,
            "messageId": msg_id,
            "signedRequest": sr,
        }));
        return (200, json!({ "seq": seq }));
    }
    if target.contains("/xrpc/blue.catbird.chat.getConversations") {
        let list: Vec<Value> = g.conversations.values().cloned().collect();
        return (200, json!({ "conversations": list }));
    }
    if target.contains("/xrpc/blue.catbird.chat.getPendingWelcomes") {
        let dev = q.get("actorDeviceId").cloned().unwrap_or_default();
        let found: Vec<Value> = g
            .pending_welcomes
            .iter_mut()
            .filter(|((_, d), _)| d == &dev)
            .flat_map(|(_, v)| std::mem::take(v))
            .collect();
        return (200, json!({ "welcomes": found }));
    }
    if target.contains("/xrpc/blue.catbird.chat.acknowledgeWelcome") {
        let wid = body_json["signedRequest"]["body"]["welcomeId"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        g.acked_welcomes.push(wid);
        return (200, json!({ "acknowledged": true }));
    }
    if target.contains("/xrpc/blue.catbird.chat.getLeafRecoveryInbox") {
        let dev = q.get("actorDeviceId").cloned().unwrap_or_default();
        let owner = g
            .convo_kps
            .keys()
            .find(|(_, d)| d == &dev)
            .map(|(did, _)| did.clone())
            .unwrap_or_default();
        let reqs = g.leaf_recovery_inbox.remove(&owner).unwrap_or_default();
        return (200, json!({ "requests": reqs }));
    }
    if target.contains("/xrpc/blue.catbird.chat.getEntries") {
        let cid = q.get("conversationId").cloned().unwrap_or_default();
        let after: i64 = q.get("afterSeq").and_then(|s| s.parse().ok()).unwrap_or(0);
        let list: Vec<Value> = g
            .entries
            .get(&cid)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter(|e| e["seq"].as_i64().unwrap_or(0) > after)
            .collect();
        return (200, json!({ "entries": list }));
    }
    (200, json!({}))
}

async fn spawn_local_live_ds_server(
    ds_did: &'static str,
) -> (String, Arc<Mutex<LocalLiveDsState>>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind local ds");
    let addr = listener.local_addr().expect("local_addr");
    let base_url = format!("http://{addr}");
    let state = Arc::new(Mutex::new(LocalLiveDsState::default()));
    let state_bg = Arc::clone(&state);
    let base_bg = base_url.clone();

    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let state_conn = Arc::clone(&state_bg);
            let base_conn = base_bg.clone();
            tokio::spawn(async move {
                let mut buf = Vec::with_capacity(8192);
                let mut chunk = [0u8; 4096];
                let mut header_end = None;
                let mut content_len = 0usize;
                loop {
                    let n = match stream.read(&mut chunk).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    buf.extend_from_slice(&chunk[..n]);
                    if header_end.is_none() {
                        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            let hdr_str = String::from_utf8_lossy(&buf[..pos]);
                            for line in hdr_str.lines() {
                                if let Some((k, v)) = line.split_once(':') {
                                    if k.trim().eq_ignore_ascii_case("content-length") {
                                        content_len = v.trim().parse().unwrap_or(0);
                                    }
                                }
                            }
                            header_end = Some(pos + 4);
                        }
                    }
                    if let Some(hend) = header_end {
                        if buf.len() >= hend + content_len {
                            break;
                        }
                    }
                }
                let Some(hend) = header_end else {
                    return;
                };
                let first_line = String::from_utf8_lossy(&buf[..hend])
                    .lines()
                    .next()
                    .unwrap_or_default()
                    .to_string();
                let target = first_line.split_whitespace().nth(1).unwrap_or("/");
                let body = &buf[hend..(hend + content_len).min(buf.len())];
                let (status, resp_json) =
                    handle_ds_http(&state_conn, ds_did, &base_conn, target, body);
                let resp_bytes = serde_json::to_vec(&resp_json).unwrap();
                let reason = match status {
                    200 => "OK",
                    401 => "Unauthorized",
                    _ => "Error",
                };
                let hdr = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    resp_bytes.len()
                );
                let _ = stream.write_all(hdr.as_bytes()).await;
                let _ = stream.write_all(&resp_bytes).await;
            });
        }
    });

    (base_url, state)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn birdaemon_federated_bot_runs_without_nest_dependency_g3() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let responder = Arc::new(EchoResponder {
        seen_prompts: Mutex::new(Vec::new()),
    });

    let cfg = FederatedBotConfig {
        storage_root: tmp.path().to_path_buf(),
        bot_did: "did:plc:birdaemoncleanbot01".to_string(),
        bot_handle: "bird.catbird.blue".to_string(),
        device_id: "dev-birdaemon-01".to_string(),
        home_ds_did: "did:web:mlschat.catbird.blue".to_string(),
        home_ds_endpoint: "https://mlschat.catbird.blue".to_string(),
        pds_endpoint: "https://pds.catbird.blue".to_string(),
        pds_supports_spaces: true,
        granted_oauth_scopes: REQUIRED_LABYRINTH_OAUTH_SCOPES
            .iter()
            .map(|s| (*s).to_string())
            .collect(),
        accept_chat_requests: true,
        reply_to_all_messages: false,
        max_reply_characters: 280,
    };

    // Ensure BIRD_NEST_BASE_URL is NOT set — G3 forbids any Nest requirement!
    std::env::remove_var("BIRD_NEST_BASE_URL");

    let bot = FederatedBirdBot::open_and_enroll(cfg, responder.clone())
        .expect("bot should initialize and enroll on federated mls-ds + Spaces without Nest");
    assert_eq!(bot.account_did(), "did:plc:birdaemoncleanbot01");
    assert!(bot.labyrinth_status().expect("status").backup_enabled);

    // Create an MLS_256_XWING group and process an @mention
    let convo_id = uuid::Uuid::new_v4().to_string();
    let convo = bot
        .create_group(&convo_id, Vec::new(), Some("Aviary Group".to_string()))
        .expect("create X-Wing group");
    assert_eq!(convo.conversation_id, convo_id);

    // Non-mention in group when reply_to_all_messages == false -> ignored
    let ignored = bot
        .handle_incoming_group_text(
            &convo_id,
            "did:plc:alicepeer000001",
            "hello everyone without mention",
        )
        .await
        .expect("non-mention handled");
    assert!(ignored.is_none());

    // @bird.catbird.blue mention -> generates reply and encrypts + queues MLS message with canonical UUIDv4 message_id
    let sent = bot
        .handle_incoming_group_text(
            &convo_id,
            "did:plc:alicepeer000001",
            "hey @bird.catbird.blue what is the weather?",
        )
        .await
        .expect("mention reply")
        .expect("should reply to mention");
    assert!(uuid::Uuid::parse_str(&sent.message_id).is_ok());
    assert!(sent.plaintext_json.contains("chirp reply to:"));

    let messages = bot.list_messages(&convo_id, 20).expect("list messages");
    assert_eq!(messages.len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn birdaemon_live_local_ds_welcome_mention_and_encrypted_reply_roundtrip() {
    const DS_DID: &str = "did:web:localds.catbird.test";
    const ALICE_DID: &str = "did:plc:alicebirdlivepeer234567a";
    const BOT_DID: &str = "did:plc:birdaemonlivebot234567bc";

    let (base_url, ds_state) = spawn_local_live_ds_server(DS_DID).await;
    let tmp = tempfile::tempdir().expect("tempdir");
    let scopes: Vec<String> = REQUIRED_LABYRINTH_OAUTH_SCOPES
        .iter()
        .map(|s| (*s).to_string())
        .collect();

    // 1. Enroll BIRDaemon against live 127.0.0.1 mls-ds + PDS HTTP server
    let responder = Arc::new(EchoResponder {
        seen_prompts: Mutex::new(Vec::new()),
    });
    let bot_cfg = FederatedBotConfig {
        storage_root: tmp.path().join("bot"),
        bot_did: BOT_DID.to_string(),
        bot_handle: "bird.catbird.blue".to_string(),
        device_id: uuid::Uuid::new_v4().to_string(),
        home_ds_did: DS_DID.to_string(),
        home_ds_endpoint: base_url.clone(),
        pds_endpoint: base_url.clone(),
        pds_supports_spaces: true,
        granted_oauth_scopes: scopes.clone(),
        accept_chat_requests: true,
        reply_to_all_messages: false,
        max_reply_characters: 280,
    };
    let bot = Arc::new(
        FederatedBirdBot::open_and_enroll_with_tokens(
            bot_cfg,
            responder,
            Some("bot-ds-token".to_string()),
            Some("bot-pds-token".to_string()),
        )
        .expect("enroll BIRDaemon against live 127.0.0.1 server"),
    );

    // 2. Enroll Alice peer SDK client against the same live 127.0.0.1 server
    let alice_dir = tmp.path().join("alice");
    let alice_ks = Arc::new(BirdKeyStore::new(&alice_dir).expect("alice keystore"));
    let alice_transport = Arc::new(BirdPlatformTransport::new(base_url.clone(), true));
    alice_transport.set_tokens(
        Some("alice-ds-token".to_string()),
        Some("alice-pds-token".to_string()),
    );
    let alice = CatbirdMlsClient::open(
        CatbirdMlsClientConfig {
            storage_root: alice_dir.to_string_lossy().to_string(),
            account_did: ALICE_DID.to_string(),
            device_id: uuid::Uuid::new_v4().to_string(),
            home_ds_did: DS_DID.to_string(),
            home_ds_endpoint: base_url.clone(),
            pds_endpoint: base_url,
        },
        alice_ks,
        alice_transport as Arc<dyn PlatformTransport>,
        None,
    )
    .expect("open alice");
    let scopes_cl = scopes.clone();
    let alice_cl = Arc::clone(&alice);
    tokio::task::spawn_blocking(move || alice_cl.enroll_device(&scopes_cl))
        .await
        .unwrap()
        .expect("enroll alice");

    // 3. Alice creates group inviting BIRDaemon -> bot accepts -> Alice fulfills Welcome + sends @mention
    let convo_uuid = uuid::Uuid::new_v4().to_string();
    let cid_cl = convo_uuid.clone();
    let alice_cl = Arc::clone(&alice);
    tokio::task::spawn_blocking(move || {
        alice_cl.create_group(
            &cid_cl,
            DS_DID,
            vec![BOT_DID.to_string()],
            Some("Live Aviary".to_string()),
            None,
        )
    })
    .await
    .unwrap()
    .expect("alice create_group with bot");

    // Bot tick 1: accepts pending group invite (leaf recovery request queued for Alice)
    let first_replies = bot.sync_and_reply().await.expect("bot tick 1");
    assert!(first_replies.is_empty());

    // Alice syncs leaf recovery inbox -> posts X-Wing Welcome for BIRDaemon, then sends @mention
    let mention_msg_id = uuid::Uuid::new_v4().to_string();
    let cid_cl = convo_uuid.clone();
    let mid_cl = mention_msg_id.clone();
    let alice_cl = Arc::clone(&alice);
    tokio::task::spawn_blocking(move || {
        alice_cl.sync()?;
        alice_cl.send_message(&cid_cl, &mid_cl, "hello @bird.catbird.blue live check!")
    })
    .await
    .unwrap()
    .expect("alice fulfill welcome and send @mention");

    // 4. Bot tick 2: joins Welcome, verifies Alice I4 device record, decrypts @mention, and posts encrypted reply!
    let replies = bot
        .sync_and_reply()
        .await
        .expect("bot tick 2 sync_and_reply");
    assert_eq!(replies.len(), 1);
    assert!(uuid::Uuid::parse_str(&replies[0].message_id).is_ok());
    assert!(replies[0]
        .plaintext_json
        .contains("chirp reply to: hello @bird.catbird.blue live check!"));
    assert_eq!(ds_state.lock().unwrap().acked_welcomes.len(), 1);

    // Idempotency: Bot tick 3 must not re-reply to the same message
    let dup_replies = bot.sync_and_reply().await.expect("bot tick 3 idempotency");
    assert!(dup_replies.is_empty());

    // 5. Alice syncs from live 127.0.0.1 mls-ds and decrypts BIRDaemon's X-Wing reply!
    let cid_cl = convo_uuid.clone();
    let alice_cl = Arc::clone(&alice);
    let alice_msgs = tokio::task::spawn_blocking(move || {
        alice_cl.sync()?;
        alice_cl.list_messages(&cid_cl, None, 20)
    })
    .await
    .unwrap()
    .expect("alice sync bot reply");

    assert_eq!(alice_msgs.len(), 2);
    assert!(alice_msgs.iter().any(|m| {
        m.sender_did == BOT_DID
            && m.plaintext_json
                .contains("chirp reply to: hello @bird.catbird.blue live check!")
    }));
}
