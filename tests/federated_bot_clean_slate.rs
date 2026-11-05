use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use bird_daemon::bot::{
    BirdKeyStore, BirdPlatformTransport, BotLlmResponder, FederatedBirdBot, FederatedBotConfig,
};
use catbird_mls::client::{
    CatbirdMlsClient, CatbirdMlsClientConfig, PlatformHttpRequest, PlatformTransport,
    REQUIRED_LABYRINTH_OAUTH_SCOPES,
};
use labyrinth_protocol::receipt::{sign_sequencer_receipt, SequencerReceiptPayload};
use p256::ecdsa::SigningKey as P256SigningKey;
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

struct LocalLiveDsState {
    receipt_sk: P256SigningKey,
    pds_records: BTreeMap<(String, String, String), Value>,
    convo_kps: BTreeMap<(String, String), Vec<Value>>,
    dr_keys: BTreeMap<String, Vec<(String, Value, Value)>>,
    conversations: BTreeMap<String, Value>,
    entries: BTreeMap<String, Vec<Value>>,
    pending_welcomes: BTreeMap<(String, String), Vec<Value>>,
    leaf_recovery_inbox: BTreeMap<String, Vec<Value>>,
    acked_welcomes: Vec<String>,
    acked_watermarks: BTreeMap<(String, String), i64>,
}

impl LocalLiveDsState {
    fn new() -> Self {
        Self {
            receipt_sk: P256SigningKey::random(&mut rand::rngs::OsRng),
            pds_records: BTreeMap::new(),
            convo_kps: BTreeMap::new(),
            dr_keys: BTreeMap::new(),
            conversations: BTreeMap::new(),
            entries: BTreeMap::new(),
            pending_welcomes: BTreeMap::new(),
            leaf_recovery_inbox: BTreeMap::new(),
            acked_welcomes: Vec::new(),
            acked_watermarks: BTreeMap::new(),
        }
    }

    fn receipt_jwk_did_doc(&self, ds_did: &str) -> Value {
        let pt = self.receipt_sk.verifying_key().to_encoded_point(false);
        let x = URL_SAFE_NO_PAD.encode(pt.x().unwrap());
        let y = URL_SAFE_NO_PAD.encode(pt.y().unwrap());
        json!({
            "id": ds_did,
            "verificationMethod": [{
                "id": format!("{ds_did}#mls-receipt-1"),
                "type": "JsonWebKey2020",
                "controller": ds_did,
                "publicKeyJwk": {
                    "kty": "EC",
                    "crv": "P-256",
                    "x": x,
                    "y": y
                }
            }]
        })
    }
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

    let mut g = state.lock().unwrap();

    if target.ends_with("/.well-known/did.json")
        || (target.contains("/xrpc/com.atproto.identity.resolveDid")
            && q.get("did").map(String::as_str) == Some(ds_did))
    {
        return (200, g.receipt_jwk_did_doc(ds_did));
    }

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
        let actor_did = b["actorDid"].as_str().unwrap().to_string();
        let actor_dev = b["actorDeviceId"].as_str().unwrap().to_string();
        let gen = b["prior"]["generation"].as_u64().unwrap_or(0);
        let epoch = b["prior"]["epoch"].as_u64().unwrap_or(0);
        let group_id = catbird_mls::client::chat_wire::json_bytes(&b["prior"]["groupId"]).unwrap();
        let commit_arr: [u8; 32] =
            catbird_mls::client::chat_wire::json_bytes(&b["aad"]["archiveCommitment"])
                .unwrap()
                .try_into()
                .unwrap();
        let seq = (g.entries.get(&cid).map(|v| v.len()).unwrap_or(0) as u64) + 1;
        let payload = SequencerReceiptPayload {
            sequencer_did: ds_did.to_string(),
            conversation_id: cid.clone(),
            group_id,
            epoch,
            sender_device_did_url: format!("{actor_did}#{actor_dev}"),
            entry_id: msg_id.clone(),
            archive_commitment: commit_arr,
            seq,
            issued_at_ms: 1_762_000_000_000,
        };
        let kid_full = format!("{ds_did}#mls-receipt-1");
        let signed = sign_sequencer_receipt(&g.receipt_sk, &kid_full, &payload).unwrap();
        let rcpt_json = json!({
            "kid": signed.key_id,
            "sequencerDid": signed.payload.sequencer_did,
            "conversationId": signed.payload.conversation_id,
            "generation": gen,
            "groupId": { "$bytes": STANDARD.encode(&signed.payload.group_id) },
            "epoch": signed.payload.epoch,
            "seq": signed.payload.seq,
            "entryId": signed.payload.entry_id,
            "senderDid": actor_did,
            "senderDeviceId": actor_dev,
            "archiveCommitment": { "$bytes": STANDARD.encode(signed.payload.archive_commitment) },
            "issuedAtMs": signed.payload.issued_at_ms,
            "signature": { "$bytes": STANDARD.encode(signed.signature) },
        });
        g.entries.entry(cid).or_default().push(json!({
            "$type": "blue.catbird.chat.defs#applicationMessageEntry",
            "seq": seq,
            "messageId": msg_id,
            "signedRequest": sr,
            "sequencerReceipt": rcpt_json.clone(),
        }));
        return (200, json!({ "seq": seq, "sequencerReceipt": rcpt_json }));
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
    if target.contains("/xrpc/blue.catbird.chat.acknowledgeEntries") {
        let cid = body_json["conversationId"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        let dev = body_json["actorDeviceId"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        let wm = body_json["upToSeq"].as_i64().unwrap_or(0);
        g.acked_watermarks.insert((cid, dev), wm);
        return (200, json!({ "watermarkSeq": wm }));
    }
    (404, json!({ "error": "NotFound", "target": target }))
}

async fn spawn_local_live_ds_server(
    ds_did: &'static str,
) -> (String, Arc<Mutex<LocalLiveDsState>>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind local ds");
    let addr = listener.local_addr().expect("local_addr");
    let base_url = format!("http://{addr}");
    let state = Arc::new(Mutex::new(LocalLiveDsState::new()));
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

/// Live path (catbird-mls has no implicit offline create/send): a bare `did:plc`, a UUIDv4
/// device and the local `mls-ds` + PDS stand-in, whose sends return signed I13 receipts.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn birdaemon_federated_bot_runs_without_nest_dependency_g3() {
    const DS_DID: &str = "did:web:mlschat.catbird.blue";
    const BOT_DID: &str = "did:plc:birdaemoncleanbotaaaaaaa";

    let (base_url, _ds_state) = spawn_local_live_ds_server(DS_DID).await;
    let tmp = tempfile::tempdir().expect("tempdir");
    let responder = Arc::new(EchoResponder {
        seen_prompts: Mutex::new(Vec::new()),
    });

    let cfg = FederatedBotConfig {
        storage_root: tmp.path().to_path_buf(),
        bot_did: BOT_DID.to_string(),
        bot_handle: "bird.catbird.blue".to_string(),
        device_id: uuid::Uuid::new_v4().to_string(),
        home_ds_did: DS_DID.to_string(),
        home_ds_endpoint: base_url.clone(),
        pds_endpoint: base_url,
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
    assert_eq!(bot.account_did(), BOT_DID);
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
    let alice_transport = Arc::new(BirdPlatformTransport::new(base_url.clone()));
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

/// Reads one HTTP/1.1 request (headers plus `Content-Length` body) so the reply is not reset,
/// and returns its request line and headers (empty if the client went away first).
fn read_request(stream: &mut std::net::TcpStream) -> String {
    use std::io::Read as _;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..end]).into_owned();
            let len = head
                .to_ascii_lowercase()
                .lines()
                .find_map(|l| l.strip_prefix("content-length:"))
                .and_then(|v| v.trim().parse::<usize>().ok())
                .unwrap_or(0);
            if buf.len() >= end + 4 + len {
                return head;
            }
        }
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return String::new(),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
}

/// The production (non-loopback-prefixed) transport path: a refused connection or a timeout is
/// an error, never a fabricated `200 {}`; each call makes exactly one attempt, so an
/// ambiguous POST is not resent; real statuses (5xx included) pass through byte-for-byte and a
/// caller retry after recovery lands exactly once.
#[test]
fn birdaemon_transport_network_failures_are_errors_without_duplicate_effect() {
    use std::io::Write as _;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    // `127.1` is 127.0.0.1 but does not match the transport's `http://127.0.0.1` local
    // prefix, so the request takes the path a remote PDS / mls-ds request takes.
    let post = |base: &str| PlatformHttpRequest {
        method: "POST".to_string(),
        url: format!("{base}/xrpc/blue.catbird.chat.sendMessage"),
        headers: Vec::new(),
        body: Some(br#"{"messageId":"m1"}"#.to_vec()),
    };

    // 1. Connection refused: nothing listens on the port.
    let refused_port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let refused_base = format!("http://127.1:{refused_port}");
    let transport = BirdPlatformTransport::new(refused_base.clone());
    let err = transport
        .execute_http(post(&refused_base))
        .expect_err("a refused connection must not look like an HTTP response");
    assert!(err.to_string().contains("HTTP transport failed"), "{err}");

    // 2. Timeout after the server received the request: one attempt, bounded by the client
    // timeout, and no resend of a POST whose effect is unknown.
    let hung = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let hung_base = format!("http://127.1:{}", hung.local_addr().unwrap().port());
    let hung_hits = Arc::new(AtomicUsize::new(0));
    let hits = Arc::clone(&hung_hits);
    std::thread::spawn(move || {
        for mut stream in hung.incoming().flatten() {
            let hits = Arc::clone(&hits);
            std::thread::spawn(move || {
                read_request(&mut stream);
                hits.fetch_add(1, Ordering::SeqCst);
                // Hold the connection open without answering until the client gives up.
                read_request(&mut stream);
            });
        }
    });
    let started = Instant::now();
    let err = BirdPlatformTransport::new(hung_base.clone())
        .execute_http(post(&hung_base))
        .expect_err("a timeout must not look like an HTTP response");
    assert!(err.to_string().contains("HTTP transport failed"), "{err}");
    assert!(
        started.elapsed() < Duration::from_secs(20),
        "unbounded wait"
    );
    assert_eq!(
        hung_hits.load(Ordering::SeqCst),
        1,
        "timed-out POST was resent"
    );

    // 3. The service recovers on the refused port: a 5xx passes through unchanged, then the
    // caller's retry succeeds; each call is exactly one request.
    let recovered = std::net::TcpListener::bind(("127.0.0.1", refused_port)).unwrap();
    let served = Arc::new(AtomicUsize::new(0));
    let served_bg = Arc::clone(&served);
    std::thread::spawn(move || {
        let replies = [
            (
                "503 Service Unavailable",
                r#"{"error":"CapacityUnavailable"}"#,
            ),
            ("200 OK", r#"{"accepted":"m1"}"#),
        ];
        for (mut stream, (status, body)) in recovered.incoming().flatten().zip(replies) {
            read_request(&mut stream);
            served_bg.fetch_add(1, Ordering::SeqCst);
            let _ = write!(
                stream,
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
        }
    });
    let unavailable = transport
        .execute_http(post(&refused_base))
        .expect("503 response");
    assert_eq!(unavailable.status, 503);
    assert_eq!(unavailable.body, br#"{"error":"CapacityUnavailable"}"#);
    let ok = transport
        .execute_http(post(&refused_base))
        .expect("retry after recovery");
    assert_eq!(ok.status, 200);
    assert_eq!(ok.body, br#"{"accepted":"m1"}"#);
    assert_eq!(
        served.load(Ordering::SeqCst),
        2,
        "each call must be exactly one request"
    );
}

/// A DS call that needs a minted service-auth token fails when the PDS cannot be reached for
/// `getServiceAuth`; it never goes to the DS without the token it needed.
#[test]
fn birdaemon_service_auth_mint_network_failure_is_an_error_and_sends_nothing() {
    use std::io::Write as _;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let refused_pds = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let ds = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let ds_base = format!("http://127.1:{}", ds.local_addr().unwrap().port());
    let ds_hits = Arc::new(AtomicUsize::new(0));
    let hits = Arc::clone(&ds_hits);
    std::thread::spawn(move || {
        for mut stream in ds.incoming().flatten() {
            read_request(&mut stream);
            hits.fetch_add(1, Ordering::SeqCst);
            let _ = write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}"
            );
        }
    });

    // Different ports, so the home-DS URL is never within the PDS endpoint.
    let transport = BirdPlatformTransport::with_identity(
        format!("http://127.0.0.1:{refused_pds}"),
        ds_base.clone(),
        "did:plc:birdaemoncleanbotaaaaaaa".to_string(),
        "did:web:ds.example".to_string(),
    );
    let err = transport
        .execute_http(PlatformHttpRequest {
            method: "POST".to_string(),
            url: format!("{ds_base}/xrpc/blue.catbird.chat.sendMessage"),
            headers: Vec::new(),
            body: Some(br#"{"messageId":"m1"}"#.to_vec()),
        })
        .expect_err("an unreachable PDS must not send the DS call without its token");
    assert!(err.to_string().contains("mint getServiceAuth"), "{err}");
    assert_eq!(
        ds_hits.load(Ordering::SeqCst),
        0,
        "DS call sent without service auth"
    );
}

/// Bearers go only to their own endpoint, compared as parsed scheme, host and port plus a path
/// boundary: the PDS bearer to the PDS endpoint, the service-auth bearer to the home `mls-ds`
/// endpoint, and nothing to a sibling path, the origin root or a port whose digits extend the
/// endpoint's (a raw string prefix matched each of those).
#[test]
fn birdaemon_transport_sends_bearers_only_to_their_exact_endpoints() {
    use std::io::Write as _;

    // One local server records the request line and Authorization header of every request.
    let server = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = server.local_addr().unwrap().port();
    let seen = Arc::new(std::sync::Mutex::new(Vec::<(String, Option<String>)>::new()));
    let log = Arc::clone(&seen);
    std::thread::spawn(move || {
        for mut stream in server.incoming().flatten() {
            let head = read_request(&mut stream);
            let mut lines = head.lines();
            let path = lines
                .next()
                .unwrap_or_default()
                .split(' ')
                .nth(1)
                .unwrap_or_default()
                .to_string();
            let auth = lines.find_map(|l| {
                l.split_once(':')
                    .filter(|(name, _)| name.eq_ignore_ascii_case("authorization"))
                    .map(|(_, value)| value.trim().to_string())
            });
            log.lock().unwrap().push((path, auth));
            let _ = write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}"
            );
        }
    });
    // `127.1` parses to 127.0.0.1 without matching the transport's `http://127.0.0.1` loopback
    // prefix, so no test placeholder token is involved.
    let origin = format!("http://127.1:{port}");
    let get = |transport: &BirdPlatformTransport, url: String| {
        transport
            .execute_http(PlatformHttpRequest {
                method: "GET".to_string(),
                url,
                headers: Vec::new(),
                body: None,
            })
            .expect("local server answers");
    };

    // The service-auth token is JWT-shaped, so no getServiceAuth mint is attempted.
    let transport = BirdPlatformTransport::with_identity(
        format!("{origin}/pds"),
        format!("{origin}/ds/"),
        "did:plc:birdaemoncleanbotaaaaaaa".to_string(),
        "did:web:ds.example".to_string(),
    );
    transport.set_tokens(
        Some("ds.service.jwt".to_string()),
        Some("pds-oauth".to_string()),
    );
    get(
        &transport,
        format!("{origin}/pds/xrpc/com.atproto.repo.getRecord"),
    );
    get(
        &transport,
        format!("{origin}/ds/xrpc/blue.catbird.chat.getConversations"),
    );
    get(
        &transport,
        format!("{origin}/pds-other/xrpc/com.atproto.repo.getRecord"),
    );
    get(
        &transport,
        format!("{origin}/ds-other/xrpc/blue.catbird.chat.getConversations"),
    );
    get(
        &transport,
        format!("{origin}/xrpc/blue.catbird.chat.getConversations"),
    );

    // Endpoints on a port whose digits are a prefix of the server's port.
    let short = format!("http://127.1:{}", port / 10);
    let transport = BirdPlatformTransport::with_identity(
        short.clone(),
        short,
        "did:plc:birdaemoncleanbotaaaaaaa".to_string(),
        "did:web:ds.example".to_string(),
    );
    transport.set_tokens(
        Some("ds.service.jwt".to_string()),
        Some("pds-oauth".to_string()),
    );
    get(
        &transport,
        format!("{origin}/xrpc/blue.catbird.chat.getConversations"),
    );

    let bearer = |token: &str| Some(format!("Bearer {token}"));
    assert_eq!(
        *seen.lock().unwrap(),
        vec![
            (
                "/pds/xrpc/com.atproto.repo.getRecord".to_string(),
                bearer("pds-oauth")
            ),
            (
                "/ds/xrpc/blue.catbird.chat.getConversations".to_string(),
                bearer("ds.service.jwt")
            ),
            (
                "/pds-other/xrpc/com.atproto.repo.getRecord".to_string(),
                None
            ),
            (
                "/ds-other/xrpc/blue.catbird.chat.getConversations".to_string(),
                None
            ),
            ("/xrpc/blue.catbird.chat.getConversations".to_string(), None),
            ("/xrpc/blue.catbird.chat.getConversations".to_string(), None),
        ]
    );
}
