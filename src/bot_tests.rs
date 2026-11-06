use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use crate::bot::{
    BirdKeyStore, BirdPlatformTransport, BotLlmResponder, FederatedBirdBot, FederatedBotConfig,
};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
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

fn now_epoch_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn jwt_with_alg(claims: Value, algorithm: &str) -> String {
    let header = URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&json!({ "alg": algorithm, "typ": "JWT" })).unwrap());
    let claims = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
    let signature = URL_SAFE_NO_PAD.encode([1u8; 64]);
    format!("{header}.{claims}.{signature}")
}

fn jwt_from_claims(claims: Value) -> String {
    jwt_with_alg(claims, "ES256")
}

fn service_auth_jwt(issuer: &str, audience: &str, lxm: &str, expiry: i64) -> String {
    jwt_from_claims(json!({
        "iss": issuer,
        "aud": audience,
        "lxm": lxm,
        "exp": expiry,
    }))
}

fn handle_ds_http(
    state: &Mutex<LocalLiveDsState>,
    ds_did: &str,
    base_url: &str,
    target: &str,
    body: &[u8],
    authorization: Option<&str>,
) -> (u16, Value) {
    let q = query_map(target);
    let body_json: Value = serde_json::from_slice(body).unwrap_or_else(|_| json!({}));

    let mut g = state.lock().unwrap();

    if target.contains("/xrpc/com.atproto.server.getServiceAuth") {
        let issuer = authorization
            .and_then(|value| value.strip_prefix("Bearer "))
            .unwrap_or_default();
        let audience = q.get("aud").cloned().unwrap_or_default();
        let lxm = q.get("lxm").cloned().unwrap_or_default();
        return (
            200,
            json!({
                "token": service_auth_jwt(
                    issuer,
                    &audience,
                    &lxm,
                    now_epoch_seconds() + 60,
                )
            }),
        );
    }

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
        let mut participants = b["manifest"]["participants"].clone();
        let creator_did = b["manifest"]["actorLeaf"]["userDid"].as_str();
        if let Some(items) = participants.as_array_mut() {
            for participant in items {
                participant["leafCount"] =
                    json!(usize::from(participant["userDid"].as_str() == creator_did));
            }
        }
        g.conversations.insert(
            cid.clone(),
            json!({
                "conversationKind": "group",
                "sequencerDid": ds_did,
                "coordinates": coords.clone(),
                "cipherSuite": "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519",
                "participants": participants,
                "leaves": [b["manifest"]["actorLeaf"]],
                "metadataSnapshot": b["metadataSnapshot"],
                "snapshotSeq": 1,
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
        let requested_at = b["signedAt"].clone();
        let expires_at = (chrono::DateTime::parse_from_rfc3339(requested_at.as_str().unwrap())
            .unwrap()
            + chrono::Duration::minutes(5))
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let kp = g
            .convo_kps
            .get_mut(&(invitee_did.clone(), invitee_dev.clone()))
            .and_then(|v| v.pop())
            .expect("invitee must have conversation KP");
        let kp_ref = kp["keyPackageRef"].clone();
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
        g.conversations.get_mut(&cid).unwrap()["snapshotSeq"] = json!(next_seq);
        g.leaf_recovery_inbox
            .entry(inviter_did)
            .or_default()
            .push(json!({
                "$type": "blue.catbird.chat.defs#leafRecoveryView",
                "conversationId": cid,
                "recoveryRequestId": rec_req_id,
                "requesterDid": invitee_did,
                "requesterDeviceId": invitee_dev,
                "recoveryKind": "add",
                "boundCoordinate": next_coords,
                "status": "open",
                "requestedAt": requested_at,
                "expiresAt": expires_at,
                "reservation": {
                    "conversationId": cid,
                    "recoveryRequestId": rec_req_id,
                    "boundCoordinate": next_coords,
                    "requesterDid": invitee_did,
                    "requesterDeviceId": invitee_dev,
                    "requesterKeyId": b["keyId"],
                    "requesterAuthGeneration": b["authGeneration"],
                    "keyPackageRef": kp_ref,
                    "cipherSuite": "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519",
                    "purpose": "leafRecovery",
                    "status": "active",
                    "expiresAt": expires_at,
                    "keyPackage": kp,
                },
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
        let fulfilled_recovery_id = b["recoveryRequestId"].as_str().map(str::to_owned);
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
            st["snapshotSeq"] = json!(next_seq);
            if let Some(snapshot) = b.get("metadataSnapshot") {
                st["metadataSnapshot"] = snapshot.clone();
            }
            for change in b["manifest"]["leafChanges"]
                .as_array()
                .into_iter()
                .flatten()
            {
                if change["$type"] == "blue.catbird.chat.defs#addLeafByRecovery" {
                    st["leaves"].as_array_mut().unwrap().push(json!({
                        "userDid": change["userDid"],
                        "deviceId": change["deviceId"],
                        "leafOrigin": "recovery",
                    }));
                }
            }
            let leaves = st["leaves"].as_array().cloned().unwrap_or_default();
            if let Some(participants) = st["participants"].as_array_mut() {
                for participant in participants {
                    participant["leafCount"] = json!(leaves
                        .iter()
                        .filter(|leaf| leaf["userDid"] == participant["userDid"])
                        .count());
                }
            }
        }
        if let Some(fulfilled_recovery_id) = fulfilled_recovery_id {
            for requests in g.leaf_recovery_inbox.values_mut() {
                requests.retain(|request| {
                    request["recoveryRequestId"].as_str() != Some(&fulfilled_recovery_id)
                });
            }
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
        let received_at = b["signedAt"].clone();
        let seq = (g.entries.get(&cid).map(|v| v.len()).unwrap_or(0) as u64) + 1;
        let entry_id = uuid::Uuid::new_v4().to_string();
        let payload = SequencerReceiptPayload {
            sequencer_did: ds_did.to_string(),
            conversation_id: cid.clone(),
            group_id,
            epoch,
            sender_device_did_url: format!("{actor_did}#{actor_dev}"),
            entry_id: entry_id.clone(),
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
        let entry = json!({
            "$type": "blue.catbird.chat.defs#applicationEntry",
            "entryId": entry_id,
            "conversationId": cid.clone(),
            "seq": seq,
            "signedRequest": sr,
            "sequencerReceipt": rcpt_json.clone(),
            "receivedAt": received_at,
        });
        g.entries.entry(cid).or_default().push(entry.clone());
        return (
            200,
            json!({ "entry": entry, "sequencerReceipt": rcpt_json }),
        );
    }
    if target.contains("/xrpc/blue.catbird.chat.getConversationState") {
        let cid = q.get("conversationId").cloned().unwrap_or_default();
        let dev = q.get("actorDeviceId").cloned().unwrap_or_default();
        let Some(state) = g.conversations.get(&cid).cloned() else {
            return (400, json!({ "error": "ConversationNotFound" }));
        };
        let owner = g
            .convo_kps
            .keys()
            .find(|(_, device)| device == &dev)
            .map(|(did, _)| did.clone())
            .unwrap_or_default();
        let pending_leaf_recoveries = g
            .leaf_recovery_inbox
            .get(&owner)
            .into_iter()
            .flatten()
            .filter(|request| {
                request["conversationId"].as_str() == Some(&cid)
                    && request["requesterDeviceId"].as_str() != Some(&dev)
                    && request["status"] == "open"
                    && request["boundCoordinate"] == state["coordinates"]
            })
            .cloned()
            .collect::<Vec<_>>();
        return (
            200,
            json!({
                "state": state,
                "pendingLeafRecoveryRequests": pending_leaf_recoveries,
                "pendingResetRequests": [],
                "pendingLeaveRequests": [],
                "accountDeletions": [],
            }),
        );
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
        let reqs = g
            .leaf_recovery_inbox
            .get(&owner)
            .cloned()
            .unwrap_or_default();
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
                let headers = String::from_utf8_lossy(&buf[..hend]);
                let first_line = headers.lines().next().unwrap_or_default().to_string();
                let authorization = headers.lines().find_map(|line| {
                    line.split_once(':')
                        .filter(|(name, _)| name.eq_ignore_ascii_case("authorization"))
                        .map(|(_, value)| value.trim().to_string())
                });
                let target = first_line.split_whitespace().nth(1).unwrap_or("/");
                let body = &buf[hend..(hend + content_len).min(buf.len())];
                let (status, resp_json) = handle_ds_http(
                    &state_conn,
                    ds_did,
                    &base_conn,
                    target,
                    body,
                    authorization.as_deref(),
                );
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

    let bot = FederatedBirdBot::open_and_enroll_with_pds_token_for_test(
        cfg,
        responder.clone(),
        Some(BOT_DID.into()),
    )
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
        FederatedBirdBot::open_and_enroll_with_pds_token_for_test(
            bot_cfg,
            responder,
            Some(BOT_DID.to_string()),
        )
        .expect("enroll BIRDaemon against live 127.0.0.1 server"),
    );

    // 2. Enroll Alice peer SDK client against the same live 127.0.0.1 server
    let alice_dir = tmp.path().join("alice");
    let alice_ks = Arc::new(BirdKeyStore::new(&alice_dir).expect("alice keystore"));
    let alice_transport = Arc::new(
        BirdPlatformTransport::with_identity_for_test(
            base_url.clone(),
            base_url.clone(),
            ALICE_DID.to_string(),
            DS_DID.to_string(),
        )
        .unwrap(),
    );
    alice_transport
        .set_pds_oauth_token(Some(ALICE_DID.to_string()))
        .unwrap();
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
    let bot_message_count = bot
        .list_messages(&convo_uuid, 20)
        .map(|messages| messages.len());
    let (acked, pending_welcomes, server_entries) = {
        let state = ds_state.lock().unwrap();
        (
            state.acked_welcomes.len(),
            state.pending_welcomes.values().map(Vec::len).sum::<usize>(),
            state.entries.get(&convo_uuid).map(Vec::len),
        )
    };
    assert_eq!(
        replies.len(),
        1,
        "acked={acked} pending_welcomes={pending_welcomes} server_entries={server_entries:?} bot_messages={bot_message_count:?}"
    );
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

fn raw_http_response(status: &str, body: &[u8], declared_length: Option<usize>) -> Vec<u8> {
    let mut response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        declared_length.unwrap_or(body.len())
    )
    .into_bytes();
    response.extend_from_slice(body);
    response
}

#[test]
fn birdaemon_pds_oauth_is_never_accepted_for_a_ds_nsid() {
    let transport = BirdPlatformTransport::new_for_test("http://127.0.0.1:1".to_string()).unwrap();
    transport
        .set_pds_oauth_token(Some("app-password-or-pds-oauth".to_string()))
        .unwrap();
    let error = transport
        .execute_http(PlatformHttpRequest {
            method: "POST".to_string(),
            url: "http://127.0.0.1:1/xrpc/blue.catbird.chat.sendMessage".to_string(),
            headers: Vec::new(),
            body: Some(b"{}".to_vec()),
        })
        .expect_err("a PDS credential must not be used as home-DS service auth");
    assert!(
        error
            .to_string()
            .contains("outside the configured home DS endpoint"),
        "{error}"
    );
}

/// A refused connection or timeout is an error, never a fabricated success. Each call makes one
/// attempt, so an ambiguous POST is not resent; real statuses pass through byte-for-byte.
#[test]
fn birdaemon_transport_network_failures_are_errors_without_duplicate_effect() {
    use std::io::Write as _;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    let post = |base: &str| PlatformHttpRequest {
        method: "POST".to_string(),
        url: format!("{base}/xrpc/com.atproto.repo.putRecord"),
        headers: Vec::new(),
        body: Some(br#"{"messageId":"m1"}"#.to_vec()),
    };

    let refused_port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let refused_base = format!("http://127.0.0.1:{refused_port}");
    let transport = BirdPlatformTransport::new_for_test(refused_base.clone()).unwrap();
    let error = transport
        .execute_http(post(&refused_base))
        .expect_err("a refused connection must not look like an HTTP response");
    assert!(
        error.to_string().contains("HTTP transport failed"),
        "{error}"
    );

    let hung = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let hung_base = format!("http://127.0.0.1:{}", hung.local_addr().unwrap().port());
    let hung_hits = Arc::new(AtomicUsize::new(0));
    let hits = Arc::clone(&hung_hits);
    std::thread::spawn(move || {
        for mut stream in hung.incoming().flatten() {
            let hits = Arc::clone(&hits);
            std::thread::spawn(move || {
                read_request(&mut stream);
                hits.fetch_add(1, Ordering::SeqCst);
                read_request(&mut stream);
            });
        }
    });
    let started = Instant::now();
    let error = BirdPlatformTransport::new_for_test(hung_base.clone())
        .unwrap()
        .execute_http(post(&hung_base))
        .expect_err("a timeout must not look like an HTTP response");
    assert!(
        error.to_string().contains("HTTP transport failed"),
        "{error}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(20),
        "unbounded wait"
    );
    assert_eq!(
        hung_hits.load(Ordering::SeqCst),
        1,
        "timed-out POST was resent"
    );

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
            let _ = stream.write_all(raw_http_response(status, body.as_bytes(), None).as_slice());
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

/// A DS call never falls back to its PDS OAuth token when service-auth minting cannot connect.
#[test]
fn birdaemon_service_auth_mint_network_failure_is_retryable_and_sends_nothing() {
    let refused_pds = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let ds = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let ds_base = format!("http://127.0.0.1:{}", ds.local_addr().unwrap().port());
    let transport = BirdPlatformTransport::with_identity_for_test(
        format!("http://127.0.0.1:{refused_pds}"),
        ds_base.clone(),
        "did:plc:birdaemoncleanbotaaaaaaa".to_string(),
        "did:web:ds.example".to_string(),
    )
    .unwrap();
    transport
        .set_pds_oauth_token(Some("pds-oauth-not-ds-auth".to_string()))
        .unwrap();

    let error = transport
        .execute_http(PlatformHttpRequest {
            method: "POST".to_string(),
            url: format!("{ds_base}/xrpc/blue.catbird.chat.sendMessage"),
            headers: Vec::new(),
            body: Some(br#"{"messageId":"m1"}"#.to_vec()),
        })
        .expect_err("an unreachable PDS must abort before the DS request");
    assert!(
        error.to_string().contains("retryable service-auth mint"),
        "{error}"
    );
    ds.set_nonblocking(true).unwrap();
    match ds.accept() {
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
        other => panic!("DS was contacted without a minted service token: {other:?}"),
    }
}

/// Every mint failure class aborts the DS request while preserving a retryable transport error.
#[test]
fn birdaemon_service_auth_mint_rejects_status_body_json_missing_and_invalid_claims() {
    use std::io::Write as _;

    const ISSUER: &str = "did:plc:birdaemoncleanbotaaaaaaa";
    const AUDIENCE: &str = "did:web:ds.example#atproto_mls";
    const LXM: &str = "blue.catbird.chat.sendMessage";
    let valid_claims = || {
        json!({
            "iss": ISSUER,
            "aud": AUDIENCE,
            "lxm": LXM,
            "exp": now_epoch_seconds() + 60,
        })
    };
    let token_body = |token: String| serde_json::to_vec(&json!({ "token": token })).unwrap();
    let mut missing_claim = valid_claims();
    missing_claim.as_object_mut().unwrap().remove("lxm");
    let mut wrong_issuer = valid_claims();
    wrong_issuer["iss"] = json!("did:plc:someoneelse");
    let mut wrong_audience = valid_claims();
    wrong_audience["aud"] = json!("did:web:other.example#atproto_mls");
    let mut wrong_lxm = valid_claims();
    wrong_lxm["lxm"] = json!("blue.catbird.chat.getConversations");
    let mut expired = valid_claims();
    expired["exp"] = json!(now_epoch_seconds() - 1);
    let mut too_long = valid_claims();
    too_long["exp"] = json!(now_epoch_seconds() + 300);
    let mut future = valid_claims();
    future["nbf"] = json!(now_epoch_seconds() + 300);
    let account_token = jwt_from_claims(valid_claims());

    let cases = vec![
        (
            "non-2xx",
            raw_http_response("503 Service Unavailable", br#"{"error":"Busy"}"#, None),
        ),
        (
            "body read",
            raw_http_response("200 OK", br#"{"token":"cut-off"#, Some(200)),
        ),
        ("JSON", raw_http_response("200 OK", b"{", None)),
        (
            "missing",
            raw_http_response("200 OK", br#"{"unexpected":true}"#, None),
        ),
        (
            "empty",
            raw_http_response("200 OK", br#"{"token":""}"#, None),
        ),
        (
            "non-JWT",
            raw_http_response("200 OK", &token_body("pds-oauth-not-a-jwt".into()), None),
        ),
        (
            "account-token reuse",
            raw_http_response("200 OK", &token_body(account_token.clone()), None),
        ),
        (
            "algorithm",
            raw_http_response(
                "200 OK",
                &token_body(jwt_with_alg(valid_claims(), "HS256")),
                None,
            ),
        ),
        (
            "missing claim",
            raw_http_response("200 OK", &token_body(jwt_from_claims(missing_claim)), None),
        ),
        (
            "issuer",
            raw_http_response("200 OK", &token_body(jwt_from_claims(wrong_issuer)), None),
        ),
        (
            "audience",
            raw_http_response("200 OK", &token_body(jwt_from_claims(wrong_audience)), None),
        ),
        (
            "lxm",
            raw_http_response("200 OK", &token_body(jwt_from_claims(wrong_lxm)), None),
        ),
        (
            "expiry",
            raw_http_response("200 OK", &token_body(jwt_from_claims(expired)), None),
        ),
        (
            "lifetime",
            raw_http_response("200 OK", &token_body(jwt_from_claims(too_long)), None),
        ),
        (
            "not-before",
            raw_http_response("200 OK", &token_body(jwt_from_claims(future)), None),
        ),
    ];

    for (case, response) in cases {
        let pds = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let pds_base = format!("http://127.0.0.1:{}", pds.local_addr().unwrap().port());
        let ds = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let ds_base = format!("http://127.0.0.1:{}", ds.local_addr().unwrap().port());
        let pds_thread = std::thread::spawn(move || {
            let (mut stream, _) = pds.accept().unwrap();
            read_request(&mut stream);
            stream.write_all(&response).unwrap();
        });
        let transport = BirdPlatformTransport::with_identity_for_test(
            pds_base,
            ds_base.clone(),
            ISSUER.to_string(),
            "did:web:ds.example".to_string(),
        )
        .unwrap();
        transport
            .set_pds_oauth_token(Some(account_token.clone()))
            .unwrap();
        let error = transport
            .execute_http(PlatformHttpRequest {
                method: "POST".to_string(),
                url: format!("{ds_base}/xrpc/{LXM}"),
                headers: Vec::new(),
                body: Some(br#"{"messageId":"m1"}"#.to_vec()),
            })
            .expect_err(case);
        pds_thread.join().unwrap();
        assert!(
            error.to_string().contains("retryable service-auth mint"),
            "{case}: {error}"
        );
        ds.set_nonblocking(true).unwrap();
        match ds.accept() {
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            other => panic!("{case}: DS was contacted after failed mint: {other:?}"),
        }
    }
}

/// The mint uses the exact audience/lxm, and parsed origin/path boundaries keep both bearer types
/// off sibling paths, origin roots, alternate ports, and caller-supplied DS Authorization headers.
#[test]
fn birdaemon_transport_mints_exact_claims_and_contains_bearers() {
    use std::io::Write as _;

    const ISSUER: &str = "did:plc:birdaemoncleanbotaaaaaaa";
    const AUDIENCE: &str = "did:web:ds.example#atproto_mls";
    const LXM: &str = "blue.catbird.chat.getConversations";
    let minted = service_auth_jwt(ISSUER, AUDIENCE, LXM, now_epoch_seconds() + 60);
    let server = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = server.local_addr().unwrap().port();
    let seen = Arc::new(std::sync::Mutex::new(Vec::<(String, Option<String>)>::new()));
    let log = Arc::clone(&seen);
    let minted_for_server = minted.clone();
    let server_thread = std::thread::spawn(move || {
        for mut stream in server.incoming().flatten().take(7) {
            let head = read_request(&mut stream);
            let mut lines = head.lines();
            let path = lines
                .next()
                .unwrap_or_default()
                .split(' ')
                .nth(1)
                .unwrap_or_default()
                .to_string();
            let authorization = lines.find_map(|line| {
                line.split_once(':')
                    .filter(|(name, _)| name.eq_ignore_ascii_case("authorization"))
                    .map(|(_, value)| value.trim().to_string())
            });
            log.lock().unwrap().push((path.clone(), authorization));
            let body = if path.contains("com.atproto.server.getServiceAuth") {
                serde_json::to_vec(&json!({ "token": minted_for_server })).unwrap()
            } else {
                b"{}".to_vec()
            };
            stream
                .write_all(&raw_http_response("200 OK", &body, None))
                .unwrap();
        }
    });

    let origin = format!("http://127.0.0.1:{port}");
    let transport = BirdPlatformTransport::with_identity_for_test(
        format!("{origin}/pds"),
        format!("{origin}/ds/"),
        ISSUER.to_string(),
        "did:web:ds.example".to_string(),
    )
    .unwrap();
    transport
        .set_pds_oauth_token(Some("pds-oauth".to_string()))
        .unwrap();
    let get = |transport: &BirdPlatformTransport, url: String, headers| {
        transport
            .execute_http(PlatformHttpRequest {
                method: "GET".to_string(),
                url,
                headers,
                body: None,
            })
            .expect("local server answers");
    };
    get(
        &transport,
        format!("{origin}/pds/xrpc/com.atproto.repo.getRecord"),
        Vec::new(),
    );
    get(
        &transport,
        format!("{origin}/ds/xrpc/{LXM}"),
        vec![catbird_mls::client::PlatformHttpHeader {
            name: "Authorization".to_string(),
            value: "Bearer pds-oauth".to_string(),
        }],
    );
    get(
        &transport,
        format!("{origin}/pds-other/xrpc/com.atproto.repo.getRecord"),
        Vec::new(),
    );
    get(
        &transport,
        format!("{origin}/ds-other/xrpc/{LXM}"),
        Vec::new(),
    );
    get(&transport, format!("{origin}/xrpc/{LXM}"), Vec::new());

    let short = format!("http://127.0.0.1:{}", port / 10);
    let alternate = BirdPlatformTransport::with_identity_for_test(
        short.clone(),
        short,
        ISSUER.to_string(),
        "did:web:ds.example".to_string(),
    )
    .unwrap();
    get(&alternate, format!("{origin}/xrpc/{LXM}"), Vec::new());
    server_thread.join().unwrap();

    let records = seen.lock().unwrap();
    assert_eq!(records.len(), 7);
    assert_eq!(
        records[0],
        (
            "/pds/xrpc/com.atproto.repo.getRecord".to_string(),
            Some("Bearer pds-oauth".to_string())
        )
    );
    assert!(records[1]
        .0
        .starts_with("/pds/xrpc/com.atproto.server.getServiceAuth?"));
    assert_eq!(records[1].1, Some("Bearer pds-oauth".to_string()));
    let mint_query = query_map(&records[1].0);
    assert_eq!(mint_query.len(), 2);
    assert_eq!(mint_query.get("aud").map(String::as_str), Some(AUDIENCE));
    assert_eq!(mint_query.get("lxm").map(String::as_str), Some(LXM));
    assert_eq!(
        records[2],
        (format!("/ds/xrpc/{LXM}"), Some(format!("Bearer {minted}")))
    );
    for (path, authorization) in &records[3..] {
        assert!(authorization.is_none(), "bearer escaped to {path}");
    }
}

/// Redirects are returned to the caller and never followed to a second origin.
#[test]
fn birdaemon_transport_does_not_follow_redirects() {
    use std::io::Write as _;

    let redirected = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    redirected.set_nonblocking(true).unwrap();
    let redirected_url = format!(
        "http://127.0.0.1:{}/captured",
        redirected.local_addr().unwrap().port()
    );
    let source = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let source_base = format!("http://127.0.0.1:{}", source.local_addr().unwrap().port());
    let source_thread = std::thread::spawn(move || {
        let (mut stream, _) = source.accept().unwrap();
        read_request(&mut stream);
        write!(
            stream,
            "HTTP/1.1 302 Found\r\nLocation: {redirected_url}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )
        .unwrap();
    });
    let response = BirdPlatformTransport::new_for_test(source_base.clone())
        .unwrap()
        .execute_http(PlatformHttpRequest {
            method: "GET".to_string(),
            url: format!("{source_base}/redirect"),
            headers: Vec::new(),
            body: None,
        })
        .expect("redirect response");
    source_thread.join().unwrap();
    assert_eq!(response.status, 302);
    match redirected.accept() {
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
        other => panic!("redirect target was contacted: {other:?}"),
    }
}
