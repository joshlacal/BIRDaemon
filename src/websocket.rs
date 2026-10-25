//! DAG-CBOR WebSocket client for MLS event subscription.
//!
//! Connects to the MLS server WebSocket endpoint (via subscription ticket
//! obtained through the PDS proxy) and parses DAG-CBOR framed events.
//! Ported from the Catmos Tauri reference implementation.

use std::io::Cursor;
use std::sync::Arc;

use base64::Engine;
use ciborium::Value as CborValue;
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use tokio::sync::{mpsc, Notify};
use tokio_tungstenite::{connect_async, tungstenite::Message as WsMessage};

use catbird_atproto::blue_catbird::chat::{EventEnvelope, SubscriptionMessage, TypingEvent};
use catbird_mls::orchestrator::subscription::{
    SubscriptionDispatchOutcome, SubscriptionTicket, MAX_FRAME_BYTES,
};

/// Canonical protocol policy stays in the shared Rust orchestrator. The transport
/// only adapts DAG-CBOR frames and never persists or guesses a cursor itself.
#[async_trait::async_trait]
pub(crate) trait SubscriptionRuntime: Send + Sync {
    async fn prepare(&self) -> Result<SubscriptionTicket, String>;
    async fn apply(&self, raw: &str) -> Result<SubscriptionDispatchOutcome, String>;
}

enum DecodedFrame {
    Canonical(String),
    Legacy(MlsEvent),
}

// ── DAG-CBOR frame helpers ───────────────────────────────────────────────

/// DAG-CBOR WebSocket frame header (matches mls-ds MessageHeader).
#[derive(Debug, Deserialize)]
struct FrameHeader {
    op: i32,
    t: Option<String>,
}

/// Extract a string from a CBOR map.
fn cbor_str(map: &[(CborValue, CborValue)], key: &str) -> Option<String> {
    map.iter().find_map(|(k, v)| match (k, v) {
        (CborValue::Text(k), CborValue::Text(v)) if k == key => Some(v.clone()),
        _ => None,
    })
}

/// Extract an integer from a CBOR map.
fn cbor_int(map: &[(CborValue, CborValue)], key: &str) -> Option<i64> {
    map.iter().find_map(|(k, v)| match (k, v) {
        (CborValue::Text(k), CborValue::Integer(v)) if k == key => {
            let n: i128 = (*v).into();
            Some(n as i64)
        }
        _ => None,
    })
}

/// Extract bytes from a CBOR map.
/// Handles three formats:
/// - CBOR byte string (major type 2) -- raw bytes
/// - ATProto `{"$bytes": "base64..."}` map -- base64-decoded
/// - CBOR array of integers -- each int as u8
fn cbor_bytes(map: &[(CborValue, CborValue)], key: &str) -> Option<Vec<u8>> {
    map.iter().find_map(|(k, v)| {
        let CborValue::Text(k) = k else { return None };
        if k != key {
            return None;
        }
        extract_bytes(v)
    })
}

/// Extract bytes from a CBOR value regardless of encoding format.
fn extract_bytes(v: &CborValue) -> Option<Vec<u8>> {
    match v {
        CborValue::Bytes(b) => Some(b.clone()),
        // ATProto {"$bytes": "base64..."} format
        CborValue::Map(entries) => cbor_str(entries, "$bytes")
            .and_then(|b64| base64::engine::general_purpose::STANDARD.decode(&b64).ok()),
        CborValue::Array(arr) => arr
            .iter()
            .map(|item| match item {
                CborValue::Integer(i) => {
                    let n: i128 = (*i).into();
                    u8::try_from(n).ok()
                }
                _ => None,
            })
            .collect(),
        _ => None,
    }
}

/// Extract a nested CBOR map from a parent map.
fn cbor_map<'a>(
    map: &'a [(CborValue, CborValue)],
    key: &str,
) -> Option<&'a [(CborValue, CborValue)]> {
    map.iter().find_map(|(k, v)| match (k, v) {
        (CborValue::Text(k), CborValue::Map(m)) if k == key => Some(m.as_slice()),
        _ => None,
    })
}

/// Decode a DAG-CBOR WebSocket frame. Returns header and remaining payload bytes.
/// The frame contains two concatenated CBOR items: header + payload.
fn split_frame(data: &[u8]) -> Option<(FrameHeader, &[u8])> {
    let mut cursor = Cursor::new(data);
    let header: FrameHeader = ciborium::from_reader(&mut cursor).ok()?;
    let consumed = cursor.position() as usize;
    Some((header, &data[consumed..]))
}

// ── MlsEvent ─────────────────────────────────────────────────────────────

/// Events received from the MLS WebSocket.
#[derive(Debug)]
pub enum MlsEvent {
    /// Canonical event whose state and cursor were durably applied by the core.
    Canonical(SubscriptionDispatchOutcome),
    /// Encrypted message received.
    Message {
        id: String,
        conversation_id: String,
        ciphertext: Vec<u8>,
        epoch: u64,
        created_at: String,
        cursor: Option<String>,
    },
    /// Informational event (heartbeat, etc).
    Info {
        info: String,
        cursor: Option<String>,
    },
    /// Group has been reset — conversation needs rejoin with new group.
    GroupReset {
        conversation_id: String,
        new_group_id: String,
        reset_generation: i32,
    },
    /// Connection established.
    Connected,
    /// Connection lost, will attempt reconnect.
    Disconnected,
}

// ── MlsWebSocket ─────────────────────────────────────────────────────────

/// WebSocket subscription manager for MLS events.
///
/// Handles connection lifecycle, reconnection with exponential backoff,
/// and DAG-CBOR frame parsing. Returns parsed events via an mpsc channel.
pub struct MlsWebSocket {
    runtime: Arc<dyn SubscriptionRuntime>,
    reconnect: Arc<Notify>,
}

impl MlsWebSocket {
    pub fn new(runtime: Arc<dyn SubscriptionRuntime>) -> Self {
        Self {
            runtime,
            reconnect: Arc::new(Notify::new()),
        }
    }

    /// Get a handle to trigger reconnection (e.g., after new conversations are discovered).
    pub fn reconnect_handle(&self) -> Arc<Notify> {
        self.reconnect.clone()
    }

    /// Start the WebSocket subscription. Returns a receiver for MLS events.
    /// Spawns a background task that handles connection, reconnection, and frame parsing.
    pub fn subscribe(
        &self,
        shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> mpsc::Receiver<MlsEvent> {
        let (tx, rx) = mpsc::channel(100);
        let runtime = self.runtime.clone();
        let reconnect = self.reconnect.clone();

        tokio::spawn(async move {
            let mut attempt = 0u32;

            loop {
                if *shutdown.borrow() {
                    break;
                }

                attempt += 1;
                tracing::info!("WebSocket connecting (attempt {})", attempt);

                match do_subscribe(runtime.as_ref(), &tx, &shutdown, &reconnect).await {
                    Ok(()) => {
                        attempt = 0; // Reset on successful connection
                    }
                    Err(e) => {
                        tracing::warn!("WebSocket error: {}", e);
                    }
                }

                let _ = tx.send(MlsEvent::Disconnected).await;

                if *shutdown.borrow() {
                    break;
                }

                // Exponential backoff: 1s, 2s, 4s, 8s, max 15s
                let delay = std::cmp::min(1u64 << attempt.min(4), 15);
                tracing::info!("Reconnecting in {}s", delay);
                tokio::time::sleep(std::time::Duration::from_secs(delay)).await;
            }
        });

        rx
    }
}

// ── do_subscribe ─────────────────────────────────────────────────────────

/// Build the upgrade URL from the exact cursor bound into the one-use ticket.
fn subscription_url(ticket: &SubscriptionTicket) -> Result<String, String> {
    let mut url =
        url::Url::parse(&ticket.endpoint).map_err(|e| format!("Invalid endpoint: {e}"))?;
    if !matches!(url.scheme(), "ws" | "wss") || url.query().is_some() || url.fragment().is_some() {
        return Err("Invalid subscription endpoint".into());
    }
    url.query_pairs_mut()
        .append_pair("ticket", &ticket.ticket)
        .append_pair("cursor", &ticket.event_cursor);
    Ok(url.into())
}

/// One connection uses one freshly applied inventory and its exact ticket/cursor.
async fn do_subscribe(
    runtime: &dyn SubscriptionRuntime,
    tx: &mpsc::Sender<MlsEvent>,
    shutdown: &tokio::sync::watch::Receiver<bool>,
    reconnect: &Notify,
) -> Result<(), String> {
    let ticket = runtime.prepare().await?;
    let ws_url = subscription_url(&ticket)?;

    tracing::info!("Opening direct DS WebSocket subscription");

    // 3. Connect
    let (mut ws_stream, _) = connect_async(&ws_url)
        .await
        .map_err(|e| format!("WebSocket connect failed: {}", e))?;

    tracing::info!("WebSocket connected");
    let _ = tx.send(MlsEvent::Connected).await;

    let mut shutdown = shutdown.clone();

    // 4. Event loop
    loop {
        tokio::select! {
            msg = ws_stream.next() => {
                match msg {
                    Some(Ok(WsMessage::Binary(data))) => {
                        tracing::info!("WebSocket binary frame: {} bytes", data.len());
                        match handle_frame(&data) {
                            Ok(Some(DecodedFrame::Canonical(raw))) => {
                                // apply() validates the exact previousCursor chain, fetches
                                // canonical entries and durably processes them before CAS
                                // advancing the cursor. Any failure reconnects; it is never
                                // converted into a successful acknowledgement.
                                let outcome = runtime.apply(&raw).await?;
                                tx.send(MlsEvent::Canonical(outcome)).await
                                    .map_err(|_| "Event consumer closed".to_string())?;
                            }
                            Ok(Some(DecodedFrame::Legacy(event))) => {
                                tx.send(event).await
                                    .map_err(|_| "Event consumer closed".to_string())?;
                            }
                            Ok(None) => {} // Keepalive has no cursor.
                            Err(e) => return Err(e),
                        }
                    }
                    Some(Ok(WsMessage::Ping(data))) => {
                        let _ = ws_stream.send(WsMessage::Pong(data)).await;
                    }
                    Some(Ok(WsMessage::Text(text))) => {
                        tracing::debug!("WebSocket text frame received ({} bytes)", text.len());
                    }
                    Some(Ok(WsMessage::Close(reason))) => {
                        tracing::info!("WebSocket closed by server: {:?}", reason);
                        break;
                    }
                    Some(Err(e)) => {
                        return Err(format!("WebSocket error: {}", e));
                    }
                    None => {
                        tracing::info!("WebSocket stream ended (None)");
                        break;
                    }
                    _ => {
                        tracing::debug!("WebSocket: other frame type");
                    }
                }
            }
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    let _ = ws_stream.close(None).await;
                    return Ok(());
                }
            }
            // Reconnect signal from bot (e.g., new conversations discovered during sync)
            _ = reconnect.notified() => {
                tracing::info!("WebSocket reconnecting (new conversations discovered)");
                let _ = ws_stream.close(None).await;
                break;
            }
        }
    }

    Ok(())
}

// ── handle_frame ─────────────────────────────────────────────────────────

/// Parse a binary DAG-CBOR frame into an MlsEvent.
fn handle_frame(data: &[u8]) -> Result<Option<DecodedFrame>, String> {
    if data.len() > MAX_FRAME_BYTES {
        return Err("Subscription frame exceeds bound".into());
    }
    let (header, payload_bytes) =
        split_frame(data).ok_or("Failed to decode DAG-CBOR frame header")?;

    if header.op == -1 {
        return Err("Server error frame".to_string());
    }

    // op 0 = keepalive (no event type)
    if header.op == 0 {
        return Ok(None);
    }

    if header.op != 1 {
        return Err("Unknown subscription operation".into());
    }
    let event_type = header.t.as_deref().unwrap_or("");

    match event_type {
        "blue.catbird.chat.defs#eventEnvelope" | "blue.catbird.chat.defs#typingEvent" => {
            let mut input = Cursor::new(payload_bytes);
            let message: SubscriptionMessage<String> = if event_type.ends_with("#eventEnvelope") {
                let value: EventEnvelope<String> = ciborium::from_reader(&mut input)
                    .map_err(|e| format!("Invalid canonical event envelope: {e}"))?;
                SubscriptionMessage::EventEnvelope(Box::new(value))
            } else {
                let value: TypingEvent<String> = ciborium::from_reader(&mut input)
                    .map_err(|e| format!("Invalid typing event: {e}"))?;
                SubscriptionMessage::TypingEvent(Box::new(value))
            };
            if input.position() as usize != payload_bytes.len() {
                return Err("Trailing subscription frame data".into());
            }
            let raw = serde_json::to_string(&message).map_err(|e| e.to_string())?;
            // Reuse the core's strict schema validation before any dispatch.
            catbird_mls::orchestrator::subscription::decode_subscription_frame(&raw)
                .map_err(|e| e.to_string())?;
            Ok(Some(DecodedFrame::Canonical(raw)))
        }
        "#messageEvent" => {
            let payload: CborValue = ciborium::from_reader(Cursor::new(payload_bytes))
                .map_err(|e| format!("Failed to decode messageEvent CBOR: {}", e))?;

            let CborValue::Map(ref top) = payload else {
                return Err("messageEvent payload is not a CBOR map".into());
            };

            let cursor = cbor_str(top, "cursor");
            let msg_map =
                cbor_map(top, "message").ok_or("Missing 'message' field in messageEvent")?;

            let id = cbor_str(msg_map, "id").ok_or("Missing message.id")?;
            let convo_id = cbor_str(msg_map, "convoId").ok_or("Missing message.convoId")?;
            let created_at = cbor_str(msg_map, "createdAt").ok_or("Missing message.createdAt")?;
            let epoch = cbor_int(msg_map, "epoch").unwrap_or(0) as u64;
            let ciphertext =
                cbor_bytes(msg_map, "ciphertext").ok_or("Missing or invalid message.ciphertext")?;

            tracing::debug!(
                id = %id,
                convo_id = %convo_id,
                epoch = epoch,
                ct_len = ciphertext.len(),
                "Parsed messageEvent"
            );

            Ok(Some(DecodedFrame::Legacy(MlsEvent::Message {
                id,
                conversation_id: convo_id,
                ciphertext,
                epoch,
                created_at,
                cursor,
            })))
        }
        "#infoEvent" => {
            let payload: CborValue = ciborium::from_reader(Cursor::new(payload_bytes))
                .map_err(|e| format!("Failed to decode infoEvent CBOR: {}", e))?;

            let (info, cursor) = match &payload {
                CborValue::Map(ref top) => (
                    cbor_str(top, "info").unwrap_or_else(|| "heartbeat".to_string()),
                    cbor_str(top, "cursor"),
                ),
                _ => ("heartbeat".to_string(), None),
            };

            tracing::debug!(info = %info, "Info event");
            Ok(Some(DecodedFrame::Legacy(MlsEvent::Info { info, cursor })))
        }
        "#groupResetEvent" => {
            let payload: CborValue = ciborium::from_reader(Cursor::new(payload_bytes))
                .map_err(|e| format!("Failed to decode groupResetEvent CBOR: {}", e))?;

            let CborValue::Map(ref top) = payload else {
                return Err("groupResetEvent payload is not a CBOR map".into());
            };

            let conversation_id = cbor_str(top, "convoId")
                .or_else(|| cbor_str(top, "conversationId"))
                .ok_or("Missing convoId in groupResetEvent")?;
            let new_group_id = cbor_str(top, "newGroupId")
                .or_else(|| cbor_str(top, "new_group_id"))
                .ok_or("Missing newGroupId in groupResetEvent")?;
            let reset_generation = cbor_int(top, "resetGeneration")
                .or_else(|| cbor_int(top, "reset_generation"))
                .unwrap_or(0) as i32;

            tracing::info!(
                conversation_id = %conversation_id,
                new_group_id = %new_group_id,
                reset_generation,
                "Parsed groupResetEvent"
            );

            Ok(Some(DecodedFrame::Legacy(MlsEvent::GroupReset {
                conversation_id,
                new_group_id,
                reset_generation,
            })))
        }
        other => Err(format!("Unsupported subscription event type: {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use tokio::net::TcpListener;
    use tokio::sync::Mutex;
    use tokio_tungstenite::{
        accept_hdr_async,
        tungstenite::handshake::server::{Request, Response},
    };

    const CONVERSATION: &str = "11111111-1111-4111-8111-111111111111";

    fn event_frame(previous: &str, next: &str) -> Vec<u8> {
        // Serialize the same generated inner DTO and two-item framing as the
        // active mls-ds handler; this fixture has no accounts or encrypted data.
        let envelope: EventEnvelope<String> = serde_json::from_value(serde_json::json!({
            "previousCursor": previous,
            "cursor": next,
            "createdAt": "2026-10-25T10:00:00.000Z",
            "payload": {
                "$type": "blue.catbird.chat.defs#messageAvailableEvent",
                "conversationId": CONVERSATION,
                "seq": 1
            }
        }))
        .unwrap();
        let mut bytes = Vec::new();
        ciborium::into_writer(
            &serde_json::json!({"op": 1, "t": "blue.catbird.chat.defs#eventEnvelope"}),
            &mut bytes,
        )
        .unwrap();
        ciborium::into_writer(&envelope, &mut bytes).unwrap();
        bytes
    }

    #[test]
    fn production_envelope_frame_retains_payload_and_cursor_chain() {
        let Some(DecodedFrame::Canonical(raw)) =
            handle_frame(&event_frame("before", "after")).unwrap()
        else {
            panic!("canonical envelope was not decoded");
        };
        let value: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(value["$type"], "blue.catbird.chat.defs#eventEnvelope");
        assert_eq!(value["previousCursor"], "before");
        assert_eq!(value["cursor"], "after");
        assert_eq!(value["payload"]["conversationId"], CONVERSATION);
        assert_eq!(value["payload"]["seq"], 1);
    }

    #[test]
    fn production_typing_frame_is_typed_and_has_no_cursor() {
        let typing: TypingEvent<String> = serde_json::from_value(serde_json::json!({
            "actorDeviceId": "22222222-2222-4222-8222-222222222222",
            "actorDid": "did:plc:abcdefghijklmnopqrstuvwx",
            "conversationId": CONVERSATION,
            "expiresAt": "2026-10-25T10:00:03.000Z",
            "isTyping": true,
            "typingId": "33333333-3333-4333-8333-333333333333"
        }))
        .unwrap();
        let mut bytes = Vec::new();
        ciborium::into_writer(
            &serde_json::json!({"op": 1, "t": "blue.catbird.chat.defs#typingEvent"}),
            &mut bytes,
        )
        .unwrap();
        ciborium::into_writer(&typing, &mut bytes).unwrap();
        let Some(DecodedFrame::Canonical(raw)) = handle_frame(&bytes).unwrap() else {
            panic!("typing frame was not decoded");
        };
        let value: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(value["$type"], "blue.catbird.chat.defs#typingEvent");
        assert_eq!(value["isTyping"], true);
        assert!(value.get("cursor").is_none());
    }

    #[test]
    fn frame_rejects_unknown_types_trailing_data_and_oversize_input() {
        let mut unknown = Vec::new();
        ciborium::into_writer(
            &serde_json::json!({"op": 1, "t": "blue.catbird.chat.defs#futureEvent"}),
            &mut unknown,
        )
        .unwrap();
        ciborium::into_writer(
            &serde_json::json!({"cursor": "must-not-advance"}),
            &mut unknown,
        )
        .unwrap();
        assert!(handle_frame(&unknown).is_err());
        let mut trailing = event_frame("before", "after");
        trailing.push(0xf6);
        assert!(handle_frame(&trailing).is_err());
        assert!(handle_frame(&vec![0; MAX_FRAME_BYTES + 1]).is_err());
    }

    struct FixtureRuntime {
        endpoint: String,
        prepares: AtomicUsize,
        fail_next_apply: AtomicBool,
        cursor: Mutex<String>,
    }

    #[async_trait::async_trait]
    impl SubscriptionRuntime for FixtureRuntime {
        async fn prepare(&self) -> Result<SubscriptionTicket, String> {
            let index = self.prepares.fetch_add(1, Ordering::SeqCst);
            let event_cursor = format!("inventory:{index}&exact=cursor");
            *self.cursor.lock().await = event_cursor.clone();
            Ok(SubscriptionTicket {
                endpoint: self.endpoint.clone(),
                ticket: format!("one-use-ticket-{index}&exact=token"),
                inventory_session_id: format!("inventory-session-{index}"),
                event_cursor,
            })
        }

        async fn apply(&self, raw: &str) -> Result<SubscriptionDispatchOutcome, String> {
            if self.fail_next_apply.swap(false, Ordering::SeqCst) {
                return Err("fixture entry processing failed before cursor persistence".into());
            }
            let value: serde_json::Value = serde_json::from_str(raw).unwrap();
            let mut cursor = self.cursor.lock().await;
            if value["previousCursor"] != *cursor || value["cursor"] == *cursor {
                return Err("fixture rejected replay or broken cursor chain".into());
            }
            *cursor = value["cursor"].as_str().unwrap().to_string();
            Ok(SubscriptionDispatchOutcome::MessageAvailable {
                conversation_id: CONVERSATION.into(),
                target_seq: 1,
                messages: vec![],
                cursor: cursor.clone(),
            })
        }
    }

    #[tokio::test]
    async fn loopback_reconnect_uses_fresh_ticket_and_processing_failure_never_dispatches() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!(
            "ws://{}/xrpc/blue.catbird.chat.subscribeEvents",
            listener.local_addr().unwrap()
        );
        let queries = Arc::new(std::sync::Mutex::new(Vec::new()));
        let capture = queries.clone();
        let server = tokio::spawn(async move {
            for index in 0..2 {
                let (socket, _) = listener.accept().await.unwrap();
                let capture = capture.clone();
                let mut ws =
                    accept_hdr_async(socket, move |request: &Request, response: Response| {
                        capture.lock().unwrap().push(request.uri().to_string());
                        Ok(response)
                    })
                    .await
                    .unwrap();
                let frame = event_frame(
                    &format!("inventory:{index}&exact=cursor"),
                    "processed-cursor",
                );
                ws.send(WsMessage::Binary(frame.clone().into()))
                    .await
                    .unwrap();
                if index == 1 {
                    // The same envelope replay must fail instead of dispatching twice.
                    ws.send(WsMessage::Binary(frame.into())).await.unwrap();
                }
                let _ = ws.next().await;
            }
        });
        let runtime = FixtureRuntime {
            endpoint,
            prepares: AtomicUsize::new(0),
            fail_next_apply: AtomicBool::new(true),
            cursor: Mutex::new(String::new()),
        };
        let (tx, mut rx) = mpsc::channel(10);
        let (_shutdown_tx, shutdown) = tokio::sync::watch::channel(false);
        let reconnect = Notify::new();
        let failure = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            do_subscribe(&runtime, &tx, &shutdown, &reconnect),
        )
        .await
        .unwrap()
        .unwrap_err();
        assert!(failure.contains("processing failed"));
        assert_eq!(*runtime.cursor.lock().await, "inventory:0&exact=cursor");
        assert!(matches!(rx.try_recv().unwrap(), MlsEvent::Connected));
        assert!(
            rx.try_recv().is_err(),
            "failed processing must not dispatch a canonical event"
        );

        let replay = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            do_subscribe(&runtime, &tx, &shutdown, &reconnect),
        )
        .await
        .unwrap()
        .unwrap_err();
        assert!(replay.contains("replay"));
        assert_eq!(*runtime.cursor.lock().await, "processed-cursor");
        assert!(matches!(rx.try_recv().unwrap(), MlsEvent::Connected));
        assert!(matches!(
            rx.try_recv().unwrap(),
            MlsEvent::Canonical(SubscriptionDispatchOutcome::MessageAvailable {
                target_seq: 1,
                ..
            })
        ));
        assert!(rx.try_recv().is_err(), "a replay must not dispatch twice");
        server.await.unwrap();
        for (index, uri) in queries.lock().unwrap().iter().enumerate() {
            let url = url::Url::parse(&format!("http://localhost{uri}")).unwrap();
            let query: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
            assert_eq!(query.len(), 2);
            assert_eq!(
                query["ticket"],
                format!("one-use-ticket-{index}&exact=token")
            );
            assert_eq!(query["cursor"], format!("inventory:{index}&exact=cursor"));
        }
        assert_eq!(runtime.prepares.load(Ordering::SeqCst), 2);
    }
}
