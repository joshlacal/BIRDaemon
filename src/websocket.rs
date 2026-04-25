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

use crate::xrpc_client::BirdApiClient;

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
    api_client: Arc<BirdApiClient>,
    reconnect: Arc<Notify>,
}

impl MlsWebSocket {
    pub fn new(api_client: Arc<BirdApiClient>) -> Self {
        Self {
            api_client,
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
        let api_client = self.api_client.clone();
        let reconnect = self.reconnect.clone();

        tokio::spawn(async move {
            let mut last_cursor: Option<String> = None;
            let mut attempt = 0u32;

            loop {
                if *shutdown.borrow() {
                    break;
                }

                attempt += 1;
                tracing::info!("WebSocket connecting (attempt {})", attempt);

                match do_subscribe(&api_client, last_cursor.as_deref(), &tx, &shutdown, &reconnect).await {
                    Ok(cursor) => {
                        last_cursor = cursor;
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

/// Single WebSocket connection session. Returns the last cursor on clean disconnect.
async fn do_subscribe(
    api_client: &BirdApiClient,
    cursor: Option<&str>,
    tx: &mpsc::Sender<MlsEvent>,
    shutdown: &tokio::sync::watch::Receiver<bool>,
    reconnect: &Notify,
) -> Result<Option<String>, String> {
    // 1. Get subscription ticket via PDS proxy
    let (ticket, ws_endpoint) = api_client
        .get_subscription_ticket()
        .await
        .map_err(|e| format!("Ticket request failed: {}", e))?;

    // 2. Build WebSocket URL
    let mut ws_url = format!("{}?ticket={}", ws_endpoint, ticket);
    if let Some(cur) = cursor {
        ws_url.push_str(&format!("&cursor={}", cur));
    }

    tracing::info!("WebSocket URL: {}", ws_url);

    // 3. Connect
    let (mut ws_stream, _) = connect_async(&ws_url)
        .await
        .map_err(|e| format!("WebSocket connect failed: {}", e))?;

    tracing::info!("WebSocket connected");
    let _ = tx.send(MlsEvent::Connected).await;

    let mut last_cursor: Option<String> = cursor.map(String::from);
    let mut shutdown = shutdown.clone();

    // 4. Event loop
    loop {
        tokio::select! {
            msg = ws_stream.next() => {
                match msg {
                    Some(Ok(WsMessage::Binary(data))) => {
                        tracing::info!("WebSocket binary frame: {} bytes", data.len());
                        match handle_frame(&data) {
                            Ok(Some((event, cur))) => {
                                if let Some(c) = cur {
                                    last_cursor = Some(c);
                                }
                                let _ = tx.send(event).await;
                            }
                            Ok(None) => {} // Ignored frame (keepalive)
                            Err(e) => tracing::warn!("Frame error: {}", e),
                        }
                    }
                    Some(Ok(WsMessage::Ping(data))) => {
                        let _ = ws_stream.send(WsMessage::Pong(data)).await;
                    }
                    Some(Ok(WsMessage::Text(text))) => {
                        tracing::info!("WebSocket text frame: {}", text);
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
                    return Ok(last_cursor);
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

    Ok(last_cursor)
}

// ── handle_frame ─────────────────────────────────────────────────────────

/// Parse a binary DAG-CBOR frame into an MlsEvent.
fn handle_frame(data: &[u8]) -> Result<Option<(MlsEvent, Option<String>)>, String> {
    let (header, payload_bytes) =
        split_frame(data).ok_or("Failed to decode DAG-CBOR frame header")?;

    if header.op == -1 {
        return Err("Server error frame".to_string());
    }

    // op 0 = keepalive (no event type)
    if header.op == 0 {
        return Ok(None);
    }

    let event_type = header.t.as_deref().unwrap_or("");

    match event_type {
        "#messageEvent" => {
            let payload: CborValue = ciborium::from_reader(Cursor::new(payload_bytes))
                .map_err(|e| format!("Failed to decode messageEvent CBOR: {}", e))?;

            let CborValue::Map(ref top) = payload else {
                return Err("messageEvent payload is not a CBOR map".into());
            };

            let cursor = cbor_str(top, "cursor");
            let msg_map = cbor_map(top, "message")
                .ok_or("Missing 'message' field in messageEvent")?;

            let id = cbor_str(msg_map, "id").ok_or("Missing message.id")?;
            let convo_id = cbor_str(msg_map, "convoId").ok_or("Missing message.convoId")?;
            let created_at = cbor_str(msg_map, "createdAt").ok_or("Missing message.createdAt")?;
            let epoch = cbor_int(msg_map, "epoch").unwrap_or(0) as u64;
            let ciphertext = cbor_bytes(msg_map, "ciphertext")
                .ok_or("Missing or invalid message.ciphertext")?;

            tracing::debug!(
                id = %id,
                convo_id = %convo_id,
                epoch = epoch,
                ct_len = ciphertext.len(),
                "Parsed messageEvent"
            );

            Ok(Some((
                MlsEvent::Message {
                    id,
                    conversation_id: convo_id,
                    ciphertext,
                    epoch,
                    created_at,
                    cursor: cursor.clone(),
                },
                cursor,
            )))
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
            Ok(Some((
                MlsEvent::Info {
                    info,
                    cursor: cursor.clone(),
                },
                cursor,
            )))
        }
        "#groupResetEvent" => {
            let payload: CborValue = ciborium::from_reader(Cursor::new(payload_bytes))
                .map_err(|e| format!("Failed to decode groupResetEvent CBOR: {}", e))?;

            let CborValue::Map(ref top) = payload else {
                return Err("groupResetEvent payload is not a CBOR map".into());
            };

            let cursor = cbor_str(top, "cursor");
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

            Ok(Some((
                MlsEvent::GroupReset {
                    conversation_id,
                    new_group_id,
                    reset_generation,
                },
                cursor,
            )))
        }
        other => {
            tracing::debug!(event_type = %other, "Ignoring unhandled event type");
            // Still extract cursor if possible
            let cursor = if !payload_bytes.is_empty() {
                ciborium::from_reader::<CborValue, _>(Cursor::new(payload_bytes))
                    .ok()
                    .and_then(|v| match &v {
                        CborValue::Map(entries) => cbor_str(entries, "cursor"),
                        _ => None,
                    })
            } else {
                None
            };
            Ok(cursor.map(|c| {
                (
                    MlsEvent::Info {
                        info: format!("event: {}", other),
                        cursor: Some(c.clone()),
                    },
                    Some(c),
                )
            }))
        }
    }
}
