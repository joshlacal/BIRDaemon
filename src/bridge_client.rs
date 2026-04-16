//! Claude Code bridge client — drop-in replacement for BIRDaemon's LlmClient.
//!
//! Posts decrypted messages to the mls-chat-channel HTTP bridge and polls
//! for Claude's reply on /reply/:conversation_id.

use serde::{Deserialize, Serialize};

/// Bridge client that routes messages to the mls-chat-channel.
pub struct BridgeClient {
    http: reqwest::Client,
    bridge_url: String,
}

#[derive(Serialize)]
struct BridgeMessage {
    conversation_id: String,
    sender_did: String,
    sender_handle: Option<String>,
    text: String,
    message_id: Option<String>,
    epoch: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct PollResponse {
    status: String,
    #[serde(default)]
    text: Option<String>,
}

impl BridgeClient {
    pub fn new(bridge_url: &str) -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
            bridge_url: bridge_url.to_string(),
        }
    }

    /// Post a decrypted message to the channel bridge and poll for Claude's reply.
    pub async fn generate(
        &self,
        conversation_id: &str,
        sender_did: &str,
        user_message: &str,
        _image_base64: Option<(&str, &str)>,
        _embed_context: Option<&str>,
    ) -> anyhow::Result<String> {
        let msg = BridgeMessage {
            conversation_id: conversation_id.to_string(),
            sender_did: sender_did.to_string(),
            sender_handle: None,
            text: user_message.to_string(),
            message_id: None,
            epoch: None,
        };

        // POST the message to the channel
        let url = format!("{}/message", self.bridge_url);
        let resp = self.http.post(&url).json(&msg).send().await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("Bridge POST failed ({}): {}", status, body);
        }

        tracing::info!("Message posted to bridge, polling for reply...");

        // Poll for reply (5 minute timeout, check every 2 seconds)
        let poll_url = format!("{}/reply/{}", self.bridge_url, conversation_id);
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(300);

        loop {
            if tokio::time::Instant::now() >= deadline {
                anyhow::bail!("Timed out waiting for Claude's reply (300s)");
            }

            tokio::time::sleep(std::time::Duration::from_secs(2)).await;

            let resp = match self.http.get(&poll_url).send().await {
                Ok(r) => r,
                Err(e) => {
                    tracing::debug!("Poll error (retrying): {}", e);
                    continue;
                }
            };

            if resp.status().as_u16() == 204 {
                // No reply yet, keep polling
                continue;
            }

            if resp.status().is_success() {
                let poll: PollResponse = resp.json().await?;
                if poll.status == "ready" {
                    if let Some(text) = poll.text {
                        return Ok(text);
                    }
                }
                continue;
            }

            tracing::debug!("Poll returned {}, retrying", resp.status());
        }
    }
}
