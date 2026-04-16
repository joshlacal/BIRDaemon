//! OpenClaw LLM client.
//!
//! Connects to the OpenClaw gateway's OpenAI-compatible chat completions endpoint.
//! Each Bluesky conversation maps to an OpenClaw session via the
//! `x-openclaw-session-key` header, so OpenClaw manages conversation history
//! and memory across sessions. We only send the current user message.

use serde::{Deserialize, Serialize};

use crate::config::BirdConfig;

/// OpenClaw gateway client.
///
/// Routes each Bluesky conversation to a persistent OpenClaw session.
/// OpenClaw owns the system prompt, conversation history, and memory.
pub struct LlmClient {
    http: reqwest::Client,
    base_url: String,
    api_key: String,
    model: String,
    max_chars: u32,
}

#[derive(Serialize)]
struct ChatRequest {
    model: String,
    messages: Vec<ChatMessage>,
    stream: bool,
    max_tokens: u32,
}

const GENERATION_MAX_TOKENS: u32 = 2048;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ChatMessage {
    pub role: String,
    pub content: MessageContent,
}

/// Message content: either a plain string or multimodal content parts (for vision).
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(untagged)]
pub enum MessageContent {
    Text(String),
    Parts(Vec<ContentPart>),
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "type")]
pub enum ContentPart {
    #[serde(rename = "text")]
    Text { text: String },
    #[serde(rename = "image_url")]
    ImageUrl { image_url: ImageUrl },
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ImageUrl {
    pub url: String,
}

/// Non-streaming response format.
#[derive(Deserialize)]
struct ChatResponse {
    choices: Vec<ChatChoice>,
}

#[derive(Deserialize)]
struct ChatChoice {
    message: ChatChoiceMessage,
}

#[derive(Deserialize)]
struct ChatChoiceMessage {
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    reasoning_content: Option<String>,
}

impl LlmClient {
    pub fn new(config: &BirdConfig) -> Self {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(300))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        Self {
            http,
            base_url: config.llm_base_url.clone(),
            api_key: config.llm_api_key.clone(),
            model: config.llm_model.clone(),
            max_chars: config.max_reply_characters,
        }
    }

    /// Generate a response for a single user message within a conversation.
    ///
    /// The `conversation_id` is used as the OpenClaw session key so that each
    /// Bluesky DM conversation gets its own persistent session with history.
    /// `sender_did` identifies who sent the message (important for group chats).
    /// If `image_base64` is provided, the message is sent as multimodal content.
    /// `embed_context` provides text descriptions of non-image attachments.
    pub async fn generate(
        &self,
        conversation_id: &str,
        sender_did: &str,
        user_message: &str,
        image_base64: Option<(&str, &str)>, // (base64_data, content_type)
        embed_context: Option<&str>,
    ) -> anyhow::Result<String> {
        // Build the text portion: prefix with sender DID and append any embed context
        let mut text_parts = Vec::new();
        text_parts.push(format!("[from: {}]", sender_did));
        if !user_message.is_empty() {
            text_parts.push(user_message.to_string());
        }
        if let Some(ctx) = embed_context {
            text_parts.push(ctx.to_string());
        }
        let full_text = text_parts.join("\n");

        let content = match image_base64 {
            Some((b64_data, content_type)) => {
                let mut parts = vec![ContentPart::ImageUrl {
                    image_url: ImageUrl {
                        url: format!("data:{};base64,{}", content_type, b64_data),
                    },
                }];
                parts.push(ContentPart::Text {
                    text: if full_text.is_empty() {
                        format!("[from: {}]\nWhat's in this image?", sender_did)
                    } else {
                        full_text
                    },
                });
                MessageContent::Parts(parts)
            }
            None => MessageContent::Text(full_text),
        };

        let messages = vec![ChatMessage {
            role: "user".to_string(),
            content,
        }];

        let req = ChatRequest {
            model: self.model.clone(),
            messages,
            stream: false,
            max_tokens: GENERATION_MAX_TOKENS,
        };

        // Derive a stable OpenClaw session key from the Bluesky conversation ID.
        let session_key = format!("bluesky:{}", conversation_id);

        let url = format!("{}/v1/chat/completions", self.base_url);
        let resp = self
            .http
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .header("x-openclaw-session-key", &session_key)
            .json(&req)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("LLM API error {}: {}", status, body);
        }

        let body: ChatResponse = resp.json().await?;

        let choice = body.choices.first();
        let content = choice
            .and_then(|c| c.message.content.clone())
            .unwrap_or_default();
        let has_reasoning =
            choice.map_or(false, |c| c.message.reasoning_content.is_some());

        let cleaned = if has_reasoning {
            content
        } else {
            strip_think_blocks(&content)
        };

        // Truncate to max chars
        let result = if cleaned.len() > self.max_chars as usize {
            cleaned[..self.max_chars as usize].to_string()
        } else {
            cleaned
        };

        Ok(result.trim().to_string())
    }
}

/// Remove <think>...</think> blocks from model output.
fn strip_think_blocks(text: &str) -> String {
    let mut result = String::new();
    let mut remaining = text;

    while let Some(start) = remaining.find("<think>") {
        result.push_str(&remaining[..start]);
        if let Some(end) = remaining[start..].find("</think>") {
            remaining = &remaining[start + end + 8..];
        } else {
            // Unclosed <think> tag — skip everything after it
            return result.trim().to_string();
        }
    }
    result.push_str(remaining);
    result.trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_think_blocks() {
        assert_eq!(
            strip_think_blocks("hello <think>reasoning</think> world"),
            "hello  world"
        );
        assert_eq!(
            strip_think_blocks("<think>hidden</think>visible"),
            "visible"
        );
        assert_eq!(strip_think_blocks("no tags here"), "no tags here");
        assert_eq!(strip_think_blocks("<think>unclosed"), "");
    }
}
