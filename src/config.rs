use serde::Deserialize;
use std::path::PathBuf;

/// BIRDaemon configuration loaded from JSON + .env files.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BirdConfig {
    pub handle: String,
    pub llm_backend: String,
    #[serde(rename = "llmBaseURL")]
    pub llm_base_url: String,
    pub llm_api_key: String,
    pub llm_model: String,
    pub system_prompt: String,
    #[serde(default)]
    pub receive_chat_requests: bool,
    #[serde(default)]
    pub accept_chat_requests: bool,
    #[serde(default)]
    pub reply_to_all_messages: bool,
    pub max_reply_characters: u32,
}

/// Secrets loaded from .env file.
#[derive(Debug, Clone)]
pub struct BirdSecrets {
    pub app_password: String,
}

/// Get the Application Support directory for BIRDaemon.
pub fn data_dir() -> PathBuf {
    let home = dirs::home_dir().expect("could not find home directory");
    home.join("Library/Application Support/BirdDaemon")
}

/// Load configuration from ~/Library/Application Support/BirdDaemon/config.json
pub fn load_config() -> anyhow::Result<BirdConfig> {
    let config_path = data_dir().join("config.json");
    tracing::info!("Loading config from {}", config_path.display());
    let contents = std::fs::read_to_string(&config_path)?;
    let config: BirdConfig = serde_json::from_str(&contents)?;
    Ok(config)
}

/// Load secrets from ~/Library/Application Support/BirdDaemon/.env
pub fn load_secrets() -> anyhow::Result<BirdSecrets> {
    let env_path = data_dir().join(".env");
    tracing::info!("Loading secrets from {}", env_path.display());
    dotenvy::from_path(&env_path)?;
    let app_password = std::env::var("BIRD_APP_PASSWORD")
        .map_err(|_| anyhow::anyhow!("BIRD_APP_PASSWORD not set in .env"))?;
    Ok(BirdSecrets { app_password })
}

impl BirdConfig {
    pub fn request_delivery_enabled(&self) -> bool {
        self.receive_chat_requests || self.accept_chat_requests
    }
    pub fn request_policy(&self) -> crate::request_policy::RequestPolicy {
        crate::request_policy::RequestPolicy {
            auto_accept: self.accept_chat_requests,
            reply: self.reply_to_all_messages,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_default_to_disabled_and_auto_accept_is_explicit_opt_in() {
        let mut value = serde_json::json!({
            "handle": "fixture.example", "llmBackend": "bridge",
            "llmBaseURL": "http://127.0.0.1", "llmApiKey": "",
            "llmModel": "fixture", "systemPrompt": "fixture",
            "maxReplyCharacters": 1000
        });
        let disabled: BirdConfig = serde_json::from_value(value.clone()).unwrap();
        assert!(!disabled.request_delivery_enabled());
        assert!(!disabled.request_policy().auto_accept);
        assert!(!disabled.request_policy().reply);
        value["receiveChatRequests"] = serde_json::json!(true);
        let receiving: BirdConfig = serde_json::from_value(value.clone()).unwrap();
        assert!(receiving.request_delivery_enabled());
        assert!(!receiving.request_policy().auto_accept);
        value["receiveChatRequests"] = serde_json::json!(false);
        value["acceptChatRequests"] = serde_json::json!(true);
        let accepting: BirdConfig = serde_json::from_value(value).unwrap();
        assert!(accepting.request_delivery_enabled());
        assert!(accepting.request_policy().auto_accept);
        assert!(!accepting.request_policy().reply);
    }
}
