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
    pub accept_chat_requests: bool,
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
    let app_password =
        std::env::var("BIRD_APP_PASSWORD").map_err(|_| anyhow::anyhow!("BIRD_APP_PASSWORD not set in .env"))?;
    Ok(BirdSecrets { app_password })
}
