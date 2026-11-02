use serde::Deserialize;
use std::path::PathBuf;

/// BIRDaemon configuration loaded from JSON + .env files (`G3`: zero `nest` dependency).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BirdConfig {
    pub handle: String,
    #[serde(default)]
    pub bot_did: Option<String>,
    #[serde(default = "default_device_id")]
    pub device_id: String,
    #[serde(default = "default_home_ds_did")]
    pub home_ds_did: String,
    #[serde(default = "default_home_ds_endpoint")]
    pub home_ds_endpoint: String,
    #[serde(default = "default_pds_endpoint")]
    pub pds_endpoint: String,
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

fn default_device_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

fn default_home_ds_did() -> String {
    "did:web:mlschat.catbird.blue".to_string()
}

fn default_home_ds_endpoint() -> String {
    "https://mlschat.catbird.blue".to_string()
}

fn default_pds_endpoint() -> String {
    "https://swan.place".to_string()
}

/// Secrets loaded from `.env` file (`BIRD_APP_PASSWORD` or `BIRD_PDS_OAUTH_TOKEN`).
#[derive(Debug, Clone)]
pub struct BirdSecrets {
    pub app_password: Option<String>,
    pub pds_oauth_token: Option<String>,
}

/// Get the Application Support directory for BIRDaemon.
pub fn data_dir() -> PathBuf {
    if let Ok(override_dir) = std::env::var("BIRD_DATA_DIR") {
        if !override_dir.trim().is_empty() {
            return PathBuf::from(override_dir);
        }
    }
    let home = dirs::home_dir().expect("could not find home directory");
    home.join("Library/Application Support/BirdDaemon")
}

/// Load configuration from `<data_dir>/config.json`.
pub fn load_config() -> anyhow::Result<BirdConfig> {
    let config_path = data_dir().join("config.json");
    tracing::info!("Loading config from {}", config_path.display());
    let contents = std::fs::read_to_string(&config_path)?;
    let config: BirdConfig = serde_json::from_str(&contents)?;
    Ok(config)
}

/// Load secrets from `<data_dir>/.env`.
pub fn load_secrets() -> anyhow::Result<BirdSecrets> {
    let env_path = data_dir().join(".env");
    if env_path.exists() {
        tracing::info!("Loading secrets from {}", env_path.display());
        dotenvy::from_path(&env_path)?;
    }
    let app_password = std::env::var("BIRD_APP_PASSWORD").ok();
    let pds_oauth_token = std::env::var("BIRD_PDS_OAUTH_TOKEN").ok();
    if app_password.is_none() && pds_oauth_token.is_none() {
        anyhow::bail!("Either BIRD_APP_PASSWORD or BIRD_PDS_OAUTH_TOKEN must be set");
    }
    Ok(BirdSecrets {
        app_password,
        pds_oauth_token,
    })
}
