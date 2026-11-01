use std::sync::Arc;
use tracing_subscriber::EnvFilter;

use bird_daemon::bot::{FederatedBirdBot, FederatedBotConfig, HttpLlmResponder};
use bird_daemon::config::{data_dir, load_config, load_secrets};
use catbird_mls::client::REQUIRED_LABYRINTH_OAUTH_SCOPES;

/// Authenticate directly against an ATProto PDS via `com.atproto.server.createSession` and
/// mint a `com.atproto.server.getServiceAuth` JWT for the bot's home `mls-ds` (`G3`: zero `nest`).
async fn authenticate_with_pds_and_home_ds(
    pds_endpoint: &str,
    identifier: &str,
    app_password: &str,
    home_ds_did: &str,
) -> anyhow::Result<(String, String, String)> {
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()?;
    let trimmed = pds_endpoint.trim_end_matches('/');

    let session_resp = http
        .post(format!("{trimmed}/xrpc/com.atproto.server.createSession"))
        .json(&serde_json::json!({
            "identifier": identifier,
            "password": app_password,
        }))
        .send()
        .await?;
    let status = session_resp.status();
    let session_val: serde_json::Value = session_resp.json().await?;
    if !status.is_success() {
        anyhow::bail!("PDS createSession failed ({status}): {session_val}");
    }
    let did = session_val
        .get("did")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("missing did in createSession response"))?
        .to_string();
    let access_jwt = session_val
        .get("accessJwt")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("missing accessJwt in createSession response"))?
        .to_string();

    let svc_resp = http
        .get(format!("{trimmed}/xrpc/com.atproto.server.getServiceAuth"))
        .bearer_auth(&access_jwt)
        .query(&[("aud", home_ds_did)])
        .send()
        .await?;
    let svc_status = svc_resp.status();
    let svc_val: serde_json::Value = svc_resp.json().await?;
    if !svc_status.is_success() {
        anyhow::bail!("PDS getServiceAuth failed ({svc_status}): {svc_val}");
    }
    let service_token = svc_val
        .get("token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("missing token in getServiceAuth response"))?
        .to_string();

    Ok((did, access_jwt, service_token))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    tracing::info!("BIRDaemon (Clean-Slate Federated MLS + Spaces, zero Nest) starting...");

    let cfg = load_config()?;
    let secrets = load_secrets()?;
    let storage_root = data_dir();
    std::fs::create_dir_all(&storage_root)?;

    let (resolved_did, pds_token, ds_service_token) =
        if let Some(ref app_pw) = secrets.app_password {
            let (did, access_jwt, svc_tok) = authenticate_with_pds_and_home_ds(
                &cfg.pds_endpoint,
                &cfg.handle,
                app_pw,
                &cfg.home_ds_did,
            )
            .await?;
            (
                did,
                secrets.pds_oauth_token.clone().unwrap_or(access_jwt),
                Some(svc_tok),
            )
        } else {
            let did = cfg.bot_did.clone().ok_or_else(|| {
                anyhow::anyhow!("botDid required when using BIRD_PDS_OAUTH_TOKEN")
            })?;
            let tok = secrets
                .pds_oauth_token
                .clone()
                .ok_or_else(|| anyhow::anyhow!("missing BIRD_PDS_OAUTH_TOKEN"))?;
            (did, tok, None)
        };

    let responder = Arc::new(HttpLlmResponder::new(
        cfg.llm_base_url.clone(),
        cfg.llm_api_key.clone(),
        cfg.llm_model.clone(),
        cfg.system_prompt.clone(),
    )?);

    let bot_cfg = FederatedBotConfig {
        storage_root,
        bot_did: resolved_did,
        bot_handle: cfg.handle.clone(),
        device_id: cfg.device_id.clone(),
        home_ds_did: cfg.home_ds_did.clone(),
        home_ds_endpoint: cfg.home_ds_endpoint.clone(),
        pds_endpoint: cfg.pds_endpoint.clone(),
        pds_supports_spaces: true,
        granted_oauth_scopes: REQUIRED_LABYRINTH_OAUTH_SCOPES
            .iter()
            .map(|s| (*s).to_string())
            .collect(),
        accept_chat_requests: cfg.accept_chat_requests,
        reply_to_all_messages: cfg.reply_to_all_messages,
        max_reply_characters: cfg.max_reply_characters,
    };

    let bot = FederatedBirdBot::open_and_enroll(bot_cfg, responder)?;
    bot.set_auth_tokens(ds_service_token, Some(pds_token));
    tracing::info!(
        did = %bot.account_did(),
        mailbox_space = %bot.enrollment_receipt().mailbox_space_uri,
        "BIRDaemon enrolled and running without Nest"
    );

    let mut tick = tokio::time::interval(std::time::Duration::from_secs(15));
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("Received Ctrl-C; shutting down BIRDaemon cleanly");
                break;
            }
            _ = tick.tick() => {
                if let Err(e) = bot.accept_pending_requests() {
                    tracing::warn!("accept_pending_requests failed: {e}");
                }
                if let Err(e) = bot.flush_labyrinth_queue() {
                    tracing::debug!("flush_labyrinth_queue deferred: {e}");
                }
            }
        }
    }

    Ok(())
}
