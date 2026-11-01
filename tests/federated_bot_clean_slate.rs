use std::sync::{Arc, Mutex};

use bird_daemon::bot::{BotLlmResponder, FederatedBirdBot, FederatedBotConfig};
use catbird_mls::client::REQUIRED_LABYRINTH_OAUTH_SCOPES;

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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn birdaemon_federated_bot_runs_without_nest_dependency_g3() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let responder = Arc::new(EchoResponder {
        seen_prompts: Mutex::new(Vec::new()),
    });

    let cfg = FederatedBotConfig {
        storage_root: tmp.path().to_path_buf(),
        bot_did: "did:plc:birdaemoncleanbot01".to_string(),
        bot_handle: "bird.catbird.blue".to_string(),
        device_id: "dev-birdaemon-01".to_string(),
        home_ds_did: "did:web:mlschat.catbird.blue".to_string(),
        home_ds_endpoint: "https://mlschat.catbird.blue".to_string(),
        pds_endpoint: "https://pds.catbird.blue".to_string(),
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
    assert_eq!(bot.account_did(), "did:plc:birdaemoncleanbot01");
    assert!(bot.labyrinth_status().expect("status").backup_enabled);

    // Create an MLS_256_XWING group and process an @mention
    let convo = bot
        .create_group("convo-bird-1", Some("Aviary Group".to_string()))
        .expect("create X-Wing group");
    assert_eq!(convo.conversation_id, "convo-bird-1");

    // Non-mention in group when reply_to_all_messages == false -> ignored
    let ignored = bot
        .handle_incoming_group_text(
            "convo-bird-1",
            "did:plc:alicepeer000001",
            "hello everyone without mention",
        )
        .await
        .expect("non-mention handled");
    assert!(ignored.is_none());

    // @bird.catbird.blue mention -> generates reply and encrypts + queues MLS message
    let sent = bot
        .handle_incoming_group_text(
            "convo-bird-1",
            "did:plc:alicepeer000001",
            "hey @bird.catbird.blue what is the weather?",
        )
        .await
        .expect("mention reply")
        .expect("should reply to mention");
    assert!(sent.plaintext_json.contains("chirp reply to:"));

    let messages = bot
        .list_messages("convo-bird-1", 20)
        .expect("list messages");
    assert_eq!(messages.len(), 1);
}
