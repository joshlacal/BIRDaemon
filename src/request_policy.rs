//! Bot effect policy. A preview or membership alone never authorizes a reply.
use catbird_mls::orchestrator::{DirectRequestView, RequestConsent, RequestCrypto, RequestPreview};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestPolicy {
    pub auto_accept: bool,
    pub reply: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestKeyAction {
    None,
    Enable,
    Disable,
    Replenish,
}
pub fn request_key_action(receive: bool, current: Option<bool>) -> RequestKeyAction {
    match (receive, current) {
        (false, Some(true)) => RequestKeyAction::Disable,
        (false, _) => RequestKeyAction::None,
        (true, Some(true)) => RequestKeyAction::Replenish,
        (true, _) => RequestKeyAction::Enable,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestAction {
    Withhold,
    Accept,
    Reply,
}

impl RequestPolicy {
    pub fn action(self, view: &DirectRequestView) -> RequestAction {
        let ready = view.crypto == RequestCrypto::Ready
            && matches!(view.preview, Some(RequestPreview::Ready { .. }))
            && view.first_message_id.is_some()
            && view.introduction.is_some();
        if !ready {
            return RequestAction::Withhold;
        }
        match view.consent {
            RequestConsent::IncomingPending if self.auto_accept && view.capabilities.can_accept => {
                RequestAction::Accept
            }
            RequestConsent::Accepted if self.reply && view.capabilities.can_send => {
                RequestAction::Reply
            }
            _ => RequestAction::Withhold,
        }
    }
}

pub fn legacy_effects_allowed(
    state: &catbird_atproto::blue_catbird::chat::ConversationState,
    did: &str,
) -> bool {
    catbird_mls::orchestrator::admission::validate_conversation_policy(state).is_ok()
        && state.direct_request.is_none()
        && state.coordinates.lifecycle.as_str() == "active"
        && state
            .participants
            .iter()
            .any(|p| p.user_did.as_str() == did && p.status.as_str() == "active")
        && (state.conversation_kind.as_str() != "direct"
            || state
                .participants
                .iter()
                .all(|p| p.status.as_str() == "active"))
}

/// Called only with the shared core's verified projection. This durable gate
/// precedes every introduction effect and never stores its plaintext.
pub fn claim_request_effect(
    policy: RequestPolicy,
    view: &DirectRequestView,
    storage: &crate::storage::SqliteStorage,
) -> bool {
    policy.action(view) == RequestAction::Reply
        && view.first_message_id.as_deref().is_some_and(|id| {
            storage
                .claim_bot_effect(&view.conversation_id, id)
                .unwrap_or(false)
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::SqliteStorage;
    use catbird_mls::orchestrator::{RequestCapabilities, RequestIntroductionMetadata};

    fn view(consent: RequestConsent, crypto: RequestCrypto) -> DirectRequestView {
        DirectRequestView {
            introduction: Some(RequestIntroductionMetadata {
                sender_did: "did:plc:sender".into(),
                sender_device_id: "device".into(),
                received_at: "2026-09-19T00:00:00.000Z".into(),
                epoch: 1,
                sequence_number: 1,
            }),
            conversation_id: "11111111-1111-4111-8111-111111111111".into(),
            first_message_id: Some("22222222-2222-4222-8222-222222222222".into()),
            consent,
            crypto,
            preview: Some(RequestPreview::Ready {
                text: "PROTECTED-PENDING-PREVIEW".into(),
                invitation: None,
            }),
            capabilities: RequestCapabilities::derive(consent, crypto, true),
            state_version: 1,
            generation: 0,
        }
    }

    #[derive(Default, Debug, PartialEq, Eq)]
    struct Effects {
        plaintext_log_count: usize,
        typing_count: usize,
        download_count: usize,
        bridge_count: usize,
        reply_count: usize,
    }
    fn observe(
        policy: RequestPolicy,
        view: &DirectRequestView,
        storage: &SqliteStorage,
        effects: &mut Effects,
    ) {
        if claim_request_effect(policy, view, storage) {
            effects.bridge_count += 1;
            effects.reply_count += 1;
        }
    }
    #[test]
    fn pending_invalid_expired_closed_and_disabled_policy_have_zero_effects() {
        let path = std::env::temp_dir().join(format!("bird-policy-{}.db", uuid::Uuid::new_v4()));
        let storage = SqliteStorage::new(path.clone(), "did:plc:recipient").unwrap();
        let mut effects = Effects::default();
        for auto_accept in [false, true] {
            let policy = RequestPolicy {
                auto_accept,
                reply: true,
            };
            for consent in [
                RequestConsent::IncomingPending,
                RequestConsent::OutgoingPending,
                RequestConsent::Closed,
            ] {
                for crypto in [
                    RequestCrypto::Ready,
                    RequestCrypto::Unavailable,
                    RequestCrypto::Importing,
                    RequestCrypto::WelcomeAvailable,
                ] {
                    observe(policy, &view(consent, crypto), &storage, &mut effects);
                }
            }
            for code in [
                "InvalidIntroduction",
                "PreparationExpired",
                "Blocked",
                "Declined",
            ] {
                let mut invalid = view(RequestConsent::Accepted, RequestCrypto::Ready);
                invalid.preview = Some(RequestPreview::Unavailable { code: code.into() });
                observe(policy, &invalid, &storage, &mut effects);
            }
            let mut malformed = view(RequestConsent::Accepted, RequestCrypto::Ready);
            malformed.introduction = None;
            observe(policy, &malformed, &storage, &mut effects);
        }
        observe(
            RequestPolicy {
                auto_accept: true,
                reply: false,
            },
            &view(RequestConsent::Accepted, RequestCrypto::Ready),
            &storage,
            &mut effects,
        );
        assert_eq!(effects, Effects::default());
        let db = rusqlite::Connection::open(path).unwrap();
        assert_eq!(
            db.query_row("SELECT count(*) FROM bot_effect_claims", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert_eq!(
            db.query_row("SELECT count(*) FROM messages", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            0
        );
    }
    #[test]
    fn explicit_acceptance_then_restart_and_replay_emit_at_most_once_without_plaintext_storage() {
        let path =
            std::env::temp_dir().join(format!("bird-policy-restart-{}.db", uuid::Uuid::new_v4()));
        let policy = RequestPolicy {
            auto_accept: true,
            reply: true,
        };
        let storage = SqliteStorage::new(path.clone(), "did:plc:recipient").unwrap();
        let pending = view(RequestConsent::IncomingPending, RequestCrypto::Ready);
        assert_eq!(policy.action(&pending), RequestAction::Accept);
        assert_eq!(
            RequestPolicy {
                auto_accept: false,
                reply: true
            }
            .action(&pending),
            RequestAction::Withhold
        );
        let mut effects = Effects::default();
        observe(policy, &pending, &storage, &mut effects);
        assert_eq!(effects, Effects::default());
        let accepted = view(RequestConsent::Accepted, RequestCrypto::Ready);
        observe(policy, &accepted, &storage, &mut effects);
        observe(policy, &accepted, &storage, &mut effects);
        drop(storage);
        let restarted = SqliteStorage::new(path.clone(), "did:plc:recipient").unwrap();
        observe(policy, &accepted, &restarted, &mut effects);
        assert_eq!(effects.bridge_count, 1);
        assert_eq!(effects.reply_count, 1);
        assert_eq!(effects.plaintext_log_count, 0);
        let db = rusqlite::Connection::open(&path).unwrap();
        assert_eq!(
            db.query_row("SELECT count(*) FROM messages", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert_eq!(
            db.query_row(
                "SELECT length(effect_digest) FROM bot_effect_claims",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            32
        );
        assert!(!std::fs::read(path)
            .unwrap()
            .windows(b"PROTECTED-PENDING-PREVIEW".len())
            .any(|x| x == b"PROTECTED-PENDING-PREVIEW"));
    }
    #[test]
    fn native_pending_projection_is_encrypted_and_survives_restart() {
        use catbird_mls::orchestrator::MlsCryptoContext;
        use catbird_mls::MLSContext;
        let dir =
            std::env::temp_dir().join(format!("bird-protected-preview-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let native_path = dir.join("native.db");
        let key = "local-test-only-independent-encryption-key";
        let cid = "11111111-1111-4111-8111-111111111111";
        let marker = b"BIRD-PENDING-PLAINTEXT-MUST-NOT-APPEAR-ON-DISK";
        let open = || {
            MLSContext::new(
                native_path.to_string_lossy().into_owned(),
                key.into(),
                Box::new(
                    crate::keychain::FileKeychain::new(dir.join("test-keychain.json")).unwrap(),
                ),
            )
            .unwrap()
        };
        let native = open();
        // Storage custody probe only: malformed bytes must never become a verified view.
        assert!(native
            .compare_exchange_direct_request_projection(cid, None, marker)
            .unwrap());
        assert_eq!(
            native
                .read_direct_request_projection(cid)
                .unwrap()
                .as_deref(),
            Some(marker.as_slice())
        );
        drop(native);
        let reopened = open();
        assert_eq!(
            reopened
                .read_direct_request_projection(cid)
                .unwrap()
                .as_deref(),
            Some(marker.as_slice())
        );
        drop(reopened);
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_file() {
                assert!(
                    !std::fs::read(&path)
                        .unwrap()
                        .windows(marker.len())
                        .any(|x| x == marker),
                    "plaintext in {}",
                    path.display()
                );
            }
        }
        let unkeyed = rusqlite::Connection::open(native_path).unwrap();
        assert!(unkeyed
            .query_row("SELECT count(*) FROM sqlite_master", [], |r| r
                .get::<_, i64>(0))
            .is_err());
    }
    #[test]
    fn disabled_delivery_never_allocates_keys() {
        assert_eq!(request_key_action(false, None), RequestKeyAction::None);
        assert_eq!(
            request_key_action(false, Some(false)),
            RequestKeyAction::None
        );
        assert_eq!(
            request_key_action(false, Some(true)),
            RequestKeyAction::Disable
        );
        assert_eq!(request_key_action(true, None), RequestKeyAction::Enable);
        assert_eq!(
            request_key_action(true, Some(true)),
            RequestKeyAction::Replenish
        );
    }
    #[test]
    fn legacy_direct_requires_both_accounts_active_while_groups_keep_their_policy() {
        let mut state: catbird_atproto::blue_catbird::chat::ConversationState =
            catbird_mls::orchestrator::canonical_transport::decode_conversation_state(
                include_str!("../tests/fixtures/canonical-conversation-state.json")
                    .trim()
                    .as_bytes(),
            )
            .unwrap();
        let owner = state.participants[0].user_did.to_string();
        assert!(legacy_effects_allowed(&state, &owner));
        state.conversation_kind = "direct".into();
        assert!(!legacy_effects_allowed(&state, &owner));
        state.participants[1].status = "active".into();
        assert!(legacy_effects_allowed(&state, &owner));
        state.coordinates.lifecycle = "superseded".into();
        assert!(!legacy_effects_allowed(&state, &owner));
        assert!(!legacy_effects_allowed(&state, "did:plc:someoneelse"));
    }
    #[tokio::test]
    async fn inert_http_bridge_observes_only_one_claimed_accepted_introduction() {
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        };
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let bridge = crate::bridge_client::BridgeClient::new(&format!(
            "http://{}",
            listener.local_addr().unwrap()
        ));
        let posts = Arc::new(AtomicUsize::new(0));
        let observed = posts.clone();
        let server = tokio::spawn(async move {
            for expected_path in ["POST /message", "GET /reply/"] {
                let (mut stream, _) =
                    tokio::time::timeout(std::time::Duration::from_secs(5), listener.accept())
                        .await
                        .unwrap()
                        .unwrap();
                let mut request = Vec::new();
                loop {
                    let mut chunk = [0u8; 4096];
                    let count = stream.read(&mut chunk).await.unwrap();
                    assert_ne!(count, 0);
                    request.extend_from_slice(&chunk[..count]);
                    assert!(request.len() < 65536);
                    if let Some(end) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                        let headers = String::from_utf8_lossy(&request[..end]);
                        let length = headers
                            .lines()
                            .find_map(|line| {
                                line.to_ascii_lowercase()
                                    .strip_prefix("content-length:")
                                    .map(|value| value.trim().parse::<usize>().unwrap())
                            })
                            .unwrap_or(0);
                        if request.len() >= end + 4 + length {
                            break;
                        }
                    }
                }
                let request = String::from_utf8(request).unwrap();
                assert!(request.starts_with(expected_path));
                if expected_path.starts_with("POST") {
                    assert!(request.contains("PROTECTED-PENDING-PREVIEW"));
                    observed.fetch_add(1, Ordering::SeqCst);
                }
                let body = if expected_path.starts_with("POST") {
                    "{}"
                } else {
                    r#"{"status":"ready","text":"inert reply"}"#
                };
                stream.write_all(format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    body.len(), body
                ).as_bytes()).await.unwrap();
            }
        });
        let path = std::env::temp_dir().join(format!("bird-inert-{}.db", uuid::Uuid::new_v4()));
        let policy = RequestPolicy {
            auto_accept: true,
            reply: true,
        };
        let storage = SqliteStorage::new(path.clone(), "did:plc:recipient").unwrap();
        for consent in [
            RequestConsent::IncomingPending,
            RequestConsent::OutgoingPending,
            RequestConsent::Closed,
        ] {
            assert!(!claim_request_effect(
                policy,
                &view(consent, RequestCrypto::Ready),
                &storage
            ));
        }
        assert_eq!(posts.load(Ordering::SeqCst), 0);
        let accepted = view(RequestConsent::Accepted, RequestCrypto::Ready);
        assert!(claim_request_effect(policy, &accepted, &storage));
        let Some(RequestPreview::Ready { text, .. }) = &accepted.preview else {
            panic!("fixture preview")
        };
        let reply = bridge
            .generate(
                &accepted.conversation_id,
                "did:plc:sender",
                text,
                None,
                None,
            )
            .await
            .unwrap();
        assert_eq!(reply, "inert reply");
        server.await.unwrap();
        assert_eq!(posts.load(Ordering::SeqCst), 1);
        drop(storage);
        let reopened = SqliteStorage::new(path, "did:plc:recipient").unwrap();
        assert!(!claim_request_effect(policy, &accepted, &reopened));
        assert_eq!(posts.load(Ordering::SeqCst), 1);
    }
}
