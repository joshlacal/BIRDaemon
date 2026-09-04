use super::*;
const OWNER: &str = "did:plc:exit-test";
const CID: &str = "0a9b7f0b-1092-4221-b4a9-1a38098e97fd";
const OLD: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const NEW: &str = "2222222222222222222222222222222222222222222222222222222222222222";

async fn fixture() -> SqliteStorage {
    let path = std::env::temp_dir().join(format!("bir-exit-{}.db", uuid::Uuid::new_v4()));
    let storage = SqliteStorage::new(path, OWNER).unwrap();
    storage
        .ensure_conversation_exists(OWNER, CID, OLD)
        .await
        .unwrap();
    storage
        .set_group_state(&GroupState {
            group_id: OLD.into(),
            conversation_id: CID.into(),
            epoch: 9,
            members: vec![OWNER.into()],
        })
        .await
        .unwrap();
    storage
        .store_message(&Message {
            id: "retained".into(),
            conversation_id: CID.into(),
            sender_did: OWNER.into(),
            text: "history".into(),
            timestamp: Utc::now(),
            epoch: 9,
            sequence_number: 1,
            is_own: true,
            delivery_status: None,
            payload_json: Some("{\"retained\":true}".into()),
        })
        .await
        .unwrap();
    storage.conn.lock().unwrap().execute_batch("UPDATE conversations SET epoch = 9; CREATE TABLE exit_key_sentinel(value BLOB); INSERT INTO exit_key_sentinel VALUES(x'1234')").unwrap();
    storage
}
fn snapshot(storage: &SqliteStorage) -> String {
    let conn = storage.conn.lock().unwrap();
    let mut stmt = conn.prepare("SELECT group_id, state, epoch, reset_pending, reset_new_group_id, reset_generation, reset_generation_high_water, reset_notified_at_ms, needs_rejoin, updated_at FROM conversations").unwrap();
    let rows: Vec<Vec<rusqlite::types::Value>> = stmt
        .query_map([], |row| (0..10).map(|index| row.get(index)).collect())
        .unwrap()
        .map(|row| row.unwrap())
        .collect();
    format!("{rows:?}")
}

#[tokio::test]
async fn account_exit_preserves_history_and_exact_terminal_retry() {
    for terminal in [ConversationState::Closed, ConversationState::DeviceRemoved] {
        let storage = fixture().await;
        storage.mark_reset_pending(CID, NEW, 7, 123).await.unwrap();
        // New target's epoch is independent of the retained old group's9.
        assert!(storage
            .complete_account_exit(CID, NEW, Some(7), 3, terminal.clone())
            .await
            .unwrap());
        assert_eq!(
            storage.get_conversation_state(CID).await.unwrap(),
            Some(terminal.clone())
        );
        assert_eq!(
            storage
                .get_conversation(OWNER, CID)
                .await
                .unwrap()
                .unwrap()
                .epoch,
            3
        );
        assert_eq!(
            storage.get_group_state(OLD).await.unwrap().unwrap().epoch,
            9
        );
        assert_eq!(
            storage.get_messages(CID, 10, None).await.unwrap()[0].text,
            "history"
        );
        assert_eq!(
            storage
                .conn
                .lock()
                .unwrap()
                .query_row("SELECT hex(value) FROM exit_key_sentinel", [], |row| row
                    .get::<_, String>(
                    0
                ))
                .unwrap(),
            "1234"
        );
        let after = snapshot(&storage);
        assert!(storage
            .complete_account_exit(CID, NEW, Some(7), 3, terminal.clone())
            .await
            .unwrap());
        assert!(!storage
            .complete_account_exit(CID, NEW, Some(8), 3, terminal.clone())
            .await
            .unwrap());
        assert!(!storage.complete_account_exit(CID, NEW, Some(7), 2, terminal).await.unwrap());
        assert_eq!(snapshot(&storage), after);
        assert!(storage.mark_reset_pending(CID, NEW, 7, 123).await.is_err());
        assert_eq!(snapshot(&storage), after);
    }
}
#[tokio::test]
async fn account_exit_rejects_stale_epoch_pending_generation_and_torn_rows() {
    let storage = fixture().await;
    let before = snapshot(&storage);
    assert!(!storage
        .complete_account_exit(CID, OLD, None, 3, ConversationState::Closed)
        .await
        .unwrap());
    assert_eq!(snapshot(&storage), before);
    storage.mark_reset_pending(CID, OLD, 7, 123).await.unwrap();
    let before = snapshot(&storage);
    for (group, generation, epoch, state) in [
        (OLD, Some(7), 3, ConversationState::Closed),
        (NEW, Some(7), 10, ConversationState::Closed),
        (OLD, Some(6), 10, ConversationState::Closed),
        (OLD, None, 10, ConversationState::Closed),
        (OLD, Some(7), 10, ConversationState::Active),
        (OLD, Some(0), 10, ConversationState::Closed),
    ] {
        assert!(!storage
            .complete_account_exit(CID, group, generation, epoch, state)
            .await
            .unwrap());
    }
    assert_eq!(snapshot(&storage), before);
    storage
        .conn
        .lock()
        .unwrap()
        .execute_batch("UPDATE conversations SET reset_notified_at_ms = NULL")
        .unwrap();
    let torn = snapshot(&storage);
    assert!(!storage
        .complete_account_exit(CID, OLD, Some(7), 10, ConversationState::Closed)
        .await
        .unwrap());
    assert_eq!(snapshot(&storage), torn);
}
#[tokio::test]
async fn account_exit_historical_highwater_and_rollback_are_preserved() {
    let storage = fixture().await;
    storage.conn.lock().unwrap().execute_batch("UPDATE conversations SET reset_generation_high_water = 4; CREATE TRIGGER fail_exit BEFORE UPDATE OF state ON conversations BEGIN SELECT RAISE(ABORT,'fixture'); END").unwrap();
    let before = snapshot(&storage);
    assert!(storage
        .complete_account_exit(CID, OLD, None, 10, ConversationState::DeviceRemoved)
        .await
        .is_err());
    assert_eq!(snapshot(&storage), before);
    storage
        .conn
        .lock()
        .unwrap()
        .execute_batch("DROP TRIGGER fail_exit")
        .unwrap();
    assert!(storage
        .complete_account_exit(CID, OLD, None, 10, ConversationState::DeviceRemoved)
        .await
        .unwrap());
    assert_eq!(
        storage
            .conn
            .lock()
            .unwrap()
            .query_row(
                "SELECT reset_generation_high_water FROM conversations",
                [],
                |row| row.get::<_, i32>(0)
            )
            .unwrap(),
        4
    );
}

#[tokio::test]
async fn account_exit_advances_device_removal_only_with_dedicated_authority() {
    let storage = fixture().await;
    assert!(storage
        .complete_account_exit(CID, OLD, None, 10, ConversationState::DeviceRemoved)
        .await
        .unwrap());
    assert!(storage
        .set_conversation_state(CID, ConversationState::Active)
        .await
        .is_err());
    let before = snapshot(&storage);
    assert!(!storage
        .complete_account_exit(CID, OLD, None, 9, ConversationState::Closed)
        .await
        .unwrap());
    assert_eq!(snapshot(&storage), before);
    assert!(storage
        .complete_account_exit(CID, OLD, None, 11, ConversationState::DeviceRemoved)
        .await
        .unwrap());
    assert!(storage
        .complete_account_exit(CID, OLD, None, 12, ConversationState::Closed)
        .await
        .unwrap());
    let closed = snapshot(&storage);
    assert!(!storage
        .complete_account_exit(CID, OLD, None, 13, ConversationState::Closed)
        .await
        .unwrap());
    assert!(!storage
        .complete_account_exit(CID, OLD, None, 12, ConversationState::DeviceRemoved)
        .await
        .unwrap());
    assert!(storage.mark_reset_pending(CID, NEW, 8, 456).await.is_err());
    assert_eq!(snapshot(&storage), closed);
}

#[tokio::test]
async fn account_exit_retained_generation_cannot_authorize_a_new_terminal_record() {
    let storage = fixture().await;
    storage.mark_reset_pending(CID, NEW, 7, 123).await.unwrap();
    assert!(storage.complete_account_exit(CID, NEW, Some(7), 3, ConversationState::DeviceRemoved).await.unwrap());
    assert!(!storage.complete_account_exit(CID, NEW, Some(8), 4, ConversationState::Closed).await.unwrap());
    assert!(!storage.complete_account_exit(CID, NEW, Some(7), 4, ConversationState::Closed).await.unwrap());
    assert!(storage.complete_account_exit(CID, NEW, None, 4, ConversationState::Closed).await.unwrap());
}
