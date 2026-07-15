//! SQLite-backed MLSStorageBackend implementation.

use std::path::PathBuf;
use std::sync::Mutex;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use rusqlite::{Connection, OptionalExtension};

use catbird_mls::orchestrator::error::{OrchestratorError, Result};
use catbird_mls::orchestrator::storage::MLSStorageBackend;
use catbird_mls::orchestrator::types::*;

pub struct SqliteStorage {
    conn: Mutex<Connection>,
}

impl SqliteStorage {
    pub fn new(path: PathBuf) -> anyhow::Result<Self> {
        let conn = Connection::open(&path)?;
        let storage = Self {
            conn: Mutex::new(conn),
        };
        storage.create_tables()?;
        Ok(storage)
    }

    fn create_tables(&self) -> anyhow::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS conversations (
                conversation_id TEXT PRIMARY KEY,
                user_did TEXT NOT NULL,
                group_id TEXT NOT NULL,
                state TEXT NOT NULL DEFAULT 'Initializing',
                needs_rejoin INTEGER NOT NULL DEFAULT 0,
                reset_pending INTEGER NOT NULL DEFAULT 0,
                reset_new_group_id TEXT,
                reset_generation INTEGER,
                reset_notified_at_ms INTEGER,
                applied_reset_generation INTEGER NOT NULL DEFAULT -1,
                reset_generation_fence_initialized INTEGER NOT NULL DEFAULT 1,
                join_method TEXT,
                join_epoch INTEGER,
                epoch INTEGER NOT NULL DEFAULT 0,
                members_json TEXT NOT NULL DEFAULT '[]',
                metadata_json TEXT,
                created_at TEXT,
                updated_at TEXT,
                sequencer_did TEXT
            );

            CREATE TABLE IF NOT EXISTS messages (
                id TEXT PRIMARY KEY,
                conversation_id TEXT NOT NULL,
                sender_did TEXT NOT NULL,
                text TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                epoch INTEGER NOT NULL,
                sequence_number INTEGER NOT NULL,
                is_own INTEGER NOT NULL DEFAULT 0,
                delivery_status_json TEXT,
                payload_json TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_messages_convo
                ON messages(conversation_id, sequence_number);

            CREATE TABLE IF NOT EXISTS group_states (
                group_id TEXT PRIMARY KEY,
                conversation_id TEXT NOT NULL,
                epoch INTEGER NOT NULL,
                members_json TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS sync_cursors (
                user_did TEXT PRIMARY KEY,
                conversations_cursor TEXT,
                messages_cursor TEXT
            );
            ",
        )?;

        // Migration: add payload_json column to existing databases
        let has_payload_json: bool = conn
            .prepare("SELECT COUNT(*) FROM pragma_table_info('messages') WHERE name='payload_json'")
            .and_then(|mut stmt| stmt.query_row([], |row| row.get::<_, i64>(0)))
            .map(|count| count > 0)
            .unwrap_or(false);
        if !has_payload_json {
            conn.execute_batch("ALTER TABLE messages ADD COLUMN payload_json TEXT;")?;
            tracing::info!("Migrated messages table: added payload_json column");
        }

        let conversation_columns = [
            (
                "reset_pending",
                "ALTER TABLE conversations ADD COLUMN reset_pending INTEGER NOT NULL DEFAULT 0;",
            ),
            (
                "reset_new_group_id",
                "ALTER TABLE conversations ADD COLUMN reset_new_group_id TEXT;",
            ),
            (
                "reset_generation",
                "ALTER TABLE conversations ADD COLUMN reset_generation INTEGER;",
            ),
            (
                "reset_notified_at_ms",
                "ALTER TABLE conversations ADD COLUMN reset_notified_at_ms INTEGER;",
            ),
            (
                "applied_reset_generation",
                "ALTER TABLE conversations ADD COLUMN applied_reset_generation INTEGER NOT NULL DEFAULT -1;",
            ),
            (
                "reset_generation_fence_initialized",
                "ALTER TABLE conversations ADD COLUMN reset_generation_fence_initialized INTEGER NOT NULL DEFAULT 0;",
            ),
            (
                "sequencer_did",
                "ALTER TABLE conversations ADD COLUMN sequencer_did TEXT;",
            ),
        ];
        for (name, ddl) in conversation_columns {
            let exists: bool = conn
                .prepare("SELECT COUNT(*) FROM pragma_table_info('conversations') WHERE name=?1")
                .and_then(|mut stmt| stmt.query_row([name], |row| row.get::<_, i64>(0)))
                .map(|count| count > 0)
                .unwrap_or(false);
            if !exists {
                conn.execute_batch(ddl)?;
                tracing::info!("Migrated conversations table: added {} column", name);
            }
        }

        // Idempotently preserve the known generation of every fenced complete
        // tuple. Running this after every startup closes a crash window where
        // ALTER TABLE could have committed but this forensic seed had not.
        // The row stays fenced because the legacy writer projected group_id to
        // the target before predecessor deletion, so its mapping is untrusted.
        conn.execute(
            "UPDATE conversations
             SET applied_reset_generation = MAX(applied_reset_generation, reset_generation),
                 needs_rejoin = 1
             WHERE reset_generation_fence_initialized = 0
               AND state = 'ResetPending'
               AND reset_pending = 1
               AND reset_new_group_id IS NOT NULL
               AND reset_generation IS NOT NULL
               AND reset_notified_at_ms IS NOT NULL",
            [],
        )?;
        let fenced_rows: i64 = conn.query_row(
            "SELECT COUNT(*) FROM conversations
             WHERE reset_generation_fence_initialized = 0",
            [],
            |row| row.get(0),
        )?;
        if fenced_rows > 0 {
            tracing::warn!(
                fenced_rows,
                "Legacy MLS reset rows require authoritative reset-generation reconciliation"
            );
        }

        Ok(())
    }

    fn map_err(e: rusqlite::Error) -> OrchestratorError {
        OrchestratorError::Storage(e.to_string())
    }

    fn require_reconciled_reset_authority(conn: &Connection, conversation_id: &str) -> Result<()> {
        let reconciled = conn
            .query_row(
                "SELECT reset_generation_fence_initialized
                 FROM conversations WHERE conversation_id = ?1",
                [conversation_id],
                |row| row.get::<_, i32>(0),
            )
            .optional()
            .map_err(Self::map_err)?;
        if reconciled == Some(0) {
            return Err(OrchestratorError::Storage(format!(
                "conversation {conversation_id} has legacy reset authority and requires authoritative reconciliation"
            )));
        }
        Ok(())
    }

    fn parse_state(s: &str) -> ConversationState {
        match s {
            "Active" => ConversationState::Active,
            "NeedsRejoin" => ConversationState::NeedsRejoin,
            "ForkDetected" => ConversationState::ForkDetected,
            "ResetPending" => ConversationState::ResetPending {
                new_group_id: String::new(),
                reset_generation: 0,
                notified_at_ms: 0,
            },
            // Quarantine survives restart (suppresses auto-rejoin). reason/since_ms
            // are diagnostic and not persisted, so restore a sensible default.
            "Quarantined" => ConversationState::Quarantined {
                reason: QuarantineReason::PeerBadCommit,
                since_ms: 0,
            },
            "Failed" => ConversationState::Failed,
            _ => ConversationState::Initializing,
        }
    }

    fn state_str(s: &ConversationState) -> &'static str {
        match s {
            ConversationState::Initializing => "Initializing",
            ConversationState::Active => "Active",
            ConversationState::ForkDetected => "ForkDetected",
            ConversationState::NeedsRejoin => "NeedsRejoin",
            ConversationState::ResetPending { .. } => "ResetPending",
            ConversationState::Quarantined { .. } => "Quarantined",
            ConversationState::Failed => "Failed",
        }
    }

    fn parse_join_method(s: &str) -> JoinMethod {
        match s {
            "Welcome" => JoinMethod::Welcome,
            "ExternalCommit" => JoinMethod::ExternalCommit,
            _ => JoinMethod::Creator,
        }
    }

    fn parse_dt(s: &str) -> Option<DateTime<Utc>> {
        DateTime::parse_from_rfc3339(s)
            .ok()
            .map(|dt| dt.with_timezone(&Utc))
    }

    fn row_to_conversation_view(row: &rusqlite::Row<'_>) -> rusqlite::Result<ConversationView> {
        let conversation_id: String = row.get("conversation_id")?;
        let group_id: String = row.get("group_id")?;
        let epoch: u64 = row.get("epoch")?;
        let members_json: String = row.get("members_json")?;
        let metadata_json: Option<String> = row.get("metadata_json")?;
        let created_at: Option<String> = row.get("created_at")?;
        let updated_at: Option<String> = row.get("updated_at")?;
        let sequencer_did: Option<String> = row.get("sequencer_did")?;

        let members: Vec<MemberView> = serde_json::from_str(&members_json).unwrap_or_default();
        let metadata: Option<ConversationMetadata> =
            metadata_json.and_then(|j| serde_json::from_str(&j).ok());

        Ok(ConversationView {
            group_id,
            conversation_id,
            epoch,
            members,
            metadata,
            created_at: created_at.and_then(|s| Self::parse_dt(&s)),
            updated_at: updated_at.and_then(|s| Self::parse_dt(&s)),
            sequencer_did,
        })
    }

    /// Atomically retarget a complete, reconciled ResetPending tuple after
    /// the authoritative winner has been verified. The trait implementation
    /// forwards here so focused tests exercise the same atomic statement.
    fn adopt_reset_pending_target_cas(
        &self,
        conversation_id: &str,
        expected_generation: i32,
        expected_old_target: &str,
        authoritative_new_target: &str,
    ) -> Result<bool> {
        if authoritative_new_target.is_empty() {
            return Ok(false);
        }
        let conn = self.conn.lock().unwrap();
        let changed = conn
            .execute(
                "UPDATE conversations
                 SET reset_new_group_id = ?1,
                     needs_rejoin = 1
                 WHERE conversation_id = ?2
                   AND ?1 <> ''
                   AND state = 'ResetPending'
                   AND reset_pending = 1
                   AND reset_new_group_id = ?3
                   AND reset_new_group_id <> ''
                   AND reset_generation = ?4
                   AND reset_notified_at_ms IS NOT NULL
                   AND reset_generation_fence_initialized = 1",
                rusqlite::params![
                    authoritative_new_target,
                    conversation_id,
                    expected_old_target,
                    expected_generation,
                ],
            )
            .map_err(Self::map_err)?;
        Ok(changed == 1)
    }
}

#[async_trait]
impl MLSStorageBackend for SqliteStorage {
    // -- Conversations --

    async fn ensure_conversation_exists(
        &self,
        user_did: &str,
        conversation_id: &str,
        group_id: &str,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let now = Utc::now().to_rfc3339();
        conn.execute(
            "INSERT OR IGNORE INTO conversations
             (conversation_id, user_did, group_id, state, epoch, members_json, created_at, updated_at)
             VALUES (?1, ?2, ?3, 'Initializing', 0, '[]', ?4, ?4)",
            rusqlite::params![conversation_id, user_did, group_id, now],
        )
        .map_err(Self::map_err)?;
        Ok(())
    }

    async fn update_join_info(
        &self,
        conversation_id: &str,
        _user_did: &str,
        join_method: JoinMethod,
        join_epoch: u64,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let method_str = match join_method {
            JoinMethod::Creator => "Creator",
            JoinMethod::Welcome => "Welcome",
            JoinMethod::ExternalCommit => "ExternalCommit",
        };
        conn.execute(
            "UPDATE conversations SET join_method = ?1, join_epoch = ?2, epoch = ?2
             WHERE conversation_id = ?3",
            rusqlite::params![method_str, join_epoch, conversation_id],
        )
        .map_err(Self::map_err)?;
        Ok(())
    }

    async fn get_conversation(
        &self,
        _user_did: &str,
        conversation_id: &str,
    ) -> Result<Option<ConversationView>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT conversation_id, group_id, epoch, members_json, metadata_json, created_at, updated_at, sequencer_did
                 FROM conversations WHERE conversation_id = ?1",
            )
            .map_err(Self::map_err)?;

        let result = stmt
            .query_row(
                rusqlite::params![conversation_id],
                Self::row_to_conversation_view,
            )
            .optional()
            .map_err(Self::map_err)?;

        Ok(result)
    }

    async fn list_conversations(&self, user_did: &str) -> Result<Vec<ConversationView>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT conversation_id, group_id, epoch, members_json, metadata_json, created_at, updated_at, sequencer_did
                 FROM conversations WHERE user_did = ?1",
            )
            .map_err(Self::map_err)?;

        let views = stmt
            .query_map(rusqlite::params![user_did], Self::row_to_conversation_view)
            .map_err(Self::map_err)?
            .filter_map(|r| r.ok())
            .collect();

        Ok(views)
    }

    async fn delete_conversations(&self, _user_did: &str, ids: &[&str]) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        for id in ids {
            conn.execute(
                "DELETE FROM conversations WHERE conversation_id = ?1",
                rusqlite::params![id],
            )
            .map_err(Self::map_err)?;
            conn.execute(
                "DELETE FROM messages WHERE conversation_id = ?1",
                rusqlite::params![id],
            )
            .map_err(Self::map_err)?;
        }
        Ok(())
    }

    async fn set_conversation_state(
        &self,
        conversation_id: &str,
        state: ConversationState,
    ) -> Result<()> {
        if matches!(&state, ConversationState::ResetPending { .. }) {
            return Err(OrchestratorError::Storage(
                "ResetPending must be published atomically with mark_reset_pending".into(),
            ));
        }
        let conn = self.conn.lock().unwrap();
        Self::require_reconciled_reset_authority(&conn, conversation_id)?;
        if matches!(&state, ConversationState::Active) {
            // `complete_reset_pending` is the only causal commit point for
            // publishing Active while reset authority exists. An unbound
            // state write must never mask a newer reset generation.
            conn.execute(
                "UPDATE conversations
                 SET state = 'Active'
                 WHERE conversation_id = ?1
                   AND reset_pending = 0
                   AND reset_new_group_id IS NULL
                   AND reset_generation IS NULL
                   AND reset_notified_at_ms IS NULL",
                [conversation_id],
            )
            .map_err(Self::map_err)?;
        } else {
            conn.execute(
                "UPDATE conversations SET state = ?1
                 WHERE conversation_id = ?2
                   AND reset_pending = 0
                   AND reset_new_group_id IS NULL
                   AND reset_generation IS NULL
                   AND reset_notified_at_ms IS NULL",
                rusqlite::params![Self::state_str(&state), conversation_id],
            )
            .map_err(Self::map_err)?;
        }
        Ok(())
    }

    async fn get_conversation_state(
        &self,
        conversation_id: &str,
    ) -> Result<Option<ConversationState>> {
        let conn = self.conn.lock().unwrap();
        let row = conn
            .query_row(
                "SELECT state, reset_pending, reset_new_group_id, reset_generation,
                        reset_notified_at_ms, reset_generation_fence_initialized
                 FROM conversations WHERE conversation_id = ?1",
                [conversation_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i32>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, Option<i32>>(3)?,
                        row.get::<_, Option<i64>>(4)?,
                        row.get::<_, i32>(5)?,
                    ))
                },
            )
            .optional()
            .map_err(Self::map_err)?;

        let Some((state, reset_pending, target, generation, notified_at_ms, reconciled)) = row
        else {
            return Ok(None);
        };
        if reconciled == 0 {
            return Err(OrchestratorError::Storage(format!(
                "conversation {conversation_id} has legacy reset authority and requires authoritative reconciliation"
            )));
        }
        let has_any_reset_payload =
            target.is_some() || generation.is_some() || notified_at_ms.is_some();
        if state == "ResetPending" || reset_pending != 0 || has_any_reset_payload {
            return match (state.as_str(), reset_pending, target, generation, notified_at_ms) {
                ("ResetPending", 1, Some(new_group_id), Some(reset_generation), Some(notified_at_ms)) => {
                    Ok(Some(ConversationState::ResetPending {
                        new_group_id,
                        reset_generation,
                        notified_at_ms,
                    }))
                }
                _ => Err(OrchestratorError::Storage(format!(
                    "conversation {conversation_id} contains incomplete or inconsistent reset authority"
                ))),
            };
        }
        Ok(Some(Self::parse_state(&state)))
    }

    async fn mark_needs_rejoin(&self, conversation_id: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        Self::require_reconciled_reset_authority(&conn, conversation_id)?;
        conn.execute(
            "UPDATE conversations SET needs_rejoin = 1 WHERE conversation_id = ?1",
            rusqlite::params![conversation_id],
        )
        .map_err(Self::map_err)?;
        Ok(())
    }

    async fn needs_rejoin(&self, conversation_id: &str) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        Self::require_reconciled_reset_authority(&conn, conversation_id)?;
        let val = conn
            .query_row(
                "SELECT needs_rejoin FROM conversations WHERE conversation_id = ?1",
                rusqlite::params![conversation_id],
                |row| row.get::<_, i32>(0),
            )
            .optional()
            .map_err(Self::map_err)?;
        Ok(val.unwrap_or(0) != 0)
    }

    async fn clear_rejoin_flag(&self, conversation_id: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        Self::require_reconciled_reset_authority(&conn, conversation_id)?;
        conn.execute(
            "UPDATE conversations SET needs_rejoin = 0
             WHERE conversation_id = ?1 AND reset_pending = 0",
            rusqlite::params![conversation_id],
        )
        .map_err(Self::map_err)?;
        Ok(())
    }

    async fn mark_reset_pending(
        &self,
        conversation_id: &str,
        new_group_id_hex: &str,
        reset_generation: i32,
        notified_at_ms: i64,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        Self::require_reconciled_reset_authority(&conn, conversation_id)?;
        let changed = conn
            .execute(
                "UPDATE conversations
             SET state = 'ResetPending',
                 needs_rejoin = 1,
                 reset_pending = 1,
                 reset_new_group_id = ?1,
                 reset_generation = ?2,
                 reset_notified_at_ms = ?3,
                 updated_at = ?4
             WHERE conversation_id = ?5
               AND reset_generation_fence_initialized = 1
               AND ?2 > applied_reset_generation
               AND (
                    (reset_pending = 0
                        AND state <> 'ResetPending'
                        AND reset_new_group_id IS NULL
                        AND reset_generation IS NULL
                        AND reset_notified_at_ms IS NULL)
                    OR (state = 'ResetPending'
                        AND reset_pending = 1
                        AND reset_new_group_id IS NOT NULL
                        AND reset_generation IS NOT NULL
                        AND reset_notified_at_ms IS NOT NULL
                        AND reset_generation < ?2)
                    OR (state = 'ResetPending'
                        AND reset_pending = 1
                        AND reset_new_group_id IS NOT NULL
                        AND reset_generation IS NOT NULL
                        AND reset_notified_at_ms IS NOT NULL
                        AND reset_generation = ?2
                        AND reset_new_group_id = ?1
                        AND reset_notified_at_ms = ?3)
               )",
                rusqlite::params![
                    new_group_id_hex,
                    reset_generation,
                    notified_at_ms,
                    Utc::now().to_rfc3339(),
                    conversation_id,
                ],
            )
            .map_err(Self::map_err)?;
        if changed != 1 {
            return Err(OrchestratorError::Storage(format!(
                "reset generation {reset_generation} was stale, conflicted, or conversation {conversation_id} was missing"
            )));
        }
        Ok(())
    }

    async fn adopt_reset_pending_target(
        &self,
        conversation_id: &str,
        expected_generation: i32,
        expected_old_target: &str,
        authoritative_new_target: &str,
    ) -> Result<bool> {
        self.adopt_reset_pending_target_cas(
            conversation_id,
            expected_generation,
            expected_old_target,
            authoritative_new_target,
        )
    }

    async fn complete_reset_pending(
        &self,
        conversation_id: &str,
        expected_generation: i32,
        expected_new_group_id_hex: &str,
    ) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        Self::require_reconciled_reset_authority(&conn, conversation_id)?;
        let changed = conn
            .execute(
                "UPDATE conversations
                 SET state = 'Active',
                     group_id = ?1,
                     epoch = 0,
                     reset_pending = 0,
                     reset_new_group_id = NULL,
                     reset_generation = NULL,
                     reset_notified_at_ms = NULL,
                     applied_reset_generation = ?4,
                     needs_rejoin = 0,
                     updated_at = ?2
                 WHERE conversation_id = ?3
                   AND state = 'ResetPending'
                   AND reset_generation_fence_initialized = 1
                   AND reset_pending = 1
                   AND reset_generation = ?4
                   AND reset_new_group_id = ?1
                   AND reset_notified_at_ms IS NOT NULL",
                rusqlite::params![
                    expected_new_group_id_hex,
                    Utc::now().to_rfc3339(),
                    conversation_id,
                    expected_generation,
                ],
            )
            .map_err(Self::map_err)?;
        Ok(changed == 1)
    }

    async fn clear_reset_pending_for_delete(
        &self,
        conversation_id: &str,
        expected_generation: i32,
    ) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        Self::require_reconciled_reset_authority(&conn, conversation_id)?;
        let changed = conn
            .execute(
                "UPDATE conversations
                 SET reset_pending = 0,
                     reset_new_group_id = NULL,
                     reset_generation = NULL,
                     reset_notified_at_ms = NULL,
                     applied_reset_generation = ?3,
                     needs_rejoin = 0,
                     updated_at = ?1
                 WHERE conversation_id = ?2
                   AND state = 'ResetPending'
                   AND reset_generation_fence_initialized = 1
                   AND reset_pending = 1
                   AND reset_generation = ?3
                   AND reset_new_group_id IS NOT NULL
                   AND reset_notified_at_ms IS NOT NULL",
                rusqlite::params![
                    Utc::now().to_rfc3339(),
                    conversation_id,
                    expected_generation
                ],
            )
            .map_err(Self::map_err)?;
        Ok(changed == 1)
    }

    async fn set_conversation_sequencer(
        &self,
        conversation_id: &str,
        sequencer_did: &str,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE conversations SET sequencer_did = ?1 WHERE conversation_id = ?2",
            rusqlite::params![sequencer_did, conversation_id],
        )
        .map_err(Self::map_err)?;
        Ok(())
    }

    // -- Messages --

    async fn store_message(&self, message: &Message) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let delivery_json = message
            .delivery_status
            .as_ref()
            .and_then(|ds| serde_json::to_string(ds).ok());
        conn.execute(
            "INSERT OR REPLACE INTO messages
             (id, conversation_id, sender_did, text, timestamp, epoch, sequence_number, is_own, delivery_status_json, payload_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            rusqlite::params![
                message.id,
                message.conversation_id,
                message.sender_did,
                message.text,
                message.timestamp.to_rfc3339(),
                message.epoch,
                message.sequence_number,
                message.is_own as i32,
                delivery_json,
                message.payload_json,
            ],
        )
        .map_err(Self::map_err)?;
        Ok(())
    }

    async fn get_messages(
        &self,
        conversation_id: &str,
        limit: u32,
        before_sequence: Option<u64>,
    ) -> Result<Vec<Message>> {
        let conn = self.conn.lock().unwrap();
        let messages = if let Some(before) = before_sequence {
            let mut stmt = conn
                .prepare(
                    "SELECT id, conversation_id, sender_did, text, timestamp, epoch,
                            sequence_number, is_own, delivery_status_json, payload_json
                     FROM messages
                     WHERE conversation_id = ?1 AND sequence_number < ?2
                     ORDER BY sequence_number DESC LIMIT ?3",
                )
                .map_err(Self::map_err)?;
            let rows = stmt
                .query_map(
                    rusqlite::params![conversation_id, before, limit],
                    Self::row_to_message,
                )
                .map_err(Self::map_err)?;
            rows.filter_map(|r| r.ok()).collect::<Vec<_>>()
        } else {
            let mut stmt = conn
                .prepare(
                    "SELECT id, conversation_id, sender_did, text, timestamp, epoch,
                            sequence_number, is_own, delivery_status_json, payload_json
                     FROM messages
                     WHERE conversation_id = ?1
                     ORDER BY sequence_number DESC LIMIT ?2",
                )
                .map_err(Self::map_err)?;
            let rows = stmt
                .query_map(
                    rusqlite::params![conversation_id, limit],
                    Self::row_to_message,
                )
                .map_err(Self::map_err)?;
            rows.filter_map(|r| r.ok()).collect::<Vec<_>>()
        };

        // Reverse to get ascending order
        let mut messages = messages;
        messages.reverse();
        Ok(messages)
    }

    async fn message_exists(&self, message_id: &str) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM messages WHERE id = ?1",
                rusqlite::params![message_id],
                |row| row.get(0),
            )
            .map_err(Self::map_err)?;
        Ok(count > 0)
    }

    // -- Sync Cursors --

    async fn get_sync_cursor(&self, user_did: &str) -> Result<SyncCursor> {
        let conn = self.conn.lock().unwrap();
        let result = conn.query_row(
            "SELECT conversations_cursor, messages_cursor FROM sync_cursors WHERE user_did = ?1",
            rusqlite::params![user_did],
            |row| {
                Ok(SyncCursor {
                    conversations_cursor: row.get(0)?,
                    messages_cursor: row.get(1)?,
                })
            },
        );

        match result {
            Ok(cursor) => Ok(cursor),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(SyncCursor::default()),
            Err(e) => Err(Self::map_err(e)),
        }
    }

    async fn set_sync_cursor(&self, user_did: &str, cursor: &SyncCursor) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO sync_cursors (user_did, conversations_cursor, messages_cursor)
             VALUES (?1, ?2, ?3)",
            rusqlite::params![
                user_did,
                cursor.conversations_cursor,
                cursor.messages_cursor,
            ],
        )
        .map_err(Self::map_err)?;
        Ok(())
    }

    // -- Group State --

    async fn set_group_state(&self, state: &GroupState) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let members_json = serde_json::to_string(&state.members)
            .map_err(|e| OrchestratorError::Serialization(e.to_string()))?;
        conn.execute(
            "INSERT OR REPLACE INTO group_states (group_id, conversation_id, epoch, members_json)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![
                state.group_id,
                state.conversation_id,
                state.epoch,
                members_json
            ],
        )
        .map_err(Self::map_err)?;
        Ok(())
    }

    async fn get_group_state(&self, group_id: &str) -> Result<Option<GroupState>> {
        let conn = self.conn.lock().unwrap();
        let result = conn.query_row(
            "SELECT group_id, conversation_id, epoch, members_json
             FROM group_states WHERE group_id = ?1",
            rusqlite::params![group_id],
            |row| {
                let group_id: String = row.get(0)?;
                let conversation_id: String = row.get(1)?;
                let epoch: u64 = row.get(2)?;
                let members_json: String = row.get(3)?;
                let members: Vec<String> = serde_json::from_str(&members_json).unwrap_or_default();
                Ok(GroupState {
                    group_id,
                    conversation_id,
                    epoch,
                    members,
                })
            },
        );

        match result {
            Ok(state) => Ok(Some(state)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(Self::map_err(e)),
        }
    }

    async fn delete_group_state(&self, group_id: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM group_states WHERE group_id = ?1",
            rusqlite::params![group_id],
        )
        .map_err(Self::map_err)?;
        Ok(())
    }

    fn implemented_optional_methods(&self) -> &'static [&'static str] {
        &[
            "get_conversation_state",
            "mark_reset_pending",
            "adopt_reset_pending_target",
            "complete_reset_pending",
            "clear_reset_pending_for_delete",
            "set_conversation_sequencer",
        ]
    }
}

impl SqliteStorage {
    fn row_to_message(row: &rusqlite::Row<'_>) -> rusqlite::Result<Message> {
        let id: String = row.get("id")?;
        let conversation_id: String = row.get("conversation_id")?;
        let sender_did: String = row.get("sender_did")?;
        let text: String = row.get("text")?;
        let timestamp_str: String = row.get("timestamp")?;
        let epoch: u64 = row.get("epoch")?;
        let sequence_number: u64 = row.get("sequence_number")?;
        let is_own: i32 = row.get("is_own")?;
        let delivery_json: Option<String> = row.get("delivery_status_json")?;

        let timestamp = DateTime::parse_from_rfc3339(&timestamp_str)
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now());

        let delivery_status = delivery_json.and_then(|j| serde_json::from_str(&j).ok());

        Ok(Message {
            id,
            conversation_id,
            sender_did,
            text,
            timestamp,
            epoch,
            sequence_number,
            is_own: is_own != 0,
            delivery_status,
            payload_json: row.get("payload_json")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn new_temp_storage() -> (PathBuf, SqliteStorage) {
        let path =
            std::env::temp_dir().join(format!("birdaemon-storage-{}.db", uuid::Uuid::new_v4()));
        let storage = SqliteStorage::new(path.clone()).expect("open SqliteStorage");
        (path, storage)
    }

    #[tokio::test]
    async fn conversation_sequencer_did_round_trips() {
        let (path, storage) = new_temp_storage();
        let user_did = "did:plc:alice";
        let conversation_id = "conv-sequencer";
        let group_id = "group-sequencer";
        let sequencer_did = "did:web:ds-b.example";

        storage
            .ensure_conversation_exists(user_did, conversation_id, group_id)
            .await
            .expect("create conversation");
        storage
            .set_conversation_sequencer(conversation_id, sequencer_did)
            .await
            .expect("persist sequencer");
        assert!(
            storage
                .implemented_optional_methods()
                .contains(&"set_conversation_sequencer"),
            "storage capabilities should report sequencer persistence"
        );

        let got = storage
            .get_conversation(user_did, conversation_id)
            .await
            .expect("load conversation")
            .expect("conversation exists");
        assert_eq!(got.sequencer_did.as_deref(), Some(sequencer_did));

        let listed = storage
            .list_conversations(user_did)
            .await
            .expect("list conversations");
        let listed = listed
            .into_iter()
            .find(|c| c.conversation_id == conversation_id)
            .expect("listed conversation");
        assert_eq!(listed.sequencer_did.as_deref(), Some(sequencer_did));

        drop(storage);
        let _ = fs::remove_file(path);
    }

    fn reset_snapshot(
        storage: &SqliteStorage,
        conversation_id: &str,
    ) -> (
        String,
        String,
        i32,
        Option<String>,
        Option<i32>,
        Option<i64>,
        i32,
        i32,
        u64,
    ) {
        let conn = storage.conn.lock().unwrap();
        conn.query_row(
            "SELECT state, group_id, reset_pending, reset_new_group_id, reset_generation,
                    reset_notified_at_ms, applied_reset_generation, needs_rejoin, epoch
             FROM conversations WHERE conversation_id = ?1",
            [conversation_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                ))
            },
        )
        .expect("read reset snapshot")
    }

    fn generation_fence(storage: &SqliteStorage, conversation_id: &str) -> (i32, i32) {
        let conn = storage.conn.lock().unwrap();
        conn.query_row(
            "SELECT applied_reset_generation, reset_generation_fence_initialized
             FROM conversations WHERE conversation_id = ?1",
            [conversation_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("read generation fence")
    }

    #[tokio::test]
    async fn mark_reset_pending_atomically_publishes_authority_and_preserves_predecessor() {
        let (path, storage) = new_temp_storage();
        let conversation_id = "conv-reset-atomic-mark";
        storage
            .ensure_conversation_exists("did:plc:alice", conversation_id, "old-group")
            .await
            .expect("create conversation");
        storage
            .mark_reset_pending(conversation_id, "new-group", 7, 1_717_000_000_007)
            .await
            .expect("publish reset authority");
        assert_eq!(
            reset_snapshot(&storage, conversation_id),
            (
                "ResetPending".into(),
                "old-group".into(),
                1,
                Some("new-group".into()),
                Some(7),
                Some(1_717_000_000_007),
                -1,
                1,
                0,
            ),
            "mark must atomically publish the complete tuple and rejoin route without moving the current-group mapping"
        );
        assert_eq!(
            storage
                .get_conversation_state(conversation_id)
                .await
                .expect("read authority"),
            Some(ConversationState::ResetPending {
                new_group_id: "new-group".into(),
                reset_generation: 7,
                notified_at_ms: 1_717_000_000_007,
            })
        );

        drop(storage);
        let _ = fs::remove_file(path);
    }

    #[tokio::test]
    async fn adopt_reset_pending_target_cas_preserves_complete_authority_and_fences() {
        let (path, storage) = new_temp_storage();
        let conversation_id = "conv-reset-winner-adoption";
        storage
            .ensure_conversation_exists("did:plc:alice", conversation_id, "old-group")
            .await
            .expect("create conversation");
        storage
            .mark_reset_pending(conversation_id, "losing-group", 23, 1_717_000_000_023)
            .await
            .expect("publish losing candidate");

        assert!(storage
            .adopt_reset_pending_target_cas(conversation_id, 23, "losing-group", "winner-group",)
            .expect("adopt authoritative winner"));
        assert_eq!(
            reset_snapshot(&storage, conversation_id),
            (
                "ResetPending".into(),
                "old-group".into(),
                1,
                Some("winner-group".into()),
                Some(23),
                Some(1_717_000_000_023),
                -1,
                1,
                0,
            )
        );
        assert_eq!(generation_fence(&storage, conversation_id), (-1, 1));

        drop(storage);
        let _ = fs::remove_file(path);
    }

    #[tokio::test]
    async fn adopt_reset_pending_target_cas_rejects_stale_competing_and_unfenced_rows() {
        let (path, storage) = new_temp_storage();
        let conversation_id = "conv-reset-competing-winners";
        storage
            .ensure_conversation_exists("did:plc:alice", conversation_id, "old-group")
            .await
            .expect("create conversation");
        storage
            .mark_reset_pending(conversation_id, "losing-group", 24, 1_717_000_000_024)
            .await
            .expect("publish reset candidate");

        assert!(!storage
            .adopt_reset_pending_target_cas(conversation_id, 24, "losing-group", "")
            .expect("empty winner is rejected fail closed"));

        assert!(!storage
            .adopt_reset_pending_target_cas(conversation_id, 23, "losing-group", "winner-a")
            .expect("stale generation is a clean CAS miss"));
        assert!(!storage
            .adopt_reset_pending_target_cas(conversation_id, 24, "other-loser", "winner-a")
            .expect("wrong old target is a clean CAS miss"));
        assert!(storage
            .adopt_reset_pending_target_cas(conversation_id, 24, "losing-group", "winner-a")
            .expect("verified winner adopts"));
        assert!(storage
            .adopt_reset_pending_target_cas(conversation_id, 24, "winner-a", "winner-a")
            .expect("exact replay is idempotent"));
        assert!(!storage
            .adopt_reset_pending_target_cas(conversation_id, 24, "losing-group", "winner-b")
            .expect("competing stale winner loses CAS"));

        storage
            .conn
            .lock()
            .unwrap()
            .execute(
                "UPDATE conversations SET reset_generation_fence_initialized = 0
                 WHERE conversation_id = ?1",
                [conversation_id],
            )
            .unwrap();
        assert!(!storage
            .adopt_reset_pending_target_cas(conversation_id, 24, "winner-a", "winner-b")
            .expect("unreconciled legacy row is a clean CAS miss"));
        assert_eq!(
            reset_snapshot(&storage, conversation_id).3,
            Some("winner-a".into())
        );

        drop(storage);
        let _ = fs::remove_file(path);
    }

    #[tokio::test]
    async fn reset_authority_survives_storage_restart() {
        let (path, storage) = new_temp_storage();
        let conversation_id = "conv-reset-restart";
        storage
            .ensure_conversation_exists("did:plc:alice", conversation_id, "old-group")
            .await
            .expect("create conversation");
        storage
            .mark_reset_pending(conversation_id, "new-group", 8, 1_717_000_000_008)
            .await
            .expect("publish reset authority");
        drop(storage);

        assert_eq!(
            SqliteStorage::new(path.clone())
                .expect("reopen storage")
                .get_conversation_state(conversation_id)
                .await
                .expect("rehydrate authority"),
            Some(ConversationState::ResetPending {
                new_group_id: "new-group".into(),
                reset_generation: 8,
                notified_at_ms: 1_717_000_000_008,
            })
        );
        let _ = fs::remove_file(path);
    }

    #[tokio::test]
    async fn stale_and_conflicting_marks_cannot_replace_newer_authority() {
        let (path, storage) = new_temp_storage();
        let conversation_id = "conv-reset-mark-fence";
        storage
            .ensure_conversation_exists("did:plc:alice", conversation_id, "old-group")
            .await
            .expect("create conversation");
        storage
            .mark_reset_pending(conversation_id, "group-gen-2", 2, 1_717_000_000_002)
            .await
            .expect("commit generation 2");
        storage
            .mark_reset_pending(conversation_id, "group-gen-2", 2, 1_717_000_000_002)
            .await
            .expect("exact replay is idempotent");
        assert!(storage
            .mark_reset_pending(conversation_id, "group-gen-1", 1, 1_717_000_000_001)
            .await
            .is_err());
        assert!(storage
            .mark_reset_pending(conversation_id, "conflicting-target", 2, 1_717_000_000_002)
            .await
            .is_err());
        assert_eq!(
            reset_snapshot(&storage, conversation_id),
            (
                "ResetPending".into(),
                "old-group".into(),
                1,
                Some("group-gen-2".into()),
                Some(2),
                Some(1_717_000_000_002),
                -1,
                1,
                0,
            )
        );

        drop(storage);
        let _ = fs::remove_file(path);
    }

    #[tokio::test]
    async fn malformed_partial_authority_cannot_be_overwritten_by_newer_mark() {
        let (path, storage) = new_temp_storage();
        let conversation_id = "conv-reset-malformed";
        storage
            .ensure_conversation_exists("did:plc:alice", conversation_id, "old-group")
            .await
            .expect("create conversation");
        {
            let conn = storage.conn.lock().unwrap();
            conn.execute(
                "UPDATE conversations
                 SET state = 'ResetPending', reset_pending = 1,
                     reset_new_group_id = NULL, reset_generation = 1,
                     reset_notified_at_ms = 1717000000001, needs_rejoin = 1
                 WHERE conversation_id = ?1",
                [conversation_id],
            )
            .expect("inject malformed authority");
        }
        assert!(storage
            .mark_reset_pending(conversation_id, "new-group", 2, 1_717_000_000_002)
            .await
            .is_err());
        assert!(storage
            .get_conversation_state(conversation_id)
            .await
            .is_err());
        assert_eq!(
            reset_snapshot(&storage, conversation_id),
            (
                "ResetPending".into(),
                "old-group".into(),
                1,
                None,
                Some(1),
                Some(1_717_000_000_001),
                -1,
                1,
                0,
            )
        );

        drop(storage);
        let _ = fs::remove_file(path);
    }

    #[tokio::test]
    async fn needs_rejoin_propagates_sqlite_decode_errors() {
        let (path, storage) = new_temp_storage();
        let conversation_id = "conv-corrupt-rejoin";
        storage
            .ensure_conversation_exists("did:plc:alice", conversation_id, "old-group")
            .await
            .expect("create conversation");
        {
            let conn = storage.conn.lock().unwrap();
            conn.execute(
                "UPDATE conversations SET needs_rejoin = 'corrupt' WHERE conversation_id = ?1",
                [conversation_id],
            )
            .expect("inject invalid typed value");
        }
        assert!(storage.needs_rejoin(conversation_id).await.is_err());

        drop(storage);
        let _ = fs::remove_file(path);
    }

    #[tokio::test]
    async fn unbound_active_write_and_rejoin_clear_cannot_mask_pending_reset() {
        let (path, storage) = new_temp_storage();
        let conversation_id = "conv-reset-stale-active";
        storage
            .ensure_conversation_exists("did:plc:alice", conversation_id, "old-group")
            .await
            .expect("create conversation");
        storage
            .mark_reset_pending(conversation_id, "group-gen-2", 2, 1_717_000_000_002)
            .await
            .expect("commit generation 2");
        storage
            .set_conversation_state(conversation_id, ConversationState::Active)
            .await
            .expect("unbound active write is a no-op");
        storage
            .clear_rejoin_flag(conversation_id)
            .await
            .expect("unbound rejoin clear is a no-op");
        assert_eq!(
            reset_snapshot(&storage, conversation_id),
            (
                "ResetPending".into(),
                "old-group".into(),
                1,
                Some("group-gen-2".into()),
                Some(2),
                Some(1_717_000_000_002),
                -1,
                1,
                0,
            ),
            "unbound writes must preserve reset authority and restart routing"
        );

        drop(storage);
        let _ = fs::remove_file(path);
    }

    #[tokio::test]
    async fn complete_reset_pending_requires_exact_generation_and_target() {
        let (path, storage) = new_temp_storage();
        let conversation_id = "conv-reset-complete-cas";
        storage
            .ensure_conversation_exists("did:plc:alice", conversation_id, "old-group")
            .await
            .expect("create conversation");
        storage
            .mark_reset_pending(conversation_id, "new-group", 7, 1_717_000_000_007)
            .await
            .expect("commit reset");
        assert!(!storage
            .complete_reset_pending(conversation_id, 6, "new-group")
            .await
            .expect("stale generation is a no-op"));
        assert!(!storage
            .complete_reset_pending(conversation_id, 7, "wrong-target")
            .await
            .expect("target mismatch is a no-op"));
        assert_eq!(
            storage
                .get_conversation("did:plc:alice", conversation_id)
                .await
                .expect("read conversation")
                .expect("conversation exists")
                .group_id,
            "old-group"
        );
        assert!(storage
            .complete_reset_pending(conversation_id, 7, "new-group")
            .await
            .expect("exact completion commits"));
        assert_eq!(
            reset_snapshot(&storage, conversation_id),
            (
                "Active".into(),
                "new-group".into(),
                0,
                None,
                None,
                None,
                7,
                0,
                0,
            )
        );
        assert!(!storage
            .complete_reset_pending(conversation_id, 7, "new-group")
            .await
            .expect("completion affects exactly one pending row"));

        drop(storage);
        let _ = fs::remove_file(path);
    }

    #[tokio::test]
    async fn delete_clear_is_exact_and_never_projects_active() {
        let (path, storage) = new_temp_storage();
        let conversation_id = "conv-reset-delete-cas";
        storage
            .ensure_conversation_exists("did:plc:alice", conversation_id, "old-group")
            .await
            .expect("create conversation");
        storage
            .mark_reset_pending(conversation_id, "new-group", 8, 1_717_000_000_008)
            .await
            .expect("commit reset");
        assert!(!storage
            .clear_reset_pending_for_delete(conversation_id, 7)
            .await
            .expect("mismatch is a no-op"));
        assert!(storage
            .clear_reset_pending_for_delete(conversation_id, 8)
            .await
            .expect("matching delete clear commits"));
        assert_eq!(
            reset_snapshot(&storage, conversation_id),
            (
                "ResetPending".into(),
                "old-group".into(),
                0,
                None,
                None,
                None,
                8,
                0,
                0,
            ),
            "delete clearing must preserve the predecessor mapping and must not publish Active"
        );
        assert!(storage
            .get_conversation_state(conversation_id)
            .await
            .is_err());

        drop(storage);
        let _ = fs::remove_file(path);
    }

    #[tokio::test]
    async fn completed_generation_high_water_rejects_replay_after_restart() {
        let (path, storage) = new_temp_storage();
        let conversation_id = "conv-reset-high-water";
        storage
            .ensure_conversation_exists("did:plc:alice", conversation_id, "group-a")
            .await
            .expect("create conversation");
        storage
            .mark_reset_pending(conversation_id, "group-b", 1, 1_717_000_000_001)
            .await
            .expect("publish generation 1");
        assert!(storage
            .complete_reset_pending(conversation_id, 1, "group-b")
            .await
            .expect("complete generation 1"));
        storage
            .mark_reset_pending(conversation_id, "group-c", 2, 1_717_000_000_002)
            .await
            .expect("publish generation 2");
        assert!(storage
            .complete_reset_pending(conversation_id, 2, "group-c")
            .await
            .expect("complete generation 2"));
        drop(storage);

        let reopened = SqliteStorage::new(path.clone()).expect("reopen storage");
        assert!(reopened
            .mark_reset_pending(conversation_id, "group-b", 1, 1_717_000_000_001)
            .await
            .is_err());
        assert_eq!(
            reset_snapshot(&reopened, conversation_id),
            (
                "Active".into(),
                "group-c".into(),
                0,
                None,
                None,
                None,
                2,
                0,
                0,
            ),
            "completion must retain a durable monotonic fence across restart"
        );

        drop(reopened);
        let _ = fs::remove_file(path);
    }

    #[tokio::test]
    async fn delete_clear_preserves_generation_high_water_after_restart() {
        let (path, storage) = new_temp_storage();
        let conversation_id = "conv-reset-delete-high-water";
        storage
            .ensure_conversation_exists("did:plc:alice", conversation_id, "group-a")
            .await
            .expect("create conversation");
        storage
            .mark_reset_pending(conversation_id, "group-b", 3, 1_717_000_000_003)
            .await
            .expect("publish generation 3");
        assert!(storage
            .clear_reset_pending_for_delete(conversation_id, 3)
            .await
            .expect("clear exact pending generation"));
        drop(storage);

        let reopened = SqliteStorage::new(path.clone()).expect("reopen storage");
        assert_eq!(generation_fence(&reopened, conversation_id), (3, 1));
        assert!(reopened
            .mark_reset_pending(conversation_id, "group-b", 3, 1_717_000_000_003)
            .await
            .is_err());
        assert_eq!(
            reopened
                .get_conversation("did:plc:alice", conversation_id)
                .await
                .expect("read conversation")
                .expect("conversation remains after simulated delete failure")
                .group_id,
            "group-a"
        );

        drop(reopened);
        let _ = fs::remove_file(path);
    }

    #[tokio::test]
    async fn legacy_migration_fences_unknown_rows_and_seeds_complete_pending_rows() {
        let path =
            std::env::temp_dir().join(format!("birdaemon-legacy-{}.db", uuid::Uuid::new_v4()));
        {
            let conn = Connection::open(&path).expect("open legacy database");
            conn.execute_batch(
                "CREATE TABLE conversations (
                    conversation_id TEXT PRIMARY KEY,
                    user_did TEXT NOT NULL,
                    group_id TEXT NOT NULL,
                    state TEXT NOT NULL DEFAULT 'Initializing',
                    needs_rejoin INTEGER NOT NULL DEFAULT 0,
                    reset_pending INTEGER NOT NULL DEFAULT 0,
                    reset_new_group_id TEXT,
                    reset_generation INTEGER,
                    reset_notified_at_ms INTEGER,
                    join_method TEXT,
                    join_epoch INTEGER,
                    epoch INTEGER NOT NULL DEFAULT 0,
                    members_json TEXT NOT NULL DEFAULT '[]',
                    metadata_json TEXT,
                    created_at TEXT,
                    updated_at TEXT,
                    sequencer_did TEXT
                );
                INSERT INTO conversations
                    (conversation_id, user_did, group_id, state)
                    VALUES ('legacy-active', 'did:plc:alice', 'group-c', 'Active');
                INSERT INTO conversations
                    (conversation_id, user_did, group_id, state, needs_rejoin,
                     reset_pending, reset_new_group_id, reset_generation,
                     reset_notified_at_ms)
                    VALUES ('legacy-pending', 'did:plc:alice', 'group-a',
                            'ResetPending', 0, 1, 'group-b', 5, 1717000000005);",
            )
            .expect("create legacy rows");
        }

        let storage = SqliteStorage::new(path.clone()).expect("migrate legacy database");
        assert_eq!(generation_fence(&storage, "legacy-active"), (-1, 0));
        assert!(storage
            .mark_reset_pending("legacy-active", "group-d", 6, 1_717_000_000_006)
            .await
            .is_err());
        assert_eq!(
            storage
                .get_conversation("did:plc:alice", "legacy-active")
                .await
                .expect("read legacy active row")
                .expect("row exists")
                .group_id,
            "group-c"
        );

        assert!(storage
            .get_conversation_state("legacy-active")
            .await
            .is_err());
        assert!(storage.needs_rejoin("legacy-active").await.is_err());

        assert_eq!(generation_fence(&storage, "legacy-pending"), (5, 0));
        assert!(storage
            .get_conversation_state("legacy-pending")
            .await
            .is_err());
        assert!(storage.needs_rejoin("legacy-pending").await.is_err());
        assert!(storage
            .mark_reset_pending("legacy-pending", "group-b", 5, 1_717_000_000_005)
            .await
            .is_err());
        assert!(storage
            .complete_reset_pending("legacy-pending", 5, "group-b")
            .await
            .is_err());
        assert!(storage
            .clear_reset_pending_for_delete("legacy-pending", 5)
            .await
            .is_err());
        assert_eq!(
            reset_snapshot(&storage, "legacy-pending"),
            (
                "ResetPending".into(),
                "group-a".into(),
                1,
                Some("group-b".into()),
                Some(5),
                Some(1_717_000_000_005),
                5,
                1,
                0,
            ),
            "migration must preserve forensic authority without treating the legacy predecessor mapping as trusted"
        );

        {
            let conn = storage.conn.lock().unwrap();
            conn.execute(
                "UPDATE conversations
                 SET applied_reset_generation = -1, needs_rejoin = 0
                 WHERE conversation_id = 'legacy-pending'",
                [],
            )
            .expect("simulate crash after schema migration but before forensic seed");
        }
        drop(storage);
        let reopened = SqliteStorage::new(path.clone()).expect("resume interrupted migration");
        assert_eq!(generation_fence(&reopened, "legacy-pending"), (5, 0));
        assert_eq!(reset_snapshot(&reopened, "legacy-pending").7, 1);
        assert!(reopened
            .get_conversation_state("legacy-pending")
            .await
            .is_err());
        drop(reopened);
        let _ = fs::remove_file(path);
    }

    #[tokio::test]
    async fn reset_mutations_report_zero_affected_rows() {
        let (path, storage) = new_temp_storage();
        assert!(storage
            .mark_reset_pending("missing", "new-group", 1, 1)
            .await
            .is_err());
        assert!(!storage
            .complete_reset_pending("missing", 1, "new-group")
            .await
            .expect("missing completion is false"));
        assert!(!storage
            .clear_reset_pending_for_delete("missing", 1)
            .await
            .expect("missing delete clear is false"));

        drop(storage);
        let _ = fs::remove_file(path);
    }
}
