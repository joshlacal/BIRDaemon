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
                join_method TEXT,
                join_epoch INTEGER,
                epoch INTEGER NOT NULL DEFAULT 0,
                members_json TEXT NOT NULL DEFAULT '[]',
                metadata_json TEXT,
                created_at TEXT,
                updated_at TEXT
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

        Ok(())
    }

    fn map_err(e: rusqlite::Error) -> OrchestratorError {
        OrchestratorError::Storage(e.to_string())
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
            "Failed" => ConversationState::Failed,
            _ => ConversationState::Initializing,
        }
    }

    fn state_str(s: ConversationState) -> &'static str {
        match s {
            ConversationState::Initializing => "Initializing",
            ConversationState::Active => "Active",
            ConversationState::ForkDetected => "ForkDetected",
            ConversationState::NeedsRejoin => "NeedsRejoin",
            ConversationState::ResetPending { .. } => "ResetPending",
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
        })
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
                "SELECT conversation_id, group_id, epoch, members_json, metadata_json, created_at, updated_at
                 FROM conversations WHERE conversation_id = ?1",
            )
            .map_err(Self::map_err)?;

        let result = stmt
            .query_row(rusqlite::params![conversation_id], Self::row_to_conversation_view)
            .optional()
            .map_err(Self::map_err)?;

        Ok(result)
    }

    async fn list_conversations(&self, user_did: &str) -> Result<Vec<ConversationView>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT conversation_id, group_id, epoch, members_json, metadata_json, created_at, updated_at
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
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE conversations SET state = ?1 WHERE conversation_id = ?2",
            rusqlite::params![Self::state_str(state), conversation_id],
        )
        .map_err(Self::map_err)?;
        Ok(())
    }

    async fn mark_needs_rejoin(&self, conversation_id: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE conversations SET needs_rejoin = 1 WHERE conversation_id = ?1",
            rusqlite::params![conversation_id],
        )
        .map_err(Self::map_err)?;
        Ok(())
    }

    async fn needs_rejoin(&self, conversation_id: &str) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        let val: i32 = conn
            .query_row(
                "SELECT needs_rejoin FROM conversations WHERE conversation_id = ?1",
                rusqlite::params![conversation_id],
                |row| row.get(0),
            )
            .unwrap_or(0);
        Ok(val != 0)
    }

    async fn clear_rejoin_flag(&self, conversation_id: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE conversations SET needs_rejoin = 0 WHERE conversation_id = ?1",
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
        conn.execute(
            "UPDATE conversations
             SET state = 'ResetPending',
                 needs_rejoin = 0,
                 reset_pending = 1,
                 reset_new_group_id = ?1,
                 reset_generation = ?2,
                 reset_notified_at_ms = ?3,
                 group_id = ?1,
                 epoch = 0,
                 updated_at = ?4
             WHERE conversation_id = ?5",
            rusqlite::params![
                new_group_id_hex,
                reset_generation,
                notified_at_ms,
                Utc::now().to_rfc3339(),
                conversation_id,
            ],
        )
        .map_err(Self::map_err)?;
        Ok(())
    }

    async fn clear_reset_pending(&self, conversation_id: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE conversations
             SET state = 'Active',
                 reset_pending = 0,
                 reset_new_group_id = NULL,
                 reset_generation = NULL,
                 reset_notified_at_ms = NULL,
                 needs_rejoin = 0,
                 updated_at = ?1
             WHERE conversation_id = ?2",
            rusqlite::params![Utc::now().to_rfc3339(), conversation_id],
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
            rusqlite::params![state.group_id, state.conversation_id, state.epoch, members_json],
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
                let members: Vec<String> =
                    serde_json::from_str(&members_json).unwrap_or_default();
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

        let delivery_status =
            delivery_json.and_then(|j| serde_json::from_str(&j).ok());

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
            payload_json: row.get("payload_json")?
        })
    }
}
