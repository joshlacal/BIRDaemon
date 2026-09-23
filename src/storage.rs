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
    owner_did: String,
}

#[derive(Debug)]
struct StoredProjectionFence {
    user_did: String,
    group_id: String,
    epoch: u64,
    reset_pending: bool,
    lifecycle: ProjectionLifecycleFence,
}

impl SqliteStorage {
    pub fn new(path: PathBuf, owner_did: impl Into<String>) -> anyhow::Result<Self> {
        let owner_did = owner_did.into();
        if owner_did.trim().is_empty() {
            anyhow::bail!("SQLite storage owner DID must not be empty");
        }
        let conn = Connection::open(&path)?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        let storage = Self {
            conn: Mutex::new(conn),
            owner_did,
        };
        storage.create_tables()?;
        Ok(storage)
    }

    /// Durable at-most-once gate. Stores no message text or request preview.
    /// A crash after this claim may omit a response; retry cannot repeat effects.
    pub fn claim_bot_effect(&self, conversation_id: &str, message_id: &str) -> Result<bool> {
        use sha2::{Digest, Sha256};
        let mut hash = Sha256::new();
        hash.update(b"BIRD-BOT-EFFECT\0");
        for value in [&self.owner_did, conversation_id, message_id] {
            hash.update((value.len() as u64).to_be_bytes());
            hash.update(value.as_bytes());
        }
        let digest = hash.finalize();
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR IGNORE INTO bot_effect_claims(owner_did,effect_digest) VALUES(?1,?2)",
            rusqlite::params![self.owner_did, digest.as_slice()],
        )
        .map(|count| count == 1)
        .map_err(|error| OrchestratorError::Storage(format!("persist bot effect claim: {error}")))
    }

    fn create_tables(&self) -> anyhow::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS bot_effect_claims (
                owner_did TEXT NOT NULL,
                effect_digest BLOB NOT NULL CHECK(length(effect_digest)=32),
                PRIMARY KEY(owner_did,effect_digest)
            );
            CREATE TABLE IF NOT EXISTS conversations (
                conversation_id TEXT NOT NULL,
                user_did TEXT NOT NULL,
                group_id TEXT NOT NULL,
                state TEXT NOT NULL DEFAULT 'Initializing',
                needs_rejoin INTEGER NOT NULL DEFAULT 0,
                reset_pending INTEGER NOT NULL DEFAULT 0,
                reset_new_group_id TEXT,
                reset_generation INTEGER,
                reset_generation_high_water INTEGER,
                reset_notified_at_ms INTEGER,
                quarantine_reason_tag TEXT,
                quarantine_since_ms INTEGER,
                join_method TEXT,
                join_epoch INTEGER,
                epoch INTEGER NOT NULL DEFAULT 0,
                members_json TEXT NOT NULL DEFAULT '[]',
                metadata_json TEXT,
                created_at TEXT,
                updated_at TEXT,
                sequencer_did TEXT,
                lifecycle_generation INTEGER,
                lifecycle_state_version INTEGER,
                PRIMARY KEY (user_did, conversation_id)
            );

            CREATE TABLE IF NOT EXISTS messages (
                owner_did TEXT NOT NULL,
                id TEXT NOT NULL,
                conversation_id TEXT NOT NULL,
                source_conversation_id TEXT NOT NULL,
                sender_did TEXT NOT NULL,
                text TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                epoch INTEGER NOT NULL,
                sequence_number INTEGER NOT NULL,
                is_own INTEGER NOT NULL DEFAULT 0,
                delivery_status_json TEXT,
                payload_json TEXT,
                PRIMARY KEY (owner_did, id),
                FOREIGN KEY (owner_did, conversation_id)
                    REFERENCES conversations(user_did, conversation_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS group_states (
                owner_did TEXT NOT NULL,
                group_id TEXT NOT NULL,
                conversation_id TEXT NOT NULL,
                epoch INTEGER NOT NULL,
                members_json TEXT NOT NULL,
                PRIMARY KEY (owner_did, group_id),
                FOREIGN KEY (owner_did, conversation_id)
                    REFERENCES conversations(user_did, conversation_id) ON DELETE RESTRICT
            );

            CREATE TABLE IF NOT EXISTS sync_cursors (
                user_did TEXT PRIMARY KEY,
                conversations_cursor TEXT,
                messages_cursor TEXT
            );

            CREATE TABLE IF NOT EXISTS recovery_backoffs (
                owner_did TEXT NOT NULL,
                conversation_id TEXT NOT NULL,
                failed_rejoin_count INTEGER NOT NULL,
                last_attempt_at_ms INTEGER NOT NULL,
                quarantined_until_ms INTEGER,
                PRIMARY KEY (owner_did, conversation_id)
            );

            CREATE TABLE IF NOT EXISTS recovery_globals (
                owner_did TEXT NOT NULL,
                key TEXT NOT NULL,
                val_int INTEGER,
                PRIMARY KEY (owner_did, key)
            );

            CREATE TABLE IF NOT EXISTS conversation_aliases (
                owner_did TEXT NOT NULL,
                canonical_conversation_id TEXT NOT NULL,
                alias_conversation_id TEXT NOT NULL,
                alias_group_id TEXT NOT NULL,
                alias_incarnation INTEGER NOT NULL,
                PRIMARY KEY (owner_did, alias_conversation_id)
            );

            CREATE INDEX IF NOT EXISTS idx_conversation_aliases_canonical
                ON conversation_aliases(owner_did, canonical_conversation_id);

            CREATE TABLE IF NOT EXISTS pending_local_deletes (
                owner_did TEXT NOT NULL,
                conversation_id TEXT NOT NULL,
                group_id_hex TEXT,
                PRIMARY KEY (owner_did, conversation_id)
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

        let had_quarantine_reason: bool = conn
            .prepare(
                "SELECT COUNT(*) FROM pragma_table_info('conversations')
                 WHERE name='quarantine_reason_tag'",
            )
            .and_then(|mut stmt| stmt.query_row([], |row| row.get::<_, i64>(0)))
            .map(|count| count > 0)
            .unwrap_or(false);
        let had_quarantine_since: bool = conn
            .prepare(
                "SELECT COUNT(*) FROM pragma_table_info('conversations')
                 WHERE name='quarantine_since_ms'",
            )
            .and_then(|mut stmt| stmt.query_row([], |row| row.get::<_, i64>(0)))
            .map(|count| count > 0)
            .unwrap_or(false);

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
                "reset_generation_high_water",
                "ALTER TABLE conversations ADD COLUMN reset_generation_high_water INTEGER;",
            ),
            (
                "reset_notified_at_ms",
                "ALTER TABLE conversations ADD COLUMN reset_notified_at_ms INTEGER;",
            ),
            (
                "quarantine_reason_tag",
                "ALTER TABLE conversations ADD COLUMN quarantine_reason_tag TEXT;",
            ),
            (
                "quarantine_since_ms",
                "ALTER TABLE conversations ADD COLUMN quarantine_since_ms INTEGER;",
            ),
            (
                "sequencer_did",
                "ALTER TABLE conversations ADD COLUMN sequencer_did TEXT;",
            ),
            (
                "lifecycle_generation",
                "ALTER TABLE conversations ADD COLUMN lifecycle_generation INTEGER;",
            ),
            (
                "lifecycle_state_version",
                "ALTER TABLE conversations ADD COLUMN lifecycle_state_version INTEGER;",
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
        // Older BIR rows only had the currently-pending generation. Preserve
        // it as the reset high-water mark before the two authorities diverge.
        conn.execute(
            "UPDATE conversations
             SET reset_generation_high_water = reset_generation
             WHERE reset_generation_high_water IS NULL
               AND reset_generation IS NOT NULL",
            [],
        )?;
        // Preserve the exact behavior of pre-column BIR releases: those rows
        // rehydrated a quarantined tag as PeerBadCommit with an unknown
        // timestamp. Only perform this compatibility fill while adding both
        // columns to a legacy schema; a later partial/corrupt payload must
        // fail closed instead of being silently repaired on every startup.
        if !had_quarantine_reason && !had_quarantine_since {
            conn.execute(
                "UPDATE conversations
                 SET quarantine_reason_tag = 'peer_bad_commit',
                     quarantine_since_ms = 0
                 WHERE state = 'Quarantined'",
                [],
            )?;
        }

        Self::migrate_owner_scoped_core_tables(&conn)?;
        conn.execute_batch(
            "CREATE INDEX IF NOT EXISTS idx_messages_convo
             ON messages(owner_did, conversation_id, sequence_number);",
        )?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        let foreign_key_errors: i64 =
            conn.query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
                row.get(0)
            })?;
        if foreign_key_errors != 0 {
            anyhow::bail!("owner-scoped MLS storage migration left invalid foreign keys");
        }

        Ok(())
    }

    fn migrate_owner_scoped_core_tables(conn: &Connection) -> anyhow::Result<()> {
        let messages_owner_scoped: bool = conn.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM pragma_table_info('messages') WHERE name = 'owner_did'
             )",
            [],
            |row| row.get(0),
        )?;
        let groups_owner_scoped: bool = conn.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM pragma_table_info('group_states') WHERE name = 'owner_did'
             )",
            [],
            |row| row.get(0),
        )?;
        let conversation_composite_pk: i64 = conn.query_row(
            "SELECT COUNT(*) FROM pragma_table_info('conversations')
             WHERE (name = 'user_did' AND pk = 1)
                OR (name = 'conversation_id' AND pk = 2)",
            [],
            |row| row.get(0),
        )?;
        if messages_owner_scoped && groups_owner_scoped && conversation_composite_pk == 2 {
            return Ok(());
        }
        if messages_owner_scoped || groups_owner_scoped || conversation_composite_pk != 0 {
            anyhow::bail!("refusing a partially owner-scoped MLS storage schema");
        }

        let invalid_owners: i64 = conn.query_row(
            "SELECT COUNT(*) FROM conversations WHERE trim(user_did) = ''",
            [],
            |row| row.get(0),
        )?;
        let orphan_messages: i64 = conn.query_row(
            "SELECT COUNT(*) FROM messages AS m
             LEFT JOIN conversations AS c ON c.conversation_id = m.conversation_id
             WHERE c.conversation_id IS NULL",
            [],
            |row| row.get(0),
        )?;
        let orphan_groups: i64 = conn.query_row(
            "SELECT COUNT(*) FROM group_states AS g
             LEFT JOIN conversations AS c ON c.conversation_id = g.conversation_id
             WHERE c.conversation_id IS NULL",
            [],
            |row| row.get(0),
        )?;
        if invalid_owners != 0 || orphan_messages != 0 || orphan_groups != 0 {
            anyhow::bail!("refusing owner-scope migration with empty owners or orphaned MLS rows");
        }

        conn.pragma_update(None, "foreign_keys", "OFF")?;
        let migration = conn.execute_batch(
            "BEGIN IMMEDIATE;
             DROP INDEX IF EXISTS idx_messages_convo;
             ALTER TABLE conversations RENAME TO conversations_legacy_owner_scope;
             ALTER TABLE messages RENAME TO messages_legacy_owner_scope;
             ALTER TABLE group_states RENAME TO group_states_legacy_owner_scope;

             CREATE TABLE conversations (
                conversation_id TEXT NOT NULL,
                user_did TEXT NOT NULL,
                group_id TEXT NOT NULL,
                state TEXT NOT NULL DEFAULT 'Initializing',
                needs_rejoin INTEGER NOT NULL DEFAULT 0,
                reset_pending INTEGER NOT NULL DEFAULT 0,
                reset_new_group_id TEXT,
                reset_generation INTEGER,
                reset_generation_high_water INTEGER,
                reset_notified_at_ms INTEGER,
                quarantine_reason_tag TEXT,
                quarantine_since_ms INTEGER,
                join_method TEXT,
                join_epoch INTEGER,
                epoch INTEGER NOT NULL DEFAULT 0,
                members_json TEXT NOT NULL DEFAULT '[]',
                metadata_json TEXT,
                created_at TEXT,
                updated_at TEXT,
                sequencer_did TEXT,
                lifecycle_generation INTEGER,
                lifecycle_state_version INTEGER,
                PRIMARY KEY (user_did, conversation_id)
             );
             CREATE TABLE messages (
                owner_did TEXT NOT NULL,
                id TEXT NOT NULL,
                conversation_id TEXT NOT NULL,
                source_conversation_id TEXT NOT NULL,
                sender_did TEXT NOT NULL,
                text TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                epoch INTEGER NOT NULL,
                sequence_number INTEGER NOT NULL,
                is_own INTEGER NOT NULL DEFAULT 0,
                delivery_status_json TEXT,
                payload_json TEXT,
                PRIMARY KEY (owner_did, id),
                FOREIGN KEY (owner_did, conversation_id)
                    REFERENCES conversations(user_did, conversation_id) ON DELETE CASCADE
             );
             CREATE INDEX idx_messages_convo
                ON messages(owner_did, conversation_id, sequence_number);
             CREATE TABLE group_states (
                owner_did TEXT NOT NULL,
                group_id TEXT NOT NULL,
                conversation_id TEXT NOT NULL,
                epoch INTEGER NOT NULL,
                members_json TEXT NOT NULL,
                PRIMARY KEY (owner_did, group_id),
                FOREIGN KEY (owner_did, conversation_id)
                    REFERENCES conversations(user_did, conversation_id) ON DELETE RESTRICT
             );

             INSERT INTO conversations SELECT * FROM conversations_legacy_owner_scope;
             INSERT INTO messages
                (owner_did, id, conversation_id, source_conversation_id, sender_did,
                 text, timestamp, epoch, sequence_number, is_own,
                 delivery_status_json, payload_json)
             SELECT c.user_did, m.id, m.conversation_id, m.conversation_id, m.sender_did,
                    m.text, m.timestamp, m.epoch, m.sequence_number, m.is_own,
                    m.delivery_status_json, m.payload_json
             FROM messages_legacy_owner_scope AS m
             JOIN conversations_legacy_owner_scope AS c
               ON c.conversation_id = m.conversation_id;
             INSERT INTO group_states
                (owner_did, group_id, conversation_id, epoch, members_json)
             SELECT c.user_did, g.group_id, g.conversation_id, g.epoch, g.members_json
             FROM group_states_legacy_owner_scope AS g
             JOIN conversations_legacy_owner_scope AS c
               ON c.conversation_id = g.conversation_id;

             DROP TABLE messages_legacy_owner_scope;
             DROP TABLE group_states_legacy_owner_scope;
             DROP TABLE conversations_legacy_owner_scope;
             COMMIT;",
        );
        if let Err(error) = migration {
            let _ = conn.execute_batch("ROLLBACK;");
            let _ = conn.pragma_update(None, "foreign_keys", "ON");
            return Err(error.into());
        }
        conn.pragma_update(None, "foreign_keys", "ON")?;
        Ok(())
    }

    fn map_err(e: rusqlite::Error) -> OrchestratorError {
        OrchestratorError::Storage(e.to_string())
    }

    fn require_owner(&self, supplied: &str) -> Result<()> {
        if supplied.is_empty() || supplied != self.owner_did {
            return Err(OrchestratorError::Storage(
                "SQLite callback owner does not match the authenticated storage owner".into(),
            ));
        }
        Ok(())
    }

    fn strict_canonical_uuid(value: &str) -> bool {
        let Ok(uuid) = uuid::Uuid::parse_str(value) else {
            return false;
        };
        uuid.get_version() == Some(uuid::Version::Random)
            && uuid.get_variant() == uuid::Variant::RFC4122
            && uuid.to_string() == value
    }

    fn nonempty_group_hex(value: &str) -> bool {
        !value.is_empty()
            && hex::decode(value)
                .is_ok_and(|bytes| !bytes.is_empty() && hex::encode(bytes) == value)
    }

    fn quarantine_reason_from_tag(tag: &str) -> Option<QuarantineReason> {
        match tag {
            "peer_bad_commit" => Some(QuarantineReason::PeerBadCommit),
            "multi_peer_bad_commits" => Some(QuarantineReason::MultiPeerBadCommits),
            "repeated_framing_failures" => Some(QuarantineReason::RepeatedFramingFailures),
            _ => None,
        }
    }

    fn valid_lifecycle(fence: &ProjectionLifecycleFence) -> bool {
        (fence.reset_pending_target_group_id.is_none() || fence.reset_generation.is_some())
            && fence.generation.is_none_or(|value| value >= 0)
            && fence.state_version.is_none_or(|value| value >= 0)
            && fence.reset_generation.is_none_or(|value| value >= 0)
    }

    fn lifecycle_matches(
        actual: &ProjectionLifecycleFence,
        expected: &ProjectionLifecycleFence,
    ) -> bool {
        Self::valid_lifecycle(actual)
            && Self::valid_lifecycle(expected)
            && expected
                .generation
                .is_none_or(|value| actual.generation == Some(value))
            && expected
                .state_version
                .is_none_or(|value| actual.state_version == Some(value))
            && expected
                .reset_generation
                .is_none_or(|value| actual.reset_generation == Some(value))
            && expected
                .reset_pending_target_group_id
                .as_ref()
                .is_none_or(|value| actual.reset_pending_target_group_id.as_ref() == Some(value))
    }

    fn stored_projection_fence(
        conn: &Connection,
        owner_did: &str,
        conversation_id: &str,
    ) -> rusqlite::Result<Option<StoredProjectionFence>> {
        conn.query_row(
            "SELECT user_did, group_id, epoch, reset_pending, state,
                    lifecycle_generation, lifecycle_state_version,
                    reset_generation_high_water, reset_generation,
                    reset_new_group_id, reset_notified_at_ms
             FROM conversations WHERE user_did = ?1 AND conversation_id = ?2",
            rusqlite::params![owner_did, conversation_id],
            |row| {
                let reset_flag = row.get::<_, i64>(3)? != 0;
                let state: String = row.get(4)?;
                let reset_high_water: Option<i32> = row.get(7)?;
                let reset_generation: Option<i32> = row.get(8)?;
                let reset_target: Option<String> = row.get(9)?;
                let reset_notified_at_ms: Option<i64> = row.get(10)?;
                Ok(StoredProjectionFence {
                    user_did: row.get(0)?,
                    group_id: row.get(1)?,
                    epoch: row.get(2)?,
                    reset_pending: reset_flag
                        || state == "ResetPending"
                        || reset_generation.is_some()
                        || reset_target.is_some()
                        || reset_notified_at_ms.is_some(),
                    lifecycle: ProjectionLifecycleFence {
                        generation: row.get(5)?,
                        state_version: row.get(6)?,
                        reset_generation: reset_high_water,
                        reset_pending_target_group_id: reset_target,
                    },
                })
            },
        )
        .optional()
    }

    fn persisted_state(
        conversation_id: &str,
        state: &str,
        reset_pending: bool,
        reset_target: Option<String>,
        reset_generation: Option<i32>,
        reset_notified_at_ms: Option<i64>,
        quarantine_reason_tag: Option<String>,
        quarantine_since_ms: Option<i64>,
    ) -> Result<ConversationState> {
        if state == "ResetPending" {
            let (Some(new_group_id), Some(reset_generation), Some(notified_at_ms)) =
                (reset_target, reset_generation, reset_notified_at_ms)
            else {
                return Err(OrchestratorError::Storage(format!(
                    "conversation {conversation_id} has incomplete reset authority"
                )));
            };
            if !reset_pending
                || !Self::nonempty_group_hex(&new_group_id)
                || reset_generation < 0
                || notified_at_ms < 0
                || quarantine_reason_tag.is_some()
                || quarantine_since_ms.is_some()
            {
                return Err(OrchestratorError::Storage(format!(
                    "conversation {conversation_id} has invalid reset authority"
                )));
            }
            return Ok(ConversationState::ResetPending {
                new_group_id,
                reset_generation,
                notified_at_ms,
            });
        }

        if reset_pending
            || reset_target.is_some()
            || reset_generation.is_some()
            || reset_notified_at_ms.is_some()
        {
            return Err(OrchestratorError::Storage(format!(
                "conversation {conversation_id} has reset payload without a ResetPending state"
            )));
        }

        if state == "Quarantined" {
            let (Some(reason_tag), Some(since_ms)) = (quarantine_reason_tag, quarantine_since_ms)
            else {
                return Err(OrchestratorError::Storage(format!(
                    "conversation {conversation_id} has incomplete quarantine authority"
                )));
            };
            let Some(reason) = Self::quarantine_reason_from_tag(&reason_tag) else {
                return Err(OrchestratorError::Storage(format!(
                    "conversation {conversation_id} has unknown quarantine reason {reason_tag}"
                )));
            };
            if since_ms < 0 {
                return Err(OrchestratorError::Storage(format!(
                    "conversation {conversation_id} has invalid quarantine timestamp"
                )));
            }
            return Ok(ConversationState::Quarantined { reason, since_ms });
        }

        if quarantine_reason_tag.is_some() || quarantine_since_ms.is_some() {
            return Err(OrchestratorError::Storage(format!(
                "conversation {conversation_id} has quarantine payload without a Quarantined state"
            )));
        }

        match state {
            "Initializing" => Ok(ConversationState::Initializing),
            "Active" => Ok(ConversationState::Active),
            "NeedsRejoin" => Ok(ConversationState::NeedsRejoin),
            "DeviceRemoved" => Ok(ConversationState::DeviceRemoved),
            "Closed" => Ok(ConversationState::Closed),
            "ForkDetected" => Ok(ConversationState::ForkDetected),
            "Failed" => Ok(ConversationState::Failed),
            other => Err(OrchestratorError::Storage(format!(
                "conversation {conversation_id} has unknown state {other}"
            ))),
        }
    }

    fn state_str(s: &ConversationState) -> &'static str {
        match s {
            ConversationState::Initializing => "Initializing",
            ConversationState::Active => "Active",
            ConversationState::ForkDetected => "ForkDetected",
            ConversationState::NeedsRejoin => "NeedsRejoin",
            ConversationState::DeviceRemoved => "DeviceRemoved",
            ConversationState::Closed => "Closed",
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
            canonical_state: None,
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
        self.require_owner(user_did)?;
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
        user_did: &str,
        join_method: JoinMethod,
        join_epoch: u64,
    ) -> Result<()> {
        self.require_owner(user_did)?;
        let conn = self.conn.lock().unwrap();
        let method_str = match join_method {
            JoinMethod::Creator => "Creator",
            JoinMethod::Welcome => "Welcome",
            JoinMethod::ExternalCommit => "ExternalCommit",
        };
        conn.execute(
            "UPDATE conversations SET join_method = ?1, join_epoch = ?2, epoch = ?2
             WHERE conversation_id = ?3 AND user_did = ?4",
            rusqlite::params![method_str, join_epoch, conversation_id, self.owner_did],
        )
        .map_err(Self::map_err)?;
        Ok(())
    }

    async fn get_conversation(
        &self,
        user_did: &str,
        conversation_id: &str,
    ) -> Result<Option<ConversationView>> {
        self.require_owner(user_did)?;
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT conversation_id, group_id, epoch, members_json, metadata_json, created_at, updated_at, sequencer_did
                 FROM conversations WHERE conversation_id = ?1 AND user_did = ?2",
            )
            .map_err(Self::map_err)?;

        let result = stmt
            .query_row(
                rusqlite::params![conversation_id, self.owner_did],
                Self::row_to_conversation_view,
            )
            .optional()
            .map_err(Self::map_err)?;

        Ok(result)
    }

    async fn list_conversations(&self, user_did: &str) -> Result<Vec<ConversationView>> {
        self.require_owner(user_did)?;
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

    async fn commit_conversation_projection(
        &self,
        request: &ConversationProjectionCommitRequest,
    ) -> Result<ConversationProjectionCommitOutcome> {
        if request.owner_user_did != self.owner_did || request.owner_user_did.is_empty() {
            return Err(OrchestratorError::Storage(
                "projection caller does not match the SQLite storage owner".into(),
            ));
        }

        let (canonical_id, canonical_group, canonical_incarnation, live_view) = match (
            request.mode,
            request.canonical.as_ref(),
            request.aliases.first(),
        ) {
            (ConversationProjectionCommitMode::Live, Some(view), _) => (
                view.conversation_id.clone(),
                view.group_id.clone(),
                view.epoch,
                Some(view),
            ),
            (ConversationProjectionCommitMode::Replay, None, Some(authority)) => (
                authority.canonical_conversation_id.clone(),
                authority.canonical_group_id.clone(),
                authority.canonical_incarnation,
                None,
            ),
            _ => {
                return Ok(ConversationProjectionCommitOutcome::FenceMismatch { affected_rows: 0 })
            }
        };

        if !Self::strict_canonical_uuid(&canonical_id)
            || !Self::nonempty_group_hex(&canonical_group)
            || !Self::valid_lifecycle(&request.canonical_lifecycle)
            || request
                .canonical_lifecycle
                .reset_pending_target_group_id
                .is_some()
        {
            return Ok(ConversationProjectionCommitOutcome::FenceMismatch { affected_rows: 0 });
        }
        if live_view.is_some_and(|view| {
            view.conversation_id != canonical_id || view.group_id != canonical_group
        }) || (request.mode == ConversationProjectionCommitMode::Replay
            && request.aliases.is_empty())
        {
            return Ok(ConversationProjectionCommitOutcome::FenceMismatch { affected_rows: 0 });
        }

        let mut alias_ids = std::collections::HashSet::new();
        for authority in &request.aliases {
            if authority.owner_user_did != request.owner_user_did
                || authority.canonical_conversation_id != canonical_id
                || authority.canonical_group_id != canonical_group
                || authority.canonical_incarnation != canonical_incarnation
                || authority.canonical_lifecycle != request.canonical_lifecycle
                || !Self::valid_lifecycle(&authority.canonical_lifecycle)
                || !Self::valid_lifecycle(&authority.alias_lifecycle)
                || authority.alias_group_id != canonical_group
                || authority.alias_conversation_id != authority.alias_group_id
                || authority.alias_conversation_id == canonical_id
                || Self::strict_canonical_uuid(&authority.alias_conversation_id)
                || !alias_ids.insert(authority.alias_conversation_id.clone())
            {
                return Ok(ConversationProjectionCommitOutcome::FenceMismatch { affected_rows: 0 });
            }
        }

        let serialized_live_view = live_view
            .map(|view| {
                let members_json = serde_json::to_string(&view.members)
                    .map_err(|error| OrchestratorError::Serialization(error.to_string()))?;
                let metadata_json = view
                    .metadata
                    .as_ref()
                    .map(serde_json::to_string)
                    .transpose()
                    .map_err(|error| OrchestratorError::Serialization(error.to_string()))?;
                Ok::<_, OrchestratorError>((
                    members_json,
                    metadata_json,
                    view.created_at.map(|date| date.to_rfc3339()),
                    view.updated_at.map(|date| date.to_rfc3339()),
                    view.sequencer_did.clone(),
                ))
            })
            .transpose()?;

        let mut conn = self.conn.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(Self::map_err)?;

        let mut canonical_ids = std::collections::BTreeSet::new();
        {
            let mut stmt = tx
                .prepare(
                    "SELECT conversation_id FROM conversations
                     WHERE user_did = ?1 AND group_id = ?2",
                )
                .map_err(Self::map_err)?;
            let rows = stmt
                .query_map(
                    rusqlite::params![request.owner_user_did, canonical_group],
                    |row| row.get::<_, String>(0),
                )
                .map_err(Self::map_err)?;
            for row in rows {
                let candidate = row.map_err(Self::map_err)?;
                if Self::strict_canonical_uuid(&candidate) {
                    canonical_ids.insert(candidate);
                }
            }
        }
        {
            let mut stmt = tx
                .prepare(
                    "SELECT canonical_conversation_id FROM conversation_aliases
                     WHERE owner_did = ?1 AND alias_group_id = ?2",
                )
                .map_err(Self::map_err)?;
            let rows = stmt
                .query_map(
                    rusqlite::params![request.owner_user_did, canonical_group],
                    |row| row.get::<_, String>(0),
                )
                .map_err(Self::map_err)?;
            for row in rows {
                canonical_ids.insert(row.map_err(Self::map_err)?);
            }
        }
        if canonical_ids.iter().any(|id| id != &canonical_id) || canonical_ids.len() > 1 {
            return Ok(ConversationProjectionCommitOutcome::Ambiguous {
                canonical_ids: canonical_ids.into_iter().collect(),
                affected_rows: 0,
            });
        }

        let canonical_row =
            Self::stored_projection_fence(&tx, &request.owner_user_did, &canonical_id)
                .map_err(Self::map_err)?;
        if canonical_row.as_ref().is_some_and(|row| {
            row.user_did != request.owner_user_did
                || row.group_id != canonical_group
                || match request.mode {
                    ConversationProjectionCommitMode::Live => row.epoch > canonical_incarnation,
                    ConversationProjectionCommitMode::Replay => row.epoch != canonical_incarnation,
                }
                || row.reset_pending
                || !Self::lifecycle_matches(&row.lifecycle, &request.canonical_lifecycle)
        }) || (canonical_row.is_none()
            && request.mode == ConversationProjectionCommitMode::Replay)
        {
            return Ok(ConversationProjectionCommitOutcome::FenceMismatch { affected_rows: 0 });
        }

        let mut present_aliases = Vec::new();
        for authority in &request.aliases {
            let persisted_mapping: Option<(String, String, u64)> = tx
                .query_row(
                    "SELECT canonical_conversation_id, alias_group_id, alias_incarnation
                     FROM conversation_aliases
                     WHERE owner_did = ?1 AND alias_conversation_id = ?2",
                    rusqlite::params![request.owner_user_did, authority.alias_conversation_id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()
                .map_err(Self::map_err)?;
            if persisted_mapping.as_ref().is_some_and(|mapping| {
                mapping.0 != canonical_id
                    || mapping.1 != authority.alias_group_id
                    || mapping.2 != authority.alias_incarnation
            }) {
                return Ok(ConversationProjectionCommitOutcome::FenceMismatch { affected_rows: 0 });
            }

            match Self::stored_projection_fence(
                &tx,
                &request.owner_user_did,
                &authority.alias_conversation_id,
            )
            .map_err(Self::map_err)?
            {
                Some(row)
                    if row.user_did == request.owner_user_did
                        && row.group_id == authority.alias_group_id
                        && row.epoch == authority.alias_incarnation
                        && !row.reset_pending
                        && Self::lifecycle_matches(&row.lifecycle, &authority.alias_lifecycle) =>
                {
                    present_aliases.push(authority.alias_conversation_id.clone());
                }
                Some(_) => {
                    return Ok(ConversationProjectionCommitOutcome::FenceMismatch {
                        affected_rows: 0,
                    })
                }
                None => {}
            }
        }

        let mut affected_rows = 0_u32;
        if let (Some(view), Some((members, metadata, created_at, updated_at, sequencer))) =
            (live_view, serialized_live_view)
        {
            let rows = if canonical_row.is_some() {
                tx.execute(
                    "UPDATE conversations
                     SET epoch = ?1,
                         members_json = ?2,
                         metadata_json = ?3,
                         created_at = COALESCE(?4, created_at),
                         updated_at = COALESCE(?5, updated_at),
                         sequencer_did = ?6
                     WHERE conversation_id = ?7 AND user_did = ?8 AND group_id = ?9",
                    rusqlite::params![
                        view.epoch,
                        members,
                        metadata,
                        created_at,
                        updated_at,
                        sequencer,
                        canonical_id,
                        request.owner_user_did,
                        canonical_group,
                    ],
                )
            } else {
                tx.execute(
                    "INSERT INTO conversations
                     (conversation_id, user_did, group_id, state, epoch, members_json,
                      metadata_json, created_at, updated_at, sequencer_did,
                      lifecycle_generation, lifecycle_state_version,
                      reset_generation_high_water)
                     VALUES (?1, ?2, ?3, 'Initializing', ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                    rusqlite::params![
                        canonical_id,
                        request.owner_user_did,
                        canonical_group,
                        view.epoch,
                        members,
                        metadata,
                        created_at,
                        updated_at,
                        sequencer,
                        request.canonical_lifecycle.generation,
                        request.canonical_lifecycle.state_version,
                        request.canonical_lifecycle.reset_generation,
                    ],
                )
            }
            .map_err(Self::map_err)?;
            affected_rows = affected_rows.saturating_add(rows as u32);
        }

        let mut retired_rows = 0_u32;
        for authority in &request.aliases {
            let mapped = tx
                .execute(
                    "INSERT OR IGNORE INTO conversation_aliases
                     (owner_did, canonical_conversation_id, alias_conversation_id,
                      alias_group_id, alias_incarnation)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    rusqlite::params![
                        request.owner_user_did,
                        canonical_id,
                        authority.alias_conversation_id,
                        authority.alias_group_id,
                        authority.alias_incarnation,
                    ],
                )
                .map_err(Self::map_err)?;
            affected_rows = affected_rows.saturating_add(mapped as u32);
            retired_rows = retired_rows.saturating_add(mapped as u32);
        }
        for alias_id in present_aliases {
            // Keep the immutable source identity while moving only the public
            // projection association to the stable conversation UUID.
            let reparented_messages = tx
                .execute(
                    "UPDATE messages SET conversation_id = ?1
                     WHERE owner_did = ?2 AND conversation_id = ?3",
                    rusqlite::params![canonical_id, request.owner_user_did, alias_id],
                )
                .map_err(Self::map_err)?;
            affected_rows = affected_rows.saturating_add(reparented_messages as u32);
            let reparented_groups = tx
                .execute(
                    "UPDATE group_states SET conversation_id = ?1
                     WHERE owner_did = ?2 AND conversation_id = ?3",
                    rusqlite::params![canonical_id, request.owner_user_did, alias_id],
                )
                .map_err(Self::map_err)?;
            affected_rows = affected_rows.saturating_add(reparented_groups as u32);
            let deleted = tx
                .execute(
                    "DELETE FROM conversations
                     WHERE conversation_id = ?1 AND user_did = ?2",
                    rusqlite::params![alias_id, request.owner_user_did],
                )
                .map_err(Self::map_err)?;
            affected_rows = affected_rows.saturating_add(deleted as u32);
            retired_rows = retired_rows.saturating_add(deleted as u32);
        }

        tx.commit().map_err(Self::map_err)?;
        if retired_rows > 0 {
            Ok(ConversationProjectionCommitOutcome::Retired { affected_rows })
        } else {
            Ok(ConversationProjectionCommitOutcome::AlreadyAbsent { affected_rows })
        }
    }

    async fn delete_conversations(&self, user_did: &str, ids: &[&str]) -> Result<()> {
        self.require_owner(user_did)?;
        let mut conn = self.conn.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(Self::map_err)?;
        for id in ids {
            tx.execute(
                "DELETE FROM messages WHERE owner_did = ?1 AND conversation_id = ?2",
                rusqlite::params![self.owner_did, id],
            )
            .map_err(Self::map_err)?;
            tx.execute(
                "DELETE FROM conversation_aliases
                 WHERE owner_did = ?1
                   AND (canonical_conversation_id = ?2 OR alias_conversation_id = ?2)",
                rusqlite::params![self.owner_did, id],
            )
            .map_err(Self::map_err)?;
            tx.execute(
                "DELETE FROM conversations WHERE user_did = ?1 AND conversation_id = ?2",
                rusqlite::params![self.owner_did, id],
            )
            .map_err(Self::map_err)?;
        }
        tx.commit().map_err(Self::map_err)?;
        Ok(())
    }

    async fn set_conversation_state(
        &self,
        conversation_id: &str,
        state: ConversationState,
    ) -> Result<()> {
        if matches!(&state, ConversationState::ResetPending { .. }) {
            return Err(OrchestratorError::Storage(
                "ResetPending authority must be committed through mark_reset_pending".into(),
            ));
        }
        let (quarantine_reason_tag, quarantine_since_ms) = match &state {
            ConversationState::Quarantined { reason, since_ms } if *since_ms >= 0 => {
                (Some(reason.tag()), Some(*since_ms))
            }
            ConversationState::Quarantined { .. } => {
                return Err(OrchestratorError::Storage(
                    "quarantine timestamp must not be negative".into(),
                ));
            }
            _ => (None, None),
        };
        let conn = self.conn.lock().unwrap();
        let changed = conn
            .execute(
                "UPDATE conversations
                 SET state = ?1,
                     quarantine_reason_tag = ?2,
                     quarantine_since_ms = ?3
                 WHERE conversation_id = ?4 AND user_did = ?5
                   AND (state NOT IN ('Closed', 'DeviceRemoved') OR state = ?1)
                   AND reset_pending = 0
                   AND reset_new_group_id IS NULL
                   AND reset_generation IS NULL
                   AND reset_notified_at_ms IS NULL",
                rusqlite::params![
                    Self::state_str(&state),
                    quarantine_reason_tag,
                    quarantine_since_ms,
                    conversation_id,
                    self.owner_did,
                ],
            )
            .map_err(Self::map_err)?;
        if changed == 1 {
            return Ok(());
        }
        let exists: bool = conn
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM conversations
                    WHERE conversation_id = ?1 AND user_did = ?2
                 )",
                rusqlite::params![conversation_id, self.owner_did],
                |row| row.get(0),
            )
            .map_err(Self::map_err)?;
        if exists {
            Err(OrchestratorError::Storage(format!(
                "conversation {conversation_id} is protected by reset or terminal authority"
            )))
        } else {
            Err(OrchestratorError::ConversationNotFound(
                conversation_id.to_owned(),
            ))
        }
    }

    async fn get_conversation_state(
        &self,
        conversation_id: &str,
    ) -> Result<Option<ConversationState>> {
        let conn = self.conn.lock().unwrap();
        let row: Option<(
            String,
            bool,
            Option<String>,
            Option<i32>,
            Option<i64>,
            Option<String>,
            Option<i64>,
        )> = conn
            .query_row(
                "SELECT state, reset_pending, reset_new_group_id,
                        reset_generation, reset_notified_at_ms,
                        quarantine_reason_tag, quarantine_since_ms
                 FROM conversations
                 WHERE conversation_id = ?1 AND user_did = ?2",
                rusqlite::params![conversation_id, self.owner_did],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get::<_, i64>(1)? != 0,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                    ))
                },
            )
            .optional()
            .map_err(Self::map_err)?;
        row.map(
            |(
                state,
                reset_pending,
                reset_target,
                reset_generation,
                reset_notified_at_ms,
                quarantine_reason_tag,
                quarantine_since_ms,
            )| {
                Self::persisted_state(
                    conversation_id,
                    &state,
                    reset_pending,
                    reset_target,
                    reset_generation,
                    reset_notified_at_ms,
                    quarantine_reason_tag,
                    quarantine_since_ms,
                )
            },
        )
        .transpose()
    }

    async fn mark_needs_rejoin(&self, conversation_id: &str) -> Result<()> {
        if !Self::strict_canonical_uuid(conversation_id) {
            return Err(OrchestratorError::Storage(
                "invalid rejoin conversation id".into(),
            ));
        }
        let conn = self.conn.lock().unwrap();
        let changed = conn
            .execute(
                "UPDATE conversations SET needs_rejoin = 1
                 WHERE conversation_id = ?1 AND user_did = ?2",
                rusqlite::params![conversation_id, self.owner_did],
            )
            .map_err(Self::map_err)?;
        if changed == 1 {
            Ok(())
        } else {
            Err(OrchestratorError::ConversationNotFound(
                conversation_id.to_owned(),
            ))
        }
    }

    async fn needs_rejoin(&self, conversation_id: &str) -> Result<bool> {
        if !Self::strict_canonical_uuid(conversation_id) {
            return Err(OrchestratorError::Storage(
                "invalid rejoin conversation id".into(),
            ));
        }
        let conn = self.conn.lock().unwrap();
        let val: Option<i32> = conn
            .query_row(
                "SELECT needs_rejoin FROM conversations
                 WHERE conversation_id = ?1 AND user_did = ?2",
                rusqlite::params![conversation_id, self.owner_did],
                |row| row.get(0),
            )
            .optional()
            .map_err(Self::map_err)?;
        Ok(val.is_some_and(|value| value != 0))
    }

    async fn clear_rejoin_flag(&self, conversation_id: &str) -> Result<()> {
        if !Self::strict_canonical_uuid(conversation_id) {
            return Err(OrchestratorError::Storage(
                "invalid rejoin conversation id".into(),
            ));
        }
        let conn = self.conn.lock().unwrap();
        let changed = conn
            .execute(
                "UPDATE conversations SET needs_rejoin = 0
                 WHERE conversation_id = ?1 AND user_did = ?2
                   AND state <> 'ResetPending'
                   AND reset_pending = 0
                   AND reset_new_group_id IS NULL
                   AND reset_generation IS NULL
                   AND reset_notified_at_ms IS NULL",
                rusqlite::params![conversation_id, self.owner_did],
            )
            .map_err(Self::map_err)?;
        if changed == 1 {
            return Ok(());
        }
        let exists: bool = conn
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM conversations
                    WHERE conversation_id = ?1 AND user_did = ?2
                 )",
                rusqlite::params![conversation_id, self.owner_did],
                |row| row.get(0),
            )
            .map_err(Self::map_err)?;
        if exists {
            Err(OrchestratorError::Storage(format!(
                "conversation {conversation_id} is protected by ResetPending authority"
            )))
        } else {
            // Local-delete cleanup is idempotent: the orchestrator calls this
            // after deleting the projection row and absence is already the
            // desired result.
            Ok(())
        }
    }

    async fn mark_reset_pending(
        &self,
        conversation_id: &str,
        new_group_id_hex: &str,
        reset_generation: i32,
        notified_at_ms: i64,
    ) -> Result<()> {
        if !Self::strict_canonical_uuid(conversation_id)
            || !Self::nonempty_group_hex(new_group_id_hex)
            || reset_generation < 0
            || notified_at_ms < 0
        {
            return Err(OrchestratorError::Storage(
                "invalid reset authority coordinate".into(),
            ));
        }

        let mut conn = self.conn.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(Self::map_err)?;
        let existing: Option<(
            String,
            bool,
            Option<String>,
            Option<i32>,
            Option<i64>,
            bool,
            Option<i32>,
            Option<String>,
            Option<i64>,
        )> = tx
            .query_row(
                "SELECT state, reset_pending, reset_new_group_id,
                        reset_generation, reset_notified_at_ms, needs_rejoin,
                        reset_generation_high_water,
                        quarantine_reason_tag, quarantine_since_ms
                 FROM conversations
                 WHERE conversation_id = ?1 AND user_did = ?2",
                rusqlite::params![conversation_id, self.owner_did],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get::<_, i64>(1)? != 0,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get::<_, i64>(5)? != 0,
                        row.get(6)?,
                        row.get(7)?,
                        row.get(8)?,
                    ))
                },
            )
            .optional()
            .map_err(Self::map_err)?;
        let Some((
            state,
            reset_pending,
            target,
            generation,
            notified,
            needs_rejoin,
            reset_high_water,
            quarantine_reason_tag,
            quarantine_since_ms,
        )) = existing
        else {
            return Err(OrchestratorError::ConversationNotFound(
                conversation_id.to_owned(),
            ));
        };

        if state == "Closed" {
            return Err(OrchestratorError::Storage(
                "closed conversation cannot enter reset recovery".into(),
            ));
        }
        let has_reset_material = state == "ResetPending"
            || reset_pending
            || target.is_some()
            || generation.is_some()
            || notified.is_some();
        if has_reset_material {
            let current = Self::persisted_state(
                conversation_id,
                &state,
                reset_pending,
                target,
                generation,
                notified,
                quarantine_reason_tag,
                quarantine_since_ms,
            )?;
            let ConversationState::ResetPending {
                new_group_id: current_target,
                reset_generation: current_generation,
                notified_at_ms: current_notified,
            } = current
            else {
                return Err(OrchestratorError::Storage(format!(
                    "conversation {conversation_id} has inconsistent reset authority"
                )));
            };
            if reset_high_water != Some(current_generation) {
                return Err(OrchestratorError::Storage(format!(
                    "conversation {conversation_id} has inconsistent reset-generation fences"
                )));
            }
            if current_generation > reset_generation
                || (current_generation == reset_generation
                    && (current_target != new_group_id_hex || current_notified != notified_at_ms))
            {
                return Err(OrchestratorError::Storage(format!(
                    "stale or competing reset generation {reset_generation} for {conversation_id}"
                )));
            }
            if current_generation == reset_generation {
                if !needs_rejoin {
                    return Err(OrchestratorError::Storage(format!(
                        "conversation {conversation_id} has ResetPending authority without a durable rejoin route"
                    )));
                }
                tx.execute(
                    "DELETE FROM recovery_backoffs
                     WHERE owner_did = ?1 AND conversation_id = ?2",
                    rusqlite::params![self.owner_did, conversation_id],
                )
                .map_err(Self::map_err)?;
                tx.commit().map_err(Self::map_err)?;
                return Ok(());
            }
        } else {
            // Do not overwrite an unknown or corrupt state tag with newly
            // minted reset authority.
            let _ = Self::persisted_state(
                conversation_id,
                &state,
                false,
                None,
                None,
                None,
                quarantine_reason_tag,
                quarantine_since_ms,
            )?;
            if reset_high_water.is_some_and(|generation| generation >= reset_generation) {
                return Err(OrchestratorError::Storage(format!(
                    "stale reset generation {reset_generation} for {conversation_id}"
                )));
            }
        }

        let changed = tx
            .execute(
                "UPDATE conversations
                 SET state = 'ResetPending',
                     needs_rejoin = 1,
                     reset_pending = 1,
                     reset_new_group_id = ?1,
                     reset_generation = ?2,
                     reset_generation_high_water = ?2,
                     reset_notified_at_ms = ?3,
                     quarantine_reason_tag = NULL,
                     quarantine_since_ms = NULL,
                     updated_at = ?4
                 WHERE conversation_id = ?5 AND user_did = ?6",
                rusqlite::params![
                    new_group_id_hex,
                    reset_generation,
                    notified_at_ms,
                    Utc::now().to_rfc3339(),
                    conversation_id,
                    self.owner_did,
                ],
            )
            .map_err(Self::map_err)?;
        if changed != 1 {
            return Err(OrchestratorError::Storage(format!(
                "failed to atomically publish reset authority for {conversation_id}"
            )));
        }
        // A server reset is a fresh recovery authority and a documented
        // quarantine exit. Clear the owner-scoped persisted lockout in this
        // same transaction so a crash cannot rehydrate both ResetPending and
        // a stale quarantine/backoff gate.
        tx.execute(
            "DELETE FROM recovery_backoffs
             WHERE owner_did = ?1 AND conversation_id = ?2",
            rusqlite::params![self.owner_did, conversation_id],
        )
        .map_err(Self::map_err)?;
        tx.commit().map_err(Self::map_err)?;
        Ok(())
    }

    async fn adopt_reset_pending_target(
        &self,
        conversation_id: &str,
        expected_generation: i32,
        expected_old_target: &str,
        authoritative_new_target: &str,
    ) -> Result<bool> {
        if !Self::strict_canonical_uuid(conversation_id)
            || expected_generation < 0
            || !Self::nonempty_group_hex(expected_old_target)
            || !Self::nonempty_group_hex(authoritative_new_target)
        {
            return Ok(false);
        }
        let mut conn = self.conn.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(Self::map_err)?;
        let stored: Option<(
            String,
            bool,
            Option<String>,
            Option<i32>,
            Option<i64>,
            bool,
            Option<i32>,
            Option<String>,
            Option<i64>,
        )> = tx
            .query_row(
                "SELECT state, reset_pending, reset_new_group_id,
                        reset_generation, reset_notified_at_ms, needs_rejoin,
                        reset_generation_high_water,
                        quarantine_reason_tag, quarantine_since_ms
                 FROM conversations
                 WHERE conversation_id = ?1 AND user_did = ?2",
                rusqlite::params![conversation_id, self.owner_did],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get::<_, i64>(1)? != 0,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get::<_, i64>(5)? != 0,
                        row.get(6)?,
                        row.get(7)?,
                        row.get(8)?,
                    ))
                },
            )
            .optional()
            .map_err(Self::map_err)?;
        let Some((
            state,
            reset_pending,
            target,
            generation,
            notified,
            needs_rejoin,
            high_water,
            quarantine_reason_tag,
            quarantine_since_ms,
        )) = stored
        else {
            return Ok(false);
        };
        let persisted = Self::persisted_state(
            conversation_id,
            &state,
            reset_pending,
            target,
            generation,
            notified,
            quarantine_reason_tag,
            quarantine_since_ms,
        )?;
        let ConversationState::ResetPending {
            new_group_id,
            reset_generation,
            ..
        } = persisted
        else {
            return Ok(false);
        };
        if !needs_rejoin
            || reset_generation != expected_generation
            || high_water != Some(expected_generation)
            || new_group_id != expected_old_target
        {
            return Ok(false);
        }
        if authoritative_new_target == expected_old_target {
            tx.commit().map_err(Self::map_err)?;
            return Ok(true);
        }
        let changed = tx
            .execute(
                "UPDATE conversations
                 SET reset_new_group_id = ?1, updated_at = ?2
                 WHERE conversation_id = ?3 AND user_did = ?4
                   AND state = 'ResetPending' AND reset_pending = 1
                   AND reset_generation = ?5 AND reset_new_group_id = ?6
                   AND reset_generation_high_water = ?5
                   AND reset_notified_at_ms IS NOT NULL AND needs_rejoin = 1",
                rusqlite::params![
                    authoritative_new_target,
                    Utc::now().to_rfc3339(),
                    conversation_id,
                    self.owner_did,
                    expected_generation,
                    expected_old_target,
                ],
            )
            .map_err(Self::map_err)?;
        if changed != 1 {
            return Ok(false);
        }
        tx.commit().map_err(Self::map_err)?;
        Ok(true)
    }

    async fn complete_reset_pending(
        &self,
        conversation_id: &str,
        expected_generation: i32,
        expected_new_group_id_hex: &str,
        landed_epoch: u64,
    ) -> Result<bool> {
        let Ok(landed_epoch_sql) = i64::try_from(landed_epoch) else {
            return Ok(false);
        };
        if !Self::strict_canonical_uuid(conversation_id)
            || expected_generation < 0
            || !Self::nonempty_group_hex(expected_new_group_id_hex)
        {
            return Ok(false);
        }
        let mut conn = self.conn.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(Self::map_err)?;
        let stored: Option<(
            String,
            bool,
            Option<String>,
            Option<i32>,
            Option<i64>,
            bool,
            Option<i32>,
            Option<String>,
            Option<i64>,
        )> = tx
            .query_row(
                "SELECT state, reset_pending, reset_new_group_id,
                        reset_generation, reset_notified_at_ms, needs_rejoin,
                        reset_generation_high_water,
                        quarantine_reason_tag, quarantine_since_ms
                 FROM conversations
                 WHERE conversation_id = ?1 AND user_did = ?2",
                rusqlite::params![conversation_id, self.owner_did],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get::<_, i64>(1)? != 0,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get::<_, i64>(5)? != 0,
                        row.get(6)?,
                        row.get(7)?,
                        row.get(8)?,
                    ))
                },
            )
            .optional()
            .map_err(Self::map_err)?;
        let Some((
            state,
            reset_pending,
            target,
            generation,
            notified,
            needs_rejoin,
            high_water,
            quarantine_reason_tag,
            quarantine_since_ms,
        )) = stored
        else {
            return Ok(false);
        };
        let persisted = Self::persisted_state(
            conversation_id,
            &state,
            reset_pending,
            target,
            generation,
            notified,
            quarantine_reason_tag,
            quarantine_since_ms,
        )?;
        if !needs_rejoin
            || high_water != Some(expected_generation)
            || !matches!(
                persisted,
                ConversationState::ResetPending {
                    ref new_group_id,
                    reset_generation,
                    ..
                } if new_group_id == expected_new_group_id_hex
                    && reset_generation == expected_generation
            )
        {
            return Ok(false);
        }
        let changed = tx
            .execute(
                "UPDATE conversations
                 SET group_id = ?1,
                     epoch = ?2,
                     join_epoch = ?2,
                     state = 'Active',
                     needs_rejoin = 0,
                     reset_pending = 0,
                     reset_new_group_id = NULL,
                     reset_generation = NULL,
                     reset_notified_at_ms = NULL,
                     updated_at = ?3
                 WHERE conversation_id = ?4 AND user_did = ?5
                   AND state = 'ResetPending' AND reset_pending = 1
                   AND reset_generation = ?6 AND reset_new_group_id = ?1
                   AND reset_generation_high_water = ?6
                   AND reset_notified_at_ms IS NOT NULL AND needs_rejoin = 1",
                rusqlite::params![
                    expected_new_group_id_hex,
                    landed_epoch_sql,
                    Utc::now().to_rfc3339(),
                    conversation_id,
                    self.owner_did,
                    expected_generation,
                ],
            )
            .map_err(Self::map_err)?;
        if changed != 1 {
            return Ok(false);
        }
        tx.commit().map_err(Self::map_err)?;
        Ok(true)
    }

    async fn complete_account_exit(
        &self,
        conversation_id: &str,
        expected_group_id_hex: &str,
        expected_reset_generation: Option<i32>,
        terminal_epoch: u64,
        terminal_state: ConversationState,
    ) -> Result<bool> {
        if !Self::strict_canonical_uuid(conversation_id)
            || expected_group_id_hex.len() != 64
            || !expected_group_id_hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || expected_reset_generation.is_some_and(|generation| generation <= 0)
            || !matches!(
                terminal_state,
                ConversationState::Closed | ConversationState::DeviceRemoved
            )
        {
            return Ok(false);
        }
        if terminal_epoch > 9_007_199_254_740_991 {
            return Ok(false);
        }
        let Ok(terminal_epoch) = i64::try_from(terminal_epoch) else {
            return Ok(false);
        };
        let terminal_tag = match terminal_state {
            ConversationState::Closed => "Closed",
            ConversationState::DeviceRemoved => "DeviceRemoved",
            _ => unreachable!("terminal state checked above"),
        };
        let mut conn = self.conn.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(Self::map_err)?;
        // A single immediate transaction owns both the authority comparison
        // and projection write. A concurrent reset writer cannot slip between
        // them; history, key material and retained group aliases are untouched.
        let changed = tx
            .execute(
                "UPDATE conversations SET group_id = ?1, epoch = ?2, state = ?3,
                 needs_rejoin = 0, reset_pending = 0, reset_new_group_id = NULL,
                 reset_generation = NULL, reset_notified_at_ms = NULL, updated_at = ?4
             WHERE user_did = ?5 AND conversation_id = ?6
               AND state != 'Closed'
               AND NOT (state = ?3 AND group_id = ?1 AND epoch = ?2)
               AND epoch >= 0 AND (group_id != ?1 OR epoch <= ?2)
               AND (reset_generation_high_water IS NULL OR reset_generation_high_water > 0)
               AND quarantine_reason_tag IS NULL AND quarantine_since_ms IS NULL
               AND ((?7 IS NOT NULL AND state = 'ResetPending' AND reset_pending = 1
                     AND reset_generation = ?7 AND reset_generation_high_water = ?7
                     AND reset_new_group_id = ?1 AND reset_notified_at_ms >= 0
                     AND needs_rejoin = 1)
                 OR (?7 IS NULL AND state != 'ResetPending' AND reset_pending = 0
                     AND reset_generation IS NULL AND reset_new_group_id IS NULL
                     AND reset_notified_at_ms IS NULL AND group_id = ?1))",
                rusqlite::params![
                    expected_group_id_hex,
                    terminal_epoch,
                    terminal_tag,
                    Utc::now().to_rfc3339(),
                    self.owner_did,
                    conversation_id,
                    expected_reset_generation
                ],
            )
            .map_err(Self::map_err)?;
        if changed == 1 {
            tx.commit().map_err(Self::map_err)?;
            return Ok(true);
        }
        let exact_terminal: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM conversations
             WHERE user_did = ?1 AND conversation_id = ?2 AND group_id = ?3
               AND epoch = ?4 AND state = ?5 AND needs_rejoin = 0 AND reset_pending = 0
               AND reset_generation IS NULL AND reset_new_group_id IS NULL
               AND reset_notified_at_ms IS NULL AND quarantine_reason_tag IS NULL
               AND quarantine_since_ms IS NULL
               AND (reset_generation_high_water IS NULL OR reset_generation_high_water > 0)
               AND (?6 IS NULL OR reset_generation_high_water = ?6))",
                rusqlite::params![
                    self.owner_did,
                    conversation_id,
                    expected_group_id_hex,
                    terminal_epoch,
                    terminal_tag,
                    expected_reset_generation
                ],
                |row| row.get(0),
            )
            .map_err(Self::map_err)?;
        Ok(exact_terminal)
    }

    async fn clear_reset_pending_for_delete(
        &self,
        conversation_id: &str,
        expected_generation: i32,
    ) -> Result<bool> {
        if !Self::strict_canonical_uuid(conversation_id) || expected_generation < 0 {
            return Ok(false);
        }
        let mut conn = self.conn.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(Self::map_err)?;
        let stored: Option<(
            String,
            bool,
            Option<String>,
            Option<i32>,
            Option<i64>,
            bool,
            Option<i32>,
            Option<String>,
            Option<i64>,
        )> = tx
            .query_row(
                "SELECT state, reset_pending, reset_new_group_id,
                        reset_generation, reset_notified_at_ms, needs_rejoin,
                        reset_generation_high_water,
                        quarantine_reason_tag, quarantine_since_ms
                 FROM conversations
                 WHERE conversation_id = ?1 AND user_did = ?2",
                rusqlite::params![conversation_id, self.owner_did],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get::<_, i64>(1)? != 0,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get::<_, i64>(5)? != 0,
                        row.get(6)?,
                        row.get(7)?,
                        row.get(8)?,
                    ))
                },
            )
            .optional()
            .map_err(Self::map_err)?;
        let Some((
            state,
            reset_pending,
            target,
            generation,
            notified,
            needs_rejoin,
            high_water,
            quarantine_reason_tag,
            quarantine_since_ms,
        )) = stored
        else {
            return Ok(false);
        };
        let persisted = Self::persisted_state(
            conversation_id,
            &state,
            reset_pending,
            target,
            generation,
            notified,
            quarantine_reason_tag,
            quarantine_since_ms,
        )?;
        if !needs_rejoin
            || high_water != Some(expected_generation)
            || !matches!(
                persisted,
                ConversationState::ResetPending {
                    reset_generation,
                    ..
                } if reset_generation == expected_generation
            )
        {
            return Ok(false);
        }
        let changed = tx
            .execute(
                "UPDATE conversations
                 SET state = 'Failed',
                     reset_pending = 0,
                     reset_new_group_id = NULL,
                     reset_generation = NULL,
                     reset_notified_at_ms = NULL,
                     updated_at = ?1
                 WHERE conversation_id = ?2 AND user_did = ?3
                   AND state = 'ResetPending' AND reset_pending = 1
                   AND reset_generation = ?4
                   AND reset_generation_high_water = ?4
                   AND reset_new_group_id IS NOT NULL
                   AND reset_notified_at_ms IS NOT NULL
                   AND needs_rejoin = 1",
                rusqlite::params![
                    Utc::now().to_rfc3339(),
                    conversation_id,
                    self.owner_did,
                    expected_generation,
                ],
            )
            .map_err(Self::map_err)?;
        if changed != 1 {
            return Ok(false);
        }
        tx.commit().map_err(Self::map_err)?;
        Ok(true)
    }

    async fn mark_quarantined(
        &self,
        conversation_id: &str,
        reason_tag: &str,
        since_ms: i64,
    ) -> Result<()> {
        let Some(reason) = Self::quarantine_reason_from_tag(reason_tag) else {
            return Err(OrchestratorError::Storage(
                "invalid quarantine reason tag".into(),
            ));
        };
        if !Self::strict_canonical_uuid(conversation_id) || since_ms < 0 {
            return Err(OrchestratorError::Storage(
                "invalid quarantine authority coordinate".into(),
            ));
        }
        let conn = self.conn.lock().unwrap();
        let changed = conn
            .execute(
                "UPDATE conversations
                 SET quarantine_reason_tag = ?1,
                     quarantine_since_ms = ?2
                 WHERE conversation_id = ?3 AND user_did = ?4
                   AND state = 'Quarantined'
                   AND quarantine_reason_tag = ?1
                   AND quarantine_since_ms = ?2
                   AND reset_pending = 0
                   AND reset_new_group_id IS NULL
                   AND reset_generation IS NULL
                   AND reset_notified_at_ms IS NULL",
                rusqlite::params![reason.tag(), since_ms, conversation_id, self.owner_did],
            )
            .map_err(Self::map_err)?;
        if changed == 1 {
            Ok(())
        } else {
            Err(OrchestratorError::Storage(format!(
                "conversation {conversation_id} does not hold the exact quarantine authority"
            )))
        }
    }

    async fn clear_quarantine(&self, conversation_id: &str) -> Result<()> {
        if !Self::strict_canonical_uuid(conversation_id) {
            return Err(OrchestratorError::Storage(
                "invalid quarantine conversation id".into(),
            ));
        }
        let mut conn = self.conn.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(Self::map_err)?;
        let state: Option<String> = tx
            .query_row(
                "SELECT state FROM conversations
                 WHERE conversation_id = ?1 AND user_did = ?2",
                rusqlite::params![conversation_id, self.owner_did],
                |row| row.get(0),
            )
            .optional()
            .map_err(Self::map_err)?;
        let Some(state) = state else {
            tx.commit().map_err(Self::map_err)?;
            return Ok(());
        };
        if state == "Quarantined" {
            return Err(OrchestratorError::Storage(format!(
                "conversation {conversation_id} has not durably exited quarantine"
            )));
        }
        let changed = tx
            .execute(
                "UPDATE conversations
                 SET quarantine_reason_tag = NULL,
                     quarantine_since_ms = NULL
                 WHERE conversation_id = ?1 AND user_did = ?2
                   AND state <> 'Quarantined'",
                rusqlite::params![conversation_id, self.owner_did],
            )
            .map_err(Self::map_err)?;
        if changed == 1 {
            tx.commit().map_err(Self::map_err)?;
            Ok(())
        } else {
            Err(OrchestratorError::Storage(format!(
                "conversation {conversation_id} has not durably exited quarantine"
            )))
        }
    }

    async fn set_conversation_sequencer(
        &self,
        conversation_id: &str,
        sequencer_did: &str,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let changed = conn
            .execute(
                "UPDATE conversations SET sequencer_did = ?1
             WHERE conversation_id = ?2 AND user_did = ?3",
                rusqlite::params![sequencer_did, conversation_id, self.owner_did],
            )
            .map_err(Self::map_err)?;
        if changed == 1 {
            Ok(())
        } else {
            Err(OrchestratorError::ConversationNotFound(
                conversation_id.into(),
            ))
        }
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
             (owner_did, id, conversation_id, source_conversation_id, sender_did, text,
              timestamp, epoch, sequence_number, is_own, delivery_status_json, payload_json)
             VALUES (?1, ?2, ?3, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            rusqlite::params![
                self.owner_did,
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
                     WHERE owner_did = ?2
                       AND (conversation_id = ?1 OR conversation_id IN (
                                SELECT alias_conversation_id FROM conversation_aliases
                                WHERE owner_did = ?2 AND canonical_conversation_id = ?1
                            ))
                       AND sequence_number < ?3
                     ORDER BY sequence_number DESC, timestamp DESC, id DESC LIMIT ?4",
                )
                .map_err(Self::map_err)?;
            let rows = stmt
                .query_map(
                    rusqlite::params![conversation_id, self.owner_did, before, limit],
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
                     WHERE owner_did = ?2
                       AND (conversation_id = ?1 OR conversation_id IN (
                               SELECT alias_conversation_id FROM conversation_aliases
                               WHERE owner_did = ?2 AND canonical_conversation_id = ?1
                           ))
                     ORDER BY sequence_number DESC, timestamp DESC, id DESC LIMIT ?3",
                )
                .map_err(Self::map_err)?;
            let rows = stmt
                .query_map(
                    rusqlite::params![conversation_id, self.owner_did, limit],
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
                "SELECT COUNT(*) FROM messages WHERE owner_did = ?1 AND id = ?2",
                rusqlite::params![self.owner_did, message_id],
                |row| row.get(0),
            )
            .map_err(Self::map_err)?;
        Ok(count > 0)
    }

    // -- Sync Cursors --

    async fn get_sync_cursor(&self, user_did: &str) -> Result<SyncCursor> {
        self.require_owner(user_did)?;
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
        self.require_owner(user_did)?;
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
            "INSERT OR REPLACE INTO group_states
             (owner_did, group_id, conversation_id, epoch, members_json)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                self.owner_did,
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
             FROM group_states WHERE owner_did = ?1 AND group_id = ?2",
            rusqlite::params![self.owner_did, group_id],
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
            "DELETE FROM group_states WHERE owner_did = ?1 AND group_id = ?2",
            rusqlite::params![self.owner_did, group_id],
        )
        .map_err(Self::map_err)?;
        Ok(())
    }

    // -- RecoveryTracker persistence --

    async fn get_recovery_state(&self) -> Result<PersistedRecoveryState> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT conversation_id, failed_rejoin_count, last_attempt_at_ms, quarantined_until_ms
                 FROM recovery_backoffs
                 WHERE owner_did = ?1
                 ORDER BY conversation_id",
            )
            .map_err(Self::map_err)?;
        let rows = stmt
            .query_map(rusqlite::params![self.owner_did], |row| {
                Ok(PersistedRecoveryBackoff {
                    conversation_id: row.get(0)?,
                    failed_rejoin_count: row.get(1)?,
                    last_attempt_at_ms: row.get(2)?,
                    quarantined_until_ms: row.get(3)?,
                })
            })
            .map_err(Self::map_err)?;
        let mut entries = Vec::new();
        for row in rows {
            entries.push(row.map_err(Self::map_err)?);
        }
        let last_global_rejoin_attempt_at_ms = conn
            .query_row(
                "SELECT val_int FROM recovery_globals
                 WHERE owner_did = ?1 AND key = 'last_global_rejoin_attempt_at_ms'",
                rusqlite::params![self.owner_did],
                |row| row.get(0),
            )
            .optional()
            .map_err(Self::map_err)?;
        Ok(PersistedRecoveryState {
            entries,
            last_global_rejoin_attempt_at_ms,
        })
    }

    async fn set_recovery_backoff(&self, entry: &PersistedRecoveryBackoff) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO recovery_backoffs
             (owner_did, conversation_id, failed_rejoin_count, last_attempt_at_ms, quarantined_until_ms)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(owner_did, conversation_id) DO UPDATE SET
                 failed_rejoin_count = excluded.failed_rejoin_count,
                 last_attempt_at_ms = excluded.last_attempt_at_ms,
                 quarantined_until_ms = excluded.quarantined_until_ms",
            rusqlite::params![
                self.owner_did,
                entry.conversation_id,
                entry.failed_rejoin_count,
                entry.last_attempt_at_ms,
                entry.quarantined_until_ms,
            ],
        )
        .map_err(Self::map_err)?;
        Ok(())
    }

    async fn clear_recovery_backoff(&self, conversation_id: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM recovery_backoffs
             WHERE owner_did = ?1 AND conversation_id = ?2",
            rusqlite::params![self.owner_did, conversation_id],
        )
        .map_err(Self::map_err)?;
        Ok(())
    }

    async fn set_last_global_rejoin_attempt_at(&self, at_ms: i64) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO recovery_globals (owner_did, key, val_int)
             VALUES (?1, 'last_global_rejoin_attempt_at_ms', ?2)
             ON CONFLICT(owner_did, key) DO UPDATE SET val_int = MAX(val_int, excluded.val_int)",
            rusqlite::params![self.owner_did, at_ms],
        )
        .map_err(Self::map_err)?;
        Ok(())
    }

    async fn mark_pending_local_delete(
        &self,
        conversation_id: &str,
        group_id_hex: Option<&str>,
    ) -> Result<()> {
        if conversation_id.is_empty() {
            return Err(OrchestratorError::Storage(
                "pending local-delete conversation id must not be empty".into(),
            ));
        }
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO pending_local_deletes (owner_did, conversation_id, group_id_hex)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(owner_did, conversation_id) DO UPDATE SET
                 group_id_hex = excluded.group_id_hex",
            rusqlite::params![self.owner_did, conversation_id, group_id_hex],
        )
        .map_err(Self::map_err)?;
        Ok(())
    }

    async fn clear_pending_local_delete(&self, conversation_id: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM pending_local_deletes
             WHERE owner_did = ?1 AND conversation_id = ?2",
            rusqlite::params![self.owner_did, conversation_id],
        )
        .map_err(Self::map_err)?;
        Ok(())
    }

    async fn list_pending_local_deletes(&self) -> Result<Vec<PendingLocalDelete>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT conversation_id, group_id_hex FROM pending_local_deletes
                 WHERE owner_did = ?1 ORDER BY conversation_id",
            )
            .map_err(Self::map_err)?;
        let rows = stmt
            .query_map(rusqlite::params![self.owner_did], |row| {
                Ok(PendingLocalDelete {
                    conversation_id: row.get(0)?,
                    group_id_hex: row.get(1)?,
                })
            })
            .map_err(Self::map_err)?;
        let mut pending = Vec::new();
        for row in rows {
            pending.push(row.map_err(Self::map_err)?);
        }
        Ok(pending)
    }

    fn implemented_optional_methods(&self) -> &'static [&'static str] {
        &[
            "commit_conversation_projection",
            "get_conversation_state",
            "mark_reset_pending",
            "adopt_reset_pending_target",
            "complete_reset_pending",
            "complete_account_exit",
            "clear_reset_pending_for_delete",
            "mark_quarantined",
            "clear_quarantine",
            "set_conversation_sequencer",
            "get_recovery_state",
            "set_recovery_backoff",
            "clear_recovery_backoff",
            "set_last_global_rejoin_attempt_at",
            "mark_pending_local_delete",
            "clear_pending_local_delete",
            "list_pending_local_deletes",
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
        let storage =
            SqliteStorage::new(path.clone(), "did:plc:storage-test-owner").expect("open storage");
        (path, storage)
    }

    #[tokio::test]
    async fn conversation_sequencer_did_round_trips() {
        let (path, storage) = new_temp_storage();
        let user_did = "did:plc:storage-test-owner";
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

    #[tokio::test]
    async fn recovery_state_is_durable_and_owner_scoped_across_restart() {
        let path =
            std::env::temp_dir().join(format!("birdaemon-recovery-{}.db", uuid::Uuid::new_v4()));
        let alice = "did:plc:alice-recovery-owner";
        let bob = "did:plc:bob-recovery-owner";
        let entry = PersistedRecoveryBackoff {
            conversation_id: "11111111-1111-4111-9111-111111111111".into(),
            failed_rejoin_count: 3,
            last_attempt_at_ms: 1_725_000_000_000,
            quarantined_until_ms: Some(1_725_000_060_000),
        };

        {
            let storage = SqliteStorage::new(path.clone(), alice).expect("open Alice storage");
            storage
                .set_recovery_backoff(&entry)
                .await
                .expect("persist Alice backoff");
            storage
                .set_last_global_rejoin_attempt_at(1_725_000_000_100)
                .await
                .expect("persist Alice global backoff");
        }

        {
            let storage = SqliteStorage::new(path.clone(), bob).expect("open Bob storage");
            assert_eq!(
                storage.get_recovery_state().await.unwrap(),
                PersistedRecoveryState::default(),
                "another account must not hydrate Alice's recovery authority"
            );
        }

        {
            let storage = SqliteStorage::new(path.clone(), alice).expect("reopen Alice storage");
            assert_eq!(
                storage.get_recovery_state().await.unwrap(),
                PersistedRecoveryState {
                    entries: vec![entry.clone()],
                    last_global_rejoin_attempt_at_ms: Some(1_725_000_000_100),
                }
            );
            storage
                .clear_recovery_backoff(&entry.conversation_id)
                .await
                .expect("clear Alice backoff");
        }

        let storage = SqliteStorage::new(path.clone(), alice).expect("reopen cleared storage");
        assert!(storage
            .get_recovery_state()
            .await
            .unwrap()
            .entries
            .is_empty());
        drop(storage);
        let _ = fs::remove_file(path);
    }

    #[tokio::test]
    async fn reset_authority_is_durable_exact_and_preserves_the_old_group_until_completion() {
        let path = std::env::temp_dir().join(format!(
            "birdaemon-reset-authority-{}.db",
            uuid::Uuid::new_v4()
        ));
        let owner = "did:plc:reset-owner";
        let conversation_id = "44444444-4444-4444-8444-444444444444";
        let old_group = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let first_target = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let adopted_target = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

        {
            let storage = SqliteStorage::new(path.clone(), owner).expect("open reset storage");
            storage
                .ensure_conversation_exists(owner, conversation_id, old_group)
                .await
                .unwrap();
            storage
                .update_join_info(conversation_id, owner, JoinMethod::Welcome, 8)
                .await
                .unwrap();
            storage
                .set_conversation_state(
                    conversation_id,
                    ConversationState::Quarantined {
                        reason: QuarantineReason::MultiPeerBadCommits,
                        since_ms: 42,
                    },
                )
                .await
                .unwrap();
            storage
                .mark_quarantined(
                    conversation_id,
                    QuarantineReason::MultiPeerBadCommits.tag(),
                    42,
                )
                .await
                .unwrap();
            assert_eq!(
                storage
                    .get_conversation_state(conversation_id)
                    .await
                    .unwrap(),
                Some(ConversationState::Quarantined {
                    reason: QuarantineReason::MultiPeerBadCommits,
                    since_ms: 42,
                }),
                "quarantine diagnostics must be durable before reset admission"
            );
            storage
                .set_recovery_backoff(&PersistedRecoveryBackoff {
                    conversation_id: conversation_id.into(),
                    failed_rejoin_count: 5,
                    last_attempt_at_ms: 1_725_000_000_000,
                    quarantined_until_ms: Some(1_725_000_060_000),
                })
                .await
                .unwrap();

            storage
                .mark_reset_pending(conversation_id, first_target, 5, 1_725_000_000_000)
                .await
                .unwrap();
            storage
                .mark_reset_pending(conversation_id, first_target, 5, 1_725_000_000_000)
                .await
                .expect("exact replay is idempotent");
            assert!(storage
                .mark_reset_pending(conversation_id, adopted_target, 5, 1_725_000_000_000)
                .await
                .is_err());
            assert!(storage
                .mark_reset_pending(conversation_id, first_target, 4, 1_725_000_000_000)
                .await
                .is_err());
            assert_eq!(
                storage
                    .get_conversation_state(conversation_id)
                    .await
                    .unwrap(),
                Some(ConversationState::ResetPending {
                    new_group_id: first_target.into(),
                    reset_generation: 5,
                    notified_at_ms: 1_725_000_000_000,
                })
            );
            assert!(storage.needs_rejoin(conversation_id).await.unwrap());
            assert!(storage.clear_rejoin_flag(conversation_id).await.is_err());
            assert!(storage.needs_rejoin(conversation_id).await.unwrap());
            assert!(storage
                .get_recovery_state()
                .await
                .unwrap()
                .entries
                .is_empty());
            storage
                .mark_reset_pending(conversation_id, first_target, 6, 1_725_000_000_001)
                .await
                .expect("a higher generation supersedes the old reset authority");
            assert_eq!(
                storage
                    .get_conversation_state(conversation_id)
                    .await
                    .unwrap(),
                Some(ConversationState::ResetPending {
                    new_group_id: first_target.into(),
                    reset_generation: 6,
                    notified_at_ms: 1_725_000_000_001,
                })
            );
            let projected = storage
                .get_conversation(owner, conversation_id)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(projected.group_id, old_group);
            assert_eq!(projected.epoch, 8);

            assert!(!storage
                .adopt_reset_pending_target(conversation_id, 5, first_target, adopted_target)
                .await
                .unwrap());
            assert!(storage
                .adopt_reset_pending_target(conversation_id, 6, first_target, adopted_target)
                .await
                .unwrap());
            assert!(storage
                .adopt_reset_pending_target(conversation_id, 6, adopted_target, adopted_target)
                .await
                .expect("adopted target replay is idempotent"));
            assert_eq!(
                storage
                    .get_conversation(owner, conversation_id)
                    .await
                    .unwrap()
                    .unwrap()
                    .group_id,
                old_group,
                "target adoption must not publish the new group mapping"
            );
            assert!(!storage
                .complete_reset_pending(conversation_id, 6, first_target, 2)
                .await
                .unwrap());
        }

        {
            let storage = SqliteStorage::new(path.clone(), owner).expect("reopen reset storage");
            assert_eq!(
                storage
                    .get_conversation_state(conversation_id)
                    .await
                    .unwrap(),
                Some(ConversationState::ResetPending {
                    new_group_id: adopted_target.into(),
                    reset_generation: 6,
                    notified_at_ms: 1_725_000_000_001,
                }),
                "complete reset authority must survive restart"
            );
            assert!(storage.needs_rejoin(conversation_id).await.unwrap());
            assert!(storage
                .complete_reset_pending(conversation_id, 6, adopted_target, 2)
                .await
                .unwrap());
            let projected = storage
                .get_conversation(owner, conversation_id)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(projected.group_id, adopted_target);
            assert_eq!(projected.epoch, 2);
            assert_eq!(
                storage
                    .get_conversation_state(conversation_id)
                    .await
                    .unwrap(),
                Some(ConversationState::Active)
            );
            assert!(!storage.needs_rejoin(conversation_id).await.unwrap());
        }

        {
            let storage =
                SqliteStorage::new(path.clone(), owner).expect("reopen completed reset storage");
            assert!(
                storage
                    .mark_reset_pending(conversation_id, adopted_target, 6, 1_725_000_000_001)
                    .await
                    .is_err(),
                "a completed generation must not be rearmed after restart"
            );
            assert!(
                storage
                    .mark_reset_pending(conversation_id, first_target, 5, 1_725_000_000_000)
                    .await
                    .is_err(),
                "a generation below the durable reset high-water must stay stale"
            );
        }

        let other = SqliteStorage::new(path.clone(), "did:plc:other-reset-owner").unwrap();
        assert_eq!(
            other.get_conversation_state(conversation_id).await.unwrap(),
            None
        );
        assert!(other
            .mark_reset_pending(conversation_id, first_target, 6, 1_725_000_000_001)
            .await
            .is_err());
        drop(other);
        let _ = fs::remove_file(path);
    }

    #[tokio::test]
    async fn reset_delete_and_malformed_payloads_fail_closed() {
        let path = std::env::temp_dir().join(format!(
            "birdaemon-reset-delete-{}.db",
            uuid::Uuid::new_v4()
        ));
        let owner = "did:plc:reset-delete-owner";
        let conversation_id = "55555555-5555-4555-8555-555555555555";
        let old_group = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
        let target = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
        let storage = SqliteStorage::new(path.clone(), owner).unwrap();
        storage
            .ensure_conversation_exists(owner, conversation_id, old_group)
            .await
            .unwrap();
        assert!(storage
            .mark_reset_pending(conversation_id, target, 9, -1)
            .await
            .is_err());
        storage
            .mark_reset_pending(conversation_id, target, 9, 99)
            .await
            .unwrap();
        assert!(!storage
            .clear_reset_pending_for_delete(conversation_id, 8)
            .await
            .unwrap());
        assert!(storage
            .clear_reset_pending_for_delete(conversation_id, 9)
            .await
            .unwrap());
        assert_eq!(
            storage
                .get_conversation_state(conversation_id)
                .await
                .unwrap(),
            Some(ConversationState::Failed),
            "delete preparation must never project Active"
        );
        assert_eq!(
            storage
                .get_conversation(owner, conversation_id)
                .await
                .unwrap()
                .unwrap()
                .group_id,
            old_group
        );

        let malformed_id = "66666666-6666-4666-8666-666666666666";
        storage
            .ensure_conversation_exists(owner, malformed_id, old_group)
            .await
            .unwrap();
        {
            let conn = storage.conn.lock().unwrap();
            conn.execute(
                "UPDATE conversations SET state = 'ResetPending', reset_pending = 1
                 WHERE conversation_id = ?1 AND user_did = ?2",
                rusqlite::params![malformed_id, owner],
            )
            .unwrap();
        }
        assert!(storage.get_conversation_state(malformed_id).await.is_err());

        for capability in [
            "get_conversation_state",
            "mark_reset_pending",
            "adopt_reset_pending_target",
            "complete_reset_pending",
            "complete_account_exit",
            "clear_reset_pending_for_delete",
            "mark_quarantined",
            "clear_quarantine",
        ] {
            assert!(storage.implemented_optional_methods().contains(&capability));
        }
        assert!(!storage
            .implemented_optional_methods()
            .contains(&"clear_reset_pending"));

        drop(storage);
        let _ = fs::remove_file(path);
    }

    #[tokio::test]
    async fn quarantine_authority_round_trips_exactly_and_clears_only_after_durable_exit() {
        let path = std::env::temp_dir().join(format!(
            "birdaemon-quarantine-authority-{}.db",
            uuid::Uuid::new_v4()
        ));
        let owner = "did:plc:quarantine-owner";
        let conversation_id = "77777777-7777-4777-8777-777777777777";
        let group_id = "abababababababababababababababababababababababababababababababab";

        {
            let storage = SqliteStorage::new(path.clone(), owner).unwrap();
            storage
                .ensure_conversation_exists(owner, conversation_id, group_id)
                .await
                .unwrap();
            storage
                .set_conversation_state(
                    conversation_id,
                    ConversationState::Quarantined {
                        reason: QuarantineReason::RepeatedFramingFailures,
                        since_ms: 1_725_000_000_123,
                    },
                )
                .await
                .unwrap();
            storage
                .mark_quarantined(
                    conversation_id,
                    QuarantineReason::RepeatedFramingFailures.tag(),
                    1_725_000_000_123,
                )
                .await
                .unwrap();
            assert!(storage.clear_quarantine(conversation_id).await.is_err());
        }

        {
            let storage = SqliteStorage::new(path.clone(), owner).unwrap();
            assert_eq!(
                storage
                    .get_conversation_state(conversation_id)
                    .await
                    .unwrap(),
                Some(ConversationState::Quarantined {
                    reason: QuarantineReason::RepeatedFramingFailures,
                    since_ms: 1_725_000_000_123,
                })
            );
            storage
                .set_conversation_state(conversation_id, ConversationState::Active)
                .await
                .unwrap();
            storage.clear_quarantine(conversation_id).await.unwrap();
        }

        {
            let storage = SqliteStorage::new(path.clone(), owner).unwrap();
            assert_eq!(
                storage
                    .get_conversation_state(conversation_id)
                    .await
                    .unwrap(),
                Some(ConversationState::Active)
            );
            let malformed_id = "88888888-8888-4888-8888-888888888888";
            storage
                .ensure_conversation_exists(owner, malformed_id, group_id)
                .await
                .unwrap();
            {
                let conn = storage.conn.lock().unwrap();
                conn.execute(
                    "UPDATE conversations
                     SET state = 'Quarantined',
                         quarantine_reason_tag = 'unknown_reason',
                         quarantine_since_ms = 7
                     WHERE conversation_id = ?1 AND user_did = ?2",
                    rusqlite::params![malformed_id, owner],
                )
                .unwrap();
            }
            assert!(storage.get_conversation_state(malformed_id).await.is_err());
        }

        let _ = fs::remove_file(path);
    }

    fn projection_view(
        conversation_id: &str,
        group_id: &str,
        epoch: u64,
        member_dids: &[&str],
    ) -> ConversationView {
        ConversationView {
            group_id: group_id.into(),
            conversation_id: conversation_id.into(),
            epoch,
            members: member_dids
                .iter()
                .map(|did| MemberView {
                    did: (*did).into(),
                    role: MemberRole::Member,
                })
                .collect(),
            metadata: Some(ConversationMetadata {
                name: Some("Canonical roster".into()),
                description: Some("Adopted from the stable server projection".into()),
                avatar_url: None,
            }),
            created_at: None,
            updated_at: None,
            sequencer_did: Some("did:web:sequencer.example".into()),
            canonical_state: None,
        }
    }

    #[tokio::test]
    async fn projection_commit_retires_only_the_alias_projection_and_preserves_history() {
        let path =
            std::env::temp_dir().join(format!("birdaemon-projection-{}.db", uuid::Uuid::new_v4()));
        let owner = "did:plc:alice-projection-owner";
        let canonical_id = "11111111-1111-4111-8111-111111111111";
        let raw_group_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let canonical = projection_view(canonical_id, raw_group_id, 4, &[owner, "did:plc:bob"]);
        let mut refreshed_canonical = canonical.clone();
        refreshed_canonical.epoch = 5;
        refreshed_canonical.members.push(MemberView {
            did: "did:plc:carol".into(),
            role: MemberRole::Admin,
        });

        {
            let storage = SqliteStorage::new(path.clone(), owner).expect("open storage");
            storage
                .ensure_conversation_exists(owner, raw_group_id, raw_group_id)
                .await
                .expect("seed legacy raw-group alias");
            storage
                .update_join_info(raw_group_id, owner, JoinMethod::Welcome, 4)
                .await
                .expect("seed alias incarnation");
            let alias = storage
                .get_conversation(owner, raw_group_id)
                .await
                .unwrap()
                .unwrap();
            let canonical_lifecycle = ProjectionLifecycleFence {
                reset_generation: Some(3),
                ..ProjectionLifecycleFence::default()
            };
            let mut authority = AliasRetirementAuthority::from_views(owner, &canonical, &alias)
                .expect("strict alias authority");
            authority.canonical_lifecycle = canonical_lifecycle.clone();
            // The current shared API exposes typed replay claims, not an encoded ABI.
            // This marker tests host pending-intent persistence only.
            let encoded = "test-only-alias-retirement";
            storage
                .mark_pending_local_delete(raw_group_id, Some(encoded))
                .await
                .expect("persist replay intent");
            storage
                .store_message(&Message {
                    id: "legacy-message".into(),
                    conversation_id: raw_group_id.into(),
                    sender_did: "did:plc:bob".into(),
                    text: "preserve me".into(),
                    timestamp: Utc::now(),
                    epoch: 4,
                    sequence_number: 1,
                    is_own: false,
                    delivery_status: None,
                    payload_json: Some(
                        r#"{"ciphertext":"bound-to-source","hmac":"still-bound"}"#.into(),
                    ),
                })
                .await
                .expect("seed alias-bound history");
            storage
                .set_group_state(&GroupState {
                    group_id: raw_group_id.into(),
                    conversation_id: raw_group_id.into(),
                    epoch: 4,
                    members: vec![owner.into(), "did:plc:bob".into()],
                })
                .await
                .expect("seed crypto group projection");

            let outcome = storage
                .commit_conversation_projection(&{
                    let mut request = ConversationProjectionCommitRequest::live(
                        owner,
                        canonical.clone(),
                        vec![authority],
                    );
                    request.canonical_lifecycle = canonical_lifecycle;
                    request
                })
                .await
                .expect("commit canonical projection");
            assert!(matches!(
                outcome,
                ConversationProjectionCommitOutcome::Retired { affected_rows } if affected_rows >= 2
            ));
            assert_eq!(
                serde_json::to_value(storage.list_conversations(owner).await.unwrap()).unwrap(),
                serde_json::to_value(vec![canonical.clone()]).unwrap()
            );
            let messages = storage
                .get_messages(canonical_id, 10, None)
                .await
                .expect("read history through canonical id");
            assert_eq!(messages.len(), 1);
            assert_eq!(messages[0].conversation_id, canonical_id);
            assert!(storage
                .get_group_state(raw_group_id)
                .await
                .unwrap()
                .is_some());
            for capability in [
                "commit_conversation_projection",
                "mark_pending_local_delete",
                "clear_pending_local_delete",
                "list_pending_local_deletes",
            ] {
                assert!(storage.implemented_optional_methods().contains(&capability));
            }
        }

        let reopened = SqliteStorage::new(path.clone(), owner).expect("reopen storage");
        assert_eq!(
            serde_json::to_value(reopened.list_conversations(owner).await.unwrap()).unwrap(),
            serde_json::to_value(vec![canonical.clone()]).unwrap()
        );
        assert_eq!(
            reopened
                .get_messages(canonical_id, 10, None)
                .await
                .unwrap()
                .len(),
            1
        );
        let pending = reopened.list_pending_local_deletes().await.unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(
            pending[0].group_id_hex.as_deref(),
            Some("test-only-alias-retirement")
        );
        let alias = projection_view(raw_group_id, raw_group_id, 4, &[owner, "did:plc:bob"]);
        let mut replay_authority =
            AliasRetirementAuthority::from_views(owner, &canonical, &alias).unwrap();
        replay_authority.canonical_lifecycle.reset_generation = Some(3);
        assert!(matches!(
            reopened
                .commit_conversation_projection(&ConversationProjectionCommitRequest::replay(
                    replay_authority
                ))
                .await
                .expect("idempotent replay"),
            ConversationProjectionCommitOutcome::AlreadyAbsent { affected_rows: 0 }
        ));
        reopened
            .clear_pending_local_delete(raw_group_id)
            .await
            .expect("clear replay authority after the durable CAS");
        reopened
            .commit_conversation_projection(&ConversationProjectionCommitRequest::live(
                owner,
                refreshed_canonical.clone(),
                vec![],
            ))
            .await
            .expect("refresh canonical roster");
        assert_eq!(
            serde_json::to_value(
                reopened
                    .get_conversation(owner, canonical_id)
                    .await
                    .unwrap()
            )
            .unwrap(),
            serde_json::to_value(Some(refreshed_canonical)).unwrap()
        );
        assert!(reopened
            .list_pending_local_deletes()
            .await
            .unwrap()
            .is_empty());
        assert!(
            reopened
                .mark_reset_pending(canonical_id, raw_group_id, 3, 1_725_000_000_003,)
                .await
                .is_err(),
            "projection adoption must preserve the reset high-water fence"
        );
        let other_owner = SqliteStorage::new(path.clone(), "did:plc:other-owner")
            .expect("open same database as another owner");
        assert!(other_owner
            .list_pending_local_deletes()
            .await
            .unwrap()
            .is_empty());
        drop(reopened);
        drop(other_owner);
        let _ = fs::remove_file(path);
    }

    #[tokio::test]
    async fn projection_commit_rejects_invalid_ids_ambiguity_and_stale_fences_without_mutation() {
        let path = std::env::temp_dir().join(format!(
            "birdaemon-projection-fences-{}.db",
            uuid::Uuid::new_v4()
        ));
        let owner = "did:plc:projection-fence-owner";
        let raw_group_id = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let wanted_id = "22222222-2222-4222-8222-222222222222";
        let conflicting_id = "33333333-3333-4333-8333-333333333333";
        let storage = SqliteStorage::new(path.clone(), owner).expect("open storage");
        storage
            .ensure_conversation_exists(owner, raw_group_id, raw_group_id)
            .await
            .expect("seed alias");

        let invalid = projection_view(
            "22222222222242228222222222222222",
            raw_group_id,
            0,
            &[owner],
        );
        assert!(matches!(
            storage
                .commit_conversation_projection(&ConversationProjectionCommitRequest::live(
                    owner,
                    invalid,
                    vec![],
                ))
                .await
                .unwrap(),
            ConversationProjectionCommitOutcome::FenceMismatch { affected_rows: 0 }
        ));

        let negative_lifecycle = ProjectionLifecycleFence {
            reset_generation: Some(-1),
            ..ProjectionLifecycleFence::default()
        };
        assert!(matches!(
            storage
                .commit_conversation_projection(&{
                    let mut request = ConversationProjectionCommitRequest::live(
                        owner,
                        projection_view(wanted_id, raw_group_id, 0, &[owner]),
                        vec![],
                    );
                    request.canonical_lifecycle = negative_lifecycle;
                    request
                },)
                .await
                .unwrap(),
            ConversationProjectionCommitOutcome::FenceMismatch { affected_rows: 0 }
        ));

        storage
            .ensure_conversation_exists(owner, conflicting_id, raw_group_id)
            .await
            .expect("seed conflicting canonical mapping");
        let canonical = projection_view(wanted_id, raw_group_id, 0, &[owner]);
        let alias = storage
            .get_conversation(owner, raw_group_id)
            .await
            .unwrap()
            .unwrap();
        let authority = AliasRetirementAuthority::from_views(owner, &canonical, &alias).unwrap();
        assert_eq!(
            storage
                .commit_conversation_projection(&ConversationProjectionCommitRequest::live(
                    owner,
                    canonical.clone(),
                    vec![authority],
                ))
                .await
                .unwrap(),
            ConversationProjectionCommitOutcome::Ambiguous {
                canonical_ids: vec![conflicting_id.into()],
                affected_rows: 0,
            }
        );
        assert!(storage
            .get_conversation(owner, raw_group_id)
            .await
            .unwrap()
            .is_some());
        assert!(storage
            .get_conversation(owner, wanted_id)
            .await
            .unwrap()
            .is_none());

        storage
            .delete_conversations(owner, &[conflicting_id])
            .await
            .expect("remove ambiguity fixture");
        storage
            .update_join_info(raw_group_id, owner, JoinMethod::Welcome, 4)
            .await
            .expect("advance alias incarnation");
        let alias = storage
            .get_conversation(owner, raw_group_id)
            .await
            .unwrap()
            .unwrap();
        let canonical = projection_view(wanted_id, raw_group_id, 4, &[owner]);
        let mut stale_authority =
            AliasRetirementAuthority::from_views(owner, &canonical, &alias).unwrap();
        stale_authority.alias_incarnation = 3;
        assert!(matches!(
            storage
                .commit_conversation_projection(&ConversationProjectionCommitRequest::live(
                    owner,
                    canonical.clone(),
                    vec![stale_authority],
                ))
                .await
                .unwrap(),
            ConversationProjectionCommitOutcome::FenceMismatch { affected_rows: 0 }
        ));

        assert!(
            storage
                .mark_reset_pending(raw_group_id, raw_group_id, 9, 1_725_000_000_000)
                .await
                .is_err(),
            "reset authority must reject a raw-group alias id"
        );
        {
            let conn = storage.conn.lock().unwrap();
            conn.execute(
                "UPDATE conversations
                 SET state = 'ResetPending', needs_rejoin = 1,
                     reset_pending = 1, reset_new_group_id = ?1,
                     reset_generation = 9, reset_generation_high_water = 9,
                     reset_notified_at_ms = 1725000000000
                 WHERE conversation_id = ?1 AND user_did = ?2",
                rusqlite::params![raw_group_id, owner],
            )
            .unwrap();
        }
        let reset_alias = storage
            .get_conversation(owner, raw_group_id)
            .await
            .unwrap()
            .unwrap();
        let reset_authority =
            AliasRetirementAuthority::from_views(owner, &canonical, &reset_alias).unwrap();
        assert!(matches!(
            storage
                .commit_conversation_projection(&ConversationProjectionCommitRequest::live(
                    owner,
                    canonical,
                    vec![reset_authority],
                ))
                .await
                .unwrap(),
            ConversationProjectionCommitOutcome::FenceMismatch { affected_rows: 0 }
        ));
        assert!(storage
            .get_conversation(owner, raw_group_id)
            .await
            .unwrap()
            .is_some());

        let other_owner = SqliteStorage::new(path.clone(), "did:plc:other-owner").unwrap();
        let cross_owner_request = ConversationProjectionCommitRequest::live(
            owner,
            projection_view(wanted_id, raw_group_id, 0, &[owner]),
            vec![],
        );
        assert!(other_owner
            .commit_conversation_projection(&cross_owner_request)
            .await
            .unwrap_err()
            .to_string()
            .contains("storage owner"));

        drop(storage);
        drop(other_owner);
        let _ = fs::remove_file(path);
    }

    #[tokio::test]
    async fn projection_replay_requires_the_exact_captured_canonical_epoch() {
        let path = std::env::temp_dir().join(format!(
            "birdaemon-projection-replay-epoch-{}.db",
            uuid::Uuid::new_v4()
        ));
        let owner = "did:plc:projection-replay-owner";
        let canonical_id = "77777777-7777-4777-8777-777777777777";
        let group_id = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        let storage = SqliteStorage::new(path.clone(), owner).unwrap();
        storage
            .ensure_conversation_exists(owner, canonical_id, group_id)
            .await
            .unwrap();
        storage
            .update_join_info(canonical_id, owner, JoinMethod::Welcome, 3)
            .await
            .unwrap();
        storage
            .ensure_conversation_exists(owner, group_id, group_id)
            .await
            .unwrap();
        storage
            .update_join_info(group_id, owner, JoinMethod::Welcome, 2)
            .await
            .unwrap();
        let canonical = storage
            .get_conversation(owner, canonical_id)
            .await
            .unwrap()
            .unwrap();
        let alias = storage
            .get_conversation(owner, group_id)
            .await
            .unwrap()
            .unwrap();
        let authority = AliasRetirementAuthority::from_views(owner, &canonical, &alias).unwrap();

        for stale_epoch in [2, 4] {
            storage
                .update_join_info(canonical_id, owner, JoinMethod::Welcome, stale_epoch)
                .await
                .unwrap();
            assert!(matches!(
                storage
                    .commit_conversation_projection(&ConversationProjectionCommitRequest::replay(
                        authority.clone()
                    ))
                    .await
                    .unwrap(),
                ConversationProjectionCommitOutcome::FenceMismatch { affected_rows: 0 }
            ));
            assert!(storage
                .get_conversation(owner, group_id)
                .await
                .unwrap()
                .is_some());
        }

        storage
            .update_join_info(canonical_id, owner, JoinMethod::Welcome, 3)
            .await
            .unwrap();
        assert!(matches!(
            storage
                .commit_conversation_projection(&ConversationProjectionCommitRequest::replay(
                    authority
                ))
                .await
                .unwrap(),
            ConversationProjectionCommitOutcome::Retired { .. }
        ));
        assert!(storage
            .get_conversation(owner, group_id)
            .await
            .unwrap()
            .is_none());

        drop(storage);
        let _ = fs::remove_file(path);
    }
}

#[cfg(test)]
mod terminal_state_projection_tests {
    use super::*;

    #[test]
    fn terminal_states_round_trip_without_reset_or_quarantine_payload() {
        for state in [ConversationState::DeviceRemoved, ConversationState::Closed] {
            let stored = SqliteStorage::state_str(&state);
            assert_eq!(
                SqliteStorage::persisted_state(
                    "terminal-conversation",
                    stored,
                    false,
                    None,
                    None,
                    None,
                    None,
                    None,
                )
                .unwrap(),
                state
            );
            assert!(SqliteStorage::persisted_state(
                "terminal-conversation",
                stored,
                true,
                Some("ab".repeat(32)),
                Some(1),
                Some(7),
                None,
                None,
            )
            .is_err());
            assert!(SqliteStorage::persisted_state(
                "terminal-conversation",
                stored,
                false,
                None,
                None,
                None,
                Some("foreign".into()),
                Some(7),
            )
            .is_err());
        }
    }
}

#[cfg(test)]
mod account_exit_tests;
