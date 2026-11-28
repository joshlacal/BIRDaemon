//! File-based KeychainAccess implementation.
//!
//! Stores key-value pairs as JSON: `{ "key": "base64_value", ... }`
//! at ~/Library/Application Support/BirdDaemon/keychain.json

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;

use catbird_mls::EpochSecretStorage;
use catbird_mls::KeychainAccess;
use catbird_mls::MLSError;

/// File-based keychain that persists data as JSON.
#[derive(Clone)]
pub struct FileKeychain {
    path: PathBuf,
    data: std::sync::Arc<Mutex<HashMap<String, String>>>,
    epoch_secret_owner: Option<String>,
}

impl FileKeychain {
    pub fn new(path: PathBuf) -> Result<Self, MLSError> {
        let data = if path.exists() {
            let contents = std::fs::read_to_string(&path)
                .map_err(|e| MLSError::Internal(format!("read keychain: {e}")))?;
            serde_json::from_str(&contents)
                .map_err(|e| MLSError::Internal(format!("parse keychain: {e}")))?
        } else {
            HashMap::new()
        };

        Ok(Self {
            path,
            data: std::sync::Arc::new(Mutex::new(data)),
            epoch_secret_owner: None,
        })
    }

    /// Return a clone that shares the exact same atomic backing map but may
    /// expose epoch secrets only within one authenticated account namespace.
    pub fn with_epoch_secret_owner(&self, owner_did: &str) -> Result<Self, MLSError> {
        let parsed = owner_did
            .strip_prefix("did:")
            .and_then(|value| value.split_once(':'));
        let valid = parsed.is_some_and(|(method, identifier)| {
            !method.is_empty()
                && method
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
                && !identifier.is_empty()
                && !identifier.chars().any(|character| {
                    character.is_whitespace() || matches!(character, '#' | '?' | '/')
                })
        });
        if owner_did.trim() != owner_did || !valid {
            return Err(MLSError::invalid_input(
                "epoch-secret owner must be one authenticated base DID",
            ));
        }
        let mut scoped = self.clone();
        scoped.epoch_secret_owner = Some(owner_did.to_owned());
        Ok(scoped)
    }

    fn update_data<T>(
        &self,
        update: impl FnOnce(&mut HashMap<String, String>) -> T,
    ) -> Result<T, MLSError> {
        let mut current = self.data.lock().unwrap();
        let mut next = current.clone();
        let result = update(&mut next);
        let json = serde_json::to_string_pretty(&next)
            .map_err(|e| MLSError::Internal(format!("serialize keychain: {e}")))?;

        // Publish file contents first, then the in-memory snapshot, while one
        // mutex serializes every clone. A failed write/rename exposes neither
        // a partially-updated in-memory map nor a partial JSON file.
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, &json)
            .map_err(|e| MLSError::Internal(format!("write keychain tmp: {e}")))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| MLSError::Internal(format!("set keychain permissions: {e}")))?;
        }
        std::fs::rename(&tmp, &self.path)
            .map_err(|e| MLSError::Internal(format!("rename keychain: {e}")))?;

        *current = next;
        Ok(result)
    }

    fn epoch_secret_prefix(&self, conversation_id: &str) -> Option<String> {
        let owner = self.epoch_secret_owner.as_deref()?;
        Some(format!(
            "epoch-secret:v1:{}:{}:",
            B64.encode(owner.as_bytes()),
            B64.encode(conversation_id.as_bytes())
        ))
    }

    fn epoch_secret_key(&self, conversation_id: &str, epoch: u64) -> Option<String> {
        self.epoch_secret_prefix(conversation_id)
            .map(|prefix| format!("{prefix}{epoch}"))
    }
}

#[async_trait]
impl KeychainAccess for FileKeychain {
    async fn read(&self, key: String) -> Result<Option<Vec<u8>>, MLSError> {
        let data = self.data.lock().unwrap();
        match data.get(&key) {
            Some(b64) => {
                let bytes = B64
                    .decode(b64)
                    .map_err(|e| MLSError::Internal(format!("decode keychain value: {e}")))?;
                Ok(Some(bytes))
            }
            None => Ok(None),
        }
    }

    async fn write(&self, key: String, value: Vec<u8>) -> Result<(), MLSError> {
        let encoded = B64.encode(value);
        self.update_data(move |data| {
            data.insert(key, encoded);
        })
    }

    async fn delete(&self, key: String) -> Result<(), MLSError> {
        self.update_data(move |data| {
            data.remove(&key);
        })
    }
}

#[async_trait]
impl EpochSecretStorage for FileKeychain {
    async fn store_epoch_secret(
        &self,
        conversation_id: String,
        epoch: u64,
        secret_data: Vec<u8>,
    ) -> bool {
        let Some(key) = self.epoch_secret_key(&conversation_id, epoch) else {
            return false;
        };
        let encoded = B64.encode(secret_data);
        self.update_data(move |data| {
            data.insert(key, encoded);
        })
        .is_ok()
    }

    async fn get_epoch_secret(&self, conversation_id: String, epoch: u64) -> Option<Vec<u8>> {
        let key = self.epoch_secret_key(&conversation_id, epoch)?;
        let encoded = self.data.lock().unwrap().get(&key).cloned()?;
        B64.decode(encoded).ok()
    }

    async fn delete_epoch_secret(&self, conversation_id: String, epoch: u64) -> bool {
        let Some(key) = self.epoch_secret_key(&conversation_id, epoch) else {
            return false;
        };
        self.update_data(move |data| data.remove(&key).is_some())
            .unwrap_or(false)
    }

    async fn delete_epochs_before(&self, conversation_id: String, cutoff_epoch: u64) -> u32 {
        let Some(prefix) = self.epoch_secret_prefix(&conversation_id) else {
            return 0;
        };
        self.update_data(move |data| {
            let before = data.len();
            data.retain(|key, _| {
                !key.strip_prefix(&prefix)
                    .and_then(|epoch| epoch.parse::<u64>().ok())
                    .is_some_and(|epoch| epoch < cutoff_epoch)
            });
            u32::try_from(before.saturating_sub(data.len())).unwrap_or(u32::MAX)
        })
        .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn epoch_secrets_are_durable_owner_scoped_and_legacy_compatible() {
        let dir = std::env::temp_dir().join(format!("birdaemon-keychain-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("keychain.json");
        std::fs::write(&path, r#"{"legacy-key":"AQID"}"#).unwrap();

        let root = FileKeychain::new(path.clone()).unwrap();
        assert_eq!(
            KeychainAccess::read(&root, "legacy-key".into())
                .await
                .unwrap(),
            Some(vec![1, 2, 3]),
            "existing keychain JSON entries must remain readable"
        );
        assert!(root.with_epoch_secret_owner("").is_err());
        assert!(root.with_epoch_secret_owner("did:").is_err());
        assert!(root.with_epoch_secret_owner("did:plc:").is_err());
        assert!(root.with_epoch_secret_owner("did:PLC:alice").is_err());
        assert!(root
            .with_epoch_secret_owner("did:plc:alice#device")
            .is_err());
        assert!(
            !EpochSecretStorage::store_epoch_secret(
                &root,
                "group-without-owner".into(),
                1,
                vec![9],
            )
            .await,
            "an unscoped keychain must fail closed"
        );

        let alice = root
            .with_epoch_secret_owner("did:plc:alice")
            .expect("scope Alice");
        let bob = root
            .with_epoch_secret_owner("did:plc:bob")
            .expect("scope Bob");
        assert!(
            alice
                .store_epoch_secret("shared-group".into(), 4, vec![4, 4, 4])
                .await
        );
        assert!(
            bob.store_epoch_secret("shared-group".into(), 4, vec![8, 8, 8])
                .await
        );
        assert_eq!(
            alice.get_epoch_secret("shared-group".into(), 4).await,
            Some(vec![4, 4, 4])
        );
        assert_eq!(
            bob.get_epoch_secret("shared-group".into(), 4).await,
            Some(vec![8, 8, 8])
        );
        drop(alice);
        drop(bob);
        drop(root);

        let reopened = FileKeychain::new(path.clone()).unwrap();
        let alice = reopened.with_epoch_secret_owner("did:plc:alice").unwrap();
        let bob = reopened.with_epoch_secret_owner("did:plc:bob").unwrap();
        assert_eq!(
            alice.get_epoch_secret("shared-group".into(), 4).await,
            Some(vec![4, 4, 4]),
            "Alice's epoch secret must survive restart"
        );
        assert_eq!(
            bob.get_epoch_secret("shared-group".into(), 4).await,
            Some(vec![8, 8, 8]),
            "Bob must retain an isolated value at the same group/epoch"
        );
        assert_eq!(
            alice.delete_epochs_before("shared-group".into(), 5).await,
            1
        );
        assert_eq!(alice.get_epoch_secret("shared-group".into(), 4).await, None);
        assert_eq!(
            bob.get_epoch_secret("shared-group".into(), 4).await,
            Some(vec![8, 8, 8]),
            "Alice's pruning must not cross the owner namespace"
        );
        assert_eq!(
            KeychainAccess::read(&reopened, "legacy-key".into())
                .await
                .unwrap(),
            Some(vec![1, 2, 3]),
            "epoch-secret writes must preserve the legacy key namespace"
        );

        drop(alice);
        drop(bob);
        drop(reopened);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn malformed_existing_keychain_fails_closed_without_overwriting_material() {
        let dir = std::env::temp_dir().join(format!(
            "birdaemon-malformed-keychain-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("keychain.json");
        let malformed = b"{not valid key material";
        std::fs::write(&path, malformed).unwrap();

        assert!(FileKeychain::new(path.clone()).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), malformed);

        let _ = std::fs::remove_dir_all(dir);
    }
}
