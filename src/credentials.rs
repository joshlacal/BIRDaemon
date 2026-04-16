//! File-based CredentialStore implementation.
//!
//! Stores credentials in the same keychain JSON file, namespaced by user DID.
//! Keys are formatted as: "did:plc:xxx/signing_key", "did:plc:xxx/mls_did", etc.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;

use catbird_mls::orchestrator::credentials::CredentialStore;
use catbird_mls::orchestrator::error::{OrchestratorError, Result};

/// File-based credential store using JSON.
pub struct FileCredentialStore {
    path: PathBuf,
    data: Mutex<HashMap<String, String>>,
}

impl FileCredentialStore {
    pub fn new(path: PathBuf) -> Self {
        let data = if path.exists() {
            match std::fs::read_to_string(&path) {
                Ok(contents) => serde_json::from_str(&contents).unwrap_or_default(),
                Err(_) => HashMap::new(),
            }
        } else {
            HashMap::new()
        };

        Self {
            path,
            data: Mutex::new(data),
        }
    }

    fn key(user_did: &str, field: &str) -> String {
        format!("{}/{}", user_did, field)
    }

    fn flush(&self) -> Result<()> {
        let data = self.data.lock().unwrap();
        let json = serde_json::to_string_pretty(&*data)
            .map_err(|e| OrchestratorError::Credential(format!("serialize credentials: {e}")))?;

        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, &json)
            .map_err(|e| OrchestratorError::Credential(format!("write credentials tmp: {e}")))?;
        std::fs::rename(&tmp, &self.path)
            .map_err(|e| OrchestratorError::Credential(format!("rename credentials: {e}")))?;

        Ok(())
    }

    fn get_string(&self, user_did: &str, field: &str) -> Option<String> {
        let data = self.data.lock().unwrap();
        data.get(&Self::key(user_did, field)).cloned()
    }

    fn set_string(&self, user_did: &str, field: &str, value: &str) -> Result<()> {
        {
            let mut data = self.data.lock().unwrap();
            data.insert(Self::key(user_did, field), value.to_string());
        }
        self.flush()
    }

    fn get_bytes(&self, user_did: &str, field: &str) -> Result<Option<Vec<u8>>> {
        let data = self.data.lock().unwrap();
        match data.get(&Self::key(user_did, field)) {
            Some(b64) => {
                let bytes = B64
                    .decode(b64)
                    .map_err(|e| OrchestratorError::Credential(format!("decode: {e}")))?;
                Ok(Some(bytes))
            }
            None => Ok(None),
        }
    }

    fn set_bytes(&self, user_did: &str, field: &str, value: &[u8]) -> Result<()> {
        {
            let mut data = self.data.lock().unwrap();
            data.insert(Self::key(user_did, field), B64.encode(value));
        }
        self.flush()
    }
}

#[async_trait]
impl CredentialStore for FileCredentialStore {
    async fn store_signing_key(&self, user_did: &str, key_data: &[u8]) -> Result<()> {
        self.set_bytes(user_did, "signing_key", key_data)
    }

    async fn get_signing_key(&self, user_did: &str) -> Result<Option<Vec<u8>>> {
        self.get_bytes(user_did, "signing_key")
    }

    async fn delete_signing_key(&self, user_did: &str) -> Result<()> {
        {
            let mut data = self.data.lock().unwrap();
            data.remove(&Self::key(user_did, "signing_key"));
        }
        self.flush()
    }

    async fn store_mls_did(&self, user_did: &str, mls_did: &str) -> Result<()> {
        self.set_string(user_did, "mls_did", mls_did)
    }

    async fn get_mls_did(&self, user_did: &str) -> Result<Option<String>> {
        Ok(self.get_string(user_did, "mls_did"))
    }

    async fn store_device_uuid(&self, user_did: &str, uuid: &str) -> Result<()> {
        self.set_string(user_did, "device_uuid", uuid)
    }

    async fn get_device_uuid(&self, user_did: &str) -> Result<Option<String>> {
        Ok(self.get_string(user_did, "device_uuid"))
    }

    async fn has_credentials(&self, user_did: &str) -> Result<bool> {
        let has_mls = self.get_string(user_did, "mls_did").is_some();
        let has_uuid = self.get_string(user_did, "device_uuid").is_some();
        Ok(has_mls && has_uuid)
    }

    async fn clear_all(&self, user_did: &str) -> Result<()> {
        {
            let mut data = self.data.lock().unwrap();
            let prefix = format!("{}/", user_did);
            data.retain(|k, _| !k.starts_with(&prefix));
        }
        self.flush()
    }
}
