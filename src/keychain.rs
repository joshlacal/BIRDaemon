//! File-based KeychainAccess implementation.
//!
//! Stores key-value pairs as JSON: `{ "key": "base64_value", ... }`
//! at ~/Library/Application Support/BirdDaemon/keychain.json

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;

use catbird_mls::MLSError;
use catbird_mls::KeychainAccess;

/// File-based keychain that persists data as JSON.
pub struct FileKeychain {
    path: PathBuf,
    data: Mutex<HashMap<String, String>>,
}

impl FileKeychain {
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

    fn flush(&self) -> Result<(), MLSError> {
        let data = self.data.lock().unwrap();
        let json = serde_json::to_string_pretty(&*data)
            .map_err(|e| MLSError::Internal(format!("serialize keychain: {e}")))?;

        // Atomic write: write to temp, then rename
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, &json)
            .map_err(|e| MLSError::Internal(format!("write keychain tmp: {e}")))?;
        std::fs::rename(&tmp, &self.path)
            .map_err(|e| MLSError::Internal(format!("rename keychain: {e}")))?;

        Ok(())
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
        {
            let mut data = self.data.lock().unwrap();
            data.insert(key, B64.encode(&value));
        }
        self.flush()
    }

    async fn delete(&self, key: String) -> Result<(), MLSError> {
        {
            let mut data = self.data.lock().unwrap();
            data.remove(&key);
        }
        self.flush()
    }
}
