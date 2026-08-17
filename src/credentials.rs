//! File-based CredentialStore implementation.
//!
//! Stores credentials in the same keychain JSON file, namespaced by user DID.
//! Keys are formatted as: "did:plc:xxx/signing_key", "did:plc:xxx/mls_did", etc.

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Mutex;

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;

use catbird_mls::orchestrator::credentials::{CleanChatSigningAuthority, CredentialStore};
use catbird_mls::orchestrator::error::{OrchestratorError, Result};
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::signatures::Signer;

/// File-based credential store using JSON.
pub struct FileCredentialStore {
    path: PathBuf,
    data: Mutex<HashMap<String, String>>,
}

impl FileCredentialStore {
    pub fn new(path: PathBuf) -> Self {
        let mut data: HashMap<String, String> = if path.exists() {
            match std::fs::read_to_string(&path) {
                Ok(contents) => serde_json::from_str(&contents).unwrap_or_default(),
                Err(_) => HashMap::new(),
            }
        } else {
            HashMap::new()
        };

        let insecure_session_keys = data
            .keys()
            .filter(|key| key.ends_with("/chat_session"))
            .cloned()
            .collect::<Vec<_>>();
        let migrated_insecure_session = !insecure_session_keys.is_empty();
        for key in insecure_session_keys {
            data.remove(&key);
        }
        let store = Self {
            path,
            data: Mutex::new(data),
        };
        if migrated_insecure_session {
            let _ = store.flush();
        }
        store
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
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
        }
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

    /// Install the exact binding tuple that the Nest admission check proved.
    /// The private signing key remains in this store; only the public binding
    /// metadata is returned to the orchestrator's signed-request path.
    pub fn set_clean_chat_binding(
        &self,
        user_did: &str,
        device_id: &str,
        dpop_jkt: &str,
        auth_generation: Option<i64>,
    ) -> Result<()> {
        {
            let mut data = self.data.lock().unwrap();
            data.insert(
                Self::key(user_did, "clean_chat_device_id"),
                device_id.to_owned(),
            );
            data.insert(
                Self::key(user_did, "clean_chat_dpop_jkt"),
                dpop_jkt.to_owned(),
            );
            match auth_generation {
                Some(generation) => {
                    data.insert(
                        Self::key(user_did, "clean_chat_auth_generation"),
                        generation.to_string(),
                    );
                }
                None => {
                    data.remove(&Self::key(user_did, "clean_chat_auth_generation"));
                }
            }
        }
        self.flush()
    }

    pub fn clear_clean_chat_binding(&self, user_did: &str) -> Result<()> {
        {
            let mut data = self.data.lock().unwrap();
            for field in [
                "clean_chat_device_id",
                "clean_chat_dpop_jkt",
                "clean_chat_auth_generation",
            ] {
                data.remove(&Self::key(user_did, field));
            }
        }
        self.flush()
    }

    pub fn get_clean_chat_binding(
        &self,
        user_did: &str,
    ) -> Result<Option<(String, String, Option<i64>)>> {
        let data = self.data.lock().unwrap();
        let Some(device_id) = data
            .get(&Self::key(user_did, "clean_chat_device_id"))
            .cloned()
        else {
            return Ok(None);
        };
        let Some(dpop_jkt) = data
            .get(&Self::key(user_did, "clean_chat_dpop_jkt"))
            .cloned()
        else {
            return Ok(None);
        };
        let generation = data
            .get(&Self::key(user_did, "clean_chat_auth_generation"))
            .map(|value| {
                value.parse::<i64>().map_err(|_| {
                    OrchestratorError::Credential("clean-chat generation binding invalid".into())
                })
            })
            .transpose()?;
        Ok(Some((device_id, dpop_jkt, generation)))
    }

    /// Persist the opaque Nest session only in the platform Keychain. It is
    /// never written to ordinary credential JSON or interpreted as a Jacquard
    /// bearer/downstream DPoP token.
    pub fn store_opaque_chat_session(&self, user_did: &str, session_handle: &str) -> Result<()> {
        if session_handle.is_empty() {
            return Err(OrchestratorError::Credential(
                "opaque chat session is empty".into(),
            ));
        }
        keychain_store(user_did, session_handle)
    }

    pub fn get_opaque_chat_session(&self, user_did: &str) -> Result<Option<String>> {
        keychain_load(user_did)
    }

    pub fn delete_opaque_chat_session(&self, user_did: &str) -> Result<()> {
        keychain_delete(user_did)
    }

    pub fn clear_clean_chat_authority(&self, user_did: &str) -> Result<()> {
        // Delete the bearer first. If metadata cleanup fails, restart still
        // cannot find a complete admission tuple and therefore fails closed.
        self.delete_opaque_chat_session(user_did)?;
        self.clear_clean_chat_binding(user_did)
    }
}

const KEYCHAIN_SERVICE: &str = "blue.catbird.bird-daemon.chat-session";

#[cfg(target_os = "macos")]
fn keychain_store(account: &str, session: &str) -> Result<()> {
    security_framework::passwords::set_generic_password(
        KEYCHAIN_SERVICE,
        account,
        session.as_bytes(),
    )
    .map_err(|error| {
        OrchestratorError::Credential(format!("protected chat session store failed: {error}"))
    })
}

#[cfg(not(target_os = "macos"))]
fn keychain_store(_account: &str, _session: &str) -> Result<()> {
    Err(OrchestratorError::Credential(
        "protected chat session store unavailable".into(),
    ))
}

#[cfg(target_os = "macos")]
fn keychain_load(account: &str) -> Result<Option<String>> {
    match security_framework::passwords::get_generic_password(KEYCHAIN_SERVICE, account) {
        Ok(bytes) => {
            let value = String::from_utf8(bytes).map_err(|_| {
                OrchestratorError::Credential("protected chat session is invalid UTF-8".into())
            })?;
            let trimmed = value.trim_end_matches(['\r', '\n']).to_owned();
            Ok((!trimmed.is_empty()).then_some(trimmed))
        }
        Err(err) if err.code() == -25300 => Ok(None),
        Err(err) => Err(OrchestratorError::Credential(format!(
            "protected chat session read failed: {err}"
        ))),
    }
}

#[cfg(not(target_os = "macos"))]
fn keychain_load(_account: &str) -> Result<Option<String>> {
    Err(OrchestratorError::Credential(
        "protected chat session store unavailable".into(),
    ))
}

#[cfg(target_os = "macos")]
fn keychain_delete(account: &str) -> Result<()> {
    match security_framework::passwords::delete_generic_password(KEYCHAIN_SERVICE, account) {
        Ok(()) => Ok(()),
        Err(err) if err.code() == -25300 => Ok(()),
        Err(err) => Err(OrchestratorError::Credential(format!(
            "protected chat session delete failed: {err}"
        ))),
    }
}

#[cfg(not(target_os = "macos"))]
fn keychain_delete(_account: &str) -> Result<()> {
    Ok(())
}

#[async_trait]
impl CredentialStore for FileCredentialStore {
    async fn store_signing_key(&self, user_did: &str, key_data: &[u8]) -> Result<()> {
        self.set_bytes(user_did, "signing_key", key_data)
    }

    async fn get_signing_key(&self, user_did: &str) -> Result<Option<Vec<u8>>> {
        self.get_bytes(user_did, "signing_key")
    }

    async fn sign_clean_chat_transcript(
        &self,
        user_did: &str,
        transcript: &[u8],
        _key_id: &str,
    ) -> Result<Option<CleanChatSigningAuthority>> {
        // Keep the key bytes and binding metadata under one lock. This gives
        // each request one immutable signer/binding snapshot and prevents a
        // concurrent account/device switch from pairing a new tuple with an
        // old signer.
        let (key_data, device_id, dpop_jkt, auth_generation) = {
            let data = self.data.lock().unwrap();
            let Some(encoded) = data.get(&Self::key(user_did, "signing_key")) else {
                return Ok(None);
            };
            let key_data = B64
                .decode(encoded)
                .map_err(|e| OrchestratorError::Credential(format!("decode signing key: {e}")))?;
            let device_id = data
                .get(&Self::key(user_did, "clean_chat_device_id"))
                .cloned()
                .ok_or_else(|| {
                    OrchestratorError::Credential("clean-chat device binding missing".into())
                })?;
            let dpop_jkt = data
                .get(&Self::key(user_did, "clean_chat_dpop_jkt"))
                .cloned()
                .ok_or_else(|| {
                    OrchestratorError::Credential("clean-chat JKT binding missing".into())
                })?;
            let auth_generation = data
                .get(&Self::key(user_did, "clean_chat_auth_generation"))
                .map(|value| {
                    value.parse::<i64>().map_err(|_| {
                        OrchestratorError::Credential(
                            "clean-chat generation binding invalid".into(),
                        )
                    })
                })
                .transpose()?;
            (key_data, device_id, dpop_jkt, auth_generation)
        };
        let signer: SignatureKeyPair = serde_json::from_slice(&key_data)
            .map_err(|_| OrchestratorError::Credential("stored signing key is invalid".into()))?;
        let signature = signer
            .sign(transcript)
            .map_err(|_| OrchestratorError::Credential("clean-chat signer failed".into()))?;
        Ok(Some(CleanChatSigningAuthority {
            public_key: signer.public().to_vec(),
            signature,
            device_id,
            dpop_jkt,
            auth_generation,
        }))
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
