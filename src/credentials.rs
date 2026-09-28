//! File-based CredentialStore implementation.
//!
//! Stores credentials in the same keychain JSON file, namespaced by user DID.
//! Keys are formatted as: "did:plc:xxx/signing_key", "did:plc:xxx/mls_did", etc.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use url::Url;

use catbird_mls::orchestrator::credentials::{CleanChatSigningAuthority, CredentialStore};
use catbird_mls::orchestrator::error::{OrchestratorError, Result};
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::signatures::Signer;

use crate::chat_authority::derive_key_id;

/// File-based credential store using JSON.
pub struct FileCredentialStore {
    path: PathBuf,
    data: Mutex<HashMap<String, String>>,
    #[cfg(debug_assertions)]
    http_client: Mutex<Option<reqwest::Client>>,
}

/// The exact device identity admitted by Nest and exposed to the shared
/// orchestrator. These values are persisted as one JSON-file transaction so
/// the legacy credential callbacks can never observe a device UUID from one
/// admission alongside an MLS DID or auth generation from another.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmittedDeviceTuple {
    pub device_uuid: String,
    pub mls_did: String,
    pub auth_generation: i64,
}

/// Enrollment state persisted before the first network mutation. The opaque
/// Nest session is stored separately in the platform Keychain; none of these
/// fields satisfy the admitted credential getters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingEnrollment {
    pub device_uuid: String,
    pub mls_did: String,
    pub idempotency_key: String,
    pub prepared_body: Option<Vec<u8>>,
}

impl FileCredentialStore {
    pub fn new(path: PathBuf) -> Result<Self> {
        let mut data: HashMap<String, String> = if path.exists() {
            let contents = std::fs::read_to_string(&path).map_err(|error| {
                OrchestratorError::Credential(format!("read credentials: {error}"))
            })?;
            serde_json::from_str(&contents).map_err(|error| {
                OrchestratorError::Credential(format!("parse credentials: {error}"))
            })?
        } else {
            HashMap::new()
        };

        let mut migrated_metadata = false;
        let insecure_session_keys = data
            .keys()
            .filter(|key| key.ends_with("/chat_session"))
            .cloned()
            .collect::<Vec<_>>();
        let migrated_insecure_session = !insecure_session_keys.is_empty();
        for key in insecure_session_keys {
            data.remove(&key);
        }
        let obsolete_binding_keys = data
            .keys()
            .filter(|key| {
                key.ends_with("/clean_chat_dpop_jkt") || key.ends_with("/clean_chat_device_id")
            })
            .cloned()
            .collect::<Vec<_>>();
        for key in obsolete_binding_keys {
            migrated_metadata |= data.remove(&key).is_some();
        }
        let store = Self {
            path,
            data: Mutex::new(data),
            #[cfg(debug_assertions)]
            http_client: Mutex::new(None),
        };
        if migrated_insecure_session || migrated_metadata {
            store.flush()?;
        }
        Ok(store)
    }
    #[cfg(debug_assertions)]
    pub fn set_http_client(&self, client: reqwest::Client) {
        *self.http_client.lock().unwrap() = Some(client);
    }

    fn http_client(&self) -> Result<reqwest::Client> {
        #[cfg(debug_assertions)]
        {
            if let Some(client) = self.http_client.lock().unwrap().clone() {
                return Ok(client);
            }
        }
        reqwest::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| OrchestratorError::Credential(format!("HTTP client build failed: {e}")))
    }

    fn key(user_did: &str, field: &str) -> String {
        format!("{}/{}", user_did, field)
    }

    fn flush(&self) -> Result<()> {
        let data = self.data.lock().unwrap();
        self.persist(&data)
    }

    fn persist(&self, data: &HashMap<String, String>) -> Result<()> {
        let json = serde_json::to_string_pretty(data)
            .map_err(|e| OrchestratorError::Credential(format!("serialize credentials: {e}")))?;

        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, &json)
            .map_err(|e| OrchestratorError::Credential(format!("write credentials tmp: {e}")))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600)).map_err(
                |e| OrchestratorError::Credential(format!("set credentials permissions: {e}")),
            )?;
        }
        std::fs::rename(&tmp, &self.path)
            .map_err(|e| OrchestratorError::Credential(format!("rename credentials: {e}")))?;

        Ok(())
    }

    fn update_atomically(
        &self,
        update: impl FnOnce(&mut HashMap<String, String>) -> Result<()>,
    ) -> Result<()> {
        let mut current = self.data.lock().unwrap();
        let mut candidate = current.clone();
        update(&mut candidate)?;
        self.persist(&candidate)?;
        *current = candidate;
        Ok(())
    }

    fn get_string(&self, user_did: &str, field: &str) -> Option<String> {
        let data = self.data.lock().unwrap();
        data.get(&Self::key(user_did, field)).cloned()
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
        self.update_atomically(|data| {
            data.insert(Self::key(user_did, field), B64.encode(value));
            Ok(())
        })
    }

    /// Begin a durable, non-admitted enrollment before signing or sending it.
    pub fn begin_pending_enrollment(
        &self,
        user_did: &str,
        device_uuid: &str,
        mls_did: &str,
        idempotency_key: &str,
    ) -> Result<()> {
        validate_pending_enrollment(user_did, device_uuid, mls_did, idempotency_key)?;
        self.update_atomically(|data| {
            for field in ["device_uuid", "mls_did", "clean_chat_auth_generation"] {
                if data.contains_key(&Self::key(user_did, field)) {
                    return Err(OrchestratorError::Credential(
                        "cannot replace an admitted device tuple with a pending enrollment".into(),
                    ));
                }
            }
            for (field, expected) in [
                ("pending_device_uuid", device_uuid),
                ("pending_mls_did", mls_did),
                ("pending_enrollment_idempotency", idempotency_key),
            ] {
                if data
                    .get(&Self::key(user_did, field))
                    .is_some_and(|actual| actual != expected)
                {
                    return Err(OrchestratorError::Credential(
                        "cannot replace a pending enrollment without clearing authority".into(),
                    ));
                }
                data.insert(Self::key(user_did, field), expected.to_owned());
            }
            Ok(())
        })
    }

    /// Attach the exact signed request bytes before any enrollment POST. An
    /// exact retry is idempotent; a byte or idempotency mismatch fails closed.
    pub fn finalize_pending_enrollment(
        &self,
        user_did: &str,
        idempotency_key: &str,
        prepared_body: &[u8],
    ) -> Result<()> {
        if prepared_body.is_empty() {
            return Err(OrchestratorError::Credential(
                "pending enrollment prepared body is empty".into(),
            ));
        }
        let request: catbird_atproto::blue_catbird::chat::enroll_device::EnrollDevice<String> =
            serde_json::from_slice(prepared_body).map_err(|error| {
                OrchestratorError::Credential(format!(
                    "pending enrollment prepared body is invalid: {error}"
                ))
            })?;
        self.update_atomically(|data| {
            let pending = pending_enrollment_from_data(data, user_did)?.ok_or_else(|| {
                OrchestratorError::Credential("pending enrollment binding is missing".into())
            })?;
            if pending.idempotency_key != idempotency_key
                || request.signed_request.body.actor_did.as_str() != user_did
                || request.signed_request.body.device_id.as_str() != pending.device_uuid
                || request.signed_request.body.idempotency_key.as_str() != idempotency_key
                || request.signed_request.body.expected_auth_generation != 0
            {
                return Err(OrchestratorError::Credential(
                    "pending enrollment prepared request does not match its durable binding".into(),
                ));
            }
            let encoded = B64.encode(prepared_body);
            let body_key = Self::key(user_did, "pending_enrollment_prepared_body");
            if data
                .get(&body_key)
                .is_some_and(|existing| existing != &encoded)
            {
                return Err(OrchestratorError::Credential(
                    "pending enrollment prepared bytes changed across retry".into(),
                ));
            }
            data.insert(body_key, encoded);
            Ok(())
        })
    }

    pub fn get_pending_enrollment(&self, user_did: &str) -> Result<Option<PendingEnrollment>> {
        let data = self.data.lock().unwrap();
        pending_enrollment_from_data(&data, user_did)
    }

    /// Atomically bridge a successfully admitted clean-chat device into every
    /// identity callback consumed by the shared orchestrator.
    pub fn install_admitted_device_tuple(
        &self,
        user_did: &str,
        device_uuid: &str,
        mls_did: &str,
        auth_generation: i64,
    ) -> Result<()> {
        validate_admitted_tuple(user_did, device_uuid, mls_did, auth_generation)?;
        self.update_atomically(|data| {
            if let Some(pending) = pending_enrollment_from_data(data, user_did)? {
                if pending.device_uuid != device_uuid || pending.mls_did != mls_did {
                    return Err(OrchestratorError::Credential(
                        "Nest admission does not match the pending enrollment binding".into(),
                    ));
                }
            }
            for (field, expected) in [
                ("device_uuid", device_uuid),
                ("mls_did", mls_did),
                ("clean_chat_auth_generation", &auth_generation.to_string()),
            ] {
                if data
                    .get(&Self::key(user_did, field))
                    .is_some_and(|actual| actual != expected)
                {
                    return Err(OrchestratorError::Credential(
                        "cannot replace an admitted device tuple without clearing authority".into(),
                    ));
                }
            }
            for (field, value) in [("device_uuid", device_uuid), ("mls_did", mls_did)] {
                data.insert(Self::key(user_did, field), value.to_owned());
            }
            data.insert(
                Self::key(user_did, "clean_chat_auth_generation"),
                auth_generation.to_string(),
            );
            remove_pending_enrollment(data, user_did);
            Ok(())
        })
    }

    pub fn get_admitted_device_tuple(&self, user_did: &str) -> Result<Option<AdmittedDeviceTuple>> {
        let data = self.data.lock().unwrap();
        let fields = ["device_uuid", "mls_did", "clean_chat_auth_generation"];
        let present = fields
            .iter()
            .filter(|field| data.contains_key(&Self::key(user_did, field)))
            .count();
        if present == 0 {
            return Ok(None);
        }
        if present != fields.len() {
            return Err(OrchestratorError::Credential(
                "admitted clean-chat device tuple is incomplete".into(),
            ));
        }
        let device_uuid = data
            .get(&Self::key(user_did, "device_uuid"))
            .expect("presence counted above")
            .clone();
        let mls_did = data
            .get(&Self::key(user_did, "mls_did"))
            .expect("presence counted above")
            .clone();
        let auth_generation = data
            .get(&Self::key(user_did, "clean_chat_auth_generation"))
            .expect("presence counted above")
            .parse::<i64>()
            .map_err(|_| {
                OrchestratorError::Credential(
                    "admitted clean-chat authentication generation is invalid".into(),
                )
            })?;
        validate_admitted_tuple(user_did, &device_uuid, &mls_did, auth_generation)?;
        Ok(Some(AdmittedDeviceTuple {
            device_uuid,
            mls_did,
            auth_generation,
        }))
    }

    pub fn clear_clean_chat_binding(&self, user_did: &str) -> Result<()> {
        self.update_atomically(|data| {
            for field in [
                "clean_chat_auth_generation",
                "device_uuid",
                "mls_did",
                "clean_chat_device_id",
                "clean_chat_dpop_jkt",
            ] {
                data.remove(&Self::key(user_did, field));
            }
            remove_pending_enrollment(data, user_did);
            Ok(())
        })
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
    async fn direct_request_receipt_authority_document(
        &self,
        expected_authority_did: &str,
    ) -> Result<Option<Vec<u8>>> {
        validate_bare_did(expected_authority_did)?;
        let url = did_document_url(expected_authority_did)?;
        validate_safe_https_endpoint(&url)?;
        let http = self.http_client()?;
        let response = http
            .get(url.as_str())
            .header("accept", "application/json")
            .send()
            .await
            .map_err(|e| OrchestratorError::Credential(format!("receipt authority resolution failed: {e}")))?
            .error_for_status()
            .map_err(|e| OrchestratorError::Credential(format!("receipt authority unavailable: {e}")))?;
        let bytes = read_bounded_body(response, MAX_AUTHORITY_RESPONSE_BYTES).await?;
        let doc: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|e| OrchestratorError::Credential(format!("parse authority document: {e}")))?;
        let doc_id = doc
            .get("id")
            .and_then(|id| id.as_str())
            .ok_or_else(|| OrchestratorError::Credential("authority document missing id".into()))?;
        if doc_id != expected_authority_did {
            return Err(OrchestratorError::Credential(
                "authority document ID does not match expected authority DID".into(),
            ));
        }
        Ok(Some(bytes))
    }

    async fn get_chat_declaration_authority(
        &self,
        user_did: &str,
    ) -> Result<Option<String>> {
        validate_bare_did(user_did)?;
        let url = did_document_url(user_did)?;
        validate_safe_https_endpoint(&url)?;
        let http = self.http_client()?;
        let response = http
            .get(url.as_str())
            .header("accept", "application/json")
            .send()
            .await
            .map_err(|e| OrchestratorError::Credential(format!("user DID resolution failed: {e}")))?
            .error_for_status()
            .map_err(|e| OrchestratorError::Credential(format!("user DID document unavailable: {e}")))?;
        let doc_bytes = read_bounded_body(response, MAX_AUTHORITY_RESPONSE_BYTES).await?;
        let pds_url = parse_did_document_pds_endpoint(user_did, &doc_bytes)?;
        let record_url = declaration_record_url(&pds_url, user_did)?;
        let response = http
            .get(record_url.as_str())
            .header("accept", "application/json")
            .send()
            .await
            .map_err(|e| OrchestratorError::Credential(format!("chat declaration getRecord failed: {e}")))?;
        let status = response.status().as_u16();
        let body_bytes = read_bounded_body(response, MAX_AUTHORITY_RESPONSE_BYTES).await?;
        parse_chat_declaration_response(user_did, status, &body_bytes)
    }

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
        key_id: &str,
    ) -> Result<Option<CleanChatSigningAuthority>> {
        // Keep the key bytes and binding metadata under one lock. This gives
        // each request one immutable signer/binding snapshot and prevents a
        // concurrent account/device switch from pairing a new tuple with an
        // old signer.
        let (key_data, device_id, auth_generation) = {
            let data = self.data.lock().unwrap();
            let Some(encoded) = data.get(&Self::key(user_did, "signing_key")) else {
                return Ok(None);
            };
            let key_data = B64
                .decode(encoded)
                .map_err(|e| OrchestratorError::Credential(format!("decode signing key: {e}")))?;
            let admitted_device = data.get(&Self::key(user_did, "device_uuid")).cloned();
            let pending = pending_enrollment_from_data(&data, user_did)?;
            if admitted_device.is_some() && pending.is_some() {
                return Err(OrchestratorError::Credential(
                    "admitted and pending clean-chat authority overlap".into(),
                ));
            }
            let (device_id, auth_generation) = if let Some(device_id) = admitted_device {
                let generation = data
                    .get(&Self::key(user_did, "clean_chat_auth_generation"))
                    .ok_or_else(|| {
                        OrchestratorError::Credential(
                            "admitted clean-chat generation binding missing".into(),
                        )
                    })?
                    .parse::<i64>()
                    .map_err(|_| {
                        OrchestratorError::Credential(
                            "clean-chat generation binding invalid".into(),
                        )
                    })?;
                (device_id, Some(generation))
            } else if let Some(pending) = pending {
                (pending.device_uuid, None)
            } else {
                return Err(OrchestratorError::Credential(
                    "clean-chat device binding missing".into(),
                ));
            };
            (key_data, device_id, auth_generation)
        };
        let signer: SignatureKeyPair = serde_json::from_slice(&key_data)
            .map_err(|_| OrchestratorError::Credential("stored signing key is invalid".into()))?;
        let actual_key_id = derive_key_id(signer.public());
        if actual_key_id != key_id {
            return Err(OrchestratorError::Credential(
                "clean-chat signer does not match requested key ID".into(),
            ));
        }
        let signature = signer
            .sign(transcript)
            .map_err(|_| OrchestratorError::Credential("clean-chat signer failed".into()))?;
        Ok(Some(CleanChatSigningAuthority {
            public_key: signer.public().to_vec(),
            signature,
            device_id,
            auth_generation,
        }))
    }

    async fn delete_signing_key(&self, user_did: &str) -> Result<()> {
        self.update_atomically(|data| {
            data.remove(&Self::key(user_did, "signing_key"));
            Ok(())
        })
    }

    async fn store_mls_did(&self, user_did: &str, mls_did: &str) -> Result<()> {
        match self.get_admitted_device_tuple(user_did)? {
            Some(tuple) if tuple.mls_did == mls_did => Ok(()),
            Some(_) => Err(OrchestratorError::Credential(
                "orchestrator attempted to replace the admitted MLS identity".into(),
            )),
            None => Err(OrchestratorError::Credential(
                "MLS identity must be installed with the complete admitted device tuple".into(),
            )),
        }
    }

    async fn get_mls_did(&self, user_did: &str) -> Result<Option<String>> {
        Ok(self
            .get_admitted_device_tuple(user_did)?
            .map(|tuple| tuple.mls_did))
    }

    async fn store_device_uuid(&self, user_did: &str, uuid: &str) -> Result<()> {
        match self.get_admitted_device_tuple(user_did)? {
            Some(tuple) if tuple.device_uuid == uuid => Ok(()),
            Some(_) => Err(OrchestratorError::Credential(
                "orchestrator attempted to replace the admitted device UUID".into(),
            )),
            None => Err(OrchestratorError::Credential(
                "device UUID must be installed with the complete admitted device tuple".into(),
            )),
        }
    }

    async fn get_device_uuid(&self, user_did: &str) -> Result<Option<String>> {
        Ok(self
            .get_admitted_device_tuple(user_did)?
            .map(|tuple| tuple.device_uuid))
    }

    async fn get_auth_generation(&self, user_did: &str) -> Result<Option<i64>> {
        Ok(self
            .get_admitted_device_tuple(user_did)?
            .map(|tuple| tuple.auth_generation))
    }

    async fn has_credentials(&self, user_did: &str) -> Result<bool> {
        Ok(self.get_admitted_device_tuple(user_did)?.is_some())
    }

    async fn clear_all(&self, user_did: &str) -> Result<()> {
        self.update_atomically(|data| {
            let prefix = format!("{}/", user_did);
            data.retain(|k, _| !k.starts_with(&prefix));
            Ok(())
        })
    }
}

fn validate_admitted_tuple(
    user_did: &str,
    device_uuid: &str,
    mls_did: &str,
    auth_generation: i64,
) -> Result<()> {
    validate_device_uuid(device_uuid)?;
    if mls_did != format!("{user_did}#{device_uuid}") || auth_generation < 1 {
        return Err(OrchestratorError::Credential(
            "admitted device tuple is not canonical".into(),
        ));
    }
    Ok(())
}

fn validate_pending_enrollment(
    user_did: &str,
    device_uuid: &str,
    mls_did: &str,
    idempotency_key: &str,
) -> Result<()> {
    validate_device_uuid(device_uuid)?;
    if mls_did != format!("{user_did}#{device_uuid}") {
        return Err(OrchestratorError::Credential(
            "pending MLS identity is not device scoped".into(),
        ));
    }
    validate_device_uuid(idempotency_key).map_err(|_| {
        OrchestratorError::Credential("pending enrollment idempotency key is invalid".into())
    })
}

fn validate_device_uuid(device_uuid: &str) -> Result<()> {
    let device = uuid::Uuid::parse_str(device_uuid)
        .map_err(|_| OrchestratorError::Credential("admitted device UUID is invalid".into()))?;
    if device.get_version() != Some(uuid::Version::Random)
        || device.get_variant() != uuid::Variant::RFC4122
        || device.to_string() != device_uuid
    {
        return Err(OrchestratorError::Credential(
            "admitted device tuple is not canonical".into(),
        ));
    }
    Ok(())
}

fn pending_enrollment_from_data(
    data: &HashMap<String, String>,
    user_did: &str,
) -> Result<Option<PendingEnrollment>> {
    let required = [
        "pending_device_uuid",
        "pending_mls_did",
        "pending_enrollment_idempotency",
    ];
    let present = required
        .iter()
        .filter(|field| data.contains_key(&FileCredentialStore::key(user_did, field)))
        .count();
    let body = data.get(&FileCredentialStore::key(
        user_did,
        "pending_enrollment_prepared_body",
    ));
    if present == 0 && body.is_none() {
        return Ok(None);
    }
    if present != required.len() {
        return Err(OrchestratorError::Credential(
            "pending enrollment state is incomplete".into(),
        ));
    }
    let device_uuid = data
        .get(&FileCredentialStore::key(user_did, "pending_device_uuid"))
        .expect("presence counted above")
        .clone();
    let mls_did = data
        .get(&FileCredentialStore::key(user_did, "pending_mls_did"))
        .expect("presence counted above")
        .clone();
    let idempotency_key = data
        .get(&FileCredentialStore::key(
            user_did,
            "pending_enrollment_idempotency",
        ))
        .expect("presence counted above")
        .clone();
    validate_pending_enrollment(user_did, &device_uuid, &mls_did, &idempotency_key)?;
    let prepared_body = body
        .map(|encoded| {
            B64.decode(encoded).map_err(|error| {
                OrchestratorError::Credential(format!(
                    "pending enrollment prepared bytes are invalid: {error}"
                ))
            })
        })
        .transpose()?;
    if let Some(prepared_body) = prepared_body.as_deref() {
        let request: catbird_atproto::blue_catbird::chat::enroll_device::EnrollDevice<String> =
            serde_json::from_slice(prepared_body).map_err(|error| {
                OrchestratorError::Credential(format!(
                    "pending enrollment prepared request is invalid: {error}"
                ))
            })?;
        if request.signed_request.body.actor_did.as_str() != user_did
            || request.signed_request.body.device_id.as_str() != device_uuid
            || request.signed_request.body.idempotency_key.as_str() != idempotency_key
            || request.signed_request.body.expected_auth_generation != 0
        {
            return Err(OrchestratorError::Credential(
                "pending enrollment prepared request escaped its durable binding".into(),
            ));
        }
    }
    Ok(Some(PendingEnrollment {
        device_uuid,
        mls_did,
        idempotency_key,
        prepared_body,
    }))
}

fn remove_pending_enrollment(data: &mut HashMap<String, String>, user_did: &str) {
    for field in [
        "pending_device_uuid",
        "pending_mls_did",
        "pending_enrollment_idempotency",
        "pending_enrollment_prepared_body",
    ] {
        data.remove(&FileCredentialStore::key(user_did, field));
    }
}

const MAX_AUTHORITY_RESPONSE_BYTES: usize = 1024 * 1024;

pub(crate) fn validate_bare_did(did: &str) -> Result<()> {
    if did.len() < 12
        || did.len() > 261
        || did.contains('#')
        || did.contains('?')
        || did.contains(' ')
        || did.contains('\t')
        || did.contains('\r')
        || did.contains('\n')
    {
        return Err(OrchestratorError::Credential("invalid DID format".into()));
    }
    if let Some(host) = did.strip_prefix("did:web:") {
        if host.contains(':') || host.contains('/') || host.contains('%') {
            return Err(OrchestratorError::Credential(
                "did:web must be hostname only (no port, path, or percent encoding)".into(),
            ));
        }
        let labels: Vec<&str> = host.split('.').collect();
        if labels.len() < 2 {
            return Err(OrchestratorError::Credential(
                "did:web requires at least two domain labels".into(),
            ));
        }
        for label in &labels {
            if label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
            {
                return Err(OrchestratorError::Credential(
                    "invalid domain label in did:web".into(),
                ));
            }
            if !label
                .bytes()
                .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-'))
            {
                return Err(OrchestratorError::Credential(
                    "invalid character in did:web (lowercase alphanumeric and hyphen only)".into(),
                ));
            }
        }
        let tld = labels.last().unwrap();
        if !tld.starts_with(|c: char| c.is_ascii_alphabetic())
            || *tld == "localhost"
            || *tld == "local"
        {
            return Err(OrchestratorError::Credential(
                "invalid TLD in did:web".into(),
            ));
        }
    } else if let Some(plc) = did.strip_prefix("did:plc:") {
        if plc.len() != 24 || !plc.bytes().all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7')) {
            return Err(OrchestratorError::Credential(
                "invalid did:plc format (must be 24 base32 chars [a-z2-7])".into(),
            ));
        }
    } else {
        return Err(OrchestratorError::Credential(
            "unsupported DID method (only did:web and did:plc are supported)".into(),
        ));
    }
    Ok(())
}

pub(crate) fn did_document_url(did: &str) -> Result<Url> {
    validate_bare_did(did)?;
    let raw = if let Some(host) = did.strip_prefix("did:web:") {
        format!("https://{host}/.well-known/did.json")
    } else if did.starts_with("did:plc:") {
        format!("https://plc.directory/{did}")
    } else {
        return Err(OrchestratorError::Credential("unsupported DID method".into()));
    };
    Url::parse(&raw).map_err(|e| OrchestratorError::Credential(format!("invalid DID document URL: {e}")))
}

pub(crate) fn validate_safe_https_endpoint(url: &Url) -> Result<()> {
    if url.scheme() != "https" {
        return Err(OrchestratorError::Credential("endpoint must use HTTPS".into()));
    }
    let Some(host) = url.host_str() else {
        return Err(OrchestratorError::Credential("endpoint must have a host".into()));
    };
    if host.is_empty() {
        return Err(OrchestratorError::Credential("endpoint host is empty".into()));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(OrchestratorError::Credential("endpoint credentials forbidden".into()));
    }
    if url.fragment().is_some() {
        return Err(OrchestratorError::Credential("endpoint fragment forbidden".into()));
    }
    let host_lower = host.to_ascii_lowercase();
    if host_lower == "localhost"
        || host_lower.ends_with(".localhost")
        || host_lower.ends_with(".local")
        || host_lower == "127.0.0.1"
        || host_lower == "::1"
        || host_lower.starts_with("127.")
        || host_lower.parse::<std::net::IpAddr>().is_ok()
    {
        return Err(OrchestratorError::Credential(
            "endpoint must be a public domain name".into(),
        ));
    }
    Ok(())
}

pub(crate) fn parse_did_document_pds_endpoint(expected_did: &str, bytes: &[u8]) -> Result<Url> {
    let doc: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|e| OrchestratorError::Credential(format!("parse DID document: {e}")))?;
    let doc_id = doc
        .get("id")
        .and_then(|id| id.as_str())
        .ok_or_else(|| OrchestratorError::Credential("DID document missing id".into()))?;
    if doc_id != expected_did {
        return Err(OrchestratorError::Credential(
            "DID document id does not match expected DID".into(),
        ));
    }
    let services = doc
        .get("service")
        .and_then(|s| s.as_array())
        .ok_or_else(|| OrchestratorError::Credential("DID document missing service array".into()))?;

    let short_id = "#atproto_pds";
    let full_id = format!("{expected_did}#atproto_pds");
    let mut found = None;

    for service in services {
        let service_obj = match service.as_object() {
            Some(obj) => obj,
            None => continue,
        };
        let id = match service_obj.get("id").and_then(|v| v.as_str()) {
            Some(id) => id,
            None => continue,
        };
        if id != short_id && id != full_id.as_str() {
            continue;
        }
        let service_type = service_obj.get("type").and_then(|v| v.as_str());
        if service_type != Some("AtprotoPersonalDataServer") {
            return Err(OrchestratorError::Credential(
                "PDS service type must be AtprotoPersonalDataServer".into(),
            ));
        }
        let endpoint_str = service_obj
            .get("serviceEndpoint")
            .and_then(|v| v.as_str())
            .ok_or_else(|| OrchestratorError::Credential("PDS service missing serviceEndpoint".into()))?;

        let endpoint_url = Url::parse(endpoint_str)
            .map_err(|e| OrchestratorError::Credential(format!("invalid PDS endpoint URL: {e}")))?;
        validate_safe_https_endpoint(&endpoint_url)?;
        if endpoint_url.query().is_some() {
            return Err(OrchestratorError::Credential(
                "PDS endpoint query forbidden".into(),
            ));
        }

        if found.is_some() {
            return Err(OrchestratorError::Credential(
                "ambiguous PDS services in DID document".into(),
            ));
        }
        found = Some(endpoint_url);
    }

    found.ok_or_else(|| {
        OrchestratorError::Credential(
            "DID document has no authoritative AtprotoPersonalDataServer service".into(),
        )
    })
}

pub(crate) fn declaration_record_url(pds: &Url, user_did: &str) -> Result<Url> {
    let mut url = pds.clone();
    let base_path = url.path().trim_end_matches('/');
    url.set_path(&format!("{base_path}/xrpc/com.atproto.repo.getRecord"));
    url.set_query(Some(&format!(
        "repo={user_did}&collection=blue.catbird.chat.declaration&rkey=self"
    )));
    Ok(url)
}

pub(crate) fn parse_chat_declaration_response(
    user_did: &str,
    status: u16,
    bytes: &[u8],
) -> Result<Option<String>> {
    validate_bare_did(user_did)?;
    if status == 200 {
        let root: serde_json::Value = serde_json::from_slice(bytes)
            .map_err(|e| OrchestratorError::Credential(format!("parse declaration response: {e}")))?;
        let expected_uri = format!("at://{user_did}/blue.catbird.chat.declaration/self");
        let uri = root
            .get("uri")
            .and_then(|v| v.as_str())
            .ok_or_else(|| OrchestratorError::Credential("declaration response missing uri".into()))?;
        if uri != expected_uri {
            return Err(OrchestratorError::Credential(
                "declaration record uri does not match expected uri".into(),
            ));
        }
        let value = root
            .get("value")
            .and_then(|v| v.as_object())
            .ok_or_else(|| OrchestratorError::Credential("declaration response missing value".into()))?;
        let record_type = value
            .get("$type")
            .and_then(|v| v.as_str())
            .ok_or_else(|| OrchestratorError::Credential("declaration record missing $type".into()))?;
        if record_type != "blue.catbird.chat.declaration" {
            return Err(OrchestratorError::Credential(
                "declaration record $type mismatch".into(),
            ));
        }
        let delivery_service = value
            .get("deliveryService")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                OrchestratorError::Credential("declaration record missing deliveryService".into())
            })?;
        validate_bare_did(delivery_service)?;
        return Ok(Some(delivery_service.to_owned()));
    }

    if status == 400 || status == 404 {
        if let Ok(err_val) = serde_json::from_slice::<serde_json::Value>(bytes) {
            if err_val.get("error").and_then(|v| v.as_str()) == Some("RecordNotFound") {
                return Ok(None);
            }
        }
        return Err(OrchestratorError::Credential(format!(
            "chat declaration getRecord rejected with status {status}"
        )));
    }

    Err(OrchestratorError::Credential(format!(
        "chat declaration getRecord failed with status {status}"
    )))
}

async fn read_bounded_body(mut response: reqwest::Response, max_bytes: usize) -> Result<Vec<u8>> {
    if response.content_length().is_some_and(|len| len > max_bytes as u64) {
        return Err(OrchestratorError::Credential(format!(
            "response exceeds limit of {max_bytes} bytes"
        )));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| OrchestratorError::Credential(format!("read response chunk failed: {e}")))?
    {
        if bytes.len().saturating_add(chunk.len()) > max_bytes {
            return Err(OrchestratorError::Credential(format!(
                "response exceeds limit of {max_bytes} bytes"
            )));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use openmls_traits::types::SignatureScheme;

    const DID: &str = "did:plc:alicefixtureaaaaaaaaaaaa";
    const DEVICE: &str = "70707070-7070-4070-b070-707070707070";
    const IDEMPOTENCY: &str = "60606060-6060-4060-a060-606060606060";

    fn temporary_store(test_name: &str) -> (PathBuf, FileCredentialStore) {
        let directory = std::env::temp_dir().join(format!(
            "bird-credential-{test_name}-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("credentials.json");
        (directory, FileCredentialStore::new(path).unwrap())
    }

    #[tokio::test]
    async fn admitted_tuple_is_the_single_source_for_orchestrator_identity() {
        let (directory, store) = temporary_store("admitted-tuple");
        let scoped_did = format!("{DID}#{DEVICE}");

        store
            .install_admitted_device_tuple(DID, DEVICE, &scoped_did, 7)
            .unwrap();

        let tuple = store.get_admitted_device_tuple(DID).unwrap().unwrap();
        assert_eq!(tuple.device_uuid, DEVICE);
        assert_eq!(tuple.mls_did, scoped_did);
        assert_eq!(tuple.auth_generation, 7);
        assert_eq!(
            store.get_device_uuid(DID).await.unwrap().as_deref(),
            Some(DEVICE)
        );
        assert_eq!(
            store.get_mls_did(DID).await.unwrap().as_deref(),
            Some(format!("{DID}#{DEVICE}").as_str())
        );
        assert_eq!(store.get_auth_generation(DID).await.unwrap(), Some(7));
        assert!(store.has_credentials(DID).await.unwrap());

        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn admitted_tuple_rejects_bare_or_mismatched_mls_identity() {
        let (directory, store) = temporary_store("reject-bare");

        assert!(store
            .install_admitted_device_tuple(DID, DEVICE, DID, 7)
            .is_err());
        assert!(store
            .install_admitted_device_tuple(
                DID,
                DEVICE,
                &format!("{DID}#80808080-8080-4080-b080-808080808080"),
                7,
            )
            .is_err());
        assert!(store.get_admitted_device_tuple(DID).unwrap().is_none());

        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test]
    async fn pending_enrollment_never_becomes_orchestrator_authority() {
        let (directory, store) = temporary_store("pending-is-not-admitted");
        store
            .begin_pending_enrollment(DID, DEVICE, &format!("{DID}#{DEVICE}"), IDEMPOTENCY)
            .unwrap();

        assert!(store.get_admitted_device_tuple(DID).unwrap().is_none());
        assert_eq!(store.get_device_uuid(DID).await.unwrap(), None);
        assert_eq!(store.get_mls_did(DID).await.unwrap(), None);
        assert!(!store.has_credentials(DID).await.unwrap());

        let scoped_did = format!("{DID}#{DEVICE}");
        store
            .install_admitted_device_tuple(DID, DEVICE, &scoped_did, 3)
            .unwrap();
        assert_eq!(
            store.get_admitted_device_tuple(DID).unwrap().unwrap(),
            AdmittedDeviceTuple {
                device_uuid: DEVICE.into(),
                mls_did: scoped_did,
                auth_generation: 3,
            }
        );

        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test]
    async fn legacy_setters_cannot_drift_an_admitted_tuple() {
        let (directory, store) = temporary_store("legacy-setter-drift");
        let scoped_did = format!("{DID}#{DEVICE}");
        store
            .install_admitted_device_tuple(DID, DEVICE, &scoped_did, 4)
            .unwrap();

        store.store_mls_did(DID, &scoped_did).await.unwrap();
        store.store_device_uuid(DID, DEVICE).await.unwrap();
        assert!(store.store_mls_did(DID, DID).await.is_err());
        assert!(store
            .store_device_uuid(DID, "80808080-8080-4080-b080-808080808080")
            .await
            .is_err());

        let tuple = store.get_admitted_device_tuple(DID).unwrap().unwrap();
        assert_eq!(tuple.mls_did, scoped_did);
        assert_eq!(tuple.device_uuid, DEVICE);
        assert_eq!(tuple.auth_generation, 4);

        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test]
    async fn transcript_signing_rejects_a_key_id_from_another_identity() {
        let (directory, store) = temporary_store("signer-key-id");
        let signer = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();
        store
            .store_signing_key(DID, &serde_json::to_vec(&signer).unwrap())
            .await
            .unwrap();
        store
            .begin_pending_enrollment(DID, DEVICE, &format!("{DID}#{DEVICE}"), IDEMPOTENCY)
            .unwrap();

        let correct_key_id = derive_key_id(signer.public());
        let authority = store
            .sign_clean_chat_transcript(DID, b"enrollment transcript", &correct_key_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(authority.device_id, DEVICE);
        assert_eq!(authority.auth_generation, None);
        assert!(store
            .sign_clean_chat_transcript(DID, b"enrollment transcript", "wrong-key-id")
            .await
            .is_err());

        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn malformed_existing_credentials_fail_closed_without_overwriting_authority() {
        let directory = std::env::temp_dir().join(format!(
            "bird-credential-malformed-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("credentials.json");
        let malformed = b"{not valid admitted authority";
        std::fs::write(&path, malformed).unwrap();

        assert!(FileCredentialStore::new(path.clone()).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), malformed);

        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn bare_did_validation_strictly_enforces_syntax() {
        assert!(validate_bare_did("did:web:chat.catbird.blue").is_ok());
        assert!(validate_bare_did("did:web:alice.example.com").is_ok());
        assert!(validate_bare_did("did:plc:alicefixtureaaaaaaaaaaaa").is_ok());

        // Rejections
        assert!(validate_bare_did("did:web:127.0.0.1").is_err());
        assert!(validate_bare_did("did:web:localhost").is_err());
        assert!(validate_bare_did("did:web:api.localhost").is_err());
        assert!(validate_bare_did("did:web:chat.catbird.blue:443").is_err());
        assert!(validate_bare_did("did:web:chat.catbird.blue/path").is_err());
        assert!(validate_bare_did("did:web:Chat.catbird.blue").is_err());
        assert!(validate_bare_did("did:web:chat%2ecatbird.blue").is_err());
        assert!(validate_bare_did("did:key:z6Mku").is_err());
        assert!(validate_bare_did("did:plc:short").is_err());
        assert!(validate_bare_did("did:plc:contains0digit00000000").is_err());
        assert!(validate_bare_did("").is_err());
        assert!(validate_bare_did("did:web:foo").is_err());
    }

    #[test]
    fn did_document_url_construction_and_safety_checks() {
        let web_url = did_document_url("did:web:chat.catbird.blue").unwrap();
        assert_eq!(web_url.as_str(), "https://chat.catbird.blue/.well-known/did.json");
        assert!(validate_safe_https_endpoint(&web_url).is_ok());

        let plc_url = did_document_url("did:plc:alicefixtureaaaaaaaaaaaa").unwrap();
        assert_eq!(
            plc_url.as_str(),
            "https://plc.directory/did:plc:alicefixtureaaaaaaaaaaaa"
        );
        assert!(validate_safe_https_endpoint(&plc_url).is_ok());

        // Unsafe endpoints
        assert!(validate_safe_https_endpoint(&Url::parse("http://chat.catbird.blue/.well-known/did.json").unwrap()).is_err());
        assert!(validate_safe_https_endpoint(&Url::parse("https://user:pass@chat.catbird.blue/").unwrap()).is_err());
        assert!(validate_safe_https_endpoint(&Url::parse("https://127.0.0.1/").unwrap()).is_err());
        assert!(validate_safe_https_endpoint(&Url::parse("https://localhost/").unwrap()).is_err());
        assert!(validate_safe_https_endpoint(&Url::parse("https://chat.catbird.blue/#fragment").unwrap()).is_err());
    }

    #[test]
    fn did_document_pds_endpoint_resolution_and_validation() {
        let valid_doc = serde_json::json!({
            "id": DID,
            "service": [
                {
                    "id": "#atproto_pds",
                    "type": "AtprotoPersonalDataServer",
                    "serviceEndpoint": "https://pds.example.com"
                }
            ]
        });
        let endpoint = parse_did_document_pds_endpoint(DID, &serde_json::to_vec(&valid_doc).unwrap()).unwrap();
        assert_eq!(endpoint.as_str(), "https://pds.example.com/");

        // Full ID format
        let full_id_doc = serde_json::json!({
            "id": DID,
            "service": [
                {
                    "id": format!("{DID}#atproto_pds"),
                    "type": "AtprotoPersonalDataServer",
                    "serviceEndpoint": "https://pds.example.com"
                }
            ]
        });
        assert!(parse_did_document_pds_endpoint(DID, &serde_json::to_vec(&full_id_doc).unwrap()).is_ok());

        // Mismatched doc ID
        let mismatch_doc = serde_json::json!({
            "id": "did:plc:otheraaaaaaaaaaaaaaaaaa",
            "service": [
                {
                    "id": "#atproto_pds",
                    "type": "AtprotoPersonalDataServer",
                    "serviceEndpoint": "https://pds.example.com"
                }
            ]
        });
        assert!(parse_did_document_pds_endpoint(DID, &serde_json::to_vec(&mismatch_doc).unwrap()).is_err());

        // Ambiguous services
        let ambiguous_doc = serde_json::json!({
            "id": DID,
            "service": [
                {
                    "id": "#atproto_pds",
                    "type": "AtprotoPersonalDataServer",
                    "serviceEndpoint": "https://pds1.example.com"
                },
                {
                    "id": format!("{DID}#atproto_pds"),
                    "type": "AtprotoPersonalDataServer",
                    "serviceEndpoint": "https://pds2.example.com"
                }
            ]
        });
        assert!(parse_did_document_pds_endpoint(DID, &serde_json::to_vec(&ambiguous_doc).unwrap()).is_err());

        // Wrong service type
        let wrong_type_doc = serde_json::json!({
            "id": DID,
            "service": [
                {
                    "id": "#atproto_pds",
                    "type": "OtherServiceType",
                    "serviceEndpoint": "https://pds.example.com"
                }
            ]
        });
        assert!(parse_did_document_pds_endpoint(DID, &serde_json::to_vec(&wrong_type_doc).unwrap()).is_err());

        // Non-HTTPS PDS endpoint
        let insecure_doc = serde_json::json!({
            "id": DID,
            "service": [
                {
                    "id": "#atproto_pds",
                    "type": "AtprotoPersonalDataServer",
                    "serviceEndpoint": "http://pds.example.com"
                }
            ]
        });
        assert!(parse_did_document_pds_endpoint(DID, &serde_json::to_vec(&insecure_doc).unwrap()).is_err());
    }

    #[test]
    fn chat_declaration_response_parsing_and_fail_closed_semantics() {
        let valid_record = serde_json::json!({
            "uri": format!("at://{DID}/blue.catbird.chat.declaration/self"),
            "cid": "bafyreie5cvv4h45feadgeuwhbcutmh6t2ceseocmxhdoo6uhnqqstx54re",
            "value": {
                "$type": "blue.catbird.chat.declaration",
                "allowIncoming": "all",
                "deliveryService": "did:web:chat.catbird.blue",
                "protocolVersion": "1",
                "createdAt": "2026-09-19T00:00:00Z"
            }
        });
        let res = parse_chat_declaration_response(DID, 200, &serde_json::to_vec(&valid_record).unwrap()).unwrap();
        assert_eq!(res.as_deref(), Some("did:web:chat.catbird.blue"));

        // RecordNotFound on 404 => Ok(None)
        let not_found = serde_json::json!({"error": "RecordNotFound", "message": "Record not found"});
        assert_eq!(
            parse_chat_declaration_response(DID, 404, &serde_json::to_vec(&not_found).unwrap()).unwrap(),
            None
        );

        // RecordNotFound on 400 => Ok(None)
        assert_eq!(
            parse_chat_declaration_response(DID, 400, &serde_json::to_vec(&not_found).unwrap()).unwrap(),
            None
        );

        // InvalidRequest on 400 => Err (fail closed!)
        let invalid_req = serde_json::json!({"error": "InvalidRequest", "message": "Repo not found"});
        assert!(parse_chat_declaration_response(DID, 400, &serde_json::to_vec(&invalid_req).unwrap()).is_err());

        // 500 error => Err (fail closed!)
        let server_err = serde_json::json!({"error": "InternalServerError"});
        assert!(parse_chat_declaration_response(DID, 500, &serde_json::to_vec(&server_err).unwrap()).is_err());

        // 200 with mismatched URI => Err
        let mismatched_uri = serde_json::json!({
            "uri": "at://did:plc:other/blue.catbird.chat.declaration/self",
            "value": {
                "$type": "blue.catbird.chat.declaration",
                "deliveryService": "did:web:chat.catbird.blue"
            }
        });
        assert!(parse_chat_declaration_response(DID, 200, &serde_json::to_vec(&mismatched_uri).unwrap()).is_err());

        // 200 with mismatched $type => Err
        let mismatched_type = serde_json::json!({
            "uri": format!("at://{DID}/blue.catbird.chat.declaration/self"),
            "value": {
                "$type": "chat.bsky.actor.declaration",
                "deliveryService": "did:web:chat.catbird.blue"
            }
        });
        assert!(parse_chat_declaration_response(DID, 200, &serde_json::to_vec(&mismatched_type).unwrap()).is_err());

        // 200 with invalid deliveryService DID => Err
        let invalid_service = serde_json::json!({
            "uri": format!("at://{DID}/blue.catbird.chat.declaration/self"),
            "value": {
                "$type": "blue.catbird.chat.declaration",
                "deliveryService": "did:web:127.0.0.1"
            }
        });
        assert!(parse_chat_declaration_response(DID, 200, &serde_json::to_vec(&invalid_service).unwrap()).is_err());
    }

    #[tokio::test]
    async fn authority_resolver_methods_fail_closed_on_invalid_syntax_without_network() {
        let (directory, store) = temporary_store("authority-fail-closed");

        // direct_request_receipt_authority_document with invalid DID
        assert!(store.direct_request_receipt_authority_document("did:web:127.0.0.1").await.is_err());
        assert!(store.direct_request_receipt_authority_document("did:web:localhost").await.is_err());
        assert!(store.direct_request_receipt_authority_document("did:other:unsupported").await.is_err());

        // get_chat_declaration_authority with invalid DID
        assert!(store.get_chat_declaration_authority("did:web:127.0.0.1").await.is_err());
        assert!(store.get_chat_declaration_authority("not-a-did").await.is_err());
        assert!(store.get_chat_declaration_authority("did:key:unsupported").await.is_err());

        let _ = std::fs::remove_dir_all(directory);
    }
}
