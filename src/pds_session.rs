use std::sync::Arc;

use catbird_mls::orchestrator::error::{OrchestratorError, Result};
use petrel::account::AccountManager;
use petrel::auth::{LegacyPasswordStrategy, PasswordLoginResult};
use petrel::identity::{HickoryResolver, IdentityResolver};
use petrel::net::{RedirectPolicy, ReqwestTransport, SharedTransport};
use petrel::oauth::OAuthIdentityAdapter;
use petrel::storage::{MemorySecretStore, SessionStore};
use petrel::xrpc::{AuthError, CallOptions, Error, XrpcBody, XrpcClient};
use petrel_core::Did;
use url::Url;

/// The bot signs in on startup. PDS bearer tokens are confined to this
/// in-memory provider; chat requests authenticate separately via Nest.
pub struct PdsSession {
    accounts: Arc<AccountManager>,
    strategy: Arc<LegacyPasswordStrategy>,
    transport: SharedTransport,
    requests: tokio::sync::Mutex<()>,
}

impl PdsSession {
    pub fn new() -> anyhow::Result<Self> {
        let transport = Arc::new(ReqwestTransport::new()?);
        let identity = IdentityResolver::new(
            transport.clone(),
            HickoryResolver::system()?,
            Default::default(),
        );
        let accounts = Arc::new(AccountManager::new(SessionStore::new(
            Arc::new(MemorySecretStore::new()),
            "birdaemon",
        )?));
        let strategy = Arc::new(LegacyPasswordStrategy::new(
            accounts.clone(),
            transport.clone(),
            Arc::new(OAuthIdentityAdapter::new(identity)),
            Url::parse("https://bsky.social")?,
        ));
        Ok(Self {
            accounts,
            strategy,
            transport,
            requests: Default::default(),
        })
    }

    pub async fn login(
        &self,
        identifier: &str,
        password: &str,
    ) -> anyhow::Result<PasswordLoginResult> {
        Ok(self
            .strategy
            .login_with_password(identifier, password, None)
            .await?)
    }

    pub async fn exchange(
        &self,
        endpoint: &str,
        did: &str,
        password: &str,
        method: reqwest::Method,
        nsid: &str,
        query: &[(&str, &str)],
        body: Option<XrpcBody>,
    ) -> Result<serde_json::Value> {
        let _guard = self.requests.lock().await;
        let credential_error =
            |error: &dyn std::fmt::Display| OrchestratorError::Credential(error.to_string());
        let did = Did::parse(did).map_err(|e| credential_error(&e))?;
        let base = Url::parse(endpoint).map_err(|e| credential_error(&e))?;
        let client = XrpcClient::new(base.clone(), self.transport.clone())
            .map_err(|e| credential_error(&e))?
            .with_auth_provider(Arc::new(self.strategy.clone()));
        let options = CallOptions {
            redirects: RedirectPolicy::Never,
            ..Default::default()
        };
        for attempt in 0..2 {
            let account = self
                .accounts
                .get_current_account()
                .await
                .map_err(|e| credential_error(&e))?;
            if !account
                .is_some_and(|a| a.did == did && a.pds == base.origin().ascii_serialization())
            {
                return Err(OrchestratorError::Credential(
                    "PDS account binding changed; restart required".into(),
                ));
            }
            match client
                .exchange(
                    method.clone(),
                    nsid,
                    query.iter().copied(),
                    body.clone(),
                    &options,
                )
                .await
            {
                Ok(response) if response.status().is_success() => {
                    return serde_json::from_slice(response.body())
                        .map_err(|e| OrchestratorError::Serialization(e.to_string()));
                }
                Ok(response) => {
                    return Err(OrchestratorError::ServerError {
                        status: response.status().as_u16(),
                        body: String::from_utf8_lossy(response.body()).into_owned(),
                    })
                }
                Err(Error::Auth(AuthError::SessionExpired(_) | AuthError::NoSession))
                    if attempt == 0 =>
                {
                    self.login(did.as_str(), password)
                        .await
                        .map_err(|e| credential_error(&e))?;
                }
                Err(e) => return Err(OrchestratorError::Api(e.to_string())),
            }
        }
        Err(OrchestratorError::Credential(
            "PDS re-authentication failed".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http::{Request, Response};
    use petrel::net::{HttpTransport, SendOptions, TransportError};
    use petrel::oauth::{OAuthIdentity, OAuthIdentityError, OAuthIdentityResolver};
    use petrel::rt::BoxFuture;
    use petrel_core::AtIdentifier;
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const ENDPOINT: &str = "https://bird-pds.test";
    const DID: &str = "did:plc:birdfixture";
    const HANDLE: &str = "bird.test";

    struct LocalPds(AtomicUsize);

    impl OAuthIdentityResolver for LocalPds {
        fn resolve_identity<'a>(
            &'a self,
            id: &'a AtIdentifier,
            _: bool,
        ) -> BoxFuture<'a, std::result::Result<OAuthIdentity, OAuthIdentityError>> {
            Box::pin(async move {
                assert!(matches!(id.as_str(), HANDLE | DID));
                Ok(OAuthIdentity {
                    did: DID.parse().unwrap(),
                    handle: Some(HANDLE.parse().unwrap()),
                    pds: ENDPOINT.parse().unwrap(),
                })
            })
        }
    }

    impl HttpTransport for LocalPds {
        async fn send(
            &self,
            request: Request<Bytes>,
            _: &SendOptions,
        ) -> std::result::Result<Response<Bytes>, TransportError> {
            assert_eq!(request.uri().host(), Some("bird-pds.test"));
            let path = request.uri().path().rsplit('.').next().unwrap();
            let auth = request
                .headers()
                .get("authorization")
                .map(|value| value.to_str().unwrap());
            let number = self.0.fetch_add(1, Ordering::SeqCst);
            let (status, body) = match (number, path, auth) {
                (0 | 4, "createSession", None) => {
                    let input: serde_json::Value = serde_json::from_slice(request.body()).unwrap();
                    assert_eq!(input["identifier"], HANDLE);
                    assert_eq!(input["password"], "test-password");
                    (
                        200,
                        json!({"did":DID, "handle":HANDLE, "accessJwt":"initial", "refreshJwt":"refresh"}),
                    )
                }
                (1, "listRecords", Some("Bearer initial")) => {
                    (401, json!({"error":"ExpiredToken"}))
                }
                (2, "refreshSession", Some("Bearer refresh")) => (
                    200,
                    json!({"did":DID, "handle":HANDLE, "accessJwt":"renewed", "refreshJwt":"next"}),
                ),
                (3, "listRecords", Some("Bearer renewed")) => (200, json!({"records":[]})),
                other => panic!("unexpected call {} {}", other.0, other.1),
            };
            Ok(Response::builder()
                .status(status)
                .header("content-type", "application/json")
                .body(Bytes::from(serde_json::to_vec(&body).unwrap()))
                .unwrap())
        }
    }

    fn session(pds: Arc<LocalPds>) -> PdsSession {
        let accounts = Arc::new(AccountManager::new(
            SessionStore::new(Arc::new(MemorySecretStore::new()), "birdaemon").unwrap(),
        ));
        let strategy = Arc::new(LegacyPasswordStrategy::new(
            accounts.clone(),
            pds.clone(),
            pds.clone(),
            ENDPOINT.parse().unwrap(),
        ));
        PdsSession {
            accounts,
            strategy,
            transport: pds,
            requests: Default::default(),
        }
    }

    #[tokio::test]
    async fn app_password_session_renews_retries_and_signs_in_after_restart() {
        let pds = Arc::new(LocalPds(AtomicUsize::new(0)));
        let first = session(pds.clone());
        let login = first.login(HANDLE, "test-password").await.unwrap();
        assert_eq!(login.did.as_str(), DID);
        let reply = first
            .exchange(
                ENDPOINT,
                DID,
                "test-password",
                reqwest::Method::GET,
                "com.atproto.repo.listRecords",
                &[("repo", DID)],
                None,
            )
            .await
            .unwrap();
        assert_eq!(reply, json!({"records":[]}));
        assert!(first
            .exchange(
                "https://elsewhere.test",
                DID,
                "test-password",
                reqwest::Method::GET,
                "com.atproto.repo.listRecords",
                &[],
                None
            )
            .await
            .is_err());
        drop(first);
        session(pds.clone())
            .login(HANDLE, "test-password")
            .await
            .unwrap();
        assert_eq!(pds.0.load(Ordering::SeqCst), 5);
    }
}
