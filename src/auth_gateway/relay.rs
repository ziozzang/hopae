//! Fixed verifier endpoints. Client credentials are never logged or reflected.
use super::{PrincipalKind, Subject, VerifiedEvidence, runtime::Error};
use crate::provider::oidc::http::{EndpointPolicy, Fetcher};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{sync::Arc, time::Duration};
struct Circuit {
    started: std::time::Instant,
    state: std::sync::Mutex<super::breaker::Breaker>,
}
impl Circuit {
    fn now(&self) -> u64 {
        self.started.elapsed().as_millis().min(u64::MAX as u128) as u64
    }
    fn admit(self: &Arc<Self>) -> Result<Lease, Error> {
        let permit = self
            .state
            .lock()
            .map_err(|_| Error::Unavailable)?
            .admit(self.now())
            .ok_or(Error::Unavailable)?;
        Ok(Lease {
            circuit: self.clone(),
            permit: Some(permit),
        })
    }
}
struct Lease {
    circuit: Arc<Circuit>,
    permit: Option<super::breaker::Permit>,
}
impl Lease {
    fn finish(mut self, failed: bool) {
        self.record(failed);
    }
    fn record(&mut self, failed: bool) {
        if let Some(permit) = self.permit.take()
            && let Ok(mut circuit) = self.circuit.state.lock()
        {
            if failed {
                circuit.backend_failure(permit, self.circuit.now());
            } else {
                circuit.healthy(permit);
            }
        }
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        self.record(true);
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub url: String,
    pub issuer: String,
    #[serde(default = "deadline")]
    pub timeout_ms: u64,
    #[serde(default)]
    pub allow_private_endpoints: bool,
    #[serde(default)]
    pub verifier_key_env: Option<String>,
}
fn deadline() -> u64 {
    100
}
impl Config {
    pub fn validate(&self) -> Result<()> {
        let url = url::Url::parse(&self.url)?;
        ensure!(
            EndpointPolicy::new(&self.url, &[], self.allow_private_endpoints).url_ok(&url)
                && url.query().is_none(),
            "unsafe API verifier URL"
        );
        ensure!(
            !self.issuer.is_empty()
                && self.issuer.len() <= 256
                && !self.issuer.chars().any(char::is_control),
            "invalid API verifier issuer namespace"
        );
        ensure!(
            (1..=1000).contains(&self.timeout_ms),
            "API verifier timeout must be 1..1000 ms"
        );
        ensure!(
            self.verifier_key_env.as_ref().is_none_or(|v| !v.is_empty()
                && v.len() <= 128
                && v.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')),
            "invalid verifier credential reference"
        );
        Ok(())
    }
}
pub struct Connector {
    url: url::Url,
    issuer: String,
    timeout: Duration,
    fetcher: Fetcher,
    key: Option<reqwest::header::HeaderValue>,
    capacity: Arc<tokio::sync::Semaphore>,
    circuit: Arc<Circuit>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Reply {
    active: bool,
    subject: Option<String>,
    service_id: Option<String>,
    expires_at: Option<u64>,
}
impl Connector {
    pub fn compile(config: &Config, env: &dyn Fn(&str) -> Option<String>) -> Result<Self> {
        config.validate()?;
        let key = if let Some(name) = &config.verifier_key_env {
            let value = env(name)
                .ok_or_else(|| anyhow::anyhow!("API verifier credential reference unavailable"))?;
            ensure!(
                (32..=1024).contains(&value.len()) && value.bytes().all(|b| b.is_ascii_graphic()),
                "invalid verifier credential material"
            );
            let mut value = reqwest::header::HeaderValue::from_str(&value)?;
            value.set_sensitive(true);
            Some(value)
        } else {
            None
        };
        Ok(Self {
            url: url::Url::parse(&config.url)?,
            issuer: config.issuer.clone(),
            timeout: Duration::from_millis(config.timeout_ms),
            fetcher: Fetcher::new(config.allow_private_endpoints),
            key,
            capacity: Arc::new(tokio::sync::Semaphore::new(64)),
            circuit: Arc::new(Circuit {
                started: std::time::Instant::now(),
                state: std::sync::Mutex::new(
                    super::breaker::Breaker::new(3, 30_000).expect("constant circuit bounds"),
                ),
            }),
        })
    }
    pub async fn authenticate(
        &self,
        service: &str,
        realm: &str,
        token: &str,
        ip: std::net::IpAddr,
        now: u64,
    ) -> Result<VerifiedEvidence, Error> {
        if !(16..=4096).contains(&token.len()) || !token.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(Error::Invalid);
        }
        let _permit = self
            .capacity
            .try_acquire()
            .map_err(|_| Error::Unavailable)?;
        let lease = self.circuit.admit()?;
        let result = self.exchange(service, realm, token, ip, now).await;
        lease.finish(matches!(result, Err(Error::Unavailable)));
        result
    }
    async fn exchange(
        &self,
        service: &str,
        realm: &str,
        token: &str,
        ip: std::net::IpAddr,
        now: u64,
    ) -> Result<VerifiedEvidence, Error> {
        let mut authorization = reqwest::header::HeaderValue::from_str(&format!("Bearer {token}"))
            .map_err(|_| Error::Invalid)?;
        authorization.set_sensitive(true);
        let mut request = self
            .fetcher
            .post(&self.url)
            .header(reqwest::header::AUTHORIZATION, authorization)
            .header(reqwest::header::ACCEPT, "application/json")
            .json(&serde_json::json!({"service_id":service,"client_ip":ip.to_string()}));
        if let Some(key) = &self.key {
            request = request.header("x-hopae-verifier-key", key.clone());
        }
        let started = std::time::Instant::now();
        let response = tokio::time::timeout(self.timeout, self.fetcher.send(request))
            .await
            .map_err(|_| Error::Unavailable)?
            .map_err(|_| Error::Unavailable)?;
        if response.status == 401 || response.status == 403 {
            return Err(Error::Invalid);
        }
        if response.status != 200 {
            return Err(Error::Unavailable);
        }
        if !response.content_type.as_deref().is_some_and(|v| {
            v.split(';')
                .next()
                .is_some_and(|v| v.trim() == "application/json")
        }) {
            return Err(Error::Unavailable);
        }
        let reply: Reply =
            serde_json::from_slice(&response.body).map_err(|_| Error::Unavailable)?;
        if !reply.active {
            return Err(Error::Invalid);
        }
        if reply.service_id.as_deref() != Some(service) {
            return Err(Error::Unavailable);
        }
        let subject = reply
            .subject
            .filter(|s| !s.is_empty() && s.len() <= 128 && !s.chars().any(char::is_control))
            .ok_or(Error::Unavailable)?;
        let now = now.saturating_add(started.elapsed().as_millis().min(u64::MAX as u128) as u64);
        let expires_at = reply
            .expires_at
            .filter(|t| *t > now && *t <= now.saturating_add(5000))
            .ok_or(Error::Unavailable)?;
        Ok(VerifiedEvidence {
            subject: Subject {
                issuer: self.issuer.clone(),
                realm: realm.to_owned(),
                subject,
                kind: PrincipalKind::Service,
            },
            connector: "api-relay".into(),
            service: Some(service.to_owned()),
            expires_at: expires_at.min(now.saturating_add(1000)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Json, Router,
        http::{HeaderMap, StatusCode},
        routing::post,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};
    #[tokio::test]
    async fn fixed_verifier_authenticates_scope_and_rejects_false_assurance() {
        let calls = Arc::new(AtomicUsize::new(0));
        let count = calls.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app=Router::new().route("/verify",post(move |headers:HeaderMap,Json(body):Json<serde_json::Value>|{let count=count.clone();async move{
            count.fetch_add(1,Ordering::Relaxed);assert_eq!(headers["x-hopae-verifier-key"],"owned-verifier-key-at-least-thirty-two-bytes");assert_eq!(body["service_id"],"orders");
            let token=headers[reqwest::header::AUTHORIZATION].to_str().unwrap();
            let now=std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64;
            let mut reply=serde_json::json!({"active":true,"subject":"partner-worker","service_id":"orders","expires_at":now+1000});
            if token.contains("wrong-scope"){reply["service_id"]=serde_json::json!("other");}
            if token.contains("expired"){reply["expires_at"]=serde_json::json!(now-1);}
            if token.contains("fake-mfa"){reply["aal"]=serde_json::json!(3);}
            if token.contains("denied"){return (StatusCode::UNAUTHORIZED,Json(serde_json::json!({"active":false})));}
            (StatusCode::OK,Json(reply))
        }}));
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let config = Config {
            url: format!("http://{address}/verify"),
            issuer: "https://partner.example.test".into(),
            timeout_ms: 500,
            allow_private_endpoints: true,
            verifier_key_env: Some("OWNED_VERIFIER".into()),
        };
        let connector = Connector::compile(&config, &|_| {
            Some("owned-verifier-key-at-least-thirty-two-bytes".into())
        })
        .unwrap();
        let now = || {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64
        };
        let ip = "192.0.2.8".parse().unwrap();
        let evidence = connector
            .authenticate(
                "orders",
                "partner",
                "valid-credential-at-least-sixteen-bytes",
                ip,
                now(),
            )
            .await
            .unwrap();
        assert_eq!(evidence.subject().kind, PrincipalKind::Service);
        assert_eq!(evidence.service(), Some("orders"));
        assert_eq!(
            connector
                .authenticate(
                    "orders",
                    "partner",
                    "denied-credential-at-least-sixteen",
                    ip,
                    now()
                )
                .await
                .unwrap_err(),
            Error::Invalid
        );
        for token in [
            "wrong-scope-credential-at-least-sixteen",
            "expired-credential-at-least-sixteen",
            "fake-mfa-credential-at-least-sixteen",
        ] {
            assert_eq!(
                connector
                    .authenticate("orders", "partner", token, ip, now())
                    .await
                    .unwrap_err(),
                Error::Unavailable
            );
        }
        assert_eq!(
            connector
                .authenticate(
                    "orders",
                    "partner",
                    "valid-credential-at-least-sixteen-bytes",
                    ip,
                    now()
                )
                .await
                .unwrap_err(),
            Error::Unavailable,
            "semantic failures must open the verifier circuit"
        );
        assert_eq!(calls.load(Ordering::Relaxed), 5);
        server.abort();
    }
    #[test]
    fn verifier_configuration_cannot_accept_redirect_queries_or_plaintext_remote() {
        for url in [
            "http://verifier.example.test/verify",
            "https://user:secret@verifier.example.test/verify",
            "https://verifier.example.test/verify?target=other",
        ] {
            assert!(
                Config {
                    url: url.into(),
                    issuer: "partner".into(),
                    timeout_ms: 100,
                    allow_private_endpoints: false,
                    verifier_key_env: None
                }
                .validate()
                .is_err()
            );
        }
    }
}
