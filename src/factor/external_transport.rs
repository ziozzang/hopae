//! Fixed, authenticated HTTPS factor verification. Parsed evidence cannot issue a
//! session: durable challenge/proof consumption and owner elevation remain required.
use super::external::{Decision, Expected};
use crate::{
    auth_gateway::breaker::Circuit,
    crypto::{Clock, Secret},
    provider::oidc::http::{EndpointPolicy, Fetcher},
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{io::Read, path::PathBuf, sync::Arc, time::Duration};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub factor: String,
    pub configuration_revision: u64,
    pub url: String,
    pub verifier_key_env: String,
    pub timeout_ms: u64,
    #[serde(default)]
    pub allow_private_endpoints: bool,
    #[serde(default)]
    pub ca: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub eligibility_lua: Option<String>,
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        if let Some(source) = &self.eligibility_lua {
            crate::auth_gateway::lua::Policy::compile(source)
                .map_err(|_| anyhow::anyhow!("invalid external factor eligibility script"))?;
        }
        let url = url::Url::parse(&self.url)?;
        ensure!(
            url.scheme() == "https"
                && url.query().is_none()
                && EndpointPolicy::new(&self.url, &[], self.allow_private_endpoints).url_ok(&url),
            "unsafe external factor verifier endpoint"
        );
        ensure!(
            !self.factor.is_empty()
                && self.factor.len() <= 128
                && self
                    .factor
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
                && self.configuration_revision != 0
                && self.configuration_revision <= i64::MAX as u64
                && (1..=1000).contains(&self.timeout_ms),
            "invalid external factor binding or deadline"
        );
        ensure!(
            !self.verifier_key_env.is_empty()
                && self.verifier_key_env.len() <= 128
                && self
                    .verifier_key_env
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_')
                && self.ca.as_ref().is_none_or(|path| path.is_absolute()),
            "invalid external factor credential or CA reference"
        );
        Ok(())
    }
}

/// No transport error includes a URL, secret, proof or response body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidContext,
    Unavailable,
}

/// A transport-authenticated receipt; only this connector can create one.
/// Owner storage must check all bindings and consume its proof exactly once.
/// It cannot be serialized or cloned and grants no session authority by itself.
pub struct VerifiedProof {
    pub(crate) authority: Authority,
    pub(crate) challenge: String,
    pub(crate) user: String,
    pub(crate) session: String,
    pub(crate) service: String,
    pub(crate) credential_generation: u64,
    pub(crate) proof: crate::crypto::Digest,
    pub(crate) verified_at: crate::crypto::Timestamp,
    pub(crate) expires_at: crate::crypto::Timestamp,
    pub(crate) deadline: std::time::Instant,
}
impl std::fmt::Debug for VerifiedProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VerifiedProof(<redacted>)")
    }
}
#[derive(Clone)]
pub(crate) struct Authority {
    pub(crate) factor: String,
    pub(crate) revision: u64,
    pub(crate) binding: [u8; 32],
}
#[derive(Debug)]
pub enum Verification {
    Rejected,
    Verified(Box<VerifiedProof>),
}

pub struct Connector {
    factor: String,
    revision: u64,
    binding: [u8; 32],
    url: url::Url,
    key: reqwest::header::HeaderValue,
    timeout: Duration,
    fetcher: Fetcher,
    capacity: tokio::sync::Semaphore,
    circuit: Arc<Circuit>,
    eligibility: Option<crate::auth_gateway::lua::Policy>,
}

impl Connector {
    pub fn compile(config: &Config, env: &dyn Fn(&str) -> Option<String>) -> Result<Self> {
        config.validate()?;
        let material =
            zeroize::Zeroizing::new(env(&config.verifier_key_env).ok_or_else(|| {
                anyhow::anyhow!("external factor verifier credential unavailable")
            })?);
        ensure!(
            (32..=1024).contains(&material.len()) && material.bytes().all(|b| b.is_ascii_graphic()),
            "invalid external factor verifier credential"
        );
        let mut key = reqwest::header::HeaderValue::from_str(&material)?;
        key.set_sensitive(true);
        let mut fingerprint = Sha256::new();
        fingerprint.update(serde_json::to_vec(config)?);
        fingerprint.update(Sha256::digest(material.as_bytes()));
        let mut roots = Vec::new();
        if let Some(path) = &config.ca {
            let before_open = std::fs::metadata(path)?;
            ensure!(
                before_open.is_file() && before_open.len() <= 1024 * 1024,
                "invalid factor CA file"
            );
            let mut file = std::fs::File::open(path)?;
            let metadata = file.metadata()?;
            ensure!(
                metadata.is_file() && metadata.len() <= 1024 * 1024,
                "invalid factor CA file"
            );
            let mut bytes = Vec::new();
            (&mut file).take(1024 * 1024 + 1).read_to_end(&mut bytes)?;
            ensure!(bytes.len() <= 1024 * 1024, "factor CA file exceeds limit");
            fingerprint.update(Sha256::digest(&bytes));
            let certs = rustls_pemfile::certs(&mut bytes.as_slice())
                .collect::<std::io::Result<Vec<_>>>()?;
            ensure!(
                (1..=64).contains(&certs.len()),
                "invalid factor CA certificate count"
            );
            for cert in certs {
                roots.push(reqwest::Certificate::from_der(cert.as_ref())?);
            }
        }
        let timeout = Duration::from_millis(config.timeout_ms);
        let fetcher = Fetcher::for_verifier(config.allow_private_endpoints, timeout, roots)
            .map_err(|_| anyhow::anyhow!("external factor HTTPS client initialization failed"))?;
        Ok(Self {
            factor: config.factor.clone(),
            revision: config.configuration_revision,
            binding: fingerprint.finalize().into(),
            url: url::Url::parse(&config.url)?,
            key,
            timeout,
            fetcher,
            capacity: tokio::sync::Semaphore::new(64),
            circuit: Circuit::new(3, 30_000).expect("constant circuit bounds"),
            eligibility: config
                .eligibility_lua
                .as_deref()
                .map(crate::auth_gateway::lua::Policy::compile)
                .transpose()
                .map_err(|_| anyhow::anyhow!("invalid external factor eligibility script"))?,
        })
    }

    /// Compare immutable publication bindings, including resolved secret and CA.
    /// Retain the same connector only while this binding remains unchanged.
    pub fn same_binding(&self, other: &Self) -> bool {
        self.binding == other.binding
    }

    pub(crate) fn authority(&self) -> Authority {
        Authority {
            factor: self.factor.clone(),
            revision: self.revision,
            binding: self.binding,
        }
    }

    /// `expected` is prepared by the owner, never decoded from browser assertions.
    /// No cache, retry, weaker-provider fallback, or assurance assignment occurs here.
    pub async fn verify(
        &self,
        expected: &Expected<'_>,
        response: &Secret,
        clock: &dyn Clock,
    ) -> Result<Verification, Error> {
        let now = clock.now();
        if expected.factor != self.factor
            || expected.configuration_revision != self.revision
            || expected.started_at > now
            || expected.challenge_expires_at <= now
            || now > expected.started_at.add(Duration::from_secs(5))
            || response.expose().is_empty()
            || response.expose().len() > 4096
            || [
                expected.challenge,
                expected.user,
                expected.session,
                expected.service,
            ]
            .iter()
            .any(|value| !super::external::bounded_identifier(value))
        {
            return Err(Error::InvalidContext);
        }
        let _permit = self
            .capacity
            .try_acquire()
            .map_err(|_| Error::Unavailable)?;
        if let Some(policy) = &self.eligibility {
            match policy.permits(crate::auth_gateway::lua::Context {
                service: expected.service,
                connector: expected.factor,
                subject: expected.user,
            }) {
                Ok(true) => {}
                Ok(false) => return Ok(Verification::Rejected),
                Err(_) => return Err(Error::Unavailable),
            }
        }
        let lease = self.circuit.admit().ok_or(Error::Unavailable)?;
        let started = std::time::Instant::now();
        let result = tokio::time::timeout(self.timeout, async {
            let request = self
                .fetcher
                .post(&self.url)
                .header("x-hopae-verifier-key", self.key.clone())
                .header(reqwest::header::ACCEPT, "application/json")
                .json(&serde_json::json!({
                    "challenge":expected.challenge, "user":expected.user,
                    "session":expected.session, "service":expected.service,
                    "factor":expected.factor,
                    "configuration_revision":expected.configuration_revision,
                    "credential_generation":expected.credential_generation,
                    "challenge_expires_at":expected.challenge_expires_at,
                    "verification_started_at":expected.started_at,
                    "response":response.expose()
                }));
            let reply = self
                .fetcher
                .send_bounded(request, 8192)
                .await
                .map_err(|_| Error::Unavailable)?;
            // Even rejection must bind the exact context. A bare HTTP denial
            // cannot masquerade as a successfully authenticated factor response.
            if reply.status != 200
                || !reply.content_type.as_deref().is_some_and(|v| {
                    v.split(';')
                        .next()
                        .is_some_and(|v| v.trim() == "application/json")
                })
            {
                return Err(Error::Unavailable);
            }
            let received = clock.now();
            let received_instant = std::time::Instant::now();
            if received < now {
                return Err(Error::Unavailable);
            }
            // Include time since the owner prepared this exchange context.
            let elapsed = now
                .since(expected.started_at)
                .saturating_add(started.elapsed());
            match super::external::validate(&reply.body, expected, received, elapsed)
                .map_err(|_| Error::Unavailable)?
            {
                Decision::Rejected => Ok(Verification::Rejected),
                Decision::Verified(evidence) => {
                    let expiry_deadline = received_instant
                        .checked_add(evidence.expires_at().since(received))
                        .ok_or(Error::Unavailable)?;
                    let exchange_deadline = started
                        .checked_add(
                            Duration::from_secs(5).saturating_sub(now.since(expected.started_at)),
                        )
                        .ok_or(Error::Unavailable)?;
                    let deadline = expiry_deadline.min(exchange_deadline);
                    if deadline <= std::time::Instant::now() {
                        return Err(Error::Unavailable);
                    }
                    Ok(Verification::Verified(Box::new(VerifiedProof {
                        authority: self.authority(),
                        challenge: expected.challenge.to_owned(),
                        user: expected.user.to_owned(),
                        session: expected.session.to_owned(),
                        service: expected.service.to_owned(),
                        credential_generation: expected.credential_generation,
                        proof: crate::crypto::sha256(evidence.proof_id().as_bytes()),
                        verified_at: received,
                        expires_at: evidence.expires_at(),
                        deadline,
                    })))
                }
            }
        })
        .await
        .unwrap_or(Err(Error::Unavailable));
        lease.finish(result.is_err());
        result
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::crypto::{SystemClock, Timestamp};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    pub(crate) struct Fixture {
        directory: tempfile::TempDir,
        url: String,
        server: tokio::task::JoinHandle<()>,
        calls: Arc<AtomicUsize>,
        connections: Arc<AtomicUsize>,
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            self.server.abort();
        }
    }
    impl Fixture {
        async fn new() -> Self {
            Self::with_clock(Arc::new(SystemClock)).await
        }
        pub(crate) async fn with_clock(clock: Arc<dyn Clock>) -> Self {
            let directory = tempfile::tempdir().unwrap();
            let run = |args: &[&str]| {
                let output = std::process::Command::new("openssl")
                    .current_dir(directory.path())
                    .args(args)
                    .output()
                    .unwrap();
                assert!(
                    output.status.success(),
                    "owned TLS fixture generation failed"
                );
            };
            run(&[
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "1",
                "-subj",
                "/CN=Owned factor test CA",
                "-keyout",
                "ca.key",
                "-out",
                "ca.pem",
                "-addext",
                "basicConstraints=critical,CA:TRUE",
            ]);
            run(&[
                "req",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-subj",
                "/CN=localhost",
                "-keyout",
                "server.key",
                "-out",
                "server.csr",
            ]);
            std::fs::write(directory.path().join("extensions"),
                "basicConstraints=critical,CA:FALSE\nsubjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n").unwrap();
            run(&[
                "x509",
                "-req",
                "-in",
                "server.csr",
                "-CA",
                "ca.pem",
                "-CAkey",
                "ca.key",
                "-CAcreateserial",
                "-days",
                "1",
                "-extfile",
                "extensions",
                "-out",
                "server.pem",
            ]);
            let cert = std::fs::read(directory.path().join("server.pem")).unwrap();
            let key = std::fs::read(directory.path().join("server.key")).unwrap();
            let certs = rustls_pemfile::certs(&mut cert.as_slice())
                .collect::<std::io::Result<Vec<_>>>()
                .unwrap();
            let key = rustls_pemfile::private_key(&mut key.as_slice())
                .unwrap()
                .unwrap();
            let config = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .unwrap();
            let tls = tokio_rustls::TlsAcceptor::from(Arc::new(config));
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let calls = Arc::new(AtomicUsize::new(0));
            let connections = Arc::new(AtomicUsize::new(0));
            let count = calls.clone();
            let connected = connections.clone();
            let server = tokio::spawn(async move {
                while let Ok((socket, _)) = listener.accept().await {
                    connected.fetch_add(1, Ordering::SeqCst);
                    let tls = tls.clone();
                    let count = count.clone();
                    let clock = clock.clone();
                    tokio::spawn(async move {
                        let Ok(mut socket) = tls.accept(socket).await else {
                            return;
                        };
                        let mut buffer = Vec::new();
                        loop {
                            let header_end = loop {
                                if let Some(at) = buffer.windows(4).position(|v| v == b"\r\n\r\n") {
                                    break at + 4;
                                }
                                let mut chunk = [0; 4096];
                                let Ok(n) = socket.read(&mut chunk).await else {
                                    return;
                                };
                                if n == 0 || buffer.len() + n > 16_384 {
                                    return;
                                }
                                buffer.extend_from_slice(&chunk[..n]);
                            };
                            let header = String::from_utf8(buffer[..header_end].to_vec()).unwrap();
                            assert!(header.starts_with("POST /verify HTTP/1.1\r\n"));
                            assert!(header.to_ascii_lowercase().contains(
                                "x-hopae-verifier-key: owned-factor-verifier-key-at-least-thirty-two\r\n"));
                            let length: usize = header
                                .lines()
                                .find_map(|line| {
                                    line.to_ascii_lowercase()
                                        .strip_prefix("content-length: ")
                                        .and_then(|v| v.parse().ok())
                                })
                                .unwrap();
                            while buffer.len() < header_end + length {
                                let mut chunk = [0; 4096];
                                let Ok(n) = socket.read(&mut chunk).await else {
                                    return;
                                };
                                if n == 0 {
                                    return;
                                }
                                buffer.extend_from_slice(&chunk[..n]);
                            }
                            let request: serde_json::Value =
                                serde_json::from_slice(&buffer[header_end..header_end + length])
                                    .unwrap();
                            buffer.drain(..header_end + length);
                            count.fetch_add(1, Ordering::SeqCst);
                            let action = request["response"].as_str().unwrap();
                            if action == "slow" {
                                tokio::time::sleep(Duration::from_secs(2)).await;
                            }
                            let mut reply = request.clone();
                            reply.as_object_mut().unwrap().remove("response");
                            reply
                                .as_object_mut()
                                .unwrap()
                                .remove("challenge_expires_at");
                            reply
                                .as_object_mut()
                                .unwrap()
                                .remove("verification_started_at");
                            reply["active"] = (action != "reject").into();
                            reply["proof_id"] = "owned-proof".into();
                            reply["expires_at"] = clock.now().add(Duration::from_secs(1)).0.into();
                            match action {
                                "cross" => reply["user"] = "other-user".into(),
                                "role" => reply["aal"] = 2.into(),
                                "large" | "large-chunked" => {
                                    reply["padding"] = "x".repeat(8193).into()
                                }
                                _ => {}
                            }
                            let body = if action == "malformed" {
                                b"{".to_vec()
                            } else {
                                serde_json::to_vec(&reply).unwrap()
                            };
                            let status = if action == "redirect" {
                                "302 Found"
                            } else if action == "http-denial" {
                                "401 Unauthorized"
                            } else {
                                "200 OK"
                            };
                            let content_type = if action == "wrong-type" {
                                "text/plain"
                            } else {
                                "application/json"
                            };
                            if action == "large-header-stall" || action == "body-stall" {
                                let length = if action == "body-stall" { 1 } else { 9000 };
                                let headers = format!(
                                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {length}\r\n\r\n"
                                );
                                if socket.write_all(headers.as_bytes()).await.is_err()
                                    || socket.flush().await.is_err()
                                {
                                    return;
                                }
                                tokio::time::sleep(Duration::from_secs(2)).await;
                                return;
                            }
                            if action == "large-chunked" {
                                let headers = format!(
                                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ntransfer-encoding: chunked\r\n\r\n{:x}\r\n",
                                    body.len()
                                );
                                if socket.write_all(headers.as_bytes()).await.is_err()
                                    || socket.write_all(&body).await.is_err()
                                    || socket.write_all(b"\r\n").await.is_err()
                                    || socket.flush().await.is_err()
                                {
                                    return;
                                }
                                tokio::time::sleep(Duration::from_secs(2)).await;
                                return;
                            }
                            let headers = format!(
                                "HTTP/1.1 {status}\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\nlocation: /verify\r\n\r\n",
                                body.len()
                            );
                            if socket.write_all(headers.as_bytes()).await.is_err()
                                || socket.write_all(&body).await.is_err()
                            {
                                return;
                            }
                        }
                    });
                }
            });
            Self {
                directory,
                url: format!("https://{address}/verify"),
                server,
                calls,
                connections,
            }
        }
        fn config(&self) -> Config {
            Config {
                factor: "partner-push".into(),
                configuration_revision: 7,
                url: self.url.clone(),
                verifier_key_env: "OWNED_FACTOR_KEY".into(),
                timeout_ms: 500,
                allow_private_endpoints: true,
                ca: Some(self.directory.path().join("ca.pem")),
                eligibility_lua: None,
            }
        }
        pub(crate) fn connector(&self) -> Connector {
            Connector::compile(&self.config(), &|_| {
                Some("owned-factor-verifier-key-at-least-thirty-two".into())
            })
            .unwrap()
        }
    }
    fn expected() -> Expected<'static> {
        let now = SystemClock.now();
        Expected {
            challenge: "owned-challenge",
            user: "owned-user",
            session: "owned-session",
            service: "orders",
            factor: "partner-push",
            configuration_revision: 7,
            credential_generation: 3,
            started_at: now,
            challenge_expires_at: now.add(Duration::from_secs(5)),
        }
    }
    async fn call(connector: &Connector, action: &str) -> Result<Verification, Error> {
        connector
            .verify(&expected(), &Secret::new(action.to_owned()), &SystemClock)
            .await
    }
    #[tokio::test]
    async fn lua_eligibility_cannot_replace_native_verification() {
        let fixture = Fixture::new().await;
        for source in [
            "return false",
            "while true do end",
            "return 'true'",
            "return os.getenv('SECRET')",
        ] {
            let mut config = fixture.config();
            config.eligibility_lua = Some(source.into());
            let connector = Connector::compile(&config, &|_| Some("a".repeat(32))).unwrap();
            let result = call(&connector, "accept").await;
            if source == "return false" {
                assert!(matches!(result, Ok(Verification::Rejected)));
            } else {
                assert_eq!(result.unwrap_err(), Error::Unavailable);
            }
            assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
        }
        let mut config = fixture.config();
        config.eligibility_lua = Some("return context.service == 'orders'".into());
        let connector = Connector::compile(&config, &|_| {
            Some("owned-factor-verifier-key-at-least-thirty-two".into())
        })
        .unwrap();
        assert!(matches!(
            call(&connector, "reject").await,
            Ok(Verification::Rejected)
        ));
        assert_eq!(
            call(&connector, "role").await.unwrap_err(),
            Error::Unavailable
        );
        assert!(matches!(
            call(&connector, "accept").await,
            Ok(Verification::Verified(_))
        ));
        assert_eq!(fixture.calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn owned_https_binds_evidence_pools_connections_and_denial_is_healthy() {
        let fixture = Fixture::new().await;
        let connector = fixture.connector();
        for _ in 0..5 {
            let Verification::Verified(proof) = call(&connector, "accept").await.unwrap() else {
                panic!("expected proof")
            };
            assert_eq!(proof.proof, crate::crypto::sha256(b"owned-proof"));
            assert!(matches!(
                call(&connector, "reject").await,
                Ok(Verification::Rejected)
            ));
        }
        assert_eq!(fixture.calls.load(Ordering::SeqCst), 10);
        assert_eq!(fixture.connections.load(Ordering::SeqCst), 1);
        assert_eq!(
            connector.circuit.state(),
            Some(crate::auth_gateway::breaker::State::Closed)
        );
        for action in [
            "cross",
            "role",
            "malformed",
            "large",
            "redirect",
            "http-denial",
            "wrong-type",
        ] {
            let connector = fixture.connector();
            assert_eq!(
                call(&connector, action).await.unwrap_err(),
                Error::Unavailable,
                "{action}"
            );
        }
        // Redirect rejection did not issue a second verifier request.
        assert_eq!(fixture.calls.load(Ordering::SeqCst), 17);
        assert!(connector.same_binding(&fixture.connector()));
        let ca = fixture.directory.path().join("ca.pem");
        let mut bytes = std::fs::read(&ca).unwrap();
        bytes.push(b'\n');
        std::fs::write(ca, bytes).unwrap();
        assert!(!connector.same_binding(&fixture.connector()));
    }
    #[tokio::test]
    async fn owned_https_wrong_ca_context_admission_deadline_and_cancellation_fail_closed() {
        let fixture = Fixture::new().await;
        let mut config = fixture.config();
        config.ca = None;
        let untrusted = Connector::compile(&config, &|_| {
            Some("owned-factor-verifier-key-at-least-thirty-two".into())
        })
        .unwrap();
        assert_eq!(
            call(&untrusted, "accept").await.unwrap_err(),
            Error::Unavailable
        );
        assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
        let connector = fixture.connector();
        let mut context = expected();
        context.user = "bad\nuser";
        assert_eq!(
            connector
                .verify(&context, &Secret::new("accept".into()), &SystemClock)
                .await
                .unwrap_err(),
            Error::InvalidContext
        );
        context = expected();
        context.configuration_revision += 1;
        assert_eq!(
            connector
                .verify(&context, &Secret::new("accept".into()), &SystemClock)
                .await
                .unwrap_err(),
            Error::InvalidContext
        );
        context = expected();
        context.started_at = Timestamp(0);
        assert_eq!(
            connector
                .verify(&context, &Secret::new("accept".into()), &SystemClock)
                .await
                .unwrap_err(),
            Error::InvalidContext
        );
        let permits = connector.capacity.try_acquire_many(64).unwrap();
        assert_eq!(
            call(&connector, "accept").await.unwrap_err(),
            Error::Unavailable
        );
        drop(permits);
        assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
        for _ in 0..3 {
            assert!(
                tokio::time::timeout(Duration::from_millis(100), call(&connector, "slow"))
                    .await
                    .is_err()
            );
        }
        assert_eq!(
            connector.circuit.state(),
            Some(crate::auth_gateway::breaker::State::Open)
        );
        let before = fixture.calls.load(Ordering::SeqCst);
        assert_eq!(
            call(&connector, "accept").await.unwrap_err(),
            Error::Unavailable
        );
        assert_eq!(fixture.calls.load(Ordering::SeqCst), before);
        let connector = fixture.connector();
        let started = std::time::Instant::now();
        assert_eq!(
            call(&connector, "slow").await.unwrap_err(),
            Error::Unavailable
        );
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(connector.capacity.available_permits(), 64);
        for action in ["large-header-stall", "large-chunked"] {
            let connector = fixture.connector();
            let started = std::time::Instant::now();
            assert_eq!(
                call(&connector, action).await.unwrap_err(),
                Error::Unavailable
            );
            assert!(started.elapsed() < Duration::from_millis(400), "{action}");
        }
        let connector = fixture.connector();
        assert_eq!(
            call(&connector, "body-stall").await.unwrap_err(),
            Error::Unavailable
        );
        let mut recovering = fixture.connector();
        recovering.circuit = Circuit::new(1, 100).unwrap();
        assert_eq!(
            call(&recovering, "malformed").await.unwrap_err(),
            Error::Unavailable
        );
        assert_eq!(
            call(&recovering, "accept").await.unwrap_err(),
            Error::Unavailable
        );
        tokio::time::sleep(Duration::from_millis(110)).await;
        assert!(matches!(
            call(&recovering, "reject").await,
            Ok(Verification::Rejected)
        ));
        assert_eq!(
            recovering.circuit.state(),
            Some(crate::auth_gateway::breaker::State::Closed)
        );
    }
    #[tokio::test]
    async fn response_clock_rollback_is_refused_even_inside_challenge_lifetime() {
        struct Rollback(std::sync::atomic::AtomicI64);
        impl Clock for Rollback {
            fn now(&self) -> Timestamp {
                Timestamp(self.0.fetch_sub(1, Ordering::SeqCst))
            }
        }
        let fixture = Fixture::new().await;
        let now = SystemClock.now();
        let clock = Rollback(std::sync::atomic::AtomicI64::new(now.0));
        let mut context = expected();
        context.started_at = now.sub(Duration::from_millis(10));
        let result = fixture
            .connector()
            .verify(&context, &Secret::new("accept".into()), &clock)
            .await;
        assert_eq!(result.unwrap_err(), Error::Unavailable);
    }
    #[test]
    fn verifier_configuration_requires_https_and_compilation_fences_resolved_secret_and_ca() {
        let base = Config {
            factor: "partner-push".into(),
            configuration_revision: 7,
            url: "https://verifier.example.test/check".into(),
            verifier_key_env: "OWNED_FACTOR_KEY".into(),
            timeout_ms: 100,
            allow_private_endpoints: false,
            ca: None,
            eligibility_lua: None,
        };
        let first = Connector::compile(&base, &|_| Some("a".repeat(32))).unwrap();
        assert!(first.same_binding(&Connector::compile(&base, &|_| Some("a".repeat(32))).unwrap()));
        assert!(
            !first.same_binding(&Connector::compile(&base, &|_| Some("b".repeat(32))).unwrap())
        );
        for url in [
            "http://127.0.0.1/check",
            "https://user@verifier.example.test/check",
            "https://verifier.example.test/check?secret=x",
            "https://verifier.example.test/check#fragment",
        ] {
            let mut config = base.clone();
            config.url = url.into();
            config.allow_private_endpoints = true;
            assert!(config.validate().is_err());
        }
        assert!(Connector::compile(&base, &|_| None).is_err());
    }
}
