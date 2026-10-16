//! **Deprecated fallback** (Hangang ADR 0022): Pod-bound workload
//! authentication through a fixed trusted Kubernetes TokenReview API plus
//! live ServiceAccount/Pod metadata GETs. Every uncached invocation contacts
//! the API server. The default connector is the offline
//! [`super::workload`] verifier; this one stays for clusters whose issuer
//! keys cannot be reached. An optional positive cache (at most 10 s) bounds
//! the API load. The principal is the ServiceAccount (`wk2:`), as for the
//! offline connector; the Pod-bound subject is available only inside an
//! explicit, expiring compatibility window.
use super::workload::{
    identity::{self, BoundRef, SubjectMode, Workload},
    signals::{Seen, Signal, Sink, WorkloadRef},
};
use super::{VerifiedEvidence, breaker::Circuit, runtime::Error};
use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, sync::Arc, time::Duration};
use zeroize::Zeroizing;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub api_origin: String,
    pub issuer: String,
    pub cluster_id: String,
    pub audience: String,
    pub namespaces: Vec<String>,
    pub timeout_ms: u64,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub connection: Config,
    pub ca_pem_env: String,
    pub reviewer_token_env: String,
    pub token_prefix: String,
    /// SPIFFE trust domain; when set, evidence carries the SPIFFE ID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_domain: Option<String>,
    /// `service_account` (default) or the deprecated `legacy_pod`.
    #[serde(default)]
    pub subject: SubjectMode,
    /// Required with `legacy_pod`: the end of the compatibility window.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legacy_until_ms: Option<u64>,
    /// Report legacy Pod subject → principal mappings until this instant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legacy_mapping_until_ms: Option<u64>,
    /// Positive result cache, 0 (default, off) to 10000 ms.
    #[serde(default)]
    pub cache_ttl_ms: u64,
}
impl Profile {
    pub fn validate(&self) -> Result<()> {
        self.connection.validate()?;
        for name in [&self.ca_pem_env, &self.reviewer_token_env] {
            ensure!(
                !name.is_empty()
                    && name.len() <= 128
                    && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'),
                "invalid Kubernetes material reference"
            );
        }
        let prefix = &self.token_prefix;
        ensure!(
            (2..=32).contains(&prefix.len())
                && prefix.ends_with(':')
                && prefix[..prefix.len() - 1]
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b)),
            "explicit Kubernetes credential prefix required"
        );
        ensure!(
            self.trust_domain
                .as_deref()
                .is_none_or(identity::trust_domain)
                && self.cache_ttl_ms <= 10_000
                && self
                    .legacy_mapping_until_ms
                    .is_none_or(|t| t > 0 && t <= i64::MAX as u64),
            "invalid Kubernetes TokenReview trust domain, cache or migration window"
        );
        match self.subject {
            SubjectMode::ServiceAccount => ensure!(
                self.legacy_until_ms.is_none(),
                "legacy_until_ms requires subject legacy_pod"
            ),
            SubjectMode::LegacyPod => ensure!(
                self.legacy_until_ms
                    .is_some_and(|t| t > 0 && t <= i64::MAX as u64),
                "subject legacy_pod is deprecated and requires legacy_until_ms"
            ),
        }
        Ok(())
    }
    pub fn compile(&self, env: &dyn Fn(&str) -> Option<String>) -> Result<Connector> {
        self.validate()?;
        let ca = env(&self.ca_pem_env)
            .ok_or_else(|| anyhow::anyhow!("Kubernetes CA reference unavailable"))?;
        let reviewer = Zeroizing::new(
            env(&self.reviewer_token_env)
                .ok_or_else(|| anyhow::anyhow!("Kubernetes reviewer reference unavailable"))?,
        );
        let mut connector = Connector::compile(&self.connection, ca.as_bytes(), reviewer)?;
        connector.identity = IdentityPolicy {
            trust_domain: self.trust_domain.clone(),
            subject: self.subject,
            legacy_until_ms: self.legacy_until_ms,
            legacy_mapping_until_ms: self.legacy_mapping_until_ms,
        };
        connector.cache = super::workload::cache::Cache::new(self.cache_ttl_ms, 10_000);
        let mut binding = Sha256::new();
        binding.update(connector.binding);
        binding.update(serde_json::to_vec(&connector.identity)?);
        binding.update(self.cache_ttl_ms.to_be_bytes());
        connector.binding = binding.finalize().into();
        tracing::warn!(
            cluster = %self.connection.cluster_id,
            "kubernetes_tokenreview is deprecated: prefer kubernetes_workload (offline JWKS verification)"
        );
        Ok(connector)
    }
}
/// How verified facts become the published subject.
#[derive(Clone, Debug, Default, Serialize)]
pub(crate) struct IdentityPolicy {
    trust_domain: Option<String>,
    subject: SubjectMode,
    legacy_until_ms: Option<u64>,
    legacy_mapping_until_ms: Option<u64>,
}
pub struct Connector {
    config: Config,
    binding: [u8; 32],
    client: reqwest::Client,
    endpoint: url::Url,
    authorization: reqwest::header::HeaderValue,
    capacity: tokio::sync::Semaphore,
    circuit: Arc<Circuit>,
    identity: IdentityPolicy,
    cache: super::workload::cache::Cache,
    sink: std::sync::Mutex<Option<Sink>>,
    observed: Seen,
    mapped: Seen,
}
#[derive(Deserialize)]
struct Claims {
    iss: String,
    sub: String,
    aud: Vec<String>,
    exp: u64,
    nbf: Option<u64>,
    #[serde(rename = "kubernetes.io")]
    kubernetes: PrivateClaims,
}
#[derive(Deserialize)]
struct PrivateClaims {
    namespace: String,
    serviceaccount: BoundObject,
    pod: BoundObject,
}
#[derive(Deserialize)]
struct BoundObject {
    name: String,
    uid: String,
}
#[derive(Deserialize)]
struct Reply {
    #[serde(rename = "apiVersion")]
    api_version: String,
    kind: String,
    status: Status,
}
#[derive(Deserialize)]
struct Status {
    #[serde(default)]
    authenticated: bool,
    #[serde(default)]
    audiences: Vec<String>,
    error: Option<String>,
    user: Option<User>,
}
#[derive(Deserialize)]
struct User {
    #[serde(default)]
    username: String,
    #[serde(default)]
    uid: String,
    #[serde(default)]
    extra: BTreeMap<String, Vec<String>>,
}
fn identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._".contains(&b))
}
fn namespace(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 63
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && s.as_bytes()[0].is_ascii_alphanumeric()
        && s.as_bytes()[s.len() - 1].is_ascii_alphanumeric()
}
impl Config {
    pub fn validate(&self) -> Result<()> {
        let url = url::Url::parse(&self.api_origin)?;
        ensure!(
            url.scheme() == "https"
                && url.host_str().is_some()
                && url.username().is_empty()
                && url.password().is_none()
                && url.path() == "/"
                && url.query().is_none()
                && url.fragment().is_none(),
            "Kubernetes API must be an HTTPS origin"
        );
        let issuer = url::Url::parse(&self.issuer)?;
        ensure!(
            issuer.scheme() == "https"
                && issuer.host_str().is_some()
                && issuer.username().is_empty()
                && issuer.password().is_none()
                && issuer.query().is_none()
                && issuer.fragment().is_none()
                && self.issuer.len() <= 256,
            "invalid Kubernetes issuer"
        );
        ensure!(
            (1..=128).contains(&self.namespaces.len())
                && self.namespaces.iter().all(|n| namespace(n))
                && self
                    .namespaces
                    .iter()
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
                    == self.namespaces.len()
                && identifier(&self.cluster_id)
                && !self.audience.is_empty()
                && self.audience.len() <= 256
                && !self.audience.chars().any(char::is_control)
                && (1..=1000).contains(&self.timeout_ms),
            "invalid Kubernetes authentication scope"
        );
        Ok(())
    }
}
impl Connector {
    pub(crate) fn status(&self) -> (&'static str, usize) {
        (
            self.circuit.status_name(),
            self.capacity.available_permits(),
        )
    }

    /// Material is supplied by the native owner; it never appears in serialized Config.
    pub fn compile(
        config: &Config,
        ca_pem: &[u8],
        reviewer_token: Zeroizing<String>,
    ) -> Result<Self> {
        config.validate()?;
        ensure!(
            !ca_pem.is_empty()
                && ca_pem.len() <= 65536
                && (16..=4096).contains(&reviewer_token.len())
                && reviewer_token.bytes().all(|b| b.is_ascii_graphic()),
            "invalid Kubernetes reviewer material"
        );
        let roots = reqwest::Certificate::from_pem_bundle(ca_pem)?;
        ensure!(
            !roots.is_empty() && roots.len() <= 16,
            "invalid Kubernetes CA bundle"
        );
        let mut builder = reqwest::Client::builder()
            .https_only(true)
            .tls_built_in_root_certs(false)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_millis(config.timeout_ms));
        for root in roots {
            builder = builder.add_root_certificate(root);
        }
        let client = builder.build()?;
        let mut authorization =
            reqwest::header::HeaderValue::from_str(&format!("Bearer {}", &*reviewer_token))?;
        authorization.set_sensitive(true);
        let mut binding = Sha256::new();
        binding.update(serde_json::to_vec(config)?);
        binding.update(Sha256::digest(ca_pem));
        binding.update(Sha256::digest(reviewer_token.as_bytes()));
        Ok(Self {
            binding: binding.finalize().into(),
            config: config.clone(),
            client,
            endpoint: url::Url::parse(&config.api_origin)?
                .join("apis/authentication.k8s.io/v1/tokenreviews")?,
            authorization,
            capacity: tokio::sync::Semaphore::new(64),
            circuit: Circuit::new(3, 30_000).expect("constant circuit bounds"),
            identity: IdentityPolicy::default(),
            cache: super::workload::cache::Cache::new(0, 0),
            sink: std::sync::Mutex::new(None),
            observed: Seen::new(65_536),
            mapped: Seen::new(65_536),
        })
    }
    pub(crate) fn attach(&self, sink: Sink) {
        *self.sink.lock().unwrap_or_else(|p| p.into_inner()) = Some(sink);
    }
    fn emit(&self, signal: Signal) {
        if let Some(sink) = self.sink.lock().unwrap_or_else(|p| p.into_inner()).as_ref() {
            sink.emit(signal);
        }
    }
    pub(crate) fn config(&self) -> &Config {
        &self.config
    }
    pub(crate) fn trust_domain(&self) -> Option<&str> {
        self.identity.trust_domain.as_deref()
    }
    pub(crate) fn same_binding(&self, other: &Self) -> bool {
        self.binding == other.binding
    }
    fn claims(&self, token: &str, now_ms: u64) -> Result<Claims, Error> {
        if !(32..=4096).contains(&token.len()) {
            return Err(Error::Invalid);
        }
        let mut parts = token.split('.');
        let header = parts.next().ok_or(Error::Invalid)?;
        let payload = parts.next().ok_or(Error::Invalid)?;
        let signature = parts
            .next()
            .filter(|s| !s.is_empty())
            .ok_or(Error::Invalid)?;
        if parts.next().is_some() || URL_SAFE_NO_PAD.decode(signature).is_err() {
            return Err(Error::Invalid);
        }
        let header: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header).map_err(|_| Error::Invalid)?)
                .map_err(|_| Error::Invalid)?;
        if !header["alg"].as_str().is_some_and(|s| {
            [
                "RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "EdDSA",
            ]
            .contains(&s)
        }) {
            return Err(Error::Invalid);
        }
        let bytes = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(payload)
                .map_err(|_| Error::Invalid)?,
        );
        let claims: Claims = serde_json::from_slice(&bytes).map_err(|_| Error::Invalid)?;
        let k = &claims.kubernetes;
        let expiry = claims.exp.checked_mul(1000).ok_or(Error::Invalid)?;
        if !self.config.namespaces.contains(&k.namespace)
            || claims.iss != self.config.issuer
            || !claims.aud.iter().any(|a| a == &self.config.audience)
            || claims.aud.len() > 16
            || expiry <= now_ms
            || claims
                .nbf
                .is_some_and(|t| t.checked_mul(1000).is_none_or(|t| t > now_ms))
            || ![
                &k.namespace,
                &k.serviceaccount.name,
                &k.serviceaccount.uid,
                &k.pod.name,
                &k.pod.uid,
            ]
            .iter()
            .all(|s| identifier(s))
            || claims.sub
                != format!(
                    "system:serviceaccount:{}:{}",
                    k.namespace, k.serviceaccount.name
                )
        {
            return Err(Error::Invalid);
        }
        // Parsing is only a refusal precheck. These claims are not evidence until TokenReview succeeds.
        Ok(claims)
    }
    pub async fn authenticate(
        &self,
        service: &str,
        token: &str,
        now_ms: u64,
    ) -> Result<VerifiedEvidence, Error> {
        if !identifier(service) {
            return Err(Error::Invalid);
        }
        if self.identity.subject == SubjectMode::LegacyPod
            && self.identity.legacy_until_ms.is_some_and(|t| now_ms >= t)
        {
            super::workload::metrics::authentication(
                service,
                "tokenreview",
                "denied",
                "legacy_window_expired",
            );
            return Err(Error::Unavailable);
        }
        let claims = self.claims(token, now_ms)?;
        let key: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        if let Some((workload, expires_ms)) = self.cache.get(&key, now_ms) {
            super::workload::metrics::cache(service, "hit");
            super::workload::metrics::authentication(
                service,
                "tokenreview",
                "authenticated",
                "cached",
            );
            return self.publish(service, &workload, expires_ms, now_ms);
        }
        let _permit = self
            .capacity
            .try_acquire()
            .map_err(|_| Error::Unavailable)?;
        let lease = self.circuit.admit().ok_or(Error::Unavailable)?;
        let result = self.exchange(service, token, claims, now_ms).await;
        lease.finish(matches!(result, Err(Error::Unavailable)));
        let reason = match &result {
            Ok(_) => "ok",
            Err(Error::Unavailable) => "source_unavailable",
            Err(Error::Expired) => "expired",
            Err(_) => "invalid",
        };
        super::workload::metrics::authentication(
            service,
            "tokenreview",
            if result.is_ok() {
                "authenticated"
            } else {
                "denied"
            },
            reason,
        );
        let (workload, expires_ms) = result?;
        if self.cache.enabled() {
            super::workload::metrics::cache(service, "miss");
            self.cache
                .insert(key, Arc::new(workload.clone()), expires_ms, now_ms);
        }
        self.publish(service, &workload, expires_ms, now_ms)
    }
    /// The published subject and attributes of verified facts.
    fn publish(
        &self,
        service: &str,
        workload: &Workload,
        expires_ms: u64,
        now_ms: u64,
    ) -> Result<VerifiedEvidence, Error> {
        let (subject, attributes) = workload
            .resolve(
                self.identity.trust_domain.as_deref(),
                self.identity.subject,
                "tokenreview",
            )
            .ok_or(Error::Invalid)?;
        let reference = WorkloadRef::of(service, &attributes);
        if self.observed.insert(&attributes.principal) {
            self.emit(Signal::Observed(reference.clone()));
        }
        if let Some(legacy) = &attributes.legacy_subject_ref
            && self
                .identity
                .legacy_mapping_until_ms
                .is_some_and(|until| now_ms < until)
            && self
                .mapped
                .insert(&format!("{legacy}>{}", attributes.principal))
        {
            self.emit(Signal::LegacyMapped {
                workload: reference,
                legacy_subject_ref: legacy.clone(),
            });
        }
        let expires_at = expires_ms.min(now_ms.checked_add(1000).ok_or(Error::Unavailable)?);
        if expires_at <= now_ms {
            return Err(Error::Expired);
        }
        Ok(VerifiedEvidence {
            subject,
            connector: "kubernetes-tokenreview".into(),
            expires_at,
            service: Some(service.to_owned()),
            workload: Some(Arc::new(attributes)),
        })
    }
    async fn exchange(
        &self,
        _service: &str,
        token: &str,
        claims: Claims,
        now_ms: u64,
    ) -> Result<(Workload, u64), Error> {
        let started = std::time::Instant::now();
        let future = async {
            let mut response = self.client.post(self.endpoint.clone()).header(reqwest::header::AUTHORIZATION,self.authorization.clone()).header(reqwest::header::ACCEPT,"application/json").json(&serde_json::json!({"apiVersion":"authentication.k8s.io/v1","kind":"TokenReview","spec":{"token":token,"audiences":[self.config.audience]}})).send().await.map_err(|_| Error::Unavailable)?;
            if ![200, 201].contains(&response.status().as_u16())
                || !response
                    .headers()
                    .get(reqwest::header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .is_some_and(|v| {
                        v.split(';')
                            .next()
                            .is_some_and(|v| v.trim() == "application/json")
                    })
            {
                return Err(Error::Unavailable);
            }
            let mut body = Zeroizing::new(Vec::new());
            while let Some(chunk) = response.chunk().await.map_err(|_| Error::Unavailable)? {
                if body.len() + chunk.len() > 65536 {
                    return Err(Error::Unavailable);
                }
                body.extend_from_slice(&chunk);
            }
            let reply = serde_json::from_slice::<Reply>(&body).map_err(|_| Error::Unavailable)?;
            let verified_ms = now_ms
                .checked_add(
                    u64::try_from(started.elapsed().as_millis()).map_err(|_| Error::Unavailable)?,
                )
                .ok_or(Error::Unavailable)?;
            let (workload, expires_ms) = self.facts(&claims, reply, verified_ms)?;
            self.current_objects(&claims).await?;
            let final_ms = now_ms
                .checked_add(
                    u64::try_from(started.elapsed().as_millis()).map_err(|_| Error::Unavailable)?,
                )
                .ok_or(Error::Unavailable)?;
            let lease = expires_ms.min(now_ms.checked_add(1000).ok_or(Error::Unavailable)?);
            if lease <= final_ms {
                return Err(Error::Invalid);
            }
            Ok((workload, expires_ms))
        };
        tokio::time::timeout(Duration::from_millis(self.config.timeout_ms), future)
            .await
            .map_err(|_| Error::Unavailable)?
    }
    async fn current_objects(&self, claims: &Claims) -> Result<(), Error> {
        let k = &claims.kubernetes;
        for (resource, object) in [("serviceaccounts", &k.serviceaccount), ("pods", &k.pod)] {
            let endpoint = self
                .endpoint
                .join(&format!(
                    "/api/v1/namespaces/{}/{}/{}",
                    k.namespace, resource, object.name
                ))
                .map_err(|_| Error::Unavailable)?;
            let mut response = self
                .client
                .get(endpoint)
                .header(reqwest::header::AUTHORIZATION, self.authorization.clone())
                .header(
                    reqwest::header::ACCEPT,
                    "application/json;as=PartialObjectMetadata;g=meta.k8s.io;v=v1",
                )
                .send()
                .await
                .map_err(|_| Error::Unavailable)?;
            if [404, 410].contains(&response.status().as_u16()) {
                return Err(Error::Invalid);
            }
            if response.status().as_u16() != 200
                || !response
                    .headers()
                    .get(reqwest::header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .is_some_and(|v| {
                        v.split(';')
                            .next()
                            .is_some_and(|v| v.trim() == "application/json")
                    })
            {
                return Err(Error::Unavailable);
            }
            let mut body = Vec::new();
            while let Some(chunk) = response.chunk().await.map_err(|_| Error::Unavailable)? {
                if body.len() + chunk.len() > 16384 {
                    return Err(Error::Unavailable);
                }
                body.extend_from_slice(&chunk);
            }
            let value: serde_json::Value =
                serde_json::from_slice(&body).map_err(|_| Error::Unavailable)?;
            if value["apiVersion"] != "meta.k8s.io/v1" || value["kind"] != "PartialObjectMetadata" {
                return Err(Error::Unavailable);
            }
            let m = &value["metadata"];
            if m["name"] != object.name
                || m["namespace"] != k.namespace
                || m["uid"] != object.uid
                || m.get("deletionTimestamp").is_some_and(|v| !v.is_null())
            {
                return Err(Error::Invalid);
            }
        }
        Ok(())
    }
    /// The attested facts of a positive review and the token expiry (ms).
    fn facts(&self, claims: &Claims, reply: Reply, now_ms: u64) -> Result<(Workload, u64), Error> {
        if reply.api_version != "authentication.k8s.io/v1" || reply.kind != "TokenReview" {
            return Err(Error::Unavailable);
        }
        if !reply.status.authenticated {
            return Err(Error::Invalid);
        }
        if reply.status.error.as_ref().is_some_and(|s| !s.is_empty()) {
            return Err(Error::Unavailable);
        }
        let user = reply.status.user.ok_or(Error::Unavailable)?;
        let k = &claims.kubernetes;
        let extra = |name: &str, expected: &str| {
            user.extra
                .get(name)
                .is_some_and(|v| v.len() == 1 && v[0] == expected)
        };
        if !reply
            .status
            .audiences
            .iter()
            .any(|a| a == &self.config.audience)
            || user.username != claims.sub
            || user.uid != k.serviceaccount.uid
            || !extra("authentication.kubernetes.io/pod-name", &k.pod.name)
            || !extra("authentication.kubernetes.io/pod-uid", &k.pod.uid)
        {
            return Err(Error::Unavailable);
        }
        let expires_ms = claims.exp.checked_mul(1000).ok_or(Error::Invalid)?;
        if expires_ms.min(now_ms.checked_add(1000).ok_or(Error::Unavailable)?) <= now_ms {
            return Err(Error::Invalid);
        }
        let node = user
            .extra
            .get("authentication.kubernetes.io/node-name")
            .filter(|v| v.len() == 1 && identity::object_name(&v[0]))
            .map(|v| v[0].clone());
        Ok((
            Workload {
                issuer: self.config.issuer.clone(),
                cluster_id: self.config.cluster_id.clone(),
                namespace: k.namespace.clone(),
                service_account: k.serviceaccount.name.clone(),
                service_account_uid: k.serviceaccount.uid.clone(),
                pod: Some(BoundRef {
                    name: k.pod.name.clone(),
                    uid: k.pod.uid.clone(),
                }),
                secret: None,
                node,
            },
            expires_ms,
        ))
    }
    /// Test helper: the evidence a review would publish.
    #[cfg(test)]
    fn evidence(
        &self,
        service: &str,
        claims: &Claims,
        reply: Reply,
        now_ms: u64,
    ) -> Result<VerifiedEvidence, Error> {
        let (workload, expires_ms) = self.facts(claims, reply, now_ms)?;
        self.publish(service, &workload, expires_ms, now_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config() -> Config {
        Config {
            api_origin: "https://kubernetes.example.test/".into(),
            issuer: "https://issuer.example.test".into(),
            cluster_id: "example-cluster".into(),
            audience: "example-workload".into(),
            namespaces: vec!["blue".into()],
            timeout_ms: 500,
        }
    }
    fn token() -> String {
        format!("{}.{}.{}", URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256"}"#),URL_SAFE_NO_PAD.encode(serde_json::to_vec(&serde_json::json!({"iss":"https://issuer.example.test","sub":"system:serviceaccount:blue:worker","aud":["example-workload"],"exp":2,"kubernetes.io":{"namespace":"blue","serviceaccount":{"name":"worker","uid":"sa-1"},"pod":{"name":"worker-pod","uid":"pod-1"}}})).unwrap()),URL_SAFE_NO_PAD.encode([1;32]))
    }
    fn connector() -> Connector {
        let config = config();
        Connector {
            binding: [0; 32],
            config,
            client: reqwest::Client::new(),
            endpoint: url::Url::parse("https://kubernetes.example.test/").unwrap(),
            authorization: reqwest::header::HeaderValue::from_static("Bearer fixture-only"),
            capacity: tokio::sync::Semaphore::new(64),
            circuit: Circuit::new(3, 30_000).unwrap(),
            identity: IdentityPolicy::default(),
            cache: super::super::workload::cache::Cache::new(0, 0),
            sink: std::sync::Mutex::new(None),
            observed: Seen::new(16),
            mapped: Seen::new(16),
        }
    }
    fn reply() -> Reply {
        serde_json::from_value(serde_json::json!({"apiVersion":"authentication.k8s.io/v1","kind":"TokenReview","status":{"authenticated":true,"audiences":["example-workload"],"user":{"username":"system:serviceaccount:blue:worker","uid":"sa-1","extra":{"authentication.kubernetes.io/pod-name":["worker-pod"],"authentication.kubernetes.io/pod-uid":["pod-1"]}}}})).unwrap()
    }
    #[test]
    fn actual_api_negative_shape_is_denial_but_empty_positive_user_is_source_failure() {
        let c = connector();
        let denied: Reply = serde_json::from_value(serde_json::json!({"apiVersion":"authentication.k8s.io/v1","kind":"TokenReview","status":{"user":{},"error":"invalid fixture signature"}})).unwrap();
        assert!(matches!(
            c.evidence("orders", &c.claims(&token(), 100).unwrap(), denied, 100),
            Err(Error::Invalid)
        ));
        let positive: Reply = serde_json::from_value(serde_json::json!({"apiVersion":"authentication.k8s.io/v1","kind":"TokenReview","status":{"authenticated":true,"audiences":["example-workload"],"user":{}}})).unwrap();
        assert!(matches!(
            c.evidence("orders", &c.claims(&token(), 100).unwrap(), positive, 100),
            Err(Error::Unavailable)
        ));
    }
    #[test]
    fn scope_and_bound_object_attestation_are_required() {
        let c = connector();
        let t = token();
        let e = c
            .evidence("orders", &c.claims(&t, 100).unwrap(), reply(), 100)
            .unwrap();
        assert_eq!(e.subject.kind, super::super::PrincipalKind::Workload);
        assert_eq!(e.expires_at, 1100);
        assert_eq!(e.service(), Some("orders"));
        let stable = super::super::stable_subject(e.subject());
        // ADR 0022: the published principal is the ServiceAccount, not the Pod.
        let attrs = e.workload().unwrap();
        assert_eq!(e.subject().subject, attrs.principal);
        assert_eq!(stable, attrs.subject_ref);
        assert_eq!(attrs.pod.as_ref().unwrap().uid, "pod-1");
        // The legacy Pod-bound contract vector stays derivable for migration.
        assert_eq!(
            attrs.legacy_subject_ref.as_deref(),
            Some("s_529be5b595ab327853eabe2d1adf52256e262af036510607")
        );
        let mut legacy = connector();
        legacy.identity.subject = SubjectMode::LegacyPod;
        legacy.identity.legacy_until_ms = Some(10_000);
        let le = legacy
            .evidence("orders", &legacy.claims(&t, 100).unwrap(), reply(), 100)
            .unwrap();
        assert_eq!(
            super::super::stable_subject(le.subject()),
            "s_529be5b595ab327853eabe2d1adf52256e262af036510607"
        );
        let mut other = reply();
        other.status.user.as_mut().unwrap().uid = "sa-2".into();
        assert!(
            c.evidence("orders", &c.claims(&t, 100).unwrap(), other, 100)
                .is_err()
        );
        let mut other = reply();
        other.status.user.as_mut().unwrap().extra.clear();
        assert!(
            c.evidence("orders", &c.claims(&t, 100).unwrap(), other, 100)
                .is_err()
        );
        let mut other = reply();
        other.status.audiences = vec!["other".into()];
        assert!(
            c.evidence("orders", &c.claims(&t, 100).unwrap(), other, 100)
                .is_err()
        );
        let mut other = reply();
        other.status.authenticated = false;
        other.status.error = Some("invalid fixture credential".into());
        assert!(matches!(
            c.evidence("orders", &c.claims(&t, 100).unwrap(), other, 100),
            Err(Error::Invalid)
        ));
        let mut other = connector();
        other.config.cluster_id = "other-cluster".into();
        let e = other
            .evidence("orders", &other.claims(&t, 100).unwrap(), reply(), 100)
            .unwrap();
        assert_ne!(super::super::stable_subject(e.subject()), stable);
        assert!(
            c.evidence("orders", &c.claims(&t, 100).unwrap(), reply(), 2000)
                .is_err()
        );
    }
    #[test]
    fn token_parsing_never_accepts_wrong_issuer_audience_expiry_or_unbound_token() {
        let c = connector();
        assert!(c.claims(&token(), 2000).is_err());
        let mut c = connector();
        c.config.issuer = "https://other.example.test".into();
        assert!(c.claims(&token(), 100).is_err());
        let mut c = connector();
        c.config.audience = "other".into();
        assert!(c.claims(&token(), 100).is_err());
        for t in [
            "opaque-credential-without-jwt-claims".to_owned(),
            token() + ".extra",
            format!(
                "{}.{}.{}",
                URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#),
                URL_SAFE_NO_PAD.encode(b"{}"),
                URL_SAFE_NO_PAD.encode([1; 32])
            ),
        ] {
            assert!(connector().claims(&t, 100).is_err());
        }
    }
    #[test]
    fn api_origin_never_accepts_credentials_redirect_targets_or_http() {
        for namespaces in [
            vec![],
            vec!["blue".into(), "blue".into()],
            vec!["*".into()],
            vec!["../red".into()],
        ] {
            let mut c = config();
            c.namespaces = namespaces;
            assert!(c.validate().is_err());
        }
        for origin in [
            "http://kubernetes.example.test/",
            "https://user:pass@kubernetes.example.test/",
            "https://kubernetes.example.test/path",
            "https://kubernetes.example.test/?token=value",
            "https://kubernetes.example.test/#x",
        ] {
            let mut c = config();
            c.api_origin = origin.into();
            assert!(c.validate().is_err());
        }
    }
}
