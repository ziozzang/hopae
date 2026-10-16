//! `kubernetes_workload`: offline verification of projected ServiceAccount
//! tokens. See the module documentation of [`super`] and
//! `docs/KUBERNETES_WORKLOAD.md`.
use super::super::{VerifiedEvidence, runtime::Error};
use super::cache::Cache;
use super::http::{self, Bearer};
use super::identity::{self, BoundRef, SubjectMode, Workload};
use super::keys::{KeySource, KeyStatus, Source};
use super::metrics;
use super::revocation::{Refusal, Resource, Revocation, RevocationStatus};
use super::signals::{Seen, Signal, Sink, WorkloadRef};
use crate::provider::oidc::{idtoken, jwks};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;
use zeroize::Zeroizing;

pub const VERIFICATION: &str = "offline_jwks";
pub const CONNECTOR: &str = "kubernetes-workload";

/// Audiences a workload token for Hopae must never carry alone: tokens for
/// the API server itself would otherwise be replayable here.
const API_SERVER_AUDIENCES: &[&str] = &[
    "api",
    "kubernetes",
    "https://kubernetes.default.svc",
    "https://kubernetes.default.svc.cluster.local",
];

fn default_true() -> bool {
    true
}
fn default_bound() -> Vec<BoundKind> {
    vec![BoundKind::Pod]
}
fn default_skew() -> u64 {
    30
}
fn default_lifetime() -> u64 {
    86_400
}
fn default_refresh() -> u64 {
    300
}
fn default_max_stale() -> u64 {
    3600
}
fn default_kid_miss() -> u64 {
    10_000
}
fn default_timeout() -> u64 {
    2000
}
fn default_ttl() -> u64 {
    10_000
}
fn default_entries() -> usize {
    10_000
}
fn default_staleness() -> u64 {
    60
}
fn default_objects() -> usize {
    200_000
}
fn default_resources() -> Vec<String> {
    vec!["serviceaccounts".into(), "pods".into()]
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BoundKind {
    Pod,
    Secret,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KeySourceKind {
    Discovery,
    JwksUrl,
    Static,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KeysConfig {
    pub source: KeySourceKind,
    /// Default `<issuer>/.well-known/openid-configuration`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discovery_url: Option<String>,
    /// Required for `jwks_url`; with `discovery` it pins the advertised URI.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks_url: Option<String>,
    /// Extra origins an advertised `jwks_uri` may use (the issuer's and the
    /// discovery URL's origins are always allowed).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub jwks_origins: Vec<String>,
    /// `static`: environment reference holding the JWKS document.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks_env: Option<String>,
    /// Environment reference of the PEM CA bundle for discovery/JWKS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_pem_env: Option<String>,
    /// Optional bearer for discovery/JWKS (environment reference).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_env: Option<String>,
    /// Optional bearer re-read per fetch (a projected token file).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_file: Option<String>,
    #[serde(default = "default_refresh")]
    pub refresh_seconds: u64,
    #[serde(default = "default_max_stale")]
    pub max_stale_seconds: u64,
    #[serde(default = "default_kid_miss")]
    pub kid_miss_min_interval_ms: u64,
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CacheConfig {
    #[serde(default = "default_ttl")]
    pub ttl_ms: u64,
    #[serde(default = "default_entries")]
    pub max_entries: usize,
}
impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            ttl_ms: default_ttl(),
            max_entries: default_entries(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationConfig {
    /// Only `watch` is defined.
    pub mode: String,
    pub api_origin: String,
    /// Defaults to `keys.ca_pem_env`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_pem_env: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_env: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_file: Option<String>,
    #[serde(default = "default_resources")]
    pub resources: Vec<String>,
    #[serde(default = "default_staleness")]
    pub max_staleness_seconds: u64,
    #[serde(default = "default_objects")]
    pub max_objects: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub issuer: String,
    pub cluster_id: String,
    pub trust_domain: String,
    /// The audience this service requires (per profile, i.e. per service).
    pub audience: String,
    /// Refuse tokens that carry any other audience as well (default true).
    #[serde(default = "default_true")]
    pub exclusive_audience: bool,
    pub namespaces: Vec<String>,
    /// Optional `namespace/name` allowlist; empty admits every
    /// ServiceAccount of the allowed namespaces.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub service_accounts: Vec<String>,
    #[serde(default = "default_bound")]
    pub bound_objects: Vec<BoundKind>,
    pub keys: KeysConfig,
    #[serde(default = "default_skew")]
    pub clock_skew_seconds: u64,
    #[serde(default = "default_lifetime")]
    pub max_token_lifetime_seconds: u64,
    #[serde(default)]
    pub cache: CacheConfig,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation: Option<RevocationConfig>,
    #[serde(default)]
    pub subject: SubjectMode,
    /// Required with `subject: legacy_pod`; after it the connector refuses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legacy_until_ms: Option<u64>,
    /// Report legacy Pod subject → principal mappings until this instant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legacy_mapping_until_ms: Option<u64>,
    pub token_prefix: String,
}

fn env_ref(name: &Option<String>) -> bool {
    name.as_ref().is_none_or(|n| {
        !n.is_empty() && n.len() <= 128 && n.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
    })
}

/// `namespace/name`.
fn service_account_ref(value: &str) -> Option<(&str, &str)> {
    let (ns, name) = value.split_once('/')?;
    (identity::namespace(ns) && identity::object_name(name)).then_some((ns, name))
}

impl Profile {
    pub fn validate(&self) -> Result<()> {
        let issuer = http::https_url(&self.issuer)?;
        ensure!(
            self.issuer.len() <= 256 && issuer.path() != "",
            "invalid Kubernetes workload issuer"
        );
        ensure!(
            identifier(&self.cluster_id) && identity::trust_domain(&self.trust_domain),
            "invalid Kubernetes workload cluster or trust domain"
        );
        ensure!(
            !self.audience.is_empty()
                && self.audience.len() <= 256
                && !self
                    .audience
                    .chars()
                    .any(|c| c.is_control() || c.is_whitespace())
                && self.audience != self.issuer
                && !API_SERVER_AUDIENCES.contains(&self.audience.as_str()),
            "Kubernetes workload audience must be dedicated (never the API server audience)"
        );
        ensure!(
            (1..=128).contains(&self.namespaces.len())
                && self.namespaces.iter().all(|n| identity::namespace(n))
                && self
                    .namespaces
                    .iter()
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
                    == self.namespaces.len(),
            "invalid Kubernetes workload namespaces"
        );
        ensure!(
            self.service_accounts.len() <= 1024
                && self.service_accounts.iter().all(|s| {
                    service_account_ref(s)
                        .is_some_and(|(ns, _)| self.namespaces.iter().any(|n| n == ns))
                }),
            "service_accounts must be namespace/name within the allowed namespaces"
        );
        ensure!(
            !self.bound_objects.is_empty() && self.bound_objects.len() <= 2,
            "bound_objects must name pod and/or secret"
        );
        ensure!(
            self.clock_skew_seconds <= 300
                && (600..=7 * 86_400).contains(&self.max_token_lifetime_seconds),
            "clock skew must be 0-300 s and token lifetime 600 s-7 d"
        );
        ensure!(
            self.cache.ttl_ms <= 60_000 && self.cache.max_entries <= 262_144,
            "workload cache must be at most 60 s and 262144 entries"
        );
        let k = &self.keys;
        ensure!(
            env_ref(&k.jwks_env)
                && env_ref(&k.ca_pem_env)
                && env_ref(&k.token_env)
                && !(k.token_env.is_some() && k.token_file.is_some())
                && (30..=3600).contains(&k.refresh_seconds)
                && (k.refresh_seconds..=86_400).contains(&k.max_stale_seconds)
                && (1000..=300_000).contains(&k.kid_miss_min_interval_ms)
                && (100..=10_000).contains(&k.timeout_ms)
                && k.jwks_origins.len() <= 8,
            "invalid Kubernetes workload key source bounds"
        );
        match k.source {
            KeySourceKind::Static => ensure!(
                k.jwks_env.is_some()
                    && k.discovery_url.is_none()
                    && k.jwks_url.is_none()
                    && k.jwks_origins.is_empty()
                    && k.token_env.is_none()
                    && k.token_file.is_none(),
                "static keys take only jwks_env"
            ),
            KeySourceKind::JwksUrl => ensure!(
                k.jwks_url.is_some()
                    && k.discovery_url.is_none()
                    && k.jwks_env.is_none()
                    && k.ca_pem_env.is_some(),
                "jwks_url keys need jwks_url and ca_pem_env"
            ),
            KeySourceKind::Discovery => {
                ensure!(
                    k.jwks_env.is_none() && k.ca_pem_env.is_some(),
                    "discovery keys need ca_pem_env"
                )
            }
        }
        for u in k.discovery_url.iter().chain(k.jwks_url.iter()) {
            http::https_url(u)?;
        }
        for o in &k.jwks_origins {
            let url = http::https_url(o)?;
            ensure!(url.path() == "/", "jwks_origins must be origins");
        }
        if let Some(t) = &k.token_file {
            Bearer::file(t)?;
        }
        if let Some(r) = &self.revocation {
            ensure!(r.mode == "watch", "revocation mode must be watch");
            let origin = http::https_url(&r.api_origin)?;
            ensure!(
                origin.path() == "/",
                "revocation api_origin must be an origin"
            );
            ensure!(
                env_ref(&r.ca_pem_env)
                    && env_ref(&r.token_env)
                    && (r.token_env.is_some() != r.token_file.is_some())
                    && (r.ca_pem_env.is_some() || k.ca_pem_env.is_some())
                    && (5..=600).contains(&r.max_staleness_seconds)
                    && (1..=1_000_000).contains(&r.max_objects)
                    && !r.resources.is_empty()
                    && r.resources.len() <= 2
                    && r.resources
                        .iter()
                        .all(|x| x == "serviceaccounts" || x == "pods")
                    && r.resources.iter().any(|x| x == "serviceaccounts")
                    && r.resources
                        .iter()
                        .collect::<std::collections::BTreeSet<_>>()
                        .len()
                        == r.resources.len(),
                "invalid workload revocation watch (serviceaccounts required, credential and CA references)"
            );
            if let Some(t) = &r.token_file {
                Bearer::file(t)?;
            }
        }
        match self.subject {
            SubjectMode::ServiceAccount => ensure!(
                self.legacy_until_ms.is_none(),
                "legacy_until_ms requires subject legacy_pod"
            ),
            SubjectMode::LegacyPod => ensure!(
                self.legacy_until_ms
                    .is_some_and(|t| t > 0 && t <= i64::MAX as u64)
                    && self.bound_objects == [BoundKind::Pod],
                "subject legacy_pod is deprecated and requires legacy_until_ms and Pod-bound tokens only"
            ),
        }
        ensure!(
            self.legacy_mapping_until_ms
                .is_none_or(|t| t > 0 && t <= i64::MAX as u64),
            "invalid legacy_mapping_until_ms"
        );
        let prefix = &self.token_prefix;
        ensure!(
            (2..=32).contains(&prefix.len())
                && prefix.ends_with(':')
                && prefix[..prefix.len() - 1]
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b)),
            "explicit Kubernetes credential prefix required"
        );
        Ok(())
    }

    pub fn compile(
        &self,
        service: &str,
        env: &dyn Fn(&str) -> Option<String>,
    ) -> Result<Connector> {
        self.validate()?;
        let mut binding = Sha256::new();
        binding.update(b"hopae:kubernetes-workload:binding:v1\0");
        binding.update(service.as_bytes());
        binding.update([0]);
        binding.update(serde_json::to_vec(self)?);
        let mut material =
            |name: &Option<String>, what: &str| -> Result<Option<Zeroizing<String>>> {
                match name {
                    None => Ok(None),
                    Some(n) => {
                        let value = Zeroizing::new(env(n).ok_or_else(|| {
                            anyhow::anyhow!("Kubernetes workload {what} reference unavailable")
                        })?);
                        binding.update(Sha256::digest(value.as_bytes()));
                        Ok(Some(value))
                    }
                }
            };
        let k = &self.keys;
        let ca = material(&k.ca_pem_env, "CA")?;
        let jwks_doc = material(&k.jwks_env, "JWKS")?;
        let key_token = material(&k.token_env, "API credential")?;
        let (revocation_ca, revocation_token) = match &self.revocation {
            Some(r) => (
                material(&r.ca_pem_env, "CA")?,
                material(&r.token_env, "API credential")?,
            ),
            None => (None, None),
        };
        let source = match k.source {
            KeySourceKind::Static => Source::Static,
            kind => {
                let issuer = http::https_url(&self.issuer)?;
                let discovery = match kind {
                    KeySourceKind::Discovery => Some(match &k.discovery_url {
                        Some(u) => http::https_url(u)?,
                        None => {
                            let base = self.issuer.trim_end_matches('/');
                            http::https_url(&format!("{base}/.well-known/openid-configuration"))?
                        }
                    }),
                    _ => None,
                };
                let mut origins = vec![http::origin(&issuer)];
                if let Some(d) = &discovery {
                    origins.push(http::origin(d));
                }
                for o in &k.jwks_origins {
                    origins.push(http::origin(&http::https_url(o)?));
                }
                let bearer = match (&key_token, &k.token_file) {
                    (Some(t), _) => Bearer::fixed(t.clone())?,
                    (None, Some(f)) => Bearer::file(f)?,
                    (None, None) => Bearer::None,
                };
                Source::Remote {
                    client: http::client(ca.as_ref().expect("validated").as_bytes())?,
                    discovery,
                    jwks: k.jwks_url.as_deref().map(http::https_url).transpose()?,
                    jwks_origins: origins,
                    bearer,
                }
            }
        };
        let keys = KeySource::new(
            &self.issuer,
            service,
            source,
            jwks_doc.as_ref().map(|d| d.as_bytes()),
            Duration::from_secs(k.refresh_seconds),
            Duration::from_secs(k.max_stale_seconds),
            Duration::from_millis(k.kid_miss_min_interval_ms),
            Duration::from_millis(k.timeout_ms),
        )?;
        let revocation = match &self.revocation {
            None => None,
            Some(r) => {
                let ca = revocation_ca.as_ref().or(ca.as_ref()).expect("validated");
                let bearer = match (&revocation_token, &r.token_file) {
                    (Some(t), _) => Bearer::fixed(t.clone())?,
                    (None, Some(f)) => Bearer::file(f)?,
                    (None, None) => unreachable!("validated"),
                };
                Some(Arc::new(Revocation::new(
                    service,
                    &self.issuer,
                    &self.cluster_id,
                    Some(&self.trust_domain),
                    http::client(ca.as_bytes())?,
                    http::https_url(&r.api_origin)?,
                    bearer,
                    self.namespaces.clone(),
                    r.resources
                        .iter()
                        .map(|x| {
                            if x == "pods" {
                                Resource::Pods
                            } else {
                                Resource::ServiceAccounts
                            }
                        })
                        .collect(),
                    Duration::from_secs(r.max_staleness_seconds),
                    r.max_objects,
                )))
            }
        };
        Ok(Connector {
            binding: binding.finalize().into(),
            service: service.to_owned(),
            profile: self.clone(),
            keys: Arc::new(keys),
            cache: Arc::new(Cache::new(self.cache.ttl_ms, self.cache.max_entries)),
            revocation,
            sink: Mutex::new(None),
            activated: std::sync::atomic::AtomicBool::new(false),
            observed: Seen::new(65_536),
            mapped: Seen::new(65_536),
        })
    }
}

fn identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._".contains(&b))
}

pub struct Connector {
    binding: [u8; 32],
    service: String,
    profile: Profile,
    keys: Arc<KeySource>,
    cache: Arc<Cache>,
    revocation: Option<Arc<Revocation>>,
    sink: Mutex<Option<Sink>>,
    activated: std::sync::atomic::AtomicBool,
    observed: Seen,
    mapped: Seen,
}

/// Management view of one connector (no key or credential material).
#[derive(Clone, Debug, serde::Serialize)]
pub struct WorkloadStatus {
    pub verification: &'static str,
    pub issuer: String,
    pub cluster_id: String,
    pub trust_domain: String,
    pub audience: String,
    pub subject: SubjectMode,
    pub keys: KeyStatus,
    pub revocation: Option<RevocationStatus>,
    pub cache_entries: usize,
}

/// What the explain API may say about a hypothetical ServiceAccount caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExplainVerdict {
    NamespaceNotAllowed,
    ServiceAccountNotAllowed,
    KeysUnavailable,
    RevocationStale,
    ServiceAccountAbsent,
    LegacyWindowExpired,
    Allowed { revocation_evaluated: bool },
}

/// Why a token was refused (metrics label; never returned to the caller).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Refused {
    Malformed,
    Algorithm,
    UnknownKey,
    Signature,
    Issuer,
    Audience,
    Expired,
    NotYetValid,
    IssuedInFuture,
    Lifetime,
    Subject,
    Unbound,
    Namespace,
    ServiceAccount,
    LegacyWindow,
    KeysUnavailable,
    Revocation(Refusal),
}

impl Refused {
    fn reason(self) -> &'static str {
        match self {
            Refused::Malformed => "malformed",
            Refused::Algorithm => "algorithm",
            Refused::UnknownKey => "unknown_kid",
            Refused::Signature => "signature",
            Refused::Issuer => "issuer",
            Refused::Audience => "audience",
            Refused::Expired => "expired",
            Refused::NotYetValid => "not_yet_valid",
            Refused::IssuedInFuture => "issued_in_future",
            Refused::Lifetime => "lifetime",
            Refused::Subject => "subject",
            Refused::Unbound => "unbound",
            Refused::Namespace => "namespace",
            Refused::ServiceAccount => "service_account",
            Refused::LegacyWindow => "legacy_window_expired",
            Refused::KeysUnavailable => "keys_unavailable",
            Refused::Revocation(r) => r.reason(),
        }
    }
    fn error(self) -> Error {
        match self {
            Refused::Expired => Error::Expired,
            Refused::KeysUnavailable | Refused::LegacyWindow => Error::Unavailable,
            Refused::Revocation(r) => r.error(),
            _ => Error::Invalid,
        }
    }
}

const ALGORITHMS: [jsonwebtoken::Algorithm; 5] = [
    jsonwebtoken::Algorithm::RS256,
    jsonwebtoken::Algorithm::RS384,
    jsonwebtoken::Algorithm::RS512,
    jsonwebtoken::Algorithm::ES256,
    jsonwebtoken::Algorithm::ES384,
];

fn numeric(v: Option<&Value>) -> Option<i64> {
    let v = v?;
    v.as_i64().or_else(|| {
        v.as_f64()
            .filter(|f| f.is_finite() && f.abs() < 1e15)
            .map(|f| f.floor() as i64)
    })
}

fn bound(v: Option<&Value>) -> Result<Option<BoundRef>, Refused> {
    match v {
        None | Some(Value::Null) => Ok(None),
        Some(o) => {
            let name = o
                .get("name")
                .and_then(Value::as_str)
                .ok_or(Refused::Malformed)?;
            let uid = o
                .get("uid")
                .and_then(Value::as_str)
                .ok_or(Refused::Malformed)?;
            if !identity::object_name(name) || !identity::uid(uid) {
                return Err(Refused::Malformed);
            }
            Ok(Some(BoundRef {
                name: name.to_owned(),
                uid: uid.to_owned(),
            }))
        }
    }
}

impl Connector {
    pub(crate) fn same_binding(&self, other: &Self) -> bool {
        self.binding == other.binding
    }
    pub fn profile(&self) -> &Profile {
        &self.profile
    }

    /// Start background key refresh and the revocation watch (once), and
    /// attach the lifecycle sink. Safe to call repeatedly.
    pub fn activate(self: &Arc<Self>, sink: Option<Sink>) {
        if let Some(sink) = &sink {
            *self.sink.lock().unwrap_or_else(|p| p.into_inner()) = Some(sink.clone());
            let s = sink.clone();
            let service = self.service.clone();
            self.keys.set_on_change(Arc::new(move |added, removed| {
                s.emit(Signal::KeysRotated {
                    service: service.clone(),
                    added,
                    removed,
                })
            }));
        }
        if let Some(r) = &self.revocation {
            r.attach(sink, &self.cache);
        }
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        if self
            .activated
            .swap(true, std::sync::atomic::Ordering::AcqRel)
        {
            return;
        }
        let weak: Weak<KeySource> = Arc::downgrade(&self.keys);
        handle.spawn(async move {
            loop {
                let Some(keys) = weak.upgrade() else { return };
                if keys.refresh_due() {
                    keys.refresh().await;
                }
                drop(keys);
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        });
        if let Some(r) = &self.revocation {
            r.start();
        }
    }

    fn emit(&self, signal: Signal) {
        if let Some(sink) = self.sink.lock().unwrap_or_else(|p| p.into_inner()).as_ref() {
            sink.emit(signal);
        }
    }

    pub fn status(&self) -> WorkloadStatus {
        metrics::cache_entries(&self.service, self.cache.len());
        WorkloadStatus {
            verification: VERIFICATION,
            issuer: self.profile.issuer.clone(),
            cluster_id: self.profile.cluster_id.clone(),
            trust_domain: self.profile.trust_domain.clone(),
            audience: self.profile.audience.clone(),
            subject: self.profile.subject,
            keys: self.keys.status(),
            revocation: self.revocation.as_ref().map(|r| r.status()),
            cache_entries: self.cache.len(),
        }
    }

    fn scope(&self, namespace: &str, service_account: &str) -> Result<(), Refused> {
        if !self.profile.namespaces.iter().any(|n| n == namespace) {
            return Err(Refused::Namespace);
        }
        if !self.profile.service_accounts.is_empty()
            && !self
                .profile
                .service_accounts
                .iter()
                .any(|s| service_account_ref(s) == Some((namespace, service_account)))
        {
            return Err(Refused::ServiceAccount);
        }
        Ok(())
    }

    /// The explain API: the predicates that do not need the token.
    pub fn explain(&self, namespace: &str, service_account: &str, now_ms: u64) -> ExplainVerdict {
        match self.scope(namespace, service_account) {
            Err(Refused::Namespace) => return ExplainVerdict::NamespaceNotAllowed,
            Err(_) => return ExplainVerdict::ServiceAccountNotAllowed,
            Ok(()) => {}
        }
        if self.profile.subject == SubjectMode::LegacyPod
            && self.profile.legacy_until_ms.is_some_and(|t| now_ms >= t)
        {
            return ExplainVerdict::LegacyWindowExpired;
        }
        if !self.keys.status().fresh {
            return ExplainVerdict::KeysUnavailable;
        }
        match &self.revocation {
            None => ExplainVerdict::Allowed {
                revocation_evaluated: false,
            },
            Some(r) => match r.service_account_state(namespace, service_account) {
                Err(_) => ExplainVerdict::RevocationStale,
                Ok(None) => ExplainVerdict::ServiceAccountAbsent,
                Ok(Some(_)) => ExplainVerdict::Allowed {
                    revocation_evaluated: true,
                },
            },
        }
    }

    /// The `wk2:` principal a ServiceAccount currently has, when the
    /// revocation index knows its UID (for explain and SPIFFE resolution).
    pub fn current_principal(&self, namespace: &str, service_account: &str) -> Option<String> {
        let uid = self
            .revocation
            .as_ref()?
            .service_account_state(namespace, service_account)
            .ok()??;
        Some(identity::principal_ref(
            &self.profile.issuer,
            &self.profile.cluster_id,
            namespace,
            service_account,
            &uid,
        ))
    }

    pub async fn authenticate(
        self: &Arc<Self>,
        token: &str,
        now_ms: u64,
    ) -> Result<VerifiedEvidence, Error> {
        if !self.activated.load(std::sync::atomic::Ordering::Acquire) {
            self.activate(None);
        }
        let result = self.verify(token, now_ms).await;
        match &result {
            Ok(_) => metrics::authentication(&self.service, VERIFICATION, "authenticated", "ok"),
            Err(refused) => {
                metrics::authentication(&self.service, VERIFICATION, "denied", refused.reason())
            }
        }
        let (workload, expires_ms) = result.map_err(Refused::error)?;
        self.evidence(&workload, expires_ms, now_ms)
    }

    fn evidence(
        &self,
        w: &Workload,
        expires_ms: u64,
        now_ms: u64,
    ) -> Result<VerifiedEvidence, Error> {
        let (subject, attributes) = w
            .resolve(
                Some(&self.profile.trust_domain),
                self.profile.subject,
                VERIFICATION,
            )
            .ok_or(Error::Invalid)?;
        let workload_ref = WorkloadRef::of(&self.service, &attributes);
        if self.observed.insert(&attributes.principal) {
            self.emit(Signal::Observed(workload_ref.clone()));
        }
        if let Some(legacy) = &attributes.legacy_subject_ref
            && self
                .profile
                .legacy_mapping_until_ms
                .is_some_and(|until| now_ms < until)
            && self
                .mapped
                .insert(&format!("{legacy}>{}", attributes.principal))
        {
            self.emit(Signal::LegacyMapped {
                workload: workload_ref,
                legacy_subject_ref: legacy.clone(),
            });
        }
        // Freshness lease: at most one second (unchanged gateway contract).
        let expires_at = expires_ms.min(now_ms.saturating_add(1000));
        if expires_at <= now_ms {
            return Err(Error::Expired);
        }
        Ok(VerifiedEvidence {
            subject,
            connector: CONNECTOR.into(),
            expires_at,
            service: Some(self.service.clone()),
            workload: Some(Arc::new(attributes)),
        })
    }

    async fn verify(&self, token: &str, now_ms: u64) -> Result<(Workload, u64), Refused> {
        if !(32..=8192).contains(&token.len()) || !token.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(Refused::Malformed);
        }
        if self.profile.subject == SubjectMode::LegacyPod
            && self.profile.legacy_until_ms.is_some_and(|t| now_ms >= t)
        {
            return Err(Refused::LegacyWindow);
        }
        let key: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        if let Some((workload, expires_ms)) = self.cache.get(&key, now_ms) {
            metrics::cache(&self.service, "hit");
            // A hit skips only the signature; scope and revocation are live.
            self.live(&workload)?;
            return Ok(((*workload).clone(), expires_ms));
        }
        if self.cache.enabled() {
            metrics::cache(&self.service, "miss");
        }
        let header = idtoken::parse_header(token, &ALGORITHMS, None).map_err(|e| match e {
            crate::provider::types::ProviderError::InvalidTokenHeader => Refused::Algorithm,
            _ => Refused::Malformed,
        })?;
        let mut keys = self
            .keys
            .keys()
            .await
            .map_err(|_| Refused::KeysUnavailable)?;
        let unknown_kid = match keys.select(header.alg, header.kid.as_deref()) {
            jwks::Selection::Candidates(_) => false,
            jwks::Selection::UnknownKid => true,
            _ => return Err(Refused::UnknownKey),
        };
        if unknown_kid {
            keys = self.keys.after_kid_miss(&keys).await;
        }
        let jwks::Selection::Candidates(candidates) =
            keys.select(header.alg, header.kid.as_deref())
        else {
            return Err(Refused::UnknownKey);
        };
        let claims = candidates
            .into_iter()
            .find_map(|entry| idtoken::verify_signature(token, &header, &entry.key).ok())
            .ok_or(Refused::Signature)?;
        let (workload, expires_ms) = self.claims(&claims, now_ms)?;
        let workload = Arc::new(workload);
        self.live(&workload)?;
        self.cache.insert(key, workload.clone(), expires_ms, now_ms);
        Ok(((*workload).clone(), expires_ms))
    }

    /// Checks that do not depend on the token bytes: scope and revocation.
    fn live(&self, w: &Workload) -> Result<(), Refused> {
        self.scope(&w.namespace, &w.service_account)?;
        if let Some(r) = &self.revocation {
            r.check(
                &w.namespace,
                &w.service_account,
                &w.service_account_uid,
                w.pod.as_ref().map(|p| (p.name.as_str(), p.uid.as_str())),
            )
            .map_err(Refused::Revocation)?;
        }
        Ok(())
    }

    /// Claims of a signature-verified payload.
    fn claims(&self, claims: &Value, now_ms: u64) -> Result<(Workload, u64), Refused> {
        let p = &self.profile;
        let obj = claims.as_object().ok_or(Refused::Malformed)?;
        if obj.get("iss").and_then(Value::as_str) != Some(p.issuer.as_str()) {
            return Err(Refused::Issuer);
        }
        let audiences: Vec<&str> = match obj.get("aud") {
            Some(Value::String(a)) => vec![a.as_str()],
            Some(Value::Array(a)) if !a.is_empty() && a.len() <= 16 => a
                .iter()
                .map(Value::as_str)
                .collect::<Option<Vec<_>>>()
                .ok_or(Refused::Audience)?,
            _ => return Err(Refused::Audience),
        };
        if !audiences.contains(&p.audience.as_str())
            || (p.exclusive_audience && audiences.iter().any(|a| *a != p.audience))
        {
            return Err(Refused::Audience);
        }
        let now = i64::try_from(now_ms / 1000).map_err(|_| Refused::Malformed)?;
        let skew = p.clock_skew_seconds as i64;
        let exp = numeric(obj.get("exp")).ok_or(Refused::Malformed)?;
        let iat = numeric(obj.get("iat")).ok_or(Refused::Malformed)?;
        if exp.saturating_add(skew) <= now {
            return Err(Refused::Expired);
        }
        if let Some(nbf) = obj.get("nbf") {
            let nbf = numeric(Some(nbf)).ok_or(Refused::Malformed)?;
            if nbf > now.saturating_add(skew) {
                return Err(Refused::NotYetValid);
            }
        }
        if iat > now.saturating_add(skew) {
            return Err(Refused::IssuedInFuture);
        }
        if exp <= iat || exp - iat > p.max_token_lifetime_seconds as i64 {
            return Err(Refused::Lifetime);
        }
        let k = obj.get("kubernetes.io").ok_or(Refused::Unbound)?;
        let namespace = k
            .get("namespace")
            .and_then(Value::as_str)
            .filter(|n| identity::namespace(n))
            .ok_or(Refused::Malformed)?;
        let sa = bound(k.get("serviceaccount"))?.ok_or(Refused::Unbound)?;
        let pod = bound(k.get("pod"))?;
        let secret = bound(k.get("secret"))?;
        let node = bound(k.get("node"))?.map(|n| n.name);
        let bound_ok = (pod.is_some() && p.bound_objects.contains(&BoundKind::Pod))
            || (pod.is_none() && secret.is_some() && p.bound_objects.contains(&BoundKind::Secret));
        if !bound_ok {
            return Err(Refused::Unbound);
        }
        if obj.get("sub").and_then(Value::as_str)
            != Some(format!("system:serviceaccount:{namespace}:{}", sa.name).as_str())
        {
            return Err(Refused::Subject);
        }
        self.scope(namespace, &sa.name)?;
        if let Some(warn) = numeric(k.get("warnafter"))
            && now > warn
        {
            // An extended-expiry token past its intended lifetime (kube-apiserver
            // --service-account-extend-token-expiration); counted, not refused.
            metrics::authentication(&self.service, VERIFICATION, "warning", "warnafter_passed");
        }
        // The cached and leased lifetime never exceeds the token's expiry
        // plus the configured clock tolerance.
        let expires_ms = u64::try_from(exp.saturating_add(skew))
            .ok()
            .and_then(|e| e.checked_mul(1000))
            .ok_or(Refused::Malformed)?;
        Ok((
            Workload {
                issuer: p.issuer.clone(),
                cluster_id: p.cluster_id.clone(),
                namespace: namespace.to_owned(),
                service_account: sa.name,
                service_account_uid: sa.uid,
                pod,
                secret,
                node,
            },
            expires_ms,
        ))
    }
}
