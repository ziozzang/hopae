//! Signing keys of one Kubernetes ServiceAccount issuer.
//!
//! Sources, in the order an operator would choose them:
//!
//! * **discovery**: `GET <issuer>/.well-known/openid-configuration` (or an
//!   explicit discovery URL), whose `issuer` must equal the pinned issuer
//!   byte for byte and whose `jwks_uri` must be HTTPS on an allowed origin,
//!   then `GET <jwks_uri>`;
//! * **jwks_url**: a pinned JWKS URL, no discovery;
//! * **static**: a JWKS document supplied by reference (no network at all).
//!
//! Network fetches trust only the configured CA bundle. The set is bounded
//! (64 asymmetric signature keys, 64 KiB), refreshed in the background every
//! `refresh_seconds`, and served while younger than `max_stale_seconds`
//! (last-known-good across API-server outages); beyond that the connector
//! fails closed (`Unavailable`). A token naming an unknown `kid` triggers at
//! most one refetch per `kid_miss_min_interval_ms` (single flight), so key
//! rotation is picked up immediately while a flood of forged `kid`s cannot
//! turn into a flood of requests to the API server.
use super::super::runtime::Error;
use super::http::{self, Bearer};
use super::metrics;
use crate::provider::oidc::jwks::KeySet;
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::time::Instant;

pub(crate) const MAX_DOCUMENT_BYTES: usize = 64 * 1024;

#[allow(clippy::large_enum_variant)]
pub(crate) enum Source {
    Static,
    Remote {
        client: reqwest::Client,
        discovery: Option<url::Url>,
        jwks: Option<url::Url>,
        jwks_origins: Vec<String>,
        bearer: Bearer,
    },
}

#[derive(Default)]
struct State {
    keys: Option<Arc<KeySet>>,
    fingerprint: Option<[u8; 32]>,
    kids: usize,
    fetched_at: Option<Instant>,
    last_attempt: Option<Instant>,
    last_kid_miss: Option<Instant>,
    last_error: Option<&'static str>,
    failures: u32,
    jwks_uri: Option<url::Url>,
}

/// Observable state for status pages (no key material).
#[derive(Clone, Debug, serde::Serialize)]
pub struct KeyStatus {
    pub source: &'static str,
    pub keys: usize,
    pub age_ms: Option<u64>,
    pub fresh: bool,
    pub consecutive_failures: u32,
    pub last_error: Option<&'static str>,
}

/// Called with (added, removed) kid counts.
pub(crate) type OnChange = Arc<dyn Fn(usize, usize) + Send + Sync>;

pub(crate) struct KeySource {
    issuer: String,
    service: String,
    source: Source,
    refresh: Duration,
    max_stale: Duration,
    kid_miss_interval: Duration,
    timeout: Duration,
    state: Mutex<State>,
    flight: tokio::sync::Mutex<()>,
    /// Called with (added, removed) kid counts when a fetched set differs.
    on_change: Mutex<Option<OnChange>>,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

fn fingerprint(document: &[u8]) -> [u8; 32] {
    Sha256::digest(document).into()
}

fn kids(set: &KeySet) -> std::collections::BTreeSet<String> {
    set.keys
        .iter()
        .map(|k| k.kid.clone().unwrap_or_default())
        .collect()
}

impl KeySource {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        issuer: &str,
        service: &str,
        source: Source,
        static_jwks: Option<&[u8]>,
        refresh: Duration,
        max_stale: Duration,
        kid_miss_interval: Duration,
        timeout: Duration,
    ) -> anyhow::Result<Self> {
        let mut state = State::default();
        if let Some(document) = static_jwks {
            anyhow::ensure!(
                document.len() <= MAX_DOCUMENT_BYTES,
                "static JWKS exceeds 64 KiB"
            );
            let set = KeySet::parse(document)
                .map_err(|_| anyhow::anyhow!("static JWKS has no usable signature key"))?;
            state.kids = set.keys.len();
            state.keys = Some(Arc::new(set));
            state.fingerprint = Some(fingerprint(document));
        }
        Ok(Self {
            issuer: issuer.to_owned(),
            service: service.to_owned(),
            source,
            refresh,
            max_stale,
            kid_miss_interval,
            timeout,
            state: Mutex::new(state),
            flight: tokio::sync::Mutex::new(()),
            on_change: Mutex::new(None),
        })
    }

    pub(crate) fn set_on_change(&self, f: OnChange) {
        *lock(&self.on_change) = Some(f);
    }

    fn is_static(&self) -> bool {
        matches!(self.source, Source::Static)
    }

    pub(crate) fn status(&self) -> KeyStatus {
        let state = lock(&self.state);
        let age = state.fetched_at.map(|t| t.elapsed());
        KeyStatus {
            source: match &self.source {
                Source::Static => "static",
                Source::Remote {
                    discovery: Some(_), ..
                } => "discovery",
                Source::Remote { .. } => "jwks_url",
            },
            keys: state.kids,
            age_ms: age.map(|a| a.as_millis().min(u64::MAX as u128) as u64),
            fresh: state.keys.is_some()
                && (self.is_static() || age.is_some_and(|a| a <= self.max_stale)),
            consecutive_failures: state.failures,
            last_error: state.last_error,
        }
    }

    /// The cached set when it may still be used (younger than `max_stale`).
    fn usable(&self) -> Option<Arc<KeySet>> {
        let state = lock(&self.state);
        let keys = state.keys.clone()?;
        if self.is_static() {
            return Some(keys);
        }
        (state.fetched_at?.elapsed() <= self.max_stale).then_some(keys)
    }

    /// Whether a background refresh is due (age beyond `refresh`, with a
    /// failure backoff so an unreachable source is retried at most every
    /// few seconds, never per request).
    pub(crate) fn refresh_due(&self) -> bool {
        if self.is_static() {
            return false;
        }
        let state = lock(&self.state);
        let backoff = Duration::from_secs(1u64 << state.failures.min(5)).min(self.refresh);
        let attempted_recently = state.last_attempt.is_some_and(|t| t.elapsed() < backoff);
        !attempted_recently && state.fetched_at.is_none_or(|t| t.elapsed() >= self.refresh)
    }

    /// Keys for verification: the cached set, or a single-flight fetch when
    /// there is none (first use, or the cached set aged beyond `max_stale`).
    pub(crate) async fn keys(&self) -> Result<Arc<KeySet>, Error> {
        if let Some(keys) = self.usable() {
            return Ok(keys);
        }
        if self.is_static() {
            return Err(Error::Unavailable);
        }
        let _flight = self.flight.lock().await;
        if let Some(keys) = self.usable() {
            return Ok(keys);
        }
        {
            // Do not retry an unreachable source per request.
            let state = lock(&self.state);
            if state
                .last_attempt
                .is_some_and(|t| t.elapsed() < Duration::from_secs(1))
            {
                return Err(Error::Unavailable);
            }
        }
        self.fetch().await.map_err(|_| Error::Unavailable)
    }

    /// A token named a `kid` that `seen` lacks: refetch unless one happened
    /// within `kid_miss_interval`. Returns the newest usable set.
    pub(crate) async fn after_kid_miss(&self, seen: &Arc<KeySet>) -> Arc<KeySet> {
        if self.is_static() {
            return seen.clone();
        }
        let _flight = self.flight.lock().await;
        if let Some(current) = self.usable()
            && !Arc::ptr_eq(&current, seen)
        {
            return current;
        }
        let allowed = {
            let mut state = lock(&self.state);
            let ok = state
                .last_kid_miss
                .is_none_or(|t| t.elapsed() >= self.kid_miss_interval);
            if ok {
                state.last_kid_miss = Some(Instant::now());
            }
            ok
        };
        if !allowed {
            metrics::jwks_fetch(&self.service, "kid_miss_rate_limited");
            return seen.clone();
        }
        match self.fetch().await {
            Ok(keys) => keys,
            Err(_) => seen.clone(),
        }
    }

    /// Background refresh (single flight); failures keep the last good set.
    pub(crate) async fn refresh(&self) {
        let _flight = self.flight.lock().await;
        if self.refresh_due() {
            let _ = self.fetch().await;
        }
    }

    async fn fetch(&self) -> Result<Arc<KeySet>, &'static str> {
        lock(&self.state).last_attempt = Some(Instant::now());
        let result = tokio::time::timeout(self.timeout, self.fetch_inner())
            .await
            .unwrap_or(Err("timeout"));
        let mut state = lock(&self.state);
        match result {
            Ok((set, document_fp, jwks_uri)) => {
                let set = Arc::new(set);
                let changed = state.fingerprint != Some(document_fp);
                let (added, removed) = match &state.keys {
                    Some(old) if changed => {
                        let (old, new) = (kids(old), kids(&set));
                        (new.difference(&old).count(), old.difference(&new).count())
                    }
                    _ => (0, 0),
                };
                let first = state.keys.is_none();
                state.kids = set.keys.len();
                state.keys = Some(set.clone());
                state.fingerprint = Some(document_fp);
                state.fetched_at = Some(Instant::now());
                state.failures = 0;
                state.last_error = None;
                state.jwks_uri = jwks_uri;
                drop(state);
                metrics::jwks_fetch(&self.service, "ok");
                metrics::jwks_keys(&self.service, set.keys.len());
                if changed && !first {
                    metrics::jwks_fetch(&self.service, "rotated");
                    if let Some(f) = lock(&self.on_change).clone() {
                        f(added, removed);
                    }
                }
                Ok(set)
            }
            Err(reason) => {
                state.failures = state.failures.saturating_add(1);
                state.last_error = Some(reason);
                drop(state);
                metrics::jwks_fetch(&self.service, reason);
                tracing::warn!(
                    service = %self.service,
                    reason,
                    "Kubernetes workload signing keys could not be refreshed"
                );
                Err(reason)
            }
        }
    }

    async fn fetch_inner(&self) -> Result<(KeySet, [u8; 32], Option<url::Url>), &'static str> {
        let Source::Remote {
            client,
            discovery,
            jwks,
            jwks_origins,
            bearer,
        } = &self.source
        else {
            return Err("static");
        };
        let jwks_uri = if let Some(discovery) = discovery {
            let body = http::get_json(
                client,
                discovery,
                bearer,
                "application/json",
                MAX_DOCUMENT_BYTES,
                self.timeout,
            )
            .await?;
            let doc: serde_json::Value =
                serde_json::from_slice(&body).map_err(|_| "discovery_invalid")?;
            // Pinned issuer: the document must name exactly the configured one.
            if doc.get("issuer").and_then(|v| v.as_str()) != Some(self.issuer.as_str()) {
                return Err("discovery_issuer_mismatch");
            }
            let advertised = doc
                .get("jwks_uri")
                .and_then(|v| v.as_str())
                .ok_or("discovery_invalid")?;
            let advertised = http::https_url(advertised).map_err(|_| "jwks_uri_refused")?;
            match jwks {
                // A pinned JWKS URL must match what discovery advertises.
                Some(pinned) if pinned != &advertised => return Err("jwks_uri_mismatch"),
                Some(_) => {}
                None if !jwks_origins.contains(&http::origin(&advertised)) => {
                    return Err("jwks_uri_refused");
                }
                None => {}
            }
            advertised
        } else {
            jwks.clone().ok_or("static")?
        };
        let body = http::get_json(
            client,
            &jwks_uri,
            bearer,
            "application/jwk-set+json, application/json",
            MAX_DOCUMENT_BYTES,
            self.timeout,
        )
        .await?;
        let set = KeySet::parse(&body).map_err(|_| "jwks_invalid")?;
        Ok((set, fingerprint(&body), Some(jwks_uri)))
    }
}
