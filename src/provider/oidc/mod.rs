//! Generic OpenID Connect authorization-code client (ADR-0010).
//!
//! `begin` builds the authorization request (state, nonce, PKCE S256, always).
//! `complete` is the only place that talks to the provider after start-up:
//! discovery and JWKS (cached, hard deadline 24 h), token exchange (no
//! redirects, 10 s, 64 KiB), ID token validation, optional user-info with the
//! subject consistency check. Verify never calls this module.
//!
//! No secret reaches an error value, a log line or an event: errors are
//! reason codes, transports are logged by class, and bodies are never logged.

pub mod claims;
pub mod discovery;
pub mod http;
pub mod idtoken;
pub mod jwks;

use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use serde_json::Value;

use self::discovery::{Cache, Discovery, TokenAuth, discovery_url};
use self::http::{EndpointPolicy, Fetcher, Response};
use self::jwks::{KeySet, Selection};
use crate::crypto::{Clock, Rng, Secret, Timestamp, ct_eq, random_token, sha256};
use crate::event::types::Reason;
use crate::provider::presets;
use crate::provider::types::{
    AuthorizationRequest, CallbackQuery, Provider, ProviderError, ProviderHealth, ProviderId,
    ProviderIdentity, ProviderKind, ReauthCapability, ReauthPrompt, ReauthRequest,
};
use crate::store::types::{ProviderRow, TransactionRow};

/// Minimum spacing between JWKS fetch attempts when a token names a `kid`
/// the cached set does not contain.
pub const JWKS_REFETCH_INTERVAL: Duration = Duration::from_secs(60);

/// A provider-side failure worth an operator's attention (`provider.error`).
/// Carries reason codes only.
#[derive(Clone, Debug)]
pub struct ProviderReport {
    pub provider_id: ProviderId,
    /// `discovery`, `jwks`, `token` or `userinfo`.
    pub endpoint: &'static str,
    pub reason: Reason,
    pub status: Option<u16>,
}

/// Receives [`ProviderReport`]s; must not block.
pub type Reporter = Arc<dyn Fn(ProviderReport) + Send + Sync>;

/// Everything the client needs; built from a `providers` row.
#[derive(Clone)]
pub struct OidcSettings {
    pub provider_id: ProviderId,
    pub display_name: String,
    /// Why this provider is not usable, if it is not: `disabled`, `deleted`,
    /// `secret_missing`, `misconfigured`.
    pub disabled_reason: Option<&'static str>,
    pub client_id: String,
    pub client_secret: Option<Secret>,
    pub issuer: String,
    pub scope: String,
    /// Lower-case.
    pub authoritative_domains: Vec<String>,
    pub trust_email: bool,
    pub userinfo: bool,
    /// Whether a reauthentication request also carries `prompt=login`
    /// (stored setting `reauth_prompt`, default `login`).
    pub reauth_prompt: ReauthPrompt,
    /// Required `typ` header of the ID token, when the provider sets one.
    pub id_token_typ: Option<String>,
    /// Where the client may send requests (G7-IDP-03).
    pub endpoints: EndpointPolicy,
}

fn cfg_str(cfg: &Value, key: &str) -> Option<String> {
    cfg.get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .map(str::to_string)
}

/// The preset a row names (`preset`), is called after (no `issuer`), or whose
/// issuer matches.
fn preset_of(row: &ProviderRow) -> Option<&'static presets::Preset> {
    let cfg = &row.config;
    cfg_str(cfg, "preset")
        .and_then(|n| presets::by_name(&n))
        .or_else(|| {
            if cfg_str(cfg, "issuer").is_none() {
                presets::by_name(row.provider_id.as_str())
            } else {
                None
            }
        })
        .or_else(|| cfg_str(cfg, "issuer").and_then(|i| presets::by_issuer(&i)))
}

/// The reauthentication settings a row resolves to: the stored settings
/// `reauth` and `reauth_prompt` win, then the preset's capability, then
/// `max_age` and `login` (ADR-0016 decision 15). An unreadable stored value
/// is ignored.
pub fn reauth_settings(row: &ProviderRow) -> (ReauthCapability, ReauthPrompt) {
    let capability = cfg_str(&row.config, "reauth")
        .and_then(|s| ReauthCapability::parse(&s))
        .or_else(|| preset_of(row).map(|p| p.reauth))
        .unwrap_or(ReauthCapability::MaxAge);
    let prompt = cfg_str(&row.config, "reauth_prompt")
        .and_then(|s| ReauthPrompt::parse(&s))
        .unwrap_or(ReauthPrompt::Login);
    (capability, prompt)
}

impl OidcSettings {
    /// Read the row. `env` resolves `client_secret_env`; an absent or empty
    /// variable disables the provider (ADR-0010). Never fails: an unusable
    /// row becomes a disabled provider with a reason.
    pub fn from_row(row: &ProviderRow, env: &dyn Fn(&str) -> Option<String>) -> OidcSettings {
        let cfg = &row.config;
        let preset = preset_of(row);
        let issuer = cfg_str(cfg, "issuer")
            .or_else(|| preset.map(|p| p.issuer.to_string()))
            .unwrap_or_default();
        let client_id = cfg_str(cfg, "client_id").unwrap_or_default();
        let scope = cfg_str(cfg, "scope")
            .or_else(|| preset.map(|p| p.scope.to_string()))
            .unwrap_or_else(|| "openid email profile".to_string());
        let userinfo = cfg
            .get("userinfo")
            .and_then(Value::as_bool)
            .unwrap_or_else(|| preset.is_none_or(|p| p.userinfo));

        // Private and loopback destinations (and `http` to a loopback issuer)
        // only when the provider opts in; `test-hooks` builds default to it so
        // the loopback mock provider works. An explicit `false` always wins.
        let allow_private = cfg
            .get("allow_private_endpoints")
            .and_then(Value::as_bool)
            .unwrap_or(cfg!(feature = "test-hooks"));
        let mut hosts: Vec<String> = preset
            .map(|p| p.endpoint_hosts.iter().map(|h| h.to_string()).collect())
            .unwrap_or_default();
        if let Some(list) = cfg.get("endpoint_hosts").and_then(Value::as_array) {
            hosts.extend(list.iter().filter_map(Value::as_str).map(str::to_string));
        }
        let endpoints = EndpointPolicy::new(&issuer, &hosts, allow_private);
        let issuer_ok =
            url::Url::parse(&issuer).is_ok_and(|u| endpoints.url_ok(&u) && u.query().is_none());
        let mut client_secret = None;
        let mut disabled_reason = None;
        if row.deleted_at.is_some() {
            disabled_reason = Some("deleted");
        } else if !row.enabled {
            disabled_reason = Some("disabled");
        } else if client_id.is_empty() || !issuer_ok || row.kind != ProviderKind::Oidc {
            disabled_reason = Some("misconfigured");
        } else if let Some(name) = &row.client_secret_env {
            match env(name).filter(|v| !v.is_empty()) {
                Some(v) => client_secret = Some(Secret::new(v)),
                None => disabled_reason = Some("secret_missing"),
            }
        }
        OidcSettings {
            provider_id: row.provider_id.clone(),
            display_name: row.display_name.clone(),
            disabled_reason,
            client_id,
            client_secret,
            issuer,
            scope,
            authoritative_domains: row
                .authoritative_domains
                .iter()
                .map(|d| d.to_ascii_lowercase())
                .collect(),
            trust_email: row.trust_email,
            userinfo,
            reauth_prompt: reauth_settings(row).1,
            id_token_typ: cfg_str(cfg, "id_token_typ"),
            endpoints,
        }
    }
}

struct JwksState {
    cache: Cache<KeySet>,
    /// The `jwks_uri` the cached set was fetched from.
    uri: Option<url::Url>,
    /// When the last refetch for an unknown `kid` happened. Only these count
    /// against [`JWKS_REFETCH_INTERVAL`]: scheduled refreshes do not, so a key
    /// rotation never fails a login unless an unknown-`kid` refetch already
    /// happened in the last 60 s (ADR-0010).
    last_unknown_kid_refetch: Option<Timestamp>,
}

pub struct OidcProvider {
    s: OidcSettings,
    fetcher: Fetcher,
    clock: Arc<dyn Clock>,
    reporter: Option<Reporter>,
    disc: Mutex<Cache<Discovery>>,
    disc_flight: tokio::sync::Mutex<()>,
    jwks: Mutex<JwksState>,
    jwks_flight: tokio::sync::Mutex<()>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    // A poisoned lock only means a panic elsewhere; the cache data is still
    // internally consistent (plain fields), so keep serving.
    m.lock().unwrap_or_else(|p| p.into_inner())
}

impl OidcProvider {
    pub fn new(s: OidcSettings, clock: Arc<dyn Clock>, reporter: Option<Reporter>) -> Arc<Self> {
        Arc::new(OidcProvider {
            fetcher: Fetcher::new(s.endpoints.allow_private()),
            s,
            clock,
            reporter,
            disc: Mutex::new(Cache::empty()),
            disc_flight: tokio::sync::Mutex::new(()),
            jwks: Mutex::new(JwksState {
                cache: Cache::empty(),
                uri: None,
                last_unknown_kid_refetch: None,
            }),
            jwks_flight: tokio::sync::Mutex::new(()),
        })
    }

    pub fn from_row(
        row: &ProviderRow,
        env: &dyn Fn(&str) -> Option<String>,
        clock: Arc<dyn Clock>,
        reporter: Option<Reporter>,
    ) -> Arc<Self> {
        Self::new(OidcSettings::from_row(row, env), clock, reporter)
    }

    /// Why the provider is unusable, if it is.
    pub fn disabled_reason(&self) -> Option<&'static str> {
        self.s.disabled_reason
    }

    fn usable(&self) -> bool {
        self.s.disabled_reason.is_none()
    }

    fn report(&self, endpoint: &'static str, err: &ProviderError, started: Instant) {
        let status = match err {
            ProviderError::ProviderError { status } => Some(*status),
            _ => None,
        };
        tracing::warn!(
            provider = %self.s.provider_id,
            endpoint,
            reason = err.reason().0,
            status,
            elapsed_ms = started.elapsed().as_millis() as u64,
            "provider request failed"
        );
        if let Some(r) = &self.reporter {
            r(ProviderReport {
                provider_id: self.s.provider_id.clone(),
                endpoint,
                reason: err.reason(),
                status,
            });
        }
    }

    // ---- discovery -------------------------------------------------------

    /// The discovery document, fetching it when none within the hard deadline
    /// is held and the backoff allows. Never returns a stale document.
    async fn discovery(&self) -> Result<Arc<Discovery>, ProviderError> {
        if let Some(d) = lock(&self.disc).valid(self.clock.now()) {
            return Ok(d);
        }
        let _flight = self.disc_flight.lock().await;
        let now = self.clock.now();
        {
            let c = lock(&self.disc);
            if let Some(d) = c.valid(now) {
                return Ok(d);
            }
            if !c.may_attempt(now) {
                return Err(ProviderError::ProviderUnavailable);
            }
        }
        self.fetch_discovery().await
    }

    /// Fetch and install. The caller holds `disc_flight` and has checked the
    /// backoff. A failure keeps any previous document (it still obeys the
    /// hard deadline) and schedules the next attempt.
    async fn fetch_discovery(&self) -> Result<Arc<Discovery>, ProviderError> {
        let started = Instant::now();
        let result = self.fetch_discovery_inner().await;
        let now = self.clock.now();
        match result {
            Ok(d) => {
                let d = Arc::new(d);
                lock(&self.disc).record_ok(d.clone(), now);
                Ok(d)
            }
            Err(e) => {
                lock(&self.disc).record_err(now, e.reason().0);
                self.report("discovery", &e, started);
                Err(e)
            }
        }
    }

    async fn fetch_discovery_inner(&self) -> Result<Discovery, ProviderError> {
        let url = discovery_url(&self.s.issuer, &self.s.endpoints)
            .ok_or(ProviderError::ProviderUnavailable)?;
        let resp = self
            .fetcher
            .send(self.fetcher.get(&url).header("accept", "application/json"))
            .await?;
        match resp.status {
            200 => {}
            300..=399 => return Err(ProviderError::ProviderResponseInvalid),
            _ => return Err(ProviderError::ProviderUnavailable),
        }
        Discovery::parse(&resp.body, &self.s.issuer, &self.s.endpoints)
    }

    /// Refresh the discovery document if it is missing, expired or past
    /// half-life and the backoff allows; failures are recorded, not returned.
    /// The background task calls this; tests call it directly.
    pub async fn refresh_discovery(&self) {
        if !self.usable() {
            return;
        }
        let due = |s: &Self| {
            let now = s.clock.now();
            let c = lock(&s.disc);
            c.refresh_due(now) && c.may_attempt(now)
        };
        if !due(self) {
            return;
        }
        let _flight = self.disc_flight.lock().await;
        if !due(self) {
            return;
        }
        let _ = self.fetch_discovery().await;
    }

    /// Refresh the JWKS at half-life (best effort, only when one is held).
    pub async fn refresh_jwks(&self) {
        if !self.usable() {
            return;
        }
        let Some(disc) = lock(&self.disc).valid(self.clock.now()) else {
            return;
        };
        let due = |s: &Self| {
            let now = s.clock.now();
            let j = lock(&s.jwks);
            j.cache.valid(now).is_some() && j.cache.refresh_due(now) && j.cache.may_attempt(now)
        };
        if !due(self) {
            return;
        }
        let _flight = self.jwks_flight.lock().await;
        if due(self) {
            let _ = self.fetch_jwks(&disc).await;
        }
    }

    /// Start the background refresher on the current runtime. It holds only a
    /// weak reference and stops when the provider is dropped.
    pub fn spawn_refresher(self: &Arc<Self>) {
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let weak: Weak<OidcProvider> = Arc::downgrade(self);
        handle.spawn(async move {
            loop {
                let Some(p) = weak.upgrade() else { break };
                p.refresh_discovery().await;
                p.refresh_jwks().await;
                drop(p);
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        });
    }

    // ---- JWKS ------------------------------------------------------------

    async fn fetch_jwks(&self, disc: &Discovery) -> Result<Arc<KeySet>, ProviderError> {
        let started = Instant::now();
        let result = self.fetch_jwks_inner(disc).await;
        let now = self.clock.now();
        let mut j = lock(&self.jwks);
        match result {
            Ok(set) => {
                let set = Arc::new(set);
                j.cache.record_ok(set.clone(), now);
                j.uri = Some(disc.jwks_uri.clone());
                Ok(set)
            }
            Err(e) => {
                j.cache.record_err(now, e.reason().0);
                drop(j);
                self.report("jwks", &e, started);
                Err(e)
            }
        }
    }

    async fn fetch_jwks_inner(&self, disc: &Discovery) -> Result<KeySet, ProviderError> {
        let resp = self
            .fetcher
            .send(
                self.fetcher
                    .get(&disc.jwks_uri)
                    .header("accept", "application/json"),
            )
            .await?;
        match resp.status {
            200 => {}
            300..=399 => return Err(ProviderError::ProviderResponseInvalid),
            _ => return Err(ProviderError::ProviderUnavailable),
        }
        KeySet::parse(&resp.body)
    }

    /// The cached key set if within the hard deadline and fetched from the
    /// current `jwks_uri`.
    fn cached_keys(&self, disc: &Discovery) -> Option<Arc<KeySet>> {
        let j = lock(&self.jwks);
        if j.uri.as_ref() != Some(&disc.jwks_uri) {
            return None;
        }
        j.cache.valid(self.clock.now())
    }

    /// The current key set and whether this call fetched it (a set fetched
    /// for this very token is not refetched for its unknown `kid`).
    async fn keys(&self, disc: &Discovery) -> Result<(Arc<KeySet>, bool), ProviderError> {
        if let Some(k) = self.cached_keys(disc) {
            return Ok((k, false));
        }
        let _flight = self.jwks_flight.lock().await;
        if let Some(k) = self.cached_keys(disc) {
            return Ok((k, false));
        }
        {
            let mut j = lock(&self.jwks);
            if j.uri.as_ref() != Some(&disc.jwks_uri) {
                j.cache.clear_value();
            }
            if !j.cache.may_attempt(self.clock.now()) {
                return Err(ProviderError::ProviderUnavailable);
            }
        }
        self.fetch_jwks(disc).await.map(|k| (k, true))
    }

    /// A token named a `kid` the cached set lacks. Fetch again unless a
    /// refetch for an unknown `kid` happened within [`JWKS_REFETCH_INTERVAL`]
    /// (scheduled refreshes do not count). Returns the newest set either way.
    async fn keys_after_unknown_kid(
        &self,
        disc: &Discovery,
        seen: &Arc<KeySet>,
    ) -> Result<Arc<KeySet>, ProviderError> {
        let _flight = self.jwks_flight.lock().await;
        if let Some(k) = self.cached_keys(disc)
            && !Arc::ptr_eq(&k, seen)
        {
            return Ok(k); // someone refreshed while we waited
        }
        let now = self.clock.now();
        let allowed = {
            let mut j = lock(&self.jwks);
            let ok = j
                .last_unknown_kid_refetch
                .is_none_or(|t| now.since(t) >= JWKS_REFETCH_INTERVAL)
                && j.cache.may_attempt(now);
            if ok {
                j.last_unknown_kid_refetch = Some(now);
            }
            ok
        };
        if !allowed {
            return Ok(seen.clone());
        }
        // A failed refetch must not turn into an outage while the cached set
        // is still inside its deadline; the token is rejected as unknown-kid.
        match self.fetch_jwks(disc).await {
            Ok(k) => Ok(k),
            Err(_) => Ok(seen.clone()),
        }
    }

    // ---- token exchange --------------------------------------------------

    async fn exchange(
        &self,
        disc: &Discovery,
        code: &str,
        verifier: &str,
        redirect_uri: &url::Url,
    ) -> Result<Value, ProviderError> {
        let started = Instant::now();
        let result = self
            .exchange_inner(disc, code, verifier, redirect_uri)
            .await;
        if let Err(e) = &result {
            self.report("token", e, started);
        }
        result
    }

    async fn exchange_inner(
        &self,
        disc: &Discovery,
        code: &str,
        verifier: &str,
        redirect_uri: &url::Url,
    ) -> Result<Value, ProviderError> {
        let (req, body) = {
            let mut form = form_urlencoded::Serializer::new(String::new());
            form.append_pair("grant_type", "authorization_code")
                .append_pair("code", code)
                .append_pair("redirect_uri", redirect_uri.as_str())
                .append_pair("code_verifier", verifier);
            let mut req = self
                .fetcher
                .post(&disc.token_endpoint)
                .header("accept", "application/json")
                .header("content-type", "application/x-www-form-urlencoded");
            match (&self.s.client_secret, disc.token_auth) {
                (Some(secret), TokenAuth::Basic) => {
                    let enc =
                        |v: &str| form_urlencoded::byte_serialize(v.as_bytes()).collect::<String>();
                    let cred = STANDARD.encode(format!(
                        "{}:{}",
                        enc(&self.s.client_id),
                        enc(secret.expose())
                    ));
                    let mut v = reqwest::header::HeaderValue::from_str(&format!("Basic {cred}"))
                        .map_err(|_| ProviderError::ProviderUnavailable)?;
                    v.set_sensitive(true);
                    req = req.header(reqwest::header::AUTHORIZATION, v);
                }
                (Some(secret), TokenAuth::Post) => {
                    form.append_pair("client_id", &self.s.client_id)
                        .append_pair("client_secret", secret.expose());
                }
                (None, _) => {
                    form.append_pair("client_id", &self.s.client_id);
                }
            }
            (req, form.finish())
        };
        let resp = self.fetcher.send(req.body(body)).await?;
        check_status(&resp)?;
        let body: Value = serde_json::from_slice(&resp.body)
            .map_err(|_| ProviderError::ProviderResponseInvalid)?;
        if !body.is_object() {
            return Err(ProviderError::ProviderResponseInvalid);
        }
        Ok(body)
    }

    async fn fetch_userinfo(
        &self,
        endpoint: &url::Url,
        access_token: &str,
    ) -> Result<Value, ProviderError> {
        let started = Instant::now();
        let result = async {
            let mut auth =
                reqwest::header::HeaderValue::from_str(&format!("Bearer {access_token}"))
                    .map_err(|_| ProviderError::ProviderResponseInvalid)?;
            auth.set_sensitive(true);
            let req = self
                .fetcher
                .get(endpoint)
                .header("accept", "application/json")
                .header(reqwest::header::AUTHORIZATION, auth);
            let resp = self.fetcher.send(req).await?;
            check_status(&resp)?;
            if resp
                .content_type
                .as_deref()
                .is_some_and(|c| c.starts_with("application/jwt"))
            {
                // A signed user-info response is not supported; do not guess.
                return Err(ProviderError::ProviderResponseInvalid);
            }
            let body: Value = serde_json::from_slice(&resp.body)
                .map_err(|_| ProviderError::ProviderResponseInvalid)?;
            if !body.is_object() {
                return Err(ProviderError::ProviderResponseInvalid);
            }
            Ok(body)
        }
        .await;
        if let Err(e) = &result {
            self.report("userinfo", e, started);
        }
        result
    }

    // ---- ID token --------------------------------------------------------

    /// Header, issuer pre-check, signature (with `kid` handling and the
    /// rate-limited refetch), then claims. Returns the verified payload.
    async fn validate_id_token(
        &self,
        disc: &Discovery,
        token: &str,
        nonce: &str,
    ) -> Result<Value, ProviderError> {
        let header = idtoken::parse_header(token, &disc.algs, self.s.id_token_typ.as_deref())?;
        // A token from another issuer is reported as such even though its
        // signature would not verify here; either way it is rejected.
        if idtoken::peek_issuer(token).is_some_and(|i| i != disc.issuer) {
            return Err(ProviderError::InvalidIssuer);
        }
        let (mut keys, mut refetched) = self.keys(disc).await?;
        let payload = loop {
            match keys.select(header.alg, header.kid.as_deref()) {
                Selection::Candidates(cands) => {
                    let mut last = ProviderError::InvalidSignature;
                    let mut found = None;
                    for c in cands {
                        match idtoken::verify_signature(token, &header, &c.key) {
                            Ok(p) => {
                                found = Some(p);
                                break;
                            }
                            Err(e) => last = e,
                        }
                    }
                    break found.ok_or(last)?;
                }
                Selection::UnknownKid if !refetched => {
                    refetched = true;
                    keys = self.keys_after_unknown_kid(disc, &keys).await?;
                }
                Selection::UnknownKid | Selection::NoKey => {
                    return Err(ProviderError::InvalidSignature);
                }
                Selection::Ambiguous => return Err(ProviderError::InvalidTokenHeader),
            }
        };
        // The clock is read here, after the token exchange and the key
        // retrieval, not when the callback began (G7-IDP-05).
        idtoken::validate_claims(
            &payload,
            &idtoken::Expect {
                issuer: &disc.issuer,
                client_id: &self.s.client_id,
                nonce,
                now: self.clock.now(),
            },
        )?;
        Ok(payload)
    }
}

/// 200 is success. A redirect is never followed and is a malformed answer;
/// other statuses carry the status code.
fn check_status(resp: &Response) -> Result<(), ProviderError> {
    match resp.status {
        200 => Ok(()),
        300..=399 => Err(ProviderError::ProviderResponseInvalid),
        400..=599 => Err(ProviderError::ProviderError {
            status: resp.status,
        }),
        _ => Err(ProviderError::ProviderResponseInvalid),
    }
}

fn pkce_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(sha256(verifier.as_bytes()).0)
}

/// The scope string always contains `openid`.
fn scope_with_openid(scope: &str) -> String {
    if scope.split_ascii_whitespace().any(|s| s == "openid") {
        scope.to_string()
    } else {
        format!("openid {scope}")
    }
}

#[async_trait]
impl Provider for OidcProvider {
    fn id(&self) -> &ProviderId {
        &self.s.provider_id
    }

    fn kind(&self) -> ProviderKind {
        ProviderKind::Oidc
    }

    fn display_name(&self) -> &str {
        &self.s.display_name
    }

    fn enabled(&self) -> bool {
        self.usable()
    }

    async fn begin(
        &self,
        txn: &TransactionRow,
        redirect_uri: &url::Url,
        rng: &dyn Rng,
    ) -> Result<AuthorizationRequest, ProviderError> {
        self.begin_reauth(txn, redirect_uri, rng, None).await
    }

    async fn begin_reauth(
        &self,
        _txn: &TransactionRow,
        redirect_uri: &url::Url,
        rng: &dyn Rng,
        reauth: Option<ReauthRequest>,
    ) -> Result<AuthorizationRequest, ProviderError> {
        if !self.usable() {
            return Err(ProviderError::ProviderDisabled);
        }
        let disc = self.discovery().await?;
        let state = random_token(rng, 32);
        let nonce = random_token(rng, 32).expose().to_string();
        let verifier = random_token(rng, 32);
        let mut url = disc.authorization_endpoint.clone();
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.s.client_id)
            .append_pair("redirect_uri", redirect_uri.as_str())
            .append_pair("scope", &scope_with_openid(&self.s.scope))
            .append_pair("state", state.expose())
            .append_pair("nonce", &nonce)
            .append_pair("code_challenge", &pkce_challenge(verifier.expose()))
            .append_pair("code_challenge_method", "S256");
        if let Some(r) = reauth {
            let mut q = url.query_pairs_mut();
            q.append_pair("max_age", &r.max_age.as_secs().to_string());
            if self.s.reauth_prompt == ReauthPrompt::Login {
                q.append_pair("prompt", "login");
            }
        }
        Ok(AuthorizationRequest {
            url,
            state,
            nonce: Some(nonce),
            pkce_verifier: Some(verifier),
        })
    }

    async fn complete(
        &self,
        txn: &TransactionRow,
        callback: &CallbackQuery,
        redirect_uri: &url::Url,
    ) -> Result<ProviderIdentity, ProviderError> {
        if !self.usable() {
            return Err(ProviderError::ProviderDisabled);
        }
        // The transaction must be this provider's, unconsumed, and the state
        // the one issued for it. The portal looks the transaction up by state;
        // these checks do not rely on that.
        if txn.provider_id.as_ref() != Some(&self.s.provider_id) || txn.consumed_at.is_some() {
            return Err(ProviderError::InvalidState);
        }
        let (Some(state), Some(want)) = (callback.state.as_deref(), txn.state_sha256) else {
            return Err(ProviderError::InvalidState);
        };
        if !ct_eq(&sha256(state.as_bytes()).0, &want.0) {
            return Err(ProviderError::InvalidState);
        }
        let (Some(nonce), Some(verifier)) = (txn.nonce.as_deref(), txn.pkce_verifier.as_ref())
        else {
            return Err(ProviderError::InvalidState);
        };
        // The provider's own error response (for example the user declined).
        if callback.error.is_some() {
            return Err(ProviderError::ProviderError { status: 400 });
        }
        let code = match callback.code.as_deref() {
            Some(c) if !c.is_empty() && c.len() <= 2048 => c,
            _ => return Err(ProviderError::ProviderResponseInvalid),
        };

        let disc = self.discovery().await?;
        let tokens = self
            .exchange(&disc, code, verifier.expose(), redirect_uri)
            .await?;
        let id_token = match tokens.get("id_token") {
            None | Some(Value::Null) => return Err(ProviderError::IdTokenMissing),
            Some(Value::String(t)) => t.as_str(),
            Some(_) => return Err(ProviderError::ProviderResponseInvalid),
        };
        let claims = self.validate_id_token(&disc, id_token, nonce).await?;

        let mut userinfo = None;
        if self.s.userinfo
            && let Some(endpoint) = &disc.userinfo_endpoint
        {
            let bearer = tokens
                .get("token_type")
                .and_then(Value::as_str)
                .is_none_or(|t| t.eq_ignore_ascii_case("bearer"));
            let access = tokens.get("access_token").and_then(Value::as_str);
            let (true, Some(access)) = (bearer, access) else {
                return Err(ProviderError::ProviderResponseInvalid);
            };
            let ui = self.fetch_userinfo(endpoint, access).await?;
            // OpenID Connect Core 5.3.2: the user-info `sub` MUST equal the
            // ID token's. Checked before any user-info claim is read.
            let same = match (
                ui.get("sub").and_then(Value::as_str),
                claims.get("sub").and_then(Value::as_str),
            ) {
                (Some(a), Some(b)) => ct_eq(a.as_bytes(), b.as_bytes()),
                _ => false,
            };
            if !same {
                return Err(ProviderError::UserinfoSubjectMismatch);
            }
            userinfo = Some(ui);
        }

        Ok(claims::build(
            &claims,
            userinfo.as_ref(),
            &claims::Rules {
                authoritative_domains: &self.s.authoritative_domains,
                trust_email: self.s.trust_email,
            },
        ))
    }

    async fn ensure_ready(&self) -> ProviderHealth {
        let h = self.health().await;
        if h == ProviderHealth::Ok || h == ProviderHealth::Disabled {
            return h;
        }
        // Waits for an in-flight fetch, or starts one if the backoff allows.
        let _ = tokio::time::timeout(Duration::from_secs(2), self.refresh_discovery()).await;
        self.health().await
    }

    fn authorization_origin(&self) -> Option<url::Origin> {
        let disc = lock(&self.disc).valid(self.clock.now())?;
        let o = disc.authorization_endpoint.origin();
        o.is_tuple().then_some(o)
    }

    async fn health(&self) -> ProviderHealth {
        if !self.usable() {
            return ProviderHealth::Disabled;
        }
        let c = lock(&self.disc);
        if c.valid(self.clock.now()).is_some() {
            ProviderHealth::Ok
        } else {
            ProviderHealth::Degraded(c.last_error().unwrap_or("discovery_pending"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_challenge_matches_rfc7636_appendix_b() {
        assert_eq!(
            pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    fn stored(id: &str, config: serde_json::Value) -> ProviderRow {
        ProviderRow {
            provider_id: ProviderId::new(id),
            kind: ProviderKind::Oidc,
            display_name: id.into(),
            enabled: true,
            managed_by: crate::store::types::ManagedBy::Api,
            deleted_at: None,
            sort_order: 0,
            config,
            client_secret_env: None,
            allowed_email_domains: vec![],
            authoritative_domains: vec![],
            auto_link: false,
            trust_email: false,
        }
    }

    #[test]
    fn stored_settings_override_the_preset_and_default_capability() {
        use serde_json::json;
        let cfg = json!({"client_id": "c", "issuer": "https://idp.example.test"});
        // Default: max_age with prompt=login.
        assert_eq!(
            reauth_settings(&stored("x", cfg.clone())),
            (ReauthCapability::MaxAge, ReauthPrompt::Login)
        );
        // The preset (Google) is unsupported; a stored `reauth` beats it.
        assert_eq!(
            reauth_settings(&stored("google", json!({"client_id": "c"}))).0,
            ReauthCapability::Unsupported
        );
        assert_eq!(
            reauth_settings(&stored(
                "google",
                json!({"client_id": "c", "reauth": "max_age", "reauth_prompt": "none"})
            )),
            (ReauthCapability::MaxAge, ReauthPrompt::None)
        );
        // A stored value on a generic provider, and an unreadable one.
        let mut c = cfg.clone();
        c["reauth"] = json!("unsupported");
        assert_eq!(
            reauth_settings(&stored("x", c)).0,
            ReauthCapability::Unsupported
        );
        let mut c = cfg;
        c["reauth"] = json!("sometimes");
        c["reauth_prompt"] = json!(5);
        assert_eq!(
            reauth_settings(&stored("x", c)),
            (ReauthCapability::MaxAge, ReauthPrompt::Login)
        );
        let s = OidcSettings::from_row(
            &stored(
                "x",
                json!({"client_id": "c", "issuer": "https://i.example.test", "reauth_prompt": "none"}),
            ),
            &|_| None,
        );
        assert_eq!(s.reauth_prompt, ReauthPrompt::None);
    }

    #[test]
    fn scope_always_has_openid() {
        assert_eq!(scope_with_openid("email profile"), "openid email profile");
        assert_eq!(scope_with_openid("openid email"), "openid email");
        assert_eq!(scope_with_openid("openidx"), "openid openidx");
    }
}
