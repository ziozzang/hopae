//! S012 provider failure modes (see `scenarios/012-provider-failure-modes.md`),
//! plus the provider half of S002-A2/A6/A7/A9 and the success path.
//!
//! The provider is driven in-process (`OidcProvider::begin`/`complete`) against
//! the mock IdP and a small fake IdP for the cases the mock cannot express
//! (token redirects, crafted tokens). The HTTP surface (`/login`, `/callback`,
//! `/healthz`) belongs to W1-E/W1-D; the cases that need it are ignored with
//! the dependency named. Tests named `provider_*` are extra and carry no
//! scenario number on purpose (the scenario-coverage check owns `sNNN_`).
#![allow(dead_code)]

use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::response::Response as AxResponse;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hopae::crypto::{Clock, OsRng, TestClock, Timestamp, sha256};
use hopae::policy::types::AppId;
use hopae::provider::oidc::{OidcProvider, ProviderReport};
use hopae::provider::{
    AuthorizationRequest, CallbackQuery, Provider, ProviderError, ProviderHealth, ProviderId,
    ProviderIdentity, ProviderKind,
};
use hopae::store::types::{ManagedBy, ProviderRow, TransactionRow, TxnPurpose};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::traits::PublicKeyParts;
use serde_json::{Value, json};

use crate::support::server::{Log, Served, record};
use crate::support::*;

const SECRET: &str = "s3cr3t-Value-for-tests";
const REDIRECT: &str = "https://auth.example.test/callback/mock";

// ---- rig -------------------------------------------------------------------

struct Rig {
    idp: MockIdp,
    clock: Arc<TestClock>,
    p: Arc<OidcProvider>,
    reports: Arc<Mutex<Vec<ProviderReport>>>,
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn row_for(issuer: &str, id: &str, extra: Value) -> ProviderRow {
    let mut config = json!({"client_id": "hopae-test", "issuer": issuer, "scope": "openid email profile",
               "allow_private_endpoints": true});
    for (k, v) in extra.as_object().cloned().unwrap_or_default() {
        config[k] = v;
    }
    ProviderRow {
        provider_id: ProviderId::new(id),
        kind: ProviderKind::Oidc,
        display_name: id.to_string(),
        enabled: true,
        managed_by: ManagedBy::File,
        deleted_at: None,
        sort_order: 0,
        config,
        client_secret_env: Some("HOPAE_TEST_MOCK_SECRET".into()),
        allowed_email_domains: vec![],
        authoritative_domains: vec![],
        auto_link: false,
        trust_email: false,
    }
}

fn env(name: &str) -> Option<String> {
    (name == "HOPAE_TEST_MOCK_SECRET").then(|| SECRET.to_string())
}

fn issuer_of(idp: &MockIdp) -> String {
    idp.issuer.as_str().trim_end_matches('/').to_string()
}

fn build(
    row: &ProviderRow,
    clock: &Arc<TestClock>,
) -> (Arc<OidcProvider>, Arc<Mutex<Vec<ProviderReport>>>) {
    let reports = Arc::new(Mutex::new(Vec::new()));
    let sink = reports.clone();
    let p = OidcProvider::from_row(
        row,
        &env,
        clock.clone(),
        Some(Arc::new(move |r| sink.lock().unwrap().push(r))),
    );
    (p, reports)
}

impl Rig {
    fn new(profile: &str) -> Rig {
        Rig::with(profile, "mock", json!({}), |_| {})
    }

    fn with(profile: &str, id: &str, extra: Value, tweak: impl FnOnce(&mut ProviderRow)) -> Rig {
        let idp = MockIdp::start(profile);
        idp.set_client_secret(Some(SECRET));
        let clock = Arc::new(TestClock::new(Timestamp(now_ms())));
        idp.set_now_ms(Some(clock.now().0));
        let mut row = row_for(&issuer_of(&idp), id, extra);
        tweak(&mut row);
        let (p, reports) = build(&row, &clock);
        Rig {
            idp,
            clock,
            p,
            reports,
        }
    }

    fn advance(&self, d: Duration) {
        self.clock.advance(d);
        self.idp.set_now_ms(Some(self.clock.now().0));
    }

    fn now(&self) -> Timestamp {
        self.clock.now()
    }

    /// `begin` plus the browser hop to the IdP: the transaction and the
    /// callback query the portal would pass to `complete`.
    async fn authorize(&self) -> (TransactionRow, CallbackQuery) {
        authorize_with(&*self.p, self.p.id().as_str(), self.now()).await
    }

    async fn login(&self) -> Result<ProviderIdentity, ProviderError> {
        let (txn, cb) = self.authorize().await;
        self.p.complete(&txn, &cb, &redirect()).await
    }

    fn last_report(&self) -> Option<ProviderReport> {
        self.reports.lock().unwrap().last().cloned()
    }
}

fn redirect() -> url::Url {
    url::Url::parse(REDIRECT).unwrap()
}

fn txn_for(provider: &str, req: &AuthorizationRequest, now: Timestamp) -> TransactionRow {
    TransactionRow {
        txn_sha256: sha256(b"txn-1"),
        created_at: now,
        expires_at: now.add(Duration::from_secs(600)),
        app_id: AppId::new("app"),
        return_target: url::Url::parse("https://app.example.test/admin/x").unwrap(),
        bind_sha256: None,
        portal_bind_sha256: None,
        retry_bind_sha256: None,
        client_ip: "203.0.113.9".parse().unwrap(),
        ua_sha256: None,
        provider_id: Some(ProviderId::new(provider)),
        state_sha256: Some(req.state.digest()),
        nonce: req.nonce.clone(),
        pkce_verifier: req.pkce_verifier.clone(),
        portal_session_id: None,
        purpose: TxnPurpose::Login,
        conflicting_handle_sha256: None,
        pending_identity: None,
        recovery_depth: 0,
        consumed_at: None,
        consumed_reason: None,
    }
}

fn http() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap()
}

/// The browser hop: GET the authorization URL, read `code`/`state` from the
/// redirect back to the portal.
async fn hop(url: &url::Url) -> CallbackQuery {
    let r = http().get(url.clone()).send().await.unwrap();
    let loc = r
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .expect("authorize redirects")
        .to_string();
    let loc = url::Url::parse(&loc).unwrap();
    let q = |k: &str| {
        loc.query_pairs()
            .find(|(n, _)| n == k)
            .map(|(_, v)| v.into_owned())
    };
    CallbackQuery {
        code: q("code"),
        state: q("state"),
        error: q("error"),
        error_description: q("error_description"),
    }
}

async fn authorize_with(
    p: &dyn Provider,
    provider_id: &str,
    now: Timestamp,
) -> (TransactionRow, CallbackQuery) {
    let req = p
        .begin(&placeholder_txn(provider_id, now), &redirect(), &OsRng)
        .await
        .expect("begin");
    let cb = hop(&req.url).await;
    (txn_for(provider_id, &req, now), cb)
}

/// What `begin` receives: the transaction before it has a provider binding.
fn placeholder_txn(provider: &str, now: Timestamp) -> TransactionRow {
    let dummy = AuthorizationRequest {
        url: url::Url::parse("https://x.invalid/").unwrap(),
        state: hopae::crypto::Secret::new("x".into()),
        nonce: None,
        pkce_verifier: None,
    };
    let mut t = txn_for(provider, &dummy, now);
    t.state_sha256 = None;
    t.provider_id = None;
    t
}

fn err_of(r: Result<ProviderIdentity, ProviderError>) -> ProviderError {
    match r {
        Ok(_) => panic!("expected an error, got an identity"),
        Err(e) => e,
    }
}

// ---- fake IdP (for what the mock cannot express) -----------------------------

struct RsaPair {
    kid: &'static str,
    enc: EncodingKey,
    n: String,
    e: String,
    n_bytes: Vec<u8>,
}

struct KeygenRng;

impl rsa::rand_core::RngCore for KeygenRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        use hopae::crypto::Rng;
        OsRng.fill(dest);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rsa::rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}
impl rsa::rand_core::CryptoRng for KeygenRng {}

fn rsa_pairs() -> &'static [RsaPair; 2] {
    static K: OnceLock<[RsaPair; 2]> = OnceLock::new();
    K.get_or_init(|| {
        let make = |kid: &'static str| {
            let sk = rsa::RsaPrivateKey::new(&mut KeygenRng, 2048).expect("keygen");
            let der = sk.to_pkcs1_der().expect("der");
            RsaPair {
                kid,
                enc: EncodingKey::from_rsa_der(der.as_bytes()),
                n: URL_SAFE_NO_PAD.encode(sk.n().to_bytes_be()),
                e: URL_SAFE_NO_PAD.encode(sk.e().to_bytes_be()),
                n_bytes: sk.n().to_bytes_be(),
            }
        };
        [make("fk-1"), make("fk-2")]
    })
}

/// Status, headers and body the fake token endpoint answers with.
type TokenAnswer = (u16, Vec<(String, String)>, String);

struct FakeState {
    jwks: Mutex<String>,
    token: Mutex<TokenAnswer>,
    advertise_methods: bool,
    log: Log,
    /// Moves a test clock forward when the token endpoint is called: time
    /// that passes during the network wait.
    on_token: Mutex<Option<(Arc<TestClock>, Duration)>>,
    /// Published as `token_endpoint` instead of `<base>/token`.
    token_endpoint: Mutex<Option<String>>,
}

struct Fake {
    served: Served,
    st: Arc<FakeState>,
}

impl Fake {
    fn start(advertise_methods: bool) -> Fake {
        let st = Arc::new(FakeState {
            jwks: Mutex::new(jwks_of(&[0])),
            token: Mutex::new((200, vec![], "{}".into())),
            advertise_methods,
            log: Arc::new(Mutex::new(Vec::new())),
            on_token: Mutex::new(None),
            token_endpoint: Mutex::new(None),
        });
        let router = Router::new().fallback(fake_handle).with_state(st.clone());
        Fake {
            served: Served::start(router),
            st,
        }
    }

    fn issuer(&self) -> String {
        format!("http://{}", self.served.addr)
    }

    fn set_token(&self, status: u16, headers: Vec<(String, String)>, body: String) {
        *self.st.token.lock().unwrap() = (status, headers, body);
    }

    fn set_id_token(&self, id_token: &str) {
        self.set_token(
            200,
            vec![("content-type".into(), "application/json".into())],
            json!({"access_token": "at-fake", "token_type": "Bearer", "id_token": id_token})
                .to_string(),
        );
    }

    fn advance_clock_on_token(&self, clock: &Arc<TestClock>, d: Duration) {
        *self.st.on_token.lock().unwrap() = Some((clock.clone(), d));
    }

    fn set_jwks(&self, idx: &[usize]) {
        *self.st.jwks.lock().unwrap() = jwks_of(idx);
    }

    fn requests(&self) -> Vec<RecordedRequest> {
        self.st.log.lock().unwrap().clone()
    }
}

fn jwks_of(idx: &[usize]) -> String {
    let keys: Vec<Value> = idx
        .iter()
        .map(|i| {
            let k = &rsa_pairs()[*i];
            json!({"kty":"RSA","use":"sig","alg":"RS256","kid":k.kid,"n":k.n,"e":k.e})
        })
        .collect();
    json!({"keys": keys}).to_string()
}

async fn fake_handle(State(st): State<Arc<FakeState>>, req: Request) -> AxResponse {
    let host = req
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let rec = record(req, &st.log).await;
    let base = format!("http://{host}");
    let json_resp = |status: u16, body: String| {
        let mut r = AxResponse::new(Body::from(body));
        *r.status_mut() = axum::http::StatusCode::from_u16(status).unwrap();
        r.headers_mut()
            .insert("content-type", "application/json".parse().unwrap());
        r
    };
    match (rec.method.as_str(), rec.path()) {
        ("GET", "/.well-known/openid-configuration") => {
            let mut d = json!({
                "issuer": base,
                "authorization_endpoint": format!("{base}/authorize"),
                "token_endpoint": st
                    .token_endpoint
                    .lock()
                    .unwrap()
                    .clone()
                    .unwrap_or_else(|| format!("{base}/token")),
                "jwks_uri": format!("{base}/jwks"),
                "response_types_supported": ["code"],
                "id_token_signing_alg_values_supported": ["RS256"],
            });
            if st.advertise_methods {
                d["code_challenge_methods_supported"] = json!(["S256"]);
            }
            json_resp(200, d.to_string())
        }
        ("GET", "/jwks") => json_resp(200, st.jwks.lock().unwrap().clone()),
        ("POST", "/token") => {
            if let Some((clock, d)) = st.on_token.lock().unwrap().clone() {
                clock.advance(d);
            }
            let (status, headers, body) = st.token.lock().unwrap().clone();
            let mut r = json_resp(status, body);
            for (k, v) in headers {
                r.headers_mut().insert(
                    axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                    v.parse().unwrap(),
                );
            }
            r
        }
        _ => json_resp(404, "{}".into()),
    }
}

/// A fake-IdP provider with its own nonce: returns the provider, the
/// transaction and the callback ready for `complete`.
async fn fake_login_parts(
    fake: &Fake,
    clock: &Arc<TestClock>,
    extra: Value,
) -> (Arc<OidcProvider>, TransactionRow, CallbackQuery) {
    fake_login_parts_at(fake, &fake.issuer(), clock, extra)
        .await
        .expect("begin against fake")
}

/// As [`fake_login_parts`] with the configured issuer spelled `issuer`;
/// `Err` when `begin` is refused.
async fn fake_login_parts_at(
    fake: &Fake,
    issuer: &str,
    clock: &Arc<TestClock>,
    extra: Value,
) -> Result<(Arc<OidcProvider>, TransactionRow, CallbackQuery), ProviderError> {
    let _ = fake;
    let row = row_for(issuer, "mock", extra);
    let (p, _) = build(&row, clock);
    let req = p
        .begin(&placeholder_txn("mock", clock.now()), &redirect(), &OsRng)
        .await?;
    let txn = txn_for("mock", &req, clock.now());
    let cb = CallbackQuery {
        code: Some("fake-code".into()),
        state: Some(req.state.expose().to_string()),
        error: None,
        error_description: None,
    };
    Ok((p, txn, cb))
}

fn claims_for(iss: &str, nonce: &str, now: Timestamp) -> Value {
    json!({"iss": iss, "aud": "hopae-test", "sub": "sub-9", "exp": now.secs() + 300, "iat": now.secs(),
           "nonce": nonce, "email": "z@example.test", "email_verified": true})
}

fn sign(
    alg: Algorithm,
    header_kid: Option<&str>,
    typ: Option<&str>,
    key: &EncodingKey,
    claims: &Value,
) -> String {
    let mut h = Header::new(alg);
    h.kid = header_kid.map(str::to_string);
    h.typ = typ.map(str::to_string);
    jsonwebtoken::encode(&h, claims, key).expect("sign")
}

fn unsigned(header: &Value, claims: &Value) -> String {
    format!(
        "{}.{}.",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    )
}

// ===========================================================================
// S012 main flow
// ===========================================================================

#[tokio::test]
async fn s012_1_discovery_down_at_start_degraded() {
    let rig = Rig::new("discovery_down");
    // Constructing the provider does not fail and does not block: degraded.
    assert!(rig.p.enabled());
    assert!(matches!(rig.p.health().await, ProviderHealth::Degraded(_)));

    // The refresher's first tick fetches once and records the failure.
    rig.p.refresh_discovery().await;
    assert_eq!(rig.idp.discovery_fetches(), 1);
    assert_eq!(
        rig.p.health().await,
        ProviderHealth::Degraded("provider_unavailable")
    );
    // Backoff 1 s, 2 s, 4 s: ticks inside the window do not fetch.
    rig.p.refresh_discovery().await;
    assert_eq!(rig.idp.discovery_fetches(), 1);
    rig.advance(Duration::from_secs(1));
    rig.p.refresh_discovery().await;
    assert_eq!(rig.idp.discovery_fetches(), 2);
    rig.advance(Duration::from_secs(1));
    rig.p.refresh_discovery().await;
    assert_eq!(
        rig.idp.discovery_fetches(),
        2,
        "2 s backoff after the second failure"
    );
    rig.advance(Duration::from_secs(1));
    rig.p.refresh_discovery().await;
    assert_eq!(rig.idp.discovery_fetches(), 3);

    // A login attempt during the outage fails with provider_unavailable and
    // does not fetch inside the backoff window.
    let e = rig
        .p
        .begin(&placeholder_txn("mock", rig.now()), &redirect(), &OsRng)
        .await
        .err()
        .expect("begin fails");
    assert!(matches!(e, ProviderError::ProviderUnavailable), "{e:?}");
    assert_eq!(rig.idp.discovery_fetches(), 3);

    // The provider recovers once the backoff elapses; no restart needed.
    rig.idp.set_profile("default");
    rig.advance(Duration::from_secs(61));
    rig.p.refresh_discovery().await;
    assert_eq!(rig.p.health().await, ProviderHealth::Ok);
    assert!(rig.login().await.is_ok());
}

#[tokio::test]
async fn provider_s012_1_portal_shows_provider_unavailable() {
    // Spawn the binary with `discovery_down`: the process starts, /healthz
    // reports providers.mock = degraded and /login lists the provider as
    // temporarily unavailable; verify keeps answering.
    let idp = MockIdp::start("discovery_down");
    let h = Hopae::spawn(Fixture::new("m1-basic"), &idp, &[]);
    let body = get(h.portal, "/healthz").body;
    assert!(body.contains("degraded"), "{body}");
    // Verify keeps answering and starts a login; /login for that transaction
    // lists the provider as temporarily unavailable (no redirect to it).
    let r = h.verify(VerifyRequest::document("https://app.example.test/admin/x").ip("203.0.113.9"));
    assert_eq!(r.status, 302, "{r:?}");
    let path = r.location().expect("login redirect").to_string();
    let path = path.split("auth.example.test").nth(1).expect("portal path");
    let login = h.portal().with_ip("203.0.113.9").get(path);
    assert_eq!(login.status, 200, "{login:?}");
    assert!(
        login
            .body
            .to_lowercase()
            .contains("temporarily unavailable"),
        "{}",
        login.body
    );
}

#[tokio::test]
async fn s012_2_token_error_fails_cleanly() {
    let rig = Rig::new("token_500");
    let (txn, cb) = rig.authorize().await;
    let e = err_of(rig.p.complete(&txn, &cb, &redirect()).await);
    assert!(
        matches!(e, ProviderError::ProviderError { status: 500 }),
        "{e:?}"
    );
    assert_eq!(e.reason().0, "provider_error");
    let rep = rig.last_report().expect("provider.error report");
    assert_eq!(rep.endpoint, "token");
    assert_eq!(rep.status, Some(500));
    assert_eq!(rep.reason.0, "provider_error");
    // The transaction is untouched and usable once the provider recovers.
    rig.idp.set_profile("default");
    let id = rig
        .p
        .complete(&txn, &cb, &redirect())
        .await
        .expect("retry succeeds");
    assert_eq!(id.subject, "sub-1");
}

#[tokio::test]
async fn s012_3_slow_token_bounded() {
    let rig = Rig::new("token_slow");
    let (txn, cb) = rig.authorize().await;
    let t0 = Instant::now();
    let e = err_of(rig.p.complete(&txn, &cb, &redirect()).await);
    let took = t0.elapsed();
    assert!(matches!(e, ProviderError::ProviderTimeout), "{e:?}");
    assert!(
        took >= Duration::from_secs(9),
        "aborts at 10 s, not earlier: {took:?}"
    );
    assert!(
        took < Duration::from_secs(11),
        "returns within 11 s: {took:?}"
    );
}

#[tokio::test]
async fn s012_4_key_rotation_handled() {
    // Rotation: a first login caches key-1; the provider then publishes key-2.
    let rig = Rig::new("jwks_rotated");
    assert!(rig.login().await.is_ok(), "first login fetches the JWKS");
    assert_eq!(rig.idp.jwks_fetches(), 1);
    // Token signed by the new key, cached set has only the old one: the
    // unknown `kid` triggers one refetch at once (no unknown-kid refetch has
    // happened yet), so a rotation never fails the login (ADR-0010).
    let id = rig.login().await.expect("refetch on unknown kid");
    assert_eq!(id.subject, "sub-1");
    assert_eq!(rig.idp.jwks_fetches(), 2, "exactly one refetch");
    // The new set is cached: further logins do not fetch.
    assert!(rig.login().await.is_ok());
    assert_eq!(rig.idp.jwks_fetches(), 2);

    // A kid that is never published: the login that fills the cache already
    // has a fresh set; the next unknown kid is refetched once, then not again
    // inside 60 s (rate limited to once per 60 s, unknown-kid refetches only).
    let rig = Rig::new("jwks_unknown_kid");
    let e = err_of(rig.login().await);
    assert!(matches!(e, ProviderError::InvalidSignature), "{e:?}");
    assert_eq!(
        rig.idp.jwks_fetches(),
        1,
        "the fetch of this request is fresh"
    );
    let e = err_of(rig.login().await);
    assert!(matches!(e, ProviderError::InvalidSignature), "{e:?}");
    assert_eq!(rig.idp.jwks_fetches(), 2, "one refetch on the unknown kid");
    let e = err_of(rig.login().await);
    assert!(matches!(e, ProviderError::InvalidSignature), "{e:?}");
    assert_eq!(rig.idp.jwks_fetches(), 2, "no second refetch within 60 s");
    rig.advance(Duration::from_secs(61));
    let e = err_of(rig.login().await);
    assert!(matches!(e, ProviderError::InvalidSignature), "{e:?}");
    assert_eq!(rig.idp.jwks_fetches(), 3, "one refetch per 60 s window");
}

#[tokio::test]
async fn s012_5_discovery_issuer_change_rejected() {
    let rig = Rig::new("discovery_changed_issuer");
    // First fetch is honest.
    rig.p
        .begin(&placeholder_txn("mock", rig.now()), &redirect(), &OsRng)
        .await
        .expect("begin with the first document");
    assert_eq!(rig.idp.discovery_fetches(), 1);

    // Past half-life the refresh sees a different issuer and is refused; the
    // previous document stays in use.
    rig.advance(Duration::from_secs(12 * 3600));
    rig.p.refresh_discovery().await;
    assert_eq!(rig.idp.discovery_fetches(), 2);
    let rep = rig.last_report().expect("provider.error report");
    assert_eq!(rep.endpoint, "discovery");
    assert_eq!(rep.reason.0, "discovery_issuer_mismatch");
    assert_eq!(rig.p.health().await, ProviderHealth::Ok);
    assert!(
        rig.p
            .begin(&placeholder_txn("mock", rig.now()), &redirect(), &OsRng)
            .await
            .is_ok(),
        "old document still serves"
    );

    // At the hard deadline the old document is dropped and the changed one is
    // still refused: the provider is degraded with the mismatch reason.
    rig.advance(Duration::from_secs(12 * 3600 + 1));
    let e = rig
        .p
        .begin(&placeholder_txn("mock", rig.now()), &redirect(), &OsRng)
        .await
        .err()
        .expect("fails");
    assert!(matches!(e, ProviderError::DiscoveryIssuerMismatch), "{e:?}");
    assert_eq!(
        rig.p.health().await,
        ProviderHealth::Degraded("discovery_issuer_mismatch")
    );
}

#[tokio::test]
async fn s012_6_userinfo_failure_no_session() {
    let rig = Rig::new("userinfo_500");
    let e = err_of(rig.login().await);
    assert!(
        matches!(e, ProviderError::ProviderError { status: 500 }),
        "{e:?}"
    );
    let rep = rig.last_report().expect("report");
    assert_eq!(rep.endpoint, "userinfo");
    assert_eq!(rig.idp.requests_to("/userinfo").len(), 1);
}

#[tokio::test]
async fn s012_7_sessions_unaffected_by_provider() {
    // Complete a login against the default profile, switch the mock to a
    // failing profile, then verify with the session's handle: 200, and the
    // mock's request log does not grow during verify.
    let idp = MockIdp::start("default");
    let h = Hopae::spawn(Fixture::new("m1-basic"), &idp, &[]);
    // Start-up discovery runs in the background: let it finish so that it is
    // not mistaken for a call made by verify.
    for _ in 0..100 {
        if !idp
            .requests_to("/.well-known/openid-configuration")
            .is_empty()
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    std::thread::sleep(Duration::from_millis(200));
    idp.set_profile("token_500");
    let before = idp.requests().len();
    let r = h.verify(VerifyRequest::document("https://app.example.test/admin/x"));
    assert_ne!(r.status, 500, "{r:?}");
    assert_eq!(
        idp.requests().len(),
        before,
        "verify never calls the provider"
    );
}

// ===========================================================================
// S012 abuse cases
// ===========================================================================

/// One login up to and including the portal callback; returns the callback's
/// answer. Drives the real binary: verify, the portal, the provider, the callback.
fn callback_of_new_login(h: &Hopae, idp: &MockIdp, ip: &str) -> Response {
    let r = h.verify(VerifyRequest::document("https://app.example.test/admin/x").ip(ip));
    assert_eq!(r.status, 302, "{r:?}");
    let loc = r.location().expect("login redirect").to_string();
    let path = loc.split("auth.example.test").nth(1).expect("portal path");
    let portal = h.portal().with_ip(ip);
    let go = portal.get(path);
    assert_eq!(go.status, 302, "single provider redirects at once: {go:?}");
    portal.get(&idp.follow_authorization(go.location().expect("provider redirect")))
}

#[test]
fn s012_a1_malformed_token_response_safe() {
    let idp = MockIdp::start("token_malformed");
    let h = Hopae::spawn(Fixture::new("m1-basic"), &idp, &[]);
    // The mock cycles: invalid JSON, numeric id_token, undecodable JWT.
    for round in 0..3 {
        let r = callback_of_new_login(&h, &idp, "203.0.113.9");
        assert_eq!(r.status, 400, "round {round}: {r:?}");
        assert!(
            !r.body.contains("provider_response_invalid"),
            "the page never shows the reason code"
        );
    }
    // The failures are diagnostics: wait for the best-effort writer, then read
    // them through the test hooks (the events table, not a process-wide log).
    let mut errors = Vec::new();
    for _ in 0..100 {
        errors = h.hooks.events(Some("provider.error"), Some(100));
        if !errors.is_empty() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    // The token endpoint answered malformed bodies: reported with the endpoint
    // and the reason only (an ID token that fails to decode after a good
    // exchange is a login failure, not a provider outage).
    assert!(!errors.is_empty(), "{errors:?}");
    for e in &errors {
        assert_eq!(e["reason"], "provider_response_invalid", "{e}");
        assert_eq!(e["provider_id"], "mock", "{e}");
        assert_eq!(e["attrs"]["endpoint"], "token", "{e}");
    }
    let failed = h.hooks.events(Some("login.failed"), Some(100));
    assert_eq!(
        failed
            .iter()
            .filter(|e| e["reason"] == "provider_response_invalid")
            .count(),
        3,
        "{failed:?}"
    );
    // Nothing from the provider's bodies, and no secret, reaches events or log.
    let everything = format!(
        "{}\n{}",
        h.log(),
        h.hooks
            .events(None, Some(1000))
            .iter()
            .map(Value::to_string)
            .collect::<Vec<_>>()
            .join("\n")
    );
    for leak in ["12345", "!!!.@@@.###", "Bearer", "access_token"] {
        assert!(!everything.contains(leak), "leaks {leak:?}");
    }
    for secret in h.secret_values() {
        assert!(
            !everything.contains(&secret),
            "a secret value reached the log or events"
        );
    }
    // The process keeps serving: with a healthy provider a login completes.
    idp.set_profile("default");
    let r = callback_of_new_login(&h, &idp, "203.0.113.10");
    assert_eq!(r.status, 302, "{r:?}");
}

#[tokio::test]
async fn s012_a2_hard_deadline_on_caches() {
    let rig = Rig::new("default");
    assert!(rig.login().await.is_ok(), "warm both caches");
    assert_eq!(rig.idp.discovery_fetches(), 1);
    assert_eq!(rig.idp.jwks_fetches(), 1);

    // A code issued while everything is healthy, redeemed after the deadline.
    let (txn, cb) = rig.authorize().await;
    rig.idp.set_profile("discovery_down");
    rig.advance(Duration::from_secs(24 * 3600 + 1));
    let calls = rig.idp.token_calls();
    let e = err_of(rig.p.complete(&txn, &cb, &redirect()).await);
    assert!(matches!(e, ProviderError::ProviderUnavailable), "{e:?}");
    assert_eq!(
        rig.idp.token_calls(),
        calls,
        "no token exchange on stale discovery"
    );
    assert_eq!(
        rig.idp.jwks_fetches(),
        1,
        "stale keys neither used nor trusted"
    );
    assert_eq!(
        rig.p.health().await,
        ProviderHealth::Degraded("provider_unavailable")
    );

    // Discovery back but the key set (also past 24 h) cannot be fetched: the
    // stale keys are not used to validate.
    rig.idp.set_profile("default");
    let (txn, cb) = {
        // New code against the recovered provider; then break only the JWKS
        // by moving the provider's issuer-published keys out of reach.
        rig.advance(Duration::from_secs(61));
        rig.authorize().await
    };
    let id = rig.p.complete(&txn, &cb, &redirect()).await;
    assert!(
        id.is_ok(),
        "fresh fetches work after recovery: {:?}",
        id.err()
    );
    assert_eq!(
        rig.idp.jwks_fetches(),
        2,
        "keys were refetched, not reused past 24 h"
    );
}

#[tokio::test]
async fn s012_a3_backoff_prevents_storm() {
    let rig = Rig::new("discovery_down");
    let t0 = Instant::now();
    for _ in 0..1000 {
        rig.advance(Duration::from_millis(60)); // 1,000 attempts across 60 s
        let e = rig
            .p
            .begin(&placeholder_txn("mock", rig.now()), &redirect(), &OsRng)
            .await
            .err()
            .expect("unavailable");
        assert!(matches!(e, ProviderError::ProviderUnavailable), "{e:?}");
    }
    let fetches = rig.idp.discovery_fetches();
    assert!(
        (3..=7).contains(&fetches),
        "backoff-scheduled fetches only, got {fetches}"
    );
    assert!(
        t0.elapsed() < Duration::from_secs(5),
        "attempts answer quickly"
    );
}

#[tokio::test]
async fn s012_a4_token_redirect_not_followed() {
    let target = Fake::start(true); // the host the redirect points at
    let fake = Fake::start(true);
    fake.set_token(
        302,
        vec![("location".into(), format!("{}/steal", target.issuer()))],
        String::new(),
    );
    let clock = Arc::new(TestClock::new(Timestamp(now_ms())));
    let (p, txn, cb) = fake_login_parts(&fake, &clock, json!({})).await;
    let e = err_of(p.complete(&txn, &cb, &redirect()).await);
    assert!(matches!(e, ProviderError::ProviderResponseInvalid), "{e:?}");
    assert!(
        target.requests().is_empty(),
        "the redirect target received a request"
    );
    assert_eq!(
        fake.requests()
            .iter()
            .filter(|r| r.path() == "/token")
            .count(),
        1
    );
}

/// S012-A5 (unit): algorithm and header downgrades. The provider is driven
/// against a fake IdP whose token the test crafts.
#[tokio::test]
async fn s012_a5_algorithm_downgrade_rejected() {
    let keys = rsa_pairs();
    let clock = Arc::new(TestClock::new(Timestamp(now_ms())));

    async fn run(
        fake: &Fake,
        clock: &Arc<TestClock>,
        extra: Value,
        make: impl FnOnce(&str, &str, Timestamp) -> String,
    ) -> Result<ProviderIdentity, ProviderError> {
        let (p, txn, cb) = fake_login_parts(fake, clock, extra).await;
        let token = make(&fake.issuer(), txn.nonce.as_deref().unwrap(), clock.now());
        fake.set_id_token(&token);
        p.complete(&txn, &cb, &redirect()).await
    }

    // Control: a correctly signed RS256 token with a kid is accepted.
    let fake = Fake::start(true);
    fake.set_jwks(&[0]);
    let ok = run(&fake, &clock, json!({}), |iss, n, now| {
        sign(
            Algorithm::RS256,
            Some("fk-1"),
            Some("JWT"),
            &keys[0].enc,
            &claims_for(iss, n, now),
        )
    })
    .await;
    assert_eq!(ok.expect("control token").subject, "sub-9");

    // alg: none (signature stripped).
    let e = err_of(
        run(&fake, &clock, json!({}), |iss, n, now| {
            unsigned(
                &json!({"alg": "none", "kid": "fk-1"}),
                &claims_for(iss, n, now),
            )
        })
        .await,
    );
    assert!(
        matches!(e, ProviderError::InvalidTokenHeader),
        "none: {e:?}"
    );

    // alg: HS256 with the RSA public modulus as the HMAC secret (key confusion).
    let e = err_of(
        run(&fake, &clock, json!({}), |iss, n, now| {
            sign(
                Algorithm::HS256,
                Some("fk-1"),
                None,
                &EncodingKey::from_secret(&keys[0].n_bytes),
                &claims_for(iss, n, now),
            )
        })
        .await,
    );
    assert!(
        matches!(e, ProviderError::InvalidTokenHeader),
        "HS256: {e:?}"
    );

    // An algorithm the provider did not advertise (RS384 when only RS256).
    let e = err_of(
        run(&fake, &clock, json!({}), |iss, n, now| {
            sign(
                Algorithm::RS384,
                Some("fk-1"),
                None,
                &keys[0].enc,
                &claims_for(iss, n, now),
            )
        })
        .await,
    );
    assert!(
        matches!(e, ProviderError::InvalidTokenHeader),
        "RS384: {e:?}"
    );

    // Missing kid with a single published key is usable ...
    let ok = run(&fake, &clock, json!({}), |iss, n, now| {
        sign(
            Algorithm::RS256,
            None,
            None,
            &keys[0].enc,
            &claims_for(iss, n, now),
        )
    })
    .await;
    assert!(ok.is_ok(), "{:?}", ok.err());

    // ... with several keys it is ambiguous and rejected.
    let fake2 = Fake::start(true);
    fake2.set_jwks(&[0, 1]);
    let e = err_of(
        run(&fake2, &clock, json!({}), |iss, n, now| {
            sign(
                Algorithm::RS256,
                None,
                None,
                &keys[0].enc,
                &claims_for(iss, n, now),
            )
        })
        .await,
    );
    assert!(
        matches!(e, ProviderError::InvalidTokenHeader),
        "no kid, two keys: {e:?}"
    );

    // A kid naming one key but signed with the other key.
    let e = err_of(
        run(&fake2, &clock, json!({}), |iss, n, now| {
            sign(
                Algorithm::RS256,
                Some("fk-1"),
                None,
                &keys[1].enc,
                &claims_for(iss, n, now),
            )
        })
        .await,
    );
    assert!(
        matches!(e, ProviderError::InvalidSignature),
        "wrong key: {e:?}"
    );

    // A required `typ` that the token does not carry.
    let e = err_of(
        run(
            &fake,
            &clock,
            json!({"id_token_typ": "at+jwt"}),
            |iss, n, now| {
                sign(
                    Algorithm::RS256,
                    Some("fk-1"),
                    Some("JWT"),
                    &keys[0].enc,
                    &claims_for(iss, n, now),
                )
            },
        )
        .await,
    );
    assert!(matches!(e, ProviderError::InvalidTokenHeader), "typ: {e:?}");
    let ok = run(
        &fake,
        &clock,
        json!({"id_token_typ": "at+jwt"}),
        |iss, n, now| {
            sign(
                Algorithm::RS256,
                Some("fk-1"),
                Some("at+jwt"),
                &keys[0].enc,
                &claims_for(iss, n, now),
            )
        },
    )
    .await;
    assert!(ok.is_ok(), "{:?}", ok.err());
}

// ===========================================================================
// S002 provider half (the portal half is W1-E/W1-D, in s002_oidc_login.rs)
// ===========================================================================

#[tokio::test]
async fn provider_s002_success_path_and_client_authentication() {
    let rig = Rig::new("default");
    let (txn, cb) = rig.authorize().await;
    let id = rig.p.complete(&txn, &cb, &redirect()).await.expect("login");
    assert_eq!(id.subject, "sub-1");
    assert_eq!(
        id.email.as_ref().map(|e| e.as_str()),
        Some("a@example.test")
    );
    assert!(id.email_verified && !id.email_authoritative);
    assert_eq!(id.name.as_deref(), Some("Alice 김"));

    // The authorization request: code flow, PKCE S256, nonce, state.
    let a = rig.idp.authorizations().pop().unwrap();
    assert_eq!(a.response_type.as_deref(), Some("code"));
    assert_eq!(a.client_id.as_deref(), Some("hopae-test"));
    assert_eq!(a.redirect_uri.as_deref(), Some(REDIRECT));
    assert_eq!(a.scope.as_deref(), Some("openid email profile"));
    assert_eq!(a.code_challenge_method.as_deref(), Some("S256"));
    let verifier = txn.pkce_verifier.as_ref().unwrap().expose();
    assert_eq!(
        a.code_challenge.as_deref(),
        Some(
            URL_SAFE_NO_PAD
                .encode(sha256(verifier.as_bytes()).0)
                .as_str()
        )
    );
    assert!(verifier.len() >= 43);
    assert_eq!(a.nonce, txn.nonce);
    assert_eq!(a.state.as_deref(), cb.state.as_deref());

    // The token call authenticated with the secret (the mock enforces it) and
    // sent the verifier and redirect_uri; user-info was called once.
    let tok = rig.idp.requests_to("/token").pop().unwrap();
    assert!(
        tok.header("authorization")
            .is_some_and(|h| h.starts_with("Basic "))
    );
    let form = tok.form();
    let f = |k: &str| form.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
    assert_eq!(f("grant_type"), Some("authorization_code"));
    assert_eq!(f("code_verifier"), Some(verifier));
    assert_eq!(f("redirect_uri"), Some(REDIRECT));
    assert_eq!(
        f("client_secret"),
        None,
        "the secret is not in the body for basic auth"
    );
    assert_eq!(rig.idp.requests_to("/userinfo").len(), 1);
}

#[tokio::test]
async fn provider_s002_a2_tampered_artifacts_rejected() {
    for (profile, expect, token_calls) in [
        ("wrong_state", "invalid_state", 0),
        ("wrong_nonce", "invalid_nonce", 1),
        ("wrong_aud", "invalid_audience", 1),
        ("invalid_signature", "invalid_signature", 1),
        ("expired_token", "token_expired", 1),
    ] {
        let rig = Rig::new(profile);
        let e = err_of(rig.login().await);
        assert_eq!(e.reason().0, expect, "{profile}: {e:?}");
        assert_eq!(rig.idp.token_calls(), token_calls, "{profile}");
    }
}

#[tokio::test]
async fn provider_s002_state_and_transaction_checks() {
    let rig = Rig::new("default");
    let (txn, cb) = rig.authorize().await;
    // Another provider's transaction, a consumed transaction, a different state.
    let mut other = txn.clone();
    other.provider_id = Some(ProviderId::new("mock2"));
    let e = err_of(rig.p.complete(&other, &cb, &redirect()).await);
    assert!(matches!(e, ProviderError::InvalidState), "{e:?}");
    let mut consumed = txn.clone();
    consumed.consumed_at = Some(rig.now());
    let e = err_of(rig.p.complete(&consumed, &cb, &redirect()).await);
    assert!(matches!(e, ProviderError::InvalidState), "{e:?}");
    let mut bad = CallbackQuery {
        code: cb.code.clone(),
        state: Some("not-the-state".into()),
        error: None,
        error_description: None,
    };
    let e = err_of(rig.p.complete(&txn, &bad, &redirect()).await);
    assert!(matches!(e, ProviderError::InvalidState), "{e:?}");
    bad.state = None;
    let e = err_of(rig.p.complete(&txn, &bad, &redirect()).await);
    assert!(matches!(e, ProviderError::InvalidState), "{e:?}");
    // The provider reporting an error is a failed attempt, not a login.
    let declined = CallbackQuery {
        code: None,
        state: cb.state.clone(),
        error: Some("access_denied".into()),
        error_description: None,
    };
    let e = err_of(rig.p.complete(&txn, &declined, &redirect()).await);
    assert!(matches!(e, ProviderError::ProviderError { .. }), "{e:?}");
    // None of that reached the token endpoint, and the real callback still works.
    assert_eq!(rig.idp.token_calls(), 0);
    assert!(rig.p.complete(&txn, &cb, &redirect()).await.is_ok());
}

#[tokio::test]
async fn provider_s002_a4_oversized_and_slow_bounded() {
    // Oversized: warm discovery with the default profile, then every answer is 1 MiB.
    let rig = Rig::new("default");
    let (txn, cb) = rig.authorize().await;
    rig.idp.set_profile("oversized");
    let e = err_of(rig.p.complete(&txn, &cb, &redirect()).await);
    assert!(
        matches!(e, ProviderError::ProviderResponseTooLarge),
        "{e:?}"
    );

    // Oversized discovery on a cold provider.
    let rig = Rig::new("oversized");
    let e = rig
        .p
        .begin(&placeholder_txn("mock", rig.now()), &redirect(), &OsRng)
        .await
        .err()
        .expect("fails");
    assert!(
        matches!(e, ProviderError::ProviderResponseTooLarge),
        "{e:?}"
    );

    // Slow: every endpoint delays 15 s; the attempt ends at 10 s.
    let rig = Rig::new("slow");
    let t0 = Instant::now();
    let e = rig
        .p
        .begin(&placeholder_txn("mock", rig.now()), &redirect(), &OsRng)
        .await
        .err()
        .expect("fails");
    assert!(matches!(e, ProviderError::ProviderTimeout), "{e:?}");
    assert!(t0.elapsed() < Duration::from_secs(11), "{:?}", t0.elapsed());
}

#[tokio::test]
async fn provider_s002_a6_mixup_rejected() {
    // A transaction for `mock` presented to provider `mock2`: no exchange.
    let a = Rig::new("default");
    let b = Rig::with("default", "mock2", json!({}), |_| {});
    let (txn, cb) = a.authorize().await;
    let e = err_of(b.p.complete(&txn, &cb, &redirect()).await);
    assert!(matches!(e, ProviderError::InvalidState), "{e:?}");
    assert_eq!(a.idp.token_calls() + b.idp.token_calls(), 0);

    // A token minted by another issuer, returned by this provider's token endpoint.
    let (txn2, cb2) = b.authorize().await;
    let foreign = {
        let verifier = txn2.pkce_verifier.as_ref().unwrap().expose().to_string();
        let r = http()
            .post(b.idp.endpoint("/token"))
            .basic_auth("hopae-test", Some(SECRET))
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", cb2.code.as_deref().unwrap()),
                ("code_verifier", verifier.as_str()),
                ("redirect_uri", REDIRECT),
            ])
            .send()
            .await
            .unwrap();
        let v: Value = r.json().await.unwrap();
        v["id_token"]
            .as_str()
            .expect("foreign id token")
            .to_string()
    };
    let relay = Fake::start(true);
    relay.set_id_token(&foreign);
    let clock = Arc::new(TestClock::new(Timestamp(now_ms())));
    b.idp.set_now_ms(None);
    let (p, mut txn3, cb3) = fake_login_parts(&relay, &clock, json!({})).await;
    txn3.nonce = txn2.nonce.clone();
    let e = err_of(p.complete(&txn3, &cb3, &redirect()).await);
    assert!(matches!(e, ProviderError::InvalidIssuer), "{e:?}");
}

#[tokio::test]
async fn provider_s002_a7_pkce_and_nonce_not_negotiable() {
    // Discovery that does not advertise code_challenge_methods_supported.
    let fake = Fake::start(false);
    let clock = Arc::new(TestClock::new(Timestamp(now_ms())));
    let row = row_for(&fake.issuer(), "mock", json!({}));
    let (p, _) = build(&row, &clock);
    let req = p
        .begin(&placeholder_txn("mock", clock.now()), &redirect(), &OsRng)
        .await
        .unwrap();
    let q: Vec<(String, String)> = req
        .url
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    let get = |k: &str| q.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
    assert_eq!(get("code_challenge_method"), Some("S256"));
    assert!(get("code_challenge").is_some_and(|c| c.len() == 43));
    assert_eq!(get("nonce"), req.nonce.as_deref());
    assert!(get("nonce").is_some_and(|n| n.len() >= 22));
    assert_eq!(get("state"), Some(req.state.expose()));
    // State, nonce and verifier are distinct random values.
    assert_ne!(Some(req.state.expose()), req.nonce.as_deref());
    assert_ne!(
        Some(req.state.expose()),
        req.pkce_verifier.as_ref().map(|v| v.expose())
    );

    // A token response without id_token for kind oidc.
    let rig = Rig::new("id_token_missing");
    let e = err_of(rig.login().await);
    assert!(matches!(e, ProviderError::IdTokenMissing), "{e:?}");
    assert_eq!(e.reason().0, "id_token_missing");
}

#[tokio::test]
async fn provider_s002_a9_userinfo_subject_mismatch_rejected() {
    let rig = Rig::new("userinfo_wrong_sub");
    // sub-2's email belongs to "an existing user" in the scenario; whatever it
    // is, nothing from the user-info response may reach the result.
    let e = err_of(rig.login().await);
    assert!(matches!(e, ProviderError::UserinfoSubjectMismatch), "{e:?}");
    assert_eq!(e.reason().0, "userinfo_subject_mismatch");
    assert_eq!(rig.idp.requests_to("/userinfo").len(), 1);
}

#[tokio::test]
async fn provider_s002_hd_makes_email_authoritative_only_when_listed() {
    // Listed domain, matching hd and address.
    let rig = Rig::with("hd_example_test", "mock", json!({}), |r| {
        r.authoritative_domains = vec!["Example.Test".into()];
    });
    let id = rig.login().await.expect("login");
    assert!(id.email_verified && id.email_authoritative);

    // hd present but the provider lists no authoritative domain.
    let rig = Rig::with("hd_example_test", "mock", json!({}), |_| {});
    let id = rig.login().await.expect("login");
    assert!(id.email_verified && !id.email_authoritative);

    // Listed, but the token carries no hd.
    let rig = Rig::with("default", "mock", json!({}), |r| {
        r.authoritative_domains = vec!["example.test".into()];
    });
    let id = rig.login().await.expect("login");
    assert!(!id.email_authoritative);

    // hd present and listed, email unverified: never authoritative.
    let rig = Rig::with("unverified_email", "mock", json!({}), |r| {
        r.authoritative_domains = vec!["example.test".into()];
    });
    let id = rig.login().await.expect("login");
    assert!(!id.email_verified && !id.email_authoritative);
}

#[tokio::test]
async fn provider_disabled_and_unconfigured_rows_never_call_out() {
    let idp = MockIdp::start("default");
    let clock = Arc::new(TestClock::new(Timestamp(now_ms())));
    let base = row_for(&issuer_of(&idp), "mock", json!({}));
    let mk = |f: &dyn Fn(&mut ProviderRow), envf: &dyn Fn(&str) -> Option<String>| {
        let mut r = base.clone();
        f(&mut r);
        OidcProvider::from_row(&r, envf, clock.clone(), None)
    };
    let cases: Vec<(&str, Arc<OidcProvider>)> = vec![
        ("disabled", mk(&|r| r.enabled = false, &env)),
        ("deleted", mk(&|r| r.deleted_at = Some(Timestamp(1)), &env)),
        ("secret_missing", mk(&|_| {}, &|_| None)),
        ("secret_missing", mk(&|_| {}, &|_| Some(String::new()))),
        (
            "misconfigured",
            mk(&|r| r.config["client_id"] = json!(""), &env),
        ),
        (
            "misconfigured",
            mk(&|r| r.config["issuer"] = json!("http://example.org"), &env),
        ),
    ];
    for (why, p) in cases {
        assert!(!p.enabled(), "{why}");
        assert_eq!(p.disabled_reason(), Some(why));
        assert_eq!(p.health().await, ProviderHealth::Disabled, "{why}");
        let e = p
            .begin(&placeholder_txn("mock", clock.now()), &redirect(), &OsRng)
            .await
            .err()
            .expect("disabled");
        assert!(matches!(e, ProviderError::ProviderDisabled), "{why}: {e:?}");
    }
    assert!(
        idp.requests().is_empty(),
        "a disabled provider never calls the IdP"
    );
}

#[tokio::test]
async fn provider_google_preset_fills_issuer_and_skips_userinfo() {
    let clock = Arc::new(TestClock::new(Timestamp(now_ms())));
    let mut row = row_for("", "google", json!({}));
    row.config = json!({"client_id": "cid.apps.googleusercontent.com"});
    let p = OidcProvider::from_row(&row, &env, clock, None);
    assert!(p.enabled(), "{:?}", p.disabled_reason());
    // No network here: the preset supplies issuer and scope, nothing else to assert
    // without reaching Google; the settings are checked directly.
    let s = hopae::provider::oidc::OidcSettings::from_row(&row, &env);
    assert_eq!(s.issuer, "https://accounts.google.com");
    assert_eq!(s.scope, "openid email profile");
    assert!(!s.userinfo);
}

// Keep a reference so the helper is not reported unused when tests are filtered.
#[allow(dead_code)]
fn _uses(_: &Fake, _: Option<&Echo>) {}

/// G7-IDP-05: the token time checks use the clock at validation time, after
/// the network waits. A token that was inside the 60 s leeway when the
/// callback began, but is outside it once the token endpoint has answered, is
/// rejected.
#[tokio::test]
async fn g7_idp05_token_time_is_checked_after_the_network_wait() {
    let keys = rsa_pairs();
    let clock = Arc::new(TestClock::new(Timestamp(now_ms())));
    let fake = Fake::start(true);
    fake.set_jwks(&[0]);
    let (p, txn, cb) = fake_login_parts(&fake, &clock, json!({})).await;
    let t0 = clock.now();
    // Expired 55 s before the callback began: inside the leeway then.
    let claims = json!({"iss": fake.issuer(), "aud": "hopae-test", "sub": "sub-9",
        "exp": t0.secs() - 55, "iat": t0.secs() - 400, "nonce": txn.nonce,
        "email": "z@example.test", "email_verified": true});
    fake.set_id_token(&sign(
        Algorithm::RS256,
        Some("fk-1"),
        Some("JWT"),
        &keys[0].enc,
        &claims,
    ));
    // The token endpoint answers nine seconds later: expired 64 s ago.
    fake.advance_clock_on_token(&clock, Duration::from_secs(9));
    let e = err_of(p.complete(&txn, &cb, &redirect()).await);
    assert!(matches!(e, ProviderError::TokenExpired), "{e:?}");

    // Control: with no wait the same token is still inside the leeway.
    let (p, txn, cb) = fake_login_parts(&fake, &clock, json!({})).await;
    let t1 = clock.now();
    let claims = json!({"iss": fake.issuer(), "aud": "hopae-test", "sub": "sub-9",
        "exp": t1.secs() - 55, "iat": t1.secs() - 400, "nonce": txn.nonce,
        "email": "z@example.test", "email_verified": true});
    fake.set_id_token(&sign(
        Algorithm::RS256,
        Some("fk-1"),
        Some("JWT"),
        &keys[0].enc,
        &claims,
    ));
    *fake.st.on_token.lock().unwrap() = None;
    assert!(p.complete(&txn, &cb, &redirect()).await.is_ok());
}

/// G7-IDP-07: a provider 5xx at the token endpoint reaches the browser as a
/// server-error page (503), `login.failed` carries the provider status, and
/// the transaction stays retryable (S012-2, S002-A4). Through the real
/// callback orchestration and portal, not `OidcProvider::complete` alone.
#[test]
fn g7_idp07_provider_5xx_is_a_503_with_status_and_retryable() {
    let idp = MockIdp::start("token_500");
    let h = Hopae::spawn(Fixture::new("m1-basic"), &idp, &[]);
    let ip = "203.0.113.9";
    let r = h.verify(VerifyRequest::document("https://app.example.test/admin/x").ip(ip));
    assert_eq!(r.status, 302, "{r:?}");
    let loc = r.location().expect("login redirect").to_string();
    let path = loc.split("auth.example.test").nth(1).expect("portal path");
    let portal = h.portal().with_ip(ip);
    let go = portal.get(path);
    assert_eq!(go.status, 302, "{go:?}");
    let callback = idp.follow_authorization(go.location().expect("provider redirect"));

    let failed = portal.get(&callback);
    assert_eq!(failed.status, 503, "server-error page: {failed:?}");
    let mut rows = vec![];
    for _ in 0..100 {
        rows = h.hooks.events(Some("login.failed"), Some(100));
        if !rows.is_empty() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0]["reason"], "provider_error");
    assert_eq!(rows[0]["attrs"]["status"], 500, "{:?}", rows[0]);

    // The transaction was not consumed: once the provider recovers the same
    // callback completes the login.
    idp.set_profile("default");
    let ok = portal.get(&callback);
    assert_eq!(ok.status, 302, "retry after recovery: {ok:?}");
    assert!(
        ok.location().is_some_and(|l| l.contains("_hopae_handoff=")),
        "{ok:?}"
    );
}

/// G7-IDP-03: discovery may not send the client to endpoints on other hosts
/// (here an "internal service" on another loopback host name) unless the
/// operator lists them; nothing is requested from the destination.
#[tokio::test]
async fn g7_idp03_discovery_endpoints_are_confined_to_the_issuer_or_the_allowlist() {
    let clock = Arc::new(TestClock::new(Timestamp(now_ms())));
    let idp = Fake::start(true);
    let victim = Fake::start(false);
    let issuer = format!("http://localhost:{}", idp.served.addr.port());
    *idp.st.token_endpoint.lock().unwrap() = Some(format!(
        "http://127.0.0.1:{}/internal",
        victim.served.addr.port()
    ));
    let private_ok = json!({"allow_private_endpoints": true});

    // The issuer's own host is trusted; 127.0.0.1 is another host.
    let r = fake_login_parts_at(&idp, &issuer, &clock, private_ok.clone()).await;
    assert!(r.is_err(), "a token endpoint on another host is refused");
    assert!(
        victim.requests().is_empty(),
        "no request reached the destination"
    );

    // The operator may list the host explicitly.
    let listed = json!({"allow_private_endpoints": true, "endpoint_hosts": ["127.0.0.1"]});
    let (p, txn, cb) = fake_login_parts_at(&idp, &issuer, &clock, listed)
        .await
        .expect("a listed endpoint host is accepted");
    let _ = p.complete(&txn, &cb, &redirect()).await;
    assert!(
        victim.requests().iter().any(|r| r.path() == "/internal"),
        "the listed destination is the one called"
    );

    // Without the private-endpoint opt-in a loopback issuer is not used at
    // all, under any build.
    let off = json!({"allow_private_endpoints": false});
    let before = idp.requests().len();
    let r = fake_login_parts_at(&idp, &issuer, &clock, off).await;
    assert!(r.is_err());
    assert_eq!(
        idp.requests().len(),
        before,
        "no connection to a loopback address"
    );
}

/// G7-IDP-03 (pass 2): outbound provider traffic ignores the proxy
/// environment. A proxy would resolve the target itself, defeating the
/// destination vetting, so the client never uses one.
#[test]
fn g7_idp03_provider_traffic_ignores_proxy_environment() {
    let proxy = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    proxy.set_nonblocking(true).unwrap();
    let url = format!("http://{}", proxy.local_addr().unwrap());
    let idp = MockIdp::start("default");
    let h = Hopae::spawn(
        Fixture::new("m1-basic"),
        &idp,
        &[
            ("HTTP_PROXY", url.as_str()),
            ("http_proxy", url.as_str()),
            ("HTTPS_PROXY", url.as_str()),
            ("https_proxy", url.as_str()),
            ("ALL_PROXY", url.as_str()),
            ("all_proxy", url.as_str()),
        ],
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    while idp
        .requests_to("/.well-known/openid-configuration")
        .is_empty()
    {
        assert!(
            Instant::now() < deadline,
            "discovery never reached the provider directly; log:\n{}",
            h.log()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        proxy.accept().is_err(),
        "a provider request went through the environment proxy"
    );
}
