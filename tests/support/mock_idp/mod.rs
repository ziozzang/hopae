//! The in-process mock OIDC provider: discovery, JWKS (RS256), `/authorize`
//! (auto-consent, PKCE S256 required), `/token` (PKCE verified, single-use
//! codes), `/userinfo`, and every misbehaviour profile of the fixture
//! catalogue (see `profiles.rs`). Loopback, ephemeral port, own thread.
#![allow(dead_code)]

pub mod profiles;

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::response::Response;
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::traits::PublicKeyParts;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

pub use super::server::RecordedRequest;
use super::server::{Log, Served, record};
use profiles::{AuthTime, Behavior, Profile};

/// Adapts the OS source to the `rand_core` 0.6 traits the `rsa` crate wants.
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
        hopae::crypto::OsRng.fill(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rsa::rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl rsa::rand_core::CryptoRng for KeygenRng {}

struct KeyMaterial {
    kid: String,
    enc: EncodingKey,
    n: String,
    e: String,
}

/// Three throw-away keys per test process: the live key, its successor, and a
/// key that is never published. Generating RSA keys is slow, so only once.
fn keys() -> &'static [KeyMaterial; 3] {
    static KEYS: OnceLock<[KeyMaterial; 3]> = OnceLock::new();
    KEYS.get_or_init(|| {
        let make = |kid: &str| {
            let sk = rsa::RsaPrivateKey::new(&mut KeygenRng, 2048).expect("rsa keygen");
            let der = sk.to_pkcs1_der().expect("pkcs1 der");
            KeyMaterial {
                kid: kid.to_string(),
                enc: EncodingKey::from_rsa_der(der.as_bytes()),
                n: URL_SAFE_NO_PAD.encode(sk.n().to_bytes_be()),
                e: URL_SAFE_NO_PAD.encode(sk.e().to_bytes_be()),
            }
        };
        [make("key-1"), make("key-2"), make("rogue")]
    })
}

#[derive(Clone, Debug)]
pub struct MockUser {
    pub sub: String,
    pub email: String,
    pub email_verified: bool,
    pub name: String,
}

fn default_user(sub: &str) -> MockUser {
    match sub {
        "sub-1" => MockUser {
            sub: sub.into(),
            email: "a@example.test".into(),
            email_verified: true,
            name: "Alice 김".into(),
        },
        "sub-2" => MockUser {
            sub: sub.into(),
            email: "b@example.test".into(),
            email_verified: true,
            name: "Bob".into(),
        },
        other => MockUser {
            sub: other.into(),
            email: format!(
                "{}@example.test",
                other.replace(|c: char| !c.is_ascii_alphanumeric(), "")
            ),
            email_verified: true,
            name: format!("User {other}"),
        },
    }
}

/// One `/authorize` call, parsed.
#[derive(Clone, Debug)]
pub struct AuthRequest {
    pub client_id: Option<String>,
    pub redirect_uri: Option<String>,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub scope: Option<String>,
    pub response_type: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    /// The OpenID Connect `max_age` parameter, as sent.
    pub max_age: Option<String>,
    /// The `prompt` parameter, as sent.
    pub prompt: Option<String>,
}

struct CodeEntry {
    sub: String,
    nonce: Option<String>,
    challenge: Option<String>,
    redirect_uri: Option<String>,
    used: bool,
    /// When the code was issued (the provider's clock, seconds).
    issued_at: i64,
}

struct Inner {
    issuer: OnceLock<url::Url>,
    client_id: String,
    secret: Mutex<Option<String>>,
    profile: Mutex<Profile>,
    manual_key: AtomicUsize,
    discovery_fetches: AtomicUsize,
    jwks_fetches: AtomicUsize,
    token_calls: AtomicUsize,
    malformed_calls: AtomicUsize,
    codes: Mutex<HashMap<String, CodeEntry>>,
    access_tokens: Mutex<HashMap<String, String>>,
    /// Bearer values the provider issued or saw: (what, value). For leak scans.
    issued: Mutex<Vec<(&'static str, String)>>,
    auths: Mutex<Vec<AuthRequest>>,
    users: Mutex<HashMap<String, MockUser>>,
    next_sub: Mutex<String>,
    now_override_ms: Mutex<Option<i64>>,
    /// A chosen `auth_time` claim value (any JSON), replacing the profile's.
    auth_time_override: Mutex<Option<Value>>,
    /// Claims merged into every ID token (e.g. a `groups` claim).
    extra_claims: Mutex<serde_json::Map<String, Value>>,
    log: Log,
}

type S = Arc<Inner>;

#[derive(Clone)]
pub struct MockIdp {
    pub issuer: url::Url,
    pub client_id: String,
    inner: S,
    _server: Arc<Served>,
}

impl MockIdp {
    /// Start a provider on a loopback port with the named profile (see the catalogue).
    pub fn start(profile: &str) -> MockIdp {
        let profile =
            Profile::parse(profile).unwrap_or_else(|| panic!("unknown mock profile {profile:?}"));
        let _ = keys(); // generate before the server starts so the first request is not slow
        let inner = Arc::new(Inner {
            issuer: OnceLock::new(),
            client_id: "hopae-test".into(),
            secret: Mutex::new(None),
            profile: Mutex::new(profile),
            manual_key: AtomicUsize::new(0),
            discovery_fetches: AtomicUsize::new(0),
            jwks_fetches: AtomicUsize::new(0),
            token_calls: AtomicUsize::new(0),
            malformed_calls: AtomicUsize::new(0),
            codes: Mutex::new(HashMap::new()),
            access_tokens: Mutex::new(HashMap::new()),
            issued: Mutex::new(Vec::new()),
            auths: Mutex::new(Vec::new()),
            users: Mutex::new(HashMap::new()),
            next_sub: Mutex::new("sub-1".into()),
            now_override_ms: Mutex::new(None),
            auth_time_override: Mutex::new(None),
            extra_claims: Mutex::new(serde_json::Map::new()),
            log: Arc::new(Mutex::new(Vec::new())),
        });
        let router = Router::new().fallback(handle).with_state(inner.clone());
        let server = Served::start(router);
        let issuer = url::Url::parse(&format!("http://{}", server.addr)).expect("issuer url");
        inner.issuer.set(issuer.clone()).expect("issuer set once");
        MockIdp {
            issuer,
            client_id: inner.client_id.clone(),
            inner,
            _server: Arc::new(server),
        }
    }

    /// Switch behaviour for subsequent requests.
    pub fn set_profile(&self, profile: &str) {
        let p =
            Profile::parse(profile).unwrap_or_else(|| panic!("unknown mock profile {profile:?}"));
        *self.inner.profile.lock().unwrap() = p;
    }

    /// Every request the provider received, oldest first.
    pub fn requests(&self) -> Vec<RecordedRequest> {
        self.inner.log.lock().unwrap().clone()
    }

    /// Requests whose path is exactly `path`.
    pub fn requests_to(&self, path: &str) -> Vec<RecordedRequest> {
        self.requests()
            .into_iter()
            .filter(|r| r.path() == path)
            .collect()
    }

    /// Choose the `auth_time` claim the next ID tokens carry: any JSON value
    /// (future-dated, a string, negative), or `None` for the profile's own.
    pub fn set_auth_time(&self, v: Option<Value>) {
        *self.inner.auth_time_override.lock().unwrap() = v;
    }

    /// Merge `claims` (an object) into the next ID tokens; `{}` clears.
    pub fn set_extra_claims(&self, claims: Value) {
        *self.inner.extra_claims.lock().unwrap() = claims.as_object().cloned().unwrap_or_default();
    }

    /// The `/authorize` parameters the provider recorded, `max_age` and `prompt` included.
    pub fn authorize_requests(&self) -> Vec<AuthRequest> {
        self.authorizations()
    }

    /// Parsed `/authorize` calls.
    pub fn authorizations(&self) -> Vec<AuthRequest> {
        self.inner.auths.lock().unwrap().clone()
    }

    /// Mint a code for `state` and `sub` without going through `/authorize`.
    /// Nonce, PKCE challenge and redirect URI come from the latest authorization
    /// that used `state`; with none, the code skips those checks.
    pub fn issue_code(&self, state: &str, sub: &str) -> String {
        let auth = self
            .inner
            .auths
            .lock()
            .unwrap()
            .iter()
            .rev()
            .find(|a| a.state.as_deref() == Some(state))
            .cloned();
        let code = random_hex();
        self.inner.codes.lock().unwrap().insert(
            code.clone(),
            CodeEntry {
                sub: sub.to_string(),
                nonce: auth.as_ref().and_then(|a| a.nonce.clone()),
                challenge: auth.as_ref().and_then(|a| a.code_challenge.clone()),
                redirect_uri: auth.and_then(|a| a.redirect_uri),
                used: false,
                issued_at: now_secs(&self.inner),
            },
        );
        code
    }

    /// What the user's browser does at the provider: follow the authorization
    /// URL the portal redirected to, once. The provider records the request
    /// (nonce, PKCE challenge, redirect URI), signs `next_sub` in, and answers
    /// with a redirect to the callback; returns that callback's path and query
    /// (`/callback/mock?code=..&state=..`) for the portal client to GET.
    pub fn follow_authorization(&self, authorization_url: &str) -> String {
        let u = url::Url::parse(authorization_url).expect("authorization url");
        let port = u.port().expect("loopback provider port");
        let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
        let r = crate::support::get(addr, &format!("{}?{}", u.path(), u.query().unwrap_or("")));
        let loc = r.location().expect("authorize redirects to the callback");
        let cb = url::Url::parse(loc).expect("callback url");
        format!("{}?{}", cb.path(), cb.query().unwrap_or(""))
    }

    /// Bearer values the provider issued or received so far (ID and access
    /// tokens, the PKCE verifier): what a log must never contain.
    pub fn issued_secrets(&self) -> Vec<(&'static str, String)> {
        self.inner.issued.lock().unwrap().clone()
    }

    /// The subject `/authorize` signs in next (default `sub-1`).
    pub fn set_subject(&self, sub: &str) {
        *self.inner.next_sub.lock().unwrap() = sub.to_string();
    }

    /// Define or replace a user.
    pub fn set_user(&self, sub: &str, email: &str, email_verified: bool, name: &str) {
        self.inner.users.lock().unwrap().insert(
            sub.to_string(),
            MockUser {
                sub: sub.into(),
                email: email.into(),
                email_verified,
                name: name.into(),
            },
        );
    }

    /// The client secret `/token` requires (`None` = not checked). `Hopae::spawn` sets this.
    pub fn set_client_secret(&self, secret: Option<&str>) {
        *self.inner.secret.lock().unwrap() = secret.map(str::to_string);
    }

    /// Issue tokens with this clock (unix ms) instead of the system clock;
    /// `None` returns to the system clock. Keep it equal to Hopae's test clock.
    pub fn set_now_ms(&self, ms: Option<i64>) {
        *self.inner.now_override_ms.lock().unwrap() = ms;
    }

    /// Publish and sign with `key-2` from now on (a manual key rotation).
    pub fn rotate_keys(&self) {
        self.inner.manual_key.store(1, Ordering::SeqCst);
    }

    pub fn endpoint(&self, path: &str) -> url::Url {
        self.issuer.join(path).expect("endpoint url")
    }

    pub fn discovery_fetches(&self) -> usize {
        self.inner.discovery_fetches.load(Ordering::SeqCst)
    }

    pub fn jwks_fetches(&self) -> usize {
        self.inner.jwks_fetches.load(Ordering::SeqCst)
    }

    pub fn token_calls(&self) -> usize {
        self.inner.token_calls.load(Ordering::SeqCst)
    }
}

fn random_hex() -> String {
    use hopae::crypto::Rng;
    let mut b = [0u8; 16];
    hopae::crypto::OsRng.fill(&mut b);
    data_encoding::HEXLOWER.encode(&b)
}

fn now_secs(s: &Inner) -> i64 {
    let ms = s.now_override_ms.lock().unwrap().unwrap_or_else(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0)
    });
    ms.div_euclid(1000)
}

fn json_response(status: u16, body: &Value) -> Response {
    let mut r = Response::new(Body::from(body.to_string()));
    *r.status_mut() = axum::http::StatusCode::from_u16(status)
        .unwrap_or(axum::http::StatusCode::INTERNAL_SERVER_ERROR);
    r.headers_mut()
        .insert("content-type", "application/json".parse().unwrap());
    r.headers_mut()
        .insert("cache-control", "no-store".parse().unwrap());
    r
}

fn text_response(status: u16, body: &str) -> Response {
    let mut r = Response::new(Body::from(body.to_string()));
    *r.status_mut() = axum::http::StatusCode::from_u16(status)
        .unwrap_or(axum::http::StatusCode::INTERNAL_SERVER_ERROR);
    r.headers_mut()
        .insert("content-type", "application/json".parse().unwrap());
    r
}

fn redirect(to: &str) -> Response {
    let mut r = Response::new(Body::empty());
    *r.status_mut() = axum::http::StatusCode::FOUND;
    r.headers_mut()
        .insert("location", to.parse().expect("location header"));
    r.headers_mut()
        .insert("cache-control", "no-store".parse().unwrap());
    r
}

fn pad(mut v: Value, oversized: bool) -> Value {
    if oversized {
        v["x_padding"] = Value::String("a".repeat(1024 * 1024));
    }
    v
}

async fn handle(State(s): State<S>, req: Request) -> Response {
    let rec = record(req, &s.log).await;
    let beh = s.profile.lock().unwrap().behavior();
    if let Some(d) = beh.delay_all {
        tokio::time::sleep(d).await;
    }
    match (rec.method.as_str(), rec.path()) {
        ("GET", "/.well-known/openid-configuration") => discovery(&s, &beh),
        ("GET", "/jwks") => jwks(&s, &beh),
        ("GET", "/authorize") => authorize(&s, &beh, &rec),
        ("POST", "/token") => token(&s, &beh, &rec).await,
        ("GET", "/userinfo") => userinfo(&s, &beh, &rec),
        _ => json_response(404, &json!({"error": "not_found"})),
    }
}

fn issuer_str(s: &Inner) -> String {
    s.issuer
        .get()
        .expect("issuer")
        .as_str()
        .trim_end_matches('/')
        .to_string()
}

fn discovery(s: &Inner, beh: &Behavior) -> Response {
    let n = s.discovery_fetches.fetch_add(1, Ordering::SeqCst);
    if beh.discovery_status != 200 {
        return json_response(
            beh.discovery_status,
            &json!({"error": "temporarily_unavailable"}),
        );
    }
    let base = issuer_str(s);
    let issuer = if beh.discovery_changes_issuer && n >= 1 {
        format!("{base}/changed")
    } else {
        base.clone()
    };
    json_response(
        200,
        &pad(
            json!({
                "issuer": issuer,
                "authorization_endpoint": format!("{base}/authorize"),
                "token_endpoint": format!("{base}/token"),
                "jwks_uri": format!("{base}/jwks"),
                "userinfo_endpoint": format!("{base}/userinfo"),
                "response_types_supported": ["code"],
                "subject_types_supported": ["public"],
                "id_token_signing_alg_values_supported": ["RS256"],
                "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
                "code_challenge_methods_supported": ["S256"],
                "scopes_supported": ["openid", "email", "profile"],
                "claims_supported": ["sub", "iss", "aud", "exp", "iat", "nonce", "email", "email_verified", "name", "hd"],
            }),
            beh.oversized,
        ),
    )
}

fn active_key(s: &Inner, beh: &Behavior) -> usize {
    if beh.jwks_rotates {
        usize::from(s.jwks_fetches.load(Ordering::SeqCst) >= 1)
    } else {
        s.manual_key.load(Ordering::SeqCst)
    }
}

fn jwks(s: &Inner, beh: &Behavior) -> Response {
    let n = s.jwks_fetches.fetch_add(1, Ordering::SeqCst);
    let idx = if beh.jwks_rotates {
        usize::from(n >= 1)
    } else {
        s.manual_key.load(Ordering::SeqCst)
    };
    let k = &keys()[idx];
    json_response(
        200,
        &pad(
            json!({"keys": [{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": k.kid, "n": k.n, "e": k.e}]}),
            beh.oversized,
        ),
    )
}

fn authorize(s: &Inner, beh: &Behavior, rec: &RecordedRequest) -> Response {
    let q = |k: &str| rec.query_value(k).map(str::to_string);
    let auth = AuthRequest {
        client_id: q("client_id"),
        redirect_uri: q("redirect_uri"),
        state: q("state"),
        nonce: q("nonce"),
        scope: q("scope"),
        response_type: q("response_type"),
        code_challenge: q("code_challenge"),
        code_challenge_method: q("code_challenge_method"),
        max_age: q("max_age"),
        prompt: q("prompt"),
    };
    s.auths.lock().unwrap().push(auth.clone());
    let Some(redirect_uri) = auth.redirect_uri.clone() else {
        return json_response(
            400,
            &json!({"error": "invalid_request", "error_description": "redirect_uri required"}),
        );
    };
    if auth.client_id.as_deref() != Some(s.client_id.as_str()) {
        return json_response(400, &json!({"error": "unauthorized_client"}));
    }
    let Ok(mut to) = url::Url::parse(&redirect_uri) else {
        return json_response(
            400,
            &json!({"error": "invalid_request", "error_description": "bad redirect_uri"}),
        );
    };
    let issued_state = auth.state.clone().unwrap_or_default();
    let shown_state = if beh.wrong_state {
        format!("never-issued-{}", random_hex())
    } else {
        issued_state
    };
    let pkce_ok = auth.code_challenge_method.as_deref() == Some("S256")
        && auth
            .code_challenge
            .as_deref()
            .is_some_and(|c| !c.is_empty());
    if auth.response_type.as_deref() != Some("code") || !pkce_ok {
        to.query_pairs_mut()
            .append_pair("error", "invalid_request")
            .append_pair(
                "error_description",
                "response_type=code and PKCE S256 are required",
            )
            .append_pair("state", &shown_state);
        return redirect(to.as_str());
    }
    let sub = s.next_sub.lock().unwrap().clone();
    let code = random_hex();
    s.codes.lock().unwrap().insert(
        code.clone(),
        CodeEntry {
            sub,
            nonce: auth.nonce.clone(),
            challenge: auth.code_challenge.clone(),
            redirect_uri: Some(redirect_uri),
            used: false,
            issued_at: now_secs(s),
        },
    );
    to.query_pairs_mut()
        .append_pair("code", &code)
        .append_pair("state", &shown_state);
    redirect(to.as_str())
}

fn user(s: &Inner, sub: &str) -> MockUser {
    s.users
        .lock()
        .unwrap()
        .get(sub)
        .cloned()
        .unwrap_or_else(|| default_user(sub))
}

fn id_token(s: &Inner, beh: &Behavior, entry: &CodeEntry) -> String {
    let u = user(s, &entry.sub);
    let now = now_secs(s);
    let exp = now + beh.exp_offset_secs;
    let mut claims = json!({
        "iss": issuer_str(s),
        "sub": u.sub,
        "aud": if beh.wrong_aud { "some-other-client".to_string() } else { s.client_id.clone() },
        "exp": exp,
        "iat": exp - 300,
        "email": u.email,
        "email_verified": beh.email_verified && u.email_verified,
        "name": u.name,
    });
    if beh.exp_offset_secs > 0 {
        claims["iat"] = json!(now);
    }
    // `auth_time`: a chosen value, else the profile's (the code issue time by default).
    for (k, v) in s.extra_claims.lock().unwrap().iter() {
        claims[k.as_str()] = v.clone();
    }
    match (s.auth_time_override.lock().unwrap().clone(), beh.auth_time) {
        (Some(v), _) => claims["auth_time"] = v,
        (None, AuthTime::IssueTime) => claims["auth_time"] = json!(entry.issued_at),
        (None, AuthTime::Stale(ago)) => claims["auth_time"] = json!(entry.issued_at - ago),
        (None, AuthTime::Missing) => {}
    }
    if let Some(n) = &entry.nonce {
        claims["nonce"] = json!(if beh.wrong_nonce {
            format!("wrong-{n}")
        } else {
            n.clone()
        });
    } else if beh.wrong_nonce {
        claims["nonce"] = json!("wrong-nonce");
    }
    if let Some(hd) = beh.hd {
        claims["hd"] = json!(hd);
    }
    let idx = active_key(s, beh);
    let (kid, signer) = if beh.rogue_signature {
        (keys()[idx].kid.clone(), &keys()[2])
    } else if beh.unknown_kid {
        ("unknown-kid".to_string(), &keys()[idx])
    } else {
        (keys()[idx].kid.clone(), &keys()[idx])
    };
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid);
    jsonwebtoken::encode(&header, &claims, &signer.enc).expect("sign id token")
}

fn basic_credentials(rec: &RecordedRequest) -> Option<(String, String)> {
    let v = rec.header("authorization")?.strip_prefix("Basic ")?;
    let raw = String::from_utf8(STANDARD.decode(v).ok()?).ok()?;
    let (id, secret) = raw.split_once(':')?;
    Some((id.to_string(), secret.to_string()))
}

async fn token(s: &Inner, beh: &Behavior, rec: &RecordedRequest) -> Response {
    if let Some(d) = beh.token_delay {
        tokio::time::sleep(d).await;
    }
    s.token_calls.fetch_add(1, Ordering::SeqCst);
    if let Some(status) = beh.token_status {
        return json_response(status, &json!({"error": "server_error"}));
    }
    if beh.token_malformed {
        // The cycle starts at the first malformed answer, whatever was served before.
        return match s.malformed_calls.fetch_add(1, Ordering::SeqCst) % 3 {
            0 => text_response(200, r#"{"access_token":"x","token_type":"Bear"#),
            1 => text_response(
                200,
                r#"{"access_token":"x","token_type":"Bearer","id_token":12345}"#,
            ),
            _ => text_response(
                200,
                r#"{"access_token":"x","token_type":"Bearer","id_token":"!!!.@@@.###"}"#,
            ),
        };
    }
    let form = rec.form();
    let field = |k: &str| form.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
    let (client_id, client_secret) = match basic_credentials(rec) {
        Some((i, sec)) => (Some(i), Some(sec)),
        None => (field("client_id"), field("client_secret")),
    };
    if client_id.as_deref() != Some(s.client_id.as_str()) {
        return json_response(401, &json!({"error": "invalid_client"}));
    }
    if let Some(expected) = s.secret.lock().unwrap().clone()
        && client_secret.as_deref() != Some(expected.as_str())
    {
        return json_response(401, &json!({"error": "invalid_client"}));
    }
    if field("grant_type").as_deref() != Some("authorization_code") {
        return json_response(400, &json!({"error": "unsupported_grant_type"}));
    }
    let invalid = || json_response(400, &json!({"error": "invalid_grant"}));
    let Some(code) = field("code") else {
        return invalid();
    };
    let mut codes = s.codes.lock().unwrap();
    let Some(entry) = codes.get_mut(&code) else {
        return invalid();
    };
    if entry.used {
        return invalid();
    }
    entry.used = true;
    if let (Some(expected), Some(got)) = (&entry.redirect_uri, field("redirect_uri"))
        && *expected != got
    {
        return invalid();
    }
    if let Some(challenge) = &entry.challenge {
        let verifier = field("code_verifier").unwrap_or_default();
        s.issued
            .lock()
            .unwrap()
            .push(("PKCE verifier", verifier.clone()));
        let computed = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        if computed != *challenge {
            return invalid();
        }
    }
    let access = format!("at-{}", random_hex());
    s.access_tokens
        .lock()
        .unwrap()
        .insert(access.clone(), entry.sub.clone());
    s.issued
        .lock()
        .unwrap()
        .push(("access token", access.clone()));
    let mut body = json!({"access_token": access, "token_type": "Bearer", "expires_in": 3600, "scope": "openid email profile"});
    if !beh.omit_id_token {
        let idt = id_token(s, beh, entry);
        s.issued.lock().unwrap().push(("ID token", idt.clone()));
        body["id_token"] = json!(idt);
    }
    json_response(200, &pad(body, beh.oversized))
}

fn userinfo(s: &Inner, beh: &Behavior, rec: &RecordedRequest) -> Response {
    if let Some(status) = beh.userinfo_status {
        return json_response(status, &json!({"error": "server_error"}));
    }
    let token = rec
        .header("authorization")
        .and_then(|v| v.strip_prefix("Bearer "));
    let sub = token.and_then(|t| s.access_tokens.lock().unwrap().get(t).cloned());
    let Some(sub) = sub else {
        return json_response(401, &json!({"error": "invalid_token"}));
    };
    let sub = beh.userinfo_sub.map_or(sub, str::to_string);
    let u = user(s, &sub);
    json_response(
        200,
        &json!({"sub": u.sub, "email": u.email, "email_verified": beh.email_verified && u.email_verified, "name": u.name}),
    )
}

/// Wait helper for tests that need the server thread idle.
pub fn settle(d: Duration) {
    std::thread::sleep(d);
}
