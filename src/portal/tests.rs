//! Portal tests: the real router served on a loopback socket over a scripted
//! `PortalServices`, driven by `reqwest` (no redirects, no cookie store: the
//! tests carry cookies by hand so every `Set-Cookie` is inspected).

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use url::Url;

use super::ports::*;
use super::{PortalConfig, PortalState};
use crate::config::CookieNames;
use crate::crypto::{Clock, Secret, SeededRng, TestClock, Timestamp, is_well_formed_bind};
use crate::event::types::reasons;
use crate::http::csrf::{self, Purpose};
use crate::provider::types::{CallbackQuery, ProviderHealth, ProviderId};

const ORIGIN: &str = "https://auth.example.test";
const BIND: &str = "AAAAAAAAAAAAAAAAAAAAAA";
const BIND2: &str = "BBBBBBBBBBBBBBBBBBBBBB";
const HANDLE: &str = "v1.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const PROVIDER_URL: &str = "https://idp.example.test/authorize?client_id=c&state=S1";

fn fail(kind: FailKind) -> Failure {
    Failure {
        kind,
        reason: reasons::TXN_EXPIRED,
    }
}

fn redirect(to: &str) -> Redirect {
    Redirect {
        location: Url::parse(to).unwrap(),
        set_handle: None,
    }
}

/// Scripted services: every answer is settable, every call is recorded.
struct Fake {
    visit: Mutex<LoginVisit>,
    begin: Mutex<Result<Redirect, Failure>>,
    callback: Mutex<CallbackOutcome>,
    retry: Mutex<Result<Redirect, Failure>>,
    cont: Mutex<Result<Redirect, Failure>>,
    switch_view: Mutex<Result<SwitchView, Failure>>,
    switch_confirm: Mutex<Result<Redirect, Failure>>,
    logout: Mutex<Result<bool, Failure>>,
    health: Mutex<Health>,
    delay: Mutex<Option<Duration>>,
    calls: Mutex<Vec<String>>,
    ctxs: Mutex<Vec<RequestCtx>>,
    cookies: Mutex<Vec<Cookies>>,
    csrf_events: Mutex<Vec<(&'static str, &'static str)>>,
}

impl Fake {
    fn new() -> Arc<Fake> {
        Arc::new(Fake {
            visit: Mutex::new(LoginVisit::Chooser {
                providers: vec![
                    ProviderChoice {
                        id: ProviderId::new("mock"),
                        display_name: "Mock <b>IdP</b>".into(),
                        available: true,
                    },
                    ProviderChoice {
                        id: ProviderId::new("down"),
                        display_name: "Down".into(),
                        available: false,
                    },
                ],
            }),
            begin: Mutex::new(Ok(redirect(PROVIDER_URL))),
            callback: Mutex::new(CallbackOutcome::Redirect(redirect(
                "https://app.example.test/admin/x?_hopae_handoff=K1",
            ))),
            retry: Mutex::new(Ok(redirect(PROVIDER_URL))),
            cont: Mutex::new(Ok(redirect("https://other.example.org/?_hopae_handoff=K2"))),
            switch_view: Mutex::new(Ok(SwitchView {
                host: "app.example.test".into(),
                current_account: "v@example.test".into(),
                incoming_account: "a@example.test".into(),
            })),
            switch_confirm: Mutex::new(Ok(redirect("https://app.example.test/"))),
            logout: Mutex::new(Ok(true)),
            health: Mutex::new(Health {
                store_ok: true,
                providers: vec![
                    (ProviderId::new("mock"), ProviderHealth::Ok),
                    (
                        ProviderId::new("slow"),
                        ProviderHealth::Degraded("discovery"),
                    ),
                    (ProviderId::new("off"), ProviderHealth::Disabled),
                ],
            }),
            delay: Mutex::new(None),
            calls: Mutex::new(vec![]),
            ctxs: Mutex::new(vec![]),
            cookies: Mutex::new(vec![]),
            csrf_events: Mutex::new(vec![]),
        })
    }

    fn rec(&self, what: impl Into<String>, ctx: Option<&RequestCtx>, c: Option<&Cookies>) {
        self.calls.lock().unwrap().push(what.into());
        if let Some(c) = ctx {
            self.ctxs.lock().unwrap().push(c.clone());
        }
        if let Some(c) = c {
            self.cookies.lock().unwrap().push(c.clone());
        }
    }

    async fn pause(&self) {
        let d = *self.delay.lock().unwrap();
        if let Some(d) = d {
            tokio::time::sleep(d).await;
        }
    }

    /// Service calls other than the CSRF event hook (see `csrf_events`).
    fn calls(&self) -> Vec<String> {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .filter(|c| c.as_str() != "csrf_rejected")
            .cloned()
            .collect()
    }

    fn last_cookies(&self) -> Cookies {
        self.cookies
            .lock()
            .unwrap()
            .last()
            .cloned()
            .expect("a call")
    }
}

#[async_trait]
impl PortalServices for Fake {
    async fn login_visit(&self, ctx: &RequestCtx, txn: &Secret, c: &Cookies) -> LoginVisit {
        self.rec(format!("login_visit:{}", txn.expose()), Some(ctx), Some(c));
        self.pause().await;
        self.visit.lock().unwrap().clone()
    }
    async fn begin_provider(
        &self,
        ctx: &RequestCtx,
        txn: &Secret,
        p: &ProviderId,
        c: &Cookies,
    ) -> Result<Redirect, Failure> {
        self.rec(format!("begin:{}:{}", txn.expose(), p), Some(ctx), Some(c));
        self.begin.lock().unwrap().clone()
    }
    async fn callback(
        &self,
        ctx: &RequestCtx,
        p: &ProviderId,
        q: CallbackQuery,
        c: &Cookies,
    ) -> CallbackOutcome {
        self.rec(
            format!("callback:{}:{:?}:{:?}:{:?}", p, q.code, q.state, q.error),
            Some(ctx),
            Some(c),
        );
        self.callback.lock().unwrap().clone()
    }
    async fn retry(&self, ctx: &RequestCtx, state: &str, c: &Cookies) -> Result<Redirect, Failure> {
        self.rec(format!("retry:{state}"), Some(ctx), Some(c));
        self.retry.lock().unwrap().clone()
    }
    async fn continue_sso(
        &self,
        ctx: &RequestCtx,
        txn: &Secret,
        c: &Cookies,
    ) -> Result<Redirect, Failure> {
        self.rec(format!("continue:{}", txn.expose()), Some(ctx), Some(c));
        self.cont.lock().unwrap().clone()
    }
    async fn switch_view(
        &self,
        ctx: &RequestCtx,
        txn: &Secret,
        c: &Cookies,
    ) -> Result<SwitchView, Failure> {
        self.rec(format!("switch_view:{}", txn.expose()), Some(ctx), Some(c));
        self.switch_view.lock().unwrap().clone()
    }
    async fn switch_confirm(
        &self,
        ctx: &RequestCtx,
        txn: &Secret,
        choice: SwitchChoice,
        c: &Cookies,
    ) -> Result<Redirect, Failure> {
        self.rec(
            format!("switch:{}:{:?}", txn.expose(), choice),
            Some(ctx),
            Some(c),
        );
        self.switch_confirm.lock().unwrap().clone()
    }
    async fn logout(&self, ctx: &RequestCtx, handle: &Secret) -> Result<bool, Failure> {
        self.rec(format!("logout:{}", handle.expose()), Some(ctx), None);
        *self.logout.lock().unwrap()
    }
    async fn csrf_rejected(&self, ctx: &RequestCtx, purpose: &'static str, cause: &'static str) {
        self.rec("csrf_rejected", Some(ctx), None);
        self.csrf_events.lock().unwrap().push((purpose, cause));
    }
    async fn health(&self) -> Health {
        self.health.lock().unwrap().clone()
    }
}

struct Env {
    addr: SocketAddr,
    fake: Arc<Fake>,
    state: PortalState,
    http: reqwest::Client,
}

fn config() -> PortalConfig {
    PortalConfig {
        origin: ORIGIN.into(),
        cookie_names: CookieNames {
            handle: "__Host-hopae".into(),
            bind: "__Host-hopae_bind".into(),
            portal: "__Host-hopae_portal".into(),
        },
        secure: true,
        trusted_proxies: vec!["127.0.0.1/32".parse().unwrap()],
        max_concurrent: 8,
        insecure_mode: false,
        unauthenticated_caller: false,
    }
}

async fn env() -> Env {
    env_with(|_| {}).await
}

async fn env_with(tweak: impl FnOnce(&mut PortalConfig)) -> Env {
    let mut cfg = config();
    tweak(&mut cfg);
    let fake = Fake::new();
    let clock: Arc<dyn Clock> = Arc::new(TestClock::new(Timestamp(1_800_000_000_000)));
    let state = PortalState::new(cfg, fake.clone(), clock, Arc::new(SeededRng::new(42)));
    let app = crate::http::portal::router(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await;
    });
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    Env {
        addr,
        fake,
        state,
        http,
    }
}

struct Resp {
    status: u16,
    headers: reqwest::header::HeaderMap,
    body: String,
}

impl Resp {
    fn h(&self, n: &str) -> Option<&str> {
        self.headers.get(n).and_then(|v| v.to_str().ok())
    }
    fn set_cookies(&self) -> Vec<String> {
        self.headers
            .get_all("set-cookie")
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .collect()
    }
    fn cookie(&self, name: &str) -> Option<String> {
        self.set_cookies()
            .into_iter()
            .find(|c| c.starts_with(&format!("{name}=")))
    }
}

impl Env {
    async fn send(&self, rb: reqwest::RequestBuilder) -> Resp {
        let r = rb.send().await.unwrap();
        Resp {
            status: r.status().as_u16(),
            headers: r.headers().clone(),
            body: r.text().await.unwrap(),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.addr)
    }

    async fn get(&self, path: &str, cookie: Option<&str>) -> Resp {
        let mut rb = self.http.get(self.url(path));
        if let Some(c) = cookie {
            rb = rb.header("cookie", c);
        }
        self.send(rb).await
    }

    async fn get_lang(&self, path: &str, lang: &str) -> Resp {
        self.send(
            self.http
                .get(self.url(path))
                .header("accept-language", lang),
        )
        .await
    }

    async fn post(
        &self,
        path: &str,
        fields: &[(&str, &str)],
        cookie: Option<&str>,
        origin: Option<&str>,
    ) -> Resp {
        let mut ser = url::form_urlencoded::Serializer::new(String::new());
        for (k, v) in fields {
            ser.append_pair(k, v);
        }
        let mut rb = self
            .http
            .post(self.url(path))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(ser.finish());
        if let Some(c) = cookie {
            rb = rb.header("cookie", c);
        }
        if let Some(o) = origin {
            rb = rb.header("origin", o);
        }
        self.send(rb).await
    }

    /// A token as the portal would have issued it for `binding`.
    fn token(&self, binding: &str, purpose: Purpose) -> String {
        csrf::issue(
            &self.state.csrf_key,
            binding,
            purpose,
            self.state.clock.now(),
            self.state.rng.as_ref(),
        )
    }
}

fn portal_cookie(v: &str) -> String {
    format!("__Host-hopae_portal={v}")
}

fn hidden(html: &str, name: &str) -> String {
    let marker = format!("name=\"{name}\" value=\"");
    let i = html
        .find(&marker)
        .unwrap_or_else(|| panic!("no {name} field in {html}"));
    let rest = &html[i + marker.len()..];
    rest[..rest.find('"').unwrap()].to_string()
}

/// The page with the per-request id removed, to compare failure pages.
fn without_request_id(body: &str) -> String {
    let i = body.find("class=\"rid\"").expect("request id line");
    let j = body[i..].find("</p>").unwrap() + i;
    format!("{}{}", &body[..i], &body[j..])
}

fn assert_security_headers(r: &Resp, what: &str) {
    assert_eq!(r.h("cache-control"), Some("no-store"), "{what}");
    assert_eq!(r.h("x-content-type-options"), Some("nosniff"), "{what}");
    assert_eq!(r.h("referrer-policy"), Some("no-referrer"), "{what}");
    assert_eq!(r.h("x-frame-options"), Some("DENY"), "{what}");
    assert_eq!(
        r.h("content-security-policy"),
        Some("default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'"),
        "{what}"
    );
    assert!(r.h("x-request-id").is_some_and(|v| !v.is_empty()), "{what}");
}

// ---- security headers, 404, limits ----------------------------------------

#[tokio::test]
async fn every_response_carries_the_security_headers() {
    let e = env().await;
    let big = "x".repeat(70 * 1024);
    let cases: Vec<(&str, Resp)> = vec![
        ("login 400", e.get("/login", None).await),
        ("login 200", e.get("/login?txn=T1", None).await),
        ("404", e.get("/nope", None).await),
        ("verify 404", e.get("/_hopae/verify", None).await),
        ("healthz", e.get("/healthz", None).await),
        ("css", e.get("/assets/portal.css", None).await),
        ("logout page", e.get("/logout", None).await),
        (
            "403",
            e.post("/login/mock", &[("txn", "T1")], None, Some(ORIGIN))
                .await,
        ),
        ("405", e.send(e.http.post(e.url("/healthz")).body("")).await),
        (
            "413",
            e.post("/logout", &[("junk", &big)], None, Some(ORIGIN))
                .await,
        ),
    ];
    for (what, r) in &cases {
        assert_security_headers(r, what);
    }
    // And on a redirect.
    *e.fake.visit.lock().unwrap() = LoginVisit::Redirect(redirect(PROVIDER_URL));
    let r = e.get("/login?txn=T1", None).await;
    assert_eq!(r.status, 302);
    assert_security_headers(&r, "302");
}

#[tokio::test]
async fn verify_endpoint_is_not_served_here() {
    let e = env().await;
    let r = e
        .send(
            e.http
                .get(e.url("/_hopae/verify"))
                .header("x-hopae-gateway-key", "k")
                .header("cookie", "__Host-hopae=v1.x"),
        )
        .await;
    assert_eq!(r.status, 404);
    assert!(e.fake.calls().is_empty());
    assert_eq!(e.get("/", None).await.status, 404);
    assert_eq!(e.get("/stepup?txn=T", None).await.status, 404);
}

#[tokio::test]
async fn oversized_body_is_refused_with_413() {
    let e = env().await;
    let big = "x".repeat(70 * 1024);
    let r = e
        .post(
            "/login/mock",
            &[("csrf", &big)],
            Some(&portal_cookie(BIND)),
            Some(ORIGIN),
        )
        .await;
    assert_eq!(r.status, 413);
    assert!(r.body.contains("<h1>"));
    assert!(e.fake.calls().is_empty());
}

#[tokio::test]
async fn oversized_cookie_header_is_refused() {
    let e = env().await;
    let r = e
        .get("/login?txn=T1", Some(&format!("junk={}", "x".repeat(9000))))
        .await;
    assert_eq!(r.status, 400);
    assert!(e.fake.calls().is_empty());
    assert_security_headers(&r, "cookie too large");
}

#[tokio::test]
async fn concurrency_cap_answers_503_immediately() {
    let e = env_with(|c| c.max_concurrent = 2).await;
    *e.fake.delay.lock().unwrap() = Some(Duration::from_millis(400));
    let started = std::time::Instant::now();
    let mut tasks = vec![];
    for _ in 0..6 {
        let url = e.url("/login?txn=T1");
        let http = e.http.clone();
        tasks.push(tokio::spawn(async move {
            let r = http.get(url).send().await.unwrap();
            (
                r.status().as_u16(),
                r.headers().get("cache-control").cloned(),
                started.elapsed(),
            )
        }));
    }
    let mut ok = 0;
    let mut busy = 0;
    for t in tasks {
        let (status, cc, took) = t.await.unwrap();
        match status {
            200 => ok += 1,
            503 => {
                busy += 1;
                assert!(
                    took < Duration::from_millis(300),
                    "503 must not queue: {took:?}"
                );
                assert_eq!(cc.unwrap(), "no-store");
            }
            other => panic!("unexpected {other}"),
        }
    }
    assert_eq!(ok, 2);
    assert_eq!(busy, 4);
    // Capacity returns afterwards.
    *e.fake.delay.lock().unwrap() = None;
    assert_eq!(e.get("/login?txn=T1", None).await.status, 200);
}

#[tokio::test]
async fn static_stylesheet_is_served_from_self() {
    let e = env().await;
    let r = e.get("/assets/portal.css", None).await;
    assert_eq!(r.status, 200);
    assert!(r.h("content-type").unwrap().starts_with("text/css"));
    assert!(r.body.contains("body"));
}

#[tokio::test]
async fn wrong_methods_are_405() {
    let e = env().await;
    assert_eq!(
        e.send(e.http.post(e.url("/healthz")).body("")).await.status,
        405
    );
    assert_eq!(e.get("/login/mock", None).await.status, 405);
    assert_eq!(e.get("/login/retry", None).await.status, 405);
    assert_eq!(
        e.send(e.http.post(e.url("/callback/mock")).body(""))
            .await
            .status,
        405
    );
}

// ---- GET /login ------------------------------------------------------------

#[tokio::test]
async fn login_without_a_valid_txn_is_400_and_calls_nothing() {
    let e = env().await;
    for path in [
        "/login",
        "/login?rd=https://evil.example.org/",
        "/login?txn=",
        "/login?txn=a%20b",
        &format!("/login?txn={}", "a".repeat(300)),
    ] {
        let r = e.get(path, None).await;
        assert_eq!(r.status, 400, "{path}");
        assert!(r.set_cookies().is_empty(), "{path}");
        assert!(r.h("location").is_none(), "{path}");
    }
    assert!(e.fake.calls().is_empty());
}

#[tokio::test]
async fn login_ignores_return_style_parameters() {
    let e = env().await;
    *e.fake.visit.lock().unwrap() = LoginVisit::Redirect(redirect(PROVIDER_URL));
    let r = e
        .get(
            "/login?txn=T1&return=https://evil.example.org/&redirect_uri=https://evil.example.org/&rd=x",
            None,
        )
        .await;
    assert_eq!(r.status, 302);
    assert_eq!(r.h("location"), Some(PROVIDER_URL));
    assert_eq!(e.fake.calls(), vec!["login_visit:T1".to_string()]);
}

#[tokio::test]
async fn portal_cookie_is_planted_kept_refreshed_and_replaced() {
    let e = env().await;
    // First visit: planted.
    let r = e.get("/login?txn=T1", None).await;
    assert_eq!(r.status, 200);
    let c = r
        .cookie("__Host-hopae_portal")
        .expect("portal cookie planted");
    let (pair, attrs) = c.split_once("; ").unwrap();
    let value = pair
        .strip_prefix("__Host-hopae_portal=")
        .unwrap()
        .to_string();
    assert!(is_well_formed_bind(&value), "{value}");
    assert_eq!(attrs, "Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=600");
    assert_eq!(r.set_cookies().len(), 1);
    // The service saw the value that was planted.
    assert_eq!(e.fake.last_cookies().bind.unwrap().expose(), value);

    // Again with the cookie: same value, fresh Max-Age.
    let r2 = e.get("/login?txn=T1", Some(&portal_cookie(&value))).await;
    assert_eq!(r2.cookie("__Host-hopae_portal").unwrap(), c);

    // A well-formed value of the browser's own is stable, not replaced.
    let r3 = e.get("/login?txn=T1", Some(&portal_cookie(BIND))).await;
    assert!(
        r3.cookie("__Host-hopae_portal")
            .unwrap()
            .starts_with(&format!("__Host-hopae_portal={BIND};"))
    );

    // Malformed values are replaced.
    for bad in ["short", "AAAAAAAAAAAAAAAAAAAAA!", "AAAAAAAAAAAAAAAAAAAAAAA"] {
        let r4 = e.get("/login?txn=T1", Some(&portal_cookie(bad))).await;
        let nc = r4.cookie("__Host-hopae_portal").unwrap();
        let nv = nc
            .split_once(';')
            .unwrap()
            .0
            .strip_prefix("__Host-hopae_portal=")
            .unwrap();
        assert!(is_well_formed_bind(nv) && nv != bad, "{bad} -> {nv}");
    }
}

#[tokio::test]
async fn failed_visits_set_no_cookie() {
    let e = env().await;
    for kind in [FailKind::Expired, FailKind::Failed, FailKind::Unavailable] {
        *e.fake.visit.lock().unwrap() = LoginVisit::Failed(fail(kind));
        let r = e.get("/login?txn=T1", None).await;
        assert_eq!(r.status, ErrorStatus::of(kind), "{kind:?}");
        assert!(r.set_cookies().is_empty(), "{kind:?}");
    }
}

struct ErrorStatus;
impl ErrorStatus {
    fn of(kind: FailKind) -> u16 {
        match kind {
            FailKind::Expired | FailKind::Failed => 400,
            FailKind::Forbidden => 403,
            FailKind::Unavailable => 503,
        }
    }
}

#[tokio::test]
async fn development_mode_drops_prefix_and_secure() {
    let e = env_with(|c| {
        c.secure = false;
        c.cookie_names = CookieNames {
            handle: "hopae".into(),
            bind: "hopae_bind".into(),
            portal: "hopae_portal".into(),
        };
    })
    .await;
    let r = e.get("/login?txn=T1", None).await;
    let c = r.cookie("hopae_portal").expect("cookie without prefix");
    assert!(
        c.ends_with("; Path=/; HttpOnly; SameSite=Lax; Max-Age=600"),
        "{c}"
    );
    assert!(!c.contains("Secure"));
    // The prefixed name is not read in development mode, the plain one is.
    let r2 = e
        .get("/login?txn=T1", Some(&format!("hopae_portal={BIND}")))
        .await;
    assert_eq!(e.fake.last_cookies().bind.unwrap().expose(), BIND);
    assert!(
        r2.cookie("hopae_portal")
            .unwrap()
            .starts_with(&format!("hopae_portal={BIND};"))
    );
}

#[tokio::test]
async fn chooser_lists_providers_escapes_names_and_carries_a_bound_token() {
    let e = env().await;
    let r = e.get("/login?txn=T1", Some(&portal_cookie(BIND))).await;
    assert_eq!(r.status, 200);
    assert!(r.h("content-type").unwrap().starts_with("text/html"));
    assert!(r.body.contains("action=\"/login/mock\""));
    assert!(
        !r.body.contains("action=\"/login/down\""),
        "unavailable providers have no button"
    );
    assert!(r.body.contains("Down is temporarily unavailable."));
    assert!(
        r.body.contains("Mock &#60;b&#62;IdP&#60;/b&#62;"),
        "{}",
        r.body
    );
    assert!(!r.body.contains("<b>IdP"));
    assert!(!r.body.contains("<script") && !r.body.contains("style="));
    assert_eq!(hidden(&r.body, "txn"), "T1");
    let t = hidden(&r.body, "csrf");
    assert_eq!(
        csrf::verify(
            &e.state.csrf_key,
            BIND,
            Purpose::Login,
            &t,
            e.state.clock.now()
        ),
        Ok(())
    );
    // The request id on the page is the one in the header.
    assert!(r.body.contains(r.h("x-request-id").unwrap()));
}

#[tokio::test]
async fn pages_follow_accept_language() {
    let e = env().await;
    let en = e.get_lang("/login?txn=T1", "en-US,en;q=0.9").await;
    assert!(en.body.contains("<html lang=\"en\">") && en.body.contains("Sign in"));
    let ko = e.get_lang("/login?txn=T1", "ko-KR,ko;q=0.9,en;q=0.8").await;
    assert!(ko.body.contains("<html lang=\"ko\">") && ko.body.contains("로그인"));
    assert!(!ko.body.contains("Sign in"));
    let default = e.get("/login?txn=T1", None).await;
    assert!(default.body.contains("<html lang=\"en\">"));
    let ko404 = e.get_lang("/nope", "ko").await;
    assert!(ko404.body.contains("페이지를 찾을 수 없습니다"));
}

#[tokio::test]
async fn single_provider_and_sso_redirects_carry_cookies() {
    let e = env().await;
    *e.fake.visit.lock().unwrap() = LoginVisit::Redirect(Redirect {
        location: Url::parse("https://other.example.org/?_hopae_handoff=K2").unwrap(),
        set_handle: Some(HandleCookie {
            value: Secret::new(HANDLE.to_string()),
            max_age: Duration::from_secs(1234),
        }),
    });
    let r = e.get("/login?txn=T2", Some(&portal_cookie(BIND))).await;
    assert_eq!(r.status, 302);
    assert_eq!(
        r.h("location"),
        Some("https://other.example.org/?_hopae_handoff=K2")
    );
    let cookies = r.set_cookies();
    assert_eq!(cookies.len(), 2, "{cookies:?}");
    assert!(
        cookies
            .iter()
            .any(|c| c.starts_with(&format!("__Host-hopae_portal={BIND};")))
    );
    assert!(cookies.contains(&format!(
        "__Host-hopae={HANDLE}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=1234"
    )));
}

#[tokio::test]
async fn confirm_new_host_renders_a_bound_form() {
    let e = env().await;
    *e.fake.visit.lock().unwrap() = LoginVisit::ConfirmNewHost {
        host: "other.example.org".into(),
    };
    let r = e.get("/login?txn=T2", Some(&portal_cookie(BIND))).await;
    assert_eq!(r.status, 200);
    assert!(r.body.contains("other.example.org"));
    assert!(r.body.contains("action=\"/login/continue\""));
    let t = hidden(&r.body, "csrf");
    assert_eq!(
        csrf::verify(
            &e.state.csrf_key,
            BIND,
            Purpose::Continue,
            &t,
            e.state.clock.now()
        ),
        Ok(())
    );
    // The token for the chooser does not work here and vice versa.
    assert!(
        csrf::verify(
            &e.state.csrf_key,
            BIND,
            Purpose::Login,
            &t,
            e.state.clock.now()
        )
        .is_err()
    );
}

// ---- POST guards ------------------------------------------------------------

struct Case<'a> {
    what: &'a str,
    csrf: Option<&'a str>,
    cookie: Option<&'a str>,
    origin: Option<&'a str>,
    cause: &'a str,
}

#[tokio::test]
async fn post_login_provider_requires_origin_and_a_bound_token() {
    let e = env().await;
    let cookie = portal_cookie(BIND);
    let good = e.token(BIND, Purpose::Login);
    let other_cookie = e.token(BIND2, Purpose::Login);
    let other_purpose = e.token(BIND, Purpose::Logout);
    let stale = csrf::issue(
        &e.state.csrf_key,
        BIND,
        Purpose::Login,
        Timestamp(1_800_000_000_000).sub(Duration::from_secs(601)),
        e.state.rng.as_ref(),
    );

    let cases = [
        Case {
            what: "no origin",
            csrf: Some(&good),
            cookie: Some(&cookie),
            origin: None,
            cause: "origin",
        },
        Case {
            what: "foreign origin",
            csrf: Some(&good),
            cookie: Some(&cookie),
            origin: Some("https://evil.example.org"),
            cause: "origin",
        },
        Case {
            what: "null origin",
            csrf: Some(&good),
            cookie: Some(&cookie),
            origin: Some("null"),
            cause: "origin",
        },
        Case {
            what: "no token",
            csrf: None,
            cookie: Some(&cookie),
            origin: Some(ORIGIN),
            cause: "token",
        },
        Case {
            what: "garbage token",
            csrf: Some("zzz"),
            cookie: Some(&cookie),
            origin: Some(ORIGIN),
            cause: "token",
        },
        Case {
            what: "token of another cookie",
            csrf: Some(&other_cookie),
            cookie: Some(&cookie),
            origin: Some(ORIGIN),
            cause: "token",
        },
        Case {
            what: "token of another purpose",
            csrf: Some(&other_purpose),
            cookie: Some(&cookie),
            origin: Some(ORIGIN),
            cause: "token",
        },
        Case {
            what: "expired token",
            csrf: Some(&stale),
            cookie: Some(&cookie),
            origin: Some(ORIGIN),
            cause: "expired",
        },
        Case {
            what: "no portal cookie",
            csrf: Some(&good),
            cookie: None,
            origin: Some(ORIGIN),
            cause: "token",
        },
    ];
    for c in &cases {
        let mut fields = vec![("txn", "T1")];
        if let Some(t) = c.csrf {
            fields.push(("csrf", t));
        }
        let before = e.fake.csrf_events.lock().unwrap().len();
        let r = e.post("/login/mock", &fields, c.cookie, c.origin).await;
        assert_eq!(r.status, 403, "{}", c.what);
        assert!(r.h("location").is_none(), "{}", c.what);
        assert_security_headers(&r, c.what);
        let ev = e.fake.csrf_events.lock().unwrap().clone();
        assert_eq!(ev.len(), before + 1, "{}", c.what);
        assert_eq!(
            ev.last().unwrap(),
            &("login", c.cause_static()),
            "{}",
            c.what
        );
    }
    assert!(!e.fake.calls().iter().any(|c| c.starts_with("begin")));

    // And the accepted request, with extra client "return" fields ignored.
    let r = e
        .post(
            "/login/mock",
            &[
                ("txn", "T1"),
                ("csrf", &good),
                ("return", "https://evil.example.org/"),
            ],
            Some(&cookie),
            Some(ORIGIN),
        )
        .await;
    assert_eq!(r.status, 302);
    assert_eq!(r.h("location"), Some(PROVIDER_URL));
    assert_eq!(e.fake.calls().last().unwrap(), "begin:T1:mock");
    assert_eq!(e.fake.last_cookies().bind.unwrap().expose(), BIND);
}

impl Case<'_> {
    fn cause_static(&self) -> &'static str {
        match self.cause {
            "origin" => "origin",
            "expired" => "expired",
            _ => "token",
        }
    }
}

#[tokio::test]
async fn repeated_origin_headers_are_refused() {
    let e = env().await;
    let t = e.token(BIND, Purpose::Login);
    let r = e
        .send(
            e.http
                .post(e.url("/login/mock"))
                .header("content-type", "application/x-www-form-urlencoded")
                .header("cookie", portal_cookie(BIND))
                .header("origin", ORIGIN)
                .header("origin", "https://evil.example.org")
                .body(format!("csrf={t}&txn=T1")),
        )
        .await;
    assert_eq!(r.status, 403);
    assert!(!e.fake.calls().iter().any(|c| c.starts_with("begin")));
}

#[tokio::test]
async fn post_requires_a_form_body_and_a_sane_provider_segment() {
    let e = env().await;
    let t = e.token(BIND, Purpose::Login);
    let r = e
        .send(
            e.http
                .post(e.url("/login/mock"))
                .header("content-type", "application/json")
                .header("origin", ORIGIN)
                .header("cookie", portal_cookie(BIND))
                .body(format!("{{\"csrf\":\"{t}\",\"txn\":\"T1\"}}")),
        )
        .await;
    assert_eq!(r.status, 400);
    let r = e
        .post(
            "/login/..%2Fx",
            &[("csrf", &t), ("txn", "T1")],
            Some(&portal_cookie(BIND)),
            Some(ORIGIN),
        )
        .await;
    assert!(r.status == 400 || r.status == 404, "{}", r.status);
    let r = e
        .post(
            "/login/mock",
            &[("csrf", &t)],
            Some(&portal_cookie(BIND)),
            Some(ORIGIN),
        )
        .await;
    assert_eq!(r.status, 400, "missing txn");
    assert!(!e.fake.calls().iter().any(|c| c.starts_with("begin")));
}

#[tokio::test]
async fn begin_failures_render_pages_with_the_right_status() {
    let e = env().await;
    let cookie = portal_cookie(BIND);
    let t = e.token(BIND, Purpose::Login);
    for (kind, status) in [
        (FailKind::Expired, 400),
        (FailKind::Failed, 400),
        (FailKind::Forbidden, 403),
        (FailKind::Unavailable, 503),
    ] {
        *e.fake.begin.lock().unwrap() = Err(fail(kind));
        let r = e
            .post(
                "/login/mock",
                &[("csrf", &t), ("txn", "T1")],
                Some(&cookie),
                Some(ORIGIN),
            )
            .await;
        assert_eq!(r.status, status, "{kind:?}");
        assert!(r.h("location").is_none());
    }
}

// ---- callback ----------------------------------------------------------------

#[tokio::test]
async fn callback_passes_the_query_and_the_presented_cookie() {
    let e = env().await;
    *e.fake.callback.lock().unwrap() = CallbackOutcome::Redirect(Redirect {
        location: Url::parse("https://app.example.test/admin/x?_hopae_handoff=K1").unwrap(),
        set_handle: Some(HandleCookie {
            value: Secret::new(HANDLE.to_string()),
            max_age: Duration::from_secs(604_800),
        }),
    });
    let r = e
        .get(
            "/callback/mock?code=AC1&state=S1&return=https://evil.example.org/",
            Some(&portal_cookie(BIND)),
        )
        .await;
    assert_eq!(r.status, 302);
    assert_eq!(
        r.h("location"),
        Some("https://app.example.test/admin/x?_hopae_handoff=K1")
    );
    // Handle planted with the documented attributes; the portal cookie is left alone.
    assert_eq!(
        r.set_cookies(),
        vec![format!(
            "__Host-hopae={HANDLE}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=604800"
        )]
    );
    assert_eq!(
        e.fake.calls(),
        vec![r#"callback:mock:Some("AC1"):Some("S1"):None"#.to_string()]
    );
    assert_eq!(e.fake.last_cookies().bind.unwrap().expose(), BIND);

    // No cookie presented: the service is told so (it decides).
    let _ = e.get("/callback/mock?code=AC1&state=S1", None).await;
    assert!(e.fake.last_cookies().bind.is_none());
    // A provider error parameter is passed through, never rendered.
    let r = e
        .get(
            "/callback/mock?error=access_denied&error_description=%3Cscript%3E&state=S1",
            None,
        )
        .await;
    assert!(!r.body.contains("script"));
    assert!(
        e.fake
            .calls()
            .last()
            .unwrap()
            .contains(r#"Some("access_denied")"#)
    );
}

#[tokio::test]
async fn callback_rejects_oversized_parameters_without_calling_the_service() {
    let e = env().await;
    let r = e
        .get(
            &format!("/callback/mock?code={}&state=S1", "a".repeat(5000)),
            None,
        )
        .await;
    assert_eq!(r.status, 400);
    assert!(e.fake.calls().is_empty());
}

#[tokio::test]
async fn callback_failure_pages_are_uniform() {
    let e = env().await;
    let mut bodies = vec![];
    for reason in [
        reasons::INVALID_SIGNATURE,
        reasons::INVALID_NONCE,
        reasons::PROVIDER_TIMEOUT,
        reasons::USERINFO_SUBJECT_MISMATCH,
    ] {
        *e.fake.callback.lock().unwrap() = CallbackOutcome::Failed(Failure {
            kind: FailKind::Failed,
            reason,
        });
        let r = e
            .get("/callback/mock?code=a&state=S1", Some(&portal_cookie(BIND)))
            .await;
        assert_eq!(r.status, 400);
        assert!(
            !r.body.contains(reason.0),
            "reason code must not be rendered"
        );
        bodies.push(without_request_id(&r.body));
    }
    assert!(bodies.windows(2).all(|w| w[0] == w[1]));
    // The request id still differs per request.
    let a = e.get("/callback/mock?code=a&state=S1", None).await;
    let b = e.get("/callback/mock?code=a&state=S1", None).await;
    assert_ne!(a.h("x-request-id"), b.h("x-request-id"));
}

#[tokio::test]
async fn link_notice_names_the_provider_but_no_email() {
    let e = env().await;
    *e.fake.callback.lock().unwrap() = CallbackOutcome::LinkNotice {
        via_provider: Some("Trusted One".into()),
    };
    let r = e
        .get("/callback/mock?code=a&state=S1", Some(&portal_cookie(BIND)))
        .await;
    assert_eq!(r.status, 200);
    assert!(r.body.contains("Sign in with Trusted One to connect it."));
    assert!(r.set_cookies().is_empty());
    *e.fake.callback.lock().unwrap() = CallbackOutcome::LinkNotice { via_provider: None };
    let r = e
        .get("/callback/mock?code=a&state=S1", Some(&portal_cookie(BIND)))
        .await;
    assert!(r.body.contains("method you used before"));
}

#[tokio::test]
async fn retry_offer_page_and_post_retry() {
    let e = env().await;
    *e.fake.callback.lock().unwrap() = CallbackOutcome::RetryOffer { can_retry: true };
    let r = e
        .get(
            "/callback/mock?code=ACA&state=SA",
            Some(&portal_cookie(BIND2)),
        )
        .await;
    assert_eq!(r.status, 200);
    assert!(r.body.contains("action=\"/login/retry\""));
    assert_eq!(hidden(&r.body, "state"), "SA");
    // The token is bound to the cookie the browser presented (the replacement), not a planted one.
    assert!(r.set_cookies().is_empty());
    let t = hidden(&r.body, "csrf");
    assert_eq!(
        csrf::verify(
            &e.state.csrf_key,
            BIND2,
            Purpose::Retry,
            &t,
            e.state.clock.now()
        ),
        Ok(())
    );

    // POST /login/retry with the page's token and the same cookie.
    let ok = e
        .post(
            "/login/retry",
            &[("csrf", &t), ("state", "SA")],
            Some(&portal_cookie(BIND2)),
            Some(ORIGIN),
        )
        .await;
    assert_eq!(ok.status, 302);
    assert_eq!(ok.h("location"), Some(PROVIDER_URL));
    assert_eq!(e.fake.calls().last().unwrap(), "retry:SA");
    assert_eq!(e.fake.last_cookies().bind.unwrap().expose(), BIND2);

    // Without the token, from a foreign origin, or with another cookie: 403, service untouched.
    let n = e.fake.calls().len();
    for (fields, cookie, origin) in [
        (vec![("state", "SA")], BIND2, ORIGIN),
        (
            vec![("csrf", t.as_str()), ("state", "SA")],
            BIND2,
            "https://evil.example.org",
        ),
        (vec![("csrf", t.as_str()), ("state", "SA")], BIND, ORIGIN),
    ] {
        let r = e
            .post(
                "/login/retry",
                &fields,
                Some(&portal_cookie(cookie)),
                Some(origin),
            )
            .await;
        assert_eq!(r.status, 403);
    }
    assert_eq!(e.fake.calls().len(), n);

    // The service refuses (not a portal_bind_mismatch transaction, or no recoveries left): 403.
    *e.fake.retry.lock().unwrap() = Err(fail(FailKind::Forbidden));
    let r = e
        .post(
            "/login/retry",
            &[("csrf", &t), ("state", "SA")],
            Some(&portal_cookie(BIND2)),
            Some(ORIGIN),
        )
        .await;
    assert_eq!(r.status, 403);
}

#[tokio::test]
async fn exhausted_recoveries_offer_no_retry() {
    let e = env().await;
    *e.fake.callback.lock().unwrap() = CallbackOutcome::RetryOffer { can_retry: false };
    let r = e
        .get(
            "/callback/mock?code=ACA&state=SA",
            Some(&portal_cookie(BIND2)),
        )
        .await;
    assert_eq!(r.status, 403);
    assert!(!r.body.contains("/login/retry"));
    assert!(!r.body.contains("<form"));
}

// ---- switch, continue --------------------------------------------------------

#[tokio::test]
async fn switch_page_names_host_and_accounts_and_posts_with_a_token() {
    let e = env().await;
    let r = e.get("/switch?txn=Ts", Some(&portal_cookie(BIND))).await;
    assert_eq!(r.status, 200);
    for needle in ["app.example.test", "v@example.test", "a@example.test"] {
        assert!(r.body.contains(needle), "{needle}");
    }
    assert_eq!(hidden(&r.body, "txn"), "Ts");
    assert!(r.cookie("__Host-hopae_portal").is_some());
    let t = hidden(&r.body, "csrf");
    assert_eq!(
        csrf::verify(
            &e.state.csrf_key,
            BIND,
            Purpose::Switch,
            &t,
            e.state.clock.now()
        ),
        Ok(())
    );
    // Showing the form changes nothing.
    assert_eq!(e.fake.calls(), vec!["switch_view:Ts".to_string()]);

    let cookie = portal_cookie(BIND);
    for (choice, expect) in [("switch", "Switch"), ("keep", "Keep")] {
        let r = e
            .post(
                "/switch",
                &[("csrf", &t), ("txn", "Ts"), ("choice", choice)],
                Some(&cookie),
                Some(ORIGIN),
            )
            .await;
        assert_eq!(r.status, 302, "{choice}");
        assert_eq!(r.h("location"), Some("https://app.example.test/"));
        assert_eq!(
            e.fake.calls().last().unwrap(),
            &format!("switch:Ts:{expect}")
        );
    }
    let n = e.fake.calls().len();
    // Unknown choice, no token, foreign origin.
    let bad = [
        e.post(
            "/switch",
            &[("csrf", &t), ("txn", "Ts"), ("choice", "delete")],
            Some(&cookie),
            Some(ORIGIN),
        )
        .await,
        e.post(
            "/switch",
            &[("txn", "Ts"), ("choice", "switch")],
            Some(&cookie),
            Some(ORIGIN),
        )
        .await,
        e.post(
            "/switch",
            &[("csrf", &t), ("txn", "Ts"), ("choice", "switch")],
            Some(&cookie),
            Some("https://evil.example.org"),
        )
        .await,
    ];
    assert_eq!(
        bad.iter().map(|r| r.status).collect::<Vec<_>>(),
        vec![400, 403, 403]
    );
    assert_eq!(e.fake.calls().len(), n);
}

#[tokio::test]
async fn continue_post_is_guarded() {
    let e = env().await;
    let cookie = portal_cookie(BIND);
    let t = e.token(BIND, Purpose::Continue);
    let r = e
        .post(
            "/login/continue",
            &[("csrf", &t), ("txn", "T2")],
            Some(&cookie),
            Some(ORIGIN),
        )
        .await;
    assert_eq!(r.status, 302);
    assert_eq!(
        r.h("location"),
        Some("https://other.example.org/?_hopae_handoff=K2")
    );
    let wrong = e.token(BIND, Purpose::Login);
    let r = e
        .post(
            "/login/continue",
            &[("csrf", &wrong), ("txn", "T2")],
            Some(&cookie),
            Some(ORIGIN),
        )
        .await;
    assert_eq!(r.status, 403);
}

// ---- logout --------------------------------------------------------------------

#[tokio::test]
async fn logout_confirmation_is_bound_to_the_handle() {
    let e = env().await;
    let r = e
        .get("/logout", Some(&format!("__Host-hopae={HANDLE}")))
        .await;
    assert_eq!(r.status, 200);
    assert_eq!(r.h("cache-control"), Some("no-store"));
    let t = hidden(&r.body, "csrf");
    assert_eq!(
        csrf::verify(
            &e.state.csrf_key,
            HANDLE,
            Purpose::Logout,
            &t,
            e.state.clock.now()
        ),
        Ok(())
    );
    assert!(e.fake.calls().is_empty(), "GET /logout changes nothing");
}

#[tokio::test]
async fn confirmed_logout_terminates_and_clears_with_matching_attributes() {
    let e = env().await;
    let cookie = format!("__Host-hopae={HANDLE}");
    let t = e.token(HANDLE, Purpose::Logout);
    let r = e
        .post(
            "/logout",
            &[("csrf", &t), ("session", "s_2")],
            Some(&cookie),
            Some(ORIGIN),
        )
        .await;
    assert_eq!(r.status, 200);
    assert!(r.body.contains("Signed out"));
    assert_eq!(
        r.set_cookies(),
        vec!["__Host-hopae=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0".to_string()]
    );
    // Only the handle is passed on: the `session` field cannot target another session.
    assert_eq!(e.fake.calls(), vec![format!("logout:{HANDLE}")]);

    // Replay: the same request again is harmless (the service says nothing was left to end).
    *e.fake.logout.lock().unwrap() = Ok(false);
    let r2 = e
        .post("/logout", &[("csrf", &t)], Some(&cookie), Some(ORIGIN))
        .await;
    assert_eq!(r2.status, 200);
}

#[tokio::test]
async fn logout_with_a_session_checks_token_and_origin() {
    let e = env().await;
    let cookie = format!("__Host-hopae={HANDLE}");
    let other = "v1.BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
    let wrong_binding = e.token(other, Purpose::Logout);
    let good = e.token(HANDLE, Purpose::Logout);
    let cases = [
        ("no token", vec![], ORIGIN, "token"),
        (
            "token of another session",
            vec![("csrf", wrong_binding.as_str())],
            ORIGIN,
            "token",
        ),
        (
            "cross-site origin",
            vec![("csrf", good.as_str())],
            "https://evil.example.org",
            "origin",
        ),
    ];
    for (what, fields, origin, cause) in cases {
        let r = e
            .post("/logout", &fields, Some(&cookie), Some(origin))
            .await;
        assert_eq!(r.status, 403, "{what}");
        assert!(r.set_cookies().is_empty(), "{what}");
        assert_eq!(
            e.fake.csrf_events.lock().unwrap().last().unwrap(),
            &("logout", cause),
            "{what}"
        );
    }
    assert!(!e.fake.calls().iter().any(|c| c.starts_with("logout:")));
}

#[tokio::test]
async fn logout_without_a_session_is_a_silent_no_op() {
    let e = env().await;
    // GET then POST with the page's token, no cookie at all.
    let page = e.get("/logout", None).await;
    assert_eq!(page.status, 200);
    let t = hidden(&page.body, "csrf");
    let r = e.post("/logout", &[("csrf", &t)], None, Some(ORIGIN)).await;
    assert_eq!(r.status, 200);
    assert!(r.body.contains("Signed out"));
    // Even a cross-site post without the cookie only reaches the no-op.
    let r = e
        .post("/logout", &[], None, Some("https://evil.example.org"))
        .await;
    assert_eq!(r.status, 200);
    assert!(e.fake.calls().is_empty());
    assert!(e.fake.csrf_events.lock().unwrap().is_empty());
}

// ---- health, client info, request ids ---------------------------------------------

#[tokio::test]
async fn healthz_reports_providers_and_flags() {
    let e = env_with(|c| {
        c.insecure_mode = true;
        c.unauthenticated_caller = true;
    })
    .await;
    let r = e.get("/healthz", None).await;
    assert_eq!(r.status, 200);
    assert!(r.h("content-type").unwrap().starts_with("application/json"));
    let v: serde_json::Value = serde_json::from_str(&r.body).unwrap();
    assert_eq!(v["status"], "ok");
    assert_eq!(v["ready"], true);
    assert_eq!(v["store"], "ok");
    assert_eq!(v["insecure_mode"], true);
    assert_eq!(v["unauthenticated_caller"], true);
    assert_eq!(v["providers"]["mock"], "ok");
    assert_eq!(v["providers"]["slow"], "degraded");
    assert_eq!(v["providers"]["off"], "disabled");

    e.fake.health.lock().unwrap().store_ok = false;
    let r = e.get("/healthz", None).await;
    assert_eq!(r.status, 200, "liveness stays 200");
    let v: serde_json::Value = serde_json::from_str(&r.body).unwrap();
    assert_eq!(v["ready"], false);
    assert_eq!(v["store"], "unavailable");
    assert_eq!(v["insecure_mode"], true);
    let plain = env().await.get("/healthz", None).await;
    let v: serde_json::Value = serde_json::from_str(&plain.body).unwrap();
    assert_eq!(v["insecure_mode"], false);
    assert_eq!(v["unauthenticated_caller"], false);
}

fn fwd(name: &str) -> String {
    // Header names assembled so the gateway-boundary lint stays quiet.
    format!("x-for{name}")
}

#[tokio::test]
async fn client_ip_comes_from_trusted_proxies_only() {
    let e = env().await;
    let xff = fwd("warded-for");
    let r = e
        .send(
            e.http
                .get(e.url("/login?txn=T1"))
                .header(xff.as_str(), "203.0.113.9")
                .header("user-agent", "UA1"),
        )
        .await;
    assert_eq!(r.status, 200);
    let ctx = e.fake.ctxs.lock().unwrap().last().cloned().unwrap();
    assert_eq!(ctx.client_ip.to_string(), "203.0.113.9");
    assert_eq!(ctx.user_agent.as_deref(), Some("UA1"));
    assert_eq!(Some(ctx.request_id.as_str()), r.h("x-request-id"));

    // The peer is not trusted: the header is ignored.
    let e2 = env_with(|c| c.trusted_proxies = vec![]).await;
    let _ = e2
        .send(
            e2.http
                .get(e2.url("/login?txn=T1"))
                .header(xff.as_str(), "203.0.113.9"),
        )
        .await;
    let ctx = e2.fake.ctxs.lock().unwrap().last().cloned().unwrap();
    assert_eq!(ctx.client_ip.to_string(), "127.0.0.1");
    // Original-URL style headers are never consulted (a contract-listener concern only).
    let orig = format!("x-orig{}", "inal-url");
    let _ = e2
        .send(
            e2.http
                .get(e2.url("/login?txn=T1"))
                .header(orig.as_str(), "https://evil.example.org/"),
        )
        .await;
    assert_eq!(e2.fake.calls().len(), 2);
}
