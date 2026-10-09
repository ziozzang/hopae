//! The gateway layer of the harness: the REAL hangang binary (the build that
//! includes gateway changes HC-3 `auth.static_request_headers` and HC-12
//! `auth.strip_request_cookies`) started from a
//! generated file configuration, with the exact route fragments of
//! `docs/GATEWAY_CONTRACT.md`.
//!
//! The binary comes from `HOPAE_E2E_GATEWAY_BINARY`; when the variable is
//! absent [`Gateway::start`] returns `None` and the test skips (prints a line,
//! does not fail). `make e2e` refuses to run without the variable.
//!
//! Wiring, left to right:
//!
//! ```text
//! browser (Browser) -> hangang (public listener) -> Echo upstream      (application routes)
//!                                                -> Hopae portal       (portal route)
//!                   -> hangang -> VerifyTap -> Hopae gateway listener   (auth.url)
//! ```
//!
//! The tap is a transparent recording hop on `auth.url`: it forwards every
//! header and the whole answer unchanged and records the verify call as Hopae
//! received it (the harness has no Hopae-side recorder; the scenarios speak of
//! "the verify call Hopae received"). Tests may ask it to alter a call
//! (`TapMods`) to reproduce what a gateway without a feature would send, or a
//! Hopae that emits more than it does.
//!
//! The client plays the TLS terminator in front of the gateway: the harness
//! cannot bind port 443 or present a certificate, so the gateway trusts
//! `127.0.0.1` as a fronting proxy (`--trusted-proxy-cidrs`) and the browser
//! sends `x-forwarded-proto: https` and `x-forwarded-port: 443`. Everything
//! after that (route selection, header stripping, regeneration of the context
//! headers, `x-original-url`, the verify call, `forward_response`) is the real
//! gateway's. [`Edge::Direct`] starts the gateway without any trusted proxy
//! for the cases where the client must not be able to influence the context
//! headers (S007-A3, S008-A3, S005-A7).
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::Router;
use axum::extract::{Request, State};
use axum::response::Response as AxumResponse;
use serde_json::{Value, json};
use tempfile::TempDir;

use super::client::{Client, RawReq, Req, send};
use super::jar::{Jar, Site};
use super::server::{Log, Served, record};
use super::{Echo, Hopae, KEY_ENV, MockIdp, RecordedRequest, Response};

pub const BINARY_ENV: &str = "HOPAE_E2E_GATEWAY_BINARY";
/// The gateway-side variable holding the caller key (contract fragment).
pub const GATEWAY_KEY_ENV: &str = "HANGANG_HOPAE_KEY";

pub const APP_HOST: &str = "app.example.test";
pub const OTHER_HOST: &str = "other.example.org";
pub const PORTAL_HOST: &str = "auth.example.test";

/// Identity headers of the contract (the `response_headers` of the fragment).
pub const IDENTITY_HEADERS: [&str; 10] = [
    "x-forwarded-user",
    "x-forwarded-email",
    "x-forwarded-preferred-username",
    "x-forwarded-groups",
    "x-hopae-session",
    "x-hopae-provider",
    "x-hopae-auth-time",
    "x-hopae-expires",
    "x-hopae-aal",
    "x-hopae-factors",
];

/// The path of the gateway binary, or `None` (the test skips).
pub fn binary() -> Option<PathBuf> {
    let p = std::env::var_os(BINARY_ENV)?;
    let p = PathBuf::from(p);
    (!p.as_os_str().is_empty()).then_some(p)
}

/// Print a skip line; returns `None` so a test can `let Some(..) = skip(..) else { return }`.
pub fn skip(test: &str) {
    eprintln!("skip: {test}: {BINARY_ENV} is not set (gateway layer)");
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

/// The route fragments of the contract page, composed per test.
type RouteEdit = Arc<dyn Fn(&mut Vec<Value>) + Send + Sync>;

#[derive(Clone, Default)]
pub struct GatewayRoutes {
    parts: Vec<Part>,
    mutations: Vec<RouteEdit>,
}

#[derive(Clone)]
enum Part {
    /// Protected application, whole host.
    WholeHost(String),
    /// Public route for the host plus the higher-priority protected prefix route.
    PathScoped(String, String),
    /// Public portal route to Hopae's portal listener.
    Portal(String),
    /// Protected route without `host`/`hosts` (S005-A7).
    HostNeutral(String),
    /// The `site-hopae` route of the contract page (ADR-0015): `/_hopae` on a
    /// path-scoped host goes to Hopae too.
    HopaePrefix(String),
}

impl GatewayRoutes {
    pub fn new() -> Self {
        Self::default()
    }

    /// Whole-host protected application route (`app-example` of the contract page).
    pub fn whole_host(mut self, host: &str) -> Self {
        self.parts.push(Part::WholeHost(host.into()));
        self
    }

    /// The path-scoped pair: `site-public` (priority 0) and `site-admin`
    /// (`path_match: segment_prefix`, priority 10) on one host.
    pub fn path_scoped(mut self, host: &str, prefix: &str) -> Self {
        self.parts
            .push(Part::PathScoped(host.into(), prefix.into()));
        self
    }

    /// The portal host route (public; Hopae authenticates its own pages).
    pub fn portal(mut self, host: &str) -> Self {
        self.parts.push(Part::Portal(host.into()));
        self
    }

    /// A protected route with no `host` (host-neutral), for `path_prefix`.
    pub fn host_neutral(mut self, prefix: &str) -> Self {
        self.parts.push(Part::HostNeutral(prefix.into()));
        self
    }

    /// The `site-hopae` route for a path-scoped `host`: `path_prefix: "/_hopae"`,
    /// `segment_prefix`, higher priority, the same `auth` block.
    pub fn hopae_prefix(mut self, host: &str) -> Self {
        self.parts.push(Part::HopaePrefix(host.into()));
        self
    }

    /// Alter the generated route documents (variant fragments: a different
    /// `access_mode`, `forward_response: false`, ...).
    pub fn mutate(mut self, f: impl Fn(&mut Vec<Value>) + Send + Sync + 'static) -> Self {
        self.mutations.push(Arc::new(f));
        self
    }

    /// The default stack: the app host (whole host) and the portal host.
    pub fn standard() -> Self {
        Self::new().whole_host(APP_HOST).portal(PORTAL_HOST)
    }

    fn render(&self, verify_url: &str, echo: SocketAddr, portal: SocketAddr) -> Vec<Value> {
        let echo = format!("http://{echo}");
        let portal = format!("http://{portal}");
        let mut out = Vec::new();
        for part in &self.parts {
            match part {
                Part::WholeHost(host) => out.push(json!({
                    "id": format!("app-{host}"),
                    "access_mode": "protected",
                    "host": host,
                    "path_prefix": "/",
                    "backends": [echo],
                    "auth": auth_fragment(verify_url),
                })),
                Part::PathScoped(host, prefix) => {
                    out.push(json!({
                        "id": format!("site-public-{host}"),
                        "access_mode": "public",
                        "host": host,
                        "path_prefix": "/",
                        "priority": 0,
                        "backends": [echo],
                    }));
                    out.push(json!({
                        "id": format!("site-admin-{host}"),
                        "access_mode": "protected",
                        "host": host,
                        "path_prefix": prefix,
                        "path_match": "segment_prefix",
                        "priority": 10,
                        "backends": [echo],
                        "auth": auth_fragment(verify_url),
                    }));
                }
                Part::Portal(host) => out.push(json!({
                    "id": "hopae-portal",
                    "access_mode": "public",
                    "host": host,
                    "path_prefix": "/",
                    "backends": [portal],
                })),
                Part::HopaePrefix(host) => out.push(json!({
                    "id": format!("site-hopae-{host}"),
                    "access_mode": "protected",
                    "host": host,
                    "path_prefix": "/_hopae",
                    "path_match": "segment_prefix",
                    "priority": 10,
                    "backends": [echo],
                    "auth": auth_fragment(verify_url),
                })),
                Part::HostNeutral(prefix) => out.push(json!({
                    "id": "neutral-protected",
                    "access_mode": "protected",
                    "path_prefix": prefix,
                    "backends": [echo],
                    "auth": auth_fragment(verify_url),
                })),
            }
        }
        for m in &self.mutations {
            m(&mut out);
        }
        out
    }
}

/// The `auth` block of the contract page, byte for byte except the URL.
pub fn auth_fragment(verify_url: &str) -> Value {
    json!({
        "url": verify_url,
        "request_headers": ["cookie", "user-agent", "accept", "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site"],
        "response_headers": IDENTITY_HEADERS,
        "strip_request_cookies": ["__Host-hopae", "__Host-hopae_bind"],
        "static_request_headers": {
            "x-hopae-contract": "1",
            "x-hopae-gateway-key": {"env": GATEWAY_KEY_ENV}
        },
        "timeout_ms": 500,
        "forward_response": true
    })
}

// ---------------------------------------------------------------------------
// The verify tap
// ---------------------------------------------------------------------------

/// Alterations the tap applies to the verify calls it relays.
#[derive(Clone, Default)]
pub struct TapMods {
    /// Request headers set (replacing any copy) before the call reaches Hopae.
    pub request_headers: Vec<(String, String)>,
    /// Response headers set on Hopae's answer before it reaches the gateway.
    pub response_headers: Vec<(String, String)>,
    /// Request headers removed before the call reaches Hopae.
    pub drop_request_headers: Vec<String>,
}

/// What Hopae answered a relayed call (before any `TapMods` response change).
#[derive(Clone)]
pub struct TapAnswer {
    pub status: u16,
    pub headers: Vec<(String, String)>,
}

impl TapAnswer {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    pub fn header_all(&self, name: &str) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
            .collect()
    }
}

struct TapState {
    target: SocketAddr,
    log: Log,
    answers: Arc<Mutex<Vec<TapAnswer>>>,
    mods: Arc<Mutex<TapMods>>,
    client: reqwest::Client,
}

/// A transparent recording hop in front of one Hopae listener (the gateway
/// listener behind `auth.url`, or the portal behind the portal route).
pub struct VerifyTap {
    pub addr: SocketAddr,
    log: Log,
    answers: Arc<Mutex<Vec<TapAnswer>>>,
    mods: Arc<Mutex<TapMods>>,
    _server: Served,
}

impl VerifyTap {
    pub fn start(target: SocketAddr) -> VerifyTap {
        let log: Log = Arc::new(Mutex::new(Vec::new()));
        let mods = Arc::new(Mutex::new(TapMods::default()));
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("tap client");
        let answers: Arc<Mutex<Vec<TapAnswer>>> = Arc::new(Mutex::new(Vec::new()));
        let state = Arc::new(TapState {
            target,
            log: log.clone(),
            answers: answers.clone(),
            mods: mods.clone(),
            client,
        });
        let router = Router::new().fallback(tap).with_state(state);
        let server = Served::start(router);
        VerifyTap {
            addr: server.addr,
            log,
            answers,
            mods,
            _server: server,
        }
    }

    /// Every verify call Hopae received through the gateway, oldest first.
    pub fn calls(&self) -> Vec<RecordedRequest> {
        self.log.lock().unwrap().clone()
    }

    /// Hopae's answers to those calls, in the same order.
    pub fn answers(&self) -> Vec<TapAnswer> {
        self.answers.lock().unwrap().clone()
    }

    pub fn clear(&self) {
        self.log.lock().unwrap().clear();
        self.answers.lock().unwrap().clear();
    }

    pub fn set_mods(&self, mods: TapMods) {
        *self.mods.lock().unwrap() = mods;
    }

    pub fn reset_mods(&self) {
        self.set_mods(TapMods::default());
    }
}

async fn tap(State(st): State<Arc<TapState>>, req: Request) -> AxumResponse {
    let rec = record(req, &st.log).await;
    let mods = st.mods.lock().unwrap().clone();
    let method = reqwest::Method::from_bytes(rec.method.as_bytes()).unwrap_or(reqwest::Method::GET);
    let mut builder = st
        .client
        .request(method, format!("http://{}{}", st.target, rec.raw_path))
        .body(rec.body.clone().into_bytes());
    for (k, v) in &rec.headers {
        if matches!(k.as_str(), "host" | "connection" | "content-length")
            || mods.request_headers.iter().any(|(n, _)| n == k)
            || mods.drop_request_headers.iter().any(|n| n == k)
        {
            continue;
        }
        builder = builder.header(k.as_str(), v.as_str());
    }
    for (k, v) in &mods.request_headers {
        builder = builder.header(k.as_str(), v.as_str());
    }
    let upstream = match builder.send().await {
        Ok(r) => r,
        Err(_) => {
            let mut r = AxumResponse::new(axum::body::Body::from("tap: hopae unreachable"));
            *r.status_mut() = axum::http::StatusCode::BAD_GATEWAY;
            return r;
        }
    };
    let status = upstream.status();
    let headers = upstream.headers().clone();
    st.answers.lock().unwrap().push(TapAnswer {
        status: status.as_u16(),
        headers: headers
            .iter()
            .map(|(k, v)| {
                (
                    k.as_str().to_string(),
                    String::from_utf8_lossy(v.as_bytes()).into_owned(),
                )
            })
            .collect(),
    });
    let body = upstream.bytes().await.unwrap_or_default();
    let mut out = AxumResponse::new(axum::body::Body::from(body));
    *out.status_mut() = status;
    for (k, v) in &headers {
        if matches!(
            k.as_str(),
            "transfer-encoding" | "connection" | "content-length"
        ) || mods.response_headers.iter().any(|(n, _)| n == k.as_str())
        {
            continue;
        }
        out.headers_mut().append(k.clone(), v.clone());
    }
    for (k, v) in &mods.response_headers {
        if let (Ok(k), Ok(v)) = (
            axum::http::HeaderName::from_bytes(k.as_bytes()),
            axum::http::HeaderValue::from_str(v),
        ) {
            out.headers_mut().insert(k, v);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// The gateway process
// ---------------------------------------------------------------------------

/// How the public listener sees its clients.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Edge {
    /// `127.0.0.1` is a trusted fronting proxy: the harness client supplies
    /// `x-forwarded-for/proto/port` like a TLS terminator would.
    Terminator,
    /// No trusted proxy: every context header is the gateway's own (the
    /// scheme is `http`, the port is the listener's, which is the value given
    /// here and must be an application port of the Hopae under test; see
    /// [`Stack::direct`]).
    Direct(u16),
}

pub struct Gateway {
    /// The public listener (what a browser talks to).
    pub public: SocketAddr,
    /// The administration listener (read-only use: `GET /v1/routes/http`).
    pub admin: SocketAddr,
    /// The bearer token of the administration listener (a secret: never print).
    admin_token: String,
    /// The recording hop on `auth.url`: the verify calls Hopae received.
    pub tap: VerifyTap,
    /// The recording hop in front of Hopae's portal listener: the requests the
    /// portal received from the gateway's portal route.
    pub portal_tap: VerifyTap,
    pub config_path: PathBuf,
    pub edge: Edge,
    binary: PathBuf,
    key: String,
    log_path: PathBuf,
    child: Child,
    _dir: TempDir,
}

/// An unused loopback port (for [`Edge::Direct`], chosen before Hopae starts).
pub fn pick_port() -> u16 {
    free_port()
}

fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("free port");
    l.local_addr().expect("addr").port()
}

fn hex_token() -> String {
    use hopae::crypto::Rng;
    let mut b = [0u8; 32];
    hopae::crypto::OsRng.fill(&mut b);
    data_encoding::HEXLOWER.encode(&b)
}

impl Gateway {
    /// Start the gateway in front of `echo` and `hopae` with `routes`, behind
    /// a terminating proxy ([`Edge::Terminator`]). `None` when the binary
    /// variable is absent (the test skips). Panics when the gateway does not
    /// come up: that is a harness or gateway failure, not a result.
    pub fn start(hopae: &Hopae, echo: &Echo, routes: GatewayRoutes) -> Option<Gateway> {
        Self::start_with(hopae, echo, routes, Edge::Terminator)
    }

    pub fn start_with(
        hopae: &Hopae,
        echo: &Echo,
        routes: GatewayRoutes,
        edge: Edge,
    ) -> Option<Gateway> {
        match Self::try_start_with(hopae, echo, routes, edge) {
            Ok(g) => g,
            Err(e) => panic!("{e}"),
        }
    }

    /// Like [`Gateway::start_with`], but a gateway that cannot come up (a port
    /// taken between choosing and binding it) is an `Err`. With
    /// [`Edge::Terminator`] the ports are chosen again up to five times; with
    /// [`Edge::Direct`] the port belongs to the caller, so the `Err` is returned.
    pub fn try_start_with(
        hopae: &Hopae,
        echo: &Echo,
        routes: GatewayRoutes,
        edge: Edge,
    ) -> Result<Option<Gateway>, String> {
        let Some(binary) = binary() else {
            return Ok(None);
        };
        let key = hopae
            .env_value(KEY_ENV)
            .expect("hopae was started with a gateway key")
            .to_string();
        let tap = VerifyTap::start(hopae.gateway);
        let verify_url = format!("http://{}/_hopae/verify", tap.addr);
        let portal_tap = VerifyTap::start(hopae.portal);
        let http = routes.render(&verify_url, echo.addr, portal_tap.addr);
        let dir = tempfile::tempdir().expect("gateway dir");
        let config_path = dir.path().join("hangang.json");
        let doc = json!({"http": http, "tcp": [], "settings": {}});
        std::fs::write(&config_path, serde_json::to_vec_pretty(&doc).expect("json"))
            .expect("write gateway config");
        let log_path = dir.path().join("hangang.log");
        let attempts = if matches!(edge, Edge::Terminator) {
            5
        } else {
            1
        };
        let mut last = String::new();
        for _ in 0..attempts {
            let public_port = match edge {
                Edge::Direct(p) => p,
                Edge::Terminator => free_port(),
            };
            let public: SocketAddr = ([127, 0, 0, 1], public_port).into();
            let admin: SocketAddr = ([127, 0, 0, 1], free_port()).into();
            let admin_token = hex_token();

            let log = std::fs::File::create(&log_path).expect("gateway log");
            let log_err = log.try_clone().expect("gateway log clone");
            let mut cmd = Command::new(&binary);
            cmd.arg("--config")
                .arg(&config_path)
                .arg("--listen")
                .arg(public.to_string())
                .arg("--admin")
                .arg(admin.to_string())
                .args(["--threads", "2", "--lua-workers", "1"]);
            if matches!(edge, Edge::Terminator) {
                cmd.args(["--trusted-proxy-cidrs", "127.0.0.1/32"]);
            }
            cmd.env_clear()
                .env("PATH", std::env::var_os("PATH").unwrap_or_default())
                .env("HANGANG_ADMIN_TOKEN", &admin_token)
                .env(GATEWAY_KEY_ENV, &key)
                .env("RUST_LOG", "warn")
                .current_dir(dir.path())
                .stdin(Stdio::null())
                .stdout(Stdio::from(log))
                .stderr(Stdio::from(log_err));
            let mut child = cmd.spawn().expect("spawn hangang");
            match wait_ready(&mut child, public, admin, &admin_token, &log_path) {
                Ok(()) => {
                    return Ok(Some(Gateway {
                        public,
                        admin,
                        admin_token,
                        tap,
                        portal_tap,
                        config_path,
                        edge,
                        binary,
                        key,
                        log_path,
                        child,
                        _dir: dir,
                    }));
                }
                Err(e) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    last = e;
                }
            }
        }
        Err(last)
    }

    /// The process's output so far (it never prints header values).
    pub fn log(&self) -> String {
        std::fs::read_to_string(&self.log_path).unwrap_or_default()
    }

    /// The configuration document the gateway runs with.
    pub fn config(&self) -> Value {
        serde_json::from_slice(&std::fs::read(&self.config_path).expect("read config"))
            .expect("config json")
    }

    /// `hangang --config <file> --check` on this gateway's configuration: the
    /// gateway's own validation, including the `static_request_headers`
    /// variables. Returns `(accepted, output)`.
    pub fn check(&self) -> (bool, String) {
        check_config(&self.binary, &self.config_path, Some(&self.key))
    }

    /// `hangang --check` on a variant of this gateway's configuration (the
    /// closure edits the document). Returns `(accepted, output)`.
    pub fn check_variant(&self, edit: impl FnOnce(&mut Value)) -> (bool, String) {
        let mut doc = self.config();
        edit(&mut doc);
        let dir = tempfile::tempdir().expect("variant dir");
        let path = dir.path().join("variant.json");
        std::fs::write(&path, serde_json::to_vec_pretty(&doc).expect("json")).expect("write");
        check_config(&self.binary, &path, Some(&self.key))
    }

    /// `GET /v1/routes/http` on the administration listener (read-only).
    pub fn admin_routes(&self) -> Response {
        send(
            self.admin,
            RawReq::new("GET", "/v1/routes/http", "admin.test")
                .header("authorization", &format!("Bearer {}", self.admin_token)),
        )
    }

    /// The administration token, for a Hopae process that reads the route list
    /// (S008-5). A secret: pass it through an environment variable only.
    pub fn admin_token(&self) -> &str {
        &self.admin_token
    }

    /// A browser whose requests reach this gateway's public listener.
    pub fn browser(&self) -> Browser {
        Browser {
            gw: self.public,
            jar: Jar::new(),
            ip: "192.0.2.10".into(),
            edge: self.edge,
            spoof: Vec::new(),
        }
    }

    /// Stop the process (idempotent).
    pub fn stop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for Gateway {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Ready when OUR process answers: the administration listener accepts our
/// token (a stranger that took the port would not know it), the public listener
/// answers, and the process is still alive.
fn wait_ready(
    child: &mut Child,
    public: SocketAddr,
    admin: SocketAddr,
    token: &str,
    log_path: &Path,
) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(20);
    let log = || std::fs::read_to_string(log_path).unwrap_or_default();
    loop {
        if let Ok(Some(status)) = child.try_wait() {
            return Err(format!("hangang exited ({status}); log:\n{}", log()));
        }
        let ours = super::client::try_send(
            admin,
            RawReq::new("GET", "/v1/routes/http", "admin.test")
                .header("authorization", &format!("Bearer {token}"))
                .timeout(Duration::from_secs(2)),
        )
        .is_ok_and(|r| r.status == 200);
        if ours
            && super::client::try_send(
                public,
                RawReq::new("GET", "/", "ready.invalid").timeout(Duration::from_secs(2)),
            )
            .is_ok()
        {
            // the public port may have been taken by a stranger: our process would have exited
            std::thread::sleep(Duration::from_millis(100));
            if let Ok(Some(status)) = child.try_wait() {
                return Err(format!("hangang exited ({status}); log:\n{}", log()));
            }
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "hangang did not come up on {public}; log:\n{}",
                log()
            ));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Run `hangang --check` on an arbitrary configuration file.
pub fn check_config(binary: &Path, config: &Path, key: Option<&str>) -> (bool, String) {
    let mut cmd = Command::new(binary);
    cmd.arg("--config")
        .arg(config)
        .arg("--check")
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default());
    if let Some(k) = key {
        cmd.env(GATEWAY_KEY_ENV, k);
    }
    let out = cmd.output().expect("run hangang --check");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.success(), text)
}

// ---------------------------------------------------------------------------
// The browser
// ---------------------------------------------------------------------------

/// A browser (one cookie jar) talking to the gateway's public listener. It
/// never follows redirects; the test does, so each hop can be asserted.
#[derive(Clone)]
pub struct Browser {
    gw: SocketAddr,
    pub jar: Jar,
    ip: String,
    edge: Edge,
    /// Headers added to every request (a client that spoofs on every hop).
    spoof: Vec<(String, String)>,
}

impl Browser {
    /// The same browser, adding `headers` to every request it sends.
    pub fn spoofing(&self, headers: &[(&str, &str)]) -> Browser {
        Browser {
            spoof: headers
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
            ..self.clone()
        }
    }

    /// The same browser (jar) at another client address.
    pub fn at_ip(&self, ip: &str) -> Browser {
        Browser {
            ip: ip.into(),
            ..self.clone()
        }
    }

    /// A browser with its own empty jar at the same address.
    pub fn fresh(&self) -> Browser {
        Browser {
            jar: Jar::new(),
            ..self.clone()
        }
    }

    fn client(&self, host: &str) -> Client {
        Client::new(
            self.gw,
            host,
            matches!(self.edge, Edge::Terminator),
            self.jar.clone(),
        )
        .with_ip(&self.ip)
    }

    /// A top-level document navigation (`sec-fetch-dest: document`).
    pub fn get(&self, host: &str, path: &str) -> Response {
        self.send(host, self.navigation(path))
    }

    /// A document navigation carrying extra request headers (spoofing cases).
    pub fn get_with(&self, host: &str, path: &str, extra: &[(&str, &str)]) -> Response {
        let mut req = self.navigation(path);
        for (k, v) in extra {
            req = req.header(k, v);
        }
        self.send(host, req)
    }

    /// A document navigation of a browser with an empty jar that sends exactly
    /// `cookie` (a request whose `cookie` header the test controls).
    pub fn fresh_jar_get(&self, host: &str, path: &str, cookie: &str) -> Response {
        self.fresh().get_with(host, path, &[("cookie", cookie)])
    }

    /// A document navigation that arrives from another site (a redirect).
    pub fn get_cross_site(&self, host: &str, path: &str) -> Response {
        self.send(host, self.navigation(path).cross_site_navigation())
    }

    /// A fetch/XHR style request (`sec-fetch-dest: empty`, `sec-fetch-mode: cors`).
    pub fn fetch(&self, host: &str, path: &str) -> Response {
        let req = Req::get(path)
            .header("sec-fetch-dest", "empty")
            .header("sec-fetch-mode", "cors")
            .header("sec-fetch-site", "same-origin")
            .header("accept", "application/json");
        self.send(host, req)
    }

    pub fn navigation(&self, path: &str) -> Req {
        Req::get(path)
            .header("sec-fetch-dest", "document")
            .header("sec-fetch-mode", "navigate")
            .header("accept", "text/html,application/xhtml+xml")
    }

    /// Send `req` to `host` through the gateway; applies and updates the jar.
    pub fn send(&self, host: &str, req: Req) -> Response {
        let req = if matches!(self.edge, Edge::Terminator) {
            req.header("x-forwarded-port", "443")
        } else {
            req
        };
        let mut req = req;
        for (k, v) in &self.spoof {
            req = req.header(k, v);
        }
        self.client(host).send(req)
    }

    /// The `Location` of a redirect as (host, path-and-query) when it is an
    /// absolute `https://` URL of a host the gateway serves.
    pub fn split_location(location: &str) -> (String, String) {
        let u = url::Url::parse(location).unwrap_or_else(|e| panic!("location {location:?}: {e}"));
        let mut pq = u.path().to_string();
        if let Some(q) = u.query() {
            pq.push('?');
            pq.push_str(q);
        }
        let host = match u.port() {
            Some(p) => format!("{}:{p}", u.host_str().unwrap_or("")),
            None => u.host_str().unwrap_or("").to_string(),
        };
        (host, pq)
    }

    /// Follow one redirect: `response` must be a `302`; the next request goes
    /// to its `Location` (cross-site navigation when the host changes).
    pub fn follow(&self, from_host: &str, response: &Response) -> Response {
        assert_eq!(response.status, 302, "follow needs a 302: {response:?}");
        let (host, pq) = Self::split_location(response.location().expect("location"));
        if host == from_host {
            self.get(&host, &pq)
        } else {
            self.get_cross_site(&host, &pq)
        }
    }

    /// The login chain through the gateway for `host` + `path` as a browser
    /// without a session performs it, stopping with the handoff code in hand
    /// (not yet presented to the application host).
    pub fn login_to_code(&self, idp: &MockIdp, host: &str, path: &str) -> CodeLogin {
        let first = self.get(host, path);
        assert_eq!(first.status, 302, "unauthenticated first hop: {first:?}");
        self.login_from(idp, first)
    }

    /// Continue a login from the unauthenticated `302` `first` (to the portal).
    pub fn login_from(&self, idp: &MockIdp, first: Response) -> CodeLogin {
        let to_portal = first.location().expect("portal location").to_string();
        let (portal_host, portal_pq) = Self::split_location(&to_portal);
        let page = self.get_cross_site(&portal_host, &portal_pq);
        let go = if page.status == 302 {
            Response {
                status: page.status,
                headers: page.headers.clone(),
                body: page.body.clone(),
            }
        } else {
            let csrf = page
                .body
                .split("name=\"csrf\" value=\"")
                .nth(1)
                .and_then(|s| s.split('"').next())
                .unwrap_or_default()
                .to_string();
            let txn = url::Url::parse(&to_portal)
                .expect("portal url")
                .query_pairs()
                .find(|(k, _)| k == "txn")
                .map(|(_, v)| v.into_owned())
                .unwrap_or_default();
            self.send(
                &portal_host,
                Req::post("/login/mock").form(&[("csrf", &csrf), ("txn", &txn)]),
            )
        };
        assert_eq!(go.status, 302, "provider redirect: {go:?}");
        let callback_path = idp.follow_authorization(go.location().expect("provider redirect"));
        let callback = self.get_cross_site(&portal_host, &callback_path);
        assert_eq!(callback.status, 302, "callback: {callback:?}");
        self.code_login(first, page, go, callback)
    }

    /// The single-sign-on hop for a browser that already holds a portal
    /// session: unauthenticated `302` `first` -> portal -> `302` with a code.
    pub fn sso_to_code(&self, first: Response) -> CodeLogin {
        assert_eq!(first.status, 302, "unauthenticated first hop: {first:?}");
        let (portal_host, portal_pq) =
            Self::split_location(first.location().expect("portal location"));
        let hop = self.get_cross_site(&portal_host, &portal_pq);
        assert_eq!(hop.status, 302, "the portal hands off at once: {hop:?}");
        let loc = hop.location().expect("handoff location").to_string();
        assert!(loc.contains("_hopae_handoff="), "{loc}");
        let (app_host, _) = Self::split_location(&loc);
        CodeLogin {
            first,
            portal_page: Response {
                status: hop.status,
                headers: hop.headers.clone(),
                body: hop.body.clone(),
            },
            provider_redirect: Response {
                status: 0,
                headers: vec![],
                body: String::new(),
            },
            callback: hop,
            handoff_location: loc,
            app_host,
        }
    }

    fn code_login(
        &self,
        first: Response,
        portal_page: Response,
        provider_redirect: Response,
        callback: Response,
    ) -> CodeLogin {
        let handoff_location = callback.location().expect("handoff location").to_string();
        let (app_host, _) = Self::split_location(&handoff_location);
        CodeLogin {
            first,
            portal_page,
            provider_redirect,
            callback,
            handoff_location,
            app_host,
        }
    }

    /// The whole login chain: [`Browser::login_to_code`] plus the navigation
    /// that carries the code to the application host.
    pub fn login(&self, idp: &MockIdp, host: &str, path: &str) -> Login {
        let c = self.login_to_code(idp, host, path);
        let handoff = self.redeem(&c);
        Login {
            first: c.first,
            portal_page: c.portal_page,
            provider_redirect: c.provider_redirect,
            callback: c.callback,
            handoff_location: c.handoff_location,
            handoff,
            app_host: c.app_host,
        }
    }

    /// Present the code of `c` to the application host (a cross-site navigation).
    pub fn redeem(&self, c: &CodeLogin) -> Response {
        let (host, pq) = Self::split_location(&c.handoff_location);
        self.get_cross_site(&host, &pq)
    }

    /// Follow `302`s from `first` (a response from `host`) until a non-redirect
    /// or `max` hops; returns every hop as (host asked, response).
    pub fn chase(&self, host: &str, first: Response, max: usize) -> Vec<(String, Response)> {
        let mut out = Vec::new();
        let mut host = host.to_string();
        let mut cur = first;
        for _ in 0..max {
            if cur.status != 302 {
                break;
            }
            let (next_host, pq) = Self::split_location(cur.location().expect("location"));
            let next = if next_host == host {
                self.get(&next_host, &pq)
            } else {
                self.get_cross_site(&next_host, &pq)
            };
            let prev = std::mem::replace(&mut cur, next);
            out.push((host.clone(), prev));
            host = next_host;
        }
        out.push((host, cur));
        out
    }
}

/// A login stopped at the handoff code (see [`Browser::login_to_code`]).
pub struct CodeLogin {
    pub first: Response,
    pub portal_page: Response,
    pub provider_redirect: Response,
    pub callback: Response,
    /// `https://<app>/<path>?..._hopae_handoff=<code>`
    pub handoff_location: String,
    pub app_host: String,
}

impl CodeLogin {
    /// The code value (a credential: never print).
    pub fn code(&self) -> String {
        url::Url::parse(&self.handoff_location)
            .expect("handoff url")
            .query_pairs()
            .find(|(k, _)| k == "_hopae_handoff")
            .map(|(_, v)| v.into_owned())
            .expect("handoff code")
    }

    /// Path and query of the handoff navigation (with the code).
    pub fn path_and_query(&self) -> String {
        Browser::split_location(&self.handoff_location).1
    }
}

/// The hops of [`Browser::login`]; `handoff` is the verify-driven answer to
/// the navigation that carried the code (the cookie-planting `302`).
pub struct Login {
    pub first: Response,
    pub portal_page: Response,
    pub provider_redirect: Response,
    pub callback: Response,
    pub handoff_location: String,
    pub handoff: Response,
    pub app_host: String,
}

// ---------------------------------------------------------------------------
// The assembled stack
// ---------------------------------------------------------------------------

/// Mock IdP + Hopae + Echo + Gateway, the usual shape of a gateway test.
pub struct Stack {
    pub idp: MockIdp,
    pub hopae: Hopae,
    pub echo: Echo,
    pub gw: Gateway,
    /// The application host as a browser writes it (`app.example.test`, or
    /// `app.example.test:<port>` for [`Edge::Direct`]).
    pub app: String,
}

impl Stack {
    pub fn start(
        test: &str,
        fixture: super::Fixture,
        routes: GatewayRoutes,
        edge: Edge,
    ) -> Option<Stack> {
        match Self::try_start(test, fixture, routes, edge) {
            Ok(s) => s,
            Err(e) => panic!("{e}"),
        }
    }

    fn try_start(
        test: &str,
        fixture: super::Fixture,
        routes: GatewayRoutes,
        edge: Edge,
    ) -> Result<Option<Stack>, String> {
        if binary().is_none() {
            skip(test);
            return Ok(None);
        }
        let idp = MockIdp::start("default");
        let hopae = Hopae::spawn(fixture, &idp, &[]);
        let echo = Echo::start();
        let Some(gw) = Gateway::try_start_with(&hopae, &echo, routes, edge)? else {
            return Ok(None);
        };
        let app = match edge {
            Edge::Terminator => APP_HOST.to_string(),
            Edge::Direct(p) => format!("{APP_HOST}:{p}"),
        };
        Ok(Some(Stack {
            idp,
            hopae,
            echo,
            gw,
            app,
        }))
    }

    /// The usual stack: `m1-basic`, app host + portal host, behind a terminator.
    pub fn basic(test: &str) -> Option<Stack> {
        Self::start(
            test,
            super::Fixture::new("m1-basic"),
            GatewayRoutes::standard(),
            Edge::Terminator,
        )
    }

    /// Same with `routes`.
    pub fn with_routes(test: &str, routes: GatewayRoutes) -> Option<Stack> {
        Self::start(
            test,
            super::Fixture::new("m1-basic"),
            routes,
            Edge::Terminator,
        )
    }

    /// The gateway is the edge (no trusted proxy, plain HTTP): every context
    /// header is the gateway's own. Hopae runs the development-insecure
    /// fixture with the gateway's port registered as the application port.
    pub fn direct(test: &str, routes: GatewayRoutes) -> Option<Stack> {
        let mut last = String::new();
        for _ in 0..4 {
            let port = pick_port();
            match Self::try_start(
                test,
                super::Fixture::with(
                    "m1-dev-insecure",
                    json!({"apps": [{"app_id": "app", "ports": [port]}]}),
                ),
                routes.clone(),
                Edge::Direct(port),
            ) {
                Ok(s) => return s,
                Err(e) => last = e,
            }
        }
        panic!("{last}");
    }

    /// Log in through the gateway for `path` on the application host and
    /// return the browser holding the planted handle (the handoff `302` was
    /// received; the clean URL is not yet fetched).
    pub fn logged_in(&self, path: &str) -> Browser {
        let b = self.gw.browser();
        let l = b.login(&self.idp, &self.app, path);
        assert_eq!(l.handoff.status, 302, "handoff: {:?}", l.handoff);
        b
    }
}

/// Query helper: a header value from a recorded request's headers map.
pub fn header_map(r: &RecordedRequest) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    for (k, v) in &r.headers {
        m.entry(k.clone())
            .and_modify(|e: &mut String| {
                e.push_str(", ");
                e.push_str(v);
            })
            .or_insert_with(|| v.clone());
    }
    m
}

// ---------------------------------------------------------------------------
// Hopae store peeks (read-only; the file is Hopae's SQLite database)
// ---------------------------------------------------------------------------

fn peek(h: &Hopae) -> rusqlite::Connection {
    let path = h.state_dir.path().join("state").join("hopae.db");
    let c = rusqlite::Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .expect("open the store read-only");
    c.busy_timeout(Duration::from_secs(5))
        .expect("busy timeout");
    c
}

/// Number of login transactions Hopae holds.
pub fn txn_count(h: &Hopae) -> i64 {
    peek(h)
        .query_row("SELECT count(*) FROM login_txns", [], |r| r.get(0))
        .expect("count transactions")
}

/// The transaction id of a `Location: <portal>/login?txn=<id>` redirect.
pub fn txn_of(r: &Response) -> String {
    let loc = r.location().expect("location");
    url::Url::parse(loc)
        .expect("location url")
        .query_pairs()
        .find(|(k, _)| k == "txn")
        .map(|(_, v)| v.into_owned())
        .unwrap_or_else(|| panic!("no txn in {loc}"))
}

/// `return_target` of the transaction `txn` (the id as the portal URL carries it).
pub fn return_target(h: &Hopae, txn: &str) -> Option<String> {
    use sha2::{Digest, Sha256};
    peek(h)
        .query_row(
            "SELECT return_target FROM login_txns WHERE txn_sha256 = ?1",
            [Sha256::digest(txn.as_bytes()).to_vec()],
            |r| r.get::<_, String>(0),
        )
        .ok()
}

/// `(consumed_reason, recovery_depth)` of a handoff code (`None` if unknown).
pub fn code_row(h: &Hopae, code: &str) -> Option<(Option<String>, i64)> {
    use sha2::{Digest, Sha256};
    peek(h)
        .query_row(
            "SELECT consumed_reason, recovery_depth FROM handoff_codes WHERE code_sha256 = ?1",
            [Sha256::digest(code.as_bytes()).to_vec()],
            |r| Ok((r.get::<_, Option<String>>(0)?, r.get::<_, i64>(1)?)),
        )
        .ok()
}

/// `recovery_depth` of every login transaction, oldest first.
pub fn txn_depths(h: &Hopae) -> Vec<i64> {
    let c = peek(h);
    let mut st = c
        .prepare("SELECT recovery_depth FROM login_txns WHERE purpose = 'login' ORDER BY created_at, rowid")
        .expect("prepare");
    st.query_map([], |r| r.get::<_, i64>(0))
        .expect("query")
        .filter_map(Result::ok)
        .collect()
}
