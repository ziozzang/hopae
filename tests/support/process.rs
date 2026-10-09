//! Spawn the real `hopae` binary (built with the `test-hooks` feature) from a
//! fixture, talk to its two listeners and its hooks listener, and kill or
//! restart it.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use tempfile::TempDir;

use super::client::{Client, RawReq, send};
use super::jar::Jar;
use super::mock_idp::MockIdp;
use super::{KEY_ENV, Response};

/// Name of the environment variable holding the mock provider's client secret.
pub const MOCK_SECRET_ENV: &str = "HOPAE_TEST_MOCK_SECRET";

/// A fixture file under `tests/fixtures/` plus overrides merged into it.
///
/// Merge rule: objects merge recursively; arrays of objects that carry
/// `app_id` or `provider_id` merge element by element on that key (new keys
/// are appended); every other value is replaced. `null` removes a key.
pub struct Fixture {
    pub name: &'static str,
    pub overrides: Value,
}

impl Fixture {
    pub fn new(name: &'static str) -> Self {
        Fixture {
            name,
            overrides: json!({}),
        }
    }

    pub fn with(name: &'static str, overrides: Value) -> Self {
        Fixture { name, overrides }
    }

    /// The fixture JSON with the harness values (ports, state dir, the mock
    /// provider's issuer and client id) filled in and the overrides applied.
    pub fn render(&self, state_dir: &Path, idp: &MockIdp) -> Value {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(format!("{}.json", self.name));
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("fixture {}: {e}", path.display()));
        let mut v: Value =
            serde_json::from_str(&text).unwrap_or_else(|e| panic!("fixture {}: {e}", self.name));
        v["listen"] = json!({"portal": "127.0.0.1:0", "gateway": "127.0.0.1:0"});
        if v["admin"]["public_url"].is_string() {
            v["listen"]["admin"] = json!("127.0.0.1:0");
        }
        v["state_dir"] = json!(state_dir.join("state"));
        if let Some(providers) = v.get_mut("providers").and_then(Value::as_array_mut) {
            for p in providers.iter_mut().filter(|p| p["provider_id"] == "mock") {
                p["issuer"] = json!(idp.issuer.as_str().trim_end_matches('/'));
                p["client_id"] = json!(idp.client_id);
            }
        }
        merge(&mut v, &self.overrides);
        v
    }
}

fn array_key(a: &[Value]) -> Option<&'static str> {
    ["app_id", "provider_id"]
        .into_iter()
        .find(|k| !a.is_empty() && a.iter().all(|e| e.get(*k).is_some()))
}

fn merge(base: &mut Value, over: &Value) {
    match (base, over) {
        (Value::Object(b), Value::Object(o)) => {
            for (k, v) in o {
                if v.is_null() {
                    b.remove(k);
                } else {
                    merge(b.entry(k.clone()).or_insert(Value::Null), v);
                }
            }
        }
        (Value::Array(b), Value::Array(o))
            if array_key(b).is_some() && array_key(b) == array_key(o) =>
        {
            let key = array_key(b).expect("array key");
            for item in o {
                match b.iter_mut().find(|e| e[key] == item[key]) {
                    Some(existing) => merge(existing, item),
                    None => b.push(item.clone()),
                }
            }
        }
        (b, o) => *b = o.clone(),
    }
}

/// Which gateway caller key a verify request presents.
#[derive(Clone, Debug)]
pub enum KeySlot {
    /// The value of the variable named by `gateway.caller_key_env`.
    Current,
    /// The value of the variable named by `gateway.caller_key_next_env`.
    Next,
    /// No key header at all.
    Missing,
    /// A wrong value.
    Wrong,
    /// This exact value.
    Literal(String),
}

/// A verify call as a gateway would make it.
#[derive(Clone)]
pub struct VerifyRequest {
    url: String,
    ip: String,
    cookies: Vec<(String, String)>,
    ua: Option<String>,
    document: bool,
    key: KeySlot,
    extra: Vec<(String, String)>,
    removed: Vec<String>,
}

impl VerifyRequest {
    /// A top-level document navigation to `url` (`Sec-Fetch-Dest: document`).
    pub fn document(url: &str) -> Self {
        VerifyRequest {
            url: url.into(),
            ip: "192.0.2.10".into(),
            cookies: vec![],
            ua: None,
            document: true,
            key: KeySlot::Current,
            extra: vec![],
            removed: vec![],
        }
    }

    /// A non-navigation request (fetch/XHR: `Accept: application/json`).
    pub fn other(url: &str) -> Self {
        VerifyRequest {
            document: false,
            ..Self::document(url)
        }
    }

    pub fn ip(mut self, ip: &str) -> Self {
        self.ip = ip.into();
        self
    }

    pub fn cookie(mut self, name: &str, value: &str) -> Self {
        self.cookies.push((name.into(), value.into()));
        self
    }

    pub fn ua(mut self, ua: &str) -> Self {
        self.ua = Some(ua.into());
        self
    }

    pub fn key(mut self, key: KeySlot) -> Self {
        self.key = key;
        self
    }

    /// Add or repeat a header verbatim (duplicate-header and spoofing cases).
    pub fn header(mut self, k: &str, v: &str) -> Self {
        self.extra.push((k.to_ascii_lowercase(), v.into()));
        self
    }

    /// Drop one of the standard headers (contract-violation cases).
    pub fn without(mut self, k: &str) -> Self {
        self.removed.push(k.to_ascii_lowercase());
        self
    }
}

/// Typed wrappers over the test-hooks endpoints.
#[derive(Clone)]
pub struct Hooks {
    pub addr: SocketAddr,
}

impl Hooks {
    fn call(&self, method: &str, path: &str, body: Option<Value>) -> Response {
        let mut r =
            RawReq::new(method, path, "hooks.test").header("content-type", "application/json");
        if let Some(b) = body {
            r.body = b.to_string().into_bytes();
        }
        let resp = send(self.addr, r);
        assert!(
            resp.status == 200,
            "hooks {method} {path} -> {} {:.200}",
            resp.status,
            resp.body
        );
        resp
    }

    /// Store calls by method name and the process counters.
    pub fn counters(&self) -> Value {
        self.call("GET", "/counters", None).json()
    }

    /// How many times the named store method has been called.
    pub fn store_calls(&self, method: &str) -> u64 {
        self.counters()["store_calls"][method].as_u64().unwrap_or(0)
    }

    pub fn now_ms(&self) -> i64 {
        self.call("GET", "/clock", None).json()["now_ms"]
            .as_i64()
            .expect("now_ms")
    }

    pub fn set_clock_ms(&self, ms: i64) {
        self.call("POST", "/clock", Some(json!({"now_ms": ms})));
    }

    pub fn advance(&self, d: Duration) {
        self.call(
            "POST",
            "/clock",
            Some(json!({"advance_ms": d.as_millis() as u64})),
        );
    }

    /// Every store call sleeps `ms` before executing.
    pub fn stall(&self, ms: u64) {
        self.call("POST", "/store/stall", Some(json!({"ms": ms})));
    }

    /// Stall only the diagnostic batch writer, `ms` before each event (S014-5).
    pub fn stall_diagnostics(&self, ms: u64) {
        self.call(
            "POST",
            "/store/stall",
            Some(json!({"ms": ms, "target": "diagnostics"})),
        );
    }

    pub fn stall_diagnostics_off(&self) {
        self.call(
            "POST",
            "/store/stall",
            Some(json!({"off": true, "target": "diagnostics"})),
        );
    }

    pub fn stall_off(&self) {
        self.call("POST", "/store/stall", Some(json!({"off": true})));
    }

    /// Hold the transaction labelled `label` (`redeem`, `elevate`, `login_commit`) before commit.
    pub fn hold(&self, label: &str) {
        self.call(
            "POST",
            "/commit-gate",
            Some(json!({"label": label, "hold": true})),
        );
    }

    pub fn release(&self, label: &str) {
        self.call(
            "POST",
            "/commit-gate",
            Some(json!({"label": label, "hold": false})),
        );
    }

    /// Abort the process when execution reaches `label` (`before_login_commit`, `after_login_commit`, `after_log_line`).
    pub fn crash_at(&self, label: &str) {
        self.call("POST", "/crash-at", Some(json!({"label": label})));
    }

    pub fn disarm_crash(&self) {
        self.call("POST", "/crash-at", Some(json!({"label": null})));
    }

    /// Raise a session to AAL2 (gate label `elevate`).
    pub fn elevate(&self, session_id: &str) -> Response {
        send(self.addr, {
            let mut r = RawReq::new("POST", "/elevate", "hooks.test")
                .header("content-type", "application/json");
            r.body = json!({"session_id": session_id}).to_string().into_bytes();
            r
        })
    }

    /// Events table dump, oldest first; `kind` like `login.started`.
    pub fn events(&self, kind: Option<&str>, limit: Option<usize>) -> Vec<Value> {
        let mut q = url::form_urlencoded::Serializer::new(String::new());
        if let Some(k) = kind {
            q.append_pair("kind", k);
        }
        if let Some(l) = limit {
            q.append_pair("limit", &l.to_string());
        }
        let r = self
            .call("GET", &format!("/events?{}", q.finish()), None)
            .json();
        r["events"].as_array().cloned().unwrap_or_default()
    }

    /// `event_deliveries` dump, optionally for one sink.
    pub fn deliveries(&self, sink: Option<&str>) -> Vec<Value> {
        let path = match sink {
            Some(s) => format!("/deliveries?sink={s}"),
            None => "/deliveries".to_string(),
        };
        self.call("GET", &path, None).json()["deliveries"]
            .as_array()
            .cloned()
            .unwrap_or_default()
    }
}

pub struct Hopae {
    pub portal: SocketAddr,
    pub gateway: SocketAddr,
    /// The admin listener, when the configuration has `admin.public_url`.
    pub admin: Option<SocketAddr>,
    pub hooks: Hooks,
    pub state_dir: TempDir,
    child: Child,
    /// Environment variables the process was started with (values are secrets: never print).
    env: BTreeMap<String, String>,
    config: Value,
    config_path: PathBuf,
    log_path: PathBuf,
    _log_dir: TempDir,
    idp: MockIdp,
}

/// The binary with `test-hooks`: the one cargo built for this test run when the
/// feature is on, otherwise one built once per test process into a side target dir.
pub(super) fn hopae_bin() -> &'static Path {
    static BIN: OnceLock<PathBuf> = OnceLock::new();
    BIN.get_or_init(|| {
        let bundled = PathBuf::from(env!("CARGO_BIN_EXE_hopae"));
        if cfg!(feature = "test-hooks") {
            return bundled;
        }
        let target = bundled
            .parent()
            .and_then(Path::parent)
            .expect("target dir")
            .join("test-hooks-build");
        let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
        let out = Command::new(cargo)
            .args([
                "build",
                "--locked",
                "--quiet",
                "--features",
                "test-hooks",
                "--bin",
                "hopae",
                "--target-dir",
            ])
            .arg(&target)
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .output()
            .expect("run cargo build for the test-hooks binary");
        assert!(
            out.status.success(),
            "building the test-hooks binary failed:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        target.join("debug").join("hopae")
    })
}

fn random_secret() -> String {
    use hopae::crypto::Rng;
    let mut b = [0u8; 24];
    hopae::crypto::OsRng.fill(&mut b);
    data_encoding::HEXLOWER.encode(&b)
}

impl Hopae {
    /// Start Hopae from `fixture` against `idp`. `env` adds or overrides
    /// environment variables; the gateway key and the mock secret are generated
    /// per run unless given. Panics (a harness failure) if it does not come up.
    pub fn spawn(fixture: Fixture, idp: &MockIdp, env: &[(&str, &str)]) -> Hopae {
        let state_dir = tempfile::tempdir().expect("state dir");
        let log_dir = tempfile::tempdir().expect("log dir");
        let config = fixture.render(state_dir.path(), idp);
        let config_path = state_dir.path().join("hopae.json");
        std::fs::write(
            &config_path,
            serde_json::to_vec_pretty(&config).expect("config json"),
        )
        .expect("write config");

        let mut vars: BTreeMap<String, String> = BTreeMap::new();
        vars.insert(KEY_ENV.into(), random_secret());
        vars.insert(MOCK_SECRET_ENV.into(), random_secret());
        vars.insert("HOPAE_TEST_HOOKS".into(), "127.0.0.1:0".into());
        for (k, v) in env {
            vars.insert((*k).into(), (*v).into());
        }
        idp.set_client_secret(vars.get(MOCK_SECRET_ENV).map(String::as_str));

        let log_path = log_dir.path().join("hopae.stderr");
        let expect_admin = config["admin"]["public_url"].is_string();
        let (child, portal, gateway, admin, hooks) =
            start_process(&config_path, &vars, &log_path, expect_admin);
        let h = Hopae {
            portal,
            gateway,
            admin,
            hooks: Hooks { addr: hooks },
            state_dir,
            child,
            env: vars,
            config,
            config_path,
            log_path,
            _log_dir: log_dir,
            idp: idp.clone(),
        };
        h.wait_ready();
        h
    }

    fn wait_ready(&self) {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let probe = super::client::try_send(
                self.portal,
                RawReq::new("GET", "/healthz", "localhost").timeout(Duration::from_secs(2)),
            );
            if probe.is_ok_and(|r| r.status == 200) {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "hopae did not become ready; log:\n{}",
                self.log()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// The process's stderr so far (structured log lines).
    pub fn log(&self) -> String {
        std::fs::read_to_string(&self.log_path).unwrap_or_default()
    }

    /// The configuration the process runs with (no secret values: they are env names).
    pub fn config(&self) -> &Value {
        &self.config
    }

    /// The value of an environment variable given to the process (a secret: never print it).
    pub fn env_value(&self, name: &str) -> Option<&str> {
        self.env.get(name).map(String::as_str)
    }

    /// Every secret value the process was given, for log/body denylist assertions.
    pub fn secret_values(&self) -> Vec<String> {
        self.env
            .iter()
            .filter(|(k, _)| {
                !matches!(
                    k.as_str(),
                    "HOPAE_TEST_HOOKS" | "HOPAE_TEST_SEED" | "HOPAE_TEST_DIAG_QUEUE"
                )
            })
            .map(|(_, v)| v.clone())
            .collect()
    }

    /// The portal's public host (from `portal.public_url`).
    pub fn portal_host(&self) -> String {
        let u = self.config["portal"]["public_url"]
            .as_str()
            .expect("public_url");
        url::Url::parse(u)
            .expect("public_url")
            .host_str()
            .expect("host")
            .to_string()
    }

    fn secure(&self) -> bool {
        self.config["cookie"]["secure"].as_bool().unwrap_or(true)
    }

    /// A browser tab on the portal host with its own cookie jar; follows no redirects.
    pub fn portal(&self) -> Client {
        self.portal_with(Jar::new())
    }

    /// A tab sharing `jar` (one browser, several tabs or hosts).
    pub fn portal_with(&self, jar: Jar) -> Client {
        Client::new(self.portal, &self.portal_host(), self.secure(), jar)
    }

    /// A tab for another host the browser talks to (the application host, for
    /// jar bookkeeping only: requests still go to the portal listener).
    pub fn key_value(&self, slot: &KeySlot) -> Option<String> {
        match slot {
            KeySlot::Current => self.named_key("caller_key_env"),
            KeySlot::Next => self.named_key("caller_key_next_env"),
            KeySlot::Missing => None,
            KeySlot::Wrong => Some("wrong-key-value".into()),
            KeySlot::Literal(v) => Some(v.clone()),
        }
    }

    fn named_key(&self, field: &str) -> Option<String> {
        let name = self.config["gateway"][field].as_str()?;
        self.env.get(name).cloned()
    }

    /// Call the verify endpoint as the gateway would. Default: the current caller key present.
    pub fn verify(&self, req: VerifyRequest) -> Response {
        let url = url::Url::parse(&req.url).unwrap_or_else(|e| panic!("verify url: {e}"));
        let host = match url.port() {
            Some(p) => format!("{}:{p}", url.host_str().unwrap_or("")),
            None => url.host_str().unwrap_or("").to_string(),
        };
        let mut headers: Vec<(String, String)> = vec![
            ("x-original-url".into(), req.url.clone()),
            (
                "x-forwarded-host".into(),
                url.host_str().unwrap_or("").to_string(),
            ),
            ("x-forwarded-proto".into(), url.scheme().to_string()),
            ("x-forwarded-for".into(), req.ip.clone()),
            ("x-real-ip".into(), req.ip.clone()),
            ("x-original-method".into(), "GET".into()),
        ];
        if req.document {
            headers.push(("sec-fetch-dest".into(), "document".into()));
            headers.push(("sec-fetch-mode".into(), "navigate".into()));
            headers.push(("accept".into(), "text/html,application/xhtml+xml".into()));
        } else {
            headers.push(("sec-fetch-dest".into(), "empty".into()));
            headers.push(("accept".into(), "application/json".into()));
        }
        if !req.cookies.is_empty() {
            let c = req
                .cookies
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join("; ");
            headers.push(("cookie".into(), c));
        }
        if let Some(ua) = &req.ua {
            headers.push(("user-agent".into(), ua.clone()));
        }
        if let Some(k) = self.key_value(&req.key) {
            headers.push(("x-hopae-gateway-key".into(), k));
        }
        headers.retain(|(k, _)| !req.removed.contains(k));
        headers.extend(req.extra.iter().cloned());
        let mut raw = RawReq::new("GET", "/_hopae/verify", &host);
        raw.headers.extend(headers);
        send(self.gateway, raw)
    }

    /// Browser-facing IP type helper for tests that build addresses.
    pub fn ip(s: &str) -> IpAddr {
        s.parse().expect("ip")
    }

    /// Kill the process (SIGKILL) and wait for it.
    pub fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    /// Kill if running, then start again on the same state directory and
    /// configuration. The listeners get new ephemeral ports (the fields update).
    pub fn restart(&mut self) {
        self.kill();
        let expect_admin = self.config["admin"]["public_url"].is_string();
        let (child, portal, gateway, admin, hooks) =
            start_process(&self.config_path, &self.env, &self.log_path, expect_admin);
        self.child = child;
        self.portal = portal;
        self.gateway = gateway;
        self.admin = admin;
        self.hooks = Hooks { addr: hooks };
        self.wait_ready();
    }

    /// Whether the process has exited (for crash-point tests); returns its exit status text.
    /// The process's resident set in KiB (`VmRSS` of `/proc/<pid>/status`);
    /// `None` when the process or the file is gone.
    pub fn rss_kib(&self) -> Option<u64> {
        let status = std::fs::read_to_string(format!("/proc/{}/status", self.child.id())).ok()?;
        status
            .lines()
            .find_map(|l| l.strip_prefix("VmRSS:"))
            .and_then(|v| v.split_whitespace().next())
            .and_then(|n| n.parse().ok())
    }

    pub fn exited(&mut self) -> Option<String> {
        self.child.try_wait().ok().flatten().map(|s| s.to_string())
    }

    /// Wait up to `timeout` for the process to exit (a crash point fired).
    pub fn wait_exit(&mut self, timeout: Duration) -> Option<String> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(s) = self.exited() {
                return Some(s);
            }
            if Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    /// The mock provider this instance was started with.
    pub fn idp(&self) -> &MockIdp {
        &self.idp
    }

    /// The path of the configuration the process runs with.
    pub fn config_path(&self) -> &Path {
        &self.config_path
    }

    /// The console host (`admin.public_url`'s host); panics without a console.
    pub fn console_host(&self) -> String {
        let u = self.config["admin"]["public_url"]
            .as_str()
            .expect("admin.public_url");
        url::Url::parse(u)
            .expect("admin.public_url")
            .host_str()
            .expect("host")
            .to_string()
    }

    /// The origin browsers send for the console (`https://hopae-admin.example.test`).
    pub fn console_origin(&self) -> String {
        let u = self.config["admin"]["public_url"]
            .as_str()
            .expect("admin.public_url");
        u.trim_end_matches('/').to_string()
    }

    /// The handle cookie name (`__Host-hopae` unless configured).
    pub fn cookie_name(&self) -> String {
        self.config["cookie"]["name"]
            .as_str()
            .unwrap_or(if self.secure() {
                "__Host-hopae"
            } else {
                "hopae"
            })
            .to_string()
    }

    /// Whether the instance serves `https` (`cookie.secure`).
    pub fn is_secure(&self) -> bool {
        self.secure()
    }

    /// Set the test clock and keep the mock provider's token clock in step.
    pub fn set_clock_ms(&self, ms: i64) {
        self.hooks.set_clock_ms(ms);
        self.idp.set_now_ms(Some(ms));
    }

    /// Advance the test clock and the mock provider's token clock together.
    pub fn advance(&self, d: Duration) {
        self.hooks.advance(d);
        self.idp.set_now_ms(Some(self.hooks.now_ms()));
    }
}

impl Drop for Hopae {
    fn drop(&mut self) {
        self.kill();
    }
}

fn start_process(
    config_path: &Path,
    vars: &BTreeMap<String, String>,
    log_path: &Path,
    expect_admin: bool,
) -> (
    Child,
    SocketAddr,
    SocketAddr,
    Option<SocketAddr>,
    SocketAddr,
) {
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
        .expect("log file");
    let mut cmd = Command::new(hopae_bin());
    cmd.arg("serve")
        .arg("--config")
        .arg(config_path)
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .envs(vars)
        .stdout(Stdio::piped())
        .stderr(Stdio::from(log));
    let mut child = cmd.spawn().expect("spawn hopae");
    let stdout = child.stdout.take().expect("stdout");
    let (tx, rx) = std::sync::mpsc::channel::<(String, SocketAddr)>();
    std::thread::spawn(move || {
        // Keep draining after the address lines so the child never blocks on a full pipe.
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            for prefix in [
                "portal listening on ",
                "gateway listening on ",
                "admin listening on ",
                "hooks listening on ",
            ] {
                if let Some(rest) = line.strip_prefix(prefix)
                    && let Ok(a) = rest.trim().parse()
                {
                    let _ = tx.send((prefix.split_whitespace().next().unwrap().to_string(), a));
                }
            }
        }
    });
    let (mut portal, mut gateway, mut admin, mut hooks) = (None, None, None, None);
    let deadline = Instant::now() + Duration::from_secs(30);
    while portal.is_none()
        || gateway.is_none()
        || hooks.is_none()
        || (expect_admin && admin.is_none())
    {
        let left = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(left) {
            Ok((what, a)) => match what.as_str() {
                "portal" => portal = Some(a),
                "gateway" => gateway = Some(a),
                "admin" => admin = Some(a),
                _ => hooks = Some(a),
            },
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                let log = std::fs::read_to_string(log_path).unwrap_or_default();
                panic!("hopae did not report its listeners; log:\n{log}");
            }
        }
    }
    (
        child,
        portal.unwrap(),
        gateway.unwrap(),
        admin,
        hooks.unwrap(),
    )
}

impl Hooks {
    /// Insert `n` users (ids `u_blk…`).
    pub fn bulk_users(&self, n: u64) {
        self.call("POST", "/bulk/users", Some(json!({"n": n})));
    }

    /// Insert `n` live sessions for `user_id`.
    pub fn bulk_sessions(&self, user_id: &str, n: u64) {
        self.call(
            "POST",
            "/bulk/sessions",
            Some(json!({"user_id": user_id, "n": n})),
        );
    }

    /// Insert `n` events spread over the last `hours` hours.
    pub fn bulk_events(&self, n: u64, hours: f64) {
        self.call(
            "POST",
            "/bulk/events",
            Some(json!({"n": n, "hours": hours})),
        );
    }

    /// A session whose `auth_time_source` is `hopae_completion`; with `host`
    /// also a handle for that host, whose cookie value is returned.
    pub fn legacy_session(&self, user_id: &str, host: Option<&str>) -> (String, Option<String>) {
        let r = self
            .call(
                "POST",
                "/sessions/legacy",
                Some(json!({"user_id": user_id, "host": host})),
            )
            .json();
        (
            r["session_id"].as_str().expect("session_id").to_string(),
            r["handle"].as_str().map(str::to_string),
        )
    }

    /// `admin_grants`, tombstones included.
    pub fn grants(&self) -> Vec<Value> {
        self.call("GET", "/grants", None).json()["grants"]
            .as_array()
            .cloned()
            .unwrap_or_default()
    }

    /// Slow every interruptible scan and every loop statement down by `ms`.
    pub fn slow_scan(&self, ms: u64) {
        self.call("POST", "/store/slow_scan", Some(json!({"ms": ms})));
    }

    pub fn slow_scan_off(&self) {
        self.call("POST", "/store/slow_scan", Some(json!({"off": true})));
    }

    /// A second connection holds the write lock for `ms` milliseconds.
    pub fn hold_write_lock(&self, ms: u64) {
        self.call("POST", "/store/hold_write_lock", Some(json!({"ms": ms})));
    }

    /// The deadline the last store job observed.
    pub fn last_deadline(&self) -> Value {
        self.call("GET", "/store/last_deadline", None).json()
    }

    /// The plan (and, with `stats`, the work) of a listing's window statement;
    /// `query` is `users`, `sessions` or `events`, with extra `&k=v` parameters
    /// such as `&index=user` or `&cursor=<key>:<id>` appended.
    pub fn explain(&self, query: &str, stats: bool) -> Value {
        let stats = if stats { "&stats=1" } else { "" };
        self.call("GET", &format!("/explain?query={query}{stats}"), None)
            .json()
    }
}

impl Hopae {
    /// VM steps the window statement of `query` takes (see [`Hooks::explain`]).
    pub fn vm_steps(&self, query: &str) -> u64 {
        self.hooks.explain(query, true)["vm_step"]
            .as_u64()
            .expect("vm_step")
    }

    /// Run the `hopae` binary as a command-line administrator against this
    /// instance's configuration and state (`--config` is appended). The
    /// process gets the instance's environment, without the test-hooks address.
    /// As [`Hopae::cli`] with the process's stdout replaced by `stdout`
    /// (for example `/dev/full`, where every write fails).
    pub fn cli_with_stdout(&self, args: &[&str], stdout: Stdio) -> super::admin::CliOutput {
        let out = Command::new(hopae_bin())
            .args(args)
            .arg("--config")
            .arg(&self.config_path)
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .envs(
                self.env
                    .iter()
                    .filter(|(k, _)| k.as_str() != "HOPAE_TEST_HOOKS"),
            )
            .stdin(Stdio::null())
            .stdout(stdout)
            .stderr(Stdio::piped())
            .output()
            .expect("run hopae");
        super::admin::CliOutput {
            status: out.status.code().unwrap_or(-1),
            stdout: String::new(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        }
    }

    /// As [`Hopae::cli`], but the process is started with both streams piped
    /// and returned running, so a test can observe what it prints before it
    /// finishes.
    pub fn cli_spawn(&self, args: &[&str]) -> std::process::Child {
        let mut cmd = Command::new(hopae_bin());
        cmd.args(args)
            .arg("--config")
            .arg(&self.config_path)
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .envs(
                self.env
                    .iter()
                    .filter(|(k, _)| k.as_str() != "HOPAE_TEST_HOOKS"),
            )
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        cmd.spawn().expect("spawn hopae")
    }

    pub fn cli(&self, args: &[&str]) -> super::admin::CliOutput {
        let mut cmd = Command::new(hopae_bin());
        cmd.args(args)
            .arg("--config")
            .arg(&self.config_path)
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .envs(
                self.env
                    .iter()
                    .filter(|(k, _)| k.as_str() != "HOPAE_TEST_HOOKS"),
            )
            .stdin(Stdio::null());
        let out = cmd.output().expect("run hopae");
        super::admin::CliOutput {
            status: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        }
    }

    /// A client for the admin listener, as the gateway would present a request
    /// for the console host.
    pub fn admin_client(&self) -> super::admin::AdminClient<'_> {
        super::admin::AdminClient::new(self)
    }
}
