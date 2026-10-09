//! Scenario 013: configuration preflight and startup (`hopae --check`,
//! `hopae run`, instance lock, migration backup, provider authority).
//!
//! These tests drive the real binary (built without `test-hooks`) over its
//! command line and signals; only the cases that need the portal, the verify
//! adapter or the provider registry from other work packages are `#[ignore]`d.
#![allow(dead_code)]

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use rusqlite::Connection;
use serde_json::{Value, json};

use crate::support::*;

const GW_KEY: &str = "gwkey-value-0123456789";
const MOCK_SECRET: &str = "mock-secret-value-9876543210";
const MOCK_ENV: &str = "HOPAE_TEST_MOCK_SECRET";

fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/config")
}

/// Copy fixture `name` into `dir` with `state_dir` pointing inside `dir`; returns the config path.
fn fixture_in(dir: &Path, name: &str) -> PathBuf {
    let text = std::fs::read_to_string(fixtures_dir().join(format!("{name}.json"))).unwrap();
    let mut v: Value = serde_json::from_str(&text).unwrap();
    v["state_dir"] = json!(dir.join("state"));
    let p = dir.join(format!("{name}.json"));
    std::fs::write(&p, serde_json::to_vec_pretty(&v).unwrap()).unwrap();
    p
}

fn write_value(dir: &Path, name: &str, v: &Value) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, serde_json::to_vec_pretty(v).unwrap()).unwrap();
    p
}

fn load_fixture(dir: &Path, name: &str) -> Value {
    serde_json::from_str(&std::fs::read_to_string(fixture_in(dir, name)).unwrap()).unwrap()
}

fn hopae() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_hopae"));
    c.env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default());
    c
}

struct Out {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

impl Out {
    fn all(&self) -> String {
        format!("{}\n{}", self.stdout, self.stderr)
    }
}

fn check(cfg: &Path, env: &[(&str, &str)], extra: &[&str]) -> Out {
    let mut c = hopae();
    c.arg("--check").args(extra).arg("--config").arg(cfg);
    for (k, v) in env {
        c.env(k, v);
    }
    let o = c.output().unwrap();
    Out {
        code: o.status.code(),
        stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
    }
}

fn run_cmd(cfg: &Path, env: &[(&str, &str)]) -> Out {
    let mut c = hopae();
    c.arg("run").arg("--config").arg(cfg);
    for (k, v) in env {
        c.env(k, v);
    }
    let o = c.output().unwrap();
    Out {
        code: o.status.code(),
        stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
    }
}

/// A running `hopae run` with stdout parsed for its addresses and stderr in a file.
struct Serve {
    child: Child,
    portal: std::net::SocketAddr,
    gateway: std::net::SocketAddr,
    stdout_lines: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    stderr_path: PathBuf,
}

impl Serve {
    fn start(cfg: &Path, env: &[(&str, &str)], tag: &str) -> Serve {
        let stderr_path = cfg.with_extension(format!("{tag}.stderr"));
        let log = std::fs::File::create(&stderr_path).unwrap();
        let mut c = hopae();
        c.arg("run")
            .arg("--config")
            .arg(cfg)
            .stdout(Stdio::piped())
            .stderr(Stdio::from(log));
        for (k, v) in env {
            c.env(k, v);
        }
        let mut child = c.spawn().unwrap();
        let out = child.stdout.take().unwrap();
        let lines = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let l2 = lines.clone();
        let (tx, rx) = std::sync::mpsc::channel::<(bool, std::net::SocketAddr)>();
        std::thread::spawn(move || {
            for line in BufReader::new(out).lines().map_while(Result::ok) {
                l2.lock().unwrap().push(line.clone());
                for (prefix, is_portal) in [
                    ("portal listening on ", true),
                    ("gateway listening on ", false),
                ] {
                    if let Some(rest) = line.strip_prefix(prefix)
                        && let Ok(a) = rest.trim().parse()
                    {
                        let _ = tx.send((is_portal, a));
                    }
                }
            }
        });
        let (mut portal, mut gateway) = (None, None);
        let deadline = Instant::now() + Duration::from_secs(30);
        while portal.is_none() || gateway.is_none() {
            match rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
                Ok((true, a)) => portal = Some(a),
                Ok((false, a)) => gateway = Some(a),
                Err(_) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!(
                        "hopae did not report its listeners; stderr:\n{}",
                        std::fs::read_to_string(&stderr_path).unwrap_or_default()
                    );
                }
            }
        }
        Serve {
            child,
            portal: portal.unwrap(),
            gateway: gateway.unwrap(),
            stdout_lines: lines,
            stderr_path,
        }
    }

    fn stderr(&self) -> String {
        std::fs::read_to_string(&self.stderr_path).unwrap_or_default()
    }

    fn signal(&self, sig: &str) {
        let st = Command::new("kill")
            .arg(format!("-{sig}"))
            .arg(self.child.id().to_string())
            .status()
            .unwrap();
        assert!(st.success());
    }

    /// Wait for exit; `None` on timeout.
    fn wait(&mut self, timeout: Duration) -> Option<Option<i32>> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(s) = self.child.try_wait().unwrap() {
                return Some(s.code());
            }
            if Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    fn terminate(&mut self) -> Option<i32> {
        self.signal("TERM");
        self.wait(Duration::from_secs(10)).flatten()
    }

    fn wait_stderr(&self, needle: &str, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if self.stderr().contains(needle) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        false
    }
}

impl Drop for Serve {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn db_path(dir: &Path) -> PathBuf {
    dir.join("state").join("hopae.db")
}

fn open_db(dir: &Path) -> Connection {
    Connection::open(db_path(dir)).unwrap()
}

const BOTH: &[(&str, &str)] = &[("HOPAE_TEST_GATEWAY_KEY", GW_KEY), (MOCK_ENV, MOCK_SECRET)];

#[test]
fn s013_1_valid_configuration_passes() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = fixture_in(dir.path(), "valid");
    let out = check(&cfg, BOTH, &[]);
    assert_eq!(out.code, Some(0), "{}", out.all());
    let so = &out.stdout;
    for needle in [
        "listeners",
        "127.0.0.1:0",
        "store: sqlite",
        "hopae.db",
        "app.example.test",
        "443",
        "ip=strict",
        "return origins",
        "https://app.example.test",
        "providers",
        "https://auth.example.test/callback/mock",
        "managed_by=file",
        "x-forwarded-user",
        "x-forwarded-email",
        "x-forwarded-groups",
        "x-hopae-session",
        "x-hopae-factors",
        "verify budget: 400 ms",
        "cache staleness bound: 0 s",
        "x-hopae-gateway-key",
        "HANGANG_HOPAE_KEY",
        "HOPAE_TEST_GATEWAY_KEY",
    ] {
        assert!(so.contains(needle), "stdout lacks {needle:?}:\n{so}");
    }
    // The fragment is real JSON naming the variable, never a value.
    let at = so.find("auth fragment").expect("fragment header");
    let rest = &so[at..];
    let brace = rest.find('{').expect("fragment json");
    let frag: Value = serde_json::Deserializer::from_str(&rest[brace..])
        .into_iter::<Value>()
        .next()
        .unwrap()
        .expect("fragment parses");
    assert!(
        frag["url"].as_str().unwrap().ends_with("/_hopae/verify"),
        "{frag}"
    );
    assert_eq!(frag["forward_response"], true);
    // HC-12 (ADR-0015): the route-level field with the configured handle and
    // binding cookie names, printed beside the `auth` fragment.
    assert!(
        frag.get("strip_request_cookies").is_none(),
        "route level, not in auth"
    );
    let at = so
        .find("route field strip_request_cookies")
        .expect("route field header");
    let rest = &so[at..];
    let brace = rest.find('{').expect("route field json");
    let field: Value = serde_json::Deserializer::from_str(&rest[brace..])
        .into_iter::<Value>()
        .next()
        .unwrap()
        .expect("route field parses");
    assert_eq!(
        field["strip_request_cookies"],
        json!(["__Host-hopae", "__Host-hopae_bind"])
    );
    assert_eq!(frag["static_request_headers"]["x-hopae-contract"], "1");
    assert_eq!(
        frag["static_request_headers"]["x-hopae-gateway-key"],
        json!({"env": "HANGANG_HOPAE_KEY"})
    );
    // No secret value anywhere.
    let all = out.all();
    assert!(
        !all.contains(GW_KEY) && !all.contains(MOCK_SECRET),
        "secret leaked"
    );
    assert!(so.trim_end().ends_with("config ok"), "{so}");
}

#[test]
fn s013_2_unknown_key_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = fixture_in(dir.path(), "unknown_key");
    let out = check(&cfg, BOTH, &[]);
    assert_eq!(out.code, Some(2), "{}", out.all());
    assert!(out.stderr.contains("apps[0].bindng"), "{}", out.stderr);
    assert!(
        out.stderr.contains("did you mean binding"),
        "{}",
        out.stderr
    );
}

#[test]
fn s013_3_missing_secret_degrades() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = fixture_in(dir.path(), "missing_secret");
    let only_key = &[("HOPAE_TEST_GATEWAY_KEY", GW_KEY)];
    let out = check(&cfg, only_key, &[]);
    assert_eq!(out.code, Some(0), "{}", out.all());
    assert!(
        out.stderr
            .contains("warning: provider mock disabled: HOPAE_TEST_MOCK_SECRET unset"),
        "{}",
        out.stderr
    );
    let strict = check(&cfg, only_key, &["--strict"]);
    assert_eq!(strict.code, Some(2), "{}", strict.all());

    // `run` starts with the provider disabled.
    let mut s = Serve::start(&cfg, only_key, "m3");
    assert_eq!(get(s.portal, "/healthz").status, 200);
    assert!(
        s.stderr()
            .contains("provider mock disabled: HOPAE_TEST_MOCK_SECRET unset"),
        "{}",
        s.stderr()
    );
    assert_eq!(s.terminate(), Some(0));
}

/// S013-3: with the only provider disabled (its secret unset) a real login
/// transaction, created through verify, meets the unavailable notice and no
/// provider control. (The old version requested `/login` without a
/// transaction and so only ever saw the bad-request page.)
#[test]
fn extra_s013_3_login_page_lists_no_providers() {
    let idp = MockIdp::start("default");
    // An empty secret disables the provider exactly like an unset one.
    let h = Hopae::spawn(
        Fixture::new("m1-basic"),
        &idp,
        &[("HOPAE_TEST_MOCK_SECRET", "")],
    );
    let r = h.verify(VerifyRequest::document("https://app.example.test/admin/x"));
    assert_eq!(r.status, 302, "{r:?}");
    let login = url::Url::parse(r.location().unwrap()).unwrap();
    assert!(login.query().is_some_and(|q| q.contains("txn=")));
    // The transaction is real: the same visit with a missing txn is a bad request.
    let bad = h.portal().get("/login");
    assert_eq!(bad.status, 400, "{bad:?}");
    let page = h
        .portal()
        .get(&format!("{}?{}", login.path(), login.query().unwrap()));
    assert_eq!(page.status, 503, "the unavailable page: {}", page.body);
    assert!(
        !page.body.contains("/login/mock") && !page.body.contains("callback/mock"),
        "{}",
        page.body
    );
    assert!(
        !page.body.contains("<form"),
        "no provider control: {}",
        page.body
    );
    assert_ne!(page.body, bad.body, "not the bad-request page");
    assert!(
        page.body.to_lowercase().contains("unavailable"),
        "the unavailable notice: {}",
        page.body
    );
}

#[test]
fn s013_4_run_refuses_invalid_config() {
    for name in [
        "unknown_key",
        "missing_caller_key",
        "cache_too_long",
        "bad_app_host",
        "duplicate_host",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let cfg = fixture_in(dir.path(), name);
        let chk = check(&cfg, BOTH, &[]);
        let run = run_cmd(&cfg, BOTH);
        assert_eq!(chk.code, Some(2), "{name}: {}", chk.all());
        assert_eq!(run.code, Some(2), "{name}: {}", run.all());
        assert!(
            !run.stdout.contains("listening"),
            "{name}: bound a listener"
        );
        assert_eq!(run.stderr, chk.stderr, "{name}: run and --check differ");
        assert!(
            !db_path(dir.path()).exists(),
            "{name}: store created before validation"
        );
    }
}

#[test]
fn s013_5_startup_order_and_readiness() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = fixture_in(dir.path(), "valid");
    let mut s = Serve::start(&cfg, BOTH, "m5");
    // gateway listener is announced last
    let lines = s.stdout_lines.lock().unwrap().clone();
    let p = lines
        .iter()
        .position(|l| l.starts_with("portal listening on "))
        .unwrap();
    let g = lines
        .iter()
        .position(|l| l.starts_with("gateway listening on "))
        .unwrap();
    assert!(p < g, "{lines:?}");
    assert_eq!(get(s.portal, "/healthz").status, 200);
    // store -> mirror -> listeners, in the log
    let log = s.stderr();
    let pos = |n: &str| {
        log.find(n)
            .unwrap_or_else(|| panic!("log lacks {n:?}:\n{log}"))
    };
    assert!(pos("store ready") < pos("configuration mirrored"), "{log}");
    assert!(
        pos("configuration mirrored") < pos("listeners bound"),
        "{log}"
    );
    // mirrored rows exist while running
    {
        let db = open_db(dir.path());
        let n: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM providers WHERE provider_id='mock'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 1);
        let apps: i64 = db
            .query_row("SELECT COUNT(*) FROM apps", [], |r| r.get(0))
            .unwrap();
        assert!(apps >= 1);
        let loaded: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM events WHERE kind='config.loaded'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(loaded, 1);
    }
    let started = Instant::now();
    assert_eq!(
        s.terminate(),
        Some(0),
        "exit status on SIGTERM; stderr:\n{}",
        s.stderr()
    );
    assert!(started.elapsed() < Duration::from_secs(6));
    // after shutdown the log carries the closing line and the WAL is checkpointed
    assert!(s.stderr().contains("shutdown complete"), "{}", s.stderr());
    let wal = db_path(dir.path()).with_extension("db-wal");
    let wal_len = std::fs::metadata(&wal).map(|m| m.len()).unwrap_or(0);
    assert_eq!(wal_len, 0, "WAL not checkpointed");
}

#[test]
fn extra_s013_5_healthz_reports_ready() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = fixture_in(dir.path(), "valid");
    let s = Serve::start(&cfg, BOTH, "m5b");
    let r = get(s.portal, "/healthz");
    assert_eq!(r.status, 200);
    assert_eq!(r.json()["ready"], true);
}

fn v1_database(path: &Path) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let c = Connection::open(path).unwrap();
    c.execute_batch(
        "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY NOT NULL, name TEXT NOT NULL, applied_at INTEGER NOT NULL) STRICT;",
    )
    .unwrap();
    let sql = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src/store/migrations/0001_meta.sql"),
    )
    .unwrap();
    c.execute_batch(&sql).unwrap();
    c.execute(
        "INSERT INTO schema_migrations (version, name, applied_at) VALUES (1, '0001_meta', 0)",
        [],
    )
    .unwrap();
}

fn schema_version(path: &Path) -> i64 {
    Connection::open(path)
        .unwrap()
        .query_row("SELECT MAX(version) FROM schema_migrations", [], |r| {
            r.get(0)
        })
        .unwrap()
}

#[test]
fn s013_6_schema_migration_and_provider_authority() {
    // (a) migration from schema version 1 writes a backup first.
    let dir = tempfile::tempdir().unwrap();
    let cfg = fixture_in(dir.path(), "valid");
    v1_database(&db_path(dir.path()));
    let mut s = Serve::start(&cfg, BOTH, "m6a");
    assert_eq!(get(s.portal, "/healthz").status, 200);
    assert_eq!(s.terminate(), Some(0));
    let bak = dir.path().join("state").join("hopae.db.bak-v1");
    assert!(bak.exists(), "no backup copy");
    assert_eq!(schema_version(&bak), 1, "backup must hold the old schema");
    assert!(schema_version(&db_path(dir.path())) >= 2);
    // a second start does not back up again (already current)
    std::fs::remove_file(&bak).unwrap();
    let mut s = Serve::start(&cfg, BOTH, "m6a2");
    assert_eq!(s.terminate(), Some(0));
    assert!(!bak.exists(), "backup written although no migration ran");

    // (b) API-managed, disabled provider stays disabled; --force reasserts the file.
    let dir = tempfile::tempdir().unwrap();
    let cfg = fixture_in(dir.path(), "valid");
    let mut s = Serve::start(&cfg, BOTH, "m6b1");
    assert_eq!(s.terminate(), Some(0));
    open_db(dir.path())
        .execute(
            "UPDATE providers SET enabled=0, managed_by='api' WHERE provider_id='mock'",
            [],
        )
        .unwrap();
    let mut s = Serve::start(&cfg, BOTH, "m6b2");
    assert!(
        s.stderr()
            .contains("provider mock: database authoritative (managed_by=api); file entry ignored"),
        "{}",
        s.stderr()
    );
    assert_eq!(s.terminate(), Some(0));
    let (enabled, managed): (i64, String) = open_db(dir.path())
        .query_row(
            "SELECT enabled, managed_by FROM providers WHERE provider_id='mock'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!((enabled, managed.as_str()), (0, "api"));
    let mut c = hopae();
    c.args(["providers", "import", "--force", "mock", "--config"])
        .arg(&cfg);
    for (k, v) in BOTH {
        c.env(k, v);
    }
    let o = c.output().unwrap();
    assert_eq!(
        o.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    let (enabled, managed): (i64, String) = open_db(dir.path())
        .query_row(
            "SELECT enabled, managed_by FROM providers WHERE provider_id='mock'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!((enabled, managed.as_str()), (1, "file"));
    let admin: i64 = open_db(dir.path())
        .query_row(
            "SELECT COUNT(*) FROM events WHERE reason='admin'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(admin, 1, "forced import must record an admin event");

    // (c) tombstone: removed at run time, kept across restart, reasserted only by --force.
    let dir = tempfile::tempdir().unwrap();
    let cfg = fixture_in(dir.path(), "valid");
    let mut s = Serve::start(&cfg, BOTH, "m6c1");
    assert_eq!(s.terminate(), Some(0));
    open_db(dir.path())
        .execute(
            "UPDATE providers SET managed_by='api', deleted_at=unixepoch() WHERE provider_id='mock'",
            [],
        )
        .unwrap();
    let mut s = Serve::start(&cfg, BOTH, "m6c2");
    assert!(
        s.stderr()
            .contains("provider mock: removed at run time; file entry ignored"),
        "{}",
        s.stderr()
    );
    assert_eq!(s.terminate(), Some(0));
    let deleted: Option<i64> = open_db(dir.path())
        .query_row(
            "SELECT deleted_at FROM providers WHERE provider_id='mock'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(deleted.is_some(), "tombstone must survive a restart");
}

#[test]
fn extra_s013_6_callback_answers_provider_disabled() {
    let idp = MockIdp::start("default");
    let mut h = Hopae::spawn(Fixture::new("m1-basic"), &idp, &[]);
    // A login in flight: the transaction is bound to the provider and the
    // browser has been to the provider, whose answer is the callback URL.
    let ip = "203.0.113.9";
    let r = h.verify(VerifyRequest::document("https://app.example.test/admin/x").ip(ip));
    let loc = r.location().expect("login redirect").to_string();
    let path = loc.split("auth.example.test").nth(1).expect("portal path");
    let jar = Jar::new();
    let go = h.portal_with(jar.clone()).with_ip(ip).get(path);
    assert_eq!(go.status, 302, "{go:?}");
    let callback = idp.follow_authorization(go.location().expect("provider redirect"));

    // The provider is disabled in the database (managed_by=api), then the
    // process restarts: the database is authoritative over the file.
    h.kill();
    Connection::open(h.state_dir.path().join("state").join("hopae.db"))
        .unwrap()
        .execute(
            "UPDATE providers SET enabled=0, managed_by='api' WHERE provider_id='mock'",
            [],
        )
        .unwrap();
    h.restart();
    let r = h.portal_with(jar).with_ip(ip).get(&callback);
    assert_eq!(r.status, 400, "{r:?}");
    assert!(
        h.hooks
            .events(Some("login.failed"), None)
            .iter()
            .any(|e| e["reason"] == "provider_disabled" && e["provider_id"] == "mock"),
        "login.failed with reason provider_disabled"
    );
    // No session was created.
    assert!(h.hooks.events(Some("session.created"), None).is_empty());
}

#[test]
fn s013_7_reload_unsupported_and_key_rotation_by_restart() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = fixture_in(dir.path(), "valid");
    let mut s = Serve::start(&cfg, BOTH, "m7");
    s.signal("HUP");
    assert!(
        s.wait_stderr("reload not supported; restart", Duration::from_secs(5)),
        "{}",
        s.stderr()
    );
    assert!(
        s.wait(Duration::from_millis(300)).is_none(),
        "SIGHUP must not stop the process"
    );
    assert_eq!(get(s.portal, "/healthz").status, 200);
    assert_eq!(s.terminate(), Some(0));

    // Overlap warning: caller_key_next_env configured for more than 7 days.
    let dir = tempfile::tempdir().unwrap();
    let mut v = load_fixture(dir.path(), "valid");
    v["gateway"]["caller_key_next_env"] = json!("HOPAE_GW_KEY_B");
    let cfg = write_value(dir.path(), "rot.json", &v);
    let env: &[(&str, &str)] = &[
        ("HOPAE_TEST_GATEWAY_KEY", GW_KEY),
        ("HOPAE_GW_KEY_B", "other-key-value-b"),
        (MOCK_ENV, MOCK_SECRET),
    ];
    let mut s = Serve::start(&cfg, env, "m7r");
    assert_eq!(s.terminate(), Some(0));
    let fresh = check(&cfg, env, &[]);
    assert_eq!(fresh.code, Some(0), "{}", fresh.all());
    assert!(
        !fresh
            .stderr
            .contains("caller_key_next_env configured since"),
        "{}",
        fresh.stderr
    );
    let eight_days_ago = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
        - 8 * 86_400;
    let n = open_db(dir.path())
        .execute(
            "UPDATE meta SET value=?1 WHERE key='caller_key_next_since'",
            [eight_days_ago.to_string()],
        )
        .unwrap();
    assert_eq!(n, 1, "run must record when the overlap began");
    let stale = check(&cfg, env, &[]);
    assert_eq!(stale.code, Some(0), "{}", stale.all());
    assert!(
        stale
            .stderr
            .contains("warning: caller_key_next_env configured since "),
        "{}",
        stale.stderr
    );
    assert_eq!(check(&cfg, env, &["--strict"]).code, Some(2));
    assert!(!stale.all().contains("other-key-value-b"));
}

/// S013-7, the whole sequence A -> A+B -> B with literal key values: each
/// stage accepts exactly the keys it should (a valid key reaches the login
/// redirect, anything else is `caller_unauthorized`), and after the final
/// restart the retired key A is refused.
#[test]
fn extra_s013_7_rotation_accepts_both_keys_and_refuses_the_retired_one() {
    const KEY_A: &str = "rotation-key-a-value-0001";
    const KEY_B: &str = "rotation-key-b-value-0002";
    let url = "https://app.example.test/";
    let accepted = |h: &Hopae, key: &str| {
        let r = h.verify(VerifyRequest::document(url).key(KeySlot::Literal(key.into())));
        assert_eq!(
            r.status, 302,
            "key {key} must reach the login redirect: {r:?}"
        );
        assert_ne!(
            r.header("x-hopae-reason"),
            Some("caller_unauthorized"),
            "{r:?}"
        );
    };
    let refused = |h: &Hopae, key: &str| {
        let r = h.verify(VerifyRequest::document(url).key(KeySlot::Literal(key.into())));
        assert_eq!(
            r.header("x-hopae-reason"),
            Some("caller_unauthorized"),
            "key {key} must be refused: {r:?}"
        );
        assert_ne!(r.status, 302, "{r:?}");
    };
    // Stage 1: A only.
    let idp = MockIdp::start("default");
    let mut h = Hopae::spawn(
        Fixture::new("m1-basic"),
        &idp,
        &[(KEY_ENV, KEY_A), ("HOPAE_GW_KEY_B", KEY_B)],
    );
    accepted(&h, KEY_A);
    refused(&h, KEY_B);
    h.kill();
    // Stage 2: A+B (B is the next key).
    let mut h = Hopae::spawn(
        Fixture::with(
            "m1-basic",
            json!({"gateway": {"caller_key_next_env": "HOPAE_GW_KEY_B"}}),
        ),
        &idp,
        &[(KEY_ENV, KEY_A), ("HOPAE_GW_KEY_B", KEY_B)],
    );
    accepted(&h, KEY_A);
    accepted(&h, KEY_B);
    refused(&h, "some-other-key-value");
    h.kill();
    // Stage 3: B only (B is promoted, the overlap ends). A is retired.
    let mut h = Hopae::spawn(
        Fixture::with(
            "m1-basic",
            json!({"gateway": {"caller_key_env": "HOPAE_GW_KEY_B", "caller_key_next_env": null}}),
        ),
        &idp,
        &[(KEY_ENV, KEY_A), ("HOPAE_GW_KEY_B", KEY_B)],
    );
    accepted(&h, KEY_B);
    refused(&h, KEY_A);
    h.kill();
}

#[test]
fn s013_a1_unsafe_values_rejected() {
    let dir = tempfile::tempdir().unwrap();
    for (name, needle) in [
        ("missing_caller_key", "caller_key_env"),
        ("cache_too_long", "verify_cache_seconds"),
        ("bad_app_host", "hosts[0]"),
        ("duplicate_host", "already claimed"),
    ] {
        let cfg = fixture_in(dir.path(), name);
        let out = check(&cfg, BOTH, &[]);
        assert_eq!(out.code, Some(2), "{name}: {}", out.all());
        assert!(out.stderr.contains(needle), "{name}: {}", out.stderr);
    }
    // A caller key variable that is unset is an error, never a warning.
    let cfg = fixture_in(dir.path(), "valid");
    let out = check(&cfg, &[(MOCK_ENV, MOCK_SECRET)], &[]);
    assert_eq!(out.code, Some(2), "{}", out.all());
    assert!(
        out.stderr.contains("HOPAE_TEST_GATEWAY_KEY"),
        "{}",
        out.stderr
    );
    // A non-loopback gateway bind passes only with a key, and says so.
    let cfg = fixture_in(dir.path(), "public_gateway_listener");
    let out = check(&cfg, BOTH, &[]);
    assert_eq!(out.code, Some(0), "{}", out.all());
    assert!(
        out.stderr.contains("relies on the caller key alone"),
        "{}",
        out.stderr
    );
}

#[test]
fn s013_a2_second_process_same_store_refused() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = fixture_in(dir.path(), "valid");
    let mut first = Serve::start(&cfg, BOTH, "a2");
    let second = run_cmd(&cfg, BOTH);
    assert_eq!(second.code, Some(2), "{}", second.all());
    assert!(
        second.stderr.contains("store locked by another instance"),
        "{}",
        second.stderr
    );
    assert!(!second.stdout.contains("listening"));
    assert_eq!(get(first.portal, "/healthz").status, 200);
    assert!(dir.path().join("state").join("hopae.lock").exists());
    assert_eq!(first.terminate(), Some(0));
    // After a clean stop the lock is free again.
    let mut again = Serve::start(&cfg, BOTH, "a2b");
    assert_eq!(again.terminate(), Some(0));
}

#[test]
fn s013_a3_huge_config_bounded() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("huge.json");
    let f = std::fs::File::create(&p).unwrap();
    f.set_len(50 * 1024 * 1024).unwrap();
    drop(f);
    let started = Instant::now();
    let out = check(&p, BOTH, &[]);
    assert_eq!(out.code, Some(2), "{}", out.all());
    assert!(
        out.stderr.contains("configuration too large"),
        "{}",
        out.stderr
    );
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[test]
fn s013_a4_literal_secret_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let mut v = load_fixture(dir.path(), "valid");
    v["providers"][0]["client_secret"] = json!("literal-secret-xyz");
    let cfg = write_value(dir.path(), "literal.json", &v);
    let out = check(&cfg, BOTH, &[]);
    assert_eq!(out.code, Some(2), "{}", out.all());
    assert!(
        out.stderr
            .contains("secrets must be referenced by environment variable name"),
        "{}",
        out.stderr
    );
    assert!(!out.all().contains("literal-secret-xyz"));
}

#[test]
fn s013_a5_insecure_modes_loud() {
    let cases = [
        (
            "insecure_cookie",
            "WARNING: insecure cookie mode (development only)",
        ),
        (
            "unauthenticated_caller",
            "WARNING: verify caller authentication disabled (development only)",
        ),
    ];
    for (name, warning) in cases {
        let dir = tempfile::tempdir().unwrap();
        let cfg = fixture_in(dir.path(), name);
        let out = check(&cfg, BOTH, &[]);
        assert_eq!(out.code, Some(0), "{name}: {}", out.all());
        assert!(out.stderr.contains(warning), "{name}: {}", out.stderr);
        assert_eq!(check(&cfg, BOTH, &["--strict"]).code, Some(2), "{name}");
        let mut s = Serve::start(&cfg, BOTH, "a5");
        assert!(s.stderr().contains(warning), "{name}: {}", s.stderr());
        assert_eq!(s.terminate(), Some(0));
    }
}

#[test]
fn extra_s013_a5_health_body_reports_insecure_flags() {
    for (name, flag) in [
        ("insecure_cookie", "insecure_mode"),
        ("unauthenticated_caller", "unauthenticated_caller"),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let cfg = fixture_in(dir.path(), name);
        let s = Serve::start(&cfg, BOTH, "a5h");
        assert_eq!(get(s.portal, "/healthz").json()[flag], true, "{name}");
    }
}

/// G7 B01: migration 0002 was edited in place before the first release. A
/// database that a pre-release build left at schema version 2 lacks the
/// `sessions.authz_version_at_auth` column and the `users_primary_email`
/// index; starting on it must be refused with a clear message, not fail later
/// in a session query or silently run without the uniqueness rule.
#[test]
fn extra_s013_pre_release_v2_database_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = fixture_in(dir.path(), "valid");
    std::fs::create_dir_all(dir.path().join("state")).unwrap();
    {
        let c = Connection::open(db_path(dir.path())).unwrap();
        c.execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY NOT NULL, name TEXT NOT NULL, applied_at INTEGER NOT NULL) STRICT;",
        )
        .unwrap();
        c.execute_batch(include_str!("../../src/store/migrations/0001_meta.sql"))
            .unwrap();
        c.execute_batch(include_str!("../fixtures/pre_release_0002_m1_schema.sql"))
            .unwrap();
        c.execute_batch(
            "INSERT OR IGNORE INTO schema_migrations VALUES (1,'0001_meta',0);
             INSERT OR IGNORE INTO schema_migrations VALUES (2,'0002_m1_schema',0);",
        )
        .unwrap();
    }
    // Bounded: a start that is not refused would serve forever.
    let mut c = hopae();
    c.arg("run").arg("--config").arg(&cfg);
    for (k, v) in BOTH {
        c.env(k, v);
    }
    c.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = c.spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    let status = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break s;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("hopae started on a pre-release v2 database instead of refusing it");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let mut stderr = String::new();
    std::io::Read::read_to_string(&mut child.stderr.take().unwrap(), &mut stderr).unwrap();
    assert_eq!(status.code(), Some(2), "{stderr}");
    assert!(
        stderr.contains("development database from a pre-release schema; delete it"),
        "{stderr}"
    );
    // The shape pass 2 left behind (column and email index, but no
    // `event_deliveries(event_id)` index and no admissions table) is refused too.
    let dir3 = tempfile::tempdir().unwrap();
    let cfg3 = fixture_in(dir3.path(), "valid");
    std::fs::create_dir_all(dir3.path().join("state")).unwrap();
    {
        let c = Connection::open(db_path(dir3.path())).unwrap();
        c.execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY NOT NULL, name TEXT NOT NULL, applied_at INTEGER NOT NULL) STRICT;",
        )
        .unwrap();
        c.execute_batch(include_str!("../../src/store/migrations/0001_meta.sql"))
            .unwrap();
        c.execute_batch(include_str!(
            "../../src/store/migrations/0002_m1_schema.sql"
        ))
        .unwrap();
        c.execute_batch(
            "DROP INDEX event_deliveries_event_id; DROP TABLE txn_admissions;
             INSERT OR IGNORE INTO schema_migrations VALUES (1,'0001_meta',0);
             INSERT OR IGNORE INTO schema_migrations VALUES (2,'0002_m1_schema',0);",
        )
        .unwrap();
    }
    let mut c = hopae();
    c.arg("run").arg("--config").arg(&cfg3);
    for (k, v) in BOTH {
        c.env(k, v);
    }
    let o = c.output().unwrap();
    assert_eq!(
        o.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    // A current database starts normally.
    let dir2 = tempfile::tempdir().unwrap();
    let cfg2 = fixture_in(dir2.path(), "valid");
    let mut s = Serve::start(&cfg2, BOTH, "b01");
    assert_eq!(s.terminate(), Some(0));
}
