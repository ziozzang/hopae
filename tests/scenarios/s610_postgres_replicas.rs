//! Scenario 610: two `hopae serve` replicas on one PostgreSQL store (ADR-0020
//! slice 5), behind a TCP round-robin balancer, under browser and gateway
//! traffic, with one replica killed (SIGKILL) mid-traffic.
//!
//! Runs only when the binary has the `postgres` and `test-hooks` features and
//! `HOPAE_TEST_POSTGRES_URL` names a server (`make qualify-postgres`); each
//! run uses a fresh database that is dropped afterwards.
#![cfg(all(feature = "postgres", feature = "test-hooks"))]
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use serde_json::json;

use crate::support::client::{Client, RawReq, Req, send};
use crate::support::process::MOCK_SECRET_ENV;
use crate::support::{Fixture, Hopae, Jar, KEY_ENV, MockIdp, Response};

const APP: &str = "app.example.test";
const IP: &str = "192.0.2.10";
/// The service host whose authentication profile is published at run time.
const SVC: &str = "svc.example.test";
const SERVICE_KEY_ENV: &str = "HOPAE_QUALIFY_SERVICE_KEY";
const SERVICE_KEY: &str = "qualify-service-credential-0123456789abcdef";

fn plans(revision: u64) -> serde_json::Value {
    json!({"revision": revision, "plans": [{"service": "app", "audience": "app-api", "resource": "app",
        "action": "read", "minimum_aal": 1,
        "credential": {"type": "bearer_reference", "secret_ref": "vault:qualify"}}]})
}

fn profiles() -> serde_json::Value {
    json!({"authority_id": "qualify", "profiles": [{"service_id": "svc", "host": SVC, "ports": [443],
        "realm": "services", "api_keys": [{"token_env": SERVICE_KEY_ENV, "subject": "worker"}]}]})
}

/// A TCP round-robin balancer over the live backends: each connection goes
/// to the next backend that accepts it (a dead one is skipped).
struct Balancer {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
}

impl Balancer {
    fn start(backends: Vec<SocketAddr>) -> Balancer {
        let listener = TcpListener::bind("127.0.0.1:0").expect("balancer");
        let addr = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let next = Arc::new(AtomicUsize::new(0));
        let flag = stop.clone();
        listener.set_nonblocking(true).unwrap();
        std::thread::spawn(move || {
            while !flag.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((client, _)) => {
                        let backends = backends.clone();
                        let next = next.clone();
                        std::thread::spawn(move || {
                            let start = next.fetch_add(1, Ordering::Relaxed);
                            let upstream = (0..backends.len()).find_map(|i| {
                                TcpStream::connect_timeout(
                                    &backends[(start + i) % backends.len()],
                                    Duration::from_millis(300),
                                )
                                .ok()
                            });
                            let Some(upstream) = upstream else { return };
                            client.set_nonblocking(false).ok();
                            pipe(client, upstream);
                        });
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(2)),
                }
            }
        });
        Balancer { addr, stop }
    }
}

impl Drop for Balancer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

fn pipe(a: TcpStream, b: TcpStream) {
    let (mut a2, mut b2) = (a.try_clone().unwrap(), b.try_clone().unwrap());
    let t = std::thread::spawn(move || {
        let mut buf = [0u8; 16384];
        let mut a = a;
        let mut b = b;
        while let Ok(n) = a.read(&mut buf) {
            if n == 0 || b.write_all(&buf[..n]).is_err() {
                break;
            }
        }
        let _ = b.shutdown(std::net::Shutdown::Write);
    });
    let mut buf = [0u8; 16384];
    while let Ok(n) = b2.read(&mut buf) {
        if n == 0 || a2.write_all(&buf[..n]).is_err() {
            break;
        }
    }
    let _ = a2.shutdown(std::net::Shutdown::Write);
    let _ = t.join();
}

/// A fresh database on the test server; dropped when this goes away.
struct Database {
    admin_url: String,
    name: String,
    url: String,
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

impl Database {
    fn create() -> Option<Database> {
        let admin_url = std::env::var("HOPAE_TEST_POSTGRES_URL").ok()?;
        let name = format!("hopae_q_{}", std::process::id());
        rt().block_on(async {
            let (c, conn) = tokio_postgres::connect(&admin_url, tokio_postgres::NoTls)
                .await
                .expect("connect");
            tokio::spawn(conn);
            c.simple_query(&format!("DROP DATABASE IF EXISTS {name}"))
                .await
                .expect("drop database");
            c.simple_query(&format!("CREATE DATABASE {name}"))
                .await
                .expect("create database");
        });
        let url = if admin_url.contains("dbname=") {
            admin_url
                .split_whitespace()
                .map(|kv| {
                    if kv.starts_with("dbname=") {
                        format!("dbname={name}")
                    } else {
                        kv.to_string()
                    }
                })
                .collect::<Vec<_>>()
                .join(" ")
        } else {
            format!("{admin_url} dbname={name}")
        };
        Some(Database {
            admin_url,
            name,
            url,
        })
    }

    fn query_i64(&self, sql: &str) -> i64 {
        let url = self.url.clone();
        let sql = sql.to_string();
        rt().block_on(async move {
            let (c, conn) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
                .await
                .expect("connect");
            tokio::spawn(conn);
            c.query_one(&sql, &[]).await.expect(&sql).get::<_, i64>(0)
        })
    }

    fn execute(&self, sql: &str) {
        let url = self.url.clone();
        let sql = sql.to_string();
        rt().block_on(async move {
            let (c, conn) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
                .await
                .expect("connect");
            tokio::spawn(conn);
            c.batch_execute(&sql).await.expect(&sql);
        });
    }
}

impl Drop for Database {
    fn drop(&mut self) {
        let (url, name) = (self.admin_url.clone(), self.name.clone());
        rt().block_on(async move {
            if let Ok((c, conn)) = tokio_postgres::connect(&url, tokio_postgres::NoTls).await {
                tokio::spawn(conn);
                let _ = c
                    .simple_query(&format!("DROP DATABASE IF EXISTS {name} WITH (FORCE)"))
                    .await;
            }
        });
    }
}

/// A gateway's verify call through the balancer, with the host's cookies.
fn verify(gw: SocketAddr, key: &str, jar: &Jar, cookie: &str, url: &str) -> Response {
    let u = url::Url::parse(url).unwrap();
    let mut raw = RawReq::new("GET", "/_hopae/verify", u.host_str().unwrap())
        .header("x-original-url", url)
        .header("x-forwarded-host", u.host_str().unwrap())
        .header("x-forwarded-proto", "https")
        .header("x-forwarded-for", IP)
        .header("x-real-ip", IP)
        .header("x-original-method", "GET")
        .header("sec-fetch-dest", "document")
        .header("sec-fetch-mode", "navigate")
        .header("accept", "text/html")
        .header("x-hopae-gateway-key", key)
        .timeout(Duration::from_secs(20));
    let host = u.host_str().unwrap().to_string();
    let hj = jar.for_host(&host);
    let cookies: Vec<String> = [cookie.to_string(), format!("{cookie}_bind")]
        .iter()
        .filter_map(|n| hj.value(n).map(|v| format!("{n}={v}")))
        .collect();
    if !cookies.is_empty() {
        raw = raw.header("cookie", &cookies.join("; "));
    }
    // A connection cut by a killed replica reads as status 0.
    let r = crate::support::client::try_send(gw, raw).unwrap_or(Response {
        status: 0,
        headers: vec![],
        body: String::new(),
    });
    for c in r.set_cookies() {
        jar.store(&host, "/", true, c);
    }
    r
}

fn path_of(u: &str) -> String {
    let u = url::Url::parse(u).unwrap();
    match u.query() {
        Some(q) => format!("{}?{q}", u.path()),
        None => u.path().to_string(),
    }
}

struct Stack {
    db: Database,
    idp: MockIdp,
    a: Hopae,
    b: Hopae,
    gateway: Balancer,
    portal: Balancer,
    key: String,
    cookie: String,
}

impl Stack {
    fn start() -> Option<Stack> {
        let db = Database::create()?;
        let idp = MockIdp::start("auth_time_present");
        let key = "qualify-gateway-key-0123456789abcdef0123456789abcdef".to_string();
        let secret = "qualify-mock-secret-0123456789abcdef".to_string();
        let fixture = || {
            Fixture::with(
                "m4-admin",
                json!({
                    "store": {"kind": "postgres", "postgres": {"url_env": "HOPAE_QUALIFY_PG", "pool_size": 8}},
                    "apps": [
                        {"app_id": "app", "display_name": "app", "hosts": [APP], "ports": [443],
                         "session": {"idle": "12h", "absolute": "7d"},
                         "binding": {"ip": "strict", "ua": "off", "on_mismatch": "terminate_session"},
                         "on_authz_change": "refresh", "verify_cache_seconds": 0},
                        {"app_id": "svc", "display_name": "svc", "hosts": [SVC], "ports": [443]},
                        {"app_id": "default", "display_name": "default"}
                    ],
                    "authentication_gateway": profiles(),
                    "credential_projection": plans(1),
                }),
            )
        };
        let env = [
            (KEY_ENV, key.as_str()),
            (MOCK_SECRET_ENV, secret.as_str()),
            ("HOPAE_QUALIFY_PG", db.url.as_str()),
            (SERVICE_KEY_ENV, SERVICE_KEY),
        ];
        let a = Hopae::spawn(fixture(), &idp, &env);
        let b = Hopae::spawn(fixture(), &idp, &env);
        let gateway = Balancer::start(vec![a.gateway, b.gateway]);
        let portal = Balancer::start(vec![a.portal, b.portal]);
        let cookie = a.cookie_name();
        Some(Stack {
            db,
            idp,
            a,
            b,
            gateway,
            portal,
            key,
            cookie,
        })
    }

    /// A console JSON write as the gateway forwards it, to one replica's admin listener.
    fn console_post(&self, admin: SocketAddr, handle: &str, path: &str) -> Response {
        self.console_send("POST", admin, handle, path, None, b"{}")
    }

    fn console_send(
        &self,
        method: &str,
        admin: SocketAddr,
        handle: &str,
        path: &str,
        if_match: Option<u64>,
        body: &[u8],
    ) -> Response {
        let host = self.a.console_host();
        let mut raw = RawReq::new(method, path, &host)
            .header("x-forwarded-host", &host)
            .header("x-forwarded-proto", "https")
            .header("x-forwarded-for", IP)
            .header("cookie", &format!("{}={handle}", self.cookie))
            .header("content-type", "application/json")
            .header("x-hopae-admin-request", "1")
            .timeout(Duration::from_secs(20));
        if let Some(revision) = if_match {
            raw = raw.header("if-match", &format!("\"{revision}\""));
        }
        raw.body = body.to_vec();
        send(admin, raw)
    }

    /// A service call with the profile's API credential, straight to one replica.
    fn service_verify(&self, gateway: SocketAddr) -> Response {
        let url = format!("https://{SVC}/jobs");
        let raw = RawReq::new("GET", "/_hopae/verify", SVC)
            .header("x-original-url", &url)
            .header("x-forwarded-host", SVC)
            .header("x-forwarded-proto", "https")
            .header("x-forwarded-for", IP)
            .header("x-real-ip", IP)
            .header("x-original-method", "GET")
            .header("accept", "application/json")
            .header("authorization", &format!("Bearer {SERVICE_KEY}"))
            .header("x-hopae-gateway-key", &self.key)
            .timeout(Duration::from_secs(20));
        send(gateway, raw)
    }

    fn service_allowed(&self, gateway: SocketAddr) -> bool {
        let r = self.service_verify(gateway);
        r.status == 200 && r.header("x-hopae-principal-kind") == Some("service")
    }

    /// Wait until `gateway` enforces `allowed`; the time it took.
    fn converge(&self, gateway: SocketAddr, allowed: bool) -> Duration {
        let start = std::time::Instant::now();
        while self.service_allowed(gateway) != allowed {
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "replica never followed the publication"
            );
            std::thread::sleep(Duration::from_millis(25));
        }
        start.elapsed()
    }

    fn query_string(&self, sql: &str, arg: &str) -> String {
        let (url, sql, arg) = (self.db.url.clone(), sql.to_string(), arg.to_string());
        rt().block_on(async move {
            let (c, conn) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
                .await
                .unwrap();
            tokio::spawn(conn);
            c.query_one(&sql, &[&arg]).await.expect(&sql).get(0)
        })
    }

    fn portal_client(&self, jar: Jar) -> Client {
        Client::new(self.portal.addr, "auth.example.test", true, jar).with_ip(IP)
    }

    /// One whole login through the balancers; every hop may land on either
    /// replica. Returns the application jar (with the handle) and the portal jar.
    fn login(&self, sub: &str) -> (Jar, Jar) {
        self.login_on(sub, "https://app.example.test/admin/x")
    }

    fn login_on(&self, sub: &str, start: &str) -> (Jar, Jar) {
        self.idp
            .set_user(sub, &format!("{sub}@example.test"), true, sub);
        self.idp.set_subject(sub);
        let app = Jar::new();
        let first = verify(self.gateway.addr, &self.key, &app, &self.cookie, start);
        assert_eq!(first.status, 302, "first hop: {first:?}");
        let portal_jar = Jar::new();
        let portal = self.portal_client(portal_jar.clone());
        let ppath = path_of(first.location().unwrap());
        let page = portal.get(&ppath);
        let authorize = if page.status == 302 {
            page.location().unwrap().to_string()
        } else {
            let csrf = page
                .body
                .split("name=\"csrf\" value=\"")
                .nth(1)
                .and_then(|r| r.split('"').next())
                .expect("csrf")
                .to_string();
            let txn = ppath.split("txn=").nth(1).expect("txn").to_string();
            // The form was rendered by one replica and may be posted to the other.
            let r = portal.send(
                Req::post("/login/mock")
                    .form(&[("csrf", &csrf), ("txn", &txn)])
                    .header("origin", "https://auth.example.test"),
            );
            assert_eq!(r.status, 302, "provider redirect: {r:?}");
            r.location().unwrap().to_string()
        };
        let cb = self.idp.follow_authorization(&authorize);
        let back = portal.send(Req::get(&cb).cross_site_navigation());
        assert_eq!(back.status, 302, "callback: {back:?}");
        let handoff = back.location().unwrap().to_string();
        let redeem = verify(self.gateway.addr, &self.key, &app, &self.cookie, &handoff);
        assert_eq!(redeem.status, 302, "handoff: {redeem:?}");
        let clean = verify(
            self.gateway.addr,
            &self.key,
            &app,
            &self.cookie,
            redeem.location().unwrap_or(start),
        );
        assert_eq!(clean.status, 200, "clean request: {clean:?}");
        (app, portal_jar)
    }
}

#[test]
fn s610_1_two_replicas_share_logins_handoffs_fences_and_survive_a_killed_replica() {
    let Some(mut s) = Stack::start() else {
        eprintln!("skip: HOPAE_TEST_POSTGRES_URL not set");
        return;
    };
    // 1. Logins whose hops alternate between the replicas.
    let mut people: BTreeMap<String, (Jar, Jar)> = BTreeMap::new();
    for n in 0..8 {
        let sub = format!("user-{n}");
        let jars = s.login(&sub);
        people.insert(sub, jars);
    }
    assert_eq!(s.db.query_i64("SELECT count(*) FROM users"), 8);
    // 2. A handoff code presented to both replicas at once mints exactly once.
    let mut minted = 0;
    let mut rejected = 0;
    for (_, (_, portal_jar)) in people.iter().take(4) {
        let fresh = Jar::new();
        let first = verify(
            s.gateway.addr,
            &s.key,
            &fresh,
            &s.cookie,
            "https://app.example.test/other",
        );
        assert_eq!(first.status, 302);
        let hop = s
            .portal_client(portal_jar.clone())
            .send(Req::get(&path_of(first.location().unwrap())));
        assert_eq!(hop.status, 302, "single sign-on: {hop:?}");
        let handoff = hop.location().unwrap().to_string();
        // Both carry the browser's bind cookie: only the code decides.
        let (ja, jb) = (fresh.clone(), fresh.clone());
        let (ga, gb) = (s.a.gateway, s.b.gateway);
        let (ka, kb, ca, cb) = (
            s.key.clone(),
            s.key.clone(),
            s.cookie.clone(),
            s.cookie.clone(),
        );
        let (ha, hb) = (handoff.clone(), handoff.clone());
        let ta = std::thread::spawn(move || verify(ga, &ka, &ja, &ca, &ha));
        let tb = std::thread::spawn(move || verify(gb, &kb, &jb, &cb, &hb));
        for r in [ta.join().unwrap(), tb.join().unwrap()] {
            let handle = format!("{}=", s.cookie);
            if r.status == 302 && r.set_cookies().iter().any(|c| c.starts_with(&handle)) {
                minted += 1;
            } else {
                rejected += 1;
            }
        }
    }
    assert_eq!((minted, rejected), (4, 4), "one redemption per code");
    // 3. Fenced administrator writes through both replicas' consoles at once.
    let console = format!("https://{}/", s.a.console_host());
    let (console_jar, _) = s.login_on("admin-sub", &console);
    let handle = console_jar
        .for_host(&s.a.console_host())
        .value(&s.cookie)
        .expect("console handle");
    let admin_id = s.query_string(
        "SELECT user_id FROM identities WHERE subject = $1",
        "admin-sub",
    );
    s.db.execute(&format!(
        "INSERT INTO admin_grants (user_id, role, managed_by, granted_at, granted_by) VALUES ('{admin_id}', 'admin', 'api', extract(epoch from now())::bigint, 'qualify')"
    ));
    let target_id = s.query_string(
        "SELECT user_id FROM identities WHERE subject = $1",
        "user-0",
    );
    let target_session = s.query_string("SELECT session_id FROM sessions WHERE user_id = $1 AND terminated_at IS NULL ORDER BY created_at LIMIT 1", &target_id);
    let race = |path: String| {
        let (aa, ab) = (
            s.a.admin.expect("admin listener"),
            s.b.admin.expect("admin listener"),
        );
        let (h1, h2, p1, p2) = (handle.clone(), handle.clone(), path.clone(), path);
        std::thread::scope(|scope| {
            let t1 = scope.spawn(|| s.console_post(aa, &h1, &p1));
            let t2 = scope.spawn(|| s.console_post(ab, &h2, &p2));
            [t1.join().unwrap(), t2.join().unwrap()]
        })
    };
    let ended = race(format!("/v1/sessions/{target_session}/terminate"));
    assert!(ended.iter().all(|r| r.status == 200), "{ended:?}");
    let changed = ended
        .iter()
        .filter(|r| r.json()["changed"] == json!(true))
        .count();
    assert_eq!(changed, 1, "one termination takes effect: {ended:?}");
    let disabled = race(format!("/v1/users/{target_id}/disable"));
    assert!(disabled.iter().all(|r| r.status == 200), "{disabled:?}");
    assert_eq!(s.db.query_i64(&format!("SELECT count(*) FROM events WHERE kind = 'admin.user_disable' AND user_id = '{target_id}'")), 1, "one status change");
    assert_eq!(s.db.query_i64(&format!("SELECT count(*) FROM events WHERE kind = 'session.terminated' AND session_id = '{target_session}'")), 1);
    // 4. A profile publication through A is enforced by B within the bound:
    //    once with the NOTIFY delivered, once with B's listener dropped so B
    //    learns it only from its poll.
    let (ga, gb) = (s.a.gateway, s.b.gateway);
    assert!(
        s.service_allowed(ga) && s.service_allowed(gb),
        "bootstrap profile on both"
    );
    let (aa, ab) = (s.a.admin.unwrap(), s.b.admin.unwrap());
    let path = "/v1/authentication/profiles";
    let put = |admin, revision, configuration: serde_json::Value| {
        let body = json!({ "configuration": configuration }).to_string();
        s.console_send("PUT", admin, &handle, path, Some(revision), body.as_bytes())
    };
    let r = put(aa, 1, serde_json::Value::Null);
    assert_eq!(r.status, 200, "{r:?}");
    let notified = s.converge(gb, false);
    assert!(
        notified < Duration::from_secs(2),
        "B followed in {notified:?}"
    );
    assert!(
        !s.service_allowed(ga),
        "A enforces its own publication at once"
    );
    s.db.execute("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name = 'hopae-listen'");
    assert_eq!(
        s.db.query_i64(
            "SELECT count(*) FROM pg_stat_activity WHERE application_name = 'hopae-listen'"
        ),
        0,
        "no replica listens: the next NOTIFY is missed"
    );
    let r = put(aa, 2, profiles());
    assert_eq!(r.status, 200, "{r:?}");
    let polled = s.converge(gb, true);
    assert!(
        polled < Duration::from_secs(2),
        "B followed by polling in {polled:?}"
    );
    assert!(s.service_allowed(ga));
    // B publishes on the revision it followed; a stale revision is refused on either.
    assert_eq!(put(ab, 1, serde_json::Value::Null).status, 409);
    let r = put(ab, 3, serde_json::Value::Null);
    assert_eq!(r.status, 200, "{r:?}");
    let back = s.converge(ga, false);
    assert!(back < Duration::from_secs(2), "A followed B in {back:?}");
    assert_eq!(put(aa, 3, profiles()).status, 409);
    let r = put(aa, 4, profiles());
    assert_eq!(r.status, 200, "{r:?}");
    s.converge(gb, true);
    assert_eq!(
        s.db.query_i64(
            "SELECT count(*) FROM meta WHERE key LIKE 'authentication_profile_publication_audit:%'"
        ),
        5,
        "bootstrap and four publications, each audited once"
    );

    // Projection plans: B can publish on top of A's publication only once it
    // followed it (until then its owner holds the old revision: 409).
    let projections = "/v1/authentication/projections";
    let put_plans = |admin, revision, configuration: serde_json::Value| {
        let body = json!({ "configuration": configuration }).to_string();
        s.console_send(
            "PUT",
            admin,
            &handle,
            projections,
            Some(revision),
            body.as_bytes(),
        )
    };
    // Retried while the publisher's replica has not followed yet (409).
    let followed = |admin, revision, configuration: serde_json::Value| {
        let start = std::time::Instant::now();
        loop {
            let r = put_plans(admin, revision, configuration.clone());
            if r.status != 409 || start.elapsed() >= Duration::from_secs(2) {
                return r;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    };
    let r = put_plans(aa, 1, serde_json::Value::Null);
    assert_eq!(r.status, 200, "{r:?}");
    let r = followed(ab, 2, plans(3));
    assert_eq!(r.status, 200, "B followed A's plans: {r:?}");
    let r = followed(aa, 3, serde_json::Value::Null);
    assert_eq!(r.status, 200, "A followed B's plans: {r:?}");

    // A revoked administrator is fenced out on either replica.
    s.db.execute(&format!("UPDATE admin_grants SET revoked_at = extract(epoch from now())::bigint, revoked_by = 'qualify' WHERE user_id = '{admin_id}'"));
    let other = s.query_string(
        "SELECT user_id FROM identities WHERE subject = $1",
        "user-1",
    );
    for admin in [s.a.admin.unwrap(), s.b.admin.unwrap()] {
        let r = s.console_post(admin, &handle, &format!("/v1/users/{other}/disable"));
        assert_ne!(r.status, 200, "revoked administrator: {r:?}");
    }
    assert_eq!(
        s.db.query_i64(&format!(
            "SELECT count(*) FROM users WHERE user_id = '{other}' AND status = 'active'"
        )),
        1
    );
    // Verify keeps working for everyone while one replica is killed.
    let stop = Arc::new(AtomicBool::new(false));
    let failures = Arc::new(AtomicUsize::new(0));
    let served = Arc::new(AtomicUsize::new(0));
    let mut load = Vec::new();
    for (sub, (app, _)) in people.iter().skip(1) {
        let (gw, key, cookie, app) = (s.gateway.addr, s.key.clone(), s.cookie.clone(), app.clone());
        let (stop, failures, served, sub) =
            (stop.clone(), failures.clone(), served.clone(), sub.clone());
        load.push(std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                let r = verify(gw, &key, &app, &cookie, "https://app.example.test/admin/x");
                if r.status == 200 {
                    served.fetch_add(1, Ordering::Relaxed);
                } else if r.status != 0 {
                    // A request cut by the kill reads as status 0 (connection reset).
                    failures.fetch_add(1, Ordering::Relaxed);
                    eprintln!("{sub}: {} {:?}", r.status, r.header("x-hopae-reason"));
                }
            }
        }));
    }
    std::thread::sleep(Duration::from_millis(800));
    s.b.kill();
    std::thread::sleep(Duration::from_millis(1200));
    stop.store(true, Ordering::Relaxed);
    for t in load {
        t.join().unwrap();
    }
    assert!(served.load(Ordering::Relaxed) > 20, "traffic was served");
    assert_eq!(
        failures.load(Ordering::Relaxed),
        0,
        "no request refused by a live replica"
    );
    // 4. Store invariants after the kill.
    assert_eq!(s.db.query_i64("SELECT count(*) FROM (SELECT subject FROM identities GROUP BY provider_id, subject HAVING count(*) > 1) d"), 0);
    assert_eq!(s.db.query_i64("SELECT count(*) FROM users u LEFT JOIN human_user_ids h ON h.user_id = u.user_id WHERE h.user_id IS NULL"), 0);
    assert_eq!(
        s.db.query_i64("SELECT count(*) - count(DISTINCT position) FROM human_user_ids"),
        0
    );
    assert_eq!(s.db.query_i64("SELECT count(*) FROM (SELECT event_id FROM events GROUP BY event_id HAVING count(*) > 1) d"), 0);
    assert_eq!(
        s.db.query_i64("SELECT count(*) FROM (SELECT sink, event_id FROM event_deliveries GROUP BY sink, event_id HAVING count(*) > 1) d"),
        0
    );
    // The survivor keeps signing people in.
    let _ = s.login("after-kill");
    assert_eq!(s.db.query_i64("SELECT count(*) FROM users"), 10);
    s.a.kill();
}
