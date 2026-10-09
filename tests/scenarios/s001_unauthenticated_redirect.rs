//! S001 — Unauthenticated request on a protected host is sent to the portal.
//!
//! The verify half (the adapter, W1-B) is exercised directly. Cases that need
//! the decision engine, the session service or the portal are `#[ignore]`d
//! until those work packages land; their bodies are complete.
#![allow(unused_imports)]

use std::time::Duration;

use serde_json::json;
use sha2::{Digest as _, Sha256};

use crate::support::client::{RawReq, Req, send};
use crate::support::*;

/// 2026-10-09T00:00:00Z in unix milliseconds.
const T0_MS: i64 = 1_791_504_000_000;
const BIND_ATTRS: &str = "; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=600";
const URL: &str = "https://app.example.test/admin/x?q=1";

fn spawn() -> (MockIdp, Hopae) {
    spawn_with(json!({}))
}

fn spawn_with(overrides: serde_json::Value) -> (MockIdp, Hopae) {
    let idp = MockIdp::start("default");
    let h = Hopae::spawn(
        Fixture::with("m1-basic", overrides),
        &idp,
        &[("HOPAE_TEST_SEED", "1")],
    );
    h.set_clock_ms(T0_MS);
    (idp, h)
}

/// Two enabled providers, so the portal shows the chooser instead of redirecting.
fn two_providers(idp: &MockIdp) -> serde_json::Value {
    json!({"providers": [{
        "provider_id": "mock2", "kind": "oidc", "display_name": "Mock Two",
        "client_id": idp.client_id, "client_secret_env": "HOPAE_TEST_MOCK_SECRET",
        "issuer": idp.issuer.as_str().trim_end_matches('/'),
        "scope": "openid email profile", "auto_link": false
    }]})
}

fn sha(s: &str) -> Vec<u8> {
    Sha256::digest(s.as_bytes()).to_vec()
}

fn db(h: &Hopae) -> rusqlite::Connection {
    let path = h.state_dir.path().join("state").join("hopae.db");
    let c = rusqlite::Connection::open(path).expect("open the store");
    c.busy_timeout(Duration::from_secs(5))
        .expect("busy timeout");
    c
}

fn txn_count(h: &Hopae) -> i64 {
    db(h)
        .query_row("SELECT count(*) FROM login_txns", [], |r| r.get(0))
        .expect("count transactions")
}

/// The transaction id in `location: https://auth.example.test/login?txn=<id>`.
fn txn_of(r: &Response) -> String {
    let loc = r.location().expect("location");
    let u = url::Url::parse(loc).expect("location url");
    assert_eq!(u.path(), "/login", "{loc}");
    u.query_pairs()
        .find(|(k, _)| k == "txn")
        .map(|(_, v)| v.into_owned())
        .expect("txn parameter")
}

fn cookie_value(r: &Response, name: &str) -> Option<String> {
    r.set_cookies().iter().find_map(|c| {
        c.strip_prefix(&format!("{name}="))
            .map(|rest| rest.split(';').next().unwrap_or("").to_string())
    })
}

/// A document navigation from `203.0.113.9` with `UA1`, as in S001-1.
fn start(h: &Hopae) -> (String, Response) {
    let r = h.verify(VerifyRequest::document(URL).ip("203.0.113.9").ua("UA1"));
    assert_eq!(r.status, 302, "{r:?}");
    (txn_of(&r), r)
}

fn portal_at(h: &Hopae, ip: &str) -> Client {
    h.portal().with_ip(ip)
}

fn wait_for_event(h: &Hopae, kind: &str, reason: &str) -> Option<serde_json::Value> {
    for _ in 0..40 {
        if let Some(e) = h
            .hooks
            .events(Some(kind), None)
            .into_iter()
            .find(|e| e["reason"] == reason)
        {
            return Some(e);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    None
}

// ---- main flow -------------------------------------------------------------

#[test]
fn s001_1_document_navigation_redirects_to_portal() {
    let (_idp, h) = spawn();
    let r = h.verify(VerifyRequest::document(URL).ip("203.0.113.9").ua("UA1"));
    assert_eq!(r.status, 302, "{r:?}");
    let txn = txn_of(&r);
    assert_eq!(
        r.location(),
        Some(format!("https://auth.example.test/login?txn={txn}").as_str())
    );
    let cookies = r.set_cookies();
    assert_eq!(cookies.len(), 1, "{r:?}");
    let bind = cookie_value(&r, "__Host-hopae_bind").expect("binding cookie");
    assert_eq!(bind.len(), 22, "16 random bytes, base64url");
    assert_eq!(cookies[0], format!("__Host-hopae_bind={bind}{BIND_ATTRS}"));
    assert_eq!(r.header("cache-control"), Some("no-store"));
    assert_eq!(r.header("x-hopae-reason"), Some("login_required"));

    let c = db(&h);
    let row = c
        .query_row(
            "SELECT return_target, app_id, client_ip, ua_sha256, bind_sha256, created_at, expires_at \
             FROM login_txns WHERE txn_sha256 = ?1",
            [sha(&txn)],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, Vec<u8>>(3)?,
                    r.get::<_, Vec<u8>>(4)?,
                    r.get::<_, i64>(5)?,
                    r.get::<_, i64>(6)?,
                ))
            },
        )
        .expect("the transaction row");
    assert_eq!(row.0, URL);
    assert_eq!(row.1, "app");
    assert_eq!(row.2, "203.0.113.9");
    assert_eq!(row.3, sha("UA1"));
    assert_eq!(row.4, sha(&bind));
    assert_eq!(row.5, T0_MS / 1000);
    assert_eq!(row.6, T0_MS / 1000 + 600);
    assert_eq!(txn_count(&h), 1);
    let started = h.hooks.events(Some("login.started"), None);
    assert_eq!(started.len(), 1, "{started:?}");
}

#[test]
fn s001_2_portal_renders_chooser_and_sets_txn_cookie() {
    let idp = MockIdp::start("default");
    let (_idp2, h) = {
        let h = Hopae::spawn(
            Fixture::with("m1-basic", two_providers(&idp)),
            &idp,
            &[("HOPAE_TEST_SEED", "1")],
        );
        h.set_clock_ms(T0_MS);
        (idp.clone(), h)
    };
    let (txn, _) = start(&h);
    let portal = portal_at(&h, "203.0.113.9");
    let r = portal.send(Req::get(&format!("/login?txn={txn}")).header("user-agent", "UA1"));
    assert_eq!(r.status, 200, "{r:?}");
    assert!(
        r.header("content-type")
            .unwrap_or("")
            .starts_with("text/html"),
        "{r:?}"
    );
    assert!(r.body.contains("Mock"), "the enabled providers are listed");
    let p = cookie_value(&r, "__Host-hopae_portal").expect("portal binding cookie");
    assert_eq!(p.len(), 22);
    assert_eq!(
        r.set_cookies(),
        vec![format!("__Host-hopae_portal={p}{BIND_ATTRS}").as_str()]
    );
    let digest: Option<Vec<u8>> = db(&h)
        .query_row(
            "SELECT portal_bind_sha256 FROM login_txns WHERE txn_sha256 = ?1",
            [sha(&txn)],
            |r| r.get(0),
        )
        .expect("row");
    // S001-2 (corrected, R-4): the digest is recorded only when the provider
    // redirect is issued, never at the chooser GET.
    assert_eq!(digest, None, "not recorded by the chooser page");
    assert_eq!(r.header("cache-control"), Some("no-store"));
    assert_eq!(r.header("x-content-type-options"), Some("nosniff"));
    assert_eq!(r.header("referrer-policy"), Some("same-origin"));
    let csp = r.header("content-security-policy").expect("csp");
    assert!(!csp.contains("unsafe-inline"), "{csp}");
}

#[test]
fn s001_3_single_provider_redirects_immediately() {
    let (idp, h) = spawn();
    let (txn, _) = start(&h);
    let portal = portal_at(&h, "203.0.113.9");
    let r = portal.send(Req::get(&format!("/login?txn={txn}")).header("user-agent", "UA1"));
    assert_eq!(r.status, 302, "{r:?}");
    let loc = url::Url::parse(r.location().expect("location")).expect("url");
    assert_eq!(loc.path(), idp.endpoint("/authorize").path());
    let q: std::collections::HashMap<String, String> = loc
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    for k in ["state", "nonce", "code_challenge"] {
        assert!(q.get(k).is_some_and(|v| !v.is_empty()), "{k} missing");
    }
    assert_eq!(q["code_challenge_method"], "S256");
    assert_eq!(q["redirect_uri"], "https://auth.example.test/callback/mock");
    assert!(
        cookie_value(&r, "__Host-hopae_portal").is_some(),
        "the portal binding cookie is set on the same response"
    );
}

// ---- alternative flows -------------------------------------------------------

#[test]
fn s001_4_non_document_request_gets_401_json() {
    let (_idp, h) = spawn();
    let before = txn_count(&h);
    let r = h.verify(VerifyRequest::other(URL).ip("203.0.113.9").ua("UA1"));
    assert_eq!(r.status, 401, "{r:?}");
    assert_eq!(r.header("content-type"), Some("application/json"));
    assert_eq!(
        r.json(),
        json!({"error": "login_required", "login": "https://app.example.test/admin/x?q=1"})
    );
    assert_eq!(
        r.header("www-authenticate"),
        Some("Hopae realm=\"auth.example.test\"")
    );
    assert_eq!(r.header("cache-control"), Some("no-store"));
    assert!(r.set_cookies().is_empty(), "no set-cookie");
    assert_eq!(txn_count(&h), before, "no transaction row is created");
    // The document navigation to that URL behaves exactly as S001-1.
    let (_, doc) = start(&h);
    assert_eq!(doc.header("x-hopae-reason"), Some("login_required"));
    assert_eq!(txn_count(&h), before + 1);
}

/// S001-5, unit part: the adapter classifies the request. The wire outcome
/// (302 versus 401) follows from the classification in S001-1 and S001-4.
#[test]
fn s001_5_accept_header_fallback() {
    use axum::http::{HeaderMap, HeaderName, HeaderValue};
    use hopae::gateway::hangang::{GatewayConfig, parse};
    use hopae::verify::types::Navigation;

    let mut cfg_json = serde_json::from_str::<serde_json::Value>(
        &std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/m1-basic.json"),
        )
        .expect("fixture"),
    )
    .expect("fixture json");
    cfg_json["state_dir"] = json!("/tmp/hopae-s001-5");
    let cfg = hopae::config::parse(&cfg_json.to_string()).expect("configuration");
    let gw = GatewayConfig::from_config(&cfg);

    let nav = |extra: &[(&str, &str)]| {
        let mut h = HeaderMap::new();
        for (k, v) in [
            ("x-hopae-gateway-key", "k"),
            ("x-original-url", URL),
            ("x-forwarded-host", "app.example.test"),
            ("x-forwarded-proto", "https"),
            ("x-forwarded-for", "203.0.113.9"),
        ]
        .iter()
        .chain(extra.iter())
        {
            h.append(
                HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        // The caller key is checked by `authenticate` before `parse`; this test is about navigation.
        let caller = hopae::verify::types::CallerAuth::Keyed {
            which: hopae::verify::types::KeySlot::Current,
        };
        match parse(&gw, &h, "r".into(), caller) {
            Ok(p) => matches!(p.input.navigation, Navigation::Document),
            Err(_) => panic!("the request must parse"),
        }
    };
    // No fetch metadata: accept decides.
    assert!(nav(&[("accept", "text/html,application/xhtml+xml")]));
    assert!(!nav(&[("accept", "*/*")]));
    assert!(!nav(&[]));
    // Fetch metadata wins when present.
    assert!(nav(&[("sec-fetch-dest", "document")]));
    assert!(!nav(&[
        ("sec-fetch-dest", "empty"),
        ("sec-fetch-mode", "cors"),
        ("accept", "application/json")
    ]));
}

#[test]
fn s001_6_unregistered_host_denied() {
    let (_idp, h) = spawn();
    let r = h.verify(VerifyRequest::document("https://unknown.example.test/").ip("203.0.113.9"));
    assert_eq!(r.status, 403, "{r:?}");
    assert_eq!(r.header("x-hopae-reason"), Some("unknown_app"));
    assert!(r.set_cookies().is_empty());
    assert_eq!(txn_count(&h), 0);
    // `verify.denied` is sampled (S014-2): the held event is written when the
    // 60 s window closes.
    h.advance(Duration::from_secs(61));
    let e = wait_for_event(&h, "verify.denied", "unknown_app");
    assert!(e.is_some(), "verify.denied with reason unknown_app");
}

// ---- abuse cases ---------------------------------------------------------------

#[test]
fn s001_a1_expired_or_consumed_txn_rejected() {
    let (_idp, h) = spawn();
    // Expired.
    let (txn, _) = start(&h);
    h.advance(Duration::from_secs(601));
    let portal = portal_at(&h, "203.0.113.9");
    let r = portal.send(Req::get(&format!("/login?txn={txn}")).header("user-agent", "UA1"));
    assert_eq!(r.status, 400, "{r:?}");
    assert!(r.set_cookies().is_empty(), "no cookie");
    assert!(wait_for_event(&h, "login.failed", "txn_expired").is_some());
    // Consumed.
    let (txn2, _) = start(&h);
    db(&h)
        .execute(
            "UPDATE login_txns SET consumed_at = ?1, consumed_reason = 'test' WHERE txn_sha256 = ?2",
            rusqlite::params![h.hooks.now_ms() / 1000, sha(&txn2)],
        )
        .expect("consume");
    let before = txn_count(&h);
    let r = portal.send(Req::get(&format!("/login?txn={txn2}")).header("user-agent", "UA1"));
    assert_eq!(r.status, 400, "{r:?}");
    assert!(r.set_cookies().is_empty());
    assert_eq!(txn_count(&h), before, "no new transaction");
    assert!(wait_for_event(&h, "login.failed", "txn_consumed").is_some());
}

#[test]
fn s001_a2_client_return_target_ignored() {
    let idp = MockIdp::start("default");
    let h = Hopae::spawn(
        Fixture::with("m1-basic", two_providers(&idp)),
        &idp,
        &[("HOPAE_TEST_SEED", "1")],
    );
    h.set_clock_ms(T0_MS);
    let (txn, _) = start(&h);
    let portal = portal_at(&h, "203.0.113.9");
    let r = portal.send(
        Req::get(&format!(
            "/login?txn={txn}&return=https://evil.example.org/"
        ))
        .header("user-agent", "UA1"),
    );
    assert_eq!(r.status, 200, "unknown parameters are ignored: {r:?}");
    assert!(r.location().is_none());
    let target: String = db(&h)
        .query_row(
            "SELECT return_target FROM login_txns WHERE txn_sha256 = ?1",
            [sha(&txn)],
            |r| r.get(0),
        )
        .expect("row");
    assert_eq!(target, URL, "the stored return target is unchanged");
    // Without `txn` there is nothing to continue: 400, no redirect.
    let r = portal.get("/login?rd=https://evil.example.org/");
    assert_eq!(r.status, 400, "{r:?}");
    assert!(r.location().is_none());
}

#[test]
fn s001_a3_txn_bound_to_client() {
    let (_idp, h) = spawn();
    // A different client address.
    let (txn, _) = start(&h);
    let other = portal_at(&h, "198.51.100.7");
    let r = other.send(Req::get(&format!("/login?txn={txn}")).header("user-agent", "UA1"));
    assert_eq!(r.status, 400, "{r:?}");
    assert!(r.set_cookies().is_empty(), "no new cookie");
    assert!(wait_for_event(&h, "login.failed", "txn_binding").is_some());
    let consumed: Option<i64> = db(&h)
        .query_row(
            "SELECT consumed_at FROM login_txns WHERE txn_sha256 = ?1",
            [sha(&txn)],
            |r| r.get(0),
        )
        .expect("row");
    assert!(
        consumed.is_some(),
        "the original client must restart as well"
    );

    // Same address, but a different browser (another portal cookie).
    let (txn2, _) = start(&h);
    let first = portal_at(&h, "203.0.113.9");
    let r = first.send(Req::get(&format!("/login?txn={txn2}")).header("user-agent", "UA1"));
    assert!(matches!(r.status, 200 | 302), "{r:?}");
    let second = portal_at(&h, "203.0.113.9"); // a fresh jar: no portal cookie
    let r = second.send(Req::get(&format!("/login?txn={txn2}")).header("user-agent", "UA1"));
    assert_eq!(r.status, 400, "{r:?}");
    assert!(r.set_cookies().is_empty());
    assert!(wait_for_event(&h, "login.failed", "portal_bind_mismatch").is_some());
}

#[test]
fn s001_a4_txn_flood_bounded() {
    let (_idp, h) = spawn();
    // 30 per minute from one address, the 31st is refused.
    for i in 0..30 {
        let r = h.verify(VerifyRequest::document(URL).ip("203.0.113.50"));
        assert_eq!(r.status, 302, "request {i}: {r:?}");
    }
    let r = h.verify(VerifyRequest::document(URL).ip("203.0.113.50"));
    assert_eq!(r.status, 403, "{r:?}");
    assert_eq!(r.header("x-hopae-reason"), Some("txn_rate_limited"));
    assert_eq!(
        r.json(),
        json!({"error": "rate_limited", "retry_after": 60})
    );
    // Non-document calls create nothing and are not counted.
    let r = h.verify(VerifyRequest::other(URL).ip("203.0.113.50"));
    assert_eq!(r.status, 401, "{r:?}");
    // 2,000 more from distinct addresses: the table stays bounded.
    for n in 0..2000u32 {
        let ip = format!("198.18.{}.{}", n / 250, n % 250 + 1);
        let r = h.verify(VerifyRequest::document(URL).ip(&ip));
        assert_eq!(r.status, 302, "{ip}: {r:?}");
    }
    assert!(txn_count(&h) <= 1000, "max_rows bounds the table");
    // Wait for the best-effort diagnostic writer, then read every row (the default page is 100).
    std::thread::sleep(Duration::from_millis(500));
    let evicted = h.hooks.events(Some("txn.evicted"), Some(5000));
    assert!(!evicted.is_empty(), "eviction is reported");
    let total: i64 = evicted
        .iter()
        .map(|e| e["attrs"]["count"].as_i64().unwrap_or(0))
        .sum();
    assert!(total >= 1000, "txn.evicted events carry the count: {total}");
    // "The harness limit" of S001-A4 (R-2): the resident set stays under 200 MiB.
    let rss = h.rss_kib().expect("read VmRSS of the child");
    assert!(rss < 200 * 1024, "RSS {rss} KiB exceeds 200 MiB");
}

#[test]
fn s001_a5_verify_not_served_on_portal_listener() {
    let (_idp, h) = spawn();
    let mut req = RawReq::new("GET", "/_hopae/verify", "app.example.test");
    for (k, v) in [
        (
            "x-hopae-gateway-key",
            h.env_value("HOPAE_TEST_GATEWAY_KEY").unwrap().to_string(),
        ),
        ("x-original-url", URL.to_string()),
        ("x-forwarded-host", "app.example.test".to_string()),
        ("x-forwarded-proto", "https".to_string()),
        ("x-forwarded-for", "203.0.113.9".to_string()),
        ("sec-fetch-dest", "document".to_string()),
    ] {
        req = req.header(k, &v);
    }
    let r = send(h.portal, req);
    assert_eq!(r.status, 404, "{r:?}");
    assert!(r.set_cookies().is_empty());
    assert!(r.location().is_none());
    assert_eq!(txn_count(&h), 0, "no transaction row");
    assert!(
        h.hooks.events(Some("verify.denied"), None).is_empty(),
        "a plain 404 emits no verify.denied (wrong_listener)"
    );
}

#[test]
fn s001_a6_untrusted_forwarded_for_ignored() {
    // The harness peer is 127.0.0.1; trusting only 10.0.0.0/8 makes it untrusted.
    let (_idp, h) = spawn_with(json!({"trusted_proxies": ["10.0.0.0/8"]}));
    let (txn, _) = start(&h);
    let client = h.portal().with_ip("203.0.113.9");
    let r = client.send(Req::get(&format!("/login?txn={txn}")).header("user-agent", "UA1"));
    assert_eq!(
        r.status, 400,
        "the binding check fails on the peer address: {r:?}"
    );
    let failed = wait_for_event(&h, "login.failed", "txn_binding").expect("login.failed");
    assert_eq!(failed["client_ip"], "127.0.0.1", "the peer address is used");
    assert!(
        !failed.to_string().contains("203.0.113.9"),
        "the header value never appears in the failure event"
    );
}

#[test]
fn s001_a7_plain_http_refused() {
    let (_idp, h) = spawn();
    let r = h.verify(VerifyRequest::document("http://app.example.test/").ip("203.0.113.9"));
    assert_eq!(r.status, 400, "{r:?}");
    assert_eq!(r.header("x-hopae-reason"), Some("insecure_transport"));
    assert!(r.set_cookies().is_empty());
    assert_eq!(txn_count(&h), 0, "no transaction");
}
