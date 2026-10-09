//! S009 — cookie attributes and host scope (scenarios/009-cookie-attributes-and-host-scope.md).
//!
//! Cases that run a login through the real process need the verify engine
//! (W1-A), its adapter (W1-B), the session and identity services (W1-D) and
//! the portal wired to them; those are `#[ignore]`d until the orchestrator
//! has merged and wired W1. The portal's own cookie rules are also covered
//! in-process by `src/portal/{cookies,tests}.rs`. S009-A4 is a gateway-layer
//! case and belongs to W2-A.
#![allow(unused_imports, dead_code)]
use std::net::SocketAddr;

use crate::support::mock_idp::profiles::Profile;
use crate::support::*;

const APP: &str = "app.example.test";
const APP_URL: &str = "https://app.example.test/admin/x";
const NEEDS_STACK: &str = "needs W1-A, W1-B, W1-D and the portal wiring";

/// `path?query` of an absolute URL.
fn path_of(url: &str) -> String {
    let u = url::Url::parse(url).unwrap_or_else(|e| panic!("url {url}: {e}"));
    match u.query() {
        Some(q) => format!("{}?{q}", u.path()),
        None => u.path().to_string(),
    }
}

fn host_port(u: &url::Url) -> SocketAddr {
    format!("{}:{}", u.host_str().unwrap(), u.port().unwrap())
        .parse()
        .unwrap()
}

fn names(h: &Hopae) -> (String, String, String) {
    let base = h.config()["cookie"]["name"].as_str().unwrap().to_string();
    (
        base.clone(),
        format!("{base}_bind"),
        format!("{base}_portal"),
    )
}

fn secure(h: &Hopae) -> bool {
    h.config()["cookie"]["secure"].as_bool().unwrap_or(true)
}

/// Store every `set-cookie` of a response received from `host` into the jar.
fn absorb(jar: &Jar, host: &str, secure: bool, r: &Response) {
    for c in r.set_cookies() {
        jar.store(host, "/", secure, c);
    }
}

/// The gateway's verify call for a document navigation, presenting what the
/// jar holds for the application host.
fn verify_doc(h: &Hopae, jar: &Jar, host: &str, url: &str) -> Response {
    let (handle, bind, _) = names(h);
    let hj = jar.for_host(host);
    let mut req = VerifyRequest::document(url);
    for n in [handle, bind] {
        if let Some(v) = hj.value(&n) {
            req = req.cookie(&n, &v);
        }
    }
    let r = h.verify(req);
    absorb(jar, host, secure(h), &r);
    r
}

/// Drive the whole first login with the mock provider up to the portal's
/// redirect carrying the handoff code. Returns that redirect target.
fn login_to_handoff(h: &Hopae, jar: &Jar, app_url: &str) -> String {
    let host = url::Url::parse(app_url)
        .unwrap()
        .host_str()
        .unwrap()
        .to_string();
    let r = verify_doc(h, jar, &host, app_url);
    assert_eq!(r.status, 302, "{r:?}");
    let portal = h.portal_with(jar.clone());
    let r = portal.get(&path_of(r.location().expect("portal location")));
    assert_eq!(r.status, 302, "single provider redirects at once: {r:?}");
    let idp_url = url::Url::parse(r.location().unwrap()).unwrap();
    let to_idp = get(
        host_port(&idp_url),
        &format!("{}?{}", idp_url.path(), idp_url.query().unwrap_or("")),
    );
    assert_eq!(to_idp.status, 302, "{to_idp:?}");
    let back = portal.send(Req::get(&path_of(to_idp.location().unwrap())).cross_site_navigation());
    assert_eq!(back.status, 302, "{back:?}");
    back.location().unwrap().to_string()
}

fn spawn(fixture: &'static str) -> (Hopae, MockIdp) {
    let idp = MockIdp::start("default");
    let h = Hopae::spawn(Fixture::new(fixture), &idp, &[]);
    (h, idp)
}

fn attr_list(set_cookie: &str) -> (String, String, Vec<String>) {
    let mut parts = set_cookie.split("; ");
    let (name, value) = parts.next().unwrap().split_once('=').unwrap();
    (
        name.to_string(),
        value.to_string(),
        parts.map(str::to_string).collect(),
    )
}

fn assert_b64url_len(s: &str, n: usize) {
    assert_eq!(s.len(), n, "{s}");
    assert!(
        s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_'),
        "{s}"
    );
}

#[test]
#[ignore = "needs W1-A, W1-B, W1-D and the portal wiring"]
fn s009_1_session_cookie_attributes() {
    let (h, _idp) = spawn("m1-two-domains");
    let jar = Jar::new();
    let handoff = login_to_handoff(&h, &jar, APP_URL);
    let r = verify_doc(&h, &jar, APP, &handoff);
    assert_eq!(r.status, 302, "{r:?}");
    let cookies = r.set_cookies();
    assert_eq!(cookies.len(), 1, "{cookies:?}");
    let (name, value, attrs) = attr_list(cookies[0]);
    assert_eq!(name, "__Host-hopae");
    assert!(value.starts_with("v1."), "{value}");
    assert_b64url_len(&value[3..], 43);
    // The handle's own absolute lifetime (apps[].session.absolute = 7d), not the session's 30d.
    assert_eq!(
        attrs,
        vec![
            "Path=/",
            "Secure",
            "HttpOnly",
            "SameSite=Lax",
            "Max-Age=604800"
        ]
    );
}

#[test]
#[ignore = "needs W1-A, W1-B, W1-D and the portal wiring"]
fn s009_2_portal_binding_cookie_attributes() {
    let (h, _idp) = spawn("m1-basic");
    let jar = Jar::new();
    // First visit: no cookie yet.
    let r = verify_doc(&h, &jar, APP, APP_URL);
    let first_path = path_of(r.location().unwrap());
    let fresh = h.portal_with(Jar::new());
    let r1 = fresh.get(&first_path);
    let planted = r1
        .set_cookies()
        .into_iter()
        .find(|c| c.starts_with("__Host-hopae_portal="))
        .expect("portal cookie planted")
        .to_string();
    let (_, value, attrs) = attr_list(&planted);
    assert_b64url_len(&value, 22);
    assert_eq!(
        attrs,
        vec![
            "Path=/",
            "Secure",
            "HttpOnly",
            "SameSite=Lax",
            "Max-Age=600"
        ]
    );

    // Ten minutes later, a new transaction, the cookie still presented by the browser: same value, fresh Max-Age.
    h.hooks.advance(std::time::Duration::from_secs(600));
    let r = h.verify(VerifyRequest::document(APP_URL).ip("192.0.2.10"));
    let second_path = path_of(r.location().unwrap());
    let again = h
        .portal_with(Jar::new())
        .send(Req::get(&second_path).header("cookie", &format!("__Host-hopae_portal={value}")));
    let kept = again
        .set_cookies()
        .into_iter()
        .find(|c| c.starts_with("__Host-hopae_portal="))
        .expect("portal cookie refreshed");
    assert_eq!(kept, planted, "stable per browser, fresh Max-Age");

    // A malformed value is replaced.
    let r = h.verify(VerifyRequest::document(APP_URL).ip("192.0.2.10"));
    let third_path = path_of(r.location().unwrap());
    let replaced = h
        .portal_with(Jar::new())
        .send(Req::get(&third_path).header("cookie", "__Host-hopae_portal=too-short"));
    let rc = replaced
        .set_cookies()
        .into_iter()
        .find(|c| c.starts_with("__Host-hopae_portal="))
        .expect("replacement planted");
    let (_, nv, _) = attr_list(rc);
    assert_b64url_len(&nv, 22);
    assert_ne!(nv, "too-short");
}

#[test]
#[ignore = "needs W1-A, W1-B, W1-D and the portal wiring"]
fn s009_3_clearing_matches_attributes() {
    let (h, _idp) = spawn("m1-two-domains");
    let jar = Jar::new();
    let handoff = login_to_handoff(&h, &jar, APP_URL);
    let r = verify_doc(&h, &jar, APP, &handoff);
    assert_eq!(r.status, 302, "{r:?}");
    assert!(jar.for_host(APP).get("__Host-hopae").is_some());

    // Logout at the portal: the confirmation page carries the token.
    let portal = h.portal_with(jar.clone());
    let page = portal.get("/logout");
    assert_eq!(page.status, 200, "{page:?}");
    let marker = "name=\"csrf\" value=\"";
    let i = page.body.find(marker).expect("csrf field") + marker.len();
    let token = page.body[i..i + page.body[i..].find('"').unwrap()].to_string();
    let out = portal.send(
        Req::post("/logout")
            .header("origin", "https://auth.example.test")
            .form(&[("csrf", &token)]),
    );
    assert_eq!(out.status, 200, "{out:?}");
    assert!(
        out.set_cookies()
            .contains(&"__Host-hopae=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0")
    );
    assert!(
        jar.for_host("auth.example.test")
            .get("__Host-hopae")
            .is_none()
    );

    // The application host's stale handle is cleared the same way.
    let stale = verify_doc(&h, &jar, APP, APP_URL);
    assert_eq!(stale.status, 302, "{stale:?}");
    assert!(
        stale
            .set_cookies()
            .contains(&"__Host-hopae=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0")
    );
    assert!(jar.for_host(APP).get("__Host-hopae").is_none());
}

#[test]
fn s009_4_jar_isolation_across_hosts() {
    let jar = Jar::new();
    let attrs = "Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=600";
    for (host, value) in [
        ("auth.example.test", "v1.portal"),
        (APP, "v1.app"),
        ("other.example.org", "v1.other"),
    ] {
        assert!(jar.store(host, "/", true, &format!("__Host-hopae={value}; {attrs}")));
    }
    let nav = SendContext::navigation(true);
    for (host, value) in [
        ("auth.example.test", "v1.portal"),
        (APP, "v1.app"),
        ("other.example.org", "v1.other"),
    ] {
        assert_eq!(
            jar.header_for(host, "/", nav).as_deref(),
            Some(format!("__Host-hopae={value}").as_str()),
            "{host} carries exactly its own cookie"
        );
    }
    assert!(jar.rejected().is_empty());
}

#[test]
#[ignore = "needs W1-A, W1-B, W1-D and the portal wiring"]
fn s009_5_dev_mode_drops_prefix() {
    let (h, _idp) = spawn("m1-dev-insecure");
    let jar = Jar::new();
    let handoff = login_to_handoff(&h, &jar, "http://app.example.test/");
    let r = verify_doc(&h, &jar, APP, &handoff);
    assert_eq!(r.status, 302, "{r:?}");
    let cookies = r.set_cookies();
    assert_eq!(cookies.len(), 1, "{cookies:?}");
    let (name, _value, attrs) = attr_list(cookies[0]);
    assert_eq!(name, "hopae");
    assert_eq!(attrs.len(), 4, "{attrs:?}");
    assert_eq!(&attrs[..3], ["Path=/", "HttpOnly", "SameSite=Lax"]);
    assert!(attrs[3].starts_with("Max-Age="), "{attrs:?}");
    assert!(h.log().contains("insecure cookie mode"));
    let flagged = h
        .hooks
        .events(None, None)
        .iter()
        .any(|e| e["attrs"]["insecure_mode"] == serde_json::json!(true));
    assert!(flagged, "an events row carries insecure_mode=true");
}

#[test]
#[ignore = "needs W1-A, W1-B, W1-D and the portal wiring"]
fn s009_6_custom_cookie_name() {
    let idp = MockIdp::start("default");
    let h = Hopae::spawn(
        Fixture::with(
            "m1-two-domains",
            serde_json::json!({"cookie": {"name": "__Host-corp_sso"}}),
        ),
        &idp,
        &[],
    );
    let jar = Jar::new();
    let handoff = login_to_handoff(&h, &jar, APP_URL);
    let r = verify_doc(&h, &jar, APP, &handoff);
    let (name, _, _) = attr_list(r.set_cookies()[0]);
    assert_eq!(name, "__Host-corp_sso");
    assert!(jar.for_host(APP).get("__Host-corp_sso_bind").is_some());
    assert!(
        jar.for_host("auth.example.test")
            .get("__Host-corp_sso_portal")
            .is_some()
    );
    assert!(jar.for_host(APP).get("__Host-hopae_bind").is_none());

    // Preflight: a name without the prefix is refused while cookie.secure is true.
    let text = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/m1-basic.json"),
    )
    .unwrap();
    let mut v: serde_json::Value = serde_json::from_str(&text).unwrap();
    v["cookie"]["name"] = serde_json::json!("corp_sso");
    let cfg = hopae::config::parse(&v.to_string()).expect("parses");
    assert!(
        cfg.validate().is_err(),
        "name without __Host- must be rejected when secure"
    );
}

#[test]
#[ignore = "needs W1-A, W1-B, W1-D and the portal wiring"]
fn s009_7_binding_cookie_attributes() {
    let (h, _idp) = spawn("m1-basic");
    let jar = Jar::new();
    let attrs = [
        "Path=/",
        "Secure",
        "HttpOnly",
        "SameSite=Lax",
        "Max-Age=600",
    ];
    // 1. First unauthenticated navigation plants the binding cookie.
    let r = h.verify(VerifyRequest::document(APP_URL));
    assert_eq!(r.status, 302, "{r:?}");
    let c = r
        .set_cookies()
        .into_iter()
        .find(|c| c.starts_with("__Host-hopae_bind="))
        .expect("planted")
        .to_string();
    let (_, value, a) = attr_list(&c);
    assert_b64url_len(&value, 22);
    assert_eq!(a, attrs);
    // 2. A second navigation with the cookie re-sends the same value.
    let r2 = h.verify(VerifyRequest::document(APP_URL).cookie("__Host-hopae_bind", &value));
    assert!(
        r2.set_cookies().contains(&c.as_str()),
        "{:?}",
        r2.set_cookies()
    );
    // 3. A non-document request sets no binding cookie.
    let r3 = h.verify(VerifyRequest::other(APP_URL));
    assert_eq!(r3.status, 401);
    assert!(r3.set_cookies().is_empty());
    // 4. A malformed value is replaced.
    let r4 = h.verify(VerifyRequest::document(APP_URL).cookie("__Host-hopae_bind", "bad"));
    let rc = r4
        .set_cookies()
        .into_iter()
        .find(|c| c.starts_with("__Host-hopae_bind="))
        .expect("replaced")
        .to_string();
    assert_b64url_len(&attr_list(&rc).1, 22);
    // 5. The redemption carries no set-cookie for it; a failed redemption keeps it.
    let handoff = login_to_handoff(&h, &jar, APP_URL);
    let ok = verify_doc(&h, &jar, APP, &handoff);
    assert!(
        ok.set_cookies()
            .iter()
            .all(|c| !c.starts_with("__Host-hopae_bind=")),
        "{:?}",
        ok.set_cookies()
    );
    let bind = jar
        .for_host(APP)
        .value("__Host-hopae_bind")
        .expect("bind in jar");
    let replay = h.verify(VerifyRequest::document(&handoff).cookie("__Host-hopae_bind", &bind));
    assert_eq!(replay.status, 302, "{replay:?}");
    assert!(
        replay
            .set_cookies()
            .iter()
            .all(|c| !c.starts_with("__Host-hopae_bind=") || c.contains(&bind)),
        "the binding value is kept, never replaced: {:?}",
        replay.set_cookies()
    );
}

#[test]
#[ignore = "needs W1-A, W1-B, W1-D and the portal wiring"]
fn s009_a1_client_value_never_adopted() {
    let (h, _idp) = spawn("m1-two-domains");
    let jar = Jar::new();
    let attacker = format!("v1.{}", "A".repeat(43));
    jar.store(
        APP,
        "/",
        true,
        &format!("__Host-hopae={attacker}; Path=/; Secure; HttpOnly; SameSite=Lax"),
    );
    let handoff = login_to_handoff(&h, &jar, APP_URL);
    let r = verify_doc(&h, &jar, APP, &handoff);
    let (_, planted, _) = attr_list(r.set_cookies()[0]);
    assert_ne!(planted, attacker);
    // The attacker's value is the unknown-handle path, never a session.
    let probe = h.verify(VerifyRequest::document(APP_URL).cookie("__Host-hopae", &attacker));
    assert_eq!(probe.status, 302, "{probe:?}");
    assert_eq!(probe.header("x-hopae-reason"), Some("unknown_handle"));
}

#[test]
#[ignore = "needs W1-A, W1-B, W1-D and the portal wiring"]
fn s009_a2_many_cookies_bounded() {
    let (h, _idp) = spawn("m1-basic");
    let many = (0..200)
        .map(|i| format!("__Host-hopae=v1.{i:0>43}"))
        .collect::<Vec<_>>()
        .join("; ");
    let r = h.verify(VerifyRequest::document(APP_URL).header("cookie", &many));
    assert!(r.status == 302 || r.status == 401, "{r:?}");
    let calls_before = h.hooks.store_calls("lookup_handle");
    assert!(calls_before <= 1, "only the first pair is evaluated");
    let huge = format!("a={}", "x".repeat(9 * 1024));
    let r = h.verify(VerifyRequest::document(APP_URL).header("cookie", &huge));
    assert_eq!(r.status, 400, "{r:?}");
    assert_eq!(r.header("x-hopae-reason"), Some("header_too_large"));
}

#[test]
#[ignore = "needs W1-A, W1-B, W1-D and the portal wiring"]
fn s009_a3_sibling_cookie_tossing_ineffective() {
    let (h, _idp) = spawn("m1-two-domains");
    let jar = Jar::new();
    // A sibling host tries to set a domain cookie under both names.
    assert!(!jar.store(
        "evil.example.test",
        "/",
        true,
        "__Host-hopae=X; Domain=example.test; Path=/; Secure"
    ));
    assert!(jar.store(
        "evil.example.test",
        "/",
        true,
        "hopae=X; Domain=example.test; Path=/; Secure"
    ));
    assert!(jar.rejected().iter().any(|(n, _)| n == "__Host-hopae"));
    let header = jar
        .header_for(APP, "/", SendContext::navigation(true))
        .expect("hopae sent");
    assert_eq!(header, "hopae=X");
    // Secure mode reads only __Host-hopae: the tossed cookie is as good as absent.
    let r = h.verify(VerifyRequest::document(APP_URL).cookie("hopae", "X"));
    assert_eq!(r.status, 302, "{r:?}");
    assert_eq!(r.header("x-hopae-reason"), Some("login_required"));
}

#[test]
fn s009_a5_samesite_not_configurable() {
    let text = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/m1-basic.json"),
    )
    .unwrap();
    for value in ["none", "strict", "lax"] {
        let mut v: serde_json::Value = serde_json::from_str(&text).unwrap();
        v["cookie"]["same_site"] = serde_json::json!(value);
        let err =
            hopae::config::parse(&v.to_string()).expect_err("cookie.same_site must not exist");
        assert!(err.to_string().contains("same_site"), "{err}");
    }
    // Every cookie Hopae's portal writes carries SameSite=Lax, set or cleared, secure or not.
    use std::time::Duration;
    for secure in [true, false] {
        for c in [
            hopae::portal::cookies::set_cookie(
                "__Host-hopae_portal",
                "x",
                Duration::from_secs(600),
                secure,
            ),
            hopae::portal::cookies::set_cookie(
                "__Host-hopae",
                "x",
                Duration::from_secs(60),
                secure,
            ),
            hopae::portal::cookies::clear_cookie("__Host-hopae", secure),
        ] {
            assert!(c.contains("SameSite=Lax"), "{c}");
            assert!(
                !c.contains("SameSite=Strict") && !c.contains("SameSite=None"),
                "{c}"
            );
        }
    }
}
