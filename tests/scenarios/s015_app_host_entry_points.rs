//! Scenario 015: application-host entry points (`/_hopae/login`,
//! `/_hopae/logout`) are answered by Hopae inside the verify call and never
//! reach the upstream; with gateway change HC-12 the upstream never sees the
//! Hopae cookies.
//!
//! The Hopae-level cases drive a spawned Hopae the way a gateway and a
//! browser would. The gateway-level cases (015-9 to 015-11) are in
//! `gateway_layer` and run through the real gateway binary (`make e2e`).
//!
//! ORCHESTRATOR OVERRIDE (ADR-0015): after a confirmed logout the portal does
//! not redirect to the protected return target (a provider with a live
//! session would sign the user straight back in). It renders its signed-out
//! page with a "Sign in again to <application>" link to the validated target;
//! the direct mode answers `302` to the portal's `/signed-out?txn=<consumed
//! logout ticket>` page.
#![allow(dead_code, unused_imports)]

use std::time::Duration;

use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

use crate::support::client::{RawReq, Req, send};
use crate::support::*;

const APP: &str = "app.example.test";
const PORTAL: &str = "auth.example.test";
const PORTAL_URL: &str = "https://auth.example.test";
const IP: &str = "203.0.113.9";
const HANDLE: &str = "__Host-hopae";
const BIND: &str = "__Host-hopae_bind";
const PORTAL_COOKIE: &str = "__Host-hopae_portal";

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

fn count(h: &Hopae, sql: &str) -> i64 {
    db(h).query_row(sql, [], |r| r.get(0)).expect("count")
}

fn txn_count(h: &Hopae) -> i64 {
    count(h, "SELECT count(*) FROM login_txns")
}

fn cookie_value(r: &Response, name: &str) -> Option<String> {
    r.set_cookies().iter().find_map(|c| {
        c.strip_prefix(&format!("{name}="))
            .map(|rest| rest.split(';').next().unwrap_or("").to_string())
    })
}

fn txn_of(r: &Response, page: &str) -> String {
    let loc = r.location().expect("location");
    let u = url::Url::parse(loc).expect("location url");
    assert_eq!(u.host_str(), Some(PORTAL), "{loc}");
    assert_eq!(u.path(), page, "{loc}");
    u.query_pairs()
        .find(|(k, _)| k == "txn")
        .map(|(_, v)| v.into_owned())
        .expect("txn parameter")
}

fn csrf_of(body: &str) -> String {
    body.split("name=\"csrf\" value=\"")
        .nth(1)
        .and_then(|r| r.split('"').next())
        .expect("csrf field")
        .to_string()
}

/// The stored ticket / transaction.
#[derive(Debug)]
struct Row {
    purpose: String,
    return_target: String,
    app_id: String,
    portal_session_id: Option<String>,
    client_ip: String,
    bind: Option<Vec<u8>>,
    portal_bind: Option<Vec<u8>>,
    created_at: i64,
    expires_at: i64,
    consumed_at: Option<i64>,
    consumed_reason: Option<String>,
}

fn row(h: &Hopae, txn: &str) -> Row {
    db(h)
        .query_row(
            "SELECT purpose, return_target, app_id, portal_session_id, client_ip, bind_sha256, portal_bind_sha256, created_at, expires_at, consumed_at, consumed_reason FROM login_txns WHERE txn_sha256 = ?1",
            [sha(txn)],
            |r| {
                Ok(Row {
                    purpose: r.get(0)?,
                    return_target: r.get(1)?,
                    app_id: r.get(2)?,
                    portal_session_id: r.get(3)?,
                    client_ip: r.get(4)?,
                    bind: r.get(5)?,
                    portal_bind: r.get(6)?,
                    created_at: r.get(7)?,
                    expires_at: r.get(8)?,
                    consumed_at: r.get(9)?,
                    consumed_reason: r.get(10)?,
                })
            },
        )
        .expect("the transaction row")
}

fn session_id(h: &Hopae) -> String {
    db(h)
        .query_row("SELECT session_id FROM sessions LIMIT 1", [], |r| r.get(0))
        .expect("the session")
}

fn terminated(h: &Hopae, sid: &str) -> Option<String> {
    db(h)
        .query_row(
            "SELECT terminated_reason FROM sessions WHERE session_id = ?1 AND terminated_at IS NOT NULL",
            [sid],
            |r| r.get(0),
        )
        .ok()
}

fn events(h: &Hopae, kind: &str) -> Vec<Value> {
    h.hooks.events(Some(kind), Some(5000))
}

/// Wait for the sampled `verify.denied` diagnostic with `reason` (S014-2: the
/// held event is written when the 60 s window closes).
fn wait_denied(h: &Hopae, reason: &str) -> bool {
    h.hooks.advance(Duration::from_secs(61));
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        if events(h, "verify.denied")
            .iter()
            .any(|e| e["reason"] == reason)
        {
            return true;
        }
        if std::time::Instant::now() > deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn total_events(h: &Hopae) -> usize {
    h.hooks.events(None, Some(5000)).len()
}

/// A verify call for an entry point as a browser navigation would make it.
fn entry(path_and_query: &str, site: Option<&str>) -> VerifyRequest {
    let mut r = VerifyRequest::document(&format!("https://{APP}{path_and_query}")).ip(IP);
    if let Some(s) = site {
        r = r.header("sec-fetch-site", s);
    }
    r
}

fn with_cookies(r: VerifyRequest, s: &Signed) -> VerifyRequest {
    r.cookie(HANDLE, &s.h1).cookie(BIND, &s.b1)
}

/// What a signed-in browser holds.
struct Signed {
    /// Cookies for the portal host (`H0` and `P1`).
    jar: Jar,
    h1: String,
    b1: String,
    ip: String,
    /// The handoff `location` of the login.
    handoff: String,
    /// Where the redemption sent the browser (the clean target).
    landed: String,
}

impl Signed {
    fn portal(&self, h: &Hopae) -> Client {
        h.portal_with(self.jar.clone()).with_ip(&self.ip)
    }

    fn p1(&self) -> String {
        self.jar
            .for_host(PORTAL)
            .value(PORTAL_COOKIE)
            .expect("portal binding cookie")
    }

    fn h0(&self) -> String {
        self.jar
            .for_host(PORTAL)
            .value(HANDLE)
            .expect("portal handle")
    }
}

/// Sign in from `start_url` (a verify of it starts the login) and redeem the
/// handoff, the way scenario 003 does. `ip` is the browser's address.
fn sign_in_at(h: &Hopae, idp: &MockIdp, start_url: &str, ip: &str) -> Signed {
    let first = h.verify(
        VerifyRequest::document(start_url)
            .ip(ip)
            .header("sec-fetch-site", "same-origin"),
    );
    assert_eq!(first.status, 302, "{first:?}");
    let b1 = cookie_value(&first, BIND).expect("binding cookie");
    let login_url = first.location().expect("login redirect").to_string();
    let path = login_url
        .split(PORTAL)
        .nth(1)
        .expect("portal path")
        .to_string();
    let jar = Jar::new();
    let c = h.portal_with(jar.clone()).with_ip(ip);
    let page = c.get(&path);
    let authorize = if page.status == 302 {
        page.location().expect("provider redirect").to_string()
    } else {
        let csrf = csrf_of(&page.body);
        let txn = path.split("txn=").nth(1).expect("txn").to_string();
        let r = c.post_form("/login/mock", &[("csrf", &csrf), ("txn", &txn)]);
        assert_eq!(r.status, 302);
        r.location().expect("provider redirect").to_string()
    };
    let cb = c.get(&idp.follow_authorization(&authorize));
    assert_eq!(cb.status, 302, "{cb:?}");
    let handoff = cb.location().expect("handoff redirect").to_string();
    let redeem = h.verify(
        VerifyRequest::document(&handoff)
            .ip(ip)
            .cookie(BIND, &b1)
            .header("sec-fetch-site", "cross-site"),
    );
    assert_eq!(redeem.status, 302, "{redeem:?}");
    let h1 = cookie_value(&redeem, HANDLE).expect("application handle");
    let landed = redeem.location().expect("clean target").to_string();
    Signed {
        jar,
        h1,
        b1,
        ip: ip.to_string(),
        handoff,
        landed,
    }
}

fn sign_in(h: &Hopae, idp: &MockIdp) -> Signed {
    sign_in_at(h, idp, &format!("https://{APP}/admin/x"), IP)
}

fn spawn(fixture: &'static str) -> (MockIdp, Hopae) {
    spawn_with(fixture, json!({}))
}

fn spawn_with(fixture: &'static str, overrides: Value) -> (MockIdp, Hopae) {
    let idp = MockIdp::start("default");
    let h = Hopae::spawn(
        Fixture::with(fixture, overrides),
        &idp,
        &[("HOPAE_TEST_SEED", "1")],
    );
    (idp, h)
}

/// `POST /logout` as the confirmation page's form does.
fn confirm(c: &Client, csrf: &str, txn: Option<&str>) -> Response {
    let mut fields = vec![("csrf", csrf)];
    if let Some(t) = txn {
        fields.push(("txn", t));
    }
    c.send(
        Req::post("/logout")
            .form(&fields)
            .header("origin", PORTAL_URL),
    )
}

/// `href="…"` values of a page, HTML-unescaped for the characters that matter.
fn links(body: &str) -> Vec<String> {
    body.split("href=\"")
        .skip(1)
        .filter_map(|r| r.split('"').next())
        .map(|s| s.replace("&amp;", "&"))
        .collect()
}

// ---------------------------------------------------------------------------
// Main flow
// ---------------------------------------------------------------------------

#[test]
fn s015_1_logout_entry_creates_ticket_and_redirects() {
    let (idp, h) = spawn("m1-two-domains");
    let s = sign_in(&h, &idp);
    let sid = session_id(&h);
    let before = total_events(&h);
    let r = h.verify(with_cookies(
        entry("/_hopae/logout", Some("same-origin")),
        &s,
    ));
    assert_eq!(r.status, 302, "{r:?}");
    let t1 = txn_of(&r, "/logout");
    assert_eq!(
        r.location(),
        Some(format!("{PORTAL_URL}/logout?txn={t1}").as_str())
    );
    assert!(r.set_cookies().is_empty(), "nothing is cleared: {r:?}");
    assert_eq!(r.header("cache-control"), Some("no-store"));
    assert_eq!(r.header("x-hopae-reason"), Some("logout_entry"));
    let t = row(&h, &t1);
    assert_eq!(t.purpose, "logout");
    assert_eq!(t.return_target, format!("https://{APP}/"));
    assert_eq!(t.app_id, "app");
    assert_eq!(t.portal_session_id.as_deref(), Some(sid.as_str()));
    assert_eq!(t.client_ip, IP);
    assert_eq!(t.bind, Some(sha(&s.b1)));
    assert_eq!(t.portal_bind, None);
    assert_eq!(t.expires_at - t.created_at, 600);
    assert_eq!(t.consumed_at, None);
    assert_eq!(terminated(&h, &sid), None, "nothing is revoked");
    assert_eq!(total_events(&h), before, "no event");
    // H1 is still valid.
    let ok = h.verify(with_cookies(entry("/", None), &s));
    assert_eq!(ok.status, 200, "{ok:?}");
}

#[test]
fn s015_2_confirmation_page_with_ticket() {
    let (idp, h) = spawn("m1-two-domains");
    let s = sign_in(&h, &idp);
    let r = h.verify(with_cookies(
        entry("/_hopae/logout", Some("same-origin")),
        &s,
    ));
    let t1 = txn_of(&r, "/logout");
    let c = s.portal(&h);
    let page = c.get(&format!("/logout?txn={t1}"));
    assert_eq!(page.status, 200, "{page:?}");
    assert!(
        page.body.contains(&format!("name=\"txn\" value=\"{t1}\"")),
        "hidden ticket field: {}",
        page.body
    );
    assert!(page.body.contains("csrf"), "csrf token");
    assert!(page.body.contains("app"), "names the application");
    assert_eq!(page.header("cache-control"), Some("no-store"));
    assert_eq!(row(&h, &t1).portal_bind, Some(sha(&s.p1())));
    assert_eq!(row(&h, &t1).consumed_at, None, "no other state change");
    assert_eq!(terminated(&h, &session_id(&h)), None);
    // The binding is immutable: another browser cannot re-bind it.
    // Without a portal cookie the response plants one and records its digest.
    let r2 = h.verify(with_cookies(
        entry("/_hopae/logout", Some("same-origin")),
        &s,
    ));
    let t2 = txn_of(&r2, "/logout");
    let fresh = h.portal_with(Jar::new()).with_ip(IP);
    let page2 = fresh.get(&format!("/logout?txn={t2}"));
    assert_eq!(page2.status, 200, "{page2:?}");
    let planted = cookie_value(&page2, PORTAL_COOKIE).expect("a portal cookie is planted");
    assert_eq!(row(&h, &t2).portal_bind, Some(sha(&planted)));
}

#[test]
fn s015_3_confirmed_logout_terminates_and_returns() {
    let (idp, h) = spawn("m1-two-domains");
    let s = sign_in(&h, &idp);
    let sid = session_id(&h);
    let r = h.verify(with_cookies(
        entry("/_hopae/logout", Some("same-origin")),
        &s,
    ));
    let t1 = txn_of(&r, "/logout");
    let c = s.portal(&h);
    let page = c.get(&format!("/logout?txn={t1}"));
    let out = confirm(&c, &csrf_of(&page.body), Some(&t1));
    // Override: the signed-out page, not a redirect to the protected target.
    assert_eq!(out.status, 200, "{out:?}");
    assert_eq!(out.location(), None, "never a redirect to the target");
    let clear = out
        .set_cookies()
        .iter()
        .find(|c| c.starts_with("__Host-hopae=;"))
        .copied()
        .expect("portal handle cleared");
    assert!(
        clear.contains("Max-Age=0")
            && clear.contains("Path=/")
            && clear.contains("Secure")
            && clear.contains("HttpOnly")
            && clear.contains("SameSite=Lax"),
        "{clear}"
    );
    assert!(out.body.contains("Sign in again to app"), "{}", out.body);
    assert!(
        links(&out.body).contains(&format!("https://{APP}/")),
        "the link is the validated return target: {}",
        out.body
    );
    assert_eq!(terminated(&h, &sid).as_deref(), Some("logout"));
    assert_eq!(
        count(
            &h,
            "SELECT count(*) FROM session_handles WHERE revoked_at IS NULL"
        ),
        0,
        "H0 and H1 revoked"
    );
    assert!(row(&h, &t1).consumed_at.is_some());
    let ev = events(&h, "session.terminated");
    assert_eq!(ev.len(), 1, "{ev:?}");
    assert_eq!(ev[0]["reason"], "logout");
    // The next navigation on the application host requires login again.
    let next = h.verify(with_cookies(entry("/", None), &s));
    assert_eq!(next.status, 302, "{next:?}");
    assert_eq!(next.header("x-hopae-reason"), Some("session_terminated"));
    assert!(
        next.set_cookies()
            .iter()
            .any(|c| c.starts_with("__Host-hopae=;") && c.contains("Max-Age=0")),
        "stale cookie cleared"
    );
    // And the portal offers the provider, not single sign-on.
    let login_path = next
        .location()
        .unwrap()
        .split(PORTAL)
        .nth(1)
        .unwrap()
        .to_string();
    let offered = c.get(&login_path);
    assert!(
        offered.status == 200
            || offered
                .location()
                .is_some_and(|l| !l.contains(&format!("{APP}/"))),
        "provider offered, no handoff: {offered:?}"
    );
    assert!(
        !offered
            .location()
            .is_some_and(|l| l.contains("_hopae_handoff")),
        "{offered:?}"
    );
}

#[test]
fn s015_4_ticket_ends_session_without_portal_handle() {
    let (idp, h) = spawn("m1-two-domains");
    let s = sign_in(&h, &idp);
    let sid = session_id(&h);
    let r = h.verify(with_cookies(
        entry("/_hopae/logout", Some("same-origin")),
        &s,
    ));
    let t1 = txn_of(&r, "/logout");
    // The portal handle is gone (idle-revoked, or never presented): only P1 remains.
    s.jar.for_host(PORTAL).remove(HANDLE);
    let c = s.portal(&h);
    let page = c.get(&format!("/logout?txn={t1}"));
    assert_eq!(page.status, 200, "{page:?}");
    assert!(page.body.contains(&format!("name=\"txn\" value=\"{t1}\"")));
    let out = confirm(&c, &csrf_of(&page.body), Some(&t1));
    assert_eq!(out.status, 200, "{out:?}");
    assert!(links(&out.body).contains(&format!("https://{APP}/")));
    assert_eq!(terminated(&h, &sid).as_deref(), Some("logout"));
    let next = h.verify(with_cookies(entry("/", None), &s));
    assert_eq!(next.status, 302, "{next:?}");
    assert_eq!(next.header("x-hopae-reason"), Some("session_terminated"));
    assert!(
        next.set_cookies()
            .iter()
            .any(|c| c.starts_with("__Host-hopae=;"))
    );
}

#[test]
fn s015_5_return_on_same_origin() {
    let (idp, h) = spawn("m1-two-domains");
    let s = sign_in(&h, &idp);
    let cases = [
        (
            "%2Fdocs%2Fbye%3Fq%3D1",
            "https://app.example.test/docs/bye?q=1",
        ),
        (
            "https%3A%2F%2Fapp.example.test%2Fdocs%2Fbye",
            "https://app.example.test/docs/bye",
        ),
        (
            "https%3A%2F%2Fapp.example.test%3A443%2Fdocs%2Fbye",
            "https://app.example.test/docs/bye",
        ),
    ];
    let mut tickets = Vec::new();
    for (ret, want) in cases {
        let r = h.verify(with_cookies(
            entry(&format!("/_hopae/logout?return={ret}"), Some("same-origin")),
            &s,
        ));
        assert_eq!(r.status, 302, "{ret}: {r:?}");
        let t = txn_of(&r, "/logout");
        assert_eq!(row(&h, &t).return_target, want, "{ret}");
        tickets.push((t, want));
    }
    // After the confirmation the sign-in link is that target, byte for byte.
    let c = s.portal(&h);
    let (t, want) = &tickets[0];
    let page = c.get(&format!("/logout?txn={t}"));
    let out = confirm(&c, &csrf_of(&page.body), Some(t));
    assert_eq!(out.status, 200, "{out:?}");
    assert!(
        links(&out.body).contains(&(*want).to_string()),
        "{}",
        out.body
    );
}

#[test]
fn s015_6_login_entry_starts_login_for_target() {
    let (idp, h) = spawn("m1-two-domains");
    let r = h.verify(entry(
        "/_hopae/login?return=%2Fadmin%2Fx",
        Some("same-origin"),
    ));
    assert_eq!(r.status, 302, "{r:?}");
    let t = txn_of(&r, "/login");
    assert!(
        cookie_value(&r, BIND).is_some(),
        "binding cookie planted: {r:?}"
    );
    let t_row = row(&h, &t);
    assert_eq!(t_row.purpose, "login");
    assert_eq!(t_row.return_target, format!("https://{APP}/admin/x"));
    // Without `return` the target is the root.
    let r0 = h.verify(entry("/_hopae/login", Some("same-origin")));
    assert_eq!(r0.status, 302, "{r0:?}");
    assert_eq!(
        row(&h, &txn_of(&r0, "/login")).return_target,
        format!("https://{APP}/")
    );
    // After login the handoff lands on the target and plants H1.
    let s = sign_in_at(
        &h,
        &idp,
        &format!("https://{APP}/_hopae/login?return=%2Fadmin%2Fx"),
        "203.0.113.20",
    );
    assert!(
        s.handoff
            .starts_with("https://app.example.test/_hopae/login?return=/admin/x&_hopae_handoff="),
        "{}",
        s.handoff
    );
    assert!(s.h1.starts_with("v1."));
    // The redemption at the entry point ends at the clean validated target.
    assert_eq!(s.landed, format!("https://{APP}/admin/x"));
    // Without `return` the handoff lands on the root, through the entry point too.
    let s0 = sign_in_at(
        &h,
        &idp,
        &format!("https://{APP}/_hopae/login"),
        "203.0.113.21",
    );
    assert!(
        s0.handoff
            .starts_with("https://app.example.test/_hopae/login?return=/&_hopae_handoff="),
        "{}",
        s0.handoff
    );
    assert_eq!(s0.landed, format!("https://{APP}/"));
    // Every login, entered anywhere, is delivered the same way.
    let s1 = sign_in_at(
        &h,
        &idp,
        &format!("https://{APP}/docs/a?q=1&z=%2B"),
        "203.0.113.22",
    );
    assert!(
        s1.handoff.starts_with(
            "https://app.example.test/_hopae/login?return=/docs/a?q=1%26z=%252B&_hopae_handoff="
        ),
        "{}",
        s1.handoff
    );
    assert_eq!(s1.landed, format!("https://{APP}/docs/a?q=1&z=%2B"));
    // A target of the maximum length (2048 bytes) still fits the entry URL.
    let long = format!("https://{APP}/{}", "a".repeat(2048 - 24 - 1));
    assert_eq!(long.len(), 2048);
    let s2 = sign_in_at(&h, &idp, &long, "203.0.113.23");
    assert_eq!(s2.landed, long);
}

#[test]
fn s015_7_login_entry_with_session_redirects() {
    let (idp, h) = spawn("m1-two-domains");
    let s = sign_in(&h, &idp);
    let seen_before: i64 = count(&h, "SELECT max(last_seen_at) FROM session_handles");
    h.hooks.advance(Duration::from_secs(120));
    let r = h.verify(with_cookies(
        entry("/_hopae/login?return=%2Fadmin%2Fx", Some("same-origin")),
        &s,
    ));
    assert_eq!(r.status, 302, "{r:?}");
    assert_eq!(r.location(), Some("https://app.example.test/admin/x"));
    assert!(r.set_cookies().is_empty(), "{r:?}");
    assert_eq!(r.header("cache-control"), Some("no-store"));
    assert_eq!(r.header("x-hopae-reason"), Some("already_authenticated"));
    // last_seen_at is touched as a 200 would (best effort, asynchronous).
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        let seen = count(
            &h,
            &format!("SELECT count(*) FROM session_handles WHERE last_seen_at > {seen_before}"),
        );
        if seen > 0 {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "last_seen_at not touched"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    // A handle an ordinary verify refuses gives that verify's answer.
    let other = h.verify(with_cookies(
        entry("/_hopae/login?return=%2Fadmin%2Fx", Some("same-origin")).ip("198.51.100.7"),
        &s,
    ));
    assert_eq!(other.status, 302, "{other:?}");
    assert!(
        other
            .location()
            .unwrap()
            .starts_with("https://auth.example.test/login?txn="),
        "{other:?}"
    );
    assert_eq!(other.header("x-hopae-reason"), Some("binding_ip"));
    assert_eq!(
        terminated(&h, &session_id(&h)).as_deref(),
        Some("binding_ip")
    );
}

// ---------------------------------------------------------------------------
// Alternative flows
// ---------------------------------------------------------------------------

#[test]
fn s015_8_direct_logout_same_origin_only() {
    let (idp, h) = spawn("m1-logout-direct");
    let s = sign_in(&h, &idp);
    let sid = session_id(&h);
    // Every other metadata value takes the confirmation flow.
    for site in [
        Some("same-site"),
        Some("cross-site"),
        Some("none"),
        None,
        Some("bogus"),
    ] {
        let r = h.verify(with_cookies(entry("/_hopae/logout", site), &s));
        assert_eq!(r.status, 302, "{site:?}: {r:?}");
        let t = txn_of(&r, "/logout");
        assert_eq!(r.header("x-hopae-reason"), Some("logout_entry"), "{site:?}");
        assert!(r.set_cookies().is_empty(), "{site:?}: {r:?}");
        assert_eq!(row(&h, &t).consumed_at, None);
        assert_eq!(terminated(&h, &sid), None, "{site:?}");
    }
    // Same-origin without a valid handle: the confirmation flow, no session.
    let anon = h.verify(entry("/_hopae/logout", Some("same-origin")));
    assert_eq!(anon.status, 302, "{anon:?}");
    let ta = txn_of(&anon, "/logout");
    assert_eq!(row(&h, &ta).portal_session_id, None);
    assert_eq!(terminated(&h, &sid), None);
    // Same-origin with a valid handle: terminated at verify.
    let r = h.verify(with_cookies(
        entry("/_hopae/logout", Some("same-origin")),
        &s,
    ));
    assert_eq!(r.status, 302, "{r:?}");
    assert_eq!(r.header("x-hopae-reason"), Some("logout"));
    let t = txn_of(&r, "/signed-out");
    assert!(
        r.set_cookies()
            .iter()
            .any(|c| c.starts_with("__Host-hopae=;") && c.contains("Max-Age=0")),
        "{r:?}"
    );
    assert!(
        !r.set_cookies()
            .iter()
            .any(|c| c.starts_with("__Host-hopae_bind")),
        "binding cookie untouched: {r:?}"
    );
    assert!(
        !r.location().unwrap().contains("app.example.test"),
        "no raw URL in the redirect: {:?}",
        r.location()
    );
    assert_eq!(terminated(&h, &sid).as_deref(), Some("logout"));
    let ev = events(&h, "session.terminated");
    assert_eq!(ev.len(), 1, "{ev:?}");
    assert_eq!(ev[0]["reason"], "logout");
    // The opaque reference is the consumed ticket; the portal page links back.
    let tr = row(&h, &t);
    assert_eq!(tr.purpose, "logout");
    assert!(tr.consumed_at.is_some());
    let page = h.portal().with_ip(IP).get(&format!("/signed-out?txn={t}"));
    assert_eq!(page.status, 200, "{page:?}");
    assert!(page.body.contains("Sign in again to app"), "{}", page.body);
    assert!(
        links(&page.body).contains(&format!("https://{APP}/")),
        "{}",
        page.body
    );
    // An unconsumed confirmation ticket does not make that page say "signed out".
    let unconsumed = h.portal().with_ip(IP).get(&format!("/signed-out?txn={ta}"));
    assert_eq!(unconsumed.status, 400, "{unconsumed:?}");
    let unknown = h
        .portal()
        .with_ip(IP)
        .get("/signed-out?txn=AAAAAAAAAAAAAAAAAAAAAA");
    assert_eq!(unknown.status, 400, "{unknown:?}");
}

// ---------------------------------------------------------------------------
// Abuse cases
// ---------------------------------------------------------------------------

#[test]
fn s015_a1_replayed_or_foreign_ticket_harmless() {
    let (idp, h) = spawn("m1-two-domains");
    let s = sign_in(&h, &idp);
    let r = h.verify(with_cookies(
        entry("/_hopae/logout", Some("same-origin")),
        &s,
    ));
    let t1 = txn_of(&r, "/logout");
    let c = s.portal(&h);
    let page = c.get(&format!("/logout?txn={t1}"));
    let out = confirm(&c, &csrf_of(&page.body), Some(&t1));
    assert_eq!(out.status, 200, "{out:?}");
    let events_before = total_events(&h);
    // Replay: the consumed ticket is absent; the page is the plain confirmation.
    let again = c.get(&format!("/logout?txn={t1}"));
    assert_eq!(again.status, 200, "{again:?}");
    assert!(!again.body.contains("name=\"txn\""), "plain confirmation");
    let post = confirm(&c, &csrf_of(&again.body), Some(&t1));
    assert_eq!(post.status, 200, "signed-out page as 006-4: {post:?}");
    assert!(
        !links(&post.body).iter().any(|l| l.contains(APP)),
        "no link from a consumed ticket: {}",
        post.body
    );
    assert_eq!(total_events(&h), events_before, "no new event");
    // Unknown id and a malformed one.
    let unknown = c.get("/logout?txn=AAAAAAAAAAAAAAAAAAAAAA");
    assert_eq!(unknown.status, 200);
    assert!(!unknown.body.contains("name=\"txn\""));
    // A login transaction's id is the wrong purpose: not consumed, not altered.
    let (idp2, h2) = spawn("m1-two-domains");
    let s2 = sign_in(&h2, &idp2);
    let login =
        h2.verify(entry("/_hopae/login?return=%2Fa", Some("same-origin")).ip("203.0.113.77"));
    let lt = txn_of(&login, "/login");
    let before = row(&h2, &lt);
    let c2 = s2.portal(&h2);
    let wrong = c2.get(&format!("/logout?txn={lt}"));
    assert_eq!(wrong.status, 200, "{wrong:?}");
    assert!(!wrong.body.contains("name=\"txn\""));
    let after = row(&h2, &lt);
    assert_eq!(after.consumed_at, None);
    assert_eq!(after.portal_bind, before.portal_bind);
    assert!(h2.log().contains("txn_purpose_mismatch"), "{}", h2.log());
    // An expired ticket is absent too; and /login rejects a logout ticket
    // without consuming it.
    let r3 = h2.verify(with_cookies(
        entry("/_hopae/logout", Some("same-origin")),
        &s2,
    ));
    let t3 = txn_of(&r3, "/logout");
    let l = c2.get(&format!("/login?txn={t3}"));
    assert_eq!(l.status, 400, "{l:?}");
    assert_eq!(row(&h2, &t3).consumed_at, None, "not consumed by /login");
    h2.hooks.advance(Duration::from_secs(601));
    let expired = c2.get(&format!("/logout?txn={t3}"));
    assert_eq!(expired.status, 200);
    assert!(!expired.body.contains("name=\"txn\""));
}

#[test]
fn s015_a2_return_cannot_leave_origin() {
    let (idp, h) = spawn("m1-two-domains");
    let s = sign_in(&h, &idp);
    let before = txn_count(&h);
    let bad = [
        "https://evil.example.org/",
        "//evil.example.org/",
        "/\\evil.example.org",
        "https://other.example.org/",
        "https://app.example.test:8443/",
        "http://app.example.test/",
        "https://app.example.test@evil.example.org/",
        "https://app.example.test/#f",
        "javascript:alert(1)",
        "/x?_hopae_handoff=K",
        "/_hopae/login",
        "/_HOPAE/logout",
        "relative/path",
        "",
    ];
    let enc = |v: &str| url::form_urlencoded::byte_serialize(v.as_bytes()).collect::<String>();
    for ep in ["/_hopae/logout", "/_hopae/login"] {
        for ret in bad {
            let r = h.verify(with_cookies(
                entry(&format!("{ep}?return={}", enc(ret)), Some("same-origin")),
                &s,
            ));
            assert_eq!(r.status, 403, "{ep} {ret:?}: {r:?}");
            assert_eq!(
                r.header("x-hopae-reason"),
                Some("return_not_allowed"),
                "{ret:?}"
            );
            assert_eq!(r.json(), json!({"error": "return_not_allowed"}), "{ret:?}");
            assert!(r.set_cookies().is_empty(), "{ret:?}: {r:?}");
        }
        let dup = h.verify(with_cookies(
            entry(
                &format!("{ep}?return=%2Fa&return=%2Fb"),
                Some("same-origin"),
            ),
            &s,
        ));
        assert_eq!(dup.status, 403, "{ep}: {dup:?}");
        assert_eq!(dup.header("x-hopae-reason"), Some("return_not_allowed"));
    }
    // A target longer than the 2048-byte limit still fits the entry URL (entry
    // points carry targets up to the limit) and is refused as a target.
    let long = format!("/{}", "a".repeat(2100));
    let r = h.verify(with_cookies(
        entry(
            &format!("/_hopae/logout?return={}", enc(&long)),
            Some("same-origin"),
        ),
        &s,
    ));
    assert_eq!(r.status, 403, "{r:?}");
    assert_eq!(r.header("x-hopae-reason"), Some("return_not_allowed"));
    assert_eq!(txn_count(&h), before, "no transaction created");
    assert_eq!(terminated(&h, &session_id(&h)), None);
    assert!(
        wait_denied(&h, "return_not_allowed"),
        "denials are recorded"
    );
}

#[test]
fn s015_a3_ticket_racing_termination() {
    let (idp, h) = spawn("m1-two-domains");
    let s = sign_in(&h, &idp);
    let sid = session_id(&h);
    let r = h.verify(with_cookies(
        entry("/_hopae/logout", Some("same-origin")),
        &s,
    ));
    let t1 = txn_of(&r, "/logout");
    let c = s.portal(&h);
    let page = c.get(&format!("/logout?txn={t1}"));
    let csrf = csrf_of(&page.body);
    // The session is ended elsewhere between the page and the POST.
    let mismatch = h.verify(with_cookies(entry("/", None), &s).ip("198.51.100.7"));
    assert_eq!(mismatch.status, 302, "{mismatch:?}");
    assert_eq!(terminated(&h, &sid).as_deref(), Some("binding_ip"));
    let out = confirm(&c, &csrf, Some(&t1));
    assert_eq!(out.status, 200, "{out:?}");
    assert!(row(&h, &t1).consumed_at.is_some(), "the ticket is consumed");
    assert_eq!(
        terminated(&h, &sid).as_deref(),
        Some("binding_ip"),
        "termination is a no-op on the terminated session"
    );
    assert_eq!(
        events(&h, "session.terminated").len(),
        1,
        "exactly one event"
    );

    // Two confirmations of one ticket at once: one wins, one session.terminated.
    let (idp, h) = spawn("m1-two-domains");
    let s = sign_in(&h, &idp);
    let sid = session_id(&h);
    let r = h.verify(with_cookies(
        entry("/_hopae/logout", Some("same-origin")),
        &s,
    ));
    let t1 = txn_of(&r, "/logout");
    let c = s.portal(&h);
    let page = c.get(&format!("/logout?txn={t1}"));
    let csrf = csrf_of(&page.body);
    let (a, b) = std::thread::scope(|sc| {
        let ha = sc.spawn(|| confirm(&c, &csrf, Some(&t1)));
        let hb = sc.spawn(|| confirm(&c, &csrf, Some(&t1)));
        (ha.join().unwrap(), hb.join().unwrap())
    });
    assert_eq!((a.status, b.status), (200, 200), "{a:?} {b:?}");
    assert_eq!(terminated(&h, &sid).as_deref(), Some("logout"));
    assert_eq!(events(&h, "session.terminated").len(), 1);
}

#[test]
fn s015_a4_entry_floods_capped() {
    let (_idp, h) = spawn("m1-two-domains");
    let before = txn_count(&h);
    for i in 0..100 {
        let r = h.verify(
            VerifyRequest::other(&format!("https://{APP}/_hopae/logout"))
                .ip("203.0.113.50")
                .header("sec-fetch-site", "same-origin"),
        );
        assert_eq!(r.status, 403, "request {i}: {r:?}");
        assert_eq!(r.header("x-hopae-reason"), Some("entry_point_not_document"));
        assert_eq!(r.json(), json!({"error": "reserved_path"}));
        assert!(r.set_cookies().is_empty());
    }
    assert_eq!(txn_count(&h), before, "non-document requests write nothing");
    // 30 per minute from one address, then the cap.
    let mut created = 0;
    let mut limited = 0;
    for _ in 0..40 {
        let r = h.verify(
            VerifyRequest::document(&format!("https://{APP}/_hopae/logout"))
                .ip("203.0.113.50")
                .header("sec-fetch-site", "same-origin"),
        );
        match r.status {
            302 => created += 1,
            403 => {
                limited += 1;
                assert_eq!(r.header("x-hopae-reason"), Some("txn_rate_limited"));
                assert_eq!(
                    r.json(),
                    json!({"error": "rate_limited", "retry_after": 60})
                );
            }
            s => panic!("unexpected {s}: {r:?}"),
        }
    }
    assert_eq!((created, limited), (30, 10));
    assert_eq!(txn_count(&h), before + 30);

    // max_rows eviction is synchronous and counted.
    let (_idp, h) = spawn_with(
        "m1-two-domains",
        json!({"txn": {"max_rows": 10, "per_ip_per_minute": 1000}}),
    );
    for _ in 0..60 {
        let r = h.verify(entry("/_hopae/logout", Some("same-origin")));
        assert_eq!(r.status, 302, "{r:?}");
        assert!(txn_count(&h) <= 10, "max_rows is a hard bound");
    }
    std::thread::sleep(Duration::from_millis(500));
    let evicted: i64 = events(&h, "txn.evicted")
        .iter()
        .map(|e| e["attrs"]["count"].as_i64().unwrap_or(0))
        .sum();
    assert!(evicted >= 50, "txn.evicted counts the evictions: {evicted}");
}

#[test]
fn s015_a5_cross_site_cannot_log_out() {
    for fixture in ["m1-two-domains", "m1-logout-direct"] {
        let (idp, h) = spawn(fixture);
        let s = sign_in(&h, &idp);
        let sid = session_id(&h);
        let before = txn_count(&h);
        // (a) <img> and fetch(): never a document.
        for (dest, site) in [
            ("image", "cross-site"),
            ("empty", "cross-site"),
            ("image", "same-site"),
            ("empty", "same-site"),
            ("empty", "same-origin"),
        ] {
            let r = h.verify(
                with_cookies(
                    VerifyRequest::other(&format!("https://{APP}/_hopae/logout")).ip(IP),
                    &s,
                )
                .without("sec-fetch-dest")
                .header("sec-fetch-dest", dest)
                .header("sec-fetch-site", site),
            );
            assert_eq!(r.status, 403, "{dest}/{site}: {r:?}");
            assert_eq!(r.header("x-hopae-reason"), Some("entry_point_not_document"));
            assert!(r.set_cookies().is_empty(), "{dest}/{site}: {r:?}");
        }
        assert_eq!(txn_count(&h), before);
        // (b) top-level navigation from another site or a sibling subdomain.
        for site in ["cross-site", "same-site"] {
            let r = h.verify(with_cookies(entry("/_hopae/logout", Some(site)), &s));
            assert_eq!(r.status, 302, "{fixture} {site}: {r:?}");
            assert_eq!(r.header("x-hopae-reason"), Some("logout_entry"));
            assert!(r.set_cookies().is_empty());
            let t = txn_of(&r, "/logout");
            assert_eq!(row(&h, &t).consumed_at, None);
            assert_eq!(
                terminated(&h, &sid),
                None,
                "{fixture} {site}: nothing terminated"
            );
        }
        let ok = h.verify(with_cookies(entry("/", None), &s));
        assert_eq!(ok.status, 200, "H1 untouched: {ok:?}");
        assert!(events(&h, "session.terminated").is_empty());
    }
}

#[test]
fn s015_a6_spoofed_metadata_and_canonical_tricks() {
    let (idp, h) = spawn("m1-logout-direct");
    let s = sign_in(&h, &idp);
    let sid = session_id(&h);
    // A client that claims the metadata of a same-origin navigation only
    // logs itself out (it holds the handle).
    // A canonical-path header that disagrees with the URL is refused.
    let r = h.verify(
        with_cookies(entry("/other", Some("same-origin")), &s)
            .header("x-hangang-canonical-path", "/_hopae/logout"),
    );
    assert_eq!(r.status, 403, "{r:?}");
    assert_eq!(r.header("x-hopae-reason"), Some("canonical_path_mismatch"));
    assert_eq!(terminated(&h, &sid), None);
    // Two sec-fetch-site values: a contract violation.
    let r = h.verify(
        with_cookies(entry("/_hopae/logout", Some("same-origin")), &s)
            .header("sec-fetch-site", "same-origin"),
    );
    assert_eq!(r.status, 400, "{r:?}");
    assert_eq!(r.header("x-hopae-reason"), Some("contract_violation"));
    assert_eq!(terminated(&h, &sid), None);
    // The sender's own session is all the claim can end.
    let r = h.verify(with_cookies(
        entry("/_hopae/logout", Some("same-origin")),
        &s,
    ));
    assert_eq!(r.status, 302);
    assert_eq!(terminated(&h, &sid).as_deref(), Some("logout"));
}

#[test]
fn s015_a7_attacker_ticket_not_redeemable_by_victim() {
    let (idp, h) = spawn("m1-two-domains");
    let attacker = sign_in_at(&h, &idp, &format!("https://{APP}/admin/x"), IP);
    let a_sid = session_id(&h);
    idp.set_user("sub-victim", "victim@example.test", true, "Victim");
    let victim = sign_in_at(&h, &idp, &format!("https://{APP}/admin/x"), "203.0.113.10");
    let v_sid: String = db(&h)
        .query_row(
            "SELECT session_id FROM sessions WHERE session_id != ?1",
            [&a_sid],
            |r| r.get(0),
        )
        .unwrap();
    // The attacker mints and opens a ticket, then lures the victim.
    let r = h.verify(with_cookies(
        entry("/_hopae/logout", Some("same-origin")),
        &attacker,
    ));
    let ta = txn_of(&r, "/logout");
    let a_page = attacker.portal(&h).get(&format!("/logout?txn={ta}"));
    assert_eq!(a_page.status, 200);
    assert_eq!(row(&h, &ta).portal_bind, Some(sha(&attacker.p1())));
    let vc = victim.portal(&h);
    let page = vc.get(&format!("/logout?txn={ta}"));
    assert_eq!(page.status, 200, "{page:?}");
    assert!(
        !page.body.contains("name=\"txn\""),
        "the victim gets the plain confirmation"
    );
    // Even a forged form that names the ticket is ignored.
    let out = confirm(&vc, &csrf_of(&page.body), Some(&ta));
    assert_eq!(out.status, 200, "{out:?}");
    assert_eq!(out.location(), None);
    assert!(
        !links(&out.body).iter().any(|l| l.contains(APP)),
        "no link from a foreign ticket: {}",
        out.body
    );
    assert_eq!(
        terminated(&h, &v_sid).as_deref(),
        Some("logout"),
        "own session only"
    );
    assert_eq!(
        terminated(&h, &a_sid),
        None,
        "the attacker's session is untouched"
    );
    assert_eq!(row(&h, &ta).consumed_at, None, "the ticket is not consumed");
}

#[test]
fn s015_a8_direct_mode_accepts_navigation_gadgets_and_check_warns() {
    // Residual risk of the opt-in mode (ADR-0015, TM-41): a document the
    // application itself serves that starts a new same-origin navigation to
    // `/_hopae/logout` (a script that assigns a URL from its own query to
    // `location`) presents `sec-fetch-site: same-origin`, so the ambient handle
    // is ended without a click. The mode accepts it; the default does not.
    let (idp, h) = spawn("m1-logout-direct");
    let s = sign_in(&h, &idp);
    let sid = session_id(&h);
    let r = h.verify(with_cookies(
        entry("/_hopae/logout", Some("same-origin")),
        &s,
    ));
    assert_eq!(r.header("x-hopae-reason"), Some("logout"), "{r:?}");
    assert_eq!(terminated(&h, &sid).as_deref(), Some("logout"));
    let (idp, h) = spawn("m1-two-domains");
    let s = sign_in(&h, &idp);
    let r = h.verify(with_cookies(
        entry("/_hopae/logout", Some("same-origin")),
        &s,
    ));
    assert_eq!(r.header("x-hopae-reason"), Some("logout_entry"), "{r:?}");
    assert_eq!(
        terminated(&h, &session_id(&h)),
        None,
        "the default asks first"
    );

    // `hopae --check` names the setting.
    let check = |fixture: &str| {
        let dir = tempfile::tempdir().unwrap();
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(format!("{fixture}.json"));
        let mut v: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        v["state_dir"] = json!(dir.path().join("state"));
        let cfg = dir.path().join("hopae.json");
        std::fs::write(&cfg, serde_json::to_vec_pretty(&v).unwrap()).unwrap();
        let o = std::process::Command::new(env!("CARGO_BIN_EXE_hopae"))
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("HOPAE_TEST_GATEWAY_KEY", "k".repeat(32))
            .env("HOPAE_TEST_MOCK_SECRET", "s".repeat(32))
            .arg("--check")
            .arg("--config")
            .arg(&cfg)
            .output()
            .unwrap();
        format!(
            "{}\n{}",
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr)
        )
    };
    let warned = check("m1-logout-direct");
    assert!(
        warned.contains("logout_confirm is false") && warned.contains("navigation gadget"),
        "{warned}"
    );
    assert!(
        warned.contains("logout_confirm false"),
        "printed per application: {warned}"
    );
    let quiet = check("m1-two-domains");
    assert!(!quiet.contains("logout_confirm is false"), "{quiet}");
}

#[test]
fn s015_a9_unvisited_ticket_is_a_transferable_revocation_capability() {
    let (idp, h) = spawn("m1-two-domains");
    let attacker = sign_in_at(&h, &idp, &format!("https://{APP}/admin/x"), IP);
    let a_sid = session_id(&h);
    idp.set_user("sub-victim", "victim@example.test", true, "Victim");
    let victim = sign_in_at(&h, &idp, &format!("https://{APP}/admin/x"), "203.0.113.10");
    let v_sid: String = db(&h)
        .query_row(
            "SELECT session_id FROM sessions WHERE session_id != ?1",
            [&a_sid],
            |r| r.get(0),
        )
        .unwrap();
    // The attacker mints a ticket for their own session and never opens it.
    let r = h.verify(with_cookies(
        entry("/_hopae/logout", Some("same-origin")),
        &attacker,
    ));
    let ta = txn_of(&r, "/logout");
    assert_eq!(row(&h, &ta).portal_bind, None, "unvisited");
    // The victim's first visit binds it to the victim's browser and shows the form.
    let vc = victim.portal(&h);
    let page = vc.get(&format!("/logout?txn={ta}"));
    assert_eq!(page.status, 200, "{page:?}");
    assert!(page.body.contains(&format!("name=\"txn\" value=\"{ta}\"")));
    assert_eq!(row(&h, &ta).portal_bind, Some(sha(&victim.p1())));
    // The victim confirms: exactly the attacker-selected session (their own) and
    // the victim's own portal session end. Nothing else, and no foreign id was injected.
    let out = confirm(&vc, &csrf_of(&page.body), Some(&ta));
    assert_eq!(out.status, 200, "{out:?}");
    assert_eq!(terminated(&h, &a_sid).as_deref(), Some("logout"));
    assert_eq!(terminated(&h, &v_sid).as_deref(), Some("logout"));
    assert_eq!(
        count(
            &h,
            "SELECT count(*) FROM sessions WHERE terminated_at IS NOT NULL"
        ),
        2
    );
    assert_eq!(events(&h, "session.terminated").len(), 2);
    assert!(row(&h, &ta).consumed_at.is_some());
}

#[test]
fn s015_a10_ticket_consume_and_termination_are_one_transaction() {
    let (idp, h) = spawn("m1-two-domains");
    let mut h = h;
    let s = sign_in(&h, &idp);
    let sid = session_id(&h);
    let r = h.verify(with_cookies(
        entry("/_hopae/logout", Some("same-origin")),
        &s,
    ));
    let t1 = txn_of(&r, "/logout");
    // No portal handle: only the ticket can end the session (S015-4).
    s.jar.for_host(PORTAL).remove(HANDLE);
    let c = s.portal(&h);
    let page = c.get(&format!("/logout?txn={t1}"));
    assert_eq!(page.status, 200, "{page:?}");
    let csrf = csrf_of(&page.body);
    // The process dies between the ticket's consumption and the termination.
    h.hooks.crash_at("after_ticket_consume");
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        confirm(&c, &csrf, Some(&t1))
    }));
    assert!(
        h.wait_exit(Duration::from_secs(10)).is_some(),
        "the crash point did not fire"
    );
    h.restart();
    // Neither half survived: no consumed ticket beside a live session.
    assert_eq!(row(&h, &t1).consumed_at, None, "the ticket is not consumed");
    assert_eq!(terminated(&h, &sid), None, "the session is untouched");
    let ok = h.verify(with_cookies(entry("/", None), &s));
    assert_eq!(ok.status, 200, "H1 still works: {ok:?}");
    // The retry still logs out.
    let c = s.portal(&h);
    let page = c.get(&format!("/logout?txn={t1}"));
    assert_eq!(page.status, 200, "{page:?}");
    let out = confirm(&c, &csrf_of(&page.body), Some(&t1));
    assert_eq!(out.status, 200, "{out:?}");
    assert!(
        links(&out.body).contains(&format!("https://{APP}/")),
        "{}",
        out.body
    );
    assert!(row(&h, &t1).consumed_at.is_some());
    assert_eq!(terminated(&h, &sid).as_deref(), Some("logout"));
    assert_eq!(events(&h, "session.terminated").len(), 1);
}

#[test]
fn s015_a11_return_normalization_cannot_reach_the_reserved_namespace() {
    let (idp, h) = spawn("m1-two-domains");
    let s = sign_in(&h, &idp);
    let before = txn_count(&h);
    let enc = |v: &str| url::form_urlencoded::byte_serialize(v.as_bytes()).collect::<String>();
    let bad = [
        // single and triple slash: the URL parser repairs them into this origin
        "https:/app.example.test/_hopae/logout",
        "https:///app.example.test/_hopae/logout",
        "https:////app.example.test/_hopae/login",
        "http:///app.example.test/_hopae/logout",
        "https:\\app.example.test/_hopae/logout",
        // spellings of the namespace
        "https://app.example.test/_HOPAE/Logout",
        "https://app.example.test/_%68opae/logout",
        "https://app.example.test/x/../_hopae/logout",
        "/x/../_hopae/login",
        "/./_hopae/logout",
    ];
    for ep in ["/_hopae/logout", "/_hopae/login"] {
        for ret in bad {
            let r = h.verify(with_cookies(
                entry(&format!("{ep}?return={}", enc(ret)), Some("same-origin")),
                &s,
            ));
            assert_eq!(r.status, 403, "{ep} {ret:?}: {r:?}");
            assert_eq!(
                r.header("x-hopae-reason"),
                Some("return_not_allowed"),
                "{ret:?}"
            );
            assert!(r.set_cookies().is_empty(), "{ret:?}: {r:?}");
        }
    }
    assert_eq!(txn_count(&h), before, "no transaction created");
    assert_eq!(terminated(&h, &session_id(&h)), None);
}

#[test]
fn s015_a12_max_rows_holds_for_switch_and_link_creation() {
    // The table-wide bound is exercised where those rows are written:
    // `capped_insert_*` and `switch_and_link_inserts_*` in the store and engine
    // unit tests. Here, the black-box part: tickets and logins share one table.
    let (_idp, h) = spawn_with(
        "m1-two-domains",
        json!({"txn": {"max_rows": 4, "per_ip_per_minute": 1000}}),
    );
    for i in 0..30 {
        let ep = if i % 2 == 0 {
            "/_hopae/logout"
        } else {
            "/_hopae/login"
        };
        let r = h.verify(entry(ep, Some("same-origin")));
        assert_eq!(r.status, 302, "{r:?}");
        assert!(txn_count(&h) <= 4, "round {i}");
    }
}

#[test]
fn s015_a13_entry_points_need_an_html_accept() {
    for fixture in ["m1-two-domains", "m1-logout-direct"] {
        let (idp, h) = spawn(fixture);
        let s = sign_in(&h, &idp);
        let sid = session_id(&h);
        let before = txn_count(&h);
        for ep in ["/_hopae/logout", "/_hopae/login?return=%2Fx"] {
            for accept in [
                None,
                Some("application/json"),
                Some("*/*"),
                Some("text/plain"),
            ] {
                let mut r = with_cookies(entry(ep, Some("same-origin")), &s).without("accept");
                if let Some(a) = accept {
                    r = r.header("accept", a);
                }
                let out = h.verify(r);
                assert_eq!(out.status, 403, "{fixture} {ep} {accept:?}: {out:?}");
                assert_eq!(
                    out.header("x-hopae-reason"),
                    Some("entry_point_not_document"),
                    "{ep} {accept:?}"
                );
                assert_eq!(out.json(), json!({"error": "reserved_path"}));
                assert!(out.set_cookies().is_empty());
            }
        }
        assert_eq!(txn_count(&h), before, "no transaction");
        assert_eq!(terminated(&h, &sid), None, "nothing terminated");
        // An HTML accept in any position is a document request.
        let out = h.verify(
            with_cookies(entry("/_hopae/login", Some("same-origin")), &s)
                .without("accept")
                .header("accept", "application/json, text/html;q=0.5"),
        );
        assert_eq!(out.status, 302, "{out:?}");
    }
}

#[test]
fn s015_a14_logout_entry_records_a_refused_handle_like_login() {
    let denied_reasons = |entry_path: &str, cookie: &str| {
        let (_idp, h) = spawn("m1-two-domains");
        let r = h.verify(entry(entry_path, Some("same-origin")).cookie(HANDLE, cookie));
        assert_eq!(r.status, 302, "{entry_path}: {r:?}");
        assert!(
            r.set_cookies()
                .iter()
                .any(|c| c.starts_with("__Host-hopae=;") && c.contains("Max-Age=0")),
            "the refused handle is cleared: {r:?}"
        );
        assert!(wait_denied(&h, "unknown_handle") || wait_denied(&h, "malformed_handle"));
        let mut v: Vec<String> = events(&h, "verify.denied")
            .iter()
            .filter_map(|e| e["reason"].as_str().map(str::to_string))
            .collect();
        v.sort();
        v
    };
    let unknown = format!("v1.{}", "A".repeat(43));
    for cookie in [unknown.as_str(), "garbage"] {
        let login = denied_reasons("/_hopae/login", cookie);
        let logout = denied_reasons("/_hopae/logout", cookie);
        assert!(!login.is_empty(), "{cookie}");
        assert_eq!(login, logout, "same denial reasons for {cookie:?}");
    }
}

#[test]
fn hopae_level_encoded_namespace_gets_the_entry_limit() {
    let (_idp, h) = spawn("m1-two-domains");
    // A target of the full 2048 bytes whose query holds `%`, `&` and `+`.
    let mut target = format!("https://{APP}/x?");
    while target.len() < 2048 {
        target.push_str("a%26b=%2B+%25&");
    }
    target.truncate(2048);
    while target.ends_with('%') || target.ends_with("%2") {
        target.pop();
        target.push('z');
    }
    let ret = &target[format!("https://{APP}").len()..];
    let enc: String = url::form_urlencoded::byte_serialize(ret.as_bytes()).collect();
    for ns in [
        "/_hopae/login",
        "/_%68opae/login",
        "/%5Fhopae/login",
        "/_HOPAE/Login",
        "/_hop%61e/%6Cogin",
    ] {
        let r =
            h.verify(entry(&format!("{ns}?return={enc}"), Some("same-origin")).ip("203.0.113.40"));
        assert_eq!(r.status, 302, "{ns}: {r:?}");
        let t = txn_of(&r, "/login");
        assert_eq!(row(&h, &t).return_target, target, "{ns}");
        // The ordinary ceiling still applies off the namespace.
        let long = format!("/other{}?return={enc}", "a".repeat(10));
        let r = h.verify(entry(&long, None).ip("203.0.113.41"));
        assert_eq!(r.status, 400, "{r:?}");
    }
}

// ---------------------------------------------------------------------------
// Namespace variants at the Hopae level (the gateway cases are below)
// ---------------------------------------------------------------------------

#[test]
fn hopae_level_namespace_variants() {
    let (idp, h) = spawn("m1-two-domains");
    let s = sign_in(&h, &idp);
    let before = txn_count(&h);
    for p in ["/_HOPAE/Logout", "/_hopae/%6Cogout"] {
        let r = h.verify(with_cookies(entry(p, Some("same-origin")), &s));
        assert_eq!(r.status, 302, "{p}: {r:?}");
        assert_eq!(r.header("x-hopae-reason"), Some("logout_entry"), "{p}");
    }
    let made = txn_count(&h) - before;
    assert_eq!(made, 2);
    for p in [
        "/_hopae",
        "/_hopae/",
        "/_hopae/logout/",
        "/_hopae/verify",
        "/_hopae/report",
        "/_HOPAE/x",
    ] {
        let r = h.verify(with_cookies(entry(p, Some("same-origin")), &s));
        assert_eq!(r.status, 403, "{p}: {r:?}");
        assert_eq!(r.header("x-hopae-reason"), Some("reserved_path"), "{p}");
        assert_eq!(r.json(), json!({"error": "reserved_path"}), "{p}");
        assert!(r.set_cookies().is_empty(), "{p}");
    }
    for p in ["/_hopae//logout", "/_hopae/%2e%2e/logout"] {
        let r = h.verify(with_cookies(entry(p, Some("same-origin")), &s));
        assert_eq!(
            r.header("x-hopae-reason"),
            Some("path_not_canonical"),
            "{p}: {r:?}"
        );
    }
    assert_eq!(txn_count(&h), before + made, "no transaction for the rest");
    assert!(wait_denied(&h, "reserved_path"), "denials are recorded");
    // The reserved parameter is neither redeemed nor consulted on a reserved path.
    let r = h.verify(entry(
        "/_hopae/verify?_hopae_handoff=abc",
        Some("same-origin"),
    ));
    assert_eq!(r.header("x-hopae-reason"), Some("reserved_path"), "{r:?}");
    // An unlisted host is still unknown_app.
    let r = h.verify(VerifyRequest::document("https://nope.example.test/_hopae/logout").ip(IP));
    assert_eq!(r.status, 403);
    assert_eq!(r.header("x-hopae-reason"), Some("unknown_app"));
}

// ---------------------------------------------------------------------------
// Gateway layer
// ---------------------------------------------------------------------------

mod gateway_layer {
    use super::*;
    use crate::support::gateway::*;

    fn nav(b: &Browser, host: &str, path: &str) -> Response {
        b.get_with(host, path, &[("sec-fetch-site", "same-origin")])
    }

    #[test]
    #[ignore = "gateway layer: needs HOPAE_E2E_GATEWAY_BINARY (make e2e)"]
    fn s015_9_namespace_variants_never_reach_upstream() {
        let Some(s) = Stack::basic("s015_9") else {
            return;
        };
        let b = s.logged_in("/admin/x");
        s.echo.clear();
        // The first two are the logout entry.
        for p in ["/_HOPAE/Logout", "/_hopae/%6Cogout"] {
            let r = nav(&b, &s.app, p);
            assert_eq!(r.status, 302, "{p}: {r:?}");
            assert_eq!(
                s.gw.tap
                    .answers()
                    .last()
                    .and_then(|a| a.header("x-hopae-reason")),
                Some("logout_entry"),
                "{p}"
            );
            assert!(
                r.location()
                    .unwrap()
                    .starts_with("https://auth.example.test/logout?txn="),
                "{p}"
            );
        }
        for p in [
            "/_hopae",
            "/_hopae/",
            "/_hopae/logout/",
            "/_hopae/verify",
            "/_hopae/report",
            "/_HOPAE/x",
        ] {
            let r = nav(&b, &s.app, p);
            assert_eq!(r.status, 403, "{p}: {r:?}");
            assert_eq!(r.json(), json!({"error": "reserved_path"}), "{p}");
            assert_eq!(
                s.gw.tap
                    .answers()
                    .last()
                    .and_then(|a| a.header("x-hopae-reason")),
                Some("reserved_path"),
                "{p}"
            );
            assert!(r.set_cookies().is_empty(), "{p}: {r:?}");
        }
        for p in ["/_hopae//logout", "/_hopae/%2e%2e/logout"] {
            let r = nav(&b, &s.app, p);
            assert!(
                r.status == 403 || r.status == 400,
                "{p}: {} (path_not_canonical)",
                r.status
            );
        }
        // A fetch() of the entry point is a 403 too.
        let f = b.fetch(&s.app, "/_hopae/logout");
        assert_eq!(f.status, 403, "{f:?}");
        assert_eq!(f.json(), json!({"error": "reserved_path"}));
        assert_eq!(
            s.gw.tap
                .answers()
                .last()
                .and_then(|a| a.header("x-hopae-reason")),
            Some("entry_point_not_document")
        );
        assert!(
            s.echo.requests().is_empty(),
            "zero upstream requests: {:?}",
            s.echo.requests()
        );
    }

    #[test]
    #[ignore = "gateway layer: needs HOPAE_E2E_GATEWAY_BINARY (make e2e)"]
    fn s015_10_path_scoped_host_needs_hopae_route() {
        let routes = |with_hopae: bool| {
            let r = GatewayRoutes::new()
                .path_scoped(APP_HOST, "/admin")
                .portal(PORTAL_HOST);
            if with_hopae {
                r.hopae_prefix(APP_HOST)
            } else {
                r
            }
        };
        // Without the route Hopae is not called (the documented limitation).
        let Some(s) = Stack::with_routes("s015_10a", routes(false)) else {
            return;
        };
        let b = s.gw.browser();
        let r = nav(&b, &s.app, "/_hopae/logout");
        assert_eq!(r.status, 200, "{r:?}");
        assert_eq!(
            s.echo
                .requests()
                .iter()
                .map(|r| r.path().to_string())
                .collect::<Vec<_>>(),
            vec!["/_hopae/logout".to_string()]
        );
        assert!(s.gw.tap.calls().is_empty(), "Hopae was not called");
        drop(s);
        // With the site-hopae route Hopae answers and the upstream records nothing.
        let Some(s) = Stack::with_routes("s015_10b", routes(true)) else {
            return;
        };
        let b = s.gw.browser();
        let r = nav(&b, &s.app, "/_hopae/logout");
        assert_eq!(r.status, 302, "{r:?}");
        assert!(
            r.location()
                .unwrap()
                .starts_with("https://auth.example.test/logout?txn="),
            "{r:?}"
        );
        assert!(s.echo.requests().is_empty(), "{:?}", s.echo.requests());
        // A case variant still reaches the upstream on a gateway without HC-10
        // (TM-39); with HC-10 the protected prefix matches case-insensitively and
        // Hopae answers. Probe the binary the way scenario 008-A1 does, so the
        // same test stays right before and after the gateway gains the field.
        let (hc10, _) = s.gw.check_variant(|doc| {
            fn mark(v: &mut Value) {
                match v {
                    Value::Object(o) => {
                        if o.get("id")
                            .and_then(|i| i.as_str())
                            .is_some_and(|i| i.starts_with("site-hopae"))
                        {
                            o.insert("path_case".into(), json!("insensitive"));
                        }
                        o.values_mut().for_each(mark);
                    }
                    Value::Array(a) => a.iter_mut().for_each(mark),
                    _ => {}
                }
            }
            mark(doc);
        });
        let v = nav(&b, &s.app, "/_HOPAE/logout");
        if hc10 {
            assert_eq!(v.status, 302, "{v:?}");
            assert!(
                v.location()
                    .unwrap()
                    .starts_with("https://auth.example.test/logout?txn="),
                "{v:?}"
            );
            assert!(s.echo.requests().is_empty(), "{:?}", s.echo.requests());
        } else {
            assert_eq!(v.status, 200, "{v:?}");
            assert_eq!(s.echo.requests().len(), 1);
        }
    }

    #[test]
    #[ignore = "gateway layer: needs HOPAE_E2E_GATEWAY_BINARY (make e2e)"]
    fn s015_12_handoff_lands_on_login_entry_whatever_the_target() {
        // The three-route fragment: public `/`, protected `/admin`, and `site-hopae`.
        let routes = GatewayRoutes::new()
            .path_scoped(APP_HOST, "/admin")
            .hopae_prefix(APP_HOST)
            .portal(PORTAL_HOST);
        let Some(s) = Stack::with_routes("s015_12", routes) else {
            return;
        };
        let cases = [
            // (entry path, where the browser ends up)
            ("/_hopae/login", "/"),
            (
                "/_hopae/login?return=%2Fpublic%2Fpage%3Fx%3D1",
                "/public/page?x=1",
            ),
            ("/_hopae/login?return=%2Fadmin%2Fx", "/admin/x"),
        ];
        for (entry, end) in cases {
            let b = s.gw.browser();
            s.echo.clear();
            let first = nav(&b, &s.app, entry);
            assert_eq!(first.status, 302, "{entry}: {first:?}");
            let c = b.login_from(&s.idp, first);
            // The code is delivered to the entry point, whatever the target's path.
            assert!(
                c.handoff_location
                    .starts_with("https://app.example.test/_hopae/login?return="),
                "{entry}: {}",
                c.handoff_location
            );
            let redeemed = b.redeem(&c);
            assert_eq!(redeemed.status, 302, "{entry}: {redeemed:?}");
            assert_eq!(
                redeemed.location(),
                Some(format!("https://app.example.test{end}").as_str()),
                "{entry}"
            );
            assert!(
                b.jar.for_host(APP_HOST).value(HANDLE).is_some(),
                "{entry}: the handle is planted"
            );
            assert!(
                s.echo.requests().is_empty(),
                "{entry}: nothing, least of all the code, reached the upstream: {:?}",
                s.echo.requests()
            );
            // The clean target is then an ordinary request on its own route.
            let landed = b.follow(&s.app, &redeemed);
            assert_eq!(landed.status, 200, "{entry}: {landed:?}");
            let seen = s.echo.requests();
            assert_eq!(seen.len(), 1, "{entry}");
            assert!(
                !seen[0].path().contains("_hopae_handoff") && !seen[0].path().contains("_hopae/"),
                "{entry}: {:?}",
                seen[0]
            );
        }
    }

    #[test]
    #[ignore = "gateway layer: needs HOPAE_E2E_GATEWAY_BINARY (make e2e)"]
    fn s015_11_hc12_strips_hopae_cookies_upstream() {
        let Some(s) = Stack::basic("s015_11") else {
            return;
        };
        let b = s.logged_in("/admin/x");
        let h1 = b.jar.for_host(APP_HOST).value(HANDLE).expect("handle");
        let b1 = b.jar.for_host(APP_HOST).value(BIND).expect("binding");
        s.echo.clear();
        s.gw.tap.clear();
        // Other cookies are kept, in order.
        let cookie = format!("theme=dark; {HANDLE}={h1}; {BIND}={b1}; lang=ko");
        let r = b.fresh_jar_get(&s.app, "/x", &cookie);
        assert_eq!(r.status, 200, "{r:?}");
        let calls = s.gw.tap.calls();
        let seen_by_verify = calls.last().and_then(|c| c.header("cookie")).unwrap_or("");
        assert!(
            seen_by_verify.contains(HANDLE) && seen_by_verify.contains(BIND),
            "the verify call received the full cookie header: {seen_by_verify:?}"
        );
        let up = s.echo.requests();
        assert_eq!(up.len(), 1);
        assert_eq!(up[0].header("cookie"), Some("theme=dark; lang=ko"));
        assert!(
            up[0].header("x-forwarded-user").is_some(),
            "identity headers"
        );
        // Only Hopae cookies: no cookie header at all upstream.
        s.echo.clear();
        let only = format!("{HANDLE}={h1}; {BIND}={b1}");
        let r = b.fresh_jar_get(&s.app, "/x", &only);
        assert_eq!(r.status, 200, "{r:?}");
        let up = s.echo.requests();
        assert_eq!(up.len(), 1);
        assert_eq!(up[0].header("cookie"), None, "{:?}", up[0]);
        // No upstream request ever carries a Hopae cookie.
        for r in s.echo.requests() {
            assert!(
                !r.header("cookie").unwrap_or("").contains("__Host-hopae"),
                "{r:?}"
            );
        }
    }

    #[test]
    #[ignore = "gateway layer: needs HOPAE_E2E_GATEWAY_BINARY (make e2e)"]
    fn gateway_entry_point_flow_through_gateway() {
        let Some(s) = Stack::basic("s015_flow") else {
            return;
        };
        let b = s.logged_in("/admin/x");
        s.echo.clear();
        // logout entry -> portal confirmation -> confirmed POST -> signed-out page.
        let r = nav(&b, &s.app, "/_hopae/logout?return=%2Fdocs");
        assert_eq!(r.status, 302, "{r:?}");
        let (portal_host, pq) = Browser::split_location(r.location().unwrap());
        assert_eq!(portal_host, PORTAL_HOST);
        let page = b.get_cross_site(&portal_host, &pq);
        assert_eq!(page.status, 200, "{page:?}");
        let txn = pq.split("txn=").nth(1).unwrap().to_string();
        let out = b.send(
            &portal_host,
            Req::post("/logout")
                .form(&[("csrf", &csrf_of(&page.body)), ("txn", &txn)])
                .header("origin", PORTAL_URL),
        );
        assert_eq!(out.status, 200, "{out:?}");
        assert!(
            links(&out.body).contains(&format!("https://{APP}/docs")),
            "{}",
            out.body
        );
        // The next navigation requires login again; the upstream saw nothing.
        let next = nav(&b, &s.app, "/docs");
        assert_eq!(next.status, 302, "{next:?}");
        assert!(
            next.location()
                .unwrap()
                .starts_with("https://auth.example.test/login?txn="),
            "{next:?}"
        );
        assert!(s.echo.requests().is_empty(), "{:?}", s.echo.requests());
    }
}
