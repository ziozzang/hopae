//! Scenario 300: administrator access to the console (handle authentication,
//! grants, roles, CSRF, peers and direct connections).
//!
//! W1-A owns every case here except 300-6, 300-8, 300-15, 300-16, 300-17,
//! 300-A9 and 300-A10 (W1-C and W1-D append those functions). Grants are
//! written straight into the store (`kit::grant`) so the cases do not depend
//! on the command line; the gateway's calls are made through the harness's
//! verify endpoint client (the real gateway layer is W2's).
//!
#![allow(dead_code, unused_imports)]

use std::time::Duration;

use serde_json::{Value, json};

use crate::support::{
    AdminClient, Fixture, Hopae, MockIdp, RawReq, Response, VerifyRequest, client::send,
};

pub(crate) mod kit {
    //! Shared by the console scenarios (300 to 304).
    #![allow(dead_code)]

    use super::*;
    use crate::support::{Jar, Req};

    pub const APP_HOST: &str = "app.example.test";
    pub const UA_IP: &str = "192.0.2.10";

    /// A signed-in console session as a browser holds it.
    pub struct Signed {
        pub handle: String,
        pub user_id: String,
        pub session_id: String,
        /// The cookies of the portal host (its handle), for sign-out.
        pub portal_jar: Jar,
        pub ip: String,
    }

    pub fn spawn_with(fixture: Fixture, profile: &str) -> (MockIdp, Hopae) {
        let idp = MockIdp::start(profile);
        let h = Hopae::spawn(fixture, &idp, &[]);
        (idp, h)
    }

    pub fn spawn() -> (MockIdp, Hopae) {
        spawn_with(Fixture::new("m4-admin"), "auth_time_present")
    }

    fn path_of(u: &str) -> String {
        let u = url::Url::parse(u).expect("url");
        match u.query() {
            Some(q) => format!("{}?{q}", u.path()),
            None => u.path().to_string(),
        }
    }

    fn set_cookie_value(r: &Response, name: &str) -> Option<String> {
        r.set_cookies().into_iter().find_map(|c| {
            let (n, rest) = c.split_once('=')?;
            (n == name).then(|| rest.split(';').next().unwrap_or("").to_string())
        })
    }

    /// The gateway's part of a login on `host`: `verify` calls with the
    /// cookies the host's jar holds.
    pub struct Edge<'a> {
        pub h: &'a Hopae,
        pub host: String,
        pub scheme: &'static str,
        pub jar: Jar,
        pub ip: String,
    }

    impl<'a> Edge<'a> {
        pub fn new(h: &'a Hopae, host: &str, ip: &str) -> Edge<'a> {
            Edge {
                h,
                host: host.to_string(),
                scheme: if h.is_secure() { "https" } else { "http" },
                jar: Jar::new(),
                ip: ip.to_string(),
            }
        }

        pub fn verify(&self, url: &str) -> Response {
            let base = self.h.cookie_name();
            let hj = self.jar.for_host(&self.host);
            let mut req = VerifyRequest::document(url).ip(&self.ip);
            for n in [base.clone(), format!("{base}_bind")] {
                if let Some(v) = hj.value(&n) {
                    req = req.cookie(&n, &v);
                }
            }
            let r = self.h.verify(req);
            for c in r.set_cookies() {
                self.jar.store(&self.host, "/", self.h.is_secure(), c);
            }
            r
        }

        pub fn url(&self, path: &str) -> String {
            format!("{}://{}{path}", self.scheme, self.host)
        }

        /// The handle cookie the host's jar holds.
        pub fn handle(&self) -> Option<String> {
            self.jar.for_host(&self.host).value(&self.h.cookie_name())
        }
    }

    /// Sign `sub` in on `host` through the ordinary flow (verify, portal,
    /// provider, callback, handoff) and return the console-facing result.
    #[allow(clippy::too_many_arguments)]
    pub fn login_on(
        h: &Hopae,
        idp: &MockIdp,
        host: &str,
        path: &str,
        sub: &str,
        email: &str,
        name: &str,
        ip: &str,
    ) -> Signed {
        idp.set_user(sub, email, true, name);
        idp.set_subject(sub);
        let edge = Edge::new(h, host, ip);
        let first = edge.verify(&edge.url(path));
        assert_eq!(
            first.status,
            302,
            "first hop: {first:?} reason {:?}",
            first.header("x-hopae-reason")
        );
        let portal_jar = Jar::new();
        let portal = h.portal_with(portal_jar.clone()).with_ip(ip);
        let to_portal = first.location().expect("portal location").to_string();
        let ppath = path_of(&to_portal);
        let page = portal.get(&ppath);
        let authorize = if page.status == 302 {
            page.location().expect("provider redirect").to_string()
        } else {
            let csrf = page
                .body
                .split("name=\"csrf\" value=\"")
                .nth(1)
                .and_then(|r| r.split('"').next())
                .expect("csrf field")
                .to_string();
            let txn = ppath.split("txn=").nth(1).expect("txn").to_string();
            let r = portal.send(
                Req::post("/login/mock")
                    .form(&[("csrf", &csrf), ("txn", &txn)])
                    .header("origin", &portal_origin(h)),
            );
            assert_eq!(r.status, 302, "{r:?}");
            r.location().expect("provider redirect").to_string()
        };
        let cb_path = idp.follow_authorization(&authorize);
        let back = portal.send(Req::get(&cb_path).cross_site_navigation());
        assert_eq!(back.status, 302, "callback: {back:?}");
        let handoff = back.location().expect("handoff").to_string();
        let redeem = edge.verify(&handoff);
        assert_eq!(redeem.status, 302, "handoff: {redeem:?}");
        let handle = edge.handle().expect("handle planted");
        let ev = h.hooks.events(Some("session.created"), None);
        let created = ev.last().expect("session.created");
        Signed {
            handle,
            user_id: created["user_id"].as_str().expect("user").to_string(),
            session_id: created["session_id"].as_str().expect("session").to_string(),
            portal_jar,
            ip: ip.to_string(),
        }
    }

    /// The origin browsers send for the portal.
    pub fn portal_origin(h: &Hopae) -> String {
        h.config()["portal"]["public_url"]
            .as_str()
            .expect("portal.public_url")
            .trim_end_matches('/')
            .to_string()
    }

    pub fn console_login(
        h: &Hopae,
        idp: &MockIdp,
        sub: &str,
        email: &str,
        name: &str,
        ip: &str,
    ) -> Signed {
        login_on(h, idp, &h.console_host(), "/", sub, email, name, ip)
    }

    /// Single sign-on of an existing session onto `host`: the handle the
    /// application host gets (the portal handle is in `s.portal_jar`).
    pub fn sso_handle(h: &Hopae, s: &Signed, host: &str) -> String {
        let edge = Edge::new(h, host, &s.ip);
        let first = edge.verify(&edge.url("/"));
        assert_eq!(first.status, 302, "{first:?}");
        let portal = h.portal_with(s.portal_jar.clone()).with_ip(&s.ip);
        let hop = portal.send(Req::get(&path_of(first.location().expect("portal"))));
        assert_eq!(hop.status, 302, "single sign-on: {hop:?}");
        let redeem = edge.verify(hop.location().expect("handoff"));
        assert_eq!(redeem.status, 302, "{redeem:?}");
        edge.handle().expect("handle")
    }

    pub struct Users {
        pub a: Signed,
        pub v: Signed,
        pub n: Signed,
    }

    /// `u_a` (admin), `u_v` (viewer), `u_n` (no grant), each signed in on the console host.
    pub fn users(h: &Hopae, idp: &MockIdp) -> Users {
        let a = console_login(h, idp, "sub-a", "a@example.test", "Ada Admin", UA_IP);
        let v = console_login(h, idp, "sub-v", "v@example.test", "Vera Viewer", UA_IP);
        let n = console_login(h, idp, "sub-n", "n@example.test", "Nia Nobody", UA_IP);
        grant(h, &a.user_id, "admin");
        grant(h, &v.user_id, "viewer");
        Users { a, v, n }
    }

    pub fn setup() -> (MockIdp, Hopae, Users) {
        let (idp, h) = spawn();
        let u = users(&h, &idp);
        (idp, h, u)
    }

    // ---- direct store access (the cases do not depend on the command line) --

    pub fn db(h: &Hopae) -> rusqlite::Connection {
        let dir = h.config()["state_dir"].as_str().expect("state_dir");
        let c = rusqlite::Connection::open(std::path::Path::new(dir).join("hopae.db"))
            .expect("open the store");
        c.busy_timeout(Duration::from_secs(10)).expect("busy");
        c
    }

    pub fn now_secs(h: &Hopae) -> i64 {
        h.hooks.now_ms() / 1000
    }

    pub fn grant(h: &Hopae, user_id: &str, role: &str) {
        db(h)
            .execute(
                "INSERT INTO admin_grants (user_id, role, managed_by, granted_at, granted_by) VALUES (?1, ?2, 'api', ?3, 'cli')
                 ON CONFLICT(user_id) DO UPDATE SET role = excluded.role, managed_by = 'api', revoked_at = NULL, revoked_by = NULL",
                rusqlite::params![user_id, role, now_secs(h)],
            )
            .expect("grant");
    }

    pub fn revoke(h: &Hopae, user_id: &str) {
        db(h)
            .execute(
                "UPDATE admin_grants SET revoked_at = ?2, revoked_by = 'cli', managed_by = 'api' WHERE user_id = ?1",
                rusqlite::params![user_id, now_secs(h)],
            )
            .expect("revoke");
    }

    pub fn count(h: &Hopae, sql: &str) -> i64 {
        db(h).query_row(sql, [], |r| r.get(0)).expect("count")
    }

    pub fn user_status(h: &Hopae, user_id: &str) -> String {
        db(h)
            .query_row(
                "SELECT status FROM users WHERE user_id = ?1",
                [user_id],
                |r| r.get(0),
            )
            .expect("user status")
    }

    pub fn session_terminated(h: &Hopae, session_id: &str) -> Option<String> {
        db(h)
            .query_row(
                "SELECT terminated_reason FROM sessions WHERE session_id = ?1 AND terminated_at IS NOT NULL",
                [session_id],
                |r| r.get::<_, Option<String>>(0),
            )
            .ok()
            .flatten()
    }

    // ---- observation -------------------------------------------------------

    pub fn metric(h: &Hopae, series: &str) -> i64 {
        h.hooks.counters()["metrics"][series].as_i64().unwrap_or(0)
    }

    /// Events of `kind`, polled until `want` of them exist (diagnostic events
    /// reach the table asynchronously).
    pub fn events_of(h: &Hopae, kind: &str, want: usize) -> Vec<Value> {
        let mut last = Vec::new();
        for _ in 0..100 {
            last = h.hooks.events(Some(kind), None);
            if last.len() >= want {
                return last;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        last
    }

    /// The sampled `verify.denied` rows with `reason`: the sampling window
    /// (60 s) is closed first, then the held row is awaited.
    pub fn sampled_denials(h: &Hopae, reason: &str) -> Vec<Value> {
        h.advance(Duration::from_secs(61));
        let mut rows = Vec::new();
        for _ in 0..100 {
            rows = h
                .hooks
                .events(Some("verify.denied"), None)
                .into_iter()
                .filter(|e| e["reason"] == reason)
                .collect();
            if !rows.is_empty() {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        rows
    }

    pub fn events_with_reason(h: &Hopae, kind: &str, reason: &str) -> Vec<Value> {
        h.hooks
            .events(Some(kind), None)
            .into_iter()
            .filter(|e| e["reason"] == reason)
            .collect()
    }

    /// A raw request to the admin listener from the trusted loopback peer,
    /// with exactly these headers (no defaults).
    pub fn raw(
        h: &Hopae,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Response {
        let mut r = RawReq::new(method, path, &h.console_host());
        for (k, v) in headers {
            r = r.header(k, v);
        }
        r.body = body.to_vec();
        send(h.admin.expect("admin listener"), r)
    }

    /// The pinned headers every console response carries.
    pub fn assert_pinned_headers(r: &Response) {
        assert_eq!(r.header("cache-control"), Some("no-store"), "{r:?}");
        assert_eq!(r.header("x-content-type-options"), Some("nosniff"), "{r:?}");
        assert_eq!(r.header("referrer-policy"), Some("same-origin"), "{r:?}");
        assert_eq!(r.header("x-frame-options"), Some("DENY"), "{r:?}");
        assert_eq!(r.header("x-robots-tag"), Some("noindex"), "{r:?}");
        assert_eq!(
            r.header("content-security-policy"),
            Some(
                "default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'"
            ),
            "{r:?}"
        );
        assert!(!r.body.contains("<script"), "no script in any body");
    }

    /// The body with the request id line removed (two answers to different
    /// requests are otherwise comparable).
    pub fn without_request_id(body: &str) -> String {
        body.lines()
            .filter(|l| !l.contains("class=\"rid\""))
            .collect::<Vec<_>>()
            .join("\n")
    }

    pub fn console_url(h: &Hopae) -> String {
        format!("{}/", h.console_origin())
    }

    pub fn admin(h: &Hopae) -> AdminClient<'_> {
        h.admin_client()
    }

    /// The error code of a console answer: the JSON `error`, or the code a
    /// page shows beneath its text.
    pub fn error_code(r: &Response) -> String {
        if let Ok(v) = serde_json::from_str::<Value>(&r.body) {
            return v["error"].as_str().unwrap_or_default().to_string();
        }
        r.body
            .split("<code>")
            .nth(1)
            .and_then(|s| s.split("</code>").next())
            .unwrap_or_default()
            .to_string()
    }

    /// A syntactically valid handle that no session owns.
    pub const UNKNOWN_HANDLE: &str = "v1.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
}

use kit::*;

// ---- main flow ---------------------------------------------------------------

#[test]
fn s300_1_first_visit_logs_in_and_lands_with_console_handle() {
    // The gateway's calls made through the verify endpoint: the first visit is
    // the unauthenticated redirect, the ordinary login follows, the handoff
    // plants the handle on the console host, and only then does the browser's
    // request reach the admin listener (with its cookie).
    let (idp, h) = spawn();
    idp.set_user("sub-a", "a@example.test", true, "Ada Admin");
    idp.set_subject("sub-a");
    let requests_before = h.hooks.counters()["metrics"]
        .as_object()
        .unwrap()
        .iter()
        .filter(|(k, _)| k.starts_with("hopae_admin_requests_total"))
        .count();
    let edge = Edge::new(&h, &h.console_host(), UA_IP);
    let first = edge.verify(&edge.url("/users"));
    assert_eq!(first.status, 302, "{first:?}");
    let bind = format!("{}_bind", h.cookie_name());
    assert!(
        first
            .set_cookies()
            .iter()
            .any(|c| c.starts_with(&format!("{bind}="))),
        "the bind cookie is planted on the console host: {:?}",
        first.set_cookies()
    );
    let portal_jar = crate::support::Jar::new();
    let portal = h.portal_with(portal_jar).with_ip(UA_IP);
    let ppath = {
        let u = url::Url::parse(first.location().unwrap()).unwrap();
        format!("{}?{}", u.path(), u.query().unwrap_or(""))
    };
    let page = portal.get(&ppath);
    let authorize = if page.status == 302 {
        page.location().unwrap().to_string()
    } else {
        let csrf = page
            .body
            .split("name=\"csrf\" value=\"")
            .nth(1)
            .and_then(|r| r.split('"').next())
            .unwrap()
            .to_string();
        let txn = ppath.split("txn=").nth(1).unwrap().to_string();
        let r = portal.send(
            crate::support::Req::post("/login/mock")
                .form(&[("csrf", &csrf), ("txn", &txn)])
                .header("origin", &portal_origin(&h)),
        );
        r.location().unwrap().to_string()
    };
    let cb = idp.follow_authorization(&authorize);
    let back = portal.send(crate::support::Req::get(&cb).cross_site_navigation());
    assert_eq!(back.status, 302, "{back:?}");
    let handoff = back.location().unwrap().to_string();
    assert!(
        handoff.starts_with(&format!(
            "{}/_hopae/login?return=%2Fusers&_hopae_handoff=",
            h.console_origin()
        )) || handoff.starts_with(&format!(
            "{}/_hopae/login?return=/users&_hopae_handoff=",
            h.console_origin()
        )),
        "the handoff lands on the console host's entry point: {handoff}"
    );
    let redeem = edge.verify(&handoff);
    assert_eq!(redeem.status, 302, "{redeem:?}");
    assert!(edge.handle().is_some(), "the handle is planted: {redeem:?}");

    // The transaction named the console application.
    let started = h.hooks.events(Some("login.started"), None);
    assert_eq!(started.last().unwrap()["app_id"], "admin", "{started:?}");
    // The admin listener has recorded no request so far.
    let requests_now = h.hooks.counters()["metrics"]
        .as_object()
        .unwrap()
        .iter()
        .filter(|(k, _)| k.starts_with("hopae_admin_requests_total"))
        .count();
    assert_eq!(
        requests_now, requests_before,
        "nothing reached the listener before the cookie"
    );

    // The next request reaches the listener with the cookie present (no
    // stripping): the handle is accepted, and without a grant the answer names
    // the signed-in user.
    let r = admin(&h).with_handle(&edge.handle().unwrap()).get("/v1/me");
    assert_eq!(r.status, 403, "{r:?}");
    assert_eq!(r.json()["error"], "not_admin", "{r:?}");
}

#[test]
fn s300_2_granted_user_served_from_handle_not_headers() {
    let (_idp, h, u) = setup();
    let before = metric(
        &h,
        "hopae_admin_requests_total{role=\"admin\",outcome=\"ok\"}",
    );
    let r = admin(&h).with_handle(&u.a.handle).get_with(
        "/v1/me",
        &[
            ("x-forwarded-user", &u.n.user_id),
            ("x-forwarded-email", "n@example.test"),
            ("x-hopae-session", &u.n.session_id),
        ],
    );
    assert_eq!(r.status, 200, "{r:?}");
    let j = r.json();
    assert_eq!(j["user_id"], u.a.user_id.as_str(), "{j}");
    assert_eq!(j["role"], "admin");
    assert_eq!(j["session_id"], u.a.session_id.as_str());
    assert_eq!(j["aal"], 1);
    assert_eq!(j["email"], "a@example.test");
    let (auth_time, source): (i64, String) = db(&h)
        .query_row(
            "SELECT auth_time, auth_time_source FROM sessions WHERE session_id = ?1",
            [&u.a.session_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(j["auth_time"], auth_time, "{j}");
    assert_eq!(j["auth_time_source"], source.as_str(), "{j}");
    assert_pinned_headers(&r);

    let page = admin(&h).with_handle(&u.a.handle).get("/");
    assert_eq!(page.status, 200, "{page:?}");
    assert!(page.body.contains("<table"), "the status page");

    // The handle's `last_seen_at` is touched as a verify would (coalesced to 30 s).
    let seen = |h: &Hopae| -> i64 {
        db(h)
            .query_row(
                "SELECT last_seen_at FROM session_handles WHERE session_id = ?1 AND host = ?2",
                rusqlite::params![u.a.session_id, h.console_host()],
                |r| r.get(0),
            )
            .unwrap()
    };
    let t0 = seen(&h);
    h.advance(Duration::from_secs(120));
    assert_eq!(admin(&h).with_handle(&u.a.handle).get("/v1/me").status, 200);
    assert!(
        seen(&h) > t0,
        "last_seen_at moved from {t0} to {}",
        seen(&h)
    );
    assert!(
        metric(
            &h,
            "hopae_admin_requests_total{role=\"admin\",outcome=\"ok\"}"
        ) >= before + 3,
        "counted"
    );
}

#[test]
fn s300_3_user_without_grant_is_refused_and_named() {
    let (_idp, h, u) = setup();
    let page = admin(&h).with_handle(&u.n.handle).get("/users");
    let api = admin(&h).with_handle(&u.n.handle).get("/v1/users");
    assert_eq!(page.status, 403, "{page:?}");
    assert_eq!(api.status, 403, "{api:?}");
    assert!(page.body.contains(&u.n.user_id), "the page names the user");
    assert!(page.body.contains("n@example.test"), "and the address");
    assert!(
        !page.body.contains("href=\"/users\"") && !page.body.contains("href=\"/events\""),
        "and nothing else of the console: {}",
        page.body
    );
    assert_eq!(api.json(), json!({"error": "not_admin"}));
    assert!(page.set_cookies().is_empty() && api.set_cookies().is_empty());
    assert_pinned_headers(&page);
    assert_pinned_headers(&api);

    let denied = events_of(&h, "admin.denied", 2);
    assert_eq!(
        denied.len(),
        2,
        "one required event per request: {denied:?}"
    );
    for (e, endpoint) in denied.iter().zip(["/users", "/v1/users"]) {
        assert_eq!(e["user_id"], u.n.user_id.as_str(), "{e}");
        assert_eq!(e["session_id"], u.n.session_id.as_str(), "{e}");
        assert_eq!(e["reason"], "not_admin", "{e}");
        assert_eq!(e["app_id"], "admin", "{e}");
        assert_eq!(e["attrs"]["endpoint"], endpoint, "{e}");
        assert_eq!(e["attrs"]["method"], "GET", "{e}");
    }
    // The handle stays valid for the console host: a later grant makes it work.
    grant(&h, &u.n.user_id, "viewer");
    let me = admin(&h).with_handle(&u.n.handle).get("/v1/me");
    assert_eq!(me.status, 200, "{me:?}");
    assert_eq!(me.json()["role"], "viewer");
}

#[test]
fn s300_4_read_only_administrator_reads_but_cannot_change() {
    let (_idp, h, u) = setup();
    for path in ["/v1/users", "/v1/sessions", "/v1/events", "/v1/status"] {
        let a = admin(&h).with_handle(&u.a.handle).get(path);
        let v = admin(&h).with_handle(&u.v.handle).get(path);
        assert_eq!(a.status, 200, "{path}: {a:?}");
        assert_eq!(v.status, 200, "{path}: {v:?}");
        if path == "/v1/status" {
            assert_eq!(a.json(), v.json(), "the same body for both roles");
        }
    }
    let r = admin(&h)
        .with_handle(&u.v.handle)
        .post_json(&format!("/v1/users/{}/disable", u.n.user_id), json!({}));
    assert_eq!(r.status, 403, "{r:?}");
    assert_eq!(r.json(), json!({"error": "role_insufficient"}));
    assert_eq!(user_status(&h, &u.n.user_id), "active");
    let denied = events_with_reason(&h, "admin.denied", "role_insufficient");
    assert_eq!(denied.len(), 1, "{denied:?}");
    assert_eq!(denied[0]["attrs"]["endpoint"], "/v1/users/{id}/disable");
    let page = admin(&h)
        .with_handle(&u.v.handle)
        .get(&format!("/users/{}", u.n.user_id));
    assert_eq!(page.status, 200, "{page:?}");
    assert!(
        !page.body.contains("<form"),
        "a viewer's user page has no disable, enable or terminate form"
    );
}

#[test]
fn extra_s300_4_viewer_status_is_the_same_and_mutations_are_refused() {
    // The part of 300-4 the listener owns: the status answer is the same for
    // both roles, and a mutation that carries the API requirements is refused
    // for a read-only administrator before any handler runs.
    let (_idp, h, u) = setup();
    let a = admin(&h).with_handle(&u.a.handle).get("/v1/status");
    let v = admin(&h).with_handle(&u.v.handle).get("/v1/status");
    assert_eq!((a.status, v.status), (200, 200), "{a:?} {v:?}");
    assert_eq!(a.json(), v.json());
    let r = admin(&h)
        .with_handle(&u.v.handle)
        .post_json(&format!("/v1/users/{}/disable", u.n.user_id), json!({}));
    assert_eq!(r.status, 403, "{r:?}");
    assert_eq!(r.json(), json!({"error": "role_insufficient"}));
    assert_eq!(user_status(&h, &u.n.user_id), "active");
    let denied = events_with_reason(&h, "admin.denied", "role_insufficient");
    assert_eq!(denied.len(), 1, "{denied:?}");
    assert_eq!(denied[0]["user_id"], u.v.user_id.as_str());
    assert_eq!(denied[0]["attrs"]["endpoint"], "/v1/users/{id}/disable");
    assert_eq!(denied[0]["attrs"]["method"], "POST");
    // A form post by a viewer is refused the same way (after its token check).
    let r = admin(&h).with_handle(&u.v.handle).post_form(
        &format!("/users/{}/disable", u.n.user_id),
        &[("csrf", "x")],
        Some(&h.console_origin()),
    );
    assert_eq!(r.status, 403, "{r:?}");
}

#[test]
fn s300_5_revoked_grant_stops_next_request() {
    let (_idp, h, u) = setup();
    assert_eq!(admin(&h).with_handle(&u.a.handle).get("/v1/me").status, 200);
    revoke(&h, &u.a.user_id);
    let r = admin(&h).with_handle(&u.a.handle).get("/v1/me");
    assert_eq!(r.status, 403, "{r:?}");
    assert_eq!(r.json(), json!({"error": "not_admin"}));
    let denied = events_with_reason(&h, "admin.denied", "not_admin");
    assert_eq!(denied.len(), 1, "{denied:?}");
    // The session itself is untouched: the handle still verifies on the
    // gateway listener as an ordinary allow for the console host.
    let v = h.verify(
        VerifyRequest::document(&console_url(&h))
            .ip(UA_IP)
            .cookie(&h.cookie_name(), &u.a.handle),
    );
    assert_eq!(v.status, 200, "{v:?}");
    assert!(session_terminated(&h, &u.a.session_id).is_none());
    // Re-granting makes the next request work.
    grant(&h, &u.a.user_id, "admin");
    assert_eq!(admin(&h).with_handle(&u.a.handle).get("/v1/me").status, 200);
}

#[test]
fn s300_7_console_app_policy_applies_to_console_handle() {
    let (idp, h, u) = setup();
    // The same session on the application host, for the unaffected-app clause.
    let app_handle = sso_handle(&h, &u.a, APP_HOST);

    // (a) 31 minutes of silence: the console handle's idle timer (30 m) ran
    // out, not the session's (24 h).
    h.advance(Duration::from_secs(31 * 60));
    let r = admin(&h).with_handle(&u.a.handle).get("/v1/me");
    assert_eq!(r.status, 403, "{r:?}");
    assert_eq!(r.json()["error"], "login_required", "{r:?}");
    let gw = h.verify(
        VerifyRequest::document(&console_url(&h))
            .ip(UA_IP)
            .cookie(&h.cookie_name(), &u.a.handle),
    );
    assert_eq!(
        gw.status, 302,
        "the gateway's verify would redirect: {gw:?}"
    );
    let app = h.verify(
        VerifyRequest::document("https://app.example.test/")
            .ip(UA_IP)
            .cookie(&h.cookie_name(), &app_handle),
    );
    assert_eq!(
        app.status, 200,
        "the application handle is unaffected: {app:?}"
    );

    // (b) a different client address: strict binding ends the session.
    let b = console_login(&h, &idp, "sub-b", "b@example.test", "Bea", UA_IP);
    grant(&h, &b.user_id, "admin");
    let r = admin(&h)
        .with_handle(&b.handle)
        .client_ip("198.51.100.7")
        .get("/v1/me");
    assert_eq!(r.status, 403, "{r:?}");
    assert_eq!(r.json()["error"], "login_required");
    assert_eq!(
        session_terminated(&h, &b.session_id).as_deref(),
        Some("binding_ip")
    );
    let term = h.hooks.events(Some("session.terminated"), None);
    assert!(
        term.iter()
            .any(|e| e["session_id"] == b.session_id.as_str() && e["reason"] == "binding_ip"),
        "{term:?}"
    );

    // (c) the user's authorization data changed: the implicit application
    // terminates on a change.
    let c = console_login(&h, &idp, "sub-c", "c@example.test", "Cy", UA_IP);
    grant(&h, &c.user_id, "admin");
    assert_eq!(admin(&h).with_handle(&c.handle).get("/v1/me").status, 200);
    db(&h)
        .execute(
            "UPDATE users SET authz_version = authz_version + 1 WHERE user_id = ?1",
            [&c.user_id],
        )
        .unwrap();
    let r = admin(&h).with_handle(&c.handle).get("/v1/me");
    assert_eq!(r.status, 403, "{r:?}");
    assert_eq!(r.json()["error"], "login_required");
    assert_eq!(
        session_terminated(&h, &c.session_id).as_deref(),
        Some("authz_change")
    );
}

#[test]
fn s300_9_mutations_carry_form_token_or_api_header() {
    let (_idp, h, u) = setup();
    let a = admin(&h).with_handle(&u.a.handle);
    let page = a.get(&format!("/users/{}", u.n.user_id));
    assert_eq!(page.status, 200, "{page:?}");
    let token = AdminClient::csrf_from_page(&page.body).expect("a csrf field");
    let r = a.post_form(
        &format!("/users/{}/disable", u.n.user_id),
        &[("csrf", &token)],
        Some(&h.console_origin()),
    );
    assert_eq!(r.status, 303, "{r:?}");
    assert_eq!(user_status(&h, &u.n.user_id), "disabled");
    let r = a.post_json(&format!("/v1/users/{}/enable", u.n.user_id), json!({}));
    assert_eq!(r.status, 200, "{r:?}");
    assert_eq!(r.json()["changed"], true);
    let r = a.post_json_raw(
        &format!("/v1/users/{}/disable", u.n.user_id),
        &[
            ("content-type", "application/json"),
            ("x-hopae-admin-request", "1"),
            ("origin", &h.console_origin()),
            ("sec-fetch-site", "same-origin"),
        ],
        b"{}",
    );
    assert_eq!(r.status, 200, "{r:?}");
    assert_eq!(r.json()["changed"], true);
    // The token was bound to Ha: another handle's request refuses it.
    let r = admin(&h).with_handle(&u.v.handle).post_form(
        &format!("/users/{}/enable", u.n.user_id),
        &[("csrf", &token)],
        Some(&h.console_origin()),
    );
    assert_eq!(r.status, 403, "{r:?}");
}

#[test]
fn extra_s300_9_the_listener_checks_every_mutation_before_its_handler() {
    // What the listener owns of 300-9: a mutation passes only with the API
    // requirements or a bound token, whatever the handler behind it does.
    let (_idp, h, u) = setup();
    let a = admin(&h).with_handle(&u.a.handle);
    let path = format!("/v1/users/{}/enable", u.n.user_id);
    let origin = h.console_origin();
    let refused = |r: Response, why: &str| {
        assert_eq!(r.status, 403, "{why}: {r:?}");
        assert_eq!(r.json()["error"], "csrf_rejected", "{why}: {r:?}");
    };
    // Missing marker header, wrong content type, cross-site, foreign origin.
    refused(
        a.post_json_raw(&path, &[("content-type", "application/json")], b"{}"),
        "no marker header",
    );
    refused(
        a.post_json_raw(
            &path,
            &[
                ("content-type", "text/plain"),
                ("x-hopae-admin-request", "1"),
            ],
            b"{}",
        ),
        "plain content type",
    );
    refused(
        a.post_json_raw(
            &path,
            &[
                ("content-type", "application/json"),
                ("x-hopae-admin-request", "1"),
                ("sec-fetch-site", "cross-site"),
            ],
            b"{}",
        ),
        "cross-site",
    );
    refused(
        a.post_json_raw(
            &path,
            &[
                ("content-type", "application/json"),
                ("x-hopae-admin-request", "1"),
                ("origin", "https://evil.example.org"),
            ],
            b"{}",
        ),
        "foreign origin",
    );
    // With the API requirements the request is the handler's, not a refusal.
    for extra in [
        vec![],
        vec![
            ("origin", origin.as_str()),
            ("sec-fetch-site", "same-origin"),
        ],
        vec![("sec-fetch-site", "none")],
    ] {
        let mut headers = vec![
            ("content-type", "application/json"),
            ("x-hopae-admin-request", "1"),
        ];
        headers.extend(extra);
        let r = a.post_json_raw(&path, &headers, b"{}");
        // The handler ran: enabling an active user is the documented no-op.
        assert_eq!(r.status, 200, "{r:?}");
        assert_eq!(r.json()["changed"], false, "{r:?}");
    }
    // A form without a token, with a forged one, or without the origin.
    let form_path = format!("/users/{}/enable", u.n.user_id);
    for (fields, origin_hdr, why) in [
        (vec![], Some(origin.as_str()), "no token"),
        (
            vec![("csrf", "forged")],
            Some(origin.as_str()),
            "forged token",
        ),
        (vec![("csrf", "forged")], None, "no origin"),
    ] {
        let r = a.post_form(&form_path, &fields, origin_hdr);
        assert_eq!(r.status, 403, "{why}: {r:?}");
    }
    assert_eq!(user_status(&h, &u.n.user_id), "active");
    let rejected = events_of(&h, "csrf.rejected", 7);
    assert!(rejected.len() >= 7, "{rejected:?}");
    for e in &rejected {
        assert_eq!(e["attrs"]["purpose"], "admin", "{e}");
        assert_eq!(e["user_id"], u.a.user_id.as_str(), "{e}");
        assert!(matches!(
            e["attrs"]["cause"].as_str(),
            Some("token" | "origin" | "expired")
        ));
    }
}

#[test]
fn s300_10_sign_out_from_console_ends_session_everywhere() {
    // The gateway layer's calls through the harness: the page's sign-out link
    // is the console host's logout entry point; the portal confirmation ends
    // the session.
    let (_idp, h, u) = setup();
    let cookie = h.cookie_name();
    assert_eq!(admin(&h).with_handle(&u.a.handle).get("/").status, 200);
    assert!(
        admin(&h)
            .with_handle(&u.a.handle)
            .get("/")
            .body
            .contains(&format!("{}/_hopae/logout", h.console_origin())),
        "every page links to the sign-out entry point"
    );
    let entry = h.verify(
        VerifyRequest::document(&format!("{}/_hopae/logout", h.console_origin()))
            .ip(UA_IP)
            .cookie(&cookie, &u.a.handle),
    );
    assert_eq!(entry.status, 302, "{entry:?}");
    let to_portal = entry.location().expect("portal logout");
    let ppath = {
        let u = url::Url::parse(to_portal).unwrap();
        format!("{}?{}", u.path(), u.query().unwrap_or(""))
    };
    let portal = h.portal_with(u.a.portal_jar.clone()).with_ip(UA_IP);
    let page = portal.send(crate::support::Req::get(&ppath).cross_site_navigation());
    assert_eq!(page.status, 200, "{page:?}");
    let csrf = AdminClient::csrf_from_page(&page.body).expect("csrf");
    let txn = ppath.split("txn=").nth(1).unwrap_or_default().to_string();
    let done = portal.send(
        crate::support::Req::post("/logout")
            .form(&[("csrf", &csrf), ("txn", &txn)])
            .header("origin", &portal_origin(&h)),
    );
    assert!(matches!(done.status, 200 | 302 | 303), "{done:?}");
    assert_eq!(
        session_terminated(&h, &u.a.session_id).as_deref(),
        Some("logout")
    );
    // Through the gateway the next request never reaches the listener...
    let gw = h.verify(
        VerifyRequest::document(&console_url(&h))
            .ip(UA_IP)
            .cookie(&cookie, &u.a.handle),
    );
    assert_eq!(gw.status, 302, "{gw:?}");
    // ...and a stale handle sent straight to the listener is refused.
    let r = admin(&h).with_handle(&u.a.handle).get("/v1/me");
    assert_eq!(r.status, 403, "{r:?}");
    assert_eq!(r.json()["error"], "login_required");
}

#[test]
fn s300_11_korean_pages_and_pinned_headers() {
    let (_idp, h, u) = setup();
    let ko = admin(&h).with_handle(&u.a.handle).lang("ko").get("/");
    let en = admin(&h).with_handle(&u.a.handle).lang("en").get("/");
    assert_eq!(ko.status, 200);
    assert!(
        ko.body.contains("lang=\"ko\"") && ko.body.contains("상태"),
        "{}",
        ko.body
    );
    assert!(
        en.body.contains("lang=\"en\"") && en.body.contains("Applications"),
        "{}",
        en.body
    );
    let j_ko = admin(&h)
        .with_handle(&u.a.handle)
        .lang("ko")
        .get("/v1/status");
    let j_en = admin(&h)
        .with_handle(&u.a.handle)
        .lang("en")
        .get("/v1/status");
    assert_eq!(
        j_ko.json(),
        j_en.json(),
        "the JSON is unchanged by the language"
    );

    // Every kind of response carries the pinned headers and no script.
    let mut seen = vec![ko, en, j_ko];
    seen.push(admin(&h).get("/v1/me")); // 403 login_required (JSON)
    seen.push(admin(&h).get("/")); // 403 login_required (page)
    seen.push(admin(&h).with_handle(&u.n.handle).get("/")); // 403 not_admin (page)
    seen.push(admin(&h).with_handle(&u.a.handle).get("/no/such/page")); // 404 (page)
    seen.push(admin(&h).with_handle(&u.a.handle).get("/v1/no/such")); // 404 (JSON)
    seen.push(admin(&h).with_handle(&u.a.handle).get("/assets/admin.css")); // 200
    seen.push(
        admin(&h)
            .with_handle(&u.a.handle)
            .get("/?x=".to_string().as_str()),
    );
    let big = format!("/?x={}", "a".repeat(5000));
    seen.push(admin(&h).with_handle(&u.a.handle).get(&big)); // 413
    seen.push(raw(
        &h,
        "OPTIONS",
        "/v1/me",
        &[("x-forwarded-host", &h.console_host())],
        b"",
    )); // 404
    seen.push(admin(&h).from_peer("127.0.0.2".parse().unwrap()).get("/")); // 403 untrusted_peer
    for r in &seen {
        assert_pinned_headers(r);
    }
    let statuses: Vec<u16> = seen.iter().map(|r| r.status).collect();
    assert_eq!(
        statuses,
        [
            200, 200, 200, 403, 403, 403, 404, 404, 200, 200, 413, 404, 403
        ],
        "{statuses:?}"
    );
    // A 503: the store stalls past the verify budget.
    h.hooks.stall(2000);
    let r = admin(&h).with_handle(&u.a.handle).get("/v1/me");
    h.hooks.stall_off();
    assert_eq!(r.status, 503, "{r:?}");
    assert_eq!(r.json()["error"], "store_unavailable");
    assert_pinned_headers(&r);
}

#[test]
fn s300_12_console_route_without_auth_is_403_not_a_loop() {
    // The route is public (operator mistake): browsers with no cookies reach
    // the listener directly. It answers `403 login_required` with the console
    // link and starts no login. (`hopae --check`'s drift warning is W1-C's.)
    let (_idp, h) = spawn();
    let txns = count(&h, "SELECT COUNT(*) FROM login_txns");
    let page = admin(&h).get("/");
    assert_eq!(page.status, 403, "{page:?}");
    assert!(
        page.body.contains(&format!("href=\"{}\"", console_url(&h))),
        "the page links to the console URL: {}",
        page.body
    );
    let api = admin(&h).get("/v1/me");
    assert_eq!(api.status, 403);
    assert_eq!(
        api.json(),
        json!({"error": "login_required", "login": console_url(&h)})
    );
    assert!(page.set_cookies().is_empty() && api.set_cookies().is_empty());
    assert_eq!(
        count(&h, "SELECT COUNT(*) FROM login_txns"),
        txns,
        "no login started"
    );
}

#[test]
fn s300_13_peer_that_is_not_the_gateway_is_refused_by_default() {
    let (_idp, h, u) = setup();
    let stranger: std::net::IpAddr = "127.0.0.2".parse().unwrap();
    let calls = |h: &Hopae| -> Vec<u64> {
        [
            "lookup_handle",
            "admin_grant",
            "user_authz",
            "session",
            "touch_handle",
        ]
        .iter()
        .map(|m| h.hooks.store_calls(m))
        .collect()
    };
    let before = calls(&h);
    let denied_before = metric(&h, "hopae_admin_denied_total{reason=\"untrusted_peer\"}");
    let r = admin(&h)
        .with_handle(&u.a.handle)
        .from_peer(stranger)
        .get("/v1/me");
    assert_eq!(r.status, 403, "{r:?}");
    assert_eq!(r.json(), json!({"error": "untrusted_peer"}));
    assert_eq!(calls(&h), before, "no cookie was read, no store call made");
    assert!(
        h.log().contains("127.0.0.2"),
        "a warning names the peer: {}",
        h.log()
    );
    assert_eq!(
        metric(&h, "hopae_admin_denied_total{reason=\"untrusted_peer\"}"),
        denied_before + 1
    );
    // The warning is rate limited to one line per peer per minute.
    for _ in 0..5 {
        admin(&h).from_peer(stranger).get("/v1/me");
    }
    let lines = h.log().matches("outside trusted_proxies").count();
    assert_eq!(lines, 1, "one warning per peer per minute");
    let ev = sampled_denials(&h, "untrusted_peer");
    assert_eq!(ev.len(), 1, "a sampled verify.denied: {ev:?}");
    assert_eq!(ev[0]["client_ip"], "127.0.0.2");
    assert_eq!(ev[0]["app_id"], "admin");
    assert_eq!(ev[0]["attrs"]["sampled_count"], 6, "{ev:?}");

    // Under `as_client` the peer itself is the client and the transport is
    // not https: login_required (insecure_transport), as on the portal.
    let (idp2, h2) = spawn_with(
        Fixture::with(
            "m4-admin",
            json!({"admin": {"untrusted_peers": "as_client"}}),
        ),
        "auth_time_present",
    );
    let u2 = users(&h2, &idp2);
    let r = admin(&h2)
        .with_handle(&u2.a.handle)
        .from_peer(stranger)
        .get("/v1/me");
    assert_eq!(r.status, 403, "{r:?}");
    assert_eq!(r.json()["error"], "login_required");
    let ev = sampled_denials(&h2, "insecure_transport");
    assert_eq!(ev.len(), 1, "{ev:?}");
    assert_eq!(ev[0]["client_ip"], "127.0.0.2");
}

#[test]
fn s300_14_listener_denials_recorded_like_gateway_denials() {
    let (_idp, h, _u) = setup();
    let ip = "203.0.113.9";
    let cookie = h.cookie_name();
    let run = |label: &str, cookie_value: Option<String>, forged: bool| {
        for _ in 0..50 {
            let c = admin(&h).client_ip(ip);
            let mut extra: Vec<(&str, &str)> = Vec::new();
            if forged {
                extra.push(("x-forwarded-user", "u_a"));
                extra.push(("x-forwarded-email", "a@example.test"));
                extra.push(("x-hopae-session", "s_forged"));
            }
            if let Some(v) = &cookie_value {
                extra.push(("cookie", v.as_str()));
            }
            let r = c.get_with("/v1/me", &extra);
            assert_eq!(r.status, 403, "{label}: {r:?}");
            assert_eq!(r.json()["error"], "login_required", "{label}");
        }
    };
    let login_decisions = |h: &Hopae| {
        metric(
            h,
            "hopae_verify_decisions_total{decision=\"login\",reason=\"login_required\"}",
        )
    };
    let d0 = login_decisions(&h);
    let denied = |h: &Hopae, reason: &str| {
        metric(
            h,
            &format!("hopae_admin_denied_total{{reason=\"{reason}\"}}"),
        )
    };
    let (u0, m0, l0) = (
        denied(&h, "unknown_handle"),
        denied(&h, "malformed_handle"),
        denied(&h, "login_required"),
    );
    run(
        "unknown handle",
        Some(format!("{cookie}={UNKNOWN_HANDLE}")),
        false,
    );
    run("malformed cookie", Some(format!("{cookie}=garbage")), false);
    run("no cookie", None, false);
    run("forged identity headers", None, true);
    assert_eq!(denied(&h, "unknown_handle"), u0 + 50);
    assert_eq!(denied(&h, "malformed_handle"), m0 + 50);
    assert_eq!(denied(&h, "login_required"), l0 + 100);
    assert!(
        login_decisions(&h) >= d0 + 200,
        "every series is counted as a login decision"
    );
    // One sampled verify.denied per (client address, reason) per 60 s, written
    // with the true volume when the window closes.
    for (reason, volume) in [
        ("unknown_handle", 50),
        ("malformed_handle", 50),
        ("login_required", 100),
    ] {
        let evs = sampled_denials(&h, reason);
        assert_eq!(evs.len(), 1, "{reason}: {evs:?}");
        assert_eq!(
            evs[0]["attrs"]["sampled_count"], volume,
            "{reason}: {evs:?}"
        );
        assert_eq!(evs[0]["app_id"], "admin", "{reason}");
        assert_eq!(evs[0]["client_ip"], ip, "{reason}");
        assert!(
            evs[0]["request_id"]
                .as_str()
                .is_some_and(|r| r.starts_with("r_"))
        );
    }
    assert!(
        h.hooks.events(Some("admin.denied"), None).is_empty(),
        "no required event is written"
    );
}

// ---- abuse cases -------------------------------------------------------------

#[test]
fn s300_a1_terminated_handle_and_foreign_token_useless() {
    let (idp, h, u) = setup();
    let page = admin(&h)
        .with_handle(&u.v.handle)
        .get(&format!("/users/{}", u.n.user_id));
    let token_v = AdminClient::csrf_from_page(&page.body).expect("a token for Hv");
    // A fresh handle of u_a.
    let a2 = console_login(&h, &idp, "sub-a", "a@example.test", "Ada Admin", UA_IP);
    let r = admin(&h).with_handle(&a2.handle).post_form(
        &format!("/users/{}/disable", u.n.user_id),
        &[("csrf", &token_v)],
        Some(&h.console_origin()),
    );
    assert_eq!(r.status, 403, "{r:?}");
    let rejected = events_of(&h, "csrf.rejected", 1);
    assert_eq!(rejected[0]["attrs"]["cause"], "token", "{rejected:?}");
    assert_eq!(rejected[0]["attrs"]["purpose"], "admin");
    // A token older than ten minutes.
    let page = admin(&h)
        .with_handle(&a2.handle)
        .get(&format!("/users/{}", u.n.user_id));
    let token_a = AdminClient::csrf_from_page(&page.body).expect("token");
    h.advance(Duration::from_secs(11 * 60));
    let r = admin(&h).with_handle(&a2.handle).post_form(
        &format!("/users/{}/disable", u.n.user_id),
        &[("csrf", &token_a)],
        Some(&h.console_origin()),
    );
    assert_eq!(r.status, 403, "{r:?}");
    let rejected = events_of(&h, "csrf.rejected", 2);
    assert_eq!(rejected[1]["attrs"]["cause"], "expired", "{rejected:?}");
    assert_eq!(user_status(&h, &u.n.user_id), "active");
}

#[test]
fn extra_s300_a1_terminated_session_handle_is_useless() {
    let (_idp, h, u) = setup();
    db(&h)
        .execute(
            "UPDATE sessions SET terminated_at = ?2, terminated_reason = 'admin' WHERE session_id = ?1",
            rusqlite::params![u.a.session_id, now_secs(&h)],
        )
        .unwrap();
    let r = admin(&h).with_handle(&u.a.handle).get("/v1/me");
    assert_eq!(r.status, 403, "{r:?}");
    assert_eq!(r.json()["error"], "login_required");
    // A token bound to another handle (here: garbage) and the foreign-handle
    // rule: the listener refuses before the handler.
    let r = admin(&h).with_handle(&u.v.handle).post_form(
        &format!("/users/{}/disable", u.n.user_id),
        &[(
            "csrf",
            "AAAAAAAAAAAAAAAAAAAAAA.1.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        )],
        Some(&h.console_origin()),
    );
    assert_eq!(r.status, 403, "{r:?}");
    assert_eq!(user_status(&h, &u.n.user_id), "active");
}

#[test]
fn s300_a2_forged_identity_tampered_cookie_wrong_host() {
    let (idp, h, u) = setup();
    // (a) forged identity headers do not make u_n an administrator.
    let r = admin(&h).with_handle(&u.n.handle).get_with(
        "/v1/me",
        &[
            ("x-forwarded-user", &u.a.user_id),
            ("x-forwarded-groups", "hopae-admins"),
            ("x-hopae-aal", "2"),
        ],
    );
    assert_eq!(r.status, 403, "{r:?}");
    assert_eq!(r.json()["error"], "not_admin");

    // (b) a tampered cookie, one without its prefix, an oversized header.
    let mut altered = u.a.handle.clone().into_bytes();
    let last = altered.len() - 1;
    altered[last] = if altered[last] == b'A' { b'B' } else { b'A' };
    let altered = String::from_utf8(altered).unwrap();
    for bad in [altered, u.a.handle.trim_start_matches("v1.").to_string()] {
        let r = admin(&h).with_handle(&bad).get("/v1/me");
        assert_eq!(r.status, 403, "{r:?}");
        assert_eq!(r.json()["error"], "login_required");
    }
    let big = format!(
        "junk={}; {}={}",
        "x".repeat(9 * 1024),
        h.cookie_name(),
        u.a.handle
    );
    let r = raw(
        &h,
        "GET",
        "/v1/me",
        &[
            ("x-forwarded-host", &h.console_host()),
            ("x-forwarded-proto", "https"),
            ("x-forwarded-for", UA_IP),
            ("cookie", &big),
        ],
        b"",
    );
    assert_eq!(r.status, 431, "{r:?}");

    // (c) a forwarded host other than the console host: 404, no state read.
    let calls = h.hooks.store_calls("lookup_handle");
    let r = raw(
        &h,
        "GET",
        "/v1/me",
        &[
            ("x-forwarded-host", "app.example.test"),
            ("x-forwarded-proto", "https"),
            ("x-forwarded-for", UA_IP),
            ("cookie", &format!("{}={}", h.cookie_name(), u.a.handle)),
        ],
        b"",
    );
    assert_eq!(r.status, 404, "{r:?}");
    assert_eq!(r.json()["error"], "not_found");
    assert_eq!(h.hooks.store_calls("lookup_handle"), calls, "no state read");

    // (d) a handle of another host presented on the console host.
    let app_handle = sso_handle(&h, &u.n, APP_HOST);
    let r = admin(&h).with_handle(&app_handle).get("/v1/me");
    assert_eq!(r.status, 403, "{r:?}");
    assert_eq!(r.json()["error"], "login_required");
    let still = h.verify(
        VerifyRequest::document("https://app.example.test/")
            .ip(UA_IP)
            .cookie(&h.cookie_name(), &app_handle),
    );
    assert_eq!(
        still.status, 200,
        "the handle is not cleared on another host: {still:?}"
    );
    let _ = idp;
}

#[test]
fn s300_a3_change_between_check_and_write_wins() {
    let (_idp, h, u) = setup();
    // Control run: no intervening change commits the write.
    let r = admin(&h)
        .with_handle(&u.a.handle)
        .post_json(&format!("/v1/users/{}/disable", u.n.user_id), json!({}));
    assert_eq!(r.status, 200, "{r:?}");
    assert_eq!(user_status(&h, &u.n.user_id), "disabled");
    let r = admin(&h)
        .with_handle(&u.a.handle)
        .post_json(&format!("/v1/users/{}/enable", u.n.user_id), json!({}));
    assert_eq!(r.status, 200, "{r:?}");
    // Variant 1: the grant is revoked after the request check and before the
    // write (the commit gate `admin_mutation` holds the transaction).
    h.hooks.hold("admin_mutation");
    let path = format!("/v1/users/{}/disable", u.n.user_id);
    let handle = u.a.handle.clone();
    let addr = h.admin.unwrap();
    let console = h.console_host();
    let cookie = format!("{}={handle}", h.cookie_name());
    let worker = std::thread::spawn(move || {
        let mut r = RawReq::new("POST", &path, &console)
            .header("x-forwarded-host", &console)
            .header("x-forwarded-proto", "https")
            .header("x-forwarded-for", UA_IP)
            .header("cookie", &cookie)
            .header("content-type", "application/json")
            .header("x-hopae-admin-request", "1");
        r.body = b"{}".to_vec();
        send(addr, r)
    });
    std::thread::sleep(Duration::from_millis(500));
    revoke(&h, &u.a.user_id);
    h.hooks.release("admin_mutation");
    let r = worker.join().unwrap();
    assert_eq!(r.status, 403, "{r:?}");
    assert_eq!(r.json()["error"], "actor_revoked");
    assert_eq!(user_status(&h, &u.n.user_id), "active");
    assert!(h.hooks.events(Some("admin.user_disable"), None).len() <= 1);
    assert_eq!(
        events_with_reason(&h, "admin.denied", "actor_revoked").len(),
        1
    );
}

#[test]
fn s300_a4_unauthenticated_traffic_creates_nothing_and_cap_holds() {
    let (idp, h) = spawn_with(
        Fixture::with("m4-admin", json!({"limits": {"admin_max_concurrent": 4}})),
        "auth_time_present",
    );
    let u = users(&h, &idp);
    let txns = count(&h, "SELECT COUNT(*) FROM login_txns");
    let required_before = count(
        &h,
        "SELECT COUNT(*) FROM events WHERE kind NOT IN ('verify.denied')",
    );
    h.hooks.stall(2000);
    for i in 0..200 {
        let path = match i % 3 {
            0 => "/",
            1 => "/v1/users",
            _ => "/v1/users/u_n/disable",
        };
        let r = if i % 3 == 2 {
            admin(&h).post_json(path, json!({}))
        } else {
            admin(&h).get(path)
        };
        assert_eq!(r.status, 403, "{path}: {r:?}");
        assert_eq!(error_code(&r), "login_required");
    }
    h.hooks.stall_off();
    assert_eq!(count(&h, "SELECT COUNT(*) FROM login_txns"), txns);
    assert_eq!(
        count(
            &h,
            "SELECT COUNT(*) FROM events WHERE kind NOT IN ('verify.denied')"
        ),
        required_before,
        "no required row"
    );

    // Eight concurrent authenticated reads against a stalled store: at most
    // four are in flight; the rest are refused at once.
    h.hooks.stall(2000);
    let addr = h.admin.unwrap();
    let console = h.console_host();
    let cookie = format!("{}={}", h.cookie_name(), u.a.handle);
    let started = std::time::Instant::now();
    let results: Vec<(u16, Option<String>, std::time::Duration)> = std::thread::scope(|s| {
        let workers: Vec<_> = (0..8)
            .map(|_| {
                let (console, cookie) = (console.clone(), cookie.clone());
                s.spawn(move || {
                    let t = std::time::Instant::now();
                    let r = send(
                        addr,
                        RawReq::new("GET", "/v1/status", &console)
                            .header("x-forwarded-host", &console)
                            .header("x-forwarded-proto", "https")
                            .header("x-forwarded-for", UA_IP)
                            .header("cookie", &cookie),
                    );
                    (
                        r.status,
                        r.header("retry-after").map(str::to_string),
                        t.elapsed(),
                    )
                })
            })
            .collect();
        workers.into_iter().map(|w| w.join().unwrap()).collect()
    });
    h.hooks.stall_off();
    let _ = started;
    let overloaded: Vec<_> = results
        .iter()
        .filter(|r| r.0 == 503 && r.1.is_some())
        .collect();
    assert!(
        overloaded.len() >= 4,
        "at most four in flight, the rest refused: {results:?}"
    );
    for (_, retry, took) in &overloaded {
        assert_eq!(retry.as_deref(), Some("1"));
        assert!(
            *took < Duration::from_millis(1500),
            "refused immediately: {took:?}"
        );
    }
    // Limits: a 65 KiB body and a 5 KiB query are 413 before any parsing.
    let r = admin(&h).with_handle(&u.a.handle).post_json_raw(
        "/v1/users/u_n/disable",
        &[
            ("content-type", "application/json"),
            ("x-hopae-admin-request", "1"),
        ],
        &vec![b'a'; 65 * 1024],
    );
    assert_eq!(r.status, 413, "{r:?}");
    assert_eq!(r.json()["error"], "payload_too_large");
    let r = admin(&h)
        .with_handle(&u.a.handle)
        .get(&format!("/v1/status?x={}", "a".repeat(5 * 1024)));
    assert_eq!(r.status, 413, "{r:?}");
}

#[test]
fn s300_a5_cross_site_requests_cannot_act() {
    let (_idp, h, u) = setup();
    let target = format!("/users/{}/disable", u.n.user_id);
    let evil = "https://evil.example.org";
    // (a) a cross-site form post: with the cookie present the origin check
    // refuses it; without the cookie (SameSite=Lax) there is no session.
    let with_cookie =
        admin(&h)
            .with_handle(&u.a.handle)
            .post_form(&target, &[("csrf", "x")], Some(evil));
    assert_eq!(with_cookie.status, 403, "{with_cookie:?}");
    let without = admin(&h).post_form(&target, &[("csrf", "x")], Some(evil));
    assert_eq!(without.status, 403, "{without:?}");
    assert_eq!(error_code(&without), "login_required", "{without:?}");
    assert_eq!(error_code(&with_cookie), "csrf_rejected", "{with_cookie:?}");
    let rejected = events_of(&h, "csrf.rejected", 1);
    assert_eq!(rejected.len(), 1, "{rejected:?}");
    assert_eq!(rejected[0]["attrs"]["cause"], "origin");
    assert_eq!(rejected[0]["attrs"]["purpose"], "admin");
    // (b) a plain cross-origin fetch lacks the header and the JSON type; the
    // preflight is a 404 without CORS headers.
    let r = admin(&h).with_handle(&u.a.handle).post_json_raw(
        &format!("/v1/users/{}/disable", u.n.user_id),
        &[
            ("content-type", "text/plain"),
            ("origin", evil),
            ("sec-fetch-site", "cross-site"),
        ],
        b"{}",
    );
    assert_eq!(r.status, 403, "{r:?}");
    assert_eq!(r.json()["error"], "csrf_rejected");
    let pre = raw(
        &h,
        "OPTIONS",
        &format!("/v1/users/{}/disable", u.n.user_id),
        &[
            ("x-forwarded-host", &h.console_host()),
            ("origin", evil),
            ("access-control-request-method", "POST"),
            (
                "access-control-request-headers",
                "content-type,x-hopae-admin-request",
            ),
            ("cookie", &format!("{}={}", h.cookie_name(), u.a.handle)),
        ],
        b"",
    );
    assert_eq!(pre.status, 404, "{pre:?}");
    assert!(
        pre.headers
            .iter()
            .all(|(k, _)| !k.starts_with("access-control-")),
        "no CORS headers: {pre:?}"
    );
    // (c) a top-level GET navigation from that page renders (a read, by design).
    let nav = admin(&h).with_handle(&u.a.handle).get_with(
        "/",
        &[
            ("sec-fetch-site", "cross-site"),
            ("sec-fetch-mode", "navigate"),
            ("referer", evil),
        ],
    );
    assert_eq!(nav.status, 200, "{nav:?}");
    assert_pinned_headers(&nav);
    // (d) `Origin: null`.
    let r = admin(&h)
        .with_handle(&u.a.handle)
        .post_form(&target, &[("csrf", "x")], Some("null"));
    assert_eq!(r.status, 403, "{r:?}");
    let rejected = events_of(&h, "csrf.rejected", 3);
    assert!(
        rejected
            .iter()
            .filter(|e| e["attrs"]["cause"] == "origin")
            .count()
            >= 2,
        "{rejected:?}"
    );
    assert_eq!(user_status(&h, &u.n.user_id), "active");
}

#[test]
fn s300_a6_forwarding_headers_believed_only_from_gateway() {
    let ip = "203.0.113.9";
    let (idp, h) = spawn();
    let a = console_login(&h, &idp, "sub-a", "a@example.test", "Ada", ip);
    let a2 = console_login(&h, &idp, "sub-a2", "a2@example.test", "Ada Two", ip);
    let a3 = console_login(&h, &idp, "sub-a3", "a3@example.test", "Ada Three", ip);
    for s in [&a, &a2, &a3] {
        grant(&h, &s.user_id, "admin");
    }
    let cookie = |s: &Signed| format!("{}={}", h.cookie_name(), s.handle);
    let host = h.console_host();
    // (b) two forwarded-for lines and a cookie split over two lines are
    // joined as the portal joins them: the right-most untrusted address wins.
    let r = raw(
        &h,
        "GET",
        "/v1/me",
        &[
            ("x-forwarded-host", &host),
            ("x-forwarded-proto", "https"),
            ("x-forwarded-for", "198.51.100.77"),
            ("x-forwarded-for", ip),
            ("cookie", "theme=dark"),
            ("cookie", &cookie(&a)),
        ],
        b"",
    );
    assert_eq!(r.status, 200, "{r:?}");
    // (d) the documented residual: a trusted peer's forwarded address is
    // believed, whatever process sent it.
    let r = raw(
        &h,
        "GET",
        "/v1/me",
        &[
            ("x-forwarded-host", &host),
            ("x-forwarded-proto", "https"),
            ("x-forwarded-for", ip),
            ("cookie", &cookie(&a2)),
        ],
        b"",
    );
    assert_eq!(r.status, 200, "{r:?}");
    // (c) a different forwarded address ends the session as the gateway's
    // verify would.
    let r = raw(
        &h,
        "GET",
        "/v1/me",
        &[
            ("x-forwarded-host", &host),
            ("x-forwarded-proto", "https"),
            ("x-forwarded-for", "198.51.100.7"),
            ("cookie", &cookie(&a3)),
        ],
        b"",
    );
    assert_eq!(r.status, 403, "{r:?}");
    assert_eq!(
        session_terminated(&h, &a3.session_id).as_deref(),
        Some("binding_ip")
    );
    // (a) under the default `refuse` an outside peer is refused outright
    // (300-13); under `as_client` it cannot claim the bound address.
    let (idp2, h2) = spawn_with(
        Fixture::with(
            "m4-admin",
            json!({"admin": {"untrusted_peers": "as_client"}}),
        ),
        "auth_time_present",
    );
    let a_b = console_login(&h2, &idp2, "sub-a", "a@example.test", "Ada", ip);
    grant(&h2, &a_b.user_id, "admin");
    let r = admin(&h2)
        .with_handle(&a_b.handle)
        .client_ip(ip)
        .from_peer("127.0.0.2".parse().unwrap())
        .get("/v1/me");
    assert_eq!(r.status, 403, "{r:?}");
    assert_eq!(r.json()["error"], "login_required");
    let ev = sampled_denials(&h2, "insecure_transport");
    assert_eq!(ev.len(), 1, "{ev:?}");
    assert_eq!(
        ev[0]["client_ip"], "127.0.0.2",
        "the peer itself is the client"
    );
}

#[test]
fn s300_a7_plain_http_never_carries_the_console() {
    let (_idp, h, u) = setup();
    let r = raw(
        &h,
        "GET",
        "/v1/me",
        &[
            ("x-forwarded-host", &h.console_host()),
            ("x-forwarded-proto", "http"),
            ("x-forwarded-for", UA_IP),
            ("cookie", &format!("{}={}", h.cookie_name(), u.a.handle)),
        ],
        b"",
    );
    assert_eq!(r.status, 403, "{r:?}");
    assert_eq!(r.json()["error"], "login_required");
    let ev = sampled_denials(&h, "insecure_transport");
    assert_eq!(ev.len(), 1, "{ev:?}");

    // Development mode: `cookie.secure = false`, an `http://` console.
    let (idp, dev) = spawn_with(
        Fixture::with(
            "m1-dev-insecure",
            json!({
                "listen": {"admin": "127.0.0.1:0"},
                "trusted_proxies": ["127.0.0.1/32"],
                "admin": {
                    "public_url": "http://hopae-admin.example.test",
                    "session": {"idle": "30m", "absolute": "12h"},
                    "max_auth_age": "12h"
                }
            }),
        ),
        "auth_time_present",
    );
    let s = console_login(&dev, &idp, "sub-a", "a@example.test", "Ada", UA_IP);
    grant(&dev, &s.user_id, "admin");
    let r = admin(&dev).with_handle(&s.handle).get("/v1/me");
    assert_eq!(r.status, 200, "{r:?}");
    assert!(
        metric(
            &dev,
            "hopae_admin_requests_total{role=\"admin\",outcome=\"ok\",insecure_mode=\"true\"}"
        ) >= 1
    );
    assert!(
        dev.log().to_lowercase().contains("insecure"),
        "the loud insecure-mode warning: {}",
        dev.log()
    );
}

#[test]
fn s300_a8_outsider_learns_nothing_about_administrators() {
    let (_idp, h, u) = setup();
    // Without a handle every JSON path is the same 403, unknown ids included.
    let bodies: Vec<String> = ["/v1/users/u_a", "/v1/me", "/v1/users/u_zzzzzzzz"]
        .iter()
        .map(|p| {
            let r = admin(&h).get(p);
            assert_eq!(r.status, 403, "{p}: {r:?}");
            r.body
        })
        .collect();
    assert!(bodies.windows(2).all(|w| w[0] == w[1]), "{bodies:?}");
    let pages: Vec<String> = ["/users/u_a", "/users/u_zzzzzzzz", "/sessions/s_x"]
        .iter()
        .map(|p| {
            let r = admin(&h).get(p);
            assert_eq!(r.status, 403, "{p}: {r:?}");
            without_request_id(&r.body)
        })
        .collect();
    assert!(pages.windows(2).all(|w| w[0] == w[1]), "{pages:?}");
    // With a handle but no grant: not_admin, naming only the caller.
    for p in ["/v1/users/u_a", "/v1/me", "/v1/users/u_zzzzzzzz"] {
        let r = admin(&h).with_handle(&u.n.handle).get(p);
        assert_eq!(r.status, 403, "{p}: {r:?}");
        assert_eq!(r.json(), json!({"error": "not_admin"}), "{p}");
    }
    for p in ["/users/u_a", "/users/u_zzzzzzzz"] {
        let r = admin(&h).with_handle(&u.n.handle).get(p);
        assert_eq!(r.status, 403, "{p}: {r:?}");
        assert!(r.body.contains(&u.n.user_id) && r.body.contains("n@example.test"));
        assert!(
            !r.body.contains(&u.a.user_id) && !r.body.contains("a@example.test"),
            "{p}: nothing about the administrator"
        );
    }
}

// ---- 300-8 (W1-C): preflight --------------------------------------------------

mod s300_8 {
    use std::path::{Path, PathBuf};
    use std::process::Command;

    use serde_json::{Value, json};

    use crate::support::*;

    fn render(dir: &Path, fixture: &'static str, edit: impl FnOnce(&mut Value)) -> PathBuf {
        let idp = MockIdp::start("default");
        let mut v = Fixture::new(fixture).render(dir, &idp);
        edit(&mut v);
        let p = dir.join(format!("{fixture}.json"));
        std::fs::write(&p, serde_json::to_vec_pretty(&v).unwrap()).unwrap();
        p
    }

    struct Out {
        code: Option<i32>,
        stdout: String,
        stderr: String,
    }

    impl Out {
        fn all(&self) -> String {
            format!("{:?}\n{}\n{}", self.code, self.stdout, self.stderr)
        }
    }

    fn check(cfg: &Path, extra: &[&str]) -> Out {
        let o = Command::new(env!("CARGO_BIN_EXE_hopae"))
            .arg("--check")
            .args(extra)
            .arg("--config")
            .arg(cfg)
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("HOPAE_TEST_GATEWAY_KEY", "gwkey-value-0123456789")
            .env("HOPAE_TEST_MOCK_SECRET", "mock-secret-value-9876543210")
            .output()
            .unwrap();
        Out {
            code: o.status.code(),
            stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
        }
    }

    fn json_after(s: &str, marker: &str) -> Value {
        let at = s
            .find(marker)
            .unwrap_or_else(|| panic!("{marker:?} in:\n{s}"));
        let rest = &s[at..];
        let brace = rest.find('{').expect("json");
        serde_json::Deserializer::from_str(&rest[brace..])
            .into_iter::<Value>()
            .next()
            .unwrap()
            .expect("parses")
    }

    #[test]
    fn s300_8_preflight_prints_console_route_capabilities_and_refuses_reserved_id() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();

        // The base file: route fragment, implicit application, capability line.
        let cfg = render(d, "m4-admin", |_| {});
        let o = check(&cfg, &[]);
        assert_eq!(o.code, Some(0), "{}", o.all());
        let frag = json_after(&o.stdout, "gateway route for the console host");
        assert_eq!(frag["id"], "hopae-admin", "{frag}");
        assert_eq!(frag["host"], "hopae-admin.example.test");
        assert!(
            frag["auth"]["url"]
                .as_str()
                .unwrap()
                .ends_with("/_hopae/verify")
        );
        assert_eq!(frag["auth"]["forward_response"], true);
        assert_eq!(
            frag["auth"]["static_request_headers"]["x-hopae-gateway-key"],
            json!({"env": "HANGANG_HOPAE_KEY"})
        );
        assert!(
            frag.get("strip_request_cookies").is_none()
                && frag["auth"].get("strip_request_cookies").is_none(),
            "the console needs its handle cookie: {frag}"
        );
        let app_line = o
            .stdout
            .lines()
            .find(|l| l.trim_start().starts_with("admin (enabled"))
            .unwrap_or_else(|| panic!("implicit application line:\n{}", o.stdout));
        for needle in [
            "hopae-admin.example.test",
            "implicit",
            "session idle 30m absolute 12h",
            "ip=strict",
            "max_auth_age 12h",
        ] {
            assert!(app_line.contains(needle), "{needle}: {app_line}");
        }
        assert!(
            o.stdout.contains("admin.untrusted_peers refuse"),
            "{}",
            o.stdout
        );
        assert!(
            o.stdout
                .contains("reauth max_age: console freshness is a provider-verified challenge"),
            "{}",
            o.stdout
        );
        assert!(o.stdout.trim_end().ends_with("config ok"), "{}", o.stdout);

        // The reserved application id.
        let cfg = render(d, "m4-admin", |v| {
            let app = v["apps"][0].clone();
            v["apps"] = json!([app, {"app_id": "admin", "display_name": "x"}]);
        });
        let o = check(&cfg, &[]);
        assert_eq!(o.code, Some(2), "{}", o.all());
        assert!(
            o.stderr.contains("apps[1].app_id") && o.stderr.contains("reserved"),
            "{}",
            o.all()
        );

        // require_aal: 2 warns; --strict refuses.
        let cfg = render(d, "m4-admin", |v| v["admin"]["require_aal"] = json!(2));
        let o = check(&cfg, &[]);
        assert_eq!(o.code, Some(0), "{}", o.all());
        assert!(
            o.stderr.contains("admin.require_aal") && o.stderr.contains("will be refused"),
            "{}",
            o.all()
        );
        assert_eq!(check(&cfg, &["--strict"]).code, Some(2));

        // listeners must differ.
        let cfg = render(d, "m4-admin", |v| {
            v["listen"]["portal"] = json!("127.0.0.1:18700");
            v["listen"]["admin"] = json!("127.0.0.1:18700");
        });
        let o = check(&cfg, &[]);
        assert_eq!(o.code, Some(2), "{}", o.all());
        assert!(o.stderr.contains("must differ"), "{}", o.all());

        // origin without path.
        let cfg = render(d, "m4-admin", |v| {
            v["admin"]["public_url"] = json!("https://hopae-admin.example.test/path")
        });
        let o = check(&cfg, &[]);
        assert_eq!(o.code, Some(2), "{}", o.all());
        assert!(o.stderr.contains("origin without path"), "{}", o.all());

        // the console host is registered implicitly.
        let cfg = render(d, "m4-admin", |v| {
            v["apps"][0]["hosts"] = json!(["app.example.test", "hopae-admin.example.test"]);
        });
        let o = check(&cfg, &[]);
        assert_eq!(o.code, Some(2), "{}", o.all());
        assert!(o.stderr.contains("registered implicitly"), "{}", o.all());

        // untrusted_peers values.
        let cfg = render(d, "m4-admin", |v| {
            v["admin"]["untrusted_peers"] = json!("maybe")
        });
        let o = check(&cfg, &[]);
        assert_eq!(o.code, Some(2), "{}", o.all());

        // max_auth_age below the bound.
        for bad in ["60s", "29m"] {
            let cfg = render(d, "m4-admin", |v| v["admin"]["max_auth_age"] = json!(bad));
            let o = check(&cfg, &[]);
            assert_eq!(o.code, Some(2), "{bad}: {}", o.all());
            assert!(
                o.stderr.contains("admin.max_auth_age must be at least 30m"),
                "{bad}: {}",
                o.all()
            );
        }

        // A provider whose capability is unsupported (the google preset).
        let cfg = render(d, "m4-admin-unsupported", |v| {
            v["providers"].as_array_mut().unwrap().push(json!({
                "provider_id": "google",
                "kind": "oidc",
                "display_name": "Google",
                "client_id": "g-client",
                "client_secret_env": "HOPAE_TEST_MOCK_SECRET",
                "issuer": "https://accounts.google.com",
                "scope": "openid email profile"
            }));
        });
        let o = check(&cfg, &[]);
        assert_eq!(o.code, Some(0), "{}", o.all());
        assert!(
            o.stdout.contains(
                "reauth unsupported: console freshness is Hopae login age; enforce a second factor at the provider for administrators"
            ),
            "{}",
            o.all()
        );
    }
}

// ===========================================================================
// W1-D: console reauthentication (provider capability, `max_age`/`prompt`,
// `auth_time` validation and provenance, same-provider reauthentication).
// Scenario cases 300-6, 300-15, 300-16, 300-17, 300-A9, 300-A10. These drive
// the verify endpoint, the portal and the mock provider; the admin listener's
// own answers (`403 auth_too_old`, the actor fence) are W1-A/W1-B's cases.
// ===========================================================================
#[allow(dead_code, unused_imports)]
mod reauth {
    use std::time::Duration;

    use serde_json::{Value, json};
    use sha2::{Digest as _, Sha256};

    use crate::support::*;

    pub const APP: &str = "app.example.test";
    pub const CONSOLE: &str = "hopae-admin.example.test";
    pub const PORTAL: &str = "auth.example.test";
    pub const IP: &str = "203.0.113.9";
    pub const HANDLE: &str = "__Host-hopae";
    pub const BIND: &str = "__Host-hopae_bind";
    pub const N: i64 = 12 * 3600;

    /// Long console handle lifetimes so the cases can advance the clock by
    /// hours without keeping the handle alive between steps.
    pub fn long_handles() -> Value {
        json!({
            "admin": {"session": {"idle": "13h", "absolute": "13h"}},
            "session": {"idle": "48h", "absolute": "30d"},
            // The portal's own handle (the `default` application) outlives the stale window.
            "apps": [{"app_id": "default", "session": {"idle": "48h", "absolute": "30d"}}]
        })
    }

    pub fn sha(s: &str) -> Vec<u8> {
        Sha256::digest(s.as_bytes()).to_vec()
    }

    pub fn db(h: &Hopae) -> rusqlite::Connection {
        let path = h.state_dir.path().join("state").join("hopae.db");
        let c = rusqlite::Connection::open(path).expect("open the store");
        c.busy_timeout(Duration::from_secs(5))
            .expect("busy timeout");
        c
    }

    pub fn count(h: &Hopae, sql: &str) -> i64 {
        db(h).query_row(sql, [], |r| r.get(0)).expect("count")
    }

    pub fn cookie_value(r: &Response, name: &str) -> Option<String> {
        r.set_cookies().iter().find_map(|c| {
            c.strip_prefix(&format!("{name}="))
                .map(|rest| rest.split(';').next().unwrap_or("").to_string())
        })
    }

    pub fn csrf_of(body: &str) -> String {
        body.split("name=\"csrf\" value=\"")
            .nth(1)
            .and_then(|r| r.split('"').next())
            .expect("csrf field")
            .to_string()
    }

    /// A portal form `POST` as the browser sends it (same-origin `Origin`).
    pub fn post(c: &Client, path: &str, fields: &[(&str, &str)]) -> Response {
        c.send(
            Req::post(path)
                .form(fields)
                .header("origin", &format!("https://{PORTAL}")),
        )
    }

    pub fn now_s(h: &Hopae) -> i64 {
        h.hooks.now_ms() / 1000
    }

    pub fn spawn(fixture: &'static str, profile: &str, overrides: Value) -> (MockIdp, Hopae) {
        let idp = MockIdp::start(profile);
        let h = Hopae::spawn(
            Fixture::with(fixture, overrides),
            &idp,
            &[("HOPAE_TEST_SEED", "1")],
        );
        // The provider's token clock follows the instance's.
        h.set_clock_ms(h.hooks.now_ms());
        (idp, h)
    }

    /// The `m4-admin-unsupported` standing: the stored provider row is
    /// api-managed and declares `reauth: "unsupported"` (the harness seeds it
    /// the way the admin API of a later milestone would), then the instance
    /// restarts so the snapshot reads it.
    pub fn spawn_unsupported(profile: &str, overrides: Value) -> (MockIdp, Hopae) {
        spawn_stored(
            "m4-admin-unsupported",
            profile,
            overrides,
            json!({"reauth": "unsupported"}),
        )
    }

    /// An api-managed provider row carrying `patch` in its stored settings.
    pub fn spawn_stored(
        fixture: &'static str,
        profile: &str,
        overrides: Value,
        patch: Value,
    ) -> (MockIdp, Hopae) {
        let (idp, mut h) = spawn(fixture, profile, overrides);
        h.kill();
        {
            let c = db(&h);
            let n = c
                .execute(
                    "UPDATE providers SET managed_by = 'api', config = json_patch(config, ?1) WHERE provider_id = 'mock'",
                    [patch.to_string()],
                )
                .expect("seed the api-managed row");
            assert_eq!(n, 1);
        }
        h.restart();
        h.set_clock_ms(h.hooks.now_ms());
        (idp, h)
    }

    /// What a signed-in browser holds.
    pub struct Browser {
        pub jar: Jar,
        pub ip: String,
        pub bind: String,
        pub handle: String,
        pub target: String,
    }

    impl Browser {
        pub fn portal(&self, h: &Hopae) -> Client {
            h.portal_with(self.jar.clone()).with_ip(&self.ip)
        }

        pub fn verify(&self, h: &Hopae) -> Response {
            h.verify(
                VerifyRequest::document(&self.target)
                    .ip(&self.ip)
                    .cookie(HANDLE, &self.handle)
                    .cookie(BIND, &self.bind)
                    .header("sec-fetch-site", "same-origin"),
            )
        }

        pub fn verify_other(&self, h: &Hopae) -> Response {
            h.verify(
                VerifyRequest::other(&self.target)
                    .ip(&self.ip)
                    .cookie(HANDLE, &self.handle)
                    .cookie(BIND, &self.bind),
            )
        }
    }

    pub fn txn_of(r: &Response) -> String {
        let loc = r.location().expect("location");
        let u = url::Url::parse(loc).expect("location url");
        assert_eq!(u.host_str(), Some(PORTAL), "{loc}");
        assert_eq!(u.path(), "/login", "{loc}");
        u.query_pairs()
            .find(|(k, _)| k == "txn")
            .map(|(_, v)| v.into_owned())
            .expect("txn parameter")
    }

    /// The provider step of a login: the portal page (or the single-provider
    /// redirect) to the provider's authorization URL.
    pub fn to_provider(c: &Client, txn: &str, provider: &str) -> String {
        let page = c.get(&format!("/login?txn={txn}"));
        if page.status == 302 {
            return page.location().expect("provider redirect").to_string();
        }
        assert_eq!(page.status, 200, "{page:?}");
        let r = post(
            c,
            &format!("/login/{provider}"),
            &[("csrf", &csrf_of(&page.body)), ("txn", txn)],
        );
        assert_eq!(r.status, 302, "{r:?}");
        r.location().expect("provider redirect").to_string()
    }

    /// Sign in from `start_url` and redeem the handoff (scenarios 002, 003).
    pub fn sign_in(h: &Hopae, idp: &MockIdp, start_url: &str) -> Browser {
        sign_in_with(h, idp, start_url, "mock")
    }

    pub fn sign_in_with(h: &Hopae, idp: &MockIdp, start_url: &str, provider: &str) -> Browser {
        let first = h.verify(
            VerifyRequest::document(start_url)
                .ip(IP)
                .header("sec-fetch-site", "same-origin"),
        );
        assert_eq!(first.status, 302, "{first:?} {}", first.body);
        let bind = cookie_value(&first, BIND).expect("binding cookie");
        let txn = txn_of(&first);
        let jar = Jar::new();
        let c = h.portal_with(jar.clone()).with_ip(IP);
        let authorize = to_provider(&c, &txn, provider);
        let cb = c.get(&idp.follow_authorization(&authorize));
        assert_eq!(cb.status, 302, "{cb:?}");
        let b = Browser {
            jar,
            ip: IP.into(),
            bind,
            handle: String::new(),
            target: start_url.into(),
        };
        redeem(h, b, cb.location().expect("handoff"))
    }

    /// Redeem a handoff location; the browser then holds the application handle.
    pub fn redeem(h: &Hopae, mut b: Browser, handoff: &str) -> Browser {
        let r = h.verify(
            VerifyRequest::document(handoff)
                .ip(&b.ip)
                .cookie(BIND, &b.bind)
                .header("sec-fetch-site", "cross-site"),
        );
        assert_eq!(r.status, 302, "{r:?}");
        b.handle = cookie_value(&r, HANDLE).expect("application handle");
        b
    }

    pub fn console_url() -> String {
        format!("https://{CONSOLE}/users")
    }

    pub struct SessionRow {
        pub id: String,
        pub user_id: String,
        pub provider: String,
        pub auth_time: i64,
        pub source: String,
        pub cred_gen: i64,
        pub factors: Value,
    }

    pub fn session(h: &Hopae) -> SessionRow {
        db(h)
            .query_row(
                "SELECT session_id, user_id, provider_id, auth_time, auth_time_source, cred_gen, factors FROM sessions WHERE terminated_at IS NULL ORDER BY created_at DESC LIMIT 1",
                [],
                |r| {
                    Ok(SessionRow {
                        id: r.get(0)?,
                        user_id: r.get(1)?,
                        provider: r.get(2)?,
                        auth_time: r.get(3)?,
                        source: r.get(4)?,
                        cred_gen: r.get(5)?,
                        factors: serde_json::from_str(&r.get::<_, String>(6)?).expect("factors"),
                    })
                },
            )
            .expect("the session")
    }

    pub fn events(h: &Hopae, kind: &str) -> Vec<Value> {
        h.hooks.events(Some(kind), Some(5000))
    }

    pub fn failed_reasons(h: &Hopae) -> Vec<String> {
        events(h, "login.failed")
            .iter()
            .filter_map(|e| e["reason"].as_str().map(str::to_string))
            .collect()
    }

    /// Set the instance and provider clock to `secs`.
    pub fn at(h: &Hopae, secs: i64) {
        h.set_clock_ms(secs * 1000);
    }

    /// A stale console navigation: `302 reauth_required`; returns the transaction.
    pub fn expect_reauth(h: &Hopae, b: &Browser) -> String {
        let r = b.verify(h);
        assert_eq!(r.status, 302, "{r:?}");
        assert_eq!(r.header("x-hopae-reason"), Some("reauth_required"), "{r:?}");
        assert_eq!(r.header("cache-control"), Some("no-store"));
        assert!(
            r.set_cookies()
                .iter()
                .all(|c| !c.starts_with(&format!("{HANDLE}="))),
            "the handle is not cleared: {r:?}"
        );
        txn_of(&r)
    }

    /// Run the provider round trip of a reauthentication transaction up to
    /// and including the callback; returns the callback response.
    pub fn round_trip(h: &Hopae, idp: &MockIdp, b: &Browser, txn: &str) -> Response {
        let c = b.portal(h);
        let authorize = to_provider(&c, txn, "mock");
        c.get(&idp.follow_authorization(&authorize))
    }

    #[test]
    fn s300_6_max_age_provider_stale_session_gets_provider_verified_reauthentication() {
        let (idp, h) = spawn("m4-admin", "auth_time_present", long_handles());
        let b = sign_in(&h, &idp, &console_url());
        let s0 = session(&h);
        assert_eq!(s0.source, "provider_claim");
        assert_eq!(
            b.verify(&h).status,
            200,
            "a fresh session enters the console"
        );
        assert_eq!(idp.authorize_requests().len(), 1);
        assert_eq!(
            idp.authorize_requests()[0].max_age,
            None,
            "first login: no max_age"
        );

        // Stale by one second, the console handle still alive.
        at(&h, s0.auth_time + N + 1);

        // (a) document navigation.
        let txn = expect_reauth(&h, &b);
        let (purpose, target, portal_sid, max_age): (String, String, Option<String>, Option<i64>) = db(&h)
        .query_row(
            "SELECT purpose, return_target, portal_session_id, reauth_max_age FROM login_txns WHERE txn_sha256 = ?1",
            [sha(&txn)],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .expect("the transaction");
        assert_eq!(purpose, "login");
        assert_eq!(target, console_url());
        assert_eq!(portal_sid.as_deref(), Some(s0.id.as_str()));
        assert_eq!(max_age, Some(N));
        // (b) a non-document request creates nothing and says so.
        let before = count(&h, "SELECT count(*) FROM login_txns");
        let r = b.verify_other(&h);
        assert_eq!(r.status, 401, "{r:?}");
        assert_eq!(r.header("x-hopae-reason"), Some("reauth_required"));
        let body: Value = serde_json::from_str(&r.body).expect("json");
        assert_eq!(body["error"], "reauth_required");
        assert_eq!(body["login"], console_url());
        assert_eq!(count(&h, "SELECT count(*) FROM login_txns"), before);

        // (c) no single sign-on, the provider is asked with max_age and prompt.
        let c = b.portal(&h);
        let page = c.get(&format!("/login?txn={txn}"));
        assert_eq!(page.status, 302, "{page:?}");
        let authorize = page.location().expect("provider redirect").to_string();
        assert!(
            !authorize.contains("_hopae_handoff"),
            "no handoff: {authorize}"
        );
        let reqs = idp.authorize_requests();
        let cb = c.get(&idp.follow_authorization(&authorize));
        let reqs_after = idp.authorize_requests();
        assert_eq!(reqs_after.len(), reqs.len() + 1);
        let last = reqs_after.last().unwrap();
        assert_eq!(last.max_age.as_deref(), Some("43200"));
        assert_eq!(last.prompt.as_deref(), Some("login"));

        // (d) the callback reauthenticates the existing session.
        assert_eq!(cb.status, 302, "{cb:?}");
        let s1 = session(&h);
        assert_eq!(s1.id, s0.id, "the session keeps its identity");
        assert_eq!(s1.source, "provider_claim");
        assert!(
            s1.auth_time >= s0.auth_time + N + 1 - 2,
            "{} vs {}",
            s1.auth_time,
            s0.auth_time
        );
        assert_eq!(s1.cred_gen, s0.cred_gen + 1);
        assert_eq!(s1.factors.as_array().map(Vec::len), Some(2));
        assert_eq!(s1.factors[1]["provider"], "mock");
        assert_eq!(s1.factors[1]["at"].as_i64(), Some(s1.auth_time * 1000));
        assert_eq!(
            count(
                &h,
                "SELECT count(*) FROM session_handles WHERE revoked_reason = 'reauth'"
            ),
            2,
            "the console handle and the portal handle"
        );
        let ok = events(&h, "login.succeeded");
        let last_ok = ok.last().expect("login.succeeded");
        assert_eq!(last_ok["attrs"]["reauth"], true, "{last_ok}");
        assert_eq!(last_ok["attrs"]["auth_time_source"], "provider_claim");
        let revoked: Vec<_> = events(&h, "handle.revoked")
            .into_iter()
            .filter(|e| e["reason"] == "reauth")
            .collect();
        assert_eq!(revoked.len(), 2, "{revoked:?}");

        // The reauthentication reached the console.
        let handoff = cb.location().expect("handoff").to_string();
        assert!(
            handoff.starts_with(&format!("https://{CONSOLE}/")),
            "{handoff}"
        );
        let b2 = redeem(&h, b, &handoff);
        assert_eq!(b2.verify(&h).status, 200, "the console opens");
        // The old console handle is dead; single sign-on on the app host still works.
        let old = h.verify(
            VerifyRequest::document(&format!("https://{APP}/x"))
                .ip(IP)
                .cookie(BIND, &b2.bind)
                .header("sec-fetch-site", "same-origin"),
        );
        assert_eq!(old.status, 302, "{old:?}");
    }

    #[test]
    fn s300_15_freshness_one_predicate_every_verify_and_listener_auth_too_old() {
        let (idp, h) = spawn("m4-admin", "auth_time_present", long_handles());
        // Signed in on the application host 5 minutes ago.
        let app = sign_in(&h, &idp, &format!("https://{APP}/x"));
        let auth0 = session(&h).auth_time;
        let t0 = now_s(&h);
        assert!((t0 - auth0).abs() <= 2);

        // SSO into the console at `secs` after the claim: no provider visit.
        let enter = |h: &Hopae, secs: i64| -> Browser {
            at(h, auth0 + secs);
            let before = idp.authorize_requests().len();
            let first = h.verify(
                VerifyRequest::document(&console_url())
                    .ip(IP)
                    .header("sec-fetch-site", "same-origin"),
            );
            assert_eq!(first.status, 302, "{first:?}");
            let bind = cookie_value(&first, BIND).expect("bind");
            let txn = txn_of(&first);
            let jar = app.jar.clone();
            let c = h.portal_with(jar.clone()).with_ip(IP);
            let sso = c.get(&format!("/login?txn={txn}"));
            assert_eq!(sso.status, 302, "{sso:?}");
            let loc = sso.location().expect("handoff").to_string();
            assert!(
                loc.starts_with(&format!("https://{CONSOLE}/")),
                "single sign-on: {loc}"
            );
            assert_eq!(idp.authorize_requests().len(), before, "no provider visit");
            redeem(
                h,
                Browser {
                    jar,
                    ip: IP.into(),
                    bind,
                    handle: String::new(),
                    target: console_url(),
                },
                &loc,
            )
        };
        let b = enter(&h, 300);
        assert_eq!(b.verify(&h).status, 200);
        // The listener reads the same predicate: the engine's `Reauth` is `403 auth_too_old`.
        super::kit::grant(&h, &session(&h).user_id, "admin");
        let listener = |h: &Hopae| {
            h.admin_client()
                .client_ip(IP)
                .with_handle(&b.handle)
                .get("/v1/me")
        };
        {
            let r = listener(&h);
            assert_eq!(r.status, 200, "{r:?} {}", r.body);
        }
        at(&h, auth0 + N - 1);
        assert_eq!(b.verify(&h).status, 200, "N - 1 s is fresh");
        assert_eq!(listener(&h).status, 200, "N - 1 s is fresh on the listener");
        at(&h, auth0 + N);
        let r = listener(&h);
        assert_eq!(r.status, 403, "{r:?}");
        assert_eq!(r.json()["error"], "auth_too_old", "{r:?}");
        let denied = events(&h, "admin.denied");
        assert_eq!(denied.last().unwrap()["reason"], "auth_too_old");
        let _ = expect_reauth(&h, &b); // equality is not fresh
        at(&h, auth0 + N + 1);
        let r = listener(&h);
        assert_eq!(
            (
                r.status,
                r.json()["error"].as_str().unwrap_or_default().to_string()
            ),
            (403, "auth_too_old".to_string()),
            "{r:?}"
        );
        let _ = expect_reauth(&h, &b);
        let r = b.verify_other(&h);
        assert_eq!(r.status, 401, "{r:?}");
        // A session entering the console at the bound: entered by SSO, challenged at once.
        let b = enter(&h, N - 1);
        assert_eq!(b.verify(&h).status, 200);
        let b = enter(&h, N + 1);
        let _ = expect_reauth(&h, &b);
    }

    #[test]
    fn s300_16_unsupported_provider_freshness_is_hopae_login_age() {
        let (idp, h) = spawn_unsupported("auth_time_missing", long_handles());
        // `--check` reports the stored capability, not the file's default.
        let o = h.cli(&["--check"]);
        assert_eq!(o.status, 0, "{}", o.all());
        assert!(
            o.stdout.contains(
                "mock: reauth unsupported: console freshness is Hopae login age; enforce a second factor at the provider for administrators"
            ),
            "{}",
            o.all()
        );
        let b = sign_in(&h, &idp, &console_url());
        let s0 = session(&h);
        assert_eq!(s0.source, "hopae_completion", "the mock sent no claim");
        assert_eq!(
            events(&h, "session.created").last().unwrap()["attrs"]["auth_time_source"],
            "hopae_completion"
        );
        assert_eq!(
            b.verify(&h).status,
            200,
            "login age is all an unsupported provider has"
        );
        at(&h, s0.auth_time + N + 1);

        // (a) the same challenge as 300-6.
        let txn = expect_reauth(&h, &b);
        let max_age: Option<i64> = db(&h)
            .query_row(
                "SELECT reauth_max_age FROM login_txns WHERE txn_sha256 = ?1",
                [sha(&txn)],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(max_age, Some(N));
        // (b)-(c) no max_age, no prompt; the callback completes with Hopae's time.
        let cb = round_trip(&h, &idp, &b, &txn);
        let last = idp.authorize_requests().pop().unwrap();
        assert_eq!(last.max_age, None);
        assert_eq!(last.prompt, None);
        assert_eq!(cb.status, 302, "{cb:?}");
        let s1 = session(&h);
        assert_eq!(s1.id, s0.id);
        assert_eq!(s1.source, "hopae_completion");
        assert!((s1.auth_time - now_s(&h)).abs() <= 2);
        assert_eq!(s1.cred_gen, s0.cred_gen + 1);
        let ev = events(&h, "login.succeeded").pop().unwrap();
        assert_eq!(ev["attrs"]["reauth"], true);
        assert_eq!(ev["attrs"]["auth_time_source"], "hopae_completion");
        let b = redeem(&h, b, cb.location().unwrap());
        assert_eq!(b.verify(&h).status, 200);

        // A valid claim from an unsupported provider is still recorded as
        // Hopae's completion time: the capability decides what is demanded.
        at(&h, s1.auth_time + N + 1);
        let txn = expect_reauth(&h, &b);
        idp.set_auth_time(Some(json!(now_s(&h) - 100)));
        let cb = round_trip(&h, &idp, &b, &txn);
        assert_eq!(cb.status, 302, "{cb:?}");
        let s2 = session(&h);
        assert_eq!(s2.source, "hopae_completion");
        assert!((s2.auth_time - now_s(&h)).abs() <= 2);
        let b = redeem(&h, b, cb.location().unwrap());
        assert_eq!(b.verify(&h).status, 200);

        // An invalid claim is invalid for every provider.
        at(&h, s2.auth_time + N + 1);
        let txn = expect_reauth(&h, &b);
        idp.set_auth_time(Some(json!("yesterday")));
        let cb = round_trip(&h, &idp, &b, &txn);
        assert_eq!(cb.status, 400, "{cb:?}");
        assert!(failed_reasons(&h).contains(&"invalid_auth_time".to_string()));
        assert_eq!(session(&h).auth_time, s2.auth_time, "nothing changed");
    }

    /// Add a second `max_age` provider that shares the mock provider.
    fn two_providers() -> serde_json::Value {
        let mut o = long_handles();
        o["providers"] = json!([{
            "provider_id": "mock2", "kind": "oidc", "display_name": "Mock Two",
            "client_id": "placeholder", "client_secret_env": "HOPAE_TEST_MOCK_SECRET",
            "issuer": "http://127.0.0.1:1", "allow_private_endpoints": true,
            "scope": "openid email profile", "auto_link": false
        }]);
        o
    }

    fn spawn_two_providers() -> (MockIdp, Hopae) {
        let idp = MockIdp::start("auth_time_present");
        let mut o = two_providers();
        o["providers"][0]["issuer"] = json!(idp.issuer.as_str().trim_end_matches('/'));
        o["providers"][0]["client_id"] = json!(idp.client_id);
        let h = Hopae::spawn(
            Fixture::with("m4-admin", o),
            &idp,
            &[("HOPAE_TEST_SEED", "1")],
        );
        h.set_clock_ms(h.hooks.now_ms());
        (idp, h)
    }

    #[test]
    fn s300_17_reauthentication_belongs_to_the_sessions_provider() {
        let (idp, h) = spawn_two_providers();
        let b = sign_in(&h, &idp, &console_url());
        let s0 = session(&h);
        assert_eq!(s0.provider, "mock");
        // u_a also has an identity at mock2.
        db(&h)
        .execute(
            "INSERT INTO identities (provider_id, subject, user_id, first_seen_at, last_seen_at) VALUES ('mock2', 'sub-2', ?1, 1, 1)",
            [&s0.user_id],
        )
        .unwrap();
        idp.set_user("sub-2", "two@example.test", true, "Two");
        at(&h, s0.auth_time + N + 1);
        let portal = b.jar.for_host(PORTAL);

        // A login CSRF token for this browser's binding cookie: the chooser of an
        // ordinary transaction, rendered while the portal handle is momentarily absent.
        let h0 = portal.value(HANDLE).expect("portal handle");
        portal.remove(HANDLE);
        let ordinary = h.verify(
            VerifyRequest::document(&format!("https://{APP}/y"))
                .ip(IP)
                .header("sec-fetch-site", "same-origin"),
        );
        let ordinary_txn = txn_of(&ordinary);
        let page = b.portal(&h).get(&format!("/login?txn={ordinary_txn}"));
        assert_eq!(page.status, 200, "two providers: a chooser: {page:?}");
        assert!(page.body.contains("/login/mock2"));
        let csrf = csrf_of(&page.body);
        b.jar.store(
            PORTAL,
            "/",
            true,
            &format!("{HANDLE}={h0}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=100000"),
        );

        // (b) a crafted POST for mock2 on a reauthentication transaction.
        let txn = expect_reauth(&h, &b);
        let before = idp.authorize_requests().len();
        let r = post(
            &b.portal(&h),
            "/login/mock2",
            &[("csrf", &csrf), ("txn", &txn)],
        );
        assert_eq!(r.status, 403, "{r:?}");
        assert_eq!(
            idp.authorize_requests().len(),
            before,
            "no authorize request to mock2"
        );
        assert!(
            failed_reasons(&h).contains(&"provider_mismatch".to_string()),
            "{:?} {} {:?}",
            failed_reasons(&h),
            r.body,
            events(&h, "csrf.rejected")
        );
        let consumed: Option<i64> = db(&h)
            .query_row(
                "SELECT consumed_at FROM login_txns WHERE txn_sha256 = ?1",
                [sha(&txn)],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(consumed, None, "the transaction is unconsumed");

        // (a) the page of that transaction offers the session's provider only
        // (one provider: straight to it).
        let page = b.portal(&h).get(&format!("/login?txn={txn}"));
        assert_eq!(page.status, 302, "{page:?}");
        let authorize = page.location().unwrap().to_string();
        assert!(
            authorize.starts_with(idp.issuer.as_str().trim_end_matches('/')),
            "{authorize}"
        );

        // (d) an ordinary login of u_a through mock2 while the session is live
        // reuses it unchanged (the M1 rule): the evidence provider never changes.
        portal.remove(HANDLE);
        let app_txn = txn_of(
            &h.verify(
                VerifyRequest::document(&format!("https://{APP}/w"))
                    .ip(IP)
                    .header("sec-fetch-site", "same-origin"),
            ),
        );
        let c = b.portal(&h);
        let page = c.get(&format!("/login?txn={app_txn}"));
        assert_eq!(page.status, 200, "{page:?}");
        let r = post(
            &c,
            "/login/mock2",
            &[("csrf", &csrf_of(&page.body)), ("txn", &app_txn)],
        );
        assert_eq!(r.status, 302, "{r:?}");
        idp.set_subject("sub-2");
        b.jar.store(
            PORTAL,
            "/",
            true,
            &format!("{HANDLE}={h0}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=100000"),
        );
        let cb = c.get(&idp.follow_authorization(r.location().unwrap()));
        assert_eq!(cb.status, 302, "{cb:?}");
        let s1 = session(&h);
        assert_eq!(s1.id, s0.id);
        assert_eq!(s1.provider, "mock");
        assert_eq!(s1.auth_time, s0.auth_time);
        assert_eq!(s1.source, s0.source);
        assert_eq!(s1.cred_gen, s0.cred_gen);
        assert_eq!(count(&h, "SELECT count(*) FROM sessions"), 1);
        let _ = expect_reauth(&h, &b); // the console still challenges it

        // (c) mock tombstoned: the page names it, offers sign-out only, creates nothing.
        db(&h)
            .execute(
                "UPDATE providers SET deleted_at = 1 WHERE provider_id = 'mock'",
                [],
            )
            .unwrap();
        let txn2 = expect_reauth(&h, &b);
        let page = b.portal(&h).get(&format!("/login?txn={txn2}"));
        assert_eq!(page.status, 503, "{page:?}");
        assert!(page.body.contains("Mock"), "{}", page.body);
        assert!(
            page.body
                .contains(&format!("https://{CONSOLE}/_hopae/logout")),
            "{}",
            page.body
        );
        assert!(!page.body.contains("<form"), "{}", page.body);
        let s2 = session(&h);
        assert_eq!((s2.auth_time, s2.cred_gen), (s0.auth_time, s0.cred_gen));
        let _ = expect_reauth(&h, &b);

        // (e) a fresh sign-in through mock2 makes a new session naming mock2 with
        // its own claim, and the console opens.
        idp.set_subject("sub-2");
        let b2 = sign_in_with(&h, &idp, &console_url(), "mock2");
        let s3 = session(&h);
        assert_ne!(s3.id, s0.id);
        assert_eq!(s3.provider, "mock2");
        assert_eq!(s3.source, "provider_claim");
        assert_eq!(b2.verify(&h).status, 200);
    }

    #[test]
    fn s300_a9_silent_absent_stale_or_forged_auth_time_cannot_satisfy_max_age_console() {
        // (1) auth_time_stale and (2) auth_time_missing on the reauthentication.
        for (profile, reason) in [
            ("auth_time_stale", "reauth_not_fresh"),
            ("auth_time_missing", "reauth_auth_time_missing"),
        ] {
            let (idp, h) = spawn("m4-admin", "auth_time_present", long_handles());
            let b = sign_in(&h, &idp, &console_url());
            let s0 = session(&h);
            at(&h, s0.auth_time + N + 1);
            let txn = expect_reauth(&h, &b);
            idp.set_profile(profile);
            let cb = round_trip(&h, &idp, &b, &txn);
            assert_eq!(cb.status, 400, "{profile}: {cb:?}");
            let failed = events(&h, "login.failed");
            let ev = failed.iter().find(|e| e["reason"] == reason).expect(reason);
            assert_eq!(
                ev["provider_id"], "mock",
                "the event names the provider: {ev}"
            );
            let s1 = session(&h);
            assert_eq!(
                (
                    s1.auth_time,
                    s1.cred_gen,
                    s1.factors.as_array().map(Vec::len)
                ),
                (s0.auth_time, s0.cred_gen, Some(1)),
                "{profile}: nothing changed"
            );
            let _ = expect_reauth(&h, &b);
        }

        // (3) an ordinary login without the claim succeeds with Hopae's time, and
        // the console challenges it at once; the reauthentication that follows
        // requests max_age and obtains a provider claim.
        {
            let (idp, h) = spawn("m4-admin", "auth_time_missing", long_handles());
            let app = sign_in(&h, &idp, &format!("https://{APP}/x"));
            let s0 = session(&h);
            assert_eq!(s0.source, "hopae_completion");
            assert!((s0.auth_time - now_s(&h)).abs() <= 2);
            // Single sign-on into the console, then the verify challenges.
            let first = h.verify(
                VerifyRequest::document(&console_url())
                    .ip(IP)
                    .header("sec-fetch-site", "same-origin"),
            );
            let bind = cookie_value(&first, BIND).unwrap();
            let c = h.portal_with(app.jar.clone()).with_ip(IP);
            let sso = c.get(&format!("/login?txn={}", txn_of(&first)));
            assert_eq!(sso.status, 302, "{sso:?}");
            let b = redeem(
                &h,
                Browser {
                    jar: app.jar.clone(),
                    ip: IP.into(),
                    bind,
                    handle: String::new(),
                    target: console_url(),
                },
                sso.location().unwrap(),
            );
            let txn = expect_reauth(&h, &b);
            idp.set_profile("auth_time_present");
            let cb = round_trip(&h, &idp, &b, &txn);
            assert_eq!(
                idp.authorize_requests().last().unwrap().max_age.as_deref(),
                Some("43200")
            );
            assert_eq!(cb.status, 302, "{cb:?}");
            assert_eq!(session(&h).source, "provider_claim");
            let b = redeem(&h, b, cb.location().unwrap());
            assert_eq!(b.verify(&h).status, 200);
        }

        // (4) a claim from the future and (5) a string and a negative number fail
        // an ordinary login; no session ever carries `now` in place of them.
        {
            let (idp, h) = spawn("m4-admin", "auth_time_present", long_handles());
            for bad in [
                Some(json!(now_s(&h) + 120)),
                Some(json!("1700000000")),
                Some(json!(-5)),
            ] {
                idp.set_auth_time(bad.clone());
                let first = h.verify(
                    VerifyRequest::document(&format!("https://{APP}/x"))
                        .ip(IP)
                        .header("sec-fetch-site", "same-origin"),
                );
                let txn = txn_of(&first);
                let jar = Jar::new();
                let c = h.portal_with(jar).with_ip(IP);
                let authorize = to_provider(&c, &txn, "mock");
                let cb = c.get(&idp.follow_authorization(&authorize));
                assert_eq!(cb.status, 400, "{bad:?}: {cb:?}");
                assert_eq!(count(&h, "SELECT count(*) FROM sessions"), 0, "{bad:?}");
            }
            let n = failed_reasons(&h)
                .iter()
                .filter(|r| *r == "invalid_auth_time")
                .count();
            assert_eq!(n, 3);
        }

        // (6) a legacy session (created before migration 0003) is challenged at
        // its first console entry while its application-host verifies are unaffected.
        {
            let (idp, h) = spawn("m4-admin", "auth_time_present", long_handles());
            let app = sign_in(&h, &idp, &format!("https://{APP}/x"));
            let user = session(&h).user_id;
            let (_sid, handle) = h.hooks.legacy_session(&user, Some(CONSOLE));
            let handle = handle.expect("console handle");
            let r = h.verify(
                VerifyRequest::document(&console_url())
                    .ip("192.0.2.10")
                    .cookie(HANDLE, &handle)
                    .header("sec-fetch-site", "same-origin"),
            );
            assert_eq!(r.status, 302, "{r:?}");
            assert_eq!(r.header("x-hopae-reason"), Some("reauth_required"), "{r:?}");
            let ok = h.verify(
                VerifyRequest::document(&format!("https://{APP}/x"))
                    .ip(IP)
                    .cookie(HANDLE, &app.handle)
                    .cookie(BIND, &app.bind)
                    .header("sec-fetch-site", "same-origin"),
            );
            assert_eq!(ok.status, 200, "{ok:?}");
        }

        // An unsupported provider: (3) and (6) enter the console on login age, and
        // (4) fails the login regardless.
        {
            let (idp, h) = spawn_unsupported("auth_time_missing", long_handles());
            let b = sign_in(&h, &idp, &console_url());
            assert_eq!(b.verify(&h).status, 200);
            let user = session(&h).user_id;
            let (_sid, handle) = h.hooks.legacy_session(&user, Some(CONSOLE));
            let r = h.verify(
                VerifyRequest::document(&console_url())
                    .ip("192.0.2.10")
                    .cookie(HANDLE, &handle.unwrap())
                    .header("sec-fetch-site", "same-origin"),
            );
            assert_eq!(r.status, 200, "{r:?}");
            idp.set_auth_time(Some(json!(now_s(&h) + 120)));
            let first = h.verify(
                VerifyRequest::document(&format!("https://{APP}/x"))
                    .ip("203.0.113.50")
                    .header("sec-fetch-site", "same-origin"),
            );
            let c = h.portal_with(Jar::new()).with_ip("203.0.113.50");
            let authorize = to_provider(&c, &txn_of(&first), "mock");
            let cb = c.get(&idp.follow_authorization(&authorize));
            assert_eq!(cb.status, 400, "{cb:?}");
        }
    }

    #[test]
    fn s300_a10_callback_headroom_reaches_console_and_boundaries_are_exact() {
        // (claim offset relative to the callback time, accepted?)
        fn run(
            h: &Hopae,
            idp: &MockIdp,
            b: Browser,
            n: i64,
            offset: i64,
            accepted: bool,
        ) -> Browser {
            let s0 = session(h);
            at(h, (s0.auth_time + n + 1).max(now_s(h)));
            let txn = expect_reauth(h, &b);
            idp.set_auth_time(Some(json!(now_s(h) + offset)));
            let cb = round_trip(h, idp, &b, &txn);
            if !accepted {
                assert_eq!(cb.status, 400, "offset {offset}: {cb:?}");
                assert_eq!(session(h).cred_gen, s0.cred_gen, "offset {offset}");
                return b;
            }
            assert_eq!(cb.status, 302, "offset {offset}: {cb:?}");
            let s1 = session(h);
            assert_eq!(s1.auth_time, now_s(h) + offset);
            let b = redeem(h, b, cb.location().unwrap());
            assert_eq!(b.verify(h).status, 200, "immediately");
            let claim = s1.auth_time;
            // 599 s later (the end of the transaction lifetime), and at N - 1 s after the claim.
            at(h, now_s(h) + 599);
            assert_eq!(b.verify(h).status, 200, "599 s later, offset {offset}");
            at(h, claim + n - 1);
            assert_eq!(
                b.verify(h).status,
                200,
                "N - 1 s after the claim, offset {offset}"
            );
            b
        }
        let (idp, h) = spawn("m4-admin", "auth_time_present", long_handles());
        let mut b = sign_in(&h, &idp, &console_url());
        let bound = N - 600;
        // Just inside the headroom, exactly at it, inside N but outside the headroom.
        b = run(&h, &idp, b, N, -(bound - 1), true);
        b = run(&h, &idp, b, N, -bound, false);
        b = run(&h, &idp, b, N, -(N - 30), false);
        b = run(&h, &idp, b, N, 59, true);
        b = run(&h, &idp, b, N, 61, false);
        let failed = failed_reasons(&h);
        assert_eq!(
            failed.iter().filter(|r| *r == "reauth_not_fresh").count(),
            2,
            "{failed:?}"
        );
        assert_eq!(
            failed.iter().filter(|r| *r == "invalid_auth_time").count(),
            1,
            "{failed:?}"
        );
        drop(b);

        // The smallest permitted bound: callback bound 20 minutes.
        let n = 30 * 60;
        let (idp, h) = spawn("m4-admin", "auth_time_present", {
            let mut o = long_handles();
            o["admin"]["max_auth_age"] = json!("30m");
            o
        });
        let mut b = sign_in(&h, &idp, &console_url());
        b = run(&h, &idp, b, n, -(19 * 60 + 59), true);
        b = run(&h, &idp, b, n, -(20 * 60), false);
        drop(b);
    }
}

#[test]
fn s300_6_stored_reauth_prompt_none_asks_for_max_age_only() {
    let (idp, h) = reauth::spawn_stored(
        "m4-admin",
        "auth_time_present",
        reauth::long_handles(),
        serde_json::json!({"reauth_prompt": "none"}),
    );
    let b = reauth::sign_in(&h, &idp, &reauth::console_url());
    let s0 = reauth::session(&h);
    reauth::at(&h, s0.auth_time + reauth::N + 1);
    let txn = reauth::expect_reauth(&h, &b);
    let cb = reauth::round_trip(&h, &idp, &b, &txn);
    let last = idp.authorize_requests().pop().unwrap();
    assert_eq!(last.max_age.as_deref(), Some("43200"));
    assert_eq!(last.prompt, None, "reauth_prompt = none");
    assert_eq!(cb.status, 302, "{cb:?}");
}

// ---- W2: the gateway layer (`make e2e`) --------------------------------------

mod gateway_layer {
    use std::time::Duration;

    use crate::support::gateway::{Edge, GatewayRoutes, PORTAL_HOST, Stack};
    use crate::support::{Fixture, Req};

    const CONSOLE: &str = "hopae-admin.example.test";
    const HANDLE: &str = "__Host-hopae";
    const BIND: &str = "__Host-hopae_bind";

    fn start(test: &str, routes: GatewayRoutes) -> Option<Stack> {
        Stack::start(test, Fixture::new("m4-admin"), routes, Edge::Terminator)
    }

    fn console_routes() -> GatewayRoutes {
        GatewayRoutes::new()
            .portal(PORTAL_HOST)
            .with_console(CONSOLE)
    }

    fn db(s: &Stack) -> rusqlite::Connection {
        let c = rusqlite::Connection::open(s.hopae.state_dir.path().join("state/hopae.db"))
            .expect("open the store");
        c.busy_timeout(Duration::from_secs(5)).unwrap();
        c
    }

    fn cookie(r: &crate::support::Response, name: &str) -> Option<String> {
        r.set_cookies().iter().find_map(|c| {
            c.strip_prefix(&format!("{name}="))
                .map(|rest| rest.split(';').next().unwrap_or("").to_string())
        })
    }

    /// Sign in at the console host through the gateway; returns the browser,
    /// the console handle and the user id.
    fn sign_in(s: &Stack) -> (crate::support::gateway::Browser, String, String) {
        let b = s.gw.browser();
        let first = b.get(CONSOLE, "/users");
        assert_eq!(first.status, 302, "{first:?}");
        let code = b.login_from(&s.idp, first);
        let handoff = b.redeem(&code);
        assert_eq!(handoff.status, 302, "{handoff:?}");
        let handle = cookie(&handoff, HANDLE).expect("the console handle is planted");
        let user: String = db(s)
            .query_row(
                "SELECT user_id FROM sessions WHERE terminated_at IS NULL ORDER BY created_at DESC LIMIT 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        (b, handle, user)
    }

    fn grant(s: &Stack, user: &str) {
        let now = s.hopae.hooks.now_ms() / 1000;
        db(s)
            .execute(
                "INSERT INTO admin_grants (user_id, role, managed_by, granted_at, granted_by) VALUES (?1, 'admin', 'api', ?2, 'cli')",
                rusqlite::params![user, now],
            )
            .unwrap();
    }

    #[test]
    #[ignore = "gateway layer: needs HOPAE_E2E_GATEWAY_BINARY (make e2e)"]
    fn s300_1_first_visit_logs_in_and_lands_with_console_handle() {
        let Some(s) = start("s300_1", console_routes()) else {
            return;
        };
        let b = s.gw.browser();
        let first = b.get(CONSOLE, "/users");
        assert_eq!(first.status, 302, "{first:?}");
        assert!(
            first
                .location()
                .unwrap()
                .starts_with("https://auth.example.test/login?txn="),
            "{first:?}"
        );
        assert!(
            cookie(&first, BIND).is_some(),
            "bind cookie on the console host"
        );
        let code = b.login_from(&s.idp, first);
        assert!(
            code.handoff_location
                .starts_with("https://hopae-admin.example.test/_hopae/login?"),
            "{}",
            code.handoff_location
        );
        assert!(code.handoff_location.contains("return="));
        assert!(code.handoff_location.contains("_hopae_handoff="));
        // Nothing reached the listener before the handoff: no administrator event.
        assert!(s.hopae.hooks.events(Some("admin.denied"), None).is_empty());
        let handoff = b.redeem(&code);
        assert_eq!(handoff.status, 302, "{handoff:?}");
        let handle = cookie(&handoff, HANDLE).expect("__Host-hopae planted");
        assert!(!handle.is_empty());
        // The handle reaches the listener (no stripping): the user is named, not asked to log in.
        let page = b.get(CONSOLE, "/users");
        assert_eq!(page.status, 403, "{page:?}");
        assert!(page.body.contains("not_admin"), "{}", page.body);
        let user: String = db(&s)
            .query_row("SELECT user_id FROM sessions LIMIT 1", [], |r| r.get(0))
            .unwrap();
        assert!(page.body.contains(&user), "the page names the user");
        grant(&s, &user);
        let page = b.get(CONSOLE, "/users");
        assert_eq!(page.status, 200, "{page:?}");
        let (app, src, at): (String, String, i64) = {
            let c = db(&s);
            let app: String = c
                .query_row(
                    "SELECT app_id FROM login_txns ORDER BY created_at LIMIT 1",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            let (src, at) = c
                .query_row(
                    "SELECT auth_time_source, auth_time FROM sessions LIMIT 1",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .unwrap();
            (app, src, at)
        };
        assert_eq!(app, "admin");
        assert_eq!(src, "provider_claim");
        let now = s.hopae.hooks.now_ms() / 1000;
        assert!((now - at).abs() <= 30, "auth_time {at} vs now {now}");
        let created = s.hopae.hooks.events(Some("session.created"), None);
        assert_eq!(
            created.last().unwrap()["attrs"]["auth_time_source"],
            "provider_claim"
        );
    }

    #[test]
    #[ignore = "gateway layer: needs HOPAE_E2E_GATEWAY_BINARY (make e2e)"]
    fn s300_10_sign_out_from_console_ends_session_everywhere() {
        let Some(s) = start("s300_10", console_routes()) else {
            return;
        };
        let (b, handle, user) = sign_in(&s);
        grant(&s, &user);
        assert_eq!(b.get(CONSOLE, "/users").status, 200);
        // The sign-out link of the page (015-1 to 015-3).
        let r = b.get_with(
            CONSOLE,
            "/_hopae/logout",
            &[("sec-fetch-site", "same-origin")],
        );
        assert_eq!(r.status, 302, "{r:?}");
        let loc = r.location().unwrap().to_string();
        assert!(
            loc.starts_with("https://auth.example.test/logout?txn="),
            "{loc}"
        );
        let txn = loc.split("txn=").nth(1).unwrap().to_string();
        let page = b.get_cross_site(PORTAL_HOST, &format!("/logout?txn={txn}"));
        assert_eq!(page.status, 200, "{page:?}");
        let csrf = page
            .body
            .split("name=\"csrf\" value=\"")
            .nth(1)
            .and_then(|r| r.split('"').next())
            .expect("csrf")
            .to_string();
        let out = b.send(
            PORTAL_HOST,
            Req::post("/logout")
                .form(&[("csrf", &csrf), ("txn", &txn)])
                .header("origin", "https://auth.example.test"),
        );
        assert_eq!(out.status, 200, "{out:?}");
        let reason: Option<String> = db(&s)
            .query_row(
                "SELECT terminated_reason FROM sessions WHERE user_id = ?1",
                [&user],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(reason.as_deref(), Some("logout"));
        // The next navigation is the unauthenticated 302; the listener sees nothing.
        let denied_before = s.hopae.hooks.events(Some("admin.denied"), None).len();
        let next = b.get(CONSOLE, "/");
        assert_eq!(next.status, 302, "{next:?}");
        assert!(
            next.location()
                .unwrap()
                .starts_with("https://auth.example.test/login?txn=")
        );
        assert_eq!(
            s.hopae.hooks.events(Some("admin.denied"), None).len(),
            denied_before
        );
        // A stale handle sent straight to the listener is refused.
        let direct = s.hopae.admin_client().with_handle(&handle).get("/v1/me");
        assert_eq!(direct.status, 403, "{direct:?}");
        assert_eq!(direct.json()["error"], "login_required", "{direct:?}");
    }

    #[test]
    #[ignore = "gateway layer: needs HOPAE_E2E_GATEWAY_BINARY (make e2e)"]
    fn s300_12_console_route_without_auth_is_403_not_a_loop() {
        let routes = GatewayRoutes::new()
            .portal(PORTAL_HOST)
            .with_public_console(CONSOLE);
        let Some(s) = start("s300_12", routes) else {
            return;
        };
        let b = s.gw.browser();
        let r = b.get(CONSOLE, "/");
        assert_eq!(r.status, 403, "{r:?}");
        assert!(r.body.contains("login_required"), "{}", r.body);
        assert!(
            r.body.contains("https://hopae-admin.example.test/"),
            "the console URL is the link: {}",
            r.body
        );
        let txns: i64 = db(&s)
            .query_row("SELECT COUNT(*) FROM login_txns", [], |r| r.get(0))
            .unwrap();
        assert_eq!(txns, 0, "no login was started");
        assert!(
            s.gw.tap.calls().is_empty(),
            "the gateway made no verify call"
        );
    }
}
