//! Placeholder declared by W0 (M4-min): the scenario tests of this file are
//! added by their work package (see `internal/M4MIN_PLAN.md`).

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
        at(&h, auth0 + N - 1);
        assert_eq!(b.verify(&h).status, 200, "N - 1 s is fresh");
        at(&h, auth0 + N);
        let _ = expect_reauth(&h, &b); // equality is not fresh
        at(&h, auth0 + N + 1);
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
fn s300_6b_stored_reauth_prompt_none_asks_for_max_age_only() {
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
