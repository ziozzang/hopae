//! Scenarios 480–486: WebAuthn passkeys (ADR-0017), driven through the real
//! process with a software authenticator standing in for the browser's
//! `navigator.credentials` (the portal script only shuttles JSON).

use std::time::Duration;

use serde_json::{Value, json};
use webauthn_authenticator_rs::WebauthnAuthenticator;
use webauthn_authenticator_rs::softpasskey::SoftPasskey;
use webauthn_rs::prelude::{CreationChallengeResponse, RequestChallengeResponse, Url};

use crate::support::{Client, Fixture, Hopae, Jar, MockIdp, Req, Response, VerifyRequest};

const PORTAL: &str = "https://auth.example.test";
const IP: &str = "203.0.113.9";
const HOME: &str = "https://app.example.test/home";
const ADMIN: &str = "https://app.example.test/admin/x";

fn passkey_config(extra: Value) -> Value {
    let mut v = json!({
        "webauthn": {},
        "apps": [{"app_id": "app", "step_up": [{"path_prefix": "/admin", "require": {"aal": 2, "max_age": 900}}]}]
    });
    if let (Some(a), Some(b)) = (v.as_object_mut(), extra.as_object()) {
        for (k, val) in b {
            a.insert(k.clone(), val.clone());
        }
    }
    v
}

/// The `value` of input `name` inside the form posting to `action` (or anywhere when `action` is empty).
fn field(html: &str, action: &str, name: &str) -> String {
    let scope = if action.is_empty() {
        html
    } else {
        let start = html
            .find(&format!("action=\"{action}\""))
            .unwrap_or_else(|| panic!("no form {action} in {html}"));
        let rest = &html[start..];
        &rest[..rest.find("</form>").unwrap_or(rest.len())]
    };
    let needle = format!("name=\"{name}\" value=\"");
    let at = scope
        .find(&needle)
        .unwrap_or_else(|| panic!("no field {name} in {scope}"));
    let v = &scope[at + needle.len()..];
    unescape(&v[..v.find('"').expect("closing quote")])
}

fn unescape(s: &str) -> String {
    s.replace("&#34;", "\"")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&#60;", "<")
        .replace("&#62;", ">")
        .replace("&#38;", "&")
        .replace("&amp;", "&")
}

fn options(html: &str) -> String {
    let at = html.find("data-options=\"").expect("ceremony options");
    let v = &html[at + "data-options=\"".len()..];
    unescape(&v[..v.find('"').expect("closing quote")])
}

/// What a browser's `PublicKeyCredential.toJSON()` would carry.
fn browser_json<T: serde::Serialize>(credential: &T) -> String {
    let mut v = serde_json::to_value(credential).unwrap();
    if let Some(o) = v.as_object_mut()
        && let Some(ext) = o.remove("extensions")
    {
        o.insert("clientExtensionResults".into(), ext);
    }
    v.to_string()
}

struct Pk {
    _idp: MockIdp,
    h: Hopae,
    portal: Client,
    app_jar: Jar,
    base: String,
    key: WebauthnAuthenticator<SoftPasskey>,
}

impl Pk {
    fn start(over: Value) -> Pk {
        let idp = MockIdp::start("default");
        let h = Hopae::spawn(Fixture::with("m1-basic", over), &idp, &[]);
        let base = h.config()["cookie"]["name"].as_str().unwrap().to_string();
        let portal = h.portal_with(Jar::new()).with_ip(IP);
        let pk = Pk {
            _idp: idp,
            h,
            portal,
            app_jar: Jar::new(),
            base,
            key: WebauthnAuthenticator::new(SoftPasskey::new(true)),
        };
        let r = pk.verify(HOME);
        assert_eq!(r.status, 302, "{r:?}");
        let mut r = pk.portal.get(&path_of(r.location().unwrap()));
        if r.status == 200 {
            // The chooser (passwordless offered beside the provider).
            r = pk.post(
                "/login/mock",
                &[
                    ("csrf", &field(&r.body, "/login/mock", "csrf")),
                    ("txn", &field(&r.body, "/login/mock", "txn")),
                ],
            );
        }
        assert_eq!(r.status, 302, "{r:?}");
        let cb = pk._idp.follow_authorization(r.location().unwrap());
        let back = pk.portal.send(Req::get(&cb).cross_site_navigation());
        assert_eq!(back.status, 302, "{back:?}");
        let redeem = pk.verify(back.location().unwrap());
        assert_eq!(redeem.status, 302, "{redeem:?}");
        // The test-hook clock is frozen at spawn while the mock provider's
        // `auth_time` is wall time: under load the session would look
        // authenticated in the future. Move Hopae's clock past it.
        let wall = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        pk.h.set_clock_ms(wall.max(pk.h.hooks.now_ms()) + 1000);
        pk
    }

    fn verify(&self, url: &str) -> Response {
        let jar = self.app_jar.for_host("app.example.test");
        let mut req = VerifyRequest::document(url).ip(IP);
        for n in [self.base.clone(), format!("{}_bind", self.base)] {
            if let Some(v) = jar.value(&n) {
                req = req.cookie(&n, &v);
            }
        }
        let r = self.h.verify(req);
        for c in r.set_cookies() {
            self.app_jar.store("app.example.test", "/", true, c);
        }
        r
    }

    fn post(&self, path: &str, fields: &[(&str, &str)]) -> Response {
        self.portal
            .send(Req::post(path).header("origin", PORTAL).form(fields))
    }

    /// The registration page, the authenticator's response, the POST.
    fn register(&mut self, label: &str) -> Response {
        let page = self.portal.get("/security/passkeys/new");
        assert_eq!(page.status, 200, "{page:?} {}", page.body);
        let opts: CreationChallengeResponse = serde_json::from_str(&options(&page.body)).unwrap();
        let cred = self
            .key
            .do_registration(Url::parse(PORTAL).unwrap(), opts)
            .unwrap();
        self.post(
            "/security/passkeys/new",
            &[
                ("csrf", &field(&page.body, "/security/passkeys/new", "csrf")),
                (
                    "ceremony",
                    &field(&page.body, "/security/passkeys/new", "ceremony"),
                ),
                ("kind", "passkey"),
                ("label", label),
                ("credential", &browser_json(&cred)),
            ],
        )
    }

    /// Prove the passkey on `/security/verify` (from `origin`).
    fn verify_portal(&mut self, origin: &str) -> Response {
        let page = self.portal.get("/security/verify?next=passkeys");
        assert_eq!(page.status, 200, "{page:?} {}", page.body);
        let opts: RequestChallengeResponse = serde_json::from_str(&options(&page.body)).unwrap();
        let cred = self
            .key
            .do_authentication(Url::parse(origin).unwrap(), opts)
            .unwrap();
        self.post(
            "/security/verify/passkey",
            &[
                (
                    "csrf",
                    &field(&page.body, "/security/verify/passkey", "csrf"),
                ),
                ("next", "passkeys"),
                (
                    "ceremony",
                    &field(&page.body, "/security/verify/passkey", "ceremony"),
                ),
                ("credential", &browser_json(&cred)),
            ],
        )
    }

    /// The application step-up for `/admin`: verify → portal page → assertion → POST.
    /// Returns the step-up page and the POST answer.
    fn stepup(&mut self, origin: &str) -> (Response, Response, Vec<(String, String)>) {
        let r = self.verify(ADMIN);
        assert_eq!(r.status, 302, "step-up redirect: {r:?}");
        let page = self.portal.get(&path_of(r.location().unwrap()));
        assert_eq!(page.status, 200, "{page:?} {}", page.body);
        let opts: RequestChallengeResponse = serde_json::from_str(&options(&page.body)).unwrap();
        let cred = self
            .key
            .do_authentication(Url::parse(origin).unwrap(), opts)
            .unwrap();
        let form = vec![
            (
                "csrf".to_string(),
                field(&page.body, "/stepup/webauthn", "csrf"),
            ),
            (
                "txn".to_string(),
                field(&page.body, "/stepup/webauthn", "txn"),
            ),
            (
                "ceremony".to_string(),
                field(&page.body, "/stepup/webauthn", "ceremony"),
            ),
            ("credential".to_string(), browser_json(&cred)),
        ];
        let refs: Vec<(&str, &str)> = form.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        let done = self.post("/stepup/webauthn", &refs);
        (page, done, form)
    }

    fn sql(&self, sql: &str) -> i64 {
        let c = rusqlite::Connection::open(self.h.state_dir.path().join("state").join("hopae.db"))
            .unwrap();
        c.busy_timeout(Duration::from_secs(5)).unwrap();
        c.query_row(sql, [], |r| r.get(0)).unwrap()
    }

    fn exec(&self, sql: &str) {
        let c = rusqlite::Connection::open(self.h.state_dir.path().join("state").join("hopae.db"))
            .unwrap();
        c.busy_timeout(Duration::from_secs(5)).unwrap();
        c.execute_batch(sql).unwrap();
    }

    fn events(&self, kind: &str) -> Vec<Value> {
        self.h.hooks.events(Some(kind), Some(50))
    }
}

fn path_of(u: &str) -> String {
    let u = url::Url::parse(u).unwrap();
    match u.query() {
        Some(q) => format!("{}?{q}", u.path()),
        None => u.path().to_string(),
    }
}

// ---- 480: registration ----------------------------------------------------

#[test]
fn s480_1_register_passkey_from_a_fresh_session() {
    let mut p = Pk::start(passkey_config(json!({})));
    let overview = p.portal.get("/security");
    assert_eq!(overview.status, 200, "{overview:?}");
    assert!(overview.body.contains("href=\"/security/passkeys/new\""));
    assert!(
        !overview.body.contains("<script"),
        "the overview runs no script"
    );
    let r = p.register("");
    assert_eq!(r.status, 303, "{r:?}");
    // The first factor leads to recovery codes.
    assert_eq!(r.location(), Some("/security/recovery-codes?first=1"));
    assert_eq!(p.sql("SELECT COUNT(*) FROM webauthn_credentials WHERE state='active' AND label='Passkey' AND user_verified=1 AND assurance='aal2'"), 1);
    let ev = p.events("factor.webauthn_registered");
    assert_eq!(ev.len(), 1, "{ev:?}");
    let list = p.portal.get("/security/passkeys");
    assert!(
        list.body.contains("Device-bound passkey") && list.body.contains("value=\"Passkey\""),
        "{}",
        list.body
    );
}

#[test]
fn s480_2_a_second_passkey_needs_verification_first() {
    let mut p = Pk::start(passkey_config(json!({})));
    assert_eq!(p.register("Laptop").status, 303);
    let r = p.portal.get("/security/passkeys/new");
    assert_eq!(r.status, 303, "{r:?}");
    assert_eq!(r.location(), Some("/security/verify?next=passkeys_new"));
    let v = p.verify_portal(PORTAL);
    assert_eq!(v.status, 303, "{v:?}");
    assert!(
        v.set_cookies()
            .iter()
            .any(|c| c.starts_with(&format!("{}=", p.base))),
        "portal handle reissued"
    );
    p.key = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let r = p.register("Phone");
    assert_eq!(r.location(), Some("/security/passkeys?done=added"), "{r:?}");
    assert_eq!(
        p.sql("SELECT COUNT(*) FROM webauthn_credentials WHERE state='active'"),
        2
    );
}

#[test]
fn s480_a1_replayed_registration_is_refused() {
    let mut p = Pk::start(passkey_config(json!({})));
    let page = p.portal.get("/security/passkeys/new");
    let opts: CreationChallengeResponse = serde_json::from_str(&options(&page.body)).unwrap();
    let cred = p
        .key
        .do_registration(Url::parse(PORTAL).unwrap(), opts)
        .unwrap();
    let csrf = field(&page.body, "/security/passkeys/new", "csrf");
    let ceremony = field(&page.body, "/security/passkeys/new", "ceremony");
    let body = browser_json(&cred);
    let form = [
        ("csrf", csrf.as_str()),
        ("ceremony", ceremony.as_str()),
        ("kind", "passkey"),
        ("credential", body.as_str()),
    ];
    assert_eq!(p.post("/security/passkeys/new", &form).status, 303);
    let again = p.post("/security/passkeys/new", &form);
    // The ceremony is spent; now a factor exists, so a new ceremony needs verification first.
    assert_eq!(again.status, 303, "{again:?}");
    assert_eq!(again.location(), Some("/security/verify?next=passkeys_new"));
    assert_eq!(p.sql("SELECT COUNT(*) FROM webauthn_credentials"), 1);
}

#[test]
fn s480_a2_missing_token_or_foreign_origin_is_refused() {
    let mut p = Pk::start(passkey_config(json!({})));
    let page = p.portal.get("/security/passkeys/new");
    let opts: CreationChallengeResponse = serde_json::from_str(&options(&page.body)).unwrap();
    let cred = browser_json(
        &p.key
            .do_registration(Url::parse(PORTAL).unwrap(), opts)
            .unwrap(),
    );
    let ceremony = field(&page.body, "/security/passkeys/new", "ceremony");
    let csrf = field(&page.body, "/security/passkeys/new", "csrf");
    let no_token = p.post(
        "/security/passkeys/new",
        &[
            ("ceremony", &ceremony),
            ("kind", "passkey"),
            ("credential", &cred),
        ],
    );
    assert_eq!(no_token.status, 400, "{no_token:?}");
    let foreign = p.portal.send(
        Req::post("/security/passkeys/new")
            .header("origin", "https://app.example.test")
            .form(&[
                ("csrf", &csrf),
                ("ceremony", &ceremony),
                ("kind", "passkey"),
                ("credential", &cred),
            ]),
    );
    assert_eq!(foreign.status, 403, "{foreign:?}");
    // A token for another action does not authorize registration.
    // A token for another action does not authorize that action.
    let wrong = p.post(
        "/security/passkeys/rename",
        &[
            ("csrf", &csrf),
            ("credential", "AAAAAAAAAAAAAAAAAAAAAA"),
            ("label", "x"),
        ],
    );
    assert_eq!(wrong.status, 403, "{wrong:?}");
    assert_eq!(p.sql("SELECT COUNT(*) FROM webauthn_credentials"), 0);
    assert!(!p.h.hooks.events(Some("csrf.rejected"), Some(10)).is_empty());
}

#[test]
fn s480_a3_without_a_session_or_https_nothing_is_offered() {
    let p = Pk::start(passkey_config(json!({})));
    let stranger = p.h.portal_with(Jar::new()).with_ip(IP);
    let r = stranger.get("/security/passkeys/new");
    assert_eq!(r.status, 403, "{r:?}");
    assert!(r.body.contains("Sign in first"));
    let plain = Client::new(
        p.portal.addr,
        "auth.example.test",
        false,
        p.portal.jar.clone(),
    )
    .with_ip(IP);
    assert_eq!(plain.get("/security").status, 403);
    assert_eq!(p.sql("SELECT COUNT(*) FROM webauthn_challenges"), 0);
}

#[test]
fn s480_a4_ceremony_is_bound_to_the_browser_that_started_it() {
    let mut p = Pk::start(passkey_config(json!({})));
    let page = p.portal.get("/security/passkeys/new");
    let opts: CreationChallengeResponse = serde_json::from_str(&options(&page.body)).unwrap();
    let cred = browser_json(
        &p.key
            .do_registration(Url::parse(PORTAL).unwrap(), opts)
            .unwrap(),
    );
    // Same handle, another binding cookie (a copied handle in another browser).
    let other = p.h.portal_with(Jar::new()).with_ip(IP);
    let handle = p
        .portal
        .jar
        .for_host("auth.example.test")
        .value(&p.base)
        .unwrap();
    let fresh = other.get("/security"); // plants the other browser's binding cookie
    assert_eq!(fresh.status, 403, "no handle yet");
    other.jar.store(
        "auth.example.test",
        "/",
        true,
        &format!("{}={handle}; Path=/; Secure; HttpOnly", p.base),
    );
    let r = other.send(
        Req::post("/security/passkeys/new")
            .header("origin", PORTAL)
            .form(&[
                ("csrf", &field(&page.body, "/security/passkeys/new", "csrf")),
                (
                    "ceremony",
                    &field(&page.body, "/security/passkeys/new", "ceremony"),
                ),
                ("kind", "passkey"),
                ("credential", &cred),
            ]),
    );
    assert_eq!(
        r.status, 403,
        "the token names the first browser's binding: {r:?}"
    );
    assert_eq!(p.sql("SELECT COUNT(*) FROM webauthn_credentials"), 0);
}

// ---- 481: application step-up ---------------------------------------------

#[test]
fn s481_1_passkey_stepup_yields_aal2_identity() {
    let mut p = Pk::start(passkey_config(json!({})));
    assert_eq!(p.register("Laptop").status, 303);
    let (page, done, _) = p.stepup(PORTAL);
    assert!(page.body.contains("data-webauthn=\"get\""));
    let csp = page.header("content-security-policy").unwrap();
    assert!(
        csp.contains("script-src 'self'")
            && csp.contains("require-trusted-types-for 'script'")
            && csp.contains("form-action 'self' https://app.example.test"),
        "{csp}"
    );
    assert_eq!(done.status, 302, "{done:?}");
    let handoff = done.location().unwrap().to_string();
    assert!(
        handoff.starts_with("https://app.example.test/") && handoff.contains("_hopae_handoff="),
        "{handoff}"
    );
    let redeem = p.verify(&handoff);
    assert_eq!(redeem.status, 302, "{redeem:?}");
    let clean = p.verify(redeem.location().unwrap_or(ADMIN));
    assert_eq!(clean.status, 200, "{clean:?}");
    assert_eq!(
        clean.header("x-hopae-aal"),
        Some("2"),
        "AAL 2, never 3 (ADR-0017 decision 7)"
    );
    assert!(
        clean
            .header("x-hopae-factors")
            .unwrap()
            .contains("webauthn"),
        "{clean:?}"
    );
    let used = p.events("factor.webauthn_used");
    assert_eq!(used.len(), 1);
    assert_eq!(used[0]["attrs"]["assurance"], "aal2");
}

#[test]
fn s481_2_user_without_passkey_is_sent_to_setup() {
    let p = Pk::start(passkey_config(json!({})));
    let r = p.verify(ADMIN);
    assert_eq!(r.status, 302);
    let page = p.portal.get(&path_of(r.location().unwrap()));
    assert_eq!(page.status, 200, "{page:?} {}", page.body);
    assert!(page.body.contains("href=\"/security\""), "{}", page.body);
    assert!(!page.body.contains("<script"));
}

#[test]
fn s481_a1_assertion_from_another_origin_is_refused() {
    let mut p = Pk::start(passkey_config(json!({})));
    assert_eq!(p.register("Laptop").status, 303);
    // A subdomain of the RP ID may ask the authenticator; Hopae pins the portal origin.
    let (_, done, _) = p.stepup("https://evil.auth.example.test");
    assert_eq!(
        done.status, 200,
        "the page is shown again with an error: {done:?}"
    );
    assert!(done.body.contains("verify that passkey"), "{}", done.body);
    assert_eq!(p.events("factor.webauthn_failed").len(), 1);
    assert_eq!(p.sql("SELECT COUNT(*) FROM sessions WHERE aal=2"), 0);
}

#[test]
fn s481_a2_replayed_assertion_is_refused() {
    let mut p = Pk::start(passkey_config(json!({})));
    assert_eq!(p.register("Laptop").status, 303);
    let (_, done, form) = p.stepup(PORTAL);
    assert_eq!(done.status, 302);
    let refs: Vec<(&str, &str)> = form.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let again = p.post("/stepup/webauthn", &refs);
    assert_ne!(again.status, 302, "{again:?}");
    assert_eq!(
        p.sql("SELECT COUNT(*) FROM session_handles WHERE issued_aal=2 AND revoked_at IS NULL"),
        1
    );
}

// ---- 482: security confirmation -------------------------------------------

#[test]
fn s482_1_portal_verification_rotates_handles_and_opens_management() {
    let mut p = Pk::start(passkey_config(json!({})));
    assert_eq!(p.register("Laptop").status, 303);
    let before = p
        .portal
        .jar
        .for_host("auth.example.test")
        .value(&p.base)
        .unwrap();
    let v = p.verify_portal(PORTAL);
    assert_eq!(
        v.location(),
        Some("/security/passkeys?done=verified"),
        "{v:?}"
    );
    let after = p
        .portal
        .jar
        .for_host("auth.example.test")
        .value(&p.base)
        .unwrap();
    assert_ne!(before, after);
    assert_eq!(
        p.sql("SELECT COUNT(*) FROM session_handles WHERE revoked_reason='elevation'"),
        2,
        "portal and app handles"
    );
    let overview = p.portal.get("/security?done=verified");
    assert!(
        overview.body.contains("You confirmed it"),
        "{}",
        overview.body
    );
}

#[test]
fn s482_a1_assertion_for_another_rp_id_is_refused() {
    let mut p = Pk::start(passkey_config(json!({})));
    assert_eq!(p.register("Laptop").status, 303);
    let page = p.portal.get("/security/verify?next=security");
    let mut opts: RequestChallengeResponse = serde_json::from_str(&options(&page.body)).unwrap();
    opts.public_key.rp_id = "example.test".into();
    let cred = p
        .key
        .do_authentication(Url::parse(PORTAL).unwrap(), opts)
        .unwrap();
    let r = p.post(
        "/security/verify/passkey",
        &[
            (
                "csrf",
                &field(&page.body, "/security/verify/passkey", "csrf"),
            ),
            ("next", "security"),
            (
                "ceremony",
                &field(&page.body, "/security/verify/passkey", "ceremony"),
            ),
            ("credential", &browser_json(&cred)),
        ],
    );
    assert_eq!(r.status, 200, "{r:?}");
    assert!(r.body.contains("verify that passkey"));
    assert_eq!(p.sql("SELECT COUNT(*) FROM sessions WHERE aal=2"), 0);
}

// ---- 483: clone signal ----------------------------------------------------

#[test]
fn s483_1_counter_regression_revokes_the_passkey_and_ends_its_sessions() {
    let mut p = Pk::start(passkey_config(json!({})));
    assert_eq!(p.register("Laptop").status, 303);
    let (_, done, _) = p.stepup(PORTAL);
    assert_eq!(done.status, 302);
    // The server has seen a far higher counter than the key will report next.
    p.exec("UPDATE webauthn_credentials SET sign_count=1000, passkey=json_set(passkey,'$.counter',1000)");
    let r = p.verify_portal(PORTAL);
    // The acting session was elevated with the cloned key: it ends too, and the page says why.
    assert_eq!(r.status, 403, "{r:?}");
    assert!(
        r.body.contains("turned off to protect your account"),
        "{}",
        r.body
    );
    assert_eq!(p.sql("SELECT COUNT(*) FROM webauthn_credentials WHERE state='revoked' AND revoked_reason='counter_regression'"), 1);
    assert_eq!(
        p.sql("SELECT COUNT(*) FROM sessions WHERE terminated_reason='counter_regression'"),
        1
    );
    assert_eq!(p.events("factor.webauthn_clone_suspected").len(), 1);
}

// ---- 484: management ------------------------------------------------------

#[test]
fn s484_1_rename_and_remove_with_confirmation() {
    let mut p = Pk::start(passkey_config(json!({})));
    assert_eq!(p.register("Laptop").status, 303);
    assert_eq!(p.verify_portal(PORTAL).status, 303);
    p.key = WebauthnAuthenticator::new(SoftPasskey::new(true));
    assert_eq!(p.register("Phone").status, 303);
    let list = p.portal.get("/security/passkeys");
    let id = field(&list.body, "/security/passkeys/remove", "credential");
    let r = p.post(
        "/security/passkeys/rename",
        &[
            (
                "csrf",
                &field(&list.body, "/security/passkeys/rename", "csrf"),
            ),
            ("credential", &id),
            ("label", "Work laptop"),
        ],
    );
    assert_eq!(
        r.location(),
        Some("/security/passkeys?done=renamed"),
        "{r:?}"
    );
    let bad = p.post(
        "/security/passkeys/rename",
        &[
            (
                "csrf",
                &field(&list.body, "/security/passkeys/rename", "csrf"),
            ),
            ("credential", &id),
            ("label", "   "),
        ],
    );
    assert_eq!(
        bad.location(),
        Some("/security/passkeys?error=invalid_label")
    );
    let csrf = field(&list.body, "/security/passkeys/remove", "csrf");
    let confirm = p.post(
        "/security/passkeys/remove",
        &[("csrf", &csrf), ("credential", &id)],
    );
    assert_eq!(confirm.status, 200);
    assert!(confirm.body.contains("Work laptop") && confirm.body.contains("name=\"confirm\""));
    let gone = p.post(
        "/security/passkeys/remove",
        &[("csrf", &csrf), ("credential", &id), ("confirm", "1")],
    );
    assert_eq!(
        gone.location(),
        Some("/security/passkeys?done=removed"),
        "{gone:?}"
    );
    assert_eq!(
        p.sql("SELECT COUNT(*) FROM webauthn_credentials WHERE state='active'"),
        1
    );
    assert_eq!(p.events("factor.webauthn_revoked").len(), 1);
}

#[test]
fn s484_2_the_last_factor_cannot_be_removed() {
    let mut p = Pk::start(passkey_config(json!({})));
    assert_eq!(p.register("Laptop").status, 303);
    assert_eq!(p.verify_portal(PORTAL).status, 303);
    let single = p.portal.get("/security/passkeys");
    assert!(
        single.body.contains("only way to confirm"),
        "the page explains instead of offering removal"
    );
    assert!(!single.body.contains("action=\"/security/passkeys/remove\""));
    p.key = WebauthnAuthenticator::new(SoftPasskey::new(true));
    assert_eq!(p.register("Phone").status, 303);
    let list = p.portal.get("/security/passkeys");
    let csrf = field(&list.body, "/security/passkeys/remove", "csrf");
    let ids: Vec<String> = list
        .body
        .split("action=\"/security/passkeys/remove\"")
        .skip(1)
        .map(|f| field(f, "", "credential"))
        .collect();
    assert_eq!(ids.len(), 2);
    let first = p.post(
        "/security/passkeys/remove",
        &[("csrf", &csrf), ("credential", &ids[0]), ("confirm", "1")],
    );
    assert_eq!(
        first.location(),
        Some("/security/passkeys?done=removed"),
        "{first:?}"
    );
    // A crafted request for the remaining one is refused in the store transaction.
    let last = p.post(
        "/security/passkeys/remove",
        &[("csrf", &csrf), ("credential", &ids[1]), ("confirm", "1")],
    );
    assert_eq!(
        last.location(),
        Some("/security/passkeys?error=last_factor"),
        "{last:?}"
    );
    assert_eq!(
        p.sql("SELECT COUNT(*) FROM webauthn_credentials WHERE state='active'"),
        1
    );
    let shown = p.portal.get("/security/passkeys?error=last_factor");
    assert!(shown.body.contains("role=\"alert\""));
}

#[test]
fn s484_3_administrator_reset_revokes_factors_and_ends_sessions() {
    let mut p = Pk::start(passkey_config(json!({})));
    assert_eq!(p.register("Laptop").status, 303);
    let user: String = {
        let c = rusqlite::Connection::open(p.h.state_dir.path().join("state").join("hopae.db"))
            .unwrap();
        c.query_row("SELECT user_id FROM webauthn_credentials", [], |r| r.get(0))
            .unwrap()
    };
    let list = p.h.cli(&["admin", "factors", "list", &user]);
    assert_eq!(list.status, 0, "{}", list.all());
    assert!(
        list.stdout.contains("Laptop")
            && list.stdout.contains("pk_")
            && list.stdout.contains("aal2"),
        "{}",
        list.all()
    );
    let reset = p.h.cli(&["admin", "factors", "reset", &user]);
    assert_eq!(reset.status, 0, "{}", reset.all());
    assert!(reset.stdout.contains("1 passkey(s)"), "{}", reset.all());
    assert_eq!(
        p.sql("SELECT COUNT(*) FROM webauthn_credentials WHERE state='active'"),
        0
    );
    assert_eq!(
        p.sql("SELECT COUNT(*) FROM sessions WHERE terminated_at IS NULL"),
        0
    );
    assert_eq!(p.events("admin.factor_reset").len(), 1);
    let none =
        p.h.cli(&["admin", "factors", "list", "u_00000000000000000000000000"]);
    assert_ne!(none.status, 0);
}

#[test]
fn s484_a1_removal_needs_a_recent_second_factor() {
    let mut p = Pk::start(passkey_config(json!({})));
    assert_eq!(p.register("Laptop").status, 303);
    assert_eq!(p.verify_portal(PORTAL).status, 303);
    p.key = WebauthnAuthenticator::new(SoftPasskey::new(true));
    assert_eq!(p.register("Phone").status, 303);
    p.h.advance(Duration::from_secs(301));
    let list = p.portal.get("/security/passkeys");
    let r = p.post(
        "/security/passkeys/remove",
        &[
            (
                "csrf",
                &field(&list.body, "/security/passkeys/remove", "csrf"),
            ),
            (
                "credential",
                &field(&list.body, "/security/passkeys/remove", "credential"),
            ),
            ("confirm", "1"),
        ],
    );
    assert_eq!(
        r.location(),
        Some("/security/verify?next=passkeys"),
        "{r:?}"
    );
    assert_eq!(
        p.sql("SELECT COUNT(*) FROM webauthn_credentials WHERE state='active'"),
        2
    );
}

// ---- 485: recovery codes --------------------------------------------------

fn codes_of(html: &str) -> Vec<String> {
    html.split("<code>")
        .skip(1)
        .map(|s| s.split("</code>").next().unwrap().to_string())
        .collect()
}

#[test]
fn s485_1_codes_are_shown_once_and_a_used_code_keeps_aal1() {
    let mut p = Pk::start(passkey_config(json!({})));
    assert_eq!(p.register("Laptop").status, 303);
    let page = p.portal.get("/security/recovery-codes?first=1");
    assert!(page.body.contains("Your passkey is ready"));
    let made = p.post(
        "/security/recovery-codes",
        &[(
            "csrf",
            &field(&page.body, "/security/recovery-codes", "csrf"),
        )],
    );
    assert_eq!(made.status, 200, "{made:?}");
    assert_eq!(made.header("cache-control"), Some("no-store"));
    let codes = codes_of(&made.body);
    assert_eq!(codes.len(), 10);
    assert!(codes.iter().all(|c| c.len() == 17));
    assert_eq!(
        p.sql("SELECT COUNT(*) FROM recovery_codes WHERE hash LIKE '$argon2id$%'"),
        10
    );
    let again = p.portal.get("/security/recovery-codes");
    assert!(codes_of(&again.body).is_empty(), "never shown twice");
    let verify = p.portal.get("/security/verify?next=security");
    let csrf = field(&verify.body, "/security/verify/recovery", "csrf");
    let used = p.post(
        "/security/verify/recovery",
        &[
            ("csrf", &csrf),
            ("next", "security"),
            ("code", &codes[0].to_lowercase()),
        ],
    );
    assert_eq!(
        used.location(),
        Some("/security?done=recovered"),
        "{used:?}"
    );
    assert_eq!(
        p.sql("SELECT COUNT(*) FROM sessions WHERE aal=2"),
        0,
        "a recovery code never raises the level"
    );
    let overview = p.portal.get("/security?done=recovered");
    assert!(
        overview.body.contains("You used a recovery code"),
        "{}",
        overview.body
    );
    // The recovery entry is not AAL 2 evidence. The rotation revoked the
    // application handle; single sign-on mints a new one at AAL 1 and the
    // application still asks for a step-up.
    let r = p.verify(ADMIN);
    assert_eq!(r.status, 302, "{r:?}");
    let sso = p.portal.get(&path_of(r.location().unwrap()));
    assert_eq!(sso.status, 302, "{sso:?}");
    let redeem = p.verify(sso.location().unwrap());
    assert_eq!(redeem.status, 302, "{redeem:?}");
    let r = p.verify(ADMIN);
    assert_eq!(r.status, 302, "{r:?}");
    assert!(r.location().unwrap().contains("/stepup?"), "{r:?}");
}

#[test]
fn s485_a1_a_code_works_once_and_wrong_codes_are_refused() {
    let mut p = Pk::start(passkey_config(json!({})));
    assert_eq!(p.register("Laptop").status, 303);
    let page = p.portal.get("/security/recovery-codes");
    let made = p.post(
        "/security/recovery-codes",
        &[(
            "csrf",
            &field(&page.body, "/security/recovery-codes", "csrf"),
        )],
    );
    let codes = codes_of(&made.body);
    let verify = p.portal.get("/security/verify?next=security");
    let csrf = field(&verify.body, "/security/verify/recovery", "csrf");
    let wrong = p.post(
        "/security/verify/recovery",
        &[
            ("csrf", &csrf),
            ("next", "security"),
            ("code", "AAAAA-BBBBB-CCCCC"),
        ],
    );
    assert_eq!(wrong.status, 200);
    assert!(wrong.body.contains("That code didn"));
    assert_eq!(
        p.post(
            "/security/verify/recovery",
            &[("csrf", &csrf), ("next", "security"), ("code", &codes[1])]
        )
        .status,
        303
    );
    let verify = p.portal.get("/security/verify?next=security");
    let csrf = field(&verify.body, "/security/verify/recovery", "csrf");
    let reuse = p.post(
        "/security/verify/recovery",
        &[("csrf", &csrf), ("next", "security"), ("code", &codes[1])],
    );
    assert_eq!(reuse.status, 200, "{reuse:?}");
    assert!(reuse.body.contains("That code didn"));
    assert_eq!(
        p.sql("SELECT COUNT(*) FROM recovery_codes WHERE used_at IS NOT NULL"),
        1
    );
}

// ---- 486: assurance and configuration -------------------------------------

#[test]
fn s486_1_without_webauthn_nothing_changes() {
    let p = Pk::start(json!({}));
    for path in [
        "/security",
        "/security/passkeys",
        "/security/passkeys/new",
        "/security/verify",
        "/assets/webauthn.js",
    ] {
        assert_eq!(p.portal.get(path).status, 404, "{path}");
    }
    let r = p.post("/stepup/webauthn", &[("csrf", "x")]);
    assert_eq!(r.status, 404);
    let login = p.portal.get("/healthz");
    assert!(
        !login
            .header("content-security-policy")
            .unwrap_or("")
            .contains("script-src")
    );
    assert_eq!(p.sql("SELECT COUNT(*) FROM webauthn_challenges"), 0);
}

#[test]
fn s486_2_ceremony_script_is_static_and_integrity_pinned() {
    let p = Pk::start(passkey_config(json!({})));
    let js = p.portal.get("/assets/webauthn.js");
    assert_eq!(js.status, 200);
    assert_eq!(
        js.header("content-type"),
        Some("text/javascript; charset=utf-8")
    );
    assert!(
        !js.body.contains("innerHTML") && !js.body.contains("eval(") && !js.body.contains("fetch(")
    );
    let page = p.portal.get("/security/passkeys/new");
    let integrity = {
        use base64::Engine as _;
        use sha2::Digest as _;
        format!(
            "sha384-{}",
            base64::engine::general_purpose::STANDARD
                .encode(sha2::Sha384::digest(js.body.as_bytes()))
        )
    };
    assert!(
        page.body.contains(&format!("integrity=\"{integrity}\"")),
        "{}",
        page.body
    );
    assert!(!page.body.contains("onclick") && !page.body.contains("<script>"));
    let csp = page.header("content-security-policy").unwrap();
    assert!(
        csp.starts_with("default-src 'none'; style-src 'self'; script-src 'self';")
            && !csp.contains("unsafe"),
        "{csp}"
    );
    assert_eq!(
        page.header("permissions-policy"),
        Some("publickey-credentials-create=(self), publickey-credentials-get=(self)")
    );
    // Pages without a ceremony keep the no-script policy.
    let overview = p.portal.get("/security");
    assert!(
        !overview
            .header("content-security-policy")
            .unwrap()
            .contains("script-src")
    );
}

#[test]
fn s486_3_insecure_or_unauthenticated_deployments_are_refused_at_start() {
    let idp = MockIdp::start("default");
    let dir = tempfile::tempdir().unwrap();
    for over in [
        passkey_config(json!({"webauthn": {"rp_id": "evil.test"}})),
        passkey_config(json!({"webauthn": {"origin": "https://auth.example.test"}})),
    ] {
        let cfg = Fixture::with("m1-basic", over).render(dir.path(), &idp);
        let path = crate::support::write_config(dir.path(), &cfg.to_string());
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_hopae"))
            .args(["--check", "--config"])
            .arg(&path)
            .output()
            .unwrap();
        assert!(
            !out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

#[test]
fn s481_a3_an_expired_ceremony_is_refused() {
    let mut p = Pk::start(passkey_config(json!({})));
    assert_eq!(p.register("Laptop").status, 303);
    let page = p.portal.get("/security/verify?next=security");
    let opts: RequestChallengeResponse = serde_json::from_str(&options(&page.body)).unwrap();
    let cred = p
        .key
        .do_authentication(Url::parse(PORTAL).unwrap(), opts)
        .unwrap();
    p.h.advance(Duration::from_secs(301));
    let r = p.post(
        "/security/verify/passkey",
        &[
            (
                "csrf",
                &field(&page.body, "/security/verify/passkey", "csrf"),
            ),
            ("next", "security"),
            (
                "ceremony",
                &field(&page.body, "/security/verify/passkey", "ceremony"),
            ),
            ("credential", &browser_json(&cred)),
        ],
    );
    assert_eq!(r.status, 200, "{r:?}");
    assert!(r.body.contains("expired or was already used"), "{}", r.body);
    assert_eq!(p.sql("SELECT COUNT(*) FROM sessions WHERE aal=2"), 0);
}

// ---- 487: passwordless sign-in --------------------------------------------

fn passwordless() -> Value {
    passkey_config(json!({"webauthn": {"passwordless": true}}))
}

/// A second browser on the same machine: no cookies, same authenticator.
struct Fresh {
    portal: Client,
    app_jar: Jar,
}

impl Pk {
    fn fresh(&self) -> Fresh {
        Fresh {
            portal: self.h.portal_with(Jar::new()).with_ip(IP),
            app_jar: Jar::new(),
        }
    }

    fn verify_in(&self, b: &Fresh, url: &str) -> Response {
        let jar = b.app_jar.for_host("app.example.test");
        let mut req = VerifyRequest::document(url).ip(IP);
        for n in [self.base.clone(), format!("{}_bind", self.base)] {
            if let Some(v) = jar.value(&n) {
                req = req.cookie(&n, &v);
            }
        }
        let r = self.h.verify(req);
        for c in r.set_cookies() {
            b.app_jar.store("app.example.test", "/", true, c);
        }
        r
    }

    fn user_handle(&self, which: &str) -> String {
        use base64::Engine as _;
        let c = rusqlite::Connection::open(self.h.state_dir.path().join("state").join("hopae.db"))
            .unwrap();
        let v: Vec<u8> = c
            .query_row(&format!("SELECT webauthn_user_handle FROM users WHERE webauthn_user_handle IS NOT NULL {which} LIMIT 1"), [], |r| r.get(0))
            .unwrap();
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v)
    }

    /// The chooser page in `b`, a discoverable assertion carrying `handle`
    /// (the software key cannot discover, so the test names its credential
    /// and adds the user handle a discoverable authenticator returns), and
    /// the form fields.
    fn passwordless_form(&mut self, b: &Fresh, handle: &str) -> (Response, Vec<(String, String)>) {
        let r = self.verify_in(b, HOME);
        assert_eq!(r.status, 302, "{r:?}");
        let page = b.portal.get(&path_of(r.location().unwrap()));
        assert_eq!(page.status, 200, "{page:?} {}", page.body);
        let mut opts: Value = serde_json::from_str(&options(&page.body)).unwrap();
        assert_eq!(
            opts["publicKey"]["allowCredentials"]
                .as_array()
                .map(Vec::len)
                .unwrap_or(0),
            0,
            "discoverable"
        );
        let id = {
            use base64::Engine as _;
            let c =
                rusqlite::Connection::open(self.h.state_dir.path().join("state").join("hopae.db"))
                    .unwrap();
            let v: Vec<u8> = c
                .query_row(
                    "SELECT credential_id FROM webauthn_credentials WHERE state='active' LIMIT 1",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v)
        };
        opts["publicKey"]["allowCredentials"] = json!([{"type": "public-key", "id": id}]);
        let opts: RequestChallengeResponse = serde_json::from_value(opts).unwrap();
        let cred = self
            .key
            .do_authentication(Url::parse(PORTAL).unwrap(), opts)
            .unwrap();
        let mut v: Value = serde_json::from_str(&browser_json(&cred)).unwrap();
        v["response"]["userHandle"] = json!(handle);
        let form = vec![
            (
                "csrf".to_string(),
                field(&page.body, "/login/passkey", "csrf"),
            ),
            (
                "txn".to_string(),
                field(&page.body, "/login/passkey", "txn"),
            ),
            (
                "ceremony".to_string(),
                field(&page.body, "/login/passkey", "ceremony"),
            ),
            ("credential".to_string(), v.to_string()),
        ];
        (page, form)
    }

    fn post_in(&self, b: &Fresh, path: &str, form: &[(String, String)]) -> Response {
        let refs: Vec<(&str, &str)> = form.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        b.portal
            .send(Req::post(path).header("origin", PORTAL).form(&refs))
    }
}

#[test]
fn s487_1_passwordless_sign_in_creates_an_aal2_passkey_session() {
    let mut p = Pk::start(passwordless());
    assert_eq!(p.register("Laptop").status, 303);
    assert!(
        p.portal.get("/security/passkeys/new").status == 303,
        "verification needed for a second key"
    );
    let handle = p.user_handle("");
    let b = p.fresh();
    let (page, form) = p.passwordless_form(&b, &handle);
    assert!(page.body.contains("autocomplete=\"username webauthn\""));
    let csp = page.header("content-security-policy").unwrap();
    assert!(csp.contains("script-src 'self'"), "{csp}");
    // The sign-in redirects to the application: form-action must allow it
    // (found in the browser qualification; the harness does not enforce CSP).
    assert!(csp.contains("https://app.example.test"), "{csp}");
    let done = p.post_in(&b, "/login/passkey", &form);
    assert_eq!(done.status, 302, "{done:?}");
    assert!(
        done.set_cookies()
            .iter()
            .any(|c| c.starts_with(&format!("{}=", p.base))),
        "portal handle planted"
    );
    let redeem = p.verify_in(&b, done.location().unwrap());
    assert_eq!(redeem.status, 302, "{redeem:?}");
    let clean = p.verify_in(&b, redeem.location().unwrap_or(HOME));
    assert_eq!(clean.status, 200, "{clean:?}");
    assert_eq!(clean.header("x-hopae-aal"), Some("2"));
    assert_eq!(clean.header("x-hopae-provider"), Some("hopae.passkey"));
    assert!(
        clean
            .header("x-hopae-factors")
            .unwrap()
            .contains("webauthn")
    );
    // The passkey session can open the security settings and an AAL 2 path.
    assert_eq!(b.portal.get("/security").status, 200);
    assert_eq!(p.verify_in(&b, ADMIN).status, 200);
    let ok = p.h.hooks.events(Some("login.succeeded"), Some(10));
    assert!(
        ok.iter().any(|e| e["attrs"]["kind"] == "webauthn"),
        "{ok:?}"
    );
}

#[test]
fn s487_2_without_passwordless_the_chooser_is_unchanged() {
    let p = Pk::start(passkey_config(json!({})));
    let b = p.fresh();
    let r = p.verify_in(&b, HOME);
    let login = b.portal.get(&path_of(r.location().unwrap()));
    // One provider and no passwordless option: straight to the provider.
    assert_eq!(login.status, 302, "{login:?}");
    assert_eq!(p.sql("SELECT COUNT(*) FROM webauthn_login_challenges"), 0);
}

#[test]
fn s487_a1_unknown_or_foreign_user_handles_fail_uniformly() {
    let mut p = Pk::start(passwordless());
    assert_eq!(p.register("Laptop").status, 303);
    let b = p.fresh();
    let (_, unknown) = p.passwordless_form(&b, "AAAAAAAAAAAAAAAAAAAAAA");
    let r1 = p.post_in(&b, "/login/passkey", &unknown);
    // Another user's handle with this user's credential.
    p.exec("UPDATE users SET webauthn_user_handle=X'00112233445566778899AABBCCDDEEFF' WHERE webauthn_user_handle IS NULL AND user_id IN (SELECT user_id FROM users LIMIT 1 OFFSET 5)");
    let (_, wrong) = p.passwordless_form(&b, "ABEiM0RVZneImaq7zN3u_w");
    let r2 = p.post_in(&b, "/login/passkey", &wrong);
    for r in [&r1, &r2] {
        assert_eq!(r.status, 303, "{r:?}");
        assert!(
            r.location().unwrap().contains("passkey_error=rejected"),
            "{r:?}"
        );
    }
    assert_eq!(
        p.sql("SELECT COUNT(*) FROM sessions WHERE provider_id='hopae.passkey'"),
        0
    );
    let shown = b.portal.get(r1.location().unwrap());
    assert!(
        shown.body.contains("sign you in with that passkey"),
        "{}",
        shown.body
    );
}

#[test]
fn s487_a2_a_replayed_sign_in_is_refused() {
    let mut p = Pk::start(passwordless());
    assert_eq!(p.register("Laptop").status, 303);
    let handle = p.user_handle("");
    let b = p.fresh();
    let (_, form) = p.passwordless_form(&b, &handle);
    assert_eq!(p.post_in(&b, "/login/passkey", &form).status, 302);
    let again = p.post_in(&b, "/login/passkey", &form);
    assert_eq!(again.status, 303, "{again:?}");
    assert!(
        again.location().unwrap().contains("passkey_error=expired"),
        "{again:?}"
    );
    assert_eq!(
        p.sql("SELECT COUNT(*) FROM sessions WHERE provider_id='hopae.passkey'"),
        1
    );
}

#[test]
fn s487_a3_another_browser_cannot_complete_the_ceremony() {
    let mut p = Pk::start(passwordless());
    assert_eq!(p.register("Laptop").status, 303);
    let handle = p.user_handle("");
    let b = p.fresh();
    let (_, form) = p.passwordless_form(&b, &handle);
    let other = p.fresh();
    let _ = other.portal.get("/security"); // no session: plants nothing useful
    let r = p.post_in(&other, "/login/passkey", &form);
    assert_eq!(r.status, 403, "{r:?}");
    assert_eq!(
        p.sql("SELECT COUNT(*) FROM sessions WHERE provider_id='hopae.passkey'"),
        0
    );
}

#[test]
fn s487_a4_ceremonies_per_address_are_bounded() {
    let p = Pk::start(passwordless());
    let b = p.fresh();
    let r = p.verify_in(&b, HOME);
    let login = path_of(r.location().unwrap());
    let mut offered = 0;
    loop {
        let page = b.portal.get(&login);
        if page.status == 200 && page.body.contains("/login/passkey") {
            offered += 1;
            assert!(offered <= 30, "unbounded");
            continue;
        }
        // Withheld: the single provider is used directly, as without passkeys.
        assert_eq!(page.status, 302, "{page:?}");
        break;
    }
    // 30 per address and minute; the fixture's own sign-in used one.
    assert_eq!(offered, 29, "LOGIN_CEREMONIES_PER_MINUTE");
}

#[test]
fn s487_a5_removing_the_passkey_ends_its_passwordless_sessions() {
    let mut p = Pk::start(passwordless());
    assert_eq!(p.register("Laptop").status, 303);
    let handle = p.user_handle("");
    let b = p.fresh();
    let (_, form) = p.passwordless_form(&b, &handle);
    assert_eq!(p.post_in(&b, "/login/passkey", &form).status, 302);
    p.h.cli(&["admin", "factors", "reset", &{
        let c = rusqlite::Connection::open(p.h.state_dir.path().join("state").join("hopae.db"))
            .unwrap();
        c.query_row::<String, _, _>(
            "SELECT user_id FROM webauthn_credentials LIMIT 1",
            [],
            |r| r.get(0),
        )
        .unwrap()
    }]);
    assert_eq!(p.sql("SELECT COUNT(*) FROM sessions WHERE provider_id='hopae.passkey' AND terminated_at IS NULL"), 0);
}

/// Real-browser qualification support (G8, run by hand): start the mock
/// provider and Hopae with passkeys, passwordless sign-in and an `/admin`
/// AAL 2 rule, write the addresses and the gateway key to `$G8_STACK_FILE`
/// and keep the stack up until `$G8_STACK_FILE.stop` exists. The browser
/// driver plays TLS terminator and gateway in front of it.
#[test]
#[ignore = "manual: held open for the headless-browser qualification"]
fn g8_hold_passkey_stack() {
    let Some(file) = std::env::var_os("G8_STACK_FILE") else {
        return;
    };
    let file = std::path::PathBuf::from(file);
    let p = Pk::start(passwordless());
    let wall = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    p.h.set_clock_ms(wall);
    let info = json!({
        "portal": p.h.portal.to_string(),
        "gateway": p.h.gateway.to_string(),
        "gateway_key": p.h.key_value(&crate::support::KeySlot::Current),
        "cookie": p.base,
        "db": p.h.state_dir.path().join("state").join("hopae.db"),
    });
    std::fs::write(&file, info.to_string()).unwrap();
    let stop = file.with_extension("stop");
    let deadline = std::time::Instant::now() + Duration::from_secs(1800);
    while !stop.exists() && std::time::Instant::now() < deadline {
        // The test-hook clock is frozen at spawn; a browser run needs wall time.
        let wall = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        p.h.set_clock_ms(wall);
        std::thread::sleep(Duration::from_millis(200));
    }
}

// ---- 488: AAL 3 emission (ADR-0018) ------------------------------------------

/// A stack whose `app` presents up to `max` and accepts the software token's
/// attestation for high-assurance registration; returns it, the token and
/// the directory holding the CA.
fn aal3_stack(
    max: u8,
) -> (
    Pk,
    WebauthnAuthenticator<webauthn_authenticator_rs::softtoken::SoftToken>,
    tempfile::TempDir,
) {
    let (token, ca) = webauthn_authenticator_rs::softtoken::SoftToken::new(true).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let pem = dir.path().join("ca.pem");
    std::fs::write(&pem, ca.to_pem().unwrap()).unwrap();
    let p = Pk::start(json!({
        "webauthn": {"high_assurance": {
            "attestation_ca_files": [pem.to_str().unwrap()],
            "aaguids": [webauthn_authenticator_rs::softtoken::AAGUID.to_string()]
        }},
        "apps": [{"app_id": "app", "max_emitted_aal": max,
                  "step_up": [{"path_prefix": "/admin", "require": {"aal": 2, "max_age": 900}}]}]
    }));
    (p, WebauthnAuthenticator::new(token), dir)
}

fn aal3_register_and_step_up(
    p: &Pk,
    key: &mut WebauthnAuthenticator<webauthn_authenticator_rs::softtoken::SoftToken>,
) -> Response {
    let page = p.portal.get("/security/passkeys/new?kind=high_assurance");
    assert_eq!(page.status, 200, "{page:?}");
    let opts: CreationChallengeResponse = serde_json::from_str(&options(&page.body)).unwrap();
    let cred = key
        .do_registration(Url::parse(PORTAL).unwrap(), opts)
        .unwrap();
    let r = p.post(
        "/security/passkeys/new",
        &[
            ("csrf", &field(&page.body, "/security/passkeys/new", "csrf")),
            (
                "ceremony",
                &field(&page.body, "/security/passkeys/new", "ceremony"),
            ),
            ("kind", "high_assurance"),
            ("credential", &browser_json(&cred)),
        ],
    );
    assert_eq!(r.status, 303, "{r:?} {}", r.body);
    assert_eq!(p.sql("SELECT COUNT(*) FROM webauthn_credentials WHERE assurance='aal3' AND attested=1 AND backup_eligible=0"), 1);
    let r = p.verify(ADMIN);
    let page = p.portal.get(&path_of(r.location().unwrap()));
    let opts: RequestChallengeResponse = serde_json::from_str(&options(&page.body)).unwrap();
    let cred = key
        .do_authentication(Url::parse(PORTAL).unwrap(), opts)
        .unwrap();
    let done = p.post(
        "/stepup/webauthn",
        &[
            ("csrf", &field(&page.body, "/stepup/webauthn", "csrf")),
            ("txn", &field(&page.body, "/stepup/webauthn", "txn")),
            (
                "ceremony",
                &field(&page.body, "/stepup/webauthn", "ceremony"),
            ),
            ("credential", &browser_json(&cred)),
        ],
    );
    assert_eq!(done.status, 302, "{done:?}");
    let redeem = p.verify(done.location().unwrap());
    p.verify(redeem.location().unwrap_or(ADMIN))
}

#[test]
fn s488_1_an_opted_in_application_sees_aal3_for_a_high_assurance_key() {
    let (mut p, mut key, _ca) = aal3_stack(3);
    let clean = aal3_register_and_step_up(&p, &mut key);
    assert_eq!(clean.status, 200, "{clean:?}");
    assert_eq!(clean.header("x-hopae-aal"), Some("3"));
    let _ = &mut p;
}

#[test]
fn s488_2_without_opt_in_the_same_key_stays_aal2() {
    let (p, mut key, _ca) = aal3_stack(2);
    let clean = aal3_register_and_step_up(&p, &mut key);
    assert_eq!(clean.status, 200, "{clean:?}");
    assert_eq!(
        clean.header("x-hopae-aal"),
        Some("2"),
        "old consumers keep receiving at most 2"
    );
}

#[test]
fn s488_a1_a_synced_passkey_never_yields_aal3() {
    let (mut p, _token, _ca) = aal3_stack(3);
    assert_eq!(p.register("Phone").status, 303);
    let (_, done, _) = p.stepup(PORTAL);
    assert_eq!(done.status, 302);
    let redeem = p.verify(done.location().unwrap());
    let clean = p.verify(redeem.location().unwrap_or(ADMIN));
    assert_eq!(clean.header("x-hopae-aal"), Some("2"));
}

#[test]
fn s488_a2_aal3_needs_high_assurance_configuration() {
    let idp = MockIdp::start("default");
    let dir = tempfile::tempdir().unwrap();
    for over in [
        json!({"webauthn": {}, "apps": [{"app_id": "app", "max_emitted_aal": 3}]}),
        json!({"apps": [{"app_id": "app", "max_emitted_aal": 3}]}),
        json!({"webauthn": {}, "apps": [{"app_id": "app", "max_emitted_aal": 4}]}),
    ] {
        let cfg = Fixture::with("m1-basic", over).render(dir.path(), &idp);
        let path = crate::support::write_config(dir.path(), &cfg.to_string());
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_hopae"))
            .args(["--check", "--config"])
            .arg(&path)
            .output()
            .unwrap();
        assert!(
            !out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stdout)
        );
    }
}

#[test]
fn s487_a6_a_slower_tab_is_stale_not_a_clone() {
    // Review F2: two sign-in tabs; the assertion signed first arrives last.
    let mut p = Pk::start(passwordless());
    assert_eq!(p.register("Laptop").status, 303);
    let handle = p.user_handle("");
    let first = p.fresh();
    let second = p.fresh();
    let (_, early) = p.passwordless_form(&first, &handle);
    let (_, late) = p.passwordless_form(&second, &handle);
    assert_eq!(p.post_in(&second, "/login/passkey", &late).status, 302);
    let r = p.post_in(&first, "/login/passkey", &early);
    assert_eq!(r.status, 303, "{r:?}");
    assert!(r.location().unwrap().contains("passkey_error=rejected"));
    assert_eq!(
        p.sql("SELECT COUNT(*) FROM webauthn_credentials WHERE state='active'"),
        1,
        "not revoked"
    );
    assert_eq!(p.sql("SELECT COUNT(*) FROM sessions WHERE provider_id='hopae.passkey' AND terminated_at IS NULL"), 1);
}

#[test]
fn s487_a7_removing_the_establishing_passkey_ends_the_acting_session() {
    // Review F3: a passwordless session removes the passkey it was established with.
    let mut p = Pk::start(passwordless());
    assert_eq!(p.register("Laptop").status, 303);
    let handle = p.user_handle("");
    // A second passkey on another authenticator, so the first is not the last factor.
    assert_eq!(p.verify_portal(PORTAL).status, 303);
    let first_key = std::mem::replace(
        &mut p.key,
        WebauthnAuthenticator::new(SoftPasskey::new(true)),
    );
    assert_eq!(p.register("Phone").status, 303);
    p.key = first_key;
    let b = p.fresh();
    let (_, form) = p.passwordless_form(&b, &handle);
    assert_eq!(p.post_in(&b, "/login/passkey", &form).status, 302);
    let list = b.portal.get("/security/passkeys");
    let first_id = {
        use base64::Engine as _;
        let c = rusqlite::Connection::open(p.h.state_dir.path().join("state").join("hopae.db"))
            .unwrap();
        let v: Vec<u8> = c
            .query_row(
                "SELECT credential_id FROM webauthn_credentials WHERE label='Laptop'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v)
    };
    let gone = p.post_in(
        &b,
        "/security/passkeys/remove",
        &[
            (
                "csrf".into(),
                field(&list.body, "/security/passkeys/remove", "csrf"),
            ),
            ("credential".into(), first_id),
            ("confirm".into(), "1".into()),
        ],
    );
    assert_eq!(gone.status, 303, "{gone:?}");
    assert_eq!(p.sql("SELECT COUNT(*) FROM sessions WHERE provider_id='hopae.passkey' AND terminated_at IS NULL"), 0);
}
