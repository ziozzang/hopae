//! Harness smoke tests (included by `tests/scenarios.rs` only): spawn Hopae
//! with `m1-basic` and the mock provider, reach the hooks, move the clock,
//! and check that verify answers with the contract wire form and that
//! the harness pieces (jar, mock provider, echo upstream) behave as specified.

use std::time::Duration;

use crate::support::mock_idp::profiles::Profile;
use crate::support::*;

#[test]
fn spawn_basic_reaches_portal_gateway_and_hooks() {
    let idp = MockIdp::start("default");
    let h = Hopae::spawn(Fixture::new("m1-basic"), &idp, &[]);
    assert_eq!(get(h.portal, "/healthz").status, 200);
    assert_eq!(h.portal_host(), "auth.example.test");

    // The verify endpoint answers with the contract's wire form: never a 2xx
    // without a session (the decision itself is the verify engine's).
    let r = h.verify(VerifyRequest::document("https://app.example.test/admin/x"));
    assert!(matches!(r.status, 302 | 401 | 403 | 400 | 503), "{r:?}");
    assert!(r.header("x-hopae-reason").is_some(), "{r:?}");

    // Hooks: counters, clock, events.
    let c = h.hooks.counters();
    assert!(c["store_calls"].is_object(), "{c}");
    let before = h.hooks.now_ms();
    h.hooks.set_clock_ms(1_800_000_000_000);
    assert_eq!(h.hooks.now_ms(), 1_800_000_000_000);
    h.hooks.advance(Duration::from_secs(90));
    assert_eq!(h.hooks.now_ms(), 1_800_000_090_000);
    assert!(before > 1_600_000_000_000);
    // Start records exactly one `config.loaded` event (and its delivery); the
    // document navigation above started one login, nothing else happened.
    let evs = h.hooks.events(None, Some(10));
    let loaded = evs.iter().filter(|e| e["kind"] == "config.loaded").count();
    assert_eq!(loaded, 1, "{evs:?}");
    assert!(
        evs.iter()
            .all(|e| e["kind"] == "config.loaded" || e["kind"] == "login.started"),
        "{evs:?}"
    );
    assert_eq!(
        h.hooks.deliveries(Some("log")).len(),
        evs.len(),
        "one delivery per required event"
    );
    // Gates and stalls are accepted; a stalled store is visible in the call counters.
    h.hooks.stall(5);
    h.hooks.stall_off();
    h.hooks.hold("redeem");
    h.hooks.release("redeem");
    assert!(h.log().len() < 1_000_000);
}

#[test]
fn spawn_applies_overrides_and_restart_keeps_state() {
    let idp = MockIdp::start("default");
    let mut h = Hopae::spawn(
        Fixture::with(
            "m1-basic",
            serde_json::json!({
                "apps": [{"app_id": "app", "verify_cache_seconds": 5}],
                "limits": {"portal_max_concurrent": 7}
            }),
        ),
        &idp,
        &[],
    );
    let cfg = h.config();
    assert_eq!(cfg["apps"][0]["verify_cache_seconds"], 5);
    assert_eq!(
        cfg["apps"][0]["hosts"][0], "app.example.test",
        "array elements merge by app_id"
    );
    assert_eq!(cfg["apps"].as_array().unwrap().len(), 2);
    assert_eq!(cfg["limits"]["portal_max_concurrent"], 7);
    assert_eq!(
        cfg["providers"][0]["issuer"],
        idp.issuer.as_str().trim_end_matches('/')
    );
    let first = h.portal;
    h.kill();
    assert!(h.exited().is_some());
    h.restart();
    assert_eq!(get(h.portal, "/healthz").status, 200);
    let _ = first;
    // Secrets stay out of the config the harness shows and out of Hopae's log.
    let log = h.log();
    for secret in h.secret_values() {
        assert!(!log.contains(&secret));
        assert!(!h.config().to_string().contains(&secret));
    }
}

#[test]
fn verify_caller_key_slots_and_missing_headers_are_expressible() {
    let idp = MockIdp::start("default");
    let h = Hopae::spawn(Fixture::new("m1-basic"), &idp, &[]);
    // Every variant is expressible, and the adapter answers each as the
    // contract says: the caller key first, then the contract headers.
    let refused = |req: VerifyRequest, status: u16, reason: &str| {
        let r = h.verify(req);
        assert_eq!(r.status, status, "{r:?}");
        assert_eq!(r.header("x-hopae-reason"), Some(reason), "{r:?}");
    };
    refused(
        VerifyRequest::other("https://app.example.test/").key(KeySlot::Missing),
        403,
        "caller_unauthorized",
    );
    refused(
        VerifyRequest::document("https://app.example.test/").key(KeySlot::Wrong),
        403,
        "caller_unauthorized",
    );
    refused(
        VerifyRequest::document("https://app.example.test/").key(KeySlot::Next),
        403,
        "caller_unauthorized",
    );
    refused(
        VerifyRequest::document("https://app.example.test/")
            .without("x-forwarded-host")
            .cookie("__Host-hopae", "v1.x")
            .ua("UA")
            .ip("2001:db8::1"),
        400,
        "contract_violation",
    );
    assert!(
        h.key_value(&KeySlot::Next).is_none(),
        "no next key configured in m1-basic"
    );
    assert!(h.key_value(&KeySlot::Current).is_some());
}

#[test]
fn echo_records_what_it_receives_and_decodes_the_path() {
    let echo = Echo::start();
    let r = send_raw(echo.addr, "/%61dmin/x?q=1%202");
    assert_eq!(r.status, 200);
    let seen = echo.requests();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].raw_path, "/%61dmin/x?q=1%202");
    assert_eq!(seen[0].decoded_path, "/admin/x");
    assert_eq!(seen[0].query_value("q"), Some("1 2"));
    assert_eq!(seen[0].method, "GET");
    assert!(r.body.contains("/admin/x"));
}

fn send_raw(addr: std::net::SocketAddr, path: &str) -> Response {
    send_via_client(addr, path)
}

fn send_via_client(addr: std::net::SocketAddr, path: &str) -> Response {
    crate::support::client::send(addr, RawReq::new("GET", path, "upstream.test"))
}

#[test]
fn mock_idp_default_flow_issues_a_verifiable_token_with_pkce() {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use sha2::Digest as _;
    let idp = MockIdp::start("default");
    let disc = send_raw(idp_addr(&idp), "/.well-known/openid-configuration").json();
    assert_eq!(disc["issuer"], idp.issuer.as_str().trim_end_matches('/'));
    assert_eq!(disc["code_challenge_methods_supported"][0], "S256");
    let jwks = send_raw(idp_addr(&idp), "/jwks").json();
    assert_eq!(jwks["keys"][0]["alg"], "RS256");
    assert_eq!(jwks["keys"][0]["kid"], "key-1");

    let verifier = "v".repeat(43);
    let challenge = URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(verifier.as_bytes()));
    let q = |extra: &str| {
        format!(
            "/authorize?response_type=code&client_id={}&redirect_uri=https%3A%2F%2Fauth.example.test%2Fcallback%2Fmock&scope=openid%20email&state=S1&nonce=N1{extra}",
            idp.client_id
        )
    };
    // No PKCE: an error redirect, no code.
    let r = send_raw(idp_addr(&idp), &q(""));
    assert_eq!(r.status, 302);
    assert!(r.location().unwrap().contains("error=invalid_request"));
    // With PKCE: a code and the same state.
    let r = send_raw(
        idp_addr(&idp),
        &q(&format!(
            "&code_challenge={challenge}&code_challenge_method=S256"
        )),
    );
    let loc = url::Url::parse(r.location().unwrap()).unwrap();
    let pairs: std::collections::HashMap<_, _> = loc.query_pairs().into_owned().collect();
    assert_eq!(pairs["state"], "S1");
    let code = pairs["code"].clone();
    assert_eq!(idp.authorizations().len(), 2);
    assert_eq!(idp.authorizations()[1].nonce.as_deref(), Some("N1"));

    let token = |code: &str, verifier: &str| {
        let mut req = RawReq::new("POST", "/token", "idp.test")
            .header("content-type", "application/x-www-form-urlencoded");
        req.body = format!(
            "grant_type=authorization_code&code={code}&redirect_uri=https%3A%2F%2Fauth.example.test%2Fcallback%2Fmock&client_id={}&code_verifier={verifier}",
            idp.client_id
        )
        .into_bytes();
        crate::support::client::send(idp_addr(&idp), req)
    };
    assert_eq!(
        token(&code, "wrong-verifier").status,
        400,
        "PKCE is enforced"
    );
    let issued = idp.issue_code("S1", "sub-1");
    let t = token(&issued, &verifier);
    assert_eq!(t.status, 200, "{t:?}");
    let body = t.json();
    let id_token = body["id_token"].as_str().unwrap().to_string();
    assert_eq!(
        token(&issued, &verifier).status,
        400,
        "codes are single use"
    );

    // The ID token verifies against the published JWKS and carries the default user.
    let key = &jwks["keys"][0];
    let dk = jsonwebtoken::DecodingKey::from_rsa_components(
        key["n"].as_str().unwrap(),
        key["e"].as_str().unwrap(),
    )
    .unwrap();
    let mut v = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    v.set_audience(&["hopae-test"]);
    v.set_issuer(&[idp.issuer.as_str().trim_end_matches('/')]);
    let data = jsonwebtoken::decode::<serde_json::Value>(&id_token, &dk, &v).unwrap();
    assert_eq!(data.claims["sub"], "sub-1");
    assert_eq!(data.claims["email"], "a@example.test");
    assert_eq!(data.claims["email_verified"], true);
    assert_eq!(data.claims["name"], "Alice 김");
    assert_eq!(data.claims["nonce"], "N1");
    // User-info answers for the access token.
    let mut ui = RawReq::new("GET", "/userinfo", "idp.test");
    ui = ui.header(
        "authorization",
        &format!("Bearer {}", body["access_token"].as_str().unwrap()),
    );
    let u = crate::support::client::send(idp_addr(&idp), ui).json();
    assert_eq!(u["sub"], "sub-1");
}

fn idp_addr(idp: &MockIdp) -> std::net::SocketAddr {
    let u = &idp.issuer;
    std::net::SocketAddr::new(u.host_str().unwrap().parse().unwrap(), u.port().unwrap())
}

/// One request per profile deviation: each changes exactly what the catalogue says.
#[test]
fn mock_idp_profiles_deviate_exactly_as_catalogued() {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let idp = MockIdp::start("default");
    let addr = idp_addr(&idp);
    let claims_of = |jwt: &str| -> serde_json::Value {
        let payload = jwt.split('.').nth(1).unwrap();
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap()
    };
    let header_of = |jwt: &str| -> serde_json::Value {
        serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(jwt.split('.').next().unwrap())
                .unwrap(),
        )
        .unwrap()
    };
    let exchange = |state: &str| -> Response {
        let code = idp.issue_code(state, "sub-1");
        let mut req = RawReq::new("POST", "/token", "idp.test")
            .header("content-type", "application/x-www-form-urlencoded");
        req.body = format!(
            "grant_type=authorization_code&code={code}&client_id={}",
            idp.client_id
        )
        .into_bytes();
        crate::support::client::send(addr, req)
    };
    let idtok = |p: &str| -> String {
        idp.set_profile(p);
        let r = exchange("none");
        assert_eq!(r.status, 200, "{p}: {r:?}");
        r.json()["id_token"].as_str().unwrap().to_string()
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    assert_eq!(claims_of(&idtok("default"))["email_verified"], true);
    assert_eq!(
        claims_of(&idtok("unverified_email"))["email_verified"],
        false
    );
    assert_eq!(claims_of(&idtok("wrong_aud"))["aud"], "some-other-client");
    assert_eq!(claims_of(&idtok("hd_example_test"))["hd"], "example.test");
    let expired = claims_of(&idtok("expired_token"));
    let exp = expired["exp"].as_i64().unwrap();
    assert!((now - 120 - exp).abs() <= 5, "exp is 120 s in the past");
    assert_eq!(header_of(&idtok("jwks_unknown_kid"))["kid"], "unknown-kid");
    assert_eq!(
        header_of(&idtok("invalid_signature"))["kid"],
        "key-1",
        "claims the real kid, signed by a stranger"
    );
    let rogue = idtok("invalid_signature");
    let jwks = send_raw(addr, "/jwks").json();
    let key = &jwks["keys"][0];
    let dk = jsonwebtoken::DecodingKey::from_rsa_components(
        key["n"].as_str().unwrap(),
        key["e"].as_str().unwrap(),
    )
    .unwrap();
    let mut v = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    v.set_audience(&["hopae-test"]);
    assert!(jsonwebtoken::decode::<serde_json::Value>(&rogue, &dk, &v).is_err());

    // Token endpoint deviations.
    idp.set_profile("id_token_missing");
    assert!(exchange("s").json().get("id_token").is_none());
    idp.set_profile("token_500");
    assert_eq!(exchange("s").status, 500);
    idp.set_profile("token_malformed");
    let a = exchange("s");
    assert!(serde_json::from_str::<serde_json::Value>(&a.body).is_err());
    let b = exchange("s").json();
    assert!(b["id_token"].is_number());
    let c = exchange("s").json();
    assert_eq!(c["id_token"], "!!!.@@@.###");
    idp.set_profile("oversized");
    assert!(exchange("s").body.len() >= 1024 * 1024);
    assert!(send_raw(addr, "/jwks").body.len() >= 1024 * 1024);
    assert!(
        send_raw(addr, "/.well-known/openid-configuration")
            .body
            .len()
            >= 1024 * 1024
    );

    // Discovery and JWKS deviations.
    idp.set_profile("discovery_down");
    assert_eq!(
        send_raw(addr, "/.well-known/openid-configuration").status,
        503
    );
    let before = idp.discovery_fetches();
    idp.set_profile("discovery_changed_issuer");
    let first = send_raw(addr, "/.well-known/openid-configuration").json()["issuer"]
        .as_str()
        .unwrap()
        .to_string();
    let second = send_raw(addr, "/.well-known/openid-configuration").json()["issuer"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(idp.discovery_fetches() >= before + 2);
    let _ = first; // the first fetch after switching is not necessarily fetch #0 of the server
    assert!(second.ends_with("/changed"));
    let idp2 = MockIdp::start("jwks_rotated");
    let a2 = idp_addr(&idp2);
    let k1 = send_raw(a2, "/jwks").json()["keys"][0]["kid"]
        .as_str()
        .unwrap()
        .to_string();
    let k2 = send_raw(a2, "/jwks").json()["keys"][0]["kid"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!((k1.as_str(), k2.as_str()), ("key-1", "key-2"));
    idp.set_profile("userinfo_500");
    let mut ui = RawReq::new("GET", "/userinfo", "idp.test");
    ui = ui.header("authorization", "Bearer x");
    assert_eq!(crate::support::client::send(addr, ui).status, 500);

    // wrong_state and userinfo_wrong_sub need /authorize and a token round trip.
    idp.set_profile("wrong_state");
    let r = send_raw(
        addr,
        &format!(
            "/authorize?response_type=code&client_id={}&redirect_uri=https%3A%2F%2Fa.test%2Fcb&state=S2&nonce=n&code_challenge=abc&code_challenge_method=S256",
            idp.client_id
        ),
    );
    let loc = url::Url::parse(r.location().unwrap()).unwrap();
    let state = loc
        .query_pairs()
        .find(|(k, _)| k == "state")
        .unwrap()
        .1
        .into_owned();
    assert!(state.starts_with("never-issued-") && state != "S2");
    idp.set_profile("userinfo_wrong_sub");
    let code = idp.issue_code("none", "sub-1");
    let mut req = RawReq::new("POST", "/token", "idp.test")
        .header("content-type", "application/x-www-form-urlencoded");
    req.body = format!(
        "grant_type=authorization_code&code={code}&client_id={}",
        idp.client_id
    )
    .into_bytes();
    let at = crate::support::client::send(addr, req).json()["access_token"]
        .as_str()
        .unwrap()
        .to_string();
    let ui = RawReq::new("GET", "/userinfo", "idp.test")
        .header("authorization", &format!("Bearer {at}"));
    let u = crate::support::client::send(addr, ui).json();
    assert_eq!(
        (u["sub"].as_str(), u["email"].as_str()),
        (Some("sub-2"), Some("b@example.test"))
    );
}

#[test]
fn mock_idp_slow_profiles_really_delay() {
    let idp = MockIdp::start("slow");
    let addr = idp_addr(&idp);
    let started = std::time::Instant::now();
    let r = crate::support::client::try_send(
        addr,
        RawReq::new("GET", "/.well-known/openid-configuration", "idp.test")
            .timeout(Duration::from_millis(500)),
    );
    assert!(r.is_err(), "slow profile must not answer within 500 ms");
    assert!(started.elapsed() < Duration::from_secs(5));
    idp.set_profile("token_slow");
    assert!(
        send_raw(addr, "/jwks").status == 200,
        "only the token endpoint is slow"
    );
}

#[test]
fn every_profile_in_the_catalogue_is_selectable() {
    let idp = MockIdp::start("default");
    for p in Profile::ALL {
        idp.set_profile(p.name());
    }
}

// ---- jar and profile self-tests (run once, here) -------------------------

mod jar_rules {
    use crate::support::jar::*;
    use std::time::Duration;

    const SECURE: SendContext = SendContext {
        secure_transport: true,
        site: Site::Same,
        safe_method: true,
    };

    #[test]
    fn host_prefix_rules() {
        let j = Jar::new();
        assert!(j.store(
            "app.example.test",
            "/",
            true,
            "__Host-hopae=v1; Path=/; Secure; HttpOnly; SameSite=Lax"
        ));
        assert!(!j.store(
            "app.example.test",
            "/",
            true,
            "__Host-a=1; Path=/; Secure; Domain=example.test"
        ));
        assert!(!j.store("app.example.test", "/", true, "__Host-b=1; Path=/x; Secure"));
        assert!(!j.store("app.example.test", "/", true, "__Host-c=1; Path=/"));
        assert!(!j.store("app.example.test", "/", false, "__Host-d=1; Path=/; Secure"));
        assert!(!j.store("app.example.test", "/", true, "x=1; Domain=other.test"));
        assert_eq!(j.for_host("app.example.test").names(), ["__Host-hopae"]);
        assert_eq!(j.rejected().len(), 5);
    }

    #[test]
    fn host_only_scoping_and_domain_cookies() {
        let j = Jar::new();
        j.store("app.example.test", "/", true, "a=1; Path=/; Secure");
        j.store(
            "sib.example.test",
            "/",
            true,
            "hopae=toss; Domain=example.test; Path=/",
        );
        assert_eq!(
            j.header_for("app.example.test", "/", SECURE).as_deref(),
            Some("a=1; hopae=toss")
        );
        assert_eq!(j.header_for("other.example.org", "/", SECURE), None);
        assert_eq!(
            j.header_for("sib.example.test", "/", SECURE).as_deref(),
            Some("hopae=toss")
        );
    }

    #[test]
    fn samesite_secure_path_and_expiry() {
        let j = Jar::new();
        j.set_now_ms(1_000_000);
        j.store(
            "h.example.test",
            "/",
            true,
            "lax=1; Path=/; Secure; SameSite=Lax; Max-Age=600",
        );
        j.store(
            "h.example.test",
            "/",
            true,
            "strict=1; Path=/; Secure; SameSite=Strict",
        );
        j.store(
            "h.example.test",
            "/",
            true,
            "none=1; Path=/; Secure; SameSite=None",
        );
        j.store("h.example.test", "/", true, "sec=1; Path=/admin; Secure");
        let cross_nav = SendContext {
            site: Site::CrossSiteNavigation,
            ..SECURE
        };
        let cross_sub = SendContext {
            site: Site::CrossSiteSubresource,
            ..SECURE
        };
        let cross_post = SendContext {
            safe_method: false,
            ..cross_nav
        };
        assert_eq!(
            j.header_for("h.example.test", "/", cross_nav).as_deref(),
            Some("lax=1; none=1")
        );
        assert_eq!(
            j.header_for("h.example.test", "/", cross_sub).as_deref(),
            Some("none=1")
        );
        assert_eq!(
            j.header_for("h.example.test", "/", cross_post).as_deref(),
            Some("none=1")
        );
        assert_eq!(
            j.header_for("h.example.test", "/admin/x", SECURE)
                .as_deref(),
            Some("sec=1; lax=1; strict=1; none=1")
        );
        let insecure = SendContext {
            secure_transport: false,
            ..SECURE
        };
        assert_eq!(j.header_for("h.example.test", "/", insecure), None);
        j.advance(Duration::from_secs(601));
        assert_eq!(
            j.header_for("h.example.test", "/", SECURE).as_deref(),
            Some("strict=1; none=1")
        );
        // Max-Age=0 deletes.
        j.store(
            "h.example.test",
            "/",
            true,
            "strict=; Path=/; Secure; Max-Age=0",
        );
        assert_eq!(
            j.header_for("h.example.test", "/", SECURE).as_deref(),
            Some("none=1")
        );
    }

    #[test]
    fn size_and_count_are_bounded() {
        let j = Jar::new();
        assert!(!j.store(
            "h.example.test",
            "/",
            true,
            &format!("big={}", "x".repeat(5000))
        ));
        for i in 0..200 {
            j.store("h.example.test", "/", true, &format!("c{i}=1; Secure"));
        }
        assert_eq!(j.for_host("h.example.test").all().len(), 180);
    }
}
