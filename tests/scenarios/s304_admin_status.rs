//! Scenario 304: the console's status page and `GET /v1/status` are read-only,
//! show no secret and need no outbound call.
#![allow(dead_code, unused_imports)]

use std::time::Duration;

use serde_json::{Value, json};

use super::s300_admin_access::kit::*;
use crate::support::{Fixture, Hopae, MockIdp, RawReq, Response, client::send};

const UNSET_SECRET_ENV: &str = "HOPAE_TEST_UNSET_SECRET";

/// `m4-admin` with the providers of the scenario: `mock` (secret set), `mock2`
/// (its secret variable is unset, so it starts disabled) and `mock3` (turned
/// into an `api`-managed, disabled provider with the stored setting
/// `reauth: unsupported` once the users exist, as a later runtime change would).
fn spawn_status() -> (MockIdp, Hopae, Users) {
    let idp = MockIdp::start("auth_time_present");
    let issuer = idp.issuer.as_str().trim_end_matches('/').to_string();
    let provider = |id: &str, name: &str, env: &str| {
        json!({
            "provider_id": id, "kind": "oidc", "display_name": name,
            "client_id": "hopae-test", "client_secret_env": env,
            "issuer": issuer, "allow_private_endpoints": true,
            "scope": "openid email profile", "auto_link": false
        })
    };
    let over = json!({
        "providers": [
            provider("mock2", "Mock Two", UNSET_SECRET_ENV),
            provider("mock3", "Mock Three", "HOPAE_TEST_MOCK_SECRET"),
        ],
        // Long timers: the discovery case moves the clock by a day.
        "session": {"idle": "96h", "absolute": "30d"},
        "admin": {
            "session": {"idle": "96h", "absolute": "96h"},
            "max_auth_age": "96h"
        }
    });
    let mut h = Hopae::spawn(Fixture::with("m4-admin", over), &idp, &[]);
    let u = users(&h, &idp);
    // mock3 becomes an api-managed, disabled provider with its own stored setting.
    db(&h)
        .execute(
            "UPDATE providers SET managed_by = 'api', enabled = 0, config = json_set(config, '$.reauth', 'unsupported') WHERE provider_id = 'mock3'",
            [],
        )
        .unwrap();
    h.restart();
    (idp, h, u)
}

/// A status body without the parts that move by themselves (event and
/// delivery counts change as the background workers run).
fn stable(mut v: Value) -> Value {
    for k in ["events", "deliveries", "live_sessions", "last_prune_at"] {
        v["store"].as_object_mut().unwrap().remove(k);
    }
    v
}

fn status(h: &Hopae, handle: &str) -> Value {
    let r = admin(h).with_handle(handle).get("/v1/status");
    assert_eq!(r.status, 200, "{r:?}");
    r.json()
}

fn provider<'a>(s: &'a Value, id: &str) -> &'a Value {
    s["providers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["provider_id"] == id)
        .unwrap_or_else(|| panic!("no provider {id} in {s}"))
}

fn app<'a>(s: &'a Value, id: &str) -> &'a Value {
    s["apps"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["app_id"] == id)
        .unwrap_or_else(|| panic!("no app {id} in {s}"))
}

#[test]
fn s304_1_applications_listed_with_policy() {
    let (_idp, h, u) = spawn_status();
    let s = status(&h, &u.a.handle);
    let ids: Vec<&str> = s["apps"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["app_id"].as_str().unwrap())
        .collect();
    for want in ["app", "default", "admin"] {
        assert!(ids.contains(&want), "{ids:?}");
    }
    let admin_app = app(&s, "admin");
    assert_eq!(admin_app["hosts"], json!(["hopae-admin.example.test"]));
    assert_eq!(admin_app["ports"], json!([443]));
    assert_eq!(admin_app["enabled"], true);
    assert_eq!(admin_app["binding"]["ip"], "strict");
    assert_eq!(admin_app["binding"]["ua"], "off");
    assert_eq!(admin_app["binding"]["on_mismatch"], "terminate_session");
    assert_eq!(admin_app["on_authz_change"], "terminate");
    assert_eq!(admin_app["verify_cache_seconds"], 0);
    assert_eq!(admin_app["logout_confirm"], true);
    assert_eq!(admin_app["step_up"], 0);
    assert!(admin_app["max_auth_age"].is_string(), "{admin_app}");
    assert!(app(&s, "app")["max_auth_age"].is_null());
    assert!(app(&s, "default")["max_auth_age"].is_null());
    assert_eq!(
        app(&s, "default")["hosts"],
        json!([]),
        "default shows no hosts"
    );
    assert_eq!(app(&s, "app")["hosts"], json!(["app.example.test"]));
    for a in s["apps"].as_array().unwrap() {
        for k in [
            "app_id",
            "display_name",
            "hosts",
            "ports",
            "enabled",
            "session",
            "binding",
            "on_authz_change",
            "verify_cache_seconds",
            "logout_confirm",
            "max_auth_age",
            "step_up",
        ] {
            assert!(a.get(k).is_some(), "{k} missing in {a}");
        }
        assert!(a["session"]["idle"].is_string() && a["session"]["absolute"].is_string());
    }
    // The page renders the same as a table.
    let page = admin(&h).with_handle(&u.a.handle).get("/");
    assert_eq!(page.status, 200, "{page:?}");
    assert!(page.body.contains("<table") && page.body.contains("hopae-admin.example.test"));
    assert!(page.body.contains("app.example.test"));
}

#[test]
fn s304_1_admin_defaults_are_the_pinned_ones() {
    // The default console fixture (no long timers) shows the pinned defaults.
    let (_idp, h, u) = setup();
    let s = status(&h, &u.a.handle);
    let a = app(&s, "admin");
    assert_eq!(
        a["session"],
        json!({"idle": "30m", "absolute": "12h"}),
        "{a}"
    );
    assert_eq!(a["max_auth_age"], "12h");
}

#[test]
fn s304_2_providers_with_health_and_secret_presence() {
    let (idp, h, u) = spawn_status();
    // Discovery completes shortly after start.
    let mut s = status(&h, &u.a.handle);
    for _ in 0..100 {
        if provider(&s, "mock")["health"] == "ok" {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
        s = status(&h, &u.a.handle);
    }
    let mock = provider(&s, "mock");
    assert_eq!(mock["kind"], "oidc");
    assert_eq!(mock["enabled"], true);
    assert_eq!(mock["managed_by"], "file");
    assert_eq!(mock["health"], "ok", "{mock}");
    assert_eq!(mock["reauth"], "max_age");
    assert_eq!(mock["client_secret_env"], "HOPAE_TEST_MOCK_SECRET");
    assert_eq!(mock["secret_present"], true);
    let mock2 = provider(&s, "mock2");
    assert_eq!(mock2["enabled"], false, "{mock2}");
    assert_eq!(mock2["health"], "disabled");
    assert_eq!(mock2["client_secret_env"], UNSET_SECRET_ENV);
    assert_eq!(mock2["secret_present"], false);
    let mock3 = provider(&s, "mock3");
    assert_eq!(mock3["managed_by"], "api", "{mock3}");
    assert_eq!(mock3["enabled"], false);
    assert_eq!(mock3["reauth"], "unsupported", "from its stored setting");

    // The status request itself makes no outbound call: once the provider's
    // own refresher is quiet, a burst of reads adds nothing to the mock's log.
    let mut count = idp.requests().len();
    for _ in 0..30 {
        std::thread::sleep(Duration::from_millis(100));
        let now = idp.requests().len();
        if now == count {
            break;
        }
        count = now;
    }
    std::thread::sleep(Duration::from_millis(1200));
    let quiet = idp.requests().len();
    for _ in 0..10 {
        assert_eq!(admin(&h).with_handle(&u.a.handle).get("/").status, 200);
        status(&h, &u.a.handle);
    }
    assert_eq!(idp.requests().len(), quiet, "status made no outbound call");

    // After the discovery document is gone and its hard deadline has passed,
    // the cached state says degraded with the reason.
    idp.set_profile("discovery_down");
    h.advance(Duration::from_secs(24 * 3600 + 1));
    let mut degraded = Value::Null;
    for _ in 0..150 {
        let s = status(&h, &u.a.handle);
        let m = provider(&s, "mock").clone();
        if m["health"] == "degraded" && m["reason"] == "provider_unavailable" {
            degraded = m;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(degraded["health"], "degraded", "{degraded}");
    assert_eq!(degraded["reason"], "provider_unavailable", "{degraded}");

    // No field of any provider contains a secret's value.
    let body = admin(&h).with_handle(&u.a.handle).get("/v1/status").body;
    let page = admin(&h).with_handle(&u.a.handle).get("/").body;
    for secret in h.secret_values() {
        assert!(!body.contains(&secret) && !page.contains(&secret));
    }
}

#[test]
fn s304_3_store_build_and_configuration() {
    let (_idp, h, u) = spawn_status();
    // Three failed deliveries on the `log` sink, as the test hooks would inject
    // (the sink delivers asynchronously: wait for three delivered rows).
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while count(
        &h,
        "SELECT COUNT(*) FROM event_deliveries WHERE sink = 'log' AND state = 'delivered'",
    ) < 3
        && std::time::Instant::now() < deadline
    {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    db(&h)
        .execute(
            "UPDATE event_deliveries SET state = 'failed', last_error = 'injected' WHERE rowid IN (SELECT rowid FROM event_deliveries WHERE sink = 'log' AND state = 'delivered' LIMIT 3)",
            [],
        )
        .unwrap();
    let failed = count(
        &h,
        "SELECT COUNT(*) FROM event_deliveries WHERE sink = 'log' AND state = 'failed'",
    );
    assert!(
        failed >= 3,
        "the log sink delivered at least 3 events by now"
    );
    let users_before = count(&h, "SELECT COUNT(*) FROM users");
    let events_before = count(&h, "SELECT COUNT(*) FROM events");
    let s = status(&h, &u.a.handle);
    let events_after = count(&h, "SELECT COUNT(*) FROM events");
    let st = &s["store"];
    assert_eq!(st["kind"], "sqlite");
    assert_eq!(
        st["schema_version"],
        hopae::store::sqlite::LATEST_SCHEMA_VERSION
    );
    assert_eq!(st["users"], users_before);
    assert_eq!(
        st["live_sessions"],
        count(
            &h,
            &format!(
                "SELECT COUNT(*) FROM sessions WHERE terminated_at IS NULL AND absolute_expires_at > {}",
                now_secs(&h)
            )
        )
    );
    let n = st["events"].as_i64().unwrap();
    assert!(
        (events_before..=events_after).contains(&n),
        "{events_before} <= {n} <= {events_after}"
    );
    assert_eq!(st["deliveries"]["log"]["failed"], failed, "{st}");
    assert!(st["deliveries"]["log"]["pending"].as_i64().unwrap() >= 0);
    assert!(
        st["last_prune_at"].is_null() || st["last_prune_at"].as_i64().unwrap() > 0,
        "{st}"
    );

    let version = env!("CARGO_PKG_VERSION");
    assert_eq!(s["build"]["version"], version);
    assert_eq!(s["build"]["contract"], "1.1");
    assert!(s["build"]["started_at"].as_i64().unwrap() > 1_600_000_000);
    let cli = h.cli(&["--version"]);
    assert!(cli.stdout.contains(version), "{}", cli.all());

    let generation: i64 = db(&h)
        .query_row(
            "SELECT CAST(value AS INTEGER) FROM meta WHERE key = 'config_generation'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(s["config"]["generation"], generation);
    let loaded = h.hooks.events(Some("config.loaded"), None);
    assert_eq!(
        s["config"]["digest"],
        loaded.last().unwrap()["attrs"]["config_digest"],
        "the digest is the one config.loaded recorded"
    );
    assert_eq!(s["config"]["insecure_mode"], false);
    assert_eq!(s["config"]["unauthenticated_caller"], false);
    assert_eq!(
        s["config"]["listeners"],
        json!({
            "portal": h.portal.to_string(),
            "gateway": h.gateway.to_string(),
            "admin": h.admin.unwrap().to_string(),
        })
    );
    // No path of the state directory beyond what /healthz shows (nothing).
    let state_dir = h.config()["state_dir"].as_str().unwrap().to_string();
    assert!(!s.to_string().contains(&state_dir));
    let page = admin(&h).with_handle(&u.a.handle).get("/").body;
    assert!(!page.contains(&state_dir));
}

#[test]
fn s304_4_page_and_endpoint_change_nothing() {
    let (_idp, h, u) = spawn_status();
    let a = admin(&h).with_handle(&u.a.handle);
    let rows = |h: &Hopae| {
        (
            count(h, "SELECT COUNT(*) FROM providers"),
            count(h, "SELECT COUNT(*) FROM apps"),
            count(
                h,
                "SELECT COUNT(*) FROM events WHERE kind NOT IN ('verify.denied')",
            ),
            count(h, "SELECT COUNT(*) FROM admin_grants"),
            count(
                h,
                "SELECT COUNT(*) FROM sessions WHERE terminated_at IS NULL",
            ),
        )
    };
    let before = rows(&h);
    for path in ["/", "/v1/status"] {
        let r = a.post_json(path, json!({}));
        assert_eq!(r.status, 405, "{path}: {r:?}");
        assert_eq!(r.header("allow"), Some("GET"), "{path}: {r:?}");
    }
    for (method, path) in [
        ("POST", "/v1/providers/mock/disable"),
        ("PUT", "/v1/apps/app"),
        ("DELETE", "/v1/providers/mock2"),
    ] {
        let r = raw(
            &h,
            method,
            path,
            &[
                ("x-forwarded-host", &h.console_host()),
                ("x-forwarded-proto", "https"),
                ("x-forwarded-for", UA_IP),
                ("cookie", &format!("{}={}", h.cookie_name(), u.a.handle)),
                ("content-type", "application/json"),
                ("x-hopae-admin-request", "1"),
            ],
            b"{}",
        );
        assert_eq!(r.status, 404, "{method} {path}: {r:?}");
        assert_eq!(r.json()["error"], "not_found");
    }
    assert_eq!(rows(&h), before, "no row changed");
    assert!(
        !a.get("/").body.contains("<form"),
        "the status page has no form"
    );
}

#[test]
fn s304_5_read_only_administrators_see_the_status_too() {
    let (_idp, h, u) = spawn_status();
    let a = status(&h, &u.a.handle);
    let v = status(&h, &u.v.handle);
    assert_eq!(
        stable(a),
        stable(v.clone()),
        "the same body for both roles, secret variable names included"
    );
    assert_eq!(
        provider(&v, "mock")["client_secret_env"],
        "HOPAE_TEST_MOCK_SECRET"
    );
    for handle in [&u.a.handle, &u.v.handle] {
        let page = admin(&h).with_handle(handle).get("/");
        assert_eq!(page.status, 200, "{page:?}");
        assert!(!page.body.contains("<form"), "no form for either role");
    }
}

#[test]
fn s304_a1_query_strings_and_bodies_ignored() {
    let (_idp, h, u) = spawn_status();
    let a = admin(&h).with_handle(&u.a.handle);
    let plain = a.get("/v1/status");
    let with_query = a.get("/v1/status?provider=mock&reveal=secret");
    assert_eq!(
        stable(plain.json()),
        stable(with_query.json()),
        "the query string changed the answer"
    );
    let host = h.console_host();
    let cookie = format!("{}={}", h.cookie_name(), u.a.handle);
    let mut req = RawReq::new("GET", "/v1/status", &host)
        .header("x-forwarded-host", &host)
        .header("x-forwarded-proto", "https")
        .header("x-forwarded-for", UA_IP)
        .header("cookie", &cookie);
    req.body = vec![b'a'; 1024];
    let with_body = send(h.admin.unwrap(), req);
    assert_eq!(with_body.status, 200, "{with_body:?}");
    assert_eq!(stable(with_body.json()), stable(plain.json()));
    // Over 4 KiB of query is 413.
    let r = a.get(&format!("/?x={}", "a".repeat(4 * 1024)));
    assert_eq!(r.status, 413, "{r:?}");
    // No parameter is reflected anywhere in the page.
    let r = a.get("/?q=%3Cscript%3Ealert(1)%3C/script%3E&provider=%22%3E%3Cb%3E&x=%22");
    assert_eq!(r.status, 200, "{r:?}");
    assert!(
        !r.body.contains("alert(1)") && !r.body.contains("<b>") && !r.body.contains("\"><"),
        "nothing reflected"
    );
}

#[test]
fn s304_a2_consistent_snapshot_while_things_change() {
    let (idp, h, u) = spawn_status();
    let first = status(&h, &u.a.handle);
    let (generation, digest) = (
        first["config"]["generation"].clone(),
        first["config"]["digest"].clone(),
    );
    let stop = std::sync::atomic::AtomicBool::new(false);
    let hooks = h.hooks.clone();
    let user = u.n.user_id.clone();
    let path = h.config()["state_dir"].as_str().unwrap().to_string();
    std::thread::scope(|s| {
        let stop = &stop;
        let idp2 = idp.clone();
        s.spawn(move || {
            let mut flip = false;
            while !stop.load(std::sync::atomic::Ordering::SeqCst) {
                idp2.set_profile(if flip {
                    "auth_time_present"
                } else {
                    "discovery_down"
                });
                flip = !flip;
                std::thread::sleep(Duration::from_millis(10));
            }
        });
        s.spawn(move || {
            let conn = rusqlite::Connection::open(std::path::Path::new(&path).join("hopae.db")).unwrap();
            conn.busy_timeout(Duration::from_secs(10)).unwrap();
            while !stop.load(std::sync::atomic::Ordering::SeqCst) {
                hooks.bulk_sessions(&user, 2);
                let _ = conn.execute(
                    "UPDATE sessions SET terminated_at = 1, terminated_reason = 'admin' WHERE session_id IN (SELECT session_id FROM sessions WHERE user_id = ?1 AND terminated_at IS NULL LIMIT 1)",
                    [&user],
                );
                std::thread::sleep(Duration::from_millis(5));
            }
        });
        for _ in 0..50 {
            let r = admin(&h).with_handle(&u.a.handle).get("/v1/status");
            assert_eq!(r.status, 200, "{r:?}");
            let j = r.json();
            assert_eq!(j["config"]["generation"], generation);
            assert_eq!(j["config"]["digest"], digest);
            for k in ["users", "live_sessions", "events"] {
                assert!(j["store"][k].as_u64().is_some(), "{k}: {j}");
            }
            for p in j["providers"].as_array().unwrap() {
                assert!(
                    matches!(p["health"].as_str(), Some("ok" | "degraded" | "disabled")),
                    "{p}"
                );
            }
        }
        stop.store(true, std::sync::atomic::Ordering::SeqCst);
    });
}

#[test]
fn s304_a3_status_is_cheap() {
    let (idp, h) = spawn_with(Fixture::new("m4-admin"), "auth_time_present");
    let u = users(&h, &idp);
    h.hooks.bulk_events(1_000_000, 24.0);
    h.hooks.bulk_sessions(&u.n.user_id, 50_000);
    let requests = idp.requests().len();
    let host = h.console_host();
    let cookie = format!("{}={}", h.cookie_name(), u.a.handle);
    let addr = h.admin.unwrap();
    for round in 0..10 {
        let results: Vec<(u16, Duration)> = std::thread::scope(|s| {
            let workers: Vec<_> = (0..16)
                .map(|_| {
                    let (host, cookie) = (host.clone(), cookie.clone());
                    s.spawn(move || {
                        let t = std::time::Instant::now();
                        let r = send(
                            addr,
                            RawReq::new("GET", "/v1/status", &host)
                                .header("x-forwarded-host", &host)
                                .header("x-forwarded-proto", "https")
                                .header("x-forwarded-for", UA_IP)
                                .header("cookie", &cookie),
                        );
                        (r.status, t.elapsed())
                    })
                })
                .collect();
            workers.into_iter().map(|w| w.join().unwrap()).collect()
        });
        for (status, took) in results {
            assert_eq!(status, 200, "round {round}");
            assert!(took < Duration::from_secs(2), "round {round}: {took:?}");
        }
    }
    assert_eq!(
        idp.requests().len(),
        requests,
        "no outbound request to any provider"
    );
    if let Some(rss) = h.rss_kib() {
        assert!(rss < 2_000_000, "memory under the harness limit: {rss} KiB");
    }
    // The 17th concurrent caller is refused: the store stalls past the verify
    // budget, so the first sixteen hold their permits meanwhile.
    h.hooks.stall(1500);
    let results: Vec<u16> = std::thread::scope(|s| {
        let workers: Vec<_> = (0..17)
            .map(|_| {
                let (host, cookie) = (host.clone(), cookie.clone());
                s.spawn(move || {
                    send(
                        addr,
                        RawReq::new("GET", "/v1/status", &host)
                            .header("x-forwarded-host", &host)
                            .header("x-forwarded-proto", "https")
                            .header("x-forwarded-for", UA_IP)
                            .header("cookie", &cookie),
                    )
                    .status
                })
            })
            .collect();
        workers.into_iter().map(|w| w.join().unwrap()).collect()
    });
    h.hooks.stall_off();
    let overloaded = results.iter().filter(|s| **s == 503).count();
    assert!(overloaded >= 1, "{results:?}");
}

#[test]
fn s304_a4_page_cannot_trigger_provider_or_gateway_call() {
    // A fake gateway admin endpoint that records every connection.
    let fake = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    fake.set_nonblocking(true).unwrap();
    let url = format!("http://{}", fake.local_addr().unwrap());
    let idp = MockIdp::start("auth_time_present");
    let issuer = idp.issuer.as_str().trim_end_matches('/').to_string();
    let _ = issuer;
    let h = Hopae::spawn(
        Fixture::with(
            "m4-admin",
            json!({"gateway": {"admin_url": url, "readonly_token_env": "HOPAE_TEST_RO_TOKEN"}}),
        ),
        &idp,
        &[("HOPAE_TEST_RO_TOKEN", "ro-token")],
    );
    let u = users(&h, &idp);
    // Let the provider's own startup traffic settle first.
    std::thread::sleep(Duration::from_millis(1500));
    let before = idp.requests().len();
    for _ in 0..5 {
        assert!(status(&h, &u.a.handle)["apps"].as_array().is_some());
        assert_eq!(admin(&h).with_handle(&u.a.handle).get("/").status, 200);
    }
    assert_eq!(
        idp.requests().len(),
        before,
        "no request reached the provider"
    );
    assert!(
        fake.accept().is_err(),
        "no connection reached the gateway's admin endpoint"
    );
}

#[test]
fn s304_a5_nothing_leaks_to_the_unauthorized() {
    let (_idp, h, u) = spawn_status();
    for path in ["/v1/status", "/"] {
        let nobody = admin(&h).get(path);
        assert_eq!(nobody.status, 403, "{path}: {nobody:?}");
        assert_eq!(error_code(&nobody), "login_required");
        let outsider = admin(&h).with_handle(&u.n.handle).get(path);
        assert_eq!(outsider.status, 403, "{path}: {outsider:?}");
        assert_eq!(error_code(&outsider), "not_admin");
        for r in [&nobody, &outsider] {
            for needle in [
                "app.example.test",
                "mock",
                env!("CARGO_PKG_VERSION"),
                &h.portal.port().to_string(),
                &h.admin.unwrap().port().to_string(),
                "sqlite",
            ] {
                assert!(
                    !r.body.contains(needle),
                    "{path}: the body names {needle}: {}",
                    r.body
                );
            }
        }
    }
    // /healthz on the portal remains the only unauthenticated status surface.
    let hz = crate::support::get(h.portal, "/healthz");
    assert_eq!(hz.status, 200);
    let j = hz.json();
    for k in [
        "status",
        "ready",
        "store",
        "providers",
        "insecure_mode",
        "unauthenticated_caller",
    ] {
        assert!(j.get(k).is_some(), "{k} in {j}");
    }
}

#[test]
fn authentication_profiles_read_is_authenticated_and_reference_only() {
    let (_idp, h, u) = spawn_status();
    let anonymous = admin(&h).get("/v1/authentication/profiles");
    assert_ne!(anonymous.status, 200);
    let response = admin(&h)
        .with_handle(&u.a.handle)
        .get("/v1/authentication/profiles");
    assert_eq!(response.status, 200);
    let document: Value = serde_json::from_str(&response.body).unwrap();
    assert_eq!(document["revision"], 0);
    assert!(document["configuration"].is_null());
    let config: hopae::auth_gateway::runtime::Config =
        serde_json::from_value(json!({"authority_id":"owned","profiles":[{
        "service_id":"app","host":"app.example.test","ports":[443],"realm":"owned",
        "api_keys":[{"token_env":"OWNED_REFERENCE_ONLY","subject":"worker"}]}]}))
        .unwrap();
    hopae::auth_gateway::publication::publish(&mut db(&h), 0, Some(config), "owned-operator")
        .unwrap();
    let response = admin(&h)
        .with_handle(&u.a.handle)
        .get("/v1/authentication/profiles");
    assert_eq!(response.status, 200);
    let document: Value = serde_json::from_str(&response.body).unwrap();
    assert_eq!(document["revision"], 1);
    assert_eq!(
        document["configuration"]["profiles"][0]["api_keys"][0]["token_env"],
        "OWNED_REFERENCE_ONLY"
    );
}

#[test]
fn authentication_profiles_put_requires_csrf_admin_revision_and_persists_tombstone() {
    let idp = MockIdp::start("auth_time_present");
    let profile = json!({"authority_id":"owned","profiles":[{"service_id":"app","host":"app.example.test","ports":[443],"realm":"owned",
        "api_relay":{"url":format!("{}/verify",idp.issuer.as_str().trim_end_matches('/')),"issuer":"owned","allow_private_endpoints":true}}]});
    let h = Hopae::spawn(
        Fixture::with("m4-admin", json!({"authentication_gateway":profile})),
        &idp,
        &[],
    );
    let u = users(&h, &idp);
    let path = "/v1/authentication/profiles";
    let headers = [
        ("content-type", "application/json"),
        ("x-hopae-admin-request", "1"),
        ("if-match", "\"1\""),
    ];
    let body = br#"{"configuration":null}"#;
    assert_eq!(
        admin(&h)
            .with_handle(&u.v.handle)
            .put_json_raw(path, &headers, body)
            .status,
        403
    );
    assert_eq!(
        admin(&h)
            .with_handle(&u.a.handle)
            .put_json_raw(
                path,
                &[("content-type", "application/json"), ("if-match", "\"1\"")],
                body
            )
            .status,
        403
    );
    let mut modified = profile.clone();
    modified["profiles"][0]["api_relay"]["url"] = json!(format!(
        "{}/not-declared",
        idp.issuer.as_str().trim_end_matches('/')
    ));
    let forbidden = json!({"configuration":modified}).to_string();
    assert_eq!(
        admin(&h)
            .with_handle(&u.a.handle)
            .put_json_raw(path, &headers, forbidden.as_bytes())
            .status,
        422
    );
    let result = admin(&h)
        .with_handle(&u.a.handle)
        .put_json_raw(path, &headers, body);
    assert_eq!(result.status, 200, "{result:?}");
    assert_eq!(result.json()["revision"], 2);
    assert_eq!(
        admin(&h)
            .with_handle(&u.a.handle)
            .put_json_raw(path, &headers, body)
            .status,
        409
    );
    let stored = hopae::auth_gateway::publication::read(&db(&h))
        .unwrap()
        .unwrap();
    assert_eq!(stored.revision, 2);
    assert!(stored.configuration.is_none());
}

#[test]
fn credential_projection_admin_publication_is_fenced_and_survives_restart() {
    let idp = MockIdp::start("auth_time_present");
    let config = json!({"revision":1,"plans":[{"service":"app","audience":"app-api","resource":"app","action":"read","minimum_aal":1,"credential":{"type":"bearer_reference","secret_ref":"vault:owned-token"}}]});
    let mut h = Hopae::spawn(
        Fixture::with("m4-admin", json!({"credential_projection":config})),
        &idp,
        &[],
    );
    let u = users(&h, &idp);
    let path = "/v1/authentication/projections";
    assert_ne!(admin(&h).get(path).status, 200);
    let read = admin(&h).with_handle(&u.v.handle).get(path);
    assert_eq!(read.status, 200, "{read:?}");
    assert_eq!(read.json()["revision"], 1);
    assert_eq!(read.header("cache-control"), Some("no-store"));
    let headers = [
        ("content-type", "application/json"),
        ("x-hopae-admin-request", "1"),
        ("if-match", "\"1\""),
    ];
    let body = br#"{"configuration":null}"#;
    assert_eq!(
        admin(&h)
            .with_handle(&u.v.handle)
            .put_json_raw(path, &headers, body)
            .status,
        403
    );
    assert_eq!(
        admin(&h)
            .with_handle(&u.a.handle)
            .put_json_raw(
                path,
                &[("content-type", "application/json"), ("if-match", "\"1\"")],
                body
            )
            .status,
        403
    );
    assert_eq!(
        admin(&h)
            .with_handle(&u.a.handle)
            .put_json_raw(
                path,
                &[
                    ("content-type", "application/json"),
                    ("x-hopae-admin-request", "1")
                ],
                body
            )
            .status,
        428
    );
    assert_eq!(
        admin(&h)
            .with_handle(&u.a.handle)
            .put_json_raw(path, &headers, b"{}")
            .status,
        422
    );
    for field in ["secret", "audience", "assurance", "resource", "action"] {
        let mut modified = config.clone();
        modified["revision"] = json!(2);
        match field {
            "secret" => {
                modified["plans"][0]["credential"]["secret_ref"] = json!("vault:undeclared")
            }
            "audience" => modified["plans"][0]["audience"] = json!("another-api"),
            "assurance" => modified["plans"][0]["minimum_aal"] = json!(0),
            "resource" => modified["plans"][0]["resource"] = json!("another-resource"),
            _ => modified["plans"][0]["action"] = json!("write"),
        }
        let body = json!({"configuration":modified}).to_string();
        let result =
            admin(&h)
                .with_handle(&u.a.handle)
                .put_json_raw(path, &headers, body.as_bytes());
        assert_eq!(result.status, 422, "{field}: {result:?}");
    }
    let result = admin(&h)
        .with_handle(&u.a.handle)
        .put_json_raw(path, &headers, body);
    assert_eq!(result.status, 200, "{result:?}");
    assert_eq!(result.json()["revision"], 2);
    assert_eq!(
        admin(&h)
            .with_handle(&u.a.handle)
            .put_json_raw(path, &headers, body)
            .status,
        409
    );
    h.restart();
    let document = hopae::auth_gateway::projection_authority::read(&db(&h))
        .unwrap()
        .unwrap();
    assert_eq!(document.revision, 2);
    assert!(document.configuration.is_none());
    let read = admin(&h).with_handle(&u.a.handle).get(path);
    assert_eq!(read.status, 200, "{read:?}");
    assert!(read.json()["configuration"].is_null());
    let mut enabled = config;
    enabled["revision"] = json!(3);
    enabled["plans"][0]["minimum_aal"] = json!(2);
    let body = json!({"configuration":enabled}).to_string();
    let result = admin(&h).with_handle(&u.a.handle).put_json_raw(
        path,
        &[
            ("content-type", "application/json"),
            ("x-hopae-admin-request", "1"),
            ("if-match", "\"2\""),
        ],
        body.as_bytes(),
    );
    assert_eq!(result.status, 200, "{result:?}");
    h.restart();
    let read = admin(&h).with_handle(&u.a.handle).get(path);
    assert_eq!(read.status, 200, "{read:?}");
    assert_eq!(read.json()["revision"], 3);
    assert_eq!(read.json()["configuration"]["plans"][0]["minimum_aal"], 2);
    assert!(!read.body.contains("Bearer "));
}
