//! Scenario 307: subject resolution and search for the console (ADR-0020).
//!
//! The tests drive the real binary over the admin listener; administrators
//! sign in through the real flow (`kit` of 301) and directory rows are laid
//! down with SQL. `dkit` is shared with 308 and 309.
#![allow(dead_code)]

use serde_json::{Value, json};

use super::s301_admin_users::kit::{CLIENT_IP, Console, Who, code};
use crate::support::*;
use hopae::store::types::AdminRole;

pub(crate) mod dkit {
    use serde_json::{Value, json};

    use super::super::s301_admin_users::kit::Console;
    use crate::support::*;

    pub const KEY_ENV: &str = "HOPAE_TEST_SERVICE_KEY";
    pub const KEY: &str = "service-credential-material-0123456789abcdef";
    pub const OLD_KEY_ENV: &str = "HOPAE_TEST_SERVICE_OLD_KEY";
    pub const OLD_KEY: &str = "expired-credential-material-0123456789abcdef";
    pub const API_HOST: &str = "api.example.test";

    /// `m4-admin` with a service host `api.example.test` (application `api`
    /// and an API-key profile limited to `192.0.2.0/24`) and step-up rules on
    /// `app`: AAL 2 under `/admin`, a 600 s sign-in age under `/fresh`.
    pub fn overrides() -> Value {
        json!({
            "apps": [
                {"app_id": "app", "step_up": [
                    {"path_prefix": "/admin", "require": {"aal": 2}},
                    {"path_prefix": "/fresh", "require": {"aal": 1, "max_age": 600}}
                ]},
                {"app_id": "api", "display_name": "api", "hosts": ["api.example.test"], "ports": [443],
                 "step_up": [{"path_prefix": "/admin", "require": {"aal": 2}}]}
            ],
            "authentication_gateway": {"authority_id": "owned", "profiles": [{
                "service_id": "api", "host": API_HOST, "ports": [443], "realm": "svc",
                "networks": ["192.0.2.0/24"],
                "api_keys": [
                    {"token_env": KEY_ENV, "subject": "worker"},
                    {"token_env": OLD_KEY_ENV, "subject": "retired", "expires_at": 1000}
                ]
            }]}
        })
    }

    /// A console instance with [`overrides`] merged with `extra`.
    pub fn console(extra: Value, env: &[(&str, &str)]) -> Console {
        let mut v = overrides();
        merge(&mut v, &extra);
        let idp = MockIdp::start("default");
        let mut all = vec![(KEY_ENV, KEY), (OLD_KEY_ENV, OLD_KEY)];
        all.extend_from_slice(env);
        let h = Hopae::spawn(Fixture::with("m4-admin", v), &idp, &all);
        Console { h, idp }
    }

    fn merge(base: &mut Value, over: &Value) {
        match (base, over) {
            (Value::Object(b), Value::Object(o)) => {
                for (k, v) in o {
                    merge(b.entry(k.clone()).or_insert(Value::Null), v);
                }
            }
            (b, o) => *b = o.clone(),
        }
    }

    /// The `s_` reference of an API-key subject of the profile above.
    pub fn service_ref(name: &str) -> String {
        hopae::auth_gateway::stable_subject(&hopae::auth_gateway::Subject {
            issuer: "hopae:owned".into(),
            realm: "svc".into(),
            subject: name.into(),
            kind: hopae::auth_gateway::PrincipalKind::Service,
        })
    }

    /// The `admin.read` audit records.
    pub fn reads(k: &Console) -> Vec<Value> {
        k.events("admin.read")
    }
}

use dkit::{console, reads, service_ref};

fn resolve(k: &Console, w: &Who, body: Value) -> Response {
    k.client(w).post_json("/v1/subjects/resolve", body)
}

fn item<'a>(r: &'a Value, id: &str) -> &'a Value {
    r["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["id"] == id)
        .unwrap_or_else(|| panic!("no item {id}: {r}"))
}

/// Users `u_live` (active, linked to `mock`, one session), `u_off`
/// (disabled) and `u_gone` (deleted: reserved, no row).
fn seed(k: &Console) {
    k.add_user("u_live", "alice.live@example.test", "Alice Live");
    k.add_identity("u_live", "mock", "sub-live", "alice.live@example.test");
    let now = k.now_s();
    k.add_session(
        "s_live1",
        "u_live",
        now - 120,
        CLIENT_IP,
        None,
        &["app.example.test"],
        None,
        None,
    );
    k.add_user("u_off", "bob.off@example.test", "Bob Off");
    k.sql()
        .execute(
            "UPDATE users SET status='disabled' WHERE user_id='u_off'",
            [],
        )
        .unwrap();
    k.add_user("u_gone", "carol.gone@example.test", "Carol Gone");
    k.sql()
        .execute("DELETE FROM users WHERE user_id='u_gone'", [])
        .unwrap();
}

#[test]
fn s307_1_user_ids_resolve_with_status_tombstone_and_masking() {
    let k = console(json!({}), &[]);
    let a = k.admin("ha307a", AdminRole::Admin);
    seed(&k);
    let r = resolve(
        &k,
        &a,
        json!({"ids": ["u_live", "u_off", "u_gone", "u_never", "alice", "u_live"]}),
    );
    assert_eq!(r.status, 200, "{r:?}");
    assert_eq!(r.header("cache-control"), Some("no-store"));
    let j = r.json();
    let ids: Vec<&str> = j["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, ["u_live", "u_off", "u_gone", "u_never", "alice"]);
    let live = item(&j, "u_live");
    assert_eq!(live["status"], "active");
    assert_eq!(live["kind"], "human");
    assert_eq!(live["display_name"], "Alice Live");
    assert_eq!(live["email"], "a***@example.test");
    assert_eq!(live["providers"], json!(["mock"]));
    assert!(live["created_at"].is_i64() && live["last_seen_at"].is_i64());
    assert_eq!(live["reason"], Value::Null);
    assert_eq!(item(&j, "u_off")["status"], "disabled");
    let gone = item(&j, "u_gone");
    assert_eq!(gone["status"], "deleted");
    assert_eq!(gone["kind"], "human");
    assert_eq!(gone["display_name"], Value::Null);
    assert_eq!(gone["email"], Value::Null);
    assert_eq!(item(&j, "u_never")["status"], "unknown");
    assert_eq!(item(&j, "u_never")["reason"], "not_found");
    assert_eq!(item(&j, "alice")["reason"], "unrecognized");
    assert_eq!(j["resolved"], 3);
    assert_eq!(j["unknown"], 2);
    assert_eq!(j["privacy_profile"], "standard");
    assert!(!r.body.contains("alice.live@example.test"));
    assert!(!r.body.contains("carol"));

    let strict = resolve(
        &k,
        &a,
        json!({"ids": ["u_live"], "privacy_profile": "strict"}),
    );
    assert_eq!(strict.status, 200);
    let s = strict.json();
    assert_eq!(item(&s, "u_live")["email"], Value::Null);
    assert_eq!(item(&s, "u_live")["display_name"], "Alice Live");
    assert!(!strict.body.contains("example.test\""));
}

#[test]
fn s307_2_service_and_unconfigured_references_resolve_explicitly() {
    let k = console(json!({}), &[]);
    let a = k.admin("ha307b", AdminRole::Viewer);
    let worker = service_ref("worker");
    let retired = service_ref("retired");
    let stranger = format!("s_{}", "0".repeat(48));
    let human = format!("human1:{}", "a".repeat(64));
    let r = resolve(
        &k,
        &a,
        json!({"ids": [worker, retired, stranger, human, "s_0123456789ABCDEFGHJKMNPQRS"]}),
    );
    assert_eq!(r.status, 200, "{r:?}");
    let j = r.json();
    let w = item(&j, &worker);
    assert_eq!(w["status"], "active");
    assert_eq!(w["kind"], "service");
    assert_eq!(w["display_name"], "worker (api)");
    assert_eq!(w["service_id"], "api");
    assert_eq!(w["realm"], "svc");
    let old = item(&j, &retired);
    assert_eq!(old["status"], "disabled");
    assert_eq!(old["reason"], "credential_expired");
    assert_eq!(item(&j, &stranger)["reason"], "not_enumerable");
    assert_eq!(item(&j, &human)["reason"], "human_subjects_not_configured");
    assert_eq!(
        item(&j, "s_0123456789ABCDEFGHJKMNPQRS")["reason"],
        "unrecognized"
    );
    // No credential material or reference names leave the server.
    for secret in [dkit::KEY, dkit::OLD_KEY, dkit::KEY_ENV, dkit::OLD_KEY_ENV] {
        assert!(!r.body.contains(secret));
    }
}

#[test]
fn s307_3_search_people_and_service_principals_with_cursor() {
    let k = console(json!({}), &[]);
    let a = k.admin("ha307c", AdminRole::Admin);
    for i in 0..5 {
        k.add_user(
            &format!("u_srch{i}"),
            &format!("dana{i}@example.test"),
            &format!("Dana Number{i}"),
        );
    }
    k.add_user("u_other", "erin@example.test", "Erin");
    let cl = k.client(&a);
    let mut seen = Vec::new();
    let mut cursor: Option<String> = None;
    for _ in 0..10 {
        let mut body = json!({"q": "dana", "limit": 2});
        if let Some(c) = &cursor {
            body["cursor"] = json!(c);
        }
        let r = cl.post_json("/v1/subjects/search", body);
        assert_eq!(r.status, 200, "{r:?}");
        let j = r.json();
        for i in j["items"].as_array().unwrap() {
            assert_eq!(i["kind"], "human");
            assert!(i["email"].as_str().unwrap().starts_with("d***@"));
            seen.push(i["id"].as_str().unwrap().to_string());
        }
        match j["next_cursor"].as_str() {
            Some(c) => cursor = Some(c.to_string()),
            None => break,
        }
    }
    seen.sort();
    assert_eq!(
        seen,
        (0..5).map(|i| format!("u_srch{i}")).collect::<Vec<_>>()
    );
    // Display-name substring, case-insensitive; an exact user ID resolves.
    let r = cl.post_json("/v1/subjects/search", json!({"q": "NUMBER3"}));
    assert_eq!(r.json()["items"][0]["id"], "u_srch3");
    let r = cl.post_json("/v1/subjects/search", json!({"q": "u_other"}));
    assert_eq!(r.json()["items"][0]["display_name"], "Erin");
    let r = cl.post_json(
        "/v1/subjects/search",
        json!({"q": "u_srch1", "status": "disabled"}),
    );
    assert_eq!(r.json()["items"], json!([]));
    // Service principals by name, service or realm.
    let r = cl.post_json(
        "/v1/subjects/search",
        json!({"q": "work", "kind": "service"}),
    );
    assert_eq!(r.status, 200, "{r:?}");
    let items = r.json()["items"].as_array().unwrap().clone();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["id"], service_ref("worker"));
    let r = cl.post_json(
        "/v1/subjects/search",
        json!({"q": "svc", "kind": "service", "limit": 1}),
    );
    let j = r.json();
    assert_eq!(j["items"].as_array().unwrap().len(), 1);
    let next = j["next_cursor"]
        .as_str()
        .expect("a second page")
        .to_string();
    let r = cl.post_json(
        "/v1/subjects/search",
        json!({"q": "svc", "kind": "service", "limit": 1, "cursor": next}),
    );
    let j2 = r.json();
    assert_eq!(j2["items"].as_array().unwrap().len(), 1);
    assert_ne!(j2["items"][0]["id"], j["items"][0]["id"]);
    assert_eq!(j2["next_cursor"], Value::Null);
}

#[test]
fn s307_4_every_read_is_audited_without_identifiers() {
    let k = console(json!({}), &[]);
    let a = k.admin("ha307d", AdminRole::Admin);
    seed(&k);
    let before = reads(&k).len();
    let body = json!({"ids": ["u_live", "u_never"]});
    let r = resolve(&k, &a, body.clone());
    assert_eq!(r.status, 200);
    let r = k
        .client(&a)
        .post_json("/v1/subjects/search", json!({"q": "alice"}));
    assert_eq!(r.status, 200);
    let ev = reads(&k);
    assert_eq!(ev.len(), before + 2);
    let resolve_ev = ev
        .iter()
        .find(|e| e["attrs"]["purpose"] == "subjects.resolve")
        .unwrap();
    assert_eq!(resolve_ev["outcome"], "success");
    assert_eq!(resolve_ev["attrs"]["actor"], a.user_id.as_str());
    assert_eq!(resolve_ev["attrs"]["endpoint"], "/v1/subjects/resolve");
    assert_eq!(resolve_ev["attrs"]["requested"], 2);
    assert_eq!(resolve_ev["attrs"]["count"], 1);
    assert_eq!(resolve_ev["attrs"]["status"], "partial");
    let digest = resolve_ev["attrs"]["query_sha256"].as_str().unwrap();
    assert_eq!(digest.len(), 64);
    let text = resolve_ev.to_string();
    for leak in ["u_live", "u_never", "alice", "example.test"] {
        assert!(!text.contains(leak), "{leak} in {text}");
    }
    let search_ev = ev
        .iter()
        .find(|e| e["attrs"]["purpose"] == "subjects.search")
        .unwrap();
    assert!(!search_ev.to_string().contains("alice"));
}

#[test]
fn s307_5_delegated_console_actor_resolves() {
    use hopae::admin::delegation_wire::{Assertion, digest, sign};
    use std::os::unix::fs::PermissionsExt;
    const DKEY: &str = "fixture-delegation-key-32-bytes-minimum";
    let dir = tempfile::tempdir().unwrap();
    let mappings = dir.path().join("delegated-sessions.json");
    std::fs::write(&mappings, "[]").unwrap();
    std::fs::set_permissions(&mappings, std::fs::Permissions::from_mode(0o600)).unwrap();
    let k = console(
        json!({"admin": {"hangang_delegation": {"key_env": "HOPAE_TEST_DELEGATION_KEY", "sessions_file": mappings}}}),
        &[("HOPAE_TEST_DELEGATION_KEY", DKEY)],
    );
    let a = k.admin("ha307e", AdminRole::Viewer);
    seed(&k);
    std::fs::write(
        &mappings,
        json!([{"actor_id": 7, "actor_name": "operator", "user_id": a.user_id, "handle": a.handle, "client_ip": CLIENT_IP}]).to_string(),
    )
    .unwrap();
    let send_signed = |path: &str, body: &str, nonce: u128, tamper: bool| {
        let assertion = Assertion {
            authority: None,
            actor_id: 7,
            actor_name: "operator".into(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            nonce: format!("{nonce:032x}"),
            method: "POST".into(),
            path: path.into(),
            body_sha256: digest(body.as_bytes()),
            handle_sha256: digest(b""),
            client_ip: CLIENT_IP.into(),
            user_agent: None,
        };
        let (s, m) = sign(&assertion, DKEY.as_bytes()).unwrap();
        let mut req = RawReq::new("POST", path, &k.h.console_host())
            .header("x-hopae-delegation", &s)
            .header("x-hopae-delegation-mac", &m)
            .header("content-type", "application/json");
        req.body = if tamper {
            body.replace("u_live", "u_off").into_bytes()
        } else {
            body.as_bytes().to_vec()
        };
        client::send(k.h.admin.unwrap(), req)
    };
    let body = json!({"ids": ["u_live"]}).to_string();
    let r = send_signed("/v1/subjects/resolve", &body, 1, false);
    assert_eq!(r.status, 200, "{r:?}");
    assert_eq!(r.json()["items"][0]["status"], "active");
    // A replayed nonce and a body that differs from the signed one are refused.
    assert_eq!(
        send_signed("/v1/subjects/resolve", &body, 1, false).status,
        403
    );
    assert_eq!(
        send_signed("/v1/subjects/resolve", &body, 2, true).status,
        403
    );
    let ev = reads(&k);
    let last = ev.last().unwrap();
    assert_eq!(last["attrs"]["delegated_actor"], "7:operator");
    assert_eq!(last["attrs"]["purpose"], "subjects.resolve");
}

#[test]
fn s307_6_operator_privacy_floor_cannot_be_lowered_by_a_request() {
    let k = console(json!({"admin": {"directory_privacy": "strict"}}), &[]);
    let a = k.admin("ha307g", AdminRole::Admin);
    seed(&k);
    for body in [
        json!({"ids": ["u_live"]}),
        json!({"ids": ["u_live"], "privacy_profile": "standard"}),
        json!({"ids": ["u_live"], "privacy_profile": "strict"}),
    ] {
        let r = resolve(&k, &a, body);
        assert_eq!(r.status, 200, "{r:?}");
        let j = r.json();
        assert_eq!(j["privacy_profile"], "strict");
        assert_eq!(item(&j, "u_live")["email"], Value::Null);
        assert_eq!(item(&j, "u_live")["display_name"], "Alice Live");
        assert!(!r.body.contains("example.test"));
    }
    let r = k.client(&a).post_json(
        "/v1/subjects/search",
        json!({"q": "alice", "privacy_profile": "standard"}),
    );
    assert_eq!(r.status, 200, "{r:?}");
    assert_eq!(r.json()["privacy_profile"], "strict");
    assert!(!r.body.contains("example.test"));
}

#[test]
fn s307_a1_batch_and_reference_bounds() {
    let k = console(json!({}), &[]);
    let a = k.admin("ha307f", AdminRole::Admin);
    let before = reads(&k).len();
    let many: Vec<String> = (0..101).map(|i| format!("u_{i}")).collect();
    for body in [
        json!({"ids": many}),
        json!({"ids": []}),
        json!({"ids": ["x".repeat(257)]}),
        json!({"ids": [""]}),
        json!({"ids": ["u_a"], "extra": 1}),
        json!({"ids": "u_a"}),
        json!({"ids": ["u_a"], "privacy_profile": "none"}),
    ] {
        let r = resolve(&k, &a, body.clone());
        assert_eq!(r.status, 400, "{body}: {r:?}");
        assert_eq!(code(&r), "invalid_request");
    }
    let hundred: Vec<String> = (0..100).map(|i| format!("u_{i}")).collect();
    let r = resolve(&k, &a, json!({"ids": hundred}));
    assert_eq!(r.status, 200);
    assert_eq!(r.json()["unknown"], 100);
    for body in [
        json!({"q": ""}),
        json!({"q": "x".repeat(129)}),
        json!({"q": "a\u{7}b"}),
        json!({"q": "a", "limit": 51}),
        json!({"q": "a", "limit": 0}),
        json!({"q": "a", "kind": "workload"}),
        json!({"q": "a", "status": "deleted"}),
    ] {
        let r = k.client(&a).post_json("/v1/subjects/search", body.clone());
        assert_eq!(r.status, 400, "{body}: {r:?}");
    }
    let r = k
        .client(&a)
        .post_json("/v1/subjects/search", json!({"q": "a", "cursor": "forged"}));
    assert_eq!(r.status, 400);
    assert_eq!(code(&r), "invalid_cursor");
    // Refused requests disclose nothing and are not recorded as reads.
    assert_eq!(reads(&k).len(), before + 1);
}

#[test]
fn s307_a2_reads_require_the_json_api_rule() {
    let k = console(json!({}), &[]);
    let a = k.admin("ha307g", AdminRole::Admin);
    let cl = k.client(&a);
    let body = json!({"ids": ["u_x"]}).to_string();
    for headers in [
        vec![("content-type", "text/plain")],
        vec![("content-type", "application/json")],
        vec![
            ("content-type", "application/x-www-form-urlencoded"),
            ("x-hopae-admin-request", "1"),
        ],
        vec![
            ("content-type", "application/json"),
            ("x-hopae-admin-request", "1"),
            ("origin", "https://evil.example.test"),
        ],
        vec![
            ("content-type", "application/json"),
            ("x-hopae-admin-request", "1"),
            ("sec-fetch-site", "cross-site"),
        ],
    ] {
        let r = cl.post_json_raw("/v1/subjects/resolve", &headers, body.as_bytes());
        assert_eq!(r.status, 403, "{headers:?}: {r:?}");
        assert_eq!(code(&r), "csrf_rejected");
    }
    // The read is not a GET: a link or an image cannot trigger it.
    assert_eq!(cl.get("/v1/subjects/resolve").status, 405);
    assert!(reads(&k).is_empty());
}

#[test]
fn s307_a3_per_actor_rate_limit() {
    let k = console(json!({}), &[]);
    let a = k.admin("ha307h", AdminRole::Admin);
    let b = k.admin("hb307h", AdminRole::Viewer);
    let mut limited = None;
    for i in 0..70 {
        let r = resolve(&k, &a, json!({"ids": ["u_x"]}));
        if r.status == 429 {
            limited = Some((i, r));
            break;
        }
        assert_eq!(r.status, 200, "{r:?}");
    }
    let (i, r) = limited.expect("the limit applies");
    assert!((60..=68).contains(&i), "limited after {i}");
    assert_eq!(code(&r), "rate_limited");
    let wait: u64 = r.header("retry-after").unwrap().parse().unwrap();
    assert!((1..=60).contains(&wait));
    // Another administrator and another read family keep their own budget.
    assert_eq!(resolve(&k, &b, json!({"ids": ["u_x"]})).status, 200);
    assert_eq!(
        k.client(&a)
            .post_json("/v1/subjects/search", json!({"q": "x"}))
            .status,
        200
    );
}

#[test]
fn s307_a4_unauthenticated_and_ungranted_callers_learn_nothing() {
    let k = console(json!({}), &[]);
    seed(&k);
    let anonymous =
        k.h.admin_client()
            .post_json("/v1/subjects/resolve", json!({"ids": ["u_live"]}));
    assert_eq!(anonymous.status, 403, "{anonymous:?}");
    assert_eq!(code(&anonymous), "login_required");
    assert!(!anonymous.body.contains("u_live"));
    let plain = k.login("plain307", "plain307@example.test", "Plain");
    let r = k
        .client(&plain)
        .post_json("/v1/subjects/resolve", json!({"ids": ["u_live"]}));
    assert_eq!(r.status, 403, "{r:?}");
    assert!(!r.body.contains("Alice"));
    for path in [
        "/v1/subjects/search",
        "/v1/subjects/lifecycle",
        "/v1/subjects/lifecycle/snapshot",
        "/v1/explain/authentication",
    ] {
        let r = k.client(&plain).post_json(path, json!({}));
        assert_eq!(r.status, 403, "{path}: {r:?}");
    }
    assert!(reads(&k).is_empty());
}
