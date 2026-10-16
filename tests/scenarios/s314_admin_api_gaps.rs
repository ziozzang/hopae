//! Scenarios 314-317: the console's administration APIs for the Identities
//! section — a user's factors (list and reset), listing filters and the user
//! detail through the Hangang adapter, mutation reasons and the bulk disable,
//! the publication audit, the dry-run profile validation and the status facts.
//!
//! The binary runs for real; administrators sign in through the real flow
//! (`kit` of 301); factor rows are laid down with SQL (the WebAuthn
//! ceremonies themselves are scenario 480's).
#![allow(dead_code)]

use std::time::{SystemTime, UNIX_EPOCH};

use hopae::admin::delegation_wire::{Assertion, digest, sign};
use hopae::store::types::AdminRole;
use serde_json::{Value, json};

use super::s301_admin_users::kit::{CLIENT_IP, Console, Who, code};
use crate::support::client::send;
use crate::support::*;

const DELEGATION_KEY: &str = "fixture-delegation-key-32-bytes-minimum";
const DELEGATION_ENV: &str = "HOPAE_TEST_DELEGATION_KEY";
const SERVICE_ENV: &str = "HOPAE_TEST_SERVICE_KEY";
const SERVICE_KEY: &str = "service-credential-material-0123456789abcdef";
/// Google Titan Security Key (a known AAGUID).
const TITAN: &str = "42b4fb4a-2866-43b2-9bf7-6c6669c2e5d3";

fn console(overrides: Value) -> Console {
    let idp = MockIdp::start("default");
    let h = Hopae::spawn(
        Fixture::with("m4-admin", overrides),
        &idp,
        &[(DELEGATION_ENV, DELEGATION_KEY), (SERVICE_ENV, SERVICE_KEY)],
    );
    Console { h, idp }
}

/// A console whose authority is the Hangang console (signed assertions only).
fn hangang_console() -> Console {
    console(
        json!({"admin": {"hangang_delegation": {"key_env": DELEGATION_ENV, "authority": "hangang"}}}),
    )
}

/// A request signed as Hangang console actor 7 (`authority: hangang`).
fn signed(k: &Console, method: &str, path: &str, body: &str, nonce: u128) -> Response {
    let assertion = Assertion {
        authority: Some("hangang".into()),
        actor_id: 7,
        actor_name: "operator".into(),
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        nonce: format!("{nonce:032x}"),
        method: method.into(),
        path: path.into(),
        body_sha256: digest(body.as_bytes()),
        handle_sha256: digest(b""),
        client_ip: CLIENT_IP.into(),
        user_agent: None,
    };
    let (a, m) = sign(&assertion, DELEGATION_KEY.as_bytes()).unwrap();
    let mut request = RawReq::new(method, path, &k.h.console_host())
        .header("x-hopae-delegation", &a)
        .header("x-hopae-delegation-mac", &m)
        .header("content-type", "application/json");
    request.body = body.as_bytes().to_vec();
    send(k.h.admin.unwrap(), request)
}

fn post(k: &Console, path: &str, body: Value, nonce: u128) -> Response {
    signed(k, "POST", path, &body.to_string(), nonce)
}

/// The attrs of the latest event of `kind`.
fn last_attrs(k: &Console, kind: &str) -> Value {
    let attrs: String = k
        .sql()
        .query_row(
            "SELECT attrs FROM events WHERE kind=?1 ORDER BY at DESC, event_id DESC LIMIT 1",
            [kind],
            |r| r.get(0),
        )
        .unwrap_or_else(|_| panic!("no {kind} event"));
    serde_json::from_str(&attrs).unwrap()
}

/// `u_f` with two passkeys (a Titan key, a synced passkey without AAGUID),
/// an authenticator app, recovery codes (two unused of three, one used: a
/// re-enrollment is required) and three sessions: one elevated by the Titan
/// key, one by the authenticator app, one plain.
fn seed_factors(k: &Console) {
    k.add_user("u_f", "fay@example.test", "Fay Factors");
    k.add_identity("u_f", "mock", "sub-fay", "fay@example.test");
    let now = k.now_s();
    for (s, _) in [("s_key", 0), ("s_totp", 1), ("s_plain", 2)] {
        k.add_session(
            s,
            "u_f",
            now - 60,
            CLIENT_IP,
            None,
            &["app.example.test"],
            None,
            None,
        );
    }
    let titan = uuid_bytes(TITAN);
    let c = k.sql();
    c.execute(
        "INSERT INTO webauthn_credentials (credential_id, user_id, label, passkey, aaguid, transports, backup_eligible, backup_state, user_verified, attestation_format, attested, assurance, sign_count, created_at, last_used_at, state, revision) VALUES \
         (?1, 'u_f', 'Desk key', '{}', ?2, '[\"usb\"]', 0, 0, 1, 'packed', 1, 'aal3', 4, ?3, ?4, 'active', 1), \
         (?5, 'u_f', 'Phone', '{}', ?6, '[\"hybrid\",\"internal\"]', 1, 1, 1, 'none', 0, 'aal2', 0, ?3, NULL, 'active', 1)",
        rusqlite::params![vec![1u8; 32], titan.to_vec(), now - 3600, now - 120, vec![2u8; 32], vec![0u8; 16]],
    )
    .unwrap();
    c.execute(
        "INSERT INTO session_webauthn_elevations (session_id, credential_id, at) VALUES ('s_key', ?1, ?2)",
        rusqlite::params![vec![1u8; 32], now - 60],
    )
    .unwrap();
    c.execute(
        "UPDATE sessions SET aal=2, factors=?1 WHERE session_id='s_totp'",
        [format!(
            r#"[{{"kind":"oidc","provider":"mock","at":{0}}},{{"kind":"totp","at":{0}}}]"#,
            (now - 60) * 1000
        )],
    )
    .unwrap();
    c.execute(
        "INSERT INTO totp_enrollments (enrollment_id, user_id, envelope, revision, state, created_at, updated_at) VALUES ('t_f', 'u_f', 'x', 1, 'active', ?1, ?1)",
        [now - 3600],
    )
    .unwrap();
    for (i, used) in [(0, true), (1, false), (2, false)] {
        c.execute(
            "INSERT INTO recovery_codes (user_id, lookup, hash, batch, created_at, used_at) VALUES ('u_f', ?1, 'h', 'b1', ?2, ?3)",
            rusqlite::params![format!("LKUP{i}"), now - 3600, used.then_some(now - 600)],
        )
        .unwrap();
    }
    c.execute(
        "UPDATE users SET factor_recovery_required_at=?1 WHERE user_id='u_f'",
        [now - 600],
    )
    .unwrap();
}

fn uuid_bytes(s: &str) -> [u8; 16] {
    let hex: String = s.chars().filter(|c| *c != '-').collect();
    let mut out = [0u8; 16];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap();
    }
    out
}

fn live(k: &Console, s: &str) -> bool {
    k.count(&format!(
        "SELECT COUNT(*) FROM sessions WHERE session_id='{s}' AND terminated_at IS NULL"
    )) == 1
}

/// The `pk_` factor id of a passkey as the listing names it.
fn factor_id(list: &Value, label: &str) -> String {
    list["passkeys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["label"] == label)
        .unwrap_or_else(|| panic!("no passkey {label}: {list}"))["factor_id"]
        .as_str()
        .unwrap()
        .to_string()
}

// ---- 314: a user's factors ------------------------------------------------

#[test]
fn s314_1_factor_listing_names_authenticators_without_secrets() {
    let k = console(json!({}));
    seed_factors(&k);
    let viewer = k.admin("v314", AdminRole::Viewer);
    let r = k.client(&viewer).get("/v1/users/u_f/factors");
    assert_eq!(r.status, 200, "{r:?}");
    assert_eq!(r.header("cache-control"), Some("no-store"));
    let v = r.json();
    assert_eq!(v["user_id"], "u_f");
    assert_eq!(v["second_factors"], 3);
    assert_eq!(v["totp"]["active"], true);
    assert_eq!(v["recovery_codes"]["remaining"], 2);
    assert!(v["recovery_codes"]["reenrollment_required_at"].is_i64());
    let keys = v["passkeys"].as_array().unwrap();
    assert_eq!(keys.len(), 2);
    let desk = keys.iter().find(|p| p["label"] == "Desk key").unwrap();
    assert_eq!(desk["aaguid"], TITAN);
    assert_eq!(desk["authenticator"], "Google Titan Security Key");
    assert_eq!(desk["kind"], "device_bound");
    assert_eq!(desk["assurance"], "aal3");
    assert_eq!(desk["backup_state"], false);
    assert!(desk["last_used_at"].is_i64());
    assert_eq!(desk["transports"], json!(["usb"]));
    assert!(desk["factor_id"].as_str().unwrap().starts_with("pk_"));
    let phone = keys.iter().find(|p| p["label"] == "Phone").unwrap();
    assert_eq!(
        phone["aaguid"],
        Value::Null,
        "an all-zero AAGUID is not disclosed"
    );
    assert_eq!(phone["authenticator"], Value::Null);
    assert_eq!(phone["kind"], "synced");
    assert_eq!(phone["backup_state"], true);
    assert_eq!(phone["last_used_at"], Value::Null);
    // Never a credential id, a public key or a code hash.
    for secret in ["AQEBAQEB", "\"passkey\"", "\"hash\"", "credential_id"] {
        assert!(!r.body.contains(secret), "{secret} in {}", r.body);
    }
    let audit = last_attrs(&k, "admin.read");
    assert_eq!(audit["purpose"], "users.factors");
    assert_eq!(audit["actor"], viewer.user_id.as_str());
    // A malformed id and an unknown user.
    assert_eq!(
        code(&k.client(&viewer).get("/v1/users/x/factors")),
        "invalid_id"
    );
    let gone = k.client(&viewer).get("/v1/users/u_nobody/factors");
    assert_eq!((gone.status, code(&gone)), (404, "not_found".to_string()));
}

#[test]
fn s314_2_a_reset_removes_its_scope_and_the_sessions_that_factor_vouched_for() {
    let k = console(json!({}));
    seed_factors(&k);
    let admin = k.admin("a314", AdminRole::Admin);
    let viewer = k.admin("v314b", AdminRole::Viewer);
    let list = k.client(&admin).get("/v1/users/u_f/factors").json();
    let desk = factor_id(&list, "Desk key");
    let reset = |w: &Who, body: Value| k.client(w).post_json("/v1/users/u_f/factors/reset", body);
    // A viewer may look, not reset.
    let r = reset(&viewer, json!({"scope": "all"}));
    assert_eq!((r.status, code(&r)), (403, "role_insufficient".to_string()));
    // Malformed requests.
    for body in [
        json!({}),
        json!({"scope": "everything"}),
        json!({"scope": "passkey"}),
        json!({"scope": "passkey", "factor_id": "pk_123"}),
        json!({"scope": "all", "factor_id": desk}),
        json!({"scope": "all", "extra": 1}),
    ] {
        let r = reset(&admin, body.clone());
        assert_eq!(
            (r.status, code(&r)),
            (400, "invalid_request".to_string()),
            "{body}"
        );
    }
    let r = reset(&admin, json!({"scope": "all", "reason": "bad\u{202e}text"}));
    assert_eq!((r.status, code(&r)), (400, "invalid_reason".to_string()));
    let r = reset(
        &admin,
        json!({"scope": "passkey", "factor_id": "pk_0000000000000000"}),
    );
    assert_eq!((r.status, code(&r)), (404, "factor_not_found".to_string()));
    // One passkey: the session it elevated ends, the others stay.
    let r = reset(
        &admin,
        json!({"scope": "passkey", "factor_id": desk, "reason": "Key reported lost (ticket 4411)"}),
    );
    assert_eq!(r.status, 200, "{r:?}");
    let v = r.json();
    assert_eq!(
        (
            v["changed"].clone(),
            v["passkeys_revoked"].clone(),
            v["sessions_terminated"].clone()
        ),
        (json!(true), json!(1), json!(1))
    );
    assert!(!live(&k, "s_key") && live(&k, "s_totp") && live(&k, "s_plain"));
    let ev = last_attrs(&k, "admin.factor_reset");
    assert_eq!(ev["scope"], "passkey");
    assert_eq!(ev["factor_id"], desk.as_str());
    assert_eq!(ev["note"], "Key reported lost (ticket 4411)");
    assert_eq!(ev["actor"], admin.user_id.as_str());
    // The authenticator app: the session it elevated ends.
    let v = reset(&admin, json!({"scope": "totp"})).json();
    assert_eq!(
        (v["totp_revoked"].clone(), v["sessions_terminated"].clone()),
        (json!(1), json!(1))
    );
    assert!(!live(&k, "s_totp") && live(&k, "s_plain"));
    // Recovery codes: no session ends; a second reset changes nothing.
    let v = reset(&admin, json!({"scope": "recovery_codes"})).json();
    assert_eq!(
        (
            v["recovery_codes_removed"].clone(),
            v["sessions_terminated"].clone()
        ),
        (json!(2), json!(0))
    );
    let before = k.count("SELECT COUNT(*) FROM events WHERE kind='admin.factor_reset'");
    assert_eq!(
        reset(&admin, json!({"scope": "recovery_codes"})).json()["changed"],
        false
    );
    assert_eq!(
        k.count("SELECT COUNT(*) FROM events WHERE kind='admin.factor_reset'"),
        before
    );
    // Everything: every session ends, the re-enrollment flag clears.
    let v = reset(&admin, json!({"scope": "all"})).json();
    assert_eq!(v["passkeys_revoked"], 1);
    assert!(!live(&k, "s_plain"));
    let after = k.client(&admin).get("/v1/users/u_f/factors").json();
    assert_eq!(after["second_factors"], 0);
    assert_eq!(
        after["recovery_codes"]["reenrollment_required_at"],
        Value::Null
    );
    // One's own factors cannot be reset from the console.
    let own = k.client(&admin).post_json(
        &format!("/v1/users/{}/factors/reset", admin.user_id),
        json!({"scope": "all"}),
    );
    assert_eq!((own.status, code(&own)), (403, "self_target".to_string()));
    // The JSON API rule: without the request header the reset is refused.
    let raw = k.client(&admin).post_json_raw(
        "/v1/users/u_f/factors/reset",
        &[("content-type", "application/json")],
        br#"{"scope":"all"}"#,
    );
    assert_eq!((raw.status, code(&raw)), (403, "csrf_rejected".to_string()));
}

#[test]
fn s314_3_hangang_console_lists_and_resets_factors_with_its_actor_recorded() {
    let k = hangang_console();
    seed_factors(&k);
    let list = post(&k, "/v1/users/factors", json!({"id": "u_f"}), 1);
    assert_eq!(list.status, 200, "{list:?}");
    let desk = factor_id(&list.json(), "Desk key");
    let r = post(
        &k,
        "/v1/users/factors/reset",
        json!({"id": "u_f", "scope": "passkey", "factor_id": desk, "reason": "lost"}),
        2,
    );
    assert_eq!(r.status, 200, "{r:?}");
    assert_eq!(r.json()["sessions_terminated"], 1);
    let ev = last_attrs(&k, "admin.factor_reset");
    assert_eq!(ev["delegated_actor"], "7:operator");
    assert_eq!(ev["note"], "lost");
    // Replays, malformed ids and unknown fields are refused by the adapter.
    assert_eq!(
        post(
            &k,
            "/v1/users/factors/reset",
            json!({"id": "u_f", "scope": "all"}),
            2
        )
        .status,
        403
    );
    assert_eq!(
        post(&k, "/v1/users/factors", json!({"id": "x"}), 3).status,
        403
    );
    assert_eq!(
        post(&k, "/v1/users/factors", json!({"id": "u_f", "x": 1}), 4).status,
        403
    );
    assert_eq!(
        post(&k, "/v1/users/factors/reset", json!({"scope": "all"}), 5).status,
        403
    );
}

// ---- 315: listing filters, the user detail, the status facts ----------------

/// `u_a` (mock + corp, authenticator app, group member), `u_b` (mock,
/// synced passkey, disabled), `u_c` (mock only); sessions at AAL 1 and 2;
/// events of several kinds.
fn seed_people(k: &Console) {
    for (id, name) in [("u_a", "Ann"), ("u_b", "Ben"), ("u_c", "Cy")] {
        k.add_user(id, &format!("{}@example.test", name.to_lowercase()), name);
        k.add_identity(
            id,
            "mock",
            &format!("sub-{id}"),
            &format!("{}@example.test", name.to_lowercase()),
        );
    }
    k.add_identity("u_a", "corp", "corp-ann", "ann@corp.example.test");
    let now = k.now_s();
    let c = k.sql();
    c.execute("UPDATE users SET status='disabled' WHERE user_id='u_b'", [])
        .unwrap();
    c.execute(
        "INSERT INTO totp_enrollments (enrollment_id, user_id, envelope, revision, state, created_at, updated_at) VALUES ('t_a', 'u_a', 'x', 1, 'active', ?1, ?1)",
        [now],
    )
    .unwrap();
    c.execute(
        "INSERT INTO webauthn_credentials (credential_id, user_id, label, passkey, aaguid, transports, backup_eligible, backup_state, user_verified, attestation_format, attested, assurance, sign_count, created_at, state, revision) VALUES (?1, 'u_b', 'Phone', '{}', NULL, '[]', 1, 1, 1, 'none', 0, 'aal2', 0, ?2, 'active', 1)",
        rusqlite::params![vec![9u8; 32], now],
    )
    .unwrap();
    c.execute(
        "INSERT INTO directory_groups (group_id, source, provider_id, external_key, name, state, revision, created_at, updated_at) VALUES ('grp1:aaaaaaaaaaaaaaaaaaaaaaaaaa', 'local', NULL, 'eng', 'Eng', 'active', 1, ?1, ?1)",
        [now],
    )
    .unwrap();
    c.execute(
        "INSERT INTO group_members (group_id, user_id, source, provider_id, first_seen_at, last_seen_at) VALUES ('grp1:aaaaaaaaaaaaaaaaaaaaaaaaaa', 'u_a', 'local', NULL, ?1, ?1)",
        [now],
    )
    .unwrap();
    drop(c);
    k.add_session(
        "s_a1",
        "u_a",
        now - 300,
        CLIENT_IP,
        None,
        &["app.example.test"],
        None,
        None,
    );
    k.add_session(
        "s_a2",
        "u_a",
        now - 200,
        CLIENT_IP,
        None,
        &["app.example.test"],
        None,
        None,
    );
    k.add_session(
        "s_c1",
        "u_c",
        now - 100,
        CLIENT_IP,
        None,
        &["app.example.test"],
        None,
        None,
    );
    k.sql()
        .execute("UPDATE sessions SET aal=2 WHERE session_id='s_a2'", [])
        .unwrap();
    k.add_events(
        "f",
        3,
        "factor.webauthn_used",
        "success",
        Some("u_a"),
        None,
        None,
        now - 50,
    );
    k.add_events(
        "u",
        2,
        "admin.user_disable",
        "success",
        Some("u_b"),
        None,
        None,
        now - 40,
    );
    k.add_events(
        "l",
        2,
        "login.succeeded",
        "success",
        Some("u_a"),
        None,
        None,
        now - 1000,
    );
}

fn ids(r: &Response, key: &str) -> Vec<String> {
    assert_eq!(r.status, 200, "{r:?}");
    let mut v: Vec<String> = r.json()["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i[key].as_str().unwrap().to_string())
        .collect();
    v.sort();
    v.dedup();
    v
}

#[test]
fn s315_1_user_listing_filters_by_provider_factor_and_group() {
    let k = console(json!({}));
    let a = k.admin("a315", AdminRole::Viewer);
    seed_people(&k);
    let c = k.client(&a);
    assert_eq!(ids(&c.get("/v1/users?provider=corp"), "user_id"), ["u_a"]);
    assert_eq!(
        ids(&c.get("/v1/users?mfa=enrolled"), "user_id"),
        ["u_a", "u_b"]
    );
    let none = ids(&c.get("/v1/users?mfa=none&q=c"), "user_id");
    assert_eq!(none, ["u_c"]);
    assert_eq!(
        ids(
            &c.get("/v1/users?group=grp1:aaaaaaaaaaaaaaaaaaaaaaaaaa"),
            "user_id"
        ),
        ["u_a"]
    );
    assert_eq!(
        ids(&c.get("/v1/users?mfa=enrolled&status=disabled"), "user_id"),
        ["u_b"]
    );
    for bad in [
        "provider=Corp",
        "provider=hopae.passkey",
        "mfa=yes",
        "group=eng",
        "group=grp1:short",
    ] {
        let r = c.get(&format!("/v1/users?{bad}"));
        assert_eq!(
            (r.status, code(&r)),
            (400, "invalid_filter".to_string()),
            "{bad}"
        );
    }
    // The page keeps the filters in its next link.
    let page = c.get("/users?mfa=enrolled&limit=1");
    assert_eq!(page.status, 200);
    assert!(page.body.contains("mfa=enrolled"), "{}", page.body);
}

#[test]
fn s315_2_session_and_event_filters() {
    let k = console(json!({}));
    let a = k.admin("a315b", AdminRole::Viewer);
    seed_people(&k);
    let c = k.client(&a);
    assert_eq!(ids(&c.get("/v1/sessions?aal=2"), "session_id"), ["s_a2"]);
    let one = ids(&c.get("/v1/sessions?aal=1&user_id=u_a"), "session_id");
    assert_eq!(one, ["s_a1"]);
    for bad in ["aal=3", "aal=0", "aal=two"] {
        assert_eq!(
            code(&c.get(&format!("/v1/sessions?{bad}"))),
            "invalid_filter",
            "{bad}"
        );
    }
    let kinds = |q: &str| {
        let r = c.get(&format!("/v1/events?{q}"));
        assert_eq!(r.status, 200, "{r:?}");
        let mut v: Vec<String> = r.json()["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["kind"].as_str().unwrap().to_string())
            .collect();
        v.dedup();
        v
    };
    assert_eq!(
        kinds("kind_prefix=factor.&user_id=u_a"),
        ["factor.webauthn_used"]
    );
    assert_eq!(
        kinds("kind_prefix=admin.user_&user_id=u_b"),
        ["admin.user_disable"]
    );
    let now = k.now_s();
    assert_eq!(
        kinds(&format!(
            "user_id=u_a&since={}&until={}",
            now - 2000,
            now - 500
        )),
        ["login.succeeded"]
    );
    for bad in [
        "kind_prefix=Factor",
        "kind_prefix=a%20b",
        "since=10&until=5",
    ] {
        assert_eq!(
            code(&c.get(&format!("/v1/events?{bad}"))),
            "invalid_filter",
            "{bad}"
        );
    }
}

#[test]
fn s315_3_hangang_console_filters_listings_and_reads_the_user_detail() {
    let k = hangang_console();
    seed_people(&k);
    let r = post(
        &k,
        "/v1/users/query",
        json!({"provider": "corp", "limit": 10}),
        1,
    );
    assert_eq!(ids(&r, "user_id"), ["u_a"]);
    let r = post(
        &k,
        "/v1/users/query",
        json!({"mfa": "enrolled", "status": "disabled"}),
        2,
    );
    assert_eq!(ids(&r, "user_id"), ["u_b"]);
    let r = post(
        &k,
        "/v1/sessions/query",
        json!({"user_id": "u_a", "aal": 2}),
        3,
    );
    assert_eq!(ids(&r, "session_id"), ["s_a2"]);
    let r = post(
        &k,
        "/v1/events/query",
        json!({"user_id": "u_a", "kind_prefix": "factor."}),
        4,
    );
    assert_eq!(r.status, 200);
    assert_eq!(r.json()["items"].as_array().unwrap().len(), 3);
    // A value the native listing refuses is its 400; a field the adapter
    // does not know is a refusal.
    assert_eq!(
        post(&k, "/v1/users/query", json!({"mfa": "yes"}), 5).status,
        400
    );
    assert_eq!(
        post(&k, "/v1/users/query", json!({"role": "admin"}), 6).status,
        403
    );
    assert_eq!(
        post(&k, "/v1/sessions/query", json!({"provider": "corp"}), 7).status,
        403
    );
    assert_eq!(
        post(&k, "/v1/events/query", json!({"kind_prefix": ["x"]}), 8).status,
        403
    );
    // The user detail: linked identities with their provider subjects.
    let d = post(&k, "/v1/users/get", json!({"id": "u_a"}), 9);
    assert_eq!(d.status, 200, "{d:?}");
    let v = d.json();
    assert_eq!(v["user"]["user_id"], "u_a");
    let identities = v["identities"].as_array().unwrap();
    assert_eq!(identities.len(), 2);
    let corp = identities
        .iter()
        .find(|i| i["provider_id"] == "corp")
        .unwrap();
    assert_eq!(corp["subject"], "corp-ann");
    assert!(corp["first_seen_at"].is_i64() && corp["last_seen_at"].is_i64());
    assert!(!d.body.contains("secret_claim"), "raw claims never leave");
    assert_eq!(
        post(&k, "/v1/users/get", json!({"id": "u_nobody"}), 10).status,
        404
    );
    assert_eq!(
        post(&k, "/v1/users/get", json!({"id": "../x"}), 11).status,
        403
    );
}

#[test]
fn s315_4_status_reports_the_portal_and_the_console_authority() {
    let k = console(json!({}));
    let a = k.admin("a315d", AdminRole::Viewer);
    let v = k.client(&a).get("/v1/status").json();
    assert_eq!(
        v["portal"]["public_url"],
        k.h.config()["portal"]["public_url"]
    );
    assert_eq!(v["portal"]["passkeys"], false);
    assert_eq!(v["console"]["authority"]["mode"], "local");
    assert_eq!(v["console"]["authority"]["delegation"], "none");
    assert!(
        v["console"]["public_url"]
            .as_str()
            .unwrap()
            .starts_with("https://")
    );
    let h = hangang_console();
    let v = signed(&h, "GET", "/v1/status", "", 1).json();
    assert_eq!(v["console"]["authority"]["mode"], "hangang");
    assert_eq!(v["console"]["authority"]["delegation"], "hangang");
}

// ---- 316: reasons and the bulk disable --------------------------------------

#[test]
fn s316_1_mutation_reasons_are_recorded_as_the_note() {
    let k = console(json!({}));
    let a = k.admin("a316", AdminRole::Admin);
    seed_people(&k);
    let c = k.client(&a);
    let r = c.post_json(
        "/v1/users/u_c/disable",
        json!({"reason": "Left the company (HR-77)"}),
    );
    assert_eq!(r.status, 200, "{r:?}");
    assert_eq!(
        last_attrs(&k, "admin.user_disable")["note"],
        "Left the company (HR-77)"
    );
    let r = c.post_json("/v1/users/u_c/enable", json!({"reason": "  rehired  "}));
    assert_eq!(r.status, 200);
    assert_eq!(last_attrs(&k, "admin.user_enable")["note"], "rehired");
    let r = c.post_json(
        "/v1/sessions/s_a1/terminate",
        json!({"reason": "suspicious sign-in"}),
    );
    assert_eq!(r.status, 200);
    assert_eq!(
        last_attrs(&k, "admin.session_terminate")["note"],
        "suspicious sign-in"
    );
    let r = c.post_json("/v1/users/u_a/sessions/terminate", json!({}));
    assert_eq!(r.status, 200);
    assert!(
        last_attrs(&k, "admin.sessions_terminate")
            .get("note")
            .is_none()
    );
    // Too long, control or bidirectional characters, not a string.
    for reason in [
        json!("x".repeat(257)),
        json!("a\u{0007}b"),
        json!("a\u{202e}b"),
        json!(5),
    ] {
        let r = c.post_json("/v1/users/u_c/disable", json!({"reason": reason}));
        assert_eq!((r.status, code(&r)), (400, "invalid_reason".to_string()));
    }
    assert_eq!(
        k.count("SELECT COUNT(*) FROM users WHERE user_id='u_c' AND status='active'"),
        1
    );
    // A page form carries the reason too.
    let page = c.get("/users/u_c");
    let csrf = AdminClient::csrf_from_page(&page.body).expect("csrf");
    let origin = k.h.console_origin();
    let r = c.post_form(
        "/users/u_c/disable",
        &[("csrf", &csrf), ("reason", "form reason")],
        Some(&origin),
    );
    assert_eq!(r.status, 303, "{r:?}");
    assert_eq!(last_attrs(&k, "admin.user_disable")["note"], "form reason");
    // Through the Hangang adapter.
    let h = hangang_console();
    seed_people(&h);
    let r = post(
        &h,
        "/v1/users/disable",
        json!({"id": "u_c", "reason": "via Hangang"}),
        1,
    );
    assert_eq!(r.status, 200, "{r:?}");
    let ev = last_attrs(&h, "admin.user_disable");
    assert_eq!(
        (ev["note"].clone(), ev["delegated_actor"].clone()),
        (json!("via Hangang"), json!("7:operator"))
    );
    let r = post(
        &h,
        "/v1/sessions/terminate",
        json!({"id": "s_a1", "reason": "r"}),
        2,
    );
    assert_eq!(r.status, 200);
    assert_eq!(
        post(&h, "/v1/users/enable", json!({"id": "u_c", "why": "x"}), 3).status,
        403
    );
}

#[test]
fn s316_2_bulk_disable_answers_per_item_and_records_each_change() {
    let k = console(json!({}));
    let a = k.admin("a316b", AdminRole::Admin);
    let v = k.admin("v316b", AdminRole::Viewer);
    seed_people(&k);
    let c = k.client(&a);
    let body = json!({
        "ids": ["u_a", "u_b", "u_nobody", "bad id", a.user_id, "u_c"],
        "reason": "Offboarding batch 12"
    });
    let r = k
        .client(&v)
        .post_json("/v1/users/bulk/disable", body.clone());
    assert_eq!((r.status, code(&r)), (403, "role_insufficient".to_string()));
    let r = c.post_json("/v1/users/bulk/disable", body);
    assert_eq!(r.status, 200, "{r:?}");
    let out = r.json();
    let results: Vec<(String, String)> = out["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| {
            (
                i["result"].as_str().unwrap().to_string(),
                i["error"].as_str().unwrap_or_default().to_string(),
            )
        })
        .collect();
    let s = |a: &str, b: &str| (a.to_string(), b.to_string());
    assert_eq!(
        results,
        [
            s("disabled", ""),
            s("unchanged", ""),
            s("error", "not_found"),
            s("error", "invalid_id"),
            s("error", "self_target"),
            s("disabled", "")
        ]
    );
    assert_eq!(
        (out["disabled"].clone(), out["failed"].clone()),
        (json!(2), json!(3))
    );
    assert_eq!(out["items"][0]["sessions_terminated"], 2);
    let op = out["bulk_operation"].as_str().unwrap().to_string();
    let n = k.count(&format!(
        "SELECT COUNT(*) FROM events WHERE kind='admin.user_disable' AND json_extract(attrs,'$.bulk_operation')='{op}' AND json_extract(attrs,'$.note')='Offboarding batch 12'"
    ));
    assert_eq!(n, 2);
    assert_eq!(
        k.count(
            "SELECT COUNT(*) FROM users WHERE status='disabled' AND user_id IN ('u_a','u_b','u_c')"
        ),
        3
    );
    // Bounds and shape.
    let many: Vec<String> = (0..101).map(|i| format!("u_bulk{i}")).collect();
    for bad in [
        json!({"ids": []}),
        json!({"ids": many}),
        json!({"ids": ["u_a", "u_a"]}),
        json!({"ids": "u_a"}),
    ] {
        let r = c.post_json("/v1/users/bulk/disable", bad.clone());
        assert_eq!(r.status, 400, "{bad}");
    }
    // Through the Hangang adapter.
    let h = hangang_console();
    seed_people(&h);
    let r = post(
        &h,
        "/v1/users/bulk-disable",
        json!({"ids": ["u_a", "u_c"]}),
        1,
    );
    assert_eq!(r.status, 200, "{r:?}");
    assert_eq!(r.json()["disabled"], 2);
}

// ---- 317: publication audit and the dry-run validation ----------------------

fn gateway_overrides() -> Value {
    json!({
        "authentication_gateway": {"authority_id": "owned", "profiles": [{
            "service_id": "app", "host": "app.example.test", "ports": [443], "realm": "owned",
            "session_fallback": true, "api_keys": [{"token_env": SERVICE_ENV, "subject": "worker"}]
        }]}
    })
}

#[test]
fn s317_1_publications_are_recorded_with_their_reason() {
    let k = console(gateway_overrides());
    let a = k.admin("a317", AdminRole::Admin);
    let c = k.client(&a);
    let current = c.get("/v1/authentication/profiles");
    assert_eq!(current.status, 200, "{current:?}");
    let revision = current.json()["revision"].as_u64().unwrap();
    let body = json!({"configuration": null, "reason": "Maintenance window CHG-9"});
    let r = c.put_json_raw(
        "/v1/authentication/profiles",
        &[
            ("content-type", "application/json"),
            ("x-hopae-admin-request", "1"),
            ("if-match", &format!("\"{revision}\"")),
        ],
        body.to_string().as_bytes(),
    );
    assert_eq!(r.status, 200, "{r:?}");
    let ev = last_attrs(&k, "admin.profiles_publish");
    assert_eq!(ev["note"], "Maintenance window CHG-9");
    assert_eq!(ev["revision"], revision + 1);
    assert_eq!(ev["status"], "disabled");
    assert_eq!(ev["actor"], a.user_id.as_str());
    // A conflicting publication records nothing.
    let n = k.count("SELECT COUNT(*) FROM events WHERE kind='admin.profiles_publish'");
    let stale = c.put_json_raw(
        "/v1/authentication/profiles",
        &[
            ("content-type", "application/json"),
            ("x-hopae-admin-request", "1"),
            ("if-match", &format!("\"{revision}\"")),
        ],
        body.to_string().as_bytes(),
    );
    assert_eq!(stale.status, 409);
    assert_eq!(
        k.count("SELECT COUNT(*) FROM events WHERE kind='admin.profiles_publish'"),
        n
    );
    // A bad reason refuses the publication.
    let bad = c.put_json_raw(
        "/v1/authentication/profiles",
        &[
            ("content-type", "application/json"),
            ("x-hopae-admin-request", "1"),
            ("if-match", &format!("\"{}\"", revision + 1)),
        ],
        json!({"configuration": null, "reason": "a\u{0000}b"})
            .to_string()
            .as_bytes(),
    );
    assert_eq!(
        (bad.status, code(&bad)),
        (400, "invalid_reason".to_string())
    );
    // Projection plans, through the Hangang adapter.
    let mut over = gateway_overrides();
    over["admin"] =
        json!({"hangang_delegation": {"key_env": DELEGATION_ENV, "authority": "hangang"}});
    over["credential_projection"] = json!({"revision": 1, "plans": [{"service": "app", "audience": "app-api", "resource": "app", "action": "read", "minimum_aal": 1, "credential": {"type": "identity_header"}}]});
    let h = console(over);
    let r = post(
        &h,
        "/v1/authentication/projections/publish",
        json!({"revision": 1, "configuration": null, "reason": "retire plans"}),
        1,
    );
    assert_eq!(r.status, 200, "{r:?}");
    let ev = last_attrs(&h, "admin.projections_publish");
    assert_eq!(
        (ev["note"].clone(), ev["delegated_actor"].clone()),
        (json!("retire plans"), json!("7:operator"))
    );
    let r = post(
        &h,
        "/v1/authentication/profiles/publish",
        json!({"revision": 1, "configuration": null, "reason": "off"}),
        2,
    );
    assert_eq!(r.status, 200, "{r:?}");
    assert_eq!(last_attrs(&h, "admin.profiles_publish")["note"], "off");
}

#[test]
fn s317_2_profile_validation_reports_paths_without_publishing() {
    let k = console(gateway_overrides());
    let a = k.admin("a317b", AdminRole::Viewer);
    let c = k.client(&a);
    let before = c.get("/v1/authentication/profiles").json()["revision"].clone();
    let validate = |configuration: Value| {
        let r = c.post_json(
            "/v1/authentication/profiles/validate",
            json!({"configuration": configuration}),
        );
        assert_eq!(r.status, 200, "{r:?}");
        r.json()
    };
    let good = json!({"authority_id": "owned", "profiles": [{
        "service_id": "app", "host": "app.example.test", "ports": [443], "realm": "owned", "session_fallback": true,
        "api_keys": [{"token_env": SERVICE_ENV, "subject": "worker"}]
    }]});
    let v = validate(good.clone());
    assert_eq!(
        (v["valid"].clone(), v["errors"].clone()),
        (json!(true), json!([])),
        "{v}"
    );
    assert_eq!(
        validate(Value::Null)["valid"],
        true,
        "null disables the gateway"
    );
    // The document's shape: the path of the first mismatch.
    let mut wrong = good.clone();
    wrong["profiles"][0]["ports"] = json!([443, "https"]);
    let v = validate(wrong);
    assert_eq!(v["valid"], false);
    assert_eq!(v["errors"][0]["path"], "profiles[0].ports[1]");
    assert_eq!(v["errors"][0]["code"], "invalid_document");
    let mut unknown = good.clone();
    unknown["profiles"][0]["colour"] = json!("blue");
    assert_eq!(validate(unknown)["errors"][0]["path"], "profiles[0].colour");
    // An API key variable the file does not declare.
    let mut keyed = good.clone();
    keyed["profiles"][0]["api_keys"] = json!([{"token_env": "NOT_DECLARED", "subject": "worker"}]);
    let v = validate(keyed);
    let codes: Vec<(String, String)> = v["errors"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| {
            (
                e["path"].as_str().unwrap().into(),
                e["code"].as_str().unwrap().into(),
            )
        })
        .collect();
    assert!(
        codes.contains(&(
            "profiles[0].api_keys[0].token_env".into(),
            "undeclared_reference".into()
        )),
        "{v}"
    );
    // A profile for a host no application serves, as the second profile.
    let mut stray = good.clone();
    stray["profiles"]
        .as_array_mut()
        .unwrap()
        .push(json!({"service_id": "app", "host": "elsewhere.example.test", "ports": [443], "realm": "owned",
            "api_keys": [{"token_env": SERVICE_ENV, "subject": "worker2"}]}));
    let v = validate(stray);
    assert_eq!(v["valid"], false);
    assert!(
        v["errors"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["path"] == "profiles[1]"),
        "{v}"
    );
    // Nothing was published, every check was audited, the rule applies.
    assert_eq!(
        c.get("/v1/authentication/profiles").json()["revision"],
        before
    );
    assert_eq!(last_attrs(&k, "admin.read")["purpose"], "profiles.validate");
    let raw = c.post_json_raw(
        "/v1/authentication/profiles/validate",
        &[("content-type", "application/json")],
        br#"{"configuration":null}"#,
    );
    assert_eq!(raw.status, 403);
    assert_eq!(
        c.post_json("/v1/authentication/profiles/validate", json!({"x": 1}))
            .status,
        400
    );
    // Through the Hangang adapter.
    let mut over = gateway_overrides();
    over["admin"] =
        json!({"hangang_delegation": {"key_env": DELEGATION_ENV, "authority": "hangang"}});
    let h = console(over);
    let r = post(
        &h,
        "/v1/authentication/profiles/validate",
        json!({"configuration": good}),
        1,
    );
    assert_eq!(r.status, 200, "{r:?}");
    assert_eq!(r.json()["valid"], true);
}
