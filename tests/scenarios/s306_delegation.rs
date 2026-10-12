//! Real Hopae provider login, native grant/fence and signed Hangang actor.
use super::s300_admin_access::kit;
use crate::support::{Fixture, Hopae, MockIdp, RawReq, client::send};
use hopae::admin::delegation_wire::{Assertion, digest, sign};
use serde_json::json;
use std::{
    os::unix::fs::PermissionsExt,
    time::{SystemTime, UNIX_EPOCH},
};
const KEY: &str = "fixture-delegation-key-32-bytes-minimum";
fn signed(
    h: &Hopae,
    path: &str,
    body: &str,
    name: &str,
    id: i64,
    nonce: u128,
) -> crate::support::Response {
    let method = if body.is_empty() { "GET" } else { "POST" };
    let assertion = Assertion {
        actor_id: id,
        actor_name: name.into(),
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        nonce: format!("{nonce:032x}"),
        method: method.into(),
        path: path.into(),
        body_sha256: digest(body.as_bytes()),
        handle_sha256: digest(b""),
        client_ip: kit::UA_IP.into(),
        user_agent: None,
    };
    let (a, m) = sign(&assertion, KEY.as_bytes()).unwrap();
    let mut request = RawReq::new(method, path, &h.console_host())
        .header("x-hopae-delegation", &a)
        .header("x-hopae-delegation-mac", &m)
        .header("content-type", "application/json");
    request.body = body.as_bytes().to_vec();
    send(h.admin.unwrap(), request)
}
#[test]
fn delegated_console_keeps_native_grants_and_signed_actor_audit() {
    let dir = tempfile::tempdir().unwrap();
    let mappings = dir.path().join("delegated-sessions.json");
    std::fs::write(&mappings, "[]").unwrap();
    std::fs::set_permissions(&mappings, std::fs::Permissions::from_mode(0o600)).unwrap();
    let idp = MockIdp::start("auth_time_present");
    let fixture = Fixture::with(
        "m4-admin",
        json!({"admin":{"hangang_delegation":{"key_env":"HOPAE_TEST_DELEGATION_KEY","sessions_file":mappings}}}),
    );
    let h = Hopae::spawn(fixture, &idp, &[("HOPAE_TEST_DELEGATION_KEY", KEY)]);
    let actor = kit::login_on(
        &h,
        &idp,
        &h.console_host(),
        "/",
        "operator",
        "operator@example.test",
        "Operator",
        kit::UA_IP,
    );
    kit::grant(&h, &actor.user_id, "admin");
    let target = kit::login_on(
        &h,
        &idp,
        kit::APP_HOST,
        "/",
        "target",
        "target@example.test",
        "Target",
        kit::UA_IP,
    );
    let data = json!([{"actor_id":7,"actor_name":"operator","user_id":actor.user_id,"handle":actor.handle,"client_ip":kit::UA_IP}]);
    std::fs::write(&mappings, data.to_string()).unwrap();
    assert_eq!(signed(&h, "/v1/users", "", "operator", 7, 1).status, 200);
    assert_eq!(
        signed(&h, "/v1/users/query", r#"{"limit":1}"#, "operator", 7, 10).status,
        200
    );
    assert_eq!(signed(&h, "/v1/users", "", "intruder", 7, 2).status, 403);
    let body = json!({"id":target.user_id}).to_string();
    assert_eq!(
        signed(&h, "/v1/users/disable", &body, "operator", 7, 3).status,
        200
    );
    assert_eq!(
        signed(&h, "/v1/users/disable", &body, "operator", 7, 3).status,
        403
    );
    // Existing self-target guard survives the delegation adapter.
    assert_eq!(
        signed(
            &h,
            "/v1/users/disable",
            &json!({"id":actor.user_id}).to_string(),
            "operator",
            7,
            4
        )
        .status,
        403
    );
    let events = signed(&h, "/v1/events", "", "operator", 7, 5);
    assert_eq!(events.status, 200);
    assert!(events.body.contains("delegated_actor"));
    assert!(events.body.contains("7:operator"));
    assert!(!events.body.contains(&actor.handle));
    // Revoke native Hopae grant; Hangang's role alone cannot override it.
    kit::revoke(&h, &actor.user_id);
    assert_eq!(signed(&h, "/v1/users", "", "operator", 7, 6).status, 403);
}

#[test]
fn browser_handle_requires_both_signed_actor_and_native_hopae_grant() {
    let idp = MockIdp::start("auth_time_present");
    let h = Hopae::spawn(
        Fixture::with(
            "m4-admin",
            json!({"admin":{"hangang_delegation":{"key_env":"HOPAE_TEST_DELEGATION_KEY"}}}),
        ),
        &idp,
        &[("HOPAE_TEST_DELEGATION_KEY", KEY)],
    );
    let actor = kit::login_on(
        &h,
        &idp,
        &h.console_host(),
        "/",
        "operator",
        "operator@example.test",
        "Operator",
        kit::UA_IP,
    );
    kit::grant(&h, &actor.user_id, "admin");
    let make = |handle: &str, body: &str, nonce: u128| {
        let assertion = Assertion {
            actor_id: 7,
            actor_name: "operator".into(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            nonce: format!("{nonce:032x}"),
            method: "POST".into(),
            path: "/v1/users/query".into(),
            body_sha256: digest(body.as_bytes()),
            handle_sha256: digest(actor.handle.as_bytes()),
            client_ip: kit::UA_IP.into(),
            user_agent: None,
        };
        let (a, m) = sign(&assertion, KEY.as_bytes()).unwrap();
        let mut request = RawReq::new("POST", "/v1/users/query", &h.console_host())
            .header("x-hopae-delegation", &a)
            .header("x-hopae-delegation-mac", &m)
            .header("x-hopae-delegated-handle", handle);
        request.body = body.as_bytes().to_vec();
        send(h.admin.unwrap(), request)
    };
    assert_eq!(make(&actor.handle, r#"{"limit":1}"#, 101).status, 200);
    assert_eq!(make("wrong", r#"{"limit":1}"#, 102).status, 403);
    assert_eq!(
        make(&actor.handle, r#"{"limit":1,"unexpected":true}"#, 103).status,
        403
    );
    kit::revoke(&h, &actor.user_id);
    assert_eq!(make(&actor.handle, r#"{"limit":1}"#, 104).status, 403);
}
