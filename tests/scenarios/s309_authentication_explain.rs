//! Scenario 309: the authentication explain API (ADR-0019, ADR-0020).
//!
//! The tests drive the real binary: each simulated request is explained over
//! the admin listener first and then sent to the live verify endpoint with
//! the session's real handle, so the two answers are compared on the same
//! state.
#![allow(dead_code)]

use serde_json::{Value, json};

use super::s301_admin_users::kit::{CLIENT_IP, Console, Who, code};
use super::s307_subject_directory::dkit::{self, API_HOST, console, reads, service_ref};
use crate::support::*;
use hopae::store::types::AdminRole;

const APP: &str = "https://app.example.test";

fn explain(k: &Console, w: &Who, body: Value) -> Response {
    k.client(w).post_json("/v1/explain/authentication", body)
}

fn ok(r: &Response) -> Value {
    assert_eq!(r.status, 200, "{r:?}");
    r.json()
}

/// One explained-then-verified request.
struct Case {
    name: &'static str,
    url: String,
    session: &'static str,
    handle: String,
    ip: &'static str,
    document: bool,
    outcome: &'static str,
    code: &'static str,
}

fn run(k: &Console, a: &Who, c: &Case) {
    let e = ok(&explain(
        k,
        a,
        json!({
            "url": c.url,
            "session_id": c.session,
            "client_ip": c.ip,
            "navigation": if c.document { "document" } else { "other" },
        }),
    ));
    assert_eq!(e["outcome"], c.outcome, "{}: {e}", c.name);
    assert_eq!(
        e["reason"]["code"],
        format!("hopae.{}", c.code),
        "{}",
        c.name
    );
    let req = if c.document {
        VerifyRequest::document(&c.url)
    } else {
        VerifyRequest::other(&c.url)
    }
    .ip(c.ip)
    .cookie(&k.h.cookie_name(), &c.handle);
    let live = k.h.verify(req);
    assert_eq!(
        e["status_code"].as_u64(),
        Some(u64::from(live.status)),
        "{}: explain {e} vs live {live:?}",
        c.name
    );
}

#[test]
fn s309_1_explain_matches_live_verify_for_session_states() {
    let k = console(json!({}), &[]);
    let a = k.admin("ha309a", AdminRole::Viewer);
    let now = k.now_s();
    let host = ["app.example.test"];
    let add = |id: &'static str, user: &str, created: i64, terminated: Option<(i64, &str)>| {
        k.add_session(id, user, created, CLIENT_IP, None, &host, terminated, None)
            .remove(0)
    };
    k.add_user("u_p", "p@example.test", "P");
    k.add_user("u_d", "d@example.test", "D");
    let live = add("s_live", "u_p", now - 60, None);
    let old = add("s_old", "u_p", now - 3600, None);
    let idle = add("s_idle", "u_p", now - 13 * 3600, None);
    let term = add("s_term", "u_p", now - 60, Some((now - 30, "logout")));
    let bind = add("s_bind", "u_p", now - 60, None);
    let off = add("s_off", "u_d", now - 60, None);
    k.sql()
        .execute("UPDATE users SET status='disabled' WHERE user_id='u_d'", [])
        .unwrap();
    let case = |name, url: &str, session, handle: &String, ip, document, outcome, code| Case {
        name,
        url: format!("{APP}{url}"),
        session,
        handle: handle.clone(),
        ip,
        document,
        outcome,
        code,
    };
    for c in [
        case(
            "allow", "/x", "s_live", &live, CLIENT_IP, true, "allow", "allowed",
        ),
        case(
            "allow fetch",
            "/x",
            "s_live",
            &live,
            CLIENT_IP,
            false,
            "allow",
            "allowed",
        ),
        case(
            "aal2 rule, no factor configured",
            "/admin/x",
            "s_live",
            &live,
            CLIENT_IP,
            true,
            "deny",
            "step_up_unavailable",
        ),
        case(
            "aal2 rule, fetch",
            "/admin/x",
            "s_live",
            &live,
            CLIENT_IP,
            false,
            "login",
            "step_up_required",
        ),
        case(
            "fresh enough",
            "/fresh",
            "s_live",
            &live,
            CLIENT_IP,
            true,
            "allow",
            "allowed",
        ),
        case(
            "too old",
            "/fresh/x",
            "s_old",
            &old,
            CLIENT_IP,
            true,
            "reauth",
            "reauth_required",
        ),
        case(
            "too old, fetch",
            "/fresh/x",
            "s_old",
            &old,
            CLIENT_IP,
            false,
            "login",
            "step_up_required",
        ),
        case(
            "idle handle",
            "/x",
            "s_idle",
            &idle,
            CLIENT_IP,
            true,
            "login",
            "idle",
        ),
        case(
            "terminated",
            "/x",
            "s_term",
            &term,
            CLIENT_IP,
            true,
            "login",
            "session_terminated",
        ),
        case(
            "ip binding",
            "/x",
            "s_bind",
            &bind,
            "198.51.100.1",
            true,
            "login",
            "binding_ip",
        ),
        case(
            "disabled user",
            "/x",
            "s_off",
            &off,
            CLIENT_IP,
            true,
            "login",
            "user_disabled",
        ),
        case(
            "reserved path",
            "/_hopae/other",
            "s_live",
            &live,
            CLIENT_IP,
            true,
            "deny",
            "reserved_path",
        ),
    ] {
        run(&k, &a, &c);
    }
    // Unknown application and port: the same refusal as the live check.
    for (url, reason) in [
        ("https://nope.example.test/", "unknown_app"),
        ("https://app.example.test:8443/", "port_not_allowed"),
    ] {
        let e = ok(&explain(
            &k,
            &a,
            json!({"url": url, "session_id": "s_live"}),
        ));
        assert_eq!(e["outcome"], "deny");
        assert_eq!(e["reason"]["code"], format!("hopae.{reason}"));
        let live_r = k.h.verify(
            VerifyRequest::document(url)
                .ip(CLIENT_IP)
                .cookie(&k.h.cookie_name(), &live),
        );
        assert_eq!(e["status_code"].as_u64(), Some(u64::from(live_r.status)));
    }
}

#[test]
fn s309_2_anonymous_and_hypothetical_subjects_explain_requirements() {
    let k = console(json!({}), &[]);
    let a = k.admin("ha309b", AdminRole::Admin);
    k.add_user("u_h", "h@example.test", "Hana");
    k.add_identity("u_h", "mock", "sub-h", "h@example.test");
    k.add_user("u_off", "off@example.test", "Off");
    k.sql()
        .execute(
            "UPDATE users SET status='disabled' WHERE user_id='u_off'",
            [],
        )
        .unwrap();
    let e = ok(&explain(&k, &a, json!({"url": format!("{APP}/admin/x")})));
    assert_eq!(e["outcome"], "login");
    assert_eq!(e["status_code"], 302);
    assert_eq!(e["reason"]["code"], "hopae.login_required");
    assert_eq!(e["subject"]["input"], "anonymous");
    assert_eq!(e["application"]["app_id"], "app");
    assert_eq!(e["assurance"]["required_aal"], 2);
    assert_eq!(e["assurance"]["achievable_aal"], 1);
    assert_eq!(e["providers"][0]["provider_id"], "mock");
    assert_eq!(e["providers"][0]["enabled"], true);
    let after = &e["after_login"];
    assert_eq!(after["basis"], "sign_in");
    assert_eq!(after["outcome"], "deny");
    assert_eq!(after["reason"]["code"], "hopae.step_up_unavailable");
    assert_eq!(after["step_up"]["deciding_rule"], 0);
    assert_eq!(after["step_up"]["matched_rules"], json!([0]));
    // A hypothetical AAL 2 sign-in with a second factor satisfies the rule.
    let e = ok(&explain(
        &k,
        &a,
        json!({"url": format!("{APP}/admin/x"), "subject": "u_h",
               "hypothetical": {"aal": 2, "factors": ["totp"]}}),
    ));
    assert_eq!(e["after_login"]["outcome"], "allow");
    assert_eq!(e["subject"]["item"]["display_name"], "Hana");
    assert_eq!(e["subject"]["item"]["email"], "h***@example.test");
    assert_eq!(e["providers"][0]["linked"], true);
    assert_eq!(e["after_login"]["session"]["provider_id"], "mock");
    assert_eq!(e["after_login"]["session"]["hypothetical"], true);
    // A sign-in older than the /fresh bound needs a new sign-in.
    let e = ok(&explain(
        &k,
        &a,
        json!({"url": format!("{APP}/fresh"), "subject": "u_h",
               "hypothetical": {"auth_age_seconds": 900}}),
    ));
    assert_eq!(e["after_login"]["outcome"], "reauth");
    assert_eq!(
        e["after_login"]["step_up"]["verdict"]["required"]["max_age_seconds"],
        600
    );
    // A disabled, an unknown and an unconfigured Human subject.
    let e = ok(&explain(
        &k,
        &a,
        json!({"url": format!("{APP}/x"), "subject": "u_off"}),
    ));
    assert_eq!(e["after_login"]["outcome"], "deny");
    assert_eq!(e["after_login"]["reason"]["code"], "hopae.user_disabled");
    for subject in ["u_never".to_string(), format!("human1:{}", "b".repeat(64))] {
        let e = ok(&explain(
            &k,
            &a,
            json!({"url": format!("{APP}/x"), "subject": subject}),
        ));
        assert_eq!(e["after_login"]["outcome"], "indeterminate");
        assert_eq!(e["after_login"]["reason"]["code"], "hopae.subject_unknown");
        assert_eq!(e["subject"]["item"]["status"], "unknown");
    }
    // A session without a handle on the host is handed over by the portal.
    let now = k.now_s();
    k.add_session(
        "s_portal",
        "u_h",
        now - 60,
        CLIENT_IP,
        None,
        &["auth.example.test"],
        None,
        None,
    );
    let e = ok(&explain(
        &k,
        &a,
        json!({"url": format!("{APP}/x"), "session_id": "s_portal", "client_ip": CLIENT_IP}),
    ));
    assert_eq!(e["outcome"], "login");
    assert_eq!(e["reason"]["code"], "hopae.handle_absent");
    assert_eq!(e["after_login"]["basis"], "handoff");
    assert_eq!(e["after_login"]["outcome"], "allow");
    // An explained time in the past or future within the bound.
    let e = ok(&explain(
        &k,
        &a,
        json!({"url": format!("{APP}/x"), "at": now + 86_400}),
    ));
    assert_eq!(e["evaluated_at"], now + 86_400);
}

#[test]
fn s309_3_explain_changes_no_state() {
    let k = console(json!({}), &[]);
    let a = k.admin("ha309c", AdminRole::Admin);
    let now = k.now_s();
    k.add_user("u_q", "q@example.test", "Q");
    k.add_session(
        "s_q",
        "u_q",
        now - 13 * 3600,
        CLIENT_IP,
        None,
        &["app.example.test"],
        None,
        None,
    );
    k.add_session(
        "s_r",
        "u_q",
        now - 60,
        CLIENT_IP,
        None,
        &["app.example.test"],
        None,
        None,
    );
    let snapshot = |k: &Console| {
        (
            k.count_text(
                "SELECT group_concat(session_id||':'||coalesce(terminated_at,'-')||':'||last_seen_at||':'||cred_gen, ',') FROM (SELECT * FROM sessions WHERE user_id='u_q' ORDER BY session_id)",
            ),
            k.count_text(
                "SELECT group_concat(hex(handle_sha256)||':'||coalesce(revoked_at,'-')||':'||last_seen_at, ',') FROM (SELECT * FROM session_handles WHERE session_id IN ('s_q','s_r') ORDER BY handle_sha256)",
            ),
            k.count("SELECT COUNT(*) FROM login_txns"),
            k.count("SELECT COUNT(*) FROM handoff_codes"),
            k.count("SELECT COUNT(*) FROM events WHERE kind <> 'admin.read' AND user_id = 'u_q'"),
        )
    };
    let before = snapshot(&k);
    for body in [
        json!({"url": format!("{APP}/x"), "session_id": "s_q", "client_ip": CLIENT_IP}),
        json!({"url": format!("{APP}/x"), "session_id": "s_r", "client_ip": "198.51.100.9"}),
        json!({"url": format!("{APP}/fresh"), "session_id": "s_r"}),
        json!({"url": format!("{APP}/admin"), "subject": "u_q"}),
    ] {
        let e = ok(&explain(&k, &a, body));
        assert_eq!(e["simulated"], true);
    }
    assert_eq!(snapshot(&k), before);
    assert_eq!(reads(&k).len(), 4);
    // The idle handle the simulation found expired is still not revoked.
    assert_eq!(
        k.count(
            "SELECT COUNT(*) FROM session_handles WHERE session_id='s_q' AND revoked_at IS NULL"
        ),
        1
    );
}

#[test]
fn s309_4_service_profiles_are_explained_with_live_predicates() {
    let k = console(json!({}), &[]);
    let a = k.admin("ha309d", AdminRole::Viewer);
    let worker = service_ref("worker");
    let retired = service_ref("retired");
    let stranger = format!("s_{}", "1".repeat(48));
    let url = format!("https://{API_HOST}/x");
    type Row<'a> = (&'a str, &'a str, &'a str, &'a str, &'a str, Option<&'a str>);
    let cases: Vec<Row<'_>> = vec![
        // (subject, path, ip, outcome, reason, live bearer)
        (
            &worker,
            "/x",
            CLIENT_IP,
            "allow",
            "allowed",
            Some(dkit::KEY),
        ),
        (
            &worker,
            "/x",
            "198.51.100.1",
            "deny",
            "network_denied",
            Some(dkit::KEY),
        ),
        (
            &retired,
            "/x",
            CLIENT_IP,
            "deny",
            "credential_expired",
            Some(dkit::OLD_KEY),
        ),
        (
            &worker,
            "/admin",
            CLIENT_IP,
            "deny",
            "machine_step_up",
            Some(dkit::KEY),
        ),
        (
            &stranger,
            "/x",
            CLIENT_IP,
            "deny",
            "service_principal_unknown",
            Some("unknown-credential-material-0123456789"),
        ),
        (
            "u_nobody",
            "/x",
            CLIENT_IP,
            "deny",
            "service_credential_required",
            None,
        ),
    ];
    for (subject, path, ip, outcome, reason, bearer) in cases {
        let target = format!("https://{API_HOST}{path}");
        let e = ok(&explain(
            &k,
            &a,
            json!({"url": target, "subject": subject, "client_ip": ip, "navigation": "other"}),
        ));
        assert_eq!(e["outcome"], outcome, "{subject} {path} {ip}: {e}");
        assert_eq!(e["reason"]["code"], format!("hopae.{reason}"));
        assert_eq!(e["service_profile"]["service_id"], "api");
        assert_eq!(e["service_profile"]["connectors"], json!(["api_key"]));
        let mut req = VerifyRequest::other(&target).ip(ip);
        if let Some(b) = bearer {
            req = req.header("authorization", &format!("Bearer {b}"));
        }
        let live = k.h.verify(req);
        assert_eq!(
            e["status_code"].as_u64(),
            Some(u64::from(live.status)),
            "{subject} {path}: explain {e} vs live {live:?}"
        );
    }
    let e = ok(&explain(&k, &a, json!({"url": url, "subject": worker})));
    assert_eq!(e["assurance"]["current_aal"], 0);
    assert_eq!(e["assurance"]["achievable_aal"], 0);
    assert!(
        e["trace"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s["reason"]["code"] == "hopae.network_not_evaluated")
    );
    // A service credential on a host without a profile.
    let e = ok(&explain(
        &k,
        &a,
        json!({"url": format!("{APP}/x"), "subject": worker}),
    ));
    assert_eq!(e["reason"]["code"], "hopae.service_profile_absent");
    assert_eq!(e["status_code"], 401);
    let text = e.to_string();
    for secret in [dkit::KEY, dkit::OLD_KEY, dkit::KEY_ENV] {
        assert!(!text.contains(secret));
    }
}

#[test]
fn s309_5_reasons_carry_stable_codes_and_localized_messages() {
    let k = console(json!({}), &[]);
    let a = k.admin("ha309e", AdminRole::Admin);
    let body = json!({"url": format!("{APP}/admin")});
    let en = ok(&explain(&k, &a, body.clone()));
    let ko = ok(&k
        .client(&a)
        .lang("ko-KR,ko;q=0.9")
        .post_json("/v1/explain/authentication", body));
    for j in [&en, &ko] {
        assert_eq!(
            j["after_login"]["reason"]["code"],
            "hopae.step_up_unavailable"
        );
        assert_eq!(
            j["after_login"]["reason"]["message_key"],
            "hopae.explain.step_up_unavailable"
        );
    }
    let en_msg = en["after_login"]["reason"]["message"].as_str().unwrap();
    let ko_msg = ko["after_login"]["reason"]["message"].as_str().unwrap();
    assert!(en_msg.is_ascii() && en_msg.contains("step-up"));
    assert!(ko_msg.contains("단계 상향"));
    // Every step names its check and result; every reason has a message.
    for step in en["trace"].as_array().unwrap() {
        assert!(step["check"].is_string() && step["result"].is_string());
        if !step["reason"].is_null() {
            assert!(step["reason"]["message"].is_string(), "{step}");
        }
    }
}

#[test]
fn s309_a1_malformed_simulations_are_refused() {
    let k = console(json!({}), &[]);
    let a = k.admin("ha309f", AdminRole::Admin);
    let now = k.now_s();
    for body in [
        json!({}),
        json!({"url": "not a url"}),
        json!({"url": format!("{APP}/x"), "session_id": "s_1", "subject": "u_1"}),
        json!({"url": format!("{APP}/x"), "session_id": "../etc"}),
        json!({"url": format!("{APP}/x"), "at": now + 31 * 86_400}),
        json!({"url": format!("{APP}/x"), "at": now - 31 * 86_400}),
        json!({"url": format!("{APP}/x"), "hypothetical": {"aal": 5}}),
        json!({"url": format!("{APP}/x"), "hypothetical": {"factors": ["magic"]}}),
        json!({"url": format!("{APP}/x"), "hypothetical": {"auth_time_source": "client"}}),
        json!({"url": format!("{APP}/x"), "navigation": "image"}),
        json!({"url": format!("{APP}/x"), "client_ip": "not-an-ip"}),
        json!({"url": format!("{APP}/x"), "extra": true}),
        json!({"url": format!("{APP}/{}", "a".repeat(2100))}),
    ] {
        let r = explain(&k, &a, body.clone());
        assert_eq!(r.status, 400, "{body}: {r:?}");
        assert_eq!(code(&r), "invalid_request");
    }
    // A non-canonical path is explained as the gateway's refusal.
    let e = ok(&explain(&k, &a, json!({"url": format!("{APP}/a%2Fb")})));
    assert_eq!(e["reason"]["code"], "hopae.path_not_canonical");
    assert!(reads(&k).len() == 1);
}

#[test]
fn s309_a2_explain_is_rate_limited_and_audited() {
    let k = console(json!({}), &[]);
    let a = k.admin("ha309g", AdminRole::Admin);
    k.add_user("u_t", "t@example.test", "T");
    let now = k.now_s();
    k.add_session(
        "s_t",
        "u_t",
        now - 60,
        CLIENT_IP,
        None,
        &["app.example.test"],
        None,
        None,
    );
    let r = ok(&explain(
        &k,
        &a,
        json!({"url": format!("{APP}/x"), "session_id": "s_t", "client_ip": CLIENT_IP}),
    ));
    assert_eq!(r["outcome"], "allow");
    let ev = reads(&k);
    let last = ev.last().unwrap();
    assert_eq!(last["attrs"]["purpose"], "explain.authentication");
    assert_eq!(last["attrs"]["status"], "allow");
    assert_eq!(last["attrs"]["host"], "app.example.test");
    assert_eq!(last["attrs"]["app"], "app");
    assert_eq!(last["user_id"], "u_t");
    assert_eq!(last["session_id"], "s_t");
    let mut limited = None;
    for i in 1..45 {
        let r = explain(&k, &a, json!({"url": format!("{APP}/x")}));
        if r.status == 429 {
            limited = Some((i, r));
            break;
        }
        assert_eq!(r.status, 200);
    }
    let (i, r) = limited.expect("explain is limited");
    assert!((30..=40).contains(&i), "limited after {i}");
    assert_eq!(code(&r), "rate_limited");
    assert!(r.header("retry-after").is_some());
    assert_eq!(reads(&k).len(), i);
}
