//! Scenario 302: console sessions — list, detail and termination.
//!
//! The tests drive the real binary over the admin listener; `kit` (shared
//! with 301) signs administrators in through the real flow and lays down rows
//! with SQL.
#![allow(dead_code)]

use serde_json::{Value, json};

use super::s301_admin_users::kit::{self, Console, Who, code};
use crate::support::*;
use hopae::store::types::AdminRole;

const UA: &str = "Mozilla/5.0 (X11; Linux) Alpha";

/// The fixture of the scenario: `u_x` with `s_1` (three hosts, a handoff
/// code `K1`), `s_2`, an expired `s_3` and a terminated `s_0`, plus 40 other
/// users with one live session each. Returns `s_1`'s application handle and
/// `s_2`'s application handle.
fn seed(k: &Console) -> (String, String) {
    let now = k.now_s();
    k.add_user("u_x", "x@example.test", "Ex");
    let h1 = k.add_session(
        "s_1",
        "u_x",
        now - 300,
        "203.0.113.9",
        Some(UA),
        &["auth.example.test", "app.example.test", "other.example.org"],
        None,
        None,
    );
    k.sql()
        .execute(
            "UPDATE sessions SET cred_gen = 2 WHERE session_id = 's_1'",
            [],
        )
        .unwrap();
    let h2 = k.add_session(
        "s_2",
        "u_x",
        now - 200,
        "198.51.100.7",
        Some("Mozilla/5.0 Beta"),
        &["app.example.test"],
        None,
        None,
    );
    k.add_session(
        "s_3",
        "u_x",
        now - 100_000,
        "203.0.113.9",
        None,
        &["app.example.test"],
        None,
        Some(now - 10),
    );
    k.add_session(
        "s_0",
        "u_x",
        now - 400,
        "203.0.113.9",
        None,
        &["app.example.test"],
        Some((now - 50, "logout")),
        None,
    );
    k.sql()
        .execute(
            "INSERT INTO handoff_codes (code_sha256, session_id, host, return_target, return_path, client_ip, bind_sha256, issued_aal, cred_gen, created_at, expires_at) VALUES (zeroblob(32), 's_1', 'other.example.org', 'https://other.example.org/', '/', '203.0.113.9', zeroblob(32), 1, 2, ?1, ?1 + 600)",
            [now],
        )
        .unwrap();
    for i in 0..40 {
        let uid = format!("u_o{i:02}");
        k.add_user(&uid, &format!("o{i}@example.test"), "Other");
        k.add_session(
            &format!("s_o{i:02}"),
            &uid,
            now - 1000 - i * 7,
            "192.0.2.50",
            None,
            &["app.example.test"],
            None,
            None,
        );
    }
    (h1[1].clone(), h2[0].clone())
}

fn session_row(k: &Console, id: &str) -> (Option<i64>, Option<String>, i64) {
    k.sql()
        .query_row(
            "SELECT terminated_at, terminated_reason, cred_gen FROM sessions WHERE session_id = ?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap()
}

fn live_count(k: &Console) -> usize {
    let now = k.now_s();
    k.count(&format!(
        "SELECT COUNT(*) FROM sessions WHERE terminated_at IS NULL AND absolute_expires_at > {now}"
    )) as usize
}

fn sid(v: &Value) -> String {
    v["session_id"].as_str().expect("session_id").to_string()
}

#[test]
fn s302_1_live_sessions_listed_by_creation_with_context() {
    let k = Console::new();
    let a = k.admin("sub-a", AdminRole::Admin);
    seed(&k);
    let cl = k.client(&a);
    let all = cl.walk_rows("/v1/sessions", 60);
    let ids: Vec<String> = all.iter().map(sid).collect();
    assert_eq!(ids.len(), live_count(&k), "every live session, once");
    assert!(ids.contains(&"s_1".to_string()) && ids.contains(&"s_2".to_string()));
    assert!(!ids.contains(&"s_0".to_string()), "terminated");
    assert!(
        !ids.contains(&"s_3".to_string()),
        "expired by its absolute lifetime"
    );
    let key = |v: &Value| (v["created_at"].as_i64().unwrap(), sid(v));
    assert!(
        all.windows(2).all(|w| key(&w[0]) >= key(&w[1])),
        "created_at DESC, session_id DESC"
    );
    let s1 = all.iter().find(|s| sid(s) == "s_1").unwrap();
    for f in [
        "session_id",
        "user_id",
        "primary_email",
        "provider_id",
        "aal",
        "factors",
        "hosts",
        "created_at",
        "last_seen_at",
        "absolute_expires_at",
        "auth_time",
        "bound_ip",
        "ua_prefix",
    ] {
        assert!(s1.get(f).is_some(), "{f}");
    }
    assert_eq!(s1["ua_prefix"], UA);
    assert_eq!(s1["bound_ip"], "203.0.113.9");
    let hosts: Vec<&str> = s1["hosts"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(
        hosts.contains(&"auth.example.test") && hosts.contains(&"app.example.test"),
        "{hosts:?}"
    );
    let o = all.iter().find(|s| sid(s) == "s_o00").unwrap();
    assert!(
        o["ua_prefix"].is_null(),
        "a session without a recorded prefix"
    );
    // The filter.
    let f = cl.walk("/v1/sessions?user_id=u_x");
    let mut fids: Vec<String> = f.iter().map(sid).collect();
    fids.sort();
    assert_eq!(fids, vec!["s_1".to_string(), "s_2".to_string()]);
    // The page: the same rows, last_seen as a column, a terminate form per row.
    let p = cl.get("/sessions?limit=200");
    assert_eq!(p.status, 200);
    for id in &ids {
        assert!(p.body.contains(&format!("/sessions/{id}")), "{id}");
    }
    assert!(p.body.contains("/sessions/s_1/terminate"), "terminate form");
    assert!(p.body.contains("Last seen"), "last_seen_at column");
    // The plans.
    let e = k.h.hooks.explain("sessions", true);
    assert!(
        e["plan"].to_string().contains("sessions_live_created"),
        "{e}"
    );
    let e = k.h.hooks.explain("sessions&by_user=1", true);
    assert!(
        e["plan"].to_string().contains("sessions_live_user_created"),
        "{e}"
    );
}

#[test]
fn s302_2_session_detail_shows_handles() {
    let k = Console::new();
    let a = k.admin("sub-a", AdminRole::Admin);
    let (h1, _) = seed(&k);
    let cl = k.client(&a);
    let r = cl.get("/v1/sessions/s_1");
    assert_eq!(r.status, 200, "{}", r.body);
    let j = r.json();
    assert_eq!(j["session_id"], "s_1");
    assert!(j["terminated_at"].is_null());
    let handles = j["handles"].as_array().unwrap();
    assert_eq!(handles.len(), 3, "one per host");
    for h in handles {
        for f in [
            "host",
            "issued_aal",
            "created_at",
            "last_seen_at",
            "absolute_expires_at",
            "revoked_at",
            "revoked_reason",
        ] {
            assert!(h.get(f).is_some(), "{f}");
        }
    }
    // Never a handle value or digest, a code, or the user agent beyond the prefix.
    assert!(!r.body.contains(&h1));
    let digest = hopae::crypto::Secret::new(h1.clone()).digest().to_hex();
    assert!(!r.body.contains(&digest));
    assert!(!r.body.contains("handle_sha256") && !r.body.contains("code_sha256"));
    let p = cl.get("/sessions/s_1");
    assert_eq!(p.status, 200);
    assert!(p.body.contains("other.example.org") && p.body.contains("auth.example.test"));
    assert!(!p.body.contains(&h1));
    // A terminated session answers with its end.
    let r = cl.get("/v1/sessions/s_0");
    assert_eq!(r.status, 200);
    assert_eq!(r.json()["terminated_reason"], "logout");
    assert!(r.json()["terminated_at"].is_i64() || r.json()["terminated_at"].is_u64());
}

fn crash_post(k: &mut Console, who: &Who, path: &str) {
    let admin = k.h.admin.unwrap();
    let mut req = RawReq::new("POST", path, &k.h.console_host())
        .header("x-forwarded-host", &k.h.console_host())
        .header("x-forwarded-proto", "https")
        .header("x-forwarded-for", kit::CLIENT_IP)
        .header("cookie", &format!("__Host-hopae={}", who.handle))
        .header("content-type", "application/json")
        .header("x-hopae-admin-request", "1");
    req.body = b"{}".to_vec();
    let _ = crate::support::client::try_send(admin, req);
}

#[test]
fn s302_3_terminate_one_ends_it_everywhere_with_record() {
    let k = Console::new();
    let a = k.admin("sub-a", AdminRole::Admin);
    let (h1, _) = seed(&k);
    let handles: Vec<String> = {
        // The other hosts' handles of s_1 for the verify checks.
        let now = k.now_s();
        let _ = now;
        vec![h1.clone()]
    };
    let cl = k.client(&a);
    let r = cl.post_json("/v1/sessions/s_1/terminate", json!({}));
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(r.json(), json!({"changed": true}));
    let now = k.now_s();
    assert_eq!(
        session_row(&k, "s_1"),
        (Some(now), Some("admin".to_string()), 3)
    );
    assert_eq!(
        k.count(
            "SELECT COUNT(*) FROM session_handles WHERE session_id = 's_1' AND revoked_at IS NULL"
        ),
        0
    );
    assert_eq!(
        k.count("SELECT COUNT(*) FROM session_handles WHERE session_id = 's_1' AND revoked_reason = 'session_terminated'"),
        3
    );
    assert_eq!(
        k.count("SELECT COUNT(*) FROM handoff_codes WHERE session_id = 's_1' AND consumed_at IS NOT NULL AND consumed_reason = 'session_terminated'"),
        1,
        "K1 consumed"
    );
    let term: Vec<_> = k
        .events("session.terminated")
        .into_iter()
        .filter(|e| e["session_id"] == "s_1")
        .collect();
    assert_eq!(term.len(), 1);
    assert_eq!(
        (term[0]["reason"].as_str(), term[0]["user_id"].as_str()),
        (Some("admin"), Some("u_x"))
    );
    let adm = k.events("admin.session_terminate");
    assert_eq!(adm.len(), 1);
    assert_eq!(
        (adm[0]["session_id"].as_str(), adm[0]["user_id"].as_str()),
        (Some("s_1"), Some("u_x"))
    );
    assert_eq!(adm[0]["attrs"]["actor"], a.user_id.as_str());
    assert!(
        adm[0]["attrs"]["actor_session"]
            .as_str()
            .unwrap()
            .starts_with("s_")
    );
    // The next verify with s_1's handle is the unauthenticated 302 with the cookie cleared.
    let v = k.h.verify(
        VerifyRequest::document("https://app.example.test/x")
            .ip("203.0.113.9")
            .cookie("__Host-hopae", &handles[0]),
    );
    assert_eq!(v.status, 302, "{v:?}");
    assert!(
        v.set_cookies()
            .iter()
            .any(|c| c.starts_with("__Host-hopae=") && c.contains("Max-Age=0"))
    );
    // s_2 is untouched.
    assert_eq!(session_row(&k, "s_2").0, None);

    // The crash point before the commit leaves s_1 live and no event.
    let mut k2 = Console::new();
    let a2 = k2.admin("sub-a", AdminRole::Admin);
    seed(&k2);
    k2.h.hooks.crash_at("after_admin_terminate_write");
    crash_post(&mut k2, &a2, "/v1/sessions/s_1/terminate");
    k2.h.wait_exit(std::time::Duration::from_secs(10))
        .expect("the process crashed");
    k2.h.restart();
    assert_eq!(session_row(&k2, "s_1").0, None, "still live");
    assert!(k2.events("admin.session_terminate").is_empty());
}

#[test]
fn s302_4_terminate_every_session_of_a_user() {
    let k = Console::new();
    let a = k.admin("sub-a", AdminRole::Admin);
    seed(&k);
    let r = k
        .client(&a)
        .post_json("/v1/users/u_x/sessions/terminate", json!({}));
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(r.json(), json!({"terminated": 2}));
    for id in ["s_1", "s_2"] {
        let row = session_row(&k, id);
        assert!(row.0.is_some());
        assert_eq!(row.1.as_deref(), Some("admin"));
    }
    assert_eq!(session_row(&k, "s_3").0, None, "left to the sweep");
    assert_eq!(
        session_row(&k, "s_0").1.as_deref(),
        Some("logout"),
        "untouched"
    );
    let term: Vec<_> = k
        .events("session.terminated")
        .into_iter()
        .filter(|e| e["user_id"] == "u_x")
        .collect();
    assert_eq!(term.len(), 2);
    let adm = k.events("admin.sessions_terminate");
    assert_eq!(adm.len(), 1);
    assert_eq!(adm[0]["user_id"], "u_x");
    assert_eq!(adm[0]["attrs"]["count"], 2);
    // u_x stays active.
    assert_eq!(
        k.count("SELECT COUNT(*) FROM users WHERE user_id = 'u_x' AND status = 'active'"),
        1
    );
}

#[test]
fn s302_5_administrator_may_end_own_session() {
    let k = Console::new();
    let a = k.admin("sub-a", AdminRole::Admin);
    let own: String = k
        .sql()
        .query_row(
            "SELECT session_id FROM sessions WHERE user_id = ?1 AND terminated_at IS NULL",
            [&a.user_id],
            |r| r.get(0),
        )
        .unwrap();
    let cl = k.client(&a);
    let r = cl.post_json(&format!("/v1/sessions/{own}/terminate"), json!({}));
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(r.json(), json!({"changed": true}));
    let adm = k.events("admin.session_terminate");
    assert_eq!(adm.len(), 1);
    assert_eq!(adm[0]["user_id"], a.user_id.as_str());
    assert_eq!(adm[0]["attrs"]["actor"], a.user_id.as_str());
    let r = cl.get("/v1/sessions?limit=1");
    assert_eq!((r.status, code(&r).as_str()), (403, "login_required"));
}

#[test]
fn s302_6_html_forms_do_the_same() {
    let k = Console::new();
    let a = k.admin("sub-a", AdminRole::Admin);
    seed(&k);
    let cl = k.client(&a);
    let origin = k.origin();
    let page = cl.get("/sessions?user_id=u_x");
    let token = AdminClient::csrf_from_page(&page.body).expect("csrf on the list");
    let r = cl.post_form(
        "/sessions/s_2/terminate",
        &[("csrf", &token), ("back", "sessions"), ("user_id", "u_x")],
        Some(&origin),
    );
    assert_eq!(r.status, 303, "{r:?}");
    assert_eq!(r.location(), Some("/sessions?user_id=u_x"));
    assert_eq!(session_row(&k, "s_2").1.as_deref(), Some("admin"));
    let adm = k.events("admin.session_terminate");
    assert_eq!(adm.len(), 1);
    // The user page's terminate-all form.
    let up = cl.get("/users/u_x");
    let token = AdminClient::csrf_from_page(&up.body).expect("csrf on the user page");
    let r = cl.post_form(
        "/users/u_x/sessions/terminate",
        &[("csrf", &token), ("back", "user"), ("user_id", "u_x")],
        Some(&origin),
    );
    assert_eq!(r.status, 303, "{r:?}");
    assert_eq!(r.location(), Some("/users/u_x"));
    assert_eq!(session_row(&k, "s_1").1.as_deref(), Some("admin"));
    assert_eq!(k.events("admin.sessions_terminate").len(), 1);
    // A hostile back value is ignored: the redirect never follows client input.
    let up = cl.get("/sessions");
    let token = AdminClient::csrf_from_page(&up.body).expect("csrf");
    let r = cl.post_form(
        "/sessions/s_o00/terminate",
        &[("csrf", &token), ("back", "https://evil.example/")],
        Some(&origin),
    );
    assert_eq!(r.status, 303);
    assert_eq!(r.location(), Some("/sessions"));
}

#[test]
fn s302_a1_terminating_ended_session_changes_nothing() {
    let k = Console::new();
    let a = k.admin("sub-a", AdminRole::Admin);
    seed(&k);
    let cl = k.client(&a);
    assert_eq!(
        cl.post_json("/v1/sessions/s_1/terminate", json!({})).json()["changed"],
        true
    );
    let events = k.count("SELECT COUNT(*) FROM events");
    let cred = session_row(&k, "s_1").2;
    let r = cl.post_json("/v1/sessions/s_1/terminate", json!({}));
    assert_eq!(r.json(), json!({"changed": false}));
    let r = cl.post_json("/v1/sessions/s_0/terminate", json!({}));
    assert_eq!(r.json(), json!({"changed": false}));
    assert_eq!(k.count("SELECT COUNT(*) FROM events"), events, "no event");
    assert_eq!(session_row(&k, "s_1").2, cred, "no cred_gen change");
    // The expired, unswept session is terminated now so the list and the sweep agree.
    let r = cl.post_json("/v1/sessions/s_3/terminate", json!({}));
    assert_eq!(r.json(), json!({"changed": true}));
    assert_eq!(session_row(&k, "s_3").1.as_deref(), Some("admin"));
    assert_eq!(
        k.count("SELECT COUNT(*) FROM events") - events,
        2,
        "one event pair"
    );
}

#[test]
fn s302_a2_identifiers_validated_before_store() {
    let k = Console::new();
    let a = k.admin("sub-a", AdminRole::Admin);
    seed(&k);
    let cl = k.client(&a);
    let before = k.h.hooks.counters()["store_calls"].clone();
    for path in ["/v1/sessions/u_x/terminate", "/v1/sessions/s_%00/terminate"] {
        let r = cl.post_json(path, json!({}));
        assert_eq!((r.status, code(&r).as_str()), (400, "invalid_id"), "{path}");
    }
    let after = k.h.hooks.counters()["store_calls"].clone();
    for m in ["session_summary", "admin_terminate_session"] {
        assert_eq!(
            before[m].as_u64().unwrap_or(0),
            after[m].as_u64().unwrap_or(0),
            "{m} not called"
        );
    }
    // A query parameter and a body naming another session are ignored.
    let r = cl.post_json("/v1/sessions/s_1/terminate?session_id=s_2", json!({}));
    assert_eq!(r.json(), json!({"changed": true}));
    assert_eq!(session_row(&k, "s_2").0, None, "s_2 untouched");
    let r = cl.post_json("/v1/sessions/s_o00/terminate", json!({"session_id": "s_2"}));
    assert_eq!(r.json(), json!({"changed": true}));
    assert_eq!(session_row(&k, "s_2").0, None, "s_2 untouched");
    assert!(session_row(&k, "s_o00").0.is_some());
    // An unknown, well-formed id is a 404.
    let r = cl.post_json("/v1/sessions/s_nope/terminate", json!({}));
    assert_eq!((r.status, code(&r).as_str()), (404, "not_found"));
}

#[test]
fn s302_a3_termination_racing_redemption_and_step_up() {
    // Terminate first: the code is consumed and nothing is minted.
    let k = Console::new();
    let a = k.admin("sub-a", AdminRole::Admin);
    let (url, bind) = k
        .begin_login("sub-y", "y@example.test", "Why")
        .expect("a pending handoff");
    let y: String =
        k.count_text("SELECT user_id FROM users WHERE primary_email = 'y@example.test'");
    let ysession: String = k.count_text(&format!(
        "SELECT session_id FROM sessions WHERE user_id = '{y}'"
    ));
    let r = k
        .client(&a)
        .post_json(&format!("/v1/sessions/{ysession}/terminate"), json!({}));
    assert_eq!(r.json()["changed"], true, "{}", r.body);
    let redeemed = k.redeem(&url, &bind);
    assert!(
        !redeemed
            .set_cookies()
            .iter()
            .any(|c| c.starts_with("__Host-hopae=") && !c.contains("Max-Age=0")),
        "no handle minted: {redeemed:?}"
    );
    assert_eq!(k.count(&format!("SELECT COUNT(*) FROM session_handles WHERE session_id = '{ysession}' AND revoked_at IS NULL")), 0);
    assert_eq!(
        k.events("session.terminated")
            .into_iter()
            .filter(|e| e["session_id"] == ysession.as_str())
            .count(),
        1
    );

    // Redeem first (held before its commit): the termination queues behind it and revokes the minted handle.
    let k = Console::new();
    let a = k.admin("sub-a", AdminRole::Admin);
    let (url, bind) = k
        .begin_login("sub-y", "y@example.test", "Why")
        .expect("a pending handoff");
    let y: String =
        k.count_text("SELECT user_id FROM users WHERE primary_email = 'y@example.test'");
    let ysession: String = k.count_text(&format!(
        "SELECT session_id FROM sessions WHERE user_id = '{y}'"
    ));
    k.h.hooks.hold("redeem");
    let (redeemed, term) = std::thread::scope(|s| {
        let red = s.spawn(|| k.redeem(&url, &bind));
        std::thread::sleep(std::time::Duration::from_millis(500));
        let t = s.spawn(|| {
            k.client(&a)
                .post_json(&format!("/v1/sessions/{ysession}/terminate"), json!({}))
        });
        std::thread::sleep(std::time::Duration::from_millis(500));
        k.h.hooks.release("redeem");
        (red.join().unwrap(), t.join().unwrap())
    });
    assert_eq!(term.json()["changed"], true, "{}", term.body);
    let handle = redeemed
        .set_cookies()
        .iter()
        .find_map(|c| c.strip_prefix("__Host-hopae="))
        .map(|r| r.split(';').next().unwrap_or("").to_string());
    if let Some(handle) = handle.filter(|h| !h.is_empty()) {
        let v = k.h.verify(
            VerifyRequest::document("https://hopae-admin.example.test/users")
                .ip(kit::CLIENT_IP)
                .cookie("__Host-hopae", &handle),
        );
        assert_eq!(v.status, 302, "the minted handle is denied: {v:?}");
    }
    assert_eq!(k.count(&format!("SELECT COUNT(*) FROM session_handles WHERE session_id = '{ysession}' AND revoked_at IS NULL")), 0);
    assert_eq!(
        k.events("session.terminated")
            .into_iter()
            .filter(|e| e["session_id"] == ysession.as_str())
            .count(),
        1
    );
}

#[test]
fn s302_a4_terminate_all_bounded_and_listings_examine_bounded_window() {
    let k = Console::new();
    let a = k.admin("sub-a", AdminRole::Admin);
    k.add_user("u_big", "big@example.test", "Big");
    k.add_user("u_none", "none@example.test", "None");
    k.add_user("u_bulk", "bulk@example.test", "Bulk");
    k.h.hooks.bulk_sessions("u_big", 500);
    k.h.hooks.bulk_sessions("u_bulk", 100_000);
    let cl = k.client(&a);
    let before_events = k.count("SELECT COUNT(*) FROM events");
    let r = cl.post_json("/v1/users/u_big/sessions/terminate", json!({}));
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(r.json(), json!({"terminated": 500}));
    assert_eq!(k.count("SELECT COUNT(*) FROM events") - before_events, 501);
    // The empty filter answers at once, with no cursor and nothing examined.
    let series = "hopae_admin_rows_examined_total{list=\"sessions\"}";
    let before = k.metric(series);
    let r = cl.get("/v1/sessions?user_id=u_none").json();
    assert_eq!(r["items"].as_array().unwrap().len(), 0);
    assert!(r["next_cursor"].is_null());
    assert_eq!(k.metric(series), before, "zero candidates examined");
    // Unfiltered pages examine at most one window and return 200 items with a cursor.
    let before = k.metric(series);
    let r = cl.get("/v1/sessions?limit=200").json();
    assert_eq!(r["items"].as_array().unwrap().len(), 200);
    assert!(r["next_cursor"].is_string());
    assert!(k.metric(series) - before <= 10_000);
    // A deep cursor costs the same VM work as a shallow one.
    let now_ms = k.h.hooks.now_ms();
    let shallow =
        k.h.hooks
            .explain(&format!("sessions&cursor={now_ms}:s_blk000099000"), true);
    let deep =
        k.h.hooks
            .explain(&format!("sessions&cursor={now_ms}:s_blk000050000"), true);
    assert!(
        deep["plan"]
            .to_string()
            .contains("(created_at,session_id)<(?,?)"),
        "{deep}"
    );
    let (s1, s2) = (
        shallow["vm_step"].as_i64().unwrap(),
        deep["vm_step"].as_i64().unwrap(),
    );
    let ratio = s2 as f64 / s1 as f64;
    assert!((0.9..=1.1).contains(&ratio), "{s1} vs {s2}");

    // Under a 100 ms budget the terminate-all is interrupted, rolled back and answered 503.
    let k = Console::with(json!({"admin": {"query_budget_ms": 100}}));
    let a = k.admin("sub-a", AdminRole::Admin);
    k.add_user("u_big", "big@example.test", "Big");
    k.h.hooks.bulk_sessions("u_big", 500);
    k.h.hooks.slow_scan(1);
    let r = k
        .client(&a)
        .post_json("/v1/users/u_big/sessions/terminate", json!({}));
    assert_eq!(
        (r.status, code(&r).as_str()),
        (503, "store_unavailable"),
        "{}",
        r.body
    );
    k.h.hooks.slow_scan_off();
    assert_eq!(
        k.count("SELECT COUNT(*) FROM sessions WHERE user_id = 'u_big' AND terminated_at IS NULL"),
        500,
        "rolled back"
    );
    assert!(k.events("admin.sessions_terminate").is_empty());
    assert_eq!(
        k.client(&a).get("/v1/sessions?limit=1").status,
        200,
        "the writer serves the next job"
    );
}

#[test]
fn s302_a5_viewer_cannot_terminate_target_cannot_resist() {
    let k = Console::new();
    let a = k.admin("sub-a", AdminRole::Admin);
    let v = k.admin("sub-v", AdminRole::Viewer);
    let (_, h2) = seed(&k);
    let r = k
        .client(&v)
        .post_json("/v1/sessions/s_2/terminate", json!({}));
    assert_eq!((r.status, code(&r).as_str()), (403, "role_insufficient"));
    assert_eq!(session_row(&k, "s_2").0, None);
    assert!(
        k.events("admin.denied")
            .iter()
            .any(|e| e["reason"] == "role_insufficient")
    );
    // The target keeps verifying every 10 ms while the administrator terminates.
    let stop = std::sync::atomic::AtomicBool::new(false);
    let seen = std::thread::scope(|s| {
        let t = s.spawn(|| {
            let mut seen = Vec::new();
            while !stop.load(std::sync::atomic::Ordering::SeqCst) {
                let v = k.h.verify(
                    VerifyRequest::document("https://app.example.test/x")
                        .ip("198.51.100.7")
                        .cookie("__Host-hopae", &h2),
                );
                seen.push(v.status);
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            seen
        });
        std::thread::sleep(std::time::Duration::from_millis(200));
        let r = k
            .client(&a)
            .post_json("/v1/sessions/s_2/terminate", json!({}));
        assert_eq!(r.json()["changed"], true, "{}", r.body);
        std::thread::sleep(std::time::Duration::from_millis(200));
        stop.store(true, std::sync::atomic::Ordering::SeqCst);
        t.join().unwrap()
    });
    let first_denied = seen
        .iter()
        .position(|s| *s == 302)
        .expect("denied after the commit");
    assert!(first_denied > 0, "allowed before: {seen:?}");
    assert!(
        seen[first_denied..].iter().all(|s| *s == 302),
        "nothing keeps it alive: {seen:?}"
    );
}

#[test]
fn s302_a6_session_ids_reveal_nothing_to_unauthorized() {
    let k = Console::new();
    let _a = k.admin("sub-a", AdminRole::Admin);
    seed(&k);
    let n = k.login("sub-n", "n@example.test", "No grant");
    let anon = k.h.admin_client();
    let r = anon.get("/v1/sessions/s_1");
    assert_eq!((r.status, code(&r).as_str()), (403, "login_required"));
    let r = anon.get("/v1/sessions/s_unknown");
    assert_eq!((r.status, code(&r).as_str()), (403, "login_required"));
    let (r1, r2) = (
        k.client(&n).get("/v1/sessions/s_1"),
        k.client(&n).get("/v1/sessions/s_unknown"),
    );
    assert_eq!((r1.status, code(&r1)), (403, "not_admin".to_string()));
    assert_eq!((r2.status, code(&r2)), (403, "not_admin".to_string()));
    let r = k
        .client(&n)
        .post_json("/v1/sessions/s_1/terminate", json!({}));
    assert_eq!((r.status, code(&r).as_str()), (403, "not_admin"));
    assert_eq!(session_row(&k, "s_1").0, None);
    assert!(!r.body.contains("s_1"));
}

#[test]
fn s302_a7_activity_during_walk_neither_skips_nor_repeats() {
    let k = Console::new();
    let a = k.admin("sub-a", AdminRole::Admin);
    let now = k.now_s();
    k.add_user("u_w", "w@example.test", "Walk");
    for (id, at) in [
        ("s_wa", now - 100),
        ("s_wb", now - 110),
        ("s_wc", now - 120),
    ] {
        k.add_session(
            id,
            "u_w",
            at,
            "192.0.2.60",
            None,
            &["app.example.test"],
            None,
            None,
        );
    }
    let cl = k.client(&a);
    let enc = |c: &str| url::form_urlencoded::byte_serialize(c.as_bytes()).collect::<String>();
    let p1 = cl.get("/v1/sessions?user_id=u_w&limit=2").json();
    let ids1: Vec<String> = p1["items"].as_array().unwrap().iter().map(sid).collect();
    assert_eq!(ids1, vec!["s_wa", "s_wb"]);
    // C becomes very active and a newer session D appears.
    k.sql()
        .execute(
            "UPDATE sessions SET last_seen_at = ?1 WHERE session_id = 's_wc'",
            [now + 10],
        )
        .unwrap();
    k.add_session(
        "s_wd",
        "u_w",
        now + 20,
        "192.0.2.60",
        None,
        &["app.example.test"],
        None,
        None,
    );
    let c1 = enc(p1["next_cursor"].as_str().unwrap());
    let p2 = cl
        .get(&format!("/v1/sessions?user_id=u_w&limit=2&cursor={c1}"))
        .json();
    let items2 = p2["items"].as_array().unwrap();
    assert_eq!(items2.iter().map(sid).collect::<Vec<_>>(), vec!["s_wc"]);
    assert_eq!(
        items2[0]["last_seen_at"],
        now + 10,
        "the displayed last_seen_at is current"
    );
    let c2 = p2["next_cursor"].as_str().map(enc);
    if let Some(c2) = c2 {
        let p3 = cl
            .get(&format!("/v1/sessions?user_id=u_w&limit=2&cursor={c2}"))
            .json();
        assert!(p3["items"].as_array().unwrap().is_empty());
        assert!(p3["next_cursor"].is_null());
    }
    // D is on page 1 of a fresh walk.
    let fresh = cl.get("/v1/sessions?user_id=u_w&limit=2").json();
    assert_eq!(sid(&fresh["items"][0]), "s_wd");
    // Terminating B between page 1 and page 2 removes nothing but B.
    let fresh_ids: Vec<String> = fresh["items"].as_array().unwrap().iter().map(sid).collect();
    assert_eq!(fresh_ids, vec!["s_wd", "s_wa"]);
    let c = enc(fresh["next_cursor"].as_str().unwrap());
    assert_eq!(
        cl.post_json("/v1/sessions/s_wb/terminate", json!({}))
            .json()["changed"],
        true
    );
    let p2 = cl
        .get(&format!("/v1/sessions?user_id=u_w&limit=2&cursor={c}"))
        .json();
    let ids: Vec<String> = p2["items"].as_array().unwrap().iter().map(sid).collect();
    assert_eq!(ids, vec!["s_wc"], "B is gone, C is still found");
}
