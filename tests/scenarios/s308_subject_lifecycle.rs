//! Scenario 308: the subject lifecycle feed and its reconcile snapshot
//! (ADR-0021 orphan reconciliation).
//!
//! The tests drive the real binary over the admin listener; status changes
//! go through the console's own disable/enable API so the outbox rows are
//! the production ones.
#![allow(dead_code)]

use serde_json::{Value, json};

use super::s301_admin_users::kit::{Console, Who, code};
use super::s307_subject_directory::dkit::{console, reads};
use hopae::store::types::AdminRole;

fn feed(k: &Console, w: &Who, body: Value) -> crate::support::Response {
    k.client(w).post_json("/v1/subjects/lifecycle", body)
}

fn snapshot(k: &Console, w: &Who, body: Value) -> crate::support::Response {
    k.client(w)
        .post_json("/v1/subjects/lifecycle/snapshot", body)
}

/// Walk the feed from `cursor` to its end; returns the changes and the final cursor.
fn drain(k: &Console, w: &Who, cursor: &str, limit: usize) -> (Vec<Value>, String) {
    let mut changes = Vec::new();
    let mut cursor = cursor.to_string();
    for _ in 0..100 {
        let r = feed(k, w, json!({"cursor": cursor, "limit": limit}));
        assert_eq!(r.status, 200, "{r:?}");
        let j = r.json();
        changes.extend(j["changes"].as_array().unwrap().iter().cloned());
        cursor = j["next_cursor"].as_str().unwrap().to_string();
        if j["more"] == false {
            return (changes, cursor);
        }
    }
    panic!("the feed does not end");
}

#[test]
fn s308_1_snapshot_lists_every_reserved_subject_with_watermark() {
    let k = console(json!({}), &[]);
    let a = k.admin("ha308a", AdminRole::Viewer);
    for i in 0..5 {
        k.add_user(
            &format!("u_snap{i}"),
            &format!("snap{i}@example.test"),
            "Snap",
        );
    }
    k.sql()
        .execute(
            "UPDATE users SET status='disabled' WHERE user_id='u_snap1'",
            [],
        )
        .unwrap();
    k.sql()
        .execute("DELETE FROM users WHERE user_id='u_snap2'", [])
        .unwrap();
    let first = snapshot(&k, &a, json!({"limit": 2}));
    assert_eq!(first.status, 200, "{first:?}");
    let j = first.json();
    let watermark = j["watermark"].as_str().expect("watermark").to_string();
    assert!(watermark.starts_with("f1."));
    let mut items: Vec<Value> = j["items"].as_array().unwrap().clone();
    let mut cursor = j["next_cursor"].as_str().map(str::to_string);
    while let Some(c) = cursor {
        let r = snapshot(&k, &a, json!({"limit": 2, "cursor": c}));
        assert_eq!(r.status, 200);
        let j = r.json();
        assert_eq!(j["watermark"], Value::Null);
        items.extend(j["items"].as_array().unwrap().iter().cloned());
        cursor = j["next_cursor"].as_str().map(str::to_string);
    }
    let status = |id: &str| {
        items
            .iter()
            .find(|i| i["user_id"] == id)
            .map(|i| i["status"].clone())
            .unwrap_or_else(|| panic!("{id} missing"))
    };
    assert_eq!(status("u_snap0"), "active");
    assert_eq!(status("u_snap1"), "disabled");
    assert_eq!(status("u_snap2"), "deleted");
    assert_eq!(status(&a.user_id), "active");
    // Every reserved ID once; no names or e-mail addresses.
    let mut ids: Vec<&str> = items
        .iter()
        .map(|i| i["user_id"].as_str().unwrap())
        .collect();
    let n = ids.len();
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), n);
    let text = serde_json::to_string(&items).unwrap();
    assert!(!text.contains("example.test") && !text.contains("Snap"));
    // The feed from the watermark is empty, and an empty poll is not audited.
    let before = reads(&k).len();
    let r = feed(&k, &a, json!({"cursor": watermark}));
    assert_eq!(r.status, 200);
    assert_eq!(r.json()["changes"], json!([]));
    assert_eq!(r.json()["more"], false);
    assert_eq!(reads(&k).len(), before);
}

#[test]
fn s308_2_feed_reports_creation_and_status_changes_after_watermark() {
    let k = console(json!({}), &[]);
    let a = k.admin("ha308b", AdminRole::Admin);
    k.add_user("u_before", "before@example.test", "Before");
    let watermark = snapshot(&k, &a, json!({})).json()["watermark"]
        .as_str()
        .unwrap()
        .to_string();
    k.add_user("u_new", "new@example.test", "New");
    let cl = k.client(&a);
    assert_eq!(
        cl.post_json("/v1/users/u_before/disable", json!({})).status,
        200
    );
    assert_eq!(
        cl.post_json("/v1/users/u_new/disable", json!({})).status,
        200
    );
    assert_eq!(
        cl.post_json("/v1/users/u_new/enable", json!({})).status,
        200
    );
    // An idempotent repeat changes nothing and adds no change.
    assert_eq!(
        cl.post_json("/v1/users/u_new/enable", json!({})).status,
        200
    );
    let (changes, cursor) = drain(&k, &a, &watermark, 1);
    let summary: Vec<(String, String, String)> = changes
        .iter()
        .map(|c| {
            (
                c["change"].as_str().unwrap().to_string(),
                c["user_id"].as_str().unwrap().to_string(),
                c["status"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    let expect = |c: &str, u: &str, s: &str| (c.to_string(), u.to_string(), s.to_string());
    assert_eq!(
        summary,
        vec![
            expect("created", "u_new", "active"),
            expect("disabled", "u_before", "disabled"),
            expect("disabled", "u_new", "active"),
            expect("enabled", "u_new", "active"),
        ]
    );
    assert!(changes.iter().all(|c| c["at"].is_i64()));
    // Nothing new: the cursor only moves past unrelated outbox rows (the
    // audit records of these reads among them).
    let r = feed(&k, &a, json!({"cursor": cursor}));
    assert_eq!(r.json()["changes"], json!([]));
    assert_eq!(r.json()["more"], false);
    // A non-empty page is an audited read.
    assert!(
        reads(&k)
            .iter()
            .any(|e| e["attrs"]["purpose"] == "subjects.lifecycle"
                && e["attrs"]["endpoint"] == "/v1/subjects/lifecycle")
    );
}

#[test]
fn s308_a1_tampered_or_pruned_positions_are_refused() {
    let k = console(json!({}), &[]);
    let a = k.admin("ha308c", AdminRole::Admin);
    k.add_user("u_p", "p@example.test", "P");
    let watermark = snapshot(&k, &a, json!({})).json()["watermark"]
        .as_str()
        .unwrap()
        .to_string();
    for bad in [
        "garbage",
        "f1.0.5.-",
        "f2.0.0.-",
        "f1.-1.0.-",
        "f1.0.0.e_x.y",
    ] {
        let r = feed(&k, &a, json!({"cursor": bad}));
        assert_eq!(r.status, 400, "{bad}: {r:?}");
        assert_eq!(code(&r), "invalid_cursor");
    }
    for bad in ["l1.", "l1.x", "x"] {
        let r = snapshot(&k, &a, json!({"cursor": bad}));
        assert_eq!(r.status, 400, "{bad}");
    }
    for body in [
        json!({"limit": 0}),
        json!({"limit": 201}),
        json!({"other": 1}),
    ] {
        assert_eq!(feed(&k, &a, body.clone()).status, 400, "{body}");
    }
    // A ledger position beyond the store's: another store's cursor.
    let parts: Vec<&str> = watermark.split('.').collect();
    let foreign = format!("f1.{}.{}.{}", 999_999, parts[2], parts[3]);
    let r = feed(&k, &a, json!({"cursor": foreign}));
    assert_eq!(r.status, 410);
    assert_eq!(code(&r), "cursor_expired");
    // An outbox position with another event id, then a pruned one.
    let forged = format!("f1.{}.{}.e_forged", parts[1], parts[2]);
    assert_eq!(feed(&k, &a, json!({"cursor": forged})).status, 410);
    let row: i64 = parts[2].parse().unwrap();
    k.sql()
        .execute("DELETE FROM events WHERE rowid <= ?1", [row])
        .unwrap();
    let r = feed(&k, &a, json!({"cursor": watermark}));
    assert_eq!(r.status, 410, "{r:?}");
    assert_eq!(code(&r), "cursor_expired");
    // The snapshot is the way back.
    let fresh = snapshot(&k, &a, json!({}));
    assert_eq!(fresh.status, 200);
    let again = fresh.json()["watermark"].as_str().unwrap().to_string();
    assert_eq!(feed(&k, &a, json!({"cursor": again})).status, 200);
}
