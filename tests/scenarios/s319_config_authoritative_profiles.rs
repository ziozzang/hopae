//! Scenario 319: configuration-authoritative authentication profiles
//! (`authentication.source = config`), the declarative mode a Kubernetes
//! package (Helm values) needs.
#![allow(dead_code)]

use serde_json::{Value, json};

use super::s301_admin_users::kit::Console;
use super::s307_subject_directory::dkit::console;
use hopae::store::types::AdminRole;

fn profiles(k: &Console, a: &super::s301_admin_users::kit::Who) -> Value {
    let r = k.client(a).get("/v1/authentication/profiles");
    assert_eq!(r.status, 200, "{r:?}");
    r.json()
}

/// S319-2: in config mode every start reconciles the store to the file,
/// console edits are refused, an unchanged file keeps the revision, and
/// switching back to store mode keeps the last reconciled document.
#[test]
fn s319_2_config_mode_reconciles_on_start_and_refuses_console_edits() {
    let mut k = console(json!({"authentication": {"source": "config"}}), &[]);
    let a = k.admin("ha319", AdminRole::Admin);
    let doc = profiles(&k, &a);
    assert_eq!(doc["revision"], 1);
    assert_eq!(doc["source"], "config");
    assert_eq!(
        doc["configuration"]["profiles"][0]["networks"],
        json!(["192.0.2.0/24"])
    );
    // Console/API edits are refused with a clear reason, before any write.
    let edit = k.client(&a).put_json_raw(
        "/v1/authentication/profiles",
        &[
            ("content-type", "application/json"),
            ("x-hopae-admin-request", "1"),
            ("if-match", "\"1\""),
        ],
        br#"{"configuration":null}"#,
    );
    assert_eq!(edit.status, 409, "{edit:?}");
    assert_eq!(edit.json()["error"], "config_authoritative");
    assert_eq!(profiles(&k, &a)["revision"], 1);
    // A changed file (Helm values) is applied at the next start.
    k.h.reconfigure(|v| {
        v["authentication_gateway"]["profiles"][0]["networks"] = json!(["198.51.100.0/24"]);
    });
    k.h.restart();
    let doc = profiles(&k, &a);
    assert_eq!(doc["revision"], 2);
    assert_eq!(
        doc["configuration"]["profiles"][0]["networks"],
        json!(["198.51.100.0/24"])
    );
    let events = k.events("authentication.reconciled");
    assert_eq!(events.len(), 2, "{events:?}");
    assert_eq!(events[1]["attrs"]["kind"], "profiles");
    assert_eq!(events[1]["attrs"]["previous_revision"], 1);
    assert_eq!(events[1]["attrs"]["revision"], 2);
    assert_eq!(events[1]["attrs"]["actor"], "config");
    // An unchanged file: same revision, no event.
    k.h.restart();
    assert_eq!(profiles(&k, &a)["revision"], 2);
    assert_eq!(k.events("authentication.reconciled").len(), 2);
    // Back to store mode: the store is authoritative again and keeps the
    // last reconciled document even though the file changes.
    k.h.reconfigure(|v| {
        v["authentication"]["source"] = json!("store");
        v["authentication_gateway"]["profiles"][0]["networks"] = json!(["203.0.113.0/24"]);
    });
    k.h.restart();
    let doc = profiles(&k, &a);
    assert_eq!(doc["source"], "store");
    assert_eq!(doc["revision"], 2);
    assert_eq!(
        doc["configuration"]["profiles"][0]["networks"],
        json!(["198.51.100.0/24"])
    );
}
