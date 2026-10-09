//! Scenario 305: administrator grants from the command line and the
//! configuration file (ADR-0016). Every case runs the real `hopae` binary as
//! a second process beside a running instance on the same `state_dir`.
//!
//! The console-side effects ("the next `GET /v1/me` is `200` with
//! `role: admin`") are asserted through the admin listener with a console
//! handle of the user's real sign-in; the instance's own view of the table
//! (`hooks.grants()`, read without a restart) is asserted beside them.
#![allow(dead_code)]

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use rusqlite::Connection;
use serde_json::{Value, json};

use crate::scenarios::s301_admin_users::kit::Console;
use crate::support::*;

const GW_KEY: &str = "gwkey-value-0123456789";
const MOCK_SECRET: &str = "mock-secret-value-9876543210";

struct Rig {
    c: Console,
}

impl std::ops::DerefMut for Rig {
    fn deref_mut(&mut self) -> &mut Console {
        &mut self.c
    }
}

impl std::ops::Deref for Rig {
    type Target = Console;
    fn deref(&self) -> &Console {
        &self.c
    }
}

impl Rig {
    fn new() -> Rig {
        Rig::with(Fixture::new("m4-admin"))
    }

    fn with(f: Fixture) -> Rig {
        let idp = MockIdp::start("default");
        let h = Hopae::spawn(f, &idp, &[]);
        Rig {
            c: Console { h, idp },
        }
    }

    /// Sign `sub` in at the console host (the user exists already, so the
    /// identity resolves to it); returns the console handle.
    fn console(&self, sub: &str, email: &str) -> String {
        self.c.login(sub, email, sub).handle
    }

    /// `GET /v1/me` with `handle`: the status and the JSON body.
    fn me(&self, handle: &str) -> (u16, Value) {
        let r = self.h.admin_client().with_handle(handle).get("/v1/me");
        (r.status, r.json())
    }

    fn db_path(&self) -> PathBuf {
        self.h.state_dir.path().join("state").join("hopae.db")
    }

    fn db(&self) -> Connection {
        let c = Connection::open(self.db_path()).unwrap();
        c.busy_timeout(Duration::from_secs(10)).unwrap();
        c
    }

    #[allow(clippy::too_many_arguments)]
    fn user(
        &self,
        id: &str,
        email: Option<&str>,
        verified: bool,
        authoritative: bool,
        status: &str,
        name: &str,
        identities: &[(&str, &str)],
        created_at: i64,
    ) {
        let c = self.db();
        c.execute(
            "INSERT INTO users (user_id, primary_email, email_verified, email_authoritative, display_name, status, created_at, updated_at, last_login_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7, ?8)",
            rusqlite::params![id, email, verified, authoritative, name, status, created_at, created_at + 60],
        )
        .unwrap();
        for (i, (p, s)) in identities.iter().enumerate() {
            c.execute(
                "INSERT INTO identities (provider_id, subject, user_id, email, email_verified, email_authoritative, first_seen_at, last_seen_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)",
                rusqlite::params![p, s, id, email, verified, authoritative, created_at + i as i64],
            )
            .unwrap();
        }
    }

    /// `u_a` .. `u_u` of the scenario's preconditions.
    fn standard_users(&self) {
        let t = 1_700_000_000;
        self.user(
            "u_a",
            Some("a@example.test"),
            true,
            false,
            "active",
            "Alice A",
            &[("mock", "sub-1"), ("mock2", "sub-77")],
            t,
        );
        self.user(
            "u_h",
            Some("h@example.test"),
            true,
            true,
            "active",
            "Hana H",
            &[("mock", "sub-h")],
            t,
        );
        self.user(
            "u_v",
            Some("v@example.test"),
            true,
            false,
            "active",
            "Vera V",
            &[("mock", "sub-v")],
            t,
        );
        self.user(
            "u_d",
            Some("d@example.test"),
            true,
            false,
            "disabled",
            "Dan D",
            &[("mock", "sub-d")],
            t,
        );
        self.user(
            "u_u",
            Some("u@example.test"),
            false,
            false,
            "active",
            "Uma U",
            &[("mock", "sub-u")],
            t,
        );
    }

    fn cli(&self, args: &[&str]) -> CliOutput {
        self.h.cli(args)
    }

    fn grants(&self) -> Vec<Value> {
        self.h.hooks.grants()
    }

    fn grant(&self, id: &str) -> Option<Value> {
        self.grants().into_iter().find(|g| g["user_id"] == id)
    }

    fn events(&self, kind: &str) -> Vec<Value> {
        self.h.hooks.events(Some(kind), Some(1000))
    }

    fn admin_events(&self) -> usize {
        self.events("admin.grant").len() + self.events("admin.revoke").len()
    }

    fn users_count(&self) -> i64 {
        self.db()
            .query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0))
            .unwrap()
    }

    /// Replace `admin.users` in the configuration file the instance and the CLI share.
    fn set_users(&self, users: Value) {
        let p = self.h.config_path().to_path_buf();
        let mut v: Value = serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
        v["admin"]["users"] = users;
        std::fs::write(&p, serde_json::to_vec_pretty(&v).unwrap()).unwrap();
    }

    fn ok(&self, args: &[&str]) -> CliOutput {
        let o = self.cli(args);
        assert_eq!(o.status, 0, "{args:?}: {}", o.all());
        o
    }

    fn refused(&self, args: &[&str], needle: &str) -> CliOutput {
        let o = self.cli(args);
        assert_eq!(o.status, 2, "{args:?}: {}", o.all());
        assert!(
            o.stderr.contains(needle),
            "{args:?}: stderr lacks {needle:?}: {}",
            o.all()
        );
        o
    }
}

fn lines_of(s: &str) -> Vec<&str> {
    s.lines().collect()
}

#[test]
fn s305_1_bootstrap_first_grant_by_user_id_prints_resolution() {
    let r = Rig::new();
    r.standard_users();
    assert!(r.grants().is_empty());
    let ha = r.console("sub-1", "a@example.test");
    let (st, body) = r.me(&ha);
    assert_eq!(
        (st, body["error"].as_str()),
        (403, Some("not_admin")),
        "{body}"
    );
    let o = r.ok(&["admin", "grant", "u_a"]);
    // The very next request is the administrator's, with no restart.
    let (st, body) = r.me(&ha);
    assert_eq!(st, 200, "{body}");
    assert_eq!(body["role"], "admin", "{body}");
    for needle in [
        "user_id u_a",
        "display_name Alice A",
        "created_at ",
        "last_login_at ",
        "primary_email a@example.test (verified, not authoritative)",
        "identities mock:sub-1, mock2:sub-77",
    ] {
        assert!(o.stdout.contains(needle), "{needle}: {}", o.all());
    }
    assert_eq!(
        lines_of(&o.stdout).last().copied(),
        Some("granted admin to u_a"),
        "{}",
        o.all()
    );
    let g = r.grant("u_a").expect("row");
    assert_eq!(g["role"], "admin");
    assert_eq!(g["managed_by"], "api");
    assert!(g["source_email"].is_null());
    assert_eq!(g["granted_by"], "cli");
    assert!(g["revoked_at"].is_null());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    assert!((g["granted_at"].as_i64().unwrap() - now).abs() < 60, "{g}");
    let ev = r.events("admin.grant");
    assert_eq!(ev.len(), 1, "{ev:?}");
    assert_eq!(ev[0]["user_id"], "u_a");
    assert_eq!(ev[0]["attrs"]["actor"], "cli");
    assert_eq!(ev[0]["attrs"]["role"], "admin");
    assert_eq!(ev[0]["attrs"]["managed_by"], "api");
    assert!(ev[0]["attrs"].get("previous_role").is_none(), "{}", ev[0]);
    let id = ev[0]["event_id"].as_str().unwrap();
    assert!(
        r.h.hooks
            .deliveries(Some("log"))
            .iter()
            .any(|d| d["event_id"] == id),
        "no delivery row for the log sink"
    );
}

#[test]
fn s305_2_grant_by_email_resolves_once_and_needs_confirm_unless_authoritative() {
    let r = Rig::new();
    r.standard_users();
    // (a) authoritative: no confirmation.
    let o = r.ok(&[
        "admin",
        "grant",
        "h@example.test",
        "--role",
        "viewer",
        "--note",
        "ops rotation",
    ]);
    assert!(o.stdout.contains("user_id u_h"), "{}", o.all());
    assert!(
        o.stdout.contains("(verified, authoritative)"),
        "{}",
        o.all()
    );
    assert!(o.stdout.contains("granted viewer to u_h"), "{}", o.all());
    let g = r.grant("u_h").unwrap();
    assert_eq!(g["source_email"], "h@example.test");
    assert_eq!(g["note"], "ops rotation");
    assert_eq!(g["role"], "viewer");
    let before = (r.grants().len(), r.admin_events());
    // (b) not authoritative: the block, then a refusal.
    let o = r.refused(
        &["admin", "grant", "v@example.test"],
        "refusing: v@example.test is verified but not authoritative; re-run with --confirm u_v if this is the intended person",
    );
    assert!(o.stdout.contains("user_id u_v"), "{}", o.all());
    assert_eq!((r.grants().len(), r.admin_events()), before);
    // (d) the wrong confirmation.
    r.refused(
        &["admin", "grant", "v@example.test", "--confirm", "u_h"],
        "--confirm names u_h but the address resolves to u_v",
    );
    assert_eq!((r.grants().len(), r.admin_events()), before);
    // (e) unknown, (f) unverified.
    r.refused(
        &["admin", "grant", "nobody@example.test"],
        "no such user: sign in once first",
    );
    r.refused(&["admin", "grant", "u@example.test"], "email not verified");
    assert_eq!((r.grants().len(), r.admin_events()), before);
    // (c) confirmed.
    let o = r.ok(&["admin", "grant", "v@example.test", "--confirm", "u_v"]);
    assert!(o.stdout.contains("granted admin to u_v"), "{}", o.all());
    assert_eq!(r.grant("u_v").unwrap()["source_email"], "v@example.test");
    // The grant is bound to the id: a changed primary email never moves it.
    r.db()
        .execute(
            "UPDATE users SET primary_email = 'v2@example.test' WHERE user_id = 'u_v'",
            [],
        )
        .unwrap();
    assert_eq!(r.grant("u_v").unwrap()["user_id"], "u_v");
    r.db()
        .execute(
            "UPDATE users SET primary_email = 'v@example.test' WHERE user_id = 'u_v'",
            [],
        )
        .unwrap();
    // (g) the address is normalized (ADR-0011): the same user, a no-op.
    let n = r.admin_events();
    let o = r.ok(&["admin", "grant", "V@Example.test", "--confirm", "u_v"]);
    assert!(o.stdout.contains("unchanged"), "{}", o.all());
    assert_eq!(r.admin_events(), n);
}

#[test]
fn s305_3_revoke_takes_effect_and_leaves_tombstone() {
    let r = Rig::new();
    r.standard_users();
    r.ok(&["admin", "grant", "u_a"]);
    let ha = r.console("sub-1", "a@example.test");
    assert_eq!(r.me(&ha).0, 200);
    let o = r.ok(&["admin", "revoke", "u_a"]);
    assert!(o.stdout.contains("revoked admin from u_a"), "{}", o.all());
    let (st, body) = r.me(&ha);
    assert_eq!(
        (st, body["error"].as_str()),
        (403, Some("not_admin")),
        "{body}"
    );
    // The session itself is live: only the grant ended.
    assert_eq!(
        r.sql()
            .query_row(
                "SELECT COUNT(*) FROM sessions WHERE user_id = 'u_a' AND terminated_at IS NULL",
                [],
                |x| x.get::<_, i64>(0)
            )
            .unwrap(),
        1
    );
    let g = r.grant("u_a").unwrap();
    assert!(g["revoked_at"].is_i64(), "{g}");
    assert_eq!(g["revoked_by"], "cli");
    assert_eq!(g["managed_by"], "api");
    let ev = r.events("admin.revoke");
    assert_eq!(ev.len(), 1, "{ev:?}");
    assert_eq!(ev[0]["attrs"]["actor"], "cli");
    assert_eq!(ev[0]["attrs"]["previous_role"], "admin");
    assert_eq!(ev[0]["user_id"], "u_a");
}

fn setup_list(r: &Rig) {
    r.standard_users();
    r.ok(&["admin", "grant", "u_a"]);
    r.ok(&[
        "admin",
        "grant",
        "h@example.test",
        "--role",
        "viewer",
        "--note",
        "ops rotation",
    ]);
    r.ok(&["admin", "grant", "v@example.test", "--confirm", "u_v"]);
    r.ok(&["admin", "revoke", "u_a"]);
}

#[test]
fn s305_4_list_shows_live_grants_and_all_shows_tombstones() {
    let r = Rig::new();
    setup_list(&r);
    let o = r.ok(&["admin", "list"]);
    let ls = lines_of(&o.stdout);
    assert_eq!(ls.len(), 3, "a header and two grants: {}", o.all());
    assert!(ls[0].starts_with("USER_ID  EMAIL  ROLE"), "{}", ls[0]);
    let h = ls
        .iter()
        .find(|l| l.starts_with("u_h  "))
        .expect("u_h line");
    assert!(
        h.starts_with("u_h  h@example.test  viewer  api  ") && h.ends_with("  cli  ops rotation"),
        "{h}"
    );
    let v = ls
        .iter()
        .find(|l| l.starts_with("u_v  "))
        .expect("u_v line");
    assert!(
        v.starts_with("u_v  v@example.test  admin  api  ") && v.ends_with("  cli  -"),
        "{v}"
    );
    assert!(!o.stdout.contains("u_a"), "{}", o.all());
    let o = r.ok(&["admin", "list", "--all"]);
    let a = lines_of(&o.stdout)
        .into_iter()
        .find(|l| l.starts_with("u_a  "))
        .expect("u_a tombstone line")
        .to_string();
    assert!(
        a.contains("  admin  api  ") && a.contains("  revoked ") && a.ends_with(" by cli"),
        "{a}"
    );
    assert_eq!(lines_of(&o.stdout).len(), 4, "{}", o.all());
}

#[test]
fn s305_5_regrant_clears_revocation_and_changes_role() {
    let r = Rig::new();
    r.standard_users();
    r.ok(&["admin", "grant", "u_a"]);
    let ha = r.console("sub-1", "a@example.test");
    assert_eq!(r.me(&ha).1["role"], "admin");
    r.ok(&["admin", "revoke", "u_a"]);
    assert_eq!(r.me(&ha).0, 403);
    r.ok(&["admin", "grant", "u_a", "--role", "viewer"]);
    let (st, body) = r.me(&ha);
    assert_eq!((st, body["role"].as_str()), (200, Some("viewer")), "{body}");
    let g = r.grant("u_a").unwrap();
    assert_eq!(g["role"], "viewer");
    assert!(g["revoked_at"].is_null(), "{g}");
    let ev = r.events("admin.grant");
    assert_eq!(ev.len(), 2, "{ev:?}");
    assert_eq!(ev[1]["attrs"]["previous_role"], "admin");
    r.ok(&["admin", "grant", "u_a"]);
    assert_eq!(r.me(&ha).1["role"], "admin");
    let g = r.grant("u_a").unwrap();
    assert_eq!(g["role"], "admin");
    let ev = r.events("admin.grant");
    assert_eq!(ev.len(), 3, "{ev:?}");
    assert_eq!(ev[2]["attrs"]["previous_role"], "viewer");
}

#[test]
fn s305_6_command_works_beside_running_instance() {
    let r = Rig::new();
    r.standard_users();
    r.h.hooks.stall(200);
    let t = Instant::now();
    let o = r.ok(&["admin", "grant", "u_v", "--role", "admin"]);
    assert!(t.elapsed() < Duration::from_secs(5), "{:?}", t.elapsed());
    assert!(o.stdout.contains("granted admin to u_v"), "{}", o.all());
    r.h.hooks.stall_off();
    // The instance still serves, still holds its lock, and sees the row.
    assert_eq!(get(r.h.portal, "/healthz").status, 200);
    assert_eq!(r.grant("u_v").unwrap()["role"], "admin");
    // The CLI did not take the lock: a second CLI run works while the instance holds it.
    r.ok(&["admin", "list"]);
}

#[test]
fn s305_7_recovery_when_every_administrator_is_gone() {
    let r = Rig::new();
    r.standard_users();
    r.user(
        "u_b",
        Some("b@example.test"),
        true,
        false,
        "active",
        "Bo B",
        &[("mock", "sub-b")],
        1_700_000_000,
    );
    let o = r.ok(&["admin", "list"]);
    assert_eq!(o.stdout.trim(), "", "{}", o.all());
    // u_d plays the disabled administrator.
    r.refused(&["admin", "grant", "u_d"], "user is disabled: enable first");
    assert!(r.grants().is_empty());
    let hb = r.console("sub-b", "b@example.test");
    assert_eq!(r.me(&hb).1["error"], "not_admin");
    let o = r.ok(&["admin", "grant", "u_b"]);
    assert!(o.stdout.contains("granted admin to u_b"), "{}", o.all());
    // u_b opens the console without a restart and enables the disabled user
    // (a console action, 301-5); then the disabled user can be granted.
    assert_eq!(r.me(&hb).1["role"], "admin");
    let e =
        r.h.admin_client()
            .with_handle(&hb)
            .post_json("/v1/users/u_d/enable", json!({}));
    assert_eq!(e.status, 200, "{e:?}");
    assert_eq!(e.json()["changed"], true, "{e:?}");
    r.ok(&["admin", "grant", "u_d"]);
}

#[test]
fn s305_8_grants_seeded_from_file_by_original_keys() {
    let r = Rig::new();
    let t = 1_700_000_000;
    r.user(
        "u_a",
        Some("a@example.test"),
        true,
        false,
        "active",
        "Alice",
        &[("mock", "sub-1")],
        t,
    );
    r.user(
        "u_v",
        Some("v@example.test"),
        true,
        false,
        "active",
        "Vera",
        &[("mock", "sub-v")],
        t,
    );
    r.user(
        "u_n",
        Some("n@example.test"),
        true,
        false,
        "active",
        "Nina",
        &[("mock", "sub-n")],
        t,
    );
    let entry_a = json!({"user_id": "u_a", "role": "admin", "note": "seed"});
    let entry_v = json!({"email": "v@example.test", "role": "viewer"});
    let entry_n = json!({"email": "n@example.test", "user_id": "u_n", "role": "viewer"});
    r.set_users(json!([entry_a, entry_v, entry_n]));
    // (a)
    let o = r.ok(&["admin", "import"]);
    let a = r.grant("u_a").unwrap();
    assert_eq!(
        (a["role"].as_str(), a["managed_by"].as_str()),
        (Some("admin"), Some("file"))
    );
    assert!(a["source_email"].is_null());
    assert_eq!(a["granted_by"], "file");
    let n = r.grant("u_n").unwrap();
    assert_eq!(
        (n["role"].as_str(), n["managed_by"].as_str()),
        (Some("viewer"), Some("file"))
    );
    assert_eq!(n["source_email"], "n@example.test");
    assert!(r.grant("u_v").is_none());
    let ev = r.events("admin.grant");
    assert_eq!(ev.len(), 2, "{ev:?}");
    for e in &ev {
        assert_eq!(e["attrs"]["actor"], "file", "{e}");
        assert_eq!(e["attrs"]["managed_by"], "file", "{e}");
    }
    assert!(
        o.stdout
            .contains("skipped (email_not_authoritative): v@example.test"),
        "{}",
        o.all()
    );
    let warn = "admin.users[1]: email_not_authoritative; add user_id to apply";
    assert!(o.stderr.contains(warn), "{}", o.all());
    let c = r.cli(&["--check"]);
    assert_eq!(c.status, 0, "{}", c.all());
    assert!(c.stderr.contains(warn), "{}", c.all());
    // (b)
    let o = r.ok(&["admin", "import"]);
    assert!(o.stdout.contains("unchanged: u_a, u_n"), "{}", o.all());
    assert_eq!(r.admin_events(), 2);
    // (c)
    r.set_users(json!([
        {"user_id": "u_a", "role": "viewer", "note": "seed"},
        entry_v
    ]));
    r.ok(&["admin", "import"]);
    assert_eq!(r.grant("u_a").unwrap()["role"], "viewer");
    let n = r.grant("u_n").unwrap();
    assert!(n["revoked_at"].is_i64(), "{n}");
    assert_eq!(n["revoked_by"], "file");
    let ev = r.events("admin.grant");
    assert_eq!(ev.last().unwrap()["attrs"]["previous_role"], "admin");
    let rv = r.events("admin.revoke");
    assert_eq!(rv.len(), 1, "{rv:?}");
    assert_eq!(rv[0]["attrs"]["actor"], "file");
    assert_eq!(rv[0]["user_id"], "u_n");
    // (d)
    r.ok(&["admin", "revoke", "u_a"]);
    let events = r.admin_events();
    let o = r.ok(&["admin", "import"]);
    assert!(
        o.stdout.contains("skipped (revoked at run time): u_a"),
        "{}",
        o.all()
    );
    assert!(r.grant("u_a").unwrap()["revoked_at"].is_i64());
    assert_eq!(r.admin_events(), events);
    // (e)
    r.ok(&["admin", "import", "--force", "u_a"]);
    let a = r.grant("u_a").unwrap();
    assert!(a["revoked_at"].is_null(), "{a}");
    assert_eq!(
        (a["role"].as_str(), a["managed_by"].as_str()),
        (Some("viewer"), Some("file"))
    );
    let ev = r.events("admin.grant");
    let last = ev.last().unwrap();
    assert_eq!(last["attrs"]["actor"], "file");
    assert_eq!(last["attrs"]["forced"], true);
    // (f)
    r.ok(&["admin", "grant", "u_n", "--role", "admin"]);
    r.set_users(json!([
        {"user_id": "u_a", "role": "viewer", "note": "seed"},
        entry_v,
        entry_n
    ]));
    let o = r.ok(&["admin", "import"]);
    assert!(
        o.stdout.contains("skipped (changed at run time): u_n"),
        "{}",
        o.all()
    );
    let n = r.grant("u_n").unwrap();
    assert_eq!(
        (n["role"].as_str(), n["managed_by"].as_str()),
        (Some("admin"), Some("api"))
    );
    // (g) a present but mismatched entry leaves a live file row alone.
    r.ok(&["admin", "import", "--force", "u_n"]);
    let n = r.grant("u_n").unwrap();
    assert_eq!(
        (n["role"].as_str(), n["managed_by"].as_str()),
        (Some("viewer"), Some("file"))
    );
    r.set_users(json!([
        {"user_id": "u_a", "role": "viewer", "note": "seed"},
        entry_v,
        {"user_id": "u_n", "email": "x@example.test", "role": "viewer"}
    ]));
    let events = r.admin_events();
    let o = r.ok(&["admin", "import"]);
    assert!(
        o.stdout.contains("skipped (user_email_mismatch): u_n"),
        "{}",
        o.all()
    );
    let n = r.grant("u_n").unwrap();
    assert!(
        n["revoked_at"].is_null(),
        "present entries are never revoked: {n}"
    );
    assert_eq!(n["role"], "viewer");
    assert_eq!(r.admin_events(), events);
    // (h) the corrected entry updates the row normally.
    r.set_users(json!([
        {"user_id": "u_a", "role": "viewer", "note": "seed"},
        entry_v,
        {"email": "n@example.test", "user_id": "u_n", "role": "admin"}
    ]));
    r.ok(&["admin", "import"]);
    let n = r.grant("u_n").unwrap();
    assert_eq!(n["role"], "admin");
    assert_eq!(n["managed_by"], "file");
    assert_eq!(r.admin_events(), events + 1);
}

// ---- 305-9: the migration guard through the binary -----------------------------

fn migrations_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src/store/migrations")
}

fn read(p: &Path) -> String {
    std::fs::read_to_string(p).unwrap()
}

fn record(c: &Connection, v: i64, name: &str) {
    c.execute(
        "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?1, ?2, 0)",
        rusqlite::params![v, name],
    )
    .unwrap();
}

fn base_db(path: &Path) -> Connection {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let c = Connection::open(path).unwrap();
    c.execute_batch(
        "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY NOT NULL, name TEXT NOT NULL, applied_at INTEGER NOT NULL) STRICT;",
    )
    .unwrap();
    c.execute_batch(&read(&migrations_dir().join("0001_meta.sql")))
        .unwrap();
    record(&c, 1, "0001_meta");
    c
}

fn v2_db(path: &Path) {
    let c = base_db(path);
    c.execute_batch(&read(&migrations_dir().join("0002_m1_schema.sql")))
        .unwrap();
    record(&c, 2, "0002_m1_schema");
}

fn pre_release_db(path: &Path) {
    let c = base_db(path);
    c.execute_batch(&read(
        &Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/pre_release_0002_m1_schema.sql"),
    ))
    .unwrap();
    record(&c, 2, "0002_m1_schema");
}

fn v3_without_grants_db(path: &Path) {
    v2_db(path);
    let c = Connection::open(path).unwrap();
    c.execute_batch(&read(&migrations_dir().join("0003_admin.sql")))
        .unwrap();
    record(&c, 3, "0003_admin");
    c.execute_batch("DROP TABLE admin_grants;").unwrap();
}

fn version_of(p: &Path) -> i64 {
    Connection::open(p)
        .unwrap()
        .query_row("SELECT MAX(version) FROM schema_migrations", [], |r| {
            r.get(0)
        })
        .unwrap()
}

fn has(p: &Path, kind: &str, name: &str) -> bool {
    Connection::open(p)
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = ?1 AND name = ?2",
            [kind, name],
            |r| r.get::<_, i64>(0),
        )
        .unwrap()
        > 0
}

struct Dirs {
    dir: tempfile::TempDir,
    cfg: PathBuf,
}

fn dirs() -> Dirs {
    let dir = tempfile::tempdir().unwrap();
    let idp = MockIdp::start("default");
    let mut v = Fixture::new("m4-admin").render(dir.path(), &idp);
    v["listen"]["admin"] = json!("127.0.0.1:0");
    let cfg = dir.path().join("hopae.json");
    std::fs::write(&cfg, serde_json::to_vec_pretty(&v).unwrap()).unwrap();
    Dirs { dir, cfg }
}

impl Dirs {
    fn state(&self) -> PathBuf {
        self.dir.path().join("state")
    }

    fn db(&self) -> PathBuf {
        self.state().join("hopae.db")
    }

    fn bak(&self) -> PathBuf {
        self.state().join("hopae.db.bak-v2")
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_hopae"));
        c.args(args)
            .arg("--config")
            .arg(&self.cfg)
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("HOPAE_TEST_GATEWAY_KEY", GW_KEY)
            .env("HOPAE_TEST_MOCK_SECRET", MOCK_SECRET);
        c
    }

    fn run(&self, args: &[&str]) -> (i32, String, String) {
        let o = self.command(args).output().unwrap();
        (
            o.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&o.stdout).into_owned(),
            String::from_utf8_lossy(&o.stderr).into_owned(),
        )
    }

    /// Start `hopae run`, wait for the gateway line, stop it with SIGTERM.
    fn start_and_stop(&self) -> Option<i32> {
        let mut child = self
            .command(&["run"])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let out = child.stdout.take().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(out).lines().map_while(Result::ok) {
                if line.starts_with("gateway listening on ") {
                    let _ = tx.send(());
                }
            }
        });
        let ready = rx.recv_timeout(Duration::from_secs(30)).is_ok();
        let _ = Command::new("kill")
            .arg("-TERM")
            .arg(child.id().to_string())
            .status();
        let deadline = Instant::now() + Duration::from_secs(10);
        let code = loop {
            if let Some(s) = child.try_wait().unwrap() {
                break s.code();
            }
            if Instant::now() > deadline {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            std::thread::sleep(Duration::from_millis(25));
        };
        assert!(ready, "hopae did not come up");
        code
    }

    fn tmp_files(&self) -> Vec<String> {
        std::fs::read_dir(self.state())
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".tmp"))
            .collect()
    }
}

#[test]
fn s305_9_schema_v3_only_on_validated_foundation_and_no_backup_before() {
    // (1) a current version-2 database beside an older backup.
    let d = dirs();
    v2_db(&d.db());
    std::fs::write(d.bak(), b"old backup content").unwrap();
    assert_eq!(d.start_and_stop(), Some(0));
    assert_eq!(version_of(&d.db()), 3);
    let bak = std::fs::read(d.bak()).unwrap();
    assert_ne!(bak, b"old backup content", "the backup was replaced");
    assert_eq!(version_of(&d.bak()), 2, "the new backup holds version 2");
    assert!(d.tmp_files().is_empty(), "{:?}", d.tmp_files());
    for (k, n) in [
        ("table", "admin_grants"),
        ("index", "events_session_at_id"),
        ("index", "admin_grants_source_email"),
    ] {
        assert!(has(&d.db(), k, n), "{n}");
    }
    let c = Connection::open(d.db()).unwrap();
    let col = |t: &str, c0: &str| -> bool {
        c.prepare(&format!("PRAGMA table_info({t})"))
            .unwrap()
            .query_map([], |r| r.get::<_, String>(1))
            .unwrap()
            .any(|n| n.unwrap() == c0)
    };
    assert!(col("sessions", "bound_ua_prefix") && col("sessions", "auth_time_source"));
    assert!(col("login_txns", "reauth_max_age"));

    // (2) the pre-release version-2 fixture, also beside a backup.
    let d = dirs();
    pre_release_db(&d.db());
    std::fs::write(d.bak(), b"known backup bytes").unwrap();
    let db_before = std::fs::read(d.db()).unwrap();
    let (code, _o, e) = d.run(&["run"]);
    assert_eq!(code, 2, "{e}");
    let check = |what: &str| {
        assert_eq!(version_of(&d.db()), 2, "{what}");
        assert!(!has(&d.db(), "table", "admin_grants"), "{what}");
        assert!(!has(&d.db(), "index", "events_session_at_id"), "{what}");
        assert_eq!(
            std::fs::read(d.bak()).unwrap(),
            b"known backup bytes",
            "{what}"
        );
        assert!(d.tmp_files().is_empty(), "{what}: {:?}", d.tmp_files());
    };
    check("after run");
    let (code, _o, e) = d.run(&["admin", "list"]);
    assert_eq!(code, 2, "{e}");
    check("after admin list");
    let _ = db_before;

    // (3) a version-3 database whose admin_grants was dropped by hand.
    let d = dirs();
    v3_without_grants_db(&d.db());
    let (code, _o, e) = d.run(&["run"]);
    assert_eq!(code, 2, "{e}");
    assert!(e.contains("admin_grants"), "{e}");
    assert_eq!(version_of(&d.db()), 3);
    let (code, _o, e) = d.run(&["admin", "list"]);
    assert_eq!(code, 2, "{e}");
    assert!(e.contains("admin_grants"), "{e}");
    assert_eq!(version_of(&d.db()), 3);

    // (4) the command never migrates: an older database is refused.
    let d = dirs();
    v2_db(&d.db());
    let (code, _o, e) = d.run(&["admin", "list"]);
    assert_eq!(code, 2, "{e}");
    assert!(e.contains("start the instance once to migrate"), "{e}");
    assert_eq!(version_of(&d.db()), 2);
    assert!(!d.bak().exists(), "the command never writes a backup");
}

// ---- alternative flows and abuse cases -----------------------------------------

#[test]
fn s305_a1_repeating_a_grant_is_a_noop() {
    let r = Rig::new();
    r.standard_users();
    r.ok(&["admin", "grant", "v@example.test", "--confirm", "u_v"]);
    let n = r.admin_events();
    let o = r.ok(&["admin", "grant", "v@example.test", "--confirm", "u_v"]);
    assert!(o.stdout.contains("unchanged"), "{}", o.all());
    assert_eq!(r.admin_events(), n);
    let o = r.ok(&["admin", "revoke", "u_v"]);
    assert!(o.stdout.contains("revoked admin from u_v"), "{}", o.all());
    assert_eq!(r.admin_events(), n + 1);
    let o = r.ok(&["admin", "revoke", "u_v"]);
    assert!(o.stdout.contains("already revoked"), "{}", o.all());
    assert_eq!(r.admin_events(), n + 1);
}

#[test]
fn s305_a2_malformed_identifiers_addresses_and_entries() {
    let r = Rig::new();
    r.standard_users();
    let long = "x".repeat(2048);
    let cases: Vec<(Vec<&str>, &str)> = vec![
        (vec!["admin", "grant", "u_a; DROP TABLE users"], "target"),
        (vec!["admin", "grant", ""], "target"),
        (
            vec!["admin", "grant", "a@example.test@evil.example.org"],
            "target",
        ),
        (vec!["admin", "grant", "u_a", "--role", "root"], "--role"),
        (vec!["admin", "grant", "u_a", "--note", &long], "--note"),
        (
            vec!["admin", "grant", "u_a", "--confirm", "u_a OR 1=1"],
            "--confirm",
        ),
    ];
    for (args, needle) in cases {
        let o = r.cli(&args);
        assert_eq!(o.status, 2, "{}", o.all());
        assert!(o.stderr.contains(needle), "{needle}: {}", o.all());
        let low = o.all().to_lowercase();
        assert!(
            !low.contains("sqlite") && !low.contains("rusqlite") && !low.contains("syntax error"),
            "{}",
            o.all()
        );
    }
    assert!(r.grants().is_empty());
    // A note of exactly 256 characters is accepted and sanitized like event attributes.
    let ok_note = format!("{}\u{7}x", "n".repeat(100));
    r.ok(&["admin", "grant", "u_a", "--note", &ok_note]);
    let note = r.grant("u_a").unwrap()["note"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(!note.contains('\u{7}'), "{note:?}");
    // The files.
    for (users, strict_only) in [
        (json!([{"role": "admin"}]), false),
        (json!([{"user_id": "u_a", "role": "root"}]), false),
        (json!([{"email": "a@b@c"}]), false),
        (json!([{"user_id": "u_a", "email": "h@example.test"}]), true),
    ] {
        r.set_users(users.clone());
        let c = r.cli(&["--check"]);
        let i = r.cli(&["admin", "import"]);
        if strict_only {
            // A mismatch is a warning and a skip, an error under --strict.
            assert_eq!(c.status, 0, "{users}: {}", c.all());
            assert!(c.stderr.contains("user_email_mismatch"), "{}", c.all());
            let s = r.cli(&["--check", "--strict"]);
            assert_eq!(s.status, 2, "{users}: {}", s.all());
            assert_eq!(i.status, 0, "{users}: {}", i.all());
            assert!(i.stdout.contains("user_email_mismatch"), "{}", i.all());
        } else {
            assert_eq!(c.status, 2, "{users}: {}", c.all());
            assert_eq!(i.status, 2, "{users}: {}", i.all());
        }
    }
    // Only the 256-character-capped grant above exists.
    assert_eq!(r.grants().len(), 1);
}

#[test]
fn s305_a3_grant_and_revoke_racing_each_other_and_console() {
    let r = Rig::new();
    r.standard_users();
    r.ok(&["admin", "grant", "u_a"]);
    let h = &r.h;
    let (a, b) = std::thread::scope(|s| {
        let t1 = s.spawn(|| h.cli(&["admin", "revoke", "u_a"]));
        let t2 = s.spawn(|| h.cli(&["admin", "grant", "u_a"]));
        (t1.join().unwrap(), t2.join().unwrap())
    });
    assert_eq!((a.status, b.status), (0, 0), "{} {}", a.all(), b.all());
    // The final row equals the last committed command; events follow commit order.
    let mut ev: Vec<Value> = r.events("admin.grant");
    ev.extend(r.events("admin.revoke"));
    ev.sort_by(|x, y| {
        x["at"]
            .as_f64()
            .partial_cmp(&y["at"].as_f64())
            .unwrap()
            .then(x["event_id"].as_str().cmp(&y["event_id"].as_str()))
    });
    let last = ev.last().unwrap()["kind"].as_str().unwrap().to_string();
    let g = r.grant("u_a").unwrap();
    assert_eq!(
        g["revoked_at"].is_null(),
        last == "admin.grant",
        "row {g} vs last event {last}"
    );
    // Revoke-then-grant gives grant, revoke, grant; grant-then-revoke gives grant, revoke.
    assert!(ev.len() == 2 || ev.len() == 3, "{ev:?}");

    // The console mutation of the scenario: in flight (held between its check
    // and its write) while the command revokes the actor; the fenced write
    // re-reads the grant and refuses.
    r.ok(&["admin", "grant", "u_a"]);
    let ha = r.console("sub-1", "a@example.test");
    assert_eq!(r.me(&ha).1["role"], "admin");
    h.hooks.hold("admin_mutation");
    let refused = std::thread::scope(|s| {
        let w = s.spawn(|| {
            h.admin_client()
                .with_handle(&ha)
                .post_json("/v1/users/u_h/disable", json!({}))
        });
        std::thread::sleep(Duration::from_millis(500));
        let o = h.cli(&["admin", "revoke", "u_a"]);
        assert_eq!(o.status, 0, "{}", o.all());
        h.hooks.release("admin_mutation");
        w.join().unwrap()
    });
    assert_eq!(refused.status, 403, "{refused:?}");
    assert_eq!(refused.json()["error"], "actor_revoked", "{refused:?}");
    let status: String = r
        .db()
        .query_row("SELECT status FROM users WHERE user_id = 'u_h'", [], |x| {
            x.get(0)
        })
        .unwrap();
    assert_eq!(status, "active");
    assert!(r.events("admin.user_disable").is_empty());
    assert_eq!(r.events("admin.denied").len(), 1);
}

#[test]
fn s305_a4_email_grant_not_hijacked_by_claim_stale_account_reassigned_mailbox_or_revoked_binding() {
    let r = Rig::new();
    r.standard_users();
    let t = 1_700_000_000;
    // (a) the grant resolves to the existing user; no user is created.
    let n = r.users_count();
    r.ok(&["admin", "grant", "v@example.test", "--confirm", "u_v"]);
    assert_eq!(r.grant("u_v").unwrap()["user_id"], "u_v");
    assert_eq!(r.users_count(), n);
    // (b) a stale account: the operator sees it and must confirm it.
    r.user(
        "u_old",
        Some("ops@example.test"),
        true,
        false,
        "active",
        "Old Ops",
        &[("mock2", "sub-old")],
        t - 86_400 * 700,
    );
    let o = r.refused(&["admin", "grant", "ops@example.test"], "--confirm u_old");
    assert!(o.stdout.contains("mock2:sub-old"), "{}", o.all());
    assert!(o.stdout.contains("not authoritative"), "{}", o.all());
    assert!(o.stdout.contains("created_at "), "{}", o.all());
    assert!(r.grant("u_old").is_none());
    r.ok(&["admin", "grant", "ops@example.test", "--confirm", "u_old"]);
    assert_eq!(r.grant("u_old").unwrap()["user_id"], "u_old");
    // (c) a file entry by email stays bound to the user it first resolved to.
    r.set_users(json!([{"email": "h@example.test", "role": "admin"}]));
    r.ok(&["admin", "import"]);
    assert_eq!(r.grant("u_h").unwrap()["source_email"], "h@example.test");
    r.db()
        .execute(
            "UPDATE users SET primary_email = 'h-old@example.test' WHERE user_id = 'u_h'",
            [],
        )
        .unwrap();
    r.user(
        "u_h2",
        Some("h@example.test"),
        true,
        true,
        "active",
        "Hana Two",
        &[("mock", "sub-h2")],
        t,
    );
    let o = r.ok(&["admin", "import"]);
    assert!(r.grant("u_h2").is_none(), "{}", o.all());
    assert_eq!(r.grant("u_h").unwrap()["role"], "admin");
    let c = r.cli(&["--check"]);
    assert!(
        c.stderr.contains(
            "admin.users[0]: h@example.test now belongs to u_h2; the grant stays bound to u_h"
        ),
        "{}",
        c.all()
    );
    let o = r.ok(&["admin", "import", "--force", "h@example.test"]);
    assert!(o.stdout.contains("u_h"), "{}", o.all());
    assert!(r.grant("u_h2").is_none());
    // (d) the tombstone keeps its binding.
    r.ok(&["admin", "revoke", "u_h"]);
    let tomb = r.grant("u_h").unwrap();
    assert_eq!(tomb["source_email"], "h@example.test");
    assert_eq!(tomb["managed_by"], "api");
    let o = r.ok(&["admin", "import"]);
    assert!(
        o.stdout
            .contains("skipped (revoked at run time): h@example.test \u{2192} u_h"),
        "{}",
        o.all()
    );
    assert!(r.grant("u_h2").is_none());
    assert!(r.grant("u_h").unwrap()["revoked_at"].is_i64());
    r.ok(&["admin", "import", "--force", "h@example.test"]);
    let g = r.grant("u_h").unwrap();
    assert!(g["revoked_at"].is_null(), "{g}");
    assert_eq!(g["managed_by"], "file");
    assert!(r.grant("u_h2").is_none());
    r.ok(&["admin", "revoke", "u_h"]);
    r.ok(&["admin", "import", "--force", "u_h"]);
    let g = r.grant("u_h").unwrap();
    assert!(
        g["revoked_at"].is_null() && g["managed_by"] == "file",
        "{g}"
    );
    assert!(r.grant("u_h2").is_none());
    // (e) two rows bound through the address: ambiguous.
    r.ok(&["admin", "grant", "h@example.test", "--confirm", "u_h2"]);
    assert_eq!(r.grant("u_h2").unwrap()["source_email"], "h@example.test");
    let before = (r.grants(), r.admin_events());
    let o = r.ok(&["admin", "import"]);
    assert!(
        o.stdout
            .contains("skipped (email_binding_ambiguous): h@example.test \u{2192} u_h, u_h2"),
        "{}",
        o.all()
    );
    assert_eq!((r.grants(), r.admin_events()), before);
    r.refused(
        &["admin", "import", "--force", "h@example.test"],
        "ambiguous binding; use --force <user_id>",
    );
    assert_eq!((r.grants(), r.admin_events()), before);
}

#[test]
fn s305_a5_command_reveals_nothing_beyond_own_store() {
    let r = Rig::new();
    r.standard_users();
    r.refused(
        &["admin", "grant", "unknown@example.test"],
        "no such user: sign in once first",
    );
    r.refused(
        &["admin", "grant", "u_doesnotexist"],
        "no such user: sign in once first",
    );
    assert!(r.grants().is_empty());
}

#[test]
fn s305_a6_file_cannot_resurrect_revoke_present_or_grant_ambiguous() {
    let mut r = Rig::new();
    let t = 1_700_000_000;
    r.user(
        "u_a",
        Some("a@example.test"),
        true,
        false,
        "active",
        "Alice",
        &[("mock", "sub-1")],
        t,
    );
    r.user(
        "u_p",
        Some("p@example.test"),
        true,
        false,
        "active",
        "Pat",
        &[("mock", "sub-p")],
        t,
    );
    // u_q's identity carries the same address but it is not the primary email.
    r.user(
        "u_q",
        None,
        false,
        false,
        "active",
        "Quin",
        &[("mock", "sub-q")],
        t,
    );
    r.db()
        .execute(
            "UPDATE identities SET email = 'p@example.test', email_verified = 1 WHERE user_id = 'u_q'",
            [],
        )
        .unwrap();
    r.user(
        "u_r",
        Some("r@example.test"),
        false,
        false,
        "active",
        "Rae",
        &[("mock", "sub-r")],
        t,
    );
    r.user(
        "u_s",
        Some("s@example.test"),
        true,
        false,
        "active",
        "Sam",
        &[("mock", "sub-s")],
        t,
    );
    // u_a: granted by the file, then revoked at run time. u_s: a live file row.
    r.set_users(json!([{"user_id": "u_a"}, {"user_id": "u_s"}]));
    r.ok(&["admin", "import"]);
    r.ok(&["admin", "revoke", "u_a"]);
    let events = r.admin_events();
    r.set_users(json!([
        {"user_id": "u_a"},
        {"email": "p@example.test"},
        {"email": "r@example.test"},
        {"user_id": "u_s", "email": "p@example.test"}
    ]));
    r.h.restart();
    let log = r.h.log();
    for needle in [
        "revoked at run time",
        "admin.users[1]: email_not_authoritative",
        "admin.users[2]: email_unverified",
        "admin.users[3]: user_email_mismatch",
    ] {
        assert!(log.contains(needle), "{needle}\n{log}");
    }
    assert!(r.grant("u_a").unwrap()["revoked_at"].is_i64());
    for u in ["u_p", "u_q", "u_r"] {
        assert!(r.grant(u).is_none(), "{u}");
    }
    let s = r.grant("u_s").unwrap();
    assert!(s["revoked_at"].is_null(), "{s}");
    assert_eq!(r.admin_events(), events, "no event for any skipped entry");
    let c = r.cli(&["--check"]);
    assert_eq!(c.status, 0, "{}", c.all());
    for needle in [
        "admin.users[1]: email_not_authoritative",
        "admin.users[2]: email_unverified",
        "admin.users[3]: user_email_mismatch",
    ] {
        assert!(c.stderr.contains(needle), "{needle}\n{}", c.all());
    }
    let c = r.cli(&["--check", "--strict"]);
    assert_eq!(c.status, 2, "{}", c.all());
}
