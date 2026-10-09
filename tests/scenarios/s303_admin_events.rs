//! Scenario 303: console login history and audit browsing.
//!
//! The tests drive the real binary over the admin listener. The event table
//! is filled with SQL (and the console's own mutations); `kit` is shared with
//! 301.
#![allow(dead_code)]

use serde_json::{Value, json};

use super::s301_admin_users::kit::{self, Console, code};
use hopae::store::types::AdminRole;

const KINDS: [(&str, &str); 9] = [
    ("login.started", "info"),
    ("login.succeeded", "success"),
    ("login.failed", "failure"),
    ("session.created", "success"),
    ("session.handoff", "success"),
    ("handoff.rejected", "failure"),
    ("session.terminated", "info"),
    ("verify.denied", "failure"),
    ("csrf.rejected", "failure"),
];

/// What the generated table holds, for the expected counts.
struct Seed {
    now: i64,
    /// Rows of `u_x`, of the address, of `s_1`.
    u_x: usize,
    ip: usize,
    s_1: usize,
    /// `login.failed` rows of `u_x`.
    u_x_failed: usize,
    /// Rows by kind (generated rows only).
    by_kind: [usize; 9],
}

/// 5,000 events over 48 hours: 300 of `u_x`, 120 from `203.0.113.9`, 40 of `s_1`.
fn seed_events(k: &Console) -> Seed {
    let now = k.now_s();
    k.add_user("u_x", "x@example.test", "Ex");
    let mut seed = Seed {
        now,
        u_x: 0,
        ip: 0,
        s_1: 0,
        u_x_failed: 0,
        by_kind: [0; 9],
    };
    let mut c = k.sql();
    let tx = c.transaction().unwrap();
    {
        let mut st = tx
            .prepare(
                "INSERT INTO events (event_id, at, kind, outcome, reason, user_id, session_id, client_ip, ua_prefix, request_id, attrs) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'r_seed', '{}')",
            )
            .unwrap();
        for i in 0..5000usize {
            let at = (now - 10) as f64 - (i as f64) * (48.0 * 3600.0 / 5000.0);
            let (kind, outcome) = KINDS[i % 9];
            seed.by_kind[i % 9] += 1;
            let user = (i % 16 == 0 && seed.u_x < 300).then(|| {
                seed.u_x += 1;
                "u_x"
            });
            let session = (user.is_some() && seed.s_1 < 40).then(|| {
                seed.s_1 += 1;
                "s_1"
            });
            let ip = (i % 41 == 3 && seed.ip < 120).then(|| {
                seed.ip += 1;
                "203.0.113.9"
            });
            if user.is_some() && kind == "login.failed" {
                seed.u_x_failed += 1;
            }
            let reason = (kind == "login.failed").then_some(if i % 2 == 0 {
                "invalid_state"
            } else {
                "provider_unavailable"
            });
            st.execute(rusqlite::params![
                format!("e_seed{i:010}"),
                at,
                kind,
                outcome,
                reason,
                user,
                session,
                ip,
                ip.map(|_| "Mozilla/5.0 (X11; Linux)")
            ])
            .unwrap();
        }
    }
    tx.commit().unwrap();
    seed
}

fn total_events(k: &Console) -> usize {
    k.count("SELECT COUNT(*) FROM events") as usize
}

fn eid(v: &Value) -> String {
    v["event_id"].as_str().expect("event_id").to_string()
}

fn enc(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

#[test]
fn s303_1_unfiltered_newest_first_in_pages() {
    let k = Console::new();
    let a = k.admin("sub-a", AdminRole::Admin);
    seed_events(&k);
    let cl = k.client(&a);
    let r = cl.get("/v1/events");
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(r.json()["items"].as_array().unwrap().len(), 50);
    let total = total_events(&k);
    let all = cl.walk_rows("/v1/events", total);
    let mut ids: Vec<String> = all.iter().map(eid).collect();
    assert_eq!(ids.len(), total, "the union is the table");
    let key = |v: &Value| (v["at"].as_f64().unwrap(), eid(v));
    assert!(
        all.windows(2)
            .all(|w| key(&w[0]).partial_cmp(&key(&w[1])) != Some(std::cmp::Ordering::Less)),
        "at DESC, event_id DESC"
    );
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), total, "each event once");
    for f in [
        "event_id",
        "at",
        "kind",
        "outcome",
        "reason",
        "user_id",
        "session_id",
        "app_id",
        "provider_id",
        "client_ip",
        "ua_prefix",
        "ua_sha256",
        "request_id",
        "attrs",
    ] {
        assert!(all[0].get(f).is_some(), "{f}");
    }
    let p = cl.get("/events");
    assert_eq!(p.status, 200);
    for i in all.iter().take(50) {
        assert!(p.body.contains(&eid(i)), "{} on the page", eid(i));
    }
    for w in ["login", "success", "rel=\"next\""] {
        assert!(p.body.contains(w), "{w}");
    }
    let e = k.h.hooks.explain("events", true);
    assert!(e["plan"].to_string().contains("events_at_id"), "{e}");
}

#[test]
fn s303_2_filters_choose_one_index_and_apply_rest_inside_window() {
    let k = Console::new();
    let a = k.admin("sub-a", AdminRole::Admin);
    let seed = seed_events(&k);
    let cl = k.client(&a);
    let n = |path: &str| cl.walk(path).len();
    assert_eq!(n("/v1/events?user_id=u_x"), seed.u_x);
    assert_eq!(n("/v1/events?client_ip=203.0.113.9"), seed.ip);
    assert_eq!(n("/v1/events?session_id=s_1"), seed.s_1);
    let failed = k.count("SELECT COUNT(*) FROM events WHERE kind = 'login.failed'") as usize;
    assert_eq!(n("/v1/events?kind=login.failed"), failed);
    assert_eq!(
        n("/v1/events?kind=login.failed&outcome=failure&user_id=u_x"),
        seed.u_x_failed,
        "the intersection"
    );
    let (t1, t2) = (seed.now - 30 * 3600, seed.now - 24 * 3600);
    let in_window = k.count(&format!(
        "SELECT COUNT(*) FROM events WHERE at >= {t1} AND at <= {t2}"
    )) as usize;
    assert!(in_window > 100);
    assert_eq!(n(&format!("/v1/events?since={t1}&until={t2}")), in_window);
    let failures = k.count("SELECT COUNT(*) FROM events WHERE outcome = 'failure'") as usize;
    assert_eq!(n("/v1/events?outcome=failure"), failures);
    // A recorded administrative action is found by its kind.
    assert_eq!(cl.post_json("/v1/users/u_x/disable", json!({})).status, 200);
    assert_eq!(n("/v1/events?kind=admin.user_disable"), 1);
    // The index of each shape; with several filters the priority decides.
    for (q, ix) in [
        ("events&index=user", "events_user_at_id"),
        ("events&index=ip", "events_ip_at_id"),
        ("events&index=kind", "events_kind_at_id"),
        ("events&index=session", "events_session_at_id"),
        ("events&index=time", "events_at_id"),
    ] {
        let e = k.h.hooks.explain(q, true);
        let plan = e["plan"].to_string();
        assert!(plan.contains(ix), "{q}: {plan}");
        assert!(
            plan.contains("INDEXED") || plan.contains("USING INDEX"),
            "{plan}"
        );
    }
    use hopae::event::types::{EventKind, Outcome};
    use hopae::identity::types::UserId;
    use hopae::session::types::SessionId;
    use hopae::store::types::{EventsIndex, EventsQuery};
    let q = EventsQuery {
        kind: Some(EventKind::LoginFailed),
        outcome: Some(Outcome::Failure),
        user_id: Some(UserId::new("u_x")),
        session_id: Some(SessionId::new("s_1")),
        client_ip: Some("203.0.113.9".parse().unwrap()),
        ..EventsQuery::default()
    };
    assert_eq!(q.index(), EventsIndex::Session);
    let q = EventsQuery {
        outcome: Some(Outcome::Failure),
        ..EventsQuery::default()
    };
    assert_eq!(
        q.index(),
        EventsIndex::Time,
        "an outcome-only filter scans by time"
    );
    // `reason` is not a filter: it is ignored.
    assert_eq!(n("/v1/events?reason=invalid_state"), total_events(&k));
}

#[test]
fn s303_3_cursors_stable_under_inserts_and_advance_past_examined() {
    let k = Console::new();
    let a = k.admin("sub-a", AdminRole::Admin);
    let seed = seed_events(&k);
    let cl = k.client(&a);
    let total = total_events(&k);
    let p1 = cl.get("/v1/events?limit=50").json();
    let first: Vec<String> = p1["items"].as_array().unwrap().iter().map(eid).collect();
    let cursor = p1["next_cursor"].as_str().unwrap().to_string();
    // 200 new events arrive.
    k.add_events(
        "new",
        200,
        "login.started",
        "info",
        None,
        None,
        None,
        seed.now + 100,
    );
    let rest = kit::walk_from(&cl, "/v1/events", Some(&cursor));
    let ids: Vec<String> = rest.iter().map(eid).collect();
    assert_eq!(ids.len(), total - 50, "nothing skipped");
    assert!(
        ids.iter().all(|i| !first.contains(i)),
        "no repeat of page 1"
    );
    assert!(
        ids.iter().all(|i| !i.starts_with("e_kitnew")),
        "the new events are not in this walk"
    );
    let fresh = cl.get("/v1/events?limit=1").json();
    assert!(
        eid(&fresh["items"][0]).starts_with("e_kitnew"),
        "a fresh walk shows them first"
    );
    // A combination with no match and fewer than a window of candidates ends at once.
    let r = cl
        .get("/v1/events?kind=login.succeeded&outcome=failure")
        .json();
    assert!(r["items"].as_array().unwrap().is_empty());
    assert!(r["next_cursor"].is_null());
    // More than a window of candidates: an empty page with a cursor, then the end.
    k.h.hooks.bulk_events(25_000, 24.0);
    let series = "hopae_admin_rows_examined_total{list=\"events\"}";
    let before = k.metric(series);
    let r = cl
        .get("/v1/events?kind=login.started&outcome=failure")
        .json();
    assert!(r["items"].as_array().unwrap().is_empty());
    assert!(
        r["next_cursor"].is_string(),
        "the cursor passes the examined candidates"
    );
    assert_eq!(k.metric(series) - before, 10_000);
    let candidates = k.count("SELECT COUNT(*) FROM events WHERE kind = 'login.started'") as usize;
    let pages = kit::walk_pages(&cl, "/v1/events?kind=login.started&outcome=failure");
    assert!(
        pages <= candidates.div_ceil(10_000) + 1,
        "{pages} pages for {candidates} candidates"
    );
}

#[test]
fn s303_4_admin_actions_show_their_actor() {
    let k = Console::new();
    let a = k.admin("sub-a", AdminRole::Admin);
    k.add_user("u_x", "x@example.test", "Ex");
    let now = k.now_s();
    for i in 0..4 {
        k.add_session(
            &format!("s_x{i}"),
            "u_x",
            now - 10 - i,
            "192.0.2.10",
            None,
            &["app.example.test"],
            None,
            None,
        );
    }
    let cl = k.client(&a);
    assert_eq!(cl.post_json("/v1/users/u_x/disable", json!({})).status, 200);
    let r = cl
        .get("/v1/events?user_id=u_x&kind=admin.user_disable")
        .json();
    let items = r["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["user_id"], "u_x");
    assert_eq!(items[0]["attrs"]["actor"], a.user_id.as_str());
    assert!(items[0]["attrs"]["actor_session"].is_string());
    assert_eq!(items[0]["attrs"]["count"], 4);
    // The grant of the command line.
    let g = cl.get("/v1/events?kind=admin.grant").json();
    let g = g["items"].as_array().unwrap();
    assert!(!g.is_empty());
    assert_eq!(g[0]["attrs"]["actor"], "cli");
    assert_eq!(g[0]["attrs"]["role"], "admin");
    assert_eq!(g[0]["attrs"]["managed_by"], "api");
    // The user page's recent events: "by <actor>" linking the actor's page.
    let p = cl.get("/users/u_x");
    assert!(p.body.contains("admin.user_disable"));
    assert!(
        p.body.contains(&format!("href=\"/users/{}\"", a.user_id)),
        "the actor is linked"
    );
    assert!(p.body.contains("by <a"), "rendered as `by <actor>`");
}

#[test]
fn s303_5_rows_never_contain_credentials() {
    let k = Console::new();
    let a = k.admin("sub-a", AdminRole::Admin);
    let _b = k.admin("sub-b", AdminRole::Viewer);
    // A rejected form and a denial, for csrf.rejected-like and admin.denied rows.
    let _ = k.client(&a).post_form(
        "/users/u_none/disable",
        &[("csrf", "forged")],
        Some(&k.origin()),
    );
    seed_events(&k);
    let cl = k.client(&a);
    let total = total_events(&k);
    let api = cl.walk_rows("/v1/events", total);
    let mut body = serde_json::to_string(&api).unwrap();
    let mut page_ok = 0;
    let mut cursor: Option<String> = None;
    loop {
        let url = match &cursor {
            None => "/events?limit=200".to_string(),
            Some(c) => format!("/events?limit=200&cursor={}", enc(c)),
        };
        let p = cl.get(&url);
        assert_eq!(p.status, 200);
        body.push_str(&p.body);
        page_ok += 1;
        // The next link is the only place the cursor shows.
        cursor = p
            .body
            .split("href=\"")
            .filter_map(|l| l.split('"').next())
            .find(|l| l.contains("cursor="))
            .and_then(|l| url::Url::parse(&format!("http://x{}", l.replace("&amp;", "&"))).ok())
            .and_then(|u| {
                u.query_pairs()
                    .find(|(k, _)| k == "cursor")
                    .map(|(_, v)| v.into_owned())
            });
        if cursor.is_none() || page_ok > 100 {
            break;
        }
    }
    let mut secrets: Vec<String> = k.h.secret_values();
    secrets.extend(k.idp.issued_secrets().into_iter().map(|(_, v)| v));
    secrets.push(a.handle.clone());
    secrets.retain(|s| s.len() >= 8);
    assert!(!secrets.is_empty());
    for s in &secrets {
        assert!(
            !body.contains(s.as_str()),
            "a secret of {} bytes appears",
            s.len()
        );
    }
    // User agents appear only as the sanitized prefix and the digest.
    for i in &api {
        if let Some(p) = i["ua_prefix"].as_str() {
            assert!(p.len() <= 64);
        }
    }
}

#[test]
fn s303_6_time_filters_accept_seconds_refuse_nonsense() {
    let k = Console::new();
    let a = k.admin("sub-a", AdminRole::Admin);
    let cl = k.client(&a);
    let now = k.now_s();
    for q in [
        format!("since={}&until={}", now, now - 100),
        "since=abc".to_string(),
        "since=-1".to_string(),
        "until=1.5".to_string(),
    ] {
        let r = cl.get(&format!("/v1/events?{q}"));
        assert_eq!(
            (r.status, code(&r).as_str()),
            (400, "invalid_filter"),
            "{q}"
        );
    }
    let r = cl.get(&format!("/v1/events?until={}", now + 365 * 86_400));
    assert_eq!(
        r.status, 200,
        "an upper bound in the future is a no-op: {}",
        r.body
    );
    assert!(!r.json()["items"].as_array().unwrap().is_empty());
    let r = cl.get(&format!(
        "/v1/events?since={}&until={}",
        now - 1000,
        now + 1000
    ));
    assert_eq!(r.status, 200);
}

#[test]
fn s303_a1_cursor_outlives_pruned_rows() {
    let k = Console::new();
    let a = k.admin("sub-a", AdminRole::Admin);
    let seed = seed_events(&k);
    let cl = k.client(&a);
    let mut cursor = String::new();
    let mut r = cl.get("/v1/events?limit=200").json();
    for _ in 0..5 {
        cursor = r["next_cursor"].as_str().unwrap().to_string();
        r = cl
            .get(&format!("/v1/events?limit=200&cursor={}", enc(&cursor)))
            .json();
    }
    // The prune removes everything older than 36 hours and the oldest 500.
    k.sql()
        .execute(
            "DELETE FROM events WHERE at < ?1",
            [seed.now as f64 - 36.0 * 3600.0],
        )
        .unwrap();
    let r = cl.get(&format!("/v1/events?limit=200&cursor={}", enc(&cursor)));
    assert_eq!(r.status, 200, "{}", r.body);
    assert!(!r.json()["items"].as_array().unwrap().is_empty());
    // A cursor from one filter is a valid position under another.
    let r = cl.get(&format!(
        "/v1/events?kind=login.failed&cursor={}",
        enc(&cursor)
    ));
    assert_eq!(r.status, 200, "{}", r.body);
}

#[test]
fn s303_a2_forged_cursors_and_filter_injection() {
    let k = Console::new();
    let a = k.admin("sub-a", AdminRole::Admin);
    seed_events(&k);
    let cl = k.client(&a);
    let real = cl.get("/v1/events?limit=10").json()["next_cursor"]
        .as_str()
        .unwrap()
        .to_string();
    // Tamper with the position inside a genuine cursor.
    let mut bytes = data_encoding::BASE64URL_NOPAD
        .decode(real.as_bytes())
        .unwrap();
    bytes[3] ^= 1;
    let tampered = data_encoding::BASE64URL_NOPAD.encode(&bytes);
    let random = data_encoding::BASE64URL_NOPAD.encode(&[7u8; 40]);
    for c in [tampered.as_str(), random.as_str(), "AAAA", "!!!!"] {
        let r = cl.get(&format!("/v1/events?cursor={}", enc(c)));
        assert_eq!(
            (r.status, code(&r).as_str()),
            (400, "invalid_cursor"),
            "{c}"
        );
    }
    let big = "A".repeat(5 * 1024);
    let r = cl.get(&format!("/v1/events?cursor={big}"));
    assert!(
        (r.status == 400 && code(&r) == "invalid_cursor") || r.status == 413,
        "{} {}",
        r.status,
        r.body
    );
    for q in [
        "kind=login.failed%27%20OR%201=1".to_string(),
        format!("kind={}", "k".repeat(200)),
        "user_id=u_x;DROP".to_string(),
        "client_ip=203.0.113.0/24".to_string(),
        "outcome=maybe".to_string(),
        "session_id=u_x".to_string(),
    ] {
        let r = cl.get(&format!("/v1/events?{q}"));
        assert_eq!(
            (r.status, code(&r).as_str()),
            (400, "invalid_filter"),
            "{q}"
        );
        assert!(!r.body.contains("DROP") && !r.body.contains("OR 1"));
    }
    // The IPv4-mapped form is normalized and matches the 120 rows.
    let items = cl.walk("/v1/events?client_ip=%3A%3Affff%3A203.0.113.9");
    assert_eq!(items.len(), 120);
    assert!(items.iter().all(|i| i["client_ip"] == "203.0.113.9"));
}

#[test]
fn s303_a3_reading_while_prune_runs() {
    let k = Console::new();
    let a = k.admin("sub-a", AdminRole::Admin);
    seed_events(&k);
    let cl = k.client(&a);
    let p1 = cl.get("/v1/events?limit=50").json();
    let cursor = p1["next_cursor"].as_str().unwrap().to_string();
    // The prune deletes 1,000 rows from the middle of the remaining walk.
    k.sql()
        .execute(
            "DELETE FROM events WHERE event_id IN (SELECT event_id FROM events ORDER BY at DESC, event_id DESC LIMIT 1000 OFFSET 500)",
            [],
        )
        .unwrap();
    let rest = kit::walk_from(&cl, "/v1/events", Some(&cursor));
    let ids: Vec<String> = rest.iter().map(eid).collect();
    let mut dedup = ids.clone();
    dedup.sort();
    dedup.dedup();
    assert_eq!(dedup.len(), ids.len(), "no duplicate");
    let existing: std::collections::HashSet<String> = {
        let c = k.sql();
        let mut st = c.prepare("SELECT event_id FROM events").unwrap();
        st.query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    };
    assert!(
        ids.iter().all(|i| existing.contains(i)),
        "only rows that exist"
    );
    assert_eq!(
        ids.len() + 50,
        existing.len(),
        "counts match the table at the end"
    );
}

#[test]
fn s303_a4_every_page_examines_at_most_window_candidates() {
    let k = Console::new();
    let a = k.admin("sub-a", AdminRole::Admin);
    k.h.hooks.bulk_events(300_000, 48.0);
    k.add_user("u_x", "x@example.test", "Ex");
    let now = k.now_s();
    k.add_events(
        "ux",
        25_000,
        "login.started",
        "info",
        Some("u_x"),
        None,
        None,
        now - 1000,
    );
    let cl = k.client(&a);
    let series = "hopae_admin_rows_examined_total{list=\"events\"}";
    let measure = |path: &str| -> (Value, i64) {
        let before = k.metric(series);
        let r = cl.get(path);
        assert_eq!(r.status, 200, "{path}: {}", r.body);
        let d = k.metric(series) - before;
        assert!(d <= 10_000, "{path} examined {d}");
        (r.json(), d)
    };
    // The least selective filter: 200 of the first 10,000 rows by time, with a cursor.
    let (j, d) = measure("/v1/events?outcome=info&limit=200");
    assert_eq!(j["items"].as_array().unwrap().len(), 200);
    assert!(j["next_cursor"].is_string());
    assert_eq!(d, 10_000);
    // A session with no rows: empty, no cursor, nothing examined.
    let (j, d) = measure("/v1/events?session_id=s_nonexistent");
    assert!(j["items"].as_array().unwrap().is_empty() && j["next_cursor"].is_null());
    assert_eq!(d, 0);
    // An indexed kind with an outcome absent from it: empty page, cursor, 10,000 candidates.
    let (j, d) = measure("/v1/events?kind=login.started&outcome=failure");
    assert!(j["items"].as_array().unwrap().is_empty());
    assert!(j["next_cursor"].is_string());
    assert_eq!(d, 10_000);
    let candidates = k.count("SELECT COUNT(*) FROM events WHERE kind = 'login.started'") as usize;
    let pages = kit::walk_pages(&cl, "/v1/events?kind=login.started&outcome=failure");
    assert!(pages <= candidates.div_ceil(10_000) + 1, "{pages} pages");
    // An indexed user whose rows all fail the time filter.
    let (j, d) = measure(&format!("/v1/events?user_id=u_x&since={}", now + 1));
    assert!(j["items"].as_array().unwrap().is_empty());
    assert!(j["next_cursor"].is_string());
    assert_eq!(d, 10_000);
    // Sixteen concurrent walks of a few pages each.
    std::thread::scope(|s| {
        let hs: Vec<_> = (0..16)
            .map(|_| {
                s.spawn(|| {
                    let mut cursor: Option<String> = None;
                    for _ in 0..3 {
                        let url = match &cursor {
                            None => "/v1/events?outcome=info&limit=200".to_string(),
                            Some(c) => {
                                format!("/v1/events?outcome=info&limit=200&cursor={}", enc(c))
                            }
                        };
                        let r = cl.get(&url);
                        assert_eq!(r.status, 200, "{}", r.body);
                        cursor = r.json()["next_cursor"].as_str().map(str::to_string);
                    }
                })
            })
            .collect();
        for h in hs {
            h.join().unwrap();
        }
    });
    // Deep cursor: the cursor statement seeks, so a deep page costs the same as a shallow one.
    let near_end = format!("{}:e_blk000000000000000000", (now - 40 * 3600) * 1000);
    let near_start = format!("{}:e_blk000000000000000000", (now - 10) * 1000);
    let shallow =
        k.h.hooks
            .explain(&format!("events&index=user&cursor={near_start}"), true);
    let deep =
        k.h.hooks
            .explain(&format!("events&index=user&cursor={near_end}"), true);
    assert!(
        deep["plan"].to_string().contains("(at,event_id)<(?,?)"),
        "{deep}"
    );
    let (s1, s2) = (
        shallow["vm_step"].as_i64().unwrap(),
        deep["vm_step"].as_i64().unwrap(),
    );
    let ratio = s2 as f64 / s1 as f64;
    assert!((0.9..=1.1).contains(&ratio), "{s1} vs {s2}");
    assert!(s2 < 20 * 10_000, "below 20 x the window: {s2}");
}

#[test]
fn s303_a5_viewer_reads_nobody_else_does() {
    let k = Console::new();
    let _a = k.admin("sub-a", AdminRole::Admin);
    let v = k.admin("sub-v", AdminRole::Viewer);
    let n = k.login("sub-n", "n@example.test", "No grant");
    seed_events(&k);
    let r = k.client(&v).get("/v1/events?user_id=u_x");
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(r.json()["items"].as_array().unwrap().len(), 50);
    let calls = |k: &Console| {
        k.h.hooks.counters()["store_calls"]["query_page"]
            .as_u64()
            .unwrap_or(0)
    };
    let before = calls(&k);
    let r = k.client(&n).get("/v1/events?user_id=u_x");
    assert_eq!((r.status, code(&r).as_str()), (403, "not_admin"));
    let r = k.h.admin_client().get("/v1/events?user_id=u_x");
    assert_eq!((r.status, code(&r).as_str()), (403, "login_required"));
    assert_eq!(calls(&k), before, "no query executed in the refused cases");
}

#[test]
fn s303_a6_history_is_not_a_user_directory() {
    let k = Console::new();
    let a = k.admin("sub-a", AdminRole::Admin);
    seed_events(&k);
    let cl = k.client(&a);
    let r = cl.get("/v1/events?user_id=u_x");
    assert_eq!(r.status, 200);
    assert!(
        !r.body.contains("x@example.test"),
        "rows carry user ids, not emails"
    );
    let p = cl.get("/events?user_id=u_x");
    assert_eq!(p.status, 200);
    assert!(
        p.body.contains("/users/u_x"),
        "the id links to the user page"
    );
    assert!(!p.body.contains("x@example.test"));
    // No filter by email: the parameter is ignored and narrows nothing.
    let all = cl.get("/v1/events?limit=200").json();
    let by_email = cl.get("/v1/events?limit=200&email=x@example.test").json();
    assert_eq!(all["items"], by_email["items"]);
    // A client address must be exact: prefixes are refused.
    let r = cl.get("/v1/events?client_ip=203.0.113");
    assert_eq!((r.status, code(&r).as_str()), (400, "invalid_filter"));
}

#[test]
fn s303_a7_query_reaching_deadline_is_interrupted_inside_store() {
    let k = Console::with(json!({"admin": {"query_budget_ms": 100}}));
    let a = k.admin("sub-a", AdminRole::Admin);
    k.h.hooks.bulk_events(100_000, 48.0);
    k.add_user("u_t", "t@example.test", "Target");
    let now = k.now_s();
    k.add_session(
        "s_t",
        "u_t",
        now - 10,
        "192.0.2.77",
        None,
        &["app.example.test"],
        None,
        None,
    );
    let cl = k.client(&a);
    k.h.hooks.slow_scan(1);
    let before = k.metric("hopae_store_interrupts_total");
    let t = std::time::Instant::now();
    let r = cl.get("/v1/events?outcome=info");
    assert_eq!(
        (r.status, code(&r).as_str()),
        (503, "store_unavailable"),
        "{}",
        r.body
    );
    assert!(
        t.elapsed() < std::time::Duration::from_millis(1500),
        "{:?}",
        t.elapsed()
    );
    assert!(
        k.metric("hopae_store_interrupts_total") > before,
        "interrupted inside SQLite"
    );
    // Sixteen concurrent ones all end within the bound while the writer stays free.
    let t = std::time::Instant::now();
    std::thread::scope(|s| {
        let hs: Vec<_> = (0..16)
            .map(|_| s.spawn(|| cl.get("/v1/events?outcome=info")))
            .collect();
        let term = s.spawn(|| {
            k.client(&a)
                .post_json("/v1/sessions/s_t/terminate", json!({}))
        });
        for h in hs {
            assert_eq!(h.join().unwrap().status, 503);
        }
        let r = term.join().unwrap();
        // The terminate also runs under the slowed store; it may itself be cut off, never blocked.
        assert!(r.status == 200 || r.status == 503, "{}", r.body);
    });
    assert!(
        t.elapsed() < std::time::Duration::from_secs(3),
        "{:?}",
        t.elapsed()
    );
    // The connection is usable afterwards.
    k.h.hooks.slow_scan_off();
    assert_eq!(cl.get("/v1/events?limit=5").status, 200);
    // The deadline of the job is visible.
    let d = k.h.hooks.last_deadline();
    assert_eq!(d["seen"], true, "{d}");
    // The control run: budget 2000, hook off.
    let k = Console::new();
    let a = k.admin("sub-a", AdminRole::Admin);
    k.h.hooks.bulk_events(100_000, 48.0);
    let r = k.client(&a).get("/v1/events?outcome=info");
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(r.json()["items"].as_array().unwrap().len(), 50);
    // The deadline comes from the explicit budget. Background store jobs
    // (delivery, prune) can run after the request and overwrite the hook's
    // "last" value, so the request is repeated until its own job is the last.
    let mut last = serde_json::Value::Null;
    for _ in 0..10 {
        let r = k.client(&a).get("/v1/events?limit=5");
        assert_eq!(r.status, 200);
        last = k.h.hooks.last_deadline();
        if last["deadline"].as_bool() == Some(true) {
            break;
        }
    }
    assert_eq!(
        (last["seen"].as_bool(), last["deadline"].as_bool()),
        (Some(true), Some(true)),
        "{last}"
    );
    assert!(last["remaining_ms"].as_i64().unwrap() <= 2000, "{last}");
}
