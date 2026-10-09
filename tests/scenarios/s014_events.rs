//! Scenario 014: core flows emit events with the fixed schema, delivered
//! at-least-once from per-sink rows, with a storage bound that a stalled sink
//! cannot remove.
//!
//! The delivery, retention and bound cases run in-process against the real
//! SQLite store and the real workers (a test clock stands in for time); the
//! cases that need login, verify or portal traffic from other work packages
//! drive the spawned binary and are `#[ignore]`d until those land.
#![allow(dead_code)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use serde_json::{Value, json};

use hopae::crypto::{Clock, OsRng, TestClock, Timestamp};
use hopae::event::Emitter;
use hopae::event::bus;
use hopae::event::deliveries::DeliveryWorker;
use hopae::event::diagnostic::DiagnosticWriter;
use hopae::event::prune::{PruneTrigger, Pruner};
use hopae::event::sampling::Sampler;
use hopae::event::sinks::{LogSink, Sink};
use hopae::event::types::{Event, EventBuilder, EventId, EventKind, Outcome, reasons};
use hopae::store::Store;
use hopae::store::types::EventRetention;
use hopae::telemetry::counters;

use crate::support::*;

const T0: i64 = 1_800_000_000_000;
const DAY: Duration = Duration::from_secs(86_400);

struct Rig {
    store: Store,
    clock: Arc<TestClock>,
    rng: Arc<OsRng>,
    _dir: tempfile::TempDir,
}

fn rig() -> Rig {
    let dir = tempfile::tempdir().unwrap();
    let clock = Arc::new(TestClock::new(Timestamp(T0)));
    let rng = Arc::new(OsRng);
    let store = Store::open(
        &dir.path().join("hopae.db"),
        clock.clone(),
        vec!["log".to_string()],
        None,
    )
    .unwrap();
    store.set_rng(rng.clone());
    Rig {
        store,
        clock,
        rng,
        _dir: dir,
    }
}

impl Rig {
    fn event(&self, kind: EventKind) -> Event {
        EventBuilder::new(&*self.clock, &*self.rng, kind, Outcome::Success, "req-1").build()
    }

    /// Commit `events` the way a state change does: rows plus one pending delivery per sink.
    async fn commit(&self, events: Vec<Event>) {
        self.store
            .directory()
            .import_providers(vec![], None, events)
            .await
            .unwrap();
    }

    async fn commit_n(&self, n: usize, kind: EventKind) {
        let evs = (0..n).map(|_| self.event(kind)).collect();
        self.commit(evs).await;
    }

    fn policy(&self, max_rows: u64, prune_every: u64, max_pending: u64) -> EventRetention {
        EventRetention {
            retention: DAY,
            max_rows,
            prune_every,
            max_pending_per_sink: max_pending,
            terminal_retention: DAY,
        }
    }

    fn pruner(&self, policy: EventRetention) -> Pruner {
        Pruner::new(
            self.store.events(),
            self.clock.clone(),
            policy.clone(),
            Arc::new(PruneTrigger::new(policy.prune_every)),
            vec!["log".to_string()],
        )
    }

    fn worker(&self, sink: Arc<dyn Sink>) -> DeliveryWorker {
        DeliveryWorker::new(self.store.events(), sink, self.clock.clone())
    }

    async fn counts(&self) -> (u64, u64) {
        self.store.events().count_rows().await.unwrap()
    }

    async fn deliveries(&self) -> Vec<hopae::store::types::DeliveryRow> {
        self.store.dump_deliveries(Some("log")).await.unwrap()
    }

    async fn pending(&self) -> usize {
        self.deliveries()
            .await
            .iter()
            .filter(|d| d.state == "pending")
            .count()
    }

    async fn all_events(&self) -> Vec<Event> {
        self.store
            .events()
            .query(hopae::store::types::EventQuery {
                limit: Some(10_000),
                ..Default::default()
            })
            .await
            .unwrap()
    }
}

/// Records every delivery (a receiver that deduplicates by `event_id` in the test).
#[derive(Default)]
struct Recorder {
    got: Mutex<Vec<EventId>>,
}

impl Recorder {
    fn all(&self) -> Vec<EventId> {
        self.got.lock().unwrap().clone()
    }

    fn distinct(&self) -> usize {
        let mut v = self.all();
        v.sort();
        v.dedup();
        v.len()
    }
}

#[async_trait]
impl Sink for Recorder {
    fn name(&self) -> &str {
        "log"
    }

    async fn deliver(&self, e: &Event) -> Result<(), String> {
        self.got.lock().unwrap().push(e.event_id.clone());
        Ok(())
    }
}

/// A receiver that takes the event and then never answers (a hung or crashed sink).
struct Hung(Recorder);

#[async_trait]
impl Sink for Hung {
    fn name(&self) -> &str {
        "log"
    }

    async fn deliver(&self, e: &Event) -> Result<(), String> {
        self.0.got.lock().unwrap().push(e.event_id.clone());
        std::future::pending::<()>().await;
        Ok(())
    }
}

/// A sink that never acknowledges and does not even record.
struct Stuck;

#[async_trait]
impl Sink for Stuck {
    fn name(&self) -> &str {
        "log"
    }

    async fn deliver(&self, _e: &Event) -> Result<(), String> {
        std::future::pending::<()>().await;
        Ok(())
    }
}

async fn run_bounded(w: &DeliveryWorker, ms: u64) {
    let _ = tokio::time::timeout(Duration::from_millis(ms), async {
        loop {
            if w.run_once().await == 0 {
                break;
            }
        }
    })
    .await;
}

// ---------------------------------------------------------------------------
// Driving the spawned binary (cases that need other work packages)
// ---------------------------------------------------------------------------

/// Run one complete login through the verify, portal and mock provider; returns the session cookie jar client.
fn login_once(h: &Hopae, idp: &MockIdp, sub: &str, ip: &str) -> Response {
    idp.set_subject(sub);
    let r = h.verify(VerifyRequest::document("https://app.example.test/admin/x").ip(ip));
    assert_eq!(r.status, 302, "{r:?}");
    let loc = url::Url::parse(r.location().expect("location")).unwrap();
    let txn = loc
        .query_pairs()
        .find(|(k, _)| k == "txn")
        .map(|(_, v)| v.into_owned())
        .expect("txn");
    let c = h.portal().with_ip(ip);
    let page = c.get(&format!("/login?txn={txn}"));
    let csrf = page
        .body
        .split("name=\"csrf\" value=\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .unwrap_or_default()
        .to_string();
    let go = c.post_form("/login/mock", &[("csrf", &csrf), ("txn", &txn)]);
    assert_eq!(go.status, 302, "{go:?}");
    let auth = idp.authorizations().pop().expect("authorization");
    let state = auth.state.clone().expect("state");
    let code = idp.issue_code(&state, sub);
    c.get(&format!("/callback/mock?code={code}&state={state}"))
}

fn kinds(h: &Hopae) -> Vec<String> {
    h.hooks
        .events(None, Some(1000))
        .iter()
        .map(|e| e["kind"].as_str().unwrap().to_string())
        .collect()
}

fn find_json_log_line(log: &str, kind: &str) -> Option<Value> {
    log.lines()
        .filter(|l| l.starts_with('{'))
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .find(|v| v["kind"] == kind)
}

// ---------------------------------------------------------------------------
// S014 cases
// ---------------------------------------------------------------------------

#[test]
#[ignore = "needs W1-A/B/C/D/E (login flow)"]
fn s014_1_login_flow_event_sequence() {
    let idp = MockIdp::start("default");
    let h = Hopae::spawn(Fixture::new("m1-basic"), &idp, &[]);
    let r = login_once(&h, &idp, "sub-1", "203.0.113.9");
    assert_eq!(r.status, 302, "{r:?}");
    let evs = h.hooks.events(None, Some(1000));
    let order: Vec<&str> = evs.iter().map(|e| e["kind"].as_str().unwrap()).collect();
    let pos = |k: &str| {
        order
            .iter()
            .position(|x| *x == k)
            .unwrap_or_else(|| panic!("no {k} in {order:?}"))
    };
    assert!(pos("login.started") < pos("login.succeeded"));
    assert!(pos("login.succeeded") <= pos("session.created"));
    assert!(pos("session.created") <= pos("session.handoff"));
    let mut ids: Vec<&str> = evs
        .iter()
        .map(|e| e["event_id"].as_str().unwrap())
        .collect();
    let sorted = {
        let mut s = ids.clone();
        s.sort();
        s
    };
    assert_eq!(ids, sorted, "event ids must be time ordered");
    ids.dedup();
    assert_eq!(ids.len(), evs.len(), "event ids must be unique");
    for e in &evs {
        assert!(!e["request_id"].as_str().unwrap_or("").is_empty());
        for k in e["attrs"].as_object().unwrap().keys() {
            assert!(
                hopae::event::types::ATTR_ALLOWLIST.contains(&k.as_str()),
                "attr {k}"
            );
        }
    }
    let started = &evs[pos("login.started")];
    assert!(started["client_ip"].is_string() && started["app_id"].is_string());
    let handoff = &evs[pos("session.handoff")];
    assert!(handoff["attrs"]["host"].is_string());
}

#[test]
#[ignore = "needs W1-A/B (verify denials)"]
fn s014_2_denials_sampled() {
    let idp = MockIdp::start("default");
    let h = Hopae::spawn(Fixture::new("m1-basic"), &idp, &[]);
    let handle = format!("v1.{}", "A".repeat(43));
    for _ in 0..100 {
        let r = h.verify(
            VerifyRequest::document("https://app.example.test/x")
                .ip("198.51.100.7")
                .cookie("__Host-hopae", &handle),
        );
        assert_ne!(r.status, 200, "{r:?}");
    }
    // The window closes after 60 s; the held row is then written with the count.
    h.advance(Duration::from_secs(61));
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let rows = loop {
        let rows: Vec<Value> = h
            .hooks
            .events(Some("verify.denied"), Some(100))
            .into_iter()
            .filter(|e| e["reason"] == "unknown_handle")
            .collect();
        if !rows.is_empty() || std::time::Instant::now() > deadline {
            break rows;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert!(
        rows[0]["attrs"]["sampled_count"].as_u64().unwrap() >= 99,
        "{rows:?}"
    );
    let m = &h.hooks.counters()["metrics"];
    assert_eq!(
        m["hopae_verify_denied_total{reason=\"unknown_handle\"}"], 100,
        "{m}"
    );
}

#[test]
fn s014_3_log_line_shape_no_secrets() {
    let idp = MockIdp::start("default");
    let h = Hopae::spawn(Fixture::new("m1-basic"), &idp, &[]);
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    let line = loop {
        if let Some(v) = find_json_log_line(&h.log(), "config.loaded") {
            break v;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "no config.loaded line in the log:\n{}",
            h.log()
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    // Same fields as the row.
    let rows = h.hooks.events(Some("config.loaded"), None);
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0], line, "log line and row differ");
    for k in [
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
        "ua_sha256",
        "ua_prefix",
        "request_id",
        "attrs",
    ] {
        assert!(line.get(k).is_some(), "line lacks {k}: {line}");
    }
    assert!(line["event_id"].as_str().unwrap().starts_with("e_"));
    let attrs = &line["attrs"];
    assert!(
        attrs["config_digest"].as_str().unwrap().len() >= 16,
        "{attrs}"
    );
    assert_eq!(attrs["providers"], 1);
    assert!(attrs["apps"].as_u64().unwrap() >= 1);
    // The delivery row reaches `delivered` and the log never holds a secret.
    let id = line["event_id"].as_str().unwrap().to_string();
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let d = h.hooks.deliveries(Some("log"));
        let mine = d.iter().find(|x| x["event_id"] == id.as_str());
        if mine.is_some_and(|x| x["state"] == "delivered" && x["attempts"].as_u64().unwrap() >= 1) {
            break;
        }
        assert!(std::time::Instant::now() < deadline, "not delivered: {d:?}");
        std::thread::sleep(Duration::from_millis(50));
    }
    let log = h.log();
    for s in h.secret_values() {
        assert!(!log.contains(&s), "a secret value reached the log");
    }
    // Every JSON line in the log parses.
    for l in log.lines().filter(|l| l.starts_with('{')) {
        serde_json::from_str::<Value>(l).unwrap_or_else(|e| panic!("bad json line {l}: {e}"));
    }
    let m = &h.hooks.counters()["metrics"];
    assert!(
        m.as_object()
            .unwrap()
            .keys()
            .any(|k| k.starts_with("hopae_build_info")),
        "{m}"
    );
    assert!(
        m.as_object()
            .unwrap()
            .keys()
            .any(|k| k.starts_with("hopae_config_loaded_timestamp")),
        "{m}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn s014_4_retention() {
    let r = rig();
    // 100 events that will be a day old, then the clock moves past one day.
    for kind in [EventKind::LoginStarted, EventKind::SessionCreated] {
        r.commit_n(50, kind).await;
    }
    let old_ids: Vec<EventId> = r
        .all_events()
        .await
        .iter()
        .map(|e| e.event_id.clone())
        .collect();
    assert_eq!(old_ids.len(), 100);
    r.clock.advance(DAY + Duration::from_secs(60));
    for kind in [
        EventKind::LoginSucceeded,
        EventKind::SessionHandoff,
        EventKind::LoginFailed,
    ] {
        r.commit_n(100, kind).await;
    }
    r.commit_n(200, EventKind::SessionTerminated).await;
    assert_eq!(r.counts().await.0, 600);
    let report = r
        .pruner(r.policy(500, 100, 10_000))
        .run_once()
        .await
        .unwrap();
    assert_eq!(report.events_deleted, 100, "{report:?}");
    let (events, deliveries) = r.counts().await;
    assert_eq!(events, 500);
    assert_eq!(deliveries, 500, "delivery rows must die with their events");
    let left: Vec<EventId> = r
        .all_events()
        .await
        .iter()
        .map(|e| e.event_id.clone())
        .collect();
    assert!(
        old_ids.iter().all(|id| !left.contains(id)),
        "old rows must go first"
    );
    // 50 more: the oldest beyond max_rows are removed, login.* and session.* included.
    r.commit_n(50, EventKind::LoginSucceeded).await;
    assert_eq!(r.counts().await.0, 550);
    r.pruner(r.policy(500, 100, 10_000))
        .run_once()
        .await
        .unwrap();
    assert_eq!(r.counts().await.0, 500);
    assert_eq!(r.counts().await.1, 500);
    // Terminal delivery rows expire on their own clock even where the event stays.
    let w = r.worker(Arc::new(Recorder::default()));
    while w.run_once().await > 0 {}
    assert_eq!(r.pending().await, 0);
    r.clock.advance(DAY + Duration::from_secs(60));
    let mut p = r.policy(1_000, 100, 10_000);
    p.retention = DAY * 10;
    let report = r.pruner(p).run_once().await.unwrap();
    assert_eq!(report.terminal_deliveries_deleted, 500, "{report:?}");
    assert_eq!(r.counts().await, (500, 0));
}

#[test]
#[ignore = "needs W1-A..E (login and verify traffic) for the 1,000 logins and 1,000 denials"]
fn s014_5_required_events_committed_with_state() {
    let idp = MockIdp::start("default");
    let h = Hopae::spawn(Fixture::new("m1-basic"), &idp, &[]);
    h.hooks.stall(1000);
    let denied_handle = format!("v1.{}", "B".repeat(43));
    std::thread::scope(|s| {
        for t in 0..8 {
            let (h, idp) = (&h, &idp);
            let denied_handle = denied_handle.clone();
            s.spawn(move || {
                for i in 0..125 {
                    let ip = format!("203.0.113.{}", 1 + (t * 125 + i) % 250);
                    let _ = login_once(h, idp, &format!("sub-{t}-{i}"), &ip);
                    let _ = h.verify(
                        VerifyRequest::document("https://app.example.test/x")
                            .ip(&format!("198.51.{}.{}", t, i))
                            .cookie("__Host-hopae", &denied_handle),
                    );
                }
            });
        }
    });
    h.hooks.stall_off();
    std::thread::sleep(Duration::from_secs(3));
    let created = h.hooks.events(Some("session.created"), Some(10_000));
    let succeeded = h.hooks.events(Some("login.succeeded"), Some(10_000));
    assert_eq!(created.len(), succeeded.len());
    let deliveries = h.hooks.deliveries(Some("log"));
    for e in created.iter().chain(succeeded.iter()) {
        assert!(
            deliveries.iter().any(|d| d["event_id"] == e["event_id"]),
            "no delivery row for {}",
            e["event_id"]
        );
    }
    let dropped = h.hooks.events(Some("events.dropped"), Some(100));
    assert!(
        !dropped.is_empty(),
        "the stalled writer must have dropped diagnostics"
    );
    assert!(
        dropped[0]["attrs"]["dropped_by_kind"].is_object(),
        "{dropped:?}"
    );
}

#[test]
#[ignore = "needs W1-D/E (login transaction) and the crash points inside it"]
fn s014_6_crash_atomicity_state_and_record() {
    let idp = MockIdp::start("default");
    let mut h = Hopae::spawn(Fixture::new("m1-basic"), &idp, &[]);
    h.hooks.crash_at("after_login_commit");
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        login_once(&h, &idp, "sub-1", "203.0.113.9")
    }));
    assert!(
        h.wait_exit(Duration::from_secs(10)).is_some(),
        "crash point did not fire"
    );
    h.restart();
    let k = kinds(&h);
    assert!(
        k.contains(&"session.created".to_string()) && k.contains(&"login.succeeded".to_string()),
        "{k:?}"
    );

    h.hooks.crash_at("before_login_commit");
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        login_once(&h, &idp, "sub-2", "203.0.113.10")
    }));
    assert!(
        h.wait_exit(Duration::from_secs(10)).is_some(),
        "crash point did not fire"
    );
    h.restart();
    let k = kinds(&h);
    assert_eq!(
        k.iter().filter(|x| *x == "session.created").count(),
        1,
        "{k:?}"
    );
    let db = rusqlite::Connection::open(h.state_dir.path().join("state").join("hopae.db")).unwrap();
    let sessions: i64 = db
        .query_row("SELECT COUNT(*) FROM sessions", [], |r| r.get(0))
        .unwrap();
    assert_eq!(sessions, 1);
    let open_txns: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM login_txns WHERE consumed_at IS NULL",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(
        open_txns >= 1,
        "the interrupted transaction must stay unconsumed"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn s014_7_at_least_once_delivery_no_skips() {
    let r = rig();
    // Fifty events committed while the sink was stopped.
    r.commit_n(50, EventKind::LoginSucceeded).await;
    assert_eq!(r.pending().await, 50);

    // A transaction allocates an earlier id but commits after a later one was delivered.
    let early = r.event(EventKind::SessionCreated);
    r.clock.advance(Duration::from_millis(5));
    let late_committed = r.event(EventKind::SessionHandoff);
    assert!(early.event_id < late_committed.event_id);
    r.commit(vec![late_committed.clone()]).await;
    let rec = Arc::new(Recorder::default());
    let w = r.worker(rec.clone());
    while w.run_once().await > 0 {}
    assert!(rec.all().contains(&late_committed.event_id));
    r.commit(vec![early.clone()]).await;
    while w.run_once().await > 0 {}
    assert!(
        rec.all().contains(&early.event_id),
        "the late commit was skipped"
    );
    assert_eq!(rec.distinct(), 52);
    assert_eq!(r.pending().await, 0);
    for d in r.deliveries().await {
        assert_eq!(d.state, "delivered");
        assert!(d.attempts >= 1);
    }

    // A crash between writing the line and marking the row: delivered twice, counted once.
    r.commit_n(3, EventKind::LoginFailed).await;
    let hung = Arc::new(Hung(Recorder::default()));
    let crashing = r.worker(hung.clone());
    run_bounded(&crashing, 300).await; // cancelled mid-delivery, nothing marked
    let first = hung.0.all();
    assert!(!first.is_empty());
    assert_eq!(r.pending().await, 3, "unmarked rows stay pending");
    r.clock.advance(Duration::from_secs(120)); // the claim lease runs out
    let survivor = Arc::new(Recorder::default());
    let w2 = r.worker(survivor.clone());
    while w2.run_once().await > 0 {}
    assert_eq!(survivor.distinct(), 3, "no event delivered zero times");
    let mut seen = hung.0.all();
    seen.extend(survivor.all());
    assert!(
        seen.len() > survivor.distinct(),
        "the crashed delivery repeats"
    );
    seen.sort();
    seen.dedup();
    assert_eq!(seen.len(), 3, "deduplicated by event_id");
    assert_eq!(r.pending().await, 0);
    assert!(r.deliveries().await.iter().any(|d| d.attempts >= 2));
}

#[tokio::test(flavor = "multi_thread")]
async fn s014_8_stalled_sink_keeps_storage_bound() {
    let r = rig();
    let policy = r.policy(500, 100, 100);
    let pruner = r.pruner(policy.clone());
    let stuck = r.worker(Arc::new(Stuck));
    let before = counters::get(
        counters::EVENT_DELIVERIES_FAILED_TOTAL,
        &[("sink", "log"), ("reason", "backlog_overflow")],
    );
    let mut overflow_events = 0u64;
    for round in 0..2 {
        for _batch in 0..20 {
            r.commit_n(100, EventKind::LoginSucceeded).await;
            run_bounded(&stuck, 20).await; // the sink never acknowledges
            pruner.run_once().await.unwrap();
            let (events, deliveries) = r.counts().await;
            assert!(events <= 600, "events {events}");
            assert!(r.pending().await <= 100, "pending {}", r.pending().await);
            // Delivery rows only exist for retained events.
            let live: std::collections::HashSet<_> = r
                .all_events()
                .await
                .into_iter()
                .map(|e| e.event_id)
                .collect();
            let rows = r.deliveries().await;
            assert!(
                rows.iter().all(|d| live.contains(&d.event_id)),
                "orphan delivery rows"
            );
            assert_eq!(rows.len() as u64, deliveries);
            assert!(deliveries <= 100 + events);
        }
        let failed_overflow = r
            .deliveries()
            .await
            .iter()
            .filter(|d| d.state == "failed" && d.last_error.as_deref() == Some("backlog_overflow"))
            .count();
        assert!(failed_overflow > 0, "round {round}: nothing dead-lettered");
        overflow_events = r
            .store
            .events()
            .query(hopae::store::types::EventQuery {
                kind: Some(EventKind::SinkBacklogOverflow),
                limit: Some(10_000),
                ..Default::default()
            })
            .await
            .unwrap()
            .len() as u64;
        assert!(overflow_events >= 1);
        if round == 0 {
            // A day later the terminal rows of the first round are gone.
            r.clock.advance(DAY + Duration::from_secs(60));
            pruner.run_once().await.unwrap();
            let cutoff = r.clock.now().secs() - 86_400;
            assert!(
                r.deliveries()
                    .await
                    .iter()
                    .all(|d| d.state == "pending" || d.updated_at.secs() >= cutoff),
                "terminal delivery rows older than a day survived"
            );
        }
    }
    let after = counters::get(
        counters::EVENT_DELIVERIES_FAILED_TOTAL,
        &[("sink", "log"), ("reason", "backlog_overflow")],
    );
    assert!(
        after > before,
        "metric hopae_event_deliveries_failed_total did not move"
    );
    assert!(overflow_events >= 2);
    // Released: after the claim leases lapse the remaining pending rows are
    // delivered; failed ones stay listed.
    r.clock.advance(Duration::from_secs(120));
    let rec = Arc::new(Recorder::default());
    let w = r.worker(rec.clone());
    while w.run_once().await > 0 {}
    assert_eq!(r.pending().await, 0);
    assert!(rec.distinct() > 0);
    assert!(r.deliveries().await.iter().any(|d| d.state == "failed"));
}

#[test]
fn s014_a1_user_strings_not_stored_raw() {
    let clock = TestClock::new(Timestamp(T0));
    let rng = OsRng;
    let ua = format!(
        "Mozilla/5.0 \"}}\n{{\"kind\":\"x\" \u{0}\u{1b}[31m{}",
        "A".repeat(10 * 1024)
    );
    let name = "N".repeat(5 * 1024);
    let ev = EventBuilder::new(
        &clock,
        &rng,
        EventKind::LoginSucceeded,
        Outcome::Success,
        "req",
    )
    .ua(Some(&ua))
    .attr("provider", name.as_str())
    .attr("label", name.as_str())
    .attr("error", name.as_str())
    .attr("host", name.as_str())
    .attr("method", name.as_str())
    .attr("sink", name.as_str())
    .attr("status", name.as_str())
    .attr("purpose", name.as_str())
    .attr("route_id", name.as_str())
    .attr("kind", name.as_str())
    .attr("app", name.as_str())
    .build();
    assert_eq!(ev.ua_sha256, Some(hopae::crypto::sha256(ua.as_bytes())));
    let prefix = ev.ua_prefix.clone().unwrap();
    assert!(prefix.len() <= 64);
    assert!(
        prefix.chars().all(|c| c.is_ascii_graphic() || c == ' '),
        "{prefix:?}"
    );
    assert!(serde_json::to_vec(&ev.attrs).unwrap().len() <= 2048);
    assert_eq!(ev.attrs.get("truncated"), Some(&Value::Bool(true)));

    // The log line is one line of valid JSON and carries neither the raw UA nor the claim.
    let line = LogSink::line(&ev);
    assert!(!line.contains('\n'));
    let parsed: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(parsed["event_id"], ev.event_id.as_str());
    assert!(!line.contains(&ua[..200]) && !line.contains(&name));

    // And through the sink itself.
    #[derive(Clone, Default)]
    struct Buf(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for Buf {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let buf = Buf::default();
    let sink = LogSink::new(Box::new(buf.clone()), None);
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    rt.block_on(sink.deliver(&ev)).unwrap();
    let out = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
    assert_eq!(out.lines().count(), 1);
    assert_eq!(
        serde_json::from_str::<Value>(out.trim_end()).unwrap(),
        parsed
    );
}

#[test]
#[ignore = "needs W1-A..E (100 concurrent logins)"]
fn s014_a2_ordering_under_concurrency() {
    let idp = MockIdp::start("default");
    let h = Hopae::spawn(Fixture::new("m1-basic"), &idp, &[]);
    std::thread::scope(|s| {
        for t in 0..10 {
            let (h, idp) = (&h, &idp);
            s.spawn(move || {
                for i in 0..10 {
                    let _ = login_once(
                        h,
                        idp,
                        &format!("sub-{t}-{i}"),
                        &format!("203.0.113.{}", 1 + t * 10 + i),
                    );
                }
            });
        }
    });
    let evs = h.hooks.events(None, Some(10_000));
    let mut ids: Vec<&str> = evs
        .iter()
        .map(|e| e["event_id"].as_str().unwrap())
        .collect();
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), evs.len());
    for created in evs.iter().filter(|e| e["kind"] == "session.created") {
        let sid = &created["session_id"];
        let ok = evs
            .iter()
            .find(|e| e["kind"] == "login.succeeded" && &e["session_id"] == sid)
            .expect("login.succeeded for every session");
        assert!(ok["at"].as_f64() <= created["at"].as_f64());
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn s014_a3_events_cannot_fill_disk() {
    let dir = tempfile::tempdir().unwrap();
    let clock = Arc::new(TestClock::new(Timestamp(T0)));
    let rng = Arc::new(OsRng);
    let store = Store::open(
        &dir.path().join("hopae.db"),
        clock.clone(),
        vec!["log".into()],
        None,
    )
    .unwrap();
    store.set_rng(rng.clone());
    let policy = EventRetention {
        retention: DAY,
        max_rows: 500,
        prune_every: 100,
        max_pending_per_sink: 100,
        terminal_retention: DAY,
    };
    let (bus, rx) = bus::channel(bus::BUS_CAPACITY);
    let sampler = Arc::new(Sampler::default());
    let trigger = Arc::new(PruneTrigger::new(policy.prune_every));
    let emitter = Emitter::new(
        clock.clone(),
        rng.clone(),
        bus,
        sampler.clone(),
        trigger.clone(),
        false,
    );
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let pruner = Pruner::new(
        store.events(),
        clock.clone(),
        policy,
        trigger.clone(),
        vec!["log".into()],
    );
    let writer = DiagnosticWriter {
        store: store.clone(),
        events: store.events(),
        rx,
        drops: emitter.drops().clone(),
        sampler,
        clock: clock.clone(),
        rng: rng.clone(),
        trigger: trigger.clone(),
        pruner: Some(pruner.clone()),
    };
    let wtask = tokio::spawn(writer.run(stop_rx.clone()));
    let ptask = tokio::spawn(pruner.run(stop_rx.clone()));

    let max_seen = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let poll_stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let poller = {
        let (store, max_seen, poll_stop) = (store.clone(), max_seen.clone(), poll_stop.clone());
        tokio::spawn(async move {
            while !poll_stop.load(std::sync::atomic::Ordering::Relaxed) {
                if let Ok((e, _)) = store.events().count_rows().await {
                    max_seen.fetch_max(e, std::sync::atomic::Ordering::Relaxed);
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
    };

    // Burst 1: 10,000 diagnostic events.
    for i in 0..10_000u32 {
        emitter.diagnostic(EventKind::ProviderError, Outcome::Failure, "r", |b| {
            b.reason(reasons::PROVIDER_TIMEOUT).attr("count", i)
        });
        if i % 200 == 0 {
            tokio::task::yield_now().await;
        }
    }
    tokio::time::sleep(Duration::from_millis(800)).await;

    // Burst 2: 10,000 required events, committed in small transactions, sink stalled.
    for _ in 0..1_000 {
        let evs: Vec<Event> = (0..10)
            .map(|_| emitter.required(EventKind::LoginSucceeded, Outcome::Success, "r", |b| b))
            .collect();
        store
            .directory()
            .import_providers(vec![], None, evs)
            .await
            .unwrap();
    }
    tokio::time::sleep(Duration::from_millis(800)).await;
    poll_stop.store(true, std::sync::atomic::Ordering::Relaxed);
    poller.await.unwrap();
    let seen = max_seen.load(std::sync::atomic::Ordering::Relaxed);
    assert!(seen <= 600, "the table reached {seen} rows");
    let (rows, _) = store.events().count_rows().await.unwrap();
    assert!(rows <= 600, "{rows}");
    // The diagnostic burst overran the bounded queue: drops are counted, not silent.
    assert!(
        counters::get(
            counters::EVENTS_DROPPED_TOTAL,
            &[("kind", "provider.error")]
        ) > 0,
        "no drops counted for a 10,000-event diagnostic burst"
    );
    // The file is bounded after a checkpoint.
    store.barrier().await.unwrap();
    store
        .conn()
        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))
        .unwrap();
    let size = std::fs::metadata(dir.path().join("hopae.db"))
        .unwrap()
        .len();
    assert!(size < 8 * 1024 * 1024, "database file is {size} bytes");
    stop_tx.send(true).unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(5), wtask).await;
    let _ = tokio::time::timeout(Duration::from_secs(5), ptask).await;
}

#[test]
#[ignore = "needs W1-E (portal request path assigns the request id)"]
fn s014_a4_spoofed_request_id() {
    let idp = MockIdp::start("default");
    let h = Hopae::spawn(Fixture::new("m1-basic"), &idp, &[]);
    let r = h
        .portal()
        .send(Req::get("/login?txn=nope").header("x-request-id", "evil"));
    let _ = r;
    for e in h.hooks.events(None, Some(1000)) {
        assert_ne!(e["request_id"], "evil");
        assert!(e["attrs"].get("client_request_id").is_none());
    }
    assert!(!h.log().contains("\"request_id\":\"evil\""));
}

#[test]
fn emitter_client_request_id_policy() {
    for (accept, present) in [(false, false), (true, true)] {
        let clock = Arc::new(TestClock::new(Timestamp(T0)));
        let (b, _rx) = bus::channel(4);
        let e = Emitter::new(
            clock,
            Arc::new(OsRng),
            b,
            Arc::new(Sampler::default()),
            Arc::new(PruneTrigger::new(100)),
            accept,
        );
        let long = "y".repeat(1000);
        let ev = e
            .with_client_request_id(
                e.builder(EventKind::LoginStarted, Outcome::Info, "server-id"),
                Some(&long),
            )
            .build();
        assert_eq!(ev.request_id, "server-id");
        assert_eq!(ev.attrs.contains_key("client_request_id"), present);
        if present {
            assert!(ev.attrs["client_request_id"].as_str().unwrap().len() <= 256);
        }
    }
    let _ = json!({});
}
