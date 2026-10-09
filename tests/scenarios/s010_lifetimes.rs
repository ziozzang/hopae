//! Scenario 010: handle and session lifetimes, enforced at verify with an
//! injected clock. Engine-level (`hopae::verify::decide` over a real store);
//! the portal half of S010-3/7 belongs to W1-D/W1-E.
#![allow(dead_code)]

use hopae::crypto::{Secret, Timestamp};
use hopae::event::types::{EventKind, reasons};
use hopae::store::types::User;
use hopae::verify::{Decision, DenyKind};

use super::s004_verify::fx::*;

const H: u64 = 3600;
const DAY: u64 = 24 * H;
const SHORT_URL: &str = "https://short.example.test/";

struct Life {
    f: Fx,
    user: User,
    s: Sess,
    h1: Secret,
    h2: Secret,
}

/// Session `s_1` created at t0 with portal handle H0, H1 on `app`, H2 on `short`.
async fn life() -> Life {
    let f = Fx::new("m1-lifetimes");
    let user = f.user("a@example.test", Some("alice"), None).await;
    let s = f.session(&user).await;
    let h1 = f.handle(&s, "app.example.test").await;
    let h2 = f.handle(&s, "short.example.test").await;
    Life { f, user, s, h1, h2 }
}

impl Life {
    /// Mark `h` (and the session) as last seen `secs` after t0.
    fn seen(&self, h: &Secret, secs: u64) {
        let t = T0 / 1000 + secs as i64;
        self.f.exec(&format!(
            "UPDATE session_handles SET last_seen_at = {t} WHERE handle_sha256 = x'{}'",
            h.digest().to_hex()
        ));
        self.f.exec(&format!(
            "UPDATE sessions SET last_seen_at = MAX(last_seen_at, {t}) WHERE session_id = '{}'",
            self.s.row.session_id
        ));
    }

    fn handle_events(
        &self,
    ) -> impl std::future::Future<Output = Vec<hopae::event::types::Event>> + '_ {
        self.f.events(EventKind::HandleRevoked)
    }
}

#[tokio::test]
async fn s010_1_active_handle_reports_earliest_deadline() {
    let l = life().await;
    l.seen(&l.h1, 11 * H);
    l.f.at(11 * H);
    let (id, _) = allow(l.f.decide(l.f.req(APP_URL).cookie(&l.h1)).await);
    // Idle deadline last_seen + 12 h, earlier than the handle's 7 d and the session's 30 d.
    assert_eq!(id.expires_at.secs(), T0 / 1000 + 23 * H as i64);
    // A later call, past the 30 s coalescing window, writes last_seen_at once.
    l.f.at(11 * H + 31);
    allow(l.f.decide(l.f.req(APP_URL).cookie(&l.h1)).await);
    let want = T0 / 1000 + 11 * H as i64 + 31;
    for _ in 0..50 {
        if l.f.handle_state(&l.h1).1 == want {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert_eq!(l.f.handle_state(&l.h1).1, want);
}

#[tokio::test]
async fn s010_2_handle_idle_expiry_revokes_handle_only() {
    let l = life().await;
    // (The scenario text says H1 was last seen at "t0 + 1h30m", after `now`; t0 + 30 m is meant.)
    l.seen(&l.h1, 1800);
    l.f.at(H + 1);
    let (txn, _, clear) = login(l.f.decide(l.f.req(SHORT_URL).cookie(&l.h2)).await);
    assert!(txn.is_some() && clear);
    assert_eq!(l.f.handle_state(&l.h2).0.as_deref(), Some("idle"));
    let ev = l.handle_events().await;
    assert_eq!(ev.len(), 1);
    assert_eq!(ev[0].reason, Some(reasons::IDLE));
    assert_eq!(l.f.session_state(&l.s).0, None, "the session continues");
    allow(l.f.decide(l.f.req(APP_URL).cookie(&l.h1)).await);
    assert_eq!(
        l.f.handle_state(&l.s.portal).0,
        None,
        "portal handle unaffected"
    );
}

#[tokio::test]
async fn s010_3_handle_absolute_expiry_despite_activity() {
    let l = life().await;
    let day7 = 7 * DAY;
    l.seen(&l.h1, day7 - H);
    l.seen(&l.s.portal, day7 - H);
    l.f.at(day7 - 1800);
    let (id, _) = allow(l.f.decide(l.f.req(APP_URL).cookie(&l.h1)).await);
    assert_eq!(id.expires_at.secs(), T0 / 1000 + day7 as i64);
    l.seen(&l.h1, day7 - 1800);
    l.f.at(day7 + 1);
    let (txn, _, clear) = login(l.f.decide(l.f.req(APP_URL).cookie(&l.h1)).await);
    assert!(txn.is_some() && clear);
    assert_eq!(l.f.handle_state(&l.h1).0.as_deref(), Some("absolute"));
    let ev = l.handle_events().await;
    assert_eq!(ev.last().and_then(|e| e.reason), Some(reasons::ABSOLUTE));
    // The portal handle (and the session) are still running: single sign-on can
    // issue a fresh handle on `app` (the portal side is W1-D's).
    assert_eq!(l.f.handle_state(&l.s.portal).0, None);
    assert_eq!(l.f.session_state(&l.s).0, None);
}

#[tokio::test]
async fn s010_4_session_idle_expiry_terminates_all() {
    let l = life().await;
    l.f.at(24 * H + 1);
    let (_, _, clear) = login(l.f.decide(l.f.req(APP_URL).cookie(&l.h1)).await);
    assert!(clear);
    assert_eq!(l.f.session_state(&l.s).0.as_deref(), Some("idle"));
    for h in [&l.h1, &l.h2, &l.s.portal] {
        assert_eq!(l.f.handle_state(h).0.as_deref(), Some("session_terminated"));
    }
    let ev = l.f.events(EventKind::SessionTerminated).await;
    assert_eq!(ev.len(), 1);
    assert_eq!(ev[0].reason, Some(reasons::IDLE));
    // The next verify with any of them is an unknown-session denial.
    let (txn, _, _) = login(l.f.decide(l.f.req(SHORT_URL).cookie(&l.h2)).await);
    assert!(txn.is_some());
}

#[tokio::test]
async fn s010_5_activity_does_not_extend_other_host() {
    let l = life().await;
    l.seen(&l.h1, 2 * H - 600);
    l.f.at(2 * H);
    let (txn, _, clear) = login(l.f.decide(l.f.req(SHORT_URL).cookie(&l.h2)).await);
    assert!(txn.is_some() && clear);
    assert_eq!(l.f.handle_state(&l.h2).0.as_deref(), Some("idle"));
    let (id, _) = allow(l.f.decide(l.f.req(APP_URL).cookie(&l.h1)).await);
    // H1's own idle clock; the session's idle clock is newest activity + 24 h.
    assert_eq!(
        id.expires_at.secs(),
        T0 / 1000 + (2 * H - 600 + 12 * H) as i64
    );
    let last: i64 = l.f.sql(&format!(
        "SELECT last_seen_at FROM sessions WHERE session_id = '{}'",
        l.s.row.session_id
    ));
    assert_eq!(last, T0 / 1000 + (2 * H - 600) as i64);
}

#[tokio::test]
async fn s010_6_session_absolute_expiry() {
    let l = life().await;
    let day30 = 30 * DAY;
    for h in [&l.h1, &l.h2, &l.s.portal] {
        l.seen(h, day30 - 1800);
    }
    l.f.at(day30 + 1);
    let (_, _, clear) = login(l.f.decide(l.f.req(APP_URL).cookie(&l.h1)).await);
    assert!(clear);
    assert_eq!(l.f.session_state(&l.s).0.as_deref(), Some("absolute"));
    for h in [&l.h1, &l.h2, &l.s.portal] {
        assert_eq!(l.f.handle_state(h).0.as_deref(), Some("session_terminated"));
    }
}

#[tokio::test]
async fn s010_7_portal_handle_follows_default_policy() {
    // The portal's own page logic is W1-E's; the policy it applies is the
    // `default` application's lifetimes through the shared evaluator.
    let l = life().await;
    l.seen(&l.h1, 2 * H);
    l.f.at(2 * H + 1);
    let snapshot = l.f.snapshot.load_full();
    assert_eq!(snapshot.default_app.session.idle, secs(2 * H));
    let view =
        l.f.store
            .sessions()
            .lookup_handle(&l.s.portal.digest(), &host(PORTAL_HOST))
            .await
            .unwrap()
            .expect("portal handle");
    let verdict = hopae::policy::lifetimes::evaluate(
        &view.handle,
        &view.session,
        &snapshot.default_app.session,
        &l.f.ctx.limits.session,
        l.f.now(),
    );
    assert_eq!(
        verdict,
        hopae::policy::lifetimes::LifetimeVerdict::HandleExpired(reasons::IDLE)
    );
    // The session itself continues and H1 still verifies.
    allow(l.f.decide(l.f.req(APP_URL).cookie(&l.h1)).await);
}

#[tokio::test]
async fn s010_8_cookie_max_age_mirrors_handle_absolute() {
    let l = life().await;
    l.f.at(H);
    let (code, bind) = mint_code(&l, "https://app.example.test/admin/x").await;
    let d =
        l.f.decide(
            l.f.req("https://app.example.test/admin/x")
                .code(&code)
                .bind(&bind),
        )
        .await;
    match d {
        Decision::Handoff { max_age, .. } => assert_eq!(max_age, secs(7 * DAY)),
        other => panic!("expected handoff, got {}", show(&other)),
    }
}

/// An unconsumed code for the session of `l` on `url`, bound to a fresh bind cookie.
async fn mint_code(l: &Life, url: &str) -> (Secret, Secret) {
    let code = hopae::crypto::random_token(&*l.f.rng, 32);
    let bind = hopae::crypto::random_token(&*l.f.rng, 16);
    let target = url::Url::parse(url).unwrap();
    let now = l.f.now();
    l.f.store
        .sessions()
        .mint_handoff_code(
            hopae::store::types::HandoffCodeRow {
                code_sha256: code.digest(),
                session_id: l.s.row.session_id.clone(),
                host: host(target.host_str().unwrap()),
                return_target: target,
                client_ip: ip("203.0.113.9"),
                bind_sha256: bind.digest(),
                issued_aal: hopae::session::types::Aal::One,
                cred_gen: l.f.session_state(&l.s).1 as u64,
                recovery_depth: 0,
                created_at: now,
                expires_at: now.add(secs(60)),
                consumed_at: None,
                consumed_reason: None,
            },
            vec![],
        )
        .await
        .unwrap();
    (code, bind)
}

#[tokio::test]
async fn s010_9_sweep_prunes_terminated_rows() {
    let f = Fx::new("m1-lifetimes");
    let user = f.user("a@example.test", Some("alice"), None).await;
    for _ in 0..1000 {
        let s = f.session(&user).await;
        f.handle(&s, "app.example.test").await;
        f.store
            .sessions()
            .terminate_session(&s.row.session_id, reasons::LOGOUT, f.now(), vec![])
            .await
            .unwrap();
    }
    let events_before: i64 = f.sql("SELECT COUNT(*) FROM events");
    assert_eq!(f.sql::<i64>("SELECT COUNT(*) FROM sessions"), 1000);
    assert!(f.sql::<i64>("SELECT COUNT(*) FROM session_handles") >= 2000);
    // Younger than the retention: nothing goes.
    f.at(29 * DAY);
    let kept = f
        .store
        .sessions()
        .sweep(f.now(), std::time::Duration::from_secs(30 * DAY))
        .await
        .unwrap();
    assert_eq!(kept.sessions, 0);
    f.at(31 * DAY);
    let swept = f
        .store
        .sessions()
        .sweep(f.now(), std::time::Duration::from_secs(30 * DAY))
        .await
        .unwrap();
    assert_eq!(swept.sessions, 1000);
    assert_eq!(f.sql::<i64>("SELECT COUNT(*) FROM sessions"), 0);
    assert_eq!(
        f.sql::<i64>("SELECT COUNT(*) FROM session_handles"),
        0,
        "handles cascade"
    );
    assert_eq!(
        f.sql::<i64>("SELECT COUNT(*) FROM events"),
        events_before,
        "events keep their own retention"
    );
}

#[tokio::test]
async fn s010_a1_terminated_session_not_revived_by_code() {
    let l = life().await;
    let (code, bind) = mint_code(&l, "https://app.example.test/admin/x").await;
    l.f.at(30);
    l.f.store
        .sessions()
        .terminate_session(&l.s.row.session_id, reasons::IDLE, l.f.now(), vec![])
        .await
        .unwrap();
    let handles_before: i64 = l.f.sql("SELECT COUNT(*) FROM session_handles");
    let d =
        l.f.decide(
            l.f.req("https://app.example.test/admin/x")
                .code(&code)
                .bind(&bind),
        )
        .await;
    let (txn, _, clear) = login(d);
    assert!(txn.is_some() && !clear, "unauthenticated 302 to the portal");
    assert_eq!(
        l.f.sql::<i64>("SELECT COUNT(*) FROM session_handles"),
        handles_before
    );
    let consumed: Option<String> = l.f.sql(&format!(
        "SELECT consumed_reason FROM handoff_codes WHERE code_sha256 = x'{}'",
        code.digest().to_hex()
    ));
    assert!(consumed.is_some(), "the code stays burned");
}

#[tokio::test]
async fn s010_a2_client_cannot_extend_lifetime() {
    let l = life().await;
    l.seen(&l.h1, H);
    l.f.at(H);
    let (before, _) = allow(l.f.decide(l.f.req(APP_URL).cookie(&l.h1)).await);
    // Cookie attributes smuggled into the value make it malformed: unknown handle.
    let smuggled = format!("{}; Max-Age=999999", l.h1.expose());
    let (txn, _, clear) = login(l.f.decide(l.f.req(APP_URL).raw_cookie(&smuggled)).await);
    assert!(txn.is_some() && clear);
    let (after, _) = allow(l.f.decide(l.f.req(APP_URL).cookie(&l.h1)).await);
    assert_eq!(before.expires_at, after.expires_at);
    // (An `x-hopae-expires` request header is not part of `VerifyInput` at all.)
}

#[tokio::test]
async fn s010_a3_clock_skew_tolerance() {
    // Unit level: the evaluator.
    let l = life().await;
    let view =
        l.f.store
            .sessions()
            .lookup_handle(&l.h1.digest(), &host("app.example.test"))
            .await
            .unwrap()
            .unwrap();
    let app =
        l.f.snapshot
            .load()
            .app_for_host(&host("app.example.test"))
            .unwrap()
            .session;
    let session = l.f.ctx.limits.session;
    let eval = |ahead: u64| {
        let mut h = view.handle.clone();
        h.created_at = Timestamp(T0).add(secs(ahead));
        hopae::policy::lifetimes::evaluate(&h, &view.session, &app, &session, Timestamp(T0))
    };
    assert!(matches!(
        eval(59),
        hopae::policy::lifetimes::LifetimeVerdict::Live { .. }
    ));
    assert_eq!(
        eval(61),
        hopae::policy::lifetimes::LifetimeVerdict::ClockSkew
    );

    // Engine level: 61 s ahead is denied, 59 s is allowed.
    let skewed =
        l.f.handle_with(&l.s, "app.example.test", |h| {
            h.created_at = h.created_at.add(secs(61))
        })
        .await;
    let (reason, kind) = deny(l.f.decide(l.f.req(APP_URL).cookie(&skewed)).await);
    assert_eq!(reason, reasons::CLOCK_SKEW);
    assert!(matches!(kind, DenyKind::Unavailable { .. }));
    let near =
        l.f.handle_with(&l.s, "app.example.test", |h| {
            h.created_at = h.created_at.add(secs(59))
        })
        .await;
    allow(l.f.decide(l.f.req(APP_URL).cookie(&near)).await);
}

#[tokio::test(flavor = "multi_thread")]
async fn s010_a4_keepalive_flood_no_growth() {
    // The scenario names 100,000 calls; 10,000 keep the suite fast and
    // exercise the same coalescing window.
    let l = life().await;
    l.f.at(H);
    let events_before: i64 = l.f.sql("SELECT COUNT(*) FROM events");
    let rows_before: i64 = l.f.sql("SELECT COUNT(*) FROM session_handles");
    for i in 0..10_000i64 {
        l.f.clock.set(Timestamp(T0 + 3_600_000 + i));
        allow(l.f.decide(l.f.req(APP_URL).cookie(&l.h1)).await);
    }
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert_eq!(l.f.store_calls("touch_handle"), 1, "one last_seen write");
    assert_eq!(l.f.sql::<i64>("SELECT COUNT(*) FROM events"), events_before);
    assert_eq!(
        l.f.sql::<i64>("SELECT COUNT(*) FROM session_handles"),
        rows_before
    );
    let _ = &l.user;
}

/// G7-C01: a handoff code must not revive a session whose idle deadline has
/// passed while `terminated_at` is still NULL.
#[tokio::test]
async fn g7_c01_code_does_not_revive_idle_expired_session() {
    let f = Fx::with("m1-lifetimes", |v| v["session"]["idle"] = "60s".into());
    let user = f.user("a@example.test", Some("alice"), None).await;
    let s = f.session(&user).await;
    let l = Life {
        f,
        user,
        h1: Secret::new("x".into()),
        h2: Secret::new("y".into()),
        s,
    };
    let (code, bind) = mint_code(&l, "https://app.example.test/admin/x").await;
    // The session was last seen long ago (idle policy 60 s) while the code is fresh.
    l.f.exec(&format!(
        "UPDATE sessions SET last_seen_at = last_seen_at - 3600, created_at = created_at - 3600 WHERE session_id = '{}'",
        l.s.row.session_id
    ));
    l.f.at(31);
    let handles_before: i64 = l.f.sql("SELECT COUNT(*) FROM session_handles");
    let d =
        l.f.decide(
            l.f.req("https://app.example.test/admin/x")
                .code(&code)
                .bind(&bind),
        )
        .await;
    let (txn, _, _) = login(d);
    assert!(
        txn.is_some(),
        "an expired session sends the browser to log in again"
    );
    assert_eq!(
        l.f.sql::<i64>("SELECT COUNT(*) FROM session_handles"),
        handles_before,
        "no handle is minted for an expired session"
    );
    assert_eq!(l.f.session_state(&l.s).0.as_deref(), Some("idle"));
    let ev = l.f.events(EventKind::SessionTerminated).await;
    assert_eq!(ev.len(), 1);
    assert_eq!(ev[0].reason, Some(reasons::IDLE));
}

/// G7-B05 (perf, `--ignored`): a handoff redemption whose success event
/// crosses `prune_every` with `events.max_rows = 50000` and ~50k delivered
/// delivery rows. The prune runs inside the redemption's transaction, so it
/// is on the request's critical path and must stay far below the 400 ms
/// verify budget. (Set `HOPAE_PERF_DROP_INDEX=1` to measure without the
/// `event_deliveries(event_id)` index.)
#[tokio::test]
#[ignore = "perf: run with --ignored (see G7-B05)"]
async fn extra_s010_perf_redemption_that_triggers_a_retention_sized_prune() {
    use hopae::event::types::{EventBuilder, Outcome};
    let l = life().await;
    l.f.store
        .set_event_retention(hopae::store::types::EventRetention {
            retention: std::time::Duration::from_secs(90 * 86_400),
            max_rows: 50_000,
            prune_every: 1000,
            max_pending_per_sink: 1_000_000,
            terminal_retention: std::time::Duration::from_secs(7 * 86_400),
        });
    if std::env::var("HOPAE_PERF_DROP_INDEX").is_ok() {
        l.f.exec("DROP INDEX event_deliveries_event_id");
    }
    let t = T0 as f64 / 1000.0;
    l.f.exec(&format!(
        "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i < 50000)
         INSERT INTO events (event_id, at, kind, outcome, request_id)
           SELECT printf('e_0%08d', i), {t} - 100000.0 + i * 0.001, 'login.succeeded', 'success', 'r' FROM n;
         INSERT INTO event_deliveries (sink, event_id, state, attempts, next_attempt_at, updated_at)
           SELECT 'log', event_id, 'delivered', 1, 0, {} FROM events;",
        T0 / 1000
    ));
    let (code, bind) = mint_code(&l, "https://app.example.test/admin/x").await;
    for _ in 0..999 {
        let ev = EventBuilder::new(
            &*l.f.clock,
            &*l.f.rng,
            hopae::event::types::EventKind::LoginSucceeded,
            Outcome::Success,
            "r",
        )
        .build();
        l.f.store
            .directory()
            .import_providers(vec![], None, vec![ev])
            .await
            .unwrap();
    }
    let rows_before: i64 = l.f.sql("SELECT COUNT(*) FROM events");
    let started = std::time::Instant::now();
    let d =
        l.f.decide(
            l.f.req("https://app.example.test/admin/x")
                .code(&code)
                .bind(&bind),
        )
        .await;
    let took = started.elapsed();
    eprintln!("redemption took {took:?}");
    assert!(
        matches!(d, Decision::Handoff { .. }),
        "redemption succeeded"
    );
    let rows_after: i64 = l.f.sql("SELECT COUNT(*) FROM events");
    eprintln!("redemption with prune: {took:?} (events {rows_before} -> {rows_after})");
    assert!(
        rows_after < rows_before,
        "the redemption triggered the prune"
    );
    assert!(
        took < std::time::Duration::from_millis(100),
        "redemption took {took:?} against a 400 ms verify budget"
    );
}
