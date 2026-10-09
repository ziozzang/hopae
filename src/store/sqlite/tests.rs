//! Store unit tests: atomic redemption in both commit orders, session
//! termination, the outbox, the provider import rule, event pruning and
//! delivery retention.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use super::Store;
use crate::crypto::{
    Clock, Digest, Secret, SeededRng, TestClock, Timestamp, handle_value, random_id, random_token,
    sha256,
};
use crate::event::types::{Event, EventBuilder, EventKind, Outcome, Reason, reasons};
use crate::identity::types::{NormalizedEmail, UserId};
use crate::policy::types::{AppId, Host};
use crate::provider::types::{ProviderId, ProviderKind};
use crate::session::types::{Aal, FactorEntry, FactorKind, SessionId};
use crate::store::types::*;
use crate::store::{Directory, Events, Sessions, StoreError, StoreHooks};

const T0: i64 = 1_700_000_000_000;
const APP_HOST: &str = "app.example.test";
const PORTAL_HOST: &str = "auth.example.test";

struct Fx {
    store: Store,
    clock: Arc<TestClock>,
    hooks: Arc<StoreHooks>,
    rng: SeededRng,
    _dir: tempfile::TempDir,
}

fn fx() -> Fx {
    let dir = tempfile::tempdir().unwrap();
    let clock = Arc::new(TestClock::new(Timestamp(T0)));
    let hooks = Arc::new(StoreHooks::new());
    let store = Store::open(
        &dir.path().join("hopae.db"),
        clock.clone(),
        vec!["log".to_string()],
        Some(hooks.clone()),
    )
    .unwrap();
    store.set_rng(Arc::new(SeededRng::new(99)));
    Fx {
        store,
        clock,
        hooks,
        rng: SeededRng::new(42),
        _dir: dir,
    }
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn host(s: &str) -> Host {
    Host::parse(s).unwrap()
}

struct Sess {
    row: SessionRow,
    portal_digest: Digest,
}

struct Code {
    secret: Secret,
    bind: Secret,
    row: HandoffCodeRow,
}

impl Fx {
    fn now(&self) -> Timestamp {
        self.clock.now()
    }

    fn event(&self, kind: EventKind) -> Event {
        EventBuilder::new(&*self.clock, &self.rng, kind, Outcome::Info, "req-test").build()
    }

    fn event_ip(&self, kind: EventKind, who: IpAddr) -> Event {
        EventBuilder::new(&*self.clock, &self.rng, kind, Outcome::Failure, "req-test")
            .ip(who)
            .build()
    }

    async fn user(&self, n: u32) -> User {
        let email = NormalizedEmail::parse(&format!("user{n}@example.test")).unwrap();
        self.store
            .create_user(
                NewUser {
                    primary_email: Some(email.clone()),
                    email_verified: true,
                    email_authoritative: false,
                    display_name: Some(format!("User {n}")),
                    username: Some(format!("user{n}")),
                },
                NewIdentity {
                    provider_id: ProviderId::new("mock"),
                    subject: format!("sub-{n}"),
                    email: Some(email),
                    email_verified: true,
                    email_authoritative: false,
                    name: Some(format!("User {n}")),
                    picture: None,
                    raw_claims: serde_json::json!({"sub": format!("sub-{n}")}),
                },
                vec![],
            )
            .await
            .unwrap()
    }

    fn session_row(&self, user: &User) -> SessionRow {
        let now = self.now();
        SessionRow {
            session_id: SessionId::new(random_id(&self.rng, "s_")),
            user_id: user.user_id.clone(),
            provider_id: ProviderId::new("mock"),
            auth_time: now,
            factors: vec![FactorEntry {
                kind: FactorKind::Oidc,
                provider: Some(ProviderId::new("mock")),
                at: now,
            }],
            aal: Aal::One,
            authz_version: user.authz_version,
            cred_gen: 1,
            snapshot: IdentitySnapshot {
                email: user.primary_email.clone(),
                display_name: user.display_name.clone(),
                username: user.username.clone(),
                groups: vec![],
            },
            bound_ip: ip("192.0.2.10"),
            bound_ua_sha256: None,
            created_at: now,
            last_seen_at: now,
            absolute_expires_at: now.add(Duration::from_secs(30 * 86400)),
            terminated_at: None,
            terminated_reason: None,
        }
    }

    fn handle_row(&self, session: &SessionId, host_name: &str, secret: &Secret) -> HandleRow {
        let now = self.now();
        HandleRow {
            handle_sha256: secret.digest(),
            session_id: session.clone(),
            host: host(host_name),
            issued_aal: Aal::One,
            created_at: now,
            last_seen_at: now,
            absolute_expires_at: now.add(Duration::from_secs(7 * 86400)),
            revoked_at: None,
            revoked_reason: None,
        }
    }

    async fn session(&self, user: &User, events: Vec<Event>) -> Sess {
        let row = self.session_row(user);
        let secret = handle_value(&self.rng);
        let handle = self.handle_row(&row.session_id, PORTAL_HOST, &secret);
        let digest = handle.handle_sha256;
        self.store
            .create_session(CreateSession {
                session: row.clone(),
                portal_handle: handle,
                portal_handle_digest: digest,
                consume_txn: None,
                events,
            })
            .await
            .unwrap();
        Sess {
            row,
            portal_digest: digest,
        }
    }

    /// A code for `session` on APP_HOST, path /admin/x, from 192.0.2.10.
    async fn code(&self, s: &Sess) -> Code {
        let secret = random_token(&self.rng, 32);
        let bind = random_token(&self.rng, 16);
        let now = self.now();
        let row = HandoffCodeRow {
            code_sha256: secret.digest(),
            session_id: s.row.session_id.clone(),
            host: host(APP_HOST),
            return_target: url::Url::parse("https://app.example.test/admin/x?a=1").unwrap(),
            client_ip: ip("192.0.2.10"),
            bind_sha256: bind.digest(),
            issued_aal: Aal::One,
            cred_gen: s.row.cred_gen,
            recovery_depth: 0,
            created_at: now,
            expires_at: now.add(Duration::from_secs(60)),
            consumed_at: None,
            consumed_reason: None,
        };
        self.store
            .mint_handoff_code(row.clone(), vec![])
            .await
            .unwrap();
        Code { secret, bind, row }
    }

    fn redeem_req(&self, c: &Code, presented: Option<HandleView>) -> (RedeemRequest, Secret) {
        let new = handle_value(&self.rng);
        let handle = self.handle_row(&c.row.session_id, APP_HOST, &new);
        (
            RedeemRequest {
                code_sha256: c.row.code_sha256,
                host: host(APP_HOST),
                path: "/admin/x".into(),
                client_ip: ip("192.0.2.10"),
                presented_bind_sha256: Some(c.bind.digest()),
                presented_handle: presented,
                new_handle: handle,
                now: self.now(),
                max_recoveries: 3,
            },
            new,
        )
    }

    async fn redeem(&self, req: RedeemRequest) -> RedeemOutcome {
        let ok = vec![self.event(EventKind::SessionHandoff)];
        let fail = vec![self.event_ip(EventKind::HandoffRejected, ip("192.0.2.10"))];
        self.store.redeem_handoff_code(req, ok, fail).await.unwrap()
    }

    fn count(&self, sql: &str) -> i64 {
        self.store.conn().query_row(sql, [], |r| r.get(0)).unwrap()
    }
}

fn expect_rejected(o: RedeemOutcome) -> (Reason, Option<HandoffCodeRow>) {
    match o {
        RedeemOutcome::Rejected { reason, code } => (reason, code),
        RedeemOutcome::Minted { .. } => panic!("expected Rejected, got Minted"),
        RedeemOutcome::AlreadyRedeemed => panic!("expected Rejected, got AlreadyRedeemed"),
        RedeemOutcome::SessionConflict { .. } => panic!("expected Rejected, got SessionConflict"),
        RedeemOutcome::Exhausted { .. } => panic!("expected Rejected, got Exhausted"),
    }
}

// ---- redemption --------------------------------------------------------

#[tokio::test]
async fn redeem_mints_one_handle_consumes_the_code_and_writes_the_event_with_it() {
    let f = fx();
    let u = f.user(1).await;
    let s = f.session(&u, vec![]).await;
    let c = f.code(&s).await;
    let (req, new_secret) = f.redeem_req(&c, None);
    let out = f.redeem(req).await;
    let RedeemOutcome::Minted {
        session,
        issued_aal,
    } = out
    else {
        panic!("expected Minted");
    };
    assert_eq!(issued_aal, Aal::One);
    assert_eq!(session.session_id, s.row.session_id);

    let view = f
        .store
        .lookup_handle(&new_secret.digest(), &host(APP_HOST))
        .await
        .unwrap()
        .expect("handle exists");
    assert_eq!(view.handle.issued_aal, Aal::One);
    assert!(view.handle.revoked_at.is_none());
    assert_eq!(view.user.authz_version, u.authz_version);

    let (consumed_at, reason): (i64, String) = f
        .store
        .conn()
        .query_row(
            "SELECT consumed_at, consumed_reason FROM handoff_codes",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(consumed_at, f.now().secs());
    assert_eq!(reason, "redeemed");
    // The success event and its delivery row committed with the handle.
    assert_eq!(
        f.count("SELECT COUNT(*) FROM events WHERE kind='session.handoff'"),
        1
    );
    assert_eq!(
        f.count("SELECT COUNT(*) FROM event_deliveries WHERE state='pending' AND sink='log'"),
        1
    );
    assert_eq!(
        f.count("SELECT COUNT(*) FROM events WHERE kind='handoff.rejected'"),
        0
    );
}

#[tokio::test]
async fn redeem_failures_burn_the_code_with_the_classified_reason() {
    struct Case {
        name: &'static str,
        reason: Reason,
        mutate: fn(&mut RedeemRequest),
    }
    let cases = [
        Case {
            name: "host",
            reason: reasons::CODE_HOST_MISMATCH,
            mutate: |r| r.host = host("other.example.org"),
        },
        Case {
            name: "path",
            reason: reasons::CODE_PATH_MISMATCH,
            mutate: |r| r.path = "/other".into(),
        },
        Case {
            name: "ip",
            reason: reasons::CODE_IP_MISMATCH,
            mutate: |r| r.client_ip = ip("192.0.2.99"),
        },
        Case {
            name: "wrong bind",
            reason: reasons::BIND_MISMATCH,
            mutate: |r| r.presented_bind_sha256 = Some(sha256(b"other")),
        },
        Case {
            name: "no bind",
            reason: reasons::BIND_MISMATCH,
            mutate: |r| r.presented_bind_sha256 = None,
        },
    ];
    for case in cases {
        let f = fx();
        let u = f.user(1).await;
        let s = f.session(&u, vec![]).await;
        let c = f.code(&s).await;
        let (mut req, new_secret) = f.redeem_req(&c, None);
        (case.mutate)(&mut req);
        let (reason, burned) = expect_rejected(f.redeem(req).await);
        assert_eq!(reason, case.reason, "{}", case.name);
        let burned = burned.expect("known code is returned burned");
        assert_eq!(
            burned.consumed_reason.as_deref(),
            Some(case.reason.0),
            "{}",
            case.name
        );
        assert!(burned.consumed_at.is_some());
        assert_eq!(burned.recovery_depth, 0);
        // No handle was minted and the failure event was written.
        assert!(
            f.store
                .lookup_handle(&new_secret.digest(), &host(APP_HOST))
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            f.count("SELECT COUNT(*) FROM events WHERE kind='handoff.rejected'"),
            1,
            "{}",
            case.name
        );
        assert_eq!(
            f.count("SELECT COUNT(*) FROM events WHERE kind='session.handoff'"),
            0
        );
        // The legitimate holder is refused afterwards: the code is burned.
        let (req2, _) = f.redeem_req(&c, None);
        assert_eq!(
            expect_rejected(f.redeem(req2).await).0,
            reasons::CODE_CONSUMED,
            "{}",
            case.name
        );
    }
}

#[tokio::test]
async fn redeem_expired_unknown_and_stale_generation() {
    let f = fx();
    let u = f.user(1).await;
    let s = f.session(&u, vec![]).await;

    // expired: exactly at the 60 s lifetime and beyond
    let c = f.code(&s).await;
    f.clock.advance(Duration::from_secs(61));
    let (req, _) = f.redeem_req(&c, None);
    let (reason, burned) = expect_rejected(f.redeem(req).await);
    assert_eq!(reason, reasons::CODE_EXPIRED);
    assert!(burned.is_some());

    // unknown: nothing to burn, but the failure event is still recorded
    let ghost = Code {
        secret: random_token(&f.rng, 32),
        bind: random_token(&f.rng, 16),
        row: HandoffCodeRow {
            code_sha256: sha256(b"nope"),
            ..f.code(&s).await.row
        },
    };
    let (req, _) = f.redeem_req(&ghost, None);
    let (reason, burned) = expect_rejected(f.redeem(req).await);
    assert_eq!(reason, reasons::CODE_UNKNOWN);
    assert!(burned.is_none());
    let _ = ghost.secret;

    // stale generation: the session's generation moved after the code was minted
    let c2 = f.code(&s).await;
    f.store
        .conn()
        .execute("UPDATE sessions SET cred_gen = cred_gen + 1", [])
        .unwrap();
    let (req, _) = f.redeem_req(&c2, None);
    let (reason, burned) = expect_rejected(f.redeem(req).await);
    assert_eq!(reason, reasons::CODE_STALE_GENERATION);
    assert!(burned.is_some());
}

#[tokio::test]
async fn replayed_code_is_rejected_and_already_redeemed_needs_the_same_sessions_handle() {
    let f = fx();
    let u = f.user(1).await;
    let s = f.session(&u, vec![]).await;
    let c = f.code(&s).await;
    let (req, new_secret) = f.redeem_req(&c, None);
    assert!(matches!(f.redeem(req).await, RedeemOutcome::Minted { .. }));

    // A replay without any handle: rejected, no second handle.
    let (req, replay_secret) = f.redeem_req(&c, None);
    assert_eq!(
        expect_rejected(f.redeem(req).await).0,
        reasons::CODE_CONSUMED
    );
    assert!(
        f.store
            .lookup_handle(&replay_secret.digest(), &host(APP_HOST))
            .await
            .unwrap()
            .is_none()
    );

    // A prefetch/retry that already holds the minted handle: clean, no state change.
    let view = f
        .store
        .lookup_handle(&new_secret.digest(), &host(APP_HOST))
        .await
        .unwrap();
    let handles_before = f.count("SELECT COUNT(*) FROM session_handles");
    let events_before = f.count("SELECT COUNT(*) FROM events");
    let (req, _) = f.redeem_req(&c, view);
    assert!(matches!(
        f.redeem(req).await,
        RedeemOutcome::AlreadyRedeemed
    ));
    assert_eq!(
        f.count("SELECT COUNT(*) FROM session_handles"),
        handles_before
    );
    assert_eq!(f.count("SELECT COUNT(*) FROM events"), events_before);
}

#[tokio::test]
async fn another_users_valid_handle_is_a_session_conflict_and_burns_the_code() {
    let f = fx();
    let victim = f.user(1).await;
    let attacker = f.user(2).await;
    let vs = f.session(&victim, vec![]).await;
    let a_s = f.session(&attacker, vec![]).await;
    // The victim already holds a handle on the application host.
    let vh = handle_value(&f.rng);
    f.store
        .mint_handle(
            f.handle_row(&vs.row.session_id, APP_HOST, &vh),
            None,
            vec![],
        )
        .await
        .unwrap();
    let presented = f
        .store
        .lookup_handle(&vh.digest(), &host(APP_HOST))
        .await
        .unwrap();

    let c = f.code(&a_s).await;
    let (req, new_secret) = f.redeem_req(&c, presented);
    match f.redeem(req).await {
        RedeemOutcome::SessionConflict { code } => {
            assert_eq!(code.consumed_reason.as_deref(), Some("session_conflict"));
        }
        _ => panic!("expected SessionConflict"),
    }
    assert!(
        f.store
            .lookup_handle(&new_secret.digest(), &host(APP_HOST))
            .await
            .unwrap()
            .is_none()
    );
    // The victim's handle is untouched.
    let still = f
        .store
        .lookup_handle(&vh.digest(), &host(APP_HOST))
        .await
        .unwrap()
        .unwrap();
    assert!(still.handle.revoked_at.is_none());
    assert_eq!(
        f.count("SELECT COUNT(*) FROM events WHERE kind='handoff.rejected'"),
        1
    );
}

#[tokio::test]
async fn same_session_handle_is_replaced_without_moving_the_generation() {
    let f = fx();
    let u = f.user(1).await;
    let s = f.session(&u, vec![]).await;
    let old = handle_value(&f.rng);
    f.store
        .mint_handle(
            f.handle_row(&s.row.session_id, APP_HOST, &old),
            None,
            vec![],
        )
        .await
        .unwrap();
    let presented = f
        .store
        .lookup_handle(&old.digest(), &host(APP_HOST))
        .await
        .unwrap();
    let c = f.code(&s).await;
    let (req, new_secret) = f.redeem_req(&c, presented);
    assert!(matches!(f.redeem(req).await, RedeemOutcome::Minted { .. }));
    let old_view = f
        .store
        .lookup_handle(&old.digest(), &host(APP_HOST))
        .await
        .unwrap()
        .unwrap();
    assert!(old_view.handle.revoked_at.is_some());
    assert_eq!(old_view.handle.revoked_reason.as_deref(), Some("replaced"));
    assert!(
        f.store
            .lookup_handle(&new_secret.digest(), &host(APP_HOST))
            .await
            .unwrap()
            .unwrap()
            .handle
            .revoked_at
            .is_none()
    );
    assert_eq!(
        f.store
            .session(&s.row.session_id)
            .await
            .unwrap()
            .unwrap()
            .cred_gen,
        1
    );
}

#[tokio::test]
async fn simultaneous_redemptions_produce_exactly_one_handle() {
    let f = fx();
    let u = f.user(1).await;
    let s = f.session(&u, vec![]).await;
    let c = f.code(&s).await;
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let (req, _) = f.redeem_req(&c, None);
        let store = f.store.clone();
        tasks.push(tokio::spawn(async move {
            store
                .redeem_handoff_code(req, vec![], vec![])
                .await
                .unwrap()
        }));
    }
    let mut minted = 0;
    for t in tasks {
        if matches!(t.await.unwrap(), RedeemOutcome::Minted { .. }) {
            minted += 1;
        }
    }
    assert_eq!(minted, 1);
    assert_eq!(
        f.count(&format!(
            "SELECT COUNT(*) FROM session_handles WHERE host='{APP_HOST}'"
        )),
        1
    );
}

#[tokio::test]
async fn redeem_then_terminate_in_both_commit_orders_leaves_no_valid_handle() {
    // Order A: the redemption holds the write transaction at its commit gate;
    // the termination queues behind it and runs second.
    let f = fx();
    let u = f.user(1).await;
    let s = f.session(&u, vec![]).await;
    let c = f.code(&s).await;
    let (req, new_secret) = f.redeem_req(&c, None);
    f.hooks.set_gate("redeem", true);
    let st = f.store.clone();
    let redeem =
        tokio::spawn(async move { st.redeem_handoff_code(req, vec![], vec![]).await.unwrap() });
    let h = f.hooks.clone();
    assert!(
        tokio::task::spawn_blocking(move || h.wait_reached("redeem", 1, Duration::from_secs(5)))
            .await
            .unwrap()
    );
    let st = f.store.clone();
    let (sid, at) = (s.row.session_id.clone(), f.now());
    let terminate = tokio::spawn(async move {
        st.terminate_session(&sid, reasons::LOGOUT, at, vec![])
            .await
            .unwrap()
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        !terminate.is_finished(),
        "termination must wait for the redemption's transaction"
    );
    f.hooks.set_gate("redeem", false);
    assert!(matches!(
        redeem.await.unwrap(),
        RedeemOutcome::Minted { .. }
    ));
    terminate.await.unwrap();
    let v = f
        .store
        .lookup_handle(&new_secret.digest(), &host(APP_HOST))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        v.handle.revoked_reason.as_deref(),
        Some("session_terminated")
    );
    assert!(v.session.terminated_at.is_some());
    assert_eq!(
        f.count("SELECT COUNT(*) FROM session_handles WHERE revoked_at IS NULL"),
        0
    );

    // Order B: the termination commits first; the redemption finds the code consumed.
    let f = fx();
    let u = f.user(1).await;
    let s = f.session(&u, vec![]).await;
    let c = f.code(&s).await;
    f.store
        .terminate_session(&s.row.session_id, reasons::LOGOUT, f.now(), vec![])
        .await
        .unwrap();
    let (req, new_secret) = f.redeem_req(&c, None);
    assert_eq!(
        expect_rejected(f.redeem(req).await).0,
        reasons::CODE_CONSUMED
    );
    assert!(
        f.store
            .lookup_handle(&new_secret.digest(), &host(APP_HOST))
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        f.count(&format!(
            "SELECT COUNT(*) FROM session_handles WHERE host='{APP_HOST}'"
        )),
        0
    );
}

#[tokio::test]
async fn pre_elevation_code_never_yields_an_elevated_or_any_handle() {
    // The redemption is held at its gate; the elevation queues behind it. The
    // handle the redemption minted is then revoked by the elevation.
    let f = fx();
    let u = f.user(1).await;
    let s = f.session(&u, vec![]).await;
    let c = f.code(&s).await;
    let (req, new_secret) = f.redeem_req(&c, None);
    f.hooks.set_gate("redeem", true);
    let st = f.store.clone();
    let redeem =
        tokio::spawn(async move { st.redeem_handoff_code(req, vec![], vec![]).await.unwrap() });
    let h = f.hooks.clone();
    assert!(
        tokio::task::spawn_blocking(move || h.wait_reached("redeem", 1, Duration::from_secs(5)))
            .await
            .unwrap()
    );
    let st = f.store.clone();
    let (sid, at) = (s.row.session_id.clone(), f.now());
    let elevate = tokio::spawn(async move { st.elevate_session(&sid, at, vec![]).await.unwrap() });
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!elevate.is_finished());
    f.hooks.set_gate("redeem", false);
    assert!(matches!(
        redeem.await.unwrap(),
        RedeemOutcome::Minted {
            issued_aal: Aal::One,
            ..
        }
    ));
    elevate.await.unwrap();
    let v = f
        .store
        .lookup_handle(&new_secret.digest(), &host(APP_HOST))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(v.handle.issued_aal, Aal::One);
    assert_eq!(v.handle.revoked_reason.as_deref(), Some("elevation"));
    assert_eq!(v.session.aal, Aal::Two);
    assert_eq!(v.session.cred_gen, 2);

    // Elevation first: the old code is consumed, nothing is minted.
    let f = fx();
    let u = f.user(1).await;
    let s = f.session(&u, vec![]).await;
    let c = f.code(&s).await;
    f.store
        .elevate_session(&s.row.session_id, f.now(), vec![])
        .await
        .unwrap();
    let (req, new_secret) = f.redeem_req(&c, None);
    let (reason, _) = expect_rejected(f.redeem(req).await);
    assert!(reason == reasons::CODE_CONSUMED || reason == reasons::CODE_STALE_GENERATION);
    assert!(
        f.store
            .lookup_handle(&new_secret.digest(), &host(APP_HOST))
            .await
            .unwrap()
            .is_none()
    );
}

// ---- termination, revocation, generations ------------------------------

#[tokio::test]
async fn terminate_session_is_one_transaction_that_bumps_the_generation_and_consumes_codes() {
    let f = fx();
    let u = f.user(1).await;
    let s = f.session(&u, vec![]).await;
    let h2 = handle_value(&f.rng);
    f.store
        .mint_handle(f.handle_row(&s.row.session_id, APP_HOST, &h2), None, vec![])
        .await
        .unwrap();
    let c1 = f.code(&s).await;
    let c2 = f.code(&s).await;
    let ev = vec![f.event(EventKind::SessionTerminated)];
    f.clock.advance(Duration::from_secs(5));
    f.store
        .terminate_session(&s.row.session_id, reasons::LOGOUT, f.now(), ev)
        .await
        .unwrap();

    let row = f.store.session(&s.row.session_id).await.unwrap().unwrap();
    assert_eq!(row.cred_gen, s.row.cred_gen + 1);
    assert_eq!(
        row.terminated_at,
        Some(Timestamp::from_secs(f.now().secs()))
    );
    assert_eq!(row.terminated_reason.as_deref(), Some("logout"));
    for h in [&s.portal_digest, &h2.digest()] {
        let (_, reason): (Option<i64>, Option<String>) = f
            .store
            .conn()
            .query_row(
                "SELECT revoked_at, revoked_reason FROM session_handles WHERE handle_sha256=?1",
                [&h.0[..]],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(reason.as_deref(), Some("session_terminated"));
    }
    for c in [&c1, &c2] {
        let got: (Option<i64>, Option<String>) = f
            .store
            .conn()
            .query_row(
                "SELECT consumed_at, consumed_reason FROM handoff_codes WHERE code_sha256=?1",
                [&c.row.code_sha256.0[..]],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert!(got.0.is_some());
        assert_eq!(got.1.as_deref(), Some("logout"));
    }
    assert_eq!(
        f.count("SELECT COUNT(*) FROM events WHERE kind='session.terminated'"),
        1
    );
    assert_eq!(f.count("SELECT COUNT(*) FROM event_deliveries"), 1);

    // A replayed termination changes nothing and records nothing more.
    f.store
        .terminate_session(
            &s.row.session_id,
            reasons::LOGOUT,
            f.now(),
            vec![f.event(EventKind::SessionTerminated)],
        )
        .await
        .unwrap();
    assert_eq!(
        f.store
            .session(&s.row.session_id)
            .await
            .unwrap()
            .unwrap()
            .cred_gen,
        s.row.cred_gen + 1
    );
    assert_eq!(
        f.count("SELECT COUNT(*) FROM events WHERE kind='session.terminated'"),
        1
    );
}

#[tokio::test]
async fn revoking_a_handle_moves_the_generation_and_consumes_outstanding_codes() {
    let f = fx();
    let u = f.user(1).await;
    let s = f.session(&u, vec![]).await;
    let h = handle_value(&f.rng);
    f.store
        .mint_handle(f.handle_row(&s.row.session_id, APP_HOST, &h), None, vec![])
        .await
        .unwrap();
    let c = f.code(&s).await;
    f.store
        .revoke_handle(
            &h.digest(),
            reasons::IDLE,
            f.now(),
            vec![f.event(EventKind::HandleRevoked)],
        )
        .await
        .unwrap();
    let v = f
        .store
        .lookup_handle(&h.digest(), &host(APP_HOST))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(v.handle.revoked_reason.as_deref(), Some("idle"));
    assert_eq!(v.session.cred_gen, 2);
    assert!(v.session.terminated_at.is_none());
    let (req, _) = f.redeem_req(&c, None);
    assert_eq!(
        expect_rejected(f.redeem(req).await).0,
        reasons::CODE_CONSUMED
    );
    // Repeating the revocation is a no-op.
    f.store
        .revoke_handle(
            &h.digest(),
            reasons::IDLE,
            f.now(),
            vec![f.event(EventKind::HandleRevoked)],
        )
        .await
        .unwrap();
    assert_eq!(
        f.count("SELECT COUNT(*) FROM events WHERE kind='handle.revoked'"),
        1
    );
}

#[tokio::test]
async fn handles_are_scoped_to_their_host_and_touch_only_moves_forward() {
    let f = fx();
    let u = f.user(1).await;
    let s = f.session(&u, vec![]).await;
    assert!(
        f.store
            .lookup_handle(&s.portal_digest, &host(PORTAL_HOST))
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        f.store
            .lookup_handle(&s.portal_digest, &host(APP_HOST))
            .await
            .unwrap()
            .is_none()
    );
    f.clock.advance(Duration::from_secs(40));
    let later = f.now();
    f.store.touch_handle(&s.portal_digest, later).await.unwrap();
    f.store
        .touch_handle(&s.portal_digest, f.now().sub(Duration::from_secs(30)))
        .await
        .unwrap();
    let v = f
        .store
        .lookup_handle(&s.portal_digest, &host(PORTAL_HOST))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(v.handle.last_seen_at, Timestamp::from_secs(later.secs()));
    assert_eq!(v.session.last_seen_at, Timestamp::from_secs(later.secs()));
    assert_eq!(v.session.user_id, u.user_id);
}

// ---- outbox ------------------------------------------------------------

#[tokio::test]
async fn required_events_and_delivery_rows_commit_with_the_state_change_or_not_at_all() {
    let f = fx();
    let u = f.user(1).await;
    let events = vec![
        f.event(EventKind::SessionCreated),
        f.event(EventKind::LoginSucceeded),
        f.event(EventKind::VerifyDenied), // diagnostic kind: a row, no delivery
    ];
    let s = f.session(&u, events).await;
    assert_eq!(f.count("SELECT COUNT(*) FROM events"), 3);
    assert_eq!(
        f.count("SELECT COUNT(*) FROM event_deliveries WHERE state='pending' AND sink='log'"),
        2
    );
    assert_eq!(f.count("SELECT COUNT(*) FROM sessions"), 1);
    assert!(
        f.store
            .conn()
            .query_row("SELECT last_login_at FROM users", [], |r| r
                .get::<_, Option<i64>>(0))
            .unwrap()
            .is_some()
    );

    // A failing state change (duplicate session id) takes its events with it.
    let dup = CreateSession {
        session: s.row.clone(),
        portal_handle: f.handle_row(&s.row.session_id, PORTAL_HOST, &handle_value(&f.rng)),
        portal_handle_digest: sha256(b"unused"),
        consume_txn: None,
        events: vec![f.event(EventKind::SessionCreated)],
    };
    assert!(f.store.create_session(dup).await.is_err());
    let mut dup2 = CreateSession {
        session: f.session_row(&u),
        portal_handle: f.handle_row(
            &SessionId::new("s_other"),
            PORTAL_HOST,
            &handle_value(&f.rng),
        ),
        portal_handle_digest: sha256(b"unused"),
        consume_txn: None,
        events: vec![f.event(EventKind::SessionCreated)],
    };
    dup2.portal_handle_digest = dup2.portal_handle.handle_sha256;
    // The handle names another session: refused, nothing written.
    assert!(f.store.create_session(dup2).await.is_err());
    assert_eq!(f.count("SELECT COUNT(*) FROM events"), 3);
    assert_eq!(f.count("SELECT COUNT(*) FROM sessions"), 1);
    assert_eq!(f.count("SELECT COUNT(*) FROM event_deliveries"), 2);
}

#[tokio::test]
async fn the_login_transaction_is_consumed_in_the_session_creating_call() {
    // S014-6 b (R-7): one store call creates the session and consumes the
    // transaction; a transaction that is already consumed creates nothing.
    let f = fx();
    let u = f.user(1).await;
    let txn = random_token(&f.rng, 16);
    f.store
        .create_transaction(new_txn(&f, &txn, "192.0.2.1"), vec![])
        .await
        .unwrap();
    let create = |row: SessionRow| {
        let secret = handle_value(&f.rng);
        let handle = f.handle_row(&row.session_id, PORTAL_HOST, &secret);
        let digest = handle.handle_sha256;
        CreateSession {
            session: row,
            portal_handle: handle,
            portal_handle_digest: digest,
            consume_txn: Some((txn.digest(), reasons::TXN_CONSUMED)),
            events: vec![f.event(EventKind::SessionCreated)],
        }
    };
    f.store
        .create_session(create(f.session_row(&u)))
        .await
        .unwrap();
    let t = f.store.transaction(&txn.digest()).await.unwrap().unwrap();
    assert!(t.consumed_at.is_some());
    assert_eq!(t.consumed_reason.as_deref(), Some("txn_consumed"));
    assert_eq!(f.count("SELECT COUNT(*) FROM sessions"), 1);
    // A second session for the same transaction: refused, nothing written.
    let before = f.count("SELECT COUNT(*) FROM events");
    assert!(matches!(
        f.store.create_session(create(f.session_row(&u))).await,
        Err(StoreError::Conflict(_))
    ));
    assert_eq!(f.count("SELECT COUNT(*) FROM sessions"), 1);
    assert_eq!(f.count("SELECT COUNT(*) FROM session_handles"), 1);
    assert_eq!(f.count("SELECT COUNT(*) FROM events"), before);
}

#[tokio::test]
async fn retry_is_single_use() {
    let f = fx();
    let txn = random_token(&f.rng, 16);
    f.store
        .create_transaction(new_txn(&f, &txn, "192.0.2.1"), vec![])
        .await
        .unwrap();
    assert!(f.store.use_retry(&txn.digest(), f.now()).await.unwrap());
    assert!(!f.store.use_retry(&txn.digest(), f.now()).await.unwrap());
    // An unknown transaction is not a first use.
    assert!(
        !f.store
            .use_retry(&sha256(b"nobody"), f.now())
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn append_required_is_one_transaction_with_delivery_rows_and_refuses_stateful_kinds() {
    let f = fx();
    f.store
        .append_required(vec![
            f.event(EventKind::LoginFailed),
            f.event(EventKind::HandoffRejected),
        ])
        .await
        .unwrap();
    assert_eq!(f.count("SELECT COUNT(*) FROM events"), 2);
    assert_eq!(
        f.count("SELECT COUNT(*) FROM event_deliveries WHERE state='pending' AND sink='log'"),
        2
    );
    // Diagnostic kinds have their own door.
    assert!(
        f.store
            .append_required(vec![f.event(EventKind::VerifyDenied)])
            .await
            .is_err()
    );
    assert_eq!(f.count("SELECT COUNT(*) FROM events"), 2);
}

#[tokio::test]
#[should_panic(expected = "must travel with its state change")]
async fn append_required_asserts_against_stateful_kinds() {
    let f = fx();
    let _ = f
        .store
        .append_required(vec![f.event(EventKind::SessionCreated)])
        .await;
}

#[tokio::test]
async fn user_creation_and_identity_rules() {
    let f = fx();
    let u = f.user(1).await;
    assert!(u.user_id.as_str().starts_with("u_"));
    assert_eq!(u.authz_version, 1);
    assert_eq!(u.status, UserStatus::Active);
    let authz = f.store.user_authz(&u.user_id).await.unwrap().unwrap();
    assert_eq!(authz.authz_version, 1);
    assert!(
        f.store
            .user_authz(&UserId::new("u_missing"))
            .await
            .unwrap()
            .is_none()
    );
    let id = f
        .store
        .identity(&ProviderId::new("mock"), "sub-1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(id.user_id, u.user_id);
    let by_email = f
        .store
        .user_by_email(&NormalizedEmail::parse("user1@Example.TEST").unwrap())
        .await
        .unwrap();
    assert_eq!(by_email.unwrap().user_id, u.user_id);

    // Duplicate (provider, subject) and duplicate username conflict and leave no new user.
    let dup = f
        .store
        .create_user(
            NewUser {
                primary_email: None,
                email_verified: false,
                email_authoritative: false,
                display_name: None,
                username: Some("other".into()),
            },
            NewIdentity {
                provider_id: ProviderId::new("mock"),
                subject: "sub-1".into(),
                email: None,
                email_verified: false,
                email_authoritative: false,
                name: None,
                picture: None,
                raw_claims: serde_json::json!({}),
            },
            vec![],
        )
        .await;
    assert!(matches!(dup, Err(StoreError::Conflict(_))), "{dup:?}");
    assert_eq!(f.count("SELECT COUNT(*) FROM users"), 1);

    // Linking a second identity to the same user.
    let new = NewIdentity {
        provider_id: ProviderId::new("other"),
        subject: "x".into(),
        email: None,
        email_verified: false,
        email_authoritative: false,
        name: None,
        picture: None,
        raw_claims: serde_json::json!({"big": "y".repeat(9000)}),
    };
    f.store
        .link_identity(
            &u.user_id,
            new.clone(),
            vec![f.event(EventKind::IdentityLinked)],
        )
        .await
        .unwrap();
    let claims: String = f
        .store
        .conn()
        .query_row(
            "SELECT raw_claims FROM identities WHERE provider_id='other'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(
        claims.len() <= 8192,
        "oversized claims are replaced, not stored"
    );
    assert!(matches!(
        f.store
            .link_identity(
                &UserId::new("u_missing"),
                NewIdentity {
                    subject: "z".into(),
                    ..new
                },
                vec![]
            )
            .await,
        Err(StoreError::Conflict(_))
    ));

    // touch updates the mutable fields only.
    f.clock.advance(Duration::from_secs(10));
    let seen = NewIdentity {
        provider_id: ProviderId::new("mock"),
        subject: "sub-1".into(),
        email: None,
        email_verified: true,
        email_authoritative: true,
        name: Some("Renamed".into()),
        picture: Some("p".into()),
        raw_claims: serde_json::json!({}),
    };
    f.store
        .touch_identity(&ProviderId::new("mock"), "sub-1", &seen, f.now())
        .await
        .unwrap();
    let id = f
        .store
        .identity(&ProviderId::new("mock"), "sub-1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(id.name.as_deref(), Some("Renamed"));
    assert_eq!(id.user_id, u.user_id);
    assert_eq!(id.last_seen_at, Timestamp::from_secs(f.now().secs()));
    assert!(id.first_seen_at < id.last_seen_at);
}

// ---- provider import ---------------------------------------------------

fn prow(id: &str, name: &str) -> ProviderRow {
    ProviderRow {
        provider_id: ProviderId::new(id),
        kind: ProviderKind::Oidc,
        display_name: name.into(),
        enabled: true,
        managed_by: ManagedBy::File,
        deleted_at: None,
        sort_order: 0,
        config: serde_json::json!({"client_id": "c"}),
        client_secret_env: Some("SECRET_ENV".into()),
        allowed_email_domains: vec![],
        authoritative_domains: vec!["example.test".into()],
        auto_link: false,
        trust_email: false,
    }
}

#[tokio::test]
async fn provider_import_follows_the_file_api_deleted_rule() {
    let f = fx();
    let first = f
        .store
        .import_providers(
            vec![prow("a", "A1"), prow("b", "B1"), prow("c", "C1")],
            None,
            vec![f.event(EventKind::ConfigLoaded)],
        )
        .await
        .unwrap();
    assert_eq!(first.inserted.len(), 3);
    // b was disabled through the API; c was removed through the API (tombstone).
    f.store
        .conn()
        .execute(
            "UPDATE providers SET managed_by='api', enabled=0 WHERE provider_id='b'",
            [],
        )
        .unwrap();
    f.store.conn().execute("UPDATE providers SET managed_by='api', deleted_at=1700000000, client_secret_env=NULL WHERE provider_id='c'", []).unwrap();

    let report = f
        .store
        .import_providers(
            vec![
                prow("a", "A2"),
                prow("b", "B2"),
                prow("c", "C2"),
                prow("d", "D1"),
            ],
            None,
            vec![],
        )
        .await
        .unwrap();
    assert_eq!(report.inserted, vec![ProviderId::new("d")]);
    assert_eq!(report.updated, vec![ProviderId::new("a")]);
    assert_eq!(report.skipped_api_managed, vec![ProviderId::new("b")]);
    assert_eq!(report.skipped_deleted, vec![ProviderId::new("c")]);
    let rows = f.store.providers().await.unwrap();
    let get = |id: &str| {
        rows.iter()
            .find(|r| r.provider_id.as_str() == id)
            .unwrap()
            .clone()
    };
    assert_eq!(get("a").display_name, "A2");
    assert_eq!(get("b").display_name, "B1");
    assert!(!get("b").enabled);
    assert_eq!(get("b").managed_by, ManagedBy::Api);
    assert!(get("c").deleted_at.is_some());
    assert_eq!(get("c").client_secret_env, None);
    assert_eq!(get("d").managed_by, ManagedBy::File);

    // --force names exactly one row and reasserts the file for it.
    let c = ProviderId::new("c");
    let report = f
        .store
        .import_providers(vec![prow("b", "B3"), prow("c", "C3")], Some(&c), vec![])
        .await
        .unwrap();
    assert_eq!(report.forced, vec![c.clone()]);
    assert_eq!(report.skipped_api_managed, vec![ProviderId::new("b")]);
    let rows = f.store.providers().await.unwrap();
    let c_row = rows.iter().find(|r| r.provider_id == c).unwrap();
    assert!(c_row.deleted_at.is_none());
    assert_eq!(c_row.managed_by, ManagedBy::File);
    assert_eq!(c_row.display_name, "C3");
    assert_eq!(
        rows.iter()
            .find(|r| r.provider_id.as_str() == "b")
            .unwrap()
            .display_name,
        "B1"
    );
    // Forcing a provider the file does not list is refused.
    assert!(matches!(
        f.store
            .import_providers(vec![], Some(&ProviderId::new("zzz")), vec![])
            .await,
        Err(StoreError::Conflict(_))
    ));
}

#[tokio::test]
async fn config_generation_counts_up() {
    let f = fx();
    assert_eq!(f.store.config_generation().await.unwrap(), 0);
    assert_eq!(f.store.bump_config_generation().await.unwrap(), 1);
    assert_eq!(f.store.bump_config_generation().await.unwrap(), 2);
    assert_eq!(f.store.config_generation().await.unwrap(), 2);
}

// ---- transactions ------------------------------------------------------

fn new_txn(f: &Fx, secret: &Secret, who: &str) -> NewTransaction {
    let now = f.now();
    NewTransaction {
        txn_sha256: secret.digest(),
        created_at: now,
        expires_at: now.add(Duration::from_secs(600)),
        app_id: AppId::new("app"),
        return_target: url::Url::parse("https://app.example.test/a?b=1%202").unwrap(),
        bind_sha256: Some(sha256(b"bind")),
        portal_bind_sha256: None,
        retry_bind_sha256: None,
        client_ip: ip(who),
        ua_sha256: None,
        provider_id: None,
        state_sha256: None,
        nonce: None,
        pkce_verifier: None,
        portal_session_id: None,
        purpose: TxnPurpose::Login,
        conflicting_handle_sha256: None,
        pending_identity: None,
        recovery_depth: 2,
    }
}

#[tokio::test]
async fn transaction_lifecycle_bind_once_consume_once() {
    let f = fx();
    let secret = random_token(&f.rng, 16);
    f.store
        .create_transaction(
            new_txn(&f, &secret, "192.0.2.1"),
            vec![f.event(EventKind::LoginStarted)],
        )
        .await
        .unwrap();
    assert!(matches!(
        f.store
            .create_transaction(new_txn(&f, &secret, "192.0.2.1"), vec![])
            .await,
        Err(StoreError::Conflict(_))
    ));
    let t = f
        .store
        .transaction(&secret.digest())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        t.return_target.as_str(),
        "https://app.example.test/a?b=1%202"
    );
    assert_eq!(t.recovery_depth, 2);
    assert!(t.state_sha256.is_none() && t.portal_bind_sha256.is_none());

    let state = random_token(&f.rng, 16);
    let binding = TransactionBinding {
        provider_id: ProviderId::new("mock"),
        state_sha256: state.digest(),
        nonce: "n-1".into(),
        pkce_verifier: Secret::new("verifier".into()),
        portal_bind_sha256: sha256(b"portal"),
    };
    f.store
        .bind_transaction(&secret.digest(), binding.clone())
        .await
        .unwrap();
    // The portal binding digest is immutable: a second bind conflicts and changes nothing.
    let again = TransactionBinding {
        portal_bind_sha256: sha256(b"attacker"),
        ..binding
    };
    assert!(matches!(
        f.store.bind_transaction(&secret.digest(), again).await,
        Err(StoreError::Conflict(_))
    ));
    let by_state = f
        .store
        .transaction_by_state(&state.digest())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(by_state.txn_sha256, secret.digest());
    assert_eq!(by_state.portal_bind_sha256, Some(sha256(b"portal")));
    assert_eq!(by_state.nonce.as_deref(), Some("n-1"));
    assert_eq!(
        by_state.pkce_verifier.as_ref().map(|s| s.expose()),
        Some("verifier")
    );

    assert!(
        f.store
            .consume_transaction(
                &secret.digest(),
                reasons::PORTAL_BIND_MISMATCH,
                f.now(),
                vec![f.event(EventKind::LoginFailed)]
            )
            .await
            .unwrap()
    );
    assert!(
        !f.store
            .consume_transaction(
                &secret.digest(),
                reasons::TXN_CONSUMED,
                f.now(),
                vec![f.event(EventKind::LoginFailed)]
            )
            .await
            .unwrap()
    );
    assert_eq!(
        f.count("SELECT COUNT(*) FROM events WHERE kind='login.failed'"),
        1
    );
    f.store
        .record_retry_bind(&secret.digest(), sha256(b"retry"))
        .await
        .unwrap();
    assert!(matches!(
        f.store
            .record_retry_bind(&secret.digest(), sha256(b"other"))
            .await,
        Err(StoreError::Conflict(_))
    ));
    let t = f
        .store
        .transaction(&secret.digest())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(t.retry_bind_sha256, Some(sha256(b"retry")));
    assert_eq!(t.consumed_reason.as_deref(), Some("portal_bind_mismatch"));
    // A consumed transaction cannot be bound.
    let other = random_token(&f.rng, 16);
    f.store
        .create_transaction(new_txn(&f, &other, "192.0.2.1"), vec![])
        .await
        .unwrap();
    f.store
        .consume_transaction(&other.digest(), reasons::TXN_CONSUMED, f.now(), vec![])
        .await
        .unwrap();
    let b = TransactionBinding {
        provider_id: ProviderId::new("mock"),
        state_sha256: sha256(b"s2"),
        nonce: "n".into(),
        pkce_verifier: Secret::new("v".into()),
        portal_bind_sha256: sha256(b"p"),
    };
    assert!(matches!(
        f.store.bind_transaction(&other.digest(), b).await,
        Err(StoreError::Conflict(_))
    ));
}

#[tokio::test]
async fn counters_eviction_and_sweep() {
    let f = fx();
    for i in 0..6 {
        let who = if i < 4 { "192.0.2.1" } else { "192.0.2.2" };
        f.store
            .create_transaction(new_txn(&f, &random_token(&f.rng, 16), who), vec![])
            .await
            .unwrap();
        f.clock.advance(Duration::from_secs(1));
    }
    let since = Timestamp(T0);
    assert_eq!(
        f.store
            .count_transactions_since(ip("192.0.2.1"), since)
            .await
            .unwrap(),
        4
    );
    assert_eq!(
        f.store
            .count_transactions_since(ip("192.0.2.2"), since)
            .await
            .unwrap(),
        2
    );
    assert_eq!(
        f.store
            .count_transactions_since(ip("192.0.2.1"), since.add(Duration::from_secs(3)))
            .await
            .unwrap(),
        1
    );

    // Handoff failures are counted from the recorded handoff.rejected events.
    let u = f.user(1).await;
    let s = f.session(&u, vec![]).await;
    let c = f.code(&s).await;
    for _ in 0..3 {
        let (mut req, _) = f.redeem_req(&c, None);
        req.code_sha256 = sha256(&random_id(&f.rng, "x").into_bytes()); // unknown code
        f.redeem(req).await;
    }
    assert_eq!(
        f.store
            .count_handoff_failures_since(ip("192.0.2.10"), since)
            .await
            .unwrap(),
        3
    );
    assert_eq!(
        f.store
            .count_handoff_failures_since(ip("192.0.2.11"), since)
            .await
            .unwrap(),
        0
    );

    // Eviction keeps at most max_rows, dropping dead rows before live ones.
    let evicted = f.store.evict_transactions(4, f.now()).await.unwrap();
    assert_eq!(evicted, 2);
    assert_eq!(f.count("SELECT COUNT(*) FROM login_txns"), 4);
    assert_eq!(f.store.evict_transactions(4, f.now()).await.unwrap(), 0);

    // Sweep removes expired transactions and codes, and terminated sessions past retention.
    f.store
        .terminate_session(&s.row.session_id, reasons::LOGOUT, f.now(), vec![])
        .await
        .unwrap();
    f.clock.advance(Duration::from_secs(700));
    let r = f
        .store
        .sweep(f.now(), Duration::from_secs(3600))
        .await
        .unwrap();
    assert_eq!((r.transactions, r.codes, r.sessions), (4, 1, 0));
    f.clock.advance(Duration::from_secs(3700));
    let r = f
        .store
        .sweep(f.now(), Duration::from_secs(3600))
        .await
        .unwrap();
    assert_eq!(r.sessions, 1);
    assert_eq!(
        f.count("SELECT COUNT(*) FROM session_handles"),
        0,
        "handles go with their session"
    );
    assert_eq!(f.count("SELECT COUNT(*) FROM sessions"), 0);
}

// ---- events: delivery, pruning, retention -------------------------------

async fn put_events(f: &Fx, n: usize) {
    for _ in 0..n {
        f.store
            .import_providers(vec![], None, vec![f.event(EventKind::ConfigLoaded)])
            .await
            .unwrap();
        f.clock.advance(Duration::from_millis(5));
    }
}

fn policy(max_rows: u64, prune_every: u64) -> EventRetention {
    EventRetention {
        retention: Duration::from_secs(90 * 86400),
        max_rows,
        prune_every,
        max_pending_per_sink: 10_000,
        terminal_retention: Duration::from_secs(7 * 86400),
    }
}

#[tokio::test]
async fn pruning_keeps_the_table_within_max_rows_plus_prune_every() {
    let f = fx();
    let (max_rows, prune_every) = (50u64, 10u64);
    for i in 1..=200u64 {
        put_events(&f, 1).await;
        let (events, deliveries) = f.store.count_rows().await.unwrap();
        assert!(
            events <= max_rows + prune_every,
            "events {events} at insert {i}"
        );
        assert_eq!(
            events, deliveries,
            "every required event keeps its delivery row"
        );
        if i % prune_every == 0 {
            f.store
                .prune(f.now(), &policy(max_rows, prune_every))
                .await
                .unwrap();
            assert!(f.store.count_rows().await.unwrap().0 <= max_rows);
        }
    }
    // The newest events survive (oldest are the ones removed).
    let kept = f
        .store
        .query(EventQuery {
            limit: Some(1000),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(kept.len() as u64, f.store.count_rows().await.unwrap().0);
    assert!(kept.windows(2).all(|w| w[0].at <= w[1].at));
}

#[tokio::test]
async fn deleting_events_deletes_their_deliveries_and_marks_pending_ones_pruned() {
    let f = fx();
    put_events(&f, 12).await;
    let mark = f
        .store
        .conn()
        .query_row(
            "SELECT event_id FROM events ORDER BY at LIMIT 1 OFFSET 3",
            [],
            |r| r.get::<_, String>(0),
        )
        .unwrap();
    // One delivery already delivered, the rest still pending.
    f.store
        .mark_delivered("log", &crate::event::types::EventId::new(mark), f.now())
        .await
        .unwrap();
    let report = f.store.prune(f.now(), &policy(5, 1)).await.unwrap();
    assert_eq!(report.events_deleted, 7);
    assert_eq!(
        report.deliveries_marked_pruned, 6,
        "the delivered one was already terminal"
    );
    assert_eq!(f.store.count_rows().await.unwrap(), (5, 5));
    assert_eq!(f.count("SELECT COUNT(*) FROM event_deliveries WHERE event_id NOT IN (SELECT event_id FROM events)"), 0);

    // Age-based: everything older than the retention goes, whatever its delivery state.
    f.clock.advance(Duration::from_secs(91 * 86400));
    let report = f.store.prune(f.now(), &policy(1_000, 10)).await.unwrap();
    assert_eq!(report.events_deleted, 5);
    assert_eq!(f.store.count_rows().await.unwrap(), (0, 0));
}

#[tokio::test]
async fn terminal_deliveries_expire_before_their_events_do() {
    let f = fx();
    put_events(&f, 6).await;
    let ids: Vec<String> = f
        .store
        .conn()
        .prepare("SELECT event_id FROM events ORDER BY at")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    let id = |i: usize| crate::event::types::EventId::new(ids[i].clone());
    f.store
        .mark_delivered("log", &id(0), f.now())
        .await
        .unwrap();
    f.store
        .mark_delivered("log", &id(1), f.now())
        .await
        .unwrap();
    f.store
        .mark_failed("log", &id(2), "boom", None)
        .await
        .unwrap();
    f.store
        .mark_failed(
            "log",
            &id(3),
            "again",
            Some(f.now().add(Duration::from_secs(30))),
        )
        .await
        .unwrap();
    // 3 terminal (2 delivered, 1 failed), 3 non-terminal (one retrying, two pending).
    f.clock.advance(Duration::from_secs(8 * 86400));
    let report = f.store.prune(f.now(), &policy(1_000, 10)).await.unwrap();
    assert_eq!(report.terminal_deliveries_deleted, 3);
    assert_eq!(
        report.events_deleted, 0,
        "events outlive their terminal deliveries"
    );
    assert_eq!(f.store.count_rows().await.unwrap(), (6, 3));
    // Within the window nothing is removed.
    let f2 = fx();
    put_events(&f2, 2).await;
    let first: String = f2
        .store
        .conn()
        .query_row("SELECT event_id FROM events LIMIT 1", [], |r| r.get(0))
        .unwrap();
    f2.store
        .mark_delivered("log", &crate::event::types::EventId::new(first), f2.now())
        .await
        .unwrap();
    f2.clock.advance(Duration::from_secs(6 * 86400));
    assert_eq!(
        f2.store
            .prune(f2.now(), &policy(1_000, 10))
            .await
            .unwrap()
            .terminal_deliveries_deleted,
        0
    );
}

#[tokio::test]
async fn backlog_beyond_the_per_sink_cap_dead_letters_the_oldest() {
    let f = fx();
    put_events(&f, 12).await;
    let mut p = policy(1_000, 10);
    p.max_pending_per_sink = 5;
    let report = f.store.prune(f.now(), &p).await.unwrap();
    assert_eq!(report.backlog_overflowed, 7);
    assert_eq!(
        f.count("SELECT COUNT(*) FROM event_deliveries WHERE state='pending'"),
        5
    );
    assert_eq!(f.count("SELECT COUNT(*) FROM event_deliveries WHERE state='failed' AND last_error='backlog_overflow'"), 7);
    // The oldest were the ones failed, and one overflow event reports it.
    let newest_pending: i64 = f.count("SELECT COUNT(*) FROM event_deliveries d JOIN events e USING (event_id) WHERE d.state='pending' AND e.at >= (SELECT at FROM events ORDER BY at LIMIT 1 OFFSET 7)");
    assert_eq!(newest_pending, 5);
    let overflow = f
        .store
        .query(EventQuery {
            kind: Some(EventKind::SinkBacklogOverflow),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(overflow.len(), 1);
    assert_eq!(
        overflow[0].attrs.get("sink").and_then(|v| v.as_str()),
        Some("log")
    );
}

#[tokio::test]
async fn deliveries_are_claimed_marked_and_retried_at_least_once() {
    let f = fx();
    put_events(&f, 3).await;
    let first = f.store.claim_deliveries("log", 2, f.now()).await.unwrap();
    assert_eq!(first.len(), 2);
    assert!(first.iter().all(|d| d.attempts == 1 && d.sink == "log"));
    assert_eq!(first[0].event.kind, EventKind::ConfigLoaded);
    // A claim is leased: the same rows are not handed out again straight away.
    let second = f.store.claim_deliveries("log", 10, f.now()).await.unwrap();
    assert_eq!(second.len(), 1);
    assert!(
        f.store
            .claim_deliveries("log", 10, f.now())
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        f.store
            .claim_deliveries("other-sink", 10, f.now())
            .await
            .unwrap()
            .is_empty()
    );
    // A worker that died mid-delivery: the lease lapses and the row comes back (at-least-once).
    f.clock.advance(Duration::from_secs(120));
    let again = f.store.claim_deliveries("log", 10, f.now()).await.unwrap();
    assert_eq!(again.len(), 3);
    assert!(again.iter().all(|d| d.attempts == 2));
    f.store
        .mark_delivered("log", &again[0].event.event_id, f.now())
        .await
        .unwrap();
    f.store
        .mark_failed(
            "log",
            &again[1].event.event_id,
            "retry later",
            Some(f.now().add(Duration::from_secs(10))),
        )
        .await
        .unwrap();
    f.store
        .mark_failed("log", &again[2].event.event_id, "retries_exhausted", None)
        .await
        .unwrap();
    assert!(
        f.store
            .claim_deliveries("log", 10, f.now())
            .await
            .unwrap()
            .is_empty()
    );
    f.clock.advance(Duration::from_secs(11));
    let retry = f.store.claim_deliveries("log", 10, f.now()).await.unwrap();
    assert_eq!(retry.len(), 1);
    assert_eq!(retry[0].event.event_id, again[1].event.event_id);
    assert_eq!(
        f.count("SELECT COUNT(*) FROM event_deliveries WHERE state='delivered'"),
        1
    );
    assert_eq!(
        f.count("SELECT COUNT(*) FROM event_deliveries WHERE state='failed'"),
        1
    );
}

#[tokio::test]
async fn diagnostic_events_are_bounded_and_have_no_delivery_rows() {
    let f = fx();
    f.store
        .append_diagnostic(f.event(EventKind::VerifyDenied))
        .await
        .unwrap();
    assert!(matches!(
        f.store
            .append_diagnostic(f.event(EventKind::LoginStarted))
            .await,
        Err(StoreError::Conflict(_))
    ));
    let rows = f.store.query(EventQuery::default()).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].kind, EventKind::VerifyDenied);
    assert_eq!(f.store.count_rows().await.unwrap(), (1, 0));

    // The queue is bounded: with the writer held, appends beyond the cap say Busy.
    f.hooks.set_gate("redeem", true);
    let u = f.user(1).await;
    let s = f.session(&u, vec![]).await;
    let c = f.code(&s).await;
    let (req, _) = f.redeem_req(&c, None);
    let st = f.store.clone();
    let blocker = tokio::spawn(async move { st.redeem_handoff_code(req, vec![], vec![]).await });
    let h = f.hooks.clone();
    assert!(
        tokio::task::spawn_blocking(move || h.wait_reached("redeem", 1, Duration::from_secs(5)))
            .await
            .unwrap()
    );
    let mut busy = 0;
    for _ in 0..(super::DIAGNOSTIC_QUEUE_CAP + 10) {
        if matches!(
            f.store
                .append_diagnostic(f.event(EventKind::VerifyDenied))
                .await,
            Err(StoreError::Busy)
        ) {
            busy += 1;
        }
    }
    assert_eq!(busy, 10);
    f.hooks.set_gate("redeem", false);
    blocker.await.unwrap().unwrap();
    f.store.barrier().await.unwrap();
    assert_eq!(
        f.store.count_rows().await.unwrap().0 as usize,
        1 + super::DIAGNOSTIC_QUEUE_CAP
    );
}

// ---- hooks, deadline, misc ----------------------------------------------

#[tokio::test]
async fn stall_hook_and_deadline_make_a_slow_store_fail_closed() {
    let f = fx();
    let u = f.user(1).await;
    f.hooks.set_stall(500);
    let started = std::time::Instant::now();
    let deadline = tokio::time::Instant::now() + Duration::from_millis(100);
    let out = super::with_deadline(deadline, f.store.user_authz(&u.user_id)).await;
    assert!(matches!(out, Err(StoreError::Unavailable(_))), "{out:?}");
    assert!(started.elapsed() < Duration::from_millis(400));
    // Without a deadline the call waits out the stall and succeeds.
    assert!(f.store.user_authz(&u.user_id).await.unwrap().is_some());
    f.hooks.set_stall(0);
    let calls = f.hooks.calls();
    assert!(
        calls.get("user_authz").copied().unwrap_or(0) >= 2,
        "{calls:?}"
    );
}

#[tokio::test]
async fn crash_hook_is_inert_unless_its_label_is_armed() {
    let f = fx();
    f.hooks.set_crash_at(Some("after_log_line".into()));
    f.hooks.crash_point("before_login_commit"); // different label: nothing happens
    f.hooks.set_crash_at(None);
    f.hooks.crash_point("after_log_line");
    let u = f.user(1).await;
    let s = f.session(&u, vec![]).await;
    assert_eq!(s.row.cred_gen, 1);
}

#[tokio::test]
async fn refresh_snapshot_updates_the_session_identity() {
    let f = fx();
    let u = f.user(1).await;
    let s = f.session(&u, vec![]).await;
    let snap = IdentitySnapshot {
        email: u.primary_email.clone(),
        display_name: Some("Renamed".into()),
        username: u.username.clone(),
        groups: vec!["staff".into(), "admins".into()],
    };
    f.store
        .refresh_snapshot(&s.row.session_id, snap, 4)
        .await
        .unwrap();
    let row = f.store.session(&s.row.session_id).await.unwrap().unwrap();
    assert_eq!(row.authz_version, 4);
    assert_eq!(row.snapshot.groups, ["staff", "admins"]);
    assert_eq!(row.snapshot.display_name.as_deref(), Some("Renamed"));
    assert_eq!(row.factors.len(), 1);
    assert_eq!(row.bound_ip, ip("192.0.2.10"));
}

#[test]
fn schema_has_the_documented_tables_and_indexes() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(
        &dir.path().join("h.db"),
        Arc::new(TestClock::new(Timestamp(0))),
        vec![],
        None,
    )
    .unwrap();
    let c = store.conn();
    let names = |kind: &str| -> Vec<String> {
        c.prepare(&format!("SELECT name FROM sqlite_master WHERE type='{kind}' AND name NOT LIKE 'sqlite_%' ORDER BY name"))
            .unwrap().query_map([], |r| r.get(0)).unwrap().map(Result::unwrap).collect()
    };
    let tables = names("table");
    for t in [
        "apps",
        "event_deliveries",
        "events",
        "handoff_codes",
        "identities",
        "login_txns",
        "meta",
        "providers",
        "session_handles",
        "sessions",
        "users",
    ] {
        assert!(tables.iter().any(|x| x == t), "missing table {t}");
    }
    let strict: i64 = c.query_row("SELECT COUNT(*) FROM pragma_table_list WHERE schema='main' AND strict=1 AND name NOT LIKE 'sqlite_%'", [], |r| r.get(0)).unwrap();
    assert_eq!(strict as usize, tables.len(), "every table is STRICT");
    let idx = names("index");
    for i in [
        "identities_user_id",
        "identities_email",
        "sessions_user_terminated",
        "session_handles_session",
        "events_at",
        "events_user_at",
        "events_ip_at",
        "event_deliveries_claim",
        "handoff_codes_session",
        "handoff_codes_expires",
        "login_txns_state",
        "login_txns_expires",
    ] {
        assert!(idx.iter().any(|x| x == i), "missing index {i}");
    }
    let cascade: i64 = c.query_row("SELECT COUNT(*) FROM pragma_foreign_key_list('event_deliveries') WHERE on_delete='CASCADE'", [], |r| r.get(0)).unwrap();
    assert_eq!(cascade, 1);
}
