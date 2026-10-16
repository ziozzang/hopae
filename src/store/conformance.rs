//! Dual-backend conformance suite for the slice-1 store contract
//! ([`super::core::CoreStore`], ADR-0020, scenario 600). Every case runs
//! against SQLite always and against PostgreSQL when the crate is built with
//! the `postgres` feature and `HOPAE_TEST_POSTGRES_URL` names a server; each
//! PostgreSQL run uses a fresh schema that is dropped afterwards.
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use super::core::{AdminStore, CoreStore, HandoffStore, NonceStore};
use super::types::*;
use super::{StoreError, StoreResult};
use crate::crypto::{Clock, Digest, SeededRng, TestClock, Timestamp, random_id, random_token};
use crate::event::types::{Event, EventBuilder, EventKind, Outcome, reasons};
use crate::identity::types::NormalizedEmail;
use crate::policy::types::Host;
use crate::provider::types::{ProviderId, ProviderKind};
use crate::session::types::{Aal, FactorEntry, FactorKind, SessionId};

const T0: i64 = 1_700_000_000_000;

pub(crate) struct Backend {
    pub store: Arc<dyn CoreStore>,
    pub handoff: Arc<dyn HandoffStore>,
    pub admin: Arc<dyn AdminStore>,
    pub nonces: Arc<dyn NonceStore>,
    pub clock: Arc<TestClock>,
    pub rng: Arc<SeededRng>,
    _dir: Option<tempfile::TempDir>,
    #[cfg(feature = "postgres")]
    pg: Option<(Arc<super::postgres::PgStore>, String)>,
}

impl Backend {
    async fn cleanup(self) {
        #[cfg(feature = "postgres")]
        if let Some((pg, schema)) = self.pg {
            let client = pg.raw().await;
            client
                .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
                .await
                .expect("drop test schema");
        }
    }
}

fn sqlite() -> Backend {
    let dir = tempfile::tempdir().unwrap();
    let clock = Arc::new(TestClock::new(Timestamp(T0)));
    let store = super::sqlite::Store::open(
        &dir.path().join("hopae.db"),
        clock.clone(),
        vec!["log".to_string()],
        None,
    )
    .unwrap();
    let rng = Arc::new(SeededRng::new(42));
    store.set_rng(Arc::new(SeededRng::new(99)));
    let store = Arc::new(store);
    Backend {
        store: store.clone(),
        handoff: store.clone(),
        admin: store.clone(),
        nonces: store,
        clock,
        rng,
        _dir: Some(dir),
        #[cfg(feature = "postgres")]
        pg: None,
    }
}

#[cfg(feature = "postgres")]
pub(crate) async fn postgres() -> Option<Backend> {
    let url = std::env::var("HOPAE_TEST_POSTGRES_URL").ok()?;
    let clock = Arc::new(TestClock::new(Timestamp(T0)));
    let schema = format!(
        "hopae_t_{}",
        random_id(&crate::crypto::OsRng, "").to_ascii_lowercase()
    );
    let store = super::postgres::PgStore::connect(
        super::postgres::PgOptions {
            url,
            ca_pem: None,
            pool_size: 8,
            connect_timeout: Duration::from_secs(5),
            statement_timeout: Duration::from_secs(5),
            search_path: Some(schema.clone()),
        },
        clock.clone(),
        Arc::new(SeededRng::new(99)),
        vec!["log".to_string()],
    )
    .await
    .expect("connect to HOPAE_TEST_POSTGRES_URL");
    let store = Arc::new(store);
    Some(Backend {
        handoff: store.clone(),
        admin: store.clone(),
        nonces: store.clone(),
        store: store.clone(),
        clock,
        rng: Arc::new(SeededRng::new(42)),
        _dir: None,
        pg: Some((store, schema)),
    })
}

pub(crate) async fn backends() -> Vec<Backend> {
    #[allow(unused_mut)]
    let mut all = vec![sqlite()];
    #[cfg(feature = "postgres")]
    if let Some(pg) = postgres().await {
        all.push(pg);
    }
    all
}

// ---- fixtures ----------------------------------------------------------

fn provider(id: &str, enabled: bool) -> ProviderRow {
    ProviderRow {
        provider_id: ProviderId::new(id),
        kind: ProviderKind::Oidc,
        display_name: id.to_uppercase(),
        enabled,
        managed_by: ManagedBy::File,
        deleted_at: None,
        sort_order: 0,
        config: serde_json::json!({"client_id": "hopae", "issuer": "https://idp.example.test"}),
        client_secret_env: None,
        allowed_email_domains: vec![],
        authoritative_domains: vec![],
        auto_link: false,
        trust_email: false,
    }
}

fn identity(provider: &str, sub: &str, email: Option<&NormalizedEmail>) -> NewIdentity {
    NewIdentity {
        provider_id: ProviderId::new(provider),
        subject: sub.into(),
        email: email.cloned(),
        email_verified: true,
        email_authoritative: false,
        name: Some(format!("Name {sub}")),
        picture: None,
        raw_claims: serde_json::json!({"sub": sub}),
    }
}

fn new_user(n: u32) -> (NewUser, NormalizedEmail) {
    let email = NormalizedEmail::parse(&format!("user{n}@example.test")).unwrap();
    (
        NewUser {
            primary_email: Some(email.clone()),
            email_verified: true,
            email_authoritative: false,
            display_name: Some(format!("User {n}")),
            username: Some(format!("user{n}")),
        },
        email,
    )
}

fn ev(b: &Backend, kind: EventKind) -> Event {
    EventBuilder::new(
        b.clock.as_ref(),
        b.rng.as_ref(),
        kind,
        Outcome::Info,
        "req-conformance",
    )
    .attr("count", 3)
    .build()
}

fn session_row(b: &Backend, user: &User) -> SessionRow {
    let now = b.clock.now();
    SessionRow {
        session_id: SessionId::new(random_id(b.rng.as_ref(), "s_")),
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
        bound_ip: "192.0.2.10".parse::<IpAddr>().unwrap(),
        bound_ua_sha256: Some(Digest([7; 32])),
        created_at: now,
        last_seen_at: now,
        absolute_expires_at: now.add(Duration::from_secs(30 * 86400)),
        terminated_at: None,
        terminated_reason: None,
        authz_version_at_auth: user.authz_version,
        auth_time_source: AuthTimeSource::HopaeCompletion,
        bound_ua_prefix: Some("Mozilla/5.0".into()),
    }
}

fn handle(b: &Backend, session: &SessionId) -> HandleRow {
    let now = b.clock.now();
    HandleRow {
        handle_sha256: random_token(b.rng.as_ref(), 32).digest(),
        session_id: session.clone(),
        host: Host::parse("auth.example.test").unwrap(),
        issued_aal: Aal::One,
        created_at: now,
        last_seen_at: now,
        absolute_expires_at: now.add(Duration::from_secs(7 * 86400)),
        revoked_at: None,
        revoked_reason: None,
    }
}

async fn user(b: &Backend, n: u32) -> User {
    let (u, email) = new_user(n);
    b.store
        .create_user(
            u,
            identity("mock", &format!("sub-{n}"), Some(&email)),
            vec![],
        )
        .await
        .unwrap()
}

async fn session(b: &Backend, u: &User) -> (SessionRow, HandleRow) {
    let row = session_row(b, u);
    let h = handle(b, &row.session_id);
    b.store
        .create_session(CreateSession {
            provider_configuration: None,
            session: row.clone(),
            portal_handle: h.clone(),
            portal_handle_digest: h.handle_sha256,
            consume_txn: None,
            events: vec![],
        })
        .await
        .unwrap();
    (row, h)
}

fn conflict<T: std::fmt::Debug>(r: StoreResult<T>) -> bool {
    matches!(r, Err(StoreError::Conflict(_)))
}

// ---- cases ---------------------------------------------------------------

async fn users_identities_and_outbox(b: &Backend) {
    let name = b.store.backend();
    b.store
        .ensure_provider(provider("mock", true))
        .await
        .unwrap();
    b.store
        .ensure_provider(provider("off", false))
        .await
        .unwrap();
    let (u, email) = new_user(1);
    let created_event = ev(b, EventKind::IdentityLinked);
    let id = created_event.event_id.clone();
    let user = b
        .store
        .create_user(
            u.clone(),
            identity("mock", "sub-1", Some(&email)),
            vec![created_event],
        )
        .await
        .unwrap();
    assert!(user.user_id.as_str().starts_with("u_"), "{name}");
    let read = b.store.user(&user.user_id).await.unwrap().unwrap();
    assert_eq!(read.primary_email, Some(email.clone()), "{name}");
    assert_eq!(read.created_at, Timestamp::from_secs(T0 / 1000), "{name}");
    assert_eq!(read.username.as_deref(), Some("user1"));
    let authz = b.store.user_authz(&user.user_id).await.unwrap().unwrap();
    assert_eq!((authz.status, authz.authz_version), (UserStatus::Active, 1));
    assert_eq!(
        b.store
            .user_by_email(&email)
            .await
            .unwrap()
            .unwrap()
            .user_id,
        user.user_id
    );
    let i = b
        .store
        .identity(&ProviderId::new("mock"), "sub-1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(i.user_id, user.user_id, "{name}");
    // The event and its delivery row travel with the user.
    let events = b.store.recent_events(10).await.unwrap();
    assert!(events.iter().any(|e| e.event_id == id), "{name}");
    assert_eq!(
        b.store.pending_deliveries(id.as_str()).await.unwrap(),
        vec!["log"]
    );
    // Uniqueness: identity, username, primary email.
    let (other, other_email) = new_user(2);
    assert!(
        conflict(
            b.store
                .create_user(other.clone(), identity("mock", "sub-1", None), vec![])
                .await
        ),
        "{name}: identity"
    );
    let mut same_name = other.clone();
    same_name.username = Some("user1".into());
    assert!(
        conflict(
            b.store
                .create_user(same_name, identity("mock", "sub-2", None), vec![])
                .await
        ),
        "{name}: username"
    );
    let mut same_email = other.clone();
    same_email.primary_email = Some(email.clone());
    assert!(
        conflict(
            b.store
                .create_user(same_email, identity("mock", "sub-2", None), vec![])
                .await
        ),
        "{name}: email"
    );
    // A disabled provider refuses new users and links.
    assert!(
        matches!(
            b.store
                .create_user(
                    other.clone(),
                    identity("off", "sub-x", Some(&other_email)),
                    vec![]
                )
                .await,
            Err(StoreError::ProviderDisabled)
        ),
        "{name}"
    );
    // Linking and touching.
    assert!(conflict(
        b.store
            .link_identity(
                &crate::identity::types::UserId::new("u_unknown"),
                identity("mock", "sub-9", None),
                vec![]
            )
            .await
    ));
    b.store
        .link_identity(&user.user_id, identity("mock", "sub-1b", None), vec![])
        .await
        .unwrap();
    assert!(conflict(
        b.store
            .link_identity(&user.user_id, identity("mock", "sub-1b", None), vec![])
            .await
    ));
    let later = Timestamp::from_secs(T0 / 1000 + 600);
    let mut seen = identity("mock", "sub-1b", None);
    seen.name = Some("Renamed".into());
    b.store
        .touch_identity(&ProviderId::new("mock"), "sub-1b", &seen, later)
        .await
        .unwrap();
    let touched = b
        .store
        .identity(&ProviderId::new("mock"), "sub-1b")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (touched.name.as_deref(), touched.last_seen_at),
        (Some("Renamed"), later)
    );
    assert!(conflict(
        b.store
            .touch_identity(&ProviderId::new("mock"), "missing", &seen, later)
            .await
    ));
    // The import rule overwrites a live file-managed row.
    let mut renamed = provider("mock", true);
    renamed.display_name = "Mock IdP".into();
    b.store.ensure_provider(renamed).await.unwrap();
}

async fn sessions_handles_and_termination(b: &Backend) {
    let name = b.store.backend();
    b.store
        .ensure_provider(provider("mock", true))
        .await
        .unwrap();
    let u = user(b, 1).await;
    let (row, h) = session(b, &u).await;
    let got = b.store.session(&row.session_id).await.unwrap().unwrap();
    assert_eq!(got.cred_gen, 1, "{name}");
    assert_eq!(got.bound_ua_sha256, row.bound_ua_sha256);
    assert_eq!(got.factors.len(), 1);
    assert_eq!(got.bound_ua_prefix.as_deref(), Some("Mozilla/5.0"));
    let view = b
        .store
        .lookup_handle(&h.handle_sha256, &h.host)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(view.session.session_id, row.session_id);
    assert_eq!(view.user.status, UserStatus::Active);
    assert!(
        b.store
            .lookup_handle(
                &h.handle_sha256,
                &Host::parse("other.example.test").unwrap()
            )
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        b.store
            .user(&u.user_id)
            .await
            .unwrap()
            .unwrap()
            .last_login_at,
        Some(row.created_at)
    );
    // A login transaction that is not there: nothing is created.
    let row2 = session_row(b, &u);
    let h2 = handle(b, &row2.session_id);
    assert!(
        conflict(
            b.store
                .create_session(CreateSession {
                    provider_configuration: None,
                    session: row2.clone(),
                    portal_handle: h2.clone(),
                    portal_handle_digest: h2.handle_sha256,
                    consume_txn: Some((Digest([1; 32]), reasons::OK)),
                    events: vec![],
                })
                .await
        ),
        "{name}"
    );
    assert!(
        b.store.session(&row2.session_id).await.unwrap().is_none(),
        "{name}: rolled back"
    );
    // Touch is monotonic.
    let t1 = Timestamp::from_secs(T0 / 1000 + 100);
    b.store.touch_handle(&h.handle_sha256, t1).await.unwrap();
    b.store
        .touch_handle(&h.handle_sha256, Timestamp::from_secs(T0 / 1000 + 50))
        .await
        .unwrap();
    let view = b
        .store
        .lookup_handle(&h.handle_sha256, &h.host)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (view.handle.last_seen_at, view.session.last_seen_at),
        (t1, t1),
        "{name}"
    );
    // Revocation moves the generation once.
    let (row3, h3) = session(b, &u).await;
    b.store
        .revoke_handle(
            &h3.handle_sha256,
            reasons::LOGOUT,
            t1,
            vec![ev(b, EventKind::HandleRevoked)],
        )
        .await
        .unwrap();
    b.store
        .revoke_handle(
            &h3.handle_sha256,
            reasons::LOGOUT,
            t1,
            vec![ev(b, EventKind::HandleRevoked)],
        )
        .await
        .unwrap();
    let s3 = b.store.session(&row3.session_id).await.unwrap().unwrap();
    assert_eq!(s3.cred_gen, 2, "{name}: idempotent revocation");
    assert!(conflict(
        b.store
            .revoke_handle(&Digest([9; 32]), reasons::LOGOUT, t1, vec![])
            .await
    ));
    // Termination revokes every handle and is idempotent.
    let term = ev(b, EventKind::SessionTerminated);
    let term_id = term.event_id.clone();
    b.store
        .terminate_session(&row.session_id, reasons::LOGOUT, t1, vec![term])
        .await
        .unwrap();
    b.store
        .terminate_session(
            &row.session_id,
            reasons::LOGOUT,
            t1,
            vec![ev(b, EventKind::SessionTerminated)],
        )
        .await
        .unwrap();
    let ended = b.store.session(&row.session_id).await.unwrap().unwrap();
    assert_eq!(
        (
            ended.terminated_at,
            ended.terminated_reason.as_deref(),
            ended.cred_gen
        ),
        (Some(t1), Some("logout"), 2),
        "{name}"
    );
    let view = b
        .store
        .lookup_handle(&h.handle_sha256, &h.host)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        view.handle.revoked_reason.as_deref(),
        Some("session_terminated")
    );
    let terminated: Vec<_> = b
        .store
        .recent_events(100)
        .await
        .unwrap()
        .into_iter()
        .filter(|e| e.kind == EventKind::SessionTerminated)
        .collect();
    assert_eq!(terminated.len(), 1, "{name}: no event for a no-op");
    assert_eq!(terminated[0].event_id, term_id);
    // Unknown session: nothing happens.
    b.store
        .terminate_session(&SessionId::new("s_unknown"), reasons::LOGOUT, t1, vec![])
        .await
        .unwrap();
}

async fn concurrent_writers_keep_invariants(b: &Backend) {
    let name = b.store.backend();
    b.store
        .ensure_provider(provider("mock", true))
        .await
        .unwrap();
    let u = user(b, 1).await;
    let (row, h) = session(b, &u).await;
    let at = Timestamp::from_secs(T0 / 1000 + 10);
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let (store, e, d) = (
            b.store.clone(),
            ev(b, EventKind::HandleRevoked),
            h.handle_sha256,
        );
        tasks.push(tokio::spawn(async move {
            store.revoke_handle(&d, reasons::LOGOUT, at, vec![e]).await
        }));
    }
    for t in tasks {
        t.await.unwrap().unwrap();
    }
    assert_eq!(
        b.store
            .session(&row.session_id)
            .await
            .unwrap()
            .unwrap()
            .cred_gen,
        2,
        "{name}: one generation move for racing revocations"
    );
    let revoked = b
        .store
        .recent_events(1000)
        .await
        .unwrap()
        .into_iter()
        .filter(|e| e.kind == EventKind::HandleRevoked)
        .count();
    assert_eq!(revoked, 1, "{name}: one event for racing revocations");
    // Racing creations of the same identity: exactly one wins.
    let mut tasks = Vec::new();
    for n in 10..18u32 {
        let store = b.store.clone();
        let (u, _) = new_user(n);
        tasks.push(tokio::spawn(async move {
            store
                .create_user(u, identity("mock", "shared-subject", None), vec![])
                .await
        }));
    }
    let mut ok = 0;
    for t in tasks {
        match t.await.unwrap() {
            Ok(_) => ok += 1,
            Err(StoreError::Conflict(_)) => {}
            Err(e) => panic!("{name}: {e}"),
        }
    }
    assert_eq!(ok, 1, "{name}: one identity owner");
    // Racing terminations: one termination, one event.
    let (row2, _) = session(b, &u).await;
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let (store, e, id) = (
            b.store.clone(),
            ev(b, EventKind::SessionTerminated),
            row2.session_id.clone(),
        );
        tasks.push(tokio::spawn(async move {
            store
                .terminate_session(&id, reasons::LOGOUT, at, vec![e])
                .await
        }));
    }
    for t in tasks {
        t.await.unwrap().unwrap();
    }
    let ended = b
        .store
        .recent_events(1000)
        .await
        .unwrap()
        .into_iter()
        .filter(|e| e.kind == EventKind::SessionTerminated)
        .count();
    assert_eq!(ended, 1, "{name}");
}

async fn outbox_rules(b: &Backend) {
    let name = b.store.backend();
    assert!(
        conflict(
            b.store
                .append_required(vec![ev(b, EventKind::ProviderError)])
                .await
        ),
        "{name}: diagnostic"
    );
    // Kinds that travel with a state change are a programming error
    // (debug assertion in SQLite, `Conflict` in PostgreSQL); not exercised here.
    let e = EventBuilder::new(
        b.clock.as_ref(),
        b.rng.as_ref(),
        EventKind::AdminRead,
        Outcome::Success,
        "req-1",
    )
    .ip("198.51.100.7".parse().unwrap())
    .ua(Some("Mozilla/5.0 (X11)"))
    .attr("purpose", "subjects.resolve")
    .attr("count", 2)
    .build();
    let expected = e.to_json();
    b.store.append_required(vec![e.clone()]).await.unwrap();
    let got = b.store.recent_events(1).await.unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].to_json(), expected, "{name}: identical round trip");
    assert_eq!(
        b.store
            .pending_deliveries(e.event_id.as_str())
            .await
            .unwrap(),
        vec!["log"]
    );
    // A duplicate event id is a conflict, never a second row.
    assert!(conflict(b.store.append_required(vec![e]).await), "{name}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s600_1_users_identities_ledger_and_outbox_agree_on_both_backends() {
    for b in backends().await {
        users_identities_and_outbox(&b).await;
        b.cleanup().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s600_2_sessions_handles_and_termination_agree_on_both_backends() {
    for b in backends().await {
        sessions_handles_and_termination(&b).await;
        b.cleanup().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s600_3_concurrent_writers_keep_invariants_on_both_backends() {
    for b in backends().await {
        concurrent_writers_keep_invariants(&b).await;
        b.cleanup().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s600_4_outbox_rules_agree_on_both_backends() {
    for b in backends().await {
        outbox_rules(&b).await;
        b.cleanup().await;
    }
}

fn new_txn(b: &Backend, ip: &str) -> (NewTransaction, Digest) {
    let now = b.clock.now();
    let d = random_token(b.rng.as_ref(), 32).digest();
    (
        NewTransaction {
            txn_sha256: d,
            created_at: now,
            expires_at: now.add(Duration::from_secs(600)),
            app_id: crate::policy::types::AppId::new("app"),
            return_target: url::Url::parse("https://app.example.test/admin/x").unwrap(),
            bind_sha256: Some(Digest([3; 32])),
            portal_bind_sha256: None,
            retry_bind_sha256: None,
            client_ip: ip.parse().unwrap(),
            ua_sha256: None,
            provider_id: None,
            state_sha256: None,
            nonce: None,
            pkce_verifier: None,
            portal_session_id: None,
            purpose: TxnPurpose::Login,
            conflicting_handle_sha256: None,
            pending_identity: Some(serde_json::json!({"sub": "x"})),
            recovery_depth: 1,
            reauth_max_age: Some(600),
        },
        d,
    )
}

async fn transactions(b: &Backend) {
    let name = b.store.backend();
    let since = Timestamp(T0 - 60_000);
    let h = &b.handoff;
    let (t1, d1) = new_txn(b, "192.0.2.1");
    assert!(matches!(
        h.create_transaction_capped(t1, vec![], since, Some(2), 100)
            .await
            .unwrap(),
        Admission::Admitted { evicted: 0 }
    ));
    let (t2, _) = new_txn(b, "192.0.2.1");
    h.create_transaction_capped(t2, vec![], since, Some(2), 100)
        .await
        .unwrap();
    let (t3, d3) = new_txn(b, "192.0.2.1");
    assert!(
        matches!(
            h.create_transaction_capped(t3, vec![], since, Some(2), 100)
                .await
                .unwrap(),
            Admission::OverCap
        ),
        "{name}: per-address cap"
    );
    assert!(
        h.transaction(&d3).await.unwrap().is_none(),
        "{name}: nothing written"
    );
    assert_eq!(
        h.count_transactions_since("192.0.2.1".parse().unwrap(), since)
            .await
            .unwrap(),
        2
    );
    let row = h.transaction(&d1).await.unwrap().unwrap();
    assert_eq!(row.purpose, TxnPurpose::Login);
    assert_eq!(row.pending_identity, Some(serde_json::json!({"sub": "x"})));
    assert_eq!((row.recovery_depth, row.reauth_max_age), (1, Some(600)));
    // The row bound: other addresses fill the table to max_rows.
    for i in 0..4 {
        let (t, _) = new_txn(b, &format!("198.51.100.{i}"));
        h.create_transaction_capped(t, vec![], since, None, 3)
            .await
            .unwrap();
    }
    assert!(
        h.transaction(&d1).await.unwrap().is_none(),
        "{name}: oldest evicted"
    );
    // Bind once, then find by state; consume once; retry once.
    let (t, d) = new_txn(b, "203.0.113.9");
    h.create_transaction_capped(t, vec![], since, None, 100)
        .await
        .unwrap();
    let binding = TransactionBinding {
        provider_id: ProviderId::new("mock"),
        state_sha256: Digest([5; 32]),
        nonce: Some("n".into()),
        pkce_verifier: Some(crate::crypto::Secret::new("verifier".into())),
        portal_bind_sha256: Digest([6; 32]),
    };
    h.bind_transaction(&d, binding.clone()).await.unwrap();
    assert!(
        conflict(h.bind_transaction(&d, binding).await),
        "{name}: bound once"
    );
    let by_state = h
        .transaction_by_state(&Digest([5; 32]))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(by_state.txn_sha256, d);
    assert_eq!(by_state.pkce_verifier.unwrap().expose(), "verifier");
    assert!(h.use_retry(&d, b.clock.now()).await.unwrap());
    assert!(!h.use_retry(&d, b.clock.now()).await.unwrap());
    // Racing consumers: one wins.
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let (h, e) = (b.handoff.clone(), ev(b, EventKind::LoginSucceeded));
        tasks.push(tokio::spawn(async move {
            h.consume_transaction(&d, reasons::OK, Timestamp(T0), vec![e])
                .await
        }));
    }
    let mut won = 0;
    for t in tasks {
        if t.await.unwrap().unwrap() {
            won += 1;
        }
    }
    assert_eq!(won, 1, "{name}: consume once");
}

fn code_row(
    b: &Backend,
    session: &SessionRow,
    cred_gen: u64,
) -> (HandoffCodeRow, crate::crypto::Secret) {
    let now = b.clock.now();
    let secret = random_token(b.rng.as_ref(), 32);
    (
        HandoffCodeRow {
            code_sha256: secret.digest(),
            session_id: session.session_id.clone(),
            host: Host::parse("app.example.test").unwrap(),
            return_target: url::Url::parse("https://app.example.test/admin/x").unwrap(),
            client_ip: "192.0.2.10".parse().unwrap(),
            bind_sha256: Digest([8; 32]),
            issued_aal: Aal::One,
            cred_gen,
            recovery_depth: 0,
            created_at: now,
            expires_at: now.add(Duration::from_secs(60)),
            consumed_at: None,
            consumed_reason: None,
        },
        secret,
    )
}

fn redeem_req(b: &Backend, c: &HandoffCodeRow, presented: Option<HandleView>) -> RedeemRequest {
    let mut new_handle = handle(b, &c.session_id);
    new_handle.host = Host::parse("app.example.test").unwrap();
    RedeemRequest {
        code_sha256: c.code_sha256,
        host: Host::parse("app.example.test").unwrap(),
        path: "/admin/x".into(),
        client_ip: "192.0.2.10".parse().unwrap(),
        presented_bind_sha256: Some(Digest([8; 32])),
        presented_handle: presented,
        new_handle,
        now: b.clock.now(),
        max_recoveries: 3,
        session_policy: Default::default(),
        app_lifetimes: Default::default(),
        expiry_events: vec![],
    }
}

fn rejected(b: &Backend) -> Vec<Event> {
    vec![
        EventBuilder::new(
            b.clock.as_ref(),
            b.rng.as_ref(),
            EventKind::HandoffRejected,
            Outcome::Failure,
            "req",
        )
        .ip("192.0.2.10".parse().unwrap())
        .build(),
    ]
}

async fn handoff_redemption(b: &Backend) {
    let name = b.store.backend();
    let h = &b.handoff;
    b.store
        .ensure_provider(provider("mock", true))
        .await
        .unwrap();
    let u = user(b, 1).await;
    let (row, _) = session(b, &u).await;
    let (stale, _) = code_row(b, &row, 5);
    assert!(
        conflict(h.mint_handoff_code(stale, vec![]).await),
        "{name}: stale generation"
    );
    let (c, _) = code_row(b, &row, 1);
    h.mint_handoff_code(c.clone(), vec![]).await.unwrap();
    let req = redeem_req(b, &c, None);
    let new_handle = req.new_handle.clone();
    let ok = vec![ev(b, EventKind::SessionHandoff)];
    match h.redeem_handoff_code(req, ok, rejected(b)).await.unwrap() {
        RedeemOutcome::Minted {
            session,
            issued_aal,
        } => {
            assert_eq!(session.session_id, row.session_id, "{name}");
            assert_eq!(issued_aal, Aal::One);
        }
        _ => panic!("{name}: expected Minted"),
    }
    let view = b
        .store
        .lookup_handle(&new_handle.handle_sha256, &new_handle.host)
        .await
        .unwrap()
        .unwrap();
    // A replay from the same browser is idempotent; from anyone else it is consumed.
    let again = h
        .redeem_handoff_code(redeem_req(b, &c, Some(view)), vec![], rejected(b))
        .await
        .unwrap();
    assert!(matches!(again, RedeemOutcome::AlreadyRedeemed), "{name}");
    let replay = h
        .redeem_handoff_code(redeem_req(b, &c, None), vec![], rejected(b))
        .await
        .unwrap();
    assert!(
        matches!(replay, RedeemOutcome::Rejected { reason, code: Some(_) } if reason == reasons::CODE_CONSUMED),
        "{name}"
    );
    // A mismatch is classified and burns the code.
    let (c2, _) = code_row(b, &row, 1);
    h.mint_handoff_code(c2.clone(), vec![]).await.unwrap();
    let mut wrong = redeem_req(b, &c2, None);
    wrong.host = Host::parse("other.example.test").unwrap();
    wrong.new_handle.host = wrong.host.clone();
    let out = h
        .redeem_handoff_code(wrong, vec![], rejected(b))
        .await
        .unwrap();
    assert!(
        matches!(out, RedeemOutcome::Rejected { reason, code: Some(ref burned) } if reason == reasons::CODE_HOST_MISMATCH && burned.consumed_at.is_some()),
        "{name}"
    );
    let unknown = RedeemRequest {
        code_sha256: Digest([0xee; 32]),
        ..redeem_req(b, &c2, None)
    };
    assert!(matches!(
        h.redeem_handoff_code(unknown, vec![], rejected(b)).await.unwrap(),
        RedeemOutcome::Rejected { reason, code: None } if reason == reasons::CODE_UNKNOWN
    ));
    assert!(
        h.count_handoff_failures_since("192.0.2.10".parse().unwrap(), Timestamp(T0 - 1000))
            .await
            .unwrap()
            >= 3,
        "{name}: failures counted per address"
    );
    // Racing redemptions of one code: exactly one mints.
    let (c3, _) = code_row(b, &row, 1);
    h.mint_handoff_code(c3.clone(), vec![]).await.unwrap();
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let (h, req, fail) = (b.handoff.clone(), redeem_req(b, &c3, None), rejected(b));
        tasks.push(tokio::spawn(async move {
            h.redeem_handoff_code(req, vec![], fail).await
        }));
    }
    let mut minted = 0;
    for t in tasks {
        match t.await.unwrap().unwrap() {
            RedeemOutcome::Minted { .. } => minted += 1,
            RedeemOutcome::Rejected { reason, .. } => assert_eq!(reason, reasons::CODE_CONSUMED),
            _ => panic!("{name}: unexpected outcome"),
        }
    }
    assert_eq!(minted, 1, "{name}: one redemption mints");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s600_7_login_transactions_agree_on_both_backends() {
    for b in backends().await {
        transactions(&b).await;
        b.cleanup().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s600_8_handoff_redemption_agrees_on_both_backends() {
    for b in backends().await {
        handoff_redemption(&b).await;
        b.cleanup().await;
    }
}

/// PostgreSQL only: the user-ID ledger refuses reuse across replicas,
/// migrations are idempotent under the advisory lock, and a newer schema is
/// refused (ADR-0020 decisions 3 and 4).
#[cfg(feature = "postgres")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s600_5_postgres_ledger_migrations_and_newer_schema() {
    let Some(b) = postgres().await else {
        eprintln!("skip: HOPAE_TEST_POSTGRES_URL not set");
        return;
    };
    let (pg, schema) = b.pg.clone().unwrap();
    b.store
        .ensure_provider(provider("mock", true))
        .await
        .unwrap();
    let u = user(&b, 1).await;
    let client = pg.raw().await;
    // Remove the user row by hand: its ID stays reserved.
    client
        .batch_execute(&format!(
            "DELETE FROM identities WHERE user_id='{0}'; DELETE FROM users WHERE user_id='{0}'",
            u.user_id.as_str()
        ))
        .await
        .unwrap();
    let reuse = client
        .execute(
            "INSERT INTO users (user_id, created_at, updated_at) VALUES ($1, 0, 0)",
            &[&u.user_id.as_str()],
        )
        .await;
    assert!(reuse.is_err(), "a reserved ID is never reused");
    assert!(
        client
            .execute("DELETE FROM human_user_ids", &[])
            .await
            .is_err(),
        "reservations are permanent"
    );
    // Concurrent migrations by several replicas: all succeed, one applies.
    let mut tasks = Vec::new();
    for _ in 0..4 {
        let pg = pg.clone();
        tasks.push(tokio::spawn(async move { pg.migrate().await }));
    }
    for t in tasks {
        assert_eq!(
            t.await.unwrap().unwrap(),
            super::postgres::LATEST_SCHEMA_VERSION
        );
    }
    let applied: i64 = client
        .query_one("SELECT count(*) FROM schema_migrations", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(applied, i64::from(super::postgres::LATEST_SCHEMA_VERSION));
    // A database migrated by a newer binary is refused.
    client
        .execute(
            "INSERT INTO schema_migrations (version, name, applied_at) VALUES (9999, 'future', 0)",
            &[],
        )
        .await
        .unwrap();
    assert!(matches!(
        pg.migrate().await,
        Err(StoreError::SchemaTooNew { found: 9999, .. })
    ));
    drop(client);
    let _ = schema;
    b.cleanup().await;
}

// ---- slice 2b: administrator grants, the actor fence, replay ledger -------

fn grant_event(b: &Backend) -> Event {
    EventBuilder::new(
        b.clock.as_ref(),
        b.rng.as_ref(),
        EventKind::IdentityLinked,
        Outcome::Info,
        "req-conformance",
    )
    .build()
}

fn deadline() -> Deadline {
    Deadline::after(Duration::from_secs(10))
}

fn actor_of(row: &SessionRow, h: &HandleRow) -> Actor {
    Actor {
        user_id: row.user_id.clone(),
        session_id: row.session_id.clone(),
        handle_sha256: h.handle_sha256,
    }
}

fn console_policy(b: &Backend) -> ActorPolicy {
    ActorPolicy {
        authority: None,
        console_host: Host::parse("auth.example.test").unwrap(),
        session: Default::default(),
        handle: Default::default(),
        max_auth_age: Duration::from_secs(86400),
        capability_requires_claim: false,
        require_aal: Aal::One,
        now: b.clock.now(),
        skew: Duration::from_secs(60),
    }
}

async fn admin_grants(b: &Backend) {
    let name = b.store.backend();
    b.store
        .ensure_provider(provider("mock", true))
        .await
        .unwrap();
    let u = user(b, 1).await;
    let (_, email) = new_user(1);
    let at = b.clock.now();
    let ghost = crate::identity::types::UserId::new("u_GHOST");
    assert!(
        matches!(
            b.admin
                .grant_admin(
                    &ghost,
                    AdminRole::Admin,
                    GrantManagedBy::Api,
                    None,
                    "op",
                    None,
                    at,
                    grant_event(b)
                )
                .await,
            Err(StoreError::Conflict("unknown user"))
        ),
        "{name}"
    );
    let first = b
        .admin
        .grant_admin(
            &u.user_id,
            AdminRole::Viewer,
            GrantManagedBy::File,
            Some(email.clone()),
            "op",
            None,
            at,
            grant_event(b),
        )
        .await
        .unwrap();
    assert_eq!(first, (None, true), "{name}");
    // The same live grant again is no change and writes no event.
    let before = b.store.recent_events(100).await.unwrap().len();
    let again = b
        .admin
        .grant_admin(
            &u.user_id,
            AdminRole::Viewer,
            GrantManagedBy::File,
            Some(email.clone()),
            "op",
            None,
            at,
            grant_event(b),
        )
        .await
        .unwrap();
    assert_eq!(again, (Some(AdminRole::Viewer), false), "{name}");
    assert_eq!(
        b.store.recent_events(100).await.unwrap().len(),
        before,
        "{name}"
    );
    // A binding is never replaced by another address.
    let other = NormalizedEmail::parse("other@example.test").unwrap();
    assert!(
        matches!(
            b.admin
                .grant_admin(
                    &u.user_id,
                    AdminRole::Admin,
                    GrantManagedBy::File,
                    Some(other),
                    "op",
                    None,
                    at,
                    grant_event(b)
                )
                .await,
            Err(StoreError::Conflict("source_email_bound"))
        ),
        "{name}"
    );
    // A role change is a write that records the previous role.
    let promote = grant_event(b);
    let promote_id = promote.event_id.clone();
    let up = b
        .admin
        .grant_admin(
            &u.user_id,
            AdminRole::Admin,
            GrantManagedBy::Api,
            None,
            "op2",
            Some("note".into()),
            at,
            promote,
        )
        .await
        .unwrap();
    assert_eq!(up, (Some(AdminRole::Viewer), true), "{name}");
    let e = b
        .store
        .recent_events(100)
        .await
        .unwrap()
        .into_iter()
        .find(|e| e.event_id == promote_id)
        .unwrap();
    assert_eq!(
        e.attrs.get("previous_role").and_then(|v| v.as_str()),
        Some("viewer"),
        "{name}"
    );
    let g = b
        .admin
        .admin_grant(&u.user_id, deadline())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (g.role, g.managed_by, g.granted_by.as_str()),
        (AdminRole::Admin, GrantManagedBy::Api, "op2"),
        "{name}"
    );
    assert_eq!(g.source_email, Some(email.clone()), "{name}: binding kept");
    assert_eq!(g.note.as_deref(), Some("note"), "{name}");
    // Revocation: once, then nothing to revoke; the row stays for audit.
    assert!(
        b.admin
            .revoke_admin(&u.user_id, "op3", GrantManagedBy::Api, at, grant_event(b))
            .await
            .unwrap(),
        "{name}"
    );
    assert!(
        !b.admin
            .revoke_admin(&u.user_id, "op3", GrantManagedBy::Api, at, grant_event(b))
            .await
            .unwrap(),
        "{name}"
    );
    assert!(
        b.admin
            .admin_grants(false, deadline())
            .await
            .unwrap()
            .is_empty(),
        "{name}"
    );
    let all = b.admin.admin_grants(true, deadline()).await.unwrap();
    assert_eq!(all.len(), 1, "{name}");
    assert_eq!(all[0].revoked_by.as_deref(), Some("op3"), "{name}");
    // Re-granting a revoked row revives it and reports the old role.
    let back = b
        .admin
        .grant_admin(
            &u.user_id,
            AdminRole::Admin,
            GrantManagedBy::Api,
            None,
            "op",
            None,
            at,
            grant_event(b),
        )
        .await
        .unwrap();
    assert_eq!(back, (Some(AdminRole::Admin), true), "{name}");
    assert!(
        b.admin
            .admin_grant(&u.user_id, deadline())
            .await
            .unwrap()
            .unwrap()
            .revoked_at
            .is_none()
    );
}

async fn fenced_console_mutations(b: &Backend) {
    let name = b.store.backend();
    b.store
        .ensure_provider(provider("mock", true))
        .await
        .unwrap();
    let admin = user(b, 1).await;
    let (row, h) = session(b, &admin).await;
    let actor = actor_of(&row, &h);
    let policy = console_policy(b);
    let target = user(b, 2).await;
    let (t1, _) = session(b, &target).await;
    let (t2, _) = session(b, &target).await;
    let mk = |s: &SessionRow| {
        let mut e = grant_event(b);
        e.session_id = Some(s.session_id.clone());
        e
    };
    // No grant: the fence refuses before anything is written.
    let out = b
        .admin
        .set_user_status(
            &actor,
            &policy,
            &target.user_id,
            UserStatus::Disabled,
            deadline(),
            grant_event(b),
            &mk,
        )
        .await;
    assert!(
        matches!(out, Err(StoreError::Conflict("actor_revoked"))),
        "{name}: {out:?}"
    );
    assert_eq!(
        b.store
            .user_authz(&target.user_id)
            .await
            .unwrap()
            .unwrap()
            .status,
        UserStatus::Active
    );
    b.admin
        .grant_admin(
            &admin.user_id,
            AdminRole::Admin,
            GrantManagedBy::Api,
            None,
            "op",
            None,
            b.clock.now(),
            grant_event(b),
        )
        .await
        .unwrap();
    // A viewer-only requirement the session cannot meet is refused too.
    let mut strict = console_policy(b);
    strict.capability_requires_claim = true;
    assert!(
        conflict(
            b.admin
                .set_user_status(
                    &actor,
                    &strict,
                    &target.user_id,
                    UserStatus::Disabled,
                    deadline(),
                    grant_event(b),
                    &mk
                )
                .await
        ),
        "{name}: claim"
    );
    let mut other_host = console_policy(b);
    other_host.console_host = Host::parse("console.example.test").unwrap();
    assert!(
        conflict(
            b.admin
                .set_user_status(
                    &actor,
                    &other_host,
                    &target.user_id,
                    UserStatus::Disabled,
                    deadline(),
                    grant_event(b),
                    &mk
                )
                .await
        ),
        "{name}: host"
    );
    // An expired deadline writes nothing.
    let gone = Deadline(std::time::Instant::now() - Duration::from_millis(1));
    assert!(
        matches!(
            b.admin.set_user_status(&actor, &policy, &target.user_id, UserStatus::Disabled, gone, grant_event(b), &mk).await,
            Err(StoreError::Unavailable(ref m)) if m == "deadline"
        ),
        "{name}: deadline"
    );
    // Disabling ends every live session, one event each, and counts them.
    let disable = grant_event(b);
    let disable_id = disable.event_id.clone();
    let out = b
        .admin
        .set_user_status(
            &actor,
            &policy,
            &target.user_id,
            UserStatus::Disabled,
            deadline(),
            disable,
            &mk,
        )
        .await
        .unwrap();
    assert_eq!(out, (true, 2), "{name}");
    for s in [&t1, &t2] {
        let r = b.store.session(&s.session_id).await.unwrap().unwrap();
        assert_eq!(
            r.terminated_reason,
            Some(reasons::USER_DISABLED.0.to_string()),
            "{name}"
        );
    }
    let events = b.store.recent_events(100).await.unwrap();
    let e = events.iter().find(|e| e.event_id == disable_id).unwrap();
    assert_eq!(
        e.attrs.get("count").and_then(|v| v.as_u64()),
        Some(2),
        "{name}"
    );
    assert_eq!(
        events
            .iter()
            .filter(|e| e
                .session_id
                .as_ref()
                .is_some_and(|s| *s == t1.session_id || *s == t2.session_id))
            .count(),
        2,
        "{name}"
    );
    let authz = b.store.user_authz(&target.user_id).await.unwrap().unwrap();
    assert_eq!(
        (authz.status, authz.authz_version),
        (UserStatus::Disabled, 2),
        "{name}"
    );
    // Idempotent, unknown user, and a disabled user cannot be granted.
    assert_eq!(
        b.admin
            .set_user_status(
                &actor,
                &policy,
                &target.user_id,
                UserStatus::Disabled,
                deadline(),
                grant_event(b),
                &mk
            )
            .await
            .unwrap(),
        (false, 0)
    );
    let ghost = crate::identity::types::UserId::new("u_GHOST");
    assert!(matches!(
        b.admin
            .set_user_status(
                &actor,
                &policy,
                &ghost,
                UserStatus::Disabled,
                deadline(),
                grant_event(b),
                &mk
            )
            .await,
        Err(StoreError::Conflict("unknown user"))
    ));
    assert!(matches!(
        b.admin
            .grant_admin(
                &target.user_id,
                AdminRole::Admin,
                GrantManagedBy::Api,
                None,
                "op",
                None,
                b.clock.now(),
                grant_event(b)
            )
            .await,
        Err(StoreError::Conflict("user_disabled"))
    ));
    assert_eq!(
        b.admin
            .set_user_status(
                &actor,
                &policy,
                &target.user_id,
                UserStatus::Active,
                deadline(),
                grant_event(b),
                &mk
            )
            .await
            .unwrap(),
        (true, 0)
    );
    // A single session: ended once; a second termination is no change.
    let (t3, _) = session(b, &target).await;
    let mut sev = grant_event(b);
    sev.session_id = Some(t3.session_id.clone());
    assert!(
        b.admin
            .admin_terminate_session(
                &actor,
                &policy,
                &t3.session_id,
                deadline(),
                grant_event(b),
                sev.clone()
            )
            .await
            .unwrap(),
        "{name}"
    );
    assert_eq!(
        b.store
            .session(&t3.session_id)
            .await
            .unwrap()
            .unwrap()
            .terminated_reason,
        Some(reasons::ADMIN.0.to_string())
    );
    assert!(
        !b.admin
            .admin_terminate_session(
                &actor,
                &policy,
                &t3.session_id,
                deadline(),
                grant_event(b),
                sev
            )
            .await
            .unwrap(),
        "{name}"
    );
    // Revoking the actor's grant closes the fence for the next mutation.
    b.admin
        .revoke_admin(
            &admin.user_id,
            "op",
            GrantManagedBy::Api,
            b.clock.now(),
            grant_event(b),
        )
        .await
        .unwrap();
    let (t4, _) = session(b, &target).await;
    assert!(
        matches!(
            b.admin
                .admin_terminate_session(
                    &actor,
                    &policy,
                    &t4.session_id,
                    deadline(),
                    grant_event(b),
                    grant_event(b)
                )
                .await,
            Err(StoreError::Conflict("actor_revoked"))
        ),
        "{name}"
    );
    assert!(
        b.store
            .session(&t4.session_id)
            .await
            .unwrap()
            .unwrap()
            .terminated_at
            .is_none()
    );
    // An actor whose own session ended is fenced out once re-granted.
    b.admin
        .grant_admin(
            &admin.user_id,
            AdminRole::Admin,
            GrantManagedBy::Api,
            None,
            "op",
            None,
            b.clock.now(),
            grant_event(b),
        )
        .await
        .unwrap();
    assert!(
        b.admin
            .admin_terminate_session(
                &actor,
                &policy,
                &t4.session_id,
                deadline(),
                grant_event(b),
                grant_event(b)
            )
            .await
            .unwrap()
    );
    b.store
        .terminate_session(&row.session_id, reasons::LOGOUT, b.clock.now(), vec![])
        .await
        .unwrap();
    let (t5, _) = session(b, &target).await;
    assert!(
        conflict(
            b.admin
                .admin_terminate_session(
                    &actor,
                    &policy,
                    &t5.session_id,
                    deadline(),
                    grant_event(b),
                    grant_event(b)
                )
                .await
        ),
        "{name}"
    );
}

async fn replay_ledger(b: &Backend) {
    let name = b.store.backend();
    let now = Timestamp::from_secs(1000);
    let exp = Timestamp::from_secs(1031);
    assert!(
        b.nonces
            .admit_nonce("delegation", "n-1", exp, now, 8)
            .await
            .unwrap(),
        "{name}"
    );
    assert!(
        !b.nonces
            .admit_nonce("delegation", "n-1", exp, now, 8)
            .await
            .unwrap(),
        "{name}"
    );
    // Scopes are separate ledgers.
    assert!(
        b.nonces
            .admit_nonce("other", "n-1", exp, now, 8)
            .await
            .unwrap(),
        "{name}"
    );
    // Malformed keys are refused, never stored.
    for (scope, nonce) in [
        ("", "n"),
        ("delegation", ""),
        ("bad scope", "n"),
        ("delegation", "a%b"),
    ] {
        assert!(
            conflict(b.nonces.admit_nonce(scope, nonce, exp, now, 8).await),
            "{name}: {scope:?} {nonce:?}"
        );
    }
    // Capacity is per scope and fails closed until entries expire.
    assert!(b.nonces.admit_nonce("cap", "a", exp, now, 2).await.unwrap());
    assert!(
        b.nonces
            .admit_nonce("cap", "b", Timestamp::from_secs(2000), now, 2)
            .await
            .unwrap()
    );
    assert!(
        !b.nonces.admit_nonce("cap", "c", exp, now, 2).await.unwrap(),
        "{name}: full"
    );
    assert!(
        !b.nonces
            .admit_nonce("cap", "a", exp, Timestamp::from_secs(1030), 2)
            .await
            .unwrap(),
        "{name}: still live"
    );
    assert!(
        b.nonces
            .admit_nonce("cap", "a", exp, Timestamp::from_secs(1031), 2)
            .await
            .unwrap(),
        "{name}: expired"
    );
    // Concurrent replicas presenting one nonce: exactly one is admitted.
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let n = b.nonces.clone();
        tasks.push(tokio::spawn(async move {
            n.admit_nonce("race", "same", exp, now, 64).await
        }));
    }
    let mut admitted = 0;
    for t in tasks {
        if t.await.unwrap().unwrap() {
            admitted += 1;
        }
    }
    assert_eq!(admitted, 1, "{name}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s600_9_admin_grants_agree_on_both_backends() {
    for b in backends().await {
        admin_grants(&b).await;
        b.cleanup().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s600_10_fenced_console_mutations_agree_on_both_backends() {
    for b in backends().await {
        fenced_console_mutations(&b).await;
        b.cleanup().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s600_11_replay_ledger_admits_each_nonce_once_on_both_backends() {
    for b in backends().await {
        replay_ledger(&b).await;
        b.cleanup().await;
    }
}
