//! Dual-backend conformance suite for the slice-1 store contract
//! ([`super::core::CoreStore`], ADR-0020, scenario 600). Every case runs
//! against SQLite always and against PostgreSQL when the crate is built with
//! the `postgres` feature and `HOPAE_TEST_POSTGRES_URL` names a server; each
//! PostgreSQL run uses a fresh schema that is dropped afterwards.
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use super::core::{AdminStore, ConsoleStore, CoreStore, HandoffStore, NonceStore};
use super::passkeys::*;
use super::types::*;
use super::{Events, Factors, Passkeys};
use super::{StoreError, StoreResult};
use crate::crypto::{Clock, Digest, SeededRng, TestClock, Timestamp, random_id, random_token};
use crate::event::types::{Event, EventBuilder, EventId, EventKind, Outcome, reasons};
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
    pub factors: Arc<dyn Factors>,
    pub passkeys: Arc<dyn Passkeys>,
    pub events: Arc<dyn Events>,
    pub console: Arc<dyn ConsoleStore>,
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
        nonces: store.clone(),
        factors: store.clone(),
        passkeys: store.clone(),
        events: store.clone(),
        console: store,
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
        factors: store.clone(),
        passkeys: store.clone(),
        events: store.clone(),
        console: store.clone(),
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

// ---- slice 2c: second factors and passkeys -------------------------------

const PORTAL: &str = "auth.example.test";

fn factor_actor(b: &Backend, view: &HandleView) -> FactorActor {
    FactorActor {
        request_id: "r_conformance".into(),
        provider_configuration: (ProviderKind::Oidc, provider("mock", true).config),
        client_ip: "192.0.2.10".parse().unwrap(),
        view: view.clone(),
        authorized_at: b.clock.now(),
        session_idle: Duration::from_secs(86_400),
        handle_idle: Duration::from_secs(86_400),
    }
}

async fn view_of(b: &Backend, h: &HandleRow) -> HandleView {
    b.store
        .lookup_handle(&h.handle_sha256, &Host::parse(PORTAL).unwrap())
        .await
        .unwrap()
        .unwrap()
}

fn envelope(b: &Backend, user: &User, id: &str) -> crate::factor::seed_cipher::Envelope {
    let key = crate::factor::seed_cipher::Key::new("key-1".into(), [7; 32]).unwrap();
    let seed = crate::factor::totp::Seed::from_bytes(&[5; 20]).unwrap();
    key.seal(&seed, user.user_id.as_str(), id, b.rng.as_ref())
        .unwrap()
}

/// A reissued portal handle at `aal` that does not outlive `view`'s.
fn elevated_handle(b: &Backend, view: &HandleView, aal: Aal) -> HandleRow {
    let mut h = handle(b, &view.session.session_id);
    h.issued_aal = aal;
    h.absolute_expires_at = view.handle.absolute_expires_at;
    h
}

/// A step-up transaction of the portal session, matching `code`.
async fn stepup_txn(b: &Backend, view: &HandleView, code: &HandoffCodeRow) -> Digest {
    let (mut txn, d) = new_txn(b, "192.0.2.10");
    txn.purpose = TxnPurpose::Stepup;
    txn.portal_session_id = Some(view.session.session_id.clone());
    txn.return_target = code.return_target.clone();
    txn.bind_sha256 = Some(code.bind_sha256);
    txn.recovery_depth = code.recovery_depth;
    txn.pending_identity = None;
    txn.reauth_max_age = None;
    let since = Timestamp(b.clock.now().0 - 60_000);
    b.handoff
        .create_transaction_capped(txn, vec![], since, None, 10_000)
        .await
        .unwrap();
    d
}

fn passkey(user: &User, id: u8, now: Timestamp) -> PasskeyRecord {
    PasskeyRecord {
        credential_id: vec![id; 32],
        user_id: user.user_id.clone(),
        label: format!("Key {id}"),
        passkey: format!("{{\"cred\":{id}}}"),
        aaguid: Some([id; 16]),
        transports: vec!["internal".into()],
        backup_eligible: true,
        backup_state: true,
        user_verified: true,
        attestation_format: "none".into(),
        attested: false,
        assurance: Assurance::Aal2,
        sign_count: 0,
        created_at: now,
        last_used_at: None,
        revision: 1,
    }
}

fn passkey_use(id: u8, count: u32) -> PasskeyUse {
    PasskeyUse {
        credential_id: vec![id; 32],
        passkey: format!("{{\"cred\":{id},\"count\":{count}}}"),
        sign_count: count,
        backup_eligible: true,
        backup_state: true,
        assurance: Assurance::Aal2,
    }
}

async fn ceremony(
    b: &Backend,
    view: &HandleView,
    purpose: CeremonyPurpose,
    txn: Option<Digest>,
) -> StoreResult<Digest> {
    let digest = random_token(b.rng.as_ref(), 32).digest();
    b.passkeys
        .begin_ceremony(NewCeremony {
            actor: factor_actor(b, view),
            purpose,
            digest,
            portal_binding: Digest([9; 32]),
            transaction: txn,
            state: "{\"opaque\":true}".into(),
            expires_at: b.clock.now().add(Duration::from_secs(300)),
        })
        .await?;
    Ok(digest)
}

fn refused<T: std::fmt::Debug>(r: StoreResult<T>, what: &str) -> bool {
    matches!(r, Err(StoreError::Conflict(m)) if m == what)
}

async fn totp_lifecycle_and_stepup(b: &Backend) {
    let name = b.store.backend();
    b.store
        .ensure_provider(provider("mock", true))
        .await
        .unwrap();
    let u = user(b, 1).await;
    let (_, h) = session(b, &u).await;
    let view = view_of(b, &h).await;
    // A stale actor (factors changed since it was issued) is refused.
    let mut stale = view.clone();
    stale.session.cred_gen += 1;
    assert!(
        refused(
            b.factors
                .create_totp_pending_authorized(
                    "t-0".into(),
                    factor_actor(b, &stale),
                    envelope(b, &u, "t-0"),
                    vec![]
                )
                .await,
            "factor authorization revoked"
        ),
        "{name}"
    );
    b.factors
        .create_totp_pending_authorized(
            "t-1".into(),
            factor_actor(b, &view),
            envelope(b, &u, "t-1"),
            vec![],
        )
        .await
        .unwrap();
    // One pending enrollment per user.
    assert!(conflict(
        b.factors
            .create_totp_pending(
                "t-2".into(),
                u.user_id.clone(),
                envelope(b, &u, "t-2"),
                vec![]
            )
            .await
    ));
    let e = b
        .factors
        .totp_enrollment("t-1", &u.user_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (e.revision, e.active, e.last_counter),
        (1, false, None),
        "{name}"
    );
    assert!(!b.factors.has_active_totp(&u.user_id).await.unwrap());
    assert!(
        b.factors
            .activate_totp_authorized("t-1", factor_actor(b, &view), 1, 10, vec![])
            .await
            .unwrap(),
        "{name}"
    );
    assert!(b.factors.has_active_totp(&u.user_id).await.unwrap());
    // The counter only moves forward; a stale revision is no change.
    assert!(
        !b.factors
            .consume_totp_counter("t-1", &u.user_id, 2, 10, vec![])
            .await
            .unwrap()
    );
    assert!(
        !b.factors
            .consume_totp_counter("t-1", &u.user_id, 1, 11, vec![])
            .await
            .unwrap()
    );
    assert!(
        b.factors
            .consume_totp_counter("t-1", &u.user_id, 2, 11, vec![])
            .await
            .unwrap()
    );
    let mut racers = Vec::new();
    for _ in 0..8 {
        let f = b.factors.clone();
        let id = u.user_id.clone();
        racers.push(tokio::spawn(async move {
            f.consume_totp_counter("t-1", &id, 2, 20, vec![]).await
        }));
    }
    let mut won = 0;
    for t in racers {
        if t.await.unwrap().unwrap() {
            won += 1;
        }
    }
    assert_eq!(won, 1, "{name}: one code, one use");
    // Native step-up: bind, then elevate with a fresh counter.
    let generation = b.store.bump_config_generation().await.unwrap();
    assert_eq!(b.store.config_generation().await.unwrap(), generation);
    let (mut code, _) = code_row(b, &view.session, view.session.cred_gen + 1);
    code.issued_aal = Aal::Two;
    let txn = stepup_txn(b, &view, &code).await;
    let bind = BindTotpStepUp {
        actor: factor_actor(b, &view),
        transaction: txn,
        portal_binding: Digest([9; 32]),
        config_generation: Some(generation),
    };
    let binding = b.factors.bind_totp_stepup(bind).await.unwrap();
    assert_eq!(
        (binding.enrollment(), binding.revision()),
        ("t-1", 2),
        "{name}"
    );
    // Rebinding the same browser is idempotent; another binding is refused.
    let again = BindTotpStepUp {
        actor: factor_actor(b, &view),
        transaction: txn,
        portal_binding: Digest([9; 32]),
        config_generation: Some(generation),
    };
    b.factors.bind_totp_stepup(again).await.unwrap();
    let other = BindTotpStepUp {
        actor: factor_actor(b, &view),
        transaction: txn,
        portal_binding: Digest([10; 32]),
        config_generation: Some(generation),
    };
    assert!(refused(
        b.factors.bind_totp_stepup(other).await,
        "step-up challenge unavailable"
    ));
    let new_handle = elevated_handle(b, &view, Aal::Two);
    let elevate =
        |counter: u64, generation: u64, code: HandoffCodeRow, handle: HandleRow| TotpElevation {
            actor: factor_actor(b, &view),
            enrollment: "t-1".into(),
            revision: 2,
            counter,
            transaction: txn,
            portal_binding: Digest([9; 32]),
            config_generation: Some(generation),
            portal_handle: handle,
            handoff: code,
            events: vec![],
        };
    // A changed configuration generation, then a replayed counter, are refused.
    assert!(refused(
        b.factors
            .elevate_totp(elevate(
                30,
                generation + 1,
                code.clone(),
                new_handle.clone()
            ))
            .await,
        "step-up configuration changed"
    ));
    assert!(refused(
        b.factors
            .elevate_totp(elevate(20, generation, code.clone(), new_handle.clone()))
            .await,
        "factor proof unavailable"
    ));
    b.factors
        .elevate_totp(elevate(30, generation, code.clone(), new_handle.clone()))
        .await
        .unwrap();
    let elevated = view_of(b, &new_handle).await;
    assert_eq!(
        (
            elevated.session.aal,
            elevated.session.cred_gen,
            elevated.handle.issued_aal
        ),
        (Aal::Two, view.session.cred_gen + 1, Aal::Two),
        "{name}"
    );
    assert_eq!(
        elevated.session.factors.last().unwrap().kind,
        FactorKind::Totp
    );
    assert_eq!(
        elevated.session.auth_time, view.session.auth_time,
        "{name}: primary time kept"
    );
    assert!(
        b.store
            .lookup_handle(&h.handle_sha256, &Host::parse(PORTAL).unwrap())
            .await
            .unwrap()
            .is_none_or(|v| v.handle.revoked_at.is_some()),
        "{name}: old handle revoked"
    );
    // The challenge is single use.
    let mut code2 = code.clone();
    code2.code_sha256 = Digest([0x42; 32]);
    assert!(conflict(
        b.factors
            .elevate_totp(elevate(
                31,
                generation,
                code2,
                elevated_handle(b, &view, Aal::Two)
            ))
            .await
    ));
    // Revoking an active factor without a recent second factor is refused;
    // with one, it ends the user's sessions.
    let fresh = view_of(b, &new_handle).await;
    assert!(refused(
        b.factors
            .revoke_totp_authorized("t-1", factor_actor(b, &view), 2, vec![])
            .await,
        "factor authorization revoked"
    ));
    assert!(
        b.factors
            .revoke_totp_authorized("t-1", factor_actor(b, &fresh), 2, vec![])
            .await
            .unwrap(),
        "{name}"
    );
    let s = b
        .store
        .session(&fresh.session.session_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        s.terminated_reason.as_deref(),
        Some(reasons::FACTOR_REVOKED.0),
        "{name}"
    );
    assert!(!b.factors.has_active_totp(&u.user_id).await.unwrap());
}

async fn external_registry(b: &Backend) {
    let name = b.store.backend();
    let generation = b.store.bump_config_generation().await.unwrap();
    assert_eq!(
        b.factors.external_snapshot_revision().await.unwrap(),
        0,
        "{name}"
    );
    let authority =
        |factor: &str, revision: u64, binding: u8| crate::factor::external_transport::Authority {
            factor: factor.into(),
            revision,
            binding: [binding; 32],
        };
    let snapshot = |expected: u64, authorities| ExternalFactorSnapshot {
        authorities,
        config_generation: generation,
        expected_revision: expected,
    };
    assert_eq!(
        b.factors
            .publish_external_snapshot(snapshot(
                0,
                vec![authority("otp:a", 1, 1), authority("otp:b", 1, 2)]
            ))
            .await
            .unwrap(),
        1,
        "{name}"
    );
    // A stale expected revision, a duplicate id and a revision regression are refused.
    assert!(refused(
        b.factors
            .publish_external_snapshot(snapshot(0, vec![]))
            .await,
        "external factor snapshot revision changed"
    ));
    assert!(refused(
        b.factors
            .publish_external_snapshot(snapshot(
                1,
                vec![authority("otp:a", 1, 1), authority("otp:a", 1, 1)]
            ))
            .await,
        "duplicate external factor id"
    ));
    assert!(refused(
        b.factors
            .publish_external_snapshot(snapshot(1, vec![authority("otp:a", 1, 9)]))
            .await,
        "external factor revision changed"
    ));
    // Dropping `otp:b` leaves a disable tombstone; the revision moves once.
    assert_eq!(
        b.factors
            .publish_external_snapshot(snapshot(1, vec![authority("otp:a", 1, 1)]))
            .await
            .unwrap(),
        2
    );
    // Concurrent publishers on one expected revision: exactly one wins.
    let mut racers = Vec::new();
    for i in 0..4u8 {
        let f = b.factors.clone();
        racers.push(tokio::spawn(async move {
            f.publish_external_snapshot(ExternalFactorSnapshot {
                authorities: vec![crate::factor::external_transport::Authority {
                    factor: "otp:a".into(),
                    revision: 2 + u64::from(i),
                    binding: [i; 32],
                }],
                config_generation: generation,
                expected_revision: 2,
            })
            .await
        }));
    }
    let mut won = 0;
    for t in racers {
        if t.await.unwrap().is_ok() {
            won += 1;
        }
    }
    assert_eq!(won, 1, "{name}");
    assert_eq!(
        b.factors.external_snapshot_revision().await.unwrap(),
        3,
        "{name}"
    );
}

async fn passkeys_and_recovery(b: &Backend) {
    let name = b.store.backend();
    b.store
        .ensure_provider(provider("mock", true))
        .await
        .unwrap();
    let u = user(b, 1).await;
    let (_, h) = session(b, &u).await;
    let view = view_of(b, &h).await;
    let handle_a = b
        .passkeys
        .passkey_user_handle(&u.user_id, [1; 16])
        .await
        .unwrap();
    assert_eq!(handle_a, [1; 16]);
    assert_eq!(
        b.passkeys
            .passkey_user_handle(&u.user_id, [2; 16])
            .await
            .unwrap(),
        [1; 16],
        "{name}: stable"
    );
    // Register: ceremony consumed once; a second registration of the id is refused.
    let c = ceremony(b, &view, CeremonyPurpose::Register, None)
        .await
        .unwrap();
    let rec = b.passkeys.ceremony(&c).await.unwrap().unwrap();
    assert_eq!(
        (rec.purpose, rec.session_id.clone()),
        (CeremonyPurpose::Register, view.session.session_id.clone())
    );
    let register = |c: Digest, id: u8| RegisterPasskey {
        actor: factor_actor(b, &view),
        ceremony: c,
        portal_binding: Digest([9; 32]),
        record: passkey(&u, id, b.clock.now()),
        events: vec![],
    };
    b.passkeys.register_passkey(register(c, 1)).await.unwrap();
    assert!(refused(
        b.passkeys.register_passkey(register(c, 2)).await,
        refusal::CEREMONY_UNAVAILABLE
    ));
    // With a passkey present, adding another needs a recent second factor.
    let c2 = ceremony(b, &view, CeremonyPurpose::Register, None)
        .await
        .unwrap();
    assert!(
        refused(
            b.passkeys.register_passkey(register(c2, 2)).await,
            refusal::VERIFICATION_REQUIRED
        ),
        "{name}"
    );
    let summary = b.passkeys.factor_summary(&u.user_id).await.unwrap();
    assert_eq!(
        (
            summary.passkeys.len(),
            summary.totp_active,
            summary.recovery_unused
        ),
        (1, false, 0)
    );
    let (who, keys) = b.passkeys.passkey_account([1; 16]).await.unwrap().unwrap();
    assert_eq!((who, keys.len()), (u.user_id.clone(), 1), "{name}");
    // Portal verification with the passkey raises the session and rotates.
    let c3 = ceremony(b, &view, CeremonyPurpose::Verify, None)
        .await
        .unwrap();
    let verified = elevated_handle(b, &view, Aal::Two);
    b.passkeys
        .elevate_portal(PortalElevation {
            actor: factor_actor(b, &view),
            portal_binding: Digest([9; 32]),
            proof: PortalProof::Passkey {
                ceremony: c3,
                used: passkey_use(1, 5),
            },
            portal_handle: verified.clone(),
            events: vec![],
        })
        .await
        .unwrap();
    let v2 = view_of(b, &verified).await;
    assert_eq!(
        (v2.session.aal, v2.session.cred_gen),
        (Aal::Two, view.session.cred_gen + 1),
        "{name}"
    );
    // A counter that did not move is stale (out-of-order tabs).
    let c4 = ceremony(b, &v2, CeremonyPurpose::Verify, None)
        .await
        .unwrap();
    assert!(refused(
        b.passkeys
            .elevate_portal(PortalElevation {
                actor: factor_actor(b, &v2),
                portal_binding: Digest([9; 32]),
                proof: PortalProof::Passkey {
                    ceremony: c4,
                    used: passkey_use(1, 5)
                },
                portal_handle: elevated_handle(b, &v2, Aal::Two),
                events: vec![],
            })
            .await,
        refusal::COUNTER_STALE
    ));
    // The only second factor cannot be removed; renaming works.
    assert!(refused(
        b.passkeys
            .revoke_passkey(factor_actor(b, &v2), &[1; 32], vec![])
            .await,
        refusal::LAST_FACTOR
    ));
    assert!(
        b.passkeys
            .rename_passkey(factor_actor(b, &v2), &[1; 32], "Laptop".into(), vec![])
            .await
            .unwrap()
    );
    assert!(
        !b.passkeys
            .rename_passkey(factor_actor(b, &v2), &[7; 32], "Nope".into(), vec![])
            .await
            .unwrap()
    );
    // Application step-up with the passkey: ceremony, transaction and
    // counter are consumed together and the session rotates again.
    let generation = b.store.bump_config_generation().await.unwrap();
    let (mut code, _) = code_row(b, &v2.session, v2.session.cred_gen + 1);
    code.issued_aal = Aal::Two;
    let txn = stepup_txn(b, &v2, &code).await;
    let c6 = ceremony(b, &v2, CeremonyPurpose::StepUp, Some(txn))
        .await
        .unwrap();
    let stepped = elevated_handle(b, &v2, Aal::Two);
    let webauthn = |c: Digest, code: HandoffCodeRow, h: HandleRow, count: u32| WebauthnElevation {
        actor: factor_actor(b, &v2),
        ceremony: c,
        portal_binding: Digest([9; 32]),
        transaction: txn,
        config_generation: generation,
        used: passkey_use(1, count),
        portal_handle: h,
        handoff: code,
        events: vec![],
    };
    b.passkeys
        .elevate_webauthn(webauthn(c6, code.clone(), stepped.clone(), 6))
        .await
        .unwrap();
    let mut replay = code.clone();
    replay.code_sha256 = Digest([0x43; 32]);
    assert!(
        conflict(
            b.passkeys
                .elevate_webauthn(webauthn(c6, replay, elevated_handle(b, &v2, Aal::Two), 7))
                .await
        ),
        "{name}: step-up replay"
    );
    let v2 = view_of(b, &stepped).await;
    assert_eq!(
        v2.session.factors.last().unwrap().kind,
        FactorKind::Webauthn
    );
    // Recovery codes: minted after a possession factor, each used once.
    let codes: Vec<(String, String)> = (0..10)
        .map(|i| (format!("L{i:04}"), format!("$argon2id$h{i}")))
        .collect();
    b.passkeys
        .replace_recovery_codes(
            factor_actor(b, &v2),
            "batch-1".into(),
            codes.clone(),
            vec![],
        )
        .await
        .unwrap();
    assert_eq!(
        b.passkeys
            .recovery_code_hash(&u.user_id, "L0003")
            .await
            .unwrap()
            .as_deref(),
        Some("$argon2id$h3")
    );
    let recovered = elevated_handle(b, &v2, Aal::Two);
    b.passkeys
        .elevate_portal(PortalElevation {
            actor: factor_actor(b, &v2),
            portal_binding: Digest([9; 32]),
            proof: PortalProof::Recovery {
                lookup: "L0003".into(),
            },
            portal_handle: recovered.clone(),
            events: vec![],
        })
        .await
        .unwrap();
    let v3 = view_of(b, &recovered).await;
    assert!(
        b.passkeys
            .recovery_code_hash(&u.user_id, "L0003")
            .await
            .unwrap()
            .is_none(),
        "{name}"
    );
    let summary = b.passkeys.factor_summary(&u.user_id).await.unwrap();
    assert_eq!(summary.recovery_unused, 9, "{name}");
    assert!(summary.recovery_required_at.is_some(), "{name}");
    assert!(refused(
        b.passkeys
            .elevate_portal(PortalElevation {
                actor: factor_actor(b, &v3),
                portal_binding: Digest([9; 32]),
                proof: PortalProof::Recovery {
                    lookup: "L0003".into()
                },
                portal_handle: elevated_handle(b, &v3, Aal::Two),
                events: vec![],
            })
            .await,
        "recovery code unavailable"
    ));
    // A clone signal revokes the credential and ends the sessions it elevated.
    let c5 = ceremony(b, &v3, CeremonyPurpose::Verify, None)
        .await
        .unwrap();
    b.passkeys
        .passkey_clone_detected(&c5, &[1; 32], vec![])
        .await
        .unwrap();
    let ended = b
        .store
        .session(&v3.session.session_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        ended.terminated_reason.as_deref(),
        Some(reasons::COUNTER_REGRESSION.0),
        "{name}"
    );
    assert!(
        b.passkeys
            .factor_summary(&u.user_id)
            .await
            .unwrap()
            .passkeys
            .is_empty()
    );
    // The administrator reset clears what is left and ends every session.
    let (_, h2) = session(b, &u).await;
    let report = b
        .passkeys
        .reset_factors(&u.user_id, "r_reset", vec![])
        .await
        .unwrap();
    assert_eq!(
        (
            report.passkeys,
            report.totp,
            report.recovery_codes,
            report.sessions
        ),
        (0, 0, 9, 1),
        "{name}"
    );
    assert!(
        b.store
            .lookup_handle(&h2.handle_sha256, &Host::parse(PORTAL).unwrap())
            .await
            .unwrap()
            .is_none_or(|v| v.session.terminated_at.is_some())
    );
    assert!(refused(
        b.passkeys
            .reset_factors(&crate::identity::types::UserId::new("u_GHOST"), "r", vec![])
            .await,
        "user unavailable"
    ));
}

async fn passwordless_sign_in(b: &Backend) {
    let name = b.store.backend();
    b.store
        .ensure_provider(provider("mock", true))
        .await
        .unwrap();
    let u = user(b, 1).await;
    let (_, h) = session(b, &u).await;
    let view = view_of(b, &h).await;
    b.passkeys
        .passkey_user_handle(&u.user_id, [3; 16])
        .await
        .unwrap();
    let c = ceremony(b, &view, CeremonyPurpose::Register, None)
        .await
        .unwrap();
    b.passkeys
        .register_passkey(RegisterPasskey {
            actor: factor_actor(b, &view),
            ceremony: c,
            portal_binding: Digest([9; 32]),
            record: passkey(&u, 4, b.clock.now()),
            events: vec![],
        })
        .await
        .unwrap();
    let (mut txn, d) = new_txn(b, "198.51.100.7");
    txn.reauth_max_age = None;
    let since = Timestamp(b.clock.now().0 - 60_000);
    b.handoff
        .create_transaction_capped(txn, vec![], since, None, 10_000)
        .await
        .unwrap();
    let begin = |digest: Digest| NewLoginCeremony {
        digest,
        transaction: d,
        portal_binding: Digest([11; 32]),
        client_ip: "198.51.100.7".parse().unwrap(),
        state: "{}".into(),
        expires_at: b.clock.now().add(Duration::from_secs(300)),
    };
    let first = Digest([0x51; 32]);
    b.passkeys.begin_login_ceremony(begin(first)).await.unwrap();
    let rec = b.passkeys.login_ceremony(&first).await.unwrap().unwrap();
    assert_eq!(
        (rec.transaction, rec.portal_bind_sha256),
        (d, Digest([11; 32])),
        "{name}"
    );
    b.passkeys
        .fail_login_ceremony(&first, vec![])
        .await
        .unwrap();
    assert!(
        b.passkeys.login_ceremony(&first).await.unwrap().is_none(),
        "{name}"
    );
    // Per-address rate: thirty a minute (spent rows do not count), then busy.
    for i in 0..LOGIN_CEREMONIES_PER_MINUTE {
        b.passkeys
            .begin_login_ceremony(begin(Digest([i as u8; 32])))
            .await
            .unwrap();
    }
    assert!(
        refused(
            b.passkeys
                .begin_login_ceremony(begin(Digest([0xEE; 32])))
                .await,
            refusal::LOGIN_BUSY
        ),
        "{name}"
    );
    // A verified sign-in consumes the ceremony and the transaction once.
    let now = b.clock.now();
    let mut s = session_row(b, &u);
    s.provider_id = ProviderId::new(crate::provider::types::PASSKEY_PROVIDER);
    s.aal = Aal::Two;
    s.cred_gen = 1;
    s.factors = vec![FactorEntry {
        kind: FactorKind::Webauthn,
        provider: None,
        at: now,
    }];
    let mut ph = handle(b, &s.session_id);
    ph.issued_aal = Aal::Two;
    let login = |s: SessionRow, ph: HandleRow| PasskeyLogin {
        ceremony: Digest([0; 32]),
        transaction: d,
        portal_binding: Digest([11; 32]),
        client_ip: "198.51.100.7".parse().unwrap(),
        used: passkey_use(4, 1),
        session: s,
        portal_handle: ph,
        events: vec![],
    };
    b.passkeys
        .create_passkey_session(login(s.clone(), ph.clone()))
        .await
        .unwrap();
    let made = b.store.session(&s.session_id).await.unwrap().unwrap();
    assert_eq!(
        (made.aal, made.provider_id.as_str()),
        (Aal::Two, crate::provider::types::PASSKEY_PROVIDER),
        "{name}"
    );
    let mut s2 = s.clone();
    s2.session_id = SessionId::new(random_id(b.rng.as_ref(), "s_"));
    let mut ph2 = handle(b, &s2.session_id);
    ph2.issued_aal = Aal::Two;
    assert!(
        refused(
            b.passkeys.create_passkey_session(login(s2, ph2)).await,
            refusal::CEREMONY_UNAVAILABLE
        ),
        "{name}"
    );
    // Turning passwordless sign-in off ends those sessions only.
    assert_eq!(
        b.passkeys.end_passkey_sessions("r_off").await.unwrap(),
        1,
        "{name}"
    );
    assert!(
        b.store
            .session(&view.session.session_id)
            .await
            .unwrap()
            .unwrap()
            .terminated_at
            .is_none()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s600_12_totp_lifecycle_and_native_stepup_agree_on_both_backends() {
    for b in backends().await {
        totp_lifecycle_and_stepup(&b).await;
        b.cleanup().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s600_13_external_factor_registry_agrees_on_both_backends() {
    for b in backends().await {
        external_registry(&b).await;
        b.cleanup().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s600_14_passkeys_and_recovery_codes_agree_on_both_backends() {
    for b in backends().await {
        passkeys_and_recovery(&b).await;
        b.cleanup().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s600_15_passwordless_sign_in_agrees_on_both_backends() {
    for b in backends().await {
        passwordless_sign_in(&b).await;
        b.cleanup().await;
    }
}

async fn external_stepup(b: &Backend) {
    let name = b.store.backend();
    b.store
        .ensure_provider(provider("mock", true))
        .await
        .unwrap();
    let u = user(b, 1).await;
    let (_, h) = session(b, &u).await;
    let view = view_of(b, &h).await;
    let generation = b.store.bump_config_generation().await.unwrap();
    let authority = |revision: u64, binding: u8| crate::factor::external_transport::Authority {
        factor: "otp:a".into(),
        revision,
        binding: [binding; 32],
    };
    b.factors
        .publish_external_snapshot(ExternalFactorSnapshot {
            authorities: vec![authority(1, 1)],
            config_generation: generation,
            expected_revision: 0,
        })
        .await
        .unwrap();
    let (mut code, _) = code_row(b, &view.session, view.session.cred_gen + 1);
    code.issued_aal = Aal::Two;
    let txn = stepup_txn(b, &view, &code).await;
    let bind = |a| BindExternalStepUp {
        actor: factor_actor(b, &view),
        transaction: txn,
        portal_binding: Digest([9; 32]),
        authority: a,
        config_generation: generation,
    };
    // An authority that is not the published one is refused.
    assert!(refused(
        b.factors.bind_external_stepup(bind(authority(1, 2))).await,
        "external factor disabled or changed"
    ));
    b.factors
        .bind_external_stepup(bind(authority(1, 1)))
        .await
        .unwrap();
    let now = b.clock.now();
    let proof = |digest: u8| crate::factor::external_transport::VerifiedProof {
        authority: authority(1, 1),
        challenge: txn.to_hex(),
        user: u.user_id.as_str().into(),
        session: view.session.session_id.as_str().into(),
        service: "app".into(),
        credential_generation: view.session.cred_gen,
        proof: Digest([digest; 32]),
        verified_at: now,
        expires_at: now.add(Duration::from_secs(5)),
        deadline: std::time::Instant::now() + Duration::from_secs(5),
    };
    let new_handle = elevated_handle(b, &view, Aal::Two);
    let elevation = |p, code: HandoffCodeRow, handle: HandleRow| ExternalElevation {
        actor: factor_actor(b, &view),
        proof: p,
        transaction: txn,
        portal_binding: Digest([9; 32]),
        config_generation: generation,
        portal_handle: handle,
        handoff: code,
        events: vec![],
    };
    // A proof for another session is refused before anything is consumed.
    let mut foreign = proof(0x71);
    foreign.session = "s_OTHER".into();
    assert!(refused(
        b.factors
            .elevate_external(elevation(foreign, code.clone(), new_handle.clone()))
            .await,
        "external proof context unavailable"
    ));
    b.factors
        .elevate_external(elevation(proof(0x72), code.clone(), new_handle.clone()))
        .await
        .unwrap();
    let elevated = view_of(b, &new_handle).await;
    assert_eq!(elevated.session.aal, Aal::Two, "{name}");
    assert_eq!(
        elevated.session.factors.last().unwrap().kind,
        FactorKind::External
    );
    let mut again = code.clone();
    again.code_sha256 = Digest([0x44; 32]);
    assert!(conflict(
        b.factors
            .elevate_external(elevation(
                proof(0x72),
                again,
                elevated_handle(b, &view, Aal::Two)
            ))
            .await
    ));
    // Rotating the authority's binding ends the sessions it elevated.
    b.factors
        .publish_external_snapshot(ExternalFactorSnapshot {
            authorities: vec![authority(2, 3)],
            config_generation: generation,
            expected_revision: 1,
        })
        .await
        .unwrap();
    let s = b
        .store
        .session(&view.session.session_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        s.terminated_reason.as_deref(),
        Some(reasons::FACTOR_REVOKED.0),
        "{name}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s600_16_external_factor_stepup_agrees_on_both_backends() {
    for b in backends().await {
        external_stepup(&b).await;
        b.cleanup().await;
    }
}

// ---- slice 3a: the event relay and console listings -----------------------

fn required(b: &Backend, user: Option<&User>) -> Event {
    let mut e = EventBuilder::new(
        b.clock.as_ref(),
        b.rng.as_ref(),
        EventKind::LoginFailed,
        Outcome::Failure,
        "req-relay",
    )
    .build();
    e.user_id = user.map(|u| u.user_id.clone());
    e
}

async fn event_relay(b: &Backend) {
    let name = b.store.backend();
    let ids: Vec<EventId> = {
        let evs: Vec<Event> = (0..6).map(|_| required(b, None)).collect();
        let ids = evs.iter().map(|e| e.event_id.clone()).collect();
        b.events.append_required(evs).await.unwrap();
        ids
    };
    // A diagnostic kind cannot be appended as required, nor a required one as diagnostic.
    assert!(conflict(
        b.events.append_diagnostic(required(b, None)).await
    ));
    let diag = EventBuilder::new(
        b.clock.as_ref(),
        b.rng.as_ref(),
        EventKind::ProviderError,
        Outcome::Failure,
        "req-diag",
    )
    .build();
    b.events.append_diagnostic(diag).await.unwrap();
    // An expired deadline writes nothing.
    let gone = Deadline(std::time::Instant::now() - Duration::from_millis(1));
    assert!(
        matches!(
            b.events.append_required_within(vec![required(b, None)], gone).await,
            Err(StoreError::Unavailable(ref m)) if m == "deadline"
        ),
        "{name}"
    );
    let (events, deliveries) = b.events.count_rows().await.unwrap();
    assert_eq!(
        (events, deliveries),
        (7, 6),
        "{name}: diagnostics have no delivery rows"
    );
    // Two relays claim concurrently: every delivery is handed out once.
    let now = b.clock.now();
    let (x, y) = (b.events.clone(), b.events.clone());
    let (cx, cy) = tokio::join!(
        async move { x.claim_deliveries("log", 4, now).await.unwrap() },
        async move { y.claim_deliveries("log", 4, now).await.unwrap() }
    );
    let mut seen: Vec<String> = cx
        .iter()
        .chain(cy.iter())
        .map(|d| d.event.event_id.to_string())
        .collect();
    seen.sort();
    let before = seen.len();
    seen.dedup();
    assert_eq!((before, seen.len()), (6, 6), "{name}: no double claim");
    assert!(cx.iter().chain(cy.iter()).all(|d| d.attempts == 1));
    // Claimed rows are leased: nothing is due until the lease ends.
    assert!(
        b.events
            .claim_deliveries("log", 10, now)
            .await
            .unwrap()
            .is_empty(),
        "{name}"
    );
    b.events.mark_delivered("log", &ids[0], now).await.unwrap();
    b.events
        .mark_failed("log", &ids[1], "http_503 remote said things", Some(now))
        .await
        .unwrap();
    b.events
        .mark_failed("log", &ids[2], "rejected", None)
        .await
        .unwrap();
    let again = b.events.claim_deliveries("log", 10, now).await.unwrap();
    assert_eq!(again.len(), 1, "{name}: the retried one only");
    assert_eq!(
        (again[0].event.event_id.clone(), again[0].attempts),
        (ids[1].clone(), 2)
    );
    let lease_over = now.add(Duration::from_secs(61));
    assert_eq!(
        b.events
            .claim_deliveries("log", 10, lease_over)
            .await
            .unwrap()
            .len(),
        4,
        "{name}: expired leases return"
    );
    // History query and status.
    let found = b
        .events
        .query(EventQuery {
            kind: Some(EventKind::LoginFailed),
            session_id: None,
            user_id: None,
            client_ip: None,
            since: None,
            limit: Some(3),
        })
        .await
        .unwrap();
    assert_eq!(found.len(), 3, "{name}");
    assert_eq!(found[0].event_id, ids[0], "{name}: oldest first");
    let st = b.events.status(deadline()).await.unwrap();
    assert_eq!((st.events, st.deliveries.len()), (7, 1), "{name}");
    assert_eq!(st.deliveries[0], ("log".to_string(), 4, 1), "{name}");
    assert!(st.schema_version > 0);
    // Prune: the count bound takes the oldest; the backlog cap dead-letters.
    let policy = EventRetention {
        retention: Duration::from_secs(86_400),
        max_rows: 5,
        prune_every: 1,
        max_pending_per_sink: 2,
        terminal_retention: Duration::from_secs(86_400),
    };
    let report = b.events.prune(now, &policy).await.unwrap();
    assert_eq!(report.events_deleted, 2, "{name}");
    assert!(report.backlog_overflowed >= 1, "{name}");
    let st = b.events.status(deadline()).await.unwrap();
    assert_eq!(
        st.last_prune_at.map(|t| t.secs()),
        Some(now.secs()),
        "{name}"
    );
    let overflow = b
        .events
        .query(EventQuery {
            kind: Some(EventKind::SinkBacklogOverflow),
            session_id: None,
            user_id: None,
            client_ip: None,
            since: None,
            limit: None,
        })
        .await
        .unwrap();
    assert_eq!(overflow.len(), 1, "{name}");
    // Age: everything older than the retention goes.
    b.clock.advance(Duration::from_secs(2 * 86_400));
    let report = b.events.prune(b.clock.now(), &policy).await.unwrap();
    assert!(report.events_deleted >= 5, "{name}");
    assert_eq!(b.events.count_rows().await.unwrap().0, 0, "{name}");
}

async fn console_listings(b: &Backend) {
    let name = b.store.backend();
    b.store
        .ensure_provider(provider("mock", true))
        .await
        .unwrap();
    let mut users = Vec::new();
    for n in 1..=5 {
        users.push(user(b, n).await);
        b.clock.advance(Duration::from_secs(1));
    }
    let q = |q: Option<&str>, limit, cursor| UsersQuery {
        q: q.map(Into::into),
        status: None,
        limit,
        cursor,
    };
    // Newest first, two per page, then a cursor page.
    let p1 = b
        .console
        .list_users(q(None, 2, None), deadline())
        .await
        .unwrap();
    let names: Vec<_> = p1
        .items
        .iter()
        .map(|u| u.user.username.clone().unwrap())
        .collect();
    assert_eq!(names, ["user5", "user4"], "{name}");
    assert_eq!(p1.examined, 5);
    let p2 = b
        .console
        .list_users(q(None, 2, p1.next.clone()), deadline())
        .await
        .unwrap();
    let names: Vec<_> = p2
        .items
        .iter()
        .map(|u| u.user.username.clone().unwrap())
        .collect();
    assert_eq!(names, ["user3", "user2"], "{name}");
    let p3 = b
        .console
        .list_users(q(None, 2, p2.next.clone()), deadline())
        .await
        .unwrap();
    assert_eq!((p3.items.len(), p3.next.is_none()), (1, true), "{name}");
    // Prefix search ignores ASCII case, as SQLite's LIKE does.
    let found = b
        .console
        .list_users(q(Some("USER3"), 10, None), deadline())
        .await
        .unwrap();
    assert_eq!(found.items.len(), 1, "{name}");
    assert_eq!(found.items[0].user.user_id, users[2].user_id);
    // Sessions: live only, per user or all, with hosts and the owner's address.
    let (s1, _) = session(b, &users[0]).await;
    b.clock.advance(Duration::from_secs(1));
    let (s2, _) = session(b, &users[0]).await;
    b.clock.advance(Duration::from_secs(1));
    let (s3, _) = session(b, &users[1]).await;
    b.store
        .terminate_session(&s2.session_id, reasons::LOGOUT, b.clock.now(), vec![])
        .await
        .unwrap();
    let sq = |user: Option<&User>| SessionsQuery {
        user_id: user.map(|u| u.user_id.clone()),
        limit: 10,
        cursor: None,
        now: b.clock.now(),
    };
    let all = b
        .console
        .list_live_sessions(sq(None), deadline())
        .await
        .unwrap();
    let ids: Vec<_> = all
        .items
        .iter()
        .map(|s| s.session.session_id.clone())
        .collect();
    assert_eq!(
        ids,
        [s3.session_id.clone(), s1.session_id.clone()],
        "{name}"
    );
    assert_eq!(all.items[0].hosts, [Host::parse(PORTAL).unwrap()], "{name}");
    assert_eq!(all.items[1].primary_email, users[0].primary_email);
    let mine = b
        .console
        .list_live_sessions(sq(Some(&users[0])), deadline())
        .await
        .unwrap();
    assert_eq!(mine.items.len(), 1, "{name}");
    let summary = b.users_live(&users[0]).await;
    assert_eq!(summary, 1, "{name}");
    let detail = b
        .console
        .user_detail(&users[0].user_id, b.clock.now(), deadline())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (
            detail.identities.len(),
            detail.sessions_live.len(),
            detail.sessions_live_total,
            detail.sessions_terminated.len()
        ),
        (1, 1, 1, 1),
        "{name}"
    );
    assert!(detail.grant.is_none());
    let (one, handles) = b
        .console
        .session_summary(&s2.session_id, deadline())
        .await
        .unwrap()
        .unwrap();
    assert!(one.session.terminated_at.is_some());
    assert_eq!(handles.len(), 1, "{name}");
    assert!(
        b.console
            .session_summary(&SessionId::new("s_NONE"), deadline())
            .await
            .unwrap()
            .is_none()
    );
    // Events listing: filters by user and kind, newest first, with a cursor.
    for _ in 0..3 {
        b.events
            .append_required(vec![required(b, Some(&users[0]))])
            .await
            .unwrap();
        b.clock.advance(Duration::from_millis(10));
    }
    let eq = |cursor| EventsQuery {
        kind: Some(EventKind::LoginFailed),
        user_id: Some(users[0].user_id.clone()),
        limit: 2,
        cursor,
        ..Default::default()
    };
    let e1 = b.events.query_page(eq(None), deadline()).await.unwrap();
    assert_eq!(e1.items.len(), 2, "{name}");
    assert!(e1.items[0].at > e1.items[1].at, "{name}: newest first");
    let e2 = b
        .events
        .query_page(eq(e1.next.clone()), deadline())
        .await
        .unwrap();
    assert_eq!(e2.items.len(), 1, "{name}");
    assert!(e2.next.is_none(), "{name}");
    // An expired deadline answers `deadline`, never a partial page.
    let gone = Deadline(std::time::Instant::now() - Duration::from_millis(1));
    assert!(
        matches!(b.console.list_users(q(None, 2, None), gone).await, Err(StoreError::Unavailable(ref m)) if m == "deadline"),
        "{name}"
    );
}

impl Backend {
    async fn users_live(&self, u: &User) -> u32 {
        let page = self
            .console
            .list_users(
                UsersQuery {
                    q: u.username.clone(),
                    status: None,
                    limit: 10,
                    cursor: None,
                },
                deadline(),
            )
            .await
            .unwrap();
        page.items
            .iter()
            .find(|s| s.user.user_id == u.user_id)
            .unwrap()
            .live_sessions
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s600_17_event_relay_agrees_on_both_backends() {
    for b in backends().await {
        event_relay(&b).await;
        b.cleanup().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s600_18_console_listings_agree_on_both_backends() {
    for b in backends().await {
        console_listings(&b).await;
        b.cleanup().await;
    }
}
