//! Dual-backend conformance suite for the slice-1 store contract
//! ([`super::core::CoreStore`], ADR-0020, scenario 600). Every case runs
//! against SQLite always and against PostgreSQL when the crate is built with
//! the `postgres` feature and `HOPAE_TEST_POSTGRES_URL` names a server; each
//! PostgreSQL run uses a fresh schema that is dropped afterwards.
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use super::core::CoreStore;
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
    Backend {
        store: Arc::new(store),
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
