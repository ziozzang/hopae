//! PostgreSQL backend, slice 1 (ADR-0020): `CoreStore` over a
//! `deadpool-postgres` pool. Writes run in `READ COMMITTED` transactions
//! that lock the rows their invariants depend on (`FOR UPDATE` / `FOR
//! SHARE`), consume-once updates are single conditional statements, and
//! uniqueness (user-ID ledger, identities, handles, events) is enforced by
//! constraints, so several replicas behave like the single SQLite writer.
//! Times come from the application clock, never from `now()`.
mod admin;
mod attempts;
mod directory;
mod events;
mod factors;
mod groups;
mod handoff;
pub(crate) mod human;
pub mod import;
pub mod meta;
mod owners;
mod passkeys;
mod risk;
mod service_credentials;
pub mod sslmode;
mod traits;
mod workloads;
mod write;

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use deadpool_postgres::{Manager, ManagerConfig, Pool, RecyclingMethod, Transaction};
use tokio_postgres::{IsolationLevel, Row};

use crate::crypto::{Clock, Digest, Rng, Timestamp, random_id};
use crate::event::types::{Event, EventId, EventKind, Outcome, Reason, reasons};
use crate::identity::types::{NormalizedEmail, UserId};
use crate::policy::types::{AppId, Host};
use crate::provider::types::ProviderId;
use crate::session::types::{Aal, FactorEntry, SessionId};
use crate::store::core::CoreStore;
use crate::store::types::*;
use crate::store::{StoreError, StoreResult};

/// Embedded PostgreSQL migrations (independent numbering from SQLite).
const MIGRATIONS: &[(i32, &str, &str)] = &[
    (1, "0001_slice1", include_str!("migrations/0001_slice1.sql")),
    (
        2,
        "0002_slice2_handoff",
        include_str!("migrations/0002_slice2_handoff.sql"),
    ),
    (
        3,
        "0003_slice2b_admin_nonces",
        include_str!("migrations/0003_slice2b_admin_nonces.sql"),
    ),
    (
        4,
        "0004_slice2c_factors",
        include_str!("migrations/0004_slice2c_factors.sql"),
    ),
    (
        5,
        "0005_slice3_groups_feeds",
        include_str!("migrations/0005_slice3_groups_feeds.sql"),
    ),
    (
        6,
        "0006_slice4_owners",
        include_str!("migrations/0006_slice4_owners.sql"),
    ),
    (
        7,
        "0007_slice4_apps",
        include_str!("migrations/0007_slice4_apps.sql"),
    ),
    (
        8,
        "0008_identity_platform",
        include_str!("migrations/0008_identity_platform.sql"),
    ),
    (
        9,
        "0009_slice5_meta",
        include_str!("migrations/0009_slice5_meta.sql"),
    ),
    (
        10,
        "0010_slice5_material_upsert",
        include_str!("migrations/0010_slice5_material_upsert.sql"),
    ),
    (
        11,
        "0011_slice5_lock_namespace",
        include_str!("migrations/0011_slice5_lock_namespace.sql"),
    ),
    (
        12,
        "0012_attempt_windows",
        include_str!("migrations/0012_attempt_windows.sql"),
    ),
    (
        13,
        "0013_risk_memory",
        include_str!("migrations/0013_risk_memory.sql"),
    ),
];
pub const LATEST_SCHEMA_VERSION: i32 = MIGRATIONS[MIGRATIONS.len() - 1].0;
/// Take the transaction-scoped advisory lock `$1` (an `i64` key below 2^31)
/// in this store's namespace: its schema. Stores in different schemas of
/// one database never contend, and the two-key space never meets other
/// applications' single-key locks. Only the migration runner's lock spans
/// the database.
pub(crate) const ADVISORY_XACT_LOCK: &str =
    "SELECT pg_advisory_xact_lock(hashtext(current_schema()), ($1::bigint)::int4)";
/// Advisory lock key serializing login-transaction admission (count, evict, insert).
pub(crate) const LOGIN_TXN_LOCK: i64 = 7008;
/// `pg_advisory_xact_lock` key of the migration runner ("hopae-mi").
const MIGRATION_LOCK: i64 = 0x686f_7061_652d_6d69;
const RAW_CLAIMS_MAX: usize = 8192;
/// Retries of a write that hit a serialization failure or deadlock.
const RETRIES: usize = 2;

/// Connection settings (secrets resolved by the caller).
#[derive(Clone)]
pub struct PgOptions {
    /// libpq-style URL or key/value string.
    pub url: String,
    /// PEM roots for TLS (`verify-full`); `None` = plain TCP, loopback or
    /// Unix socket only.
    pub ca_pem: Option<Vec<u8>>,
    pub pool_size: usize,
    pub connect_timeout: Duration,
    pub statement_timeout: Duration,
    /// Tests: a private schema to run in (created when absent).
    pub search_path: Option<String>,
}

impl std::fmt::Debug for PgOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgOptions")
            .field("pool_size", &self.pool_size)
            .field("search_path", &self.search_path)
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
pub struct PgStore {
    pool: Pool,
    clock: Arc<dyn Clock>,
    rng: Arc<dyn Rng>,
    sinks: Arc<Vec<String>>,
    statement_timeout_ms: u64,
    /// Bounds the diagnostic writes in flight (SQLite's queue capacity).
    diag: Arc<tokio::sync::Semaphore>,
    /// The runtime the pool's connections live on (blocking owner calls use it).
    handle: tokio::runtime::Handle,
    /// How to open the dedicated `LISTEN` connection (outside the pool).
    listen: Listen,
    /// Whether that connection is listening now (metrics).
    listening: Arc<std::sync::atomic::AtomicBool>,
}

/// The connection settings of the publication listener.
#[derive(Clone)]
enum Listen {
    Plain(tokio_postgres::Config),
    Tls(
        tokio_postgres::Config,
        tokio_postgres_rustls::MakeRustlsConnect,
    ),
}

/// Map a driver error to the store's error classes; never echo values.
fn pg(e: tokio_postgres::Error) -> StoreError {
    if let Some(db) = e.as_db_error() {
        let code = db.code().code();
        return match code {
            "23505" | "23503" | "23514" | "23502" | "P0001" => {
                crate::telemetry::metrics::STORE_FAILURES.inc(["conflict"]);
                StoreError::Conflict("constraint violated")
            }
            "40001" | "40P01" | "55P03" => {
                crate::telemetry::metrics::STORE_FAILURES.inc(["busy"]);
                StoreError::Busy
            }
            _ => {
                crate::telemetry::metrics::STORE_FAILURES.inc(["other"]);
                StoreError::Unavailable(format!("postgres sqlstate {code}"))
            }
        };
    }
    crate::telemetry::metrics::STORE_FAILURES.inc(["other"]);
    if e.is_closed() {
        StoreError::Unavailable("postgres connection closed".into())
    } else {
        StoreError::Unavailable("postgres error".into())
    }
}

fn pool_err<E: std::fmt::Display>(_: E) -> StoreError {
    StoreError::Unavailable("postgres pool unavailable".into())
}

fn corrupt(col: &str) -> StoreError {
    StoreError::Corrupt(format!("column {col}"))
}

fn loopback_only(cfg: &tokio_postgres::Config) -> bool {
    cfg.get_hosts().iter().all(|h| match h {
        tokio_postgres::config::Host::Tcp(name) => {
            name == "localhost"
                || name
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
        }
        #[cfg(unix)]
        tokio_postgres::config::Host::Unix(_) => true,
    })
}

impl PgStore {
    /// Connect, verify the server is writable, and migrate under an advisory
    /// lock. A database newer than this binary is refused.
    pub async fn connect(
        options: PgOptions,
        clock: Arc<dyn Clock>,
        rng: Arc<dyn Rng>,
        sinks: Vec<String>,
    ) -> StoreResult<Self> {
        // libpq's `sslmode`, decided here (the driver lacks `verify-*`).
        let (url, transport) = sslmode::apply(&options.url, options.ca_pem.is_some())
            .map_err(StoreError::Unavailable)?;
        let mut cfg: tokio_postgres::Config = url
            .parse()
            .map_err(|_| StoreError::Unavailable("invalid postgres connection string".into()))?;
        debug_assert_eq!(
            transport == sslmode::Transport::VerifyFull,
            options.ca_pem.is_some()
        );
        cfg.connect_timeout(options.connect_timeout);
        cfg.application_name("hopae");
        if let Some(schema) = &options.search_path {
            if !schema
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
            {
                return Err(StoreError::Unavailable("invalid search path".into()));
            }
            cfg.options(format!("-c search_path={schema}"));
        }
        let manager_config = ManagerConfig {
            recycling_method: RecyclingMethod::Verified,
        };
        let mut listen_cfg = cfg.clone();
        listen_cfg.application_name("hopae-listen");
        let listen;
        let manager = match &options.ca_pem {
            Some(pem) => {
                let mut roots = rustls::RootCertStore::empty();
                for cert in rustls_pemfile::certs(&mut pem.as_slice()) {
                    roots
                        .add(cert.map_err(|_| StoreError::Unavailable("invalid CA".into()))?)
                        .map_err(|_| StoreError::Unavailable("invalid CA".into()))?;
                }
                let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
                    rustls::crypto::ring::default_provider(),
                ))
                .with_safe_default_protocol_versions()
                .map_err(|_| StoreError::Unavailable("TLS configuration".into()))?
                .with_root_certificates(roots)
                .with_no_client_auth();
                cfg.ssl_mode(tokio_postgres::config::SslMode::Require);
                listen_cfg.ssl_mode(tokio_postgres::config::SslMode::Require);
                let connector = tokio_postgres_rustls::MakeRustlsConnect::new(tls);
                listen = Listen::Tls(listen_cfg, connector.clone());
                Manager::from_config(cfg, connector, manager_config)
            }
            None => {
                if !loopback_only(&cfg) {
                    return Err(StoreError::Unavailable(
                        "postgres without TLS is allowed only on loopback or a Unix socket".into(),
                    ));
                }
                listen = Listen::Plain(listen_cfg);
                Manager::from_config(cfg, tokio_postgres::NoTls, manager_config)
            }
        };
        let pool = Pool::builder(manager)
            .max_size(options.pool_size.clamp(1, 128))
            .wait_timeout(Some(options.connect_timeout))
            .create_timeout(Some(options.connect_timeout))
            .runtime(deadpool_postgres::Runtime::Tokio1)
            .build()
            .map_err(pool_err)?;
        let store = Self {
            pool,
            clock,
            rng,
            sinks: Arc::new(sinks),
            statement_timeout_ms: options.statement_timeout.as_millis().clamp(1, 600_000) as u64,
            diag: Arc::new(tokio::sync::Semaphore::new(
                crate::store::sqlite::DIAGNOSTIC_QUEUE_CAP,
            )),
            handle: tokio::runtime::Handle::current(),
            listen,
            listening: Arc::default(),
        };
        if let Some(schema) = &options.search_path {
            let client = store.pool.get().await.map_err(pool_err)?;
            client
                .batch_execute(&format!("CREATE SCHEMA IF NOT EXISTS {schema}"))
                .await
                .map_err(pg)?;
        }
        store.migrate().await?;
        Ok(store)
    }

    /// Set the store's Human realm (its public identity namespace) when it
    /// has none: 32 bytes from the store's RNG, once, immutable afterwards.
    /// A store migrated from SQLite keeps the SQLite realm.
    pub async fn ensure_realm(&self) -> StoreResult<String> {
        let mut bytes = [0u8; 32];
        self.rng.fill(&mut bytes);
        let candidate = data_encoding::HEXLOWER.encode(&bytes);
        let client = self.client().await?;
        client
            .execute(
                "INSERT INTO human_authority_realm (singleton, realm) VALUES (1, $1) ON CONFLICT (singleton) DO NOTHING",
                &[&candidate],
            )
            .await
            .map_err(pg)?;
        Ok(client
            .query_one(
                "SELECT realm FROM human_authority_realm WHERE singleton = 1",
                &[],
            )
            .await
            .map_err(pg)?
            .get(0))
    }

    /// Apply missing migrations in one transaction under an advisory lock.
    pub async fn migrate(&self) -> StoreResult<i32> {
        let mut client = self.pool.get().await.map_err(pool_err)?;
        let tx = client.transaction().await.map_err(pg)?;
        tx.execute("SELECT pg_advisory_xact_lock($1)", &[&MIGRATION_LOCK])
            .await
            .map_err(pg)?;
        tx.batch_execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at BIGINT NOT NULL)",
        )
        .await
        .map_err(pg)?;
        let current: i32 = tx
            .query_one(
                "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
                &[],
            )
            .await
            .map_err(pg)?
            .get(0);
        if current > LATEST_SCHEMA_VERSION {
            return Err(StoreError::SchemaTooNew {
                found: current as u32,
                supported: LATEST_SCHEMA_VERSION as u32,
            });
        }
        let now = self.clock.now().secs();
        for (version, name, sql) in MIGRATIONS {
            if *version <= current {
                continue;
            }
            tx.batch_execute(sql).await.map_err(pg)?;
            tx.execute(
                "INSERT INTO schema_migrations (version, name, applied_at) VALUES ($1, $2, $3)",
                &[version, name, &now],
            )
            .await
            .map_err(pg)?;
        }
        tx.commit().await.map_err(pg)?;
        Ok(LATEST_SCHEMA_VERSION)
    }

    /// One write transaction with the statement timeout and the primary check.
    async fn begin<'a>(
        &self,
        client: &'a mut deadpool_postgres::Object,
    ) -> StoreResult<Transaction<'a>> {
        let tx = client
            .build_transaction()
            .isolation_level(IsolationLevel::ReadCommitted)
            .start()
            .await
            .map_err(pg)?;
        tx.batch_execute(&format!(
            "SET LOCAL statement_timeout = {}",
            self.statement_timeout_ms
        ))
        .await
        .map_err(pg)?;
        let ro: String = tx
            .query_one("SELECT current_setting('transaction_read_only')", &[])
            .await
            .map_err(pg)?
            .get(0);
        if ro != "off" {
            // A standby after failover: refuse writes, never queue them.
            return Err(StoreError::Unavailable(
                "postgres server is read-only".into(),
            ));
        }
        Ok(tx)
    }

    /// One read-only snapshot (`REPEATABLE READ`) with the statement timeout.
    pub(super) async fn begin_snapshot<'a>(
        &self,
        client: &'a mut deadpool_postgres::Object,
    ) -> StoreResult<Transaction<'a>> {
        let tx = client
            .build_transaction()
            .isolation_level(IsolationLevel::RepeatableRead)
            .read_only(true)
            .start()
            .await
            .map_err(pg)?;
        tx.batch_execute(&format!(
            "SET LOCAL statement_timeout = {}",
            self.statement_timeout_ms
        ))
        .await
        .map_err(pg)?;
        Ok(tx)
    }

    pub(crate) async fn client(&self) -> StoreResult<deadpool_postgres::Object> {
        self.pool.get().await.map_err(pool_err)
    }

    fn now(&self) -> Timestamp {
        self.clock.now()
    }

    async fn insert_events(&self, tx: &Transaction<'_>, events: &[Event]) -> StoreResult<()> {
        let now = self.now().secs();
        for ev in events {
            let attrs = serde_json::to_string(&serde_json::Value::Object(ev.attrs.clone()))
                .map_err(|_| corrupt("events.attrs"))?;
            tx.execute(
                "INSERT INTO events (event_id, at, kind, outcome, reason, user_id, session_id, app_id, provider_id, client_ip, ua_sha256, ua_prefix, request_id, attrs) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,CAST($14::text AS jsonb))",
                &[
                    &ev.event_id.as_str(),
                    &(ev.at.0 as f64 / 1000.0),
                    &ev.kind.name(),
                    &ev.outcome.as_str(),
                    &ev.reason.map(|r| r.0),
                    &ev.user_id.as_ref().map(|v| v.as_str()),
                    &ev.session_id.as_ref().map(|v| v.as_str()),
                    &ev.app_id.as_ref().map(|v| v.as_str()),
                    &ev.provider_id.as_ref().map(|v| v.as_str()),
                    &ev.client_ip.map(|v| v.to_string()),
                    &ev.ua_sha256.as_ref().map(|d| d.0.to_vec()),
                    &ev.ua_prefix.as_deref(),
                    &ev.request_id.as_str(),
                    &attrs,
                ],
            )
            .await
            .map_err(pg)?;
            // As SQLite: counted when the row is written in its transaction.
            crate::telemetry::metrics::event(ev);
            if events::in_feed(ev.kind) {
                // Feed positions in commit order: only these writes take the lock.
                tx.execute(ADVISORY_XACT_LOCK, &[&events::FEED_LOCK])
                    .await
                    .map_err(pg)?;
                tx.execute(
                    "INSERT INTO outbox_feed (event_id) VALUES ($1)",
                    &[&ev.event_id.as_str()],
                )
                .await
                .map_err(pg)?;
            }
            if ev.kind.is_required() {
                for sink in self.sinks.iter() {
                    tx.execute(
                        "INSERT INTO event_deliveries (sink, event_id, state, attempts, next_attempt_at, updated_at) VALUES ($1, $2, 'pending', 0, $3, $3)",
                        &[sink, &ev.event_id.as_str(), &now],
                    )
                    .await
                    .map_err(pg)?;
                }
            }
        }
        Ok(())
    }
}

/// Retry a write on serialization failure or deadlock (`Busy`).
async fn retry<T, F, Fut>(mut f: F) -> StoreResult<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = StoreResult<T>>,
{
    let mut attempt = 0;
    loop {
        match f().await {
            Err(StoreError::Busy) if attempt < RETRIES => {
                attempt += 1;
                tokio::time::sleep(Duration::from_millis(5 * attempt as u64)).await;
            }
            other => return other,
        }
    }
}

// ---- row decoding ------------------------------------------------------

const USER_COLS: &str = "user_id, primary_email, email_verified, email_authoritative, display_name, username, status, authz_version, groups, created_at, updated_at, last_login_at";
const IDENTITY_COLS: &str = "provider_id, subject, user_id, email, email_verified, email_authoritative, name, picture, first_seen_at, last_seen_at";
const SESSION_COLS: &str = "s.session_id, s.user_id, s.provider_id, s.auth_time, s.factors, s.aal, s.authz_version, s.cred_gen, s.snapshot, s.bound_ip, s.bound_ua_sha256, s.created_at, s.last_seen_at, s.absolute_expires_at, s.terminated_at, s.terminated_reason, s.authz_version_at_auth, s.auth_time_source, s.bound_ua_prefix";
const HANDLE_COLS: &str = "h.handle_sha256, h.session_id, h.host, h.issued_aal, h.created_at, h.last_seen_at, h.absolute_expires_at, h.revoked_at, h.revoked_reason";
const EVENT_COLS: &str = "event_id, at, kind, outcome, reason, user_id, session_id, app_id, provider_id, client_ip, ua_sha256, ua_prefix, request_id, attrs::text";

fn email(r: &Row, i: usize, col: &str) -> StoreResult<Option<NormalizedEmail>> {
    match r.get::<_, Option<String>>(i) {
        None => Ok(None),
        Some(s) => NormalizedEmail::from_stored(&s)
            .map(Some)
            .ok_or_else(|| corrupt(col)),
    }
}
fn u64_of(r: &Row, i: usize, col: &str) -> StoreResult<u64> {
    u64::try_from(r.get::<_, i64>(i)).map_err(|_| corrupt(col))
}
fn digest(b: Vec<u8>, col: &str) -> StoreResult<Digest> {
    Digest::from_slice(&b).ok_or_else(|| corrupt(col))
}
fn opt_ts(r: &Row, i: usize) -> Option<Timestamp> {
    r.get::<_, Option<i64>>(i).map(Timestamp::from_secs)
}
fn json<T: serde::de::DeserializeOwned>(r: &Row, i: usize, col: &str) -> StoreResult<T> {
    serde_json::from_str(&r.get::<_, String>(i)).map_err(|_| corrupt(col))
}
fn aal(r: &Row, i: usize, col: &str) -> StoreResult<Aal> {
    Aal::from_i64(i64::from(r.get::<_, i32>(i))).ok_or_else(|| corrupt(col))
}

fn user(r: &Row, o: usize) -> StoreResult<User> {
    Ok(User {
        user_id: UserId::new(r.get::<_, String>(o)),
        primary_email: email(r, o + 1, "users.primary_email")?,
        email_verified: r.get(o + 2),
        email_authoritative: r.get(o + 3),
        display_name: r.get(o + 4),
        username: r.get(o + 5),
        status: UserStatus::parse(&r.get::<_, String>(o + 6))
            .ok_or_else(|| corrupt("users.status"))?,
        authz_version: u64_of(r, o + 7, "users.authz_version")?,
        groups: json(r, o + 8, "users.groups")?,
        created_at: Timestamp::from_secs(r.get(o + 9)),
        updated_at: Timestamp::from_secs(r.get(o + 10)),
        last_login_at: opt_ts(r, o + 11),
    })
}
fn user_authz(r: &Row, o: usize) -> StoreResult<UserAuthz> {
    Ok(UserAuthz {
        status: UserStatus::parse(&r.get::<_, String>(o)).ok_or_else(|| corrupt("users.status"))?,
        authz_version: u64_of(r, o + 1, "users.authz_version")?,
        groups: json(r, o + 2, "users.groups")?,
    })
}
fn identity(r: &Row) -> StoreResult<IdentityRow> {
    Ok(IdentityRow {
        provider_id: ProviderId::new(r.get::<_, String>(0)),
        subject: r.get(1),
        user_id: UserId::new(r.get::<_, String>(2)),
        email: email(r, 3, "identities.email")?,
        email_verified: r.get(4),
        email_authoritative: r.get(5),
        name: r.get(6),
        picture: r.get(7),
        first_seen_at: Timestamp::from_secs(r.get(8)),
        last_seen_at: Timestamp::from_secs(r.get(9)),
    })
}
fn session(r: &Row, o: usize) -> StoreResult<SessionRow> {
    let snap: serde_json::Value = json(r, o + 8, "sessions.snapshot")?;
    let snapshot = IdentitySnapshot {
        email: match snap.get("email") {
            Some(serde_json::Value::String(s)) => {
                Some(NormalizedEmail::from_stored(s).ok_or_else(|| corrupt("sessions.snapshot"))?)
            }
            _ => None,
        },
        display_name: snap
            .get("display_name")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        username: snap
            .get("username")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        groups: snap
            .get("groups")
            .map(|g| serde_json::from_value(g.clone()))
            .transpose()
            .map_err(|_| corrupt("sessions.snapshot"))?
            .unwrap_or_default(),
    };
    Ok(SessionRow {
        session_id: SessionId::new(r.get::<_, String>(o)),
        user_id: UserId::new(r.get::<_, String>(o + 1)),
        provider_id: ProviderId::new(r.get::<_, String>(o + 2)),
        auth_time: Timestamp::from_secs(r.get(o + 3)),
        factors: json::<Vec<FactorEntry>>(r, o + 4, "sessions.factors")?,
        aal: aal(r, o + 5, "sessions.aal")?,
        authz_version: u64_of(r, o + 6, "sessions.authz_version")?,
        cred_gen: u64_of(r, o + 7, "sessions.cred_gen")?,
        snapshot,
        bound_ip: r
            .get::<_, String>(o + 9)
            .parse()
            .map_err(|_| corrupt("sessions.bound_ip"))?,
        bound_ua_sha256: r
            .get::<_, Option<Vec<u8>>>(o + 10)
            .map(|b| digest(b, "sessions.bound_ua_sha256"))
            .transpose()?,
        created_at: Timestamp::from_secs(r.get(o + 11)),
        last_seen_at: Timestamp::from_secs(r.get(o + 12)),
        absolute_expires_at: Timestamp::from_secs(r.get(o + 13)),
        terminated_at: opt_ts(r, o + 14),
        terminated_reason: r.get(o + 15),
        authz_version_at_auth: u64_of(r, o + 16, "sessions.authz_version_at_auth")?,
        auth_time_source: AuthTimeSource::parse(&r.get::<_, String>(o + 17))
            .ok_or_else(|| corrupt("sessions.auth_time_source"))?,
        bound_ua_prefix: r.get(o + 18),
    })
}
fn handle(r: &Row, o: usize) -> StoreResult<HandleRow> {
    Ok(HandleRow {
        handle_sha256: digest(r.get(o), "session_handles.handle_sha256")?,
        session_id: SessionId::new(r.get::<_, String>(o + 1)),
        host: Host::parse(&r.get::<_, String>(o + 2))
            .map_err(|_| corrupt("session_handles.host"))?,
        issued_aal: aal(r, o + 3, "session_handles.issued_aal")?,
        created_at: Timestamp::from_secs(r.get(o + 4)),
        last_seen_at: Timestamp::from_secs(r.get(o + 5)),
        absolute_expires_at: Timestamp::from_secs(r.get(o + 6)),
        revoked_at: opt_ts(r, o + 7),
        revoked_reason: r.get(o + 8),
    })
}
fn event(r: &Row) -> StoreResult<Event> {
    let at: f64 = r.get(1);
    let attrs: String = r.get(13);
    Ok(Event {
        event_id: EventId::new(r.get::<_, String>(0)),
        at: Timestamp((at * 1000.0).round() as i64),
        kind: EventKind::from_name(&r.get::<_, String>(2)).ok_or_else(|| corrupt("events.kind"))?,
        outcome: Outcome::parse(&r.get::<_, String>(3)).ok_or_else(|| corrupt("events.outcome"))?,
        reason: r
            .get::<_, Option<String>>(4)
            .and_then(|s| reasons::parse(&s)),
        user_id: r.get::<_, Option<String>>(5).map(UserId::new),
        session_id: r.get::<_, Option<String>>(6).map(SessionId::new),
        app_id: r.get::<_, Option<String>>(7).map(AppId::new),
        provider_id: r.get::<_, Option<String>>(8).map(ProviderId::new),
        client_ip: r
            .get::<_, Option<String>>(9)
            .map(|s| s.parse().map_err(|_| corrupt("events.client_ip")))
            .transpose()?,
        ua_sha256: r
            .get::<_, Option<Vec<u8>>>(10)
            .map(|b| digest(b, "events.ua_sha256"))
            .transpose()?,
        ua_prefix: r.get(11),
        request_id: r.get(12),
        attrs: serde_json::from_str(&attrs).map_err(|_| corrupt("events.attrs"))?,
    })
}

fn snapshot_json(s: &IdentitySnapshot) -> String {
    serde_json::json!({
        "email": s.email.as_ref().map(|e| e.as_str()),
        "display_name": s.display_name,
        "username": s.username,
        "groups": s.groups,
    })
    .to_string()
}

fn bounded_claims(v: &serde_json::Value) -> String {
    match serde_json::to_string(v) {
        Ok(s) if s.len() <= RAW_CLAIMS_MAX => s,
        _ => r#"{"truncated":true}"#.to_string(),
    }
}

fn i64_of(n: u64) -> i64 {
    i64::try_from(n).unwrap_or(i64::MAX)
}

/// The provider must not be disabled or deleted (absent is allowed, as in
/// SQLite); `FOR SHARE` holds it against a concurrent disable.
async fn require_provider_live(tx: &Transaction<'_>, id: &str) -> StoreResult<()> {
    let dead = tx
        .query_opt(
            "SELECT 1 FROM providers WHERE provider_id=$1 AND (NOT enabled OR deleted_at IS NOT NULL) FOR SHARE",
            &[&id],
        )
        .await
        .map_err(pg)?;
    if dead.is_some() {
        return Err(StoreError::ProviderDisabled);
    }
    Ok(())
}

async fn insert_identity(
    tx: &Transaction<'_>,
    user: &UserId,
    i: &NewIdentity,
    now: Timestamp,
) -> StoreResult<()> {
    let exists = tx
        .query_opt(
            "SELECT 1 FROM identities WHERE provider_id=$1 AND subject=$2",
            &[&i.provider_id.as_str(), &i.subject],
        )
        .await
        .map_err(pg)?;
    if exists.is_some() {
        return Err(StoreError::Conflict("identity already exists"));
    }
    tx.execute(
        "INSERT INTO identities (provider_id, subject, user_id, email, email_verified, email_authoritative, name, picture, raw_claims, first_seen_at, last_seen_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$10)",
        &[
            &i.provider_id.as_str(),
            &i.subject,
            &user.as_str(),
            &i.email.as_ref().map(|e| e.as_str()),
            &i.email_verified,
            &i.email_authoritative,
            &i.name,
            &i.picture,
            &bounded_claims(&i.raw_claims),
            &now.secs(),
        ],
    )
    .await
    .map_err(pg)?;
    Ok(())
}

impl PgStore {
    async fn try_create_user(
        &self,
        user: &NewUser,
        identity: &NewIdentity,
        events: &[Event],
    ) -> StoreResult<User> {
        let mut client = self.client().await?;
        let tx = self.begin(&mut client).await?;
        let now = Timestamp::from_secs(self.now().secs());
        let id = UserId::new(random_id(self.rng.as_ref(), "u_"));
        if let Some(name) = &user.username
            && tx
                .query_opt("SELECT 1 FROM users WHERE username=$1", &[name])
                .await
                .map_err(pg)?
                .is_some()
        {
            return Err(StoreError::Conflict("username already taken"));
        }
        require_provider_live(&tx, identity.provider_id.as_str()).await?;
        if tx
            .query_opt(
                "SELECT 1 FROM identities WHERE provider_id=$1 AND subject=$2",
                &[&identity.provider_id.as_str(), &identity.subject],
            )
            .await
            .map_err(pg)?
            .is_some()
        {
            return Err(StoreError::Conflict("identity already exists"));
        }
        tx.execute(
            "INSERT INTO users (user_id, primary_email, email_verified, email_authoritative, display_name, username, status, authz_version, groups, created_at, updated_at) VALUES ($1,$2,$3,$4,$5,$6,'active',1,'[]',$7,$7)",
            &[
                &id.as_str(),
                &user.primary_email.as_ref().map(|e| e.as_str()),
                &user.email_verified,
                &user.email_authoritative,
                &user.display_name,
                &user.username,
                &now.secs(),
            ],
        )
        .await
        .map_err(pg)?;
        insert_identity(&tx, &id, identity, now).await?;
        self.insert_events(&tx, events).await?;
        tx.commit().await.map_err(pg)?;
        Ok(User {
            user_id: id,
            primary_email: user.primary_email.clone(),
            email_verified: user.email_verified,
            email_authoritative: user.email_authoritative,
            display_name: user.display_name.clone(),
            username: user.username.clone(),
            status: UserStatus::Active,
            authz_version: 1,
            groups: Vec::new(),
            created_at: now,
            updated_at: now,
            last_login_at: None,
        })
    }

    /// A login session whose native primary authentication is recorded in
    /// the same transaction (ADR-0020 slice 5).
    pub(crate) async fn create_session_primary(
        &self,
        req: CreateSession,
        primary: crate::session::service::VerifiedPrimary,
    ) -> StoreResult<()> {
        retry(|| self.try_create_session(&req, Some(&primary))).await
    }

    async fn try_create_session(
        &self,
        req: &CreateSession,
        primary: Option<&crate::session::service::VerifiedPrimary>,
    ) -> StoreResult<()> {
        if req.portal_handle.handle_sha256 != req.portal_handle_digest {
            return Err(StoreError::Conflict("portal handle digest mismatch"));
        }
        if req.portal_handle.session_id != req.session.session_id {
            return Err(StoreError::Conflict("portal handle names another session"));
        }
        let s = &req.session;
        let mut client = self.client().await?;
        let tx = self.begin(&mut client).await?;
        require_provider_live(&tx, s.provider_id.as_str()).await?;
        if let Some((kind, config)) = &req.provider_configuration {
            let row = tx
                .query_opt(
                    "SELECT kind, config FROM providers WHERE provider_id=$1 AND enabled AND deleted_at IS NULL FOR SHARE",
                    &[&s.provider_id.as_str()],
                )
                .await
                .map_err(pg)?;
            let matches = row.is_some_and(|r| {
                r.get::<_, String>(0) == kind.as_str()
                    && serde_json::from_str::<serde_json::Value>(&r.get::<_, String>(1))
                        .is_ok_and(|c| c == *config)
            });
            if !matches {
                return Err(StoreError::ProviderDisabled);
            }
        }
        write::insert_session(&tx, s).await?;
        write::insert_handle(&tx, &req.portal_handle).await?;
        if let Some(primary) = primary {
            primary.write_postgres(self, &tx, s, 0).await?;
        }
        tx.execute(
            "UPDATE users SET last_login_at=$2 WHERE user_id=$1",
            &[&s.user_id.as_str(), &s.created_at.secs()],
        )
        .await
        .map_err(pg)?;
        if let Some((txn, why)) = &req.consume_txn {
            let n = tx
                .execute(
                    "UPDATE login_txns SET consumed_at=$2, consumed_reason=$3 WHERE txn_sha256=$1 AND consumed_at IS NULL",
                    &[&txn.0.to_vec(), &s.created_at.secs(), &why.0],
                )
                .await
                .map_err(pg)?;
            if n != 1 {
                return Err(StoreError::Conflict("transaction already consumed"));
            }
        }
        self.insert_events(&tx, &req.events).await?;
        if let Some(primary) = primary {
            primary.publication()?;
        }
        tx.commit().await.map_err(pg)
    }

    async fn try_revoke_handle(
        &self,
        d: &Digest,
        reason: Reason,
        at: Timestamp,
        events: &[Event],
    ) -> StoreResult<()> {
        let mut client = self.client().await?;
        let tx = self.begin(&mut client).await?;
        // Lock the handle: a concurrent revocation waits and then sees it revoked.
        let row = tx
            .query_opt(
                "SELECT session_id, revoked_at FROM session_handles WHERE handle_sha256=$1 FOR UPDATE",
                &[&d.0.to_vec()],
            )
            .await
            .map_err(pg)?;
        let Some(row) = row else {
            return Err(StoreError::Conflict("unknown handle"));
        };
        if row.get::<_, Option<i64>>(1).is_some() {
            return Ok(());
        }
        let sid: String = row.get(0);
        tx.execute(
            "UPDATE session_handles SET revoked_at=$2, revoked_reason=$3 WHERE handle_sha256=$1",
            &[&d.0.to_vec(), &at.secs(), &reason.0],
        )
        .await
        .map_err(pg)?;
        tx.execute(
            "UPDATE sessions SET cred_gen = cred_gen + 1 WHERE session_id=$1",
            &[&sid],
        )
        .await
        .map_err(pg)?;
        tx.execute(
            "UPDATE handoff_codes SET consumed_at=$2, consumed_reason=$3 WHERE session_id=$1 AND consumed_at IS NULL",
            &[&sid, &at.secs(), &reason.0],
        )
        .await
        .map_err(pg)?;
        self.insert_events(&tx, events).await?;
        tx.commit().await.map_err(pg)
    }

    async fn try_terminate(
        &self,
        id: &SessionId,
        reason: Reason,
        at: Timestamp,
        events: &[Event],
    ) -> StoreResult<()> {
        let mut client = self.client().await?;
        let tx = self.begin(&mut client).await?;
        if admin::terminate_in(self, &tx, id, reason, at, events).await? {
            tx.commit().await.map_err(pg)?;
        }
        Ok(())
    }
}

#[async_trait]
impl CoreStore for PgStore {
    fn backend(&self) -> &'static str {
        "postgres"
    }

    async fn ensure_provider(&self, r: ProviderRow) -> StoreResult<()> {
        retry(|| async {
            let mut client = self.client().await?;
            let tx = self.begin(&mut client).await?;
            let now = self.now().secs();
            let config = serde_json::to_string(&r.config).map_err(|_| corrupt("providers.config"))?;
            let allowed = serde_json::to_string(&r.allowed_email_domains)
                .map_err(|_| corrupt("providers.allowed_email_domains"))?;
            let authoritative = serde_json::to_string(&r.authoritative_domains)
                .map_err(|_| corrupt("providers.authoritative_domains"))?;
            let current = tx
                .query_opt(
                    "SELECT managed_by, deleted_at FROM providers WHERE provider_id=$1 FOR UPDATE",
                    &[&r.provider_id.as_str()],
                )
                .await
                .map_err(pg)?;
            match current {
                None => {
                    tx.execute(
                        "INSERT INTO providers (provider_id, kind, display_name, enabled, managed_by, deleted_at, sort_order, config, client_secret_env, allowed_email_domains, authoritative_domains, auto_link, trust_email, created_at, updated_at) VALUES ($1,$2,$3,$4,'file',NULL,$5,$6,$7,$8,$9,$10,$11,$12,$12) ON CONFLICT (provider_id) DO NOTHING",
                        &[
                            &r.provider_id.as_str(), &r.kind.as_str(), &r.display_name, &r.enabled,
                            &r.sort_order, &config, &r.client_secret_env, &allowed, &authoritative,
                            &r.auto_link, &r.trust_email, &now,
                        ],
                    )
                    .await
                    .map_err(pg)?;
                }
                Some(row)
                    if row.get::<_, String>(0) == "file" && row.get::<_, Option<i64>>(1).is_none() =>
                {
                    tx.execute(
                        "UPDATE providers SET kind=$2, display_name=$3, enabled=$4, sort_order=$5, config=$6, client_secret_env=$7, allowed_email_domains=$8, authoritative_domains=$9, auto_link=$10, trust_email=$11, updated_at=$12 WHERE provider_id=$1",
                        &[
                            &r.provider_id.as_str(), &r.kind.as_str(), &r.display_name, &r.enabled,
                            &r.sort_order, &config, &r.client_secret_env, &allowed, &authoritative,
                            &r.auto_link, &r.trust_email, &now,
                        ],
                    )
                    .await
                    .map_err(pg)?;
                }
                Some(_) => {}
            }
            tx.commit().await.map_err(pg)
        })
        .await
    }

    async fn user(&self, id: &UserId) -> StoreResult<Option<User>> {
        let client = self.client().await?;
        client
            .query_opt(
                &format!("SELECT {USER_COLS} FROM users WHERE user_id=$1"),
                &[&id.as_str()],
            )
            .await
            .map_err(pg)?
            .map(|r| user(&r, 0))
            .transpose()
    }

    async fn user_authz(&self, id: &UserId) -> StoreResult<Option<UserAuthz>> {
        let client = self.client().await?;
        client
            .query_opt(
                "SELECT status, authz_version, groups FROM users WHERE user_id=$1",
                &[&id.as_str()],
            )
            .await
            .map_err(pg)?
            .map(|r| user_authz(&r, 0))
            .transpose()
    }

    async fn user_by_email(&self, email: &NormalizedEmail) -> StoreResult<Option<User>> {
        let client = self.client().await?;
        client
            .query_opt(
                &format!("SELECT {USER_COLS} FROM users WHERE primary_email=$1 ORDER BY created_at, user_id LIMIT 1"),
                &[&email.as_str()],
            )
            .await
            .map_err(pg)?
            .map(|r| user(&r, 0))
            .transpose()
    }

    async fn identity(
        &self,
        provider: &ProviderId,
        subject: &str,
    ) -> StoreResult<Option<IdentityRow>> {
        let client = self.client().await?;
        client
            .query_opt(
                &format!(
                    "SELECT {IDENTITY_COLS} FROM identities WHERE provider_id=$1 AND subject=$2"
                ),
                &[&provider.as_str(), &subject],
            )
            .await
            .map_err(pg)?
            .map(|r| identity(&r))
            .transpose()
    }

    async fn create_user(
        &self,
        user: NewUser,
        identity: NewIdentity,
        events: Vec<Event>,
    ) -> StoreResult<User> {
        retry(|| self.try_create_user(&user, &identity, &events)).await
    }

    async fn link_identity(
        &self,
        user: &UserId,
        identity: NewIdentity,
        events: Vec<Event>,
    ) -> StoreResult<()> {
        retry(|| async {
            let mut client = self.client().await?;
            let tx = self.begin(&mut client).await?;
            let now = self.now();
            if tx
                .query_opt(
                    "SELECT 1 FROM users WHERE user_id=$1 FOR SHARE",
                    &[&user.as_str()],
                )
                .await
                .map_err(pg)?
                .is_none()
            {
                return Err(StoreError::Conflict("unknown user"));
            }
            require_provider_live(&tx, identity.provider_id.as_str()).await?;
            insert_identity(&tx, user, &identity, now).await?;
            self.insert_events(&tx, &events).await?;
            tx.commit().await.map_err(pg)
        })
        .await
    }

    async fn touch_identity(
        &self,
        provider: &ProviderId,
        subject: &str,
        seen: &NewIdentity,
        at: Timestamp,
    ) -> StoreResult<()> {
        let client = self.client().await?;
        let n = client
            .execute(
                "UPDATE identities SET email=$3, email_verified=$4, email_authoritative=$5, name=$6, picture=$7, last_seen_at=$8 WHERE provider_id=$1 AND subject=$2",
                &[
                    &provider.as_str(),
                    &subject,
                    &seen.email.as_ref().map(|e| e.as_str()),
                    &seen.email_verified,
                    &seen.email_authoritative,
                    &seen.name,
                    &seen.picture,
                    &at.secs(),
                ],
            )
            .await
            .map_err(pg)?;
        if n == 0 {
            return Err(StoreError::Conflict("unknown identity"));
        }
        Ok(())
    }

    async fn create_session(&self, req: CreateSession) -> StoreResult<()> {
        retry(|| self.try_create_session(&req, None)).await
    }

    async fn session(&self, id: &SessionId) -> StoreResult<Option<SessionRow>> {
        let client = self.client().await?;
        client
            .query_opt(
                &format!("SELECT {SESSION_COLS} FROM sessions s WHERE s.session_id=$1"),
                &[&id.as_str()],
            )
            .await
            .map_err(pg)?
            .map(|r| session(&r, 0))
            .transpose()
    }

    async fn lookup_handle(
        &self,
        handle_sha256: &Digest,
        host: &Host,
    ) -> StoreResult<Option<HandleView>> {
        let client = self.client().await?;
        let sql = format!(
            "SELECT {HANDLE_COLS}, {SESSION_COLS}, u.status, u.authz_version, u.groups FROM session_handles h JOIN sessions s ON s.session_id = h.session_id JOIN users u ON u.user_id = s.user_id WHERE h.handle_sha256=$1 AND h.host=$2"
        );
        client
            .query_opt(&sql, &[&handle_sha256.0.to_vec(), &host.as_str()])
            .await
            .map_err(pg)?
            .map(|r| {
                Ok(HandleView {
                    handle: handle(&r, 0)?,
                    session: session(&r, 9)?,
                    user: user_authz(&r, 28)?,
                })
            })
            .transpose()
    }

    async fn touch_handle(&self, handle_sha256: &Digest, at: Timestamp) -> StoreResult<()> {
        let d = handle_sha256.0.to_vec();
        retry(|| async {
            let mut client = self.client().await?;
            let tx = self.begin(&mut client).await?;
            tx.execute(
                "UPDATE session_handles SET last_seen_at = GREATEST(last_seen_at, $2) WHERE handle_sha256=$1 AND revoked_at IS NULL",
                &[&d, &at.secs()],
            )
            .await
            .map_err(pg)?;
            tx.execute(
                "UPDATE sessions SET last_seen_at = GREATEST(last_seen_at, $2) WHERE terminated_at IS NULL AND session_id = (SELECT session_id FROM session_handles WHERE handle_sha256=$1)",
                &[&d, &at.secs()],
            )
            .await
            .map_err(pg)?;
            tx.commit().await.map_err(pg)
        })
        .await
    }

    async fn revoke_handle(
        &self,
        handle_sha256: &Digest,
        reason: Reason,
        at: Timestamp,
        events: Vec<Event>,
    ) -> StoreResult<()> {
        retry(|| self.try_revoke_handle(handle_sha256, reason, at, &events)).await
    }

    async fn terminate_session(
        &self,
        id: &SessionId,
        reason: Reason,
        at: Timestamp,
        events: Vec<Event>,
    ) -> StoreResult<()> {
        retry(|| self.try_terminate(id, reason, at, &events)).await
    }

    async fn append_required(&self, events: Vec<Event>) -> StoreResult<()> {
        if events.is_empty() {
            return Ok(());
        }
        for ev in &events {
            if !ev.kind.is_required() {
                return Err(StoreError::Conflict(
                    "diagnostic kinds use append_diagnostic",
                ));
            }
            if crate::store::sqlite::events::travels_with_state(ev.kind) {
                return Err(StoreError::Conflict(
                    "this kind must travel with its state change",
                ));
            }
        }
        retry(|| async {
            let mut client = self.client().await?;
            let tx = self.begin(&mut client).await?;
            self.insert_events(&tx, &events).await?;
            tx.commit().await.map_err(pg)
        })
        .await
    }

    async fn recent_events(&self, limit: usize) -> StoreResult<Vec<Event>> {
        let client = self.client().await?;
        let limit = i64::try_from(limit.min(1000)).unwrap_or(1000);
        let rows = client
            .query(
                &format!(
                    "SELECT {EVENT_COLS} FROM events ORDER BY at DESC, event_id DESC LIMIT $1"
                ),
                &[&limit],
            )
            .await
            .map_err(pg)?;
        let mut out = rows.iter().map(event).collect::<StoreResult<Vec<_>>>()?;
        out.reverse();
        Ok(out)
    }

    async fn pending_deliveries(&self, event: &str) -> StoreResult<Vec<String>> {
        let client = self.client().await?;
        Ok(client
            .query(
                "SELECT sink FROM event_deliveries WHERE event_id=$1 AND state='pending' ORDER BY sink",
                &[&event],
            )
            .await
            .map_err(pg)?
            .iter()
            .map(|r| r.get(0))
            .collect())
    }
    async fn config_generation(&self) -> StoreResult<u64> {
        let client = self.client().await?;
        let v = client
            .query_opt("SELECT value FROM meta WHERE key='config_generation'", &[])
            .await
            .map_err(pg)?
            .map(|r| r.get::<_, String>(0));
        match v {
            None => Ok(0),
            Some(s) => s.parse().map_err(|_| corrupt("meta.value")),
        }
    }

    async fn bump_config_generation(&self) -> StoreResult<u64> {
        retry(|| async {
            let mut client = self.client().await?;
            let tx = self.begin(&mut client).await?;
            // The row lock orders a bump against writes that read the generation.
            let n: String = tx
                .query_one(
                    "INSERT INTO meta (key, value) VALUES ('config_generation', '1') ON CONFLICT (key) DO UPDATE SET value = (meta.value::bigint + 1)::text RETURNING value",
                    &[],
                )
                .await
                .map_err(pg)?
                .get(0);
            tx.commit().await.map_err(pg)?;
            n.parse().map_err(|_| corrupt("meta.value"))
        })
        .await
    }
}

/// Test support: a direct client on the store's pool (raw SQL in
/// backend-specific tests).
#[cfg(test)]
impl PgStore {
    pub(crate) async fn raw(&self) -> deadpool_postgres::Object {
        self.pool.get().await.expect("pool")
    }
}

/// Pool and listener facts for `/metrics`.
#[derive(Clone, Copy, Debug)]
pub struct PoolMetrics {
    pub max: usize,
    pub open: usize,
    pub idle: usize,
    pub waiting: usize,
    pub listening: bool,
}

impl PgStore {
    pub fn pool_metrics(&self) -> PoolMetrics {
        let s = self.pool.status();
        PoolMetrics {
            max: s.max_size,
            open: s.size,
            idle: s.available,
            waiting: s.waiting,
            listening: self.listening.load(std::sync::atomic::Ordering::Acquire),
        }
    }
}

/// Wait on the publication channel (ADR-0020 slice 5).
impl PgStore {
    /// Follow `NOTIFY` on the publication channel over a dedicated
    /// connection and wake `wake` for each one, and once after every
    /// (re)connect so a follower catches up on what it missed. A dropped
    /// connection is reopened after `retry`; notifications sent meanwhile
    /// are lost, which is why followers also poll. Runs until the process
    /// exits.
    pub async fn follow_publications(
        self: Arc<Self>,
        wake: Arc<tokio::sync::Notify>,
        retry: std::time::Duration,
    ) {
        loop {
            let result = match &self.listen {
                Listen::Plain(cfg) => {
                    listen_once(cfg, tokio_postgres::NoTls, &wake, &self.listening).await
                }
                Listen::Tls(cfg, tls) => {
                    listen_once(cfg, tls.clone(), &wake, &self.listening).await
                }
            };
            self.listening
                .store(false, std::sync::atomic::Ordering::Release);
            if let Err(e) = result {
                tracing::warn!(
                    "publication listener disconnected ({}); polling until it reconnects",
                    pg(e)
                );
            }
            tokio::time::sleep(retry).await;
        }
    }
}

async fn listen_once<T>(
    cfg: &tokio_postgres::Config,
    tls: T,
    wake: &tokio::sync::Notify,
    listening: &std::sync::atomic::AtomicBool,
) -> Result<(), tokio_postgres::Error>
where
    T: tokio_postgres::tls::MakeTlsConnect<tokio_postgres::Socket>,
    T::Stream: Send + 'static,
{
    let (client, mut connection) = cfg.connect(tls).await?;
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let driver = tokio::spawn(async move {
        loop {
            match std::future::poll_fn(|cx| connection.poll_message(cx)).await {
                Some(Ok(tokio_postgres::AsyncMessage::Notification(_))) => {
                    if tx.send(()).is_err() {
                        return Ok(());
                    }
                }
                Some(Ok(_)) => {}
                Some(Err(e)) => return Err(e),
                None => return Ok(()),
            }
        }
    });
    let listened = client
        .batch_execute(&format!("LISTEN {}", meta::PUBLICATION_CHANNEL))
        .await;
    if let Err(e) = listened {
        driver.abort();
        return Err(e);
    }
    listening.store(true, std::sync::atomic::Ordering::Release);
    wake.notify_one();
    while rx.recv().await.is_some() {
        wake.notify_one();
    }
    drop(client);
    match driver.await {
        Ok(result) => result,
        Err(_) => Ok(()),
    }
}
