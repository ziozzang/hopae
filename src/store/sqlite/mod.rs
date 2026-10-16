//! SQLite backend: WAL, one writer thread fed by a channel, readers on the
//! blocking pool, embedded versioned migrations (ADR-0002).
//!
//! Every mutation runs as a closure on the single writer thread inside one
//! `BEGIN IMMEDIATE` transaction together with its events and delivery rows,
//! so a state change and its audit record commit or vanish together.

mod admin;
mod directory;
mod events;
mod factors;
pub(crate) mod groups;
pub(crate) mod human_owner;
mod human_subject;
mod identity_owner;
pub(crate) mod material_owner;
pub(crate) mod primary_owner;
// Internal infrastructure only; native Human candidate integration is queued.
#[allow(dead_code)]
pub(crate) mod provider_owner;
mod rows;
mod sessions;
pub(crate) mod subject_directory;
// Provenance infrastructure; actual native Human candidate integration is queued.
#[cfg(test)]
mod tests;
#[allow(dead_code)]
pub(crate) mod totp_owner;
pub(crate) mod webauthn;
mod webauthn_owner;
mod window;

use std::collections::VecDeque;
use std::fs::OpenOptions;
use std::future::Future;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, MutexGuard, RwLock};
use std::time::{Duration, Instant};

use rusqlite::{Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior};

pub use window::Shape;

use super::hooks::StoreHooks;
use super::{Deadline, Directory, Events, Sessions, StoreError, StoreResult};
use crate::crypto::{Clock, OsRng, Rng};
use crate::event::types::Event;

/// Embedded migrations in order. The version must match the numeric prefix of
/// the file name; it is the position + 1 except where a number is reserved by
/// a branch that merges first (0011-0013).
const MIGRATIONS: &[(u32, &str, &str)] = &[
    (1, "0001_meta", include_str!("../migrations/0001_meta.sql")),
    (
        2,
        "0002_m1_schema",
        include_str!("../migrations/0002_m1_schema.sql"),
    ),
    (
        3,
        "0003_admin",
        include_str!("../migrations/0003_admin.sql"),
    ),
    (
        4,
        "0004_ldap_provider_kind",
        include_str!("../migrations/0004_ldap_provider_kind.sql"),
    ),
    (
        5,
        "0005_totp_enrollments",
        include_str!("../migrations/0005_totp_enrollments.sql"),
    ),
    (
        6,
        "0006_external_factor_proofs",
        include_str!("../migrations/0006_external_factor_proofs.sql"),
    ),
    (
        7,
        "0007_human_provider_owners",
        include_str!("../migrations/0007_human_provider_owners.sql"),
    ),
    (
        8,
        "0008_session_totp_provenance",
        include_str!("../migrations/0008_session_totp_provenance.sql"),
    ),
    (
        9,
        "0009_session_primary_provenance",
        include_str!("../migrations/0009_session_primary_provenance.sql"),
    ),
    (
        10,
        "0010_human_identity_owners",
        include_str!("../migrations/0010_human_identity_owners.sql"),
    ),
    (
        11,
        "0011_webauthn",
        include_str!("../migrations/0011_webauthn.sql"),
    ),
    (
        12,
        "0012_session_webauthn_provenance",
        include_str!("../migrations/0012_session_webauthn_provenance.sql"),
    ),
    (
        13,
        "0013_webauthn_login_challenges",
        include_str!("../migrations/0013_webauthn_login_challenges.sql"),
    ),
    (
        14,
        "0014_groups",
        include_str!("../migrations/0014_groups.sql"),
    ),
];

/// The schema version this binary migrates to (the last embedded migration).
pub const LATEST_SCHEMA_VERSION: u32 = MIGRATIONS[MIGRATIONS.len() - 1].0;

/// Bound of the best-effort diagnostic event queue.
pub const DIAGNOSTIC_QUEUE_CAP: usize = 4096;
/// Read connections kept for reuse.
const READER_POOL_MAX: usize = 4;

tokio::task_local! {
    /// Real-time deadline for store calls made inside [`with_deadline`].
    static STORE_DEADLINE: tokio::time::Instant;
}

/// Run `fut` with every store call inside it bounded by `deadline`: a call
/// that is not finished by then fails with [`StoreError::Unavailable`].
/// (The plan names an `Option<Timestamp>`; a real-time `Instant` is used
/// because a test clock does not advance while a stalled call sleeps.)
///
/// Scopes nest by taking the **earliest**: an inner scope can shorten the
/// enclosing deadline but never extend it (the console's budget survives the
/// engine's own, larger verify budget). Work detached with `tokio::spawn` does
/// not inherit a task-local; it must carry its own deadline (see the touch).
pub async fn with_deadline<F: Future>(deadline: tokio::time::Instant, fut: F) -> F::Output {
    let deadline = match STORE_DEADLINE.try_with(|d| *d) {
        Ok(outer) => outer.min(deadline),
        Err(_) => deadline,
    };
    STORE_DEADLINE.scope(deadline, fut).await
}

type Job = Box<dyn FnOnce(&mut WriterEnv) + Send>;

/// The deadline of a call, captured in the async context: the task-local one
/// (if any) and the explicit one, whichever is earlier.
fn captured_deadline(explicit: Option<Deadline>) -> Option<Instant> {
    earliest_present(
        STORE_DEADLINE.try_with(|d| d.into_std()).ok(),
        explicit.map(|d| d.0),
    )
}

/// State shared by the handle and the writer thread.
pub(crate) struct Shared {
    pub(crate) clock: Arc<dyn Clock>,
    pub(crate) sinks: Vec<String>,
    pub(crate) hooks: Option<Arc<StoreHooks>>,
    pub(crate) rng: RwLock<Arc<dyn Rng>>,
    pub(crate) diag: Mutex<VecDeque<Event>>,
    pub(crate) diag_flush_queued: AtomicBool,
    /// Retention policy enforced inline by the writer (ADR-0009, G7-P01).
    /// Structured log output of persisted diagnostic events: written after the
    /// batch that holds them commits, never before (G7 B02).
    pub(crate) diag_log: Mutex<Option<Arc<crate::event::sinks::LogSink>>>,
    /// Where diagnostic events lost at the persistence boundary are counted.
    pub(crate) drops: Mutex<Option<Arc<crate::event::bus::DropCounts>>>,
    pub(crate) retention: Mutex<Option<crate::store::types::EventRetention>>,
    /// Event rows inserted by the transaction in progress (writer thread).
    pub(crate) pending_events: AtomicU64,
    /// Event rows committed since the last prune.
    pub(crate) committed_events: AtomicU64,
}

impl Shared {
    pub(crate) fn rng(&self) -> Arc<dyn Rng> {
        self.rng.read().unwrap_or_else(|p| p.into_inner()).clone()
    }
}

/// What a writer job gets: the write connection and the shared state.
pub(crate) struct WriterEnv {
    pub(crate) conn: Connection,
    pub(crate) shared: Arc<Shared>,
}

impl WriterEnv {
    pub(crate) fn begin(&mut self) -> StoreResult<Transaction<'_>> {
        // A transaction that did not commit leaves its count behind.
        self.shared.pending_events.store(0, Ordering::Relaxed);
        Ok(self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?)
    }

    pub(crate) fn now(&self) -> crate::crypto::Timestamp {
        self.shared.clock.now()
    }
}

/// Fail with [`StoreError::ProviderDisabled`] when the providers table holds a
/// row for `id` that is disabled or tombstoned. Called inside the write
/// transaction that creates identities or sessions, so a disable committed
/// after the caller's last read still wins (G7-IDP-01).
pub(crate) fn require_provider_live(tx: &Transaction<'_>, id: &str) -> StoreResult<()> {
    use rusqlite::OptionalExtension;
    let dead: Option<i64> = tx
        .query_row(
            "SELECT 1 FROM providers WHERE provider_id=?1 AND (enabled=0 OR deleted_at IS NOT NULL)",
            [id],
            |r| r.get(0),
        )
        .optional()?;
    if dead.is_some() {
        return Err(StoreError::ProviderDisabled);
    }
    Ok(())
}

/// Pass the commit gate `label` (if hooks are present), then commit.
pub(crate) fn commit(tx: Transaction<'_>, shared: &Shared, gate: Option<&str>) -> StoreResult<()> {
    commit_inner(tx, shared, gate, None)
}

/// As [`commit`] for a job that runs under a deadline: the inline retention
/// prune may not swallow the deadline, and the deadline is checked once more
/// after it, immediately before `COMMIT` (a job that reaches its deadline never
/// commits late).
pub(crate) fn commit_checked(
    tx: Transaction<'_>,
    shared: &Shared,
    gate: Option<&str>,
    check: &Check,
) -> StoreResult<()> {
    commit_inner(tx, shared, gate, Some(check))
}

/// Whether a retention failure is the job's deadline or an interrupt of its
/// statement: those end the job, they are never logged and committed past.
fn is_deadline_error(e: &StoreError) -> bool {
    match e {
        StoreError::Unavailable(m) => m == "deadline" || m == "interrupted",
        StoreError::Sqlite(rusqlite::Error::SqliteFailure(f, _)) => {
            f.code == rusqlite::ErrorCode::OperationInterrupted
        }
        _ => false,
    }
}

fn commit_inner(
    tx: Transaction<'_>,
    shared: &Shared,
    gate: Option<&str>,
    check: Option<&Check>,
) -> StoreResult<()> {
    if let (Some(h), Some(label)) = (&shared.hooks, gate) {
        h.pass_gate(label);
    }
    // Retention is enforced at the commit boundary (G7-P01): when this
    // transaction's own event rows bring the rows committed since the last
    // prune to `prune_every`, the prune runs inside it, so no committed state
    // holds more than `max_rows + prune_every - 1` rows.
    let n = shared.pending_events.swap(0, Ordering::Relaxed);
    let before = shared.committed_events.load(Ordering::Relaxed);
    let mut pruned = None;
    if n > 0
        && let Some(policy) = events::retention(shared)
        && before + n >= policy.prune_every.max(1)
    {
        match events::prune_statements(&tx, shared, shared.clock.now(), &policy) {
            Ok(report) => pruned = Some(report),
            // The deadline (or an interrupted statement) ends the job: the
            // transaction is dropped, so nothing of it commits.
            Err(e) if is_deadline_error(&e) => return Err(e),
            Err(e) => tracing::warn!(error = %e, "inline event prune failed"),
        }
    }
    if let Some(check) = check {
        check.now()?;
    }
    tx.commit()?;
    match pruned {
        Some(report) => {
            shared.committed_events.store(0, Ordering::Relaxed);
            let policy_sinks = shared.sinks.clone();
            crate::event::prune::account_report(
                &report,
                &crate::event::prune::sink_label(&policy_sinks),
            );
        }
        None => {
            shared.committed_events.fetch_add(n, Ordering::Relaxed);
        }
    }
    Ok(())
}

struct Inner {
    shared: Arc<Shared>,
    tx: mpsc::Sender<Job>,
    path: PathBuf,
    readers: Mutex<Vec<Connection>>,
    util: Mutex<Connection>,
}

/// The SQLite store. Cheap to clone; clones share the writer thread.
#[derive(Clone)]
pub struct Store {
    inner: Arc<Inner>,
}

impl Store {
    /// Create the parent directory (0700 when newly created) and the database
    /// file (0600), open it, run pending migrations and start the writer.
    /// `sinks` names the event sinks that get a delivery row per required event.
    pub fn open(
        path: &Path,
        clock: Arc<dyn Clock>,
        sinks: Vec<String>,
        hooks: Option<Arc<StoreHooks>>,
    ) -> Result<Self, StoreError> {
        Self::open_with(path, clock, sinks, hooks, false)
    }

    /// Open an existing, current database for a command-line administrator
    /// (ADR-0016): the read-only [`precheck`] runs first, the file is never
    /// created and never migrated (an older database is refused: "start the
    /// instance once to migrate"), no instance lock is taken, and no backup is
    /// written. Busy waits are bounded at five seconds.
    pub fn open_cli(
        path: &Path,
        clock: Arc<dyn Clock>,
        sinks: Vec<String>,
    ) -> Result<Self, StoreError> {
        let found = precheck(path)?;
        let latest = supported_version();
        if found < latest {
            return Err(StoreError::SchemaTooOld { found, latest });
        }
        Self::open_with(path, clock, sinks, None, true)
    }

    fn open_with(
        path: &Path,
        clock: Arc<dyn Clock>,
        sinks: Vec<String>,
        hooks: Option<Arc<StoreHooks>>,
        cli: bool,
    ) -> Result<Self, StoreError> {
        let io = |p: &Path| {
            let p = p.display().to_string();
            move |source| StoreError::Io {
                path: p.clone(),
                source,
            }
        };
        if !cli {
            // A refused database is left byte for byte as it is: validate
            // read-only before the journal mode or anything else is touched.
            precheck(path)?;
            if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
                std::fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(dir)
                    .map_err(io(dir))?;
            }
            // Create the file with a restrictive mode before SQLite does; the WAL
            // and shared-memory files inherit the main file's permissions.
            OpenOptions::new()
                .create(true)
                .append(true)
                .mode(0o600)
                .open(path)
                .map_err(io(path))?;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .map_err(io(path))?;
        }
        let util = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        configure(&util)?;
        if !cli {
            migrate(&util)?;
        }
        let writer = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        configure(&writer)?;

        let shared = Arc::new(Shared {
            clock,
            sinks,
            hooks,
            rng: RwLock::new(Arc::new(OsRng)),
            diag: Mutex::new(VecDeque::new()),
            diag_flush_queued: AtomicBool::new(false),
            drops: Mutex::new(None),
            diag_log: Mutex::new(None),
            retention: Mutex::new(None),
            pending_events: AtomicU64::new(0),
            committed_events: AtomicU64::new(0),
        });
        let (tx, rx) = mpsc::channel::<Job>();
        let mut env = WriterEnv {
            conn: writer,
            shared: shared.clone(),
        };
        std::thread::Builder::new()
            .name("hopae-store-writer".into())
            .spawn(move || {
                while let Ok(job) = rx.recv() {
                    job(&mut env);
                }
            })
            .map_err(io(path))?;
        Ok(Self {
            inner: Arc::new(Inner {
                shared,
                tx,
                path: path.to_path_buf(),
                readers: Mutex::new(Vec::new()),
                util: Mutex::new(util),
            }),
        })
    }

    pub fn directory(&self) -> Arc<dyn Directory> {
        Arc::new(self.clone())
    }

    pub fn sessions(&self) -> Arc<dyn Sessions> {
        Arc::new(self.clone())
    }

    pub fn events(&self) -> Arc<dyn Events> {
        Arc::new(self.clone())
    }

    /// Write each persisted diagnostic event as a JSON line to `log`, after
    /// the batch transaction that stores it has committed.
    ///
    /// `LogSink::emit` only queues the line on the bounded output channel and
    /// never waits, so blocked output cannot stop the store writer.
    pub fn set_diagnostic_log(&self, log: Arc<crate::event::sinks::LogSink>) {
        *self
            .inner
            .shared
            .diag_log
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = Some(log);
    }

    /// Count diagnostic events whose batch could not be persisted in `drops`.
    pub fn set_drop_counts(&self, drops: Arc<crate::event::bus::DropCounts>) {
        *self
            .inner
            .shared
            .drops
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = Some(drops);
    }

    /// The retention policy the writer enforces itself: after a job, once
    /// `prune_every / 2` event rows have been committed since the last prune,
    /// the writer prunes inline, so the table never exceeds
    /// `max_rows + prune_every` however the prune task is scheduled.
    pub fn set_event_retention(&self, policy: crate::store::types::EventRetention) {
        *self
            .inner
            .shared
            .retention
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = Some(policy);
    }

    /// Replace the random source used for ids the store mints (user ids).
    pub fn set_rng(&self, rng: Arc<dyn Rng>) {
        *self
            .inner
            .shared
            .rng
            .write()
            .unwrap_or_else(|p| p.into_inner()) = rng;
    }

    /// Record required events on the caller's already-open publication
    /// transaction (they commit or roll back with it).
    pub(crate) fn record_in(
        &self,
        connection: &Connection,
        events: &[crate::event::types::Event],
    ) -> crate::store::StoreResult<()> {
        events::insert_events(connection, self.shared(), events)
    }

    /// Check administrator authority on the caller's already-open publication transaction.
    pub(crate) fn fence_profile_actor(
        &self,
        connection: &Connection,
        actor: &crate::store::Actor,
        policy: &crate::store::ActorPolicy,
    ) -> crate::store::StoreResult<()> {
        admin::fence(connection, self.shared(), actor, policy)
    }

    /// Borrow a utility connection (tests, operators, the test hooks). Not for request paths.
    pub fn conn(&self) -> MutexGuard<'_, Connection> {
        self.inner.util.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Test support (`store/hold_write_lock`): a second connection takes the
    /// write lock for `ms` milliseconds, then rolls back. Returns once the
    /// lock is held.
    pub fn hold_write_lock(&self, ms: u64) -> Result<(), StoreError> {
        let conn = Connection::open_with_flags(
            &self.inner.path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        conn.busy_timeout(DEFAULT_BUSY)?;
        conn.execute_batch("BEGIN IMMEDIATE")?;
        std::thread::Builder::new()
            .name("hopae-hold-lock".into())
            .spawn(move || {
                std::thread::sleep(Duration::from_millis(ms));
                let _ = conn.execute_batch("ROLLBACK");
            })
            .map_err(|source| StoreError::Io {
                path: "hold_write_lock".into(),
                source,
            })?;
        Ok(())
    }

    /// Highest applied migration version.
    pub fn schema_version(&self) -> Result<u32, StoreError> {
        current_version(&self.conn())
    }

    pub fn path(&self) -> &Path {
        &self.inner.path
    }

    pub(crate) fn shared(&self) -> &Arc<Shared> {
        &self.inner.shared
    }

    /// Account for the call, apply the stall hook and the task-local deadline.
    async fn run<T>(
        &self,
        method: &'static str,
        work: impl Future<Output = StoreResult<T>>,
    ) -> StoreResult<T> {
        let stall = self.inner.shared.hooks.as_ref().map(|h| {
            h.count_call(method);
            h.stall()
        });
        let work = async move {
            if let Some(d) = stall.filter(|d| !d.is_zero()) {
                tokio::time::sleep(d).await;
            }
            work.await
        };
        match STORE_DEADLINE.try_with(|d| *d) {
            Ok(deadline) => tokio::time::timeout_at(deadline, work)
                .await
                .unwrap_or_else(|_| Err(StoreError::Unavailable("deadline exceeded".into()))),
            Err(_) => work.await,
        }
    }

    /// Run a mutation on the writer thread.
    pub(crate) async fn write<T: Send + 'static>(
        &self,
        method: &'static str,
        f: impl FnOnce(&mut WriterEnv) -> StoreResult<T> + Send + 'static,
    ) -> StoreResult<T> {
        self.write_checked(method, None, move |env, _| f(env)).await
    }

    /// As [`Store::write`], with an explicit deadline and the job's [`Check`].
    /// The deadline is captured HERE, in the async context, with the
    /// earliest-present combiner, and travels into the job as a plain value
    /// (task-locals do not cross the dispatch boundary).
    pub(crate) async fn write_checked<T: Send + 'static>(
        &self,
        method: &'static str,
        explicit: Option<Deadline>,
        f: impl FnOnce(&mut WriterEnv, &Check) -> StoreResult<T> + Send + 'static,
    ) -> StoreResult<T> {
        let deadline = captured_deadline(explicit);
        let tx = self.inner.tx.clone();
        self.run(method, async move {
            let (reply, rx) = tokio::sync::oneshot::channel();
            let job: Job = Box::new(move |env| {
                let hooks = env.shared.hooks.clone();
                let out = match arm(&env.conn, deadline, &hooks) {
                    Err(e) => Err(e),
                    Ok(check) => {
                        let out = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            f(env, &check)
                        }))
                        .unwrap_or_else(|_| Err(StoreError::Unavailable("internal error".into())))
                        .map_err(|e| map_interrupt(e, &check));
                        disarm(&env.conn, deadline.is_some());
                        out
                    }
                };
                let _ = reply.send(out);
            });
            tx.send(job)
                .map_err(|_| StoreError::Unavailable("store writer stopped".into()))?;
            rx.await
                .map_err(|_| StoreError::Unavailable("store writer stopped".into()))?
        })
        .await
    }

    /// Run a read on the blocking pool with a pooled read-only connection.
    pub(crate) async fn read<T: Send + 'static>(
        &self,
        method: &'static str,
        f: impl FnOnce(&Connection) -> StoreResult<T> + Send + 'static,
    ) -> StoreResult<T> {
        self.read_checked(method, None, move |c, _| f(c)).await
    }

    /// As [`Store::read`], with an explicit deadline and the job's [`Check`].
    pub(crate) async fn read_checked<T: Send + 'static>(
        &self,
        method: &'static str,
        explicit: Option<Deadline>,
        f: impl FnOnce(&Connection, &Check) -> StoreResult<T> + Send + 'static,
    ) -> StoreResult<T> {
        let deadline = captured_deadline(explicit);
        let inner = self.inner.clone();
        self.run(method, async move {
            tokio::task::spawn_blocking(move || {
                let pooled = inner
                    .readers
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .pop();
                let conn = match pooled {
                    Some(c) => c,
                    None => open_reader(&inner.path)?,
                };
                let hooks = inner.shared.hooks.clone();
                let out = match arm(&conn, deadline, &hooks) {
                    Err(e) => Err(e),
                    Ok(check) => {
                        let out = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            f(&conn, &check)
                        }))
                        .unwrap_or_else(|_| Err(StoreError::Unavailable("internal error".into())))
                        .map_err(|e| map_interrupt(e, &check));
                        disarm(&conn, deadline.is_some());
                        out
                    }
                };
                // A connection that failed mid-statement may hold an open
                // transaction or a temp table; only a clean one is reused.
                if conn.is_autocommit() {
                    let mut pool = inner.readers.lock().unwrap_or_else(|p| p.into_inner());
                    if pool.len() < READER_POOL_MAX {
                        pool.push(conn);
                    }
                }
                out
            })
            .await
            .map_err(|_| StoreError::Unavailable("store reader failed".into()))?
        })
        .await
    }

    /// Wait until every job queued before this call (including queued
    /// diagnostic events) has run.
    pub async fn barrier(&self) -> StoreResult<()> {
        self.write("barrier", |env| {
            events::flush_diagnostics(env);
            Ok(())
        })
        .await
    }
}

fn current_version(conn: &Connection) -> Result<u32, StoreError> {
    let v: Option<u32> = conn.query_row("SELECT MAX(version) FROM schema_migrations", [], |r| {
        r.get(0)
    })?;
    Ok(v.unwrap_or(0))
}

/// The newest schema version this binary knows.
fn supported_version() -> u32 {
    MIGRATIONS.last().map_or(0, |m| m.0)
}

/// Structures a database at `version` must have (public: the CLI and the
/// backup step call it too). A version-2 database written before migration
/// 0002 was finalized lacks later additions and no migration would add them:
/// it is refused as [`StoreError::DevelopmentSchema`]; a later version missing
/// its own structures is [`StoreError::Corrupt`] naming the structure.
pub fn validate_foundation(conn: &Connection, version: u32) -> Result<(), StoreError> {
    let count = |sql: &str, arg: &str, arg2: &str| -> Result<bool, StoreError> {
        Ok(conn.query_row(sql, rusqlite::params![arg, arg2], |r| r.get::<_, i64>(0))? > 0)
    };
    let table = |name: &str| {
        count(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1 AND ?2=?2",
            name,
            "",
        )
    };
    let index = |name: &str| {
        count(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name=?1 AND ?2=?2",
            name,
            "",
        )
    };
    let column = |tbl: &str, col: &str| {
        count(
            "SELECT COUNT(*) FROM pragma_table_info(?1) WHERE name=?2",
            tbl,
            col,
        )
    };
    if version >= 2 {
        let complete = column("sessions", "authz_version_at_auth")?
            && index("users_primary_email")?
            && index("event_deliveries_event_id")?
            && table("txn_admissions")?
            && conn.query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='login_txns' AND sql LIKE '%''logout''%'",
                [],
                |r| r.get::<_, i64>(0),
            )? > 0;
        if !complete {
            return Err(StoreError::DevelopmentSchema);
        }
    }
    if version >= 3 {
        let missing = |what: String| StoreError::Corrupt(format!("schema v3 is missing {what}"));
        if !table("admin_grants")? {
            return Err(missing("admin_grants".into()));
        }
        for (t, c) in [
            ("sessions", "bound_ua_prefix"),
            ("sessions", "auth_time_source"),
            ("login_txns", "reauth_max_age"),
        ] {
            if !column(t, c)? {
                return Err(missing(format!("{t}.{c}")));
            }
        }
        for ix in [
            "events_at_id",
            "events_user_at_id",
            "events_ip_at_id",
            "events_kind_at_id",
            "events_session_at_id",
            "users_created_id",
            "sessions_live_created",
            "sessions_live_user_created",
            "admin_grants_source_email",
        ] {
            if !index(ix)? {
                return Err(missing(ix.into()));
            }
        }
    }
    if version >= 4 {
        let supported:bool=conn.query_row("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='providers' AND sql LIKE '%''ldap''%'",[],|row|Ok(row.get::<_,i64>(0)?>0))?;
        if !supported {
            return Err(StoreError::Corrupt(
                "schema v4 is missing LDAP provider support".into(),
            ));
        }
    }
    if version >= 5 {
        let corrupt =
            |what: &str| StoreError::Corrupt(format!("schema v5 invalid TOTP structure: {what}"));
        if !table("totp_enrollments")? {
            return Err(corrupt("table"));
        }
        for name in [
            "enrollment_id",
            "user_id",
            "envelope",
            "revision",
            "state",
            "last_counter",
            "pending_expires_at",
            "created_at",
            "updated_at",
        ] {
            if !column("totp_enrollments", name)? {
                return Err(corrupt("column"));
            }
        }
        let strict: bool = conn.query_row(
            "SELECT strict FROM pragma_table_list WHERE schema='main' AND name='totp_enrollments'",
            [],
            |row| row.get(0),
        )?;
        if !strict {
            return Err(corrupt("strict table"));
        }
        for (name, state) in [
            ("totp_one_pending_per_user", "pending"),
            ("totp_one_active_per_user", "active"),
        ] {
            let flags: Option<(bool,bool)> = conn.query_row("SELECT [unique],partial FROM pragma_index_list('totp_enrollments') WHERE name=?1",[name],|row|Ok((row.get(0)?,row.get(1)?))).optional()?;
            if flags != Some((true, true)) {
                return Err(corrupt("unique partial index"));
            }
            let columns: Vec<String> = conn
                .prepare("SELECT name FROM pragma_index_info(?1) ORDER BY seqno")?
                .query_map([name], |row| row.get(0))?
                .collect::<Result<_, _>>()?;
            if columns != ["user_id"] {
                return Err(corrupt("index owner"));
            }
            let sql: String = conn.query_row(
                "SELECT sql FROM sqlite_master WHERE type='index' AND name=?1",
                [name],
                |row| row.get(0),
            )?;
            let normalized: String = sql
                .to_ascii_lowercase()
                .chars()
                .filter(|c| !c.is_whitespace() && *c != '"')
                .collect();
            if !normalized.ends_with(&format!("wherestate='{state}'")) {
                return Err(corrupt("index predicate"));
            }
        }
    }
    if version >= 6 {
        // Exact schema comparison includes constraints, primary-key scope and
        // the capacity trigger. No repair or business write during precheck.
        let normalize = |sql: &str| -> String {
            sql.to_ascii_lowercase()
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect::<String>()
                .trim_end_matches(';')
                .to_owned()
        };
        let migration = include_str!("../migrations/0006_external_factor_proofs.sql");
        for (kind, name) in [
            ("table", "external_factor_authorities"),
            ("table", "external_factor_proofs"),
            ("table", "external_factor_sessions"),
            ("table", "external_factor_budget"),
            ("trigger", "external_factor_proof_budget"),
        ] {
            let start = migration
                .find(&format!("CREATE {} {name}", kind.to_ascii_uppercase()))
                .expect("embedded external factor schema");
            let expected = if kind == "trigger" {
                &migration[start..]
            } else {
                migration[start..]
                    .split(';')
                    .next()
                    .expect("embedded table")
            };
            let actual: Option<String> = conn
                .query_row(
                    "SELECT sql FROM sqlite_master WHERE type=?1 AND name=?2",
                    [kind, name],
                    |row| row.get(0),
                )
                .optional()?;
            if actual.as_deref().map(normalize) != Some(normalize(expected)) {
                return Err(StoreError::Corrupt(
                    "schema v6 invalid external factor structure".into(),
                ));
            }
        }
        let count: i64 =
            conn.query_row("SELECT count(*) FROM external_factor_proofs", [], |r| {
                r.get(0)
            })?;
        let used: Option<i64> = conn
            .query_row(
                "SELECT used FROM external_factor_budget WHERE singleton=1",
                [],
                |r| r.get(0),
            )
            .optional()?;
        if used != Some(count) || count > 1_000_000 {
            return Err(StoreError::Corrupt(
                "schema v6 invalid external proof capacity".into(),
            ));
        }
    }
    if version >= 7 {
        provider_owner::validate_foundation(conn)?;
    }
    if version >= 8 {
        totp_owner::validate_foundation(conn)?;
    }
    if version >= 9 {
        primary_owner::validate_foundation(conn)?;
    }
    if version >= 10 {
        identity_owner::validate_foundation(conn)?;
    }
    if version >= 11 {
        webauthn::validate_foundation(conn)?;
    }
    if version >= 12 {
        webauthn_owner::validate_foundation(conn)?;
    }
    if version >= 13 {
        webauthn::validate_login_foundation(conn)?;
    }
    if version >= 14 {
        for t in [
            "directory_groups",
            "group_members",
            "group_changes",
            "group_sync_state",
        ] {
            if !table(t)? {
                return Err(StoreError::Corrupt(format!("missing table {t}")));
            }
        }
    }
    Ok(())
}

/// Read-only pre-check used by `bind` and by every CLI command BEFORE any
/// backup or write: opens the file read-only, reads the recorded version,
/// refuses a newer one, validates the foundation and returns the version. A
/// missing or empty file is a fresh database (version 0).
pub fn precheck(path: &Path) -> Result<u32, StoreError> {
    match std::fs::metadata(path) {
        Ok(m) if m.len() > 0 => {}
        Ok(_) => return Ok(0),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(source) => {
            return Err(StoreError::Io {
                path: path.display().to_string(),
                source,
            });
        }
    }
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    conn.busy_timeout(DEFAULT_BUSY)?;
    let has_table: i64 = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='schema_migrations'",
        [],
        |r| r.get(0),
    )?;
    if has_table == 0 {
        return Ok(0);
    }
    let found = current_version(&conn)?;
    let supported = supported_version();
    if found > supported {
        return Err(StoreError::SchemaTooNew { found, supported });
    }
    validate_foundation(&conn, found)?;
    Ok(found)
}

/// Apply every migration newer than the recorded version, each in its own
/// transaction. Idempotent. Refuses a database from a newer binary, validates
/// the foundation before applying anything and the structures again at the
/// final version.
pub fn migrate(conn: &Connection) -> Result<u32, StoreError> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_migrations (
             version    INTEGER PRIMARY KEY NOT NULL,
             name       TEXT NOT NULL,
             applied_at INTEGER NOT NULL
         ) STRICT;",
    )?;
    let found = current_version(conn)?;
    let supported = supported_version();
    if found > supported {
        return Err(StoreError::SchemaTooNew { found, supported });
    }
    validate_foundation(conn, found)?;
    if found > 0 && found < supported {
        tracing::info!("schema foundation validated (v{found})");
    }
    for &(version, name, sql) in MIGRATIONS.iter().filter(|m| m.0 > found) {
        let tx = conn.unchecked_transaction()?;
        tx.execute_batch(sql)?;
        tx.execute(
            "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?1, ?2, unixepoch())",
            rusqlite::params![version, name],
        )?;
        tx.commit()?;
    }
    let version = current_version(conn)?;
    validate_foundation(conn, version)?;
    Ok(version)
}

// ---- deadlines and interruption (P2-05, P3-03) ------------------------------

/// Default SQLite busy timeout of every connection.
pub(crate) const DEFAULT_BUSY: Duration = Duration::from_millis(5000);

/// Earliest PRESENT deadline: either sole source is kept; `Option::min` would
/// drop a present one (`None < Some`).
pub fn earliest_present(a: Option<Instant>, b: Option<Instant>) -> Option<Instant> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.min(y)),
        (Some(x), None) => Some(x),
        (None, Some(y)) => Some(y),
        (None, None) => None,
    }
}

/// What a job checks between statements: the deadline it was handed, and the
/// test hook that slows each step down.
pub struct Check {
    deadline: Option<Instant>,
    /// The busy timeout was shortened to the deadline: a busy result after it
    /// is the deadline, not contention.
    bounded_busy: bool,
    hooks: Option<Arc<StoreHooks>>,
}

impl Check {
    /// No deadline: every check passes.
    pub fn none() -> Check {
        Check {
            deadline: None,
            bounded_busy: false,
            hooks: None,
        }
    }

    /// Time left, or `None` without a deadline.
    pub fn remaining(&self) -> Option<Duration> {
        self.deadline
            .map(|d| d.saturating_duration_since(Instant::now()))
    }

    /// Fail with `Unavailable("deadline")` once the deadline has passed.
    pub fn now(&self) -> StoreResult<()> {
        match self.deadline {
            Some(d) if Instant::now() >= d => Err(StoreError::Unavailable("deadline".into())),
            _ => Ok(()),
        }
    }

    /// A statement boundary inside a loop: the slow-scan hook sleeps, then the deadline is checked.
    pub fn step(&self) -> StoreResult<()> {
        if let Some(h) = &self.hooks {
            let d = h.slow_scan();
            if !d.is_zero() {
                std::thread::sleep(d);
            }
        }
        self.now()
    }
}

thread_local! {
    // Every connection job runs entirely on one dedicated/blocking thread.
    // rusqlite's safe busy-handler API accepts a function pointer, not a capture.
    static BUSY_DEADLINE: std::cell::Cell<Option<Instant>> = const { std::cell::Cell::new(None) };
}
fn deadline_busy(_attempt: i32) -> bool {
    BUSY_DEADLINE.with(|slot| {
        let Some(deadline) = slot.get() else {
            return false;
        };
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return false;
        }
        std::thread::sleep(remaining.min(Duration::from_millis(2)));
        // Sleep may overshoot under OS scheduling/coalescing. Never accumulate
        // only requested milliseconds as SQLite's default callback does.
        Instant::now() < deadline
    })
}

/// Install the deadline on `conn` for one job: refuse before the first
/// statement when it has passed, bound the busy timeout, install the progress
/// handler. Always paired with [`disarm`].
fn arm(
    conn: &Connection,
    deadline: Option<Instant>,
    hooks: &Option<Arc<StoreHooks>>,
) -> StoreResult<Check> {
    if let Some(h) = hooks {
        h.record_deadline(deadline);
    }
    let Some(d) = deadline else {
        return Ok(Check {
            deadline: None,
            bounded_busy: false,
            hooks: hooks.clone(),
        });
    };
    let remaining = d.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(StoreError::Unavailable("deadline".into()));
    }
    BUSY_DEADLINE.with(|slot| slot.set(Some(d.min(Instant::now() + DEFAULT_BUSY))));
    conn.busy_handler(Some(deadline_busy))?;
    let slow = hooks.clone();
    conn.progress_handler(
        1000,
        Some(move || {
            if let Some(h) = &slow {
                let s = h.slow_scan();
                if !s.is_zero() {
                    std::thread::sleep(s);
                }
            }
            Instant::now() >= d
        }),
    );
    Ok(Check {
        deadline: Some(d),
        bounded_busy: remaining <= DEFAULT_BUSY,
        hooks: hooks.clone(),
    })
}

/// Undo [`arm`]: the connection is reused only without a handler and with the default busy timeout.
fn disarm(conn: &Connection, armed: bool) {
    BUSY_DEADLINE.with(|slot| slot.set(None));
    if armed {
        conn.progress_handler(0, None::<fn() -> bool>);
    }
    let _ = conn.busy_timeout(DEFAULT_BUSY);
}

fn map_interrupt(e: StoreError, check: &Check) -> StoreError {
    match &e {
        StoreError::Sqlite(rusqlite::Error::SqliteFailure(f, _))
            if f.code == rusqlite::ErrorCode::OperationInterrupted =>
        {
            crate::telemetry::counters::inc(
                crate::telemetry::counters::STORE_INTERRUPTS_TOTAL,
                &[],
            );
            StoreError::Unavailable("interrupted".into())
        }
        StoreError::Busy if check.deadline.is_some() && check.bounded_busy => {
            StoreError::Unavailable("deadline".into())
        }
        _ => e,
    }
}

/// Run `f` on `conn` under `deadline` (P3-03): refused before the first
/// statement when it has passed, a held lock cannot block past it, the
/// statement is interrupted inside SQLite, and the connection is restored
/// (handler cleared, default busy timeout) before it is reused.
pub fn with_job_deadline<T>(
    conn: &Connection,
    deadline: Option<Instant>,
    f: impl FnOnce(&Connection, &Check) -> StoreResult<T>,
) -> StoreResult<T> {
    let check = arm(conn, deadline, &None)?;
    let out = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        f(conn, &check).map_err(|e| map_interrupt(e, &check))
    }));
    disarm(conn, deadline.is_some());
    match out {
        Ok(value) => value,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

fn open_reader(path: &Path) -> StoreResult<Connection> {
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    conn.busy_timeout(DEFAULT_BUSY)?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.pragma_update(None, "temp_store", "MEMORY")?;
    Ok(conn)
}

fn configure(conn: &Connection) -> Result<(), StoreError> {
    conn.busy_timeout(DEFAULT_BUSY)?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    Ok(())
}
