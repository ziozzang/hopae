//! SQLite backend: WAL, one writer thread fed by a channel, readers on the
//! blocking pool, embedded versioned migrations (ADR-0002).
//!
//! Every mutation runs as a closure on the single writer thread inside one
//! `BEGIN IMMEDIATE` transaction together with its events and delivery rows,
//! so a state change and its audit record commit or vanish together.

mod directory;
mod events;
mod rows;
mod sessions;
#[cfg(test)]
mod tests;

use std::collections::VecDeque;
use std::fs::OpenOptions;
use std::future::Future;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, MutexGuard, RwLock};
use std::time::Duration;

use rusqlite::{Connection, OpenFlags, Transaction, TransactionBehavior};

use super::hooks::StoreHooks;
use super::{Directory, Events, Sessions, StoreError, StoreResult};
use crate::crypto::{Clock, OsRng, Rng};
use crate::event::types::Event;

/// Embedded migrations in order. The version is the position + 1 and must
/// match the numeric prefix of the file name.
const MIGRATIONS: &[(u32, &str, &str)] = &[
    (1, "0001_meta", include_str!("../migrations/0001_meta.sql")),
    (
        2,
        "0002_m1_schema",
        include_str!("../migrations/0002_m1_schema.sql"),
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
pub async fn with_deadline<F: Future>(deadline: tokio::time::Instant, fut: F) -> F::Output {
    STORE_DEADLINE.scope(deadline, fut).await
}

type Job = Box<dyn FnOnce(&mut WriterEnv) + Send>;

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
            Err(e) => tracing::warn!(error = %e, "inline event prune failed"),
        }
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
        let io = |p: &Path| {
            let p = p.display().to_string();
            move |source| StoreError::Io {
                path: p.clone(),
                source,
            }
        };
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
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(io(path))?;
        let util = Connection::open(path)?;
        configure(&util)?;
        migrate(&util)?;
        let writer = Connection::open(path)?;
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

    /// Borrow a utility connection (tests, operators, the test hooks). Not for request paths.
    pub fn conn(&self) -> MutexGuard<'_, Connection> {
        self.inner.util.lock().unwrap_or_else(|p| p.into_inner())
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
        let tx = self.inner.tx.clone();
        self.run(method, async move {
            let (reply, rx) = tokio::sync::oneshot::channel();
            let job: Job = Box::new(move |env| {
                let out = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(env)))
                    .unwrap_or_else(|_| Err(StoreError::Unavailable("internal error".into())));
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
                let out = f(&conn);
                let mut pool = inner.readers.lock().unwrap_or_else(|p| p.into_inner());
                if pool.len() < READER_POOL_MAX {
                    pool.push(conn);
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

fn open_reader(path: &Path) -> StoreResult<Connection> {
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    conn.busy_timeout(Duration::from_millis(5000))?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    Ok(conn)
}

fn configure(conn: &Connection) -> Result<(), StoreError> {
    conn.busy_timeout(Duration::from_millis(5000))?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    Ok(())
}

fn current_version(conn: &Connection) -> Result<u32, StoreError> {
    let v: Option<u32> = conn.query_row("SELECT MAX(version) FROM schema_migrations", [], |r| {
        r.get(0)
    })?;
    Ok(v.unwrap_or(0))
}

/// Apply every migration newer than the recorded version, each in its own
/// transaction. Idempotent. Refuses a database from a newer binary.
pub fn migrate(conn: &Connection) -> Result<u32, StoreError> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_migrations (
             version    INTEGER PRIMARY KEY NOT NULL,
             name       TEXT NOT NULL,
             applied_at INTEGER NOT NULL
         ) STRICT;",
    )?;
    let found = current_version(conn)?;
    let supported = MIGRATIONS.last().map_or(0, |m| m.0);
    if found > supported {
        return Err(StoreError::SchemaTooNew { found, supported });
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
    refuse_pre_release_schema(conn, version)?;
    Ok(version)
}

/// Migration 0002 gained `sessions.authz_version_at_auth`, the
/// `users_primary_email`, `event_deliveries_event_id` index, the
/// `txn_admissions` table and the `logout` transaction purpose while still
/// unreleased (no new migration). A
/// version-2 database written before that has neither, and no migration will
/// add them: refuse it rather than fail later in a session query.
fn refuse_pre_release_schema(conn: &Connection, version: u32) -> Result<(), StoreError> {
    if version != 2 {
        return Ok(());
    }
    let present = |sql: &str| -> Result<bool, StoreError> {
        Ok(conn.query_row(sql, [], |r| r.get::<_, i64>(0))? > 0)
    };
    let complete = present(
        "SELECT COUNT(*) FROM pragma_table_info('sessions') WHERE name='authz_version_at_auth'",
    )? && present(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='users_primary_email'",
    )? && present(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='event_deliveries_event_id'",
    )? && present(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='txn_admissions'",
    )? && present(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='login_txns' AND sql LIKE '%''logout''%'",
    )?;
    if !complete {
        return Err(StoreError::DevelopmentSchema);
    }
    Ok(())
}
