//! `MetaDb` on PostgreSQL (ADR-0020 slice 5): synchronous owner
//! transactions over the async driver. Every call blocks the calling thread
//! (`block_in_place` + the runtime handle), so owners run where blocking is
//! allowed; every write transaction takes one advisory lock first, so owner
//! writes serialize across replicas exactly as behind SQLite's single
//! writer, and key ranges are compared in byte order (`COLLATE "C"`).
use std::cell::Cell;
use std::future::Future;
use std::sync::Arc;

use deadpool_postgres::Transaction;

use super::PgStore;
use crate::store::StoreResult;
use crate::store::meta::{MetaDb, MetaError, MetaTx};
use crate::store::types::{Actor, ActorPolicy};

/// `pg_advisory_xact_lock` key every owner write transaction takes.
pub(crate) const META_LOCK: i64 = 7070;

/// The `LISTEN`/`NOTIFY` channel of published owner state.
pub(crate) const PUBLICATION_CHANNEL: &str = "hopae_publication";

fn wait<F: Future>(handle: &tokio::runtime::Handle, f: F) -> F::Output {
    match tokio::runtime::Handle::try_current() {
        // On a runtime thread: let the runtime move other tasks away first.
        Ok(_) => tokio::task::block_in_place(|| handle.block_on(f)),
        Err(_) => handle.block_on(f),
    }
}

/// The meta connection of a PostgreSQL store.
pub struct PgMeta {
    store: Arc<PgStore>,
    handle: tokio::runtime::Handle,
    deadline: Option<crate::store::Deadline>,
}

impl PgMeta {
    pub fn new(store: Arc<PgStore>) -> Self {
        let handle = store.handle.clone();
        Self {
            store,
            handle,
            deadline: None,
        }
    }

    /// Every transaction of this handle ends by `deadline`: its statements
    /// time out, and past it nothing commits.
    pub fn within(mut self, deadline: crate::store::Deadline) -> Self {
        self.deadline = Some(deadline);
        self
    }
}

/// One open PostgreSQL transaction seen through `MetaTx`.
pub struct PgMetaTx<'a> {
    tx: &'a Transaction<'a>,
    store: &'a PgStore,
    handle: &'a tokio::runtime::Handle,
    write: bool,
}

impl<'a> PgMetaTx<'a> {
    /// A view of an open transaction (`write`: an owner write transaction,
    /// whose reads lock what they rely on until commit).
    pub(super) fn view(
        tx: &'a Transaction<'a>,
        store: &'a PgStore,
        handle: &'a tokio::runtime::Handle,
        write: bool,
    ) -> Self {
        Self {
            tx,
            store,
            handle,
            write,
        }
    }
}

impl PgMetaTx<'_> {
    fn run<F: Future>(&self, f: F) -> F::Output {
        wait(self.handle, f)
    }

    /// The row-lock suffix for a decision read in this transaction: inside
    /// an owner write, `FOR SHARE` keeps the rows as read until commit (a
    /// read snapshot is consistent by itself: `REPEATABLE READ`).
    pub(crate) fn lock(&self) -> &'static str {
        if self.write { " FOR SHARE" } else { "" }
    }

    /// One row of a query in this transaction (blocking).
    pub(crate) fn query_opt(
        &self,
        sql: &str,
        params: &[&(dyn tokio_postgres::types::ToSql + Sync)],
    ) -> StoreResult<Option<tokio_postgres::Row>> {
        self.run(self.tx.query_opt(sql, params)).map_err(super::pg)
    }

    /// Required events inside this transaction (outbox, feed positions).
    pub fn record(&self, events: &[crate::event::types::Event]) -> StoreResult<()> {
        self.run(self.store.insert_events(self.tx, events))
    }

    /// The administrator fence (ADR-0016) inside this transaction.
    pub fn fence(&self, actor: &Actor, policy: &ActorPolicy) -> StoreResult<()> {
        self.run(super::admin::fence(
            self.tx,
            self.store.now().secs(),
            actor,
            policy,
        ))
    }
}

impl MetaTx for PgMetaTx<'_> {
    fn get(&self, key: &str) -> Result<Option<String>, MetaError> {
        self.run(
            self.tx
                .query_opt("SELECT value FROM meta WHERE key=$1", &[&key]),
        )
        .map(|r| r.map(|r| r.get(0)))
        .map_err(|_| MetaError)
    }
    fn put(&self, key: &str, value: &str) -> Result<(), MetaError> {
        self.run(self.tx.execute(
            "INSERT INTO meta (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = excluded.value",
            &[&key, &value],
        ))
        .map(|_| ())
        .map_err(|_| MetaError)
    }
    fn insert(&self, key: &str, value: &str) -> Result<(), MetaError> {
        self.run(self.tx.execute(
            "INSERT INTO meta (key, value) VALUES ($1, $2)",
            &[&key, &value],
        ))
        .map(|_| ())
        .map_err(|_| MetaError)
    }
    fn insert_if_absent(&self, key: &str, value: &str) -> Result<bool, MetaError> {
        self.run(self.tx.execute(
            "INSERT INTO meta (key, value) VALUES ($1, $2) ON CONFLICT (key) DO NOTHING",
            &[&key, &value],
        ))
        .map(|n| n == 1)
        .map_err(|_| MetaError)
    }
    fn delete(&self, key: &str) -> Result<(), MetaError> {
        self.run(self.tx.execute("DELETE FROM meta WHERE key=$1", &[&key]))
            .map(|_| ())
            .map_err(|_| MetaError)
    }
    fn range(
        &self,
        from: &str,
        to: &str,
        limit: usize,
    ) -> Result<Vec<(String, String)>, MetaError> {
        self.run(self.tx.query(
            "SELECT key, value FROM meta WHERE key COLLATE \"C\" >= $1 AND key COLLATE \"C\" < $2 ORDER BY key COLLATE \"C\" LIMIT $3",
            &[&from, &to, &(limit as i64)],
        ))
        .map(|rows| rows.iter().map(|r| (r.get(0), r.get(1))).collect())
        .map_err(|_| MetaError)
    }
    fn count(&self, from: &str, to: &str) -> Result<u64, MetaError> {
        self.run(self.tx.query_one(
            "SELECT count(*) FROM meta WHERE key COLLATE \"C\" >= $1 AND key COLLATE \"C\" < $2",
            &[&from, &to],
        ))
        .map(|r| r.get::<_, i64>(0) as u64)
        .map_err(|_| MetaError)
    }
    fn value_equals(&self, key: &str, expected: &str) -> Result<bool, MetaError> {
        self.run(self.tx.query_opt(
            "SELECT value = $2 FROM meta WHERE key=$1",
            &[&key, &expected],
        ))
        .map(|r| r.is_some_and(|r| r.get::<_, bool>(0)))
        .map_err(|_| MetaError)
    }
    fn announce(&self, topic: &str) -> Result<(), MetaError> {
        // Delivered by the server only if and when this transaction commits.
        self.run(
            self.tx
                .execute("SELECT pg_notify($1, $2)", &[&PUBLICATION_CHANNEL, &topic]),
        )
        .map(|_| ())
        .map_err(|_| MetaError)
    }
    fn postgres(&self) -> Option<&PgMetaTx<'_>> {
        Some(self)
    }
}

impl PgMeta {
    fn open<T, E: From<MetaError>>(
        &mut self,
        write: bool,
        attempted: &Cell<bool>,
        f: impl FnOnce(&dyn MetaTx) -> Result<T, E>,
    ) -> Result<T, E> {
        let handle = self.handle.clone();
        let store = self.store.clone();
        let mut client = wait(&handle, store.client()).map_err(|_| MetaError)?;
        // A read is one consistent snapshot, as SQLite's deferred
        // transaction; it can never write.
        let tx = if write {
            wait(&handle, store.begin(&mut client))
        } else {
            wait(&handle, store.begin_snapshot(&mut client))
        }
        .map_err(|_| MetaError)?;
        if let Some(deadline) = self.deadline {
            let ms = super::admin::deadline_ms(deadline).min(store.statement_timeout_ms);
            wait(
                &handle,
                tx.batch_execute(&format!("SET LOCAL statement_timeout = {ms}")),
            )
            .map_err(|_| MetaError)?;
        }
        if write {
            wait(
                &handle,
                tx.execute(super::ADVISORY_XACT_LOCK, &[&META_LOCK]),
            )
            .map_err(|_| MetaError)?;
        }
        let out = {
            let view = PgMetaTx::view(&tx, &store, &handle, write);
            f(&view)?
        };
        if self
            .deadline
            .is_some_and(|d| std::time::Instant::now() >= d.0)
        {
            // Past the deadline nothing commits (nothing was attempted).
            return Err(MetaError.into());
        }
        attempted.set(true);
        wait(&handle, tx.commit()).map_err(|_| MetaError)?;
        Ok(out)
    }
}

impl MetaDb for PgMeta {
    fn meta_read<T, E: From<MetaError>>(
        &mut self,
        f: impl FnOnce(&dyn MetaTx) -> Result<T, E>,
    ) -> Result<T, E> {
        self.open(false, &Cell::new(false), f)
    }
    fn meta_write<T, E: From<MetaError>>(
        &mut self,
        attempted: &Cell<bool>,
        f: impl FnOnce(&dyn MetaTx) -> Result<T, E>,
    ) -> Result<T, E> {
        self.open(true, attempted, f)
    }
}
