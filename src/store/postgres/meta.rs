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
}

impl PgMeta {
    pub fn new(store: Arc<PgStore>) -> Self {
        let handle = store.handle.clone();
        Self { store, handle }
    }
}

/// One open PostgreSQL transaction seen through `MetaTx`.
pub struct PgMetaTx<'a> {
    tx: &'a Transaction<'a>,
    store: &'a PgStore,
    handle: &'a tokio::runtime::Handle,
}

impl PgMetaTx<'_> {
    fn run<F: Future>(&self, f: F) -> F::Output {
        wait(self.handle, f)
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
        let tx = wait(&handle, store.begin(&mut client)).map_err(|_| MetaError)?;
        if write {
            wait(
                &handle,
                tx.execute("SELECT pg_advisory_xact_lock($1)", &[&META_LOCK]),
            )
            .map_err(|_| MetaError)?;
        }
        let out = {
            let view = PgMetaTx {
                tx: &tx,
                store: &store,
                handle: &handle,
            };
            f(&view)?
        };
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
