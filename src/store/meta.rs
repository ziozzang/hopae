//! The `meta` key/value state of the native owners (receipt keys and replay,
//! profile and projection publication, process facts), behind one
//! backend-neutral interface (ADR-0020 slice 5).
//!
//! The owners are synchronous and transactional: a write runs as one
//! exclusive transaction (SQLite `BEGIN IMMEDIATE`; PostgreSQL a
//! transaction holding one advisory lock that every owner write takes), so
//! read-check-write sequences and their actor guards keep the exact
//! serialization the single SQLite writer gave them, across replicas.
//! PostgreSQL calls block the calling thread: owners run on blocking threads
//! (`spawn_blocking`) or inside `block_in_place`.
use std::cell::Cell;

use rusqlite::{Connection, OptionalExtension};

/// A storage failure inside a meta transaction (no detail: owners fail closed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetaError;

impl std::error::Error for MetaError {}

impl std::fmt::Display for MetaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("meta storage failure")
    }
}

/// One open transaction (or snapshot) over `meta`.
pub trait MetaTx {
    fn get(&self, key: &str) -> Result<Option<String>, MetaError>;
    /// Insert or overwrite.
    fn put(&self, key: &str, value: &str) -> Result<(), MetaError>;
    /// Insert a key that must not exist (an existing key is a failure).
    fn insert(&self, key: &str, value: &str) -> Result<(), MetaError>;
    /// Insert unless present; true when inserted.
    fn insert_if_absent(&self, key: &str, value: &str) -> Result<bool, MetaError>;
    fn delete(&self, key: &str) -> Result<(), MetaError>;
    /// Keys in `[from, to)` in byte order, at most `limit`.
    fn range(&self, from: &str, to: &str, limit: usize)
    -> Result<Vec<(String, String)>, MetaError>;
    fn count(&self, from: &str, to: &str) -> Result<u64, MetaError>;
    /// Whether `key` holds exactly `expected` (false when absent), compared
    /// in the database without copying the stored value out.
    fn value_equals(&self, key: &str, expected: &str) -> Result<bool, MetaError>;
    /// The SQLite connection behind this transaction (its native fences).
    fn sqlite(&self) -> Option<&Connection> {
        None
    }
    /// The PostgreSQL transaction behind this one (its native fences).
    #[cfg(feature = "postgres")]
    fn postgres(&self) -> Option<&super::postgres::meta::PgMetaTx<'_>> {
        None
    }
}

/// A store connection that can open meta transactions.
pub trait MetaDb {
    /// A consistent read without the write lock.
    fn meta_read<T, E: From<MetaError>>(
        &mut self,
        f: impl FnOnce(&dyn MetaTx) -> Result<T, E>,
    ) -> Result<T, E>;
    /// One exclusive write transaction, committed when `f` returns `Ok`.
    /// `attempted` is set immediately before `COMMIT`: after a failure with
    /// it unset, nothing was written.
    fn meta_write<T, E: From<MetaError>>(
        &mut self,
        attempted: &Cell<bool>,
        f: impl FnOnce(&dyn MetaTx) -> Result<T, E>,
    ) -> Result<T, E>;
}

fn sq<T>(r: rusqlite::Result<T>) -> Result<T, MetaError> {
    r.map_err(|_| MetaError)
}

impl MetaTx for Connection {
    fn get(&self, key: &str) -> Result<Option<String>, MetaError> {
        sq(self
            .prepare_cached("SELECT value FROM meta WHERE key=?1")
            .and_then(|mut s| s.query_row([key], |r| r.get(0)).optional()))
    }
    fn put(&self, key: &str, value: &str) -> Result<(), MetaError> {
        sq(self.execute(
            "INSERT INTO meta(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            [key, value],
        ))
        .map(|_| ())
    }
    fn insert(&self, key: &str, value: &str) -> Result<(), MetaError> {
        sq(self.execute("INSERT INTO meta(key,value) VALUES(?1,?2)", [key, value])).map(|_| ())
    }
    fn insert_if_absent(&self, key: &str, value: &str) -> Result<bool, MetaError> {
        sq(self.execute(
            "INSERT OR IGNORE INTO meta(key,value) VALUES(?1,?2)",
            [key, value],
        ))
        .map(|n| n == 1)
    }
    fn delete(&self, key: &str) -> Result<(), MetaError> {
        sq(self.execute("DELETE FROM meta WHERE key=?1", [key])).map(|_| ())
    }
    fn range(
        &self,
        from: &str,
        to: &str,
        limit: usize,
    ) -> Result<Vec<(String, String)>, MetaError> {
        let mut st = sq(self.prepare_cached(
            "SELECT key,value FROM meta WHERE key>=?1 AND key<?2 ORDER BY key LIMIT ?3",
        ))?;
        let rows = sq(
            st.query_map(rusqlite::params![from, to, limit as i64], |r| {
                Ok((r.get(0)?, r.get(1)?))
            }),
        )?;
        sq(rows.collect())
    }
    fn count(&self, from: &str, to: &str) -> Result<u64, MetaError> {
        sq(self.query_row(
            "SELECT count(*) FROM meta WHERE key>=?1 AND key<?2",
            [from, to],
            |r| r.get(0),
        ))
    }
    fn value_equals(&self, key: &str, expected: &str) -> Result<bool, MetaError> {
        // Borrow SQLite's row bytes: no copy of the stored document.
        sq(self
            .prepare_cached("SELECT value FROM meta WHERE key=?1")
            .and_then(|mut s| {
                s.query_row([key], |r| Ok(r.get_ref(0)?.as_str()? == expected))
                    .optional()
            }))
        .map(|v| v.unwrap_or(false))
    }
    fn sqlite(&self) -> Option<&Connection> {
        Some(self)
    }
}

impl MetaTx for rusqlite::Transaction<'_> {
    fn get(&self, key: &str) -> Result<Option<String>, MetaError> {
        (**self).get(key)
    }
    fn put(&self, key: &str, value: &str) -> Result<(), MetaError> {
        (**self).put(key, value)
    }
    fn insert(&self, key: &str, value: &str) -> Result<(), MetaError> {
        (**self).insert(key, value)
    }
    fn insert_if_absent(&self, key: &str, value: &str) -> Result<bool, MetaError> {
        (**self).insert_if_absent(key, value)
    }
    fn delete(&self, key: &str) -> Result<(), MetaError> {
        MetaTx::delete(&**self, key)
    }
    fn range(
        &self,
        from: &str,
        to: &str,
        limit: usize,
    ) -> Result<Vec<(String, String)>, MetaError> {
        (**self).range(from, to, limit)
    }
    fn count(&self, from: &str, to: &str) -> Result<u64, MetaError> {
        (**self).count(from, to)
    }
    fn value_equals(&self, key: &str, expected: &str) -> Result<bool, MetaError> {
        (**self).value_equals(key, expected)
    }
    fn sqlite(&self) -> Option<&Connection> {
        Some(self)
    }
}

impl MetaDb for Connection {
    fn meta_read<T, E: From<MetaError>>(
        &mut self,
        f: impl FnOnce(&dyn MetaTx) -> Result<T, E>,
    ) -> Result<T, E> {
        let tx = self.transaction().map_err(|_| MetaError)?;
        let out = f(&*tx)?;
        tx.commit().map_err(|_| MetaError)?;
        Ok(out)
    }
    fn meta_write<T, E: From<MetaError>>(
        &mut self,
        attempted: &Cell<bool>,
        f: impl FnOnce(&dyn MetaTx) -> Result<T, E>,
    ) -> Result<T, E> {
        let tx = self
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|_| MetaError)?;
        let out = f(&*tx)?;
        attempted.set(true);
        tx.commit().map_err(|_| MetaError)?;
        Ok(out)
    }
}

impl MetaTx for std::sync::MutexGuard<'_, Connection> {
    fn get(&self, key: &str) -> Result<Option<String>, MetaError> {
        (**self).get(key)
    }
    fn put(&self, key: &str, value: &str) -> Result<(), MetaError> {
        (**self).put(key, value)
    }
    fn insert(&self, key: &str, value: &str) -> Result<(), MetaError> {
        (**self).insert(key, value)
    }
    fn insert_if_absent(&self, key: &str, value: &str) -> Result<bool, MetaError> {
        (**self).insert_if_absent(key, value)
    }
    fn delete(&self, key: &str) -> Result<(), MetaError> {
        MetaTx::delete(&**self, key)
    }
    fn range(
        &self,
        from: &str,
        to: &str,
        limit: usize,
    ) -> Result<Vec<(String, String)>, MetaError> {
        (**self).range(from, to, limit)
    }
    fn count(&self, from: &str, to: &str) -> Result<u64, MetaError> {
        (**self).count(from, to)
    }
    fn value_equals(&self, key: &str, expected: &str) -> Result<bool, MetaError> {
        (**self).value_equals(key, expected)
    }
    fn sqlite(&self) -> Option<&Connection> {
        Some(self)
    }
}

impl MetaDb for std::sync::MutexGuard<'_, Connection> {
    fn meta_read<T, E: From<MetaError>>(
        &mut self,
        f: impl FnOnce(&dyn MetaTx) -> Result<T, E>,
    ) -> Result<T, E> {
        (**self).meta_read(f)
    }
    fn meta_write<T, E: From<MetaError>>(
        &mut self,
        attempted: &Cell<bool>,
        f: impl FnOnce(&dyn MetaTx) -> Result<T, E>,
    ) -> Result<T, E> {
        (**self).meta_write(attempted, f)
    }
}

/// The meta connection of the application's store.
pub enum MetaHandle<'a> {
    Sqlite(std::sync::MutexGuard<'a, Connection>),
    #[cfg(feature = "postgres")]
    Postgres(super::postgres::meta::PgMeta),
}

impl MetaDb for MetaHandle<'_> {
    fn meta_read<T, E: From<MetaError>>(
        &mut self,
        f: impl FnOnce(&dyn MetaTx) -> Result<T, E>,
    ) -> Result<T, E> {
        match self {
            MetaHandle::Sqlite(c) => c.meta_read(f),
            #[cfg(feature = "postgres")]
            MetaHandle::Postgres(p) => p.meta_read(f),
        }
    }
    fn meta_write<T, E: From<MetaError>>(
        &mut self,
        attempted: &Cell<bool>,
        f: impl FnOnce(&dyn MetaTx) -> Result<T, E>,
    ) -> Result<T, E> {
        match self {
            MetaHandle::Sqlite(c) => c.meta_write(attempted, f),
            #[cfg(feature = "postgres")]
            MetaHandle::Postgres(p) => p.meta_write(attempted, f),
        }
    }
}

impl From<MetaError> for crate::auth_gateway::receipt_keys::Refused {
    fn from(_: MetaError) -> Self {
        crate::auth_gateway::receipt_keys::Refused
    }
}
