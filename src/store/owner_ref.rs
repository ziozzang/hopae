//! Which open store a prepared native owner value belongs to: values read
//! from one store are never accepted by another, even with identical rows.
use std::sync::{Arc, Weak};

#[derive(Clone)]
pub(crate) enum OwnerRef {
    Sqlite(Weak<super::sqlite::Inner>),
    #[cfg(feature = "postgres")]
    Postgres(Weak<super::postgres::PgStore>),
}

impl OwnerRef {
    pub(crate) fn sqlite(inner: &Arc<super::sqlite::Inner>) -> Self {
        OwnerRef::Sqlite(Arc::downgrade(inner))
    }
    #[cfg(feature = "postgres")]
    pub(crate) fn postgres(store: &Arc<super::postgres::PgStore>) -> Self {
        OwnerRef::Postgres(Arc::downgrade(store))
    }
    pub(crate) fn is_sqlite(&self, inner: &Arc<super::sqlite::Inner>) -> bool {
        matches!(self, OwnerRef::Sqlite(w) if Weak::ptr_eq(w, &Arc::downgrade(inner)))
    }
    #[cfg(feature = "postgres")]
    pub(crate) fn is_postgres(&self, store: &Arc<super::postgres::PgStore>) -> bool {
        matches!(self, OwnerRef::Postgres(w) if Weak::ptr_eq(w, &Arc::downgrade(store)))
    }
    /// Whether this names `store` (by identity, without its `Arc`).
    #[cfg(feature = "postgres")]
    pub(crate) fn is_postgres_store(&self, store: &super::postgres::PgStore) -> bool {
        matches!(self, OwnerRef::Postgres(w) if std::ptr::eq(w.as_ptr(), store))
    }
    pub(crate) fn same(&self, other: &Self) -> bool {
        match (self, other) {
            (OwnerRef::Sqlite(a), OwnerRef::Sqlite(b)) => Weak::ptr_eq(a, b),
            #[cfg(feature = "postgres")]
            (OwnerRef::Postgres(a), OwnerRef::Postgres(b)) => Weak::ptr_eq(a, b),
            #[allow(unreachable_patterns)]
            _ => false,
        }
    }
}
