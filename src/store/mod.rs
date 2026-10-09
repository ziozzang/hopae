//! Storage. `Directory`, `Sessions` and `Events` traits arrive in M1; in M0
//! only the SQLite connection, pragmas, file permissions and the migration
//! runner exist. PostgreSQL is M2.

pub mod sqlite;

pub use sqlite::Store;
