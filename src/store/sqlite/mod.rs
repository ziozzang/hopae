//! SQLite backend: open with WAL, busy timeout and foreign keys, then apply
//! embedded, versioned migrations.

use std::fs::OpenOptions;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

use rusqlite::Connection;

/// Embedded migrations in order. The version is the position + 1 and must
/// match the numeric prefix of the file name.
const MIGRATIONS: &[(u32, &str, &str)] =
    &[(1, "0001_meta", include_str!("../migrations/0001_meta.sql"))];

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("store I/O error at {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
    #[error("store error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("database schema version {found} is newer than this binary supports ({supported})")]
    SchemaTooNew { found: u32, supported: u32 },
}

pub struct Store {
    conn: Connection,
}

impl Store {
    /// Create the parent directory (0700 when newly created) and the database
    /// file (0600), open it and run pending migrations.
    pub fn open(path: &Path) -> Result<Self, StoreError> {
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
        let conn = Connection::open(path)?;
        configure(&conn)?;
        migrate(&conn)?;
        Ok(Self { conn })
    }

    /// Borrow the connection (tests and the future store implementation).
    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    /// Highest applied migration version.
    pub fn schema_version(&self) -> Result<u32, StoreError> {
        current_version(&self.conn)
    }
}

fn configure(conn: &Connection) -> Result<(), StoreError> {
    conn.busy_timeout(std::time::Duration::from_millis(5000))?;
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
    current_version(conn)
}
