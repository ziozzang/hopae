//! A backup copy of the database before a migration (scenario 013-6).

use std::path::{Path, PathBuf};

use anyhow::Context;
use rusqlite::{Connection, OpenFlags};

pub use crate::store::LATEST_SCHEMA_VERSION;

/// The schema version recorded in an existing database file, 0 when it has none.
pub fn recorded_version(path: &Path) -> anyhow::Result<u32> {
    let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .with_context(|| format!("opening {}", path.display()))?;
    let has_table: i64 = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='schema_migrations'",
        [],
        |r| r.get(0),
    )?;
    if has_table == 0 {
        return Ok(0);
    }
    let v: Option<u32> = conn.query_row("SELECT MAX(version) FROM schema_migrations", [], |r| {
        r.get(0)
    })?;
    Ok(v.unwrap_or(0))
}

/// When `path` holds a database older than `latest`, write a consistent copy
/// next to it as `<file>.bak-v<N>` (mode 0600) and return its path. Nothing
/// is written for a missing, empty, fresh (version 0) or current database.
pub fn backup_before_migration(path: &Path, latest: u32) -> anyhow::Result<Option<PathBuf>> {
    let Ok(meta) = std::fs::metadata(path) else {
        return Ok(None);
    };
    if meta.len() == 0 {
        return Ok(None);
    }
    let found = recorded_version(path)?;
    if found == 0 || found >= latest {
        return Ok(None);
    }
    let mut name = path
        .file_name()
        .context("database path has no file name")?
        .to_os_string();
    name.push(format!(".bak-v{found}"));
    let target = path.with_file_name(name);
    if target.exists() {
        std::fs::remove_file(&target).with_context(|| format!("replacing {}", target.display()))?;
    }
    let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    // VACUUM INTO writes a transactionally consistent copy, WAL content included.
    let quoted = target.to_string_lossy().replace('\'', "''");
    conn.execute_batch(&format!("VACUUM INTO '{quoted}'"))
        .with_context(|| format!("writing backup {}", target.display()))?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600))?;
    Ok(Some(target))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SystemClock;
    use crate::store::Store;
    use std::sync::Arc;

    #[test]
    fn latest_schema_version_matches_the_store() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(
            &dir.path().join("t.db"),
            Arc::new(SystemClock),
            vec![],
            None,
        )
        .unwrap();
        assert_eq!(store.schema_version().unwrap(), LATEST_SCHEMA_VERSION);
    }

    #[test]
    fn backs_up_only_older_databases() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("h.db");
        assert!(
            backup_before_migration(&db, 2).unwrap().is_none(),
            "missing file"
        );
        {
            let c = Connection::open(&db).unwrap();
            c.execute_batch(
                "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY NOT NULL, name TEXT NOT NULL, applied_at INTEGER NOT NULL) STRICT;
                 INSERT INTO schema_migrations VALUES (1, 'x', 0);
                 CREATE TABLE marker (v TEXT);
                 INSERT INTO marker VALUES ('kept');",
            )
            .unwrap();
        }
        let bak = backup_before_migration(&db, 2).unwrap().expect("backup");
        assert_eq!(bak.file_name().unwrap(), "h.db.bak-v1");
        let c = Connection::open(&bak).unwrap();
        let v: String = c
            .query_row("SELECT v FROM marker", [], |r| r.get(0))
            .unwrap();
        assert_eq!(v, "kept");
        assert!(
            backup_before_migration(&db, 1).unwrap().is_none(),
            "already current"
        );
    }
}
