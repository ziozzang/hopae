//! Small facts kept in the `meta` table that belong to the process, not to a
//! request: when the caller-key overlap began and the digest of the last
//! configuration. Operator-level SQL on the store's utility connection; never
//! used on a request path.

use std::path::Path;

use rusqlite::{Connection, OpenFlags, OptionalExtension};

pub const CALLER_KEY_NEXT_SINCE: &str = "caller_key_next_since";
pub const CONFIG_DIGEST: &str = "config_digest";

/// Read one `meta` value from a database file without modifying it; `None`
/// when the file, the table or the key is missing.
pub fn read_meta(path: &Path, key: &str) -> Option<String> {
    let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY).ok()?;
    get(&conn, key)
}

pub fn get(conn: &Connection, key: &str) -> Option<String> {
    conn.query_row("SELECT value FROM meta WHERE key=?1", [key], |r| r.get(0))
        .optional()
        .ok()
        .flatten()
}

pub fn set(conn: &Connection, key: &str, value: &str) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO meta (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        [key, value],
    )?;
    Ok(())
}

/// Note when `caller_key_next_env` was first seen configured; forget it when it is not.
pub fn track_caller_key_next(
    conn: &Connection,
    configured: bool,
    now_secs: i64,
) -> rusqlite::Result<()> {
    if configured {
        conn.execute(
            "INSERT OR IGNORE INTO meta (key, value) VALUES (?1, ?2)",
            [CALLER_KEY_NEXT_SINCE, &now_secs.to_string()],
        )?;
    } else {
        conn.execute("DELETE FROM meta WHERE key=?1", [CALLER_KEY_NEXT_SINCE])?;
    }
    Ok(())
}

/// Record the configuration digest; true when it differs from the stored one.
pub fn config_changed(conn: &Connection, digest: &str) -> rusqlite::Result<bool> {
    let changed = get(conn, CONFIG_DIGEST).as_deref() != Some(digest);
    if changed {
        set(conn, CONFIG_DIGEST, digest)?;
    }
    Ok(changed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(
            "CREATE TABLE meta (key TEXT PRIMARY KEY NOT NULL, value TEXT NOT NULL) STRICT;",
        )
        .unwrap();
        c
    }

    #[test]
    fn overlap_start_is_recorded_once_and_forgotten_when_unconfigured() {
        let c = db();
        track_caller_key_next(&c, true, 100).unwrap();
        track_caller_key_next(&c, true, 900).unwrap();
        assert_eq!(get(&c, CALLER_KEY_NEXT_SINCE).as_deref(), Some("100"));
        track_caller_key_next(&c, false, 1000).unwrap();
        assert_eq!(get(&c, CALLER_KEY_NEXT_SINCE), None);
    }

    #[test]
    fn config_digest_change_detection() {
        let c = db();
        assert!(config_changed(&c, "a").unwrap());
        assert!(!config_changed(&c, "a").unwrap());
        assert!(config_changed(&c, "b").unwrap());
    }
}
