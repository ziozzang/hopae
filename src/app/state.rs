//! Small facts kept in the `meta` table that belong to the process, not to a
//! request: when the caller-key overlap began and the digest of the last
//! configuration. Operator-level writes in a meta transaction; never used on
//! a request path.

use std::path::Path;

use rusqlite::{Connection, OpenFlags};

use crate::store::meta::{MetaError, MetaTx};

pub const CALLER_KEY_NEXT_SINCE: &str = "caller_key_next_since";
pub const CONFIG_DIGEST: &str = "config_digest";

/// Read one `meta` value from a database file without modifying it; `None`
/// when the file, the table or the key is missing.
pub fn read_meta(path: &Path, key: &str) -> Option<String> {
    let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY).ok()?;
    get(&conn, key)
}

pub fn get(db: &dyn MetaTx, key: &str) -> Option<String> {
    db.get(key).ok().flatten()
}

pub fn set(db: &dyn MetaTx, key: &str, value: &str) -> Result<(), MetaError> {
    db.put(key, value)
}

/// Note when `caller_key_next_env` was first seen configured; forget it when it is not.
pub fn track_caller_key_next(
    db: &dyn MetaTx,
    configured: bool,
    now_secs: i64,
) -> Result<(), MetaError> {
    if configured {
        db.insert_if_absent(CALLER_KEY_NEXT_SINCE, &now_secs.to_string())?;
    } else {
        db.delete(CALLER_KEY_NEXT_SINCE)?;
    }
    Ok(())
}

/// Record the configuration digest; true when it differs from the stored one.
pub fn config_changed(db: &dyn MetaTx, digest: &str) -> Result<bool, MetaError> {
    let changed = db.get(CONFIG_DIGEST)?.as_deref() != Some(digest);
    if changed {
        set(db, CONFIG_DIGEST, digest)?;
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
