//! Reference-only DB owner and immutable projection readers. Management handlers
//! must supply authenticated actor authorization; this is not an HTTP API.
use super::{
    projection::{Configuration, Output, Projector},
    projection_admission::Admission,
    receipt_keys::Refused,
};
use arc_swap::ArcSwap;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::sync::Arc;
use zeroize::Zeroizing;
const KEY: &str = "projection_plan_authority_v1";
const LIMIT: usize = 128 * 1024;
const MAX_REVISION: u64 = 9_007_199_254_740_991;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Document {
    pub revision: u64,
    pub digest: String,
    pub configuration: Option<Configuration>,
}
fn encoded(config: &Option<Configuration>) -> Result<Vec<u8>, Refused> {
    let bytes = serde_json::to_vec(config).map_err(|_| Refused)?;
    if bytes.len() > LIMIT {
        return Err(Refused);
    }
    Ok(bytes)
}
pub fn read(db: &Connection) -> Result<Option<Document>, Refused> {
    Ok(read_encoded(db)?.map(|(document, _)| document))
}
fn read_encoded(db: &Connection) -> Result<Option<(Document, String)>, Refused> {
    let bytes: Option<String> = db
        .query_row("SELECT value FROM meta WHERE key=?1", [KEY], |r| r.get(0))
        .optional()
        .map_err(|_| Refused)?;
    bytes
        .map(|bytes| {
            if bytes.len() > LIMIT + 1024 {
                return Err(Refused);
            }
            let document: Document = serde_json::from_str(&bytes).map_err(|_| Refused)?;
            if !(1..=MAX_REVISION).contains(&document.revision)
                || document.digest
                    != format!("{:x}", Sha256::digest(encoded(&document.configuration)?))
            {
                return Err(Refused);
            }
            if let Some(config) = &document.configuration {
                if config.revision != document.revision {
                    return Err(Refused);
                }
                Projector::compile(config.clone())?;
            }
            Ok((document, bytes))
        })
        .transpose()
}
pub struct Snapshot {
    revision: u64,
    document: Option<String>,
    projector: Option<Projector>,
}
impl Snapshot {
    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub fn enabled(&self) -> bool {
        self.projector.is_some()
    }
    /// The captured reader cannot issue after a durable update/tombstone, even in
    /// the DB-commit/snapshot-install interval. External guard rechecks live owners.
    pub fn project(
        &self,
        admission: Admission,
        db: &mut Connection,
        clock: &dyn Fn() -> u64,
        guard: &dyn Fn(&Connection) -> Result<(), Refused>,
        resolve: &dyn Fn(&str) -> Result<Zeroizing<String>, Refused>,
    ) -> Result<Output, Refused> {
        let projector = self.projector.as_ref().ok_or(Refused)?;
        projector.project(
            admission,
            db,
            clock,
            &|db| {
                guard(db)?;
                let expected = self.document.as_deref().ok_or(Refused)?;
                // Borrow SQLite's row bytes: no JSON decoding, plan compilation
                // or temporary document allocation on the request path.
                let unchanged = db
                    .prepare_cached("SELECT value FROM meta WHERE key=?1")
                    .map_err(|_| Refused)?
                    .query_row([KEY], |row| Ok(row.get_ref(0)?.as_str()? == expected))
                    .optional()
                    .map_err(|_| Refused)?
                    .unwrap_or(false);
                if !unchanged {
                    return Err(Refused);
                }
                Ok(())
            },
            resolve,
        )
    }
}
pub struct Authority {
    snapshot: Arc<ArcSwap<Snapshot>>,
}
impl Authority {
    /// No bootstrap overwrite. An absent DB row is disabled revision zero, unless
    /// an external minimum requires a prior publication to exist.
    pub fn load(db: &Connection, minimum_revision: u64) -> Result<Self, Refused> {
        let (document, encoded_document) = match read_encoded(db)? {
            Some((document, bytes)) => (Some(document), Some(bytes)),
            None => (None, None),
        };
        let revision = document.as_ref().map_or(0, |d| d.revision);
        if revision < minimum_revision {
            return Err(Refused);
        }
        let projector = document
            .as_ref()
            .and_then(|d| d.configuration.as_ref())
            .map(|c| Projector::compile(c.clone()))
            .transpose()?;
        Ok(Self {
            snapshot: Arc::new(ArcSwap::from_pointee(Snapshot {
                revision,
                document: encoded_document,
                projector,
            })),
        })
    }
    pub fn reader(&self) -> Arc<ArcSwap<Snapshot>> {
        self.snapshot.clone()
    }
    /// Exclusive native owner must remain the sole publisher. Desired revision
    /// must equal expected+1; None creates a durable disabled tombstone.
    pub fn publish(
        &mut self,
        db: &mut Connection,
        expected: u64,
        desired: Option<Configuration>,
        actor: &str,
        guard: &dyn Fn(&Connection) -> Result<(), Refused>,
    ) -> Result<Document, Refused> {
        if actor.is_empty()
            || actor.len() > 128
            || actor.chars().any(char::is_control)
            || self.snapshot.load().revision != expected
        {
            return Err(Refused);
        }
        let revision = expected
            .checked_add(1)
            .filter(|r| *r <= MAX_REVISION)
            .ok_or(Refused)?;
        if desired.as_ref().is_some_and(|d| d.revision != revision) {
            return Err(Refused);
        }
        let projector = desired
            .as_ref()
            .map(|d| Projector::compile(d.clone()))
            .transpose()?;
        let document = Document {
            revision,
            digest: format!("{:x}", Sha256::digest(encoded(&desired)?)),
            configuration: desired,
        };
        let value = serde_json::to_string(&document).map_err(|_| Refused)?;
        // Prepare all allocations before successful commit and live installation.
        let prepared = Arc::new(Snapshot {
            revision,
            document: Some(value.clone()),
            projector,
        });
        let audit = serde_json::json!({"revision": revision,"actor": actor,"digest": document.digest,"disabled": document.configuration.is_none()}).to_string();
        let tx = db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| Refused)?;
        guard(&tx)?;
        if read(&tx)?.as_ref().map_or(0, |d| d.revision) != expected {
            return Err(Refused);
        }
        tx.execute("INSERT INTO meta(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value", rusqlite::params![KEY,value]).map_err(|_| Refused)?;
        tx.execute(
            "INSERT INTO meta(key,value) VALUES(?1,?2)",
            rusqlite::params![
                format!("projection_plan_publication_audit:{revision}"),
                audit
            ],
        )
        .map_err(|_| Refused)?;
        guard(&tx)?;
        let final_value: String = tx
            .query_row("SELECT value FROM meta WHERE key=?1", [KEY], |r| r.get(0))
            .map_err(|_| Refused)?;
        if final_value != value {
            return Err(Refused);
        }
        tx.commit().map_err(|_| Refused)?;
        self.snapshot.store(prepared);
        Ok(document)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth_gateway::projection::{Credential, Plan};
    fn config(revision: u64) -> Configuration {
        Configuration {
            revision,
            plans: vec![Plan {
                service: "orders".into(),
                audience: "orders-api".into(),
                resource: "orders".into(),
                action: "read".into(),
                minimum_aal: 2,
                credential: Credential::BearerReference {
                    secret_ref: "vault:owned-token".into(),
                },
            }],
        }
    }
    #[test]
    fn restart_keeps_tombstone_floor_and_rejects_stale_owner_publication() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let mut db = Connection::open(file.path()).unwrap();
        db.execute_batch("CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT NOT NULL)")
            .unwrap();
        assert!(Authority::load(&db, 1).is_err());
        let mut owner = Authority::load(&db, 0).unwrap();
        let reader = owner.reader();
        let mut stale_owner = Authority::load(&db, 0).unwrap();
        owner
            .publish(&mut db, 0, Some(config(1)), "operator", &|_| Ok(()))
            .unwrap();
        assert!(reader.load().enabled());
        assert_eq!(reader.load().revision(), 1);
        assert!(
            stale_owner
                .publish(&mut db, 0, Some(config(1)), "operator", &|_| Ok(()))
                .is_err()
        );
        assert_eq!(stale_owner.reader().load().revision(), 0);
        owner
            .publish(&mut db, 1, None, "operator", &|_| Ok(()))
            .unwrap();
        drop(db);
        let db = Connection::open(file.path()).unwrap();
        let restarted = Authority::load(&db, 2).unwrap();
        assert_eq!(restarted.reader().load().revision(), 2);
        assert!(!restarted.reader().load().enabled());
        assert!(read(&db).unwrap().unwrap().configuration.is_none());
        assert!(Authority::load(&db, 3).is_err());
    }
    #[test]
    fn late_actor_revocation_and_audit_failure_leave_db_and_snapshot_unchanged() {
        let mut db = Connection::open_in_memory().unwrap();
        db.execute_batch("CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT NOT NULL)")
            .unwrap();
        let mut owner = Authority::load(&db, 0).unwrap();
        let reader = owner.reader();
        let before = reader.load_full();
        let calls = std::cell::Cell::new(0);
        assert!(
            owner
                .publish(&mut db, 0, Some(config(1)), "operator", &|_| {
                    calls.set(calls.get() + 1);
                    if calls.get() == 2 {
                        Err(Refused)
                    } else {
                        Ok(())
                    }
                })
                .is_err()
        );
        assert!(read(&db).unwrap().is_none());
        assert!(Arc::ptr_eq(&before, &reader.load_full()));
        db.execute(
            "INSERT INTO meta(key,value) VALUES('projection_plan_publication_audit:1','occupied')",
            [],
        )
        .unwrap();
        assert!(
            owner
                .publish(&mut db, 0, Some(config(1)), "operator", &|_| Ok(()))
                .is_err()
        );
        assert!(read(&db).unwrap().is_none());
        assert!(Arc::ptr_eq(&before, &reader.load_full()));
        db.execute("DELETE FROM meta", []).unwrap();
        owner
            .publish(&mut db, 0, Some(config(1)), "operator", &|_| Ok(()))
            .unwrap();
        assert_eq!(reader.load().revision(), 1);
    }
    #[test]
    fn corrupt_state_and_final_guard_mutation_fail_closed() {
        let mut db = Connection::open_in_memory().unwrap();
        db.execute_batch("CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT NOT NULL)")
            .unwrap();
        let mut owner = Authority::load(&db, 0).unwrap();
        assert!(
            owner
                .publish(&mut db, 0, Some(config(2)), "operator", &|_| Ok(()))
                .is_err()
        );
        let calls = std::cell::Cell::new(0);
        assert!(
            owner
                .publish(&mut db, 0, Some(config(1)), "operator", &|db| {
                    calls.set(calls.get() + 1);
                    if calls.get() == 2 {
                        db.execute("UPDATE meta SET value='null' WHERE key=?1", [KEY])
                            .map_err(|_| Refused)?;
                    }
                    Ok(())
                })
                .is_err()
        );
        assert!(read(&db).unwrap().is_none());
        assert_eq!(owner.reader().load().revision(), 0);
        owner
            .publish(&mut db, 0, Some(config(1)), "operator", &|_| Ok(()))
            .unwrap();
        let mut forged = read(&db).unwrap().unwrap();
        forged.configuration.as_mut().unwrap().revision = 2;
        forged.digest = format!(
            "{:x}",
            Sha256::digest(encoded(&forged.configuration).unwrap())
        );
        db.execute(
            "UPDATE meta SET value=?1 WHERE key=?2",
            rusqlite::params![serde_json::to_string(&forged).unwrap(), KEY],
        )
        .unwrap();
        assert!(Authority::load(&db, 1).is_err());
        assert!(
            owner
                .publish(&mut db, 1, None, "operator", &|_| Ok(()))
                .is_err()
        );
        assert_eq!(owner.reader().load().revision(), 1);
    }
}
