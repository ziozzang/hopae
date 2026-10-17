//! Durable public-key history only. Owner must authenticate the caller and
//! install the returned immutable registry after a successful transaction.
use super::receipt_keys::{Key, Refused, Registry};
use crate::store::meta::{MetaDb, MetaTx};
use sha2::{Digest as _, Sha256};
const KEY: &str = "projection_receipt_registry_v1";
pub fn load(db: &dyn MetaTx, minimum_revision: u64) -> Result<Option<Registry>, Refused> {
    let value = db.get(KEY).map_err(|_| Refused)?;
    match value {
        Some(value) => Registry::decode(&value, minimum_revision).map(Some),
        None if minimum_revision == 0 => Ok(None),
        None => Err(Refused),
    }
}
pub fn publish<D: MetaDb>(
    db: &mut D,
    expected: u64,
    desired: &[Key],
    actor: &str,
    guard: &dyn Fn(&dyn MetaTx) -> Result<(), Refused>,
) -> Result<std::sync::Arc<Registry>, Refused> {
    publish_with_commit_state(
        db,
        expected,
        desired,
        actor,
        guard,
        &std::cell::Cell::new(false),
    )
}
pub(crate) fn publish_with_commit_state<D: MetaDb>(
    db: &mut D,
    expected: u64,
    desired: &[Key],
    actor: &str,
    guard: &dyn Fn(&dyn MetaTx) -> Result<(), Refused>,
    commit_attempted: &std::cell::Cell<bool>,
) -> Result<std::sync::Arc<Registry>, Refused> {
    if actor.is_empty() || actor.len() > 128 || actor.chars().any(char::is_control) {
        return Err(Refused);
    }
    db.meta_write(commit_attempted, |tx| {
        guard(tx)?;
        let previous = load(tx, expected)?;
        if previous.as_ref().map_or(0, Registry::revision) != expected {
            return Err(Refused);
        }
        let next = Registry::compile(expected.checked_add(1).ok_or(Refused)?, desired, previous.as_ref())?;
        let encoded = next.encode()?;
        tx.put(KEY, &encoded).map_err(|_| Refused)?;
        let audit_key = format!("projection_receipt_registry_audit:{}", next.revision());
        let audit = serde_json::json!({"revision":next.revision(),"actor":actor,"digest":format!("{:x}",Sha256::digest(encoded.as_bytes()))}).to_string();
        tx.insert(&audit_key, &audit).map_err(|_| Refused)?;
        guard(tx)?;
        let final_value = tx.get(KEY).map_err(|_| Refused)?;
        let final_audit = tx.get(&audit_key).map_err(|_| Refused)?;
        if final_value.as_deref() != Some(encoded.as_str()) || final_audit.as_deref() != Some(audit.as_str()) {
            return Err(Refused);
        }
        Ok(std::sync::Arc::new(next))
    })
}
#[cfg(test)]
mod tests {
    use super::super::receipt::Purpose;
    use super::*;
    use rusqlite::Connection;
    fn key(epoch: u64) -> Key {
        Key {
            issuer_ref: "owned".into(),
            purpose: Purpose::Authentication,
            epoch,
            public_key: ed25519_dalek::SigningKey::from_bytes(&[7; 32])
                .verifying_key()
                .to_bytes(),
        }
    }
    #[test]
    fn restart_retains_removal_and_minimum_revision() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let mut db = Connection::open(file.path()).unwrap();
        db.execute_batch("CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT NOT NULL)")
            .unwrap();
        publish(&mut db, 0, &[key(1)], "operator", &|_| Ok(())).unwrap();
        publish(&mut db, 1, &[], "operator", &|_| Ok(())).unwrap();
        drop(db);
        let mut db = Connection::open(file.path()).unwrap();
        assert_eq!(load(&db, 2).unwrap().unwrap().revision(), 2);
        assert!(load(&db, 3).is_err());
        assert!(publish(&mut db, 2, &[key(1)], "operator", &|_| Ok(())).is_err());
        assert!(publish(&mut db, 1, &[key(2)], "operator", &|_| Ok(())).is_err());
        assert!(
            publish(&mut db, 2, &[key(2)], "operator", &|_| Ok(())).is_err(),
            "retired public material cannot return at a larger epoch"
        );
        let mut replacement = key(2);
        replacement.public_key = ed25519_dalek::SigningKey::from_bytes(&[8; 32])
            .verifying_key()
            .to_bytes();
        assert_eq!(
            publish(&mut db, 2, &[replacement], "operator", &|_| Ok(()))
                .unwrap()
                .revision(),
            3
        );
    }
    #[test]
    fn late_actor_revocation_rolls_back_registry_and_audit() {
        let mut db = Connection::open_in_memory().unwrap();
        db.execute_batch("CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT NOT NULL)")
            .unwrap();
        let checks = std::cell::Cell::new(0);
        assert!(
            publish(&mut db, 0, &[key(1)], "operator", &|_| {
                checks.set(checks.get() + 1);
                if checks.get() == 2 {
                    Err(Refused)
                } else {
                    Ok(())
                }
            })
            .is_err()
        );
        assert!(load(&db, 0).unwrap().is_none());
        assert_eq!(
            db.query_row("SELECT count(*) FROM meta", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert!(load(&db, 1).is_err());
    }

    #[test]
    fn malformed_snapshot_and_failed_audit_never_install_state() {
        let mut db = Connection::open_in_memory().unwrap();
        db.execute_batch("CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT NOT NULL)")
            .unwrap();
        let registry = publish(&mut db, 0, &[key(1)], "operator", &|_| Ok(())).unwrap();
        let good = registry.encode().unwrap();
        for mutate in [
            |v: &mut serde_json::Value| v["owners"] = serde_json::json!([]),
            |v: &mut serde_json::Value| v["version"] = serde_json::json!(2),
            |v: &mut serde_json::Value| v["floors"][0]["epoch"] = serde_json::json!(0),
        ] {
            let mut bad: serde_json::Value = serde_json::from_str(&good).unwrap();
            mutate(&mut bad);
            db.execute(
                "UPDATE meta SET value=?1 WHERE key=?2",
                rusqlite::params![bad.to_string(), KEY],
            )
            .unwrap();
            assert!(load(&db, 1).is_err());
        }
        db.execute(
            "UPDATE meta SET value=?1 WHERE key=?2",
            rusqlite::params![good, KEY],
        )
        .unwrap();
        db.execute(
            "INSERT INTO meta(key,value) VALUES('projection_receipt_registry_audit:2','injected')",
            [],
        )
        .unwrap();
        assert!(publish(&mut db, 1, &[], "operator", &|_| Ok(())).is_err());
        assert_eq!(
            load(&db, 1).unwrap().unwrap().encode().unwrap(),
            registry.encode().unwrap()
        );
    }
}
