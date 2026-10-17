//! Durable reference-only profile state. The caller owns compilation and runtime installation.
use super::runtime::Config;
use crate::store::meta::{MetaDb, MetaError, MetaTx};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const KEY: &str = "authentication_profile_authority_v1";
const LIMIT: usize = 262_144;
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Document {
    pub revision: u64,
    pub digest: String,
    pub configuration: Option<Config>,
}
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("authentication profile revision conflict")]
    Conflict,
    #[error("invalid authentication profile document")]
    Invalid,
    #[error("authentication profile actor revoked")]
    Denied,
    #[error("authentication profile storage failure")]
    Storage,
}
fn encoded(configuration: &Option<Config>) -> Result<Vec<u8>, Error> {
    if let Some(config) = configuration {
        config.validate().map_err(|_| Error::Invalid)?;
    }
    let bytes = serde_json::to_vec(configuration).map_err(|_| Error::Invalid)?;
    if bytes.len() > LIMIT {
        return Err(Error::Invalid);
    }
    Ok(bytes)
}
fn decode(value: &str) -> Result<Document, Error> {
    if value.len() > LIMIT + 1024 {
        return Err(Error::Invalid);
    }
    let document: Document = serde_json::from_str(value).map_err(|_| Error::Invalid)?;
    if document.revision == 0
        || document.revision > i64::MAX as u64
        || document.digest != format!("{:x}", Sha256::digest(encoded(&document.configuration)?))
    {
        return Err(Error::Invalid);
    }
    Ok(document)
}
impl From<MetaError> for Error {
    fn from(_: MetaError) -> Self {
        Error::Storage
    }
}
pub fn read(db: &dyn MetaTx) -> Result<Option<Document>, Error> {
    let value = db.get(KEY)?;
    value.as_deref().map(decode).transpose()
}
/// Persist authority and reference-only audit in one transaction; None is a durable tombstone.
/// Must run in the serialized publication worker after complete runtime compilation.
pub fn publish<D: MetaDb>(
    connection: &mut D,
    expected: u64,
    configuration: Option<Config>,
    actor: &str,
) -> Result<Document, Error> {
    publish_guarded(connection, expected, configuration, actor, &|_| Ok(()))
}
/// Recheck the authenticated actor inside the same transaction as authority and audit writes.
pub fn publish_guarded<D: MetaDb>(
    connection: &mut D,
    expected: u64,
    configuration: Option<Config>,
    actor: &str,
    guard: &dyn Fn(&dyn MetaTx) -> Result<(), Error>,
) -> Result<Document, Error> {
    if actor.is_empty() || actor.len() > 128 || actor.chars().any(char::is_control) {
        return Err(Error::Invalid);
    }
    let digest = format!("{:x}", Sha256::digest(encoded(&configuration)?));
    connection.meta_write(&std::cell::Cell::new(false), |tx| {
        guard(tx)?;
        let previous = read(tx)?;
        if previous.as_ref().map_or(0, |d| d.revision) != expected {
            return Err(Error::Conflict);
        }
        let revision = expected
            .checked_add(1)
            .filter(|r| *r <= i64::MAX as u64)
            .ok_or(Error::Invalid)?;
        let document = Document {
            revision,
            digest,
            configuration,
        };
        let value = serde_json::to_string(&document).map_err(|_| Error::Invalid)?;
        let audit = serde_json::json!({"revision":revision,"actor":actor,"digest":document.digest,
            "disabled":document.configuration.is_none()})
        .to_string();
        tx.put(KEY, &value)?;
        tx.insert(
            &format!("authentication_profile_publication_audit:{revision}"),
            &audit,
        )?;
        guard(tx)?;
        Ok(document)
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    #[test]
    fn revoked_actor_before_commit_rolls_back_authority_and_audit() {
        let mut db = Connection::open_in_memory().unwrap();
        db.execute_batch("CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT NOT NULL) STRICT")
            .unwrap();
        let calls = std::cell::Cell::new(0);
        let guard = |_: &dyn MetaTx| {
            calls.set(calls.get() + 1);
            if calls.get() == 2 {
                Err(Error::Denied)
            } else {
                Ok(())
            }
        };
        assert!(matches!(
            publish_guarded(&mut db, 0, None, "admin", &guard),
            Err(Error::Denied)
        ));
        assert!(read(&db).unwrap().is_none());
        let count: i64 = db
            .query_row("SELECT count(*) FROM meta", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0);
    }
    #[test]
    fn deletion_survives_reopen_and_stale_publication_cannot_restore_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("owned.db");
        let mut db = Connection::open(&path).unwrap();
        db.execute_batch("CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT NOT NULL) STRICT")
            .unwrap();
        assert!(read(&db).unwrap().is_none());
        let config: Config =
            serde_json::from_value(serde_json::json!({"authority_id":"owned","profiles":[{
            "service_id":"orders","host":"app.example.test","ports":[443],"realm":"services",
            "api_keys":[{"token_env":"OWNED_KEY","subject":"worker"}]}]}))
            .unwrap();
        assert_eq!(
            publish(&mut db, 0, Some(config.clone()), "admin")
                .unwrap()
                .revision,
            1
        );
        assert_eq!(publish(&mut db, 1, None, "admin").unwrap().revision, 2);
        assert!(matches!(
            publish(&mut db, 1, Some(config), "admin"),
            Err(Error::Conflict)
        ));
        drop(db);
        let db = Connection::open(path).unwrap();
        let state = read(&db).unwrap().unwrap();
        assert_eq!(state.revision, 2);
        assert!(state.configuration.is_none());
        let audits:i64=db.query_row("SELECT count(*) FROM meta WHERE key LIKE 'authentication_profile_publication_audit:%'",[],|r|r.get(0)).unwrap();
        assert_eq!(audits, 2);
    }
    #[test]
    fn corrupt_state_and_audit_collision_fail_closed_and_roll_back() {
        let mut db = Connection::open_in_memory().unwrap();
        db.execute_batch("CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT NOT NULL) STRICT; INSERT INTO meta VALUES('authentication_profile_publication_audit:1','occupied')").unwrap();
        assert!(matches!(
            publish(&mut db, 0, None, "admin"),
            Err(Error::Storage)
        ));
        assert!(read(&db).unwrap().is_none());
        db.execute("INSERT INTO meta VALUES(?1,'{}')", [KEY])
            .unwrap();
        assert!(matches!(read(&db), Err(Error::Invalid)));
        assert!(matches!(
            publish(&mut db, 0, None, "admin"),
            Err(Error::Invalid)
        ));
    }
}
