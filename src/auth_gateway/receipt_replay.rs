//! Atomic receipt consumption in owner meta state. No credential is issued here.
use super::{receipt_authority::Checked, receipt_key_store, receipt_keys::Refused};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior};
const COUNT: &str = "projection_nonce_count_v1";
const CLOCK: &str = "projection_nonce_clock_v1";
const IDS: &str = "projection_nonce_id:";
const EXPIRY: &str = "projection_nonce_expiry:";
fn value(db: &Connection, key: &str) -> Result<Option<String>, Refused> {
    db.query_row("SELECT value FROM meta WHERE key=?1", [key], |r| r.get(0))
        .optional()
        .map_err(|_| Refused)
}
fn put(db: &Connection, key: &str, val: &str) -> Result<(), Refused> {
    db.execute("INSERT INTO meta(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",rusqlite::params![key,val]).map_err(|_|Refused)?;
    Ok(())
}
pub fn consume<T>(
    db: &mut Connection,
    checked: &Checked,
    clock: &dyn Fn() -> u64,
    guard: &dyn Fn(&Connection) -> Result<(), Refused>,
    operation: impl FnOnce(&Transaction<'_>) -> Result<T, Refused>,
) -> Result<T, Refused> {
    consume_group(db, &[checked], clock, guard, operation)
}
/// Internal bounded admission for one receipt or an authenticated projection pair.
/// The caller must validate chain relationships before entering this transaction.
pub(crate) fn consume_group<T>(
    db: &mut Connection,
    receipts: &[&Checked],
    clock: &dyn Fn() -> u64,
    guard: &dyn Fn(&Connection) -> Result<(), Refused>,
    operation: impl FnOnce(&Transaction<'_>) -> Result<T, Refused>,
) -> Result<T, Refused> {
    if receipts.is_empty() || receipts.len() > 2 {
        return Err(Refused);
    }
    let checked = receipts[0];
    if receipts
        .iter()
        .any(|item| item.revision() != checked.revision())
    {
        return Err(Refused);
    }
    let tx = db
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| Refused)?;
    guard(&tx)?;
    let current = receipt_key_store::load(&tx, checked.revision())?.ok_or(Refused)?;
    if current.revision() != checked.revision() {
        return Err(Refused);
    }
    let floor = value(&tx, CLOCK)?
        .map(|v| v.parse::<u64>().map_err(|_| Refused))
        .transpose()?
        .unwrap_or(0);
    let now = clock().max(floor);
    let begun = std::time::Instant::now();
    if receipts.iter().any(|item| {
        let claims = item.receipt().claims();
        now < claims.issued_ms || now >= claims.expires_ms
    }) {
        return Err(Refused);
    }
    let mut count = match value(&tx, COUNT)? {
        Some(v) => v.parse::<u64>().map_err(|_| Refused)?,
        None => tx
            .query_row(
                "SELECT count(*) FROM meta WHERE key>=?1 AND key<?2",
                rusqlite::params![IDS, "projection_nonce_id;"],
                |r| r.get::<_, u64>(0),
            )
            .map_err(|_| Refused)?,
    };
    if count > 1_000_000 {
        return Err(Refused);
    }
    // Expiry keys are lexically ordered; bounded cleanup avoids full-ledger scans.
    let expired = {
        let mut query = tx
            .prepare("SELECT key,value FROM meta WHERE key>=?1 AND key<?2 ORDER BY key LIMIT 128")
            .map_err(|_| Refused)?;
        query
            .query_map(
                rusqlite::params![EXPIRY, format!("{EXPIRY}{now:020};")],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
            )
            .map_err(|_| Refused)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| Refused)?
    };
    for (index, id) in expired {
        if id.len() != 64 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Refused);
        }
        let id_key = format!("{IDS}{id}");
        let expiry = value(&tx, &id_key)?
            .ok_or(Refused)?
            .parse::<u64>()
            .map_err(|_| Refused)?;
        if expiry > now || index != format!("{EXPIRY}{expiry:020}:{id}") {
            return Err(Refused);
        }
        tx.execute(
            "DELETE FROM meta WHERE key=?1 OR key=?2",
            rusqlite::params![index, id_key],
        )
        .map_err(|_| Refused)?;
        count = count.checked_sub(1).ok_or(Refused)?;
    }
    for checked in receipts {
        let claims = checked.receipt().claims();
        let id = data_encoding::HEXLOWER.encode(checked.replay_key());
        let id_key = format!("{IDS}{id}");
        if count >= 1_000_000 || value(&tx, &id_key)?.is_some() {
            return Err(Refused);
        }
        tx.execute(
            "INSERT INTO meta(key,value) VALUES(?1,?2)",
            rusqlite::params![id_key, claims.expires_ms.to_string()],
        )
        .map_err(|_| Refused)?;
        tx.execute(
            "INSERT INTO meta(key,value) VALUES(?1,?2)",
            rusqlite::params![format!("{EXPIRY}{:020}:{id}", claims.expires_ms), id],
        )
        .map_err(|_| Refused)?;
        count += 1;
    }
    put(&tx, COUNT, &count.to_string())?;
    put(&tx, CLOCK, &now.to_string())?;
    let result = operation(&tx)?;
    guard(&tx)?;
    let final_registry = receipt_key_store::load(&tx, checked.revision())?.ok_or(Refused)?;
    if final_registry.revision() != checked.revision() {
        return Err(Refused);
    }
    let final_now =
        clock().max(now.saturating_add(begun.elapsed().as_millis().min(u64::MAX as u128) as u64));
    if receipts
        .iter()
        .any(|item| final_now >= item.receipt().claims().expires_ms)
    {
        return Err(Refused);
    }
    put(&tx, CLOCK, &final_now.to_string())?;
    tx.commit().map_err(|_| Refused)?;
    Ok(result)
}
#[cfg(test)]
mod tests {
    use super::super::{
        PrincipalKind,
        receipt::{self, Claims, Purpose},
        receipt_authority::Authority,
        receipt_binding::{self, Context, Identity},
        receipt_keys::Key,
    };
    use super::*;
    fn fixture(db: &mut Connection) -> (Authority, Checked) {
        db.execute_batch("CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT NOT NULL)")
            .unwrap();
        let mut owner = Authority::load(db, 0).unwrap();
        let signer = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        owner
            .publish(
                db,
                0,
                &[Key {
                    issuer_ref: "owned".into(),
                    purpose: Purpose::Authentication,
                    epoch: 1,
                    public_key: signer.verifying_key().to_bytes(),
                }],
                "operator",
                &|_| Ok(()),
            )
            .unwrap();
        let context = Context {
            issuer_ref: "owned",
            key_epoch: 1,
            identity_authority_epoch: "identity-1",
            identity: Identity {
                subject_ref: "user",
                kind: PrincipalKind::Human,
                aal: 1,
                revision: 1,
                credential_generation: 1,
            },
            service: "orders",
            audience: "orders-api",
            request_sha256: [4; 32],
        };
        let bytes = receipt::sign(
            &signer,
            &Claims {
                purpose: Purpose::Authentication,
                issued_ms: 100,
                expires_ms: 1000,
                binding: receipt_binding::digest(&context, None).unwrap(),
                nonce: [8; 32],
            },
        )
        .unwrap();
        let checked = owner
            .verifier()
            .verify(&context, None, &bytes, 101)
            .unwrap();
        (owner, checked)
    }
    #[test]
    fn independent_connections_admit_exactly_one_concurrent_consumer() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let mut db = Connection::open(file.path()).unwrap();
        let (_owner, checked) = fixture(&mut db);
        let barrier = std::sync::Barrier::new(8);
        let successes = std::thread::scope(|scope| {
            let mut threads = Vec::new();
            for _ in 0..8 {
                let path = file.path();
                let checked = &checked;
                let barrier = &barrier;
                threads.push(scope.spawn(move || {
                    let mut connection = Connection::open(path).unwrap();
                    connection
                        .busy_timeout(std::time::Duration::from_secs(2))
                        .unwrap();
                    barrier.wait();
                    consume(&mut connection, checked, &|| 101, &|_| Ok(()), |tx| {
                        let count = value(tx, "issued-fixture")?
                            .unwrap_or_else(|| "0".into())
                            .parse::<u64>()
                            .map_err(|_| Refused)?;
                        put(tx, "issued-fixture", &(count + 1).to_string())
                    })
                    .is_ok()
                }));
            }
            threads
                .into_iter()
                .map(|thread| thread.join().unwrap())
                .filter(|success| *success)
                .count()
        });
        assert_eq!(successes, 1);
        assert_eq!(value(&db, "issued-fixture").unwrap().unwrap(), "1");
        drop(db);
        let mut restarted = Connection::open(file.path()).unwrap();
        assert!(consume(&mut restarted, &checked, &|| 102, &|_| Ok(()), |_| Ok(())).is_err());
    }
    #[test]
    fn final_authorization_failure_rolls_back_nonce_and_owner_work() {
        let mut db = Connection::open_in_memory().unwrap();
        let (_owner, checked) = fixture(&mut db);
        let checks = std::cell::Cell::new(0);
        assert!(
            consume(
                &mut db,
                &checked,
                &|| 101,
                &|_| {
                    checks.set(checks.get() + 1);
                    if checks.get() == 2 {
                        Err(Refused)
                    } else {
                        Ok(())
                    }
                },
                |tx| put(tx, "issued-fixture", "must-rollback")
            )
            .is_err()
        );
        assert_eq!(checks.get(), 2);
        assert!(value(&db, "issued-fixture").unwrap().is_none());
        assert!(value(&db, COUNT).unwrap().is_none());
        consume(&mut db, &checked, &|| 101, &|_| Ok(()), |_| Ok(())).unwrap();
    }

    #[test]
    fn registry_change_inside_owner_work_cannot_commit_old_receipt() {
        let mut db = Connection::open_in_memory().unwrap();
        let (_owner, checked) = fixture(&mut db);
        let original = value(&db, "projection_receipt_registry_v1")
            .unwrap()
            .unwrap();
        assert!(
            consume(&mut db, &checked, &|| 101, &|_| Ok(()), |tx| {
                let mut changed: serde_json::Value = serde_json::from_str(&original).unwrap();
                changed["revision"] = serde_json::json!(2);
                put(tx, "projection_receipt_registry_v1", &changed.to_string())?;
                put(tx, "issued-fixture", "must-rollback")
            })
            .is_err()
        );
        assert_eq!(
            value(&db, "projection_receipt_registry_v1")
                .unwrap()
                .unwrap(),
            original
        );
        assert!(value(&db, "issued-fixture").unwrap().is_none());
        assert!(value(&db, COUNT).unwrap().is_none());
        consume(&mut db, &checked, &|| 101, &|_| Ok(()), |_| Ok(())).unwrap();
    }
    #[test]
    fn single_use_operation_failure_expiry_and_publication_are_atomic() {
        let mut db = Connection::open_in_memory().unwrap();
        db.execute_batch("CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT NOT NULL)")
            .unwrap();
        let mut owner = Authority::load(&db, 0).unwrap();
        let signer = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        owner
            .publish(
                &mut db,
                0,
                &[Key {
                    issuer_ref: "owned".into(),
                    purpose: Purpose::Authentication,
                    epoch: 1,
                    public_key: signer.verifying_key().to_bytes(),
                }],
                "operator",
                &|_| Ok(()),
            )
            .unwrap();
        let context = Context {
            issuer_ref: "owned",
            key_epoch: 1,
            identity_authority_epoch: "identity-1",
            identity: Identity {
                subject_ref: "user",
                kind: PrincipalKind::Human,
                aal: 1,
                revision: 1,
                credential_generation: 1,
            },
            service: "orders",
            audience: "orders-api",
            request_sha256: [4; 32],
        };
        let bytes = receipt::sign(
            &signer,
            &Claims {
                purpose: Purpose::Authentication,
                issued_ms: 100,
                expires_ms: 1000,
                binding: receipt_binding::digest(&context, None).unwrap(),
                nonce: [8; 32],
            },
        )
        .unwrap();
        let checked = owner
            .verifier()
            .verify(&context, None, &bytes, 101)
            .unwrap();
        let clock = std::cell::Cell::new(101);
        assert!(
            consume(&mut db, &checked, &|| clock.get(), &|_| Ok(()), |tx| {
                put(tx, "issuance-fixture", "expired")?;
                clock.set(1000);
                Ok(())
            })
            .is_err()
        );
        assert!(value(&db, "issuance-fixture").unwrap().is_none());
        assert!(value(&db, COUNT).unwrap().is_none());
        assert!(
            consume(&mut db, &checked, &|| 101, &|_| Ok(()), |tx| {
                put(tx, "issuance-fixture", "should-rollback")?;
                Err::<(), _>(Refused)
            })
            .is_err()
        );
        assert!(value(&db, "issuance-fixture").unwrap().is_none());
        assert!(value(&db, COUNT).unwrap().is_none());
        consume(&mut db, &checked, &|| 101, &|_| Ok(()), |tx| {
            put(tx, "issuance-fixture", "committed")
        })
        .unwrap();
        assert!(consume(&mut db, &checked, &|| 102, &|_| Ok(()), |_| Ok(())).is_err());
        assert!(consume(&mut db, &checked, &|| 1000, &|_| Ok(()), |_| Ok(())).is_err());
        let fresh = receipt::sign(
            &signer,
            &Claims {
                purpose: Purpose::Authentication,
                issued_ms: 1100,
                expires_ms: 2000,
                binding: receipt_binding::digest(&context, None).unwrap(),
                nonce: [9; 32],
            },
        )
        .unwrap();
        let fresh_checked = owner
            .verifier()
            .verify(&context, None, &fresh, 1101)
            .unwrap();
        consume(&mut db, &fresh_checked, &|| 1101, &|_| Ok(()), |_| Ok(())).unwrap();
        assert_eq!(
            value(&db, COUNT).unwrap().unwrap(),
            "1",
            "expired nonce was not collected"
        );
        assert!(
            consume(&mut db, &checked, &|| 102, &|_| Ok(()), |_| Ok(())).is_err(),
            "clock rollback resurrected a collected nonce"
        );
        owner
            .publish(&mut db, 1, &[], "operator", &|_| Ok(()))
            .unwrap();
        assert!(consume(&mut db, &checked, &|| 103, &|_| Ok(()), |_| Ok(())).is_err());
    }
}
