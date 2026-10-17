//! Atomic receipt consumption in owner meta state. No credential is issued here.
use super::{receipt_authority::Checked, receipt_key_store, receipt_keys::Refused};
use crate::store::meta::{MetaDb, MetaTx};
const COUNT: &str = "projection_nonce_count_v1";
const CLOCK: &str = "projection_nonce_clock_v1";
const IDS: &str = "projection_nonce_id:";
const EXPIRY: &str = "projection_nonce_expiry:";
fn value(db: &dyn MetaTx, key: &str) -> Result<Option<String>, Refused> {
    db.get(key).map_err(|_| Refused)
}
fn put(db: &dyn MetaTx, key: &str, val: &str) -> Result<(), Refused> {
    db.put(key, val).map_err(|_| Refused)
}
fn insert(db: &dyn MetaTx, key: &str, val: &str) -> Result<(), Refused> {
    db.insert(key, val).map_err(|_| Refused)
}
fn delete(db: &dyn MetaTx, key: &str) -> Result<(), Refused> {
    db.delete(key).map_err(|_| Refused)
}
/// The live nonce count, recounted from the id rows when the counter is absent.
fn nonce_count(db: &dyn MetaTx) -> Result<u64, Refused> {
    match value(db, COUNT)? {
        Some(v) => v.parse::<u64>().map_err(|_| Refused),
        None => db.count(IDS, "projection_nonce_id;").map_err(|_| Refused),
    }
}
pub fn consume<T, D: MetaDb>(
    db: &mut D,
    checked: &Checked,
    clock: &dyn Fn() -> u64,
    guard: &dyn Fn(&dyn MetaTx) -> Result<(), Refused>,
    operation: impl FnOnce(&dyn MetaTx) -> Result<T, Refused>,
) -> Result<T, Refused> {
    consume_group(db, &[checked], clock, guard, operation)
}
/// Internal bounded admission for one receipt or an authenticated projection pair.
/// The caller must validate chain relationships before entering this transaction.
pub(crate) fn consume_group<T, D: MetaDb>(
    db: &mut D,
    receipts: &[&Checked],
    clock: &dyn Fn() -> u64,
    guard: &dyn Fn(&dyn MetaTx) -> Result<(), Refused>,
    operation: impl FnOnce(&dyn MetaTx) -> Result<T, Refused>,
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
    db.meta_write(&std::cell::Cell::new(false), |tx| {
        guard(tx)?;
        if receipts.iter().any(|item| !item.current()) {
            return Err(Refused);
        }
        let current = receipt_key_store::load(tx, checked.revision())?.ok_or(Refused)?;
        if current.revision() != checked.revision() {
            return Err(Refused);
        }
        let floor = value(tx, CLOCK)?
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
        let mut count = nonce_count(tx)?;
        if count > 1_000_000 {
            return Err(Refused);
        }
        // Expiry keys are lexically ordered; bounded cleanup avoids full-ledger scans.
        let expired = tx
            .range(EXPIRY, &format!("{EXPIRY}{now:020};"), 128)
            .map_err(|_| Refused)?;
        for (index, id) in expired {
            if id.len() != 64 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(Refused);
            }
            let id_key = format!("{IDS}{id}");
            let expiry = value(tx, &id_key)?
                .ok_or(Refused)?
                .parse::<u64>()
                .map_err(|_| Refused)?;
            if expiry > now || index != format!("{EXPIRY}{expiry:020}:{id}") {
                return Err(Refused);
            }
            delete(tx, &index)?;
            delete(tx, &id_key)?;
            count = count.checked_sub(1).ok_or(Refused)?;
        }
        for checked in receipts {
            let claims = checked.receipt().claims();
            let id = data_encoding::HEXLOWER.encode(checked.replay_key());
            let id_key = format!("{IDS}{id}");
            if count >= 1_000_000 || value(tx, &id_key)?.is_some() {
                return Err(Refused);
            }
            insert(tx, &id_key, &claims.expires_ms.to_string())?;
            insert(tx, &format!("{EXPIRY}{:020}:{id}", claims.expires_ms), &id)?;
            count += 1;
        }
        put(tx, COUNT, &count.to_string())?;
        put(tx, CLOCK, &now.to_string())?;
        let result = operation(tx)?;
        guard(tx)?;
        if receipts.iter().any(|item| !item.current()) {
            return Err(Refused);
        }
        let final_registry = receipt_key_store::load(tx, checked.revision())?.ok_or(Refused)?;
        if final_registry.revision() != checked.revision() {
            return Err(Refused);
        }
        let final_now = clock()
            .max(now.saturating_add(begun.elapsed().as_millis().min(u64::MAX as u128) as u64));
        if receipts
            .iter()
            .any(|item| final_now >= item.receipt().claims().expires_ms)
        {
            return Err(Refused);
        }
        put(tx, CLOCK, &final_now.to_string())?;
        Ok(result)
    })
}
// Observed v2 rows share IDS/COUNT with v1: mode never changes nonce identity.
// Only this generation's BOOTTIME index can collect them. Unknown generations
// remain tombstones indefinitely, including after restart; capacity fails closed.
const OBSERVED_EXPIRY: &str = "projection_nonce_observed_expiry_v2:";
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ObservedRow {
    version: u8,
    receiver_generation: [u8; 16],
    retain_until_ms: u64,
    source_domain: String,
}
pub(crate) struct ObservedProof {
    checked: super::receipt_authority::ObservedChecked,
    deadline: hangang_runtime::time::LocalDeadline,
    retention: hangang_runtime::time::ReplayRetention,
    source_domain: String,
}
impl ObservedProof {
    /// Only native fixed-owner adapters may call this after authenticating the
    /// report's exact source domain, proof digest and live owner generations.
    pub(crate) fn from_owner_report(
        checked: super::receipt_authority::ObservedChecked,
        source_domain: String,
        report: &hopae_grpc::receipt_time::Report,
        exchange: hangang_runtime::time::ExchangeSample,
        rates: &hopae_grpc::receipt_time::ClockRates,
    ) -> Result<Self, Refused> {
        if source_domain.is_empty()
            || source_domain.len() > 256
            || source_domain.chars().any(char::is_control)
            || !checked.current()
        {
            return Err(Refused);
        }
        let bounds = hopae_grpc::receipt_time::Bounds::from_signature_with_rates(
            checked.evidence(),
            report,
            &hopae_grpc::receipt_time::Exchange {
                before_ms: exchange.before_ticks(),
                after_ms: exchange.after_ticks(),
                elapsed_ms: exchange.elapsed_ms(),
            },
            rates,
        )
        .map_err(|_| Refused)?;
        let (deadline, retention) = exchange
            .bind_bounds(bounds.admit_until_ms(), bounds.retain_until_ms())
            .map_err(|_| Refused)?;
        Ok(Self {
            checked,
            deadline,
            retention,
            source_domain,
        })
    }
    pub(crate) fn matches_bytes(&self, bytes: &[u8]) -> bool {
        use sha2::{Digest as _, Sha256};
        <[u8; 32]>::from(Sha256::digest(bytes)) == *self.checked.evidence().sha256()
    }
    pub(crate) fn remaining(
        &self,
        clock: &hangang_runtime::time::ReceiverClock,
    ) -> Result<std::time::Duration, Refused> {
        let remaining = self.deadline.remaining(clock).map_err(|_| Refused)?;
        if !self.checked.current() {
            return Err(Refused);
        }
        Ok(remaining)
    }
}
/// Exactly two independently retained nonces. No UTC/source-time read or cleanup
/// occurs here. Native guard is called before and after secret resolution, then
/// local time/registry fences run after the final external callback.
pub(crate) fn consume_observed_pair<T, D: MetaDb>(
    db: &mut D,
    proofs: [&ObservedProof; 2],
    clock: &hangang_runtime::time::ReceiverClock,
    guard: &dyn Fn(&dyn MetaTx) -> Result<(), Refused>,
    operation: impl FnOnce(&dyn MetaTx) -> Result<T, Refused>,
) -> Result<T, Refused> {
    consume_observed_pair_with_final(db, proofs, clock, guard, &|| Ok(()), operation)
}
/// Same paired algorithm with a known callback-free final native latch fence.
/// It cannot perform SQL, time reads, allocation or external callbacks.
pub(crate) fn consume_observed_pair_with_final<T, D: MetaDb>(
    db: &mut D,
    proofs: [&ObservedProof; 2],
    clock: &hangang_runtime::time::ReceiverClock,
    guard: &dyn Fn(&dyn MetaTx) -> Result<(), Refused>,
    final_guard: &dyn Fn() -> Result<(), Refused>,
    operation: impl FnOnce(&dyn MetaTx) -> Result<T, Refused>,
) -> Result<T, Refused> {
    let revision = proofs[0].checked.revision();
    if proofs.iter().any(|p| p.checked.revision() != revision)
        || proofs[0].checked.replay_key() == proofs[1].checked.replay_key()
    {
        return Err(Refused);
    }
    let check = |db: &dyn MetaTx| -> Result<(), Refused> {
        for p in &proofs {
            p.deadline.check(clock).map_err(|_| Refused)?;
            // Checks the private clock instance, not merely generation bytes.
            p.retention.elapsed(clock).map_err(|_| Refused)?;
            if !p.checked.current() {
                return Err(Refused);
            }
        }
        let current = receipt_key_store::load(db, revision)?.ok_or(Refused)?;
        if current.revision() != revision
            || proofs
                .iter()
                .any(|p| !p.checked.matches_registry(&current).unwrap_or(false))
        {
            return Err(Refused);
        }
        Ok(())
    };
    db.meta_write(&std::cell::Cell::new(false), |tx| {
        guard(tx)?;
        check(tx)?;
        let registry = receipt_key_store::load(tx, revision)?
            .ok_or(Refused)?
            .encode()?;
        let now = clock.sample_ticks().map_err(|_| Refused)?;
        let generation = data_encoding::HEXLOWER.encode(clock.generation());
        let prefix = format!("{OBSERVED_EXPIRY}{generation}:");
        let mut count = nonce_count(tx)?;
        if count > 1_000_000 {
            return Err(Refused);
        }
        let expired = tx
            .range(&prefix, &format!("{prefix}{now:020};"), 128)
            .map_err(|_| Refused)?;
        for (index, id) in expired {
            if id.len() != 64 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(Refused);
            }
            let id_key = format!("{IDS}{id}");
            let row: ObservedRow =
                serde_json::from_str(&value(tx, &id_key)?.ok_or(Refused)?).map_err(|_| Refused)?;
            if row.version != 2
                || row.receiver_generation != *clock.generation()
                || row.retain_until_ms > now
                || index != format!("{prefix}{:020}:{id}", row.retain_until_ms)
            {
                return Err(Refused);
            }
            delete(tx, &index)?;
            delete(tx, &id_key)?;
            count = count.checked_sub(1).ok_or(Refused)?;
        }
        for proof in proofs {
            let id = data_encoding::HEXLOWER.encode(proof.checked.replay_key());
            let id_key = format!("{IDS}{id}");
            if count >= 1_000_000 || value(tx, &id_key)?.is_some() {
                return Err(Refused);
            }
            let row = ObservedRow {
                version: 2,
                receiver_generation: *clock.generation(),
                retain_until_ms: proof.retention.ticks(),
                source_domain: proof.source_domain.clone(),
            };
            let encoded = serde_json::to_string(&row).map_err(|_| Refused)?;
            insert(tx, &id_key, &encoded)?;
            insert(
                tx,
                &format!("{prefix}{:020}:{id}", row.retain_until_ms),
                &id,
            )?;
            count += 1;
        }
        put(tx, COUNT, &count.to_string())?;
        let result = operation(tx)?;
        guard(tx)?;
        check(tx)?;
        if receipt_key_store::load(tx, revision)?
            .ok_or(Refused)?
            .encode()?
            != registry
        {
            return Err(Refused);
        }
        final_guard()?;
        Ok(result)
    })
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
    use rusqlite::Connection;
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
    /// The same race across PostgreSQL connections (ADR-0020 slice 5): the
    /// owner lock serializes the consumers, exactly one admits the receipt.
    #[cfg(feature = "postgres")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn s600_28_postgres_connections_admit_exactly_one_concurrent_consumer() {
        let Some(b) = crate::store::conformance::postgres_with(true).await else {
            eprintln!("skip: HOPAE_TEST_POSTGRES_URL not set");
            return;
        };
        let app = b.app.clone();
        let handle = tokio::runtime::Handle::current();
        let (successes, issued) = tokio::task::spawn_blocking(move || {
            let _enter = handle.enter();
            let mut db = app.meta();
            let mut owner = db.meta_read(|tx| Authority::load(tx, 0)).unwrap();
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
            let barrier = std::sync::Barrier::new(8);
            let successes = std::thread::scope(|scope| {
                let threads: Vec<_> = (0..8)
                    .map(|_| {
                        let (app, checked, barrier) = (app.clone(), &checked, &barrier);
                        scope.spawn(move || {
                            barrier.wait();
                            let mut db = app.meta();
                            consume(&mut db, checked, &|| 101, &|_| Ok(()), |tx| {
                                let count = value(tx, "issued-fixture")?
                                    .unwrap_or_else(|| "0".into())
                                    .parse::<u64>()
                                    .map_err(|_| Refused)?;
                                put(tx, "issued-fixture", &(count + 1).to_string())
                            })
                            .is_ok()
                        })
                    })
                    .collect();
                threads
                    .into_iter()
                    .map(|t| t.join().unwrap())
                    .filter(|w| *w)
                    .count()
            });
            let issued = db.meta_read(|tx| value(tx, "issued-fixture")).unwrap();
            (successes, issued)
        })
        .await
        .unwrap();
        assert_eq!(successes, 1);
        assert_eq!(issued.as_deref(), Some("1"));
        b.cleanup().await;
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
