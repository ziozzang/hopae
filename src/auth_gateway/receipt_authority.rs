//! Serialized owner publication and immutable live verification. Snapshot tags
//! still need DB-revision rechecking during nonce consumption/issuance.
use super::{
    receipt::VerifiedReceipt,
    receipt_binding::{Context, Permit},
    receipt_key_store,
    receipt_keys::{Key, Refused, Registry},
};
use arc_swap::ArcSwapOption;
use rusqlite::Connection;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
pub struct Authority {
    available: Arc<AtomicBool>,
    snapshot: Arc<ArcSwapOption<Registry>>,
}
#[derive(Clone)]
pub struct Verifier {
    available: Arc<AtomicBool>,
    snapshot: Arc<ArcSwapOption<Registry>>,
}
/// Exact immutable receiver generation, not a remote permission lease.
pub struct Current {
    available: Arc<AtomicBool>,
    snapshot: Arc<ArcSwapOption<Registry>>,
    registry: Arc<Registry>,
}
impl Current {
    pub(crate) fn revision(&self) -> u64 {
        self.registry.revision()
    }
    pub fn current(&self) -> bool {
        self.available.load(Ordering::Acquire)
            && self
                .snapshot
                .load_full()
                .is_some_and(|registry| Arc::ptr_eq(&registry, &self.registry))
    }
}
pub struct Checked {
    available: Arc<AtomicBool>,
    snapshot: Arc<ArcSwapOption<Registry>>,
    registry: Arc<Registry>,
    receipt: VerifiedReceipt,
    replay_key: [u8; 32],
}
impl Checked {
    pub fn current(&self) -> bool {
        self.available.load(Ordering::Acquire)
            && self
                .snapshot
                .load_full()
                .is_some_and(|registry| Arc::ptr_eq(&registry, &self.registry))
    }
    pub(crate) fn replay_key(&self) -> &[u8; 32] {
        &self.replay_key
    }
    pub fn revision(&self) -> u64 {
        self.registry.revision()
    }
    pub fn receipt(&self) -> &VerifiedReceipt {
        &self.receipt
    }
}
/// Signature/registry evidence only. Source observations and local deadlines are
/// deliberately separate; this type can never enter strict UTC consumption.
pub(crate) struct ObservedChecked {
    current: Current,
    evidence: super::receipt::SignatureEvidence,
    replay_key: [u8; 32],
}
impl ObservedChecked {
    pub(crate) fn current(&self) -> bool {
        self.current.current()
    }
    pub(crate) fn revision(&self) -> u64 {
        self.current.registry.revision()
    }
    pub(crate) fn matches_registry(&self, registry: &Registry) -> Result<bool, Refused> {
        Ok(self.current.registry.encode()? == registry.encode()?)
    }
    pub(crate) fn evidence(&self) -> &super::receipt::SignatureEvidence {
        &self.evidence
    }
    pub(crate) fn replay_key(&self) -> &[u8; 32] {
        &self.replay_key
    }
}
fn replay_key(issuer: &str, claims: &super::receipt::Claims) -> [u8; 32] {
    use sha2::{Digest as _, Sha256};
    let mut hash = Sha256::new();
    hash.update(b"hangang-zerotrust:receipt-consumption:v1\0");
    hash.update((issuer.len() as u32).to_be_bytes());
    hash.update(issuer.as_bytes());
    hash.update([claims.purpose as u8]);
    hash.update(claims.nonce);
    hash.finalize().into()
}
impl Authority {
    pub fn load(connection: &Connection, minimum_revision: u64) -> Result<Self, Refused> {
        let registry = receipt_key_store::load(connection, minimum_revision)?.map(Arc::new);
        Ok(Self {
            available: Arc::new(AtomicBool::new(true)),
            snapshot: Arc::new(ArcSwapOption::from(registry)),
        })
    }
    pub fn verifier(&self) -> Verifier {
        Verifier {
            available: self.available.clone(),
            snapshot: self.snapshot.clone(),
        }
    }
    /// Startup/configuration reconciliation preserves the exact reader on an
    /// unchanged set. Durable retirement floors still govern every transition.
    pub fn reconcile(
        &mut self,
        connection: &mut Connection,
        desired: &[Key],
        actor: &str,
        guard: &dyn Fn(&Connection) -> Result<(), Refused>,
    ) -> Result<u64, Refused> {
        if !self.available.load(Ordering::Acquire)
            || actor.is_empty()
            || actor.len() > 128
            || actor.chars().any(char::is_control)
        {
            return Err(Refused);
        }
        let current = self.snapshot.load_full();
        let revision = current.as_ref().map_or(0, |registry| registry.revision());
        let unchanged = current.as_ref().map_or(desired.is_empty(), |registry| {
            registry.active_matches(desired)
        });
        if !unchanged {
            return self.publish(connection, revision, desired, actor, guard);
        }
        let expected = current
            .as_ref()
            .map(|registry| registry.encode())
            .transpose()?;
        let transaction = connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|_| Refused)?;
        let matches = |db: &Connection| -> Result<(), Refused> {
            let actual = receipt_key_store::load(db, revision)?
                .map(|registry| registry.encode())
                .transpose()?;
            if actual != expected {
                return Err(Refused);
            }
            Ok(())
        };
        guard(&transaction)?;
        matches(&transaction)?;
        guard(&transaction)?;
        matches(&transaction)?;
        transaction.commit().map_err(|_| Refused)?;
        Ok(revision)
    }
    /// Exclusive mutable ownership serializes commit/install order. Caller must
    /// retain this authority rather than constructing independent DB writers.
    pub fn publish(
        &mut self,
        connection: &mut Connection,
        expected: u64,
        desired: &[Key],
        actor: &str,
        guard: &dyn Fn(&Connection) -> Result<(), Refused>,
    ) -> Result<u64, Refused> {
        let previous = self.snapshot.load_full();
        if previous.as_ref().map_or(0, |registry| registry.revision()) != expected
            || actor.is_empty()
            || actor.len() > 128
            || actor.chars().any(char::is_control)
        {
            return Err(Refused);
        }
        let before = previous
            .as_ref()
            .map(|registry| registry.encode())
            .transpose()?;
        if !self.available.swap(false, Ordering::AcqRel) {
            return Err(Refused);
        }
        let commit_attempted = std::cell::Cell::new(false);
        let registry = match receipt_key_store::publish_with_commit_state(
            connection,
            expected,
            desired,
            actor,
            guard,
            &commit_attempted,
        ) {
            Ok(registry) => registry,
            Err(error) => {
                if !commit_attempted.get()
                    && connection.is_autocommit()
                    && receipt_key_store::load(connection, expected)
                        .and_then(|registry| registry.map(|registry| registry.encode()).transpose())
                        .is_ok_and(|current| current == before)
                {
                    self.available.store(true, Ordering::Release);
                }
                return Err(error);
            }
        };
        let revision = registry.revision();
        self.snapshot.store(Some(registry));
        self.available.store(true, Ordering::Release);
        Ok(revision)
    }
}
impl Verifier {
    pub fn capture(&self) -> Result<Current, Refused> {
        let current = Current {
            available: self.available.clone(),
            snapshot: self.snapshot.clone(),
            registry: self.snapshot.load_full().ok_or(Refused)?,
        };
        if !current.current() {
            return Err(Refused);
        }
        Ok(current)
    }
    pub fn verify(
        &self,
        context: &Context<'_>,
        permit: Option<&Permit<'_>>,
        bytes: &[u8],
        now: u64,
    ) -> Result<Checked, Refused> {
        if context.identity_authority_epoch.starts_with("clock1:")
            || (context.identity.kind == super::PrincipalKind::Workload
                && hopae_grpc::workload_epoch::decode(context.identity_authority_epoch).is_ok())
            || (context.identity.kind == super::PrincipalKind::Human
                && hopae_grpc::human_epoch::decode(context.identity_authority_epoch).is_ok())
            || permit.is_some_and(|p| p.authority_epoch.starts_with("pobs1:"))
        {
            return Err(Refused);
        }
        self.verify_source_time(context, permit, bytes, now)
    }
    /// Exact local source validation only. Observed evidence never reaches the
    /// public UTC verifier or generic replay entry through this method.
    pub(crate) fn verify_source_time(
        &self,
        context: &Context<'_>,
        permit: Option<&Permit<'_>>,
        bytes: &[u8],
        now: u64,
    ) -> Result<Checked, Refused> {
        if !self.available.load(Ordering::Acquire) {
            return Err(Refused);
        }
        let registry = self.snapshot.load_full().ok_or(Refused)?;
        let receipt = registry.verify(context, permit, bytes, now)?;
        let checked = Checked {
            available: self.available.clone(),
            snapshot: self.snapshot.clone(),
            registry,
            replay_key: replay_key(context.issuer_ref, receipt.claims()),
            receipt,
        };
        if !self.is_current(&checked) {
            return Err(Refused);
        }
        Ok(checked)
    }
    pub(crate) fn verify_observed_signature(
        &self,
        context: &Context<'_>,
        permit: Option<&Permit<'_>>,
        bytes: &[u8],
    ) -> Result<ObservedChecked, Refused> {
        let current = self.capture()?;
        let evidence = current.registry.verify_signature(context, permit, bytes)?;
        let checked = ObservedChecked {
            replay_key: replay_key(context.issuer_ref, evidence.claims()),
            current,
            evidence,
        };
        if !checked.current() {
            return Err(Refused);
        }
        Ok(checked)
    }
    /// Advisory local-current check, not a transactional issuance fence.
    pub fn is_current(&self, checked: &Checked) -> bool {
        self.available.load(Ordering::Acquire)
            && self
                .snapshot
                .load_full()
                .is_some_and(|registry| Arc::ptr_eq(&registry, &checked.registry))
    }
}
#[cfg(test)]
mod tests {
    use super::super::{
        PrincipalKind,
        receipt::{self, Claims, Purpose},
        receipt_binding::{self, Identity},
    };
    use super::*;
    fn descriptor(seed: u8, epoch: u64) -> Key {
        Key {
            issuer_ref: "owned".into(),
            purpose: Purpose::Authentication,
            epoch,
            public_key: ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
                .verifying_key()
                .to_bytes(),
        }
    }
    #[test]
    fn workload_ticks_refuse_strict_utc_without_changing_legacy_service_authority_names() {
        let mut db = Connection::open_in_memory().unwrap();
        db.execute_batch("CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT NOT NULL)")
            .unwrap();
        let mut owner = Authority::load(&db, 0).unwrap();
        owner
            .reconcile(&mut db, &[descriptor(7, 1)], "startup", &|_| Ok(()))
            .unwrap();
        let verifier = owner.verifier();
        let mut context = Context {
            issuer_ref: "owned",
            key_epoch: 1,
            identity_authority_epoch: "wobs1:legacy:service:1:app:1",
            identity: Identity {
                subject_ref: "s_529be5b595ab327853eabe2d1adf52256e262af036510607",
                kind: PrincipalKind::Service,
                aal: 0,
                revision: 1,
                credential_generation: 1,
            },
            service: "orders",
            audience: "orders-api",
            request_sha256: [9; 32],
        };
        let sign = |context: &Context<'_>| {
            receipt::sign(
                &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
                &Claims {
                    purpose: Purpose::Authentication,
                    issued_ms: 100,
                    expires_ms: 1000,
                    binding: receipt_binding::digest(context, None).unwrap(),
                    nonce: [42; 32],
                },
            )
            .unwrap()
        };
        let legacy = sign(&context);
        assert!(verifier.verify(&context, None, &legacy, 101).is_ok());
        context.identity.kind = PrincipalKind::Workload;
        context.identity_authority_epoch = "wobs1:legacy";
        let legacy_workload = sign(&context);
        assert!(
            verifier
                .verify(&context, None, &legacy_workload, 101)
                .is_ok()
        );
        context.identity_authority_epoch = "wobs1:11112222333344445555666677778888:owned:p:1:a:1";
        let workload = sign(&context);
        assert!(
            verifier
                .verify_observed_signature(&context, None, &workload)
                .is_ok()
        );
        assert!(verifier.verify(&context, None, &workload, 101).is_err());
        context.identity.kind = PrincipalKind::Service; // class spoof invalidates signed binding
        assert!(verifier.verify(&context, None, &workload, 101).is_err());
        context.identity.kind = PrincipalKind::Human;
        context.identity.aal = 1;
        context.identity.subject_ref =
            "human1:1111222233334444555566667777888811112222333344445555666677778888";
        context.identity_authority_epoch = "hobs1:legacy";
        let legacy_human = sign(&context);
        assert!(verifier.verify(&context, None, &legacy_human, 101).is_ok());
        context.identity_authority_epoch = "hobs1:11112222333344445555666677778888:owned:s:1:a:1";
        let human = sign(&context);
        assert!(
            verifier
                .verify_observed_signature(&context, None, &human)
                .is_ok()
        );
        assert!(verifier.verify(&context, None, &human, 101).is_err());
        context.identity.kind = PrincipalKind::Service;
        assert!(verifier.verify(&context, None, &human, 101).is_err());
    }
    #[test]
    fn publication_closes_exact_tags_and_only_definite_rollback_reopens() {
        let mut db = Connection::open_in_memory().unwrap();
        db.execute_batch("CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT NOT NULL)")
            .unwrap();
        let mut owner = Authority::load(&db, 0).unwrap();
        owner
            .reconcile(&mut db, &[descriptor(7, 1)], "startup", &|_| Ok(()))
            .unwrap();
        let verifier = owner.verifier();
        let tag = verifier.capture().unwrap();
        assert!(
            owner
                .publish(&mut db, 1, &[], "operator", &|_| {
                    assert!(!tag.current());
                    assert!(verifier.capture().is_err());
                    Err(Refused)
                })
                .is_err()
        );
        assert!(tag.current());
        owner
            .publish(&mut db, 1, &[], "operator", &|_| {
                assert!(!tag.current());
                Ok(())
            })
            .unwrap();
        assert!(!tag.current());
        assert!(verifier.capture().unwrap().current());
    }
    #[test]
    fn uncertain_key_commit_stays_closed_until_a_durable_reload() {
        let mut db = Connection::open_in_memory().unwrap();
        db.execute_batch("PRAGMA foreign_keys=ON;CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);CREATE TABLE parent(id INTEGER PRIMARY KEY);CREATE TABLE child(id INTEGER REFERENCES parent(id) DEFERRABLE INITIALLY DEFERRED);").unwrap();
        let mut owner = Authority::load(&db, 0).unwrap();
        owner
            .reconcile(&mut db, &[descriptor(7, 1)], "startup", &|_| Ok(()))
            .unwrap();
        let verifier = owner.verifier();
        let tag = verifier.capture().unwrap();
        assert!(
            owner
                .publish(&mut db, 1, &[], "operator", &|tx| {
                    tx.execute("INSERT INTO child(id) VALUES(42)", [])
                        .map_err(|_| Refused)?;
                    Ok(())
                })
                .is_err()
        );
        assert!(!tag.current());
        assert!(verifier.capture().is_err());
        assert!(
            owner
                .reconcile(&mut db, &[descriptor(7, 1)], "startup", &|_| Ok(()))
                .is_err()
        );
        assert!(
            Authority::load(&db, 1)
                .unwrap()
                .verifier()
                .capture()
                .unwrap()
                .current()
        );
        assert!(!tag.current());
    }
    #[test]
    fn reconciliation_preserves_noop_tags_rejects_stale_owners_and_retains_restart_floors() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let mut db = Connection::open(file.path()).unwrap();
        db.execute_batch("CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT NOT NULL)")
            .unwrap();
        let mut owner = Authority::load(&db, 0).unwrap();
        let mut stale = Authority::load(&db, 0).unwrap();
        assert_eq!(
            owner
                .reconcile(&mut db, &[], "startup", &|_| Ok(()))
                .unwrap(),
            0
        );
        assert_eq!(
            owner
                .reconcile(&mut db, &[descriptor(7, 1)], "startup", &|_| Ok(()))
                .unwrap(),
            1
        );
        let before = owner.snapshot.load_full().unwrap();
        let guards = std::cell::Cell::new(0);
        assert_eq!(
            owner
                .reconcile(&mut db, &[descriptor(7, 1)], "startup", &|_| {
                    guards.set(guards.get() + 1);
                    Ok(())
                })
                .unwrap(),
            1
        );
        assert_eq!(guards.get(), 2);
        assert!(Arc::ptr_eq(&before, &owner.snapshot.load_full().unwrap()));
        let audits: u64 = db
            .query_row(
                "SELECT count(*) FROM meta WHERE key LIKE 'projection_receipt_registry_audit:%'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(audits, 1);
        assert!(
            stale
                .reconcile(&mut db, &[], "startup", &|_| Ok(()))
                .is_err()
        );
        assert!(
            owner
                .reconcile(&mut db, &[descriptor(7, 1)], "", &|_| panic!(
                    "invalid actor cannot inspect store"
                ))
                .is_err()
        );
        drop(db);
        let mut db = Connection::open(file.path()).unwrap();
        let mut restarted = Authority::load(&db, 1).unwrap();
        assert_eq!(
            restarted
                .reconcile(&mut db, &[descriptor(7, 1)], "startup", &|_| Ok(()))
                .unwrap(),
            1
        );
        assert_eq!(
            restarted
                .reconcile(&mut db, &[], "startup", &|_| Ok(()))
                .unwrap(),
            2
        );
        drop(db);
        let mut db = Connection::open(file.path()).unwrap();
        let mut restarted = Authority::load(&db, 2).unwrap();
        assert!(
            restarted
                .reconcile(&mut db, &[descriptor(7, 1)], "startup", &|_| Ok(()))
                .is_err()
        );
        assert!(
            restarted
                .reconcile(&mut db, &[descriptor(7, 2)], "startup", &|_| Ok(()))
                .is_err()
        );
        assert_eq!(
            restarted
                .reconcile(&mut db, &[descriptor(8, 2)], "startup", &|_| Ok(()))
                .unwrap(),
            3
        );
    }
    #[test]
    fn noop_guards_cannot_mutate_history_or_commit_after_late_revocation() {
        let mut db = Connection::open_in_memory().unwrap();
        db.execute_batch("CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT NOT NULL)")
            .unwrap();
        let mut owner = Authority::load(&db, 0).unwrap();
        owner
            .reconcile(&mut db, &[descriptor(7, 1)], "startup", &|_| Ok(()))
            .unwrap();
        let before = owner.snapshot.load_full().unwrap();
        let calls = std::cell::Cell::new(0);
        assert!(owner.reconcile(&mut db,&[descriptor(7,1)],"startup",&|tx| {
            calls.set(calls.get()+1);
            if calls.get()==2 {tx.execute("UPDATE meta SET value='null' WHERE key='projection_receipt_registry_v1'",[]).map_err(|_|Refused)?;}
            Ok(())
        }).is_err());
        assert!(Arc::ptr_eq(&before, &owner.snapshot.load_full().unwrap()));
        assert_eq!(
            receipt_key_store::load(&db, 1)
                .unwrap()
                .unwrap()
                .encode()
                .unwrap(),
            before.encode().unwrap()
        );
        // A valid document with the same revision but different key material
        // must also fail; decoding/revision checks alone are insufficient.
        let forged = Registry::compile(1, &[descriptor(8, 1)], None)
            .unwrap()
            .encode()
            .unwrap();
        let calls = std::cell::Cell::new(0);
        assert!(
            owner
                .reconcile(&mut db, &[descriptor(7, 1)], "startup", &|tx| {
                    calls.set(calls.get() + 1);
                    if calls.get() == 2 {
                        tx.execute(
                            "UPDATE meta SET value=?1 WHERE key='projection_receipt_registry_v1'",
                            [&forged],
                        )
                        .map_err(|_| Refused)?;
                    }
                    Ok(())
                })
                .is_err()
        );
        assert_eq!(
            receipt_key_store::load(&db, 1)
                .unwrap()
                .unwrap()
                .encode()
                .unwrap(),
            before.encode().unwrap()
        );
        let calls = std::cell::Cell::new(0);
        assert!(
            owner
                .reconcile(&mut db, &[descriptor(7, 1)], "startup", &|_| {
                    calls.set(calls.get() + 1);
                    if calls.get() == 2 {
                        Err(Refused)
                    } else {
                        Ok(())
                    }
                })
                .is_err()
        );
        assert_eq!(
            owner
                .reconcile(&mut db, &[descriptor(7, 1)], "startup", &|_| Ok(()))
                .unwrap(),
            1
        );
    }
    #[test]
    fn live_removal_invalidates_shared_verifiers_and_checked_tags() {
        let mut db = Connection::open_in_memory().unwrap();
        db.execute_batch("CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT NOT NULL)")
            .unwrap();
        let mut owner = Authority::load(&db, 0).unwrap();
        let verifier = owner.verifier();
        let peer = verifier.clone();
        let signer = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let context = Context {
            issuer_ref: "owned",
            key_epoch: 1,
            identity_authority_epoch: "identity-1",
            identity: Identity {
                subject_ref: "user-1",
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
        assert!(verifier.verify(&context, None, &bytes, 101).is_err());
        let key = Key {
            issuer_ref: "owned".into(),
            purpose: Purpose::Authentication,
            epoch: 1,
            public_key: signer.verifying_key().to_bytes(),
        };
        assert_eq!(
            owner
                .publish(&mut db, 0, &[key], "operator", &|_| Ok(()))
                .unwrap(),
            1
        );
        let checked = peer.verify(&context, None, &bytes, 101).unwrap();
        assert_eq!(checked.revision(), 1);
        assert!(verifier.is_current(&checked));
        assert!(
            owner
                .publish(&mut db, 1, &[], "operator", &|_| Err(Refused))
                .is_err()
        );
        assert!(verifier.is_current(&checked));
        assert!(peer.verify(&context, None, &bytes, 101).is_ok());
        assert_eq!(
            owner
                .publish(&mut db, 1, &[], "operator", &|_| Ok(()))
                .unwrap(),
            2
        );
        assert!(!verifier.is_current(&checked));
        assert!(peer.verify(&context, None, &bytes, 101).is_err());
        let restarted = Authority::load(&db, 2).unwrap();
        assert!(
            restarted
                .verifier()
                .verify(&context, None, &bytes, 101)
                .is_err()
        );
        assert!(Authority::load(&db, 3).is_err());
    }
}
