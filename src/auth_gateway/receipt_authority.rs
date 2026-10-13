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
use std::sync::Arc;
pub struct Authority {
    snapshot: Arc<ArcSwapOption<Registry>>,
}
#[derive(Clone)]
pub struct Verifier {
    snapshot: Arc<ArcSwapOption<Registry>>,
}
pub struct Checked {
    registry: Arc<Registry>,
    receipt: VerifiedReceipt,
    replay_key: [u8; 32],
}
impl Checked {
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
impl Authority {
    pub fn load(connection: &Connection, minimum_revision: u64) -> Result<Self, Refused> {
        let registry = receipt_key_store::load(connection, minimum_revision)?.map(Arc::new);
        Ok(Self {
            snapshot: Arc::new(ArcSwapOption::from(registry)),
        })
    }
    pub fn verifier(&self) -> Verifier {
        Verifier {
            snapshot: self.snapshot.clone(),
        }
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
        let registry = receipt_key_store::publish(connection, expected, desired, actor, guard)?;
        let revision = registry.revision();
        // The Arc is allocated inside the transaction. No await or fallible
        // operation separates successful commit and snapshot installation.
        self.snapshot.store(Some(registry));
        Ok(revision)
    }
}
impl Verifier {
    pub fn verify(
        &self,
        context: &Context<'_>,
        permit: Option<&Permit<'_>>,
        bytes: &[u8],
        now: u64,
    ) -> Result<Checked, Refused> {
        let registry = self.snapshot.load_full().ok_or(Refused)?;
        let receipt = registry.verify(context, permit, bytes, now)?;
        use sha2::{Digest as _, Sha256};
        let mut hash = Sha256::new();
        hash.update(b"hangang-zerotrust:receipt-consumption:v1\0");
        hash.update((context.issuer_ref.len() as u32).to_be_bytes());
        hash.update(context.issuer_ref.as_bytes());
        hash.update([receipt.claims().purpose as u8]);
        hash.update(receipt.claims().nonce);
        Ok(Checked {
            registry,
            receipt,
            replay_key: hash.finalize().into(),
        })
    }
    /// Advisory local-current check, not a transactional issuance fence.
    pub fn is_current(&self, checked: &Checked) -> bool {
        self.snapshot
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
