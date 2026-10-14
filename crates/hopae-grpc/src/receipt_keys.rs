//! Immutable receiver-owned receipt keys. In-memory transition fences require
//! durable publication/floors before distributed or restart-safe activation.
use super::{
    receipt::{self, Purpose, VerifiedReceipt},
    receipt_binding::{self, Context, Permit},
};
use ed25519_dalek::VerifyingKey;
use std::collections::{BTreeMap, BTreeSet};
pub struct Key {
    pub issuer_ref: String,
    pub purpose: Purpose,
    pub epoch: u64,
    pub public_key: [u8; 32],
}
#[derive(Debug, PartialEq, Eq)]
pub struct Refused;
#[derive(Clone)]
struct Floor {
    epoch: u64,
    public_key: [u8; 32],
    active: bool,
}
pub struct Registry {
    revision: u64,
    keys: BTreeMap<String, BTreeMap<(u8, u64), VerifyingKey>>,
    floors: BTreeMap<(String, u8), Floor>,
    key_owners: BTreeMap<[u8; 32], (String, u8)>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    version: u8,
    revision: u64,
    floors: Vec<SavedFloor>,
    owners: Vec<SavedOwner>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedFloor {
    issuer: String,
    purpose: u8,
    epoch: u64,
    public_key: [u8; 32],
    active: bool,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedOwner {
    public_key: [u8; 32],
    issuer: String,
    purpose: u8,
}
fn valid_issuer(issuer: &str) -> bool {
    !issuer.is_empty()
        && issuer.len() <= 128
        && issuer
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
}
impl Registry {
    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub fn encode(&self) -> Result<String, Refused> {
        let snapshot = Snapshot {
            version: 1,
            revision: self.revision,
            floors: self
                .floors
                .iter()
                .map(|((issuer, purpose), f)| SavedFloor {
                    issuer: issuer.clone(),
                    purpose: *purpose,
                    epoch: f.epoch,
                    public_key: f.public_key,
                    active: f.active,
                })
                .collect(),
            owners: self
                .key_owners
                .iter()
                .map(|(key, (issuer, purpose))| SavedOwner {
                    public_key: *key,
                    issuer: issuer.clone(),
                    purpose: *purpose,
                })
                .collect(),
        };
        let value = serde_json::to_string(&snapshot).map_err(|_| Refused)?;
        if value.len() > 131072 {
            return Err(Refused);
        }
        Ok(value)
    }
    pub fn decode(value: &str, minimum_revision: u64) -> Result<Self, Refused> {
        if value.len() > 131072 {
            return Err(Refused);
        }
        let s: Snapshot = serde_json::from_str(value).map_err(|_| Refused)?;
        if s.version != 1
            || !(1..=9_007_199_254_740_991).contains(&s.revision)
            || s.revision < minimum_revision
            || s.floors.len() > 128
            || s.owners.len() > 256
        {
            return Err(Refused);
        }
        let mut owners = BTreeMap::new();
        let mut floors = BTreeMap::new();
        for o in s.owners {
            let public = VerifyingKey::from_bytes(&o.public_key).map_err(|_| Refused)?;
            if !valid_issuer(&o.issuer)
                || !(1..=2).contains(&o.purpose)
                || public.is_weak()
                || owners.insert(o.public_key, (o.issuer, o.purpose)).is_some()
            {
                return Err(Refused);
            }
        }
        let mut active = Vec::new();
        for f in s.floors {
            let context = (f.issuer.clone(), f.purpose);
            if !valid_issuer(&f.issuer)
                || !(1..=2).contains(&f.purpose)
                || !(1..=9_007_199_254_740_991).contains(&f.epoch)
                || owners.get(&f.public_key) != Some(&context)
                || floors
                    .insert(
                        context,
                        Floor {
                            epoch: f.epoch,
                            public_key: f.public_key,
                            active: f.active,
                        },
                    )
                    .is_some()
            {
                return Err(Refused);
            }
            if f.active {
                active.push(Key {
                    issuer_ref: f.issuer,
                    purpose: if f.purpose == 1 {
                        Purpose::Authentication
                    } else {
                        Purpose::Permit
                    },
                    epoch: f.epoch,
                    public_key: f.public_key,
                });
            }
        }
        if owners.values().any(|context| !floors.contains_key(context)) {
            return Err(Refused);
        }
        let mut rebuilt = Self::compile(1, &active, None)?;
        rebuilt.revision = s.revision;
        rebuilt.floors = floors;
        rebuilt.key_owners = owners;
        Ok(rebuilt)
    }
    pub fn compile(
        revision: u64,
        desired: &[Key],
        previous: Option<&Self>,
    ) -> Result<Self, Refused> {
        if !(1..=9_007_199_254_740_991).contains(&revision)
            || desired.len() > 64
            || previous.is_some_and(|p| revision <= p.revision)
        {
            return Err(Refused);
        }
        let mut floors = previous.map(|p| p.floors.clone()).unwrap_or_default();
        let mut key_owners = previous.map(|p| p.key_owners.clone()).unwrap_or_default();
        let mut keys: BTreeMap<String, BTreeMap<(u8, u64), VerifyingKey>> = BTreeMap::new();
        let mut contexts = BTreeSet::new();
        let mut material = BTreeSet::new();
        for key in desired {
            if key.issuer_ref.is_empty()
                || key.issuer_ref.len() > 128
                || !key
                    .issuer_ref
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
                || !(1..=9_007_199_254_740_991).contains(&key.epoch)
                || !contexts.insert((key.issuer_ref.clone(), key.purpose as u8))
                || !material.insert(key.public_key)
            {
                return Err(Refused);
            }
            let public = VerifyingKey::from_bytes(&key.public_key).map_err(|_| Refused)?;
            if public.is_weak() {
                return Err(Refused);
            }
            let context = (key.issuer_ref.clone(), key.purpose as u8);
            if key_owners
                .get(&key.public_key)
                .is_some_and(|owner| owner != &context)
            {
                return Err(Refused);
            }
            if key_owners.contains_key(&key.public_key)
                && !floors.get(&context).is_some_and(|old| {
                    old.active && old.epoch == key.epoch && old.public_key == key.public_key
                })
            {
                // A compromised/retired private key cannot be made current by
                // assigning its old public material a larger epoch.
                return Err(Refused);
            }
            key_owners.insert(key.public_key, context.clone());
            if let Some(old) = floors.get(&context)
                && (key.epoch < old.epoch
                    || (key.epoch == old.epoch
                        && (!old.active || old.public_key != key.public_key)))
            {
                return Err(Refused);
            }
            keys.entry(key.issuer_ref.clone())
                .or_default()
                .insert((key.purpose as u8, key.epoch), public);
            floors.insert(
                context,
                Floor {
                    epoch: key.epoch,
                    public_key: key.public_key,
                    active: true,
                },
            );
        }
        for (context, floor) in &mut floors {
            if !contexts.contains(context) {
                floor.active = false;
            }
        }
        if floors.len() > 128 || key_owners.len() > 256 {
            return Err(Refused);
        }
        Ok(Self {
            revision,
            keys,
            floors,
            key_owners,
        })
    }
    /// Context and purpose come from native state; the wire carries no key selector.
    pub fn verify(
        &self,
        context: &Context<'_>,
        permit: Option<&Permit<'_>>,
        bytes: &[u8],
        now_ms: u64,
    ) -> Result<VerifiedReceipt, Refused> {
        let purpose = if permit.is_some() {
            Purpose::Permit
        } else {
            Purpose::Authentication
        };
        let key = self
            .keys
            .get(context.issuer_ref)
            .and_then(|keys| keys.get(&(purpose as u8, context.key_epoch)))
            .ok_or(Refused)?;
        let binding = receipt_binding::digest(context, permit).map_err(|_| Refused)?;
        receipt::verify(key, bytes, purpose, &binding, now_ms).map_err(|_| Refused)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn key(seed: u8, purpose: Purpose, epoch: u64) -> Key {
        Key {
            issuer_ref: "owned".into(),
            purpose,
            epoch,
            public_key: ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
                .verifying_key()
                .to_bytes(),
        }
    }
    #[test]
    fn historical_material_cannot_rotate_or_resurrect_at_a_larger_epoch_after_restart() {
        let first = Registry::compile(1, &[key(7, Purpose::Authentication, 1)], None).unwrap();
        assert!(Registry::compile(2, &[key(7, Purpose::Authentication, 2)], Some(&first)).is_err());
        let removed = Registry::compile(2, &[], Some(&first)).unwrap();
        let restored_history = Registry::decode(&removed.encode().unwrap(), 2).unwrap();
        assert!(
            Registry::compile(
                3,
                &[key(7, Purpose::Authentication, 2)],
                Some(&restored_history)
            )
            .is_err()
        );
        let renewed = Registry::compile(
            3,
            &[key(8, Purpose::Authentication, 2)],
            Some(&restored_history),
        )
        .unwrap();
        let restarted = Registry::decode(&renewed.encode().unwrap(), 3).unwrap();
        assert!(
            Registry::compile(4, &[key(7, Purpose::Authentication, 3)], Some(&restarted)).is_err()
        );
        assert!(
            Registry::compile(4, &[key(8, Purpose::Authentication, 2)], Some(&restarted)).is_ok()
        );
    }

    #[test]
    fn removed_keys_cannot_resurrect_or_roll_back() {
        let first = Registry::compile(1, &[key(7, Purpose::Authentication, 1)], None).unwrap();
        assert!(Registry::compile(1, &[], Some(&first)).is_err());
        assert!(Registry::compile(2, &[key(8, Purpose::Authentication, 1)], Some(&first)).is_err());
        let unchanged =
            Registry::compile(2, &[key(7, Purpose::Authentication, 1)], Some(&first)).unwrap();
        let removed = Registry::compile(3, &[], Some(&unchanged)).unwrap();
        assert!(
            Registry::compile(4, &[key(7, Purpose::Authentication, 1)], Some(&removed)).is_err()
        );
        let restored =
            Registry::compile(4, &[key(8, Purpose::Authentication, 2)], Some(&removed)).unwrap();
        assert!(
            Registry::compile(5, &[key(7, Purpose::Permit, 1)], Some(&restored)).is_err(),
            "retired authentication material became a permit key"
        );
        let mut reassigned = key(7, Purpose::Authentication, 2);
        reassigned.issuer_ref = "other".into();
        assert!(Registry::compile(5, &[reassigned], Some(&restored)).is_err());
        assert!(
            Registry::compile(5, &[key(7, Purpose::Authentication, 1)], Some(&restored)).is_err()
        );
        assert!(
            Registry::compile(
                1,
                &[
                    key(7, Purpose::Authentication, 1),
                    key(7, Purpose::Permit, 1)
                ],
                None
            )
            .is_err()
        );
        assert!(
            Registry::compile(
                1,
                &[
                    key(7, Purpose::Authentication, 1),
                    key(8, Purpose::Authentication, 2)
                ],
                None
            )
            .is_err()
        );
    }
    #[test]
    fn native_selection_refuses_stale_epoch_and_wrong_purpose_key() {
        use crate::{PrincipalKind, receipt_binding::Identity};
        let signer = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let mut context = Context {
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
            &receipt::Claims {
                purpose: Purpose::Authentication,
                issued_ms: 100,
                expires_ms: 1000,
                binding: receipt_binding::digest(&context, None).unwrap(),
                nonce: [8; 32],
            },
        )
        .unwrap();
        let old = Registry::compile(1, &[key(7, Purpose::Authentication, 1)], None).unwrap();
        assert!(old.verify(&context, None, &bytes, 101).is_ok());
        let changed =
            Registry::compile(2, &[key(8, Purpose::Authentication, 2)], Some(&old)).unwrap();
        assert!(changed.verify(&context, None, &bytes, 101).is_err());
        context.key_epoch = 2;
        assert!(changed.verify(&context, None, &bytes, 101).is_err());
        context.key_epoch = 1;
        let wrong = Registry::compile(1, &[key(7, Purpose::Permit, 1)], None).unwrap();
        assert!(wrong.verify(&context, None, &bytes, 101).is_err());
    }
}
