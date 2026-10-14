//! Canonical service ownership epoch for profile and application generations.
//! Parsing borrows the authority reference. Live owners must still be checked.
const MAX_REVISION: u64 = 9_007_199_254_740_991;
#[derive(Debug, PartialEq, Eq)]
pub struct Refused;
#[derive(Debug, PartialEq, Eq)]
pub struct Epoch<'a> {
    pub authority: &'a str,
    pub profile_revision: u64,
    pub application_generation: u64,
}
fn authority(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 96
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
}
fn revision(value: &str) -> Result<u64, Refused> {
    if value.is_empty()
        || value.len() > 16
        || value.starts_with('0')
        || !value.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(Refused);
    }
    let result = value.parse::<u64>().map_err(|_| Refused)?;
    if !(1..=MAX_REVISION).contains(&result) {
        return Err(Refused);
    }
    Ok(result)
}
pub fn encode(base: &str, profile: u64, application: u64) -> Result<String, Refused> {
    if !authority(base)
        || !(1..=MAX_REVISION).contains(&profile)
        || !(1..=MAX_REVISION).contains(&application)
    {
        return Err(Refused);
    }
    let result = format!("{base}:service:{profile}:app:{application}");
    if result.len() > 128 {
        return Err(Refused);
    }
    Ok(result)
}
pub fn decode(value: &str) -> Result<Epoch<'_>, Refused> {
    if value.len() > 128 {
        return Err(Refused);
    }
    let (prefix, application) = value.rsplit_once(":app:").ok_or(Refused)?;
    let (base, profile) = prefix.rsplit_once(":service:").ok_or(Refused)?;
    if !authority(base) {
        return Err(Refused);
    }
    Ok(Epoch {
        authority: base,
        profile_revision: revision(profile)?,
        application_generation: revision(application)?,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn canonical_borrowed_epoch_binds_both_owners() {
        let value = encode("owned:realm", 7, 11).unwrap();
        assert_eq!(value, "owned:realm:service:7:app:11");
        let epoch = decode(&value).unwrap();
        assert_eq!(epoch.authority, "owned:realm");
        assert_eq!(epoch.profile_revision, 7);
        assert_eq!(epoch.application_generation, 11);
        assert_eq!(epoch.authority.as_ptr(), value.as_ptr());
        assert_ne!(value, encode("owned:realm", 8, 11).unwrap());
        assert_ne!(value, encode("owned:realm", 7, 12).unwrap());
    }
    #[test]
    fn signed_receipt_refuses_a_changed_application_owner() {
        use crate::{PrincipalKind, receipt, receipt_binding};
        let first = encode("owned", 7, 11).unwrap();
        let changed = encode("owned", 7, 12).unwrap();
        let mut context = receipt_binding::Context {
            issuer_ref: "hopae",
            key_epoch: 1,
            identity_authority_epoch: &first,
            identity: receipt_binding::Identity {
                subject_ref: "service-worker",
                kind: PrincipalKind::Service,
                aal: 0,
                revision: 7,
                credential_generation: 7,
            },
            service: "orders",
            audience: "orders-api",
            request_sha256: [3; 32],
        };
        let key = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
        let bytes = receipt::sign(
            &key,
            &receipt::Claims {
                purpose: receipt::Purpose::Authentication,
                issued_ms: 1000,
                expires_ms: 1800,
                binding: receipt_binding::digest(&context, None).unwrap(),
                nonce: [7; 32],
            },
        )
        .unwrap();
        assert!(
            receipt::verify(
                &key.verifying_key(),
                &bytes,
                receipt::Purpose::Authentication,
                &receipt_binding::digest(&context, None).unwrap(),
                1001
            )
            .is_ok()
        );
        context.identity_authority_epoch = &changed;
        assert!(
            receipt::verify(
                &key.verifying_key(),
                &bytes,
                receipt::Purpose::Authentication,
                &receipt_binding::digest(&context, None).unwrap(),
                1001
            )
            .is_err()
        );
    }
    #[test]
    fn absent_noncanonical_unbounded_or_rollback_values_are_refused() {
        for value in [
            "owned:service:7",
            "owned:service:07:app:1",
            "owned:service:1:app:01",
            "owned:service:0:app:1",
            "owned:service:1:app:0",
            "owned:service:+1:app:1",
            "owned:service:1:app:9007199254740992",
            "owned:service:1:app:1:extra",
            ":service:1:app:1",
            "bad realm:service:1:app:1",
        ] {
            assert!(decode(value).is_err(), "{value}");
        }
        assert!(encode("owned", 0, 1).is_err());
        assert!(encode("owned", 1, MAX_REVISION + 1).is_err());
        assert!(encode(&"a".repeat(96), MAX_REVISION, MAX_REVISION).is_err());
    }
}
