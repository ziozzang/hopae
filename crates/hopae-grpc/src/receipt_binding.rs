//! Canonical native receipt context. Digest construction alone authenticates
//! nothing: each field must come from its verified owner before signing/checking.
use crate::PrincipalKind;
use sha2::{Digest as _, Sha256};

pub struct Identity<'a> {
    pub subject_ref: &'a str,
    pub kind: PrincipalKind,
    pub aal: u8,
    pub revision: u64,
    pub credential_generation: u64,
}
pub struct Context<'a> {
    pub issuer_ref: &'a str,
    pub key_epoch: u64,
    pub identity_authority_epoch: &'a str,
    pub identity: Identity<'a>,
    pub service: &'a str,
    pub audience: &'a str,
    pub request_sha256: [u8; 32],
}
pub struct Permit<'a> {
    pub authentication_receipt_sha256: [u8; 32],
    pub decision_ref: &'a str,
    pub resource: &'a str,
    pub action: &'a str,
    pub authority_epoch: &'a str,
    pub catalog_revision: u64,
    pub policy_revision: u64,
    pub network_revision: u64,
    pub route_revision: u64,
    pub plan_revision: u64,
}
#[derive(Debug, PartialEq, Eq)]
pub struct InvalidBinding;
fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
}
fn revision(value: u64) -> bool {
    (1..=9_007_199_254_740_991).contains(&value)
}
fn field(hash: &mut Sha256, bytes: &[u8]) {
    hash.update((bytes.len() as u32).to_be_bytes());
    hash.update(bytes);
}
/// Authentication excludes unowned policy/network assertions. A permit adds
/// owner revisions and the hash of the exact signed authentication receipt.
pub fn digest(
    context: &Context<'_>,
    permit: Option<&Permit<'_>>,
) -> Result<[u8; 32], InvalidBinding> {
    if [
        context.issuer_ref,
        context.identity_authority_epoch,
        context.identity.subject_ref,
        context.service,
        context.audience,
    ]
    .iter()
    .any(|v| !identifier(v))
        || !revision(context.key_epoch)
        || !revision(context.identity.revision)
        || !revision(context.identity.credential_generation)
        || match context.identity.kind {
            PrincipalKind::Human => !(1..=3).contains(&context.identity.aal),
            _ => context.identity.aal != 0,
        }
    {
        return Err(InvalidBinding);
    }
    if let Some(p) = permit
        && ([p.decision_ref, p.resource, p.action, p.authority_epoch]
            .iter()
            .any(|v| !identifier(v))
            || [
                p.catalog_revision,
                p.policy_revision,
                p.network_revision,
                p.route_revision,
                p.plan_revision,
            ]
            .iter()
            .any(|v| !revision(*v))
            || p.authentication_receipt_sha256 == [0; 32])
    {
        return Err(InvalidBinding);
    }
    let mut hash = Sha256::new();
    hash.update(b"hangang-zerotrust:projection-receipt-binding:v1\0");
    field(&mut hash, &[if permit.is_some() { 2 } else { 1 }]);
    field(&mut hash, context.issuer_ref.as_bytes());
    field(&mut hash, &context.key_epoch.to_be_bytes());
    field(&mut hash, context.identity_authority_epoch.as_bytes());
    field(&mut hash, context.identity.subject_ref.as_bytes());
    field(
        &mut hash,
        &[match context.identity.kind {
            PrincipalKind::Human => 1,
            PrincipalKind::Service => 2,
            PrincipalKind::Workload => 3,
            PrincipalKind::Network => 4,
        }],
    );
    field(&mut hash, &[context.identity.aal]);
    field(&mut hash, &context.identity.revision.to_be_bytes());
    field(
        &mut hash,
        &context.identity.credential_generation.to_be_bytes(),
    );
    field(&mut hash, context.service.as_bytes());
    field(&mut hash, context.audience.as_bytes());
    field(&mut hash, &context.request_sha256);
    if let Some(p) = permit {
        field(&mut hash, &p.authentication_receipt_sha256);
        for value in [p.decision_ref, p.resource, p.action, p.authority_epoch] {
            field(&mut hash, value.as_bytes());
        }
        for value in [
            p.catalog_revision,
            p.policy_revision,
            p.network_revision,
            p.route_revision,
            p.plan_revision,
        ] {
            field(&mut hash, &value.to_be_bytes());
        }
    }
    Ok(hash.finalize().into())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn context() -> Context<'static> {
        Context {
            issuer_ref: "owned-issuer",
            key_epoch: 1,
            identity_authority_epoch: "identity-epoch-1",
            identity: Identity {
                subject_ref: "owned-subject",
                kind: PrincipalKind::Service,
                aal: 0,
                revision: 1,
                credential_generation: 1,
            },
            service: "orders",
            audience: "orders-api",
            request_sha256: [3; 32],
        }
    }
    fn permit() -> Permit<'static> {
        Permit {
            authentication_receipt_sha256: [4; 32],
            decision_ref: "decision-1",
            resource: "orders",
            action: "read",
            authority_epoch: "epoch-1",
            catalog_revision: 1,
            policy_revision: 1,
            network_revision: 1,
            route_revision: 1,
            plan_revision: 1,
        }
    }
    #[test]
    fn identity_authority_and_request_changes_cannot_share_binding() {
        let original = digest(&context(), None).unwrap();
        assert_eq!(
            original
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
            "d81e90ebd0d14bfbad3d0274ab37e4bb82c4231a436f0f340f96ff6cb460ca5b"
        );
        let mutators: [fn(&mut Context<'static>); 10] = [
            |c| c.identity.subject_ref = "other",
            |c| c.issuer_ref = "other",
            |c| c.key_epoch = 2,
            |c| c.identity_authority_epoch = "identity-epoch-2",
            |c| c.identity.revision = 2,
            |c| c.identity.credential_generation = 2,
            |c| c.service = "other",
            |c| c.audience = "other",
            |c| c.request_sha256 = [5; 32],
            |c| c.identity.kind = PrincipalKind::Network,
        ];
        for mutate in mutators {
            let mut c = context();
            mutate(&mut c);
            assert_ne!(digest(&c, None).unwrap(), original);
        }
        let mut c = context();
        c.identity.aal = 2;
        assert!(digest(&c, None).is_err());
        c.identity.kind = PrincipalKind::Human;
        assert!(digest(&c, None).is_ok());
        c.identity.aal = 0;
        assert!(digest(&c, None).is_err());
        c.key_epoch = 0;
        assert!(digest(&c, None).is_err());
    }
    #[test]
    fn permit_chain_and_all_owner_versions_are_bound() {
        let c = context();
        let original = digest(&c, Some(&permit())).unwrap();
        assert_eq!(
            original
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
            "a6836c5ee53ad2ae81ec7f9cf25690dd4247148cbf92bfe100adc3cb3957f612"
        );
        assert_ne!(original, digest(&c, None).unwrap());
        let mutators: [fn(&mut Permit<'static>); 10] = [
            |p| p.authentication_receipt_sha256 = [5; 32],
            |p| p.decision_ref = "other",
            |p| p.resource = "other",
            |p| p.action = "write",
            |p| p.authority_epoch = "other",
            |p| p.catalog_revision = 2,
            |p| p.policy_revision = 2,
            |p| p.network_revision = 2,
            |p| p.route_revision = 2,
            |p| p.plan_revision = 2,
        ];
        for mutate in mutators {
            let mut p = permit();
            mutate(&mut p);
            assert_ne!(digest(&c, Some(&p)).unwrap(), original);
        }
        let mut p = permit();
        p.plan_revision = 0;
        assert!(digest(&c, Some(&p)).is_err());
        p.plan_revision = 1;
        p.authentication_receipt_sha256 = [0; 32];
        assert!(digest(&c, Some(&p)).is_err());
    }

    #[test]
    fn signed_permit_refuses_other_identity_epoch_plan_and_authentication_chain() {
        use super::super::receipt::{self, Claims, Purpose};
        let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let mut c = context();
        let mut p = permit();
        let claims = Claims {
            purpose: Purpose::Permit,
            issued_ms: 100,
            expires_ms: 1000,
            binding: digest(&c, Some(&p)).unwrap(),
            nonce: [8; 32],
        };
        let bytes = receipt::sign(&key, &claims).unwrap();
        assert!(
            receipt::verify(
                &key.verifying_key(),
                &bytes,
                Purpose::Permit,
                &digest(&c, Some(&p)).unwrap(),
                101
            )
            .is_ok()
        );
        c.identity_authority_epoch = "new-epoch";
        assert!(
            receipt::verify(
                &key.verifying_key(),
                &bytes,
                Purpose::Permit,
                &digest(&c, Some(&p)).unwrap(),
                101
            )
            .is_err()
        );
        c = context();
        p.plan_revision = 2;
        assert!(
            receipt::verify(
                &key.verifying_key(),
                &bytes,
                Purpose::Permit,
                &digest(&c, Some(&p)).unwrap(),
                101
            )
            .is_err()
        );
        p = permit();
        p.authentication_receipt_sha256 = [9; 32];
        assert!(
            receipt::verify(
                &key.verifying_key(),
                &bytes,
                Purpose::Permit,
                &digest(&c, Some(&p)).unwrap(),
                101
            )
            .is_err()
        );
        assert!(
            receipt::verify(
                &key.verifying_key(),
                &bytes,
                Purpose::Authentication,
                &digest(&c, None).unwrap(),
                101
            )
            .is_err()
        );
    }
}
