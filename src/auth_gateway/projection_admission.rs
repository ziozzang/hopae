//! Authenticated chain admission, before credential resolution. Native owners must
//! supply contexts and recheck live identity, policy, network and plan in `guard`.
use super::{
    receipt_authority::{Checked, Verifier},
    receipt_binding::{Context, Permit},
    receipt_keys::Refused,
    receipt_replay,
};
use sha2::{Digest as _, Sha256};

pub struct Input<'a> {
    pub authentication_context: &'a Context<'a>,
    pub authentication_receipt: &'a [u8],
    pub permission_context: &'a Context<'a>,
    pub permit: &'a Permit<'a>,
    pub permission_receipt: &'a [u8],
}
/// A verified chain, not a permission to emit credentials. Fields are private and
/// the pair cannot be cloned; durable single-use admission still occurs in consume.
pub struct Admission {
    authentication: Checked,
    permission: Checked,
    pub(crate) scope: super::projection::Scope,
}
pub fn verify(verifier: &Verifier, input: Input<'_>, now: u64) -> Result<Admission, Refused> {
    validate_chain(&input)?;
    let a = input.authentication_context;
    let p = input.permission_context;
    let authentication = verifier.verify(a, None, input.authentication_receipt, now)?;
    let permission = verifier.verify(p, Some(input.permit), input.permission_receipt, now)?;
    if authentication.revision() != permission.revision() {
        return Err(Refused);
    }
    Ok(Admission {
        scope: super::projection::Scope {
            service: a.service.to_owned(),
            audience: a.audience.to_owned(),
            subject: a.identity.subject_ref.to_owned(),
            resource: input.permit.resource.to_owned(),
            action: input.permit.action.to_owned(),
            aal: a.identity.aal,
            request_sha256: a.request_sha256,
            plan_revision: input.permit.plan_revision,
            issued_ms: authentication
                .receipt()
                .claims()
                .issued_ms
                .max(permission.receipt().claims().issued_ms),
            expires_ms: authentication
                .receipt()
                .claims()
                .expires_ms
                .min(permission.receipt().claims().expires_ms),
        },
        authentication,
        permission,
    })
}
pub(crate) fn validate_chain(input: &Input<'_>) -> Result<(), Refused> {
    let a = input.authentication_context;
    let p = input.permission_context;
    if a.identity_authority_epoch != p.identity_authority_epoch
        || a.identity.subject_ref != p.identity.subject_ref
        || a.identity.kind != p.identity.kind
        || a.identity.aal != p.identity.aal
        || a.identity.revision != p.identity.revision
        || a.identity.credential_generation != p.identity.credential_generation
        || a.service != p.service
        || a.audience != p.audience
        || a.request_sha256 != p.request_sha256
        || <[u8; 32]>::from(Sha256::digest(input.authentication_receipt))
            != input.permit.authentication_receipt_sha256
    {
        return Err(Refused);
    }
    Ok(())
}
impl Admission {
    pub(crate) fn restrict_expiry(&mut self, expiry: u64) -> Result<(), Refused> {
        self.scope.expires_ms = self.scope.expires_ms.min(expiry);
        if self.scope.expires_ms <= self.scope.issued_ms {
            return Err(Refused);
        }
        Ok(())
    }

    /// Consume both receipts and associated owner DB work in one transaction.
    /// Guard must inspect authoritative current state twice. Credential output and
    /// irreversible network effects must occur only after this returns success.
    pub fn consume<T, D: crate::store::meta::MetaDb>(
        self,
        db: &mut D,
        clock: &dyn Fn() -> u64,
        guard: &dyn Fn(&dyn crate::store::meta::MetaTx) -> Result<(), Refused>,
        operation: impl FnOnce(&dyn crate::store::meta::MetaTx) -> Result<T, Refused>,
    ) -> Result<T, Refused> {
        receipt_replay::consume_group(
            db,
            &[&self.authentication, &self.permission],
            clock,
            guard,
            operation,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth_gateway::{
        PrincipalKind,
        receipt::{self, Claims, Purpose},
        receipt_authority::Authority,
        receipt_binding::{self, Identity},
        receipt_keys::Key,
    };
    use rusqlite::Connection;
    use rusqlite::OptionalExtension;
    struct Fixture {
        db: Connection,
        owner: Authority,
        auth: [u8; receipt::LENGTH],
        permission: [u8; receipt::LENGTH],
        auth_context: Context<'static>,
        permission_context: Context<'static>,
        permit: Permit<'static>,
        permission_signer: ed25519_dalek::SigningKey,
    }
    impl Fixture {
        fn new() -> Self {
            let mut db = Connection::open_in_memory().unwrap();
            db.execute_batch("CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT NOT NULL)")
                .unwrap();
            let mut owner = Authority::load(&db, 0).unwrap();
            let auth_signer = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
            let permission_signer = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
            owner
                .publish(
                    &mut db,
                    0,
                    &[
                        Key {
                            issuer_ref: "hopae".into(),
                            purpose: Purpose::Authentication,
                            epoch: 1,
                            public_key: auth_signer.verifying_key().to_bytes(),
                        },
                        Key {
                            issuer_ref: "pumgye".into(),
                            purpose: Purpose::Permit,
                            epoch: 1,
                            public_key: permission_signer.verifying_key().to_bytes(),
                        },
                    ],
                    "operator",
                    &|_| Ok(()),
                )
                .unwrap();
            fn context(issuer_ref: &'static str) -> Context<'static> {
                Context {
                    issuer_ref,
                    key_epoch: 1,
                    identity_authority_epoch: "identity-1",
                    identity: Identity {
                        subject_ref: "owned-user",
                        kind: PrincipalKind::Human,
                        aal: 2,
                        revision: 1,
                        credential_generation: 1,
                    },
                    service: "orders",
                    audience: "orders-api",
                    request_sha256: [4; 32],
                }
            }
            let auth_context = context("hopae");
            let permission_context = context("pumgye");
            let auth = receipt::sign(
                &auth_signer,
                &Claims {
                    purpose: Purpose::Authentication,
                    issued_ms: 100,
                    expires_ms: 900,
                    binding: receipt_binding::digest(&auth_context, None).unwrap(),
                    nonce: [8; 32],
                },
            )
            .unwrap();
            let permit = Permit {
                authentication_receipt_sha256: Sha256::digest(auth).into(),
                decision_ref: "decision-1",
                resource: "orders",
                action: "read",
                authority_epoch: "policy-1",
                catalog_revision: 1,
                policy_revision: 1,
                network_revision: 1,
                route_revision: 1,
                plan_revision: 1,
            };
            let permission =
                Self::sign_permission(&permission_signer, &permission_context, &permit);
            Self {
                db,
                owner,
                auth,
                permission,
                auth_context,
                permission_context,
                permit,
                permission_signer,
            }
        }
        fn sign_permission(
            signer: &ed25519_dalek::SigningKey,
            context: &Context<'_>,
            permit: &Permit<'_>,
        ) -> [u8; receipt::LENGTH] {
            receipt::sign(
                signer,
                &Claims {
                    purpose: Purpose::Permit,
                    issued_ms: 101,
                    expires_ms: 950,
                    binding: receipt_binding::digest(context, Some(permit)).unwrap(),
                    nonce: [10; 32],
                },
            )
            .unwrap()
        }
        fn admission(&self) -> Result<Admission, Refused> {
            verify(
                &self.owner.verifier(),
                Input {
                    authentication_context: &self.auth_context,
                    authentication_receipt: &self.auth,
                    permission_context: &self.permission_context,
                    permit: &self.permit,
                    permission_receipt: &self.permission,
                },
                102,
            )
        }
        fn nonce_count(&self) -> u64 {
            self.db
                .query_row(
                    "SELECT count(*) FROM meta WHERE key LIKE 'projection_nonce_id:%'",
                    [],
                    |row| row.get(0),
                )
                .unwrap()
        }
    }
    #[test]
    fn signed_chain_must_preserve_identity_request_and_authentication_hash() {
        let mut f = Fixture::new();
        assert!(f.admission().is_ok());
        // Each conflicting permit is genuinely signed by the trusted policy key.
        // Signature verification alone must not authorize a different identity.
        for field in 0..10 {
            f.permission_context = Context {
                issuer_ref: "pumgye",
                key_epoch: 1,
                identity_authority_epoch: "identity-1",
                identity: Identity {
                    subject_ref: "owned-user",
                    kind: PrincipalKind::Human,
                    aal: 2,
                    revision: 1,
                    credential_generation: 1,
                },
                service: "orders",
                audience: "orders-api",
                request_sha256: [4; 32],
            };
            f.permit.authentication_receipt_sha256 = Sha256::digest(f.auth).into();
            match field {
                0 => f.permission_context.identity_authority_epoch = "identity-2",
                1 => f.permission_context.identity.subject_ref = "another-user",
                2 => {
                    f.permission_context.identity.kind = PrincipalKind::Service;
                    f.permission_context.identity.aal = 0;
                }
                3 => f.permission_context.identity.aal = 3,
                4 => f.permission_context.identity.revision = 2,
                5 => f.permission_context.identity.credential_generation = 2,
                6 => f.permission_context.service = "billing",
                7 => f.permission_context.audience = "billing-api",
                8 => f.permission_context.request_sha256 = [5; 32],
                _ => f.permit.authentication_receipt_sha256 = [6; 32],
            }
            f.permission =
                Fixture::sign_permission(&f.permission_signer, &f.permission_context, &f.permit);
            assert!(
                f.owner
                    .verifier()
                    .verify(&f.permission_context, Some(&f.permit), &f.permission, 102)
                    .is_ok()
            );
            assert!(f.admission().is_err());
            assert_eq!(f.nonce_count(), 0);
        }
    }
    #[test]
    fn both_nonces_and_owner_work_commit_or_roll_back_together() {
        let mut f = Fixture::new();
        let clock = std::cell::Cell::new(102);
        let result =
            f.admission()
                .unwrap()
                .consume(&mut f.db, &|| clock.get(), &|_| Ok(()), |tx| {
                    tx.sqlite()
                        .unwrap()
                        .execute(
                            "INSERT INTO meta(key,value) VALUES('issued-fixture','1')",
                            [],
                        )
                        .map_err(|_| Refused)?;
                    clock.set(900); // Authentication expires first, while permit remains valid.
                    Ok(())
                });
        assert!(result.is_err());
        assert_eq!(f.nonce_count(), 0);
        assert_eq!(
            f.db.query_row(
                "SELECT count(*) FROM meta WHERE key='issued-fixture'",
                [],
                |r| r.get::<_, u64>(0)
            )
            .unwrap(),
            0
        );
        f.admission()
            .unwrap()
            .consume(&mut f.db, &|| 102, &|_| Ok(()), |tx| {
                tx.sqlite()
                    .unwrap()
                    .execute(
                        "INSERT INTO meta(key,value) VALUES('issued-fixture','1')",
                        [],
                    )
                    .map_err(|_| Refused)?;
                Ok(())
            })
            .unwrap();
        assert_eq!(f.nonce_count(), 2);
        assert!(
            f.admission()
                .unwrap()
                .consume::<(), _>(&mut f.db, &|| 103, &|_| Ok(()), |_| panic!(
                    "replay reached owner work"
                ))
                .is_err()
        );
    }
    #[test]
    fn already_consumed_permission_rolls_back_authentication_admission() {
        let mut f = Fixture::new();
        let checked = f
            .owner
            .verifier()
            .verify(&f.permission_context, Some(&f.permit), &f.permission, 102)
            .unwrap();
        receipt_replay::consume(&mut f.db, &checked, &|| 102, &|_| Ok(()), |_| Ok(())).unwrap();
        assert!(
            f.admission()
                .unwrap()
                .consume::<(), _>(&mut f.db, &|| 103, &|_| Ok(()), |_| panic!(
                    "used permission reached work"
                ))
                .is_err()
        );
        assert_eq!(f.nonce_count(), 1);
        let checked = f
            .owner
            .verifier()
            .verify(&f.auth_context, None, &f.auth, 103)
            .unwrap();
        receipt_replay::consume(&mut f.db, &checked, &|| 103, &|_| Ok(()), |_| Ok(())).unwrap();
        assert_eq!(f.nonce_count(), 2);
    }
    #[test]
    fn independent_connections_commit_one_complete_chain() {
        let f = Fixture::new();
        let file = tempfile::NamedTempFile::new().unwrap();
        let db = Connection::open(file.path()).unwrap();
        db.execute_batch("CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT NOT NULL)")
            .unwrap();
        let mut query = f.db.prepare("SELECT key,value FROM meta").unwrap();
        for row in query
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
            .unwrap()
        {
            let (key, value) = row.unwrap();
            db.execute(
                "INSERT INTO meta(key,value) VALUES(?1,?2)",
                rusqlite::params![key, value],
            )
            .unwrap();
        }
        let verifier = f.owner.verifier();
        let auth_context = &f.auth_context;
        let permission_context = &f.permission_context;
        let auth = &f.auth;
        let permission = &f.permission;
        let permit = &f.permit;
        let barrier = std::sync::Barrier::new(8);
        let successes = std::thread::scope(|scope| {
            let mut threads = Vec::new();
            for _ in 0..8 {
                let path = file.path();
                let verifier = &verifier;
                let barrier = &barrier;
                threads.push(scope.spawn(move || {
                    let mut db = Connection::open(path).unwrap();
                    db.busy_timeout(std::time::Duration::from_secs(2)).unwrap();
                    let admitted = verify(verifier, Input { authentication_context: auth_context, authentication_receipt: auth, permission_context, permission_receipt: permission, permit }, 102).unwrap();
                    barrier.wait();
                    admitted.consume(&mut db, &|| 102, &|_| Ok(()), |tx| {
                        let count = tx.sqlite().unwrap().query_row("SELECT value FROM meta WHERE key='issued-fixture'", [], |r| r.get::<_,String>(0)).optional().map_err(|_| Refused)?.unwrap_or_else(|| "0".into()).parse::<u64>().map_err(|_| Refused)?;
                        tx.sqlite().unwrap().execute("INSERT INTO meta(key,value) VALUES('issued-fixture',?1) ON CONFLICT(key) DO UPDATE SET value=excluded.value", [(count+1).to_string()]).map_err(|_| Refused)?;
                        Ok(())
                    }).is_ok()
                }));
            }
            threads
                .into_iter()
                .map(|t| t.join().unwrap())
                .filter(|ok| *ok)
                .count()
        });
        assert_eq!(successes, 1);
        assert_eq!(
            db.query_row(
                "SELECT count(*) FROM meta WHERE key LIKE 'projection_nonce_id:%'",
                [],
                |r| r.get::<_, u64>(0)
            )
            .unwrap(),
            2
        );
        assert_eq!(
            db.query_row(
                "SELECT value FROM meta WHERE key='projection_nonce_count_v1'",
                [],
                |r| r.get::<_, String>(0)
            )
            .unwrap(),
            "2"
        );
        assert_eq!(
            db.query_row(
                "SELECT value FROM meta WHERE key='issued-fixture'",
                [],
                |r| r.get::<_, String>(0)
            )
            .unwrap(),
            "1"
        );
    }
    fn projector(
        revision: u64,
        minimum_aal: u8,
        credential: super::super::projection::Credential,
    ) -> super::super::projection::Projector {
        use super::super::projection::{Configuration, Plan, Projector};
        Projector::compile(Configuration {
            revision,
            plans: vec![Plan {
                service: "orders".into(),
                audience: "orders-api".into(),
                resource: "orders".into(),
                action: "read".into(),
                minimum_aal,
                credential,
            }],
        })
        .unwrap()
    }
    #[test]
    fn projection_resolves_only_after_admission_and_rolls_back_late_revocation() {
        use super::super::projection::Credential;
        let mut f = Fixture::new();
        let projector = projector(
            1,
            2,
            Credential::BearerReference {
                secret_ref: "owned-token".into(),
            },
        );
        let calls = std::cell::Cell::new(0);
        let resolve = |reference: &str| {
            assert_eq!(reference, "owned-token");
            calls.set(calls.get() + 1);
            Ok(zeroize::Zeroizing::new("owned-example-token".to_owned()))
        };
        assert!(
            projector
                .project(
                    f.admission().unwrap(),
                    &mut f.db,
                    &|| 102,
                    &|_| Err(Refused),
                    &resolve
                )
                .is_err()
        );
        assert_eq!(calls.get(), 0);
        assert_eq!(f.nonce_count(), 0);
        let guards = std::cell::Cell::new(0);
        assert!(
            projector
                .project(
                    f.admission().unwrap(),
                    &mut f.db,
                    &|| 102,
                    &|_| {
                        guards.set(guards.get() + 1);
                        if guards.get() == 2 {
                            Err(Refused)
                        } else {
                            Ok(())
                        }
                    },
                    &resolve
                )
                .is_err()
        );
        assert_eq!(calls.get(), 1);
        assert_eq!(f.nonce_count(), 0);
        let output = projector
            .project(
                f.admission().unwrap(),
                &mut f.db,
                &|| 102,
                &|_| Ok(()),
                &resolve,
            )
            .unwrap();
        let (name, value) = output
            .into_header("orders", "orders-api", &[4; 32], 103)
            .unwrap();
        assert_eq!(name, http::header::AUTHORIZATION);
        assert_eq!(value.to_str().unwrap(), "Bearer owned-example-token");
        assert!(value.is_sensitive());
        assert!(!format!("{value:?}").contains("owned-example-token"));
        assert_eq!(f.nonce_count(), 2);
        assert!(
            projector
                .project(
                    f.admission().unwrap(),
                    &mut f.db,
                    &|| 103,
                    &|_| Ok(()),
                    &resolve
                )
                .is_err()
        );
        assert_eq!(calls.get(), 2);
    }
    #[test]
    fn native_plan_revision_assurance_and_permission_scope_precede_secret_resolution() {
        use super::super::projection::Credential;
        for mismatch in 0..4 {
            let mut f = Fixture::new();
            if mismatch >= 2 {
                if mismatch == 2 {
                    f.permit.resource = "billing";
                } else {
                    f.permit.action = "write";
                }
                f.permission = Fixture::sign_permission(
                    &f.permission_signer,
                    &f.permission_context,
                    &f.permit,
                );
            }
            let projector = projector(
                if mismatch == 0 { 2 } else { 1 },
                if mismatch == 1 { 3 } else { 2 },
                Credential::BearerReference {
                    secret_ref: "owned-token".into(),
                },
            );
            assert!(
                projector
                    .project(
                        f.admission().unwrap(),
                        &mut f.db,
                        &|| 102,
                        &|_| Ok(()),
                        &|_| panic!("mismatched plan resolved a credential")
                    )
                    .is_err()
            );
            assert_eq!(f.nonce_count(), 0);
        }
    }
    #[test]
    fn projection_output_is_bound_and_identity_headers_need_no_secret_capability() {
        use super::super::projection::Credential;
        for mismatch in 0..6 {
            let mut f = Fixture::new();
            let output = projector(1, 2, Credential::IdentityHeader)
                .project(
                    f.admission().unwrap(),
                    &mut f.db,
                    &|| 102,
                    &|_| Ok(()),
                    &|_| panic!("identity projection requested a secret"),
                )
                .unwrap();
            let result = output.into_header(
                if mismatch == 0 { "billing" } else { "orders" },
                if mismatch == 1 {
                    "billing-api"
                } else {
                    "orders-api"
                },
                &if mismatch == 2 { [5; 32] } else { [4; 32] },
                match mismatch {
                    3 => 900,
                    4 => 100,
                    _ => 103,
                },
            );
            if mismatch < 5 {
                assert!(result.is_err());
            } else {
                let (name, value) = result.unwrap();
                assert_eq!(name, "x-hopae-subject");
                assert_eq!(value.to_str().unwrap(), "owned-user");
            }
        }
    }
    #[test]
    fn malformed_or_unavailable_bearer_reference_leaves_receipts_reusable() {
        use super::super::projection::Credential;
        for token in [
            "",
            "=",
            "bad\r\nInjected: true",
            "bad token",
            "bad=middle",
            "nonascii-é",
        ] {
            let mut f = Fixture::new();
            let projector = projector(
                1,
                2,
                Credential::BearerReference {
                    secret_ref: "owned-token".into(),
                },
            );
            assert!(
                projector
                    .project(
                        f.admission().unwrap(),
                        &mut f.db,
                        &|| 102,
                        &|_| Ok(()),
                        &|_| Ok(zeroize::Zeroizing::new(token.to_owned()))
                    )
                    .is_err()
            );
            assert_eq!(f.nonce_count(), 0);
            assert!(
                projector
                    .project(
                        f.admission().unwrap(),
                        &mut f.db,
                        &|| 102,
                        &|_| Ok(()),
                        &|_| Err(Refused)
                    )
                    .is_err()
            );
            assert_eq!(f.nonce_count(), 0);
            assert!(
                projector
                    .project(
                        f.admission().unwrap(),
                        &mut f.db,
                        &|| 102,
                        &|_| Ok(()),
                        &|_| Ok(zeroize::Zeroizing::new("valid-example==".to_owned()))
                    )
                    .is_ok()
            );
        }
    }
    #[test]
    fn durable_plan_removal_blocks_retained_reader_and_reenable_requires_new_permit() {
        use super::super::projection::{Configuration, Credential, Plan};
        use super::super::projection_authority::Authority as PlanAuthority;
        let mut f = Fixture::new();
        let mut owner = PlanAuthority::load(&f.db, 0).unwrap();
        let configuration = |revision| Configuration {
            revision,
            plans: vec![Plan {
                service: "orders".into(),
                audience: "orders-api".into(),
                resource: "orders".into(),
                action: "read".into(),
                minimum_aal: 2,
                credential: Credential::BearerReference {
                    secret_ref: "owned-token".into(),
                },
            }],
        };
        owner
            .publish(
                &mut f.db,
                0,
                Some(configuration(1)),
                "operator",
                &|_| Ok(()),
            )
            .unwrap();
        let reader = owner.reader();
        let retained = reader.load_full();
        owner
            .publish(&mut f.db, 1, None, "operator", &|_| Ok(()))
            .unwrap();
        assert!(
            retained
                .project(
                    f.admission().unwrap(),
                    &mut f.db,
                    &|| 102,
                    &|_| Ok(()),
                    &|_| panic!("retired snapshot resolved a secret")
                )
                .is_err()
        );
        assert_eq!(f.nonce_count(), 0);
        assert!(
            reader
                .load()
                .project(
                    f.admission().unwrap(),
                    &mut f.db,
                    &|| 102,
                    &|_| Ok(()),
                    &|_| panic!("disabled snapshot resolved a secret")
                )
                .is_err()
        );
        owner
            .publish(
                &mut f.db,
                2,
                Some(configuration(3)),
                "operator",
                &|_| Ok(()),
            )
            .unwrap();
        assert!(
            reader
                .load()
                .project(
                    f.admission().unwrap(),
                    &mut f.db,
                    &|| 102,
                    &|_| Ok(()),
                    &|_| panic!("old permit resolved a secret")
                )
                .is_err()
        );
        assert_eq!(f.nonce_count(), 0);
        f.permit.plan_revision = 3;
        f.permission =
            Fixture::sign_permission(&f.permission_signer, &f.permission_context, &f.permit);
        let restarted = PlanAuthority::load(&f.db, 3).unwrap();
        let output = restarted
            .reader()
            .load()
            .project(
                f.admission().unwrap(),
                &mut f.db,
                &|| 102,
                &|_| Ok(()),
                &|_| Ok(zeroize::Zeroizing::new("owned-example-token".into())),
            )
            .unwrap();
        assert!(
            output
                .into_header("orders", "orders-api", &[4; 32], 103)
                .is_ok()
        );
        assert_eq!(f.nonce_count(), 2);
    }
    #[test]
    fn plan_change_inside_final_guard_cannot_release_projected_secret() {
        use super::super::projection::{Configuration, Credential, Plan};
        use super::super::projection_authority::Authority as PlanAuthority;
        let mut f = Fixture::new();
        let mut owner = PlanAuthority::load(&f.db, 0).unwrap();
        owner
            .publish(
                &mut f.db,
                0,
                Some(Configuration {
                    revision: 1,
                    plans: vec![Plan {
                        service: "orders".into(),
                        audience: "orders-api".into(),
                        resource: "orders".into(),
                        action: "read".into(),
                        minimum_aal: 2,
                        credential: Credential::BearerReference {
                            secret_ref: "owned-token".into(),
                        },
                    }],
                }),
                "operator",
                &|_| Ok(()),
            )
            .unwrap();
        let reader = owner.reader();
        let calls = std::cell::Cell::new(0);
        assert!(reader.load().project(f.admission().unwrap(), &mut f.db, &|| 102, &|db| {
            calls.set(calls.get()+1);
            if calls.get() == 2 {
                db.sqlite().unwrap().execute("UPDATE meta SET value=json_set(value,'$.configuration.plans[0].resource','billing') WHERE key='projection_plan_authority_v1'", []).map_err(|_| Refused)?;
            }
            Ok(())
        }, &|_| Ok(zeroize::Zeroizing::new("owned-example-token".into()))).is_err());
        assert_eq!(f.nonce_count(), 0);
        let document = super::super::projection_authority::read(&f.db)
            .unwrap()
            .unwrap();
        assert_eq!(document.configuration.unwrap().plans[0].resource, "orders");
        assert!(
            reader
                .load()
                .project(
                    f.admission().unwrap(),
                    &mut f.db,
                    &|| 102,
                    &|_| Ok(()),
                    &|_| Ok(zeroize::Zeroizing::new("owned-example-token".into()))
                )
                .is_ok()
        );
    }
}
