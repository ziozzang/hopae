//! Shared Service/Workload observed paired projection core. Fixed-class native
//! adapters must authenticate exact owners and retain immutable owner fences.
//! Signature/numeric bounds alone cannot enter the production adapters.
use super::{
    projection,
    receipt_keys::Refused,
    receipt_replay::{self, ObservedProof},
};
use hangang_runtime::time::ReceiverClock;
#[cfg(test)]
use hopae_grpc::receipt_time::{ClockRates, Report};
#[cfg(test)]
use sha2::{Digest as _, Sha256};
use std::sync::Arc;
#[cfg(test)]
use {
    super::{
        projection_admission::{self, Input},
        receipt_authority::Verifier,
    },
    hangang_runtime::time::ExchangeSample,
};

#[cfg(test)]
pub(crate) struct SourceObservation<'a> {
    pub(crate) domain: &'a str,
    pub(crate) report: &'a Report,
    pub(crate) exchange: ExchangeSample,
}
pub(crate) struct Scope {
    pub(crate) service: String,
    pub(crate) audience: String,
    pub(crate) subject: String,
    pub(crate) resource: String,
    pub(crate) action: String,
    pub(crate) aal: u8,
    pub(crate) request_sha256: [u8; 32],
    pub(crate) plan_revision: u64,
}
pub(crate) struct Admission {
    authentication: ObservedProof,
    permission: ObservedProof,
    pub(crate) scope: Scope,
    chain_sha256: [u8; 32],
}
/// No caller numeric time grants access: native adapters owe authenticated
/// reports, issuer-affine authentication ownership, and final owner guards.
#[cfg(test)]
pub(crate) fn verify(
    verifier: &Verifier,
    input: Input<'_>,
    authentication: SourceObservation<'_>,
    permission: SourceObservation<'_>,
    rates: &ClockRates,
    permission_query: &[u8],
) -> Result<Admission, Refused> {
    projection_admission::validate_chain(&input)?;
    let a = input.authentication_context;
    let domain = match a.identity.kind {
        super::PrincipalKind::Service => {
            hopae_grpc::service_epoch::decode_clock(a.identity_authority_epoch)
                .map_err(|_| Refused)?
                .clock_domain
        }
        super::PrincipalKind::Workload => {
            hopae_grpc::workload_epoch::decode(a.identity_authority_epoch)
                .map_err(|_| Refused)?
                .clock_domain
        }
        _ => return Err(Refused),
    };
    if domain != authentication.domain
        || input.permit.authority_epoch != permission.domain
        || !permission.domain.starts_with("pobs1:")
    {
        return Err(Refused);
    }
    let auth = verifier.verify_observed_signature(a, None, input.authentication_receipt)?;
    let permit = verifier.verify_observed_signature(
        input.permission_context,
        Some(input.permit),
        input.permission_receipt,
    )?;
    let chain_sha256 = Sha256::digest(permission_query).into();
    Ok(Admission {
        authentication: ObservedProof::from_owner_report(
            auth,
            authentication.domain.to_owned(),
            authentication.report,
            authentication.exchange,
            rates,
        )?,
        permission: ObservedProof::from_owner_report(
            permit,
            permission.domain.to_owned(),
            permission.report,
            permission.exchange,
            rates,
        )?,
        scope: Scope {
            service: a.service.to_owned(),
            audience: a.audience.to_owned(),
            subject: a.identity.subject_ref.to_owned(),
            resource: input.permit.resource.to_owned(),
            action: input.permit.action.to_owned(),
            aal: a.identity.aal,
            request_sha256: a.request_sha256,
            plan_revision: input.permit.plan_revision,
        },
        chain_sha256,
    })
}
/// Sealed local issuer-affine authentication observation. Numeric report input
/// cannot construct this; LiveService must prove this exact runtime's live domain.
pub(crate) struct LocalAuthentication {
    proof: ObservedProof,
}
pub(crate) fn observe_local(
    verifier: &super::receipt_authority::Verifier,
    request: &super::permission_live::Request,
    live: &super::receipt_issuer::LiveService<'_>,
    clock: &ReceiverClock,
    rates: &hopae_grpc::receipt_time::ClockRates,
) -> Result<LocalAuthentication, Refused> {
    let start = clock.begin_exchange().map_err(|_| Refused)?;
    let report = live.observe_time()?;
    let context = request.authentication_context()?;
    let parsed = hopae_grpc::service_epoch::decode_clock(context.identity_authority_epoch)
        .map_err(|_| Refused)?;
    if parsed.clock_domain != report.clock_domain {
        return Err(Refused);
    }
    let checked = verifier.verify_observed_signature(&context, None, &request.native().receipt)?;
    let exchange = clock.finish_exchange(start).map_err(|_| Refused)?;
    let proof = ObservedProof::from_owner_report(
        checked,
        report.clock_domain.to_owned(),
        &report.report,
        exchange,
        rates,
    )?;
    live.current()?;
    Ok(LocalAuthentication { proof })
}
pub(crate) fn from_native(
    request: &Arc<super::permission_live::Request>,
    authentication: LocalAuthentication,
    permission: super::permission_live::ObservedObservation,
    client: &super::permission_live::Client,
    clock: &ReceiverClock,
) -> Result<Admission, Refused> {
    let a = request.authentication_context()?;
    let p = request.permission_context()?;
    let binding = request.binding()?;
    super::projection_admission::validate_chain(&super::projection_admission::Input {
        authentication_context: &a,
        authentication_receipt: &request.native().receipt,
        permission_context: &p,
        permit: &binding,
        permission_receipt: &request.permit().receipt,
    })?;
    if a.request_sha256.as_slice() != request.native().request_sha256.as_slice()
        || binding.resource != request.native().resource
        || binding.action != request.native().action
        || !authentication
            .proof
            .matches_bytes(&request.native().receipt)
    {
        return Err(Refused);
    }
    let permission = permission.into_proof(request, client, clock)?;
    authentication.proof.remaining(clock)?;
    Ok(Admission {
        authentication: authentication.proof,
        permission,
        scope: Scope {
            service: a.service.to_owned(),
            audience: a.audience.to_owned(),
            subject: a.identity.subject_ref.to_owned(),
            resource: binding.resource.to_owned(),
            action: binding.action.to_owned(),
            aal: a.identity.aal,
            request_sha256: a.request_sha256,
            plan_revision: binding.plan_revision,
        },
        chain_sha256: request.observed_chain_sha256()?,
    })
}
/// Sealed actual local Workload Record; never a signature/numeric grant.
pub(crate) struct LocalWorkloadAuthentication {
    proof: ObservedProof,
    record: Arc<super::workload_owner::Record>,
}
impl LocalWorkloadAuthentication {
    pub(crate) fn record(&self) -> &Arc<super::workload_owner::Record> {
        &self.record
    }
}
pub(crate) fn observe_local_workload(
    verifier: &super::receipt_authority::Verifier,
    request: &super::workload_permission_live::Request,
    issuer: &super::receipt_issuer::Issuer,
    clock: &ReceiverClock,
) -> Result<LocalWorkloadAuthentication, Refused> {
    let start = clock.begin_exchange().map_err(|_| Refused)?;
    let context = request.authentication_context()?;
    let record = issuer.observe_workload(
        &context,
        &request.native().receipt,
        &context.request_sha256,
        verifier,
    )?;
    let (owner_now_ms, remaining_ms) = issuer.workload_time(&record)?;
    let epoch = hopae_grpc::workload_epoch::decode(context.identity_authority_epoch)
        .map_err(|_| Refused)?;
    if epoch.clock_domain != record.attempt.owner()?.domain() {
        return Err(Refused);
    }
    let checked = verifier.verify_observed_signature(&context, None, &request.native().receipt)?;
    if checked.evidence().sha256() != &record.hash {
        return Err(Refused);
    }
    let exchange = clock.finish_exchange(start).map_err(|_| Refused)?;
    // Both clocks are actual BOOTTIME on this host; independent origins still
    // require the normal pre-call anchor and millisecond quantum conversion.
    let proof = ObservedProof::from_owner_report(
        checked,
        epoch.clock_domain.into(),
        &hopae_grpc::receipt_time::Report {
            owner_now_ms,
            remaining_ms,
            receipt_sha256: record.hash,
        },
        exchange,
        &hopae_grpc::receipt_time::ClockRates::EQUAL,
    )?;
    issuer.workload_time(&record)?;
    proof.remaining(clock)?;
    Ok(LocalWorkloadAuthentication { proof, record })
}
pub(crate) fn from_workload(
    request: &Arc<super::workload_permission_live::Request>,
    authentication: LocalWorkloadAuthentication,
    permission: super::workload_permission_live::ObservedObservation,
    client: &super::workload_permission_live::Client,
    issuer: &super::receipt_issuer::Issuer,
    clock: &ReceiverClock,
) -> Result<Admission, Refused> {
    let a = request.authentication_context()?;
    let p = request.permission_context()?;
    let binding = request.binding()?;
    super::projection_admission::validate_chain(&super::projection_admission::Input {
        authentication_context: &a,
        authentication_receipt: &request.native().receipt,
        permission_context: &p,
        permit: &binding,
        permission_receipt: &request.permit().receipt,
    })?;
    if a.request_sha256.as_slice() != request.native().request_sha256.as_slice()
        || binding.resource != request.native().resource
        || binding.action != request.native().action
        || !authentication
            .proof
            .matches_bytes(&request.native().receipt)
    {
        return Err(Refused);
    }
    let permission = permission.into_proof(request, client, clock)?;
    issuer.workload_time(&authentication.record)?;
    authentication.proof.remaining(clock)?;
    Ok(Admission {
        authentication: authentication.proof,
        permission,
        scope: Scope {
            service: a.service.into(),
            audience: a.audience.into(),
            subject: a.identity.subject_ref.into(),
            resource: binding.resource.into(),
            action: binding.action.into(),
            aal: 0,
            request_sha256: a.request_sha256,
            plan_revision: binding.plan_revision,
        },
        chain_sha256: request.observed_chain_sha256()?,
    })
}
/// Distinct output-source report; no auth or permit absolute expiry is exported.
/// This envelope must travel only on the authenticated projection owner RPC.
#[cfg(test)]
pub(crate) struct Envelope {
    pub(crate) request_sha256: [u8; 32],
    pub(crate) chain_sha256: [u8; 32],
    pub(crate) output_clock_domain: String,
    pub(crate) owner_now_ms: u64,
    pub(crate) remaining_ms: u32,
    pub(crate) plan_revision: u64,
}
/// Secret material is resolved only inside the atomic paired transaction.
/// Keep the native final owner/caller/config fence with this output until send.
pub(crate) struct Output {
    admission: Admission,
    clock: Arc<ReceiverClock>,
    name: http::HeaderName,
    value: zeroize::Zeroizing<String>,
    #[cfg(test)]
    after_reply_allocation: Option<Box<dyn Fn() + Send + Sync>>,
}
impl Admission {
    pub(crate) fn remaining(&self, clock: &ReceiverClock) -> Result<std::time::Duration, Refused> {
        Ok(self
            .authentication
            .remaining(clock)?
            .min(self.permission.remaining(clock)?))
    }
    pub(crate) fn project(
        self,
        projector: &projection::Projector,
        db: &mut rusqlite::Connection,
        clock: Arc<ReceiverClock>,
        guard: &dyn Fn(&rusqlite::Connection) -> Result<(), Refused>,
        resolve: &dyn Fn(&str) -> Result<zeroize::Zeroizing<String>, Refused>,
    ) -> Result<Output, Refused> {
        let (name, value) = receipt_replay::consume_observed_pair(
            db,
            [&self.authentication, &self.permission],
            &clock,
            guard,
            |_| projector.resolve_observed(&self.scope, resolve),
        )?;
        Ok(Output {
            admission: self,
            clock,
            name,
            value,
            #[cfg(test)]
            after_reply_allocation: None,
        })
    }
}
pub(crate) struct ReplyMetadata<'a> {
    pub(crate) service: &'a str,
    pub(crate) audience: &'a str,
    pub(crate) request_sha256: [u8; 32],
    pub(crate) request_id: u64,
    pub(crate) profile_revision: u64,
    pub(crate) application_generation: u64,
    pub(crate) key_registry_revision: u64,
}
impl Output {
    /// Allocate all reply fields before the final callback/time/local-owner fences.
    /// Pending secret bytes remain zeroizing until the checks have succeeded.
    pub(crate) fn into_reply(
        self,
        metadata: ReplyMetadata<'_>,
        guard: &dyn Fn() -> Result<(), Refused>,
        local_guard: &dyn Fn() -> Result<(), Refused>,
    ) -> Result<hopae_grpc::v1::ObservedProjectionReply, Refused> {
        if self.admission.scope.service != metadata.service
            || self.admission.scope.audience != metadata.audience
            || self.admission.scope.request_sha256 != metadata.request_sha256
        {
            return Err(Refused);
        }
        let mut value = http::HeaderValue::from_str(&self.value).map_err(|_| Refused)?;
        value.set_sensitive(true);
        let mut secret = zeroize::Zeroizing::new(value.as_bytes().to_vec());
        let mut reply = hopae_grpc::v1::ObservedProjectionReply {
            request_id: metadata.request_id,
            service: self.admission.scope.service.clone(),
            audience: self.admission.scope.audience.clone(),
            request_sha256: self.admission.scope.request_sha256.to_vec(),
            header_name: self.name.to_string(),
            header_value: vec![],
            chain_sha256: self.admission.chain_sha256.to_vec(),
            output_clock_domain: format!(
                "hproj1:{}",
                data_encoding::HEXLOWER.encode(self.clock.generation())
            ),
            owner_now_ms: 0,
            remaining_ms: 0,
            profile_revision: metadata.profile_revision,
            application_generation: metadata.application_generation,
            key_registry_revision: metadata.key_registry_revision,
            plan_revision: self.admission.scope.plan_revision,
            cache_ttl_ms: 0,
        };
        #[cfg(test)]
        if let Some(hook) = &self.after_reply_allocation {
            hook();
        }
        guard()?;
        let sample = self
            .clock
            .finish_exchange(self.clock.begin_exchange().map_err(|_| Refused)?)
            .map_err(|_| Refused)?;
        let remaining = self
            .admission
            .authentication
            .remaining(&self.clock)?
            .min(self.admission.permission.remaining(&self.clock)?);
        let remaining_ms = u32::try_from(remaining.as_millis())
            .ok()
            .filter(|v| *v > 0 && *v <= 1000)
            .ok_or(Refused)?;
        local_guard()?; // Pure owner checks only; no callback or allocation afterward.
        reply.owner_now_ms = sample.after_ticks();
        reply.remaining_ms = remaining_ms;
        reply.header_value = std::mem::take(&mut *secret);
        Ok(reply)
    }
    /// Callback precedes the final BOOTTIME checks. Calling it twice fences any
    /// serialization/header work before returning the sensitive output.
    #[cfg(test)]
    pub(crate) fn into_header(
        self,
        service: &str,
        audience: &str,
        request_sha256: &[u8; 32],
        guard: &dyn Fn() -> Result<(), Refused>,
    ) -> Result<(http::HeaderName, http::HeaderValue, Envelope), Refused> {
        guard()?;
        if service != self.admission.scope.service
            || audience != self.admission.scope.audience
            || request_sha256 != &self.admission.scope.request_sha256
        {
            return Err(Refused);
        }
        let mut value = http::HeaderValue::from_str(&self.value).map_err(|_| Refused)?;
        value.set_sensitive(true);
        guard()?;
        let sample = self
            .clock
            .finish_exchange(self.clock.begin_exchange().map_err(|_| Refused)?)
            .map_err(|_| Refused)?;
        let remaining = self
            .admission
            .authentication
            .remaining(&self.clock)?
            .min(self.admission.permission.remaining(&self.clock)?);
        let remaining_ms = u32::try_from(remaining.as_millis())
            .ok()
            .filter(|v| *v > 0 && *v <= 1000)
            .ok_or(Refused)?;
        let envelope = Envelope {
            request_sha256: *request_sha256,
            chain_sha256: self.admission.chain_sha256,
            output_clock_domain: format!(
                "hproj1:{}",
                data_encoding::HEXLOWER.encode(self.clock.generation())
            ),
            owner_now_ms: sample.after_ticks(),
            remaining_ms,
            plan_revision: self.admission.scope.plan_revision,
        };
        Ok((self.name, value, envelope))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth_gateway::{
        PrincipalKind,
        receipt::{self, Claims, Purpose},
        receipt_authority::Authority,
        receipt_binding::{self, Context, Identity, Permit},
        receipt_keys::Key,
    };
    const AUTH_DOMAIN: &str = "123456789abcdef0123456789abcdef0";
    const AUTH_EPOCH: &str = "clock1:123456789abcdef0123456789abcdef0:owned:service:1:app:1";
    const PERMIT_DOMAIN: &str = "pobs1:223456789abcdef0123456789abcdef0:policy";
    struct Fixture {
        db: rusqlite::Connection,
        owner: Authority,
        clock: Arc<ReceiverClock>,
    }
    impl Fixture {
        fn new() -> Self {
            Self::with_db(rusqlite::Connection::open_in_memory().unwrap())
        }
        fn with_db(mut db: rusqlite::Connection) -> Self {
            db.execute_batch("CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT NOT NULL)")
                .unwrap();
            let mut owner = Authority::load(&db, 0).unwrap();
            owner
                .publish(
                    &mut db,
                    0,
                    &[
                        Key {
                            issuer_ref: "hopae".into(),
                            purpose: Purpose::Authentication,
                            epoch: 1,
                            public_key: ed25519_dalek::SigningKey::from_bytes(&[7; 32])
                                .verifying_key()
                                .to_bytes(),
                        },
                        Key {
                            issuer_ref: "pumgye".into(),
                            purpose: Purpose::Permit,
                            epoch: 1,
                            public_key: ed25519_dalek::SigningKey::from_bytes(&[9; 32])
                                .verifying_key()
                                .to_bytes(),
                        },
                    ],
                    "test",
                    &|_| Ok(()),
                )
                .unwrap();
            Self {
                db,
                owner,
                clock: Arc::new(ReceiverClock::new([1; 16]).unwrap()),
            }
        }
        fn admission(
            &self,
            nonce: u8,
            auth_time: u64,
            permit_time: u64,
            remaining: u32,
        ) -> Admission {
            self.class_admission(
                nonce,
                auth_time,
                permit_time,
                remaining,
                PrincipalKind::Service,
            )
        }
        fn class_admission(
            &self,
            nonce: u8,
            auth_time: u64,
            permit_time: u64,
            remaining: u32,
            kind: PrincipalKind,
        ) -> Admission {
            let epoch = if kind == PrincipalKind::Workload {
                format!("wobs1:{AUTH_DOMAIN}:owned:p:1:a:1")
            } else {
                AUTH_EPOCH.into()
            };
            let context = |issuer_ref| Context {
                issuer_ref,
                key_epoch: 1,
                identity_authority_epoch: &epoch,
                identity: Identity {
                    subject_ref: if kind == PrincipalKind::Workload {
                        "s_529be5b595ab327853eabe2d1adf52256e262af036510607"
                    } else {
                        "s_fixture"
                    },
                    kind,
                    aal: 0,
                    revision: 1,
                    credential_generation: 1,
                },
                service: "orders",
                audience: "orders-api",
                request_sha256: [3; 32],
            };
            let a = context("hopae");
            let p = context("pumgye");
            let auth = receipt::sign(
                &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
                &Claims {
                    purpose: Purpose::Authentication,
                    issued_ms: auth_time,
                    expires_ms: auth_time + 900,
                    binding: receipt_binding::digest(&a, None).unwrap(),
                    nonce: [nonce; 32],
                },
            )
            .unwrap();
            let permit = Permit {
                authentication_receipt_sha256: Sha256::digest(auth).into(),
                decision_ref: "decision",
                resource: "orders",
                action: "read",
                authority_epoch: PERMIT_DOMAIN,
                catalog_revision: 1,
                policy_revision: 1,
                network_revision: 1,
                route_revision: 1,
                plan_revision: 1,
            };
            let permission = receipt::sign(
                &ed25519_dalek::SigningKey::from_bytes(&[9; 32]),
                &Claims {
                    purpose: Purpose::Permit,
                    issued_ms: permit_time,
                    expires_ms: permit_time + 950,
                    binding: receipt_binding::digest(&p, Some(&permit)).unwrap(),
                    nonce: [nonce + 1; 32],
                },
            )
            .unwrap();
            let ar = Report {
                owner_now_ms: auth_time + 1,
                remaining_ms: remaining,
                receipt_sha256: Sha256::digest(auth).into(),
            };
            let pr = Report {
                owner_now_ms: permit_time + 1,
                remaining_ms: remaining,
                receipt_sha256: Sha256::digest(permission).into(),
            };
            let sample = || {
                self.clock
                    .finish_exchange(self.clock.begin_exchange().unwrap())
                    .unwrap()
            };
            verify(
                &self.owner.verifier(),
                Input {
                    authentication_context: &a,
                    authentication_receipt: &auth,
                    permission_context: &p,
                    permit: &permit,
                    permission_receipt: &permission,
                },
                SourceObservation {
                    domain: AUTH_DOMAIN,
                    report: &ar,
                    exchange: sample(),
                },
                SourceObservation {
                    domain: PERMIT_DOMAIN,
                    report: &pr,
                    exchange: sample(),
                },
                &ClockRates::EQUAL,
                b"exact-permission-query-fixture",
            )
            .unwrap()
        }
        fn strict_auth(&self, nonce: u8, issued: u64) -> super::super::receipt_authority::Checked {
            let context = Context {
                issuer_ref: "hopae",
                key_epoch: 1,
                identity_authority_epoch: "owned:service:1:app:1",
                identity: Identity {
                    subject_ref: "s_fixture",
                    kind: PrincipalKind::Service,
                    aal: 0,
                    revision: 1,
                    credential_generation: 1,
                },
                service: "orders",
                audience: "orders-api",
                request_sha256: [3; 32],
            };
            let bytes = receipt::sign(
                &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
                &Claims {
                    purpose: Purpose::Authentication,
                    issued_ms: issued,
                    expires_ms: issued + 900,
                    binding: receipt_binding::digest(&context, None).unwrap(),
                    nonce: [nonce; 32],
                },
            )
            .unwrap();
            self.owner
                .verifier()
                .verify(&context, None, &bytes, issued + 1)
                .unwrap()
        }
        fn projector() -> projection::Projector {
            projection::Projector::compile(projection::Configuration {
                revision: 1,
                plans: vec![projection::Plan {
                    service: "orders".into(),
                    audience: "orders-api".into(),
                    resource: "orders".into(),
                    action: "read".into(),
                    minimum_aal: 0,
                    credential: projection::Credential::BearerReference {
                        secret_ref: "vault:fixture".into(),
                    },
                }],
            })
            .unwrap()
        }
        fn count(&self) -> u64 {
            self.db
                .query_row(
                    "SELECT count(*) FROM meta WHERE key LIKE 'projection_nonce_id:%'",
                    [],
                    |r| r.get(0),
                )
                .unwrap()
        }
    }
    #[test]
    fn independent_connections_commit_exactly_one_observed_pair() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let fixture = Fixture::with_db(rusqlite::Connection::open(file.path()).unwrap());
        let admission = fixture.admission(130, 100, 9_000_000, 700);
        let barrier = std::sync::Barrier::new(8);
        let successes = std::thread::scope(|scope| {
            let mut workers = Vec::new();
            for _ in 0..8 {
                let barrier = &barrier;
                let admission = &admission;
                let clock = &fixture.clock;
                let path = file.path();
                workers.push(scope.spawn(move || {
                    let mut db = rusqlite::Connection::open(path).unwrap();
                    db.busy_timeout(std::time::Duration::from_secs(2)).unwrap();
                    barrier.wait();
                    receipt_replay::consume_observed_pair(
                        &mut db,
                        [&admission.authentication, &admission.permission],
                        clock,
                        &|_| Ok(()),
                        |tx| {
                            tx.execute(
                                "INSERT INTO meta(key,value) VALUES('observed-issued','once')",
                                [],
                            )
                            .map_err(|_| Refused)?;
                            Ok(())
                        },
                    )
                    .is_ok()
                }));
            }
            workers
                .into_iter()
                .map(|worker| worker.join().unwrap())
                .filter(|success| *success)
                .count()
        });
        assert_eq!(successes, 1);
        assert_eq!(fixture.count(), 2);
        assert_eq!(
            fixture
                .db
                .query_row(
                    "SELECT value FROM meta WHERE key='projection_nonce_count_v1'",
                    [],
                    |r| r.get::<_, String>(0)
                )
                .unwrap(),
            "2"
        );
    }
    #[test]
    fn independent_offsets_native_sql_output_and_lost_response_keep_pair_consumed() {
        let mut fixture = Fixture::new();
        let projector = Fixture::projector();
        let admission = fixture.admission(10, 100, 8_000_000, 700);
        let output = admission
            .project(
                &projector,
                &mut fixture.db,
                fixture.clock.clone(),
                &|_| Ok(()),
                &|name| {
                    assert_eq!(name, "vault:fixture");
                    Ok(zeroize::Zeroizing::new("fixture-secret".into()))
                },
            )
            .unwrap();
        assert_eq!(fixture.count(), 2);
        let (name, header, envelope) = output
            .into_header("orders", "orders-api", &[3; 32], &|| Ok(()))
            .unwrap();
        assert_eq!(name, "authorization");
        assert!(header.is_sensitive());
        assert_eq!(envelope.request_sha256, [3; 32]);
        assert_ne!(envelope.chain_sha256, [0; 32]);
        assert!(envelope.output_clock_domain.starts_with("hproj1:"));
        assert!(envelope.owner_now_ms < 1000);
        assert!(envelope.remaining_ms > 0 && envelope.remaining_ms < 700);
        assert_eq!(envelope.plan_revision, 1);
        let replay = fixture.admission(10, 100, 8_000_000, 700);
        assert!(
            replay
                .project(
                    &projector,
                    &mut fixture.db,
                    fixture.clock.clone(),
                    &|_| Ok(()),
                    &|_| panic!("replay resolved secret")
                )
                .is_err()
        );
        let lost = fixture
            .admission(20, 100, 9_000_000, 700)
            .project(
                &projector,
                &mut fixture.db,
                fixture.clock.clone(),
                &|_| Ok(()),
                &|_| Ok(zeroize::Zeroizing::new("secret".into())),
            )
            .unwrap();
        drop(lost);
        assert!(
            fixture
                .admission(20, 100, 9_000_000, 700)
                .project(
                    &projector,
                    &mut fixture.db,
                    fixture.clock.clone(),
                    &|_| Ok(()),
                    &|_| panic!("lost reply reopened nonce")
                )
                .is_err()
        );
        assert_eq!(fixture.count(), 4);
    }
    #[test]
    fn final_callback_and_secret_failure_roll_back_both_rows_and_owner_work() {
        let mut fixture = Fixture::new();
        let projector = Fixture::projector();
        let calls = std::cell::Cell::new(0);
        let admission = fixture.admission(30, 100, 900_000, 700);
        assert!(
            admission
                .project(
                    &projector,
                    &mut fixture.db,
                    fixture.clock.clone(),
                    &|db| {
                        calls.set(calls.get() + 1);
                        db.execute(
                            "INSERT OR REPLACE INTO meta(key,value) VALUES('work','pending')",
                            [],
                        )
                        .map_err(|_| Refused)?;
                        if calls.get() == 2 {
                            Err(Refused)
                        } else {
                            Ok(())
                        }
                    },
                    &|_| Ok(zeroize::Zeroizing::new("secret".into()))
                )
                .is_err()
        );
        assert_eq!(fixture.count(), 0);
        assert_eq!(
            fixture
                .db
                .query_row("SELECT count(*) FROM meta WHERE key='work'", [], |r| r
                    .get::<_, u64>(0))
                .unwrap(),
            0
        );
        let admission = fixture.admission(30, 100, 900_000, 700);
        assert!(
            admission
                .project(
                    &projector,
                    &mut fixture.db,
                    fixture.clock.clone(),
                    &|_| Ok(()),
                    &|_| Err(Refused)
                )
                .is_err()
        );
        assert_eq!(fixture.count(), 0);
        fixture
            .admission(30, 100, 900_000, 700)
            .project(
                &projector,
                &mut fixture.db,
                fixture.clock.clone(),
                &|_| Ok(()),
                &|_| Ok(zeroize::Zeroizing::new("secret".into())),
            )
            .unwrap();
        assert_eq!(fixture.count(), 2);
    }
    #[test]
    fn shortened_admission_preserves_full_retention_and_receiver_restart_tombstones() {
        let mut fixture = Fixture::new();
        let projector = Fixture::projector();
        fixture
            .admission(40, 100, 900_000, 40)
            .project(
                &projector,
                &mut fixture.db,
                fixture.clock.clone(),
                &|_| Ok(()),
                &|_| Ok(zeroize::Zeroizing::new("secret".into())),
            )
            .unwrap();
        let rows: Vec<String> = fixture
            .db
            .prepare("SELECT value FROM meta WHERE key LIKE 'projection_nonce_id:%'")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        for encoded in rows {
            let row: serde_json::Value = serde_json::from_str(&encoded).unwrap();
            assert_eq!(row["version"], 2);
            assert!(row["retain_until_ms"].as_u64().unwrap() > 850);
        }
        std::thread::sleep(std::time::Duration::from_millis(60));
        assert!(
            fixture
                .admission(40, 100, 900_000, 700)
                .project(
                    &projector,
                    &mut fixture.db,
                    fixture.clock.clone(),
                    &|_| Ok(()),
                    &|_| panic!("short admission collected retention")
                )
                .is_err()
        );
        fixture.clock = Arc::new(ReceiverClock::new([2; 16]).unwrap());
        assert!(
            fixture
                .admission(40, 100, 900_000, 700)
                .project(
                    &projector,
                    &mut fixture.db,
                    fixture.clock.clone(),
                    &|_| Ok(()),
                    &|_| panic!("receiver restart collected unknown generation")
                )
                .is_err()
        );
        fixture
            .admission(50, 100, 900_000, 700)
            .project(
                &projector,
                &mut fixture.db,
                fixture.clock.clone(),
                &|_| Ok(()),
                &|_| Ok(zeroize::Zeroizing::new("secret".into())),
            )
            .unwrap();
        assert_eq!(fixture.count(), 4);
    }
    #[test]
    fn strict_and_observed_share_identity_and_wall_forward_cannot_collect_observed() {
        let mut fixture = Fixture::new();
        let projector = Fixture::projector();
        let strict = fixture.strict_auth(80, 100);
        super::super::receipt_replay::consume(
            &mut fixture.db,
            &strict,
            &|| 101,
            &|_| Ok(()),
            |_| Ok(()),
        )
        .unwrap();
        assert!(
            fixture
                .admission(80, 100, 900_000, 700)
                .project(
                    &projector,
                    &mut fixture.db,
                    fixture.clock.clone(),
                    &|_| Ok(()),
                    &|_| panic!("strict to observed double consumption")
                )
                .is_err()
        );
        fixture
            .admission(90, 100, 900_000, 700)
            .project(
                &projector,
                &mut fixture.db,
                fixture.clock.clone(),
                &|_| Ok(()),
                &|_| Ok(zeroize::Zeroizing::new("secret".into())),
            )
            .unwrap();
        let strict = fixture.strict_auth(90, 100);
        assert!(
            super::super::receipt_replay::consume(
                &mut fixture.db,
                &strict,
                &|| 101,
                &|_| Ok(()),
                |_| -> Result<(), Refused> { panic!("observed to strict double consumption") }
            )
            .is_err()
        );
        let future = fixture.strict_auth(100, 9_000_000);
        super::super::receipt_replay::consume(
            &mut fixture.db,
            &future,
            &|| 9_000_001,
            &|_| Ok(()),
            |_| Ok(()),
        )
        .unwrap();
        assert_eq!(fixture.count(), 3, "UTC jump may collect strict row only");
        assert!(
            fixture
                .admission(90, 100, 900_000, 700)
                .project(
                    &projector,
                    &mut fixture.db,
                    fixture.clock.clone(),
                    &|_| Ok(()),
                    &|_| panic!("wall cleanup resurrected observed pair")
                )
                .is_err()
        );
    }
    #[test]
    fn unknown_generation_capacity_refuses_without_dropping_tombstones() {
        let mut fixture = Fixture::new();
        let projector = Fixture::projector();
        fixture
            .admission(110, 100, 900_000, 700)
            .project(
                &projector,
                &mut fixture.db,
                fixture.clock.clone(),
                &|_| Ok(()),
                &|_| Ok(zeroize::Zeroizing::new("secret".into())),
            )
            .unwrap();
        fixture.clock = Arc::new(ReceiverClock::new([3; 16]).unwrap());
        fixture
            .db
            .execute(
                "UPDATE meta SET value='1000000' WHERE key='projection_nonce_count_v1'",
                [],
            )
            .unwrap();
        assert!(
            fixture
                .admission(120, 100, 900_000, 700)
                .project(
                    &projector,
                    &mut fixture.db,
                    fixture.clock.clone(),
                    &|_| Ok(()),
                    &|_| panic!("capacity resolved secret")
                )
                .is_err()
        );
        assert_eq!(fixture.count(), 2);
    }
    #[test]
    fn output_fences_reject_expiry_retirement_and_final_callback_registry_change() {
        let mut fixture = Fixture::new();
        let projector = Fixture::projector();
        let output = fixture
            .admission(60, 100, 9_000_000, 40)
            .project(
                &projector,
                &mut fixture.db,
                fixture.clock.clone(),
                &|_| Ok(()),
                &|_| Ok(zeroize::Zeroizing::new("secret".into())),
            )
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(
            output
                .into_header("orders", "orders-api", &[3; 32], &|| Ok(()))
                .is_err()
        );
        let output = fixture
            .admission(70, 100, 9_000_000, 700)
            .project(
                &projector,
                &mut fixture.db,
                fixture.clock.clone(),
                &|_| Ok(()),
                &|_| Ok(zeroize::Zeroizing::new("secret".into())),
            )
            .unwrap();
        let calls = std::cell::Cell::new(0);
        assert!(
            output
                .into_header("orders", "orders-api", &[3; 32], &|| {
                    calls.set(calls.get() + 1);
                    if calls.get() == 2 {
                        fixture.clock.retire();
                    }
                    Ok(())
                })
                .is_err()
        );
    }
    #[test]
    fn reply_finalizer_refuses_late_allocation_expiry_and_final_callback_retirement() {
        for mode in 0..3 {
            let mut fixture = Fixture::new();
            let projector = Fixture::projector();
            let mut output = fixture
                .admission(180 + mode, 100, 900_000, 100)
                .project(
                    &projector,
                    &mut fixture.db,
                    fixture.clock.clone(),
                    &|_| Ok(()),
                    &|_| Ok(zeroize::Zeroizing::new("owned-secret".into())),
                )
                .unwrap();
            assert_eq!(fixture.count(), 2);
            if mode == 0 {
                output.after_reply_allocation = Some(Box::new(|| {
                    std::thread::sleep(std::time::Duration::from_millis(120))
                }));
            }
            if mode == 1 {
                let clock = fixture.clock.clone();
                output.after_reply_allocation = Some(Box::new(move || clock.retire()));
            }
            let metadata = ReplyMetadata {
                request_id: 7,
                service: "orders",
                audience: "orders-api",
                request_sha256: [3; 32],
                profile_revision: 1,
                application_generation: 1,
                key_registry_revision: 1,
            };
            assert!(
                output
                    .into_reply(
                        metadata,
                        &|| {
                            if mode == 2 {
                                fixture.clock.retire();
                            }
                            Ok(())
                        },
                        &|| Ok(())
                    )
                    .is_err()
            );
            assert_eq!(fixture.count(), 2); // Committed consumption cannot be reset by late output failure.
        }
    }
    #[test]
    fn reply_finalizer_checks_pure_owner_after_time_and_keeps_exact_scope() {
        let mut fixture = Fixture::new();
        let projector = Fixture::projector();
        let output = fixture
            .admission(190, 100, 900_000, 700)
            .project(
                &projector,
                &mut fixture.db,
                fixture.clock.clone(),
                &|_| Ok(()),
                &|_| Ok(zeroize::Zeroizing::new("owned-secret".into())),
            )
            .unwrap();
        let metadata = ReplyMetadata {
            request_id: 7,
            service: "orders",
            audience: "orders-api",
            request_sha256: [3; 32],
            profile_revision: 1,
            application_generation: 1,
            key_registry_revision: 1,
        };
        assert!(
            output
                .into_reply(metadata, &|| Ok(()), &|| Err(Refused))
                .is_err()
        );
        let output = fixture
            .admission(191, 100, 900_000, 700)
            .project(
                &projector,
                &mut fixture.db,
                fixture.clock.clone(),
                &|_| Ok(()),
                &|_| Ok(zeroize::Zeroizing::new("owned-secret".into())),
            )
            .unwrap();
        let metadata = ReplyMetadata {
            request_id: 8,
            service: "other",
            audience: "orders-api",
            request_sha256: [3; 32],
            profile_revision: 1,
            application_generation: 1,
            key_registry_revision: 1,
        };
        assert!(output.into_reply(metadata, &|| Ok(()), &|| Ok(())).is_err());
    }
    #[test]
    fn service_and_workload_auth_nonces_consume_the_same_durable_pair_namespace() {
        for first in [PrincipalKind::Service, PrincipalKind::Workload] {
            let mut fixture = Fixture::new();
            let projector = Fixture::projector();
            let second = if first == PrincipalKind::Service {
                PrincipalKind::Workload
            } else {
                PrincipalKind::Service
            };
            fixture
                .class_admission(210, 100, 900_000, 700, first)
                .project(
                    &projector,
                    &mut fixture.db,
                    fixture.clock.clone(),
                    &|_| Ok(()),
                    &|_| Ok(zeroize::Zeroizing::new("owned-secret".into())),
                )
                .unwrap();
            assert_eq!(fixture.count(), 2);
            assert!(
                fixture
                    .class_admission(210, 100, 900_000, 700, second)
                    .project(
                        &projector,
                        &mut fixture.db,
                        fixture.clock.clone(),
                        &|_| Ok(()),
                        &|_| panic!("already-consumed class must not fetch secrets")
                    )
                    .is_err()
            );
            assert_eq!(fixture.count(), 2);
        }
    }
}
