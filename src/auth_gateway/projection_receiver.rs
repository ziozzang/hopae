//! Native permission observation -> independently checked chain -> paired replay
//! transaction. Runtime adapters must supply live local identity/caller guards.
use super::{
    PrincipalKind,
    permission_live::{Client, Observation, Request},
    projection, projection_admission, projection_authority,
    receipt_authority::Verifier,
    receipt_binding::{Context, Identity, Permit},
    receipt_keys::Refused,
};
use std::sync::Arc;
/// Private construction and no Clone/Debug/serde. Neither a raw acknowledgement
/// nor a caller-selected context can skip signature and replay admission.
pub struct Admission {
    request: Arc<Request>,
    observation: Observation,
    chain: projection_admission::Admission,
}
pub fn verify(
    observation: Observation,
    client: &Client,
    verifier: &Verifier,
    now: u64,
) -> Result<Admission, Refused> {
    let request = observation.request().clone();
    if !observation.valid_for(&request, client, now) {
        return Err(Refused);
    }
    let native = request.native();
    let wire = request.permit();
    let a = native.context.as_ref().ok_or(Refused)?;
    let p = wire.context.as_ref().ok_or(Refused)?;
    let ai = a.identity.as_ref().ok_or(Refused)?;
    let pi = p.identity.as_ref().ok_or(Refused)?;
    if ai.kind != 2 || ai.aal != 0 || pi.kind != 2 || pi.aal != 0 {
        return Err(Refused);
    }
    let authentication_context = Context {
        issuer_ref: &a.issuer_ref,
        key_epoch: a.key_epoch,
        identity_authority_epoch: &a.identity_authority_epoch,
        identity: Identity {
            subject_ref: &ai.subject_ref,
            kind: PrincipalKind::Service,
            aal: 0,
            revision: ai.revision,
            credential_generation: ai.credential_generation,
        },
        service: &a.service,
        audience: &a.audience,
        request_sha256: a
            .request_sha256
            .as_slice()
            .try_into()
            .map_err(|_| Refused)?,
    };
    let permission_context = Context {
        issuer_ref: &p.issuer_ref,
        key_epoch: p.key_epoch,
        identity_authority_epoch: &p.identity_authority_epoch,
        identity: Identity {
            subject_ref: &pi.subject_ref,
            kind: PrincipalKind::Service,
            aal: 0,
            revision: pi.revision,
            credential_generation: pi.credential_generation,
        },
        service: &p.service,
        audience: &p.audience,
        request_sha256: p
            .request_sha256
            .as_slice()
            .try_into()
            .map_err(|_| Refused)?,
    };
    let binding = wire.binding.as_ref().ok_or(Refused)?;
    let permit = Permit {
        authentication_receipt_sha256: binding
            .authentication_receipt_sha256
            .as_slice()
            .try_into()
            .map_err(|_| Refused)?,
        decision_ref: &binding.decision_ref,
        resource: &binding.resource,
        action: &binding.action,
        authority_epoch: &binding.authority_epoch,
        catalog_revision: binding.catalog_revision,
        policy_revision: binding.policy_revision,
        network_revision: binding.network_revision,
        route_revision: binding.route_revision,
        plan_revision: binding.plan_revision,
    };
    if authentication_context.request_sha256.as_slice() != native.request_sha256.as_slice()
        || permit.resource != native.resource
        || permit.action != native.action
    {
        return Err(Refused);
    }
    let mut chain = projection_admission::verify(
        verifier,
        projection_admission::Input {
            authentication_context: &authentication_context,
            authentication_receipt: &native.receipt,
            permission_context: &permission_context,
            permit: &permit,
            permission_receipt: &wire.receipt,
        },
        now,
    )?;
    chain.restrict_expiry(observation.expires_ms())?;
    Ok(Admission {
        request,
        observation,
        chain,
    })
}
impl Admission {
    /// Both nonces and owner work commit together. `guard` must recheck actual
    /// native local identity/caller owners, not request claims or a constant.
    /// Remote acknowledgement is point-in-time; it does not replace that guard.
    #[allow(clippy::too_many_arguments)]
    pub fn project<D: crate::store::meta::MetaDb>(
        self,
        client: &Client,
        plan: &projection_authority::Snapshot,
        db: &mut D,
        clock: &dyn Fn() -> u64,
        guard: &dyn Fn(&dyn crate::store::meta::MetaTx) -> Result<(), Refused>,
        resolve: &dyn Fn(&str) -> Result<zeroize::Zeroizing<String>, Refused>,
    ) -> Result<projection::Output, Refused> {
        let Self {
            request,
            observation,
            chain,
        } = self;
        if !observation.valid_for(&request, client, clock()) {
            return Err(Refused);
        }
        plan.project(
            chain,
            db,
            clock,
            &|db| {
                if !observation.valid_for(&request, client, clock()) {
                    return Err(Refused);
                }
                guard(db)?;
                if !observation.valid_for(&request, client, clock()) {
                    return Err(Refused);
                }
                Ok(())
            },
            resolve,
        )
    }
}
