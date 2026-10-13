//! Native external-MFA publication and atomic completion. Portal adapters must
//! still enforce HTTPS, CSRF, admission and current application assurance policy.
use super::external_transport::{Connector, Verification};
use crate::{
    crypto::{Clock, Digest, Secret},
    store::{Factors, Sessions, StoreError},
};

#[derive(Debug)]
pub enum Error {
    Refused,
    Unavailable,
    Store(StoreError),
}

/// Publish only a native operator-approved independent second-factor verifier.
/// This is not an API credential relay or an externally supplied assurance claim.
pub async fn publish_authorized_configuration(
    store: &dyn Factors,
    connector: &Connector,
    config_generation: u64,
) -> Result<(), Error> {
    let authority = connector.authority();
    store
        .publish_external_factor(crate::store::ExternalFactorPublication {
            factor: authority.factor,
            revision: authority.revision,
            binding: Some(authority.binding),
            config_generation,
        })
        .await
        .map_err(Error::Store)
}

/// A revisioned disable tombstone revokes every session elevated by this factor.
pub async fn disable_authorized_configuration(
    store: &dyn Factors,
    factor: &str,
    revision: u64,
    config_generation: u64,
) -> Result<(), Error> {
    store
        .publish_external_factor(crate::store::ExternalFactorPublication {
            factor: factor.to_owned(),
            revision,
            binding: None,
            config_generation,
        })
        .await
        .map_err(Error::Store)
}

pub struct StepUp<'a> {
    pub actor: crate::store::FactorActor,
    pub response: &'a Secret,
    pub transaction: Digest,
    pub portal_binding: Digest,
    pub config_generation: u64,
    pub portal_handle: crate::store::HandleRow,
    pub handoff: crate::store::HandoffCodeRow,
    pub events: Vec<crate::event::types::Event>,
}

/// Exchange context comes from the owner transaction and live native actor.
/// The verifier receives a transaction digest, never the browser bearer token.
pub async fn elevate_authorized<S: Factors + Sessions + ?Sized>(
    store: &S,
    connector: &Connector,
    clock: &dyn Clock,
    input: StepUp<'_>,
) -> Result<(), Error> {
    let proof = verify_authorized(
        store,
        connector,
        clock,
        VerificationRequest {
            actor: &input.actor,
            response: input.response,
            transaction: input.transaction,
            portal_binding: input.portal_binding,
            config_generation: input.config_generation,
        },
    )
    .await?;
    store
        .elevate_external(crate::store::ExternalElevation {
            actor: input.actor,
            proof,
            transaction: input.transaction,
            portal_binding: input.portal_binding,
            config_generation: input.config_generation,
            portal_handle: input.portal_handle,
            handoff: input.handoff,
            events: input.events,
        })
        .await
        .map_err(Error::Store)
}

pub struct VerificationRequest<'a> {
    pub actor: &'a crate::store::FactorActor,
    pub response: &'a Secret,
    pub transaction: Digest,
    pub portal_binding: Digest,
    pub config_generation: u64,
}
/// Prepare and verify before minting replacement credentials. Completion must
/// still consume this receipt in the owner transaction; verification grants nothing.
pub async fn verify_authorized<S: Factors + Sessions + ?Sized>(
    store: &S,
    connector: &Connector,
    clock: &dyn Clock,
    input: VerificationRequest<'_>,
) -> Result<super::external_transport::VerifiedProof, Error> {
    // Recheck authorization before contacting the verifier, then again inside
    // the final owner transaction after the untrusted asynchronous exchange.
    store
        .bind_external_stepup(crate::store::BindExternalStepUp {
            actor: crate::store::FactorActor {
                request_id: input.actor.request_id.clone(),
                provider_configuration: input.actor.provider_configuration.clone(),
                client_ip: input.actor.client_ip,
                view: input.actor.view.clone(),
                authorized_at: input.actor.authorized_at,
                session_idle: input.actor.session_idle,
                handle_idle: input.actor.handle_idle,
            },
            transaction: input.transaction,
            portal_binding: input.portal_binding,
            authority: connector.authority(),
            config_generation: input.config_generation,
        })
        .await
        .map_err(Error::Store)?;
    let transaction = store
        .transaction(&input.transaction)
        .await
        .map_err(Error::Store)?
        .ok_or(Error::Refused)?;
    let started = clock.now();
    if transaction.consumed_at.is_some() || transaction.expires_at <= started {
        return Err(Error::Refused);
    }
    let challenge = input.transaction.to_hex();
    let authority = connector.authority();
    let expected = super::external::Expected {
        challenge: &challenge,
        user: input.actor.user().as_str(),
        session: input.actor.view.session.session_id.as_str(),
        service: transaction.app_id.as_str(),
        factor: &authority.factor,
        configuration_revision: authority.revision,
        credential_generation: input.actor.view.session.cred_gen,
        started_at: started,
        challenge_expires_at: transaction.expires_at,
    };
    let proof = match connector
        .verify(&expected, input.response, clock)
        .await
        .map_err(|_| Error::Unavailable)?
    {
        Verification::Rejected => return Err(Error::Refused),
        Verification::Verified(proof) => *proof,
    };
    Ok(proof)
}
