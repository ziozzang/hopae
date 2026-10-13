//! Native TOTP verification followed by revision-fenced owner consumption.
//! This receipt is not a session assertion; challenge/session atomicity remains required.
use super::{keyring::Keyring, totp::Parameters};
use crate::{
    crypto::{Clock, Secret, Timestamp},
    event::types::Event,
    identity::types::UserId,
    store::{Factors, StoreError},
};
#[derive(Clone, Copy, Debug)]
pub enum Purpose {
    ConfirmEnrollment,
    ConsumeAuthentication,
}
#[derive(Debug)]
pub enum Error {
    Refused,
    Store(StoreError),
}
/// Not serializable or constructible by adapters. Does not confer AAL or issue sessions.
#[derive(Debug)]
pub struct Consumption {
    purpose: Purpose,
    user: UserId,
    enrollment: String,
    revision: u64,
    counter: u64,
    at: Timestamp,
}
impl Consumption {
    pub fn purpose(&self) -> Purpose {
        self.purpose
    }
    pub fn user(&self) -> &UserId {
        &self.user
    }
    pub fn enrollment(&self) -> &str {
        &self.enrollment
    }
    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub fn counter(&self) -> u64 {
        self.counter
    }
    pub fn at(&self) -> Timestamp {
        self.at
    }
}
pub struct Verification<'a> {
    pub enrollment: &'a str,
    pub user: &'a UserId,
    pub code: &'a Secret,
    pub purpose: Purpose,
}
/// Trusted service call, after HTTP admission/recent-authentication/challenge checks.
pub async fn verify(
    store: &dyn Factors,
    keys: &Keyring,
    clock: &dyn Clock,
    input: Verification<'_>,
    events: Vec<Event>,
) -> Result<Consumption, Error> {
    let row = store
        .totp_enrollment(input.enrollment, input.user)
        .await
        .map_err(Error::Store)?
        .ok_or(Error::Refused)?;
    let expected_active = matches!(input.purpose, Purpose::ConsumeAuthentication);
    if row.active != expected_active {
        return Err(Error::Refused);
    }
    let key = keys.for_envelope(&row.envelope).ok_or(Error::Refused)?;
    let seed = key
        .open(&row.envelope, input.user.as_str(), input.enrollment)
        .map_err(|_| Error::Refused)?;
    let at = clock.now();
    let counter = Parameters::default()
        .matching_counter(&seed, at, input.code, row.last_counter)
        .ok_or(Error::Refused)?;
    let consumed = match input.purpose {
        Purpose::ConfirmEnrollment => {
            store
                .activate_totp(input.enrollment, input.user, row.revision, counter, events)
                .await
        }
        Purpose::ConsumeAuthentication => {
            store
                .consume_totp_counter(input.enrollment, input.user, row.revision, counter, events)
                .await
        }
    }
    .map_err(Error::Store)?;
    if !consumed {
        return Err(Error::Refused);
    }
    Ok(Consumption {
        purpose: input.purpose,
        user: input.user.clone(),
        enrollment: input.enrollment.to_owned(),
        revision: if expected_active {
            row.revision
        } else {
            row.revision + 1
        },
        counter,
        at,
    })
}

/// Enrollment confirmation after native session authorization and transport admission.
pub async fn confirm_authorized(
    store: &dyn Factors,
    keys: &Keyring,
    clock: &dyn Clock,
    enrollment: &str,
    actor: crate::store::FactorActor,
    code: &Secret,
    events: Vec<Event>,
) -> Result<Consumption, Error> {
    let user = actor.user().clone();
    let row = store
        .totp_enrollment(enrollment, &user)
        .await
        .map_err(Error::Store)?
        .ok_or(Error::Refused)?;
    if row.active {
        return Err(Error::Refused);
    }
    let key = keys.for_envelope(&row.envelope).ok_or(Error::Refused)?;
    let seed = key
        .open(&row.envelope, user.as_str(), enrollment)
        .map_err(|_| Error::Refused)?;
    let at = clock.now();
    let counter = Parameters::default()
        .matching_counter(&seed, at, code, row.last_counter)
        .ok_or(Error::Refused)?;
    if !store
        .activate_totp_authorized(enrollment, actor, row.revision, counter, events)
        .await
        .map_err(Error::Store)?
    {
        return Err(Error::Refused);
    }
    Ok(Consumption {
        purpose: Purpose::ConfirmEnrollment,
        user,
        enrollment: enrollment.into(),
        revision: row.revision + 1,
        counter,
        at,
    })
}

/// Server-prepared, browser-bound step-up output. Callers must validate HTTPS,
/// CSRF, both browser bindings and the live application policy before calling.
pub struct StepUp<'a> {
    pub enrollment: &'a str,
    pub actor: crate::store::FactorActor,
    pub code: &'a Secret,
    pub transaction: crate::crypto::Digest,
    pub portal_binding: crate::crypto::Digest,
    pub config_generation: Option<u64>,
    pub portal_handle: crate::store::HandleRow,
    pub handoff: crate::store::HandoffCodeRow,
    pub events: Vec<Event>,
}

/// Verifies the code without consuming it, then commits proof, challenge,
/// elevation, old-credential revocation and replacements as one owner write.
/// This is a native service primitive, not an HTTP endpoint or policy bypass.
pub async fn elevate_authorized(
    store: &dyn Factors,
    keys: &Keyring,
    clock: &dyn Clock,
    input: StepUp<'_>,
) -> Result<(), Error> {
    let user = input.actor.user().clone();
    let row = store
        .totp_enrollment(input.enrollment, &user)
        .await
        .map_err(Error::Store)?
        .filter(|row| row.active)
        .ok_or(Error::Refused)?;
    let key = keys.for_envelope(&row.envelope).ok_or(Error::Refused)?;
    let seed = key
        .open(&row.envelope, user.as_str(), input.enrollment)
        .map_err(|_| Error::Refused)?;
    let counter = Parameters::default()
        .matching_counter(&seed, clock.now(), input.code, row.last_counter)
        .ok_or(Error::Refused)?;
    store
        .elevate_totp(crate::store::TotpElevation {
            actor: input.actor,
            enrollment: input.enrollment.into(),
            revision: row.revision,
            counter,
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

/// Bind a native challenge after HTTPS/recent portal-session authorization.
/// The application binding is verified again during elevated handoff redemption.
pub async fn bind_stepup(
    store: &dyn Factors,
    actor: crate::store::FactorActor,
    transaction: &Secret,
    portal_cookie: &Secret,
) -> Result<crate::store::TotpChallengeBinding, Error> {
    if !crate::crypto::is_well_formed_bind(portal_cookie.expose())
        || !crate::crypto::is_well_formed_bind(transaction.expose())
    {
        return Err(Error::Refused);
    }
    store
        .bind_totp_stepup(crate::store::BindTotpStepUp {
            actor,
            transaction: transaction.digest(),
            portal_binding: portal_cookie.digest(),
            config_generation: None,
        })
        .await
        .map_err(Error::Store)
}
