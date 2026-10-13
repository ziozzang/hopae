//! Native TOTP verification followed by revision-fenced owner consumption.
//! This receipt is not a session assertion; challenge/session atomicity remains required.
use super::{seed_cipher::Key, totp::Parameters};
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
    key: &Key,
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
