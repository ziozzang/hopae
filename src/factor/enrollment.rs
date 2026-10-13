//! Enrollment preparation returns provisioning material only at creation.
//! Recent authentication, HTTP disclosure controls and enrollment confirmation are caller responsibilities.
use super::{keyring::Keyring, totp::Seed};
use crate::{
    crypto::Rng,
    event::types::Event,
    identity::types::UserId,
    store::{Factors, StoreError},
};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use zeroize::Zeroizing;

pub struct Provisioning(Zeroizing<String>);
impl Provisioning {
    pub fn expose_uri(&self) -> &str {
        &self.0
    }
    /// Explicit plaintext disclosure only for the authenticated creation response.
    pub fn setup_key(&self) -> &str {
        self.0
            .split_once("?secret=")
            .and_then(|(_, q)| q.split('&').next())
            .unwrap_or("")
    }
}
impl std::fmt::Debug for Provisioning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Provisioning(<redacted>)")
    }
}
#[derive(Debug)]
pub enum Error {
    Invalid,
    Store(StoreError),
}
fn label(value: &str) -> bool {
    !value.trim().is_empty()
        && value.len() <= 128
        && !value.chars().any(|c| c.is_control() || c == ':')
}
fn uri(seed: &Seed, issuer: &str, account: &str) -> Result<Provisioning, Error> {
    if !label(issuer) || !label(account) {
        return Err(Error::Invalid);
    }
    let issuer = utf8_percent_encode(issuer, NON_ALPHANUMERIC).to_string();
    let account = utf8_percent_encode(account, NON_ALPHANUMERIC).to_string();
    let encoded = Zeroizing::new(data_encoding::BASE32_NOPAD.encode(seed.bytes()));
    Ok(Provisioning(Zeroizing::new(format!(
        "otpauth://totp/{issuer}:{account}?secret={}&issuer={issuer}&algorithm=SHA1&digits=6&period=30",
        encoded.as_str()
    ))))
}
pub struct Request<'a> {
    pub id: &'a str,
    pub user: &'a UserId,
    pub issuer: &'a str,
    pub account: &'a str,
}
/// No existing seed/envelope is exposed; failure drops provisioning material.
pub async fn prepare(
    store: &dyn Factors,
    keys: &Keyring,
    rng: &dyn Rng,
    request: Request<'_>,
    events: Vec<Event>,
) -> Result<Provisioning, Error> {
    if !label(request.issuer) || !label(request.account) {
        return Err(Error::Invalid);
    }
    let mut random = Zeroizing::new([0u8; 20]);
    rng.fill(random.as_mut());
    let seed = Seed::from_bytes(random.as_ref()).ok_or(Error::Invalid)?;
    let provisioning = uri(&seed, request.issuer, request.account)?;
    let envelope = keys
        .active()
        .seal(&seed, request.user.as_str(), request.id, rng)
        .map_err(|_| Error::Invalid)?;
    store
        .create_totp_pending(
            request.id.to_owned(),
            request.user.clone(),
            envelope,
            events,
        )
        .await
        .map_err(Error::Store)?;
    Ok(provisioning)
}
/// Native end-user preparation; the actor is issued by the session service.
pub struct AuthorizedRequest<'a> {
    pub id: &'a str,
    pub actor: crate::store::FactorActor,
    pub issuer: &'a str,
    pub account: &'a str,
}
pub async fn prepare_authorized(
    store: &dyn Factors,
    keys: &Keyring,
    rng: &dyn Rng,
    request: AuthorizedRequest<'_>,
    events: Vec<Event>,
) -> Result<Provisioning, Error> {
    if !label(request.issuer) || !label(request.account) {
        return Err(Error::Invalid);
    }
    let mut random = Zeroizing::new([0u8; 20]);
    rng.fill(random.as_mut());
    let seed = Seed::from_bytes(random.as_ref()).ok_or(Error::Invalid)?;
    let provisioning = uri(&seed, request.issuer, request.account)?;
    let envelope = keys
        .active()
        .seal(&seed, request.actor.user().as_str(), request.id, rng)
        .map_err(|_| Error::Invalid)?;
    store
        .create_totp_pending_authorized(request.id.to_owned(), request.actor, envelope, events)
        .await
        .map_err(Error::Store)?;
    Ok(provisioning)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn uri_has_matching_issuer_base32_and_fixed_native_profile() {
        let seed = Seed::from_bytes(b"12345678901234567890").unwrap();
        let provisioning = uri(&seed, "Hangang 운영", "alice+test@example.test").unwrap();
        let parsed = url::Url::parse(provisioning.expose_uri()).unwrap();
        assert_eq!(parsed.scheme(), "otpauth");
        assert_eq!(parsed.host_str(), Some("totp"));
        let query: std::collections::HashMap<_, _> = parsed.query_pairs().collect();
        assert_eq!(query["issuer"], "Hangang 운영");
        assert_eq!(
            data_encoding::BASE32_NOPAD
                .decode(query["secret"].as_bytes())
                .unwrap(),
            seed.bytes()
        );
        assert_eq!(query["algorithm"], "SHA1");
        assert_eq!(query["digits"], "6");
        assert_eq!(query["period"], "30");
        assert!(parsed.path().starts_with("/Hangang%20"));
        assert_eq!(format!("{provisioning:?}"), "Provisioning(<redacted>)");
    }
    #[test]
    fn rejects_ambiguous_or_unbounded_labels() {
        let seed = Seed::from_bytes(&[0; 20]).unwrap();
        for value in ["", " ", "other:issuer", "bad\nlabel"] {
            assert!(uri(&seed, value, "account").is_err());
            assert!(uri(&seed, "issuer", value).is_err());
        }
        assert!(uri(&seed, &"a".repeat(129), "account").is_err());
    }
}
