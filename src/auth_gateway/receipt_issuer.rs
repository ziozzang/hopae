//! Native session receipt signing. The verify engine seals original metadata;
//! caller claims, ordinary response headers and Lua are never signing inputs.
use super::{
    PrincipalKind,
    receipt::{self, Claims, Purpose},
    receipt_binding::{Context, Identity as BindingIdentity},
    receipt_keys::Refused,
};
use crate::{
    crypto::{Clock, Rng, Timestamp},
    verify::types::Identity,
};
use sha2::{Digest as _, Sha256};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use zeroize::Zeroizing;

pub(crate) struct SessionSeal {
    digest: [u8; 32],
    verified_ms: i64,
}
fn field(hash: &mut Sha256, bytes: &[u8]) {
    hash.update((bytes.len() as u32).to_be_bytes());
    hash.update(bytes);
}
fn metadata(identity: &Identity, service: &str, verified_ms: i64) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"hopae:native-session-receipt-seal:v1\0");
    for value in [
        service,
        identity.user_id.as_str(),
        identity.session_id.as_str(),
        identity.provider_id.as_str(),
    ] {
        field(&mut hash, value.as_bytes());
    }
    for value in [identity.auth_time.0, identity.expires_at.0, verified_ms] {
        field(&mut hash, &value.to_be_bytes());
    }
    for value in [
        identity.generations.user,
        identity.generations.session,
        identity.generations.config,
        identity.aal.as_i64() as u64,
    ] {
        field(&mut hash, &value.to_be_bytes());
    }
    hash.finalize().into()
}
impl SessionSeal {
    pub(crate) fn new(identity: &Identity, service: &str, verified: Timestamp) -> Self {
        Self {
            digest: metadata(identity, service, verified.0),
            verified_ms: verified.0,
        }
    }
}
#[derive(Clone, Debug)]
pub struct Scope {
    pub service: String,
    pub audience: String,
}
#[derive(Clone, Debug)]
pub struct Configuration {
    pub issuer_ref: String,
    pub key_epoch: u64,
    pub identity_authority_epoch: String,
    pub public_key: [u8; 32],
    pub scopes: Vec<Scope>,
}
pub struct Request<'a> {
    pub service: &'a str,
    pub audience: &'a str,
    pub request_sha256: [u8; 32],
}
pub struct Issuer {
    config: Arc<Configuration>,
    signer: ed25519_dalek::SigningKey,
    clock: Arc<dyn Clock>,
    rng: Arc<dyn Rng>,
    observed_time: AtomicU64,
    scopes: std::collections::HashMap<String, std::collections::HashSet<String>>,
}
/// No Clone/Debug/serde: adapters must expose this only through the authenticated
/// receipt phase, never automatically through ordinary auth-response headers.
pub struct Issued {
    config: Arc<Configuration>,
    identity_epoch: String,
    subject: String,
    aal: u8,
    revision: u64,
    credential_generation: u64,
    service: String,
    audience: String,
    request_sha256: [u8; 32],
    bytes: [u8; receipt::LENGTH],
}
fn identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
}
impl Issuer {
    /// Seed is supplied by a native key-vault capability, with a pinned public key.
    /// Clock/RNG are native resources; production wiring must use the OS CSPRNG.
    pub fn new(
        config: Configuration,
        seed: Zeroizing<[u8; 32]>,
        clock: Arc<dyn Clock>,
        rng: Arc<dyn Rng>,
    ) -> Result<Self, Refused> {
        let signer = ed25519_dalek::SigningKey::from_bytes(&seed);
        if !identifier(&config.issuer_ref)
            || !identifier(&config.identity_authority_epoch)
            || config.identity_authority_epoch.len() > 96
            || !(1..=9_007_199_254_740_991).contains(&config.key_epoch)
            || signer.verifying_key().is_weak()
            || signer.verifying_key().to_bytes() != config.public_key
        {
            return Err(Refused);
        }
        if config.scopes.is_empty() || config.scopes.len() > 128 {
            return Err(Refused);
        }
        let mut scopes: std::collections::HashMap<String, std::collections::HashSet<String>> =
            std::collections::HashMap::new();
        for scope in &config.scopes {
            if !identifier(&scope.service)
                || !identifier(&scope.audience)
                || !scopes
                    .entry(scope.service.clone())
                    .or_default()
                    .insert(scope.audience.clone())
            {
                return Err(Refused);
            }
        }
        Ok(Self {
            config: Arc::new(config),
            signer,
            clock,
            rng,
            observed_time: AtomicU64::new(0),
            scopes,
        })
    }
    fn now(&self) -> Result<u64, Refused> {
        let now = u64::try_from(self.clock.now().0).map_err(|_| Refused)?;
        Ok(self.observed_time.fetch_max(now, Ordering::AcqRel).max(now))
    }
    /// Native guard must inspect current session/handle, user/provider/config and
    /// signer epoch both times. The seal prevents changing a prior native allow;
    /// it cannot replace live revocation or distributed authority fences.
    pub fn issue_session(
        &self,
        identity: &Identity,
        request: Request<'_>,
        guard: &dyn Fn() -> Result<(), Refused>,
    ) -> Result<Issued, Refused> {
        if !self
            .scopes
            .get(request.service)
            .is_some_and(|audiences| audiences.contains(request.audience))
        {
            return Err(Refused);
        }
        let seal = identity.receipt_seal.as_ref().ok_or(Refused)?;
        if seal.digest != metadata(identity, request.service, seal.verified_ms) {
            return Err(Refused);
        }
        let begun = std::time::Instant::now();
        let now = self.now()?;
        let verified = u64::try_from(seal.verified_ms).map_err(|_| Refused)?;
        let expires = u64::try_from(identity.expires_at.0)
            .map_err(|_| Refused)?
            .min(verified.checked_add(1000).ok_or(Refused)?)
            .min(now.saturating_add(1000));
        if now < verified || now >= expires {
            return Err(Refused);
        }
        guard()?;
        let mut issued = Issued {
            config: self.config.clone(),
            identity_epoch: format!(
                "{}:{}",
                self.config.identity_authority_epoch, identity.generations.config
            ),
            subject: identity.user_id.as_str().to_owned(),
            aal: identity.aal.as_i64() as u8,
            revision: identity.generations.user,
            credential_generation: identity.generations.session,
            service: request.service.to_owned(),
            audience: request.audience.to_owned(),
            request_sha256: request.request_sha256,
            bytes: [0; receipt::LENGTH],
        };
        if !(1..=9_007_199_254_740_991).contains(&identity.generations.config) {
            return Err(Refused);
        }
        let binding =
            super::receipt_binding::digest(&issued.context(), None).map_err(|_| Refused)?;
        let mut nonce = [0; 32];
        self.rng.fill(&mut nonce);
        issued.bytes = receipt::sign(
            &self.signer,
            &Claims {
                purpose: Purpose::Authentication,
                issued_ms: now,
                expires_ms: expires,
                binding,
                nonce,
            },
        )
        .map_err(|_| Refused)?;
        guard()?;
        let final_now = self
            .now()?
            .max(now.saturating_add(begun.elapsed().as_millis().min(u64::MAX as u128) as u64));
        self.observed_time.fetch_max(final_now, Ordering::AcqRel);
        if final_now >= expires {
            return Err(Refused);
        }
        Ok(issued)
    }
}
impl Issued {
    pub fn bytes(&self) -> &[u8; receipt::LENGTH] {
        &self.bytes
    }
    pub fn context(&self) -> Context<'_> {
        Context {
            issuer_ref: &self.config.issuer_ref,
            key_epoch: self.config.key_epoch,
            identity_authority_epoch: &self.identity_epoch,
            identity: BindingIdentity {
                subject_ref: &self.subject,
                kind: PrincipalKind::Human,
                aal: self.aal,
                revision: self.revision,
                credential_generation: self.credential_generation,
            },
            service: &self.service,
            audience: &self.audience,
            request_sha256: self.request_sha256,
        }
    }
}
