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
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
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
/// Internal response extension; never serialized as a gateway header or body.
pub struct CapturedService {
    pub(crate) authentication: super::authority::ServiceAuthentication,
    pub(crate) profile: Arc<super::authority::Snapshot>,
    pub(crate) application: Arc<crate::policy::types::ConfigSnapshot>,
}
impl CapturedService {
    pub fn application_generation(&self) -> u64 {
        self.application.generation
    }
    pub fn issue(
        &self,
        issuer: &Issuer,
        reader: &Arc<arc_swap::ArcSwap<super::authority::Snapshot>>,
        applications: &Arc<arc_swap::ArcSwap<crate::policy::types::ConfigSnapshot>>,
        request: Request<'_>,
        guard: &dyn Fn() -> Result<(), Refused>,
    ) -> Result<Issued, Refused> {
        self.issue_domain(issuer, reader, applications, request, false, guard)
    }
    pub fn issue_observed(
        &self,
        issuer: &Issuer,
        reader: &Arc<arc_swap::ArcSwap<super::authority::Snapshot>>,
        applications: &Arc<arc_swap::ArcSwap<crate::policy::types::ConfigSnapshot>>,
        request: Request<'_>,
        guard: &dyn Fn() -> Result<(), Refused>,
    ) -> Result<Issued, Refused> {
        self.issue_domain(issuer, reader, applications, request, true, guard)
    }
    pub(crate) fn issue_domain(
        &self,
        issuer: &Issuer,
        reader: &Arc<arc_swap::ArcSwap<super::authority::Snapshot>>,
        applications: &Arc<arc_swap::ArcSwap<crate::policy::types::ConfigSnapshot>>,
        request: Request<'_>,
        clocked: bool,
        guard: &dyn Fn() -> Result<(), Refused>,
    ) -> Result<Issued, Refused> {
        issuer.issue_service_owned(
            &self.authentication,
            request,
            Some(self.application.generation),
            clocked,
            &|| {
                let current = reader.load_full();
                if !current.available()
                    || !Arc::ptr_eq(&current, &self.profile)
                    || !Arc::ptr_eq(&applications.load_full(), &self.application)
                {
                    return Err(Refused);
                }
                guard()?;
                let current = reader.load_full();
                if !current.available()
                    || !Arc::ptr_eq(&current, &self.profile)
                    || !Arc::ptr_eq(&applications.load_full(), &self.application)
                {
                    return Err(Refused);
                }
                Ok(())
            },
        )
    }
}

/// Opaque local validation seal. Its owners must be rechecked before use.
/// No permission grant, replay consumption or remote freshness assertion.
pub struct LiveService<'a> {
    issuer: &'a Issuer,
    profiles: &'a Arc<arc_swap::ArcSwap<super::authority::Snapshot>>,
    applications: &'a Arc<arc_swap::ArcSwap<crate::policy::types::ConfigSnapshot>>,
    profile: Arc<super::authority::Snapshot>,
    application: Arc<crate::policy::types::ConfigSnapshot>,
    expires_ms: u64,
    receipt_sha256: [u8; 32],
    key_check: Option<super::receipt_authority::Checked>,
    verified_ms: u64,
    begun: std::time::Instant,
}
impl LiveService<'_> {
    pub fn current(&self) -> Result<(), Refused> {
        let clocked = self.key_check.is_some();
        let clock_now = if clocked {
            self.issuer.clock_now()?
        } else {
            self.issuer.now()?
        };
        let now = clock_now.max(
            self.verified_ms
                .saturating_add(self.begun.elapsed().as_millis().min(u64::MAX as u128) as u64),
        );
        if clocked {
            self.issuer.clock_floor.fetch_max(now, Ordering::AcqRel);
        } else {
            self.issuer.observed_time.fetch_max(now, Ordering::AcqRel);
        }
        // The clock is an external dependency: it may overlap publication.
        // Acquire the profile after sampling it so a retired captured Arc cannot
        // become apparently available again through the shared publication flag.
        let current = self.profiles.load_full();
        if self
            .key_check
            .as_ref()
            .is_some_and(|checked| !checked.current())
            || !current.available()
            || !Arc::ptr_eq(&current, &self.profile)
            || !Arc::ptr_eq(&self.applications.load_full(), &self.application)
            || now >= self.expires_ms
        {
            return Err(Refused);
        }
        Ok(())
    }
    pub fn expires_ms(&self) -> u64 {
        self.expires_ms
    }
    pub fn observe_time(&self) -> Result<ObservedTime<'_>, Refused> {
        self.current()?;
        let keys = self.key_check.as_ref().ok_or(Refused)?;
        let now = self.issuer.clock_now()?.max(
            self.verified_ms
                .saturating_add(self.begun.elapsed().as_millis().min(u64::MAX as u128) as u64),
        );
        let remaining = self
            .expires_ms
            .checked_sub(now)
            .filter(|v| (1..=1000).contains(v))
            .ok_or(Refused)?;
        self.current()?;
        Ok(ObservedTime {
            report: hopae_grpc::receipt_time::Report {
                owner_now_ms: now,
                remaining_ms: remaining as u32,
                receipt_sha256: self.receipt_sha256,
            },
            clock_domain: &self.issuer.clock_domain,
            profile_revision: self.profile.revision,
            application_generation: self.application.generation,
            key_registry_revision: keys.revision(),
        })
    }
}
pub struct ObservedTime<'a> {
    pub report: hopae_grpc::receipt_time::Report,
    pub clock_domain: &'a str,
    pub profile_revision: u64,
    pub application_generation: u64,
    pub key_registry_revision: u64,
}

pub struct ServiceRequest<'a> {
    pub host: &'a str,
    pub port: u16,
    pub credential: Option<&'a str>,
    pub client_ip: std::net::IpAddr,
}
pub struct Issuer {
    config: Arc<Configuration>,
    signer: ed25519_dalek::SigningKey,
    clock: Arc<dyn Clock>,
    rng: Arc<dyn Rng>,
    observed_time: AtomicU64,
    clock_domain: String,
    clock_started: Option<hangang_runtime::time::ElapsedStamp>,
    clock_offset: AtomicU64,
    clock_floor: AtomicU64,
    scopes: std::collections::HashMap<String, std::collections::HashSet<String>>,
    workloads: Option<Arc<super::workload_owner::Owner>>,
}
/// No Clone/Debug/serde: adapters must expose this only through the authenticated
/// receipt phase, never automatically through ordinary auth-response headers.
pub struct Issued {
    config: Arc<Configuration>,
    identity_epoch: String,
    subject: String,
    kind: PrincipalKind,
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
    /// Validate this issuer's signed service proof against actual live owners.
    /// The request hash must be derived by the authenticated enforcement caller.
    pub fn verify_live_service<'a>(
        &'a self,
        profiles: &'a Arc<arc_swap::ArcSwap<super::authority::Snapshot>>,
        applications: &'a Arc<arc_swap::ArcSwap<crate::policy::types::ConfigSnapshot>>,
        context: &Context<'_>,
        bytes: &[u8],
        request_sha256: &[u8; 32],
    ) -> Result<LiveService<'a>, Refused> {
        self.verify_live_service_domain(
            profiles,
            applications,
            context,
            bytes,
            request_sha256,
            None,
        )
    }
    pub fn verify_live_service_observed<'a>(
        &'a self,
        profiles: &'a Arc<arc_swap::ArcSwap<super::authority::Snapshot>>,
        applications: &'a Arc<arc_swap::ArcSwap<crate::policy::types::ConfigSnapshot>>,
        context: &Context<'_>,
        bytes: &[u8],
        request_sha256: &[u8; 32],
        verifier: &super::receipt_authority::Verifier,
    ) -> Result<LiveService<'a>, Refused> {
        self.verify_live_service_domain(
            profiles,
            applications,
            context,
            bytes,
            request_sha256,
            Some(verifier),
        )
    }
    fn verify_live_service_domain<'a>(
        &'a self,
        profiles: &'a Arc<arc_swap::ArcSwap<super::authority::Snapshot>>,
        applications: &'a Arc<arc_swap::ArcSwap<crate::policy::types::ConfigSnapshot>>,
        context: &Context<'_>,
        bytes: &[u8],
        request_sha256: &[u8; 32],
        key_verifier: Option<&super::receipt_authority::Verifier>,
    ) -> Result<LiveService<'a>, Refused> {
        let clocked = key_verifier.is_some();
        let begun = std::time::Instant::now();
        let verified_ms = if clocked {
            self.clock_now()?
        } else {
            self.now()?
        };
        let epoch = if clocked {
            let parsed = hopae_grpc::service_epoch::decode_clock(context.identity_authority_epoch)
                .map_err(|_| Refused)?;
            if parsed.clock_domain != self.clock_domain {
                return Err(Refused);
            }
            parsed.epoch
        } else {
            hopae_grpc::service_epoch::decode(context.identity_authority_epoch)
                .map_err(|_| Refused)?
        };
        let profile = profiles.load_full();
        let application = applications.load_full();
        if context.issuer_ref != self.config.issuer_ref
            || context.key_epoch != self.config.key_epoch
            || epoch.authority != self.config.identity_authority_epoch
            || epoch.profile_revision != profile.revision
            || !profile.available()
            || epoch.application_generation != application.generation
            || context.identity.kind != PrincipalKind::Service
            || context.identity.aal != 0
            || context.identity.revision != profile.revision
            || context.identity.credential_generation != profile.revision
            || context.request_sha256 != *request_sha256
            || !self.permits_service_audience(context.service, context.audience)
        {
            return Err(Refused);
        }
        let key_check = key_verifier
            .map(|verifier| verifier.verify_source_time(context, None, bytes, verified_ms))
            .transpose()?;
        let (expires_ms, receipt_sha256) = if let Some(checked) = &key_check {
            (
                checked.receipt().claims().expires_ms,
                *checked.receipt().sha256(),
            )
        } else {
            let binding = super::receipt_binding::digest(context, None).map_err(|_| Refused)?;
            let checked = receipt::verify(
                &self.signer.verifying_key(),
                bytes,
                Purpose::Authentication,
                &binding,
                verified_ms,
            )
            .map_err(|_| Refused)?;
            (checked.claims().expires_ms, *checked.sha256())
        };
        let live = LiveService {
            issuer: self,
            profiles,
            applications,
            profile,
            application,
            expires_ms,
            receipt_sha256,
            key_check,
            verified_ms,
            begun,
        };
        live.current()?;
        Ok(live)
    }
    pub fn permits_service_audience(&self, service: &str, audience: &str) -> bool {
        self.scopes
            .get(service)
            .is_some_and(|audiences| audiences.contains(audience))
    }
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
        let mut clock_bytes = [0_u8; 16];
        rng.fill(&mut clock_bytes);
        if clock_bytes == [0; 16] {
            return Err(Refused);
        }
        let clock_domain = clock_bytes.iter().map(|b| format!("{b:02x}")).collect();
        Ok(Self {
            clock_started: hangang_runtime::time::ElapsedStamp::now().ok(),
            clock_offset: AtomicU64::new(0),
            clock_floor: AtomicU64::new(0),
            clock_domain,
            config: Arc::new(config),
            signer,
            clock,
            rng,
            observed_time: AtomicU64::new(0),
            scopes,
            workloads: None,
        })
    }
    /// Clock-domain time never freezes after wall rollback: retain the largest
    /// observed wall-minus-monotonic offset, then advance with process elapsed.
    fn clock_now(&self) -> Result<u64, Refused> {
        // The external wall dependency may overlap host suspend. Sample the
        // suspend-inclusive age after it, before the final native owner fences.
        let wall = u64::try_from(self.clock.now().0).map_err(|_| Refused)?;
        let elapsed = u64::try_from(
            self.clock_started
                .as_ref()
                .ok_or(Refused)?
                .elapsed()
                .map_err(|_| Refused)?
                .as_millis(),
        )
        .map_err(|_| Refused)?;
        self.clock_sample(wall, elapsed)
    }
    fn clock_sample(&self, wall: u64, elapsed: u64) -> Result<u64, Refused> {
        let offset = wall.checked_sub(elapsed).ok_or(Refused)?;
        let offset = self
            .clock_offset
            .fetch_max(offset, Ordering::AcqRel)
            .max(offset);
        let now = offset
            .checked_add(elapsed)
            .filter(|v| (1..=9_007_199_254_740_991).contains(v))
            .ok_or(Refused)?;
        Ok(self.clock_floor.fetch_max(now, Ordering::AcqRel).max(now))
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
        let issued = Issued {
            config: self.config.clone(),
            identity_epoch: format!(
                "{}:{}",
                self.config.identity_authority_epoch, identity.generations.config
            ),
            subject: identity.user_id.as_str().to_owned(),
            kind: PrincipalKind::Human,
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
        self.sign_checked(issued, now, expires, begun, false, guard)
    }
    /// Only profile-owned Service evidence is supported here. Neither network
    /// evidence nor an arbitrary caller principal can manufacture Human/MFA.
    /// Native adapter entry: caller/route authorization remains mandatory in guard.
    /// Snapshot identity is fenced around actual authentication and signing.
    pub async fn authenticate_service_and_issue(
        &self,
        reader: &Arc<arc_swap::ArcSwap<super::authority::Snapshot>>,
        input: ServiceRequest<'_>,
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
        guard()?;
        let snapshot = reader.load_full();
        let authentication = snapshot
            .authenticate_for_receipt(
                input.host,
                input.port,
                input.credential,
                input.client_ip,
                self.now()?,
            )
            .await
            .map_err(|_| Refused)?;
        self.issue_service(&authentication, request, &|| {
            let current = reader.load_full();
            if !Arc::ptr_eq(&snapshot, &current) || !current.available() {
                return Err(Refused);
            }
            guard()?;
            // A native guard can run owner work; recheck after that work as well.
            let current = reader.load_full();
            if !Arc::ptr_eq(&snapshot, &current) || !current.available() {
                return Err(Refused);
            }
            Ok(())
        })
    }

    pub fn issue_service(
        &self,
        authentication: &super::authority::ServiceAuthentication,
        request: Request<'_>,
        guard: &dyn Fn() -> Result<(), Refused>,
    ) -> Result<Issued, Refused> {
        self.issue_service_owned(authentication, request, None, false, guard)
    }
    fn issue_service_owned(
        &self,
        authentication: &super::authority::ServiceAuthentication,
        request: Request<'_>,
        application_generation: Option<u64>,
        clocked: bool,
        guard: &dyn Fn() -> Result<(), Refused>,
    ) -> Result<Issued, Refused> {
        let evidence = &authentication.evidence;
        if evidence.subject.kind != PrincipalKind::Service
            || evidence.service.as_deref() != Some(request.service)
            || !self
                .scopes
                .get(request.service)
                .is_some_and(|audiences| audiences.contains(request.audience))
        {
            return Err(Refused);
        }
        let begun = std::time::Instant::now();
        let now = if clocked {
            self.clock_now()?
        } else {
            self.now()?
        };
        let expires = if clocked {
            // UTC credential expiry and issuer-domain time are distinct clocks.
            // Translate a capped remaining budget; never add fresh lifetime to
            // a captured proof or compare foreign absolute timestamps directly.
            let remaining = authentication
                .observed_remaining_ms(self.now()?)
                .ok_or(Refused)?;
            now.checked_add(remaining)
                .filter(|v| *v <= 9_007_199_254_740_991)
                .ok_or(Refused)?
        } else {
            let expires = evidence
                .expires_at
                .min(
                    authentication
                        .verified_ms
                        .checked_add(1000)
                        .ok_or(Refused)?,
                )
                .min(now.saturating_add(1000));
            if now < authentication.verified_ms || now >= expires {
                return Err(Refused);
            }
            expires
        };
        guard()?;
        let issued = Issued {
            config: self.config.clone(),
            identity_epoch: match application_generation {
                Some(generation) if clocked => hopae_grpc::service_epoch::encode_clock(
                    &self.config.identity_authority_epoch,
                    authentication.revision,
                    generation,
                    &self.clock_domain,
                )
                .map_err(|_| Refused)?,
                Some(generation) => hopae_grpc::service_epoch::encode(
                    &self.config.identity_authority_epoch,
                    authentication.revision,
                    generation,
                )
                .map_err(|_| Refused)?,
                None => format!(
                    "{}:service:{}",
                    self.config.identity_authority_epoch, authentication.revision
                ),
            },
            subject: super::stable_subject(&evidence.subject),
            kind: PrincipalKind::Service,
            aal: 0,
            revision: authentication.revision,
            credential_generation: authentication.revision,
            service: request.service.to_owned(),
            audience: request.audience.to_owned(),
            request_sha256: request.request_sha256,
            bytes: [0; receipt::LENGTH],
        };
        self.sign_checked(issued, now, expires, begun, clocked, guard)
    }
    fn sign_checked(
        &self,
        mut issued: Issued,
        now: u64,
        expires: u64,
        begun: std::time::Instant,
        clocked: bool,
        guard: &dyn Fn() -> Result<(), Refused>,
    ) -> Result<Issued, Refused> {
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
        let final_now = (if clocked {
            self.clock_now()?
        } else {
            self.now()?
        })
        .max(now.saturating_add(begun.elapsed().as_millis().min(u64::MAX as u128) as u64));
        if clocked {
            self.clock_floor.fetch_max(final_now, Ordering::AcqRel);
        } else {
            self.observed_time.fetch_max(final_now, Ordering::AcqRel);
        }
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
                kind: self.kind,
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

/// Actual gateway TokenReview capture. Never serialized or reconstructed from claims.
pub(crate) struct CapturedWorkload {
    authentication: super::authority::ServiceAuthentication,
    profile: Arc<super::authority::Snapshot>,
    application: Arc<crate::policy::types::ConfigSnapshot>,
    attempt: Arc<super::workload_owner::Attempt>,
}
impl CapturedWorkload {
    pub(crate) fn new(
        authentication: super::authority::ServiceAuthentication,
        profile: Arc<super::authority::Snapshot>,
        application: Arc<crate::policy::types::ConfigSnapshot>,
        attempt: Arc<super::workload_owner::Attempt>,
    ) -> Result<Self, Refused> {
        if authentication.evidence.subject.kind != PrincipalKind::Workload
            || authentication.evidence.connector != "kubernetes-tokenreview"
            || authentication.revision != profile.revision
            || !profile.available()
        {
            return Err(attempt.retire());
        }
        attempt.restrict(authentication.evidence.expires_at)?;
        Ok(Self {
            authentication,
            profile,
            application,
            attempt,
        })
    }
    pub(crate) fn issue(
        &self,
        issuer: &Issuer,
        profiles: &Arc<arc_swap::ArcSwap<super::authority::Snapshot>>,
        applications: &Arc<arc_swap::ArcSwap<crate::policy::types::ConfigSnapshot>>,
        verifier: &super::receipt_authority::Verifier,
        request: Request<'_>,
        guard: &dyn Fn() -> Result<(), Refused>,
    ) -> Result<(Issued, Arc<super::workload_owner::Record>), Refused> {
        let owner = issuer.workloads.as_ref().ok_or(Refused)?;
        if !Arc::ptr_eq(owner, &self.attempt.owner()?)
            || !owner.permits(request.service, request.audience)
            || self.authentication.evidence.service.as_deref() != Some(request.service)
        {
            return Err(self.attempt.retire());
        }
        let current = || {
            guard().map_err(|_| self.attempt.retire())?;
            let now = self.attempt.now(issuer.clock.as_ref())?;
            let profile = profiles.load_full();
            if !profile.available()
                || !Arc::ptr_eq(&profile, &self.profile)
                || !Arc::ptr_eq(&applications.load_full(), &self.application)
            {
                return Err(self.attempt.retire());
            }
            Ok(now)
        };
        let now = current()?;
        let mut issued = Issued {
            config: issuer.config.clone(),
            identity_epoch: hopae_grpc::workload_epoch::encode(
                &issuer.config.identity_authority_epoch,
                self.profile.revision,
                self.application.generation,
                owner.domain(),
            )
            .map_err(|_| Refused)?,
            subject: super::stable_subject(&self.authentication.evidence.subject),
            kind: PrincipalKind::Workload,
            aal: 0,
            revision: self.profile.revision,
            credential_generation: self.profile.revision,
            service: request.service.into(),
            audience: request.audience.into(),
            request_sha256: request.request_sha256,
            bytes: [0; receipt::LENGTH],
        };
        let binding =
            super::receipt_binding::digest(&issued.context(), None).map_err(|_| Refused)?;
        let mut nonce = [0; 32];
        issuer.rng.fill(&mut nonce);
        current()?; // RNG/caller callbacks cannot renew the original deadline.
        issued.bytes = receipt::sign(
            &issuer.signer,
            &Claims {
                purpose: Purpose::Authentication,
                issued_ms: now,
                expires_ms: self.attempt.expiry(),
                binding,
                nonce,
            },
        )
        .map_err(|_| Refused)?;
        current()?;
        let keys = verifier.verify_observed_signature(&issued.context(), None, &issued.bytes)?;
        let record = Arc::new(super::workload_owner::Record {
            hash: *keys.evidence().sha256(),
            binding,
            attempt: self.attempt.clone(),
            profile: self.profile.clone(),
            application: self.application.clone(),
            profiles: profiles.clone(),
            applications: applications.clone(),
            keys: Arc::new(keys),
        });
        record.current(issuer.clock.as_ref())?;
        owner.insert(record.clone())?;
        guard().map_err(|_| self.attempt.retire())?;
        record.current(issuer.clock.as_ref())?;
        Ok((issued, record))
    }
}
impl Issuer {
    pub(crate) fn enable_workloads(
        mut self,
        configuration: super::workload_owner::Configuration,
    ) -> Result<Self, Refused> {
        configuration.validate(&self.config.identity_authority_epoch, &self.config.scopes)?;
        let mut generation = [0; 16];
        self.rng.fill(&mut generation);
        let owner = super::workload_owner::Owner::new(configuration, generation)?;
        if owner.domain() == self.clock_domain {
            return Err(Refused);
        }
        self.workloads = Some(owner);
        Ok(self)
    }
    pub(crate) fn begin_workload(
        &self,
        service: &str,
        audience: &str,
    ) -> Result<Arc<super::workload_owner::Attempt>, Refused> {
        let owner = self.workloads.as_ref().ok_or(Refused)?;
        if !owner.permits(service, audience) {
            return Err(Refused);
        }
        owner.begin(self.clock.as_ref())
    }
    pub(crate) fn workloads_enabled(&self) -> bool {
        self.workloads.is_some()
    }
    pub(crate) fn observe_workload(
        &self,
        context: &Context<'_>,
        bytes: &[u8],
        request: &[u8; 32],
        verifier: &super::receipt_authority::Verifier,
    ) -> Result<Arc<super::workload_owner::Record>, Refused> {
        let owner = self.workloads.as_ref().ok_or(Refused)?;
        let epoch = hopae_grpc::workload_epoch::decode(context.identity_authority_epoch)
            .map_err(|_| Refused)?;
        if context.identity.kind != PrincipalKind::Workload
            || context.identity.aal != 0
            || context.issuer_ref != self.config.issuer_ref
            || context.key_epoch != self.config.key_epoch
            || epoch.authority != self.config.identity_authority_epoch
            || epoch.clock_domain != owner.domain()
            || context.request_sha256 != *request
            || !owner.permits(context.service, context.audience)
        {
            return Err(Refused);
        }
        let binding = super::receipt_binding::digest(context, None).map_err(|_| Refused)?;
        owner.ticks()?;
        let checked = verifier.verify_observed_signature(context, None, bytes)?;
        let record = owner.lookup(checked.evidence().sha256())?;
        if record.binding != binding
            || record.profile.revision != epoch.profile_revision
            || record.application.generation != epoch.application_generation
            || context.identity.revision != record.profile.revision
            || context.identity.credential_generation != record.profile.revision
            || checked.evidence().claims().expires_ms != record.attempt.expiry()
            || !checked.current()
        {
            return Err(record.attempt.retire());
        }
        record.current(self.clock.as_ref())?;
        Ok(record)
    }
    pub(crate) fn workload_time(
        &self,
        record: &super::workload_owner::Record,
    ) -> Result<(u64, u32), Refused> {
        let now = record.current(self.clock.as_ref())?;
        // Ticks quantize down: remove one full millisecond before exporting any
        // remaining admission. Signed expiry is the original entry bound itself.
        let remaining = record
            .attempt
            .expiry()
            .checked_sub(now)
            .and_then(|n| n.checked_sub(1))
            .filter(|n| (1..=1000).contains(n))
            .ok_or_else(|| record.attempt.retire())?;
        Ok((now, remaining as u32))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth_gateway::{
        authority::Authority,
        receipt_keys::{Key, Registry},
        runtime,
    };
    fn config(relay_url: Option<String>) -> runtime::Config {
        let mut value = serde_json::json!({"authority_id":"owned","profiles":[{"service_id":"orders","host":"orders.example.test","ports":[443],"realm":"partner","api_keys":[{"token_env":"OWNED_NATIVE_KEY","subject":"worker","expires_at":350}],"networks":["203.0.113.0/24"]}]});
        if let Some(url) = relay_url {
            value["profiles"][0]["relay_token_prefix"] = serde_json::json!("partner:");
            value["profiles"][0]["api_relay"] = serde_json::json!({"url":url,"issuer":"https://partner.example.test","timeout_ms":500,"allow_private_endpoints":true});
        }
        serde_json::from_value(value).unwrap()
    }
    const TOKEN: &str = "owned-native-key-at-least-thirty-two-bytes";
    fn owner(db: &mut rusqlite::Connection, configuration: runtime::Config) -> Authority {
        db.execute_batch("CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT NOT NULL)")
            .unwrap();
        Authority::load(
            db,
            Some(configuration),
            &|_| Some(TOKEN.into()),
            &|_| Ok(()),
        )
        .unwrap()
    }
    fn issuer(clock: Arc<dyn Clock>) -> Issuer {
        let signer = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        Issuer::new(
            Configuration {
                issuer_ref: "owned-hopae".into(),
                key_epoch: 1,
                identity_authority_epoch: "identity-1".into(),
                public_key: signer.verifying_key().to_bytes(),
                scopes: vec![Scope {
                    service: "orders".into(),
                    audience: "orders-api".into(),
                }],
            },
            Zeroizing::new([7; 32]),
            clock,
            Arc::new(crate::crypto::OsRng),
        )
        .unwrap()
    }
    #[tokio::test]
    async fn observed_clock_advances_through_backward_and_forward_wall_changes() {
        let clock = Arc::new(crate::crypto::TestClock::new(Timestamp(10_000)));
        let issuer = issuer(clock.clone());
        let first = issuer.clock_now().unwrap();
        clock.set(Timestamp(9_000));
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        let second = issuer.clock_now().unwrap();
        assert!(second >= first + 5);
        clock.set(Timestamp(20_000));
        let jumped = issuer.clock_now().unwrap();
        assert!(jumped >= 20_000);
        clock.set(Timestamp(9_000));
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        assert!(issuer.clock_now().unwrap() >= jumped + 5);
    }

    #[test]
    fn observed_source_progress_includes_suspended_age_even_when_utc_rolls_back() {
        let clock = Arc::new(crate::crypto::TestClock::new(Timestamp(10_000)));
        let issuer = issuer(clock.clone());
        assert_eq!(issuer.clock_sample(10_000, 0).unwrap(), 10_000);
        // Equal active time with rolled-back UTC models the previous freeze.
        assert_eq!(issuer.clock_sample(9_000, 0).unwrap(), 10_000);
        // Native BOOTTIME instead charges the two suspended seconds.
        assert_eq!(issuer.clock_sample(9_000, 2000).unwrap(), 12_000);
        assert_eq!(issuer.clock_sample(20_000, 2001).unwrap(), 20_000);
        assert_eq!(issuer.clock_sample(9_000, 4001).unwrap(), 22_000);
        // The original strict UTC API has a separate floor and semantics.
        assert_eq!(issuer.now().unwrap(), 10_000);
    }

    #[tokio::test]
    async fn unavailable_observed_clock_does_not_upgrade_or_break_legacy_issuance() {
        let mut db = rusqlite::Connection::open_in_memory().unwrap();
        let mut configuration = config(None);
        configuration.profiles[0].api_keys[0].expires_at = None;
        let owner = owner(&mut db, configuration);
        let authentication = owner
            .snapshot()
            .authenticate_for_receipt(
                "orders.example.test",
                443,
                Some(TOKEN),
                "203.0.113.9".parse().unwrap(),
                1000,
            )
            .await
            .unwrap();
        let mut signer = issuer(Arc::new(crate::crypto::TestClock::new(Timestamp(
            authentication.verified_ms as i64,
        ))));
        signer.clock_started = None;
        assert!(
            signer
                .issue_service(&authentication, request(), &|| Ok(()))
                .is_ok()
        );
        assert!(
            signer
                .issue_service_owned(&authentication, request(), Some(1), true, &|| Ok(()))
                .is_err()
        );
        assert!(signer.clock_now().is_err());
    }

    fn request() -> Request<'static> {
        Request {
            service: "orders",
            audience: "orders-api",
            request_sha256: [4; 32],
        }
    }
    fn verify(issued: &Issued, now: u64) {
        let registry = Registry::compile(
            1,
            &[Key {
                issuer_ref: "owned-hopae".into(),
                purpose: Purpose::Authentication,
                epoch: 1,
                public_key: ed25519_dalek::SigningKey::from_bytes(&[7; 32])
                    .verifying_key()
                    .to_bytes(),
            }],
            None,
        )
        .unwrap();
        registry
            .verify(&issued.context(), None, issued.bytes(), now)
            .unwrap();
        assert_eq!(issued.context().identity.kind, PrincipalKind::Service);
        assert_eq!(issued.context().identity.aal, 0);
        assert_eq!(issued.context().identity.revision, 1);
        assert_eq!(issued.context().identity.credential_generation, 1);
        if let Ok(epoch) =
            hopae_grpc::service_epoch::decode(issued.context().identity_authority_epoch)
        {
            assert_eq!(epoch.authority, "identity-1");
            assert_eq!(epoch.profile_revision, 1);
        } else {
            assert_eq!(
                issued.context().identity_authority_epoch,
                "identity-1:service:1"
            );
        }
    }
    #[tokio::test]
    async fn native_service_adapter_refuses_late_verifier_success_after_profile_revocation() {
        let entered = Arc::new(tokio::sync::Notify::new());
        let released = Arc::new(tokio::sync::Notify::new());
        let arrived = entered.clone();
        let resume = released.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = axum::Router::new().route("/verify", axum::routing::post(move || {
            let arrived = arrived.clone(); let resume = resume.clone();
            async move {
                arrived.notify_one(); resume.notified().await;
                let now = crate::crypto::SystemClock.now().0 as u64;
                axum::Json(serde_json::json!({"active":true,"subject":"worker","service_id":"orders","expires_at":now+1000}))
            }
        }));
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let mut db = rusqlite::Connection::open_in_memory().unwrap();
        let mut configuration = config(Some(format!("http://{address}/verify")));
        configuration.profiles[0].api_keys[0].expires_at = None;
        let mut owner = owner(&mut db, configuration);
        let reader = owner.reader();
        let old = reader.load_full();
        let issuer = issuer(Arc::new(crate::crypto::SystemClock));
        let calls = std::cell::Cell::new(0usize);
        let guard = || {
            calls.set(calls.get() + 1);
            Ok(())
        };
        let issue = issuer.authenticate_service_and_issue(
            &reader,
            ServiceRequest {
                host: "orders.example.test",
                port: 443,
                credential: Some("partner:owned-relay-credential"),
                client_ip: "203.0.113.9".parse().unwrap(),
            },
            request(),
            &guard,
        );
        let revoke = async {
            tokio::time::timeout(std::time::Duration::from_secs(2), entered.notified())
                .await
                .unwrap();
            owner
                .publish(
                    &mut db,
                    1,
                    None,
                    "owned-operator",
                    &|_| Some(TOKEN.into()),
                    &|_| Ok(()),
                )
                .unwrap();
            assert_eq!(reader.load_full().revision, 2);
            assert!(
                old.available(),
                "completed publication resets shared availability; pointer fencing remains necessary"
            );
            released.notify_one();
        };
        let (result, ()) = tokio::join!(issue, revoke);
        assert!(
            result.is_err(),
            "late valid external identity must not obtain a revoked receipt"
        );
        assert_eq!(
            calls.get(),
            1,
            "old owner must be rejected before signing guard"
        );
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn live_service_rechecks_profile_after_clock_sample_for_both_contracts() {
        // Run a real native publication inside the Clock trait call. This gives
        // the interleaving deterministically without sleeps or scheduler races.
        #[derive(Default)]
        struct PublishingClock {
            on_read: std::sync::Mutex<Option<Box<dyn FnOnce() + Send>>>,
        }
        impl Clock for PublishingClock {
            fn now(&self) -> Timestamp {
                let callback = self.on_read.lock().unwrap().take();
                if let Some(callback) = callback {
                    callback();
                }
                Timestamp(1000)
            }
        }

        for clocked in [false, true] {
            let mut db = rusqlite::Connection::open_in_memory().unwrap();
            let mut configuration = config(None);
            configuration.profiles[0].api_keys[0].expires_at = None;
            let mut owner = owner(&mut db, configuration);
            let reader = owner.reader();
            let profile = reader.load_full();
            let clock = Arc::new(PublishingClock::default());
            let signer = issuer(clock.clone());
            let authentication = profile
                .authenticate_for_receipt(
                    "orders.example.test",
                    443,
                    Some(TOKEN),
                    "203.0.113.9".parse().unwrap(),
                    1000,
                )
                .await
                .unwrap();
            let cfg = crate::config::parse(
                r#"{"state_dir":"owned","portal":{"public_url":"https://auth.example.test"},"gateway":{"kind":"hangang","caller_key_env":"OWNED_GATEWAY"}}"#,
            )
            .unwrap();
            let application = Arc::new(cfg.snapshot(1));
            let applications = Arc::new(arc_swap::ArcSwap::from(application.clone()));
            let captured = CapturedService {
                authentication,
                profile,
                application,
            };
            let issued = captured
                .issue_domain(&signer, &reader, &applications, request(), clocked, &|| {
                    Ok(())
                })
                .unwrap();
            let mut key_owner = super::super::receipt_authority::Authority::load(&db, 0).unwrap();
            key_owner
                .reconcile(
                    &mut db,
                    &[Key {
                        issuer_ref: "owned-hopae".into(),
                        purpose: Purpose::Authentication,
                        epoch: 1,
                        public_key: ed25519_dalek::SigningKey::from_bytes(&[7; 32])
                            .verifying_key()
                            .to_bytes(),
                    }],
                    "owned-operator",
                    &|_| Ok(()),
                )
                .unwrap();
            let verifier = key_owner.verifier();
            let live = signer
                .verify_live_service_domain(
                    &reader,
                    &applications,
                    &issued.context(),
                    issued.bytes(),
                    &request().request_sha256,
                    clocked.then_some(&verifier),
                )
                .unwrap();
            assert!(live.current().is_ok());

            // The old snapshot's shared publication flag becomes available
            // again after the replacement is installed. Only a fresh pointer
            // comparison can identify the completed withdrawal.
            *clock.on_read.lock().unwrap() = Some(Box::new(move || {
                owner
                    .publish(
                        &mut db,
                        1,
                        None,
                        "owned-operator",
                        &|_| Some(TOKEN.into()),
                        &|_| Ok(()),
                    )
                    .unwrap();
            }));
            let result = live.current();
            assert_eq!(reader.load_full().revision, 2);
            assert!(captured.profile.available());
            assert!(
                !Arc::ptr_eq(&reader.load_full(), &captured.profile),
                "the native owner must really have replaced the old snapshot"
            );
            let still_before_expiry = live
                .verified_ms
                .saturating_add(u64::try_from(live.begun.elapsed().as_millis()).unwrap())
                < live.expires_ms;
            assert!(
                still_before_expiry,
                "test must not pass through incidental expiry"
            );
            if clocked {
                assert!(signer.clock_now().unwrap() < live.expires_ms);
                assert!(live.key_check.as_ref().unwrap().current());
            }
            assert!(
                result.is_err(),
                "withdrawal completed during final clock sampling must refuse (clocked={clocked})"
            );
        }
    }

    #[tokio::test]
    async fn captured_proof_signs_without_reauthentication_and_refuses_application_replacement() {
        let mut db = rusqlite::Connection::open_in_memory().unwrap();
        let mut configuration = config(None);
        configuration.profiles[0].api_keys[0].expires_at = None;
        let owner = owner(&mut db, configuration);
        let reader = owner.reader();
        let profile = reader.load_full();
        let clock = Arc::new(crate::crypto::TestClock::new(Timestamp(1000)));
        let signer = issuer(clock.clone());
        let authentication = profile
            .authenticate_for_receipt(
                "orders.example.test",
                443,
                Some(TOKEN),
                "203.0.113.9".parse().unwrap(),
                clock.now().0 as u64,
            )
            .await
            .unwrap();
        let cfg=crate::config::parse(r#"{"state_dir":"owned","portal":{"public_url":"https://auth.example.test"},"gateway":{"kind":"hangang","caller_key_env":"OWNED_GATEWAY"}}"#).unwrap();
        let application = Arc::new(cfg.snapshot(1));
        let applications = Arc::new(arc_swap::ArcSwap::from(application.clone()));
        let captured = CapturedService {
            authentication,
            profile,
            application,
        };
        let issued = captured
            .issue(&signer, &reader, &applications, request(), &|| Ok(()))
            .unwrap();
        verify(&issued, clock.now().0 as u64);
        let epoch =
            hopae_grpc::service_epoch::decode(issued.context().identity_authority_epoch).unwrap();
        assert_eq!(
            epoch.application_generation,
            captured.application_generation()
        );
        assert_eq!(epoch.profile_revision, issued.context().identity.revision);
        let live = signer
            .verify_live_service(
                &reader,
                &applications,
                &issued.context(),
                issued.bytes(),
                &request().request_sha256,
            )
            .unwrap();
        assert!(live.current().is_ok());
        let mut tampered = *issued.bytes();
        tampered[20] ^= 1;
        assert!(
            signer
                .verify_live_service(
                    &reader,
                    &applications,
                    &issued.context(),
                    &tampered,
                    &request().request_sha256
                )
                .is_err()
        );
        applications.store(Arc::new(cfg.snapshot(1)));
        assert!(live.current().is_err());
        applications.store(Arc::new(cfg.snapshot(2)));
        assert!(
            signer
                .verify_live_service(
                    &reader,
                    &applications,
                    &issued.context(),
                    issued.bytes(),
                    &request().request_sha256
                )
                .is_err()
        );
        assert!(
            captured
                .issue(&signer, &reader, &applications, request(), &|| panic!(
                    "replacement must be fenced before signing guard"
                ))
                .is_err()
        );
        applications.store(captured.application.clone());
        reader.store(Arc::new(super::super::authority::Snapshot {
            publication: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            revision: 2,
            runtime: None,
        }));
        assert!(live.current().is_err());
        assert!(
            signer
                .verify_live_service(
                    &reader,
                    &applications,
                    &issued.context(),
                    issued.bytes(),
                    &request().request_sha256
                )
                .is_err()
        );
        reader.store(captured.profile.clone());
        clock.set(Timestamp(live.expires_ms() as i64));
        assert!(live.current().is_err());
        assert!(
            signer
                .verify_live_service(
                    &reader,
                    &applications,
                    &issued.context(),
                    issued.bytes(),
                    &request().request_sha256
                )
                .is_err()
        );
    }

    #[tokio::test]
    async fn native_service_adapter_fences_owner_change_during_final_guard() {
        let mut db = rusqlite::Connection::open_in_memory().unwrap();
        let mut configuration = config(None);
        configuration.profiles[0].api_keys[0].expires_at = None;
        let owner = owner(&mut db, configuration);
        let reader = owner.reader();
        let clock = Arc::new(crate::crypto::SystemClock);
        let issuer = issuer(clock.clone());
        let input = || ServiceRequest {
            host: "orders.example.test",
            port: 443,
            credential: Some(TOKEN),
            client_ip: "203.0.113.9".parse().unwrap(),
        };
        let issued = issuer
            .authenticate_service_and_issue(&reader, input(), request(), &|| Ok(()))
            .await
            .unwrap();
        verify(&issued, clock.now().0 as u64);
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let changed = issuer
            .authenticate_service_and_issue(&reader, input(), request(), &|| {
                if calls.fetch_add(1, Ordering::SeqCst) == 2 {
                    reader
                        .load_full()
                        .publication
                        .store(true, Ordering::Release);
                }
                Ok(())
            })
            .await;
        assert!(
            changed.is_err(),
            "final owner unavailability cannot release a receipt"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn native_profile_proof_signs_aal_zero_and_refuses_scope_kind_and_revocation() {
        let mut db = rusqlite::Connection::open_in_memory().unwrap();
        let mut owner = owner(&mut db, config(None));
        let snapshot = owner.snapshot();
        let mut authentication = snapshot
            .authenticate_for_receipt(
                "orders.example.test",
                443,
                Some(TOKEN),
                "203.0.113.9".parse().unwrap(),
                100,
            )
            .await
            .unwrap();
        let clock = Arc::new(crate::crypto::TestClock::new(Timestamp(
            authentication.verified_ms as i64,
        )));
        let issuer = issuer(clock.clone());
        let issued = issuer
            .issue_service(&authentication, request(), &|| Ok(()))
            .unwrap();
        verify(&issued, clock.now().0 as u64);
        assert_eq!(
            issued.context().identity.subject_ref,
            super::super::stable_subject(&authentication.evidence.subject)
        );
        let claims = receipt::verify(
            &issuer.signer.verifying_key(),
            issued.bytes(),
            Purpose::Authentication,
            &super::super::receipt_binding::digest(&issued.context(), None).unwrap(),
            clock.now().0 as u64,
        )
        .unwrap();
        assert_eq!(claims.claims().expires_ms, 350);
        for kind in [
            PrincipalKind::Human,
            PrincipalKind::Network,
            PrincipalKind::Workload,
        ] {
            authentication.evidence.subject.kind = kind;
            assert!(
                issuer
                    .issue_service(&authentication, request(), &|| panic!(
                        "wrong kind reached owner guard"
                    ))
                    .is_err()
            );
        }
        authentication.evidence.subject.kind = PrincipalKind::Service;
        assert!(
            issuer
                .issue_service(
                    &authentication,
                    Request {
                        service: "billing",
                        ..request()
                    },
                    &|| panic!("wrong service reached guard")
                )
                .is_err()
        );
        assert!(
            issuer
                .issue_service(
                    &authentication,
                    Request {
                        audience: "billing-api",
                        ..request()
                    },
                    &|| panic!("wrong audience reached guard")
                )
                .is_err()
        );
        assert!(
            snapshot
                .authenticate_for_receipt(
                    "orders.example.test",
                    443,
                    Some("unknown-credential-at-least-thirty-two-bytes"),
                    "203.0.113.9".parse().unwrap(),
                    100
                )
                .await
                .is_err()
        );
        assert!(
            snapshot
                .authenticate_for_receipt(
                    "orders.example.test",
                    443,
                    Some(TOKEN),
                    "198.51.100.9".parse().unwrap(),
                    100
                )
                .await
                .is_err()
        );
        owner
            .publish(
                &mut db,
                1,
                None,
                "operator",
                &|_| Some(TOKEN.into()),
                &|_| Ok(()),
            )
            .unwrap();
        let guard = || {
            if super::super::publication::read(&db)
                .map_err(|_| Refused)?
                .ok_or(Refused)?
                .revision
                == authentication.revision()
            {
                Ok(())
            } else {
                Err(Refused)
            }
        };
        assert!(
            issuer
                .issue_service(&authentication, request(), &guard)
                .is_err()
        );
        assert!(
            owner
                .snapshot()
                .authenticate_for_receipt(
                    "orders.example.test",
                    443,
                    Some(TOKEN),
                    "203.0.113.9".parse().unwrap(),
                    100
                )
                .await
                .is_err()
        );
    }
    #[tokio::test]
    async fn service_issuance_rechecks_final_guard_expiry_and_clock_rollback() {
        let mut db = rusqlite::Connection::open_in_memory().unwrap();
        let owner = owner(&mut db, config(None));
        let authentication = owner
            .snapshot()
            .authenticate_for_receipt(
                "orders.example.test",
                443,
                Some(TOKEN),
                "203.0.113.9".parse().unwrap(),
                100,
            )
            .await
            .unwrap();
        let clock = Arc::new(crate::crypto::TestClock::new(Timestamp(
            authentication.verified_ms as i64,
        )));
        let issuer = issuer(clock.clone());
        let calls = std::cell::Cell::new(0);
        assert!(
            issuer
                .issue_service(&authentication, request(), &|| {
                    calls.set(calls.get() + 1);
                    if calls.get() == 2 {
                        Err(Refused)
                    } else {
                        Ok(())
                    }
                })
                .is_err()
        );
        assert_eq!(calls.get(), 2);
        assert!(
            issuer
                .issue_service(&authentication, request(), &|| {
                    clock.set(Timestamp(350));
                    Ok(())
                })
                .is_err()
        );
        clock.set(Timestamp(100));
        assert!(
            issuer
                .issue_service(&authentication, request(), &|| panic!(
                    "expired service evidence revived"
                ))
                .is_err()
        );
    }
    #[tokio::test]
    async fn mixed_relay_and_native_proofs_preserve_distinct_namespace_and_aal_zero() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app=axum::Router::new().route("/verify",axum::routing::post(|headers:axum::http::HeaderMap|async move{
            let fake=headers[http::header::AUTHORIZATION].to_str().unwrap().contains("fake-mfa");
            let mut value=serde_json::json!({"active":true,"subject":"worker","service_id":"orders","expires_at":1000});
            if fake{value["aal"]=serde_json::json!(3);}
            axum::Json(value)
        }));
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let mut db = rusqlite::Connection::open_in_memory().unwrap();
        let owner = owner(&mut db, config(Some(format!("http://{address}/verify"))));
        let snapshot = owner.snapshot();
        let native = snapshot
            .authenticate_for_receipt(
                "orders.example.test",
                443,
                Some(TOKEN),
                "203.0.113.9".parse().unwrap(),
                100,
            )
            .await
            .unwrap();
        let relay = snapshot
            .authenticate_for_receipt(
                "orders.example.test",
                443,
                Some("partner:owned-relay-credential"),
                "203.0.113.9".parse().unwrap(),
                100,
            )
            .await
            .unwrap();
        let clock = Arc::new(crate::crypto::TestClock::new(Timestamp(
            native.verified_ms.max(relay.verified_ms) as i64,
        )));
        let issuer = issuer(clock.clone());
        let native = issuer
            .issue_service(&native, request(), &|| Ok(()))
            .unwrap();
        let relay = issuer.issue_service(&relay, request(), &|| Ok(())).unwrap();
        verify(&native, clock.now().0 as u64);
        verify(&relay, clock.now().0 as u64);
        assert_ne!(
            native.context().identity.subject_ref,
            relay.context().identity.subject_ref
        );
        assert!(
            snapshot
                .authenticate_for_receipt(
                    "orders.example.test",
                    443,
                    Some("partner:fake-mfa-credential"),
                    "203.0.113.9".parse().unwrap(),
                    100
                )
                .await
                .is_err()
        );
        server.abort();
    }
}
