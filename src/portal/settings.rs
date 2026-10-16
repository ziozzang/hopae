//! The portal's view of the security settings and passkey services
//! (ADR-0017). Like [`super::ports::PortalServices`], the portal owns
//! transport and presentation; everything that touches a session, a
//! credential or a code is behind [`SecurityServices`].

use async_trait::async_trait;
use url::Origin;

use super::ports::{Cookies, Failure, HandleCookie, Redirect, RequestCtx};
use crate::crypto::{Secret, Timestamp};

/// One passkey as the security pages show it.
#[derive(Clone, Debug)]
pub struct PasskeyView {
    /// base64url of the credential id (the form value naming it).
    pub id: String,
    pub label: String,
    /// Backup-eligible: a synchronized passkey (password manager, platform keychain).
    pub synced: bool,
    /// Attested high-assurance security key.
    pub high_assurance: bool,
    pub created_at: Timestamp,
    pub last_used_at: Option<Timestamp>,
}

/// Everything the overview and the list need.
#[derive(Clone, Debug, Default)]
pub struct SecurityView {
    pub passkeys: Vec<PasskeyView>,
    pub totp_active: bool,
    /// An authenticator app can be set up on this deployment.
    pub totp_available: bool,
    pub recovery_unused: u32,
    pub recovery_generated: bool,
    /// A recovery code was used: a new factor must be added.
    pub recovery_required: bool,
    /// Factor management is allowed right now (ADR-0017 decision 10).
    pub can_manage: bool,
    /// The user has a second factor to verify with.
    pub can_verify: bool,
    /// The high-assurance (attested security key) registration exists.
    pub high_assurance_available: bool,
    /// The only way to manage factors is a new primary sign-in.
    pub needs_fresh_sign_in: bool,
}

/// A ceremony to render: the bearer the form carries and the options JSON
/// for `navigator.credentials`.
pub struct CeremonyPage {
    pub ceremony: Secret,
    pub options: String,
}

/// The passkey step-up page.
pub struct StepUpCeremony {
    pub page: Option<CeremonyPage>,
    /// Origin of the step-up's return target (`form-action`).
    pub form_origin: Origin,
    pub totp: bool,
    /// The target requires AAL 3: only high-assurance keys are offered, and
    /// without one (`page: None`) the user is told so instead of being sent
    /// to methods that cannot satisfy the rule.
    pub high_assurance: bool,
}

/// A refusal the page explains (the user can act on it), or a plain failure page.
#[derive(Clone, Copy, Debug)]
pub enum Refusal {
    /// A recent second factor (or a fresh sign-in, without one) is needed first.
    VerificationRequired,
    /// The passkey is the last second factor.
    LastFactor,
    /// This authenticator is already registered.
    Duplicate,
    /// The maximum number of passkeys is registered.
    Capacity,
    /// The passkey response could not be verified (or the browser sent none).
    Rejected,
    /// The ceremony expired or was already used.
    Expired,
    /// High-assurance registration: the security key is not on the approved list.
    NotAllowedAuthenticator,
    /// The passkey reported a lower use counter: it was disabled.
    CloneSuspected,
    /// The target needs a high-assurance security key (AAL 3, ADR-0018).
    HighAssuranceRequired,
    /// The authenticator or recovery code is wrong or used.
    InvalidCode,
    /// Too many attempts from this address.
    RateLimited,
    /// Anything else: rendered as the generic page for `kind`.
    Failure(Failure),
}

#[async_trait]
pub trait SecurityServices: Send + Sync {
    fn high_assurance_available(&self) -> bool;
    async fn overview(&self, ctx: &RequestCtx, cookies: &Cookies) -> Result<SecurityView, Refusal>;
    async fn begin_registration(
        &self,
        ctx: &RequestCtx,
        cookies: &Cookies,
        high_assurance: bool,
    ) -> Result<CeremonyPage, Refusal>;
    async fn finish_registration(
        &self,
        ctx: &RequestCtx,
        cookies: &Cookies,
        ceremony: &Secret,
        label: Option<&str>,
        default_label: (&str, &str),
        response: &str,
    ) -> Result<(), Refusal>;
    async fn rename(
        &self,
        ctx: &RequestCtx,
        cookies: &Cookies,
        credential: &str,
        label: &str,
    ) -> Result<(), Refusal>;
    async fn remove(
        &self,
        ctx: &RequestCtx,
        cookies: &Cookies,
        credential: &str,
    ) -> Result<(), Refusal>;
    /// A verification ceremony when the user has passkeys.
    async fn begin_verify(
        &self,
        ctx: &RequestCtx,
        cookies: &Cookies,
    ) -> Result<Option<CeremonyPage>, Refusal>;
    async fn verify_passkey(
        &self,
        ctx: &RequestCtx,
        cookies: &Cookies,
        ceremony: &Secret,
        response: &str,
    ) -> Result<HandleCookie, Refusal>;
    async fn verify_totp(
        &self,
        ctx: &RequestCtx,
        cookies: &Cookies,
        code: &Secret,
    ) -> Result<HandleCookie, Refusal>;
    async fn verify_recovery(
        &self,
        ctx: &RequestCtx,
        cookies: &Cookies,
        code: &Secret,
    ) -> Result<HandleCookie, Refusal>;
    /// A new set of recovery codes, shown once.
    async fn generate_recovery_codes(
        &self,
        ctx: &RequestCtx,
        cookies: &Cookies,
    ) -> Result<Vec<zeroize::Zeroizing<String>>, Refusal>;
    /// The passkey step-up page for an application's step-up transaction.
    async fn begin_stepup(
        &self,
        ctx: &RequestCtx,
        cookies: &Cookies,
        transaction: &Secret,
    ) -> Result<StepUpCeremony, Refusal>;
    /// Complete a passwordless passkey sign-in on the chooser's transaction.
    async fn finish_login(
        &self,
        ctx: &RequestCtx,
        cookies: &Cookies,
        transaction: &Secret,
        ceremony: &Secret,
        response: &str,
    ) -> Result<Redirect, Refusal>;
    async fn complete_stepup(
        &self,
        ctx: &RequestCtx,
        cookies: &Cookies,
        transaction: &Secret,
        ceremony: &Secret,
        response: &str,
    ) -> Result<Redirect, Refusal>;
}
