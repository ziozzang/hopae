//! The portal's view of the session and identity services.
//!
//! The portal owns transport: cookies, CSRF, `Origin`, headers, templates and
//! language. Everything that reads or writes a transaction, a session, a
//! handle or an identity is behind [`PortalServices`], which `session::Service`
//! and `identity::Service` (W1-D) satisfy through one adapter. Each method is
//! named after the flow it serves and returns a typed result; a result never
//! carries a bearer value except the handle the browser must be given.

use std::net::IpAddr;
use std::time::Duration;

use async_trait::async_trait;
use url::{Origin, Url};

use crate::crypto::Secret;
use crate::event::types::Reason;
use crate::provider::types::{CallbackQuery, ProviderHealth, ProviderId};

/// Per-request facts the services record in events and transactions.
#[derive(Clone, Debug)]
pub struct RequestCtx {
    pub request_id: String,
    /// The client's own `x-request-id` (never trusted, never used as `request_id`).
    pub client_request_id: Option<String>,
    /// Client address after the trusted-proxy rule (never a raw header value).
    pub client_ip: IpAddr,
    pub user_agent: Option<String>,
    /// Whether the client connection was HTTPS, from a trusted proxy only.
    pub https: bool,
}

/// Cookies the browser presented, already checked for well-formedness
/// (a malformed value is treated as absent).
#[derive(Clone, Debug, Default)]
pub struct Cookies {
    /// The portal binding cookie. On `GET /login`, `GET /switch` and the
    /// SSO-confirmation page the portal passes the effective value: the
    /// presented one, or a freshly generated one it is about to plant.
    pub bind: Option<Secret>,
    /// The portal handle (`__Host-hopae` on the portal host).
    pub handle: Option<Secret>,
}

/// A handle to be planted on the portal host.
#[derive(Clone, Debug)]
pub struct HandleCookie {
    pub value: Secret,
    /// The handle's remaining absolute lifetime.
    pub max_age: Duration,
}

/// A `302` the portal must issue.
#[derive(Clone, Debug)]
pub struct Redirect {
    pub location: Url,
    pub set_handle: Option<HandleCookie>,
}

/// How the portal words a failure. The page never shows the reason code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailKind {
    /// `400`, "this sign-in link has expired" (unknown, expired, consumed or mismatched transaction).
    Expired,
    /// `400`, generic "sign-in failed" (provider, token or state problems).
    Failed,
    /// `403` (CSRF-protected action refused, retry not allowed).
    Forbidden,
    /// `503` (store or provider unavailable).
    Unavailable,
}

/// A refusal with its stable reason code (for logs; never rendered).
#[derive(Clone, Copy, Debug)]
pub struct Failure {
    pub kind: FailKind,
    pub reason: Reason,
}

#[derive(Clone, Debug)]
pub struct ProviderChoice {
    pub id: ProviderId,
    pub display_name: String,
    /// `false` renders "temporarily unavailable" instead of a button.
    pub available: bool,
}

/// Result of `GET /login?txn=`.
#[derive(Clone, Debug)]
pub enum LoginVisit {
    /// Show the chooser (several providers, or one that is unavailable).
    Chooser {
        providers: Vec<ProviderChoice>,
        /// Origin of every enabled provider's authorization endpoint, from
        /// discovery: the page's CSP `form-action` lists them (R-5), because
        /// the browser enforces it on the redirect that follows the POST.
        form_origins: Vec<Origin>,
    },
    /// Immediate redirect: single enabled provider, or single sign-on from a valid portal handle.
    Redirect(Redirect),
    /// `portal.sso_confirm_new_host`: ask once before the first handoff to `host`.
    ConfirmNewHost {
        host: String,
        /// Origin of the transaction's return target (`form-action`, R-5).
        form_origin: Origin,
    },
    Failed(Failure),
}

/// Result of `GET /callback/<provider>`.
#[derive(Clone, Debug)]
pub enum CallbackOutcome {
    /// Session created or reused: redirect to the return target with the handoff code.
    Redirect(Redirect),
    /// `linking.on_conflict = link_required`: "sign in with <provider> to connect it".
    LinkNotice {
        via_provider: Option<String>,
    },
    /// The portal binding cookie differed (first-contact race). The transaction
    /// is consumed and `retry_bind_sha256` recorded; `can_retry` is false once
    /// `handoff.max_recoveries` is reached.
    RetryOffer {
        can_retry: bool,
        /// Origin of the interrupted transaction's provider (`form-action`, R-5).
        form_origin: Option<Origin>,
    },
    Failed(Failure),
}

/// What `GET /switch?txn=` names.
#[derive(Clone, Debug)]
pub struct SwitchView {
    pub host: String,
    pub current_account: String,
    pub incoming_account: String,
    /// Origin of the transaction's return target (`form-action`, R-5).
    pub form_origin: Origin,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SwitchChoice {
    Switch,
    Keep,
}

/// Provider and store state for `/healthz`.
#[derive(Clone, Debug)]
pub struct Health {
    pub store_ok: bool,
    pub providers: Vec<(ProviderId, ProviderHealth)>,
}

#[async_trait]
pub trait PortalServices: Send + Sync + 'static {
    /// `GET /login?txn=`: validate the transaction (unexpired, unconsumed, client
    /// IP policy), decide chooser, immediate provider redirect, SSO handoff or
    /// confirmation. The services record the portal binding digest when the
    /// provider redirect is issued (immutable afterwards).
    async fn login_visit(&self, ctx: &RequestCtx, txn: &Secret, cookies: &Cookies) -> LoginVisit;

    /// `POST /login/<provider>` after CSRF and `Origin`: store state, nonce and
    /// PKCE; return the provider's authorization URL.
    async fn begin_provider(
        &self,
        ctx: &RequestCtx,
        txn: &Secret,
        provider: &ProviderId,
        cookies: &Cookies,
    ) -> Result<Redirect, Failure>;

    /// `GET /callback/<provider>`: locate the transaction by `state`, check the
    /// portal binding, exchange and validate, resolve identity, create or reuse
    /// the session, mint the handoff code.
    async fn callback(
        &self,
        ctx: &RequestCtx,
        provider: &ProviderId,
        query: CallbackQuery,
        cookies: &Cookies,
    ) -> CallbackOutcome;

    /// `POST /login/retry` after CSRF and `Origin`: `state` names the consumed
    /// transaction; `cookies.bind` must match its `retry_bind_sha256`; start a
    /// new transaction at `recovery_depth + 1` and return the provider redirect.
    async fn retry(
        &self,
        ctx: &RequestCtx,
        state: &str,
        cookies: &Cookies,
    ) -> Result<Redirect, Failure>;

    /// `POST /login/continue` after CSRF and `Origin`: the one click of
    /// `portal.sso_confirm_new_host`; mint the SSO handoff.
    async fn continue_sso(
        &self,
        ctx: &RequestCtx,
        txn: &Secret,
        cookies: &Cookies,
    ) -> Result<Redirect, Failure>;

    /// `GET /switch?txn=`: no state change.
    async fn switch_view(
        &self,
        ctx: &RequestCtx,
        txn: &Secret,
        cookies: &Cookies,
    ) -> Result<SwitchView, Failure>;

    /// `POST /switch` after CSRF and `Origin`: purpose must be `switch`.
    async fn switch_confirm(
        &self,
        ctx: &RequestCtx,
        txn: &Secret,
        choice: SwitchChoice,
        cookies: &Cookies,
    ) -> Result<Redirect, Failure>;

    /// `POST /logout` after CSRF and `Origin`, with a well-formed handle:
    /// terminate that handle's session (`reason=logout`). Unknown or already
    /// revoked handles are a silent no-op (`Ok(false)`).
    async fn logout(&self, ctx: &RequestCtx, handle: &Secret) -> Result<bool, Failure>;

    /// Append a `csrf.rejected` event. `purpose` is the CSRF purpose name;
    /// `cause` is `origin`, `token` or `expired`. Best effort.
    async fn csrf_rejected(&self, ctx: &RequestCtx, purpose: &'static str, cause: &'static str);

    /// `/healthz` body input.
    async fn health(&self) -> Health;
}
