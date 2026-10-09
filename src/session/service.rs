//! The session service: login transactions, the provider round trip, the
//! callback that turns a validated assertion into a session, single sign-on
//! and logout (ADR-0004, ADR-0008, ADR-0011). Handoff minting and redemption
//! live in `handoff`, the account switch in `switch`, transaction creation and
//! the portal retry in `transactions`; all of them are methods of [`Service`].
//!
//! Security invariants kept here:
//! - The single-use transaction is consumed *before* any user or session is
//!   written, by the store's conditional update, so two racing callbacks
//!   produce one session.
//! - The portal binding digest is recorded once, when the provider redirect is
//!   issued, and never changes; the callback compares it in constant time.
//! - No secret (state, nonce, PKCE verifier, codes, handles, cookies) is ever
//!   placed in an event, an error or a log line.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use url::Url;

use crate::config::Config;
use crate::crypto::{
    Clock, Digest, Rng, Secret, ct_eq, handle_value, is_well_formed_bind, is_well_formed_handle,
    random_id, random_token, sha256,
};
use crate::event::types::{Event, EventBuilder, EventKind, Outcome, Reason, reasons};
use crate::identity::linking::LinkingPolicy;
use crate::identity::service::{EventCtx, PendingIdentity, Resolution, Service as IdentityService};
use crate::identity::types::UserId;
use crate::policy::types::{
    AppPolicy, ConfigSnapshot, Host, IpBinding, OnMismatch, SessionPolicy, UaBinding,
};
use crate::provider::types::{CallbackQuery, Provider, ProviderError, ProviderId, ProviderKind};
use crate::session::handoff::{CodeDirectory, MintRequest};
use crate::session::types::{Aal, FactorEntry, FactorKind, SessionId};
use crate::store::types::{
    CreateSession, HandleRow, HandleView, IdentitySnapshot, NewTransaction, SessionRow,
    TransactionBinding, TransactionRow, TxnPurpose, User, UserStatus,
};
use crate::store::{Directory, Events, Sessions, StoreError};

/// The callback arrived on a path whose provider is not the one the
/// transaction chose (ADR-0010 mix-up defence). Local until the shared reason
/// table gains it (reported to the orchestrator).
pub const PROVIDER_MISMATCH: Reason = Reason("provider_mismatch");
/// `consumed_reason` of a transaction that completed a login (text column).
pub(crate) const CONSUMED_COMPLETED: Reason = Reason("completed");
/// `consumed_reason` of a transaction that ended in single sign-on.
pub(crate) const CONSUMED_SSO: Reason = Reason("sso");

/// Lifetime of a login transaction (ARCHITECTURE: `login_txns.expires_at` 10 min).
pub const TXN_LIFETIME: Duration = Duration::from_secs(10 * 60);
/// Lifetime of a handoff code (ADR-0004).
pub const CODE_LIFETIME: Duration = Duration::from_secs(60);
/// Window of the per-IP counters.
pub(crate) const COUNTER_WINDOW: Duration = Duration::from_secs(60);

/// What the portal or the verify engine knows about the request.
#[derive(Clone, Debug)]
pub struct RequestCtx {
    pub client_ip: IpAddr,
    pub user_agent: Option<String>,
    pub request_id: String,
}

/// Numbers and switches the service needs, from the configuration.
#[derive(Clone, Debug)]
pub struct ServiceConfig {
    pub portal_host: Host,
    pub portal_url: Url,
    /// `cookie.secure`
    pub secure: bool,
    pub session: SessionPolicy,
    pub txn_max_rows: u32,
    pub txn_per_ip_per_minute: u32,
    pub handoff_failures_per_minute: u32,
    pub max_recoveries: u32,
    pub sso_confirm_new_host: bool,
    pub linking: LinkingPolicy,
}

impl ServiceConfig {
    /// Read the values from a validated configuration.
    pub fn from_config(cfg: &Config) -> Result<ServiceConfig, String> {
        let portal_url = Url::parse(&cfg.portal.public_url)
            .map_err(|_| "portal.public_url is not a URL".to_string())?;
        let host = portal_url
            .host_str()
            .and_then(|h| Host::parse(h).ok())
            .ok_or_else(|| "portal.public_url has no usable host".to_string())?;
        Ok(ServiceConfig {
            portal_host: host,
            portal_url,
            secure: cfg.cookie.secure,
            session: cfg.session_policy(),
            txn_max_rows: cfg.txn.max_rows,
            txn_per_ip_per_minute: cfg.txn.per_ip_per_minute,
            handoff_failures_per_minute: cfg.handoff.per_ip_failures_per_minute,
            max_recoveries: cfg.handoff.max_recoveries,
            sso_confirm_new_host: cfg.portal.sso_confirm_new_host,
            linking: LinkingPolicy {
                mode: cfg.linking.mode,
                on_conflict: cfg.linking.on_conflict,
            },
        })
    }
}

/// Provider instances by id (implemented by `provider::Registry`).
pub trait ProviderLookup: Send + Sync {
    fn get(&self, id: &ProviderId) -> Option<Arc<dyn Provider>>;
    /// Enabled providers in chooser order.
    fn enabled_sorted(&self) -> Vec<Arc<dyn Provider>>;
}

pub struct Deps {
    pub directory: Arc<dyn Directory>,
    pub sessions: Arc<dyn Sessions>,
    pub events: Arc<dyn Events>,
    pub codes: Arc<dyn CodeDirectory>,
    pub clock: Arc<dyn Clock>,
    pub rng: Arc<dyn Rng>,
    pub snapshot: Arc<ArcSwap<ConfigSnapshot>>,
    pub providers: Arc<dyn ProviderLookup>,
    pub config: ServiceConfig,
}

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("store: {0}")]
    Store(#[from] StoreError),
    /// A uniform refusal; the reason is for events and metrics, never for the user.
    #[error("refused ({})", .0.0)]
    Refused(Reason),
    #[error("rate limited")]
    RateLimited { retry_after: Duration },
    /// The transaction already started a provider flow (its digest is immutable).
    #[error("transaction already started a provider flow")]
    AlreadyBound,
    #[error("no provider is enabled")]
    NoProviders,
    #[error("provider: {0}")]
    Provider(#[from] ProviderError),
    #[error("not implemented")]
    Unimplemented,
}

impl SessionError {
    /// The stable reason code.
    pub fn reason(&self) -> Reason {
        match self {
            SessionError::Store(_) => reasons::STORE_UNAVAILABLE,
            SessionError::Refused(r) => *r,
            SessionError::RateLimited { .. } => reasons::TXN_RATE_LIMITED,
            SessionError::AlreadyBound => reasons::TXN_CONSUMED,
            SessionError::NoProviders => reasons::PROVIDER_UNAVAILABLE,
            SessionError::Provider(e) => e.reason(),
            SessionError::Unimplemented => reasons::STORE_UNAVAILABLE,
        }
    }
}

/// A handle the portal sets on the browser.
#[derive(Debug)]
pub struct IssuedHandle {
    pub value: Secret,
    pub max_age: Duration,
}

#[derive(Debug)]
pub struct ProviderChoice {
    pub provider_id: ProviderId,
    pub display_name: String,
}

#[derive(Debug)]
pub enum LoginEntry {
    /// Single sign-on: go straight to the application with a code.
    Sso {
        location: Url,
        session_id: SessionId,
    },
    /// `portal.sso_confirm_new_host`: ask once before the first handoff to this host.
    ConfirmNewHost { host: Host },
    /// Show the providers (the portal redirects at once when there is exactly one).
    Chooser { providers: Vec<ProviderChoice> },
}

#[derive(Debug)]
pub enum CallbackOutcome {
    /// Session created (or reused): redirect to `location`.
    LoggedIn {
        location: Url,
        session_id: SessionId,
        user_id: UserId,
        /// `None` when the browser already held a valid portal handle for this user.
        portal_handle: Option<IssuedHandle>,
        created_user: bool,
        auto_linked: bool,
        /// `linking.on_conflict = separate`: show the notice.
        notice_separate: bool,
        reused_session: bool,
    },
    /// ADR-0011 `link_required`: no user, identity or session was created.
    LinkRequired { transaction: Secret },
    /// The portal binding cookie differs from the recorded one: the first-use
    /// race. The transaction is consumed; `retry_ref` names it for
    /// `POST /login/retry`.
    Interrupted {
        retry_ref: Digest,
        retry_allowed: bool,
        depth: u32,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub enum LogoutOutcome {
    SignedOut {
        session_id: SessionId,
    },
    /// No (valid) portal handle: nothing changed, nothing is reported.
    NoSession,
}

/// The session service. Cheap to clone.
#[derive(Clone)]
pub struct Service {
    pub(crate) directory: Arc<dyn Directory>,
    pub(crate) sessions: Arc<dyn Sessions>,
    pub(crate) events: Arc<dyn Events>,
    pub(crate) codes: Arc<dyn CodeDirectory>,
    pub(crate) clock: Arc<dyn Clock>,
    pub(crate) rng: Arc<dyn Rng>,
    pub(crate) snapshot: Arc<ArcSwap<ConfigSnapshot>>,
    pub(crate) providers: Arc<dyn ProviderLookup>,
    pub(crate) identity: IdentityService,
    pub(crate) cfg: ServiceConfig,
}

pub(crate) enum HandleState {
    Usable,
    /// Revoked, terminated session or disabled user.
    Dead,
    Expired,
    Mismatch(Reason),
}

impl Service {
    pub fn new(deps: Deps) -> Service {
        let identity = IdentityService::new(
            deps.directory.clone(),
            deps.clock.clone(),
            deps.rng.clone(),
            deps.config.linking,
        );
        Service {
            directory: deps.directory,
            sessions: deps.sessions,
            events: deps.events,
            codes: deps.codes,
            clock: deps.clock,
            rng: deps.rng,
            snapshot: deps.snapshot,
            providers: deps.providers,
            identity,
            cfg: deps.config,
        }
    }

    pub fn config(&self) -> &ServiceConfig {
        &self.cfg
    }

    // ---- shared helpers -------------------------------------------------

    pub(crate) fn ev(&self, ctx: &RequestCtx, kind: EventKind, outcome: Outcome) -> EventBuilder {
        EventBuilder::new(
            &*self.clock,
            &*self.rng,
            kind,
            outcome,
            ctx.request_id.clone(),
        )
        .ip(ctx.client_ip)
        .ua(ctx.user_agent.as_deref())
    }

    pub(crate) fn event_ctx(&self, ctx: &RequestCtx, app: Option<&TransactionRow>) -> EventCtx {
        EventCtx {
            request_id: ctx.request_id.clone(),
            client_ip: ctx.client_ip,
            user_agent: ctx.user_agent.clone(),
            app_id: app.map(|t| t.app_id.clone()),
            session_id: None,
        }
    }

    /// A required event with no state change to travel with. The store has no
    /// standalone append for required kinds (reported to the orchestrator), so
    /// it goes to the structured log only.
    pub(crate) fn log_unattached(&self, ev: &Event) {
        tracing::info!(
            event = ev.kind.name(),
            event_id = %ev.event_id,
            reason = ev.reason.map(|r| r.0),
            session = ev.session_id.as_ref().map(|s| s.as_str()),
            provider = ev.provider_id.as_ref().map(|s| s.as_str()),
            "event not persisted (no state change to carry it)"
        );
    }

    pub(crate) fn ua_digest(&self, ctx: &RequestCtx) -> Option<Digest> {
        ctx.user_agent.as_deref().map(|u| sha256(u.as_bytes()))
    }

    pub(crate) fn app_policy(
        &self,
        snap: &ConfigSnapshot,
        app_id: &crate::policy::types::AppId,
    ) -> AppPolicy {
        snap.apps
            .iter()
            .find(|a| &a.app_id == app_id)
            .unwrap_or(&snap.default_app)
            .clone()
    }

    /// The transaction's IP policy (ADR-0007: it inherits the application's
    /// `binding.ip`; a transaction started from IP A cannot be completed from
    /// IP B under `strict`).
    pub(crate) fn txn_ip_ok(&self, txn: &TransactionRow, ctx: &RequestCtx) -> bool {
        let snap = self.snapshot.load();
        let app = self.app_policy(&snap, &txn.app_id);
        ip_matches(app.binding.ip, txn.client_ip, ctx.client_ip)
    }

    /// Look a live (existing, unconsumed, unexpired) transaction up by its bearer id.
    pub(crate) async fn load_live_txn(
        &self,
        secret: &Secret,
    ) -> Result<TransactionRow, SessionError> {
        if !is_well_formed_bind(secret.expose()) {
            return Err(SessionError::Refused(reasons::TXN_EXPIRED));
        }
        let Some(txn) = self.sessions.transaction(&secret.digest()).await? else {
            return Err(SessionError::Refused(reasons::TXN_EXPIRED));
        };
        if txn.consumed_at.is_some() {
            return Err(SessionError::Refused(reasons::TXN_CONSUMED));
        }
        if txn.expires_at <= self.clock.now() {
            return Err(SessionError::Refused(reasons::TXN_EXPIRED));
        }
        Ok(txn)
    }

    /// Refuse without a state change to attach an event to.
    fn refuse(
        &self,
        ctx: &RequestCtx,
        txn: Option<&TransactionRow>,
        provider: Option<&ProviderId>,
        reason: Reason,
    ) -> SessionError {
        let mut b = self
            .ev(ctx, EventKind::LoginFailed, Outcome::Failure)
            .reason(reason);
        if let Some(t) = txn {
            b = b.app(&t.app_id);
        }
        // The provider id from the URL path is client input: name it only
        // when it is a configured provider.
        let known = provider.filter(|p| self.providers.get(p).is_some());
        if let Some(p) = known.or(txn.and_then(|t| t.provider_id.as_ref())) {
            b = b.provider(p);
        }
        self.log_unattached(&b.build());
        SessionError::Refused(reason)
    }

    /// Consume the transaction with a `login.failed` event in the same
    /// transaction, then refuse. A lost consume race reports `txn_consumed`.
    async fn refuse_consuming(
        &self,
        ctx: &RequestCtx,
        txn: &TransactionRow,
        reason: Reason,
    ) -> SessionError {
        let mut b = self
            .ev(ctx, EventKind::LoginFailed, Outcome::Failure)
            .app(&txn.app_id)
            .reason(reason);
        if let Some(p) = &txn.provider_id {
            b = b.provider(p);
        }
        let event = b.build();
        match self
            .sessions
            .consume_transaction(
                &txn.txn_sha256,
                reason,
                self.clock.now(),
                vec![event.clone()],
            )
            .await
        {
            Ok(true) => SessionError::Refused(reason),
            Ok(false) => {
                self.log_unattached(&event);
                SessionError::Refused(reasons::TXN_CONSUMED)
            }
            Err(e) => SessionError::Store(e),
        }
    }

    /// Evaluate a handle against lifetimes (ADR-0007 state machine) and the
    /// application's binding policy.
    pub(crate) fn evaluate_handle(
        &self,
        view: &HandleView,
        app: &AppPolicy,
        ctx: &RequestCtx,
    ) -> HandleState {
        let now = self.clock.now();
        if view.handle.revoked_at.is_some()
            || view.session.terminated_at.is_some()
            || view.user.status != UserStatus::Active
        {
            return HandleState::Dead;
        }
        if now >= view.session.absolute_expires_at {
            return HandleState::Expired;
        }
        if now.since(view.session.last_seen_at) >= self.cfg.session.idle {
            return HandleState::Expired;
        }
        if now >= view.handle.absolute_expires_at {
            return HandleState::Expired;
        }
        if now.since(view.handle.last_seen_at) >= app.session.idle {
            return HandleState::Expired;
        }
        if !ip_matches(app.binding.ip, view.session.bound_ip, ctx.client_ip) {
            return HandleState::Mismatch(reasons::BINDING_IP);
        }
        if app.binding.ua == UaBinding::Strict
            && self.ua_digest(ctx).map(|d| d.0) != view.session.bound_ua_sha256.map(|d| d.0)
        {
            return HandleState::Mismatch(reasons::BINDING_UA);
        }
        HandleState::Usable
    }

    /// The portal handle's session when the handle passes the `default`
    /// application's lifetimes and binding policy; a binding mismatch applies
    /// the policy's consequence and yields `None`.
    pub(crate) async fn portal_session(
        &self,
        ctx: &RequestCtx,
        handle: Option<&Secret>,
    ) -> Result<Option<HandleView>, SessionError> {
        let Some(h) = handle.filter(|h| is_well_formed_handle(h.expose())) else {
            return Ok(None);
        };
        let Some(view) = self
            .sessions
            .lookup_handle(&h.digest(), &self.cfg.portal_host)
            .await?
        else {
            return Ok(None);
        };
        let snap = self.snapshot.load_full();
        match self.evaluate_handle(&view, &snap.default_app, ctx) {
            HandleState::Usable => Ok(Some(view)),
            HandleState::Dead | HandleState::Expired => Ok(None),
            HandleState::Mismatch(reason) => {
                self.apply_mismatch(ctx, &view, &snap.default_app, reason)
                    .await?;
                Ok(None)
            }
        }
    }

    async fn apply_mismatch(
        &self,
        ctx: &RequestCtx,
        view: &HandleView,
        app: &AppPolicy,
        reason: Reason,
    ) -> Result<(), SessionError> {
        let now = self.clock.now();
        let recorded = sha256(view.session.bound_ip.to_string().as_bytes()).to_hex();
        let observed = sha256(ctx.client_ip.to_string().as_bytes()).to_hex();
        let build = |kind| {
            self.ev(ctx, kind, Outcome::Info)
                .user(&view.session.user_id)
                .session(&view.session.session_id)
                .app(&app.app_id)
                .reason(reason)
                .attr("recorded_sha256", recorded.clone())
                .attr("observed_sha256", observed.clone())
                .build()
        };
        match app.binding.on_mismatch {
            OnMismatch::TerminateSession => {
                self.sessions
                    .terminate_session(
                        &view.session.session_id,
                        reason,
                        now,
                        vec![build(EventKind::SessionTerminated)],
                    )
                    .await?;
            }
            OnMismatch::DropHandle => {
                self.sessions
                    .revoke_handle(
                        &view.handle.handle_sha256,
                        reason,
                        now,
                        vec![build(EventKind::HandleRevoked)],
                    )
                    .await?;
            }
        }
        Ok(())
    }

    // ---- provider round trip -------------------------------------------

    /// `POST /login/<provider>` (and the single-provider auto-redirect): ask
    /// the provider for its authorization request and record `state`, `nonce`,
    /// the PKCE verifier and the portal binding digest in the transaction. The
    /// digest is immutable once recorded: a second call fails with
    /// [`SessionError::AlreadyBound`] and changes nothing.
    pub async fn begin_provider(
        &self,
        ctx: &RequestCtx,
        txn: &Secret,
        provider_id: &ProviderId,
        portal_cookie: Option<&Secret>,
    ) -> Result<Url, SessionError> {
        let portal_cookie = portal_cookie
            .filter(|c| is_well_formed_bind(c.expose()))
            .ok_or(SessionError::Refused(reasons::PORTAL_BIND_MISMATCH))?;
        let row = self.load_live_txn(txn).await?;
        self.begin_provider_for(ctx, &row, provider_id, portal_cookie)
            .await
    }

    pub(crate) async fn begin_provider_for(
        &self,
        ctx: &RequestCtx,
        row: &TransactionRow,
        provider_id: &ProviderId,
        portal_cookie: &Secret,
    ) -> Result<Url, SessionError> {
        if row.purpose != TxnPurpose::Login {
            return Err(SessionError::Refused(reasons::INVALID_STATE));
        }
        if !self.txn_ip_ok(row, ctx) {
            return Err(SessionError::Refused(reasons::TXN_BINDING));
        }
        if row.state_sha256.is_some() {
            return Err(SessionError::AlreadyBound);
        }
        let provider = self
            .providers
            .get(provider_id)
            .ok_or(SessionError::Refused(reasons::PROVIDER_UNAVAILABLE))?;
        if !provider.enabled() {
            return Err(SessionError::Refused(reasons::PROVIDER_DISABLED));
        }
        let redirect_uri = self.redirect_uri(provider_id)?;
        let auth = provider.begin(row, &redirect_uri, &*self.rng).await?;
        // PKCE and nonce are not negotiable for OIDC (S002-A7): a provider
        // that cannot supply them is refused rather than weakened.
        if provider.kind() == ProviderKind::Oidc
            && (auth.nonce.as_deref().is_none_or(str::is_empty) || auth.pkce_verifier.is_none())
        {
            return Err(SessionError::Provider(ProviderError::InvalidNonce));
        }
        let binding = TransactionBinding {
            provider_id: provider_id.clone(),
            state_sha256: auth.state.digest(),
            nonce: auth.nonce.unwrap_or_default(),
            pkce_verifier: auth
                .pkce_verifier
                .unwrap_or_else(|| Secret::new(String::new())),
            portal_bind_sha256: portal_cookie.digest(),
        };
        match self
            .sessions
            .bind_transaction(&row.txn_sha256, binding)
            .await
        {
            Ok(()) => Ok(auth.url),
            Err(StoreError::Conflict(_)) => Err(SessionError::AlreadyBound),
            Err(e) => Err(e.into()),
        }
    }

    pub(crate) fn redirect_uri(&self, provider_id: &ProviderId) -> Result<Url, SessionError> {
        let mut u = self.cfg.portal_url.clone();
        u.set_path(&format!("/callback/{provider_id}"));
        u.set_query(None);
        Ok(u)
    }

    /// `GET /login?txn=`: single sign-on when the browser holds a valid portal
    /// handle (ADR-0004), otherwise the provider chooser. `confirmed` is set
    /// by `POST /login/continue` after the optional new-host confirmation.
    pub async fn sso_or_chooser(
        &self,
        ctx: &RequestCtx,
        txn: &Secret,
        portal_handle: Option<&Secret>,
        confirmed: bool,
    ) -> Result<LoginEntry, SessionError> {
        let row = self.load_live_txn(txn).await?;
        if row.purpose != TxnPurpose::Login {
            return Err(SessionError::Refused(reasons::INVALID_STATE));
        }
        if !self.txn_ip_ok(&row, ctx) {
            return Err(SessionError::Refused(reasons::TXN_BINDING));
        }
        if row.state_sha256.is_some() {
            // A provider flow already started on this transaction; a visit
            // (a lure, a back button) never changes it.
            return Err(SessionError::AlreadyBound);
        }
        if let Some(view) = self.portal_session(ctx, portal_handle).await? {
            let host = host_of(&row.return_target)?;
            if self.cfg.sso_confirm_new_host
                && !confirmed
                && !self
                    .handed_off_before(&view.session.session_id, &host)
                    .await?
            {
                return Ok(LoginEntry::ConfirmNewHost { host });
            }
            return self.sso(ctx, &row, &view, &host).await;
        }
        let providers: Vec<ProviderChoice> = self
            .providers
            .enabled_sorted()
            .into_iter()
            .map(|p| ProviderChoice {
                provider_id: p.id().clone(),
                display_name: p.display_name().to_string(),
            })
            .collect();
        if providers.is_empty() {
            return Err(SessionError::NoProviders);
        }
        Ok(LoginEntry::Chooser { providers })
    }

    async fn sso(
        &self,
        ctx: &RequestCtx,
        row: &TransactionRow,
        view: &HandleView,
        host: &Host,
    ) -> Result<LoginEntry, SessionError> {
        let bind = row
            .bind_sha256
            .ok_or(SessionError::Refused(reasons::TXN_BINDING))?;
        let now = self.clock.now();
        // The conditional consume is the arbiter: only the winner mints.
        if !self
            .sessions
            .consume_transaction(&row.txn_sha256, CONSUMED_SSO, now, vec![])
            .await?
        {
            return Err(SessionError::Refused(reasons::TXN_CONSUMED));
        }
        let event = self
            .ev(ctx, EventKind::SessionHandoff, Outcome::Success)
            .user(&view.session.user_id)
            .session(&view.session.session_id)
            .app(&row.app_id)
            .attr("host", host.as_str())
            .attr("sso", true)
            .build();
        let minted = self
            .mint_handoff(MintRequest {
                session_id: view.session.session_id.clone(),
                aal_cap: view.handle.issued_aal,
                target: row.return_target.clone(),
                client_ip: row.client_ip,
                bind_sha256: bind,
                recovery_depth: row.recovery_depth,
                events: vec![event],
            })
            .await?;
        Ok(LoginEntry::Sso {
            location: minted.location,
            session_id: view.session.session_id.clone(),
        })
    }

    /// Whether this session was ever handed off to `host` (a `session.handoff`
    /// event with that host exists).
    async fn handed_off_before(
        &self,
        session: &SessionId,
        host: &Host,
    ) -> Result<bool, SessionError> {
        let events = self
            .events
            .query(crate::store::types::EventQuery {
                kind: Some(EventKind::SessionHandoff),
                session_id: Some(session.clone()),
                limit: Some(10_000),
                ..Default::default()
            })
            .await?;
        Ok(events
            .iter()
            .any(|e| e.attrs.get("host").and_then(|h| h.as_str()) == Some(host.as_str())))
    }

    // ---- callback -------------------------------------------------------

    /// `GET /callback/<provider>`: validate the assertion and create the
    /// session (ADR-0004, ADR-0011). Every refusal is uniform to the user; the
    /// reason is in the error and in the events.
    pub async fn complete_callback(
        &self,
        ctx: &RequestCtx,
        provider_id: &ProviderId,
        query: CallbackQuery,
        portal_cookie: Option<&Secret>,
        portal_handle: Option<&Secret>,
    ) -> Result<CallbackOutcome, SessionError> {
        let now = self.clock.now();
        let Some(state) = query
            .state
            .as_deref()
            .filter(|s| !s.is_empty() && s.len() <= 512)
        else {
            return Err(self.refuse(ctx, None, Some(provider_id), reasons::INVALID_STATE));
        };
        let Some(txn) = self
            .sessions
            .transaction_by_state(&sha256(state.as_bytes()))
            .await?
        else {
            return Err(self.refuse(ctx, None, Some(provider_id), reasons::INVALID_STATE));
        };
        if txn.consumed_at.is_some() {
            return Err(self.refuse(ctx, Some(&txn), Some(provider_id), reasons::TXN_CONSUMED));
        }
        if txn.expires_at <= now {
            return Err(self.refuse(ctx, Some(&txn), Some(provider_id), reasons::TXN_EXPIRED));
        }
        if txn.purpose != TxnPurpose::Login {
            return Err(self.refuse(ctx, Some(&txn), Some(provider_id), reasons::INVALID_STATE));
        }
        let (Some(expected_bind), Some(app_bind)) = (txn.portal_bind_sha256, txn.bind_sha256)
        else {
            return Err(self.refuse(ctx, Some(&txn), Some(provider_id), reasons::INVALID_STATE));
        };
        if txn.provider_id.as_ref() != Some(provider_id) {
            return Err(self.refuse_consuming(ctx, &txn, PROVIDER_MISMATCH).await);
        }

        // The portal binding cookie must match the digest recorded when the
        // provider redirect was issued (constant-time compare).
        let Some(presented) = portal_cookie.filter(|c| is_well_formed_bind(c.expose())) else {
            return Err(self
                .refuse_consuming(ctx, &txn, reasons::PORTAL_BIND_MISMATCH)
                .await);
        };
        let presented_digest = presented.digest();
        if !ct_eq(&presented_digest.0, &expected_bind.0) {
            return self.interrupted(ctx, &txn, presented_digest).await;
        }
        if !self.txn_ip_ok(&txn, ctx) {
            return Err(self.refuse_consuming(ctx, &txn, reasons::TXN_BINDING).await);
        }

        let provider = self.providers.get(provider_id).ok_or_else(|| {
            self.refuse(
                ctx,
                Some(&txn),
                Some(provider_id),
                reasons::PROVIDER_UNAVAILABLE,
            )
        })?;
        if !provider.enabled() {
            return Err(self.refuse(
                ctx,
                Some(&txn),
                Some(provider_id),
                reasons::PROVIDER_DISABLED,
            ));
        }
        let redirect_uri = self.redirect_uri(provider_id)?;
        let ident = match provider.complete(&txn, &query, &redirect_uri, now).await {
            Ok(i) => i,
            Err(e) => {
                self.provider_failed(ctx, &txn, provider_id, &e).await;
                if transient(&e) {
                    // The user may retry until the transaction expires.
                    return Err(self.refuse(ctx, Some(&txn), Some(provider_id), e.reason()));
                }
                let _ = self.refuse_consuming(ctx, &txn, e.reason()).await;
                return Err(SessionError::Provider(e));
            }
        };

        let row = self
            .directory
            .providers()
            .await?
            .into_iter()
            .find(|r| &r.provider_id == provider_id && r.deleted_at.is_none())
            .ok_or(SessionError::Refused(reasons::PROVIDER_UNAVAILABLE))?;
        let resolution = self.identity.resolve(&ident, &row).await?;
        let ectx = self.event_ctx(ctx, Some(&txn));

        match resolution {
            Resolution::Denied(reason) => {
                let mut events = vec![
                    self.ev(ctx, EventKind::LoginFailed, Outcome::Failure)
                        .app(&txn.app_id)
                        .provider(provider_id)
                        .reason(reason)
                        .build(),
                ];
                if reason == reasons::EMAIL_IN_USE {
                    events.push(self.identity.conflict_event(provider_id, reason, &ectx));
                }
                if self
                    .sessions
                    .consume_transaction(&txn.txn_sha256, reason, now, events)
                    .await?
                {
                    return Err(SessionError::Refused(reason));
                }
                return Err(SessionError::Refused(reasons::TXN_CONSUMED));
            }
            Resolution::LinkRequired { pending } => {
                return self
                    .link_required(ctx, &txn, provider_id, pending, &ectx)
                    .await;
            }
            _ => {}
        }

        // The conditional consume is the arbiter between racing callbacks.
        if !self
            .sessions
            .consume_transaction(&txn.txn_sha256, CONSUMED_COMPLETED, now, vec![])
            .await?
        {
            self.log_unattached(
                &self
                    .ev(ctx, EventKind::LoginFailed, Outcome::Failure)
                    .app(&txn.app_id)
                    .provider(provider_id)
                    .reason(reasons::TXN_CONSUMED)
                    .build(),
            );
            return Err(SessionError::Refused(reasons::TXN_CONSUMED));
        }
        let resolved = match self.identity.apply(resolution, &row, &ident, &ectx).await {
            Ok(Some(r)) => r,
            Ok(None) => return Err(SessionError::Refused(reasons::INVALID_STATE)),
            Err(StoreError::Conflict(_)) => {
                return Err(SessionError::Refused(reasons::EMAIL_IN_USE));
            }
            Err(e) => return Err(e.into()),
        };
        let user = resolved.user;

        // A callback that completes while the browser already holds a valid
        // portal handle for the same user reuses that session.
        if let Some(view) = self.portal_session(ctx, portal_handle).await?
            && view.session.user_id == user.user_id
        {
            let event = self
                .ev(ctx, EventKind::LoginSucceeded, Outcome::Success)
                .user(&user.user_id)
                .session(&view.session.session_id)
                .provider(provider_id)
                .app(&txn.app_id)
                .build();
            let minted = self
                .mint_handoff(MintRequest {
                    session_id: view.session.session_id.clone(),
                    aal_cap: view.handle.issued_aal,
                    target: txn.return_target.clone(),
                    client_ip: txn.client_ip,
                    bind_sha256: app_bind,
                    recovery_depth: txn.recovery_depth,
                    events: vec![event],
                })
                .await?;
            return Ok(CallbackOutcome::LoggedIn {
                location: minted.location,
                session_id: view.session.session_id,
                user_id: user.user_id,
                portal_handle: None,
                created_user: resolved.created,
                auto_linked: resolved.auto_linked,
                notice_separate: resolved.notice_separate,
                reused_session: true,
            });
        }

        let (session, issued) = self
            .create_session(ctx, &txn, provider.kind(), provider_id, &user)
            .await?;
        let minted = self
            .mint_handoff(MintRequest {
                session_id: session.session_id.clone(),
                aal_cap: Aal::One,
                target: txn.return_target.clone(),
                client_ip: txn.client_ip,
                bind_sha256: app_bind,
                recovery_depth: txn.recovery_depth,
                events: vec![],
            })
            .await?;
        Ok(CallbackOutcome::LoggedIn {
            location: minted.location,
            session_id: session.session_id,
            user_id: user.user_id,
            portal_handle: Some(issued),
            created_user: resolved.created,
            auto_linked: resolved.auto_linked,
            notice_separate: resolved.notice_separate,
            reused_session: false,
        })
    }

    /// The first-use race at the portal: consume the transaction with
    /// `portal_bind_mismatch`, remember the presented cookie's digest for
    /// `POST /login/retry`, and let the portal render the interrupted page.
    async fn interrupted(
        &self,
        ctx: &RequestCtx,
        txn: &TransactionRow,
        presented: Digest,
    ) -> Result<CallbackOutcome, SessionError> {
        let reason = reasons::PORTAL_BIND_MISMATCH;
        let event = self
            .ev(ctx, EventKind::LoginFailed, Outcome::Failure)
            .app(&txn.app_id)
            .reason(reason)
            .attr("recovery_depth", txn.recovery_depth)
            .build();
        let mut b = event;
        if let Some(p) = &txn.provider_id {
            b.provider_id = Some(p.clone());
        }
        let won = self
            .sessions
            .consume_transaction(&txn.txn_sha256, reason, self.clock.now(), vec![b])
            .await?;
        if !won {
            return Err(SessionError::Refused(reasons::TXN_CONSUMED));
        }
        match self
            .sessions
            .record_retry_bind(&txn.txn_sha256, presented)
            .await
        {
            Ok(()) | Err(StoreError::Conflict(_)) => {}
            Err(e) => return Err(e.into()),
        }
        Ok(CallbackOutcome::Interrupted {
            retry_ref: txn.txn_sha256,
            retry_allowed: txn.recovery_depth < self.cfg.max_recoveries,
            depth: txn.recovery_depth,
        })
    }

    async fn provider_failed(
        &self,
        ctx: &RequestCtx,
        txn: &TransactionRow,
        provider_id: &ProviderId,
        e: &ProviderError,
    ) {
        let ev = self
            .ev(ctx, EventKind::ProviderError, Outcome::Failure)
            .app(&txn.app_id)
            .provider(provider_id)
            .reason(e.reason())
            .build();
        // Best effort: a full diagnostic queue drops the event.
        let _ = self.events.append_diagnostic(ev).await;
    }

    async fn link_required(
        &self,
        ctx: &RequestCtx,
        txn: &TransactionRow,
        provider_id: &ProviderId,
        pending: PendingIdentity,
        ectx: &EventCtx,
    ) -> Result<CallbackOutcome, SessionError> {
        let now = self.clock.now();
        let conflict = self
            .identity
            .conflict_event(provider_id, reasons::LINK_REQUIRED, ectx);
        if !self
            .sessions
            .consume_transaction(&txn.txn_sha256, reasons::LINK_REQUIRED, now, vec![conflict])
            .await?
        {
            return Err(SessionError::Refused(reasons::TXN_CONSUMED));
        }
        let link = random_token(&*self.rng, 16);
        let pending_json = serde_json::to_value(&pending)
            .map_err(|_| SessionError::Refused(reasons::INVALID_STATE))?;
        // The store has no way to change a transaction's purpose in place, so
        // the pending identity travels in a fresh `link` transaction with a
        // fresh 10-minute expiry (ADR-0011).
        self.sessions
            .create_transaction(
                NewTransaction {
                    txn_sha256: link.digest(),
                    created_at: now,
                    expires_at: now.add(TXN_LIFETIME),
                    app_id: txn.app_id.clone(),
                    return_target: txn.return_target.clone(),
                    bind_sha256: txn.bind_sha256,
                    portal_bind_sha256: txn.portal_bind_sha256,
                    retry_bind_sha256: None,
                    client_ip: txn.client_ip,
                    ua_sha256: txn.ua_sha256,
                    provider_id: Some(provider_id.clone()),
                    state_sha256: None,
                    nonce: None,
                    pkce_verifier: None,
                    portal_session_id: None,
                    purpose: TxnPurpose::Link,
                    conflicting_handle_sha256: None,
                    pending_identity: Some(pending_json),
                    recovery_depth: txn.recovery_depth,
                },
                vec![],
            )
            .await?;
        let _ = ctx;
        Ok(CallbackOutcome::LinkRequired { transaction: link })
    }

    /// New session with its portal handle and the events, in one store transaction.
    async fn create_session(
        &self,
        ctx: &RequestCtx,
        txn: &TransactionRow,
        kind: ProviderKind,
        provider_id: &ProviderId,
        user: &User,
    ) -> Result<(SessionRow, IssuedHandle), SessionError> {
        let now = self.clock.now();
        let snap = self.snapshot.load_full();
        let session_id = SessionId::new(random_id(&*self.rng, "s_"));
        let handle = handle_value(&*self.rng);
        let digest = handle.digest();
        let session_abs = now.add(self.cfg.session.absolute);
        let handle_abs = now.add(snap.default_app.session.absolute).min(session_abs);
        let session = SessionRow {
            session_id: session_id.clone(),
            user_id: user.user_id.clone(),
            provider_id: provider_id.clone(),
            auth_time: now,
            factors: vec![FactorEntry {
                kind: factor_kind(kind),
                provider: Some(provider_id.clone()),
                at: now,
            }],
            aal: Aal::One,
            authz_version: user.authz_version,
            cred_gen: 1,
            snapshot: IdentitySnapshot {
                email: user.primary_email.clone(),
                display_name: user.display_name.clone(),
                username: user.username.clone(),
                groups: user.groups.clone(),
            },
            bound_ip: ctx.client_ip,
            bound_ua_sha256: self.ua_digest(ctx),
            created_at: now,
            last_seen_at: now,
            absolute_expires_at: session_abs,
            terminated_at: None,
            terminated_reason: None,
        };
        let portal_handle = HandleRow {
            handle_sha256: digest,
            session_id: session_id.clone(),
            host: self.cfg.portal_host.clone(),
            issued_aal: Aal::One,
            created_at: now,
            last_seen_at: now,
            absolute_expires_at: handle_abs,
            revoked_at: None,
            revoked_reason: None,
        };
        let base = |kind| {
            self.ev(ctx, kind, Outcome::Success)
                .user(&user.user_id)
                .session(&session_id)
                .provider(provider_id)
                .app(&txn.app_id)
        };
        let events = vec![
            base(EventKind::LoginSucceeded).build(),
            base(EventKind::SessionCreated).attr("aal", 1).build(),
        ];
        self.sessions
            .create_session(CreateSession {
                session: session.clone(),
                portal_handle,
                portal_handle_digest: digest,
                events,
            })
            .await?;
        Ok((
            session,
            IssuedHandle {
                value: handle,
                max_age: handle_abs.since(now),
            },
        ))
    }

    // ---- logout ---------------------------------------------------------

    /// `POST /logout` (scope this): terminate the session the portal handle
    /// names. Idempotent and uniform: without a live handle nothing changes
    /// and nothing is recorded. The CSRF and `Origin` checks are the portal's.
    pub async fn logout(
        &self,
        ctx: &RequestCtx,
        portal_handle: Option<&Secret>,
    ) -> Result<LogoutOutcome, SessionError> {
        let Some(h) = portal_handle.filter(|h| is_well_formed_handle(h.expose())) else {
            return Ok(LogoutOutcome::NoSession);
        };
        let Some(view) = self
            .sessions
            .lookup_handle(&h.digest(), &self.cfg.portal_host)
            .await?
        else {
            return Ok(LogoutOutcome::NoSession);
        };
        if view.handle.revoked_at.is_some() || view.session.terminated_at.is_some() {
            return Ok(LogoutOutcome::NoSession);
        }
        let event = self
            .ev(ctx, EventKind::SessionTerminated, Outcome::Info)
            .user(&view.session.user_id)
            .session(&view.session.session_id)
            .provider(&view.session.provider_id)
            .reason(reasons::LOGOUT)
            .build();
        self.sessions
            .terminate_session(
                &view.session.session_id,
                reasons::LOGOUT,
                self.clock.now(),
                vec![event],
            )
            .await?;
        Ok(LogoutOutcome::SignedOut {
            session_id: view.session.session_id,
        })
    }
}

fn factor_kind(kind: ProviderKind) -> FactorKind {
    match kind {
        ProviderKind::Oidc => FactorKind::Oidc,
        ProviderKind::Oauth2 => FactorKind::Oauth2,
        ProviderKind::EmailLink => FactorKind::EmailLink,
        ProviderKind::Password => FactorKind::Password,
    }
}

/// Provider failures that leave the transaction usable (the user may retry
/// until it expires): the provider was slow, unavailable or too large, not
/// wrong about who the user is.
fn transient(e: &ProviderError) -> bool {
    matches!(
        e,
        ProviderError::ProviderTimeout
            | ProviderError::ProviderResponseTooLarge
            | ProviderError::ProviderUnavailable
            | ProviderError::ProviderError { .. }
    )
}

pub(crate) fn host_of(url: &Url) -> Result<Host, SessionError> {
    url.host_str()
        .and_then(|h| Host::parse(h).ok())
        .ok_or(SessionError::Refused(reasons::NOT_ABSOLUTE))
}

/// `binding.ip` comparison of the recorded address with the observed one.
pub(crate) fn ip_matches(mode: IpBinding, recorded: IpAddr, observed: IpAddr) -> bool {
    match mode {
        IpBinding::Off => true,
        IpBinding::Strict => recorded == observed,
        IpBinding::Prefix { v4, v6 } => {
            let bits = match recorded {
                IpAddr::V4(_) => v4,
                IpAddr::V6(_) => v6,
            };
            match ipnet::IpNet::new(recorded, bits) {
                Ok(net) => {
                    matches!(
                        (&recorded, &observed),
                        (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_))
                    ) && net.contains(&observed)
                }
                Err(_) => false,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn ip_binding_modes() {
        let a = ip("203.0.113.9");
        assert!(ip_matches(IpBinding::Off, a, ip("198.51.100.1")));
        assert!(ip_matches(IpBinding::Strict, a, a));
        assert!(!ip_matches(IpBinding::Strict, a, ip("203.0.113.10")));
        let p = IpBinding::Prefix { v4: 24, v6: 64 };
        assert!(ip_matches(p, a, ip("203.0.113.200")));
        assert!(!ip_matches(p, a, ip("203.0.114.9")));
        assert!(ip_matches(
            p,
            ip("2001:db8:1:2::1"),
            ip("2001:db8:1:2:ffff::9")
        ));
        assert!(!ip_matches(p, ip("2001:db8:1:2::1"), ip("2001:db8:1:3::1")));
        // a family change never matches a prefix
        assert!(!ip_matches(p, a, ip("::ffff:203.0.113.9")));
    }

    #[test]
    fn transient_provider_errors_keep_the_transaction() {
        assert!(transient(&ProviderError::ProviderTimeout));
        assert!(transient(&ProviderError::ProviderResponseTooLarge));
        assert!(!transient(&ProviderError::InvalidNonce));
        assert!(!transient(&ProviderError::UserinfoSubjectMismatch));
    }
}
