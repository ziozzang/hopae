//! The decision flow. See [`super::decide`] for the order.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use tokio::time::Instant;

use super::handoff;
use super::lifetimes::{self, LifetimeVerdict};
use super::types::*;
use crate::crypto::{
    Digest, Secret, Timestamp, is_well_formed_bind, is_well_formed_handle, random_token, sha256,
};
use crate::event::types::{EventBuilder, EventKind, Outcome, Reason, reasons};
use crate::policy::apps;
use crate::policy::binding::{self, BindingVerdict};
use crate::policy::freshness;
use crate::policy::step_up;
use crate::policy::types::{AppPolicy, AuthzChange, ConfigSnapshot, OnMismatch};
use crate::session::types::Generations;
use crate::session::types::SessionId;
use crate::store::types::{
    Admission, HandleView, IdentitySnapshot, NewTransaction, TxnPurpose, UserStatus,
};
use crate::store::{StoreError, sqlite::with_deadline};

const RATE_WINDOW: Duration = Duration::from_secs(60);
const UNAVAILABLE_RETRY: Duration = Duration::from_secs(1);
/// Most handles remembered for `last_seen_at` coalescing before old entries are dropped.
const TOUCH_MEMORY: usize = 8192;

/// `Err` carries a final decision that ends the flow early.
pub(super) type Flow = Result<Decision, Decision>;

/// Everything one request's flow needs.
pub(super) struct Cx<'a> {
    pub ctx: &'a VerifyContext,
    pub input: &'a VerifyInput,
    pub snapshot: Arc<ConfigSnapshot>,
    pub now: Timestamp,
    pub deadline: Instant,
    /// Why a presented handle was refused, once known; whatever the request
    /// ends up being answered (a login `302`, or a rate-limit denial), this
    /// is the primary reason it is recorded under (`verify.denied`).
    pub cause: std::sync::Mutex<Option<Reason>>,
}

impl Cx<'_> {
    pub fn document(&self) -> bool {
        matches!(self.input.navigation, Navigation::Document)
    }

    pub fn deny(&self, reason: Reason, kind: DenyKind) -> Decision {
        Decision::Deny { reason, kind }
    }

    /// Fail closed: a store error never lets a request through.
    pub fn store_err(&self, _e: StoreError) -> Decision {
        let reason = if Instant::now() >= self.deadline {
            reasons::BUDGET_EXCEEDED
        } else {
            reasons::STORE_UNAVAILABLE
        };
        self.deny(
            reason,
            DenyKind::Unavailable {
                retry_after: UNAVAILABLE_RETRY,
            },
        )
    }

    /// A required event for this request, ready for `.reason(..)`/`.attr(..)`.
    pub fn event(&self, kind: EventKind, outcome: Outcome, app: &AppPolicy) -> EventBuilder {
        let b = match &self.ctx.emitter {
            Some(e) => e.counted(kind, outcome, self.input.request_id.clone()),
            None => EventBuilder::new(
                &*self.ctx.clock,
                &*self.ctx.rng,
                kind,
                outcome,
                self.input.request_id.clone(),
            ),
        };
        b.app(&app.app_id)
            .ip(self.input.client_ip)
            .ua(self.input.user_agent.as_deref())
    }

    fn view_event(
        &self,
        kind: EventKind,
        app: &AppPolicy,
        view: &HandleView,
        reason: Reason,
    ) -> EventBuilder {
        self.event(kind, Outcome::Info, app)
            .session(&view.session.session_id)
            .user(&view.session.user_id)
            .provider(&view.session.provider_id)
            .reason(reason)
    }

    /// The browser's binding cookie digest and what to do with the cookie:
    /// keep a well-formed one, otherwise plant a fresh one.
    pub fn bind_for_transaction(&self) -> (Digest, BindAction) {
        match self
            .input
            .bind_cookie
            .as_ref()
            .filter(|b| is_well_formed_bind(b.expose()))
        {
            Some(b) => (b.digest(), BindAction::Keep),
            None => {
                let fresh = random_token(&*self.ctx.rng, 16);
                (fresh.digest(), BindAction::Plant(fresh))
            }
        }
    }

    /// The handle the browser presented, when it is still a live handle of
    /// this host: not revoked, session running, timers and binding intact.
    /// Read-only; used to classify handoff outcomes.
    pub async fn live_presented_handle(
        &self,
        app: &AppPolicy,
    ) -> Result<Option<HandleView>, Decision> {
        let Some(cookie) = self
            .input
            .cookie_handle
            .as_ref()
            .filter(|c| is_well_formed_handle(c.expose()))
        else {
            return Ok(None);
        };
        let view = self
            .ctx
            .sessions
            .lookup_handle(&cookie.digest(), &self.input.host)
            .await
            .map_err(|e| self.store_err(e))?;
        Ok(view.filter(|v| {
            v.handle.revoked_at.is_none()
                && v.session.terminated_at.is_none()
                && matches!(
                    lifetimes::evaluate(
                        &v.handle,
                        &v.session,
                        &app.session,
                        &self.ctx.limits.session,
                        self.now
                    ),
                    LifetimeVerdict::Live { .. }
                )
                && self.binding_verdict(app, v) == BindingVerdict::Ok
        }))
    }

    fn binding_verdict(&self, app: &AppPolicy, v: &HandleView) -> BindingVerdict {
        binding::check(
            &app.binding,
            v.session.bound_ip,
            v.session.bound_ua_sha256.as_ref(),
            self.input.client_ip,
            self.input.user_agent.as_deref(),
        )
    }
}

pub(super) async fn run(ctx: &VerifyContext, input: VerifyInput) -> (Decision, Option<Reason>) {
    let deadline = ctx
        .deadline
        .unwrap_or_else(|| Instant::now() + ctx.limits.budget);
    let cx = Cx {
        ctx,
        input: &input,
        snapshot: ctx.snapshot.load_full(),
        now: ctx.clock.now(),
        deadline,
        cause: std::sync::Mutex::new(None),
    };
    let work = with_deadline(deadline, async {
        match flow(&cx).await {
            Ok(d) | Err(d) => d,
        }
    });
    let decision = match tokio::time::timeout_at(deadline, work).await {
        Ok(d) => d,
        Err(_) => cx.deny(
            reasons::BUDGET_EXCEEDED,
            DenyKind::Unavailable {
                retry_after: UNAVAILABLE_RETRY,
            },
        ),
    };
    let cause = *cx.cause.lock().unwrap_or_else(|p| p.into_inner());
    (decision, cause)
}

async fn flow(cx: &Cx<'_>) -> Flow {
    let (ctx, input) = (cx.ctx, cx.input);

    // Contract checks the core can make on its own input.
    if input.contract > 1 {
        return Err(cx.deny(reasons::CONTRACT_UNSUPPORTED, DenyKind::ContractViolation));
    }
    if input.proto == Scheme::Http && ctx.limits.secure {
        return Err(cx.deny(reasons::INSECURE_TRANSPORT, DenyKind::ContractViolation));
    }

    // The return target: the only URL a user is ever sent back to. An entry
    // point's own URL may carry a whole target in `return` (longer than the
    // limit); its host, port and application are checked on the origin's root,
    // and the `return` itself is validated by the entry point.
    let validated = if matches!(input.canonical_path.reserved(), Reserved::Entry(_)) {
        let mut root = input.original_url.clone();
        root.set_path("/");
        root.set_query(None);
        root
    } else {
        input.original_url.clone()
    };
    let target = apps::validate_return_target(validated.as_str(), &cx.snapshot, ctx.limits.secure)
        .map_err(|r| {
            let kind = if r == reasons::UNKNOWN_APP
                || r == reasons::APP_DISABLED
                || r == reasons::PORT_NOT_ALLOWED
            {
                DenyKind::Forbidden
            } else {
                DenyKind::ContractViolation
            };
            cx.deny(r, kind)
        })?;
    if target.host_str() != Some(input.host.as_str()) {
        return Err(cx.deny(reasons::CONTRACT_VIOLATION, DenyKind::ContractViolation));
    }
    let app =
        apps::resolve(&cx.snapshot, &input.host).map_err(|r| cx.deny(r, DenyKind::Forbidden))?;

    // The reserved namespace (ADR-0015): after the application checks, before
    // the reserved handoff parameter, which is neither redeemed nor consulted here.
    match input.canonical_path.reserved() {
        Reserved::No => {}
        Reserved::Other => return Err(cx.deny(reasons::RESERVED_PATH, DenyKind::Forbidden)),
        Reserved::Entry(entry) => return entry_point(cx, app, entry).await,
    }

    // Reserved handoff parameter.
    match (&input.handoff, cx.document()) {
        (Handoff::None, _) => {}
        (Handoff::Code(code), true) => return handoff::redeem(cx, app, &target, code).await,
        (Handoff::Ambiguous, true) => return Err(ambiguous_handoff(cx, app).await),
        (_, false) => {
            return Err(cx.deny(reasons::HANDOFF_PARAMETER_NOT_ALLOWED, DenyKind::Forbidden));
        }
    }

    match authenticate(cx, app).await? {
        Authn::Refused(cause) => login(cx, app, &target, cause, 0).await,
        Authn::Allowed(authed) => {
            // The console's freshness rule, after the step-up rules (ADR-0016
            // decision 15): one predicate at every verify.
            if let Some(n) = app.max_auth_age {
                let session = &authed.view.session;
                let capability = cx.snapshot.reauth_capability(&session.provider_id);
                if !freshness::console_fresh(session, capability, cx.now, n) {
                    return reauth(cx, app, &target, &authed.view, n).await;
                }
            }
            Ok(allow(cx, app, *authed))
        }
    }
}

/// The session is too old (or its age is not provider-verified) for the
/// console: a document navigation starts a reauthentication transaction that
/// carries the server-owned freshness requirement and names the live session;
/// any other request gets the `401`. The handle is kept.
async fn reauth(
    cx: &Cx<'_>,
    app: &AppPolicy,
    target: &url::Url,
    view: &HandleView,
    n: Duration,
) -> Flow {
    if !cx.document() {
        return Ok(Decision::Login {
            transaction: None,
            bind: BindAction::Keep,
            kind: LoginKind::Reauth,
            clear_handle: false,
            cause: None,
        });
    }
    let (bind_digest, bind) = cx.bind_for_transaction();
    let started = cx
        .event(EventKind::LoginStarted, Outcome::Info, app)
        .session(&view.session.session_id)
        .user(&view.session.user_id)
        .reason(reasons::REAUTH_REQUIRED)
        .attr("navigation", "document")
        .attr("reauth", true)
        .build();
    let txn = create_txn(
        cx,
        app,
        NewTxn {
            target,
            purpose: TxnPurpose::Login,
            bind: Some(bind_digest),
            portal_session_id: Some(view.session.session_id.clone()),
            recovery_depth: 0,
            reauth_max_age: Some(u32::try_from(n.as_secs()).unwrap_or(u32::MAX)),
            events: vec![started],
        },
    )
    .await?;
    Ok(Decision::Login {
        transaction: Some(txn),
        bind,
        kind: LoginKind::Reauth,
        clear_handle: false,
        cause: None,
    })
}

/// Refused before any redemption is attempted; the code (if any) stays
/// unconsumed. Recorded as `handoff.rejected` (required, its own transaction:
/// nothing else changes).
async fn ambiguous_handoff(cx: &Cx<'_>, app: &AppPolicy) -> Decision {
    if let Some(events) = &cx.ctx.events {
        let ev = cx
            .event(EventKind::HandoffRejected, Outcome::Failure, app)
            .attr("host", cx.input.host.as_str())
            .reason(reasons::HANDOFF_AMBIGUOUS)
            .build();
        if let Err(e) = events.append_required(vec![ev]).await {
            tracing::warn!(error = %e, "handoff.rejected (ambiguous) could not be recorded");
        }
    }
    cx.deny(reasons::HANDOFF_AMBIGUOUS, DenyKind::Forbidden)
}

/// What the presented handle amounts to.
enum Authn {
    /// A live handle of an enabled user: everything a `200` needs.
    Allowed(Box<Authed>),
    /// No usable handle; the reason a presented one was refused, if any.
    /// The side effects of the refusal (termination, revocation) are done.
    Refused(Option<Reason>),
}

struct Authed {
    view: HandleView,
    snapshot: IdentitySnapshot,
    expires_at: Timestamp,
}

/// The handle checks of an ordinary verify: lookup, lifetimes, binding policy,
/// user status and authorization version. The entry points reuse them: they
/// "evaluate the presented handle as an ordinary verify would".
async fn authenticate(cx: &Cx<'_>, app: &AppPolicy) -> Result<Authn, Decision> {
    let (ctx, input) = (cx.ctx, cx.input);
    // Cookie handle: absent or malformed handles never reach the store.
    let Some(cookie) = input
        .cookie_handle
        .as_ref()
        .filter(|c| is_well_formed_handle(c.expose()))
    else {
        let cause = input
            .cookie_handle
            .is_some()
            .then_some(reasons::MALFORMED_HANDLE);
        return Ok(Authn::Refused(cause));
    };
    let digest = cookie.digest();
    let Some(view) = ctx
        .sessions
        .lookup_handle(&digest, &input.host)
        .await
        .map_err(|e| cx.store_err(e))?
    else {
        return Ok(Authn::Refused(Some(reasons::UNKNOWN_HANDLE)));
    };
    if view.session.terminated_at.is_some() {
        return Ok(Authn::Refused(Some(reasons::SESSION_TERMINATED)));
    }
    if view.handle.revoked_at.is_some() {
        return Ok(Authn::Refused(Some(reasons::UNKNOWN_HANDLE)));
    }

    // Lifetimes: session timers first, then the handle's.
    let expires_at = match lifetimes::evaluate(
        &view.handle,
        &view.session,
        &app.session,
        &ctx.limits.session,
        cx.now,
    ) {
        LifetimeVerdict::Live { expires_at } => expires_at,
        LifetimeVerdict::ClockSkew => {
            return Err(cx.deny(
                reasons::CLOCK_SKEW,
                DenyKind::Unavailable {
                    retry_after: UNAVAILABLE_RETRY,
                },
            ));
        }
        LifetimeVerdict::HandleExpired(reason) => {
            revoke_handle(cx, app, &view, reason, vec![]).await?;
            return Ok(Authn::Refused(Some(reason)));
        }
        LifetimeVerdict::SessionExpired(reason) => {
            terminate(cx, app, &view, reason, vec![]).await?;
            return Ok(Authn::Refused(Some(reason)));
        }
    };

    // Binding policy.
    if let BindingVerdict::Mismatch { signal, action } = cx.binding_verdict(app, &view) {
        let attrs = binding_attrs(cx, &view, signal);
        match action {
            OnMismatch::TerminateSession => {
                terminate(cx, app, &view, signal.reason(), attrs).await?;
            }
            OnMismatch::DropHandle => {
                revoke_handle(cx, app, &view, signal.reason(), attrs).await?;
            }
        }
        return Ok(Authn::Refused(Some(signal.reason())));
    }

    // User status and authorization version, read with the handle.
    if view.user.status == UserStatus::Disabled {
        terminate(cx, app, &view, reasons::USER_DISABLED, vec![]).await?;
        return Ok(Authn::Refused(Some(reasons::USER_DISABLED)));
    }
    let mut snapshot = view.session.snapshot.clone();
    match app.on_authz_change {
        // Compared against the version at authentication, which a refresh
        // application never advances (G7-C02).
        AuthzChange::Terminate if view.user.authz_version != view.session.authz_version_at_auth => {
            terminate(cx, app, &view, reasons::AUTHZ_CHANGE, vec![]).await?;
            return Ok(Authn::Refused(Some(reasons::AUTHZ_CHANGE)));
        }
        AuthzChange::Terminate => {}
        AuthzChange::Refresh if view.user.authz_version != view.session.authz_version => {
            let Some(user) = ctx
                .directory
                .user(&view.session.user_id)
                .await
                .map_err(|e| cx.store_err(e))?
            else {
                terminate(cx, app, &view, reasons::USER_DISABLED, vec![]).await?;
                return Ok(Authn::Refused(Some(reasons::USER_DISABLED)));
            };
            snapshot = IdentitySnapshot {
                email: user.primary_email,
                display_name: user.display_name,
                username: user.username,
                groups: view.user.groups.clone(),
            };
            ctx.sessions
                .refresh_snapshot(
                    &view.session.session_id,
                    snapshot.clone(),
                    view.user.authz_version,
                )
                .await
                .map_err(|e| cx.store_err(e))?;
        }
        AuthzChange::Refresh => {}
    }

    Ok(Authn::Allowed(Box::new(Authed {
        view,
        snapshot,
        expires_at,
    })))
}

/// The `200`: touch the handle, then identity and cacheability.
fn allow(cx: &Cx<'_>, app: &AppPolicy, authed: Authed) -> Decision {
    let Authed {
        view,
        snapshot,
        expires_at,
    } = authed;
    // Application policy is `enabled` (checked with the host); step-up rules
    // are parsed but not enforced in M1: they only make the answer path-dependent.
    let path_dependent = step_up::forces_no_store(&app.step_up);

    touch(cx, app, &view);

    let cache = cacheability(cx, app, expires_at, path_dependent);
    Decision::Allow {
        identity: Identity {
            user_id: view.session.user_id.clone(),
            email: snapshot.email,
            preferred_username: snapshot.username.or(snapshot.display_name),
            groups: snapshot.groups,
            session_id: view.session.session_id.clone(),
            provider_id: view.session.provider_id.clone(),
            auth_time: view.session.auth_time,
            expires_at,
            aal: view.handle.issued_aal,
            factors: view.session.factors.clone(),
            generations: Generations {
                session: view.session.cred_gen,
                user: view.user.authz_version,
                config: cx.snapshot.generation,
            },
        },
        cache,
    }
}

fn binding_attrs(
    cx: &Cx<'_>,
    view: &HandleView,
    signal: binding::BindSignal,
) -> Vec<(&'static str, serde_json::Value)> {
    match signal {
        binding::BindSignal::Ip => vec![
            ("bound_ip", view.session.bound_ip.to_string().into()),
            ("observed_ip", cx.input.client_ip.to_string().into()),
        ],
        binding::BindSignal::Ua => vec![
            (
                "recorded_sha256",
                view.session
                    .bound_ua_sha256
                    .map(|d| d.to_hex())
                    .unwrap_or_default()
                    .into(),
            ),
            (
                "observed_sha256",
                cx.input
                    .user_agent
                    .as_deref()
                    .map(|u| sha256(u.as_bytes()).to_hex())
                    .unwrap_or_default()
                    .into(),
            ),
        ],
    }
}

async fn terminate(
    cx: &Cx<'_>,
    app: &AppPolicy,
    view: &HandleView,
    reason: Reason,
    attrs: Vec<(&'static str, serde_json::Value)>,
) -> Result<(), Decision> {
    let mut b = cx.view_event(EventKind::SessionTerminated, app, view, reason);
    for (k, v) in attrs {
        b = b.attr(k, v);
    }
    cx.ctx
        .sessions
        .terminate_session(&view.session.session_id, reason, cx.now, vec![b.build()])
        .await
        .map_err(|e| cx.store_err(e))
}

async fn revoke_handle(
    cx: &Cx<'_>,
    app: &AppPolicy,
    view: &HandleView,
    reason: Reason,
    attrs: Vec<(&'static str, serde_json::Value)>,
) -> Result<(), Decision> {
    let mut b = cx
        .view_event(EventKind::HandleRevoked, app, view, reason)
        .attr("host", view.handle.host.as_str());
    for (k, v) in attrs {
        b = b.attr(k, v);
    }
    cx.ctx
        .sessions
        .revoke_handle(&view.handle.handle_sha256, reason, cx.now, vec![b.build()])
        .await
        .map_err(|e| cx.store_err(e))
}

/// `last_seen_at` write coalescing: at most one write per handle per
/// `touch_coalesce`, never awaited by the decision.
/// The deadline of a detached handle touch.
const TOUCH_DEADLINE: Duration = Duration::from_secs(2);

fn touch(cx: &Cx<'_>, app: &AppPolicy, view: &HandleView) {
    static SCHEDULED: OnceLock<Mutex<HashMap<Digest, i64>>> = OnceLock::new();
    // Never longer than half of either idle timer (a short policy must not idle out).
    let window = cx
        .ctx
        .limits
        .touch_coalesce
        .min(app.session.idle / 2)
        .min(cx.ctx.limits.session.idle / 2);
    if cx.now.since(view.handle.last_seen_at) < window {
        return;
    }
    let digest = view.handle.handle_sha256;
    {
        let mut map = SCHEDULED
            .get_or_init(|| Mutex::new(HashMap::new()))
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if map
            .get(&digest)
            .is_some_and(|t| cx.now.since(Timestamp(*t)) < window)
        {
            return;
        }
        if map.len() >= TOUCH_MEMORY {
            map.retain(|_, t| cx.now.since(Timestamp(*t)) < window);
            if map.len() >= TOUCH_MEMORY {
                map.clear();
            }
        }
        map.insert(digest, cx.now.0);
    }
    let (sessions, at) = (cx.ctx.sessions.clone(), cx.now);
    // A spawned task inherits no task-local deadline: the touch is bounded by
    // its own short one, so it can neither pile up nor commit long after the
    // verify that scheduled it.
    tokio::spawn(with_deadline(
        tokio::time::Instant::now() + TOUCH_DEADLINE,
        async move {
            // Best effort: a lost touch only makes the next verify retry it.
            let _ = sessions.touch_handle(&digest, at).await;
        },
    ));
}

fn cacheability(
    cx: &Cx<'_>,
    app: &AppPolicy,
    expires_at: Timestamp,
    path_dependent: bool,
) -> Cacheability {
    let n = Duration::from_secs(u64::from(app.verify_cache_seconds.min(30)));
    if n.is_zero() || path_dependent {
        return Cacheability::NoStore;
    }
    // `max-age` is the configured N; the absolute deadline is the bound
    // every tier obeys (ADR-0006), taken from this authoritative read.
    let fresh_until = cx.now.add(n).min(expires_at);
    if fresh_until <= cx.now {
        return Cacheability::NoStore;
    }
    Cacheability::Private {
        max_age: n,
        fresh_until,
    }
}

/// The unauthenticated path: a document navigation starts a login
/// transaction (nothing for any other request, which gets the `401`).
pub(super) async fn login(
    cx: &Cx<'_>,
    app: &AppPolicy,
    target: &url::Url,
    cause: Option<Reason>,
    recovery_depth: u32,
) -> Flow {
    let clear_handle = cause.is_some();
    *cx.cause.lock().unwrap_or_else(|p| p.into_inner()) = cause;
    if !cx.document() {
        return Ok(Decision::Login {
            transaction: None,
            bind: BindAction::Keep,
            kind: LoginKind::Login,
            clear_handle,
            cause,
        });
    }
    let (bind_digest, bind) = cx.bind_for_transaction();
    let started = cx
        .event(EventKind::LoginStarted, Outcome::Info, app)
        .attr("navigation", "document")
        .attr("recovery_depth", i64::from(recovery_depth))
        .build();
    let txn = create_txn(
        cx,
        app,
        NewTxn {
            target,
            purpose: TxnPurpose::Login,
            bind: Some(bind_digest),
            portal_session_id: None,
            recovery_depth,
            reauth_max_age: None,
            events: vec![started],
        },
    )
    .await?;
    Ok(Decision::Login {
        transaction: Some(txn),
        bind,
        kind: LoginKind::Login,
        clear_handle,
        cause,
    })
}

/// What a new transaction row is made of.
struct NewTxn<'a> {
    target: &'a url::Url,
    purpose: TxnPurpose,
    bind: Option<Digest>,
    portal_session_id: Option<SessionId>,
    recovery_depth: u32,
    reauth_max_age: Option<u32>,
    events: Vec<crate::event::types::Event>,
}

/// Report rows a transaction insert evicted (`txn.evicted`, a diagnostic).
pub(super) fn report_eviction(cx: &Cx<'_>, app: &AppPolicy, evicted: u32) {
    if evicted == 0 {
        return;
    }
    if let Some(emitter) = cx.ctx.emitter.clone() {
        emitter.diagnostic(
            EventKind::TxnEvicted,
            Outcome::Info,
            cx.input.request_id.clone(),
            |b| {
                b.app(&app.app_id)
                    .reason(reasons::TXN_EVICTED)
                    .attr("count", evicted)
            },
        );
    }
}

/// Admit and write one transaction (a login, or a logout ticket) under the
/// per-address cap and `txn.max_rows`, both enforced inside the one store
/// write (eviction included, so `max_rows` is a hard bound). Over the cap is
/// `txn_rate_limited`. The returned secret is the transaction id.
async fn create_txn(cx: &Cx<'_>, app: &AppPolicy, t: NewTxn<'_>) -> Result<Secret, Decision> {
    let (ctx, input) = (cx.ctx, cx.input);
    let txn: Secret = random_token(&*ctx.rng, 16);
    let row = NewTransaction {
        txn_sha256: txn.digest(),
        created_at: cx.now,
        expires_at: cx.now.add(ctx.limits.txn_lifetime),
        app_id: app.app_id.clone(),
        return_target: t.target.clone(),
        bind_sha256: t.bind,
        portal_bind_sha256: None,
        retry_bind_sha256: None,
        client_ip: input.client_ip,
        ua_sha256: input.user_agent.as_deref().map(|u| sha256(u.as_bytes())),
        provider_id: None,
        state_sha256: None,
        nonce: None,
        pkce_verifier: None,
        portal_session_id: t.portal_session_id,
        purpose: t.purpose,
        conflicting_handle_sha256: None,
        pending_identity: None,
        recovery_depth: t.recovery_depth,
        reauth_max_age: t.reauth_max_age,
    };
    let admission = ctx
        .sessions
        .create_transaction_capped(
            row,
            t.events,
            cx.now.sub(RATE_WINDOW),
            Some(ctx.limits.txn_per_ip_per_minute),
            ctx.limits.txn_max_rows,
        )
        .await
        .map_err(|e| cx.store_err(e))?;
    match admission {
        Admission::OverCap => Err(cx.deny(
            reasons::TXN_RATE_LIMITED,
            DenyKind::RateLimited {
                retry_after: RATE_WINDOW,
            },
        )),
        Admission::Admitted { evicted } => {
            report_eviction(cx, app, evicted);
            Ok(txn)
        }
    }
}

// ---- application-host entry points (ADR-0015) ------------------------------

/// `GET /_hopae/login` and `GET /_hopae/logout`: answered here, never relayed
/// upstream, never a `2xx`.
async fn entry_point(cx: &Cx<'_>, app: &AppPolicy, entry: EntryPoint) -> Flow {
    // Only a document navigation by `GET` is an entry-point request; anything
    // else (fetch, `<img>`, a form `POST`) changes nothing and gets one answer.
    if !cx.document() || !cx.input.accepts_html || cx.input.method != http::Method::GET {
        return Err(cx.deny(reasons::ENTRY_POINT_NOT_DOCUMENT, DenyKind::Forbidden));
    }
    let Some(target) = entry_target(cx) else {
        return Err(cx.deny(reasons::RETURN_NOT_ALLOWED, DenyKind::Forbidden));
    };
    match entry {
        // Every handoff is delivered here (ADR-0015): the reserved parameter is
        // redeemed against the validated `return` target, which is also where the
        // browser is sent next. On the logout entry point, and on every other
        // reserved path, the parameter is neither redeemed nor consulted.
        EntryPoint::Login => match &cx.input.handoff {
            Handoff::Code(code) => handoff::redeem(cx, app, &target, code).await,
            Handoff::Ambiguous => Err(ambiguous_handoff(cx, app).await),
            Handoff::None => match authenticate(cx, app).await? {
                Authn::Allowed(authed) => {
                    // As a `200` would: the handle is in use.
                    touch(cx, app, &authed.view);
                    Ok(Decision::AlreadyAuthenticated { location: target })
                }
                Authn::Refused(cause) => login(cx, app, &target, cause, 0).await,
            },
        },
        EntryPoint::Logout => logout_entry(cx, app, &target).await,
    }
}

/// The entry point's target: the request origin's `/`, or the validated
/// `return` on exactly the request's origin. `None` is `return_not_allowed`.
fn entry_target(cx: &Cx<'_>) -> Option<url::Url> {
    let request = &cx.input.original_url;
    match &cx.input.entry_return {
        EntryReturn::Absent => {
            let mut root = request.clone();
            root.set_path("/");
            root.set_query(None);
            root.set_fragment(None);
            Some(root)
        }
        EntryReturn::Invalid => None,
        EntryReturn::Candidate {
            url,
            canonical_path,
        } => {
            let target =
                apps::validate_return_target(url, &cx.snapshot, cx.ctx.limits.secure).ok()?;
            // The same registered origin, not merely a registered one; never a
            // reserved path (the entry point itself), never the handoff parameter
            // (the adapter checked the query).
            (target.origin() == request.origin() && canonical_path.reserved() == Reserved::No)
                .then_some(target)
        }
    }
}

/// The logout entry point: the presented handle is evaluated as an ordinary
/// verify would; then either the session ends here (the no-confirmation mode
/// for a same-origin navigation with a valid handle) or a logout ticket sends
/// the browser to the portal's confirmation page. A `GET` that clears nothing
/// and revokes nothing in the default mode (decision 6).
async fn logout_entry(cx: &Cx<'_>, app: &AppPolicy, target: &url::Url) -> Flow {
    let (ctx, input) = (cx.ctx, cx.input);
    let authn = authenticate(cx, app).await?;
    let (session, clear_handle) = match authn {
        Authn::Allowed(authed) => (Some(authed.view), false),
        Authn::Refused(cause) => {
            // As the ordinary login records it (`verify.denied`), including
            // when the ticket then cannot be admitted.
            *cx.cause.lock().unwrap_or_else(|p| p.into_inner()) = cause;
            (None, cause.is_some())
        }
    };
    let cause = *cx.cause.lock().unwrap_or_else(|p| p.into_inner());
    let direct =
        !app.logout_confirm && input.fetch_site == FetchSite::SameOrigin && session.is_some();
    // The informational binding digest of the browser, never planted here.
    let bind = input
        .bind_cookie
        .as_ref()
        .filter(|b| is_well_formed_bind(b.expose()))
        .map(Secret::digest);
    let portal_session_id = session.as_ref().map(|v| v.session.session_id.clone());
    if direct && let Some(view) = &session {
        // Reducing access comes first: the session ends even when the
        // reference page cannot be offered (rate limited).
        terminate(cx, app, view, reasons::LOGOUT, vec![]).await?;
    }
    let ticket = create_txn(
        cx,
        app,
        NewTxn {
            target,
            purpose: TxnPurpose::Logout,
            bind,
            portal_session_id,
            recovery_depth: 0,
            reauth_max_age: None,
            events: vec![],
        },
    )
    .await?;
    if direct {
        // The ticket becomes the opaque reference to the return target for
        // the portal's signed-out page: consumed at once, readable until it
        // expires. No URL travels in the redirect (TM-01).
        ctx.sessions
            .consume_transaction(&ticket.digest(), reasons::LOGOUT, cx.now, vec![])
            .await
            .map_err(|e| cx.store_err(e))?;
        return Ok(Decision::LoggedOut {
            transaction: ticket,
        });
    }
    Ok(Decision::LogoutEntry {
        transaction: ticket,
        clear_handle,
        cause,
    })
}
