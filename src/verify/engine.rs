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
use crate::policy::step_up;
use crate::policy::types::{AppPolicy, AuthzChange, ConfigSnapshot, OnMismatch};
use crate::session::types::Generations;
use crate::store::types::{HandleView, IdentitySnapshot, NewTransaction, TxnPurpose, UserStatus};
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

    // The return target: the only URL a user is ever sent back to.
    let target =
        apps::validate_return_target(input.original_url.as_str(), &cx.snapshot, ctx.limits.secure)
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

    // Reserved handoff parameter.
    match (&input.handoff, cx.document()) {
        (Handoff::None, _) => {}
        (Handoff::Code(code), true) => return handoff::redeem(cx, app, &target, code).await,
        (Handoff::Ambiguous, true) => {
            // Refused before any redemption is attempted; the code (if any)
            // stays unconsumed. Recorded as `handoff.rejected` (required, its
            // own transaction: nothing else changes).
            if let Some(events) = &ctx.events {
                let ev = cx
                    .event(EventKind::HandoffRejected, Outcome::Failure, app)
                    .attr("host", input.host.as_str())
                    .reason(reasons::HANDOFF_AMBIGUOUS)
                    .build();
                if let Err(e) = events.append_required(vec![ev]).await {
                    tracing::warn!(error = %e, "handoff.rejected (ambiguous) could not be recorded");
                }
            }
            return Err(cx.deny(reasons::HANDOFF_AMBIGUOUS, DenyKind::Forbidden));
        }
        (_, false) => {
            return Err(cx.deny(reasons::HANDOFF_PARAMETER_NOT_ALLOWED, DenyKind::Forbidden));
        }
    }

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
        return login(cx, app, &target, cause, 0).await;
    };
    let digest = cookie.digest();
    let Some(view) = ctx
        .sessions
        .lookup_handle(&digest, &input.host)
        .await
        .map_err(|e| cx.store_err(e))?
    else {
        return login(cx, app, &target, Some(reasons::UNKNOWN_HANDLE), 0).await;
    };
    if view.session.terminated_at.is_some() {
        return login(cx, app, &target, Some(reasons::SESSION_TERMINATED), 0).await;
    }
    if view.handle.revoked_at.is_some() {
        return login(cx, app, &target, Some(reasons::UNKNOWN_HANDLE), 0).await;
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
            return login(cx, app, &target, Some(reason), 0).await;
        }
        LifetimeVerdict::SessionExpired(reason) => {
            terminate(cx, app, &view, reason, vec![]).await?;
            return login(cx, app, &target, Some(reason), 0).await;
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
        return login(cx, app, &target, Some(signal.reason()), 0).await;
    }

    // User status and authorization version, read with the handle.
    if view.user.status == UserStatus::Disabled {
        terminate(cx, app, &view, reasons::USER_DISABLED, vec![]).await?;
        return login(cx, app, &target, Some(reasons::USER_DISABLED), 0).await;
    }
    let mut snapshot = view.session.snapshot.clone();
    if view.user.authz_version != view.session.authz_version {
        match app.on_authz_change {
            AuthzChange::Terminate => {
                terminate(cx, app, &view, reasons::AUTHZ_CHANGE, vec![]).await?;
                return login(cx, app, &target, Some(reasons::AUTHZ_CHANGE), 0).await;
            }
            AuthzChange::Refresh => {
                let Some(user) = ctx
                    .directory
                    .user(&view.session.user_id)
                    .await
                    .map_err(|e| cx.store_err(e))?
                else {
                    terminate(cx, app, &view, reasons::USER_DISABLED, vec![]).await?;
                    return login(cx, app, &target, Some(reasons::USER_DISABLED), 0).await;
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
        }
    }

    // Application policy is `enabled` (checked with the host); step-up rules
    // are parsed but not enforced in M1: they only make the answer path-dependent.
    let path_dependent = step_up::forces_no_store(&app.step_up);

    touch(cx, &view);

    let cache = cacheability(cx, app, expires_at, path_dependent);
    Ok(Decision::Allow {
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
    })
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
fn touch(cx: &Cx<'_>, view: &HandleView) {
    static SCHEDULED: OnceLock<Mutex<HashMap<Digest, i64>>> = OnceLock::new();
    let window = cx.ctx.limits.touch_coalesce;
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
    tokio::spawn(async move {
        // Best effort: a lost touch only makes the next verify retry it.
        let _ = sessions.touch_handle(&digest, at).await;
    });
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
    let (ctx, input) = (cx.ctx, cx.input);
    let recent = ctx
        .sessions
        .count_transactions_since(input.client_ip, cx.now.sub(RATE_WINDOW))
        .await
        .map_err(|e| cx.store_err(e))?;
    if recent >= ctx.limits.txn_per_ip_per_minute {
        return Err(cx.deny(
            reasons::TXN_RATE_LIMITED,
            DenyKind::RateLimited {
                retry_after: RATE_WINDOW,
            },
        ));
    }
    let (bind_digest, bind) = cx.bind_for_transaction();
    let txn: Secret = random_token(&*ctx.rng, 16);
    let row = NewTransaction {
        txn_sha256: txn.digest(),
        created_at: cx.now,
        expires_at: cx.now.add(ctx.limits.txn_lifetime),
        app_id: app.app_id.clone(),
        return_target: target.clone(),
        bind_sha256: Some(bind_digest),
        portal_bind_sha256: None,
        retry_bind_sha256: None,
        client_ip: input.client_ip,
        ua_sha256: input.user_agent.as_deref().map(|u| sha256(u.as_bytes())),
        provider_id: None,
        state_sha256: None,
        nonce: None,
        pkce_verifier: None,
        portal_session_id: None,
        purpose: TxnPurpose::Login,
        conflicting_handle_sha256: None,
        pending_identity: None,
        recovery_depth,
    };
    let started = cx
        .event(EventKind::LoginStarted, Outcome::Info, app)
        .attr("navigation", "document")
        .attr("recovery_depth", i64::from(recovery_depth))
        .build();
    ctx.sessions
        .create_transaction(row, vec![started])
        .await
        .map_err(|e| cx.store_err(e))?;
    // Keep the table bounded; best effort, never on the decision's path.
    let (sessions, now, max_rows) = (ctx.sessions.clone(), cx.now, ctx.limits.txn_max_rows);
    let (emitter, request_id, app_id) = (
        ctx.emitter.clone(),
        input.request_id.clone(),
        app.app_id.clone(),
    );
    tokio::spawn(async move {
        if let Ok(evicted) = sessions.evict_transactions(max_rows, now).await
            && evicted > 0
            && let Some(emitter) = emitter
        {
            emitter.diagnostic(EventKind::TxnEvicted, Outcome::Info, request_id, |b| {
                b.app(&app_id)
                    .reason(reasons::TXN_EVICTED)
                    .attr("count", evicted)
            });
        }
    });
    Ok(Decision::Login {
        transaction: Some(txn),
        bind,
        kind: LoginKind::Login,
        clear_handle,
        cause,
    })
}
