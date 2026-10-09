//! Handoff codes (ADR-0004, ADR-0008): minting for a host, and redemption on
//! the application host with the browser-bind check, the `cred_gen` check,
//! the `min(issued_aal, aal)` rule, the same-user / other-user handle rules
//! and the depth-bounded recovery from the first-use cookie race.
//!
//! The store's conditional update is the arbiter of every redemption; the
//! checks repeated here only choose the event reason (the store takes its
//! event lists before it knows which rule failed) and the response.

use std::net::IpAddr;
use std::time::Duration;

use async_trait::async_trait;
use url::Url;

use crate::crypto::{
    Digest, Secret, ct_eq, handle_value, is_well_formed_bind, is_well_formed_handle, random_token,
};
use crate::event::types::{Event, EventKind, Outcome, Reason, reasons};
use crate::policy::types::Host;
use crate::session::service::{
    CODE_LIFETIME, COUNTER_WINDOW, HandleState, RequestCtx, Service, SessionError, TXN_LIFETIME,
    host_of,
};
use crate::session::transactions::{HANDOFF_PARAM, StartedLogin};
use crate::session::types::{Aal, SessionId};
use crate::store::types::{
    HandleRow, HandleView, HandoffCodeRow, NewTransaction, RedeemOutcome, RedeemRequest,
    SessionRow, TxnPurpose,
};
use crate::store::{StoreError, StoreResult};

/// Non-consuming read of a handoff code row. Redemption needs the code's
/// session before it calls the store (to build the new handle and to name the
/// session and user in the events), and `Sessions` has no such read yet; the
/// orchestrator wires this to `Sessions::handoff_code` once W0 provides it.
#[async_trait]
pub trait CodeDirectory: Send + Sync {
    async fn handoff_code(&self, code_sha256: &Digest) -> StoreResult<Option<HandoffCodeRow>>;
}

pub struct MintRequest {
    pub session_id: SessionId,
    /// The grant the caller may pass on; the code carries `min(aal_cap, session.aal)`.
    pub aal_cap: Aal,
    /// The clean return target.
    pub target: Url,
    /// The client IP the application host will see.
    pub client_ip: IpAddr,
    /// Digest of the browser's binding cookie on the application host.
    pub bind_sha256: Digest,
    /// Copied from the minting transaction (never from the client).
    pub recovery_depth: u32,
    pub events: Vec<Event>,
}

#[derive(Debug)]
pub struct MintedHandoff {
    pub code: Secret,
    /// The return target with the reserved parameter appended.
    pub location: Url,
    pub issued_aal: Aal,
}

pub struct RedeemInput {
    pub code: Secret,
    /// The request URL with the reserved parameter removed (other parameters and order kept).
    pub target: Url,
    pub client_ip: IpAddr,
    pub user_agent: Option<String>,
    /// `__Host-hopae_bind` as received.
    pub bind_cookie: Option<Secret>,
    /// `__Host-hopae` as received.
    pub handle_cookie: Option<Secret>,
    pub request_id: String,
}

#[derive(Debug)]
pub enum RedeemResult {
    /// `302` to `location` planting `handle` (`Max-Age = max_age`); the bind cookie is left alone.
    Minted {
        location: Url,
        handle: Secret,
        issued_aal: Aal,
        max_age: Duration,
        session_id: SessionId,
    },
    /// A consumed code with the handle it produced: the clean `302`, no cookie change.
    AlreadyRedeemed { location: Url },
    /// Any other failure: the code is burned and this is the ordinary
    /// unauthenticated `302` to the portal (the bind is kept when present).
    Login(StartedLogin),
    /// A valid handle of another user: `302` to `/switch?txn=`, every cookie untouched.
    Switch { transaction: Secret },
    /// The recovery depth reached `handoff.max_recoveries`: a relayed `403`
    /// (`handoff_recovery_exhausted`), no transaction created.
    Exhausted { depth: u32 },
    /// `handoff.per_ip_failures_per_minute` reached: nothing was attempted.
    RateLimited { retry_after: Duration },
}

/// What the rules predict for a redemption, used to pick event reasons.
#[derive(Debug, PartialEq, Eq)]
enum Prediction {
    Success,
    AlreadyRedeemed,
    Reject(Reason),
}

/// Append the reserved parameter to the raw query, leaving every existing
/// parameter byte for byte as it was.
pub fn append_handoff_param(target: &Url, code: &str) -> Url {
    let mut u = target.clone();
    let q = match u.query() {
        Some(q) if !q.is_empty() => format!("{q}&{HANDOFF_PARAM}={code}"),
        _ => format!("{HANDOFF_PARAM}={code}"),
    };
    u.set_query(Some(&q));
    u
}

impl Service {
    /// Mint a handoff code for `req.target`'s host, bound to the application
    /// host's binding cookie digest, the client IP and the session's current
    /// credential generation (ADR-0004/0008). A concurrent revocation or
    /// elevation moves the generation; the mint is retried once against the
    /// new generation and fails if the session is gone.
    pub async fn mint_handoff(&self, req: MintRequest) -> Result<MintedHandoff, SessionError> {
        let host = host_of(&req.target)?;
        let port = req.target.port_or_known_default().unwrap_or(0);
        if !self.snapshot.load().return_origin_allowed(&host, port) {
            return Err(SessionError::Refused(reasons::UNKNOWN_APP));
        }
        for attempt in 0..2 {
            let session = self
                .sessions
                .session(&req.session_id)
                .await?
                .filter(|s| s.terminated_at.is_none())
                .ok_or(SessionError::Refused(reasons::SESSION_TERMINATED))?;
            let code = random_token(&*self.rng, 32);
            let now = self.clock.now();
            let issued = req.aal_cap.min(session.aal);
            let row = HandoffCodeRow {
                code_sha256: code.digest(),
                session_id: session.session_id.clone(),
                host: host.clone(),
                return_target: req.target.clone(),
                client_ip: req.client_ip,
                bind_sha256: req.bind_sha256,
                issued_aal: issued,
                cred_gen: session.cred_gen,
                recovery_depth: req.recovery_depth,
                created_at: now,
                expires_at: now.add(CODE_LIFETIME),
                consumed_at: None,
                consumed_reason: None,
            };
            match self
                .sessions
                .mint_handoff_code(row, req.events.clone())
                .await
            {
                Ok(()) => {
                    return Ok(MintedHandoff {
                        location: append_handoff_param(&req.target, code.expose()),
                        code,
                        issued_aal: issued,
                    });
                }
                Err(StoreError::Conflict(_)) if attempt == 0 => continue,
                Err(StoreError::Conflict(_)) => break,
                Err(e) => return Err(e.into()),
            }
        }
        Err(SessionError::Refused(reasons::CODE_STALE_GENERATION))
    }

    /// Redeem `input.code` on its application host (a document navigation
    /// that carries exactly one reserved parameter; the caller has already
    /// refused every other shape). See [`RedeemResult`] for the outcomes.
    pub async fn redeem(&self, input: RedeemInput) -> Result<RedeemResult, SessionError> {
        let ctx = RequestCtx {
            client_ip: input.client_ip,
            user_agent: input.user_agent.clone(),
            request_id: input.request_id.clone(),
        };
        let now = self.clock.now();
        let host = host_of(&input.target)?;
        // A cookie planted over plain http would be readable on the wire: while
        // cookies are Secure the code is not even looked at (S003-A7).
        if self.cfg.secure && input.target.scheme() != "https" {
            return Err(SessionError::Refused(reasons::INSECURE_TRANSPORT));
        }

        // Guessing is bounded per IP before anything is attempted.
        let failures = self
            .sessions
            .count_handoff_failures_since(ctx.client_ip, now.sub(COUNTER_WINDOW))
            .await?;
        if failures >= self.cfg.handoff_failures_per_minute {
            return Ok(RedeemResult::RateLimited {
                retry_after: COUNTER_WINDOW,
            });
        }

        let bind = input
            .bind_cookie
            .as_ref()
            .filter(|b| is_well_formed_bind(b.expose()));
        let bind_digest = bind.map(|b| b.digest());
        let snap = self.snapshot.load_full();
        let app = snap
            .app_for_host(&host)
            .ok_or(SessionError::Refused(reasons::UNKNOWN_APP))?
            .clone();
        let presented = self
            .presented_handle(&ctx, &host, input.handle_cookie.as_ref(), &app)
            .await?;

        // The code's row names its session; the store arbitrates the rest.
        let code_digest = input.code.digest();
        let peeked = self.codes.handoff_code(&code_digest).await?;
        let session: Option<SessionRow> = match &peeked {
            Some(c) => self.sessions.session(&c.session_id).await?,
            None => None,
        };
        let path = input.target.path().to_string();
        let prediction = predict(
            peeked.as_ref(),
            session.as_ref(),
            &host,
            &path,
            ctx.client_ip,
            bind_digest,
            presented.as_ref(),
            now,
        );
        let exhausted_depth = match (&prediction, &peeked) {
            (Prediction::Reject(r), Some(c))
                if *r == reasons::BIND_MISMATCH
                    && presented.is_none()
                    && c.recovery_depth >= self.cfg.max_recoveries =>
            {
                Some(c.recovery_depth)
            }
            _ => None,
        };

        let new_secret = handle_value(&*self.rng);
        let handle_abs = {
            let by_app = now.add(app.session.absolute);
            session
                .as_ref()
                .map_or(by_app, |s| by_app.min(s.absolute_expires_at))
        };
        let new_handle = HandleRow {
            handle_sha256: new_secret.digest(),
            session_id: peeked
                .as_ref()
                .map(|c| c.session_id.clone())
                .unwrap_or_else(|| SessionId::new("")),
            host: host.clone(),
            issued_aal: Aal::One,
            created_at: now,
            last_seen_at: now,
            absolute_expires_at: handle_abs,
            revoked_at: None,
            revoked_reason: None,
        };

        let mut ok_event = self
            .ev(&ctx, EventKind::SessionHandoff, Outcome::Success)
            .app(&app.app_id)
            .attr("host", host.as_str())
            .attr("sso", false);
        if let Some(s) = &session {
            ok_event = ok_event.user(&s.user_id).session(&s.session_id);
        }
        let reject_reason = match (&prediction, exhausted_depth) {
            (_, Some(_)) => reasons::HANDOFF_RECOVERY_EXHAUSTED,
            (Prediction::Reject(r), None) => *r,
            // Predicted to succeed but the store refused: a concurrent
            // revocation, elevation or redemption consumed the code first.
            _ => reasons::CODE_CONSUMED,
        };
        let mut fail_event = self
            .ev(&ctx, EventKind::HandoffRejected, Outcome::Failure)
            .app(&app.app_id)
            .reason(reject_reason)
            .attr("host", host.as_str());
        if let Some(c) = &peeked {
            fail_event = fail_event
                .session(&c.session_id)
                .attr("recovery_depth", c.recovery_depth);
        }
        if let Some(s) = &session {
            fail_event = fail_event.user(&s.user_id);
        }

        let outcome = self
            .sessions
            .redeem_handoff_code(
                RedeemRequest {
                    code_sha256: code_digest,
                    host: host.clone(),
                    path,
                    client_ip: ctx.client_ip,
                    presented_bind_sha256: bind_digest,
                    presented_handle: presented.clone(),
                    new_handle: new_handle.clone(),
                    now,
                },
                vec![ok_event.build()],
                vec![fail_event.build()],
            )
            .await?;

        match outcome {
            RedeemOutcome::Minted {
                session,
                issued_aal,
            } => Ok(RedeemResult::Minted {
                location: input.target,
                handle: new_secret,
                issued_aal,
                max_age: new_handle
                    .absolute_expires_at
                    .min(session.absolute_expires_at)
                    .since(now),
                session_id: session.session_id,
            }),
            RedeemOutcome::AlreadyRedeemed => Ok(RedeemResult::AlreadyRedeemed {
                location: input.target,
            }),
            RedeemOutcome::SessionConflict { code } => {
                let old = presented.ok_or(SessionError::Refused(reasons::SESSION_CONFLICT))?;
                let transaction = self
                    .switch_transaction(&ctx, &app.app_id, &input.target, &code, &old)
                    .await?;
                Ok(RedeemResult::Switch { transaction })
            }
            RedeemOutcome::Rejected { reason, code } => {
                // Recovery applies only to a bind mismatch while the browser
                // holds no valid handle; the depth comes from the burned
                // row, never from the request.
                if reason == reasons::BIND_MISMATCH && presented.is_none() {
                    let depth = code.as_ref().map_or(0, |c| c.recovery_depth);
                    if depth >= self.cfg.max_recoveries {
                        return Ok(RedeemResult::Exhausted { depth });
                    }
                    let started = self
                        .start_login(&ctx, &input.target, bind, depth + 1)
                        .await?;
                    return Ok(RedeemResult::Login(started));
                }
                let started = self.start_login(&ctx, &input.target, bind, 0).await?;
                Ok(RedeemResult::Login(started))
            }
            RedeemOutcome::Exhausted { code } => Ok(RedeemResult::Exhausted {
                depth: code.recovery_depth,
            }),
        }
    }

    /// The handle the browser presented on this host, when it is valid
    /// (not revoked, session alive, user active, lifetimes and binding pass).
    async fn presented_handle(
        &self,
        ctx: &RequestCtx,
        host: &Host,
        cookie: Option<&Secret>,
        app: &crate::policy::types::AppPolicy,
    ) -> Result<Option<HandleView>, SessionError> {
        let Some(c) = cookie.filter(|c| is_well_formed_handle(c.expose())) else {
            return Ok(None);
        };
        let Some(view) = self.sessions.lookup_handle(&c.digest(), host).await? else {
            return Ok(None);
        };
        Ok(match self.evaluate_handle(&view, app, ctx) {
            HandleState::Usable => Some(view),
            _ => None,
        })
    }

    /// The `switch` transaction of S003-A10: it stores the clean target, the
    /// digest of the presented (other user's) handle, and the session the
    /// burned code was for, so the confirmation can only be completed by a
    /// browser signed in to that session at the portal.
    async fn switch_transaction(
        &self,
        ctx: &RequestCtx,
        app: &crate::policy::types::AppId,
        target: &Url,
        code: &HandoffCodeRow,
        old: &HandleView,
    ) -> Result<Secret, SessionError> {
        let now = self.clock.now();
        let recent = self
            .sessions
            .count_transactions_since(ctx.client_ip, now.sub(COUNTER_WINDOW))
            .await?;
        if recent >= self.cfg.txn_per_ip_per_minute {
            return Err(SessionError::RateLimited {
                retry_after: COUNTER_WINDOW,
            });
        }
        self.make_room(ctx, app).await?;
        let txn = random_token(&*self.rng, 16);
        self.sessions
            .create_transaction(
                NewTransaction {
                    txn_sha256: txn.digest(),
                    created_at: now,
                    expires_at: now.add(TXN_LIFETIME),
                    app_id: app.clone(),
                    return_target: target.clone(),
                    bind_sha256: Some(code.bind_sha256),
                    portal_bind_sha256: None,
                    retry_bind_sha256: None,
                    client_ip: ctx.client_ip,
                    ua_sha256: self.ua_digest(ctx),
                    provider_id: None,
                    state_sha256: None,
                    nonce: None,
                    pkce_verifier: None,
                    portal_session_id: Some(code.session_id.clone()),
                    purpose: TxnPurpose::Switch,
                    conflicting_handle_sha256: Some(old.handle.handle_sha256),
                    pending_identity: None,
                    recovery_depth: code.recovery_depth,
                },
                vec![],
            )
            .await?;
        Ok(txn)
    }
}

/// The ADR-0004 redemption rule, evaluated in the store's order, to pick the
/// reason an event names. It never decides: the store's conditional update does.
#[allow(clippy::too_many_arguments)]
fn predict(
    code: Option<&HandoffCodeRow>,
    session: Option<&SessionRow>,
    host: &Host,
    path: &str,
    client_ip: IpAddr,
    bind: Option<Digest>,
    presented: Option<&HandleView>,
    now: crate::crypto::Timestamp,
) -> Prediction {
    let Some(code) = code else {
        return Prediction::Reject(reasons::CODE_UNKNOWN);
    };
    if code.consumed_at.is_some() {
        let same_session = presented
            .is_some_and(|v| v.session.session_id == code.session_id && &v.handle.host == host);
        return if code.consumed_reason.as_deref() == Some("redeemed") && same_session {
            Prediction::AlreadyRedeemed
        } else {
            Prediction::Reject(reasons::CODE_CONSUMED)
        };
    }
    if code.expires_at.secs() <= now.secs() {
        return Prediction::Reject(reasons::CODE_EXPIRED);
    }
    if &code.host != host {
        return Prediction::Reject(reasons::CODE_HOST_MISMATCH);
    }
    if code.return_target.path() != path {
        return Prediction::Reject(reasons::CODE_PATH_MISMATCH);
    }
    if code.client_ip != client_ip {
        return Prediction::Reject(reasons::CODE_IP_MISMATCH);
    }
    match bind {
        Some(b) if ct_eq(&b.0, &code.bind_sha256.0) => {}
        _ => return Prediction::Reject(reasons::BIND_MISMATCH),
    }
    let Some(s) = session.filter(|s| s.terminated_at.is_none() && s.cred_gen == code.cred_gen)
    else {
        return Prediction::Reject(reasons::CODE_STALE_GENERATION);
    };
    if presented.is_some_and(|v| v.session.user_id != s.user_id) {
        return Prediction::Reject(reasons::SESSION_CONFLICT);
    }
    Prediction::Success
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handoff_parameter_is_appended_without_touching_the_rest() {
        let t = Url::parse("https://app.example.test/admin/x?q=1&z=%2B2").unwrap();
        assert_eq!(
            append_handoff_param(&t, "K").as_str(),
            "https://app.example.test/admin/x?q=1&z=%2B2&_hopae_handoff=K"
        );
        let t = Url::parse("https://app.example.test/admin/x").unwrap();
        assert_eq!(
            append_handoff_param(&t, "K").as_str(),
            "https://app.example.test/admin/x?_hopae_handoff=K"
        );
        let t = Url::parse("https://app.example.test/?").unwrap();
        assert_eq!(
            append_handoff_param(&t, "K").as_str(),
            "https://app.example.test/?_hopae_handoff=K"
        );
    }
}
