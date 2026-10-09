//! The logout ticket on the portal side (ADR-0015).
//!
//! `/_hopae/logout` creates a transaction of purpose `logout` (the verify
//! engine's job) and sends the browser to `GET /logout?txn=<ticket>`. The
//! first visit records the digest of the portal binding cookie on the ticket,
//! once; the confirming `POST` must present the same cookie. The `POST`
//! consumes the ticket (single use) and ends the session the ticket names, as
//! well as the session of the portal handle presented, with `reason=logout`.
//! A ticket that is unknown, consumed, expired, of another purpose or bound to
//! another browser is treated as absent by the caller: the plain `/logout`
//! behavior, never an error page.
//!
//! After the confirmation nothing redirects to the protected return target (a
//! provider with a live session would sign the user straight back in): the
//! portal renders its signed-out page with a link, validated like any return
//! target.

use url::Url;

use crate::crypto::{Secret, ct_eq, is_well_formed_bind};
use crate::event::types::{EventKind, Outcome, reasons};
use crate::policy::apps;
use crate::policy::types::AppId;
use crate::session::service::{RequestCtx, Service, SessionError};
use crate::store::types::{TransactionRow, TxnPurpose};

/// What the signed-out page shows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedOutView {
    /// The application's display name ("Sign in again to <name>").
    pub app_name: String,
    /// The validated return target; `None` when it no longer validates
    /// (the application was removed or disabled since the ticket was made).
    pub sign_in: Option<Url>,
}

impl Service {
    fn app_display_name(&self, app_id: &AppId) -> String {
        let snap = self.snapshot.load();
        snap.apps
            .iter()
            .find(|a| &a.app_id == app_id)
            .map_or_else(|| app_id.to_string(), |a| a.display_name.clone())
    }

    fn signed_out(&self, row: &TransactionRow) -> SignedOutView {
        let snap = self.snapshot.load();
        SignedOutView {
            app_name: self.app_display_name(&row.app_id),
            // The same validation as every return target; the link is only
            // ever a target this deployment would send a user to.
            sign_in: apps::validate_return_target(
                row.return_target.as_str(),
                &snap,
                self.cfg.secure,
            )
            .ok(),
        }
    }

    /// A live logout ticket presented by the browser that holds `portal_bind`.
    /// `establish` records the binding at the first visit (once); without it
    /// a ticket that no browser opened yet is refused.
    async fn load_ticket(
        &self,
        txn: &Secret,
        portal_bind: Option<&Secret>,
        establish: bool,
    ) -> Result<TransactionRow, SessionError> {
        if !is_well_formed_bind(txn.expose()) {
            return Err(SessionError::Refused(reasons::TXN_EXPIRED));
        }
        let Some(row) = self.sessions.transaction(&txn.digest()).await? else {
            return Err(SessionError::Refused(reasons::TXN_EXPIRED));
        };
        if row.purpose != TxnPurpose::Logout {
            return Err(SessionError::Refused(reasons::TXN_PURPOSE_MISMATCH));
        }
        if row.consumed_at.is_some() {
            return Err(SessionError::Refused(reasons::TXN_CONSUMED));
        }
        if row.expires_at <= self.clock.now() {
            return Err(SessionError::Refused(reasons::TXN_EXPIRED));
        }
        let bind = portal_bind
            .filter(|b| is_well_formed_bind(b.expose()))
            .ok_or(SessionError::Refused(reasons::PORTAL_BIND_MISMATCH))?;
        let digest = bind.digest();
        let matches = |recorded: &crate::crypto::Digest| ct_eq(&recorded.0, &digest.0);
        match &row.portal_bind_sha256 {
            Some(recorded) if matches(recorded) => Ok(row),
            Some(_) => Err(SessionError::Refused(reasons::PORTAL_BIND_MISMATCH)),
            None if !establish => Err(SessionError::Refused(reasons::PORTAL_BIND_MISMATCH)),
            None => {
                if self
                    .sessions
                    .bind_logout_transaction(&row.txn_sha256, digest)
                    .await?
                {
                    return Ok(row);
                }
                // Lost a race with another visit: the recorded binding decides.
                let now = self
                    .sessions
                    .transaction(&row.txn_sha256)
                    .await?
                    .ok_or(SessionError::Refused(reasons::TXN_EXPIRED))?;
                match &now.portal_bind_sha256 {
                    Some(recorded) if matches(recorded) => Ok(now),
                    _ => Err(SessionError::Refused(reasons::PORTAL_BIND_MISMATCH)),
                }
            }
        }
    }

    /// `GET /logout?txn=`: the application's name when the ticket is live and
    /// belongs to this browser. The only state change is recording the
    /// browser binding of the ticket.
    pub async fn logout_visit(
        &self,
        txn: &Secret,
        portal_bind: Option<&Secret>,
    ) -> Result<String, SessionError> {
        let row = self.load_ticket(txn, portal_bind, true).await?;
        Ok(self.app_display_name(&row.app_id))
    }

    /// `POST /logout` with a ticket, after the CSRF and `Origin` checks. Ends
    /// the session of the portal handle presented (as the plain `/logout`
    /// does) and, when the ticket is live and bound to this browser, consumes
    /// it and ends the session it names. `signed_out` is `Some` only for a
    /// ticket that was just consumed.
    pub async fn logout_confirmed(
        &self,
        ctx: &RequestCtx,
        portal_handle: Option<&Secret>,
        ticket: Option<&Secret>,
        portal_bind: Option<&Secret>,
    ) -> Result<Option<SignedOutView>, SessionError> {
        let row = match ticket {
            Some(t) => match self.load_ticket(t, portal_bind, false).await {
                Ok(row) => Some(row),
                Err(e @ SessionError::Store(_)) => return Err(e),
                // Absent: the plain behavior below.
                Err(e) => {
                    tracing::info!(
                        request_id = %ctx.request_id,
                        reason = e.reason().0,
                        "logout ticket ignored"
                    );
                    None
                }
            },
            None => None,
        };
        // The portal handle's own session first (the plain `/logout`).
        self.logout(ctx, portal_handle).await?;
        let Some(row) = row else {
            return Ok(None);
        };
        // Single use, and atomic with the termination of the session the ticket
        // names: the conditional consume arbitrates racing confirmations, and a
        // failure between the two can never leave a consumed ticket beside a
        // live session (a retry still logs out).
        let (session, events) = match &row.portal_session_id {
            Some(id) => match self.sessions.session(id).await? {
                Some(s) if s.terminated_at.is_none() => (
                    Some(s.session_id.clone()),
                    vec![
                        self.ev(ctx, EventKind::SessionTerminated, Outcome::Info)
                            .user(&s.user_id)
                            .session(&s.session_id)
                            .provider(&s.provider_id)
                            .reason(reasons::LOGOUT)
                            .build(),
                    ],
                ),
                _ => (None, vec![]),
            },
            None => (None, vec![]),
        };
        if !self
            .sessions
            .consume_logout_ticket(
                &row.txn_sha256,
                session.as_ref(),
                reasons::LOGOUT,
                self.clock.now(),
                events,
            )
            .await?
        {
            return Ok(None);
        }
        Ok(Some(self.signed_out(&row)))
    }

    /// `GET /signed-out?txn=`: the page the no-confirmation mode redirects to.
    /// The reference is a logout ticket consumed by a logout; readable until
    /// it expires. Nothing is changed.
    pub async fn signed_out_view(&self, txn: &Secret) -> Result<SignedOutView, SessionError> {
        if !is_well_formed_bind(txn.expose()) {
            return Err(SessionError::Refused(reasons::TXN_EXPIRED));
        }
        let Some(row) = self.sessions.transaction(&txn.digest()).await? else {
            return Err(SessionError::Refused(reasons::TXN_EXPIRED));
        };
        if row.purpose != TxnPurpose::Logout {
            return Err(SessionError::Refused(reasons::TXN_PURPOSE_MISMATCH));
        }
        if row.expires_at <= self.clock.now() {
            return Err(SessionError::Refused(reasons::TXN_EXPIRED));
        }
        if row.consumed_reason.as_deref() != Some(reasons::LOGOUT.0) {
            // Not (yet) a completed logout: never claim one.
            return Err(SessionError::Refused(reasons::INVALID_STATE));
        }
        Ok(self.signed_out(&row))
    }
}
