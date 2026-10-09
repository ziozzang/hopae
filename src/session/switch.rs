//! The account switch (ADR-0004 "Account switch", S003-A10, S006-5): after a
//! `session_conflict` the browser may replace the other user's handle on the
//! application host, but only by an explicit, CSRF-protected confirmation.
//! Nothing switches silently.

use url::Url;

use crate::crypto::{Secret, ct_eq, is_well_formed_bind};
use crate::event::types::{EventKind, Outcome, reasons};
use crate::identity::types::{NormalizedEmail, UserId};
use crate::policy::types::Host;
use crate::session::handoff::MintRequest;
use crate::session::service::{RequestCtx, Service, SessionError, host_of};
use crate::store::StoreError;
use crate::store::types::{SessionRow, TransactionRow, TxnPurpose};

/// What the confirmation page shows about an account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountSummary {
    pub user_id: UserId,
    pub email: Option<NormalizedEmail>,
    pub display_name: Option<String>,
}

#[derive(Clone, Debug)]
pub struct SwitchView {
    pub host: Host,
    /// The account whose handle the application host holds now (None when that handle is gone).
    pub current: Option<AccountSummary>,
    /// The account the portal session belongs to.
    pub incoming: AccountSummary,
    /// Origin of the return target (the confirmation page's `form-action`).
    pub origin: url::Origin,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SwitchChoice {
    Switch,
    Keep,
}

#[derive(Debug)]
pub enum SwitchOutcome {
    /// The other handle is revoked; `location` is the target with a fresh code.
    Switched { location: Url },
    /// Declined: back to the clean target as the existing user.
    Kept { location: Url },
}

fn summary(s: &SessionRow) -> AccountSummary {
    AccountSummary {
        user_id: s.user_id.clone(),
        email: s.snapshot.email.clone(),
        display_name: s.snapshot.display_name.clone(),
    }
}

impl Service {
    /// Bind the switch transaction to the browser that opened it, or check
    /// the browser against the recorded binding (ADR-0004: the portal cookie
    /// of the incoming session's browser). The first visit that holds the
    /// incoming session's portal handle records the digest of its portal
    /// cookie, once; every later visit and every submission must present
    /// that cookie. Nothing is consumed here.
    async fn check_switch_binding(
        &self,
        ctx: &RequestCtx,
        row: &TransactionRow,
        portal_bind: Option<&Secret>,
        portal_handle: Option<&Secret>,
        establish: bool,
    ) -> Result<(), SessionError> {
        let bind = portal_bind
            .filter(|b| is_well_formed_bind(b.expose()))
            .ok_or(SessionError::Refused(reasons::PORTAL_BIND_MISMATCH))?;
        let digest = bind.digest();
        let matches = |recorded: &crate::crypto::Digest| ct_eq(&recorded.0, &digest.0);
        if let Some(recorded) = &row.portal_bind_sha256 {
            return if matches(recorded) {
                Ok(())
            } else {
                Err(SessionError::Refused(reasons::PORTAL_BIND_MISMATCH))
            };
        }
        if !establish {
            // Never bound: no browser has opened the confirmation page.
            return Err(SessionError::Refused(reasons::PORTAL_BIND_MISMATCH));
        }
        let view = self
            .portal_session(ctx, portal_handle)
            .await?
            .ok_or(SessionError::Refused(reasons::LOGIN_REQUIRED))?;
        if Some(&view.session.session_id) != row.portal_session_id.as_ref() {
            return Err(SessionError::Refused(reasons::SESSION_CONFLICT));
        }
        if self
            .sessions
            .bind_switch_transaction(&row.txn_sha256, digest)
            .await?
        {
            return Ok(());
        }
        // Lost a race with another visit: the recorded binding decides.
        let now = self
            .sessions
            .transaction(&row.txn_sha256)
            .await?
            .ok_or(SessionError::Refused(reasons::TXN_EXPIRED))?;
        match &now.portal_bind_sha256 {
            Some(recorded) if matches(recorded) => Ok(()),
            _ => Err(SessionError::Refused(reasons::PORTAL_BIND_MISMATCH)),
        }
    }

    /// `GET /switch?txn=`: names the host and both accounts. The only state
    /// change is recording the browser binding of the transaction.
    pub async fn switch_view(
        &self,
        ctx: &RequestCtx,
        txn: &Secret,
        portal_bind: Option<&Secret>,
        portal_handle: Option<&Secret>,
    ) -> Result<SwitchView, SessionError> {
        let row = self.load_switch_txn(txn).await?;
        self.check_switch_binding(ctx, &row, portal_bind, portal_handle, true)
            .await?;
        let host = host_of(&row.return_target)?;
        let incoming = self.incoming_session(&row).await?;
        let current = match row.conflicting_handle_sha256 {
            Some(d) => self
                .sessions
                .lookup_handle(&d, &host)
                .await?
                .filter(|v| v.handle.revoked_at.is_none() && v.session.terminated_at.is_none())
                .map(|v| summary(&v.session)),
            None => None,
        };
        Ok(SwitchView {
            host,
            current,
            incoming: summary(&incoming),
            origin: row.return_target.origin(),
        })
    }

    /// `POST /switch`: confirm or decline. Confirming requires the portal
    /// handle of the session the burned code was for; it revokes the handle
    /// the browser presented on the application host (`handle.revoked`,
    /// reason `switch`) and mints a fresh code for the new session bound to
    /// the same application-host binding cookie. The portal's CSRF token and
    /// `Origin` checks come first.
    pub async fn switch_confirm(
        &self,
        ctx: &RequestCtx,
        txn: &Secret,
        choice: SwitchChoice,
        portal_handle: Option<&Secret>,
        portal_bind: Option<&Secret>,
    ) -> Result<SwitchOutcome, SessionError> {
        let row = self.load_switch_txn(txn).await?;
        // Before either choice can consume the transaction: the submission
        // must come from the browser the transaction was bound to.
        self.check_switch_binding(ctx, &row, portal_bind, portal_handle, false)
            .await?;
        let host = host_of(&row.return_target)?;
        let now = self.clock.now();

        // Confirming needs the incoming account's own portal session.
        let portal = match choice {
            SwitchChoice::Switch => {
                let view = self
                    .portal_session(ctx, portal_handle)
                    .await?
                    .ok_or(SessionError::Refused(reasons::LOGIN_REQUIRED))?;
                if Some(&view.session.session_id) != row.portal_session_id.as_ref() {
                    return Err(SessionError::Refused(reasons::SESSION_CONFLICT));
                }
                Some(view)
            }
            SwitchChoice::Keep => None,
        };

        // The transaction is single use: the conditional consume arbitrates.
        let reason = match choice {
            SwitchChoice::Switch => reasons::SWITCH,
            SwitchChoice::Keep => reasons::REPLACED,
        };
        if !self
            .sessions
            .consume_transaction(&row.txn_sha256, reason, now, vec![])
            .await?
        {
            return Err(SessionError::Refused(reasons::TXN_CONSUMED));
        }
        let Some(portal) = portal else {
            return Ok(SwitchOutcome::Kept {
                location: row.return_target,
            });
        };

        let bind = row
            .bind_sha256
            .ok_or(SessionError::Refused(reasons::TXN_BINDING))?;
        if let Some(d) = row.conflicting_handle_sha256 {
            let old = self.sessions.lookup_handle(&d, &host).await?;
            let mut event = self
                .ev(ctx, EventKind::HandleRevoked, Outcome::Success)
                .app(&row.app_id)
                .reason(reasons::SWITCH)
                .attr("host", host.as_str())
                .attr("to_user_id", portal.session.user_id.to_string());
            if let Some(v) = &old {
                event = event
                    .user(&v.session.user_id)
                    .session(&v.session.session_id)
                    .attr("from_user_id", v.session.user_id.to_string());
            }
            match self
                .sessions
                .revoke_handle(&d, reasons::SWITCH, now, vec![event.build()])
                .await
            {
                // Already gone (expired and swept, or revoked by logout): nothing to revoke.
                Ok(()) | Err(StoreError::Conflict(_)) => {}
                Err(e) => return Err(e.into()),
            }
        }
        let minted = self
            .mint_handoff(MintRequest {
                session_id: portal.session.session_id.clone(),
                aal_cap: portal.handle.issued_aal,
                target: row.return_target.clone(),
                client_ip: row.client_ip,
                bind_sha256: bind,
                recovery_depth: row.recovery_depth,
                events: vec![],
            })
            .await?;
        Ok(SwitchOutcome::Switched {
            location: minted.location,
        })
    }

    async fn load_switch_txn(&self, txn: &Secret) -> Result<TransactionRow, SessionError> {
        if !is_well_formed_bind(txn.expose()) {
            return Err(SessionError::Refused(reasons::TXN_EXPIRED));
        }
        let row = self.load_live_txn_quiet(txn).await?;
        if row.purpose != TxnPurpose::Switch {
            return Err(SessionError::Refused(reasons::INVALID_STATE));
        }
        Ok(row)
    }

    async fn incoming_session(&self, row: &TransactionRow) -> Result<SessionRow, SessionError> {
        let id = row
            .portal_session_id
            .as_ref()
            .ok_or(SessionError::Refused(reasons::INVALID_STATE))?;
        self.sessions
            .session(id)
            .await?
            .filter(|s| s.terminated_at.is_none())
            .ok_or(SessionError::Refused(reasons::SESSION_TERMINATED))
    }
}
