//! Login transactions on the portal side: eviction room and the single-use
//! portal retry after a first-use cookie race (ADR-0004). The unauthenticated
//! `302` and its transaction belong to the verify engine (ruling R-1).

use url::Url;

use crate::crypto::{Digest, Secret, ct_eq, is_well_formed_bind, random_token};
use crate::event::types::{EventKind, Outcome, reasons};
use crate::policy::types::AppId;
use crate::provider::types::ProviderId;
use crate::session::service::{COUNTER_WINDOW, RequestCtx, Service, SessionError, TXN_LIFETIME};
use crate::store::types::{NewTransaction, TransactionRow, TxnPurpose};

#[derive(Debug)]
pub struct RetryOutcome {
    /// The provider authorization URL of the new transaction.
    pub location: Url,
}

pub use crate::gateway::recognition::HANDOFF_PARAM;

impl Service {
    /// `txn.max_rows`: evict so that one more row fits (dead rows first,
    /// then the oldest), and report the eviction as a diagnostic.
    pub(crate) async fn make_room(
        &self,
        ctx: &RequestCtx,
        app: &AppId,
    ) -> Result<(), SessionError> {
        let evicted = self
            .sessions
            .evict_transactions(self.cfg.txn_max_rows.saturating_sub(1), self.clock.now())
            .await?;
        if evicted > 0 {
            self.emitter
                .diagnostic(EventKind::TxnEvicted, Outcome::Info, &ctx.request_id, |b| {
                    b.app(app)
                        .reason(reasons::TXN_EVICTED)
                        .attr("count", evicted)
                });
        }
        Ok(())
    }

    /// `POST /login/retry` addressed by the callback's `state`, which is how
    /// the interrupted page names the consumed transaction.
    pub async fn retry_by_state(
        &self,
        ctx: &RequestCtx,
        state: &str,
        portal_cookie: Option<&Secret>,
    ) -> Result<RetryOutcome, SessionError> {
        let found = self
            .sessions
            .transaction_by_state(&crate::crypto::sha256(state.as_bytes()))
            .await?
            .ok_or(SessionError::Refused(reasons::TXN_EXPIRED))?;
        self.retry(ctx, &found.txn_sha256, portal_cookie).await
    }

    /// The origin of the transaction's provider flow, for the interrupted
    /// page's `form-action` (from the provider registry, never request input).
    pub async fn retry_form_origin(&self, state: &str) -> Option<url::Origin> {
        let txn = self
            .sessions
            .transaction_by_state(&crate::crypto::sha256(state.as_bytes()))
            .await
            .ok()??;
        self.providers
            .get(txn.provider_id.as_ref()?)?
            .authorization_origin()
    }

    /// `POST /login/retry`: after a callback consumed a transaction with
    /// `portal_bind_mismatch`, start a new transaction for the same return
    /// target at `recovery_depth + 1` and redirect to the provider again,
    /// recording the replacement cookie's digest at that redirect.
    ///
    /// The portal's CSRF token and `Origin` checks come first. Here: the
    /// referenced transaction must have failed with `portal_bind_mismatch`,
    /// its recorded `retry_bind_sha256` must equal the presented cookie's
    /// digest (not the original digest), and the depth is bounded by
    /// `handoff.max_recoveries`.
    pub async fn retry(
        &self,
        ctx: &RequestCtx,
        retry_ref: &Digest,
        portal_cookie: Option<&Secret>,
    ) -> Result<RetryOutcome, SessionError> {
        let now = self.clock.now();
        let old: TransactionRow = self
            .sessions
            .transaction(retry_ref)
            .await?
            .ok_or(SessionError::Refused(reasons::TXN_EXPIRED))?;
        if old.consumed_reason.as_deref() != Some(reasons::PORTAL_BIND_MISMATCH.0) {
            return Err(SessionError::Refused(reasons::PORTAL_BIND_MISMATCH));
        }
        let cookie = portal_cookie
            .filter(|c| is_well_formed_bind(c.expose()))
            .ok_or(SessionError::Refused(reasons::PORTAL_BIND_MISMATCH))?;
        let expected = old
            .retry_bind_sha256
            .ok_or(SessionError::Refused(reasons::PORTAL_BIND_MISMATCH))?;
        if !ct_eq(&cookie.digest().0, &expected.0) {
            return Err(SessionError::Refused(reasons::PORTAL_BIND_MISMATCH));
        }
        if old.expires_at <= now {
            return Err(SessionError::Refused(reasons::TXN_EXPIRED));
        }
        if old.recovery_depth >= self.cfg.max_recoveries {
            return Err(SessionError::Refused(reasons::HANDOFF_RECOVERY_EXHAUSTED));
        }
        // Single use per consumed transaction (R-4): the first POST wins, a
        // replay is refused whatever its cookie and token.
        if !self.sessions.use_retry(retry_ref, now).await? {
            return Err(SessionError::Refused(reasons::TXN_CONSUMED));
        }
        let provider: ProviderId = old
            .provider_id
            .clone()
            .ok_or(SessionError::Refused(reasons::INVALID_STATE))?;

        let recent = self
            .sessions
            .count_transactions_since(ctx.client_ip, now.sub(COUNTER_WINDOW))
            .await?;
        if recent >= self.cfg.txn_per_ip_per_minute {
            return Err(SessionError::RateLimited {
                retry_after: COUNTER_WINDOW,
            });
        }
        self.make_room(ctx, &old.app_id).await?;

        let depth = old.recovery_depth + 1;
        let txn = random_token(&*self.rng, 16);
        let started = self
            .ev(ctx, EventKind::LoginStarted, Outcome::Info)
            .app(&old.app_id)
            .attr("recovery_depth", depth)
            .build();
        let new_row = NewTransaction {
            txn_sha256: txn.digest(),
            created_at: now,
            expires_at: now.add(TXN_LIFETIME),
            app_id: old.app_id.clone(),
            return_target: old.return_target.clone(),
            bind_sha256: old.bind_sha256,
            portal_bind_sha256: None,
            retry_bind_sha256: None,
            client_ip: old.client_ip,
            ua_sha256: old.ua_sha256,
            provider_id: None,
            state_sha256: None,
            nonce: None,
            pkce_verifier: None,
            portal_session_id: None,
            purpose: TxnPurpose::Login,
            conflicting_handle_sha256: None,
            pending_identity: None,
            recovery_depth: depth,
        };
        self.sessions
            .create_transaction(new_row, vec![started])
            .await?;
        let fresh = self
            .sessions
            .transaction(&txn.digest())
            .await?
            .ok_or(SessionError::Refused(reasons::INVALID_STATE))?;
        let location = self
            .begin_provider_for(ctx, &fresh, &provider, cookie)
            .await?;
        Ok(RetryOutcome { location })
    }
}
