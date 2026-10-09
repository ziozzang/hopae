//! Login transactions: creation (Flow 1), per-IP caps and eviction, and the
//! portal retry after a first-use cookie race (ADR-0004).

use url::Url;

use crate::crypto::{Digest, Secret, ct_eq, is_well_formed_bind, random_token};
use crate::event::types::{EventKind, Outcome, reasons};
use crate::policy::types::AppId;
use crate::provider::types::ProviderId;
use crate::session::service::{
    COUNTER_WINDOW, RequestCtx, Service, SessionError, TXN_LIFETIME, host_of,
};
use crate::store::types::{NewTransaction, TransactionRow, TxnPurpose};
use crate::verify::types::BindAction;

/// A created login transaction. `transaction` is the bearer id for
/// `/login?txn=`; `bind` says whether the response plants the application
/// host's binding cookie or keeps the one the browser presented.
pub struct StartedLogin {
    pub transaction: Secret,
    pub bind: BindAction,
    pub app_id: AppId,
}

impl std::fmt::Debug for StartedLogin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StartedLogin")
            .field("app_id", &self.app_id)
            .field(
                "bind",
                &match self.bind {
                    BindAction::Keep => "keep",
                    BindAction::Plant(_) => "plant",
                },
            )
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub struct RetryOutcome {
    /// The provider authorization URL of the new transaction.
    pub location: Url,
}

/// The reserved handoff parameter (ADR-0004).
pub const HANDOFF_PARAM: &str = "_hopae_handoff";

impl Service {
    /// Create the transaction that starts a login for `return_target`
    /// (Flow 1, document navigations only; the caller creates nothing for a
    /// `401`). The target is re-validated here against the return-origin
    /// allowlist, so a caller bug cannot create an open redirect.
    ///
    /// `presented_bind` is the application host's binding cookie as received:
    /// a well-formed value is kept (and its `Max-Age` refreshed by the
    /// caller), anything else is replaced by a fresh one. `recovery_depth` is
    /// 0 for a fresh login and is only ever taken from a burned code's row.
    pub async fn start_login(
        &self,
        ctx: &RequestCtx,
        return_target: &Url,
        presented_bind: Option<&Secret>,
        recovery_depth: u32,
    ) -> Result<StartedLogin, SessionError> {
        let now = self.clock.now();
        let snap = self.snapshot.load_full();
        let host = self.validate_target(return_target)?;
        let app = snap
            .app_for_host(&host)
            .ok_or(SessionError::Refused(reasons::UNKNOWN_APP))?;
        if !app.enabled {
            return Err(SessionError::Refused(reasons::APP_DISABLED));
        }
        let port = return_target.port_or_known_default().unwrap_or(0);
        if !snap.return_origin_allowed(&host, port) {
            return Err(SessionError::Refused(reasons::PORT_NOT_ALLOWED));
        }

        // Per-IP cap, then room for one more row.
        let recent = self
            .sessions
            .count_transactions_since(ctx.client_ip, now.sub(COUNTER_WINDOW))
            .await?;
        if recent >= self.cfg.txn_per_ip_per_minute {
            return Err(SessionError::RateLimited {
                retry_after: COUNTER_WINDOW,
            });
        }
        self.make_room(ctx, &app.app_id).await?;

        let (bind, action) = match presented_bind.filter(|b| is_well_formed_bind(b.expose())) {
            Some(b) => (b.digest(), BindAction::Keep),
            None => {
                let fresh = random_token(&*self.rng, 16);
                (fresh.digest(), BindAction::Plant(fresh))
            }
        };
        let txn = random_token(&*self.rng, 16);
        let mut started = self
            .ev(ctx, EventKind::LoginStarted, Outcome::Info)
            .app(&app.app_id)
            .attr("host", host.as_str());
        if recovery_depth > 0 {
            started = started.attr("recovery_depth", recovery_depth);
        }
        self.sessions
            .create_transaction(
                NewTransaction {
                    txn_sha256: txn.digest(),
                    created_at: now,
                    expires_at: now.add(TXN_LIFETIME),
                    app_id: app.app_id.clone(),
                    return_target: return_target.clone(),
                    bind_sha256: Some(bind),
                    portal_bind_sha256: None,
                    retry_bind_sha256: None,
                    client_ip: ctx.client_ip,
                    ua_sha256: self.ua_digest(ctx),
                    provider_id: None,
                    state_sha256: None,
                    nonce: None,
                    pkce_verifier: None,
                    portal_session_id: None,
                    purpose: TxnPurpose::Login,
                    conflicting_handle_sha256: None,
                    pending_identity: None,
                    recovery_depth,
                },
                vec![started.build()],
            )
            .await?;
        Ok(StartedLogin {
            transaction: txn,
            bind: action,
            app_id: app.app_id.clone(),
        })
    }

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
            let ev = self
                .ev(ctx, EventKind::TxnEvicted, Outcome::Info)
                .app(app)
                .reason(reasons::TXN_EVICTED)
                .attr("count", evicted)
                .build();
            let _ = self.events.append_diagnostic(ev).await;
        }
        Ok(())
    }

    /// Shape checks of ADR-0004 "Return target" that do not need the snapshot.
    fn validate_target(&self, url: &Url) -> Result<crate::policy::types::Host, SessionError> {
        let refuse = |r| Err(SessionError::Refused(r));
        match url.scheme() {
            "https" => {}
            "http" if !self.cfg.secure => {}
            _ => return refuse(reasons::SCHEME),
        }
        if !url.username().is_empty() || url.password().is_some() {
            return refuse(reasons::USERINFO);
        }
        if url.fragment().is_some() {
            return refuse(reasons::FRAGMENT);
        }
        if url.as_str().len() > 2048 {
            return refuse(reasons::TOO_LONG);
        }
        if url.query_pairs().any(|(k, _)| k == HANDOFF_PARAM) {
            return refuse(reasons::HANDOFF_PARAMETER_NOT_ALLOWED);
        }
        host_of(url)
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
