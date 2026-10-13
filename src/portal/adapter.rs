//! The adapter that satisfies [`PortalServices`] with the session service
//! (W1-D) and the provider registry (W1-C). The portal owns transport; this
//! owns the mapping from service results to the portal's typed results and
//! the failure wording (`FailKind`). Nothing here reads a request.

use std::sync::Arc;

use async_trait::async_trait;

use super::ports::*;
use crate::app::Readiness;
use crate::crypto::Secret;
use crate::event::bus::Emitter;
use crate::event::types::{EventKind, Outcome, reasons};
use crate::provider::Registry;
use crate::provider::types::{CallbackQuery, ProviderError, ProviderHealth, ProviderId};
use crate::session::service::{
    self, CallbackOutcome as Cb, LoginEntry, LogoutOutcome, Service, SessionError,
};
use crate::session::switch::{AccountSummary, SwitchChoice as SvcChoice, SwitchOutcome};
use crate::store::{Directory, Events};

/// `PortalServices` over `session::Service` and `provider::Registry`.
struct TotpDeps {
    store: Arc<dyn crate::store::Factors>,
    keys: Arc<crate::factor::keyring::Keyring>,
    clock: Arc<dyn crate::crypto::Clock>,
    rng: Arc<dyn crate::crypto::Rng>,
}
pub struct Adapter {
    totp: Option<TotpDeps>,
    svc: Service,
    registry: Arc<Registry>,
    directory: Arc<dyn Directory>,
    events: Arc<dyn Events>,
    emitter: Emitter,
    readiness: Readiness,
}

impl Adapter {
    pub fn with_totp(
        mut self,
        store: Arc<dyn crate::store::Factors>,
        keys: Arc<crate::factor::keyring::Keyring>,
        clock: Arc<dyn crate::crypto::Clock>,
        rng: Arc<dyn crate::crypto::Rng>,
    ) -> Self {
        self.totp = Some(TotpDeps {
            store,
            keys,
            clock,
            rng,
        });
        self
    }
    fn factor_store_error(error: crate::store::StoreError) -> Failure {
        match error {
            crate::store::StoreError::Conflict(_) | crate::store::StoreError::ProviderDisabled => {
                Self::totp_refusal()
            }
            _ => Failure {
                kind: FailKind::Unavailable,
                reason: reasons::STORE_UNAVAILABLE,
            },
        }
    }
    fn factor_session_error(error: SessionError) -> Failure {
        match error {
            SessionError::Store(error) => Self::factor_store_error(error),
            _ => Self::totp_refusal(),
        }
    }
    fn factor_verification_error(error: crate::factor::service::Error) -> Failure {
        match error {
            crate::factor::service::Error::Store(error) => Self::factor_store_error(error),
            _ => Self::totp_refusal(),
        }
    }
    fn totp_refusal() -> Failure {
        Failure {
            kind: FailKind::Forbidden,
            reason: reasons::INVALID_STATE,
        }
    }

    pub fn new(
        svc: Service,
        registry: Arc<Registry>,
        directory: Arc<dyn Directory>,
        events: Arc<dyn Events>,
        emitter: Emitter,
        readiness: Readiness,
    ) -> Adapter {
        Adapter {
            totp: None,
            svc,
            registry,
            directory,
            events,
            emitter,
            readiness,
        }
    }

    fn sctx(ctx: &RequestCtx) -> service::RequestCtx {
        service::RequestCtx {
            client_ip: ctx.client_ip,
            user_agent: ctx.user_agent.clone(),
            request_id: ctx.request_id.clone(),
            client_request_id: ctx.client_request_id.clone(),
        }
    }

    /// The origin of every enabled provider's authorization endpoint.
    fn provider_origins(&self) -> Vec<url::Origin> {
        self.registry
            .enabled_sorted()
            .iter()
            .filter_map(|p| p.authorization_origin())
            .collect()
    }

    async fn available(&self, id: &ProviderId) -> bool {
        if let Some(provider) = self.registry.credential(id) {
            return provider.enabled();
        }
        match self.registry.get(id) {
            Some(p) => p.enabled() && p.ensure_ready().await == ProviderHealth::Ok,
            None => false,
        }
    }
}

fn failure(e: &SessionError) -> Failure {
    let reason = e.reason();
    let kind = match e {
        SessionError::Store(_) | SessionError::RateLimited { .. } | SessionError::NoProviders => {
            FailKind::Unavailable
        }
        SessionError::AlreadyBound => FailKind::Expired,
        SessionError::Provider(pe) => match pe {
            // A provider server error (5xx), timeout or outage is a
            // server-error page; a refusal the provider reports about the
            // user (4xx, for example a declined consent) is not.
            ProviderError::ProviderError { status } if *status >= 500 => FailKind::Unavailable,
            ProviderError::ProviderTimeout
            | ProviderError::ProviderUnavailable
            | ProviderError::ProviderDisabled
            | ProviderError::DiscoveryIssuerMismatch => FailKind::Unavailable,
            _ => FailKind::Failed,
        },
        SessionError::Refused(r) => {
            if *r == reasons::TXN_EXPIRED
                || *r == reasons::TXN_CONSUMED
                || *r == reasons::TXN_PURPOSE_MISMATCH
                || *r == reasons::TXN_BINDING
            {
                FailKind::Expired
            } else if *r == reasons::PROVIDER_UNAVAILABLE {
                FailKind::Unavailable
            } else if *r == reasons::LOGIN_REQUIRED
                || *r == reasons::SESSION_CONFLICT
                || *r == reasons::SESSION_TERMINATED
            {
                FailKind::Forbidden
            } else {
                FailKind::Failed
            }
        }
        SessionError::Unimplemented => FailKind::Unavailable,
    };
    Failure { kind, reason }
}

/// Every refusal of a CSRF-protected retry is a `403` (R-4); only store and
/// rate-limit trouble is `503`.
fn retry_failure(e: &SessionError) -> Failure {
    let reason = e.reason();
    let kind = match e {
        SessionError::Store(_) | SessionError::RateLimited { .. } => FailKind::Unavailable,
        _ => FailKind::Forbidden,
    };
    Failure { kind, reason }
}

fn redirect(location: url::Url) -> Redirect {
    Redirect {
        location,
        set_handle: None,
    }
}

fn account_label(a: &AccountSummary) -> String {
    a.email
        .as_ref()
        .map(|e| e.as_str().to_string())
        .or_else(|| a.display_name.clone())
        .unwrap_or_else(|| a.user_id.to_string())
}

#[async_trait]
impl PortalServices for Adapter {
    async fn stepup_visit(
        &self,
        ctx: &RequestCtx,
        cookies: &Cookies,
        transaction: &Secret,
    ) -> Result<bool, Failure> {
        if !ctx.https {
            return Err(Self::totp_refusal());
        }
        let deps = self.totp.as_ref().ok_or_else(Self::totp_refusal)?;
        let portal = cookies.bind.as_ref().ok_or_else(Self::totp_refusal)?;
        let (actor, _, generation) = self
            .svc
            .stepup_context(&Self::sctx(ctx), transaction, cookies.handle.as_ref())
            .await
            .map_err(Self::factor_session_error)?;
        if !deps
            .store
            .has_active_totp(actor.user())
            .await
            .map_err(Self::factor_store_error)?
        {
            return Ok(false);
        }
        deps.store
            .bind_totp_stepup(crate::store::BindTotpStepUp {
                actor,
                transaction: transaction.digest(),
                portal_binding: portal.digest(),
                config_generation: Some(generation),
            })
            .await
            .map_err(Self::factor_store_error)?;
        Ok(true)
    }
    async fn stepup_complete(
        &self,
        ctx: &RequestCtx,
        cookies: &Cookies,
        transaction: &Secret,
        code: &Secret,
    ) -> Result<Redirect, Failure> {
        if !ctx.https {
            return Err(Self::totp_refusal());
        }
        let deps = self.totp.as_ref().ok_or_else(Self::totp_refusal)?;
        let portal = cookies.bind.as_ref().ok_or_else(Self::totp_refusal)?;
        let (actor, row, generation) = self
            .svc
            .stepup_context(&Self::sctx(ctx), transaction, cookies.handle.as_ref())
            .await
            .map_err(Self::factor_session_error)?;
        let enrollment = row
            .pending_identity
            .as_ref()
            .and_then(|v| v.get("enrollment_id"))
            .and_then(|v| v.as_str())
            .ok_or_else(Self::totp_refusal)?
            .to_owned();
        let now = deps.clock.now();
        let handle = crate::crypto::handle_value(deps.rng.as_ref());
        let handoff = crate::crypto::random_token(deps.rng.as_ref(), 32);
        let expiry = actor
            .view
            .handle
            .absolute_expires_at
            .min(actor.view.session.absolute_expires_at);
        let portal_handle = crate::store::HandleRow {
            handle_sha256: handle.digest(),
            session_id: actor.view.session.session_id.clone(),
            host: actor.view.handle.host.clone(),
            issued_aal: crate::session::Aal::Two,
            created_at: now,
            last_seen_at: now,
            absolute_expires_at: expiry,
            revoked_at: None,
            revoked_reason: None,
        };
        let handoff_row = crate::store::HandoffCodeRow {
            code_sha256: handoff.digest(),
            session_id: actor.view.session.session_id.clone(),
            host: crate::policy::types::Host::parse(row.return_target.host_str().unwrap_or(""))
                .map_err(|_| Self::totp_refusal())?,
            return_target: row.return_target.clone(),
            client_ip: ctx.client_ip,
            bind_sha256: row.bind_sha256.ok_or_else(Self::totp_refusal)?,
            issued_aal: crate::session::Aal::Two,
            cred_gen: actor
                .view
                .session
                .cred_gen
                .checked_add(1)
                .ok_or_else(Self::totp_refusal)?,
            recovery_depth: row.recovery_depth,
            created_at: now,
            expires_at: now
                .add(std::time::Duration::from_secs(60))
                .min(actor.view.session.absolute_expires_at),
            consumed_at: None,
            consumed_reason: None,
        };
        crate::factor::service::elevate_authorized(
            deps.store.as_ref(),
            &deps.keys,
            deps.clock.as_ref(),
            crate::factor::service::StepUp {
                enrollment: &enrollment,
                actor,
                code,
                transaction: transaction.digest(),
                portal_binding: portal.digest(),
                config_generation: Some(generation),
                portal_handle,
                handoff: handoff_row,
                events: vec![],
            },
        )
        .await
        .map_err(Self::factor_verification_error)?;
        Ok(Redirect {
            location: crate::session::handoff::landing_location(
                &row.return_target,
                handoff.expose(),
            ),
            set_handle: Some(HandleCookie {
                value: handle,
                max_age: expiry.since(now),
            }),
        })
    }
    fn totp_enabled(&self) -> bool {
        self.totp.is_some()
    }
    async fn totp_access(&self, ctx: &RequestCtx, cookies: &Cookies) -> Result<bool, Failure> {
        let deps = self.totp.as_ref().ok_or_else(Self::totp_refusal)?;
        if !ctx.https {
            return Err(Self::totp_refusal());
        }
        let actor = self
            .svc
            .factor_actor(&Self::sctx(ctx), cookies.handle.as_ref())
            .await
            .map_err(|_| Self::totp_refusal())?;
        deps.store
            .has_active_totp(actor.user())
            .await
            .map_err(|_| Failure {
                kind: FailKind::Unavailable,
                reason: reasons::STORE_UNAVAILABLE,
            })
    }
    async fn totp_prepare(
        &self,
        ctx: &RequestCtx,
        cookies: &Cookies,
    ) -> Result<TotpPrepared, Failure> {
        if !ctx.https {
            return Err(Self::totp_refusal());
        }
        let deps = self.totp.as_ref().ok_or_else(Self::totp_refusal)?;
        let actor = self
            .svc
            .factor_actor(&Self::sctx(ctx), cookies.handle.as_ref())
            .await
            .map_err(|_| Self::totp_refusal())?;
        let id = crate::crypto::random_id(deps.rng.as_ref(), "f_");
        let account = actor.user().as_str().to_owned();
        let material = crate::factor::enrollment::prepare_authorized(
            deps.store.as_ref(),
            &deps.keys,
            deps.rng.as_ref(),
            crate::factor::enrollment::AuthorizedRequest {
                id: &id,
                actor,
                issuer: "Hopae",
                account: &account,
            },
            vec![],
        )
        .await
        .map_err(|_| Self::totp_refusal())?;
        Ok(TotpPrepared {
            enrollment: id,
            material,
        })
    }
    async fn totp_confirm(
        &self,
        ctx: &RequestCtx,
        cookies: &Cookies,
        enrollment: &str,
        code: &Secret,
    ) -> Result<(), Failure> {
        if !ctx.https {
            return Err(Self::totp_refusal());
        }
        let deps = self.totp.as_ref().ok_or_else(Self::totp_refusal)?;
        let actor = self
            .svc
            .factor_actor(&Self::sctx(ctx), cookies.handle.as_ref())
            .await
            .map_err(|_| Self::totp_refusal())?;
        crate::factor::service::confirm_authorized(
            deps.store.as_ref(),
            &deps.keys,
            deps.clock.as_ref(),
            enrollment,
            actor,
            code,
            vec![],
        )
        .await
        .map(|_| ())
        .map_err(|_| Self::totp_refusal())
    }

    async fn login_visit(&self, ctx: &RequestCtx, txn: &Secret, cookies: &Cookies) -> LoginVisit {
        let sctx = Self::sctx(ctx);
        match self
            .svc
            .sso_or_chooser(
                &sctx,
                txn,
                cookies.handle.as_ref(),
                cookies.bind.as_ref(),
                false,
            )
            .await
        {
            Ok(LoginEntry::Sso { location, .. }) => LoginVisit::Redirect(redirect(location)),
            Ok(LoginEntry::ReauthProviderUnavailable { provider, sign_out }) => {
                LoginVisit::ReauthProviderUnavailable {
                    provider,
                    sign_out: sign_out.to_string(),
                }
            }
            Ok(LoginEntry::ConfirmNewHost { host, origin }) => LoginVisit::ConfirmNewHost {
                host: host.to_string(),
                form_origin: origin,
            },
            Ok(LoginEntry::Chooser { providers }) => {
                let mut choices = Vec::with_capacity(providers.len());
                for p in providers {
                    let available = self.available(&p.provider_id).await;
                    choices.push(ProviderChoice {
                        id: p.provider_id,
                        display_name: p.display_name,
                        available,
                    });
                }
                // Exactly one provider, and it works: no chooser, straight
                // to the provider (the portal cookie is planted on this
                // response by the handler).
                if let [only] = choices.as_slice()
                    && only.available
                    && self.registry.credential(&only.id).is_none()
                {
                    return match self
                        .svc
                        .begin_provider(&sctx, txn, &only.id, cookies.bind.as_ref())
                        .await
                    {
                        Ok(url) => LoginVisit::Redirect(redirect(url)),
                        Err(e) => LoginVisit::Failed(failure(&e)),
                    };
                }
                LoginVisit::Chooser {
                    providers: choices,
                    form_origins: self.provider_origins(),
                }
            }
            Err(e) => LoginVisit::Failed(failure(&e)),
        }
    }

    async fn begin_provider(
        &self,
        ctx: &RequestCtx,
        txn: &Secret,
        provider: &ProviderId,
        cookies: &Cookies,
    ) -> Result<Redirect, Failure> {
        self.svc
            .begin_provider(&Self::sctx(ctx), txn, provider, cookies.bind.as_ref())
            .await
            .map(redirect)
            .map_err(|e| match &e {
                // A crafted POST for another provider on a reauthentication
                // transaction is a refused action, not a failed sign-in.
                SessionError::Refused(r) if *r == reasons::PROVIDER_MISMATCH => Failure {
                    kind: FailKind::Forbidden,
                    reason: *r,
                },
                _ => failure(&e),
            })
    }

    fn password_provider(&self, provider: &ProviderId) -> bool {
        self.registry.credential(provider).is_some()
    }

    async fn prepare_password(
        &self,
        ctx: &RequestCtx,
        txn: &Secret,
        provider: &ProviderId,
        cookies: &Cookies,
    ) -> Result<super::ports::PasswordChallenge, Failure> {
        let challenge = self
            .svc
            .begin_password(&Self::sctx(ctx), txn, provider, cookies.bind.as_ref())
            .await
            .map_err(|error| failure(&error))?;
        let rows = self.directory.providers().await.map_err(|_| Failure {
            kind: FailKind::Unavailable,
            reason: crate::event::types::reasons::PROVIDER_UNAVAILABLE,
        })?;
        let row = rows
            .into_iter()
            .find(|row| &row.provider_id == provider && row.enabled && row.deleted_at.is_none())
            .ok_or(Failure {
                kind: FailKind::Unavailable,
                reason: crate::event::types::reasons::PROVIDER_DISABLED,
            })?;
        Ok(super::ports::PasswordChallenge {
            provider: provider.clone(),
            provider_name: row.display_name,
            challenge,
        })
    }

    async fn password(
        &self,
        ctx: &RequestCtx,
        submission: super::ports::PasswordSubmission<'_>,
        cookies: &Cookies,
    ) -> CallbackOutcome {
        let input = match crate::provider::credentials::PasswordInput::new(
            submission.username,
            submission.password,
        ) {
            Ok(input) => input,
            Err(_) => {
                return CallbackOutcome::Failed(Failure {
                    kind: FailKind::Failed,
                    reason: crate::event::types::reasons::INVALID_CREDENTIALS,
                });
            }
        };
        match self
            .svc
            .complete_password(
                &Self::sctx(ctx),
                crate::session::service::PasswordCompletion {
                    provider_id: submission.provider,
                    challenge: submission.challenge,
                    input,
                    portal_cookie: cookies.bind.as_ref(),
                    portal_handle: cookies.handle.as_ref(),
                },
            )
            .await
        {
            Ok(Cb::LoggedIn {
                location,
                portal_handle,
                ..
            }) => CallbackOutcome::Redirect(Redirect {
                location,
                set_handle: portal_handle.map(|handle| HandleCookie {
                    value: handle.value,
                    max_age: handle.max_age,
                }),
            }),
            Ok(Cb::LinkRequired { .. }) => CallbackOutcome::LinkNotice { via_provider: None },
            Ok(Cb::Interrupted { .. }) => CallbackOutcome::Failed(Failure {
                kind: FailKind::Failed,
                reason: crate::event::types::reasons::PORTAL_BIND_MISMATCH,
            }),
            Err(error) => CallbackOutcome::Failed(failure(&error)),
        }
    }

    async fn callback(
        &self,
        ctx: &RequestCtx,
        provider: &ProviderId,
        query: CallbackQuery,
        cookies: &Cookies,
    ) -> CallbackOutcome {
        let state = query.state.clone();
        match self
            .svc
            .complete_callback(
                &Self::sctx(ctx),
                provider,
                query,
                cookies.bind.as_ref(),
                cookies.handle.as_ref(),
            )
            .await
        {
            Ok(Cb::LoggedIn {
                location,
                portal_handle,
                ..
            }) => CallbackOutcome::Redirect(Redirect {
                location,
                set_handle: portal_handle.map(|h| HandleCookie {
                    value: h.value,
                    max_age: h.max_age,
                }),
            }),
            Ok(Cb::LinkRequired { .. }) => CallbackOutcome::LinkNotice { via_provider: None },
            Ok(Cb::Interrupted { retry_allowed, .. }) => {
                let form_origin = match (&state, retry_allowed) {
                    (Some(s), true) => self.svc.retry_form_origin(s).await,
                    _ => None,
                };
                CallbackOutcome::RetryOffer {
                    can_retry: retry_allowed,
                    form_origin,
                }
            }
            Err(e) => CallbackOutcome::Failed(failure(&e)),
        }
    }

    async fn retry(
        &self,
        ctx: &RequestCtx,
        state: &str,
        cookies: &Cookies,
    ) -> Result<Redirect, Failure> {
        self.svc
            .retry_by_state(&Self::sctx(ctx), state, cookies.bind.as_ref())
            .await
            .map(|o| redirect(o.location))
            .map_err(|e| retry_failure(&e))
    }

    async fn continue_sso(
        &self,
        ctx: &RequestCtx,
        txn: &Secret,
        cookies: &Cookies,
    ) -> Result<Redirect, Failure> {
        match self
            .svc
            .sso_or_chooser(
                &Self::sctx(ctx),
                txn,
                cookies.handle.as_ref(),
                cookies.bind.as_ref(),
                true,
            )
            .await
        {
            Ok(LoginEntry::Sso { location, .. }) => Ok(redirect(location)),
            // The confirmation only applies to single sign-on; with no valid
            // portal session there is nothing to continue.
            Ok(_) => Err(Failure {
                kind: FailKind::Forbidden,
                reason: reasons::LOGIN_REQUIRED,
            }),
            Err(e) => Err(failure(&e)),
        }
    }

    async fn switch_view(
        &self,
        ctx: &RequestCtx,
        txn: &Secret,
        cookies: &Cookies,
    ) -> Result<SwitchView, Failure> {
        let v = self
            .svc
            .switch_view(
                &Self::sctx(ctx),
                txn,
                cookies.bind.as_ref(),
                cookies.handle.as_ref(),
            )
            .await
            .map_err(|e| failure(&e))?;
        Ok(SwitchView {
            host: v.host.to_string(),
            current_account: v.current.as_ref().map(account_label).unwrap_or_default(),
            incoming_account: account_label(&v.incoming),
            form_origin: v.origin,
        })
    }

    async fn switch_confirm(
        &self,
        ctx: &RequestCtx,
        txn: &Secret,
        choice: SwitchChoice,
        cookies: &Cookies,
    ) -> Result<Redirect, Failure> {
        let choice = match choice {
            SwitchChoice::Switch => SvcChoice::Switch,
            SwitchChoice::Keep => SvcChoice::Keep,
        };
        match self
            .svc
            .switch_confirm(
                &Self::sctx(ctx),
                txn,
                choice,
                cookies.handle.as_ref(),
                cookies.bind.as_ref(),
            )
            .await
        {
            Ok(SwitchOutcome::Switched { location } | SwitchOutcome::Kept { location }) => {
                Ok(redirect(location))
            }
            Err(e) => Err(failure(&e)),
        }
    }

    async fn logout(&self, ctx: &RequestCtx, handle: &Secret) -> Result<bool, Failure> {
        match self.svc.logout(&Self::sctx(ctx), Some(handle)).await {
            Ok(LogoutOutcome::SignedOut { .. }) => Ok(true),
            Ok(LogoutOutcome::NoSession) => Ok(false),
            Err(e) => Err(failure(&e)),
        }
    }

    async fn logout_visit(
        &self,
        ctx: &RequestCtx,
        txn: &Secret,
        cookies: &Cookies,
    ) -> Option<String> {
        match self.svc.logout_visit(txn, cookies.bind.as_ref()).await {
            Ok(name) => Some(name),
            Err(e) => {
                tracing::info!(
                    request_id = %ctx.request_id,
                    reason = e.reason().0,
                    "logout ticket ignored"
                );
                None
            }
        }
    }

    async fn logout_with_ticket(
        &self,
        ctx: &RequestCtx,
        txn: &Secret,
        cookies: &Cookies,
    ) -> Result<Option<SignedOutPage>, Failure> {
        self.svc
            .logout_confirmed(
                &Self::sctx(ctx),
                cookies.handle.as_ref(),
                Some(txn),
                cookies.bind.as_ref(),
            )
            .await
            .map(|v| {
                v.map(|v| SignedOutPage {
                    app_name: v.app_name,
                    sign_in: v.sign_in,
                })
            })
            .map_err(|e| failure(&e))
    }

    async fn signed_out(&self, _ctx: &RequestCtx, txn: &Secret) -> Result<SignedOutPage, Failure> {
        self.svc
            .signed_out_view(txn)
            .await
            .map(|v| SignedOutPage {
                app_name: v.app_name,
                sign_in: v.sign_in,
            })
            .map_err(|e| failure(&e))
    }

    async fn csrf_rejected(&self, ctx: &RequestCtx, purpose: &'static str, cause: &'static str) {
        let ev = self.emitter.required(
            EventKind::CsrfRejected,
            Outcome::Failure,
            ctx.request_id.clone(),
            |b| {
                self.emitter
                    .with_client_request_id(b, ctx.client_request_id.as_deref())
                    .ip(ctx.client_ip)
                    .ua(ctx.user_agent.as_deref())
                    .reason(reasons::CSRF_REJECTED)
                    .attr("purpose", purpose)
                    .attr("cause", cause)
            },
        );
        if let Err(e) = self.events.append_required(vec![ev]).await {
            tracing::warn!(error = %e, "csrf.rejected could not be recorded");
        }
    }

    async fn health(&self) -> Health {
        // Ready only after startup finished; the store must also answer now.
        let store_ok =
            self.readiness.is_ready() && self.directory.config_generation().await.is_ok();
        let mut providers = Vec::new();
        for p in self.registry.all_sorted() {
            providers.push((p.id().clone(), p.health().await));
        }
        Health {
            store_ok,
            providers,
        }
    }
}
