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
pub struct Adapter {
    svc: Service,
    registry: Arc<Registry>,
    directory: Arc<dyn Directory>,
    events: Arc<dyn Events>,
    emitter: Emitter,
    readiness: Readiness,
}

impl Adapter {
    pub fn new(
        svc: Service,
        registry: Arc<Registry>,
        directory: Arc<dyn Directory>,
        events: Arc<dyn Events>,
        emitter: Emitter,
        readiness: Readiness,
    ) -> Adapter {
        Adapter {
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
            .map_err(|e| failure(&e))
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
