//! The identity service: maps a validated provider assertion to a Hopae user
//! per the linking policy (ADR-0011). `resolve` only reads; `apply` performs
//! the one write the decision calls for. Splitting them lets the session
//! service consume the login transaction (the single-use arbiter) between the
//! decision and any write.

use std::net::IpAddr;
use std::sync::Arc;

use crate::crypto::{Clock, Rng};
use crate::event::types::{EventBuilder, EventKind, Outcome, Reason, reasons};
use crate::identity::email::{domain_allowed, new_identity};
use crate::identity::linking::{LinkDecision, LinkingPolicy, decide_unknown_identity};
use crate::identity::types::{NormalizedEmail, UserId};
use crate::policy::types::AppId;
use crate::provider::types::{ProviderId, ProviderIdentity};
use crate::session::types::SessionId;
use crate::store::types::{NewIdentity, NewUser, ProviderRow, User, UserStatus};
use crate::store::{Directory, StoreError, StoreResult};

/// An identity waiting for a fresh authentication to the account that owns its
/// email (purpose `link`, stored in the transaction). No raw claims, tokens or
/// the other account's details are kept.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PendingIdentity {
    pub provider_id: ProviderId,
    pub subject: String,
    pub email: Option<NormalizedEmail>,
    pub email_verified: bool,
    pub email_authoritative: bool,
    pub name: Option<String>,
    pub username: Option<String>,
    pub picture: Option<String>,
    /// The account the identity would join after a fresh authentication.
    pub existing_user_id: UserId,
}

/// The decision for one provider assertion. Nothing has been written.
#[derive(Clone, Debug)]
pub enum Resolution {
    /// The identity exists; use its user.
    ExistingUser {
        user: User,
    },
    /// No account has this identity: create one.
    NewUser {
        user: NewUser,
        identity: NewIdentity,
        /// `linking.on_conflict = separate` produced an account without a
        /// primary email; the portal shows the notice.
        notice_separate: bool,
    },
    /// The email belongs to another account: store the pending identity and
    /// require a fresh authentication there (default).
    LinkRequired {
        pending: PendingIdentity,
    },
    /// Authoritative-email opt-in: attach to `user`.
    AutoLinked {
        user: User,
        identity: NewIdentity,
    },
    Denied(Reason),
}

/// The user a login resolved to, after `apply`.
#[derive(Clone, Debug)]
pub struct ResolvedUser {
    pub user: User,
    pub created: bool,
    pub auto_linked: bool,
    pub notice_separate: bool,
}

/// Request facts for the events `apply` writes.
#[derive(Clone, Debug)]
pub struct EventCtx {
    pub request_id: String,
    pub client_ip: IpAddr,
    pub user_agent: Option<String>,
    pub app_id: Option<AppId>,
    pub session_id: Option<SessionId>,
    /// The client's `x-request-id`, recorded only under `log.accept_client_request_id`.
    pub client_request_id: Option<String>,
}

#[derive(Clone)]
pub struct Service {
    directory: Arc<dyn Directory>,
    clock: Arc<dyn Clock>,
    rng: Arc<dyn Rng>,
    policy: LinkingPolicy,
    /// Counts the required events it builds (and tells the prune trigger).
    emitter: Option<crate::event::bus::Emitter>,
}

impl Service {
    pub fn new(
        directory: Arc<dyn Directory>,
        clock: Arc<dyn Clock>,
        rng: Arc<dyn Rng>,
        policy: LinkingPolicy,
    ) -> Self {
        Service {
            directory,
            clock,
            rng,
            policy,
            emitter: None,
        }
    }

    /// The same service counting the required events it builds through `emitter`.
    pub fn with_emitter(mut self, emitter: crate::event::bus::Emitter) -> Self {
        self.emitter = Some(emitter);
        self
    }

    pub fn policy(&self) -> LinkingPolicy {
        self.policy
    }

    /// ADR-0011 table. The domain allowlist comes first, then the identity
    /// lookup, then the email policy.
    pub async fn resolve(
        &self,
        ident: &ProviderIdentity,
        provider: &ProviderRow,
    ) -> StoreResult<Resolution> {
        // A non-empty allowlist is an admission policy on a mailbox the user
        // owns: an address the provider did not verify proves nothing (G7-IDP-02).
        let admitted_email = ident.email.as_ref().filter(|_| ident.email_verified);
        if !domain_allowed(admitted_email, &provider.allowed_email_domains) {
            return Ok(Resolution::Denied(reasons::EMAIL_DOMAIN_NOT_ALLOWED));
        }
        if let Some(row) = self
            .directory
            .identity(&provider.provider_id, &ident.subject)
            .await?
        {
            let user = self
                .directory
                .user(&row.user_id)
                .await?
                .ok_or_else(|| StoreError::Corrupt("identity without user".into()))?;
            if user.status != UserStatus::Active {
                return Ok(Resolution::Denied(reasons::USER_DISABLED));
            }
            return Ok(Resolution::ExistingUser { user });
        }
        let owner = match &ident.email {
            Some(email) => self.directory.user_by_email(email).await?,
            None => None,
        };
        let identity = new_identity(&provider.provider_id, ident);
        Ok(
            match decide_unknown_identity(self.policy, provider, ident, owner.as_ref()) {
                LinkDecision::Create { primary_email } => Resolution::NewUser {
                    user: new_user(ident, primary_email),
                    identity,
                    notice_separate: false,
                },
                LinkDecision::CreateSeparate => Resolution::NewUser {
                    user: new_user(ident, false),
                    identity,
                    notice_separate: true,
                },
                LinkDecision::LinkRequired => {
                    let existing = owner.ok_or_else(|| {
                        StoreError::Corrupt("link decision without an owner".into())
                    })?;
                    Resolution::LinkRequired {
                        pending: PendingIdentity {
                            provider_id: provider.provider_id.clone(),
                            subject: ident.subject.clone(),
                            email: ident.email.clone(),
                            email_verified: ident.email_verified,
                            email_authoritative: ident.email_authoritative,
                            name: ident.name.clone(),
                            username: ident.username.clone(),
                            picture: ident.picture.clone(),
                            existing_user_id: existing.user_id,
                        },
                    }
                }
                LinkDecision::AutoLink => {
                    let user = owner.ok_or_else(|| {
                        StoreError::Corrupt("link decision without an owner".into())
                    })?;
                    if user.status != UserStatus::Active {
                        Resolution::Denied(reasons::USER_DISABLED)
                    } else {
                        Resolution::AutoLinked { user, identity }
                    }
                }
                LinkDecision::Deny(r) => Resolution::Denied(r),
            },
        )
    }

    /// Perform the write a `Resolution` calls for. `LinkRequired` and `Denied`
    /// are not applicable and return `Ok(None)`.
    pub async fn apply(
        &self,
        resolution: Resolution,
        provider: &ProviderRow,
        ident: &ProviderIdentity,
        ctx: &EventCtx,
    ) -> StoreResult<Option<ResolvedUser>> {
        let now = self.clock.now();
        match resolution {
            Resolution::ExistingUser { user } => {
                let seen = new_identity(&provider.provider_id, ident);
                self.directory
                    .touch_identity(&provider.provider_id, &ident.subject, &seen, now)
                    .await?;
                Ok(Some(ResolvedUser {
                    user,
                    created: false,
                    auto_linked: false,
                    notice_separate: false,
                }))
            }
            Resolution::NewUser {
                user,
                identity,
                notice_separate,
            } => {
                let user = self.directory.create_user(user, identity, vec![]).await?;
                Ok(Some(ResolvedUser {
                    user,
                    created: true,
                    auto_linked: false,
                    notice_separate,
                }))
            }
            Resolution::AutoLinked { user, identity } => {
                let event = self
                    .event(EventKind::IdentityLinked, Outcome::Success, ctx)
                    .user(&user.user_id)
                    .provider(&provider.provider_id)
                    .reason(reasons::AUTHORITATIVE_EMAIL)
                    .build();
                self.directory
                    .link_identity(&user.user_id, identity, vec![event])
                    .await?;
                Ok(Some(ResolvedUser {
                    user,
                    created: false,
                    auto_linked: true,
                    notice_separate: false,
                }))
            }
            Resolution::LinkRequired { .. } | Resolution::Denied(_) => Ok(None),
        }
    }

    /// The `identity.conflict` event for a `link_required` refusal. It carries
    /// no email and no detail of the existing account.
    pub fn conflict_event(
        &self,
        provider: &ProviderId,
        reason: Reason,
        ctx: &EventCtx,
    ) -> crate::event::types::Event {
        self.event(EventKind::IdentityConflict, Outcome::Failure, ctx)
            .provider(provider)
            .reason(reason)
            .build()
    }

    fn event(&self, kind: EventKind, outcome: Outcome, ctx: &EventCtx) -> EventBuilder {
        let b = match &self.emitter {
            Some(e) => e.counted(kind, outcome, ctx.request_id.clone()),
            None => EventBuilder::new(
                &*self.clock,
                &*self.rng,
                kind,
                outcome,
                ctx.request_id.clone(),
            ),
        };
        let mut b = b.ip(ctx.client_ip).ua(ctx.user_agent.as_deref());
        if let Some(e) = &self.emitter {
            b = e.with_client_request_id(b, ctx.client_request_id.as_deref());
        }
        if let Some(app) = &ctx.app_id {
            b = b.app(app);
        }
        if let Some(s) = &ctx.session_id {
            b = b.session(s);
        }
        b
    }
}

fn new_user(ident: &ProviderIdentity, with_email: bool) -> NewUser {
    let email = if with_email {
        ident.email.clone()
    } else {
        None
    };
    NewUser {
        email_authoritative: with_email && ident.email_authoritative,
        email_verified: with_email && ident.email_verified,
        primary_email: email,
        display_name: ident.name.clone(),
        username: ident.username.clone(),
    }
}
