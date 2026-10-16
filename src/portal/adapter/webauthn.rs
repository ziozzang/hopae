//! [`SecurityServices`] over the session service, the relying party and the
//! passkey store (ADR-0017). Every method re-derives its actor from the
//! presented portal handle; the store re-checks it inside the write.

use std::sync::Arc;

use async_trait::async_trait;
use data_encoding::BASE64URL_NOPAD;

use super::{Adapter, PreparedCredentials};
use crate::crypto::{Secret, Timestamp};
use crate::event::types::{Event, EventBuilder, EventKind, Outcome, reasons};
use crate::factor::webauthn::{Failure as Ceremony, RelyingParty, StoredCredential};
use crate::portal::ports::*;
use crate::portal::settings::*;
use crate::store::passkeys::{
    Assurance, CeremonyPurpose, NewCeremony, PasskeyRecord, PasskeyUse, PortalElevation,
    PortalProof, RECOVERY_CODES_PER_SET, RegisterPasskey, WebauthnElevation, refusal,
};
use crate::store::{FactorActor, Factors, HandleRow, Passkeys, StoreError};

/// Ceremony rows live five minutes, like the authenticator timeout.
const CEREMONY_LIFETIME: std::time::Duration = std::time::Duration::from_secs(300);

pub(super) struct WebauthnDeps {
    pub(super) store: Arc<crate::store::Store>,
    pub(super) rp: Arc<RelyingParty>,
    pub(super) keys: Option<Arc<crate::factor::keyring::Keyring>>,
    pub(super) clock: Arc<dyn crate::crypto::Clock>,
    pub(super) rng: Arc<dyn crate::crypto::Rng>,
}

impl Adapter {
    pub fn with_webauthn(
        mut self,
        store: Arc<crate::store::Store>,
        rp: Arc<RelyingParty>,
        keys: Option<Arc<crate::factor::keyring::Keyring>>,
        clock: Arc<dyn crate::crypto::Clock>,
        rng: Arc<dyn crate::crypto::Rng>,
    ) -> Self {
        self.webauthn = Some(WebauthnDeps {
            store,
            rp,
            keys,
            clock,
            rng,
        });
        self
    }

    fn deps(&self) -> Result<&WebauthnDeps, Refusal> {
        self.webauthn.as_ref().ok_or(Refusal::Failure(Failure {
            kind: FailKind::Forbidden,
            reason: reasons::INVALID_STATE,
        }))
    }

    async fn security_actor(
        &self,
        ctx: &RequestCtx,
        cookies: &Cookies,
    ) -> Result<FactorActor, Refusal> {
        if !ctx.https || cookies.bind.is_none() {
            return Err(forbidden());
        }
        self.svc
            .security_actor(&Self::sctx(ctx), cookies.handle.as_ref())
            .await
            .map_err(|e| match e {
                crate::session::service::SessionError::Store(_) => unavailable(),
                _ => forbidden(),
            })
    }
}

fn forbidden() -> Refusal {
    Refusal::Failure(Failure {
        kind: FailKind::Forbidden,
        reason: reasons::INVALID_STATE,
    })
}

fn unavailable() -> Refusal {
    Refusal::Failure(Failure {
        kind: FailKind::Unavailable,
        reason: reasons::STORE_UNAVAILABLE,
    })
}

fn store_refusal(e: StoreError) -> Refusal {
    match e {
        StoreError::Conflict(m) if m == refusal::VERIFICATION_REQUIRED => {
            Refusal::VerificationRequired
        }
        StoreError::Conflict(m) if m == refusal::LAST_FACTOR => Refusal::LastFactor,
        StoreError::Conflict(m) if m == refusal::DUPLICATE_CREDENTIAL => Refusal::Duplicate,
        StoreError::Conflict(m) if m == refusal::PASSKEY_CAPACITY => Refusal::Capacity,
        StoreError::Conflict(m) if m == refusal::CEREMONY_UNAVAILABLE => Refusal::Expired,
        StoreError::Conflict(m) if m == refusal::COUNTER_STALE => Refusal::Rejected,
        StoreError::Conflict("recovery code unavailable")
        | StoreError::Conflict("factor proof unavailable") => Refusal::InvalidCode,
        StoreError::Conflict("step-up challenge unavailable") => Refusal::Expired,
        StoreError::Conflict(_) | StoreError::ProviderDisabled => forbidden(),
        _ => unavailable(),
    }
}

fn credential_id(form_value: &str) -> Result<Vec<u8>, Refusal> {
    if form_value.is_empty() || form_value.len() > 1400 {
        return Err(Refusal::Failure(Failure {
            kind: FailKind::Failed,
            reason: reasons::INVALID_ID,
        }));
    }
    BASE64URL_NOPAD
        .decode(form_value.as_bytes())
        .ok()
        .filter(|v| (16..=1023).contains(&v.len()))
        .ok_or(Refusal::Failure(Failure {
            kind: FailKind::Failed,
            reason: reasons::INVALID_ID,
        }))
}

/// A label the user typed: trimmed, 1–64 characters, no control characters.
fn clean_label(label: &str) -> Option<String> {
    let label = label.trim();
    (!label.is_empty() && label.chars().count() <= 64 && !label.chars().any(char::is_control))
        .then(|| label.to_owned())
}

impl WebauthnDeps {
    fn event(&self, kind: EventKind, outcome: Outcome, actor: &FactorActor) -> EventBuilder {
        EventBuilder::new(
            self.clock.as_ref(),
            self.rng.as_ref(),
            kind,
            outcome,
            &actor.request_id,
        )
        .user(actor.user())
        .session(&actor.view.session.session_id)
    }

    fn failed(&self, actor: &FactorActor, purpose: CeremonyPurpose, cause: Ceremony) -> Event {
        self.event(EventKind::FactorWebauthnFailed, Outcome::Failure, actor)
            .reason(reasons::CEREMONY_INVALID)
            .attr("purpose", purpose.as_str())
            .attr("cause", cause.label())
            .build()
    }

    /// Persist a new ceremony for `actor` and return the bearer.
    async fn ceremony(
        &self,
        actor: FactorActor,
        purpose: CeremonyPurpose,
        bind: &Secret,
        transaction: Option<&Secret>,
        state: String,
    ) -> Result<Secret, Refusal> {
        let bearer = crate::crypto::random_token(self.rng.as_ref(), 32);
        self.store
            .begin_ceremony(NewCeremony {
                actor,
                purpose,
                digest: bearer.digest(),
                portal_binding: bind.digest(),
                transaction: transaction.map(Secret::digest),
                state,
                expires_at: self.clock.now().add(CEREMONY_LIFETIME),
            })
            .await
            .map_err(store_refusal)?;
        Ok(bearer)
    }

    /// The live ceremony `bearer` names, for this actor, purpose and (step-up) transaction.
    async fn live_ceremony(
        &self,
        actor: &FactorActor,
        bearer: &Secret,
        purpose: CeremonyPurpose,
        bind: &Secret,
        transaction: Option<&Secret>,
    ) -> Result<String, Refusal> {
        let b = bearer.expose();
        if b.len() != 43
            || !b
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        {
            return Err(Refusal::Expired);
        }
        let row = self
            .store
            .ceremony(&bearer.digest())
            .await
            .map_err(|_| unavailable())?
            .ok_or(Refusal::Expired)?;
        if row.purpose != purpose
            || row.user_id != *actor.user()
            || row.session_id != actor.view.session.session_id
            || row.handle_sha256 != actor.view.handle.handle_sha256
            || row.portal_bind_sha256 != bind.digest()
            || row.transaction != transaction.map(Secret::digest)
            || row.credential_generation != actor.view.session.cred_gen
        {
            return Err(Refusal::Expired);
        }
        Ok(row.state)
    }

    /// Verify an assertion; on a clone signal or a failure the ceremony is
    /// consumed and the event recorded before the refusal is returned.
    async fn assert(
        &self,
        actor: &FactorActor,
        bearer: &Secret,
        state: &str,
        response: &str,
        purpose: CeremonyPurpose,
    ) -> Result<PasskeyUse, Refusal> {
        let summary = self
            .store
            .factor_summary(actor.user())
            .await
            .map_err(|_| unavailable())?;
        let stored: Vec<StoredCredential<'_>> = summary
            .passkeys
            .iter()
            .map(|p| StoredCredential {
                credential: &p.passkey,
                assurance: p.assurance,
            })
            .collect();
        match self.rp.finish_authentication(response, state, &stored) {
            Ok(a) => Ok(PasskeyUse {
                credential_id: a.credential_id,
                passkey: a.credential,
                sign_count: a.sign_count,
                backup_eligible: a.backup_eligible,
                backup_state: a.backup_state,
                assurance: a.assurance,
            }),
            Err(Ceremony::CounterRegression) => {
                let id = RelyingParty::response_credential_id(response).unwrap_or_default();
                let event = self
                    .event(
                        EventKind::FactorWebauthnCloneSuspected,
                        Outcome::Failure,
                        actor,
                    )
                    .reason(reasons::COUNTER_REGRESSION)
                    .attr("factor_id", crate::store::sqlite::webauthn::factor_id(&id))
                    .attr("purpose", purpose.as_str())
                    .build();
                tracing::warn!(request_id = %actor.request_id, "passkey counter regression: credential revoked");
                self.store
                    .passkey_clone_detected(&bearer.digest(), &id, vec![event])
                    .await
                    .map_err(store_refusal)?;
                Err(Refusal::CloneSuspected)
            }
            Err(cause) => {
                let event = self.failed(actor, purpose, cause);
                self.store
                    .fail_ceremony(&bearer.digest(), vec![event])
                    .await
                    .map_err(|_| unavailable())?;
                Err(Refusal::Rejected)
            }
        }
    }

    /// The reissued portal handle after a portal elevation.
    fn portal_handle(
        &self,
        actor: &FactorActor,
        aal: crate::session::Aal,
    ) -> (Secret, HandleRow, Timestamp) {
        let now = self.clock.now();
        let handle = crate::crypto::handle_value(self.rng.as_ref());
        let expiry = actor
            .view
            .handle
            .absolute_expires_at
            .min(actor.view.session.absolute_expires_at);
        let row = HandleRow {
            handle_sha256: handle.digest(),
            session_id: actor.view.session.session_id.clone(),
            host: actor.view.handle.host.clone(),
            issued_aal: aal,
            created_at: now,
            last_seen_at: now,
            absolute_expires_at: expiry,
            revoked_at: None,
            revoked_reason: None,
        };
        (handle, row, expiry)
    }

    async fn elevate_portal(
        &self,
        actor: FactorActor,
        bind: &Secret,
        proof: PortalProof,
    ) -> Result<HandleCookie, Refusal> {
        let aal = match proof {
            PortalProof::Recovery { .. } => actor.view.session.aal,
            _ => crate::session::Aal::Two,
        };
        let (handle, row, expiry) = self.portal_handle(&actor, aal);
        let now = row.created_at;
        self.store
            .elevate_portal(PortalElevation {
                actor,
                portal_binding: bind.digest(),
                proof,
                portal_handle: row,
                events: vec![],
            })
            .await
            .map_err(store_refusal)?;
        Ok(HandleCookie {
            value: handle,
            max_age: expiry.since(now),
        })
    }
}

#[async_trait]
impl SecurityServices for Adapter {
    fn high_assurance_available(&self) -> bool {
        self.webauthn
            .as_ref()
            .is_some_and(|d| d.rp.high_assurance())
    }

    async fn overview(&self, ctx: &RequestCtx, cookies: &Cookies) -> Result<SecurityView, Refusal> {
        let deps = self.deps()?;
        let actor = self.security_actor(ctx, cookies).await?;
        let summary = deps
            .store
            .factor_summary(actor.user())
            .await
            .map_err(|_| unavailable())?;
        let now = deps.clock.now();
        let has = summary.second_factors() > 0;
        let session = &actor.view.session;
        let can_manage = crate::store::sqlite::webauthn::management_allowed(
            &session.factors,
            session.auth_time,
            has,
            now,
        );
        Ok(SecurityView {
            passkeys: summary
                .passkeys
                .iter()
                .map(|p| PasskeyView {
                    id: BASE64URL_NOPAD.encode(&p.credential_id),
                    label: p.label.clone(),
                    synced: p.backup_eligible,
                    high_assurance: p.assurance == Assurance::Aal3,
                    created_at: p.created_at,
                    last_used_at: p.last_used_at,
                })
                .collect(),
            totp_active: summary.totp_active,
            totp_available: deps.keys.is_some(),
            recovery_unused: summary.recovery_unused,
            recovery_generated: summary.recovery_generated_at.is_some(),
            recovery_required: summary.recovery_required_at.is_some(),
            can_manage,
            can_verify: has || summary.recovery_unused > 0,
            high_assurance_available: deps.rp.high_assurance(),
            needs_fresh_sign_in: !has && !can_manage,
        })
    }

    async fn begin_registration(
        &self,
        ctx: &RequestCtx,
        cookies: &Cookies,
        high_assurance: bool,
    ) -> Result<CeremonyPage, Refusal> {
        let deps = self.deps()?;
        let actor = self.security_actor(ctx, cookies).await?;
        let bind = cookies.bind.as_ref().ok_or_else(forbidden)?;
        if high_assurance && !deps.rp.high_assurance() {
            return Err(forbidden());
        }
        let summary = deps
            .store
            .factor_summary(actor.user())
            .await
            .map_err(|_| unavailable())?;
        let session = &actor.view.session;
        if !crate::store::sqlite::webauthn::management_allowed(
            &session.factors,
            session.auth_time,
            summary.second_factors() > 0,
            deps.clock.now(),
        ) {
            return Err(Refusal::VerificationRequired);
        }
        if summary.passkeys.len() >= crate::store::passkeys::MAX_PASSKEYS as usize {
            return Err(Refusal::Capacity);
        }
        let mut candidate = [0u8; 16];
        deps.rng.fill(&mut candidate);
        // RFC 9562 version 4 and variant bits on the random handle.
        candidate[6] = (candidate[6] & 0x0f) | 0x40;
        candidate[8] = (candidate[8] & 0x3f) | 0x80;
        let user_handle = deps
            .store
            .passkey_user_handle(actor.user(), candidate)
            .await
            .map_err(store_refusal)?;
        let snapshot = &session.snapshot;
        let user_name = snapshot
            .email
            .as_ref()
            .map(|e| e.as_str().to_owned())
            .or_else(|| snapshot.username.clone())
            .unwrap_or_else(|| actor.user().as_str().to_owned());
        let display_name = snapshot
            .display_name
            .clone()
            .unwrap_or_else(|| user_name.clone());
        let exclude = summary
            .passkeys
            .iter()
            .map(|p| p.credential_id.clone())
            .collect();
        let (options, state) = deps
            .rp
            .start_registration(
                user_handle,
                &user_name,
                &display_name,
                exclude,
                high_assurance,
            )
            .map_err(|_| unavailable())?;
        let options = serde_json::to_string(&options).map_err(|_| unavailable())?;
        let ceremony = deps
            .ceremony(actor, CeremonyPurpose::Register, bind, None, state)
            .await?;
        Ok(CeremonyPage { ceremony, options })
    }

    async fn finish_registration(
        &self,
        ctx: &RequestCtx,
        cookies: &Cookies,
        ceremony: &Secret,
        label: Option<&str>,
        default_label: (&str, &str),
        response: &str,
    ) -> Result<(), Refusal> {
        let deps = self.deps()?;
        let actor = self.security_actor(ctx, cookies).await?;
        let bind = cookies.bind.as_ref().ok_or_else(forbidden)?;
        let state = deps
            .live_ceremony(&actor, ceremony, CeremonyPurpose::Register, bind, None)
            .await?;
        let registered = match deps.rp.finish_registration(response, &state) {
            Ok(r) => r,
            Err(cause) => {
                let event = deps.failed(&actor, CeremonyPurpose::Register, cause);
                deps.store
                    .fail_ceremony(&ceremony.digest(), vec![event])
                    .await
                    .map_err(|_| unavailable())?;
                return Err(if cause == Ceremony::NotAllowed {
                    Refusal::NotAllowedAuthenticator
                } else {
                    Refusal::Rejected
                });
            }
        };
        let roaming = registered
            .transports
            .iter()
            .any(|t| matches!(t.as_str(), "usb" | "nfc" | "ble"))
            && !registered
                .transports
                .iter()
                .any(|t| matches!(t.as_str(), "internal" | "hybrid"));
        let label = label
            .and_then(clean_label)
            .or_else(|| registered.authenticator_name.map(str::to_owned))
            .unwrap_or_else(|| {
                if registered.attested || (roaming && !registered.backup_eligible) {
                    default_label.1.to_owned()
                } else {
                    default_label.0.to_owned()
                }
            });
        let now = deps.clock.now();
        let user = actor.user().clone();
        deps.store
            .register_passkey(RegisterPasskey {
                actor,
                ceremony: ceremony.digest(),
                portal_binding: bind.digest(),
                record: PasskeyRecord {
                    credential_id: registered.credential_id,
                    user_id: user,
                    label,
                    passkey: registered.credential,
                    aaguid: registered.aaguid,
                    transports: registered.transports,
                    backup_eligible: registered.backup_eligible,
                    backup_state: registered.backup_state,
                    user_verified: registered.user_verified,
                    attestation_format: registered.attestation_format,
                    attested: registered.attested,
                    assurance: registered.assurance,
                    sign_count: 0,
                    created_at: now,
                    last_used_at: None,
                    revision: 1,
                },
                events: vec![],
            })
            .await
            .map_err(store_refusal)
    }

    async fn rename(
        &self,
        ctx: &RequestCtx,
        cookies: &Cookies,
        credential: &str,
        label: &str,
    ) -> Result<(), Refusal> {
        let deps = self.deps()?;
        let actor = self.security_actor(ctx, cookies).await?;
        let id = credential_id(credential)?;
        let label = clean_label(label).ok_or(Refusal::Failure(Failure {
            kind: FailKind::Failed,
            reason: reasons::INVALID_ID,
        }))?;
        match deps
            .store
            .rename_passkey(actor, &id, label, vec![])
            .await
            .map_err(store_refusal)?
        {
            true => Ok(()),
            false => Err(Refusal::Failure(Failure {
                kind: FailKind::Failed,
                reason: reasons::NOT_FOUND,
            })),
        }
    }

    async fn remove(
        &self,
        ctx: &RequestCtx,
        cookies: &Cookies,
        credential: &str,
    ) -> Result<(), Refusal> {
        let deps = self.deps()?;
        let actor = self.security_actor(ctx, cookies).await?;
        let id = credential_id(credential)?;
        match deps
            .store
            .revoke_passkey(actor, &id, vec![])
            .await
            .map_err(store_refusal)?
        {
            true => Ok(()),
            false => Err(Refusal::Failure(Failure {
                kind: FailKind::Failed,
                reason: reasons::NOT_FOUND,
            })),
        }
    }

    async fn begin_verify(
        &self,
        ctx: &RequestCtx,
        cookies: &Cookies,
    ) -> Result<Option<CeremonyPage>, Refusal> {
        let deps = self.deps()?;
        let actor = self.security_actor(ctx, cookies).await?;
        let bind = cookies.bind.as_ref().ok_or_else(forbidden)?;
        let summary = deps
            .store
            .factor_summary(actor.user())
            .await
            .map_err(|_| unavailable())?;
        if summary.passkeys.is_empty() {
            return Ok(None);
        }
        let stored: Vec<_> = summary
            .passkeys
            .iter()
            .map(|p| StoredCredential {
                credential: &p.passkey,
                assurance: p.assurance,
            })
            .collect();
        let (options, state) = deps
            .rp
            .start_authentication(&stored)
            .map_err(|_| unavailable())?;
        let options = serde_json::to_string(&options).map_err(|_| unavailable())?;
        let ceremony = deps
            .ceremony(actor, CeremonyPurpose::Verify, bind, None, state)
            .await?;
        Ok(Some(CeremonyPage { ceremony, options }))
    }

    async fn verify_passkey(
        &self,
        ctx: &RequestCtx,
        cookies: &Cookies,
        ceremony: &Secret,
        response: &str,
    ) -> Result<HandleCookie, Refusal> {
        let deps = self.deps()?;
        let actor = self.security_actor(ctx, cookies).await?;
        let bind = cookies.bind.as_ref().ok_or_else(forbidden)?;
        let state = deps
            .live_ceremony(&actor, ceremony, CeremonyPurpose::Verify, bind, None)
            .await?;
        let used = deps
            .assert(&actor, ceremony, &state, response, CeremonyPurpose::Verify)
            .await?;
        deps.elevate_portal(
            actor,
            bind,
            PortalProof::Passkey {
                ceremony: ceremony.digest(),
                used,
            },
        )
        .await
    }

    async fn verify_totp(
        &self,
        ctx: &RequestCtx,
        cookies: &Cookies,
        code: &Secret,
    ) -> Result<HandleCookie, Refusal> {
        let deps = self.deps()?;
        let keys = deps.keys.as_ref().ok_or_else(forbidden)?;
        let actor = self.security_actor(ctx, cookies).await?;
        let bind = cookies.bind.as_ref().ok_or_else(forbidden)?;
        let enrollment = deps
            .store
            .active_totp_enrollment(actor.user())
            .await
            .map_err(|_| unavailable())?
            .ok_or(Refusal::InvalidCode)?;
        let row = deps
            .store
            .totp_enrollment(&enrollment, actor.user())
            .await
            .map_err(|_| unavailable())?
            .filter(|r| r.active)
            .ok_or(Refusal::InvalidCode)?;
        let key = keys.for_envelope(&row.envelope).ok_or_else(unavailable)?;
        let seed = key
            .open(&row.envelope, actor.user().as_str(), &enrollment)
            .map_err(|_| unavailable())?;
        let Some(counter) = crate::factor::totp::Parameters::default().matching_counter(
            &seed,
            deps.clock.now(),
            code,
            row.last_counter,
        ) else {
            return Err(Refusal::InvalidCode);
        };
        deps.elevate_portal(
            actor,
            bind,
            PortalProof::Totp {
                enrollment,
                revision: row.revision,
                counter,
            },
        )
        .await
    }

    async fn verify_recovery(
        &self,
        ctx: &RequestCtx,
        cookies: &Cookies,
        code: &Secret,
    ) -> Result<HandleCookie, Refusal> {
        let deps = self.deps()?;
        let actor = self.security_actor(ctx, cookies).await?;
        let bind = cookies.bind.as_ref().ok_or_else(forbidden)?;
        let presented =
            crate::factor::recovery::parse(code.expose()).ok_or(Refusal::InvalidCode)?;
        let hash = deps
            .store
            .recovery_code_hash(actor.user(), &presented.lookup)
            .await
            .map_err(|_| unavailable())?;
        let (ok, presented) = tokio::task::spawn_blocking(move || {
            let ok = match &hash {
                Some(h) => crate::factor::recovery::verify(&presented, h),
                None => {
                    crate::factor::recovery::verify_dummy(&presented);
                    false
                }
            };
            (ok, presented)
        })
        .await
        .map_err(|_| unavailable())?;
        if !ok {
            let event = deps
                .event(EventKind::FactorRecoveryCodeUsed, Outcome::Failure, &actor)
                .reason(reasons::INVALID_CREDENTIALS)
                .attr("kind", "recovery")
                .build();
            self.events
                .append_required(vec![event])
                .await
                .map_err(|_| unavailable())?;
            return Err(Refusal::InvalidCode);
        }
        deps.elevate_portal(
            actor,
            bind,
            PortalProof::Recovery {
                lookup: presented.lookup,
            },
        )
        .await
    }

    async fn generate_recovery_codes(
        &self,
        ctx: &RequestCtx,
        cookies: &Cookies,
    ) -> Result<Vec<zeroize::Zeroizing<String>>, Refusal> {
        let deps = self.deps()?;
        let actor = self.security_actor(ctx, cookies).await?;
        let rng = deps.rng.clone();
        let generated = tokio::task::spawn_blocking(move || {
            crate::factor::recovery::generate(rng.as_ref(), RECOVERY_CODES_PER_SET)
        })
        .await
        .map_err(|_| unavailable())?;
        let batch = crate::crypto::random_id(deps.rng.as_ref(), "rc_");
        let pairs = generated
            .iter()
            .map(|g| (g.lookup.clone(), g.hash.clone()))
            .collect();
        deps.store
            .replace_recovery_codes(actor, batch, pairs, vec![])
            .await
            .map_err(|e| match e {
                StoreError::Conflict("recovery codes require a second factor") => {
                    Refusal::VerificationRequired
                }
                e => store_refusal(e),
            })?;
        Ok(generated.into_iter().map(|g| g.display).collect())
    }

    async fn begin_stepup(
        &self,
        ctx: &RequestCtx,
        cookies: &Cookies,
        transaction: &Secret,
    ) -> Result<StepUpCeremony, Refusal> {
        let deps = self.deps()?;
        let bind = cookies.bind.as_ref().ok_or_else(forbidden)?;
        if !ctx.https {
            return Err(forbidden());
        }
        let (actor, row, _generation) = self
            .svc
            .stepup_context(&Self::sctx(ctx), transaction, cookies.handle.as_ref())
            .await
            .map_err(|e| Refusal::Failure(Self::factor_session_error(e)))?;
        let summary = deps
            .store
            .factor_summary(actor.user())
            .await
            .map_err(|_| unavailable())?;
        let totp = deps.keys.is_some() && summary.totp_active;
        let form_origin = row.return_target.origin();
        if summary.passkeys.is_empty() {
            return Ok(StepUpCeremony {
                page: None,
                form_origin,
                totp,
            });
        }
        let stored: Vec<_> = summary
            .passkeys
            .iter()
            .map(|p| StoredCredential {
                credential: &p.passkey,
                assurance: p.assurance,
            })
            .collect();
        let (options, state) = deps
            .rp
            .start_authentication(&stored)
            .map_err(|_| unavailable())?;
        let options = serde_json::to_string(&options).map_err(|_| unavailable())?;
        let ceremony = deps
            .ceremony(
                actor,
                CeremonyPurpose::StepUp,
                bind,
                Some(transaction),
                state,
            )
            .await?;
        Ok(StepUpCeremony {
            page: Some(CeremonyPage { ceremony, options }),
            form_origin,
            totp,
        })
    }

    async fn complete_stepup(
        &self,
        ctx: &RequestCtx,
        cookies: &Cookies,
        transaction: &Secret,
        ceremony: &Secret,
        response: &str,
    ) -> Result<Redirect, Refusal> {
        let deps = self.deps()?;
        let bind = cookies.bind.as_ref().ok_or_else(forbidden)?;
        if !ctx.https {
            return Err(forbidden());
        }
        let (actor, row, generation) = self
            .svc
            .stepup_context(&Self::sctx(ctx), transaction, cookies.handle.as_ref())
            .await
            .map_err(|e| Refusal::Failure(Self::factor_session_error(e)))?;
        let state = deps
            .live_ceremony(
                &actor,
                ceremony,
                CeremonyPurpose::StepUp,
                bind,
                Some(transaction),
            )
            .await?;
        let used = deps
            .assert(&actor, ceremony, &state, response, CeremonyPurpose::StepUp)
            .await?;
        let PreparedCredentials {
            now,
            handle,
            handoff,
            expiry,
            portal_handle,
            handoff_row,
        } = Self::prepare_stepup(&actor, &row, ctx, deps.clock.as_ref(), deps.rng.as_ref())
            .map_err(Refusal::Failure)?;
        deps.store
            .elevate_webauthn(WebauthnElevation {
                actor,
                ceremony: ceremony.digest(),
                portal_binding: bind.digest(),
                transaction: transaction.digest(),
                config_generation: generation,
                used,
                portal_handle,
                handoff: handoff_row,
                events: vec![],
            })
            .await
            .map_err(store_refusal)?;
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
}
