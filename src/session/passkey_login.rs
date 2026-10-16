//! Passwordless passkey sign-in (ADR-0017 decision 16): the session-service
//! half. The relying party verified the assertion; this builds the session
//! (reserved provider `hopae.passkey`, factor `webauthn`, AAL 2), lets the
//! store create it atomically with the ceremony, the login transaction and
//! the passkey's counter, then hands the browser off at AAL 2.

use super::*;
use crate::provider::types::PASSKEY_PROVIDER;
use crate::store::Passkeys;
use crate::store::passkeys::{PasskeyLogin, PasskeyUse};

impl Service {
    /// The live login transaction a passkey sign-in may complete: purpose
    /// `login`, same client address, no provider flow started and not a
    /// reauthentication (those need the session's own provider).
    pub(crate) async fn passkey_login_txn(
        &self,
        ctx: &RequestCtx,
        txn: &Secret,
    ) -> Result<TransactionRow, SessionError> {
        let row = self.load_live_txn_quiet(txn).await?;
        if row.purpose != TxnPurpose::Login
            || !self.txn_ip_ok(&row, ctx)
            || row.state_sha256.is_some()
            || row.reauth_max_age.is_some()
            || row.bind_sha256.is_none()
        {
            return Err(SessionError::Refused(reasons::TXN_PURPOSE_MISMATCH));
        }
        Ok(row)
    }

    /// Create the passkey session and mint the hand-off.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn complete_passkey_login(
        &self,
        ctx: &RequestCtx,
        store: &dyn Passkeys,
        row: &TransactionRow,
        portal_binding: crate::crypto::Digest,
        ceremony: crate::crypto::Digest,
        user_id: &UserId,
        used: PasskeyUse,
    ) -> Result<(Url, IssuedHandle), SessionError> {
        let user = self
            .directory
            .user(user_id)
            .await?
            .filter(|u| u.status == crate::store::UserStatus::Active)
            .ok_or(SessionError::Refused(reasons::USER_DISABLED))?;
        let app_bind = row
            .bind_sha256
            .ok_or(SessionError::Refused(reasons::TXN_BINDING))?;
        let now = self.clock.now();
        let snap = self.snapshot.load_full();
        let provider = ProviderId::new(PASSKEY_PROVIDER);
        let session_id = SessionId::new(random_id(&*self.rng, "s_"));
        let handle = handle_value(&*self.rng);
        let session_abs = now.add(self.cfg.session.absolute);
        let handle_abs = now.add(snap.default_app.session.absolute).min(session_abs);
        let session = SessionRow {
            session_id: session_id.clone(),
            user_id: user.user_id.clone(),
            provider_id: provider.clone(),
            auth_time: now,
            factors: vec![FactorEntry {
                kind: FactorKind::Webauthn,
                provider: None,
                at: now,
            }],
            // A user-verified passkey is a multi-factor cryptographic
            // authenticator: AAL 2 on its own (ADR-0017 decision 16).
            aal: Aal::Two,
            authz_version: user.authz_version,
            cred_gen: 1,
            snapshot: IdentitySnapshot {
                email: user.primary_email.clone(),
                display_name: user.display_name.clone(),
                username: user.username.clone(),
                groups: user.groups.clone(),
            },
            bound_ip: ctx.client_ip,
            bound_ua_sha256: self.ua_digest(ctx),
            created_at: now,
            last_seen_at: now,
            absolute_expires_at: session_abs,
            terminated_at: None,
            terminated_reason: None,
            authz_version_at_auth: user.authz_version,
            auth_time_source: AuthTimeSource::HopaeCompletion,
            bound_ua_prefix: ctx
                .user_agent
                .as_deref()
                .map(crate::event::types::ua_prefix),
        };
        let portal_handle = HandleRow {
            handle_sha256: handle.digest(),
            session_id: session_id.clone(),
            host: self.cfg.portal_host.clone(),
            issued_aal: Aal::Two,
            created_at: now,
            last_seen_at: now,
            absolute_expires_at: handle_abs,
            revoked_at: None,
            revoked_reason: None,
        };
        let base = |kind| {
            self.ev(ctx, kind, Outcome::Success)
                .user(&user.user_id)
                .session(&session_id)
                .provider(&provider)
                .app(&row.app_id)
        };
        let factor = crate::store::sqlite::webauthn::factor_id(&used.credential_id);
        let assurance = used.assurance.as_str();
        let events = vec![
            base(EventKind::LoginSucceeded)
                .attr("kind", "webauthn")
                .attr("factor_id", factor.clone())
                .build(),
            base(EventKind::SessionCreated)
                .attr("aal", 2)
                .attr("auth_time_source", AuthTimeSource::HopaeCompletion.as_str())
                .build(),
            base(EventKind::FactorWebauthnUsed)
                .attr("kind", "webauthn")
                .attr("factor_id", factor)
                .attr("aal", 2)
                .attr("assurance", assurance)
                .attr("purpose", "login")
                .build(),
        ];
        store
            .create_passkey_session(PasskeyLogin {
                ceremony,
                transaction: row.txn_sha256,
                portal_binding,
                client_ip: ctx.client_ip,
                used,
                session,
                portal_handle,
                events,
            })
            .await?;
        let minted = self
            .mint_handoff(MintRequest {
                session_id,
                aal_cap: Aal::Two,
                target: row.return_target.clone(),
                client_ip: row.client_ip,
                bind_sha256: app_bind,
                recovery_depth: row.recovery_depth,
                events: vec![],
            })
            .await?;
        Ok((
            minted.location,
            IssuedHandle {
                value: handle,
                max_age: handle_abs.since(now),
            },
        ))
    }
}
