//! Slice 2c for PostgreSQL (ADR-0020): `Factors` — sealed TOTP enrollments,
//! monotonic counters, the external factor registry and single-use proofs,
//! and native step-up elevation.
//!
//! Every write locks the subject user's row `FOR UPDATE` first, then the
//! acting session (`FOR UPDATE`) and handle (`FOR SHARE`) while it re-checks
//! them: writes for one user serialize as they do behind the single SQLite
//! writer, and a revocation or termination cannot slip between the check
//! and the change. Registry-wide changes take an advisory lock.
use async_trait::async_trait;
use deadpool_postgres::Transaction;

use super::write::{self, factors_json};
use super::{PgStore, pg};
use crate::crypto::Timestamp;
use crate::event::types::{Event, EventBuilder, EventKind, Outcome, reasons};
use crate::identity::types::UserId;
use crate::session::types::{Aal, FactorEntry, FactorKind, SessionId};
use crate::store::{
    BindExternalStepUp, BindTotpStepUp, ExternalElevation, ExternalFactorPublication,
    ExternalFactorSnapshot, FactorActor, Factors, HandleRow, HandoffCodeRow, StoreError,
    StoreResult, TotpChallengeBinding, TotpElevation, TotpEnrollment,
};

/// `pg_advisory_xact_lock` key serializing the external factor registry.
const EXTERNAL_REGISTRY_LOCK: i64 = 7011;

fn conflict(what: &'static str) -> StoreError {
    StoreError::Conflict(what)
}

/// Lock the user row: factor writes for one user run one at a time.
pub(super) async fn lock_user(tx: &Transaction<'_>, user: &str) -> StoreResult<Option<String>> {
    Ok(tx
        .query_opt(
            "SELECT status FROM users WHERE user_id=$1 FOR UPDATE",
            &[&user],
        )
        .await
        .map_err(pg)?
        .map(|r| r.get(0)))
}

/// Which actor rule applies: TOTP management also requires a primary sign-in
/// at most five minutes old and accepts a higher level than the view's.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum ActorRule {
    Totp,
    Security,
}

/// The acting portal session is still exactly what the actor saw (SQLite
/// `require_actor` / `require_security_actor`), with its session row locked
/// `FOR UPDATE` and its handle and user `FOR SHARE`.
pub(super) async fn require_actor(
    store: &PgStore,
    tx: &Transaction<'_>,
    user: &str,
    actor: &FactorActor,
    rule: ActorRule,
) -> StoreResult<()> {
    let now = store.now();
    if now < actor.authorized_at
        || now.since(actor.authorized_at) > std::time::Duration::from_secs(5)
    {
        return Err(conflict("factor authorization expired"));
    }
    let view = &actor.view;
    if view.session.provider_id.as_str() != crate::provider::types::PASSKEY_PROVIDER {
        write::require_provider_configuration(
            tx,
            view.session.provider_id.as_str(),
            Some(&actor.provider_configuration),
        )
        .await?;
    }
    let (aal_cmp, fresh) = match rule {
        ActorRule::Totp => (">=", "AND s.auth_time >= $10"),
        ActorRule::Security => ("=", "AND $10::bigint IS NOT NULL"),
    };
    let sql = format!(
        "SELECT 1 FROM sessions s JOIN session_handles h ON h.session_id=s.session_id JOIN users u ON u.user_id=s.user_id \
         LEFT JOIN providers p ON p.provider_id=s.provider_id \
         WHERE s.session_id=$1 AND s.user_id=$2 AND h.handle_sha256=$3 AND h.host=$4 AND s.cred_gen=$5 AND s.auth_time=$6 \
         AND s.authz_version_at_auth=u.authz_version AND u.status='active' AND s.terminated_at IS NULL AND h.revoked_at IS NULL \
         AND ((s.provider_id='hopae.passkey' AND p.provider_id IS NULL) OR (p.enabled AND p.deleted_at IS NULL)) \
         AND s.aal {aal_cmp} $11::integer AND h.issued_aal {aal_cmp} $12::integer AND s.absolute_expires_at > $7::bigint AND h.absolute_expires_at > $7::bigint \
         AND s.last_seen_at > $8::bigint AND h.last_seen_at > $9::bigint {fresh} AND s.auth_time <= $7::bigint AND s.factors = $13 \
         FOR UPDATE OF s FOR SHARE OF h, u"
    );
    let (s_aal, h_aal) = match rule {
        ActorRule::Totp => (
            view.session.aal.as_i64().max(1),
            view.handle.issued_aal.as_i64().max(1),
        ),
        ActorRule::Security => (view.session.aal.as_i64(), view.handle.issued_aal.as_i64()),
    };
    let generation =
        i64::try_from(view.session.cred_gen).map_err(|_| conflict("credential generation"))?;
    let live = tx
        .query_opt(
            &sql,
            &[
                &view.session.session_id.as_str(),
                &user,
                &view.handle.handle_sha256.0.to_vec(),
                &view.handle.host.as_str(),
                &generation,
                &view.session.auth_time.secs(),
                &now.secs(),
                &now.secs()
                    .saturating_sub(actor.session_idle.as_secs() as i64),
                &now.secs()
                    .saturating_sub(actor.handle_idle.as_secs() as i64),
                &now.secs().saturating_sub(300),
                &(s_aal as i32),
                &(h_aal as i32),
                &factors_json(&view.session.factors)?,
            ],
        )
        .await
        .map_err(pg)?;
    if live.is_none() {
        return Err(conflict("factor authorization revoked"));
    }
    Ok(())
}

fn factor_event(
    store: &PgStore,
    user: &UserId,
    id: &str,
    kind: EventKind,
    request_id: &str,
) -> Event {
    EventBuilder::new(
        store.clock.as_ref(),
        store.rng.as_ref(),
        kind,
        Outcome::Success,
        request_id,
    )
    .user(user)
    .attr("enrollment_id", id)
    .build()
}

fn builder(store: &PgStore, kind: EventKind, request_id: &str) -> EventBuilder {
    EventBuilder::new(
        store.clock.as_ref(),
        store.rng.as_ref(),
        kind,
        Outcome::Success,
        request_id,
    )
}

fn stepup_context(
    generation: u64,
    enrollment: &str,
    revision: i64,
    config_generation: Option<u64>,
) -> StoreResult<String> {
    if revision <= 0 || i64::try_from(generation).is_err() {
        return Err(conflict("invalid step-up context"));
    }
    Ok(serde_json::json!({"credential_generation":generation,"enrollment_id":enrollment,"enrollment_revision":revision,"config_generation":config_generation.unwrap_or(0)}).to_string())
}

fn external_context(
    generation: u64,
    authority: &crate::factor::external_transport::Authority,
    configuration: u64,
) -> StoreResult<String> {
    if i64::try_from(generation).is_err() {
        return Err(conflict("invalid credential generation"));
    }
    Ok(serde_json::json!({"kind":"external","credential_generation":generation,"factor":authority.factor,"revision":authority.revision,"binding":crate::crypto::Digest(authority.binding).to_hex(),"config_generation":configuration}).to_string())
}

async fn require_external_authority(
    tx: &Transaction<'_>,
    authority: &crate::factor::external_transport::Authority,
    generation: u64,
) -> StoreResult<()> {
    write::require_stepup_generation(tx, Some(generation)).await?;
    let revision =
        i64::try_from(authority.revision).map_err(|_| conflict("invalid factor revision"))?;
    let generation =
        i64::try_from(generation).map_err(|_| conflict("invalid configuration generation"))?;
    let active = tx
        .query_opt(
            "SELECT 1 FROM external_factor_authorities WHERE factor=$1 AND revision=$2 AND binding=$3 AND config_generation=$4 FOR SHARE",
            &[&authority.factor, &revision, &authority.binding.to_vec(), &generation],
        )
        .await
        .map_err(pg)?;
    if active.is_none() {
        return Err(conflict("external factor disabled or changed"));
    }
    Ok(())
}

/// The step-up transaction the native binding writes: live, bound to the
/// acting session, address and browser, and not yet bound elsewhere.
const STEPUP_BIND: &str = "UPDATE login_txns SET portal_bind_sha256=$2, conflicting_handle_sha256=$3, pending_identity=$4 \
     WHERE txn_sha256=$1 AND purpose='stepup' AND portal_session_id=$5 AND client_ip=$6 AND bind_sha256 IS NOT NULL AND consumed_at IS NULL \
     AND created_at<=$7 AND expires_at>$7 AND portal_bind_sha256 IS NULL AND conflicting_handle_sha256 IS NULL AND pending_identity IS NULL \
     AND provider_id IS NULL AND state_sha256 IS NULL AND nonce IS NULL AND pkce_verifier IS NULL AND reauth_max_age IS NULL";
const STEPUP_SAME: &str = "SELECT 1 FROM login_txns WHERE txn_sha256=$1 AND purpose='stepup' AND portal_session_id=$5 AND client_ip=$6 \
     AND bind_sha256 IS NOT NULL AND consumed_at IS NULL AND created_at<=$7 AND expires_at>$7 AND portal_bind_sha256=$2 \
     AND conflicting_handle_sha256=$3 AND pending_identity=$4 AND provider_id IS NULL AND state_sha256 IS NULL AND nonce IS NULL \
     AND pkce_verifier IS NULL AND reauth_max_age IS NULL";

/// Bind a step-up transaction (`changed`) or confirm an identical binding.
async fn bind_stepup(
    tx: &Transaction<'_>,
    actor: &FactorActor,
    transaction: &crate::crypto::Digest,
    portal_binding: &crate::crypto::Digest,
    context: &str,
    now: Timestamp,
) -> StoreResult<Option<bool>> {
    let view = &actor.view;
    let txn = transaction.0.to_vec();
    let bind = portal_binding.0.to_vec();
    let handle = view.handle.handle_sha256.0.to_vec();
    let ip = actor.client_ip.to_string();
    let params: [&(dyn tokio_postgres::types::ToSql + Sync); 7] = [
        &txn,
        &bind,
        &handle,
        &context,
        &view.session.session_id.as_str(),
        &ip,
        &now.secs(),
    ];
    // Lock the transaction row first: a concurrent binder waits, then sees ours.
    tx.query_opt(
        "SELECT 1 FROM login_txns WHERE txn_sha256=$1 FOR UPDATE",
        &[&txn],
    )
    .await
    .map_err(pg)?;
    let changed = tx.execute(STEPUP_BIND, &params).await.map_err(pg)?;
    if changed == 1 {
        return Ok(Some(true));
    }
    let same = tx.query_opt(STEPUP_SAME, &params).await.map_err(pg)?;
    Ok(same.map(|_| false))
}

/// Check the reissued portal handle and handoff code of an elevation.
#[allow(clippy::too_many_arguments)]
fn check_elevated(
    actor: &FactorActor,
    handle: &HandleRow,
    code: &HandoffCodeRow,
    generation: i64,
    now: Timestamp,
    exact_second: bool,
) -> StoreResult<()> {
    let view = &actor.view;
    let sid = &view.session.session_id;
    let fresh_handle = if exact_second {
        handle.created_at.secs() == now.secs() && handle.last_seen_at.secs() == now.secs()
    } else {
        handle.created_at <= now
            && now.since(handle.created_at) <= std::time::Duration::from_secs(5)
            && handle.last_seen_at == handle.created_at
    };
    let fresh_code = if exact_second {
        code.created_at.secs() == now.secs()
    } else {
        code.created_at == handle.created_at
    };
    if handle.session_id != *sid
        || handle.host != view.handle.host
        || handle.handle_sha256 == view.handle.handle_sha256
        || handle.issued_aal != Aal::Two
        || !fresh_handle
        || handle.absolute_expires_at.secs() <= now.secs()
        || handle.absolute_expires_at
            > view
                .handle
                .absolute_expires_at
                .min(view.session.absolute_expires_at)
        || handle.revoked_at.is_some()
        || handle.revoked_reason.is_some()
        || code.client_ip != actor.client_ip
        || code.session_id != *sid
        || code.issued_aal != Aal::Two
        || i64::try_from(code.cred_gen).ok() != Some(generation)
        || !fresh_code
        || code.expires_at.secs() <= now.secs()
        || code.expires_at
            > now
                .add(std::time::Duration::from_secs(60))
                .min(view.session.absolute_expires_at)
        || code.consumed_at.is_some()
        || code.consumed_reason.is_some()
        || code.return_target.scheme() != "https"
        || code.return_target.host_str() != Some(code.host.as_str())
        || !code.return_target.username().is_empty()
        || code.return_target.password().is_some()
        || code.return_target.fragment().is_some()
    {
        return Err(conflict("invalid elevated credentials"));
    }
    Ok(())
}

/// Revoke every live handle of the session (one event per host) and consume
/// its codes, as an elevation does before issuing the new credentials.
pub(super) async fn rotate_credentials(
    store: &PgStore,
    tx: &Transaction<'_>,
    actor: &FactorActor,
    now: Timestamp,
    events: &mut Vec<Event>,
) -> StoreResult<()> {
    let sid = &actor.view.session.session_id;
    let hosts = tx
        .query(
            "SELECT host FROM session_handles WHERE session_id=$1 AND revoked_at IS NULL ORDER BY host, handle_sha256",
            &[&sid.as_str()],
        )
        .await
        .map_err(pg)?;
    for r in hosts {
        events.push(
            builder(store, EventKind::HandleRevoked, &actor.request_id)
                .user(actor.user())
                .session(sid)
                .reason(reasons::ELEVATION)
                .attr("host", r.get::<_, String>(0))
                .build(),
        );
    }
    write::revoke_session_handles(tx, sid, reasons::ELEVATION.0, now).await?;
    write::consume_session_codes(tx, sid, reasons::ELEVATION.0, now).await
}

/// End every live session of `user` with `reason`, one event each.
pub(super) async fn end_user_sessions(
    store: &PgStore,
    tx: &Transaction<'_>,
    user: &UserId,
    reason: crate::event::types::Reason,
    request_id: &str,
    attr: Option<(&str, &str)>,
) -> StoreResult<u32> {
    let now = store.now();
    let rows = tx
        .query(
            "SELECT session_id FROM sessions WHERE user_id=$1 AND terminated_at IS NULL ORDER BY session_id",
            &[&user.as_str()],
        )
        .await
        .map_err(pg)?;
    let mut n = 0u32;
    for r in rows {
        let sid = SessionId::new(r.get::<_, String>(0));
        let mut b = builder(store, EventKind::SessionTerminated, request_id)
            .user(user)
            .session(&sid)
            .reason(reason);
        if let Some((k, v)) = attr {
            b = b.attr(k, v);
        }
        if super::admin::terminate_in(store, tx, &sid, reason, now, &[b.build()]).await? {
            n += 1;
        }
    }
    Ok(n)
}

async fn snapshot_revision(tx: &Transaction<'_>) -> StoreResult<u64> {
    match write::meta(tx, "external_factor_snapshot_revision", true).await? {
        None => Ok(0),
        Some(v) => v
            .parse::<u64>()
            .ok()
            .filter(|v| *v > 0 && *v <= i64::MAX as u64)
            .ok_or(StoreError::Corrupt(
                "external factor snapshot revision".into(),
            )),
    }
}

async fn advance_snapshot_revision(tx: &Transaction<'_>) -> StoreResult<u64> {
    let revision = snapshot_revision(tx)
        .await?
        .checked_add(1)
        .filter(|v| *v <= i64::MAX as u64)
        .ok_or(conflict("external snapshot revision exhausted"))?;
    write::set_meta(
        tx,
        "external_factor_snapshot_revision",
        &revision.to_string(),
    )
    .await?;
    Ok(revision)
}

/// Apply one authority publication; `Ok(false)` when nothing changed.
async fn apply_external_publication(
    store: &PgStore,
    tx: &Transaction<'_>,
    request: &ExternalFactorPublication,
) -> StoreResult<bool> {
    write::require_stepup_generation(tx, Some(request.config_generation)).await?;
    let revision = i64::try_from(request.revision)
        .ok()
        .filter(|v| *v > 0)
        .ok_or(conflict("invalid external factor revision"))?;
    if request.factor.is_empty()
        || request.factor.len() > 128
        || !request
            .factor
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
    {
        return Err(conflict("invalid external factor id"));
    }
    let binding = request.binding.map(|b| b.to_vec());
    let old = tx
        .query_opt(
            "SELECT revision, binding, config_generation FROM external_factor_authorities WHERE factor=$1 FOR UPDATE",
            &[&request.factor],
        )
        .await
        .map_err(pg)?
        .map(|r| {
            (
                r.get::<_, i64>(0),
                r.get::<_, Option<Vec<u8>>>(1),
                r.get::<_, i64>(2),
            )
        });
    if let Some((old_revision, old_binding, old_generation)) = old {
        if u64::try_from(old_generation)
            .ok()
            .is_none_or(|g| g > request.config_generation)
        {
            return Err(conflict("external factor configuration epoch decreased"));
        }
        if revision < old_revision || (revision == old_revision && old_binding != binding) {
            return Err(conflict("external factor revision changed"));
        }
        if revision == old_revision && old_generation as u64 == request.config_generation {
            return Ok(false);
        }
        if revision != old_revision || old_binding != binding {
            let sessions = tx
                .query(
                    "SELECT s.session_id, s.user_id FROM external_factor_sessions e JOIN sessions s ON s.session_id=e.session_id \
                     WHERE e.factor=$1 AND s.terminated_at IS NULL ORDER BY s.session_id",
                    &[&request.factor],
                )
                .await
                .map_err(pg)?;
            for r in sessions {
                let sid = SessionId::new(r.get::<_, String>(0));
                let user = UserId::new(r.get::<_, String>(1));
                let event = builder(
                    store,
                    EventKind::SessionTerminated,
                    "r_external_factor_publication",
                )
                .user(&user)
                .session(&sid)
                .reason(reasons::FACTOR_REVOKED)
                .attr("factor_id", request.factor.as_str())
                .build();
                super::admin::terminate_in(
                    store,
                    tx,
                    &sid,
                    reasons::FACTOR_REVOKED,
                    store.now(),
                    &[event],
                )
                .await?;
            }
        }
    } else {
        let count: i64 = tx
            .query_one("SELECT count(*) FROM external_factor_authorities", &[])
            .await
            .map_err(pg)?
            .get(0);
        if count >= 64 {
            return Err(conflict("external factor capacity"));
        }
    }
    let generation = i64::try_from(request.config_generation)
        .map_err(|_| conflict("invalid configuration generation"))?;
    tx.execute(
        "INSERT INTO external_factor_authorities (factor, revision, binding, config_generation) VALUES ($1,$2,$3,$4) \
         ON CONFLICT (factor) DO UPDATE SET revision=excluded.revision, binding=excluded.binding, config_generation=excluded.config_generation",
        &[&request.factor, &revision, &binding, &generation],
    )
    .await
    .map_err(pg)?;
    let event = builder(
        store,
        EventKind::FactorAuthorityPublished,
        "r_external_factor_publication",
    )
    .attr("factor_id", request.factor.as_str())
    .build();
    store.insert_events(tx, &[event]).await?;
    Ok(true)
}

async fn registry_lock(tx: &Transaction<'_>) -> StoreResult<()> {
    tx.execute(
        "SELECT pg_advisory_xact_lock($1)",
        &[&EXTERNAL_REGISTRY_LOCK],
    )
    .await
    .map_err(pg)?;
    Ok(())
}

#[async_trait]
impl Factors for PgStore {
    async fn external_snapshot_revision(&self) -> StoreResult<u64> {
        let mut client = self.client().await?;
        let tx = self.begin(&mut client).await?;
        let v = snapshot_revision(&tx).await?;
        tx.commit().await.map_err(pg)?;
        Ok(v)
    }

    async fn publish_external_snapshot(&self, request: ExternalFactorSnapshot) -> StoreResult<u64> {
        super::retry(|| async {
            let mut client = self.client().await?;
            let tx = self.begin(&mut client).await?;
            registry_lock(&tx).await?;
            write::require_stepup_generation(&tx, Some(request.config_generation)).await?;
            if snapshot_revision(&tx).await? != request.expected_revision {
                return Err(conflict("external factor snapshot revision changed"));
            }
            if request.authorities.len() > 64 {
                return Err(conflict("external factor capacity"));
            }
            let mut desired = std::collections::BTreeSet::new();
            for a in &request.authorities {
                if !desired.insert(a.factor.as_str()) {
                    return Err(conflict("duplicate external factor id"));
                }
            }
            for a in &request.authorities {
                apply_external_publication(
                    self,
                    &tx,
                    &ExternalFactorPublication {
                        factor: a.factor.clone(),
                        revision: a.revision,
                        binding: Some(a.binding),
                        config_generation: request.config_generation,
                    },
                )
                .await?;
            }
            let old = tx
                .query(
                    "SELECT factor, revision, binding FROM external_factor_authorities ORDER BY factor",
                    &[],
                )
                .await
                .map_err(pg)?;
            for r in old {
                let factor: String = r.get(0);
                let revision: i64 = r.get(1);
                let binding: Option<Vec<u8>> = r.get(2);
                if desired.contains(factor.as_str()) {
                    continue;
                }
                let revision = if binding.is_some() {
                    revision
                        .checked_add(1)
                        .ok_or(conflict("external factor revision exhausted"))?
                } else {
                    revision
                };
                apply_external_publication(
                    self,
                    &tx,
                    &ExternalFactorPublication {
                        factor,
                        revision: u64::try_from(revision)
                            .map_err(|_| StoreError::Corrupt("external factor revision".into()))?,
                        binding: None,
                        config_generation: request.config_generation,
                    },
                )
                .await?;
            }
            let revision = advance_snapshot_revision(&tx).await?;
            let event = EventBuilder::new(
                self.clock.as_ref(),
                self.rng.as_ref(),
                EventKind::FactorRegistryPublished,
                Outcome::Success,
                "r_external_snapshot_publication",
            )
            .attr("count", request.authorities.len() as u64)
            .build();
            self.insert_events(&tx, &[event]).await?;
            tx.commit().await.map_err(pg)?;
            Ok(revision)
        })
        .await
    }

    async fn publish_external_factor(&self, request: ExternalFactorPublication) -> StoreResult<()> {
        super::retry(|| async {
            let mut client = self.client().await?;
            let tx = self.begin(&mut client).await?;
            registry_lock(&tx).await?;
            if apply_external_publication(self, &tx, &request).await? {
                advance_snapshot_revision(&tx).await?;
            }
            tx.commit().await.map_err(pg)
        })
        .await
    }

    async fn bind_external_stepup(&self, request: BindExternalStepUp) -> StoreResult<()> {
        super::retry(|| async {
            let now = self.now();
            let mut client = self.client().await?;
            let tx = self.begin(&mut client).await?;
            let actor = &request.actor;
            let view = &actor.view;
            lock_user(&tx, actor.user().as_str()).await?;
            require_actor(self, &tx, actor.user().as_str(), actor, ActorRule::Totp).await?;
            require_external_authority(&tx, &request.authority, request.config_generation).await?;
            let context = external_context(
                view.session.cred_gen,
                &request.authority,
                request.config_generation,
            )?;
            match bind_stepup(
                &tx,
                actor,
                &request.transaction,
                &request.portal_binding,
                &context,
                now,
            )
            .await?
            {
                None => return Err(conflict("external challenge unavailable")),
                Some(true) => {
                    let event = builder(self, EventKind::LoginStarted, &actor.request_id)
                        .user(actor.user())
                        .session(&view.session.session_id)
                        .reason(reasons::STEP_UP_REQUIRED)
                        .attr("factor_id", request.authority.factor.as_str())
                        .build();
                    let mut event = event;
                    event.outcome = Outcome::Info;
                    self.insert_events(&tx, &[event]).await?;
                }
                Some(false) => {}
            }
            tx.commit().await.map_err(pg)
        })
        .await
    }

    async fn elevate_external(&self, request: ExternalElevation) -> StoreResult<()> {
        super::retry(|| async {
            let now = self.now();
            let mut client = self.client().await?;
            let tx = self.begin(&mut client).await?;
            let actor = &request.actor;
            let view = &actor.view;
            let user = actor.user();
            let sid = &view.session.session_id;
            lock_user(&tx, user.as_str()).await?;
            require_actor(self, &tx, user.as_str(), actor, ActorRule::Totp).await?;
            let proof = &request.proof;
            require_external_authority(&tx, &proof.authority, request.config_generation).await?;
            if proof.user != user.as_str()
                || proof.session != sid.as_str()
                || proof.challenge != request.transaction.to_hex()
                || proof.credential_generation != view.session.cred_gen
                || proof.verified_at > now
                || proof.expires_at <= now
                || proof.deadline <= std::time::Instant::now()
                || now.since(proof.verified_at) > std::time::Duration::from_secs(5)
                || proof.expires_at > proof.verified_at.add(std::time::Duration::from_secs(5))
            {
                return Err(conflict("external proof context unavailable"));
            }
            let generation = view
                .session
                .cred_gen
                .checked_add(1)
                .and_then(|n| i64::try_from(n).ok())
                .ok_or(conflict("credential generation exhausted"))?;
            let handle = &request.portal_handle;
            let code = &request.handoff;
            check_elevated(actor, handle, code, generation, now, false)?;
            let consumed = tx
                .execute(
                    "UPDATE login_txns SET consumed_at=$2, consumed_reason='elevation' WHERE txn_sha256=$1 AND purpose='stepup' AND portal_session_id=$3 \
                     AND conflicting_handle_sha256=$4 AND bind_sha256=$5 AND return_target=$6 AND client_ip=$7 AND recovery_depth=$8 AND consumed_at IS NULL \
                     AND created_at<=$2 AND expires_at>$2 AND reauth_max_age IS NULL AND provider_id IS NULL AND state_sha256 IS NULL AND nonce IS NULL \
                     AND pkce_verifier IS NULL AND portal_bind_sha256=$9 AND pending_identity=$10 AND app_id=$11",
                    &[
                        &request.transaction.0.to_vec(),
                        &now.secs(),
                        &sid.as_str(),
                        &view.handle.handle_sha256.0.to_vec(),
                        &code.bind_sha256.0.to_vec(),
                        &code.return_target.as_str(),
                        &code.client_ip.to_string(),
                        &(code.recovery_depth.min(i32::MAX as u32) as i32),
                        &request.portal_binding.0.to_vec(),
                        &external_context(view.session.cred_gen, &proof.authority, request.config_generation)?,
                        &proof.service,
                    ],
                )
                .await
                .map_err(pg)?;
            if consumed != 1 {
                return Err(conflict("step-up challenge unavailable"));
            }
            let revision = i64::try_from(proof.authority.revision)
                .map_err(|_| conflict("invalid factor revision"))?;
            let inserted = tx
                .execute(
                    "INSERT INTO external_factor_proofs (factor, revision, proof_sha256, consumed_at_ms) VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING",
                    &[&proof.authority.factor, &revision, &proof.proof.0.to_vec(), &now.0],
                )
                .await
                .map_err(pg)?;
            if inserted != 1 {
                return Err(conflict("external proof already consumed"));
            }
            let mut factors = view.session.factors.clone();
            factors.push(FactorEntry {
                kind: FactorKind::External,
                provider: Some(crate::provider::types::ProviderId::new(format!(
                    "external:{}",
                    proof.authority.factor
                ))),
                at: now,
            });
            tx.execute(
                "INSERT INTO external_factor_sessions (factor, session_id, revision) VALUES ($1,$2,$3) ON CONFLICT (factor, session_id) DO UPDATE SET revision=excluded.revision",
                &[&proof.authority.factor, &sid.as_str(), &revision],
            )
            .await
            .map_err(pg)?;
            // An external second factor does not replace primary authentication time.
            tx.execute(
                "UPDATE sessions SET aal=2, factors=$2, cred_gen=$3 WHERE session_id=$1",
                &[&sid.as_str(), &factors_json(&factors)?, &generation],
            )
            .await
            .map_err(pg)?;
            let mut events = request.events.clone();
            rotate_credentials(self, &tx, actor, now, &mut events).await?;
            write::insert_handle(&tx, handle).await?;
            write::insert_code(&tx, code).await?;
            events.push(
                builder(self, EventKind::FactorExternalConsumed, &actor.request_id)
                    .user(user)
                    .session(sid)
                    .reason(reasons::ELEVATION)
                    .attr("factor_id", proof.authority.factor.as_str())
                    .build(),
            );
            events.push(
                builder(self, EventKind::SessionHandoff, &actor.request_id)
                    .user(user)
                    .session(sid)
                    .reason(reasons::ELEVATION)
                    .attr("host", code.host.as_str())
                    .build(),
            );
            self.insert_events(&tx, &events).await?;
            let final_now = self.now();
            if proof.deadline <= std::time::Instant::now()
                || proof.expires_at <= final_now
                || final_now < proof.verified_at
            {
                return Err(conflict("external proof expired before commit"));
            }
            tx.commit().await.map_err(pg)
        })
        .await
    }

    async fn bind_totp_stepup(&self, request: BindTotpStepUp) -> StoreResult<TotpChallengeBinding> {
        super::retry(|| async {
            let now = self.now();
            let mut client = self.client().await?;
            let tx = self.begin(&mut client).await?;
            let actor = &request.actor;
            let view = &actor.view;
            let user = actor.user();
            lock_user(&tx, user.as_str()).await?;
            require_actor(self, &tx, user.as_str(), actor, ActorRule::Totp).await?;
            write::require_stepup_generation(&tx, request.config_generation).await?;
            let (enrollment, revision) = tx
                .query_opt(
                    "SELECT enrollment_id, revision FROM totp_enrollments WHERE user_id=$1 AND state='active'",
                    &[&user.as_str()],
                )
                .await
                .map_err(pg)?
                .map(|r| (r.get::<_, String>(0), r.get::<_, i64>(1)))
                .ok_or(conflict("active factor unavailable"))?;
            let context =
                stepup_context(view.session.cred_gen, &enrollment, revision, request.config_generation)?;
            match bind_stepup(
                &tx,
                actor,
                &request.transaction,
                &request.portal_binding,
                &context,
                now,
            )
            .await?
            {
                None => return Err(conflict("step-up challenge unavailable")),
                Some(true) => {
                    let mut event = builder(self, EventKind::LoginStarted, &actor.request_id)
                        .user(user)
                        .session(&view.session.session_id)
                        .reason(reasons::STEP_UP_REQUIRED)
                        .attr("enrollment_id", enrollment.as_str())
                        .build();
                    event.outcome = Outcome::Info;
                    self.insert_events(&tx, &[event]).await?;
                }
                Some(false) => {}
            }
            let binding = TotpChallengeBinding {
                enrollment,
                revision: u64::try_from(revision)
                    .map_err(|_| StoreError::Corrupt("factor revision".into()))?,
            };
            tx.commit().await.map_err(pg)?;
            Ok(binding)
        })
        .await
    }

    async fn elevate_totp(&self, request: TotpElevation) -> StoreResult<()> {
        super::retry(|| async {
            let now = self.now();
            let mut client = self.client().await?;
            let tx = self.begin(&mut client).await?;
            let actor = &request.actor;
            let view = &actor.view;
            let user = actor.user();
            let sid = &view.session.session_id;
            lock_user(&tx, user.as_str()).await?;
            require_actor(self, &tx, user.as_str(), actor, ActorRule::Totp).await?;
            write::require_stepup_generation(&tx, request.config_generation).await?;
            let revision = i64::try_from(request.revision)
                .map_err(|_| conflict("invalid enrollment revision"))?;
            let counter =
                i64::try_from(request.counter).map_err(|_| conflict("invalid OTP counter"))?;
            let generation = view
                .session
                .cred_gen
                .checked_add(1)
                .and_then(|n| i64::try_from(n).ok())
                .ok_or(conflict("credential generation exhausted"))?;
            let handle = &request.portal_handle;
            let code = &request.handoff;
            check_elevated(actor, handle, code, generation, now, true)?;
            let consumed = tx
                .execute(
                    "UPDATE login_txns SET consumed_at=$2, consumed_reason='elevation' WHERE txn_sha256=$1 AND purpose='stepup' AND portal_session_id=$3 \
                     AND conflicting_handle_sha256=$4 AND bind_sha256=$5 AND return_target=$6 AND client_ip=$7 AND recovery_depth=$8 AND consumed_at IS NULL \
                     AND created_at<=$2 AND expires_at>$2 AND reauth_max_age IS NULL AND provider_id IS NULL AND state_sha256 IS NULL AND nonce IS NULL \
                     AND pkce_verifier IS NULL AND portal_bind_sha256=$9 AND pending_identity=$10",
                    &[
                        &request.transaction.0.to_vec(),
                        &now.secs(),
                        &sid.as_str(),
                        &view.handle.handle_sha256.0.to_vec(),
                        &code.bind_sha256.0.to_vec(),
                        &code.return_target.as_str(),
                        &code.client_ip.to_string(),
                        &(code.recovery_depth.min(i32::MAX as u32) as i32),
                        &request.portal_binding.0.to_vec(),
                        &stepup_context(view.session.cred_gen, &request.enrollment, revision, request.config_generation)?,
                    ],
                )
                .await
                .map_err(pg)?;
            if consumed != 1 {
                return Err(conflict("step-up challenge unavailable"));
            }
            let used = tx
                .execute(
                    "UPDATE totp_enrollments SET last_counter=$4, updated_at=$5 WHERE enrollment_id=$1 AND user_id=$2 AND revision=$3 AND state='active' AND last_counter<$4",
                    &[&request.enrollment, &user.as_str(), &revision, &counter, &now.secs()],
                )
                .await
                .map_err(pg)?;
            if used != 1 {
                return Err(conflict("factor proof unavailable"));
            }
            let mut factors = view.session.factors.clone();
            factors.push(FactorEntry {
                kind: FactorKind::Totp,
                provider: None,
                at: now,
            });
            // Preserve the primary authentication time: OTP is not provider reauthentication.
            tx.execute(
                "UPDATE sessions SET aal=2, factors=$2, cred_gen=$3 WHERE session_id=$1",
                &[&sid.as_str(), &factors_json(&factors)?, &generation],
            )
            .await
            .map_err(pg)?;
            let index = i64::try_from(factors.len() - 1)
                .map_err(|_| conflict("factor provenance exhausted"))?;
            let config_generation = request
                .config_generation
                .map(i64::try_from)
                .transpose()
                .map_err(|_| conflict("invalid configuration generation"))?;
            record_totp_provenance(
                &tx,
                sid,
                user,
                generation,
                &request.enrollment,
                revision,
                index,
                now,
                config_generation,
            )
            .await?;
            let mut events = request.events.clone();
            rotate_credentials(self, &tx, actor, now, &mut events).await?;
            write::insert_handle(&tx, handle).await?;
            write::insert_code(&tx, code).await?;
            let mut proof_event = factor_event(
                self,
                user,
                &request.enrollment,
                EventKind::FactorTotpConsumed,
                &actor.request_id,
            );
            proof_event.session_id = Some(sid.clone());
            proof_event.reason = Some(reasons::ELEVATION);
            events.push(proof_event);
            events.push(
                builder(self, EventKind::SessionHandoff, &actor.request_id)
                    .user(user)
                    .session(sid)
                    .reason(reasons::ELEVATION)
                    .attr("host", code.host.as_str())
                    .build(),
            );
            self.insert_events(&tx, &events).await?;
            tx.commit().await.map_err(pg)
        })
        .await
    }

    async fn has_active_totp(&self, user: &UserId) -> StoreResult<bool> {
        let client = self.client().await?;
        Ok(client
            .query_opt(
                "SELECT 1 FROM totp_enrollments t JOIN users u ON u.user_id=t.user_id WHERE t.user_id=$1 AND t.state='active' AND u.status='active'",
                &[&user.as_str()],
            )
            .await
            .map_err(pg)?
            .is_some())
    }

    async fn activate_totp_authorized(
        &self,
        id: &str,
        actor: FactorActor,
        revision: u64,
        counter: u64,
        events: Vec<Event>,
    ) -> StoreResult<bool> {
        let user = actor.user().clone();
        self.mutate_totp(
            id,
            &user,
            revision,
            Some(counter),
            TotpOp::Activate,
            Some(&actor),
            events,
        )
        .await
    }

    async fn revoke_totp_authorized(
        &self,
        id: &str,
        actor: FactorActor,
        revision: u64,
        events: Vec<Event>,
    ) -> StoreResult<bool> {
        let user = actor.user().clone();
        self.mutate_totp(
            id,
            &user,
            revision,
            None,
            TotpOp::Revoke,
            Some(&actor),
            events,
        )
        .await
    }

    async fn create_totp_pending_authorized(
        &self,
        id: String,
        actor: FactorActor,
        envelope: crate::factor::seed_cipher::Envelope,
        events: Vec<Event>,
    ) -> StoreResult<()> {
        let user = actor.user().clone();
        self.create_pending(id, user, envelope, events, Some(&actor))
            .await
    }

    async fn totp_enrollment(
        &self,
        id: &str,
        user: &UserId,
    ) -> StoreResult<Option<TotpEnrollment>> {
        let client = self.client().await?;
        let row = client
            .query_opt(
                "SELECT revision, state, last_counter, envelope FROM totp_enrollments WHERE enrollment_id=$1 AND user_id=$2 AND state<>'revoked' \
                 AND (state='active' OR pending_expires_at>$3) AND EXISTS (SELECT 1 FROM users WHERE user_id=$2 AND status='active')",
                &[&id, &user.as_str(), &self.now().secs()],
            )
            .await
            .map_err(pg)?;
        row.map(|r| {
            let revision = u64::try_from(r.get::<_, i64>(0))
                .ok()
                .filter(|n| *n > 0)
                .ok_or_else(|| StoreError::Corrupt("totp revision".into()))?;
            let last_counter = r
                .get::<_, Option<i64>>(2)
                .map(u64::try_from)
                .transpose()
                .map_err(|_| StoreError::Corrupt("totp counter".into()))?;
            let envelope = crate::factor::seed_cipher::Envelope::from_json(&r.get::<_, String>(3))
                .map_err(|_| StoreError::Corrupt("totp envelope".into()))?;
            Ok(TotpEnrollment {
                enrollment_id: id.to_owned(),
                user_id: user.clone(),
                revision,
                active: r.get::<_, String>(1) == "active",
                last_counter,
                envelope,
            })
        })
        .transpose()
    }

    async fn create_totp_pending(
        &self,
        id: String,
        user: UserId,
        envelope: crate::factor::seed_cipher::Envelope,
        events: Vec<Event>,
    ) -> StoreResult<()> {
        self.create_pending(id, user, envelope, events, None).await
    }

    async fn activate_totp(
        &self,
        id: &str,
        user: &UserId,
        revision: u64,
        counter: u64,
        events: Vec<Event>,
    ) -> StoreResult<bool> {
        self.mutate_totp(
            id,
            user,
            revision,
            Some(counter),
            TotpOp::Activate,
            None,
            events,
        )
        .await
    }

    async fn consume_totp_counter(
        &self,
        id: &str,
        user: &UserId,
        revision: u64,
        counter: u64,
        events: Vec<Event>,
    ) -> StoreResult<bool> {
        self.mutate_totp(
            id,
            user,
            revision,
            Some(counter),
            TotpOp::Consume,
            None,
            events,
        )
        .await
    }

    async fn revoke_totp(
        &self,
        id: &str,
        user: &UserId,
        revision: u64,
        events: Vec<Event>,
    ) -> StoreResult<bool> {
        self.mutate_totp(id, user, revision, None, TotpOp::Revoke, None, events)
            .await
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn record_totp_provenance(
    tx: &Transaction<'_>,
    sid: &SessionId,
    user: &UserId,
    generation: i64,
    enrollment: &str,
    revision: i64,
    index: i64,
    now: Timestamp,
    config_generation: Option<i64>,
) -> StoreResult<()> {
    let linked = tx
        .execute(
            "INSERT INTO session_totp_provenance (session_id, user_id, credential_generation, enrollment_id, enrollment_revision, factor_index, verified_at_ms, config_generation) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (session_id) DO UPDATE SET user_id=excluded.user_id, credential_generation=excluded.credential_generation, \
             enrollment_id=excluded.enrollment_id, enrollment_revision=excluded.enrollment_revision, factor_index=excluded.factor_index, \
             verified_at_ms=excluded.verified_at_ms, config_generation=excluded.config_generation \
             WHERE excluded.user_id=session_totp_provenance.user_id AND excluded.credential_generation>session_totp_provenance.credential_generation",
            &[&sid.as_str(), &user.as_str(), &generation, &enrollment, &revision, &index, &now.0, &config_generation],
        )
        .await
        .map_err(pg)?;
    if linked != 1 {
        return Err(conflict("TOTP provenance generation unavailable"));
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum TotpOp {
    Activate,
    Consume,
    Revoke,
}

impl PgStore {
    async fn create_pending(
        &self,
        id: String,
        user: UserId,
        envelope: crate::factor::seed_cipher::Envelope,
        events: Vec<Event>,
        actor: Option<&FactorActor>,
    ) -> StoreResult<()> {
        if id.is_empty()
            || id.len() > 128
            || !id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
        {
            return Err(conflict("invalid enrollment id"));
        }
        let envelope = serde_json::to_string(&envelope)
            .map_err(|_| StoreError::Corrupt("totp envelope".into()))?;
        crate::factor::seed_cipher::Envelope::from_json(&envelope)
            .map_err(|_| StoreError::Corrupt("totp envelope".into()))?;
        let request_id = actor
            .map(|a| a.request_id.as_str())
            .unwrap_or("r_totp_store");
        super::retry(|| async {
            let now = self.now();
            let mut client = self.client().await?;
            let tx = self.begin(&mut client).await?;
            if lock_user(&tx, user.as_str()).await?.as_deref() != Some("active") {
                return Err(conflict("user unavailable"));
            }
            if let Some(actor) = actor {
                require_actor(self, &tx, user.as_str(), actor, ActorRule::Totp).await?;
                let enrolled = tx
                    .query_opt(
                        "SELECT 1 FROM totp_enrollments WHERE user_id=$1 AND state='active'",
                        &[&user.as_str()],
                    )
                    .await
                    .map_err(pg)?
                    .is_some();
                if enrolled {
                    return Err(conflict("active factor requires replacement flow"));
                }
                // ADR-0017 decision 10: with a passkey present, adding a factor needs a recent second factor.
                let passkeys = tx
                    .query_opt(
                        "SELECT 1 FROM webauthn_credentials WHERE user_id=$1 AND state='active'",
                        &[&user.as_str()],
                    )
                    .await
                    .map_err(pg)?
                    .is_some();
                if passkeys
                    && !crate::store::sqlite::webauthn::recent_second_factor(&actor.view.session.factors, now)
                {
                    return Err(conflict(crate::store::passkeys::refusal::VERIFICATION_REQUIRED));
                }
            }
            let expired = tx
                .query_opt(
                    "SELECT enrollment_id FROM totp_enrollments WHERE user_id=$1 AND state='pending' AND pending_expires_at<=$2",
                    &[&user.as_str(), &now.secs()],
                )
                .await
                .map_err(pg)?
                .map(|r| r.get::<_, String>(0));
            if let Some(expired) = expired {
                tx.execute(
                    "UPDATE totp_enrollments SET state='revoked', revision=revision+1, pending_expires_at=NULL, updated_at=$2 WHERE enrollment_id=$1",
                    &[&expired, &now.secs()],
                )
                .await
                .map_err(pg)?;
                self.insert_events(
                    &tx,
                    &[factor_event(self, &user, &expired, EventKind::FactorEnrollmentExpired, request_id)],
                )
                .await?;
            }
            tx.execute(
                "INSERT INTO totp_enrollments (enrollment_id, user_id, envelope, revision, state, pending_expires_at, created_at, updated_at) VALUES ($1,$2,$3,1,'pending',$4,$5,$5)",
                &[&id, &user.as_str(), &envelope, &now.secs().saturating_add(600), &now.secs()],
            )
            .await
            .map_err(pg)?;
            self.insert_events(
                &tx,
                &[factor_event(self, &user, &id, EventKind::FactorEnrollmentPrepared, request_id)],
            )
            .await?;
            self.insert_events(&tx, &events).await?;
            tx.commit().await.map_err(pg)
        })
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn mutate_totp(
        &self,
        id: &str,
        user: &UserId,
        revision: u64,
        counter: Option<u64>,
        op: TotpOp,
        actor: Option<&FactorActor>,
        events: Vec<Event>,
    ) -> StoreResult<bool> {
        let revision =
            i64::try_from(revision).map_err(|_| conflict("invalid enrollment revision"))?;
        let counter = counter
            .map(i64::try_from)
            .transpose()
            .map_err(|_| conflict("invalid OTP counter"))?;
        let request_id = actor
            .map(|a| a.request_id.as_str())
            .unwrap_or("r_totp_store");
        super::retry(|| async {
            let now = self.now();
            let mut client = self.client().await?;
            let tx = self.begin(&mut client).await?;
            lock_user(&tx, user.as_str()).await?;
            let active = tx
                .query_opt(
                    "SELECT 1 FROM totp_enrollments WHERE enrollment_id=$1 AND user_id=$2 AND state='active'",
                    &[&id, &user.as_str()],
                )
                .await
                .map_err(pg)?
                .is_some();
            let was_active = op == TotpOp::Revoke && active;
            if let Some(actor) = actor {
                require_actor(self, &tx, user.as_str(), actor, ActorRule::Totp).await?;
                if op == TotpOp::Revoke {
                    let recent_mfa = actor.view.session.factors.iter().any(|f| {
                        matches!(
                            f.kind,
                            FactorKind::Totp | FactorKind::Webauthn | FactorKind::External
                        ) && f.at <= now
                            && now.since(f.at) <= std::time::Duration::from_secs(300)
                    });
                    if active
                        && (actor.view.session.aal < Aal::Two
                            || actor.view.handle.issued_aal < Aal::Two
                            || !recent_mfa)
                    {
                        return Err(conflict("active factor removal requires step-up"));
                    }
                }
            }
            let sql = match op {
                TotpOp::Activate => "UPDATE totp_enrollments SET state='active', revision=revision+1, last_counter=$4, pending_expires_at=NULL, updated_at=$5 \
                    WHERE enrollment_id=$1 AND user_id=$2 AND revision=$3 AND state='pending' AND pending_expires_at>$5 \
                    AND EXISTS (SELECT 1 FROM users WHERE user_id=$2 AND status='active')",
                TotpOp::Consume => "UPDATE totp_enrollments SET last_counter=$4, updated_at=$5 \
                    WHERE enrollment_id=$1 AND user_id=$2 AND revision=$3 AND state='active' AND last_counter<$4 \
                    AND EXISTS (SELECT 1 FROM users WHERE user_id=$2 AND status='active')",
                TotpOp::Revoke => "UPDATE totp_enrollments SET state='revoked', revision=revision+1, pending_expires_at=NULL, updated_at=$5 \
                    WHERE enrollment_id=$1 AND user_id=$2 AND revision=$3 AND state<>'revoked' AND $4::bigint IS NULL",
            };
            let n = tx
                .execute(sql, &[&id, &user.as_str(), &revision, &counter, &now.secs()])
                .await
                .map_err(pg)?;
            if n != 1 {
                return Ok(false);
            }
            if op == TotpOp::Activate {
                // A new factor satisfies the re-enrollment requirement of a used recovery code (ADR-0017).
                tx.execute(
                    "UPDATE users SET factor_recovery_required_at=NULL WHERE user_id=$1",
                    &[&user.as_str()],
                )
                .await
                .map_err(pg)?;
            }
            if was_active {
                end_user_sessions(self, &tx, user, reasons::FACTOR_REVOKED, "r_totp_store", None)
                    .await?;
            }
            let kind = match op {
                TotpOp::Activate => EventKind::FactorEnrollmentActivated,
                TotpOp::Consume => EventKind::FactorTotpConsumed,
                TotpOp::Revoke => EventKind::FactorEnrollmentRevoked,
            };
            self.insert_events(&tx, &[factor_event(self, user, id, kind, request_id)])
                .await?;
            self.insert_events(&tx, &events).await?;
            tx.commit().await.map_err(pg)?;
            Ok(true)
        })
        .await
    }
}
