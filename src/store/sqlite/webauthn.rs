//! `Passkeys` for SQLite (ADR-0017): WebAuthn credentials, single-use ceremony
//! rows, recovery codes, portal and application elevation.
//!
//! Every write re-checks the acting session ([`require_security_actor`]) and
//! evaluates the factor-management rule against the re-checked values in the
//! same `BEGIN IMMEDIATE` transaction as the change and its required events.

use async_trait::async_trait;
use rusqlite::{OptionalExtension, Transaction, params};

use super::events::insert_events;
use super::rows::blob;
use super::{Shared, Store, commit};
use crate::crypto::{Digest, Timestamp};
use crate::event::types::{Event, EventBuilder, EventKind, Outcome, reasons};
use crate::identity::types::UserId;
use crate::session::types::{Aal, FactorEntry, FactorKind, SessionId};
use crate::store::passkeys::*;
use crate::store::{FactorActor, HandleRow, HandoffCodeRow, StoreError, StoreResult};

const PASSKEY_COLS: &str = "credential_id,user_id,label,passkey,aaguid,transports,backup_eligible,backup_state,user_verified,attestation_format,attested,assurance,sign_count,created_at,last_used_at,revision";

fn conflict(what: &'static str) -> StoreError {
    StoreError::Conflict(what)
}

/// `pk_` plus 16 hex digits of SHA-256 over the credential id: the only form
/// a credential id takes in events and logs.
pub(crate) fn factor_id(credential_id: &[u8]) -> String {
    use sha2::{Digest as _, Sha256};
    let d = Sha256::digest(credential_id);
    let hex: String = d.iter().take(8).map(|b| format!("{b:02x}")).collect();
    format!("pk_{hex}")
}

fn passkey_row(r: &rusqlite::Row<'_>) -> StoreResult<PasskeyRecord> {
    let corrupt = |c: &str| StoreError::Corrupt(format!("webauthn_credentials.{c}"));
    let aaguid: Option<Vec<u8>> = r.get(4)?;
    let aaguid = aaguid
        .map(|v| <[u8; 16]>::try_from(v.as_slice()).map_err(|_| corrupt("aaguid")))
        .transpose()?;
    let transports: String = r.get(5)?;
    let transports: Vec<String> =
        serde_json::from_str(&transports).map_err(|_| corrupt("transports"))?;
    let assurance: String = r.get(11)?;
    let sign_count: i64 = r.get(12)?;
    let revision: i64 = r.get(15)?;
    Ok(PasskeyRecord {
        credential_id: r.get(0)?,
        user_id: UserId::new(r.get::<_, String>(1)?),
        label: r.get(2)?,
        passkey: r.get(3)?,
        aaguid,
        transports,
        backup_eligible: r.get(6)?,
        backup_state: r.get(7)?,
        user_verified: r.get(8)?,
        attestation_format: r.get(9)?,
        attested: r.get(10)?,
        assurance: Assurance::parse(&assurance).ok_or_else(|| corrupt("assurance"))?,
        sign_count: u32::try_from(sign_count).map_err(|_| corrupt("sign_count"))?,
        created_at: Timestamp::from_secs(r.get(13)?),
        last_used_at: r.get::<_, Option<i64>>(14)?.map(Timestamp::from_secs),
        revision: u64::try_from(revision).map_err(|_| corrupt("revision"))?,
    })
}

/// Whether `factors` holds a second-factor entry (recovery included) at most
/// [`MANAGEMENT_WINDOW`] old and not in the future.
pub(crate) fn recent_second_factor(factors: &[FactorEntry], now: Timestamp) -> bool {
    factors.iter().any(|f| {
        matches!(
            f.kind,
            FactorKind::Webauthn | FactorKind::Totp | FactorKind::External | FactorKind::Recovery
        ) && f.at <= now
            && now.since(f.at) <= MANAGEMENT_WINDOW
    })
}

/// ADR-0017 decision 10: a recent second factor, or — for a user without
/// one — a primary sign-in at most five minutes old.
pub(crate) fn management_allowed(
    factors: &[FactorEntry],
    auth_time: Timestamp,
    has_second_factor: bool,
    now: Timestamp,
) -> bool {
    recent_second_factor(factors, now)
        || (!has_second_factor && auth_time <= now && now.since(auth_time) <= MANAGEMENT_WINDOW)
}

/// The acting portal session is still exactly what the actor saw: live
/// session and handle, same generation, primary time, factors and
/// authorization version, active user, live provider with the same
/// configuration. Unlike TOTP enrollment, primary freshness is not required
/// here; each operation applies [`management_allowed`] itself.
fn require_security_actor(
    tx: &Transaction<'_>,
    shared: &Shared,
    actor: &FactorActor,
) -> StoreResult<()> {
    let now = shared.clock.now();
    if now < actor.authorized_at
        || now.since(actor.authorized_at) > std::time::Duration::from_secs(5)
    {
        return Err(conflict("factor authorization expired"));
    }
    let view = &actor.view;
    super::sessions::require_provider_configuration(
        tx,
        view.session.provider_id.as_str(),
        Some(&actor.provider_configuration),
    )?;
    let live: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM sessions s JOIN session_handles h ON h.session_id=s.session_id JOIN users u ON u.user_id=s.user_id JOIN providers p ON p.provider_id=s.provider_id \
         WHERE s.session_id=?1 AND s.user_id=?2 AND h.handle_sha256=?3 AND h.host=?4 AND s.cred_gen=?5 AND s.auth_time=?6 \
         AND s.authz_version_at_auth=u.authz_version AND u.status='active' AND s.terminated_at IS NULL AND h.revoked_at IS NULL \
         AND p.enabled=1 AND p.deleted_at IS NULL AND s.aal=?10 AND h.issued_aal=?11 AND s.absolute_expires_at>?7 AND h.absolute_expires_at>?7 \
         AND s.last_seen_at>?8 AND h.last_seen_at>?9 AND s.auth_time<=?7 AND s.factors=?12)",
        params![
            view.session.session_id.as_str(),
            view.session.user_id.as_str(),
            blob(&view.handle.handle_sha256),
            view.handle.host.as_str(),
            i64::try_from(view.session.cred_gen).map_err(|_| conflict("credential generation"))?,
            view.session.auth_time.secs(),
            now.secs(),
            now.secs().saturating_sub(actor.session_idle.as_secs() as i64),
            now.secs().saturating_sub(actor.handle_idle.as_secs() as i64),
            view.session.aal.as_i64(),
            view.handle.issued_aal.as_i64(),
            super::rows::json_str(&view.session.factors)?,
        ],
        |r| r.get(0),
    )?;
    if !live {
        return Err(conflict("factor authorization revoked"));
    }
    Ok(())
}

fn second_factor_count(tx: &Transaction<'_>, user: &str) -> StoreResult<i64> {
    Ok(tx.query_row(
        "SELECT (SELECT COUNT(*) FROM webauthn_credentials WHERE user_id=?1 AND state='active') \
              + (SELECT COUNT(*) FROM totp_enrollments WHERE user_id=?1 AND state='active')",
        [user],
        |r| r.get(0),
    )?)
}

fn require_management(
    tx: &Transaction<'_>,
    shared: &Shared,
    actor: &FactorActor,
) -> StoreResult<()> {
    let has = second_factor_count(tx, actor.user().as_str())? > 0;
    let view = &actor.view;
    if !management_allowed(
        &view.session.factors,
        view.session.auth_time,
        has,
        shared.clock.now(),
    ) {
        return Err(conflict(refusal::VERIFICATION_REQUIRED));
    }
    Ok(())
}

/// Consume a live ceremony of `purpose` bound to the actor's session, handle,
/// portal binding and generation (and, for step-up, `transaction`).
fn consume_ceremony(
    tx: &Transaction<'_>,
    actor: &FactorActor,
    digest: &Digest,
    purpose: CeremonyPurpose,
    portal_binding: &Digest,
    transaction: Option<&Digest>,
    now: Timestamp,
) -> StoreResult<()> {
    let view = &actor.view;
    let n = tx.execute(
        "UPDATE webauthn_challenges SET consumed_at=?9 WHERE challenge_sha256=?1 AND purpose=?2 AND user_id=?3 AND session_id=?4 \
         AND handle_sha256=?5 AND portal_bind_sha256=?6 AND credential_generation=?7 AND txn_sha256 IS ?8 \
         AND consumed_at IS NULL AND created_at<=?9 AND expires_at>?9",
        params![
            blob(digest),
            purpose.as_str(),
            view.session.user_id.as_str(),
            view.session.session_id.as_str(),
            blob(&view.handle.handle_sha256),
            blob(portal_binding),
            i64::try_from(view.session.cred_gen).map_err(|_| conflict("credential generation"))?,
            transaction.map(blob),
            now.secs(),
        ],
    )?;
    if n != 1 {
        return Err(conflict(refusal::CEREMONY_UNAVAILABLE));
    }
    Ok(())
}

fn event(shared: &Shared, kind: EventKind, outcome: Outcome, request_id: &str) -> EventBuilder {
    EventBuilder::new(
        shared.clock.as_ref(),
        shared.rng().as_ref(),
        kind,
        outcome,
        request_id,
    )
}

/// Record the verified use of a credential: the counter only moves forward
/// (equal is allowed only while both are zero, as synchronized passkeys
/// report), flags and the serialized credential follow the assertion.
fn apply_use(
    tx: &Transaction<'_>,
    user: &str,
    used: &PasskeyUse,
    now: Timestamp,
) -> StoreResult<()> {
    let n = tx.execute(
        "UPDATE webauthn_credentials SET passkey=?3, sign_count=?4, backup_eligible=?5, backup_state=?6, last_used_at=?7, revision=revision+1 \
         WHERE credential_id=?1 AND user_id=?2 AND state='active' AND (sign_count<?4 OR (sign_count=0 AND ?4=0)) \
         AND (?8='aal2' OR (assurance='aal3' AND ?5=0 AND ?6=0))",
        params![
            used.credential_id,
            user,
            used.passkey,
            i64::from(used.sign_count),
            used.backup_eligible,
            used.backup_state,
            now.secs(),
            used.assurance.as_str(),
        ],
    )?;
    if n != 1 {
        let active: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM webauthn_credentials WHERE credential_id=?1 AND user_id=?2 AND state='active')",
            params![used.credential_id, user],
            |r| r.get(0),
        )?;
        return Err(conflict(if active {
            refusal::COUNTER_STALE
        } else {
            "credential unavailable"
        }));
    }
    Ok(())
}

/// Rotate a session after a portal or application elevation (ADR-0008):
/// raise `aal` to `aal`, append `entry`, increment the generation, revoke
/// every handle and consume every outstanding code, with their events.
fn rotate(
    tx: &Transaction<'_>,
    shared: &Shared,
    actor: &FactorActor,
    aal: Aal,
    entry: FactorEntry,
    events: &mut Vec<Event>,
) -> StoreResult<i64> {
    let view = &actor.view;
    let sid = &view.session.session_id;
    let now = shared.clock.now();
    let generation = view
        .session
        .cred_gen
        .checked_add(1)
        .and_then(|n| i64::try_from(n).ok())
        .ok_or(conflict("credential generation exhausted"))?;
    let mut factors = view.session.factors.clone();
    factors.push(entry);
    tx.execute(
        "UPDATE sessions SET aal=?2, factors=?3, cred_gen=?4 WHERE session_id=?1",
        params![
            sid.as_str(),
            aal.as_i64(),
            super::rows::json_str(&factors)?,
            generation
        ],
    )?;
    let live: Vec<String> = tx
        .prepare("SELECT host FROM session_handles WHERE session_id=?1 AND revoked_at IS NULL ORDER BY host,handle_sha256")?
        .query_map([sid.as_str()], |r| r.get(0))?
        .collect::<Result<_, _>>()?;
    for host in live {
        events.push(
            event(
                shared,
                EventKind::HandleRevoked,
                Outcome::Success,
                &actor.request_id,
            )
            .user(actor.user())
            .session(sid)
            .reason(reasons::ELEVATION)
            .attr("host", host)
            .build(),
        );
    }
    super::sessions::revoke_session_handles(tx, sid, reasons::ELEVATION.0, now)?;
    super::sessions::consume_session_codes(tx, sid, reasons::ELEVATION.0, now)?;
    Ok(generation)
}

/// The reissued portal handle must belong to the acting session and host,
/// be new, start now at `aal` and not outlive the old handle or the session.
fn check_portal_handle(
    actor: &FactorActor,
    handle: &HandleRow,
    aal: Aal,
    now: Timestamp,
) -> StoreResult<()> {
    let view = &actor.view;
    if handle.session_id != view.session.session_id
        || handle.host != view.handle.host
        || handle.handle_sha256 == view.handle.handle_sha256
        || handle.issued_aal != aal
        || handle.created_at.secs() != now.secs()
        || handle.last_seen_at.secs() != now.secs()
        || handle.absolute_expires_at.secs() <= now.secs()
        || handle.absolute_expires_at
            > view
                .handle
                .absolute_expires_at
                .min(view.session.absolute_expires_at)
        || handle.revoked_at.is_some()
        || handle.revoked_reason.is_some()
    {
        return Err(conflict("invalid elevated credentials"));
    }
    Ok(())
}

fn check_handoff(
    actor: &FactorActor,
    code: &HandoffCodeRow,
    generation: i64,
    now: Timestamp,
) -> StoreResult<()> {
    let view = &actor.view;
    if code.client_ip != actor.client_ip
        || code.session_id != view.session.session_id
        || code.issued_aal != Aal::Two
        || i64::try_from(code.cred_gen).ok() != Some(generation)
        || code.created_at.secs() != now.secs()
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

/// End every live session of `user` that `credential_id` elevated, except `keep`.
fn end_elevated_sessions(
    tx: &Transaction<'_>,
    shared: &Shared,
    user: &UserId,
    credential_id: &[u8],
    keep: Option<&SessionId>,
    reason: crate::event::types::Reason,
    request_id: &str,
) -> StoreResult<u32> {
    let now = shared.clock.now();
    let sessions: Vec<String> = tx
        .prepare(
            "SELECT s.session_id FROM session_webauthn_elevations e JOIN sessions s ON s.session_id=e.session_id \
             WHERE e.credential_id=?1 AND s.user_id=?2 AND s.terminated_at IS NULL ORDER BY s.session_id",
        )?
        .query_map(params![credential_id, user.as_str()], |r| r.get(0))?
        .collect::<Result<_, _>>()?;
    let mut ended = 0;
    for id in sessions {
        let id = SessionId::new(id);
        if keep == Some(&id) {
            continue;
        }
        let ev = event(
            shared,
            EventKind::SessionTerminated,
            Outcome::Success,
            request_id,
        )
        .user(user)
        .session(&id)
        .reason(reason)
        .build();
        super::sessions::terminate_in(tx, shared, &id, reason, now, &[ev])?;
        ended += 1;
    }
    Ok(ended)
}

#[async_trait]
impl Passkeys for Store {
    async fn passkey_user_handle(
        &self,
        user: &UserId,
        candidate: [u8; 16],
    ) -> StoreResult<[u8; 16]> {
        let user = user.clone();
        self.write("passkey_user_handle", move |env| {
            let shared = env.shared.clone();
            let tx = env.begin()?;
            tx.execute(
                "UPDATE users SET webauthn_user_handle=?2 WHERE user_id=?1 AND webauthn_user_handle IS NULL AND status='active'",
                params![user.as_str(), &candidate[..]],
            )?;
            let handle: Option<Option<Vec<u8>>> = tx
                .query_row("SELECT webauthn_user_handle FROM users WHERE user_id=?1 AND status='active'", [user.as_str()], |r| r.get(0))
                .optional()?;
            let handle = handle
                .flatten()
                .ok_or(conflict("user unavailable"))
                .and_then(|v| <[u8; 16]>::try_from(v.as_slice()).map_err(|_| StoreError::Corrupt("users.webauthn_user_handle".into())))?;
            commit(tx, &shared, None)?;
            Ok(handle)
        })
        .await
    }

    async fn factor_summary(&self, user: &UserId) -> StoreResult<FactorSummary> {
        let user = user.clone();
        self.read("factor_summary", move |conn| {
            let passkeys = conn
                .prepare(&format!("SELECT {PASSKEY_COLS} FROM webauthn_credentials WHERE user_id=?1 AND state='active' ORDER BY created_at, credential_id"))?
                .query_map([user.as_str()], |r| Ok(passkey_row(r)))?
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .collect::<StoreResult<Vec<_>>>()?;
            let totp_active: bool = conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM totp_enrollments WHERE user_id=?1 AND state='active')",
                [user.as_str()],
                |r| r.get(0),
            )?;
            let (unused, generated): (i64, Option<i64>) = conn.query_row(
                "SELECT COUNT(*) FILTER (WHERE used_at IS NULL), MAX(created_at) FROM recovery_codes WHERE user_id=?1",
                [user.as_str()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            let required: Option<i64> = conn
                .query_row("SELECT factor_recovery_required_at FROM users WHERE user_id=?1", [user.as_str()], |r| r.get(0))
                .optional()?
                .flatten();
            Ok(FactorSummary {
                passkeys,
                totp_active,
                recovery_unused: u32::try_from(unused).unwrap_or(0),
                recovery_generated_at: generated.map(Timestamp::from_secs),
                recovery_required_at: required.map(Timestamp::from_secs),
            })
        })
        .await
    }

    async fn begin_ceremony(&self, ceremony: NewCeremony) -> StoreResult<()> {
        if ceremony.state.len() > 65_536
            || (ceremony.purpose == CeremonyPurpose::StepUp) != ceremony.transaction.is_some()
        {
            return Err(conflict("invalid ceremony"));
        }
        self.write("begin_webauthn_ceremony", move |env| {
            let shared = env.shared.clone();
            let now = shared.clock.now();
            let tx = env.begin()?;
            let actor = &ceremony.actor;
            let view = &actor.view;
            require_security_actor(&tx, &shared, actor)?;
            if ceremony.expires_at <= now || ceremony.expires_at.since(now) > std::time::Duration::from_secs(600) {
                return Err(conflict("invalid ceremony"));
            }
            if let Some(txn) = &ceremony.transaction {
                let live: bool = tx.query_row(
                    "SELECT EXISTS(SELECT 1 FROM login_txns WHERE txn_sha256=?1 AND purpose='stepup' AND portal_session_id=?2 AND client_ip=?3 \
                     AND bind_sha256 IS NOT NULL AND consumed_at IS NULL AND created_at<=?4 AND expires_at>?4 AND provider_id IS NULL \
                     AND state_sha256 IS NULL AND nonce IS NULL AND pkce_verifier IS NULL AND reauth_max_age IS NULL \
                     AND (portal_bind_sha256 IS NULL OR portal_bind_sha256=?5) AND (conflicting_handle_sha256 IS NULL OR conflicting_handle_sha256=?6))",
                    params![blob(txn), view.session.session_id.as_str(), actor.client_ip.to_string(), now.secs(), blob(&ceremony.portal_binding), blob(&view.handle.handle_sha256)],
                    |r| r.get(0),
                )?;
                if !live {
                    return Err(conflict("step-up challenge unavailable"));
                }
            }
            // Expired rows of this session go first; then the oldest live ones beyond the cap.
            tx.execute(
                "DELETE FROM webauthn_challenges WHERE session_id=?1 AND (consumed_at IS NOT NULL OR expires_at<=?2)",
                params![view.session.session_id.as_str(), now.secs()],
            )?;
            tx.execute(
                "DELETE FROM webauthn_challenges WHERE challenge_sha256 IN (SELECT challenge_sha256 FROM webauthn_challenges WHERE session_id=?1 ORDER BY created_at DESC, rowid DESC LIMIT -1 OFFSET ?2)",
                params![view.session.session_id.as_str(), MAX_LIVE_CEREMONIES - 1],
            )?;
            tx.execute(
                "INSERT INTO webauthn_challenges(challenge_sha256,purpose,user_id,session_id,handle_sha256,portal_bind_sha256,txn_sha256,credential_generation,state,created_at,expires_at,consumed_at) \
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,NULL)",
                params![
                    blob(&ceremony.digest),
                    ceremony.purpose.as_str(),
                    view.session.user_id.as_str(),
                    view.session.session_id.as_str(),
                    blob(&view.handle.handle_sha256),
                    blob(&ceremony.portal_binding),
                    ceremony.transaction.as_ref().map(blob),
                    i64::try_from(view.session.cred_gen).map_err(|_| conflict("credential generation"))?,
                    ceremony.state,
                    now.secs(),
                    ceremony.expires_at.secs(),
                ],
            )?;
            commit(tx, &shared, None)
        })
        .await
    }

    async fn ceremony(&self, digest: &Digest) -> StoreResult<Option<CeremonyRecord>> {
        let digest = *digest;
        let clock = self.inner.shared.clock.clone();
        self.read("webauthn_ceremony", move |conn| {
            let row = conn
                .query_row(
                    "SELECT purpose,user_id,session_id,handle_sha256,portal_bind_sha256,txn_sha256,credential_generation,state,expires_at FROM webauthn_challenges \
                     WHERE challenge_sha256=?1 AND consumed_at IS NULL AND expires_at>?2",
                    params![blob(&digest), clock.now().secs()],
                    |r| {
                        Ok((
                            r.get::<_, String>(0)?,
                            r.get::<_, String>(1)?,
                            r.get::<_, String>(2)?,
                            r.get::<_, Vec<u8>>(3)?,
                            r.get::<_, Vec<u8>>(4)?,
                            r.get::<_, Option<Vec<u8>>>(5)?,
                            r.get::<_, i64>(6)?,
                            r.get::<_, String>(7)?,
                            r.get::<_, i64>(8)?,
                        ))
                    },
                )
                .optional()?;
            let Some((purpose, user, session, handle, bind, txn, generation, state, expires)) = row else {
                return Ok(None);
            };
            let corrupt = |c: &str| StoreError::Corrupt(format!("webauthn_challenges.{c}"));
            let digest_of = |v: Vec<u8>, c: &str| <[u8; 32]>::try_from(v.as_slice()).map(Digest).map_err(|_| corrupt(c));
            Ok(Some(CeremonyRecord {
                purpose: match purpose.as_str() {
                    "register" => CeremonyPurpose::Register,
                    "verify" => CeremonyPurpose::Verify,
                    "stepup" => CeremonyPurpose::StepUp,
                    _ => return Err(corrupt("purpose")),
                },
                user_id: UserId::new(user),
                session_id: SessionId::new(session),
                handle_sha256: digest_of(handle, "handle_sha256")?,
                portal_bind_sha256: digest_of(bind, "portal_bind_sha256")?,
                transaction: txn.map(|v| digest_of(v, "txn_sha256")).transpose()?,
                credential_generation: u64::try_from(generation).map_err(|_| corrupt("credential_generation"))?,
                state,
                expires_at: Timestamp::from_secs(expires),
            }))
        })
        .await
    }

    async fn fail_ceremony(&self, digest: &Digest, events: Vec<Event>) -> StoreResult<()> {
        let digest = *digest;
        self.write("fail_webauthn_ceremony", move |env| {
            let shared = env.shared.clone();
            let now = shared.clock.now();
            let tx = env.begin()?;
            tx.execute(
                "UPDATE webauthn_challenges SET consumed_at=?2 WHERE challenge_sha256=?1 AND consumed_at IS NULL",
                params![blob(&digest), now.secs()],
            )?;
            insert_events(&tx, &shared, &events)?;
            commit(tx, &shared, None)
        })
        .await
    }

    async fn register_passkey(&self, request: RegisterPasskey) -> StoreResult<()> {
        let record = &request.record;
        if record.label.is_empty()
            || record.label.chars().count() > 64
            || record.credential_id.len() < 16
            || record.credential_id.len() > 1023
            || record.transports.len() > 8
            || record.user_id != *request.actor.user()
        {
            return Err(conflict("invalid credential"));
        }
        self.write("register_passkey", move |env| {
            let shared = env.shared.clone();
            let now = shared.clock.now();
            let tx = env.begin()?;
            let actor = &request.actor;
            let user = actor.user();
            let record = &request.record;
            require_security_actor(&tx, &shared, actor)?;
            consume_ceremony(&tx, actor, &request.ceremony, CeremonyPurpose::Register, &request.portal_binding, None, now)?;
            require_management(&tx, &shared, actor)?;
            let exists: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM webauthn_credentials WHERE credential_id=?1)",
                [&record.credential_id],
                |r| r.get(0),
            )?;
            if exists {
                return Err(conflict(refusal::DUPLICATE_CREDENTIAL));
            }
            let active: i64 = tx.query_row(
                "SELECT COUNT(*) FROM webauthn_credentials WHERE user_id=?1 AND state='active'",
                [user.as_str()],
                |r| r.get(0),
            )?;
            if active >= MAX_PASSKEYS {
                return Err(conflict(refusal::PASSKEY_CAPACITY));
            }
            tx.execute(
                &format!("INSERT INTO webauthn_credentials({PASSKEY_COLS},state,revoked_at,revoked_reason) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,NULL,1,'active',NULL,NULL)"),
                params![
                    record.credential_id,
                    user.as_str(),
                    record.label,
                    record.passkey,
                    record.aaguid.as_ref().map(|a| &a[..]),
                    serde_json::to_string(&record.transports).map_err(|_| conflict("invalid credential"))?,
                    record.backup_eligible,
                    record.backup_state,
                    record.user_verified,
                    record.attestation_format,
                    record.attested,
                    record.assurance.as_str(),
                    i64::from(record.sign_count),
                    now.secs(),
                ],
            )?;
            tx.execute("UPDATE users SET factor_recovery_required_at=NULL WHERE user_id=?1", [user.as_str()])?;
            insert_events(&tx, &shared, &[
                event(&shared, EventKind::FactorWebauthnRegistered, Outcome::Success, &actor.request_id)
                    .user(user)
                    .session(&actor.view.session.session_id)
                    .attr("factor_id", factor_id(&record.credential_id))
                    .attr("kind", "webauthn")
                    .attr("assurance", record.assurance.as_str())
                    .build(),
            ])?;
            insert_events(&tx, &shared, &request.events)?;
            commit(tx, &shared, None)
        })
        .await
    }

    async fn elevate_webauthn(&self, request: WebauthnElevation) -> StoreResult<()> {
        self.write("elevate_webauthn", move |env| {
            let shared = env.shared.clone();
            let now = shared.clock.now();
            let tx = env.begin()?;
            let actor = &request.actor;
            let view = &actor.view;
            let user = actor.user();
            let sid = &view.session.session_id;
            require_security_actor(&tx, &shared, actor)?;
            super::factors::require_stepup_generation(&tx, Some(request.config_generation))?;
            let generation = i64::try_from(view.session.cred_gen.saturating_add(1)).map_err(|_| conflict("credential generation exhausted"))?;
            check_portal_handle(actor, &request.portal_handle, Aal::Two, now)?;
            check_handoff(actor, &request.handoff, generation, now)?;
            consume_ceremony(&tx, actor, &request.ceremony, CeremonyPurpose::StepUp, &request.portal_binding, Some(&request.transaction), now)?;
            let code = &request.handoff;
            let consumed = tx.execute(
                "UPDATE login_txns SET consumed_at=?2,consumed_reason='elevation' WHERE txn_sha256=?1 AND purpose='stepup' AND portal_session_id=?3 \
                 AND bind_sha256=?4 AND return_target=?5 AND client_ip=?6 AND recovery_depth=?7 AND consumed_at IS NULL AND created_at<=?2 AND expires_at>?2 \
                 AND reauth_max_age IS NULL AND provider_id IS NULL AND state_sha256 IS NULL AND nonce IS NULL AND pkce_verifier IS NULL \
                 AND (portal_bind_sha256 IS NULL OR portal_bind_sha256=?8) AND (conflicting_handle_sha256 IS NULL OR conflicting_handle_sha256=?9)",
                params![
                    blob(&request.transaction),
                    now.secs(),
                    sid.as_str(),
                    blob(&code.bind_sha256),
                    code.return_target.as_str(),
                    code.client_ip.to_string(),
                    i64::from(code.recovery_depth),
                    blob(&request.portal_binding),
                    blob(&view.handle.handle_sha256),
                ],
            )?;
            if consumed != 1 {
                return Err(conflict("step-up challenge unavailable"));
            }
            apply_use(&tx, user.as_str(), &request.used, now)?;
            let mut events = request.events;
            rotate(&tx, &shared, actor, Aal::Two, FactorEntry { kind: FactorKind::Webauthn, provider: None, at: now }, &mut events)?;
            tx.execute(
                "INSERT INTO session_webauthn_elevations(session_id,credential_id,at) VALUES(?1,?2,?3) ON CONFLICT(session_id,credential_id) DO UPDATE SET at=excluded.at",
                params![sid.as_str(), request.used.credential_id, now.secs()],
            )?;
            super::sessions::insert_handle(&tx, &request.portal_handle)?;
            super::sessions::insert_handoff_code(&tx, code)?;
            events.push(
                event(&shared, EventKind::FactorWebauthnUsed, Outcome::Success, &actor.request_id)
                    .user(user)
                    .session(sid)
                    .reason(reasons::ELEVATION)
                    .attr("factor_id", factor_id(&request.used.credential_id))
                    .attr("kind", "webauthn")
                    .attr("aal", 2)
                    .attr("assurance", request.used.assurance.as_str())
                    .attr("purpose", "stepup")
                    .build(),
            );
            events.push(
                event(&shared, EventKind::SessionHandoff, Outcome::Success, &actor.request_id)
                    .user(user)
                    .session(sid)
                    .reason(reasons::ELEVATION)
                    .attr("host", code.host.as_str())
                    .build(),
            );
            insert_events(&tx, &shared, &events)?;
            commit(tx, &shared, None)
        })
        .await
    }

    async fn elevate_portal(&self, request: PortalElevation) -> StoreResult<()> {
        self.write("elevate_portal", move |env| {
            let shared = env.shared.clone();
            let now = shared.clock.now();
            let tx = env.begin()?;
            let actor = &request.actor;
            let view = &actor.view;
            let user = actor.user();
            let sid = &view.session.session_id;
            require_security_actor(&tx, &shared, actor)?;
            let mut events = request.events;
            let (kind, aal) = match &request.proof {
                PortalProof::Passkey { ceremony, used } => {
                    consume_ceremony(&tx, actor, ceremony, CeremonyPurpose::Verify, &request.portal_binding, None, now)?;
                    apply_use(&tx, user.as_str(), used, now)?;
                    events.push(
                        event(&shared, EventKind::FactorWebauthnUsed, Outcome::Success, &actor.request_id)
                            .user(user)
                            .session(sid)
                            .reason(reasons::ELEVATION)
                            .attr("factor_id", factor_id(&used.credential_id))
                            .attr("kind", "webauthn")
                            .attr("aal", 2)
                            .attr("assurance", used.assurance.as_str())
                            .attr("purpose", "verify")
                            .build(),
                    );
                    (FactorKind::Webauthn, Aal::Two)
                }
                PortalProof::Totp { enrollment, revision, counter } => {
                    let revision = i64::try_from(*revision).map_err(|_| conflict("invalid enrollment revision"))?;
                    let counter = i64::try_from(*counter).map_err(|_| conflict("invalid OTP counter"))?;
                    if tx.execute(
                        "UPDATE totp_enrollments SET last_counter=?4,updated_at=?5 WHERE enrollment_id=?1 AND user_id=?2 AND revision=?3 AND state='active' AND last_counter<?4",
                        params![enrollment, user.as_str(), revision, counter, now.secs()],
                    )? != 1
                    {
                        return Err(conflict("factor proof unavailable"));
                    }
                    events.push(
                        event(&shared, EventKind::FactorTotpConsumed, Outcome::Success, &actor.request_id)
                            .user(user)
                            .session(sid)
                            .reason(reasons::ELEVATION)
                            .attr("enrollment_id", enrollment.as_str())
                            .attr("purpose", "verify")
                            .build(),
                    );
                    (FactorKind::Totp, Aal::Two)
                }
                PortalProof::Recovery { lookup } => {
                    if tx.execute(
                        "UPDATE recovery_codes SET used_at=?3 WHERE user_id=?1 AND lookup=?2 AND used_at IS NULL",
                        params![user.as_str(), lookup, now.secs()],
                    )? != 1
                    {
                        return Err(conflict("recovery code unavailable"));
                    }
                    tx.execute("UPDATE users SET factor_recovery_required_at=?2 WHERE user_id=?1", params![user.as_str(), now.secs()])?;
                    let remaining: i64 = tx.query_row(
                        "SELECT COUNT(*) FROM recovery_codes WHERE user_id=?1 AND used_at IS NULL",
                        [user.as_str()],
                        |r| r.get(0),
                    )?;
                    events.push(
                        event(&shared, EventKind::FactorRecoveryCodeUsed, Outcome::Success, &actor.request_id)
                            .user(user)
                            .session(sid)
                            .reason(reasons::RECOVERY_CODE)
                            .attr("kind", "recovery")
                            .attr("aal", view.session.aal.as_i64())
                            .attr("count", remaining)
                            .build(),
                    );
                    // A recovery code never raises the level (ADR-0017 decision 9).
                    (FactorKind::Recovery, view.session.aal)
                }
            };
            check_portal_handle(actor, &request.portal_handle, aal, now)?;
            rotate(&tx, &shared, actor, aal, FactorEntry { kind, provider: None, at: now }, &mut events)?;
            if let PortalProof::Passkey { used, .. } = &request.proof {
                tx.execute(
                    "INSERT INTO session_webauthn_elevations(session_id,credential_id,at) VALUES(?1,?2,?3) ON CONFLICT(session_id,credential_id) DO UPDATE SET at=excluded.at",
                    params![sid.as_str(), used.credential_id, now.secs()],
                )?;
            }
            super::sessions::insert_handle(&tx, &request.portal_handle)?;
            insert_events(&tx, &shared, &events)?;
            commit(tx, &shared, None)
        })
        .await
    }

    async fn passkey_clone_detected(
        &self,
        ceremony: &Digest,
        credential_id: &[u8],
        events: Vec<Event>,
    ) -> StoreResult<()> {
        let (ceremony, credential_id) = (*ceremony, credential_id.to_vec());
        self.write("passkey_clone_detected", move |env| {
            let shared = env.shared.clone();
            let now = shared.clock.now();
            let tx = env.begin()?;
            let user: Option<String> = tx
                .query_row(
                    "SELECT c.user_id FROM webauthn_challenges c JOIN webauthn_credentials w ON w.user_id=c.user_id \
                     WHERE c.challenge_sha256=?1 AND c.consumed_at IS NULL AND w.credential_id=?2",
                    params![blob(&ceremony), credential_id],
                    |r| r.get(0),
                )
                .optional()?;
            let user = UserId::new(user.ok_or(conflict(refusal::CEREMONY_UNAVAILABLE))?);
            tx.execute(
                "UPDATE webauthn_challenges SET consumed_at=?2 WHERE challenge_sha256=?1",
                params![blob(&ceremony), now.secs()],
            )?;
            let revoked = tx.execute(
                "UPDATE webauthn_credentials SET state='revoked',revoked_at=?3,revoked_reason='counter_regression',revision=revision+1 WHERE credential_id=?1 AND user_id=?2 AND state='active'",
                params![credential_id, user.as_str(), now.secs()],
            )?;
            if revoked == 1 {
                end_elevated_sessions(&tx, &shared, &user, &credential_id, None, reasons::COUNTER_REGRESSION, "r_webauthn_store")?;
            }
            insert_events(&tx, &shared, &events)?;
            commit(tx, &shared, None)
        })
        .await
    }

    async fn rename_passkey(
        &self,
        actor: FactorActor,
        credential_id: &[u8],
        label: String,
        events: Vec<Event>,
    ) -> StoreResult<bool> {
        if label.is_empty() || label.chars().count() > 64 {
            return Err(conflict("invalid label"));
        }
        let credential_id = credential_id.to_vec();
        self.write("rename_passkey", move |env| {
            let shared = env.shared.clone();
            let tx = env.begin()?;
            require_security_actor(&tx, &shared, &actor)?;
            let user = actor.user();
            let n = tx.execute(
                "UPDATE webauthn_credentials SET label=?3,revision=revision+1 WHERE credential_id=?1 AND user_id=?2 AND state='active'",
                params![credential_id, user.as_str(), label],
            )?;
            if n != 1 {
                return Ok(false);
            }
            insert_events(&tx, &shared, &[
                event(&shared, EventKind::FactorWebauthnRenamed, Outcome::Success, &actor.request_id)
                    .user(user)
                    .session(&actor.view.session.session_id)
                    .attr("factor_id", factor_id(&credential_id))
                    .build(),
            ])?;
            insert_events(&tx, &shared, &events)?;
            commit(tx, &shared, None)?;
            Ok(true)
        })
        .await
    }

    async fn revoke_passkey(
        &self,
        actor: FactorActor,
        credential_id: &[u8],
        events: Vec<Event>,
    ) -> StoreResult<bool> {
        let credential_id = credential_id.to_vec();
        self.write("revoke_passkey", move |env| {
            let shared = env.shared.clone();
            let now = shared.clock.now();
            let tx = env.begin()?;
            require_security_actor(&tx, &shared, &actor)?;
            let user = actor.user();
            let owned: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM webauthn_credentials WHERE credential_id=?1 AND user_id=?2 AND state='active')",
                params![credential_id, user.as_str()],
                |r| r.get(0),
            )?;
            if !owned {
                return Ok(false);
            }
            if !recent_second_factor(&actor.view.session.factors, now) {
                return Err(conflict(refusal::VERIFICATION_REQUIRED));
            }
            // In the same transaction as the revocation: concurrent removals serialize.
            if second_factor_count(&tx, user.as_str())? <= 1 {
                return Err(conflict(refusal::LAST_FACTOR));
            }
            tx.execute(
                "UPDATE webauthn_credentials SET state='revoked',revoked_at=?3,revoked_reason='removed',revision=revision+1 WHERE credential_id=?1 AND user_id=?2 AND state='active'",
                params![credential_id, user.as_str(), now.secs()],
            )?;
            end_elevated_sessions(&tx, &shared, user, &credential_id, Some(&actor.view.session.session_id), reasons::PASSKEY_REMOVED, &actor.request_id)?;
            insert_events(&tx, &shared, &[
                event(&shared, EventKind::FactorWebauthnRevoked, Outcome::Success, &actor.request_id)
                    .user(user)
                    .session(&actor.view.session.session_id)
                    .reason(reasons::PASSKEY_REMOVED)
                    .attr("factor_id", factor_id(&credential_id))
                    .build(),
            ])?;
            insert_events(&tx, &shared, &events)?;
            commit(tx, &shared, None)?;
            Ok(true)
        })
        .await
    }

    async fn replace_recovery_codes(
        &self,
        actor: FactorActor,
        batch: String,
        codes: Vec<(String, String)>,
        events: Vec<Event>,
    ) -> StoreResult<()> {
        if codes.len() != RECOVERY_CODES_PER_SET
            || codes
                .iter()
                .any(|(l, h)| l.len() != 5 || h.is_empty() || h.len() > 256)
            || batch.is_empty()
            || batch.len() > 64
        {
            return Err(conflict("invalid recovery codes"));
        }
        self.write("replace_recovery_codes", move |env| {
            let shared = env.shared.clone();
            let now = shared.clock.now();
            let tx = env.begin()?;
            require_security_actor(&tx, &shared, &actor)?;
            let user = actor.user();
            let view = &actor.view;
            if second_factor_count(&tx, user.as_str())? == 0 {
                return Err(conflict("recovery codes require a second factor"));
            }
            let unused: i64 = tx.query_row(
                "SELECT COUNT(*) FROM recovery_codes WHERE user_id=?1 AND used_at IS NULL",
                [user.as_str()],
                |r| r.get(0),
            )?;
            // The first set needs the enrollment freshness; replacing live codes needs a recent second factor.
            let allowed = if unused == 0 {
                management_allowed(&view.session.factors, view.session.auth_time, false, now)
            } else {
                recent_second_factor(&view.session.factors, now)
            };
            if !allowed {
                return Err(conflict(refusal::VERIFICATION_REQUIRED));
            }
            tx.execute("DELETE FROM recovery_codes WHERE user_id=?1", [user.as_str()])?;
            for (lookup, hash) in &codes {
                tx.execute(
                    "INSERT INTO recovery_codes(user_id,lookup,hash,batch,created_at,used_at) VALUES(?1,?2,?3,?4,?5,NULL)",
                    params![user.as_str(), lookup, hash, batch, now.secs()],
                )
                .map_err(|e| match e {
                    rusqlite::Error::SqliteFailure(f, _) if f.code == rusqlite::ErrorCode::ConstraintViolation => conflict("duplicate recovery code"),
                    e => StoreError::from(e),
                })?;
            }
            insert_events(&tx, &shared, &[
                event(&shared, EventKind::FactorRecoveryCodesGenerated, Outcome::Success, &actor.request_id)
                    .user(user)
                    .session(&view.session.session_id)
                    .attr("kind", "recovery")
                    .attr("count", codes.len())
                    .build(),
            ])?;
            insert_events(&tx, &shared, &events)?;
            commit(tx, &shared, None)
        })
        .await
    }

    async fn recovery_code_hash(&self, user: &UserId, lookup: &str) -> StoreResult<Option<String>> {
        let (user, lookup) = (user.clone(), lookup.to_owned());
        self.read("recovery_code_hash", move |conn| {
            Ok(conn
                .query_row(
                    "SELECT r.hash FROM recovery_codes r JOIN users u ON u.user_id=r.user_id WHERE r.user_id=?1 AND r.lookup=?2 AND r.used_at IS NULL AND u.status='active'",
                    params![user.as_str(), lookup],
                    |r| r.get(0),
                )
                .optional()?)
        })
        .await
    }

    async fn reset_factors(
        &self,
        user: &UserId,
        request_id: &str,
        events: Vec<Event>,
    ) -> StoreResult<FactorResetReport> {
        let (user, request_id) = (user.clone(), request_id.to_owned());
        self.write("reset_factors", move |env| {
            let shared = env.shared.clone();
            let now = shared.clock.now();
            let tx = env.begin()?;
            let exists: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM users WHERE user_id=?1)", [user.as_str()], |r| r.get(0))?;
            if !exists {
                return Err(conflict("user unavailable"));
            }
            let count = |n: usize| u32::try_from(n).unwrap_or(u32::MAX);
            let passkeys = count(tx.execute(
                "UPDATE webauthn_credentials SET state='revoked',revoked_at=?2,revoked_reason='factor_reset',revision=revision+1 WHERE user_id=?1 AND state='active'",
                params![user.as_str(), now.secs()],
            )?);
            let totp = count(tx.execute(
                "UPDATE totp_enrollments SET state='revoked',revision=revision+1,pending_expires_at=NULL,updated_at=?2 WHERE user_id=?1 AND state!='revoked'",
                params![user.as_str(), now.secs()],
            )?);
            let recovery_codes = count(tx.execute("DELETE FROM recovery_codes WHERE user_id=?1 AND used_at IS NULL", [user.as_str()])?);
            tx.execute("DELETE FROM recovery_codes WHERE user_id=?1", [user.as_str()])?;
            tx.execute("UPDATE users SET factor_recovery_required_at=NULL WHERE user_id=?1", [user.as_str()])?;
            tx.execute("DELETE FROM webauthn_challenges WHERE user_id=?1", [user.as_str()])?;
            let sessions: Vec<String> = tx
                .prepare("SELECT session_id FROM sessions WHERE user_id=?1 AND terminated_at IS NULL ORDER BY session_id")?
                .query_map([user.as_str()], |r| r.get(0))?
                .collect::<Result<_, _>>()?;
            let ended = count(sessions.len());
            for id in sessions {
                let id = SessionId::new(id);
                let ev = event(&shared, EventKind::SessionTerminated, Outcome::Success, &request_id)
                    .user(&user)
                    .session(&id)
                    .reason(reasons::FACTOR_RESET)
                    .build();
                super::sessions::terminate_in(&tx, &shared, &id, reasons::FACTOR_RESET, now, &[ev])?;
            }
            let report = FactorResetReport { passkeys, totp, recovery_codes, sessions: ended };
            insert_events(&tx, &shared, &events)?;
            commit(tx, &shared, None)?;
            Ok(report)
        })
        .await
    }
}

/// Read-only foundation check: the v11 tables match the embedded migration exactly.
pub(crate) fn validate_foundation(conn: &rusqlite::Connection) -> StoreResult<()> {
    let migration = include_str!("../migrations/0011_webauthn.sql");
    let normalize = |s: &str| -> String {
        s.to_ascii_lowercase()
            .lines()
            .map(|l| l.split("--").next().unwrap_or(""))
            .collect::<String>()
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '"')
            .collect::<String>()
            .trim_end_matches(';')
            .to_owned()
    };
    for name in [
        "webauthn_credentials",
        "webauthn_challenges",
        "recovery_codes",
        "session_webauthn_elevations",
    ] {
        let start = migration
            .find(&format!("CREATE TABLE {name} ("))
            .expect("embedded webauthn schema");
        let expected = migration[start..]
            .split(") STRICT;")
            .next()
            .expect("embedded table");
        let expected = format!("{expected}) STRICT");
        let actual: Option<String> = conn
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name=?1",
                [name],
                |r| r.get(0),
            )
            .optional()?;
        if actual.as_deref().map(normalize) != Some(normalize(&expected)) {
            return Err(StoreError::Corrupt(
                "schema v11 invalid WebAuthn structure".into(),
            ));
        }
    }
    for (table, column) in [
        ("users", "webauthn_user_handle"),
        ("users", "factor_recovery_required_at"),
    ] {
        let present: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info(?1) WHERE name=?2)",
            [table, column],
            |r| r.get(0),
        )?;
        if !present {
            return Err(StoreError::Corrupt(
                "schema v11 invalid WebAuthn structure".into(),
            ));
        }
    }
    Ok(())
}
