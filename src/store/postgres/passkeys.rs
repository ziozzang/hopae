//! Slice 2c for PostgreSQL (ADR-0020): `Passkeys` — WebAuthn credentials,
//! single-use ceremony rows, recovery codes, portal and application
//! elevation, passwordless sign-in and the administrator factor reset.
//!
//! The locking rule is the one of [`super::factors`]: the subject user's row
//! `FOR UPDATE` first, then the acting session and handle while they are
//! re-checked, so the factor-management rule ("not the last factor", "a
//! recent second factor") is evaluated against values no concurrent
//! writer can change before the commit. The passwordless ceremony caps are
//! table-wide and take an advisory lock.
use async_trait::async_trait;
use deadpool_postgres::Transaction;
use tokio_postgres::Row;

use super::factors::{ActorRule, end_user_sessions, lock_user, require_actor, rotate_credentials};
use super::write::{self, factors_json};
use super::{PgStore, pg};
use crate::crypto::{Digest, Timestamp};
use crate::event::types::{Event, EventBuilder, EventKind, Outcome, Reason, reasons};
use crate::identity::types::UserId;
use crate::session::types::{Aal, FactorEntry, FactorKind, SessionId};
use crate::store::passkeys::*;
use crate::store::sqlite::webauthn::{
    factor_id, management_allowed, recent_possession_factor, recent_second_factor,
};
use crate::store::{FactorActor, HandleRow, HandoffCodeRow, StoreError, StoreResult};

const PASSKEY_COLS: &str = "credential_id, user_id, label, passkey, aaguid, transports, backup_eligible, backup_state, user_verified, attestation_format, attested, assurance, sign_count, created_at, last_used_at, revision";
/// `pg_advisory_xact_lock` key serializing the passwordless ceremony caps.
const LOGIN_CEREMONY_LOCK: i64 = 7013;

fn conflict(what: &'static str) -> StoreError {
    StoreError::Conflict(what)
}

fn passkey_row(r: &Row) -> StoreResult<PasskeyRecord> {
    let corrupt = |c: &str| StoreError::Corrupt(format!("webauthn_credentials.{c}"));
    let aaguid = r
        .get::<_, Option<Vec<u8>>>(4)
        .map(|v| <[u8; 16]>::try_from(v.as_slice()).map_err(|_| corrupt("aaguid")))
        .transpose()?;
    let transports: Vec<String> =
        serde_json::from_str(&r.get::<_, String>(5)).map_err(|_| corrupt("transports"))?;
    Ok(PasskeyRecord {
        credential_id: r.get(0),
        user_id: UserId::new(r.get::<_, String>(1)),
        label: r.get(2),
        passkey: r.get(3),
        aaguid,
        transports,
        backup_eligible: r.get(6),
        backup_state: r.get(7),
        user_verified: r.get(8),
        attestation_format: r.get(9),
        attested: r.get(10),
        assurance: Assurance::parse(&r.get::<_, String>(11)).ok_or_else(|| corrupt("assurance"))?,
        sign_count: u32::try_from(r.get::<_, i64>(12)).map_err(|_| corrupt("sign_count"))?,
        created_at: Timestamp::from_secs(r.get(13)),
        last_used_at: r.get::<_, Option<i64>>(14).map(Timestamp::from_secs),
        revision: u64::try_from(r.get::<_, i64>(15)).map_err(|_| corrupt("revision"))?,
    })
}

fn digest_of(v: Vec<u8>, col: &str) -> StoreResult<Digest> {
    <[u8; 32]>::try_from(v.as_slice())
        .map(Digest)
        .map_err(|_| StoreError::Corrupt(format!("column {col}")))
}

fn event(store: &PgStore, kind: EventKind, outcome: Outcome, request_id: &str) -> EventBuilder {
    EventBuilder::new(
        store.clock.as_ref(),
        store.rng.as_ref(),
        kind,
        outcome,
        request_id,
    )
}

async fn second_factor_count(tx: &Transaction<'_>, user: &str) -> StoreResult<i64> {
    Ok(tx
        .query_one(
            "SELECT (SELECT count(*) FROM webauthn_credentials WHERE user_id=$1 AND state='active') \
                  + (SELECT count(*) FROM totp_enrollments WHERE user_id=$1 AND state='active')",
            &[&user],
        )
        .await
        .map_err(pg)?
        .get(0))
}

async fn require_management(
    store: &PgStore,
    tx: &Transaction<'_>,
    actor: &FactorActor,
) -> StoreResult<()> {
    let has = second_factor_count(tx, actor.user().as_str()).await? > 0;
    let view = &actor.view;
    if !management_allowed(
        &view.session.factors,
        view.session.auth_time,
        has,
        store.now(),
    ) {
        return Err(conflict(refusal::VERIFICATION_REQUIRED));
    }
    Ok(())
}

/// Lock the user, then re-check the acting session (security-actor rule).
async fn begin_actor(
    store: &PgStore,
    tx: &Transaction<'_>,
    actor: &FactorActor,
) -> StoreResult<()> {
    lock_user(tx, actor.user().as_str()).await?;
    require_actor(store, tx, actor.user().as_str(), actor, ActorRule::Security).await
}

async fn consume_ceremony(
    tx: &Transaction<'_>,
    actor: &FactorActor,
    digest: &Digest,
    purpose: CeremonyPurpose,
    portal_binding: &Digest,
    transaction: Option<&Digest>,
    now: Timestamp,
) -> StoreResult<()> {
    let view = &actor.view;
    let n = tx
        .execute(
            "UPDATE webauthn_challenges SET consumed_at=$9 WHERE challenge_sha256=$1 AND purpose=$2 AND user_id=$3 AND session_id=$4 \
             AND handle_sha256=$5 AND portal_bind_sha256=$6 AND credential_generation=$7 AND txn_sha256 IS NOT DISTINCT FROM $8 \
             AND consumed_at IS NULL AND created_at<=$9 AND expires_at>$9",
            &[
                &digest.0.to_vec(),
                &purpose.as_str(),
                &view.session.user_id.as_str(),
                &view.session.session_id.as_str(),
                &view.handle.handle_sha256.0.to_vec(),
                &portal_binding.0.to_vec(),
                &i64::try_from(view.session.cred_gen).map_err(|_| conflict("credential generation"))?,
                &transaction.map(|d| d.0.to_vec()),
                &now.secs(),
            ],
        )
        .await
        .map_err(pg)?;
    if n != 1 {
        return Err(conflict(refusal::CEREMONY_UNAVAILABLE));
    }
    Ok(())
}

/// Record a verified credential use: the counter only moves forward (equal
/// only while both are zero), flags and the serialized credential follow.
async fn apply_use(
    tx: &Transaction<'_>,
    user: &str,
    used: &PasskeyUse,
    now: Timestamp,
) -> StoreResult<()> {
    let n = tx
        .execute(
            "UPDATE webauthn_credentials SET passkey=$3, sign_count=$4, backup_eligible=$5, backup_state=$6, last_used_at=$7, revision=revision+1 \
             WHERE credential_id=$1 AND user_id=$2 AND state='active' AND (sign_count<$4 OR (sign_count=0 AND $4=0)) \
             AND ($8='aal2' OR (assurance='aal3' AND NOT $5 AND NOT $6))",
            &[
                &used.credential_id,
                &user,
                &used.passkey,
                &i64::from(used.sign_count),
                &used.backup_eligible,
                &used.backup_state,
                &now.secs(),
                &used.assurance.as_str(),
            ],
        )
        .await
        .map_err(pg)?;
    if n != 1 {
        let active = tx
            .query_opt(
                "SELECT 1 FROM webauthn_credentials WHERE credential_id=$1 AND user_id=$2 AND state='active'",
                &[&used.credential_id, &user],
            )
            .await
            .map_err(pg)?
            .is_some();
        return Err(conflict(if active {
            refusal::COUNTER_STALE
        } else {
            "credential unavailable"
        }));
    }
    Ok(())
}

/// Raise the session to `aal`, append `entry`, move the generation and
/// revoke every handle and code (ADR-0008); returns the new generation.
async fn rotate(
    store: &PgStore,
    tx: &Transaction<'_>,
    actor: &FactorActor,
    aal: Aal,
    entry: FactorEntry,
    events: &mut Vec<Event>,
) -> StoreResult<i64> {
    let view = &actor.view;
    let sid = &view.session.session_id;
    let now = store.now();
    let generation = view
        .session
        .cred_gen
        .checked_add(1)
        .and_then(|n| i64::try_from(n).ok())
        .ok_or(conflict("credential generation exhausted"))?;
    let mut factors = view.session.factors.clone();
    factors.push(entry);
    tx.execute(
        "UPDATE sessions SET aal=$2, factors=$3, cred_gen=$4 WHERE session_id=$1",
        &[
            &sid.as_str(),
            &(aal.as_i64() as i32),
            &factors_json(&factors)?,
            &generation,
        ],
    )
    .await
    .map_err(pg)?;
    rotate_credentials(store, tx, actor, now, events).await?;
    Ok(generation)
}

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

async fn record_elevation(
    tx: &Transaction<'_>,
    sid: &SessionId,
    credential: &[u8],
    now: Timestamp,
) -> StoreResult<()> {
    tx.execute(
        "INSERT INTO session_webauthn_elevations (session_id, credential_id, at) VALUES ($1,$2,$3) \
         ON CONFLICT (session_id, credential_id) DO UPDATE SET at=LEAST(session_webauthn_elevations.at, excluded.at)",
        &[&sid.as_str(), &credential, &now.secs()],
    )
    .await
    .map_err(pg)?;
    Ok(())
}

/// Native Human owner provenance of the establishing passkey (SQLite `webauthn_owner::record`).
#[allow(clippy::too_many_arguments)]
async fn record_provenance(
    tx: &Transaction<'_>,
    session: &str,
    user: &str,
    generation: i64,
    credential: &[u8],
    assurance: &str,
    factor_index: i64,
    at_ms: i64,
    config_generation: Option<i64>,
) -> StoreResult<()> {
    let n = tx
        .execute(
            "INSERT INTO session_webauthn_provenance (session_id, user_id, credential_generation, credential_id, assurance, factor_index, verified_at_ms, config_generation) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (session_id) DO UPDATE SET user_id=excluded.user_id, credential_generation=excluded.credential_generation, \
             credential_id=excluded.credential_id, assurance=excluded.assurance, factor_index=excluded.factor_index, verified_at_ms=excluded.verified_at_ms, \
             config_generation=excluded.config_generation \
             WHERE excluded.user_id=session_webauthn_provenance.user_id AND excluded.credential_generation>session_webauthn_provenance.credential_generation",
            &[&session, &user, &generation, &credential, &assurance, &factor_index, &at_ms, &config_generation],
        )
        .await
        .map_err(pg)?;
    if n != 1 {
        return Err(conflict("WebAuthn provenance generation unavailable"));
    }
    Ok(())
}

/// End every live session of `user` that `credential` elevated, except `keep`.
async fn end_elevated_sessions(
    store: &PgStore,
    tx: &Transaction<'_>,
    user: &UserId,
    credential: &[u8],
    keep: Option<&SessionId>,
    reason: Reason,
    request_id: &str,
) -> StoreResult<u32> {
    let now = store.now();
    let rows = tx
        .query(
            "SELECT s.session_id FROM session_webauthn_elevations e JOIN sessions s ON s.session_id=e.session_id \
             WHERE e.credential_id=$1 AND s.user_id=$2 AND s.terminated_at IS NULL ORDER BY s.session_id",
            &[&credential, &user.as_str()],
        )
        .await
        .map_err(pg)?;
    let mut ended = 0;
    for r in rows {
        let id = SessionId::new(r.get::<_, String>(0));
        if keep == Some(&id) {
            continue;
        }
        let ev = event(
            store,
            EventKind::SessionTerminated,
            Outcome::Success,
            request_id,
        )
        .user(user)
        .session(&id)
        .reason(reason)
        .build();
        if super::admin::terminate_in(store, tx, &id, reason, now, &[ev]).await? {
            ended += 1;
        }
    }
    Ok(ended)
}

async fn active_passkeys(c: &Transaction<'_>, user: &str) -> StoreResult<Vec<PasskeyRecord>> {
    c.query(
        &format!("SELECT {PASSKEY_COLS} FROM webauthn_credentials WHERE user_id=$1 AND state='active' ORDER BY created_at, credential_id"),
        &[&user],
    )
    .await
    .map_err(pg)?
    .iter()
    .map(passkey_row)
    .collect()
}

#[async_trait]
impl Passkeys for PgStore {
    async fn passkey_user_handle(
        &self,
        user: &UserId,
        candidate: [u8; 16],
    ) -> StoreResult<[u8; 16]> {
        super::retry(|| async {
            let mut client = self.client().await?;
            let tx = self.begin(&mut client).await?;
            tx.execute(
                "UPDATE users SET webauthn_user_handle=$2 WHERE user_id=$1 AND webauthn_user_handle IS NULL AND status='active'",
                &[&user.as_str(), &candidate.to_vec()],
            )
            .await
            .map_err(pg)?;
            let handle = tx
                .query_opt(
                    "SELECT webauthn_user_handle FROM users WHERE user_id=$1 AND status='active'",
                    &[&user.as_str()],
                )
                .await
                .map_err(pg)?
                .and_then(|r| r.get::<_, Option<Vec<u8>>>(0))
                .ok_or(conflict("user unavailable"))
                .and_then(|v| {
                    <[u8; 16]>::try_from(v.as_slice())
                        .map_err(|_| StoreError::Corrupt("users.webauthn_user_handle".into()))
                })?;
            tx.commit().await.map_err(pg)?;
            Ok(handle)
        })
        .await
    }

    async fn factor_summary(&self, user: &UserId) -> StoreResult<FactorSummary> {
        let mut client = self.client().await?;
        // One snapshot for the four reads.
        let tx = client
            .build_transaction()
            .isolation_level(tokio_postgres::IsolationLevel::RepeatableRead)
            .read_only(true)
            .start()
            .await
            .map_err(pg)?;
        let passkeys = active_passkeys(&tx, user.as_str()).await?;
        let totp_active = tx
            .query_opt(
                "SELECT 1 FROM totp_enrollments WHERE user_id=$1 AND state='active'",
                &[&user.as_str()],
            )
            .await
            .map_err(pg)?
            .is_some();
        let r = tx
            .query_one(
                "SELECT count(*) FILTER (WHERE used_at IS NULL), max(created_at) FROM recovery_codes WHERE user_id=$1",
                &[&user.as_str()],
            )
            .await
            .map_err(pg)?;
        let (unused, generated): (i64, Option<i64>) = (r.get(0), r.get(1));
        let required = tx
            .query_opt(
                "SELECT factor_recovery_required_at FROM users WHERE user_id=$1",
                &[&user.as_str()],
            )
            .await
            .map_err(pg)?
            .and_then(|r| r.get::<_, Option<i64>>(0));
        tx.commit().await.map_err(pg)?;
        Ok(FactorSummary {
            passkeys,
            totp_active,
            recovery_unused: u32::try_from(unused).unwrap_or(0),
            recovery_generated_at: generated.map(Timestamp::from_secs),
            recovery_required_at: required.map(Timestamp::from_secs),
        })
    }

    async fn active_totp_enrollment(&self, user: &UserId) -> StoreResult<Option<String>> {
        let client = self.client().await?;
        Ok(client
            .query_opt(
                "SELECT enrollment_id FROM totp_enrollments WHERE user_id=$1 AND state='active'",
                &[&user.as_str()],
            )
            .await
            .map_err(pg)?
            .map(|r| r.get(0)))
    }

    async fn begin_ceremony(&self, ceremony: NewCeremony) -> StoreResult<()> {
        if ceremony.state.len() > 65_536
            || (ceremony.purpose == CeremonyPurpose::StepUp) != ceremony.transaction.is_some()
        {
            return Err(conflict("invalid ceremony"));
        }
        super::retry(|| async {
            let now = self.now();
            let mut client = self.client().await?;
            let tx = self.begin(&mut client).await?;
            let actor = &ceremony.actor;
            let view = &actor.view;
            begin_actor(self, &tx, actor).await?;
            if ceremony.expires_at <= now
                || ceremony.expires_at.since(now) > std::time::Duration::from_secs(600)
            {
                return Err(conflict("invalid ceremony"));
            }
            if let Some(txn) = &ceremony.transaction {
                let live = tx
                    .query_opt(
                        "SELECT 1 FROM login_txns WHERE txn_sha256=$1 AND purpose='stepup' AND portal_session_id=$2 AND client_ip=$3 \
                         AND bind_sha256 IS NOT NULL AND consumed_at IS NULL AND created_at<=$4 AND expires_at>$4 AND provider_id IS NULL \
                         AND state_sha256 IS NULL AND nonce IS NULL AND pkce_verifier IS NULL AND reauth_max_age IS NULL \
                         AND (portal_bind_sha256 IS NULL OR portal_bind_sha256=$5) AND (conflicting_handle_sha256 IS NULL OR conflicting_handle_sha256=$6) \
                         FOR SHARE",
                        &[
                            &txn.0.to_vec(),
                            &view.session.session_id.as_str(),
                            &actor.client_ip.to_string(),
                            &now.secs(),
                            &ceremony.portal_binding.0.to_vec(),
                            &view.handle.handle_sha256.0.to_vec(),
                        ],
                    )
                    .await
                    .map_err(pg)?;
                if live.is_none() {
                    return Err(conflict("step-up challenge unavailable"));
                }
            }
            // Expired rows of this session go first; then the oldest live ones beyond the cap.
            tx.execute(
                "DELETE FROM webauthn_challenges WHERE session_id=$1 AND (consumed_at IS NOT NULL OR expires_at<=$2)",
                &[&view.session.session_id.as_str(), &now.secs()],
            )
            .await
            .map_err(pg)?;
            tx.execute(
                "DELETE FROM webauthn_challenges WHERE challenge_sha256 IN (SELECT challenge_sha256 FROM webauthn_challenges WHERE session_id=$1 ORDER BY created_at DESC, seq DESC OFFSET $2)",
                &[&view.session.session_id.as_str(), &(MAX_LIVE_CEREMONIES - 1)],
            )
            .await
            .map_err(pg)?;
            tx.execute(
                "INSERT INTO webauthn_challenges (challenge_sha256, purpose, user_id, session_id, handle_sha256, portal_bind_sha256, txn_sha256, credential_generation, state, created_at, expires_at, consumed_at) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,NULL)",
                &[
                    &ceremony.digest.0.to_vec(),
                    &ceremony.purpose.as_str(),
                    &view.session.user_id.as_str(),
                    &view.session.session_id.as_str(),
                    &view.handle.handle_sha256.0.to_vec(),
                    &ceremony.portal_binding.0.to_vec(),
                    &ceremony.transaction.as_ref().map(|d| d.0.to_vec()),
                    &i64::try_from(view.session.cred_gen).map_err(|_| conflict("credential generation"))?,
                    &ceremony.state,
                    &now.secs(),
                    &ceremony.expires_at.secs(),
                ],
            )
            .await
            .map_err(pg)?;
            tx.commit().await.map_err(pg)
        })
        .await
    }

    async fn ceremony(&self, digest: &Digest) -> StoreResult<Option<CeremonyRecord>> {
        let client = self.client().await?;
        let row = client
            .query_opt(
                "SELECT purpose, user_id, session_id, handle_sha256, portal_bind_sha256, txn_sha256, credential_generation, state, expires_at \
                 FROM webauthn_challenges WHERE challenge_sha256=$1 AND consumed_at IS NULL AND expires_at>$2",
                &[&digest.0.to_vec(), &self.now().secs()],
            )
            .await
            .map_err(pg)?;
        let Some(r) = row else { return Ok(None) };
        let corrupt = |c: &str| StoreError::Corrupt(format!("webauthn_challenges.{c}"));
        Ok(Some(CeremonyRecord {
            purpose: match r.get::<_, String>(0).as_str() {
                "register" => CeremonyPurpose::Register,
                "verify" => CeremonyPurpose::Verify,
                "stepup" => CeremonyPurpose::StepUp,
                _ => return Err(corrupt("purpose")),
            },
            user_id: UserId::new(r.get::<_, String>(1)),
            session_id: SessionId::new(r.get::<_, String>(2)),
            handle_sha256: digest_of(r.get(3), "webauthn_challenges.handle_sha256")?,
            portal_bind_sha256: digest_of(r.get(4), "webauthn_challenges.portal_bind_sha256")?,
            transaction: r
                .get::<_, Option<Vec<u8>>>(5)
                .map(|v| digest_of(v, "webauthn_challenges.txn_sha256"))
                .transpose()?,
            credential_generation: u64::try_from(r.get::<_, i64>(6))
                .map_err(|_| corrupt("credential_generation"))?,
            state: r.get(7),
            expires_at: Timestamp::from_secs(r.get(8)),
        }))
    }

    async fn fail_ceremony(&self, digest: &Digest, events: Vec<Event>) -> StoreResult<()> {
        super::retry(|| async {
            let mut client = self.client().await?;
            let tx = self.begin(&mut client).await?;
            tx.execute(
                "UPDATE webauthn_challenges SET consumed_at=$2 WHERE challenge_sha256=$1 AND consumed_at IS NULL",
                &[&digest.0.to_vec(), &self.now().secs()],
            )
            .await
            .map_err(pg)?;
            self.insert_events(&tx, &events).await?;
            tx.commit().await.map_err(pg)
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
        let transports = serde_json::to_string(&record.transports)
            .map_err(|_| conflict("invalid credential"))?;
        super::retry(|| async {
            let now = self.now();
            let mut client = self.client().await?;
            let tx = self.begin(&mut client).await?;
            let actor = &request.actor;
            let user = actor.user();
            begin_actor(self, &tx, actor).await?;
            consume_ceremony(&tx, actor, &request.ceremony, CeremonyPurpose::Register, &request.portal_binding, None, now).await?;
            require_management(self, &tx, actor).await?;
            let exists = tx
                .query_opt(
                    "SELECT 1 FROM webauthn_credentials WHERE credential_id=$1",
                    &[&record.credential_id],
                )
                .await
                .map_err(pg)?
                .is_some();
            if exists {
                return Err(conflict(refusal::DUPLICATE_CREDENTIAL));
            }
            let active: i64 = tx
                .query_one(
                    "SELECT count(*) FROM webauthn_credentials WHERE user_id=$1 AND state='active'",
                    &[&user.as_str()],
                )
                .await
                .map_err(pg)?
                .get(0);
            if active >= MAX_PASSKEYS {
                return Err(conflict(refusal::PASSKEY_CAPACITY));
            }
            // The credential id is a primary key: a concurrent registration of
            // the same authenticator by another user fails here.
            let inserted = tx
                .execute(
                    &format!("INSERT INTO webauthn_credentials ({PASSKEY_COLS}, state, revoked_at, revoked_reason) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,NULL,1,'active',NULL,NULL) ON CONFLICT (credential_id) DO NOTHING"),
                    &[
                        &record.credential_id,
                        &user.as_str(),
                        &record.label,
                        &record.passkey,
                        &record.aaguid.map(|a| a.to_vec()),
                        &transports,
                        &record.backup_eligible,
                        &record.backup_state,
                        &record.user_verified,
                        &record.attestation_format,
                        &record.attested,
                        &record.assurance.as_str(),
                        &i64::from(record.sign_count),
                        &now.secs(),
                    ],
                )
                .await
                .map_err(pg)?;
            if inserted != 1 {
                return Err(conflict(refusal::DUPLICATE_CREDENTIAL));
            }
            tx.execute(
                "UPDATE users SET factor_recovery_required_at=NULL WHERE user_id=$1",
                &[&user.as_str()],
            )
            .await
            .map_err(pg)?;
            let registered = event(self, EventKind::FactorWebauthnRegistered, Outcome::Success, &actor.request_id)
                .user(user)
                .session(&actor.view.session.session_id)
                .attr("factor_id", factor_id(&record.credential_id))
                .attr("kind", "webauthn")
                .attr("assurance", record.assurance.as_str())
                .build();
            self.insert_events(&tx, &[registered]).await?;
            self.insert_events(&tx, &request.events).await?;
            tx.commit().await.map_err(pg)
        })
        .await
    }

    async fn elevate_webauthn(&self, request: WebauthnElevation) -> StoreResult<()> {
        super::retry(|| async {
            let now = self.now();
            let mut client = self.client().await?;
            let tx = self.begin(&mut client).await?;
            let actor = &request.actor;
            let view = &actor.view;
            let user = actor.user();
            let sid = &view.session.session_id;
            begin_actor(self, &tx, actor).await?;
            write::require_stepup_generation(&tx, Some(request.config_generation)).await?;
            let generation = i64::try_from(view.session.cred_gen.saturating_add(1))
                .map_err(|_| conflict("credential generation exhausted"))?;
            check_portal_handle(actor, &request.portal_handle, Aal::Two, now)?;
            check_handoff(actor, &request.handoff, generation, now)?;
            consume_ceremony(&tx, actor, &request.ceremony, CeremonyPurpose::StepUp, &request.portal_binding, Some(&request.transaction), now).await?;
            let code = &request.handoff;
            let consumed = tx
                .execute(
                    "UPDATE login_txns SET consumed_at=$2, consumed_reason='elevation' WHERE txn_sha256=$1 AND purpose='stepup' AND portal_session_id=$3 \
                     AND bind_sha256=$4 AND return_target=$5 AND client_ip=$6 AND recovery_depth=$7 AND consumed_at IS NULL AND created_at<=$2 AND expires_at>$2 \
                     AND reauth_max_age IS NULL AND provider_id IS NULL AND state_sha256 IS NULL AND nonce IS NULL AND pkce_verifier IS NULL \
                     AND (portal_bind_sha256 IS NULL OR portal_bind_sha256=$8) AND (conflicting_handle_sha256 IS NULL OR conflicting_handle_sha256=$9)",
                    &[
                        &request.transaction.0.to_vec(),
                        &now.secs(),
                        &sid.as_str(),
                        &code.bind_sha256.0.to_vec(),
                        &code.return_target.as_str(),
                        &code.client_ip.to_string(),
                        &(code.recovery_depth.min(i32::MAX as u32) as i32),
                        &request.portal_binding.0.to_vec(),
                        &view.handle.handle_sha256.0.to_vec(),
                    ],
                )
                .await
                .map_err(pg)?;
            if consumed != 1 {
                return Err(conflict("step-up challenge unavailable"));
            }
            apply_use(&tx, user.as_str(), &request.used, now).await?;
            let mut events = request.events.clone();
            let generation = rotate(
                self,
                &tx,
                actor,
                Aal::Two,
                FactorEntry { kind: FactorKind::Webauthn, provider: None, at: now },
                &mut events,
            )
            .await?;
            record_elevation(&tx, sid, &request.used.credential_id, now).await?;
            record_provenance(
                &tx,
                sid.as_str(),
                user.as_str(),
                generation,
                &request.used.credential_id,
                request.used.assurance.as_str(),
                i64::try_from(view.session.factors.len()).map_err(|_| conflict("factor provenance exhausted"))?,
                now.0,
                Some(i64::try_from(request.config_generation).map_err(|_| conflict("invalid configuration generation"))?),
            )
            .await?;
            write::insert_handle(&tx, &request.portal_handle).await?;
            write::insert_code(&tx, code).await?;
            events.push(
                event(self, EventKind::FactorWebauthnUsed, Outcome::Success, &actor.request_id)
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
                event(self, EventKind::SessionHandoff, Outcome::Success, &actor.request_id)
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

    async fn elevate_portal(&self, request: PortalElevation) -> StoreResult<()> {
        super::retry(|| async {
            let now = self.now();
            let mut client = self.client().await?;
            let tx = self.begin(&mut client).await?;
            let actor = &request.actor;
            let view = &actor.view;
            let user = actor.user();
            let sid = &view.session.session_id;
            begin_actor(self, &tx, actor).await?;
            let mut events = request.events.clone();
            let (kind, aal) = match &request.proof {
                PortalProof::Passkey { ceremony, used } => {
                    consume_ceremony(&tx, actor, ceremony, CeremonyPurpose::Verify, &request.portal_binding, None, now).await?;
                    apply_use(&tx, user.as_str(), used, now).await?;
                    events.push(
                        event(self, EventKind::FactorWebauthnUsed, Outcome::Success, &actor.request_id)
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
                    let n = tx
                        .execute(
                            "UPDATE totp_enrollments SET last_counter=$4, updated_at=$5 WHERE enrollment_id=$1 AND user_id=$2 AND revision=$3 AND state='active' AND last_counter<$4",
                            &[enrollment, &user.as_str(), &revision, &counter, &now.secs()],
                        )
                        .await
                        .map_err(pg)?;
                    if n != 1 {
                        return Err(conflict("factor proof unavailable"));
                    }
                    events.push(
                        event(self, EventKind::FactorTotpConsumed, Outcome::Success, &actor.request_id)
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
                    let n = tx
                        .execute(
                            "UPDATE recovery_codes SET used_at=$3 WHERE user_id=$1 AND lookup=$2 AND used_at IS NULL",
                            &[&user.as_str(), lookup, &now.secs()],
                        )
                        .await
                        .map_err(pg)?;
                    if n != 1 {
                        return Err(conflict("recovery code unavailable"));
                    }
                    tx.execute(
                        "UPDATE users SET factor_recovery_required_at=$2 WHERE user_id=$1",
                        &[&user.as_str(), &now.secs()],
                    )
                    .await
                    .map_err(pg)?;
                    let remaining: i64 = tx
                        .query_one(
                            "SELECT count(*) FROM recovery_codes WHERE user_id=$1 AND used_at IS NULL",
                            &[&user.as_str()],
                        )
                        .await
                        .map_err(pg)?
                        .get(0);
                    events.push(
                        event(self, EventKind::FactorRecoveryCodeUsed, Outcome::Success, &actor.request_id)
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
            let generation = rotate(self, &tx, actor, aal, FactorEntry { kind, provider: None, at: now }, &mut events).await?;
            let index = i64::try_from(view.session.factors.len()).map_err(|_| conflict("factor provenance exhausted"))?;
            let config_generation = write::config_generation(&tx).await?;
            match &request.proof {
                PortalProof::Passkey { used, .. } => {
                    record_elevation(&tx, sid, &used.credential_id, now).await?;
                    record_provenance(&tx, sid.as_str(), user.as_str(), generation, &used.credential_id, used.assurance.as_str(), index, now.0, config_generation).await?;
                }
                PortalProof::Totp { enrollment, revision, .. } => {
                    let revision = i64::try_from(*revision).map_err(|_| conflict("invalid enrollment revision"))?;
                    super::factors::record_totp_provenance(&tx, sid, user, generation, enrollment, revision, index, now, config_generation).await?;
                }
                PortalProof::Recovery { .. } => {}
            }
            write::insert_handle(&tx, &request.portal_handle).await?;
            self.insert_events(&tx, &events).await?;
            tx.commit().await.map_err(pg)
        })
        .await
    }

    async fn passkey_clone_detected(
        &self,
        ceremony: &Digest,
        credential_id: &[u8],
        events: Vec<Event>,
    ) -> StoreResult<()> {
        super::retry(|| async {
            let now = self.now();
            let mut client = self.client().await?;
            let tx = self.begin(&mut client).await?;
            let user = tx
                .query_opt(
                    "SELECT c.user_id FROM webauthn_challenges c JOIN webauthn_credentials w ON w.user_id=c.user_id \
                     WHERE c.challenge_sha256=$1 AND c.consumed_at IS NULL AND w.credential_id=$2",
                    &[&ceremony.0.to_vec(), &credential_id],
                )
                .await
                .map_err(pg)?
                .map(|r| UserId::new(r.get::<_, String>(0)))
                .ok_or(conflict(refusal::CEREMONY_UNAVAILABLE))?;
            lock_user(&tx, user.as_str()).await?;
            tx.execute(
                "UPDATE webauthn_challenges SET consumed_at=$2 WHERE challenge_sha256=$1",
                &[&ceremony.0.to_vec(), &now.secs()],
            )
            .await
            .map_err(pg)?;
            let revoked = tx
                .execute(
                    "UPDATE webauthn_credentials SET state='revoked', revoked_at=$3, revoked_reason='counter_regression', revision=revision+1 WHERE credential_id=$1 AND user_id=$2 AND state='active'",
                    &[&credential_id, &user.as_str(), &now.secs()],
                )
                .await
                .map_err(pg)?;
            if revoked == 1 {
                end_elevated_sessions(self, &tx, &user, credential_id, None, reasons::COUNTER_REGRESSION, "r_webauthn_store").await?;
            }
            self.insert_events(&tx, &events).await?;
            tx.commit().await.map_err(pg)
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
        super::retry(|| async {
            let mut client = self.client().await?;
            let tx = self.begin(&mut client).await?;
            begin_actor(self, &tx, &actor).await?;
            let user = actor.user();
            let n = tx
                .execute(
                    "UPDATE webauthn_credentials SET label=$3, revision=revision+1 WHERE credential_id=$1 AND user_id=$2 AND state='active'",
                    &[&credential_id, &user.as_str(), &label],
                )
                .await
                .map_err(pg)?;
            if n != 1 {
                return Ok(false);
            }
            let renamed = event(self, EventKind::FactorWebauthnRenamed, Outcome::Success, &actor.request_id)
                .user(user)
                .session(&actor.view.session.session_id)
                .attr("factor_id", factor_id(credential_id))
                .build();
            self.insert_events(&tx, &[renamed]).await?;
            self.insert_events(&tx, &events).await?;
            tx.commit().await.map_err(pg)?;
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
        super::retry(|| async {
            let now = self.now();
            let mut client = self.client().await?;
            let tx = self.begin(&mut client).await?;
            begin_actor(self, &tx, &actor).await?;
            let user = actor.user();
            let owned = tx
                .query_opt(
                    "SELECT 1 FROM webauthn_credentials WHERE credential_id=$1 AND user_id=$2 AND state='active'",
                    &[&credential_id, &user.as_str()],
                )
                .await
                .map_err(pg)?
                .is_some();
            if !owned {
                return Ok(false);
            }
            if !recent_second_factor(&actor.view.session.factors, now) {
                return Err(conflict(refusal::VERIFICATION_REQUIRED));
            }
            // Under the user lock: concurrent removals serialize.
            if second_factor_count(&tx, user.as_str()).await? <= 1 {
                return Err(conflict(refusal::LAST_FACTOR));
            }
            tx.execute(
                "UPDATE webauthn_credentials SET state='revoked', revoked_at=$3, revoked_reason='removed', revision=revision+1 WHERE credential_id=$1 AND user_id=$2 AND state='active'",
                &[&credential_id, &user.as_str(), &now.secs()],
            )
            .await
            .map_err(pg)?;
            // The acting session continues unless this passkey established it.
            let established_here = actor.view.session.provider_id.as_str()
                == crate::provider::types::PASSKEY_PROVIDER
                && tx
                    .query_opt(
                        "SELECT 1 FROM events WHERE kind='factor.webauthn_used' AND session_id=$1 AND attrs->>'purpose'='login' AND attrs->>'factor_id'=$2",
                        &[&actor.view.session.session_id.as_str(), &factor_id(credential_id)],
                    )
                    .await
                    .map_err(pg)?
                    .is_some();
            let keep = (!established_here).then_some(&actor.view.session.session_id);
            end_elevated_sessions(self, &tx, user, credential_id, keep, reasons::PASSKEY_REMOVED, &actor.request_id).await?;
            let revoked = event(self, EventKind::FactorWebauthnRevoked, Outcome::Success, &actor.request_id)
                .user(user)
                .session(&actor.view.session.session_id)
                .reason(reasons::PASSKEY_REMOVED)
                .attr("factor_id", factor_id(credential_id))
                .build();
            self.insert_events(&tx, &[revoked]).await?;
            self.insert_events(&tx, &events).await?;
            tx.commit().await.map_err(pg)?;
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
        let mut lookups: Vec<&str> = codes.iter().map(|(l, _)| l.as_str()).collect();
        lookups.sort_unstable();
        lookups.dedup();
        if lookups.len() != codes.len() {
            return Err(conflict("duplicate recovery code"));
        }
        super::retry(|| async {
            let now = self.now();
            let mut client = self.client().await?;
            let tx = self.begin(&mut client).await?;
            begin_actor(self, &tx, &actor).await?;
            let user = actor.user();
            let view = &actor.view;
            let factors = second_factor_count(&tx, user.as_str()).await?;
            if factors == 0 {
                return Err(conflict("recovery codes require a second factor"));
            }
            let r = tx
                .query_one(
                    "SELECT count(*) FILTER (WHERE used_at IS NULL), count(*) FROM recovery_codes WHERE user_id=$1",
                    &[&user.as_str()],
                )
                .await
                .map_err(pg)?;
            let (unused, ever): (i64, i64) = (r.get(0), r.get(1));
            // The first set may follow this session's enrollment of the only
            // factor with a fresh primary sign-in (review F1).
            let first_enrollment = if ever == 0 && unused == 0 && factors == 1 {
                let since = (now.0 - crate::store::passkeys::MANAGEMENT_WINDOW.as_millis() as i64) as f64 / 1000.0;
                let enrolled_here = tx
                    .query_opt(
                        "SELECT 1 FROM events WHERE kind='factor.webauthn_registered' AND user_id=$1 AND session_id=$2 AND at>=$3",
                        &[&user.as_str(), &view.session.session_id.as_str(), &since],
                    )
                    .await
                    .map_err(pg)?
                    .is_some();
                enrolled_here && management_allowed(&view.session.factors, view.session.auth_time, false, now)
            } else {
                false
            };
            if !(first_enrollment || recent_possession_factor(&view.session.factors, now)) {
                return Err(conflict(refusal::VERIFICATION_REQUIRED));
            }
            tx.execute("DELETE FROM recovery_codes WHERE user_id=$1", &[&user.as_str()])
                .await
                .map_err(pg)?;
            for (lookup, hash) in &codes {
                tx.execute(
                    "INSERT INTO recovery_codes (user_id, lookup, hash, batch, created_at, used_at) VALUES ($1,$2,$3,$4,$5,NULL)",
                    &[&user.as_str(), lookup, hash, &batch, &now.secs()],
                )
                .await
                .map_err(pg)?;
            }
            let generated = event(self, EventKind::FactorRecoveryCodesGenerated, Outcome::Success, &actor.request_id)
                .user(user)
                .session(&view.session.session_id)
                .attr("kind", "recovery")
                .attr("count", codes.len())
                .build();
            self.insert_events(&tx, &[generated]).await?;
            self.insert_events(&tx, &events).await?;
            tx.commit().await.map_err(pg)
        })
        .await
    }

    async fn recovery_code_hash(&self, user: &UserId, lookup: &str) -> StoreResult<Option<String>> {
        let client = self.client().await?;
        Ok(client
            .query_opt(
                "SELECT r.hash FROM recovery_codes r JOIN users u ON u.user_id=r.user_id WHERE r.user_id=$1 AND r.lookup=$2 AND r.used_at IS NULL AND u.status='active'",
                &[&user.as_str(), &lookup],
            )
            .await
            .map_err(pg)?
            .map(|r| r.get(0)))
    }

    async fn begin_login_ceremony(&self, ceremony: NewLoginCeremony) -> StoreResult<()> {
        if ceremony.state.len() > 65_536 {
            return Err(conflict("invalid ceremony"));
        }
        super::retry(|| async {
            let now = self.now();
            let mut client = self.client().await?;
            let tx = self.begin(&mut client).await?;
            if ceremony.expires_at <= now
                || ceremony.expires_at.since(now) > std::time::Duration::from_secs(600)
            {
                return Err(conflict("invalid ceremony"));
            }
            let ip = ceremony.client_ip.to_string();
            let live = tx
                .query_opt(
                    "SELECT 1 FROM login_txns WHERE txn_sha256=$1 AND purpose='login' AND client_ip=$2 AND consumed_at IS NULL AND created_at<=$3 AND expires_at>$3 \
                     AND state_sha256 IS NULL AND reauth_max_age IS NULL AND (portal_bind_sha256 IS NULL OR portal_bind_sha256=$4) FOR SHARE",
                    &[&ceremony.transaction.0.to_vec(), &ip, &now.secs(), &ceremony.portal_binding.0.to_vec()],
                )
                .await
                .map_err(pg)?;
            if live.is_none() {
                return Err(conflict("login transaction unavailable"));
            }
            // The caps count every replica's rows: one admission at a time.
            tx.execute(super::ADVISORY_XACT_LOCK, &[&LOGIN_CEREMONY_LOCK])
                .await
                .map_err(pg)?;
            tx.execute(
                "DELETE FROM webauthn_login_challenges WHERE expires_at<=$1 OR consumed_at IS NOT NULL",
                &[&now.secs()],
            )
            .await
            .map_err(pg)?;
            let r = tx
                .query_one(
                    "SELECT count(*) FILTER (WHERE client_ip=$1 AND created_at>$2), count(*) FROM webauthn_login_challenges",
                    &[&ip, &(now.secs() - 60)],
                )
                .await
                .map_err(pg)?;
            let (recent, total): (i64, i64) = (r.get(0), r.get(1));
            if recent >= LOGIN_CEREMONIES_PER_MINUTE || total >= MAX_LOGIN_CEREMONIES {
                return Err(conflict(refusal::LOGIN_BUSY));
            }
            tx.execute(
                "INSERT INTO webauthn_login_challenges (challenge_sha256, txn_sha256, portal_bind_sha256, client_ip, state, created_at, expires_at, consumed_at) VALUES ($1,$2,$3,$4,$5,$6,$7,NULL)",
                &[
                    &ceremony.digest.0.to_vec(),
                    &ceremony.transaction.0.to_vec(),
                    &ceremony.portal_binding.0.to_vec(),
                    &ip,
                    &ceremony.state,
                    &now.secs(),
                    &ceremony.expires_at.secs(),
                ],
            )
            .await
            .map_err(pg)?;
            tx.commit().await.map_err(pg)
        })
        .await
    }

    async fn login_ceremony(&self, digest: &Digest) -> StoreResult<Option<LoginCeremonyRecord>> {
        let client = self.client().await?;
        let row = client
            .query_opt(
                "SELECT txn_sha256, portal_bind_sha256, client_ip, state, created_at FROM webauthn_login_challenges WHERE challenge_sha256=$1 AND consumed_at IS NULL AND expires_at>$2",
                &[&digest.0.to_vec(), &self.now().secs()],
            )
            .await
            .map_err(pg)?;
        let Some(r) = row else { return Ok(None) };
        Ok(Some(LoginCeremonyRecord {
            transaction: digest_of(r.get(0), "webauthn_login_challenges.txn_sha256")?,
            portal_bind_sha256: digest_of(
                r.get(1),
                "webauthn_login_challenges.portal_bind_sha256",
            )?,
            client_ip: r
                .get::<_, String>(2)
                .parse()
                .map_err(|_| StoreError::Corrupt("webauthn_login_challenges.client_ip".into()))?,
            state: r.get(3),
            created_at: Timestamp::from_secs(r.get(4)),
        }))
    }

    async fn fail_login_ceremony(&self, digest: &Digest, events: Vec<Event>) -> StoreResult<()> {
        super::retry(|| async {
            let mut client = self.client().await?;
            let tx = self.begin(&mut client).await?;
            tx.execute(
                "UPDATE webauthn_login_challenges SET consumed_at=$2 WHERE challenge_sha256=$1 AND consumed_at IS NULL",
                &[&digest.0.to_vec(), &self.now().secs()],
            )
            .await
            .map_err(pg)?;
            self.insert_events(&tx, &events).await?;
            tx.commit().await.map_err(pg)
        })
        .await
    }

    async fn passkey_account(
        &self,
        handle: [u8; 16],
    ) -> StoreResult<Option<(UserId, Vec<PasskeyRecord>)>> {
        let mut client = self.client().await?;
        let tx = client
            .build_transaction()
            .isolation_level(tokio_postgres::IsolationLevel::RepeatableRead)
            .read_only(true)
            .start()
            .await
            .map_err(pg)?;
        let user = tx
            .query_opt(
                "SELECT user_id FROM users WHERE webauthn_user_handle=$1 AND status='active'",
                &[&handle.to_vec()],
            )
            .await
            .map_err(pg)?
            .map(|r| r.get::<_, String>(0));
        let out = match user {
            None => None,
            Some(user) => {
                let passkeys = active_passkeys(&tx, &user).await?;
                Some((UserId::new(user), passkeys))
            }
        };
        tx.commit().await.map_err(pg)?;
        Ok(out)
    }

    async fn create_passkey_session(&self, login: PasskeyLogin) -> StoreResult<()> {
        let s = &login.session;
        if s.provider_id.as_str() != crate::provider::types::PASSKEY_PROVIDER
            || s.aal != Aal::Two
            || s.cred_gen != 1
            || s.factors.len() != 1
            || s.factors[0].kind != FactorKind::Webauthn
            || login.portal_handle.session_id != s.session_id
            || login.portal_handle.issued_aal != Aal::Two
        {
            return Err(conflict("invalid passkey session"));
        }
        super::retry(|| async {
            let now = self.now();
            let mut client = self.client().await?;
            let tx = self.begin(&mut client).await?;
            let ip = login.client_ip.to_string();
            let consumed = tx
                .execute(
                    "UPDATE webauthn_login_challenges SET consumed_at=$5 WHERE challenge_sha256=$1 AND txn_sha256=$2 AND portal_bind_sha256=$3 AND client_ip=$4 AND consumed_at IS NULL AND expires_at>$5",
                    &[&login.ceremony.0.to_vec(), &login.transaction.0.to_vec(), &login.portal_binding.0.to_vec(), &ip, &now.secs()],
                )
                .await
                .map_err(pg)?;
            if consumed != 1 {
                return Err(conflict(refusal::CEREMONY_UNAVAILABLE));
            }
            let txn = tx
                .execute(
                    "UPDATE login_txns SET consumed_at=$2, consumed_reason='completed', portal_bind_sha256=COALESCE(portal_bind_sha256, $4) WHERE txn_sha256=$1 AND purpose='login' AND client_ip=$3 \
                     AND consumed_at IS NULL AND created_at<=$2 AND expires_at>$2 AND state_sha256 IS NULL AND reauth_max_age IS NULL AND (portal_bind_sha256 IS NULL OR portal_bind_sha256=$4)",
                    &[&login.transaction.0.to_vec(), &now.secs(), &ip, &login.portal_binding.0.to_vec()],
                )
                .await
                .map_err(pg)?;
            if txn != 1 {
                return Err(conflict("login transaction unavailable"));
            }
            let active = tx
                .query_opt(
                    "SELECT 1 FROM users WHERE user_id=$1 AND status='active' AND authz_version=$2 FOR SHARE",
                    &[&s.user_id.as_str(), &i64::try_from(s.authz_version).unwrap_or(i64::MAX)],
                )
                .await
                .map_err(pg)?
                .is_some();
            if !active {
                return Err(conflict("user unavailable"));
            }
            apply_use(&tx, s.user_id.as_str(), &login.used, now).await?;
            write::insert_session(&tx, s).await?;
            write::insert_handle(&tx, &login.portal_handle).await?;
            tx.execute(
                "UPDATE users SET last_login_at=$2 WHERE user_id=$1",
                &[&s.user_id.as_str(), &s.created_at.secs()],
            )
            .await
            .map_err(pg)?;
            tx.execute(
                "INSERT INTO session_webauthn_elevations (session_id, credential_id, at) VALUES ($1,$2,$3)",
                &[&s.session_id.as_str(), &login.used.credential_id, &now.secs()],
            )
            .await
            .map_err(pg)?;
            let config_generation = write::config_generation(&tx).await?;
            record_provenance(
                &tx,
                s.session_id.as_str(),
                s.user_id.as_str(),
                1,
                &login.used.credential_id,
                login.used.assurance.as_str(),
                0,
                s.factors[0].at.0,
                config_generation,
            )
            .await?;
            self.insert_events(&tx, &login.events).await?;
            tx.commit().await.map_err(pg)
        })
        .await
    }

    async fn passkey_login_clone(
        &self,
        ceremony: &Digest,
        credential_id: &[u8],
        events: Vec<Event>,
    ) -> StoreResult<()> {
        super::retry(|| async {
            let now = self.now();
            let mut client = self.client().await?;
            let tx = self.begin(&mut client).await?;
            let n = tx
                .execute(
                    "UPDATE webauthn_login_challenges SET consumed_at=$2 WHERE challenge_sha256=$1 AND consumed_at IS NULL",
                    &[&ceremony.0.to_vec(), &now.secs()],
                )
                .await
                .map_err(pg)?;
            if n != 1 {
                return Err(conflict(refusal::CEREMONY_UNAVAILABLE));
            }
            let user = tx
                .query_opt(
                    "SELECT user_id FROM webauthn_credentials WHERE credential_id=$1 AND state='active'",
                    &[&credential_id],
                )
                .await
                .map_err(pg)?
                .map(|r| UserId::new(r.get::<_, String>(0)));
            if let Some(user) = user {
                lock_user(&tx, user.as_str()).await?;
                let revoked = tx
                    .execute(
                        "UPDATE webauthn_credentials SET state='revoked', revoked_at=$2, revoked_reason='counter_regression', revision=revision+1 WHERE credential_id=$1 AND state='active'",
                        &[&credential_id, &now.secs()],
                    )
                    .await
                    .map_err(pg)?;
                if revoked == 1 {
                    end_elevated_sessions(self, &tx, &user, credential_id, None, reasons::COUNTER_REGRESSION, "r_webauthn_store").await?;
                }
            }
            self.insert_events(&tx, &events).await?;
            tx.commit().await.map_err(pg)
        })
        .await
    }

    async fn end_passkey_sessions(&self, request_id: &str) -> StoreResult<u32> {
        super::retry(|| async {
            let now = self.now();
            let mut client = self.client().await?;
            let tx = self.begin(&mut client).await?;
            let live = tx
                .query(
                    "SELECT session_id, user_id FROM sessions WHERE provider_id=$1 AND terminated_at IS NULL ORDER BY session_id",
                    &[&crate::provider::types::PASSKEY_PROVIDER],
                )
                .await
                .map_err(pg)?;
            let mut n = 0u32;
            for r in live {
                let sid = SessionId::new(r.get::<_, String>(0));
                let ev = event(self, EventKind::SessionTerminated, Outcome::Success, request_id)
                    .user(&UserId::new(r.get::<_, String>(1)))
                    .session(&sid)
                    .reason(reasons::PROVIDER_DISABLED)
                    .build();
                if super::admin::terminate_in(self, &tx, &sid, reasons::PROVIDER_DISABLED, now, &[ev]).await? {
                    n += 1;
                }
            }
            tx.commit().await.map_err(pg)?;
            Ok(n)
        })
        .await
    }

    async fn reset_factors(
        &self,
        user: &UserId,
        request_id: &str,
        events: Vec<Event>,
    ) -> StoreResult<FactorResetReport> {
        super::retry(|| async {
            let now = self.now();
            let mut client = self.client().await?;
            let tx = self.begin(&mut client).await?;
            if lock_user(&tx, user.as_str()).await?.is_none() {
                return Err(conflict("user unavailable"));
            }
            let count = |n: u64| u32::try_from(n).unwrap_or(u32::MAX);
            let passkeys = count(
                tx.execute(
                    "UPDATE webauthn_credentials SET state='revoked', revoked_at=$2, revoked_reason='factor_reset', revision=revision+1 WHERE user_id=$1 AND state='active'",
                    &[&user.as_str(), &now.secs()],
                )
                .await
                .map_err(pg)?,
            );
            let totp = count(
                tx.execute(
                    "UPDATE totp_enrollments SET state='revoked', revision=revision+1, pending_expires_at=NULL, updated_at=$2 WHERE user_id=$1 AND state<>'revoked'",
                    &[&user.as_str(), &now.secs()],
                )
                .await
                .map_err(pg)?,
            );
            let recovery_codes = count(
                tx.execute(
                    "DELETE FROM recovery_codes WHERE user_id=$1 AND used_at IS NULL",
                    &[&user.as_str()],
                )
                .await
                .map_err(pg)?,
            );
            tx.execute("DELETE FROM recovery_codes WHERE user_id=$1", &[&user.as_str()])
                .await
                .map_err(pg)?;
            tx.execute(
                "UPDATE users SET factor_recovery_required_at=NULL WHERE user_id=$1",
                &[&user.as_str()],
            )
            .await
            .map_err(pg)?;
            tx.execute("DELETE FROM webauthn_challenges WHERE user_id=$1", &[&user.as_str()])
                .await
                .map_err(pg)?;
            let sessions = end_user_sessions(self, &tx, user, reasons::FACTOR_RESET, request_id, None).await?;
            let report = FactorResetReport { passkeys, totp, recovery_codes, sessions };
            self.insert_events(&tx, &events).await?;
            tx.commit().await.map_err(pg)?;
            Ok(report)
        })
        .await
    }
}
