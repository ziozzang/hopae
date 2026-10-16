//! Slice 2b for PostgreSQL (ADR-0020): administrator grants, the actor fence
//! and fenced console mutations, and the shared replay ledger.
//!
//! The fence locks the acting administrator's session, handle, user and
//! grant rows `FOR SHARE` while it re-evaluates them: a concurrent
//! revocation of that grant (or termination of that session) waits for the
//! fenced mutation to commit, and a mutation that starts after the
//! revocation sees it — the same serial order the single SQLite writer gives.
use std::time::Duration;

use async_trait::async_trait;
use deadpool_postgres::Transaction;
use tokio_postgres::Row;

use super::{PgStore, corrupt, pg, session};
use crate::crypto::Timestamp;
use crate::event::types::{Event, Reason, reasons};
use crate::identity::types::{NormalizedEmail, UserId};
use crate::session::types::SessionId;
use crate::store::core::{AdminStore, NonceStore, nonce_key_ok};
use crate::store::types::*;
use crate::store::{Deadline, StoreError, StoreResult};

const GRANT_COLS: &str =
    "user_id, role, managed_by, source_email, granted_at, granted_by, revoked_at, revoked_by, note";
const SESSION_COLS: &str = "s.session_id, s.user_id, s.provider_id, s.auth_time, s.factors, s.aal, s.authz_version, s.cred_gen, s.snapshot, s.bound_ip, s.bound_ua_sha256, s.created_at, s.last_seen_at, s.absolute_expires_at, s.terminated_at, s.terminated_reason, s.authz_version_at_auth, s.auth_time_source, s.bound_ua_prefix";

fn grant(r: &Row) -> StoreResult<AdminGrant> {
    Ok(AdminGrant {
        user_id: UserId::new(r.get::<_, String>(0)),
        role: AdminRole::parse(&r.get::<_, String>(1))
            .ok_or_else(|| corrupt("admin_grants.role"))?,
        managed_by: GrantManagedBy::parse(&r.get::<_, String>(2))
            .ok_or_else(|| corrupt("admin_grants.managed_by"))?,
        source_email: r
            .get::<_, Option<String>>(3)
            .map(|s| {
                NormalizedEmail::from_stored(&s).ok_or_else(|| corrupt("admin_grants.source_email"))
            })
            .transpose()?,
        granted_at: Timestamp::from_secs(r.get(4)),
        granted_by: r.get(5),
        revoked_at: r.get::<_, Option<i64>>(6).map(Timestamp::from_secs),
        revoked_by: r.get(7),
        note: r.get(8),
    })
}

fn secs(d: Duration) -> i64 {
    i64::try_from(d.as_secs()).unwrap_or(i64::MAX)
}

/// The actor fence (ADR-0016, P2-02) with the rows it depends on locked.
async fn fence(tx: &Transaction<'_>, now: i64, actor: &Actor, p: &ActorPolicy) -> StoreResult<()> {
    if let Some(proof) = &p.authority {
        return if proof.valid_for(actor) {
            Ok(())
        } else {
            Err(StoreError::Conflict("actor_revoked"))
        };
    }
    let hit = tx
        .query_opt(
            "SELECT 1
             FROM sessions s
             JOIN session_handles h ON h.session_id = s.session_id
             JOIN users u            ON u.user_id = s.user_id
             JOIN admin_grants g     ON g.user_id = s.user_id
             WHERE s.session_id = $1
               AND s.user_id    = $2
               AND s.terminated_at IS NULL
               AND s.created_at <= $3::bigint + $4::bigint
               AND $3::bigint < LEAST(s.absolute_expires_at, s.created_at + $5::bigint)
               AND $3::bigint < s.last_seen_at + $6::bigint
               AND s.auth_time <= $3::bigint + $4::bigint
               AND $3::bigint - s.auth_time < $7::bigint
               AND ($8::boolean = FALSE OR s.auth_time_source = 'provider_claim')
               AND h.handle_sha256 = $9
               AND h.host          = $10
               AND h.revoked_at IS NULL
               AND h.created_at <= $3::bigint + $4::bigint
               AND $3::bigint < LEAST(h.absolute_expires_at, h.created_at + $11::bigint)
               AND $3::bigint < h.last_seen_at + $12::bigint
               AND h.issued_aal >= $13::integer
               AND u.status = 'active'
               AND u.authz_version = s.authz_version_at_auth
               AND g.revoked_at IS NULL
               AND g.role = 'admin'
             FOR SHARE OF s, h, u, g",
            &[
                &actor.session_id.as_str(),
                &actor.user_id.as_str(),
                &now,
                &secs(p.skew),
                &secs(p.session.absolute),
                &secs(p.session.idle),
                &secs(p.max_auth_age),
                &p.capability_requires_claim,
                &actor.handle_sha256.0.to_vec(),
                &p.console_host.as_str(),
                &secs(p.handle.absolute),
                &secs(p.handle.idle),
                &(p.require_aal.as_i64() as i32),
            ],
        )
        .await
        .map_err(pg)?;
    hit.map(|_| ()).ok_or(StoreError::Conflict("actor_revoked"))
}

/// End a live session inside `tx` (idempotent), as SQLite's `terminate_in`.
pub(super) async fn terminate_in(
    store: &PgStore,
    tx: &Transaction<'_>,
    id: &SessionId,
    reason: Reason,
    at: Timestamp,
    events: &[Event],
) -> StoreResult<bool> {
    let live = tx
        .query_opt(
            "SELECT terminated_at FROM sessions WHERE session_id=$1 FOR UPDATE",
            &[&id.as_str()],
        )
        .await
        .map_err(pg)?
        .is_some_and(|r| r.get::<_, Option<i64>>(0).is_none());
    if !live {
        return Ok(false);
    }
    tx.execute(
        "UPDATE sessions SET terminated_at=$2, terminated_reason=$3, cred_gen = cred_gen + 1 WHERE session_id=$1",
        &[&id.as_str(), &at.secs(), &reason.0],
    )
    .await
    .map_err(pg)?;
    tx.execute(
        "UPDATE session_handles SET revoked_at=$2, revoked_reason=$3 WHERE session_id=$1 AND revoked_at IS NULL",
        &[&id.as_str(), &at.secs(), &reasons::SESSION_TERMINATED.0],
    )
    .await
    .map_err(pg)?;
    let code_reason = if reason == reasons::ADMIN {
        reasons::SESSION_TERMINATED
    } else {
        reason
    };
    tx.execute(
        "UPDATE handoff_codes SET consumed_at=$2, consumed_reason=$3 WHERE session_id=$1 AND consumed_at IS NULL",
        &[&id.as_str(), &at.secs(), &code_reason.0],
    )
    .await
    .map_err(pg)?;
    store.insert_events(tx, events).await?;
    Ok(true)
}

/// A statement cancelled by the deadline-derived `statement_timeout`
/// (SQLSTATE 57014) is the deadline, as SQLite reports it.
fn deadline_err(e: StoreError) -> StoreError {
    match e {
        StoreError::Unavailable(m) if m == "postgres sqlstate 57014" => {
            StoreError::Unavailable("deadline".into())
        }
        other => other,
    }
}

fn deadline_ms(d: Deadline) -> u64 {
    d.0.saturating_duration_since(std::time::Instant::now())
        .as_millis()
        .clamp(1, 600_000) as u64
}

impl PgStore {
    /// A fenced write: the statement timeout follows the caller's deadline.
    async fn begin_fenced<'a>(
        &self,
        client: &'a mut deadpool_postgres::Object,
        actor: &Actor,
        policy: &ActorPolicy,
        deadline: Deadline,
    ) -> StoreResult<Transaction<'a>> {
        check_deadline(deadline)?;
        let tx = self.begin(client).await?;
        // Never longer than the configured statement timeout.
        let ms = deadline_ms(deadline).min(self.statement_timeout_ms);
        tx.batch_execute(&format!("SET LOCAL statement_timeout = {ms}"))
            .await
            .map_err(pg)?;
        fence(&tx, self.now().secs(), actor, policy).await?;
        Ok(tx)
    }
}

fn check_deadline(deadline: Deadline) -> StoreResult<()> {
    if std::time::Instant::now() >= deadline.0 {
        return Err(StoreError::Unavailable("deadline".into()));
    }
    Ok(())
}

#[async_trait]
impl AdminStore for PgStore {
    async fn admin_grant(
        &self,
        user: &UserId,
        _deadline: Deadline,
    ) -> StoreResult<Option<AdminGrant>> {
        let client = self.client().await?;
        client
            .query_opt(
                &format!("SELECT {GRANT_COLS} FROM admin_grants WHERE user_id=$1"),
                &[&user.as_str()],
            )
            .await
            .map_err(pg)?
            .map(|r| grant(&r))
            .transpose()
    }

    async fn admin_grants(&self, all: bool, _deadline: Deadline) -> StoreResult<Vec<AdminGrant>> {
        let client = self.client().await?;
        let sql = format!(
            "SELECT {GRANT_COLS} FROM admin_grants {} ORDER BY granted_at, user_id",
            if all { "" } else { "WHERE revoked_at IS NULL" }
        );
        client
            .query(&sql, &[])
            .await
            .map_err(pg)?
            .iter()
            .map(grant)
            .collect()
    }

    async fn grant_admin(
        &self,
        user: &UserId,
        role: AdminRole,
        managed_by: GrantManagedBy,
        source_email: Option<NormalizedEmail>,
        by: &str,
        note: Option<String>,
        at: Timestamp,
        event: Event,
    ) -> StoreResult<(Option<AdminRole>, bool)> {
        super::retry(|| async {
            let mut client = self.client().await?;
            let tx = self.begin(&mut client).await?;
            let status = tx
                .query_opt("SELECT status FROM users WHERE user_id=$1 FOR SHARE", &[&user.as_str()])
                .await
                .map_err(pg)?
                .map(|r| r.get::<_, String>(0));
            match status.as_deref() {
                None => return Err(StoreError::Conflict("unknown user")),
                Some("active") => {}
                Some(_) => return Err(StoreError::Conflict("user_disabled")),
            }
            let existing = tx
                .query_opt(
                    &format!("SELECT {GRANT_COLS} FROM admin_grants WHERE user_id=$1 FOR UPDATE"),
                    &[&user.as_str()],
                )
                .await
                .map_err(pg)?
                .map(|r| grant(&r))
                .transpose()?;
            if let (Some(g), Some(new)) = (&existing, &source_email)
                && let Some(old) = &g.source_email
                && old != new
            {
                return Err(StoreError::Conflict("source_email_bound"));
            }
            let previous = existing.as_ref().map(|g| g.role);
            if let Some(g) = &existing
                && g.revoked_at.is_none()
                && g.role == role
                && g.managed_by == managed_by
                && (note.is_none() || note == g.note)
                && (source_email.is_none() || g.source_email.is_some())
            {
                return Ok((previous, false));
            }
            tx.execute(
                "INSERT INTO admin_grants (user_id, role, managed_by, source_email, granted_at, granted_by, revoked_at, revoked_by, note)
                 VALUES ($1, $2, $3, $4, $5, $6, NULL, NULL, $7)
                 ON CONFLICT (user_id) DO UPDATE SET
                    role = excluded.role, managed_by = excluded.managed_by,
                    source_email = COALESCE(admin_grants.source_email, excluded.source_email),
                    granted_at = excluded.granted_at, granted_by = excluded.granted_by,
                    revoked_at = NULL, revoked_by = NULL, note = excluded.note",
                &[
                    &user.as_str(),
                    &role.as_str(),
                    &managed_by.as_str(),
                    &source_email.as_ref().map(|e| e.as_str()),
                    &at.secs(),
                    &by,
                    &note,
                ],
            )
            .await
            .map_err(pg)?;
            let mut event = event.clone();
            if let Some(p) = previous {
                event.attrs.insert("previous_role".into(), p.as_str().into());
            }
            self.insert_events(&tx, &[event]).await?;
            tx.commit().await.map_err(pg)?;
            Ok((previous, true))
        })
        .await
    }

    async fn revoke_admin(
        &self,
        user: &UserId,
        by: &str,
        managed_by: GrantManagedBy,
        at: Timestamp,
        event: Event,
    ) -> StoreResult<bool> {
        super::retry(|| async {
            let mut client = self.client().await?;
            let tx = self.begin(&mut client).await?;
            let Some(g) = tx
                .query_opt(
                    &format!("SELECT {GRANT_COLS} FROM admin_grants WHERE user_id=$1 FOR UPDATE"),
                    &[&user.as_str()],
                )
                .await
                .map_err(pg)?
                .map(|r| grant(&r))
                .transpose()?
                .filter(|g| g.revoked_at.is_none())
            else {
                return Ok(false);
            };
            tx.execute(
                "UPDATE admin_grants SET revoked_at = $2, revoked_by = $3, managed_by = $4 WHERE user_id = $1",
                &[&user.as_str(), &at.secs(), &by, &managed_by.as_str()],
            )
            .await
            .map_err(pg)?;
            let mut event = event.clone();
            event.attrs.insert("previous_role".into(), g.role.as_str().into());
            self.insert_events(&tx, &[event]).await?;
            tx.commit().await.map_err(pg)?;
            Ok(true)
        })
        .await
    }

    async fn set_user_status(
        &self,
        actor: &Actor,
        policy: &ActorPolicy,
        user: &UserId,
        status: UserStatus,
        deadline: Deadline,
        admin_event: Event,
        mk: &(dyn for<'a> Fn(&'a SessionRow) -> Event + Sync),
    ) -> StoreResult<(bool, u32)> {
        super::retry(|| async {
            let mut client = self.client().await?;
            let tx = self.begin_fenced(&mut client, actor, policy, deadline).await?;
            let current = tx
                .query_opt("SELECT status FROM users WHERE user_id=$1 FOR UPDATE", &[&user.as_str()])
                .await
                .map_err(pg)?
                .map(|r| r.get::<_, String>(0))
                .ok_or(StoreError::Conflict("unknown user"))?;
            if current == status.as_str() {
                return Ok((false, 0));
            }
            let now = self.now();
            tx.execute(
                "UPDATE users SET status = $2, authz_version = authz_version + 1, updated_at = $3 WHERE user_id = $1",
                &[&user.as_str(), &status.as_str(), &now.secs()],
            )
            .await
            .map_err(pg)?;
            let mut ended = 0u32;
            if status == UserStatus::Disabled {
                let rows = tx
                    .query(
                        &format!("SELECT {SESSION_COLS} FROM sessions s WHERE s.user_id = $1 AND s.terminated_at IS NULL AND s.absolute_expires_at > $2 ORDER BY s.created_at, s.session_id FOR UPDATE"),
                        &[&user.as_str(), &now.secs()],
                    )
                    .await
                    .map_err(pg)?;
                for r in rows {
                    check_deadline(deadline)?;
                    let row = session(&r, 0)?;
                    let ev = mk(&row);
                    if terminate_in(self, &tx, &row.session_id, reasons::USER_DISABLED, now, &[ev]).await? {
                        ended += 1;
                    }
                }
            }
            let mut admin_event = admin_event.clone();
            if status == UserStatus::Disabled {
                admin_event.attrs.insert("count".into(), ended.into());
            }
            self.insert_events(&tx, &[admin_event]).await?;
            check_deadline(deadline)?;
            tx.commit().await.map_err(pg)?;
            Ok((true, ended))
        })
        .await
        .map_err(deadline_err)
    }

    async fn admin_terminate_session(
        &self,
        actor: &Actor,
        policy: &ActorPolicy,
        id: &SessionId,
        deadline: Deadline,
        admin_event: Event,
        session_event: Event,
    ) -> StoreResult<bool> {
        super::retry(|| async {
            let mut client = self.client().await?;
            let tx = self
                .begin_fenced(&mut client, actor, policy, deadline)
                .await?;
            let now = self.now();
            if !terminate_in(
                self,
                &tx,
                id,
                reasons::ADMIN,
                now,
                std::slice::from_ref(&session_event),
            )
            .await?
            {
                return Ok(false);
            }
            self.insert_events(&tx, std::slice::from_ref(&admin_event))
                .await?;
            check_deadline(deadline)?;
            tx.commit().await.map_err(pg)?;
            Ok(true)
        })
        .await
        .map_err(deadline_err)
    }
}

#[async_trait]
impl NonceStore for PgStore {
    async fn admit_nonce(
        &self,
        scope: &str,
        nonce: &str,
        expires_at: Timestamp,
        now: Timestamp,
        capacity: u32,
    ) -> StoreResult<bool> {
        if !nonce_key_ok(scope, nonce) {
            return Err(StoreError::Conflict("invalid nonce key"));
        }
        super::retry(|| async {
            let mut client = self.client().await?;
            let tx = self.begin(&mut client).await?;
            tx.execute(
                "DELETE FROM replay_nonces WHERE scope = $1 AND expires_at <= $2",
                &[&scope, &now.secs()],
            )
            .await
            .map_err(pg)?;
            let live: i64 = tx
                .query_one("SELECT count(*) FROM replay_nonces WHERE scope = $1", &[&scope])
                .await
                .map_err(pg)?
                .get(0);
            if live >= i64::from(capacity) {
                return Ok(false);
            }
            // The primary key decides across replicas: one insert wins.
            let n = tx
                .execute(
                    "INSERT INTO replay_nonces (scope, nonce, expires_at) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
                    &[&scope, &nonce, &expires_at.secs()],
                )
                .await
                .map_err(pg)?;
            tx.commit().await.map_err(pg)?;
            Ok(n == 1)
        })
        .await
    }
}
