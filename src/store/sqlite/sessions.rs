//! `Sessions` for SQLite: sessions, handles, login transactions and handoff
//! codes. Every mutation is one `BEGIN IMMEDIATE` transaction on the writer
//! thread, carrying its events and delivery rows.

use std::net::IpAddr;
use std::time::Duration;

use async_trait::async_trait;
use rusqlite::{Connection, OptionalExtension, Transaction, params};

use super::events::insert_events;
use super::rows::{
    self, CODE_COLS, HANDLE_COLS, SESSION_COLS, TXN_COLS, blob, cols, opt_blob, snapshot_json,
};
use super::{Shared, Store, WriterEnv, commit, commit_checked, require_provider_live};
use crate::crypto::{Digest, Timestamp};
use crate::event::types::{Event, Reason, reasons};
use crate::identity::types::UserId;
use crate::policy::types::Host;
use crate::provider::types::ProviderId;
use crate::session::types::{Aal, FactorEntry, SessionId};
use crate::store::types::*;
use crate::store::{Sessions, StoreError, StoreResult};
use crate::verify::lifetimes::{self, LifetimeVerdict};

const CODE_BURN_REASON_REDEEMED: &str = "redeemed";
const CODE_BURN_REASON_CONFLICT: &str = "session_conflict";

pub(super) fn session_by_id(conn: &Connection, id: &SessionId) -> StoreResult<Option<SessionRow>> {
    let sql = format!(
        "SELECT {} FROM sessions WHERE session_id=?1",
        cols("", SESSION_COLS)
    );
    conn.query_row(&sql, [id.as_str()], |r| Ok(rows::session(r, 0)))
        .optional()?
        .transpose()
}

fn code_by_digest(conn: &Connection, d: &Digest) -> StoreResult<Option<HandoffCodeRow>> {
    let sql = format!(
        "SELECT {} FROM handoff_codes WHERE code_sha256=?1",
        cols("", CODE_COLS)
    );
    conn.query_row(&sql, [blob(d)], |r| Ok(rows::code(r, 0)))
        .optional()?
        .transpose()
}

pub(super) fn insert_handle(conn: &Connection, h: &HandleRow) -> StoreResult<()> {
    conn.execute(
        "INSERT INTO session_handles (handle_sha256, session_id, host, issued_aal, created_at, last_seen_at, absolute_expires_at, revoked_at, revoked_reason) VALUES (?1,?2,?3,?4,?5,?6,?7,NULL,NULL)",
        params![
            blob(&h.handle_sha256),
            h.session_id.as_str(),
            h.host.as_str(),
            h.issued_aal.as_i64(),
            h.created_at.secs(),
            h.last_seen_at.secs(),
            h.absolute_expires_at.secs(),
        ],
    )?;
    Ok(())
}

/// Revoke the session's unrevoked handles with `reason`.
pub(super) fn revoke_session_handles(
    tx: &Transaction<'_>,
    id: &SessionId,
    reason: &str,
    at: Timestamp,
) -> StoreResult<()> {
    tx.execute(
        "UPDATE session_handles SET revoked_at=?2, revoked_reason=?3 WHERE session_id=?1 AND revoked_at IS NULL",
        params![id.as_str(), at.secs(), reason],
    )?;
    Ok(())
}

/// Consume the session's outstanding handoff codes with `reason`.
pub(super) fn consume_session_codes(
    tx: &Transaction<'_>,
    id: &SessionId,
    reason: &str,
    at: Timestamp,
) -> StoreResult<()> {
    tx.execute(
        "UPDATE handoff_codes SET consumed_at=?2, consumed_reason=?3 WHERE session_id=?1 AND consumed_at IS NULL",
        params![id.as_str(), at.secs(), reason],
    )?;
    Ok(())
}

fn handle_is_valid(v: &HandleView) -> bool {
    v.handle.revoked_at.is_none() && v.session.terminated_at.is_none()
}

fn finish(tx: Transaction<'_>, shared: &Shared, gate: Option<&str>) -> StoreResult<()> {
    commit(tx, shared, gate)
}

#[async_trait]
impl Sessions for Store {
    async fn create_session(&self, req: CreateSession) -> StoreResult<()> {
        self.write("create_session", move |env| {
            let shared = env.shared.clone();
            if req.portal_handle.handle_sha256 != req.portal_handle_digest {
                return Err(StoreError::Conflict("portal handle digest mismatch"));
            }
            if req.portal_handle.session_id != req.session.session_id {
                return Err(StoreError::Conflict("portal handle names another session"));
            }
            let s = &req.session;
            let tx = env.begin()?;
            require_provider_live(&tx, s.provider_id.as_str())?;
            tx.execute(
                "INSERT INTO sessions (session_id, user_id, provider_id, auth_time, factors, aal, authz_version, cred_gen, snapshot, bound_ip, bound_ua_sha256, created_at, last_seen_at, absolute_expires_at, terminated_at, terminated_reason, authz_version_at_auth, auth_time_source, bound_ua_prefix) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,NULL,NULL,?15,?16,?17)",
                params![
                    s.session_id.as_str(),
                    s.user_id.as_str(),
                    s.provider_id.as_str(),
                    s.auth_time.secs(),
                    rows::json_str(&s.factors)?,
                    s.aal.as_i64(),
                    i64::try_from(s.authz_version).unwrap_or(i64::MAX),
                    i64::try_from(s.cred_gen).unwrap_or(i64::MAX),
                    snapshot_json(&s.snapshot).to_string(),
                    s.bound_ip.to_string(),
                    opt_blob(&s.bound_ua_sha256),
                    s.created_at.secs(),
                    s.last_seen_at.secs(),
                    s.absolute_expires_at.secs(),
                    i64::try_from(s.authz_version_at_auth).unwrap_or(i64::MAX),
                    s.auth_time_source.as_str(),
                    s.bound_ua_prefix,
                ],
            )?;
            insert_handle(&tx, &req.portal_handle)?;
            tx.execute(
                "UPDATE users SET last_login_at=?2 WHERE user_id=?1",
                params![s.user_id.as_str(), s.created_at.secs()],
            )?;
            // The login transaction is consumed in this same transaction
            // (S014-6 b): the session exists only if the transaction was
            // still unconsumed, and a lost race creates nothing.
            if let Some((txn, why)) = &req.consume_txn {
                let n = tx.execute(
                    "UPDATE login_txns SET consumed_at=?2, consumed_reason=?3 WHERE txn_sha256=?1 AND consumed_at IS NULL",
                    params![blob(txn), s.created_at.secs(), why.0],
                )?;
                if n != 1 {
                    return Err(StoreError::Conflict("transaction already consumed"));
                }
            }
            insert_events(&tx, &shared, &req.events)?;
            if let Some(h) = &shared.hooks {
                h.crash_point("before_login_commit");
            }
            finish(tx, &shared, Some("login_commit"))?;
            if let Some(h) = &shared.hooks {
                h.crash_point("after_login_commit");
            }
            Ok(())
        })
        .await
    }

    async fn session(&self, id: &SessionId) -> StoreResult<Option<SessionRow>> {
        let id = id.clone();
        self.read("session", move |c| session_by_id(c, &id)).await
    }

    async fn lookup_handle(
        &self,
        handle_sha256: &Digest,
        host: &Host,
    ) -> StoreResult<Option<HandleView>> {
        let (d, host) = (*handle_sha256, host.to_string());
        self.read("lookup_handle", move |c| {
            let sql = format!(
                "SELECT {}, {}, u.status, u.authz_version, u.groups FROM session_handles h JOIN sessions s ON s.session_id = h.session_id JOIN users u ON u.user_id = s.user_id WHERE h.handle_sha256=?1 AND h.host=?2",
                cols("h", HANDLE_COLS),
                cols("s", SESSION_COLS),
            );
            let hn = HANDLE_COLS.len();
            let sn = SESSION_COLS.len();
            c.query_row(&sql, params![blob(&d), host], |r| {
                Ok((|| {
                    Ok(HandleView {
                        handle: rows::handle(r, 0)?,
                        session: rows::session(r, hn)?,
                        user: rows::user_authz(r, hn + sn)?,
                    })
                })())
            })
            .optional()?
            .transpose()
        })
        .await
    }

    async fn lookup_handle_within(
        &self,
        handle_sha256: &Digest,
        host: &Host,
        deadline: Deadline,
    ) -> StoreResult<Option<HandleView>> {
        let (d, host) = (*handle_sha256, host.to_string());
        self.read_checked("lookup_handle", Some(deadline), move |c, _| {
            let sql = format!(
                "SELECT {}, {}, u.status, u.authz_version, u.groups FROM session_handles h JOIN sessions s ON s.session_id = h.session_id JOIN users u ON u.user_id = s.user_id WHERE h.handle_sha256=?1 AND h.host=?2",
                cols("h", HANDLE_COLS),
                cols("s", SESSION_COLS),
            );
            let hn = HANDLE_COLS.len();
            let sn = SESSION_COLS.len();
            c.query_row(&sql, params![blob(&d), host], |r| {
                Ok((|| {
                    Ok(HandleView {
                        handle: rows::handle(r, 0)?,
                        session: rows::session(r, hn)?,
                        user: rows::user_authz(r, hn + sn)?,
                    })
                })())
            })
            .optional()?
            .transpose()
        })
        .await
    }

    async fn touch_handle(&self, handle_sha256: &Digest, at: Timestamp) -> StoreResult<()> {
        let d = *handle_sha256;
        self.write("touch_handle", move |env| {
            let shared = env.shared.clone();
            let tx = env.begin()?;
            tx.execute(
                "UPDATE session_handles SET last_seen_at = MAX(last_seen_at, ?2) WHERE handle_sha256=?1 AND revoked_at IS NULL",
                params![blob(&d), at.secs()],
            )?;
            tx.execute(
                "UPDATE sessions SET last_seen_at = MAX(last_seen_at, ?2) WHERE terminated_at IS NULL AND session_id = (SELECT session_id FROM session_handles WHERE handle_sha256=?1)",
                params![blob(&d), at.secs()],
            )?;
            finish(tx, &shared, None)
        })
        .await
    }

    async fn mint_handle(
        &self,
        handle: HandleRow,
        replaces: Option<Digest>,
        events: Vec<Event>,
    ) -> StoreResult<()> {
        self.write("mint_handle", move |env| {
            let shared = env.shared.clone();
            let now = shared.clock.now();
            let tx = env.begin()?;
            let session = session_by_id(&tx, &handle.session_id)?
                .filter(|s| s.terminated_at.is_none())
                .ok_or(StoreError::Conflict("session unavailable"))?;
            if let Some(old) = replaces {
                let owner: Option<String> = tx
                    .query_row(
                        "SELECT session_id FROM session_handles WHERE handle_sha256=?1",
                        [blob(&old)],
                        |r| r.get(0),
                    )
                    .optional()?;
                if owner.as_deref() != Some(handle.session_id.as_str()) {
                    return Err(StoreError::Conflict("replaced handle belongs to another session"));
                }
                tx.execute(
                    "UPDATE session_handles SET revoked_at=?2, revoked_reason=?3 WHERE handle_sha256=?1 AND revoked_at IS NULL",
                    params![blob(&old), now.secs(), reasons::REPLACED.0],
                )?;
            }
            let mut h = handle;
            h.issued_aal = h.issued_aal.min(session.aal);
            insert_handle(&tx, &h)?;
            insert_events(&tx, &shared, &events)?;
            finish(tx, &shared, None)
        })
        .await
    }

    async fn revoke_handle(
        &self,
        handle_sha256: &Digest,
        reason: Reason,
        at: Timestamp,
        events: Vec<Event>,
    ) -> StoreResult<()> {
        let d = *handle_sha256;
        self.write("revoke_handle", move |env| {
            let shared = env.shared.clone();
            let tx = env.begin()?;
            let found: Option<(String, Option<i64>)> = tx
                .query_row(
                    "SELECT session_id, revoked_at FROM session_handles WHERE handle_sha256=?1",
                    [blob(&d)],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            let Some((sid, revoked)) = found else {
                return Err(StoreError::Conflict("unknown handle"));
            };
            if revoked.is_some() {
                return Ok(()); // already revoked: nothing changes, nothing is recorded again
            }
            let sid = SessionId::new(sid);
            tx.execute(
                "UPDATE session_handles SET revoked_at=?2, revoked_reason=?3 WHERE handle_sha256=?1",
                params![blob(&d), at.secs(), reason.0],
            )?;
            // ADR-0004: every revocation moves the generation and consumes outstanding codes.
            tx.execute(
                "UPDATE sessions SET cred_gen = cred_gen + 1 WHERE session_id=?1",
                [sid.as_str()],
            )?;
            consume_session_codes(&tx, &sid, reason.0, at)?;
            insert_events(&tx, &shared, &events)?;
            finish(tx, &shared, None)
        })
        .await
    }

    async fn terminate_session(
        &self,
        id: &SessionId,
        reason: Reason,
        at: Timestamp,
        events: Vec<Event>,
    ) -> StoreResult<()> {
        let id = id.clone();
        self.write_checked("terminate_session", None, move |env, check| {
            let shared = env.shared.clone();
            let tx = env.begin()?;
            check.now()?; // the lock may have been waited for
            terminate_in(&tx, &shared, &id, reason, at, &events)?;
            commit_checked(tx, &shared, None, check)
        })
        .await
    }

    async fn consume_logout_ticket(
        &self,
        txn_sha256: &Digest,
        session: Option<&SessionId>,
        reason: Reason,
        at: Timestamp,
        events: Vec<Event>,
    ) -> StoreResult<bool> {
        let (d, session) = (*txn_sha256, session.cloned());
        self.write("consume_logout_ticket", move |env| {
            let shared = env.shared.clone();
            let tx = env.begin()?;
            let n = tx.execute(
                "UPDATE login_txns SET consumed_at=?2, consumed_reason=?3 WHERE txn_sha256=?1 AND purpose='logout' AND consumed_at IS NULL",
                params![blob(&d), at.secs(), reason.0],
            )?;
            if n == 0 {
                return Ok(false);
            }
            if let Some(h) = &shared.hooks {
                h.crash_point("after_ticket_consume");
            }
            // The same write transaction: a ticket is never consumed while the
            // session it names stays live.
            if let Some(id) = &session {
                terminate_in(&tx, &shared, id, reason, at, &events)?;
            }
            finish(tx, &shared, None)?;
            Ok(true)
        })
        .await
    }

    async fn list_live_sessions(
        &self,
        q: SessionsQuery,
        deadline: Deadline,
    ) -> StoreResult<Page<SessionSummary>> {
        self.list_live_sessions_impl(q, deadline).await
    }

    async fn session_summary(
        &self,
        id: &SessionId,
        deadline: Deadline,
    ) -> StoreResult<Option<(SessionSummary, Vec<HandleRow>)>> {
        self.session_summary_impl(id, deadline).await
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
        self.admin_terminate_session_impl(actor, policy, id, deadline, admin_event, session_event)
            .await
    }

    async fn admin_terminate_user_sessions(
        &self,
        actor: &Actor,
        policy: &ActorPolicy,
        user: &UserId,
        deadline: Deadline,
        admin_event: Event,
        mk_session_event: &(dyn for<'a> Fn(&'a SessionRow) -> Event + Sync),
    ) -> StoreResult<u32> {
        let (ask, responder) = super::admin::asker();
        let job =
            self.admin_terminate_user_sessions_job(actor, policy, user, deadline, admin_event, ask);
        responder
            .drive(job, &|row: SessionRow| mk_session_event(&row))
            .await
    }

    async fn reauthenticate_session(
        &self,
        id: &SessionId,
        provider: &ProviderId,
        auth_time: Timestamp,
        source: AuthTimeSource,
        factor: FactorEntry,
        new_portal_handle: HandleRow,
        consume_txn: (Digest, Reason),
        deadline: Deadline,
        events: Vec<Event>,
        mk_revoked_event: &(dyn for<'a> Fn(&'a HandleRow) -> Event + Sync),
    ) -> StoreResult<()> {
        let (ask, responder) = super::admin::asker();
        let job = self.reauthenticate_session_impl(
            id,
            provider,
            auth_time,
            source,
            factor,
            new_portal_handle,
            consume_txn,
            deadline,
            events,
            ask,
        );
        responder
            .drive(job, &|row: HandleRow| mk_revoked_event(&row))
            .await
    }

    async fn refresh_snapshot(
        &self,
        id: &SessionId,
        snapshot: IdentitySnapshot,
        authz_version: u64,
    ) -> StoreResult<()> {
        let id = id.clone();
        self.write("refresh_snapshot", move |env| {
            env.conn.execute(
                "UPDATE sessions SET snapshot=?2, authz_version=?3 WHERE session_id=?1 AND terminated_at IS NULL AND authz_version <= ?3",
                params![
                    id.as_str(),
                    snapshot_json(&snapshot).to_string(),
                    i64::try_from(authz_version).unwrap_or(i64::MAX),
                ],
            )?;
            Ok(())
        })
        .await
    }

    async fn create_transaction(&self, t: NewTransaction, events: Vec<Event>) -> StoreResult<()> {
        self.write("create_transaction", move |env| {
            let shared = env.shared.clone();
            let tx = env.begin()?;
            insert_txn(&tx, &t)?;
            insert_events(&tx, &shared, &events)?;
            finish(tx, &shared, None)
        })
        .await
    }

    async fn create_transaction_capped(
        &self,
        t: NewTransaction,
        events: Vec<Event>,
        since: Timestamp,
        cap: Option<u32>,
        max_rows: u32,
    ) -> StoreResult<Admission> {
        self.write("create_transaction_capped", move |env| {
            let shared = env.shared.clone();
            let tx = env.begin()?;
            // Count, evict and insert in one write transaction: parallel
            // callers are serialized here, so neither the per-address cap nor
            // `txn.max_rows` can be overshot.
            let n: i64 = tx.query_row(
                "SELECT COUNT(*) FROM txn_admissions WHERE ip=?1 AND at >= ?2",
                params![t.client_ip.to_string(), since.secs()],
                |r| r.get(0),
            )?;
            if cap.is_some_and(|cap| n >= i64::from(cap)) {
                return Ok(Admission::OverCap);
            }
            let evicted = evict_to(&tx, max_rows.saturating_sub(1), t.created_at)?;
            insert_txn(&tx, &t)?;
            insert_events(&tx, &shared, &events)?;
            finish(tx, &shared, None)?;
            Ok(Admission::Admitted { evicted })
        })
        .await
    }

    async fn transaction(&self, txn_sha256: &Digest) -> StoreResult<Option<TransactionRow>> {
        let d = *txn_sha256;
        self.read("transaction", move |c| {
            let sql = format!(
                "SELECT {} FROM login_txns WHERE txn_sha256=?1",
                cols("", TXN_COLS)
            );
            c.query_row(&sql, [blob(&d)], |r| Ok(rows::txn(r, 0)))
                .optional()?
                .transpose()
        })
        .await
    }

    async fn transaction_by_state(
        &self,
        state_sha256: &Digest,
    ) -> StoreResult<Option<TransactionRow>> {
        let d = *state_sha256;
        self.read("transaction_by_state", move |c| {
            let sql = format!(
                "SELECT {} FROM login_txns WHERE state_sha256=?1",
                cols("", TXN_COLS)
            );
            c.query_row(&sql, [blob(&d)], |r| Ok(rows::txn(r, 0)))
                .optional()?
                .transpose()
        })
        .await
    }

    async fn bind_transaction(
        &self,
        txn_sha256: &Digest,
        b: TransactionBinding,
    ) -> StoreResult<()> {
        let d = *txn_sha256;
        self.write("bind_transaction", move |env| {
            let now = env.now().secs();
            let tx = env.begin()?;
            let state: Option<(Option<i64>, i64, Option<Vec<u8>>)> = tx
                .query_row(
                    "SELECT consumed_at, expires_at, state_sha256 FROM login_txns WHERE txn_sha256=?1",
                    [blob(&d)],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional()?;
            match state {
                None => return Err(StoreError::Conflict("unknown transaction")),
                Some((Some(_), _, _)) => return Err(StoreError::Conflict("transaction consumed")),
                Some((_, _, Some(_))) => return Err(StoreError::Conflict("transaction already bound")),
                Some((_, expires, _)) if expires <= now => {
                    return Err(StoreError::Conflict("transaction expired"));
                }
                Some(_) => {}
            }
            let n = tx.execute(
                "UPDATE login_txns SET provider_id=?2, state_sha256=?3, nonce=?4, pkce_verifier=?5, portal_bind_sha256=?6 WHERE txn_sha256=?1 AND state_sha256 IS NULL AND consumed_at IS NULL",
                params![
                    blob(&d),
                    b.provider_id.as_str(),
                    blob(&b.state_sha256),
                    b.nonce,
                    b.pkce_verifier.expose(),
                    blob(&b.portal_bind_sha256),
                ],
            )?;
            if n != 1 {
                return Err(StoreError::Conflict("transaction already bound"));
            }
            tx.commit()?;
            Ok(())
        })
        .await
    }

    async fn bind_switch_transaction(
        &self,
        txn_sha256: &Digest,
        portal_bind_sha256: Digest,
    ) -> StoreResult<bool> {
        let d = *txn_sha256;
        self.write("bind_switch_transaction", move |env| {
            let n = env.conn.execute(
                "UPDATE login_txns SET portal_bind_sha256=?2 WHERE txn_sha256=?1 AND purpose='switch' AND portal_bind_sha256 IS NULL AND consumed_at IS NULL",
                params![blob(&d), blob(&portal_bind_sha256)],
            )?;
            Ok(n == 1)
        })
        .await
    }

    async fn bind_logout_transaction(
        &self,
        txn_sha256: &Digest,
        portal_bind_sha256: Digest,
    ) -> StoreResult<bool> {
        let d = *txn_sha256;
        self.write("bind_logout_transaction", move |env| {
            let n = env.conn.execute(
                "UPDATE login_txns SET portal_bind_sha256=?2 WHERE txn_sha256=?1 AND purpose='logout' AND portal_bind_sha256 IS NULL AND consumed_at IS NULL",
                params![blob(&d), blob(&portal_bind_sha256)],
            )?;
            Ok(n == 1)
        })
        .await
    }

    async fn use_retry(&self, txn_sha256: &Digest, at: Timestamp) -> StoreResult<bool> {
        let d = *txn_sha256;
        self.write("use_retry", move |env| {
            let n = env.conn.execute(
                "UPDATE login_txns SET retry_used_at=?2 WHERE txn_sha256=?1 AND retry_used_at IS NULL",
                params![blob(&d), at.secs()],
            )?;
            Ok(n == 1)
        })
        .await
    }

    async fn record_retry_bind(
        &self,
        txn_sha256: &Digest,
        retry_bind_sha256: Digest,
    ) -> StoreResult<()> {
        let d = *txn_sha256;
        self.write("record_retry_bind", move |env| {
            let n = env.conn.execute(
                "UPDATE login_txns SET retry_bind_sha256=?2 WHERE txn_sha256=?1 AND retry_bind_sha256 IS NULL",
                params![blob(&d), blob(&retry_bind_sha256)],
            )?;
            if n != 1 {
                return Err(StoreError::Conflict("retry bind already recorded or transaction unknown"));
            }
            Ok(())
        })
        .await
    }

    async fn consume_transaction(
        &self,
        txn_sha256: &Digest,
        reason: Reason,
        at: Timestamp,
        events: Vec<Event>,
    ) -> StoreResult<bool> {
        self.consume_txn("consume_transaction", txn_sha256, None, reason, at, events)
            .await
    }

    async fn consume_transaction_for_provider(
        &self,
        txn_sha256: &Digest,
        provider: &ProviderId,
        reason: Reason,
        at: Timestamp,
        events: Vec<Event>,
    ) -> StoreResult<bool> {
        self.consume_txn(
            "consume_transaction",
            txn_sha256,
            Some(provider.clone()),
            reason,
            at,
            events,
        )
        .await
    }

    async fn mint_handoff_code(&self, code: HandoffCodeRow, events: Vec<Event>) -> StoreResult<()> {
        self.write("mint_handoff_code", move |env| {
            let shared = env.shared.clone();
            let tx = env.begin()?;
            let session = session_by_id(&tx, &code.session_id)?
                .filter(|s| s.terminated_at.is_none())
                .ok_or(StoreError::Conflict("session unavailable"))?;
            if session.cred_gen != code.cred_gen {
                return Err(StoreError::Conflict("stale credential generation"));
            }
            tx.execute(
                "INSERT INTO handoff_codes (code_sha256, session_id, host, return_target, return_path, client_ip, bind_sha256, issued_aal, cred_gen, recovery_depth, created_at, expires_at, consumed_at, consumed_reason) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,NULL,NULL)",
                params![
                    blob(&code.code_sha256),
                    code.session_id.as_str(),
                    code.host.as_str(),
                    code.return_target.as_str(),
                    code.return_target.path(),
                    code.client_ip.to_string(),
                    blob(&code.bind_sha256),
                    code.issued_aal.as_i64(),
                    i64::try_from(code.cred_gen).unwrap_or(i64::MAX),
                    i64::from(code.recovery_depth),
                    code.created_at.secs(),
                    code.expires_at.secs(),
                ],
            )?;
            insert_events(&tx, &shared, &events)?;
            finish(tx, &shared, None)
        })
        .await
    }

    async fn redeem_handoff_code(
        &self,
        req: RedeemRequest,
        events_on_success: Vec<Event>,
        events_on_failure: Vec<Event>,
    ) -> StoreResult<RedeemOutcome> {
        self.write("redeem_handoff_code", move |env| {
            redeem(env, req, &events_on_success, &events_on_failure)
        })
        .await
    }

    async fn count_transactions_since(&self, ip: IpAddr, since: Timestamp) -> StoreResult<u32> {
        self.read("count_transactions_since", move |c| {
            let n: i64 = c.query_row(
                "SELECT COUNT(*) FROM txn_admissions WHERE ip=?1 AND at >= ?2",
                params![ip.to_string(), since.secs()],
                |r| r.get(0),
            )?;
            Ok(u32::try_from(n).unwrap_or(u32::MAX))
        })
        .await
    }

    async fn count_handoff_failures_since(&self, ip: IpAddr, since: Timestamp) -> StoreResult<u32> {
        self.read("count_handoff_failures_since", move |c| {
            let n: i64 = c.query_row(
                "SELECT COUNT(*) FROM events WHERE kind='handoff.rejected' AND client_ip=?1 AND at >= ?2 AND COALESCE(reason, '') != 'rate_limited'",
                params![ip.to_string(), since.0 as f64 / 1000.0],
                |r| r.get(0),
            )?;
            Ok(u32::try_from(n).unwrap_or(u32::MAX))
        })
        .await
    }

    async fn evict_transactions(&self, max_rows: u32, now: Timestamp) -> StoreResult<u32> {
        self.write("evict_transactions", move |env| {
            let shared = env.shared.clone();
            let tx = env.begin()?;
            let n = evict_to(&tx, max_rows, now)?;
            finish(tx, &shared, None)?;
            Ok(n)
        })
        .await
    }

    async fn sweep(&self, now: Timestamp, retention: Duration) -> StoreResult<SweepReport> {
        self.write("sweep", move |env| {
            let shared = env.shared.clone();
            let tx = env.begin()?;
            let n = |x: usize| u32::try_from(x).unwrap_or(u32::MAX);
            let transactions = n(tx.execute(
                "DELETE FROM login_txns WHERE expires_at <= ?1",
                [now.secs()],
            )?);
            let codes = n(tx.execute(
                "DELETE FROM handoff_codes WHERE expires_at <= ?1",
                [now.secs()],
            )?);
            // Handles and remaining codes of a deleted session go with it (ON DELETE CASCADE).
            let sessions = n(tx.execute(
                "DELETE FROM sessions WHERE terminated_at IS NOT NULL AND terminated_at <= ?1",
                [now.sub(retention).secs()],
            )?);
            finish(tx, &shared, None)?;
            Ok(SweepReport {
                transactions,
                codes,
                sessions,
            })
        })
        .await
    }
}

impl Store {
    /// Consume a transaction; with `provider`, in the same write transaction
    /// that checks the provider row is enabled and not tombstoned.
    async fn consume_txn(
        &self,
        method: &'static str,
        txn_sha256: &Digest,
        provider: Option<ProviderId>,
        reason: Reason,
        at: Timestamp,
        events: Vec<Event>,
    ) -> StoreResult<bool> {
        let d = *txn_sha256;
        self.write(method, move |env| {
            let shared = env.shared.clone();
            let tx = env.begin()?;
            if let Some(p) = &provider {
                require_provider_live(&tx, p.as_str())?;
            }
            let n = tx.execute(
                "UPDATE login_txns SET consumed_at=?2, consumed_reason=?3 WHERE txn_sha256=?1 AND consumed_at IS NULL",
                params![blob(&d), at.secs(), reason.0],
            )?;
            if n == 0 {
                return Ok(false);
            }
            insert_events(&tx, &shared, &events)?;
            finish(tx, &shared, None)?;
            Ok(true)
        })
        .await
    }
}

/// End a session inside `tx`: idempotent (an unknown or already terminated
/// session changes nothing and records no events).
pub(super) fn terminate_in(
    tx: &Transaction<'_>,
    shared: &Shared,
    id: &SessionId,
    reason: Reason,
    at: Timestamp,
    events: &[Event],
) -> StoreResult<()> {
    let state: Option<Option<i64>> = tx
        .query_row(
            "SELECT terminated_at FROM sessions WHERE session_id=?1",
            [id.as_str()],
            |r| r.get(0),
        )
        .optional()?;
    if !matches!(state, Some(None)) {
        return Ok(());
    }
    tx.execute(
        "UPDATE sessions SET terminated_at=?2, terminated_reason=?3, cred_gen = cred_gen + 1 WHERE session_id=?1",
        params![id.as_str(), at.secs(), reason.0],
    )?;
    revoke_session_handles(tx, id, reasons::SESSION_TERMINATED.0, at)?;
    // A code consumed by an administrator's termination reads like the
    // revoked handles (scenario 302-3); every other ending keeps its own reason.
    let code_reason = if reason == reasons::ADMIN {
        reasons::SESSION_TERMINATED
    } else {
        reason
    };
    consume_session_codes(tx, id, code_reason.0, at)?;
    insert_events(tx, shared, events)?;
    Ok(())
}

/// Delete transactions until at most `keep` remain: dead rows (consumed or
/// expired) go before live ones, oldest first within each group.
fn evict_to(tx: &Transaction<'_>, keep: u32, now: Timestamp) -> StoreResult<u32> {
    let total: i64 = tx.query_row("SELECT COUNT(*) FROM login_txns", [], |r| r.get(0))?;
    let excess = total - i64::from(keep);
    if excess <= 0 {
        return Ok(0);
    }
    let n = tx.execute(
        "DELETE FROM login_txns WHERE txn_sha256 IN (SELECT txn_sha256 FROM login_txns ORDER BY (consumed_at IS NULL AND expires_at > ?1), created_at, rowid LIMIT ?2)",
        params![now.secs(), excess],
    )?;
    Ok(u32::try_from(n).unwrap_or(u32::MAX))
}

fn insert_txn(tx: &Transaction<'_>, t: &NewTransaction) -> StoreResult<()> {
    // Admission history lives in its own small table so that evicting
    // transaction rows never erases rate-limit evidence (G7 C07).
    tx.execute(
        "INSERT INTO txn_admissions (ip, at) VALUES (?1, ?2)",
        params![t.client_ip.to_string(), t.created_at.secs()],
    )?;
    tx.execute(
        "DELETE FROM txn_admissions WHERE at < ?1",
        [t.created_at.secs() - 3600],
    )?;
    tx.execute(
        "INSERT INTO login_txns (txn_sha256, created_at, expires_at, app_id, return_target, bind_sha256, portal_bind_sha256, retry_bind_sha256, client_ip, ua_sha256, provider_id, state_sha256, nonce, pkce_verifier, portal_session_id, purpose, conflicting_handle_sha256, pending_identity, recovery_depth, reauth_max_age) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20)",
        params![
            blob(&t.txn_sha256),
            t.created_at.secs(),
            t.expires_at.secs(),
            t.app_id.as_str(),
            t.return_target.as_str(),
            opt_blob(&t.bind_sha256),
            opt_blob(&t.portal_bind_sha256),
            opt_blob(&t.retry_bind_sha256),
            t.client_ip.to_string(),
            opt_blob(&t.ua_sha256),
            t.provider_id.as_ref().map(|p| p.as_str()),
            opt_blob(&t.state_sha256),
            t.nonce,
            t.pkce_verifier.as_ref().map(|s| s.expose()),
            t.portal_session_id.as_ref().map(|s| s.as_str()),
            t.purpose.as_str(),
            opt_blob(&t.conflicting_handle_sha256),
            t.pending_identity.as_ref().map(|v| v.to_string()),
            i64::from(t.recovery_depth),
            t.reauth_max_age.map(i64::from),
        ],
    )?;
    Ok(())
}

/// ADR-0004 redemption as one transaction: the pinned conditional `UPDATE`
/// decides; a failed update is classified from the row and burns the code.
fn redeem(
    env: &mut WriterEnv,
    req: RedeemRequest,
    ok_events: &[Event],
    fail_events: &[Event],
) -> StoreResult<RedeemOutcome> {
    let shared = env.shared.clone();
    let tx = env.begin()?;
    let now = req.now.secs();
    let presented = req.presented_handle.as_ref().filter(|v| handle_is_valid(v));
    let browser_holds_handle = presented.is_some();
    let max_recoveries = req.max_recoveries;
    let fail = |tx: Transaction<'_>, outcome: RedeemOutcome| -> StoreResult<RedeemOutcome> {
        // The failure events name the classified reason and the session of
        // the burned code. For a known code they also carry its recovery
        // depth, and a rejection at the bound (ADR-0014: depth carries on the
        // first rejection of a code, never on `code_consumed`, and only while
        // the browser holds no valid handle) is recorded as exhausted, with
        // the classified reason kept as `cause`.
        let (why, sid, depth, exhausted) = match &outcome {
            RedeemOutcome::Rejected { reason, code } => (
                Some(*reason),
                code.as_ref().map(|c| c.session_id.clone()),
                code.as_ref().map(|c| c.recovery_depth),
                code.as_ref().is_some_and(|c| {
                    *reason != reasons::CODE_CONSUMED
                        && !browser_holds_handle
                        && c.recovery_depth >= max_recoveries
                }),
            ),
            RedeemOutcome::SessionConflict { code } => (
                Some(reasons::SESSION_CONFLICT),
                Some(code.session_id.clone()),
                Some(code.recovery_depth),
                false,
            ),
            _ => (None, None, None, false),
        };
        let fail_events: Vec<Event> = fail_events
            .iter()
            .cloned()
            .map(|mut e| {
                if e.reason.is_none() {
                    e.reason = why;
                }
                if e.session_id.is_none() {
                    e.session_id = sid.clone();
                }
                if let Some(d) = depth {
                    e.attrs.insert("recovery_depth".into(), d.into());
                }
                if exhausted {
                    if let Some(w) = why {
                        e.attrs.insert("cause".into(), w.0.into());
                    }
                    e.reason = Some(reasons::HANDOFF_RECOVERY_EXHAUSTED);
                }
                e
            })
            .collect();
        insert_events(&tx, &shared, &fail_events)?;
        finish(tx, &shared, Some("redeem"))?;
        Ok(outcome)
    };

    let Some(code) = code_by_digest(&tx, &req.code_sha256)? else {
        return fail(
            tx,
            RedeemOutcome::Rejected {
                reason: reasons::CODE_UNKNOWN,
                code: None,
            },
        );
    };
    let session = session_by_id(&tx, &code.session_id)?;

    if code.consumed_at.is_some() {
        let same_session_handle = presented
            .is_some_and(|v| v.session.session_id == code.session_id && v.handle.host == req.host);
        if code.consumed_reason.as_deref() == Some(CODE_BURN_REASON_REDEEMED) && same_session_handle
        {
            tx.commit()?;
            return Ok(RedeemOutcome::AlreadyRedeemed);
        }
        return fail(
            tx,
            RedeemOutcome::Rejected {
                reason: reasons::CODE_CONSUMED,
                code: Some(code),
            },
        );
    }

    // ADR-0007: the session's own timers are evaluated in this transaction,
    // before anything is minted or touched. An expired session is terminated
    // here and the code is rejected (G7-C01).
    if let Some(s) = session.as_ref().filter(|s| s.terminated_at.is_none())
        && let LifetimeVerdict::SessionExpired(reason) = lifetimes::evaluate(
            &req.new_handle,
            s,
            &req.app_lifetimes,
            &req.session_policy,
            req.now,
        )
    {
        tx.execute(
            "UPDATE sessions SET terminated_at=?2, terminated_reason=?3, cred_gen = cred_gen + 1 WHERE session_id=?1 AND terminated_at IS NULL",
            params![s.session_id.as_str(), now, reason.0],
        )?;
        revoke_session_handles(&tx, &s.session_id, reasons::SESSION_TERMINATED.0, req.now)?;
        consume_session_codes(&tx, &s.session_id, reason.0, req.now)?;
        let events: Vec<Event> = req
            .expiry_events
            .iter()
            .cloned()
            .map(|mut e| {
                e.reason = Some(reason);
                e.session_id = Some(s.session_id.clone());
                e.user_id = Some(s.user_id.clone());
                e.provider_id = Some(s.provider_id.clone());
                e
            })
            .collect();
        insert_events(&tx, &shared, &events)?;
        let burned = code_by_digest(&tx, &req.code_sha256)?;
        return fail(
            tx,
            RedeemOutcome::Rejected {
                reason,
                code: burned,
            },
        );
    }

    let other_user = match (&session, presented) {
        (Some(s), Some(v)) => v.session.user_id != s.user_id,
        _ => false,
    };
    let consume_as = if other_user {
        CODE_BURN_REASON_CONFLICT
    } else {
        CODE_BURN_REASON_REDEEMED
    };
    let changed = tx.execute(
        "UPDATE handoff_codes SET consumed_at=?1, consumed_reason=?2 WHERE code_sha256=?3 AND consumed_at IS NULL AND expires_at>?1 AND host=?4 AND return_path=?5 AND client_ip=?6 AND bind_sha256=?7 AND cred_gen=(SELECT cred_gen FROM sessions WHERE session_id=handoff_codes.session_id AND terminated_at IS NULL)",
        params![
            now,
            consume_as,
            blob(&req.code_sha256),
            req.host.as_str(),
            req.path,
            req.client_ip.to_string(),
            opt_blob(&req.presented_bind_sha256),
        ],
    )?;

    if changed == 1 {
        let burned = code_by_digest(&tx, &req.code_sha256)?
            .ok_or_else(|| StoreError::Corrupt("handoff code vanished".into()))?;
        if other_user {
            return fail(tx, RedeemOutcome::SessionConflict { code: burned });
        }
        let session =
            session.ok_or_else(|| StoreError::Corrupt("handoff code without session".into()))?;
        if req.new_handle.host != req.host {
            return Err(StoreError::Conflict("new handle does not match the code"));
        }
        let issued_aal: Aal = code.issued_aal.min(session.aal);
        let mut handle = req.new_handle.clone();
        handle.session_id = code.session_id.clone();
        handle.issued_aal = issued_aal;
        if let Some(old) = presented
            && old.session.session_id == code.session_id
            && old.handle.host == req.host
            && old.handle.handle_sha256 != handle.handle_sha256
        {
            tx.execute(
                "UPDATE session_handles SET revoked_at=?2, revoked_reason=?3 WHERE handle_sha256=?1 AND revoked_at IS NULL",
                params![blob(&old.handle.handle_sha256), now, reasons::REPLACED.0],
            )?;
        }
        insert_handle(&tx, &handle)?;
        tx.execute(
            "UPDATE sessions SET last_seen_at = MAX(last_seen_at, ?2) WHERE session_id=?1",
            params![code.session_id.as_str(), now],
        )?;
        let ok_events: Vec<Event> = ok_events
            .iter()
            .cloned()
            .map(|mut e| {
                if e.session_id.is_none() {
                    e.session_id = Some(code.session_id.clone());
                    e.user_id = Some(session.user_id.clone());
                }
                e
            })
            .collect();
        insert_events(&tx, &shared, &ok_events)?;
        let session = session_by_id(&tx, &code.session_id)?
            .ok_or_else(|| StoreError::Corrupt("session vanished".into()))?;
        finish(tx, &shared, Some("redeem"))?;
        return Ok(RedeemOutcome::Minted {
            session,
            issued_aal,
        });
    }

    // The conditional update matched nothing: say why, and burn the code.
    let reason = if code.expires_at.secs() <= now {
        reasons::CODE_EXPIRED
    } else if code.host != req.host {
        reasons::CODE_HOST_MISMATCH
    } else if code.return_target.path() != req.path {
        reasons::CODE_PATH_MISMATCH
    } else if code.client_ip != req.client_ip {
        reasons::CODE_IP_MISMATCH
    } else if req.presented_bind_sha256 != Some(code.bind_sha256) {
        reasons::BIND_MISMATCH
    } else {
        reasons::CODE_STALE_GENERATION
    };
    tx.execute(
        "UPDATE handoff_codes SET consumed_at=?2, consumed_reason=?3 WHERE code_sha256=?1 AND consumed_at IS NULL",
        params![blob(&req.code_sha256), now, reason.0],
    )?;
    let burned = code_by_digest(&tx, &req.code_sha256)?;
    fail(
        tx,
        RedeemOutcome::Rejected {
            reason,
            code: burned,
        },
    )
}

impl Store {
    /// Test support: raise the session to AAL2 in one transaction (commit gate
    /// `elevate`): `cred_gen += 1`, every handle revoked (reason `elevation`),
    /// every outstanding code consumed (reason `elevation`).
    #[cfg(any(test, feature = "test-hooks"))]
    pub async fn elevate_session(
        &self,
        id: &SessionId,
        at: Timestamp,
        events: Vec<Event>,
    ) -> StoreResult<()> {
        let id = id.clone();
        self.write("elevate_session", move |env| {
            let shared = env.shared.clone();
            let tx = env.begin()?;
            let live = session_by_id(&tx, &id)?.is_some_and(|s| s.terminated_at.is_none());
            if !live {
                return Err(StoreError::Conflict("session unavailable"));
            }
            tx.execute(
                "UPDATE sessions SET aal = 2, cred_gen = cred_gen + 1 WHERE session_id=?1",
                [id.as_str()],
            )?;
            revoke_session_handles(&tx, &id, reasons::ELEVATION.0, at)?;
            consume_session_codes(&tx, &id, reasons::ELEVATION.0, at)?;
            insert_events(&tx, &shared, &events)?;
            finish(tx, &shared, Some("elevate"))
        })
        .await
    }
}
