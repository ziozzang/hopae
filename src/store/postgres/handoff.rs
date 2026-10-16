//! Slice 2a for PostgreSQL (ADR-0020): login transactions and the ADR-0004
//! handoff-code redemption. The redemption locks the code row and the
//! session row (`FOR UPDATE`) before deciding, so concurrent replicas
//! redeeming the same code serialize exactly like the single SQLite writer:
//! one mints, the others see a consumed code.
use std::net::IpAddr;

use async_trait::async_trait;
use tokio_postgres::Row;

use super::{PgStore, corrupt, digest, pg, session};
use crate::crypto::{Digest, Secret, Timestamp};
use crate::event::types::{Event, Reason, reasons};
use crate::policy::types::{AppId, Host};
use crate::provider::types::ProviderId;
use crate::session::types::{Aal, SessionId};
use crate::store::core::HandoffStore;
use crate::store::types::*;
use crate::store::{StoreError, StoreResult};
use crate::verify::lifetimes::{self, LifetimeVerdict};

const BURN_REDEEMED: &str = "redeemed";
const BURN_CONFLICT: &str = "session_conflict";

const TXN_COLS: &str = "txn_sha256, created_at, expires_at, app_id, return_target, bind_sha256, portal_bind_sha256, retry_bind_sha256, client_ip, ua_sha256, provider_id, state_sha256, nonce, pkce_verifier, portal_session_id, purpose, conflicting_handle_sha256, pending_identity, recovery_depth, consumed_at, consumed_reason, reauth_max_age";
const CODE_COLS: &str = "code_sha256, session_id, host, return_target, client_ip, bind_sha256, issued_aal, cred_gen, recovery_depth, created_at, expires_at, consumed_at, consumed_reason";
const SESSION_COLS: &str = "s.session_id, s.user_id, s.provider_id, s.auth_time, s.factors, s.aal, s.authz_version, s.cred_gen, s.snapshot, s.bound_ip, s.bound_ua_sha256, s.created_at, s.last_seen_at, s.absolute_expires_at, s.terminated_at, s.terminated_reason, s.authz_version_at_auth, s.auth_time_source, s.bound_ua_prefix";

fn opt_digest(r: &Row, i: usize, col: &str) -> StoreResult<Option<Digest>> {
    r.get::<_, Option<Vec<u8>>>(i)
        .map(|b| digest(b, col))
        .transpose()
}
fn bytes(d: &Option<Digest>) -> Option<Vec<u8>> {
    d.as_ref().map(|d| d.0.to_vec())
}

fn txn(r: &Row) -> StoreResult<TransactionRow> {
    let target: String = r.get(4);
    Ok(TransactionRow {
        txn_sha256: digest(r.get(0), "login_txns.txn_sha256")?,
        created_at: Timestamp::from_secs(r.get(1)),
        expires_at: Timestamp::from_secs(r.get(2)),
        app_id: AppId::new(r.get::<_, String>(3)),
        return_target: url::Url::parse(&target).map_err(|_| corrupt("login_txns.return_target"))?,
        bind_sha256: opt_digest(r, 5, "login_txns.bind_sha256")?,
        portal_bind_sha256: opt_digest(r, 6, "login_txns.portal_bind_sha256")?,
        retry_bind_sha256: opt_digest(r, 7, "login_txns.retry_bind_sha256")?,
        client_ip: r
            .get::<_, String>(8)
            .parse()
            .map_err(|_| corrupt("login_txns.client_ip"))?,
        ua_sha256: opt_digest(r, 9, "login_txns.ua_sha256")?,
        provider_id: r.get::<_, Option<String>>(10).map(ProviderId::new),
        state_sha256: opt_digest(r, 11, "login_txns.state_sha256")?,
        nonce: r.get(12),
        pkce_verifier: r.get::<_, Option<String>>(13).map(Secret::new),
        portal_session_id: r.get::<_, Option<String>>(14).map(SessionId::new),
        purpose: TxnPurpose::parse(&r.get::<_, String>(15))
            .ok_or_else(|| corrupt("login_txns.purpose"))?,
        conflicting_handle_sha256: opt_digest(r, 16, "login_txns.conflicting_handle_sha256")?,
        pending_identity: r
            .get::<_, Option<String>>(17)
            .map(|p| serde_json::from_str(&p))
            .transpose()
            .map_err(|_| corrupt("login_txns.pending_identity"))?,
        recovery_depth: u32::try_from(r.get::<_, i32>(18))
            .map_err(|_| corrupt("login_txns.recovery_depth"))?,
        consumed_at: r.get::<_, Option<i64>>(19).map(Timestamp::from_secs),
        consumed_reason: r.get(20),
        reauth_max_age: r
            .get::<_, Option<i32>>(21)
            .map(|n| u32::try_from(n).map_err(|_| corrupt("login_txns.reauth_max_age")))
            .transpose()?,
    })
}

fn code(r: &Row) -> StoreResult<HandoffCodeRow> {
    let target: String = r.get(3);
    Ok(HandoffCodeRow {
        code_sha256: digest(r.get(0), "handoff_codes.code_sha256")?,
        session_id: SessionId::new(r.get::<_, String>(1)),
        host: Host::parse(&r.get::<_, String>(2)).map_err(|_| corrupt("handoff_codes.host"))?,
        return_target: url::Url::parse(&target)
            .map_err(|_| corrupt("handoff_codes.return_target"))?,
        client_ip: r
            .get::<_, String>(4)
            .parse()
            .map_err(|_| corrupt("handoff_codes.client_ip"))?,
        bind_sha256: digest(r.get(5), "handoff_codes.bind_sha256")?,
        issued_aal: Aal::from_i64(i64::from(r.get::<_, i32>(6)))
            .ok_or_else(|| corrupt("handoff_codes.issued_aal"))?,
        cred_gen: u64::try_from(r.get::<_, i64>(7))
            .map_err(|_| corrupt("handoff_codes.cred_gen"))?,
        recovery_depth: u32::try_from(r.get::<_, i32>(8))
            .map_err(|_| corrupt("handoff_codes.recovery_depth"))?,
        created_at: Timestamp::from_secs(r.get(9)),
        expires_at: Timestamp::from_secs(r.get(10)),
        consumed_at: r.get::<_, Option<i64>>(11).map(Timestamp::from_secs),
        consumed_reason: r.get(12),
    })
}

async fn code_locked(
    tx: &deadpool_postgres::Transaction<'_>,
    d: &Digest,
) -> StoreResult<Option<HandoffCodeRow>> {
    tx.query_opt(
        &format!("SELECT {CODE_COLS} FROM handoff_codes WHERE code_sha256=$1 FOR UPDATE"),
        &[&d.0.to_vec()],
    )
    .await
    .map_err(pg)?
    .map(|r| code(&r))
    .transpose()
}

async fn session_locked(
    tx: &deadpool_postgres::Transaction<'_>,
    id: &SessionId,
) -> StoreResult<Option<SessionRow>> {
    tx.query_opt(
        &format!("SELECT {SESSION_COLS} FROM sessions s WHERE s.session_id=$1 FOR UPDATE"),
        &[&id.as_str()],
    )
    .await
    .map_err(pg)?
    .map(|r| session(&r, 0))
    .transpose()
}

impl PgStore {
    async fn try_create_txn(
        &self,
        t: &NewTransaction,
        events: &[Event],
        since: Timestamp,
        cap: Option<u32>,
        max_rows: u32,
    ) -> StoreResult<Admission> {
        let mut client = self.client().await?;
        let tx = self.begin(&mut client).await?;
        // One writer at a time per table bound: the advisory lock serializes
        // count + evict + insert across replicas, as SQLite's writer does.
        tx.execute("SELECT pg_advisory_xact_lock(7008)", &[])
            .await
            .map_err(pg)?;
        let n: i64 = tx
            .query_one(
                "SELECT COUNT(*) FROM txn_admissions WHERE ip=$1 AND at >= $2",
                &[&t.client_ip.to_string(), &since.secs()],
            )
            .await
            .map_err(pg)?
            .get(0);
        if cap.is_some_and(|cap| n >= i64::from(cap)) {
            return Ok(Admission::OverCap);
        }
        let total: i64 = tx
            .query_one("SELECT COUNT(*) FROM login_txns", &[])
            .await
            .map_err(pg)?
            .get(0);
        let excess = total - i64::from(max_rows.saturating_sub(1));
        let evicted = if excess > 0 {
            tx.execute(
                "DELETE FROM login_txns WHERE txn_sha256 IN (SELECT txn_sha256 FROM login_txns ORDER BY (consumed_at IS NULL AND expires_at > $1), created_at, seq LIMIT $2)",
                &[&t.created_at.secs(), &excess],
            )
            .await
            .map_err(pg)? as u32
        } else {
            0
        };
        tx.execute(
            "INSERT INTO txn_admissions (ip, at) VALUES ($1, $2)",
            &[&t.client_ip.to_string(), &t.created_at.secs()],
        )
        .await
        .map_err(pg)?;
        tx.execute(
            "DELETE FROM txn_admissions WHERE at < $1",
            &[&(t.created_at.secs() - 3600)],
        )
        .await
        .map_err(pg)?;
        tx.execute(
            "INSERT INTO login_txns (txn_sha256, created_at, expires_at, app_id, return_target, bind_sha256, portal_bind_sha256, retry_bind_sha256, client_ip, ua_sha256, provider_id, state_sha256, nonce, pkce_verifier, portal_session_id, purpose, conflicting_handle_sha256, pending_identity, recovery_depth, reauth_max_age) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)",
            &[
                &t.txn_sha256.0.to_vec(),
                &t.created_at.secs(),
                &t.expires_at.secs(),
                &t.app_id.as_str(),
                &t.return_target.as_str(),
                &bytes(&t.bind_sha256),
                &bytes(&t.portal_bind_sha256),
                &bytes(&t.retry_bind_sha256),
                &t.client_ip.to_string(),
                &bytes(&t.ua_sha256),
                &t.provider_id.as_ref().map(|p| p.as_str()),
                &bytes(&t.state_sha256),
                &t.nonce,
                &t.pkce_verifier.as_ref().map(|s| s.expose()),
                &t.portal_session_id.as_ref().map(|s| s.as_str()),
                &t.purpose.as_str(),
                &bytes(&t.conflicting_handle_sha256),
                &t.pending_identity.as_ref().map(|v| v.to_string()),
                &(t.recovery_depth.min(i32::MAX as u32) as i32),
                &t.reauth_max_age.map(|n| n.min(i32::MAX as u32) as i32),
            ],
        )
        .await
        .map_err(pg)?;
        self.insert_events(&tx, events).await?;
        tx.commit().await.map_err(pg)?;
        Ok(Admission::Admitted { evicted })
    }

    async fn try_redeem(
        &self,
        req: &RedeemRequest,
        ok_events: &[Event],
        fail_events: &[Event],
    ) -> StoreResult<RedeemOutcome> {
        let mut client = self.client().await?;
        let tx = self.begin(&mut client).await?;
        let now = req.now.secs();
        let presented = req
            .presented_handle
            .as_ref()
            .filter(|v| v.handle.revoked_at.is_none() && v.session.terminated_at.is_none());
        let browser_holds_handle = presented.is_some();
        let max_recoveries = req.max_recoveries;
        // Failure events carry the classified reason, the burned code's
        // session and depth, and exhaustion (ADR-0014), as in SQLite.
        let decorate = |outcome: &RedeemOutcome| -> Vec<Event> {
            let (why, sid, depth, exhausted) = match outcome {
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
            fail_events
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
                .collect()
        };
        macro_rules! fail {
            ($outcome:expr) => {{
                let outcome = $outcome;
                self.insert_events(&tx, &decorate(&outcome)).await?;
                tx.commit().await.map_err(pg)?;
                return Ok(outcome);
            }};
        }
        let Some(found) = code_locked(&tx, &req.code_sha256).await? else {
            fail!(RedeemOutcome::Rejected {
                reason: reasons::CODE_UNKNOWN,
                code: None,
            });
        };
        let session_row = session_locked(&tx, &found.session_id).await?;
        if found.consumed_at.is_some() {
            let same = presented.is_some_and(|v| {
                v.session.session_id == found.session_id && v.handle.host == req.host
            });
            if found.consumed_reason.as_deref() == Some(BURN_REDEEMED) && same {
                tx.commit().await.map_err(pg)?;
                return Ok(RedeemOutcome::AlreadyRedeemed);
            }
            fail!(RedeemOutcome::Rejected {
                reason: reasons::CODE_CONSUMED,
                code: Some(found),
            });
        }
        if let Some(s) = session_row.as_ref().filter(|s| s.terminated_at.is_none())
            && let LifetimeVerdict::SessionExpired(reason) = lifetimes::evaluate(
                &req.new_handle,
                s,
                &req.app_lifetimes,
                &req.session_policy,
                req.now,
            )
        {
            tx.execute(
                "UPDATE sessions SET terminated_at=$2, terminated_reason=$3, cred_gen = cred_gen + 1 WHERE session_id=$1 AND terminated_at IS NULL",
                &[&s.session_id.as_str(), &now, &reason.0],
            )
            .await
            .map_err(pg)?;
            tx.execute(
                "UPDATE session_handles SET revoked_at=$2, revoked_reason=$3 WHERE session_id=$1 AND revoked_at IS NULL",
                &[&s.session_id.as_str(), &now, &reasons::SESSION_TERMINATED.0],
            )
            .await
            .map_err(pg)?;
            tx.execute(
                "UPDATE handoff_codes SET consumed_at=$2, consumed_reason=$3 WHERE session_id=$1 AND consumed_at IS NULL",
                &[&s.session_id.as_str(), &now, &reason.0],
            )
            .await
            .map_err(pg)?;
            let expiry: Vec<Event> = req
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
            self.insert_events(&tx, &expiry).await?;
            let burned = code_locked(&tx, &req.code_sha256).await?;
            fail!(RedeemOutcome::Rejected {
                reason,
                code: burned,
            });
        }
        let other_user = match (&session_row, presented) {
            (Some(s), Some(v)) => v.session.user_id != s.user_id,
            _ => false,
        };
        let consume_as = if other_user {
            BURN_CONFLICT
        } else {
            BURN_REDEEMED
        };
        let changed = tx
            .execute(
                "UPDATE handoff_codes SET consumed_at=$1, consumed_reason=$2 WHERE code_sha256=$3 AND consumed_at IS NULL AND expires_at>$1 AND host=$4 AND return_path=$5 AND client_ip=$6 AND bind_sha256=$7 AND cred_gen=(SELECT cred_gen FROM sessions WHERE session_id=handoff_codes.session_id AND terminated_at IS NULL)",
                &[
                    &now,
                    &consume_as,
                    &req.code_sha256.0.to_vec(),
                    &req.host.as_str(),
                    &req.path,
                    &req.client_ip.to_string(),
                    &bytes(&req.presented_bind_sha256),
                ],
            )
            .await
            .map_err(pg)?;
        if changed == 1 {
            let burned = code_locked(&tx, &req.code_sha256)
                .await?
                .ok_or_else(|| StoreError::Corrupt("handoff code vanished".into()))?;
            if other_user {
                fail!(RedeemOutcome::SessionConflict { code: burned });
            }
            let s = session_row
                .ok_or_else(|| StoreError::Corrupt("handoff code without session".into()))?;
            if req.new_handle.host != req.host {
                return Err(StoreError::Conflict("new handle does not match the code"));
            }
            let issued_aal = found.issued_aal.min(s.aal);
            let mut h = req.new_handle.clone();
            h.session_id = found.session_id.clone();
            h.issued_aal = issued_aal;
            if let Some(old) = presented
                && old.session.session_id == found.session_id
                && old.handle.host == req.host
                && old.handle.handle_sha256 != h.handle_sha256
            {
                tx.execute(
                    "UPDATE session_handles SET revoked_at=$2, revoked_reason=$3 WHERE handle_sha256=$1 AND revoked_at IS NULL",
                    &[&old.handle.handle_sha256.0.to_vec(), &now, &reasons::REPLACED.0],
                )
                .await
                .map_err(pg)?;
            }
            tx.execute(
                "INSERT INTO session_handles (handle_sha256, session_id, host, issued_aal, created_at, last_seen_at, absolute_expires_at, revoked_at, revoked_reason) VALUES ($1,$2,$3,$4,$5,$6,$7,NULL,NULL)",
                &[
                    &h.handle_sha256.0.to_vec(),
                    &h.session_id.as_str(),
                    &h.host.as_str(),
                    &(h.issued_aal.as_i64() as i32),
                    &h.created_at.secs(),
                    &h.last_seen_at.secs(),
                    &h.absolute_expires_at.secs(),
                ],
            )
            .await
            .map_err(pg)?;
            tx.execute(
                "UPDATE sessions SET last_seen_at = GREATEST(last_seen_at, $2) WHERE session_id=$1",
                &[&found.session_id.as_str(), &now],
            )
            .await
            .map_err(pg)?;
            let events: Vec<Event> = ok_events
                .iter()
                .cloned()
                .map(|mut e| {
                    if e.session_id.is_none() {
                        e.session_id = Some(found.session_id.clone());
                        e.user_id = Some(s.user_id.clone());
                    }
                    e
                })
                .collect();
            self.insert_events(&tx, &events).await?;
            let session = session_locked(&tx, &found.session_id)
                .await?
                .ok_or_else(|| StoreError::Corrupt("session vanished".into()))?;
            tx.commit().await.map_err(pg)?;
            return Ok(RedeemOutcome::Minted {
                session,
                issued_aal,
            });
        }
        let reason = if found.expires_at.secs() <= now {
            reasons::CODE_EXPIRED
        } else if found.host != req.host {
            reasons::CODE_HOST_MISMATCH
        } else if found.return_target.path() != req.path {
            reasons::CODE_PATH_MISMATCH
        } else if found.client_ip != req.client_ip {
            reasons::CODE_IP_MISMATCH
        } else if req.presented_bind_sha256 != Some(found.bind_sha256) {
            reasons::BIND_MISMATCH
        } else {
            reasons::CODE_STALE_GENERATION
        };
        tx.execute(
            "UPDATE handoff_codes SET consumed_at=$2, consumed_reason=$3 WHERE code_sha256=$1 AND consumed_at IS NULL",
            &[&req.code_sha256.0.to_vec(), &now, &reason.0],
        )
        .await
        .map_err(pg)?;
        let burned = code_locked(&tx, &req.code_sha256).await?;
        fail!(RedeemOutcome::Rejected {
            reason,
            code: burned,
        })
    }
}

#[async_trait]
impl HandoffStore for PgStore {
    async fn create_transaction_capped(
        &self,
        txn: NewTransaction,
        events: Vec<Event>,
        since: Timestamp,
        cap: Option<u32>,
        max_rows: u32,
    ) -> StoreResult<Admission> {
        super::retry(|| self.try_create_txn(&txn, &events, since, cap, max_rows)).await
    }

    async fn transaction(&self, d: &Digest) -> StoreResult<Option<TransactionRow>> {
        let client = self.client().await?;
        client
            .query_opt(
                &format!("SELECT {TXN_COLS} FROM login_txns WHERE txn_sha256=$1"),
                &[&d.0.to_vec()],
            )
            .await
            .map_err(pg)?
            .map(|r| txn(&r))
            .transpose()
    }

    async fn transaction_by_state(&self, d: &Digest) -> StoreResult<Option<TransactionRow>> {
        let client = self.client().await?;
        client
            .query_opt(
                &format!("SELECT {TXN_COLS} FROM login_txns WHERE state_sha256=$1"),
                &[&d.0.to_vec()],
            )
            .await
            .map_err(pg)?
            .map(|r| txn(&r))
            .transpose()
    }

    async fn bind_transaction(&self, d: &Digest, b: TransactionBinding) -> StoreResult<()> {
        super::retry(|| async {
            let mut client = self.client().await?;
            let tx = self.begin(&mut client).await?;
            let now = self.now().secs();
            let state = tx
                .query_opt(
                    "SELECT consumed_at, expires_at, state_sha256 FROM login_txns WHERE txn_sha256=$1 FOR UPDATE",
                    &[&d.0.to_vec()],
                )
                .await
                .map_err(pg)?;
            match state {
                None => return Err(StoreError::Conflict("unknown transaction")),
                Some(r) if r.get::<_, Option<i64>>(0).is_some() => {
                    return Err(StoreError::Conflict("transaction consumed"));
                }
                Some(r) if r.get::<_, Option<Vec<u8>>>(2).is_some() => {
                    return Err(StoreError::Conflict("transaction already bound"));
                }
                Some(r) if r.get::<_, i64>(1) <= now => {
                    return Err(StoreError::Conflict("transaction expired"));
                }
                Some(_) => {}
            }
            tx.execute(
                "UPDATE login_txns SET provider_id=$2, state_sha256=$3, nonce=$4, pkce_verifier=$5, portal_bind_sha256=$6 WHERE txn_sha256=$1",
                &[
                    &d.0.to_vec(),
                    &b.provider_id.as_str(),
                    &b.state_sha256.0.to_vec(),
                    &b.nonce,
                    &b.pkce_verifier.as_ref().map(|v| v.expose()),
                    &b.portal_bind_sha256.0.to_vec(),
                ],
            )
            .await
            .map_err(pg)?;
            tx.commit().await.map_err(pg)
        })
        .await
    }

    async fn use_retry(&self, d: &Digest, at: Timestamp) -> StoreResult<bool> {
        let client = self.client().await?;
        let n = client
            .execute(
                "UPDATE login_txns SET retry_used_at=$2 WHERE txn_sha256=$1 AND retry_used_at IS NULL",
                &[&d.0.to_vec(), &at.secs()],
            )
            .await
            .map_err(pg)?;
        Ok(n == 1)
    }

    async fn consume_transaction(
        &self,
        d: &Digest,
        reason: Reason,
        at: Timestamp,
        events: Vec<Event>,
    ) -> StoreResult<bool> {
        super::retry(|| async {
            let mut client = self.client().await?;
            let tx = self.begin(&mut client).await?;
            let n = tx
                .execute(
                    "UPDATE login_txns SET consumed_at=$2, consumed_reason=$3 WHERE txn_sha256=$1 AND consumed_at IS NULL",
                    &[&d.0.to_vec(), &at.secs(), &reason.0],
                )
                .await
                .map_err(pg)?;
            if n == 0 {
                return Ok(false);
            }
            self.insert_events(&tx, &events).await?;
            tx.commit().await.map_err(pg)?;
            Ok(true)
        })
        .await
    }

    async fn mint_handoff_code(&self, c: HandoffCodeRow, events: Vec<Event>) -> StoreResult<()> {
        super::retry(|| async {
            let mut client = self.client().await?;
            let tx = self.begin(&mut client).await?;
            let s = session_locked(&tx, &c.session_id)
                .await?
                .filter(|s| s.terminated_at.is_none())
                .ok_or(StoreError::Conflict("session unavailable"))?;
            if s.cred_gen != c.cred_gen {
                return Err(StoreError::Conflict("stale credential generation"));
            }
            tx.execute(
                "INSERT INTO handoff_codes (code_sha256, session_id, host, return_target, return_path, client_ip, bind_sha256, issued_aal, cred_gen, recovery_depth, created_at, expires_at, consumed_at, consumed_reason) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,NULL,NULL)",
                &[
                    &c.code_sha256.0.to_vec(),
                    &c.session_id.as_str(),
                    &c.host.as_str(),
                    &c.return_target.as_str(),
                    &c.return_target.path(),
                    &c.client_ip.to_string(),
                    &c.bind_sha256.0.to_vec(),
                    &(c.issued_aal.as_i64() as i32),
                    &super::i64_of(c.cred_gen),
                    &(c.recovery_depth.min(i32::MAX as u32) as i32),
                    &c.created_at.secs(),
                    &c.expires_at.secs(),
                ],
            )
            .await
            .map_err(pg)?;
            self.insert_events(&tx, &events).await?;
            tx.commit().await.map_err(pg)
        })
        .await
    }

    async fn redeem_handoff_code(
        &self,
        req: RedeemRequest,
        ok: Vec<Event>,
        fail: Vec<Event>,
    ) -> StoreResult<RedeemOutcome> {
        super::retry(|| self.try_redeem(&req, &ok, &fail)).await
    }

    async fn count_transactions_since(&self, ip: IpAddr, since: Timestamp) -> StoreResult<u32> {
        let client = self.client().await?;
        let n: i64 = client
            .query_one(
                "SELECT COUNT(*) FROM txn_admissions WHERE ip=$1 AND at >= $2",
                &[&ip.to_string(), &since.secs()],
            )
            .await
            .map_err(pg)?
            .get(0);
        Ok(u32::try_from(n).unwrap_or(u32::MAX))
    }

    async fn count_handoff_failures_since(&self, ip: IpAddr, since: Timestamp) -> StoreResult<u32> {
        let client = self.client().await?;
        let n: i64 = client
            .query_one(
                "SELECT COUNT(*) FROM events WHERE kind='handoff.rejected' AND client_ip=$1 AND at >= $2 AND COALESCE(reason, '') != 'rate_limited'",
                &[&ip.to_string(), &(since.0 as f64 / 1000.0)],
            )
            .await
            .map_err(pg)?
            .get(0);
        Ok(u32::try_from(n).unwrap_or(u32::MAX))
    }
}
