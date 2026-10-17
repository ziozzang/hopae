//! Row writers and checks shared by the PostgreSQL slices: the same
//! statements SQLite's `sessions` helpers run, inside the caller's
//! transaction.
use deadpool_postgres::Transaction;

use super::{i64_of, pg, snapshot_json};
use crate::crypto::Timestamp;
use crate::session::types::SessionId;
use crate::store::types::*;
use crate::store::{StoreError, StoreResult};

pub(super) async fn insert_session(tx: &Transaction<'_>, s: &SessionRow) -> StoreResult<()> {
    tx.execute(
        "INSERT INTO sessions (session_id, user_id, provider_id, auth_time, factors, aal, authz_version, cred_gen, snapshot, bound_ip, bound_ua_sha256, created_at, last_seen_at, absolute_expires_at, terminated_at, terminated_reason, authz_version_at_auth, auth_time_source, bound_ua_prefix) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,NULL,NULL,$15,$16,$17)",
        &[
            &s.session_id.as_str(),
            &s.user_id.as_str(),
            &s.provider_id.as_str(),
            &s.auth_time.secs(),
            &factors_json(&s.factors)?,
            &(s.aal.as_i64() as i32),
            &i64_of(s.authz_version),
            &i64_of(s.cred_gen),
            &snapshot_json(&s.snapshot),
            &s.bound_ip.to_string(),
            &s.bound_ua_sha256.as_ref().map(|d| d.0.to_vec()),
            &s.created_at.secs(),
            &s.last_seen_at.secs(),
            &s.absolute_expires_at.secs(),
            &i64_of(s.authz_version_at_auth),
            &s.auth_time_source.as_str(),
            &s.bound_ua_prefix,
        ],
    )
    .await
    .map_err(pg)?;
    Ok(())
}

pub(super) async fn insert_handle(tx: &Transaction<'_>, h: &HandleRow) -> StoreResult<()> {
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
    Ok(())
}

pub(super) async fn insert_code(tx: &Transaction<'_>, c: &HandoffCodeRow) -> StoreResult<()> {
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
            &i64_of(c.cred_gen),
            &(c.recovery_depth.min(i32::MAX as u32) as i32),
            &c.created_at.secs(),
            &c.expires_at.secs(),
        ],
    )
    .await
    .map_err(pg)?;
    Ok(())
}

pub(super) async fn revoke_session_handles(
    tx: &Transaction<'_>,
    id: &SessionId,
    reason: &str,
    at: Timestamp,
) -> StoreResult<()> {
    tx.execute(
        "UPDATE session_handles SET revoked_at=$2, revoked_reason=$3 WHERE session_id=$1 AND revoked_at IS NULL",
        &[&id.as_str(), &at.secs(), &reason],
    )
    .await
    .map_err(pg)?;
    Ok(())
}

pub(super) async fn consume_session_codes(
    tx: &Transaction<'_>,
    id: &SessionId,
    reason: &str,
    at: Timestamp,
) -> StoreResult<()> {
    tx.execute(
        "UPDATE handoff_codes SET consumed_at=$2, consumed_reason=$3 WHERE session_id=$1 AND consumed_at IS NULL",
        &[&id.as_str(), &at.secs(), &reason],
    )
    .await
    .map_err(pg)?;
    Ok(())
}

pub(super) fn factors_json(f: &[crate::session::types::FactorEntry]) -> StoreResult<String> {
    serde_json::to_string(f).map_err(|_| StoreError::Corrupt("unserializable value".into()))
}

/// The provider is enabled, not deleted, and configured exactly as the
/// caller saw it; held `FOR SHARE` against a concurrent change.
pub(super) async fn require_provider_configuration(
    tx: &Transaction<'_>,
    id: &str,
    expected: Option<&(crate::provider::types::ProviderKind, serde_json::Value)>,
) -> StoreResult<()> {
    let Some((kind, config)) = expected else {
        return Ok(());
    };
    let row = tx
        .query_opt(
            "SELECT kind, config FROM providers WHERE provider_id=$1 AND enabled AND deleted_at IS NULL FOR SHARE",
            &[&id],
        )
        .await
        .map_err(pg)?;
    let matches = row.is_some_and(|r| {
        r.get::<_, String>(0) == kind.as_str()
            && serde_json::from_str::<serde_json::Value>(&r.get::<_, String>(1))
                .is_ok_and(|c| c == *config)
    });
    if !matches {
        return Err(StoreError::ProviderDisabled);
    }
    Ok(())
}

/// A `meta` value; `lock` holds the row against a concurrent writer.
pub(super) async fn meta(
    tx: &Transaction<'_>,
    key: &str,
    lock: bool,
) -> StoreResult<Option<String>> {
    let sql = if lock {
        "SELECT value FROM meta WHERE key=$1 FOR UPDATE"
    } else {
        "SELECT value FROM meta WHERE key=$1"
    };
    Ok(tx
        .query_opt(sql, &[&key])
        .await
        .map_err(pg)?
        .map(|r| r.get(0)))
}

pub(super) async fn set_meta(tx: &Transaction<'_>, key: &str, value: &str) -> StoreResult<()> {
    tx.execute(
        "INSERT INTO meta (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = excluded.value",
        &[&key, &value],
    )
    .await
    .map_err(pg)?;
    Ok(())
}

/// The configuration generation in force (absent or invalid is `None`).
pub(super) async fn config_generation(tx: &Transaction<'_>) -> StoreResult<Option<i64>> {
    // `FOR SHARE`: a configuration bump waits for a write that relied on it.
    let v = tx
        .query_opt(
            "SELECT value FROM meta WHERE key='config_generation' FOR SHARE",
            &[],
        )
        .await
        .map_err(pg)?
        .map(|r| r.get::<_, String>(0));
    Ok(v.and_then(|s| s.parse::<i64>().ok()).filter(|n| *n > 0))
}

/// A step-up bound to configuration generation `expected` requires it still in force.
pub(super) async fn require_stepup_generation(
    tx: &Transaction<'_>,
    expected: Option<u64>,
) -> StoreResult<()> {
    if let Some(expected) = expected {
        if expected == 0 {
            return Err(StoreError::Conflict("step-up configuration unavailable"));
        }
        let current = tx
            .query_opt(
                "SELECT value FROM meta WHERE key='config_generation' FOR SHARE",
                &[],
            )
            .await
            .map_err(pg)?
            .map(|r| r.get::<_, String>(0));
        if current.and_then(|s| s.parse::<u64>().ok()) != Some(expected) {
            return Err(StoreError::Conflict("step-up configuration changed"));
        }
    }
    Ok(())
}
