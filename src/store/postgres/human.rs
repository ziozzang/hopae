//! Slice 5 for PostgreSQL (ADR-0020): the reads and the primary-provenance
//! write of the native Human owners (`store::sqlite::{human_owner,
//! primary_owner, totp_owner, webauthn_owner, material_owner}` hold the
//! comparisons, shared by both backends).
//!
//! SQLite serializes these owners behind its single writer. Here a read
//! snapshot is one `REPEATABLE READ` transaction, and inside a write
//! transaction every row a decision rests on is read `FOR SHARE`
//! ([`PgMetaTx::lock`]), so a concurrent change waits for the commit or is
//! seen before the decision, never in between.
use deadpool_postgres::Transaction;

use super::meta::PgMetaTx;
use super::{HANDLE_COLS, SESSION_COLS, handle, pg, session, user_authz};
use crate::crypto::Digest;
use crate::store::{HandleView, StoreResult};

/// `meta.config_generation`, locked inside a write.
pub(crate) fn config_generation(tx: &PgMetaTx<'_>) -> StoreResult<Option<String>> {
    Ok(tx
        .query_opt(
            &format!(
                "SELECT value FROM meta WHERE key = 'config_generation'{}",
                tx.lock()
            ),
            &[],
        )?
        .map(|r| r.get(0)))
}

/// The handle, its session and user, the provider owner revision and the
/// realm of a native Human snapshot (as SQLite's `SnapshotCheck` query).
pub(crate) fn snapshot_row(
    tx: &PgMetaTx<'_>,
    handle_sha256: &Digest,
    host: &str,
) -> StoreResult<Option<(HandleView, i64, String)>> {
    let sql = format!(
        "SELECT {HANDLE_COLS}, {SESSION_COLS}, u.status, u.authz_version, u.groups, o.revision, a.realm \
         FROM session_handles h JOIN sessions s ON s.session_id = h.session_id \
         JOIN users u ON u.user_id = s.user_id \
         JOIN providers p ON p.provider_id = s.provider_id AND p.enabled AND p.deleted_at IS NULL \
         JOIN human_provider_owners o ON o.provider_id = p.provider_id \
         JOIN human_user_ids i ON i.user_id = u.user_id \
         JOIN human_authority_realm a ON a.singleton = 1 \
         WHERE h.handle_sha256 = $1 AND h.host = $2 AND length(s.factors) <= 65536 \
         AND length(s.snapshot) <= 65536 AND length(u.groups) <= 65536{}",
        tx.lock()
    );
    tx.query_opt(&sql, &[&handle_sha256.0.to_vec(), &host])?
        .map(|r| {
            Ok((
                HandleView {
                    handle: handle(&r, 0)?,
                    session: session(&r, 9)?,
                    user: user_authz(&r, 28)?,
                },
                r.get::<_, i64>(31),
                r.get::<_, String>(32),
            ))
        })
        .transpose()
}

/// The primary provenance row of a session, joined to its live identity link.
pub(crate) type PrimaryRow = (
    String,
    String,
    i64,
    i64,
    i64,
    String,
    i64,
    String,
    i64,
    String,
    i64,
    i64,
);

pub(crate) fn primary_row(tx: &PgMetaTx<'_>, session_id: &str) -> StoreResult<Option<PrimaryRow>> {
    let sql = format!(
        "SELECT p.user_id, p.provider_id, p.provider_revision, p.config_generation, p.credential_generation, \
         p.subject, p.auth_time_ms, p.auth_time_source, p.factor_index, p.factor_kind, p.factor_at_ms, p.material_revision \
         FROM session_primary_provenance p JOIN identities i ON i.provider_id = p.provider_id \
         AND i.subject = p.subject AND i.user_id = p.user_id WHERE p.session_id = $1{}",
        tx.lock()
    );
    Ok(tx.query_opt(&sql, &[&session_id])?.map(|r| {
        (
            r.get(0),
            r.get(1),
            r.get(2),
            r.get(3),
            r.get(4),
            r.get(5),
            r.get(6),
            r.get(7),
            r.get(8),
            r.get(9),
            r.get(10),
            r.get(11),
        )
    }))
}

/// The published compiled-material row of a provider.
pub(crate) fn material_row(
    tx: &PgMetaTx<'_>,
    provider_id: &str,
) -> StoreResult<Option<(i64, Vec<u8>)>> {
    let sql = format!(
        "SELECT revision, fingerprint FROM human_provider_material_owners \
         WHERE provider_id = $1 AND fingerprint IS NOT NULL{}",
        tx.lock()
    );
    Ok(tx
        .query_opt(&sql, &[&provider_id])?
        .map(|r| (r.get(0), r.get(1))))
}

/// The establishing TOTP of a session: the provenance facts (user,
/// credential generation, enrollment, its revision, index, time,
/// configuration generation), the session's factor list (bounded) and the
/// configuration generation in force.
pub(crate) type TotpRow = (
    (String, i64, String, i64, i64, i64, i64),
    Option<String>,
    Option<String>,
);

pub(crate) fn totp_row(tx: &PgMetaTx<'_>, session_id: &str) -> StoreResult<Option<TotpRow>> {
    let sql = format!(
        "SELECT p.user_id, p.credential_generation, p.enrollment_id, p.enrollment_revision, p.factor_index, \
         p.verified_at_ms, p.config_generation, CASE WHEN length(s.factors) <= 65536 THEN s.factors ELSE NULL END, \
         (SELECT value FROM meta WHERE key = 'config_generation') \
         FROM session_totp_provenance p \
         JOIN sessions s ON s.session_id = p.session_id AND s.user_id = p.user_id AND s.cred_gen = p.credential_generation \
         JOIN users u ON u.user_id = s.user_id \
         JOIN totp_enrollments e ON e.enrollment_id = p.enrollment_id AND e.user_id = p.user_id AND e.revision = p.enrollment_revision \
         WHERE p.session_id = $1 AND s.terminated_at IS NULL AND s.aal = 2 AND u.status = 'active' \
         AND e.state = 'active' AND e.last_counter IS NOT NULL AND p.config_generation IS NOT NULL{}",
        tx.lock()
    );
    Ok(tx.query_opt(&sql, &[&session_id])?.map(|r| {
        (
            (
                r.get(0),
                r.get(1),
                r.get(2),
                r.get(3),
                r.get(4),
                r.get(5),
                r.get(6),
            ),
            r.get(7),
            r.get(8),
        )
    }))
}

/// The establishing passkey of a session: the provenance facts (user,
/// credential generation, credential, assurance, index, time, configuration
/// generation), the factor list and the configuration generation in force.
pub(crate) type WebauthnRow = (
    (String, i64, Vec<u8>, String, i64, i64, i64),
    Option<String>,
    Option<String>,
);

pub(crate) fn webauthn_row(
    tx: &PgMetaTx<'_>,
    session_id: &str,
) -> StoreResult<Option<WebauthnRow>> {
    let sql = format!(
        "SELECT p.user_id, p.credential_generation, p.credential_id, p.assurance, p.factor_index, p.verified_at_ms, \
         p.config_generation, CASE WHEN length(s.factors) <= 65536 THEN s.factors ELSE NULL END, \
         (SELECT value FROM meta WHERE key = 'config_generation') \
         FROM session_webauthn_provenance p \
         JOIN sessions s ON s.session_id = p.session_id AND s.user_id = p.user_id AND s.cred_gen = p.credential_generation \
         JOIN users u ON u.user_id = s.user_id \
         JOIN webauthn_credentials w ON w.credential_id = p.credential_id AND w.user_id = p.user_id \
         WHERE p.session_id = $1 AND s.terminated_at IS NULL AND s.aal = 2 AND u.status = 'active' \
         AND w.state = 'active' AND p.config_generation IS NOT NULL{}",
        tx.lock()
    );
    Ok(tx.query_opt(&sql, &[&session_id])?.map(|r| {
        (
            (
                r.get(0),
                r.get(1),
                r.get(2),
                r.get(3),
                r.get(4),
                r.get(5),
                r.get(6),
            ),
            r.get(7),
            r.get(8),
        )
    }))
}

/// What a primary-provenance write rests on, read `FOR SHARE` in the
/// session's own transaction: the configuration generation, the provider's
/// owner revision (live provider only), its published material and whether
/// the identity link exists.
pub(crate) struct PrimaryFence {
    pub config: Option<String>,
    pub revision: Option<i64>,
    pub material: Option<(i64, Vec<u8>)>,
    pub linked: bool,
}

pub(crate) async fn primary_fence(
    tx: &Transaction<'_>,
    provider_id: &str,
    subject: &str,
    user_id: &str,
) -> StoreResult<PrimaryFence> {
    let config = tx
        .query_opt(
            "SELECT value FROM meta WHERE key = 'config_generation' FOR SHARE",
            &[],
        )
        .await
        .map_err(pg)?
        .map(|r| r.get(0));
    let revision = tx
        .query_opt(
            "SELECT o.revision FROM human_provider_owners o JOIN providers p ON p.provider_id = o.provider_id \
             WHERE p.provider_id = $1 AND p.enabled AND p.deleted_at IS NULL FOR SHARE",
            &[&provider_id],
        )
        .await
        .map_err(pg)?
        .map(|r| r.get(0));
    let material = tx
        .query_opt(
            "SELECT revision, fingerprint FROM human_provider_material_owners \
             WHERE provider_id = $1 AND fingerprint IS NOT NULL FOR SHARE",
            &[&provider_id],
        )
        .await
        .map_err(pg)?
        .map(|r| (r.get(0), r.get(1)));
    let linked = tx
        .query_opt(
            "SELECT 1 FROM identities WHERE provider_id = $1 AND subject = $2 AND user_id = $3 FOR SHARE",
            &[&provider_id, &subject, &user_id],
        )
        .await
        .map_err(pg)?
        .is_some();
    Ok(PrimaryFence {
        config,
        revision,
        material,
        linked,
    })
}

/// The primary provenance values to record (as SQLite's statement).
pub(crate) struct PrimaryInsert<'a> {
    pub session_id: &'a str,
    pub user_id: &'a str,
    pub provider_id: &'a str,
    pub material_revision: i64,
    pub provider_revision: i64,
    pub config_generation: i64,
    pub credential_generation: i64,
    pub subject: &'a str,
    pub auth_time_ms: i64,
    pub auth_time_source: &'a str,
    pub factor_index: i64,
    pub factor_kind: &'a str,
    pub factor_at_ms: i64,
}

/// Record (or replace with a strictly newer credential generation of the
/// same user and provider) a session's primary provenance; the row count.
pub(crate) async fn insert_primary(
    tx: &Transaction<'_>,
    v: &PrimaryInsert<'_>,
) -> StoreResult<u64> {
    tx.execute(
        "INSERT INTO session_primary_provenance (session_id, user_id, provider_id, material_revision, provider_revision, \
         config_generation, credential_generation, subject, auth_time_ms, auth_time_source, factor_index, factor_kind, factor_at_ms) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) ON CONFLICT (session_id) DO UPDATE SET \
         material_revision = excluded.material_revision, provider_revision = excluded.provider_revision, \
         config_generation = excluded.config_generation, credential_generation = excluded.credential_generation, \
         subject = excluded.subject, auth_time_ms = excluded.auth_time_ms, auth_time_source = excluded.auth_time_source, \
         factor_index = excluded.factor_index, factor_kind = excluded.factor_kind, factor_at_ms = excluded.factor_at_ms \
         WHERE excluded.user_id = session_primary_provenance.user_id AND excluded.provider_id = session_primary_provenance.provider_id \
         AND excluded.credential_generation > session_primary_provenance.credential_generation",
        &[
            &v.session_id,
            &v.user_id,
            &v.provider_id,
            &v.material_revision,
            &v.provider_revision,
            &v.config_generation,
            &v.credential_generation,
            &v.subject,
            &v.auth_time_ms,
            &v.auth_time_source,
            &v.factor_index,
            &v.factor_kind,
            &v.factor_at_ms,
        ],
    )
    .await
    .map_err(pg)
}
