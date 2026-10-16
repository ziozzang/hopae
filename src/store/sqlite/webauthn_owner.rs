//! Exact native establishing-WebAuthn metadata (ADR-0017 phase 2), the
//! counterpart of [`super::totp_owner`]: not an authentication capability.
//!
//! A row exists only for a successful native passkey elevation (application
//! step-up or portal confirmation) and names the credential, the new
//! credential generation, the factor index and time, and the configuration
//! generation. The native Human owner accepts an AAL 2 handle only while the
//! row is current: same session generation, same factor entry, the credential
//! still active for the same user, and the configuration generation unchanged.
use crate::{
    session::types::{FactorEntry, FactorKind},
    store::{StoreError, StoreResult},
};
use rusqlite::OptionalExtension;

#[derive(Clone, PartialEq, Eq)]
pub(super) struct Facts {
    user: String,
    generation: i64,
    credential: Vec<u8>,
    pub(super) assurance: String,
    index: i64,
    pub(super) at_ms: i64,
    config: i64,
}

fn refused() -> StoreError {
    StoreError::Conflict("WebAuthn establishing owner unavailable")
}

pub(super) fn current(c: &rusqlite::Connection, session: &str) -> StoreResult<Facts> {
    let found = c
        .query_row(
            "SELECT p.user_id,p.credential_generation,p.credential_id,p.assurance,p.factor_index,p.verified_at_ms,p.config_generation,\
             CASE WHEN length(s.factors)<=65536 THEN s.factors ELSE NULL END,(SELECT value FROM meta WHERE key='config_generation') \
             FROM session_webauthn_provenance p JOIN sessions s ON s.session_id=p.session_id AND s.user_id=p.user_id AND s.cred_gen=p.credential_generation \
             JOIN users u ON u.user_id=s.user_id JOIN webauthn_credentials w ON w.credential_id=p.credential_id AND w.user_id=p.user_id \
             WHERE p.session_id=?1 AND s.terminated_at IS NULL AND s.aal=2 AND u.status='active' AND w.state='active' AND p.config_generation IS NOT NULL",
            [session],
            |r| {
                Ok((
                    Facts {
                        user: r.get(0)?,
                        generation: r.get(1)?,
                        credential: r.get(2)?,
                        assurance: r.get(3)?,
                        index: r.get(4)?,
                        at_ms: r.get(5)?,
                        config: r.get(6)?,
                    },
                    r.get::<_, Option<String>>(7)?,
                    r.get::<_, Option<String>>(8)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(refused)?;
    let (facts, factors, config) = found;
    let config = config
        .and_then(|s| s.parse::<i64>().ok())
        .filter(|n| *n > 0);
    if config != Some(facts.config) {
        return Err(refused());
    }
    let factors: Vec<FactorEntry> =
        serde_json::from_str(&factors.ok_or_else(refused)?).map_err(|_| refused())?;
    let entry = usize::try_from(facts.index)
        .ok()
        .and_then(|i| factors.get(i))
        .ok_or_else(refused)?;
    if entry.kind != FactorKind::Webauthn || entry.provider.is_some() || entry.at.0 != facts.at_ms {
        return Err(refused());
    }
    Ok(facts)
}

/// Record the establishing passkey of a native elevation in its transaction.
/// Replacement needs a strictly newer credential generation for the same user.
#[allow(clippy::too_many_arguments)]
pub(super) fn record(
    tx: &rusqlite::Transaction<'_>,
    session: &str,
    user: &str,
    generation: i64,
    credential: &[u8],
    assurance: &str,
    factor_index: i64,
    at_ms: i64,
    config_generation: Option<i64>,
) -> StoreResult<()> {
    let n = tx.execute(
        "INSERT INTO session_webauthn_provenance(session_id,user_id,credential_generation,credential_id,assurance,factor_index,verified_at_ms,config_generation) \
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8) ON CONFLICT(session_id) DO UPDATE SET user_id=excluded.user_id,credential_generation=excluded.credential_generation,\
         credential_id=excluded.credential_id,assurance=excluded.assurance,factor_index=excluded.factor_index,verified_at_ms=excluded.verified_at_ms,\
         config_generation=excluded.config_generation WHERE excluded.user_id=session_webauthn_provenance.user_id AND excluded.credential_generation>session_webauthn_provenance.credential_generation",
        rusqlite::params![session, user, generation, credential, assurance, factor_index, at_ms, config_generation],
    )?;
    if n != 1 {
        return Err(StoreError::Conflict(
            "WebAuthn provenance generation unavailable",
        ));
    }
    Ok(())
}

/// The configuration generation in force, for a portal elevation (no application rule).
pub(super) fn config_generation(tx: &rusqlite::Connection) -> StoreResult<Option<i64>> {
    let v: Option<String> = tx
        .query_row(
            "SELECT value FROM meta WHERE key='config_generation'",
            [],
            |r| r.get(0),
        )
        .optional()?;
    Ok(v.and_then(|s| s.parse::<i64>().ok()).filter(|n| *n > 0))
}

pub(super) fn validate_foundation(c: &rusqlite::Connection) -> StoreResult<()> {
    let migration = include_str!("../migrations/0012_session_webauthn_provenance.sql");
    let expected = &migration[migration.find("CREATE TABLE").expect("embedded provenance")..];
    let normalize = |s: &str| -> String {
        s.to_ascii_lowercase()
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>()
            .trim_end_matches(';')
            .to_owned()
    };
    let actual: Option<String> = c
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='session_webauthn_provenance'",
            [],
            |r| r.get(0),
        )
        .optional()?;
    if actual.as_deref().map(normalize) != Some(normalize(expected)) {
        return Err(StoreError::Corrupt(
            "schema v12 invalid WebAuthn provenance structure".into(),
        ));
    }
    Ok(())
}

impl Facts {
    #[allow(dead_code)] // Used by the additive native Human retained-record quota.
    pub(super) fn owned_heap_bytes(&self) -> StoreResult<usize> {
        crate::store::types::heap_sum([
            self.user.capacity(),
            self.credential.capacity(),
            self.assurance.capacity(),
        ])
    }
}
