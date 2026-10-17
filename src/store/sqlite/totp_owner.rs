//! Exact native establishing-factor metadata, not a Human authentication capability.
use super::{Inner, Store};
use crate::{
    session::types::{FactorEntry, FactorKind, SessionId},
    store::{Deadline, StoreError, StoreResult},
};
use rusqlite::OptionalExtension;
use std::sync::{Arc, Weak};

#[derive(Clone, PartialEq, Eq)]
pub(super) struct Facts {
    user: String,
    generation: i64,
    enrollment: String,
    revision: i64,
    index: i64,
    pub(super) at_ms: i64,
    config: i64,
}
/// No public constructor, serialization or Debug; no raw factor material.
pub(crate) struct TotpOwner {
    store: Weak<Inner>,
    session: String,
    facts: Facts,
}
/// The provenance facts, the session's factor list and the configuration
/// generation in force, as one row reads them.
type Found = (Facts, Option<String>, Option<String>);

fn refused() -> StoreError {
    StoreError::Conflict("TOTP establishing owner unavailable")
}

pub(super) fn current(tx: &dyn crate::store::meta::MetaTx, session: &str) -> StoreResult<Facts> {
    let found: Option<Found> = if let Some(c) = tx.sqlite() {
        c.query_row(
        "SELECT p.user_id,p.credential_generation,p.enrollment_id,p.enrollment_revision,p.factor_index,p.verified_at_ms,p.config_generation,CASE WHEN length(s.factors)<=65536 THEN s.factors ELSE NULL END,(SELECT value FROM meta WHERE key='config_generation') FROM session_totp_provenance p JOIN sessions s ON s.session_id=p.session_id AND s.user_id=p.user_id AND s.cred_gen=p.credential_generation JOIN users u ON u.user_id=s.user_id JOIN totp_enrollments e ON e.enrollment_id=p.enrollment_id AND e.user_id=p.user_id AND e.revision=p.enrollment_revision WHERE p.session_id=?1 AND s.terminated_at IS NULL AND s.aal=2 AND u.status='active' AND e.state='active' AND e.last_counter IS NOT NULL AND p.config_generation IS NOT NULL",
        [session], |r| Ok((Facts{user:r.get(0)?,generation:r.get(1)?,enrollment:r.get(2)?,revision:r.get(3)?,index:r.get(4)?,at_ms:r.get(5)?,config:r.get(6)?},r.get::<_,Option<String>>(7)?,r.get::<_,Option<String>>(8)?))
        ).optional()?
    } else {
        postgres_current(tx, session)?
    };
    let found = found.ok_or_else(refused)?;
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
    if entry.kind != FactorKind::Totp || entry.provider.is_some() || entry.at.0 != facts.at_ms {
        return Err(refused());
    }
    Ok(facts)
}

#[cfg(feature = "postgres")]
fn postgres_current(
    tx: &dyn crate::store::meta::MetaTx,
    session: &str,
) -> StoreResult<Option<Found>> {
    let tx = tx.postgres().ok_or_else(refused)?;
    Ok(crate::store::postgres::human::totp_row(tx, session)?.map(
        |((user, generation, enrollment, revision, index, at_ms, config), factors, current)| {
            (
                Facts {
                    user,
                    generation,
                    enrollment,
                    revision,
                    index,
                    at_ms,
                    config,
                },
                factors,
                current,
            )
        },
    ))
}

#[cfg(not(feature = "postgres"))]
fn postgres_current(
    _tx: &dyn crate::store::meta::MetaTx,
    _session: &str,
) -> StoreResult<Option<Found>> {
    Err(refused())
}

pub(super) fn validate_foundation(c: &rusqlite::Connection) -> StoreResult<()> {
    let migration = include_str!("../migrations/0008_session_totp_provenance.sql");
    let expected = &migration[migration
        .find("CREATE TABLE")
        .expect("embedded TOTP provenance")..];
    let normalize = |s: &str| {
        s.to_ascii_lowercase()
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>()
            .trim_end_matches(';')
            .to_owned()
    };
    let actual: Option<String> = c
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='session_totp_provenance'",
            [],
            |r| r.get(0),
        )
        .optional()?;
    if actual.as_deref().map(normalize) != Some(normalize(expected)) {
        return Err(StoreError::Corrupt(
            "schema v8 invalid TOTP provenance structure".into(),
        ));
    }
    Ok(())
}
impl Store {
    pub(crate) async fn capture_totp_owner(
        &self,
        session: &SessionId,
        deadline: Deadline,
    ) -> StoreResult<TotpOwner> {
        let session = session.to_string();
        let lookup = session.clone();
        let facts = self
            .read_checked("capture_totp_owner", Some(deadline), move |c, check| {
                check.now()?;
                let facts = current(c, &lookup)?;
                check.now()?;
                Ok(facts)
            })
            .await?;
        Ok(TotpOwner {
            store: Arc::downgrade(&self.inner),
            session,
            facts,
        })
    }
    pub(crate) async fn require_totp_owner(
        &self,
        owner: &TotpOwner,
        deadline: Deadline,
    ) -> StoreResult<()> {
        if !Weak::ptr_eq(&owner.store, &Arc::downgrade(&self.inner)) {
            return Err(refused());
        }
        let session = owner.session.clone();
        let facts = self
            .read_checked("require_totp_owner", Some(deadline), move |c, check| {
                check.now()?;
                let facts = current(c, &session)?;
                check.now()?;
                Ok(facts)
            })
            .await?;
        if facts != owner.facts {
            return Err(refused());
        }
        Ok(())
    }
}

impl Facts {
    #[allow(dead_code)] // Used by the additive native Human retained-record quota.
    pub(super) fn owned_heap_bytes(&self) -> StoreResult<usize> {
        crate::store::types::heap_sum([self.user.capacity(), self.enrollment.capacity()])
    }
}

#[cfg(test)]
mod retained_heap_tests {
    use super::*;
    #[test]
    fn retained_heap_totp_counts_both_capacities() {
        let mut user = String::with_capacity(128);
        user.push('u');
        let mut enrollment = String::with_capacity(256);
        enrollment.push('e');
        let expected = user.capacity() + enrollment.capacity();
        let facts = Facts {
            user,
            generation: 1,
            enrollment,
            revision: 1,
            index: 0,
            at_ms: 0,
            config: 1,
        };
        assert_eq!(facts.owned_heap_bytes().unwrap(), expected);
    }
}
