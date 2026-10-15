//! Durable provider incarnation infrastructure, not Human authentication evidence.
//! Only future native verify integration can bind this to an authenticated session.
use super::{Inner, Store};
use crate::{
    provider::types::ProviderId,
    store::{Deadline, StoreError, StoreResult},
};
use rusqlite::OptionalExtension;
use std::sync::{Arc, Weak};

/// Private fields prevent numeric construction; bind even identical DB contents
/// to this opened Store instance. No cookie, provider config or secret is retained.
pub(crate) struct ProviderOwner {
    store: Weak<Inner>,
    provider_id: String,
    revision: i64,
}

fn current(connection: &rusqlite::Connection, provider: &str) -> StoreResult<i64> {
    let revision: Option<i64> = connection.query_row(
        "SELECT o.revision FROM human_provider_owners o JOIN providers p ON p.provider_id=o.provider_id WHERE p.provider_id=?1 AND p.enabled=1 AND p.deleted_at IS NULL",
        [provider], |row| row.get(0),
    ).optional()?;
    revision
        .filter(|revision| *revision > 0)
        .ok_or(StoreError::Conflict("provider owner unavailable"))
}

/// Refuse missing/modified guards before migration backup or listener startup.
/// Validation is read-only; a damaged v7 DB must never silently recreate epochs.
pub(super) fn validate_foundation(connection: &rusqlite::Connection) -> StoreResult<()> {
    let sql = include_str!("../migrations/0007_human_provider_owners.sql");
    let normalize = |value: &str| {
        value
            .to_ascii_lowercase()
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>()
            .trim_end_matches(';')
            .to_owned()
    };
    for (kind, name) in [
        ("table", "human_provider_owners"),
        ("trigger", "human_provider_owner_identity"),
        ("trigger", "human_provider_owner_insert"),
        ("trigger", "human_provider_owner_delete"),
        ("trigger", "human_provider_owner_material"),
    ] {
        let start = sql
            .find(&format!("CREATE {} {name}", kind.to_ascii_uppercase()))
            .expect("embedded provider owner schema");
        let rest = &sql[start..];
        let end = if kind == "trigger" {
            rest.find("\nEND;").expect("embedded provider trigger") + 5
        } else {
            rest.find(';').expect("embedded provider table") + 1
        };
        let actual: Option<String> = connection
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type=?1 AND name=?2",
                [kind, name],
                |row| row.get(0),
            )
            .optional()?;
        if actual.as_deref().map(normalize) != Some(normalize(&rest[..end])) {
            return Err(StoreError::Corrupt(
                "schema v7 invalid provider owner structure".into(),
            ));
        }
    }
    let missing: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM providers p LEFT JOIN human_provider_owners o ON o.provider_id=p.provider_id WHERE o.provider_id IS NULL)", [], |row| row.get(0))?;
    if missing {
        return Err(StoreError::Corrupt(
            "schema v7 missing provider owner".into(),
        ));
    }
    Ok(())
}

impl Store {
    pub(crate) async fn capture_provider_owner(
        &self,
        provider: &ProviderId,
        deadline: Deadline,
    ) -> StoreResult<ProviderOwner> {
        let provider_id = provider.to_string();
        let lookup = provider_id.clone();
        let revision = self
            .read_checked(
                "capture_provider_owner",
                Some(deadline),
                move |connection, check| {
                    check.now()?;
                    let revision = current(connection, &lookup)?;
                    check.now()?;
                    Ok(revision)
                },
            )
            .await?;
        Ok(ProviderOwner {
            store: Arc::downgrade(&self.inner),
            provider_id,
            revision,
        })
    }

    pub(crate) async fn require_provider_owner(
        &self,
        owner: &ProviderOwner,
        deadline: Deadline,
    ) -> StoreResult<()> {
        if !Weak::ptr_eq(&owner.store, &Arc::downgrade(&self.inner)) {
            return Err(StoreError::Conflict("provider store owner changed"));
        }
        let provider = owner.provider_id.clone();
        let revision = owner.revision;
        self.read_checked(
            "require_provider_owner",
            Some(deadline),
            move |connection, check| {
                check.now()?;
                if current(connection, &provider)? != revision {
                    return Err(StoreError::Conflict("provider owner changed"));
                }
                check.now()
            },
        )
        .await
    }
}

#[cfg(test)]
#[path = "provider_owner_tests.rs"]
mod tests;
