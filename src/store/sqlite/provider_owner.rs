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

/// Exact actual DB rows and incarnations read under one storage snapshot.
/// Only the Store constructs this; public Registry::from_snapshot is unqualified.
pub(crate) struct PreparedProviders {
    store: Weak<Inner>,
    rows: Vec<crate::store::ProviderRow>,
    owners: std::collections::BTreeMap<String, i64>,
    generation: u64,
}
impl PreparedProviders {
    pub(crate) fn rows(&self) -> &[crate::store::ProviderRow] {
        &self.rows
    }
    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }
}
fn prepared_rows(
    c: &rusqlite::Connection,
    check: &super::Check,
    expected: u64,
) -> StoreResult<(
    Vec<crate::store::ProviderRow>,
    std::collections::BTreeMap<String, i64>,
)> {
    use super::rows::{self, PROVIDER_COLS, cols};
    let transaction = c.unchecked_transaction()?;
    check.now()?;
    let generation: Option<String> = transaction
        .query_row(
            "SELECT value FROM meta WHERE key='config_generation'",
            [],
            |r| r.get(0),
        )
        .optional()?;
    if expected == 0 || generation.and_then(|v| v.parse::<u64>().ok()) != Some(expected) {
        return Err(StoreError::Conflict("provider configuration owner changed"));
    }
    let mut out = Vec::new();
    let mut owners = std::collections::BTreeMap::new();
    {
        let sql = format!(
            "SELECT {},o.revision FROM providers p LEFT JOIN human_provider_owners o ON o.provider_id=p.provider_id ORDER BY p.sort_order,p.provider_id",
            cols("p", PROVIDER_COLS)
        );
        let mut statement = transaction.prepare(&sql)?;
        let mut query = statement.query([])?;
        while let Some(row) = query.next()? {
            check.step()?;
            if out.len() >= 4096 {
                return Err(StoreError::Conflict("provider preparation capacity"));
            }
            let provider = rows::provider(row, 0)?;
            let revision: Option<i64> = row.get(PROVIDER_COLS.len())?;
            let revision = revision
                .filter(|v| *v > 0)
                .ok_or_else(|| StoreError::Corrupt("missing provider incarnation".into()))?;
            owners.insert(provider.provider_id.to_string(), revision);
            out.push(provider);
        }
    }
    check.now()?;
    transaction.commit()?;
    Ok((out, owners))
}
impl Store {
    pub(crate) async fn prepare_registry_providers(
        &self,
        expected_generation: u64,
        deadline: Deadline,
    ) -> StoreResult<PreparedProviders> {
        let (rows, owners) = self
            .read_checked(
                "prepare_registry_providers",
                Some(deadline),
                move |c, check| prepared_rows(c, check, expected_generation),
            )
            .await?;
        Ok(PreparedProviders {
            store: Arc::downgrade(&self.inner),
            rows,
            owners,
            generation: expected_generation,
        })
    }
    pub(crate) async fn require_prepared_providers(
        &self,
        prepared: &PreparedProviders,
        deadline: Deadline,
    ) -> StoreResult<()> {
        if !Weak::ptr_eq(&prepared.store, &Arc::downgrade(&self.inner)) {
            return Err(StoreError::Conflict("provider store owner changed"));
        }
        let generation = prepared.generation;
        let (_, owners) = self
            .read_checked(
                "require_prepared_providers",
                Some(deadline),
                move |c, check| prepared_rows(c, check, generation),
            )
            .await?;
        if owners != prepared.owners {
            return Err(StoreError::Conflict("provider registry owner changed"));
        }
        Ok(())
    }
    pub(crate) async fn require_prepared_provider(
        &self,
        prepared: &PreparedProviders,
        id: &crate::provider::types::ProviderId,
        deadline: Deadline,
    ) -> StoreResult<()> {
        if !Weak::ptr_eq(&prepared.store, &Arc::downgrade(&self.inner)) {
            return Err(StoreError::Conflict("provider store owner changed"));
        }
        let expected = prepared
            .owners
            .get(id.as_str())
            .copied()
            .ok_or(StoreError::Conflict("provider not prepared"))?;
        let id = id.to_string();
        let generation = prepared.generation;
        self.read_checked(
            "require_prepared_provider",
            Some(deadline),
            move |c, check| {
                check.now()?;
                let tx = c.unchecked_transaction()?;
                let config: Option<String> = tx
                    .query_row(
                        "SELECT value FROM meta WHERE key='config_generation'",
                        [],
                        |r| r.get(0),
                    )
                    .optional()?;
                if config.and_then(|v| v.parse::<u64>().ok()) != Some(generation)
                    || current(&tx, &id)? != expected
                {
                    return Err(StoreError::Conflict("provider registry owner changed"));
                }
                check.now()?;
                tx.commit()?;
                Ok(())
            },
        )
        .await
    }
}
