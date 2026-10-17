//! Slice 5 for PostgreSQL (ADR-0020): the native provider and compiled
//! material owners the application prepares at start and fences against.
//! Reads run on one `REPEATABLE READ` snapshot; the material publication
//! takes an advisory lock and relies on the schema-6 trigger for its
//! revision rules, as SQLite does.
use std::collections::BTreeMap;
use std::sync::Arc;

use super::admin::{check_deadline, deadline_err};
use super::traits::provider_row;
use super::{PgStore, pg};
use crate::provider::material::Fingerprint;
use crate::provider::types::ProviderId;
use crate::store::owner_ref::OwnerRef;
use crate::store::sqlite::material_owner::{Ledger, Published, Row};
use crate::store::sqlite::provider_owner::PreparedProviders;
use crate::store::{Deadline, StoreError, StoreResult};

/// `pg_advisory_xact_lock` key serializing material publications.
const MATERIAL_LOCK: i64 = 7080;

const PROVIDER_COLS: &str = "p.provider_id, p.kind, p.display_name, p.enabled, p.managed_by, p.deleted_at, p.sort_order, p.config, p.client_secret_env, p.allowed_email_domains, p.authoritative_domains, p.auto_link, p.trust_email";

fn material_refused() -> StoreError {
    StoreError::Conflict("compiled material owner changed")
}

async fn generation_is(
    tx: &deadpool_postgres::Transaction<'_>,
    expected: u64,
) -> StoreResult<bool> {
    let v = tx
        .query_opt("SELECT value FROM meta WHERE key='config_generation'", &[])
        .await
        .map_err(pg)?
        .map(|r| r.get::<_, String>(0));
    Ok(expected != 0 && v.and_then(|v| v.parse::<u64>().ok()) == Some(expected))
}

async fn materials(tx: &deadpool_postgres::Transaction<'_>) -> StoreResult<Ledger> {
    let mut out = Ledger::new();
    for r in tx
        .query("SELECT provider_id, revision, fingerprint FROM human_provider_material_owners ORDER BY provider_id COLLATE \"C\"", &[])
        .await
        .map_err(pg)?
    {
        if out.len() >= 16384 {
            return Err(StoreError::Conflict("material owner capacity"));
        }
        let row = Row { revision: r.get(1), fingerprint: r.get(2) };
        if row.revision <= 0 || row.fingerprint.as_ref().is_some_and(|v| v.len() != 32) {
            return Err(material_refused());
        }
        out.insert(r.get(0), row);
    }
    Ok(out)
}

type Prepared = (
    Vec<crate::store::ProviderRow>,
    BTreeMap<String, i64>,
    Ledger,
);

impl PgStore {
    async fn prepared_rows(&self, expected: u64, deadline: Deadline) -> StoreResult<Prepared> {
        let mut client = self.client().await?;
        let tx = self.read_within(&mut client, deadline).await?;
        if !generation_is(&tx, expected).await? {
            return Err(StoreError::Conflict("provider configuration owner changed"));
        }
        let mut rows = Vec::new();
        let mut owners = BTreeMap::new();
        for r in tx
            .query(
                &format!("SELECT {PROVIDER_COLS}, o.revision FROM providers p LEFT JOIN human_provider_owners o ON o.provider_id = p.provider_id ORDER BY p.sort_order, p.provider_id COLLATE \"C\""),
                &[],
            )
            .await
            .map_err(pg)?
        {
            if rows.len() >= 4096 {
                return Err(StoreError::Conflict("provider preparation capacity"));
            }
            let provider = provider_row(&r)?;
            let revision = r
                .get::<_, Option<i64>>(13)
                .filter(|v| *v > 0)
                .ok_or_else(|| StoreError::Corrupt("missing provider incarnation".into()))?;
            owners.insert(provider.provider_id.to_string(), revision);
            rows.push(provider);
        }
        let materials = materials(&tx).await?;
        check_deadline(deadline)?;
        tx.commit().await.map_err(pg)?;
        Ok((rows, owners, materials))
    }

    pub(crate) async fn prepare_registry_providers(
        self: &Arc<Self>,
        expected: u64,
        deadline: Deadline,
    ) -> StoreResult<PreparedProviders> {
        let (rows, owners, materials) = self
            .prepared_rows(expected, deadline)
            .await
            .map_err(deadline_err)?;
        Ok(PreparedProviders::from_parts(
            OwnerRef::postgres(self),
            rows,
            owners,
            materials,
            expected,
        ))
    }

    pub(crate) async fn require_prepared_providers(
        self: &Arc<Self>,
        prepared: &PreparedProviders,
        deadline: Deadline,
    ) -> StoreResult<()> {
        if !prepared.store.is_postgres(self) {
            return Err(StoreError::Conflict("provider store owner changed"));
        }
        let (_, owners, _) = self
            .prepared_rows(prepared.generation, deadline)
            .await
            .map_err(deadline_err)?;
        if owners != prepared.owners {
            return Err(StoreError::Conflict("provider registry owner changed"));
        }
        Ok(())
    }

    pub(crate) async fn require_prepared_provider(
        self: &Arc<Self>,
        prepared: &PreparedProviders,
        id: &ProviderId,
        deadline: Deadline,
    ) -> StoreResult<()> {
        if !prepared.store.is_postgres(self) {
            return Err(StoreError::Conflict("provider store owner changed"));
        }
        let expected = prepared
            .owners
            .get(id.as_str())
            .copied()
            .ok_or(StoreError::Conflict("provider not prepared"))?;
        let out = async {
            let mut client = self.client().await?;
            let tx = self.read_within(&mut client, deadline).await?;
            let current = tx
                .query_opt(
                    "SELECT o.revision FROM human_provider_owners o JOIN providers p ON p.provider_id = o.provider_id \
                     WHERE p.provider_id = $1 AND p.enabled AND p.deleted_at IS NULL",
                    &[&id.as_str()],
                )
                .await
                .map_err(pg)?
                .map(|r| r.get::<_, i64>(0))
                .filter(|v| *v > 0);
            if !generation_is(&tx, prepared.generation).await? || current != Some(expected) {
                return Err(StoreError::Conflict("provider registry owner changed"));
            }
            tx.commit().await.map_err(pg)?;
            Ok(())
        }
        .await;
        out.map_err(deadline_err)
    }

    pub(crate) async fn publish_materials(
        self: &Arc<Self>,
        prepared: &PreparedProviders,
        desired: &BTreeMap<String, Fingerprint>,
        deadline: Deadline,
    ) -> StoreResult<Published> {
        if !prepared.store.is_postgres(self) {
            return Err(material_refused());
        }
        let expected = prepared.materials.clone();
        let entries = super::retry(|| async {
            check_deadline(deadline)?;
            let mut client = self.client().await?;
            let tx = self.begin(&mut client).await?;
            tx.execute("SELECT pg_advisory_xact_lock($1)", &[&MATERIAL_LOCK]).await.map_err(pg)?;
            if !generation_is(&tx, prepared.generation).await? {
                return Err(material_refused());
            }
            let mut actual = BTreeMap::new();
            for r in tx
                .query("SELECT p.provider_id, o.revision FROM providers p JOIN human_provider_owners o ON o.provider_id = p.provider_id", &[])
                .await
                .map_err(pg)?
            {
                if actual.len() >= 4096 {
                    return Err(material_refused());
                }
                actual.insert(r.get::<_, String>(0), r.get::<_, i64>(1));
            }
            if actual != prepared.owners {
                return Err(material_refused());
            }
            let current = materials(&tx).await?;
            // As SQLite: only the exact single anticipated transition (or none) is accepted.
            let mut intended = expected.clone();
            for id in expected.keys().chain(desired.keys()) {
                let fingerprint = desired.get(id).map(|v| v.bytes().to_vec());
                if intended.get(id).is_some_and(|r| r.fingerprint == fingerprint) {
                    continue;
                }
                let revision = match expected.get(id) {
                    Some(r) => r.revision.checked_add(1).ok_or_else(material_refused)?,
                    None => 1,
                };
                intended.insert(id.clone(), Row { revision, fingerprint });
            }
            if current != expected && current != intended {
                return Err(material_refused());
            }
            let mut next = current.clone();
            let ids: Vec<String> = current.keys().chain(desired.keys()).cloned().collect();
            for id in ids {
                let fingerprint = desired.get(&id).map(|v| v.bytes().to_vec());
                if next.get(&id).is_some_and(|r| r.fingerprint == fingerprint) {
                    continue;
                }
                let revision = match next.get(&id) {
                    Some(r) => r.revision.checked_add(1).ok_or_else(material_refused)?,
                    None => {
                        if next.len() >= 16384 {
                            return Err(StoreError::Conflict("material owner capacity"));
                        }
                        1
                    }
                };
                tx.execute(
                    "INSERT INTO human_provider_material_owners (provider_id, revision, fingerprint) VALUES ($1, $2, $3) \
                     ON CONFLICT (provider_id) DO UPDATE SET revision = excluded.revision, fingerprint = excluded.fingerprint",
                    &[&id, &revision, &fingerprint],
                )
                .await
                .map_err(pg)?;
                next.insert(id, Row { revision, fingerprint });
            }
            check_deadline(deadline)?;
            tx.commit().await.map_err(pg)?;
            Ok(next)
        })
        .await
        .map_err(deadline_err)?;
        Ok(Published::from_parts(OwnerRef::postgres(self), entries))
    }
}
