//! Original compiled-provider binding established by native authentication.
use super::Store;
use crate::store::owner_ref::OwnerRef;
use crate::{
    crypto::Timestamp,
    policy::types::ConfigSnapshot,
    provider::{ProviderId, Registry, registry::RegistryProviderFence},
    store::{AuthTimeSource, SessionRow, StoreError, StoreResult},
};
use rusqlite::{OptionalExtension, params};
use std::sync::Arc;
fn refused() -> StoreError {
    StoreError::Conflict("native primary authentication owner changed")
}
/// Captured before adapter verification. Not authentication evidence by itself.
pub(crate) struct Source {
    store: OwnerRef,
    registry: Arc<Registry>,
    fence: RegistryProviderFence,
    application: Arc<ConfigSnapshot>,
    provider: ProviderId,
    revision: i64,
    generation: u64,
    material: super::material_owner::Expected,
}
impl Source {
    pub(crate) fn from_registry(
        store: OwnerRef,
        registry: Arc<Registry>,
        fence: RegistryProviderFence,
        application: Arc<ConfigSnapshot>,
        provider: ProviderId,
        (revision, generation, material): (i64, u64, super::material_owner::Expected),
    ) -> Self {
        Self {
            store,
            registry,
            fence,
            application,
            provider,
            revision,
            generation,
            material,
        }
    }
    pub(crate) fn publication(&self) -> StoreResult<()> {
        self.registry
            .require_human_publication(&self.fence, &self.application)
    }
    pub(crate) fn write(
        &self,
        store: &Store,
        tx: &rusqlite::Transaction<'_>,
        session: &SessionRow,
        subject: &str,
        (auth_time, source): (Timestamp, AuthTimeSource),
        index: usize,
    ) -> StoreResult<()> {
        if !self.store.is_sqlite(&store.inner) {
            return Err(refused());
        }
        self.admissible(session, (auth_time, source))?;
        let config: Option<String> = tx
            .query_row(
                "SELECT value FROM meta WHERE key='config_generation'",
                [],
                |r| r.get(0),
            )
            .optional()?;
        let revision:Option<i64>=tx.query_row("SELECT o.revision FROM human_provider_owners o JOIN providers p ON p.provider_id=o.provider_id WHERE p.provider_id=?1 AND p.enabled=1 AND p.deleted_at IS NULL",[self.provider.as_str()],|r|r.get(0)).optional()?;
        if config.and_then(|s| s.parse::<u64>().ok()) != Some(self.generation)
            || revision != Some(self.revision)
        {
            return Err(refused());
        }
        self.material.require(tx, self.provider.as_str())?;
        let linked:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM identities WHERE provider_id=?1 AND subject=?2 AND user_id=?3)",params![self.provider.as_str(),subject,session.user_id.as_str()],|r|r.get(0))?;
        let (factor, generation, credential, index) = self.recorded(session, linked, index)?;
        let n=tx.execute("INSERT INTO session_primary_provenance(session_id,user_id,provider_id,material_revision,provider_revision,config_generation,credential_generation,subject,auth_time_ms,auth_time_source,factor_index,factor_kind,factor_at_ms) VALUES(?1,?2,?3,?13,?4,?5,?6,?7,?8,?9,?10,?11,?12) ON CONFLICT(session_id) DO UPDATE SET material_revision=excluded.material_revision,provider_revision=excluded.provider_revision,config_generation=excluded.config_generation,credential_generation=excluded.credential_generation,subject=excluded.subject,auth_time_ms=excluded.auth_time_ms,auth_time_source=excluded.auth_time_source,factor_index=excluded.factor_index,factor_kind=excluded.factor_kind,factor_at_ms=excluded.factor_at_ms WHERE excluded.user_id=session_primary_provenance.user_id AND excluded.provider_id=session_primary_provenance.provider_id AND excluded.credential_generation>session_primary_provenance.credential_generation",params![session.session_id.as_str(),session.user_id.as_str(),self.provider.as_str(),self.revision,generation,credential,subject,auth_time.0,source.as_str(),index,factor.kind.as_str(),factor.at.0,self.material.revision()])?;
        if n != 1 {
            return Err(refused());
        }
        Ok(())
    }
}
impl Source {
    /// The checks before any read: same provider, same authentication time
    /// and source, the publication still current.
    fn admissible(
        &self,
        session: &SessionRow,
        (auth_time, source): (Timestamp, AuthTimeSource),
    ) -> StoreResult<()> {
        if session.provider_id != self.provider
            || session.auth_time.secs() != auth_time.secs()
            || session.auth_time_source != source
        {
            return Err(refused());
        }
        self.publication()
    }
    /// The factor entry and the numbers to record, after the durable checks.
    fn recorded<'s>(
        &self,
        session: &'s SessionRow,
        linked: bool,
        index: usize,
    ) -> StoreResult<(&'s crate::session::FactorEntry, i64, i64, i64)> {
        let factor = session.factors.get(index).ok_or_else(refused)?;
        if !linked
            || factor.provider.as_ref() != Some(&self.provider)
            || matches!(
                factor.kind,
                crate::session::FactorKind::Totp
                    | crate::session::FactorKind::External
                    | crate::session::FactorKind::Recovery
                    | crate::session::FactorKind::Webauthn
            )
        {
            return Err(refused());
        }
        Ok((
            factor,
            i64::try_from(self.generation).map_err(|_| refused())?,
            i64::try_from(session.cred_gen).map_err(|_| refused())?,
            i64::try_from(index).map_err(|_| refused())?,
        ))
    }

    /// The PostgreSQL write, in the session's own transaction: the rows it
    /// rests on are read `FOR SHARE`, so an owner change waits for this
    /// commit or is seen before it.
    #[cfg(feature = "postgres")]
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn write_postgres(
        &self,
        store: &crate::store::postgres::PgStore,
        tx: &deadpool_postgres::Transaction<'_>,
        session: &SessionRow,
        subject: &str,
        (auth_time, source): (Timestamp, AuthTimeSource),
        index: usize,
    ) -> StoreResult<()> {
        use crate::store::postgres::human;
        if !self.store.is_postgres_store(store) {
            return Err(refused());
        }
        self.admissible(session, (auth_time, source))?;
        let fence = human::primary_fence(
            tx,
            self.provider.as_str(),
            subject,
            session.user_id.as_str(),
        )
        .await?;
        if fence.config.and_then(|s| s.parse::<u64>().ok()) != Some(self.generation)
            || fence.revision != Some(self.revision)
        {
            return Err(refused());
        }
        self.material.require_row(fence.material)?;
        let (factor, generation, credential, index) =
            self.recorded(session, fence.linked, index)?;
        let n = human::insert_primary(
            tx,
            &human::PrimaryInsert {
                session_id: session.session_id.as_str(),
                user_id: session.user_id.as_str(),
                provider_id: self.provider.as_str(),
                material_revision: self.material.revision(),
                provider_revision: self.revision,
                config_generation: generation,
                credential_generation: credential,
                subject,
                auth_time_ms: auth_time.0,
                auth_time_source: source.as_str(),
                factor_index: index,
                factor_kind: factor.kind.as_str(),
                factor_at_ms: factor.at.0,
            },
        )
        .await?;
        if n != 1 {
            return Err(refused());
        }
        Ok(())
    }
}
#[derive(Clone, PartialEq, Eq)]
pub(super) struct Facts {
    user: String,
    provider: String,
    revision: i64,
    material: i64,
    config: u64,
    credential: u64,
    subject: String,
    auth_time: i64,
    source: String,
    index: usize,
    kind: String,
    at: i64,
}
pub(super) fn current(
    tx: &dyn crate::store::meta::MetaTx,
    session: &SessionRow,
    revision: i64,
    config: u64,
    material: &super::material_owner::Expected,
) -> StoreResult<Facts> {
    let facts = if let Some(c) = tx.sqlite() {
        c.query_row("SELECT p.user_id,p.provider_id,p.provider_revision,p.config_generation,p.credential_generation,p.subject,p.auth_time_ms,p.auth_time_source,p.factor_index,p.factor_kind,p.factor_at_ms,p.material_revision FROM session_primary_provenance p JOIN identities i ON i.provider_id=p.provider_id AND i.subject=p.subject AND i.user_id=p.user_id WHERE p.session_id=?1",[session.session_id.as_str()],|r|Ok(Facts{user:r.get(0)?,provider:r.get(1)?,revision:r.get(2)?,config:r.get(3)?,credential:r.get(4)?,subject:r.get(5)?,auth_time:r.get(6)?,source:r.get(7)?,index:r.get(8)?,kind:r.get(9)?,at:r.get(10)?,material:r.get(11)?})).optional()?
    } else {
        postgres_current(tx, session.session_id.as_str())?
    }
    .ok_or_else(refused)?;
    material.require(tx, session.provider_id.as_str())?;
    let factor = session.factors.get(facts.index).ok_or_else(refused)?;
    if facts.user != session.user_id.as_str()
        || facts.provider != session.provider_id.as_str()
        || facts.material != material.revision()
        || facts.revision != revision
        || facts.config != config
        || facts.credential == 0
        || facts.credential > session.cred_gen
        || Timestamp(facts.auth_time).secs() != session.auth_time.secs()
        || facts.source != session.auth_time_source.as_str()
        || factor.provider.as_ref() != Some(&session.provider_id)
        || factor.kind.as_str() != facts.kind
        || factor.at.0 != facts.at
    {
        return Err(refused());
    }
    Ok(facts)
}
#[cfg(feature = "postgres")]
fn postgres_current(
    tx: &dyn crate::store::meta::MetaTx,
    session: &str,
) -> StoreResult<Option<Facts>> {
    let tx = tx.postgres().ok_or_else(refused)?;
    crate::store::postgres::human::primary_row(tx, session)?
        .map(
            |(
                user,
                provider,
                revision,
                config,
                credential,
                subject,
                auth_time,
                source,
                index,
                kind,
                at,
                material,
            )| {
                Ok(Facts {
                    user,
                    provider,
                    revision,
                    material,
                    config: u64::try_from(config).map_err(|_| refused())?,
                    credential: u64::try_from(credential).map_err(|_| refused())?,
                    subject,
                    auth_time,
                    source,
                    index: usize::try_from(index).map_err(|_| refused())?,
                    kind,
                    at,
                })
            },
        )
        .transpose()
}

#[cfg(not(feature = "postgres"))]
fn postgres_current(
    _tx: &dyn crate::store::meta::MetaTx,
    _session: &str,
) -> StoreResult<Option<Facts>> {
    Err(refused())
}

pub(super) fn validate_foundation(c: &rusqlite::Connection) -> StoreResult<()> {
    let sql = include_str!("../migrations/0009_session_primary_provenance.sql");
    let normalize = |s: &str| {
        s.to_ascii_lowercase()
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>()
            .trim_end_matches(';')
            .to_owned()
    };
    for (kind, name) in [
        ("table", "session_primary_provenance"),
        ("table", "human_provider_material_owners"),
        ("trigger", "human_material_owner_delete"),
        ("trigger", "human_material_owner_update"),
        ("trigger", "human_material_owner_insert"),
    ] {
        let start = sql
            .find(&format!("CREATE {} {name}", kind.to_ascii_uppercase()))
            .expect("embedded v9 schema");
        let rest = &sql[start..];
        let end = if kind == "trigger" {
            rest.find("\nEND;").expect("embedded trigger") + 5
        } else {
            rest.find(';').expect("embedded table") + 1
        };
        let actual: Option<String> = c
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type=?1 AND name=?2",
                [kind, name],
                |r| r.get(0),
            )
            .optional()?;
        if actual.as_deref().map(normalize) != Some(normalize(&rest[..end])) {
            return Err(StoreError::Corrupt(
                "schema v9 invalid native owner structure".into(),
            ));
        }
    }
    Ok(())
}

impl Facts {
    #[allow(dead_code)] // Used by the additive native Human retained-record quota.
    pub(super) fn owned_heap_bytes(&self) -> StoreResult<usize> {
        crate::store::types::heap_sum([
            self.user.capacity(),
            self.provider.capacity(),
            self.subject.capacity(),
            self.source.capacity(),
            self.kind.capacity(),
        ])
    }
}

#[cfg(test)]
mod retained_heap_tests {
    use super::*;
    #[test]
    fn retained_heap_primary_counts_each_owned_fact() {
        let mut value = String::with_capacity(128);
        value.push('x');
        let cap = value.capacity();
        let facts = Facts {
            user: value,
            provider: String::new(),
            revision: 1,
            material: 1,
            config: 1,
            credential: 1,
            subject: String::new(),
            auth_time: 0,
            source: String::new(),
            index: 0,
            kind: String::new(),
            at: 0,
        };
        assert_eq!(facts.owned_heap_bytes().unwrap(), cap);
        let mut next = facts.clone();
        next.subject.reserve(256);
        assert_eq!(
            next.owned_heap_bytes().unwrap(),
            next.user.capacity() + next.subject.capacity()
        );
    }
}
