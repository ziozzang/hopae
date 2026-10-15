//! Durable CAS for opaque fingerprints of actual compiled material, not grants.
use super::{Check, Inner, Store, commit_checked, provider_owner::PreparedProviders};
use crate::{
    provider::material::Fingerprint,
    store::{Deadline, StoreError, StoreResult},
};
use rusqlite::{OptionalExtension, params};
use std::{
    collections::BTreeMap,
    sync::{Arc, Weak},
};
#[derive(Clone, PartialEq, Eq)]
pub(super) struct Row {
    pub(super) revision: i64,
    pub(super) fingerprint: Option<Vec<u8>>,
}
pub(super) type Ledger = BTreeMap<String, Row>;
pub(crate) struct Published {
    store: Weak<Inner>,
    entries: Ledger,
}
#[derive(Clone)]
pub(crate) struct Expected {
    revision: i64,
    fingerprint: Vec<u8>,
}
fn refused() -> StoreError {
    StoreError::Conflict("compiled material owner changed")
}
pub(super) fn read(c: &rusqlite::Connection, check: &Check) -> StoreResult<Ledger> {
    let mut s=c.prepare("SELECT provider_id,revision,fingerprint FROM human_provider_material_owners ORDER BY provider_id")?;
    let mut rows = s.query([])?;
    let mut out = Ledger::new();
    while let Some(r) = rows.next()? {
        check.step()?;
        if out.len() >= 16384 {
            return Err(StoreError::Conflict("material owner capacity"));
        }
        let row = Row {
            revision: r.get(1)?,
            fingerprint: r.get(2)?,
        };
        if row.revision <= 0 || row.fingerprint.as_ref().is_some_and(|v| v.len() != 32) {
            return Err(refused());
        }
        out.insert(r.get(0)?, row);
    }
    Ok(out)
}
impl Published {
    pub(crate) fn same(&self, other: &Self) -> bool {
        Weak::ptr_eq(&self.store, &other.store) && self.entries == other.entries
    }
    pub(crate) fn expected(&self, store: &Store, id: &str) -> StoreResult<Expected> {
        if !Weak::ptr_eq(&self.store, &Arc::downgrade(&store.inner)) {
            return Err(refused());
        }
        let row = self.entries.get(id).ok_or_else(refused)?;
        Ok(Expected {
            revision: row.revision,
            fingerprint: row.fingerprint.clone().ok_or_else(refused)?,
        })
    }
    pub(crate) fn contains(&self, id: &str) -> bool {
        self.entries
            .get(id)
            .is_some_and(|r| r.fingerprint.is_some())
    }
}
impl Expected {
    pub(crate) fn revision(&self) -> i64 {
        self.revision
    }
    pub(crate) fn require(&self, c: &rusqlite::Connection, id: &str) -> StoreResult<()> {
        let row:Option<(i64,Vec<u8>)>=c.query_row("SELECT revision,fingerprint FROM human_provider_material_owners WHERE provider_id=?1 AND fingerprint IS NOT NULL",[id],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
        if row != Some((self.revision, self.fingerprint.clone())) {
            return Err(refused());
        }
        Ok(())
    }
}
impl Store {
    pub(crate) async fn publish_materials(
        &self,
        prepared: &PreparedProviders,
        desired: &BTreeMap<String, Fingerprint>,
        deadline: Deadline,
    ) -> StoreResult<Published> {
        if !Weak::ptr_eq(&prepared.store, &Arc::downgrade(&self.inner)) {
            return Err(refused());
        }
        let expected = prepared.materials.clone();
        let providers = prepared.owners.clone();
        let generation = prepared.generation;
        let desired = desired.clone();
        let entries=self.write_checked("publish_compiled_material",Some(deadline),move|env,check|{
 let shared=env.shared.clone();let tx=env.begin()?;check.now()?;
 let config:Option<String>=tx.query_row("SELECT value FROM meta WHERE key='config_generation'",[],|r|r.get(0)).optional()?;
 if config.and_then(|v|v.parse::<u64>().ok())!=Some(generation){return Err(refused());}
 let actual:BTreeMap<String,i64>={let mut s=tx.prepare("SELECT p.provider_id,o.revision FROM providers p JOIN human_provider_owners o ON o.provider_id=p.provider_id")?;let mut q=s.query([])?;let mut out=BTreeMap::new();while let Some(r)=q.next()?{check.step()?;if out.len()>=4096{return Err(refused());}out.insert(r.get(0)?,r.get(1)?);}out};
 if actual!=providers{return Err(refused());}
 let current=read(&tx,check)?;
 // A concurrently published identical complete material set is a stable no-op.
 // An unexpected different owner may never be overwritten by this preparation.
 let mut intended=expected.clone();
 for id in expected.keys().chain(desired.keys()) {
     let fingerprint=desired.get(id).map(|v|v.bytes().to_vec());
     if intended.get(id).is_some_and(|r|r.fingerprint==fingerprint){continue;}
     let revision=match expected.get(id){Some(r)=>r.revision.checked_add(1).ok_or_else(refused)?,None=>1};
     intended.insert(id.clone(),Row{revision,fingerprint});
 }
 // Only the exact single transition anticipated before compilation may be
 // shared by an identical preparation. Equal bytes after an ABA are NOT it.
 if current!=expected && current!=intended{return Err(refused());}
 let mut next=current.clone();
 for id in current.keys().chain(desired.keys()) {
 let fingerprint=desired.get(id).map(|v|v.bytes().to_vec());
 if next.get(id).is_some_and(|r|r.fingerprint==fingerprint){continue;}
 let revision=match next.get(id){Some(r)=>r.revision.checked_add(1).ok_or_else(refused)?,None=>{if next.len()>=16384{return Err(StoreError::Conflict("material owner capacity"));}1}};
 tx.execute("INSERT INTO human_provider_material_owners(provider_id,revision,fingerprint) VALUES(?1,?2,?3) ON CONFLICT(provider_id) DO UPDATE SET revision=excluded.revision,fingerprint=excluded.fingerprint",params![id,revision,fingerprint])?;
 next.insert(id.clone(),Row{revision,fingerprint});
 }
 commit_checked(tx,&shared,Some("human_material_publish"),check)?;Ok(next)
 }).await?;
        Ok(Published {
            store: Arc::downgrade(&self.inner),
            entries,
        })
    }
}
