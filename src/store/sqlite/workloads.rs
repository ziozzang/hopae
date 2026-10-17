//! Kubernetes workload principal registry (schema 16): written with the
//! `workload.*` lifecycle events in one transaction, read by the workload
//! snapshot so a consumer can recover after `cursor_expired`.
use rusqlite::{OptionalExtension, params};

use super::events::insert_events;
use super::{Store, commit};
use crate::auth_gateway::workload::signals::WorkloadRef;
use crate::event::types::Event;
use crate::store::{Deadline, StoreResult};

/// One registry change (mirrors the lifecycle signal it came from).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WorkloadChange {
    Observed(WorkloadRef),
    Retired {
        workload: WorkloadRef,
        cause: &'static str,
        replacement: Option<String>,
    },
    LegacyMapped {
        workload: WorkloadRef,
        legacy_subject_ref: String,
    },
}

/// One registry row with its legacy Pod-bound subjects.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkloadRow {
    pub position: i64,
    pub principal: String,
    pub subject_ref: String,
    pub spiffe_id: Option<String>,
    pub service: String,
    pub cluster: String,
    pub namespace: String,
    pub service_account: String,
    pub service_account_uid: String,
    pub status: String,
    pub first_seen_at: i64,
    pub last_seen_at: i64,
    pub retired_at: Option<i64>,
    pub cause: Option<String>,
    pub replacement: Option<String>,
    pub legacy_subject_refs: Vec<String>,
}

/// Most legacy subjects reported per principal in a snapshot item.
pub const LEGACY_PER_PRINCIPAL: i64 = 64;

fn upsert(tx: &rusqlite::Transaction<'_>, w: &WorkloadRef, now: i64) -> StoreResult<()> {
    tx.execute(
        "INSERT INTO workload_principals (principal, subject_ref, spiffe_id, service, cluster, namespace, service_account, service_account_uid, status, first_seen_at, last_seen_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,'active',?9,?9) ON CONFLICT(principal) DO UPDATE SET last_seen_at = MAX(last_seen_at, excluded.last_seen_at)",
        params![
            w.principal,
            w.subject_ref,
            w.spiffe_id,
            w.service,
            w.cluster_id,
            w.namespace,
            w.service_account,
            w.service_account_uid,
            now,
        ],
    )?;
    Ok(())
}

impl Store {
    /// Apply registry changes together with their events (one transaction).
    pub async fn workload_record(
        &self,
        changes: Vec<WorkloadChange>,
        events: Vec<Event>,
    ) -> StoreResult<()> {
        self.write("workload_record", move |env| {
            let shared = env.shared.clone();
            let now = shared.clock.now().secs();
            let tx = env.begin()?;
            for change in &changes {
                match change {
                    WorkloadChange::Observed(w) => upsert(&tx, w, now)?,
                    WorkloadChange::Retired {
                        workload,
                        cause,
                        replacement,
                    } => {
                        upsert(&tx, workload, now)?;
                        tx.execute(
                            "UPDATE workload_principals SET status='retired', retired_at=?2, cause=?3, replacement=?4 WHERE principal=?1 AND status='active'",
                            params![workload.principal, now, cause, replacement],
                        )?;
                    }
                    WorkloadChange::LegacyMapped {
                        workload,
                        legacy_subject_ref,
                    } => {
                        upsert(&tx, workload, now)?;
                        tx.execute(
                            "INSERT OR IGNORE INTO workload_legacy_mappings (legacy_subject_ref, principal, observed_at) VALUES (?1,?2,?3)",
                            params![legacy_subject_ref, workload.principal, now],
                        )?;
                    }
                }
            }
            insert_events(&tx, &shared, &events)?;
            commit(tx, &shared, None)
        })
        .await
    }

    /// Registry rows after `after` (position order), at most `limit`.
    pub async fn workload_snapshot_after(
        &self,
        after: i64,
        limit: usize,
        deadline: Deadline,
    ) -> StoreResult<Vec<WorkloadRow>> {
        let limit = i64::try_from(limit.min(1000)).unwrap_or(1000);
        self.read_checked("workload_snapshot", Some(deadline), move |c, check| {
            let mut st = c.prepare_cached(
                "SELECT position, principal, subject_ref, spiffe_id, service, cluster, namespace, service_account, service_account_uid, status, first_seen_at, last_seen_at, retired_at, cause, replacement FROM workload_principals WHERE position > ?1 ORDER BY position LIMIT ?2",
            )?;
            let mut rows = st
                .query_map(params![after, limit], |r| {
                    Ok(WorkloadRow {
                        position: r.get(0)?,
                        principal: r.get(1)?,
                        subject_ref: r.get(2)?,
                        spiffe_id: r.get(3)?,
                        service: r.get(4)?,
                        cluster: r.get(5)?,
                        namespace: r.get(6)?,
                        service_account: r.get(7)?,
                        service_account_uid: r.get(8)?,
                        status: r.get(9)?,
                        first_seen_at: r.get(10)?,
                        last_seen_at: r.get(11)?,
                        retired_at: r.get(12)?,
                        cause: r.get(13)?,
                        replacement: r.get(14)?,
                        legacy_subject_refs: Vec::new(),
                    })
                })?
                .collect::<Result<Vec<_>, _>>()?;
            check.now()?;
            let mut legacy = c.prepare_cached(
                "SELECT legacy_subject_ref FROM workload_legacy_mappings WHERE principal=?1 ORDER BY legacy_subject_ref LIMIT ?2",
            )?;
            for row in &mut rows {
                row.legacy_subject_refs = legacy
                    .query_map(params![row.principal, LEGACY_PER_PRINCIPAL], |r| r.get(0))?
                    .collect::<Result<Vec<_>, _>>()?;
            }
            Ok(rows)
        })
        .await
    }

    /// The registry's highest position (tests and status).
    pub async fn workload_head(&self) -> StoreResult<i64> {
        self.read("workload_head", |c| {
            Ok(c.query_row(
                "SELECT position FROM workload_principals ORDER BY position DESC LIMIT 1",
                [],
                |r| r.get(0),
            )
            .optional()?
            .unwrap_or(0))
        })
        .await
    }
}
