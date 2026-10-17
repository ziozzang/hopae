//! The Kubernetes workload principal registry on PostgreSQL (schema 8), as
//! SQLite's `store::sqlite::workloads`: registry changes commit with their
//! `workload.*` lifecycle events, and the snapshot pages by position.
//! Registry writes serialize on one advisory lock, so positions become
//! visible in commit order (a snapshot reader never later finds a row below
//! the position it reached).
use super::admin::{check_deadline, deadline_err};
use super::{PgStore, pg, retry};
use crate::event::types::Event;
use crate::store::sqlite::workloads::{LEGACY_PER_PRINCIPAL, WorkloadChange, WorkloadRow};
use crate::store::{Deadline, StoreResult};

/// Advisory lock key serializing registry writes.
const WORKLOAD_LOCK: i64 = 7090;

async fn upsert(
    tx: &deadpool_postgres::Transaction<'_>,
    w: &crate::auth_gateway::workload::signals::WorkloadRef,
    now: i64,
) -> StoreResult<()> {
    tx.execute(
        "INSERT INTO workload_principals (principal, subject_ref, spiffe_id, service, cluster, namespace, service_account, service_account_uid, status, first_seen_at, last_seen_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'active',$9,$9) \
         ON CONFLICT (principal) DO UPDATE SET last_seen_at = GREATEST(workload_principals.last_seen_at, excluded.last_seen_at)",
        &[
            &w.principal,
            &w.subject_ref,
            &w.spiffe_id,
            &w.service,
            &w.cluster_id,
            &w.namespace,
            &w.service_account,
            &w.service_account_uid,
            &now,
        ],
    )
    .await
    .map_err(pg)?;
    Ok(())
}

impl PgStore {
    /// Apply registry changes together with their events (one transaction).
    pub async fn workload_record(
        &self,
        changes: Vec<WorkloadChange>,
        events: Vec<Event>,
    ) -> StoreResult<()> {
        retry(|| async {
            let mut client = self.client().await?;
            let tx = self.begin(&mut client).await?;
            tx.execute(super::ADVISORY_XACT_LOCK, &[&WORKLOAD_LOCK])
                .await
                .map_err(pg)?;
            let now = self.now().secs();
            for change in &changes {
                match change {
                    WorkloadChange::Observed(w) => upsert(&tx, w, now).await?,
                    WorkloadChange::Retired {
                        workload,
                        cause,
                        replacement,
                    } => {
                        upsert(&tx, workload, now).await?;
                        tx.execute(
                            "UPDATE workload_principals SET status = 'retired', retired_at = $2, cause = $3, replacement = $4 \
                             WHERE principal = $1 AND status = 'active'",
                            &[&workload.principal, &now, cause, replacement],
                        )
                        .await
                        .map_err(pg)?;
                    }
                    WorkloadChange::LegacyMapped {
                        workload,
                        legacy_subject_ref,
                    } => {
                        upsert(&tx, workload, now).await?;
                        tx.execute(
                            "INSERT INTO workload_legacy_mappings (legacy_subject_ref, principal, observed_at) VALUES ($1,$2,$3) \
                             ON CONFLICT DO NOTHING",
                            &[legacy_subject_ref, &workload.principal, &now],
                        )
                        .await
                        .map_err(pg)?;
                    }
                }
            }
            self.insert_events(&tx, &events).await?;
            tx.commit().await.map_err(pg)
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
        let out = async {
            let mut client = self.client().await?;
            let tx = self.read_within(&mut client, deadline).await?;
            let mut rows: Vec<WorkloadRow> = tx
                .query(
                    "SELECT position, principal, subject_ref, spiffe_id, service, cluster, namespace, service_account, service_account_uid, \
                     status, first_seen_at, last_seen_at, retired_at, cause, replacement FROM workload_principals \
                     WHERE position > $1 ORDER BY position LIMIT $2",
                    &[&after, &limit],
                )
                .await
                .map_err(pg)?
                .iter()
                .map(|r| WorkloadRow {
                    position: r.get(0),
                    principal: r.get(1),
                    subject_ref: r.get(2),
                    spiffe_id: r.get(3),
                    service: r.get(4),
                    cluster: r.get(5),
                    namespace: r.get(6),
                    service_account: r.get(7),
                    service_account_uid: r.get(8),
                    status: r.get(9),
                    first_seen_at: r.get(10),
                    last_seen_at: r.get(11),
                    retired_at: r.get(12),
                    cause: r.get(13),
                    replacement: r.get(14),
                    legacy_subject_refs: Vec::new(),
                })
                .collect();
            check_deadline(deadline)?;
            for row in &mut rows {
                row.legacy_subject_refs = tx
                    .query(
                        "SELECT legacy_subject_ref FROM workload_legacy_mappings WHERE principal = $1 \
                         ORDER BY legacy_subject_ref COLLATE \"C\" LIMIT $2",
                        &[&row.principal, &LEGACY_PER_PRINCIPAL],
                    )
                    .await
                    .map_err(pg)?
                    .iter()
                    .map(|r| r.get(0))
                    .collect();
            }
            tx.commit().await.map_err(pg)?;
            Ok(rows)
        }
        .await;
        out.map_err(deadline_err)
    }

    /// The registry's highest position (tests and status).
    pub async fn workload_head(&self) -> StoreResult<i64> {
        let client = self.client().await?;
        Ok(client
            .query_one(
                "SELECT COALESCE(max(position), 0) FROM workload_principals",
                &[],
            )
            .await
            .map_err(pg)?
            .get(0))
    }
}
