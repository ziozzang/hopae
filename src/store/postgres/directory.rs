//! Slice 3 for PostgreSQL (ADR-0020): the read-only subject directory and
//! its lifecycle feeds.
//!
//! SQLite numbers both feeds by `rowid`, which its single writer hands out
//! in commit order. PostgreSQL assigns identity values before commit, so
//! both feeds take a transaction-scoped advisory lock before their row is
//! numbered (schema 5): the reservation ledger in its insert trigger, the
//! lifecycle feed (`outbox_feed`, the `admin.user_*` and `group.*` outbox
//! events) in the outbox insert. Positions therefore become visible in
//! order and a consumer never skips one.
use std::collections::BTreeMap;

use async_trait::async_trait;

use super::admin::{check_deadline, deadline_err};
use super::{HANDLE_COLS, PgStore, USER_COLS, handle, pg, user};
use crate::store::core::SubjectDirectoryStore;
use crate::store::sqlite::subject_directory::{
    DirectoryRow, FEED_SCAN, LedgerRow, MAX_BATCH, OutboxPosition, PositionLost, StatusChange,
    StatusPage,
};
use crate::store::types::HandleRow;
use crate::store::{Deadline, StoreError, StoreResult};

fn bounded(n: usize) -> StoreResult<()> {
    if n > MAX_BATCH {
        return Err(StoreError::Conflict("directory batch too large"));
    }
    Ok(())
}

/// What a feed row reports, as SQLite's classification.
fn classify(kind: &str, groups: bool, workloads: bool) -> Option<&'static str> {
    match kind {
        "workload.principal_observed" if workloads => Some("workload_observed"),
        "workload.principal_retired" if workloads => Some("workload_retired"),
        "workload.legacy_subject_mapped" if workloads => Some("workload_legacy_mapped"),
        "admin.user_disable" => Some("disabled"),
        "admin.user_enable" => Some("enabled"),
        "group.created" if groups => Some("group_created"),
        "group.updated" if groups => Some("group_updated"),
        "group.deleted" if groups => Some("group_deleted"),
        "group.member_added" if groups => Some("member_added"),
        "group.member_removed" if groups => Some("member_removed"),
        "group.membership_stale" if groups => Some("member_suspended"),
        "group.membership_restored" if groups => Some("member_restored"),
        _ => None,
    }
}

#[async_trait]
impl SubjectDirectoryStore for PgStore {
    async fn admin_directory_rows(
        &self,
        users: Vec<String>,
        deadline: Deadline,
    ) -> StoreResult<BTreeMap<String, DirectoryRow>> {
        bounded(users.len())?;
        let out = async {
            let mut client = self.client().await?;
            let tx = self.read_within(&mut client, deadline).await?;
            let mut out: BTreeMap<String, DirectoryRow> = BTreeMap::new();
            for r in tx
                .query(&format!("SELECT {USER_COLS} FROM users WHERE user_id = ANY($1)"), &[&users])
                .await
                .map_err(pg)?
            {
                let u = user(&r, 0)?;
                out.insert(
                    u.user_id.to_string(),
                    DirectoryRow { user: Some(u), ledger: None, providers: Vec::new(), last_seen_at: None },
                );
            }
            check_deadline(deadline)?;
            for r in tx
                .query("SELECT user_id, position FROM human_user_ids WHERE user_id = ANY($1)", &[&users])
                .await
                .map_err(pg)?
            {
                let (id, position): (String, i64) = (r.get(0), r.get(1));
                out.entry(id)
                    .or_insert(DirectoryRow { user: None, ledger: None, providers: Vec::new(), last_seen_at: None })
                    .ledger = Some(position);
            }
            check_deadline(deadline)?;
            for r in tx
                .query(
                    "SELECT DISTINCT user_id, provider_id FROM identities WHERE user_id = ANY($1) ORDER BY user_id, provider_id",
                    &[&users],
                )
                .await
                .map_err(pg)?
            {
                let (id, provider): (String, String) = (r.get(0), r.get(1));
                if let Some(row) = out.get_mut(&id) {
                    row.providers.push(provider);
                }
            }
            check_deadline(deadline)?;
            for r in tx
                .query(
                    "SELECT user_id, max(last_seen_at) FROM sessions WHERE user_id = ANY($1) GROUP BY user_id",
                    &[&users],
                )
                .await
                .map_err(pg)?
            {
                let (id, seen): (String, Option<i64>) = (r.get(0), r.get(1));
                if let Some(row) = out.get_mut(&id) {
                    row.last_seen_at = seen;
                }
            }
            tx.commit().await.map_err(pg)?;
            Ok(out)
        }
        .await;
        out.map_err(deadline_err)
    }

    async fn admin_ledger_after(
        &self,
        after: i64,
        limit: usize,
        deadline: Deadline,
    ) -> StoreResult<Vec<LedgerRow>> {
        let limit = i64::try_from(limit.min(50_000)).unwrap_or(0);
        let out = async {
            let mut client = self.client().await?;
            let tx = self.read_within(&mut client, deadline).await?;
            let rows = tx
                .query(
                    "SELECT i.position, i.user_id, u.status, u.created_at FROM human_user_ids i LEFT JOIN users u ON u.user_id = i.user_id \
                     WHERE i.position > $1 ORDER BY i.position LIMIT $2",
                    &[&after, &limit],
                )
                .await
                .map_err(pg)?;
            tx.commit().await.map_err(pg)?;
            Ok(rows
                .iter()
                .map(|r| LedgerRow { position: r.get(0), user_id: r.get(1), status: r.get(2), created_at: r.get(3) })
                .collect())
        }
        .await;
        out.map_err(deadline_err)
    }

    async fn admin_ledger_at(
        &self,
        positions: Vec<i64>,
        deadline: Deadline,
    ) -> StoreResult<BTreeMap<i64, String>> {
        bounded(positions.len())?;
        let out = async {
            let mut client = self.client().await?;
            let tx = self.read_within(&mut client, deadline).await?;
            let rows = tx
                .query(
                    "SELECT position, user_id FROM human_user_ids WHERE position = ANY($1)",
                    &[&positions],
                )
                .await
                .map_err(pg)?;
            tx.commit().await.map_err(pg)?;
            Ok(rows.iter().map(|r| (r.get(0), r.get(1))).collect())
        }
        .await;
        out.map_err(deadline_err)
    }

    async fn admin_ledger_head(&self, deadline: Deadline) -> StoreResult<i64> {
        let out = async {
            let mut client = self.client().await?;
            let tx = self.read_within(&mut client, deadline).await?;
            let head: i64 = tx
                .query_one("SELECT COALESCE(max(position), 0) FROM human_user_ids", &[])
                .await
                .map_err(pg)?
                .get(0);
            tx.commit().await.map_err(pg)?;
            Ok(head)
        }
        .await;
        out.map_err(deadline_err)
    }

    async fn admin_outbox_head(&self, deadline: Deadline) -> StoreResult<OutboxPosition> {
        let out = async {
            let mut client = self.client().await?;
            let tx = self.read_within(&mut client, deadline).await?;
            let row = tx
                .query_opt(
                    "SELECT pos, event_id FROM outbox_feed ORDER BY pos DESC LIMIT 1",
                    &[],
                )
                .await
                .map_err(pg)?;
            tx.commit().await.map_err(pg)?;
            Ok(match row {
                Some(r) => OutboxPosition {
                    row: r.get(0),
                    event_id: Some(r.get(1)),
                },
                None => OutboxPosition {
                    row: 0,
                    event_id: None,
                },
            })
        }
        .await;
        out.map_err(deadline_err)
    }

    async fn admin_feed_changes(
        &self,
        after: OutboxPosition,
        limit: usize,
        groups: bool,
        workloads: bool,
        deadline: Deadline,
    ) -> StoreResult<Result<StatusPage, PositionLost>> {
        let limit = limit.min(MAX_BATCH);
        let out = async {
            let mut client = self.client().await?;
            let tx = self.read_within(&mut client, deadline).await?;
            if after.row < 0 {
                return Ok(Err(PositionLost));
            }
            if after.row > 0 {
                let id = tx
                    .query_opt("SELECT event_id FROM outbox_feed WHERE pos = $1", &[&after.row])
                    .await
                    .map_err(pg)?
                    .map(|r| r.get::<_, String>(0));
                if id.is_none() || id != after.event_id {
                    return Ok(Err(PositionLost));
                }
            } else if after.event_id.is_some() {
                return Ok(Err(PositionLost));
            }
            let head: i64 = tx
                .query_one("SELECT COALESCE(max(pos), 0) FROM outbox_feed", &[])
                .await
                .map_err(pg)?
                .get(0);
            let rows = tx
                .query(
                    "SELECT f.pos, e.event_id, e.at, e.kind, e.user_id, e.attrs->>'group_id', CASE WHEN e.kind LIKE 'workload.%' THEN e.attrs::text END FROM outbox_feed f JOIN events e ON e.event_id = f.event_id \
                     WHERE f.pos > $1 ORDER BY f.pos LIMIT $2",
                    &[&after.row, &FEED_SCAN],
                )
                .await
                .map_err(pg)?;
            tx.commit().await.map_err(pg)?;
            let mut changes = Vec::new();
            let mut next = after.clone();
            for r in &rows {
                let (row, id, at, kind, user, group, attrs): (i64, String, f64, String, Option<String>, Option<String>, Option<String>) =
                    (r.get(0), r.get(1), r.get(2), r.get(3), r.get(4), r.get(5), r.get(6));
                let change = classify(&kind, groups, workloads);
                // As SQLite: the reported workload identifiers only.
                let workload = attrs
                    .filter(|_| change.is_some_and(|c| c.starts_with("workload_")))
                    .and_then(|a| serde_json::from_str::<serde_json::Value>(&a).ok())
                    .and_then(|v| v.as_object().cloned())
                    .map(|mut m| {
                        m.retain(|k, _| {
                            crate::store::sqlite::subject_directory::WORKLOAD_CHANGE_KEYS
                                .contains(&k.as_str())
                        });
                        m
                    });
                let wanted = match change {
                    Some(c) if c.starts_with("workload_") => {
                        workload.as_ref().is_some_and(|w| w.contains_key("principal"))
                    }
                    Some("disabled" | "enabled") => user.is_some(),
                    Some("member_added" | "member_removed" | "member_suspended" | "member_restored") => {
                        user.is_some() && group.is_some()
                    }
                    Some(_) => group.is_some(),
                    None => false,
                };
                if let (true, Some(change)) = (wanted, change) {
                    if changes.len() == limit {
                        break;
                    }
                    changes.push(StatusChange {
                        position: row,
                        event_id: id.clone(),
                        at: at.floor() as i64,
                        change,
                        user_id: user,
                        group_id: group.filter(|_| {
                            change != "disabled" && change != "enabled" && !change.starts_with("workload_")
                        }),
                        workload,
                    });
                }
                next = OutboxPosition { row, event_id: Some(id) };
            }
            Ok(Ok(StatusPage { changes, next, head }))
        }
        .await;
        out.map_err(deadline_err)
    }

    async fn admin_live_handle(
        &self,
        session: String,
        host: String,
        deadline: Deadline,
    ) -> StoreResult<Option<HandleRow>> {
        let out = async {
            let mut client = self.client().await?;
            let tx = self.read_within(&mut client, deadline).await?;
            let row = tx
                .query_opt(
                    &format!("SELECT {HANDLE_COLS} FROM session_handles h WHERE h.session_id = $1 AND h.host = $2 AND h.revoked_at IS NULL ORDER BY h.created_at DESC LIMIT 1"),
                    &[&session, &host],
                )
                .await
                .map_err(pg)?
                .map(|r| handle(&r, 0))
                .transpose()?;
            tx.commit().await.map_err(pg)?;
            Ok(row)
        }
        .await;
        out.map_err(deadline_err)
    }

    async fn admin_totp_active(&self, user: String, deadline: Deadline) -> StoreResult<bool> {
        let out = async {
            let mut client = self.client().await?;
            let tx = self.read_within(&mut client, deadline).await?;
            let active = tx
                .query_opt(
                    "SELECT 1 FROM totp_enrollments WHERE user_id = $1 AND state = 'active'",
                    &[&user],
                )
                .await
                .map_err(pg)?
                .is_some();
            tx.commit().await.map_err(pg)?;
            Ok(active)
        }
        .await;
        out.map_err(deadline_err)
    }

    async fn admin_human_realm(&self, deadline: Deadline) -> StoreResult<Option<String>> {
        let out = async {
            let mut client = self.client().await?;
            let tx = self.read_within(&mut client, deadline).await?;
            let realm = tx
                .query_opt(
                    "SELECT realm FROM human_authority_realm WHERE singleton = 1",
                    &[],
                )
                .await
                .map_err(pg)?
                .map(|r| r.get::<_, String>(0));
            tx.commit().await.map_err(pg)?;
            Ok(realm)
        }
        .await;
        out.map_err(deadline_err)
    }

    async fn admin_human_subjects(
        &self,
        issuer: String,
        users: Vec<String>,
        deadline: Deadline,
    ) -> StoreResult<BTreeMap<String, String>> {
        if users.len() > MAX_BATCH {
            return Err(StoreError::Conflict("too many Human metadata subjects"));
        }
        let users: Vec<String> = users
            .into_iter()
            .filter(|u| !u.is_empty() && u.len() <= 256 && !u.chars().any(char::is_control))
            .collect();
        let out = async {
            let mut client = self.client().await?;
            let tx = self.read_within(&mut client, deadline).await?;
            let rows = tx
                .query(
                    "SELECT u.user_id, a.realm FROM users u JOIN human_user_ids i ON i.user_id = u.user_id \
                     JOIN human_authority_realm a ON a.singleton = 1 WHERE u.user_id = ANY($1)",
                    &[&users],
                )
                .await
                .map_err(pg)?;
            tx.commit().await.map_err(pg)?;
            let mut out = BTreeMap::new();
            for r in rows {
                let (user, realm): (String, String) = (r.get(0), r.get(1));
                let subject = crate::store::sqlite::subject_directory::human_subject(&issuer, &realm, &user)
                    .ok_or(StoreError::Conflict("invalid Human subject coordinate"))?;
                out.insert(user, subject);
            }
            Ok(out)
        }
        .await;
        out.map_err(deadline_err)
    }
}
