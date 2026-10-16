//! Read-only subject directory queries for the administrative subject APIs
//! (resolve, search, lifecycle feed and snapshot) and the authentication
//! explain API. Nothing here writes, creates a session or touches a handle.
//!
//! Two append-only sources carry the subject lifecycle without a schema of
//! its own:
//!
//! * the reservation ledger `human_user_ids` (schema v10): one row per user
//!   ID ever created, never deleted or reused, in creation order (`rowid`);
//!   a reserved ID without a `users` row is a tombstone;
//! * the event outbox `events`: `admin.user_disable` / `admin.user_enable`
//!   are written in the transaction that changes `users.status`, and only
//!   when it changes. Retention prunes the oldest rows, so a position in it
//!   is checked before use.
use std::collections::BTreeMap;

use rusqlite::{OptionalExtension, params};

use super::Store;
use super::rows::{self, HANDLE_COLS, USER_COLS, cols};
use crate::store::types::{HandleRow, User};
use crate::store::{Deadline, StoreError, StoreResult};

/// Largest batch any directory read accepts.
pub const MAX_BATCH: usize = 200;
/// Most outbox rows one feed page examines (a bound on work per call, not on results).
pub const FEED_SCAN: i64 = 20_000;

/// What the directory knows about one user ID.
#[derive(Clone, Debug)]
pub struct DirectoryRow {
    /// `None`: reserved in the ledger but no longer present (a tombstone).
    pub user: Option<User>,
    /// Position in the reservation ledger (absent for pre-ledger rows only in
    /// a damaged store; the migration seeds every live user).
    pub ledger: Option<i64>,
    /// Providers of the linked identities, sorted, without duplicates.
    pub providers: Vec<String>,
    /// Newest `sessions.last_seen_at` (unix seconds).
    pub last_seen_at: Option<i64>,
}

/// One reservation-ledger row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerRow {
    pub position: i64,
    pub user_id: String,
    /// `active`, `disabled`, or `None` for a tombstone.
    pub status: Option<String>,
    pub created_at: Option<i64>,
}

/// One status change taken from the outbox.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatusChange {
    pub position: i64,
    pub event_id: String,
    pub at: i64,
    /// `disabled` or `enabled`; with groups also `group_created`,
    /// `group_updated`, `group_deleted`, `member_added`, `member_removed`.
    pub change: &'static str,
    /// Absent for a group's own lifecycle change.
    pub user_id: Option<String>,
    /// The group of a group change.
    pub group_id: Option<String>,
}

/// A position in the outbox: the row and its event id, so a reused or
/// pruned row is detected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutboxPosition {
    pub row: i64,
    pub event_id: Option<String>,
}

/// One page of the status-change stream.
#[derive(Clone, Debug)]
pub struct StatusPage {
    pub changes: Vec<StatusChange>,
    /// Where the next page starts.
    pub next: OutboxPosition,
    /// The newest outbox row at read time.
    pub head: i64,
}

/// The outbox no longer holds the asked position (pruned by retention, or
/// the store was replaced): the consumer must take a new snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PositionLost;

fn bounded(n: usize) -> StoreResult<()> {
    if n > MAX_BATCH {
        return Err(StoreError::Conflict("directory batch too large"));
    }
    Ok(())
}

fn json_list<T: serde::Serialize>(v: &T) -> StoreResult<String> {
    serde_json::to_string(v).map_err(|_| StoreError::Conflict("invalid directory query"))
}

/// The canonical Human subject of a user under `issuer` and `realm`, when
/// both are well formed (the same derivation the gateway uses).
pub fn human_subject(issuer: &str, realm: &str, user: &str) -> Option<String> {
    super::human_subject::derive(issuer, realm, user).ok()
}

impl Store {
    /// A process-local identity of this open store, for caches derived from it.
    pub(crate) fn directory_identity(&self) -> usize {
        std::sync::Arc::as_ptr(&self.inner) as usize
    }

    /// Directory rows of the given user IDs that exist or are reserved.
    pub(crate) async fn admin_directory_rows(
        &self,
        users: Vec<String>,
        deadline: Deadline,
    ) -> StoreResult<BTreeMap<String, DirectoryRow>> {
        bounded(users.len())?;
        let query = json_list(&users)?;
        self.read_checked("admin_directory_rows", Some(deadline), move |c, check| {
            let mut out: BTreeMap<String, DirectoryRow> = BTreeMap::new();
            let sql = format!(
                "SELECT {} FROM users WHERE user_id IN (SELECT value FROM json_each(?1))",
                cols("", USER_COLS)
            );
            let mut st = c.prepare_cached(&sql)?;
            let mut q = st.query([&query])?;
            while let Some(r) = q.next()? {
                check.now()?;
                let user = rows::user(r, 0)?;
                out.insert(
                    user.user_id.to_string(),
                    DirectoryRow {
                        user: Some(user),
                        ledger: None,
                        providers: Vec::new(),
                        last_seen_at: None,
                    },
                );
            }
            check.now()?;
            let mut st = c.prepare_cached(
                "SELECT user_id, rowid FROM human_user_ids WHERE user_id IN (SELECT value FROM json_each(?1))",
            )?;
            let mut q = st.query([&query])?;
            while let Some(r) = q.next()? {
                let (id, position): (String, i64) = (r.get(0)?, r.get(1)?);
                out.entry(id)
                    .or_insert(DirectoryRow {
                        user: None,
                        ledger: None,
                        providers: Vec::new(),
                        last_seen_at: None,
                    })
                    .ledger = Some(position);
            }
            check.now()?;
            let mut st = c.prepare_cached(
                "SELECT DISTINCT user_id, provider_id FROM identities WHERE user_id IN (SELECT value FROM json_each(?1)) ORDER BY user_id, provider_id",
            )?;
            let mut q = st.query([&query])?;
            while let Some(r) = q.next()? {
                let (id, provider): (String, String) = (r.get(0)?, r.get(1)?);
                if let Some(row) = out.get_mut(&id) {
                    row.providers.push(provider);
                }
            }
            check.now()?;
            let mut st = c.prepare_cached(
                "SELECT user_id, MAX(last_seen_at) FROM sessions WHERE user_id IN (SELECT value FROM json_each(?1)) GROUP BY user_id",
            )?;
            let mut q = st.query([&query])?;
            while let Some(r) = q.next()? {
                let (id, seen): (String, Option<i64>) = (r.get(0)?, r.get(1)?);
                if let Some(row) = out.get_mut(&id) {
                    row.last_seen_at = seen;
                }
            }
            check.now()?;
            Ok(out)
        })
        .await
    }

    /// The store's Human realm (64 lowercase hex), absent before schema v10.
    pub(crate) async fn admin_human_realm(
        &self,
        deadline: Deadline,
    ) -> StoreResult<Option<String>> {
        self.read_checked("admin_human_realm", Some(deadline), |c, _| {
            Ok(c.query_row(
                "SELECT realm FROM human_authority_realm WHERE singleton = 1",
                [],
                |r| r.get::<_, String>(0),
            )
            .optional()?)
        })
        .await
    }

    /// Up to `limit` ledger rows after `after`, with their current status.
    pub(crate) async fn admin_ledger_after(
        &self,
        after: i64,
        limit: usize,
        deadline: Deadline,
    ) -> StoreResult<Vec<LedgerRow>> {
        let limit = i64::try_from(limit.min(50_000)).unwrap_or(0);
        self.read_checked("admin_ledger_after", Some(deadline), move |c, check| {
            let mut st = c.prepare_cached(
                "SELECT i.rowid, i.user_id, u.status, u.created_at FROM human_user_ids i LEFT JOIN users u ON u.user_id = i.user_id WHERE i.rowid > ?1 ORDER BY i.rowid LIMIT ?2",
            )?;
            let mut q = st.query(params![after, limit])?;
            let mut out = Vec::new();
            while let Some(r) = q.next()? {
                if out.len().is_multiple_of(1024) {
                    check.now()?;
                }
                out.push(LedgerRow {
                    position: r.get(0)?,
                    user_id: r.get(1)?,
                    status: r.get(2)?,
                    created_at: r.get(3)?,
                });
            }
            Ok(out)
        })
        .await
    }

    /// The ledger rows at the given positions (to confirm index candidates).
    pub(crate) async fn admin_ledger_at(
        &self,
        positions: Vec<i64>,
        deadline: Deadline,
    ) -> StoreResult<BTreeMap<i64, String>> {
        bounded(positions.len())?;
        let query = json_list(&positions)?;
        self.read_checked("admin_ledger_at", Some(deadline), move |c, _| {
            let mut st = c.prepare_cached(
                "SELECT rowid, user_id FROM human_user_ids WHERE rowid IN (SELECT value FROM json_each(?1))",
            )?;
            let mut q = st.query([&query])?;
            let mut out = BTreeMap::new();
            while let Some(r) = q.next()? {
                out.insert(r.get(0)?, r.get(1)?);
            }
            Ok(out)
        })
        .await
    }

    /// The newest ledger position (0 when empty).
    pub(crate) async fn admin_ledger_head(&self, deadline: Deadline) -> StoreResult<i64> {
        self.read_checked("admin_ledger_head", Some(deadline), |c, _| {
            Ok(c.query_row(
                "SELECT COALESCE(MAX(rowid), 0) FROM human_user_ids",
                [],
                |r| r.get(0),
            )?)
        })
        .await
    }

    /// The newest outbox row and its event id.
    pub(crate) async fn admin_outbox_head(
        &self,
        deadline: Deadline,
    ) -> StoreResult<OutboxPosition> {
        self.read_checked("admin_outbox_head", Some(deadline), |c, _| {
            let row = c
                .query_row(
                    "SELECT rowid, event_id FROM events ORDER BY rowid DESC LIMIT 1",
                    [],
                    |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)),
                )
                .optional()?;
            Ok(match row {
                Some((row, id)) => OutboxPosition {
                    row,
                    event_id: Some(id),
                },
                None => OutboxPosition {
                    row: 0,
                    event_id: None,
                },
            })
        })
        .await
    }

    /// Up to `limit` status changes after `after`, examining at most
    /// [`FEED_SCAN`] outbox rows. `Err(PositionLost)` when `after` names a
    /// row the outbox no longer holds with that id.
    #[cfg(test)]
    pub(crate) async fn admin_status_changes(
        &self,
        after: OutboxPosition,
        limit: usize,
        deadline: Deadline,
    ) -> StoreResult<Result<StatusPage, PositionLost>> {
        self.admin_feed_changes(after, limit, false, deadline).await
    }

    /// As [`Store::admin_status_changes`], also reporting the `group.*`
    /// outbox events when `groups` is set (ADR-0019).
    pub(crate) async fn admin_feed_changes(
        &self,
        after: OutboxPosition,
        limit: usize,
        groups: bool,
        deadline: Deadline,
    ) -> StoreResult<Result<StatusPage, PositionLost>> {
        let limit = limit.min(MAX_BATCH);
        self.read_checked("admin_status_changes", Some(deadline), move |c, check| {
            if after.row < 0 {
                return Ok(Err(PositionLost));
            }
            if after.row > 0 {
                let id: Option<String> = c
                    .query_row(
                        "SELECT event_id FROM events WHERE rowid = ?1",
                        [after.row],
                        |r| r.get(0),
                    )
                    .optional()?;
                if id.is_none() || id != after.event_id {
                    return Ok(Err(PositionLost));
                }
            } else if after.event_id.is_some() {
                return Ok(Err(PositionLost));
            }
            let head: i64 =
                c.query_row("SELECT COALESCE(MAX(rowid), 0) FROM events", [], |r| r.get(0))?;
            let mut st = c.prepare_cached(
                "SELECT rowid, event_id, at, kind, user_id, json_extract(attrs, '$.group_id') FROM events WHERE rowid > ?1 ORDER BY rowid LIMIT ?2",
            )?;
            let mut q = st.query(params![after.row, FEED_SCAN])?;
            let mut changes = Vec::new();
            let mut next = after.clone();
            let mut examined = 0usize;
            while let Some(r) = q.next()? {
                examined += 1;
                if examined.is_multiple_of(1024) {
                    check.now()?;
                }
                let (row, id, at, kind, user, group): (
                    i64,
                    String,
                    f64,
                    String,
                    Option<String>,
                    Option<String>,
                ) = (
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5).unwrap_or(None),
                );
                let change = match kind.as_str() {
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
                };
                let wanted = match change {
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
                        group_id: group.filter(|_| change != "disabled" && change != "enabled"),
                    });
                }
                next = OutboxPosition {
                    row,
                    event_id: Some(id),
                };
            }
            Ok(Ok(StatusPage {
                changes,
                next,
                head,
            }))
        })
        .await
    }

    /// The newest live handle of a session on a host (read-only; the explain
    /// API never sees a handle value, only the row the gateway would find).
    pub(crate) async fn admin_live_handle(
        &self,
        session: String,
        host: String,
        deadline: Deadline,
    ) -> StoreResult<Option<HandleRow>> {
        self.read_checked("admin_live_handle", Some(deadline), move |c, _| {
            let sql = format!(
                "SELECT {} FROM session_handles WHERE session_id = ?1 AND host = ?2 AND revoked_at IS NULL ORDER BY created_at DESC LIMIT 1",
                cols("", HANDLE_COLS)
            );
            c.query_row(&sql, params![session, host], |r| Ok(rows::handle(r, 0)))
                .optional()?
                .transpose()
        })
        .await
    }

    /// Whether the user holds an active TOTP enrollment.
    pub(crate) async fn admin_totp_active(
        &self,
        user: String,
        deadline: Deadline,
    ) -> StoreResult<bool> {
        self.read_checked("admin_totp_active", Some(deadline), move |c, _| {
            Ok(c.query_row(
                "SELECT EXISTS(SELECT 1 FROM totp_enrollments WHERE user_id = ?1 AND state = 'active')",
                [user],
                |r| r.get(0),
            )?)
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{TestClock, Timestamp};
    use std::sync::Arc;
    use std::time::Duration;

    const T0: i64 = 1_700_000_000_000;

    fn store() -> (Store, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let clock = Arc::new(TestClock::new(Timestamp(T0)));
        let store = Store::open(&dir.path().join("hopae.db"), clock, vec![], None).unwrap();
        (store, dir)
    }

    fn dl() -> Deadline {
        Deadline(std::time::Instant::now() + Duration::from_secs(5))
    }

    fn add_user(s: &Store, id: &str, status: &str) {
        s.conn()
            .execute(
                "INSERT INTO users(user_id,primary_email,display_name,status,created_at,updated_at) VALUES(?1,?1||'@example.test','Name '||?1,?2,100,100)",
                params![id, status],
            )
            .unwrap();
    }

    fn add_event(s: &Store, id: &str, kind: &str, user: &str) {
        s.conn()
            .execute(
                "INSERT INTO events(event_id,at,kind,outcome,user_id,request_id) VALUES(?1,200.5,?2,'success',?3,'r_t')",
                params![id, kind, user],
            )
            .unwrap();
    }

    #[tokio::test]
    async fn rows_distinguish_live_tombstoned_and_unknown_ids() {
        let (s, _d) = store();
        add_user(&s, "u_live", "active");
        add_user(&s, "u_gone", "disabled");
        s.conn()
            .execute(
                "INSERT INTO identities(provider_id,subject,user_id,first_seen_at,last_seen_at) VALUES('mock','sub','u_live',1,1)",
                [],
            )
            .unwrap();
        s.conn()
            .execute("DELETE FROM users WHERE user_id='u_gone'", [])
            .unwrap();
        let rows = s
            .admin_directory_rows(
                vec!["u_live".into(), "u_gone".into(), "u_never".into()],
                dl(),
            )
            .await
            .unwrap();
        assert_eq!(rows.len(), 2);
        assert!(rows["u_live"].user.is_some() && rows["u_live"].ledger.is_some());
        assert_eq!(rows["u_live"].providers, vec!["mock".to_string()]);
        assert!(rows["u_gone"].user.is_none() && rows["u_gone"].ledger.is_some());
        assert!(
            s.admin_directory_rows(vec!["u".into(); MAX_BATCH + 1], dl())
                .await
                .is_err()
        );
        let ledger = s.admin_ledger_after(0, 10, dl()).await.unwrap();
        assert_eq!(
            ledger
                .iter()
                .map(|r| (r.user_id.as_str(), r.status.as_deref()))
                .collect::<Vec<_>>(),
            vec![("u_live", Some("active")), ("u_gone", None)]
        );
        assert_eq!(s.admin_ledger_head(dl()).await.unwrap(), ledger[1].position);
        let at = s
            .admin_ledger_at(vec![ledger[1].position], dl())
            .await
            .unwrap();
        assert_eq!(at[&ledger[1].position], "u_gone");
        let realm = s.admin_human_realm(dl()).await.unwrap().unwrap();
        assert_eq!(
            human_subject("owned", &realm, "u_gone").unwrap(),
            super::super::human_subject::derive("owned", &realm, "u_gone").unwrap()
        );
    }

    #[tokio::test]
    async fn status_stream_pages_and_detects_lost_positions() {
        let (s, _d) = store();
        add_user(&s, "u_a", "active");
        add_event(&s, "e_1", "admin.user_disable", "u_a");
        add_event(&s, "e_2", "login.succeeded", "u_a");
        add_event(&s, "e_3", "admin.user_enable", "u_a");
        let start = OutboxPosition {
            row: 0,
            event_id: None,
        };
        let page = s
            .admin_status_changes(start.clone(), 1, dl())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(page.changes.len(), 1);
        assert_eq!(page.changes[0].change, "disabled");
        assert_eq!(page.changes[0].at, 200);
        let page2 = s
            .admin_status_changes(page.next.clone(), 10, dl())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            page2.changes.iter().map(|c| c.change).collect::<Vec<_>>(),
            vec!["enabled"]
        );
        assert_eq!(page2.next.row, page2.head);
        let done = s
            .admin_status_changes(page2.next.clone(), 10, dl())
            .await
            .unwrap()
            .unwrap();
        assert!(done.changes.is_empty() && done.next == page2.next);
        // A forged id, a pruned row and a negative row are all lost positions.
        let forged = OutboxPosition {
            row: page.next.row,
            event_id: Some("e_other".into()),
        };
        assert!(
            s.admin_status_changes(forged, 1, dl())
                .await
                .unwrap()
                .is_err()
        );
        // The first page stopped after the row following `e_1` (a login).
        assert_eq!(page.next.event_id.as_deref(), Some("e_2"));
        s.conn()
            .execute("DELETE FROM events WHERE event_id='e_2'", [])
            .unwrap();
        assert!(
            s.admin_status_changes(page.next.clone(), 1, dl())
                .await
                .unwrap()
                .is_err()
        );
        let negative = OutboxPosition {
            row: -1,
            event_id: None,
        };
        assert!(
            s.admin_status_changes(negative, 1, dl())
                .await
                .unwrap()
                .is_err()
        );
        let head = s.admin_outbox_head(dl()).await.unwrap();
        assert_eq!(head.event_id.as_deref(), Some("e_3"));
    }
}
