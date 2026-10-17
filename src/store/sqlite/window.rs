//! Bounded, interruptible console listings (ADR-0016, F4, P2-03, P2-04).
//!
//! Every listing runs on a read connection inside one deferred transaction as
//! three statements: the candidate window is materialized in a temp table by a
//! statement pinned to one index (`INDEXED BY`, so a planner regression is a
//! hard error), the window's own metadata is read independently of the
//! matches, and the matches are filtered out of the window. A first page and a
//! cursor page use different window statements; the cursor page always seeks
//! on the index's two trailing columns with a row-value comparison.

use std::collections::HashMap;

use rusqlite::types::Value;
use rusqlite::{Connection, OptionalExtension, Row, params};

use super::rows::{self, EVENT_COLS, HANDLE_COLS, IDENTITY_COLS, SESSION_COLS, USER_COLS, cols};
use super::sessions::session_by_id;
use super::{Check, Store};
use crate::crypto::Timestamp;
use crate::event::types::Event;
use crate::identity::types::{NormalizedEmail, UserId};
use crate::policy::types::Host;
use crate::session::types::SessionId;
use crate::store::StoreResult;
use crate::store::types::*;

/// Rows a listing may return at most, whatever the caller asks.
const MAX_LIMIT: usize = 1000;

/// Which listing, hence which window statement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shape {
    Events(EventsIndex),
    Sessions { by_user: bool },
    Users,
}

/// The columns the window keeps: the keys and what the residual filters on.
/// Whole rows are fetched by primary key for the page only, so the work per
/// candidate stays small however wide the table is.
fn window_cols(shape: Shape) -> &'static str {
    match shape {
        Shape::Events(_) => {
            "e.event_id, e.at, e.kind, e.outcome, e.user_id, e.session_id, e.client_ip"
        }
        Shape::Sessions { .. } => "e.session_id, e.created_at, e.absolute_expires_at, e.aal",
        Shape::Users => {
            "e.user_id, e.created_at, e.primary_email, e.username, e.display_name, e.status"
        }
    }
}

/// The statement that materializes the window (`CREATE TEMP TABLE w AS …`).
/// `cursor` selects the cursor-page form. Parameter names are the ones
/// [`Params`] carries; a statement binds only those it mentions.
pub fn window_sql(shape: Shape, cursor: bool) -> String {
    let w = CANDIDATE_WINDOW;
    match shape {
        Shape::Events(index) => {
            let pred = match (index, cursor) {
                (EventsIndex::Session, _) => "e.session_id = :session".to_string(),
                (EventsIndex::User, _) => "e.user_id = :user".to_string(),
                (EventsIndex::Ip, _) => "e.client_ip = :ip".to_string(),
                (EventsIndex::Kind, _) => "e.kind = :kind".to_string(),
                (EventsIndex::Time, false) => "e.at >= :since_w AND e.at <= :until_w".to_string(),
                (EventsIndex::Time, true) => "e.at >= :since_w".to_string(),
            };
            let seek = if cursor {
                " AND (e.at, e.event_id) < (:c_at, :c_id)"
            } else {
                ""
            };
            format!(
                "CREATE TEMP TABLE w AS SELECT {} FROM events e INDEXED BY {} WHERE {pred}{seek} ORDER BY e.at DESC, e.event_id DESC LIMIT {w}",
                window_cols(shape),
                index.index_name()
            )
        }
        Shape::Sessions { by_user } => {
            let (index, pred) = if by_user {
                (
                    "sessions_live_user_created",
                    "e.user_id = :user AND e.terminated_at IS NULL",
                )
            } else {
                ("sessions_live_created", "e.terminated_at IS NULL")
            };
            let seek = if cursor {
                " AND (e.created_at, e.session_id) < (:c_at, :c_id)"
            } else if by_user {
                ""
            } else {
                " AND e.created_at <= :max_w"
            };
            format!(
                "CREATE TEMP TABLE w AS SELECT {} FROM sessions e INDEXED BY {index} WHERE {pred}{seek} ORDER BY e.created_at DESC, e.session_id DESC LIMIT {w}",
                window_cols(shape)
            )
        }
        Shape::Users => {
            let seek = if cursor {
                "(e.created_at, e.user_id) < (:c_at, :c_id)"
            } else {
                "e.created_at <= :max_w"
            };
            format!(
                "CREATE TEMP TABLE w AS SELECT {} FROM users e INDEXED BY users_created_id WHERE {seek} ORDER BY e.created_at DESC, e.user_id DESC LIMIT {w}",
                window_cols(shape)
            )
        }
    }
}

/// The window's own metadata (independent of the matches): row count, and the
/// oldest row's key columns. The window is filled newest first, so the oldest
/// row is the one inserted last.
fn meta_sql(shape: Shape) -> String {
    let (a, b) = match shape {
        Shape::Events(_) => ("at", "event_id"),
        Shape::Sessions { .. } => ("created_at", "session_id"),
        Shape::Users => ("created_at", "user_id"),
    };
    format!(
        "SELECT COUNT(*), (SELECT {a} FROM w ORDER BY rowid DESC LIMIT 1), (SELECT {b} FROM w ORDER BY rowid DESC LIMIT 1) FROM w"
    )
}

/// The matches: the residual predicate over the window picks at most
/// `limit + 1` keys, newest first; the page's rows are read by primary key.
fn match_sql(shape: Shape) -> String {
    match shape {
        Shape::Events(_) => format!(
            "SELECT {cols} FROM events ev WHERE ev.event_id IN (SELECT event_id FROM w WHERE (:user IS NULL OR user_id = :user) AND (:kind IS NULL OR kind = :kind) AND (:outcome IS NULL OR outcome = :outcome) AND (:session IS NULL OR session_id = :session) AND (:ip IS NULL OR client_ip = :ip) AND (:since IS NULL OR at >= :since) AND (:until IS NULL OR at <= :until) AND (:kind_prefix IS NULL OR substr(kind, 1, length(:kind_prefix)) = :kind_prefix) ORDER BY at DESC, event_id DESC LIMIT :limit_plus) ORDER BY ev.at DESC, ev.event_id DESC",
            cols = cols("ev", EVENT_COLS)
        ),
        Shape::Sessions { .. } => format!(
            "SELECT {cols} FROM sessions s WHERE s.session_id IN (SELECT session_id FROM w WHERE absolute_expires_at > :now AND (:aal IS NULL OR aal = :aal) ORDER BY created_at DESC, session_id DESC LIMIT :limit_plus) ORDER BY s.created_at DESC, s.session_id DESC",
            cols = cols("s", SESSION_COLS)
        ),
        Shape::Users => format!(
            "SELECT {cols} FROM users u WHERE u.user_id IN (SELECT user_id FROM w WHERE (:q IS NULL OR primary_email LIKE :q || '%' ESCAPE '\\' OR username LIKE :q || '%' ESCAPE '\\' OR lower(display_name) LIKE '%' || lower(:q) || '%' ESCAPE '\\') AND (:status IS NULL OR status = :status) AND (:provider IS NULL OR EXISTS (SELECT 1 FROM identities i WHERE i.user_id = w.user_id AND i.provider_id = :provider)) AND (:mfa IS NULL OR :mfa = (EXISTS (SELECT 1 FROM webauthn_credentials c WHERE c.user_id = w.user_id AND c.state = 'active') OR EXISTS (SELECT 1 FROM totp_enrollments t WHERE t.user_id = w.user_id AND t.state = 'active'))) AND (:grp IS NULL OR EXISTS (SELECT 1 FROM group_members gm JOIN directory_groups g ON g.group_id = gm.group_id WHERE gm.group_id = :grp AND gm.user_id = w.user_id AND g.state = 'active' AND gm.stale_at IS NULL AND (gm.expires_at IS NULL OR gm.expires_at > :now))) ORDER BY created_at DESC, user_id DESC LIMIT :limit_plus) ORDER BY u.created_at DESC, u.user_id DESC",
            cols = cols("u", USER_COLS)
        ),
    }
}

/// Named parameters shared by the three statements.
#[derive(Default)]
pub(crate) struct Params(Vec<(&'static str, Value)>);

impl Params {
    fn set(&mut self, name: &'static str, v: Value) {
        self.0.push((name, v));
    }

    /// Bind every parameter the statement mentions, ignore the rest.
    fn bind(&self, stmt: &mut rusqlite::Statement<'_>) -> rusqlite::Result<()> {
        for (name, v) in &self.0 {
            let full = format!(":{name}");
            if let Some(i) = stmt.parameter_index(&full)? {
                stmt.raw_bind_parameter(i, v)?;
            }
        }
        Ok(())
    }
}

/// `(rows, window row count, oldest row key)` of one listing.
pub(crate) struct Windowed<T> {
    pub rows: Vec<(T, i64, String)>,
    pub examined: u32,
    pub oldest: Option<(i64, String)>,
}

fn key_ms(v: f64) -> i64 {
    (v * 1000.0).round() as i64
}

/// Run the three statements; `map` decodes one match into `(item, key, id)`.
pub(crate) fn run_window<T>(
    conn: &Connection,
    check: &Check,
    shape: Shape,
    cursor: bool,
    params: &Params,
    limit: usize,
    mut map: impl FnMut(&Row<'_>) -> StoreResult<(T, i64, String)>,
) -> StoreResult<Windowed<T>> {
    let tx = conn.unchecked_transaction()?;
    tx.execute_batch("DROP TABLE IF EXISTS temp.w")?;
    check.now()?;
    {
        let mut st = tx.prepare(&window_sql(shape, cursor))?;
        params.bind(&mut st)?;
        st.raw_execute()?;
    }
    check.now()?;
    let (count, oldest) = {
        let mut st = tx.prepare(&meta_sql(shape))?;
        st.query_row([], |r| {
            let n: i64 = r.get(0)?;
            let k: Option<f64> = r.get(1)?;
            let id: Option<String> = r.get(2)?;
            Ok((n, k.zip(id).map(|(k, id)| (key_ms(k), id))))
        })?
    };
    check.now()?;
    let mut rows_out = Vec::new();
    {
        let mut st = tx.prepare(&match_sql(shape))?;
        let mut p = Params(params.0.iter().map(|(n, v)| (*n, v.clone())).collect());
        p.set(
            "limit_plus",
            Value::Integer(i64::try_from(limit.saturating_add(1)).unwrap_or(i64::MAX)),
        );
        p.bind(&mut st)?;
        let mut q = st.raw_query();
        while let Some(r) = q.next()? {
            rows_out.push(map(r)?);
        }
    }
    tx.execute_batch("DROP TABLE w")?;
    tx.commit()?;
    Ok(Windowed {
        rows: rows_out,
        examined: u32::try_from(count).unwrap_or(u32::MAX),
        oldest,
    })
}

/// Apply the cursor rule: more matches than `limit` ⇒ resume after the last
/// returned row; else a full window ⇒ resume after the window's oldest row;
/// else the listing is complete.
pub(crate) fn finish_page<T>(w: Windowed<T>, limit: usize) -> Page<T> {
    let Windowed {
        mut rows,
        examined,
        oldest,
    } = w;
    let next = if rows.len() > limit {
        rows.truncate(limit);
        rows.last().map(|(_, k, id)| Cursor {
            key: *k,
            id: id.clone(),
        })
    } else if examined == CANDIDATE_WINDOW {
        oldest.map(|(key, id)| Cursor { key, id })
    } else {
        None
    };
    Page {
        items: rows.into_iter().map(|(t, _, _)| t).collect(),
        next,
        examined,
    }
}

fn clamp_limit(limit: usize) -> usize {
    limit.clamp(1, MAX_LIMIT)
}

/// LIKE needs `%`, `_` and `\` escaped by the caller; an empty query is none.
fn q_value(q: &Option<String>) -> Value {
    match q {
        Some(s) if !s.is_empty() => Value::Text(s.clone()),
        _ => Value::Null,
    }
}

fn opt_text(v: Option<String>) -> Value {
    v.map_or(Value::Null, Value::Text)
}

/// A cursor key (ms) as the bound value for a table whose key column holds seconds.
fn secs_param(c: &Cursor) -> Value {
    Value::Integer(c.key.div_euclid(1000))
}

/// A cursor key (ms) as the bound value for `events.at` (seconds with a ms fraction).
fn real_param(c: &Cursor) -> Value {
    Value::Real(c.key as f64 / 1000.0)
}

/// Summary of one session: the owner's address, the hosts of its unrevoked handles.
fn summarize(conn: &Connection, session: SessionRow) -> StoreResult<SessionSummary> {
    let email: Option<Option<String>> = conn
        .query_row(
            "SELECT primary_email FROM users WHERE user_id = ?1",
            [session.user_id.as_str()],
            |r| r.get(0),
        )
        .optional()?;
    let primary_email = match email.flatten() {
        Some(s) => Some(
            NormalizedEmail::from_stored(&s).ok_or_else(|| rows::corrupt("users.primary_email"))?,
        ),
        None => None,
    };
    let mut st = conn.prepare(
        "SELECT DISTINCT host FROM session_handles WHERE session_id = ?1 AND revoked_at IS NULL ORDER BY host LIMIT 100",
    )?;
    let mut hosts = Vec::new();
    let mut q = st.query([session.session_id.as_str()])?;
    while let Some(r) = q.next()? {
        let h: String = r.get(0)?;
        hosts.push(Host::parse(&h).map_err(|_| rows::corrupt("session_handles.host"))?);
    }
    Ok(SessionSummary {
        ua_prefix: session.bound_ua_prefix.clone(),
        session,
        primary_email,
        hosts,
    })
}

impl Store {
    pub(super) async fn list_users_impl(
        &self,
        q: UsersQuery,
        deadline: Deadline,
    ) -> StoreResult<Page<UserSummary>> {
        let limit = clamp_limit(q.limit);
        let clock = self.shared().clock.clone();
        self.read_checked("list_users", Some(deadline), move |c, check| {
            let mut p = Params::default();
            p.set("q", q_value(&q.q));
            p.set(
                "status",
                q.status
                    .map_or(Value::Null, |s| Value::Text(s.as_str().into())),
            );
            p.set("provider", opt_text(q.filters.provider.clone()));
            p.set(
                "mfa",
                q.filters
                    .mfa_enrolled
                    .map_or(Value::Null, |b| Value::Integer(i64::from(b))),
            );
            p.set("grp", opt_text(q.filters.group.clone()));
            p.set("now", Value::Integer(clock.now().secs()));
            match &q.cursor {
                Some(cur) => {
                    p.set("c_at", secs_param(cur));
                    p.set("c_id", Value::Text(cur.id.clone()));
                }
                None => p.set("max_w", Value::Integer(i64::MAX)),
            }
            let now = clock.now().secs();
            let w = run_window(c, check, Shape::Users, q.cursor.is_some(), &p, limit, |r| {
                let u = rows::user(r, 0)?;
                let key = u.created_at.secs().saturating_mul(1000);
                let id = u.user_id.to_string();
                Ok((u, key, id))
            })?;
            let mut page = finish_page(w, limit);
            let items = std::mem::take(&mut page.items);
            let mut out = Vec::with_capacity(items.len());
            for user in items {
                check.now()?;
                let live: i64 = c.query_row(
                    "SELECT COUNT(*) FROM sessions WHERE user_id = ?1 AND terminated_at IS NULL AND absolute_expires_at > ?2",
                    params![user.user_id.as_str(), now],
                    |r| r.get(0),
                )?;
                let role: Option<String> = c
                    .query_row(
                        "SELECT role FROM admin_grants WHERE user_id = ?1 AND revoked_at IS NULL",
                        [user.user_id.as_str()],
                        |r| r.get(0),
                    )
                    .optional()?;
                out.push(UserSummary {
                    user,
                    live_sessions: u32::try_from(live).unwrap_or(u32::MAX),
                    role: role.as_deref().and_then(AdminRole::parse),
                });
            }
            Ok(Page {
                items: out,
                next: page.next,
                examined: page.examined,
            })
        })
        .await
    }

    pub(super) async fn user_detail_impl(
        &self,
        user: &UserId,
        now: Timestamp,
        deadline: Deadline,
    ) -> StoreResult<Option<UserDetail>> {
        let id = user.clone();
        self.read_checked("user_detail", Some(deadline), move |c, check| {
            let sql = format!("SELECT {} FROM users WHERE user_id = ?1", cols("", USER_COLS));
            let Some(user) = c
                .query_row(&sql, [id.as_str()], |r| Ok(rows::user(r, 0)))
                .optional()?
                .transpose()?
            else {
                return Ok(None);
            };
            check.now()?;
            let identities = {
                let sql = format!(
                    "SELECT {} FROM identities WHERE user_id = ?1 ORDER BY first_seen_at, provider_id, subject LIMIT 50",
                    cols("", IDENTITY_COLS)
                );
                let mut st = c.prepare(&sql)?;
                let mut q = st.query([id.as_str()])?;
                let mut v = Vec::new();
                while let Some(r) = q.next()? {
                    v.push(rows::identity(r, 0)?);
                }
                v
            };
            check.now()?;
            let session_cols = cols("", SESSION_COLS);
            let live_pred = "user_id = ?1 AND terminated_at IS NULL AND absolute_expires_at > ?2";
            let total: i64 = c.query_row(
                &format!("SELECT COUNT(*) FROM sessions WHERE {live_pred}"),
                params![id.as_str(), now.secs()],
                |r| r.get(0),
            )?;
            let live_rows = {
                let mut st = c.prepare(&format!(
                    "SELECT {session_cols} FROM sessions WHERE {live_pred} ORDER BY created_at DESC, session_id DESC LIMIT 20"
                ))?;
                let mut q = st.query(params![id.as_str(), now.secs()])?;
                let mut v = Vec::new();
                while let Some(r) = q.next()? {
                    v.push(rows::session(r, 0)?);
                }
                v
            };
            let terminated_rows = {
                let mut st = c.prepare(&format!(
                    "SELECT {session_cols} FROM sessions WHERE user_id = ?1 AND terminated_at IS NOT NULL ORDER BY terminated_at DESC, session_id DESC LIMIT 20"
                ))?;
                let mut q = st.query([id.as_str()])?;
                let mut v = Vec::new();
                while let Some(r) = q.next()? {
                    v.push(rows::session(r, 0)?);
                }
                v
            };
            let mut sessions_live = Vec::new();
            for s in live_rows {
                check.now()?;
                sessions_live.push(summarize(c, s)?);
            }
            let mut sessions_terminated = Vec::new();
            for s in terminated_rows {
                check.now()?;
                sessions_terminated.push(summarize(c, s)?);
            }
            let grant = super::admin::grant_row(c, id.as_str())?;
            Ok(Some(UserDetail {
                user,
                identities,
                sessions_live,
                sessions_live_total: u32::try_from(total).unwrap_or(u32::MAX),
                sessions_terminated,
                grant,
            }))
        })
        .await
    }

    pub(super) async fn list_live_sessions_impl(
        &self,
        q: SessionsQuery,
        deadline: Deadline,
    ) -> StoreResult<Page<SessionSummary>> {
        let limit = clamp_limit(q.limit);
        self.read_checked("list_live_sessions", Some(deadline), move |c, check| {
            let by_user = q.user_id.is_some();
            let mut p = Params::default();
            p.set("now", Value::Integer(q.now.secs()));
            p.set(
                "aal",
                q.aal.map_or(Value::Null, |a| Value::Integer(a.as_i64())),
            );
            if let Some(u) = &q.user_id {
                p.set("user", Value::Text(u.to_string()));
            }
            match &q.cursor {
                Some(cur) => {
                    p.set("c_at", secs_param(cur));
                    p.set("c_id", Value::Text(cur.id.clone()));
                }
                None => p.set("max_w", Value::Integer(i64::MAX)),
            }
            let w = run_window(
                c,
                check,
                Shape::Sessions { by_user },
                q.cursor.is_some(),
                &p,
                limit,
                |r| {
                    let s = rows::session(r, 0)?;
                    let key = s.created_at.secs().saturating_mul(1000);
                    let id = s.session_id.to_string();
                    Ok((s, key, id))
                },
            )?;
            let mut page = finish_page(w, limit);
            let items = std::mem::take(&mut page.items);
            let mut out = Vec::with_capacity(items.len());
            for s in items {
                check.now()?;
                out.push(summarize(c, s)?);
            }
            Ok(Page {
                items: out,
                next: page.next,
                examined: page.examined,
            })
        })
        .await
    }

    pub(super) async fn session_summary_impl(
        &self,
        id: &SessionId,
        deadline: Deadline,
    ) -> StoreResult<Option<(SessionSummary, Vec<HandleRow>)>> {
        let id = id.clone();
        self.read_checked("session_summary", Some(deadline), move |c, check| {
            let Some(session) = session_by_id(c, &id)? else {
                return Ok(None);
            };
            check.now()?;
            let handles = {
                let sql = format!(
                    "SELECT {} FROM session_handles WHERE session_id = ?1 ORDER BY created_at DESC, handle_sha256 LIMIT 100",
                    cols("", HANDLE_COLS)
                );
                let mut st = c.prepare(&sql)?;
                let mut q = st.query([id.as_str()])?;
                let mut v = Vec::new();
                while let Some(r) = q.next()? {
                    v.push(rows::handle(r, 0)?);
                }
                v
            };
            Ok(Some((summarize(c, session)?, handles)))
        })
        .await
    }

    pub(super) async fn query_page_impl(
        &self,
        q: EventsQuery,
        deadline: Deadline,
    ) -> StoreResult<Page<Event>> {
        let limit = clamp_limit(q.limit);
        self.read_checked("query_events_page", Some(deadline), move |c, check| {
            let index = q.index();
            let mut p = Params::default();
            p.set("user", opt_text(q.user_id.as_ref().map(|v| v.to_string())));
            p.set("kind", opt_text(q.kind.map(|k| k.name().to_string())));
            p.set(
                "outcome",
                opt_text(q.outcome.map(|o| o.as_str().to_string())),
            );
            p.set(
                "session",
                opt_text(q.session_id.as_ref().map(|v| v.to_string())),
            );
            p.set("ip", opt_text(q.client_ip.map(|v| v.to_string())));
            p.set("kind_prefix", opt_text(q.kind_prefix.clone()));
            let secs =
                |t: Option<Timestamp>| t.map_or(Value::Null, |t| Value::Real(t.0 as f64 / 1000.0));
            p.set("since", secs(q.since));
            p.set("until", secs(q.until));
            p.set(
                "since_w",
                Value::Real(q.since.map_or(f64::MIN, |t| t.0 as f64 / 1000.0)),
            );
            p.set(
                "until_w",
                Value::Real(q.until.map_or(f64::MAX, |t| t.0 as f64 / 1000.0)),
            );
            if let Some(cur) = &q.cursor {
                p.set("c_at", real_param(cur));
                p.set("c_id", Value::Text(cur.id.clone()));
            }
            let w = run_window(
                c,
                check,
                Shape::Events(index),
                q.cursor.is_some(),
                &p,
                limit,
                |r| {
                    let e = rows::event(r, 0)?;
                    let key = e.at.0;
                    let id = e.event_id.to_string();
                    Ok((e, key, id))
                },
            )?;
            Ok(finish_page(w, limit))
        })
        .await
    }

    pub(super) async fn status_impl(&self, deadline: Deadline) -> StoreResult<StoreStatus> {
        let clock = self.shared().clock.clone();
        self.read_checked("store_status", Some(deadline), move |c, check| {
            let now = clock.now().secs();
            let count = |sql: &str, p: &[&dyn rusqlite::ToSql]| -> StoreResult<u64> {
                check.now()?;
                let n: i64 = c.query_row(sql, p, |r| r.get(0))?;
                Ok(u64::try_from(n).unwrap_or(0))
            };
            let users = count("SELECT COUNT(*) FROM users", &[])?;
            let events = count("SELECT COUNT(*) FROM events", &[])?;
            let live_sessions = count(
                "SELECT COUNT(*) FROM sessions WHERE terminated_at IS NULL AND absolute_expires_at > ?1",
                &[&now],
            )?;
            let mut per_sink: HashMap<String, (u64, u64)> = HashMap::new();
            {
                let mut st = c.prepare(
                    "SELECT sink, state, COUNT(*) FROM event_deliveries WHERE state IN ('pending','failed') GROUP BY sink, state",
                )?;
                let mut q = st.query([])?;
                while let Some(r) = q.next()? {
                    let (sink, state, n): (String, String, i64) = (r.get(0)?, r.get(1)?, r.get(2)?);
                    let e = per_sink.entry(sink).or_default();
                    let n = u64::try_from(n).unwrap_or(0);
                    if state == "pending" {
                        e.0 = n;
                    } else {
                        e.1 = n;
                    }
                }
            }
            let mut deliveries: Vec<(String, u64, u64)> = per_sink
                .into_iter()
                .map(|(s, (p, f))| (s, p, f))
                .collect();
            deliveries.sort();
            let last_prune: Option<String> = c
                .query_row("SELECT value FROM meta WHERE key = 'last_prune_at'", [], |r| {
                    r.get(0)
                })
                .optional()?;
            let schema_version: Option<u32> =
                c.query_row("SELECT MAX(version) FROM schema_migrations", [], |r| r.get(0))?;
            let projection_changes = count("SELECT COUNT(*) FROM group_changes", &[])?;
            let lifecycle_ledger_head =
                count("SELECT COALESCE(MAX(rowid), 0) FROM human_user_ids", &[])?;
            let outbox_head = count("SELECT COALESCE(MAX(rowid), 0) FROM events", &[])?;
            let workload_principals = count("SELECT COUNT(*) FROM workload_principals", &[])?;
            Ok(StoreStatus {
                schema_version: schema_version.unwrap_or(0),
                users,
                live_sessions,
                events,
                deliveries,
                last_prune_at: last_prune
                    .and_then(|s| s.parse::<i64>().ok())
                    .map(Timestamp::from_secs),
                projection_changes,
                lifecycle_ledger_head,
                outbox_head,
                workload_principals,
            })
        })
        .await
    }
}

impl Store {
    /// Test support (`GET /explain`): the plan of a listing's window statement
    /// and, with `stats`, the work running it took. `cursor` is `(key, id)`.
    pub fn explain_window(
        &self,
        shape: Shape,
        cursor: Option<(i64, String)>,
        stats: bool,
    ) -> StoreResult<serde_json::Value> {
        use rusqlite::StatementStatus;
        let conn = self.conn();
        let is_cursor = cursor.is_some();
        let sql = window_sql(shape, is_cursor);
        let select = sql.strip_prefix("CREATE TEMP TABLE w AS ").unwrap_or(&sql);
        let bind = |st: &mut rusqlite::Statement<'_>| -> rusqlite::Result<()> {
            let events = matches!(shape, Shape::Events(_));
            let (key, id) = cursor.clone().unwrap_or((0, String::new()));
            let all: Vec<(&str, Value)> = vec![
                ("user", Value::Text(String::new())),
                ("session", Value::Text(String::new())),
                ("ip", Value::Text(String::new())),
                ("kind", Value::Text(String::new())),
                ("since_w", Value::Real(f64::MIN)),
                ("until_w", Value::Real(f64::MAX)),
                ("max_w", Value::Integer(i64::MAX)),
                (
                    "c_at",
                    if events {
                        Value::Real(key as f64 / 1000.0)
                    } else {
                        Value::Integer(key.div_euclid(1000))
                    },
                ),
                ("c_id", Value::Text(id)),
            ];
            for (n, v) in all {
                if let Some(i) = st.parameter_index(&format!(":{n}"))? {
                    st.raw_bind_parameter(i, v)?;
                }
            }
            Ok(())
        };
        let mut plan = Vec::new();
        {
            let mut st = conn.prepare(&format!("EXPLAIN QUERY PLAN {select}"))?;
            bind(&mut st)?;
            let mut q = st.raw_query();
            while let Some(r) = q.next()? {
                plan.push(r.get::<_, String>(3)?);
            }
        }
        let mut out = serde_json::json!({"statement": sql, "plan": plan});
        if stats {
            conn.execute_batch("DROP TABLE IF EXISTS temp.w")?;
            let mut st = conn.prepare(&sql)?;
            bind(&mut st)?;
            st.raw_execute()?;
            out["vm_step"] = st.get_status(StatementStatus::VmStep).into();
            out["fullscan_step"] = st.get_status(StatementStatus::FullscanStep).into();
            out["sort"] = st.get_status(StatementStatus::Sort).into();
            drop(st);
            conn.execute_batch("DROP TABLE IF EXISTS temp.w")?;
        }
        Ok(out)
    }
}
