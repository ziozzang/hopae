//! Slice 3 for PostgreSQL (ADR-0020): `Events` (the outbox relay — claim,
//! acknowledge, retry, prune — plus diagnostics, history and status) and
//! the bounded console listings (`ConsoleStore`, ADR-0016).
//!
//! Claims use `FOR UPDATE SKIP LOCKED` and a lease, so relays on several
//! replicas never hand out the same delivery at once and a dead relay's
//! claims come back after the lease (at-least-once, as on SQLite). Listings
//! run in one read-only `REPEATABLE READ` transaction: the candidate window
//! (at most [`CANDIDATE_WINDOW`] rows of one index range) is evaluated as a
//! CTE for its metadata and again for the matches, both on one snapshot.
use async_trait::async_trait;
use deadpool_postgres::Transaction;
use tokio_postgres::types::ToSql;

use super::admin::{check_deadline, deadline_err, deadline_ms};
use super::{
    EVENT_COLS, HANDLE_COLS, IDENTITY_COLS, PgStore, SESSION_COLS, USER_COLS, corrupt, event,
    handle, identity, pg, session, user,
};
use crate::crypto::Timestamp;
use crate::event::types::{Event, EventBuilder, EventId, EventKind, Outcome, reasons};
use crate::identity::types::{NormalizedEmail, UserId};
use crate::policy::types::Host;
use crate::session::types::SessionId;
use crate::store::core::ConsoleStore;
use crate::store::types::*;
use crate::store::{Deadline, Events, StoreError, StoreResult};

/// `pg_advisory_xact_lock` key ordering the subject lifecycle feed.
pub(super) const FEED_LOCK: i64 = 7041;
/// `pg_advisory_xact_lock` key serializing prune passes.
const PRUNE_LOCK: i64 = 7021;
/// How long a claimed delivery stays invisible to other claims.
const CLAIM_LEASE_SECS: i64 = 60;
/// Rows a listing may return at most, whatever the caller asks.
const MAX_LIMIT: usize = 1000;

/// Outbox kinds the subject lifecycle feed reports (positions in `outbox_feed`).
pub(super) fn in_feed(kind: EventKind) -> bool {
    let name = kind.name();
    matches!(name, "admin.user_disable" | "admin.user_enable") || name.starts_with("group.")
}

fn standalone(events: &[Event]) -> StoreResult<()> {
    for ev in events {
        if !ev.kind.is_required() {
            return Err(StoreError::Conflict(
                "diagnostic kinds use append_diagnostic",
            ));
        }
        if crate::store::sqlite::events::travels_with_state(ev.kind) {
            return Err(StoreError::Conflict(
                "this kind must travel with its state change",
            ));
        }
    }
    Ok(())
}

fn secs_f(t: Timestamp) -> f64 {
    t.0 as f64 / 1000.0
}

fn count(n: i64) -> u64 {
    u64::try_from(n).unwrap_or(0)
}

/// Positional parameters for SQL assembled in pieces.
#[derive(Default)]
struct Args(Vec<Box<dyn ToSql + Sync + Send>>);

impl Args {
    fn p(&mut self, v: impl ToSql + Sync + Send + 'static) -> String {
        self.0.push(Box::new(v));
        format!("${}", self.0.len())
    }
    fn refs(&self) -> Vec<&(dyn ToSql + Sync)> {
        self.0
            .iter()
            .map(|b| b.as_ref() as &(dyn ToSql + Sync))
            .collect()
    }
}

impl PgStore {
    /// One read-only snapshot whose statements stop at the deadline.
    pub(super) async fn read_within<'a>(
        &self,
        client: &'a mut deadpool_postgres::Object,
        deadline: Deadline,
    ) -> StoreResult<Transaction<'a>> {
        check_deadline(deadline)?;
        let tx = client
            .build_transaction()
            .isolation_level(tokio_postgres::IsolationLevel::RepeatableRead)
            .read_only(true)
            .start()
            .await
            .map_err(pg)?;
        let ms = deadline_ms(deadline).min(self.statement_timeout_ms);
        tx.batch_execute(&format!("SET LOCAL statement_timeout = {ms}"))
            .await
            .map_err(pg)?;
        Ok(tx)
    }
}

// ---- listing windows -------------------------------------------------------

#[derive(Clone, Copy)]
enum Shape {
    Events(EventsIndex),
    Sessions { by_user: bool },
    Users,
}

/// The window CTE (`w`), newest first, at most [`CANDIDATE_WINDOW`] rows.
fn window(shape: Shape, a: &mut Args, f: &Filters) -> String {
    let w = CANDIDATE_WINDOW;
    match shape {
        Shape::Events(index) => {
            let pred = match index {
                EventsIndex::Session => format!("e.session_id = {}", a.p(f.session.clone())),
                EventsIndex::User => format!("e.user_id = {}", a.p(f.user.clone())),
                EventsIndex::Ip => format!("e.client_ip = {}", a.p(f.ip.clone())),
                EventsIndex::Kind => format!("e.kind = {}", a.p(f.kind.clone())),
                EventsIndex::Time if f.cursor.is_some() => {
                    format!("e.at >= {}", a.p(f.since_w))
                }
                EventsIndex::Time => {
                    format!("e.at >= {} AND e.at <= {}", a.p(f.since_w), a.p(f.until_w))
                }
            };
            let seek = match &f.cursor {
                Some(c) => format!(
                    " AND (e.at, e.event_id) < ({}::float8, {}::text)",
                    a.p(c.key as f64 / 1000.0),
                    a.p(c.id.clone())
                ),
                None => String::new(),
            };
            format!(
                "w AS (SELECT e.event_id, e.at, e.kind, e.outcome, e.user_id, e.session_id, e.client_ip FROM events e \
                 WHERE {pred}{seek} ORDER BY e.at DESC, e.event_id DESC LIMIT {w})"
            )
        }
        Shape::Sessions { by_user } => {
            let pred = if by_user {
                format!(
                    "e.user_id = {} AND e.terminated_at IS NULL",
                    a.p(f.user.clone())
                )
            } else {
                "e.terminated_at IS NULL".to_string()
            };
            let seek = match &f.cursor {
                Some(c) => format!(
                    " AND (e.created_at, e.session_id) < ({}::bigint, {}::text)",
                    a.p(c.key.div_euclid(1000)),
                    a.p(c.id.clone())
                ),
                None => String::new(),
            };
            format!(
                "w AS (SELECT e.session_id, e.created_at, e.absolute_expires_at FROM sessions e \
                 WHERE {pred}{seek} ORDER BY e.created_at DESC, e.session_id DESC LIMIT {w})"
            )
        }
        Shape::Users => {
            let seek = match &f.cursor {
                Some(c) => format!(
                    "WHERE (e.created_at, e.user_id) < ({}::bigint, {}::text)",
                    a.p(c.key.div_euclid(1000)),
                    a.p(c.id.clone())
                ),
                None => String::new(),
            };
            format!(
                "w AS (SELECT e.user_id, e.created_at, e.primary_email, e.username, e.display_name, e.status FROM users e \
                 {seek} ORDER BY e.created_at DESC, e.user_id DESC LIMIT {w})"
            )
        }
    }
}

/// The window's metadata: row count and the oldest row's keys.
fn meta(shape: Shape) -> &'static str {
    match shape {
        Shape::Events(_) => {
            "SELECT count(*), (SELECT at FROM w ORDER BY at, event_id LIMIT 1)::float8, (SELECT event_id FROM w ORDER BY at, event_id LIMIT 1) FROM w"
        }
        Shape::Sessions { .. } => {
            "SELECT count(*), (SELECT created_at FROM w ORDER BY created_at, session_id LIMIT 1)::float8, (SELECT session_id FROM w ORDER BY created_at, session_id LIMIT 1) FROM w"
        }
        Shape::Users => {
            "SELECT count(*), (SELECT created_at FROM w ORDER BY created_at, user_id LIMIT 1)::float8, (SELECT user_id FROM w ORDER BY created_at, user_id LIMIT 1) FROM w"
        }
    }
}

/// The matches: the residual filter over the window, `limit + 1` keys.
fn matches(shape: Shape, a: &mut Args, f: &Filters, limit: usize) -> String {
    let n = a.p(i64::try_from(limit.saturating_add(1)).unwrap_or(i64::MAX));
    match shape {
        Shape::Events(_) => {
            let mut r = Vec::new();
            if let Some(v) = &f.user {
                r.push(format!("user_id = {}", a.p(v.clone())));
            }
            if let Some(v) = &f.kind {
                r.push(format!("kind = {}", a.p(v.clone())));
            }
            if let Some(v) = &f.outcome {
                r.push(format!("outcome = {}", a.p(v.clone())));
            }
            if let Some(v) = &f.session {
                r.push(format!("session_id = {}", a.p(v.clone())));
            }
            if let Some(v) = &f.ip {
                r.push(format!("client_ip = {}", a.p(v.clone())));
            }
            if let Some(v) = f.since {
                r.push(format!("at >= {}", a.p(v)));
            }
            if let Some(v) = f.until {
                r.push(format!("at <= {}", a.p(v)));
            }
            let pred = if r.is_empty() {
                "TRUE".into()
            } else {
                r.join(" AND ")
            };
            format!(
                "SELECT {EVENT_COLS} FROM events WHERE event_id IN (SELECT event_id FROM w WHERE {pred} ORDER BY at DESC, event_id DESC LIMIT {n}) ORDER BY at DESC, event_id DESC"
            )
        }
        Shape::Sessions { .. } => format!(
            "SELECT {SESSION_COLS} FROM sessions s WHERE s.session_id IN (SELECT session_id FROM w WHERE absolute_expires_at > {} ORDER BY created_at DESC, session_id DESC LIMIT {n}) ORDER BY s.created_at DESC, s.session_id DESC",
            a.p(f.now)
        ),
        Shape::Users => {
            let mut r = Vec::new();
            if let Some(q) = &f.q {
                let q = a.p(q.clone());
                // SQLite's LIKE ignores ASCII case; the caller escapes `%`, `_`, `\`.
                r.push(format!(
                    "(primary_email ILIKE {q} || '%' ESCAPE '\\' OR username ILIKE {q} || '%' ESCAPE '\\' OR lower(display_name) LIKE '%' || lower({q}) || '%' ESCAPE '\\')"
                ));
            }
            if let Some(s) = &f.status {
                r.push(format!("status = {}", a.p(s.clone())));
            }
            let pred = if r.is_empty() {
                "TRUE".into()
            } else {
                r.join(" AND ")
            };
            format!(
                "SELECT {USER_COLS} FROM users WHERE user_id IN (SELECT user_id FROM w WHERE {pred} ORDER BY created_at DESC, user_id DESC LIMIT {n}) ORDER BY created_at DESC, user_id DESC"
            )
        }
    }
}

#[derive(Default)]
struct Filters {
    cursor: Option<Cursor>,
    user: Option<String>,
    kind: Option<String>,
    outcome: Option<String>,
    session: Option<String>,
    ip: Option<String>,
    since: Option<f64>,
    until: Option<f64>,
    since_w: f64,
    until_w: f64,
    now: i64,
    q: Option<String>,
    status: Option<String>,
}

/// `(rows, examined, oldest key)`; a row is `(item, key ms, id)`.
async fn run_window<T>(
    tx: &Transaction<'_>,
    shape: Shape,
    f: &Filters,
    limit: usize,
    map: impl Fn(&tokio_postgres::Row) -> StoreResult<(T, i64, String)>,
) -> StoreResult<Page<T>> {
    let mut a = Args::default();
    let w = window(shape, &mut a, f);
    let r = tx
        .query_one(&format!("WITH {w} {}", meta(shape)), &a.refs())
        .await
        .map_err(pg)?;
    let examined = u32::try_from(r.get::<_, i64>(0)).unwrap_or(u32::MAX);
    let oldest = r
        .get::<_, Option<f64>>(1)
        .zip(r.get::<_, Option<String>>(2))
        .map(|(k, id)| {
            let key = match shape {
                Shape::Events(_) => (k * 1000.0).round() as i64,
                _ => (k as i64).saturating_mul(1000),
            };
            (key, id)
        });
    let mut a = Args::default();
    let w = window(shape, &mut a, f);
    let m = matches(shape, &mut a, f, limit);
    let rows = tx
        .query(&format!("WITH {w} {m}"), &a.refs())
        .await
        .map_err(pg)?;
    let mut items = rows.iter().map(&map).collect::<StoreResult<Vec<_>>>()?;
    let next = if items.len() > limit {
        items.truncate(limit);
        items.last().map(|(_, k, id)| Cursor {
            key: *k,
            id: id.clone(),
        })
    } else if examined == CANDIDATE_WINDOW {
        oldest.map(|(key, id)| Cursor { key, id })
    } else {
        None
    };
    Ok(Page {
        items: items.into_iter().map(|(t, _, _)| t).collect(),
        next,
        examined,
    })
}

fn clamp_limit(limit: usize) -> usize {
    limit.clamp(1, MAX_LIMIT)
}

/// The owner's address and the hosts of the session's unrevoked handles.
async fn summarize(tx: &Transaction<'_>, session: SessionRow) -> StoreResult<SessionSummary> {
    let primary_email = tx
        .query_opt(
            "SELECT primary_email FROM users WHERE user_id = $1",
            &[&session.user_id.as_str()],
        )
        .await
        .map_err(pg)?
        .and_then(|r| r.get::<_, Option<String>>(0))
        .map(|s| NormalizedEmail::from_stored(&s).ok_or_else(|| corrupt("users.primary_email")))
        .transpose()?;
    let hosts = tx
        .query(
            "SELECT DISTINCT host FROM session_handles WHERE session_id = $1 AND revoked_at IS NULL ORDER BY host LIMIT 100",
            &[&session.session_id.as_str()],
        )
        .await
        .map_err(pg)?
        .iter()
        .map(|r| Host::parse(&r.get::<_, String>(0)).map_err(|_| corrupt("session_handles.host")))
        .collect::<StoreResult<Vec<_>>>()?;
    Ok(SessionSummary {
        ua_prefix: session.bound_ua_prefix.clone(),
        session,
        primary_email,
        hosts,
    })
}

#[async_trait]
impl ConsoleStore for PgStore {
    async fn list_users(
        &self,
        q: UsersQuery,
        deadline: Deadline,
    ) -> StoreResult<Page<UserSummary>> {
        let limit = clamp_limit(q.limit);
        let now = self.now().secs();
        let out = async {
            let mut client = self.client().await?;
            let tx = self.read_within(&mut client, deadline).await?;
            let f = Filters {
                cursor: q.cursor.clone(),
                q: q.q.clone().filter(|s| !s.is_empty()),
                status: q.status.map(|s| s.as_str().to_string()),
                ..Filters::default()
            };
            let page = run_window(&tx, Shape::Users, &f, limit, |r| {
                let u = user(r, 0)?;
                let key = u.created_at.secs().saturating_mul(1000);
                let id = u.user_id.to_string();
                Ok((u, key, id))
            })
            .await?;
            let mut items = Vec::with_capacity(page.items.len());
            for u in page.items {
                check_deadline(deadline)?;
                let r = tx
                    .query_one(
                        "SELECT (SELECT count(*) FROM sessions WHERE user_id = $1 AND terminated_at IS NULL AND absolute_expires_at > $2), \
                                (SELECT role FROM admin_grants WHERE user_id = $1 AND revoked_at IS NULL)",
                        &[&u.user_id.as_str(), &now],
                    )
                    .await
                    .map_err(pg)?;
                items.push(UserSummary {
                    live_sessions: u32::try_from(r.get::<_, i64>(0)).unwrap_or(u32::MAX),
                    role: r.get::<_, Option<String>>(1).as_deref().and_then(AdminRole::parse),
                    user: u,
                });
            }
            tx.commit().await.map_err(pg)?;
            Ok(Page { items, next: page.next, examined: page.examined })
        }
        .await;
        out.map_err(deadline_err)
    }

    async fn user_detail(
        &self,
        id: &UserId,
        now: Timestamp,
        deadline: Deadline,
    ) -> StoreResult<Option<UserDetail>> {
        let out = async {
            let mut client = self.client().await?;
            let tx = self.read_within(&mut client, deadline).await?;
            let Some(u) = tx
                .query_opt(&format!("SELECT {USER_COLS} FROM users WHERE user_id = $1"), &[&id.as_str()])
                .await
                .map_err(pg)?
                .map(|r| user(&r, 0))
                .transpose()?
            else {
                return Ok(None);
            };
            check_deadline(deadline)?;
            let identities = tx
                .query(
                    &format!("SELECT {IDENTITY_COLS} FROM identities WHERE user_id = $1 ORDER BY first_seen_at, provider_id, subject LIMIT 50"),
                    &[&id.as_str()],
                )
                .await
                .map_err(pg)?
                .iter()
                .map(identity)
                .collect::<StoreResult<Vec<_>>>()?;
            check_deadline(deadline)?;
            let live_pred = "s.user_id = $1 AND s.terminated_at IS NULL AND s.absolute_expires_at > $2";
            let total: i64 = tx
                .query_one(&format!("SELECT count(*) FROM sessions s WHERE {live_pred}"), &[&id.as_str(), &now.secs()])
                .await
                .map_err(pg)?
                .get(0);
            let live = tx
                .query(
                    &format!("SELECT {SESSION_COLS} FROM sessions s WHERE {live_pred} ORDER BY s.created_at DESC, s.session_id DESC LIMIT 20"),
                    &[&id.as_str(), &now.secs()],
                )
                .await
                .map_err(pg)?;
            let ended = tx
                .query(
                    &format!("SELECT {SESSION_COLS} FROM sessions s WHERE s.user_id = $1 AND s.terminated_at IS NOT NULL ORDER BY s.terminated_at DESC, s.session_id DESC LIMIT 20"),
                    &[&id.as_str()],
                )
                .await
                .map_err(pg)?;
            let mut sessions_live = Vec::new();
            for r in &live {
                check_deadline(deadline)?;
                sessions_live.push(summarize(&tx, session(r, 0)?).await?);
            }
            let mut sessions_terminated = Vec::new();
            for r in &ended {
                check_deadline(deadline)?;
                sessions_terminated.push(summarize(&tx, session(r, 0)?).await?);
            }
            let grant = tx
                .query_opt(
                    &format!("SELECT {} FROM admin_grants WHERE user_id=$1", super::admin::GRANT_COLS),
                    &[&id.as_str()],
                )
                .await
                .map_err(pg)?
                .map(|r| super::admin::grant(&r))
                .transpose()?;
            tx.commit().await.map_err(pg)?;
            Ok(Some(UserDetail {
                user: u,
                identities,
                sessions_live,
                sessions_live_total: u32::try_from(total).unwrap_or(u32::MAX),
                sessions_terminated,
                grant,
            }))
        }
        .await;
        out.map_err(deadline_err)
    }

    async fn list_live_sessions(
        &self,
        q: SessionsQuery,
        deadline: Deadline,
    ) -> StoreResult<Page<SessionSummary>> {
        let limit = clamp_limit(q.limit);
        let out = async {
            let mut client = self.client().await?;
            let tx = self.read_within(&mut client, deadline).await?;
            let f = Filters {
                cursor: q.cursor.clone(),
                user: q.user_id.as_ref().map(|u| u.to_string()),
                now: q.now.secs(),
                ..Filters::default()
            };
            let shape = Shape::Sessions {
                by_user: q.user_id.is_some(),
            };
            let page = run_window(&tx, shape, &f, limit, |r| {
                let s = session(r, 0)?;
                let key = s.created_at.secs().saturating_mul(1000);
                let id = s.session_id.to_string();
                Ok((s, key, id))
            })
            .await?;
            let mut items = Vec::with_capacity(page.items.len());
            for s in page.items {
                check_deadline(deadline)?;
                items.push(summarize(&tx, s).await?);
            }
            tx.commit().await.map_err(pg)?;
            Ok(Page {
                items,
                next: page.next,
                examined: page.examined,
            })
        }
        .await;
        out.map_err(deadline_err)
    }

    async fn session_summary(
        &self,
        id: &SessionId,
        deadline: Deadline,
    ) -> StoreResult<Option<(SessionSummary, Vec<HandleRow>)>> {
        let out = async {
            let mut client = self.client().await?;
            let tx = self.read_within(&mut client, deadline).await?;
            let Some(s) = tx
                .query_opt(&format!("SELECT {SESSION_COLS} FROM sessions s WHERE s.session_id = $1"), &[&id.as_str()])
                .await
                .map_err(pg)?
                .map(|r| session(&r, 0))
                .transpose()?
            else {
                return Ok(None);
            };
            check_deadline(deadline)?;
            let handles = tx
                .query(
                    &format!("SELECT {HANDLE_COLS} FROM session_handles h WHERE h.session_id = $1 ORDER BY h.created_at DESC, h.handle_sha256 LIMIT 100"),
                    &[&id.as_str()],
                )
                .await
                .map_err(pg)?
                .iter()
                .map(|r| handle(r, 0))
                .collect::<StoreResult<Vec<_>>>()?;
            let summary = summarize(&tx, s).await?;
            tx.commit().await.map_err(pg)?;
            Ok(Some((summary, handles)))
        }
        .await;
        out.map_err(deadline_err)
    }
}

// ---- the relay -------------------------------------------------------------

impl PgStore {
    /// The prune statements (age, count, terminal deliveries, backlog cap).
    async fn prune_in(
        &self,
        tx: &Transaction<'_>,
        now: Timestamp,
        p: &EventRetention,
    ) -> StoreResult<PruneReport> {
        let mut report = PruneReport::default();
        super::write::set_meta(tx, "last_prune_at", &now.secs().to_string()).await?;
        // 1. Age.
        let cutoff = secs_f(now.sub(p.retention));
        report.deliveries_marked_pruned += tx
            .execute(
                "UPDATE event_deliveries SET state='failed', last_error='pruned', updated_at=$2 WHERE state='pending' AND event_id IN (SELECT event_id FROM events WHERE at < $1)",
                &[&cutoff, &now.secs()],
            )
            .await
            .map_err(pg)?;
        report.events_deleted += tx
            .execute("DELETE FROM events WHERE at < $1", &[&cutoff])
            .await
            .map_err(pg)?;
        // 2. Count, oldest first, whatever the delivery state.
        let total: i64 = tx
            .query_one("SELECT count(*) FROM events", &[])
            .await
            .map_err(pg)?
            .get(0);
        let max = i64::try_from(p.max_rows).unwrap_or(i64::MAX);
        if total > max {
            let excess = total - max;
            let victims = "SELECT event_id FROM events ORDER BY at, event_id LIMIT $1";
            report.deliveries_marked_pruned += tx
                .execute(
                    &format!("UPDATE event_deliveries SET state='failed', last_error='pruned', updated_at=$2 WHERE state='pending' AND event_id IN ({victims})"),
                    &[&excess, &now.secs()],
                )
                .await
                .map_err(pg)?;
            report.events_deleted += tx
                .execute(
                    &format!("DELETE FROM events WHERE event_id IN ({victims})"),
                    &[&excess],
                )
                .await
                .map_err(pg)?;
        }
        // 3. Terminal delivery rows expire on their own clock.
        report.terminal_deliveries_deleted = tx
            .execute(
                "DELETE FROM event_deliveries WHERE state IN ('delivered','failed') AND updated_at < $1",
                &[&now.sub(p.terminal_retention).secs()],
            )
            .await
            .map_err(pg)?;
        // 4. Backlog cap per sink: the oldest pending deliveries are dead-lettered.
        let sinks = tx
            .query(
                "SELECT DISTINCT sink FROM event_deliveries ORDER BY sink",
                &[],
            )
            .await
            .map_err(pg)?;
        let cap = i64::try_from(p.max_pending_per_sink).unwrap_or(i64::MAX);
        for r in sinks {
            let sink: String = r.get(0);
            let pending: i64 = tx
                .query_one(
                    "SELECT count(*) FROM event_deliveries WHERE sink=$1 AND state='pending'",
                    &[&sink],
                )
                .await
                .map_err(pg)?
                .get(0);
            if pending <= cap {
                continue;
            }
            let moved = tx
                .execute(
                    "UPDATE event_deliveries SET state='failed', last_error='backlog_overflow', updated_at=$3 WHERE sink=$1 AND event_id IN \
                     (SELECT d.event_id FROM event_deliveries d JOIN events e USING (event_id) WHERE d.sink=$1 AND d.state='pending' ORDER BY e.at, d.event_id LIMIT $2)",
                    &[&sink, &(pending - cap), &now.secs()],
                )
                .await
                .map_err(pg)?;
            report.backlog_overflowed += moved;
            let ev = EventBuilder::new(
                self.clock.as_ref(),
                self.rng.as_ref(),
                EventKind::SinkBacklogOverflow,
                Outcome::Failure,
                "prune",
            )
            .reason(reasons::BACKLOG_OVERFLOW)
            .attr("sink", sink.as_str())
            .attr("count", moved)
            .build();
            self.insert_events(tx, &[ev]).await?;
        }
        Ok(report)
    }
}

#[async_trait]
impl Events for PgStore {
    async fn append_required(&self, events: Vec<Event>) -> StoreResult<()> {
        crate::store::core::CoreStore::append_required(self, events).await
    }

    async fn append_required_within(
        &self,
        events: Vec<Event>,
        deadline: Deadline,
    ) -> StoreResult<()> {
        if events.is_empty() {
            return Ok(());
        }
        standalone(&events)?;
        super::retry(|| async {
            check_deadline(deadline)?;
            let mut client = self.client().await?;
            let tx = self.begin(&mut client).await?;
            let ms = deadline_ms(deadline).min(self.statement_timeout_ms);
            tx.batch_execute(&format!("SET LOCAL statement_timeout = {ms}"))
                .await
                .map_err(pg)?;
            self.insert_events(&tx, &events).await?;
            // A write that reached its deadline rolls back instead of committing late.
            check_deadline(deadline)?;
            tx.commit().await.map_err(pg)
        })
        .await
        .map_err(deadline_err)
    }

    async fn append_diagnostic(&self, ev: Event) -> StoreResult<()> {
        if ev.kind.is_required() {
            return Err(StoreError::Conflict(
                "required kinds travel with their state change",
            ));
        }
        // As SQLite's bounded queue: a full one refuses at once (the caller counts a drop).
        let _permit = self
            .diag
            .clone()
            .try_acquire_owned()
            .map_err(|_| StoreError::Busy)?;
        let attrs = serde_json::to_string(&serde_json::Value::Object(ev.attrs.clone()))
            .map_err(|_| corrupt("events.attrs"))?;
        let client = self.client().await?;
        client
            .execute(
                "INSERT INTO events (event_id, at, kind, outcome, reason, user_id, session_id, app_id, provider_id, client_ip, ua_sha256, ua_prefix, request_id, attrs) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,CAST($14::text AS jsonb)) ON CONFLICT (event_id) DO NOTHING",
                &[
                    &ev.event_id.as_str(),
                    &secs_f(ev.at),
                    &ev.kind.name(),
                    &ev.outcome.as_str(),
                    &ev.reason.map(|r| r.0),
                    &ev.user_id.as_ref().map(|v| v.as_str()),
                    &ev.session_id.as_ref().map(|v| v.as_str()),
                    &ev.app_id.as_ref().map(|v| v.as_str()),
                    &ev.provider_id.as_ref().map(|v| v.as_str()),
                    &ev.client_ip.map(|v| v.to_string()),
                    &ev.ua_sha256.as_ref().map(|d| d.0.to_vec()),
                    &ev.ua_prefix.as_deref(),
                    &ev.request_id.as_str(),
                    &attrs,
                ],
            )
            .await
            .map_err(pg)?;
        Ok(())
    }

    async fn claim_deliveries(
        &self,
        sink: &str,
        limit: usize,
        now: Timestamp,
    ) -> StoreResult<Vec<Delivery>> {
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        super::retry(|| async {
            let mut client = self.client().await?;
            let tx = self.begin(&mut client).await?;
            // Rows another relay holds are skipped, never waited for.
            let due = tx
                .query(
                    "SELECT event_id, attempts FROM event_deliveries WHERE sink=$1 AND state='pending' AND next_attempt_at <= $2 \
                     ORDER BY next_attempt_at, seq LIMIT $3 FOR UPDATE SKIP LOCKED",
                    &[&sink, &now.secs(), &limit],
                )
                .await
                .map_err(pg)?;
            let mut out = Vec::with_capacity(due.len());
            for r in due {
                let id: String = r.get(0);
                let attempts: i32 = r.get(1);
                tx.execute(
                    "UPDATE event_deliveries SET attempts = attempts + 1, next_attempt_at = $3, updated_at = $4 WHERE sink=$1 AND event_id=$2",
                    &[&sink, &id, &(now.secs() + CLAIM_LEASE_SECS), &now.secs()],
                )
                .await
                .map_err(pg)?;
                let ev = tx
                    .query_one(&format!("SELECT {EVENT_COLS} FROM events WHERE event_id=$1"), &[&id])
                    .await
                    .map_err(pg)?;
                out.push(Delivery {
                    sink: sink.to_string(),
                    event: event(&ev)?,
                    attempts: u32::try_from(attempts + 1).unwrap_or(u32::MAX),
                });
            }
            tx.commit().await.map_err(pg)?;
            Ok(out)
        })
        .await
    }

    async fn mark_delivered(
        &self,
        sink: &str,
        event_id: &EventId,
        at: Timestamp,
    ) -> StoreResult<()> {
        let client = self.client().await?;
        client
            .execute(
                "UPDATE event_deliveries SET state='delivered', last_error=NULL, updated_at=$3 WHERE sink=$1 AND event_id=$2",
                &[&sink, &event_id.as_str(), &at.secs()],
            )
            .await
            .map_err(pg)?;
        Ok(())
    }

    async fn mark_failed(
        &self,
        sink: &str,
        event_id: &EventId,
        error: &str,
        next_attempt_at: Option<Timestamp>,
    ) -> StoreResult<()> {
        // Only the reason keyword survives: delivery errors may carry remote text.
        let error: String = error.chars().take(120).collect();
        let now = self.now().secs();
        let client = self.client().await?;
        match next_attempt_at {
            Some(t) => client
                .execute(
                    "UPDATE event_deliveries SET state='pending', last_error=$3, next_attempt_at=$4, updated_at=$5 WHERE sink=$1 AND event_id=$2",
                    &[&sink, &event_id.as_str(), &error, &t.secs(), &now],
                )
                .await,
            None => client
                .execute(
                    "UPDATE event_deliveries SET state='failed', last_error=$3, updated_at=$4 WHERE sink=$1 AND event_id=$2",
                    &[&sink, &event_id.as_str(), &error, &now],
                )
                .await,
        }
        .map_err(pg)?;
        Ok(())
    }

    async fn prune(&self, now: Timestamp, policy: &EventRetention) -> StoreResult<PruneReport> {
        super::retry(|| async {
            let mut client = self.client().await?;
            let tx = self.begin(&mut client).await?;
            // One pass at a time across replicas.
            tx.execute("SELECT pg_advisory_xact_lock($1)", &[&PRUNE_LOCK])
                .await
                .map_err(pg)?;
            let report = self.prune_in(&tx, now, policy).await?;
            tx.commit().await.map_err(pg)?;
            Ok(report)
        })
        .await
    }

    async fn count_rows(&self) -> StoreResult<(u64, u64)> {
        let client = self.client().await?;
        let r = client
            .query_one(
                "SELECT (SELECT count(*) FROM events), (SELECT count(*) FROM event_deliveries)",
                &[],
            )
            .await
            .map_err(pg)?;
        Ok((count(r.get(0)), count(r.get(1))))
    }

    async fn query(&self, filter: EventQuery) -> StoreResult<Vec<Event>> {
        let mut a = Args::default();
        let mut sql = format!("SELECT {EVENT_COLS} FROM events WHERE TRUE");
        if let Some(k) = filter.kind {
            sql.push_str(&format!(" AND kind = {}", a.p(k.name().to_string())));
        }
        if let Some(s) = &filter.session_id {
            sql.push_str(&format!(" AND session_id = {}", a.p(s.to_string())));
        }
        if let Some(u) = &filter.user_id {
            sql.push_str(&format!(" AND user_id = {}", a.p(u.to_string())));
        }
        if let Some(ip) = filter.client_ip {
            sql.push_str(&format!(" AND client_ip = {}", a.p(ip.to_string())));
        }
        if let Some(t) = filter.since {
            sql.push_str(&format!(" AND at >= {}", a.p(secs_f(t))));
        }
        let limit = filter.limit.unwrap_or(100).clamp(1, 10_000);
        sql.push_str(&format!(" ORDER BY at, event_id LIMIT {limit}"));
        let client = self.client().await?;
        client
            .query(&sql, &a.refs())
            .await
            .map_err(pg)?
            .iter()
            .map(event)
            .collect()
    }

    async fn query_page(&self, q: EventsQuery, deadline: Deadline) -> StoreResult<Page<Event>> {
        let limit = clamp_limit(q.limit);
        let out = async {
            let mut client = self.client().await?;
            let tx = self.read_within(&mut client, deadline).await?;
            let f = Filters {
                cursor: q.cursor.clone(),
                user: q.user_id.as_ref().map(|v| v.to_string()),
                kind: q.kind.map(|k| k.name().to_string()),
                outcome: q.outcome.map(|o| o.as_str().to_string()),
                session: q.session_id.as_ref().map(|v| v.to_string()),
                ip: q.client_ip.map(|v| v.to_string()),
                since: q.since.map(secs_f),
                until: q.until.map(secs_f),
                since_w: q.since.map_or(f64::MIN, secs_f),
                until_w: q.until.map_or(f64::MAX, secs_f),
                ..Filters::default()
            };
            let page = run_window(&tx, Shape::Events(q.index()), &f, limit, |r| {
                let e = event(r)?;
                let key = e.at.0;
                let id = e.event_id.to_string();
                Ok((e, key, id))
            })
            .await?;
            tx.commit().await.map_err(pg)?;
            Ok(page)
        }
        .await;
        out.map_err(deadline_err)
    }

    async fn status(&self, deadline: Deadline) -> StoreResult<StoreStatus> {
        let now = self.now().secs();
        let out = async {
            let mut client = self.client().await?;
            let tx = self.read_within(&mut client, deadline).await?;
            let r = tx
                .query_one(
                    "SELECT (SELECT count(*) FROM users), (SELECT count(*) FROM events), \
                            (SELECT count(*) FROM sessions WHERE terminated_at IS NULL AND absolute_expires_at > $1), \
                            (SELECT value FROM meta WHERE key = 'last_prune_at'), \
                            (SELECT COALESCE(max(version), 0) FROM schema_migrations)",
                    &[&now],
                )
                .await
                .map_err(pg)?;
            check_deadline(deadline)?;
            let mut deliveries: Vec<(String, u64, u64)> = Vec::new();
            for d in tx
                .query(
                    "SELECT sink, count(*) FILTER (WHERE state='pending'), count(*) FILTER (WHERE state='failed') \
                     FROM event_deliveries WHERE state IN ('pending','failed') GROUP BY sink ORDER BY sink",
                    &[],
                )
                .await
                .map_err(pg)?
            {
                deliveries.push((d.get(0), count(d.get(1)), count(d.get(2))));
            }
            tx.commit().await.map_err(pg)?;
            Ok(StoreStatus {
                schema_version: u32::try_from(r.get::<_, i32>(4)).unwrap_or(0),
                users: count(r.get(0)),
                events: count(r.get(1)),
                live_sessions: count(r.get(2)),
                deliveries,
                last_prune_at: r
                    .get::<_, Option<String>>(3)
                    .and_then(|s| s.parse::<i64>().ok())
                    .map(Timestamp::from_secs),
            })
        }
        .await;
        out.map_err(deadline_err)
    }
}
