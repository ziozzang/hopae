//! `Events` for SQLite: the outbox insert shared by every mutating store
//! method, the bounded diagnostic queue with its batch writer, delivery
//! claiming, pruning and retention.

use std::sync::atomic::Ordering;

use async_trait::async_trait;
use rusqlite::{Connection, params, params_from_iter, types::ToSql};

use super::rows::{self, EVENT_COLS, cols};
use super::{DIAGNOSTIC_QUEUE_CAP, Shared, Store, WriterEnv, commit};
use crate::crypto::Timestamp;
use crate::event::types::{Event, EventBuilder, EventId, EventKind, Outcome, reasons};
use crate::store::types::*;
use crate::store::{Events, StoreError, StoreResult};

/// How long a claimed delivery stays invisible to other claims. A worker that
/// dies mid-delivery gets the row handed out again afterwards: at-least-once.
const CLAIM_LEASE_SECS: i64 = 60;
/// Diagnostic events written per transaction by the batch writer.
const DIAG_BATCH: usize = 256;

/// Insert one event; for a required kind also one `pending` delivery row per
/// sink, in the caller's transaction. `ignore_duplicate` is for the
/// best-effort diagnostic writer only.
pub(super) fn insert_event(
    conn: &Connection,
    ev: &Event,
    sinks: &[String],
    now: Timestamp,
    ignore_duplicate: bool,
) -> StoreResult<()> {
    let attrs = rows::json_str(&serde_json::Value::Object(ev.attrs.clone()))?;
    let sql = if ignore_duplicate {
        "INSERT OR IGNORE INTO events (event_id, at, kind, outcome, reason, user_id, session_id, app_id, provider_id, client_ip, ua_sha256, ua_prefix, request_id, attrs) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)"
    } else {
        "INSERT INTO events (event_id, at, kind, outcome, reason, user_id, session_id, app_id, provider_id, client_ip, ua_sha256, ua_prefix, request_id, attrs) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)"
    };
    let changed = conn.execute(
        sql,
        params![
            ev.event_id.as_str(),
            ev.at.0 as f64 / 1000.0,
            ev.kind.name(),
            ev.outcome.as_str(),
            ev.reason.map(|r| r.0),
            ev.user_id.as_ref().map(|v| v.as_str()),
            ev.session_id.as_ref().map(|v| v.as_str()),
            ev.app_id.as_ref().map(|v| v.as_str()),
            ev.provider_id.as_ref().map(|v| v.as_str()),
            ev.client_ip.map(|v| v.to_string()),
            rows::opt_blob(&ev.ua_sha256),
            ev.ua_prefix.as_deref(),
            ev.request_id.as_str(),
            attrs,
        ],
    )?;
    if changed == 1 && ev.kind.is_required() {
        for sink in sinks {
            conn.execute(
                "INSERT INTO event_deliveries (sink, event_id, state, attempts, next_attempt_at, updated_at) VALUES (?1, ?2, 'pending', 0, ?3, ?3)",
                params![sink, ev.event_id.as_str(), now.secs()],
            )?;
        }
    }
    Ok(())
}

pub(super) fn insert_events(
    conn: &Connection,
    shared: &Shared,
    events: &[Event],
) -> StoreResult<()> {
    let now = shared.clock.now();
    for ev in events {
        insert_event(conn, ev, &shared.sinks, now, false)?;
    }
    Ok(())
}

/// Drain the diagnostic queue in batches, one transaction per batch. Failures
/// are logged and the batch dropped: diagnostics are best effort.
pub(super) fn flush_diagnostics(env: &mut WriterEnv) {
    env.shared.diag_flush_queued.store(false, Ordering::SeqCst);
    loop {
        let batch: Vec<Event> = {
            let mut q = env.shared.diag.lock().unwrap_or_else(|p| p.into_inner());
            let n = q.len().min(DIAG_BATCH);
            q.drain(..n).collect()
        };
        if batch.is_empty() {
            return;
        }
        let shared = env.shared.clone();
        let now = shared.clock.now();
        let result = (|| -> StoreResult<()> {
            let tx = env.begin()?;
            for ev in &batch {
                insert_event(&tx, ev, &shared.sinks, now, true)?;
            }
            commit(tx, &shared, None)
        })();
        if let Err(e) = result {
            tracing::warn!(error = %e, dropped = batch.len(), "diagnostic event batch failed");
        }
    }
}

fn secs_f(t: Timestamp) -> f64 {
    t.0 as f64 / 1000.0
}

#[async_trait]
impl Events for Store {
    async fn append_diagnostic(&self, event: Event) -> StoreResult<()> {
        if event.kind.is_required() {
            return Err(StoreError::Conflict(
                "required kinds travel with their state change",
            ));
        }
        let shared = self.shared().clone();
        let tx = self.inner.tx.clone();
        self.run("append_diagnostic", async move {
            {
                let mut q = shared.diag.lock().unwrap_or_else(|p| p.into_inner());
                if q.len() >= DIAGNOSTIC_QUEUE_CAP {
                    return Err(StoreError::Busy);
                }
                q.push_back(event);
            }
            if !shared.diag_flush_queued.swap(true, Ordering::SeqCst) {
                let job: super::Job = Box::new(flush_diagnostics);
                if tx.send(job).is_err() {
                    shared.diag_flush_queued.store(false, Ordering::SeqCst);
                    return Err(StoreError::Unavailable("store writer stopped".into()));
                }
            }
            Ok(())
        })
        .await
    }

    async fn claim_deliveries(
        &self,
        sink: &str,
        limit: usize,
        now: Timestamp,
    ) -> StoreResult<Vec<Delivery>> {
        let sink = sink.to_string();
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        self.write("claim_deliveries", move |env| {
            let tx = env.begin()?;
            let due: Vec<(String, i64)> = {
                let mut stmt = tx.prepare(
                    "SELECT event_id, attempts FROM event_deliveries WHERE sink=?1 AND state='pending' AND next_attempt_at <= ?2 ORDER BY next_attempt_at, rowid LIMIT ?3",
                )?;
                stmt.query_map(params![sink, now.secs(), limit], |r| Ok((r.get(0)?, r.get(1)?)))?
                    .collect::<Result<_, _>>()?
            };
            let mut out = Vec::with_capacity(due.len());
            for (id, attempts) in due {
                tx.execute(
                    "UPDATE event_deliveries SET attempts = attempts + 1, next_attempt_at = ?3, updated_at = ?4 WHERE sink=?1 AND event_id=?2",
                    params![sink, id, now.secs() + CLAIM_LEASE_SECS, now.secs()],
                )?;
                let sql = format!("SELECT {} FROM events WHERE event_id=?1", cols("", EVENT_COLS));
                let event = tx.query_row(&sql, [&id], |r| Ok(rows::event(r, 0)))??;
                out.push(Delivery {
                    sink: sink.clone(),
                    event,
                    attempts: u32::try_from(attempts + 1).unwrap_or(u32::MAX),
                });
            }
            tx.commit()?;
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
        let (sink, id) = (sink.to_string(), event_id.to_string());
        self.write("mark_delivered", move |env| {
            env.conn.execute(
                "UPDATE event_deliveries SET state='delivered', last_error=NULL, updated_at=?3 WHERE sink=?1 AND event_id=?2",
                params![sink, id, at.secs()],
            )?;
            Ok(())
        })
        .await
    }

    async fn mark_failed(
        &self,
        sink: &str,
        event_id: &EventId,
        error: &str,
        next_attempt_at: Option<Timestamp>,
    ) -> StoreResult<()> {
        let (sink, id) = (sink.to_string(), event_id.to_string());
        // Only the reason keyword survives: delivery errors may carry remote text.
        let error: String = error.chars().take(120).collect();
        self.write("mark_failed", move |env| {
            let now = env.now().secs();
            match next_attempt_at {
                Some(t) => env.conn.execute(
                    "UPDATE event_deliveries SET state='pending', last_error=?3, next_attempt_at=?4, updated_at=?5 WHERE sink=?1 AND event_id=?2",
                    params![sink, id, error, t.secs(), now],
                )?,
                None => env.conn.execute(
                    "UPDATE event_deliveries SET state='failed', last_error=?3, updated_at=?4 WHERE sink=?1 AND event_id=?2",
                    params![sink, id, error, now],
                )?,
            };
            Ok(())
        })
        .await
    }

    async fn prune(&self, now: Timestamp, policy: &EventRetention) -> StoreResult<PruneReport> {
        let p = policy.clone();
        self.write("prune", move |env| {
            let shared = env.shared.clone();
            let tx = env.begin()?;
            let mut report = PruneReport::default();

            // 1. Age.
            let cutoff = secs_f(now.sub(p.retention));
            report.deliveries_marked_pruned += tx.execute(
                "UPDATE event_deliveries SET state='failed', last_error='pruned', updated_at=?2 WHERE state='pending' AND event_id IN (SELECT event_id FROM events WHERE at < ?1)",
                params![cutoff, now.secs()],
            )? as u64;
            report.events_deleted += tx.execute("DELETE FROM events WHERE at < ?1", params![cutoff])? as u64;

            // 2. Count, oldest first, whatever the delivery state.
            let total: i64 = tx.query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))?;
            let max = i64::try_from(p.max_rows).unwrap_or(i64::MAX);
            if total > max {
                let excess = total - max;
                let victims = "SELECT event_id FROM events ORDER BY at, event_id LIMIT ?1";
                report.deliveries_marked_pruned += tx.execute(
                    &format!("UPDATE event_deliveries SET state='failed', last_error='pruned', updated_at=?2 WHERE state='pending' AND event_id IN ({victims})"),
                    params![excess, now.secs()],
                )? as u64;
                report.events_deleted += tx.execute(
                    &format!("DELETE FROM events WHERE event_id IN ({victims})"),
                    params![excess],
                )? as u64;
            }

            // 3. Terminal delivery rows expire on their own clock.
            let terminal_cutoff = now.sub(p.terminal_retention).secs();
            report.terminal_deliveries_deleted = tx.execute(
                "DELETE FROM event_deliveries WHERE state IN ('delivered','failed') AND updated_at < ?1",
                params![terminal_cutoff],
            )? as u64;

            // 4. Backlog cap per sink: the oldest pending deliveries are dead-lettered.
            let sinks: Vec<String> = {
                let mut stmt = tx.prepare("SELECT DISTINCT sink FROM event_deliveries")?;
                stmt.query_map([], |r| r.get(0))?.collect::<Result<_, _>>()?
            };
            let cap = i64::try_from(p.max_pending_per_sink).unwrap_or(i64::MAX);
            for sink in sinks {
                let pending: i64 = tx.query_row(
                    "SELECT COUNT(*) FROM event_deliveries WHERE sink=?1 AND state='pending'",
                    [&sink],
                    |r| r.get(0),
                )?;
                if pending <= cap {
                    continue;
                }
                let excess = pending - cap;
                let moved = tx.execute(
                    "UPDATE event_deliveries SET state='failed', last_error='backlog_overflow', updated_at=?3 WHERE sink=?1 AND event_id IN (SELECT d.event_id FROM event_deliveries d JOIN events e USING (event_id) WHERE d.sink=?1 AND d.state='pending' ORDER BY e.at, d.event_id LIMIT ?2)",
                    params![sink, excess, now.secs()],
                )? as u64;
                report.backlog_overflowed += moved;
                let rng = shared.rng();
                let ev = EventBuilder::new(&*shared.clock, &*rng, EventKind::SinkBacklogOverflow, Outcome::Failure, "prune")
                    .reason(reasons::BACKLOG_OVERFLOW)
                    .attr("sink", sink.as_str())
                    .attr("count", moved)
                    .build();
                insert_event(&tx, &ev, &shared.sinks, now, false)?;
            }
            commit(tx, &shared, None)?;
            Ok(report)
        })
        .await
    }

    async fn count_rows(&self) -> StoreResult<(u64, u64)> {
        self.barrier().await?;
        self.read("count_rows", |c| {
            let e: i64 = c.query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))?;
            let d: i64 = c.query_row("SELECT COUNT(*) FROM event_deliveries", [], |r| r.get(0))?;
            Ok((u64::try_from(e).unwrap_or(0), u64::try_from(d).unwrap_or(0)))
        })
        .await
    }

    async fn query(&self, filter: EventQuery) -> StoreResult<Vec<Event>> {
        self.barrier().await?;
        self.read("query_events", move |c| {
            let mut sql = format!("SELECT {} FROM events WHERE 1=1", cols("", EVENT_COLS));
            let mut args: Vec<Box<dyn ToSql>> = Vec::new();
            let mut add = |clause: &str, v: Box<dyn ToSql>| {
                args.push(v);
                sql.push_str(&format!(" AND {clause} = ?{}", args.len()));
            };
            if let Some(k) = filter.kind {
                add("kind", Box::new(k.name().to_string()));
            }
            if let Some(s) = &filter.session_id {
                add("session_id", Box::new(s.to_string()));
            }
            if let Some(u) = &filter.user_id {
                add("user_id", Box::new(u.to_string()));
            }
            if let Some(ip) = filter.client_ip {
                add("client_ip", Box::new(ip.to_string()));
            }
            if let Some(t) = filter.since {
                args.push(Box::new(secs_f(t)));
                sql.push_str(&format!(" AND at >= ?{}", args.len()));
            }
            let limit = filter.limit.unwrap_or(100).clamp(1, 10_000);
            sql.push_str(&format!(" ORDER BY at, event_id LIMIT {limit}"));
            let mut stmt = c.prepare(&sql)?;
            let mut rows_iter = stmt.query(params_from_iter(args.iter().map(|b| b.as_ref())))?;
            let mut out = Vec::new();
            while let Some(r) = rows_iter.next()? {
                out.push(rows::event(r, 0)?);
            }
            Ok(out)
        })
        .await
    }
}

impl Store {
    /// Rows of `event_deliveries`, optionally for one sink (test hooks and operators).
    pub async fn dump_deliveries(&self, sink: Option<&str>) -> StoreResult<Vec<DeliveryRow>> {
        self.barrier().await?;
        let sink = sink.map(str::to_string);
        self.read("dump_deliveries", move |c| {
            let mut stmt = c.prepare(
                "SELECT sink, event_id, state, attempts, next_attempt_at, last_error, updated_at FROM event_deliveries WHERE (?1 IS NULL OR sink = ?1) ORDER BY rowid LIMIT 10000",
            )?;
            let mut rows_iter = stmt.query(params![sink])?;
            let mut out = Vec::new();
            while let Some(r) = rows_iter.next()? {
                out.push(DeliveryRow {
                    sink: r.get(0)?,
                    event_id: EventId::new(r.get::<_, String>(1)?),
                    state: r.get(2)?,
                    attempts: rows::u32_of(r, 3, "event_deliveries.attempts")?,
                    next_attempt_at: Timestamp::from_secs(r.get(4)?),
                    last_error: r.get(5)?,
                    updated_at: Timestamp::from_secs(r.get(6)?),
                });
            }
            Ok(out)
        })
        .await
    }
}
