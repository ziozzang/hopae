//! Pruning (ADR-0009: bounded storage) and the session-retention sweep.
//!
//! The pruner runs after every `events.prune_every` rows inserted since its
//! last run or every 60 s, whichever comes first. Insertions are counted at
//! the [`crate::event::Emitter`], which every required event passes through;
//! the trigger fires at a quarter of `prune_every` so that rows committed
//! while a prune is queued still fit inside `max_rows + prune_every`.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tokio::sync::{Notify, watch};

use crate::crypto::Clock;
use crate::event::types::reasons;
use crate::store::types::{EventRetention, PruneReport, SweepReport};
use crate::store::{Events, Sessions, StoreResult};
use crate::telemetry::counters;

/// Longest gap between prune runs.
pub const PRUNE_PERIOD: Duration = Duration::from_secs(60);
/// The session-retention sweep runs hourly.
pub const SWEEP_PERIOD: Duration = Duration::from_secs(3600);
/// How often the loops look at the clocks.
const TICK: Duration = Duration::from_millis(250);

/// Counts event rows about to be inserted and wakes the pruner.
pub struct PruneTrigger {
    inserted: AtomicU64,
    threshold: u64,
    notify: Notify,
}

impl PruneTrigger {
    pub fn new(prune_every: u64) -> Self {
        PruneTrigger {
            inserted: AtomicU64::new(0),
            threshold: (prune_every / 4).max(1),
            notify: Notify::new(),
        }
    }

    /// A required event is about to be committed.
    pub fn note_insert(&self) {
        let n = self.inserted.fetch_add(1, Ordering::Relaxed) + 1;
        if n >= self.threshold {
            self.notify.notify_one();
        }
    }

    fn reset(&self) {
        self.inserted.store(0, Ordering::Relaxed);
    }

    /// Rows to write between two checks of [`PruneTrigger::due`].
    pub fn threshold(&self) -> u64 {
        self.threshold
    }

    /// Whether enough rows have been inserted since the last prune.
    pub fn due(&self) -> bool {
        self.inserted.load(Ordering::Relaxed) >= self.threshold
    }

    async fn fired(&self) {
        self.notify.notified().await;
    }
}

/// "Has `period` passed on the process clock or on the wall clock?" The
/// process clock is the test clock under `test-hooks`, which a test moves in
/// jumps; the wall clock keeps production honest if it is wrong.
struct Every {
    period: Duration,
    clock_at: crate::crypto::Timestamp,
    real_at: Instant,
}

impl Every {
    fn new(period: Duration, clock: &dyn Clock) -> Self {
        Every {
            period,
            clock_at: clock.now(),
            real_at: Instant::now(),
        }
    }

    fn due(&self, clock: &dyn Clock) -> bool {
        clock.now().since(self.clock_at) >= self.period || self.real_at.elapsed() >= self.period
    }

    fn reset(&mut self, clock: &dyn Clock) {
        self.clock_at = clock.now();
        self.real_at = Instant::now();
    }
}

#[derive(Clone)]
pub struct Pruner {
    events: Arc<dyn Events>,
    clock: Arc<dyn Clock>,
    policy: EventRetention,
    trigger: Arc<PruneTrigger>,
    sink_label: String,
}

impl Pruner {
    /// `sinks` are the configured sink names, used only to label the
    /// backlog-overflow metric (`all` when there is more than one).
    pub fn new(
        events: Arc<dyn Events>,
        clock: Arc<dyn Clock>,
        policy: EventRetention,
        trigger: Arc<PruneTrigger>,
        sinks: Vec<String>,
    ) -> Self {
        let sink_label = match sinks.as_slice() {
            [one] => one.clone(),
            _ => "all".to_string(),
        };
        Pruner {
            events,
            clock,
            policy,
            trigger,
            sink_label,
        }
    }

    /// Whether the insert count says a prune is due.
    pub fn due(&self) -> bool {
        self.trigger.due()
    }

    /// One prune pass under the retention policy.
    pub async fn run_once(&self) -> StoreResult<PruneReport> {
        let report = self.events.prune(self.clock.now(), &self.policy).await?;
        self.trigger.reset();
        if report.events_deleted > 0 {
            counters::add(counters::EVENTS_PRUNED_TOTAL, &[], report.events_deleted);
        }
        if report.deliveries_marked_pruned > 0 {
            counters::add(
                counters::EVENT_DELIVERIES_FAILED_TOTAL,
                &[("sink", &self.sink_label), ("reason", reasons::PRUNED.0)],
                report.deliveries_marked_pruned,
            );
        }
        if report.backlog_overflowed > 0 {
            counters::add(
                counters::EVENT_DELIVERIES_FAILED_TOTAL,
                &[
                    ("sink", &self.sink_label),
                    ("reason", reasons::BACKLOG_OVERFLOW.0),
                ],
                report.backlog_overflowed,
            );
            tracing::warn!(
                sink = %self.sink_label,
                moved = report.backlog_overflowed,
                "event delivery backlog over the cap: oldest pending deliveries marked failed"
            );
        }
        Ok(report)
    }

    /// Prune on the trigger and at least every 60 s until `stop` flips to `true`.
    pub async fn run(self, mut stop: watch::Receiver<bool>) {
        let mut every = Every::new(PRUNE_PERIOD, &*self.clock);
        loop {
            tokio::select! {
                _ = crate::event::bus::stopped(&mut stop) => break,
                _ = self.trigger.fired() => {}
                _ = tokio::time::sleep(TICK) => {
                    if !every.due(&*self.clock) {
                        continue;
                    }
                }
            }
            if let Err(e) = self.run_once().await {
                tracing::warn!(error = %e, "event prune failed");
            }
            every.reset(&*self.clock);
        }
    }
}

/// Deletes expired transactions and handoff codes and sessions terminated
/// longer ago than `sessions.retention_days`.
pub struct Sweeper {
    sessions: Arc<dyn Sessions>,
    clock: Arc<dyn Clock>,
    retention: Duration,
}

impl Sweeper {
    pub fn new(sessions: Arc<dyn Sessions>, clock: Arc<dyn Clock>, retention: Duration) -> Self {
        Sweeper {
            sessions,
            clock,
            retention,
        }
    }

    pub async fn run_once(&self) -> StoreResult<SweepReport> {
        let report = self
            .sessions
            .sweep(self.clock.now(), self.retention)
            .await?;
        if report.transactions + report.codes + report.sessions > 0 {
            tracing::info!(
                transactions = report.transactions,
                codes = report.codes,
                sessions = report.sessions,
                "retention sweep"
            );
        }
        Ok(report)
    }

    /// Sweep once at start, then hourly, until `stop` flips to `true`.
    pub async fn run(self, mut stop: watch::Receiver<bool>) {
        let mut every = Every::new(SWEEP_PERIOD, &*self.clock);
        loop {
            if let Err(e) = self.run_once().await {
                tracing::warn!(error = %e, "retention sweep failed");
            }
            every.reset(&*self.clock);
            loop {
                tokio::select! {
                    _ = crate::event::bus::stopped(&mut stop) => return,
                    _ = tokio::time::sleep(TICK) => {}
                }
                if every.due(&*self.clock) {
                    break;
                }
            }
        }
    }
}
