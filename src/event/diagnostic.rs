//! The diagnostic batch writer. Drains the bounded queue into the store (the
//! store batches them into transactions), releases sampled `verify.denied`
//! windows when they close and reports drops as one `events.dropped` event
//! with the count per kind. Diagnostics are best effort by design (ADR-0009):
//! nothing here can delay or fail a request.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, watch};

use crate::crypto::{Clock, Rng};
use crate::event::bus::DropCounts;
use crate::event::prune::{PruneTrigger, Pruner};
use crate::event::sampling::Sampler;
use crate::event::types::{Event, EventBuilder, EventKind, Outcome};
use crate::store::{Events, Store};
use crate::telemetry::counters;

/// How often sampled windows are released and drops are reported.
const HOUSEKEEPING: Duration = Duration::from_millis(200);
/// Drops are reported at most this often.
const REPORT_EVERY: Duration = Duration::from_secs(1);

pub struct DiagnosticWriter {
    /// For the barrier that keeps each chunk of writes small; `events` is its `Events` view.
    pub store: Store,
    pub events: Arc<dyn Events>,
    pub rx: mpsc::Receiver<Event>,
    pub drops: Arc<DropCounts>,
    pub sampler: Arc<Sampler>,
    pub clock: Arc<dyn Clock>,
    pub rng: Arc<dyn Rng>,
    pub trigger: Arc<PruneTrigger>,
    /// Pruned inline once enough rows are in, so a burst of diagnostics keeps
    /// the table inside its bound without waiting for the prune task.
    pub pruner: Option<Pruner>,
}

impl DiagnosticWriter {
    async fn write(&self, ev: Event, since_sync: &mut u64) {
        let kind = ev.kind;
        match self.events.append_diagnostic(ev).await {
            Ok(()) => {
                self.trigger.note_insert();
                *since_sync += 1;
                // The store batches queued diagnostics in one transaction; flush
                // in chunks no larger than the prune trigger so a prune can
                // interleave before the table passes its bound.
                if *since_sync >= self.trigger.threshold() {
                    *since_sync = 0;
                    let _ = self.store.barrier().await;
                    if let Some(p) = &self.pruner
                        && p.due()
                        && let Err(e) = p.run_once().await
                    {
                        tracing::warn!(error = %e, "event prune failed");
                    }
                }
            }
            Err(_) => self.drops.record(kind),
        }
    }

    async fn release_due(&self, since_sync: &mut u64) {
        for ev in self.sampler.drain_due(self.clock.now()) {
            self.write(ev, since_sync).await;
        }
    }

    /// Write one `events.dropped` event for the drops since the last report.
    async fn report_drops(&self) {
        let counts = self.drops.take();
        if counts.is_empty() {
            return;
        }
        let total: u64 = counts.values().sum();
        let by_kind: serde_json::Map<String, serde_json::Value> = counts
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).into()))
            .collect();
        let ev = EventBuilder::new(
            &*self.clock,
            &*self.rng,
            EventKind::EventsDropped,
            Outcome::Info,
            "events",
        )
        .attr("dropped", total)
        .attr("dropped_by_kind", serde_json::Value::Object(by_kind))
        .build();
        counters::inc(
            counters::EVENTS_TOTAL,
            &[("kind", "events.dropped"), ("outcome", "info")],
        );
        if self.events.append_diagnostic(ev).await.is_err() {
            // Keep the counts for the next report; the metric already has them.
            self.drops.restore(counts);
        }
    }

    /// Run until `stop` flips to `true` (or its sender is dropped), then flush.
    pub async fn run(mut self, mut stop: watch::Receiver<bool>) {
        let mut tick = tokio::time::interval(HOUSEKEEPING);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut last_report = Instant::now();
        let mut since_sync = 0u64;
        loop {
            tokio::select! {
                _ = crate::event::bus::stopped(&mut stop) => break,
                got = self.rx.recv() => match got {
                    Some(ev) => self.write(ev, &mut since_sync).await,
                    None => break,
                },
                _ = tick.tick() => {
                    self.release_due(&mut since_sync).await;
                    if last_report.elapsed() >= REPORT_EVERY {
                        self.report_drops().await;
                        last_report = Instant::now();
                    }
                }
            }
        }
        while let Ok(ev) = self.rx.try_recv() {
            self.write(ev, &mut since_sync).await;
        }
        for ev in self.sampler.drain_all() {
            self.write(ev, &mut since_sync).await;
        }
        self.report_drops().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{OsRng, TestClock, Timestamp};
    use crate::event::bus::{Emitter, channel};
    use crate::event::prune::PruneTrigger;
    use crate::event::types::reasons;
    use crate::store::{Store, StoreHooks, types::EventQuery};

    #[tokio::test(flavor = "multi_thread")]
    async fn a_stalled_store_drops_diagnostics_and_reports_them_by_kind() {
        let dir = tempfile::tempdir().unwrap();
        let clock = Arc::new(TestClock::new(Timestamp(1_800_000_000_000)));
        let hooks = Arc::new(StoreHooks::new());
        let store = Store::open(
            &dir.path().join("t.db"),
            clock.clone(),
            vec!["log".into()],
            Some(hooks.clone()),
        )
        .unwrap();
        let (bus, rx) = channel(100);
        let sampler = Arc::new(Sampler::default());
        let em = Emitter::new(
            clock.clone(),
            Arc::new(OsRng),
            bus,
            sampler.clone(),
            Arc::new(PruneTrigger::new(1000)),
            false,
        );
        let (stop_tx, stop_rx) = watch::channel(false);
        let writer = DiagnosticWriter {
            store: store.clone(),
            events: store.events(),
            rx,
            drops: em.drops().clone(),
            sampler,
            clock: clock.clone(),
            rng: Arc::new(OsRng),
            trigger: Arc::new(PruneTrigger::new(1000)),
            pruner: None,
        };
        let task = tokio::spawn(writer.run(stop_rx));
        hooks.set_stall(300);
        for _ in 0..1000 {
            em.diagnostic(EventKind::ProviderError, Outcome::Failure, "r", |b| {
                b.reason(reasons::PROVIDER_TIMEOUT)
            });
        }
        hooks.set_stall(0);
        tokio::time::sleep(Duration::from_millis(1500)).await;
        stop_tx.send(true).unwrap();
        task.await.unwrap();
        store.barrier().await.unwrap();
        let dropped = store
            .events()
            .query(EventQuery {
                kind: Some(EventKind::EventsDropped),
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(!dropped.is_empty(), "no events.dropped row");
        let total: u64 = dropped
            .iter()
            .map(|e| e.attrs["dropped"].as_u64().unwrap())
            .sum();
        assert!(total > 0);
        let by_kind: u64 = dropped
            .iter()
            .map(|e| {
                e.attrs["dropped_by_kind"]["provider.error"]
                    .as_u64()
                    .unwrap_or(0)
            })
            .sum();
        assert_eq!(total, by_kind);
        let kept = store
            .events()
            .query(EventQuery {
                kind: Some(EventKind::ProviderError),
                limit: Some(10_000),
                ..Default::default()
            })
            .await
            .unwrap()
            .len() as u64;
        assert_eq!(
            kept + total,
            1000,
            "every diagnostic is either kept or counted"
        );
    }
}
