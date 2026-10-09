//! The in-process event front door. [`Emitter`] is the one object the other
//! M1 tasks use: it builds events with the process clock and RNG, counts them,
//! and hands diagnostic ones to a bounded queue drained by the batch writer
//! ([`crate::event::diagnostic`]). Required events are only *built* here; the
//! caller attaches them to the store call that makes the state change, so they
//! commit with it (transactional outbox, ADR-0009).

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use tokio::sync::mpsc;

use crate::crypto::{Clock, Rng};
use crate::event::prune::PruneTrigger;
use crate::event::sampling::{Observed, Sampler, Scope};
use crate::event::types::{Event, EventBuilder, EventKind, Outcome, Reason};
use crate::telemetry::counters;

/// Completes when the stop flag flips to `true` (or its sender is gone).
/// A plain `async fn` so the watch guard never lives across a caller's await.
pub(crate) async fn stopped(rx: &mut tokio::sync::watch::Receiver<bool>) {
    let _ = rx.wait_for(|s| *s).await;
}

/// Capacity of the diagnostic queue.
pub const BUS_CAPACITY: usize = 1024;

/// Diagnostic events lost before they reached the store, by kind name.
#[derive(Default)]
pub struct DropCounts(Mutex<BTreeMap<&'static str, u64>>);

impl DropCounts {
    pub fn record(&self, kind: EventKind) {
        self.record_n(kind, 1);
    }

    pub fn record_n(&self, kind: EventKind, n: u64) {
        let mut m = self.0.lock().unwrap_or_else(|p| p.into_inner());
        *m.entry(kind.name()).or_insert(0) += n;
        counters::add(counters::EVENTS_DROPPED_TOTAL, &[("kind", kind.name())], n);
    }

    /// Take and reset the counts.
    pub fn take(&self) -> BTreeMap<&'static str, u64> {
        std::mem::take(&mut *self.0.lock().unwrap_or_else(|p| p.into_inner()))
    }

    /// Put counts back (a report that could not be written).
    pub fn restore(&self, counts: BTreeMap<&'static str, u64>) {
        let mut m = self.0.lock().unwrap_or_else(|p| p.into_inner());
        for (k, v) in counts {
            *m.entry(k).or_insert(0) += v;
        }
    }

    pub fn total(&self) -> u64 {
        self.0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .values()
            .sum()
    }
}

/// Sender side of the bounded diagnostic queue.
#[derive(Clone)]
pub struct Bus {
    tx: mpsc::Sender<Event>,
    drops: Arc<DropCounts>,
}

/// A new queue of `capacity` events and its receiving end.
pub fn channel(capacity: usize) -> (Bus, mpsc::Receiver<Event>) {
    let (tx, rx) = mpsc::channel(capacity.max(1));
    (
        Bus {
            tx,
            drops: Arc::new(DropCounts::default()),
        },
        rx,
    )
}

impl Bus {
    /// Queue without waiting; a full queue (or a stopped writer) counts a drop.
    pub fn submit(&self, ev: Event) {
        let kind = ev.kind;
        if self.tx.try_send(ev).is_err() {
            self.drops.record(kind);
        }
    }

    pub fn drops(&self) -> &Arc<DropCounts> {
        &self.drops
    }
}

struct Inner {
    clock: Arc<dyn Clock>,
    rng: Arc<dyn Rng>,
    bus: Bus,
    sampler: Arc<Sampler>,
    trigger: Arc<PruneTrigger>,
    accept_client_request_id: bool,
}

/// Builds events and routes diagnostic ones to the batch writer.
#[derive(Clone)]
pub struct Emitter {
    inner: Arc<Inner>,
}

impl Emitter {
    pub fn new(
        clock: Arc<dyn Clock>,
        rng: Arc<dyn Rng>,
        bus: Bus,
        sampler: Arc<Sampler>,
        trigger: Arc<PruneTrigger>,
        accept_client_request_id: bool,
    ) -> Self {
        Emitter {
            inner: Arc::new(Inner {
                clock,
                rng,
                bus,
                sampler,
                trigger,
                accept_client_request_id,
            }),
        }
    }

    pub fn clock(&self) -> &Arc<dyn Clock> {
        &self.inner.clock
    }

    pub fn rng(&self) -> &Arc<dyn Rng> {
        &self.inner.rng
    }

    /// A plain builder with the process clock and RNG (no counting, no routing).
    pub fn builder(
        &self,
        kind: EventKind,
        outcome: Outcome,
        request_id: impl Into<String>,
    ) -> EventBuilder {
        EventBuilder::new(
            &*self.inner.clock,
            &*self.inner.rng,
            kind,
            outcome,
            request_id,
        )
    }

    /// Build a required event for the caller to pass to a store call that
    /// carries `events: Vec<Event>`. `build` adds the fields. The event is
    /// counted when built and the prune trigger is told a row is coming.
    pub fn required(
        &self,
        kind: EventKind,
        outcome: Outcome,
        request_id: impl Into<String>,
        build: impl FnOnce(EventBuilder) -> EventBuilder,
    ) -> Event {
        debug_assert!(kind.is_required(), "{} is a diagnostic kind", kind.name());
        let ev = build(self.builder(kind, outcome, request_id)).build();
        counters::inc(
            counters::EVENTS_TOTAL,
            &[("kind", kind.name()), ("outcome", outcome.as_str())],
        );
        self.inner.trigger.note_insert();
        ev
    }

    /// Build and queue a diagnostic event; never blocks, never fails.
    pub fn diagnostic(
        &self,
        kind: EventKind,
        outcome: Outcome,
        request_id: impl Into<String>,
        build: impl FnOnce(EventBuilder) -> EventBuilder,
    ) {
        debug_assert!(!kind.is_required(), "{} is a required kind", kind.name());
        let ev = build(self.builder(kind, outcome, request_id)).build();
        counters::inc(
            counters::EVENTS_TOTAL,
            &[("kind", kind.name()), ("outcome", outcome.as_str())],
        );
        self.inner.bus.submit(ev);
    }

    /// Record a verify denial: always counted, and sampled to one event per
    /// (`scope`, `reason`) per window with `attrs.sampled_count` on the row.
    pub fn verify_denied(
        &self,
        scope: Scope,
        reason: Reason,
        request_id: impl Into<String>,
        build: impl FnOnce(EventBuilder) -> EventBuilder,
    ) {
        counters::inc(counters::VERIFY_DENIED_TOTAL, &[("reason", reason.0)]);
        let now = self.inner.clock.now();
        let request_id = request_id.into();
        let (seen, ready) = self.inner.sampler.observe(scope, reason, now, || {
            counters::inc(
                counters::EVENTS_TOTAL,
                &[("kind", "verify.denied"), ("outcome", "failure")],
            );
            build(
                self.builder(EventKind::VerifyDenied, Outcome::Failure, request_id)
                    .reason(reason),
            )
            .build()
        });
        for ev in ready {
            self.inner.bus.submit(ev);
        }
        if seen == Observed::Overflow {
            self.inner.bus.drops().record(EventKind::VerifyDenied);
        }
    }

    /// Add the client-supplied `x-request-id` to `b` as `attrs.client_request_id`
    /// when `log.accept_client_request_id` is on; otherwise return `b` unchanged.
    pub fn with_client_request_id(&self, b: EventBuilder, client: Option<&str>) -> EventBuilder {
        match client {
            Some(v) if self.inner.accept_client_request_id => b.attr("client_request_id", v),
            _ => b,
        }
    }

    pub fn drops(&self) -> &Arc<DropCounts> {
        self.inner.bus.drops()
    }

    pub fn sampler(&self) -> &Arc<Sampler> {
        &self.inner.sampler
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{SeededRng, TestClock, Timestamp};
    use crate::event::types::reasons;

    fn emitter(cap: usize, accept: bool) -> (Emitter, mpsc::Receiver<Event>, Arc<TestClock>) {
        let clock = Arc::new(TestClock::new(Timestamp(1_000_000)));
        let (bus, rx) = channel(cap);
        let e = Emitter::new(
            clock.clone(),
            Arc::new(SeededRng::new(3)),
            bus,
            Arc::new(Sampler::default()),
            Arc::new(PruneTrigger::new(1000)),
            accept,
        );
        (e, rx, clock)
    }

    #[test]
    fn a_full_queue_drops_and_counts_by_kind() {
        let (e, mut rx, _) = emitter(2, false);
        for _ in 0..5 {
            e.diagnostic(EventKind::ProviderError, Outcome::Failure, "r", |b| {
                b.reason(reasons::PROVIDER_TIMEOUT)
            });
        }
        assert_eq!(e.drops().total(), 3);
        assert_eq!(e.drops().take().get("provider.error"), Some(&3));
        assert!(rx.try_recv().is_ok() && rx.try_recv().is_ok() && rx.try_recv().is_err());
    }

    #[test]
    fn denials_are_all_counted_but_sampled() {
        let (e, mut rx, clock) = emitter(8, false);
        let ip: std::net::IpAddr = "198.51.100.7".parse().unwrap();
        let before = counters::get(
            counters::VERIFY_DENIED_TOTAL,
            &[("reason", "unknown_handle")],
        );
        for _ in 0..100 {
            e.verify_denied(Scope::Ip(ip), reasons::UNKNOWN_HANDLE, "r", |b| b.ip(ip));
        }
        assert_eq!(
            counters::get(
                counters::VERIFY_DENIED_TOTAL,
                &[("reason", "unknown_handle")]
            ) - before,
            100
        );
        assert!(rx.try_recv().is_err(), "held until the window closes");
        clock.advance(std::time::Duration::from_secs(61));
        let out = e.sampler().drain_due(crate::crypto::Clock::now(&*clock));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].attrs["sampled_count"], 100);
        assert_eq!(out[0].reason, Some(reasons::UNKNOWN_HANDLE));
    }

    #[test]
    fn client_request_id_is_recorded_only_when_enabled() {
        for (accept, present) in [(false, false), (true, true)] {
            let (e, _rx, _) = emitter(2, accept);
            let ev = e
                .with_client_request_id(
                    e.builder(EventKind::LoginStarted, Outcome::Info, "own-id"),
                    Some("evil"),
                )
                .build();
            assert_eq!(ev.request_id, "own-id");
            assert_eq!(ev.attrs.contains_key("client_request_id"), present);
        }
    }

    #[test]
    fn required_events_are_built_with_ordered_unique_ids() {
        let (e, _rx, clock) = emitter(2, false);
        let a = e.required(EventKind::LoginStarted, Outcome::Info, "r", |b| b);
        clock.advance(std::time::Duration::from_millis(1));
        let b = e.required(EventKind::LoginStarted, Outcome::Info, "r", |b| b);
        assert!(a.event_id < b.event_id);
    }
}
