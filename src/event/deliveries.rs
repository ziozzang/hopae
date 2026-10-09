//! Delivery workers: claim pending `event_deliveries` rows for one sink,
//! deliver, mark. At-least-once: a worker that dies between delivering and
//! marking leaves the row claimed; the lease runs out and the row is handed
//! out again, so the receiver may see an event twice and deduplicates by
//! `event_id`. There is no cursor over event ids, so a transaction that
//! commits late is never skipped (ADR-0009).

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;

use crate::crypto::Clock;
use crate::event::sinks::Sink;
use crate::event::types::reasons;
use crate::store::Events;
use crate::telemetry::counters;

/// Deliveries claimed per round.
const BATCH: usize = 32;
/// One delivery attempt may take this long before it counts as failed.
const DELIVER_TIMEOUT: Duration = Duration::from_secs(5);
/// Sleep when a round found nothing due.
const IDLE_POLL: Duration = Duration::from_millis(200);
/// Retries stop once their cumulative wait would pass this.
const RETRY_BUDGET: Duration = Duration::from_secs(24 * 3600);
const MAX_BACKOFF: Duration = Duration::from_secs(3600);

pub struct DeliveryWorker {
    events: Arc<dyn Events>,
    sink: Arc<dyn Sink>,
    clock: Arc<dyn Clock>,
}

fn backoff(failures: u32) -> Duration {
    let exp = failures.saturating_sub(1).min(20);
    Duration::from_secs(1u64 << exp).min(MAX_BACKOFF)
}

/// Wait before the next attempt after `attempts` attempts have failed
/// (exponential from 1 s, capped at 1 h); `None` once the cumulative wait
/// passes the 24 h budget of ADR-0009.
pub fn retry_delay(attempts: u32) -> Option<Duration> {
    let attempts = attempts.max(1);
    let spent: Duration = (1..=attempts).map(backoff).sum();
    (spent <= RETRY_BUDGET).then(|| backoff(attempts))
}

impl DeliveryWorker {
    pub fn new(events: Arc<dyn Events>, sink: Arc<dyn Sink>, clock: Arc<dyn Clock>) -> Self {
        DeliveryWorker {
            events,
            sink,
            clock,
        }
    }

    /// Claim and deliver one batch; returns how many rows were claimed.
    /// Cancel-safe: dropping the future between claim and mark leaves rows
    /// claimed (retried after the lease), never lost.
    pub async fn run_once(&self) -> usize {
        let sink = self.sink.name().to_string();
        let claimed = match self
            .events
            .claim_deliveries(&sink, BATCH, self.clock.now())
            .await
        {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(sink = %sink, error = %e, "claiming event deliveries failed");
                return 0;
            }
        };
        let n = claimed.len();
        for d in claimed {
            let id = d.event.event_id.clone();
            let result =
                match tokio::time::timeout(DELIVER_TIMEOUT, self.sink.deliver(&d.event)).await {
                    Ok(r) => r,
                    Err(_) => Err("timeout".to_string()),
                };
            let marked = match result {
                Ok(()) => {
                    counters::inc(
                        counters::EVENT_DELIVERIES_DELIVERED_TOTAL,
                        &[("sink", &sink)],
                    );
                    self.events
                        .mark_delivered(&sink, &id, self.clock.now())
                        .await
                }
                Err(why) => match retry_delay(d.attempts) {
                    Some(delay) => {
                        self.events
                            .mark_failed(&sink, &id, &why, Some(self.clock.now().add(delay)))
                            .await
                    }
                    None => {
                        counters::inc(
                            counters::EVENT_DELIVERIES_FAILED_TOTAL,
                            &[("sink", &sink), ("reason", reasons::RETRIES_EXHAUSTED.0)],
                        );
                        self.events
                            .mark_failed(&sink, &id, reasons::RETRIES_EXHAUSTED.0, None)
                            .await
                    }
                },
            };
            if let Err(e) = marked {
                tracing::warn!(sink = %sink, error = %e, "marking an event delivery failed");
            }
        }
        n
    }

    /// Deliver until `stop` flips to `true`.
    pub async fn run(self, mut stop: watch::Receiver<bool>) {
        loop {
            if *stop.borrow() {
                break;
            }
            let n = self.run_once().await;
            if n == 0 {
                tokio::select! {
                    _ = tokio::time::sleep(IDLE_POLL) => {}
                    _ = crate::event::bus::stopped(&mut stop) => break,
                }
            }
        }
        // One last pass so events committed just before shutdown are delivered.
        self.run_once().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_delay_is_exponential_capped_and_bounded_to_24_hours() {
        assert_eq!(retry_delay(1), Some(Duration::from_secs(1)));
        assert_eq!(retry_delay(2), Some(Duration::from_secs(2)));
        assert_eq!(retry_delay(5), Some(Duration::from_secs(16)));
        assert_eq!(retry_delay(13), Some(Duration::from_secs(3600)));
        let last = (1..200).take_while(|n| retry_delay(*n).is_some()).last();
        let last = last.expect("some retries are allowed");
        let total: Duration = (1..=last).map(backoff).sum();
        assert!(total <= RETRY_BUDGET);
        assert!(
            total + MAX_BACKOFF > RETRY_BUDGET,
            "the budget is not wasted"
        );
        assert_eq!(retry_delay(last + 1), None);
        assert_eq!(retry_delay(10_000), None);
    }
}
