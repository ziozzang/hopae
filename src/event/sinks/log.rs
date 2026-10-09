//! The structured-log sink: one JSON line per event on stderr, the same
//! fields as the `events` row (`Event::to_json`). The line carries
//! identifiers and reason codes only; `EventBuilder` has already bounded and
//! allowlisted everything that gets here.

use std::io::Write;
use std::sync::Arc;

use async_trait::async_trait;

use super::Sink;
use crate::event::types::Event;
use crate::store::StoreHooks;
use crate::telemetry::counters;
use crate::telemetry::output::Output;

/// Name of the log sink in `event_deliveries`.
pub const NAME: &str = "log";

pub struct LogSink {
    out: Arc<Output>,
    hooks: Option<Arc<StoreHooks>>,
}

impl LogSink {
    /// A sink writing to `out` through an output thread of its own.
    pub fn new(out: Box<dyn Write + Send>, hooks: Option<Arc<StoreHooks>>) -> Self {
        LogSink {
            out: Output::spawn(out, 1024),
            hooks,
        }
    }

    /// A sink on the process-wide stderr output, shared with the tracing lines.
    pub fn stderr(hooks: Option<Arc<StoreHooks>>) -> Self {
        LogSink {
            out: Output::global().clone(),
            hooks,
        }
    }

    /// Queue `event`'s line, best effort and never blocking: a diagnostic event
    /// that reached the store also reaches the log, without a delivery row
    /// (ADR-0009). A line that does not fit is dropped and counted.
    pub fn emit(&self, event: &Event) {
        let mut line = Self::line(event);
        line.push('\n');
        if !self.out.try_line(line.into_bytes(), None) {
            counters::inc(counters::EVENTS_LOG_DROPPED_TOTAL, &[]);
        }
    }

    /// The line written for `event`, without the newline. `serde_json`
    /// escapes control characters, so it is always exactly one line.
    pub fn line(event: &Event) -> String {
        event.to_json().to_string()
    }
}

#[async_trait]
impl Sink for LogSink {
    fn name(&self) -> &str {
        NAME
    }

    /// Hand the line to the output thread. A full queue is a retryable
    /// failure: the delivery stays pending and is retried with backoff, so
    /// delivery stays at-least-once. No thread is parked per attempt.
    async fn deliver(&self, event: &Event) -> Result<(), String> {
        let mut line = Self::line(event);
        line.push('\n');
        // Test hook: die between writing the line and marking the row
        // delivered; the output thread triggers it once the line is out.
        if self.out.try_line(line.into_bytes(), self.hooks.clone()) {
            Ok(())
        } else {
            Err("log_queue_full".to_string())
        }
    }
}
