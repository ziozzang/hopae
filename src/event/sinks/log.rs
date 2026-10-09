//! The structured-log sink: one JSON line per event on stderr, the same
//! fields as the `events` row (`Event::to_json`). The line carries
//! identifiers and reason codes only; `EventBuilder` has already bounded and
//! allowlisted everything that gets here.

use std::io::Write;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use super::Sink;
use crate::event::types::Event;
use crate::store::StoreHooks;

/// Name of the log sink in `event_deliveries`.
pub const NAME: &str = "log";

pub struct LogSink {
    out: Mutex<Box<dyn Write + Send>>,
    hooks: Option<Arc<StoreHooks>>,
}

impl LogSink {
    pub fn new(out: Box<dyn Write + Send>, hooks: Option<Arc<StoreHooks>>) -> Self {
        LogSink {
            out: Mutex::new(out),
            hooks,
        }
    }

    pub fn stderr(hooks: Option<Arc<StoreHooks>>) -> Self {
        Self::new(Box::new(std::io::stderr()), hooks)
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

    async fn deliver(&self, event: &Event) -> Result<(), String> {
        let mut line = Self::line(event);
        line.push('\n');
        {
            let mut out = self.out.lock().unwrap_or_else(|p| p.into_inner());
            out.write_all(line.as_bytes())
                .and_then(|()| out.flush())
                .map_err(|_| "write_failed".to_string())?;
        }
        // Test hook: die between writing the line and marking the row delivered.
        if let Some(h) = &self.hooks {
            h.crash_point("after_log_line");
        }
        Ok(())
    }
}
