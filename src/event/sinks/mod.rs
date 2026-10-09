//! Delivery sinks: where a durable event goes after it is committed.

pub mod log;

use async_trait::async_trait;

use crate::event::types::Event;

pub use log::LogSink;

/// A delivery target. `deliver` returns `Ok` only once the receiver has the
/// event; an `Err` carries a short reason keyword (never remote text).
#[async_trait]
pub trait Sink: Send + Sync {
    /// The sink name stored in `event_deliveries.sink`.
    fn name(&self) -> &str;
    async fn deliver(&self, event: &Event) -> Result<(), String>;
}
