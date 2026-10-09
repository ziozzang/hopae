//! Telemetry: tracing setup (M0) and the counters module (M1). Prometheus
//! exposition arrives in M7.

pub mod counters;
pub mod output;

use tracing_subscriber::EnvFilter;

/// Install the global tracing subscriber writing to stderr. `level` is a
/// validated level name from the configuration.
pub fn init(level: &str) {
    init_with(level, output::Output::global());
}

/// As [`init`] with an explicit output (tests). `true` when this call
/// installed the subscriber.
pub fn init_with(level: &str, out: &std::sync::Arc<output::Output>) -> bool {
    let filter = EnvFilter::try_new(level).unwrap_or_else(|_| EnvFilter::new("info"));
    // The error means a subscriber is already installed (tests): ignore it.
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(out.make_writer())
        .try_init()
        .is_ok()
}
