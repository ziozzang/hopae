//! Telemetry: tracing setup (M0); metrics arrive in M7.

use tracing_subscriber::EnvFilter;

/// Install the global tracing subscriber writing to stderr. `level` is a
/// validated level name from the configuration.
pub fn init(level: &str) {
    let filter = EnvFilter::try_new(level).unwrap_or_else(|_| EnvFilter::new("info"));
    // Ignore the error when a subscriber is already installed (tests).
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}
