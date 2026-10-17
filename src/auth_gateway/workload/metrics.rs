//! Workload identity metrics (no subjects, no token material in labels).
use crate::telemetry::counters;

pub(crate) fn authentication(service: &str, verification: &str, result: &str, reason: &str) {
    counters::inc(
        counters::WORKLOAD_AUTHENTICATIONS_TOTAL,
        &[
            ("service", service),
            ("verification", verification),
            ("result", result),
            ("reason", reason),
        ],
    );
}

pub(crate) fn cache(service: &str, result: &str) {
    counters::inc(
        counters::WORKLOAD_CACHE_TOTAL,
        &[("service", service), ("result", result)],
    );
}

pub(crate) fn cache_entries(service: &str, entries: usize) {
    counters::set(
        counters::WORKLOAD_CACHE_ENTRIES,
        &[("service", service)],
        entries as i64,
    );
}

pub(crate) fn jwks_fetch(service: &str, result: &str) {
    counters::inc(
        counters::WORKLOAD_JWKS_FETCH_TOTAL,
        &[("service", service), ("result", result)],
    );
}

pub(crate) fn jwks_keys(service: &str, keys: usize) {
    counters::set(
        counters::WORKLOAD_JWKS_KEYS,
        &[("service", service)],
        keys as i64,
    );
}

pub(crate) fn revocation_event(service: &str, resource: &str, event: &str) {
    counters::inc(
        counters::WORKLOAD_REVOCATION_EVENTS_TOTAL,
        &[
            ("service", service),
            ("resource", resource),
            ("event", event),
        ],
    );
}

pub(crate) fn revocation_staleness(service: &str, ms: u64) {
    counters::set(
        counters::WORKLOAD_REVOCATION_STALENESS_MS,
        &[("service", service)],
        ms.min(i64::MAX as u64) as i64,
    );
}

pub(crate) fn signal(kind: &str, result: &str) {
    counters::inc(
        counters::WORKLOAD_SIGNALS_TOTAL,
        &[("kind", kind), ("result", result)],
    );
}
