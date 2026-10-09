//! Process-wide counters and gauges, plain integers behind one lock. Exposed
//! as JSON through `/counters` under `--features test-hooks`; Prometheus text
//! exposition is M7. Series are keyed `name{label="value",...}` with labels in
//! the order given by the caller, so a call site must use one fixed order.

use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock};

/// Events recorded, by kind and outcome.
pub const EVENTS_TOTAL: &str = "hopae_events_total";
/// Diagnostic events dropped before they reached the store, by kind.
pub const EVENTS_DROPPED_TOTAL: &str = "hopae_events_dropped_total";
/// Diagnostic log lines dropped because the bounded logging queue was full
/// (output blocked or slower than the events).
pub const EVENTS_LOG_DROPPED_TOTAL: &str = "hopae_events_log_dropped_total";
/// Tracing log lines dropped because the bounded output channel was full.
pub const LOG_LINES_DROPPED_TOTAL: &str = "hopae_log_lines_dropped_total";
/// Writes to the log output that failed (the line was not written).
pub const LOG_WRITE_ERRORS_TOTAL: &str = "hopae_log_write_errors_total";
/// Event rows removed by the prune task.
pub const EVENTS_PRUNED_TOTAL: &str = "hopae_events_pruned_total";
/// Deliveries moved to `failed`, by sink and reason.
pub const EVENT_DELIVERIES_FAILED_TOTAL: &str = "hopae_event_deliveries_failed_total";
/// Deliveries completed, by sink.
pub const EVENT_DELIVERIES_DELIVERED_TOTAL: &str = "hopae_event_deliveries_delivered_total";
/// Every verify denial, sampled or not, by reason.
pub const VERIFY_DENIED_TOTAL: &str = "hopae_verify_denied_total";
/// Verify calls refused for a missing or wrong caller key.
pub const VERIFY_UNAUTHORIZED_TOTAL: &str = "hopae_verify_unauthorized_total";
/// Verify calls authenticated by a caller key, by slot (`current` or `next`).
pub const VERIFY_CALLER_KEY_TOTAL: &str = "hopae_verify_caller_key_total";
/// Verify decisions, by decision and reason.
pub const VERIFY_DECISIONS_TOTAL: &str = "hopae_verify_decisions_total";
/// Verify calls refused because no concurrency permit was free.
pub const VERIFY_OVERLOADED_TOTAL: &str = "hopae_verify_overloaded_total";
/// Verify calls whose canonical path disagreed with the gateway's.
pub const VERIFY_CANONICAL_MISMATCH_TOTAL: &str = "hopae_verify_canonical_mismatch_total";
/// Store failures seen on the verify path.
pub const STORE_ERRORS_TOTAL: &str = "hopae_store_errors_total";
/// Gauge: always 1, labelled with the version.
pub const BUILD_INFO: &str = "hopae_build_info";
/// Gauge: unix seconds of the last configuration load.
pub const CONFIG_LOADED_TIMESTAMP: &str = "hopae_config_loaded_timestamp";

fn table() -> &'static Mutex<BTreeMap<String, i64>> {
    static T: OnceLock<Mutex<BTreeMap<String, i64>>> = OnceLock::new();
    T.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn series(name: &str, labels: &[(&str, &str)]) -> String {
    if labels.is_empty() {
        return name.to_string();
    }
    let mut s = String::with_capacity(name.len() + 16 * labels.len());
    s.push_str(name);
    s.push('{');
    for (i, (k, v)) in labels.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str(k);
        s.push_str("=\"");
        for c in v.chars() {
            match c {
                '"' | '\\' => {
                    s.push('\\');
                    s.push(c);
                }
                '\n' => s.push_str("\\n"),
                c => s.push(c),
            }
        }
        s.push('"');
    }
    s.push('}');
    s
}

/// Add one to a counter.
pub fn inc(name: &str, labels: &[(&str, &str)]) {
    add(name, labels, 1);
}

/// Add `n` to a counter.
pub fn add(name: &str, labels: &[(&str, &str)], n: u64) {
    let n = i64::try_from(n).unwrap_or(i64::MAX);
    let mut t = table().lock().unwrap_or_else(|p| p.into_inner());
    let v = t.entry(series(name, labels)).or_insert(0);
    *v = v.saturating_add(n);
}

/// Set a gauge.
pub fn set(name: &str, labels: &[(&str, &str)], value: i64) {
    let mut t = table().lock().unwrap_or_else(|p| p.into_inner());
    t.insert(series(name, labels), value);
}

/// The current value of one series (0 when it was never touched).
pub fn get(name: &str, labels: &[(&str, &str)]) -> i64 {
    let t = table().lock().unwrap_or_else(|p| p.into_inner());
    t.get(&series(name, labels)).copied().unwrap_or(0)
}

/// Every series as a JSON object `{ "name{labels}": value }`.
pub fn snapshot() -> serde_json::Value {
    let t = table().lock().unwrap_or_else(|p| p.into_inner());
    serde_json::Value::Object(t.iter().map(|(k, v)| (k.clone(), (*v).into())).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_accumulate_per_label_set() {
        inc("test_counter_a", &[("kind", "x")]);
        add("test_counter_a", &[("kind", "x")], 4);
        inc("test_counter_a", &[("kind", "y")]);
        assert_eq!(get("test_counter_a", &[("kind", "x")]), 5);
        assert_eq!(get("test_counter_a", &[("kind", "y")]), 1);
        assert_eq!(get("test_counter_a", &[]), 0);
        set("test_gauge_a", &[], 7);
        set("test_gauge_a", &[], 9);
        assert_eq!(get("test_gauge_a", &[]), 9);
        let snap = snapshot();
        assert_eq!(snap["test_counter_a{kind=\"x\"}"], 5);
        assert_eq!(snap["test_gauge_a"], 9);
    }

    #[test]
    fn label_values_are_escaped() {
        inc("test_counter_b", &[("reason", "a\"b\\c\nd")]);
        assert_eq!(get("test_counter_b", &[("reason", "a\"b\\c\nd")]), 1);
        assert!(
            snapshot()
                .get("test_counter_b{reason=\"a\\\"b\\\\c\\nd\"}")
                .is_some()
        );
    }
}
