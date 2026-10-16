//! Workload lifecycle signals: what the verifiers learn that Pumgye (and any
//! other consumer of the subject lifecycle feed) must reconcile. The runtime
//! never writes the store itself; a pump owned by the application turns
//! signals into outbox events (`workload.*`, Hangang ADR 0021 orphan
//! reconciliation). Delivery is best effort with bounded memory: a full queue
//! drops and counts, and the periodic reconcile of the consumer catches up.
use super::identity::WorkloadAttributes;
use super::metrics;
use std::collections::{HashSet, VecDeque};
use std::sync::Mutex;

/// Identifiers of one workload principal; never credential material.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct WorkloadRef {
    pub service: String,
    pub principal: String,
    pub subject_ref: String,
    pub spiffe_id: Option<String>,
    pub cluster_id: String,
    pub namespace: String,
    pub service_account: String,
    pub service_account_uid: String,
}

impl WorkloadRef {
    pub(crate) fn of(service: &str, attributes: &WorkloadAttributes) -> Self {
        Self {
            service: service.to_owned(),
            principal: attributes.principal.clone(),
            subject_ref: attributes.subject_ref.clone(),
            spiffe_id: attributes.spiffe_id.clone(),
            cluster_id: attributes.cluster_id.clone(),
            namespace: attributes.namespace.clone(),
            service_account: attributes.service_account.clone(),
            service_account_uid: attributes.service_account_uid.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Signal {
    /// First authentication of a principal by this process.
    Observed(WorkloadRef),
    /// The ServiceAccount incarnation is gone: deleted, or re-created with a
    /// new UID (`replacement` names the new principal then).
    Retired {
        workload: WorkloadRef,
        cause: &'static str,
        replacement: Option<String>,
    },
    /// During the migration window: the deprecated Pod-bound subject
    /// `legacy_subject_ref` authenticated as `workload`.
    LegacyMapped {
        workload: WorkloadRef,
        legacy_subject_ref: String,
    },
    /// The issuer's signing-key set changed.
    KeysRotated {
        service: String,
        added: usize,
        removed: usize,
    },
    /// The revocation index became stale (`true`) or current again (`false`).
    RevocationStale { service: String, stale: bool },
}

impl Signal {
    pub fn kind(&self) -> &'static str {
        match self {
            Signal::Observed(_) => "observed",
            Signal::Retired { .. } => "retired",
            Signal::LegacyMapped { .. } => "legacy_mapped",
            Signal::KeysRotated { .. } => "keys_rotated",
            Signal::RevocationStale { .. } => "revocation_stale",
        }
    }
}

/// Where signals go. Cloned into every workload connector of a runtime.
#[derive(Clone, Debug)]
pub struct Sink(tokio::sync::mpsc::Sender<Signal>);

pub const CHANNEL_CAPACITY: usize = 4096;

pub fn channel() -> (Sink, tokio::sync::mpsc::Receiver<Signal>) {
    let (tx, rx) = tokio::sync::mpsc::channel(CHANNEL_CAPACITY);
    (Sink(tx), rx)
}

impl Sink {
    pub fn emit(&self, signal: Signal) {
        let kind = signal.kind();
        match self.0.try_send(signal) {
            Ok(()) => metrics::signal(kind, "queued"),
            Err(_) => metrics::signal(kind, "dropped"),
        }
    }
}

/// A bounded "seen" set: the first `insert` of a key returns true; the
/// oldest keys are forgotten beyond `capacity` (a forgotten key is reported
/// again, which consumers treat idempotently).
pub(crate) struct Seen {
    capacity: usize,
    inner: Mutex<(HashSet<String>, VecDeque<String>)>,
}

impl Seen {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            capacity,
            inner: Mutex::new((HashSet::new(), VecDeque::new())),
        }
    }
    pub(crate) fn insert(&self, key: &str) -> bool {
        let mut guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let (set, order) = &mut *guard;
        if set.contains(key) {
            return false;
        }
        if order.len() >= self.capacity
            && let Some(old) = order.pop_front()
        {
            set.remove(&old);
        }
        set.insert(key.to_owned());
        order.push_back(key.to_owned());
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn seen_is_bounded_and_reports_forgotten_keys_again() {
        let seen = Seen::new(2);
        assert!(seen.insert("a"));
        assert!(!seen.insert("a"));
        assert!(seen.insert("b"));
        assert!(seen.insert("c"));
        assert!(seen.insert("a"), "evicted keys are reported again");
    }
    #[test]
    fn full_queue_drops_instead_of_blocking() {
        let (sink, _rx) = channel();
        for _ in 0..CHANNEL_CAPACITY + 10 {
            sink.emit(Signal::RevocationStale {
                service: "orders".into(),
                stale: true,
            });
        }
    }
}
