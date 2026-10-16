//! The application-owned pump that turns workload lifecycle signals into
//! events: `workload.principal_observed`, `workload.principal_retired` and
//! `workload.legacy_subject_mapped` are required (outbox) events and the
//! sources of the subject lifecycle feed's workload changes;
//! `workload.keys_rotated` and `workload.revocation_stale` are diagnostics.
use super::metrics;
use super::signals::{Signal, WorkloadRef};
use crate::event::bus::Emitter;
use crate::event::types::{EventBuilder, EventKind, Outcome};
use crate::store::Events;
use std::sync::Arc;

const BATCH: usize = 64;

fn workload(b: EventBuilder, w: &WorkloadRef) -> EventBuilder {
    let b = b
        .attr("service", w.service.as_str())
        .attr("principal", w.principal.as_str())
        .attr("subject_ref", w.subject_ref.as_str())
        .attr("cluster", w.cluster_id.as_str())
        .attr("namespace", w.namespace.as_str())
        .attr("service_account", w.service_account.as_str())
        .attr("service_account_uid", w.service_account_uid.as_str());
    match &w.spiffe_id {
        Some(id) => b.attr("spiffe_id", id.as_str()),
        None => b,
    }
}

/// Run until every sink is dropped.
pub async fn pump(
    mut rx: tokio::sync::mpsc::Receiver<Signal>,
    emitter: Emitter,
    events: Arc<dyn Events>,
) {
    let mut buffer = Vec::with_capacity(BATCH);
    while rx.recv_many(&mut buffer, BATCH).await > 0 {
        let mut required = Vec::new();
        let mut kinds = Vec::new();
        for signal in buffer.drain(..) {
            let kind = signal.kind();
            match signal {
                Signal::Observed(w) => {
                    required.push(emitter.required(
                        EventKind::WorkloadPrincipalObserved,
                        Outcome::Info,
                        "workload-lifecycle",
                        |b| workload(b, &w).attr("status", "active"),
                    ));
                    kinds.push(kind);
                }
                Signal::Retired {
                    workload: w,
                    cause,
                    replacement,
                } => {
                    required.push(emitter.required(
                        EventKind::WorkloadPrincipalRetired,
                        Outcome::Info,
                        "workload-lifecycle",
                        |b| {
                            let b = workload(b, &w)
                                .attr("cause", cause)
                                .attr("status", "retired");
                            match &replacement {
                                Some(r) => b.attr("replacement", r.as_str()),
                                None => b,
                            }
                        },
                    ));
                    kinds.push(kind);
                }
                Signal::LegacyMapped {
                    workload: w,
                    legacy_subject_ref,
                } => {
                    required.push(emitter.required(
                        EventKind::WorkloadLegacySubjectMapped,
                        Outcome::Info,
                        "workload-lifecycle",
                        |b| workload(b, &w).attr("legacy_subject_ref", legacy_subject_ref.as_str()),
                    ));
                    kinds.push(kind);
                }
                Signal::KeysRotated {
                    service,
                    added,
                    removed,
                } => emitter.diagnostic(
                    EventKind::WorkloadKeysRotated,
                    Outcome::Info,
                    "workload-lifecycle",
                    |b| {
                        b.attr("service", service.as_str())
                            .attr("keys_added", added as u64)
                            .attr("keys_removed", removed as u64)
                    },
                ),
                Signal::RevocationStale { service, stale } => emitter.diagnostic(
                    EventKind::WorkloadRevocationStale,
                    if stale {
                        Outcome::Failure
                    } else {
                        Outcome::Info
                    },
                    "workload-lifecycle",
                    |b| b.attr("service", service.as_str()).attr("stale", stale),
                ),
            }
        }
        if required.is_empty() {
            continue;
        }
        let result = events.append_required(required).await;
        for kind in kinds {
            metrics::signal(kind, if result.is_ok() { "recorded" } else { "failed" });
        }
        if let Err(error) = result {
            tracing::warn!(%error, "workload lifecycle events could not be recorded");
        }
    }
}
