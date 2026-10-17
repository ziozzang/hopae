//! The application-owned pump that turns workload lifecycle signals into
//! events: `workload.principal_observed`, `workload.principal_retired` and
//! `workload.legacy_subject_mapped` are required (outbox) events and the
//! sources of the subject lifecycle feed's workload changes;
//! `workload.keys_rotated` and `workload.revocation_stale` are diagnostics.
use super::metrics;
use super::signals::{Signal, WorkloadRef};
use crate::event::bus::Emitter;
use crate::event::types::{EventBuilder, EventKind, Outcome};

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
    store: crate::store::sqlite::Store,
) {
    use crate::store::sqlite::workloads::WorkloadChange;
    let mut buffer = Vec::with_capacity(BATCH);
    while rx.recv_many(&mut buffer, BATCH).await > 0 {
        let mut required = Vec::new();
        let mut kinds = Vec::new();
        let mut changes = Vec::new();
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
                    changes.push(WorkloadChange::Observed(w));
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
                    changes.push(WorkloadChange::Retired {
                        workload: w,
                        cause,
                        replacement,
                    });
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
                    changes.push(WorkloadChange::LegacyMapped {
                        workload: w,
                        legacy_subject_ref,
                    });
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
        // The registry rows and their events commit together.
        let result = store.workload_record(changes, required).await;
        for kind in kinds {
            metrics::signal(kind, if result.is_ok() { "recorded" } else { "failed" });
        }
        if let Err(error) = result {
            tracing::warn!(%error, "workload lifecycle events could not be recorded");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth_gateway::workload::signals::{self, Signal, WorkloadRef};
    use crate::crypto::{SeededRng, TestClock, Timestamp};
    use crate::event::bus;
    use crate::event::prune::PruneTrigger;
    use crate::event::sampling::Sampler;
    use crate::store::sqlite::Store;
    use crate::store::sqlite::subject_directory::OutboxPosition;
    use crate::store::types::Deadline;
    use std::sync::Arc;

    fn workload(uid: &str) -> WorkloadRef {
        WorkloadRef {
            service: "orders".into(),
            principal: crate::auth_gateway::workload::identity::principal_ref(
                "https://issuer.example.test",
                "example-cluster",
                "blue",
                "worker",
                uid,
            ),
            subject_ref: format!("s_{}", "a".repeat(48)),
            spiffe_id: Some("spiffe://cluster.example.test/ns/blue/sa/worker".into()),
            cluster_id: "example-cluster".into(),
            namespace: "blue".into(),
            service_account: "worker".into(),
            service_account_uid: uid.into(),
        }
    }

    /// S900-8: lifecycle signals become outbox events and the subject
    /// lifecycle feed reports them only with `include_workloads`.
    #[tokio::test]
    async fn s900_8_signals_become_lifecycle_feed_changes() {
        let dir = tempfile::tempdir().unwrap();
        let clock = Arc::new(TestClock::new(Timestamp(1_700_000_000_000)));
        let store = Store::open(
            &dir.path().join("hopae.db"),
            clock.clone(),
            vec!["log".to_string()],
            None,
        )
        .unwrap();
        let (bus, _rx) = bus::channel(16);
        let emitter = Emitter::new(
            clock,
            Arc::new(SeededRng::new(7)),
            bus,
            Arc::new(Sampler::default()),
            Arc::new(PruneTrigger::new(1000)),
            false,
        );
        let (sink, rx) = signals::channel();
        let pump = tokio::spawn(pump(rx, emitter, store.clone()));
        sink.emit(Signal::Observed(workload("sa-1")));
        sink.emit(Signal::LegacyMapped {
            workload: workload("sa-1"),
            legacy_subject_ref: format!("s_{}", "b".repeat(48)),
        });
        sink.emit(Signal::KeysRotated {
            service: "orders".into(),
            added: 1,
            removed: 0,
        });
        sink.emit(Signal::Retired {
            workload: workload("sa-1"),
            cause: "uid_changed",
            replacement: Some(workload("sa-2").principal),
        });
        drop(sink);
        pump.await.unwrap();
        let deadline = || Deadline(std::time::Instant::now() + std::time::Duration::from_secs(5));
        let start = OutboxPosition {
            row: 0,
            event_id: None,
        };
        let page = store
            .admin_feed_changes(start.clone(), 100, false, true, deadline())
            .await
            .unwrap()
            .unwrap();
        let changes: Vec<_> = page.changes.iter().map(|c| c.change).collect();
        assert_eq!(
            changes,
            vec![
                "workload_observed",
                "workload_legacy_mapped",
                "workload_retired"
            ]
        );
        let retired = page.changes[2].workload.as_ref().unwrap();
        assert_eq!(retired["principal"], workload("sa-1").principal.as_str());
        assert_eq!(retired["cause"], "uid_changed");
        assert_eq!(retired["replacement"], workload("sa-2").principal.as_str());
        assert_eq!(
            retired["spiffe_id"],
            "spiffe://cluster.example.test/ns/blue/sa/worker"
        );
        assert!(
            page.changes
                .iter()
                .all(|c| c.user_id.is_none() && c.group_id.is_none())
        );
        let mapped = page.changes[1].workload.as_ref().unwrap();
        assert_eq!(
            mapped["legacy_subject_ref"],
            format!("s_{}", "b".repeat(48))
        );
        // Without the option the feed is unchanged for existing consumers.
        let page = store
            .admin_feed_changes(start, 100, true, false, deadline())
            .await
            .unwrap()
            .unwrap();
        assert!(page.changes.is_empty());
    }

    /// S900-12: the registry keeps live and retired principals with their
    /// legacy subjects for the workload snapshot; retirement is final.
    #[tokio::test]
    async fn s900_12_registry_snapshot_survives_outbox_retention() {
        let dir = tempfile::tempdir().unwrap();
        let clock = Arc::new(TestClock::new(Timestamp(1_700_000_000_000)));
        let store = Store::open(&dir.path().join("hopae.db"), clock.clone(), vec![], None).unwrap();
        let (bus, _rx) = bus::channel(16);
        let emitter = Emitter::new(
            clock,
            Arc::new(SeededRng::new(7)),
            bus,
            Arc::new(Sampler::default()),
            Arc::new(PruneTrigger::new(1000)),
            false,
        );
        let (sink, rx) = signals::channel();
        let pump = tokio::spawn(pump(rx, emitter, store.clone()));
        let legacy = format!("s_{}", "c".repeat(48));
        sink.emit(Signal::Observed(workload("sa-1")));
        sink.emit(Signal::LegacyMapped {
            workload: workload("sa-1"),
            legacy_subject_ref: legacy.clone(),
        });
        sink.emit(Signal::Retired {
            workload: workload("sa-1"),
            cause: "uid_changed",
            replacement: Some(workload("sa-2").principal),
        });
        sink.emit(Signal::Observed(workload("sa-2")));
        // A late observation of the retired incarnation never revives it.
        sink.emit(Signal::Observed(workload("sa-1")));
        drop(sink);
        pump.await.unwrap();
        // Outbox retention removes the events; the registry remains.
        store
            .conn()
            .execute_batch("DELETE FROM event_deliveries; DELETE FROM events;")
            .unwrap();
        let deadline = || Deadline(std::time::Instant::now() + std::time::Duration::from_secs(5));
        let rows = store
            .workload_snapshot_after(0, 10, deadline())
            .await
            .unwrap();
        assert_eq!(rows.len(), 2);
        let old = &rows[0];
        assert_eq!(old.principal, workload("sa-1").principal);
        assert_eq!(old.status, "retired");
        assert_eq!(old.cause.as_deref(), Some("uid_changed"));
        assert_eq!(old.replacement, Some(workload("sa-2").principal));
        assert_eq!(old.legacy_subject_refs, vec![legacy]);
        assert_eq!(
            old.spiffe_id.as_deref(),
            Some("spiffe://cluster.example.test/ns/blue/sa/worker")
        );
        assert_eq!(rows[1].status, "active");
        // Pagination by position.
        let page = store
            .workload_snapshot_after(rows[0].position, 1, deadline())
            .await
            .unwrap();
        assert_eq!(page.len(), 1);
        assert_eq!(page[0].principal, workload("sa-2").principal);
        // The schema itself refuses un-retiring.
        assert!(
            store
                .conn()
                .execute(
                    "UPDATE workload_principals SET status='active', retired_at=NULL WHERE position=?1",
                    [rows[0].position],
                )
                .is_err()
        );
    }
}
