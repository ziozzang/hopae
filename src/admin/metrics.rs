//! `GET /metrics`: the OpenMetrics exposition on the admin listener.
//!
//! Admitted like every console read: an administrator (any role) or a
//! route-scoped service credential holding `GET /metrics` (CLI preset
//! `metrics`), always over the admin listener's mutual TLS. The answer holds
//! no subject, user id, email or address; see `docs/OPERATIONS.md`
//! (Prometheus metrics). Store-derived gauges are read with the console's
//! query budget; a store that does not answer gives `hopae_store_up 0` and
//! the process-wide series still answer.
use std::sync::Arc;

use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};

use super::{AdminState, Ctx, api};
use crate::provider::types::ProviderHealth;
use crate::telemetry::metrics::{self, gauge, label};

/// `GET /metrics`.
pub async fn get(State(st): State<Arc<AdminState>>, _ctx: Ctx) -> Response {
    let mut out = String::with_capacity(32 * 1024);
    metrics::render(&mut out);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);

    let store = st.events.status(api::deadline(&st)).await.ok();
    gauge(
        &mut out,
        "hopae_store_up",
        "1 when the store answered this scrape's status read.",
        &[(String::new(), i64::from(store.is_some()))],
    );
    if let Some(s) = &store {
        let n = |v: u64| i64::try_from(v).unwrap_or(i64::MAX);
        gauge(
            &mut out,
            "hopae_sessions_active",
            "Live (not terminated, not expired) sessions.",
            &[(String::new(), n(s.live_sessions))],
        );
        gauge(
            &mut out,
            "hopae_users",
            "Users in the directory.",
            &[(String::new(), n(s.users))],
        );
        gauge(
            &mut out,
            "hopae_event_rows",
            "Event rows retained in the store.",
            &[(String::new(), n(s.events))],
        );
        let mut backlog = Vec::new();
        for (sink, pending, failed) in &s.deliveries {
            backlog.push((
                format!("{},state=\"pending\"", label("sink", sink)),
                n(*pending),
            ));
            backlog.push((
                format!("{},state=\"failed\"", label("sink", sink)),
                n(*failed),
            ));
        }
        gauge(
            &mut out,
            "hopae_event_relay_backlog",
            "Event deliveries waiting (pending) or given up (failed), by sink.",
            &backlog,
        );
        gauge(
            &mut out,
            "hopae_projection_feed_rows",
            "Rows of the group projection change feed.",
            &[(String::new(), n(s.projection_changes))],
        );
        gauge(
            &mut out,
            "hopae_lifecycle_feed_head",
            "Head positions of the subject lifecycle feed (ledger and event outbox).",
            &[
                ("source=\"ledger\"".into(), n(s.lifecycle_ledger_head)),
                ("source=\"outbox\"".into(), n(s.outbox_head)),
            ],
        );
        gauge(
            &mut out,
            "hopae_workload_principals",
            "Workload principals known to the store.",
            &[(String::new(), n(s.workload_principals))],
        );
        if let Some(t) = s.last_prune_at {
            gauge(
                &mut out,
                "hopae_events_last_prune_timestamp_seconds",
                "Unix time of the last event prune.",
                &[(String::new(), t.secs())],
            );
        }
    }

    if let Ok(rows) = st.directory.providers().await {
        let mut up = Vec::new();
        for row in &rows {
            let live = st.registry.get(&row.provider_id);
            let enabled = row.enabled
                && row.deleted_at.is_none()
                && live.as_ref().is_some_and(|p| p.enabled());
            let health = match &live {
                Some(p) if enabled => p.health().await,
                _ => ProviderHealth::Disabled,
            };
            let state = match health {
                ProviderHealth::Ok => "ok",
                ProviderHealth::Degraded(_) => "degraded",
                ProviderHealth::Disabled => "disabled",
            };
            for s in ["ok", "degraded", "disabled"] {
                up.push((
                    format!(
                        "{},{},{}",
                        label("provider", row.provider_id.as_str()),
                        label("kind", row.kind.as_str()),
                        label("state", s)
                    ),
                    i64::from(s == state),
                ));
            }
        }
        gauge(
            &mut out,
            "hopae_provider_state",
            "1 for each provider's current state (ok, degraded, disabled).",
            &up,
        );
    }

    let snapshot = st.snapshot.load_full();
    gauge(
        &mut out,
        "hopae_config_generation",
        "Generation of the configuration snapshot in force.",
        &[(
            String::new(),
            i64::try_from(snapshot.generation).unwrap_or(i64::MAX),
        )],
    );
    let reload = st.reload.to_json();
    let mut expiry = Vec::new();
    for e in reload["tls"].as_array().into_iter().flatten() {
        let (Some(name), Some(print)) = (e["name"].as_str(), e["fingerprint"].as_str()) else {
            continue;
        };
        if let Some(at) = metrics::leaf_not_after(print) {
            expiry.push((label("name", name), at - now));
        }
    }
    gauge(
        &mut out,
        "hopae_tls_leaf_expiry_seconds",
        "Seconds until the leaf certificate in use expires (negative once expired), by TLS user.",
        &expiry,
    );
    if let Some(owner) = &st.profile_authority
        && let Ok(owner) = owner.try_lock()
    {
        let snapshot = owner.snapshot();
        gauge(
            &mut out,
            "hopae_authentication_gateway_available",
            "1 when the authentication gateway profiles in force are available.",
            &[(String::new(), i64::from(snapshot.available()))],
        );
        gauge(
            &mut out,
            "hopae_authentication_profiles_revision",
            "Revision of the authentication profiles in force.",
            &[(
                String::new(),
                i64::try_from(snapshot.revision).unwrap_or(i64::MAX),
            )],
        );
    }
    metrics::finish(&mut out);
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, metrics::CONTENT_TYPE),
            (header::CACHE_CONTROL, "no-store"),
        ],
        out,
    )
        .into_response()
}
