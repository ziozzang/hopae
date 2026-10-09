//! `GET /` (the status page) and `GET /v1/status`: applications, providers,
//! the store, the build and the configuration generation, read-only.
//!
//! Everything comes from state Hopae already holds: the configuration
//! snapshot, the provider rows, the registry's cached discovery state and
//! `count(*)` over indexed columns. No provider and no gateway is contacted.

use std::sync::Arc;
use std::time::Duration;

use askama::Template;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Response;
use serde_json::{Value, json};

use super::pages::{self, Chrome};
use super::{AdminState, Ctx, api};
use crate::policy::types::{AppPolicy, AuthzChange, IpBinding, OnMismatch, UaBinding};
use crate::provider::types::{ProviderHealth, ReauthCapability};
use crate::store::{ManagedBy, ProviderRow, StoreError};

/// The gateway contract version this build speaks.
pub const CONTRACT: &str = "1.1";

/// `30m`, `12h`, `7d`: the largest unit that divides the duration exactly.
pub fn format_duration(d: Duration) -> String {
    let s = d.as_secs();
    if s != 0 && s.is_multiple_of(86_400) {
        format!("{}d", s / 86_400)
    } else if s != 0 && s.is_multiple_of(3_600) {
        format!("{}h", s / 3_600)
    } else if s != 0 && s.is_multiple_of(60) {
        format!("{}m", s / 60)
    } else {
        format!("{s}s")
    }
}

/// What the page and the endpoint show, resolved once per request.
pub struct StatusData {
    pub json: Value,
    pub view: StatusView,
}

/// The page's rows, as text.
pub struct StatusView {
    pub apps: Vec<AppRow>,
    pub providers: Vec<ProviderView>,
    pub store_kind: &'static str,
    pub schema_version: u32,
    pub users: u64,
    pub live_sessions: u64,
    pub events: u64,
    pub last_prune_at: String,
    pub deliveries: Vec<DeliveryRow>,
    pub version: &'static str,
    pub contract: &'static str,
    pub started_at: i64,
    pub generation: u64,
    pub digest: String,
    pub insecure_mode: bool,
    pub unauthenticated_caller: bool,
    pub listeners: String,
}

pub struct AppRow {
    pub app_id: String,
    pub display_name: String,
    pub hosts: String,
    pub ports: String,
    pub enabled: bool,
    pub session: String,
    pub binding: String,
    pub on_authz_change: &'static str,
    pub verify_cache_seconds: u32,
    pub logout_confirm: bool,
    pub max_auth_age: String,
    pub step_up: usize,
}

pub struct ProviderView {
    pub provider_id: String,
    pub kind: &'static str,
    pub display_name: String,
    pub enabled: bool,
    pub managed_by: &'static str,
    pub health: String,
    pub reauth: &'static str,
    pub client_secret_env: String,
    pub secret_present: bool,
}

pub struct DeliveryRow {
    pub sink: String,
    pub pending: u64,
    pub failed: u64,
}

fn binding_json(a: &AppPolicy) -> Value {
    let (ip, extra) = match a.binding.ip {
        IpBinding::Strict => ("strict", None),
        IpBinding::Off => ("off", None),
        IpBinding::Prefix { v4, v6 } => ("prefix", Some((v4, v6))),
    };
    let mut b = json!({
        "ip": ip,
        "ua": match a.binding.ua { UaBinding::Strict => "strict", UaBinding::Off => "off" },
        "on_mismatch": on_mismatch(a),
    });
    if let Some((v4, v6)) = extra {
        b["ip_prefix_v4"] = json!(v4);
        b["ip_prefix_v6"] = json!(v6);
    }
    b
}

fn on_mismatch(a: &AppPolicy) -> &'static str {
    match a.binding.on_mismatch {
        OnMismatch::TerminateSession => "terminate_session",
        OnMismatch::DropHandle => "drop_handle",
    }
}

fn binding_text(a: &AppPolicy) -> String {
    let ip = match a.binding.ip {
        IpBinding::Strict => "strict".to_string(),
        IpBinding::Off => "off".to_string(),
        IpBinding::Prefix { v4, v6 } => format!("prefix /{v4} /{v6}"),
    };
    let ua = match a.binding.ua {
        UaBinding::Strict => "strict",
        UaBinding::Off => "off",
    };
    format!("ip {ip}, ua {ua}, {}", on_mismatch(a))
}

fn app_json(a: &AppPolicy) -> Value {
    json!({
        "app_id": a.app_id.as_str(),
        "display_name": a.display_name,
        "hosts": a.hosts.iter().map(|h| h.as_str()).collect::<Vec<_>>(),
        "ports": a.ports,
        "enabled": a.enabled,
        "session": {
            "idle": format_duration(a.session.idle),
            "absolute": format_duration(a.session.absolute),
        },
        "binding": binding_json(a),
        "on_authz_change": authz(a),
        "verify_cache_seconds": a.verify_cache_seconds,
        "logout_confirm": a.logout_confirm,
        "max_auth_age": a.max_auth_age.map(format_duration),
        "step_up": a.step_up.len(),
    })
}

fn authz(a: &AppPolicy) -> &'static str {
    match a.on_authz_change {
        AuthzChange::Refresh => "refresh",
        AuthzChange::Terminate => "terminate",
    }
}

fn app_row(a: &AppPolicy) -> AppRow {
    AppRow {
        app_id: a.app_id.to_string(),
        display_name: a.display_name.clone(),
        hosts: a
            .hosts
            .iter()
            .map(|h| h.as_str())
            .collect::<Vec<_>>()
            .join(", "),
        ports: a
            .ports
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(", "),
        enabled: a.enabled,
        session: format!(
            "{} / {}",
            format_duration(a.session.idle),
            format_duration(a.session.absolute)
        ),
        binding: binding_text(a),
        on_authz_change: authz(a),
        verify_cache_seconds: a.verify_cache_seconds,
        logout_confirm: a.logout_confirm,
        max_auth_age: a
            .max_auth_age
            .map_or_else(|| "-".to_string(), format_duration),
        step_up: a.step_up.len(),
    }
}

/// The capability the console reads from a provider: its stored setting,
/// else what the configuration resolved, else the generic default.
fn capability(row: &ProviderRow, st: &AdminState) -> ReauthCapability {
    row.config
        .get("reauth")
        .and_then(Value::as_str)
        .and_then(ReauthCapability::parse)
        .or_else(|| {
            st.snapshot
                .load()
                .providers
                .iter()
                .find(|p| p.provider_id == row.provider_id)
                .map(|p| p.reauth)
        })
        .unwrap_or(ReauthCapability::MaxAge)
}

fn secret_present(name: &str) -> bool {
    std::env::var(name).is_ok_and(|v| !v.is_empty())
}

/// Collect the page and the endpoint's data. A store failure is the caller's `503`.
pub async fn collect(st: &AdminState) -> Result<StatusData, StoreError> {
    let snap = st.snapshot.load_full();
    let rows = st.directory.providers().await?;
    let store = st.events.status(api::deadline(st)).await?;

    let mut apps: Vec<&AppPolicy> = snap.apps.iter().collect();
    apps.push(&snap.default_app);
    let apps_json: Vec<Value> = apps.iter().map(|a| app_json(a)).collect();
    let app_rows: Vec<AppRow> = apps.iter().map(|a| app_row(a)).collect();

    let mut providers_json = Vec::new();
    let mut provider_views = Vec::new();
    for row in &rows {
        let live = st.registry.get(&row.provider_id);
        let enabled =
            row.enabled && row.deleted_at.is_none() && live.as_ref().is_some_and(|p| p.enabled());
        let health = match &live {
            Some(p) if enabled => p.health().await,
            _ => ProviderHealth::Disabled,
        };
        let (health_name, reason) = match health {
            ProviderHealth::Ok => ("ok", None),
            ProviderHealth::Degraded(r) => ("degraded", Some(r)),
            ProviderHealth::Disabled => ("disabled", None),
        };
        let managed_by = match row.managed_by {
            ManagedBy::File => "file",
            ManagedBy::Api => "api",
        };
        let reauth = capability(row, st).as_str();
        let env_name = row.client_secret_env.clone();
        let present = env_name.as_deref().is_some_and(secret_present);
        let mut j = json!({
            "provider_id": row.provider_id.as_str(),
            "kind": row.kind.as_str(),
            "display_name": row.display_name,
            "enabled": enabled,
            "managed_by": managed_by,
            "health": health_name,
            "reauth": reauth,
            "client_secret_env": env_name,
            "secret_present": present,
        });
        if let Some(r) = reason {
            j["reason"] = json!(r);
        }
        providers_json.push(j);
        provider_views.push(ProviderView {
            provider_id: row.provider_id.to_string(),
            kind: row.kind.as_str(),
            display_name: row.display_name.clone(),
            enabled,
            managed_by,
            health: match reason {
                Some(r) => format!("{health_name} ({r})"),
                None => health_name.to_string(),
            },
            reauth,
            client_secret_env: env_name.unwrap_or_default(),
            secret_present: present,
        });
    }

    let mut deliveries = serde_json::Map::new();
    let mut delivery_rows = Vec::new();
    for (sink, pending, failed) in &store.deliveries {
        deliveries.insert(sink.clone(), json!({"pending": pending, "failed": failed}));
        delivery_rows.push(DeliveryRow {
            sink: sink.clone(),
            pending: *pending,
            failed: *failed,
        });
    }
    let listeners = json!({
        "portal": st.listeners.portal,
        "gateway": st.listeners.gateway,
        "admin": st.listeners.admin,
    });
    let version = env!("CARGO_PKG_VERSION");
    let json = json!({
        "apps": apps_json,
        "providers": providers_json,
        "store": {
            "kind": "sqlite",
            "schema_version": store.schema_version,
            "users": store.users,
            "live_sessions": store.live_sessions,
            "events": store.events,
            "deliveries": deliveries,
            "last_prune_at": store.last_prune_at.map(|t| t.secs()),
        },
        "build": {
            "version": version,
            "contract": CONTRACT,
            "started_at": st.started_at.secs(),
        },
        "config": {
            "generation": snap.generation,
            "digest": st.config_digest,
            "insecure_mode": st.cfg.insecure_mode,
            "unauthenticated_caller": st.cfg.unauthenticated_caller,
            "listeners": listeners,
        },
    });
    let view = StatusView {
        apps: app_rows,
        providers: provider_views,
        store_kind: "sqlite",
        schema_version: store.schema_version,
        users: store.users,
        live_sessions: store.live_sessions,
        events: store.events,
        last_prune_at: store
            .last_prune_at
            .map_or_else(|| "-".to_string(), |t| t.secs().to_string()),
        deliveries: delivery_rows,
        version,
        contract: CONTRACT,
        started_at: st.started_at.secs(),
        generation: snap.generation,
        digest: st.config_digest.clone(),
        insecure_mode: st.cfg.insecure_mode,
        unauthenticated_caller: st.cfg.unauthenticated_caller,
        listeners: format!(
            "portal {}, gateway {}, admin {}",
            st.listeners.portal, st.listeners.gateway, st.listeners.admin
        ),
    };
    Ok(StatusData { json, view })
}

#[derive(Template)]
#[template(path = "admin/status.html")]
struct StatusPage<'a> {
    c: &'a Chrome<'a>,
    v: &'a StatusView,
}

fn unavailable(e: &StoreError) -> &'static str {
    tracing::error!(error = %e, "status could not read the store");
    "store_unavailable"
}

/// `GET /`.
pub async fn page(State(st): State<Arc<AdminState>>, ctx: Ctx) -> Response {
    match collect(&st).await {
        Ok(data) => {
            let c = Chrome::signed_in(&st, &ctx.req, &ctx.principal, "status");
            pages::render(
                StatusCode::OK,
                &StatusPage {
                    c: &c,
                    v: &data.view,
                },
            )
        }
        Err(e) => api::error(
            &st,
            &ctx.req,
            &ctx.principal,
            StatusCode::SERVICE_UNAVAILABLE,
            unavailable(&e),
        ),
    }
}

/// `GET /v1/status`.
pub async fn data(State(st): State<Arc<AdminState>>, ctx: Ctx) -> Response {
    match collect(&st).await {
        Ok(data) => api::json(StatusCode::OK, &data.json),
        Err(e) => api::error(
            &st,
            &ctx.req,
            &ctx.principal,
            StatusCode::SERVICE_UNAVAILABLE,
            unavailable(&e),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_use_the_largest_exact_unit() {
        assert_eq!(format_duration(Duration::from_secs(1800)), "30m");
        assert_eq!(format_duration(Duration::from_secs(12 * 3600)), "12h");
        assert_eq!(format_duration(Duration::from_secs(7 * 86_400)), "7d");
        assert_eq!(format_duration(Duration::from_secs(90)), "90s");
        assert_eq!(format_duration(Duration::from_secs(0)), "0s");
    }
}
