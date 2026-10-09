//! Routers, one per listener, with disjoint route sets (ADR-0003).
//! Router assembly only: the handlers live in `gateway.rs` (verify) and, for
//! the portal, in the portal modules.

pub mod gateway;

pub mod csrf;
#[cfg(feature = "test-hooks")]
pub mod hooks;
pub mod portal;
pub mod security;

use axum::Router;
use axum::http::StatusCode;
use axum::routing::get;

/// Router for the portal listener. M0: `GET /healthz` only.
pub fn portal_router() -> Router {
    Router::new().route("/healthz", get(healthz))
}

/// Router for the gateway listener: the verify endpoint only.
pub fn gateway_router(state: std::sync::Arc<gateway::GatewayState>) -> Router {
    gateway::router(state)
}

async fn healthz() -> (StatusCode, &'static str) {
    (StatusCode::OK, "ok\n")
}
