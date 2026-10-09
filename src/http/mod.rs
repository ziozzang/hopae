//! Routers, one per listener, with disjoint route sets (ADR-0003).
//! Middleware (request id, security headers, limits) is added in M1.

#[cfg(feature = "test-hooks")]
pub mod hooks;

use axum::Router;
use axum::http::StatusCode;
use axum::routing::get;

use crate::gateway::hangang;

/// Router for the portal listener. M0: `GET /healthz` only.
pub fn portal_router() -> Router {
    Router::new().route("/healthz", get(healthz))
}

/// Router for the gateway listener. M0: the fail-closed verify stub only.
pub fn gateway_router() -> Router {
    Router::new().route(hangang::VERIFY_PATH, get(hangang::verify_not_implemented))
}

async fn healthz() -> (StatusCode, &'static str) {
    (StatusCode::OK, "ok\n")
}
