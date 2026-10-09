//! The admin listener's router. W0 ships the minimal form — the pinned
//! response headers, the peer check and the `403` fallback — so the listener
//! can be bound and exercised; W1-A replaces it with the full router
//! (authentication, pages, `/v1` API, the concurrency cap and the limits).
//!
//! Serve it with connect info so the trusted-proxy rule can see the TCP peer:
//! `axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>())`.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};

use crate::admin::AdminState;
use crate::config::UntrustedPeers;
use crate::crypto::random_id;
use crate::event::types::reasons;
use crate::http::denials::{self, DenialCounters};
use crate::http::security;

/// The console's content security policy: the portal's, plus `img-src 'self'`.
pub const CONTENT_SECURITY_POLICY: &str = "default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'";

/// Router of the admin listener.
pub fn router(state: Arc<AdminState>) -> Router {
    Router::new()
        .fallback(refuse)
        .layer(middleware::from_fn(headers))
        .with_state(state)
}

/// The pinned headers on every response, whatever produced it.
async fn headers(req: Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    security::apply(h);
    h.insert(
        "content-security-policy",
        HeaderValue::from_static(CONTENT_SECURITY_POLICY),
    );
    h.insert("x-robots-tag", HeaderValue::from_static("noindex"));
    resp
}

fn json_error(status: StatusCode, code: &str) -> Response {
    (
        status,
        [("content-type", "application/json")],
        format!(r#"{{"error":"{code}"}}"#),
    )
        .into_response()
}

/// A peer outside `trusted_proxies` is refused before any header is read
/// (`refuse`); everything else, with no authentication yet, is `login_required`.
async fn refuse(
    State(st): State<Arc<AdminState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
) -> Response {
    let trusted = st.cfg.trusted.iter().any(|n| n.contains(&peer.ip()));
    if !trusted && st.cfg.untrusted_peers == UntrustedPeers::Refuse {
        let rid = random_id(st.rng.as_ref(), "r_");
        denials::record_refusal(
            st.emitter.as_ref(),
            &DenialCounters::ADMIN,
            reasons::UNTRUSTED_PEER,
            peer.ip(),
            Some(&st.cfg.policy.app_id),
            &rid,
        );
        return json_error(StatusCode::FORBIDDEN, "untrusted_peer");
    }
    json_error(StatusCode::FORBIDDEN, "login_required")
}
