//! Portal listener router: routes, request ids, security headers on every
//! response, the concurrency cap and the `404` fallback.
//!
//! Serve it with connect info so the trusted-proxy rule can see the TCP peer:
//! `axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>())`.

use axum::Router;
use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{get, post};

use crate::crypto::random_id;
use crate::http::security;
use crate::portal::PortalState;
use crate::portal::handlers::{self, RequestId};
use crate::portal::pages::ErrorPage;

/// Router for the portal listener (all routes, middleware and the 404 fallback).
pub fn router(state: PortalState) -> Router {
    Router::new()
        .route("/healthz", get(handlers::healthz))
        .route(
            "/stepup",
            get(handlers::stepup_get).post(handlers::stepup_post),
        )
        .route(
            "/stepup/external",
            get(handlers::external_stepup_get).post(handlers::external_stepup_post),
        )
        .route("/security/totp", get(handlers::totp_get))
        .route("/security/totp/prepare", post(handlers::totp_prepare_post))
        .route("/security/totp/confirm", post(handlers::totp_confirm_post))
        .route("/assets/portal.css", get(handlers::stylesheet))
        .route("/login", get(handlers::login_get))
        .route("/login/retry", post(handlers::retry_post))
        .route("/login/continue", post(handlers::continue_post))
        .route("/login/{provider}", post(handlers::login_post))
        .route("/login/{provider}/password", post(handlers::password_post))
        .route("/callback/{provider}", get(handlers::callback_get))
        .route(
            "/switch",
            get(handlers::switch_get).post(handlers::switch_post),
        )
        .route(
            "/logout",
            get(handlers::logout_get).post(handlers::logout_post),
        )
        .route("/signed-out", get(handlers::signed_out_get))
        .fallback(handlers::not_found)
        // Innermost first: the cap runs inside the request-id/header layer, so
        // even its 503 carries the security headers and an id.
        .layer(middleware::from_fn_with_state(state.clone(), limit))
        .layer(middleware::from_fn_with_state(state.clone(), outer))
        .with_state(state)
}

/// Assign the request id, run the request, and stamp the security headers
/// (and the id) on whatever comes back, whatever produced it.
async fn outer(State(st): State<PortalState>, mut req: Request, next: Next) -> Response {
    let rid = random_id(st.rng.as_ref(), "r_");
    req.extensions_mut().insert(RequestId(rid.clone()));
    // The client's own id is kept apart: only an event attribute, and only
    // when the operator turned `log.accept_client_request_id` on.
    if let Some(v) = req
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.is_empty())
    {
        let v: String = v.chars().take(256).collect();
        req.extensions_mut().insert(handlers::ClientRequestId(v));
    }
    let mut resp = next.run(req).await;
    security::apply(resp.headers_mut());
    if let Some(origins) = resp
        .extensions()
        .get::<security::FormActionOrigins>()
        .cloned()
    {
        security::with_form_action(resp.headers_mut(), &origins.0);
    }
    if let Ok(v) = HeaderValue::from_str(&rid) {
        resp.headers_mut().insert(handlers::request_id_header(), v);
    }
    resp
}

/// `limits.portal_max_concurrent`: excess requests are refused at once, not queued.
async fn limit(State(st): State<PortalState>, req: Request, next: Next) -> Response {
    match st.in_flight.clone().try_acquire_owned() {
        Ok(permit) => {
            let resp = next.run(req).await;
            drop(permit);
            resp
        }
        Err(_) => {
            let rid = handlers::request_id_of(&req);
            let mut resp = handlers::plain_error(req.headers(), &rid, ErrorPage::Unavailable);
            *resp.status_mut() = StatusCode::SERVICE_UNAVAILABLE;
            resp.headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
            resp
        }
    }
}
