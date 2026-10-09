//! Hangang adapter, gateway contract v1 (M1).

use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};

/// Path of the verify endpoint on the gateway listener.
pub const VERIFY_PATH: &str = "/_hopae/verify";

/// M0 stub: always fail closed with `503` and a machine-readable reason.
pub async fn verify_not_implemented() -> Response {
    let mut resp = StatusCode::SERVICE_UNAVAILABLE.into_response();
    let h = resp.headers_mut();
    h.insert(
        "x-hopae-reason",
        HeaderValue::from_static("not_implemented"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}
