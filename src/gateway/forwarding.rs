//! Trusted-proxy forwarding header names (ADR-0013, R-6). The portal may
//! consume these from a trusted proxy; it may not spell them, so the names
//! live here, inside the gateway boundary.

use axum::http::HeaderName;

/// The client address chain.
pub static X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");
/// The protocol the client used.
pub static X_FORWARDED_PROTO: HeaderName = HeaderName::from_static("x-forwarded-proto");
