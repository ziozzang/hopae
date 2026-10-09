//! Gateway facts the preflight prints for the operator: the identity header
//! set the gateway must relay and the route `auth` fragment to register.
//! Every wire name stays inside `src/gateway/` (ADR-0013). Included by the
//! application preflight (`src/app/preflight.rs`); W1-B may fold it into the
//! adapter module and drop the `#[path]` include.

use serde_json::{Value, json};

/// Response headers the gateway copies from the verify answer to the upstream request.
pub const IDENTITY_HEADERS: [&str; 10] = [
    "x-forwarded-user",
    "x-forwarded-email",
    "x-forwarded-preferred-username",
    "x-forwarded-groups",
    "x-hopae-session",
    "x-hopae-provider",
    "x-hopae-auth-time",
    "x-hopae-expires",
    "x-hopae-aal",
    "x-hopae-factors",
];

/// Request headers the gateway lists for the verify call.
pub const REQUEST_HEADERS: [&str; 6] = [
    "cookie",
    "user-agent",
    "accept",
    "sec-fetch-dest",
    "sec-fetch-mode",
    "sec-fetch-site",
];

/// The gateway-side environment variable that holds the caller key
/// (gateway change HC-3); the gateway operator may choose another name.
pub const GATEWAY_KEY_ENV: &str = "HANGANG_HOPAE_KEY";

/// The route-level `strip_request_cookies` field (gateway change HC-12,
/// ADR-0015): the configured handle and binding cookie names, which the gateway
/// removes from the request it forwards upstream. It belongs on every route
/// that reaches an application upstream, public routes of a path-scoped host
/// included.
pub fn route_strip_fragment(strip_cookies: &[&str]) -> Value {
    json!({ "strip_request_cookies": strip_cookies })
}

/// The `auth` block of a protected route, as in docs/GATEWAY_CONTRACT.md.
pub fn route_auth_fragment(verify_url: &str, timeout_ms: u64) -> Value {
    json!({
        "url": verify_url,
        "request_headers": REQUEST_HEADERS,
        "response_headers": IDENTITY_HEADERS,
        "static_request_headers": {
            "x-hopae-contract": "1",
            "x-hopae-gateway-key": {"env": GATEWAY_KEY_ENV},
        },
        "timeout_ms": timeout_ms,
        "forward_response": true,
    })
}
