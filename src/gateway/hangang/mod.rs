//! Hangang adapter, gateway contract v1 (ADR-0005, ADR-0013).
//!
//! `parse` turns the verify request's headers into a gateway-neutral
//! `VerifyInput` (or into a ready denial); `render` turns every `Decision`
//! into the exact status, headers and body of the contract. Only
//! `Decision::Allow` ever renders to a `2xx`.

use crate::config::{Config, CookieNames};
use crate::verify::types::{Decision, VerifyInput};

mod parse;
mod render;
#[cfg(test)]
mod tests;
#[cfg(any(test, feature = "test-hooks"))]
mod walk;
#[cfg(test)]
mod wire_tests;

pub use parse::{authenticate, parse, presented_key};
pub use render::{decision_label, render};
#[cfg(any(test, feature = "test-hooks"))]
pub use walk::assert_only_allow_is_2xx;

/// Path of the verify endpoint on the gateway listener.
pub const VERIFY_PATH: &str = "/_hopae/verify";

/// Contract major version this adapter speaks.
pub const CONTRACT_VERSION: u8 = 1;

/// Everything the adapter needs from the configuration, resolved once.
#[derive(Clone)]
pub struct GatewayConfig {
    pub cookies: CookieNames,
    /// `portal.public_url`: the origin of every `Location` the contract emits.
    pub portal_url: url::Url,
    /// `cookie.secure`.
    pub secure: bool,
}

impl GatewayConfig {
    /// Resolve the adapter's view of the configuration. The caller keys are
    /// not here: `app::CallerKeys` is the one place they are held and compared.
    pub fn from_config(cfg: &Config) -> Self {
        GatewayConfig {
            cookies: cfg.cookie_names(),
            portal_url: portal_origin(&cfg.portal.public_url),
            secure: cfg.cookie.secure,
        }
    }
}

/// `portal.public_url` as a URL whose path is `/` (a validated value; the
/// fallback only guards a hand-built configuration).
fn portal_origin(public_url: &str) -> url::Url {
    let mut u = url::Url::parse(public_url)
        .unwrap_or_else(|_| url::Url::parse("https://localhost").expect("literal url"));
    u.set_path("/");
    u.set_query(None);
    u.set_fragment(None);
    u
}

/// What `render` needs to know about the request beyond the decision.
#[derive(Clone, Debug, Default)]
pub struct RenderEnv {
    /// Correlation id shown on failure pages and in logs.
    pub request_id: String,
    /// The requested URL (the `login` target of a `401`, minus the handoff parameter).
    pub original_url: Option<url::Url>,
    /// The binding cookie the browser presented, when well formed (refreshed by `BindAction::Keep`).
    pub bind_cookie: Option<String>,
    /// The request matched the reserved-parameter rule: never cacheable.
    pub handoff_seen: bool,
    /// The header a contract violation names.
    pub detail: Option<&'static str>,
}

/// A request that parsed.
pub struct Parsed {
    pub input: VerifyInput,
    pub env: RenderEnv,
}

/// A request refused before any state was touched.
pub struct Rejected {
    pub decision: Decision,
    pub env: RenderEnv,
    /// Counter to increment for this refusal, when it has one.
    pub metric: Option<&'static str>,
}

/// Parse a request that is taken to be authenticated already (for tests that
/// are not about the caller key).
#[cfg(any(test, feature = "test-hooks"))]
pub fn parse_for_tests(
    cfg: &GatewayConfig,
    h: &axum::http::HeaderMap,
    request_id: String,
) -> Result<Parsed, Box<Rejected>> {
    parse(
        cfg,
        h,
        request_id,
        crate::verify::types::CallerAuth::Keyed {
            which: crate::verify::types::KeySlot::Current,
        },
    )
}
