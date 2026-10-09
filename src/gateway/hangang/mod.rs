//! Hangang adapter, gateway contract v1 (ADR-0005, ADR-0013).
//!
//! `parse` turns the verify request's headers into a gateway-neutral
//! `VerifyInput` (or into a ready denial); `render` turns every `Decision`
//! into the exact status, headers and body of the contract. Only
//! `Decision::Allow` ever renders to a `2xx`.

use crate::config::{Config, CookieNames};
use crate::crypto::Secret;
use crate::verify::types::{Decision, VerifyInput};

mod parse;
mod render;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod wire_tests;

pub use parse::{key_matches, parse};
pub use render::{decision_label, render};

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
    /// The value of the variable named by `gateway.caller_key_env`.
    pub caller_current: Option<Secret>,
    /// The value of the variable named by `gateway.caller_key_next_env`.
    pub caller_next: Option<Secret>,
    /// `gateway.allow_unauthenticated_caller` (development only).
    pub allow_unauthenticated: bool,
}

impl GatewayConfig {
    /// Resolve the caller keys with `lookup` (the environment in production).
    /// An unset or empty variable yields no key, which accepts nothing.
    pub fn from_config(cfg: &Config, lookup: impl Fn(&str) -> Option<String>) -> Self {
        let key = |name: &Option<String>| {
            name.as_deref()
                .and_then(&lookup)
                .filter(|v| !v.is_empty())
                .map(Secret::new)
        };
        GatewayConfig {
            cookies: cfg.cookie_names(),
            portal_url: portal_origin(&cfg.portal.public_url),
            secure: cfg.cookie.secure,
            caller_current: key(&cfg.gateway.caller_key_env),
            caller_next: key(&cfg.gateway.caller_key_next_env),
            allow_unauthenticated: cfg.gateway.allow_unauthenticated_caller,
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
