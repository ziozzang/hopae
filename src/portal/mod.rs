//! Portal: login chooser, provider callback, logout, switch, health (M1);
//! step-up (M5).
//!
//! The portal owns transport and presentation. The flows themselves run in the
//! session and identity services behind [`ports::PortalServices`]. The routes,
//! the middleware and the router assembly are in `http::portal`.

pub mod clientinfo;
pub mod cookies;
pub mod handlers;
pub mod i18n;
pub mod pages;
pub mod ports;
#[cfg(test)]
mod tests;

use std::sync::Arc;

use ipnet::IpNet;
use tokio::sync::Semaphore;

use crate::config::{Config, CookieNames};
use crate::crypto::{Clock, Rng};
use crate::http::csrf::CsrfKey;
use crate::http::security;
use ports::PortalServices;

/// Largest request body the portal reads, in bytes.
pub const MAX_BODY_BYTES: usize = 64 * 1024;

/// The configuration the portal consults, copied out of [`Config`] at start.
#[derive(Clone, Debug)]
pub struct PortalConfig {
    /// The exact `Origin` value of the portal (`https://auth.example.test`).
    pub origin: String,
    pub cookie_names: CookieNames,
    /// `cookie.secure`; `false` is development mode.
    pub secure: bool,
    pub trusted_proxies: Vec<IpNet>,
    pub max_concurrent: usize,
    /// Reported by `/healthz`.
    pub insecure_mode: bool,
    pub unauthenticated_caller: bool,
}

impl PortalConfig {
    /// Derive from a validated configuration.
    pub fn from_config(cfg: &Config) -> PortalConfig {
        PortalConfig {
            origin: security::portal_origin(&cfg.portal.public_url).unwrap_or_default(),
            cookie_names: cfg.cookie_names(),
            secure: cfg.cookie.secure,
            trusted_proxies: cfg.trusted_proxy_nets(),
            max_concurrent: usize::try_from(cfg.limits.portal_max_concurrent)
                .unwrap_or(usize::MAX)
                .max(1),
            insecure_mode: cfg.insecure_mode(),
            unauthenticated_caller: cfg.gateway.allow_unauthenticated_caller,
        }
    }
}

/// Everything a portal request needs. Cheap to clone.
#[derive(Clone)]
pub struct PortalState {
    pub cfg: Arc<PortalConfig>,
    pub services: Arc<dyn PortalServices>,
    pub clock: Arc<dyn Clock>,
    pub rng: Arc<dyn Rng>,
    pub(crate) csrf_key: CsrfKey,
    pub(crate) in_flight: Arc<Semaphore>,
}

impl PortalState {
    /// The CSRF key is drawn from `rng` once, here.
    pub fn new(
        cfg: PortalConfig,
        services: Arc<dyn PortalServices>,
        clock: Arc<dyn Clock>,
        rng: Arc<dyn Rng>,
    ) -> PortalState {
        let in_flight = Arc::new(Semaphore::new(cfg.max_concurrent));
        let csrf_key = CsrfKey::random(rng.as_ref());
        PortalState {
            cfg: Arc::new(cfg),
            services,
            clock,
            rng,
            csrf_key,
            in_flight,
        }
    }
}
