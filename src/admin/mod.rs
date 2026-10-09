//! The management console (ADR-0016): types shared by its handlers. W0 froze
//! the shared types and stub handlers; W1-A fills the authentication, the
//! router and the pages, W1-B the users, sessions and events handlers.

pub mod events;
pub mod sessions;
pub mod users;

use std::sync::Arc;
use std::time::Duration;

use ipnet::IpNet;
use tokio::sync::Semaphore;

use crate::config::{AdminLimits, UntrustedPeers};
use crate::crypto::{Clock, Digest, Rng, Secret, Timestamp};
use crate::event::bus::Emitter;
use crate::identity::types::{NormalizedEmail, UserId};
use crate::policy::types::{AppPolicy, Host};
use crate::session::types::{Aal, SessionId};
use crate::store::{AdminRole, AuthTimeSource, Directory, Events, Sessions};

/// What the admin listener needs of the configuration, resolved once.
#[derive(Clone, Debug)]
pub struct AdminConfig {
    /// The tuple origin of `admin.public_url`.
    pub origin: url::Origin,
    /// The console host and the port browsers use for it.
    pub host: Host,
    pub port: u16,
    pub limits: AdminLimits,
    /// The implicit application `admin`.
    pub policy: AppPolicy,
    pub untrusted_peers: UntrustedPeers,
    /// `admin.query_budget_ms`: the deadline of every store operation.
    pub query_budget: Duration,
    /// `trusted_proxies`.
    pub trusted: Vec<IpNet>,
    /// `cookie.secure`.
    pub secure: bool,
}

impl AdminConfig {
    /// `None` when the console is not enabled.
    pub fn from_config(cfg: &crate::config::Config) -> Option<AdminConfig> {
        let (host, port) = cfg.admin_host()?;
        let limits = cfg.admin_limits()?;
        Some(AdminConfig {
            origin: cfg.admin_origin()?,
            host,
            port,
            limits,
            policy: cfg.admin_policy()?,
            untrusted_peers: limits.untrusted_peers,
            query_budget: limits.query_budget,
            trusted: cfg.trusted_proxy_nets(),
            secure: cfg.cookie.secure,
        })
    }
}

/// Shared state of the admin listener.
pub struct AdminState {
    pub cfg: AdminConfig,
    pub directory: Arc<dyn Directory>,
    pub sessions: Arc<dyn Sessions>,
    pub events: Arc<dyn Events>,
    pub emitter: Option<Emitter>,
    pub clock: Arc<dyn Clock>,
    pub rng: Arc<dyn Rng>,
    /// `limits.admin_max_concurrent`.
    pub in_flight: Arc<Semaphore>,
}

/// An authenticated administrator, as authentication hands it to a handler.
#[derive(Clone)]
pub struct Principal {
    pub user_id: UserId,
    pub session_id: SessionId,
    pub handle_sha256: Digest,
    pub handle_value: Secret,
    pub role: AdminRole,
    pub email: Option<NormalizedEmail>,
    pub display_name: Option<String>,
    pub auth_time: Timestamp,
    pub auth_time_source: AuthTimeSource,
    pub aal: Aal,
}

impl std::fmt::Debug for Principal {
    /// Never the handle value.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Principal")
            .field("user_id", &self.user_id)
            .field("session_id", &self.session_id)
            .field("role", &self.role)
            .finish_non_exhaustive()
    }
}

/// Why a console request is refused (ADMIN.md, "Denials").
#[derive(Clone, Debug)]
pub enum Denial {
    UntrustedPeer,
    LoginRequired,
    AuthTooOld,
    NotAdmin {
        user_id: UserId,
        email: Option<NormalizedEmail>,
    },
    RoleInsufficient,
    AalInsufficient,
    WrongHost,
    StoreUnavailable,
    Overloaded,
}
