//! The management console (ADR-0016): types shared by its handlers. W0 froze
//! the shared types and stub handlers; W1-A fills the authentication, the
//! router and the pages, W1-B the users, sessions and events handlers.
//!
//! What a handler can rely on (the listener, `crate::http::admin`, does it
//! before the handler runs):
//!
//! * Every request but the stylesheet is authenticated and granted: take
//!   [`Ctx`] (the [`Principal`] and the [`ReqInfo`]) as an extractor.
//! * Every mutation (a `POST` to a route of [`auth::is_mutation`]) has passed
//!   the CSRF rule (form token or API header, [`csrf::guard`]) and then the
//!   role check (`403 role_insufficient` for a viewer, recorded), in that
//!   order and before any store read. The handler takes
//!   `axum::Extension<csrf::Mutation>` for the parsed form and must not read
//!   the body again; it still owns `self_target`, the fenced write
//!   ([`api::actor`], [`api::actor_policy`], [`api::deadline`]) and the
//!   `actor_revoked` refusal ([`auth::record_denied`]).
//! * Answers: [`api::json`] / [`api::error`] (JSON for `/v1/`, a page inside
//!   the layout otherwise), pages extend `templates/admin/layout.html` through
//!   a [`pages::Chrome`] field named `c`. Tokens for forms: [`csrf::issue`].
//! * Cursors: [`cursor::encode`] / [`cursor::decode`] with [`AdminState::key`].

pub mod api;
pub mod auth;
pub mod csrf;
pub mod cursor;
pub mod delegation;
pub mod delegation_wire;
pub mod events;
pub mod me;
pub mod pages;
pub mod profiles;
pub mod seed;
pub mod sessions;
pub mod status;
pub mod users;

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arc_swap::ArcSwap;
use ipnet::IpNet;
use tokio::sync::Semaphore;

use crate::config::{AdminLimits, CookieNames, UntrustedPeers};
use crate::crypto::{Clock, Digest, Rng, Secret, Timestamp};
use crate::event::bus::Emitter;
use crate::identity::types::{NormalizedEmail, UserId};
use crate::policy::types::{AppPolicy, ConfigSnapshot, Host, SessionPolicy};
use crate::portal::i18n::Lang;
use crate::provider::registry::Registry;
use crate::provider::types::ProviderId;
use crate::session::types::{Aal, SessionId};
use crate::store::{AdminRole, AuthTimeSource, Directory, Events, Sessions};
use crate::verify::types::VerifyContext;

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
    /// The configured cookie names (the console reads the handle cookie).
    pub cookie_names: CookieNames,
    /// Session-wide idle and absolute lifetimes (`session.*`).
    pub session: SessionPolicy,
    /// `cookie.secure = false` (development mode).
    pub insecure_mode: bool,
    /// `gateway.allow_unauthenticated_caller`.
    pub unauthenticated_caller: bool,
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
            cookie_names: cfg.cookie_names(),
            session: cfg.session_policy(),
            insecure_mode: cfg.insecure_mode(),
            unauthenticated_caller: cfg.gateway.allow_unauthenticated_caller,
        })
    }
}

/// Shared state of the admin listener.
pub struct AdminState {
    pub profile_store: crate::store::sqlite::Store,
    pub profile_workers: Arc<Semaphore>,
    pub cfg: AdminConfig,
    pub directory: Arc<dyn Directory>,
    pub sessions: Arc<dyn Sessions>,
    pub events: Arc<dyn Events>,
    pub emitter: Option<Emitter>,
    pub clock: Arc<dyn Clock>,
    pub rng: Arc<dyn Rng>,
    /// `limits.admin_max_concurrent`.
    pub in_flight: Arc<Semaphore>,
    /// The current configuration snapshot (applications, providers, generation).
    pub snapshot: Arc<ArcSwap<ConfigSnapshot>>,
    /// The verify engine's context: the console authenticates with it.
    pub verify: VerifyContext,
    /// The configured providers' cached state (health) — never contacted.
    pub registry: Arc<Registry>,
    /// Process-wide MAC key for form tokens and cursors (random per process).
    pub key: [u8; 32],
    pub started_at: Timestamp,
    /// Digest of the effective configuration, as `config.loaded` records it.
    pub config_digest: String,
    /// The bound listener addresses, as the status page shows them.
    pub listeners: Listeners,
    /// When each untrusted peer was last warned about (one line per minute).
    pub peer_warned: Mutex<HashMap<IpAddr, Timestamp>>,
    pub delegation: Option<delegation::Config>,
    pub delegation_replay: delegation::Replay,
}

/// The bound listener addresses (`portal`, `gateway`, `admin`).
#[derive(Clone, Debug, Default)]
pub struct Listeners {
    pub portal: String,
    pub gateway: String,
    pub admin: String,
    pub native_gateway: Option<String>,
}

/// An authenticated administrator, as authentication hands it to a handler.
#[derive(Clone)]
pub struct Principal {
    pub authority: Option<delegation::Proof>,
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
    /// The provider that created the session (its capability decides what
    /// console freshness means; the fence needs it).
    pub provider_id: ProviderId,
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
    /// The `cookie` headers exceed the size the console reads (`431`).
    HeaderTooLarge,
}

/// Everything a handler needs to know about the request besides the
/// principal. Put into the request extensions by the listener's middleware.
#[derive(Clone, Debug)]
pub struct ReqInfo {
    pub rid: String,
    pub client_ip: IpAddr,
    pub user_agent: Option<String>,
    pub lang: Lang,
    pub https: bool,
    pub method: http::Method,
    /// The route pattern (`/v1/users/{id}/disable`), `unmatched` for none.
    pub pattern: &'static str,
    /// A `/v1/` request answers JSON, everything else HTML.
    pub api: bool,
}

/// An authenticated, granted administrator with the request facts: the
/// extractor of every console handler behind authentication.
#[derive(Clone, Debug)]
pub struct Ctx {
    pub delegated_actor: Option<delegation::Actor>,
    pub principal: Principal,
    pub req: ReqInfo,
}

impl<S: Send + Sync> axum::extract::FromRequestParts<S> for Ctx {
    type Rejection = axum::response::Response;

    async fn from_request_parts(
        parts: &mut http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        use axum::response::IntoResponse;
        parts.extensions.get::<Ctx>().cloned().ok_or_else(|| {
            // Unreachable behind the listener's authentication; fail closed.
            (
                http::StatusCode::FORBIDDEN,
                [("content-type", "application/json")],
                r#"{"error":"login_required"}"#,
            )
                .into_response()
        })
    }
}
