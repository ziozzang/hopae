//! Verify core types, gateway-neutral (ADR-0013): no header names, status
//! codes or cookie attributes appear here.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;

use crate::crypto::{Clock, Rng, Secret, Timestamp};
use crate::event::types::Reason;
use crate::identity::types::{NormalizedEmail, UserId};
use crate::policy::types::{ConfigSnapshot, Host, SessionPolicy};
use crate::provider::types::ProviderId;
use crate::session::types::{Aal, FactorEntry, Generations, SessionId};
use crate::store::{Directory, Sessions};

pub enum Navigation {
    Document,
    Other,
}

pub enum Handoff {
    None,
    Code(Secret),
    Ambiguous,
}

/// Which accepted caller key matched.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeySlot {
    Current,
    Next,
}

pub enum CallerAuth {
    Keyed { which: KeySlot, /* Current|Next */ },
    Unauthenticated,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scheme {
    Http,
    Https,
}

/// Computed by the adapter with the gateway's rules; Err -> Decision::Deny(path_not_canonical).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalPath(String);

impl CanonicalPath {
    /// Wrap a path the adapter already canonicalized. The core never
    /// canonicalizes; it only compares and matches.
    pub fn new(path: String) -> Self {
        CanonicalPath(path)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The reserved namespace on application hosts (ADR-0015).
const RESERVED_ROOT: &str = "/_hopae";

/// The two application-host entry points.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryPoint {
    Login,
    Logout,
}

/// What a canonical path is in the reserved namespace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reserved {
    /// Not in the namespace.
    No,
    /// One of the two entry points.
    Entry(EntryPoint),
    /// Anything else under `/_hopae` (denied).
    Other,
}

impl CanonicalPath {
    /// Classify the path against the reserved namespace, ASCII-case-insensitively:
    /// `/_hopae` or `/_hopae/...` is reserved; exactly `/_hopae/login` and
    /// `/_hopae/logout` are the entry points.
    pub fn reserved(&self) -> Reserved {
        let p = self.0.to_ascii_lowercase();
        if p == RESERVED_ROOT {
            return Reserved::Other;
        }
        match p.strip_prefix("/_hopae/") {
            None => Reserved::No,
            Some("login") => Reserved::Entry(EntryPoint::Login),
            Some("logout") => Reserved::Entry(EntryPoint::Logout),
            Some(_) => Reserved::Other,
        }
    }
}

/// The request's `sec-fetch-site`, as far as the core cares.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FetchSite {
    SameOrigin,
    SameSite,
    CrossSite,
    /// A user-initiated navigation (`none`).
    UserInitiated,
    /// Absent or not a value the specification defines.
    Unknown,
}

/// The `return` query parameter of an entry point, resolved by the adapter
/// (query parsing stays out of the core, ADR-0013).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EntryReturn {
    /// No `return` parameter: the target is the request origin's `/`.
    Absent,
    /// Present but unusable: repeated, not a path-absolute reference or an
    /// absolute URL, carries a handoff parameter, or its path is not canonical.
    Invalid,
    /// An absolute candidate (a path-absolute reference was resolved against
    /// the request origin) with the canonical path of its URL.
    Candidate {
        url: String,
        canonical_path: CanonicalPath,
    },
}

pub struct VerifyInput {
    pub original_url: url::Url,
    pub canonical_path: CanonicalPath,
    pub client_ip: IpAddr,
    pub host: Host,
    pub port: u16,
    pub proto: Scheme,
    pub method: http::Method,
    pub route_id: Option<String>,
    pub cookie_handle: Option<Secret>,
    pub bind_cookie: Option<Secret>,
    pub user_agent: Option<String>,
    pub navigation: Navigation,
    /// An `Accept` header names HTML (`text/html`, `application/xhtml+xml`).
    pub accepts_html: bool,
    pub fetch_site: FetchSite,
    pub entry_return: EntryReturn,
    pub handoff: Handoff,
    pub contract: u8,
    pub caller: CallerAuth,
    pub request_id: String,
}

pub struct Identity {
    pub user_id: UserId,
    pub email: Option<NormalizedEmail>,
    pub preferred_username: Option<String>,
    pub groups: Vec<String>,
    pub session_id: SessionId,
    pub provider_id: ProviderId,
    pub auth_time: Timestamp,
    pub expires_at: Timestamp,
    pub aal: Aal,
    pub factors: Vec<FactorEntry>,
    pub generations: Generations,
}

pub enum Cacheability {
    NoStore,
    Private {
        max_age: Duration,
        fresh_until: Timestamp,
    },
}

pub enum BindAction {
    Keep,
    Plant(Secret),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoginKind {
    Login,
    StepUp,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DenyKind {
    Forbidden,
    ForbiddenHtml,
    RateLimited { retry_after: Duration },
    ContractViolation,
    Unavailable { retry_after: Duration },
}

pub enum Decision {
    Allow {
        identity: Identity,
        cache: Cacheability,
    },
    /// Document: 302 to portal /login?txn=..; Other: 401 JSON {login: original url}; `transaction` is None for Other (nothing created).
    Login {
        transaction: Option<Secret>,
        bind: BindAction,
        kind: LoginKind, /* Login|StepUp */
        clear_handle: bool,
        /// Why a presented handle was refused (`unknown_handle`, `idle`, ...);
        /// `None` when no handle was presented. The `verify.denied` reason.
        cause: Option<Reason>,
    },
    Handoff {
        location: url::Url,
        handle: Secret,
        issued_aal: Aal,
        max_age: Duration,
    },
    CleanRedirect {
        location: url::Url,
    },
    Switch {
        transaction: Secret,
    },
    /// `GET /_hopae/login` with a live session: `302` to the target.
    AlreadyAuthenticated {
        location: url::Url,
    },
    /// `GET /_hopae/logout`: `302` to the portal's `/logout?txn=<ticket>`;
    /// `clear_handle` only for a handle that was refused.
    LogoutEntry {
        transaction: Secret,
        clear_handle: bool,
        /// Why a presented handle was refused (as on `Login`): the
        /// `verify.denied` reason.
        cause: Option<Reason>,
    },
    /// `GET /_hopae/logout` in the no-confirmation mode, after the session
    /// ended: `302` to the portal's `/signed-out?txn=<consumed ticket>` with
    /// the application handle cleared. The ticket is the opaque reference to
    /// the return target; no URL travels in the redirect.
    LoggedOut {
        transaction: Secret,
    },
    Deny {
        reason: Reason,
        kind: DenyKind, /* Forbidden | ForbiddenHtml | RateLimited{retry_after} | ContractViolation | Unavailable{retry_after} */
    },
}

/// Numbers from the configuration that the engine needs.
#[derive(Clone, Copy, Debug)]
pub struct VerifyLimits {
    /// `handoff.max_recoveries`.
    pub max_recoveries: u32,
    /// `txn.per_ip_per_minute`.
    pub txn_per_ip_per_minute: u32,
    /// `txn.max_rows`.
    pub txn_max_rows: u32,
    /// `handoff.per_ip_failures_per_minute`.
    pub handoff_failures_per_minute: u32,
    /// Lifetime of a login transaction: the ADR-0004 constant (600 s), no config key.
    pub txn_lifetime: Duration,
    /// `gateway.verify_budget_ms`.
    pub budget: Duration,
    /// `session.idle` / `session.absolute`.
    pub session: SessionPolicy,
    /// `last_seen_at` write coalescing (ADR-0004: 30 s).
    pub touch_coalesce: Duration,
    /// `cookie.secure`.
    pub secure: bool,
}

impl Default for VerifyLimits {
    fn default() -> Self {
        VerifyLimits {
            max_recoveries: 3,
            txn_per_ip_per_minute: 30,
            txn_max_rows: 1000,
            handoff_failures_per_minute: 10,
            txn_lifetime: Duration::from_secs(600),
            budget: Duration::from_millis(400),
            session: SessionPolicy::default(),
            touch_coalesce: Duration::from_secs(30),
            secure: true,
        }
    }
}

/// The engine's dependencies. Cheap to clone; the budget deadline is per request.
#[derive(Clone)]
pub struct VerifyContext {
    pub directory: Arc<dyn Directory>,
    pub sessions: Arc<dyn Sessions>,
    pub clock: Arc<dyn Clock>,
    pub rng: Arc<dyn Rng>,
    pub snapshot: Arc<ArcSwap<ConfigSnapshot>>,
    pub limits: VerifyLimits,
    /// Real-time deadline for this request's store calls (`None` = unbounded).
    pub deadline: Option<tokio::time::Instant>,
    /// Counts required events as they are built (and tells the prune
    /// trigger); `None` in core unit tests.
    pub emitter: Option<crate::event::bus::Emitter>,
    /// For required events with no state change (a rate-limited redemption).
    pub events: Option<Arc<dyn crate::store::Events>>,
}

impl VerifyContext {
    pub fn new(
        directory: Arc<dyn Directory>,
        sessions: Arc<dyn Sessions>,
        clock: Arc<dyn Clock>,
        rng: Arc<dyn Rng>,
        snapshot: Arc<ArcSwap<ConfigSnapshot>>,
        limits: VerifyLimits,
    ) -> Self {
        VerifyContext {
            directory,
            sessions,
            clock,
            rng,
            snapshot,
            limits,
            deadline: None,
            emitter: None,
            events: None,
        }
    }

    /// The same context counting its required events through `emitter` and
    /// recording stateless ones through `events`.
    pub fn with_events(
        mut self,
        emitter: crate::event::bus::Emitter,
        events: Arc<dyn crate::store::Events>,
    ) -> Self {
        self.emitter = Some(emitter);
        self.events = Some(events);
        self
    }

    /// The same context with the request's budget deadline set to now + budget.
    pub fn with_budget(&self) -> Self {
        let mut c = self.clone();
        c.deadline = Some(tokio::time::Instant::now() + self.limits.budget);
        c
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn class(p: &str) -> Reserved {
        CanonicalPath::new(p.to_string()).reserved()
    }

    #[test]
    fn the_reserved_namespace_is_matched_ascii_case_insensitively() {
        assert_eq!(class("/"), Reserved::No);
        assert_eq!(class("/admin"), Reserved::No);
        assert_eq!(class("/_hopae-x"), Reserved::No);
        assert_eq!(class("/x/_hopae/login"), Reserved::No);
        assert_eq!(class("/_hopae"), Reserved::Other);
        assert_eq!(class("/_HOPAE"), Reserved::Other);
        assert_eq!(class("/_hopae/"), Reserved::Other);
        assert_eq!(class("/_hopae/verify"), Reserved::Other);
        assert_eq!(class("/_hopae/logout/"), Reserved::Other);
        assert_eq!(class("/_hopae/login/x"), Reserved::Other);
        assert_eq!(class("/_hopae/login"), Reserved::Entry(EntryPoint::Login));
        assert_eq!(class("/_HOPAE/Logout"), Reserved::Entry(EntryPoint::Logout));
    }
}
