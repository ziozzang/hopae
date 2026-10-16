//! The typed event model (ADR-0009): kinds, outcomes, stable reason codes and
//! the builder that enforces "identifiers only, bounded, allowlisted attrs".

use std::net::IpAddr;

use crate::crypto::{Clock, Digest, Rng, Timestamp, sha256, time_ordered_id};
use crate::identity::types::UserId;
use crate::policy::types::AppId;
use crate::provider::types::ProviderId;
use crate::session::types::SessionId;

string_newtype!(
    /// Event identifier, `e_` + 26 Crockford base32 characters, time-ordered
    /// (48-bit millisecond prefix). Also the webhook idempotency key.
    EventId
);

#[derive(Clone)]
pub struct Event {
    pub event_id: EventId,
    pub at: Timestamp,
    pub kind: EventKind,
    pub outcome: Outcome,
    pub reason: Option<Reason>,
    pub user_id: Option<UserId>,
    pub session_id: Option<SessionId>,
    pub app_id: Option<AppId>,
    pub provider_id: Option<ProviderId>,
    pub client_ip: Option<IpAddr>,
    pub ua_sha256: Option<Digest>,
    /// At most 64 bytes, sanitized.
    pub ua_prefix: Option<String>,
    pub request_id: String,
    /// At most 2 KiB serialized; allowlisted keys.
    pub attrs: serde_json::Map<String, serde_json::Value>,
}

impl std::fmt::Debug for Event {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Event")
            .field("event_id", &self.event_id)
            .field("kind", &self.kind.name())
            .field("outcome", &self.outcome)
            .field("reason", &self.reason.map(|r| r.0))
            .finish_non_exhaustive()
    }
}

impl Event {
    /// The JSON shape used by the structured-log sink and the test hooks.
    /// `at` is unix seconds with a millisecond fraction.
    pub fn to_json(&self) -> serde_json::Value {
        let mut m = serde_json::Map::new();
        m.insert("event_id".into(), self.event_id.as_str().into());
        m.insert("at".into(), (self.at.0 as f64 / 1000.0).into());
        m.insert("kind".into(), self.kind.name().into());
        m.insert("outcome".into(), self.outcome.as_str().into());
        let mut opt = |k: &str, v: Option<String>| {
            m.insert(k.into(), v.map_or(serde_json::Value::Null, Into::into));
        };
        opt("reason", self.reason.map(|r| r.0.to_string()));
        opt("user_id", self.user_id.as_ref().map(|v| v.to_string()));
        opt(
            "session_id",
            self.session_id.as_ref().map(|v| v.to_string()),
        );
        opt("app_id", self.app_id.as_ref().map(|v| v.to_string()));
        opt(
            "provider_id",
            self.provider_id.as_ref().map(|v| v.to_string()),
        );
        opt("client_ip", self.client_ip.map(|v| v.to_string()));
        opt("ua_sha256", self.ua_sha256.map(|v| v.to_hex()));
        opt("ua_prefix", self.ua_prefix.clone());
        m.insert("request_id".into(), self.request_id.clone().into());
        m.insert(
            "attrs".into(),
            serde_json::Value::Object(self.attrs.clone()),
        );
        serde_json::Value::Object(m)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EventKind {
    LoginStarted,
    LoginSucceeded,
    LoginFailed,
    SessionCreated,
    FactorEnrollmentPrepared,
    FactorEnrollmentActivated,
    FactorEnrollmentExpired,
    FactorTotpConsumed,
    FactorExternalConsumed,
    FactorRegistryPublished,
    FactorAuthorityPublished,
    FactorEnrollmentRevoked,
    FactorWebauthnRegistered,
    FactorWebauthnUsed,
    FactorWebauthnRenamed,
    FactorWebauthnRevoked,
    FactorWebauthnFailed,
    FactorWebauthnCloneSuspected,
    FactorRecoveryCodesGenerated,
    FactorRecoveryCodeUsed,

    SessionHandoff,
    HandoffRejected,
    SessionTerminated,
    HandleRevoked,
    IdentityLinked,
    IdentityConflict,
    CsrfRejected,
    ConfigLoaded, // required (outbox)
    /// `hopae providers import --force` (required, `admin.*`).
    AdminProvidersImport,
    VerifyDenied,
    ProviderError,
    TxnEvicted,
    EventsDropped,
    SinkBacklogOverflow, // diagnostic (batch writer)
    /// Management console mutations and refusals (ADR-0016, required).
    AdminGrant,
    AdminRevoke,
    AdminUserDisable,
    AdminUserEnable,
    AdminSessionTerminate,
    AdminSessionsTerminate,
    AdminDenied,
    /// `hopae admin factors reset` and the console's factor reset (ADR-0017,
    /// required; `attrs.scope` names what was reset).
    AdminFactorReset,
    /// A console publication of the service authentication profiles or the
    /// credential projection plans (required; in the publication's transaction).
    AdminProfilesPublish,
    AdminProjectionsPublish,
    /// An audited administrative read of the subject directory or the
    /// authentication explain API (required; travels alone).
    AdminRead,
    /// Groups (ADR-0019, required): a group's lifecycle and memberships,
    /// whether changed by an administrator, a provider sync or maintenance.
    GroupCreated,
    GroupUpdated,
    GroupDeleted,
    GroupMemberAdded,
    GroupMemberRemoved,
    /// A provider membership suspended because no successful assertion
    /// refreshed it within `groups.max_staleness_secs`, and restored.
    GroupMembershipStale,
    GroupMembershipRestored,
    /// A provider's group assertion was not applied (diagnostic).
    GroupSyncRefused,
}

impl EventKind {
    pub const ALL: [EventKind; 53] = [
        EventKind::LoginStarted,
        EventKind::LoginSucceeded,
        EventKind::LoginFailed,
        EventKind::SessionCreated,
        EventKind::FactorEnrollmentPrepared,
        EventKind::FactorEnrollmentActivated,
        EventKind::FactorEnrollmentExpired,
        EventKind::FactorTotpConsumed,
        EventKind::FactorExternalConsumed,
        EventKind::FactorRegistryPublished,
        EventKind::FactorAuthorityPublished,
        EventKind::FactorEnrollmentRevoked,
        EventKind::FactorWebauthnRegistered,
        EventKind::FactorWebauthnUsed,
        EventKind::FactorWebauthnRenamed,
        EventKind::FactorWebauthnRevoked,
        EventKind::FactorWebauthnFailed,
        EventKind::FactorWebauthnCloneSuspected,
        EventKind::FactorRecoveryCodesGenerated,
        EventKind::FactorRecoveryCodeUsed,
        EventKind::SessionHandoff,
        EventKind::HandoffRejected,
        EventKind::SessionTerminated,
        EventKind::HandleRevoked,
        EventKind::IdentityLinked,
        EventKind::IdentityConflict,
        EventKind::CsrfRejected,
        EventKind::ConfigLoaded,
        EventKind::AdminProvidersImport,
        EventKind::VerifyDenied,
        EventKind::ProviderError,
        EventKind::TxnEvicted,
        EventKind::EventsDropped,
        EventKind::SinkBacklogOverflow,
        EventKind::AdminGrant,
        EventKind::AdminRevoke,
        EventKind::AdminUserDisable,
        EventKind::AdminUserEnable,
        EventKind::AdminSessionTerminate,
        EventKind::AdminSessionsTerminate,
        EventKind::AdminDenied,
        EventKind::AdminFactorReset,
        EventKind::AdminProfilesPublish,
        EventKind::AdminProjectionsPublish,
        EventKind::AdminRead,
        EventKind::GroupCreated,
        EventKind::GroupUpdated,
        EventKind::GroupDeleted,
        EventKind::GroupMemberAdded,
        EventKind::GroupMemberRemoved,
        EventKind::GroupMembershipStale,
        EventKind::GroupMembershipRestored,
        EventKind::GroupSyncRefused,
    ];

    /// Required kinds travel in the transaction of the state change they
    /// describe (transactional outbox); the rest are best-effort diagnostics.
    pub fn is_required(self) -> bool {
        !matches!(
            self,
            EventKind::VerifyDenied
                | EventKind::ProviderError
                | EventKind::TxnEvicted
                | EventKind::EventsDropped
                | EventKind::SinkBacklogOverflow
                | EventKind::GroupSyncRefused
        )
    }

    pub fn name(self) -> &'static str {
        match self {
            EventKind::LoginStarted => "login.started",
            EventKind::LoginSucceeded => "login.succeeded",
            EventKind::LoginFailed => "login.failed",
            EventKind::SessionCreated => "session.created",
            EventKind::FactorEnrollmentPrepared => "factor.enrollment_prepared",
            EventKind::FactorEnrollmentActivated => "factor.enrollment_activated",
            EventKind::FactorEnrollmentExpired => "factor.enrollment_expired",
            EventKind::FactorTotpConsumed => "factor.totp_consumed",
            EventKind::FactorExternalConsumed => "factor.external_consumed",
            EventKind::FactorRegistryPublished => "factor.registry_published",
            EventKind::FactorAuthorityPublished => "factor.authority_published",
            EventKind::FactorEnrollmentRevoked => "factor.enrollment_revoked",
            EventKind::FactorWebauthnRegistered => "factor.webauthn_registered",
            EventKind::FactorWebauthnUsed => "factor.webauthn_used",
            EventKind::FactorWebauthnRenamed => "factor.webauthn_renamed",
            EventKind::FactorWebauthnRevoked => "factor.webauthn_revoked",
            EventKind::FactorWebauthnFailed => "factor.webauthn_failed",
            EventKind::FactorWebauthnCloneSuspected => "factor.webauthn_clone_suspected",
            EventKind::FactorRecoveryCodesGenerated => "factor.recovery_codes_generated",
            EventKind::FactorRecoveryCodeUsed => "factor.recovery_code_used",

            EventKind::SessionHandoff => "session.handoff",
            EventKind::HandoffRejected => "handoff.rejected",
            EventKind::SessionTerminated => "session.terminated",
            EventKind::HandleRevoked => "handle.revoked",
            EventKind::IdentityLinked => "identity.linked",
            EventKind::IdentityConflict => "identity.conflict",
            EventKind::CsrfRejected => "csrf.rejected",
            EventKind::ConfigLoaded => "config.loaded",
            EventKind::AdminProvidersImport => "admin.providers_import",
            EventKind::VerifyDenied => "verify.denied",
            EventKind::ProviderError => "provider.error",
            EventKind::TxnEvicted => "txn.evicted",
            EventKind::EventsDropped => "events.dropped",
            EventKind::SinkBacklogOverflow => "sink.backlog_overflow",
            EventKind::AdminGrant => "admin.grant",
            EventKind::AdminRevoke => "admin.revoke",
            EventKind::AdminUserDisable => "admin.user_disable",
            EventKind::AdminUserEnable => "admin.user_enable",
            EventKind::AdminSessionTerminate => "admin.session_terminate",
            EventKind::AdminSessionsTerminate => "admin.sessions_terminate",
            EventKind::AdminDenied => "admin.denied",
            EventKind::AdminFactorReset => "admin.factor_reset",
            EventKind::AdminProfilesPublish => "admin.profiles_publish",
            EventKind::AdminProjectionsPublish => "admin.projections_publish",
            EventKind::AdminRead => "admin.read",
            EventKind::GroupCreated => "group.created",
            EventKind::GroupUpdated => "group.updated",
            EventKind::GroupDeleted => "group.deleted",
            EventKind::GroupMemberAdded => "group.member_added",
            EventKind::GroupMemberRemoved => "group.member_removed",
            EventKind::GroupMembershipStale => "group.membership_stale",
            EventKind::GroupMembershipRestored => "group.membership_restored",
            EventKind::GroupSyncRefused => "group.sync_refused",
        }
    }

    pub fn from_name(s: &str) -> Option<EventKind> {
        EventKind::ALL.into_iter().find(|k| k.name() == s)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Success,
    Failure,
    Info,
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::Success => "success",
            Outcome::Failure => "failure",
            Outcome::Info => "info",
        }
    }

    pub fn parse(s: &str) -> Option<Outcome> {
        match s {
            "success" => Some(Outcome::Success),
            "failure" => Some(Outcome::Failure),
            "info" => Some(Outcome::Info),
            _ => None,
        }
    }
}

/// Stable reason code: a &'static str from `event::reasons` (every code used by a scenario is a constant there).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Reason(pub &'static str);

/// Every reason code the scenarios, ADRs and the gateway contract name.
pub mod reasons {
    use super::Reason;

    macro_rules! reasons {
        ($($name:ident = $code:literal),+ $(,)?) => {
            $(pub const $name: Reason = Reason($code);)+
            /// All codes, for tests and documentation checks.
            pub const ALL: &[Reason] = &[$($name),+];
        };
    }

    reasons! {
        // Verify / gateway contract
        OK = "ok",
        UNKNOWN_APP = "unknown_app",
        APP_DISABLED = "app_disabled",
        CALLER_UNAUTHORIZED = "caller_unauthorized",
        CONTRACT_VIOLATION = "contract_violation",
        CONTRACT_UNSUPPORTED = "contract_unsupported",
        PATH_NOT_CANONICAL = "path_not_canonical",
        CANONICAL_PATH_MISMATCH = "canonical_path_mismatch",
        WRONG_LISTENER = "wrong_listener",
        STORE_UNAVAILABLE = "store_unavailable",
        BUDGET_EXCEEDED = "budget_exceeded",
        OVERLOADED = "overloaded",
        HEADER_TOO_LARGE = "header_too_large",
        // Application-host entry points (ADR-0015)
        RESERVED_PATH = "reserved_path",
        ENTRY_POINT_NOT_DOCUMENT = "entry_point_not_document",
        RETURN_NOT_ALLOWED = "return_not_allowed",
        LOGOUT_ENTRY = "logout_entry",
        ALREADY_AUTHENTICATED = "already_authenticated",
        TXN_PURPOSE_MISMATCH = "txn_purpose_mismatch",
        // Only for defects no scenario reason covers; logged at `error` level,
        // never replaces store_unavailable, budget_exceeded or overloaded.
        INTERNAL_ERROR = "internal_error",
        RATE_LIMITED = "rate_limited",
        CLOCK_SKEW = "clock_skew",
        LOGIN_REQUIRED = "login_required",
        STEP_UP_REQUIRED = "step_up_required",
        UNKNOWN_HANDLE = "unknown_handle",
        MALFORMED_HANDLE = "malformed_handle",
        HANDLE_HOST_MISMATCH = "handle_host_mismatch",
        USER_DISABLED = "user_disabled",
        AUTHZ_CHANGE = "authz_change",
        // Handoff
        HANDOFF = "handoff",
        HANDOFF_AMBIGUOUS = "handoff_ambiguous",
        HANDOFF_PARAMETER_NOT_ALLOWED = "handoff_parameter_not_allowed",
        HANDOFF_RECOVERY_EXHAUSTED = "handoff_recovery_exhausted",
        CODE_UNKNOWN = "code_unknown",
        CODE_CONSUMED = "code_consumed",
        CODE_EXPIRED = "code_expired",
        CODE_HOST_MISMATCH = "code_host_mismatch",
        CODE_PATH_MISMATCH = "code_path_mismatch",
        CODE_IP_MISMATCH = "code_ip_mismatch",
        CODE_STALE_GENERATION = "code_stale_generation",
        CODE_ALREADY_REDEEMED = "code_already_redeemed",
        BIND_MISMATCH = "bind_mismatch",
        SESSION_CONFLICT = "session_conflict",
        // Return target validation
        INSECURE_TRANSPORT = "insecure_transport",
        USERINFO = "userinfo",
        FRAGMENT = "fragment",
        TOO_LONG = "too_long",
        NOT_ABSOLUTE = "not_absolute",
        PORT_NOT_ALLOWED = "port_not_allowed",
        SCHEME = "scheme",
        // Session and handle termination
        LOGOUT = "logout",
        LOGOUT_ALL = "logout_all",
        IDLE = "idle",
        ABSOLUTE = "absolute",
        BINDING_IP = "binding_ip",
        BINDING_UA = "binding_ua",
        ADMIN = "admin",
        BLOCKED = "blocked",
        KEY_ROTATION = "key_rotation",
        ELEVATION = "elevation",
        SWITCH = "switch",
        SESSION_TERMINATED = "session_terminated",
        REPLACED = "replaced",
        // Transactions and portal
        TXN_BINDING = "txn_binding",
        TXN_EXPIRED = "txn_expired",
        TXN_CONSUMED = "txn_consumed",
        TXN_RATE_LIMITED = "txn_rate_limited",
        TXN_EVICTED = "txn_evicted",
        PORTAL_BIND_MISMATCH = "portal_bind_mismatch",
        CSRF_REJECTED = "csrf_rejected",
        COUNTER_UNAVAILABLE = "counter_unavailable",
        // Identity and linking
        LINK_REQUIRED = "link_required",
        EMAIL_IN_USE = "email_in_use",
        AUTHORITATIVE_EMAIL = "authoritative_email",
        FRESH_AUTH = "fresh_auth",
        // Providers
        PROVIDER_DISABLED = "provider_disabled",
        PROVIDER_MISMATCH = "provider_mismatch",
        EMAIL_DOMAIN_NOT_ALLOWED = "email_domain_not_allowed",
        INVALID_CREDENTIALS = "invalid_credentials",
        PROVIDER_UNAVAILABLE = "provider_unavailable",
        PROVIDER_ERROR = "provider_error",
        PROVIDER_TIMEOUT = "provider_timeout",
        PROVIDER_RESPONSE_INVALID = "provider_response_invalid",
        PROVIDER_RESPONSE_TOO_LARGE = "provider_response_too_large",
        INVALID_STATE = "invalid_state",
        INVALID_NONCE = "invalid_nonce",
        INVALID_AUDIENCE = "invalid_audience",
        INVALID_ISSUER = "invalid_issuer",
        INVALID_SIGNATURE = "invalid_signature",
        INVALID_TOKEN_HEADER = "invalid_token_header",
        TOKEN_EXPIRED = "token_expired",
        ID_TOKEN_MISSING = "id_token_missing",
        USERINFO_SUBJECT_MISMATCH = "userinfo_subject_mismatch",
        DISCOVERY_ISSUER_MISMATCH = "discovery_issuer_mismatch",
        // Management console (ADR-0016)
        NOT_ADMIN = "not_admin",
        ROLE_INSUFFICIENT = "role_insufficient",
        AUTH_TOO_OLD = "auth_too_old",
        AAL_INSUFFICIENT = "aal_insufficient",
        SELF_TARGET = "self_target",
        ACTOR_REVOKED = "actor_revoked",
        UNTRUSTED_PEER = "untrusted_peer",
        REAUTH_REQUIRED = "reauth_required",
        REAUTH_NOT_FRESH = "reauth_not_fresh",
        REAUTH_AUTH_TIME_MISSING = "reauth_auth_time_missing",
        INVALID_AUTH_TIME = "invalid_auth_time",
        REAUTH = "reauth",
        FACTOR_REVOKED = "factor_revoked",
        // WebAuthn and recovery codes (ADR-0017)
        COUNTER_REGRESSION = "counter_regression",
        COUNTER_STALE = "counter_stale",
        FACTOR_RESET = "factor_reset",
        HIGH_ASSURANCE_REQUIRED = "high_assurance_required",
        PASSKEY_REMOVED = "passkey_removed",
        CEREMONY_INVALID = "ceremony_invalid",
        CEREMONY_EXPIRED = "ceremony_expired",
        RECOVERY_CODE = "recovery_code",
        INVALID_CURSOR = "invalid_cursor",
        INVALID_FILTER = "invalid_filter",
        INVALID_ID = "invalid_id",
        PAYLOAD_TOO_LARGE = "payload_too_large",
        NOT_FOUND = "not_found",
        // Events and delivery
        BACKLOG_OVERFLOW = "backlog_overflow",
        RETRIES_EXHAUSTED = "retries_exhausted",
        PRUNED = "pruned",
        SAMPLED = "sampled",
    }

    /// Look a code up by its text (the store uses this when reading rows).
    pub fn parse(s: &str) -> Option<Reason> {
        ALL.iter().copied().find(|r| r.0 == s)
    }
}

/// Keys an event's `attrs` may carry. A key outside this list is dropped by
/// [`EventBuilder::attr`]; add keys here (a minor change, ADR-0009), never
/// token-like names.
pub const ATTR_ALLOWLIST: &[&str] = &[
    "aal",
    "actor",
    "assurance",
    "enrollment_id",
    "factor_id",
    "actor_session",
    "delegated_issuer",
    "delegated_actor",
    "delegated_operation",
    "app",
    "apps",
    "change",
    "auth_time_source",
    "bound_ip",
    "bulk_operation",
    "cause",
    "client_request_id",
    "config_digest",
    "count",
    "depth",
    "dropped",
    "dropped_by_kind",
    "endpoint",
    "error",
    "expires_at",
    "forced",
    "from_user_id",
    "group_id",
    "host",
    "insecure_mode",
    "kind",
    "label",
    "listeners",
    "managed_by",
    "method",
    "navigation",
    "note",
    "observed_ip",
    "observed_sha256",
    "port",
    "previous_role",
    "provider",
    "providers",
    "purpose",
    "query_sha256",
    "recorded_sha256",
    "recovery_depth",
    "requested",
    "reauth",
    "retry_after",
    "revision",
    "role",
    "route_id",
    "sampled_count",
    "scope",
    "sink",
    "source",
    "sso",
    "status",
    "to_user_id",
    "truncated",
    "unauthenticated_caller",
];

/// Largest serialized `attrs` object, in bytes.
pub const ATTRS_MAX_BYTES: usize = 2048;
/// Longest string value kept in `attrs`, in bytes.
pub const ATTR_VALUE_MAX_BYTES: usize = 256;
/// Longest sanitized user-agent prefix kept on an event, in bytes.
pub const UA_PREFIX_MAX_BYTES: usize = 64;

/// `EventBuilder::new(clock, rng, kind, outcome, request_id).user(..).session(..).app(..).ip(..).ua(..).reason(..).attr(k, v).build()`
pub struct EventBuilder {
    event: Event,
}

impl EventBuilder {
    pub fn new(
        clock: &dyn Clock,
        rng: &dyn Rng,
        kind: EventKind,
        outcome: Outcome,
        request_id: impl Into<String>,
    ) -> Self {
        let at = clock.now();
        EventBuilder {
            event: Event {
                event_id: EventId::new(time_ordered_id(rng, "e_", at)),
                at,
                kind,
                outcome,
                reason: None,
                user_id: None,
                session_id: None,
                app_id: None,
                provider_id: None,
                client_ip: None,
                ua_sha256: None,
                ua_prefix: None,
                request_id: request_id.into(),
                attrs: serde_json::Map::new(),
            },
        }
    }

    pub fn user(mut self, id: &UserId) -> Self {
        self.event.user_id = Some(id.clone());
        self
    }

    pub fn session(mut self, id: &SessionId) -> Self {
        self.event.session_id = Some(id.clone());
        self
    }

    pub fn app(mut self, id: &AppId) -> Self {
        self.event.app_id = Some(id.clone());
        self
    }

    pub fn provider(mut self, id: &ProviderId) -> Self {
        self.event.provider_id = Some(id.clone());
        self
    }

    pub fn ip(mut self, ip: IpAddr) -> Self {
        self.event.client_ip = Some(ip);
        self
    }

    /// Record the user agent as a digest plus a sanitized prefix (never the raw string).
    pub fn ua(mut self, ua: Option<&str>) -> Self {
        if let Some(ua) = ua {
            self.event.ua_sha256 = Some(sha256(ua.as_bytes()));
            self.event.ua_prefix = Some(sanitize_prefix(ua, UA_PREFIX_MAX_BYTES));
        }
        self
    }

    pub fn reason(mut self, reason: Reason) -> Self {
        self.event.reason = Some(reason);
        self
    }

    /// Add an attribute. Keys outside [`ATTR_ALLOWLIST`] are dropped, string
    /// values are cut to 256 bytes, and once the object would exceed 2 KiB
    /// further attributes are dropped and `truncated: true` is set.
    pub fn attr(mut self, key: &str, value: impl Into<serde_json::Value>) -> Self {
        if !ATTR_ALLOWLIST.contains(&key) {
            return self;
        }
        let value = bound_value(value.into());
        let mut probe = self.event.attrs.clone();
        probe.insert(key.to_string(), value.clone());
        let size = serde_json::to_vec(&probe).map_or(usize::MAX, |v| v.len());
        if size <= ATTRS_MAX_BYTES - 20 {
            self.event.attrs = probe;
        } else {
            self.event.attrs.insert("truncated".into(), true.into());
        }
        self
    }

    pub fn build(self) -> Event {
        self.event
    }
}

fn bound_value(v: serde_json::Value) -> serde_json::Value {
    match v {
        serde_json::Value::String(s) => {
            serde_json::Value::String(sanitize_prefix(&s, ATTR_VALUE_MAX_BYTES))
        }
        other => other,
    }
}

/// The sanitized user-agent prefix events and sessions record (never the raw string).
pub fn ua_prefix(ua: &str) -> String {
    sanitize_prefix(ua, UA_PREFIX_MAX_BYTES)
}

/// Keep printable ASCII and spaces, replace everything else with `?`, cut to `max` bytes.
fn sanitize_prefix(s: &str, max: usize) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_graphic() || c == ' ' {
                c
            } else {
                '?'
            }
        })
        .take(max)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{SeededRng, TestClock};

    fn builder(kind: EventKind) -> EventBuilder {
        let clock = TestClock::new(Timestamp(1_700_000_000_123));
        EventBuilder::new(&clock, &SeededRng::new(1), kind, Outcome::Info, "req-1")
    }

    #[test]
    fn kinds_have_unique_names_and_the_documented_split() {
        let mut names: Vec<_> = EventKind::ALL.iter().map(|k| k.name()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), EventKind::ALL.len());
        for k in EventKind::ALL {
            assert_eq!(EventKind::from_name(k.name()), Some(k));
        }
        let required = EventKind::ALL.iter().filter(|k| k.is_required()).count();
        assert_eq!(required, 47);
        assert!(!EventKind::VerifyDenied.is_required());
        assert!(EventKind::ConfigLoaded.is_required());
    }

    #[test]
    fn console_kinds_reasons_and_attributes_are_registered() {
        assert_eq!(EventKind::ALL.len(), 53);
        for (kind, name) in [
            (
                EventKind::FactorExternalConsumed,
                "factor.external_consumed",
            ),
            (EventKind::AdminGrant, "admin.grant"),
            (EventKind::AdminRevoke, "admin.revoke"),
            (EventKind::AdminUserDisable, "admin.user_disable"),
            (EventKind::AdminUserEnable, "admin.user_enable"),
            (EventKind::AdminSessionTerminate, "admin.session_terminate"),
            (
                EventKind::AdminSessionsTerminate,
                "admin.sessions_terminate",
            ),
            (EventKind::AdminDenied, "admin.denied"),
            (EventKind::AdminRead, "admin.read"),
        ] {
            assert_eq!(kind.name(), name);
            assert!(kind.is_required(), "{name} travels in the outbox");
            assert_eq!(EventKind::from_name(name), Some(kind));
        }
        for r in [
            "not_admin",
            "role_insufficient",
            "auth_too_old",
            "aal_insufficient",
            "self_target",
            "actor_revoked",
            "untrusted_peer",
            "reauth_required",
            "reauth_not_fresh",
            "reauth_auth_time_missing",
            "invalid_auth_time",
            "reauth",
            "invalid_cursor",
            "invalid_filter",
            "invalid_id",
            "payload_too_large",
            "not_found",
            "user_disabled",
        ] {
            assert!(reasons::parse(r).is_some(), "{r}");
        }
        let b = builder(EventKind::AdminGrant)
            .attr("actor", "cli")
            .attr("actor_session", "s_1")
            .attr("role", "admin")
            .attr("previous_role", "viewer")
            .attr("managed_by", "file")
            .attr("forced", true)
            .attr("note", "n".repeat(1000))
            .attr("reauth", true)
            .attr("auth_time_source", "provider_claim")
            .attr("password", "never")
            .build();
        assert_eq!(b.attrs.len(), 9, "{:?}", b.attrs);
        assert_eq!(
            b.attrs["note"].as_str().unwrap().len(),
            256,
            "note is bounded"
        );
    }

    #[test]
    fn reasons_are_unique_snake_case() {
        let mut seen = std::collections::HashSet::new();
        for r in reasons::ALL {
            assert!(seen.insert(r.0), "duplicate {}", r.0);
            assert!(
                r.0.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'),
                "{}",
                r.0
            );
            assert_eq!(reasons::parse(r.0), Some(*r));
        }
    }

    #[test]
    fn builder_fills_fields_and_ids_are_time_ordered() {
        let clock = TestClock::new(Timestamp(1_000));
        let rng = SeededRng::new(5);
        let a =
            EventBuilder::new(&clock, &rng, EventKind::LoginStarted, Outcome::Info, "r").build();
        clock.advance(std::time::Duration::from_millis(1));
        let b =
            EventBuilder::new(&clock, &rng, EventKind::LoginStarted, Outcome::Info, "r").build();
        assert!(a.event_id < b.event_id);
        assert_eq!(a.at, Timestamp(1_000));
        let e = builder(EventKind::LoginFailed)
            .user(&UserId::new("u_1"))
            .session(&SessionId::new("s_1"))
            .app(&AppId::new("app"))
            .provider(&ProviderId::new("mock"))
            .ip("192.0.2.1".parse().unwrap())
            .reason(reasons::INVALID_STATE)
            .build();
        let j = e.to_json();
        assert_eq!(j["kind"], "login.failed");
        assert_eq!(j["reason"], "invalid_state");
        assert_eq!(j["client_ip"], "192.0.2.1");
        assert_eq!(j["at"], 1_700_000_000.123);
        assert_eq!(j["request_id"], "req-1");
    }

    #[test]
    fn user_agent_is_digest_plus_sanitized_prefix() {
        let ua = format!("Mozilla/5.0 \u{0}\u{7f}\u{00e9}{}", "x".repeat(200));
        let e = builder(EventKind::VerifyDenied).ua(Some(&ua)).build();
        assert_eq!(e.ua_sha256, Some(sha256(ua.as_bytes())));
        let p = e.ua_prefix.unwrap();
        assert_eq!(p.len(), 64);
        assert!(p.starts_with("Mozilla/5.0 ???"));
        let e = builder(EventKind::VerifyDenied).ua(None).build();
        assert!(e.ua_sha256.is_none() && e.ua_prefix.is_none());
    }

    #[test]
    fn attrs_are_allowlisted_and_bounded() {
        let e = builder(EventKind::SessionHandoff)
            .attr("host", "app.example.test")
            .attr("access_token", "secret")
            .attr("sso", true)
            .attr("client_request_id", "y".repeat(1000))
            .build();
        assert_eq!(e.attrs.len(), 3);
        assert!(!e.attrs.contains_key("access_token"));
        assert_eq!(e.attrs["client_request_id"].as_str().unwrap().len(), 256);
        let mut b = builder(EventKind::SessionHandoff);
        for _ in 0..40 {
            b = b.attr("error", "z".repeat(200));
            b = b.attr("label", "q".repeat(200));
            b = b.attr("method", "m".repeat(200));
            b = b.attr("kind", "k".repeat(200));
            b = b.attr("status", "s".repeat(200));
            b = b.attr("sink", "s".repeat(200));
            b = b.attr("route_id", "r".repeat(200));
            b = b.attr("purpose", "p".repeat(200));
            b = b.attr("host", "h".repeat(200));
            b = b.attr("provider", "v".repeat(200));
            b = b.attr("app", "a".repeat(200));
        }
        let e = b.build();
        let size = serde_json::to_vec(&e.attrs).unwrap().len();
        assert!(size <= ATTRS_MAX_BYTES, "{size}");
        assert_eq!(
            e.attrs.get("truncated"),
            Some(&serde_json::Value::Bool(true))
        );
    }
}
