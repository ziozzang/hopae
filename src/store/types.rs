//! Rows and value types exchanged through the store traits.

use std::net::IpAddr;
use std::time::Duration;

use crate::crypto::{Digest, Secret, Timestamp};
use crate::event::types::{Event, EventId, EventKind, Reason};
use crate::identity::types::{NormalizedEmail, UserId};
use crate::policy::types::{AppId, Host, ProviderConfig};
use crate::provider::types::{ProviderId, ProviderKind};
use crate::session::types::{Aal, FactorEntry, SessionId};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UserStatus {
    Active,
    Disabled,
}

impl UserStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            UserStatus::Active => "active",
            UserStatus::Disabled => "disabled",
        }
    }

    pub fn parse(s: &str) -> Option<UserStatus> {
        match s {
            "active" => Some(UserStatus::Active),
            "disabled" => Some(UserStatus::Disabled),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct User {
    pub user_id: UserId,
    pub primary_email: Option<NormalizedEmail>,
    pub email_verified: bool,
    pub email_authoritative: bool,
    pub display_name: Option<String>,
    pub username: Option<String>,
    pub status: UserStatus,
    pub authz_version: u64,
    pub groups: Vec<String>,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
    pub last_login_at: Option<Timestamp>,
}

#[derive(Clone, Debug)]
pub struct UserAuthz {
    pub status: UserStatus,
    pub authz_version: u64,
    pub groups: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct IdentityRow {
    pub provider_id: ProviderId,
    pub subject: String,
    pub user_id: UserId,
    pub email: Option<NormalizedEmail>,
    pub email_verified: bool,
    pub email_authoritative: bool,
    pub name: Option<String>,
    pub picture: Option<String>,
    pub first_seen_at: Timestamp,
    pub last_seen_at: Timestamp,
}

#[derive(Clone, Debug)]
pub struct NewUser {
    pub primary_email: Option<NormalizedEmail>,
    pub email_verified: bool,
    pub email_authoritative: bool,
    pub display_name: Option<String>,
    pub username: Option<String>,
}

#[derive(Clone, Debug)]
pub struct NewIdentity {
    pub provider_id: ProviderId,
    pub subject: String,
    pub email: Option<NormalizedEmail>,
    pub email_verified: bool,
    pub email_authoritative: bool,
    pub name: Option<String>,
    pub picture: Option<String>,
    /// At most 8 KiB serialized; a larger value is replaced by `{"truncated":true}`.
    pub raw_claims: serde_json::Value,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManagedBy {
    File,
    Api,
}

impl ManagedBy {
    pub fn as_str(self) -> &'static str {
        match self {
            ManagedBy::File => "file",
            ManagedBy::Api => "api",
        }
    }

    pub fn parse(s: &str) -> Option<ManagedBy> {
        match s {
            "file" => Some(ManagedBy::File),
            "api" => Some(ManagedBy::Api),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ProviderRow {
    pub provider_id: ProviderId,
    pub kind: ProviderKind,
    pub display_name: String,
    pub enabled: bool,
    pub managed_by: ManagedBy,
    pub deleted_at: Option<Timestamp>,
    pub sort_order: i32,
    pub config: serde_json::Value,
    pub client_secret_env: Option<String>,
    pub allowed_email_domains: Vec<String>,
    pub authoritative_domains: Vec<String>,
    pub auto_link: bool,
    pub trust_email: bool,
}

impl ProviderRow {
    /// The row a configuration entry imports as: `managed_by = file`, not
    /// deleted. `config` carries `client_id`, `issuer` and `scope`.
    pub fn from_config(c: &ProviderConfig) -> ProviderRow {
        ProviderRow {
            provider_id: c.provider_id.clone(),
            kind: c.kind,
            display_name: c.display_name.clone(),
            enabled: c.enabled,
            managed_by: ManagedBy::File,
            deleted_at: None,
            sort_order: c.sort_order,
            config: {
                let mut config = serde_json::json!({
                    "client_id": c.client_id,
                    "issuer": c.issuer,
                    "scope": c.scope,
                });
                if let Some(ldap) = &c.ldap {
                    config["ldap"] = serde_json::json!(ldap);
                }
                if !c.endpoint_hosts.is_empty() {
                    config["endpoint_hosts"] = serde_json::json!(c.endpoint_hosts);
                }
                if let Some(allow) = c.allow_private_endpoints {
                    config["allow_private_endpoints"] = serde_json::json!(allow);
                }
                config
            },
            client_secret_env: c.client_secret_env.clone(),
            allowed_email_domains: c.allowed_email_domains.clone(),
            authoritative_domains: c.authoritative_domains.clone(),
            auto_link: c.auto_link,
            trust_email: c.trust_email,
        }
    }
}

/// What `import_providers` did, by provider id.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ImportReport {
    pub inserted: Vec<ProviderId>,
    pub updated: Vec<ProviderId>,
    /// Rows left alone because the database is authoritative (`managed_by = api`).
    pub skipped_api_managed: Vec<ProviderId>,
    /// Rows left alone because they are tombstones (`deleted_at` set).
    pub skipped_deleted: Vec<ProviderId>,
    /// Rows reasserted from the file because `force` named them.
    pub forced: Vec<ProviderId>,
}

#[derive(Clone, Debug)]
pub struct IdentitySnapshot {
    pub email: Option<NormalizedEmail>,
    pub display_name: Option<String>,
    pub username: Option<String>,
    pub groups: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct SessionRow {
    pub session_id: SessionId,
    pub user_id: UserId,
    pub provider_id: ProviderId,
    pub auth_time: Timestamp,
    pub factors: Vec<FactorEntry>,
    pub aal: Aal,
    pub authz_version: u64,
    pub cred_gen: u64,
    pub snapshot: IdentitySnapshot,
    pub bound_ip: IpAddr,
    pub bound_ua_sha256: Option<Digest>,
    pub created_at: Timestamp,
    pub last_seen_at: Timestamp,
    pub absolute_expires_at: Timestamp,
    pub terminated_at: Option<Timestamp>,
    pub terminated_reason: Option<String>,
    /// The user `authz_version` when the session was authenticated. Never
    /// changes; `authz_version` is the mutable snapshot version.
    pub authz_version_at_auth: u64,
    /// Where `auth_time` came from (ADR-0016 decision 15).
    pub auth_time_source: AuthTimeSource,
    /// Sanitized user-agent prefix recorded at creation (console listings only).
    pub bound_ua_prefix: Option<String>,
}

#[derive(Clone, Debug)]
pub struct HandleRow {
    pub handle_sha256: Digest,
    pub session_id: SessionId,
    pub host: Host,
    pub issued_aal: Aal,
    pub created_at: Timestamp,
    pub last_seen_at: Timestamp,
    pub absolute_expires_at: Timestamp,
    pub revoked_at: Option<Timestamp>,
    pub revoked_reason: Option<String>,
}

/// Everything verify needs in one read: handle + session + user authz, or None when the handle digest is unknown for that host.
#[derive(Clone, Debug)]
pub struct HandleView {
    pub handle: HandleRow,
    pub session: SessionRow,
    pub user: UserAuthz,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxnPurpose {
    Login,
    Stepup,
    Link,
    Switch,
    /// The logout ticket of `/_hopae/logout` (ADR-0015).
    Logout,
}

impl TxnPurpose {
    pub fn as_str(self) -> &'static str {
        match self {
            TxnPurpose::Login => "login",
            TxnPurpose::Stepup => "stepup",
            TxnPurpose::Link => "link",
            TxnPurpose::Switch => "switch",
            TxnPurpose::Logout => "logout",
        }
    }

    pub fn parse(s: &str) -> Option<TxnPurpose> {
        match s {
            "login" => Some(TxnPurpose::Login),
            "stepup" => Some(TxnPurpose::Stepup),
            "link" => Some(TxnPurpose::Link),
            "switch" => Some(TxnPurpose::Switch),
            "logout" => Some(TxnPurpose::Logout),
            _ => None,
        }
    }
}

/// Result of the capped transaction insert.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admission {
    /// The transaction was written; `evicted` rows were removed in the same
    /// write to keep the table within `txn.max_rows`.
    Admitted { evicted: u32 },
    /// The per-address cap was reached; nothing was written.
    OverCap,
}

#[derive(Clone, Debug)]
pub struct TransactionRow {
    pub txn_sha256: Digest,
    pub created_at: Timestamp,
    pub expires_at: Timestamp,
    pub app_id: AppId,
    pub return_target: url::Url,
    pub bind_sha256: Option<Digest>,
    pub portal_bind_sha256: Option<Digest>,
    pub retry_bind_sha256: Option<Digest>,
    pub client_ip: IpAddr,
    pub ua_sha256: Option<Digest>,
    pub provider_id: Option<ProviderId>,
    pub state_sha256: Option<Digest>,
    pub nonce: Option<String>,
    pub pkce_verifier: Option<Secret>,
    pub portal_session_id: Option<SessionId>,
    pub purpose: TxnPurpose,
    pub conflicting_handle_sha256: Option<Digest>,
    pub pending_identity: Option<serde_json::Value>,
    pub recovery_depth: u32,
    pub consumed_at: Option<Timestamp>,
    pub consumed_reason: Option<String>,
    /// Seconds: the freshness bound a reauthentication transaction must meet (ADR-0016).
    pub reauth_max_age: Option<u32>,
}

/// Same fields as [`TransactionRow`] minus `consumed_*`; the transaction id
/// is given as its digest and the caller keeps the secret.
#[derive(Clone, Debug)]
pub struct NewTransaction {
    pub txn_sha256: Digest,
    pub created_at: Timestamp,
    pub expires_at: Timestamp,
    pub app_id: AppId,
    pub return_target: url::Url,
    pub bind_sha256: Option<Digest>,
    pub portal_bind_sha256: Option<Digest>,
    pub retry_bind_sha256: Option<Digest>,
    pub client_ip: IpAddr,
    pub ua_sha256: Option<Digest>,
    pub provider_id: Option<ProviderId>,
    pub state_sha256: Option<Digest>,
    pub nonce: Option<String>,
    pub pkce_verifier: Option<Secret>,
    pub portal_session_id: Option<SessionId>,
    pub purpose: TxnPurpose,
    pub conflicting_handle_sha256: Option<Digest>,
    pub pending_identity: Option<serde_json::Value>,
    pub recovery_depth: u32,
    pub reauth_max_age: Option<u32>,
}

#[derive(Clone, Debug)]
pub struct TransactionBinding {
    pub provider_id: ProviderId,
    pub state_sha256: Digest,
    pub nonce: Option<String>,
    pub pkce_verifier: Option<Secret>,
    pub portal_bind_sha256: Digest,
}

#[derive(Clone, Debug)]
pub struct HandoffCodeRow {
    pub code_sha256: Digest,
    pub session_id: SessionId,
    pub host: Host,
    pub return_target: url::Url,
    pub client_ip: IpAddr,
    pub bind_sha256: Digest,
    pub issued_aal: Aal,
    pub cred_gen: u64,
    pub recovery_depth: u32,
    pub created_at: Timestamp,
    pub expires_at: Timestamp,
    pub consumed_at: Option<Timestamp>,
    pub consumed_reason: Option<String>,
}

pub struct CreateSession {
    /// Expected provider kind/configuration, checked inside the write transaction.
    pub provider_configuration: Option<(crate::provider::types::ProviderKind, serde_json::Value)>,
    /// Ids pre-generated by the caller.
    pub session: SessionRow,
    pub portal_handle: HandleRow,
    pub portal_handle_digest: Digest,
    /// The login transaction to consume in the same store transaction as the
    /// session (at `session.created_at`); `Err(Conflict)` and nothing created
    /// when it was already consumed.
    pub consume_txn: Option<(Digest, Reason)>,
    pub events: Vec<Event>,
}

pub struct RedeemRequest {
    pub code_sha256: Digest,
    pub host: Host,
    /// The path of the stripped return target, in the form `Url::path()` gives.
    pub path: String,
    pub client_ip: IpAddr,
    pub presented_bind_sha256: Option<Digest>,
    pub presented_handle: Option<HandleView>,
    pub new_handle: HandleRow,
    pub now: Timestamp,
    /// `handoff.max_recoveries`: a rejected known code at this depth is
    /// recorded as `handoff_recovery_exhausted` (the engine decides the answer).
    pub max_recoveries: u32,
    /// The session-wide and the application's timers: the store evaluates
    /// them inside the redemption transaction (G7-C01) with the shared
    /// lifetime evaluator, so a code never revives an expired session.
    pub session_policy: crate::policy::types::SessionPolicy,
    pub app_lifetimes: crate::policy::types::Lifetimes,
    /// Recorded (with the verdict's reason) when the session turns out to
    /// have expired and is terminated by the redemption.
    pub expiry_events: Vec<Event>,
}

pub enum RedeemOutcome {
    Minted {
        session: SessionRow,
        issued_aal: Aal,
    },
    Rejected {
        reason: Reason,
        /// Some = burned.
        code: Option<HandoffCodeRow>,
    },
    AlreadyRedeemed,
    SessionConflict {
        code: HandoffCodeRow,
    },
    /// Never produced by the SQLite store: it does not know `handoff.max_recoveries`.
    /// The engine decides exhaustion from `Rejected { code: Some(..) }`.
    Exhausted {
        code: HandoffCodeRow,
    },
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SweepReport {
    pub transactions: u32,
    pub codes: u32,
    pub sessions: u32,
}

pub struct Delivery {
    pub sink: String,
    pub event: Event,
    pub attempts: u32,
}

#[derive(Clone, Debug)]
pub struct EventRetention {
    pub retention: Duration,
    pub max_rows: u64,
    pub prune_every: u64,
    pub max_pending_per_sink: u64,
    pub terminal_retention: Duration,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PruneReport {
    /// Event rows deleted (age or count); their delivery rows went with them.
    pub events_deleted: u64,
    /// Non-terminal deliveries marked `failed` (`pruned`) before their event was deleted.
    pub deliveries_marked_pruned: u64,
    /// Terminal delivery rows deleted by `delivery_terminal_retention_days`.
    pub terminal_deliveries_deleted: u64,
    /// Pending deliveries moved to `failed` (`backlog_overflow`), over all sinks.
    pub backlog_overflowed: u64,
}

#[derive(Clone, Debug, Default)]
pub struct EventQuery {
    pub kind: Option<EventKind>,
    pub session_id: Option<SessionId>,
    pub user_id: Option<UserId>,
    pub client_ip: Option<IpAddr>,
    pub since: Option<Timestamp>,
    /// Defaults to 100; capped at 10,000.
    pub limit: Option<usize>,
}

/// One row of `event_deliveries`, for the test hooks and operators.
#[derive(Clone, Debug)]
pub struct DeliveryRow {
    pub sink: String,
    pub event_id: EventId,
    pub state: String,
    pub attempts: u32,
    pub next_attempt_at: Timestamp,
    pub last_error: Option<String>,
    pub updated_at: Timestamp,
}

// ---- management console (ADR-0016) -----------------------------------------

/// Role of an administrator grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdminRole {
    Admin,
    Viewer,
}

impl AdminRole {
    pub fn as_str(self) -> &'static str {
        match self {
            AdminRole::Admin => "admin",
            AdminRole::Viewer => "viewer",
        }
    }

    pub fn parse(s: &str) -> Option<AdminRole> {
        match s {
            "admin" => Some(AdminRole::Admin),
            "viewer" => Some(AdminRole::Viewer),
            _ => None,
        }
    }
}

/// Who owns a grant row: the configuration file or runtime commands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrantManagedBy {
    File,
    Api,
}

impl GrantManagedBy {
    pub fn as_str(self) -> &'static str {
        match self {
            GrantManagedBy::File => "file",
            GrantManagedBy::Api => "api",
        }
    }

    pub fn parse(s: &str) -> Option<GrantManagedBy> {
        match s {
            "file" => Some(GrantManagedBy::File),
            "api" => Some(GrantManagedBy::Api),
            _ => None,
        }
    }
}

/// Where a session's `auth_time` came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthTimeSource {
    ProviderClaim,
    HopaeCompletion,
}

impl AuthTimeSource {
    pub fn as_str(self) -> &'static str {
        match self {
            AuthTimeSource::ProviderClaim => "provider_claim",
            AuthTimeSource::HopaeCompletion => "hopae_completion",
        }
    }

    pub fn parse(s: &str) -> Option<AuthTimeSource> {
        match s {
            "provider_claim" => Some(AuthTimeSource::ProviderClaim),
            "hopae_completion" => Some(AuthTimeSource::HopaeCompletion),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdminGrant {
    pub user_id: UserId,
    pub role: AdminRole,
    pub managed_by: GrantManagedBy,
    /// The address the grant was resolved from, if any; never re-resolved.
    pub source_email: Option<NormalizedEmail>,
    pub granted_at: Timestamp,
    /// A user id, `cli` or `file`.
    pub granted_by: String,
    pub revoked_at: Option<Timestamp>,
    pub revoked_by: Option<String>,
    pub note: Option<String>,
}

/// Who performs a console mutation; re-evaluated inside the write (ADR-0016 decision 11).
#[derive(Clone, Debug)]
pub struct Actor {
    pub user_id: UserId,
    pub session_id: SessionId,
    pub handle_sha256: Digest,
}

/// Everything the fence needs besides the actor, taken from the snapshot and
/// the clock when the job starts (P2-02). The fence itself reads the store
/// clock at the moment it runs, so a gate that holds the job is accounted for;
/// `now` records the reading the caller used.
#[derive(Clone, Debug)]
pub struct ActorPolicy {
    pub authority: Option<crate::admin::delegation::Proof>,
    pub console_host: Host,
    /// Session-wide idle and absolute.
    pub session: crate::policy::types::SessionPolicy,
    /// The implicit application's handle idle and absolute.
    pub handle: crate::policy::types::Lifetimes,
    pub max_auth_age: Duration,
    pub capability_requires_claim: bool,
    pub require_aal: Aal,
    pub now: Timestamp,
    /// Clock-skew tolerance, 60 s.
    pub skew: Duration,
}

/// Opaque position of a listing (MAC'd by the admin layer).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cursor {
    /// `at` (milliseconds) for events, `created_at` (milliseconds) for users and sessions.
    pub key: i64,
    pub id: String,
}

#[derive(Clone, Debug)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub next: Option<Cursor>,
    /// Candidate rows the window held (feeds `hopae_admin_rows_examined_total`).
    pub examined: u32,
}

/// Candidate rows one listing window examines.
pub const CANDIDATE_WINDOW: u32 = 10_000;

/// Absolute deadline captured in the async context BEFORE dispatch and handed to the job (P2-05).
#[derive(Clone, Copy, Debug)]
pub struct Deadline(pub std::time::Instant);

impl Deadline {
    /// A deadline `budget` from now.
    pub fn after(budget: Duration) -> Deadline {
        Deadline(std::time::Instant::now() + budget)
    }
}

#[derive(Clone, Debug)]
pub struct UsersQuery {
    pub q: Option<String>,
    pub status: Option<UserStatus>,
    pub limit: usize,
    pub cursor: Option<Cursor>,
}

#[derive(Clone, Debug)]
pub struct UserSummary {
    pub user: User,
    pub live_sessions: u32,
    pub role: Option<AdminRole>,
}

#[derive(Clone, Debug)]
pub struct UserDetail {
    pub user: User,
    /// At most 50.
    pub identities: Vec<IdentityRow>,
    /// At most 20, newest created first.
    pub sessions_live: Vec<SessionSummary>,
    pub sessions_live_total: u32,
    /// At most 20, most recently terminated first.
    pub sessions_terminated: Vec<SessionSummary>,
    pub grant: Option<AdminGrant>,
}

#[derive(Clone, Debug)]
pub struct SessionsQuery {
    pub user_id: Option<UserId>,
    pub limit: usize,
    pub cursor: Option<Cursor>,
    pub now: Timestamp,
}

#[derive(Clone, Debug)]
pub struct SessionSummary {
    pub session: SessionRow,
    pub primary_email: Option<NormalizedEmail>,
    /// Hosts of the session's unrevoked handles, at most 100.
    pub hosts: Vec<Host>,
    pub ua_prefix: Option<String>,
}

/// The index an events listing is pinned to, chosen by fixed priority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventsIndex {
    Session,
    User,
    Ip,
    Kind,
    Time,
}

impl EventsIndex {
    /// The index name used in `INDEXED BY`.
    pub fn index_name(self) -> &'static str {
        match self {
            EventsIndex::Session => "events_session_at_id",
            EventsIndex::User => "events_user_at_id",
            EventsIndex::Ip => "events_ip_at_id",
            EventsIndex::Kind => "events_kind_at_id",
            EventsIndex::Time => "events_at_id",
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct EventsQuery {
    pub kind: Option<EventKind>,
    pub outcome: Option<crate::event::types::Outcome>,
    pub user_id: Option<UserId>,
    pub session_id: Option<SessionId>,
    pub client_ip: Option<IpAddr>,
    pub since: Option<Timestamp>,
    pub until: Option<Timestamp>,
    pub limit: usize,
    pub cursor: Option<Cursor>,
}

impl EventsQuery {
    /// Session, then user, then address, then kind, else time.
    pub fn index(&self) -> EventsIndex {
        if self.session_id.is_some() {
            EventsIndex::Session
        } else if self.user_id.is_some() {
            EventsIndex::User
        } else if self.client_ip.is_some() {
            EventsIndex::Ip
        } else if self.kind.is_some() {
            EventsIndex::Kind
        } else {
            EventsIndex::Time
        }
    }
}

#[derive(Clone, Debug)]
pub struct StoreStatus {
    pub schema_version: u32,
    pub users: u64,
    pub live_sessions: u64,
    pub events: u64,
    /// Per sink: `(sink, pending, failed)`.
    pub deliveries: Vec<(String, u64, u64)>,
    pub last_prune_at: Option<Timestamp>,
}

/// One configuration entry, with its ORIGINAL key preserved (P2-06); resolution happens inside the import transaction.
#[derive(Clone, Debug)]
pub enum SeedKey {
    ById(UserId),
    ByEmail(NormalizedEmail),
    Both {
        user_id: UserId,
        email: NormalizedEmail,
    },
}

#[derive(Clone, Debug)]
pub struct SeedEntry {
    pub index: usize,
    pub key: SeedKey,
    pub role: AdminRole,
    pub note: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GrantImportReport {
    pub inserted: Vec<UserId>,
    pub updated: Vec<UserId>,
    pub revoked: Vec<UserId>,
    pub unchanged: Vec<UserId>,
    /// `(entry index, reason)`; see the `SKIP_*` constants in the admin store module.
    pub skipped: Vec<(usize, &'static str)>,
    pub forced: Vec<UserId>,
    /// `(entry index, bound user, user the address resolves to now)`.
    pub rebound_warnings: Vec<(usize, UserId, UserId)>,
}

#[derive(Clone, Debug)]
pub enum ForceTarget {
    ById(UserId),
    ByEmail(NormalizedEmail),
}

/// The target of `grant_admin` resolution: a user id or a normalized address.
#[derive(Clone, Debug)]
pub enum GrantTarget {
    Id(UserId),
    Email(NormalizedEmail),
}

/// Reasons an `import_grants` entry was skipped (`GrantImportReport::skipped`).
pub mod skip {
    /// A matched `api`-managed live row: changed at run time, the file does not override it.
    pub const CHANGED_AT_RUN_TIME: &str = "changed_at_run_time";
    /// A matched revoked row (tombstone): the file never resurrects it without `--force`.
    pub const REVOKED_AT_RUN_TIME: &str = "revoked_at_run_time";
    /// Two or more rows are bound through the entry's address.
    pub const EMAIL_BINDING_AMBIGUOUS: &str = "email_binding_ambiguous";
    /// The entry names a user id and an address that do not belong together.
    pub const USER_EMAIL_MISMATCH: &str = "user_email_mismatch";
    /// The address is held by a user, verified, but not authoritative.
    pub const EMAIL_NOT_AUTHORITATIVE: &str = "email_not_authoritative";
    /// The address is held by a user who has not verified it.
    pub const EMAIL_UNVERIFIED: &str = "email_unverified";
    /// No user has that id or primary address.
    pub const NO_SUCH_USER: &str = "no_such_user";
    /// The resolved user is disabled.
    pub const USER_DISABLED: &str = "user_disabled";
}

/// Internal-only encrypted factor material; never serialize into a console response.
#[derive(Debug)]
pub struct TotpEnrollment {
    pub enrollment_id: String,
    pub user_id: crate::identity::types::UserId,
    pub revision: u64,
    pub active: bool,
    pub last_counter: Option<u64>,
    pub envelope: crate::factor::seed_cipher::Envelope,
}

/// Short-lived, non-serializable authorization issued only by the native session service.
pub struct FactorActor {
    pub(crate) view: HandleView,
    pub(crate) authorized_at: Timestamp,
    pub(crate) session_idle: std::time::Duration,
    pub(crate) handle_idle: std::time::Duration,
}
impl FactorActor {
    pub fn user(&self) -> &UserId {
        &self.view.session.user_id
    }
}

impl std::fmt::Debug for FactorActor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FactorActor(<redacted>)")
    }
}
