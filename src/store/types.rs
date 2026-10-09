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
            config: serde_json::json!({
                "client_id": c.client_id,
                "issuer": c.issuer,
                "scope": c.scope,
            }),
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
}

impl TxnPurpose {
    pub fn as_str(self) -> &'static str {
        match self {
            TxnPurpose::Login => "login",
            TxnPurpose::Stepup => "stepup",
            TxnPurpose::Link => "link",
            TxnPurpose::Switch => "switch",
        }
    }

    pub fn parse(s: &str) -> Option<TxnPurpose> {
        match s {
            "login" => Some(TxnPurpose::Login),
            "stepup" => Some(TxnPurpose::Stepup),
            "link" => Some(TxnPurpose::Link),
            "switch" => Some(TxnPurpose::Switch),
            _ => None,
        }
    }
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
}

#[derive(Clone, Debug)]
pub struct TransactionBinding {
    pub provider_id: ProviderId,
    pub state_sha256: Digest,
    pub nonce: String,
    pub pkce_verifier: Secret,
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
    /// Ids pre-generated by the caller.
    pub session: SessionRow,
    pub portal_handle: HandleRow,
    pub portal_handle_digest: Digest,
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
