//! Storage: the `Directory`, `Sessions` and `Events` traits (ADR-0002) and the
//! SQLite implementation. Handlers never run ad hoc SQL; every query is a
//! named method here. PostgreSQL is M2.
//!
//! Required events travel with their state change: every mutating method that
//! takes `events: Vec<Event>` writes the rows and one `event_deliveries`
//! `pending` row per configured sink in the same transaction.

pub mod hooks;
pub mod sqlite;
pub mod types;

use std::net::IpAddr;

use async_trait::async_trait;

use crate::crypto::{Digest, Timestamp};
use crate::event::types::{Event, EventId, Reason};
use crate::identity::types::{NormalizedEmail, UserId};
use crate::policy::types::Host;
use crate::provider::types::ProviderId;
use crate::session::types::SessionId;

pub use hooks::StoreHooks;
pub use sqlite::{LATEST_SCHEMA_VERSION, Store};
pub use types::*;

pub type StoreResult<T> = Result<T, StoreError>;

#[derive(thiserror::Error, Debug)]
pub enum StoreError {
    /// The store cannot answer now (closed, stalled past the deadline, writer gone): fail closed.
    #[error("store unavailable: {0}")]
    Unavailable(String),
    /// A bounded queue is full or the database stayed locked; retry later.
    #[error("store busy")]
    Busy,
    /// The request conflicts with current state (duplicate, already bound, unknown parent).
    #[error("store conflict: {0}")]
    Conflict(&'static str),
    /// A stored value could not be decoded; the message names a column, never a value.
    #[error("stored data is corrupt: {0}")]
    Corrupt(String),
    #[error("store I/O error at {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
    #[error("store error: {0}")]
    Sqlite(rusqlite::Error),
    #[error("database schema version {found} is newer than this binary supports ({supported})")]
    SchemaTooNew { found: u32, supported: u32 },
}

impl From<rusqlite::Error> for StoreError {
    fn from(e: rusqlite::Error) -> Self {
        use rusqlite::ErrorCode;
        match &e {
            rusqlite::Error::SqliteFailure(f, _)
                if matches!(f.code, ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked) =>
            {
                StoreError::Busy
            }
            rusqlite::Error::SqliteFailure(f, _) if f.code == ErrorCode::ConstraintViolation => {
                StoreError::Conflict("constraint violated")
            }
            _ => StoreError::Sqlite(e),
        }
    }
}

#[async_trait]
pub trait Directory: Send + Sync {
    async fn user(&self, id: &UserId) -> StoreResult<Option<User>>;
    /// One indexed read; used by every verify.
    async fn user_authz(&self, id: &UserId) -> StoreResult<Option<UserAuthz>>;
    async fn identity(
        &self,
        provider: &ProviderId,
        subject: &str,
    ) -> StoreResult<Option<IdentityRow>>;
    async fn user_by_email(&self, email: &NormalizedEmail) -> StoreResult<Option<User>>;
    async fn create_user(
        &self,
        user: NewUser,
        identity: NewIdentity,
        events: Vec<Event>,
    ) -> StoreResult<User>;
    async fn link_identity(
        &self,
        user: &UserId,
        identity: NewIdentity,
        events: Vec<Event>,
    ) -> StoreResult<()>;
    /// Updates email/name/picture/last_seen only.
    async fn touch_identity(
        &self,
        provider: &ProviderId,
        subject: &str,
        seen: &NewIdentity,
        at: Timestamp,
    ) -> StoreResult<()>;
    async fn providers(&self) -> StoreResult<Vec<ProviderRow>>;
    /// ADR-0010 import rule: insert absent rows; overwrite rows with managed_by=File and deleted_at NULL; never touch Api-managed or deleted rows unless `force` names them.
    async fn import_providers(
        &self,
        from_file: Vec<ProviderRow>,
        force: Option<&ProviderId>,
        events: Vec<Event>,
    ) -> StoreResult<ImportReport>;
    async fn bump_config_generation(&self) -> StoreResult<u64>;
    async fn config_generation(&self) -> StoreResult<u64>;
}

#[async_trait]
pub trait Sessions: Send + Sync {
    async fn create_session(&self, req: CreateSession) -> StoreResult<()>;
    async fn session(&self, id: &SessionId) -> StoreResult<Option<SessionRow>>;
    async fn lookup_handle(
        &self,
        handle_sha256: &Digest,
        host: &Host,
    ) -> StoreResult<Option<HandleView>>;
    /// Caller coalesces to 30 s.
    async fn touch_handle(&self, handle_sha256: &Digest, at: Timestamp) -> StoreResult<()>;
    /// SSO / elevation re-handoff (same session only).
    async fn mint_handle(
        &self,
        handle: HandleRow,
        replaces: Option<Digest>,
        events: Vec<Event>,
    ) -> StoreResult<()>;
    async fn revoke_handle(
        &self,
        handle_sha256: &Digest,
        reason: Reason,
        at: Timestamp,
        events: Vec<Event>,
    ) -> StoreResult<()>;
    /// One transaction: cred_gen += 1, every handle revoked (reason session_terminated), every outstanding code consumed (reason), session terminated.
    async fn terminate_session(
        &self,
        id: &SessionId,
        reason: Reason,
        at: Timestamp,
        events: Vec<Event>,
    ) -> StoreResult<()>;
    async fn refresh_snapshot(
        &self,
        id: &SessionId,
        snapshot: IdentitySnapshot,
        authz_version: u64,
    ) -> StoreResult<()>;
    async fn create_transaction(&self, txn: NewTransaction, events: Vec<Event>) -> StoreResult<()>;
    async fn transaction(&self, txn_sha256: &Digest) -> StoreResult<Option<TransactionRow>>;
    async fn transaction_by_state(
        &self,
        state_sha256: &Digest,
    ) -> StoreResult<Option<TransactionRow>>;
    /// Err(Conflict) if already bound or consumed.
    async fn bind_transaction(
        &self,
        txn_sha256: &Digest,
        binding: TransactionBinding,
    ) -> StoreResult<()>;
    /// `POST /login/retry` is single-use per consumed transaction: true for
    /// the first call, false afterwards (`UPDATE … WHERE retry_used_at IS NULL`).
    async fn use_retry(&self, txn_sha256: &Digest, at: Timestamp) -> StoreResult<bool>;
    async fn record_retry_bind(
        &self,
        txn_sha256: &Digest,
        retry_bind_sha256: Digest,
    ) -> StoreResult<()>;
    /// false = already consumed.
    async fn consume_transaction(
        &self,
        txn_sha256: &Digest,
        reason: Reason,
        at: Timestamp,
        events: Vec<Event>,
    ) -> StoreResult<bool>;
    async fn mint_handoff_code(&self, code: HandoffCodeRow, events: Vec<Event>) -> StoreResult<()>;
    /// ADR-0004 redemption rule as ONE atomic statement sequence.
    async fn redeem_handoff_code(
        &self,
        req: RedeemRequest,
        events_on_success: Vec<Event>,
        events_on_failure: Vec<Event>,
    ) -> StoreResult<RedeemOutcome>;
    async fn count_transactions_since(&self, ip: IpAddr, since: Timestamp) -> StoreResult<u32>;
    /// Counts `handoff.rejected` events recorded for `ip`: callers must attach
    /// one (with `client_ip`) to every failed redemption, unknown codes included.
    async fn count_handoff_failures_since(&self, ip: IpAddr, since: Timestamp) -> StoreResult<u32>;
    async fn evict_transactions(&self, max_rows: u32, now: Timestamp) -> StoreResult<u32>;
    /// Expired txns/codes, terminated sessions older than retention.
    async fn sweep(
        &self,
        now: Timestamp,
        retention: std::time::Duration,
    ) -> StoreResult<SweepReport>;
}

#[async_trait]
pub trait Events: Send + Sync {
    /// Required events with no state change to travel with (a `login.failed`
    /// on a callback that mutates nothing, a `handoff.rejected` for an unknown
    /// code or a rate limit): one transaction, delivery rows included, never
    /// dropped or batched. `session.*`, `handle.*`, `identity.*` and
    /// `session.handoff` must travel with their mutation and are refused.
    async fn append_required(&self, events: Vec<Event>) -> StoreResult<()>;
    /// Diagnostic kinds only; bounded queue; returns Err(Busy) when the queue is full (the caller counts a drop).
    async fn append_diagnostic(&self, event: Event) -> StoreResult<()>;
    async fn claim_deliveries(
        &self,
        sink: &str,
        limit: usize,
        now: Timestamp,
    ) -> StoreResult<Vec<Delivery>>;
    async fn mark_delivered(
        &self,
        sink: &str,
        event_id: &EventId,
        at: Timestamp,
    ) -> StoreResult<()>;
    async fn mark_failed(
        &self,
        sink: &str,
        event_id: &EventId,
        error: &str,
        next_attempt_at: Option<Timestamp>,
    ) -> StoreResult<()>;
    async fn prune(&self, now: Timestamp, policy: &EventRetention) -> StoreResult<PruneReport>;
    /// (events, deliveries)
    async fn count_rows(&self) -> StoreResult<(u64, u64)>;
    /// Tests and M2 history.
    async fn query(&self, filter: EventQuery) -> StoreResult<Vec<Event>>;
}
