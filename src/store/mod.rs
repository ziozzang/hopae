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
use crate::event::types::{Event, EventId, EventKind, Reason};
use crate::identity::types::{NormalizedEmail, UserId};
use crate::policy::types::Host;
use crate::provider::types::ProviderId;
use crate::session::types::SessionId;

pub use hooks::StoreHooks;
pub use sqlite::{
    LATEST_SCHEMA_VERSION, Shape as WindowShape, Store, earliest_present, precheck,
    validate_foundation,
};
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
    /// The provider the write names is disabled or tombstoned in the database
    /// (checked inside the write transaction, G7-IDP-01).
    #[error("provider disabled")]
    ProviderDisabled,
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
    /// Schema version 2 was edited in place before the first release; a
    /// database from such a build lacks the later additions.
    #[error("development database from a pre-release schema; delete it")]
    DevelopmentSchema,
    #[error("database schema version {found} is newer than this binary supports ({supported})")]
    SchemaTooNew { found: u32, supported: u32 },
    /// A command-line tool never migrates: the instance does.
    #[error(
        "database schema version {found} is older than this binary ({latest}): start the instance once to migrate"
    )]
    SchemaTooOld { found: u32, latest: u32 },
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
    /// As [`Directory::user`], under an explicit deadline (the console's reads).
    async fn user_within(&self, id: &UserId, deadline: Deadline) -> StoreResult<Option<User>>;
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

    // ---- management console (ADR-0016) ------------------------------------
    /// The grant row of `user` in any state (revoked included).
    async fn admin_grant(
        &self,
        user: &UserId,
        deadline: Deadline,
    ) -> StoreResult<Option<AdminGrant>>;
    /// Live grants, or every row (tombstones too) with `include_revoked`.
    async fn admin_grants(
        &self,
        include_revoked: bool,
        deadline: Deadline,
    ) -> StoreResult<Vec<AdminGrant>>;
    /// Resolve a user id or a normalized address to the user and **every**
    /// linked identity (the operator's evidence; the console's previews are
    /// bounded separately, only the deadline bounds this).
    async fn resolve_grant_target(
        &self,
        target: &GrantTarget,
        deadline: Deadline,
    ) -> StoreResult<Option<(User, Vec<IdentityRow>)>>;
    /// Grant or re-grant. Returns `(previous role, changed)`: the role the row
    /// held before (even a revoked one), and whether anything was written. An
    /// identical live grant is a no-op: no row change and no event. The store
    /// adds `previous_role` to the event's attributes; a disabled or unknown
    /// user is refused (`Conflict`).
    #[allow(clippy::too_many_arguments)]
    async fn grant_admin(
        &self,
        user: &UserId,
        role: AdminRole,
        managed_by: GrantManagedBy,
        source_email: Option<NormalizedEmail>,
        by: &str,
        note: Option<String>,
        at: Timestamp,
        event: Event,
    ) -> StoreResult<(Option<AdminRole>, bool)>;
    /// Revoke a live grant (tombstone). `false` = no live grant, nothing written.
    async fn revoke_admin(
        &self,
        user: &UserId,
        by: &str,
        managed_by: GrantManagedBy,
        at: Timestamp,
        event: Event,
    ) -> StoreResult<bool>;
    /// The file rule, ONE write transaction, in this order (P2-06, P3-01): (1) match every entry — skipped ones included — by its key
    /// (ById/Both → PK; ByEmail → EVERY row with source_email = email, in any state: file or api, live or revoked, whatever user it is
    /// bound to; two or more such rows → `email_binding_ambiguous`, skipped, present); (2) matched live file rows: update role/note,
    /// unless the entry is invalid (Both naming different users, etc.) → skipped, row untouched, still PRESENT; a matched api row or
    /// tombstone → `skipped (changed|revoked at run time)`, PRESENT, never re-resolved; (3) unmatched entries: resolve once (ById: must
    /// exist; ByEmail: exactly one verified holder AND authoritative; Both: agree) and insert as file, else skipped; (4) live file rows
    /// matched by NO entry → revoked_by = 'file'; api rows and tombstones untouched unless `force` names them (ForceTarget::ByEmail
    /// selects the source_email binding BEFORE any resolution and is refused when ambiguous: "use --force <user_id>").
    /// Deadline checked after BEGIN IMMEDIATE, between the four phases and before COMMIT.
    async fn import_grants(
        &self,
        entries: Vec<SeedEntry>,
        force: Option<ForceTarget>,
        deadline: Deadline,
        at: Timestamp,
        mk_event: &(
             dyn for<'a> Fn(&'a UserId, EventKind, Option<AdminRole>, AdminRole, bool) -> Event
                 + Sync
         ),
    ) -> StoreResult<GrantImportReport>;
    async fn list_users(&self, q: UsersQuery, deadline: Deadline)
    -> StoreResult<Page<UserSummary>>;
    async fn user_detail(
        &self,
        user: &UserId,
        now: Timestamp,
        deadline: Deadline,
    ) -> StoreResult<Option<UserDetail>>;
    /// ONE write transaction: fence → status/authz_version → terminate every live session (reason user_disabled, their events) → admin event.
    /// Deadline checked before each session's statements; expiry → rollback, Err(Unavailable("deadline")).
    /// Returns `(changed, sessions terminated)`; setting the status a user already has writes nothing.
    #[allow(clippy::too_many_arguments)]
    async fn set_user_status(
        &self,
        actor: &Actor,
        policy: &ActorPolicy,
        user: &UserId,
        status: UserStatus,
        deadline: Deadline,
        admin_event: Event,
        mk_session_event: &(dyn for<'a> Fn(&'a SessionRow) -> Event + Sync),
    ) -> StoreResult<(bool, u32)>;
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
    /// As [`Sessions::lookup_handle`], under an explicit deadline (the console's reads).
    async fn lookup_handle_within(
        &self,
        handle_sha256: &Digest,
        host: &Host,
        deadline: Deadline,
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
    /// Consume a `logout` ticket and, when `session` is given, end that
    /// session (idempotently, with `events` only if it was live) in ONE write
    /// transaction: a ticket is never consumed while its session stays live.
    /// `false` = the ticket was not a live logout ticket (nothing changed).
    async fn consume_logout_ticket(
        &self,
        txn_sha256: &Digest,
        session: Option<&SessionId>,
        reason: Reason,
        at: Timestamp,
        events: Vec<Event>,
    ) -> StoreResult<bool>;
    // ---- management console (ADR-0016) ------------------------------------
    async fn list_live_sessions(
        &self,
        q: SessionsQuery,
        deadline: Deadline,
    ) -> StoreResult<Page<SessionSummary>>;
    /// The session with its (at most 100) handles, any state.
    async fn session_summary(
        &self,
        id: &SessionId,
        deadline: Deadline,
    ) -> StoreResult<Option<(SessionSummary, Vec<HandleRow>)>>;
    /// Fenced termination (reason `admin`). `false` = unknown or already ended, nothing written.
    async fn admin_terminate_session(
        &self,
        actor: &Actor,
        policy: &ActorPolicy,
        id: &SessionId,
        deadline: Deadline,
        admin_event: Event,
        session_event: Event,
    ) -> StoreResult<bool>;
    /// Fenced termination of every live session of `user`; zero sessions writes nothing.
    async fn admin_terminate_user_sessions(
        &self,
        actor: &Actor,
        policy: &ActorPolicy,
        user: &UserId,
        deadline: Deadline,
        admin_event: Event,
        mk_session_event: &(dyn for<'a> Fn(&'a SessionRow) -> Event + Sync),
    ) -> StoreResult<u32>;
    /// Reauthentication (decision 15): auth_time := claim or completion time, auth_time_source set, factors += entry, cred_gen += 1,
    /// every handle revoked (reason reauth), outstanding codes consumed (reason reauth), new portal handle, the login transaction consumed;
    /// deadline checked between statements. One event per handle actually revoked in the transaction is built by
    /// `mk_revoked_event` from the revoked row, never from a preview read beforehand. Refuses `Conflict("provider_mismatch")` when `provider` is not the session's provider.
    #[allow(clippy::too_many_arguments)]
    async fn reauthenticate_session(
        &self,
        id: &SessionId,
        provider: &ProviderId,
        auth_time: Timestamp,
        source: AuthTimeSource,
        factor: crate::session::types::FactorEntry,
        new_portal_handle: HandleRow,
        consume_txn: (Digest, Reason),
        deadline: Deadline,
        events: Vec<Event>,
        mk_revoked_event: &(dyn for<'a> Fn(&'a HandleRow) -> Event + Sync),
    ) -> StoreResult<()>;
    async fn refresh_snapshot(
        &self,
        id: &SessionId,
        snapshot: IdentitySnapshot,
        authz_version: u64,
    ) -> StoreResult<()>;
    async fn create_transaction(&self, txn: NewTransaction, events: Vec<Event>) -> StoreResult<()>;
    /// As `create_transaction`, but only when fewer than `cap` transactions of
    /// the same `client_ip` were created since `since`; the count, the
    /// eviction down to `max_rows - 1` rows (dead rows first, then the
    /// oldest) and the insert are one write transaction, so `max_rows` is a
    /// hard bound on this path. `cap = None` skips the per-address count (post-
    /// authentication transactions: switch and link) but never the eviction.
    /// Every production transaction insert goes through here. `OverCap` =
    /// nothing written.
    async fn create_transaction_capped(
        &self,
        txn: NewTransaction,
        events: Vec<Event>,
        since: Timestamp,
        cap: Option<u32>,
        max_rows: u32,
    ) -> StoreResult<Admission>;
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
    /// Record the portal binding of a `switch` transaction, once: true when
    /// this call set it, false when one was already recorded (or the
    /// transaction is consumed or not a switch).
    async fn bind_switch_transaction(
        &self,
        txn_sha256: &Digest,
        portal_bind_sha256: Digest,
    ) -> StoreResult<bool>;
    /// Record the portal binding of a `logout` ticket, once (as
    /// `bind_switch_transaction` does for a `switch` transaction).
    async fn bind_logout_transaction(
        &self,
        txn_sha256: &Digest,
        portal_bind_sha256: Digest,
    ) -> StoreResult<bool>;
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
    /// As `consume_transaction`, in a write transaction that also refuses
    /// (`StoreError::ProviderDisabled`) when `provider` is disabled or
    /// tombstoned in the database.
    async fn consume_transaction_for_provider(
        &self,
        txn_sha256: &Digest,
        provider: &ProviderId,
        configuration: Option<(crate::provider::types::ProviderKind, serde_json::Value)>,
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
    /// As [`Events::append_required`] under an explicit deadline: checked after
    /// the write lock is won and again immediately before `COMMIT`, so a write
    /// that reaches its deadline rolls back instead of committing late.
    async fn append_required_within(
        &self,
        events: Vec<Event>,
        deadline: Deadline,
    ) -> StoreResult<()>;
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
    /// One console listing page, newest first (ADR-0016).
    async fn query_page(&self, q: EventsQuery, deadline: Deadline) -> StoreResult<Page<Event>>;
    async fn status(&self, deadline: Deadline) -> StoreResult<StoreStatus>;
}
