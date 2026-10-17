//! Slice 1 of the backend-neutral store contract (ADR-0020): users and
//! identities with the user-ID ledger, provider bootstrap, sessions and
//! handles, and the transactional outbox. Implemented by the SQLite store
//! (delegating to the existing traits) and by the PostgreSQL store; the
//! conformance suite (`store::conformance`) runs against both.
use async_trait::async_trait;

use super::Deadline;
use super::StoreResult;
use super::sqlite::groups;
use super::sqlite::subject_directory as directory;
use super::types::*;
use crate::crypto::{Digest, Timestamp};
use crate::event::types::{Event, Reason};
use crate::identity::types::{NormalizedEmail, UserId};
use crate::policy::types::Host;
use crate::provider::types::ProviderId;
use crate::session::types::SessionId;

#[async_trait]
pub trait CoreStore: Send + Sync {
    /// `sqlite` or `postgres`.
    fn backend(&self) -> &'static str;

    /// The ADR-0010 import rule for one row: insert when absent, overwrite a
    /// live file-managed row, leave API-managed rows and tombstones alone.
    async fn ensure_provider(&self, row: ProviderRow) -> StoreResult<()>;

    async fn user(&self, id: &UserId) -> StoreResult<Option<User>>;
    async fn user_authz(&self, id: &UserId) -> StoreResult<Option<UserAuthz>>;
    async fn user_by_email(&self, email: &NormalizedEmail) -> StoreResult<Option<User>>;
    async fn identity(
        &self,
        provider: &ProviderId,
        subject: &str,
    ) -> StoreResult<Option<IdentityRow>>;
    /// New user + first identity + events in one transaction; the user ID is
    /// reserved in the ledger forever.
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
    async fn touch_identity(
        &self,
        provider: &ProviderId,
        subject: &str,
        seen: &NewIdentity,
        at: Timestamp,
    ) -> StoreResult<()>;

    async fn create_session(&self, req: CreateSession) -> StoreResult<()>;
    async fn session(&self, id: &SessionId) -> StoreResult<Option<SessionRow>>;
    async fn lookup_handle(
        &self,
        handle_sha256: &Digest,
        host: &Host,
    ) -> StoreResult<Option<HandleView>>;
    async fn touch_handle(&self, handle_sha256: &Digest, at: Timestamp) -> StoreResult<()>;
    async fn revoke_handle(
        &self,
        handle_sha256: &Digest,
        reason: Reason,
        at: Timestamp,
        events: Vec<Event>,
    ) -> StoreResult<()>;
    async fn terminate_session(
        &self,
        id: &SessionId,
        reason: Reason,
        at: Timestamp,
        events: Vec<Event>,
    ) -> StoreResult<()>;

    /// Required events without a state change, one transaction.
    async fn append_required(&self, events: Vec<Event>) -> StoreResult<()>;
    /// The newest `limit` events, oldest first (`at`, `event_id`).
    async fn recent_events(&self, limit: usize) -> StoreResult<Vec<Event>>;
    /// Pending delivery rows of one event (outbox fan-out check).
    async fn pending_deliveries(&self, event: &str) -> StoreResult<Vec<String>>;

    /// The configuration generation (0 before the first bump); step-up
    /// bindings and factor provenance record it (slice 2c).
    async fn config_generation(&self) -> StoreResult<u64>;
    async fn bump_config_generation(&self) -> StoreResult<u64>;
}

/// Slice 2a of the store contract (ADR-0020): login transactions and the
/// handoff-code redemption of ADR-0004, the remainder of the login hot path.
#[async_trait]
pub trait HandoffStore: Send + Sync {
    /// Count, evict down to `max_rows - 1` and insert in one write.
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
    async fn bind_transaction(
        &self,
        txn_sha256: &Digest,
        binding: TransactionBinding,
    ) -> StoreResult<()>;
    async fn use_retry(&self, txn_sha256: &Digest, at: Timestamp) -> StoreResult<bool>;
    async fn consume_transaction(
        &self,
        txn_sha256: &Digest,
        reason: Reason,
        at: Timestamp,
        events: Vec<Event>,
    ) -> StoreResult<bool>;
    async fn mint_handoff_code(&self, code: HandoffCodeRow, events: Vec<Event>) -> StoreResult<()>;
    async fn redeem_handoff_code(
        &self,
        req: RedeemRequest,
        events_on_success: Vec<Event>,
        events_on_failure: Vec<Event>,
    ) -> StoreResult<RedeemOutcome>;
    async fn count_transactions_since(
        &self,
        ip: std::net::IpAddr,
        since: Timestamp,
    ) -> StoreResult<u32>;
    async fn count_handoff_failures_since(
        &self,
        ip: std::net::IpAddr,
        since: Timestamp,
    ) -> StoreResult<u32>;
}

/// Slice 2b (ADR-0020): administrator grants and the fenced console
/// mutations. The fence re-evaluates the acting administrator inside the
/// write (ADR-0016 decision 11).
#[async_trait]
pub trait AdminStore: Send + Sync {
    async fn admin_grant(
        &self,
        user: &UserId,
        deadline: Deadline,
    ) -> StoreResult<Option<AdminGrant>>;
    async fn admin_grants(
        &self,
        include_revoked: bool,
        deadline: Deadline,
    ) -> StoreResult<Vec<AdminGrant>>;
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
    async fn revoke_admin(
        &self,
        user: &UserId,
        by: &str,
        managed_by: GrantManagedBy,
        at: Timestamp,
        event: Event,
    ) -> StoreResult<bool>;
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
    async fn admin_terminate_session(
        &self,
        actor: &Actor,
        policy: &ActorPolicy,
        id: &SessionId,
        deadline: Deadline,
        admin_event: Event,
        session_event: Event,
    ) -> StoreResult<bool>;
}

/// Slice 2b (ADR-0020): replay ledgers shared by every replica (Hangang
/// delegation nonces, receipt replay). `admit` is true exactly once per
/// `(scope, nonce)` while the entry is live; expired entries are pruned.
#[async_trait]
pub trait NonceStore: Send + Sync {
    async fn admit_nonce(
        &self,
        scope: &str,
        nonce: &str,
        expires_at: Timestamp,
        now: Timestamp,
        capacity: u32,
    ) -> StoreResult<bool>;
}

/// Bounds of a replay-ledger key.
pub fn nonce_key_ok(scope: &str, nonce: &str) -> bool {
    let ok = |s: &str, n: usize| {
        !s.is_empty()
            && s.len() <= n
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
    };
    ok(scope, 64) && ok(nonce, 256)
}

/// Slice 3 (ADR-0020, ADR-0016): bounded console listings. Every listing
/// examines at most [`CANDIDATE_WINDOW`] rows of one index window and
/// answers within its deadline (`Unavailable("deadline")` otherwise).
#[async_trait]
pub trait ConsoleStore: Send + Sync {
    async fn list_users(&self, q: UsersQuery, deadline: Deadline)
    -> StoreResult<Page<UserSummary>>;
    async fn user_detail(
        &self,
        user: &UserId,
        now: Timestamp,
        deadline: Deadline,
    ) -> StoreResult<Option<UserDetail>>;
    async fn list_live_sessions(
        &self,
        q: SessionsQuery,
        deadline: Deadline,
    ) -> StoreResult<Page<SessionSummary>>;
    async fn session_summary(
        &self,
        id: &SessionId,
        deadline: Deadline,
    ) -> StoreResult<Option<(SessionSummary, Vec<HandleRow>)>>;
}

/// Slice 3 (ADR-0020, ADR-0019): groups, memberships and the signed
/// projection journal. Every write appends its journal rows and `group.*`
/// events in the same transaction; journal revisions are gapless and become
/// visible in order, so a projection consumer never skips one.
#[async_trait]
pub trait GroupStore: Send + Sync {
    #[allow(clippy::too_many_arguments)]
    async fn groups_admin_edit(
        &self,
        actor: &Actor,
        policy: &ActorPolicy,
        edit: groups::Edit,
        settings: groups::WritePolicy,
        template: Event,
        deadline: Deadline,
    ) -> StoreResult<groups::Cas<groups::GroupRow>>;
    #[allow(clippy::too_many_arguments)]
    async fn groups_sync_user(
        &self,
        provider: ProviderId,
        source: crate::groups::Source,
        user: UserId,
        asserted: Vec<crate::groups::config::Mapped>,
        grace_secs: u64,
        settings: groups::WritePolicy,
        template: Event,
        deadline: Deadline,
    ) -> StoreResult<groups::SyncReport>;
    #[allow(clippy::too_many_arguments)]
    async fn groups_maintenance(
        &self,
        grace: std::collections::HashMap<String, u64>,
        stale_before: i64,
        suspend_before: i64,
        journal_before: i64,
        settings: groups::WritePolicy,
        template: Event,
        deadline: Deadline,
    ) -> StoreResult<groups::MaintenanceReport>;
    #[allow(clippy::too_many_arguments)]
    async fn groups_list(
        &self,
        q: Option<String>,
        source: Option<crate::groups::Source>,
        provider: Option<String>,
        include_deleted: bool,
        after: Option<(i64, String)>,
        limit: usize,
        deadline: Deadline,
    ) -> StoreResult<(Vec<groups::GroupRow>, bool)>;
    async fn group_get(
        &self,
        id: String,
        deadline: Deadline,
    ) -> StoreResult<Option<groups::GroupRow>>;
    async fn group_members(
        &self,
        id: String,
        after: Option<String>,
        limit: usize,
        now: i64,
        deadline: Deadline,
    ) -> StoreResult<(Vec<groups::MemberRow>, bool)>;
    async fn groups_of_users(
        &self,
        users: Vec<String>,
        after: Option<String>,
        limit: usize,
        now: i64,
        deadline: Deadline,
    ) -> StoreResult<GroupsOfUsers>;
    async fn groups_journal_bounds(&self, deadline: Deadline) -> StoreResult<(i64, Option<i64>)>;
    async fn groups_projection_snapshot(
        &self,
        vocabulary: Vec<String>,
        after: Option<String>,
        limit: usize,
        now: i64,
        deadline: Deadline,
    ) -> StoreResult<(Vec<groups::SnapshotEntry>, bool)>;
    async fn groups_projection_changes(
        &self,
        vocabulary: Vec<String>,
        after: i64,
        limit: usize,
        deadline: Deadline,
    ) -> StoreResult<Result<groups::JournalPage, groups::RevisionLost>>;
    async fn groups_sync_batch(
        &self,
        provider: String,
        interval_secs: u64,
        batch: usize,
        deadline: Deadline,
    ) -> StoreResult<Option<Vec<(String, String)>>>;
    async fn groups_sync_result(
        &self,
        provider: String,
        error: Option<&'static str>,
        deadline: Deadline,
    ) -> StoreResult<()>;
}

/// Each person's live groups (and whether the list was cut).
pub type GroupsOfUsers =
    std::collections::BTreeMap<String, (Vec<(groups::MemberRow, groups::GroupRow)>, bool)>;

/// Slice 3 (ADR-0020): the read-only subject directory and its lifecycle
/// feeds (reservation ledger, status and group changes). Positions are
/// handed out in commit order, so a consumer that has read position N never
/// later finds a new entry below N; a position the store no longer holds is
/// reported as lost (take a new snapshot).
#[async_trait]
pub trait SubjectDirectoryStore: Send + Sync {
    async fn admin_directory_rows(
        &self,
        users: Vec<String>,
        deadline: Deadline,
    ) -> StoreResult<std::collections::BTreeMap<String, directory::DirectoryRow>>;
    async fn admin_ledger_after(
        &self,
        after: i64,
        limit: usize,
        deadline: Deadline,
    ) -> StoreResult<Vec<directory::LedgerRow>>;
    async fn admin_ledger_at(
        &self,
        positions: Vec<i64>,
        deadline: Deadline,
    ) -> StoreResult<std::collections::BTreeMap<i64, String>>;
    async fn admin_ledger_head(&self, deadline: Deadline) -> StoreResult<i64>;
    async fn admin_outbox_head(&self, deadline: Deadline)
    -> StoreResult<directory::OutboxPosition>;
    async fn admin_feed_changes(
        &self,
        after: directory::OutboxPosition,
        limit: usize,
        groups: bool,
        workloads: bool,
        deadline: Deadline,
    ) -> StoreResult<Result<directory::StatusPage, directory::PositionLost>>;
    async fn admin_live_handle(
        &self,
        session: String,
        host: String,
        deadline: Deadline,
    ) -> StoreResult<Option<HandleRow>>;
    async fn admin_totp_active(&self, user: String, deadline: Deadline) -> StoreResult<bool>;
    /// The store's Human realm (64 lowercase hex), absent before it is set.
    async fn admin_human_realm(&self, deadline: Deadline) -> StoreResult<Option<String>>;
    /// The canonical Human subjects under `issuer` of existing, reserved users.
    async fn admin_human_subjects(
        &self,
        issuer: String,
        users: Vec<String>,
        deadline: Deadline,
    ) -> StoreResult<std::collections::BTreeMap<String, String>>;
}
