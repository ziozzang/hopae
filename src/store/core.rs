//! Slice 1 of the backend-neutral store contract (ADR-0020): users and
//! identities with the user-ID ledger, provider bootstrap, sessions and
//! handles, and the transactional outbox. Implemented by the SQLite store
//! (delegating to the existing traits) and by the PostgreSQL store; the
//! conformance suite (`store::conformance`) runs against both.
use async_trait::async_trait;

use super::StoreResult;
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
