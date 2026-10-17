//! The application's store handle (ADR-0020 slice 5): one type the whole
//! application holds, backed by SQLite or, with the `postgres` feature, by
//! PostgreSQL. The store traits dispatch to the backend; the
//! backend-specific methods the application calls are listed below with a
//! PostgreSQL implementation or a typed refusal while their subsystem is
//! not ported yet (never a silent fallback).
use std::net::IpAddr;
use std::sync::Arc;

use async_trait::async_trait;

use super::passkeys::*;
use super::types::*;
use super::{Directory, Events, Factors, Passkeys, Sessions, StoreError, StoreResult};
use crate::crypto::{Digest, Timestamp};
use crate::event::types::{Event, EventId, EventKind, Reason};
use crate::identity::types::{NormalizedEmail, UserId};
use crate::policy::types::Host;
use crate::provider::types::ProviderId;
use crate::session::types::SessionId;

#[derive(Clone)]
pub enum AppStore {
    Sqlite(super::sqlite::Store),
    #[cfg(feature = "postgres")]
    Postgres(Arc<super::postgres::PgStore>),
}

impl std::fmt::Debug for AppStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.backend())
    }
}

/// Run `$e` with `$s` bound to the backend store.
macro_rules! on {
    ($self:expr, $s:ident => $e:expr) => {
        match $self {
            AppStore::Sqlite($s) => $e,
            #[cfg(feature = "postgres")]
            AppStore::Postgres(p) => {
                let $s: &super::postgres::PgStore = p;
                $e
            }
        }
    };
}

impl From<super::sqlite::Store> for AppStore {
    fn from(s: super::sqlite::Store) -> Self {
        AppStore::Sqlite(s)
    }
}

#[cfg(feature = "postgres")]
impl From<Arc<super::postgres::PgStore>> for AppStore {
    fn from(s: Arc<super::postgres::PgStore>) -> Self {
        AppStore::Postgres(s)
    }
}

/// A backend-specific operation the PostgreSQL store does not provide yet.
pub fn unported(what: &'static str) -> StoreError {
    StoreError::Unavailable(format!(
        "{what} is not available on PostgreSQL yet (ADR-0020 slice 5)"
    ))
}

impl AppStore {
    /// This store's identity for prepared native owner values.
    pub(crate) fn owner_ref(&self) -> super::owner_ref::OwnerRef {
        match self {
            AppStore::Sqlite(s) => s.owner_ref(),
            #[cfg(feature = "postgres")]
            AppStore::Postgres(p) => super::owner_ref::OwnerRef::postgres(p),
        }
    }

    pub fn backend(&self) -> &'static str {
        match self {
            AppStore::Sqlite(_) => "sqlite",
            #[cfg(feature = "postgres")]
            AppStore::Postgres(_) => "postgres",
        }
    }

    /// The SQLite store, for subsystems that still run on its connection.
    pub fn sqlite(&self) -> Option<&super::sqlite::Store> {
        match self {
            AppStore::Sqlite(s) => Some(s),
            #[cfg(feature = "postgres")]
            AppStore::Postgres(_) => None,
        }
    }

    #[cfg(feature = "postgres")]
    pub fn postgres(&self) -> Option<&Arc<super::postgres::PgStore>> {
        match self {
            AppStore::Postgres(s) => Some(s),
            AppStore::Sqlite(_) => None,
        }
    }

    pub fn directory(&self) -> Arc<dyn Directory> {
        Arc::new(self.clone())
    }
    pub fn sessions(&self) -> Arc<dyn Sessions> {
        Arc::new(self.clone())
    }
    pub fn events(&self) -> Arc<dyn Events> {
        Arc::new(self.clone())
    }
}

// Generated dispatch (tools: see AppStore docs).
#[async_trait]
impl Directory for AppStore {
    #[allow(clippy::too_many_arguments)]
    async fn user(&self, id: &UserId) -> StoreResult<Option<User>> {
        on!(self, s => Directory::user(s, id).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn user_within(&self, id: &UserId, deadline: Deadline) -> StoreResult<Option<User>> {
        on!(self, s => Directory::user_within(s, id, deadline).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn user_authz(&self, id: &UserId) -> StoreResult<Option<UserAuthz>> {
        on!(self, s => Directory::user_authz(s, id).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn identity(
        &self,
        provider: &ProviderId,
        subject: &str,
    ) -> StoreResult<Option<IdentityRow>> {
        on!(self, s => Directory::identity(s, provider, subject).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn user_by_email(&self, email: &NormalizedEmail) -> StoreResult<Option<User>> {
        on!(self, s => Directory::user_by_email(s, email).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn create_user(
        &self,
        user: NewUser,
        identity: NewIdentity,
        events: Vec<Event>,
    ) -> StoreResult<User> {
        on!(self, s => Directory::create_user(s, user, identity, events).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn link_identity(
        &self,
        user: &UserId,
        identity: NewIdentity,
        events: Vec<Event>,
    ) -> StoreResult<()> {
        on!(self, s => Directory::link_identity(s, user, identity, events).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn touch_identity(
        &self,
        provider: &ProviderId,
        subject: &str,
        seen: &NewIdentity,
        at: Timestamp,
    ) -> StoreResult<()> {
        on!(self, s => Directory::touch_identity(s, provider, subject, seen, at).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn providers(&self) -> StoreResult<Vec<ProviderRow>> {
        on!(self, s => Directory::providers(s).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn import_providers(
        &self,
        from_file: Vec<ProviderRow>,
        force: Option<&ProviderId>,
        events: Vec<Event>,
    ) -> StoreResult<ImportReport> {
        on!(self, s => Directory::import_providers(s, from_file, force, events).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn bump_config_generation(&self) -> StoreResult<u64> {
        on!(self, s => Directory::bump_config_generation(s).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn config_generation(&self) -> StoreResult<u64> {
        on!(self, s => Directory::config_generation(s).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn admin_grant(
        &self,
        user: &UserId,
        deadline: Deadline,
    ) -> StoreResult<Option<AdminGrant>> {
        on!(self, s => Directory::admin_grant(s, user, deadline).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn admin_grants(
        &self,
        include_revoked: bool,
        deadline: Deadline,
    ) -> StoreResult<Vec<AdminGrant>> {
        on!(self, s => Directory::admin_grants(s, include_revoked, deadline).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn resolve_grant_target(
        &self,
        target: &GrantTarget,
        deadline: Deadline,
    ) -> StoreResult<Option<(User, Vec<IdentityRow>)>> {
        on!(self, s => Directory::resolve_grant_target(s, target, deadline).await)
    }
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
    ) -> StoreResult<(Option<AdminRole>, bool)> {
        on!(self, s => Directory::grant_admin(s, user, role, managed_by, source_email, by, note, at, event).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn revoke_admin(
        &self,
        user: &UserId,
        by: &str,
        managed_by: GrantManagedBy,
        at: Timestamp,
        event: Event,
    ) -> StoreResult<bool> {
        on!(self, s => Directory::revoke_admin(s, user, by, managed_by, at, event).await)
    }
    #[allow(clippy::too_many_arguments)]
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
    ) -> StoreResult<GrantImportReport> {
        on!(self, s => Directory::import_grants(s, entries, force, deadline, at, mk_event).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn list_users(
        &self,
        q: UsersQuery,
        deadline: Deadline,
    ) -> StoreResult<Page<UserSummary>> {
        on!(self, s => Directory::list_users(s, q, deadline).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn user_detail(
        &self,
        user: &UserId,
        now: Timestamp,
        deadline: Deadline,
    ) -> StoreResult<Option<UserDetail>> {
        on!(self, s => Directory::user_detail(s, user, now, deadline).await)
    }
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
    ) -> StoreResult<(bool, u32)> {
        on!(self, s => Directory::set_user_status(s, actor, policy, user, status, deadline, admin_event, mk_session_event).await)
    }
}

#[async_trait]
impl Sessions for AppStore {
    #[allow(clippy::too_many_arguments)]
    async fn create_session(&self, req: CreateSession) -> StoreResult<()> {
        on!(self, s => Sessions::create_session(s, req).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn session(&self, id: &SessionId) -> StoreResult<Option<SessionRow>> {
        on!(self, s => Sessions::session(s, id).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn lookup_handle(
        &self,
        handle_sha256: &Digest,
        host: &Host,
    ) -> StoreResult<Option<HandleView>> {
        on!(self, s => Sessions::lookup_handle(s, handle_sha256, host).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn lookup_handle_within(
        &self,
        handle_sha256: &Digest,
        host: &Host,
        deadline: Deadline,
    ) -> StoreResult<Option<HandleView>> {
        on!(self, s => Sessions::lookup_handle_within(s, handle_sha256, host, deadline).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn touch_handle(&self, handle_sha256: &Digest, at: Timestamp) -> StoreResult<()> {
        on!(self, s => Sessions::touch_handle(s, handle_sha256, at).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn mint_handle(
        &self,
        handle: HandleRow,
        replaces: Option<Digest>,
        events: Vec<Event>,
    ) -> StoreResult<()> {
        on!(self, s => Sessions::mint_handle(s, handle, replaces, events).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn revoke_handle(
        &self,
        handle_sha256: &Digest,
        reason: Reason,
        at: Timestamp,
        events: Vec<Event>,
    ) -> StoreResult<()> {
        on!(self, s => Sessions::revoke_handle(s, handle_sha256, reason, at, events).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn terminate_session(
        &self,
        id: &SessionId,
        reason: Reason,
        at: Timestamp,
        events: Vec<Event>,
    ) -> StoreResult<()> {
        on!(self, s => Sessions::terminate_session(s, id, reason, at, events).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn consume_logout_ticket(
        &self,
        txn_sha256: &Digest,
        session: Option<&SessionId>,
        reason: Reason,
        at: Timestamp,
        events: Vec<Event>,
    ) -> StoreResult<bool> {
        on!(self, s => Sessions::consume_logout_ticket(s, txn_sha256, session, reason, at, events).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn list_live_sessions(
        &self,
        q: SessionsQuery,
        deadline: Deadline,
    ) -> StoreResult<Page<SessionSummary>> {
        on!(self, s => Sessions::list_live_sessions(s, q, deadline).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn session_summary(
        &self,
        id: &SessionId,
        deadline: Deadline,
    ) -> StoreResult<Option<(SessionSummary, Vec<HandleRow>)>> {
        on!(self, s => Sessions::session_summary(s, id, deadline).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn admin_terminate_session(
        &self,
        actor: &Actor,
        policy: &ActorPolicy,
        id: &SessionId,
        deadline: Deadline,
        admin_event: Event,
        session_event: Event,
    ) -> StoreResult<bool> {
        on!(self, s => Sessions::admin_terminate_session(s, actor, policy, id, deadline, admin_event, session_event).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn admin_terminate_user_sessions(
        &self,
        actor: &Actor,
        policy: &ActorPolicy,
        user: &UserId,
        deadline: Deadline,
        admin_event: Event,
        mk_session_event: &(dyn for<'a> Fn(&'a SessionRow) -> Event + Sync),
    ) -> StoreResult<u32> {
        on!(self, s => Sessions::admin_terminate_user_sessions(s, actor, policy, user, deadline, admin_event, mk_session_event).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn reauthenticate_session(
        &self,
        id: &SessionId,
        provider: &ProviderId,
        configuration: Option<(crate::provider::types::ProviderKind, serde_json::Value)>,
        auth_time: Timestamp,
        source: AuthTimeSource,
        factor: crate::session::types::FactorEntry,
        new_portal_handle: HandleRow,
        consume_txn: (Digest, Reason),
        deadline: Deadline,
        events: Vec<Event>,
        mk_revoked_event: &(dyn for<'a> Fn(&'a HandleRow) -> Event + Sync),
    ) -> StoreResult<()> {
        on!(self, s => Sessions::reauthenticate_session(s, id, provider, configuration, auth_time, source, factor, new_portal_handle, consume_txn, deadline, events, mk_revoked_event).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn refresh_snapshot(
        &self,
        id: &SessionId,
        snapshot: IdentitySnapshot,
        authz_version: u64,
    ) -> StoreResult<()> {
        on!(self, s => Sessions::refresh_snapshot(s, id, snapshot, authz_version).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn create_transaction(&self, txn: NewTransaction, events: Vec<Event>) -> StoreResult<()> {
        on!(self, s => Sessions::create_transaction(s, txn, events).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn create_transaction_capped(
        &self,
        txn: NewTransaction,
        events: Vec<Event>,
        since: Timestamp,
        cap: Option<u32>,
        max_rows: u32,
    ) -> StoreResult<Admission> {
        on!(self, s => Sessions::create_transaction_capped(s, txn, events, since, cap, max_rows).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn transaction(&self, txn_sha256: &Digest) -> StoreResult<Option<TransactionRow>> {
        on!(self, s => Sessions::transaction(s, txn_sha256).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn transaction_by_state(
        &self,
        state_sha256: &Digest,
    ) -> StoreResult<Option<TransactionRow>> {
        on!(self, s => Sessions::transaction_by_state(s, state_sha256).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn bind_transaction(
        &self,
        txn_sha256: &Digest,
        binding: TransactionBinding,
    ) -> StoreResult<()> {
        on!(self, s => Sessions::bind_transaction(s, txn_sha256, binding).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn bind_switch_transaction(
        &self,
        txn_sha256: &Digest,
        portal_bind_sha256: Digest,
    ) -> StoreResult<bool> {
        on!(self, s => Sessions::bind_switch_transaction(s, txn_sha256, portal_bind_sha256).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn bind_logout_transaction(
        &self,
        txn_sha256: &Digest,
        portal_bind_sha256: Digest,
    ) -> StoreResult<bool> {
        on!(self, s => Sessions::bind_logout_transaction(s, txn_sha256, portal_bind_sha256).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn use_retry(&self, txn_sha256: &Digest, at: Timestamp) -> StoreResult<bool> {
        on!(self, s => Sessions::use_retry(s, txn_sha256, at).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn record_retry_bind(
        &self,
        txn_sha256: &Digest,
        retry_bind_sha256: Digest,
    ) -> StoreResult<()> {
        on!(self, s => Sessions::record_retry_bind(s, txn_sha256, retry_bind_sha256).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn consume_transaction(
        &self,
        txn_sha256: &Digest,
        reason: Reason,
        at: Timestamp,
        events: Vec<Event>,
    ) -> StoreResult<bool> {
        on!(self, s => Sessions::consume_transaction(s, txn_sha256, reason, at, events).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn consume_transaction_for_provider(
        &self,
        txn_sha256: &Digest,
        provider: &ProviderId,
        configuration: Option<(crate::provider::types::ProviderKind, serde_json::Value)>,
        reason: Reason,
        at: Timestamp,
        events: Vec<Event>,
    ) -> StoreResult<bool> {
        on!(self, s => Sessions::consume_transaction_for_provider(s, txn_sha256, provider, configuration, reason, at, events).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn mint_handoff_code(&self, code: HandoffCodeRow, events: Vec<Event>) -> StoreResult<()> {
        on!(self, s => Sessions::mint_handoff_code(s, code, events).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn redeem_handoff_code(
        &self,
        req: RedeemRequest,
        events_on_success: Vec<Event>,
        events_on_failure: Vec<Event>,
    ) -> StoreResult<RedeemOutcome> {
        on!(self, s => Sessions::redeem_handoff_code(s, req, events_on_success, events_on_failure).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn count_transactions_since(&self, ip: IpAddr, since: Timestamp) -> StoreResult<u32> {
        on!(self, s => Sessions::count_transactions_since(s, ip, since).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn count_handoff_failures_since(&self, ip: IpAddr, since: Timestamp) -> StoreResult<u32> {
        on!(self, s => Sessions::count_handoff_failures_since(s, ip, since).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn evict_transactions(&self, max_rows: u32, now: Timestamp) -> StoreResult<u32> {
        on!(self, s => Sessions::evict_transactions(s, max_rows, now).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn session_aal3_evidence(&self, session: &SessionId, cred_gen: u64) -> StoreResult<bool> {
        on!(self, s => Sessions::session_aal3_evidence(s, session, cred_gen).await)
    }
    async fn user_has_passkey(&self, user: &UserId) -> StoreResult<bool> {
        on!(self, s => Sessions::user_has_passkey(s, user).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn sweep(
        &self,
        now: Timestamp,
        retention: std::time::Duration,
    ) -> StoreResult<SweepReport> {
        on!(self, s => Sessions::sweep(s, now, retention).await)
    }
}

#[async_trait]
impl Events for AppStore {
    #[allow(clippy::too_many_arguments)]
    async fn append_required(&self, events: Vec<Event>) -> StoreResult<()> {
        on!(self, s => Events::append_required(s, events).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn append_required_within(
        &self,
        events: Vec<Event>,
        deadline: Deadline,
    ) -> StoreResult<()> {
        on!(self, s => Events::append_required_within(s, events, deadline).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn append_diagnostic(&self, event: Event) -> StoreResult<()> {
        on!(self, s => Events::append_diagnostic(s, event).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn claim_deliveries(
        &self,
        sink: &str,
        limit: usize,
        now: Timestamp,
    ) -> StoreResult<Vec<Delivery>> {
        on!(self, s => Events::claim_deliveries(s, sink, limit, now).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn mark_delivered(
        &self,
        sink: &str,
        event_id: &EventId,
        at: Timestamp,
    ) -> StoreResult<()> {
        on!(self, s => Events::mark_delivered(s, sink, event_id, at).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn mark_failed(
        &self,
        sink: &str,
        event_id: &EventId,
        error: &str,
        next_attempt_at: Option<Timestamp>,
    ) -> StoreResult<()> {
        on!(self, s => Events::mark_failed(s, sink, event_id, error, next_attempt_at).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn prune(&self, now: Timestamp, policy: &EventRetention) -> StoreResult<PruneReport> {
        on!(self, s => Events::prune(s, now, policy).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn count_rows(&self) -> StoreResult<(u64, u64)> {
        on!(self, s => Events::count_rows(s).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn query(&self, filter: EventQuery) -> StoreResult<Vec<Event>> {
        on!(self, s => Events::query(s, filter).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn query_page(&self, q: EventsQuery, deadline: Deadline) -> StoreResult<Page<Event>> {
        on!(self, s => Events::query_page(s, q, deadline).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn status(&self, deadline: Deadline) -> StoreResult<StoreStatus> {
        on!(self, s => Events::status(s, deadline).await)
    }
}

#[async_trait]
impl Factors for AppStore {
    #[allow(clippy::too_many_arguments)]
    async fn external_snapshot_revision(&self) -> StoreResult<u64> {
        on!(self, s => Factors::external_snapshot_revision(s).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn publish_external_snapshot(&self, request: ExternalFactorSnapshot) -> StoreResult<u64> {
        on!(self, s => Factors::publish_external_snapshot(s, request).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn publish_external_factor(&self, request: ExternalFactorPublication) -> StoreResult<()> {
        on!(self, s => Factors::publish_external_factor(s, request).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn bind_external_stepup(&self, request: BindExternalStepUp) -> StoreResult<()> {
        on!(self, s => Factors::bind_external_stepup(s, request).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn elevate_external(&self, request: ExternalElevation) -> StoreResult<()> {
        on!(self, s => Factors::elevate_external(s, request).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn bind_totp_stepup(&self, request: BindTotpStepUp) -> StoreResult<TotpChallengeBinding> {
        on!(self, s => Factors::bind_totp_stepup(s, request).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn elevate_totp(&self, request: TotpElevation) -> StoreResult<()> {
        on!(self, s => Factors::elevate_totp(s, request).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn has_active_totp(&self, user: &UserId) -> StoreResult<bool> {
        on!(self, s => Factors::has_active_totp(s, user).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn activate_totp_authorized(
        &self,
        id: &str,
        actor: FactorActor,
        revision: u64,
        counter: u64,
        events: Vec<Event>,
    ) -> StoreResult<bool> {
        on!(self, s => Factors::activate_totp_authorized(s, id, actor, revision, counter, events).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn revoke_totp_authorized(
        &self,
        id: &str,
        actor: FactorActor,
        revision: u64,
        events: Vec<Event>,
    ) -> StoreResult<bool> {
        on!(self, s => Factors::revoke_totp_authorized(s, id, actor, revision, events).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn create_totp_pending_authorized(
        &self,
        id: String,
        actor: FactorActor,
        envelope: crate::factor::seed_cipher::Envelope,
        events: Vec<Event>,
    ) -> StoreResult<()> {
        on!(self, s => Factors::create_totp_pending_authorized(s, id, actor, envelope, events).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn totp_enrollment(
        &self,
        id: &str,
        user: &UserId,
    ) -> StoreResult<Option<TotpEnrollment>> {
        on!(self, s => Factors::totp_enrollment(s, id, user).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn create_totp_pending(
        &self,
        id: String,
        user: UserId,
        envelope: crate::factor::seed_cipher::Envelope,
        events: Vec<Event>,
    ) -> StoreResult<()> {
        on!(self, s => Factors::create_totp_pending(s, id, user, envelope, events).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn activate_totp(
        &self,
        id: &str,
        user: &UserId,
        revision: u64,
        counter: u64,
        events: Vec<Event>,
    ) -> StoreResult<bool> {
        on!(self, s => Factors::activate_totp(s, id, user, revision, counter, events).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn consume_totp_counter(
        &self,
        id: &str,
        user: &UserId,
        revision: u64,
        counter: u64,
        events: Vec<Event>,
    ) -> StoreResult<bool> {
        on!(self, s => Factors::consume_totp_counter(s, id, user, revision, counter, events).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn revoke_totp(
        &self,
        id: &str,
        user: &UserId,
        revision: u64,
        events: Vec<Event>,
    ) -> StoreResult<bool> {
        on!(self, s => Factors::revoke_totp(s, id, user, revision, events).await)
    }
}

#[async_trait]
impl Passkeys for AppStore {
    #[allow(clippy::too_many_arguments)]
    async fn passkey_user_handle(
        &self,
        user: &UserId,
        candidate: [u8; 16],
    ) -> StoreResult<[u8; 16]> {
        on!(self, s => Passkeys::passkey_user_handle(s, user, candidate).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn factor_summary(&self, user: &UserId) -> StoreResult<FactorSummary> {
        on!(self, s => Passkeys::factor_summary(s, user).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn active_totp_enrollment(&self, user: &UserId) -> StoreResult<Option<String>> {
        on!(self, s => Passkeys::active_totp_enrollment(s, user).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn begin_ceremony(&self, ceremony: NewCeremony) -> StoreResult<()> {
        on!(self, s => Passkeys::begin_ceremony(s, ceremony).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn ceremony(&self, digest: &Digest) -> StoreResult<Option<CeremonyRecord>> {
        on!(self, s => Passkeys::ceremony(s, digest).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn fail_ceremony(&self, digest: &Digest, events: Vec<Event>) -> StoreResult<()> {
        on!(self, s => Passkeys::fail_ceremony(s, digest, events).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn register_passkey(&self, request: RegisterPasskey) -> StoreResult<()> {
        on!(self, s => Passkeys::register_passkey(s, request).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn elevate_webauthn(&self, request: WebauthnElevation) -> StoreResult<()> {
        on!(self, s => Passkeys::elevate_webauthn(s, request).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn elevate_portal(&self, request: PortalElevation) -> StoreResult<()> {
        on!(self, s => Passkeys::elevate_portal(s, request).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn passkey_clone_detected(
        &self,
        ceremony: &Digest,
        credential_id: &[u8],
        events: Vec<Event>,
    ) -> StoreResult<()> {
        on!(self, s => Passkeys::passkey_clone_detected(s, ceremony, credential_id, events).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn rename_passkey(
        &self,
        actor: FactorActor,
        credential_id: &[u8],
        label: String,
        events: Vec<Event>,
    ) -> StoreResult<bool> {
        on!(self, s => Passkeys::rename_passkey(s, actor, credential_id, label, events).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn revoke_passkey(
        &self,
        actor: FactorActor,
        credential_id: &[u8],
        events: Vec<Event>,
    ) -> StoreResult<bool> {
        on!(self, s => Passkeys::revoke_passkey(s, actor, credential_id, events).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn replace_recovery_codes(
        &self,
        actor: FactorActor,
        batch: String,
        codes: Vec<(String, String)>,
        events: Vec<Event>,
    ) -> StoreResult<()> {
        on!(self, s => Passkeys::replace_recovery_codes(s, actor, batch, codes, events).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn recovery_code_hash(&self, user: &UserId, lookup: &str) -> StoreResult<Option<String>> {
        on!(self, s => Passkeys::recovery_code_hash(s, user, lookup).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn begin_login_ceremony(&self, ceremony: NewLoginCeremony) -> StoreResult<()> {
        on!(self, s => Passkeys::begin_login_ceremony(s, ceremony).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn login_ceremony(&self, digest: &Digest) -> StoreResult<Option<LoginCeremonyRecord>> {
        on!(self, s => Passkeys::login_ceremony(s, digest).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn fail_login_ceremony(&self, digest: &Digest, events: Vec<Event>) -> StoreResult<()> {
        on!(self, s => Passkeys::fail_login_ceremony(s, digest, events).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn passkey_account(
        &self,
        handle: [u8; 16],
    ) -> StoreResult<Option<(UserId, Vec<PasskeyRecord>)>> {
        on!(self, s => Passkeys::passkey_account(s, handle).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn create_passkey_session(&self, login: PasskeyLogin) -> StoreResult<()> {
        on!(self, s => Passkeys::create_passkey_session(s, login).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn passkey_login_clone(
        &self,
        ceremony: &Digest,
        credential_id: &[u8],
        events: Vec<Event>,
    ) -> StoreResult<()> {
        on!(self, s => Passkeys::passkey_login_clone(s, ceremony, credential_id, events).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn end_passkey_sessions(&self, request_id: &str) -> StoreResult<u32> {
        on!(self, s => Passkeys::end_passkey_sessions(s, request_id).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn reset_factors(
        &self,
        user: &UserId,
        request_id: &str,
        events: Vec<Event>,
    ) -> StoreResult<FactorResetReport> {
        on!(self, s => Passkeys::reset_factors(s, user, request_id, events).await)
    }
}

// ---- backend-specific operations ---------------------------------------------

use super::core::{GroupStore, GroupsOfUsers, SubjectDirectoryStore};
use super::sqlite::groups;
use super::sqlite::subject_directory as directory;
use super::{Deadline, StoreHooks};
use crate::crypto::Clock;

impl AppStore {
    /// Open (and migrate) the SQLite store at `path`.
    pub fn open(
        path: &std::path::Path,
        clock: Arc<dyn Clock>,
        sinks: Vec<String>,
        hooks: Option<Arc<StoreHooks>>,
    ) -> Result<Self, StoreError> {
        super::sqlite::Store::open(path, clock, sinks, hooks).map(AppStore::Sqlite)
    }

    /// Open the SQLite store for a command-line tool (never migrates).
    pub fn open_cli(
        path: &std::path::Path,
        clock: Arc<dyn Clock>,
        sinks: Vec<String>,
    ) -> Result<Self, StoreError> {
        super::sqlite::Store::open_cli(path, clock, sinks).map(AppStore::Sqlite)
    }

    /// The SQLite writer connection of a subsystem that still runs on it.
    ///
    /// # Panics
    /// On PostgreSQL: such subsystems are refused before a PostgreSQL store
    /// is opened (`serve` checks every caller is ported first).
    pub fn conn(&self) -> std::sync::MutexGuard<'_, rusqlite::Connection> {
        match self {
            AppStore::Sqlite(s) => s.conn(),
            #[cfg(feature = "postgres")]
            AppStore::Postgres(_) => panic!("SQLite connection requested from a PostgreSQL store"),
        }
    }

    /// The meta connection of the native owners (blocking; see `store::meta`).
    pub fn meta(&self) -> super::meta::MetaHandle<'_> {
        match self {
            AppStore::Sqlite(s) => super::meta::MetaHandle::Sqlite(s.conn()),
            #[cfg(feature = "postgres")]
            AppStore::Postgres(p) => {
                super::meta::MetaHandle::Postgres(super::postgres::meta::PgMeta::new(p.clone()))
            }
        }
    }

    /// The administrator fence (ADR-0016) inside an open meta transaction.
    pub fn fence_meta(
        &self,
        tx: &dyn super::meta::MetaTx,
        actor: &Actor,
        policy: &ActorPolicy,
    ) -> StoreResult<()> {
        match self {
            AppStore::Sqlite(s) => {
                let c = tx
                    .sqlite()
                    .ok_or(StoreError::Unavailable("foreign meta transaction".into()))?;
                s.fence_profile_actor(c, actor, policy)
            }
            #[cfg(feature = "postgres")]
            AppStore::Postgres(_) => tx
                .postgres()
                .ok_or(StoreError::Unavailable("foreign meta transaction".into()))?
                .fence(actor, policy),
        }
    }

    /// Record required events on the caller's already-open meta (publication)
    /// transaction: they commit or roll back with it.
    pub(crate) fn record_in(
        &self,
        tx: &dyn super::meta::MetaTx,
        events: &[crate::event::types::Event],
    ) -> StoreResult<()> {
        match self {
            AppStore::Sqlite(s) => {
                let c = tx
                    .sqlite()
                    .ok_or(StoreError::Unavailable("foreign meta transaction".into()))?;
                s.record_in(c, events)
            }
            #[cfg(feature = "postgres")]
            AppStore::Postgres(_) => tx
                .postgres()
                .ok_or(StoreError::Unavailable("foreign meta transaction".into()))?
                .record(events),
        }
    }

    // ---- identity platform: workload registry, service credentials, factor reset

    pub async fn workload_record(
        &self,
        changes: Vec<super::sqlite::workloads::WorkloadChange>,
        events: Vec<Event>,
    ) -> StoreResult<()> {
        match self {
            AppStore::Sqlite(s) => s.workload_record(changes, events).await,
            #[cfg(feature = "postgres")]
            AppStore::Postgres(p) => p.workload_record(changes, events).await,
        }
    }

    pub async fn workload_snapshot_after(
        &self,
        after: i64,
        limit: usize,
        deadline: Deadline,
    ) -> StoreResult<Vec<super::sqlite::workloads::WorkloadRow>> {
        match self {
            AppStore::Sqlite(s) => s.workload_snapshot_after(after, limit, deadline).await,
            #[cfg(feature = "postgres")]
            AppStore::Postgres(p) => p.workload_snapshot_after(after, limit, deadline).await,
        }
    }

    pub async fn workload_head(&self) -> StoreResult<i64> {
        match self {
            AppStore::Sqlite(s) => s.workload_head().await,
            #[cfg(feature = "postgres")]
            AppStore::Postgres(p) => p.workload_head().await,
        }
    }

    pub async fn service_credential_get(
        &self,
        id: String,
        deadline: Deadline,
    ) -> StoreResult<Option<super::sqlite::service_credentials::ServiceCredentialRow>> {
        match self {
            AppStore::Sqlite(s) => s.service_credential_get(id, deadline).await,
            #[cfg(feature = "postgres")]
            AppStore::Postgres(p) => p.service_credential_get(id, deadline).await,
        }
    }

    pub async fn service_credential_list(
        &self,
    ) -> StoreResult<Vec<super::sqlite::service_credentials::ServiceCredentialRow>> {
        match self {
            AppStore::Sqlite(s) => s.service_credential_list().await,
            #[cfg(feature = "postgres")]
            AppStore::Postgres(p) => p.service_credential_list().await,
        }
    }

    pub async fn service_credential_create(
        &self,
        row: super::sqlite::service_credentials::ServiceCredentialRow,
        events: Vec<Event>,
    ) -> StoreResult<()> {
        match self {
            AppStore::Sqlite(s) => s.service_credential_create(row, events).await,
            #[cfg(feature = "postgres")]
            AppStore::Postgres(p) => p.service_credential_create(row, events).await,
        }
    }

    pub async fn service_credential_change(
        &self,
        id: String,
        change: super::sqlite::service_credentials::Change,
        digest: Option<String>,
        events: Vec<Event>,
    ) -> StoreResult<super::sqlite::service_credentials::ServiceCredentialRow> {
        match self {
            AppStore::Sqlite(s) => {
                s.service_credential_change(id, change, digest, events)
                    .await
            }
            #[cfg(feature = "postgres")]
            AppStore::Postgres(p) => {
                p.service_credential_change(id, change, digest, events)
                    .await
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn admin_reset_factors(
        &self,
        actor: &Actor,
        policy: &ActorPolicy,
        user: &UserId,
        scope: FactorResetScope,
        deadline: Deadline,
        admin_event: Event,
    ) -> StoreResult<(bool, FactorResetReport)> {
        match self {
            AppStore::Sqlite(s) => {
                s.admin_reset_factors(actor, policy, user, scope, deadline, admin_event)
                    .await
            }
            #[cfg(feature = "postgres")]
            AppStore::Postgres(p) => {
                p.admin_reset_factors(actor, policy, user, scope, deadline, admin_event)
                    .await
            }
        }
    }

    /// Wait until every write queued before this call has committed.
    pub async fn barrier(&self) -> StoreResult<()> {
        match self {
            AppStore::Sqlite(s) => s.barrier().await,
            // Every PostgreSQL write commits before its call returns.
            #[cfg(feature = "postgres")]
            AppStore::Postgres(_) => Ok(()),
        }
    }

    #[allow(irrefutable_let_patterns)]
    pub fn set_event_retention(&self, policy: EventRetention) {
        if let AppStore::Sqlite(s) = self {
            s.set_event_retention(policy);
        }
    }

    #[allow(irrefutable_let_patterns)]
    pub fn set_drop_counts(&self, drops: Arc<crate::event::bus::DropCounts>) {
        if let AppStore::Sqlite(s) = self {
            s.set_drop_counts(drops);
        }
    }

    #[allow(irrefutable_let_patterns)]
    pub fn set_diagnostic_log(&self, log: Arc<crate::event::sinks::LogSink>) {
        if let AppStore::Sqlite(s) = self {
            s.set_diagnostic_log(log);
        }
    }

    #[allow(irrefutable_let_patterns)]
    pub fn set_rng(&self, rng: Arc<dyn crate::crypto::Rng>) {
        if let AppStore::Sqlite(s) = self {
            s.set_rng(rng);
        }
    }

    pub fn schema_version(&self) -> Result<u32, StoreError> {
        match self {
            AppStore::Sqlite(s) => s.schema_version(),
            #[cfg(feature = "postgres")]
            AppStore::Postgres(_) => Ok(super::postgres::LATEST_SCHEMA_VERSION as u32),
        }
    }

    pub fn hold_write_lock(&self, ms: u64) -> Result<(), StoreError> {
        match self {
            AppStore::Sqlite(s) => s.hold_write_lock(ms),
            #[cfg(feature = "postgres")]
            AppStore::Postgres(_) => Err(unported("the test write lock")),
        }
    }

    pub fn explain_window(
        &self,
        shape: super::WindowShape,
        cursor: Option<(i64, String)>,
        stats: bool,
    ) -> StoreResult<serde_json::Value> {
        match self {
            AppStore::Sqlite(s) => s.explain_window(shape, cursor, stats),
            #[cfg(feature = "postgres")]
            AppStore::Postgres(_) => Err(unported("listing plans")),
        }
    }

    pub async fn dump_deliveries(&self, sink: Option<&str>) -> StoreResult<Vec<DeliveryRow>> {
        match self {
            AppStore::Sqlite(s) => s.dump_deliveries(sink).await,
            #[cfg(feature = "postgres")]
            AppStore::Postgres(_) => Err(unported("the delivery dump")),
        }
    }

    /// A process-local identity of this open store, for caches derived from it.
    pub(crate) fn directory_identity(&self) -> usize {
        match self {
            AppStore::Sqlite(s) => s.directory_identity(),
            #[cfg(feature = "postgres")]
            AppStore::Postgres(p) => Arc::as_ptr(p) as usize,
        }
    }

    pub async fn mirror_apps(&self, apps: &[crate::policy::types::AppPolicy]) -> StoreResult<()> {
        match self {
            AppStore::Sqlite(s) => s.mirror_apps(apps).await,
            #[cfg(feature = "postgres")]
            AppStore::Postgres(p) => p.mirror_apps(apps).await,
        }
    }

    #[cfg(any(test, feature = "test-hooks"))]
    pub async fn elevate_session(
        &self,
        id: &SessionId,
        at: Timestamp,
        events: Vec<Event>,
    ) -> StoreResult<()> {
        match self {
            AppStore::Sqlite(s) => s.elevate_session(id, at, events).await,
            #[cfg(feature = "postgres")]
            AppStore::Postgres(_) => Err(unported("session elevation")),
        }
    }

    pub(crate) async fn admin_human_subject(
        &self,
        issuer: String,
        user: String,
        deadline: Deadline,
    ) -> StoreResult<Option<String>> {
        Ok(
            SubjectDirectoryStore::admin_human_subjects(self, issuer, vec![user.clone()], deadline)
                .await?
                .remove(&user),
        )
    }

    // Native owners: SQLite only until their PostgreSQL port lands.

    pub(crate) async fn prepare_registry_providers(
        &self,
        expected_generation: u64,
        deadline: Deadline,
    ) -> StoreResult<super::sqlite::provider_owner::PreparedProviders> {
        match self {
            AppStore::Sqlite(s) => {
                s.prepare_registry_providers(expected_generation, deadline)
                    .await
            }
            #[cfg(feature = "postgres")]
            AppStore::Postgres(p) => {
                p.prepare_registry_providers(expected_generation, deadline)
                    .await
            }
        }
    }

    pub(crate) async fn require_prepared_providers(
        &self,
        prepared: &super::sqlite::provider_owner::PreparedProviders,
        deadline: Deadline,
    ) -> StoreResult<()> {
        match self {
            AppStore::Sqlite(s) => s.require_prepared_providers(prepared, deadline).await,
            #[cfg(feature = "postgres")]
            AppStore::Postgres(p) => p.require_prepared_providers(prepared, deadline).await,
        }
    }

    pub(crate) async fn require_prepared_provider(
        &self,
        prepared: &super::sqlite::provider_owner::PreparedProviders,
        id: &ProviderId,
        deadline: Deadline,
    ) -> StoreResult<()> {
        match self {
            AppStore::Sqlite(s) => s.require_prepared_provider(prepared, id, deadline).await,
            #[cfg(feature = "postgres")]
            AppStore::Postgres(p) => p.require_prepared_provider(prepared, id, deadline).await,
        }
    }

    pub(crate) async fn publish_materials(
        &self,
        prepared: &super::sqlite::provider_owner::PreparedProviders,
        desired: &std::collections::BTreeMap<String, crate::provider::material::Fingerprint>,
        deadline: Deadline,
    ) -> StoreResult<super::sqlite::material_owner::Published> {
        match self {
            AppStore::Sqlite(s) => s.publish_materials(prepared, desired, deadline).await,
            #[cfg(feature = "postgres")]
            AppStore::Postgres(p) => p.publish_materials(prepared, desired, deadline).await,
        }
    }

    pub(crate) async fn require_human_snapshot(
        &self,
        prepared: &super::sqlite::provider_owner::PreparedProviders,
        materials: &super::sqlite::material_owner::Published,
        witness: &crate::verify::human::Witness,
        now: Timestamp,
        deadline: Deadline,
    ) -> StoreResult<super::sqlite::human_owner::Current> {
        match self {
            AppStore::Sqlite(s) => {
                s.require_human_snapshot(prepared, materials, witness, now, deadline)
                    .await
            }
            #[cfg(feature = "postgres")]
            AppStore::Postgres(p) => {
                super::sqlite::human_owner::postgres::require_human_snapshot(
                    p, prepared, materials, witness, now, deadline,
                )
                .await
            }
        }
    }

    pub(crate) fn prepare_human_snapshot(
        &self,
        prepared: &super::sqlite::provider_owner::PreparedProviders,
        materials: &super::sqlite::material_owner::Published,
        witness: &crate::verify::human::Witness,
    ) -> StoreResult<super::sqlite::human_owner::SnapshotCheck> {
        super::sqlite::human_owner::prepare_human_snapshot(
            &self.owner_ref(),
            prepared,
            materials,
            witness,
        )
    }

    pub(crate) async fn human_ledger<T: Send + 'static>(
        &self,
        deadline: Deadline,
        operation: impl FnOnce(&mut super::sqlite::human_owner::Ledger<'_>) -> StoreResult<T>
        + Send
        + 'static,
    ) -> StoreResult<T> {
        match self {
            AppStore::Sqlite(s) => s.human_ledger(deadline, operation).await,
            #[cfg(feature = "postgres")]
            AppStore::Postgres(p) => {
                super::sqlite::human_owner::postgres::human_ledger(p, deadline, operation).await
            }
        }
    }

    pub(crate) async fn create_session_primary(
        &self,
        req: CreateSession,
        primary: crate::session::service::VerifiedPrimary,
    ) -> StoreResult<()> {
        match self {
            AppStore::Sqlite(s) => s.create_session_primary(req, primary).await,
            #[cfg(feature = "postgres")]
            AppStore::Postgres(p) => p.create_session_primary(req, primary).await,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn reauthenticate_primary(
        &self,
        id: &SessionId,
        provider: &ProviderId,
        configuration: Option<(crate::provider::types::ProviderKind, serde_json::Value)>,
        auth_time: Timestamp,
        source: AuthTimeSource,
        factor: crate::session::types::FactorEntry,
        new_portal_handle: HandleRow,
        consume_txn: (Digest, Reason),
        deadline: Deadline,
        events: Vec<Event>,
        mk_revoked_event: &(dyn for<'a> Fn(&'a HandleRow) -> Event + Sync),
        primary: crate::session::service::VerifiedPrimary,
    ) -> StoreResult<()> {
        match self {
            AppStore::Sqlite(s) => {
                s.reauthenticate_primary(
                    id,
                    provider,
                    configuration,
                    auth_time,
                    source,
                    factor,
                    new_portal_handle,
                    consume_txn,
                    deadline,
                    events,
                    mk_revoked_event,
                    primary,
                )
                .await
            }
            #[cfg(feature = "postgres")]
            AppStore::Postgres(p) => {
                p.reauthenticate_primary(
                    id,
                    provider,
                    configuration.as_ref(),
                    auth_time,
                    source,
                    &factor,
                    &new_portal_handle,
                    &consume_txn,
                    deadline,
                    &events,
                    mk_revoked_event,
                    &primary,
                )
                .await
            }
        }
    }
}

#[async_trait]
impl GroupStore for AppStore {
    #[allow(clippy::too_many_arguments)]
    async fn groups_admin_edit(
        &self,
        actor: &Actor,
        policy: &ActorPolicy,
        edit: groups::Edit,
        settings: groups::WritePolicy,
        template: Event,
        deadline: Deadline,
    ) -> StoreResult<groups::Cas<groups::GroupRow>> {
        on!(self, s => GroupStore::groups_admin_edit(s, actor, policy, edit, settings, template, deadline).await)
    }
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
    ) -> StoreResult<groups::SyncReport> {
        on!(self, s => GroupStore::groups_sync_user(s, provider, source, user, asserted, grace_secs, settings, template, deadline).await)
    }
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
    ) -> StoreResult<groups::MaintenanceReport> {
        on!(self, s => GroupStore::groups_maintenance(s, grace, stale_before, suspend_before, journal_before, settings, template, deadline).await)
    }
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
    ) -> StoreResult<(Vec<groups::GroupRow>, bool)> {
        on!(self, s => GroupStore::groups_list(s, q, source, provider, include_deleted, after, limit, deadline).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn group_get(
        &self,
        id: String,
        deadline: Deadline,
    ) -> StoreResult<Option<groups::GroupRow>> {
        on!(self, s => GroupStore::group_get(s, id, deadline).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn group_members(
        &self,
        id: String,
        after: Option<String>,
        limit: usize,
        now: i64,
        deadline: Deadline,
    ) -> StoreResult<(Vec<groups::MemberRow>, bool)> {
        on!(self, s => GroupStore::group_members(s, id, after, limit, now, deadline).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn groups_of_users(
        &self,
        users: Vec<String>,
        after: Option<String>,
        limit: usize,
        now: i64,
        deadline: Deadline,
    ) -> StoreResult<GroupsOfUsers> {
        on!(self, s => GroupStore::groups_of_users(s, users, after, limit, now, deadline).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn groups_journal_bounds(&self, deadline: Deadline) -> StoreResult<(i64, Option<i64>)> {
        on!(self, s => GroupStore::groups_journal_bounds(s, deadline).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn groups_projection_snapshot(
        &self,
        vocabulary: Vec<String>,
        after: Option<String>,
        limit: usize,
        now: i64,
        deadline: Deadline,
    ) -> StoreResult<(Vec<groups::SnapshotEntry>, bool)> {
        on!(self, s => GroupStore::groups_projection_snapshot(s, vocabulary, after, limit, now, deadline).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn groups_projection_changes(
        &self,
        vocabulary: Vec<String>,
        after: i64,
        limit: usize,
        deadline: Deadline,
    ) -> StoreResult<Result<groups::JournalPage, groups::RevisionLost>> {
        on!(self, s => GroupStore::groups_projection_changes(s, vocabulary, after, limit, deadline).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn groups_sync_batch(
        &self,
        provider: String,
        interval_secs: u64,
        batch: usize,
        deadline: Deadline,
    ) -> StoreResult<Option<Vec<(String, String)>>> {
        on!(self, s => GroupStore::groups_sync_batch(s, provider, interval_secs, batch, deadline).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn groups_sync_result(
        &self,
        provider: String,
        error: Option<&'static str>,
        deadline: Deadline,
    ) -> StoreResult<()> {
        on!(self, s => GroupStore::groups_sync_result(s, provider, error, deadline).await)
    }
}

#[async_trait]
impl SubjectDirectoryStore for AppStore {
    #[allow(clippy::too_many_arguments)]
    async fn admin_directory_rows(
        &self,
        users: Vec<String>,
        deadline: Deadline,
    ) -> StoreResult<std::collections::BTreeMap<String, directory::DirectoryRow>> {
        on!(self, s => SubjectDirectoryStore::admin_directory_rows(s, users, deadline).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn admin_ledger_after(
        &self,
        after: i64,
        limit: usize,
        deadline: Deadline,
    ) -> StoreResult<Vec<directory::LedgerRow>> {
        on!(self, s => SubjectDirectoryStore::admin_ledger_after(s, after, limit, deadline).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn admin_ledger_at(
        &self,
        positions: Vec<i64>,
        deadline: Deadline,
    ) -> StoreResult<std::collections::BTreeMap<i64, String>> {
        on!(self, s => SubjectDirectoryStore::admin_ledger_at(s, positions, deadline).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn admin_ledger_head(&self, deadline: Deadline) -> StoreResult<i64> {
        on!(self, s => SubjectDirectoryStore::admin_ledger_head(s, deadline).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn admin_outbox_head(
        &self,
        deadline: Deadline,
    ) -> StoreResult<directory::OutboxPosition> {
        on!(self, s => SubjectDirectoryStore::admin_outbox_head(s, deadline).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn admin_feed_changes(
        &self,
        after: directory::OutboxPosition,
        limit: usize,
        groups: bool,
        workloads: bool,
        deadline: Deadline,
    ) -> StoreResult<Result<directory::StatusPage, directory::PositionLost>> {
        on!(self, s => SubjectDirectoryStore::admin_feed_changes(s, after, limit, groups, workloads, deadline).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn admin_live_handle(
        &self,
        session: String,
        host: String,
        deadline: Deadline,
    ) -> StoreResult<Option<HandleRow>> {
        on!(self, s => SubjectDirectoryStore::admin_live_handle(s, session, host, deadline).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn admin_totp_active(&self, user: String, deadline: Deadline) -> StoreResult<bool> {
        on!(self, s => SubjectDirectoryStore::admin_totp_active(s, user, deadline).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn admin_human_realm(&self, deadline: Deadline) -> StoreResult<Option<String>> {
        on!(self, s => SubjectDirectoryStore::admin_human_realm(s, deadline).await)
    }
    #[allow(clippy::too_many_arguments)]
    async fn admin_human_subjects(
        &self,
        issuer: String,
        users: Vec<String>,
        deadline: Deadline,
    ) -> StoreResult<std::collections::BTreeMap<String, String>> {
        on!(self, s => SubjectDirectoryStore::admin_human_subjects(s, issuer, users, deadline).await)
    }
}
