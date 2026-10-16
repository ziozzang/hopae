//! `CoreStore` (ADR-0020 slice 1) for SQLite: delegation to the existing
//! traits, plus the two outbox reads the contract adds.
use async_trait::async_trait;

use super::Store;
use super::rows::{self, EVENT_COLS, cols};
use crate::crypto::{Digest, Timestamp};
use crate::event::types::{Event, Reason};
use crate::identity::types::{NormalizedEmail, UserId};
use crate::policy::types::Host;
use crate::provider::types::ProviderId;
use crate::session::types::SessionId;
use crate::store::core::{
    AdminStore, ConsoleStore, CoreStore, GroupStore, GroupsOfUsers, HandoffStore, NonceStore,
    SubjectDirectoryStore, nonce_key_ok,
};
use crate::store::types::*;
use crate::store::{Deadline, Directory, Events, Sessions, StoreError, StoreResult};

#[async_trait]
impl CoreStore for Store {
    fn backend(&self) -> &'static str {
        "sqlite"
    }
    async fn ensure_provider(&self, row: ProviderRow) -> StoreResult<()> {
        Directory::import_providers(self, vec![row], None, vec![])
            .await
            .map(|_| ())
    }
    async fn user(&self, id: &UserId) -> StoreResult<Option<User>> {
        Directory::user(self, id).await
    }
    async fn user_authz(&self, id: &UserId) -> StoreResult<Option<UserAuthz>> {
        Directory::user_authz(self, id).await
    }
    async fn user_by_email(&self, email: &NormalizedEmail) -> StoreResult<Option<User>> {
        Directory::user_by_email(self, email).await
    }
    async fn identity(
        &self,
        provider: &ProviderId,
        subject: &str,
    ) -> StoreResult<Option<IdentityRow>> {
        Directory::identity(self, provider, subject).await
    }
    async fn create_user(
        &self,
        user: NewUser,
        identity: NewIdentity,
        events: Vec<Event>,
    ) -> StoreResult<User> {
        Directory::create_user(self, user, identity, events).await
    }
    async fn link_identity(
        &self,
        user: &UserId,
        identity: NewIdentity,
        events: Vec<Event>,
    ) -> StoreResult<()> {
        Directory::link_identity(self, user, identity, events).await
    }
    async fn touch_identity(
        &self,
        provider: &ProviderId,
        subject: &str,
        seen: &NewIdentity,
        at: Timestamp,
    ) -> StoreResult<()> {
        Directory::touch_identity(self, provider, subject, seen, at).await
    }
    async fn create_session(&self, req: CreateSession) -> StoreResult<()> {
        Sessions::create_session(self, req).await
    }
    async fn session(&self, id: &SessionId) -> StoreResult<Option<SessionRow>> {
        Sessions::session(self, id).await
    }
    async fn lookup_handle(
        &self,
        handle_sha256: &Digest,
        host: &Host,
    ) -> StoreResult<Option<HandleView>> {
        Sessions::lookup_handle(self, handle_sha256, host).await
    }
    async fn touch_handle(&self, handle_sha256: &Digest, at: Timestamp) -> StoreResult<()> {
        Sessions::touch_handle(self, handle_sha256, at).await
    }
    async fn revoke_handle(
        &self,
        handle_sha256: &Digest,
        reason: Reason,
        at: Timestamp,
        events: Vec<Event>,
    ) -> StoreResult<()> {
        Sessions::revoke_handle(self, handle_sha256, reason, at, events).await
    }
    async fn terminate_session(
        &self,
        id: &SessionId,
        reason: Reason,
        at: Timestamp,
        events: Vec<Event>,
    ) -> StoreResult<()> {
        Sessions::terminate_session(self, id, reason, at, events).await
    }
    async fn append_required(&self, events: Vec<Event>) -> StoreResult<()> {
        Events::append_required(self, events).await
    }
    async fn recent_events(&self, limit: usize) -> StoreResult<Vec<Event>> {
        let limit = i64::try_from(limit.min(1000)).unwrap_or(1000);
        self.read("recent_events", move |c| {
            let sql = format!(
                "SELECT {} FROM events ORDER BY at DESC, event_id DESC LIMIT ?1",
                cols("", EVENT_COLS)
            );
            let mut st = c.prepare(&sql)?;
            let mut q = st.query([limit])?;
            let mut out = Vec::new();
            while let Some(r) = q.next()? {
                out.push(rows::event(r, 0)?);
            }
            out.reverse();
            Ok(out)
        })
        .await
    }
    async fn pending_deliveries(&self, event: &str) -> StoreResult<Vec<String>> {
        let event = event.to_owned();
        self.read("pending_deliveries", move |c| {
            let mut st = c.prepare(
                "SELECT sink FROM event_deliveries WHERE event_id=?1 AND state='pending' ORDER BY sink",
            )?;
            let rows = st
                .query_map([event], |r| r.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(rows)
        })
        .await
    }
    async fn config_generation(&self) -> StoreResult<u64> {
        Directory::config_generation(self).await
    }
    async fn bump_config_generation(&self) -> StoreResult<u64> {
        Directory::bump_config_generation(self).await
    }
}

#[async_trait]
impl HandoffStore for Store {
    async fn create_transaction_capped(
        &self,
        txn: NewTransaction,
        events: Vec<Event>,
        since: Timestamp,
        cap: Option<u32>,
        max_rows: u32,
    ) -> StoreResult<Admission> {
        Sessions::create_transaction_capped(self, txn, events, since, cap, max_rows).await
    }
    async fn transaction(&self, d: &Digest) -> StoreResult<Option<TransactionRow>> {
        Sessions::transaction(self, d).await
    }
    async fn transaction_by_state(&self, d: &Digest) -> StoreResult<Option<TransactionRow>> {
        Sessions::transaction_by_state(self, d).await
    }
    async fn bind_transaction(&self, d: &Digest, b: TransactionBinding) -> StoreResult<()> {
        Sessions::bind_transaction(self, d, b).await
    }
    async fn use_retry(&self, d: &Digest, at: Timestamp) -> StoreResult<bool> {
        Sessions::use_retry(self, d, at).await
    }
    async fn consume_transaction(
        &self,
        d: &Digest,
        reason: Reason,
        at: Timestamp,
        events: Vec<Event>,
    ) -> StoreResult<bool> {
        Sessions::consume_transaction(self, d, reason, at, events).await
    }
    async fn mint_handoff_code(&self, code: HandoffCodeRow, events: Vec<Event>) -> StoreResult<()> {
        Sessions::mint_handoff_code(self, code, events).await
    }
    async fn redeem_handoff_code(
        &self,
        req: RedeemRequest,
        ok: Vec<Event>,
        fail: Vec<Event>,
    ) -> StoreResult<RedeemOutcome> {
        Sessions::redeem_handoff_code(self, req, ok, fail).await
    }
    async fn count_transactions_since(
        &self,
        ip: std::net::IpAddr,
        since: Timestamp,
    ) -> StoreResult<u32> {
        Sessions::count_transactions_since(self, ip, since).await
    }
    async fn count_handoff_failures_since(
        &self,
        ip: std::net::IpAddr,
        since: Timestamp,
    ) -> StoreResult<u32> {
        Sessions::count_handoff_failures_since(self, ip, since).await
    }
}

#[async_trait]
impl AdminStore for Store {
    async fn admin_grant(
        &self,
        user: &UserId,
        deadline: Deadline,
    ) -> StoreResult<Option<AdminGrant>> {
        Directory::admin_grant(self, user, deadline).await
    }
    async fn admin_grants(&self, all: bool, deadline: Deadline) -> StoreResult<Vec<AdminGrant>> {
        Directory::admin_grants(self, all, deadline).await
    }
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
        Directory::grant_admin(
            self,
            user,
            role,
            managed_by,
            source_email,
            by,
            note,
            at,
            event,
        )
        .await
    }
    async fn revoke_admin(
        &self,
        user: &UserId,
        by: &str,
        managed_by: GrantManagedBy,
        at: Timestamp,
        event: Event,
    ) -> StoreResult<bool> {
        Directory::revoke_admin(self, user, by, managed_by, at, event).await
    }
    async fn set_user_status(
        &self,
        actor: &Actor,
        policy: &ActorPolicy,
        user: &UserId,
        status: UserStatus,
        deadline: Deadline,
        admin_event: Event,
        mk: &(dyn for<'a> Fn(&'a SessionRow) -> Event + Sync),
    ) -> StoreResult<(bool, u32)> {
        Directory::set_user_status(self, actor, policy, user, status, deadline, admin_event, mk)
            .await
    }
    async fn admin_terminate_session(
        &self,
        actor: &Actor,
        policy: &ActorPolicy,
        id: &SessionId,
        deadline: Deadline,
        admin_event: Event,
        session_event: Event,
    ) -> StoreResult<bool> {
        Sessions::admin_terminate_session(
            self,
            actor,
            policy,
            id,
            deadline,
            admin_event,
            session_event,
        )
        .await
    }
}

/// SQLite keeps replay ledgers in `meta` (`nonce:<scope>:<nonce>` → expiry),
/// as the receipt replay index already does; the single writer serializes.
#[async_trait]
impl NonceStore for Store {
    async fn admit_nonce(
        &self,
        scope: &str,
        nonce: &str,
        expires_at: Timestamp,
        now: Timestamp,
        capacity: u32,
    ) -> StoreResult<bool> {
        if !nonce_key_ok(scope, nonce) {
            return Err(StoreError::Conflict("invalid nonce key"));
        }
        let key = format!("nonce:{scope}:{nonce}");
        let prefix = format!("nonce:{scope}:");
        self.write("admit_nonce", move |env| {
            let shared = env.shared.clone();
            let tx = env.begin()?;
            // Prune expired entries of this scope (value = expiry seconds).
            tx.execute(
                "DELETE FROM meta WHERE key >= ?1 AND key < ?2 AND CAST(value AS INTEGER) <= ?3",
                rusqlite::params![prefix, format!("{prefix}\u{10FFFF}"), now.secs()],
            )?;
            let live: i64 = tx.query_row(
                "SELECT count(*) FROM meta WHERE key >= ?1 AND key < ?2",
                rusqlite::params![prefix, format!("{prefix}\u{10FFFF}")],
                |r| r.get(0),
            )?;
            if live >= i64::from(capacity) {
                return Ok(false);
            }
            let n = tx.execute(
                "INSERT OR IGNORE INTO meta (key, value) VALUES (?1, ?2)",
                rusqlite::params![key, expires_at.secs().to_string()],
            )?;
            super::commit(tx, &shared, None)?;
            Ok(n == 1)
        })
        .await
    }
}

#[async_trait]
impl ConsoleStore for Store {
    async fn list_users(
        &self,
        q: UsersQuery,
        deadline: Deadline,
    ) -> StoreResult<Page<UserSummary>> {
        Directory::list_users(self, q, deadline).await
    }
    async fn user_detail(
        &self,
        user: &UserId,
        now: Timestamp,
        deadline: Deadline,
    ) -> StoreResult<Option<UserDetail>> {
        Directory::user_detail(self, user, now, deadline).await
    }
    async fn list_live_sessions(
        &self,
        q: SessionsQuery,
        deadline: Deadline,
    ) -> StoreResult<Page<SessionSummary>> {
        Sessions::list_live_sessions(self, q, deadline).await
    }
    async fn session_summary(
        &self,
        id: &SessionId,
        deadline: Deadline,
    ) -> StoreResult<Option<(SessionSummary, Vec<HandleRow>)>> {
        Sessions::session_summary(self, id, deadline).await
    }
}

#[async_trait]
impl GroupStore for Store {
    async fn groups_admin_edit(
        &self,
        actor: &Actor,
        policy: &ActorPolicy,
        edit: super::groups::Edit,
        settings: super::groups::WritePolicy,
        template: Event,
        deadline: Deadline,
    ) -> StoreResult<super::groups::Cas<super::groups::GroupRow>> {
        Store::groups_admin_edit(self, actor, policy, edit, settings, template, deadline).await
    }
    async fn groups_sync_user(
        &self,
        provider: ProviderId,
        source: crate::groups::Source,
        user: UserId,
        asserted: Vec<crate::groups::config::Mapped>,
        grace_secs: u64,
        settings: super::groups::WritePolicy,
        template: Event,
        deadline: Deadline,
    ) -> StoreResult<super::groups::SyncReport> {
        Store::groups_sync_user(
            self, provider, source, user, asserted, grace_secs, settings, template, deadline,
        )
        .await
    }
    async fn groups_maintenance(
        &self,
        grace: std::collections::HashMap<String, u64>,
        stale_before: i64,
        suspend_before: i64,
        journal_before: i64,
        settings: super::groups::WritePolicy,
        template: Event,
        deadline: Deadline,
    ) -> StoreResult<super::groups::MaintenanceReport> {
        Store::groups_maintenance(
            self,
            grace,
            stale_before,
            suspend_before,
            journal_before,
            settings,
            template,
            deadline,
        )
        .await
    }
    async fn groups_list(
        &self,
        q: Option<String>,
        source: Option<crate::groups::Source>,
        provider: Option<String>,
        include_deleted: bool,
        after: Option<(i64, String)>,
        limit: usize,
        deadline: Deadline,
    ) -> StoreResult<(Vec<super::groups::GroupRow>, bool)> {
        Store::groups_list(
            self,
            q,
            source,
            provider,
            include_deleted,
            after,
            limit,
            deadline,
        )
        .await
    }
    async fn group_get(
        &self,
        id: String,
        deadline: Deadline,
    ) -> StoreResult<Option<super::groups::GroupRow>> {
        Store::group_get(self, id, deadline).await
    }
    async fn group_members(
        &self,
        id: String,
        after: Option<String>,
        limit: usize,
        now: i64,
        deadline: Deadline,
    ) -> StoreResult<(Vec<super::groups::MemberRow>, bool)> {
        Store::group_members(self, id, after, limit, now, deadline).await
    }
    async fn groups_of_users(
        &self,
        users: Vec<String>,
        after: Option<String>,
        limit: usize,
        now: i64,
        deadline: Deadline,
    ) -> StoreResult<GroupsOfUsers> {
        Store::groups_of_users(self, users, after, limit, now, deadline).await
    }
    async fn groups_journal_bounds(&self, deadline: Deadline) -> StoreResult<(i64, Option<i64>)> {
        Store::groups_journal_bounds(self, deadline).await
    }
    async fn groups_projection_snapshot(
        &self,
        vocabulary: Vec<String>,
        after: Option<String>,
        limit: usize,
        now: i64,
        deadline: Deadline,
    ) -> StoreResult<(Vec<super::groups::SnapshotEntry>, bool)> {
        Store::groups_projection_snapshot(self, vocabulary, after, limit, now, deadline).await
    }
    async fn groups_projection_changes(
        &self,
        vocabulary: Vec<String>,
        after: i64,
        limit: usize,
        deadline: Deadline,
    ) -> StoreResult<Result<super::groups::JournalPage, super::groups::RevisionLost>> {
        Store::groups_projection_changes(self, vocabulary, after, limit, deadline).await
    }
    async fn groups_sync_batch(
        &self,
        provider: String,
        interval_secs: u64,
        batch: usize,
        deadline: Deadline,
    ) -> StoreResult<Option<Vec<(String, String)>>> {
        Store::groups_sync_batch(self, provider, interval_secs, batch, deadline).await
    }
    async fn groups_sync_result(
        &self,
        provider: String,
        error: Option<&'static str>,
        deadline: Deadline,
    ) -> StoreResult<()> {
        Store::groups_sync_result(self, provider, error, deadline).await
    }
}

#[async_trait]
impl SubjectDirectoryStore for Store {
    async fn admin_directory_rows(
        &self,
        users: Vec<String>,
        deadline: Deadline,
    ) -> StoreResult<std::collections::BTreeMap<String, super::subject_directory::DirectoryRow>>
    {
        Store::admin_directory_rows(self, users, deadline).await
    }
    async fn admin_ledger_after(
        &self,
        after: i64,
        limit: usize,
        deadline: Deadline,
    ) -> StoreResult<Vec<super::subject_directory::LedgerRow>> {
        Store::admin_ledger_after(self, after, limit, deadline).await
    }
    async fn admin_ledger_at(
        &self,
        positions: Vec<i64>,
        deadline: Deadline,
    ) -> StoreResult<std::collections::BTreeMap<i64, String>> {
        Store::admin_ledger_at(self, positions, deadline).await
    }
    async fn admin_ledger_head(&self, deadline: Deadline) -> StoreResult<i64> {
        Store::admin_ledger_head(self, deadline).await
    }
    async fn admin_outbox_head(
        &self,
        deadline: Deadline,
    ) -> StoreResult<super::subject_directory::OutboxPosition> {
        Store::admin_outbox_head(self, deadline).await
    }
    async fn admin_feed_changes(
        &self,
        after: super::subject_directory::OutboxPosition,
        limit: usize,
        groups: bool,
        deadline: Deadline,
    ) -> StoreResult<
        Result<super::subject_directory::StatusPage, super::subject_directory::PositionLost>,
    > {
        Store::admin_feed_changes(self, after, limit, groups, deadline).await
    }
    async fn admin_live_handle(
        &self,
        session: String,
        host: String,
        deadline: Deadline,
    ) -> StoreResult<Option<HandleRow>> {
        Store::admin_live_handle(self, session, host, deadline).await
    }
    async fn admin_totp_active(&self, user: String, deadline: Deadline) -> StoreResult<bool> {
        Store::admin_totp_active(self, user, deadline).await
    }
}
