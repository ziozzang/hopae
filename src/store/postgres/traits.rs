//! The full `Directory` and `Sessions` store traits on PostgreSQL (ADR-0020
//! slice 5): the methods earlier slices did not cover, plus delegations to
//! the slice contracts (`CoreStore`, `HandoffStore`, `AdminStore`,
//! `ConsoleStore`) for the rest, so the application can hold a PostgreSQL
//! store wherever it holds these traits.
use std::collections::HashSet;
use std::net::IpAddr;
use std::time::Duration;

use async_trait::async_trait;
use deadpool_postgres::Transaction;
use tokio_postgres::Row;

use super::admin::{check_deadline, deadline_err, deadline_ms};
use super::write::{self, factors_json};
use super::{
    HANDLE_COLS, IDENTITY_COLS, PgStore, SESSION_COLS, USER_COLS, corrupt, handle, i64_of,
    identity, json, opt_ts, pg, require_provider_live, session, snapshot_json, user,
};
use crate::crypto::{Digest, Timestamp};
use crate::event::types::{Event, EventKind, Reason, reasons};
use crate::identity::types::{NormalizedEmail, UserId};
use crate::policy::types::Host;
use crate::provider::types::{ProviderId, ProviderKind};
use crate::session::types::{FactorEntry, SessionId};
use crate::store::core::{AdminStore, ConsoleStore, CoreStore, HandoffStore};
use crate::store::types::*;
use crate::store::{Deadline, Directory, Sessions, StoreError, StoreResult};

/// `pg_advisory_xact_lock` key: grant writes and the file import serialize.
pub(super) const GRANTS_LOCK: i64 = 7060;

const PROVIDER_COLS: &str = "provider_id, kind, display_name, enabled, managed_by, deleted_at, sort_order, config, client_secret_env, allowed_email_domains, authoritative_domains, auto_link, trust_email";

fn provider_row(r: &Row) -> StoreResult<ProviderRow> {
    Ok(ProviderRow {
        provider_id: ProviderId::new(r.get::<_, String>(0)),
        kind: ProviderKind::parse(&r.get::<_, String>(1))
            .ok_or_else(|| corrupt("providers.kind"))?,
        display_name: r.get(2),
        enabled: r.get(3),
        managed_by: ManagedBy::parse(&r.get::<_, String>(4))
            .ok_or_else(|| corrupt("providers.managed_by"))?,
        deleted_at: opt_ts(r, 5),
        sort_order: r.get(6),
        config: json(r, 7, "providers.config")?,
        client_secret_env: r.get(8),
        allowed_email_domains: json(r, 9, "providers.allowed_email_domains")?,
        authoritative_domains: json(r, 10, "providers.authoritative_domains")?,
        auto_link: r.get(11),
        trust_email: r.get(12),
    })
}

/// Run `f` but give up at `deadline` (a read that would answer late answers
/// `Unavailable("deadline")`).
async fn within<T>(
    deadline: Deadline,
    f: impl std::future::Future<Output = StoreResult<T>>,
) -> StoreResult<T> {
    check_deadline(deadline)?;
    let left = deadline
        .0
        .saturating_duration_since(std::time::Instant::now());
    match tokio::time::timeout(left, f).await {
        Ok(out) => out.map_err(deadline_err),
        Err(_) => Err(StoreError::Unavailable("deadline".into())),
    }
}

async fn write_provider(
    tx: &Transaction<'_>,
    r: &ProviderRow,
    now: i64,
    insert: bool,
) -> StoreResult<()> {
    let config = serde_json::to_string(&r.config).map_err(|_| corrupt("providers.config"))?;
    let allowed = serde_json::to_string(&r.allowed_email_domains)
        .map_err(|_| corrupt("providers.allowed_email_domains"))?;
    let authoritative = serde_json::to_string(&r.authoritative_domains)
        .map_err(|_| corrupt("providers.authoritative_domains"))?;
    let sql = if insert {
        "INSERT INTO providers (provider_id, kind, display_name, enabled, managed_by, deleted_at, sort_order, config, client_secret_env, allowed_email_domains, authoritative_domains, auto_link, trust_email, created_at, updated_at) \
         VALUES ($1,$2,$3,$4,'file',NULL,$5,$6,$7,$8,$9,$10,$11,$12,$12)"
    } else {
        "UPDATE providers SET kind=$2, display_name=$3, enabled=$4, managed_by='file', deleted_at=NULL, sort_order=$5, config=$6, client_secret_env=$7, \
         allowed_email_domains=$8, authoritative_domains=$9, auto_link=$10, trust_email=$11, updated_at=$12 WHERE provider_id=$1"
    };
    tx.execute(
        sql,
        &[
            &r.provider_id.as_str(),
            &r.kind.as_str(),
            &r.display_name,
            &r.enabled,
            &r.sort_order,
            &config,
            &r.client_secret_env,
            &allowed,
            &authoritative,
            &r.auto_link,
            &r.trust_email,
            &now,
        ],
    )
    .await
    .map_err(pg)?;
    Ok(())
}

async fn grant_row(tx: &Transaction<'_>, user: &str) -> StoreResult<Option<AdminGrant>> {
    tx.query_opt(
        &format!(
            "SELECT {} FROM admin_grants WHERE user_id=$1",
            super::admin::GRANT_COLS
        ),
        &[&user],
    )
    .await
    .map_err(pg)?
    .map(|r| super::admin::grant(&r))
    .transpose()
}

async fn grants_by_email(tx: &Transaction<'_>, email: &str) -> StoreResult<Vec<AdminGrant>> {
    tx.query(
        &format!(
            "SELECT {} FROM admin_grants WHERE source_email=$1 ORDER BY user_id",
            super::admin::GRANT_COLS
        ),
        &[&email],
    )
    .await
    .map_err(pg)?
    .iter()
    .map(super::admin::grant)
    .collect()
}

enum Found {
    None,
    One(AdminGrant),
    Ambiguous(Vec<AdminGrant>),
}

fn entry_email(key: &SeedKey) -> Option<&NormalizedEmail> {
    match key {
        SeedKey::ByEmail(e) | SeedKey::Both { email: e, .. } => Some(e),
        SeedKey::ById(_) => None,
    }
}

fn entry_user(key: &SeedKey) -> Option<&UserId> {
    match key {
        SeedKey::ById(u) | SeedKey::Both { user_id: u, .. } => Some(u),
        SeedKey::ByEmail(_) => None,
    }
}

type MkGrantEvent<'a> =
    &'a (dyn for<'b> Fn(&'b UserId, EventKind, Option<AdminRole>, AdminRole, bool) -> Event + Sync);

/// The ADR-0016 file rule for `admin.users[]`, as SQLite's `Import`.
struct Import<'a> {
    store: &'a PgStore,
    tx: &'a Transaction<'a>,
    mk: MkGrantEvent<'a>,
    deadline: Deadline,
    at: Timestamp,
    report: GrantImportReport,
    present: HashSet<String>,
}

impl Import<'_> {
    async fn event(
        &self,
        user: &UserId,
        kind: EventKind,
        prev: Option<AdminRole>,
        role: AdminRole,
        forced: bool,
    ) -> StoreResult<()> {
        let ev = (self.mk)(user, kind, prev, role, forced);
        self.store.insert_events(self.tx, &[ev]).await
    }

    fn skip(&mut self, e: &SeedEntry, why: &'static str) {
        self.report.skipped.push((e.index, why));
    }

    async fn run(&mut self, entries: &[SeedEntry], force: Option<&ForceTarget>) -> StoreResult<()> {
        let mut found = Vec::with_capacity(entries.len());
        for e in entries {
            found.push(match &e.key {
                SeedKey::ById(u) | SeedKey::Both { user_id: u, .. } => {
                    match grant_row(self.tx, u.as_str()).await? {
                        Some(g) => Found::One(g),
                        None => Found::None,
                    }
                }
                SeedKey::ByEmail(em) => {
                    let mut rows = grants_by_email(self.tx, em.as_str()).await?;
                    match rows.len() {
                        0 => Found::None,
                        1 => Found::One(rows.remove(0)),
                        _ => Found::Ambiguous(rows),
                    }
                }
            });
        }
        let forced_user: Option<UserId> = match force {
            None => None,
            Some(ForceTarget::ById(u)) => Some(u.clone()),
            Some(ForceTarget::ByEmail(em)) => {
                let rows = grants_by_email(self.tx, em.as_str()).await?;
                if rows.len() > 1 {
                    return Err(StoreError::Conflict(
                        "ambiguous binding; use --force <user_id>",
                    ));
                }
                rows.into_iter().next().map(|g| g.user_id)
            }
        };
        if let Some(f) = force {
            let named = entries.iter().zip(&found).any(|(e, m)| {
                let by_key = match f {
                    ForceTarget::ById(u) => entry_user(&e.key) == Some(u),
                    ForceTarget::ByEmail(em) => entry_email(&e.key) == Some(em),
                };
                let by_row = match m {
                    Found::One(g) => Some(&g.user_id) == forced_user.as_ref(),
                    Found::Ambiguous(rows) => rows
                        .iter()
                        .any(|g| Some(&g.user_id) == forced_user.as_ref()),
                    Found::None => false,
                };
                by_key || by_row
            });
            if !named {
                return Err(StoreError::Conflict(
                    "force names an entry the file does not list",
                ));
            }
        }
        check_deadline(self.deadline)?;
        let mut unmatched = Vec::new();
        for (e, m) in entries.iter().zip(found) {
            match m {
                Found::Ambiguous(rows) => {
                    for g in &rows {
                        self.present.insert(g.user_id.to_string());
                    }
                    match rows
                        .into_iter()
                        .find(|g| Some(&g.user_id) == forced_user.as_ref())
                    {
                        Some(g) => {
                            self.apply_matched(e, g, forced_user.as_ref(), false)
                                .await?
                        }
                        None => self.skip(e, skip::EMAIL_BINDING_AMBIGUOUS),
                    }
                }
                Found::One(g) => self.apply_matched(e, g, forced_user.as_ref(), true).await?,
                Found::None => unmatched.push(e),
            }
        }
        check_deadline(self.deadline)?;
        for e in unmatched {
            self.resolve_and_insert(e, forced_user.as_ref()).await?;
        }
        check_deadline(self.deadline)?;
        let stale: Vec<(String, String)> = self
            .tx
            .query("SELECT user_id, role FROM admin_grants WHERE managed_by = 'file' AND revoked_at IS NULL ORDER BY user_id", &[])
            .await
            .map_err(pg)?
            .iter()
            .map(|r| (r.get(0), r.get(1)))
            .collect();
        for (uid, role) in stale {
            if self.present.contains(&uid) {
                continue;
            }
            let role = AdminRole::parse(&role).ok_or_else(|| corrupt("admin_grants.role"))?;
            self.tx
                .execute("UPDATE admin_grants SET revoked_at = $2, revoked_by = 'file' WHERE user_id = $1", &[&uid, &self.at.secs()])
                .await
                .map_err(pg)?;
            let user = UserId::new(uid);
            self.event(&user, EventKind::AdminRevoke, Some(role), role, false)
                .await?;
            self.report.revoked.push(user);
        }
        Ok(())
    }

    async fn apply_matched(
        &mut self,
        e: &SeedEntry,
        g: AdminGrant,
        forced_user: Option<&UserId>,
        check_rebind: bool,
    ) -> StoreResult<()> {
        self.present.insert(g.user_id.to_string());
        if check_rebind && let SeedKey::ByEmail(em) = &e.key {
            let holder = self
                .tx
                .query_opt(
                    "SELECT user_id FROM users WHERE primary_email = $1",
                    &[&em.as_str()],
                )
                .await
                .map_err(pg)?
                .map(|r| r.get::<_, String>(0));
            if let Some(h) = holder.filter(|h| h != g.user_id.as_str()) {
                self.report
                    .rebound_warnings
                    .push((e.index, g.user_id.clone(), UserId::new(h)));
            }
        }
        if let SeedKey::Both { user_id, email } = &e.key {
            let primary = self
                .tx
                .query_opt(
                    "SELECT primary_email FROM users WHERE user_id = $1",
                    &[&user_id.as_str()],
                )
                .await
                .map_err(pg)?
                .and_then(|r| r.get::<_, Option<String>>(0));
            if primary.as_deref() != Some(email.as_str()) {
                self.skip(e, skip::USER_EMAIL_MISMATCH);
                return Ok(());
            }
        }
        if forced_user == Some(&g.user_id) {
            self.tx
                .execute(
                    "UPDATE admin_grants SET role = $2, note = $3, managed_by = 'file', granted_at = $4, granted_by = 'file', revoked_at = NULL, revoked_by = NULL WHERE user_id = $1",
                    &[&g.user_id.as_str(), &e.role.as_str(), &e.note, &self.at.secs()],
                )
                .await
                .map_err(pg)?;
            self.event(
                &g.user_id,
                EventKind::AdminGrant,
                Some(g.role),
                e.role,
                true,
            )
            .await?;
            self.report.forced.push(g.user_id);
            return Ok(());
        }
        if g.revoked_at.is_some() {
            self.skip(e, skip::REVOKED_AT_RUN_TIME);
        } else if g.managed_by == GrantManagedBy::Api {
            self.skip(e, skip::CHANGED_AT_RUN_TIME);
        } else if g.role == e.role && g.note == e.note {
            self.report.unchanged.push(g.user_id);
        } else {
            self.tx
                .execute(
                    "UPDATE admin_grants SET role = $2, note = $3 WHERE user_id = $1",
                    &[&g.user_id.as_str(), &e.role.as_str(), &e.note],
                )
                .await
                .map_err(pg)?;
            self.event(
                &g.user_id,
                EventKind::AdminGrant,
                Some(g.role),
                e.role,
                false,
            )
            .await?;
            self.report.updated.push(g.user_id);
        }
        Ok(())
    }

    async fn resolve_and_insert(
        &mut self,
        e: &SeedEntry,
        forced_user: Option<&UserId>,
    ) -> StoreResult<()> {
        let (sql, arg) = match &e.key {
            SeedKey::ById(u) | SeedKey::Both { user_id: u, .. } => (
                "SELECT user_id, primary_email, email_verified, email_authoritative, status FROM users WHERE user_id = $1",
                u.as_str(),
            ),
            SeedKey::ByEmail(em) => (
                "SELECT user_id, primary_email, email_verified, email_authoritative, status FROM users WHERE primary_email = $1",
                em.as_str(),
            ),
        };
        let Some(u) = self.tx.query_opt(sql, &[&arg]).await.map_err(pg)? else {
            self.skip(e, skip::NO_SUCH_USER);
            return Ok(());
        };
        let (id, primary, verified, authoritative, active): (
            String,
            Option<String>,
            bool,
            bool,
            bool,
        ) = (
            u.get(0),
            u.get(1),
            u.get(2),
            u.get(3),
            u.get::<_, String>(4) == "active",
        );
        match &e.key {
            SeedKey::ByEmail(_) => {
                if !verified {
                    self.skip(e, skip::EMAIL_UNVERIFIED);
                    return Ok(());
                }
                if !authoritative {
                    self.skip(e, skip::EMAIL_NOT_AUTHORITATIVE);
                    return Ok(());
                }
            }
            SeedKey::Both { email, .. } => {
                if primary.as_deref() != Some(email.as_str()) {
                    self.skip(e, skip::USER_EMAIL_MISMATCH);
                    return Ok(());
                }
            }
            SeedKey::ById(_) => {}
        }
        if !active {
            self.skip(e, skip::USER_DISABLED);
            return Ok(());
        }
        if let Some(g) = grant_row(self.tx, &id).await? {
            if let SeedKey::ByEmail(em) = &e.key
                && g.source_email.is_none()
            {
                self.tx
                    .execute(
                        "UPDATE admin_grants SET source_email = $2 WHERE user_id = $1 AND source_email IS NULL",
                        &[&g.user_id.as_str(), &em.as_str()],
                    )
                    .await
                    .map_err(pg)?;
            }
            return Box::pin(self.apply_matched(e, g, forced_user, false)).await;
        }
        let user = UserId::new(id);
        self.tx
            .execute(
                "INSERT INTO admin_grants (user_id, role, managed_by, source_email, granted_at, granted_by, note) VALUES ($1, $2, 'file', $3, $4, 'file', $5)",
                &[&user.as_str(), &e.role.as_str(), &entry_email(&e.key).map(|x| x.as_str()), &self.at.secs(), &e.note],
            )
            .await
            .map_err(pg)?;
        self.event(&user, EventKind::AdminGrant, None, e.role, false)
            .await?;
        self.present.insert(user.to_string());
        self.report.inserted.push(user);
        Ok(())
    }
}

#[async_trait]
impl Directory for PgStore {
    async fn user(&self, id: &UserId) -> StoreResult<Option<User>> {
        CoreStore::user(self, id).await
    }
    async fn user_within(&self, id: &UserId, deadline: Deadline) -> StoreResult<Option<User>> {
        within(deadline, CoreStore::user(self, id)).await
    }
    async fn user_authz(&self, id: &UserId) -> StoreResult<Option<UserAuthz>> {
        CoreStore::user_authz(self, id).await
    }
    async fn identity(
        &self,
        provider: &ProviderId,
        subject: &str,
    ) -> StoreResult<Option<IdentityRow>> {
        CoreStore::identity(self, provider, subject).await
    }
    async fn user_by_email(&self, email: &NormalizedEmail) -> StoreResult<Option<User>> {
        CoreStore::user_by_email(self, email).await
    }
    async fn create_user(
        &self,
        user: NewUser,
        identity: NewIdentity,
        events: Vec<Event>,
    ) -> StoreResult<User> {
        CoreStore::create_user(self, user, identity, events).await
    }
    async fn link_identity(
        &self,
        user: &UserId,
        identity: NewIdentity,
        events: Vec<Event>,
    ) -> StoreResult<()> {
        CoreStore::link_identity(self, user, identity, events).await
    }
    async fn touch_identity(
        &self,
        provider: &ProviderId,
        subject: &str,
        seen: &NewIdentity,
        at: Timestamp,
    ) -> StoreResult<()> {
        CoreStore::touch_identity(self, provider, subject, seen, at).await
    }

    async fn providers(&self) -> StoreResult<Vec<ProviderRow>> {
        let client = self.client().await?;
        client
            .query(
                &format!("SELECT {PROVIDER_COLS} FROM providers ORDER BY sort_order, provider_id"),
                &[],
            )
            .await
            .map_err(pg)?
            .iter()
            .map(provider_row)
            .collect()
    }

    async fn import_providers(
        &self,
        from_file: Vec<ProviderRow>,
        force: Option<&ProviderId>,
        events: Vec<Event>,
    ) -> StoreResult<ImportReport> {
        if let Some(f) = force
            && !from_file.iter().any(|r| &r.provider_id == f)
        {
            return Err(StoreError::Conflict(
                "force names a provider the file does not list",
            ));
        }
        super::retry(|| async {
            let mut client = self.client().await?;
            let tx = self.begin(&mut client).await?;
            let now = self.now().secs();
            let mut report = ImportReport::default();
            for r in &from_file {
                let existing = tx
                    .query_opt("SELECT managed_by, deleted_at FROM providers WHERE provider_id=$1 FOR UPDATE", &[&r.provider_id.as_str()])
                    .await
                    .map_err(pg)?
                    .map(|row| (row.get::<_, String>(0), row.get::<_, Option<i64>>(1)));
                let id = r.provider_id.clone();
                let forced = force == Some(&id);
                match existing {
                    None => {
                        write_provider(&tx, r, now, true).await?;
                        report.inserted.push(id);
                    }
                    Some(_) if forced => {
                        write_provider(&tx, r, now, false).await?;
                        report.forced.push(id);
                    }
                    Some((_, Some(_))) => report.skipped_deleted.push(id),
                    Some((managed, None)) if managed == "file" => {
                        write_provider(&tx, r, now, false).await?;
                        report.updated.push(id);
                    }
                    Some(_) => report.skipped_api_managed.push(id),
                }
            }
            self.insert_events(&tx, &events).await?;
            tx.commit().await.map_err(pg)?;
            Ok(report)
        })
        .await
    }

    async fn bump_config_generation(&self) -> StoreResult<u64> {
        CoreStore::bump_config_generation(self).await
    }
    async fn config_generation(&self) -> StoreResult<u64> {
        CoreStore::config_generation(self).await
    }
    async fn admin_grant(
        &self,
        user: &UserId,
        deadline: Deadline,
    ) -> StoreResult<Option<AdminGrant>> {
        within(deadline, AdminStore::admin_grant(self, user, deadline)).await
    }
    async fn admin_grants(
        &self,
        include_revoked: bool,
        deadline: Deadline,
    ) -> StoreResult<Vec<AdminGrant>> {
        within(
            deadline,
            AdminStore::admin_grants(self, include_revoked, deadline),
        )
        .await
    }

    async fn resolve_grant_target(
        &self,
        target: &GrantTarget,
        deadline: Deadline,
    ) -> StoreResult<Option<(User, Vec<IdentityRow>)>> {
        let out = async {
            let mut client = self.client().await?;
            let tx = self.read_within(&mut client, deadline).await?;
            let (clause, arg) = match target {
                GrantTarget::Id(u) => ("user_id", u.to_string()),
                GrantTarget::Email(e) => ("primary_email", e.to_string()),
            };
            let Some(u) = tx
                .query_opt(&format!("SELECT {USER_COLS} FROM users WHERE {clause} = $1"), &[&arg])
                .await
                .map_err(pg)?
                .map(|r| user(&r, 0))
                .transpose()?
            else {
                return Ok(None);
            };
            let ids = tx
                .query(
                    &format!("SELECT {IDENTITY_COLS} FROM identities WHERE user_id = $1 ORDER BY first_seen_at, provider_id, subject"),
                    &[&u.user_id.as_str()],
                )
                .await
                .map_err(pg)?
                .iter()
                .map(identity)
                .collect::<StoreResult<Vec<_>>>()?;
            tx.commit().await.map_err(pg)?;
            Ok(Some((u, ids)))
        }
        .await;
        out.map_err(deadline_err)
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
        AdminStore::grant_admin(
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
        AdminStore::revoke_admin(self, user, by, managed_by, at, event).await
    }

    async fn import_grants(
        &self,
        entries: Vec<SeedEntry>,
        force: Option<ForceTarget>,
        deadline: Deadline,
        at: Timestamp,
        mk_event: MkGrantEvent<'_>,
    ) -> StoreResult<GrantImportReport> {
        super::retry(|| async {
            check_deadline(deadline)?;
            let mut client = self.client().await?;
            let tx = self.begin(&mut client).await?;
            let ms = deadline_ms(deadline).min(self.statement_timeout_ms);
            tx.batch_execute(&format!("SET LOCAL statement_timeout = {ms}"))
                .await
                .map_err(pg)?;
            tx.execute("SELECT pg_advisory_xact_lock($1)", &[&GRANTS_LOCK])
                .await
                .map_err(pg)?;
            let mut imp = Import {
                store: self,
                tx: &tx,
                mk: mk_event,
                deadline,
                at,
                report: GrantImportReport::default(),
                present: HashSet::new(),
            };
            imp.run(&entries, force.as_ref()).await?;
            let report = imp.report;
            check_deadline(deadline)?;
            tx.commit().await.map_err(pg)?;
            Ok(report)
        })
        .await
        .map_err(deadline_err)
    }

    async fn list_users(
        &self,
        q: UsersQuery,
        deadline: Deadline,
    ) -> StoreResult<Page<UserSummary>> {
        ConsoleStore::list_users(self, q, deadline).await
    }
    async fn user_detail(
        &self,
        user: &UserId,
        now: Timestamp,
        deadline: Deadline,
    ) -> StoreResult<Option<UserDetail>> {
        ConsoleStore::user_detail(self, user, now, deadline).await
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
        AdminStore::set_user_status(self, actor, policy, user, status, deadline, admin_event, mk)
            .await
    }
}

/// A live session row, locked for the write.
async fn live_session_locked(tx: &Transaction<'_>, id: &SessionId) -> StoreResult<SessionRow> {
    tx.query_opt(
        &format!("SELECT {SESSION_COLS} FROM sessions s WHERE s.session_id=$1 FOR UPDATE"),
        &[&id.as_str()],
    )
    .await
    .map_err(pg)?
    .map(|r| session(&r, 0))
    .transpose()?
    .filter(|s| s.terminated_at.is_none())
    .ok_or(StoreError::Conflict("session unavailable"))
}

#[async_trait]
impl Sessions for PgStore {
    async fn create_session(&self, req: CreateSession) -> StoreResult<()> {
        CoreStore::create_session(self, req).await
    }
    async fn session(&self, id: &SessionId) -> StoreResult<Option<SessionRow>> {
        CoreStore::session(self, id).await
    }
    async fn lookup_handle(&self, d: &Digest, host: &Host) -> StoreResult<Option<HandleView>> {
        CoreStore::lookup_handle(self, d, host).await
    }
    async fn lookup_handle_within(
        &self,
        d: &Digest,
        host: &Host,
        deadline: Deadline,
    ) -> StoreResult<Option<HandleView>> {
        within(deadline, CoreStore::lookup_handle(self, d, host)).await
    }
    async fn touch_handle(&self, d: &Digest, at: Timestamp) -> StoreResult<()> {
        CoreStore::touch_handle(self, d, at).await
    }

    async fn mint_handle(
        &self,
        h: HandleRow,
        replaces: Option<Digest>,
        events: Vec<Event>,
    ) -> StoreResult<()> {
        super::retry(|| async {
            let mut client = self.client().await?;
            let tx = self.begin(&mut client).await?;
            let s = live_session_locked(&tx, &h.session_id).await?;
            if let Some(old) = replaces {
                let owner = tx
                    .query_opt("SELECT session_id FROM session_handles WHERE handle_sha256=$1 FOR UPDATE", &[&old.0.to_vec()])
                    .await
                    .map_err(pg)?
                    .map(|r| r.get::<_, String>(0));
                if owner.as_deref() != Some(h.session_id.as_str()) {
                    return Err(StoreError::Conflict("replaced handle belongs to another session"));
                }
                tx.execute(
                    "UPDATE session_handles SET revoked_at=$2, revoked_reason=$3 WHERE handle_sha256=$1 AND revoked_at IS NULL",
                    &[&old.0.to_vec(), &self.now().secs(), &reasons::REPLACED.0],
                )
                .await
                .map_err(pg)?;
            }
            let mut h = h.clone();
            h.issued_aal = h.issued_aal.min(s.aal);
            write::insert_handle(&tx, &h).await?;
            self.insert_events(&tx, &events).await?;
            tx.commit().await.map_err(pg)
        })
        .await
    }

    async fn revoke_handle(
        &self,
        d: &Digest,
        reason: Reason,
        at: Timestamp,
        events: Vec<Event>,
    ) -> StoreResult<()> {
        CoreStore::revoke_handle(self, d, reason, at, events).await
    }
    async fn terminate_session(
        &self,
        id: &SessionId,
        reason: Reason,
        at: Timestamp,
        events: Vec<Event>,
    ) -> StoreResult<()> {
        CoreStore::terminate_session(self, id, reason, at, events).await
    }

    async fn consume_logout_ticket(
        &self,
        d: &Digest,
        session: Option<&SessionId>,
        reason: Reason,
        at: Timestamp,
        events: Vec<Event>,
    ) -> StoreResult<bool> {
        super::retry(|| async {
            let mut client = self.client().await?;
            let tx = self.begin(&mut client).await?;
            let n = tx
                .execute(
                    "UPDATE login_txns SET consumed_at=$2, consumed_reason=$3 WHERE txn_sha256=$1 AND purpose='logout' AND consumed_at IS NULL",
                    &[&d.0.to_vec(), &at.secs(), &reason.0],
                )
                .await
                .map_err(pg)?;
            if n == 0 {
                return Ok(false);
            }
            // The same transaction: a ticket is never consumed while its session stays live.
            if let Some(id) = session {
                super::admin::terminate_in(self, &tx, id, reason, at, &events).await?;
            }
            tx.commit().await.map_err(pg)?;
            Ok(true)
        })
        .await
    }

    async fn list_live_sessions(
        &self,
        q: SessionsQuery,
        deadline: Deadline,
    ) -> StoreResult<Page<SessionSummary>> {
        ConsoleStore::list_live_sessions(self, q, deadline).await
    }
    async fn session_summary(
        &self,
        id: &SessionId,
        deadline: Deadline,
    ) -> StoreResult<Option<(SessionSummary, Vec<HandleRow>)>> {
        ConsoleStore::session_summary(self, id, deadline).await
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
        AdminStore::admin_terminate_session(
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

    async fn admin_terminate_user_sessions(
        &self,
        actor: &Actor,
        policy: &ActorPolicy,
        user: &UserId,
        deadline: Deadline,
        admin_event: Event,
        mk: &(dyn for<'a> Fn(&'a SessionRow) -> Event + Sync),
    ) -> StoreResult<u32> {
        super::retry(|| async {
            let mut client = self.client().await?;
            let tx = self.begin_fenced(&mut client, actor, policy, deadline).await?;
            let now = self.now();
            let rows = tx
                .query(
                    &format!("SELECT {SESSION_COLS} FROM sessions s WHERE s.user_id = $1 AND s.terminated_at IS NULL AND s.absolute_expires_at > $2 ORDER BY s.created_at, s.session_id FOR UPDATE"),
                    &[&user.as_str(), &now.secs()],
                )
                .await
                .map_err(pg)?;
            let mut n = 0u32;
            for r in rows {
                check_deadline(deadline)?;
                let row = session(&r, 0)?;
                if super::admin::terminate_in(self, &tx, &row.session_id, reasons::ADMIN, now, &[mk(&row)]).await? {
                    n += 1;
                }
            }
            if n == 0 {
                return Ok(0); // nothing live: no write, no event
            }
            let mut admin_event = admin_event.clone();
            admin_event.attrs.insert("count".into(), n.into());
            self.insert_events(&tx, &[admin_event]).await?;
            check_deadline(deadline)?;
            tx.commit().await.map_err(pg)?;
            Ok(n)
        })
        .await
        .map_err(deadline_err)
    }

    async fn reauthenticate_session(
        &self,
        id: &SessionId,
        provider: &ProviderId,
        configuration: Option<(ProviderKind, serde_json::Value)>,
        auth_time: Timestamp,
        source: AuthTimeSource,
        factor: FactorEntry,
        new_portal_handle: HandleRow,
        consume_txn: (Digest, Reason),
        deadline: Deadline,
        events: Vec<Event>,
        mk_revoked_event: &(dyn for<'a> Fn(&'a HandleRow) -> Event + Sync),
    ) -> StoreResult<()> {
        self.reauthenticate(
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
        )
        .await
    }

    async fn refresh_snapshot(
        &self,
        id: &SessionId,
        snapshot: IdentitySnapshot,
        authz_version: u64,
    ) -> StoreResult<()> {
        let client = self.client().await?;
        client
            .execute(
                "UPDATE sessions SET snapshot=$2, authz_version=$3 WHERE session_id=$1 AND terminated_at IS NULL AND authz_version <= $3",
                &[&id.as_str(), &snapshot_json(&snapshot), &i64_of(authz_version)],
            )
            .await
            .map_err(pg)?;
        Ok(())
    }

    async fn create_transaction(&self, txn: NewTransaction, events: Vec<Event>) -> StoreResult<()> {
        let since = txn.created_at;
        HandoffStore::create_transaction_capped(self, txn, events, since, None, u32::MAX)
            .await
            .map(|_| ())
    }
    async fn create_transaction_capped(
        &self,
        txn: NewTransaction,
        events: Vec<Event>,
        since: Timestamp,
        cap: Option<u32>,
        max_rows: u32,
    ) -> StoreResult<Admission> {
        HandoffStore::create_transaction_capped(self, txn, events, since, cap, max_rows).await
    }
    async fn transaction(&self, d: &Digest) -> StoreResult<Option<TransactionRow>> {
        HandoffStore::transaction(self, d).await
    }
    async fn transaction_by_state(&self, d: &Digest) -> StoreResult<Option<TransactionRow>> {
        HandoffStore::transaction_by_state(self, d).await
    }
    async fn bind_transaction(&self, d: &Digest, b: TransactionBinding) -> StoreResult<()> {
        HandoffStore::bind_transaction(self, d, b).await
    }

    async fn bind_switch_transaction(&self, d: &Digest, bind: Digest) -> StoreResult<bool> {
        self.bind_purpose(d, bind, "switch").await
    }
    async fn bind_logout_transaction(&self, d: &Digest, bind: Digest) -> StoreResult<bool> {
        self.bind_purpose(d, bind, "logout").await
    }
    async fn use_retry(&self, d: &Digest, at: Timestamp) -> StoreResult<bool> {
        HandoffStore::use_retry(self, d, at).await
    }

    async fn record_retry_bind(&self, d: &Digest, bind: Digest) -> StoreResult<()> {
        let client = self.client().await?;
        let n = client
            .execute(
                "UPDATE login_txns SET retry_bind_sha256=$2 WHERE txn_sha256=$1 AND retry_bind_sha256 IS NULL",
                &[&d.0.to_vec(), &bind.0.to_vec()],
            )
            .await
            .map_err(pg)?;
        if n != 1 {
            return Err(StoreError::Conflict(
                "retry bind already recorded or transaction unknown",
            ));
        }
        Ok(())
    }

    async fn consume_transaction(
        &self,
        d: &Digest,
        reason: Reason,
        at: Timestamp,
        events: Vec<Event>,
    ) -> StoreResult<bool> {
        HandoffStore::consume_transaction(self, d, reason, at, events).await
    }

    async fn consume_transaction_for_provider(
        &self,
        d: &Digest,
        provider: &ProviderId,
        configuration: Option<(ProviderKind, serde_json::Value)>,
        reason: Reason,
        at: Timestamp,
        events: Vec<Event>,
    ) -> StoreResult<bool> {
        super::retry(|| async {
            let mut client = self.client().await?;
            let tx = self.begin(&mut client).await?;
            require_provider_live(&tx, provider.as_str()).await?;
            write::require_provider_configuration(&tx, provider.as_str(), configuration.as_ref()).await?;
            let n = tx
                .execute(
                    "UPDATE login_txns SET consumed_at=$2, consumed_reason=$3 WHERE txn_sha256=$1 AND consumed_at IS NULL",
                    &[&d.0.to_vec(), &at.secs(), &reason.0],
                )
                .await
                .map_err(pg)?;
            if n == 0 {
                return Ok(false);
            }
            self.insert_events(&tx, &events).await?;
            tx.commit().await.map_err(pg)?;
            Ok(true)
        })
        .await
    }

    async fn mint_handoff_code(&self, code: HandoffCodeRow, events: Vec<Event>) -> StoreResult<()> {
        HandoffStore::mint_handoff_code(self, code, events).await
    }
    async fn redeem_handoff_code(
        &self,
        req: RedeemRequest,
        ok: Vec<Event>,
        fail: Vec<Event>,
    ) -> StoreResult<RedeemOutcome> {
        HandoffStore::redeem_handoff_code(self, req, ok, fail).await
    }
    async fn count_transactions_since(&self, ip: IpAddr, since: Timestamp) -> StoreResult<u32> {
        HandoffStore::count_transactions_since(self, ip, since).await
    }
    async fn count_handoff_failures_since(&self, ip: IpAddr, since: Timestamp) -> StoreResult<u32> {
        HandoffStore::count_handoff_failures_since(self, ip, since).await
    }

    async fn evict_transactions(&self, max_rows: u32, now: Timestamp) -> StoreResult<u32> {
        super::retry(|| async {
            let mut client = self.client().await?;
            let tx = self.begin(&mut client).await?;
            tx.execute("SELECT pg_advisory_xact_lock(7008)", &[]).await.map_err(pg)?;
            let total: i64 = tx.query_one("SELECT count(*) FROM login_txns", &[]).await.map_err(pg)?.get(0);
            let excess = total - i64::from(max_rows);
            let n = if excess > 0 {
                tx.execute(
                    "DELETE FROM login_txns WHERE txn_sha256 IN (SELECT txn_sha256 FROM login_txns ORDER BY (consumed_at IS NULL AND expires_at > $1), created_at, seq LIMIT $2)",
                    &[&now.secs(), &excess],
                )
                .await
                .map_err(pg)? as u32
            } else {
                0
            };
            tx.commit().await.map_err(pg)?;
            Ok(n)
        })
        .await
    }

    async fn session_aal3_evidence(&self, session: &SessionId, cred_gen: u64) -> StoreResult<bool> {
        let client = self.client().await?;
        Ok(client
            .query_opt(
                "SELECT 1 FROM session_webauthn_provenance p JOIN sessions s ON s.session_id=p.session_id AND s.cred_gen=p.credential_generation \
                 JOIN webauthn_credentials w ON w.credential_id=p.credential_id AND w.user_id=p.user_id \
                 WHERE p.session_id=$1 AND s.cred_gen=$2 AND s.terminated_at IS NULL AND s.aal=2 AND p.assurance='aal3' \
                 AND w.assurance='aal3' AND w.state='active' AND NOT w.backup_eligible AND NOT w.backup_state",
                &[&session.as_str(), &i64::try_from(cred_gen).unwrap_or(-1)],
            )
            .await
            .map_err(pg)?
            .is_some())
    }

    async fn sweep(&self, now: Timestamp, retention: Duration) -> StoreResult<SweepReport> {
        super::retry(|| async {
            let mut client = self.client().await?;
            let tx = self.begin(&mut client).await?;
            let n = |x: u64| u32::try_from(x).unwrap_or(u32::MAX);
            let transactions = n(tx.execute("DELETE FROM login_txns WHERE expires_at <= $1", &[&now.secs()]).await.map_err(pg)?);
            let codes = n(tx.execute("DELETE FROM handoff_codes WHERE expires_at <= $1", &[&now.secs()]).await.map_err(pg)?);
            tx.execute("DELETE FROM webauthn_challenges WHERE expires_at <= $1 OR consumed_at IS NOT NULL", &[&now.secs()]).await.map_err(pg)?;
            tx.execute("DELETE FROM webauthn_login_challenges WHERE expires_at <= $1 OR consumed_at IS NOT NULL", &[&now.secs()]).await.map_err(pg)?;
            let sessions = n(tx
                .execute("DELETE FROM sessions WHERE terminated_at IS NOT NULL AND terminated_at <= $1", &[&now.sub(retention).secs()])
                .await
                .map_err(pg)?);
            tx.commit().await.map_err(pg)?;
            Ok(SweepReport { transactions, codes, sessions })
        })
        .await
    }
}

impl PgStore {
    async fn bind_purpose(&self, d: &Digest, bind: Digest, purpose: &str) -> StoreResult<bool> {
        let client = self.client().await?;
        let n = client
            .execute(
                "UPDATE login_txns SET portal_bind_sha256=$2 WHERE txn_sha256=$1 AND purpose=$3 AND portal_bind_sha256 IS NULL AND consumed_at IS NULL",
                &[&d.0.to_vec(), &bind.0.to_vec(), &purpose],
            )
            .await
            .map_err(pg)?;
        Ok(n == 1)
    }

    /// Reauthentication (ADR-0016 decision 15) in one transaction, the
    /// session row locked first.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn reauthenticate(
        &self,
        id: &SessionId,
        provider: &ProviderId,
        configuration: Option<&(ProviderKind, serde_json::Value)>,
        auth_time: Timestamp,
        source: AuthTimeSource,
        factor: &FactorEntry,
        new_portal_handle: &HandleRow,
        consume_txn: &(Digest, Reason),
        deadline: Deadline,
        events: &[Event],
        mk_revoked_event: &(dyn for<'a> Fn(&'a HandleRow) -> Event + Sync),
    ) -> StoreResult<()> {
        if new_portal_handle.session_id != *id {
            return Err(StoreError::Conflict("portal handle names another session"));
        }
        super::retry(|| async {
            check_deadline(deadline)?;
            let mut client = self.client().await?;
            let tx = self.begin(&mut client).await?;
            let ms = deadline_ms(deadline).min(self.statement_timeout_ms);
            tx.batch_execute(&format!("SET LOCAL statement_timeout = {ms}")).await.map_err(pg)?;
            let s = live_session_locked(&tx, id).await?;
            if s.provider_id != *provider {
                return Err(StoreError::Conflict("provider_mismatch"));
            }
            require_provider_live(&tx, provider.as_str()).await?;
            write::require_provider_configuration(&tx, provider.as_str(), configuration).await?;
            let now = self.now();
            let consumed = tx
                .execute(
                    "UPDATE login_txns SET consumed_at = $2, consumed_reason = $3 WHERE txn_sha256 = $1 AND consumed_at IS NULL",
                    &[&consume_txn.0.0.to_vec(), &now.secs(), &consume_txn.1.0],
                )
                .await
                .map_err(pg)?;
            if consumed != 1 {
                return Err(StoreError::Conflict("transaction already consumed"));
            }
            let mut factors = s.factors.clone();
            factors.push(factor.clone());
            tx.execute(
                "UPDATE sessions SET auth_time = $2, auth_time_source = $3, factors = $4, cred_gen = cred_gen + 1 WHERE session_id = $1",
                &[&id.as_str(), &auth_time.secs(), &source.as_str(), &factors_json(&factors)?],
            )
            .await
            .map_err(pg)?;
            // The audit lists exactly the handles this transaction revokes.
            let live: Vec<HandleRow> = tx
                .query(
                    &format!("SELECT {HANDLE_COLS} FROM session_handles h WHERE h.session_id = $1 AND h.revoked_at IS NULL ORDER BY h.created_at, h.handle_sha256 FOR UPDATE"),
                    &[&id.as_str()],
                )
                .await
                .map_err(pg)?
                .iter()
                .map(|r| handle(r, 0))
                .collect::<StoreResult<_>>()?;
            let mut all = events.to_vec();
            for row in &live {
                all.push(mk_revoked_event(row));
            }
            write::revoke_session_handles(&tx, id, reasons::REAUTH.0, now).await?;
            write::consume_session_codes(&tx, id, reasons::REAUTH.0, now).await?;
            let mut h = new_portal_handle.clone();
            h.issued_aal = h.issued_aal.min(s.aal);
            write::insert_handle(&tx, &h).await?;
            // An unqualified reauthentication cannot keep an earlier primary proof.
            tx.execute("DELETE FROM session_primary_provenance WHERE session_id=$1", &[&id.as_str()]).await.map_err(pg)?;
            self.insert_events(&tx, &all).await?;
            check_deadline(deadline)?;
            tx.commit().await.map_err(pg)
        })
        .await
        .map_err(deadline_err)
    }
}

impl PgStore {
    /// Mirror the configured applications into `apps` (informational: verify
    /// reads the in-memory snapshot), as SQLite's `mirror_apps`.
    pub async fn mirror_apps(&self, apps: &[crate::policy::types::AppPolicy]) -> StoreResult<()> {
        super::retry(|| async {
            let mut client = self.client().await?;
            let tx = self.begin(&mut client).await?;
            let now = self.now().secs();
            let keep: Vec<String> = apps.iter().map(|a| a.app_id.to_string()).collect();
            for a in apps {
                let hosts: Vec<&str> = a.hosts.iter().map(|h| h.as_str()).collect();
                let session = serde_json::json!({"idle_secs": a.session.idle.as_secs(), "absolute_secs": a.session.absolute.as_secs()});
                let binding = serde_json::json!({
                    "ip": format!("{:?}", a.binding.ip),
                    "ua": format!("{:?}", a.binding.ua),
                    "on_mismatch": format!("{:?}", a.binding.on_mismatch),
                });
                let step_up: Vec<serde_json::Value> = a
                    .step_up
                    .iter()
                    .map(|r| serde_json::json!({"path_prefix": r.path_prefix, "aal": r.aal.as_i64(), "max_age_secs": r.max_age.map(|d| d.as_secs())}))
                    .collect();
                let change = match a.on_authz_change {
                    crate::policy::types::AuthzChange::Refresh => "refresh",
                    crate::policy::types::AuthzChange::Terminate => "terminate",
                };
                tx.execute(
                    "INSERT INTO apps (app_id, display_name, hosts, ports, enabled, session_policy, binding_policy, step_up, on_authz_change, created_at, updated_at) \
                     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$10) ON CONFLICT (app_id) DO UPDATE SET display_name=excluded.display_name, hosts=excluded.hosts, \
                     ports=excluded.ports, enabled=excluded.enabled, session_policy=excluded.session_policy, binding_policy=excluded.binding_policy, \
                     step_up=excluded.step_up, on_authz_change=excluded.on_authz_change, updated_at=excluded.updated_at",
                    &[
                        &a.app_id.as_str(),
                        &a.display_name,
                        &serde_json::to_string(&hosts).map_err(|_| corrupt("apps.hosts"))?,
                        &serde_json::to_string(&a.ports).map_err(|_| corrupt("apps.ports"))?,
                        &a.enabled,
                        &session.to_string(),
                        &binding.to_string(),
                        &serde_json::to_string(&step_up).map_err(|_| corrupt("apps.step_up"))?,
                        &change,
                        &now,
                    ],
                )
                .await
                .map_err(pg)?;
            }
            tx.execute("DELETE FROM apps WHERE NOT (app_id = ANY($1))", &[&keep]).await.map_err(pg)?;
            tx.commit().await.map_err(pg)
        })
        .await
    }
}
