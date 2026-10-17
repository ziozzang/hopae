//! Slice 3 for PostgreSQL (ADR-0020, ADR-0019): groups, memberships and the
//! membership-projection journal.
//!
//! Every group write takes one transaction-scoped advisory lock before it
//! reads anything, then appends its journal rows numbered from the current
//! maximum: group writes run one at a time across replicas (as behind the
//! single SQLite writer), journal revisions are gapless and commit in order,
//! and a projection consumer that has read revision N never later finds a
//! new row below N. Administrator writes are fenced like every console
//! mutation; provider syncs hold the provider row against a disable.
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use async_trait::async_trait;
use deadpool_postgres::Transaction;
use tokio_postgres::Row;

use super::admin::{check_deadline, deadline_err, deadline_ms};
use super::{PgStore, pg, require_provider_live};
use crate::crypto::time_ordered_id;
use crate::event::types::{Event, EventId, EventKind};
use crate::groups::Source;
use crate::groups::config::{GATEWAY_HEADER_MAX, Mapped};
use crate::identity::types::UserId;
use crate::provider::types::ProviderId;
use crate::store::core::{GroupStore, GroupsOfUsers};
use crate::store::sqlite::groups::{
    Cas, Edit, GroupRow, JOURNAL_SCAN, JournalPage, JournalRow, MAX_LOCAL_GROUPS,
    MAX_LOCAL_MEMBERS, MAX_PAGE, MAX_PAGE_REFS, MaintenanceReport, MemberRow, RevisionLost,
    SnapshotEntry, SyncReport, WritePolicy,
};
use crate::store::types::{Actor, ActorPolicy};
use crate::store::{Deadline, StoreError, StoreResult};

/// `pg_advisory_xact_lock` key serializing group writes and the journal.
const GROUPS_LOCK: i64 = 7030;
/// Most rows one maintenance step touches.
const MAINTENANCE_BATCH: i64 = 1_000;

const GROUP_COLS: &str = "g.group_id, g.source, g.provider_id, g.external_key, g.name, g.description, g.state, g.revision, g.created_at, g.updated_at, g.last_seen_at, g.deleted_at, (SELECT count(*) FROM group_members m WHERE m.group_id = g.group_id)";
const MEMBER_COLS: &str = "gm.group_id, gm.user_id, gm.source, gm.provider_id, gm.first_seen_at, gm.last_seen_at, gm.expires_at, gm.removal_pending_at, gm.added_by, gm.reason, gm.stale_at";

fn group_row(r: &Row, o: usize) -> GroupRow {
    GroupRow {
        group_id: r.get(o),
        source: r.get(o + 1),
        provider_id: r.get(o + 2),
        external_key: r.get(o + 3),
        name: r.get(o + 4),
        description: r.get(o + 5),
        state: r.get(o + 6),
        revision: r.get(o + 7),
        created_at: r.get(o + 8),
        updated_at: r.get(o + 9),
        last_seen_at: r.get(o + 10),
        deleted_at: r.get(o + 11),
        members: r.get(o + 12),
    }
}

fn member_row(r: &Row, o: usize) -> MemberRow {
    MemberRow {
        group_id: r.get(o),
        user_id: r.get(o + 1),
        source: r.get(o + 2),
        provider_id: r.get(o + 3),
        first_seen_at: r.get(o + 4),
        last_seen_at: r.get(o + 5),
        expires_at: r.get(o + 6),
        removal_pending_at: r.get(o + 7),
        added_by: r.get(o + 8),
        reason: r.get(o + 9),
        stale_at: r.get(o + 10),
    }
}

#[derive(Clone, Copy)]
enum Change {
    GroupCreated,
    GroupUpdated,
    GroupDeleted,
    MemberAdded,
    MemberRemoved,
    MemberSuspended,
    MemberRestored,
}

impl Change {
    fn name(self) -> &'static str {
        match self {
            Change::GroupCreated => "group_created",
            Change::GroupUpdated => "group_updated",
            Change::GroupDeleted => "group_deleted",
            Change::MemberAdded | Change::MemberRestored => "member_added",
            Change::MemberRemoved | Change::MemberSuspended => "member_removed",
        }
    }
    fn kind(self) -> EventKind {
        match self {
            Change::GroupCreated => EventKind::GroupCreated,
            Change::GroupUpdated => EventKind::GroupUpdated,
            Change::GroupDeleted => EventKind::GroupDeleted,
            Change::MemberAdded => EventKind::GroupMemberAdded,
            Change::MemberRemoved => EventKind::GroupMemberRemoved,
            Change::MemberSuspended => EventKind::GroupMembershipStale,
            Change::MemberRestored => EventKind::GroupMembershipRestored,
        }
    }
}

struct GroupKey<'a> {
    id: &'a str,
    source: &'a str,
    provider: Option<&'a str>,
}

struct Journal<'a> {
    store: &'a PgStore,
    template: Event,
    events: Vec<Event>,
    now: crate::crypto::Timestamp,
    touched_users: BTreeSet<String>,
}

impl Journal<'_> {
    #[allow(clippy::too_many_arguments)]
    async fn record(
        &mut self,
        tx: &Transaction<'_>,
        change: Change,
        group: &GroupKey<'_>,
        user: Option<&str>,
        revision: i64,
        event: bool,
        extra: &[(&str, serde_json::Value)],
    ) -> StoreResult<()> {
        // Under the group lock: the next revision is the maximum plus one.
        tx.execute(
            "INSERT INTO group_changes (revision, at, change, group_id, user_id) \
             VALUES ((SELECT COALESCE(max(revision), 0) + 1 FROM group_changes), $1, $2, $3, $4)",
            &[&self.now.secs(), &change.name(), &group.id, &user],
        )
        .await
        .map_err(pg)?;
        if let Some(u) = user {
            self.touched_users.insert(u.to_string());
        }
        if !event {
            return Ok(());
        }
        let mut ev = self.template.clone();
        ev.event_id = EventId::new(time_ordered_id(self.store.rng.as_ref(), "e_", self.now));
        ev.at = self.now;
        ev.kind = change.kind();
        ev.user_id = user.map(UserId::new);
        if let Some(p) = group.provider {
            ev.provider_id = Some(ProviderId::new(p));
        }
        ev.attrs.insert("group_id".into(), group.id.into());
        ev.attrs.insert("source".into(), group.source.into());
        ev.attrs.insert("revision".into(), revision.into());
        for (k, v) in extra {
            ev.attrs.insert((*k).into(), v.clone());
        }
        self.events.push(ev);
        Ok(())
    }

    /// Mirror the touched people's group references into `users.groups`
    /// (cleared when the gateway header is off), moving `authz_version`
    /// only when the value changes.
    async fn mirror(&self, tx: &Transaction<'_>, enabled: bool) -> StoreResult<()> {
        for user in &self.touched_users {
            let refs: Vec<String> = if enabled {
                tx.query(
                    "SELECT gm.group_id FROM group_members gm JOIN directory_groups g ON g.group_id = gm.group_id \
                     WHERE gm.user_id = $1 AND g.state = 'active' AND gm.stale_at IS NULL ORDER BY gm.group_id LIMIT $2",
                    &[user, &(GATEWAY_HEADER_MAX as i64)],
                )
                .await
                .map_err(pg)?
                .iter()
                .map(|r| r.get(0))
                .collect()
            } else {
                Vec::new()
            };
            let value =
                serde_json::to_string(&refs).map_err(|_| StoreError::Conflict("group mirror"))?;
            tx.execute(
                "UPDATE users SET groups = $2, authz_version = authz_version + 1, updated_at = $3 WHERE user_id = $1 AND groups <> $2",
                &[user, &value, &self.now.secs()],
            )
            .await
            .map_err(pg)?;
        }
        Ok(())
    }
}

async fn group_by_id(tx: &Transaction<'_>, id: &str) -> StoreResult<Option<GroupRow>> {
    Ok(tx
        .query_opt(
            &format!("SELECT {GROUP_COLS} FROM directory_groups g WHERE g.group_id = $1"),
            &[&id],
        )
        .await
        .map_err(pg)?
        .map(|r| group_row(&r, 0)))
}

async fn user_exists(tx: &Transaction<'_>, user: &str) -> StoreResult<bool> {
    Ok(tx
        .query_opt("SELECT 1 FROM users WHERE user_id = $1", &[&user])
        .await
        .map_err(pg)?
        .is_some())
}

async fn memberships_of(tx: &Transaction<'_>, user: &str) -> StoreResult<i64> {
    Ok(tx
        .query_one(
            "SELECT count(*) FROM group_members gm JOIN directory_groups g ON g.group_id = gm.group_id WHERE gm.user_id = $1 AND g.state = 'active'",
            &[&user],
        )
        .await
        .map_err(pg)?
        .get(0))
}

async fn bump(tx: &Transaction<'_>, id: &str, now: i64) -> StoreResult<i64> {
    Ok(tx
        .query_one(
            "UPDATE directory_groups SET revision = revision + 1, updated_at = $2 WHERE group_id = $1 RETURNING revision",
            &[&id, &now],
        )
        .await
        .map_err(pg)?
        .get(0))
}

async fn local_at(
    tx: &Transaction<'_>,
    id: &str,
    expected: i64,
) -> StoreResult<Result<GroupRow, Cas<()>>> {
    let Some(g) = group_by_id(tx, id).await? else {
        return Ok(Err(Cas::NotFound));
    };
    if g.state != "active" {
        return Ok(Err(Cas::Deleted));
    }
    if g.source != "local" {
        return Ok(Err(Cas::NotLocal));
    }
    if g.revision != expected {
        return Ok(Err(Cas::Stale(g.revision)));
    }
    Ok(Ok(g))
}

fn cas<T>(e: Cas<()>) -> Cas<T> {
    match e {
        Cas::Done(()) => Cas::Conflict("internal"),
        Cas::NotFound => Cas::NotFound,
        Cas::Deleted => Cas::Deleted,
        Cas::NotLocal => Cas::NotLocal,
        Cas::Stale(r) => Cas::Stale(r),
        Cas::Conflict(c) => Cas::Conflict(c),
    }
}

async fn remove_all(
    tx: &Transaction<'_>,
    j: &mut Journal<'_>,
    g: &GroupRow,
    revision: i64,
    deadline: Deadline,
) -> StoreResult<u32> {
    let users: Vec<String> = tx
        .query(
            "SELECT user_id FROM group_members WHERE group_id = $1 ORDER BY user_id",
            &[&g.group_id],
        )
        .await
        .map_err(pg)?
        .iter()
        .map(|r| r.get(0))
        .collect();
    let key = GroupKey {
        id: &g.group_id,
        source: &g.source,
        provider: g.provider_id.as_deref(),
    };
    for (i, u) in users.iter().enumerate() {
        if i % 1024 == 0 {
            check_deadline(deadline)?;
        }
        j.record(
            tx,
            Change::MemberRemoved,
            &key,
            Some(u),
            revision,
            false,
            &[],
        )
        .await?;
    }
    tx.execute(
        "DELETE FROM group_members WHERE group_id = $1",
        &[&g.group_id],
    )
    .await
    .map_err(pg)?;
    Ok(u32::try_from(users.len()).unwrap_or(u32::MAX))
}

async fn delete_group(
    tx: &Transaction<'_>,
    j: &mut Journal<'_>,
    g: &GroupRow,
    deadline: Deadline,
    extra: &[(&str, serde_json::Value)],
) -> StoreResult<i64> {
    let now = j.now.secs();
    let revision: i64 = tx
        .query_one(
            "UPDATE directory_groups SET state = 'deleted', deleted_at = $2, updated_at = $2, revision = revision + 1 WHERE group_id = $1 RETURNING revision",
            &[&g.group_id, &now],
        )
        .await
        .map_err(pg)?
        .get(0);
    let n = remove_all(tx, j, g, revision, deadline).await?;
    let key = GroupKey {
        id: &g.group_id,
        source: &g.source,
        provider: g.provider_id.as_deref(),
    };
    let mut extra = extra.to_vec();
    extra.push(("count", n.into()));
    j.record(tx, Change::GroupDeleted, &key, None, revision, true, &extra)
        .await?;
    Ok(revision)
}

fn escape_like(v: &str) -> String {
    let mut out = String::with_capacity(v.len() + 4);
    for ch in v.chars() {
        if matches!(ch, '\\' | '%' | '_') {
            out.push('\\');
        }
        out.push(ch);
    }
    out
}

async fn journal_bounds(tx: &Transaction<'_>) -> StoreResult<(i64, Option<i64>)> {
    let r = tx
        .query_one(
            "SELECT COALESCE(max(revision), 0), min(revision) FROM group_changes",
            &[],
        )
        .await
        .map_err(pg)?;
    Ok((r.get(0), r.get(1)))
}

impl PgStore {
    /// A group write: the deadline as statement timeout, then the group lock.
    async fn begin_groups<'a>(
        &self,
        client: &'a mut deadpool_postgres::Object,
        deadline: Deadline,
    ) -> StoreResult<Transaction<'a>> {
        check_deadline(deadline)?;
        let tx = self.begin(client).await?;
        let ms = deadline_ms(deadline).min(self.statement_timeout_ms);
        tx.batch_execute(&format!("SET LOCAL statement_timeout = {ms}"))
            .await
            .map_err(pg)?;
        tx.execute(super::ADVISORY_XACT_LOCK, &[&GROUPS_LOCK])
            .await
            .map_err(pg)?;
        Ok(tx)
    }
}

#[async_trait]
impl GroupStore for PgStore {
    async fn groups_admin_edit(
        &self,
        actor: &Actor,
        policy: &ActorPolicy,
        edit: Edit,
        settings: WritePolicy,
        template: Event,
        deadline: Deadline,
    ) -> StoreResult<Cas<GroupRow>> {
        super::retry(|| async {
            let mut client = self.client().await?;
            // The group lock first, then the fence (which locks the actor's rows).
            let tx = self.begin_groups(&mut client, deadline).await?;
            super::admin::fence(&tx, self.now().secs(), actor, policy).await?;
            let now = self.now();
            let mut j = Journal { store: self, template: template.clone(), events: Vec::new(), now, touched_users: BTreeSet::new() };
            let note = |r: &str| ("note", serde_json::Value::from(r));
            let id = match edit.clone() {
                Edit::Create { group_id, key, name, description } => {
                    let live: i64 = tx
                        .query_one("SELECT count(*) FROM directory_groups WHERE source = 'local' AND state = 'active'", &[])
                        .await
                        .map_err(pg)?
                        .get(0);
                    if live >= MAX_LOCAL_GROUPS {
                        return Ok(Cas::Conflict("too_many_local_groups"));
                    }
                    let taken = tx
                        .query_opt(
                            "SELECT 1 FROM directory_groups WHERE source = 'local' AND external_key = $1 AND state = 'active'",
                            &[&key],
                        )
                        .await
                        .map_err(pg)?
                        .is_some();
                    if taken {
                        return Ok(Cas::Conflict("key_in_use"));
                    }
                    tx.execute(
                        "INSERT INTO directory_groups (group_id, source, provider_id, external_key, name, description, state, revision, created_at, updated_at) \
                         VALUES ($1, 'local', NULL, $2, $3, $4, 'active', 1, $5, $5)",
                        &[&group_id, &key, &name, &description, &now.secs()],
                    )
                    .await
                    .map_err(pg)?;
                    let k = GroupKey { id: &group_id, source: "local", provider: None };
                    j.record(&tx, Change::GroupCreated, &k, None, 1, true, &[]).await?;
                    group_id
                }
                Edit::Update { group_id, expected, name, description } => {
                    let g = match local_at(&tx, &group_id, expected).await? {
                        Ok(g) => g,
                        Err(e) => return Ok(cas(e)),
                    };
                    let name = name.unwrap_or(g.name.clone());
                    let description = description.unwrap_or(g.description.clone());
                    if name == g.name && description == g.description {
                        return Ok(Cas::Done(g));
                    }
                    tx.execute(
                        "UPDATE directory_groups SET name = $2, description = $3 WHERE group_id = $1",
                        &[&group_id, &name, &description],
                    )
                    .await
                    .map_err(pg)?;
                    let revision = bump(&tx, &group_id, now.secs()).await?;
                    let k = GroupKey { id: &group_id, source: "local", provider: None };
                    let what = if name != g.name { "renamed" } else { "described" };
                    j.record(&tx, Change::GroupUpdated, &k, None, revision, true, &[("change", what.into())]).await?;
                    group_id
                }
                Edit::Delete { group_id, expected, force } => {
                    let g = match local_at(&tx, &group_id, expected).await? {
                        Ok(g) => g,
                        Err(e) => return Ok(cas(e)),
                    };
                    if g.members > 0 && !force {
                        return Ok(Cas::Conflict("group_not_empty"));
                    }
                    delete_group(&tx, &mut j, &g, deadline, &[]).await?;
                    group_id
                }
                Edit::AddMember { group_id, expected, user_id, expires_at, reason } => {
                    let g = match local_at(&tx, &group_id, expected).await? {
                        Ok(g) => g,
                        Err(e) => return Ok(cas(e)),
                    };
                    if !user_exists(&tx, &user_id).await? {
                        return Ok(Cas::Conflict("unknown_user"));
                    }
                    let member = tx
                        .query_opt("SELECT 1 FROM group_members WHERE group_id = $1 AND user_id = $2", &[&group_id, &user_id])
                        .await
                        .map_err(pg)?
                        .is_some();
                    if member {
                        return Ok(Cas::Conflict("already_member"));
                    }
                    if g.members >= MAX_LOCAL_MEMBERS {
                        return Ok(Cas::Conflict("group_full"));
                    }
                    if memberships_of(&tx, &user_id).await? >= settings.max_groups_per_user as i64 {
                        return Ok(Cas::Conflict("too_many_groups"));
                    }
                    tx.execute(
                        "INSERT INTO group_members (group_id, user_id, source, provider_id, first_seen_at, last_seen_at, expires_at, added_by, reason) \
                         VALUES ($1, $2, 'local', NULL, $3, $3, $4, $5, $6)",
                        &[&group_id, &user_id, &now.secs(), &expires_at, &actor.user_id.as_str(), &reason],
                    )
                    .await
                    .map_err(pg)?;
                    let revision = bump(&tx, &group_id, now.secs()).await?;
                    let k = GroupKey { id: &group_id, source: "local", provider: None };
                    let mut extra = vec![note(&reason)];
                    if let Some(e) = expires_at {
                        extra.push(("expires_at", e.into()));
                    }
                    j.record(&tx, Change::MemberAdded, &k, Some(&user_id), revision, true, &extra).await?;
                    group_id
                }
                Edit::RemoveMember { group_id, expected, user_id } => {
                    if let Err(e) = local_at(&tx, &group_id, expected).await? {
                        return Ok(cas(e));
                    }
                    let n = tx
                        .execute("DELETE FROM group_members WHERE group_id = $1 AND user_id = $2", &[&group_id, &user_id])
                        .await
                        .map_err(pg)?;
                    if n == 0 {
                        return Ok(Cas::Conflict("not_member"));
                    }
                    let revision = bump(&tx, &group_id, now.secs()).await?;
                    let k = GroupKey { id: &group_id, source: "local", provider: None };
                    j.record(&tx, Change::MemberRemoved, &k, Some(&user_id), revision, true, &[]).await?;
                    group_id
                }
            };
            j.mirror(&tx, settings.gateway_header).await?;
            check_deadline(deadline)?;
            self.insert_events(&tx, &j.events).await?;
            let row = group_by_id(&tx, &id).await?.ok_or(StoreError::Conflict("group vanished"))?;
            check_deadline(deadline)?;
            tx.commit().await.map_err(pg)?;
            Ok(Cas::Done(row))
        })
        .await
        .map_err(deadline_err)
    }

    async fn groups_sync_user(
        &self,
        provider: ProviderId,
        source: Source,
        user: UserId,
        asserted: Vec<Mapped>,
        grace_secs: u64,
        settings: WritePolicy,
        template: Event,
        deadline: Deadline,
    ) -> StoreResult<SyncReport> {
        super::retry(|| async {
            let mut client = self.client().await?;
            let tx = self.begin_groups(&mut client, deadline).await?;
            require_provider_live(&tx, provider.as_str()).await?;
            let user = user.as_str().to_string();
            if !user_exists(&tx, &user).await? {
                return Err(StoreError::Conflict("unknown user"));
            }
            let now = self.now();
            let secs = now.secs();
            let src = source.as_str();
            let pid = provider.as_str();
            let mut report = SyncReport::default();
            let mut j = Journal { store: self, template: template.clone(), events: Vec::new(), now, touched_users: BTreeSet::new() };
            let mut wanted: BTreeMap<String, String> = BTreeMap::new();
            for m in &asserted {
                let found = tx
                    .query_opt(
                        "SELECT group_id, name FROM directory_groups WHERE source = $1 AND provider_id = $2 AND external_key = $3 AND state = 'active'",
                        &[&src, &pid, &m.key],
                    )
                    .await
                    .map_err(pg)?
                    .map(|r| (r.get::<_, String>(0), r.get::<_, String>(1)));
                let id = match found {
                    Some((id, name)) => {
                        if name != m.name {
                            tx.execute("UPDATE directory_groups SET name = $2 WHERE group_id = $1", &[&id, &m.name])
                                .await
                                .map_err(pg)?;
                            let revision = bump(&tx, &id, secs).await?;
                            let k = GroupKey { id: &id, source: src, provider: Some(pid) };
                            j.record(&tx, Change::GroupUpdated, &k, None, revision, true, &[("change", "renamed".into())]).await?;
                            report.groups_renamed += 1;
                        }
                        tx.execute("UPDATE directory_groups SET last_seen_at = $2 WHERE group_id = $1", &[&id, &secs])
                            .await
                            .map_err(pg)?;
                        id
                    }
                    None => {
                        let id = crate::groups::new_ref(self.rng.as_ref());
                        tx.execute(
                            "INSERT INTO directory_groups (group_id, source, provider_id, external_key, name, description, state, revision, created_at, updated_at, last_seen_at) \
                             VALUES ($1, $2, $3, $4, $5, NULL, 'active', 1, $6, $6, $6)",
                            &[&id, &src, &pid, &m.key, &m.name, &secs],
                        )
                        .await
                        .map_err(pg)?;
                        let k = GroupKey { id: &id, source: src, provider: Some(pid) };
                        j.record(&tx, Change::GroupCreated, &k, None, 1, true, &[]).await?;
                        report.groups_created += 1;
                        id
                    }
                };
                wanted.insert(id, m.key.clone());
            }
            check_deadline(deadline)?;
            let current: HashMap<String, (Option<i64>, Option<i64>)> = tx
                .query(
                    "SELECT group_id, removal_pending_at, stale_at FROM group_members WHERE user_id = $1 AND source = $2 AND provider_id = $3",
                    &[&user, &src, &pid],
                )
                .await
                .map_err(pg)?
                .iter()
                .map(|r| (r.get(0), (r.get(1), r.get(2))))
                .collect();
            for id in wanted.keys() {
                let k = GroupKey { id, source: src, provider: Some(pid) };
                if let Some((_, stale)) = current.get(id) {
                    tx.execute(
                        "UPDATE group_members SET last_seen_at = $3, removal_pending_at = NULL, stale_at = NULL WHERE group_id = $1 AND user_id = $2",
                        &[id, &user, &secs],
                    )
                    .await
                    .map_err(pg)?;
                    if stale.is_some() {
                        let revision = bump(&tx, id, secs).await?;
                        j.record(&tx, Change::MemberRestored, &k, Some(&user), revision, true, &[]).await?;
                        report.restored += 1;
                    }
                } else {
                    tx.execute(
                        "INSERT INTO group_members (group_id, user_id, source, provider_id, first_seen_at, last_seen_at) VALUES ($1, $2, $3, $4, $5, $5)",
                        &[id, &user, &src, &pid, &secs],
                    )
                    .await
                    .map_err(pg)?;
                    let revision = bump(&tx, id, secs).await?;
                    j.record(&tx, Change::MemberAdded, &k, Some(&user), revision, true, &[]).await?;
                    report.added += 1;
                }
            }
            let mut gone: Vec<(&String, &Option<i64>)> =
                current.iter().filter(|(id, _)| !wanted.contains_key(*id)).map(|(id, (p, _))| (id, p)).collect();
            gone.sort();
            for (id, pending) in gone {
                let expired = match pending {
                    _ if grace_secs == 0 => true,
                    None => false,
                    Some(at) => secs - at >= i64::try_from(grace_secs).unwrap_or(i64::MAX),
                };
                if expired {
                    tx.execute("DELETE FROM group_members WHERE group_id = $1 AND user_id = $2", &[id, &user])
                        .await
                        .map_err(pg)?;
                    let revision = bump(&tx, id, secs).await?;
                    let k = GroupKey { id, source: src, provider: Some(pid) };
                    j.record(&tx, Change::MemberRemoved, &k, Some(&user), revision, true, &[]).await?;
                    report.removed += 1;
                } else {
                    if pending.is_none() {
                        tx.execute(
                            "UPDATE group_members SET removal_pending_at = $3 WHERE group_id = $1 AND user_id = $2",
                            &[id, &user, &secs],
                        )
                        .await
                        .map_err(pg)?;
                    }
                    report.pending += 1;
                }
            }
            if memberships_of(&tx, &user).await? > settings.max_groups_per_user as i64 {
                // Dropped transaction: nothing of this assertion is applied.
                return Ok(SyncReport { refused: Some("too_many_groups"), ..SyncReport::default() });
            }
            j.mirror(&tx, settings.gateway_header).await?;
            check_deadline(deadline)?;
            self.insert_events(&tx, &j.events).await?;
            check_deadline(deadline)?;
            tx.commit().await.map_err(pg)?;
            Ok(report)
        })
        .await
        .map_err(deadline_err)
    }

    async fn groups_maintenance(
        &self,
        grace: HashMap<String, u64>,
        stale_before: i64,
        suspend_before: i64,
        journal_before: i64,
        settings: WritePolicy,
        template: Event,
        deadline: Deadline,
    ) -> StoreResult<MaintenanceReport> {
        super::retry(|| async {
            let mut client = self.client().await?;
            let tx = self.begin_groups(&mut client, deadline).await?;
            let now = self.now();
            let secs = now.secs();
            let mut report = MaintenanceReport::default();
            let mut j = Journal { store: self, template: template.clone(), events: Vec::new(), now, touched_users: BTreeSet::new() };
            let mut doomed: Vec<(MemberRow, &'static str)> = Vec::new();
            let rows = tx
                .query(
                    &format!(
                        "SELECT {MEMBER_COLS}, (p.deleted_at IS NOT NULL OR p.provider_id IS NULL) FROM group_members gm \
                         LEFT JOIN providers p ON p.provider_id = gm.provider_id \
                         WHERE (gm.expires_at IS NOT NULL AND gm.expires_at <= $1) OR gm.removal_pending_at IS NOT NULL \
                            OR (gm.provider_id IS NOT NULL AND (p.provider_id IS NULL OR p.deleted_at IS NOT NULL)) \
                         ORDER BY gm.group_id, gm.user_id LIMIT $2"
                    ),
                    &[&secs, &MAINTENANCE_BATCH],
                )
                .await
                .map_err(pg)?;
            for r in &rows {
                let m = member_row(r, 0);
                let gone_provider: bool = r.get(11);
                if m.source == "local" {
                    if m.expires_at.is_some_and(|e| e <= secs) {
                        doomed.push((m, "expired"));
                    }
                } else if gone_provider {
                    doomed.push((m, "provider_deleted"));
                } else if let (Some(at), Some(g)) = (m.removal_pending_at, m.provider_id.as_ref().and_then(|p| grace.get(p)))
                    && secs - at >= i64::try_from(*g).unwrap_or(i64::MAX)
                {
                    doomed.push((m, "grace_elapsed"));
                }
            }
            for (m, cause) in &doomed {
                check_deadline(deadline)?;
                tx.execute("DELETE FROM group_members WHERE group_id = $1 AND user_id = $2", &[&m.group_id, &m.user_id])
                    .await
                    .map_err(pg)?;
                let revision = bump(&tx, &m.group_id, secs).await?;
                let k = GroupKey { id: &m.group_id, source: &m.source, provider: m.provider_id.as_deref() };
                j.record(&tx, Change::MemberRemoved, &k, Some(&m.user_id), revision, true, &[("cause", (*cause).into())]).await?;
                match *cause {
                    "expired" => report.expired += 1,
                    "grace_elapsed" => report.grace_removed += 1,
                    _ => report.orphaned += 1,
                }
            }
            let stale_members: Vec<MemberRow> = tx
                .query(
                    &format!(
                        "SELECT {MEMBER_COLS} FROM group_members gm WHERE gm.source <> 'local' AND gm.stale_at IS NULL AND gm.last_seen_at < $1 \
                         ORDER BY gm.group_id, gm.user_id LIMIT $2"
                    ),
                    &[&suspend_before, &MAINTENANCE_BATCH],
                )
                .await
                .map_err(pg)?
                .iter()
                .map(|r| member_row(r, 0))
                .collect();
            for m in &stale_members {
                check_deadline(deadline)?;
                tx.execute(
                    "UPDATE group_members SET stale_at = $3 WHERE group_id = $1 AND user_id = $2",
                    &[&m.group_id, &m.user_id, &secs],
                )
                .await
                .map_err(pg)?;
                let revision = bump(&tx, &m.group_id, secs).await?;
                let k = GroupKey { id: &m.group_id, source: &m.source, provider: m.provider_id.as_deref() };
                j.record(&tx, Change::MemberSuspended, &k, Some(&m.user_id), revision, true, &[("cause", "stale".into())]).await?;
                report.suspended += 1;
            }
            report.stale_total = tx
                .query_one("SELECT count(*) FROM group_members WHERE stale_at IS NOT NULL", &[])
                .await
                .map_err(pg)?
                .get(0);
            let stale: Vec<GroupRow> = tx
                .query(
                    &format!(
                        "SELECT {GROUP_COLS} FROM directory_groups g LEFT JOIN providers p ON p.provider_id = g.provider_id \
                         WHERE g.state = 'active' AND g.source <> 'local' \
                           AND NOT EXISTS (SELECT 1 FROM group_members m WHERE m.group_id = g.group_id) \
                           AND (COALESCE(g.last_seen_at, g.created_at) < $1 OR p.provider_id IS NULL OR p.deleted_at IS NOT NULL) \
                         ORDER BY g.group_id LIMIT $2"
                    ),
                    &[&stale_before, &MAINTENANCE_BATCH],
                )
                .await
                .map_err(pg)?
                .iter()
                .map(|r| group_row(r, 0))
                .collect();
            for g in &stale {
                check_deadline(deadline)?;
                delete_group(&tx, &mut j, g, deadline, &[("cause", "stale".into())]).await?;
                report.stale_groups += 1;
            }
            let pruned = tx
                .execute(
                    "DELETE FROM group_changes WHERE revision IN (SELECT revision FROM group_changes WHERE at < $1 \
                       AND revision < (SELECT max(revision) FROM group_changes) ORDER BY revision LIMIT $2)",
                    &[&journal_before, &(MAINTENANCE_BATCH * 10)],
                )
                .await
                .map_err(pg)?;
            report.journal_pruned = u32::try_from(pruned).unwrap_or(u32::MAX);
            j.mirror(&tx, settings.gateway_header).await?;
            check_deadline(deadline)?;
            self.insert_events(&tx, &j.events).await?;
            check_deadline(deadline)?;
            tx.commit().await.map_err(pg)?;
            Ok(report)
        })
        .await
        .map_err(deadline_err)
    }

    async fn groups_list(
        &self,
        q: Option<String>,
        source: Option<Source>,
        provider: Option<String>,
        include_deleted: bool,
        after: Option<(i64, String)>,
        limit: usize,
        deadline: Deadline,
    ) -> StoreResult<(Vec<GroupRow>, bool)> {
        let limit = limit.min(MAX_PAGE);
        let out = async {
            let mut client = self.client().await?;
            let tx = self.read_within(&mut client, deadline).await?;
            let (after_at, after_id) = after.clone().unwrap_or((i64::MIN, String::new()));
            let like = q.as_deref().map(escape_like);
            // SQLite's LIKE ignores ASCII case: ILIKE here.
            let mut rows: Vec<GroupRow> = tx
                .query(
                    &format!(
                        "SELECT {GROUP_COLS} FROM directory_groups g \
                         WHERE ($1::text IS NULL OR g.name ILIKE '%' || $1 || '%' ESCAPE '\\' OR g.external_key ILIKE $1 || '%' ESCAPE '\\' OR g.group_id = $6) \
                           AND ($2::text IS NULL OR g.source = $2) AND ($3::text IS NULL OR g.provider_id = $3) AND ($4 OR g.state = 'active') \
                           AND (g.created_at > $5 OR (g.created_at = $5 AND g.group_id > $7)) \
                         ORDER BY g.created_at, g.group_id LIMIT $8"
                    ),
                    &[&like, &source.map(Source::as_str), &provider, &include_deleted, &after_at, &q, &after_id, &((limit + 1) as i64)],
                )
                .await
                .map_err(pg)?
                .iter()
                .map(|r| group_row(r, 0))
                .collect();
            tx.commit().await.map_err(pg)?;
            let more = rows.len() > limit;
            rows.truncate(limit);
            Ok((rows, more))
        }
        .await;
        out.map_err(deadline_err)
    }

    async fn group_get(&self, id: String, deadline: Deadline) -> StoreResult<Option<GroupRow>> {
        let out = async {
            let mut client = self.client().await?;
            let tx = self.read_within(&mut client, deadline).await?;
            let g = group_by_id(&tx, &id).await?;
            tx.commit().await.map_err(pg)?;
            Ok(g)
        }
        .await;
        out.map_err(deadline_err)
    }

    async fn group_members(
        &self,
        id: String,
        after: Option<String>,
        limit: usize,
        now: i64,
        deadline: Deadline,
    ) -> StoreResult<(Vec<MemberRow>, bool)> {
        let limit = limit.min(MAX_PAGE);
        let out = async {
            let mut client = self.client().await?;
            let tx = self.read_within(&mut client, deadline).await?;
            let mut rows: Vec<MemberRow> = tx
                .query(
                    &format!(
                        "SELECT {MEMBER_COLS} FROM group_members gm WHERE gm.group_id = $1 AND gm.user_id > $2 \
                           AND (gm.expires_at IS NULL OR gm.expires_at > $3) ORDER BY gm.user_id LIMIT $4"
                    ),
                    &[&id, &after.clone().unwrap_or_default(), &now, &((limit + 1) as i64)],
                )
                .await
                .map_err(pg)?
                .iter()
                .map(|r| member_row(r, 0))
                .collect();
            tx.commit().await.map_err(pg)?;
            let more = rows.len() > limit;
            rows.truncate(limit);
            Ok((rows, more))
        }
        .await;
        out.map_err(deadline_err)
    }

    async fn groups_of_users(
        &self,
        users: Vec<String>,
        after: Option<String>,
        limit: usize,
        now: i64,
        deadline: Deadline,
    ) -> StoreResult<GroupsOfUsers> {
        if users.len() > crate::store::sqlite::subject_directory::MAX_BATCH {
            return Err(StoreError::Conflict("directory batch too large"));
        }
        let limit = limit.min(MAX_PAGE);
        let out = async {
            let mut client = self.client().await?;
            let tx = self.read_within(&mut client, deadline).await?;
            let sql = format!(
                "SELECT {MEMBER_COLS}, {GROUP_COLS} FROM group_members gm JOIN directory_groups g ON g.group_id = gm.group_id \
                 WHERE gm.user_id = $1 AND g.state = 'active' AND gm.group_id > $2 AND (gm.expires_at IS NULL OR gm.expires_at > $3) \
                 ORDER BY gm.group_id LIMIT $4"
            );
            let mut out = BTreeMap::new();
            for u in &users {
                check_deadline(deadline)?;
                let mut rows: Vec<(MemberRow, GroupRow)> = tx
                    .query(&sql, &[u, &after.clone().unwrap_or_default(), &now, &((limit + 1) as i64)])
                    .await
                    .map_err(pg)?
                    .iter()
                    .map(|r| (member_row(r, 0), group_row(r, 11)))
                    .collect();
                let more = rows.len() > limit;
                rows.truncate(limit);
                out.insert(u.clone(), (rows, more));
            }
            tx.commit().await.map_err(pg)?;
            Ok(out)
        }
        .await;
        out.map_err(deadline_err)
    }

    async fn groups_journal_bounds(&self, deadline: Deadline) -> StoreResult<(i64, Option<i64>)> {
        let out = async {
            let mut client = self.client().await?;
            let tx = self.read_within(&mut client, deadline).await?;
            let b = journal_bounds(&tx).await?;
            tx.commit().await.map_err(pg)?;
            Ok(b)
        }
        .await;
        out.map_err(deadline_err)
    }

    async fn groups_projection_snapshot(
        &self,
        vocabulary: Vec<String>,
        after: Option<String>,
        limit: usize,
        now: i64,
        deadline: Deadline,
    ) -> StoreResult<(Vec<SnapshotEntry>, bool)> {
        let limit = limit.min(MAX_PAGE);
        let out = async {
            let mut client = self.client().await?;
            let tx = self.read_within(&mut client, deadline).await?;
            // At most `limit` people plus one, and the reference bound plus one.
            let cap = i64::try_from(MAX_PAGE_REFS + 1).unwrap_or(i64::MAX);
            let rows = tx
                .query(
                    "SELECT gm.user_id, u.status, gm.group_id FROM group_members gm \
                     JOIN directory_groups g ON g.group_id = gm.group_id AND g.state = 'active' JOIN users u ON u.user_id = gm.user_id \
                     WHERE gm.group_id = ANY($1) AND gm.user_id > $2 AND (gm.expires_at IS NULL OR gm.expires_at > $3) AND gm.stale_at IS NULL \
                     ORDER BY gm.user_id, gm.group_id LIMIT $4",
                    &[&vocabulary, &after.clone().unwrap_or_default(), &now, &cap],
                )
                .await
                .map_err(pg)?;
            tx.commit().await.map_err(pg)?;
            let cut = rows.len() as i64 == cap;
            let mut out: Vec<SnapshotEntry> = Vec::new();
            let mut more = false;
            for (i, r) in rows.iter().enumerate() {
                let n = i + 1;
                let (user, status, group): (String, String, String) = (r.get(0), r.get(1), r.get(2));
                match out.last_mut() {
                    Some(last) if last.user_id == user => last.groups.push(group),
                    _ => {
                        if out.len() == limit || n > MAX_PAGE_REFS {
                            more = true;
                            break;
                        }
                        out.push(SnapshotEntry { user_id: user, status, groups: vec![group] });
                    }
                }
            }
            if cut && !more {
                // The row bound may have cut the last person's list: never
                // hand out a partial one (a person holds far fewer groups
                // than the bound, so at least one complete entry remains).
                out.pop();
                more = true;
            }
            Ok((out, more))
        }
        .await;
        out.map_err(deadline_err)
    }

    async fn groups_projection_changes(
        &self,
        vocabulary: Vec<String>,
        after: i64,
        limit: usize,
        deadline: Deadline,
    ) -> StoreResult<Result<JournalPage, RevisionLost>> {
        let limit = limit.min(MAX_PAGE);
        let out = async {
            let mut client = self.client().await?;
            let tx = self.read_within(&mut client, deadline).await?;
            let (head, oldest) = journal_bounds(&tx).await?;
            if after < 0 || after > head || (after < head && oldest.is_none_or(|o| after + 1 < o)) {
                return Ok(Err(RevisionLost));
            }
            let vocab: HashSet<String> = vocabulary.iter().cloned().collect();
            let rows = tx
                .query(
                    "SELECT revision, at, change, group_id, user_id FROM group_changes WHERE revision > $1 ORDER BY revision LIMIT $2",
                    &[&after, &JOURNAL_SCAN],
                )
                .await
                .map_err(pg)?;
            tx.commit().await.map_err(pg)?;
            let mut changes = Vec::new();
            let mut next = after;
            for r in &rows {
                let row = JournalRow {
                    revision: r.get(0),
                    at: r.get(1),
                    change: r.get(2),
                    group_id: r.get(3),
                    user_id: r.get(4),
                };
                if vocab.contains(&row.group_id) {
                    if changes.len() == limit {
                        break;
                    }
                    next = row.revision;
                    changes.push(row);
                } else {
                    next = row.revision;
                }
            }
            Ok(Ok(JournalPage { changes, next, head }))
        }
        .await;
        out.map_err(deadline_err)
    }

    async fn groups_sync_batch(
        &self,
        provider: String,
        interval_secs: u64,
        batch: usize,
        deadline: Deadline,
    ) -> StoreResult<Option<Vec<(String, String)>>> {
        super::retry(|| async {
            let mut client = self.client().await?;
            // One cursor holder at a time, whichever replica's scheduler asks.
            let tx = self.begin_groups(&mut client, deadline).await?;
            let now = self.now().secs();
            let state = tx
                .query_opt(
                    "SELECT cursor_subject, last_run_at FROM group_sync_state WHERE provider_id = $1",
                    &[&provider],
                )
                .await
                .map_err(pg)?
                .map(|r| (r.get::<_, Option<String>>(0), r.get::<_, Option<i64>>(1)));
            let (cursor, started) = state.unwrap_or((None, None));
            if cursor.is_none()
                && started.is_some_and(|s| now - s < i64::try_from(interval_secs).unwrap_or(i64::MAX))
            {
                return Ok(None);
            }
            let rows: Vec<(String, String)> = tx
                .query(
                    "SELECT subject, user_id FROM identities WHERE provider_id = $1 AND subject > $2 ORDER BY subject LIMIT $3",
                    &[&provider, &cursor.clone().unwrap_or_default(), &(batch as i64)],
                )
                .await
                .map_err(pg)?
                .iter()
                .map(|r| (r.get(0), r.get(1)))
                .collect();
            let next = if rows.len() < batch { None } else { rows.last().map(|r| r.0.clone()) };
            let started = if cursor.is_none() { now } else { started.unwrap_or(now) };
            tx.execute(
                "INSERT INTO group_sync_state (provider_id, cursor_subject, last_run_at) VALUES ($1, $2, $3) \
                 ON CONFLICT (provider_id) DO UPDATE SET cursor_subject = $2, last_run_at = $3",
                &[&provider, &next, &started],
            )
            .await
            .map_err(pg)?;
            check_deadline(deadline)?;
            tx.commit().await.map_err(pg)?;
            Ok(Some(rows))
        })
        .await
        .map_err(deadline_err)
    }

    async fn groups_sync_result(
        &self,
        provider: String,
        error: Option<&'static str>,
        deadline: Deadline,
    ) -> StoreResult<()> {
        super::retry(|| async {
            check_deadline(deadline)?;
            let mut client = self.client().await?;
            let tx = self.begin(&mut client).await?;
            let now = self.now().secs();
            tx.execute(
                "INSERT INTO group_sync_state (provider_id, last_ok_at, last_error) VALUES ($1, CASE WHEN $2::text IS NULL THEN $3::bigint END, $2) \
                 ON CONFLICT (provider_id) DO UPDATE SET last_error = $2, last_ok_at = CASE WHEN $2::text IS NULL THEN $3::bigint ELSE group_sync_state.last_ok_at END",
                &[&provider, &error, &now],
            )
            .await
            .map_err(pg)?;
            tx.commit().await.map_err(pg)
        })
        .await
        .map_err(deadline_err)
    }
}
