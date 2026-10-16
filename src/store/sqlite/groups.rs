//! Groups, memberships and the membership-projection journal (ADR-0018).
//!
//! Every write runs in one `BEGIN IMMEDIATE` transaction that also appends
//! the projection journal rows (`group_changes`) and the required `group.*`
//! events, so a change, its journal entry and its audit record commit or
//! vanish together. Administrator writes are fenced like every console
//! mutation; provider syncs check the provider row is still live.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use rusqlite::{OptionalExtension, Row, Transaction, params};

use super::admin::{before_commit, begin_fenced};
use super::events::insert_events;
use super::{Check, Shared, Store, commit_checked, require_provider_live};
use crate::crypto::{Timestamp, time_ordered_id};
use crate::event::types::{Event, EventId, EventKind};
use crate::groups::Source;
use crate::groups::config::{GATEWAY_HEADER_MAX, Mapped};
use crate::identity::types::UserId;
use crate::provider::types::ProviderId;
use crate::store::types::{Actor, ActorPolicy};
use crate::store::{Deadline, StoreError, StoreResult};

/// Most local groups (live) a store holds.
pub const MAX_LOCAL_GROUPS: i64 = 10_000;
/// Most members of one local group.
pub const MAX_LOCAL_MEMBERS: i64 = 50_000;
/// Most rows any listing returns per call.
pub const MAX_PAGE: usize = 500;
/// Most journal rows one projection feed page examines.
pub const JOURNAL_SCAN: i64 = 20_000;
/// Most group references one projection snapshot page carries (a bound on
/// the signed payload: about 1.6 MiB of references).
pub const MAX_PAGE_REFS: usize = 50_000;
/// Most rows one maintenance step touches.
const MAINTENANCE_BATCH: i64 = 1_000;

const GROUP_COLS: &str = "g.group_id, g.source, g.provider_id, g.external_key, g.name, g.description, g.state, g.revision, g.created_at, g.updated_at, g.last_seen_at, g.deleted_at, (SELECT COUNT(*) FROM group_members m WHERE m.group_id = g.group_id)";
const MEMBER_COLS: &str = "gm.group_id, gm.user_id, gm.source, gm.provider_id, gm.first_seen_at, gm.last_seen_at, gm.expires_at, gm.removal_pending_at, gm.added_by, gm.reason";

/// One group as stored.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct GroupRow {
    pub group_id: String,
    pub source: String,
    pub provider_id: Option<String>,
    pub external_key: String,
    pub name: String,
    pub description: Option<String>,
    pub state: String,
    pub revision: i64,
    pub created_at: i64,
    pub updated_at: i64,
    pub last_seen_at: Option<i64>,
    pub deleted_at: Option<i64>,
    pub members: i64,
}

/// One membership as stored.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct MemberRow {
    pub group_id: String,
    pub user_id: String,
    pub source: String,
    pub provider_id: Option<String>,
    pub first_seen_at: i64,
    pub last_seen_at: i64,
    pub expires_at: Option<i64>,
    pub removal_pending_at: Option<i64>,
    pub added_by: Option<String>,
    pub reason: Option<String>,
}

fn group_row(r: &Row<'_>) -> rusqlite::Result<GroupRow> {
    Ok(GroupRow {
        group_id: r.get(0)?,
        source: r.get(1)?,
        provider_id: r.get(2)?,
        external_key: r.get(3)?,
        name: r.get(4)?,
        description: r.get(5)?,
        state: r.get(6)?,
        revision: r.get(7)?,
        created_at: r.get(8)?,
        updated_at: r.get(9)?,
        last_seen_at: r.get(10)?,
        deleted_at: r.get(11)?,
        members: r.get(12)?,
    })
}

fn member_row(r: &Row<'_>, o: usize) -> rusqlite::Result<MemberRow> {
    Ok(MemberRow {
        group_id: r.get(o)?,
        user_id: r.get(o + 1)?,
        source: r.get(o + 2)?,
        provider_id: r.get(o + 3)?,
        first_seen_at: r.get(o + 4)?,
        last_seen_at: r.get(o + 5)?,
        expires_at: r.get(o + 6)?,
        removal_pending_at: r.get(o + 7)?,
        added_by: r.get(o + 8)?,
        reason: r.get(o + 9)?,
    })
}

/// The answer of an administrator write.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Cas<T> {
    Done(T),
    NotFound,
    /// The group is a tombstone.
    Deleted,
    /// The group is provider-synced: only its provider's sync writes it.
    NotLocal,
    /// `expected_revision` is not the current one.
    Stale(i64),
    /// A state conflict, named: `key_in_use`, `already_member`,
    /// `not_member`, `unknown_user`, `too_many_groups`, `group_full`,
    /// `too_many_local_groups`.
    Conflict(&'static str),
}

/// What an administrator write changes.
#[derive(Clone, Debug)]
pub enum Edit {
    Create {
        group_id: String,
        key: String,
        name: String,
        description: Option<String>,
    },
    Update {
        group_id: String,
        expected: i64,
        name: Option<String>,
        /// `Some(None)` clears the description.
        description: Option<Option<String>>,
    },
    Delete {
        group_id: String,
        expected: i64,
    },
    AddMember {
        group_id: String,
        expected: i64,
        user_id: String,
        expires_at: Option<i64>,
        reason: String,
    },
    RemoveMember {
        group_id: String,
        expected: i64,
        user_id: String,
    },
}

/// A sync's outcome for one person and provider.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SyncReport {
    pub added: u32,
    pub removed: u32,
    /// Memberships the provider stopped reporting, kept within the grace.
    pub pending: u32,
    pub groups_created: u32,
    pub groups_renamed: u32,
    /// `Some(reason)`: nothing was applied.
    pub refused: Option<&'static str>,
}

/// What the maintenance pass did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MaintenanceReport {
    pub expired: u32,
    pub grace_removed: u32,
    pub orphaned: u32,
    pub stale_groups: u32,
    pub journal_pruned: u32,
}

/// The settings a write needs from the configuration.
#[derive(Clone, Copy, Debug)]
pub struct WritePolicy {
    pub max_groups_per_user: usize,
    pub gateway_header: bool,
}

/// One projection journal row.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct JournalRow {
    pub revision: i64,
    pub at: i64,
    pub change: String,
    pub group_id: String,
    pub user_id: Option<String>,
}

/// One page of the projection journal.
#[derive(Clone, Debug)]
pub struct JournalPage {
    pub changes: Vec<JournalRow>,
    /// The revision the next page starts after.
    pub next: i64,
    pub head: i64,
}

/// The journal no longer holds the asked revision (pruned, or a different
/// store): the consumer takes a new snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RevisionLost;

/// One person's memberships in a projection snapshot page.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotEntry {
    pub user_id: String,
    pub status: String,
    pub groups: Vec<String>,
}

// ---- journal and events inside a transaction -------------------------------

struct Journal<'a> {
    shared: &'a Shared,
    template: Event,
    events: Vec<Event>,
    now: Timestamp,
    touched_users: BTreeSet<String>,
}

#[derive(Clone, Copy)]
enum Change {
    GroupCreated,
    GroupUpdated,
    GroupDeleted,
    MemberAdded,
    MemberRemoved,
}

impl Change {
    fn name(self) -> &'static str {
        match self {
            Change::GroupCreated => "group_created",
            Change::GroupUpdated => "group_updated",
            Change::GroupDeleted => "group_deleted",
            Change::MemberAdded => "member_added",
            Change::MemberRemoved => "member_removed",
        }
    }

    fn kind(self) -> EventKind {
        match self {
            Change::GroupCreated => EventKind::GroupCreated,
            Change::GroupUpdated => EventKind::GroupUpdated,
            Change::GroupDeleted => EventKind::GroupDeleted,
            Change::MemberAdded => EventKind::GroupMemberAdded,
            Change::MemberRemoved => EventKind::GroupMemberRemoved,
        }
    }
}

struct GroupKey<'a> {
    id: &'a str,
    source: &'a str,
    provider: Option<&'a str>,
}

impl Journal<'_> {
    /// Journal one change and queue its event. `event` decides whether the
    /// change gets its own audit event (a group deletion records one event
    /// for the group, not one per removed member).
    #[allow(clippy::too_many_arguments)]
    fn record(
        &mut self,
        tx: &Transaction<'_>,
        change: Change,
        group: &GroupKey<'_>,
        user: Option<&str>,
        revision: i64,
        event: bool,
        extra: &[(&str, serde_json::Value)],
    ) -> StoreResult<()> {
        tx.execute(
            "INSERT INTO group_changes (at, change, group_id, user_id) VALUES (?1, ?2, ?3, ?4)",
            params![self.now.secs(), change.name(), group.id, user],
        )?;
        if let Some(u) = user {
            self.touched_users.insert(u.to_string());
        }
        if !event {
            return Ok(());
        }
        let mut ev = self.template.clone();
        ev.event_id = EventId::new(time_ordered_id(self.shared.rng().as_ref(), "e_", self.now));
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
    /// (or clear them when the gateway header is off), bumping
    /// `authz_version` only when the value changes.
    fn mirror(&self, tx: &Transaction<'_>, enabled: bool) -> StoreResult<()> {
        for user in &self.touched_users {
            let refs: Vec<String> = if enabled {
                let mut st = tx.prepare_cached(
                    "SELECT gm.group_id FROM group_members gm JOIN directory_groups g ON g.group_id = gm.group_id
                     WHERE gm.user_id = ?1 AND g.state = 'active' ORDER BY gm.group_id LIMIT ?2",
                )?;
                st.query_map(params![user, GATEWAY_HEADER_MAX as i64], |r| r.get(0))?
                    .collect::<Result<_, _>>()?
            } else {
                Vec::new()
            };
            let value =
                serde_json::to_string(&refs).map_err(|_| StoreError::Conflict("group mirror"))?;
            tx.execute(
                "UPDATE users SET groups = ?2, authz_version = authz_version + 1, updated_at = ?3
                 WHERE user_id = ?1 AND groups <> ?2",
                params![user, value, self.now.secs()],
            )?;
        }
        Ok(())
    }
}

fn group_by_id(tx: &rusqlite::Connection, id: &str) -> StoreResult<Option<GroupRow>> {
    let sql = format!("SELECT {GROUP_COLS} FROM directory_groups g WHERE g.group_id = ?1");
    Ok(tx.query_row(&sql, [id], group_row).optional()?)
}

fn user_exists(tx: &rusqlite::Connection, user: &str) -> StoreResult<bool> {
    Ok(tx
        .query_row("SELECT 1 FROM users WHERE user_id = ?1", [user], |_| Ok(()))
        .optional()?
        .is_some())
}

fn memberships_of(tx: &rusqlite::Connection, user: &str) -> StoreResult<i64> {
    Ok(tx.query_row(
        "SELECT COUNT(*) FROM group_members gm JOIN directory_groups g ON g.group_id = gm.group_id
         WHERE gm.user_id = ?1 AND g.state = 'active'",
        [user],
        |r| r.get(0),
    )?)
}

fn bump(tx: &Transaction<'_>, id: &str, now: i64) -> StoreResult<i64> {
    Ok(tx.query_row(
        "UPDATE directory_groups SET revision = revision + 1, updated_at = ?2 WHERE group_id = ?1 RETURNING revision",
        params![id, now],
        |r| r.get(0),
    )?)
}

/// Check a group for an administrator write: present, live, local and at the
/// expected revision.
fn local_at(
    tx: &rusqlite::Connection,
    id: &str,
    expected: i64,
) -> StoreResult<Result<GroupRow, Cas<()>>> {
    let Some(g) = group_by_id(tx, id)? else {
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

/// Remove every member of a group (journaled, no per-member event).
fn remove_all(
    tx: &Transaction<'_>,
    j: &mut Journal<'_>,
    g: &GroupRow,
    revision: i64,
    check: &Check,
) -> StoreResult<u32> {
    let users: Vec<String> = {
        let mut st = tx.prepare_cached("SELECT user_id FROM group_members WHERE group_id = ?1")?;
        st.query_map([&g.group_id], |r| r.get(0))?
            .collect::<Result<_, _>>()?
    };
    let key = GroupKey {
        id: &g.group_id,
        source: &g.source,
        provider: g.provider_id.as_deref(),
    };
    for (i, u) in users.iter().enumerate() {
        if i % 1024 == 0 {
            check.now()?;
        }
        j.record(
            tx,
            Change::MemberRemoved,
            &key,
            Some(u),
            revision,
            false,
            &[],
        )?;
    }
    tx.execute(
        "DELETE FROM group_members WHERE group_id = ?1",
        [&g.group_id],
    )?;
    Ok(u32::try_from(users.len()).unwrap_or(u32::MAX))
}

fn delete_group(
    tx: &Transaction<'_>,
    j: &mut Journal<'_>,
    g: &GroupRow,
    check: &Check,
    extra: &[(&str, serde_json::Value)],
) -> StoreResult<i64> {
    let now = j.now.secs();
    let revision: i64 = tx.query_row(
        "UPDATE directory_groups SET state = 'deleted', deleted_at = ?2, updated_at = ?2, revision = revision + 1
         WHERE group_id = ?1 RETURNING revision",
        params![g.group_id, now],
        |r| r.get(0),
    )?;
    let n = remove_all(tx, j, g, revision, check)?;
    let key = GroupKey {
        id: &g.group_id,
        source: &g.source,
        provider: g.provider_id.as_deref(),
    };
    let mut extra = extra.to_vec();
    extra.push(("count", n.into()));
    j.record(tx, Change::GroupDeleted, &key, None, revision, true, &extra)?;
    Ok(revision)
}

impl Store {
    /// One administrator write of a local group or its memberships, fenced on
    /// the actor and compare-and-swapped on the group revision. `template`
    /// is the audit event every resulting `group.*` event is built from.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn groups_admin_edit(
        &self,
        actor: &Actor,
        policy: &ActorPolicy,
        edit: Edit,
        settings: WritePolicy,
        template: Event,
        deadline: Deadline,
    ) -> StoreResult<Cas<GroupRow>> {
        let (actor, policy) = (actor.clone(), policy.clone());
        self.write_checked("groups_admin_edit", Some(deadline), move |env, check| {
            let (tx, shared) = begin_fenced(env, check, &actor, &policy)?;
            let now = shared.clock.now();
            let mut j = Journal {
                shared: &shared,
                template,
                events: Vec::new(),
                now,
                touched_users: BTreeSet::new(),
            };
            let note = |r: &str| ("note", serde_json::Value::from(r));
            let id = match edit {
                Edit::Create {
                    group_id,
                    key,
                    name,
                    description,
                } => {
                    let live: i64 = tx.query_row(
                        "SELECT COUNT(*) FROM directory_groups WHERE source = 'local' AND state = 'active'",
                        [],
                        |r| r.get(0),
                    )?;
                    if live >= MAX_LOCAL_GROUPS {
                        return Ok(Cas::Conflict("too_many_local_groups"));
                    }
                    let taken = tx
                        .query_row(
                            "SELECT 1 FROM directory_groups WHERE source = 'local' AND external_key = ?1 AND state = 'active'",
                            [&key],
                            |_| Ok(()),
                        )
                        .optional()?
                        .is_some();
                    if taken {
                        return Ok(Cas::Conflict("key_in_use"));
                    }
                    tx.execute(
                        "INSERT INTO directory_groups (group_id, source, provider_id, external_key, name, description, state, revision, created_at, updated_at)
                         VALUES (?1, 'local', NULL, ?2, ?3, ?4, 'active', 1, ?5, ?5)",
                        params![group_id, key, name, description, now.secs()],
                    )?;
                    let k = GroupKey { id: &group_id, source: "local", provider: None };
                    j.record(&tx, Change::GroupCreated, &k, None, 1, true, &[])?;
                    group_id
                }
                Edit::Update {
                    group_id,
                    expected,
                    name,
                    description,
                } => {
                    let g = match local_at(&tx, &group_id, expected)? {
                        Ok(g) => g,
                        Err(e) => return Ok(cas(e)),
                    };
                    let name = name.unwrap_or(g.name.clone());
                    let description = description.unwrap_or(g.description.clone());
                    if name == g.name && description == g.description {
                        return Ok(Cas::Done(g));
                    }
                    tx.execute(
                        "UPDATE directory_groups SET name = ?2, description = ?3 WHERE group_id = ?1",
                        params![group_id, name, description],
                    )?;
                    let revision = bump(&tx, &group_id, now.secs())?;
                    let k = GroupKey { id: &group_id, source: "local", provider: None };
                    let renamed = name != g.name;
                    j.record(&tx, Change::GroupUpdated, &k, None, revision, true, &[("change", if renamed { "renamed" } else { "described" }.into())])?;
                    group_id
                }
                Edit::Delete { group_id, expected } => {
                    let g = match local_at(&tx, &group_id, expected)? {
                        Ok(g) => g,
                        Err(e) => return Ok(cas(e)),
                    };
                    delete_group(&tx, &mut j, &g, check, &[])?;
                    group_id
                }
                Edit::AddMember {
                    group_id,
                    expected,
                    user_id,
                    expires_at,
                    reason,
                } => {
                    let g = match local_at(&tx, &group_id, expected)? {
                        Ok(g) => g,
                        Err(e) => return Ok(cas(e)),
                    };
                    if !user_exists(&tx, &user_id)? {
                        return Ok(Cas::Conflict("unknown_user"));
                    }
                    let member = tx
                        .query_row(
                            "SELECT 1 FROM group_members WHERE group_id = ?1 AND user_id = ?2",
                            params![group_id, user_id],
                            |_| Ok(()),
                        )
                        .optional()?
                        .is_some();
                    if member {
                        return Ok(Cas::Conflict("already_member"));
                    }
                    if g.members >= MAX_LOCAL_MEMBERS {
                        return Ok(Cas::Conflict("group_full"));
                    }
                    if memberships_of(&tx, &user_id)? >= settings.max_groups_per_user as i64 {
                        return Ok(Cas::Conflict("too_many_groups"));
                    }
                    tx.execute(
                        "INSERT INTO group_members (group_id, user_id, source, provider_id, first_seen_at, last_seen_at, expires_at, added_by, reason)
                         VALUES (?1, ?2, 'local', NULL, ?3, ?3, ?4, ?5, ?6)",
                        params![group_id, user_id, now.secs(), expires_at, actor.user_id.as_str(), reason],
                    )?;
                    let revision = bump(&tx, &group_id, now.secs())?;
                    let k = GroupKey { id: &group_id, source: "local", provider: None };
                    let mut extra = vec![note(&reason)];
                    if let Some(e) = expires_at {
                        extra.push(("expires_at", e.into()));
                    }
                    j.record(&tx, Change::MemberAdded, &k, Some(&user_id), revision, true, &extra)?;
                    group_id
                }
                Edit::RemoveMember {
                    group_id,
                    expected,
                    user_id,
                } => {
                    if let Err(e) = local_at(&tx, &group_id, expected)? {
                        return Ok(cas(e));
                    }
                    let n = tx.execute(
                        "DELETE FROM group_members WHERE group_id = ?1 AND user_id = ?2",
                        params![group_id, user_id],
                    )?;
                    if n == 0 {
                        return Ok(Cas::Conflict("not_member"));
                    }
                    let revision = bump(&tx, &group_id, now.secs())?;
                    let k = GroupKey { id: &group_id, source: "local", provider: None };
                    j.record(&tx, Change::MemberRemoved, &k, Some(&user_id), revision, true, &[])?;
                    group_id
                }
            };
            j.mirror(&tx, settings.gateway_header)?;
            check.now()?;
            insert_events(&tx, &shared, &j.events)?;
            let row = group_by_id(&tx, &id)?.ok_or(StoreError::Conflict("group vanished"))?;
            before_commit(&shared, check)?;
            commit_checked(tx, &shared, Some("groups_admin"), check)?;
            Ok(Cas::Done(row))
        })
        .await
    }

    /// Apply one provider assertion of a person's complete group set. Groups
    /// not yet known are created; renamed ones updated; memberships no
    /// longer asserted are removed after `grace_secs` (immediately at 0).
    /// A result above `max_groups_per_user` is refused and changes nothing.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn groups_sync_user(
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
        self.write_checked("groups_sync_user", Some(deadline), move |env, check| {
            let shared = env.shared.clone();
            let tx = env.begin()?;
            check.now()?;
            require_provider_live(&tx, provider.as_str())?;
            let user = user.as_str().to_string();
            if !user_exists(&tx, &user)? {
                return Err(StoreError::Conflict("unknown user"));
            }
            let now = shared.clock.now();
            let secs = now.secs();
            let src = source.as_str();
            let pid = provider.as_str();
            let mut report = SyncReport::default();
            let mut j = Journal {
                shared: &shared,
                template,
                events: Vec::new(),
                now,
                touched_users: BTreeSet::new(),
            };
            // The groups the assertion names, created or renamed as needed.
            let mut wanted: BTreeMap<String, String> = BTreeMap::new();
            for m in &asserted {
                let found: Option<(String, String)> = tx
                    .query_row(
                        "SELECT group_id, name FROM directory_groups WHERE source = ?1 AND provider_id = ?2 AND external_key = ?3 AND state = 'active'",
                        params![src, pid, m.key],
                        |r| Ok((r.get(0)?, r.get(1)?)),
                    )
                    .optional()?;
                let id = match found {
                    Some((id, name)) => {
                        if name != m.name {
                            tx.execute(
                                "UPDATE directory_groups SET name = ?2 WHERE group_id = ?1",
                                params![id, m.name],
                            )?;
                            let revision = bump(&tx, &id, secs)?;
                            let k = GroupKey { id: &id, source: src, provider: Some(pid) };
                            j.record(&tx, Change::GroupUpdated, &k, None, revision, true, &[("change", "renamed".into())])?;
                            report.groups_renamed += 1;
                        }
                        tx.execute(
                            "UPDATE directory_groups SET last_seen_at = ?2 WHERE group_id = ?1",
                            params![id, secs],
                        )?;
                        id
                    }
                    None => {
                        let id = crate::groups::new_ref(shared.rng().as_ref());
                        tx.execute(
                            "INSERT INTO directory_groups (group_id, source, provider_id, external_key, name, description, state, revision, created_at, updated_at, last_seen_at)
                             VALUES (?1, ?2, ?3, ?4, ?5, NULL, 'active', 1, ?6, ?6, ?6)",
                            params![id, src, pid, m.key, m.name, secs],
                        )?;
                        let k = GroupKey { id: &id, source: src, provider: Some(pid) };
                        j.record(&tx, Change::GroupCreated, &k, None, 1, true, &[])?;
                        report.groups_created += 1;
                        id
                    }
                };
                wanted.insert(id, m.key.clone());
            }
            check.now()?;
            // The person's current memberships from this provider.
            let current: HashMap<String, Option<i64>> = {
                let mut st = tx.prepare_cached(
                    "SELECT group_id, removal_pending_at FROM group_members WHERE user_id = ?1 AND source = ?2 AND provider_id = ?3",
                )?;
                st.query_map(params![user, src, pid], |r| Ok((r.get(0)?, r.get(1)?)))?
                    .collect::<Result<_, _>>()?
            };
            for id in wanted.keys() {
                let k = GroupKey { id, source: src, provider: Some(pid) };
                if current.contains_key(id) {
                    tx.execute(
                        "UPDATE group_members SET last_seen_at = ?3, removal_pending_at = NULL WHERE group_id = ?1 AND user_id = ?2",
                        params![id, user, secs],
                    )?;
                } else {
                    tx.execute(
                        "INSERT INTO group_members (group_id, user_id, source, provider_id, first_seen_at, last_seen_at)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?5)",
                        params![id, user, src, pid, secs],
                    )?;
                    let revision = bump(&tx, id, secs)?;
                    j.record(&tx, Change::MemberAdded, &k, Some(&user), revision, true, &[])?;
                    report.added += 1;
                }
            }
            for (id, pending) in &current {
                if wanted.contains_key(id) {
                    continue;
                }
                let expired = match pending {
                    _ if grace_secs == 0 => true,
                    None => false,
                    Some(at) => secs - at >= i64::try_from(grace_secs).unwrap_or(i64::MAX),
                };
                if expired {
                    tx.execute(
                        "DELETE FROM group_members WHERE group_id = ?1 AND user_id = ?2",
                        params![id, user],
                    )?;
                    let revision = bump(&tx, id, secs)?;
                    let k = GroupKey { id, source: src, provider: Some(pid) };
                    j.record(&tx, Change::MemberRemoved, &k, Some(&user), revision, true, &[])?;
                    report.removed += 1;
                } else {
                    if pending.is_none() {
                        tx.execute(
                            "UPDATE group_members SET removal_pending_at = ?3 WHERE group_id = ?1 AND user_id = ?2",
                            params![id, user, secs],
                        )?;
                    }
                    report.pending += 1;
                }
            }
            if memberships_of(&tx, &user)? > settings.max_groups_per_user as i64 {
                // Dropped transaction: nothing of this assertion is applied.
                return Ok(SyncReport {
                    refused: Some("too_many_groups"),
                    ..SyncReport::default()
                });
            }
            j.mirror(&tx, settings.gateway_header)?;
            check.now()?;
            insert_events(&tx, &shared, &j.events)?;
            commit_checked(tx, &shared, Some("groups_sync"), check)?;
            Ok(report)
        })
        .await
    }

    /// The maintenance pass: expired local memberships, provider memberships
    /// past their provider's grace (`grace` by provider ID; a provider not
    /// named keeps its pending memberships), memberships of tombstoned
    /// providers, stale provider groups and journal retention. Bounded per
    /// call; the report says what was done.
    pub(crate) async fn groups_maintenance(
        &self,
        grace: HashMap<String, u64>,
        stale_before: i64,
        journal_before: i64,
        settings: WritePolicy,
        template: Event,
        deadline: Deadline,
    ) -> StoreResult<MaintenanceReport> {
        self.write_checked("groups_maintenance", Some(deadline), move |env, check| {
            let shared = env.shared.clone();
            let tx = env.begin()?;
            check.now()?;
            let now = shared.clock.now();
            let secs = now.secs();
            let mut report = MaintenanceReport::default();
            let mut j = Journal {
                shared: &shared,
                template,
                events: Vec::new(),
                now,
                touched_users: BTreeSet::new(),
            };
            let mut doomed: Vec<(MemberRow, &'static str)> = Vec::new();
            {
                let sql = format!(
                    "SELECT {MEMBER_COLS}, p.deleted_at IS NOT NULL OR p.provider_id IS NULL FROM group_members gm
                     LEFT JOIN providers p ON p.provider_id = gm.provider_id
                     WHERE (gm.expires_at IS NOT NULL AND gm.expires_at <= ?1)
                        OR gm.removal_pending_at IS NOT NULL
                        OR (gm.provider_id IS NOT NULL AND (p.provider_id IS NULL OR p.deleted_at IS NOT NULL))
                     LIMIT ?2"
                );
                let mut st = tx.prepare(&sql)?;
                let mut q = st.query(params![secs, MAINTENANCE_BATCH])?;
                while let Some(r) = q.next()? {
                    let m = member_row(r, 0)?;
                    let gone_provider: bool = r.get(10)?;
                    if m.source == "local" {
                        if m.expires_at.is_some_and(|e| e <= secs) {
                            doomed.push((m, "expired"));
                        }
                    } else if gone_provider {
                        doomed.push((m, "provider_deleted"));
                    } else if let (Some(at), Some(g)) = (
                        m.removal_pending_at,
                        m.provider_id.as_ref().and_then(|p| grace.get(p)),
                    ) && secs - at >= i64::try_from(*g).unwrap_or(i64::MAX)
                    {
                        doomed.push((m, "grace_elapsed"));
                    }
                }
            }
            for (m, cause) in &doomed {
                check.now()?;
                tx.execute(
                    "DELETE FROM group_members WHERE group_id = ?1 AND user_id = ?2",
                    params![m.group_id, m.user_id],
                )?;
                let revision = bump(&tx, &m.group_id, secs)?;
                let k = GroupKey { id: &m.group_id, source: &m.source, provider: m.provider_id.as_deref() };
                j.record(&tx, Change::MemberRemoved, &k, Some(&m.user_id), revision, true, &[("cause", (*cause).into())])?;
                match *cause {
                    "expired" => report.expired += 1,
                    "grace_elapsed" => report.grace_removed += 1,
                    _ => report.orphaned += 1,
                }
            }
            // Provider groups with no member, unseen since `stale_before`, or
            // whose provider is gone.
            let stale: Vec<GroupRow> = {
                let sql = format!(
                    "SELECT {GROUP_COLS} FROM directory_groups g LEFT JOIN providers p ON p.provider_id = g.provider_id
                     WHERE g.state = 'active' AND g.source <> 'local'
                       AND NOT EXISTS (SELECT 1 FROM group_members m WHERE m.group_id = g.group_id)
                       AND (COALESCE(g.last_seen_at, g.created_at) < ?1 OR p.provider_id IS NULL OR p.deleted_at IS NOT NULL)
                     LIMIT ?2"
                );
                let mut st = tx.prepare(&sql)?;
                st.query_map(params![stale_before, MAINTENANCE_BATCH], group_row)?
                    .collect::<Result<_, _>>()?
            };
            for g in &stale {
                check.now()?;
                delete_group(&tx, &mut j, g, check, &[("cause", "stale".into())])?;
                report.stale_groups += 1;
            }
            let pruned = tx.execute(
                "DELETE FROM group_changes WHERE revision IN (
                     SELECT revision FROM group_changes WHERE at < ?1
                       AND revision < (SELECT MAX(revision) FROM group_changes)
                     ORDER BY revision LIMIT ?2)",
                params![journal_before, MAINTENANCE_BATCH * 10],
            )?;
            report.journal_pruned = u32::try_from(pruned).unwrap_or(u32::MAX);
            j.mirror(&tx, settings.gateway_header)?;
            check.now()?;
            insert_events(&tx, &shared, &j.events)?;
            commit_checked(tx, &shared, Some("groups_maintenance"), check)?;
            Ok(report)
        })
        .await
    }

    // ---- reads ---------------------------------------------------------------

    /// Groups by creation, after `(created_at, group_id)`, filtered.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn groups_list(
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
        self.read_checked("groups_list", Some(deadline), move |c, check| {
            let (after_at, after_id) = after.unwrap_or((i64::MIN, String::new()));
            let sql = format!(
                "SELECT {GROUP_COLS} FROM directory_groups g
                 WHERE (?1 IS NULL OR g.name LIKE '%' || ?1 || '%' ESCAPE '\\' OR g.external_key LIKE ?1 || '%' ESCAPE '\\' OR g.group_id = ?6)
                   AND (?2 IS NULL OR g.source = ?2)
                   AND (?3 IS NULL OR g.provider_id = ?3)
                   AND (?4 OR g.state = 'active')
                   AND (g.created_at > ?5 OR (g.created_at = ?5 AND g.group_id > ?7))
                 ORDER BY g.created_at, g.group_id LIMIT ?8"
            );
            let mut st = c.prepare_cached(&sql)?;
            let like = q.as_deref().map(escape_like);
            let mut rows = st
                .query_map(
                    params![
                        like,
                        source.map(Source::as_str),
                        provider,
                        include_deleted,
                        after_at,
                        q,
                        after_id,
                        (limit + 1) as i64
                    ],
                    group_row,
                )?
                .collect::<Result<Vec<_>, _>>()?;
            check.now()?;
            let more = rows.len() > limit;
            rows.truncate(limit);
            Ok((rows, more))
        })
        .await
    }

    /// One group, live or tombstoned.
    pub(crate) async fn group_get(
        &self,
        id: String,
        deadline: Deadline,
    ) -> StoreResult<Option<GroupRow>> {
        self.read_checked("group_get", Some(deadline), move |c, _| group_by_id(c, &id))
            .await
    }

    /// Members of a group after `after` (user ID order), effective at `now`.
    pub(crate) async fn group_members(
        &self,
        id: String,
        after: Option<String>,
        limit: usize,
        now: i64,
        deadline: Deadline,
    ) -> StoreResult<(Vec<MemberRow>, bool)> {
        let limit = limit.min(MAX_PAGE);
        self.read_checked("group_members", Some(deadline), move |c, _| {
            let sql = format!(
                "SELECT {MEMBER_COLS} FROM group_members gm WHERE gm.group_id = ?1 AND gm.user_id > ?2
                   AND (gm.expires_at IS NULL OR gm.expires_at > ?3)
                 ORDER BY gm.user_id LIMIT ?4"
            );
            let mut st = c.prepare_cached(&sql)?;
            let mut rows = st
                .query_map(
                    params![id, after.unwrap_or_default(), now, (limit + 1) as i64],
                    |r| member_row(r, 0),
                )?
                .collect::<Result<Vec<_>, _>>()?;
            let more = rows.len() > limit;
            rows.truncate(limit);
            Ok((rows, more))
        })
        .await
    }

    /// Up to `limit` live groups of each person (group ID order) and whether
    /// each list was cut, effective at `now`.
    pub(crate) async fn groups_of_users(
        &self,
        users: Vec<String>,
        after: Option<String>,
        limit: usize,
        now: i64,
        deadline: Deadline,
    ) -> StoreResult<BTreeMap<String, (Vec<(MemberRow, GroupRow)>, bool)>> {
        if users.len() > super::subject_directory::MAX_BATCH {
            return Err(StoreError::Conflict("directory batch too large"));
        }
        let limit = limit.min(MAX_PAGE);
        self.read_checked("groups_of_users", Some(deadline), move |c, check| {
            let sql = format!(
                "SELECT {MEMBER_COLS}, {GROUP_COLS} FROM group_members gm JOIN directory_groups g ON g.group_id = gm.group_id
                 WHERE gm.user_id = ?1 AND g.state = 'active' AND gm.group_id > ?2
                   AND (gm.expires_at IS NULL OR gm.expires_at > ?3)
                 ORDER BY gm.group_id LIMIT ?4"
            );
            let mut st = c.prepare_cached(&sql)?;
            let mut out = BTreeMap::new();
            for u in users {
                check.now()?;
                let mut rows = st
                    .query_map(
                        params![u, after.clone().unwrap_or_default(), now, (limit + 1) as i64],
                        |r| {
                            let m = member_row(r, 0)?;
                            let g = GroupRow {
                                group_id: r.get(10)?,
                                source: r.get(11)?,
                                provider_id: r.get(12)?,
                                external_key: r.get(13)?,
                                name: r.get(14)?,
                                description: r.get(15)?,
                                state: r.get(16)?,
                                revision: r.get(17)?,
                                created_at: r.get(18)?,
                                updated_at: r.get(19)?,
                                last_seen_at: r.get(20)?,
                                deleted_at: r.get(21)?,
                                members: r.get(22)?,
                            };
                            Ok((m, g))
                        },
                    )?
                    .collect::<Result<Vec<_>, _>>()?;
                let more = rows.len() > limit;
                rows.truncate(limit);
                out.insert(u, (rows, more));
            }
            Ok(out)
        })
        .await
    }

    /// The projection journal's head revision (0 when nothing was ever
    /// journaled) and its oldest kept revision.
    pub(crate) async fn groups_journal_bounds(
        &self,
        deadline: Deadline,
    ) -> StoreResult<(i64, Option<i64>)> {
        self.read_checked("groups_journal_bounds", Some(deadline), |c, _| {
            journal_bounds(c)
        })
        .await
    }

    /// Projection snapshot page: people (user ID order, after `after`) with
    /// their effective memberships in `vocabulary`.
    pub(crate) async fn groups_projection_snapshot(
        &self,
        vocabulary: Vec<String>,
        after: Option<String>,
        limit: usize,
        now: i64,
        deadline: Deadline,
    ) -> StoreResult<(Vec<SnapshotEntry>, bool)> {
        let limit = limit.min(MAX_PAGE);
        let vocab =
            serde_json::to_string(&vocabulary).map_err(|_| StoreError::Conflict("vocabulary"))?;
        self.read_checked(
            "groups_projection_snapshot",
            Some(deadline),
            move |c, check| {
                let mut st = c.prepare_cached(
                    "SELECT gm.user_id, u.status, gm.group_id FROM group_members gm
                 JOIN directory_groups g ON g.group_id = gm.group_id AND g.state = 'active'
                 JOIN users u ON u.user_id = gm.user_id
                 WHERE gm.group_id IN (SELECT value FROM json_each(?1)) AND gm.user_id > ?2
                   AND (gm.expires_at IS NULL OR gm.expires_at > ?3)
                 ORDER BY gm.user_id, gm.group_id",
                )?;
                let mut q = st.query(params![vocab, after.unwrap_or_default(), now])?;
                let mut out: Vec<SnapshotEntry> = Vec::new();
                let mut more = false;
                let mut n = 0usize;
                while let Some(r) = q.next()? {
                    n += 1;
                    if n.is_multiple_of(1024) {
                        check.now()?;
                    }
                    let (user, status, group): (String, String, String) =
                        (r.get(0)?, r.get(1)?, r.get(2)?);
                    match out.last_mut() {
                        Some(last) if last.user_id == user => last.groups.push(group),
                        _ => {
                            if out.len() == limit || n > MAX_PAGE_REFS {
                                more = true;
                                break;
                            }
                            out.push(SnapshotEntry {
                                user_id: user,
                                status,
                                groups: vec![group],
                            });
                        }
                    }
                }
                Ok((out, more))
            },
        )
        .await
    }

    /// Projection journal after `after`, restricted to `vocabulary`, at most
    /// `limit` changes and [`JOURNAL_SCAN`] rows examined.
    pub(crate) async fn groups_projection_changes(
        &self,
        vocabulary: Vec<String>,
        after: i64,
        limit: usize,
        deadline: Deadline,
    ) -> StoreResult<Result<JournalPage, RevisionLost>> {
        let limit = limit.min(MAX_PAGE);
        self.read_checked("groups_projection_changes", Some(deadline), move |c, check| {
            let (head, oldest) = journal_bounds(c)?;
            if after < 0 || after > head || (after < head && oldest.is_none_or(|o| after + 1 < o)) {
                return Ok(Err(RevisionLost));
            }
            let vocab: HashSet<String> = vocabulary.into_iter().collect();
            let mut st = c.prepare_cached(
                "SELECT revision, at, change, group_id, user_id FROM group_changes WHERE revision > ?1 ORDER BY revision LIMIT ?2",
            )?;
            let mut q = st.query(params![after, JOURNAL_SCAN])?;
            let mut changes = Vec::new();
            let mut next = after;
            let mut n = 0usize;
            while let Some(r) = q.next()? {
                n += 1;
                if n.is_multiple_of(1024) {
                    check.now()?;
                }
                let row = JournalRow {
                    revision: r.get(0)?,
                    at: r.get(1)?,
                    change: r.get(2)?,
                    group_id: r.get(3)?,
                    user_id: r.get(4)?,
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
        })
        .await
    }

    /// The next people of a provider's periodic sync: `(subject, user_id)` of
    /// linked identities after the saved cursor, when a cycle is due.
    /// `None` when the provider's interval has not elapsed since the cycle
    /// began.
    pub(crate) async fn groups_sync_batch(
        &self,
        provider: String,
        interval_secs: u64,
        batch: usize,
        deadline: Deadline,
    ) -> StoreResult<Option<Vec<(String, String)>>> {
        self.write_checked("groups_sync_batch", Some(deadline), move |env, check| {
            let shared = env.shared.clone();
            let tx = env.begin()?;
            check.now()?;
            let now = shared.clock.now().secs();
            let state: Option<(Option<String>, Option<i64>)> = tx
                .query_row(
                    "SELECT cursor_subject, last_run_at FROM group_sync_state WHERE provider_id = ?1",
                    [&provider],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            let (cursor, started) = state.unwrap_or((None, None));
            if cursor.is_none()
                && started.is_some_and(|s| now - s < i64::try_from(interval_secs).unwrap_or(i64::MAX))
            {
                return Ok(None);
            }
            let rows: Vec<(String, String)> = {
                let mut st = tx.prepare_cached(
                    "SELECT subject, user_id FROM identities WHERE provider_id = ?1 AND subject > ?2 ORDER BY subject LIMIT ?3",
                )?;
                st.query_map(
                    params![provider, cursor.clone().unwrap_or_default(), batch as i64],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )?
                .collect::<Result<_, _>>()?
            };
            let next = if rows.len() < batch { None } else { rows.last().map(|r| r.0.clone()) };
            let started = if cursor.is_none() { now } else { started.unwrap_or(now) };
            tx.execute(
                "INSERT INTO group_sync_state (provider_id, cursor_subject, last_run_at) VALUES (?1, ?2, ?3)
                 ON CONFLICT (provider_id) DO UPDATE SET cursor_subject = ?2, last_run_at = ?3",
                params![provider, next, started],
            )?;
            commit_checked(tx, &shared, None, check)?;
            Ok(Some(rows))
        })
        .await
    }

    /// Record the outcome of a periodic sync step (for status).
    pub(crate) async fn groups_sync_result(
        &self,
        provider: String,
        error: Option<&'static str>,
        deadline: Deadline,
    ) -> StoreResult<()> {
        self.write_checked("groups_sync_result", Some(deadline), move |env, check| {
            let shared = env.shared.clone();
            let tx = env.begin()?;
            let now = shared.clock.now().secs();
            tx.execute(
                "INSERT INTO group_sync_state (provider_id, last_ok_at, last_error) VALUES (?1, CASE WHEN ?2 IS NULL THEN ?3 END, ?2)
                 ON CONFLICT (provider_id) DO UPDATE SET last_error = ?2, last_ok_at = CASE WHEN ?2 IS NULL THEN ?3 ELSE last_ok_at END",
                params![provider, error, now],
            )?;
            commit_checked(tx, &shared, None, check)?;
            Ok(())
        })
        .await
    }
}

fn journal_bounds(c: &rusqlite::Connection) -> StoreResult<(i64, Option<i64>)> {
    let head: i64 = c
        .query_row(
            "SELECT seq FROM sqlite_sequence WHERE name = 'group_changes'",
            [],
            |r| r.get(0),
        )
        .optional()?
        .unwrap_or(0);
    let oldest: Option<i64> =
        c.query_row("SELECT MIN(revision) FROM group_changes", [], |r| r.get(0))?;
    Ok((head, oldest))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{Clock, OsRng, TestClock};
    use crate::event::types::{EventBuilder, Outcome};
    use std::sync::Arc;
    use std::time::Duration;

    const T0: i64 = 1_700_000_000_000;

    struct Fx {
        store: Store,
        clock: Arc<TestClock>,
        _dir: tempfile::TempDir,
    }

    fn fx() -> Fx {
        let dir = tempfile::tempdir().unwrap();
        let clock = Arc::new(TestClock::new(Timestamp(T0)));
        let store = Store::open(&dir.path().join("hopae.db"), clock.clone(), vec![], None).unwrap();
        for u in ["u_a", "u_b"] {
            store
                .conn()
                .execute(
                    "INSERT INTO users(user_id,created_at,updated_at) VALUES(?1,1,1)",
                    [u],
                )
                .unwrap();
        }
        store
            .conn()
            .execute(
                "INSERT INTO providers(provider_id,kind,display_name,enabled,managed_by,created_at,updated_at) VALUES('dir','ldap','Dir',1,'file',0,0)",
                [],
            )
            .unwrap();
        Fx {
            store,
            clock,
            _dir: dir,
        }
    }

    fn dl() -> Deadline {
        Deadline::after(Duration::from_secs(5))
    }

    fn tpl(clock: &TestClock) -> Event {
        EventBuilder::new(
            clock,
            &OsRng,
            EventKind::GroupMemberAdded,
            Outcome::Success,
            "r_t",
        )
        .attr("cause", "login")
        .build()
    }

    fn m(keys: &[&str]) -> Vec<Mapped> {
        keys.iter()
            .map(|k| Mapped {
                key: (*k).into(),
                name: k.to_uppercase(),
            })
            .collect()
    }

    const POLICY: WritePolicy = WritePolicy {
        max_groups_per_user: 3,
        gateway_header: false,
    };

    impl Fx {
        async fn sync(
            &self,
            user: &str,
            keys: &[&str],
            grace: u64,
            policy: WritePolicy,
        ) -> SyncReport {
            self.store
                .groups_sync_user(
                    ProviderId::new("dir"),
                    Source::Ldap,
                    UserId::new(user),
                    m(keys),
                    grace,
                    policy,
                    tpl(&self.clock),
                    dl(),
                )
                .await
                .unwrap()
        }

        fn keys(&self, user: &str) -> Vec<String> {
            let c = self.store.conn();
            let mut st = c
                .prepare("SELECT g.external_key FROM group_members gm JOIN directory_groups g ON g.group_id=gm.group_id WHERE gm.user_id=?1 ORDER BY 1")
                .unwrap();
            st.query_map([user], |r| r.get(0))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap()
        }

        fn count(&self, sql: &str) -> i64 {
            self.store.conn().query_row(sql, [], |r| r.get(0)).unwrap()
        }
    }

    #[tokio::test]
    async fn a_sync_creates_groups_adds_and_removes_memberships_and_journals_them() {
        let f = fx();
        let r = f.sync("u_a", &["cn=x", "cn=y"], 0, POLICY).await;
        assert_eq!((r.added, r.groups_created, r.removed), (2, 2, 0));
        assert_eq!(f.keys("u_a"), ["cn=x", "cn=y"]);
        // Same assertion: nothing changes, nothing is journaled.
        let before = f.count("SELECT COUNT(*) FROM group_changes");
        assert_eq!(
            f.sync("u_a", &["cn=x", "cn=y"], 0, POLICY).await,
            SyncReport::default()
        );
        assert_eq!(f.count("SELECT COUNT(*) FROM group_changes"), before);
        // The second person reuses the group; a rename is an update.
        f.store
            .conn()
            .execute(
                "UPDATE directory_groups SET name='old' WHERE external_key='cn=x'",
                [],
            )
            .unwrap();
        let r = f.sync("u_b", &["cn=x"], 0, POLICY).await;
        assert_eq!((r.added, r.groups_created, r.groups_renamed), (1, 0, 1));
        // Grace 0: no longer asserted means removed now.
        let r = f.sync("u_a", &["cn=x"], 0, POLICY).await;
        assert_eq!(r.removed, 1);
        assert_eq!(f.keys("u_a"), ["cn=x"]);
        let (head, oldest) = f.store.groups_journal_bounds(dl()).await.unwrap();
        assert_eq!(oldest, Some(1));
        assert_eq!(head, f.count("SELECT MAX(revision) FROM group_changes"));
        assert_eq!(
            f.count("SELECT COUNT(*) FROM events WHERE kind='group.member_removed' AND json_extract(attrs,'$.cause')='login'"),
            1
        );
        // An unknown person is refused.
        assert!(
            f.store
                .groups_sync_user(
                    ProviderId::new("dir"),
                    Source::Ldap,
                    UserId::new("u_zz"),
                    m(&["cn=x"]),
                    0,
                    POLICY,
                    tpl(&f.clock),
                    dl()
                )
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn removal_waits_for_the_grace_and_a_renewed_assertion_cancels_it() {
        let f = fx();
        f.sync("u_a", &["cn=x", "cn=y"], 600, POLICY).await;
        let r = f.sync("u_a", &["cn=x"], 600, POLICY).await;
        assert_eq!((r.removed, r.pending), (0, 1));
        assert_eq!(f.keys("u_a").len(), 2);
        f.clock.advance(Duration::from_secs(300));
        // Asserted again within the grace: pending is cleared.
        f.sync("u_a", &["cn=x", "cn=y"], 600, POLICY).await;
        assert_eq!(
            f.count("SELECT COUNT(*) FROM group_members WHERE removal_pending_at IS NOT NULL"),
            0
        );
        f.sync("u_a", &["cn=x"], 600, POLICY).await;
        f.clock.advance(Duration::from_secs(601));
        // The maintenance pass removes it once the grace passed.
        let grace: HashMap<String, u64> = [("dir".to_string(), 600)].into();
        let now = f.clock.now().secs();
        let rep = f
            .store
            .groups_maintenance(
                grace,
                now - 86_400,
                now - 86_400,
                POLICY,
                tpl(&f.clock),
                dl(),
            )
            .await
            .unwrap();
        assert_eq!(rep.grace_removed, 1);
        assert_eq!(f.keys("u_a"), ["cn=x"]);
    }

    #[tokio::test]
    async fn more_groups_than_the_per_person_limit_change_nothing() {
        let f = fx();
        f.sync("u_a", &["a"], 0, POLICY).await;
        let journal = f.count("SELECT COUNT(*) FROM group_changes");
        let r = f.sync("u_a", &["a", "b", "c", "d"], 0, POLICY).await;
        assert_eq!(r.refused, Some("too_many_groups"));
        assert_eq!(f.keys("u_a"), ["a"]);
        assert_eq!(f.count("SELECT COUNT(*) FROM group_changes"), journal);
        assert_eq!(f.count("SELECT COUNT(*) FROM directory_groups"), 1);
    }

    #[tokio::test]
    async fn the_gateway_mirror_follows_memberships_and_bumps_authz_version() {
        let f = fx();
        let on = WritePolicy {
            max_groups_per_user: 3,
            gateway_header: true,
        };
        let v0 = f.count("SELECT authz_version FROM users WHERE user_id='u_a'");
        f.sync("u_a", &["a", "b"], 0, on).await;
        let groups: String = f
            .store
            .conn()
            .query_row("SELECT groups FROM users WHERE user_id='u_a'", [], |r| {
                r.get(0)
            })
            .unwrap();
        let refs: Vec<String> = serde_json::from_str(&groups).unwrap();
        assert_eq!(refs.len(), 2);
        assert!(refs.iter().all(|r| crate::groups::valid_ref(r)));
        assert_eq!(
            f.count("SELECT authz_version FROM users WHERE user_id='u_a'"),
            v0 + 1
        );
        // Unchanged memberships do not bump the version; the header off clears.
        f.sync("u_a", &["a", "b"], 0, on).await;
        assert_eq!(
            f.count("SELECT authz_version FROM users WHERE user_id='u_a'"),
            v0 + 1
        );
        f.sync("u_a", &["a"], 0, POLICY).await;
        assert_eq!(
            f.count("SELECT COUNT(*) FROM users WHERE user_id='u_a' AND groups='[]'"),
            1
        );
    }

    #[tokio::test]
    async fn maintenance_expires_local_memberships_orphans_deleted_providers_and_prunes() {
        let f = fx();
        f.sync("u_a", &["a"], 0, POLICY).await;
        let now = f.clock.now().secs();
        f.store
            .conn()
            .execute_batch(&format!(
                "INSERT INTO directory_groups(group_id,source,external_key,name,created_at,updated_at) VALUES('grp1:0000000000000000000000abc1','local','loc','Loc',{now},{now});
                 INSERT INTO group_members(group_id,user_id,source,first_seen_at,last_seen_at,expires_at) VALUES('grp1:0000000000000000000000abc1','u_b','local',{now},{now},{});",
                now + 10
            ))
            .unwrap();
        // Effective reads hide an expired membership before maintenance runs.
        f.clock.advance(Duration::from_secs(11));
        let now = f.clock.now().secs();
        let (members, _) = f
            .store
            .group_members(
                "grp1:0000000000000000000000abc1".into(),
                None,
                10,
                now,
                dl(),
            )
            .await
            .unwrap();
        assert!(members.is_empty());
        f.store
            .conn()
            .execute(
                "UPDATE providers SET deleted_at=1 WHERE provider_id='dir'",
                [],
            )
            .unwrap();
        let rep = f
            .store
            .groups_maintenance(
                HashMap::new(),
                now - 1,
                now + 1,
                POLICY,
                tpl(&f.clock),
                dl(),
            )
            .await
            .unwrap();
        assert_eq!((rep.expired, rep.orphaned), (1, 1));
        // The provider group lost its last member and its provider: deleted.
        assert_eq!(rep.stale_groups, 1);
        assert_eq!(
            f.count("SELECT COUNT(*) FROM directory_groups WHERE state='deleted'"),
            1
        );
        // The journal keeps only its newest row after a full prune.
        assert!(rep.journal_pruned > 0);
        assert_eq!(f.count("SELECT COUNT(*) FROM group_changes"), 1);
        let (head, oldest) = f.store.groups_journal_bounds(dl()).await.unwrap();
        assert_eq!(Some(head), oldest);
        assert!(
            f.store
                .groups_projection_changes(vec![], 0, 10, dl())
                .await
                .unwrap()
                .is_err()
        );
        assert!(
            f.store
                .groups_projection_changes(vec![], head, 10, dl())
                .await
                .unwrap()
                .is_ok()
        );
    }

    #[tokio::test]
    async fn projection_reads_are_restricted_to_the_vocabulary_and_paged() {
        let f = fx();
        f.sync("u_a", &["a", "b"], 0, POLICY).await;
        f.sync("u_b", &["a"], 0, POLICY).await;
        let id_of = |k: &str| -> String {
            f.store
                .conn()
                .query_row(
                    "SELECT group_id FROM directory_groups WHERE external_key=?1",
                    [k],
                    |r| r.get(0),
                )
                .unwrap()
        };
        let a = id_of("a");
        let now = f.clock.now().secs();
        let (page, more) = f
            .store
            .groups_projection_snapshot(vec![a.clone()], None, 1, now, dl())
            .await
            .unwrap();
        assert!(more);
        assert_eq!(page[0].user_id, "u_a");
        assert_eq!(page[0].groups, vec![a.clone()]);
        let (page, more) = f
            .store
            .groups_projection_snapshot(vec![a.clone()], Some("u_a".into()), 1, now, dl())
            .await
            .unwrap();
        assert!(!more);
        assert_eq!(page[0].user_id, "u_b");
        let feed = f
            .store
            .groups_projection_changes(vec![a.clone()], 0, 100, dl())
            .await
            .unwrap()
            .unwrap();
        assert!(feed.changes.iter().all(|c| c.group_id == a));
        assert_eq!(
            feed.changes
                .iter()
                .filter(|c| c.change == "member_added")
                .count(),
            2
        );
        assert_eq!(feed.next, feed.head);
        // A position beyond the head is another store's.
        assert!(
            f.store
                .groups_projection_changes(vec![a], feed.head + 1, 10, dl())
                .await
                .unwrap()
                .is_err()
        );
    }

    #[tokio::test]
    async fn periodic_batches_walk_identities_and_wait_for_the_interval() {
        let f = fx();
        for (i, u) in ["u_a", "u_b"].iter().enumerate() {
            f.store
                .conn()
                .execute(
                    "INSERT INTO identities(provider_id,subject,user_id,first_seen_at,last_seen_at) VALUES('dir',?1,?2,1,1)",
                    rusqlite::params![format!("t:uid:{i}"), u],
                )
                .unwrap();
        }
        let b1 = f
            .store
            .groups_sync_batch("dir".into(), 3600, 1, dl())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(b1, vec![("t:uid:0".to_string(), "u_a".to_string())]);
        let b2 = f
            .store
            .groups_sync_batch("dir".into(), 3600, 1, dl())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(b2[0].1, "u_b");
        let b3 = f
            .store
            .groups_sync_batch("dir".into(), 3600, 1, dl())
            .await
            .unwrap()
            .unwrap();
        assert!(b3.is_empty());
        // The cycle ended: the next one waits for the interval.
        assert!(
            f.store
                .groups_sync_batch("dir".into(), 3600, 1, dl())
                .await
                .unwrap()
                .is_none()
        );
        f.clock.advance(Duration::from_secs(3601));
        assert!(
            f.store
                .groups_sync_batch("dir".into(), 3600, 1, dl())
                .await
                .unwrap()
                .is_some()
        );
        f.store
            .groups_sync_result("dir".into(), Some("provider_unavailable"), dl())
            .await
            .unwrap();
        assert_eq!(
            f.count(
                "SELECT COUNT(*) FROM group_sync_state WHERE last_error='provider_unavailable'"
            ),
            1
        );
    }
}
