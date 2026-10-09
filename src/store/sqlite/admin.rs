//! Administrator grants, fenced console mutations and reauthentication
//! (ADR-0016).
//!
//! Every `admin_*` write runs in one `BEGIN IMMEDIATE` transaction whose
//! first statement is the actor fence: the acting administrator's session,
//! handle, user and grant are re-evaluated against the state and the policy
//! current at that moment, so a change committed between the request check and
//! the write wins. Events travel with their rows.

use std::collections::HashSet;
use std::future::Future;
use std::time::Duration;

use rusqlite::{Connection, OptionalExtension, Row, Transaction, named_params, params};

use super::events::insert_events;
use super::rows::{self, cols, corrupt};
use super::sessions::{
    consume_session_codes, insert_handle, revoke_session_handles, session_by_id, terminate_in,
};
use super::{Check, Shared, Store, WriterEnv, commit};
use crate::crypto::{Digest, Timestamp};
use crate::event::types::{Event, EventKind, Reason, reasons};
use crate::identity::types::{NormalizedEmail, UserId};
use crate::provider::types::ProviderId;
use crate::session::types::{FactorEntry, SessionId};
use crate::store::types::*;
use crate::store::{StoreError, StoreResult};

// ---- asking the async side for events built mid-transaction ---------------

/// A job on the writer thread needs events built from rows it only learns
/// inside the transaction. The caller's builder is not `'static`, so it stays
/// in the async context; the job sends it a request and waits for the answer.
/// If the caller goes away the request fails and the job rolls back.
pub(super) struct Ask<Q, A> {
    tx: tokio::sync::mpsc::UnboundedSender<(Q, std::sync::mpsc::Sender<A>)>,
}

pub(super) struct Responder<Q, A> {
    rx: tokio::sync::mpsc::UnboundedReceiver<(Q, std::sync::mpsc::Sender<A>)>,
}

pub(super) fn asker<Q, A>() -> (Ask<Q, A>, Responder<Q, A>) {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    (Ask { tx }, Responder { rx })
}

impl<Q, A> Ask<Q, A> {
    pub(super) fn ask(&self, q: Q, check: &Check) -> StoreResult<A> {
        let (reply, answer) = std::sync::mpsc::channel();
        self.tx
            .send((q, reply))
            .map_err(|_| StoreError::Unavailable("caller gone".into()))?;
        let wait = check.remaining().unwrap_or(Duration::from_secs(5));
        answer
            .recv_timeout(wait.max(Duration::from_millis(1)))
            .map_err(|_| StoreError::Unavailable("deadline".into()))
    }
}

impl<Q, A> Responder<Q, A> {
    /// Drive `job` while answering its requests with `build`.
    pub(super) async fn drive<T>(
        mut self,
        job: impl Future<Output = StoreResult<T>>,
        build: &(dyn Fn(Q) -> A + Sync),
    ) -> StoreResult<T> {
        tokio::pin!(job);
        loop {
            tokio::select! {
                biased;
                out = &mut job => return out,
                Some((q, reply)) = self.rx.recv() => {
                    let _ = reply.send(build(q));
                }
            }
        }
    }
}

// ---- grant rows -------------------------------------------------------------

const GRANT_COLS: &[&str] = &[
    "user_id",
    "role",
    "managed_by",
    "source_email",
    "granted_at",
    "granted_by",
    "revoked_at",
    "revoked_by",
    "note",
];

fn grant_decode(r: &Row<'_>) -> StoreResult<AdminGrant> {
    let source: Option<String> = r.get(3)?;
    Ok(AdminGrant {
        user_id: UserId::new(r.get::<_, String>(0)?),
        role: AdminRole::parse(&r.get::<_, String>(1)?)
            .ok_or_else(|| corrupt("admin_grants.role"))?,
        managed_by: GrantManagedBy::parse(&r.get::<_, String>(2)?)
            .ok_or_else(|| corrupt("admin_grants.managed_by"))?,
        source_email: match source {
            None => None,
            Some(s) => Some(
                NormalizedEmail::from_stored(&s)
                    .ok_or_else(|| corrupt("admin_grants.source_email"))?,
            ),
        },
        granted_at: rows::ts(r, 4, "admin_grants.granted_at")?,
        granted_by: r.get(5)?,
        revoked_at: rows::opt_ts(r, 6)?,
        revoked_by: r.get(7)?,
        note: r.get(8)?,
    })
}

/// The grant row of `user` in any state.
pub(super) fn grant_row(conn: &Connection, user: &str) -> StoreResult<Option<AdminGrant>> {
    let sql = format!(
        "SELECT {} FROM admin_grants WHERE user_id = ?1",
        cols("", GRANT_COLS)
    );
    conn.query_row(&sql, [user], |r| Ok(grant_decode(r)))
        .optional()?
        .transpose()
}

/// Every row bound through `email`, in any state, whatever user it names.
fn grants_by_email(conn: &Connection, email: &str) -> StoreResult<Vec<AdminGrant>> {
    let sql = format!(
        "SELECT {} FROM admin_grants WHERE source_email = ?1 ORDER BY user_id",
        cols("", GRANT_COLS)
    );
    let mut st = conn.prepare(&sql)?;
    let mut q = st.query([email])?;
    let mut out = Vec::new();
    while let Some(r) = q.next()? {
        out.push(grant_decode(r)?);
    }
    Ok(out)
}

fn secs_i64(d: Duration) -> i64 {
    i64::try_from(d.as_secs()).unwrap_or(i64::MAX)
}

/// The actor fence, pinned SQL (ADR-0016, P2-02): no row means the actor is no
/// longer a live administrator under the policy in force now.
fn fence(conn: &Connection, shared: &Shared, actor: &Actor, p: &ActorPolicy) -> StoreResult<()> {
    let now = shared.clock.now().secs();
    let hit: Option<i64> = conn
        .query_row(
            "SELECT 1
             FROM sessions s
             JOIN session_handles h ON h.session_id = s.session_id
             JOIN users u            ON u.user_id = s.user_id
             JOIN admin_grants g     ON g.user_id = s.user_id
             WHERE s.session_id = :actor_session
               AND s.user_id    = :actor_user
               AND s.terminated_at IS NULL
               AND s.created_at <= :now + :skew
               AND :now < MIN(s.absolute_expires_at, s.created_at + :session_absolute)
               AND :now < s.last_seen_at + :session_idle
               AND s.auth_time <= :now + :skew
               AND :now - s.auth_time < :max_auth_age
               AND (:cap_requires_claim = 0 OR s.auth_time_source = 'provider_claim')
               AND h.handle_sha256 = :handle
               AND h.host          = :console_host
               AND h.revoked_at IS NULL
               AND h.created_at <= :now + :skew
               AND :now < MIN(h.absolute_expires_at, h.created_at + :handle_absolute)
               AND :now < h.last_seen_at + :handle_idle
               AND h.issued_aal >= :require_aal
               AND u.status = 'active'
               AND u.authz_version = s.authz_version_at_auth
               AND g.revoked_at IS NULL
               AND g.role = 'admin'",
            named_params! {
                ":actor_session": actor.session_id.as_str(),
                ":actor_user": actor.user_id.as_str(),
                ":now": now,
                ":skew": secs_i64(p.skew),
                ":session_absolute": secs_i64(p.session.absolute),
                ":session_idle": secs_i64(p.session.idle),
                ":max_auth_age": secs_i64(p.max_auth_age),
                ":cap_requires_claim": i64::from(p.capability_requires_claim),
                ":handle": &actor.handle_sha256.0[..],
                ":console_host": p.console_host.as_str(),
                ":handle_absolute": secs_i64(p.handle.absolute),
                ":handle_idle": secs_i64(p.handle.idle),
                ":require_aal": p.require_aal.as_i64(),
            },
            |r| r.get(0),
        )
        .optional()?;
    match hit {
        Some(_) => Ok(()),
        None => Err(StoreError::Conflict("actor_revoked")),
    }
}

/// Open the write transaction of a fenced mutation: the `admin_mutation` gate
/// (test hook), `BEGIN IMMEDIATE`, the deadline check (the lock may have been
/// waited for), then the fence as the first statement.
fn begin_fenced<'a>(
    env: &'a mut WriterEnv,
    check: &Check,
    actor: &Actor,
    policy: &ActorPolicy,
) -> StoreResult<(Transaction<'a>, std::sync::Arc<Shared>)> {
    let shared = env.shared.clone();
    if let Some(h) = &shared.hooks {
        h.pass_gate("admin_mutation");
    }
    let tx = env.begin()?;
    check.now()?;
    fence(&tx, &shared, actor, policy)?;
    Ok((tx, shared))
}

/// Just before COMMIT: the `admin_precommit` gate (test hook), then the
/// deadline check, so a job that reaches its deadline never commits late.
fn before_commit(shared: &Shared, check: &Check) -> StoreResult<()> {
    if let Some(h) = &shared.hooks {
        h.pass_gate("admin_precommit");
    }
    check.now()
}

fn crash(shared: &Shared, label: &str) {
    if let Some(h) = &shared.hooks {
        h.crash_point(label);
    }
}

impl Store {
    pub(super) async fn admin_grant_impl(
        &self,
        user: &UserId,
        deadline: Deadline,
    ) -> StoreResult<Option<AdminGrant>> {
        let id = user.clone();
        self.read_checked("admin_grant", Some(deadline), move |c, _| {
            grant_row(c, id.as_str())
        })
        .await
    }

    pub(super) async fn admin_grants_impl(
        &self,
        include_revoked: bool,
        deadline: Deadline,
    ) -> StoreResult<Vec<AdminGrant>> {
        self.read_checked("admin_grants", Some(deadline), move |c, check| {
            let sql = format!(
                "SELECT {} FROM admin_grants {} ORDER BY granted_at, user_id",
                cols("", GRANT_COLS),
                if include_revoked {
                    ""
                } else {
                    "WHERE revoked_at IS NULL"
                }
            );
            let mut st = c.prepare(&sql)?;
            let mut q = st.query([])?;
            let mut out = Vec::new();
            while let Some(r) = q.next()? {
                check.now()?;
                out.push(grant_decode(r)?);
            }
            Ok(out)
        })
        .await
    }

    pub(super) async fn resolve_grant_target_impl(
        &self,
        target: &GrantTarget,
        deadline: Deadline,
    ) -> StoreResult<Option<(User, Vec<IdentityRow>)>> {
        let target = target.clone();
        self.read_checked("resolve_grant_target", Some(deadline), move |c, _| {
            let (clause, arg) = match &target {
                GrantTarget::Id(u) => ("user_id", u.to_string()),
                GrantTarget::Email(e) => ("primary_email", e.to_string()),
            };
            let sql = format!(
                "SELECT {} FROM users WHERE {clause} = ?1",
                cols("", rows::USER_COLS)
            );
            let Some(user) = c
                .query_row(&sql, [&arg], |r| Ok(rows::user(r, 0)))
                .optional()?
                .transpose()?
            else {
                return Ok(None);
            };
            let sql = format!(
                "SELECT {} FROM identities WHERE user_id = ?1 ORDER BY first_seen_at, provider_id, subject LIMIT 50",
                cols("", rows::IDENTITY_COLS)
            );
            let mut st = c.prepare(&sql)?;
            let mut q = st.query([user.user_id.as_str()])?;
            let mut ids = Vec::new();
            while let Some(r) = q.next()? {
                ids.push(rows::identity(r, 0)?);
            }
            Ok(Some((user, ids)))
        })
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn grant_admin_impl(
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
        let (user, by) = (user.clone(), by.to_string());
        self.write("grant_admin", move |env| {
            let shared = env.shared.clone();
            let tx = env.begin()?;
            let status: Option<String> = tx
                .query_row(
                    "SELECT status FROM users WHERE user_id = ?1",
                    [user.as_str()],
                    |r| r.get(0),
                )
                .optional()?;
            match status.as_deref() {
                None => return Err(StoreError::Conflict("unknown user")),
                Some("active") => {}
                Some(_) => return Err(StoreError::Conflict("user_disabled")),
            }
            let existing = grant_row(&tx, user.as_str())?;
            let previous = existing.as_ref().map(|g| g.role);
            if let Some(g) = &existing
                && g.revoked_at.is_none()
                && g.role == role
                && g.managed_by == managed_by
                && (note.is_none() || note == g.note)
            {
                return Ok((previous, false));
            }
            tx.execute(
                "INSERT INTO admin_grants (user_id, role, managed_by, source_email, granted_at, granted_by, revoked_at, revoked_by, note)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, NULL, ?7)
                 ON CONFLICT (user_id) DO UPDATE SET
                    role = excluded.role, managed_by = excluded.managed_by,
                    source_email = COALESCE(excluded.source_email, admin_grants.source_email),
                    granted_at = excluded.granted_at, granted_by = excluded.granted_by,
                    revoked_at = NULL, revoked_by = NULL, note = excluded.note",
                params![
                    user.as_str(),
                    role.as_str(),
                    managed_by.as_str(),
                    source_email.as_ref().map(|e| e.as_str()),
                    at.secs(),
                    by,
                    note,
                ],
            )?;
            let mut event = event;
            if let Some(p) = previous {
                event.attrs.insert("previous_role".into(), p.as_str().into());
            }
            insert_events(&tx, &shared, &[event])?;
            crash(&shared, "after_grant_row");
            commit(tx, &shared, Some("admin_grant"))?;
            Ok((previous, true))
        })
        .await
    }

    pub(super) async fn revoke_admin_impl(
        &self,
        user: &UserId,
        by: &str,
        managed_by: GrantManagedBy,
        at: Timestamp,
        event: Event,
    ) -> StoreResult<bool> {
        let (user, by) = (user.clone(), by.to_string());
        self.write("revoke_admin", move |env| {
            let shared = env.shared.clone();
            let tx = env.begin()?;
            let Some(g) = grant_row(&tx, user.as_str())?.filter(|g| g.revoked_at.is_none())
            else {
                return Ok(false);
            };
            tx.execute(
                "UPDATE admin_grants SET revoked_at = ?2, revoked_by = ?3, managed_by = ?4 WHERE user_id = ?1",
                params![user.as_str(), at.secs(), by, managed_by.as_str()],
            )?;
            let mut event = event;
            event
                .attrs
                .insert("previous_role".into(), g.role.as_str().into());
            insert_events(&tx, &shared, &[event])?;
            crash(&shared, "after_grant_row");
            commit(tx, &shared, Some("admin_revoke"))?;
            Ok(true)
        })
        .await
    }

    pub(super) async fn import_grants_job(
        &self,
        entries: Vec<SeedEntry>,
        force: Option<ForceTarget>,
        deadline: Deadline,
        at: Timestamp,
        ask: ImportAsk,
    ) -> StoreResult<GrantImportReport> {
        self.write_checked("import_grants", Some(deadline), move |env, check| {
            let shared = env.shared.clone();
            let tx = env.begin()?;
            check.now()?;
            let mut imp = Import {
                tx: &tx,
                ask: &ask,
                check,
                at,
                report: GrantImportReport::default(),
                present: HashSet::new(),
                shared: &shared,
            };
            imp.run(&entries, force.as_ref())?;
            before_commit(&shared, check)?;
            let report = imp.report;
            commit(tx, &shared, Some("admin_import"))?;
            Ok(report)
        })
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn set_user_status_job(
        &self,
        actor: &Actor,
        policy: &ActorPolicy,
        user: &UserId,
        status: UserStatus,
        deadline: Deadline,
        admin_event: Event,
        ask: SessionAsk,
    ) -> StoreResult<(bool, u32)> {
        let (actor, policy, user) = (actor.clone(), policy.clone(), user.clone());
        self.write_checked("admin_set_user_status", Some(deadline), move |env, check| {
            let (tx, shared) = begin_fenced(env, check, &actor, &policy)?;
            let current: Option<String> = tx
                .query_row(
                    "SELECT status FROM users WHERE user_id = ?1",
                    [user.as_str()],
                    |r| r.get(0),
                )
                .optional()?;
            let Some(current) = current else {
                return Err(StoreError::Conflict("unknown user"));
            };
            if current == status.as_str() {
                return Ok((false, 0)); // idempotent: no write, no event
            }
            let now = shared.clock.now();
            tx.execute(
                "UPDATE users SET status = ?2, authz_version = authz_version + 1, updated_at = ?3 WHERE user_id = ?1",
                params![user.as_str(), status.as_str(), now.secs()],
            )?;
            let mut ended = 0u32;
            if status == UserStatus::Disabled {
                ended = terminate_all(&tx, &shared, check, &user, reasons::USER_DISABLED, now, &ask)?;
            }
            crash(&shared, "after_admin_status_write");
            check.now()?;
            insert_events(&tx, &shared, &[admin_event])?;
            before_commit(&shared, check)?;
            commit(tx, &shared, Some("admin_status"))?;
            Ok((true, ended))
        })
        .await
    }

    pub(super) async fn admin_terminate_session_impl(
        &self,
        actor: &Actor,
        policy: &ActorPolicy,
        id: &SessionId,
        deadline: Deadline,
        admin_event: Event,
        session_event: Event,
    ) -> StoreResult<bool> {
        let (actor, policy, id) = (actor.clone(), policy.clone(), id.clone());
        self.write_checked(
            "admin_terminate_session",
            Some(deadline),
            move |env, check| {
                let (tx, shared) = begin_fenced(env, check, &actor, &policy)?;
                let live = tx
                    .query_row(
                        "SELECT terminated_at IS NULL FROM sessions WHERE session_id = ?1",
                        [id.as_str()],
                        |r| r.get::<_, bool>(0),
                    )
                    .optional()?
                    .unwrap_or(false);
                if !live {
                    return Ok(false);
                }
                let now = shared.clock.now();
                terminate_in(&tx, &shared, &id, reasons::ADMIN, now, &[session_event])?;
                crash(&shared, "after_admin_terminate_write");
                check.now()?;
                insert_events(&tx, &shared, &[admin_event])?;
                before_commit(&shared, check)?;
                commit(tx, &shared, Some("admin_terminate"))?;
                Ok(true)
            },
        )
        .await
    }

    pub(super) async fn admin_terminate_user_sessions_job(
        &self,
        actor: &Actor,
        policy: &ActorPolicy,
        user: &UserId,
        deadline: Deadline,
        admin_event: Event,
        ask: SessionAsk,
    ) -> StoreResult<u32> {
        let (actor, policy, user) = (actor.clone(), policy.clone(), user.clone());
        self.write_checked(
            "admin_terminate_user_sessions",
            Some(deadline),
            move |env, check| {
                let (tx, shared) = begin_fenced(env, check, &actor, &policy)?;
                let now = shared.clock.now();
                let n = terminate_all(&tx, &shared, check, &user, reasons::ADMIN, now, &ask)?;
                if n == 0 {
                    return Ok(0); // nothing live: no write, no event
                }
                crash(&shared, "after_admin_terminate_write");
                check.now()?;
                insert_events(&tx, &shared, &[admin_event])?;
                before_commit(&shared, check)?;
                commit(tx, &shared, Some("admin_terminate"))?;
                Ok(n)
            },
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn reauthenticate_session_impl(
        &self,
        id: &SessionId,
        provider: &ProviderId,
        auth_time: Timestamp,
        source: AuthTimeSource,
        factor: FactorEntry,
        new_portal_handle: HandleRow,
        consume_txn: (Digest, Reason),
        deadline: Deadline,
        events: Vec<Event>,
    ) -> StoreResult<()> {
        let (id, provider) = (id.clone(), provider.clone());
        self.write_checked("reauthenticate_session", Some(deadline), move |env, check| {
            let shared = env.shared.clone();
            if new_portal_handle.session_id != id {
                return Err(StoreError::Conflict("portal handle names another session"));
            }
            let tx = env.begin()?;
            check.now()?;
            let session = session_by_id(&tx, &id)?
                .filter(|s| s.terminated_at.is_none())
                .ok_or(StoreError::Conflict("session unavailable"))?;
            if session.provider_id != provider {
                return Err(StoreError::Conflict("provider_mismatch"));
            }
            let now = shared.clock.now();
            check.now()?;
            let consumed = tx.execute(
                "UPDATE login_txns SET consumed_at = ?2, consumed_reason = ?3 WHERE txn_sha256 = ?1 AND consumed_at IS NULL",
                params![&consume_txn.0.0[..], now.secs(), consume_txn.1.0],
            )?;
            if consumed != 1 {
                return Err(StoreError::Conflict("transaction already consumed"));
            }
            let mut factors = session.factors.clone();
            factors.push(factor);
            check.now()?;
            tx.execute(
                "UPDATE sessions SET auth_time = ?2, auth_time_source = ?3, factors = ?4, cred_gen = cred_gen + 1 WHERE session_id = ?1",
                params![
                    id.as_str(),
                    auth_time.secs(),
                    source.as_str(),
                    rows::json_str(&factors)?,
                ],
            )?;
            check.now()?;
            revoke_session_handles(&tx, &id, reasons::REAUTH.0, now)?;
            consume_session_codes(&tx, &id, reasons::REAUTH.0, now)?;
            check.now()?;
            let mut handle = new_portal_handle;
            handle.issued_aal = handle.issued_aal.min(session.aal);
            insert_handle(&tx, &handle)?;
            insert_events(&tx, &shared, &events)?;
            crash(&shared, "after_reauth_write");
            before_commit(&shared, check)?;
            commit(tx, &shared, Some("admin_reauth"))
        })
        .await
    }
}

/// Terminate every live session of `user` with `reason`, one event each from
/// the caller's builder; the deadline is checked per session.
fn terminate_all(
    tx: &Transaction<'_>,
    shared: &Shared,
    check: &Check,
    user: &UserId,
    reason: Reason,
    now: Timestamp,
    ask: &Ask<SessionRow, Event>,
) -> StoreResult<u32> {
    let ids: Vec<String> = {
        let mut st = tx.prepare(
            "SELECT session_id FROM sessions WHERE user_id = ?1 AND terminated_at IS NULL ORDER BY created_at, session_id",
        )?;
        st.query_map([user.as_str()], |r| r.get(0))?
            .collect::<Result<_, _>>()?
    };
    let mut n = 0u32;
    for sid in ids {
        check.step()?;
        let id = SessionId::new(sid);
        let Some(row) = session_by_id(tx, &id)? else {
            continue;
        };
        let ev = ask.ask(row, check)?;
        terminate_in(tx, shared, &id, reason, now, &[ev])?;
        n += 1;
    }
    Ok(n)
}

// ---- the file import --------------------------------------------------------

pub(super) type ImportAsk = Ask<(UserId, EventKind, Option<AdminRole>, AdminRole, bool), Event>;
pub(super) type SessionAsk = Ask<SessionRow, Event>;

/// What matching found for one entry (phase 1).
enum Found {
    None,
    One(AdminGrant),
    Ambiguous(Vec<AdminGrant>),
}

struct Import<'a> {
    tx: &'a Transaction<'a>,
    ask: &'a ImportAsk,
    check: &'a Check,
    at: Timestamp,
    report: GrantImportReport,
    /// Users whose row an entry named (or whose binding it matched): never revoked as "removed".
    present: HashSet<String>,
    shared: &'a Shared,
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

impl Import<'_> {
    fn event(
        &self,
        user: &UserId,
        kind: EventKind,
        prev: Option<AdminRole>,
        role: AdminRole,
        forced: bool,
    ) -> StoreResult<()> {
        let ev = self
            .ask
            .ask((user.clone(), kind, prev, role, forced), self.check)?;
        insert_events(self.tx, self.shared, &[ev])
    }

    fn skip(&mut self, e: &SeedEntry, why: &'static str) {
        self.report.skipped.push((e.index, why));
    }

    fn run(&mut self, entries: &[SeedEntry], force: Option<&ForceTarget>) -> StoreResult<()> {
        // Phase 1: match every entry by its original key.
        let mut found = Vec::with_capacity(entries.len());
        for e in entries {
            found.push(match &e.key {
                SeedKey::ById(u) | SeedKey::Both { user_id: u, .. } => {
                    match grant_row(self.tx, u.as_str())? {
                        Some(g) => Found::One(g),
                        None => Found::None,
                    }
                }
                SeedKey::ByEmail(em) => {
                    let mut rows = grants_by_email(self.tx, em.as_str())?;
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
                let rows = grants_by_email(self.tx, em.as_str())?;
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
                let by_row = matches!(m, Found::One(g) if Some(&g.user_id) == forced_user.as_ref());
                by_key || by_row
            });
            if !named {
                return Err(StoreError::Conflict(
                    "force names an entry the file does not list",
                ));
            }
        }
        if let Some(h) = &self.shared.hooks {
            h.crash_point("after_import_match");
        }
        self.check.now()?;

        // Phase 2: matched rows.
        let mut unmatched = Vec::new();
        for (e, m) in entries.iter().zip(found) {
            self.check.step()?;
            match m {
                Found::Ambiguous(rows) => {
                    for g in &rows {
                        self.present.insert(g.user_id.to_string());
                    }
                    self.skip(e, skip::EMAIL_BINDING_AMBIGUOUS);
                }
                Found::One(g) => self.apply_matched(e, g, forced_user.as_ref(), true)?,
                Found::None => unmatched.push(e),
            }
        }
        self.check.now()?;

        // Phase 3: resolve what no row matched, once.
        for e in unmatched {
            self.check.step()?;
            self.resolve_and_insert(e, forced_user.as_ref())?;
        }
        self.check.now()?;

        // Phase 4: live file rows no entry named are revoked by the file.
        let stale: Vec<(String, String)> = {
            let mut st = self.tx.prepare(
                "SELECT user_id, role FROM admin_grants WHERE managed_by = 'file' AND revoked_at IS NULL ORDER BY user_id",
            )?;
            st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<Result<_, _>>()?
        };
        for (uid, role) in stale {
            if self.present.contains(&uid) {
                continue;
            }
            self.check.step()?;
            let role = AdminRole::parse(&role).ok_or_else(|| corrupt("admin_grants.role"))?;
            self.tx.execute(
                "UPDATE admin_grants SET revoked_at = ?2, revoked_by = 'file' WHERE user_id = ?1",
                params![uid, self.at.secs()],
            )?;
            let user = UserId::new(uid);
            self.event(&user, EventKind::AdminRevoke, Some(role), role, false)?;
            self.report.revoked.push(user);
        }
        Ok(())
    }

    /// An entry whose key matched a row (phase 2; also phase 3 when the
    /// resolved user already holds a row).
    fn apply_matched(
        &mut self,
        e: &SeedEntry,
        g: AdminGrant,
        forced_user: Option<&UserId>,
        check_rebind: bool,
    ) -> StoreResult<()> {
        self.present.insert(g.user_id.to_string());
        // An email entry stays bound to its row; say so when the address moved.
        if check_rebind && let SeedKey::ByEmail(em) = &e.key {
            let holder: Option<String> = self
                .tx
                .query_row(
                    "SELECT user_id FROM users WHERE primary_email = ?1",
                    [em.as_str()],
                    |r| r.get(0),
                )
                .optional()?;
            if let Some(h) = holder.filter(|h| h != g.user_id.as_str()) {
                self.report
                    .rebound_warnings
                    .push((e.index, g.user_id.clone(), UserId::new(h)));
            }
        }
        // A present but mismatched entry leaves its row untouched.
        if let SeedKey::Both { user_id, email } = &e.key {
            let primary: Option<Option<String>> = self
                .tx
                .query_row(
                    "SELECT primary_email FROM users WHERE user_id = ?1",
                    [user_id.as_str()],
                    |r| r.get(0),
                )
                .optional()?;
            if primary.flatten().as_deref() != Some(email.as_str()) {
                self.skip(e, skip::USER_EMAIL_MISMATCH);
                return Ok(());
            }
        }
        if forced_user == Some(&g.user_id) {
            self.tx.execute(
                "UPDATE admin_grants SET role = ?2, note = ?3, managed_by = 'file', granted_at = ?4, granted_by = 'file', revoked_at = NULL, revoked_by = NULL WHERE user_id = ?1",
                params![g.user_id.as_str(), e.role.as_str(), e.note, self.at.secs()],
            )?;
            self.event(
                &g.user_id,
                EventKind::AdminGrant,
                Some(g.role),
                e.role,
                true,
            )?;
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
            self.tx.execute(
                "UPDATE admin_grants SET role = ?2, note = ?3 WHERE user_id = ?1",
                params![g.user_id.as_str(), e.role.as_str(), e.note],
            )?;
            self.event(
                &g.user_id,
                EventKind::AdminGrant,
                Some(g.role),
                e.role,
                false,
            )?;
            self.report.updated.push(g.user_id);
        }
        Ok(())
    }

    /// Resolve an unmatched entry exactly once and insert a file row.
    fn resolve_and_insert(
        &mut self,
        e: &SeedEntry,
        forced_user: Option<&UserId>,
    ) -> StoreResult<()> {
        struct U {
            id: String,
            primary: Option<String>,
            verified: bool,
            authoritative: bool,
            active: bool,
        }
        let decode = |r: &Row<'_>| -> rusqlite::Result<U> {
            Ok(U {
                id: r.get(0)?,
                primary: r.get(1)?,
                verified: r.get(2)?,
                authoritative: r.get(3)?,
                active: r.get::<_, String>(4)? == "active",
            })
        };
        const BY_ID: &str = "SELECT user_id, primary_email, email_verified, email_authoritative, status FROM users WHERE user_id = ?1";
        const BY_EMAIL: &str = "SELECT user_id, primary_email, email_verified, email_authoritative, status FROM users WHERE primary_email = ?1";
        let user: Option<U> = match &e.key {
            SeedKey::ById(u) | SeedKey::Both { user_id: u, .. } => {
                self.tx.query_row(BY_ID, [u.as_str()], decode).optional()?
            }
            SeedKey::ByEmail(em) => self
                .tx
                .query_row(BY_EMAIL, [em.as_str()], decode)
                .optional()?,
        };
        let Some(u) = user else {
            self.skip(e, skip::NO_SUCH_USER);
            return Ok(());
        };
        match &e.key {
            SeedKey::ByEmail(_) => {
                if !u.verified {
                    self.skip(e, skip::EMAIL_UNVERIFIED);
                    return Ok(());
                }
                if !u.authoritative {
                    self.skip(e, skip::EMAIL_NOT_AUTHORITATIVE);
                    return Ok(());
                }
            }
            SeedKey::Both { email, .. } => {
                if u.primary.as_deref() != Some(email.as_str()) {
                    self.skip(e, skip::USER_EMAIL_MISMATCH);
                    return Ok(());
                }
            }
            SeedKey::ById(_) => {}
        }
        if !u.active {
            self.skip(e, skip::USER_DISABLED);
            return Ok(());
        }
        // The resolved user may already hold a row bound some other way.
        if let Some(g) = grant_row(self.tx, &u.id)? {
            return self.apply_matched(e, g, forced_user, false);
        }
        let user = UserId::new(u.id);
        self.tx.execute(
            "INSERT INTO admin_grants (user_id, role, managed_by, source_email, granted_at, granted_by, note) VALUES (?1, ?2, 'file', ?3, ?4, 'file', ?5)",
            params![
                user.as_str(),
                e.role.as_str(),
                entry_email(&e.key).map(|x| x.as_str()),
                self.at.secs(),
                e.note,
            ],
        )?;
        self.event(&user, EventKind::AdminGrant, None, e.role, false)?;
        self.present.insert(user.to_string());
        self.report.inserted.push(user);
        Ok(())
    }
}
