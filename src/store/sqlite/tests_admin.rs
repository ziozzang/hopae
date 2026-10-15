//! Store tests for the management console (ADR-0016, W0): foundation
//! validation and backup ordering, the actor fence, fenced mutations, grants
//! and the file import, bounded windows, deadlines and interruption.

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rusqlite::{Connection, StatementStatus};

use super::super::{Store, earliest_present, precheck, validate_foundation, window};
use super::{APP_HOST, Fx, PORTAL_HOST, Sess, fx, host, ip, new_txn};
use crate::crypto::{Secret, Timestamp, handle_value};
use crate::event::types::{Event, EventBuilder, EventKind, Outcome, reasons};
use crate::identity::types::{NormalizedEmail, UserId};
use crate::policy::types::{Lifetimes, SessionPolicy};
use crate::provider::types::ProviderId;
use crate::session::types::{Aal, FactorEntry, FactorKind, SessionId};
use crate::store::types::*;
use crate::store::{Directory, Events, Sessions, StoreError};

const CONSOLE: &str = "hopae-admin.example.test";

fn dl(ms: u64) -> Deadline {
    Deadline::after(Duration::from_millis(ms))
}

fn long() -> Deadline {
    Deadline::after(Duration::from_secs(60))
}

// ---- schema files ------------------------------------------------------

fn write_v2(path: &Path) {
    let c = Connection::open(path).unwrap();
    c.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY NOT NULL, name TEXT NOT NULL, applied_at INTEGER NOT NULL) STRICT;",
    )
    .unwrap();
    c.execute_batch(include_str!("../migrations/0001_meta.sql"))
        .unwrap();
    c.execute_batch(include_str!("../migrations/0002_m1_schema.sql"))
        .unwrap();
    c.execute_batch(
        "INSERT INTO schema_migrations VALUES (1,'0001_meta',0); INSERT INTO schema_migrations VALUES (2,'0002_m1_schema',0);",
    )
    .unwrap();
}

fn write_pre_release_v2(path: &Path) {
    let c = Connection::open(path).unwrap();
    c.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY NOT NULL, name TEXT NOT NULL, applied_at INTEGER NOT NULL) STRICT;",
    )
    .unwrap();
    c.execute_batch(include_str!("../migrations/0001_meta.sql"))
        .unwrap();
    c.execute_batch(include_str!(
        "../../../tests/fixtures/pre_release_0002_m1_schema.sql"
    ))
    .unwrap();
    c.execute_batch(
        "INSERT OR IGNORE INTO schema_migrations VALUES (1,'0001_meta',0); INSERT OR IGNORE INTO schema_migrations VALUES (2,'0002_m1_schema',0);",
    )
    .unwrap();
}

fn version_of(path: &Path) -> i64 {
    Connection::open(path)
        .unwrap()
        .query_row("SELECT MAX(version) FROM schema_migrations", [], |r| {
            r.get(0)
        })
        .unwrap()
}

fn has(path: &Path, kind: &str, name: &str) -> bool {
    Connection::open(path)
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type=?1 AND name=?2",
            [kind, name],
            |r| r.get::<_, i64>(0),
        )
        .unwrap()
        > 0
}

fn leftovers(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".tmp"))
        .collect();
    v.sort();
    v
}

#[test]
fn migration_2_to_3_backs_up_after_precheck_and_keeps_old_sessions_legible() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("hopae.db");
    write_v2(&db);
    {
        let c = Connection::open(&db).unwrap();
        c.execute_batch(
            "INSERT INTO users (user_id, created_at, updated_at) VALUES ('u_old', 1, 1);
             INSERT INTO sessions (session_id, user_id, provider_id, auth_time, aal, authz_version, cred_gen, bound_ip, created_at, last_seen_at, absolute_expires_at, authz_version_at_auth)
                VALUES ('s_old', 'u_old', 'mock', 5, 1, 1, 1, '192.0.2.1', 5, 5, 99, 1);",
        )
        .unwrap();
    }
    assert_eq!(precheck(&db).unwrap(), 2);
    // A previous backup exists with known content.
    let bak = dir.path().join("hopae.db.bak-v2");
    std::fs::write(&bak, b"previous backup").unwrap();
    let made = crate::app::backup::backup_before_migration(&db, 3).unwrap();
    assert_eq!(made.as_deref(), Some(bak.as_path()));
    assert!(
        leftovers(dir.path()).is_empty(),
        "no temporary file remains"
    );
    let copy = Connection::open(&bak).unwrap();
    let n: i64 = copy
        .query_row("SELECT COUNT(*) FROM sessions", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 1, "the new copy replaced the old backup");
    assert!(
        !has(&bak, "table", "admin_grants"),
        "the backup is the v2 database"
    );

    let store = Store::open(
        &db,
        Arc::new(crate::crypto::TestClock::new(Timestamp(0))),
        vec![],
        None,
    )
    .unwrap();
    assert_eq!(
        store.schema_version().unwrap(),
        crate::store::sqlite::LATEST_SCHEMA_VERSION
    );
    let c = store.conn();
    let (src, prefix): (String, Option<String>) = c
        .query_row(
            "SELECT auth_time_source, bound_ua_prefix FROM sessions WHERE session_id='s_old'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(src, "hopae_completion");
    assert_eq!(prefix, None);
    drop(c);
    drop(store);
    validate_foundation(&Connection::open(&db).unwrap(), 3).unwrap();
    for ix in [
        "events_at_id",
        "events_user_at_id",
        "events_ip_at_id",
        "events_kind_at_id",
        "events_session_at_id",
        "users_created_id",
        "sessions_live_created",
        "sessions_live_user_created",
        "admin_grants_source_email",
    ] {
        assert!(has(&db, "index", ix), "{ix}");
    }
    for old in ["events_at", "events_user_at", "events_ip_at"] {
        assert!(!has(&db, "index", old), "{old} is superseded");
    }
}

#[test]
fn a_pre_release_database_is_refused_before_any_backup_or_migration() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("hopae.db");
    write_pre_release_v2(&db);
    let bak = dir.path().join("hopae.db.bak-v2");
    std::fs::write(&bak, b"known backup content").unwrap();
    let before = std::fs::read(&db).unwrap();

    assert!(matches!(precheck(&db), Err(StoreError::DevelopmentSchema)));
    let e = crate::app::backup::backup_before_migration(&db, 3).unwrap_err();
    assert!(
        e.chain().any(|c| matches!(
            c.downcast_ref::<StoreError>(),
            Some(StoreError::DevelopmentSchema)
        )),
        "{e:#}"
    );
    let opened = Store::open(
        &db,
        Arc::new(crate::crypto::TestClock::new(Timestamp(0))),
        vec![],
        None,
    );
    assert!(matches!(opened, Err(StoreError::DevelopmentSchema)));
    let cli = Store::open_cli(
        &db,
        Arc::new(crate::crypto::TestClock::new(Timestamp(0))),
        vec![],
    );
    assert!(matches!(cli, Err(StoreError::DevelopmentSchema)));

    assert_eq!(version_of(&db), 2, "the recorded version did not move");
    assert!(!has(&db, "table", "admin_grants"));
    assert!(!has(&db, "index", "events_session_at_id"));
    assert_eq!(std::fs::read(&bak).unwrap(), b"known backup content");
    assert!(leftovers(dir.path()).is_empty());
    assert_eq!(
        std::fs::read(&db).unwrap(),
        before,
        "the database file is untouched"
    );
}

#[test]
fn a_current_database_missing_a_v3_structure_is_refused_naming_it() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("hopae.db");
    drop(
        Store::open(
            &db,
            Arc::new(crate::crypto::TestClock::new(Timestamp(0))),
            vec![],
            None,
        )
        .unwrap(),
    );
    Connection::open(&db)
        .unwrap()
        .execute_batch("DROP TABLE admin_grants")
        .unwrap();
    match precheck(&db) {
        Err(StoreError::Corrupt(m)) => assert!(m.contains("admin_grants"), "{m}"),
        other => panic!("expected Corrupt naming admin_grants, got {other:?}"),
    }
    // Restore the table so only one other structure is missing.
    let c = Connection::open(&db).unwrap();
    c.execute_batch(
        include_str!("../migrations/0003_admin.sql")
            .split("ALTER TABLE")
            .next()
            .unwrap(),
    )
    .unwrap();
    c.execute_batch("DROP INDEX events_kind_at_id").unwrap();
    drop(c);
    match precheck(&db) {
        Err(StoreError::Corrupt(m)) => assert!(m.contains("events_kind_at_id"), "{m}"),
        other => panic!("{other:?}"),
    }
    assert_eq!(
        version_of(&db),
        i64::from(crate::store::sqlite::LATEST_SCHEMA_VERSION)
    );
    let opened = Store::open(
        &db,
        Arc::new(crate::crypto::TestClock::new(Timestamp(0))),
        vec![],
        None,
    );
    assert!(matches!(opened, Err(StoreError::Corrupt(_))));
    assert_eq!(
        version_of(&db),
        i64::from(crate::store::sqlite::LATEST_SCHEMA_VERSION),
        "a refused database keeps its version"
    );
}

#[test]
fn a_failed_backup_leaves_the_previous_one_and_no_temporary_file() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("hopae.db");
    write_v2(&db);
    let bak = dir.path().join("hopae.db.bak-v2");
    std::fs::write(&bak, b"previous").unwrap();
    // A directory in the way of the temporary name makes the copy fail.
    std::fs::create_dir(dir.path().join("hopae.db.bak-v2.tmp")).unwrap();
    assert!(crate::app::backup::backup_before_migration(&db, 3).is_err());
    assert_eq!(
        std::fs::read(&bak).unwrap(),
        b"previous",
        "never deleted first"
    );
    std::fs::remove_dir(dir.path().join("hopae.db.bak-v2.tmp")).unwrap();
    // A stale temporary file of an interrupted run is replaced.
    std::fs::write(dir.path().join("hopae.db.bak-v2.tmp"), b"junk").unwrap();
    crate::app::backup::backup_before_migration(&db, 3).unwrap();
    assert!(leftovers(dir.path()).is_empty());
    assert_ne!(std::fs::read(&bak).unwrap(), b"previous");
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        std::fs::metadata(&bak).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[test]
fn the_cli_open_never_migrates_creates_or_backs_up() {
    let dir = tempfile::tempdir().unwrap();
    let clock = Arc::new(crate::crypto::TestClock::new(Timestamp(0)));
    let missing = dir.path().join("none.db");
    assert!(Store::open_cli(&missing, clock.clone(), vec![]).is_err());
    assert!(!missing.exists(), "the CLI never creates the database");
    let db = dir.path().join("hopae.db");
    write_v2(&db);
    match Store::open_cli(&db, clock.clone(), vec![]) {
        Err(StoreError::SchemaTooOld { found: 2, latest })
            if latest == crate::store::sqlite::LATEST_SCHEMA_VERSION => {}
        other => panic!("{:?}", other.map(|_| ())),
    }
    assert_eq!(version_of(&db), 2);
    assert!(!dir.path().join("hopae.db.bak-v2").exists());
    drop(Store::open(&db, clock.clone(), vec![], None).unwrap());
    let cli = Store::open_cli(&db, clock, vec!["log".into()]).unwrap();
    assert_eq!(
        cli.schema_version().unwrap(),
        crate::store::sqlite::LATEST_SCHEMA_VERSION
    );
}

#[test]
fn ldap_kind_migration_preserves_provider_rows_and_is_atomic_on_failure() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("owned.db");
    write_v2(&path);
    let conn = Connection::open(&path).unwrap();
    conn.execute_batch(include_str!("../migrations/0003_admin.sql"))
        .unwrap();
    conn.execute("INSERT INTO schema_migrations VALUES(3,'0003_admin',0)", [])
        .unwrap();
    conn.execute("INSERT INTO providers(provider_id,kind,display_name,enabled,managed_by,client_secret_env,created_at,updated_at)VALUES('owned','oidc','Owned',1,'api','OWNED_REFERENCE',10,20)",[]).unwrap();
    conn.execute_batch("CREATE TABLE providers_v4(occupied INTEGER)")
        .unwrap();
    assert!(super::super::migrate(&conn).is_err());
    assert_eq!(version_of(&path), 3);
    let original: (String, String, String) = conn
        .query_row(
            "SELECT kind,managed_by,client_secret_env FROM providers WHERE provider_id='owned'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(
        original,
        ("oidc".into(), "api".into(), "OWNED_REFERENCE".into())
    );
    conn.execute_batch("DROP TABLE providers_v4").unwrap();
    // Force rename failure after the replacement table was copied and old table dropped.
    conn.execute_batch("CREATE VIEW invalid_owned_view AS SELECT * FROM missing_owned_table")
        .unwrap();
    assert!(super::super::migrate(&conn).is_err());
    assert_eq!(version_of(&path), 3);
    let rows: i64 = conn
        .query_row(
            "SELECT count(*) FROM providers WHERE provider_id='owned'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(rows, 1, "failed DDL did not restore the original table");
    conn.execute_batch("DROP VIEW invalid_owned_view").unwrap();

    assert_eq!(
        super::super::migrate(&conn).unwrap(),
        crate::store::sqlite::LATEST_SCHEMA_VERSION
    );
    let retained: (String, String, String) = conn
        .query_row(
            "SELECT kind,managed_by,client_secret_env FROM providers WHERE provider_id='owned'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(retained, original);
    conn.execute("INSERT INTO providers(provider_id,kind,display_name,enabled,managed_by,created_at,updated_at)VALUES('directory','ldap','Directory',0,'file',0,0)",[]).unwrap();
    assert_eq!(
        super::super::migrate(&conn).unwrap(),
        crate::store::sqlite::LATEST_SCHEMA_VERSION
    );
}

// ---- the console fixture -----------------------------------------------

#[allow(dead_code)]
struct Console {
    f: Fx,
    admin: User,
    target: User,
    sess: Sess,
    handle: Secret,
    actor: Actor,
    policy: ActorPolicy,
}

fn base_policy(now: Timestamp) -> ActorPolicy {
    ActorPolicy {
        authority: None,
        console_host: host(CONSOLE),
        session: SessionPolicy {
            idle: Duration::from_secs(24 * 3600),
            absolute: Duration::from_secs(30 * 86400),
        },
        handle: Lifetimes {
            idle: Duration::from_secs(12 * 3600),
            absolute: Duration::from_secs(7 * 86400),
        },
        max_auth_age: Duration::from_secs(12 * 3600),
        capability_requires_claim: false,
        require_aal: Aal::One,
        now,
        skew: Duration::from_secs(60),
    }
}

impl Fx {
    fn ev(&self, kind: EventKind) -> Event {
        EventBuilder::new(&*self.clock, &self.rng, kind, Outcome::Success, "req-admin").build()
    }

    fn ev_user(&self, kind: EventKind, user: &UserId) -> Event {
        EventBuilder::new(&*self.clock, &self.rng, kind, Outcome::Success, "req-admin")
            .user(user)
            .build()
    }

    fn session_event(&self, row: &SessionRow) -> Event {
        EventBuilder::new(
            &*self.clock,
            &self.rng,
            EventKind::SessionTerminated,
            Outcome::Success,
            "req-admin",
        )
        .user(&row.user_id)
        .session(&row.session_id)
        .reason(reasons::USER_DISABLED)
        .build()
    }

    async fn grant(&self, user: &User, role: AdminRole) {
        self.store
            .grant_admin(
                &user.user_id,
                role,
                GrantManagedBy::Api,
                None,
                "cli",
                None,
                self.now(),
                self.ev_user(EventKind::AdminGrant, &user.user_id),
            )
            .await
            .unwrap();
    }

    fn count_kind(&self, kind: &str) -> i64 {
        self.count(&format!("SELECT COUNT(*) FROM events WHERE kind='{kind}'"))
    }
}

/// `admin` (granted `admin`) with a console handle, and a `target` user.
async fn console() -> Console {
    let f = fx();
    let admin = f.user(1).await;
    let target = f.user(2).await;
    let sess = f.session(&admin, vec![]).await;
    let handle = handle_value(&f.rng);
    f.store
        .mint_handle(
            f.handle_row(&sess.row.session_id, CONSOLE, &handle),
            None,
            vec![],
        )
        .await
        .unwrap();
    f.grant(&admin, AdminRole::Admin).await;
    let actor = Actor {
        user_id: admin.user_id.clone(),
        session_id: sess.row.session_id.clone(),
        handle_sha256: handle.digest(),
    };
    let policy = base_policy(f.now());
    Console {
        f,
        admin,
        target,
        sess,
        handle,
        actor,
        policy,
    }
}

impl Console {
    async fn disable_target(&self) -> Result<(bool, u32), StoreError> {
        self.disable_with(&self.policy).await
    }

    async fn disable_with(&self, policy: &ActorPolicy) -> Result<(bool, u32), StoreError> {
        let f = &self.f;
        self.f
            .store
            .set_user_status(
                &self.actor,
                policy,
                &self.target.user_id,
                UserStatus::Disabled,
                long(),
                f.ev_user(EventKind::AdminUserDisable, &self.target.user_id),
                &|row| f.session_event(row),
            )
            .await
    }

    fn target_status(&self) -> String {
        self.f
            .store
            .conn()
            .query_row(
                "SELECT status FROM users WHERE user_id=?1",
                [self.target.user_id.as_str()],
                |r| r.get(0),
            )
            .unwrap()
    }

    fn sql(&self, sql: &str) {
        self.f.store.conn().execute_batch(sql).unwrap();
    }
}

fn assert_actor_revoked(c: &Console, out: Result<(bool, u32), StoreError>, name: &str) {
    assert!(
        matches!(out, Err(StoreError::Conflict("actor_revoked"))),
        "{name}: {out:?}"
    );
    assert_eq!(c.target_status(), "active", "{name}: target unchanged");
    assert_eq!(c.f.count_kind("admin.user_disable"), 0, "{name}: no event");
}

// ---- the actor fence: 300-A3's thirteen variants and the controls -------------

#[tokio::test]
async fn fence_control_run_commits_and_writes_its_event() {
    let c = console().await;
    let t =
        c.f.store
            .directory()
            .user(&c.target.user_id)
            .await
            .unwrap()
            .unwrap();
    assert_eq!(t.status, UserStatus::Active);
    assert_eq!(c.disable_target().await.unwrap(), (true, 0));
    assert_eq!(c.target_status(), "disabled");
    assert_eq!(c.f.count_kind("admin.user_disable"), 1);
}

#[tokio::test]
async fn fence_refuses_each_of_the_thirteen_changes_between_check_and_write() {
    type Case = (&'static str, fn(&Console) -> Option<ActorPolicy>);
    // Each case changes ONE thing; the fence must see it. Returning a policy
    // replaces the one passed to the write (policy shortened).
    let cases: Vec<Case> = vec![
        ("1 grant revoked", |c| {
            c.sql("UPDATE admin_grants SET revoked_at=1, revoked_by='cli'");
            None
        }),
        ("2 role viewer", |c| {
            c.sql("UPDATE admin_grants SET role='viewer'");
            None
        }),
        ("3 session terminated", |c| {
            c.sql("UPDATE sessions SET terminated_at=1, terminated_reason='admin'");
            None
        }),
        ("4 handle revoked", |c| {
            c.sql("UPDATE session_handles SET revoked_at=1, revoked_reason='switch' WHERE host='hopae-admin.example.test'");
            None
        }),
        ("5 handle idle passed, no sweep", |c| {
            c.f.clock.advance(Duration::from_secs(12 * 3600 + 1));
            // The session itself stays active and fresh, so the handle's idle
            // deadline is the only predicate that can refuse.
            c.sql("UPDATE sessions SET last_seen_at=last_seen_at + 43201, auth_time=auth_time + 43201");
            None
        }),
        ("6 session stored absolute passed, no sweep", |c| {
            c.sql("UPDATE sessions SET absolute_expires_at=created_at + 3600");
            c.f.clock.advance(Duration::from_secs(3601));
            c.sql("UPDATE session_handles SET last_seen_at=last_seen_at + 3601; UPDATE sessions SET last_seen_at=last_seen_at + 3601");
            None
        }),
        ("7 actor disabled", |c| {
            c.sql(&format!(
                "UPDATE users SET status='disabled' WHERE user_id='{}'",
                c.admin.user_id
            ));
            None
        }),
        ("8 groups changed (authz_version moved)", |c| {
            c.sql(&format!(
                "UPDATE users SET authz_version=authz_version+1 WHERE user_id='{}'",
                c.admin.user_id
            ));
            None
        }),
        ("9 FRESH fails by one second", |c| {
            let mut p = c.policy.clone();
            p.max_auth_age = Duration::from_secs(1000);
            c.f.clock.advance(Duration::from_secs(1000));
            c.sql("UPDATE sessions SET last_seen_at=last_seen_at + 1000; UPDATE session_handles SET last_seen_at=last_seen_at + 1000");
            Some(p)
        }),
        ("10 handle host mismatch", |c| {
            c.sql("UPDATE session_handles SET host='app.example.test' WHERE host='hopae-admin.example.test'");
            None
        }),
        (
            "11 policy shortened below the stored handle deadline",
            |c| {
                c.f.clock.advance(Duration::from_secs(3600));
                c.sql("UPDATE sessions SET last_seen_at=last_seen_at + 3600; UPDATE session_handles SET last_seen_at=last_seen_at + 3600");
                let mut p = c.policy.clone();
                p.handle.absolute = Duration::from_secs(3599); // created_at + 3599 is one second in the past
                Some(p)
            },
        ),
        ("12 session-wide absolute shortened", |c| {
            c.f.clock.advance(Duration::from_secs(3600));
            c.sql("UPDATE sessions SET last_seen_at=last_seen_at + 3600; UPDATE session_handles SET last_seen_at=last_seen_at + 3600");
            let mut p = c.policy.clone();
            p.session.absolute = Duration::from_secs(3599);
            Some(p)
        }),
        ("13 handle created 61 s in the future", |c| {
            c.sql(&format!(
                "UPDATE session_handles SET created_at={} WHERE host='hopae-admin.example.test'",
                c.f.now().secs() + 61
            ));
            None
        }),
    ];
    assert_eq!(cases.len(), 13);
    for (name, change) in cases {
        let c = console().await;
        let replaced = change(&c);
        let out = c.disable_with(replaced.as_ref().unwrap_or(&c.policy)).await;
        assert_actor_revoked(&c, out, name);
    }
}

/// Each of these moves the clock or one stored value so that exactly one
/// predicate of the fence can refuse; removing that predicate from the SQL
/// makes its case commit.
#[tokio::test]
async fn s300_a3_fence_each_isolated_predicate_refuses_on_its_own() {
    type Case = (&'static str, fn(&Console) -> Option<ActorPolicy>);
    let cases: Vec<Case> = vec![
        ("handle idle only", |c| {
            c.f.clock.advance(Duration::from_secs(12 * 3600 + 1));
            // The session is kept alive and fresh; the handle was last seen long ago.
            c.sql("UPDATE sessions SET last_seen_at=last_seen_at + 43201, auth_time=auth_time + 43201");
            None
        }),
        ("session idle only", |c| {
            c.f.clock.advance(Duration::from_secs(24 * 3600 + 1));
            // The handle is kept alive and the claim fresh; the session was last seen long ago.
            c.sql("UPDATE session_handles SET last_seen_at=last_seen_at + 86401; UPDATE sessions SET auth_time=auth_time + 86401");
            None
        }),
        ("session created 61 s in the future", |c| {
            c.sql(&format!(
                "UPDATE sessions SET created_at={}",
                c.f.now().secs() + 61
            ));
            None
        }),
        ("auth_time 61 s in the future", |c| {
            c.sql(&format!(
                "UPDATE sessions SET auth_time={}",
                c.f.now().secs() + 61
            ));
            None
        }),
        ("actor handle digest differs from the stored handle", |c| {
            c.sql("UPDATE session_handles SET handle_sha256=randomblob(32)");
            None
        }),
    ];
    for (name, change) in cases {
        let c = console().await;
        let replaced = change(&c);
        let out = c.disable_with(replaced.as_ref().unwrap_or(&c.policy)).await;
        assert_actor_revoked(&c, out, name);
    }
}

#[tokio::test]
async fn fence_boundaries_the_other_side_still_commits() {
    // One second short of each bound commits; the bound itself does not.
    type Change = fn(&Console) -> Option<ActorPolicy>;
    let cases: Vec<(&str, Change)> = vec![
        ("fresh by one second", |c| {
            let mut p = c.policy.clone();
            p.max_auth_age = Duration::from_secs(1000);
            c.f.clock.advance(Duration::from_secs(999));
            c.sql("UPDATE sessions SET last_seen_at=last_seen_at + 999; UPDATE session_handles SET last_seen_at=last_seen_at + 999");
            Some(p)
        }),
        ("handle created exactly 60 s ahead", |c| {
            c.sql(&format!(
                "UPDATE session_handles SET created_at={} WHERE host='hopae-admin.example.test'",
                c.f.now().secs() + 60
            ));
            None
        }),
        ("policy lengthened within the stored deadline", |c| {
            c.f.clock.advance(Duration::from_secs(3600));
            c.sql("UPDATE sessions SET last_seen_at=last_seen_at + 3600; UPDATE session_handles SET last_seen_at=last_seen_at + 3600");
            let mut p = c.policy.clone();
            p.handle.absolute = Duration::from_secs(100 * 86400);
            p.session.absolute = Duration::from_secs(100 * 86400);
            Some(p)
        }),
    ];
    for (name, change) in cases {
        let c = console().await;
        let replaced = change(&c);
        let out = c.disable_with(replaced.as_ref().unwrap_or(&c.policy)).await;
        assert_eq!(
            out.unwrap_or_else(|e| panic!("{name}: {e:?}")),
            (true, 0),
            "{name}"
        );
    }
    // Lengthening the policy never extends the stored deadline.
    let c = console().await;
    c.sql("UPDATE session_handles SET absolute_expires_at=created_at + 1800 WHERE host='hopae-admin.example.test'");
    c.f.clock.advance(Duration::from_secs(1801));
    c.sql("UPDATE sessions SET last_seen_at=last_seen_at + 1801; UPDATE session_handles SET last_seen_at=last_seen_at + 1801");
    let mut p = c.policy.clone();
    p.handle.absolute = Duration::from_secs(365 * 86400);
    assert_actor_revoked(&c, c.disable_with(&p).await, "stored deadline still bounds");
}

#[tokio::test]
async fn fence_also_checks_the_claim_requirement_and_aal() {
    let c = console().await;
    let mut p = c.policy.clone();
    p.capability_requires_claim = true; // the session's auth_time came from Hopae completion
    assert_actor_revoked(&c, c.disable_with(&p).await, "claim required");
    c.sql("UPDATE sessions SET auth_time_source='provider_claim'");
    assert_eq!(c.disable_with(&p).await.unwrap(), (true, 0));

    let c = console().await;
    let mut p = c.policy.clone();
    p.require_aal = Aal::Two;
    assert_actor_revoked(&c, c.disable_with(&p).await, "aal");
}

#[tokio::test]
async fn a_change_committed_while_the_gate_holds_the_job_wins() {
    let c = console().await;
    c.f.hooks.set_gate("admin_mutation", true);
    let revoke = {
        let store = c.f.store.clone();
        let user = c.admin.user_id.clone();
        let ev = c.f.ev_user(EventKind::AdminRevoke, &user);
        let at = c.f.now();
        let hooks = c.f.hooks.clone();
        async move {
            let hooks2 = hooks.clone();
            assert!(
                tokio::task::spawn_blocking(move || hooks2.wait_reached(
                    "admin_mutation",
                    1,
                    Duration::from_secs(5)
                ))
                .await
                .unwrap(),
                "the mutation job reached the gate"
            );
            // The write is queued behind the held job on the one writer; commit the
            // revocation through a second connection (the CLI's path).
            let c2 = Connection::open(store.path()).unwrap();
            c2.busy_timeout(Duration::from_secs(5)).unwrap();
            c2.execute(
                "UPDATE admin_grants SET revoked_at=?2, revoked_by='cli' WHERE user_id=?1",
                rusqlite::params![user.as_str(), at.secs()],
            )
            .unwrap();
            let _ = ev;
            hooks.set_gate("admin_mutation", false);
        }
    };
    let (out, ()) = tokio::join!(c.disable_target(), revoke);
    assert_actor_revoked(&c, out, "gate");
}

// ---- fenced mutations ----------------------------------------------------

#[tokio::test]
async fn disabling_terminates_n_sessions_with_n_plus_one_events_in_one_transaction() {
    let c = console().await;
    let mut sessions = Vec::new();
    for _ in 0..3 {
        sessions.push(c.f.session(&c.target, vec![]).await);
    }
    let before =
        c.f.store
            .directory()
            .user(&c.target.user_id)
            .await
            .unwrap()
            .unwrap();
    assert_eq!(c.disable_target().await.unwrap(), (true, 3));
    let after =
        c.f.store
            .directory()
            .user(&c.target.user_id)
            .await
            .unwrap()
            .unwrap();
    assert_eq!(after.status, UserStatus::Disabled);
    assert_eq!(after.authz_version, before.authz_version + 1);
    for s in &sessions {
        let row = c.f.store.session(&s.row.session_id).await.unwrap().unwrap();
        assert!(row.terminated_at.is_some());
        assert_eq!(row.terminated_reason.as_deref(), Some("user_disabled"));
        assert_eq!(row.cred_gen, s.row.cred_gen + 1);
    }
    assert_eq!(c.f.count_kind("session.terminated"), 3);
    assert_eq!(c.f.count_kind("admin.user_disable"), 1);
    assert_eq!(
        c.f.count("SELECT COUNT(*) FROM session_handles h JOIN sessions s USING (session_id) WHERE s.user_id IN (SELECT user_id FROM users WHERE status='disabled') AND h.revoked_at IS NULL"),
        0
    );
    assert_eq!(
        c.f.count("SELECT COUNT(*) FROM event_deliveries WHERE sink='log' AND state='pending'"),
        c.f.count("SELECT COUNT(*) FROM events WHERE kind IN ('session.terminated','admin.user_disable','admin.grant')"),
        "every required event has its delivery row"
    );
}

#[tokio::test]
async fn disabling_is_rolled_back_when_the_deadline_passes_mid_loop() {
    let c = console().await;
    for _ in 0..8 {
        c.f.session(&c.target, vec![]).await;
    }
    c.f.hooks.set_slow_scan(40);
    let f = &c.f;
    let started = Instant::now();
    let out = f
        .store
        .set_user_status(
            &c.actor,
            &c.policy,
            &c.target.user_id,
            UserStatus::Disabled,
            dl(150),
            f.ev_user(EventKind::AdminUserDisable, &c.target.user_id),
            &|row| f.session_event(row),
        )
        .await;
    c.f.hooks.set_slow_scan(0);
    assert!(
        matches!(out, Err(StoreError::Unavailable(ref m)) if m == "deadline" || m == "interrupted"),
        "{out:?}"
    );
    assert!(started.elapsed() < Duration::from_millis(1500));
    assert_eq!(c.target_status(), "active");
    assert_eq!(c.f.count("SELECT COUNT(*) FROM sessions WHERE user_id IN (SELECT user_id FROM users WHERE status='active' AND user_id='') OR terminated_at IS NOT NULL"), 0);
    assert_eq!(c.f.count_kind("session.terminated"), 0);
    assert_eq!(c.f.count_kind("admin.user_disable"), 0);
}

#[tokio::test]
async fn idempotent_status_changes_write_no_event() {
    let c = console().await;
    // Enabling an active user is a no-op.
    let f = &c.f;
    let out = f
        .store
        .set_user_status(
            &c.actor,
            &c.policy,
            &c.target.user_id,
            UserStatus::Active,
            long(),
            f.ev_user(EventKind::AdminUserEnable, &c.target.user_id),
            &|row| f.session_event(row),
        )
        .await
        .unwrap();
    assert_eq!(out, (false, 0));
    assert!(c.disable_target().await.unwrap().0);
    assert_eq!(
        c.disable_target().await.unwrap(),
        (false, 0),
        "disable twice"
    );
    assert_eq!(c.f.count_kind("admin.user_disable"), 1);
    assert_eq!(c.f.count_kind("admin.user_enable"), 0);
    // Enable really enables and moves authz_version.
    let before = f
        .store
        .directory()
        .user(&c.target.user_id)
        .await
        .unwrap()
        .unwrap();
    let out = f
        .store
        .set_user_status(
            &c.actor,
            &c.policy,
            &c.target.user_id,
            UserStatus::Active,
            long(),
            f.ev_user(EventKind::AdminUserEnable, &c.target.user_id),
            &|row| f.session_event(row),
        )
        .await
        .unwrap();
    assert_eq!(out, (true, 0));
    let after = f
        .store
        .directory()
        .user(&c.target.user_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after.status, UserStatus::Active);
    assert_eq!(after.authz_version, before.authz_version + 1);
    assert_eq!(c.f.count_kind("admin.user_enable"), 1);
    // An unknown user is refused, not silently ignored.
    let out = f
        .store
        .set_user_status(
            &c.actor,
            &c.policy,
            &UserId::new("u_nobody"),
            UserStatus::Disabled,
            long(),
            f.ev(EventKind::AdminUserDisable),
            &|row| f.session_event(row),
        )
        .await;
    assert!(
        matches!(out, Err(StoreError::Conflict("unknown user"))),
        "{out:?}"
    );
}

#[tokio::test]
async fn admin_session_termination_is_fenced_idempotent_and_writes_both_events() {
    let c = console().await;
    let victim = c.f.session(&c.target, vec![]).await;
    let f = &c.f;
    let mk = |f: &Fx, s: &SessionRow| {
        EventBuilder::new(
            &*f.clock,
            &f.rng,
            EventKind::SessionTerminated,
            Outcome::Success,
            "r",
        )
        .session(&s.session_id)
        .reason(reasons::ADMIN)
        .build()
    };
    let ended = f
        .store
        .admin_terminate_session(
            &c.actor,
            &c.policy,
            &victim.row.session_id,
            long(),
            f.ev(EventKind::AdminSessionTerminate),
            mk(f, &victim.row),
        )
        .await
        .unwrap();
    assert!(ended);
    let row = f
        .store
        .session(&victim.row.session_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.terminated_reason.as_deref(), Some("admin"));
    assert_eq!(f.count_kind("admin.session_terminate"), 1);
    assert_eq!(f.count_kind("session.terminated"), 1);
    // Again: nothing live, nothing written.
    let again = f
        .store
        .admin_terminate_session(
            &c.actor,
            &c.policy,
            &victim.row.session_id,
            long(),
            f.ev(EventKind::AdminSessionTerminate),
            mk(f, &victim.row),
        )
        .await
        .unwrap();
    assert!(!again);
    assert_eq!(f.count_kind("admin.session_terminate"), 1);
    // Unknown session.
    let none = f
        .store
        .admin_terminate_session(
            &c.actor,
            &c.policy,
            &SessionId::new("s_none"),
            long(),
            f.ev(EventKind::AdminSessionTerminate),
            mk(f, &victim.row),
        )
        .await
        .unwrap();
    assert!(!none);
    // A revoked actor cannot.
    c.sql("UPDATE admin_grants SET revoked_at=1, revoked_by='cli'");
    let other = f.session(&c.target, vec![]).await;
    let out = f
        .store
        .admin_terminate_session(
            &c.actor,
            &c.policy,
            &other.row.session_id,
            long(),
            f.ev(EventKind::AdminSessionTerminate),
            mk(f, &other.row),
        )
        .await;
    assert!(
        matches!(out, Err(StoreError::Conflict("actor_revoked"))),
        "{out:?}"
    );
    assert!(
        f.store
            .session(&other.row.session_id)
            .await
            .unwrap()
            .unwrap()
            .terminated_at
            .is_none()
    );
}

#[tokio::test]
async fn admin_terminating_a_users_sessions_counts_and_writes_one_admin_event() {
    let c = console().await;
    for _ in 0..2 {
        c.f.session(&c.target, vec![]).await;
    }
    let f = &c.f;
    let n = f
        .store
        .admin_terminate_user_sessions(
            &c.actor,
            &c.policy,
            &c.target.user_id,
            long(),
            f.ev(EventKind::AdminSessionsTerminate),
            &|row| f.session_event(row),
        )
        .await
        .unwrap();
    assert_eq!(n, 2);
    assert_eq!(f.count_kind("session.terminated"), 2);
    assert_eq!(f.count_kind("admin.sessions_terminate"), 1);
    let n = f
        .store
        .admin_terminate_user_sessions(
            &c.actor,
            &c.policy,
            &c.target.user_id,
            long(),
            f.ev(EventKind::AdminSessionsTerminate),
            &|row| f.session_event(row),
        )
        .await
        .unwrap();
    assert_eq!(n, 0);
    assert_eq!(
        f.count_kind("admin.sessions_terminate"),
        1,
        "nothing live: no event"
    );
}

// ---- reauthentication ------------------------------------------------------

#[tokio::test]
async fn reauthentication_is_atomic_rotates_handles_and_checks_the_provider() {
    let f = fx();
    let u = f.user(1).await;
    let s = f.session(&u, vec![]).await;
    let app_handle = handle_value(&f.rng);
    f.store
        .mint_handle(
            f.handle_row(&s.row.session_id, APP_HOST, &app_handle),
            None,
            vec![],
        )
        .await
        .unwrap();
    let code = f.code(&s).await;
    let txn_secret = handle_value(&f.rng);
    f.store
        .create_transaction(new_txn(&f, &txn_secret, "192.0.2.10"), vec![])
        .await
        .unwrap();
    f.clock.advance(Duration::from_secs(120));
    let at = f.now();
    let fresh = handle_value(&f.rng);
    let new_handle = f.handle_row(&s.row.session_id, PORTAL_HOST, &fresh);
    let factor = FactorEntry {
        kind: FactorKind::Oidc,
        provider: Some(ProviderId::new("mock")),
        at,
    };

    // The wrong provider is refused inside the transaction; nothing changes.
    let out = f
        .store
        .reauthenticate_session(
            &s.row.session_id,
            &ProviderId::new("other"),
            None,
            at,
            AuthTimeSource::ProviderClaim,
            factor.clone(),
            new_handle.clone(),
            (txn_secret.digest(), reasons::REAUTH),
            long(),
            vec![f.ev(EventKind::LoginSucceeded)],
            &|_| f.ev(EventKind::HandleRevoked),
        )
        .await;
    assert!(
        matches!(out, Err(StoreError::Conflict("provider_mismatch"))),
        "{out:?}"
    );
    let row = f.store.session(&s.row.session_id).await.unwrap().unwrap();
    assert_eq!(row.cred_gen, s.row.cred_gen);
    assert_eq!(row.auth_time, s.row.auth_time);
    assert_eq!(f.count_kind("login.succeeded"), 0);
    assert_eq!(
        f.count("SELECT COUNT(*) FROM login_txns WHERE consumed_at IS NOT NULL"),
        0
    );

    f.store.conn().execute(
        "INSERT INTO providers(provider_id,kind,display_name,enabled,managed_by,config,created_at,updated_at) VALUES('mock','oidc','Mock',1,'api','{}',0,0)", [],
    ).unwrap();
    for expected in [
        (
            crate::provider::types::ProviderKind::Ldap,
            serde_json::json!({}),
        ),
        (
            crate::provider::types::ProviderKind::Oidc,
            serde_json::json!({"stale":true}),
        ),
    ] {
        let result = f
            .store
            .reauthenticate_session(
                &s.row.session_id,
                &ProviderId::new("mock"),
                Some(expected),
                at,
                AuthTimeSource::ProviderClaim,
                factor.clone(),
                new_handle.clone(),
                (txn_secret.digest(), reasons::REAUTH),
                long(),
                vec![f.ev(EventKind::LoginSucceeded)],
                &|_| f.ev(EventKind::HandleRevoked),
            )
            .await;
        assert!(matches!(result, Err(StoreError::ProviderDisabled)));
        let unchanged = f.store.session(&s.row.session_id).await.unwrap().unwrap();
        assert_eq!(unchanged.cred_gen, s.row.cred_gen);
        assert_eq!(unchanged.auth_time, s.row.auth_time);
        assert_eq!(
            f.count("SELECT COUNT(*) FROM session_handles WHERE revoked_at IS NOT NULL"),
            0
        );
        assert_eq!(
            f.count("SELECT COUNT(*) FROM login_txns WHERE consumed_at IS NOT NULL"),
            0
        );
        assert_eq!(f.count_kind("login.succeeded"), 0);
    }

    f.store
        .reauthenticate_session(
            &s.row.session_id,
            &ProviderId::new("mock"),
            None,
            at,
            AuthTimeSource::ProviderClaim,
            factor,
            new_handle,
            (txn_secret.digest(), reasons::REAUTH),
            long(),
            vec![f.ev(EventKind::LoginSucceeded)],
            &|_| f.ev(EventKind::HandleRevoked),
        )
        .await
        .unwrap();
    assert_eq!(
        f.count_kind("handle.revoked"),
        2,
        "one event per handle revoked in the transaction"
    );
    let row = f.store.session(&s.row.session_id).await.unwrap().unwrap();
    assert_eq!(row.auth_time, at);
    assert_eq!(row.auth_time_source, AuthTimeSource::ProviderClaim);
    assert_eq!(row.factors.len(), 2);
    assert_eq!(row.cred_gen, s.row.cred_gen + 1);
    assert_eq!(row.created_at, s.row.created_at, "session identity is kept");
    assert_eq!(row.absolute_expires_at, s.row.absolute_expires_at);
    // Every old handle is revoked with reason reauth; only the new portal handle is live.
    assert_eq!(
        f.count("SELECT COUNT(*) FROM session_handles WHERE revoked_reason='reauth'"),
        2
    );
    assert_eq!(
        f.count("SELECT COUNT(*) FROM session_handles WHERE revoked_at IS NULL"),
        1
    );
    assert!(
        f.store
            .lookup_handle(&fresh.digest(), &host(PORTAL_HOST))
            .await
            .unwrap()
            .is_some()
    );
    // Outstanding codes are consumed, the transaction too, the event committed with it.
    let (consumed, why): (Option<i64>, Option<String>) = f
        .store
        .conn()
        .query_row(
            "SELECT consumed_at, consumed_reason FROM handoff_codes WHERE code_sha256=?1",
            [&code.row.code_sha256.0[..]],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert!(consumed.is_some());
    assert_eq!(why.as_deref(), Some("reauth"));
    assert_eq!(
        f.count("SELECT COUNT(*) FROM login_txns WHERE consumed_reason='reauth'"),
        1
    );
    assert_eq!(f.count_kind("login.succeeded"), 1);

    // A consumed transaction cannot be used twice, and the refusal rolls everything back.
    let again = handle_value(&f.rng);
    let out = f
        .store
        .reauthenticate_session(
            &s.row.session_id,
            &ProviderId::new("mock"),
            None,
            at,
            AuthTimeSource::ProviderClaim,
            FactorEntry {
                kind: FactorKind::Oidc,
                provider: None,
                at,
            },
            f.handle_row(&s.row.session_id, PORTAL_HOST, &again),
            (txn_secret.digest(), reasons::REAUTH),
            long(),
            vec![],
            &|_| f.ev(EventKind::HandleRevoked),
        )
        .await;
    assert!(matches!(out, Err(StoreError::Conflict(_))), "{out:?}");
    assert_eq!(
        f.store
            .session(&s.row.session_id)
            .await
            .unwrap()
            .unwrap()
            .cred_gen,
        s.row.cred_gen + 1
    );
    assert!(
        f.store
            .lookup_handle(&again.digest(), &host(PORTAL_HOST))
            .await
            .unwrap()
            .is_none()
    );
}

// ---- grants --------------------------------------------------------------

fn email(s: &str) -> NormalizedEmail {
    NormalizedEmail::parse(s).unwrap()
}

impl Fx {
    async fn grant_by(
        &self,
        user: &User,
        role: AdminRole,
        by: &str,
        managed: GrantManagedBy,
        source: Option<&str>,
    ) -> (Option<AdminRole>, bool) {
        self.store
            .grant_admin(
                &user.user_id,
                role,
                managed,
                source.map(email),
                by,
                None,
                self.now(),
                self.ev_user(EventKind::AdminGrant, &user.user_id),
            )
            .await
            .unwrap()
    }

    async fn revoke(&self, user: &User, by: &str) -> bool {
        self.store
            .revoke_admin(
                &user.user_id,
                by,
                GrantManagedBy::Api,
                self.now(),
                self.ev_user(EventKind::AdminRevoke, &user.user_id),
            )
            .await
            .unwrap()
    }

    async fn grant_row(&self, user: &User) -> Option<AdminGrant> {
        self.store.admin_grant(&user.user_id, long()).await.unwrap()
    }
}

fn last_event_attr(f: &Fx, kind: &str, key: &str) -> Option<String> {
    f.store
        .conn()
        .query_row(
            // This helper asks for the last committed fixture mutation. Event
            // IDs order generation, not commit, and bounded global ID state
            // need not retain an old fixture millisecond during parallel tests.
            "SELECT CAST(json_extract(attrs, ?2) AS TEXT) FROM events WHERE kind=?1 ORDER BY rowid DESC LIMIT 1",
            [kind, &format!("$.{key}")],
            |r| r.get(0),
        )
        .unwrap()
}

#[test]
fn latest_admin_event_fixture_uses_commit_order_with_equal_times_and_reversed_ids() {
    let f = fx();
    let conn = f.store.conn();
    for (id, attrs) in [
        ("e_0000000000000000000000000Z", r#"{"actor":"first"}"#),
        ("e_0000000000000000000000000A", r#"{"actor":"second"}"#),
    ] {
        conn.execute("INSERT INTO events(event_id,at,kind,outcome,request_id,attrs) VALUES (?1,10,'admin.grant','info','fixture',?2)",rusqlite::params![id,attrs]).unwrap();
    }
    drop(conn);
    assert_eq!(
        last_event_attr(&f, "admin.grant", "actor").as_deref(),
        Some("second")
    );
}

#[tokio::test]
async fn grants_are_written_with_their_event_repeated_ones_are_noops_and_regrants_report_the_previous_role()
 {
    let f = fx();
    let u = f.user(1).await;
    // First grant: no previous role, row and event in one transaction.
    assert_eq!(
        f.grant_by(&u, AdminRole::Admin, "cli", GrantManagedBy::Api, None)
            .await,
        (None, true)
    );
    let g = f.grant_row(&u).await.unwrap();
    assert_eq!(
        (g.role, g.managed_by, g.granted_by.as_str()),
        (AdminRole::Admin, GrantManagedBy::Api, "cli")
    );
    assert!(g.revoked_at.is_none() && g.source_email.is_none());
    assert_eq!(f.count_kind("admin.grant"), 1);
    assert_eq!(last_event_attr(&f, "admin.grant", "previous_role"), None);
    assert_eq!(
        f.count("SELECT COUNT(*) FROM event_deliveries WHERE sink='log' AND state='pending'"),
        1
    );
    // Repeating it is a no-op: no row change, no event.
    assert_eq!(
        f.grant_by(&u, AdminRole::Admin, "cli", GrantManagedBy::Api, None)
            .await,
        (Some(AdminRole::Admin), false)
    );
    assert_eq!(f.count_kind("admin.grant"), 1);
    // Revoke leaves a tombstone; revoking twice writes nothing the second time.
    assert!(f.revoke(&u, "cli").await);
    assert!(!f.revoke(&u, "cli").await);
    assert_eq!(f.count_kind("admin.revoke"), 1);
    assert_eq!(
        last_event_attr(&f, "admin.revoke", "previous_role").as_deref(),
        Some("admin")
    );
    let g = f.grant_row(&u).await.unwrap();
    assert!(g.revoked_at.is_some());
    assert_eq!(g.revoked_by.as_deref(), Some("cli"));
    assert_eq!(f.store.admin_grants(false, long()).await.unwrap().len(), 0);
    assert_eq!(f.store.admin_grants(true, long()).await.unwrap().len(), 1);
    // Re-grant clears the revocation and may change the role; previous role is the role before, revoked or not.
    f.clock.advance(Duration::from_secs(5));
    assert_eq!(
        f.grant_by(&u, AdminRole::Viewer, "cli", GrantManagedBy::Api, None)
            .await,
        (Some(AdminRole::Admin), true)
    );
    let g = f.grant_row(&u).await.unwrap();
    assert!(g.revoked_at.is_none() && g.revoked_by.is_none());
    assert_eq!(g.role, AdminRole::Viewer);
    assert_eq!(g.granted_at, f.now());
    assert_eq!(
        last_event_attr(&f, "admin.grant", "previous_role").as_deref(),
        Some("admin")
    );
    assert_eq!(
        f.grant_by(&u, AdminRole::Admin, "cli", GrantManagedBy::Api, None)
            .await,
        (Some(AdminRole::Viewer), true)
    );
    assert_eq!(
        last_event_attr(&f, "admin.grant", "previous_role").as_deref(),
        Some("viewer")
    );
}

#[tokio::test]
async fn a_grant_goes_only_to_an_existing_active_user_and_keeps_its_source_binding() {
    let f = fx();
    let u = f.user(1).await;
    let r = f
        .store
        .grant_admin(
            &UserId::new("u_nobody"),
            AdminRole::Admin,
            GrantManagedBy::Api,
            None,
            "cli",
            None,
            f.now(),
            f.ev(EventKind::AdminGrant),
        )
        .await;
    assert!(
        matches!(r, Err(StoreError::Conflict("unknown user"))),
        "{r:?}"
    );
    f.store
        .conn()
        .execute("UPDATE users SET status='disabled'", [])
        .unwrap();
    let r = f
        .store
        .grant_admin(
            &u.user_id,
            AdminRole::Admin,
            GrantManagedBy::Api,
            None,
            "cli",
            None,
            f.now(),
            f.ev(EventKind::AdminGrant),
        )
        .await;
    assert!(
        matches!(r, Err(StoreError::Conflict("user_disabled"))),
        "{r:?}"
    );
    assert_eq!(f.count("SELECT COUNT(*) FROM admin_grants"), 0);
    assert_eq!(f.count_kind("admin.grant"), 0);
    f.store
        .conn()
        .execute("UPDATE users SET status='active'", [])
        .unwrap();
    f.grant_by(
        &u,
        AdminRole::Admin,
        "cli",
        GrantManagedBy::Api,
        Some("user1@example.test"),
    )
    .await;
    // A later grant by id does not drop the address binding.
    f.grant_by(&u, AdminRole::Viewer, "cli", GrantManagedBy::Api, None)
        .await;
    assert_eq!(
        f.grant_row(&u).await.unwrap().source_email,
        Some(email("user1@example.test"))
    );
}

#[tokio::test]
async fn a_regrant_by_another_address_never_replaces_the_binding() {
    let f = fx();
    let u = f.user(1).await;
    f.grant_by(
        &u,
        AdminRole::Admin,
        "file",
        GrantManagedBy::File,
        Some("user1@example.test"),
    )
    .await;
    let events = f.count_kind("admin.grant");
    // Another address, a different role: refused, nothing written.
    let r = f
        .store
        .grant_admin(
            &u.user_id,
            AdminRole::Viewer,
            GrantManagedBy::Api,
            Some(email("moved@example.test")),
            "cli",
            None,
            f.now(),
            f.ev_user(EventKind::AdminGrant, &u.user_id),
        )
        .await;
    assert!(
        matches!(r, Err(StoreError::Conflict("source_email_bound"))),
        "{r:?}"
    );
    let g = f.grant_row(&u).await.unwrap();
    assert_eq!(g.source_email, Some(email("user1@example.test")));
    assert_eq!(
        (g.role, g.managed_by),
        (AdminRole::Admin, GrantManagedBy::File)
    );
    assert_eq!(f.count_kind("admin.grant"), events);
    // The same address again, and by id, are fine; the binding stays.
    f.grant_by(
        &u,
        AdminRole::Viewer,
        "cli",
        GrantManagedBy::Api,
        Some("user1@example.test"),
    )
    .await;
    f.grant_by(&u, AdminRole::Admin, "cli", GrantManagedBy::Api, None)
        .await;
    assert_eq!(
        f.grant_row(&u).await.unwrap().source_email,
        Some(email("user1@example.test"))
    );
    // A revoked row keeps its binding too.
    assert!(f.revoke(&u, "cli").await);
    let r = f
        .store
        .grant_admin(
            &u.user_id,
            AdminRole::Admin,
            GrantManagedBy::Api,
            Some(email("moved@example.test")),
            "cli",
            None,
            f.now(),
            f.ev_user(EventKind::AdminGrant, &u.user_id),
        )
        .await;
    assert!(
        matches!(r, Err(StoreError::Conflict("source_email_bound"))),
        "{r:?}"
    );
    assert_eq!(
        f.grant_row(&u).await.unwrap().source_email,
        Some(email("user1@example.test"))
    );
}

#[tokio::test]
async fn grant_targets_resolve_by_id_and_by_normalized_email_with_identities() {
    let f = fx();
    let u = f.user(1).await;
    let (by_id, ids) = f
        .store
        .resolve_grant_target(&GrantTarget::Id(u.user_id.clone()), long())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(by_id.user_id, u.user_id);
    assert_eq!(ids.len(), 1);
    assert_eq!(ids[0].subject, "sub-1");
    let (by_mail, _) = f
        .store
        .resolve_grant_target(&GrantTarget::Email(email("user1@Example.test")), long())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(by_mail.user_id, u.user_id);
    assert!(
        f.store
            .resolve_grant_target(&GrantTarget::Email(email("nobody@example.test")), long())
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        f.store
            .resolve_grant_target(&GrantTarget::Id(UserId::new("u_x")), long())
            .await
            .unwrap()
            .is_none()
    );
}

// ---- the file import -------------------------------------------------------

fn seed(index: usize, key: SeedKey, role: AdminRole) -> SeedEntry {
    SeedEntry {
        index,
        key,
        role,
        note: None,
    }
}

async fn import(
    f: &Fx,
    entries: Vec<SeedEntry>,
    force: Option<ForceTarget>,
) -> Result<GrantImportReport, StoreError> {
    f.store
        .import_grants(
            entries,
            force,
            long(),
            f.now(),
            &|user, kind, prev, role, forced| {
                let mut b = EventBuilder::new(&*f.clock, &f.rng, kind, Outcome::Success, "import")
                    .user(user)
                    .attr("actor", "file")
                    .attr("role", role.as_str())
                    .attr("managed_by", "file");
                if let Some(p) = prev {
                    b = b.attr("previous_role", p.as_str());
                }
                if forced {
                    b = b.attr("forced", true);
                }
                b.build()
            },
        )
        .await
}

fn ids(v: &[UserId]) -> Vec<&str> {
    v.iter().map(UserId::as_str).collect()
}

#[tokio::test]
async fn import_inserts_by_original_key_skips_the_unresolvable_and_is_idempotent() {
    let f = fx();
    let a = f.user(1).await; // user1@example.test, verified, not authoritative
    let n = f.user(2).await;
    let h = f.user(3).await;
    f.store
        .conn()
        .execute(
            "UPDATE users SET email_authoritative=1 WHERE user_id=?1",
            [h.user_id.as_str()],
        )
        .unwrap();
    let u = f.user(4).await;
    f.store
        .conn()
        .execute(
            "UPDATE users SET email_verified=0 WHERE user_id=?1",
            [u.user_id.as_str()],
        )
        .unwrap();
    f.user(5).await; // verified, not authoritative, and nobody names it by id
    let entries = || {
        vec![
            seed(0, SeedKey::ById(a.user_id.clone()), AdminRole::Admin),
            seed(
                1,
                SeedKey::ByEmail(email("user5@example.test")),
                AdminRole::Viewer,
            ), // verified, not authoritative
            seed(
                2,
                SeedKey::Both {
                    user_id: n.user_id.clone(),
                    email: email("user2@example.test"),
                },
                AdminRole::Viewer,
            ),
            seed(
                3,
                SeedKey::ByEmail(email("user3@example.test")),
                AdminRole::Admin,
            ), // authoritative
            seed(
                4,
                SeedKey::ByEmail(email("user4@example.test")),
                AdminRole::Admin,
            ), // unverified
            seed(
                5,
                SeedKey::ByEmail(email("nobody@example.test")),
                AdminRole::Admin,
            ),
            seed(6, SeedKey::ById(UserId::new("u_ghost")), AdminRole::Admin),
        ]
    };
    let r = import(&f, entries(), None).await.unwrap();
    assert_eq!(
        ids(&r.inserted),
        [a.user_id.as_str(), n.user_id.as_str(), h.user_id.as_str()]
    );
    assert_eq!(
        r.skipped,
        vec![
            (1, "email_not_authoritative"),
            (4, "email_unverified"),
            (5, "no_such_user"),
            (6, "no_such_user"),
        ]
    );
    let ga = f.grant_row(&a).await.unwrap();
    assert_eq!(
        (
            ga.managed_by,
            ga.source_email.clone(),
            ga.granted_by.as_str()
        ),
        (GrantManagedBy::File, None, "file")
    );
    assert_eq!(
        f.grant_row(&n).await.unwrap().source_email,
        Some(email("user2@example.test"))
    );
    assert_eq!(
        f.grant_row(&h).await.unwrap().source_email,
        Some(email("user3@example.test"))
    );
    assert_eq!(f.count_kind("admin.grant"), 3);
    assert_eq!(
        f.count("SELECT COUNT(*) FROM event_deliveries WHERE sink='log'"),
        3,
        "events travel with their rows"
    );
    // Again: unchanged, and no event is written.
    let r = import(&f, entries(), None).await.unwrap();
    assert_eq!(
        ids(&r.unchanged),
        [a.user_id.as_str(), n.user_id.as_str(), h.user_id.as_str()]
    );
    assert!(r.inserted.is_empty() && r.updated.is_empty() && r.revoked.is_empty());
    assert_eq!(f.count_kind("admin.grant"), 3);
    assert_eq!(f.count_kind("admin.revoke"), 0);
}

#[tokio::test]
async fn import_updates_file_rows_and_revokes_the_ones_the_file_dropped() {
    let f = fx();
    let a = f.user(1).await;
    let n = f.user(2).await;
    import(
        &f,
        vec![
            seed(0, SeedKey::ById(a.user_id.clone()), AdminRole::Admin),
            seed(
                1,
                SeedKey::Both {
                    user_id: n.user_id.clone(),
                    email: email("user2@example.test"),
                },
                AdminRole::Viewer,
            ),
        ],
        None,
    )
    .await
    .unwrap();
    // The file now says viewer for the first and no longer lists the second.
    let r = import(
        &f,
        vec![seed(0, SeedKey::ById(a.user_id.clone()), AdminRole::Viewer)],
        None,
    )
    .await
    .unwrap();
    assert_eq!(ids(&r.updated), [a.user_id.as_str()]);
    assert_eq!(ids(&r.revoked), [n.user_id.as_str()]);
    assert_eq!(f.grant_row(&a).await.unwrap().role, AdminRole::Viewer);
    assert_eq!(
        last_event_attr(&f, "admin.grant", "previous_role").as_deref(),
        Some("admin")
    );
    let g = f.grant_row(&n).await.unwrap();
    assert_eq!(g.revoked_by.as_deref(), Some("file"));
    assert!(g.revoked_at.is_some());
    assert_eq!(f.count_kind("admin.revoke"), 1);
    assert_eq!(
        last_event_attr(&f, "admin.revoke", "actor").as_deref(),
        Some("file")
    );
}

#[tokio::test]
async fn import_never_resurrects_a_runtime_revocation_or_overrides_a_runtime_change() {
    let f = fx();
    let a = f.user(1).await;
    let n = f.user(2).await;
    let entries = |role_a: AdminRole| {
        vec![
            seed(0, SeedKey::ById(a.user_id.clone()), role_a),
            seed(1, SeedKey::ById(n.user_id.clone()), AdminRole::Viewer),
        ]
    };
    import(&f, entries(AdminRole::Admin), None).await.unwrap();
    // (d) a runtime revocation of a file row, then an import with the file unchanged.
    assert!(f.revoke(&a, "cli").await);
    let grants_before = f.count_kind("admin.grant");
    let r = import(&f, entries(AdminRole::Admin), None).await.unwrap();
    assert_eq!(r.skipped, vec![(0, "revoked_at_run_time")]);
    assert!(
        f.grant_row(&a).await.unwrap().revoked_at.is_some(),
        "still revoked"
    );
    assert_eq!(f.count_kind("admin.grant"), grants_before, "no event");
    // (f) a runtime change flips the row to api; the file does not override it.
    f.grant_by(&n, AdminRole::Admin, "cli", GrantManagedBy::Api, None)
        .await;
    let r = import(&f, entries(AdminRole::Admin), None).await.unwrap();
    assert!(
        r.skipped.contains(&(1, "changed_at_run_time")),
        "{:?}",
        r.skipped
    );
    assert_eq!(f.grant_row(&n).await.unwrap().role, AdminRole::Admin);
    // An api row is not revoked as "removed from the file" either.
    let r = import(&f, vec![], None).await.unwrap();
    assert!(r.revoked.is_empty(), "{:?}", ids(&r.revoked));
    assert!(f.grant_row(&n).await.unwrap().revoked_at.is_none());
    // (e) --force reasserts the entry: live again, managed by the file, event with forced=true.
    let r = import(
        &f,
        entries(AdminRole::Viewer),
        Some(ForceTarget::ById(a.user_id.clone())),
    )
    .await
    .unwrap();
    assert_eq!(ids(&r.forced), [a.user_id.as_str()]);
    let g = f.grant_row(&a).await.unwrap();
    assert!(g.revoked_at.is_none());
    assert_eq!(
        (g.role, g.managed_by, g.granted_by.as_str()),
        (AdminRole::Viewer, GrantManagedBy::File, "file")
    );
    assert_eq!(
        last_event_attr(&f, "admin.grant", "forced").as_deref(),
        Some("1")
    );
    // Forcing something the file does not list is refused.
    let r = import(&f, vec![], Some(ForceTarget::ById(a.user_id.clone()))).await;
    assert!(matches!(r, Err(StoreError::Conflict(_))), "{r:?}");
}

#[tokio::test]
async fn a_present_but_mismatched_entry_leaves_its_row_untouched_and_is_not_treated_as_removed() {
    let f = fx();
    let n = f.user(2).await;
    let good = vec![seed(
        0,
        SeedKey::Both {
            user_id: n.user_id.clone(),
            email: email("user2@example.test"),
        },
        AdminRole::Viewer,
    )];
    import(&f, good.clone(), None).await.unwrap();
    // (g) the entry now names an address that is not u_n's.
    let bad = vec![seed(
        0,
        SeedKey::Both {
            user_id: n.user_id.clone(),
            email: email("x@example.test"),
        },
        AdminRole::Admin,
    )];
    let r = import(&f, bad, None).await.unwrap();
    assert_eq!(r.skipped, vec![(0, "user_email_mismatch")]);
    assert!(r.revoked.is_empty() && r.updated.is_empty());
    let g = f.grant_row(&n).await.unwrap();
    assert_eq!((g.role, g.revoked_at), (AdminRole::Viewer, None));
    // (h) corrected back, with a new role: the row updates normally.
    let fixed = vec![seed(
        0,
        SeedKey::Both {
            user_id: n.user_id.clone(),
            email: email("user2@example.test"),
        },
        AdminRole::Admin,
    )];
    let r = import(&f, fixed, None).await.unwrap();
    assert_eq!(ids(&r.updated), [n.user_id.as_str()]);
    assert_eq!(f.grant_row(&n).await.unwrap().role, AdminRole::Admin);
    // A mismatched entry with no row yet is skipped, not applied.
    let m = f.user(5).await;
    let r = import(
        &f,
        vec![seed(
            0,
            SeedKey::Both {
                user_id: m.user_id.clone(),
                email: email("elsewhere@example.test"),
            },
            AdminRole::Admin,
        )],
        None,
    )
    .await
    .unwrap();
    assert_eq!(r.skipped, vec![(0, "user_email_mismatch")]);
    assert!(f.grant_row(&m).await.is_none());
}

#[tokio::test]
async fn an_email_entry_stays_bound_to_its_row_when_the_address_moves() {
    let f = fx();
    let h = f.user(3).await;
    f.store
        .conn()
        .execute(
            "UPDATE users SET email_authoritative=1 WHERE user_id=?1",
            [h.user_id.as_str()],
        )
        .unwrap();
    let entry = || {
        vec![seed(
            0,
            SeedKey::ByEmail(email("user3@example.test")),
            AdminRole::Admin,
        )]
    };
    import(&f, entry(), None).await.unwrap();
    // The provider's address for u_h changes; u_h2 later obtains the old one, verified and authoritative.
    let h2 = f.user(9).await;
    f.store.conn().execute_batch(&format!(
        "UPDATE users SET primary_email='moved@example.test' WHERE user_id='{}';
         UPDATE users SET primary_email='user3@example.test', email_authoritative=1 WHERE user_id='{}';",
        h.user_id, h2.user_id
    )).unwrap();
    let r = import(
        &f,
        vec![seed(
            0,
            SeedKey::ByEmail(email("user3@example.test")),
            AdminRole::Viewer,
        )],
        None,
    )
    .await
    .unwrap();
    assert_eq!(
        ids(&r.updated),
        [h.user_id.as_str()],
        "matched by source_email first"
    );
    assert_eq!(
        r.rebound_warnings,
        vec![(0, h.user_id.clone(), h2.user_id.clone())]
    );
    assert!(
        f.grant_row(&h2).await.is_none(),
        "the new holder receives nothing"
    );
    // --force by the address selects the existing binding, not a fresh resolution.
    let r = import(
        &f,
        vec![seed(
            0,
            SeedKey::ByEmail(email("user3@example.test")),
            AdminRole::Admin,
        )],
        Some(ForceTarget::ByEmail(email("user3@example.test"))),
    )
    .await
    .unwrap();
    assert_eq!(ids(&r.forced), [h.user_id.as_str()]);
    assert!(f.grant_row(&h2).await.is_none());
    // (d) the pass-3 state: revoked at run time, the row is an api tombstone still bound to the address.
    assert!(f.revoke(&h, "cli").await);
    let r = import(&f, entry(), None).await.unwrap();
    assert_eq!(r.skipped, vec![(0, "revoked_at_run_time")]);
    assert!(
        f.grant_row(&h2).await.is_none(),
        "no grant for the new holder"
    );
    assert!(f.grant_row(&h).await.unwrap().revoked_at.is_some());
    let r = import(
        &f,
        entry(),
        Some(ForceTarget::ByEmail(email("user3@example.test"))),
    )
    .await
    .unwrap();
    assert_eq!(ids(&r.forced), [h.user_id.as_str()]);
    assert!(f.grant_row(&h).await.unwrap().revoked_at.is_none());
    assert!(f.grant_row(&h2).await.is_none());
    assert!(f.revoke(&h, "cli").await);
    let r = import(&f, entry(), Some(ForceTarget::ById(h.user_id.clone())))
        .await
        .unwrap();
    assert_eq!(
        ids(&r.forced),
        [h.user_id.as_str()],
        "--force <user_id> does the same"
    );
    // (e) two rows bound through the same address: ambiguous, nothing changes, force by address refused.
    f.grant_by(
        &h2,
        AdminRole::Admin,
        "cli",
        GrantManagedBy::Api,
        Some("user3@example.test"),
    )
    .await;
    let snapshot = f.count("SELECT COUNT(*) FROM events");
    let r = import(&f, entry(), None).await.unwrap();
    assert_eq!(r.skipped, vec![(0, "email_binding_ambiguous")]);
    assert!(r.updated.is_empty() && r.revoked.is_empty() && r.inserted.is_empty());
    assert_eq!(f.count("SELECT COUNT(*) FROM events"), snapshot);
    let r = import(
        &f,
        entry(),
        Some(ForceTarget::ByEmail(email("user3@example.test"))),
    )
    .await;
    match r {
        Err(StoreError::Conflict(m)) => assert!(m.contains("--force <user_id>"), "{m}"),
        other => panic!("{other:?}"),
    }
    assert_eq!(f.count("SELECT COUNT(*) FROM events"), snapshot);
    // The ambiguous rows are present, not removed: a different import of an unrelated entry keeps them.
    let r = import(
        &f,
        vec![seed(
            0,
            SeedKey::ByEmail(email("user3@example.test")),
            AdminRole::Admin,
        )],
        None,
    )
    .await
    .unwrap();
    assert!(r.revoked.is_empty());
}

#[tokio::test]
async fn import_is_one_transaction_and_never_commits_past_its_deadline() {
    let f = fx();
    let users: Vec<User> = {
        let mut v = Vec::new();
        for i in 1..=6 {
            v.push(f.user(i).await);
        }
        v
    };
    let entries: Vec<SeedEntry> = users
        .iter()
        .enumerate()
        .map(|(i, u)| seed(i, SeedKey::ById(u.user_id.clone()), AdminRole::Admin))
        .collect();
    f.hooks.set_slow_scan(60);
    let started = Instant::now();
    let out = f
        .store
        .import_grants(
            entries,
            None,
            dl(150),
            f.now(),
            &|user, kind, _, role, _| {
                EventBuilder::new(&*f.clock, &f.rng, kind, Outcome::Success, "import")
                    .user(user)
                    .attr("role", role.as_str())
                    .build()
            },
        )
        .await;
    f.hooks.set_slow_scan(0);
    assert!(
        matches!(out, Err(StoreError::Unavailable(ref m)) if m == "deadline" || m == "interrupted"),
        "{out:?}"
    );
    assert!(started.elapsed() < Duration::from_millis(2000));
    assert_eq!(
        f.count("SELECT COUNT(*) FROM admin_grants"),
        0,
        "nothing committed"
    );
    assert_eq!(f.count_kind("admin.grant"), 0);
}

// ---- bounded windows -------------------------------------------------------

use super::super::window::Shape;
use rusqlite::types::Value;

fn bulk_users(c: &Connection, n: i64) {
    c.execute_batch(&format!(
        "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i < {n})
         INSERT INTO users (user_id, primary_email, email_verified, display_name, status, created_at, updated_at)
         SELECT printf('u_b%09d', i), printf('b%d@bulk.test', i), 1, printf('Bulk %d', i), 'active', 1000000 + i, 1000000 + i FROM n;"
    ))
    .unwrap();
}

fn bulk_sessions(c: &Connection, n: i64) {
    c.execute_batch(&format!(
        "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i < {n})
         INSERT INTO sessions (session_id, user_id, provider_id, auth_time, aal, authz_version, cred_gen, bound_ip, created_at, last_seen_at, absolute_expires_at, authz_version_at_auth)
         SELECT printf('s_b%09d', i), printf('u_b%09d', 1 + (i % 50)), 'mock', 1000000, 1, 1, 1, '192.0.2.1', 1000000 + i, 1000000 + i, 4000000000, 1 FROM n;"
    ))
    .unwrap();
}

/// `n` events of one user; the newest `newest_failed` carry kind `login.failed`, the rest `login.started`.
fn bulk_events(c: &Connection, n: i64, newest_failed: i64) {
    c.execute_batch(&format!(
        "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i < {n})
         INSERT INTO events (event_id, at, kind, outcome, user_id, session_id, client_ip, request_id, attrs)
         SELECT printf('e_%09d', i), 1700000000.0 + i, CASE WHEN i > {n} - {newest_failed} THEN 'login.failed' ELSE 'login.started' END,
                CASE WHEN i % 2 = 0 THEN 'success' ELSE 'failure' END, 'u_w', printf('s_%d', i % 7), printf('192.0.2.%d', i % 200), 'r', '{{}}' FROM n;"
    ))
    .unwrap();
}

fn user_events_query(limit: usize, kind: Option<EventKind>, cursor: Option<Cursor>) -> EventsQuery {
    EventsQuery {
        kind,
        user_id: Some(UserId::new("u_w")),
        limit,
        cursor,
        ..Default::default()
    }
}

fn plan(c: &Connection, select: &str) -> String {
    let mut st = c.prepare(&format!("EXPLAIN QUERY PLAN {select}")).unwrap();
    for i in 1..=st.parameter_count() {
        st.raw_bind_parameter(i, 0).unwrap();
    }
    let mut q = st.raw_query();
    let mut rows = Vec::new();
    while let Some(r) = q.next().unwrap() {
        rows.push(r.get::<_, String>(3).unwrap());
    }
    rows.join(" | ")
}

fn all_shapes() -> Vec<(Shape, &'static str)> {
    vec![
        (Shape::Events(EventsIndex::Session), "events_session_at_id"),
        (Shape::Events(EventsIndex::User), "events_user_at_id"),
        (Shape::Events(EventsIndex::Ip), "events_ip_at_id"),
        (Shape::Events(EventsIndex::Kind), "events_kind_at_id"),
        (Shape::Events(EventsIndex::Time), "events_at_id"),
        (Shape::Sessions { by_user: false }, "sessions_live_created"),
        (
            Shape::Sessions { by_user: true },
            "sessions_live_user_created",
        ),
        (Shape::Users, "users_created_id"),
    ]
}

#[test]
fn every_window_statement_names_its_index_and_cursor_pages_seek_on_the_two_trailing_columns() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(
        &dir.path().join("h.db"),
        Arc::new(crate::crypto::TestClock::new(Timestamp(0))),
        vec![],
        None,
    )
    .unwrap();
    let c = store.conn();
    for (shape, index) in all_shapes() {
        for cursor in [false, true] {
            let sql = window::window_sql(shape, cursor);
            assert!(
                sql.contains(&format!("INDEXED BY {index}")),
                "{shape:?}: {sql}"
            );
            let select = sql.strip_prefix("CREATE TEMP TABLE w AS ").unwrap();
            let p = plan(&c, select);
            assert!(
                p.contains(&format!("USING INDEX {index}")),
                "{shape:?} cursor={cursor}: {p}"
            );
            assert!(p.starts_with("SEARCH"), "a search, never a scan: {p}");
            if cursor {
                let seek = match shape {
                    Shape::Events(_) => "(at,event_id)<(?,?)",
                    Shape::Sessions { .. } => "(created_at,session_id)<(?,?)",
                    Shape::Users => "(created_at,user_id)<(?,?)",
                };
                assert!(
                    p.contains(seek),
                    "{shape:?}: the cursor page seeks on both trailing columns: {p}"
                );
            }
        }
    }
}

fn bind_all(st: &mut rusqlite::Statement<'_>, cursor_key: i64, real: bool) {
    let binds: Vec<(&str, Value)> = vec![
        ("user", Value::Text("u_w".into())),
        ("session", Value::Text("s_3".into())),
        ("ip", Value::Text("192.0.2.5".into())),
        ("kind", Value::Text("login.failed".into())),
        ("since_w", Value::Real(f64::MIN)),
        ("until_w", Value::Real(f64::MAX)),
        ("max_w", Value::Integer(i64::MAX)),
        (
            "c_at",
            if real {
                Value::Real(cursor_key as f64)
            } else {
                Value::Integer(cursor_key)
            },
        ),
        ("c_id", Value::Text("e_000000005".into())),
    ];
    for (n, v) in binds {
        if let Some(i) = st.parameter_index(&format!(":{n}")).unwrap() {
            st.raw_bind_parameter(i, v).unwrap();
        }
    }
}

/// `(vm steps, full-scan steps, sort steps)` of one window statement.
fn window_work(c: &Connection, shape: Shape, cursor: bool, cursor_key: i64) -> (i32, i32, i32) {
    c.execute_batch("DROP TABLE IF EXISTS temp.w").unwrap();
    let mut st = c.prepare(&window::window_sql(shape, cursor)).unwrap();
    bind_all(&mut st, cursor_key, matches!(shape, Shape::Events(_)));
    st.raw_execute().unwrap();
    (
        st.get_status(StatementStatus::VmStep),
        st.get_status(StatementStatus::FullscanStep),
        st.get_status(StatementStatus::Sort),
    )
}

#[test]
fn window_statements_never_scan_or_sort_on_a_hundred_thousand_rows() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(
        &dir.path().join("h.db"),
        Arc::new(crate::crypto::TestClock::new(Timestamp(0))),
        vec![],
        None,
    )
    .unwrap();
    let c = store.conn();
    bulk_users(&c, 100_000);
    bulk_sessions(&c, 100_000);
    bulk_events(&c, 100_000, 10);
    for (shape, _) in all_shapes() {
        for cursor in [false, true] {
            // A cursor in the middle of each table (events: seconds; others: seconds).
            let key = if matches!(shape, Shape::Events(_)) {
                1_700_050_000
            } else {
                1_050_000
            };
            let (vm, full, sort) = window_work(&c, shape, cursor, key);
            assert_eq!(full, 0, "{shape:?} cursor={cursor}: FULLSCAN_STEP");
            assert_eq!(sort, 0, "{shape:?} cursor={cursor}: SORT");
            // About 25 VM steps per candidate row: bounded by the window, not the table.
            assert!(
                vm < 30 * CANDIDATE_WINDOW as i32,
                "{shape:?} cursor={cursor}: {vm} VM steps"
            );
        }
    }
}

#[test]
fn deep_cursor_work_does_not_grow_with_the_table() {
    let measure = |rows: i64| -> (i32, i32) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(
            &dir.path().join("h.db"),
            Arc::new(crate::crypto::TestClock::new(Timestamp(0))),
            vec![],
            None,
        )
        .unwrap();
        let c = store.conn();
        bulk_events(&c, rows, 10);
        let shape = Shape::Events(EventsIndex::User);
        // Next to the oldest row, and in the middle of the table.
        let deep = window_work(&c, shape, true, 1_700_000_005).0;
        let mid = window_work(&c, shape, true, 1_700_000_000 + rows / 2).0;
        (deep, mid)
    };
    let (deep_100, mid_100) = measure(100_000);
    let (deep_200, mid_200) = measure(200_000);
    let within = |a: i32, b: i32| (f64::from(a) - f64::from(b)).abs() <= 0.10 * f64::from(a.max(b));
    assert!(
        within(mid_100, mid_200),
        "mid-table cursor: {mid_100} vs {mid_200} VM steps"
    );
    assert!(
        within(deep_100, deep_200) || (deep_100 - deep_200).abs() < 50,
        "deep cursor: {deep_100} vs {deep_200} VM steps"
    );
    for v in [deep_100, deep_200] {
        assert!(
            v < 20 * CANDIDATE_WINDOW as i32,
            "{v} VM steps stays below 20 x window"
        );
    }
    for v in [mid_100, mid_200] {
        assert!(
            v < 30 * CANDIDATE_WINDOW as i32,
            "{v} VM steps: a full window costs about 25 steps per row"
        );
    }
    assert!(
        deep_200 < mid_200,
        "a cursor next to the oldest row reads little"
    );
}

#[tokio::test]
async fn a_window_of_non_matches_returns_an_empty_page_with_a_cursor_and_the_next_page_finds_the_matches()
 {
    let f = fx();
    bulk_events(&f.store.conn(), 100_000, CANDIDATE_WINDOW as i64);
    // The newest 10,000 candidates all fail the kind filter; 90,000 older ones match.
    let q1 = user_events_query(50, Some(EventKind::LoginStarted), None);
    let p1 = f.store.query_page(q1, long()).await.unwrap();
    assert!(p1.items.is_empty());
    assert_eq!(p1.examined, CANDIDATE_WINDOW);
    let cur = p1
        .next
        .clone()
        .expect("a full window of non-matches still continues");
    let p2 = f
        .store
        .query_page(
            user_events_query(50, Some(EventKind::LoginStarted), Some(cur.clone())),
            long(),
        )
        .await
        .unwrap();
    assert_eq!(p2.items.len(), 50, "the next page finds the matches");
    assert!(p2.items.iter().all(|e| e.kind == EventKind::LoginStarted));
    assert!(
        p2.items
            .windows(2)
            .all(|w| (w[0].at, &w[0].event_id) > (w[1].at, &w[1].event_id)),
        "newest first"
    );
    assert!(p2.items[0].at.0 < cur.key, "strictly after the cursor");
    // The cursor is a position: page 3 continues exactly after page 2's last row.
    let c2 = p2.next.clone().unwrap();
    let last = p2.items.last().unwrap();
    assert_eq!(
        (c2.key, c2.id.as_str()),
        (last.at.0, last.event_id.as_str())
    );
    let p3 = f
        .store
        .query_page(
            user_events_query(50, Some(EventKind::LoginStarted), Some(c2)),
            long(),
        )
        .await
        .unwrap();
    assert!(p3.items[0].at.0 <= last.at.0 && p3.items[0].event_id != last.event_id);
    // A kind nobody has: the walk terminates within rows / window + 1 pages and returns nothing.
    let mut pages = 0;
    let mut cursor = None;
    loop {
        let p = f
            .store
            .query_page(
                user_events_query(50, Some(EventKind::AdminDenied), cursor.take()),
                long(),
            )
            .await
            .unwrap();
        assert!(p.items.is_empty());
        pages += 1;
        match p.next {
            Some(c) => cursor = Some(c),
            None => break,
        }
        assert!(pages <= 100_000 / CANDIDATE_WINDOW as usize + 1);
    }
    assert_eq!(
        pages, 11,
        "ten full windows, then the empty one that ends the walk"
    );
}

#[tokio::test]
async fn listing_pages_use_the_three_cursor_branches_and_break_ties_by_id() {
    let f = fx();
    for n in 1..=30 {
        f.user(n).await; // all created in the same second
    }
    // matches > limit: the cursor is the last returned row.
    let mut seen = Vec::new();
    let mut cursor = None;
    let mut pages = 0;
    loop {
        let p = f
            .store
            .list_users(
                UsersQuery {
                    q: None,
                    status: None,
                    limit: 7,
                    cursor: cursor.take(),
                },
                long(),
            )
            .await
            .unwrap();
        assert!(p.items.len() <= 7);
        assert_eq!(
            p.examined as usize,
            30 - seen.len(),
            "the window holds only rows older than the cursor"
        );
        seen.extend(
            p.items
                .iter()
                .map(|s| (s.user.created_at, s.user.user_id.to_string())),
        );
        pages += 1;
        match p.next {
            Some(c) => cursor = Some(c),
            None => break, // everything fits and the window is not full: no cursor
        }
    }
    assert_eq!(seen.len(), 30);
    assert_eq!(pages, 5);
    assert!(
        seen.windows(2).all(|w| w[0] > w[1]),
        "strictly descending (created_at, user_id): ties never repeat or skip"
    );
    let distinct: std::collections::HashSet<_> = seen.iter().map(|s| &s.1).collect();
    assert_eq!(distinct.len(), 30);
    // A page that holds everything and a window that is not full has no cursor.
    let all = f
        .store
        .list_users(
            UsersQuery {
                q: None,
                status: None,
                limit: 100,
                cursor: None,
            },
            long(),
        )
        .await
        .unwrap();
    assert_eq!((all.items.len(), all.next.is_none()), (30, true));
}

#[tokio::test]
async fn user_search_filters_inside_the_window_and_reports_sessions_and_role() {
    let f = fx();
    let a = f.user(1).await;
    let b = f.user(2).await;
    f.session(&a, vec![]).await;
    f.session(&a, vec![]).await;
    f.grant(&a, AdminRole::Viewer).await;
    f.store
        .conn()
        .execute(
            "UPDATE users SET status='disabled' WHERE user_id=?1",
            [b.user_id.as_str()],
        )
        .unwrap();
    let q = |q: Option<&str>, status| UsersQuery {
        q: q.map(str::to_string),
        status,
        limit: 50,
        cursor: None,
    };
    let by_email = f
        .store
        .list_users(q(Some("user1@"), None), long())
        .await
        .unwrap();
    assert_eq!(by_email.items.len(), 1);
    assert_eq!(by_email.items[0].live_sessions, 2);
    assert_eq!(by_email.items[0].role, Some(AdminRole::Viewer));
    let by_name = f
        .store
        .list_users(q(Some("er 2"), None), long())
        .await
        .unwrap(); // substring of display_name, case-insensitive
    assert_eq!(by_name.items.len(), 1);
    assert_eq!(by_name.items[0].user.user_id, b.user_id);
    let by_username = f
        .store
        .list_users(q(Some("USER1"), None), long())
        .await
        .unwrap();
    assert_eq!(
        by_username.items.len(),
        1,
        "prefix match on the username, ASCII case-insensitive like the address"
    );
    let none = f
        .store
        .list_users(q(Some("nobody"), None), long())
        .await
        .unwrap();
    assert!(none.items.is_empty() && none.next.is_none());
    let disabled = f
        .store
        .list_users(q(None, Some(UserStatus::Disabled)), long())
        .await
        .unwrap();
    assert_eq!(disabled.items.len(), 1);
    assert_eq!(disabled.items[0].role, None);
    // Escaped wildcards are literal.
    let literal = f
        .store
        .list_users(q(Some("user\\_"), None), long())
        .await
        .unwrap();
    assert!(literal.items.is_empty());
}

#[tokio::test]
async fn live_session_listing_skips_terminated_and_expired_and_reports_hosts() {
    let f = fx();
    let a = f.user(1).await;
    let b = f.user(2).await;
    let s1 = f.session(&a, vec![]).await;
    f.clock.advance(Duration::from_secs(10));
    let s2 = f.session(&a, vec![]).await;
    let s3 = f.session(&b, vec![]).await;
    f.store
        .mint_handle(
            f.handle_row(&s1.row.session_id, APP_HOST, &handle_value(&f.rng)),
            None,
            vec![],
        )
        .await
        .unwrap();
    f.store
        .terminate_session(&s3.row.session_id, reasons::LOGOUT, f.now(), vec![])
        .await
        .unwrap();
    f.store
        .conn()
        .execute(
            "UPDATE sessions SET absolute_expires_at=?2 WHERE session_id=?1",
            rusqlite::params![s2.row.session_id.as_str(), f.now().secs() - 1],
        )
        .unwrap();
    let q = SessionsQuery {
        user_id: None,
        limit: 50,
        cursor: None,
        now: f.now(),
    };
    let page = f.store.list_live_sessions(q.clone(), long()).await.unwrap();
    assert_eq!(
        page.items.len(),
        1,
        "terminated and expired sessions are not live"
    );
    let item = &page.items[0];
    assert_eq!(item.session.session_id, s1.row.session_id);
    assert_eq!(item.primary_email, a.primary_email);
    let hosts: Vec<&str> = item.hosts.iter().map(|h| h.as_str()).collect();
    assert_eq!(hosts, [APP_HOST, PORTAL_HOST]);
    let mine = f
        .store
        .list_live_sessions(
            SessionsQuery {
                user_id: Some(b.user_id.clone()),
                ..q.clone()
            },
            long(),
        )
        .await
        .unwrap();
    assert!(mine.items.is_empty());
    // The detail view: any state, with its handles.
    let (sum, handles) = f
        .store
        .session_summary(&s3.row.session_id, long())
        .await
        .unwrap()
        .unwrap();
    assert!(sum.session.terminated_at.is_some());
    assert_eq!(handles.len(), 1);
    assert!(handles[0].revoked_at.is_some());
    assert!(
        f.store
            .session_summary(&SessionId::new("s_none"), long())
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn user_detail_caps_its_lists_and_counts_the_live_sessions() {
    let f = fx();
    let a = f.user(1).await;
    for _ in 0..25 {
        f.clock.advance(Duration::from_secs(1));
        f.session(&a, vec![]).await;
    }
    for _ in 0..22 {
        f.clock.advance(Duration::from_secs(1));
        let s = f.session(&a, vec![]).await;
        f.store
            .terminate_session(&s.row.session_id, reasons::LOGOUT, f.now(), vec![])
            .await
            .unwrap();
    }
    f.grant(&a, AdminRole::Admin).await;
    let d = f
        .store
        .user_detail(&a.user_id, f.now(), long())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(d.sessions_live.len(), 20);
    assert_eq!(d.sessions_live_total, 25);
    assert_eq!(d.sessions_terminated.len(), 20);
    assert!(
        d.sessions_live
            .windows(2)
            .all(|w| w[0].session.created_at >= w[1].session.created_at),
        "newest created first"
    );
    assert!(
        d.sessions_terminated
            .windows(2)
            .all(|w| w[0].session.terminated_at >= w[1].session.terminated_at)
    );
    assert_eq!(d.identities.len(), 1);
    assert_eq!(d.grant.as_ref().map(|g| g.role), Some(AdminRole::Admin));
    assert!(
        f.store
            .user_detail(&UserId::new("u_none"), f.now(), long())
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn event_listing_filters_pins_one_index_and_pages_newest_first() {
    let f = fx();
    let u = UserId::new("u_x");
    let s = SessionId::new("s_x");
    let mut evs = Vec::new();
    for i in 0..8 {
        f.clock.advance(Duration::from_secs(1));
        let kind = if i % 2 == 0 {
            EventKind::LoginFailed
        } else {
            EventKind::LoginSucceeded
        };
        let outcome = if i % 2 == 0 {
            Outcome::Failure
        } else {
            Outcome::Success
        };
        let mut b = EventBuilder::new(&*f.clock, &f.rng, kind, outcome, "r")
            .ip(ip(&format!("192.0.2.{}", 1 + i % 2)));
        if i < 6 {
            b = b.user(&u);
        }
        if i >= 2 {
            b = b.session(&s);
        }
        evs.push(b.build());
    }
    f.store.append_required(evs).await.unwrap();
    let q = |mut q: EventsQuery| {
        q.limit = 50;
        q
    };
    let all = f
        .store
        .query_page(q(EventsQuery::default()), long())
        .await
        .unwrap();
    assert_eq!(all.items.len(), 8);
    assert!(
        all.items
            .windows(2)
            .all(|w| (w[0].at, &w[0].event_id) > (w[1].at, &w[1].event_id))
    );
    assert_eq!(EventsQuery::default().index(), EventsIndex::Time);
    let by_user = f
        .store
        .query_page(
            q(EventsQuery {
                user_id: Some(u.clone()),
                ..Default::default()
            }),
            long(),
        )
        .await
        .unwrap();
    assert_eq!(by_user.items.len(), 6);
    let by_kind = f
        .store
        .query_page(
            q(EventsQuery {
                kind: Some(EventKind::LoginFailed),
                ..Default::default()
            }),
            long(),
        )
        .await
        .unwrap();
    assert_eq!(by_kind.items.len(), 4);
    let by_outcome = f
        .store
        .query_page(
            q(EventsQuery {
                outcome: Some(Outcome::Success),
                ..Default::default()
            }),
            long(),
        )
        .await
        .unwrap();
    assert_eq!(by_outcome.items.len(), 4);
    let by_ip = f
        .store
        .query_page(
            q(EventsQuery {
                client_ip: Some(ip("192.0.2.2")),
                ..Default::default()
            }),
            long(),
        )
        .await
        .unwrap();
    assert_eq!(by_ip.items.len(), 4);
    // The index follows the fixed priority; filters that are not the index still apply.
    let both = EventsQuery {
        session_id: Some(s.clone()),
        user_id: Some(u.clone()),
        kind: Some(EventKind::LoginFailed),
        ..Default::default()
    };
    assert_eq!(both.index(), EventsIndex::Session);
    let page = f.store.query_page(q(both), long()).await.unwrap();
    assert_eq!(page.items.len(), 2); // i = 2, 4 (i = 6 has no user, i = 0 no session)
    // Time range on the time index: events 2..=4 by their clock.
    let first = all.items.last().unwrap().at;
    let range = EventsQuery {
        since: Some(first.add(Duration::from_secs(2))),
        until: Some(first.add(Duration::from_secs(4))),
        ..Default::default()
    };
    assert_eq!(range.index(), EventsIndex::Time);
    let page = f.store.query_page(q(range), long()).await.unwrap();
    assert_eq!(page.items.len(), 3);
    // Paging: three at a time, no repeats, a cursor on every page but the last.
    let mut seen = Vec::new();
    let mut cursor = None;
    loop {
        let p = f
            .store
            .query_page(
                EventsQuery {
                    limit: 3,
                    cursor: cursor.take(),
                    ..Default::default()
                },
                long(),
            )
            .await
            .unwrap();
        seen.extend(p.items.iter().map(|e| e.event_id.to_string()));
        match p.next {
            Some(c) => cursor = Some(c),
            None => break,
        }
    }
    let mut expect: Vec<String> = all.items.iter().map(|e| e.event_id.to_string()).collect();
    assert_eq!(seen, expect);
    expect.dedup();
    assert_eq!(expect.len(), 8);
}

#[tokio::test]
async fn store_status_counts_rows_deliveries_and_the_last_prune() {
    let f = fx();
    let a = f.user(1).await;
    f.user(2).await;
    f.session(&a, vec![f.ev(EventKind::SessionCreated)]).await;
    let dead = f.session(&a, vec![]).await;
    f.store
        .terminate_session(&dead.row.session_id, reasons::LOGOUT, f.now(), vec![])
        .await
        .unwrap();
    f.store.conn().execute_batch("INSERT INTO event_deliveries SELECT 'webhook', event_id, 'failed', 3, 0, 'x', 0 FROM events").unwrap();
    let st = f.store.status(long()).await.unwrap();
    assert_eq!(
        st.schema_version,
        crate::store::sqlite::LATEST_SCHEMA_VERSION
    );
    assert_eq!(st.users, 2);
    assert_eq!(st.live_sessions, 1);
    assert_eq!(st.events, 1);
    assert_eq!(
        st.deliveries,
        vec![("log".to_string(), 1, 0), ("webhook".to_string(), 0, 1)]
    );
    assert_eq!(st.last_prune_at, None);
    f.store
        .prune(
            f.now(),
            &EventRetention {
                retention: Duration::from_secs(86400),
                max_rows: 100,
                prune_every: 10,
                max_pending_per_sink: 100,
                terminal_retention: Duration::from_secs(86400),
            },
        )
        .await
        .unwrap();
    assert_eq!(
        f.store.status(long()).await.unwrap().last_prune_at,
        Some(f.now())
    );
}

// ---- deadlines and interruption ------------------------------------------------

#[test]
fn earliest_present_keeps_either_sole_source_and_the_earlier_of_two() {
    let a = Instant::now();
    let b = a + Duration::from_secs(5);
    assert_eq!(earliest_present(None, None), None);
    assert_eq!(
        earliest_present(Some(a), None),
        Some(a),
        "Option::min would drop this one"
    );
    assert_eq!(earliest_present(None, Some(b)), Some(b));
    assert_eq!(earliest_present(Some(a), Some(b)), Some(a));
    assert_eq!(earliest_present(Some(b), Some(a)), Some(a));
}

#[tokio::test]
async fn the_deadline_reaches_the_job_as_a_value_not_through_the_task_local() {
    let f = fx();
    let u = f.user(1).await;
    // A task-local set in the async caller.
    let local = tokio::time::Instant::now() + Duration::from_secs(30);
    let seen = super::super::with_deadline(local, async {
        f.store
            .read_checked("probe", None, |_, check| {
                Ok((
                    super::super::STORE_DEADLINE.try_with(|d| *d).is_ok(),
                    check.remaining(),
                ))
            })
            .await
    })
    .await
    .unwrap();
    assert!(!seen.0, "the job cannot see the task-local");
    let left = seen.1.expect("but it was handed the captured value");
    assert!(
        left > Duration::from_secs(25) && left <= Duration::from_secs(30),
        "{left:?}"
    );
    assert_eq!(f.hooks.last_deadline().map(|d| d.is_some()), Some(true));
    // An explicit deadline later than the task-local one does not win; the earliest does.
    let early = tokio::time::Instant::now() + Duration::from_secs(10);
    let seen = super::super::with_deadline(early, async {
        f.store
            .read_checked(
                "probe",
                Some(Deadline::after(Duration::from_secs(60))),
                |_, check| Ok(check.remaining()),
            )
            .await
    })
    .await
    .unwrap();
    assert!(seen.unwrap() <= Duration::from_secs(10));
    // The explicit deadline alone is kept (not dropped by an Option::min).
    let seen = f
        .store
        .read_checked(
            "probe",
            Some(Deadline::after(Duration::from_secs(20))),
            |_, c| Ok(c.remaining()),
        )
        .await
        .unwrap();
    assert!(seen.is_some());
    // No deadline anywhere: the job runs unbounded.
    f.store.user(&u.user_id).await.unwrap();
    assert_eq!(f.hooks.last_deadline(), Some(None));
    // Writer jobs get it the same way.
    let seen = f
        .store
        .write_checked(
            "probe",
            Some(Deadline::after(Duration::from_secs(20))),
            |_, c| Ok(c.remaining()),
        )
        .await
        .unwrap();
    assert!(seen.is_some());
}

#[tokio::test]
async fn a_job_that_starts_after_its_deadline_is_refused_without_a_statement() {
    let f = fx();
    let ran = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = ran.clone();
    let past = Deadline(Instant::now() - Duration::from_millis(1));
    let out = f
        .store
        .read_checked("probe", Some(past), move |_, _| {
            flag.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        })
        .await;
    assert!(
        matches!(out, Err(StoreError::Unavailable(ref m)) if m == "deadline"),
        "{out:?}"
    );
    assert!(!ran.load(std::sync::atomic::Ordering::SeqCst));
    let flag = ran.clone();
    let out = f
        .store
        .write_checked("probe", Some(past), move |_, _| {
            flag.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        })
        .await;
    assert!(
        matches!(out, Err(StoreError::Unavailable(ref m)) if m == "deadline"),
        "{out:?}"
    );
    assert!(!ran.load(std::sync::atomic::Ordering::SeqCst));
    let u = f.user(1).await;
    // The refusal leaves the writer healthy.
    f.store.directory().user(&u.user_id).await.unwrap().unwrap();
}

#[tokio::test]
async fn a_held_write_lock_cannot_block_a_job_past_its_deadline_and_nothing_commits_late() {
    let c = console().await;
    c.f.store.hold_write_lock(600).unwrap();
    let f = &c.f;
    let started = Instant::now();
    let out = f
        .store
        .set_user_status(
            &c.actor,
            &c.policy,
            &c.target.user_id,
            UserStatus::Disabled,
            dl(100),
            f.ev_user(EventKind::AdminUserDisable, &c.target.user_id),
            &|row| f.session_event(row),
        )
        .await;
    let took = started.elapsed();
    assert!(
        matches!(out, Err(StoreError::Unavailable(ref m)) if m == "deadline"),
        "{out:?}"
    );
    assert!(took < Duration::from_millis(250), "returned in {took:?}");
    // After the lock is released nothing appears: the job was rolled back, not parked.
    tokio::time::sleep(Duration::from_millis(700)).await;
    assert_eq!(c.target_status(), "active");
    assert_eq!(c.f.count_kind("admin.user_disable"), 0);
    // And the writer is usable again with its default busy timeout.
    assert_eq!(c.disable_target().await.unwrap(), (true, 0));
}

#[tokio::test]
async fn the_deadline_is_checked_after_the_lock_is_won_and_before_commit() {
    // After BEGIN IMMEDIATE: the gate holds the job until its deadline has passed.
    let c = console().await;
    c.f.hooks.set_gate("admin_mutation", true);
    let hooks = c.f.hooks.clone();
    let release = async move {
        let h = hooks.clone();
        assert!(
            tokio::task::spawn_blocking(move || h.wait_reached(
                "admin_mutation",
                1,
                Duration::from_secs(5)
            ))
            .await
            .unwrap()
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
        hooks.set_gate("admin_mutation", false);
    };
    let f = &c.f;
    let mk = |row: &SessionRow| f.session_event(row);
    let ev = f.ev_user(EventKind::AdminUserDisable, &c.target.user_id);
    let write = f.store.set_user_status(
        &c.actor,
        &c.policy,
        &c.target.user_id,
        UserStatus::Disabled,
        dl(150),
        ev,
        &mk,
    );
    let (out, ()) = tokio::join!(write, release);
    assert!(
        matches!(out, Err(StoreError::Unavailable(ref m)) if m == "deadline"),
        "after BEGIN: {out:?}"
    );
    assert_eq!(c.target_status(), "active");

    // Before COMMIT: the pre-commit gate holds the job past its deadline.
    let c = console().await;
    c.f.hooks.set_gate("admin_precommit", true);
    let hooks = c.f.hooks.clone();
    let release = async move {
        let h = hooks.clone();
        assert!(
            tokio::task::spawn_blocking(move || h.wait_reached(
                "admin_precommit",
                1,
                Duration::from_secs(5)
            ))
            .await
            .unwrap()
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
        hooks.set_gate("admin_precommit", false);
    };
    let f = &c.f;
    let mk = |row: &SessionRow| f.session_event(row);
    let ev = f.ev_user(EventKind::AdminUserDisable, &c.target.user_id);
    let write = f.store.set_user_status(
        &c.actor,
        &c.policy,
        &c.target.user_id,
        UserStatus::Disabled,
        dl(150),
        ev,
        &mk,
    );
    let (out, ()) = tokio::join!(write, release);
    assert!(
        matches!(out, Err(StoreError::Unavailable(ref m)) if m == "deadline"),
        "before COMMIT: {out:?}"
    );
    assert_eq!(
        c.target_status(),
        "active",
        "a job that reaches its deadline never commits late"
    );
    assert_eq!(c.f.count_kind("admin.user_disable"), 0);
}

#[tokio::test]
async fn retention_inside_the_commit_cannot_swallow_the_deadline() {
    // The write is complete and the inline retention prune is what runs out of
    // time: its interrupted statement must end the job, not be logged and
    // followed by a COMMIT that lands after the deadline.
    let c = console().await;
    bulk_events(&c.f.store.conn(), 30_000, 0);
    c.f.store.set_event_retention(EventRetention {
        retention: Duration::from_secs(90 * 86400),
        max_rows: 100,
        prune_every: 1,
        max_pending_per_sink: 10_000,
        terminal_retention: Duration::from_secs(7 * 86400),
    });
    c.f.hooks.set_slow_scan(80);
    let f = &c.f;
    let started = Instant::now();
    let out = f
        .store
        .set_user_status(
            &c.actor,
            &c.policy,
            &c.target.user_id,
            UserStatus::Disabled,
            dl(400),
            f.ev_user(EventKind::AdminUserDisable, &c.target.user_id),
            &|row| f.session_event(row),
        )
        .await;
    c.f.hooks.set_slow_scan(0);
    assert!(
        matches!(out, Err(StoreError::Unavailable(ref m)) if m == "interrupted" || m == "deadline"),
        "{out:?} after {:?}",
        started.elapsed()
    );
    assert_eq!(
        c.target_status(),
        "active",
        "a job whose retention ran out of time rolled back"
    );
    assert_eq!(c.f.count_kind("admin.user_disable"), 0);
    // Without a deadline the same write commits and prunes.
    assert_eq!(c.disable_target().await.unwrap(), (true, 0));
    assert!(c.f.count("SELECT COUNT(*) FROM events") <= 101);
}

#[tokio::test]
async fn expiry_during_a_retention_read_rolls_the_write_back() {
    // The review's sequence: the write is done, the inline retention prune
    // reads the sinks, the deadline passes while it waits, and the read is
    // interrupted without ending the write transaction. The interrupted read
    // used to be logged and the COMMIT that followed landed the write.
    let c = console().await;
    c.f.store
        .conn()
        .execute_batch(
            "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i < 40000)
             INSERT INTO events (event_id, at, kind, outcome, user_id, session_id, client_ip, request_id, attrs)
             SELECT printf('d_%09d', i), 4102444800.0 + i, 'login.started', 'success', 'u_w', 's_1', '192.0.2.1', 'r', '{}' FROM n;
             INSERT INTO event_deliveries (sink, event_id, state, attempts, next_attempt_at, updated_at)
             SELECT 'log', event_id, 'pending', 0, 4102444800, 4102444800 FROM events WHERE event_id LIKE 'd_%';",
        )
        .unwrap();
    c.f.store.set_event_retention(EventRetention {
        retention: Duration::from_secs(90 * 86400),
        max_rows: 1_000_000,
        prune_every: 1,
        max_pending_per_sink: 1_000_000,
        terminal_retention: Duration::from_secs(7 * 86400),
    });
    c.f.hooks.set_gate("retention_read", true);
    let hooks = c.f.hooks.clone();
    let release = async move {
        let h = hooks.clone();
        assert!(
            tokio::task::spawn_blocking(move || h.wait_reached(
                "retention_read",
                1,
                Duration::from_secs(5)
            ))
            .await
            .unwrap()
        );
        tokio::time::sleep(Duration::from_millis(400)).await;
        hooks.set_gate("retention_read", false);
    };
    let f = &c.f;
    let mk = |row: &SessionRow| f.session_event(row);
    let ev = f.ev_user(EventKind::AdminUserDisable, &c.target.user_id);
    let write = f.store.set_user_status(
        &c.actor,
        &c.policy,
        &c.target.user_id,
        UserStatus::Disabled,
        dl(250),
        ev,
        &mk,
    );
    let (out, ()) = tokio::join!(write, release);
    assert!(
        matches!(out, Err(StoreError::Unavailable(ref m)) if m == "interrupted" || m == "deadline"),
        "{out:?}"
    );
    assert_eq!(
        c.target_status(),
        "active",
        "the write did not commit after its deadline"
    );
    assert_eq!(c.f.count_kind("admin.user_disable"), 0);
}

#[tokio::test]
async fn nested_deadline_scopes_keep_the_earliest() {
    let f = fx();
    f.user(1).await;
    let outer = tokio::time::Instant::now() + Duration::from_secs(5);
    let later = tokio::time::Instant::now() + Duration::from_secs(600);
    let sooner = tokio::time::Instant::now() + Duration::from_secs(1);
    let kept = super::super::with_deadline(
        outer,
        super::super::with_deadline(
            later,
            f.store
                .read_checked("probe", None, |_, c| Ok(c.remaining())),
        ),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(
        kept <= Duration::from_secs(5),
        "a later inner scope extended it: {kept:?}"
    );
    let shorter = super::super::with_deadline(
        outer,
        super::super::with_deadline(
            sooner,
            f.store
                .read_checked("probe", None, |_, c| Ok(c.remaining())),
        ),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(shorter <= Duration::from_secs(1), "{shorter:?}");
}

#[tokio::test]
async fn a_slow_scan_is_interrupted_inside_sqlite_and_the_connection_is_restored() {
    let f = fx();
    f.user(1).await;
    // A long statement under a short deadline is interrupted by the progress handler.
    let heavy = "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i < 50000000) SELECT COUNT(*) FROM n";
    let started = Instant::now();
    let out = f
        .store
        .read_checked("probe", Some(dl(100)), move |c, _| {
            Ok(c.query_row(heavy, [], |r| r.get::<_, i64>(0))?)
        })
        .await;
    assert!(
        matches!(out, Err(StoreError::Unavailable(ref m)) if m == "interrupted"),
        "{out:?}"
    );
    assert!(started.elapsed() < Duration::from_secs(2));
    // The pooled reader returns with no handler and the default busy timeout: a
    // later job without a deadline runs the same kind of statement to its end.
    let n = f
        .store
        .read_checked("probe", None, |c, _| {
            let busy: i64 = c.pragma_query_value(None, "busy_timeout", |r| r.get(0))?;
            assert_eq!(busy, 5000);
            let n: i64 = c.query_row("WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i < 3000000) SELECT COUNT(*) FROM n", [], |r| r.get(0))?;
            Ok(n)
        })
        .await
        .unwrap();
    assert_eq!(n, 3_000_000);
    // Same for the writer.
    let out = f
        .store
        .write_checked("probe", Some(dl(50)), move |env, _| {
            Ok(env.conn.query_row(heavy, [], |r| r.get::<_, i64>(0))?)
        })
        .await;
    assert!(
        matches!(out, Err(StoreError::Unavailable(ref m)) if m == "interrupted"),
        "{out:?}"
    );
    std::thread::sleep(Duration::from_millis(100));
    let n = f
        .store
        .write("probe", |env| {
            let busy: i64 = env.conn.pragma_query_value(None, "busy_timeout", |r| r.get(0))?;
            assert_eq!(busy, 5000);
            Ok(env.conn.query_row("WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i < 3000000) SELECT COUNT(*) FROM n", [], |r| r.get::<_, i64>(0))?)
        })
        .await
        .unwrap();
    assert_eq!(n, 3_000_000);
    assert!(
        crate::telemetry::counters::get(crate::telemetry::counters::STORE_INTERRUPTS_TOTAL, &[])
            >= 2
    );
}

#[tokio::test]
async fn response_deadline_precedes_worker_interruption_and_rollback() {
    let f = fx();
    f.store
        .write("probe", |env| {
            env.conn
                .execute_batch("CREATE TABLE deadline_probe (value INTEGER)")?;
            Ok(())
        })
        .await
        .unwrap();
    let (entered, started) = tokio::sync::oneshot::channel();
    let (release, held) = std::sync::mpsc::channel();
    let (completed, completion) = tokio::sync::oneshot::channel();
    let store = f.store.clone();
    let request = tokio::spawn(async move {
        super::super::with_deadline(
            tokio::time::Instant::now() + Duration::from_secs(1),
            store.write_checked("probe", None, move |env, _| {
                let tx = env.conn.transaction()?;
                tx.execute("INSERT INTO deadline_probe VALUES (1)", [])?;
                let _ = entered.send(());
                // Hold the worker across the response deadline. The installed
                // SQLite progress handler must still interrupt after release.
                held.recv_timeout(Duration::from_secs(5)).unwrap();
                let result = tx.query_row(
                    "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i < 50000000) SELECT COUNT(*) FROM n",
                    [],
                    |r| r.get::<_, i64>(0),
                );
                let interrupted = matches!(
                    &result,
                    Err(rusqlite::Error::SqliteFailure(e, _))
                        if e.code == rusqlite::ErrorCode::OperationInterrupted
                );
                drop(tx);
                let _ = completed.send(interrupted);
                Ok(result?)
            }),
        )
        .await
    });
    tokio::time::timeout(Duration::from_secs(2), started)
        .await
        .expect("the worker must enter the owned transaction")
        .unwrap();
    let out = tokio::time::timeout(Duration::from_secs(2), request)
        .await
        .expect("the response must not await the held worker")
        .unwrap();
    release.send(()).unwrap();
    assert!(
        matches!(out, Err(StoreError::Unavailable(ref m)) if m == "deadline exceeded"),
        "{out:?}"
    );
    assert!(
        tokio::time::timeout(Duration::from_secs(2), completion)
            .await
            .unwrap()
            .unwrap(),
        "the detached job must receive real SQLITE_INTERRUPT"
    );
    // Queue behind the worker so rollback, error mapping and disarm have all
    // finished before checking that the next job can use the connection.
    let count = f
        .store
        .write("probe", |env| {
            assert!(env.conn.is_autocommit());
            let busy: i64 = env
                .conn
                .pragma_query_value(None, "busy_timeout", |r| r.get(0))?;
            assert_eq!(busy, 5000);
            Ok(env
                .conn
                .query_row("SELECT COUNT(*) FROM deadline_probe", [], |r| {
                    r.get::<_, i64>(0)
                })?)
        })
        .await
        .unwrap();
    assert_eq!(count, 0, "the detached mutation must roll back");
}

#[tokio::test]
async fn admin_denials_and_csrf_rejections_are_appended_alone_with_their_delivery_rows() {
    let f = fx();
    let denied = EventBuilder::new(
        &*f.clock,
        &f.rng,
        EventKind::AdminDenied,
        Outcome::Failure,
        "r",
    )
    .reason(reasons::NOT_ADMIN)
    .attr("actor", "u_x")
    .build();
    let csrf = EventBuilder::new(
        &*f.clock,
        &f.rng,
        EventKind::CsrfRejected,
        Outcome::Failure,
        "r",
    )
    .attr("purpose", "admin")
    .build();
    f.store.append_required(vec![denied, csrf]).await.unwrap();
    assert_eq!(f.count_kind("admin.denied"), 1);
    assert_eq!(f.count_kind("csrf.rejected"), 1);
    assert_eq!(
        f.count("SELECT COUNT(*) FROM event_deliveries WHERE sink='log' AND state='pending'"),
        2
    );
}

#[test]
fn a_bounded_job_on_a_plain_connection_is_refused_late_and_leaves_the_connection_clean() {
    let dir = tempfile::tempdir().unwrap();
    let c = Connection::open(dir.path().join("x.db")).unwrap();
    let past = Some(Instant::now() - Duration::from_millis(1));
    let out = super::super::with_job_deadline(&c, past, |_, _| Ok(1));
    assert!(
        matches!(out, Err(StoreError::Unavailable(ref m)) if m == "deadline"),
        "{out:?}"
    );
    // Within the deadline the job runs; afterwards the handler is gone and the default busy timeout is back.
    let soon = Some(Instant::now() + Duration::from_millis(80));
    let r = super::super::with_job_deadline(&c, soon, |c, check| {
        assert!(check.remaining().is_some());
        let busy: i64 = c.pragma_query_value(None, "busy_timeout", |r| r.get(0))?;
        assert!(busy <= 80, "bounded by the deadline: {busy}");
        Ok(7)
    })
    .unwrap();
    assert_eq!(r, 7);
    std::thread::sleep(Duration::from_millis(120));
    let busy: i64 = c
        .pragma_query_value(None, "busy_timeout", |r| r.get(0))
        .unwrap();
    assert_eq!(busy, 5000);
    let n: i64 = c
        .query_row("WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i < 2000000) SELECT COUNT(*) FROM n", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 2_000_000, "no stale progress handler interrupts it");
}

#[test]
fn a_panicking_bounded_job_restores_sqlite_busy_state() {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _: crate::store::StoreResult<()> = crate::store::sqlite::with_job_deadline(
            &conn,
            Some(Instant::now() + Duration::from_millis(100)),
            |_, _| panic!("fixture job panic"),
        );
    }));
    assert!(result.is_err());
    let timeout: i64 = conn
        .pragma_query_value(None, "busy_timeout", |r| r.get(0))
        .unwrap();
    assert_eq!(timeout, 5000);
    conn.execute_batch("CREATE TABLE recovery(id INTEGER)")
        .unwrap();
}

#[test]
fn v5_foundation_refuses_missing_or_weakened_totp_structures() {
    for damage in [
        "DROP TABLE totp_enrollments",
        "ALTER TABLE totp_enrollments RENAME COLUMN last_counter TO unrelated",
        "DROP INDEX totp_one_pending_per_user",
        "DROP INDEX totp_one_active_per_user;CREATE INDEX totp_one_active_per_user ON totp_enrollments(user_id) WHERE state='active'",
        "DROP INDEX totp_one_active_per_user;CREATE UNIQUE INDEX totp_one_active_per_user ON totp_enrollments(enrollment_id) WHERE state='active'",
        "DROP INDEX totp_one_active_per_user;CREATE UNIQUE INDEX totp_one_active_per_user ON totp_enrollments(user_id) WHERE state='pending'",
    ] {
        let conn = Connection::open_in_memory().unwrap();
        super::super::migrate(&conn).unwrap();
        super::super::validate_foundation(&conn, 5).unwrap();
        conn.execute_batch(damage).unwrap();
        assert!(matches!(
            super::super::validate_foundation(&conn, 5),
            Err(StoreError::Corrupt(_))
        ));
    }
}
