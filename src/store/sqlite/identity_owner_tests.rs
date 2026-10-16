use super::super::{MIGRATIONS, Store, migrate, precheck};
use super::*;
use crate::{
    crypto::{SeededRng, TestClock, Timestamp},
    provider::types::ProviderId,
    store::{Directory, NewIdentity, NewUser},
};
use std::sync::Arc;
fn fixture() -> (tempfile::TempDir, Store) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(
        &dir.path().join("identity.db"),
        Arc::new(TestClock::new(Timestamp(1_700_000_000_000))),
        vec![],
        None,
    )
    .unwrap();
    (dir, store)
}
fn user() -> NewUser {
    NewUser {
        primary_email: None,
        email_verified: false,
        email_authoritative: false,
        display_name: None,
        username: None,
    }
}
fn identity(subject: &str) -> NewIdentity {
    NewIdentity {
        provider_id: ProviderId::new("mock"),
        subject: subject.into(),
        email: None,
        email_verified: false,
        email_authoritative: false,
        name: None,
        picture: None,
        raw_claims: serde_json::json!({}),
    }
}
fn realm(store: &Store) -> String {
    store
        .conn()
        .query_row("SELECT realm FROM human_authority_realm", [], |r| r.get(0))
        .unwrap()
}
#[tokio::test]
async fn identity_owner_actual_directory_create_link_reopen_and_historical_collision() {
    let (dir, store) = fixture();
    let first_realm = realm(&store);
    assert!(valid_realm(&first_realm));
    store.set_rng(Arc::new(SeededRng::new(91)));
    let a = store
        .create_user(user(), identity("original"), vec![])
        .await
        .unwrap();
    store
        .link_identity(&a.user_id, identity("linked"), vec![])
        .await
        .unwrap();
    assert_eq!(
        store
            .identity(&ProviderId::new("mock"), "linked")
            .await
            .unwrap()
            .unwrap()
            .user_id,
        a.user_id
    );
    assert_eq!(realm(&store), first_realm);
    let reopened = Store::open(
        &dir.path().join("identity.db"),
        Arc::new(TestClock::new(Timestamp(1_700_000_000_000))),
        vec![],
        None,
    )
    .unwrap();
    assert_eq!(realm(&reopened), first_realm);
    {
        let conn = store.conn();
        assert!(
            conn.execute(
                "UPDATE users SET user_id='replacement' WHERE user_id=?1",
                [a.user_id.as_str()]
            )
            .is_err()
        );
        assert!(
            conn.execute(
                "INSERT OR REPLACE INTO users(user_id,created_at,updated_at) VALUES(?1,1,1)",
                [a.user_id.as_str()]
            )
            .is_err()
        );
        conn.execute(
            "UPDATE users SET status='disabled',authz_version=authz_version+1 WHERE user_id=?1",
            [a.user_id.as_str()],
        )
        .unwrap();
    }
    assert_eq!(
        store.user(&a.user_id).await.unwrap().unwrap().status,
        crate::store::UserStatus::Disabled
    );
    {
        let conn = store.conn();
        conn.execute(
            "DELETE FROM identities WHERE user_id=?1",
            [a.user_id.as_str()],
        )
        .unwrap();
        conn.execute("DELETE FROM users WHERE user_id=?1", [a.user_id.as_str()])
            .unwrap();
    }
    store.set_rng(Arc::new(SeededRng::new(91)));
    assert!(
        store
            .create_user(user(), identity("after-delete"), vec![])
            .await
            .is_err()
    );
    assert!(
        store
            .identity(&ProviderId::new("mock"), "after-delete")
            .await
            .unwrap()
            .is_none()
    );
    assert!(store.user(&a.user_id).await.unwrap().is_none());
    assert_eq!(realm(&store), first_realm);
    validate_foundation(&store.conn()).unwrap();
}
#[test]
fn identity_owner_realm_and_history_resist_replace_mutation_and_delete() {
    let (_dir, store) = fixture();
    let before = realm(&store);
    let conn = store.conn();
    assert_eq!(
        conn.query_row("PRAGMA recursive_triggers", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        0
    );
    for sql in [
        "INSERT OR REPLACE INTO human_authority_realm VALUES(1,lower(hex(randomblob(32))))",
        "UPDATE human_authority_realm SET realm=lower(hex(randomblob(32)))",
        "DELETE FROM human_authority_realm",
    ] {
        assert!(conn.execute(sql, []).is_err());
    }
    conn.execute(
        "INSERT INTO users(user_id,created_at,updated_at) VALUES('legacy arbitrary Ω',1,1)",
        [],
    )
    .unwrap();
    for sql in [
        "INSERT OR REPLACE INTO human_user_ids VALUES('legacy arbitrary Ω')",
        "DELETE FROM human_user_ids",
        "UPDATE human_user_ids SET user_id='another'",
    ] {
        assert!(conn.execute(sql, []).is_err());
    }
    conn.execute("DELETE FROM users", []).unwrap();
    assert!(
        conn.execute(
            "INSERT INTO users(user_id,created_at,updated_at) VALUES('legacy arbitrary Ω',1,1)",
            []
        )
        .is_err()
    );
    assert_eq!(
        conn.query_row("SELECT realm FROM human_authority_realm", [], |r| r
            .get::<_, String>(0))
            .unwrap(),
        before
    );
}
#[test]
fn identity_owner_v9_backfill_is_atomic_and_preserves_legacy_ids() {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    conn.execute_batch("CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY NOT NULL,name TEXT NOT NULL,applied_at INTEGER NOT NULL) STRICT").unwrap();
    for (version, name, sql) in MIGRATIONS.iter().take(9) {
        conn.execute_batch(sql).unwrap();
        conn.execute(
            "INSERT INTO schema_migrations VALUES(?1,?2,1)",
            rusqlite::params![version, name],
        )
        .unwrap();
    }
    conn.execute(
        "INSERT INTO users(user_id,created_at,updated_at) VALUES('old user Ω',1,1)",
        [],
    )
    .unwrap();
    assert_eq!(migrate(&conn).unwrap(), 13);
    validate_foundation(&conn).unwrap();
    assert_eq!(
        conn.query_row("SELECT user_id FROM human_user_ids", [], |r| r
            .get::<_, String>(0))
            .unwrap(),
        "old user Ω"
    );
    let before: String = conn
        .query_row("SELECT realm FROM human_authority_realm", [], |r| r.get(0))
        .unwrap();
    migrate(&conn).unwrap();
    assert_eq!(
        conn.query_row("SELECT realm FROM human_authority_realm", [], |r| r
            .get::<_, String>(0))
            .unwrap(),
        before
    );
}
#[test]
fn identity_owner_precheck_refuses_tampered_guards_without_writing() {
    for trigger in [
        "human_realm_insert",
        "human_realm_update",
        "human_realm_delete",
        "human_user_ids_insert",
        "human_user_ids_update",
        "human_user_ids_delete",
        "human_user_identity_insert",
        "human_user_identity_reserve",
        "human_user_identity_update",
    ] {
        let (dir, store) = fixture();
        store
            .conn()
            .execute_batch(&format!("DROP TRIGGER {trigger}"))
            .unwrap();
        assert!(precheck(&dir.path().join("identity.db")).is_err());
        assert!(
            Store::open(
                &dir.path().join("identity.db"),
                Arc::new(TestClock::new(Timestamp(1))),
                vec![],
                None
            )
            .is_err()
        );
        assert_eq!(
            store
                .conn()
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='trigger' AND name=?1",
                    [trigger],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
            0
        );
    }
}
#[test]
fn identity_owner_ddl_literals_are_case_and_space_sensitive() {
    assert_ne!(
        normalized("CHECK(x NOT GLOB '*[^a-f]*')"),
        normalized("CHECK(x NOT GLOB '*[^A-F]*')")
    );
    assert_ne!(normalized("CHECK(x='a b')"), normalized("CHECK(x='ab')"));
    for change in [
        "realm NOT GLOB '*[^0-9A-F]*'",
        "realm NOT GLOB '*[^0-9a-f ]*'",
    ] {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE users(user_id TEXT PRIMARY KEY) STRICT")
            .unwrap();
        let sql = include_str!("../migrations/0010_human_identity_owners.sql")
            .replace("realm NOT GLOB '*[^0-9a-f]*'", change)
            .replace(
                "lower(hex(randomblob(32)))",
                "'1111111111111111111111111111111111111111111111111111111111111111'",
            );
        conn.execute_batch(&sql).unwrap();
        assert!(validate_foundation(&conn).is_err());
    }
}

#[test]
fn identity_owner_zero_realm_initialization_rolls_back_without_fallback() {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    conn.execute_batch("CREATE TABLE users(user_id TEXT PRIMARY KEY) STRICT; INSERT INTO users VALUES('existing');").unwrap();
    {
        let tx = conn.unchecked_transaction().unwrap();
        let sql = include_str!("../migrations/0010_human_identity_owners.sql").replace(
            "lower(hex(randomblob(32)))",
            "'0000000000000000000000000000000000000000000000000000000000000000'",
        );
        assert!(tx.execute_batch(&sql).is_err());
    }
    assert_eq!(conn.query_row("SELECT COUNT(*) FROM sqlite_master WHERE name IN ('human_authority_realm','human_user_ids')",[],|r|r.get::<_,i64>(0)).unwrap(),0);
    assert_eq!(
        conn.query_row("SELECT user_id FROM users", [], |r| r.get::<_, String>(0))
            .unwrap(),
        "existing"
    );
}
