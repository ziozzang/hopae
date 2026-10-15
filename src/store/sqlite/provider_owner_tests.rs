use super::*;
use crate::{
    crypto::{TestClock, Timestamp},
    provider::types::ProviderKind,
    store::{
        Directory,
        types::{ManagedBy, ProviderRow},
    },
};
use std::time::{Duration, Instant};

fn deadline() -> Deadline {
    Deadline(Instant::now() + Duration::from_secs(5))
}
fn fixture() -> (tempfile::TempDir, Store) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(
        &dir.path().join("owner.db"),
        Arc::new(TestClock::new(Timestamp(1_700_000_000_000))),
        vec![],
        None,
    )
    .unwrap();
    (dir, store)
}
fn provider() -> ProviderRow {
    ProviderRow {
        provider_id: ProviderId::new("directory"),
        kind: ProviderKind::Ldap,
        display_name: "Directory".into(),
        enabled: true,
        managed_by: ManagedBy::File,
        deleted_at: None,
        sort_order: 0,
        config: serde_json::json!({"realm":"owned"}),
        client_secret_env: Some("OWNED_REFERENCE".into()),
        allowed_email_domains: vec![],
        authoritative_domains: vec![],
        auto_link: false,
        trust_email: false,
    }
}
async fn import(store: &Store, row: ProviderRow) {
    store
        .import_providers(vec![row], None, vec![])
        .await
        .unwrap();
}
fn revision(store: &Store) -> i64 {
    store
        .conn()
        .query_row(
            "SELECT revision FROM human_provider_owners WHERE provider_id='directory'",
            [],
            |r| r.get(0),
        )
        .unwrap()
}

#[tokio::test]
async fn no_op_import_and_presentation_changes_preserve_owner_material_import_retires() {
    let (_dir, store) = fixture();
    let mut row = provider();
    import(&store, row.clone()).await;
    let owner = store
        .capture_provider_owner(&row.provider_id, deadline())
        .await
        .unwrap();
    import(&store, row.clone()).await;
    row.display_name = "Renamed".into();
    row.sort_order = 9;
    import(&store, row.clone()).await;
    assert_eq!(revision(&store), 1);
    store
        .require_provider_owner(&owner, deadline())
        .await
        .unwrap();
    row.config = serde_json::json!({"realm":"replacement"});
    import(&store, row).await;
    assert_eq!(revision(&store), 2);
    assert!(
        store
            .require_provider_owner(&owner, deadline())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn material_aba_disable_reenable_and_all_authority_fields_retire() {
    let (_dir, store) = fixture();
    let row = provider();
    import(&store, row.clone()).await;
    let changes = [
        ("kind", "'oidc'"),
        ("enabled", "0"),
        ("deleted_at", "1"),
        ("config", "'{\"replacement\":true}'"),
        ("client_secret_env", "'NEW_REFERENCE'"),
        ("allowed_email_domains", "'[\"example.test\"]'"),
        ("authoritative_domains", "'[\"example.test\"]'"),
        ("auto_link", "1"),
        ("trust_email", "1"),
    ];
    for (column, value) in changes {
        let owner = store
            .capture_provider_owner(&row.provider_id, deadline())
            .await
            .unwrap();
        let before = revision(&store);
        store
            .conn()
            .execute(
                &format!("UPDATE providers SET {column}={value} WHERE provider_id='directory'"),
                [],
            )
            .unwrap();
        assert!(
            store
                .require_provider_owner(&owner, deadline())
                .await
                .is_err(),
            "{column}"
        );
        if column == "deleted_at" {
            // Ordinary import deliberately preserves a tombstoned provider;
            // only the existing explicit force-import owner can revive it.
            import(&store, row.clone()).await;
            assert_eq!(revision(&store), before + 1);
            store
                .import_providers(vec![row.clone()], Some(&row.provider_id), vec![])
                .await
                .unwrap();
        } else {
            import(&store, row.clone()).await;
        }
        assert_eq!(revision(&store), before + 2, "{column}");
        assert!(
            store
                .require_provider_owner(&owner, deadline())
                .await
                .is_err(),
            "ABA {column}"
        );
    }
}

#[tokio::test]
async fn deletion_recreation_and_replace_keep_tombstone_and_never_reuse_owner() {
    let (_dir, store) = fixture();
    let row = provider();
    import(&store, row.clone()).await;
    let owner = store
        .capture_provider_owner(&row.provider_id, deadline())
        .await
        .unwrap();
    store
        .conn()
        .execute("DELETE FROM providers WHERE provider_id='directory'", [])
        .unwrap();
    assert_eq!(revision(&store), 2);
    assert!(
        store
            .capture_provider_owner(&row.provider_id, deadline())
            .await
            .is_err()
    );
    import(&store, row.clone()).await;
    assert_eq!(revision(&store), 3);
    assert!(
        store
            .require_provider_owner(&owner, deadline())
            .await
            .is_err()
    );
    let owner = store
        .capture_provider_owner(&row.provider_id, deadline())
        .await
        .unwrap();
    store.conn().execute("INSERT OR REPLACE INTO providers SELECT * FROM providers WHERE provider_id='directory'",[]).unwrap();
    assert!(revision(&store) > 3);
    assert!(
        store
            .require_provider_owner(&owner, deadline())
            .await
            .is_err()
    );
    assert!(
        store
            .conn()
            .execute(
                "UPDATE providers SET provider_id='another' WHERE provider_id='directory'",
                []
            )
            .is_err()
    );
}

#[tokio::test]
async fn rollback_and_overflow_leave_provider_and_owner_atomic() {
    let (_dir, store) = fixture();
    let row = provider();
    import(&store, row.clone()).await;
    let owner = store
        .capture_provider_owner(&row.provider_id, deadline())
        .await
        .unwrap();
    {
        let mut connection = store.conn();
        let tx = connection.transaction().unwrap();
        tx.execute(
            "UPDATE providers SET enabled=0 WHERE provider_id='directory'",
            [],
        )
        .unwrap();
        let n: i64 = tx
            .query_row("SELECT revision FROM human_provider_owners", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(n, 2);
        tx.rollback().unwrap();
    }
    store
        .require_provider_owner(&owner, deadline())
        .await
        .unwrap();
    assert_eq!(revision(&store), 1);
    store
        .conn()
        .execute(
            "UPDATE human_provider_owners SET revision=9223372036854775807",
            [],
        )
        .unwrap();
    assert!(
        store
            .conn()
            .execute(
                "UPDATE providers SET enabled=0 WHERE provider_id='directory'",
                []
            )
            .is_err()
    );
    assert!(
        store
            .conn()
            .execute("DELETE FROM providers WHERE provider_id='directory'", [])
            .is_err()
    );
    assert!(
        store
            .import_providers(
                vec![ProviderRow {
                    enabled: false,
                    ..row
                }],
                None,
                vec![]
            )
            .await
            .is_err()
    );
    assert_eq!(revision(&store), i64::MAX);
    let enabled: bool = store
        .conn()
        .query_row("SELECT enabled FROM providers", [], |r| r.get(0))
        .unwrap();
    assert!(enabled);
}

#[tokio::test]
async fn store_restart_and_other_store_and_expired_deadline_cannot_accept_token() {
    let (dir, store) = fixture();
    let row = provider();
    import(&store, row.clone()).await;
    let owner = store
        .capture_provider_owner(&row.provider_id, deadline())
        .await
        .unwrap();
    let (_other, other) = fixture();
    import(&other, row.clone()).await;
    assert!(
        other
            .require_provider_owner(&owner, deadline())
            .await
            .is_err()
    );
    assert!(
        store
            .require_provider_owner(&owner, Deadline(Instant::now() - Duration::from_secs(1)))
            .await
            .is_err()
    );
    drop(store);
    let reopened = Store::open(
        &dir.path().join("owner.db"),
        Arc::new(TestClock::new(Timestamp(1_700_000_000_000))),
        vec![],
        None,
    )
    .unwrap();
    assert_eq!(revision(&reopened), 1);
    assert!(
        reopened
            .require_provider_owner(&owner, deadline())
            .await
            .is_err()
    );
}

#[test]
fn migration_backfills_existing_live_and_tombstoned_providers_transactionally() {
    let mut c = rusqlite::Connection::open_in_memory().unwrap();
    for (_, _, sql) in super::super::MIGRATIONS.iter().take(6) {
        c.execute_batch(sql).unwrap();
    }
    c.execute("INSERT INTO providers(provider_id,kind,display_name,enabled,managed_by,created_at,updated_at) VALUES('directory','ldap','Owned',1,'file',0,0)",[]).unwrap();
    c.execute("INSERT INTO providers(provider_id,kind,display_name,enabled,managed_by,deleted_at,created_at,updated_at) VALUES('retired','oidc','Retired',0,'file',1,0,0)", []).unwrap();
    let sql = include_str!("../migrations/0007_human_provider_owners.sql");
    {
        let tx = c.transaction().unwrap();
        tx.execute_batch(sql).unwrap();
        tx.rollback().unwrap();
    }
    let count: i64 = c
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE name='human_provider_owners'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 0);
    {
        let tx = c.transaction().unwrap();
        tx.execute_batch(sql).unwrap();
        tx.commit().unwrap();
    }
    assert_eq!(current(&c, "directory").unwrap(), 1);
    let retired: i64 = c
        .query_row(
            "SELECT revision FROM human_provider_owners WHERE provider_id='retired'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(retired, 1);
    assert!(current(&c, "retired").is_err());
    c.execute("UPDATE providers SET deleted_at=1", []).unwrap();
    assert!(current(&c, "directory").is_err());
}

#[test]
fn precheck_refuses_missing_or_modified_guards_without_repair() {
    for name in [
        "human_provider_owner_identity",
        "human_provider_owner_insert",
        "human_provider_owner_delete",
        "human_provider_owner_material",
    ] {
        let (dir, store) = fixture();
        store.conn().execute_batch(&format!("DROP TRIGGER {name}; CREATE TRIGGER {name} AFTER INSERT ON providers BEGIN SELECT 1; END;")).unwrap();
        assert!(super::super::precheck(&dir.path().join("owner.db")).is_err());
        let sql: String = store
            .conn()
            .query_row("SELECT sql FROM sqlite_master WHERE name=?1", [name], |r| {
                r.get(0)
            })
            .unwrap();
        assert!(sql.contains("SELECT 1"));
    }
}

#[tokio::test]
async fn missing_provider_owner_is_corruption_not_epoch_reinitialization() {
    let (dir, store) = fixture();
    let row = provider();
    import(&store, row.clone()).await;
    store
        .conn()
        .execute("DELETE FROM human_provider_owners", [])
        .unwrap();
    assert!(super::super::precheck(&dir.path().join("owner.db")).is_err());
    assert!(
        store
            .capture_provider_owner(&row.provider_id, deadline())
            .await
            .is_err()
    );
    assert_eq!(
        store
            .conn()
            .query_row("SELECT count(*) FROM human_provider_owners", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
}
