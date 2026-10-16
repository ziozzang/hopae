//! M0: SQLite store, migrations and file permissions.
mod support;

fn open(path: &std::path::Path) -> Result<Store, hopae::store::StoreError> {
    Store::open(path, Arc::new(SystemClock), vec!["log".to_string()], None)
}

use std::os::unix::fs::PermissionsExt;

use std::sync::Arc;

use hopae::crypto::SystemClock;
use hopae::store::Store;
use hopae::store::sqlite::migrate;

fn mode(p: &std::path::Path) -> u32 {
    std::fs::metadata(p).unwrap().permissions().mode() & 0o777
}

#[test]
fn open_applies_migration_and_sets_pragmas() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(&dir.path().join("state/hopae.db")).unwrap();
    assert_eq!(
        store.schema_version().unwrap(),
        hopae::store::sqlite::LATEST_SCHEMA_VERSION
    );
    let c = store.conn();
    let jm: String = c
        .pragma_query_value(None, "journal_mode", |r| r.get(0))
        .unwrap();
    assert_eq!(jm, "wal");
    let fk: i64 = c
        .pragma_query_value(None, "foreign_keys", |r| r.get(0))
        .unwrap();
    assert_eq!(fk, 1);
    let bt: i64 = c
        .pragma_query_value(None, "busy_timeout", |r| r.get(0))
        .unwrap();
    assert!(bt >= 1000);
    // M1 data model (migration 0002), administrator grants (0003) plus bookkeeping.
    let tables: Vec<String> = c
        .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(
        tables,
        [
            "admin_grants",
            "apps",
            "directory_groups",
            "event_deliveries",
            "events",
            "external_factor_authorities",
            "external_factor_budget",
            "external_factor_proofs",
            "external_factor_sessions",
            "group_changes",
            "group_members",
            "group_sync_state",
            "handoff_codes",
            "human_authority_realm",
            "human_provider_material_owners",
            "human_provider_owners",
            "human_user_ids",
            "identities",
            "login_txns",
            "meta",
            "providers",
            "recovery_codes",
            "schema_migrations",
            "service_credentials",
            "session_handles",
            "session_primary_provenance",
            "session_totp_provenance",
            "session_webauthn_elevations",
            "session_webauthn_provenance",
            "sessions",
            "sqlite_sequence",
            "totp_enrollments",
            "txn_admissions",
            "users",
            "webauthn_challenges",
            "webauthn_credentials",
            "webauthn_login_challenges"
        ]
    );
}

#[test]
fn migrations_are_idempotent_across_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("hopae.db");
    let first = open(&path).unwrap();
    let count = |s: &hopae::store::sqlite::Store| -> (i64, i64) {
        s.conn()
            .query_row(
                "SELECT COUNT(*), MAX(version) FROM schema_migrations",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap()
    };
    let before = count(&first);
    drop(first);
    let store = open(&path).unwrap();
    assert_eq!(
        migrate(&store.conn()).unwrap(),
        hopae::store::sqlite::LATEST_SCHEMA_VERSION
    );
    // Versions may skip numbers reserved by another branch (ADR-0019).
    let (n, max) = count(&store);
    assert_eq!((n, max), before);
    assert_eq!(max, i64::from(hopae::store::sqlite::LATEST_SCHEMA_VERSION));
}

#[test]
fn newer_database_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("hopae.db");
    let store = open(&path).unwrap();
    store
        .conn()
        .execute(
            "INSERT INTO schema_migrations (version, name, applied_at) VALUES (99, 'future', 0)",
            [],
        )
        .unwrap();
    drop(store);
    assert!(open(&path).is_err());
}

#[test]
fn db_file_is_0600_and_new_state_dir_is_0700() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    let path = state.join("hopae.db");
    let store = open(&path).unwrap();
    store
        .conn()
        .execute("INSERT INTO meta (key, value) VALUES ('k', 'v')", [])
        .unwrap();
    assert_eq!(mode(&state), 0o700);
    assert_eq!(mode(&path), 0o600);
    for suffix in ["-wal", "-shm"] {
        let side = state.join(format!("hopae.db{suffix}"));
        if side.exists() {
            assert_eq!(mode(&side), 0o600, "{suffix}");
        }
    }
}

#[test]
fn existing_loose_file_is_tightened() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("hopae.db");
    std::fs::write(&path, b"").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    drop(open(&path).unwrap());
    assert_eq!(mode(&path), 0o600);
}
