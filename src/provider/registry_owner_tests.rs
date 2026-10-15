use super::*;
use crate::{
    crypto::{TestClock, Timestamp},
    store::{Deadline, Directory, ManagedBy, Store},
};
use std::time::{Duration, Instant};
fn deadline() -> Deadline {
    Deadline(Instant::now() + Duration::from_secs(5))
}
fn row() -> ProviderRow {
    ProviderRow {
        provider_id: ProviderId::new("actual-db"),
        kind: ProviderKind::Oidc,
        display_name: "Actual".into(),
        enabled: true,
        managed_by: ManagedBy::File,
        deleted_at: None,
        sort_order: 0,
        config: serde_json::json!({"client_id":"actual-db-client","issuer":"https://127.0.0.1:1","allow_private_endpoints":true}),
        client_secret_env: Some("OWNED_REFERENCE".into()),
        allowed_email_domains: vec![],
        authoritative_domains: vec![],
        auto_link: false,
        trust_email: false,
    }
}
fn clock() -> Arc<dyn Clock> {
    Arc::new(TestClock::new(Timestamp(1_800_000_000_000)))
}
async fn fixture() -> (
    tempfile::TempDir,
    Store,
    Arc<arc_swap::ArcSwap<crate::policy::types::ConfigSnapshot>>,
) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("owner.db"), clock(), vec![], None).unwrap();
    store.bump_config_generation().await.unwrap();
    store
        .import_providers(vec![row()], None, vec![])
        .await
        .unwrap();
    let config=crate::config::parse(&serde_json::json!({"state_dir":dir.path().join("state"),"portal":{"public_url":"https://auth.example.test"},"gateway":{"kind":"hangang","caller_key_env":"OWNED_CALLER"},"apps":[{"app_id":"orders","hosts":["orders.example.test"]}]}).to_string()).unwrap();
    let applications = Arc::new(arc_swap::ArcSwap::from_pointee(config.snapshot(1)));
    (dir, store, applications)
}
async fn registry(
    store: &Store,
    applications: Arc<arc_swap::ArcSwap<crate::policy::types::ConfigSnapshot>>,
) -> Arc<Registry> {
    let prepared = store
        .prepare_registry_providers(1, deadline())
        .await
        .unwrap();
    Arc::new(
        Registry::from_prepared(
            prepared,
            applications,
            &|_| Some("owned-fixed-credential".into()),
            clock(),
            None,
        )
        .unwrap(),
    )
}

#[tokio::test]
async fn actual_db_rows_owned_registry_requires_publication_and_preserves_noop() {
    let (_dir, store, apps) = fixture().await;
    let registry = registry(&store, apps).await;
    let id = row().provider_id;
    assert_eq!(registry.deferred_refreshers.len(), 1);
    assert!(registry.get(&id).unwrap().enabled());
    assert!(
        registry
            .capture_provider_fence(&store, &id, deadline())
            .await
            .is_err()
    );
    registry.publish_prepared(&store, deadline()).await.unwrap();
    let owner = registry
        .capture_provider_fence(&store, &id, deadline())
        .await
        .unwrap();
    store
        .import_providers(vec![row()], None, vec![])
        .await
        .unwrap();
    registry
        .require_provider_fence(&store, &owner, deadline())
        .await
        .unwrap();
    assert!(
        registry
            .capture_provider_fence(&store, &ProviderId::new("file-only"), deadline())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn actual_retained_api_managed_row_compiles_instead_of_file_declaration() {
    let (_dir, store, apps) = fixture().await;
    store
        .conn()
        .execute("UPDATE providers SET managed_by='api'", [])
        .unwrap();
    let mut bootstrap = row();
    bootstrap.config["client_id"] = serde_json::json!("wrong-file-client");
    let report = store
        .import_providers(vec![bootstrap], None, vec![])
        .await
        .unwrap();
    assert_eq!(report.skipped_api_managed.len(), 1);
    let prepared = store
        .prepare_registry_providers(1, deadline())
        .await
        .unwrap();
    assert_eq!(prepared.rows()[0].config["client_id"], "actual-db-client");
    let registry = Arc::new(
        Registry::from_prepared(
            prepared,
            apps,
            &|_| Some("owned-fixed-credential".into()),
            clock(),
            None,
        )
        .unwrap(),
    );
    registry.publish_prepared(&store, deadline()).await.unwrap();
    registry
        .capture_provider_fence(&store, &row().provider_id, deadline())
        .await
        .unwrap();
}

#[tokio::test]
async fn material_aba_and_disable_restore_require_new_registry_not_late_binding() {
    for column in ["config", "enabled", "deleted_at"] {
        let (_dir, store, apps) = fixture().await;
        let registry = registry(&store, apps.clone()).await;
        registry.publish_prepared(&store, deadline()).await.unwrap();
        let owner = registry
            .capture_provider_fence(&store, &row().provider_id, deadline())
            .await
            .unwrap();
        let sql = match column {
            "config" => "UPDATE providers SET config='{\"client_id\":\"changed\"}'",
            "enabled" => "UPDATE providers SET enabled=0",
            _ => "UPDATE providers SET deleted_at=1",
        };
        store.conn().execute(sql, []).unwrap();
        assert!(
            registry
                .require_provider_fence(&store, &owner, deadline())
                .await
                .is_err()
        );
        store
            .import_providers(vec![row()], Some(&row().provider_id), vec![])
            .await
            .unwrap();
        assert!(
            registry
                .require_provider_fence(&store, &owner, deadline())
                .await
                .is_err()
        );
        assert!(
            registry
                .capture_provider_fence(&store, &row().provider_id, deadline())
                .await
                .is_err()
        );
        let next = super::owner_tests::registry(&store, apps).await;
        next.publish_prepared(&store, deadline()).await.unwrap();
        next.capture_provider_fence(&store, &row().provider_id, deadline())
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn compile_gap_mutation_refuses_publication_before_starting_refresher() {
    let (_dir, store, apps) = fixture().await;
    let prepared = store
        .prepare_registry_providers(1, deadline())
        .await
        .unwrap();
    let env = |_: &str| {
        store
            .conn()
            .execute("UPDATE providers SET enabled=0", [])
            .unwrap();
        Some("owned-fixed-credential".into())
    };
    let registry = Arc::new(Registry::from_prepared(prepared, apps, &env, clock(), None).unwrap());
    // Compiled the original row, while an independently committed SQL owner
    // mutation occurred in the compile gap. No process environment is changed.
    assert!(registry.get(&row().provider_id).unwrap().enabled());
    assert!(
        !registry
            .owners
            .as_ref()
            .unwrap()
            .published
            .load(std::sync::atomic::Ordering::Acquire)
    );
    assert!(registry.publish_prepared(&store, deadline()).await.is_err());
    assert!(
        !registry
            .owners
            .as_ref()
            .unwrap()
            .published
            .load(std::sync::atomic::Ordering::Acquire)
    );
    assert!(
        registry
            .capture_provider_fence(&store, &row().provider_id, deadline())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn usable_compiled_adapter_not_db_enabled_bit_is_required() {
    for kind in [
        ProviderKind::Oidc,
        ProviderKind::Ldap,
        ProviderKind::Password,
    ] {
        let (_dir, store, apps) = fixture().await;
        let mut row = row();
        row.kind = kind;
        if kind == ProviderKind::Ldap {
            row.config = serde_json::json!({"ldap":{"endpoint":"invalid"}});
        }
        store
            .import_providers(vec![row.clone()], None, vec![])
            .await
            .unwrap();
        let prepared = store
            .prepare_registry_providers(1, deadline())
            .await
            .unwrap();
        let registry =
            Arc::new(Registry::from_prepared(prepared, apps, &|_| None, clock(), None).unwrap());
        registry.publish_prepared(&store, deadline()).await.unwrap();
        assert!(
            registry
                .capture_provider_fence(&store, &row.provider_id, deadline())
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn same_generation_app_replacement_cross_registry_store_and_unqualified_snapshot_refuse() {
    let (_dir, store, apps) = fixture().await;
    let registry = registry(&store, apps.clone()).await;
    registry.publish_prepared(&store, deadline()).await.unwrap();
    let owner = registry
        .capture_provider_fence(&store, &row().provider_id, deadline())
        .await
        .unwrap();
    let old = apps.load_full();
    apps.store(Arc::new((*old).clone()));
    assert!(
        registry
            .require_provider_fence(&store, &owner, deadline())
            .await
            .is_err()
    );
    apps.store(old);
    assert!(
        registry
            .require_provider_fence(&store, &owner, deadline())
            .await
            .is_err()
    ); // retired witness
    let next = super::owner_tests::registry(&store, apps).await;
    next.publish_prepared(&store, deadline()).await.unwrap();
    assert!(
        next.require_provider_fence(&store, &owner, deadline())
            .await
            .is_err()
    );
    let (_other, other, _) = fixture().await;
    assert!(
        next.capture_provider_fence(&other, &row().provider_id, deadline())
            .await
            .is_err()
    );
    let legacy = Arc::new(Registry::from_snapshot(
        &[row()],
        &|_| Some("owned-fixed-credential".into()),
        clock(),
        None,
    ));
    assert!(legacy.get(&row().provider_id).unwrap().enabled());
    assert!(
        legacy
            .capture_provider_fence(&store, &row().provider_id, deadline())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn original_config_generation_and_deadline_are_required_during_prepare_and_publication() {
    let (_dir, store, apps) = fixture().await;
    assert!(
        store
            .prepare_registry_providers(2, deadline())
            .await
            .is_err()
    );
    assert!(
        store
            .prepare_registry_providers(1, Deadline(Instant::now() - Duration::from_secs(1)))
            .await
            .is_err()
    );
    let registry = registry(&store, apps).await;
    store.bump_config_generation().await.unwrap();
    assert!(registry.publish_prepared(&store, deadline()).await.is_err());
    assert!(
        registry
            .capture_provider_fence(&store, &row().provider_id, deadline())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn actual_ldap_compilation_qualifies_but_missing_trust_material_does_not() {
    let (dir, store, apps) = fixture().await;
    let ca = dir.path().join("ca.pem");
    let key = dir.path().join("key.pem");
    let status = std::process::Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=owned.example.test",
            "-keyout",
        ])
        .arg(&key)
        .arg("-out")
        .arg(&ca)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap();
    assert!(status.success());
    let mut ldap = row();
    ldap.provider_id = ProviderId::new("actual-directory");
    ldap.kind = ProviderKind::Ldap;
    ldap.config = serde_json::json!({"ldap":{"endpoint":"ldaps://127.0.0.1:636","ca":ca,"base_dn":"dc=example,dc=test","bind_dn":"cn=reader,dc=example,dc=test","bind_password_env":"OWNED_BIND","username_attribute":"uid","subject_attribute":"entryUUID","timeout_ms":1000}});
    store
        .import_providers(vec![ldap.clone()], None, vec![])
        .await
        .unwrap();
    let make = |prepared| {
        Arc::new(
            Registry::from_prepared(
                prepared,
                apps.clone(),
                &|name| (name == "OWNED_BIND").then(|| "owned-fixed-credential".into()),
                clock(),
                None,
            )
            .unwrap(),
        )
    };
    let registry = make(
        store
            .prepare_registry_providers(1, deadline())
            .await
            .unwrap(),
    );
    assert!(registry.credential(&ldap.provider_id).unwrap().enabled());
    registry.publish_prepared(&store, deadline()).await.unwrap();
    registry
        .capture_provider_fence(&store, &ldap.provider_id, deadline())
        .await
        .unwrap();
    std::fs::remove_file(&ca).unwrap();
    let missing = make(
        store
            .prepare_registry_providers(1, deadline())
            .await
            .unwrap(),
    );
    assert!(!missing.credential(&ldap.provider_id).unwrap().enabled());
    missing.publish_prepared(&store, deadline()).await.unwrap();
    assert!(
        missing
            .capture_provider_fence(&store, &ldap.provider_id, deadline())
            .await
            .is_err()
    );
}

#[test]
fn overlapping_check_observes_retirement_after_durable_read() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .build()
        .unwrap();
    runtime.block_on(async {
        let (_dir, store, apps) = fixture().await;
        let (_other_dir, other_store, _) = fixture().await;
        let registry = registry(&store, apps).await;
        registry.publish_prepared(&store, deadline()).await.unwrap();
        let fence = registry
            .capture_provider_fence(&store, &row().provider_id, deadline())
            .await
            .unwrap();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let blocker = tokio::task::spawn_blocking(move || {
            ready_tx.send(()).unwrap();
            release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        });
        ready_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let mut pending = Box::pin(registry.require_provider_fence(&store, &fence, deadline()));
        std::future::poll_fn(|cx| {
            assert!(std::future::Future::poll(pending.as_mut(), cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        let retiring = registry
            .require_provider_fence(&other_store, &fence, deadline())
            .await;
        release_tx.send(()).unwrap();
        blocker.await.unwrap();
        assert!(retiring.is_err());
        assert!(
            pending.await.is_err(),
            "a durable read must not revive a concurrently retired fence"
        );
    });
}

fn material_key() -> super::super::material::Key {
    super::super::material::Key::resolve(Some("OWNED_KEY"), &|_| {
        Some(data_encoding::BASE64URL_NOPAD.encode(&[0x42; 32]))
    })
    .unwrap()
}
async fn material_registry(
    store: &Store,
    apps: Arc<arc_swap::ArcSwap<crate::policy::types::ConfigSnapshot>>,
    secret: &str,
) -> Arc<Registry> {
    Arc::new(
        Registry::from_prepared_keyed(
            store
                .prepare_registry_providers(1, deadline())
                .await
                .unwrap(),
            apps,
            &|_| Some(secret.into()),
            clock(),
            None,
            Some(&material_key()),
        )
        .unwrap(),
    )
}
fn material_revision(store: &Store) -> i64 {
    store
        .conn()
        .query_row(
            "SELECT revision FROM human_provider_material_owners WHERE provider_id='actual-db'",
            [],
            |r| r.get(0),
        )
        .unwrap()
}
#[tokio::test]
async fn material_preparation_cas_rejects_stale_and_preserves_identical_overlaps() {
    let (_dir, store, apps) = fixture().await;
    let first = material_registry(&store, apps.clone(), "owned-first").await;
    let identical = material_registry(&store, apps.clone(), "owned-first").await;
    let stale = material_registry(&store, apps.clone(), "owned-old-different").await;
    first.publish_prepared(&store, deadline()).await.unwrap();
    identical
        .publish_prepared(&store, deadline())
        .await
        .unwrap();
    assert_eq!(material_revision(&store), 1);
    assert!(stale.publish_prepared(&store, deadline()).await.is_err());
    let old = material_registry(&store, apps.clone(), "owned-first").await;
    let new = material_registry(&store, apps.clone(), "owned-second").await;
    new.publish_prepared(&store, deadline()).await.unwrap();
    assert_eq!(material_revision(&store), 2);
    assert!(old.publish_prepared(&store, deadline()).await.is_err());
    let back = material_registry(&store, apps, "owned-first").await;
    back.publish_prepared(&store, deadline()).await.unwrap();
    assert_eq!(material_revision(&store), 3);
    assert!(old.publish_prepared(&store, deadline()).await.is_err());
    assert!(first.publish_prepared(&store, deadline()).await.is_err());
}
#[tokio::test]
async fn material_compiler_resolves_secret_once_and_ledger_guards_survive_reopen() {
    let (dir, store, apps) = fixture().await;
    let calls = std::sync::atomic::AtomicUsize::new(0);
    let reg = Registry::from_prepared_keyed(
        store
            .prepare_registry_providers(1, deadline())
            .await
            .unwrap(),
        apps,
        &|_| {
            assert_eq!(calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst), 0);
            Some("single-immutable-read".into())
        },
        clock(),
        None,
        Some(&material_key()),
    )
    .unwrap();
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    reg.publish_prepared(&store, deadline()).await.unwrap();
    assert_eq!(material_revision(&store), 1);
    for sql in [
        "DELETE FROM human_provider_material_owners",
        "UPDATE human_provider_material_owners SET revision=revision+1",
        "UPDATE human_provider_material_owners SET fingerprint=zeroblob(32)",
        "UPDATE human_provider_material_owners SET provider_id='replacement'",
        "INSERT INTO human_provider_material_owners VALUES('forged',7,zeroblob(32))",
    ] {
        assert!(store.conn().execute(sql, []).is_err());
    }
    drop(reg);
    drop(store);
    let reopened = Store::open(&dir.path().join("owner.db"), clock(), vec![], None).unwrap();
    assert_eq!(material_revision(&reopened), 1);
}

#[tokio::test]
async fn ldap_same_ca_path_and_bind_reference_track_consumed_material_and_disable() {
    let (dir, store, apps) = fixture().await;
    let ca = dir.path().join("trust.pem");
    let make_ca = |name: &str| {
        let cert = dir.path().join(format!("{name}.pem"));
        assert!(
            std::process::Command::new("openssl")
                .args([
                    "req",
                    "-x509",
                    "-newkey",
                    "ec",
                    "-pkeyopt",
                    "ec_paramgen_curve:P-256",
                    "-nodes",
                    "-days",
                    "1",
                    "-subj",
                    "/CN=Owned material fixture",
                    "-keyout"
                ])
                .arg(dir.path().join(format!("{name}.key")))
                .arg("-out")
                .arg(&cert)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .unwrap()
                .success()
        );
        std::fs::read(cert).unwrap()
    };
    let first = make_ca("first");
    let second = make_ca("second");
    std::fs::write(&ca, &first).unwrap();
    let mut provider = row();
    provider.kind = ProviderKind::Ldap;
    provider.client_secret_env = None;
    provider.config = serde_json::json!({"ldap":{"endpoint":"ldaps://directory.example.test","ca":ca,"base_dn":"dc=example,dc=test","bind_dn":"cn=service,dc=example,dc=test","bind_password_env":"SAME_BIND_REFERENCE","username_attribute":"uid","subject_attribute":"entryUUID","timeout_ms":1000}});
    store
        .import_providers(vec![provider], None, vec![])
        .await
        .unwrap();
    let compile = |secret: &str| {
        let secret = secret.to_owned();
        let store = store.clone();
        let apps = apps.clone();
        async move { material_registry(&store, apps, &secret).await }
    };
    let a = compile("bind-first").await;
    a.publish_prepared(&store, deadline()).await.unwrap();
    let a2 = compile("bind-first").await;
    a2.publish_prepared(&store, deadline()).await.unwrap();
    assert_eq!(material_revision(&store), 1);
    std::fs::write(&ca, &second).unwrap();
    let b = compile("bind-first").await;
    b.publish_prepared(&store, deadline()).await.unwrap();
    assert_eq!(material_revision(&store), 2);
    std::fs::write(&ca, &first).unwrap();
    let a3 = compile("bind-first").await;
    a3.publish_prepared(&store, deadline()).await.unwrap();
    assert_eq!(material_revision(&store), 3);
    let c = compile("bind-second").await;
    c.publish_prepared(&store, deadline()).await.unwrap();
    assert_eq!(material_revision(&store), 4);
    std::fs::write(&ca, b"invalid CA").unwrap();
    let disabled = compile("bind-second").await;
    assert!(
        !disabled
            .credential(&ProviderId::new("actual-db"))
            .unwrap()
            .enabled()
    );
    disabled.publish_prepared(&store, deadline()).await.unwrap();
    assert_eq!(material_revision(&store), 5);
    assert!(
        !disabled
            .owners()
            .unwrap()
            .materials
            .get()
            .unwrap()
            .contains("actual-db")
    );
}

#[tokio::test]
async fn material_publication_failure_rolls_back_and_noop_import_keeps_incarnation() {
    let (_dir, store, apps) = fixture().await;
    let a = material_registry(&store, apps.clone(), "original").await;
    a.publish_prepared(&store, deadline()).await.unwrap();
    let mut presentation = row();
    presentation.display_name = "Renamed".into();
    presentation.sort_order = 8;
    store
        .import_providers(vec![presentation], None, vec![])
        .await
        .unwrap();
    let same = material_registry(&store, apps.clone(), "original").await;
    same.publish_prepared(&store, deadline()).await.unwrap();
    assert_eq!(material_revision(&store), 1);
    let next = material_registry(&store, apps, "replacement").await;
    store.conn().execute_batch("CREATE TRIGGER owned_material_abort BEFORE UPDATE ON human_provider_material_owners BEGIN SELECT RAISE(ABORT,'owned material failure'); END;").unwrap();
    assert!(next.publish_prepared(&store, deadline()).await.is_err());
    assert_eq!(material_revision(&store), 1);
    assert!(
        !next
            .owners()
            .unwrap()
            .published
            .load(std::sync::atomic::Ordering::Acquire)
    );
    store
        .conn()
        .execute_batch("DROP TRIGGER owned_material_abort")
        .unwrap();
    next.publish_prepared(&store, deadline()).await.unwrap();
    assert_eq!(material_revision(&store), 2);
    assert!(a.publish_prepared(&store, deadline()).await.is_err());
}

#[tokio::test]
async fn material_capacity_refuses_without_partial_publication() {
    let (_dir, store, apps) = fixture().await;
    store.conn().execute_batch("WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<16384) INSERT INTO human_provider_material_owners(provider_id,revision,fingerprint) SELECT 'retired-'||x,1,NULL FROM n;").unwrap();
    let reg = material_registry(&store, apps, "owned-source").await;
    assert!(reg.publish_prepared(&store, deadline()).await.is_err());
    let count: i64 = store
        .conn()
        .query_row(
            "SELECT count(*) FROM human_provider_material_owners",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 16384);
    assert!(
        !reg.owners()
            .unwrap()
            .published
            .load(std::sync::atomic::Ordering::Acquire)
    );
}
