//! Actual FactorService -> private native command -> owning SQLite transaction.
use super::*;
use crate::factor::service::{StepUp, elevate_authorized};
use crate::store::Factors;
use std::time::Instant;
fn deadline() -> Deadline {
    Deadline(Instant::now() + Duration::from_secs(5))
}

async fn elevated(f: &Fx) -> (crate::factor::keyring::Keyring, Sess, HandleRow) {
    let (keys, session, txn, view, handle, code) =
        totp_stepup_fixture_at_generation(f, Some(1)).await;
    elevate_authorized(
        &f.store,
        &keys,
        f.clock.as_ref(),
        StepUp {
            enrollment: "elevate",
            actor: stepup_actor(f, view),
            code: &Secret::new("287082".into()),
            transaction: txn.txn_sha256,
            portal_binding: txn.portal_bind_sha256.unwrap(),
            config_generation: Some(1),
            portal_handle: handle.clone(),
            handoff: code,
            events: vec![],
        },
    )
    .await
    .unwrap();
    (keys, session, handle)
}

async fn next_elevation(f: &Fx, keys: &crate::factor::keyring::Keyring, view: HandleView) {
    let session = Sess {
        row: view.session.clone(),
        portal_digest: view.handle.handle_sha256,
    };
    let old = f.code(&session).await;
    let mut txn = new_txn(f, &random_token(&f.rng, 32), "192.0.2.10");
    txn.purpose = TxnPurpose::Stepup;
    txn.portal_session_id = Some(session.row.session_id.clone());
    txn.return_target = old.row.return_target.clone();
    txn.bind_sha256 = Some(old.row.bind_sha256);
    txn.recovery_depth = 0;
    let digest = txn.txn_sha256;
    f.store.create_transaction(txn, vec![]).await.unwrap();
    let binding = sha256(b"next-native-portal-binding");
    f.store
        .bind_totp_stepup(BindTotpStepUp {
            actor: stepup_actor(f, view.clone()),
            transaction: digest,
            portal_binding: binding,
            config_generation: Some(1),
        })
        .await
        .unwrap();
    let mut handle = f.handle_row(&session.row.session_id, PORTAL_HOST, &handle_value(&f.rng));
    handle.issued_aal = Aal::Two;
    handle.absolute_expires_at = handle
        .absolute_expires_at
        .min(view.handle.absolute_expires_at)
        .min(view.session.absolute_expires_at);
    let mut code = old.row;
    code.code_sha256 = random_token(&f.rng, 32).digest();
    code.issued_aal = Aal::Two;
    code.cred_gen = session.row.cred_gen + 1;
    elevate_authorized(
        &f.store,
        keys,
        f.clock.as_ref(),
        StepUp {
            enrollment: "elevate",
            actor: stepup_actor(f, view),
            code: &Secret::new("359152".into()),
            transaction: digest,
            portal_binding: binding,
            config_generation: Some(1),
            portal_handle: handle,
            handoff: code,
            events: vec![],
        },
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn genuine_factor_elevation_captures_exact_original_provenance_and_reads_do_not_refresh() {
    let f = fx();
    let (_, session, _) = elevated(&f).await;
    let owner = f
        .store
        .capture_totp_owner(&session.row.session_id, deadline())
        .await
        .unwrap();
    assert_eq!(f.count("SELECT count(*) FROM session_totp_provenance WHERE credential_generation=2 AND enrollment_id='elevate' AND enrollment_revision=2 AND factor_index=1 AND verified_at_ms=59000 AND config_generation=1"),1);
    let before = f
        .store
        .session(&session.row.session_id)
        .await
        .unwrap()
        .unwrap();
    f.clock.set(Timestamp(89_000));
    f.store
        .require_totp_owner(&owner, deadline())
        .await
        .unwrap();
    let after = f
        .store
        .session(&session.row.session_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(before.last_seen_at, after.last_seen_at);
    assert_eq!(before.factors, after.factors);
    assert_eq!(
        f.count("SELECT verified_at_ms FROM session_totp_provenance"),
        59000
    );
}

#[tokio::test]
async fn next_real_elevation_replaces_current_generation_without_reviving_original_owner() {
    let f = fx();
    let (keys, session, handle) = elevated(&f).await;
    let owner = f
        .store
        .capture_totp_owner(&session.row.session_id, deadline())
        .await
        .unwrap();
    f.clock.set(Timestamp(89_000));
    let view = f
        .store
        .lookup_handle(&handle.handle_sha256, &host(PORTAL_HOST))
        .await
        .unwrap()
        .unwrap();
    next_elevation(&f, &keys, view).await;
    assert!(
        f.store
            .require_totp_owner(&owner, deadline())
            .await
            .is_err()
    );
    f.store
        .capture_totp_owner(&session.row.session_id, deadline())
        .await
        .unwrap();
    assert_eq!(f.count("SELECT count(*) FROM session_totp_provenance"), 1);
    assert_eq!(
        f.count("SELECT credential_generation FROM session_totp_provenance"),
        3
    );
}

#[tokio::test]
async fn another_session_genuine_counter_advance_does_not_retire_original_owner() {
    let f = fx();
    let (keys, first, _) = elevated(&f).await;
    let owner = f
        .store
        .capture_totp_owner(&first.row.session_id, deadline())
        .await
        .unwrap();
    f.clock.set(Timestamp(89_000));
    let user = f.store.user(&first.row.user_id).await.unwrap().unwrap();
    let second = f.session(&user, vec![]).await;
    let view = f
        .store
        .lookup_handle(&second.portal_digest, &host(PORTAL_HOST))
        .await
        .unwrap()
        .unwrap();
    next_elevation(&f, &keys, view).await;
    assert_eq!(
        f.count("SELECT last_counter FROM totp_enrollments WHERE enrollment_id='elevate'"),
        2
    );
    f.store
        .require_totp_owner(&owner, deadline())
        .await
        .unwrap();
    assert_eq!(f.count("SELECT count(*) FROM session_totp_provenance"), 2);
}

#[tokio::test]
async fn actual_factor_revocation_and_session_termination_retire_original_owner() {
    for revoke in [true, false] {
        let f = fx();
        let (_, session, _) = elevated(&f).await;
        let owner = f
            .store
            .capture_totp_owner(&session.row.session_id, deadline())
            .await
            .unwrap();
        if revoke {
            f.store
                .revoke_totp("elevate", &session.row.user_id, 2, vec![])
                .await
                .unwrap();
        } else {
            f.store
                .terminate_session(
                    &session.row.session_id,
                    reasons::FACTOR_REVOKED,
                    f.now(),
                    vec![],
                )
                .await
                .unwrap();
        }
        assert!(
            f.store
                .require_totp_owner(&owner, deadline())
                .await
                .is_err()
        );
        assert!(
            f.store
                .capture_totp_owner(&session.row.session_id, deadline())
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn missing_legacy_link_and_changed_provenance_never_infer_a_current_enrollment() {
    for mutation in [
        "DELETE FROM session_totp_provenance",
        "UPDATE session_totp_provenance SET factor_index=0",
        "UPDATE session_totp_provenance SET verified_at_ms=60000",
        "UPDATE session_totp_provenance SET enrollment_revision=3",
        "UPDATE users SET status='disabled'",
        "UPDATE sessions SET cred_gen=cred_gen+1",
        "UPDATE meta SET value='2' WHERE key='config_generation'",
        "UPDATE meta SET value='1corrupt' WHERE key='config_generation'",
        "UPDATE totp_enrollments SET revision=revision+1",
        "DELETE FROM totp_enrollments",
    ] {
        let f = fx();
        let (_, session, handle) = elevated(&f).await;
        let owner = f
            .store
            .capture_totp_owner(&session.row.session_id, deadline())
            .await
            .unwrap();
        f.store.conn().execute(mutation, []).unwrap();
        assert!(
            f.store
                .require_totp_owner(&owner, deadline())
                .await
                .is_err(),
            "{mutation}"
        );
        assert!(
            f.store
                .capture_totp_owner(&session.row.session_id, deadline())
                .await
                .is_err(),
            "{mutation}"
        );
        if mutation == "DELETE FROM session_totp_provenance" {
            let view = f
                .store
                .lookup_handle(&handle.handle_sha256, &host(PORTAL_HOST))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(view.handle.issued_aal, Aal::Two);
            assert!(view.handle.revoked_at.is_none());
            assert_eq!(view.session.aal, Aal::Two); // legacy storage semantics unchanged
        }
    }
}

#[tokio::test]
async fn provenance_insert_failure_rolls_back_real_proof_challenge_and_credential_rotation() {
    let f = fx();
    let (keys, session, txn, view, handle, code) = totp_stepup_fixture(&f).await;
    f.store.conn().execute_batch("CREATE TRIGGER owned_fail_provenance BEFORE INSERT ON session_totp_provenance BEGIN SELECT RAISE(ABORT,'owned test failure'); END;").unwrap();
    assert!(
        elevate_authorized(
            &f.store,
            &keys,
            f.clock.as_ref(),
            StepUp {
                enrollment: "elevate",
                actor: stepup_actor(&f, view),
                code: &Secret::new("287082".into()),
                transaction: txn.txn_sha256,
                portal_binding: txn.portal_bind_sha256.unwrap(),
                config_generation: None,
                portal_handle: handle,
                handoff: code,
                events: vec![]
            }
        )
        .await
        .is_err()
    );
    assert_eq!(f.count("SELECT last_counter FROM totp_enrollments"), 0);
    assert_eq!(f.count("SELECT count(*) FROM session_totp_provenance"), 0);
    assert_eq!(f.count("SELECT cred_gen FROM sessions"), 1);
    assert!(
        f.store
            .transaction(&txn.txn_sha256)
            .await
            .unwrap()
            .unwrap()
            .consumed_at
            .is_none()
    );
    assert!(
        f.store
            .lookup_handle(&session.portal_digest, &host(PORTAL_HOST))
            .await
            .unwrap()
            .unwrap()
            .handle
            .revoked_at
            .is_none()
    );
}

#[tokio::test]
async fn store_identity_deadline_schema_guard_and_session_pruning_fail_closed() {
    let f = fx();
    let (_, session, _) = elevated(&f).await;
    let owner = f
        .store
        .capture_totp_owner(&session.row.session_id, deadline())
        .await
        .unwrap();
    let other = fx();
    assert!(
        other
            .store
            .require_totp_owner(&owner, deadline())
            .await
            .is_err()
    );
    assert!(
        f.store
            .require_totp_owner(&owner, Deadline(Instant::now() - Duration::from_secs(1)))
            .await
            .is_err()
    );
    f.store.conn().execute("DELETE FROM sessions", []).unwrap();
    assert_eq!(f.count("SELECT count(*) FROM session_totp_provenance"), 0);
    assert!(
        f.store
            .require_totp_owner(&owner, deadline())
            .await
            .is_err()
    );
    f.store.conn().execute_batch("DROP TABLE session_totp_provenance; CREATE TABLE session_totp_provenance(session_id TEXT PRIMARY KEY) STRICT;").unwrap();
    assert!(super::super::precheck(&f._dir.path().join("hopae.db")).is_err());
}

#[tokio::test]
async fn migration_is_atomic_and_does_not_backfill_legacy_aal2_sessions() {
    let f = fx();
    let (_, session, _) = elevated(&f).await;
    {
        let mut c = f.store.conn();
        c.execute_batch("DROP TABLE session_totp_provenance;")
            .unwrap();
        let sql = include_str!("../migrations/0008_session_totp_provenance.sql");
        {
            let tx = c.transaction().unwrap();
            tx.execute_batch(sql).unwrap();
            tx.rollback().unwrap();
        }
        assert_eq!(
            c.query_row(
                "SELECT count(*) FROM sqlite_master WHERE name='session_totp_provenance'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
        {
            let tx = c.transaction().unwrap();
            tx.execute_batch(sql).unwrap();
            tx.commit().unwrap();
        }
        assert_eq!(
            c.query_row("SELECT count(*) FROM session_totp_provenance", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }
    assert_eq!(
        f.store
            .session(&session.row.session_id)
            .await
            .unwrap()
            .unwrap()
            .aal,
        Aal::Two
    );
    assert!(
        f.store
            .capture_totp_owner(&session.row.session_id, deadline())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn native_provenance_never_overwrites_an_equal_or_ahead_generation() {
    for generation in [2, 3] {
        let f = fx();
        let (keys, session, txn, view, handle, code) = totp_stepup_fixture(&f).await;
        f.store
            .conn()
            .execute(
                "INSERT INTO session_totp_provenance VALUES(?1,?2,?3,'elevate',2,1,59000,NULL)",
                rusqlite::params![
                    session.row.session_id.as_str(),
                    session.row.user_id.as_str(),
                    generation
                ],
            )
            .unwrap();
        assert!(
            elevate_authorized(
                &f.store,
                &keys,
                f.clock.as_ref(),
                StepUp {
                    enrollment: "elevate",
                    actor: stepup_actor(&f, view),
                    code: &Secret::new("287082".into()),
                    transaction: txn.txn_sha256,
                    portal_binding: txn.portal_bind_sha256.unwrap(),
                    config_generation: None,
                    portal_handle: handle,
                    handoff: code,
                    events: vec![]
                }
            )
            .await
            .is_err()
        );
        assert_eq!(f.count("SELECT last_counter FROM totp_enrollments"), 0);
        assert_eq!(f.count("SELECT cred_gen FROM sessions"), 1);
        assert_eq!(
            f.count("SELECT credential_generation FROM session_totp_provenance"),
            generation
        );
        assert!(
            f.store
                .transaction(&txn.txn_sha256)
                .await
                .unwrap()
                .unwrap()
                .consumed_at
                .is_none()
        );
    }
}
