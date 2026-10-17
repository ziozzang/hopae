//! Actual native witnesses checked inside the actual Store writer transaction.
use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_human_projection_same_writer_current_and_in_transaction_withdrawal() {
    let f = Fx::new(None).await;
    let (cookie, _) = f.login().await;
    let checked = Arc::new(captured(&f, &cookie).await);
    let current = checked.prepare_projection_current().unwrap();
    let retained = checked.clone();
    f.store
        .human_ledger(
            crate::store::Deadline(std::time::Instant::now() + Duration::from_secs(1)),
            move |ledger| {
                ledger.test_transaction(|snapshot| {
                    current.current_on(&retained, snapshot)?;
                    snapshot.execute_for_test("UPDATE users SET status='disabled'")?;
                    assert!(current.current_on(&retained, snapshot).is_err());
                    Ok(())
                })
            },
        )
        .await
        .unwrap();
    // A rolled-back withdrawal does not resurrect an already retired capture.
    assert!(checked.require_current_retained().await.is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_human_projection_other_store_writer_cannot_supply_current() {
    let f = Fx::new(None).await;
    let (cookie, _) = f.login().await;
    let checked = Arc::new(captured(&f, &cookie).await);
    let current = checked.prepare_projection_current().unwrap();
    let other = Fx::new(None).await;
    let retained = checked.clone();
    assert!(
        other
            .store
            .human_ledger(
                crate::store::Deadline(std::time::Instant::now() + Duration::from_secs(1)),
                move |ledger| ledger
                    .test_transaction(|snapshot| current.current_on(&retained, snapshot))
            )
            .await
            .is_err()
    );
    assert!(checked.require_current_retained().await.is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_human_projection_writer_never_calls_owner_clock_callback() {
    let mut f = Fx::new(None).await;
    let armed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let called = armed.clone();
    Arc::get_mut(&mut f.owner).unwrap().ticks = Some(Arc::new(move || {
        assert!(
            !called.load(Ordering::Acquire),
            "owner callback under native writer"
        );
        Ok(100)
    }));
    let (cookie, _) = f.login().await;
    let checked = Arc::new(captured(&f, &cookie).await);
    let current = checked.prepare_projection_current().unwrap();
    armed.store(true, Ordering::Release);
    f.store
        .human_ledger(
            crate::store::Deadline(std::time::Instant::now() + Duration::from_secs(1)),
            move |ledger| {
                ledger.test_transaction(|snapshot| {
                    current.current_on(&checked, snapshot)?;
                    current.current_on(&checked, snapshot)?;
                    Ok(())
                })
            },
        )
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_human_projection_original_elapsed_expiry_and_reversal_latch() {
    for reverse in [false, true] {
        let f = Fx::new(None).await;
        let (cookie, _) = f.login().await;
        let checked = Arc::new(captured(&f, &cookie).await);
        let mut current = checked.prepare_projection_current().unwrap();
        let elapsed = Arc::new(AtomicU64::new(10));
        current.elapsed_for_test(elapsed.clone());
        f.store
            .human_ledger(
                crate::store::Deadline(std::time::Instant::now() + Duration::from_secs(1)),
                move |ledger| {
                    ledger.test_transaction(|snapshot| {
                        current.current_on(&checked, snapshot)?;
                        // Real request Instant is still live; simulate suspend-aging or reversal.
                        elapsed.store(if reverse { 9 } else { 401 }, Ordering::Release);
                        assert!(current.current_on(&checked, snapshot).is_err());
                        elapsed.store(10, Ordering::Release);
                        assert!(current.current_on(&checked, snapshot).is_err());
                        Ok(())
                    })
                },
            )
            .await
            .unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_human_projection_post_prepare_application_and_provider_withdrawal() {
    for provider in [false, true] {
        let f = Fx::new(None).await;
        let (cookie, _) = f.login().await;
        let checked = Arc::new(captured(&f, &cookie).await);
        let current = checked.prepare_projection_current().unwrap();
        if provider {
            f.sql("UPDATE providers SET enabled=0");
        } else {
            f.ctx.snapshot.store(Arc::new(f.config.snapshot(2)));
        }
        assert!(
            f.store
                .human_ledger(
                    crate::store::Deadline(std::time::Instant::now() + Duration::from_secs(1)),
                    move |ledger| ledger
                        .test_transaction(|snapshot| current.current_on(&checked, snapshot))
                )
                .await
                .is_err()
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_human_projection_post_prepare_original_readiness_withdrawal() {
    let f = Fx::new(None).await;
    let (cookie, _) = f.login().await;
    let readiness = crate::app::Readiness::default();
    readiness.set(true);
    let admission = f
        .owner
        .capture(
            f.owner.admit(Duration::from_millis(400)).unwrap(),
            readiness.clone(),
        )
        .unwrap()
        .take(&f.owner)
        .unwrap();
    let input = f.input(&cookie);
    let (decision, _, witness) = decide_for_human(&f.ctx, &input, f.owner.clone(), admission).await;
    assert!(matches!(decision, Decision::Allow { .. }));
    let checked = Arc::new(witness.unwrap().finish(&input).await.unwrap());
    let current = checked.prepare_projection_current().unwrap();
    readiness.set(false);
    assert!(
        f.store
            .human_ledger(
                crate::store::Deadline(std::time::Instant::now() + Duration::from_secs(1)),
                move |ledger| ledger
                    .test_transaction(|snapshot| current.current_on(&checked, snapshot))
            )
            .await
            .is_err()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires private owned LDAP TLS fixture, executed separately"]
async fn native_human_projection_actual_ldap_primary_totp_same_writer() {
    let ldap = serde_json::json!({"ldap":{"endpoint":std::env::var("OWNED_LDAP_ENDPOINT").unwrap(),"starttls":std::env::var("OWNED_LDAP_STARTTLS").is_ok_and(|s|s=="1"),"ca":std::env::var("OWNED_LDAP_CA").unwrap(),"base_dn":"dc=example,dc=test","bind_dn":"cn=reader,dc=example,dc=test","bind_password_env":"OWNED_LDAP_BIND_KEY","username_attribute":"uid","subject_attribute":"entryUUID","timeout_ms":1000}});
    let f = Fx::new(Some(ldap)).await;
    let (mut cookie, _) = f.login().await;
    for aal in [1, 2] {
        if aal == 2 {
            cookie = f.elevate(&cookie).await;
        }
        let checked = Arc::new(captured(&f, &cookie).await);
        let current = checked.prepare_projection_current().unwrap();
        f.store
            .human_ledger(
                crate::store::Deadline(std::time::Instant::now() + Duration::from_secs(1)),
                move |ledger| {
                    ledger.test_transaction(|snapshot| current.current_on(&checked, snapshot))
                },
            )
            .await
            .unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_human_projection_retirement_is_observed_after_last_publication_load() {
    let f = Fx::new(None).await;
    // Built first: a fixture's setup is not charged to the capture's budget.
    let other = Fx::new(None).await;
    let (cookie, _) = f.login().await;
    let checked = Arc::new(captured(&f, &cookie).await);
    let entered = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let release = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut prepared = checked.prepare_projection_current().unwrap();
    prepared.final_latch_gate_for_test(entered.clone(), release.clone());
    let prepared = Arc::new(prepared);
    let (original, native, store) = (prepared.clone(), checked.clone(), f.store.clone());
    let pending = tokio::spawn(async move {
        store
            .human_ledger(
                crate::store::Deadline(std::time::Instant::now() + Duration::from_secs(1)),
                move |ledger| {
                    ledger.test_transaction(|snapshot| original.current_on(&native, snapshot))
                },
            )
            .await
    });
    tokio::time::timeout(Duration::from_secs(1), async {
        while !entered.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    // Another writer's wrong-owner rejection irreversibly retires this same check.
    let retired = other
        .store
        .human_ledger(
            crate::store::Deadline(std::time::Instant::now() + Duration::from_secs(1)),
            move |ledger| {
                ledger.test_transaction(|snapshot| prepared.current_on(&checked, snapshot))
            },
        )
        .await;
    release.store(true, Ordering::Release);
    assert!(retired.is_err());
    assert!(pending.await.unwrap().is_err());
}
