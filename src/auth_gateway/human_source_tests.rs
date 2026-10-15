//! Child of verify::human_tests: reuse actual owned OIDC/LDAP/TOTP native Engine.
use super::*;
use crate::auth_gateway::{
    human_source::{Configuration, Source},
    receipt::Purpose,
    receipt_authority::Authority,
    receipt_config::NativeIssuer,
    receipt_keys::Key,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use sha2::{Digest as _, Sha256};
fn native(configuration: serde_json::Value) -> NativeIssuer {
    serde_json::from_value(serde_json::json!({
        "issuer_ref":"native-human","key_epoch":1,"identity_authority_epoch":"owned-human",
        "public_key":STANDARD.encode(ed25519_dalek::SigningKey::from_bytes(&[0x45;32]).verifying_key().to_bytes()),
        "seed_env":"OWNED_HUMAN_SIGNING","scopes":[{"service":"orders","audience":"orders-api"}],
        "human_receipts":configuration
    })).unwrap()
}
fn configuration() -> serde_json::Value {
    serde_json::json!({"source_revision":7,"scopes":[{
        "service":"orders","audience":"orders-api","application":"app","route":"owned-route",
        "route_revision":11,"destination_sha256":"12".repeat(32),"header_revision":13,
        "headers":[],"reserved_headers":["x-owned-secret"],"maximum_entity_bytes":16777216
    }]})
}
fn request() -> hopae_grpc::v1::HumanFinalRequest {
    hopae_grpc::v1::HumanFinalRequest {
        binding_contract: 2,
        method: "GET".into(),
        target: "/data".into(),
        entity_sha256: Sha256::digest(b"actual final bytes").to_vec(),
        entity_length: 18,
        route_id: "owned-route".into(),
        route_revision: 11,
        destination_sha256: vec![0x12; 32],
        header_policy_revision: 13,
        headers: vec![],
    }
}
fn source(f: &Fx, configuration: serde_json::Value) -> (Source, Authority, NativeIssuer) {
    source_rng(f, configuration, f.rng.clone())
}
fn source_rng(
    f: &Fx,
    configuration: serde_json::Value,
    rng: Arc<dyn crate::crypto::Rng>,
) -> (Source, Authority, NativeIssuer) {
    let native = native(configuration);
    let issuer = Arc::new(
        native
            .load(&|_| Some(STANDARD.encode([0x45; 32])), f.clock.clone(), rng)
            .unwrap(),
    );
    let mut authority = Authority::load(&f.store.conn(), 0).unwrap();
    authority
        .reconcile(
            &mut f.store.conn(),
            &[Key {
                issuer_ref: "native-human".into(),
                purpose: Purpose::Authentication,
                epoch: 1,
                public_key: ed25519_dalek::SigningKey::from_bytes(&[0x45; 32])
                    .verifying_key()
                    .to_bytes(),
            }],
            "owned-human-fixture",
            &|_| Ok(()),
        )
        .unwrap();
    let source = Source::new(f.owner.clone(), issuer, authority.verifier(), &native).unwrap();
    (source, authority, native)
}
async fn captured(f: &Fx, cookie: &Secret) -> human::Checked {
    f.witness(cookie)
        .await
        .finish(&f.input(cookie))
        .await
        .unwrap()
}
#[tokio::test]
async fn native_human_source_actual_oidc_signed_pair_independent_observation_and_totp() {
    let f = Fx::new(None).await;
    let (cookie, view) = f.login().await;
    let (source, authority, native) = source(&f, configuration());
    let request = request();
    let binding = source.validate("orders", "orders-api", &request).unwrap();
    let policy =
        hopae_grpc::request_binding_v2::HeaderPolicy::new(13, &[], &["x-owned-secret"]).unwrap();
    let expected = hopae_grpc::request_binding_v2::digest(
        &policy,
        &hopae_grpc::request_binding_v2::Request {
            service: "orders",
            audience: "orders-api",
            route_id: "owned-route",
            route_revision: 11,
            destination_sha256: &[0x12; 32],
            method: "GET",
            target: "/data",
            body: b"actual final bytes",
            bound_headers: &[],
        },
    )
    .unwrap();
    assert_eq!(binding.sha256(), expected);
    let expected_scope = binding.scope_sha256();
    let record = source
        .issue(captured(&f, &cookie).await, binding)
        .await
        .unwrap();
    let context = record.issued().context();
    assert_eq!(
        context.identity.kind,
        crate::auth_gateway::PrincipalKind::Human
    );
    assert_eq!(context.identity.aal, 1);
    assert_eq!(context.identity.revision, view.user.authz_version);
    assert_eq!(
        context.identity.credential_generation,
        view.session.cred_gen
    );
    assert!(context.identity.subject_ref.starts_with("human1:"));
    let subject = context.identity.subject_ref.to_owned();
    let first = source
        .observe(&context, record.issued().bytes(), &expected)
        .await
        .unwrap();
    assert!(first.remaining_ms > 0 && first.remaining_ms < 1000);
    assert_eq!(first.source_revision, 7);
    assert_eq!(first.scope_sha256, expected_scope);
    assert_eq!(first.application_generation, 1);
    assert_eq!(first.key_registry_revision, 1);
    assert_eq!(
        hopae_grpc::human_epoch::decode(context.identity_authority_epoch)
            .unwrap()
            .clock_domain,
        first.clock_domain
    );
    let issuer = Arc::new(
        native
            .load(
                &|_| Some(STANDARD.encode([0x45; 32])),
                f.clock.clone(),
                f.rng.clone(),
            )
            .unwrap(),
    );
    let empty = Source::new(f.owner.clone(), issuer, authority.verifier(), &native).unwrap();
    assert!(
        empty
            .observe(&context, record.issued().bytes(), &expected)
            .await
            .is_err()
    );
    let elevated = f.elevate(&cookie).await;
    let binding = source.validate("orders", "orders-api", &request).unwrap();
    let record = source
        .issue(captured(&f, &elevated).await, binding)
        .await
        .unwrap();
    let context = record.issued().context();
    assert_eq!(context.identity.aal, 2);
    assert_eq!(context.identity.subject_ref, subject);
    assert!(context.identity.credential_generation > view.session.cred_gen);
    source
        .observe(&context, record.issued().bytes(), &expected)
        .await
        .unwrap();
}
#[tokio::test]
async fn native_human_source_withdrawal_restart_hash_scope_and_type_refuse() {
    for mode in ["user", "app", "key", "retire", "hash", "kind", "scope"] {
        let f = Fx::new(None).await;
        let (cookie, _) = f.login().await;
        let (source, mut authority, _) = source(&f, configuration());
        let binding = source.validate("orders", "orders-api", &request()).unwrap();
        let record = source
            .issue(captured(&f, &cookie).await, binding)
            .await
            .unwrap();
        let mut context = record.issued().context();
        let mut hash = context.request_sha256;
        match mode {
            "user" => f.sql("UPDATE users SET status='disabled'"),
            "app" => f.ctx.snapshot.store(Arc::new(f.config.snapshot(2))),
            "key" => {
                authority
                    .reconcile(&mut f.store.conn(), &[], "withdraw", &|_| Ok(()))
                    .unwrap();
            }
            "retire" => source.retire(),
            "hash" => hash[0] ^= 1,
            "kind" => context.identity.kind = crate::auth_gateway::PrincipalKind::Service,
            _ => context.service = "unowned",
        }
        assert!(
            source
                .observe(&context, record.issued().bytes(), &hash)
                .await
                .is_err(),
            "mode {mode}"
        );
    }
}
#[tokio::test]
async fn native_human_source_original_boottime_expiry_cannot_renew() {
    let mut f = Fx::new(None).await;
    let ticks = Arc::new(AtomicU64::new(100));
    let now = ticks.clone();
    Arc::get_mut(&mut f.owner).unwrap().ticks =
        Some(Arc::new(move || Ok(now.load(Ordering::SeqCst))));
    let (cookie, _) = f.login().await;
    let mut config = configuration();
    config["capacity"] = serde_json::json!(1);
    let (source, _, _) = source(&f, config);
    let record = source
        .issue(
            captured(&f, &cookie).await,
            source.validate("orders", "orders-api", &request()).unwrap(),
        )
        .await
        .unwrap();
    let context = record.issued().context();
    let hash = context.request_sha256;
    let first = source
        .observe(&context, record.issued().bytes(), &hash)
        .await
        .unwrap();
    ticks.store(150, Ordering::SeqCst);
    let second = source
        .observe(&context, record.issued().bytes(), &hash)
        .await
        .unwrap();
    assert!(second.remaining_ms < first.remaining_ms);
    ticks.store(2000, Ordering::SeqCst);
    assert!(
        source
            .observe(&context, record.issued().bytes(), &hash)
            .await
            .is_err()
    );
    ticks.store(2001, Ordering::SeqCst);
    assert!(
        source
            .observe(&context, record.issued().bytes(), &hash)
            .await
            .is_err()
    );
    drop(record);
    // One fresh native admission may reclaim the expired original record even
    // when its randomized shard differs from the normal cleanup cursor.
    source
        .issue(
            captured(&f, &cookie).await,
            source.validate("orders", "orders-api", &request()).unwrap(),
        )
        .await
        .unwrap();
}
#[test]
fn native_human_source_configuration_default_off_bounds_and_exact_manifest() {
    let config = native(configuration());
    assert!(config.validate().is_ok());
    assert_eq!(config.human_receipts.as_ref().unwrap().capacity, 131072);
    assert_eq!(
        config.human_receipts.as_ref().unwrap().retained_bytes,
        268435456
    );
    let raw = serde_json::json!({"issuer_ref":"owned","key_epoch":1,"identity_authority_epoch":"owned","public_key":config.public_key,"seed_env":"OWNED_SEED","scopes":[{"service":"orders","audience":"orders-api"}]});
    assert!(
        serde_json::from_value::<NativeIssuer>(raw)
            .unwrap()
            .human_receipts
            .is_none()
    );
    for (field, value) in [
        ("capacity", serde_json::json!(0)),
        ("capacity", serde_json::json!(1048577)),
        ("retained_bytes", serde_json::json!(0)),
        ("retained_bytes", serde_json::json!(17179869185u64)),
        ("source_revision", serde_json::json!(0)),
    ] {
        let mut c = configuration();
        c[field] = value;
        assert!(native(c).validate().is_err());
    }
    let mut c = configuration();
    let duplicate = c["scopes"][0].clone();
    c["scopes"].as_array_mut().unwrap().push(duplicate);
    assert!(native(c).validate().is_err());
    let mut c = configuration();
    c["scopes"][0]["headers"] = serde_json::json!(["x-owned-secret"]);
    assert!(native(c).validate().is_err());
    let mut c = configuration();
    c["scopes"][0]["destination_sha256"] = serde_json::json!("00".repeat(32));
    assert!(native(c).validate().is_err());
    let mut c = configuration();
    c["capacity"] = serde_json::json!(1048576);
    c["retained_bytes"] = serde_json::json!(17179869184u64);
    assert!(native(c).validate().is_ok());
    let _: Configuration = serde_json::from_value(configuration()).unwrap();
}

#[tokio::test]
async fn native_human_source_quota_record_loss_held_arc_and_oversize() {
    let f = Fx::new(None).await;
    let (cookie, _) = f.login().await;
    let mut config = configuration();
    config["capacity"] = serde_json::json!(1);
    let (source, _, _) = source(&f, config);
    let base = source.usage_for_test().1;
    let record = source
        .issue(
            captured(&f, &cookie).await,
            source.validate("orders", "orders-api", &request()).unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(source.usage_for_test().0, 1);
    assert!(source.usage_for_test().1 > base);
    let context = record.issued().context();
    let hash = context.request_sha256;
    source.forget_for_test(&record).unwrap();
    assert!(
        source
            .observe(&context, record.issued().bytes(), &hash)
            .await
            .is_err()
    );
    // Lookup/response Arcs retain the charge even after index removal.
    assert_eq!(source.usage_for_test().0, 1);
    assert!(
        source
            .issue(
                captured(&f, &cookie).await,
                source.validate("orders", "orders-api", &request()).unwrap()
            )
            .await
            .is_err()
    );
    drop(record);
    assert_eq!(source.usage_for_test(), (0, base));
    let record = source
        .issue(
            captured(&f, &cookie).await,
            source.validate("orders", "orders-api", &request()).unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(source.usage_for_test().0, 1);
    drop(record);
    let mut config = configuration();
    config["retained_bytes"] = serde_json::json!(base + 1);
    let (small, _, _) = self::source(&f, config);
    let small_base = small.usage_for_test().1;
    assert!(
        small
            .issue(
                captured(&f, &cookie).await,
                small.validate("orders", "orders-api", &request()).unwrap()
            )
            .await
            .is_err()
    );
    assert_eq!(small.usage_for_test(), (0, small_base));
}
#[tokio::test]
async fn native_human_source_cancelled_issuance_releases_reserved_quota() {
    let f = Fx::new(None).await;
    let (cookie, _) = f.login().await;
    let (source, _, _) = source(&f, configuration());
    let base = source.usage_for_test().1;
    let checked = captured(&f, &cookie).await;
    let binding = source.validate("orders", "orders-api", &request()).unwrap();
    let mut pending = Box::pin(source.issue(checked, binding));
    let mut reserved = false;
    for _ in 0..10000 {
        std::future::poll_fn(|cx| {
            assert!(
                std::future::Future::poll(pending.as_mut(), cx).is_pending(),
                "source completed before cancellable reserved await"
            );
            std::task::Poll::Ready(())
        })
        .await;
        if source.usage_for_test().0 == 1 {
            reserved = true;
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(reserved);
    drop(pending);
    assert_eq!(source.usage_for_test(), (0, base));
}
#[tokio::test]
async fn native_human_source_fixed_native_method_and_default_off_refuse() {
    let f = Fx::new(None).await;
    let (cookie, _) = f.login().await;
    let (source, authority, mut native) = source(&f, configuration());
    let mut descriptor = request();
    descriptor.method = "POST".into();
    let binding = source
        .validate("orders", "orders-api", &descriptor)
        .unwrap();
    assert!(
        source
            .issue(captured(&f, &cookie).await, binding)
            .await
            .is_err()
    );
    assert_eq!(source.usage_for_test().0, 0);
    native.human_receipts = None;
    let issuer = Arc::new(
        native
            .load(
                &|_| Some(STANDARD.encode([0x45; 32])),
                f.clock.clone(),
                f.rng.clone(),
            )
            .unwrap(),
    );
    assert!(Source::new(f.owner.clone(), issuer, authority.verifier(), &native).is_err());
}
#[tokio::test]
#[ignore = "requires private owned LDAP TLS fixture, executed separately"]
async fn native_human_source_actual_ldap_primary_totp_sign_and_observe() {
    let ldap = serde_json::json!({"ldap":{"endpoint":std::env::var("OWNED_LDAP_ENDPOINT").unwrap(),"starttls":std::env::var("OWNED_LDAP_STARTTLS").is_ok_and(|s|s=="1"),"ca":std::env::var("OWNED_LDAP_CA").unwrap(),"base_dn":"dc=example,dc=test","bind_dn":"cn=reader,dc=example,dc=test","bind_password_env":"OWNED_LDAP_BIND_KEY","username_attribute":"uid","subject_attribute":"entryUUID","timeout_ms":1000}});
    let f = Fx::new(Some(ldap)).await;
    let (cookie, _) = f.login().await;
    let (source, _, _) = source(&f, configuration());
    let record = source
        .issue(
            captured(&f, &cookie).await,
            source.validate("orders", "orders-api", &request()).unwrap(),
        )
        .await
        .unwrap();
    let context = record.issued().context();
    assert_eq!(context.identity.aal, 1);
    source
        .observe(&context, record.issued().bytes(), &context.request_sha256)
        .await
        .unwrap();
    let elevated = f.elevate(&cookie).await;
    assert!(
        source
            .observe(&context, record.issued().bytes(), &context.request_sha256)
            .await
            .is_err()
    );
    let record = source
        .issue(
            captured(&f, &elevated).await,
            source.validate("orders", "orders-api", &request()).unwrap(),
        )
        .await
        .unwrap();
    let context = record.issued().context();
    assert_eq!(context.identity.aal, 2);
    source
        .observe(&context, record.issued().bytes(), &context.request_sha256)
        .await
        .unwrap();
}

#[test]
fn native_human_source_actual_configuration_separate_application_and_legacy_guards() {
    let key = STANDARD.encode(
        ed25519_dalek::SigningKey::from_bytes(&[0x45; 32])
            .verifying_key()
            .to_bytes(),
    );
    let base = serde_json::json!({"state_dir":"owned-human","portal":{"public_url":"https://auth.example.test"},"gateway":{"kind":"hangang","caller_key_env":"OWNED_CALLER"},"listen":{"grpc_gateway":"127.0.0.1:0","native_gateway_tls":{"certificate":"/owned/server.pem","key":"/owned/key.pem","client_ca":"/owned/ca.pem"}},"apps":[{"app_id":"app","hosts":["app.example.test"]}],"receipt_issuer":{"issuer_ref":"native-human","key_epoch":1,"identity_authority_epoch":"owned-human","public_key":key,"seed_env":"OWNED_HUMAN_SIGNING","scopes":[{"service":"orders","audience":"orders-api"}],"human_receipts":configuration()}});
    crate::config::parse(&base.to_string()).unwrap();
    for mode in [
        "absent", "app", "service", "audience", "mtls", "grpc", "unknown",
    ] {
        let mut changed = base.clone();
        match mode {
            "absent" => {
                changed["receipt_issuer"]
                    .as_object_mut()
                    .unwrap()
                    .remove("human_receipts");
            }
            "app" => {
                changed["receipt_issuer"]["human_receipts"]["scopes"][0]["application"] =
                    "unknown".into()
            }
            "service" => {
                changed["receipt_issuer"]["human_receipts"]["scopes"][0]["service"] =
                    "unknown".into()
            }
            "audience" => {
                changed["receipt_issuer"]["human_receipts"]["scopes"][0]["audience"] =
                    "unknown".into()
            }
            "mtls" => {
                changed["listen"]
                    .as_object_mut()
                    .unwrap()
                    .remove("native_gateway_tls");
            }
            "grpc" => {
                changed["listen"]
                    .as_object_mut()
                    .unwrap()
                    .remove("grpc_gateway");
            }
            _ => {
                changed["receipt_issuer"]["human_receipts"]["raw_seed"] =
                    "reserved-secret-not-echoed".into()
            }
        }
        let Err(error) = crate::config::parse(&changed.to_string()) else {
            panic!("invalid configuration accepted: {mode}")
        };
        let error = error.to_string();
        assert!(!error.contains("reserved-secret-not-echoed"));
    }
    let mut legacy = base;
    legacy["apps"][0]["app_id"] = "orders".into();
    legacy["receipt_issuer"]
        .as_object_mut()
        .unwrap()
        .remove("human_receipts");
    crate::config::parse(&legacy.to_string()).unwrap();
}

#[tokio::test]
async fn native_human_source_signing_callback_withdrawal_cannot_publish_record() {
    struct CallbackRng {
        rng: Arc<SeededRng>,
        callback: std::sync::Mutex<Option<Box<dyn FnOnce() + Send>>>,
    }
    impl crate::crypto::Rng for CallbackRng {
        fn fill(&self, bytes: &mut [u8]) {
            self.rng.fill(bytes);
            if let Some(callback) = self.callback.lock().unwrap().take() {
                callback();
            }
        }
    }
    let f = Fx::new(None).await;
    let (cookie, _) = f.login().await;
    let rng = Arc::new(CallbackRng {
        rng: f.rng.clone(),
        callback: std::sync::Mutex::new(None),
    });
    let (source, _, _) = source_rng(&f, configuration(), rng.clone());
    let base = source.usage_for_test().1;
    let checked = captured(&f, &cookie).await;
    let snapshot = f.ctx.snapshot.clone();
    let changed = f.config.snapshot(2);
    let called = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let did_call = called.clone();
    *rng.callback.lock().unwrap() = Some(Box::new(move || {
        did_call.store(true, Ordering::Release);
        snapshot.store(Arc::new(changed));
    }));
    assert!(
        source
            .issue(
                checked,
                source.validate("orders", "orders-api", &request()).unwrap()
            )
            .await
            .is_err()
    );
    assert!(called.load(Ordering::Acquire));
    assert_eq!(source.usage_for_test(), (0, base));
}

#[tokio::test]
async fn native_human_source_final_callback_refusal_and_original_age_charge() {
    for mode in ["refuse", "cost", "publication"] {
        let mut f = Fx::new(None).await;
        let ticks = Arc::new(AtomicU64::new(100));
        let now = ticks.clone();
        Arc::get_mut(&mut f.owner).unwrap().ticks =
            Some(Arc::new(move || Ok(now.load(Ordering::Acquire))));
        let (cookie, _) = f.login().await;
        let (source, _, _) = source(&f, configuration());
        let record = source
            .issue(
                captured(&f, &cookie).await,
                source.validate("orders", "orders-api", &request()).unwrap(),
            )
            .await
            .unwrap();
        let context = record.issued().context();
        let called = std::sync::atomic::AtomicBool::new(false);
        let callback = || {
            called.store(true, Ordering::Release);
            match mode {
                "refuse" => Err(crate::auth_gateway::receipt_keys::Refused),
                "cost" => {
                    ticks.store(2000, Ordering::Release);
                    Ok(())
                }
                _ => {
                    f.ctx.snapshot.store(Arc::new(f.config.snapshot(2)));
                    Ok(())
                }
            }
        };
        assert!(
            source
                .observe_with_final(
                    &context,
                    record.issued().bytes(),
                    &context.request_sha256,
                    &callback
                )
                .await
                .is_err()
        );
        assert!(called.load(Ordering::Acquire));
    }
}

#[tokio::test]
async fn native_human_source_signed_assurance_uses_downgraded_actual_handle() {
    let f = Fx::new(None).await;
    let (cookie, _) = f.login().await;
    let elevated = f.elevate(&cookie).await;
    f.store
        .conn()
        .execute(
            "UPDATE session_handles SET issued_aal=1 WHERE handle_sha256=?1",
            [elevated.digest().0.as_slice()],
        )
        .unwrap();
    let (source, _, _) = source(&f, configuration());
    let record = source
        .issue(
            captured(&f, &elevated).await,
            source.validate("orders", "orders-api", &request()).unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(record.issued().context().identity.aal, 1);
    source
        .observe(
            &record.issued().context(),
            record.issued().bytes(),
            &record.issued().context().request_sha256,
        )
        .await
        .unwrap();
}
