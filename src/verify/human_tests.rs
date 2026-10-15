//! Actual native OIDC login and owned LDAP TLS authentication through Engine capture.
#[path = "human_oidc_fixture.rs"]
mod oidc_fixture;
#[path = "../../tests/support/server.rs"]
mod server;
fn material_key() -> Option<crate::provider::material::Key> {
    crate::provider::material::Key::resolve(Some("OWNED_MATERIAL_KEY"), &|_| {
        Some(data_encoding::BASE64URL_NOPAD.encode(&[0x5au8; 32]))
    })
}

use super::*;
use crate::{
    crypto::{Clock, Secret, SeededRng, TestClock, Timestamp, handle_value, random_token},
    policy::types::Host,
    provider::{ProviderId, Registry},
    session::Aal,
    store::{Deadline, Directory, Factors, Sessions, Store, types::*},
};
use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
fn deadline() -> Deadline {
    Deadline(Instant::now() + Duration::from_secs(5))
}
struct Fx {
    _dir: tempfile::TempDir,
    store: Store,
    clock: Arc<TestClock>,
    rng: Arc<SeededRng>,
    ctx: VerifyContext,
    owner: Arc<human::Owner>,
    config: crate::config::Config,
    provider_config: serde_json::Value,
    _oidc: Option<oidc_fixture::Issuer>,
    portal: std::sync::Mutex<Option<Secret>>,
}
impl Fx {
    async fn new(ldap: Option<serde_json::Value>) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let clock = Arc::new(TestClock::new(Timestamp(59_000)));
        let rng = Arc::new(SeededRng::new(593));
        let store =
            Store::open(&dir.path().join("native.db"), clock.clone(), vec![], None).unwrap();
        store.set_rng(rng.clone());
        store.bump_config_generation().await.unwrap();
        let oidc = ldap
            .is_none()
            .then(|| oidc_fixture::Issuer::new(clock.clone()));
        let provider_config=ldap.clone().unwrap_or_else(||serde_json::json!({"client_id":"native-owned-client","issuer":oidc.as_ref().unwrap().url,"allow_private_endpoints":true}));
        let row = ProviderRow {
            provider_id: ProviderId::new("native"),
            kind: if ldap.is_some() {
                crate::provider::types::ProviderKind::Ldap
            } else {
                crate::provider::types::ProviderKind::Oidc
            },
            display_name: "Native".into(),
            enabled: true,
            managed_by: ManagedBy::Api,
            deleted_at: None,
            sort_order: 0,
            config: provider_config.clone(),
            client_secret_env: Some("OWNED_REFERENCE".into()),
            allowed_email_domains: vec![],
            authoritative_domains: vec![],
            auto_link: false,
            trust_email: false,
        };
        store
            .import_providers(vec![row], None, vec![])
            .await
            .unwrap();
        let config=crate::config::parse(&serde_json::json!({"state_dir":dir.path(),"portal":{"public_url":"https://auth.example.test"},"gateway":{"kind":"hangang","caller_key_env":"OWNED_CALLER"},"apps":[{"app_id":"app","hosts":["app.example.test"],"on_authz_change":"refresh","binding":{"ip":"strict","ua":"off","on_mismatch":"terminate_session"}}]}).to_string()).unwrap();
        let snapshot = Arc::new(arc_swap::ArcSwap::from_pointee(config.snapshot(1)));
        let registry = Arc::new(
            Registry::from_prepared_keyed(
                store
                    .prepare_registry_providers(1, deadline())
                    .await
                    .unwrap(),
                snapshot.clone(),
                &|name| {
                    if name == "OWNED_LDAP_BIND_KEY" {
                        std::env::var(name).ok()
                    } else {
                        Some("fixed-owned-reference".into())
                    }
                },
                clock.clone(),
                None,
                material_key().as_ref(),
            )
            .unwrap(),
        );
        registry.publish_prepared(&store, deadline()).await.unwrap();
        let ctx = VerifyContext::new(
            store.directory(),
            store.sessions(),
            clock.clone(),
            rng.clone(),
            snapshot.clone(),
            VerifyLimits::default(),
        );
        let owner = human::Owner::new(
            store.clone(),
            registry,
            snapshot,
            clock.clone(),
            rng.as_ref(),
        );
        Self {
            _dir: dir,
            store,
            clock,
            rng,
            ctx,
            owner,
            config,
            provider_config,
            _oidc: oidc,
            portal: std::sync::Mutex::new(None),
        }
    }
    fn input(&self, cookie: &Secret) -> VerifyInput {
        VerifyInput {
            original_url: "https://app.example.test/data".parse().unwrap(),
            canonical_path: CanonicalPath::new("/data".into()),
            client_ip: "192.0.2.10".parse().unwrap(),
            host: Host::parse("app.example.test").unwrap(),
            port: 443,
            proto: Scheme::Https,
            method: http::Method::GET,
            route_id: Some("owned-route".into()),
            cookie_handle: Some(Secret::new(cookie.expose().to_owned())),
            bind_cookie: None,
            user_agent: None,
            navigation: Navigation::Other,
            accepts_html: false,
            fetch_site: FetchSite::Unknown,
            entry_return: EntryReturn::Absent,
            handoff: Handoff::None,
            contract: 1,
            caller: CallerAuth::Keyed {
                which: KeySlot::Current,
            },
            request_id: "native-capture-test".into(),
        }
    }
    async fn login(&self) -> (Secret, HandleView) {
        let cookie = self.native_login().await;
        let view = self
            .store
            .lookup_handle(&cookie.digest(), &Host::parse("app.example.test").unwrap())
            .await
            .unwrap()
            .unwrap();
        (cookie, view)
    }
    async fn witness(&self, cookie: &Secret) -> human::Witness {
        let input = self.input(cookie);
        let (decision, _, witness) = decide_for_human(
            &self.ctx,
            &input,
            self.owner.clone(),
            self.owner.admit(Duration::from_millis(400)).unwrap(),
        )
        .await;
        assert!(
            matches!(decision, Decision::Allow { .. }),
            "native Engine did not allow"
        );
        witness.expect("ordinary Allow did not retain witness")
    }
    fn sql(&self, sql: &str) {
        self.store.conn().execute_batch(sql).unwrap();
    }
}
#[tokio::test]
async fn native_human_engine_exact_allow_and_post_refresh_expected_snapshot() {
    let f = Fx::new(None).await;
    let (cookie, _) = f.login().await;
    f.sql("UPDATE users SET authz_version=authz_version+1,display_name='Changed' WHERE user_id=(SELECT user_id FROM sessions)");
    let witness = f.witness(&cookie).await;
    assert_eq!(
        witness.view.session.authz_version,
        witness.view.user.authz_version
    );
    assert_eq!(
        witness.view.session.snapshot.display_name.as_deref(),
        Some("Changed")
    );
    let checked = witness.finish(&f.input(&cookie)).await.unwrap();
    checked.require_current(&f.input(&cookie)).await.unwrap();
}
#[tokio::test]
async fn native_human_engine_durable_withdrawals_and_provider_aba_refuse_original() {
    for mutation in [
        "UPDATE session_handles SET revoked_at=59",
        "UPDATE sessions SET terminated_at=59",
        "UPDATE users SET status='disabled'",
        "UPDATE users SET authz_version=authz_version+1",
        "UPDATE sessions SET cred_gen=cred_gen+1",
        "UPDATE providers SET enabled=0;UPDATE providers SET enabled=1",
        "MATERIAL_ABA",
        "UPDATE meta SET value='2' WHERE key='config_generation'",
    ] {
        let f = Fx::new(None).await;
        let (cookie, _) = f.login().await;
        let checked = f
            .witness(&cookie)
            .await
            .finish(&f.input(&cookie))
            .await
            .unwrap();
        if mutation == "MATERIAL_ABA" {
            f.sql("UPDATE providers SET config='{}'");
            f.store
                .conn()
                .execute(
                    "UPDATE providers SET config=?1",
                    [f.provider_config.to_string()],
                )
                .unwrap();
        } else {
            f.sql(mutation);
        }
        assert!(
            checked.require_current(&f.input(&cookie)).await.is_err(),
            "withdrawal accepted: {mutation}"
        );
    }
}
#[tokio::test]
async fn native_human_engine_scope_and_publication_failure_latch() {
    let f = Fx::new(None).await;
    let (cookie, _) = f.login().await;
    let checked = f
        .witness(&cookie)
        .await
        .finish(&f.input(&cookie))
        .await
        .unwrap();
    let mut input = f.input(&cookie);
    input.route_id = Some("other".into());
    assert!(checked.require_current(&input).await.is_err());
    assert!(checked.require_current(&f.input(&cookie)).await.is_err());
    let f = Fx::new(None).await;
    let (cookie, _) = f.login().await;
    let checked = f
        .witness(&cookie)
        .await
        .finish(&f.input(&cookie))
        .await
        .unwrap();
    let original = f.ctx.snapshot.load_full();
    f.ctx.snapshot.store(Arc::new(f.config.snapshot(1)));
    assert!(checked.require_current(&f.input(&cookie)).await.is_err());
    f.ctx.snapshot.store(original);
    assert!(checked.require_current(&f.input(&cookie)).await.is_err());
}
#[tokio::test]
async fn native_human_engine_original_suspend_wall_rollback_and_clock_failure() {
    for mode in 0..4 {
        let mut f = Fx::new(None).await;
        let ticks = Arc::new(AtomicU64::new(100));
        let read = ticks.clone();
        Arc::get_mut(&mut f.owner).unwrap().ticks = Some(Arc::new(move || {
            let n = read.load(Ordering::Acquire);
            if n == 0 {
                Err(crate::store::StoreError::Conflict("owned clock failure"))
            } else {
                Ok(n)
            }
        }));
        let (cookie, _) = f.login().await;
        let witness = f.witness(&cookie).await;
        match mode {
            0 => ticks.store(1100, Ordering::Release),
            1 => f.clock.set(Timestamp(58_000)),
            2 => ticks.store(0, Ordering::Release),
            _ => ticks.store(99, Ordering::Release),
        }
        assert!(witness.finish(&f.input(&cookie)).await.is_err());
    }
}
impl Fx {
    async fn elevate(&self, cookie: &Secret) -> Secret {
        let portal = self
            .portal
            .lock()
            .unwrap()
            .as_ref()
            .map(|secret| Secret::new(secret.expose().into()))
            .expect("actual native portal handle");
        let app = self
            .store
            .lookup_handle(&cookie.digest(), &Host::parse("app.example.test").unwrap())
            .await
            .unwrap()
            .unwrap();
        let view = self
            .store
            .lookup_handle(&portal.digest(), &Host::parse("auth.example.test").unwrap())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(app.session.session_id, view.session.session_id);
        let user = view.session.user_id.clone();
        let keys = crate::factor::keyring::Keyring::compile(
            &crate::factor::keyring::Configuration {
                active_key: "owned".into(),
                keys: vec![crate::factor::keyring::Reference {
                    id: "owned".into(),
                    key_env: "OWNED_TOTP_TEST".into(),
                }],
            },
            &|_| Some(data_encoding::BASE64URL_NOPAD.encode(&[7u8; 32])),
        )
        .unwrap();
        let seed = crate::factor::totp::Seed::from_bytes(b"12345678901234567890").unwrap();
        let envelope = keys
            .active()
            .seal(&seed, user.as_str(), "native-enrollment", self.rng.as_ref())
            .unwrap();
        self.store
            .create_totp_pending("native-enrollment".into(), user.clone(), envelope, vec![])
            .await
            .unwrap();
        self.store
            .activate_totp("native-enrollment", &user, 1, 0, vec![])
            .await
            .unwrap();
        let now = self.clock.now();
        let token = random_token(self.rng.as_ref(), 32);
        let bind = random_token(self.rng.as_ref(), 16);
        let binding = bind.digest();
        let ip = "192.0.2.10".parse().unwrap();
        let transaction = NewTransaction {
            txn_sha256: token.digest(),
            created_at: now,
            expires_at: now.add(Duration::from_secs(60)),
            app_id: crate::policy::types::AppId::new("app"),
            return_target: "https://app.example.test/data".parse().unwrap(),
            bind_sha256: Some(binding),
            portal_bind_sha256: None,
            retry_bind_sha256: None,
            client_ip: ip,
            ua_sha256: None,
            provider_id: None,
            state_sha256: None,
            nonce: None,
            pkce_verifier: None,
            portal_session_id: Some(view.session.session_id.clone()),
            purpose: TxnPurpose::Stepup,
            conflicting_handle_sha256: None,
            pending_identity: None,
            recovery_depth: 0,
            reauth_max_age: None,
        };
        self.store
            .create_transaction(transaction, vec![])
            .await
            .unwrap();
        let actor = || FactorActor {
            request_id: "native-factor".into(),
            view: view.clone(),
            provider_configuration: (
                if self.provider_config.get("ldap").is_some() {
                    crate::provider::types::ProviderKind::Ldap
                } else {
                    crate::provider::types::ProviderKind::Oidc
                },
                self.provider_config.clone(),
            ),
            client_ip: ip,
            authorized_at: now,
            session_idle: Duration::from_secs(300),
            handle_idle: Duration::from_secs(300),
        };
        self.store
            .bind_totp_stepup(BindTotpStepUp {
                actor: actor(),
                transaction: token.digest(),
                portal_binding: binding,
                config_generation: Some(self.ctx.snapshot.load().generation),
            })
            .await
            .unwrap();
        let fresh = handle_value(self.rng.as_ref());
        let mut handle = view.handle.clone();
        handle.handle_sha256 = fresh.digest();
        handle.issued_aal = Aal::Two;
        handle.created_at = now;
        handle.last_seen_at = now;
        let code_secret = random_token(self.rng.as_ref(), 32);
        let code = HandoffCodeRow {
            code_sha256: code_secret.digest(),
            session_id: view.session.session_id.clone(),
            host: Host::parse("app.example.test").unwrap(),
            return_target: "https://app.example.test/data".parse().unwrap(),
            client_ip: ip,
            bind_sha256: binding,
            issued_aal: Aal::Two,
            cred_gen: view.session.cred_gen + 1,
            recovery_depth: 0,
            created_at: now,
            expires_at: now.add(Duration::from_secs(30)),
            consumed_at: None,
            consumed_reason: None,
        };
        crate::factor::service::elevate_authorized(
            &self.store,
            &keys,
            self.clock.as_ref(),
            crate::factor::service::StepUp {
                enrollment: "native-enrollment",
                actor: actor(),
                code: &Secret::new("287082".into()),
                transaction: token.digest(),
                portal_binding: binding,
                config_generation: Some(self.ctx.snapshot.load().generation),
                portal_handle: handle,
                handoff: code,
                events: vec![],
            },
        )
        .await
        .unwrap();
        *self.portal.lock().unwrap() = Some(fresh);
        let target = "https://app.example.test/data".parse().unwrap();
        let location = crate::session::handoff::landing_location(&target, code_secret.expose());
        self.redeem(location, &bind).await
    }
}
#[tokio::test]
async fn native_human_engine_real_totp_provenance_and_revocation() {
    let f = Fx::new(None).await;
    let (old, _) = f.login().await;
    let cookie = f.elevate(&old).await;
    let witness = f.witness(&cookie).await;
    assert_eq!(witness.view.handle.issued_aal, Aal::Two);
    let checked = witness.finish(&f.input(&cookie)).await.unwrap();
    f.sql("UPDATE totp_enrollments SET last_counter=last_counter+1");
    checked.require_current(&f.input(&cookie)).await.unwrap();
    f.sql("UPDATE totp_enrollments SET state='revoked',revision=revision+1");
    assert!(checked.require_current(&f.input(&cookie)).await.is_err());
}
#[tokio::test]
async fn native_human_engine_legacy_and_newer_unsupported_factor_cannot_supply_provenance_or_freshness()
 {
    for mutation in [
        "DELETE FROM session_totp_provenance",
        "UPDATE session_totp_provenance SET verified_at_ms=58000",
        "UPDATE session_totp_provenance SET enrollment_revision=enrollment_revision+1",
    ] {
        let f = Fx::new(None).await;
        let (old, _) = f.login().await;
        let cookie = f.elevate(&old).await;
        f.sql(mutation);
        assert!(matches!(
            decide(&f.ctx, f.input(&cookie)).await,
            Decision::Allow { .. }
        ));
        let (decision, _, witness) = decide_for_human(
            &f.ctx,
            &f.input(&cookie),
            f.owner.clone(),
            f.owner.admit(Duration::from_millis(400)).unwrap(),
        )
        .await;
        assert!(!matches!(decision, Decision::Allow { .. }));
        assert!(witness.is_none());
    }
    let f = Fx::new(None).await;
    let (old, _) = f.login().await;
    let cookie = f.elevate(&old).await;
    let mut snapshot = f.config.snapshot(1);
    snapshot.apps[0].step_up = vec![crate::policy::types::StepUpRule {
        path_prefix: None,
        aal: Aal::Two,
        max_age: Some(Duration::from_secs(1)),
    }];
    // Reprepare the real registry for this exact native app publisher.
    let apps = Arc::new(arc_swap::ArcSwap::from_pointee(snapshot));
    let registry = Arc::new(
        Registry::from_prepared_keyed(
            f.store
                .prepare_registry_providers(1, deadline())
                .await
                .unwrap(),
            apps.clone(),
            &|_| Some("fixed-owned-reference".into()),
            f.clock.clone(),
            None,
            material_key().as_ref(),
        )
        .unwrap(),
    );
    registry
        .publish_prepared(&f.store, deadline())
        .await
        .unwrap();
    let owner = human::Owner::new(
        f.store.clone(),
        registry,
        apps.clone(),
        f.clock.clone(),
        f.rng.as_ref(),
    );
    let mut ctx = f.ctx.clone();
    ctx.snapshot = apps;
    f.clock.set(Timestamp(61_000));
    f.sql("UPDATE sessions SET factors=json_insert(factors,'$[#]',json('{\"kind\":\"external\",\"at\":61000}'))");
    assert!(matches!(
        decide(&ctx, f.input(&cookie)).await,
        Decision::Allow { .. }
    ));
    let (decision, _, witness) = decide_for_human(
        &ctx,
        &f.input(&cookie),
        owner.clone(),
        owner.admit(Duration::from_millis(400)).unwrap(),
    )
    .await;
    assert!(!matches!(decision, Decision::Allow { .. }));
    assert!(witness.is_none());
}
#[tokio::test]
#[ignore = "requires private owned LDAP TLS fixture, executed separately"]
async fn native_human_owned_ldap_login_totp_engine_capture() {
    let ldap = serde_json::json!({"ldap":{"endpoint":std::env::var("OWNED_LDAP_ENDPOINT").unwrap(),"starttls":std::env::var("OWNED_LDAP_STARTTLS").is_ok_and(|s|s=="1"),"ca":std::env::var("OWNED_LDAP_CA").unwrap(),"base_dn":"dc=example,dc=test","bind_dn":"cn=reader,dc=example,dc=test","bind_password_env":"OWNED_LDAP_BIND_KEY","username_attribute":"uid","subject_attribute":"entryUUID","timeout_ms":1000}});
    let f = Fx::new(Some(ldap)).await;
    let cookie = f.native_login().await;
    let aal1 = f.witness(&cookie).await;
    assert_eq!(aal1.view.handle.issued_aal, Aal::One);
    aal1.finish(&f.input(&cookie)).await.unwrap();
    let cookie = f.elevate(&cookie).await;
    let checked = f
        .witness(&cookie)
        .await
        .finish(&f.input(&cookie))
        .await
        .unwrap();
    checked.require_current(&f.input(&cookie)).await.unwrap();
    assert_gateway_capture(&f, &cookie).await;
}
async fn assert_gateway_capture(f: &Fx, cookie: &Secret) {
    use tower::ServiceExt;
    let state = crate::http::gateway::GatewayState::new(
        crate::gateway::hangang::GatewayConfig::from_config(&f.config),
        f.ctx.clone(),
        Arc::new(crate::app::CallerKeys::new(
            Some(Secret::new("native-owned-gateway-key".into())),
            None,
            false,
        )),
        8,
        None,
        None,
    )
    .with_human_owner(f.owner.clone())
    .unwrap();
    let app = crate::http::gateway::router(state);
    let request = |marker: bool, key: &str| {
        let mut request = http::Request::builder()
            .uri(crate::gateway::hangang::VERIFY_PATH)
            .header("x-hopae-gateway-key", key)
            .header("x-hopae-contract", "1")
            .header("x-original-url", "https://app.example.test/data")
            .header("x-forwarded-proto", "https")
            .header("x-forwarded-host", "app.example.test")
            .header("x-forwarded-for", "192.0.2.10")
            .header("x-original-method", "GET")
            .header("x-hangang-canonical-path", "/data")
            .header("x-hangang-route-id", "owned-route")
            .header("cookie", format!("__Host-hopae={}", cookie.expose()))
            .body(axum::body::Body::empty())
            .unwrap();
        if marker {
            let readiness = crate::app::Readiness::default();
            readiness.set(true);
            request.extensions_mut().insert(
                f.owner
                    .capture(f.owner.admit(f.ctx.limits.budget).unwrap(), readiness)
                    .unwrap(),
            );
        }
        request
    };
    let ordinary = app
        .clone()
        .oneshot(request(false, "native-owned-gateway-key"))
        .await
        .unwrap();
    assert!(ordinary.status().is_success());
    assert!(ordinary.extensions().get::<Arc<human::Checked>>().is_none());
    let unauthorized = app.clone().oneshot(request(true, "wrong")).await.unwrap();
    assert!(!unauthorized.status().is_success());
    assert!(
        unauthorized
            .extensions()
            .get::<Arc<human::Checked>>()
            .is_none()
    );
    let mut mixed = request(true, "native-owned-gateway-key");
    let original = mixed.extensions().get::<human::Capture>().unwrap().clone();
    let workload_owner = crate::auth_gateway::workload_owner::Owner::new(
        crate::auth_gateway::workload_owner::Configuration {
            scopes: vec![],
            capacity: 1,
        },
        [0x31; 16],
    )
    .unwrap();
    mixed
        .extensions_mut()
        .insert(workload_owner.begin(f.clock.as_ref()).unwrap());
    let refused = app.clone().oneshot(mixed).await.unwrap();
    assert_eq!(refused.status(), http::StatusCode::SERVICE_UNAVAILABLE);
    assert!(refused.extensions().get::<Arc<human::Checked>>().is_none());
    // Collision is rejected before admission consumption or any native Engine bind.
    assert!(original.take(&f.owner).is_ok());
    let captured = app
        .oneshot(request(true, "native-owned-gateway-key"))
        .await
        .unwrap();
    assert!(captured.status().is_success());
    assert!(captured.extensions().get::<Arc<human::Checked>>().is_some());
}
#[tokio::test]
async fn native_human_engine_owning_gateway_marker_and_caller_gate() {
    let f = Fx::new(None).await;
    let (cookie, _) = f.login().await;
    assert_gateway_capture(&f, &cookie).await;
}
struct CallbackClock {
    base: Arc<TestClock>,
    callback: std::sync::Mutex<Option<Box<dyn FnOnce() + Send>>>,
}
impl Clock for CallbackClock {
    fn now(&self) -> Timestamp {
        let callback = self.callback.lock().unwrap().take();
        if let Some(callback) = callback {
            callback();
        }
        self.base.now()
    }
}
#[tokio::test]
async fn native_human_engine_clock_callback_withdrawal_precedes_joined_current_read() {
    let mut f = Fx::new(None).await;
    let (cookie, _) = f.login().await;
    let clock = Arc::new(CallbackClock {
        base: f.clock.clone(),
        callback: std::sync::Mutex::new(None),
    });
    f.ctx.clock = clock.clone();
    f.owner = human::Owner::new(
        f.store.clone(),
        f.owner.registry.clone(),
        f.ctx.snapshot.clone(),
        clock.clone(),
        f.rng.as_ref(),
    );
    let checked = f
        .witness(&cookie)
        .await
        .finish(&f.input(&cookie))
        .await
        .unwrap();
    let store = f.store.clone();
    *clock.callback.lock().unwrap() = Some(Box::new(move || {
        store
            .conn()
            .execute("UPDATE users SET status='disabled'", [])
            .unwrap();
    }));
    assert!(checked.require_current(&f.input(&cookie)).await.is_err());
}
#[test]
fn native_human_engine_cancellation_and_original_queue_deadline_fail_closed() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .build()
        .unwrap();
    runtime.block_on(async {
        let f = Fx::new(None).await;
        let (cookie, _) = f.login().await;
        let input = f.input(&cookie);
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let blocker = tokio::task::spawn_blocking(move || {
            ready_tx.send(()).unwrap();
            release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        });
        ready_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let mut cancelled = Box::pin(decide_for_human(
            &f.ctx,
            &input,
            f.owner.clone(),
            f.owner.admit(Duration::from_millis(400)).unwrap(),
        ));
        std::future::poll_fn(|cx| {
            assert!(std::future::Future::poll(cancelled.as_mut(), cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        drop(cancelled);
        let admission = f.owner.admit(Duration::from_millis(20)).unwrap();
        tokio::time::sleep(Duration::from_millis(25)).await;
        release_tx.send(()).unwrap();
        blocker.await.unwrap();
        let (decision, _, witness) =
            decide_for_human(&f.ctx, &input, f.owner.clone(), admission).await;
        assert!(!matches!(decision, Decision::Allow { .. }));
        assert!(witness.is_none());
        // Cancellation did not install a result or consume the original handle.
        assert!(matches!(
            decide(&f.ctx, f.input(&cookie)).await,
            Decision::Allow { .. }
        ));
    });
}
impl Fx {
    fn service(&self) -> crate::session::service::Service {
        use crate::session::service::{Deps, Service, ServiceConfig};
        let (bus, _receiver) = crate::event::bus::channel(128);
        let emitter = crate::event::bus::Emitter::new(
            self.clock.clone(),
            self.rng.clone(),
            bus,
            Arc::new(crate::event::sampling::Sampler::default()),
            Arc::new(crate::event::prune::PruneTrigger::new(1000)),
            false,
        );
        Service::new(Deps {
            directory: self.store.directory(),
            sessions: self.store.sessions(),
            events: self.store.events(),
            emitter,
            clock: self.clock.clone(),
            rng: self.rng.clone(),
            snapshot: self.ctx.snapshot.clone(),
            providers: self.owner.registry.clone(),
            config: ServiceConfig::from_config(&self.config).unwrap(),
        })
        .with_native_primary(self.store.clone(), self.owner.registry.clone())
    }
    async fn native_login(&self) -> Secret {
        self.try_native_login(None)
            .await
            .expect("native source login failed")
    }
    async fn try_native_login(
        &self,
        old: Option<&Secret>,
    ) -> Result<Secret, crate::session::service::SessionError> {
        use crate::provider::credentials::PasswordInput;
        use crate::session::service::{CallbackOutcome, PasswordCompletion, RequestCtx};
        let service = self.service();
        let bind = random_token(self.rng.as_ref(), 16);
        let mut input = self.input(&handle_value(self.rng.as_ref()));
        input.cookie_handle = old.map(|cookie| Secret::new(cookie.expose().into()));
        input.navigation = Navigation::Document;
        input.bind_cookie = Some(Secret::new(bind.expose().into()));
        let Decision::Login {
            transaction: Some(transaction),
            ..
        } = decide(&self.ctx, input).await
        else {
            panic!("native login transaction not issued")
        };
        let portal_binding = random_token(self.rng.as_ref(), 16);
        let id = ProviderId::new("native");
        let request = RequestCtx {
            client_ip: "192.0.2.10".parse().unwrap(),
            user_agent: None,
            request_id: "owned-native-human".into(),
            client_request_id: None,
        };
        let prior_portal = if old.is_some() {
            self.portal
                .lock()
                .unwrap()
                .as_ref()
                .map(|secret| Secret::new(secret.expose().into()))
        } else {
            None
        };
        let outcome = if self._oidc.is_some() {
            let location = service
                .begin_provider(&request, &transaction, &id, Some(&portal_binding))
                .await
                .unwrap();
            let client = reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap();
            let response = client.get(location).send().await.unwrap();
            assert_eq!(response.status(), http::StatusCode::TEMPORARY_REDIRECT);
            let callback = url::Url::parse(
                response
                    .headers()
                    .get("location")
                    .unwrap()
                    .to_str()
                    .unwrap(),
            )
            .unwrap();
            let pairs: std::collections::HashMap<_, _> = callback
                .query_pairs()
                .map(|(k, v)| (k.into_owned(), v.into_owned()))
                .collect();
            service
                .complete_callback(
                    &request,
                    &id,
                    crate::provider::CallbackQuery {
                        code: pairs.get("code").cloned(),
                        state: pairs.get("state").cloned(),
                        error: None,
                        error_description: None,
                    },
                    Some(&portal_binding),
                    prior_portal.as_ref(),
                )
                .await?
        } else {
            let challenge = service
                .begin_password(&request, &transaction, &id, Some(&portal_binding))
                .await
                .unwrap();
            let password = Secret::new(std::env::var("OWNED_LDAP_USER_PASSWORD").unwrap());
            service
                .complete_password(
                    &request,
                    PasswordCompletion {
                        provider_id: &id,
                        challenge: &challenge,
                        input: PasswordInput::new("alice", &password).unwrap(),
                        portal_cookie: Some(&portal_binding),
                        portal_handle: prior_portal.as_ref(),
                    },
                )
                .await?
        };
        let CallbackOutcome::LoggedIn {
            location,
            portal_handle,
            ..
        } = outcome
        else {
            panic!("native provider did not complete login")
        };
        if let Some(handle) = portal_handle {
            *self.portal.lock().unwrap() = Some(handle.value);
        }
        Ok(self.redeem(location, &bind).await)
    }
    async fn redeem(&self, location: url::Url, bind: &Secret) -> Secret {
        let cfg = crate::gateway::hangang::GatewayConfig::from_config(&self.config);
        let headers = http::Request::builder()
            .header("x-hopae-gateway-key", "native-owned-gateway-key")
            .header("x-hopae-contract", "1")
            .header("x-original-url", location.as_str())
            .header("x-hangang-canonical-path", location.path())
            .header("x-original-method", "GET")
            .header("x-forwarded-host", "app.example.test")
            .header("x-forwarded-proto", "https")
            .header("x-forwarded-for", "192.0.2.10")
            .header("accept", "text/html")
            .header("cookie", format!("{}={}", cfg.cookies.bind, bind.expose()))
            .body(())
            .unwrap()
            .into_parts()
            .0
            .headers;
        let callers = crate::app::CallerKeys::new(
            Some(Secret::new("native-owned-gateway-key".into())),
            None,
            false,
        );
        let caller = crate::gateway::hangang::authenticate(&callers, &headers, "native-handoff")
            .unwrap_or_else(|_| panic!("owning caller refused"));
        let redeem =
            crate::gateway::hangang::parse(&cfg, &headers, "native-handoff".into(), caller)
                .unwrap_or_else(|_| panic!("owning handoff parse refused"))
                .input;
        let Decision::Handoff { handle: cookie, .. } = decide(&self.ctx, redeem).await else {
            panic!("native handoff did not issue app handle")
        };
        cookie
    }
}
impl Fx {
    async fn republish(&mut self, generation: u64, max_auth_age: Option<Duration>) {
        let mut snapshot = self.config.snapshot(generation);
        snapshot.apps[0].max_auth_age = max_auth_age;
        self.publish_snapshot(snapshot).await;
    }
    async fn publish_snapshot(&mut self, snapshot: crate::policy::types::ConfigSnapshot) {
        self.publish_material_snapshot(snapshot, "fixed-owned-reference")
            .await;
    }
    async fn publish_material_snapshot(
        &mut self,
        snapshot: crate::policy::types::ConfigSnapshot,
        secret: &str,
    ) {
        let generation = snapshot.generation;
        let applications = Arc::new(arc_swap::ArcSwap::from_pointee(snapshot));
        let registry = Arc::new(
            Registry::from_prepared_keyed(
                self.store
                    .prepare_registry_providers(generation, deadline())
                    .await
                    .unwrap(),
                applications.clone(),
                &|name| {
                    if name == "OWNED_LDAP_BIND_KEY" {
                        std::env::var(name).ok()
                    } else {
                        Some(secret.into())
                    }
                },
                self.clock.clone(),
                None,
                material_key().as_ref(),
            )
            .unwrap(),
        );
        registry
            .publish_prepared(&self.store, deadline())
            .await
            .unwrap();
        self.ctx.snapshot = applications.clone();
        self.owner = human::Owner::new(
            self.store.clone(),
            registry,
            applications,
            self.clock.clone(),
            self.rng.as_ref(),
        );
    }
    fn count(&self, sql: &str) -> i64 {
        self.store.conn().query_row(sql, [], |r| r.get(0)).unwrap()
    }
    async fn assert_unqualified(&self, cookie: &Secret) {
        let (decision, _, witness) = decide_for_human(
            &self.ctx,
            &self.input(cookie),
            self.owner.clone(),
            self.owner.admit(Duration::from_millis(400)).unwrap(),
        )
        .await;
        assert!(!matches!(decision, Decision::Allow { .. }));
        assert!(witness.is_none());
    }
}
#[tokio::test]
async fn native_human_engine_primary_legacy_and_new_registry_cannot_relabel_old_authentication() {
    let mut f = Fx::new(None).await;
    let (cookie, _) = f.login().await;
    assert_eq!(
        f.count("SELECT count(*) FROM session_primary_provenance"),
        1
    );
    f.sql("UPDATE providers SET enabled=0;UPDATE providers SET enabled=1");
    f.republish(1, None).await;
    assert!(matches!(
        decide(&f.ctx, f.input(&cookie)).await,
        Decision::Allow { .. }
    ));
    f.assert_unqualified(&cookie).await;
    let f = Fx::new(None).await;
    let (cookie, _) = f.login().await;
    f.sql("DELETE FROM session_primary_provenance");
    assert!(matches!(
        decide(&f.ctx, f.input(&cookie)).await,
        Decision::Allow { .. }
    ));
    f.assert_unqualified(&cookie).await;
    assert_eq!(
        f.count("SELECT count(*) FROM session_primary_provenance"),
        0
    );
}
#[tokio::test]
async fn native_human_engine_restart_generation_requires_actual_native_primary_reauthentication() {
    let mut f = Fx::new(None).await;
    let (cookie, original) = f.login().await;
    let checked = f
        .witness(&cookie)
        .await
        .finish(&f.input(&cookie))
        .await
        .unwrap();
    assert_eq!(f.store.bump_config_generation().await.unwrap(), 2);
    f.republish(2, Some(Duration::from_secs(1800))).await;
    f.clock.set(Timestamp(1_860_000));
    assert!(checked.require_current(&f.input(&cookie)).await.is_err());
    let cookie = f.try_native_login(Some(&cookie)).await.unwrap();
    let view = f
        .store
        .lookup_handle(&cookie.digest(), &Host::parse("app.example.test").unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(view.session.session_id, original.session.session_id);
    assert_eq!(view.session.cred_gen, 2);
    assert_eq!(view.session.auth_time, Timestamp(1_860_000));
    assert_eq!(
        f.count("SELECT credential_generation FROM session_primary_provenance"),
        2
    );
    assert_eq!(
        f.count("SELECT config_generation FROM session_primary_provenance"),
        2
    );
    f.witness(&cookie)
        .await
        .finish(&f.input(&cookie))
        .await
        .unwrap();
}
#[tokio::test]
async fn native_human_engine_primary_withdrawal_during_actual_token_verification_rolls_back() {
    for mode in 0..4 {
        let f = Fx::new(None).await;
        let store = f.store.clone();
        let config = f.provider_config.clone();
        f._oidc.as_ref().unwrap().on_token(move || match mode {
            0 => {
                store
                    .conn()
                    .execute_batch("UPDATE providers SET enabled=0;UPDATE providers SET enabled=1")
                    .unwrap();
            }
            1 => {
                store
                    .conn()
                    .execute("UPDATE providers SET config='{}'", [])
                    .unwrap();
                store
                    .conn()
                    .execute("UPDATE providers SET config=?1", [config.to_string()])
                    .unwrap();
            }
            2 => {
                store
                    .conn()
                    .execute(
                        "UPDATE meta SET value='2' WHERE key='config_generation'",
                        [],
                    )
                    .unwrap();
            }
            _ => {
                store.conn().execute("UPDATE human_provider_material_owners SET revision=revision+1,fingerprint=zeroblob(32)",[]).unwrap();
            }
        });
        let result = f.try_native_login(None).await;
        assert!(
            matches!(
                result,
                Err(crate::session::service::SessionError::Refused(
                    crate::event::types::reasons::TXN_CONSUMED
                ))
            ),
            "withdrawn source did not fail native owning session commit"
        );
        assert_eq!(f.count("SELECT count(*) FROM sessions"), 0);
        assert_eq!(
            f.count("SELECT count(*) FROM session_primary_provenance"),
            0
        );
        assert_eq!(
            f.count("SELECT count(*) FROM login_txns WHERE consumed_at IS NOT NULL"),
            0
        );
    }
}
#[tokio::test]
async fn native_human_engine_primary_insert_failure_rolls_back_session_and_login_consumption() {
    let f = Fx::new(None).await;
    f.sql("CREATE TRIGGER owned_primary_abort BEFORE INSERT ON session_primary_provenance BEGIN SELECT RAISE(ABORT,'owned primary insertion failure'); END;");
    assert!(matches!(
        f.try_native_login(None).await,
        Err(crate::session::service::SessionError::Refused(
            crate::event::types::reasons::TXN_CONSUMED
        ))
    ));
    assert_eq!(f.count("SELECT count(*) FROM sessions"), 0);
    assert_eq!(
        f.count("SELECT count(*) FROM session_primary_provenance"),
        0
    );
    assert_eq!(
        f.count("SELECT count(*) FROM login_txns WHERE consumed_at IS NOT NULL"),
        0
    );
}
#[tokio::test]
async fn native_human_engine_primary_ahead_generation_cannot_be_overwritten_by_reauthentication() {
    let mut f = Fx::new(None).await;
    let (cookie, original) = f.login().await;
    f.store.bump_config_generation().await.unwrap();
    f.republish(2, Some(Duration::from_secs(1800))).await;
    f.clock.set(Timestamp(1_860_000));
    f.sql("UPDATE session_primary_provenance SET credential_generation=2");
    assert!(f.try_native_login(Some(&cookie)).await.is_err());
    let session = f
        .store
        .session(&original.session.session_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(session.cred_gen, 1);
    assert_eq!(session.auth_time, Timestamp(59_000));
    assert_eq!(
        f.count("SELECT credential_generation FROM session_primary_provenance"),
        2
    );
    assert_eq!(
        f.count("SELECT count(*) FROM session_handles WHERE revoked_at IS NOT NULL"),
        0
    );
}
#[tokio::test]
async fn native_human_engine_primary_schema_guard_and_subject_link_withdrawal() {
    let f = Fx::new(None).await;
    let (cookie, _) = f.login().await;
    let checked = f
        .witness(&cookie)
        .await
        .finish(&f.input(&cookie))
        .await
        .unwrap();
    f.sql("DELETE FROM identities");
    assert!(checked.require_current(&f.input(&cookie)).await.is_err());
    f.sql("DROP TABLE session_primary_provenance;CREATE TABLE session_primary_provenance(session_id TEXT PRIMARY KEY) STRICT;");
    assert!(crate::store::sqlite::validate_foundation(&f.store.conn(), 9).is_err());
}
#[test]
fn native_human_engine_overlapping_current_check_cannot_return_after_retirement() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .build()
        .unwrap();
    runtime.block_on(async {
        let f = Fx::new(None).await;
        let (cookie, _) = f.login().await;
        let input = f.input(&cookie);
        let checked = f.witness(&cookie).await.finish(&input).await.unwrap();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let blocker = tokio::task::spawn_blocking(move || {
            ready_tx.send(()).unwrap();
            release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        });
        ready_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let mut pending = Box::pin(checked.require_current_retained());
        std::future::poll_fn(|cx| {
            assert!(std::future::Future::poll(pending.as_mut(), cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        let mut wrong = f.input(&cookie);
        wrong.route_id = Some("retire-sibling".into());
        let retiring = checked.require_current(&wrong).await;
        release_tx.send(()).unwrap();
        blocker.await.unwrap();
        assert!(retiring.is_err());
        assert!(pending.await.is_err());
    });
}
#[tokio::test]
async fn native_human_engine_cold_store_reopen_and_new_owner_do_not_adopt_old_primary() {
    let f = Fx::new(None).await;
    let (cookie, _) = f.login().await;
    let ordinary = f.input(&cookie);
    let captured = f.input(&cookie);
    let Fx {
        _dir,
        store,
        clock,
        rng,
        ctx,
        owner,
        config,
        provider_config: _,
        _oidc,
        portal: _,
    } = f;
    drop(owner);
    drop(ctx);
    drop(store);
    let store = Store::open(&_dir.path().join("native.db"), clock.clone(), vec![], None).unwrap();
    assert_eq!(store.bump_config_generation().await.unwrap(), 2);
    let applications = Arc::new(arc_swap::ArcSwap::from_pointee(config.snapshot(2)));
    let registry = Arc::new(
        Registry::from_prepared_keyed(
            store
                .prepare_registry_providers(2, deadline())
                .await
                .unwrap(),
            applications.clone(),
            &|_| Some("fixed-owned-reference".into()),
            clock.clone(),
            None,
            material_key().as_ref(),
        )
        .unwrap(),
    );
    registry.publish_prepared(&store, deadline()).await.unwrap();
    let ctx = VerifyContext::new(
        store.directory(),
        store.sessions(),
        clock.clone(),
        rng.clone(),
        applications.clone(),
        VerifyLimits::default(),
    );
    let owner = human::Owner::new(store.clone(), registry, applications, clock, rng.as_ref());
    assert!(matches!(
        decide(&ctx, ordinary).await,
        Decision::Allow { .. }
    ));
    let (decision, _, witness) = decide_for_human(
        &ctx,
        &captured,
        owner.clone(),
        owner.admit(Duration::from_millis(400)).unwrap(),
    )
    .await;
    assert!(!matches!(decision, Decision::Allow { .. }));
    assert!(witness.is_none());
    assert_eq!(
        store
            .conn()
            .query_row(
                "SELECT config_generation FROM session_primary_provenance",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        1
    );
    drop(_oidc);
}
#[tokio::test]
async fn native_human_engine_legacy_primary_reauthentication_retires_even_equal_time_provenance() {
    let f = Fx::new(None).await;
    let (_, view) = f.login().await;
    let now = f.clock.now();
    let token = random_token(f.rng.as_ref(), 32);
    let transaction = NewTransaction {
        txn_sha256: token.digest(),
        created_at: now,
        expires_at: now.add(Duration::from_secs(60)),
        app_id: crate::policy::types::AppId::new("app"),
        return_target: "https://app.example.test/data".parse().unwrap(),
        bind_sha256: Some(crate::crypto::sha256(b"owned-legacy-primary-bind")),
        portal_bind_sha256: None,
        retry_bind_sha256: None,
        client_ip: view.session.bound_ip,
        ua_sha256: None,
        provider_id: None,
        state_sha256: None,
        nonce: None,
        pkce_verifier: None,
        portal_session_id: Some(view.session.session_id.clone()),
        purpose: TxnPurpose::Login,
        conflicting_handle_sha256: None,
        pending_identity: None,
        recovery_depth: 0,
        reauth_max_age: Some(1800),
    };
    f.store
        .create_transaction(transaction, vec![])
        .await
        .unwrap();
    let mut handle = view.handle.clone();
    handle.handle_sha256 = handle_value(f.rng.as_ref()).digest();
    handle.host = Host::parse("auth.example.test").unwrap();
    let factor = view.session.factors[0].clone();
    f.store
        .reauthenticate_session(
            &view.session.session_id,
            &view.session.provider_id,
            None,
            view.session.auth_time,
            view.session.auth_time_source,
            factor,
            handle,
            (token.digest(), crate::event::types::reasons::REAUTH),
            deadline(),
            vec![],
            &|_| {
                crate::event::types::EventBuilder::new(
                    f.clock.as_ref(),
                    f.rng.as_ref(),
                    crate::event::types::EventKind::HandleRevoked,
                    crate::event::types::Outcome::Success,
                    "legacy-primary",
                )
                .build()
            },
        )
        .await
        .unwrap();
    assert_eq!(
        f.count("SELECT count(*) FROM session_primary_provenance"),
        0
    );
    assert_eq!(
        f.store
            .session(&view.session.session_id)
            .await
            .unwrap()
            .unwrap()
            .cred_gen,
        2
    );
}
#[tokio::test]
async fn native_human_engine_touch_cannot_extend_original_lifetime() {
    let mut f = Fx::new(None).await;
    let mut snapshot = f.config.snapshot(1);
    snapshot.apps[0].session.idle = Duration::from_secs(1);
    f.publish_snapshot(snapshot).await;
    let (cookie, _) = f.login().await;
    f.clock.set(Timestamp(59_950));
    let witness = f.witness(&cookie).await;
    assert_eq!(witness.expires, Timestamp(60_000));
    let checked = witness.finish(&f.input(&cookie)).await.unwrap();
    f.store
        .touch_handle(&cookie.digest(), Timestamp(60_000))
        .await
        .unwrap();
    f.clock.set(Timestamp(60_000));
    assert!(matches!(
        decide(&f.ctx, f.input(&cookie)).await,
        Decision::Allow { .. }
    ));
    assert!(checked.require_current(&f.input(&cookie)).await.is_err());
}
#[tokio::test]
async fn native_human_engine_lower_handle_never_borrows_session_aal2() {
    let f = Fx::new(None).await;
    let (cookie, _) = f.login().await;
    let cookie = f.elevate(&cookie).await;
    let view = f
        .store
        .lookup_handle(&cookie.digest(), &Host::parse("app.example.test").unwrap())
        .await
        .unwrap()
        .unwrap();
    let binding = random_token(f.rng.as_ref(), 16);
    let minted = f
        .service()
        .mint_handoff(crate::session::MintRequest {
            session_id: view.session.session_id,
            aal_cap: Aal::One,
            target: "https://app.example.test/data".parse().unwrap(),
            client_ip: "192.0.2.10".parse().unwrap(),
            bind_sha256: binding.digest(),
            recovery_depth: 0,
            events: vec![],
        })
        .await
        .unwrap();
    let lower = f.redeem(minted.location, &binding).await;
    let input = f.input(&lower);
    let (decision, _, witness) = decide_for_human(
        &f.ctx,
        &input,
        f.owner.clone(),
        f.owner.admit(Duration::from_millis(400)).unwrap(),
    )
    .await;
    let Decision::Allow { identity, .. } = decision else {
        panic!("native lower handle was not allowed")
    };
    assert_eq!(identity.aal, Aal::One);
    let witness = witness.unwrap();
    assert_eq!(witness.view.handle.issued_aal, Aal::One);
    assert_eq!(witness.view.session.aal, Aal::Two);
    witness.finish(&input).await.unwrap();
}
struct ReorderedClock {
    base: Arc<TestClock>,
    armed: std::sync::atomic::AtomicBool,
    count: std::sync::atomic::AtomicUsize,
    started: std::sync::mpsc::Sender<()>,
    release: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
}
impl Clock for ReorderedClock {
    fn now(&self) -> Timestamp {
        if !self.armed.load(Ordering::Acquire) {
            return self.base.now();
        }
        let n = self.count.fetch_add(1, Ordering::AcqRel) + 1;
        if n == 1 {
            self.started.send(()).unwrap();
            self.release
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(5))
                .unwrap();
        }
        Timestamp(self.base.now().0 + i64::try_from(n).unwrap())
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_human_engine_delayed_earlier_wall_sample_is_not_false_rollback() {
    let mut f = Fx::new(None).await;
    let (cookie, _) = f.login().await;
    let (started, ready) = std::sync::mpsc::channel();
    let (release, wait) = std::sync::mpsc::channel();
    let clock = Arc::new(ReorderedClock {
        base: f.clock.clone(),
        armed: std::sync::atomic::AtomicBool::new(false),
        count: std::sync::atomic::AtomicUsize::new(0),
        started,
        release: std::sync::Mutex::new(wait),
    });
    f.ctx.clock = clock.clone();
    f.owner = human::Owner::new(
        f.store.clone(),
        f.owner.registry.clone(),
        f.ctx.snapshot.clone(),
        clock.clone(),
        f.rng.as_ref(),
    );
    let checked = Arc::new(
        f.witness(&cookie)
            .await
            .finish(&f.input(&cookie))
            .await
            .unwrap(),
    );
    clock.armed.store(true, Ordering::Release);
    let a = checked.clone();
    let first_input = f.input(&cookie);
    let first = tokio::spawn(async move { a.require_current(&first_input).await });
    ready.recv_timeout(Duration::from_secs(5)).unwrap();
    let second = checked.require_current(&f.input(&cookie)).await;
    release.send(()).unwrap();
    assert!(second.is_ok());
    assert!(first.await.unwrap().is_ok());
}

#[tokio::test]
async fn native_human_engine_same_reference_material_restart_and_aba() {
    let mut f = Fx::new(None).await;
    let (cookie, _) = f.login().await;
    let original = f.count("SELECT material_revision FROM session_primary_provenance");
    f.republish(1, None).await;
    assert_eq!(
        f.count("SELECT revision FROM human_provider_material_owners WHERE provider_id='native'"),
        original
    );
    let checked = f
        .witness(&cookie)
        .await
        .finish(&f.input(&cookie))
        .await
        .unwrap();
    checked.require_current(&f.input(&cookie)).await.unwrap();
    // Same DB provider row/config generation/reference, different actual secret.
    f.publish_material_snapshot(f.config.snapshot(1), "replacement-compiled-secret")
        .await;
    assert_eq!(
        f.count("SELECT revision FROM human_provider_material_owners WHERE provider_id='native'"),
        original + 1
    );
    assert!(matches!(
        decide(&f.ctx, f.input(&cookie)).await,
        Decision::Allow { .. }
    ));
    f.assert_unqualified(&cookie).await;
    f.republish(1, None).await;
    assert_eq!(
        f.count("SELECT revision FROM human_provider_material_owners WHERE provider_id='native'"),
        original + 2
    );
    f.assert_unqualified(&cookie).await;
    let new = f.native_login().await;
    let _ = f.witness(&new).await;
}

#[tokio::test]
async fn native_human_engine_cold_store_unchanged_material_restores_original_native_primary() {
    let f = Fx::new(None).await;
    let (cookie, _) = f.login().await;
    let ordinary = f.input(&cookie);
    let captured = f.input(&cookie);
    let Fx {
        _dir,
        store,
        clock,
        rng,
        ctx,
        owner,
        config,
        provider_config: _,
        _oidc,
        portal: _,
    } = f;
    drop(owner);
    drop(ctx);
    drop(store);
    let store = Store::open(&_dir.path().join("native.db"), clock.clone(), vec![], None).unwrap();

    let applications = Arc::new(arc_swap::ArcSwap::from_pointee(config.snapshot(1)));
    let registry = Arc::new(
        Registry::from_prepared_keyed(
            store
                .prepare_registry_providers(1, deadline())
                .await
                .unwrap(),
            applications.clone(),
            &|_| Some("fixed-owned-reference".into()),
            clock.clone(),
            None,
            material_key().as_ref(),
        )
        .unwrap(),
    );
    registry.publish_prepared(&store, deadline()).await.unwrap();
    let ctx = VerifyContext::new(
        store.directory(),
        store.sessions(),
        clock.clone(),
        rng.clone(),
        applications.clone(),
        VerifyLimits::default(),
    );
    let owner = human::Owner::new(store.clone(), registry, applications, clock, rng.as_ref());
    assert!(matches!(
        decide(&ctx, ordinary).await,
        Decision::Allow { .. }
    ));
    let (decision, _, witness) = decide_for_human(
        &ctx,
        &captured,
        owner.clone(),
        owner.admit(Duration::from_millis(400)).unwrap(),
    )
    .await;
    assert!(matches!(decision, Decision::Allow { .. }));
    let checked = witness.unwrap().finish(&captured).await.unwrap();
    checked.require_current(&captured).await.unwrap();
    assert_eq!(
        store
            .conn()
            .query_row(
                "SELECT config_generation FROM session_primary_provenance",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        1
    );
    drop(_oidc);
}

#[tokio::test]
async fn native_human_current_includes_same_transaction_realm_and_latches_retirement() {
    let f = Fx::new(None).await;
    let (cookie, _) = f.login().await;
    let checked = f
        .witness(&cookie)
        .await
        .finish(&f.input(&cookie))
        .await
        .unwrap();
    checked.require_current(&f.input(&cookie)).await.unwrap();
    let original: String = f
        .store
        .conn()
        .query_row("SELECT realm FROM human_authority_realm", [], |r| r.get(0))
        .unwrap();
    assert!(
        f.store
            .conn()
            .execute(
                "UPDATE human_authority_realm SET realm=lower(hex(randomblob(32)))",
                []
            )
            .is_err()
    );
    // Deliberate privileged fault injection only: runtime users cannot change
    // the realm. This proves the joined Current compares it, not live DB-clone
    // or arbitrary SQL-tampering support.
    f.sql("DROP TRIGGER human_realm_update;UPDATE human_authority_realm SET realm=lower(hex(randomblob(32)))");
    assert!(checked.require_current(&f.input(&cookie)).await.is_err());
    f.store
        .conn()
        .execute("UPDATE human_authority_realm SET realm=?1", [original])
        .unwrap();
    assert!(checked.require_current(&f.input(&cookie)).await.is_err());
}

#[tokio::test]
async fn native_human_generated_ingress_original_decode_age_and_caller_pause() {
    use prost::Message;
    use std::sync::atomic::AtomicUsize;
    struct Chunks {
        chunks: std::collections::VecDeque<bytes::Bytes>,
        polls: Arc<AtomicUsize>,
        ticks: Arc<AtomicU64>,
        mode: &'static str,
    }
    impl axum::body::HttpBody for Chunks {
        type Data = bytes::Bytes;
        type Error = std::io::Error;
        fn poll_frame(
            mut self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
            self.polls.fetch_add(1, Ordering::SeqCst);
            if self.mode == "cancel" {
                return std::task::Poll::Pending;
            }
            if self.mode == "decode-age" {
                self.ticks.store(2000, Ordering::SeqCst);
            }
            std::task::Poll::Ready(
                self.chunks
                    .pop_front()
                    .map(|data| Ok(http_body::Frame::data(data))),
            )
        }
    }
    for mode in [
        "green",
        "decode-age",
        "caller-age",
        "invalid-caller",
        "cancel",
    ] {
        let mut f = Fx::new(None).await;
        let ticks = Arc::new(AtomicU64::new(100));
        let observed = ticks.clone();
        Arc::get_mut(&mut f.owner).unwrap().ticks =
            Some(Arc::new(move || Ok(observed.load(Ordering::SeqCst))));
        let (cookie, _) = f.login().await;
        let keys = Arc::new(
            crate::app::CallerKeys::new(
                Some(Secret::new("native-owned-gateway-key".into())),
                None,
                false,
            )
            .with_counter({
                let ticks = ticks.clone();
                Arc::new(move |_, _| {
                    if mode == "caller-age" {
                        ticks.store(2000, Ordering::SeqCst);
                    }
                })
            }),
        );
        let state = crate::http::gateway::GatewayState::new(
            crate::gateway::hangang::GatewayConfig::from_config(&f.config),
            f.ctx.clone(),
            keys.clone(),
            8,
            None,
            None,
        )
        .with_human_owner(f.owner.clone())
        .unwrap();
        let fields = [
            ("x-hopae-contract", "1".to_owned()),
            ("x-original-url", "https://app.example.test/data".into()),
            ("x-forwarded-proto", "https".into()),
            ("x-forwarded-host", "app.example.test".into()),
            ("x-forwarded-for", "192.0.2.10".into()),
            ("x-original-method", "GET".into()),
            ("x-hangang-canonical-path", "/data".into()),
            ("x-hangang-route-id", "owned-route".into()),
            ("cookie", format!("__Host-hopae={}", cookie.expose())),
        ];
        let input = hopae_grpc::v1::VerifyRequest {
            request_id: 1,
            headers: fields
                .into_iter()
                .map(|(name, value)| hopae_grpc::v1::Header {
                    name: name.into(),
                    value: value.into_bytes(),
                })
                .collect(),
        };
        let payload = input.encode_to_vec();
        let mut frame = vec![0];
        frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        frame.extend_from_slice(&payload);
        let polls = Arc::new(AtomicUsize::new(0));
        let calls = polls.clone();
        let time = ticks.clone();
        let body = axum::body::Body::new(Chunks {
            chunks: vec![
                bytes::Bytes::copy_from_slice(&frame[..3]),
                bytes::Bytes::copy_from_slice(&frame[3..]),
            ]
            .into(),
            polls: calls,
            ticks: time,
            mode,
        });
        let readiness = crate::app::Readiness::default();
        readiness.set(true);
        let captured = Arc::new(AtomicUsize::new(0));
        let slots = Arc::new(tokio::sync::Semaphore::new(1));
        let credential = if mode == "invalid-caller" {
            "Bearer wrong"
        } else {
            "Bearer native-owned-gateway-key"
        };
        let future = crate::http::grpc_gateway::human_transport_fixture(
            crate::http::gateway::router(state),
            keys,
            f.owner.clone(),
            readiness,
            f.ctx.limits.budget,
            body,
            credential,
            captured.clone(),
            slots.clone(),
        );
        let mut future = Box::pin(future);
        if mode == "cancel" {
            std::future::poll_fn(|cx| {
                assert!(std::future::Future::poll(future.as_mut(), cx).is_pending());
                std::task::Poll::Ready(())
            })
            .await;
            assert!(polls.load(Ordering::SeqCst) > 0);
            assert_eq!(slots.available_permits(), 0);
            drop(future);
            assert_eq!(slots.available_permits(), 1);
            assert_eq!(captured.load(Ordering::SeqCst), 0);
            continue;
        }
        let (code, data) = future.await;
        assert_eq!(slots.available_permits(), 1);
        match mode {
            "green" => {
                assert_eq!(code, 0);
                let reply = hopae_grpc::v1::VerifyReply::decode(&data[5..]).unwrap();
                assert_eq!(reply.status, 200);
                assert_eq!(captured.load(Ordering::SeqCst), 1);
            }
            "decode-age" => {
                assert_eq!(code, 0);
                let reply = hopae_grpc::v1::VerifyReply::decode(&data[5..]).unwrap();
                assert_eq!(reply.status, 503);
                assert_eq!(captured.load(Ordering::SeqCst), 0);
                assert!(polls.load(Ordering::SeqCst) > 0);
            }
            "caller-age" => {
                assert_eq!(code, 14);
                assert_eq!(polls.load(Ordering::SeqCst), 0);
                assert_eq!(captured.load(Ordering::SeqCst), 0);
            }
            _ => {
                assert_eq!(code, 16);
                assert_eq!(polls.load(Ordering::SeqCst), 0);
                assert_eq!(captured.load(Ordering::SeqCst), 0);
            }
        }
    }
}

#[tokio::test]
async fn native_human_original_admission_one_shot_wrong_owner_readiness_and_cancel() {
    let f = Fx::new(None).await;
    let ready = crate::app::Readiness::default();
    ready.set(true);
    let capture = f
        .owner
        .capture(f.owner.admit(f.ctx.limits.budget).unwrap(), ready.clone())
        .unwrap();
    let duplicate = capture.clone();
    assert!(capture.take(&f.owner).is_ok());
    assert!(duplicate.take(&f.owner).is_err());
    let other = human::Owner::new(
        f.store.clone(),
        f.owner.registry.clone(),
        f.ctx.snapshot.clone(),
        f.ctx.clock.clone(),
        f.rng.as_ref(),
    );
    let capture = f
        .owner
        .capture(f.owner.admit(f.ctx.limits.budget).unwrap(), ready.clone())
        .unwrap();
    assert!(capture.take(&other).is_err());
    assert!(capture.take(&f.owner).is_err());
    let capture = f
        .owner
        .capture(f.owner.admit(f.ctx.limits.budget).unwrap(), ready.clone())
        .unwrap();
    ready.set(false);
    assert!(capture.take(&f.owner).is_err());
    ready.set(true);
    assert!(capture.take(&f.owner).is_err());
    let capture = f
        .owner
        .capture(f.owner.admit(f.ctx.limits.budget).unwrap(), ready)
        .unwrap();
    let weak = Arc::downgrade(&capture.admission);
    let task = tokio::spawn(async move {
        let _capture = capture;
        std::future::pending::<()>().await;
    });
    tokio::task::yield_now().await;
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert!(weak.upgrade().is_none());
}

#[tokio::test]
async fn native_human_readiness_retained_after_take_and_checked_current() {
    let f = Fx::new(None).await;
    let (cookie, _) = f.login().await;
    let ready = crate::app::Readiness::default();
    ready.set(true);
    let capture = f
        .owner
        .capture(f.owner.admit(f.ctx.limits.budget).unwrap(), ready.clone())
        .unwrap();
    let admission = capture.take(&f.owner).unwrap();
    ready.set(false);
    let (decision, _, witness) =
        decide_for_human(&f.ctx, &f.input(&cookie), f.owner.clone(), admission).await;
    assert!(!matches!(decision, Decision::Allow { .. }));
    assert!(witness.is_none());
    ready.set(true);
    let capture = f
        .owner
        .capture(f.owner.admit(f.ctx.limits.budget).unwrap(), ready.clone())
        .unwrap();
    let (decision, _, witness) = decide_for_human(
        &f.ctx,
        &f.input(&cookie),
        f.owner.clone(),
        capture.take(&f.owner).unwrap(),
    )
    .await;
    assert!(matches!(decision, Decision::Allow { .. }));
    let checked = witness.unwrap().finish(&f.input(&cookie)).await.unwrap();
    ready.set(false);
    assert!(checked.require_current(&f.input(&cookie)).await.is_err());
    ready.set(true);
    assert!(checked.require_current(&f.input(&cookie)).await.is_err());
}

#[test]
fn native_human_readiness_withdrawn_while_actual_engine_store_awaits() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(1)
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let f = Fx::new(None).await;
        let (cookie, _) = f.login().await;
        let ready = crate::app::Readiness::default();
        ready.set(true);
        let capture = f
            .owner
            .capture(f.owner.admit(f.ctx.limits.budget).unwrap(), ready.clone())
            .unwrap();
        let admission = capture.take(&f.owner).unwrap();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let blocker = tokio::task::spawn_blocking(move || {
            started_tx.send(()).unwrap();
            release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        });
        started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let input = f.input(&cookie);
        let mut pending = Box::pin(decide_for_human(&f.ctx, &input, f.owner.clone(), admission));
        std::future::poll_fn(|cx| {
            assert!(std::future::Future::poll(pending.as_mut(), cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        ready.set(false);
        release_tx.send(()).unwrap();
        blocker.await.unwrap();
        let (decision, _, witness) = pending.await;
        assert!(!matches!(decision, Decision::Allow { .. }));
        assert!(witness.is_none());
    });
}

#[tokio::test]
async fn native_human_retained_current_rechecks_actual_owner_without_cookie() {
    for withdrawal in [
        "UPDATE session_handles SET revoked_at=59",
        "UPDATE sessions SET terminated_at=59",
        "UPDATE users SET status='disabled'",
        "UPDATE users SET authz_version=authz_version+1",
        "DELETE FROM session_primary_provenance",
    ] {
        let f = Fx::new(None).await;
        let (cookie, _) = f.login().await;
        let checked = f
            .witness(&cookie)
            .await
            .finish(&f.input(&cookie))
            .await
            .unwrap();
        drop(cookie);
        checked.require_current_retained().await.unwrap();
        f.sql(withdrawal);
        assert!(
            checked.require_current_retained().await.is_err(),
            "{withdrawal}"
        );
        assert!(
            checked.require_current_retained().await.is_err(),
            "retired: {withdrawal}"
        );
    }
}
#[tokio::test]
async fn native_human_retained_current_cannot_revive_scope_retirement() {
    let f = Fx::new(None).await;
    let (cookie, _) = f.login().await;
    let checked = f
        .witness(&cookie)
        .await
        .finish(&f.input(&cookie))
        .await
        .unwrap();
    checked.require_current_retained().await.unwrap();
    let mut wrong = f.input(&cookie);
    wrong.route_id = Some("wrong-route".into());
    assert!(checked.require_current(&wrong).await.is_err());
    assert!(checked.require_current_retained().await.is_err());
}

#[tokio::test]
async fn native_human_retained_current_keeps_original_clock_fence() {
    for mode in 0..3 {
        let mut f = Fx::new(None).await;
        let ticks = Arc::new(AtomicU64::new(100));
        let read = ticks.clone();
        Arc::get_mut(&mut f.owner).unwrap().ticks =
            Some(Arc::new(move || Ok(read.load(Ordering::Acquire))));
        let (cookie, _) = f.login().await;
        let checked = f
            .witness(&cookie)
            .await
            .finish(&f.input(&cookie))
            .await
            .unwrap();
        drop(cookie);
        checked.require_current_retained().await.unwrap();
        match mode {
            0 => ticks.store(1100, Ordering::Release),
            1 => ticks.store(99, Ordering::Release),
            _ => f.clock.set(Timestamp(58_000)),
        }
        assert!(checked.require_current_retained().await.is_err());
        ticks.store(100, Ordering::Release);
        f.clock.set(Timestamp(59_000));
        assert!(checked.require_current_retained().await.is_err());
    }
}

fn source_binding(
    application: &str,
    route: &str,
    method: &str,
) -> crate::auth_gateway::human_request::Binding {
    use crate::auth_gateway::human_request::{Configuration, Scope};
    use sha2::{Digest as _, Sha256};
    let scope = Scope::compile(Configuration {
        service: "orders",
        audience: "orders-api",
        application,
        route,
        route_revision: 1,
        destination: [3; 32],
        header_revision: 1,
        headers: &[],
        reserved_headers: &[],
        maximum_entity_bytes: 16 * 1024 * 1024,
    })
    .unwrap();
    scope
        .validate(
            "orders",
            "orders-api",
            &hopae_grpc::v1::HumanFinalRequest {
                binding_contract: 2,
                method: method.into(),
                target: "/transformed".into(),
                entity_sha256: Sha256::digest([]).to_vec(),
                entity_length: 0,
                route_id: route.into(),
                route_revision: 1,
                destination_sha256: vec![3; 32],
                header_policy_revision: 1,
                headers: vec![],
            },
        )
        .unwrap()
}
#[tokio::test]
async fn native_human_source_facts_use_actual_native_user_and_same_owner_clock() {
    let f = Fx::new(None).await;
    let (cookie, _) = f.login().await;
    let checked = f
        .witness(&cookie)
        .await
        .finish(&f.input(&cookie))
        .await
        .unwrap();
    drop(cookie);
    let binding = source_binding("app", "owned-route", "GET");
    let facts = checked
        .source_facts("native-issuer", &binding)
        .await
        .unwrap();
    assert_eq!(facts.subject.len(), 71);
    assert!(facts.subject.starts_with("human1:"));
    assert_eq!(facts.aal, 1);
    assert!(facts.user_revision > 0 && facts.credential_generation > 0);
    assert_eq!(facts.application_generation, 1);
    assert!(checked.belongs_to(&f.owner));
    let other = Fx::new(None).await;
    assert!(!checked.belongs_to(&other.owner));
    let first = checked.source_time().unwrap();
    let next = checked.source_time().unwrap();
    assert_ne!(first.clock_domain, [0; 16]);
    assert_eq!(next.clock_domain, first.clock_domain);
    assert!(next.owner_now_ms >= first.owner_now_ms);
    assert!(next.expires_ms <= first.expires_ms);
    assert!(next.expires_ms > next.owner_now_ms);
    assert!(next.expires_ms - next.owner_now_ms < 1000);
    let second = checked
        .source_facts("native-issuer", &binding)
        .await
        .unwrap();
    assert_eq!(second.subject, facts.subject);
    let different = checked
        .source_facts("other-issuer", &binding)
        .await
        .unwrap();
    assert_ne!(different.subject, facts.subject);
    f.sql("UPDATE users SET status='disabled'");
    assert!(
        checked
            .source_facts("native-issuer", &binding)
            .await
            .is_err()
    );
    assert!(checked.source_time().is_err());
}
#[tokio::test]
async fn native_human_source_facts_refuse_scope_substitution_and_latch() {
    for (app, route, method) in [
        ("other", "owned-route", "GET"),
        ("app", "other", "GET"),
        ("app", "owned-route", "POST"),
    ] {
        let f = Fx::new(None).await;
        let (cookie, _) = f.login().await;
        let checked = f
            .witness(&cookie)
            .await
            .finish(&f.input(&cookie))
            .await
            .unwrap();
        assert!(
            checked
                .source_facts("native-issuer", &source_binding(app, route, method))
                .await
                .is_err()
        );
        assert!(
            checked
                .source_facts(
                    "native-issuer",
                    &source_binding("app", "owned-route", "GET")
                )
                .await
                .is_err()
        );
        assert!(checked.source_time().is_err());
    }
}

#[tokio::test]
async fn native_human_source_final_clock_callback_cannot_hide_publication_withdrawal() {
    for final_read in [2, 3] {
        let mut f = Fx::new(None).await;
        let reads = Arc::new(AtomicU64::new(0));
        let armed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let snapshot = f.ctx.snapshot.clone();
        let replacement = Arc::new(f.config.snapshot(1));
        let count = reads.clone();
        let trigger = armed.clone();
        Arc::get_mut(&mut f.owner).unwrap().ticks = Some(Arc::new(move || {
            if trigger.load(Ordering::Acquire)
                && count.fetch_add(1, Ordering::AcqRel) + 1 == final_read
            {
                snapshot.store(replacement.clone());
            }
            Ok(100)
        }));
        let (cookie, _) = f.login().await;
        let checked = f
            .witness(&cookie)
            .await
            .finish(&f.input(&cookie))
            .await
            .unwrap();
        armed.store(true, Ordering::Release);
        if final_read == 2 {
            assert!(checked.require_publication_current().is_err());
        } else {
            assert!(checked.source_time().is_err());
        }
        assert!(checked.require_current_retained().await.is_err());
    }
}

#[tokio::test]
async fn native_human_source_publication_is_fixed_and_final_check_has_no_clock_callback() {
    let mut f = Fx::new(None).await;
    let calls = Arc::new(AtomicU64::new(0));
    let count = calls.clone();
    Arc::get_mut(&mut f.owner).unwrap().ticks = Some(Arc::new(move || {
        count.fetch_add(1, Ordering::AcqRel);
        Ok(100)
    }));
    let publication = f.owner.source_publication().unwrap();
    let (cookie, _) = f.login().await;
    let checked = f
        .witness(&cookie)
        .await
        .finish(&f.input(&cookie))
        .await
        .unwrap();
    let before = calls.load(Ordering::Acquire);
    publication.require_current().unwrap();
    assert!(publication.accepts(&checked));
    assert_eq!(calls.load(Ordering::Acquire), before);
    assert!(publication.retained_bytes().unwrap() > 0);
    assert!(checked.retained_bytes().unwrap() > std::mem::size_of::<human::Checked>());
    let other = Fx::new(None).await;
    let (other_cookie, _) = other.login().await;
    let other_checked = other
        .witness(&other_cookie)
        .await
        .finish(&other.input(&other_cookie))
        .await
        .unwrap();
    assert!(!publication.accepts(&other_checked));
    let original = f.ctx.snapshot.load_full();
    f.ctx.snapshot.store(Arc::new(f.config.snapshot(1)));
    assert!(publication.require_current().is_err());
    f.ctx.snapshot.store(original);
    assert!(publication.require_current().is_err());
    assert!(!publication.accepts(&checked));
}

#[tokio::test]
async fn native_human_source_facts_never_promote_aal_from_session_alone() {
    let f = Fx::new(None).await;
    let (old, _) = f.login().await;
    let cookie = f.elevate(&old).await;
    // Deliberate downgrade fixture: retain actual native TOTP session but
    // present an AAL1 handle. A session's stronger level cannot promote it.
    f.store
        .conn()
        .execute(
            "UPDATE session_handles SET issued_aal=1 WHERE handle_sha256=?1",
            [cookie.digest().0.as_slice()],
        )
        .unwrap();
    let witness = f.witness(&cookie).await;
    assert_eq!(witness.view.session.aal, Aal::Two);
    assert_eq!(witness.view.handle.issued_aal, Aal::One);
    let checked = witness.finish(&f.input(&cookie)).await.unwrap();
    let facts = checked
        .source_facts(
            "native-issuer",
            &source_binding("app", "owned-route", "GET"),
        )
        .await
        .unwrap();
    assert_eq!(facts.aal, 1);
}

#[tokio::test]
async fn native_human_source_final_fences_do_not_call_wall_after_durable_check() {
    struct CountWall {
        base: Arc<TestClock>,
        calls: Arc<AtomicU64>,
    }
    impl Clock for CountWall {
        fn now(&self) -> Timestamp {
            self.calls.fetch_add(1, Ordering::AcqRel);
            self.base.now()
        }
    }
    let mut f = Fx::new(None).await;
    let calls = Arc::new(AtomicU64::new(0));
    let wall: Arc<dyn Clock> = Arc::new(CountWall {
        base: f.clock.clone(),
        calls: calls.clone(),
    });
    f.ctx.clock = wall.clone();
    f.owner = human::Owner::new(
        f.store.clone(),
        f.owner.registry.clone(),
        f.ctx.snapshot.clone(),
        wall,
        f.rng.as_ref(),
    );
    let (cookie, _) = f.login().await;
    let checked = f
        .witness(&cookie)
        .await
        .finish(&f.input(&cookie))
        .await
        .unwrap();
    let before = calls.load(Ordering::Acquire);
    assert!(before > 0);
    checked.require_publication_current().unwrap();
    checked.source_time().unwrap();
    assert_eq!(calls.load(Ordering::Acquire), before);
    checked.require_current_retained().await.unwrap();
    assert!(calls.load(Ordering::Acquire) > before);
}

#[path = "../auth_gateway/human_source_tests.rs"]
mod native_source_tests;

#[path = "../http/grpc_human_tests.rs"]
mod native_rpc_tests;

#[path = "../auth_gateway/human_projection_tests.rs"]
mod native_projection_tests;
