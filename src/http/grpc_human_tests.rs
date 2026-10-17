//! Child of verify::human_tests. Actual OIDC/session/Engine → production Human RPC.
use super::*;
use crate::auth_gateway::{receipt_authority, receipt_config::NativeIssuer, receipt_keys};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use hopae_grpc::{human_observed_client as sdk, receipt_time::ClockRates, v1};
use tonic::{
    Request,
    transport::{Certificate, Identity, ServerTlsConfig},
};
pub(super) const CALLER: &str = "native-human-rpc-owned-caller-thirty-two-bytes";
pub(super) fn native() -> NativeIssuer {
    serde_json::from_value(serde_json::json!({"issuer_ref":"native-human","key_epoch":1,"identity_authority_epoch":"owned-human","public_key":STANDARD.encode(ed25519_dalek::SigningKey::from_bytes(&[0x45;32]).verifying_key().to_bytes()),"seed_env":"OWNED_HUMAN_SIGNING","scopes":[{"service":"orders","audience":"orders-api"}],"human_receipts":{"source_revision":7,"scopes":[{"service":"orders","audience":"orders-api","application":"app","route":"owned-route","route_revision":11,"destination_sha256":"12".repeat(32),"header_revision":13,"headers":[],"reserved_headers":["x-owned-secret"],"maximum_entity_bytes":16777216}],"capacity":1024,"retained_bytes":33554432}})).unwrap()
}
pub(super) async fn services(f: &Fx) -> (crate::app::Bound, crate::app::Services) {
    let mut config = f.config.clone();
    config.listen.portal = "127.0.0.1:0".into();
    config.listen.gateway = "127.0.0.1:0".into();
    let bound = crate::app::bind(&config).await.unwrap();
    let mut services = bound.services().clone();
    services.store = f.store.clone();
    services.registry = f.owner.registry.clone();
    services.snapshot = f.ctx.snapshot.clone();
    services.clock = f.clock.clone();
    services.rng = f.rng.clone();
    services.human_owner = f.owner.clone();
    services.readiness.set(true);
    let native = native();
    config.receipt_issuer = Some(native.clone());
    services.config = Arc::new(config);
    services.receipt_issuer = Some(Arc::new(
        native
            .load(
                &|_| Some(STANDARD.encode([0x45; 32])),
                f.clock.clone(),
                f.rng.clone(),
            )
            .unwrap(),
    ));
    let mut authority = {
        use crate::store::meta::MetaDb as _;
        f.store
            .meta()
            .meta_read(|tx| receipt_authority::Authority::load(tx, 0))
            .unwrap()
    };
    authority
        .reconcile(
            &mut f.store.meta(),
            &[receipt_keys::Key {
                issuer_ref: "native-human".into(),
                purpose: crate::auth_gateway::receipt::Purpose::Authentication,
                epoch: 1,
                public_key: ed25519_dalek::SigningKey::from_bytes(&[0x45; 32])
                    .verifying_key()
                    .to_bytes(),
            }],
            "owned-human-rpc",
            &|_| Ok(()),
        )
        .unwrap();
    services.receipt_authority = Arc::new(std::sync::Mutex::new(authority));
    services.human_receipt_source = Some(Arc::new(
        crate::auth_gateway::human_source::Source::new(
            services.human_owner.clone(),
            services.receipt_issuer.clone().unwrap(),
            services.receipt_authority.lock().unwrap().verifier(),
            &native,
        )
        .unwrap(),
    ));
    services.authentication_authority = None;
    services.caller_keys = Arc::new(crate::app::CallerKeys::new(
        Some(Secret::new(CALLER.into())),
        None,
        false,
    ));
    (bound, services)
}
pub(super) fn headers(cookie: &Secret) -> Vec<v1::Header> {
    [
        ("x-hopae-contract", "1".into()),
        ("x-original-url", "https://app.example.test/data".into()),
        ("x-forwarded-proto", "https".into()),
        ("x-forwarded-host", "app.example.test".into()),
        ("x-forwarded-for", "192.0.2.10".into()),
        ("x-original-method", "GET".into()),
        ("x-hangang-canonical-path", "/data".into()),
        ("x-hangang-route-id", "owned-route".into()),
        ("cookie", format!("__Host-hopae={}", cookie.expose())),
    ]
    .into_iter()
    .map(|(name, value): (&str, String)| v1::Header {
        name: name.into(),
        value: value.into_bytes(),
    })
    .collect()
}
pub(super) fn scope() -> sdk::HumanScope {
    sdk::HumanScope {
        service: "orders".into(),
        audience: "orders-api".into(),
        app_id: "app".into(),
        route_id: "owned-route".into(),
        route_revision: 11,
        destination_sha256: [0x12; 32],
        header_policy_revision: 13,
        header_names: vec![],
        reserved_names: vec!["x-owned-secret".into()],
    }
}
fn descriptor() -> v1::HumanFinalRequest {
    use sha2::{Digest as _, Sha256};
    v1::HumanFinalRequest {
        binding_contract: 2,
        method: "GET".into(),
        target: "/data".into(),
        entity_sha256: Sha256::digest(b"body").to_vec(),
        entity_length: 4,
        route_id: "owned-route".into(),
        route_revision: 11,
        destination_sha256: vec![0x12; 32],
        header_policy_revision: 13,
        headers: vec![],
    }
}
fn raw(cookie: &Secret) -> Request<v1::HumanReceiptRequest> {
    let mut q = Request::new(v1::HumanReceiptRequest {
        verification: Some(v1::VerifyRequest {
            request_id: 1,
            headers: headers(cookie),
        }),
        service: "orders".into(),
        audience: "orders-api".into(),
        final_request: Some(descriptor()),
    });
    q.metadata_mut()
        .insert("authorization", format!("Bearer {CALLER}").parse().unwrap());
    q
}
fn capture(f: &Fx, s: &crate::app::Services) -> human::Capture {
    f.owner
        .capture(
            f.owner.admit(Duration::from_secs(1)).unwrap(),
            s.readiness.clone(),
        )
        .unwrap()
}
pub(super) fn tls(root: &std::path::Path) {
    let openssl = |args: &[&str]| {
        assert!(
            std::process::Command::new("openssl")
                .args(args)
                .current_dir(root)
                .output()
                .unwrap()
                .status
                .success()
        )
    };
    openssl(&[
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-days",
        "1",
        "-subj",
        "/CN=owned-ca",
        "-keyout",
        "ca.key",
        "-out",
        "ca.pem",
        "-addext",
        "basicConstraints=critical,CA:TRUE",
    ]);
    openssl(&[
        "req",
        "-new",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-subj",
        "/CN=owned-peer",
        "-keyout",
        "peer.key",
        "-out",
        "peer.csr",
    ]);
    std::fs::write(root.join("ext"),"basicConstraints=critical,CA:FALSE\nsubjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth,clientAuth\n").unwrap();
    openssl(&[
        "x509",
        "-req",
        "-in",
        "peer.csr",
        "-CA",
        "ca.pem",
        "-CAkey",
        "ca.key",
        "-CAcreateserial",
        "-days",
        "1",
        "-extfile",
        "ext",
        "-out",
        "peer.pem",
    ]);
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_human_rpc_actual_oidc_public_sdk_issue_observe_refresh_and_totp() {
    actual_provider_rpc(None).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires private owned LDAP TLS fixture, executed separately"]
async fn native_human_rpc_actual_ldap_public_sdk_issue_observe_refresh_and_totp() {
    let ldap = serde_json::json!({"ldap":{"endpoint":std::env::var("OWNED_LDAP_ENDPOINT").unwrap(),"starttls":std::env::var("OWNED_LDAP_STARTTLS").is_ok_and(|s|s=="1"),"ca":std::env::var("OWNED_LDAP_CA").unwrap(),"base_dn":"dc=example,dc=test","bind_dn":"cn=reader,dc=example,dc=test","bind_password_env":"OWNED_LDAP_BIND_KEY","username_attribute":"uid","subject_attribute":"entryUUID","timeout_ms":1000}});
    actual_provider_rpc(Some(ldap)).await;
}
async fn actual_provider_rpc(ldap: Option<serde_json::Value>) {
    let f = Fx::new(ldap).await;
    let (cookie, _) = f.login().await;
    let (_bound, services) = services(&f).await;
    assert!(services.authentication_authority.is_none());
    let root = tempfile::tempdir().unwrap();
    tls(root.path());
    let read = |n| std::fs::read(root.path().join(n)).unwrap();
    let ca = read("ca.pem");
    let cert = read("peer.pem");
    let key = read("peer.key");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = format!("https://{}", listener.local_addr().unwrap());
    let router = crate::app::build_routers(&services).unwrap().gateway;
    let (stop, rx) = tokio::sync::watch::channel(false);
    let task = tokio::spawn(crate::http::grpc_gateway::serve_with_receipts(
        listener,
        ServerTlsConfig::new()
            .identity(Identity::from_pem(cert.clone(), key.clone()))
            .client_ca_root(Certificate::from_pem(&ca)),
        router,
        services.caller_keys.clone(),
        rx,
        Some(services.clone()),
    ));
    let make_scope = |token: &str, configured: sdk::HumanScope| {
        sdk::Client::new_human(
            sdk::EndpointConfig {
                address: &addr,
                server_name: "localhost",
                ca: &ca,
                certificate: &cert,
                private_key: &key,
                caller_key: token,
            },
            sdk::HumanTrustPolicy {
                issuer_ref: "native-human".into(),
                key_epoch: 1,
                verifying_key: ed25519_dalek::SigningKey::from_bytes(&[0x45; 32]).verifying_key(),
                identity_authority: "owned-human".into(),
                scopes: vec![configured],
                minimum_source_revision: 7,
                minimum_application_generation: 1,
                minimum_key_registry_revision: 1,
            },
            Arc::new(hangang_runtime::time::ReceiverClock::new([0x33; 16]).unwrap()),
            ClockRates::new(50, 50).unwrap(),
            sdk::Limits {
                concurrent: 8,
                timeout: Duration::from_millis(400),
            },
        )
        .unwrap()
    };
    let prepare = |client: &sdk::Client, cookie: &Secret| {
        client
            .prepare(
                &scope(),
                &hopae_grpc::request_binding_v2::Request {
                    service: "orders",
                    audience: "orders-api",
                    route_id: "owned-route",
                    route_revision: 11,
                    destination_sha256: &[0x12; 32],
                    method: "GET",
                    target: "/data",
                    body: b"body",
                    bound_headers: &[],
                },
                headers(cookie),
            )
            .unwrap()
    };
    let make = |token: &str| make_scope(token, scope());
    let client = make(CALLER);
    let first = client.issue(prepare(&client, &cookie)).await.unwrap();
    assert_eq!(first.context().identity.as_ref().unwrap().kind, 1);
    assert_eq!(first.context().identity.as_ref().unwrap().aal, 1);
    let observer = make(CALLER);
    let observed = observer
        .observe(
            observer
                .prepare_observation(
                    first.context().clone(),
                    first.receipt(),
                    first
                        .context()
                        .request_sha256
                        .as_slice()
                        .try_into()
                        .unwrap(),
                )
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(observer.check(&observed, observed.request()).is_ok());
    let left = client.check(&first, first.request()).unwrap();
    let refreshed = client.refresh(first).await.unwrap();
    assert!(client.check(&refreshed, refreshed.request()).unwrap() <= left);
    assert_eq!(
        observed.scope().fingerprint().unwrap(),
        scope().fingerprint().unwrap()
    );
    for field in 0..6 {
        let fresh = client.issue(prepare(&client, &cookie)).await.unwrap();
        let mut sibling = scope();
        match field {
            0 => sibling.app_id = "sibling-app".into(),
            1 => sibling.route_id = "sibling-route".into(),
            2 => sibling.route_revision += 1,
            3 => sibling.destination_sha256 = [0x13; 32],
            4 => sibling.header_policy_revision += 1,
            _ => sibling.header_names = vec!["x-intent".into()],
        }
        let wrong_scope = make_scope(CALLER, sibling);
        let pending = wrong_scope
            .prepare_observation(
                fresh.context().clone(),
                fresh.receipt(),
                fresh
                    .context()
                    .request_sha256
                    .as_slice()
                    .try_into()
                    .unwrap(),
            )
            .unwrap();
        assert!(
            wrong_scope.observe(pending).await.is_err(),
            "scope substitution field{field}"
        );
        assert!(
            client.refresh(fresh).await.is_ok(),
            "original source remains current after scope refusal field{field}"
        );
    }
    let mfa = f.elevate(&cookie).await;
    let second = client.issue(prepare(&client, &mfa)).await.unwrap();
    assert_eq!(second.context().identity.as_ref().unwrap().aal, 2);
    let wrong = make("wrong-native-human-caller-thirty-two-bytes");
    assert!(wrong.issue(prepare(&wrong, &mfa)).await.is_err());
    assert!(client.check(&second, second.request()).unwrap() > Duration::from_millis(100));
    let elevated_view = f
        .store
        .lookup_handle(&mfa.digest(), &Host::parse("app.example.test").unwrap())
        .await
        .unwrap()
        .unwrap();
    f.store
        .sessions()
        .terminate_session(
            &elevated_view.session.session_id,
            crate::event::types::reasons::LOGOUT,
            f.clock.now(),
            vec![],
        )
        .await
        .unwrap();
    assert!(client.refresh(second).await.is_err());
    services.readiness.set(false);
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_human_rpc_direct_original_missing_wrong_owner_duplicate_stale_and_mixed_refuse() {
    let f = Fx::new(None).await;
    let (cookie, _) = f.login().await;
    let (_bound, services) = services(&f).await;
    assert!(
        crate::http::grpc_human::direct_issue_fixture(&services, raw(&cookie))
            .await
            .is_err()
    );
    let other = Fx::new(None).await;
    let mut q = raw(&cookie);
    q.extensions_mut().insert(capture(&other, &services));
    assert!(
        crate::http::grpc_human::direct_issue_fixture(&services, q)
            .await
            .is_err()
    );
    let token = capture(&f, &services);
    token.take(&f.owner).unwrap();
    let mut q = raw(&cookie);
    q.extensions_mut().insert(token);
    assert!(
        crate::http::grpc_human::direct_issue_fixture(&services, q)
            .await
            .is_err()
    );
    let token = f
        .owner
        .capture(
            f.owner.admit(Duration::from_millis(20)).unwrap(),
            services.readiness.clone(),
        )
        .unwrap();
    tokio::time::sleep(Duration::from_millis(30)).await;
    let mut q = raw(&cookie);
    q.extensions_mut().insert(token);
    assert!(
        crate::http::grpc_human::direct_issue_fixture(&services, q)
            .await
            .is_err()
    );
    let workload = crate::auth_gateway::workload_owner::Owner::new(
        crate::auth_gateway::workload_owner::Configuration {
            scopes: vec![],
            capacity: 1,
        },
        [0x11; 16],
    )
    .unwrap();
    let mut q = raw(&cookie);
    q.extensions_mut().insert(capture(&f, &services));
    q.extensions_mut()
        .insert(workload.begin(f.clock.as_ref()).unwrap());
    assert!(
        crate::http::grpc_human::direct_issue_fixture(&services, q)
            .await
            .is_err()
    );
    let mut q = raw(&cookie);
    q.metadata_mut()
        .insert("authorization", "Bearer invalid".parse().unwrap());
    q.extensions_mut().insert(capture(&f, &services));
    assert!(
        crate::http::grpc_human::direct_issue_fixture(&services, q)
            .await
            .is_err()
    );
    assert!(
        crate::http::grpc_human::direct_observe_fixture(
            &services,
            Request::new(v1::HumanReceiptObservationRequest::default())
        )
        .await
        .is_err()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_human_rpc_query_started_before_later_valid_proof_cannot_readmit() {
    let mut f = Fx::new(None).await;
    let ticks = Arc::new(AtomicU64::new(100));
    let now = ticks.clone();
    Arc::get_mut(&mut f.owner).unwrap().ticks =
        Some(Arc::new(move || Ok(now.load(Ordering::SeqCst))));
    let (cookie, _) = f.login().await;
    let (_bound, services) = services(&f).await;
    let query = f
        .owner
        .capture(
            f.owner.admit(Duration::from_millis(400)).unwrap(),
            services.readiness.clone(),
        )
        .unwrap();
    ticks.store(1000, Ordering::SeqCst); // Query body arrives after its own original budget.
    let mut issue = raw(&cookie);
    issue.extensions_mut().insert(capture(&f, &services));
    let (proof_current, result) =
        crate::http::grpc_human::delayed_query_fixture(&services, issue, query).await;
    assert!(
        proof_current,
        "later actual native proof remains current independently"
    );
    assert!(result.is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_human_rpc_query_cannot_cross_expiry_during_last_source_samples() {
    use std::sync::atomic::{AtomicBool, AtomicUsize};
    // Vary the clock-read position; do not assume a particular count of SQL/fence samples.
    for crossing in 1..=10 {
        let mut f = Fx::new(None).await;
        let ticks = Arc::new(AtomicU64::new(100));
        let armed = Arc::new(AtomicBool::new(false));
        let reads = Arc::new(AtomicUsize::new(0));
        let (time, active, count) = (ticks.clone(), armed.clone(), reads.clone());
        Arc::get_mut(&mut f.owner).unwrap().ticks = Some(Arc::new(move || {
            if active.load(Ordering::SeqCst) {
                let n = count.fetch_add(1, Ordering::SeqCst) + 1;
                Ok(if n >= crossing { 301 } else { 298 })
            } else {
                Ok(time.load(Ordering::SeqCst))
            }
        }));
        let (cookie, _) = f.login().await;
        let (_bound, services) = services(&f).await;
        let query = f
            .owner
            .capture(
                f.owner.admit(Duration::from_millis(200)).unwrap(),
                services.readiness.clone(),
            )
            .unwrap();
        ticks.store(200, Ordering::SeqCst);
        let mut issue = raw(&cookie);
        issue.extensions_mut().insert(capture(&f, &services));
        let (still_current, result) = crate::http::grpc_human::query_crossing_fixture(
            &services,
            issue,
            query,
            &|| {
                ticks.store(298, Ordering::SeqCst);
            },
            &|| {
                armed.store(true, Ordering::SeqCst);
            },
        )
        .await;
        assert!(
            still_current,
            "source proof independently current at crossing{crossing}"
        );
        if let Ok(report) = result {
            assert!(report.owner_now_ms < 300);
            assert!(
                report.remaining_ms <= 1,
                "query original cutoff, not the later proof lifetime"
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_human_rpc_query_remaining_same_sample_rejects_wrong_owner_domain_and_latches() {
    let mut f = Fx::new(None).await;
    Arc::get_mut(&mut f.owner).unwrap().ticks = Some(Arc::new(|| Ok(100)));
    let other = Fx::new(None).await;
    let (cookie, _) = f.login().await;
    let checked = f
        .witness(&cookie)
        .await
        .finish(&f.input(&cookie))
        .await
        .unwrap();
    for attack in 0..4 {
        let query = f.owner.admit(Duration::from_millis(400)).unwrap();
        let mut sample = checked.source_time().unwrap();
        assert!(query.remaining_at(&f.owner, &sample).unwrap() > 0);
        let original_now = sample.owner_now_ms;
        let original_domain = sample.clock_domain;
        match attack {
            0 => assert!(query.remaining_at(&other.owner, &sample).is_err()),
            1 => {
                sample.clock_domain[0] ^= 1;
                assert!(query.remaining_at(&f.owner, &sample).is_err());
            }
            2 => {
                sample.owner_now_ms = 99;
                assert!(query.remaining_at(&f.owner, &sample).is_err());
            }
            3 => {
                sample.owner_now_ms = 500;
                assert!(query.remaining_at(&f.owner, &sample).is_err());
            }
            _ => unreachable!(),
        }
        sample.owner_now_ms = original_now;
        sample.clock_domain = original_domain;
        assert!(
            query.remaining_at(&f.owner, &sample).is_err(),
            "failed query cannot recover after attack {attack}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_human_rpc_verify_metadata_is_canonical_for_ordinary_and_private_capture() {
    use tower::ServiceExt;
    let f = Fx::new(None).await;
    let (cookie, view) = f.login().await;
    let (_bound, services) = services(&f).await;
    let router = crate::app::build_routers(&services).unwrap().gateway;
    let expected = services
        .store
        .admin_human_subject(
            "native-human".into(),
            view.session.user_id.as_str().into(),
            crate::store::Deadline(std::time::Instant::now() + Duration::from_secs(1)),
        )
        .await
        .unwrap()
        .unwrap();
    for private_capture in [false, true] {
        let mut request = axum::http::Request::builder()
            .uri("/_hopae/verify")
            .body(axum::body::Body::empty())
            .unwrap();
        for header in headers(&cookie) {
            request.headers_mut().append(
                axum::http::HeaderName::from_bytes(header.name.as_bytes()).unwrap(),
                axum::http::HeaderValue::from_bytes(&header.value).unwrap(),
            );
        }
        request
            .headers_mut()
            .insert("x-hopae-gateway-key", CALLER.parse().unwrap());
        request.headers_mut().insert(
            "x-hopae-human-policy-subject",
            "human1:forged".parse().unwrap(),
        );
        request
            .headers_mut()
            .insert("x-hopae-human-policy-issuer", "forged".parse().unwrap());
        if private_capture {
            request.extensions_mut().insert(capture(&f, &services));
        }
        let response = router.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        assert_eq!(response.headers()["x-hopae-human-policy-subject"], expected);
        assert_eq!(
            response.headers()["x-hopae-human-policy-issuer"],
            "native-human"
        );
        assert_eq!(
            response
                .headers()
                .get_all("x-hopae-human-policy-subject")
                .iter()
                .count(),
            1
        );
        assert_eq!(
            response.headers()["x-forwarded-user"],
            view.session.user_id.as_str()
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_human_rpc_legacy_uid_verify_allows_without_metadata_source_refuses() {
    use tower::ServiceExt;
    let f = Fx::new(None).await;
    let (_, original) = f.login().await;
    let legacy = "u_legacy\n";
    f.sql(&format!(
        "INSERT INTO users(user_id,created_at,updated_at) VALUES('{legacy}',0,0)"
    ));
    f.sql(&format!(
        "UPDATE identities SET user_id='{legacy}' WHERE user_id='{}'",
        original.session.user_id.as_str()
    ));
    assert_eq!(
        f.count(&format!(
            "SELECT count(*) FROM identities WHERE user_id='{legacy}'"
        )),
        1
    );
    // Fresh actual provider authentication creates the native session/provenance.
    let (cookie, view) = f.login().await;
    assert_eq!(view.session.user_id.as_str(), legacy);
    let (_bound, services) = services(&f).await;
    let router = crate::app::build_routers(&services).unwrap().gateway;
    let mut request = axum::http::Request::builder()
        .uri("/_hopae/verify")
        .body(axum::body::Body::empty())
        .unwrap();
    for header in headers(&cookie) {
        request.headers_mut().append(
            axum::http::HeaderName::from_bytes(header.name.as_bytes()).unwrap(),
            axum::http::HeaderValue::from_bytes(&header.value).unwrap(),
        );
    }
    request
        .headers_mut()
        .insert("x-hopae-gateway-key", CALLER.parse().unwrap());
    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    assert!(
        !response
            .headers()
            .contains_key("x-hopae-human-policy-subject")
    );
    assert!(
        !response
            .headers()
            .contains_key("x-hopae-human-policy-issuer")
    );
    assert!(response.headers().contains_key("x-forwarded-user"));
    let mut request = raw(&cookie);
    request.extensions_mut().insert(capture(&f, &services));
    assert!(
        crate::http::grpc_human::direct_issue_fixture(&services, request)
            .await
            .is_err()
    );
}
