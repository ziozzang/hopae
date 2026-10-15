//! Actual authenticated TLS TokenReview -> gateway -> native Workload RPC.
//! Owned mock API; no claim to validate real Kubernetes JWT signatures here.
use super::*;
use crate::{
    auth_gateway::{authority, receipt_config, receipt_keys, runtime},
    crypto::Rng,
};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use std::{
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use v1::workload_authentication_receipts_client::WorkloadAuthenticationReceiptsClient;
const CALLER: &str = "owned-workload-gateway-caller-at-least-thirty-two";
struct DelayRng(AtomicBool);
impl Rng for DelayRng {
    fn fill(&self, bytes: &mut [u8]) {
        if self.0.swap(false, Ordering::AcqRel) {
            std::thread::sleep(Duration::from_millis(300));
        }
        crate::crypto::OsRng.fill(bytes);
    }
}
struct Fixture {
    _bound: crate::app::Bound,
    root: tempfile::TempDir,
    api: std::process::Child,
    services: crate::app::Services,
    client: WorkloadAuthenticationReceiptsClient<tonic::transport::Channel>,
    stop: watch::Sender<bool>,
    server: tokio::task::JoinHandle<anyhow::Result<()>>,
    rng: Arc<DelayRng>,
    credential: String,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.stop.send(true);
        self.server.abort();
        let _ = self.api.kill();
        let _ = self.api.wait();
    }
}
impl Fixture {
    async fn start(capacity: usize) -> Self {
        let root = tempfile::tempdir().unwrap();
        let openssl = |args: &[&str]| {
            assert!(
                std::process::Command::new("openssl")
                    .args(args)
                    .current_dir(root.path())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status()
                    .unwrap()
                    .success()
            );
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
            "/CN=Owned Workload CA",
            "-keyout",
            "ca.key",
            "-out",
            "ca.pem",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
        ]);
        openssl(&[
            "req",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-subj",
            "/CN=localhost",
            "-keyout",
            "server.key",
            "-out",
            "server.csr",
        ]);
        std::fs::write(root.path().join("extensions"),"basicConstraints=critical,CA:FALSE\nsubjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth,clientAuth\n").unwrap();
        openssl(&[
            "x509",
            "-req",
            "-in",
            "server.csr",
            "-CA",
            "ca.pem",
            "-CAkey",
            "ca.key",
            "-CAcreateserial",
            "-days",
            "1",
            "-extfile",
            "extensions",
            "-out",
            "server.pem",
        ]);
        std::fs::write(root.path().join("mode"), "valid").unwrap();
        let api = std::process::Command::new("python3")
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tools/owned_kubernetes_verifier.py"
            ))
            .arg(root.path())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        for _ in 0..500 {
            if root.path().join("ready").exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let port = std::fs::read_to_string(root.path().join("ready")).unwrap();
        let ca = std::fs::read_to_string(root.path().join("ca.pem")).unwrap();
        let value = serde_json::json!({"state_dir":root.path().join("state"),"listen":{"portal":"127.0.0.1:0","gateway":"127.0.0.1:0"},"portal":{"public_url":"https://auth.example.test"},"gateway":{"kind":"hangang","caller_key_env":"OWNED_CALLER","verify_budget_ms":2000},"apps":[{"app_id":"orders","hosts":["orders.example.test"]}]});
        let config = crate::config::parse(&value.to_string()).unwrap();
        let bound = crate::app::bind(&config).await.unwrap();
        let mut services = bound.services().clone();
        services.caller_keys = Arc::new(CallerKeys::from_env(&config, |_| Some(CALLER.into())));
        let runtime:runtime::Config=serde_json::from_value(serde_json::json!({"authority_id":"owned","profiles":[{"service_id":"orders","host":"orders.example.test","ports":[443],"realm":"example-cluster","api_keys":[{"token_env":"OWNED_LOCAL_KEY","subject":"worker"}],"kubernetes_tokenreview":{"connection":{"api_origin":format!("https://127.0.0.1:{port}"),"issuer":"https://issuer.example.test","cluster_id":"example-cluster","audience":"orders-workload","namespaces":["blue"],"timeout_ms":1000},"ca_pem_env":"OWNED_KUBE_CA","reviewer_token_env":"OWNED_KUBE_REVIEWER","token_prefix":"k8s:"},"networks":["203.0.113.0/24"]}]})).unwrap();
        let env = |name: &str| match name {
            "OWNED_KUBE_CA" => Some(ca.clone()),
            "OWNED_KUBE_REVIEWER" => Some("owned-kubernetes-reviewer-at-least-thirty-two".into()),
            "OWNED_LOCAL_KEY" => Some("owned-local-service-key-at-least-thirty-two".into()),
            _ => None,
        };
        let owner = authority::Authority::load(
            &mut services.store.conn(),
            Some(runtime),
            &env,
            &|_| Ok(()),
        )
        .unwrap();
        services.authentication_authority = Some(Arc::new(Mutex::new(owner)));
        let public = ed25519_dalek::SigningKey::from_bytes(&[7; 32])
            .verifying_key()
            .to_bytes();
        let issuer:receipt_config::NativeIssuer=serde_json::from_value(serde_json::json!({"issuer_ref":"owned-workload","key_epoch":1,"identity_authority_epoch":"owned-workload-authority","public_key":STANDARD.encode(public),"seed_env":"OWNED_SYNTHETIC_SEED","scopes":[{"service":"orders","audience":"orders-api"}],"workload_receipts":{"scopes":[{"service":"orders","audience":"orders-api"}],"capacity":capacity}})).unwrap();
        let rng = Arc::new(DelayRng(AtomicBool::new(false)));
        services.receipt_issuer = Some(Arc::new(
            issuer
                .load(
                    &|_| Some(STANDARD.encode([7; 32])),
                    services.clock.clone(),
                    rng.clone(),
                )
                .unwrap(),
        ));
        services
            .receipt_authority
            .lock()
            .unwrap()
            .reconcile(
                &mut services.store.conn(),
                &[receipt_keys::Key {
                    issuer_ref: "owned-workload".into(),
                    purpose: hopae_grpc::receipt::Purpose::Authentication,
                    epoch: 1,
                    public_key: public,
                }],
                "test-bootstrap",
                &|_| Ok(()),
            )
            .unwrap();
        let router = crate::app::build_routers(&services).unwrap().gateway;
        let cert = std::fs::read(root.path().join("server.pem")).unwrap();
        let key = std::fs::read(root.path().join("server.key")).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let tls = ServerTlsConfig::new()
            .identity(tonic::transport::Identity::from_pem(&cert, &key))
            .client_ca_root(tonic::transport::Certificate::from_pem(ca.clone()));
        let (stop, rx) = watch::channel(false);
        let keys = services.caller_keys.clone();
        let resources = services.clone();
        let server = tokio::spawn(serve_with_receipts(
            listener,
            tls,
            router,
            keys,
            rx,
            Some(resources),
        ));
        let channel = tonic::transport::Endpoint::from_shared(format!("https://{addr}"))
            .unwrap()
            .tls_config(
                tonic::transport::ClientTlsConfig::new()
                    .domain_name("localhost")
                    .ca_certificate(tonic::transport::Certificate::from_pem(ca))
                    .identity(tonic::transport::Identity::from_pem(cert, key)),
            )
            .unwrap()
            .connect()
            .await
            .unwrap();
        let claims = serde_json::json!({"iss":"https://issuer.example.test","sub":"system:serviceaccount:blue:worker","aud":["orders-workload"],"exp":(services.clock.now().0 as u64+60000)/1000,"kubernetes.io":{"namespace":"blue","serviceaccount":{"name":"worker","uid":"sa-1"},"pod":{"name":"worker-pod","uid":"pod-1"}}});
        let credential = format!(
            "k8s:{}.{}.{}",
            URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256"}"#),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap()),
            URL_SAFE_NO_PAD.encode([1; 32])
        );
        Self {
            _bound: bound,
            root,
            api,
            services,
            client: WorkloadAuthenticationReceiptsClient::new(channel),
            stop,
            server,
            rng,
            credential,
        }
    }
    fn request(&self) -> Request<v1::WorkloadReceiptRequest> {
        let headers = [
            ("x-hopae-contract", "1"),
            ("x-forwarded-host", "orders.example.test"),
            ("x-forwarded-proto", "https"),
            ("x-forwarded-port", "443"),
            ("x-forwarded-for", "203.0.113.9"),
            ("x-original-method", "GET"),
            ("x-original-url", "https://orders.example.test/reports"),
        ];
        let mut fields: Vec<_> = headers
            .into_iter()
            .map(|(n, v)| Header {
                name: n.into(),
                value: v.as_bytes().to_vec(),
            })
            .collect();
        fields.push(Header {
            name: "authorization".into(),
            value: format!("Bearer {}", self.credential).into_bytes(),
        });
        let mut r = Request::new(v1::WorkloadReceiptRequest {
            verification: Some(VerifyRequest {
                request_id: 41,
                headers: fields,
            }),
            service: "orders".into(),
            audience: "orders-api".into(),
            request_sha256: vec![9; 32],
        });
        r.metadata_mut()
            .insert("authorization", format!("Bearer {CALLER}").parse().unwrap());
        r
    }
    fn observation(
        receipt: &v1::WorkloadReceiptReply,
    ) -> Request<v1::WorkloadReceiptObservationRequest> {
        let c = receipt.context.clone().unwrap();
        let mut r = Request::new(v1::WorkloadReceiptObservationRequest {
            request_id: 42,
            request_sha256: c.request_sha256.clone(),
            context: Some(c),
            receipt: receipt.receipt.clone(),
        });
        r.metadata_mut()
            .insert("authorization", format!("Bearer {CALLER}").parse().unwrap());
        r
    }
    async fn held(&self) {
        for _ in 0..500 {
            if self.root.path().join("entered").exists() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        panic!("TokenReview did not enter");
    }
}
#[tokio::test]
async fn native_workload_receipt_and_observation_keep_class_original_age_and_owner() {
    let mut f = Fixture::start(4).await;
    let reply = f
        .client
        .issue_observed(f.request())
        .await
        .unwrap()
        .into_inner();
    let receipt = reply.receipt.unwrap();
    let initial = reply.observation.unwrap();
    let c = receipt.context.as_ref().unwrap();
    assert_eq!(c.identity.as_ref().unwrap().kind, 3);
    assert_eq!(c.identity.as_ref().unwrap().aal, 0);
    assert_eq!(
        c.identity.as_ref().unwrap().subject_ref,
        "s_529be5b595ab327853eabe2d1adf52256e262af036510607"
    );
    assert_eq!(
        hopae_grpc::workload_epoch::decode(&c.identity_authority_epoch)
            .unwrap()
            .clock_domain,
        initial.clock_domain
    );
    assert_eq!(
        std::fs::read_to_string(f.root.path().join("calls")).unwrap(),
        "1"
    );
    let next = f
        .client
        .observe_time(Fixture::observation(&receipt))
        .await
        .unwrap()
        .into_inner();
    assert!(next.remaining_ms <= initial.remaining_ms);
    // Native local key remains Service and must never become Workload through this RPC.
    let mut local = f.request();
    local
        .get_mut()
        .verification
        .as_mut()
        .unwrap()
        .headers
        .last_mut()
        .unwrap()
        .value = b"Bearer owned-local-service-key-at-least-thirty-two".to_vec();
    assert!(f.client.issue_observed(local).await.is_err());
    let mut forged = Fixture::observation(&receipt);
    forged
        .get_mut()
        .context
        .as_mut()
        .unwrap()
        .identity
        .as_mut()
        .unwrap()
        .kind = 2;
    assert!(f.client.observe_time(forged).await.is_err());
    // Same-content new application Arc retires original source record permanently.
    let app = f.services.snapshot.load_full();
    f.services.snapshot.store(Arc::new((*app).clone()));
    assert!(
        f.client
            .observe_time(Fixture::observation(&receipt))
            .await
            .is_err()
    );
    f.services.snapshot.store(app);
    assert!(
        f.client
            .observe_time(Fixture::observation(&receipt))
            .await
            .is_err()
    );
}
#[tokio::test]
async fn slow_actual_tokenreview_does_not_receive_a_fresh_signing_second() {
    let mut f = Fixture::start(4).await;
    std::fs::write(f.root.path().join("mode"), "hold").unwrap();
    let mut client = f.client.clone();
    let request = f.request();
    let task = tokio::spawn(async move { client.issue_observed(request).await });
    f.held().await;
    tokio::time::sleep(Duration::from_millis(800)).await;
    std::fs::write(f.root.path().join("release"), "yes").unwrap();
    let reply = task.await.unwrap().unwrap().into_inner();
    let report = reply.observation.unwrap();
    assert!(report.remaining_ms <= 200);
    tokio::time::sleep(Duration::from_millis(220)).await;
    assert!(
        f.client
            .observe_time(Fixture::observation(&reply.receipt.unwrap()))
            .await
            .is_err()
    );
}
#[tokio::test]
async fn sign_callback_and_capacity_refuse_without_reanchoring_native_proof() {
    let mut f = Fixture::start(1).await;
    std::fs::write(f.root.path().join("mode"), "hold").unwrap();
    let mut client = f.client.clone();
    let request = f.request();
    let task = tokio::spawn(async move { client.issue_observed(request).await });
    f.held().await;
    assert!(f.client.issue_observed(f.request()).await.is_err());
    assert_eq!(
        std::fs::read_to_string(f.root.path().join("calls")).unwrap(),
        "1"
    );
    tokio::time::sleep(Duration::from_millis(750)).await;
    f.rng.0.store(true, Ordering::Release);
    std::fs::write(f.root.path().join("release"), "yes").unwrap();
    assert!(task.await.unwrap().is_err()); // 300ms RNG callback crosses ORIGINAL1000ms
}

fn context(c: &v1::AuthenticationReceiptContext) -> hopae_grpc::receipt_binding::Context<'_> {
    let i = c.identity.as_ref().unwrap();
    hopae_grpc::receipt_binding::Context {
        issuer_ref: &c.issuer_ref,
        key_epoch: c.key_epoch,
        identity_authority_epoch: &c.identity_authority_epoch,
        identity: hopae_grpc::receipt_binding::Identity {
            subject_ref: &i.subject_ref,
            kind: hopae_grpc::PrincipalKind::Workload,
            aal: 0,
            revision: i.revision,
            credential_generation: i.credential_generation,
        },
        service: &c.service,
        audience: &c.audience,
        request_sha256: c.request_sha256.as_slice().try_into().unwrap(),
    }
}
#[tokio::test]
async fn valid_signature_without_native_record_and_strict_utc_paths_refuse() {
    let mut f = Fixture::start(4).await;
    let reply = f
        .client
        .issue_observed(f.request())
        .await
        .unwrap()
        .into_inner();
    let receipt = reply.receipt.unwrap();
    let report = reply.observation.unwrap();
    let c = context(receipt.context.as_ref().unwrap());
    let binding = hopae_grpc::receipt_binding::digest(&c, None).unwrap();
    let signer = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
    let checked = hopae_grpc::receipt::verify_signature(
        &signer.verifying_key(),
        &receipt.receipt,
        hopae_grpc::receipt::Purpose::Authentication,
        &binding,
    )
    .unwrap();
    let verifier = f.services.receipt_authority.lock().unwrap().verifier();
    assert!(
        verifier
            .verify(&c, None, &receipt.receipt, report.owner_now_ms)
            .is_err()
    );
    let missing = hopae_grpc::receipt::sign(
        &signer,
        &hopae_grpc::receipt::Claims {
            purpose: hopae_grpc::receipt::Purpose::Authentication,
            issued_ms: checked.claims().issued_ms,
            expires_ms: checked.claims().issued_ms + 1000,
            binding,
            nonce: [42; 32],
        },
    )
    .unwrap();
    let mut observation = Fixture::observation(&receipt);
    observation.get_mut().receipt = missing.to_vec();
    assert!(f.client.observe_time(observation).await.is_err());
    assert!(
        f.client
            .observe_time(Fixture::observation(&receipt))
            .await
            .is_ok()
    );
    // A different process owner with the same key/config has no record/domain grant.
    let issuer:receipt_config::NativeIssuer=serde_json::from_value(serde_json::json!({"issuer_ref":"owned-workload","key_epoch":1,"identity_authority_epoch":"owned-workload-authority","public_key":STANDARD.encode(signer.verifying_key().to_bytes()),"seed_env":"OWNED_SYNTHETIC_SEED","scopes":[{"service":"orders","audience":"orders-api"}],"workload_receipts":{"scopes":[{"service":"orders","audience":"orders-api"}],"capacity":4}})).unwrap();
    let restarted = issuer
        .load(
            &|_| Some(STANDARD.encode([7; 32])),
            f.services.clock.clone(),
            Arc::new(crate::crypto::OsRng),
        )
        .unwrap();
    assert!(
        restarted
            .observe_workload(&c, &receipt.receipt, &[9; 32], &verifier)
            .is_err()
    );
}
#[tokio::test]
async fn native_source_denial_and_profile_retirement_during_tokenreview_cannot_publish() {
    let mut f = Fixture::start(1).await;
    for (index, mode) in ["denied", "wrong-uid", "unavailable"]
        .into_iter()
        .enumerate()
    {
        std::fs::write(f.root.path().join("mode"), mode).unwrap();
        assert!(f.client.issue_observed(f.request()).await.is_err());
        assert_eq!(
            std::fs::read_to_string(f.root.path().join("calls")).unwrap(),
            (index + 1).to_string()
        );
    }
    std::fs::write(f.root.path().join("mode"), "hold").unwrap();
    let mut client = f.client.clone();
    let request = f.request();
    let task = tokio::spawn(async move { client.issue_observed(request).await });
    f.held().await;
    f.services
        .authentication_authority
        .as_ref()
        .unwrap()
        .lock()
        .unwrap()
        .publish(
            &mut f.services.store.conn(),
            1,
            None,
            "test-withdrawal",
            &|_| None,
            &|_| Ok(()),
        )
        .unwrap();
    std::fs::write(f.root.path().join("release"), "yes").unwrap();
    assert!(task.await.unwrap().is_err());
}

#[tokio::test]
async fn application_replacement_during_actual_tokenreview_refuses_old_capture() {
    let f = Fixture::start(4).await;
    std::fs::write(f.root.path().join("mode"), "hold").unwrap();
    let mut client = f.client.clone();
    let request = f.request();
    let task = tokio::spawn(async move { client.issue_observed(request).await });
    f.held().await;
    let app = f.services.snapshot.load_full();
    f.services.snapshot.store(Arc::new((*app).clone()));
    std::fs::write(f.root.path().join("release"), "yes").unwrap();
    assert!(task.await.unwrap().is_err());
}
