//! Actual HTTPS provider exchanges; synthetic credentials and owned CA only.
use super::super::composition::{Credential, Mode};
use super::*;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU64, Ordering},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
const LOCAL: &str = "synthetic-local-service-key-at-least-thirty-two";
const REMOTE: &str = "synthetic-remote-service-key-at-least-thirty-two";
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}
fn envelope(entries: &[(&str, &str)]) -> String {
    URL_SAFE_NO_PAD.encode(serde_json::to_vec(&serde_json::json!({"version":1,"credentials":entries.iter().map(|(slot,credential)|serde_json::json!({"slot":slot,"credential":credential})).collect::<Vec<_>>()})).unwrap())
}
struct Peer {
    root: tempfile::TempDir,
    ca: Vec<u8>,
    address: String,
    requests: Arc<Mutex<Vec<Vec<u8>>>>,
    delay: Arc<AtomicU64>,
    server: tokio::task::JoinHandle<()>,
}
impl Drop for Peer {
    fn drop(&mut self) {
        self.server.abort();
    }
}
impl Peer {
    async fn start() -> Self {
        Self::start_certificate(false).await
    }
    async fn start_certificate(wrong_name: bool) -> Self {
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
            "-keyout",
            "ca.key",
            "-out",
            "ca.pem",
            "-days",
            "1",
            "-subj",
            "/CN=Owned composition CA",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
        ]);
        openssl(&[
            "req",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            "server.key",
            "-out",
            "server.csr",
            "-subj",
            "/CN=localhost",
        ]);
        std::fs::write(root.path().join("extensions"),(if wrong_name { "subjectAltName=DNS:wrong.example.test\nbasicConstraints=critical,CA:FALSE\nextendedKeyUsage=serverAuth,clientAuth\n" } else { "subjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=critical,CA:FALSE\nextendedKeyUsage=serverAuth,clientAuth\n" }).as_bytes()).unwrap();
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
            "-out",
            "server.pem",
            "-days",
            "1",
            "-extfile",
            "extensions",
        ]);
        let ca = std::fs::read(root.path().join("ca.pem")).unwrap();
        let cert = std::fs::read(root.path().join("server.pem")).unwrap();
        let key = std::fs::read(root.path().join("server.key")).unwrap();
        let certs = rustls_pemfile::certs(&mut cert.as_slice())
            .collect::<std::io::Result<Vec<_>>>()
            .unwrap();
        let key = rustls_pemfile::private_key(&mut key.as_slice())
            .unwrap()
            .unwrap();
        let tls = tokio_rustls::TlsAcceptor::from(Arc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .unwrap(),
        ));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = format!("https://{}/verify", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let seen = requests.clone();
        let delay = Arc::new(AtomicU64::new(0));
        let pause = delay.clone();
        let server = tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                let tls = tls.clone();
                let seen = seen.clone();
                let pause = pause.clone();
                tokio::spawn(async move {
                    let Ok(mut socket) = tls.accept(socket).await else {
                        return;
                    };
                    let mut bytes = Vec::new();
                    let header_end;
                    loop {
                        let mut chunk = [0; 4096];
                        let n = socket.read(&mut chunk).await.unwrap_or(0);
                        if n == 0 {
                            return;
                        }
                        bytes.extend_from_slice(&chunk[..n]);
                        if bytes.len() > 8192 {
                            return;
                        }
                        if let Some(at) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                            header_end = at + 4;
                            break;
                        }
                    }
                    let headers = String::from_utf8_lossy(&bytes[..header_end]);
                    let size = headers
                        .lines()
                        .find_map(|line| {
                            line.to_ascii_lowercase()
                                .strip_prefix("content-length: ")
                                .and_then(|n| n.parse::<usize>().ok())
                        })
                        .unwrap_or(0);
                    while bytes.len() < header_end + size {
                        let mut chunk = [0; 4096];
                        let n = socket.read(&mut chunk).await.unwrap_or(0);
                        if n == 0 {
                            return;
                        }
                        bytes.extend_from_slice(&chunk[..n]);
                        if bytes.len() > 8192 {
                            return;
                        }
                    }
                    let valid =
                        String::from_utf8_lossy(&bytes).contains(&format!("Bearer {REMOTE}"));
                    seen.lock().unwrap().push(bytes);
                    tokio::time::sleep(std::time::Duration::from_millis(
                        pause.load(Ordering::Acquire),
                    ))
                    .await;
                    let body=serde_json::to_vec(&serde_json::json!({"active":valid,"subject":"partner-worker","service_id":"orders","expires_at":now()+900})).unwrap();
                    let response = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = socket.write_all(response.as_bytes()).await;
                    let _ = socket.write_all(&body).await;
                    let _ = socket.shutdown().await;
                });
            }
        });
        Self {
            root,
            ca,
            address,
            requests,
            delay,
            server,
        }
    }
    fn config(&self, mode: &str) -> Config {
        serde_json::from_value(serde_json::json!({"authority_id":"owned","profiles":[{"service_id":"orders","host":"api.example.test","ports":[443],"realm":"services","api_keys":[{"token_env":"OWNED_LOCAL","subject":"worker"},{"token_env":"OWNED_OTHER","subject":"other"}],"api_relay":{"url":self.address,"ca_file":self.root.path().join("ca.pem"),"issuer":"partner-directory","timeout_ms":500,"allow_private_endpoints":true,"verifier_key_env":"OWNED_VERIFIER"},"networks":["192.0.2.0/24"],"composition":{"mode":mode,"timeout_ms":500,"slots":[{"id":"local","provider":"api_key"},{"id":"partner","provider":"api_relay"}],"identities":[{"subject":"worker","bindings":[{"slot":"local","issuer":"hopae:owned","realm":"services","subject":"worker","kind":"service"},{"slot":"partner","issuer":"partner-directory","realm":"services","subject":"partner-worker","kind":"service"}]},{"subject":"other","bindings":[{"slot":"local","issuer":"hopae:owned","realm":"services","subject":"other","kind":"service"},{"slot":"partner","issuer":"partner-directory","realm":"services","subject":"partner-other","kind":"service"}]}]}}]})).unwrap()
    }
    fn runtime(&self, config: &Config) -> Runtime {
        Runtime::compile(config, &|name| {
            Some(
                match name {
                    "OWNED_LOCAL" => LOCAL,
                    "OWNED_OTHER" => "synthetic-other-local-key-at-least-thirty-two",
                    _ => "synthetic-verifier-caller-at-least-thirty-two",
                }
                .into(),
            )
        })
        .unwrap()
    }

    fn count(&self) -> usize {
        self.requests.lock().unwrap().len()
    }
}
async fn authenticate(runtime: &Runtime, encoded: &str) -> Result<VerifiedEvidence, Error> {
    let stamp = super::super::composition::EntryTime::capture(&crate::crypto::SystemClock).unwrap();
    runtime
        .authenticate_credential_async(
            "api.example.test",
            443,
            Some(Credential::Composite(encoded)),
            "192.0.2.9".parse().unwrap(),
            now(),
            Some(&stamp),
        )
        .await
}
#[tokio::test]
async fn composition_actual_https_all_any_ambiguity_and_credential_isolation() {
    let peer = Peer::start().await;
    let cfg = peer.config("all");
    let runtime = peer.runtime(&cfg);
    let encoded = envelope(&[("partner", REMOTE), ("local", LOCAL)]);
    let checked = authenticate(&runtime, &encoded).await.unwrap();
    assert_eq!(checked.subject.kind, PrincipalKind::Service);
    assert_eq!(checked.subject.subject, "worker");
    assert_eq!(checked.connector, "composition:local+partner");
    assert_eq!(checked.service(), Some("orders"));
    let request = peer.requests.lock().unwrap()[0].clone();
    let request = String::from_utf8_lossy(&request);
    assert!(request.contains(REMOTE));
    assert!(!request.contains(LOCAL));
    assert!(!request.contains(&encoded));
    assert!(!request.to_ascii_lowercase().contains("x-forwarded-user"));
    assert!(
        authenticate(&runtime, &envelope(&[("local", LOCAL)]))
            .await
            .is_err()
    );
    assert_eq!(peer.count(), 1);
    assert!(
        runtime
            .authenticate_async(
                "api.example.test",
                443,
                Some(LOCAL),
                "192.0.2.9".parse().unwrap(),
                now()
            )
            .await
            .is_err()
    );
    assert!(
        runtime
            .authenticate(
                "api.example.test",
                443,
                Some(LOCAL),
                "192.0.2.9".parse().unwrap(),
                now()
            )
            .is_err()
    );
    let mut cfg = cfg;
    cfg.profiles[0].composition.as_mut().unwrap().mode = Mode::Any;
    let runtime = peer.runtime(&cfg);
    authenticate(&runtime, &envelope(&[("local", LOCAL)]))
        .await
        .unwrap();
    assert_eq!(peer.count(), 1);
    authenticate(&runtime, &envelope(&[("partner", REMOTE)]))
        .await
        .unwrap();
    assert_eq!(peer.count(), 2);
    assert!(
        authenticate(
            &runtime,
            &envelope(&[
                ("local", "synthetic-other-local-key-at-least-thirty-two"),
                ("partner", REMOTE)
            ])
        )
        .await
        .is_err(),
        "successful siblings with different canonical principals must refuse"
    );
    let before = peer.count();
    assert!(
        authenticate(
            &runtime,
            &envelope(&[
                ("local", "invalid-but-long-local-key-at-least-thirty-two"),
                ("partner", REMOTE)
            ])
        )
        .await
        .is_err()
    );
    assert_eq!(
        peer.count(),
        before,
        "a presented failure never silently falls back"
    );
    assert!(peer.root.path().exists());
}
#[tokio::test]
async fn composition_original_short_budget_cancellation_capacity_and_circuit_retention() {
    let peer = Peer::start().await;
    let mut cfg = peer.config("all");
    cfg.profiles[0].api_keys[0].expires_at = Some(now() + 150);
    let runtime = peer.runtime(&cfg);
    peer.delay.store(220, Ordering::Release);
    assert!(
        authenticate(
            &runtime,
            &envelope(&[("local", LOCAL), ("partner", REMOTE)])
        )
        .await
        .is_err(),
        "later verified remote branch cannot renew original local expiry"
    );
    assert_eq!(
        peer.count(),
        1,
        "test must verify the later branch, not just reject an already expired input"
    );
    let cfg = peer.config("all");
    let runtime = Arc::new(peer.runtime(&cfg));
    peer.delay.store(1000, Ordering::Release);
    let encoded = envelope(&[("local", LOCAL), ("partner", REMOTE)]);
    for _ in 0..3 {
        let r = runtime.clone();
        let e = encoded.clone();
        let before = peer.count();
        let task = tokio::spawn(async move { authenticate(&r, &e).await });
        tokio::time::timeout(std::time::Duration::from_millis(300), async {
            while peer.count() == before {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
    }
    assert_eq!(runtime.connector_status()[0].circuit, "open");
    assert_eq!(runtime.connector_status()[0].available_capacity, 64);
    let p = &runtime.profiles["api.example.test"][&443];
    assert_eq!(
        p.composition.as_ref().unwrap().capacity.available_permits(),
        32
    );
    let resumed = Runtime::compile_resuming(
        &cfg,
        &|name| {
            Some(
                match name {
                    "OWNED_LOCAL" => LOCAL,
                    "OWNED_OTHER" => "synthetic-other-local-key-at-least-thirty-two",
                    _ => "synthetic-verifier-caller-at-least-thirty-two",
                }
                .into(),
            )
        },
        Some(&runtime),
    )
    .unwrap();
    assert_eq!(resumed.connector_status()[0].circuit, "open");
    let before = peer.count();
    assert!(authenticate(&resumed, &encoded).await.is_err());
    assert_eq!(peer.count(), before);
    let held = p
        .composition
        .as_ref()
        .unwrap()
        .capacity
        .acquire_many(32)
        .await
        .unwrap();
    let before = peer.count();
    assert!(authenticate(&runtime, &encoded).await.is_err());
    assert_eq!(peer.count(), before);
    drop(held);
}
#[tokio::test]
async fn composition_wire_and_relationship_validation_fail_before_provider_io() {
    let peer = Peer::start().await;
    let original = peer.config("all");
    for mutate in [
        |c: &mut Config| {
            c.profiles[0].composition.as_mut().unwrap().identities[0].bindings[0].kind =
                "human".into()
        },
        |c: &mut Config| {
            c.profiles[0].composition.as_mut().unwrap().identities[0].bindings[1].realm =
                "other".into()
        },
        |c: &mut Config| {
            c.profiles[0].composition.as_mut().unwrap().identities[0].bindings[1].issuer =
                "wrong".into()
        },
        |c: &mut Config| {
            c.profiles[0].composition.as_mut().unwrap().identities[1].bindings[1].subject =
                "partner-worker".into()
        },
        |c: &mut Config| c.profiles[0].session_fallback = true,
        |c: &mut Config| {
            c.profiles[0].api_relay.as_mut().unwrap().url = "http://127.0.0.1/verify".into()
        },
        |c: &mut Config| c.profiles[0].composition.as_mut().unwrap().timeout_ms = 1001,
    ] {
        let mut c = original.clone();
        mutate(&mut c);
        assert!(c.validate().is_err());
    }
    let runtime = peer.runtime(&original);
    for encoded in [
        envelope(&[("local", LOCAL), ("local", LOCAL)]),
        envelope(&[("local", LOCAL), ("unknown", REMOTE)]),
        "x".repeat(4097),
        URL_SAFE_NO_PAD.encode(br#"{"version":1,"credentials":[],"identity":"forged"}"#),
    ] {
        assert!(authenticate(&runtime, &encoded).await.is_err());
    }
    assert_eq!(peer.count(), 0);
    assert!(
        authenticate(&runtime, &envelope(&[("local", LOCAL), ("partner", LOCAL)]))
            .await
            .is_err()
    );
    assert_eq!(
        peer.count(),
        0,
        "a declared remote slot cannot disclose a recognized native credential"
    );
    let encoded = envelope(&[("local", LOCAL), ("partner", REMOTE)]);
    assert!(
        runtime
            .authenticate_credential_async(
                "api.example.test",
                443,
                Some(Credential::Composite(&encoded)),
                "203.0.113.8".parse().unwrap(),
                now(),
                Some(
                    &super::super::composition::EntryTime::capture(&crate::crypto::SystemClock)
                        .unwrap()
                ),
            )
            .await
            .is_err()
    );
    assert_eq!(peer.count(), 0);
    let mut cross_service = original.clone();
    cross_service.profiles.push(serde_json::from_value(serde_json::json!({"service_id":"billing","host":"billing.example.test","ports":[443],"realm":"billing","api_keys":[{"token_env":"OWNED_BILLING","subject":"billing-worker","expires_at":1}]})).unwrap());
    let cross_service = peer.runtime(&cross_service);
    assert!(
        authenticate(
            &cross_service,
            &envelope(&[
                ("local", LOCAL),
                ("partner", "synthetic-verifier-caller-at-least-thirty-two")
            ])
        )
        .await
        .is_err()
    );
    assert_eq!(
        peer.count(),
        0,
        "expired but still declared keys from another service remain native secrets"
    );
    let mut legacy = original;
    legacy.profiles[0].composition = None;
    legacy.profiles[0].relay_token_prefix = Some("remote:".into());
    let legacy = peer.runtime(&legacy);
    assert!(authenticate(&legacy, &encoded).await.is_err());
    assert_eq!(peer.count(), 0);
}

#[tokio::test]
async fn composition_native_entry_gap_clock_failure_and_wall_steps_do_not_renew() {
    use super::super::composition::EntryTime;
    let peer = Peer::start().await;
    let mut cfg = peer.config("all");
    cfg.profiles[0].api_keys[0].expires_at = Some(now() + 100);
    let runtime = peer.runtime(&cfg);
    let clock = crate::crypto::TestClock::new(crate::crypto::Timestamp(now() as i64));
    let entry = EntryTime::capture(&clock).unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(130)).await;
    let encoded = envelope(&[("local", LOCAL), ("partner", REMOTE)]);
    assert!(
        runtime
            .authenticate_credential_async(
                "api.example.test",
                443,
                Some(Credential::Composite(&encoded)),
                "192.0.2.9".parse().unwrap(),
                entry.entry_ms(),
                Some(&entry)
            )
            .await
            .is_err()
    );
    assert_eq!(
        peer.count(),
        0,
        "a descheduled original native sample must not make an expired local key fresh"
    );
    struct FailingClock(std::sync::atomic::AtomicUsize);
    impl crate::crypto::Clock for FailingClock {
        fn now(&self) -> crate::crypto::Timestamp {
            let n = self.0.fetch_add(1, Ordering::AcqRel);
            crate::crypto::Timestamp(if n >= 2 { -1 } else { now() as i64 })
        }
    }
    let runtime = peer.runtime(&peer.config("all"));
    let clock = FailingClock(std::sync::atomic::AtomicUsize::new(0));
    let entry = EntryTime::capture(&clock).unwrap();
    assert_eq!(
        runtime
            .authenticate_credential_async(
                "api.example.test",
                443,
                Some(Credential::Composite(&encoded)),
                "192.0.2.9".parse().unwrap(),
                entry.entry_ms(),
                Some(&entry)
            )
            .await
            .unwrap_err(),
        Error::Unavailable
    );
    assert_eq!(
        clock.0.load(Ordering::Acquire),
        3,
        "failure follows actual local verification"
    );
    assert_eq!(peer.count(), 0);
}
#[tokio::test]
async fn composition_actual_config_file_loader_rejects_unknown_relationship_keys() {
    let peer = Peer::start().await;
    let profile = peer.config("all");
    let mut value = serde_json::json!({"state_dir":peer.root.path().join("loader-state"),"portal":{"public_url":"https://auth.example.test"},"gateway":{"kind":"hangang","caller_key_env":"OWNED_CALLER"},"apps":[{"app_id":"orders","hosts":["api.example.test"]}],"authentication_gateway":profile});
    let file = peer.root.path().join("config.json");
    std::fs::write(&file, value.to_string()).unwrap();
    crate::config::load(&file).unwrap();
    value["authentication_gateway"]["profiles"][0]["composition"]["identities"][0]["bindings"][0]
        ["client_identity_header"] = serde_json::json!("x-forged-user");
    std::fs::write(&file, value.to_string()).unwrap();
    assert!(
        crate::config::load(&file)
            .err()
            .unwrap()
            .to_string()
            .contains("client_identity_header")
    );
    let encoded = serde_json::to_string(&profile).unwrap();
    let roundtrip: Config = serde_json::from_str(&encoded).unwrap();
    assert_eq!(
        serde_json::to_value(roundtrip).unwrap(),
        serde_json::to_value(profile).unwrap()
    );
}

const CALLER: &str = "synthetic-gateway-caller-at-least-thirty-two";
async fn gateway(
    peer: &Peer,
    config: &Config,
    capture: bool,
    counters: Option<crate::http::gateway::CounterFn>,
    clock: Option<Arc<dyn crate::crypto::Clock>>,
) -> (
    crate::app::Bound,
    axum::Router,
    Arc<arc_swap::ArcSwap<super::super::authority::Snapshot>>,
) {
    let value = serde_json::json!({"state_dir":peer.root.path().join(format!("gateway-state-{capture}")),"listen":{"portal":"127.0.0.1:0","gateway":"127.0.0.1:0"},"portal":{"public_url":"https://auth.example.test"},"gateway":{"kind":"hangang","caller_key_env":"OWNED_CALLER"},"apps":[{"app_id":"orders","hosts":["api.example.test"]}]});
    let config_root = crate::config::parse(&value.to_string()).unwrap();
    let bound = crate::app::bind(&config_root).await.unwrap();
    let mut services = bound.services().clone();
    services.caller_keys = Arc::new(crate::app::CallerKeys::from_env(&config_root, |_| {
        Some(CALLER.into())
    }));
    if let Some(clock) = clock {
        services.clock = clock;
    }
    let reader = Arc::new(arc_swap::ArcSwap::from_pointee(
        super::super::authority::Snapshot {
            publication: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            revision: 1,
            runtime: Some(peer.runtime(config)),
        },
    ));
    let mut state = crate::http::gateway::GatewayState::new(
        crate::gateway::hangang::GatewayConfig::from_config(&config_root),
        services.verify_context(),
        services.caller_keys.clone(),
        16,
        counters,
        None,
    )
    .with_authentication_authority(reader.clone())
    .unwrap();
    if capture {
        state = state.with_service_receipt_capture().unwrap();
    }
    (bound, crate::http::gateway::router(state), reader)
}
fn request(encoded: &str, duplicate: bool) -> axum::http::Request<axum::body::Body> {
    let mut request = axum::http::Request::builder()
        .uri("/_hopae/verify")
        .header("x-hopae-gateway-key", CALLER)
        .header("x-hopae-contract", "1")
        .header("authorization", format!("Hopae-Compose {encoded}"))
        .header("x-forwarded-host", "api.example.test")
        .header("x-forwarded-proto", "https")
        .header("x-forwarded-port", "443")
        .header("x-forwarded-for", "192.0.2.9")
        .header("x-original-method", "GET")
        .header("x-original-url", "https://api.example.test/private")
        .header("x-forwarded-user", "forged-human")
        .header("x-hopae-aal", "3")
        .body(axum::body::Body::empty())
        .unwrap();
    if duplicate {
        request
            .headers_mut()
            .append("authorization", format!("Bearer {LOCAL}").parse().unwrap());
    }
    request
}
#[tokio::test]
async fn composition_actual_http_and_generated_mtls_native_ingress_duplicate_refusal() {
    use tower::ServiceExt;
    let peer = Peer::start().await;
    let (bound, router, reader) = gateway(&peer, &peer.config("all"), true, None, None).await;
    let encoded = envelope(&[("local", LOCAL), ("partner", REMOTE)]);
    let response = router
        .clone()
        .oneshot(request(&encoded, false))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["x-hopae-aal"], "0");
    assert_eq!(response.headers()["x-hopae-principal-kind"], "service");
    assert_ne!(response.headers()["x-forwarded-user"], "forged-human");
    assert!(
        response
            .extensions()
            .get::<Arc<super::super::receipt_issuer::CapturedService>>()
            .is_some()
    );
    // The actual captured composition enters the existing native receipt issuer;
    // only the trusted final request owner supplies transformed request bytes.
    let captured = response
        .extensions()
        .get::<Arc<super::super::receipt_issuer::CapturedService>>()
        .unwrap();
    use base64::engine::general_purpose::STANDARD;
    let signer = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
    let issuer_config = super::super::receipt_config::NativeIssuer {
        issuer_ref: "owned".into(),
        key_epoch: 1,
        identity_authority_epoch: "composition-test".into(),
        public_key: STANDARD.encode(signer.verifying_key().to_bytes()),
        seed_env: "OWNED_SYNTHETIC_SEED".into(),
        workload_receipts: None,
        scopes: vec![super::super::receipt_issuer::Scope {
            service: "orders".into(),
            audience: "orders-api".into(),
        }],
    };
    let issuer = issuer_config
        .load(
            &|_| Some(STANDARD.encode([7; 32])),
            bound.services().clock.clone(),
            bound.services().rng.clone(),
        )
        .unwrap();
    let body_sha256: [u8; 32] = Sha256::digest(b"owned final transformed body").into();
    let digest = hopae_grpc::request_binding::digest(&hopae_grpc::request_binding::Request {
        service: "orders",
        audience: "orders-api",
        method: "POST",
        target: "/internal/orders?view=owned",
        body_sha256: &body_sha256,
    })
    .unwrap();
    let issued = captured
        .issue(
            &issuer,
            &reader,
            &bound.services().snapshot,
            super::super::receipt_issuer::Request {
                service: "orders",
                audience: "orders-api",
                request_sha256: digest,
            },
            &|| Ok(()),
        )
        .unwrap();
    let mut context = issued.context();
    assert_eq!(context.identity.kind, PrincipalKind::Service);
    assert_eq!(context.identity.aal, 0);
    let binding = super::super::receipt_binding::digest(&context, None).unwrap();
    super::super::receipt::verify(
        &signer.verifying_key(),
        issued.bytes(),
        super::super::receipt::Purpose::Authentication,
        &binding,
        now(),
    )
    .unwrap();
    context.request_sha256[0] ^= 1;
    assert!(
        super::super::receipt::verify(
            &signer.verifying_key(),
            issued.bytes(),
            super::super::receipt::Purpose::Authentication,
            &super::super::receipt_binding::digest(&context, None).unwrap(),
            now()
        )
        .is_err()
    );
    let before = peer.count();
    let response = router
        .clone()
        .oneshot(request(&encoded, true))
        .await
        .unwrap();
    assert_eq!(response.status(), 401);
    assert_eq!(peer.count(), before);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = format!("https://{}", listener.local_addr().unwrap());
    let tls = hangang_runtime::configuration(
        &peer.root.path().join("server.pem"),
        &peer.root.path().join("server.key"),
        &peer.root.path().join("ca.pem"),
    )
    .unwrap();
    let service = crate::http::grpc_gateway::authentication_server_for_test(
        router,
        Arc::new(crate::app::CallerKeys::from_env(
            &bound.services().config,
            |_| Some(CALLER.into()),
        )),
    );
    let server = tokio::spawn(async move {
        hangang_runtime::server(tls)
            .unwrap()
            .add_service(service)
            .serve_with_incoming(hangang_runtime::incoming(listener))
            .await
            .unwrap();
    });
    let channel = tonic::transport::Endpoint::from_shared(address)
        .unwrap()
        .tls_config(
            tonic::transport::ClientTlsConfig::new()
                .domain_name("localhost")
                .ca_certificate(tonic::transport::Certificate::from_pem(&peer.ca))
                .identity(tonic::transport::Identity::from_pem(
                    std::fs::read(peer.root.path().join("server.pem")).unwrap(),
                    std::fs::read(peer.root.path().join("server.key")).unwrap(),
                )),
        )
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut client = hopae_grpc::v1::authentication_client::AuthenticationClient::new(channel);
    let native = |duplicate| {
        let source = request(&encoded, duplicate);
        let mut rpc = tonic::Request::new(hopae_grpc::v1::VerifyRequest {
            request_id: 7,
            headers: source
                .headers()
                .iter()
                .filter(|(name, _)| name.as_str() != "x-hopae-gateway-key")
                .map(|(name, value)| hopae_grpc::v1::Header {
                    name: name.to_string(),
                    value: value.as_bytes().to_vec(),
                })
                .collect(),
        });
        rpc.metadata_mut()
            .insert("authorization", format!("Bearer {CALLER}").parse().unwrap());
        rpc
    };
    assert_eq!(
        client
            .verify(native(false))
            .await
            .unwrap()
            .into_inner()
            .status,
        200
    );
    let before = peer.count();
    assert_eq!(
        client
            .verify(native(true))
            .await
            .unwrap()
            .into_inner()
            .status,
        401
    );
    assert_eq!(
        peer.count(),
        before,
        "native duplicate service Authorization must refuse before provider calls"
    );
    server.abort();
}
#[tokio::test]
async fn composition_actual_http_withdrawal_and_post_provider_output_clock_fences() {
    use tower::ServiceExt;
    let peer = Peer::start().await;
    let cfg = peer.config("all");
    let (_bound, router, reader) = gateway(&peer, &cfg, true, None, None).await;
    peer.delay.store(60, Ordering::Release);
    let encoded = envelope(&[("local", LOCAL), ("partner", REMOTE)]);
    let req = request(&encoded, false);
    let before = peer.count();
    let pending = tokio::spawn(async move { router.oneshot(req).await.unwrap() });
    tokio::time::timeout(std::time::Duration::from_millis(300), async {
        while peer.count() == before {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    reader.store(Arc::new(super::super::authority::Snapshot {
        publication: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        revision: 2,
        runtime: None,
    }));
    let response = pending.await.unwrap();
    assert_eq!(response.status(), 503);
    assert!(
        response
            .extensions()
            .get::<Arc<super::super::receipt_issuer::CapturedService>>()
            .is_none()
    );
    drop(_bound);
    peer.delay.store(0, Ordering::Release);
    for capture in [false, true] {
        let mut cfg = peer.config("all");
        cfg.profiles[0].composition.as_mut().unwrap().timeout_ms = 80;
        let clock = Arc::new(crate::crypto::TestClock::new(crate::crypto::Timestamp(
            now() as i64,
        )));
        let changed = clock.clone();
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let hits = calls.clone();
        let counter: crate::http::gateway::CounterFn = Arc::new(move |name, _| {
            if name == "hopae_authentication_gateway_total" {
                hits.fetch_add(1, Ordering::AcqRel);
                std::thread::sleep(std::time::Duration::from_millis(100));
                changed.set(crate::crypto::Timestamp(now() as i64 - 10_000));
            }
        });
        let (_bound, router, _) = gateway(&peer, &cfg, capture, Some(counter), Some(clock)).await;
        let response = router.oneshot(request(&encoded, false)).await.unwrap();
        assert_eq!(calls.load(Ordering::Acquire), 1);
        assert_eq!(
            response.status(),
            503,
            "post-provider descheduling plus wall rollback cannot revive either HTTP identity or captured receipt"
        );
        assert!(!response.headers().contains_key("x-hopae-evidence-ttl-ms"));
        assert!(
            response
                .extensions()
                .get::<Arc<super::super::receipt_issuer::CapturedService>>()
                .is_none()
        );
    }
}

#[tokio::test]
async fn composition_durable_publication_reload_and_invalid_update_preserve_authority() {
    use super::super::{authority::Authority, publication};
    let peer = Peer::start().await;
    let config = peer.config("all");
    let file = peer.root.path().join("authority.sqlite");
    let mut db = rusqlite::Connection::open(&file).unwrap();
    db.execute_batch("CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT NOT NULL)")
        .unwrap();
    let environment = |name: &str| {
        Some(
            match name {
                "OWNED_LOCAL" => LOCAL,
                "OWNED_OTHER" => "synthetic-other-local-key-at-least-thirty-two",
                _ => "synthetic-verifier-caller-at-least-thirty-two",
            }
            .into(),
        )
    };
    let mut owner =
        Authority::load(&mut db, Some(config.clone()), &environment, &|_| Ok(())).unwrap();
    let before = owner.reader().load_full();
    let saved = publication::read(&db).unwrap().unwrap();
    assert_eq!(saved.revision, 1);
    assert_eq!(
        serde_json::to_value(saved.configuration.unwrap()).unwrap(),
        serde_json::to_value(&config).unwrap()
    );
    let mut invalid = config.clone();
    invalid.profiles[0].composition.as_mut().unwrap().identities[0].bindings[1].kind =
        "workload".into();
    assert!(
        owner
            .publish(
                &mut db,
                1,
                Some(invalid),
                "owned-test-operator",
                &environment,
                &|_| Ok(())
            )
            .is_err()
    );
    let mut invalid_ca = config.clone();
    invalid_ca.profiles[0].api_relay.as_mut().unwrap().ca_file = Some(
        peer.root
            .path()
            .join("missing.pem")
            .to_string_lossy()
            .into_owned(),
    );
    assert!(
        owner
            .publish(
                &mut db,
                1,
                Some(invalid_ca),
                "owned-test-operator",
                &environment,
                &|_| Ok(())
            )
            .is_err()
    );
    assert!(before.available());
    assert!(Arc::ptr_eq(&before, &owner.reader().load_full()));
    assert_eq!(publication::read(&db).unwrap().unwrap().revision, 1);
    let encoded: String = db
        .query_row(
            "SELECT value FROM meta WHERE key='authentication_profile_authority_v1'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    for forbidden in [
        LOCAL,
        REMOTE,
        "synthetic-verifier-caller-at-least-thirty-two",
    ] {
        assert!(!encoded.contains(forbidden));
    }
    drop(owner);
    drop(db);
    let mut db = rusqlite::Connection::open(file).unwrap();
    let owner = Authority::load(&mut db, None, &environment, &|_| Ok(())).unwrap();
    let reader = owner.reader();
    let restored = reader.load_full();
    assert_eq!(restored.revision, 1);
    assert!(
        restored.runtime.as_ref().unwrap().profiles["api.example.test"][&443]
            .composition
            .is_some()
    );
}

#[tokio::test]
async fn composition_production_ca_snapshot_refuses_wrong_trust_and_rebinds_owner() {
    let peer = Peer::start().await;
    let config = peer.config("all");
    let runtime = peer.runtime(&config);
    assert!(
        authenticate(
            &runtime,
            &envelope(&[("local", LOCAL), ("partner", REMOTE)])
        )
        .await
        .is_ok()
    );
    let env = |name: &str| {
        Some(
            match name {
                "OWNED_LOCAL" => LOCAL,
                "OWNED_OTHER" => "synthetic-other-local-key-at-least-thirty-two",
                _ => "synthetic-verifier-caller-at-least-thirty-two",
            }
            .to_string(),
        )
    };
    let resumed = Runtime::compile_resuming(&config, &env, Some(&runtime)).unwrap();
    let relay = |r: &Runtime| r.profiles["api.example.test"][&443].relay.clone().unwrap();
    assert!(
        Arc::ptr_eq(&relay(&runtime), &relay(&resumed)),
        "unchanged trust preserves circuit owner"
    );
    let ca_path = peer.root.path().join("ca.pem");
    let original = std::fs::read(&ca_path).unwrap();
    for invalid in [
        Vec::new(),
        b"invalid PEM".to_vec(),
        vec![b'x'; 128 * 1024 + 1],
    ] {
        std::fs::write(&ca_path, invalid).unwrap();
        assert!(Runtime::compile_resuming(&config, &env, Some(&runtime)).is_err());
    }
    std::fs::remove_file(&ca_path).unwrap();
    assert!(Runtime::compile_resuming(&config, &env, Some(&runtime)).is_err());
    let foreign = Peer::start().await;
    std::fs::write(&ca_path, &foreign.ca).unwrap();
    let changed = Runtime::compile_resuming(&config, &env, Some(&runtime)).unwrap();
    assert!(
        !Arc::ptr_eq(&relay(&runtime), &relay(&changed)),
        "changed bytes create separate circuit/trust owner"
    );
    assert!(
        authenticate(
            &changed,
            &envelope(&[("local", LOCAL), ("partner", REMOTE)])
        )
        .await
        .is_err()
    );
    // Existing connector owns its original immutable trust despite path replacement.
    assert!(
        authenticate(
            &runtime,
            &envelope(&[("local", LOCAL), ("partner", REMOTE)])
        )
        .await
        .is_ok()
    );
    std::fs::write(&ca_path, original).unwrap();
    let wrong_name = Peer::start_certificate(true).await;
    assert!(
        authenticate(
            &wrong_name.runtime(&wrong_name.config("all")),
            &envelope(&[("local", LOCAL), ("partner", REMOTE)])
        )
        .await
        .is_err()
    );
    assert_eq!(
        wrong_name.count(),
        0,
        "hostname refusal precedes HTTP credential delivery"
    );
}
