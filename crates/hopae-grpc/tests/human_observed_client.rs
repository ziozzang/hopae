// Authenticated fixture signer only: this is NOT actual Hop Human source qualification.
#![cfg(all(feature = "native-client", target_os = "linux"))]
use hopae_grpc::{
    PrincipalKind, human_epoch, human_observed_client::*, receipt, receipt_binding,
    receipt_time::ClockRates, v1,
};
use std::{
    sync::{
        Arc,
        atomic::{AtomicU8, AtomicU64, Ordering},
    },
    time::Duration,
};
use tonic::{Request, Response, Status};
const CALLER: &str = "native-test-caller-at-least-thirty-two-bytes";
fn context() -> v1::AuthenticationReceiptContext {
    v1::AuthenticationReceiptContext {
        issuer_ref: "issuer".into(),
        key_epoch: 1,
        identity_authority_epoch: human_epoch::encode(
            "owner",
            7,
            9,
            "11111111111111111111111111111111",
        )
        .unwrap(),
        identity: Some(v1::ReceiptIdentity {
            subject_ref: format!("human1:{}", "a".repeat(64)),
            kind: 1,
            aal: 1,
            revision: 41,
            credential_generation: 53,
        }),
        service: "orders".into(),
        audience: "api".into(),
        request_sha256: vec![],
    }
}
fn peer_context(mode: u8) -> v1::AuthenticationReceiptContext {
    let mut c = context();
    if mode == 13 {
        let (subject, revision, domain) = if mode == 13 {
            ('b', 3, "22222222222222222222222222222222")
        } else {
            ('a', 7, "11111111111111111111111111111111")
        };
        let i = c.identity.as_mut().unwrap();
        i.subject_ref = format!("human1:{}", subject.to_string().repeat(64));
        i.revision = revision;
        i.credential_generation = revision;
        c.identity_authority_epoch = human_epoch::encode("owner", revision, 9, domain).unwrap();
    }
    match mode {
        16 => c.identity.as_mut().unwrap().kind = 2,
        17 => c.identity.as_mut().unwrap().aal = 0,
        25 => c.identity.as_mut().unwrap().aal = 2,
        18 => {
            c.identity_authority_epoch = hopae_grpc::service_epoch::encode_clock(
                "owner",
                7,
                9,
                "11111111111111111111111111111111",
            )
            .unwrap()
        }
        _ => {}
    }
    c
}
fn context_binding(c: &v1::AuthenticationReceiptContext) -> [u8; 32] {
    let i = c.identity.as_ref().unwrap();
    receipt_binding::digest(
        &receipt_binding::Context {
            issuer_ref: &c.issuer_ref,
            key_epoch: c.key_epoch,
            identity_authority_epoch: &c.identity_authority_epoch,
            identity: receipt_binding::Identity {
                subject_ref: &i.subject_ref,
                kind: if i.kind == 2 {
                    PrincipalKind::Service
                } else {
                    PrincipalKind::Human
                },
                aal: i.aal as u8,
                revision: i.revision,
                credential_generation: i.credential_generation,
            },
            service: &c.service,
            audience: &c.audience,
            request_sha256: c.request_sha256.as_slice().try_into().unwrap(),
        },
        None,
    )
    .unwrap()
}

struct Peer(
    Arc<AtomicU8>,
    Arc<AtomicU64>,
    Arc<tokio::sync::Semaphore>,
    Arc<tokio::sync::Semaphore>,
);
#[tonic::async_trait]
impl v1::human_authentication_receipts_server::HumanAuthenticationReceipts for Peer {
    async fn issue_observed(
        &self,
        request: Request<v1::HumanReceiptRequest>,
    ) -> Result<Response<v1::HumanReceiptObservedReply>, Status> {
        if request
            .metadata()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            != Some(&format!("Bearer {CALLER}"))
        {
            return Err(Status::unauthenticated("caller"));
        }
        let q = request.into_inner();
        let id = q.verification.unwrap().request_id;
        let mut c = peer_context(self.0.load(Ordering::Acquire));
        let final_request = q.final_request.unwrap();
        assert_eq!(final_request.entity_length, 4);
        use sha2::{Digest as _, Sha256};
        assert_eq!(
            final_request.entity_sha256,
            Sha256::digest(b"body").to_vec()
        );
        c.request_sha256 = final_digest();
        let binding = context_binding(&c);
        let raw = receipt::sign(
            &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
            &receipt::Claims {
                purpose: receipt::Purpose::Authentication,
                issued_ms: 1_000_000,
                expires_ms: 1_001_000,
                binding,
                nonce: [3; 32],
            },
        )
        .unwrap();
        let report = self.report(id, &raw).await;
        Ok(Response::new(v1::HumanReceiptObservedReply {
            receipt: Some(v1::HumanReceiptReply {
                request_id: id,
                context: Some(c),
                receipt: raw.to_vec(),
            }),
            observation: Some(report),
        }))
    }
    async fn observe_time(
        &self,
        request: Request<v1::HumanReceiptObservationRequest>,
    ) -> Result<Response<v1::HumanReceiptTimeReply>, Status> {
        if request
            .metadata()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            != Some(&format!("Bearer {CALLER}"))
        {
            return Err(Status::unauthenticated("caller"));
        }
        let q = request.into_inner();
        if self.0.load(Ordering::Acquire) == 22 {
            return Err(Status::permission_denied("source record missing"));
        }
        let c = q
            .context
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("context"))?;
        let mut expected = peer_context(self.0.load(Ordering::Acquire));
        expected.request_sha256 = q.request_sha256;
        if c != &expected {
            return Err(Status::permission_denied("context pin"));
        }
        receipt::verify_signature(
            &ed25519_dalek::SigningKey::from_bytes(&[7; 32]).verifying_key(),
            &q.receipt,
            receipt::Purpose::Authentication,
            &context_binding(c),
        )
        .map_err(|_| Status::permission_denied("binding"))?;
        Ok(Response::new(self.report(q.request_id, &q.receipt).await))
    }
}
impl Peer {
    async fn report(&self, id: u64, raw: &[u8]) -> v1::HumanReceiptTimeReply {
        use sha2::{Digest, Sha256};
        let mode = self.0.load(Ordering::Acquire);
        let previous_id = self.1.swap(id, Ordering::AcqRel);
        if mode == 11 {
            self.2.add_permits(1);
            self.3.acquire().await.unwrap().forget();
        }
        if mode == 5 {
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        v1::HumanReceiptTimeReply {
            request_id: if mode == 10 {
                previous_id
            } else {
                id + u64::from(mode == 1)
            },
            owner_now_ms: if mode == 19 { 1_001_001 } else { 1_000_100 },
            remaining_ms: if mode == 24 {
                40
            } else if mode == 20 {
                1001
            } else if mode == 21 {
                0
            } else if mode == 6 {
                850
            } else {
                700
            },
            receipt_sha256: if mode == 3 {
                vec![9; 32]
            } else {
                Sha256::digest(raw).to_vec()
            },
            clock_domain: if mode == 2 || mode == 13 {
                "22222222222222222222222222222222"
            } else {
                "11111111111111111111111111111111"
            }
            .into(),
            source_revision: if mode == 7 {
                8
            } else if mode == 13 {
                3
            } else {
                7
            },
            application_generation: if mode == 8 { 10 } else { 9 },
            key_registry_revision: if mode == 9 || mode == 14 { 2 } else { 1 },
            cache_ttl_ms: u32::from(mode == 4),
            scope_sha256: match mode {
                26 => vec![],
                27 => vec![0; 32],
                28 => vec![9; 32],
                29..=33 => {
                    let mut sibling = scope();
                    match mode {
                        29 => sibling.route_id = "sibling-route".into(),
                        30 => sibling.app_id = "sibling-app".into(),
                        31 => sibling.destination_sha256 = [2; 32],
                        32 => sibling.header_policy_revision = 2,
                        _ => sibling.header_names = vec!["x-intent".into()],
                    };
                    sibling.fingerprint().unwrap().to_vec()
                }
                _ => scope().fingerprint().unwrap().to_vec(),
            },
        }
    }
}
#[tokio::test]
async fn authenticated_owner_success_refresh_and_hostile_replies() {
    let dir = tempfile::tempdir().unwrap();
    let openssl = |args: &[&str]| {
        assert!(
            std::process::Command::new("openssl")
                .args(args)
                .current_dir(dir.path())
                .output()
                .unwrap()
                .status
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
        "/CN=test-ca",
        "-keyout",
        "ca.key",
        "-out",
        "ca.pem",
        "-addext",
        "basicConstraints=critical,CA:TRUE",
    ]);
    for (name, usage) in [("server", "serverAuth"), ("client", "clientAuth")] {
        openssl(&[
            "req",
            "-new",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-subj",
            "/CN=test",
            "-keyout",
            &format!("{name}.key"),
            "-out",
            &format!("{name}.csr"),
        ]);
        std::fs::write(dir.path().join(format!("{name}.ext")), format!("basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage={usage}\nsubjectAltName=DNS:hopae.test\n")).unwrap();
        openssl(&[
            "x509",
            "-req",
            "-in",
            &format!("{name}.csr"),
            "-CA",
            "ca.pem",
            "-CAkey",
            "ca.key",
            "-CAcreateserial",
            "-days",
            "1",
            "-extfile",
            &format!("{name}.ext"),
            "-out",
            &format!("{name}.pem"),
        ]);
    }
    let read = |name: &str| std::fs::read(dir.path().join(name)).unwrap();
    let ca = read("ca.pem");
    let cert = read("client.pem");
    let key = read("client.key");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = format!("https://{}", listener.local_addr().unwrap());
    let mode = Arc::new(AtomicU8::new(0));
    let last_id = Arc::new(AtomicU64::new(0));
    let entered = Arc::new(tokio::sync::Semaphore::new(0));
    let release = Arc::new(tokio::sync::Semaphore::new(0));
    let tls = tonic::transport::ServerTlsConfig::new()
        .identity(tonic::transport::Identity::from_pem(
            read("server.pem"),
            read("server.key"),
        ))
        .client_ca_root(tonic::transport::Certificate::from_pem(&ca));
    let server = tokio::spawn(
        tonic::transport::Server::builder()
            .tls_config(tls)
            .unwrap()
            .add_service(
                v1::human_authentication_receipts_server::HumanAuthenticationReceiptsServer::new(
                    Peer(
                        mode.clone(),
                        last_id.clone(),
                        entered.clone(),
                        release.clone(),
                    ),
                ),
            )
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener)),
    );
    let clock = Arc::new(hangang_runtime::time::ReceiverClock::new([7; 16]).unwrap());
    let make_scopes = |token: &str, name: &str, scopes: Vec<HumanScope>| {
        Client::new_human(
            EndpointConfig {
                address: &address,
                server_name: name,
                ca: &ca,
                certificate: &cert,
                private_key: &key,
                caller_key: token,
            },
            HumanTrustPolicy {
                issuer_ref: "issuer".into(),
                key_epoch: 1,
                verifying_key: ed25519_dalek::SigningKey::from_bytes(&[7; 32]).verifying_key(),
                identity_authority: "owner".into(),
                scopes,
                minimum_source_revision: 1,
                minimum_application_generation: 9,
                minimum_key_registry_revision: 1,
            },
            clock.clone(),
            ClockRates::new(50, 50).unwrap(),
            Limits {
                concurrent: 1,
                timeout: Duration::from_millis(200),
            },
        )
        .unwrap()
    };
    let make = |token: &str, name: &str| make_scopes(token, name, vec![scope()]);
    let prepare = |c: &Client| {
        c.prepare(
            &scope(),
            &hopae_grpc::request_binding_v2::Request {
                service: "orders",
                audience: "api",
                route_id: "orders-route",
                route_revision: 1,
                destination_sha256: &[1; 32],
                method: "POST",
                target: "/orders",
                body: b"body",
                bound_headers: &[],
            },
            vec![],
        )
        .unwrap()
    };
    let client = make(CALLER, "hopae.test");
    let first = client.issue(prepare(&client)).await.unwrap();
    assert!(client.check(&first, first.request()).is_ok());
    assert_eq!(first.context().identity.as_ref().unwrap().revision, 41);
    assert_eq!(
        first
            .context()
            .identity
            .as_ref()
            .unwrap()
            .credential_generation,
        53
    );
    let context = first.context().clone();
    let raw = first.receipt().to_vec();
    let digest = final_digest().try_into().unwrap();
    let observer = make(CALLER, "hopae.test");
    let independent = observer
        .observe(
            observer
                .prepare_observation(context.clone(), &raw, digest)
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(observer.check(&independent, independent.request()).is_ok());
    assert!(client.check(&independent, independent.request()).is_err());
    let before = client.check(&first, first.request()).unwrap();
    mode.store(6, Ordering::Release);
    let refreshed = client.refresh(first).await.unwrap();
    assert!(client.check(&refreshed, refreshed.request()).unwrap() <= before);
    for attack in [
        1, 2, 3, 4, 5, 7, 8, 10, 16, 17, 18, 19, 20, 21, 26, 27, 28, 29, 30, 31, 32, 33,
    ] {
        mode.store(attack, Ordering::Release);
        assert!(
            client.issue(prepare(&client)).await.is_err(),
            "issue attack {attack}"
        );
        assert!(
            observer
                .observe(
                    observer
                        .prepare_observation(context.clone(), &raw, digest)
                        .unwrap()
                )
                .await
                .is_err(),
            "observe attack {attack}"
        );
    }
    mode.store(0, Ordering::Release);
    for field in 0..9 {
        let mut c = context.clone();
        match field {
            0 => c.issuer_ref = "other".into(),
            1 => c.key_epoch = 2,
            2 => c.service = "other".into(),
            3 => c.audience = "other".into(),
            4 => c.identity.as_mut().unwrap().subject_ref = "human1:bad".into(),
            5 => c.identity.as_mut().unwrap().revision = 0,
            6 => c.identity.as_mut().unwrap().credential_generation = 0,
            7 => c.identity.as_mut().unwrap().kind = 3,
            _ => c.identity.as_mut().unwrap().aal = 4,
        }
        assert!(
            observer.prepare_observation(c, &raw, digest).is_err(),
            "field{field}"
        );
    }
    let wrong = make("wrong-caller-at-least-thirty-two-bytes", "hopae.test");
    assert!(wrong.issue(prepare(&wrong)).await.is_err());
    let wrong = make(CALLER, "wrong.test");
    assert!(wrong.issue(prepare(&wrong)).await.is_err());
    let mut tampered = raw.clone();
    tampered[20] ^= 1;
    assert!(
        observer
            .observe(
                observer
                    .prepare_observation(context.clone(), &tampered, digest)
                    .unwrap()
            )
            .await
            .is_err()
    );
    mode.store(22, Ordering::Release);
    assert!(
        observer
            .observe(
                observer
                    .prepare_observation(context.clone(), &raw, digest)
                    .unwrap()
            )
            .await
            .is_err()
    );
    mode.store(0, Ordering::Release);
    for operation in 0..3 {
        let retiring = make(CALLER, "hopae.test");
        let old = retiring.issue(prepare(&retiring)).await.unwrap();
        let prepared = retiring
            .prepare_observation(context.clone(), &raw, digest)
            .unwrap();
        mode.store(11, Ordering::Release);
        let rpc = async {
            match operation {
                0 => retiring.issue(prepare(&retiring)).await,
                1 => retiring.observe(prepared).await,
                _ => retiring.refresh(old).await,
            }
        };
        let retire = async {
            entered.acquire().await.unwrap().forget();
            retiring.retire();
            release.add_permits(1);
        };
        let (result, ()) = tokio::join!(rpc, retire);
        assert!(result.is_err());
        mode.store(0, Ordering::Release);
    }
    // Same proof cannot outlive the original admission interval.
    mode.store(24, Ordering::Release);
    let short = client.issue(prepare(&client)).await.unwrap();
    tokio::time::sleep(Duration::from_millis(60)).await;
    assert!(client.check(&short, short.request()).is_err());
    mode.store(0, Ordering::Release);
    assert!(client.issue(prepare(&client)).await.is_ok());
    mode.store(13, Ordering::Release);
    let second_user = client.issue(prepare(&client)).await.unwrap();
    assert_eq!(second_user.context().identity.as_ref().unwrap().revision, 3);
    mode.store(25, Ordering::Release);
    let mfa = client.issue(prepare(&client)).await.unwrap();
    assert_eq!(mfa.context().identity.as_ref().unwrap().aal, 2);
    mode.store(0, Ordering::Release);
    let mut sibling = scope();
    sibling.route_id = "sibling-route".into();
    let both = make_scopes(CALLER, "hopae.test", vec![scope(), sibling]);
    let original = both.issue(prepare(&both)).await.unwrap();
    assert!(original.scope() == &scope());
    let observed = both
        .observe(
            both.prepare_observation(original.context().clone(), original.receipt(), digest)
                .unwrap(),
        )
        .await
        .unwrap();
    mode.store(29, Ordering::Release);
    assert!(
        both.issue(prepare(&both)).await.is_err(),
        "Issue must match exact selected scope even when sibling configured"
    );
    assert!(
        both.refresh(observed).await.is_err(),
        "Refresh cannot switch previously observed scope"
    );
    server.abort();
}
fn scope() -> HumanScope {
    HumanScope {
        service: "orders".into(),
        audience: "api".into(),
        app_id: "orders-web".into(),
        route_id: "orders-route".into(),
        route_revision: 1,
        destination_sha256: [1; 32],
        header_policy_revision: 1,
        header_names: vec![],
        reserved_names: vec!["x-projected-credential".into()],
    }
}
fn final_digest() -> Vec<u8> {
    let p = hopae_grpc::request_binding_v2::HeaderPolicy::new(1, &[], &["x-projected-credential"])
        .unwrap();
    hopae_grpc::request_binding_v2::digest(
        &p,
        &hopae_grpc::request_binding_v2::Request {
            service: "orders",
            audience: "api",
            route_id: "orders-route",
            route_revision: 1,
            destination_sha256: &[1; 32],
            method: "POST",
            target: "/orders",
            body: b"body",
            bound_headers: &[],
        },
    )
    .unwrap()
    .to_vec()
}
