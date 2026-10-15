#![cfg(feature = "native-client")]
use hopae_grpc::{
    PrincipalKind, observed_client::*, receipt, receipt_binding, receipt_time::ClockRates,
    service_epoch, v1,
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
        identity_authority_epoch: service_epoch::encode_clock(
            "owner",
            7,
            9,
            "11111111111111111111111111111111",
        )
        .unwrap(),
        identity: Some(v1::ReceiptIdentity {
            subject_ref: "worker".into(),
            kind: 2,
            aal: 0,
            revision: 7,
            credential_generation: 7,
        }),
        service: "orders".into(),
        audience: "api".into(),
        request_sha256: vec![],
    }
}
fn peer_context(mode: u8) -> v1::AuthenticationReceiptContext {
    let mut c = context();
    if mode >= 12 {
        let (subject, revision, domain) = if mode == 13 {
            ('b', 3, "22222222222222222222222222222222")
        } else {
            ('a', 7, "11111111111111111111111111111111")
        };
        let i = c.identity.as_mut().unwrap();
        i.subject_ref = format!("s_{}", subject.to_string().repeat(48));
        i.revision = revision;
        i.credential_generation = revision;
        c.identity_authority_epoch =
            service_epoch::encode_clock("owner", revision, 9, domain).unwrap();
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
                kind: PrincipalKind::Service,
                aal: 0,
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
impl v1::authentication_receipts_server::AuthenticationReceipts for Peer {
    async fn issue_service(
        &self,
        _: Request<v1::ServiceReceiptRequest>,
    ) -> Result<Response<v1::ServiceReceiptReply>, Status> {
        Err(Status::unimplemented("strict unused"))
    }
    async fn validate_service(
        &self,
        _: Request<v1::ServiceReceiptValidationRequest>,
    ) -> Result<Response<v1::ServiceReceiptValidationReply>, Status> {
        Err(Status::unimplemented("strict unused"))
    }
    async fn issue_service_observed(
        &self,
        request: Request<v1::ServiceReceiptRequest>,
    ) -> Result<Response<v1::ServiceReceiptObservedReply>, Status> {
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
        c.request_sha256 = q.request_sha256;
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
        Ok(Response::new(v1::ServiceReceiptObservedReply {
            receipt: Some(v1::ServiceReceiptReply {
                request_id: id,
                context: Some(c),
                receipt: raw.to_vec(),
            }),
            observation: Some(report),
        }))
    }
    async fn observe_service_time(
        &self,
        request: Request<v1::ServiceReceiptValidationRequest>,
    ) -> Result<Response<v1::ServiceReceiptTimeReply>, Status> {
        if request
            .metadata()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            != Some(&format!("Bearer {CALLER}"))
        {
            return Err(Status::unauthenticated("caller"));
        }
        let q = request.into_inner();
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
    async fn report(&self, id: u64, raw: &[u8]) -> v1::ServiceReceiptTimeReply {
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
        v1::ServiceReceiptTimeReply {
            request_id: if mode == 10 {
                previous_id
            } else {
                id + u64::from(mode == 1)
            },
            owner_now_ms: 1_000_100,
            remaining_ms: if mode == 6 { 850 } else { 700 },
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
            profile_revision: if mode == 7 {
                8
            } else if mode == 13 {
                3
            } else {
                7
            },
            application_generation: if mode == 8 { 10 } else { 9 },
            key_registry_revision: if mode == 9 || mode == 14 { 2 } else { 1 },
            cache_ttl_ms: u32::from(mode == 4),
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
                v1::authentication_receipts_server::AuthenticationReceiptsServer::new(Peer(
                    mode.clone(),
                    last_id.clone(),
                    entered.clone(),
                    release.clone(),
                )),
            )
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener)),
    );
    let clock = Arc::new(hangang_runtime::time::ReceiverClock::new([7; 16]).unwrap());
    let make_pinned =
        |token: &str, name: &str, pinned_context: v1::AuthenticationReceiptContext| {
            Client::new(
                EndpointConfig {
                    address: &address,
                    server_name: name,
                    ca: &ca,
                    certificate: &cert,
                    private_key: &key,
                    caller_key: token,
                },
                OwnerPin {
                    context: pinned_context,
                    verifying_key: ed25519_dalek::SigningKey::from_bytes(&[7; 32]).verifying_key(),
                    key_registry_revision: 1,
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
    let make = |token: &str, name: &str| make_pinned(token, name, context());
    let client = make(CALLER, "hopae.test");
    let prepare = |c: &Client| {
        c.prepare(
            &hopae_grpc::request_binding::Request {
                service: "orders",
                audience: "api",
                method: "GET",
                target: "/",
                body_sha256: &[0; 32],
            },
            vec![],
        )
        .unwrap()
    };
    let request = prepare(&client);
    let observation = client.issue(request.clone()).await.unwrap();
    let first_id = last_id.load(Ordering::Acquire);
    assert!(client.issue(request.clone()).await.is_ok());
    assert_ne!(first_id, last_id.load(Ordering::Acquire));
    mode.store(10, Ordering::Release);
    assert!(client.issue(request.clone()).await.is_err());
    mode.store(0, Ordering::Release);
    let old = client.check(&observation, &request).unwrap();
    assert!(client.check(&observation, &prepare(&client)).is_err());
    assert!(!client.retention_elapsed(&observation).unwrap());
    mode.store(6, Ordering::Release);
    let observation = client.refresh(observation).await.unwrap();
    let public_proof = observation.receipt().to_vec();
    let observer = make(CALLER, "hopae.test");
    let observed_request = prepare(&observer);
    let independent = observer
        .observe(observed_request.clone(), &public_proof)
        .await
        .unwrap();
    assert!(observer.check(&independent, &observed_request).is_ok());
    assert!(client.check(&independent, &request).is_err());
    assert!(
        observer
            .observe(request.clone(), &public_proof)
            .await
            .is_err()
    );
    let different = observer
        .prepare(
            &hopae_grpc::request_binding::Request {
                service: "orders",
                audience: "api",
                method: "GET",
                target: "/different",
                body_sha256: &[0; 32],
            },
            vec![],
        )
        .unwrap();
    assert!(observer.observe(different, &public_proof).await.is_err());
    assert!(
        observer
            .observe(
                observed_request.clone(),
                &public_proof[..public_proof.len() - 1]
            )
            .await
            .is_err()
    );
    let mut changed_proof = public_proof.clone();
    changed_proof[20] ^= 1;
    assert!(
        observer
            .observe(observed_request.clone(), &changed_proof)
            .await
            .is_err()
    );

    assert!(client.check(&observation, &request).unwrap() <= old);
    let mut wrong_pin = context();
    wrong_pin.issuer_ref = "other-issuer".into();
    let cross_pin = make_pinned(CALLER, "hopae.test", wrong_pin);
    assert!(
        cross_pin
            .observe(prepare(&cross_pin), &public_proof)
            .await
            .is_err()
    );
    let other = make(CALLER, "hopae.test");
    assert!(other.issue(request.clone()).await.is_err());
    assert!(other.refresh(observation).await.is_err());
    for attack in [1, 2, 3, 4, 5, 7, 8, 9] {
        mode.store(attack, Ordering::Release);
        assert!(
            client.issue(prepare(&client)).await.is_err(),
            "attack {attack}"
        );
        assert!(
            observer
                .observe(observed_request.clone(), &public_proof)
                .await
                .is_err(),
            "observe attack {attack}"
        );
    }
    mode.store(0, Ordering::Release);
    let wrong = make("wrong-caller-at-least-thirty-two-bytes", "hopae.test");
    assert!(wrong.issue(prepare(&wrong)).await.is_err());
    let wrong = make(CALLER, "wrong.test");
    assert!(wrong.issue(prepare(&wrong)).await.is_err());
    // Dropping a pending future cannot produce observation and releases admission.
    mode.store(5, Ordering::Release);
    assert!(
        tokio::time::timeout(Duration::from_millis(10), client.issue(prepare(&client)))
            .await
            .is_err()
    );
    mode.store(0, Ordering::Release);
    assert!(client.issue(prepare(&client)).await.is_ok());
    // Retirement is per-client and refuses an already authenticated RPC result.
    for operation in 0..3 {
        let retiring = make(CALLER, "hopae.test");
        let q = prepare(&retiring);
        let retained = retiring.issue(q.clone()).await.unwrap();
        let refresh_input = retiring.issue(q.clone()).await.unwrap();
        mode.store(11, Ordering::Release);
        let rpc = async {
            match operation {
                0 => retiring.issue(q.clone()).await,
                1 => retiring.refresh(refresh_input).await,
                _ => retiring.observe(q.clone(), &public_proof).await,
            }
        };
        let retire = async {
            tokio::time::timeout(Duration::from_secs(1), entered.acquire())
                .await
                .unwrap()
                .unwrap()
                .forget();
            retiring.retire();
            release.add_permits(1);
        };
        let (result, ()) = tokio::join!(rpc, retire);
        assert!(result.is_err());
        assert!(retiring.check(&retained, &q).is_err());
        assert!(retiring.retention_elapsed(&retained).is_ok());
        assert!(retiring.issue(q.clone()).await.is_err());
        assert!(retiring.refresh(retained).await.is_err());
        assert!(
            retiring
                .prepare(
                    &hopae_grpc::request_binding::Request {
                        service: "orders",
                        audience: "api",
                        method: "GET",
                        target: "/",
                        body_sha256: &[0; 32]
                    },
                    vec![]
                )
                .is_err()
        );
        mode.store(0, Ordering::Release);
        assert!(client.issue(request.clone()).await.is_ok());
    }
    // The same fixed mTLS client resolves dynamic subjects and owner restarts.
    let stable = Client::new_service(
        EndpointConfig {
            address: &address,
            server_name: "hopae.test",
            ca: &ca,
            certificate: &cert,
            private_key: &key,
            caller_key: CALLER,
        },
        ServiceTrustPolicy {
            issuer_ref: "issuer".into(),
            key_epoch: 1,
            verifying_key: ed25519_dalek::SigningKey::from_bytes(&[7; 32]).verifying_key(),
            identity_authority: "owner".into(),
            scopes: vec![ServiceScope {
                service: "orders".into(),
                audience: "api".into(),
            }],
            minimum_profile_revision: 1,
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
    .unwrap();
    let digest = hopae_grpc::request_binding::digest(&hopae_grpc::request_binding::Request {
        service: "orders",
        audience: "api",
        method: "GET",
        target: "/",
        body_sha256: &[0; 32],
    })
    .unwrap();
    let intent = stable
        .prepare_issue_digest(
            ServiceScope {
                service: "orders".into(),
                audience: "api".into(),
            },
            digest,
            vec![],
        )
        .unwrap();
    mode.store(12, Ordering::Release);
    let first = stable.issue(intent.clone()).await.unwrap();
    assert_eq!(first.context().request_sha256, digest);
    let canonical = stable.issue(prepare(&stable)).await.unwrap();
    assert_eq!(canonical.context(), first.context());
    let q = stable
        .prepare_observation(first.context().clone(), digest)
        .unwrap();
    assert!(stable.observe(q.clone(), first.receipt()).await.is_ok());
    assert!(
        stable
            .prepare_observation(first.context().clone(), [99; 32])
            .is_err()
    );
    for field in 0..8 {
        let mut c = first.context().clone();
        match field {
            0 => c.issuer_ref = "other".into(),
            1 => c.key_epoch = 2,
            2 => {
                c.identity_authority_epoch =
                    service_epoch::encode_clock("other", 7, 9, "11111111111111111111111111111111")
                        .unwrap()
            }
            3 => c.service = "other".into(),
            4 => c.audience = "other".into(),
            5 => c.identity.as_mut().unwrap().subject_ref = "worker".into(),
            6 => c.identity.as_mut().unwrap().credential_generation = 8,
            _ => {
                c.identity_authority_epoch =
                    service_epoch::encode_clock("owner", 7, 8, "11111111111111111111111111111111")
                        .unwrap()
            }
        }
        assert!(
            stable.prepare_observation(c, digest).is_err(),
            "policy field {field}"
        );
    }
    mode.store(13, Ordering::Release);
    let second = stable.issue(intent.clone()).await.unwrap();
    assert_ne!(first.context().identity, second.context().identity);
    assert!(stable.check(&second, second.request()).is_ok());
    assert!(stable.observe(q, first.receipt()).await.is_err());
    assert!(stable.refresh(first).await.is_err());
    assert!(stable.refresh(second).await.is_ok());
    // Registry floor belongs to this owner/configuration, not a profile subject.
    mode.store(12, Ordering::Release);
    let older = stable.issue(intent.clone()).await.unwrap();
    mode.store(14, Ordering::Release);
    assert!(stable.issue(intent.clone()).await.is_ok());
    assert!(stable.check(&older, older.request()).is_err());
    assert!(stable.refresh(older).await.is_err());
    mode.store(12, Ordering::Release);
    assert!(stable.issue(intent).await.is_err());
    stable.retire();
    clock.retire();
    assert!(client.issue(prepare(&client)).await.is_err());
    server.abort();
}
