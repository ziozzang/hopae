#![cfg(all(feature = "native-client", target_os = "linux"))]
use hopae_grpc::{
    PrincipalKind, receipt, receipt_binding, receipt_time::ClockRates, v1, workload_epoch,
    workload_observed_client::*,
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
        identity_authority_epoch: workload_epoch::encode(
            "owner",
            7,
            9,
            "11111111111111111111111111111111",
        )
        .unwrap(),
        identity: Some(v1::ReceiptIdentity {
            subject_ref: format!("s_{}", "a".repeat(48)),
            kind: 3,
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
        c.identity_authority_epoch = workload_epoch::encode("owner", revision, 9, domain).unwrap();
    }
    match mode {
        16 => c.identity.as_mut().unwrap().kind = 2,
        17 => c.identity.as_mut().unwrap().aal = 1,
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
                    PrincipalKind::Workload
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
impl v1::workload_authentication_receipts_server::WorkloadAuthenticationReceipts for Peer {
    async fn issue_observed(
        &self,
        request: Request<v1::WorkloadReceiptRequest>,
    ) -> Result<Response<v1::WorkloadReceiptObservedReply>, Status> {
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
        Ok(Response::new(v1::WorkloadReceiptObservedReply {
            receipt: Some(v1::WorkloadReceiptReply {
                request_id: id,
                context: Some(c),
                receipt: raw.to_vec(),
            }),
            observation: Some(report),
        }))
    }
    async fn observe_time(
        &self,
        request: Request<v1::WorkloadReceiptObservationRequest>,
    ) -> Result<Response<v1::WorkloadReceiptTimeReply>, Status> {
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
    async fn report(&self, id: u64, raw: &[u8]) -> v1::WorkloadReceiptTimeReply {
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
        v1::WorkloadReceiptTimeReply {
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
                v1::workload_authentication_receipts_server::WorkloadAuthenticationReceiptsServer::new(Peer(
                    mode.clone(),
                    last_id.clone(),
                    entered.clone(),
                    release.clone(),
                )),
            )
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener)),
    );
    let clock = Arc::new(hangang_runtime::time::ReceiverClock::new([7; 16]).unwrap());
    let make = |token: &str, name: &str| {
        Client::new_workload(
            EndpointConfig {
                address: &address,
                server_name: name,
                ca: &ca,
                certificate: &cert,
                private_key: &key,
                caller_key: token,
            },
            WorkloadTrustPolicy {
                issuer_ref: "issuer".into(),
                key_epoch: 1,
                verifying_key: ed25519_dalek::SigningKey::from_bytes(&[7; 32]).verifying_key(),
                identity_authority: "owner".into(),
                scopes: vec![WorkloadScope {
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
        .unwrap()
    };
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
    let client = make(CALLER, "hopae.test");
    let intent = prepare(&client);
    let first = client.issue(intent.clone()).await.unwrap();
    assert!(client.check(&first, first.request()).is_ok());
    assert!(client.check(&first, &intent).is_err()); // unresolved preparation is not the signed context
    assert!(!client.retention_elapsed(&first).unwrap());
    let digest: [u8; 32] = first
        .context()
        .request_sha256
        .as_slice()
        .try_into()
        .unwrap();
    let context = first.context().clone();
    let raw = first.receipt().to_vec();
    let observer = make(CALLER, "hopae.test");
    let observed_request = observer
        .prepare_observation(context.clone(), digest)
        .unwrap();
    let independent = observer
        .observe(observed_request.clone(), &raw)
        .await
        .unwrap();
    assert!(observer.check(&independent, &observed_request).is_ok());
    assert!(client.check(&independent, independent.request()).is_err());
    assert!(
        observer
            .observe(first.request().clone(), &raw)
            .await
            .is_err()
    );
    let first_remaining = client.check(&first, first.request()).unwrap();
    mode.store(6, Ordering::Release); // owner increases admission report; old lower bound must survive
    let refreshed = client.refresh(first).await.unwrap();
    assert!(client.check(&refreshed, refreshed.request()).unwrap() <= first_remaining);
    assert!(!client.retention_elapsed(&refreshed).unwrap());
    for field in 0..12 {
        let mut c = context.clone();
        match field {
            0 => c.issuer_ref = "other".into(),
            1 => c.key_epoch = 2,
            2 => {
                c.identity_authority_epoch =
                    workload_epoch::encode("other", 7, 9, "11111111111111111111111111111111")
                        .unwrap()
            }
            3 => c.service = "other".into(),
            4 => c.audience = "other".into(),
            5 => c.identity.as_mut().unwrap().subject_ref = "worker".into(),
            6 => c.identity.as_mut().unwrap().credential_generation = 8,
            7 => {
                c.identity_authority_epoch =
                    workload_epoch::encode("owner", 7, 8, "11111111111111111111111111111111")
                        .unwrap()
            }
            8 => c.identity.as_mut().unwrap().kind = 2,
            9 => c.identity.as_mut().unwrap().aal = 1,
            10 => {
                c.identity_authority_epoch = hopae_grpc::service_epoch::encode_clock(
                    "owner",
                    7,
                    9,
                    "11111111111111111111111111111111",
                )
                .unwrap()
            }
            _ => c.request_sha256 = vec![9; 32],
        }
        assert!(
            observer.prepare_observation(c, digest).is_err(),
            "field {field}"
        );
    }
    mode.store(0, Ordering::Release);
    for attack in [1, 2, 3, 4, 5, 7, 8, 10, 16, 17, 18, 19, 20, 21] {
        mode.store(attack, Ordering::Release);
        assert!(
            client.issue(intent.clone()).await.is_err(),
            "issue attack {attack}"
        );
        assert!(
            observer
                .observe(observed_request.clone(), &raw)
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
    let mut tampered = raw.clone();
    tampered[20] ^= 1;
    assert!(
        observer
            .observe(observed_request.clone(), &tampered)
            .await
            .is_err()
    );
    assert!(
        observer
            .observe(observed_request.clone(), &raw[..raw.len() - 1])
            .await
            .is_err()
    );
    mode.store(22, Ordering::Release);
    assert!(
        observer
            .observe(observed_request.clone(), &raw)
            .await
            .is_err()
    );
    // Cancellation releases semaphore and cannot materialize a capability.
    mode.store(5, Ordering::Release);
    assert!(
        tokio::time::timeout(Duration::from_millis(10), client.issue(intent.clone()))
            .await
            .is_err()
    );
    mode.store(0, Ordering::Release);
    assert!(client.issue(intent.clone()).await.is_ok());
    for operation in 0..3 {
        let retiring = make(CALLER, "hopae.test");
        let old = retiring.issue(prepare(&retiring)).await.unwrap();
        let request = retiring
            .prepare_observation(context.clone(), digest)
            .unwrap();
        mode.store(11, Ordering::Release);
        let rpc = async {
            match operation {
                0 => retiring.issue(prepare(&retiring)).await,
                1 => retiring.observe(request, &raw).await,
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
        assert!(
            retiring
                .prepare_observation(context.clone(), digest)
                .is_err()
        );
        mode.store(0, Ordering::Release);
    }
    // Expiring one short proof refuses that request without retiring the client.
    mode.store(24, Ordering::Release);
    let short = client.issue(intent.clone()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(60)).await;
    assert!(client.check(&short, short.request()).is_err());
    mode.store(0, Ordering::Release);
    assert!(client.issue(intent.clone()).await.is_ok());
    // New issuer process/subject is accepted only through a fresh signed context.
    let stable = make(CALLER, "hopae.test");
    let old = stable.issue(prepare(&stable)).await.unwrap();
    mode.store(13, Ordering::Release);
    let new = stable.issue(prepare(&stable)).await.unwrap();
    assert_ne!(old.context().identity, new.context().identity);
    assert!(stable.refresh(old).await.is_err());
    assert!(stable.check(&new, new.request()).is_ok());
    mode.store(12, Ordering::Release);
    let older = stable.issue(prepare(&stable)).await.unwrap();
    mode.store(14, Ordering::Release);
    assert!(stable.issue(prepare(&stable)).await.is_ok());
    assert!(stable.check(&older, older.request()).is_err());
    mode.store(12, Ordering::Release);
    assert!(stable.issue(prepare(&stable)).await.is_err());
    clock.retire();
    assert!(client.check(&refreshed, refreshed.request()).is_err());
    assert!(client.prepare_observation(context, digest).is_err());
    assert!(client.issue(intent).await.is_err());
    server.abort();
}
