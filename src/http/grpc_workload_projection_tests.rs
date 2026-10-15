//! Real TokenReview/native auth plus actual typed output RPC and paired DB.
//! Pum Observe is an owned authenticated signing fixture, not native policy evidence.
use super::*;
use crate::auth_gateway::{projection, projection_resources};
use prost::Message;
use pumgye_grpc::v1 as pv;
use sha2::{Digest as _, Sha256};
use std::sync::atomic::{AtomicU8, AtomicU64};
use tonic::{Response, Status};
struct Peer {
    mode: Arc<AtomicU8>,
    calls: Arc<AtomicU64>,
}
#[tonic::async_trait]
impl pv::workload_observed_projection_permits_server::WorkloadObservedProjectionPermits for Peer {
    async fn issue(
        &self,
        _: Request<pv::AuthenticatedResourceRequest>,
    ) -> Result<Response<pv::ObservedProjectionPermitReply>, Status> {
        Err(Status::unimplemented("fixture Observe only"))
    }
    async fn observe(
        &self,
        q: Request<pv::PermitValidationRequest>,
    ) -> Result<Response<pv::ObservedPermitTimeReply>, Status> {
        if q.metadata()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            != Some(&format!("Bearer {CALLER}"))
        {
            return Err(Status::unauthenticated("caller"));
        }
        self.calls.fetch_add(1, Ordering::AcqRel);
        let q = q.into_inner();
        let p = q.permit.ok_or_else(|| Status::invalid_argument("permit"))?;
        let b = p
            .binding
            .ok_or_else(|| Status::invalid_argument("binding"))?;
        match self.mode.load(Ordering::Acquire) {
            1 => return Err(Status::permission_denied("fixture withdrawn")),
            2 => tokio::time::sleep(Duration::from_millis(700)).await,
            _ => {}
        }
        Ok(Response::new(pv::ObservedPermitTimeReply {
            request_id: q.request_id,
            receipt_sha256: if self.mode.load(Ordering::Acquire) == 3 {
                vec![9; 32]
            } else {
                Sha256::digest(&p.receipt).to_vec()
            },
            clock_domain: b.authority_epoch,
            owner_now_ms: 1_000_100,
            proof_remaining_ms: 900,
            remaining_ms: 700,
            policy_revision: b.policy_revision,
            network_revision: b.network_revision,
            route_revision: b.route_revision,
            plan_revision: b.plan_revision,
            cache_ttl_ms: 0,
        }))
    }
}
struct World {f:Fixture,client:v1::workload_observed_credential_projection_client::WorkloadObservedCredentialProjectionClient<tonic::transport::Channel>,mode:Arc<AtomicU8>,calls:Arc<AtomicU64>,channel:tonic::transport::Channel,pum:tokio::task::JoinHandle<Result<(),tonic::transport::Error>>,server:tokio::task::JoinHandle<anyhow::Result<()>>,stop:watch::Sender<bool>}
impl Drop for World {
    fn drop(&mut self) {
        let _ = self.stop.send(true);
        self.pum.abort();
        self.server.abort();
    }
}
impl World {
    async fn start(allowed: bool) -> Self {
        let mut f = Fixture::start(64).await;
        let ca = std::fs::read(f.root.path().join("ca.pem")).unwrap();
        let cert = std::fs::read(f.root.path().join("server.pem")).unwrap();
        let key = std::fs::read(f.root.path().join("server.key")).unwrap();
        let tls = || {
            ServerTlsConfig::new()
                .identity(tonic::transport::Identity::from_pem(&cert, &key))
                .client_ca_root(tonic::transport::Certificate::from_pem(&ca))
        };
        let mode = Arc::new(AtomicU8::new(0));
        let calls = Arc::new(AtomicU64::new(0));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = format!("https://{}", listener.local_addr().unwrap());
        let pum=tokio::spawn(tonic::transport::Server::builder().tls_config(tls()).unwrap().add_service(pv::workload_observed_projection_permits_server::WorkloadObservedProjectionPermitsServer::new(Peer{mode:mode.clone(),calls:calls.clone()})).serve_with_incoming(hangang_runtime::incoming(listener)));
        f.services
            .receipt_authority
            .lock()
            .unwrap()
            .reconcile(
                &mut f.services.store.conn(),
                &[
                    receipt_keys::Key {
                        issuer_ref: "owned-workload".into(),
                        purpose: hopae_grpc::receipt::Purpose::Authentication,
                        epoch: 1,
                        public_key: ed25519_dalek::SigningKey::from_bytes(&[7; 32])
                            .verifying_key()
                            .to_bytes(),
                    },
                    receipt_keys::Key {
                        issuer_ref: "owned-pumgye".into(),
                        purpose: hopae_grpc::receipt::Purpose::Permit,
                        epoch: 1,
                        public_key: ed25519_dalek::SigningKey::from_bytes(&[8; 32])
                            .verifying_key()
                            .to_bytes(),
                    },
                ],
                "owned-projection-bootstrap",
                &|_| Ok(()),
            )
            .unwrap();
        let plans = projection::Configuration {
            revision: 1,
            plans: vec![projection::Plan {
                service: "orders".into(),
                audience: "orders-api".into(),
                minimum_aal: 0,
                resource: "db:orders".into(),
                action: "select".into(),
                credential: projection::Credential::BearerReference {
                    secret_ref: "vault:orders".into(),
                },
            }],
        };
        f.services
            .projection_authority
            .lock()
            .unwrap()
            .publish(
                &mut f.services.store.conn(),
                0,
                Some(plans.clone()),
                "owned-plan-bootstrap",
                &|_| Ok(()),
            )
            .unwrap();
        let resources = projection_resources::Configuration {
            authority: projection_resources::Authority {
                address,
                server_name: "localhost".into(),
                ca: f.root.path().join("ca.pem"),
                certificate: f.root.path().join("server.pem"),
                key: f.root.path().join("server.key"),
                token_env: "OWNED_PUM_CALLER".into(),
            },
            observed_clock_rates: Some(projection_resources::ObservedClockRates {
                source_ppm: 500,
                receiver_ppm: 500,
            }),
            workload_observed_scopes: if allowed {
                vec![crate::auth_gateway::receipt_issuer::Scope {
                    service: "orders".into(),
                    audience: "orders-api".into(),
                }]
            } else {
                vec![]
            },
            secrets: vec![projection_resources::SecretReference {
                reference: "vault:orders".into(),
                token_env: "OWNED_SECRET".into(),
            }],
        };
        resources.validate_plans(&plans).unwrap();
        f.services.projection_resources = Some(Arc::new(
            resources
                .prepare(&|name| {
                    Some(
                        if name == "OWNED_SECRET" {
                            "owned-final-secret"
                        } else {
                            CALLER
                        }
                        .into(),
                    )
                })
                .unwrap(),
        ));
        let router = crate::app::build_routers(&f.services).unwrap().gateway;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = format!("https://{}", listener.local_addr().unwrap());
        let (stop, rx) = watch::channel(false);
        let server = tokio::spawn(serve_with_receipts(
            listener,
            tls(),
            router,
            f.services.caller_keys.clone(),
            rx,
            Some(f.services.clone()),
        ));
        let channel = tonic::transport::Endpoint::from_shared(address)
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
        Self{f,client:v1::workload_observed_credential_projection_client::WorkloadObservedCredentialProjectionClient::new(channel.clone()),mode,calls,channel,pum,server,stop}
    }
    async fn query(&mut self, id: u64) -> Vec<u8> {
        let auth = self
            .f
            .client
            .issue_observed(self.f.request())
            .await
            .unwrap()
            .into_inner()
            .receipt
            .unwrap();
        let c = auth.context.as_ref().unwrap();
        let mut pcontext = context(c);
        pcontext.issuer_ref = "owned-pumgye";
        let binding = crate::auth_gateway::receipt_binding::Permit {
            authentication_receipt_sha256: Sha256::digest(&auth.receipt).into(),
            decision_ref: "owned-decision",
            resource: "db:orders",
            action: "select",
            authority_epoch: "pobs1:11111111111111111111111111111111:owned-pumgye",
            catalog_revision: 1,
            policy_revision: 1,
            network_revision: 1,
            route_revision: 1,
            plan_revision: 1,
        };
        let proof = hopae_grpc::receipt::sign(
            &ed25519_dalek::SigningKey::from_bytes(&[8; 32]),
            &hopae_grpc::receipt::Claims {
                purpose: hopae_grpc::receipt::Purpose::Permit,
                issued_ms: 1_000_000,
                expires_ms: 1_001_000,
                binding: crate::auth_gateway::receipt_binding::digest(&pcontext, Some(&binding))
                    .unwrap(),
                nonce: [id as u8; 32],
            },
        )
        .unwrap();
        let native = pv::AuthenticatedResourceRequest {
            request_id: 41,
            minimum_revision: 1,
            ip: vec![203, 0, 113, 9],
            resource: "db:orders".into(),
            action: "select".into(),
            context: Some(prost::Message::decode(c.encode_to_vec().as_slice()).unwrap()),
            receipt: auth.receipt,
            request_sha256: vec![9; 32],
            route: Some(pv::NativeRouteReference {
                reference: vec![3; 32],
                destination_sha256: vec![4; 32],
            }),
        };
        let mut permit_context = native.context.clone().unwrap();
        permit_context.issuer_ref = "owned-pumgye".into();
        pv::PermitValidationRequest {
            request_id: id,
            request: Some(native),
            permit: Some(pv::ProjectionPermitReply {
                request_id: 41,
                context: Some(permit_context),
                binding: Some(pv::PermitBinding {
                    authentication_receipt_sha256: binding.authentication_receipt_sha256.to_vec(),
                    decision_ref: binding.decision_ref.into(),
                    resource: binding.resource.into(),
                    action: binding.action.into(),
                    authority_epoch: binding.authority_epoch.into(),
                    catalog_revision: 1,
                    policy_revision: 1,
                    network_revision: 1,
                    route_revision: 1,
                    plan_revision: 1,
                }),
                receipt: proof.to_vec(),
                cache_ttl_ms: 0,
            }),
        }
        .encode_to_vec()
    }
    fn rpc(id: u64, bytes: Vec<u8>, contract: u32) -> Request<v1::ProjectionRequest> {
        let mut q = Request::new(v1::ProjectionRequest {
            request_id: id,
            permission_contract: contract,
            permission_query: bytes,
        });
        q.metadata_mut()
            .insert("authorization", format!("Bearer {CALLER}").parse().unwrap());
        q
    }
    fn consumed(&self) -> u64 {
        self.f
            .services
            .store
            .conn()
            .query_row(
                "SELECT count(*) FROM meta WHERE key LIKE 'projection_nonce_id:%'",
                [],
                |r| r.get(0),
            )
            .unwrap()
    }
}
#[tokio::test]
async fn workload_contract3_actual_native_auth_typed_output_and_shared_pair_replay() {
    let mut w = World::start(true).await;
    let query = w.query(101).await;
    let expected: Vec<u8> = Sha256::digest(&query).to_vec();
    let reply = w
        .client
        .project(World::rpc(101, query.clone(), 3))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(reply.header_name, "authorization");
    assert_eq!(reply.header_value, b"Bearer owned-final-secret");
    assert_eq!(reply.chain_sha256, expected);
    assert_eq!(reply.request_sha256, vec![9; 32]);
    assert!(reply.remaining_ms > 0 && reply.remaining_ms <= 700);
    assert!(reply.output_clock_domain.starts_with("hproj1:"));
    assert_eq!(reply.cache_ttl_ms, 0);
    assert!(!format!("{reply:?}").contains("owned-final-secret"));
    assert_eq!(w.consumed(), 2);
    let mut query = pv::PermitValidationRequest::decode(query.as_slice()).unwrap();
    query.request_id = 102;
    assert!(
        w.client
            .project(World::rpc(102, query.encode_to_vec(), 3))
            .await
            .is_err()
    );
    assert_eq!(w.consumed(), 2);
}
#[tokio::test]
async fn workload_output_activation_contract_and_actual_owner_refusals_are_closed() {
    let mut disabled = World::start(false).await;
    let q = disabled.query(110).await;
    assert!(
        disabled
            .client
            .project(World::rpc(110, q, 3))
            .await
            .is_err()
    );
    assert_eq!(disabled.calls.load(Ordering::Acquire), 0);
    assert_eq!(disabled.consumed(), 0);
    let mut w = World::start(true).await;
    for (id, mode) in [(111, 0), (112, 1), (113, 3), (114, 2)] {
        let query = w.query(id).await;
        w.mode.store(mode, Ordering::Release);
        assert!(
            w.client
                .project(World::rpc(id, query, if id == 111 { 2 } else { 3 }))
                .await
                .is_err()
        );
        assert_eq!(w.consumed(), 0);
    }
    w.mode.store(0, Ordering::Release);
    let query = w.query(115).await;
    let app = w.f.services.snapshot.load_full();
    w.f.services.snapshot.store(Arc::new((*app).clone()));
    assert!(w.client.project(World::rpc(115, query, 3)).await.is_err());
    assert_eq!(w.consumed(), 0);
}

#[tokio::test]
async fn workload_query_cannot_enter_existing_service_output_or_downgrade_identity() {
    let mut w = World::start(true).await;
    let query = w.query(120).await;
    let mut service =
        v1::observed_credential_projection_client::ObservedCredentialProjectionClient::new(
            w.channel.clone(),
        );
    assert!(
        service
            .project(World::rpc(120, query.clone(), 2))
            .await
            .is_err()
    );
    let mut q = pv::PermitValidationRequest::decode(query.as_slice()).unwrap();
    q.request
        .as_mut()
        .unwrap()
        .context
        .as_mut()
        .unwrap()
        .identity
        .as_mut()
        .unwrap()
        .kind = 2;
    q.permit
        .as_mut()
        .unwrap()
        .context
        .as_mut()
        .unwrap()
        .identity
        .as_mut()
        .unwrap()
        .kind = 2;
    assert!(
        w.client
            .project(World::rpc(120, q.encode_to_vec(), 3))
            .await
            .is_err()
    );
    assert_eq!(w.calls.load(Ordering::Acquire), 0);
    assert_eq!(w.consumed(), 0);
}

#[tokio::test]
async fn workload_cancellation_while_blocking_worker_waits_cannot_commit_pair_or_emit() {
    let mut w = World::start(true).await;
    let query = w.query(130).await;
    let request =
        crate::auth_gateway::workload_permission_live::Request::decode_observed_query(&query, 130)
            .unwrap();
    let runtime = crate::auth_gateway::projection_runtime::Runtime::from_services(&w.f.services)
        .unwrap()
        .unwrap();
    let calls = Arc::new(AtomicU64::new(0));
    let counted = calls.clone();
    let caller: Arc<dyn Fn() -> bool + Send + Sync> = Arc::new(move || {
        counted.fetch_add(1, Ordering::AcqRel);
        true
    });
    let store = w.f.services.store.clone();
    let (ready, locked) = tokio::sync::oneshot::channel();
    let (release, hold) = tokio::sync::oneshot::channel::<()>();
    let holder = tokio::task::spawn_blocking(move || {
        let connection = store.conn();
        let _ = ready.send(());
        let _ = hold.blocking_recv();
        drop(connection);
    });
    locked.await.unwrap();
    let task =
        tokio::spawn(async move { runtime.project_workload_observed(request, caller).await });
    tokio::time::timeout(Duration::from_millis(500), async {
        while calls.load(Ordering::Acquire) < 2 {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .unwrap();
    task.abort();
    assert!(matches!(task.await,Err(error) if error.is_cancelled()));
    release.send(()).unwrap();
    holder.await.unwrap();
    tokio::time::timeout(Duration::from_millis(500), async {
        while calls.load(Ordering::Acquire) < 3 {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(w.consumed(), 0);
}
#[tokio::test]
async fn workload_final_reply_callback_withdraws_native_owner_after_secret_work() {
    for owner in 0..3 {
        let mut w = World::start(true).await;
        let query = w.query(140).await;
        let request =
            crate::auth_gateway::workload_permission_live::Request::decode_observed_query(
                &query, 140,
            )
            .unwrap();
        let runtime =
            crate::auth_gateway::projection_runtime::Runtime::from_services(&w.f.services)
                .unwrap()
                .unwrap();
        let withdraw = Arc::new(AtomicBool::new(false));
        let trigger = withdraw.clone();
        let services = w.f.services.clone();
        let caller: Arc<dyn Fn() -> bool + Send + Sync> = Arc::new(move || {
            if trigger.swap(false, Ordering::AcqRel) {
                match owner {
                    0 => {
                        services
                            .authentication_authority
                            .as_ref()
                            .unwrap()
                            .lock()
                            .unwrap()
                            .publish(
                                &mut services.store.conn(),
                                1,
                                None,
                                "owned-final-profile-withdrawal",
                                &|_| None,
                                &|_| Ok(()),
                            )
                            .unwrap();
                    }
                    1 => {
                        services
                            .projection_authority
                            .lock()
                            .unwrap()
                            .publish(
                                &mut services.store.conn(),
                                1,
                                None,
                                "owned-final-plan-withdrawal",
                                &|_| Ok(()),
                            )
                            .unwrap();
                    }
                    _ => {
                        services
                            .receipt_authority
                            .lock()
                            .unwrap()
                            .publish(
                                &mut services.store.conn(),
                                2,
                                &[],
                                "owned-final-key-withdrawal",
                                &|_| Ok(()),
                            )
                            .unwrap();
                    }
                }
            }
            true
        });
        let output = runtime
            .project_workload_observed(request, caller)
            .await
            .unwrap();
        assert_eq!(w.consumed(), 2);
        withdraw.store(true, Ordering::Release);
        assert!(output.into_reply(140).is_err());
        assert_eq!(w.consumed(), 2); // Late refusal cannot reopen consumed nonces.
    }
}
