//! Real local ownership and bounded blocking execution around paired projection.
use super::{
    permission_live::Request,
    projection, projection_authority, projection_receiver,
    projection_resources::Prepared,
    receipt_authority::{Current, Verifier},
    receipt_issuer::Issuer,
    receipt_keys::Refused,
};
use arc_swap::ArcSwap;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tokio::sync::Semaphore;
type Caller = Arc<dyn Fn() -> bool + Send + Sync>;
pub struct Runtime {
    resources: Arc<Prepared>,
    issuer: Arc<Issuer>,
    verifier: Verifier,
    profiles: Arc<ArcSwap<super::authority::Snapshot>>,
    applications: Arc<ArcSwap<crate::policy::types::ConfigSnapshot>>,
    plans: Arc<ArcSwap<projection_authority::Snapshot>>,
    store: crate::store::Store,
    clock: Arc<dyn crate::crypto::Clock>,
    workers: Arc<Semaphore>,
}
struct Active(Arc<AtomicBool>);
impl Drop for Active {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}
struct Fence {
    runtime: Arc<Runtime>,
    request: Arc<Request>,
    profile: Arc<super::authority::Snapshot>,
    application: Arc<crate::policy::types::ConfigSnapshot>,
    plan: Arc<projection_authority::Snapshot>,
    keys: Current,
    caller: Caller,
    active: Active,
    expires_ms: u64,
}
impl Fence {
    fn check(&self) -> Result<(), Refused> {
        if !self.active.0.load(Ordering::Acquire)
            || !(self.caller)()
            || !self.profile.available()
            || !Arc::ptr_eq(&self.profile, &self.runtime.profiles.load_full())
            || !Arc::ptr_eq(&self.application, &self.runtime.applications.load_full())
            || !Arc::ptr_eq(&self.plan, &self.runtime.plans.load_full())
            || !self.keys.current()
            || !self.plan.available()
            || self.runtime.now()? >= self.expires_ms
        {
            return Err(Refused);
        }
        Ok(())
    }
}
/// Output remains guarded through final header conversion. No Clone/Debug/serde.
pub struct Output {
    fence: Fence,
    value: projection::Output,
}
impl Output {
    pub fn expires_ms(&self) -> u64 {
        self.fence.expires_ms
    }
    pub fn into_header(self) -> Result<(http::HeaderName, http::HeaderValue), Refused> {
        self.fence.check()?;
        let context = self.fence.request.authentication_context()?;
        let result = self.value.into_header(
            context.service,
            context.audience,
            &context.request_sha256,
            self.fence.runtime.now()?,
        )?;
        self.fence.check()?;
        Ok(result)
    }
}
impl Runtime {
    /// Capture actual owners once at listener setup, never a request-defined owner.
    pub fn from_services(services: &crate::app::Services) -> Result<Option<Arc<Self>>, Refused> {
        let Some(resources) = services.projection_resources.clone() else {
            return Ok(None);
        };
        let issuer = services.receipt_issuer.clone().ok_or(Refused)?;
        let profiles = services
            .authentication_authority
            .as_ref()
            .ok_or(Refused)?
            .lock()
            .map_err(|_| Refused)?
            .reader();
        let verifier = services
            .receipt_authority
            .lock()
            .map_err(|_| Refused)?
            .verifier();
        let plans = services
            .projection_authority
            .lock()
            .map_err(|_| Refused)?
            .reader();
        Ok(Some(Arc::new(Self {
            resources,
            issuer,
            verifier,
            profiles,
            plans,
            applications: services.snapshot.clone(),
            store: services.store.clone(),
            clock: services.clock.clone(),
            workers: Arc::new(Semaphore::new(4)),
        })))
    }
    fn now(&self) -> Result<u64, Refused> {
        self.clock.now().0.try_into().map_err(|_| Refused)
    }
    /// Caller is a native transport-role recheck. It must never originate in
    /// request claims, scripts or a caller-provided allow flag.
    pub async fn project(
        self: &Arc<Self>,
        request: Arc<Request>,
        caller: Caller,
    ) -> Result<Output, Refused> {
        if !caller() {
            return Err(Refused);
        }
        let begun = std::time::Instant::now();
        let profile = self.profiles.load_full();
        let application = self.applications.load_full();
        let plan = self.plans.load_full();
        if !plan.available() || !plan.enabled() {
            return Err(Refused);
        }
        let context = request.authentication_context()?;
        let live = self.issuer.verify_live_service(
            &self.profiles,
            &self.applications,
            &context,
            &request.native().receipt,
            &context.request_sha256,
        )?;
        let local_expiry = live.expires_ms();
        let observed = self
            .resources
            .client
            .validate(request.clone(), &|| self.now().unwrap_or(0))
            .await
            .map_err(|_| Refused)?;
        live.current()?;
        let remaining = std::time::Duration::from_millis(
            observed
                .expires_ms()
                .min(local_expiry)
                .checked_sub(self.now()?)
                .ok_or(Refused)?,
        )
        .min(
            std::time::Duration::from_secs(1)
                .checked_sub(begun.elapsed())
                .ok_or(Refused)?,
        );
        if remaining.is_zero() {
            return Err(Refused);
        }
        let worker = self
            .workers
            .clone()
            .try_acquire_owned()
            .map_err(|_| Refused)?;
        let active = Active(Arc::new(AtomicBool::new(true)));
        let cancelled = active.0.clone();
        let runtime = self.clone();
        let output_runtime = self.clone();
        let expires_ms = observed.expires_ms().min(local_expiry);
        let task = tokio::task::spawn_blocking(move || {
            let _worker = worker;
            let keys = runtime.verifier.capture()?;
            let current = || -> Result<(), Refused> {
                if !cancelled.load(Ordering::Acquire)
                    || !caller()
                    || !profile.available()
                    || !keys.current()
                    || !plan.available()
                    || !Arc::ptr_eq(&profile, &runtime.profiles.load_full())
                    || !Arc::ptr_eq(&application, &runtime.applications.load_full())
                    || !Arc::ptr_eq(&plan, &runtime.plans.load_full())
                {
                    return Err(Refused);
                }
                Ok(())
            };
            current()?;
            let context = request.authentication_context()?;
            let live = runtime.issuer.verify_live_service(
                &runtime.profiles,
                &runtime.applications,
                &context,
                &request.native().receipt,
                &context.request_sha256,
            )?;
            let chain = projection_receiver::verify(
                observed,
                &runtime.resources.client,
                &runtime.verifier,
                runtime.now()?,
            )?;
            current()?;
            let value = chain.project(
                &runtime.resources.client,
                &plan,
                &mut runtime.store.conn(),
                &|| runtime.now().unwrap_or(0),
                &|_| {
                    current()?;
                    live.current()?;
                    Ok(())
                },
                &|reference| runtime.resources.resolve(reference),
            )?;
            current()?;
            live.current()?;
            Ok::<_, Refused>((value, request, profile, application, plan, keys, caller))
        });
        let (value, request, profile, application, plan, keys, caller) =
            tokio::time::timeout(remaining, task)
                .await
                .map_err(|_| Refused)?
                .map_err(|_| Refused)??;
        let fence = Fence {
            runtime: output_runtime,
            request,
            profile,
            application,
            plan,
            keys,
            caller,
            active,
            expires_ms,
        };
        fence.check()?;
        Ok(Output { fence, value })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::super::{projection_resources, receipt, receipt_binding, receipt_keys::Key};
    use super::*;
    use prost::Message;
    use pumgye_grpc::v1::{
        AuthenticatedResourceRequest, PermitValidationReply, PermitValidationRequest,
        ProjectionPermitReply,
        projection_permits_server::{ProjectionPermits, ProjectionPermitsServer},
    };
    use std::sync::atomic::AtomicU64;
    struct Peer(Arc<AtomicU64>);
    const TOKEN: &str = "owned-runtime-peer-credential-at-least-32-bytes";
    #[tonic::async_trait]
    impl ProjectionPermits for Peer {
        async fn issue(
            &self,
            _: tonic::Request<AuthenticatedResourceRequest>,
        ) -> Result<tonic::Response<ProjectionPermitReply>, tonic::Status> {
            Err(tonic::Status::unimplemented("protocol fixture only"))
        }
        async fn validate(
            &self,
            request: tonic::Request<PermitValidationRequest>,
        ) -> Result<tonic::Response<PermitValidationReply>, tonic::Status> {
            if request
                .metadata()
                .get("authorization")
                .and_then(|value| value.to_str().ok())
                != Some(concat!(
                    "Bearer ",
                    "owned-runtime-peer-credential-at-least-32-bytes"
                ))
            {
                return Err(tonic::Status::unauthenticated("fixture caller"));
            }
            self.0.fetch_add(1, Ordering::Relaxed);
            let input = request.into_inner();
            let proof = input
                .permit
                .ok_or_else(|| tonic::Status::invalid_argument("proof"))?;
            Ok(tonic::Response::new(PermitValidationReply {
                request_id: input.request_id,
                expires_ms: u64::from_be_bytes(proof.receipt[10..18].try_into().unwrap()),
                cache_ttl_ms: 0,
            }))
        }
    }
    async fn fresh(
        services: &crate::app::Services,
        router: &axum::Router,
        message: &hopae_grpc::v1::ServiceReceiptRequest,
        key: &str,
        plan_revision: u64,
    ) -> Arc<Request> {
        use sha2::{Digest, Sha256};
        let mut call = tonic::Request::new(message.clone());
        call.metadata_mut()
            .insert("authorization", format!("Bearer {key}").parse().unwrap());
        let auth = crate::http::grpc_gateway::issue_service_for_test(
            services.clone(),
            router.clone(),
            call,
        )
        .await
        .unwrap()
        .into_inner();
        let context = auth.context.as_ref().unwrap();
        let identity = context.identity.as_ref().unwrap();
        let signer = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
        let permission_context = receipt_binding::Context {
            issuer_ref: "pumgye",
            key_epoch: 1,
            identity_authority_epoch: &context.identity_authority_epoch,
            identity: receipt_binding::Identity {
                subject_ref: &identity.subject_ref,
                kind: super::super::PrincipalKind::Service,
                aal: 0,
                revision: identity.revision,
                credential_generation: identity.credential_generation,
            },
            service: &context.service,
            audience: &context.audience,
            request_sha256: [3; 32],
        };
        let binding = receipt_binding::Permit {
            authentication_receipt_sha256: Sha256::digest(&auth.receipt).into(),
            decision_ref: "owned-runtime-decision",
            resource: "db:orders",
            action: "select",
            authority_epoch: "owned-policy",
            catalog_revision: 1,
            policy_revision: 1,
            network_revision: 1,
            route_revision: 1,
            plan_revision,
        };
        let now = services.clock.now().0 as u64;
        let permission = receipt::sign(
            &signer,
            &receipt::Claims {
                purpose: receipt::Purpose::Permit,
                issued_ms: now,
                expires_ms: now + 800,
                binding: receipt_binding::digest(&permission_context, Some(&binding)).unwrap(),
                nonce: services_nonce(services),
            },
        )
        .unwrap();
        let mut native = AuthenticatedResourceRequest {
            request_id: auth.request_id,
            minimum_revision: 1,
            ip: vec![203, 0, 113, 9],
            resource: "db:orders".into(),
            action: "select".into(),
            context: Some(prost::Message::decode(context.encode_to_vec().as_slice()).unwrap()),
            receipt: auth.receipt,
            request_sha256: vec![3; 32],
            route: Some(pumgye_grpc::v1::NativeRouteReference {
                reference: vec![4; 32],
                destination_sha256: vec![5; 32],
            }),
        };
        let mut permission_context = native.context.clone().unwrap();
        permission_context.issuer_ref = "pumgye".into();
        let wire = ProjectionPermitReply {
            request_id: native.request_id,
            context: Some(permission_context),
            binding: Some(pumgye_grpc::v1::PermitBinding {
                authentication_receipt_sha256: binding.authentication_receipt_sha256.to_vec(),
                decision_ref: binding.decision_ref.into(),
                resource: binding.resource.into(),
                action: binding.action.into(),
                authority_epoch: binding.authority_epoch.into(),
                catalog_revision: 1,
                policy_revision: 1,
                network_revision: 1,
                route_revision: 1,
                plan_revision,
            }),
            receipt: permission.to_vec(),
            cache_ttl_ms: 0,
        };
        native.context.as_mut().unwrap().key_epoch = 1;
        Request::new(native, wire).unwrap()
    }
    fn services_nonce(services: &crate::app::Services) -> [u8; 32] {
        let mut nonce = [0; 32];
        services.rng.fill(&mut nonce);
        nonce
    }
    /// Real Hopae ownership/SQL with an explicit mTLS protocol mock for Pumgye.
    // Intentionally hold the owned store lock to test cancellation of queued work.
    #[allow(clippy::await_holding_lock)]
    pub(crate) async fn qualify(
        mut services: crate::app::Services,
        router: axum::Router,
        message: hopae_grpc::v1::ServiceReceiptRequest,
        key: &str,
        tlsdir: &std::path::Path,
    ) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = format!("https://{}", listener.local_addr().unwrap());
        let tls = hangang_runtime::configuration(
            &tlsdir.join("server.pem"),
            &tlsdir.join("server.key"),
            &tlsdir.join("ca.pem"),
        )
        .unwrap();
        let calls = Arc::new(AtomicU64::new(0));
        let peer = Peer(calls.clone());
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let resources = projection_resources::Configuration {
            authority: projection_resources::Authority {
                address: address.clone(),
                server_name: "hopae.example.test".into(),
                ca: tlsdir.join("ca.pem"),
                certificate: tlsdir.join("client.pem"),
                key: tlsdir.join("client.key"),
                token_env: "OWNED_PEER".into(),
            },
            secrets: vec![projection_resources::SecretReference {
                reference: "vault:runtime".into(),
                token_env: "OWNED_ORIGIN".into(),
            }],
        };
        services.projection_resources = Some(Arc::new(
            resources
                .prepare(&|name| {
                    Some(if name == "OWNED_PEER" {
                        TOKEN.into()
                    } else {
                        "owned-runtime-origin-token".into()
                    })
                })
                .unwrap(),
        ));
        services
            .receipt_authority
            .lock()
            .unwrap()
            .reconcile(
                &mut services.store.conn(),
                &[
                    Key {
                        issuer_ref: "owned".into(),
                        purpose: receipt::Purpose::Authentication,
                        epoch: 1,
                        public_key: ed25519_dalek::SigningKey::from_bytes(&[7; 32])
                            .verifying_key()
                            .to_bytes(),
                    },
                    Key {
                        issuer_ref: "pumgye".into(),
                        purpose: receipt::Purpose::Permit,
                        epoch: 1,
                        public_key: ed25519_dalek::SigningKey::from_bytes(&[9; 32])
                            .verifying_key()
                            .to_bytes(),
                    },
                ],
                "operator",
                &|_| Ok(()),
            )
            .unwrap();
        let revision = services
            .projection_authority
            .lock()
            .unwrap()
            .reader()
            .load()
            .revision();
        let plan_revision = revision + 1;
        services
            .projection_authority
            .lock()
            .unwrap()
            .publish(
                &mut services.store.conn(),
                revision,
                Some(super::super::projection::Configuration {
                    revision: plan_revision,
                    plans: vec![super::super::projection::Plan {
                        service: "orders".into(),
                        audience: "orders-api".into(),
                        minimum_aal: 0,
                        resource: "db:orders".into(),
                        action: "select".into(),
                        credential: super::super::projection::Credential::BearerReference {
                            secret_ref: "vault:runtime".into(),
                        },
                    }],
                }),
                "operator",
                &|_| Ok(()),
            )
            .unwrap();
        let runtime = Runtime::from_services(&services).unwrap().unwrap();
        let projection =
            crate::http::grpc_projection::server(runtime.clone(), services.caller_keys.clone());
        let running = tokio::spawn(async move {
            hangang_runtime::server(tls)
                .unwrap()
                .add_service(
                    ProjectionPermitsServer::new(peer)
                        .max_decoding_message_size(8192)
                        .max_encoding_message_size(128),
                )
                .add_service(projection)
                .serve_with_incoming_shutdown(hangang_runtime::incoming(listener), async {
                    let _ = stopped.await;
                })
                .await
                .unwrap();
        });

        let keys = services.caller_keys.clone();
        let caller_key = key.to_string();
        let caller: Caller = Arc::new(move || {
            matches!(
                keys.check(Some(caller_key.as_bytes())),
                crate::app::KeyVerdict::Accepted(_)
            )
        });
        let request = fresh(&services, &router, &message, key, plan_revision).await;
        let output = runtime
            .project(request.clone(), caller.clone())
            .await
            .unwrap();
        let (name, value) = output.into_header().unwrap();
        assert_eq!(name, "authorization");
        assert!(value.is_sensitive());
        assert!(runtime.project(request, caller.clone()).await.is_err());
        let count = || {
            services
                .store
                .conn()
                .query_row(
                    "SELECT count(*) FROM meta WHERE key LIKE 'projection_nonce_id:%'",
                    [],
                    |row| row.get::<_, u64>(0),
                )
                .unwrap()
        };
        assert_eq!(count(), 2);
        let request = fresh(&services, &router, &message, key, plan_revision).await;
        let output = runtime.project(request, caller.clone()).await.unwrap();
        let original = services.snapshot.load_full();
        services.snapshot.store(Arc::new((*original).clone()));
        assert!(output.into_header().is_err());
        services.snapshot.store(original);
        assert_eq!(count(), 4);
        let request = fresh(&services, &router, &message, key, plan_revision).await;
        let before = calls.load(Ordering::Relaxed);
        let keys = services.caller_keys.clone();
        let refused: Caller = Arc::new(move || {
            matches!(
                keys.check(Some(b"wrong")),
                crate::app::KeyVerdict::Accepted(_)
            )
        });
        assert!(runtime.project(request, refused).await.is_err());
        assert_eq!(calls.load(Ordering::Relaxed), before);
        let held = runtime.workers.clone().acquire_many_owned(4).await.unwrap();
        let request = fresh(&services, &router, &message, key, plan_revision).await;
        assert!(runtime.project(request, caller.clone()).await.is_err());
        drop(held);
        assert_eq!(count(), 4);
        let request = fresh(&services, &router, &message, key, plan_revision).await;
        let lock = services.store.conn();
        let r = runtime.clone();
        let c = caller.clone();
        let pending = tokio::spawn(async move { r.project(request, c).await });
        tokio::time::timeout(std::time::Duration::from_millis(700), async {
            while runtime.workers.available_permits() == 4 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        pending.abort();
        assert!(pending.await.err().unwrap().is_cancelled());
        drop(lock);
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while runtime.workers.available_permits() != 4 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(count(), 4);
        // Exercise the actual Hopae receiver RPC; only the Pumgye protocol peer is mocked.
        let tls = tonic::transport::ClientTlsConfig::new()
            .domain_name("hopae.example.test")
            .ca_certificate(tonic::transport::Certificate::from_pem(
                std::fs::read(tlsdir.join("ca.pem")).unwrap(),
            ))
            .identity(tonic::transport::Identity::from_pem(
                std::fs::read(tlsdir.join("client.pem")).unwrap(),
                std::fs::read(tlsdir.join("client.key")).unwrap(),
            ));
        let channel = tonic::transport::Endpoint::from_shared(address)
            .unwrap()
            .tls_config(tls)
            .unwrap()
            .connect()
            .await
            .unwrap();
        let mut client =
            hopae_grpc::v1::credential_projection_client::CredentialProjectionClient::new(channel)
                .max_encoding_message_size(8448)
                .max_decoding_message_size(8192);
        let request_rpc = fresh(&services, &router, &message, key, plan_revision).await;
        let payload = PermitValidationRequest {
            request_id: 9001,
            request: Some(request_rpc.native().clone()),
            permit: Some(request_rpc.permit().clone()),
        }
        .encode_to_vec();
        let rpc = |token: &str, contract| {
            let mut request = tonic::Request::new(hopae_grpc::v1::ProjectionRequest {
                request_id: 9001,
                permission_contract: contract,
                permission_query: payload.clone(),
            });
            let mut token: tonic::metadata::MetadataValue<_> =
                format!("Bearer {token}").parse().unwrap();
            token.set_sensitive(true);
            request.metadata_mut().insert("authorization", token);
            request
        };
        assert_eq!(
            client.project(rpc("wrong", 1)).await.err().unwrap().code(),
            tonic::Code::Unauthenticated
        );
        assert_eq!(
            client.project(rpc(key, 2)).await.err().unwrap().code(),
            tonic::Code::InvalidArgument
        );
        let reply = client.project(rpc(key, 1)).await.unwrap().into_inner();
        assert_eq!(
            (reply.request_id, reply.plan_revision),
            (9001, plan_revision)
        );
        assert_eq!(reply.header_name, "authorization");
        assert!(reply.header_value == b"Bearer owned-runtime-origin-token");
        assert_eq!(reply.request_sha256, vec![3; 32]);
        assert!(!format!("{reply:?}").contains("owned-runtime-origin-token"));
        assert_eq!(
            client.project(rpc(key, 1)).await.err().unwrap().code(),
            tonic::Code::Unavailable
        );
        assert_eq!(count(), 6);
        let request = fresh(&services, &router, &message, key, plan_revision).await;
        let output = runtime.project(request, caller).await.unwrap();
        services
            .receipt_authority
            .lock()
            .unwrap()
            .publish(&mut services.store.conn(), 1, &[], "operator", &|_| Ok(()))
            .unwrap();
        assert!(output.into_header().is_err());
        stop.send(()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(3), running)
            .await
            .unwrap()
            .unwrap();
    }
}
