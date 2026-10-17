//! Fixed native Pumgye current-owner observations, never replay admission.
use prost::Message;
use pumgye_grpc::v1::{
    AuthenticatedResourceRequest, PermitValidationReply, PermitValidationRequest,
    ProjectionPermitReply, projection_permits_client::ProjectionPermitsClient,
};
use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::Semaphore;
use tonic::{
    metadata::MetadataValue,
    transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity},
};
const MAXIMUM: u64 = 9_007_199_254_740_991;
#[derive(Debug, PartialEq, Eq)]
pub struct Refused;
/// Immutable private fields. This is unverified input until an actual owner RPC.
/// Retained Arc identity prevents mutation or substitution after observation.
pub struct Request {
    native: AuthenticatedResourceRequest,
    permit: ProjectionPermitReply,
    observed_chain_sha256: Option<[u8; 32]>,
}
impl Request {
    pub fn new(
        native: AuthenticatedResourceRequest,
        permit: ProjectionPermitReply,
    ) -> Result<Arc<Self>, Refused> {
        if native.encoded_len() > 4096
            || permit.encoded_len() > 2048
            || !(1..=MAXIMUM).contains(&native.request_id)
            || permit.request_id != native.request_id
            || native.minimum_revision > MAXIMUM
            || native.receipt.len() != hopae_grpc::receipt::LENGTH
            || permit.receipt.len() != hopae_grpc::receipt::LENGTH
            || native.request_sha256.len() != 32
            || native.context.is_none()
            || permit.context.is_none()
            || permit.binding.is_none()
            || native.route.as_ref().is_none_or(|route| {
                route.reference.len() != 32 || route.destination_sha256.len() != 32
            })
            || !matches!(native.ip.len(), 4 | 16)
            || permit.cache_ttl_ms != 0
        {
            return Err(Refused);
        }
        Ok(Arc::new(Self {
            native,
            permit,
            observed_chain_sha256: None,
        }))
    }
    pub(crate) fn decode_observed_query(
        bytes: &[u8],
        request_id: u64,
    ) -> Result<Arc<Self>, Refused> {
        use sha2::{Digest as _, Sha256};
        if bytes.len() > 8192 {
            return Err(Refused);
        }
        let query = PermitValidationRequest::decode(bytes).map_err(|_| Refused)?;
        if query.request_id != request_id {
            return Err(Refused);
        }
        let mut request = Self::new(query.request.ok_or(Refused)?, query.permit.ok_or(Refused)?)?;
        Arc::get_mut(&mut request)
            .ok_or(Refused)?
            .observed_chain_sha256 = Some(Sha256::digest(bytes).into());
        Ok(request)
    }
    pub(crate) fn observed_chain_sha256(&self) -> Result<[u8; 32], super::receipt_keys::Refused> {
        self.observed_chain_sha256
            .ok_or(super::receipt_keys::Refused)
    }
    pub(crate) fn authentication_context(
        &self,
    ) -> Result<super::receipt_binding::Context<'_>, super::receipt_keys::Refused> {
        use super::{
            PrincipalKind,
            receipt_binding::{Context, Identity},
            receipt_keys::Refused,
        };
        let context = self.native.context.as_ref().ok_or(Refused)?;
        let identity = context.identity.as_ref().ok_or(Refused)?;
        if identity.kind != 2 || identity.aal != 0 {
            return Err(Refused);
        }
        Ok(Context {
            issuer_ref: &context.issuer_ref,
            key_epoch: context.key_epoch,
            identity_authority_epoch: &context.identity_authority_epoch,
            identity: Identity {
                subject_ref: &identity.subject_ref,
                kind: PrincipalKind::Service,
                aal: 0,
                revision: identity.revision,
                credential_generation: identity.credential_generation,
            },
            service: &context.service,
            audience: &context.audience,
            request_sha256: context
                .request_sha256
                .as_slice()
                .try_into()
                .map_err(|_| Refused)?,
        })
    }
    pub(crate) fn permission_context(
        &self,
    ) -> Result<super::receipt_binding::Context<'_>, super::receipt_keys::Refused> {
        use super::{
            PrincipalKind,
            receipt_binding::{Context, Identity},
            receipt_keys::Refused,
        };
        let p = self.permit.context.as_ref().ok_or(Refused)?;
        let i = p.identity.as_ref().ok_or(Refused)?;
        if i.kind != 2 || i.aal != 0 {
            return Err(Refused);
        }
        Ok(Context {
            issuer_ref: &p.issuer_ref,
            key_epoch: p.key_epoch,
            identity_authority_epoch: &p.identity_authority_epoch,
            identity: Identity {
                subject_ref: &i.subject_ref,
                kind: PrincipalKind::Service,
                aal: 0,
                revision: i.revision,
                credential_generation: i.credential_generation,
            },
            service: &p.service,
            audience: &p.audience,
            request_sha256: p
                .request_sha256
                .as_slice()
                .try_into()
                .map_err(|_| Refused)?,
        })
    }
    pub(crate) fn binding(
        &self,
    ) -> Result<super::receipt_binding::Permit<'_>, super::receipt_keys::Refused> {
        use super::{receipt_binding::Permit, receipt_keys::Refused};
        let b = self.permit.binding.as_ref().ok_or(Refused)?;
        Ok(Permit {
            authentication_receipt_sha256: b
                .authentication_receipt_sha256
                .as_slice()
                .try_into()
                .map_err(|_| Refused)?,
            decision_ref: &b.decision_ref,
            resource: &b.resource,
            action: &b.action,
            authority_epoch: &b.authority_epoch,
            catalog_revision: b.catalog_revision,
            policy_revision: b.policy_revision,
            network_revision: b.network_revision,
            route_revision: b.route_revision,
            plan_revision: b.plan_revision,
        })
    }
    pub fn native(&self) -> &AuthenticatedResourceRequest {
        &self.native
    }
    pub fn permit(&self) -> &ProjectionPermitReply {
        &self.permit
    }
}
pub struct Client {
    rpc: ProjectionPermitsClient<Channel>,
    observed_rpc:
        pumgye_grpc::v1::observed_projection_permits_client::ObservedProjectionPermitsClient<
            Channel,
        >,
    credential: MetadataValue<tonic::metadata::Ascii>,
    admission: Semaphore,
    sequence: AtomicU64,
    owner: Arc<()>,
}
/// No public constructor, Clone, Debug or serde. A proof of a point-in-time RPC,
/// not a permission to resolve secrets or a distributed lease.
pub struct Observation {
    request: Arc<Request>,
    owner: Arc<()>,
    before_ms: u64,
    expires_ms: u64,
    begun: Instant,
}
impl Observation {
    pub(crate) fn request(&self) -> &Arc<Request> {
        &self.request
    }
    pub fn expires_ms(&self) -> u64 {
        self.expires_ms
    }
    pub fn valid_for(&self, request: &Arc<Request>, client: &Client, now: u64) -> bool {
        Arc::ptr_eq(&self.request, request)
            && Arc::ptr_eq(&self.owner, &client.owner)
            && now >= self.before_ms
            && now.max(
                self.before_ms
                    .saturating_add(self.begun.elapsed().as_millis().min(u64::MAX as u128) as u64),
            ) < self.expires_ms
    }
}
/// Private fixed-owner authenticated completion, not caller numeric evidence.
pub(crate) struct ObservedObservation {
    request: Arc<Request>,
    owner: Arc<()>,
    proof: super::receipt_replay::ObservedProof,
}
impl ObservedObservation {
    pub(crate) fn into_proof(
        self,
        request: &Arc<Request>,
        client: &Client,
        clock: &hangang_runtime::time::ReceiverClock,
    ) -> Result<super::receipt_replay::ObservedProof, super::receipt_keys::Refused> {
        if !Arc::ptr_eq(&self.request, request) || !Arc::ptr_eq(&self.owner, &client.owner) {
            return Err(super::receipt_keys::Refused);
        }
        self.proof.remaining(clock)?;
        Ok(self.proof)
    }
}
impl Client {
    /// Native configured endpoint only. Validates mTLS material now, connects
    /// lazily to avoid an authority startup cycle, and reuses the h2 channel.
    pub fn prepare(
        address: &str,
        server_name: &str,
        ca: &[u8],
        certificate: &[u8],
        key: &[u8],
        token: &str,
    ) -> Result<Self, Refused> {
        let uri: tonic::codegen::http::Uri = address.parse().map_err(|_| Refused)?;
        if address.len() > 256
            || uri.scheme_str() != Some("https")
            || uri
                .authority()
                .is_none_or(|authority| authority.as_str().contains('@'))
            || uri
                .path_and_query()
                .is_some_and(|path| path.as_str() != "/")
            || uri.port_u16() == Some(0)
            || server_name.is_empty()
            || server_name.len() > 253
            || !server_name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".-".contains(&b))
            || [ca, certificate, key]
                .iter()
                .any(|value| value.is_empty() || value.len() > 128 * 1024)
            || !(32..=256).contains(&token.len())
            || !token.bytes().all(|b| b.is_ascii_graphic())
        {
            return Err(Refused);
        }
        let mut credential: MetadataValue<tonic::metadata::Ascii> =
            format!("Bearer {token}").parse().map_err(|_| Refused)?;
        credential.set_sensitive(true);
        let tls = ClientTlsConfig::new()
            .domain_name(server_name)
            .ca_certificate(Certificate::from_pem(ca))
            .identity(Identity::from_pem(certificate, key));
        let channel = Endpoint::from_shared(address.to_owned())
            .map_err(|_| Refused)?
            .connect_timeout(Duration::from_secs(1))
            .timeout(Duration::from_secs(1))
            .tcp_nodelay(true)
            .tls_config(tls)
            .map_err(|_| Refused)?
            .connect_lazy();
        Ok(Self {
            observed_rpc: pumgye_grpc::v1::observed_projection_permits_client::ObservedProjectionPermitsClient::new(channel.clone()).max_encoding_message_size(8192).max_decoding_message_size(1024),
            rpc: ProjectionPermitsClient::new(channel)
                .max_encoding_message_size(8192)
                .max_decoding_message_size(128),
            credential,
            admission: Semaphore::new(128),
            sequence: AtomicU64::new(1),
            owner: Arc::new(()),
        })
    }
    pub(crate) async fn observe(
        &self,
        request: Arc<Request>,
        verifier: &super::receipt_authority::Verifier,
        clock: &hangang_runtime::time::ReceiverClock,
        rates: &hopae_grpc::receipt_time::ClockRates,
    ) -> Result<ObservedObservation, super::receipt_keys::Refused> {
        use super::receipt_keys::Refused;
        let _admission = self.admission.try_acquire().map_err(|_| Refused)?;
        let context = request.permission_context()?;
        let binding = request.binding()?;
        let checked = verifier.verify_observed_signature(
            &context,
            Some(&binding),
            &request.permit.receipt,
        )?;
        let request_id = self
            .sequence
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                (v < MAXIMUM).then(|| v + 1)
            })
            .map_err(|_| Refused)?;
        let start = clock.begin_exchange().map_err(|_| Refused)?;
        let mut rpc = tonic::Request::new(PermitValidationRequest {
            request_id,
            request: Some(request.native.clone()),
            permit: Some(request.permit.clone()),
        });
        rpc.metadata_mut()
            .insert("authorization", self.credential.clone());
        rpc.set_timeout(Duration::from_secs(1));
        let reply = tokio::time::timeout(
            Duration::from_secs(1),
            self.observed_rpc.clone().observe(rpc),
        )
        .await
        .map_err(|_| Refused)?
        .map_err(|_| Refused)?
        .into_inner();
        let exchange = clock.finish_exchange(start).map_err(|_| Refused)?;
        let signed_remaining = checked
            .evidence()
            .claims()
            .expires_ms
            .checked_sub(reply.owner_now_ms)
            .ok_or(Refused)?;
        let domain = reply
            .clock_domain
            .strip_prefix("pobs1:")
            .and_then(|v| v.split_once(':'))
            .ok_or(Refused)?;
        if domain.0.len() != 32
            || !domain
                .0
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || domain.0.bytes().all(|b| b == b'0')
            || domain.1.is_empty()
            || domain.1.len() > 64
            || !domain
                .1
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
            || reply.request_id != request_id
            || reply.cache_ttl_ms != 0
            || reply.clock_domain != binding.authority_epoch
            || reply.receipt_sha256.as_slice() != checked.evidence().sha256()
            || u64::from(reply.proof_remaining_ms) != signed_remaining
            || reply.policy_revision != binding.policy_revision
            || reply.network_revision != binding.network_revision
            || reply.route_revision != binding.route_revision
            || reply.plan_revision != binding.plan_revision
        {
            return Err(Refused);
        }
        let proof = super::receipt_replay::ObservedProof::from_owner_report(
            checked,
            reply.clock_domain,
            &hopae_grpc::receipt_time::Report {
                owner_now_ms: reply.owner_now_ms,
                remaining_ms: reply.remaining_ms,
                receipt_sha256: reply
                    .receipt_sha256
                    .as_slice()
                    .try_into()
                    .map_err(|_| Refused)?,
            },
            exchange,
            rates,
        )?;
        Ok(ObservedObservation {
            request,
            owner: self.owner.clone(),
            proof,
        })
    }
    pub async fn validate(
        &self,
        request: Arc<Request>,
        clock: &(dyn Fn() -> u64 + Sync),
    ) -> Result<Observation, Refused> {
        let _admission = self.admission.try_acquire().map_err(|_| Refused)?;
        let request_id = self
            .sequence
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                (value < MAXIMUM).then(|| value + 1)
            })
            .map_err(|_| Refused)?;
        let before_ms = clock();
        let begun = Instant::now();
        let mut rpc = tonic::Request::new(PermitValidationRequest {
            request_id,
            request: Some(request.native.clone()),
            permit: Some(request.permit.clone()),
        });
        rpc.metadata_mut()
            .insert("authorization", self.credential.clone());
        rpc.set_timeout(Duration::from_secs(1));
        let reply = tokio::time::timeout(Duration::from_secs(1), self.rpc.clone().validate(rpc))
            .await
            .map_err(|_| Refused)?
            .map_err(|_| Refused)?
            .into_inner();
        self.accept(request, request_id, before_ms, clock(), begun, reply)
    }
    fn accept(
        &self,
        request: Arc<Request>,
        request_id: u64,
        before_ms: u64,
        after_ms: u64,
        begun: Instant,
        reply: PermitValidationReply,
    ) -> Result<Observation, Refused> {
        let permission_expiry = u64::from_be_bytes(
            request.permit.receipt[10..18]
                .try_into()
                .map_err(|_| Refused)?,
        );
        let authentication_expiry = u64::from_be_bytes(
            request.native.receipt[10..18]
                .try_into()
                .map_err(|_| Refused)?,
        );
        if reply.request_id != request_id
            || reply.cache_ttl_ms != 0
            || after_ms < before_ms
            || reply.expires_ms > permission_expiry.min(authentication_expiry)
            || reply.expires_ms > before_ms.checked_add(1000).ok_or(Refused)?
        {
            return Err(Refused);
        }
        let observed = Observation {
            request: request.clone(),
            owner: self.owner.clone(),
            before_ms,
            expires_ms: reply.expires_ms,
            begun,
        };
        if !observed.valid_for(&request, self, after_ms) {
            return Err(Refused);
        }
        Ok(observed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pumgye_grpc::v1::NativeRouteReference;
    fn request(expiry: u64) -> Arc<Request> {
        let mut bytes = vec![0; hopae_grpc::receipt::LENGTH];
        bytes[10..18].copy_from_slice(&expiry.to_be_bytes());
        Request::new(
            AuthenticatedResourceRequest {
                request_id: 7,
                minimum_revision: 1,
                ip: vec![192, 0, 2, 1],
                resource: "db:orders".into(),
                action: "select".into(),
                context: Some(Default::default()),
                receipt: bytes.clone(),
                request_sha256: vec![3; 32],
                route: Some(NativeRouteReference {
                    reference: vec![4; 32],
                    destination_sha256: vec![5; 32],
                }),
            },
            ProjectionPermitReply {
                request_id: 7,
                context: Some(Default::default()),
                binding: Some(Default::default()),
                receipt: bytes,
                cache_ttl_ms: 0,
            },
        )
        .unwrap()
    }
    fn client() -> Client {
        Client {
            observed_rpc:pumgye_grpc::v1::observed_projection_permits_client::ObservedProjectionPermitsClient::new(Channel::from_static("https://owned.example.test").connect_lazy()),
            rpc: ProjectionPermitsClient::new(
                Channel::from_static("https://owned.example.test").connect_lazy(),
            ),
            credential: "Bearer owned-fixture".parse().unwrap(),
            admission: Semaphore::new(1),
            sequence: AtomicU64::new(1),
            owner: Arc::new(()),
        }
    }
    #[tokio::test]
    async fn observed_transport_owner_exact_request_and_elapsed_deadline_are_bound() {
        let client = client();
        let other = self::client();
        let request = request(1900);
        let duplicate = Request::new(request.native.clone(), request.permit.clone()).unwrap();
        let reply = || PermitValidationReply {
            request_id: 7,
            expires_ms: 1800,
            cache_ttl_ms: 0,
        };
        let observed = client
            .accept(request.clone(), 7, 1000, 1001, Instant::now(), reply())
            .unwrap();
        assert_eq!(observed.expires_ms(), 1800);
        assert!(observed.valid_for(&request, &client, 1002));
        assert!(!observed.valid_for(&duplicate, &client, 1002));
        assert!(!observed.valid_for(&request, &other, 1002));
        assert!(!observed.valid_for(&request, &client, 999));
        assert!(!observed.valid_for(&request, &client, 1800));
        assert!(
            client
                .accept(
                    request.clone(),
                    7,
                    1000,
                    1001,
                    Instant::now() - Duration::from_secs(2),
                    reply()
                )
                .is_err()
        );
        for case in 0..5 {
            let mut bad = reply();
            match case {
                0 => bad.request_id = 8,
                1 => bad.cache_ttl_ms = 1,
                2 => bad.expires_ms = 1001,
                3 => bad.expires_ms = 1901,
                _ => bad.expires_ms = 2001,
            }
            assert!(
                client
                    .accept(request.clone(), 7, 1000, 1001, Instant::now(), bad)
                    .is_err(),
                "case {case}"
            );
        }
        assert!(
            client
                .accept(request.clone(), 7, 1000, 999, Instant::now(), reply())
                .is_err()
        );
        let permit = client.admission.acquire().await.unwrap();
        assert!(client.validate(request.clone(), &|| 1000).await.is_err());
        drop(permit);
        client.sequence.store(MAXIMUM, Ordering::Relaxed);
        assert!(client.validate(request, &|| 1000).await.is_err());
    }
    #[test]
    fn bounded_request_constructor_cannot_skip_native_route_and_proof_shapes() {
        let good = request(1900);
        for case in 0..6 {
            let mut native = good.native.clone();
            let mut permit = good.permit.clone();
            match case {
                0 => native.route = None,
                1 => native.receipt.clear(),
                2 => permit.receipt.clear(),
                3 => native.request_id = 0,
                4 => permit.context = None,
                _ => native.resource = "x".repeat(8192),
            }
            assert!(Request::new(native, permit).is_err(), "case {case}");
        }
    }
    #[tokio::test]
    async fn actual_mtls_protocol_requires_peer_caller_and_bounded_correlated_ack() {
        use pumgye_grpc::v1::projection_permits_server::{
            ProjectionPermits, ProjectionPermitsServer,
        };
        use std::sync::atomic::AtomicU8;
        struct Peer(Arc<AtomicU8>);
        const TOKEN: &str = "owned-caller-credential-at-least-32-bytes";
        #[tonic::async_trait]
        impl ProjectionPermits for Peer {
            async fn issue(
                &self,
                _: tonic::Request<AuthenticatedResourceRequest>,
            ) -> Result<tonic::Response<ProjectionPermitReply>, tonic::Status> {
                Err(tonic::Status::unimplemented(
                    "fixture validates transport only",
                ))
            }
            async fn validate(
                &self,
                request: tonic::Request<PermitValidationRequest>,
            ) -> Result<tonic::Response<PermitValidationReply>, tonic::Status> {
                if request
                    .metadata()
                    .get("authorization")
                    .and_then(|v| v.to_str().ok())
                    != Some(concat!(
                        "Bearer ",
                        "owned-caller-credential-at-least-32-bytes"
                    ))
                {
                    return Err(tonic::Status::unauthenticated("fixture caller required"));
                }
                let input = request.into_inner();
                let proof = input
                    .permit
                    .ok_or_else(|| tonic::Status::invalid_argument("fixture proof required"))?;
                let mode = self.0.load(Ordering::Acquire);
                if mode == 3 {
                    return Err(tonic::Status::permission_denied("fixture refusal"));
                }
                if mode == 4 {
                    tokio::time::sleep(Duration::from_millis(1100)).await;
                }
                Ok(tonic::Response::new(PermitValidationReply {
                    request_id: input.request_id + u64::from(mode == 1),
                    expires_ms: u64::from_be_bytes(proof.receipt[10..18].try_into().unwrap()),
                    cache_ttl_ms: u32::from(mode == 2),
                }))
            }
        }
        let root = tempfile::tempdir().unwrap();
        let openssl = |args: &[&str]| {
            assert!(
                std::process::Command::new("openssl")
                    .args(args)
                    .current_dir(root.path())
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
        for (name, usage) in [("server", "serverAuth"), ("client", "clientAuth")] {
            openssl(&[
                "req",
                "-new",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-subj",
                "/CN=owned",
                "-keyout",
                &format!("{name}.key"),
                "-out",
                &format!("{name}.csr"),
            ]);
            std::fs::write(root.path().join(format!("{name}.ext")),format!("basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage={usage}\nsubjectAltName=DNS:pumgye.example.test\n")).unwrap();
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
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = format!("https://{}", listener.local_addr().unwrap());
        let tls = hangang_runtime::configuration(
            &root.path().join("server.pem"),
            &root.path().join("server.key"),
            &root.path().join("ca.pem"),
        )
        .unwrap();
        let mode = Arc::new(AtomicU8::new(0));
        let service = ProjectionPermitsServer::new(Peer(mode.clone()))
            .max_decoding_message_size(8192)
            .max_encoding_message_size(128);
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let running = tokio::spawn(async move {
            hangang_runtime::server(tls)
                .unwrap()
                .add_service(service)
                .serve_with_incoming_shutdown(hangang_runtime::incoming(listener), async {
                    let _ = stopped.await;
                })
                .await
                .unwrap();
        });
        let ca = std::fs::read(root.path().join("ca.pem")).unwrap();
        let certificate = std::fs::read(root.path().join("client.pem")).unwrap();
        let key = std::fs::read(root.path().join("client.key")).unwrap();
        let client = Client::prepare(
            &address,
            "pumgye.example.test",
            &ca,
            &certificate,
            &key,
            TOKEN,
        )
        .unwrap();
        let now = || {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64
        };
        let resources = super::super::projection_resources::Configuration {
            human_observed_scopes: vec![],
            workload_observed_scopes: vec![],
            observed_clock_rates: None,
            authority: super::super::projection_resources::Authority {
                address: address.clone(),
                server_name: "pumgye.example.test".into(),
                ca: root.path().join("ca.pem"),
                certificate: root.path().join("client.pem"),
                key: root.path().join("client.key"),
                token_env: "OWNED_AUTHORITY".into(),
            },
            secrets: vec![super::super::projection_resources::SecretReference {
                reference: "vault:owned".into(),
                token_env: "OWNED_ORIGIN".into(),
            }],
        };
        let prepared = resources
            .prepare(&|name| match name {
                "OWNED_AUTHORITY" => Some(TOKEN.into()),
                "OWNED_ORIGIN" => Some("owned-upstream-token".into()),
                _ => None,
            })
            .unwrap();
        assert!(
            prepared
                .client
                .validate(request(now() + 900), &now)
                .await
                .is_ok()
        );
        assert!(prepared.resolve("vault:owned").is_ok());
        assert!(prepared.resolve("vault:other").is_err());
        assert!(
            resources
                .prepare(&|name| if name == "OWNED_AUTHORITY" {
                    Some(TOKEN.into())
                } else {
                    Some("bad\r\ncredential".into())
                })
                .is_err()
        );
        let mut malformed = resources.clone();
        malformed.authority.key = root.path().join("malformed-client.key");
        std::fs::write(&malformed.authority.key, b"not a private key").unwrap();
        assert!(malformed.prepare(&|_| Some(TOKEN.into())).is_err());
        let mut invalid = resources.clone();
        invalid.authority.ca = root.path().join("oversized.pem");
        std::fs::write(&invalid.authority.ca, vec![b'x'; 128 * 1024 + 1]).unwrap();
        assert!(invalid.prepare(&|_| Some(TOKEN.into())).is_err());
        let input = request(now() + 900);
        let observed = client.validate(input.clone(), &now).await.unwrap();
        assert!(observed.valid_for(&input, &client, now()));
        for value in [1, 2, 3, 4] {
            mode.store(value, Ordering::Release);
            assert!(
                client.validate(request(now() + 900), &now).await.is_err(),
                "mode {value}"
            );
        }
        mode.store(0, Ordering::Release);
        let wrong = Client::prepare(
            &address,
            "wrong.example.test",
            &ca,
            &certificate,
            &key,
            TOKEN,
        )
        .unwrap();
        assert!(wrong.validate(request(now() + 900), &now).await.is_err());
        let wrong = Client::prepare(
            &address,
            "pumgye.example.test",
            &ca,
            &certificate,
            &key,
            "wrong-caller-credential-at-least-32-bytes",
        )
        .unwrap();
        assert!(wrong.validate(request(now() + 900), &now).await.is_err());
        assert!(client.validate(request(now() + 900), &now).await.is_ok());
        stop.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(3), running)
            .await
            .unwrap()
            .unwrap();
    }
    fn signed_chain() -> (
        rusqlite::Connection,
        super::super::receipt_authority::Authority,
        Arc<super::super::projection_authority::Snapshot>,
        Arc<Request>,
    ) {
        use super::super::{
            projection, projection_authority, receipt, receipt_authority, receipt_binding,
            receipt_keys,
        };
        use sha2::{Digest, Sha256};
        let mut db = rusqlite::Connection::open_in_memory().unwrap();
        db.execute_batch("CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT NOT NULL); INSERT INTO meta VALUES('owned_identity_revision','1');").unwrap();
        let auth_key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let permit_key = ed25519_dalek::SigningKey::from_bytes(&[8; 32]);
        let mut keys = receipt_authority::Authority::load(&db, 0).unwrap();
        keys.publish(
            &mut db,
            0,
            &[
                receipt_keys::Key {
                    issuer_ref: "hopae".into(),
                    purpose: receipt::Purpose::Authentication,
                    epoch: 1,
                    public_key: auth_key.verifying_key().to_bytes(),
                },
                receipt_keys::Key {
                    issuer_ref: "pumgye".into(),
                    purpose: receipt::Purpose::Permit,
                    epoch: 1,
                    public_key: permit_key.verifying_key().to_bytes(),
                },
            ],
            "operator",
            &|_| Ok(()),
        )
        .unwrap();
        let a = receipt_binding::Context {
            issuer_ref: "hopae",
            key_epoch: 1,
            identity_authority_epoch: "owned-auth",
            identity: receipt_binding::Identity {
                subject_ref: "s_owned",
                kind: super::super::PrincipalKind::Service,
                aal: 0,
                revision: 1,
                credential_generation: 1,
            },
            service: "orders",
            audience: "orders-api",
            request_sha256: [3; 32],
        };
        let auth = receipt::sign(
            &auth_key,
            &receipt::Claims {
                purpose: receipt::Purpose::Authentication,
                issued_ms: 100,
                expires_ms: 900,
                binding: receipt_binding::digest(&a, None).unwrap(),
                nonce: [1; 32],
            },
        )
        .unwrap();
        let p = receipt_binding::Permit {
            authentication_receipt_sha256: Sha256::digest(auth).into(),
            decision_ref: "owned-decision",
            resource: "db:orders",
            action: "select",
            authority_epoch: "owned-policy",
            catalog_revision: 1,
            policy_revision: 1,
            network_revision: 1,
            route_revision: 1,
            plan_revision: 1,
        };
        let context = receipt_binding::Context {
            issuer_ref: "pumgye",
            ..a
        };
        let permission = receipt::sign(
            &permit_key,
            &receipt::Claims {
                purpose: receipt::Purpose::Permit,
                issued_ms: 102,
                expires_ms: 800,
                binding: receipt_binding::digest(&context, Some(&p)).unwrap(),
                nonce: [2; 32],
            },
        )
        .unwrap();
        let base = request(1900);
        let mut native = base.native.clone();
        native.receipt = auth.to_vec();
        let context = native.context.as_mut().unwrap();
        context.issuer_ref = "hopae".into();
        context.key_epoch = 1;
        context.identity_authority_epoch = "owned-auth".into();
        context.service = "orders".into();
        context.audience = "orders-api".into();
        context.request_sha256 = vec![3; 32];
        context.identity = Some(Default::default());
        let identity = context.identity.as_mut().unwrap();
        identity.subject_ref = "s_owned".into();
        identity.kind = 2;
        identity.revision = 1;
        identity.credential_generation = 1;
        let mut wire = base.permit.clone();
        wire.context = native.context.clone();
        wire.context.as_mut().unwrap().issuer_ref = "pumgye".into();
        wire.receipt = permission.to_vec();
        let binding = wire.binding.as_mut().unwrap();
        binding.authentication_receipt_sha256 = p.authentication_receipt_sha256.to_vec();
        binding.decision_ref = "owned-decision".into();
        binding.resource = "db:orders".into();
        binding.action = "select".into();
        binding.authority_epoch = "owned-policy".into();
        binding.catalog_revision = 1;
        binding.policy_revision = 1;
        binding.network_revision = 1;
        binding.route_revision = 1;
        binding.plan_revision = 1;
        let request = Request::new(native, wire).unwrap();
        let mut plans = projection_authority::Authority::load(&db, 0).unwrap();
        plans
            .publish(
                &mut db,
                0,
                Some(projection::Configuration {
                    revision: 1,
                    plans: vec![projection::Plan {
                        service: "orders".into(),
                        audience: "orders-api".into(),
                        minimum_aal: 0,
                        resource: "db:orders".into(),
                        action: "select".into(),
                        credential: projection::Credential::BearerReference {
                            secret_ref: "vault:owned".into(),
                        },
                    }],
                }),
                "operator",
                &|_| Ok(()),
            )
            .unwrap();
        (db, keys, plans.reader().load_full(), request)
    }
    fn local_identity(
        db: &dyn crate::store::meta::MetaTx,
    ) -> Result<(), super::super::receipt_keys::Refused> {
        let revision: String = db
            .sqlite()
            .unwrap()
            .query_row(
                "SELECT value FROM meta WHERE key='owned_identity_revision'",
                [],
                |row| row.get(0),
            )
            .map_err(|_| super::super::receipt_keys::Refused)?;
        if revision != "1" {
            return Err(super::super::receipt_keys::Refused);
        }
        Ok(())
    }
    #[tokio::test]
    async fn receiver_checks_both_signatures_consumes_pair_once_and_caps_secret_expiry() {
        use super::super::projection_receiver;
        let (mut db, keys, plan, request) = signed_chain();
        let client = client();
        let calls = std::cell::Cell::new(0);
        let resolve = |_: &str| {
            calls.set(calls.get() + 1);
            Ok(zeroize::Zeroizing::new("owned-upstream-token".into()))
        };
        let observe = || {
            client
                .accept(
                    request.clone(),
                    7,
                    103,
                    104,
                    Instant::now(),
                    PermitValidationReply {
                        request_id: 7,
                        expires_ms: 700,
                        cache_ttl_ms: 0,
                    },
                )
                .unwrap()
        };
        let admission =
            projection_receiver::verify(observe(), &client, &keys.verifier(), 104).unwrap();
        let output = admission
            .project(&client, &plan, &mut db, &|| 105, &local_identity, &resolve)
            .unwrap();
        let (name, value) = output
            .into_header("orders", "orders-api", &[3; 32], 106)
            .unwrap();
        assert_eq!(name, "authorization");
        assert!(value.is_sensitive());
        assert_eq!(calls.get(), 1);
        let count: u64 = db
            .query_row(
                "SELECT count(*) FROM meta WHERE key LIKE 'projection_nonce_id:%'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 2);
        let duplicate =
            projection_receiver::verify(observe(), &client, &keys.verifier(), 106).unwrap();
        assert!(
            duplicate
                .project(&client, &plan, &mut db, &|| 107, &local_identity, &resolve)
                .is_err()
        );
        assert_eq!(calls.get(), 1);
        let (mut db, keys, plan, request) = signed_chain();
        let observed = client
            .accept(
                request,
                7,
                103,
                104,
                Instant::now(),
                PermitValidationReply {
                    request_id: 7,
                    expires_ms: 700,
                    cache_ttl_ms: 0,
                },
            )
            .unwrap();
        let admission =
            projection_receiver::verify(observed, &client, &keys.verifier(), 104).unwrap();
        let output = admission
            .project(&client, &plan, &mut db, &|| 105, &local_identity, &resolve)
            .unwrap();
        assert!(
            output
                .into_header("orders", "orders-api", &[3; 32], 701)
                .is_err()
        );
    }
    #[tokio::test]
    async fn late_local_guard_failure_rolls_back_both_nonces_and_never_releases_output() {
        use super::super::projection_receiver;
        let (mut db, keys, plan, request) = signed_chain();
        let client = client();
        let observed = client
            .accept(
                request,
                7,
                103,
                104,
                Instant::now(),
                PermitValidationReply {
                    request_id: 7,
                    expires_ms: 700,
                    cache_ttl_ms: 0,
                },
            )
            .unwrap();
        let admission =
            projection_receiver::verify(observed, &client, &keys.verifier(), 104).unwrap();
        let checks = std::cell::Cell::new(0);
        let guard = |db: &dyn crate::store::meta::MetaTx| {
            checks.set(checks.get() + 1);
            if checks.get() == 2 {
                db.sqlite()
                    .unwrap()
                    .execute(
                        "UPDATE meta SET value='2' WHERE key='owned_identity_revision'",
                        [],
                    )
                    .map_err(|_| super::super::receipt_keys::Refused)?;
            }
            local_identity(db)
        };
        assert!(
            admission
                .project(&client, &plan, &mut db, &|| 105, &guard, &|_| Ok(
                    zeroize::Zeroizing::new("owned-upstream-token".into())
                ))
                .is_err()
        );
        let count: u64 = db
            .query_row(
                "SELECT count(*) FROM meta WHERE key LIKE 'projection_nonce_id:%'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 0);
        local_identity(&db).unwrap();
    }
    #[tokio::test]
    async fn owner_ack_cannot_bypass_crypto_or_key_retirement_before_consumption() {
        use super::super::projection_receiver;
        let (mut db, mut keys, plan, request) = signed_chain();
        let client = client();
        let mut bad = request.permit.clone();
        bad.receipt[100] ^= 1;
        let bad = Request::new(request.native.clone(), bad).unwrap();
        let observed = client
            .accept(
                bad,
                7,
                103,
                104,
                Instant::now(),
                PermitValidationReply {
                    request_id: 7,
                    expires_ms: 700,
                    cache_ttl_ms: 0,
                },
            )
            .unwrap();
        assert!(projection_receiver::verify(observed, &client, &keys.verifier(), 104).is_err());
        let observed = client
            .accept(
                request,
                7,
                103,
                104,
                Instant::now(),
                PermitValidationReply {
                    request_id: 7,
                    expires_ms: 700,
                    cache_ttl_ms: 0,
                },
            )
            .unwrap();
        let admission =
            projection_receiver::verify(observed, &client, &keys.verifier(), 104).unwrap();
        keys.publish(&mut db, 1, &[], "operator", &|_| Ok(()))
            .unwrap();
        let resolutions = std::cell::Cell::new(0);
        assert!(
            admission
                .project(&client, &plan, &mut db, &|| 105, &local_identity, &|_| {
                    resolutions.set(resolutions.get() + 1);
                    Ok(zeroize::Zeroizing::new("owned-upstream-token".into()))
                })
                .is_err()
        );
        assert_eq!(resolutions.get(), 0);
        let count: u64 = db
            .query_row(
                "SELECT count(*) FROM meta WHERE key LIKE 'projection_nonce_id:%'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 0);
    }
}
