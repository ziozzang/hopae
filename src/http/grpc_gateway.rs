//! Additional transport through the authoritative caller/parse/verify/render pipeline.
use crate::{
    app::{CallerKeys, KeyVerdict},
    gateway::{hangang, native_codec as wire},
};
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{HeaderMap, HeaderName, HeaderValue, Request as HttpRequest},
};
use std::sync::Arc;
use tokio::{
    net::TcpListener,
    sync::{Semaphore, watch},
};
use tonic::{Request, Response, Status, transport::ServerTlsConfig};
use tower::ServiceExt;

pub use hopae_grpc::v1;
use v1::{
    Header, VerifyReply, VerifyRequest,
    authentication_server::{Authentication, AuthenticationServer},
};
#[derive(Clone)]
pub(super) struct Service {
    pub(super) router: Router,
    pub(super) keys: Arc<CallerKeys>,
    pub(super) requests: Arc<Semaphore>,
}
// Generated unary handlers decode before invoking the domain service. Reject
// unauthenticated initial metadata before that allocation/decoding work, while
// retaining domain checks for internal calls and final caller freshness.
fn authenticate_transport<S>(
    service: S,
    pipeline: Service,
) -> tonic::service::interceptor::InterceptedService<S, impl tonic::service::Interceptor + Clone> {
    tonic::service::interceptor::InterceptedService::new(service, move |request: Request<()>| {
        pipeline.caller(request.metadata())?;
        Ok(request)
    })
}
fn bounded_transport<S>(
    service: S,
    pipeline: Service,
    slots: Arc<Semaphore>,
    max_payload: usize,
) -> tonic::service::interceptor::InterceptedService<
    hangang_runtime::unary_ingress::UnaryIngress<S>,
    impl tonic::service::Interceptor + Clone,
> {
    authenticate_transport(
        hangang_runtime::unary_ingress::UnaryIngress::new(service, slots, max_payload),
        pipeline,
    )
}
// Human-only original admission before caller/decode. Existing Service/Workload
// mounts retain their exact semantics.
fn bounded_human_transport<S>(
    service: S,
    pipeline: Service,
    slots: Arc<Semaphore>,
    max_payload: usize,
    owner: Arc<crate::verify::human::Owner>,
    readiness: crate::app::Readiness,
    budget: std::time::Duration,
) -> tonic::service::interceptor::InterceptedService<
    hangang_runtime::unary_ingress::UnaryIngress<S>,
    impl tonic::service::Interceptor + Clone,
> {
    tonic::service::interceptor::InterceptedService::new(
        hangang_runtime::unary_ingress::UnaryIngress::new(service, slots, max_payload),
        move |mut request: Request<()>| {
            // Original age starts before caller/key callbacks and protobuf work.
            // Invalid callers may sample the clock, but never poll the body.
            let admission = owner
                .admit(budget)
                .map_err(|_| Status::unavailable("Human ingress unavailable"))?;
            pipeline.caller(request.metadata())?;
            let capture = owner
                .capture(admission, readiness.clone())
                .map_err(|_| Status::unavailable("Human ingress unavailable"))?;
            if request
                .extensions()
                .get::<crate::verify::human::Capture>()
                .is_some()
            {
                return Err(Status::failed_precondition("duplicate Human ingress"));
            }
            request.extensions_mut().insert(capture);
            Ok(request)
        },
    )
}
impl Service {
    pub(super) fn caller(
        &self,
        metadata: &tonic::metadata::MetadataMap,
    ) -> Result<HeaderValue, Status> {
        let mut entries = metadata.get_all("authorization").iter();
        let token = entries
            .next()
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "));
        if entries.next().is_some()
            || !token.is_some_and(|v| {
                matches!(self.keys.check(Some(v.as_bytes())), KeyVerdict::Accepted(_))
            })
        {
            return Err(Status::unauthenticated("gateway credential required"));
        }
        HeaderValue::from_str(token.unwrap())
            .map_err(|_| Status::unauthenticated("invalid gateway credential"))
    }
    /// Callback-free final caller fence over the same immutable key owner.
    pub(super) fn caller_current(
        &self,
        metadata: &tonic::metadata::MetadataMap,
    ) -> Result<(), Status> {
        let mut entries = metadata.get_all("authorization").iter();
        let token = entries
            .next()
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "));
        if entries.next().is_some()
            || !token.is_some_and(|v| {
                matches!(
                    self.keys.check_untracked(Some(v.as_bytes())),
                    KeyVerdict::Accepted(_)
                )
            })
        {
            return Err(Status::unauthenticated("gateway credential required"));
        }
        Ok(())
    }
    async fn exchange(
        &self,
        request: Request<VerifyRequest>,
    ) -> Result<
        (
            u64,
            axum::response::Response,
            tokio::sync::OwnedSemaphorePermit,
        ),
        Status,
    > {
        self.exchange_inner(request, None, None).await
    }
    async fn exchange_workload(
        &self,
        request: Request<VerifyRequest>,
        attempt: Arc<crate::auth_gateway::workload_owner::Attempt>,
    ) -> Result<
        (
            u64,
            axum::response::Response,
            tokio::sync::OwnedSemaphorePermit,
        ),
        Status,
    > {
        self.exchange_inner(request, Some(attempt), None).await
    }
    pub(super) async fn exchange_human(
        &self,
        request: Request<VerifyRequest>,
    ) -> Result<
        (
            u64,
            axum::response::Response,
            tokio::sync::OwnedSemaphorePermit,
        ),
        Status,
    > {
        let capture = request
            .extensions()
            .get::<crate::verify::human::Capture>()
            .cloned()
            .ok_or_else(|| Status::failed_precondition("original Human admission required"))?;
        self.exchange_inner(request, None, Some(capture)).await
    }
    async fn exchange_inner(
        &self,
        request: Request<VerifyRequest>,
        attempt: Option<Arc<crate::auth_gateway::workload_owner::Attempt>>,
        human: Option<crate::verify::human::Capture>,
    ) -> Result<
        (
            u64,
            axum::response::Response,
            tokio::sync::OwnedSemaphorePermit,
        ),
        Status,
    > {
        if (request
            .extensions()
            .get::<crate::verify::human::Capture>()
            .is_some()
            && request
                .extensions()
                .get::<Arc<crate::auth_gateway::workload_owner::Attempt>>()
                .is_some())
            || (attempt.is_some() && human.is_some())
            || (human.is_some()
                && request
                    .extensions()
                    .get::<Arc<crate::auth_gateway::workload_owner::Attempt>>()
                    .is_some())
            || (attempt.is_some()
                && request
                    .extensions()
                    .get::<crate::verify::human::Capture>()
                    .is_some())
        {
            return Err(Status::failed_precondition("mixed native admission"));
        }
        let key = self.caller(request.metadata())?;
        let _permit = self
            .requests
            .clone()
            .try_acquire_owned()
            .map_err(|_| Status::resource_exhausted("verification capacity"))?;
        let input = request.into_inner();
        let fields = input
            .headers
            .into_iter()
            .map(|h| (h.name, h.value))
            .collect::<Vec<_>>();
        // Apply the same aggregate/per-header bounds as HOP1.
        wire::encode_request(&fields)
            .map_err(|_| Status::invalid_argument("invalid verification headers"))?;
        let mut headers = HeaderMap::new();
        for (name, value) in fields {
            let name = HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| Status::invalid_argument("invalid header name"))?;
            if name == "x-hopae-gateway-key" {
                return Err(Status::invalid_argument("reserved gateway credential"));
            }
            let value = HeaderValue::from_bytes(&value)
                .map_err(|_| Status::invalid_argument("invalid header value"))?;
            headers.append(name, value);
        }
        headers.insert("x-hopae-gateway-key", key);
        let mut request = HttpRequest::builder()
            .method("GET")
            .uri(hangang::VERIFY_PATH)
            .body(Body::empty())
            .map_err(|_| Status::internal("verification request"))?;
        *request.headers_mut() = headers;
        if let Some(attempt) = attempt {
            request.extensions_mut().insert(attempt);
        }
        if let Some(capture) = human {
            request.extensions_mut().insert(capture);
        }
        let response = self
            .router
            .clone()
            .oneshot(request)
            .await
            .map_err(|_| Status::unavailable("verification unavailable"))?;
        Ok((input.request_id, response, _permit))
    }
}
#[tonic::async_trait]
impl Authentication for Service {
    async fn verify(
        &self,
        request: Request<VerifyRequest>,
    ) -> Result<Response<VerifyReply>, Status> {
        let (request_id, response, _permit) = self.exchange(request).await?;
        let (parts, body) = response.into_parts();
        let body = to_bytes(body, wire::MAX_BODY)
            .await
            .map_err(|_| Status::resource_exhausted("verification body"))?
            .to_vec();
        let fields = parts
            .headers
            .iter()
            .map(|(n, v)| (n.as_str().to_owned(), v.as_bytes().to_vec()))
            .collect::<Vec<_>>();
        wire::encode_reply(&wire::Reply {
            status: parts.status.as_u16(),
            headers: fields.clone(),
            body: body.clone(),
        })
        .map_err(|_| Status::resource_exhausted("verification response"))?;
        Ok(Response::new(VerifyReply {
            request_id,
            status: u32::from(parts.status.as_u16()),
            headers: fields
                .into_iter()
                .map(|(name, value)| Header { name, value })
                .collect(),
            body,
        }))
    }
}

struct PlanService {
    pipeline: Service,
    plans: Arc<arc_swap::ArcSwap<crate::auth_gateway::projection_authority::Snapshot>>,
}
#[tonic::async_trait]
impl v1::projection_plans_server::ProjectionPlans for PlanService {
    async fn observe(
        &self,
        request: Request<v1::ProjectionPlanRequest>,
    ) -> Result<Response<v1::ProjectionPlanReply>, Status> {
        self.pipeline.caller(request.metadata())?;
        let _permit = self
            .pipeline
            .requests
            .clone()
            .try_acquire_owned()
            .map_err(|_| Status::resource_exhausted("verification capacity"))?;
        let metadata = request.metadata().clone();
        let input = request.into_inner();
        let valid_scope = |value: &str| {
            !value.is_empty() && value.len() <= 128 && value.bytes().all(|b| b.is_ascii_graphic())
        };
        if input.request_id == 0
            || input.request_id > 9_007_199_254_740_991
            || !valid_scope(&input.service)
            || !valid_scope(&input.audience)
        {
            return Err(Status::invalid_argument("invalid plan request"));
        }
        let observed = crate::auth_gateway::projection_authority::observe(
            self.plans.clone(),
            &input.service,
            &input.audience,
            input.minimum_revision,
        )
        .map_err(|_| Status::unavailable("projection plan unavailable"))?;
        let plan = observed
            .metadata()
            .map_err(|_| Status::unavailable("projection plan retired"))?;
        let reply = v1::ProjectionPlanReply {
            request_id: input.request_id,
            revision: observed.revision(),
            service: plan.service.into(),
            audience: plan.audience.into(),
            resource: plan.resource.into(),
            action: plan.action.into(),
            minimum_aal: u32::from(plan.minimum_aal),
            cache_ttl_ms: 0,
        };
        self.pipeline.caller(&metadata)?;
        if !observed.current() {
            return Err(Status::unavailable("projection plan retired"));
        }
        Ok(Response::new(reply))
    }
}

#[derive(Clone)]
struct ReceiptService {
    pipeline: Service,
    issuer: Arc<crate::auth_gateway::receipt_issuer::Issuer>,
    key_verifier: crate::auth_gateway::receipt_authority::Verifier,
    profiles: Arc<arc_swap::ArcSwap<crate::auth_gateway::authority::Snapshot>>,
    applications: Arc<arc_swap::ArcSwap<crate::policy::types::ConfigSnapshot>>,
}
#[tonic::async_trait]
impl v1::authentication_receipts_server::AuthenticationReceipts for ReceiptService {
    async fn validate_service(
        &self,
        request: Request<v1::ServiceReceiptValidationRequest>,
    ) -> Result<Response<v1::ServiceReceiptValidationReply>, Status> {
        self.pipeline.caller(request.metadata())?;
        let _permit = self
            .pipeline
            .requests
            .clone()
            .try_acquire_owned()
            .map_err(|_| Status::resource_exhausted("verification capacity"))?;
        let metadata = request.metadata().clone();
        let input = request.into_inner();
        if input.request_id == 0 || input.receipt.len() != hopae_grpc::receipt::LENGTH {
            return Err(Status::invalid_argument("invalid receipt request"));
        }
        let context = input
            .context
            .ok_or_else(|| Status::invalid_argument("receipt context required"))?;
        let identity = context
            .identity
            .ok_or_else(|| Status::invalid_argument("identity required"))?;
        if identity.kind != 2 || identity.aal != 0 {
            return Err(Status::permission_denied("service proof required"));
        }
        let context = hopae_grpc::receipt_binding::Context {
            issuer_ref: &context.issuer_ref,
            key_epoch: context.key_epoch,
            identity_authority_epoch: &context.identity_authority_epoch,
            identity: hopae_grpc::receipt_binding::Identity {
                subject_ref: &identity.subject_ref,
                kind: hopae_grpc::PrincipalKind::Service,
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
                .map_err(|_| Status::invalid_argument("request digest required"))?,
        };
        let expected = input
            .request_sha256
            .as_slice()
            .try_into()
            .map_err(|_| Status::invalid_argument("request digest required"))?;
        let live = self
            .issuer
            .verify_live_service(
                &self.profiles,
                &self.applications,
                &context,
                &input.receipt,
                &expected,
            )
            .map_err(|_| Status::permission_denied("receipt no longer valid"))?;
        self.pipeline.caller(&metadata)?;
        live.current()
            .map_err(|_| Status::unavailable("receipt authority changed"))?;
        Ok(Response::new(v1::ServiceReceiptValidationReply {
            request_id: input.request_id,
            expires_ms: live.expires_ms(),
        }))
    }
    async fn issue_service(
        &self,
        request: Request<v1::ServiceReceiptRequest>,
    ) -> Result<Response<v1::ServiceReceiptReply>, Status> {
        self.issue_inner(request, false).await
    }
    async fn issue_service_observed(
        &self,
        request: Request<v1::ServiceReceiptRequest>,
    ) -> Result<Response<v1::ServiceReceiptObservedReply>, Status> {
        let metadata = request.metadata().clone();
        let receipt = self.issue_inner(request, true).await?.into_inner();
        let context = receipt
            .context
            .clone()
            .ok_or_else(|| Status::unavailable("native context unavailable"))?;
        let mut check = Request::new(v1::ServiceReceiptValidationRequest {
            request_id: receipt.request_id,
            request_sha256: context.request_sha256.clone(),
            context: Some(context),
            receipt: receipt.receipt.clone(),
        });
        *check.metadata_mut() = metadata;
        let observation = self.observe_service_time(check).await?.into_inner();
        Ok(Response::new(v1::ServiceReceiptObservedReply {
            receipt: Some(receipt),
            observation: Some(observation),
        }))
    }
    async fn observe_service_time(
        &self,
        request: Request<v1::ServiceReceiptValidationRequest>,
    ) -> Result<Response<v1::ServiceReceiptTimeReply>, Status> {
        self.pipeline.caller(request.metadata())?;
        let _permit = self
            .pipeline
            .requests
            .clone()
            .try_acquire_owned()
            .map_err(|_| Status::resource_exhausted("time observation capacity"))?;
        let metadata = request.metadata().clone();
        let input = request.into_inner();
        if !(1..=9_007_199_254_740_991).contains(&input.request_id)
            || input.receipt.len() != hopae_grpc::receipt::LENGTH
        {
            return Err(Status::invalid_argument("invalid time observation"));
        }
        let context = input
            .context
            .ok_or_else(|| Status::invalid_argument("receipt context required"))?;
        let identity = context
            .identity
            .ok_or_else(|| Status::invalid_argument("identity required"))?;
        if identity.kind != 2 || identity.aal != 0 {
            return Err(Status::permission_denied("service proof required"));
        }
        let context = hopae_grpc::receipt_binding::Context {
            issuer_ref: &context.issuer_ref,
            key_epoch: context.key_epoch,
            identity_authority_epoch: &context.identity_authority_epoch,
            identity: hopae_grpc::receipt_binding::Identity {
                subject_ref: &identity.subject_ref,
                kind: hopae_grpc::PrincipalKind::Service,
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
                .map_err(|_| Status::invalid_argument("request digest required"))?,
        };
        let expected = input
            .request_sha256
            .as_slice()
            .try_into()
            .map_err(|_| Status::invalid_argument("request digest required"))?;
        let live = self
            .issuer
            .verify_live_service_observed(
                &self.profiles,
                &self.applications,
                &context,
                &input.receipt,
                &expected,
                &self.key_verifier,
            )
            .map_err(|_| Status::permission_denied("native receipt clock or owner refused"))?;
        let observed = live
            .observe_time()
            .map_err(|_| Status::unavailable("native time unavailable"))?;
        let reply = v1::ServiceReceiptTimeReply {
            request_id: input.request_id,
            owner_now_ms: observed.report.owner_now_ms,
            remaining_ms: observed.report.remaining_ms,
            receipt_sha256: observed.report.receipt_sha256.to_vec(),
            clock_domain: observed.clock_domain.into(),
            profile_revision: observed.profile_revision,
            application_generation: observed.application_generation,
            key_registry_revision: observed.key_registry_revision,
            cache_ttl_ms: 0,
        };
        self.pipeline.caller(&metadata)?;
        live.current()
            .map_err(|_| Status::unavailable("native time owner changed"))?;
        Ok(Response::new(reply))
    }
}
impl ReceiptService {
    async fn issue_inner(
        &self,
        request: Request<v1::ServiceReceiptRequest>,
        clocked: bool,
    ) -> Result<Response<v1::ServiceReceiptReply>, Status> {
        self.pipeline.caller(request.metadata())?;
        let metadata = request.metadata().clone();
        let input = request.into_inner();
        if input.request_sha256.len() != 32
            || [&input.service, &input.audience].iter().any(|s| {
                s.is_empty()
                    || s.len() > 128
                    || !s
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
            })
        {
            return Err(Status::invalid_argument("invalid receipt scope"));
        }
        if !self
            .issuer
            .permits_service_audience(&input.service, &input.audience)
        {
            return Err(Status::permission_denied("receipt scope not declared"));
        }
        let verification = input
            .verification
            .ok_or_else(|| Status::invalid_argument("verification required"))?;
        if clocked && !(1..=9_007_199_254_740_991).contains(&verification.request_id) {
            return Err(Status::invalid_argument("invalid observed receipt request"));
        }
        let mut request = Request::new(verification);
        *request.metadata_mut() = metadata.clone();
        let (request_id, response, _permit) = self.pipeline.exchange(request).await?;
        if !response.status().is_success() {
            return Err(match response.status().as_u16() {
                401 => Status::unauthenticated("authentication refused"),
                403 => Status::permission_denied("authentication refused"),
                400 => Status::invalid_argument("verification refused"),
                _ => Status::unavailable("authentication unavailable"),
            });
        }
        let captured = response
            .extensions()
            .get::<Arc<crate::auth_gateway::receipt_issuer::CapturedService>>()
            .ok_or_else(|| Status::failed_precondition("service proof required"))?;
        let issued = captured
            .issue_domain(
                &self.issuer,
                &self.profiles,
                &self.applications,
                crate::auth_gateway::receipt_issuer::Request {
                    service: &input.service,
                    audience: &input.audience,
                    request_sha256: input.request_sha256.as_slice().try_into().unwrap(),
                },
                clocked,
                &|| {
                    let token = metadata
                        .get("authorization")
                        .and_then(|v| v.to_str().ok())
                        .and_then(|v| v.strip_prefix("Bearer "));
                    if !token.is_some_and(|v| {
                        matches!(
                            self.pipeline.keys.check(Some(v.as_bytes())),
                            KeyVerdict::Accepted(_)
                        )
                    }) {
                        return Err(crate::auth_gateway::receipt_keys::Refused);
                    }
                    Ok(())
                },
            )
            .map_err(|_| Status::unavailable("receipt authority changed or refused"))?;
        let context = issued.context();
        Ok(Response::new(v1::ServiceReceiptReply {
            request_id,
            receipt: issued.bytes().to_vec(),
            context: Some(v1::AuthenticationReceiptContext {
                issuer_ref: context.issuer_ref.into(),
                key_epoch: context.key_epoch,
                identity_authority_epoch: context.identity_authority_epoch.into(),
                identity: Some(v1::ReceiptIdentity {
                    subject_ref: context.identity.subject_ref.into(),
                    kind: 2,
                    aal: u32::from(context.identity.aal),
                    revision: context.identity.revision,
                    credential_generation: context.identity.credential_generation,
                }),
                service: context.service.into(),
                audience: context.audience.into(),
                request_sha256: context.request_sha256.to_vec(),
            }),
        }))
    }
}
pub async fn serve_with_receipts(
    listener: TcpListener,
    tls: ServerTlsConfig,
    router: Router,
    keys: Arc<CallerKeys>,
    mut stop: watch::Receiver<bool>,
    services: Option<crate::app::Services>,
) -> anyhow::Result<()> {
    let pipeline = Service {
        router,
        keys,
        requests: Arc::new(Semaphore::new(4096)),
    };
    // All generated services and connections share a separate decode budget.
    // Verify's repeated headers can amplify a 128 KiB message in memory.
    let ingress = Arc::new(Semaphore::new(16));
    let plan_service = services
        .as_ref()
        .map(|services| {
            let plans = services
                .projection_authority
                .lock()
                .map_err(|_| anyhow::anyhow!("projection plan owner unavailable"))?
                .reader();
            Ok::<_, anyhow::Error>(
                v1::projection_plans_server::ProjectionPlansServer::new(PlanService {
                    pipeline: pipeline.clone(),
                    plans,
                })
                .max_decoding_message_size(512)
                .max_encoding_message_size(1024),
            )
        })
        .transpose()?;
    let projection_service = services
        .as_ref()
        .map(|services| {
            super::grpc_projection::Projection::new(pipeline.clone(), services)
                .map_err(|_| anyhow::anyhow!("native projection owners unavailable"))
        })
        .transpose()?
        .flatten();
    let workload_projection_service=projection_service.as_ref().filter(|s|s.workloads_enabled()).cloned().map(|service|v1::workload_observed_credential_projection_server::WorkloadObservedCredentialProjectionServer::new(service).max_decoding_message_size(8448).max_encoding_message_size(8192));
    let observed_projection_service = projection_service.clone().map(|service| {
        v1::observed_credential_projection_server::ObservedCredentialProjectionServer::new(service)
            .max_decoding_message_size(8448)
            .max_encoding_message_size(8192)
    });
    let projection_service = projection_service.map(|service| {
        v1::credential_projection_server::CredentialProjectionServer::new(service)
            .max_decoding_message_size(8448)
            .max_encoding_message_size(8192)
    });
    let human_service=services.as_ref().map(|services| {
        super::grpc_human::Human::from_services(pipeline.clone(),services).map(|human|human.map(|human| {
            let service=v1::human_authentication_receipts_server::HumanAuthenticationReceiptsServer::new(human)
                .max_decoding_message_size(wire::MAX_FRAME).max_encoding_message_size(wire::MAX_FRAME);
            bounded_human_transport(service,pipeline.clone(),ingress.clone(),wire::MAX_FRAME,
                services.human_owner.clone(),services.readiness.clone(),
                services.config.verify_limits().budget.min(std::time::Duration::from_secs(1)))
        }))
    }).transpose()?.flatten();
    let receipt_resources = services
        .map(|services| receipt_resources(pipeline.clone(), services))
        .transpose()?
        .flatten();
    let workload_receipt_service = receipt_resources
        .as_ref()
        .filter(|service| service.issuer.workloads_enabled())
        .map(|service| {
            v1::workload_authentication_receipts_server::WorkloadAuthenticationReceiptsServer::new(
                service.clone(),
            )
            .max_decoding_message_size(wire::MAX_FRAME)
            .max_encoding_message_size(2048)
        });
    let receipt_service = receipt_resources.map(|service| {
        v1::authentication_receipts_server::AuthenticationReceiptsServer::new(service)
            .max_decoding_message_size(wire::MAX_FRAME)
            .max_encoding_message_size(2048)
    });
    hangang_runtime::server(tls)?
        .add_optional_service(human_service)
        .add_service(bounded_transport(
            AuthenticationServer::new(pipeline.clone())
                .max_decoding_message_size(wire::MAX_FRAME)
                .max_encoding_message_size(wire::MAX_FRAME),
            pipeline.clone(),
            ingress.clone(),
            wire::MAX_FRAME,
        ))
        .add_optional_service(
            workload_projection_service
                .map(|service| bounded_transport(service, pipeline.clone(), ingress.clone(), 8448)),
        )
        .add_optional_service(workload_receipt_service.map(|service| {
            bounded_transport(service, pipeline.clone(), ingress.clone(), wire::MAX_FRAME)
        }))
        .add_optional_service(receipt_service.map(|service| {
            bounded_transport(service, pipeline.clone(), ingress.clone(), wire::MAX_FRAME)
        }))
        .add_optional_service(
            plan_service
                .map(|service| bounded_transport(service, pipeline.clone(), ingress.clone(), 512)),
        )
        .add_optional_service(
            projection_service
                .map(|service| bounded_transport(service, pipeline.clone(), ingress.clone(), 8448)),
        )
        .add_optional_service(
            observed_projection_service
                .map(|service| bounded_transport(service, pipeline.clone(), ingress.clone(), 8448)),
        )
        .serve_with_incoming_shutdown(hangang_runtime::incoming(listener), async move {
            let _ = stop.wait_for(|v| *v).await;
        })
        .await?;
    Ok(())
}

/// Compatibility entry for verification-only consumers.
pub async fn serve(
    listener: TcpListener,
    tls: ServerTlsConfig,
    router: Router,
    keys: Arc<CallerKeys>,
    stop: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    serve_with_receipts(listener, tls, router, keys, stop, None).await
}

fn receipt_resources(
    pipeline: Service,
    services: crate::app::Services,
) -> anyhow::Result<Option<ReceiptService>> {
    Ok(
        match (services.receipt_issuer, services.authentication_authority) {
            (Some(issuer), Some(owner)) => Some(ReceiptService {
                pipeline,
                issuer,
                key_verifier: services
                    .receipt_authority
                    .lock()
                    .map_err(|_| anyhow::anyhow!("receipt key owner unavailable"))?
                    .verifier(),
                profiles: owner
                    .lock()
                    .map_err(|_| anyhow::anyhow!("receipt profile owner unavailable"))?
                    .reader(),
                applications: services.snapshot,
            }),
            _ => None,
        },
    )
}
#[cfg(test)]
pub(crate) fn authentication_server_for_test(
    router: Router,
    keys: Arc<CallerKeys>,
) -> v1::authentication_server::AuthenticationServer<impl Authentication> {
    v1::authentication_server::AuthenticationServer::new(Service {
        router,
        keys,
        requests: Arc::new(Semaphore::new(16)),
    })
    .max_decoding_message_size(wire::MAX_FRAME)
    .max_encoding_message_size(wire::MAX_FRAME)
}
#[cfg(test)]
pub(crate) fn receipt_server_for_test(
    services: crate::app::Services,
    router: Router,
) -> v1::authentication_receipts_server::AuthenticationReceiptsServer<
    impl v1::authentication_receipts_server::AuthenticationReceipts,
> {
    let pipeline = Service {
        router,
        keys: services.caller_keys.clone(),
        requests: Arc::new(Semaphore::new(4096)),
    };
    v1::authentication_receipts_server::AuthenticationReceiptsServer::new(
        receipt_resources(pipeline, services).unwrap().unwrap(),
    )
    .max_decoding_message_size(wire::MAX_FRAME)
    .max_encoding_message_size(2048)
}

#[cfg(test)]
pub(crate) async fn qualify_observed_time_for_test(
    services: &crate::app::Services,
    message: v1::ServiceReceiptRequest,
    key: &str,
    channel: tonic::transport::Channel,
) -> v1::ServiceReceiptValidationRequest {
    use hopae_grpc::{receipt, receipt_binding, receipt_time, service_epoch};
    let mut client = v1::authentication_receipts_client::AuthenticationReceiptsClient::new(channel);
    let issue = |token: &str| {
        let mut request = Request::new(message.clone());
        request
            .metadata_mut()
            .insert("authorization", format!("Bearer {token}").parse().unwrap());
        request
    };
    assert_eq!(
        client
            .issue_service_observed(issue("wrong"))
            .await
            .err()
            .unwrap()
            .code(),
        tonic::Code::Unauthenticated
    );
    let reply = client
        .issue_service_observed(issue(key))
        .await
        .unwrap()
        .into_inner();
    let receipt = reply.receipt.unwrap();
    let observed = reply.observation.unwrap();
    assert_eq!(observed.request_id, receipt.request_id);
    assert_eq!(observed.cache_ttl_ms, 0);
    assert!(observed.remaining_ms > 0 && observed.remaining_ms <= 1000);
    let context = receipt.context.as_ref().unwrap();
    let identity = context.identity.as_ref().unwrap();
    let epoch = service_epoch::decode_clock(&context.identity_authority_epoch).unwrap();
    assert_eq!(epoch.clock_domain, observed.clock_domain);
    assert_eq!(epoch.epoch.profile_revision, observed.profile_revision);
    assert_eq!(
        epoch.epoch.application_generation,
        observed.application_generation
    );
    let context = receipt_binding::Context {
        issuer_ref: &context.issuer_ref,
        key_epoch: context.key_epoch,
        identity_authority_epoch: &context.identity_authority_epoch,
        identity: receipt_binding::Identity {
            subject_ref: &identity.subject_ref,
            kind: hopae_grpc::PrincipalKind::Service,
            aal: 0,
            revision: identity.revision,
            credential_generation: identity.credential_generation,
        },
        service: &context.service,
        audience: &context.audience,
        request_sha256: [3; 32],
    };
    let checked = receipt::verify(
        &ed25519_dalek::SigningKey::from_bytes(&[7; 32]).verifying_key(),
        &receipt.receipt,
        receipt::Purpose::Authentication,
        &receipt_binding::digest(&context, None).unwrap(),
        observed.owner_now_ms,
    )
    .unwrap();
    assert_eq!(checked.sha256().as_slice(), observed.receipt_sha256);
    // A replica with the same configured authority and signing key still has a
    // different issuing clock domain, and cannot silently observe this proof.
    let other = crate::auth_gateway::receipt_issuer::Issuer::new(
        crate::auth_gateway::receipt_issuer::Configuration {
            issuer_ref: context.issuer_ref.into(),
            key_epoch: context.key_epoch,
            identity_authority_epoch: epoch.epoch.authority.into(),
            public_key: ed25519_dalek::SigningKey::from_bytes(&[7; 32])
                .verifying_key()
                .to_bytes(),
            scopes: vec![crate::auth_gateway::receipt_issuer::Scope {
                service: context.service.into(),
                audience: context.audience.into(),
            }],
        },
        zeroize::Zeroizing::new([7; 32]),
        services.clock.clone(),
        services.rng.clone(),
    )
    .unwrap();
    let profiles = services
        .authentication_authority
        .as_ref()
        .unwrap()
        .lock()
        .unwrap()
        .reader();
    let verifier = services.receipt_authority.lock().unwrap().verifier();
    assert!(
        other
            .verify_live_service_observed(
                &profiles,
                &services.snapshot,
                &context,
                &receipt.receipt,
                &[3; 32],
                &verifier
            )
            .is_err()
    );

    let facts = receipt_time::Report {
        owner_now_ms: observed.owner_now_ms,
        remaining_ms: observed.remaining_ms,
        receipt_sha256: *checked.sha256(),
    };
    // Arbitrary receiver offset does not reinterpret the signed source clock.
    let local = observed.owner_now_ms + 100_000;
    let bounds = receipt_time::Bounds::from_receipt(
        &checked,
        &facts,
        &receipt_time::Exchange {
            before_ms: local,
            after_ms: local + 1,
            elapsed_ms: 1,
        },
    )
    .unwrap();
    assert!(bounds.admit_until_ms() <= local + u64::from(observed.remaining_ms));
    let original = v1::ServiceReceiptValidationRequest {
        request_id: 9010,
        context: receipt.context.clone(),
        receipt: receipt.receipt.clone(),
        request_sha256: vec![3; 32],
    };
    let call = |input: v1::ServiceReceiptValidationRequest, token: &str| {
        let mut request = Request::new(input);
        request
            .metadata_mut()
            .insert("authorization", format!("Bearer {token}").parse().unwrap());
        request
    };
    assert_eq!(
        client
            .observe_service_time(call(original.clone(), "wrong"))
            .await
            .err()
            .unwrap()
            .code(),
        tonic::Code::Unauthenticated
    );
    let refreshed = client
        .observe_service_time(call(original.clone(), key))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(refreshed.clock_domain, observed.clock_domain);
    assert_eq!(refreshed.receipt_sha256, observed.receipt_sha256);
    for attack in 0..3 {
        let mut altered = original.clone();
        match attack {
            0 => altered.request_sha256[0] ^= 1,
            1 => altered.receipt[20] ^= 1,
            _ => {
                let context = altered.context.as_mut().unwrap();
                let parsed =
                    service_epoch::decode_clock(&context.identity_authority_epoch).unwrap();
                let other = if parsed.clock_domain.starts_with('1') {
                    "223456789abcdef0123456789abcdef0"
                } else {
                    "123456789abcdef0123456789abcdef0"
                };
                context.identity_authority_epoch = service_epoch::encode_clock(
                    parsed.epoch.authority,
                    parsed.epoch.profile_revision,
                    parsed.epoch.application_generation,
                    other,
                )
                .unwrap();
            }
        }
        assert_eq!(
            client
                .observe_service_time(call(altered, key))
                .await
                .err()
                .unwrap()
                .code(),
            tonic::Code::PermissionDenied
        );
    }
    let legacy = client.issue_service(issue(key)).await.unwrap().into_inner();
    let old = v1::ServiceReceiptValidationRequest {
        request_id: 9011,
        context: legacy.context,
        receipt: legacy.receipt,
        request_sha256: vec![3; 32],
    };
    assert_eq!(
        client
            .observe_service_time(call(old, key))
            .await
            .err()
            .unwrap()
            .code(),
        tonic::Code::PermissionDenied
    );
    assert!((services.clock.now().0 as u64) < checked.claims().expires_ms);
    original
}

#[cfg(test)]
pub(crate) async fn issue_service_for_test(
    services: crate::app::Services,
    router: Router,
    request: Request<v1::ServiceReceiptRequest>,
) -> Result<Response<v1::ServiceReceiptReply>, Status> {
    use v1::authentication_receipts_server::AuthenticationReceipts;
    let pipeline = Service {
        router,
        keys: services.caller_keys.clone(),
        requests: Arc::new(Semaphore::new(4096)),
    };
    receipt_resources(pipeline, services)
        .map_err(|_| Status::unavailable("receipt resources"))?
        .ok_or_else(|| Status::failed_precondition("receipt disabled"))?
        .issue_service(request)
        .await
}

#[cfg(test)]
mod plan_tests {
    use super::*;
    use crate::auth_gateway::{
        projection::{Configuration, Credential, Plan},
        projection_authority::Authority,
    };
    use v1::projection_plans_server::ProjectionPlans;

    fn request() -> Request<v1::ProjectionPlanRequest> {
        let mut request = Request::new(v1::ProjectionPlanRequest {
            request_id: 1,
            service: "orders".into(),
            audience: "orders-api".into(),
            minimum_revision: 1,
        });
        request
            .metadata_mut()
            .insert("authorization", "Bearer owned-key".parse().unwrap());
        request
    }

    #[tokio::test]
    async fn native_plan_endpoint_authenticates_bounds_and_observes_retirement() {
        let mut db = rusqlite::Connection::open_in_memory().unwrap();
        db.execute_batch("CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT NOT NULL)")
            .unwrap();
        let mut owner = Authority::load(&db, 0).unwrap();
        let service = PlanService {
            pipeline: Service {
                router: Router::new(),
                keys: Arc::new(CallerKeys::new(
                    Some(crate::crypto::Secret::new("owned-key".into())),
                    None,
                    false,
                )),
                requests: Arc::new(Semaphore::new(1)),
            },
            plans: owner.reader(),
        };
        let mut unauthorized = request();
        unauthorized.metadata_mut().remove("authorization");
        assert_eq!(
            service.observe(unauthorized).await.unwrap_err().code(),
            tonic::Code::Unauthenticated
        );
        assert_eq!(
            service.observe(request()).await.unwrap_err().code(),
            tonic::Code::Unavailable
        );
        owner
            .publish(
                &mut db,
                0,
                Some(Configuration {
                    revision: 1,
                    plans: vec![Plan {
                        service: "orders".into(),
                        audience: "orders-api".into(),
                        resource: "orders".into(),
                        action: "read".into(),
                        minimum_aal: 2,
                        credential: Credential::BearerReference {
                            secret_ref: "vault:never-resolved".into(),
                        },
                    }],
                }),
                "operator",
                &|_| Ok(()),
            )
            .unwrap();
        let result = service.observe(request()).await.unwrap().into_inner();
        assert_eq!(
            (result.revision, result.minimum_aal, result.cache_ttl_ms),
            (1, 2, 0)
        );
        assert_eq!(
            (result.resource.as_str(), result.action.as_str()),
            ("orders", "read")
        );
        let mut invalid = request();
        invalid.get_mut().request_id = 0;
        assert_eq!(
            service.observe(invalid).await.unwrap_err().code(),
            tonic::Code::InvalidArgument
        );
        let permit = service
            .pipeline
            .requests
            .clone()
            .acquire_owned()
            .await
            .unwrap();
        assert_eq!(
            service.observe(request()).await.unwrap_err().code(),
            tonic::Code::ResourceExhausted
        );
        drop(permit);
        owner
            .publish(&mut db, 1, None, "operator", &|_| Ok(()))
            .unwrap();
        assert_eq!(
            service.observe(request()).await.unwrap_err().code(),
            tonic::Code::Unavailable
        );
    }
}

#[cfg(test)]
mod observed_boundary_tests {
    use super::*;
    use crate::{
        auth_gateway::{authority, receipt_authority, receipt_issuer, receipt_keys, runtime},
        crypto::{Clock, Secret, Timestamp},
    };
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use v1::authentication_receipts_server::AuthenticationReceipts;

    const TOKEN: &str = "owned-boundary-native-key-at-least-thirty-two-bytes";
    const CALLER: &str = "owned-boundary-gateway-key";

    #[derive(Default)]
    struct CountedClock(AtomicUsize);
    impl Clock for CountedClock {
        fn now(&self) -> Timestamp {
            self.0.fetch_add(1, Ordering::SeqCst);
            crate::crypto::SystemClock.now()
        }
    }

    #[derive(Default)]
    struct RouterGate {
        block_next: AtomicBool,
        entered: tokio::sync::Notify,
        release: tokio::sync::Notify,
    }

    struct Fixture {
        service: ReceiptService,
        clock: Arc<CountedClock>,
        router_calls: Arc<AtomicUsize>,
        gate: Arc<RouterGate>,
    }

    fn fixture() -> Fixture {
        fixture_with_application(true)
    }

    fn fixture_with_application(declared: bool) -> Fixture {
        let mut db = rusqlite::Connection::open_in_memory().unwrap();
        db.execute_batch("CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT NOT NULL)")
            .unwrap();
        let configuration: runtime::Config = serde_json::from_value(serde_json::json!({
            "authority_id": "owned-boundary",
            "profiles": [{
                "service_id": "orders", "host": "orders.example.test", "ports": [443],
                "realm": "partner", "api_keys": [{"token_env": "OWNED_BOUNDARY_KEY", "subject": "worker"}],
                "networks": ["203.0.113.0/24"]
            }]
        })).unwrap();
        let owner = authority::Authority::load(
            &mut db,
            Some(configuration),
            &|_| Some(TOKEN.into()),
            &|_| Ok(()),
        )
        .unwrap();
        let profiles = owner.reader();
        let cfg = crate::config::parse(
            r#"{"state_dir":"owned","portal":{"public_url":"https://auth.example.test"},"gateway":{"kind":"hangang","caller_key_env":"OWNED_GATEWAY"}}"#,
        ).unwrap();
        let mut application_snapshot = cfg.snapshot(1);
        if declared {
            let declared_cfg = crate::config::parse(
                r#"{"state_dir":"owned","portal":{"public_url":"https://auth.example.test"},"gateway":{"kind":"hangang","caller_key_env":"OWNED_GATEWAY"},"apps":[{"app_id":"orders","hosts":["orders.example.test"]}]}"#,
            ).unwrap();
            application_snapshot = declared_cfg.snapshot(1);
        }
        let application = Arc::new(application_snapshot);
        let applications = Arc::new(arc_swap::ArcSwap::from(application.clone()));
        let clock = Arc::new(CountedClock::default());
        let public_key = ed25519_dalek::SigningKey::from_bytes(&[7; 32])
            .verifying_key()
            .to_bytes();
        let issuer = Arc::new(
            receipt_issuer::Issuer::new(
                receipt_issuer::Configuration {
                    issuer_ref: "owned-boundary-hopae".into(),
                    key_epoch: 1,
                    identity_authority_epoch: "owned-boundary-identity".into(),
                    public_key,
                    scopes: vec![receipt_issuer::Scope {
                        service: "orders".into(),
                        audience: "orders-api".into(),
                    }],
                },
                zeroize::Zeroizing::new([7; 32]),
                clock.clone(),
                Arc::new(crate::crypto::OsRng),
            )
            .unwrap(),
        );
        let mut key_owner = receipt_authority::Authority::load(&db, 0).unwrap();
        key_owner
            .reconcile(
                &mut db,
                &[receipt_keys::Key {
                    issuer_ref: "owned-boundary-hopae".into(),
                    purpose: hopae_grpc::receipt::Purpose::Authentication,
                    epoch: 1,
                    public_key,
                }],
                "owned-test",
                &|_| Ok(()),
            )
            .unwrap();
        let router_calls = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new(RouterGate::default());
        let calls = router_calls.clone();
        let router_gate = gate.clone();
        let reader = profiles.clone();
        let router = Router::new().route(
            hangang::VERIFY_PATH,
            axum::routing::get(move || {
                let calls = calls.clone();
                let gate = router_gate.clone();
                let reader = reader.clone();
                let application = application.clone();
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    if gate.block_next.swap(false, Ordering::SeqCst) {
                        gate.entered.notify_one();
                        gate.release.notified().await;
                    }
                    let profile = reader.load_full();
                    let authentication = profile
                        .authenticate_for_receipt(
                            "orders.example.test",
                            443,
                            Some(TOKEN),
                            "203.0.113.9".parse().unwrap(),
                            crate::crypto::SystemClock.now().0 as u64,
                        )
                        .await
                        .unwrap();
                    let mut response = axum::response::Response::new(Body::empty());
                    response
                        .extensions_mut()
                        .insert(Arc::new(receipt_issuer::CapturedService {
                            authentication,
                            profile,
                            application,
                        }));
                    response
                }
            }),
        );
        Fixture {
            service: ReceiptService {
                pipeline: Service {
                    router,
                    keys: Arc::new(CallerKeys::new(
                        Some(Secret::new(CALLER.into())),
                        None,
                        false,
                    )),
                    requests: Arc::new(Semaphore::new(1)),
                },
                issuer,
                key_verifier: key_owner.verifier(),
                profiles,
                applications,
            },
            clock,
            router_calls,
            gate,
        }
    }

    fn authorize<T>(message: T) -> Request<T> {
        let mut request = Request::new(message);
        request
            .metadata_mut()
            .insert("authorization", format!("Bearer {CALLER}").parse().unwrap());
        request
    }

    fn issue(id: u64) -> Request<v1::ServiceReceiptRequest> {
        authorize(v1::ServiceReceiptRequest {
            verification: Some(v1::VerifyRequest {
                request_id: id,
                headers: vec![],
            }),
            service: "orders".into(),
            audience: "orders-api".into(),
            request_sha256: vec![3; 32],
        })
    }

    fn observation(reply: v1::ServiceReceiptReply) -> Request<v1::ServiceReceiptValidationRequest> {
        authorize(v1::ServiceReceiptValidationRequest {
            request_id: reply.request_id + 1,
            context: reply.context,
            receipt: reply.receipt,
            request_sha256: vec![3; 32],
        })
    }

    #[tokio::test]
    async fn observed_issue_rejects_undeclared_application() {
        let fixture = fixture_with_application(false);
        let result = fixture.service.issue_service_observed(issue(1)).await;
        assert_eq!(result.unwrap_err().code(), tonic::Code::Unavailable);
        assert_eq!(fixture.router_calls.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.service.pipeline.requests.available_permits(), 1);
    }

    #[tokio::test]
    async fn observed_issue_rejects_noncanonical_ids_before_authentication_work() {
        let fixture = fixture();
        for id in [0, 9_007_199_254_740_992, u64::MAX] {
            let result = fixture.service.issue_service_observed(issue(id)).await;
            assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
            assert_eq!(
                fixture.router_calls.load(Ordering::SeqCst),
                0,
                "malformed observed ID must be rejected before calling native authentication"
            );
            assert_eq!(
                fixture.clock.0.load(Ordering::SeqCst),
                0,
                "malformed observed ID must not reach the issuer clock"
            );
            assert_eq!(fixture.service.pipeline.requests.available_permits(), 1);
        }
    }

    #[tokio::test]
    async fn observed_methods_reject_ambiguous_or_absent_credentials_before_work() {
        let fixture = fixture();
        for credentials in [
            vec![],
            vec![""],
            vec!["Bearer "],
            vec!["Basic owned-boundary-gateway-key"],
            vec!["Bearer owned-boundary-gateway-key", "Bearer incorrect"],
            vec!["Bearer incorrect", "Bearer owned-boundary-gateway-key"],
            vec![
                "Bearer owned-boundary-gateway-key",
                "Bearer owned-boundary-gateway-key",
            ],
        ] {
            let mut issue = issue(20);
            issue.metadata_mut().remove("authorization");
            for value in &credentials {
                issue
                    .metadata_mut()
                    .append("authorization", value.parse().unwrap());
            }
            let mut observe = Request::new(v1::ServiceReceiptValidationRequest::default());
            *observe.metadata_mut() = issue.metadata().clone();
            assert_eq!(
                fixture
                    .service
                    .issue_service_observed(issue)
                    .await
                    .unwrap_err()
                    .code(),
                tonic::Code::Unauthenticated
            );
            assert_eq!(
                fixture
                    .service
                    .observe_service_time(observe)
                    .await
                    .unwrap_err()
                    .code(),
                tonic::Code::Unauthenticated
            );
        }
        assert_eq!(fixture.router_calls.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.clock.0.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.service.pipeline.requests.available_permits(), 1);

        let mut development = fixture;
        development.service.pipeline.keys = Arc::new(CallerKeys::new(None, None, true));
        assert_eq!(
            development
                .service
                .issue_service_observed(issue(20))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::Unauthenticated
        );
        assert_eq!(
            development
                .service
                .observe_service_time(authorize(v1::ServiceReceiptValidationRequest::default()))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::Unauthenticated
        );
        assert_eq!(development.router_calls.load(Ordering::SeqCst), 0);
        assert_eq!(development.clock.0.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn observed_issue_and_refresh_share_one_permit_without_self_exhaustion() {
        let fixture = fixture();
        let held = fixture
            .service
            .pipeline
            .requests
            .clone()
            .acquire_owned()
            .await
            .unwrap();
        assert_eq!(
            fixture
                .service
                .issue_service_observed(issue(30))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::ResourceExhausted
        );
        assert_eq!(
            fixture
                .service
                .observe_service_time(authorize(v1::ServiceReceiptValidationRequest::default()))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::ResourceExhausted
        );
        assert_eq!(fixture.router_calls.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.clock.0.load(Ordering::SeqCst), 0);
        drop(held);

        let issued = fixture
            .service
            .issue_service_observed(issue(30))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(fixture.service.pipeline.requests.available_permits(), 1);
        let initial = issued.observation.unwrap();
        let refreshed = fixture
            .service
            .observe_service_time(observation(issued.receipt.unwrap()))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(refreshed.request_id, 31);
        assert_eq!(refreshed.receipt_sha256, initial.receipt_sha256);
        assert_eq!(refreshed.clock_domain, initial.clock_domain);
        assert_eq!(refreshed.cache_ttl_ms, 0);
        assert_eq!(fixture.router_calls.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.service.pipeline.requests.available_permits(), 1);
    }

    #[tokio::test]
    async fn cancelled_observed_issue_releases_capacity_for_the_next_call() {
        let fixture = fixture();
        fixture.gate.block_next.store(true, Ordering::SeqCst);
        let mut pending = Box::pin(fixture.service.issue_service_observed(issue(40)));
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            tokio::select! {
                _ = fixture.gate.entered.notified() => {},
                result = &mut pending => panic!("router must suspend issuance, got {result:?}"),
            }
        })
        .await
        .expect("native authentication entry");
        assert_eq!(fixture.service.pipeline.requests.available_permits(), 0);
        assert_eq!(fixture.clock.0.load(Ordering::SeqCst), 0);
        drop(pending);
        assert_eq!(fixture.service.pipeline.requests.available_permits(), 1);

        // The gate blocks only the cancelled call. No timer or release is needed
        // for the next authentication, so a leaked permit fails immediately.
        let next = fixture
            .service
            .issue_service_observed(issue(41))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(next.receipt.unwrap().request_id, 41);
        assert_eq!(next.observation.unwrap().request_id, 41);
        assert_eq!(fixture.router_calls.load(Ordering::SeqCst), 2);
        assert_eq!(fixture.service.pipeline.requests.available_permits(), 1);
    }

    struct CountedGrpcStream {
        polls: Arc<AtomicUsize>,
        forbid_poll: bool,
        chunks: std::collections::VecDeque<bytes::Bytes>,
    }
    impl tonic::codegen::tokio_stream::Stream for CountedGrpcStream {
        type Item = Result<bytes::Bytes, std::io::Error>;
        fn poll_next(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Self::Item>> {
            self.polls.fetch_add(1, Ordering::SeqCst);
            assert!(
                !self.forbid_poll,
                "unauthenticated protobuf body was polled"
            );
            std::task::Poll::Ready(self.chunks.pop_front().map(Ok))
        }
    }

    fn grpc_body(chunks: Vec<bytes::Bytes>, forbid_poll: bool) -> (Body, Arc<AtomicUsize>) {
        let polls = Arc::new(AtomicUsize::new(0));
        let body = Body::from_stream(CountedGrpcStream {
            polls: polls.clone(),
            forbid_poll,
            chunks: chunks.into(),
        });
        (body, polls)
    }

    fn protobuf_frame(message: &impl prost::Message) -> Vec<u8> {
        let payload = message.encode_to_vec();
        let mut frame = vec![0];
        frame.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_be_bytes());
        frame.extend_from_slice(&payload);
        frame
    }

    fn grpc_http_request(method: &str, credentials: &[&str], body: Body) -> HttpRequest<Body> {
        let mut request = HttpRequest::builder()
            .method("POST")
            .version(http::Version::HTTP_2)
            .uri(format!("/hangang.hopae.v1.AuthenticationReceipts/{method}"))
            .header("content-type", "application/grpc")
            .header("te", "trailers")
            .body(body)
            .unwrap();
        for value in credentials {
            request
                .headers_mut()
                .append("authorization", value.parse().unwrap());
        }
        request
    }

    async fn grpc_response<B>(response: http::Response<B>) -> (u16, Vec<u8>)
    where
        B: tonic::codegen::Body<Data = bytes::Bytes> + Unpin,
        B::Error: std::fmt::Debug,
    {
        assert_eq!(response.status(), http::StatusCode::OK);
        let mut status = response
            .headers()
            .get("grpc-status")
            .map(|value| value.to_str().unwrap().parse::<u16>().unwrap());
        let mut body = response.into_body();
        let mut data = Vec::new();
        while let Some(frame) =
            std::future::poll_fn(|cx| std::pin::Pin::new(&mut body).poll_frame(cx)).await
        {
            match frame.unwrap().into_data() {
                Ok(bytes) => data.extend_from_slice(&bytes),
                Err(frame) => {
                    if let Ok(trailers) = frame.into_trailers()
                        && let Some(value) = trailers.get("grpc-status")
                    {
                        status = Some(value.to_str().unwrap().parse::<u16>().unwrap());
                    }
                }
            }
        }
        (status.expect("gRPC status in headers or trailers"), data)
    }

    #[tokio::test]
    async fn predecode_auth_refuses_initial_metadata_without_polling_protobuf() {
        for method in ["IssueServiceObserved", "ObserveServiceTime"] {
            for credentials in [
                vec![],
                vec!["Bearer incorrect"],
                vec!["Bearer owned-boundary-gateway-key", "Bearer incorrect"],
                vec!["Bearer incorrect", "Bearer owned-boundary-gateway-key"],
                vec![
                    "Bearer owned-boundary-gateway-key",
                    "Bearer owned-boundary-gateway-key",
                ],
            ] {
                let fixture = fixture();
                let pipeline = fixture.service.pipeline.clone();
                let capacity = pipeline.requests.clone();
                let generated =
                    v1::authentication_receipts_server::AuthenticationReceiptsServer::new(
                        fixture.service,
                    )
                    .max_decoding_message_size(wire::MAX_FRAME)
                    .max_encoding_message_size(2048);
                let service = bounded_transport(
                    generated,
                    pipeline,
                    Arc::new(Semaphore::new(16)),
                    wire::MAX_FRAME,
                );
                // Even the gRPC prefix is deliberately hostile. If protobuf
                // decoding runs first, poll_next panics instead of hiding the
                // ordering mistake behind a normal decoder error.
                let (body, polls) = grpc_body(
                    vec![bytes::Bytes::from_static(&[255, 255, 255, 255, 255])],
                    true,
                );
                let response = service
                    .oneshot(grpc_http_request(method, &credentials, body))
                    .await
                    .unwrap();
                let (status, data) = grpc_response(response).await;
                assert_eq!(status, tonic::Code::Unauthenticated as u16);
                assert!(data.is_empty());
                assert_eq!(polls.load(Ordering::SeqCst), 0);
                assert_eq!(fixture.router_calls.load(Ordering::SeqCst), 0);
                assert_eq!(fixture.clock.0.load(Ordering::SeqCst), 0);
                assert_eq!(capacity.available_permits(), 1);
            }
        }
    }

    #[tokio::test]
    async fn predecode_auth_preserves_valid_metadata_framing_and_observed_execution() {
        use prost::Message;
        let fixture = fixture();
        let pipeline = fixture.service.pipeline.clone();
        let capacity = pipeline.requests.clone();
        let generated =
            v1::authentication_receipts_server::AuthenticationReceiptsServer::new(fixture.service)
                .max_decoding_message_size(wire::MAX_FRAME)
                .max_encoding_message_size(2048);
        let service = bounded_transport(
            generated,
            pipeline,
            Arc::new(Semaphore::new(16)),
            wire::MAX_FRAME,
        );
        let frame = protobuf_frame(&issue(50).into_inner());
        // Split the five-byte framing prefix across chunks to exercise the
        // generated decoder instead of relying on one contiguous request body.
        let (body, polls) = grpc_body(
            vec![
                bytes::Bytes::copy_from_slice(&frame[..2]),
                bytes::Bytes::copy_from_slice(&frame[2..5]),
                bytes::Bytes::copy_from_slice(&frame[5..]),
            ],
            false,
        );
        let response = service
            .clone()
            .oneshot(grpc_http_request(
                "IssueServiceObserved",
                &["Bearer owned-boundary-gateway-key"],
                body,
            ))
            .await
            .unwrap();
        let (status, data) = grpc_response(response).await;
        assert_eq!(status, tonic::Code::Ok as u16);
        assert!(polls.load(Ordering::SeqCst) >= 3);
        assert!(data.len() >= 5);
        assert_eq!(data[0], 0);
        assert_eq!(
            u32::from_be_bytes(data[1..5].try_into().unwrap()) as usize,
            data.len() - 5
        );
        let issued = v1::ServiceReceiptObservedReply::decode(&data[5..]).unwrap();
        let initial = issued.observation.unwrap();
        assert_eq!(initial.request_id, 50);
        let refresh = observation(issued.receipt.unwrap()).into_inner();
        let (body, polls) = grpc_body(vec![bytes::Bytes::from(protobuf_frame(&refresh))], false);
        let response = service
            .oneshot(grpc_http_request(
                "ObserveServiceTime",
                &["Bearer owned-boundary-gateway-key"],
                body,
            ))
            .await
            .unwrap();
        let (status, data) = grpc_response(response).await;
        assert_eq!(status, tonic::Code::Ok as u16);
        assert!(polls.load(Ordering::SeqCst) > 0);
        assert!(data.len() >= 5);
        assert_eq!(data[0], 0);
        assert_eq!(
            u32::from_be_bytes(data[1..5].try_into().unwrap()) as usize,
            data.len() - 5
        );
        let refreshed = v1::ServiceReceiptTimeReply::decode(&data[5..]).unwrap();
        assert_eq!(refreshed.request_id, 51);
        assert_eq!(refreshed.receipt_sha256, initial.receipt_sha256);
        assert_eq!(refreshed.clock_domain, initial.clock_domain);
        assert_eq!(fixture.router_calls.load(Ordering::SeqCst), 1);
        assert!(fixture.clock.0.load(Ordering::SeqCst) > 0);
        assert_eq!(capacity.available_permits(), 1);
    }

    #[tokio::test]
    async fn predecode_auth_keeps_generated_message_size_limits_for_authorized_calls() {
        for method in ["IssueServiceObserved", "ObserveServiceTime"] {
            let fixture = fixture();
            let pipeline = fixture.service.pipeline.clone();
            let capacity = pipeline.requests.clone();
            let generated = v1::authentication_receipts_server::AuthenticationReceiptsServer::new(
                fixture.service,
            )
            .max_decoding_message_size(wire::MAX_FRAME)
            .max_encoding_message_size(2048);
            let service = bounded_transport(
                generated,
                pipeline,
                Arc::new(Semaphore::new(16)),
                wire::MAX_FRAME,
            );
            let mut frame = vec![0];
            frame.extend_from_slice(&u32::try_from(wire::MAX_FRAME + 1).unwrap().to_be_bytes());
            let (body, polls) = grpc_body(vec![bytes::Bytes::from(frame)], false);
            let response = service
                .oneshot(grpc_http_request(
                    method,
                    &["Bearer owned-boundary-gateway-key"],
                    body,
                ))
                .await
                .unwrap();
            let (status, data) = grpc_response(response).await;
            // Tonic rejects the declared frame size before reserving/decoding
            // the message, even though this body never supplies its payload.
            assert_eq!(status, tonic::Code::OutOfRange as u16);
            assert!(data.is_empty());
            assert!(polls.load(Ordering::SeqCst) > 0);
            assert_eq!(fixture.router_calls.load(Ordering::SeqCst), 0);
            assert_eq!(fixture.clock.0.load(Ordering::SeqCst), 0);
            assert_eq!(capacity.available_permits(), 1);
        }
    }
    #[tokio::test]
    async fn unary_ingress_refuses_extra_messages_before_observed_owner_execution() {
        for method in ["IssueServiceObserved", "ObserveServiceTime"] {
            let fixture = fixture();
            let pipeline = fixture.service.pipeline.clone();
            let generated = v1::authentication_receipts_server::AuthenticationReceiptsServer::new(
                fixture.service,
            )
            .max_decoding_message_size(wire::MAX_FRAME)
            .max_encoding_message_size(2048);
            let slots = Arc::new(Semaphore::new(1));
            let service = bounded_transport(generated, pipeline, slots.clone(), wire::MAX_FRAME);
            let frame = if method == "IssueServiceObserved" {
                protobuf_frame(&issue(50).into_inner())
            } else {
                // Empty protobuf is structurally valid; no owner handler may run.
                vec![0, 0, 0, 0, 0]
            };
            let (body, _) = grpc_body(
                vec![
                    bytes::Bytes::from(frame),
                    bytes::Bytes::from_static(&[0, 0, 0, 0, 0]),
                ],
                false,
            );
            let response = service
                .oneshot(grpc_http_request(
                    method,
                    &["Bearer owned-boundary-gateway-key"],
                    body,
                ))
                .await
                .unwrap();
            let (status, data) = grpc_response(response).await;
            assert_ne!(status, tonic::Code::Ok as u16);
            assert!(data.is_empty());
            assert_eq!(fixture.router_calls.load(Ordering::SeqCst), 0);
            assert_eq!(fixture.clock.0.load(Ordering::SeqCst), 0);
            assert_eq!(slots.available_permits(), 1);
        }
    }
}

#[tonic::async_trait]
impl v1::workload_authentication_receipts_server::WorkloadAuthenticationReceipts
    for ReceiptService
{
    async fn issue_observed(
        &self,
        request: Request<v1::WorkloadReceiptRequest>,
    ) -> Result<Response<v1::WorkloadReceiptObservedReply>, Status> {
        self.pipeline.caller(request.metadata())?;
        let metadata = request.metadata().clone();
        let input = request.into_inner();
        let digest: [u8; 32] = input
            .request_sha256
            .as_slice()
            .try_into()
            .map_err(|_| Status::invalid_argument("request digest required"))?;
        let verification = input
            .verification
            .ok_or_else(|| Status::invalid_argument("verification required"))?;
        if !(1..=9_007_199_254_740_991).contains(&verification.request_id) {
            return Err(Status::invalid_argument("invalid correlation"));
        }
        let attempt = self
            .issuer
            .begin_workload(&input.service, &input.audience)
            .map_err(|_| Status::unavailable("workload source unavailable"))?;
        let mut request = Request::new(verification);
        *request.metadata_mut() = metadata.clone();
        let (request_id, response, _permit) =
            self.pipeline.exchange_workload(request, attempt).await?;
        if !response.status().is_success() {
            return Err(Status::permission_denied(
                "native workload authentication refused",
            ));
        }
        let captured = response
            .extensions()
            .get::<Arc<crate::auth_gateway::receipt_issuer::CapturedWorkload>>()
            .ok_or_else(|| Status::failed_precondition("native workload source required"))?;
        let (issued, record) = captured
            .issue(
                &self.issuer,
                &self.profiles,
                &self.applications,
                &self.key_verifier,
                crate::auth_gateway::receipt_issuer::Request {
                    service: &input.service,
                    audience: &input.audience,
                    request_sha256: digest,
                },
                &|| {
                    self.pipeline
                        .caller(&metadata)
                        .map(|_| ())
                        .map_err(|_| crate::auth_gateway::receipt_keys::Refused)
                },
            )
            .map_err(|_| Status::unavailable("workload source retired"))?;
        let c = issued.context();
        let context = v1::AuthenticationReceiptContext {
            issuer_ref: c.issuer_ref.into(),
            key_epoch: c.key_epoch,
            identity_authority_epoch: c.identity_authority_epoch.into(),
            identity: Some(v1::ReceiptIdentity {
                subject_ref: c.identity.subject_ref.into(),
                kind: 3,
                aal: 0,
                revision: c.identity.revision,
                credential_generation: c.identity.credential_generation,
            }),
            service: c.service.into(),
            audience: c.audience.into(),
            request_sha256: c.request_sha256.to_vec(),
        };
        self.pipeline.caller(&metadata)?;
        let observation = self.workload_report(request_id, &record)?;
        Ok(Response::new(v1::WorkloadReceiptObservedReply {
            receipt: Some(v1::WorkloadReceiptReply {
                request_id,
                context: Some(context),
                receipt: issued.bytes().to_vec(),
            }),
            observation: Some(observation),
        }))
    }
    async fn observe_time(
        &self,
        request: Request<v1::WorkloadReceiptObservationRequest>,
    ) -> Result<Response<v1::WorkloadReceiptTimeReply>, Status> {
        self.pipeline.caller(request.metadata())?;
        let _permit = self
            .pipeline
            .requests
            .clone()
            .try_acquire_owned()
            .map_err(|_| Status::resource_exhausted("observation capacity"))?;
        let metadata = request.metadata().clone();
        let input = request.into_inner();
        if !(1..=9_007_199_254_740_991).contains(&input.request_id)
            || input.receipt.len() != hopae_grpc::receipt::LENGTH
        {
            return Err(Status::invalid_argument("invalid observation"));
        }
        let c = input
            .context
            .ok_or_else(|| Status::invalid_argument("context required"))?;
        let i = c
            .identity
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("identity required"))?;
        if i.kind != 3 || i.aal != 0 {
            return Err(Status::permission_denied("workload proof required"));
        }
        let context = hopae_grpc::receipt_binding::Context {
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
            request_sha256: c
                .request_sha256
                .as_slice()
                .try_into()
                .map_err(|_| Status::invalid_argument("digest required"))?,
        };
        let expected = input
            .request_sha256
            .as_slice()
            .try_into()
            .map_err(|_| Status::invalid_argument("digest required"))?;
        let record = self
            .issuer
            .observe_workload(&context, &input.receipt, &expected, &self.key_verifier)
            .map_err(|_| Status::permission_denied("workload source retired"))?;
        self.pipeline.caller(&metadata)?;
        Ok(Response::new(
            self.workload_report(input.request_id, &record)?,
        ))
    }
}
impl ReceiptService {
    fn workload_report(
        &self,
        request_id: u64,
        record: &crate::auth_gateway::workload_owner::Record,
    ) -> Result<v1::WorkloadReceiptTimeReply, Status> {
        let (now, remaining) = self
            .issuer
            .workload_time(record)
            .map_err(|_| Status::unavailable("workload time retired"))?;
        Ok(v1::WorkloadReceiptTimeReply {
            request_id,
            owner_now_ms: now,
            remaining_ms: remaining,
            receipt_sha256: record.hash.to_vec(),
            clock_domain: record
                .attempt
                .owner()
                .map_err(|_| Status::unavailable("workload owner retired"))?
                .domain()
                .into(),
            profile_revision: record.profile.revision,
            application_generation: record.application.generation,
            key_registry_revision: record.keys.revision(),
            cache_ttl_ms: 0,
        })
    }
}

#[cfg(all(test, target_os = "linux"))]
#[path = "grpc_workload_tests.rs"]
mod workload_tests;

/// Test-only mount of the production unmounted Human ingress adapter around a
/// generated existing service, not a declaration/activation of a Human RPC.
#[cfg(test)]
#[allow(clippy::too_many_arguments)] // Owned transport fixture inputs, not a production API.
pub(crate) async fn human_transport_fixture(
    router: Router,
    keys: Arc<CallerKeys>,
    owner: Arc<crate::verify::human::Owner>,
    readiness: crate::app::Readiness,
    budget: std::time::Duration,
    body: Body,
    credential: &str,
    captured: Arc<std::sync::atomic::AtomicUsize>,
    ingress: Arc<Semaphore>,
) -> (u16, Vec<u8>) {
    use axum::body::HttpBody as _;
    #[derive(Clone)]
    struct Native {
        pipeline: Service,
        captured: Arc<std::sync::atomic::AtomicUsize>,
    }
    #[tonic::async_trait]
    impl Authentication for Native {
        async fn verify(
            &self,
            request: Request<VerifyRequest>,
        ) -> Result<Response<VerifyReply>, Status> {
            let (request_id, response, _permit) = self.pipeline.exchange_human(request).await?;
            if response
                .extensions()
                .get::<Arc<crate::verify::human::Checked>>()
                .is_some()
            {
                self.captured
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
            Ok(Response::new(VerifyReply {
                request_id,
                status: response.status().as_u16().into(),
                headers: vec![],
                body: vec![],
            }))
        }
    }
    let pipeline = Service {
        router,
        keys,
        requests: Arc::new(Semaphore::new(1)),
    };
    let service = AuthenticationServer::new(Native {
        pipeline: pipeline.clone(),
        captured,
    })
    .max_decoding_message_size(wire::MAX_FRAME);
    let service = bounded_human_transport(
        service,
        pipeline,
        ingress,
        wire::MAX_FRAME,
        owner,
        readiness,
        budget,
    );
    let request = HttpRequest::builder()
        .method("POST")
        .version(http::Version::HTTP_2)
        .uri("/hangang.hopae.v1.Authentication/Verify")
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .header("authorization", credential)
        .body(body)
        .unwrap();
    let response = service.oneshot(request).await.unwrap();
    let mut status = response
        .headers()
        .get("grpc-status")
        .map(|v| v.to_str().unwrap().parse().unwrap());
    let mut body = response.into_body();
    let mut bytes = vec![];
    while let Some(frame) =
        std::future::poll_fn(|cx| std::pin::Pin::new(&mut body).poll_frame(cx)).await
    {
        let frame = frame.unwrap();
        if let Some(data) = frame.data_ref() {
            bytes.extend_from_slice(data);
        }
        if let Some(trailers) = frame.trailers_ref()
            && let Some(code) = trailers.get("grpc-status")
        {
            status = Some(code.to_str().unwrap().parse().unwrap());
        }
    }
    (status.unwrap(), bytes)
}

#[cfg(test)]
#[tokio::test]
async fn native_human_missing_original_token_refuses_before_caller_or_router() {
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counted = calls.clone();
    let pipeline = Service {
        router: Router::new(),
        keys: Arc::new(
            CallerKeys::new(None, None, false).with_counter(Arc::new(move |_, _| {
                counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            })),
        ),
        requests: Arc::new(Semaphore::new(1)),
    };
    let error = pipeline
        .exchange_human(Request::new(VerifyRequest::default()))
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::FailedPrecondition);
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert_eq!(pipeline.requests.available_permits(), 1);
}
