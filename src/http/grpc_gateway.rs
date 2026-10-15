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
struct Service {
    router: Router,
    keys: Arc<CallerKeys>,
    requests: Arc<Semaphore>,
}
impl Service {
    fn caller(&self, metadata: &tonic::metadata::MetadataMap) -> Result<HeaderValue, Status> {
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

struct ReceiptService {
    pipeline: Service,
    issuer: Arc<crate::auth_gateway::receipt_issuer::Issuer>,
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
            .issue(
                &self.issuer,
                &self.profiles,
                &self.applications,
                crate::auth_gateway::receipt_issuer::Request {
                    service: &input.service,
                    audience: &input.audience,
                    request_sha256: input.request_sha256.as_slice().try_into().unwrap(),
                },
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
    let receipt_service = services
        .map(|services| receipt_resources(pipeline.clone(), services))
        .transpose()?
        .flatten()
        .map(|service| {
            v1::authentication_receipts_server::AuthenticationReceiptsServer::new(service)
                .max_decoding_message_size(wire::MAX_FRAME)
                .max_encoding_message_size(2048)
        });
    hangang_runtime::server(tls)?
        .add_service(
            AuthenticationServer::new(pipeline)
                .max_decoding_message_size(wire::MAX_FRAME)
                .max_encoding_message_size(wire::MAX_FRAME),
        )
        .add_optional_service(receipt_service)
        .add_optional_service(plan_service)
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
