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

struct ReceiptService {
    pipeline: Service,
    issuer: Arc<crate::auth_gateway::receipt_issuer::Issuer>,
    profiles: Arc<arc_swap::ArcSwap<crate::auth_gateway::authority::Snapshot>>,
    applications: Arc<arc_swap::ArcSwap<crate::policy::types::ConfigSnapshot>>,
}
#[tonic::async_trait]
impl v1::authentication_receipts_server::AuthenticationReceipts for ReceiptService {
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
