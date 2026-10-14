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

pub mod v1 {
    tonic::include_proto!("hangang.hopae.v1");
}
use v1::{
    Header, VerifyReply, VerifyRequest,
    authentication_server::{Authentication, AuthenticationServer},
};
struct Service {
    router: Router,
    keys: Arc<CallerKeys>,
    requests: Arc<Semaphore>,
}
#[tonic::async_trait]
impl Authentication for Service {
    async fn verify(
        &self,
        request: Request<VerifyRequest>,
    ) -> Result<Response<VerifyReply>, Status> {
        let mut entries = request.metadata().get_all("authorization").iter();
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
        let key = HeaderValue::from_str(token.unwrap())
            .map_err(|_| Status::unauthenticated("invalid gateway credential"))?;
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
            request_id: input.request_id,
            status: u32::from(parts.status.as_u16()),
            headers: fields
                .into_iter()
                .map(|(name, value)| Header { name, value })
                .collect(),
            body,
        }))
    }
}
pub async fn serve(
    listener: TcpListener,
    tls: ServerTlsConfig,
    router: Router,
    keys: Arc<CallerKeys>,
    mut stop: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    hangang_runtime::server(tls)?
        .add_service(
            AuthenticationServer::new(Service {
                router,
                keys,
                requests: Arc::new(Semaphore::new(4096)),
            })
            .max_decoding_message_size(wire::MAX_FRAME)
            .max_encoding_message_size(wire::MAX_FRAME),
        )
        .serve_with_incoming_shutdown(hangang_runtime::incoming(listener), async move {
            let _ = stop.wait_for(|v| *v).await;
        })
        .await?;
    Ok(())
}
