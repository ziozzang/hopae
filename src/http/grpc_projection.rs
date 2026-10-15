//! Opt-in native mTLS credential phase; no ordinary authentication output.
use super::grpc_gateway::{Service, v1};
use crate::auth_gateway::{permission_live, projection_runtime};
use prost::Message;
use std::sync::Arc;
use tonic::{Request, Response, Status};
pub(super) struct Projection {
    pipeline: Service,
    runtime: Arc<projection_runtime::Runtime>,
}
impl Projection {
    pub(super) fn new(
        pipeline: Service,
        services: &crate::app::Services,
    ) -> Result<Option<Self>, crate::auth_gateway::receipt_keys::Refused> {
        Ok(projection_runtime::Runtime::from_services(services)?
            .map(|runtime| Self { pipeline, runtime }))
    }
}
#[tonic::async_trait]
impl v1::credential_projection_server::CredentialProjection for Projection {
    async fn project(
        &self,
        request: Request<v1::ProjectionRequest>,
    ) -> Result<Response<v1::ProjectionReply>, Status> {
        self.pipeline.caller(request.metadata())?;
        let _permit = self
            .pipeline
            .requests
            .clone()
            .try_acquire_owned()
            .map_err(|_| Status::resource_exhausted("projection capacity"))?;
        let metadata = request.metadata().clone();
        let input = request.into_inner();
        if !(1..=9_007_199_254_740_991).contains(&input.request_id)
            || input.permission_contract != 1
            || input.permission_query.len() > 8192
        {
            return Err(Status::invalid_argument("invalid projection contract"));
        }
        let query =
            pumgye_grpc::v1::PermitValidationRequest::decode(input.permission_query.as_slice())
                .map_err(|_| Status::invalid_argument("invalid permission query"))?;
        if query.request_id != input.request_id {
            return Err(Status::invalid_argument("projection correlation mismatch"));
        }
        let request = permission_live::Request::new(
            query
                .request
                .ok_or_else(|| Status::invalid_argument("native request required"))?,
            query
                .permit
                .ok_or_else(|| Status::invalid_argument("permit required"))?,
        )
        .map_err(|_| Status::invalid_argument("invalid native permission bounds"))?;
        let context = request
            .authentication_context()
            .map_err(|_| Status::invalid_argument("invalid native identity"))?;
        let service = context.service.to_owned();
        let audience = context.audience.to_owned();
        let request_sha256 = context.request_sha256.to_vec();
        let plan_revision = request
            .permit()
            .binding
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("binding required"))?
            .plan_revision;
        let pipeline = self.pipeline.clone();
        let output = self
            .runtime
            .project(
                request,
                Arc::new(move || pipeline.caller(&metadata).is_ok()),
            )
            .await
            .map_err(|_| Status::unavailable("native projection refused"))?;
        let expires_ms = output.expires_ms();
        let (name, value) = output
            .into_header()
            .map_err(|_| Status::unavailable("native projection retired"))?;
        Ok(Response::new(v1::ProjectionReply {
            request_id: input.request_id,
            service,
            audience,
            request_sha256,
            header_name: name.to_string(),
            header_value: value.as_bytes().to_vec(),
            expires_ms,
            plan_revision,
        }))
    }
}
#[cfg(test)]
pub(crate) fn server(
    runtime: Arc<projection_runtime::Runtime>,
    keys: Arc<crate::app::CallerKeys>,
) -> v1::credential_projection_server::CredentialProjectionServer<
    impl v1::credential_projection_server::CredentialProjection,
> {
    v1::credential_projection_server::CredentialProjectionServer::new(Projection {
        runtime,
        pipeline: Service {
            router: axum::Router::new(),
            keys,
            requests: Arc::new(tokio::sync::Semaphore::new(4096)),
        },
    })
    .max_decoding_message_size(8448)
    .max_encoding_message_size(8192)
}
