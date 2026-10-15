//! Optional Human contract4 endpoint; no Service profile or class fallback.
use super::grpc_gateway::Service as Pipeline;
use crate::auth_gateway::{human_permission_live, projection_human};
use hopae_grpc::v1;
use std::sync::Arc;
use tonic::{Request, Response, Status};
#[derive(Clone)]
pub(super) struct HumanProjection {
    pipeline: Pipeline,
    runtime: Arc<projection_human::Runtime>,
    owner: Arc<crate::verify::human::Owner>,
}
impl HumanProjection {
    pub(super) fn from_services(
        pipeline: Pipeline,
        services: &crate::app::Services,
    ) -> anyhow::Result<Option<Self>> {
        Ok(projection_human::Runtime::from_services(services)
            .map_err(|_| anyhow::anyhow!("Human projection owners unavailable"))?
            .map(|runtime| Self {
                pipeline,
                runtime,
                owner: services.human_owner.clone(),
            }))
    }
}
#[tonic::async_trait]
impl v1::human_observed_credential_projection_server::HumanObservedCredentialProjection
    for HumanProjection
{
    async fn project(
        &self,
        request: Request<v1::ProjectionRequest>,
    ) -> Result<Response<v1::ObservedProjectionReply>, Status> {
        if request
            .extensions()
            .get::<Arc<crate::auth_gateway::workload_owner::Attempt>>()
            .is_some()
        {
            return Err(Status::failed_precondition("mixed native admission"));
        }
        let capture = request
            .extensions()
            .get::<crate::verify::human::Capture>()
            .ok_or_else(|| Status::failed_precondition("original Human admission required"))?;
        // The outer wrapper sampled before caller/decode; never admit again.
        let query = capture
            .take(&self.owner)
            .map_err(|_| Status::unavailable("Human projection admission refused"))?;
        self.pipeline.caller(request.metadata())?;
        let _permit = self
            .pipeline
            .requests
            .clone()
            .try_acquire_owned()
            .map_err(|_| Status::resource_exhausted("Human projection capacity"))?;
        let metadata = request.metadata().clone();
        let input = request.into_inner();
        if !(1..=9_007_199_254_740_991).contains(&input.request_id)
            || input.permission_contract != 4
            || input.permission_query.len() > 8192
        {
            return Err(Status::invalid_argument(
                "invalid Human observed projection contract",
            ));
        }
        let parsed = human_permission_live::Request::decode_observed_query(
            &input.permission_query,
            input.request_id,
        )
        .map_err(|_| Status::invalid_argument("invalid Human permission query"))?;
        let pipeline = self.pipeline.clone();
        let caller = Arc::new(move || {
            pipeline
                .caller_current(&metadata)
                .map(|_| ())
                .map_err(|_| crate::auth_gateway::receipt_keys::Refused)
        });
        let output = self
            .runtime
            .project(parsed, query, caller)
            .await
            .map_err(|_| Status::unavailable("native Human projection refused"))?;
        let reply = output
            .into_reply(input.request_id)
            .await
            .map_err(|_| Status::unavailable("native Human projection retired"))?;
        Ok(Response::new(reply))
    }
}
