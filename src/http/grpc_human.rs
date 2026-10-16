//! Optional actual Human RPC adapter. Native source/Engine own every proof fact.
use super::grpc_gateway::Service as Pipeline;
use crate::auth_gateway::{human_source, receipt_binding};
use hopae_grpc::{PrincipalKind, v1};
use std::sync::Arc;
use tonic::{Request, Response, Status};

#[derive(Clone)]
pub(super) struct Human {
    pipeline: Pipeline,
    source: Arc<human_source::Source>,
    owner: Arc<crate::verify::human::Owner>,
}
fn refused() -> Status {
    Status::unavailable("native Human source refused")
}
impl Human {
    pub(super) fn from_services(
        pipeline: Pipeline,
        services: &crate::app::Services,
    ) -> anyhow::Result<Option<Self>> {
        if services
            .config
            .receipt_issuer
            .as_ref()
            .is_none_or(|native| native.human_receipts.is_none())
        {
            return Ok(None);
        }
        let source = services
            .human_receipt_source
            .clone()
            .ok_or_else(|| anyhow::anyhow!("Human source unavailable"))?;
        if !source.belongs_to(&services.human_owner) {
            anyhow::bail!("Human source owner mismatch");
        }
        Ok(Some(Self {
            pipeline,
            source,
            owner: services.human_owner.clone(),
        }))
    }
    fn query_constraint(
        &self,
        admission: &crate::verify::human::Admission,
        metadata: &tonic::metadata::MetadataMap,
        sample: &crate::verify::human::SourceTime,
    ) -> Result<u64, crate::auth_gateway::receipt_keys::Refused> {
        let remaining = admission
            .remaining_at(&self.owner, sample)
            .map_err(|_| crate::auth_gateway::receipt_keys::Refused)?;
        self.pipeline
            .caller_current(metadata)
            .map_err(|_| crate::auth_gateway::receipt_keys::Refused)?;
        Ok(remaining)
    }
}
fn wire_context(
    c: &receipt_binding::Context<'_>,
) -> Result<v1::AuthenticationReceiptContext, Status> {
    if c.identity.kind != PrincipalKind::Human || !(1..=3).contains(&c.identity.aal) {
        return Err(refused());
    }
    Ok(v1::AuthenticationReceiptContext {
        issuer_ref: c.issuer_ref.into(),
        key_epoch: c.key_epoch,
        identity_authority_epoch: c.identity_authority_epoch.into(),
        identity: Some(v1::ReceiptIdentity {
            subject_ref: c.identity.subject_ref.into(),
            kind: 1,
            aal: u32::from(c.identity.aal),
            revision: c.identity.revision,
            credential_generation: c.identity.credential_generation,
        }),
        service: c.service.into(),
        audience: c.audience.into(),
        request_sha256: c.request_sha256.to_vec(),
    })
}
fn native_context(
    c: &v1::AuthenticationReceiptContext,
) -> Result<receipt_binding::Context<'_>, Status> {
    let i = c.identity.as_ref().ok_or_else(refused)?;
    if i.kind != 1 || !(1..=3).contains(&i.aal) {
        return Err(refused());
    }
    Ok(receipt_binding::Context {
        issuer_ref: &c.issuer_ref,
        key_epoch: c.key_epoch,
        identity_authority_epoch: &c.identity_authority_epoch,
        identity: receipt_binding::Identity {
            subject_ref: &i.subject_ref,
            kind: PrincipalKind::Human,
            aal: i.aal as u8,
            revision: i.revision,
            credential_generation: i.credential_generation,
        },
        service: &c.service,
        audience: &c.audience,
        request_sha256: c
            .request_sha256
            .as_slice()
            .try_into()
            .map_err(|_| refused())?,
    })
}
fn empty_report(id: u64) -> v1::HumanReceiptTimeReply {
    v1::HumanReceiptTimeReply {
        request_id: id,
        receipt_sha256: vec![0; 32],
        scope_sha256: vec![0; 32],
        ..Default::default()
    }
}
// The output buffers already exist before the source's final time/current fence.
fn finish_report(target: &mut v1::HumanReceiptTimeReply, report: human_source::Observation) {
    target.owner_now_ms = report.owner_now_ms;
    target.remaining_ms = report.remaining_ms;
    target
        .receipt_sha256
        .copy_from_slice(&report.receipt_sha256);
    target.scope_sha256.copy_from_slice(&report.scope_sha256);
    target.clock_domain = report.clock_domain;
    target.source_revision = report.source_revision;
    target.application_generation = report.application_generation;
    target.key_registry_revision = report.key_registry_revision;
    target.cache_ttl_ms = 0;
}
fn original<T>(request: &Request<T>) -> Result<(), Status> {
    if request
        .extensions()
        .get::<crate::verify::human::Capture>()
        .is_none()
    {
        return Err(Status::failed_precondition(
            "original Human admission required",
        ));
    }
    if request
        .extensions()
        .get::<Arc<crate::auth_gateway::workload_owner::Attempt>>()
        .is_some()
    {
        return Err(Status::failed_precondition("mixed native admission"));
    }
    Ok(())
}
#[tonic::async_trait]
impl v1::human_authentication_receipts_server::HumanAuthenticationReceipts for Human {
    async fn issue_observed(
        &self,
        request: Request<v1::HumanReceiptRequest>,
    ) -> Result<Response<v1::HumanReceiptObservedReply>, Status> {
        original(&request)?;
        self.pipeline.caller(request.metadata())?;
        let (metadata, extensions, input) = request.into_parts();
        let final_request = input
            .final_request
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("Human final request required"))?;
        let binding = self
            .source
            .validate(&input.service, &input.audience, final_request)
            .map_err(|_| Status::permission_denied("Human scope refused"))?;
        let verify = input
            .verification
            .ok_or_else(|| Status::invalid_argument("Human verification required"))?;
        let id = verify.request_id;
        if !(1..=9_007_199_254_740_991).contains(&id) {
            return Err(Status::invalid_argument("Human request id"));
        }
        let final_metadata = metadata.clone();
        let verify = Request::from_parts(metadata, extensions, verify);
        let (returned, mut response, _permit) = self.pipeline.exchange_human(verify).await?;
        if returned != id || response.status() != tonic::codegen::http::StatusCode::OK {
            return Err(Status::permission_denied(
                "native Human authentication refused",
            ));
        }
        let checked = response
            .extensions_mut()
            .remove::<Arc<crate::verify::human::Checked>>()
            .ok_or_else(refused)?;
        let checked = Arc::try_unwrap(checked).map_err(|_| refused())?;
        let record = self
            .source
            .issue(checked, binding)
            .await
            .map_err(|_| refused())?;
        let issued = record.issued();
        let context = wire_context(&issued.context())?;
        let digest: [u8; 32] = context
            .request_sha256
            .as_slice()
            .try_into()
            .map_err(|_| refused())?;
        let mut reply = v1::HumanReceiptObservedReply {
            receipt: Some(v1::HumanReceiptReply {
                request_id: id,
                context: Some(context),
                receipt: issued.bytes().to_vec(),
            }),
            observation: Some(empty_report(id)),
        };
        let prepared = reply.receipt.as_ref().ok_or_else(refused)?;
        let context = native_context(prepared.context.as_ref().ok_or_else(refused)?)?;
        self.pipeline.caller(&final_metadata)?;
        let final_caller = |_: &crate::verify::human::SourceTime| {
            self.pipeline
                .caller_current(&final_metadata)
                .map(|_| u64::MAX)
                .map_err(|_| crate::auth_gateway::receipt_keys::Refused)
        };
        let report = self
            .source
            .observe_with_final(&context, &prepared.receipt, &digest, &final_caller)
            .await
            .map_err(|_| refused())?;
        finish_report(
            reply.observation.as_mut().expect("preallocated report"),
            report,
        );
        Ok(Response::new(reply))
    }
    async fn observe_time(
        &self,
        request: Request<v1::HumanReceiptObservationRequest>,
    ) -> Result<Response<v1::HumanReceiptTimeReply>, Status> {
        original(&request)?;
        self.pipeline.caller(request.metadata())?;
        let query_admission = request
            .extensions()
            .get::<crate::verify::human::Capture>()
            .ok_or_else(refused)?
            .take(&self.owner)
            .map_err(|_| refused())?;
        let _permit = self
            .pipeline
            .requests
            .clone()
            .try_acquire_owned()
            .map_err(|_| Status::resource_exhausted("Human observation capacity"))?;
        let (metadata, _, input) = request.into_parts();
        if !(1..=9_007_199_254_740_991).contains(&input.request_id) {
            return Err(Status::invalid_argument("Human request id"));
        }
        let context = native_context(input.context.as_ref().ok_or_else(refused)?)?;
        let digest: [u8; 32] = input
            .request_sha256
            .as_slice()
            .try_into()
            .map_err(|_| refused())?;
        let mut reply = empty_report(input.request_id);
        self.pipeline.caller(&metadata)?;
        let final_caller = |sample: &crate::verify::human::SourceTime| {
            self.query_constraint(&query_admission, &metadata, sample)
        };
        let report = self
            .source
            .observe_with_final(&context, &input.receipt, &digest, &final_caller)
            .await
            .map_err(|_| refused())?;
        finish_report(&mut reply, report);
        Ok(Response::new(reply))
    }
}

#[cfg(test)]
pub(crate) async fn direct_issue_fixture(
    services: &crate::app::Services,
    request: Request<v1::HumanReceiptRequest>,
) -> Result<Response<v1::HumanReceiptObservedReply>, Status> {
    use v1::human_authentication_receipts_server::HumanAuthenticationReceipts;
    let pipeline = Pipeline {
        router: crate::app::build_routers(services)
            .map_err(|_| refused())?
            .gateway,
        keys: services.caller_keys.clone(),
        requests: Arc::new(tokio::sync::Semaphore::new(8)),
    };
    Human::from_services(pipeline, services)
        .map_err(|_| refused())?
        .ok_or_else(refused)?
        .issue_observed(request)
        .await
}
#[cfg(test)]
pub(crate) async fn direct_observe_fixture(
    services: &crate::app::Services,
    request: Request<v1::HumanReceiptObservationRequest>,
) -> Result<Response<v1::HumanReceiptTimeReply>, Status> {
    use v1::human_authentication_receipts_server::HumanAuthenticationReceipts;
    let pipeline = Pipeline {
        router: crate::app::build_routers(services)
            .map_err(|_| refused())?
            .gateway,
        keys: services.caller_keys.clone(),
        requests: Arc::new(tokio::sync::Semaphore::new(8)),
    };
    Human::from_services(pipeline, services)
        .map_err(|_| refused())?
        .ok_or_else(refused)?
        .observe_time(request)
        .await
}

#[cfg(test)]
pub(crate) async fn delayed_query_fixture(
    services: &crate::app::Services,
    issue: Request<v1::HumanReceiptRequest>,
    original_query: crate::verify::human::Capture,
) -> (bool, Result<Response<v1::HumanReceiptTimeReply>, Status>) {
    use v1::human_authentication_receipts_server::HumanAuthenticationReceipts;
    let pipeline = Pipeline {
        router: crate::app::build_routers(services).unwrap().gateway,
        keys: services.caller_keys.clone(),
        requests: Arc::new(tokio::sync::Semaphore::new(8)),
    };
    let human = Human::from_services(pipeline, services).unwrap().unwrap();
    let metadata = issue.metadata().clone();
    let issued = human
        .issue_observed(issue)
        .await
        .unwrap()
        .into_inner()
        .receipt
        .unwrap();
    let context = issued.context.unwrap();
    let digest = context.request_sha256.clone();
    let native = native_context(&context).unwrap();
    let proof_current = human
        .source
        .observe(
            &native,
            &issued.receipt,
            &digest.clone().try_into().unwrap(),
        )
        .await
        .is_ok();
    let mut q = Request::new(v1::HumanReceiptObservationRequest {
        request_id: 2,
        context: Some(context),
        receipt: issued.receipt,
        request_sha256: digest,
    });
    *q.metadata_mut() = metadata;
    q.extensions_mut().insert(original_query);
    (proof_current, human.observe_time(q).await)
}

#[cfg(test)]
pub(crate) async fn query_crossing_fixture(
    services: &crate::app::Services,
    issue: Request<v1::HumanReceiptRequest>,
    query: crate::verify::human::Capture,
    before_take: &(dyn Fn() + Send + Sync),
    after_take: &(dyn Fn() + Send + Sync),
) -> (bool, Result<v1::HumanReceiptTimeReply, Status>) {
    use v1::human_authentication_receipts_server::HumanAuthenticationReceipts;
    let pipeline = Pipeline {
        router: crate::app::build_routers(services).unwrap().gateway,
        keys: services.caller_keys.clone(),
        requests: Arc::new(tokio::sync::Semaphore::new(8)),
    };
    let human = Human::from_services(pipeline, services).unwrap().unwrap();
    let metadata = issue.metadata().clone();
    let proof = human
        .issue_observed(issue)
        .await
        .unwrap()
        .into_inner()
        .receipt
        .unwrap();
    let context = native_context(proof.context.as_ref().unwrap()).unwrap();
    let hash = context.request_sha256;
    before_take();
    let admission = query.take(&human.owner).unwrap();
    after_take();
    let mut reply = empty_report(2);
    human.pipeline.caller(&metadata).unwrap();
    let result = human
        .source
        .observe_with_final(&context, &proof.receipt, &hash, &|sample| {
            human.query_constraint(&admission, &metadata, sample)
        })
        .await
        .map_err(|_| refused())
        .map(|report| {
            finish_report(&mut reply, report);
            reply
        });
    let still_current = human
        .source
        .observe(&context, &proof.receipt, &hash)
        .await
        .is_ok();
    (still_current, result)
}

#[cfg(test)]
mod caller_tests {
    use super::*;
    #[test]
    fn final_caller_check_preserves_verdict_without_running_metric_callbacks() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let calls = Arc::new(AtomicUsize::new(0));
        let count = calls.clone();
        let keys = crate::app::CallerKeys::new(
            Some(crate::crypto::Secret::new("owned-final-caller".into())),
            Some(crate::crypto::Secret::new("owned-next-caller".into())),
            false,
        )
        .with_counter(Arc::new(move |_, _| {
            count.fetch_add(1, Ordering::SeqCst);
        }));
        let pipeline = Pipeline {
            router: axum::Router::new(),
            keys: Arc::new(keys),
            requests: Arc::new(tokio::sync::Semaphore::new(1)),
        };
        for token in ["owned-final-caller", "owned-next-caller", "wrong"] {
            let mut metadata = tonic::metadata::MetadataMap::new();
            metadata.insert("authorization", format!("Bearer {token}").parse().unwrap());
            let expected = pipeline.caller(&metadata).is_ok();
            let before = calls.load(Ordering::SeqCst);
            assert_eq!(pipeline.caller_current(&metadata).is_ok(), expected);
            assert_eq!(calls.load(Ordering::SeqCst), before);
            metadata.append(
                "authorization",
                "Bearer owned-final-caller".parse().unwrap(),
            );
            assert!(pipeline.caller_current(&metadata).is_err());
            assert_eq!(calls.load(Ordering::SeqCst), before);
        }
    }
}
