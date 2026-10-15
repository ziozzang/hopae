//! Workload-only fixed-source orchestration around the SAME paired ledger.
use super::*;
use crate::auth_gateway::workload_permission_live::Request as WorkloadRequest;
struct WorkloadFence {
    runtime: Arc<Runtime>,
    request: Arc<WorkloadRequest>,
    record: Arc<crate::auth_gateway::workload_owner::Record>,
    profile: Arc<crate::auth_gateway::authority::Snapshot>,
    application: Arc<crate::policy::types::ConfigSnapshot>,
    plan: Arc<projection_authority::Snapshot>,
    keys: Current,
    caller: Caller,
    active: Active,
}
impl WorkloadFence {
    fn check(&self) -> Result<(), Refused> {
        let caller_current = (self.caller)();
        self.runtime.issuer.workload_time(&self.record)?;
        self.runtime.receiver.sample_ticks().map_err(|_| Refused)?;
        if !caller_current {
            return Err(Refused);
        }
        self.check_local()
    }
    fn check_local(&self) -> Result<(), Refused> {
        self.record.current_owners()?;
        if !self.active.0.load(Ordering::Acquire)
            || !self.profile.available()
            || !self.plan.available()
            || !self.keys.current()
            || !Arc::ptr_eq(&self.profile, &self.runtime.profiles.load_full())
            || !Arc::ptr_eq(&self.application, &self.runtime.applications.load_full())
            || !Arc::ptr_eq(&self.plan, &self.runtime.plans.load_full())
        {
            return Err(Refused);
        }
        Ok(())
    }
}
pub(crate) struct Output {
    fence: WorkloadFence,
    value: crate::auth_gateway::projection_observed::Output,
}
impl Output {
    pub(crate) fn into_reply(
        self,
        request_id: u64,
    ) -> Result<hopae_grpc::v1::ObservedProjectionReply, Refused> {
        let context = self.fence.request.authentication_context()?;
        let epoch = hopae_grpc::workload_epoch::decode(context.identity_authority_epoch)
            .map_err(|_| Refused)?;
        self.value.into_reply(
            crate::auth_gateway::projection_observed::ReplyMetadata {
                service: context.service,
                audience: context.audience,
                request_sha256: context.request_sha256,
                request_id,
                profile_revision: epoch.profile_revision,
                application_generation: epoch.application_generation,
                key_registry_revision: self.fence.keys.revision(),
            },
            &|| self.fence.check(),
            &|| self.fence.check_local(),
        )
    }
}
impl Runtime {
    pub(crate) fn workloads_enabled(&self) -> bool {
        self.issuer.workloads_enabled()
            && self.resources.workload_client.is_some()
            && !self.resources.workload_scopes.is_empty()
    }
    pub(crate) async fn project_workload_observed(
        self: &Arc<Self>,
        request: Arc<WorkloadRequest>,
        caller: Caller,
    ) -> Result<Output, Refused> {
        if !caller() {
            return Err(Refused);
        }
        let remote_rates = self.resources.observed_rates.as_ref().ok_or(Refused)?;
        let profile = self.profiles.load_full();
        let application = self.applications.load_full();
        let plan = self.plans.load_full();
        if !plan.available() || !plan.enabled() {
            return Err(Refused);
        }
        let context = request.authentication_context()?;
        if !self
            .resources
            .permits_workload(context.service, context.audience)
        {
            return Err(Refused);
        }
        let client = self.resources.workload_client.as_ref().ok_or(Refused)?;
        let authentication = super::super::projection_observed::observe_local_workload(
            &self.verifier,
            &request,
            &self.issuer,
            &self.receiver,
        )?;
        let record = authentication.record().clone();
        let permission = self
            .resources
            .workload_client
            .as_ref()
            .ok_or(Refused)?
            .observe(
                request.clone(),
                &self.verifier,
                &self.receiver,
                remote_rates,
            )
            .await?;
        self.issuer.workload_time(&record)?;
        let chain = super::super::projection_observed::from_workload(
            &request,
            authentication,
            permission,
            client,
            &self.issuer,
            &self.receiver,
        )?;
        let remaining = chain.remaining(&self.receiver)?;
        let worker = self
            .workers
            .clone()
            .try_acquire_owned()
            .map_err(|_| Refused)?;
        let active = Active(Arc::new(AtomicBool::new(true)));
        let cancelled = active.0.clone();
        let runtime = self.clone();
        let output_runtime = self.clone();
        let task = tokio::task::spawn_blocking(move || {
            let _worker = worker;
            let keys = runtime.verifier.capture()?;
            let current = || -> Result<(), Refused> {
                let caller_current = caller();
                runtime.issuer.workload_time(&record)?;
                runtime.receiver.sample_ticks().map_err(|_| Refused)?;
                if !caller_current
                    || !cancelled.load(Ordering::Acquire)
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
            let value = plan.project_observed(
                chain,
                &mut runtime.store.conn(),
                runtime.receiver.clone(),
                &|_| current(),
                &|reference| runtime.resources.resolve(reference),
            )?;
            current()?;
            Ok::<_, Refused>((
                value,
                request,
                profile,
                application,
                plan,
                keys,
                caller,
                record,
            ))
        });
        let (value, request, profile, application, plan, keys, caller, record) =
            tokio::time::timeout(remaining, task)
                .await
                .map_err(|_| Refused)?
                .map_err(|_| Refused)??;
        let fence = WorkloadFence {
            runtime: output_runtime,
            request,
            record,
            profile,
            application,
            plan,
            keys,
            caller,
            active,
        };
        fence.check()?;
        Ok(Output { fence, value })
    }
}
