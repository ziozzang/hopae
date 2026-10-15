//! Native Human contract4 runtime. Local authentication comes only from the
//! retained record of the SAME Source mounted for Human receipts.
use super::{
    human_permission_live::{Client, Request},
    human_source::{RetainedRecord, Source},
    projection_authority, projection_observed,
    projection_resources::Prepared,
    receipt_authority::{Current, Verifier},
    receipt_keys::Refused,
};
use std::{
    collections::HashSet,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::sync::Semaphore;
// Only the native caller adapter may supply this known callback-free check.
// Counted callbacks run before entry, never within the ledger or after SQL.
pub(crate) type PureCaller = Arc<dyn Fn() -> Result<(), Refused> + Send + Sync>;
pub(crate) struct Runtime {
    source: Arc<Source>,
    owner: Arc<crate::verify::human::Owner>,
    store: crate::store::Store,
    resources: Arc<Prepared>,
    client: Arc<Client>,
    verifier: Verifier,
    plans: Arc<arc_swap::ArcSwap<projection_authority::Snapshot>>,
    receiver: Arc<hangang_runtime::time::ReceiverClock>,
    scopes: Vec<Activation>,
    workers: Arc<Semaphore>,
    #[cfg(test)]
    after_permission_delay_ms: std::sync::atomic::AtomicU64,
    #[cfg(test)]
    completed_permission_observations: std::sync::atomic::AtomicU64,
    #[cfg(test)]
    after_receiver: std::sync::Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
}
struct Activation {
    service: String,
    audience: String,
    application: String,
    route: String,
    fingerprints: HashSet<[u8; 32]>,
}
struct Active(Arc<AtomicBool>);
impl Drop for Active {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}
struct Fence {
    runtime: Arc<Runtime>,
    record: Arc<RetainedRecord>,
    plan: Arc<projection_authority::Snapshot>,
    keys: Current,
    caller: PureCaller,
    active: Active,
}
impl Fence {
    fn pure_current(&self) -> Result<(), Refused> {
        (self.caller)()?;
        if !self.plan.available()
            || !self.keys.current()
            || !Arc::ptr_eq(&self.plan, &self.runtime.plans.load_full())
        {
            return Err(Refused);
        }
        // Source pure check observes actual snapshot/registry first and native
        // readiness/retirement LAST. No arbitrary callback follows it.
        self.record.require_publication()?;
        if !self.active.0.load(Ordering::Acquire) {
            return Err(Refused);
        }
        Ok(())
    }
}
pub(crate) struct Output {
    value: projection_observed::Output,
    fence: Fence,
    request: Arc<Request>,
}
impl Output {
    #[cfg(test)]
    pub(crate) fn after_allocation_for_test(&mut self, hook: Box<dyn Fn() + Send + Sync>) {
        self.value.after_allocation_for_test(hook);
    }
    pub(crate) async fn into_reply(
        self,
        request_id: u64,
    ) -> Result<hopae_grpc::v1::ObservedProjectionReply, Refused> {
        self.fence.pure_current()?;
        let context = self.request.authentication_context()?;
        let epoch = hopae_grpc::human_epoch::decode(context.identity_authority_epoch)
            .map_err(|_| Refused)?;
        // Complete allocations before the final native joined current read.
        let prepared = self
            .value
            .prepare_reply(projection_observed::ReplyMetadata {
                service: context.service,
                audience: context.audience,
                request_sha256: context.request_sha256,
                request_id,
                profile_revision: epoch.source_scope_revision,
                application_generation: epoch.application_generation,
                key_registry_revision: self.fence.keys.revision(),
            })?;
        self.fence.record.require_current().await?;
        prepared.finish(&|| self.fence.pure_current(), &|| self.fence.pure_current())
    }
}
impl Runtime {
    #[cfg(test)]
    pub(crate) fn delay_after_permission_for_test(&self, milliseconds: u64) {
        self.after_permission_delay_ms
            .store(milliseconds, Ordering::Release);
    }
    #[cfg(test)]
    pub(crate) fn completed_permissions_for_test(&self) -> u64 {
        self.completed_permission_observations
            .load(Ordering::Acquire)
    }
    #[cfg(test)]
    pub(crate) fn after_receiver_for_test(&self, hook: Option<Arc<dyn Fn() + Send + Sync>>) {
        *self.after_receiver.lock().unwrap() = hook;
    }
    #[cfg(test)]
    pub(crate) fn same_receiver_for_test(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.receiver, &other.receiver)
    }
    pub(crate) fn from_services(
        services: &crate::app::Services,
    ) -> Result<Option<Arc<Self>>, Refused> {
        let Some(resources) = services.projection_resources.clone() else {
            return Ok(None);
        };
        if resources.human_scopes.is_empty() {
            return Ok(None);
        }
        let source = services.human_receipt_source.clone().ok_or(Refused)?;
        if !source.belongs_to(&services.human_owner) {
            return Err(Refused);
        }
        let client = resources.human_client.clone().ok_or(Refused)?;
        let plans = services
            .projection_authority
            .lock()
            .map_err(|_| Refused)?
            .reader();
        let mut scopes = Vec::new();
        for scope in &resources.human_scopes {
            let plan =
                projection_authority::observe(plans.clone(), &scope.service, &scope.audience, 0)?;
            if !matches!(plan.metadata()?.minimum_aal, 1 | 2) {
                return Err(Refused);
            }
            let fingerprints = source
                .projection_fingerprints(
                    &scope.service,
                    &scope.audience,
                    &scope.application,
                    &scope.route,
                )?
                .into_iter()
                .collect();
            scopes.push(Activation {
                service: scope.service.clone(),
                audience: scope.audience.clone(),
                application: scope.application.clone(),
                route: scope.route.clone(),
                fingerprints,
            });
        }
        let verifier = services
            .receipt_authority
            .lock()
            .map_err(|_| Refused)?
            .verifier();
        let receiver = services.projection_receiver_clock()?;
        Ok(Some(Arc::new(Self {
            source,
            owner: services.human_owner.clone(),
            store: services.store.clone(),
            resources,
            client,
            verifier,
            plans,
            receiver,
            scopes,
            workers: Arc::new(Semaphore::new(4)),
            #[cfg(test)]
            after_permission_delay_ms: std::sync::atomic::AtomicU64::new(0),
            #[cfg(test)]
            completed_permission_observations: std::sync::atomic::AtomicU64::new(0),
            #[cfg(test)]
            after_receiver: std::sync::Mutex::new(None),
        })))
    }
    fn accepts(&self, record: &RetainedRecord) -> Result<(), Refused> {
        let context = record.context();
        if !self.scopes.iter().any(|scope| {
            scope.service == context.service
                && scope.audience == context.audience
                && scope.application == record.application()
                && scope.route == record.route()
                && scope.fingerprints.contains(&record.scope_sha256())
        }) {
            return Err(Refused);
        }
        record.require_publication()
    }
    pub(crate) async fn project(
        self: &Arc<Self>,
        request: Arc<Request>,
        query: crate::verify::human::Admission,
        caller: PureCaller,
    ) -> Result<Output, Refused> {
        caller()?;
        let rates = self.resources.observed_rates.as_ref().ok_or(Refused)?;
        let authentication = projection_observed::observe_local_human(
            &self.verifier,
            &request,
            &self.source,
            &self.receiver,
            &|sample| {
                caller()?;
                query.remaining_at(&self.owner, sample).map_err(|_| Refused)
            },
        )
        .await?;
        self.accepts(authentication.record())?;
        let budget = authentication.remaining(&self.receiver)?;
        let permission = self
            .client
            .observe(
                request.clone(),
                &self.verifier,
                &self.receiver,
                rates,
                budget,
            )
            .await?;
        #[cfg(test)]
        {
            self.completed_permission_observations
                .fetch_add(1, Ordering::AcqRel);
            let delay = self.after_permission_delay_ms.load(Ordering::Acquire);
            if delay > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
            }
        }
        authentication.record().require_current().await?;
        caller()?;
        let (chain, record) = projection_observed::from_human(
            &request,
            authentication,
            permission,
            &self.client,
            &self.receiver,
        )?;
        self.accepts(&record)?;
        let remaining = chain.remaining(&self.receiver)?;
        let deadline = std::time::Instant::now()
            .checked_add(remaining)
            .ok_or(Refused)?;
        let worker = self
            .workers
            .clone()
            .try_acquire_owned()
            .map_err(|_| Refused)?;
        let record = Arc::new(record);
        let native_current = record.prepare_current()?;
        let fence = Fence {
            runtime: self.clone(),
            record: record.clone(),
            plan: self.plans.load_full(),
            keys: self.verifier.capture()?,
            caller,
            active: Active(Arc::new(AtomicBool::new(true))),
        };
        fence.pure_current()?;
        // This stack owner survives cancellation until Drop; the writer's guard
        // sees false and rolls back before commit. After commit, cancellation
        // can only discard output and burn the already consumed pair.
        let active = fence.active.0.clone();
        let runtime = self.clone();
        let plan = fence.plan.clone();
        let pure_caller = fence.caller.clone();
        let keys = runtime.verifier.capture()?;
        let value = self
            .store
            .human_ledger(crate::store::Deadline(deadline), move |ledger| {
                let _worker = worker;
                let pure = || {
                    pure_caller()?;
                    if !keys.current()
                        || !plan.available()
                        || !Arc::ptr_eq(&plan, &runtime.plans.load_full())
                    {
                        return Err(Refused);
                    }
                    record.require_publication()?;
                    if !active.load(Ordering::Acquire) {
                        return Err(Refused);
                    }
                    Ok(())
                };
                let guard = |snapshot: &crate::store::sqlite::human_owner::LedgerSnapshot<'_>| {
                    record.current_on(&native_current, snapshot)?;
                    pure()
                };
                let final_guard = || {
                    #[cfg(test)]
                    {
                        let hook = runtime.after_receiver.lock().map_err(|_| Refused)?.clone();
                        if let Some(hook) = hook {
                            hook();
                        }
                    }
                    // The production final hook is pure: no SQL, clocks,
                    // counted callbacks or allocation after receiver fences.
                    pure()
                };
                plan.project_human(
                    chain,
                    ledger,
                    runtime.receiver.clone(),
                    &guard,
                    &final_guard,
                    &|reference| runtime.resources.resolve(reference),
                )
                .map_err(|_| crate::store::StoreError::Conflict("Human projection refused"))
            })
            .await
            .map_err(|_| Refused)?;
        fence.pure_current()?;
        Ok(Output {
            value,
            fence,
            request,
        })
    }
}
