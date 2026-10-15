//! Private native Engine capture. No public Human assertion or receipt capability.
use super::types::VerifyContext;
use crate::{
    crypto::{Clock, Rng, Timestamp},
    policy::types::{AppPolicy, ConfigSnapshot},
    provider::registry::{Registry, RegistryProviderFence},
    store::{Deadline, HandleView, Store, StoreError, StoreResult},
    verify::types::VerifyInput,
};
use hangang_runtime::time::ReceiverClock;
use std::sync::{
    Arc, Weak,
    atomic::{AtomicBool, AtomicU64, Ordering},
};

fn refused() -> StoreError {
    StoreError::Conflict("native Human owner unavailable")
}
/// Only an owning native adapter can request capture; never selected by a header.
#[derive(Clone)]
pub(crate) struct Capture {
    owner: Weak<Owner>,
    readiness: crate::app::Readiness,
    pub(super) admission: Arc<std::sync::Mutex<Option<Admission>>>,
}
impl Capture {
    pub(crate) fn take(&self, owner: &Arc<Owner>) -> StoreResult<Admission> {
        // Consume before checking even a wrong owner; a refused attempt cannot
        // resurrect this request's admission through another extension clone.
        let admission = self
            .admission
            .lock()
            .map_err(|_| refused())?
            .take()
            .ok_or_else(refused)?;
        if !Weak::ptr_eq(&self.owner, &Arc::downgrade(owner)) || !self.readiness.is_ready() {
            return Err(refused());
        }
        admission.now(owner)?;
        if !self.readiness.is_ready() {
            return Err(refused());
        }
        Ok(admission)
    }
}
pub(crate) struct Owner {
    pub(super) store: Store,
    pub(super) registry: Arc<Registry>,
    applications: Arc<arc_swap::ArcSwap<ConfigSnapshot>>,
    wall: Arc<dyn Clock>,
    clock: Option<ReceiverClock>,
    failed: AtomicBool,
    floor: AtomicU64,
    #[cfg(test)]
    pub(super) ticks: Option<Arc<dyn Fn() -> StoreResult<u64> + Send + Sync>>,
}
struct TimeSample {
    now: Timestamp,
    ticks: u64,
}
pub(crate) struct Admission {
    readiness: Option<crate::app::Readiness>,
    owner: Weak<Owner>,
    started: u64,
    limit_ms: u64,
    wall: Timestamp,
    last_wall: std::sync::atomic::AtomicI64,
    deadline: std::time::Instant,
    failed: AtomicBool,
}
pub(super) struct Allowed<'a> {
    pub(super) view: HandleView,
    pub(super) expires: Timestamp,
    pub(super) app: &'a AppPolicy,
}
/// Only the Engine's final ordinary Allow creates this value.
pub(crate) struct Witness {
    owner: Arc<Owner>,
    admission: Admission,
    pub(crate) view: HandleView,
    pub(crate) snapshot: Arc<ConfigSnapshot>,
    app: AppLocator,
    pub(crate) path: String,
    pub(crate) expires: Timestamp,
    pub(crate) durable: Option<crate::store::sqlite::human_owner::Current>,
    retired: AtomicBool,
    pub(crate) session_policy: crate::policy::types::SessionPolicy,
    scope: Scope,
    provider: RegistryProviderFence,
}
#[derive(PartialEq, Eq)]
struct Scope {
    url: String,
    method: String,
    host: String,
    port: u16,
    path: String,
    route: Option<String>,
    ip: std::net::IpAddr,
    ua: Option<String>,
    caller: u8,
    handle: crate::crypto::Digest,
}
impl Scope {
    fn from(input: &VerifyInput) -> StoreResult<Self> {
        let caller = match input.caller {
            super::CallerAuth::Keyed {
                which: super::KeySlot::Current,
            } => 1,
            super::CallerAuth::Keyed {
                which: super::KeySlot::Next,
            } => 2,
            _ => return Err(refused()),
        };
        if input.proto != super::Scheme::Https {
            return Err(refused());
        }
        Ok(Self {
            url: input.original_url.to_string(),
            method: input.method.to_string(),
            host: input.host.to_string(),
            port: input.port,
            path: input.canonical_path.as_str().into(),
            route: input.route_id.clone(),
            ip: input.client_ip,
            ua: input.user_agent.clone(),
            caller,
            handle: input.cookie_handle.as_ref().ok_or_else(refused)?.digest(),
        })
    }
}
/// Private point-in-time current capture, not a public grant or durable lease.
pub(crate) struct Checked {
    witness: Witness,
}
impl Owner {
    pub(crate) fn new(
        store: Store,
        registry: Arc<Registry>,
        applications: Arc<arc_swap::ArcSwap<ConfigSnapshot>>,
        wall: Arc<dyn Clock>,
        rng: &dyn Rng,
    ) -> Arc<Self> {
        let mut generation = [0; 16];
        rng.fill(&mut generation);
        Arc::new(Self {
            store,
            registry,
            applications,
            wall,
            clock: ReceiverClock::new(generation).ok(),
            failed: AtomicBool::new(false),
            floor: AtomicU64::new(0),
            #[cfg(test)]
            ticks: None,
        })
    }
    fn read(&self) -> StoreResult<u64> {
        if self.failed.load(Ordering::Acquire) {
            return Err(refused());
        }
        let floor = self.floor.load(Ordering::Acquire);
        #[cfg(test)]
        let now = self.ticks.as_ref().map_or_else(
            || {
                self.clock
                    .as_ref()
                    .ok_or_else(refused)?
                    .sample_ticks()
                    .map_err(|_| refused())
            },
            |f| f(),
        );
        #[cfg(not(test))]
        let now = self
            .clock
            .as_ref()
            .ok_or_else(refused)?
            .sample_ticks()
            .map_err(|_| refused());
        match now {
            Ok(now) if now > 0 && now >= floor && !self.failed.load(Ordering::Acquire) => {
                self.floor.fetch_max(now, Ordering::AcqRel);
                if self.failed.load(Ordering::Acquire) {
                    return Err(refused());
                }
                Ok(now)
            }
            _ => {
                self.failed.store(true, Ordering::Release);
                Err(refused())
            }
        }
    }
    /// The first clock read precedes wall sampling and all request work.
    /// Only trusted native ingress may wrap an admission sampled BEFORE caller
    /// authentication. No wire payload or public marker constructs this holder.
    pub(crate) fn capture(
        self: &Arc<Self>,
        mut admission: Admission,
        readiness: crate::app::Readiness,
    ) -> StoreResult<Capture> {
        admission.readiness = Some(readiness.clone());
        admission.now(self)?;
        if !readiness.is_ready() {
            return Err(refused());
        }
        Ok(Capture {
            owner: Arc::downgrade(self),
            readiness,
            admission: Arc::new(std::sync::Mutex::new(Some(admission))),
        })
    }
    pub(crate) fn admit(self: &Arc<Self>, budget: std::time::Duration) -> StoreResult<Admission> {
        let limit_ms = u64::try_from(budget.as_millis().min(1000))
            .map_err(|_| refused())?
            .checked_sub(1)
            .filter(|n| *n > 0)
            .ok_or_else(refused)?;
        let started = self.read()?;
        let wall = self.wall.now();
        let admission = Admission {
            readiness: None,
            owner: Arc::downgrade(self),
            started,
            limit_ms,
            wall,
            last_wall: std::sync::atomic::AtomicI64::new(wall.0),
            deadline: std::time::Instant::now() + std::time::Duration::from_millis(limit_ms),
            failed: AtomicBool::new(false),
        };
        admission.now(self)?;
        Ok(admission)
    }
    pub(super) fn native_context(&self, ctx: &VerifyContext) -> StoreResult<VerifyContext> {
        if !self.matches(ctx) {
            return Err(refused());
        }
        let mut native = ctx.clone();
        native.sessions = self.store.sessions();
        native.directory = self.store.directory();
        Ok(native)
    }
    pub(crate) fn matches(&self, ctx: &VerifyContext) -> bool {
        Arc::ptr_eq(&self.applications, &ctx.snapshot) && Arc::ptr_eq(&self.wall, &ctx.clock)
    }
    pub(super) async fn witness(
        self: &Arc<Self>,
        admission: Admission,
        ctx: &VerifyContext,
        input: &VerifyInput,
        snapshot: Arc<ConfigSnapshot>,
        allowed: Allowed<'_>,
    ) -> StoreResult<Witness> {
        let Allowed { app, view, expires } = allowed;
        if !self.matches(ctx) || !Arc::ptr_eq(&snapshot, &self.applications.load_full()) {
            return Err(refused());
        }
        let app = AppLocator::capture(&snapshot, app)?;
        let scope = Scope::from(input)?;
        if input
            .cookie_handle
            .as_ref()
            .is_none_or(|cookie| cookie.digest() != view.handle.handle_sha256)
        {
            return Err(refused());
        }
        admission.now(self)?;
        let provider = self
            .registry
            .capture_provider_fence(
                &self.store,
                &view.session.provider_id,
                Deadline(admission.deadline),
            )
            .await?;
        let mut witness = Witness {
            owner: self.clone(),
            admission,
            view,
            snapshot,
            app,
            path: input.canonical_path.as_str().into(),
            expires,
            durable: None,
            retired: AtomicBool::new(false),
            session_policy: ctx.limits.session,
            scope,
            provider,
        };
        let now = witness.admission.now(self)?;
        let current = self
            .registry
            .require_human_current(
                &self.store,
                &witness.provider,
                &witness,
                now,
                Deadline(witness.admission.deadline),
            )
            .await?;
        witness.expires = witness.expires.min(current.expires);
        witness.durable = Some(current);
        witness.current(Some(input)).await?;
        Ok(witness)
    }
}
impl Admission {
    /// Shorten this query at the source's exact final sample, without a clock callback.
    pub(crate) fn remaining_at(
        &self,
        owner: &Arc<Owner>,
        sample: &SourceTime,
    ) -> StoreResult<u64> {
        let result = (|| {
            if !self.ready()
                || self.failed.load(Ordering::Acquire)
                || owner.failed.load(Ordering::Acquire)
                || !Weak::ptr_eq(&self.owner, &Arc::downgrade(owner))
                || sample.clock_domain
                    != *owner.clock.as_ref().ok_or_else(refused)?.generation()
                || std::time::Instant::now() >= self.deadline
            {
                return Err(refused());
            }
            let elapsed = sample
                .owner_now_ms
                .checked_sub(self.started)
                .ok_or_else(refused)?;
            let remaining = self
                .limit_ms
                .checked_sub(elapsed)
                .and_then(|value| value.checked_sub(1))
                .filter(|value| *value > 0)
                .ok_or_else(refused)?;
            if !self.ready()
                || self.failed.load(Ordering::Acquire)
                || owner.failed.load(Ordering::Acquire)
                || std::time::Instant::now() >= self.deadline
            {
                return Err(refused());
            }
            Ok(remaining)
        })();
        if result.is_err() {
            self.failed.store(true, Ordering::Release);
        }
        result
    }
    /// Initial query validation may read the native wall clock before SQL.
    #[allow(dead_code)] // Additive Human RPC ingress integration.
    pub(crate) fn require_current(&self, owner: &Arc<Owner>) -> StoreResult<()> {
        self.now(owner).map(|_| ())
    }
    /// Final ingress fence: no wall-clock/metric/provider callback after SQL.
    #[allow(dead_code)] // Additive Human RPC ingress integration.
    pub(crate) fn require_final_current(&self, owner: &Arc<Owner>) -> StoreResult<()> {
        self.final_sample(owner).map(|_| ())
    }
    fn final_sample(&self, owner: &Arc<Owner>) -> StoreResult<TimeSample> {
        let result = (|| {
            if !self.ready()
                || self.failed.load(Ordering::Acquire)
                || !Weak::ptr_eq(&self.owner, &Arc::downgrade(owner))
                || std::time::Instant::now() >= self.deadline
            {
                return Err(refused());
            }
            let ticks = owner.read()?;
            let elapsed = ticks.checked_sub(self.started).ok_or_else(refused)?;
            if elapsed >= self.limit_ms {
                return Err(refused());
            }
            // The last actual wall sample precedes this elapsed interval.
            // Charging the full original elapsed interval again is conservative;
            // it avoids another externally supplied wall callback after SQL.
            let wall = self.last_wall.load(Ordering::Acquire).max(self.wall.0);
            let extra = i64::try_from(elapsed.checked_add(1).ok_or_else(refused)?)
                .map_err(|_| refused())?;
            let now = Timestamp(wall.checked_add(extra).ok_or_else(refused)?);
            if !self.ready()
                || self.failed.load(Ordering::Acquire)
                || owner.failed.load(Ordering::Acquire)
                || std::time::Instant::now() >= self.deadline
            {
                return Err(refused());
            }
            Ok(TimeSample { now, ticks })
        })();
        if result.is_err() {
            self.failed.store(true, Ordering::Release);
        }
        result
    }
    fn ready(&self) -> bool {
        self.readiness
            .as_ref()
            .is_none_or(crate::app::Readiness::is_ready)
    }
    fn now(&self, owner: &Arc<Owner>) -> StoreResult<Timestamp> {
        Ok(self.sample(owner)?.now)
    }
    // No native wall-clock callback after the joined durable check.
    fn after(&self, owner: &Arc<Owner>, sample: &TimeSample) -> StoreResult<Timestamp> {
        let result = (|| {
            let ticks = owner.read()?;
            if !self.ready()
                || self.failed.load(Ordering::Acquire)
                || std::time::Instant::now() >= self.deadline
                || ticks.checked_sub(self.started).ok_or_else(refused)? >= self.limit_ms
            {
                return Err(refused());
            }
            let elapsed = ticks.checked_sub(sample.ticks).ok_or_else(refused)?;
            Ok(sample
                .now
                .add(std::time::Duration::from_millis(elapsed + 1)))
        })();
        if result.is_err() {
            self.failed.store(true, Ordering::Release);
        }
        result
    }
    fn sample(&self, owner: &Arc<Owner>) -> StoreResult<TimeSample> {
        let result = (|| {
            if !self.ready()
                || self.failed.load(Ordering::Acquire)
                || !Weak::ptr_eq(&self.owner, &Arc::downgrade(owner))
                || std::time::Instant::now() >= self.deadline
            {
                return Err(refused());
            }
            let before = owner.read()?;
            // A delayed earlier reader must compare against the floor observed
            // before its callback, not a later concurrent reader's completion.
            let wall_floor_before = self.last_wall.load(Ordering::Acquire);
            let wall = owner.wall.now();
            let ticks = owner.read()?;
            let elapsed = ticks.checked_sub(self.started).ok_or_else(refused)?;
            // Millisecond BOOTTIME samples truncate. Charge one full quantum.
            if elapsed >= self.limit_ms {
                return Err(refused());
            }
            let floor = self
                .wall
                .0
                .checked_add(i64::try_from(elapsed + 1).map_err(|_| refused())?)
                .ok_or_else(refused)?;
            if std::time::Instant::now() >= self.deadline {
                return Err(refused());
            }
            if wall.0 < wall_floor_before || wall.0 < self.wall.0 {
                return Err(refused());
            }
            self.last_wall.fetch_max(wall.0, Ordering::AcqRel);
            let sample_gap = ticks.checked_sub(before).ok_or_else(refused)?;
            let wall_floor = wall
                .0
                .checked_add(i64::try_from(sample_gap + 1).map_err(|_| refused())?)
                .ok_or_else(refused)?;
            let now = Timestamp(wall_floor.max(floor));
            if !self.ready() || self.failed.load(Ordering::Acquire) {
                return Err(refused());
            }
            Ok(TimeSample { now, ticks })
        })();
        if result.is_err() {
            self.failed.store(true, Ordering::Release);
        }
        result
    }
}
impl Witness {
    async fn current(&self, input: Option<&VerifyInput>) -> StoreResult<()> {
        if self.retired.load(Ordering::Acquire) {
            return Err(refused());
        }
        let result = self.check(input).await;
        if result.is_err() {
            self.retired.store(true, Ordering::Release);
        }
        result
    }
    async fn check(&self, input: Option<&VerifyInput>) -> StoreResult<()> {
        if let Some(input) = input
            && Scope::from(input)? != self.scope
        {
            return Err(refused());
        }
        let sample = self.admission.sample(&self.owner)?;
        let now = sample.now;
        if now >= self.expires || !Arc::ptr_eq(&self.snapshot, &self.owner.applications.load_full())
        {
            return Err(refused());
        }
        self.owner
            .registry
            .require_human_current(
                &self.owner.store,
                &self.provider,
                self,
                now,
                Deadline(self.admission.deadline),
            )
            .await?;
        let now = self.admission.after(&self.owner, &sample)?;
        self.owner
            .registry
            .require_human_publication(&self.provider, &self.snapshot)?;
        if now >= self.expires || !Arc::ptr_eq(&self.snapshot, &self.owner.applications.load_full())
        {
            return Err(refused());
        }
        if self.retired.load(Ordering::Acquire) || !self.admission.ready() {
            return Err(refused());
        }
        Ok(())
    }
    pub(crate) async fn finish(self, input: &VerifyInput) -> StoreResult<Checked> {
        self.current(Some(input)).await?;
        Ok(Checked { witness: self })
    }
}
impl Checked {
    /// Only an actual Engine-produced Checked can retain this original scope.
    /// Repeats every owner and original admission check without retaining or
    /// reconstructing raw cookie credentials for later source observations.
    #[allow(dead_code)] // Consumed by the additive native Human source records.
    pub(crate) async fn require_current_retained(&self) -> StoreResult<()> {
        self.witness.current(None).await
    }
    /// Subsequent consumers must repeat owners and the original age fence.
    #[allow(dead_code)]
    pub(crate) async fn require_current(&self, input: &VerifyInput) -> StoreResult<()> {
        self.witness.current(Some(input)).await
    }
}

/// Private data read only from an actual Engine-sealed witness.
#[allow(dead_code)] // Pending native source integration.
pub(crate) struct SourceFacts {
    pub subject: String,
    pub aal: u8,
    pub user_revision: u64,
    pub credential_generation: u64,
    pub application_generation: u64,
}
#[allow(dead_code)] // Pending native source integration.
pub(crate) struct SourceTime {
    pub owner_now_ms: u64,
    pub expires_ms: u64,
    pub clock_domain: [u8; 16],
}
#[allow(dead_code)] // Native source integration consumes these private interfaces.
impl Checked {
    pub(crate) fn belongs_to(&self, owner: &Arc<Owner>) -> bool {
        Arc::ptr_eq(&self.witness.owner, owner)
    }
    pub(crate) async fn source_facts(
        &self,
        issuer: &str,
        binding: &crate::auth_gateway::human_request::Binding,
    ) -> StoreResult<SourceFacts> {
        let result = async {
            self.require_current_retained().await?;
            let w = &self.witness;
            if w.app().app_id.as_str() != binding.application()
                || w.scope.route.as_deref() != Some(binding.route())
                || w.scope.method != binding.method()
            {
                return Err(refused());
            }
            let subject = w
                .durable
                .as_ref()
                .ok_or_else(refused)?
                .subject_for_witness(issuer, w)?;
            let facts = SourceFacts {
                subject,
                aal: w.view.handle.issued_aal as u8,
                user_revision: w.view.user.authz_version,
                credential_generation: w.view.session.cred_gen,
                application_generation: w.snapshot.generation,
            };
            if [
                facts.user_revision,
                facts.credential_generation,
                facts.application_generation,
            ]
            .iter()
            .any(|n| !(1..=9_007_199_254_740_991).contains(n))
            {
                return Err(refused());
            }
            self.require_publication_current()?;
            Ok(facts)
        }
        .await;
        if result.is_err() {
            self.witness.retired.store(true, Ordering::Release);
        }
        result
    }
    pub(crate) fn require_publication_current(&self) -> StoreResult<()> {
        let result = (|| {
            let w = &self.witness;
            if w.retired.load(Ordering::Acquire) {
                return Err(refused());
            }
            let sample = w.admission.final_sample(&w.owner)?;
            let now = w.admission.after(&w.owner, &sample)?;
            w.owner
                .registry
                .require_human_publication(&w.provider, &w.snapshot)?;
            if now >= w.expires
                || !Arc::ptr_eq(&w.snapshot, &w.owner.applications.load_full())
                || w.retired.load(Ordering::Acquire)
                || !w.admission.ready()
            {
                return Err(refused());
            }
            Ok(())
        })();
        if result.is_err() {
            self.witness.retired.store(true, Ordering::Release);
        }
        result
    }
    pub(crate) fn source_time(&self) -> StoreResult<SourceTime> {
        let result = (|| {
            self.require_publication_current()?;
            let w = &self.witness;
            let sample = w.admission.final_sample(&w.owner)?;
            let elapsed = sample
                .ticks
                .checked_sub(w.admission.started)
                .ok_or_else(refused)?;
            let admission_left = w
                .admission
                .limit_ms
                .checked_sub(elapsed)
                .and_then(|n| n.checked_sub(1))
                .ok_or_else(refused)?;
            let utc_left =
                u64::try_from(w.expires.0.checked_sub(sample.now.0).ok_or_else(refused)?)
                    .map_err(|_| refused())?
                    .checked_sub(1)
                    .ok_or_else(refused)?;
            let remaining = admission_left.min(utc_left);
            let expires_ms = sample.ticks.checked_add(remaining).ok_or_else(refused)?;
            if remaining == 0 || expires_ms > 9_007_199_254_740_991 {
                return Err(refused());
            }
            let clock_domain = *w.owner.clock.as_ref().ok_or_else(refused)?.generation();
            // The last clock callback may itself withdraw a publication.
            w.owner
                .registry
                .require_human_publication(&w.provider, &w.snapshot)?;
            if !Arc::ptr_eq(&w.snapshot, &w.owner.applications.load_full())
                || w.retired.load(Ordering::Acquire)
                || !w.admission.ready()
            {
                return Err(refused());
            }
            Ok(SourceTime {
                owner_now_ms: sample.ticks,
                expires_ms,
                clock_domain,
            })
        })();
        if result.is_err() {
            self.witness.retired.store(true, Ordering::Release);
        }
        result
    }
}

/// Fixed actual service publication lease. Existing compiled provider clients,
/// DB pools and configuration allocations remain the service baseline; this
/// lease does not claim to measure their allocator footprint or process RSS.
/// Only separately owned Human metadata and records enter their byte quota.
pub(crate) struct SourcePublication {
    owner: Arc<Owner>,
    snapshot: Arc<ConfigSnapshot>,
    retired: AtomicBool,
}
#[allow(dead_code)] // Actual native source integration consumes this lease.
impl Owner {
    pub(crate) fn source_publication(self: &Arc<Self>) -> StoreResult<SourcePublication> {
        self.read()?;
        let publication = SourcePublication {
            owner: self.clone(),
            snapshot: self.applications.load_full(),
            retired: AtomicBool::new(false),
        };
        publication.require_current()?;
        Ok(publication)
    }
}
#[allow(dead_code)] // Actual native source integration consumes this lease.
impl SourcePublication {
    pub(crate) fn accepts(&self, checked: &Checked) -> bool {
        checked.belongs_to(&self.owner)
            && Arc::ptr_eq(&checked.witness.snapshot, &self.snapshot)
            && self.require_current().is_ok()
    }
    pub(crate) fn require_current(&self) -> StoreResult<()> {
        let result = (|| {
            if self.retired.load(Ordering::Acquire) || self.owner.failed.load(Ordering::Acquire) {
                return Err(refused());
            }
            // Callback-free publication fence for use after the final native
            // time sample. It never substitutes for Checked's native checks.
            if !Arc::ptr_eq(&self.snapshot, &self.owner.applications.load_full())
                || self.owner.failed.load(Ordering::Acquire)
                || self.retired.load(Ordering::Acquire)
            {
                return Err(refused());
            }
            Ok(())
        })();
        if result.is_err() {
            self.retired.store(true, Ordering::Release);
        }
        result
    }
    pub(crate) fn retained_bytes(&self) -> StoreResult<usize> {
        // Inline Arc handles only: these retain existing service allocations.
        Ok(std::mem::size_of::<Self>())
    }
}
#[allow(dead_code)] // Native source integration.
impl Checked {
    pub(crate) fn retained_bytes(&self) -> StoreResult<usize> {
        let w = &self.witness;
        let mut total = std::mem::size_of::<Self>();
        let scope = &w.scope;
        let mut add = |n: usize| -> StoreResult<()> {
            total = total.checked_add(n).ok_or_else(refused)?;
            Ok(())
        };
        add(w.view.owned_heap_bytes()?)?;
        add(w.provider.owned_heap_bytes()?)?;
        if let Some(current) = &w.durable {
            add(current.owned_heap_bytes()?)?;
        }
        for value in [&w.path, &scope.url, &scope.method, &scope.host, &scope.path] {
            add(value.capacity())?;
        }
        if let Some(value) = &scope.route {
            add(value.capacity())?;
        }
        if let Some(value) = &scope.ua {
            add(value.capacity())?;
        }
        Ok(total)
    }
}

/// Exact immutable publication location established from Engine's borrowed app.
/// No AppPolicy deep clone or per-record scan of every configured application.
enum AppLocator {
    Default,
    Index(usize),
}
impl AppLocator {
    fn capture(snapshot: &ConfigSnapshot, app: &AppPolicy) -> StoreResult<Self> {
        if std::ptr::eq(app, &snapshot.default_app) {
            return Ok(Self::Default);
        }
        let width = std::mem::size_of::<AppPolicy>();
        let offset = (app as *const AppPolicy)
            .addr()
            .checked_sub(snapshot.apps.as_ptr().addr())
            .ok_or_else(refused)?;
        if !offset.is_multiple_of(width) {
            return Err(refused());
        }
        let index = offset / width;
        if !snapshot
            .apps
            .get(index)
            .is_some_and(|owned| std::ptr::eq(owned, app))
        {
            return Err(refused());
        }
        Ok(Self::Index(index))
    }
    fn get<'a>(&self, snapshot: &'a ConfigSnapshot) -> &'a AppPolicy {
        match self {
            Self::Default => &snapshot.default_app,
            Self::Index(index) => &snapshot.apps[*index],
        }
    }
}
impl Witness {
    pub(crate) fn app(&self) -> &AppPolicy {
        self.app.get(&self.snapshot)
    }
}

#[cfg(test)]
mod app_locator_tests {
    use super::*;
    #[test]
    fn native_app_locator_accepts_only_exact_snapshot_locations() {
        let snapshot = ConfigSnapshot {
            generation: 1,
            apps: vec![AppPolicy::default_app(), AppPolicy::default_app()],
            default_app: AppPolicy::default_app(),
            providers: vec![],
            retained_reauth: Default::default(),
        };
        for app in [&snapshot.default_app, &snapshot.apps[0], &snapshot.apps[1]] {
            let locator = AppLocator::capture(&snapshot, app).unwrap();
            assert!(std::ptr::eq(app, locator.get(&snapshot)));
            let copy = app.clone();
            assert!(AppLocator::capture(&snapshot, &copy).is_err());
        }
        let empty = ConfigSnapshot {
            generation: 1,
            apps: vec![],
            default_app: AppPolicy::default_app(),
            providers: vec![],
            retained_reauth: Default::default(),
        };
        assert!(AppLocator::capture(&empty, &snapshot.apps[0]).is_err());
        assert!(AppLocator::capture(&empty, &empty.default_app).is_ok());
    }
}
