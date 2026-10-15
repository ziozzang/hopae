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
pub(crate) struct Capture;
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
    owner: Weak<Owner>,
    started: u64,
    limit_ms: u64,
    wall: Timestamp,
    last_wall: std::sync::atomic::AtomicI64,
    deadline: std::time::Instant,
    failed: AtomicBool,
}
pub(super) struct Allowed {
    pub(super) view: HandleView,
    pub(super) expires: Timestamp,
    pub(super) app: AppPolicy,
}
/// Only the Engine's final ordinary Allow creates this value.
pub(crate) struct Witness {
    owner: Arc<Owner>,
    admission: Admission,
    pub(crate) view: HandleView,
    pub(crate) snapshot: Arc<ConfigSnapshot>,
    pub(crate) app: AppPolicy,
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
    pub(crate) fn admit(self: &Arc<Self>, budget: std::time::Duration) -> StoreResult<Admission> {
        let limit_ms = u64::try_from(budget.as_millis().min(1000))
            .map_err(|_| refused())?
            .checked_sub(1)
            .filter(|n| *n > 0)
            .ok_or_else(refused)?;
        let started = self.read()?;
        let wall = self.wall.now();
        let admission = Admission {
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
        allowed: Allowed,
    ) -> StoreResult<Witness> {
        let Allowed { app, view, expires } = allowed;
        if !self.matches(ctx) || !Arc::ptr_eq(&snapshot, &self.applications.load_full()) {
            return Err(refused());
        }
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
        witness.current(input).await?;
        Ok(witness)
    }
}
impl Admission {
    fn now(&self, owner: &Arc<Owner>) -> StoreResult<Timestamp> {
        Ok(self.sample(owner)?.now)
    }
    // No native wall-clock callback after the joined durable check.
    fn after(&self, owner: &Arc<Owner>, sample: &TimeSample) -> StoreResult<Timestamp> {
        let result = (|| {
            let ticks = owner.read()?;
            if self.failed.load(Ordering::Acquire)
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
            if self.failed.load(Ordering::Acquire)
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
            if self.failed.load(Ordering::Acquire) {
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
    async fn current(&self, input: &VerifyInput) -> StoreResult<()> {
        if self.retired.load(Ordering::Acquire) {
            return Err(refused());
        }
        let result = self.check(input).await;
        if result.is_err() {
            self.retired.store(true, Ordering::Release);
        }
        result
    }
    async fn check(&self, input: &VerifyInput) -> StoreResult<()> {
        if Scope::from(input)? != self.scope {
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
        if self.retired.load(Ordering::Acquire) {
            return Err(refused());
        }
        Ok(())
    }
    pub(crate) async fn finish(self, input: &VerifyInput) -> StoreResult<Checked> {
        self.current(input).await?;
        Ok(Checked { witness: self })
    }
}
impl Checked {
    /// Subsequent consumers must repeat owners and the original age fence.
    #[allow(dead_code)]
    pub(crate) async fn require_current(&self, input: &VerifyInput) -> StoreResult<()> {
        self.witness.current(input).await
    }
}
