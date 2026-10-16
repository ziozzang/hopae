//! Wiring: lock, backup, store, configuration mirror, event plumbing,
//! listeners, background workers and graceful shutdown.
//!
//! # Merge points for the other work packages
//!
//! * [`build_routers`] is the one place that assembles the two routers: the
//!   gateway router (`http::gateway`, the verify adapter over
//!   `verify::decide`) and the portal router (`http::portal`, over the
//!   `portal::adapter::Adapter` that joins `session::Service` and the
//!   provider [`Registry`]).
//! * [`Services`] carries everything they need: the store traits, the clock,
//!   the RNG, the [`Emitter`], the configuration snapshot, the caller keys,
//!   the provider registry and the readiness flag.
//!
//! Startup order (scenario 013-5, 305-9): lock → read-only precheck → backup → store opened and migrated
//! → provider import and configuration mirror (with the `config.loaded`
//! event) → listeners bound, the gateway listener last → ready.

pub mod backup;
pub mod drift;
pub mod lock;
pub mod preflight;
pub mod state;

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::Context;
use arc_swap::ArcSwap;
use axum::Router;
use tokio::net::TcpListener;
use tokio::sync::watch;

use crate::config::Config;
use crate::crypto::{Clock, Rng, Secret, SystemClock, Timestamp, ct_eq, sha256};
use crate::event::bus::{self, BUS_CAPACITY, Emitter};
use crate::event::deliveries::DeliveryWorker;
use crate::event::diagnostic::DiagnosticWriter;
use crate::event::prune::{PruneTrigger, Pruner, Sweeper};
use crate::event::sampling::Sampler;
use crate::event::sinks::{LogSink, Sink};
use crate::event::types::{EventKind, Outcome, reasons};
use crate::http;
use crate::policy::types::ConfigSnapshot;
use crate::portal::adapter::Adapter;
use crate::portal::{PortalConfig, PortalState};
use crate::provider::Registry;
use crate::provider::oidc::{ProviderReport, Reporter};
use crate::provider::types::ProviderId;
use crate::session::service::{Deps, Service, ServiceConfig};
use crate::store::types::{EventRetention, ImportReport, ProviderRow};
use crate::store::{Directory, Events, Factors, Sessions, Store, StoreHooks};
use crate::telemetry::counters;
use crate::verify::types::{KeySlot, VerifyContext};

pub use lock::StoreLocked;

/// Exit status for an invalid or unsafe configuration and for a refused start.
pub const EXIT_CONFIG: u8 = 2;

// ---------------------------------------------------------------------------
// Caller keys
// ---------------------------------------------------------------------------

/// The accepted gateway caller keys (current and, during rotation, next),
/// read from the environment at start. Compared in constant time.
#[derive(Clone)]
pub struct CallerKeys {
    current: Option<Secret>,
    next: Option<Secret>,
    /// `gateway.allow_unauthenticated_caller`: development only.
    unauthenticated_allowed: bool,
    /// Where verdicts are counted: the process counters unless a test injects its own.
    counter: http::gateway::CounterFn,
}

/// What [`CallerKeys::check`] decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyVerdict {
    /// A key matched this slot.
    Accepted(KeySlot),
    /// No caller authentication is configured (development only).
    NotRequired,
    /// Missing or wrong key: answer `caller_unauthorized`.
    Rejected,
}

impl CallerKeys {
    pub fn new(
        current: Option<Secret>,
        next: Option<Secret>,
        unauthenticated_allowed: bool,
    ) -> Self {
        CallerKeys {
            current,
            next,
            unauthenticated_allowed,
            counter: Arc::new(counters::inc),
        }
    }

    /// Count verdicts through `counter` instead of the process counters.
    pub fn with_counter(mut self, counter: http::gateway::CounterFn) -> Self {
        self.counter = counter;
        self
    }

    /// Read the keys named by `gateway.caller_key_env` / `caller_key_next_env`.
    /// Empty values count as unset.
    pub fn from_env(cfg: &Config, lookup: impl Fn(&str) -> Option<String>) -> Self {
        let read = |name: &Option<String>| {
            name.as_deref()
                .and_then(&lookup)
                .filter(|v| !v.is_empty())
                .map(Secret::new)
        };
        CallerKeys::new(
            read(&cfg.gateway.caller_key_env),
            read(&cfg.gateway.caller_key_next_env),
            cfg.gateway.allow_unauthenticated_caller,
        )
    }

    /// Check a presented key against both slots (both comparisons always run)
    /// and count the outcome: `hopae_verify_caller_key_total{slot}` or
    /// `hopae_verify_unauthorized_total`.
    pub fn check(&self, presented: Option<&[u8]>) -> KeyVerdict {
        let verdict = self.check_untracked(presented);
        match verdict {
            KeyVerdict::Accepted(KeySlot::Current) => {
                (self.counter)(counters::VERIFY_CALLER_KEY_TOTAL, &[("slot", "current")])
            }
            KeyVerdict::Accepted(KeySlot::Next) => {
                (self.counter)(counters::VERIFY_CALLER_KEY_TOTAL, &[("slot", "next")])
            }
            KeyVerdict::Rejected => (self.counter)(counters::VERIFY_UNAUTHORIZED_TOTAL, &[]),
            KeyVerdict::NotRequired => (),
        }
        verdict
    }
    /// Final native fence: immutable keys only, no metric/plugin callbacks.
    pub(crate) fn check_untracked(&self, presented: Option<&[u8]>) -> KeyVerdict {
        if self.current.is_none() && self.next.is_none() {
            return if self.unauthenticated_allowed {
                KeyVerdict::NotRequired
            } else {
                KeyVerdict::Rejected
            };
        }
        let probe = presented.unwrap_or(&[]);
        let cur = self
            .current
            .as_ref()
            .is_some_and(|k| ct_eq(k.expose().as_bytes(), probe));
        let nxt = self
            .next
            .as_ref()
            .is_some_and(|k| ct_eq(k.expose().as_bytes(), probe));
        match (presented.is_some_and(|p| !p.is_empty()), cur, nxt) {
            (true, true, _) => KeyVerdict::Accepted(KeySlot::Current),
            (true, false, true) => KeyVerdict::Accepted(KeySlot::Next),
            _ => KeyVerdict::Rejected,
        }
    }

    pub fn unauthenticated_allowed(&self) -> bool {
        self.unauthenticated_allowed
    }
}

// ---------------------------------------------------------------------------
// Services and routers
// ---------------------------------------------------------------------------

/// Readiness for the portal health body: false until the store is open, the
/// configuration is mirrored and both listeners are bound.
#[derive(Clone, Default)]
pub struct Readiness(Arc<AtomicBool>);

impl Readiness {
    pub fn is_ready(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }

    pub(crate) fn set(&self, ready: bool) {
        self.0.store(ready, Ordering::SeqCst);
    }
}

/// Everything the routers and services are built from.
#[derive(Clone)]
pub struct Services {
    pub(crate) human_owner: Arc<crate::verify::human::Owner>,
    pub(crate) human_receipt_source: Option<Arc<crate::auth_gateway::human_source::Source>>,
    pub projection_resources: Option<Arc<crate::auth_gateway::projection_resources::Prepared>>,
    // One latched receiver generation for every projection class and endpoint.
    projection_clock: Arc<
        std::sync::OnceLock<
            Result<
                Arc<hangang_runtime::time::ReceiverClock>,
                crate::auth_gateway::receipt_keys::Refused,
            >,
        >,
    >,
    pub receipt_authority: Arc<std::sync::Mutex<crate::auth_gateway::receipt_authority::Authority>>,
    pub receipt_issuer: Option<Arc<crate::auth_gateway::receipt_issuer::Issuer>>,
    pub projection_authority:
        Arc<std::sync::Mutex<crate::auth_gateway::projection_authority::Authority>>,
    pub external_verifiers: Arc<crate::factor::external_registry::Registry>,
    pub totp_keyring: Option<Arc<crate::factor::keyring::Keyring>>,
    pub webauthn: Option<Arc<crate::factor::webauthn::RelyingParty>>,
    pub authentication_authority:
        Option<Arc<std::sync::Mutex<crate::auth_gateway::authority::Authority>>>,
    pub config: Arc<Config>,
    pub store: Store,
    pub clock: Arc<dyn Clock>,
    pub rng: Arc<dyn Rng>,
    pub emitter: Emitter,
    pub snapshot: Arc<ArcSwap<ConfigSnapshot>>,
    pub caller_keys: Arc<CallerKeys>,
    pub readiness: Readiness,
    pub store_hooks: Option<Arc<StoreHooks>>,
    /// The configured providers, built from the store's rows.
    pub registry: Arc<Registry>,
    /// Groups, their sync and the membership projection (ADR-0019).
    pub groups: Arc<crate::groups::sync::GroupService>,
    /// When the process started (the status page's `build.started_at`).
    pub started_at: Timestamp,
    /// The bound listener addresses, set once every listener is bound.
    pub listeners: Arc<std::sync::OnceLock<crate::admin::Listeners>>,
}

impl Services {
    pub(crate) fn projection_receiver_clock(
        &self,
    ) -> Result<Arc<hangang_runtime::time::ReceiverClock>, crate::auth_gateway::receipt_keys::Refused>
    {
        self.projection_clock
            .get_or_init(|| {
                let mut generation = [0; 16];
                self.rng.fill(&mut generation);
                hangang_runtime::time::ReceiverClock::new(generation)
                    .map(Arc::new)
                    .map_err(|_| crate::auth_gateway::receipt_keys::Refused)
            })
            .as_ref()
            .map(Arc::clone)
            .map_err(|_| crate::auth_gateway::receipt_keys::Refused)
    }

    pub fn directory(&self) -> Arc<dyn Directory> {
        self.store.directory()
    }

    pub fn sessions(&self) -> Arc<dyn Sessions> {
        self.store.sessions()
    }

    pub fn events(&self) -> Arc<dyn Events> {
        self.store.events()
    }

    /// The verify engine's context for this process.
    pub fn verify_context(&self) -> VerifyContext {
        VerifyContext::new(
            self.directory(),
            self.sessions(),
            self.clock.clone(),
            self.rng.clone(),
            self.snapshot.clone(),
            self.config.verify_limits(),
        )
        .with_events(self.emitter.clone(), self.events())
    }

    /// The session service (portal flows) for this process.
    pub fn session_service(&self) -> anyhow::Result<Service> {
        let config = ServiceConfig::from_config(&self.config)
            .map_err(|e| anyhow::anyhow!("session service configuration: {e}"))?;
        Ok(Service::new(Deps {
            directory: self.directory(),
            sessions: self.sessions(),
            events: self.events(),
            emitter: self.emitter.clone(),
            clock: self.clock.clone(),
            rng: self.rng.clone(),
            snapshot: self.snapshot.clone(),
            providers: self.registry.clone(),
            config,
        })
        .with_native_primary(self.store.clone(), self.registry.clone())
        .with_groups(self.groups.clone()))
    }
}

impl Services {
    /// The admin listener's state, when `admin.public_url` is set.
    pub fn admin_state(&self) -> Option<Arc<crate::admin::AdminState>> {
        let cfg = crate::admin::AdminConfig::from_config(&self.config)?;
        let mut key = [0u8; 32];
        self.rng.fill(&mut key);
        Some(Arc::new(crate::admin::AdminState {
            projection_authority: self.projection_authority.clone(),
            profile_authority: self.authentication_authority.clone(),
            profile_config: self.config.clone(),
            profile_store: self.store.clone(),
            profile_workers: Arc::new(tokio::sync::Semaphore::new(4)),
            cfg,
            directory: self.directory(),
            sessions: self.sessions(),
            events: self.events(),
            emitter: Some(self.emitter.clone()),
            clock: self.clock.clone(),
            rng: self.rng.clone(),
            in_flight: Arc::new(tokio::sync::Semaphore::new(
                self.config.limits.admin_max_concurrent as usize,
            )),
            snapshot: self.snapshot.clone(),
            verify: self.verify_context(),
            registry: self.registry.clone(),
            groups: self.groups.clone(),
            key,
            started_at: self.started_at,
            config_digest: config_digest(&self.config),
            listeners: self.listeners.get().cloned().unwrap_or_default(),
            peer_warned: std::sync::Mutex::new(std::collections::HashMap::new()),
            delegation: self.config.admin.hangang_delegation.clone(),
            delegation_replay: crate::admin::delegation::Replay::new(
                self.config.state_dir.join("delegation-nonces.sqlite3"),
            ),
        }))
    }
}

/// The provider registry's reporter: a provider-side failure becomes a
/// `provider.error` diagnostic event (reason codes only, never bodies).
fn provider_reporter(emitter: Emitter) -> Reporter {
    Arc::new(move |r: ProviderReport| {
        emitter.diagnostic(
            EventKind::ProviderError,
            Outcome::Failure,
            "provider",
            |b| {
                let b = b
                    .provider(&r.provider_id)
                    .reason(r.reason)
                    .attr("endpoint", r.endpoint);
                match r.status {
                    Some(s) => b.attr("status", u64::from(s)),
                    None => b,
                }
            },
        );
    })
}

/// The two routers, one per listener (ADR-0003: disjoint route sets).
pub struct Routers {
    pub portal: Router,
    pub gateway: Router,
    /// Only when `admin.public_url` is set.
    pub admin: Option<Router>,
}

/// Assemble both routers from `services`. The portal and the gateway share the
/// store, the provider registry and the emitter, never a route.
pub fn build_routers(services: &Services) -> anyhow::Result<Routers> {
    let mut gateway_state = http::gateway::GatewayState::new(
        crate::gateway::hangang::GatewayConfig::from_config(&services.config),
        services.verify_context(),
        services.caller_keys.clone(),
        services.config.limits.gateway_max_concurrent,
        Some(Arc::new(counters::inc)),
        Some(services.emitter.clone()),
    );
    gateway_state = gateway_state.with_human_owner(services.human_owner.clone())?;
    if let Some(issuer) = &services.config.receipt_issuer
        && issuer.human_receipts.is_some()
    {
        gateway_state = gateway_state
            .with_human_policy_metadata(services.store.clone(), issuer.issuer_ref.clone())?;
    }
    if let Some(authority) = &services.authentication_authority {
        let reader = authority
            .lock()
            .map_err(|_| anyhow::anyhow!("authentication authority unavailable"))?
            .reader();
        gateway_state = gateway_state.with_authentication_authority(reader)?;
    }
    if services.receipt_issuer.is_some() {
        gateway_state = gateway_state.with_service_receipt_capture()?;
    }
    let adapter = Adapter::new(
        services.session_service()?,
        services.registry.clone(),
        services.directory(),
        services.events(),
        services.emitter.clone(),
        services.readiness.clone(),
    );
    let adapter = if let Some(keys) = &services.totp_keyring {
        adapter.with_totp(
            Arc::new(services.store.clone()),
            keys.clone(),
            services.clock.clone(),
            services.rng.clone(),
        )
    } else {
        adapter
    };
    let adapter = adapter.with_external(
        Arc::new(services.store.clone()),
        services.external_verifiers.clone(),
        services.clock.clone(),
        services.rng.clone(),
    );
    let adapter = match &services.webauthn {
        Some(rp) => adapter.with_webauthn(
            Arc::new(services.store.clone()),
            rp.clone(),
            services.totp_keyring.clone(),
            services.clock.clone(),
            services.rng.clone(),
        ),
        None => adapter,
    };
    let adapter = Arc::new(adapter);
    let mut portal_state = PortalState::new(
        PortalConfig::from_config(&services.config),
        adapter.clone(),
        services.clock.clone(),
        services.rng.clone(),
    );
    if services.webauthn.is_some() {
        portal_state = portal_state.with_settings(adapter.clone());
    }
    Ok(Routers {
        portal: http::portal::router(portal_state),
        gateway: http::gateway_router(gateway_state),
        admin: services.admin_state().map(http::admin::router),
    })
}

// ---------------------------------------------------------------------------
// Process environment: clock, RNG, test hooks
// ---------------------------------------------------------------------------

/// Clock, random source and store hooks for this process. Production: the
/// system clock, the OS CSPRNG, no hooks. With `test-hooks` and
/// `HOPAE_TEST_HOOKS` set: a settable clock, `HOPAE_TEST_SEED` for the RNG,
/// and a hooks handle for the store.
struct Env {
    clock: Arc<dyn Clock>,
    rng: Arc<dyn Rng>,
    store_hooks: Option<Arc<StoreHooks>>,
    #[cfg(feature = "test-hooks")]
    test_clock: Option<Arc<crate::crypto::TestClock>>,
    #[cfg(feature = "test-hooks")]
    hooks_addr: Option<String>,
}

fn env() -> Env {
    #[cfg(feature = "test-hooks")]
    if let Some(addr) = std::env::var("HOPAE_TEST_HOOKS")
        .ok()
        .filter(|a| !a.is_empty())
    {
        let tc = Arc::new(crate::crypto::TestClock::new(SystemClock.now()));
        return Env {
            clock: tc.clone(),
            rng: crate::crypto::rng_from_env(std::env::var("HOPAE_TEST_SEED").ok().as_deref()),
            store_hooks: Some(Arc::new(StoreHooks::new())),
            test_clock: Some(tc),
            hooks_addr: Some(addr),
        };
    }
    #[cfg(not(feature = "test-hooks"))]
    if std::env::var_os("HOPAE_TEST_HOOKS").is_some() {
        tracing::warn!(
            "HOPAE_TEST_HOOKS is set but this binary was built without the test-hooks feature: ignored"
        );
    }
    Env {
        clock: Arc::new(SystemClock),
        rng: crate::crypto::rng_from_env(None),
        store_hooks: None,
        #[cfg(feature = "test-hooks")]
        test_clock: None,
        #[cfg(feature = "test-hooks")]
        hooks_addr: None,
    }
}

// ---------------------------------------------------------------------------
// bind
// ---------------------------------------------------------------------------

/// The event plumbing that `run` starts: the receiving end of the diagnostic
/// queue and the shared pieces the workers use.
struct EventWiring {
    rx: tokio::sync::mpsc::Receiver<crate::event::types::Event>,
    sampler: Arc<Sampler>,
    trigger: Arc<PruneTrigger>,
}

/// Bound listeners and the open store; call [`Bound::run`] to serve.
pub struct Bound {
    admin_tls: Option<Arc<rustls::ServerConfig>>,
    grpc_gateway: Option<(TcpListener, tonic::transport::ServerTlsConfig)>,
    native_gateway: Option<(TcpListener, SocketAddr)>,
    native_gateway_tls: Option<tokio_rustls::TlsAcceptor>,
    portal: TcpListener,
    gateway: TcpListener,
    /// The admin listener, bound after the portal and before the gateway.
    admin: Option<(TcpListener, SocketAddr)>,
    portal_addr: SocketAddr,
    gateway_addr: SocketAddr,
    services: Services,
    wiring: EventWiring,
    _lock: lock::InstanceLock,
    #[cfg(feature = "test-hooks")]
    hooks: Option<(TcpListener, SocketAddr, Arc<http::hooks::HooksState>)>,
}

/// Digest of the effective configuration (not its content) for `config.loaded`.
fn config_digest(cfg: &Config) -> String {
    sha256(format!("{cfg:?}").as_bytes()).to_hex()
}

fn unix_secs(t: Timestamp) -> i64 {
    t.secs()
}

fn log_import(report: &ImportReport) {
    for id in &report.skipped_api_managed {
        tracing::warn!(
            "provider {id}: database authoritative (managed_by=api); file entry ignored"
        );
    }
    for id in &report.skipped_deleted {
        tracing::warn!("provider {id}: removed at run time; file entry ignored");
    }
}

fn provider_rows(cfg: &Config) -> Vec<ProviderRow> {
    cfg.provider_configs()
        .iter()
        .map(ProviderRow::from_config)
        .collect()
}

/// Open the store, import and mirror the configuration, then bind both
/// listeners. Failing here is a start failure.
pub async fn bind(cfg: &Config) -> anyhow::Result<Bound> {
    bind_environment(cfg, &|n: &str| std::env::var(n).ok()).await
}
async fn bind_environment(
    cfg: &Config,
    real_env: &(dyn Fn(&str) -> Option<String> + Sync),
) -> anyhow::Result<Bound> {
    let receiver_keys = crate::auth_gateway::receipt_config::receiver_keys(
        cfg.receipt_issuer.as_ref(),
        &cfg.receipt_permit_keys,
    )
    .map_err(|_| anyhow::anyhow!("native receiver key configuration refused"))?;

    let projection_resources = cfg
        .projection_receiver
        .as_ref()
        .map(|resources| {
            resources
                .prepare(&real_env)
                .map(Arc::new)
                .map_err(|_| anyhow::anyhow!("native projection resources unavailable"))
        })
        .transpose()?;
    let external_verifiers = Arc::new(
        crate::factor::external_registry::Registry::compile(
            &cfg.external_verifiers,
            &real_env,
            None,
        )
        .map_err(|_| {
            anyhow::anyhow!("external_verifiers: unavailable or invalid verifier material")
        })?,
    );
    let totp_keyring = cfg
        .totp_keyring
        .as_ref()
        .map(|keys| {
            crate::factor::keyring::Keyring::compile(keys, &real_env)
                .map(Arc::new)
                .map_err(|_| anyhow::anyhow!("totp_keyring: unavailable or invalid key material"))
        })
        .transpose()?;
    let webauthn = cfg
        .webauthn
        .as_ref()
        .map(|w| {
            crate::factor::webauthn::RelyingParty::compile(w, &cfg.portal.public_url)
                .map(Arc::new)
                .map_err(|e| anyhow::anyhow!("{e}"))
        })
        .transpose()?;

    for w in cfg.warnings() {
        tracing::warn!("{w}");
    }
    for w in crate::config::env_warnings(cfg, real_env) {
        tracing::warn!("{w}");
    }
    let env = env();
    let receipt_issuer = cfg
        .receipt_issuer
        .as_ref()
        .map(|config| {
            config
                .load(
                    &|name| std::env::var(name).ok(),
                    env.clock.clone(),
                    env.rng.clone(),
                )
                .map(Arc::new)
        })
        .transpose()
        .map_err(|_| anyhow::anyhow!("native receipt issuer unavailable"))?;
    let store_path = cfg.store_path();

    // 1. One instance per store.
    let instance_lock = lock::acquire(&cfg.state_dir)?;

    // 2. The database is validated read-only BEFORE anything is written: a
    //    refused database (pre-release schema, missing structures, a newer
    //    version) is left byte for byte as it is, with no backup and no
    //    migration (scenario 305-9). Then a copy of an older database is
    //    written before it is migrated.
    {
        let p = store_path.clone();
        let version = tokio::task::spawn_blocking(move || crate::store::precheck(&p))
            .await
            .context("precheck task")?
            .with_context(|| format!("checking store {}", store_path.display()))?;
        if version > 0 {
            tracing::info!("schema foundation validated (v{version})");
        }
    }
    {
        let p = store_path.clone();
        let made = tokio::task::spawn_blocking(move || {
            backup::backup_before_migration(&p, backup::LATEST_SCHEMA_VERSION)
        })
        .await
        .context("backup task")??;
        if let Some(b) = made {
            tracing::info!("database backup written before migration: {}", b.display());
        }
    }

    // 3. Store opened and migrated.
    let store = {
        let p = store_path.clone();
        let (clock, hooks) = (env.clock.clone(), env.store_hooks.clone());
        let sinks = cfg.event_sinks();
        tokio::task::spawn_blocking(move || Store::open(&p, clock, sinks, hooks))
            .await
            .context("store open task")?
            .with_context(|| format!("opening store {}", store_path.display()))?
    };
    let receipt_authority = {
        let mut connection = store.conn();
        let mut authority = crate::auth_gateway::receipt_authority::Authority::load(&connection, 0)
            .map_err(|_| anyhow::anyhow!("native receipt key history unavailable"))?;
        // Native validated configuration owns startup publication; the instance
        // lock is held. Request-role publication must use its real actor guard.
        authority
            .reconcile(&mut connection, &receiver_keys, "startup", &|_| Ok(()))
            .map_err(|_| anyhow::anyhow!("native receipt key history refused configuration"))?;
        Arc::new(std::sync::Mutex::new(authority))
    };
    store.set_rng(env.rng.clone());
    tracing::info!(
        "store ready: {} (schema v{})",
        store_path.display(),
        store.schema_version().unwrap_or(0)
    );

    // 4. Event plumbing.
    // Test hooks: the harness can shrink the diagnostic queue (S014-5 uses 100).
    #[cfg(feature = "test-hooks")]
    let bus_capacity = env.hooks_addr.as_ref().map_or(BUS_CAPACITY, |_| {
        std::env::var("HOPAE_TEST_DIAG_QUEUE")
            .ok()
            .and_then(|v| v.parse().ok())
            .filter(|n| *n > 0)
            .unwrap_or(BUS_CAPACITY)
    });
    #[cfg(not(feature = "test-hooks"))]
    let bus_capacity = BUS_CAPACITY;
    let (bus, rx) = bus::channel(bus_capacity);
    let sampler = Arc::new(Sampler::default());
    let trigger = Arc::new(PruneTrigger::new(cfg.events.prune_every));
    let emitter = Emitter::new(
        env.clock.clone(),
        env.rng.clone(),
        bus,
        sampler.clone(),
        trigger.clone(),
        cfg.log.accept_client_request_id,
    );

    // 5. Configuration generation, overlap bookkeeping, provider import and
    //    the `config.loaded` event in one transaction with the import.
    let digest = config_digest(cfg);
    let now = env.clock.now();
    let (changed, _) = {
        let conn = store.conn();
        let changed = state::config_changed(&conn, &digest).context("recording config digest")?;
        state::track_caller_key_next(
            &conn,
            cfg.gateway.caller_key_next_env.is_some(),
            unix_secs(SystemClock.now()),
        )
        .context("recording caller key overlap")?;
        (changed, ())
    };
    let directory = store.directory();
    let generation = if changed || directory.config_generation().await? == 0 {
        directory.bump_config_generation().await?
    } else {
        directory.config_generation().await?
    };
    let external_revision = store.external_snapshot_revision().await?;
    external_verifiers
        .publish_authorized_configuration(&store, generation, external_revision)
        .await
        .context("publishing external verifier snapshot")?;
    let mut snapshot = cfg.snapshot(generation);
    let listeners_attr = match cfg.admin_addr() {
        Some(a) => format!(
            "portal={} gateway={} admin={a}",
            cfg.portal_addr(),
            cfg.gateway_addr()
        ),
        None => format!(
            "portal={} gateway={}",
            cfg.portal_addr(),
            cfg.gateway_addr()
        ),
    };
    let loaded = emitter.required(EventKind::ConfigLoaded, Outcome::Info, "startup", |b| {
        b.attr("config_digest", digest.as_str())
            .attr("apps", snapshot.apps.len() as u64)
            .attr("providers", snapshot.providers.len() as u64)
            .attr("listeners", listeners_attr.as_str())
            .attr("insecure_mode", cfg.insecure_mode())
            .attr(
                "unauthenticated_caller",
                cfg.gateway.allow_unauthenticated_caller,
            )
    });
    let report = directory
        .import_providers(provider_rows(cfg), None, vec![loaded])
        .await
        .context("importing providers")?;
    log_import(&report);
    import_admin_grants_at_start(cfg, &*directory, &env).await?;
    // Passwordless passkey sessions exist only while passwordless sign-in is
    // configured (ADR-0017 decision 16, review F6).
    if !cfg.webauthn.as_ref().is_some_and(|w| w.passwordless) {
        use crate::store::Passkeys;
        let ended = store
            .end_passkey_sessions("r_startup")
            .await
            .context("ending passkey sessions")?;
        if ended > 0 {
            tracing::warn!(
                ended,
                "passwordless sign-in is not configured: passkey sessions ended"
            );
        }
    }
    // The provider registry, from the rows the import just settled (the
    // database is authoritative). Its reporter writes `provider.error`.
    let prepared_providers = store
        .prepare_registry_providers(
            generation,
            crate::store::Deadline(std::time::Instant::now() + Duration::from_secs(5)),
        )
        .await
        .context("preparing native provider owners")?;
    let rows = prepared_providers.rows();
    // A stored `reauth` setting (an api-managed row) overrides the file's default.
    crate::provider::apply_stored_reauth(&mut snapshot, rows);
    let applications = Arc::new(ArcSwap::from_pointee(snapshot));
    let snapshot = applications.load_full();
    let material_key =
        crate::provider::material::Key::resolve(cfg.human_material_key_env.as_deref(), &real_env);
    if cfg.human_material_key_env.is_some() && material_key.is_none() {
        tracing::warn!(
            "native Human compiled material qualification disabled: dedicated key unavailable or invalid"
        );
    }
    let registry = Arc::new(Registry::from_prepared_keyed(
        prepared_providers,
        applications.clone(),
        real_env,
        env.clock.clone(),
        Some(provider_reporter(emitter.clone())),
        material_key.as_ref(),
    )?);
    let mut mirrored: Vec<_> = snapshot.apps.clone();
    mirrored.push(snapshot.default_app.clone());
    store
        .mirror_apps(&mirrored)
        .await
        .context("mirroring applications")?;
    tracing::info!(
        "configuration mirrored: {} applications, {} providers (generation {generation})",
        snapshot.apps.len(),
        snapshot.providers.len()
    );
    counters::set(
        counters::BUILD_INFO,
        &[("version", env!("CARGO_PKG_VERSION"))],
        1,
    );
    counters::set(counters::CONFIG_LOADED_TIMESTAMP, &[], now.secs());

    // 6. Listeners; the gateway listener last.
    let portal = TcpListener::bind(cfg.portal_addr())
        .await
        .context("binding portal listener")?;
    let portal_addr = portal.local_addr()?;
    let authentication_authority = {
        let mut connection = store.conn();
        let durable = crate::auth_gateway::publication::read(&connection)?;
        if cfg.authentication_gateway.is_some() || durable.is_some() {
            let validate = |profiles: &crate::auth_gateway::runtime::Config| {
                let mut candidate = cfg.clone();
                candidate.authentication_gateway = Some(profiles.clone());
                candidate
                    .validate()
                    .map_err(|_| crate::auth_gateway::publication::Error::Invalid)
            };
            Some(Arc::new(std::sync::Mutex::new(
                crate::auth_gateway::authority::Authority::load(
                    &mut connection,
                    cfg.authentication_gateway.clone(),
                    &|name| std::env::var(name).ok(),
                    &validate,
                )?,
            )))
        } else {
            None
        }
    };
    // Kubernetes workload lifecycle signals (ADR 0021/0022) become outbox
    // events through one pump per process.
    if let Some(authority) = &authentication_authority {
        let (sink, rx) = crate::auth_gateway::workload::signals::channel();
        tokio::spawn(crate::auth_gateway::workload::events::pump(
            rx,
            emitter.clone(),
            store.events(),
        ));
        authority
            .lock()
            .map_err(|_| anyhow::anyhow!("authentication authority unavailable"))?
            .attach_workload_signals(sink);
    }
    let projection_authority = {
        let mut connection = store.conn();
        let durable = crate::auth_gateway::projection_authority::read(&connection)
            .map_err(|_| anyhow::anyhow!("invalid durable credential projection state"))?;
        if let Some(configuration) = durable.as_ref().and_then(|d| d.configuration.as_ref()) {
            crate::auth_gateway::projection::validate_capabilities(
                configuration,
                cfg.credential_projection.as_ref(),
            )
            .map_err(|_| {
                anyhow::anyhow!("durable credential projection exceeds declared capabilities")
            })?;
        }
        let mut owner = crate::auth_gateway::projection_authority::Authority::load(&connection, 0)
            .map_err(|_| anyhow::anyhow!("credential projection owner unavailable"))?;
        if durable.is_none()
            && let Some(configuration) = &cfg.credential_projection
        {
            owner
                .publish(
                    &mut connection,
                    0,
                    Some(configuration.clone()),
                    "bootstrap",
                    &|_| Ok(()),
                )
                .map_err(|_| anyhow::anyhow!("credential projection bootstrap failed"))?;
        }
        Arc::new(std::sync::Mutex::new(owner))
    };
    let human_owner = crate::verify::human::Owner::new(
        store.clone(),
        registry.clone(),
        applications.clone(),
        env.clock.clone(),
        env.rng.as_ref(),
    );
    // One process-affine record owner is shared by Human receipt and projection RPCs.
    let human_receipt_source = cfg
        .receipt_issuer
        .as_ref()
        .filter(|native| native.human_receipts.is_some())
        .map(|native| {
            let issuer = receipt_issuer
                .clone()
                .ok_or_else(|| anyhow::anyhow!("Human issuer unavailable"))?;
            let verifier = receipt_authority
                .lock()
                .map_err(|_| anyhow::anyhow!("Human receipt keys unavailable"))?
                .verifier();
            crate::auth_gateway::human_source::Source::new(
                human_owner.clone(),
                issuer,
                verifier,
                native,
            )
            .map(Arc::new)
            .map_err(|_| anyhow::anyhow!("Human source unavailable"))
        })
        .transpose()?;
    let groups_cfg = cfg.groups.clone().unwrap_or_default();
    let projection_signer = groups_cfg
        .projection
        .as_ref()
        .map(|p| {
            crate::groups::projection::ProjectionSigner::load(
                p,
                &|name| std::env::var(name).ok(),
                cfg.receipt_issuer.as_ref().map(|r| r.public_key.as_str()),
            )
            .map(Arc::new)
        })
        .transpose()
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let groups = Arc::new(crate::groups::sync::GroupService::new(
        store.clone(),
        groups_cfg,
        projection_signer,
        env.clock.clone(),
        env.rng.clone(),
        Some(emitter.clone()),
    ));
    let services = Services {
        groups,
        human_owner,
        human_receipt_source,
        projection_clock: Arc::default(),
        projection_resources,
        receipt_authority,
        receipt_issuer,
        projection_authority,
        external_verifiers,
        totp_keyring,
        webauthn,
        authentication_authority,

        config: Arc::new(cfg.clone()),
        store: store.clone(),
        clock: env.clock.clone(),
        rng: env.rng.clone(),
        emitter,
        snapshot: applications,
        caller_keys: Arc::new(CallerKeys::from_env(cfg, |n| std::env::var(n).ok())),
        readiness: Readiness::default(),
        store_hooks: env.store_hooks.clone(),
        registry,
        started_at: env.clock.now(),
        listeners: Arc::default(),
    };
    #[cfg(feature = "test-hooks")]
    let hooks = match (&env.hooks_addr, &env.test_clock, &env.store_hooks) {
        (Some(addr), Some(clock), Some(store_hooks)) => {
            let l = TcpListener::bind(addr)
                .await
                .context("binding test hooks listener")?;
            let a = l.local_addr()?;
            anyhow::ensure!(
                a.ip().is_loopback(),
                "test hooks must bind a loopback address"
            );
            let state = Arc::new(http::hooks::HooksState::new(
                clock.clone(),
                store_hooks.clone(),
                store.clone(),
            ));
            state.set_counter_source(Arc::new(counters::snapshot));
            Some((l, a, state))
        }
        _ => None,
    };
    let admin = match cfg.admin_addr() {
        Some(addr) => {
            let l = TcpListener::bind(addr)
                .await
                .context("binding admin listener")?;
            let a = l.local_addr()?;
            Some((l, a))
        }
        None => None,
    };
    let admin_tls = cfg
        .listen
        .admin_tls
        .as_ref()
        .map(|tls| {
            hangang_runtime::tls_config(&tls.certificate, &tls.key, &tls.client_ca, &[b"http/1.1"])
        })
        .transpose()
        .context("loading administrator mTLS")?;
    let gateway = TcpListener::bind(cfg.gateway_addr())
        .await
        .context("binding gateway listener")?;
    let gateway_addr = gateway.local_addr()?;
    let native_gateway_tls = cfg
        .listen
        .native_gateway_tls
        .as_ref()
        .map(http::native_gateway::tls_acceptor)
        .transpose()
        .context("loading native gateway mTLS")?;
    let native_gateway = match &cfg.listen.native_gateway {
        Some(value) => {
            let listener = TcpListener::bind(value)
                .await
                .context("binding native gateway")?;
            let address = listener.local_addr()?;
            Some((listener, address))
        }
        None => None,
    };
    let grpc_gateway = match &cfg.listen.grpc_gateway {
        Some(value) => {
            let settings = cfg
                .listen
                .native_gateway_tls
                .as_ref()
                .context("gRPC gateway requires mTLS")?;
            let tls = hangang_runtime::configuration(
                &settings.certificate,
                &settings.key,
                &settings.client_ca,
            )?;
            let listener = TcpListener::bind(value)
                .await
                .context("binding gRPC gateway")?;
            Some((listener, tls))
        }
        None => None,
    };
    // Once set, never changed: the status page shows what is actually bound.
    let _ = services.listeners.set(crate::admin::Listeners {
        portal: portal_addr.to_string(),
        gateway: gateway_addr.to_string(),
        admin: admin.as_ref().map(|a| a.1.to_string()).unwrap_or_default(),
        native_gateway: native_gateway.as_ref().map(|a| a.1.to_string()),
        grpc_gateway: grpc_gateway
            .as_ref()
            .map(|a| a.0.local_addr().unwrap().to_string()),
    });
    match &admin {
        Some((_, a)) => tracing::info!(
            "listeners bound: portal {portal_addr}, gateway {gateway_addr}, admin {a}"
        ),
        None => tracing::info!("listeners bound: portal {portal_addr}, gateway {gateway_addr}"),
    }
    services
        .registry
        .publish_prepared(
            &store,
            crate::store::Deadline(std::time::Instant::now() + Duration::from_secs(5)),
        )
        .await
        .context("publishing native provider owners")?;
    Ok(Bound {
        admin_tls,
        grpc_gateway,
        native_gateway,
        native_gateway_tls,
        portal,
        gateway,
        admin,
        portal_addr,
        gateway_addr,
        services,
        wiring: EventWiring {
            rx,
            sampler,
            trigger,
        },
        _lock: instance_lock,
        #[cfg(feature = "test-hooks")]
        hooks,
    })
}

// ---------------------------------------------------------------------------
// run
// ---------------------------------------------------------------------------

/// How long in-flight requests get to finish after the stop signal.
pub const DRAIN: Duration = Duration::from_secs(5);

impl Bound {
    pub fn native_gateway_addr(&self) -> Option<SocketAddr> {
        self.native_gateway.as_ref().map(|v| v.1)
    }
    pub fn portal_addr(&self) -> SocketAddr {
        self.portal_addr
    }

    pub fn gateway_addr(&self) -> SocketAddr {
        self.gateway_addr
    }

    /// Address of the admin listener, when `admin.public_url` is set.
    pub fn admin_addr(&self) -> Option<SocketAddr> {
        self.admin.as_ref().map(|a| a.1)
    }

    /// Address of the test-hooks listener, when enabled (feature `test-hooks` and `HOPAE_TEST_HOOKS`).
    pub fn hooks_addr(&self) -> Option<SocketAddr> {
        #[cfg(feature = "test-hooks")]
        return self.hooks.as_ref().map(|h| h.1);
        #[cfg(not(feature = "test-hooks"))]
        None
    }

    pub fn store(&self) -> &Store {
        &self.services.store
    }

    pub fn clock(&self) -> &Arc<dyn Clock> {
        &self.services.clock
    }

    pub fn rng(&self) -> &Arc<dyn Rng> {
        &self.services.rng
    }

    pub fn services(&self) -> &Services {
        &self.services
    }

    /// Serve both listeners until `shutdown` completes, then drain gracefully.
    pub async fn run(
        self,
        shutdown: impl Future<Output = ()> + Send + 'static,
    ) -> anyhow::Result<()> {
        let routers = build_routers(&self.services)?;
        self.run_with(routers, shutdown).await
    }

    /// As [`Bound::run`] with the routers supplied by the caller.
    pub async fn run_with(
        self,
        routers: Routers,
        shutdown: impl Future<Output = ()> + Send + 'static,
    ) -> anyhow::Result<()> {
        let cfg = self.services.config.clone();
        let (stop_tx, stop_rx) = watch::channel(false);
        let (bg_tx, bg_rx) = watch::channel(false);

        // Background workers: diagnostics, delivery, pruning, retention sweep.
        let events = self.services.events();
        let mut workers = Vec::new();
        let retention = EventRetention {
            retention: Duration::from_secs(u64::from(cfg.events.retention_days) * 86_400),
            max_rows: cfg.events.max_rows,
            prune_every: cfg.events.prune_every,
            max_pending_per_sink: cfg.events.max_pending_per_sink,
            terminal_retention: Duration::from_secs(
                u64::from(cfg.events.delivery_terminal_retention_days) * 86_400,
            ),
        };
        // The store's writer enforces the same policy inline (ADR-0009: the
        // bound must not depend on when the prune task gets to run).
        self.services.store.set_event_retention(retention.clone());
        self.services
            .store
            .set_diagnostic_log(Arc::new(LogSink::stderr(None)));
        self.services
            .store
            .set_drop_counts(self.services.emitter.drops().clone());
        let pruner = Pruner::new(
            events.clone(),
            self.services.clock.clone(),
            retention,
            self.wiring.trigger.clone(),
            cfg.event_sinks(),
        );
        workers.push(tokio::spawn(
            DiagnosticWriter {
                store: self.services.store.clone(),
                events: events.clone(),
                rx: self.wiring.rx,
                drops: self.services.emitter.drops().clone(),
                sampler: self.wiring.sampler,
                clock: self.services.clock.clone(),
                rng: self.services.rng.clone(),
                trigger: self.wiring.trigger.clone(),
                pruner: Some(pruner.clone()),
                hooks: self.services.store_hooks.clone(),
            }
            .run(bg_rx.clone()),
        ));
        let sink: Arc<dyn Sink> = Arc::new(LogSink::stderr(self.services.store_hooks.clone()));
        workers.push(tokio::spawn(
            DeliveryWorker::new(events.clone(), sink, self.services.clock.clone())
                .run(bg_rx.clone()),
        ));
        workers.push(tokio::spawn(pruner.run(bg_rx.clone())));
        workers.push(tokio::spawn(self.services.groups.clone().run(
            self.services.directory(),
            self.services.registry.clone(),
            bg_rx.clone(),
        )));
        workers.push(tokio::spawn(
            Sweeper::new(
                self.services.sessions(),
                self.services.clock.clone(),
                Duration::from_secs(u64::from(cfg.sessions.retention_days) * 86_400),
            )
            .run(bg_rx.clone()),
        ));

        // Servers.
        tokio::spawn(async move {
            shutdown.await;
            let _ = stop_tx.send(true);
        });
        let wait = |mut rx: watch::Receiver<bool>| async move {
            let _ = rx.wait_for(|stop| *stop).await;
        };
        let grpc_router = routers.gateway.clone();
        let grpc_keys = self.services.caller_keys.clone();
        let grpc_stop = stop_rx.clone();
        let grpc_services = self.services.clone();
        let grpc = async {
            match self.grpc_gateway {
                Some((listener, tls)) => {
                    http::grpc_gateway::serve_with_receipts(
                        listener,
                        tls,
                        grpc_router,
                        grpc_keys,
                        grpc_stop,
                        Some(grpc_services),
                    )
                    .await
                }
                None => Ok(()),
            }
        };
        let native_router = routers.gateway.clone();
        let native_keys = self.services.caller_keys.clone();
        let native_stop = stop_rx.clone();
        let native = async {
            match self.native_gateway {
                Some((listener, _)) => {
                    http::native_gateway::serve_with_tls(
                        listener,
                        native_router,
                        native_keys,
                        native_stop,
                        self.native_gateway_tls,
                    )
                    .await
                }
                None => Ok(()),
            }
        };
        // Connect info: the portal's trusted-proxy rule needs the TCP peer.
        let portal = axum::serve(
            self.portal,
            routers
                .portal
                .into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(wait(stop_rx.clone()));
        let gateway = axum::serve(
            self.gateway,
            routers
                .gateway
                .into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(wait(stop_rx.clone()));
        let admin = async {
            match (self.admin, routers.admin) {
                (Some((l, _)), Some(router)) => {
                    if let Some(tls) = self.admin_tls {
                        http::admin_tls::serve(l, tls, router, wait(stop_rx.clone())).await
                    } else {
                        axum::serve(
                            l,
                            router.into_make_service_with_connect_info::<SocketAddr>(),
                        )
                        .with_graceful_shutdown(wait(stop_rx.clone()))
                        .await
                        .map_err(anyhow::Error::from)
                    }
                }
                _ => Ok::<(), anyhow::Error>(()),
            }
        };
        #[cfg(feature = "test-hooks")]
        let hooks = async {
            match self.hooks {
                Some((l, _, state)) => {
                    axum::serve(l, http::hooks::router(state))
                        .with_graceful_shutdown(wait(stop_rx.clone()))
                        .await
                }
                None => Ok(()),
            }
        };
        #[cfg(not(feature = "test-hooks"))]
        let hooks = async { Ok::<(), std::io::Error>(()) };

        self.services.readiness.set(true);
        let servers = async { tokio::join!(portal, gateway, admin, hooks, native, grpc) };
        tokio::pin!(servers);
        // Serve until the stop signal, then give in-flight requests DRAIN to finish.
        let mut stopped = stop_rx.clone();
        let finished = tokio::select! {
            r = &mut servers => Some(r),
            _ = stopped.wait_for(|s| *s) => None,
        };
        let served = match finished {
            Some(r) => Some(r),
            None => match tokio::time::timeout(DRAIN, &mut servers).await {
                Ok(r) => Some(r),
                Err(_) => {
                    tracing::warn!("drain deadline reached; closing remaining connections");
                    None
                }
            },
        };
        self.services.readiness.set(false);

        // Stop the workers (they flush on the way out), wait, checkpoint.
        let _ = bg_tx.send(true);
        for w in workers {
            if tokio::time::timeout(DRAIN, w).await.is_err() {
                tracing::warn!("a background worker did not stop in time");
            }
        }
        let _ = self.services.store.barrier().await;
        let store = self.services.store.clone();
        let _ = tokio::task::spawn_blocking(move || {
            store
                .conn()
                .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))
        })
        .await;
        tracing::info!("shutdown complete");

        if let Some((p, g, a, h, n, grpc)) = served {
            grpc.context("gRPC gateway listener")?;
            p.context("portal listener")?;
            g.context("gateway listener")?;
            a.context("admin listener")?;
            h.context("test hooks listener")?;
            n.context("native gateway listener")?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Signals
// ---------------------------------------------------------------------------

/// Signal handlers, installed before the process announces itself so that a
/// signal sent right after start is never handled by the default action.
pub struct Signals {
    term: tokio::signal::unix::Signal,
    int: tokio::signal::unix::Signal,
    hup: tokio::signal::unix::Signal,
}

impl Signals {
    pub fn install() -> std::io::Result<Signals> {
        use tokio::signal::unix::{SignalKind, signal};
        Ok(Signals {
            term: signal(SignalKind::terminate())?,
            int: signal(SignalKind::interrupt())?,
            hup: signal(SignalKind::hangup())?,
        })
    }

    /// Completes on SIGTERM or SIGINT. SIGHUP is logged and otherwise ignored:
    /// configuration reload arrives in M6.
    pub async fn shutdown(mut self) {
        loop {
            tokio::select! {
                _ = self.term.recv() => return,
                _ = self.int.recv() => return,
                _ = self.hup.recv() => tracing::warn!("SIGHUP received: reload not supported; restart"),
            }
        }
    }
}

/// Completes on SIGINT or SIGTERM.
pub async fn shutdown_signal() {
    match Signals::install() {
        Ok(s) => s.shutdown().await,
        Err(e) => tracing::error!("cannot install signal handlers: {e}"),
    }
}

// ---------------------------------------------------------------------------
// `hopae providers import`
// ---------------------------------------------------------------------------

/// The ADR-0010 import outside a running server. With `force`, the file entry
/// replaces the stored row even where the database is authoritative or the
/// provider was removed, and an administrator event is recorded.
pub async fn import_providers_cli(
    cfg: &Config,
    force: Option<&str>,
) -> anyhow::Result<ImportReport> {
    let env = env();
    let store_path = cfg.store_path();
    // No instance lock: a running instance is fine, SQLite serializes the write.
    let store = {
        let p = store_path.clone();
        let (clock, hooks, sinks) = (
            env.clock.clone(),
            env.store_hooks.clone(),
            cfg.event_sinks(),
        );
        tokio::task::spawn_blocking(move || Store::open(&p, clock, sinks, hooks))
            .await
            .context("store open task")?
            .with_context(|| format!("opening store {}", store_path.display()))?
    };
    store.set_rng(env.rng.clone());
    let rows = provider_rows(cfg);
    let force_id = match force {
        Some(id) => {
            anyhow::ensure!(
                rows.iter().any(|r| r.provider_id.as_str() == id),
                "provider {id} is not listed in the configuration file"
            );
            Some(ProviderId::new(id))
        }
        None => None,
    };
    let mut events = Vec::new();
    if let Some(id) = &force_id {
        events.push(
            crate::event::types::EventBuilder::new(
                &*env.clock,
                &*env.rng,
                EventKind::AdminProvidersImport,
                Outcome::Info,
                "admin-cli",
            )
            .reason(reasons::ADMIN)
            .provider(id)
            .attr("label", "providers import --force")
            .build(),
        );
    }
    let report = store
        .directory()
        .import_providers(rows, force_id.as_ref(), events)
        .await
        .context("importing providers")?;
    store.barrier().await.ok();
    let s = store.clone();
    let _ = tokio::task::spawn_blocking(move || {
        s.conn()
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))
    })
    .await;
    Ok(report)
}

// ---------------------------------------------------------------------------
// hopae admin: grants from the command line, the file import, the start import
// ---------------------------------------------------------------------------

/// What a `hopae admin` command printed and how it ended. An operator
/// refusal (bad argument, unknown or unsuitable user) is `code 2`; the store
/// refusing the database is an error the caller maps to `2` as well.
#[derive(Debug, Default)]
pub struct AdminCliOutput {
    pub stdout: String,
    pub stderr: String,
    pub code: u8,
    /// Write `stdout` to the terminal at each [`AdminCliOutput::emit`] instead
    /// of holding it until the command ends.
    pub live: bool,
}

impl AdminCliOutput {
    /// A live run prints what is buffered now and flushes it; otherwise the
    /// text stays for the caller to print (tests read it whole).
    fn emit(&mut self) -> std::io::Result<()> {
        if self.live {
            use std::io::Write as _;
            let mut so = std::io::stdout().lock();
            so.write_all(self.stdout.as_bytes())?;
            so.flush()?;
            self.stdout.clear();
        }
        Ok(())
    }

    fn out(&mut self, line: impl AsRef<str>) {
        self.stdout.push_str(line.as_ref());
        self.stdout.push('\n');
    }

    fn warn(&mut self, line: impl AsRef<str>) {
        self.stderr.push_str("warning: ");
        self.stderr.push_str(line.as_ref());
        self.stderr.push('\n');
    }

    fn refuse(mut self, msg: impl AsRef<str>) -> Self {
        self.stderr.push_str("error: ");
        self.stderr.push_str(msg.as_ref());
        self.stderr.push('\n');
        self.code = EXIT_CONFIG;
        self
    }
}

/// A `hopae admin` command as parsed from the command line.
#[derive(Debug, Clone)]
pub enum AdminCommand {
    Grant {
        target: String,
        role: crate::store::AdminRole,
        note: Option<String>,
        confirm: Option<String>,
    },
    Revoke {
        target: String,
    },
    List {
        all: bool,
    },
    Import {
        force: Option<String>,
    },
    /// `hopae admin factors list <target>` (ADR-0017).
    FactorsList {
        target: String,
    },
    /// `hopae admin factors reset <target>` (ADR-0017).
    FactorsReset {
        target: String,
    },
    /// `hopae admin service-credentials …`.
    ServiceCredential(ServiceCredentialCommand),
}

/// `hopae admin service-credentials` actions.
#[derive(Clone, Debug)]
pub enum ServiceCredentialCommand {
    Create {
        id: String,
        routes: Vec<String>,
        /// `pumgye-v2`: the four projection/lifecycle read routes.
        preset: Option<String>,
        audiences: Vec<String>,
        client_spki_sha256: Option<String>,
        client_san: Option<String>,
        expires_in_days: u32,
        rate_per_minute: u32,
        burst: u32,
        note: Option<String>,
    },
    /// Issue a next secret (current and next are both accepted).
    Rotate {
        id: String,
    },
    /// Make the next secret current; the old current stops working.
    Promote {
        id: String,
    },
    Revoke {
        id: String,
    },
    List,
}

/// `hopae admin service-credentials …`: the secret is printed once and only
/// its digest is stored; every change commits with `admin.service_credential`.
async fn service_credential_cli(
    cfg: &Config,
    cmd: ServiceCredentialCommand,
    mut out: AdminCliOutput,
) -> anyhow::Result<AdminCliOutput> {
    use crate::admin::service_credentials as sc;
    use crate::store::sqlite::service_credentials::{Change, ServiceCredentialRow};
    let id_of = |c: &ServiceCredentialCommand| match c {
        ServiceCredentialCommand::Create { id, .. }
        | ServiceCredentialCommand::Rotate { id }
        | ServiceCredentialCommand::Promote { id }
        | ServiceCredentialCommand::Revoke { id } => Some(id.clone()),
        ServiceCredentialCommand::List => None,
    };
    if let Some(id) = id_of(&cmd)
        && !sc::valid_id(&id)
    {
        return Ok(out.refuse("credential id: 3-48 lowercase letters, digits and inner '-'"));
    }
    let env = env();
    let audience_default = cfg
        .admin
        .service_audience
        .clone()
        .or_else(|| cfg.admin_origin().map(|o| o.ascii_serialization()));
    let mut validated = None;
    if let ServiceCredentialCommand::Create {
        id,
        routes,
        preset,
        audiences,
        client_spki_sha256,
        client_san,
        expires_in_days,
        rate_per_minute,
        burst,
        note,
    } = &cmd
    {
        let mut routes = routes.clone();
        match preset.as_deref() {
            None => {}
            Some("pumgye-v2") => routes.extend(sc::PUMGYE_V2_ROUTES.iter().map(|s| s.to_string())),
            Some(_) => return Ok(out.refuse("--preset: only pumgye-v2 is defined")),
        }
        routes.sort();
        routes.dedup();
        if routes.is_empty() || routes.len() > sc::MAX_ROUTES {
            return Ok(out.refuse("--route: 1-32 routes (\"METHOD /path\") or --preset"));
        }
        if let Some(bad) = routes.iter().find(|r| !sc::grantable(r)) {
            return Ok(out.refuse(format!(
                "--route {bad:?}: not a read route a service credential may hold (mutations are never grantable)"
            )));
        }
        let mut audiences = if audiences.is_empty() {
            audience_default.clone().into_iter().collect::<Vec<_>>()
        } else {
            audiences.clone()
        };
        audiences.sort();
        audiences.dedup();
        if audiences.is_empty()
            || audiences.len() > sc::MAX_AUDIENCES
            || audiences
                .iter()
                .any(|a| a.is_empty() || a.len() > 256 || !a.bytes().all(|b| b.is_ascii_graphic()))
        {
            return Ok(out.refuse(
                "--audience: 1-8 audiences of visible ASCII (default the console origin)",
            ));
        }
        let spki = client_spki_sha256.as_ref().map(|s| s.to_ascii_lowercase());
        if spki
            .as_ref()
            .is_some_and(|s| s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            return Ok(out.refuse("--client-spki-sha256: 64 hex digits"));
        }
        if client_san.as_ref().is_some_and(|s| !sc::valid_san(s)) {
            return Ok(out.refuse("--client-san: 1-512 visible ASCII characters"));
        }
        if spki.is_none() && client_san.is_none() {
            return Ok(
                out.refuse("an mTLS binding is required: --client-spki-sha256 and/or --client-san")
            );
        }
        let lifetime = i64::from(*expires_in_days) * 86_400;
        if !(1..=sc::MAX_LIFETIME_SECS).contains(&lifetime) {
            return Ok(out.refuse("--expires-in-days: 1-400"));
        }
        if !(1..=6000).contains(rate_per_minute) || !(1..=1000).contains(burst) {
            return Ok(out.refuse("--rate-per-minute 1-6000, --burst 1-1000"));
        }
        if note.as_ref().is_some_and(|n| n.chars().count() > 256) {
            return Ok(out.refuse("--note: at most 256 characters"));
        }
        if cfg.listen.admin_tls.is_none() {
            out.warn("listen.admin_tls is not configured: service credentials are refused until the admin listener uses mutual TLS");
        }
        let now = env.clock.now().secs();
        let (token, digest) = crate::admin::service_credentials::mint(env.rng.as_ref(), id);
        validated = Some((
            ServiceCredentialRow {
                credential_id: id.clone(),
                routes,
                audiences,
                client_spki_sha256: spki,
                client_san: client_san.clone(),
                current_sha256: digest,
                current_since: now,
                next_sha256: None,
                next_since: None,
                expires_at: now + lifetime,
                rate_per_minute: *rate_per_minute,
                burst: *burst,
                note: note.clone(),
                created_at: now,
                revoked_at: None,
                revision: 1,
            },
            token,
        ));
    }
    let store = open_cli_store(cfg, &env).await?;
    let event = |change: &'static str, id: &str| {
        crate::event::types::EventBuilder::new(
            &*env.clock,
            &*env.rng,
            EventKind::AdminServiceCredential,
            Outcome::Success,
            "admin-cli",
        )
        .attr("actor", "cli")
        .attr("change", change)
        .attr("credential_id", id)
        .build()
    };
    let iso = |t: i64| preflight::iso_datetime(t);
    let result: crate::store::StoreResult<()> = async {
        match cmd {
            ServiceCredentialCommand::Create { id, .. } => {
                let (row, token) = validated.take().expect("validated");
                let expires = row.expires_at;
                store
                    .service_credential_create(row, vec![event("created", &id)])
                    .await?;
                out.out(token.expose());
                out.stderr.push_str(&format!(
                    "created service credential {id} (expires {}); the token above is shown once and only its digest is stored\n",
                    iso(expires)
                ));
            }
            ServiceCredentialCommand::Rotate { id } => {
                let (token, digest) = crate::admin::service_credentials::mint(env.rng.as_ref(), &id);
                store
                    .service_credential_change(id.clone(), Change::Rotate, Some(digest), vec![event("rotated", &id)])
                    .await?;
                out.out(token.expose());
                out.stderr.push_str(&format!(
                    "issued the next secret of {id}: current and next are both accepted until `promote`\n"
                ));
            }
            ServiceCredentialCommand::Promote { id } => {
                store
                    .service_credential_change(id.clone(), Change::Promote, None, vec![event("promoted", &id)])
                    .await?;
                out.out(format!("promoted the next secret of {id}; the previous secret no longer works"));
            }
            ServiceCredentialCommand::Revoke { id } => {
                store
                    .service_credential_change(id.clone(), Change::Revoke, None, vec![event("revoked", &id)])
                    .await?;
                out.out(format!("revoked service credential {id}"));
            }
            ServiceCredentialCommand::List => {
                out.out("ID  STATE  ROUTES  AUDIENCES  BINDING  EXPIRES_AT  ROTATION  RATE");
                let now = env.clock.now().secs();
                for r in store.service_credential_list().await? {
                    let state = if r.revoked_at.is_some() {
                        "revoked"
                    } else if r.expires_at <= now {
                        "expired"
                    } else {
                        "active"
                    };
                    let binding = [
                        r.client_spki_sha256.as_ref().map(|s| format!("spki:{}", &s[..16])),
                        r.client_san.as_ref().map(|s| format!("san:{s}")),
                    ]
                    .into_iter()
                    .flatten()
                    .collect::<Vec<_>>()
                    .join("+");
                    out.out(format!(
                        "{}  {}  {}  {}  {}  {}  {}  {}/min burst {}",
                        r.credential_id,
                        state,
                        r.routes.join(","),
                        r.audiences.join(","),
                        binding,
                        iso(r.expires_at),
                        if r.next_sha256.is_some() { "pending" } else { "-" },
                        r.rate_per_minute,
                        r.burst
                    ));
                }
            }
        }
        Ok(())
    }
    .await;
    match result {
        Ok(()) => Ok(out),
        Err(crate::store::StoreError::Conflict(why)) => Ok(out.refuse(why)),
        Err(e) => store_failure(&e, out),
    }
}

/// Operator-facing text for a store failure; a database error is never echoed.
fn store_failure(
    e: &crate::store::StoreError,
    out: AdminCliOutput,
) -> anyhow::Result<AdminCliOutput> {
    use crate::store::StoreError;
    match e {
        StoreError::Conflict("user_disabled") => Ok(out.refuse("user is disabled: enable first")),
        StoreError::Conflict("source_email_bound") => Ok(out.refuse(
            "the user is already bound to another address; grant by user_id (a binding is never replaced)",
        )),
        StoreError::Conflict(m) => Ok(out.refuse(m)),
        StoreError::Busy => Err(anyhow::anyhow!("the store is busy; try again")),
        StoreError::Unavailable(_) => Err(anyhow::anyhow!("the store did not answer in time")),
        StoreError::Sqlite(_) | StoreError::Corrupt(_) | StoreError::Io { .. } => {
            Err(anyhow::anyhow!("the store could not be read or written"))
        }
        other => Err(anyhow::anyhow!("{other}")),
    }
}

/// Terminal-safe text: control characters of provider-supplied strings become `?`.
fn plain(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

fn parse_target(arg: &str) -> Result<crate::store::types::GrantTarget, String> {
    use crate::store::types::GrantTarget;
    if arg.contains('@') {
        crate::identity::types::NormalizedEmail::parse(arg)
            .map(GrantTarget::Email)
            .map_err(|_| "<target>: not a valid email address".to_string())
    } else if crate::config::valid_user_id(arg) {
        Ok(GrantTarget::Id(crate::identity::types::UserId::new(arg)))
    } else {
        Err("<target>: expected a user id (u_...) or an email address".to_string())
    }
}

/// The resolution block printed before every grant.
fn resolution_block(
    user: &crate::store::types::User,
    identities: &[crate::store::types::IdentityRow],
) -> String {
    let mut s = String::new();
    let dash = |o: Option<String>| o.map_or_else(|| "-".to_string(), |v| plain(&v));
    s.push_str(&format!("user_id {}\n", user.user_id));
    s.push_str(&format!(
        "display_name {}\n",
        dash(user.display_name.clone())
    ));
    s.push_str(&format!(
        "created_at {}\n",
        preflight::iso_datetime(user.created_at.secs())
    ));
    s.push_str(&format!(
        "last_login_at {}\n",
        dash(
            user.last_login_at
                .map(|t| preflight::iso_datetime(t.secs()))
        )
    ));
    let email = match &user.primary_email {
        None => "(none)".to_string(),
        Some(e) => {
            let state = if !user.email_verified {
                "unverified"
            } else if user.email_authoritative {
                "verified, authoritative"
            } else {
                "verified, not authoritative"
            };
            format!("{e} ({state})")
        }
    };
    s.push_str(&format!("primary_email {email}\n"));
    let ids: Vec<String> = identities
        .iter()
        .map(|i| plain(&format!("{}:{}", i.provider_id, i.subject)))
        .collect();
    s.push_str(&format!(
        "identities {}\n",
        if ids.is_empty() {
            "-".to_string()
        } else {
            ids.join(", ")
        }
    ));
    s
}

fn cli_event(
    env: &Env,
    kind: EventKind,
    user: &crate::identity::types::UserId,
    role: crate::store::AdminRole,
) -> crate::event::types::Event {
    crate::event::types::EventBuilder::new(&*env.clock, &*env.rng, kind, Outcome::Info, "admin-cli")
        .reason(reasons::ADMIN)
        .user(user)
        .attr("actor", "cli")
        .attr("role", role.as_str())
        .attr("managed_by", "api")
        .build()
}

/// Open the store as a command-line administrator: precheck, no lock, no
/// migration, no backup.
async fn open_cli_store(cfg: &Config, env: &Env) -> anyhow::Result<Store> {
    let path = cfg.store_path();
    let (clock, sinks) = (env.clock.clone(), cfg.event_sinks());
    let p = path.clone();
    let store = tokio::task::spawn_blocking(move || Store::open_cli(&p, clock, sinks))
        .await
        .context("store open task")?
        .with_context(|| format!("opening store {}", path.display()))?;
    store.set_rng(env.rng.clone());
    Ok(store)
}

/// `hopae admin grant|revoke|list|import`. Arguments are validated before the
/// store is opened; nothing is written for a refused command.
pub async fn admin_cli(cfg: &Config, cmd: AdminCommand) -> anyhow::Result<AdminCliOutput> {
    admin_cli_with(cfg, cmd, false).await
}

/// [`admin_cli`] with `live` output: the grant's resolution block reaches the
/// terminal before the grant is written (ADR-0016 decision 6), not when the
/// command ends. The returned `stdout` then holds only what was not yet printed.
pub async fn admin_cli_with(
    cfg: &Config,
    cmd: AdminCommand,
    live: bool,
) -> anyhow::Result<AdminCliOutput> {
    use crate::store::types::{Deadline, GrantTarget};
    use crate::store::{AdminRole, GrantManagedBy};
    let mut out = AdminCliOutput {
        live,
        ..AdminCliOutput::default()
    };
    if let AdminCommand::ServiceCredential(c) = cmd {
        return service_credential_cli(cfg, c, out).await;
    }
    // Validation first.
    let parsed_target = match &cmd {
        AdminCommand::Grant { target, .. }
        | AdminCommand::Revoke { target }
        | AdminCommand::FactorsList { target }
        | AdminCommand::FactorsReset { target } => match parse_target(target) {
            Ok(t) => Some(t),
            Err(m) => return Ok(out.refuse(m)),
        },
        _ => None,
    };
    if let AdminCommand::Grant { note, confirm, .. } = &cmd {
        if let Some(n) = note
            && n.chars().count() > crate::admin::seed::NOTE_MAX_CHARS
        {
            return Ok(out.refuse(format!(
                "--note: longer than {} characters",
                crate::admin::seed::NOTE_MAX_CHARS
            )));
        }
        if let Some(c) = confirm
            && !crate::config::valid_user_id(c)
        {
            return Ok(out.refuse("--confirm: expected a user id (u_...)"));
        }
    }
    let force = match &cmd {
        AdminCommand::Import { force: Some(f) } => match crate::admin::seed::force_target(f) {
            Ok(t) => Some(t),
            Err(m) => return Ok(out.refuse(m)),
        },
        _ => None,
    };

    let env = env();
    let store = open_cli_store(cfg, &env).await?;
    let dir = store.directory();
    let dl = || Deadline::after(Duration::from_secs(30));
    let result: crate::store::StoreResult<()> = async {
        match cmd {
            AdminCommand::ServiceCredential(_) => unreachable!("handled above"),
            AdminCommand::Grant {
                role,
                note,
                confirm,
                ..
            } => {
                let target = parsed_target.expect("validated");
                let found = dir.resolve_grant_target(&target, dl()).await?;
                // Only the domain is case-normalized (ADR-0011): the local part
                // is compared exactly, never guessed across case.
                let Some((user, identities)) = found else {
                    out.stderr
                        .push_str("error: no such user: sign in once first\n");
                    out.code = EXIT_CONFIG;
                    return Ok(());
                };
                out.stdout.push_str(&resolution_block(&user, &identities));
                // The evidence is on the terminal before anything is written.
                if let Err(e) = out.emit() {
                    // The operator decides on this evidence: without it, no write.
                    out.stderr.push_str(&format!(
                        "error: the resolution evidence could not be written ({e}); nothing was granted\n"
                    ));
                    out.code = EXIT_CONFIG;
                    return Ok(());
                }
                // The binding records the address as the store holds it.
                let email = match &target {
                    GrantTarget::Email(_) => user.primary_email.clone(),
                    GrantTarget::Id(_) => None,
                };
                if let Some(e) = &email {
                    if !user.email_verified {
                        out.stderr.push_str("error: email not verified\n");
                        out.code = EXIT_CONFIG;
                        return Ok(());
                    }
                    let _ = e;
                }
                if user.status != crate::store::UserStatus::Active {
                    out.stderr
                        .push_str("error: user is disabled: enable first\n");
                    out.code = EXIT_CONFIG;
                    return Ok(());
                }
                if let Some(new) = &email
                    && let Some(old) = dir
                        .admin_grant(&user.user_id, dl())
                        .await?
                        .and_then(|g| g.source_email)
                    && &old != new
                {
                    out.stderr.push_str(&format!(
                        "error: {} is already bound to {old}; grant by user_id (a binding is never replaced)\n",
                        user.user_id
                    ));
                    out.code = EXIT_CONFIG;
                    return Ok(());
                }
                if let Some(c) = &confirm
                    && c != user.user_id.as_str()
                {
                    out.stderr.push_str(&format!(
                        "error: --confirm names {c} but the {} resolves to {}\n",
                        if email.is_some() { "address" } else { "target" },
                        user.user_id
                    ));
                    out.code = EXIT_CONFIG;
                    return Ok(());
                }
                if let Some(e) = &email
                    && !user.email_authoritative
                    && confirm.is_none()
                {
                    out.stderr.push_str(&format!(
                        "error: refusing: {e} is verified but not authoritative; re-run with --confirm {} if this is the intended person\n",
                        user.user_id
                    ));
                    out.code = EXIT_CONFIG;
                    return Ok(());
                }
                let at = env.clock.now();
                let ev = cli_event(&env, EventKind::AdminGrant, &user.user_id, role);
                let (_, changed) = dir
                    .grant_admin(
                        &user.user_id,
                        role,
                        GrantManagedBy::Api,
                        email,
                        "cli",
                        note.as_deref().and_then(crate::admin::seed::sanitize_note),
                        at,
                        ev,
                    )
                    .await?;
                if changed {
                    out.out(format!("granted {} to {}", role.as_str(), user.user_id));
                } else {
                    out.out("unchanged");
                }
            }
            AdminCommand::Revoke { .. } => {
                let target = parsed_target.expect("validated");
                // An address names the row bound through it before any resolution.
                let user_id = match &target {
                    GrantTarget::Id(u) => Some(u.clone()),
                    GrantTarget::Email(e) => {
                        let bound: Vec<_> = dir
                            .admin_grants(true, dl())
                            .await?
                            .into_iter()
                            .filter(|g| g.source_email.as_ref() == Some(e) && g.revoked_at.is_none())
                            .collect();
                        match bound.len() {
                            0 => dir
                                .resolve_grant_target(&target, dl())
                                .await?
                                .map(|(u, _)| u.user_id),
                            1 => Some(bound[0].user_id.clone()),
                            _ => {
                                out.stderr.push_str(
                                    "error: ambiguous binding; use the user id\n",
                                );
                                out.code = EXIT_CONFIG;
                                return Ok(());
                            }
                        }
                    }
                };
                let Some(user_id) = user_id else {
                    out.stderr
                        .push_str("error: no such user: sign in once first\n");
                    out.code = EXIT_CONFIG;
                    return Ok(());
                };
                match dir.admin_grant(&user_id, dl()).await? {
                    None => out.out(format!("no grant for {user_id}")),
                    Some(g) if g.revoked_at.is_some() => out.out("already revoked"),
                    Some(g) => {
                        let at = env.clock.now();
                        let ev = cli_event(&env, EventKind::AdminRevoke, &user_id, g.role);
                        if dir
                            .revoke_admin(&user_id, "cli", GrantManagedBy::Api, at, ev)
                            .await?
                        {
                            out.out(format!("revoked {} from {user_id}", g.role.as_str()));
                        } else {
                            out.out("already revoked");
                        }
                    }
                }
            }
            AdminCommand::List { all } => {
                let grants = dir.admin_grants(all, dl()).await?;
                if grants.is_empty() {
                    return Ok(());
                }
                out.out("USER_ID  EMAIL  ROLE  MANAGED_BY  GRANTED_AT  GRANTED_BY  NOTE");
                for g in grants {
                    let email = match &g.source_email {
                        Some(e) => Some(e.to_string()),
                        None => dir
                            .resolve_grant_target(&GrantTarget::Id(g.user_id.clone()), dl())
                            .await?
                            .and_then(|(u, _)| u.primary_email)
                            .map(|e| e.to_string()),
                    };
                    let mut line = format!(
                        "{}  {}  {}  {}  {}  {}  {}",
                        g.user_id,
                        plain(email.as_deref().unwrap_or("-")),
                        g.role.as_str(),
                        g.managed_by.as_str(),
                        preflight::iso_datetime(g.granted_at.secs()),
                        plain(&g.granted_by),
                        plain(g.note.as_deref().unwrap_or("-")),
                    );
                    if let Some(at) = g.revoked_at {
                        line.push_str(&format!(
                            "  revoked {} by {}",
                            preflight::iso_datetime(at.secs()),
                            plain(g.revoked_by.as_deref().unwrap_or("-"))
                        ));
                    }
                    out.out(line);
                }
            }
            AdminCommand::FactorsList { .. } | AdminCommand::FactorsReset { .. } => {
                use crate::store::Passkeys;
                let reset = matches!(cmd, AdminCommand::FactorsReset { .. });
                let target = parsed_target.expect("validated");
                let Some((user, _)) = dir.resolve_grant_target(&target, dl()).await? else {
                    out.stderr.push_str("error: no such user\n");
                    out.code = EXIT_CONFIG;
                    return Ok(());
                };
                let summary = store.factor_summary(&user.user_id).await?;
                if reset {
                    let ev = crate::event::types::EventBuilder::new(
                        &*env.clock,
                        &*env.rng,
                        EventKind::AdminFactorReset,
                        Outcome::Success,
                        "admin-cli",
                    )
                    .reason(reasons::FACTOR_RESET)
                    .user(&user.user_id)
                    .attr("actor", "cli")
                    .build();
                    let report = store.reset_factors(&user.user_id, "admin-cli", vec![ev]).await?;
                    out.out(format!(
                        "reset {}: {} passkey(s), {} authenticator app(s), {} recovery code(s) revoked; {} session(s) ended",
                        user.user_id, report.passkeys, report.totp, report.recovery_codes, report.sessions
                    ));
                } else {
                    out.out(format!("user_id {}", user.user_id));
                    out.out(format!(
                        "authenticator_app {}",
                        if summary.totp_active { "active" } else { "-" }
                    ));
                    out.out(format!(
                        "recovery_codes {} unused{}",
                        summary.recovery_unused,
                        if summary.recovery_required_at.is_some() {
                            " (a code was used: re-enrollment required)"
                        } else {
                            ""
                        }
                    ));
                    out.out("PASSKEY_ID  LABEL  KIND  CLASS  CREATED_AT  LAST_USED_AT");
                    for p in &summary.passkeys {
                        out.out(format!(
                            "{}  {}  {}  {}  {}  {}",
                            crate::store::sqlite::webauthn::factor_id(&p.credential_id),
                            plain(&p.label),
                            if p.backup_eligible { "synced" } else { "device-bound" },
                            p.assurance.as_str(),
                            preflight::iso_datetime(p.created_at.secs()),
                            p.last_used_at
                                .map(|t| preflight::iso_datetime(t.secs()))
                                .unwrap_or_else(|| "-".into()),
                        ));
                    }
                }
            }
            AdminCommand::Import { .. } => {
                let seed = crate::admin::seed::entries(cfg.admin_user_entries());
                for (i, why) in &seed.malformed {
                    out.warn(format!("admin.users[{i}]: {why}"));
                }
                let forced = force.is_some();
                let report = crate::admin::seed::run_import(
                    &*dir,
                    seed.entries.clone(),
                    force,
                    &*env.clock,
                    &*env.rng,
                    "admin-cli",
                )
                .await?;
                let grants = dir.admin_grants(true, dl()).await?;
                let list = |v: &[crate::identity::types::UserId]| {
                    v.iter().map(|u| u.to_string()).collect::<Vec<_>>().join(", ")
                };
                out.out("admin grants imported");
                out.out(format!("  inserted: {}", list(&report.inserted)));
                out.out(format!("  updated: {}", list(&report.updated)));
                out.out(format!("  revoked: {}", list(&report.revoked)));
                out.out(format!("  unchanged: {}", list(&report.unchanged)));
                out.out(format!("  forced: {}", list(&report.forced)));
                let mut reasons_seen: Vec<&'static str> = Vec::new();
                for (_, r) in &report.skipped {
                    if !reasons_seen.contains(r) {
                        reasons_seen.push(r);
                    }
                }
                for reason in reasons_seen {
                    let labels: Vec<String> = report
                        .skipped
                        .iter()
                        .filter(|(_, r)| *r == reason)
                        .filter_map(|(i, _)| seed.entries.iter().find(|e| e.index == *i))
                        .map(|e| crate::admin::seed::skip_label(e, &grants))
                        .collect();
                    out.out(format!(
                        "  skipped ({}): {}",
                        crate::admin::seed::skip_text(reason),
                        labels.join(", ")
                    ));
                }
                for w in crate::admin::seed::report_warnings(&report, &seed.entries, &grants, false)
                {
                    out.warn(w);
                }
                if forced && report.forced.is_empty() {
                    out.warn("--force matched no file entry");
                }
            }
        }
        Ok(())
    }
    .await;
    let _ = AdminRole::Admin;
    store.barrier().await.ok();
    match result {
        Ok(()) => Ok(out),
        Err(e) => store_failure(&e, out),
    }
}

/// The grant import at start (decision 13): after the provider import, before
/// the listeners bind. A defective entry is a warning; the file's removals are
/// applied; a store failure is a start failure.
async fn import_admin_grants_at_start(
    cfg: &Config,
    directory: &dyn Directory,
    env: &Env,
) -> anyhow::Result<()> {
    use crate::store::types::Deadline;
    let seed = crate::admin::seed::entries(cfg.admin_user_entries());
    for (i, why) in &seed.malformed {
        tracing::warn!("admin.users[{i}]: {why}");
    }
    let report = crate::admin::seed::run_import(
        directory,
        seed.entries.clone(),
        None,
        &*env.clock,
        &*env.rng,
        "startup",
    )
    .await
    .context("importing administrator grants")?;
    let grants = if report.skipped.is_empty() && report.rebound_warnings.is_empty() {
        Vec::new()
    } else {
        directory
            .admin_grants(true, Deadline::after(Duration::from_secs(30)))
            .await
            .context("reading administrator grants")?
    };
    for w in crate::admin::seed::report_warnings(&report, &seed.entries, &grants, true) {
        tracing::warn!("{w}");
    }
    for (outcome, n) in [
        ("inserted", report.inserted.len()),
        ("updated", report.updated.len()),
        ("revoked", report.revoked.len()),
        ("unchanged", report.unchanged.len()),
        ("skipped", report.skipped.len()),
    ] {
        if n > 0 {
            counters::add(
                counters::ADMIN_GRANTS_IMPORTED_TOTAL,
                &[("outcome", outcome)],
                n as u64,
            );
        }
    }
    if !(seed.entries.is_empty() && report.revoked.is_empty() && seed.malformed.is_empty()) {
        tracing::info!(
            "admin.users: inserted {}, updated {}, revoked {}, skipped {}",
            report.inserted.len(),
            report.updated.len(),
            report.revoked.len(),
            report.skipped.len()
        );
    }
    Ok(())
}

/// `hopae --check`: the provider rows of an existing, migrated store (empty
/// without one), so the report can show the stored `reauth` capability.
pub async fn check_stored_providers(cfg: &Config) -> Vec<crate::store::types::ProviderRow> {
    if !cfg.store_path().exists() {
        return Vec::new();
    }
    let env = env();
    match open_cli_store(cfg, &env).await {
        Ok(store) => store.directory().providers().await.unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

/// `hopae --check`: what resolving `admin.users[]` against an existing store
/// would complain about. Without entries, without a store, or with a store an
/// instance has not migrated yet, there is nothing to say.
pub async fn admin_check_warnings(cfg: &Config) -> Vec<String> {
    use crate::store::types::Deadline;
    let seed = crate::admin::seed::entries(cfg.admin_user_entries());
    if seed.entries.is_empty() || !cfg.store_path().exists() {
        return Vec::new();
    }
    let env = env();
    let store = match open_cli_store(cfg, &env).await {
        Ok(s) => s,
        Err(e) => {
            return match e
                .chain()
                .find_map(|c| c.downcast_ref::<crate::store::StoreError>())
            {
                Some(crate::store::StoreError::SchemaTooOld { .. }) => Vec::new(),
                Some(other) => vec![format!("admin.users: store not inspected: {other}")],
                None => vec!["admin.users: store not inspected".to_string()],
            };
        }
    };
    let dir = store.directory();
    match crate::admin::seed::preview(
        &*dir,
        &seed.entries,
        Deadline::after(Duration::from_secs(10)),
    )
    .await
    {
        Ok(w) => w,
        Err(_) => vec!["admin.users: store not inspected".to_string()],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn actual_builder_dedicated_material_key_is_optional_stable_and_read_once() {
        let dir = tempfile::tempdir().unwrap();
        let value = serde_json::json!({"state_dir":dir.path().join("state"),"listen":{"portal":"127.0.0.1:0","gateway":"127.0.0.1:0"},"portal":{"public_url":"https://auth.example.test"},"gateway":{"kind":"hangang","caller_key_env":"OWNED_CALLER"},"human_material_key_env":"OWNED_MATERIAL_KEY","providers":[{"provider_id":"owned","kind":"oidc","client_id":"owned","client_secret_env":"OWNED_PROVIDER_SECRET","issuer":"https://127.0.0.1:1","allow_private_endpoints":true}],"apps":[{"app_id":"orders","hosts":["orders.example.test"]}]});
        for key in [
            None,
            Some("weak".to_owned()),
            Some(data_encoding::BASE64URL_NOPAD.encode(&[0x68; 32])),
            Some(data_encoding::BASE64URL_NOPAD.encode(&[0x68; 32])),
            Some(data_encoding::BASE64URL_NOPAD.encode(&[0x69; 32])),
        ] {
            let owned = tempfile::tempdir_in(dir.path()).unwrap();
            let mut value = value.clone();
            value["state_dir"] = serde_json::json!(owned.path().join("state"));
            let cfg = crate::config::parse(&value.to_string()).unwrap();
            let reads = std::sync::atomic::AtomicUsize::new(0);
            let bound = bind_environment(&cfg, &|name| {
                if name == "OWNED_MATERIAL_KEY" {
                    reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    key.clone()
                } else {
                    Some("actual-builder-owned-material".into())
                }
            })
            .await
            .unwrap();
            assert_eq!(reads.load(std::sync::atomic::Ordering::SeqCst), 1);
            assert!(
                bound
                    .services
                    .registry
                    .get(&ProviderId::new("owned"))
                    .unwrap()
                    .enabled()
            );
            let count: i64 = bound
                .services
                .store
                .conn()
                .query_row(
                    "SELECT count(*) FROM human_provider_material_owners",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            if key.as_ref().is_none_or(|v| v.len() != 43) {
                assert_eq!(count, 0);
            } else {
                let revision:i64=bound.services.store.conn().query_row("SELECT revision FROM human_provider_material_owners WHERE provider_id='owned'",[],|r|r.get(0)).unwrap();
                assert_eq!(revision, 1);
                // Exercise repeat/key rotation through the actual builder's
                // owning Store without dropping/reacquiring a process lock.
                for (material, expected) in [
                    (
                        [0x68u8; 32],
                        if key.as_ref().unwrap()
                            == &data_encoding::BASE64URL_NOPAD.encode(&[0x68; 32])
                        {
                            1
                        } else {
                            2
                        },
                    ),
                    (
                        [0x70u8; 32],
                        if key.as_ref().unwrap()
                            == &data_encoding::BASE64URL_NOPAD.encode(&[0x68; 32])
                        {
                            2
                        } else {
                            3
                        },
                    ),
                ] {
                    let key = crate::provider::material::Key::resolve(
                        Some("OWNED_MATERIAL_KEY"),
                        &|_| Some(data_encoding::BASE64URL_NOPAD.encode(&material)),
                    )
                    .unwrap();
                    let registry = Registry::from_prepared_keyed(
                        bound
                            .services
                            .store
                            .prepare_registry_providers(
                                bound.services.snapshot.load().generation,
                                crate::store::Deadline::after(std::time::Duration::from_secs(5)),
                            )
                            .await
                            .unwrap(),
                        bound.services.snapshot.clone(),
                        &|_| Some("actual-builder-owned-material".into()),
                        bound.services.clock.clone(),
                        None,
                        Some(&key),
                    )
                    .unwrap();
                    registry
                        .publish_prepared(
                            &bound.services.store,
                            crate::store::Deadline::after(std::time::Duration::from_secs(5)),
                        )
                        .await
                        .unwrap();
                    let revision:i64=bound.services.store.conn().query_row("SELECT revision FROM human_provider_material_owners WHERE provider_id='owned'",[],|r|r.get(0)).unwrap();
                    assert_eq!(revision, expected);
                }
            }
            drop(bound);
        }
    }

    #[tokio::test]
    async fn actual_gateway_captures_native_service_proof_only_in_internal_extensions() {
        use tower::ServiceExt;
        let dir = tempfile::tempdir().unwrap();
        let value = serde_json::json!({"state_dir":dir.path().join("state"),"listen":{"portal":"127.0.0.1:0","gateway":"127.0.0.1:0"},"portal":{"public_url":"https://auth.example.test"},"gateway":{"kind":"hangang","caller_key_env":"OWNED_CAPTURE_CALLER"},"apps":[{"app_id":"orders","hosts":["orders.example.test"]}]});
        let cfg = crate::config::parse(&value.to_string()).unwrap();
        let mut bound = bind(&cfg).await.unwrap();
        const KEY: &str = "owned-capture-key-at-least-thirty-two-bytes";
        bound.services.caller_keys = Arc::new(CallerKeys::from_env(&cfg, |_| Some(KEY.into())));
        let profile:crate::auth_gateway::runtime::Config=serde_json::from_value(serde_json::json!({"authority_id":"owned","profiles":[{"service_id":"orders","host":"orders.example.test","ports":[443],"realm":"owned","api_keys":[{"token_env":"OWNED_CAPTURE_KEY","subject":"worker"}],"networks":["203.0.113.0/24"]}]})).unwrap();
        let owner = crate::auth_gateway::authority::Authority::load(
            &mut bound.services.store.conn(),
            Some(profile),
            &|_| Some(KEY.into()),
            &|_| Ok(()),
        )
        .unwrap();
        bound.services.authentication_authority = Some(Arc::new(std::sync::Mutex::new(owner)));
        let signing = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let issuer = crate::auth_gateway::receipt_config::NativeIssuer {
            issuer_ref: "owned".into(),
            key_epoch: 1,
            identity_authority_epoch: "epoch1".into(),
            public_key: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                signing.verifying_key().to_bytes(),
            ),
            seed_env: "OWNED_CAPTURE_SEED".into(),
            workload_receipts: None,
            human_receipts: None,
            scopes: vec![crate::auth_gateway::receipt_issuer::Scope {
                service: "orders".into(),
                audience: "orders-api".into(),
            }],
        };
        bound.services.receipt_issuer = Some(Arc::new(
            issuer
                .load(
                    &|_| {
                        Some(base64::Engine::encode(
                            &base64::engine::general_purpose::STANDARD,
                            [7; 32],
                        ))
                    },
                    bound.services.clock.clone(),
                    bound.services.rng.clone(),
                )
                .unwrap(),
        ));
        let router = build_routers(&bound.services).unwrap().gateway;
        let request = axum::http::Request::builder()
            .uri("/_hopae/verify")
            .header("x-hopae-gateway-key", KEY)
            .header("x-hopae-contract", "1")
            .header("authorization", format!("Bearer {KEY}"))
            .header("x-forwarded-host", "orders.example.test")
            .header("x-forwarded-proto", "https")
            .header("x-forwarded-port", "443")
            .header("x-forwarded-for", "203.0.113.9")
            .header("x-original-method", "GET")
            .header("x-original-url", "https://orders.example.test/private")
            .body(axum::body::Body::empty())
            .unwrap();
        let verification = crate::http::grpc_gateway::v1::VerifyRequest {
            request_id: 42,
            headers: request
                .headers()
                .iter()
                .filter(|(name, _)| name.as_str() != "x-hopae-gateway-key")
                .map(|(name, value)| crate::http::grpc_gateway::v1::Header {
                    name: name.to_string(),
                    value: value.as_bytes().to_vec(),
                })
                .collect(),
        };
        let rpc = crate::http::grpc_gateway::v1::ServiceReceiptRequest {
            verification: Some(verification),
            service: "orders".into(),
            audience: "orders-api".into(),
            request_sha256: vec![3; 32],
        };
        let anonymous = crate::http::grpc_gateway::issue_service_for_test(
            bound.services.clone(),
            router.clone(),
            tonic::Request::new(rpc.clone()),
        )
        .await
        .err()
        .unwrap();
        assert_eq!(anonymous.code(), tonic::Code::Unauthenticated);
        let mut forbidden = rpc.clone();
        forbidden.audience = "undeclared-audience".into();
        let mut forbidden = tonic::Request::new(forbidden);
        forbidden
            .metadata_mut()
            .insert("authorization", format!("Bearer {KEY}").parse().unwrap());
        assert_eq!(
            crate::http::grpc_gateway::issue_service_for_test(
                bound.services.clone(),
                router.clone(),
                forbidden
            )
            .await
            .err()
            .unwrap()
            .code(),
            tonic::Code::PermissionDenied
        );
        let mut call = tonic::Request::new(rpc);
        call.metadata_mut()
            .insert("authorization", format!("Bearer {KEY}").parse().unwrap());
        let reply = crate::http::grpc_gateway::issue_service_for_test(
            bound.services.clone(),
            router.clone(),
            call,
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(reply.request_id, 42);
        assert_eq!(reply.receipt.len(), crate::auth_gateway::receipt::LENGTH);
        let context = reply.context.unwrap();
        let identity = context.identity.unwrap();
        assert_eq!(identity.kind, 2);
        assert_eq!(identity.aal, 0);
        let binding = crate::auth_gateway::receipt_binding::digest(
            &crate::auth_gateway::receipt_binding::Context {
                issuer_ref: &context.issuer_ref,
                key_epoch: context.key_epoch,
                identity_authority_epoch: &context.identity_authority_epoch,
                identity: crate::auth_gateway::receipt_binding::Identity {
                    subject_ref: &identity.subject_ref,
                    kind: crate::auth_gateway::PrincipalKind::Service,
                    aal: 0,
                    revision: identity.revision,
                    credential_generation: identity.credential_generation,
                },
                service: &context.service,
                audience: &context.audience,
                request_sha256: context.request_sha256.try_into().unwrap(),
            },
            None,
        )
        .unwrap();
        assert!(
            crate::auth_gateway::receipt::verify(
                &signing.verifying_key(),
                &reply.receipt,
                crate::auth_gateway::receipt::Purpose::Authentication,
                &binding,
                bound.services.clock.now().0 as u64
            )
            .is_ok()
        );
        // Exercise the registered receipt service over an actual mandatory-mTLS socket.
        let tlsdir = dir.path().join("tls");
        std::fs::create_dir(&tlsdir).unwrap();
        let openssl = |args: &[&str]| {
            assert!(
                std::process::Command::new("openssl")
                    .args(args)
                    .current_dir(&tlsdir)
                    .output()
                    .unwrap()
                    .status
                    .success()
            );
        };
        openssl(&[
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=owned-ca",
            "-keyout",
            "ca.key",
            "-out",
            "ca.pem",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
        ]);
        for (name, usage) in [("server", "serverAuth"), ("client", "clientAuth")] {
            let key = format!("{name}.key");
            let csr = format!("{name}.csr");
            let cert = format!("{name}.pem");
            let ext = format!("{name}.ext");
            openssl(&[
                "req",
                "-new",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-subj",
                "/CN=owned",
                "-keyout",
                &key,
                "-out",
                &csr,
            ]);
            std::fs::write(tlsdir.join(&ext),format!("basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage={usage}\nsubjectAltName=DNS:hopae.example.test\n")).unwrap();
            openssl(&[
                "x509",
                "-req",
                "-in",
                &csr,
                "-CA",
                "ca.pem",
                "-CAkey",
                "ca.key",
                "-CAcreateserial",
                "-days",
                "1",
                "-extfile",
                &ext,
                "-out",
                &cert,
            ]);
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let tls = hangang_runtime::configuration(
            &tlsdir.join("server.pem"),
            &tlsdir.join("server.key"),
            &tlsdir.join("ca.pem"),
        )
        .unwrap();
        let (stop, stopped) = tokio::sync::watch::channel(false);
        let running = tokio::spawn(crate::http::grpc_gateway::serve_with_receipts(
            listener,
            tls,
            router.clone(),
            bound.services.caller_keys.clone(),
            stopped,
            Some(bound.services.clone()),
        ));
        let ca =
            tonic::transport::Certificate::from_pem(std::fs::read(tlsdir.join("ca.pem")).unwrap());
        let endpoint = tonic::transport::Endpoint::from_shared(format!("https://{address}"))
            .unwrap()
            .timeout(Duration::from_secs(2));
        let tls = tonic::transport::ClientTlsConfig::new()
            .domain_name("hopae.example.test")
            .ca_certificate(ca.clone())
            .identity(tonic::transport::Identity::from_pem(
                std::fs::read(tlsdir.join("client.pem")).unwrap(),
                std::fs::read(tlsdir.join("client.key")).unwrap(),
            ));
        let channel = endpoint
            .clone()
            .tls_config(tls)
            .unwrap()
            .connect()
            .await
            .unwrap();
        let mut plan_client =
            crate::http::grpc_gateway::v1::projection_plans_client::ProjectionPlansClient::new(
                channel.clone(),
            );
        let plan_call = || {
            let mut call =
                tonic::Request::new(crate::http::grpc_gateway::v1::ProjectionPlanRequest {
                    request_id: 91,
                    service: "orders".into(),
                    audience: "orders-api".into(),
                    minimum_revision: 1,
                });
            call.metadata_mut()
                .insert("authorization", format!("Bearer {KEY}").parse().unwrap());
            call
        };
        assert_eq!(
            plan_client.observe(plan_call()).await.unwrap_err().code(),
            tonic::Code::Unavailable
        );
        {
            use crate::auth_gateway::projection::{Configuration, Credential, Plan};
            let mut owner = bound.services.projection_authority.lock().unwrap();
            owner
                .publish(
                    &mut bound.services.store.conn(),
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
                                secret_ref: "vault:unresolved".into(),
                            },
                        }],
                    }),
                    "operator",
                    &|_| Ok(()),
                )
                .unwrap();
        }
        let plan = plan_client.observe(plan_call()).await.unwrap().into_inner();
        assert_eq!(
            (
                plan.request_id,
                plan.revision,
                plan.minimum_aal,
                plan.cache_ttl_ms
            ),
            (91, 1, 2, 0)
        );
        let mut wrong_key = plan_call();
        wrong_key
            .metadata_mut()
            .insert("authorization", "Bearer wrong".parse().unwrap());
        assert_eq!(
            plan_client.observe(wrong_key).await.unwrap_err().code(),
            tonic::Code::Unauthenticated
        );
        bound
            .services
            .projection_authority
            .lock()
            .unwrap()
            .publish(
                &mut bound.services.store.conn(),
                1,
                None,
                "operator",
                &|_| Ok(()),
            )
            .unwrap();
        assert_eq!(
            plan_client.observe(plan_call()).await.unwrap_err().code(),
            tonic::Code::Unavailable
        );
        let mut client=crate::http::grpc_gateway::v1::authentication_receipts_client::AuthenticationReceiptsClient::new(channel);
        let message = crate::http::grpc_gateway::v1::ServiceReceiptRequest {
            verification: Some(crate::http::grpc_gateway::v1::VerifyRequest {
                request_id: 77,
                headers: request
                    .headers()
                    .iter()
                    .filter(|(name, _)| name.as_str() != "x-hopae-gateway-key")
                    .map(|(name, value)| crate::http::grpc_gateway::v1::Header {
                        name: name.to_string(),
                        value: value.as_bytes().to_vec(),
                    })
                    .collect(),
            }),
            service: "orders".into(),
            audience: "orders-api".into(),
            request_sha256: vec![3; 32],
        };
        crate::auth_gateway::projection_runtime::tests::qualify(
            bound.services.clone(),
            router.clone(),
            message.clone(),
            KEY,
            &tlsdir,
            &issuer.validate().unwrap(),
        )
        .await;
        let call = |key: &str| {
            let mut call = tonic::Request::new(message.clone());
            call.metadata_mut()
                .insert("authorization", format!("Bearer {key}").parse().unwrap());
            call
        };
        assert_eq!(
            client
                .issue_service(call("wrong-caller"))
                .await
                .err()
                .unwrap()
                .code(),
            tonic::Code::Unauthenticated
        );
        let reply = client.issue_service(call(KEY)).await.unwrap().into_inner();
        assert_eq!(reply.request_id, 77);
        let validation_message = crate::http::grpc_gateway::v1::ServiceReceiptValidationRequest {
            request_id: 78,
            context: reply.context.clone(),
            receipt: reply.receipt.clone(),
            request_sha256: vec![3; 32],
        };
        let validation_call = |key: &str| {
            let mut request = tonic::Request::new(validation_message.clone());
            request
                .metadata_mut()
                .insert("authorization", format!("Bearer {key}").parse().unwrap());
            request
        };
        assert_eq!(
            client
                .validate_service(validation_call("wrong-caller"))
                .await
                .err()
                .unwrap()
                .code(),
            tonic::Code::Unauthenticated
        );
        let validated = client
            .validate_service(validation_call(KEY))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(validated.request_id, 78);
        assert!(validated.expires_ms > bound.services.clock.now().0 as u64);
        let mut tampered = validation_call(KEY);
        tampered.get_mut().receipt[20] ^= 1;
        assert_eq!(
            client
                .validate_service(tampered)
                .await
                .err()
                .unwrap()
                .code(),
            tonic::Code::PermissionDenied
        );
        let context = reply.context.unwrap();
        let identity = context.identity.unwrap();
        assert_eq!(identity.kind, 2);
        assert_eq!(identity.aal, 0);
        let binding = crate::auth_gateway::receipt_binding::digest(
            &crate::auth_gateway::receipt_binding::Context {
                issuer_ref: &context.issuer_ref,
                key_epoch: context.key_epoch,
                identity_authority_epoch: &context.identity_authority_epoch,
                identity: crate::auth_gateway::receipt_binding::Identity {
                    subject_ref: &identity.subject_ref,
                    kind: crate::auth_gateway::PrincipalKind::Service,
                    aal: 0,
                    revision: identity.revision,
                    credential_generation: identity.credential_generation,
                },
                service: &context.service,
                audience: &context.audience,
                request_sha256: context.request_sha256.try_into().unwrap(),
            },
            None,
        )
        .unwrap();
        assert!(
            crate::auth_gateway::receipt::verify(
                &signing.verifying_key(),
                &reply.receipt,
                crate::auth_gateway::receipt::Purpose::Authentication,
                &binding,
                bound.services.clock.now().0 as u64
            )
            .is_ok()
        );
        let mut forbidden = call(KEY);
        forbidden.get_mut().audience = "undeclared-audience".into();
        assert_eq!(
            client.issue_service(forbidden).await.err().unwrap().code(),
            tonic::Code::PermissionDenied
        );
        let no_cert = tonic::transport::ClientTlsConfig::new()
            .domain_name("hopae.example.test")
            .ca_certificate(ca);
        if let Ok(channel) = endpoint.tls_config(no_cert).unwrap().connect().await {
            assert!(crate::http::grpc_gateway::v1::authentication_receipts_client::AuthenticationReceiptsClient::new(channel).issue_service(call(KEY)).await.is_err());
        }
        let mut external = if let Ok(binary) = std::env::var("HANGANG_RECEIPT_CLIENT") {
            use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
            let path = tlsdir.join("native-client.json");
            let headers = request
                .headers()
                .iter()
                .filter(|(name, _)| {
                    !matches!(name.as_str(), "authorization" | "x-hopae-gateway-key")
                })
                .map(|(name, value)| serde_json::json!([name.as_str(), value.to_str().unwrap()]))
                .collect::<Vec<_>>();
            std::fs::write(&path,serde_json::to_vec(&serde_json::json!({"settings":{"transport":"grpc","address":address.to_string(),"pool_size":8,"tls":{"server_name":"hopae.example.test","ca":tlsdir.join("ca.pem"),"certificate":tlsdir.join("client.pem"),"key":tlsdir.join("client.key")}},"issuer_ref":"owned","key_epoch":1,"public_key":base64::Engine::encode(&base64::engine::general_purpose::STANDARD,signing.verifying_key().to_bytes()),"service":"orders","audience":"orders-api","method":"GET","target":"/private","body":"","headers":headers})).unwrap()).unwrap();
            let mut child = tokio::process::Command::new(binary)
                .arg(path)
                .env("OWNED_RECEIPT_CALLER", KEY)
                .env("OWNED_RECEIPT_CREDENTIAL", KEY)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::from(
                    std::fs::File::create(tlsdir.join("native-client.private.log")).unwrap(),
                ))
                .kill_on_drop(true)
                .spawn()
                .unwrap();
            let mut stdin = child.stdin.take().unwrap();
            let mut stdout = tokio::io::BufReader::new(child.stdout.take().unwrap()).lines();
            stdin.write_all(b"allow\n").await.unwrap();
            let row = tokio::time::timeout(Duration::from_secs(3), stdout.next_line())
                .await
                .unwrap()
                .unwrap();
            if row.is_none() {
                let diagnostic = std::fs::read_to_string(tlsdir.join("native-client.private.log"))
                    .unwrap_or_default();
                let markers = [
                    "invalid type",
                    "unknown field",
                    "invalid native issuer pin",
                    "receipt result differed",
                    "CryptoProvider",
                    "reference unavailable",
                    "No such file",
                    "invalid native request binding",
                ];
                panic!(
                    "owned client exited; diagnostic categories: {:?}",
                    markers
                        .into_iter()
                        .filter(|marker| diagnostic.contains(marker))
                        .collect::<Vec<_>>()
                );
            }
            let row = row.unwrap();
            let row: serde_json::Value = serde_json::from_str(&row).unwrap();
            assert_eq!(row["allowed"], true);
            assert_eq!(row["revision"], 1);
            Some((child, stdin, stdout))
        } else {
            None
        };
        let saved = crate::auth_gateway::publication::read(&bound.services.store.conn())
            .unwrap()
            .unwrap();
        let owner = bound.services.authentication_authority.as_ref().unwrap();
        owner
            .lock()
            .unwrap()
            .publish(
                &mut bound.services.store.conn(),
                saved.revision,
                None,
                "owned-operator",
                &|_| Some(KEY.into()),
                &|_| Ok(()),
            )
            .unwrap();
        assert!(
            client.issue_service(call(KEY)).await.is_err(),
            "same-channel revoked profile cannot issue"
        );
        assert_eq!(
            client
                .validate_service(validation_call(KEY))
                .await
                .err()
                .unwrap()
                .code(),
            tonic::Code::PermissionDenied
        );
        if let Some((_, stdin, stdout)) = &mut external {
            use tokio::io::AsyncWriteExt;
            stdin.write_all(b"deny\n").await.unwrap();
            let row = tokio::time::timeout(Duration::from_secs(3), stdout.next_line())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(&row).unwrap()["allowed"],
                false
            );
        }

        owner
            .lock()
            .unwrap()
            .publish(
                &mut bound.services.store.conn(),
                saved.revision + 1,
                saved.configuration,
                "owned-operator",
                &|_| Some(KEY.into()),
                &|_| Ok(()),
            )
            .unwrap();
        let restored = client.issue_service(call(KEY)).await.unwrap().into_inner();

        assert_eq!(
            client
                .validate_service(validation_call(KEY))
                .await
                .err()
                .unwrap()
                .code(),
            tonic::Code::PermissionDenied
        );
        let mut restored_validation = tonic::Request::new(
            crate::http::grpc_gateway::v1::ServiceReceiptValidationRequest {
                request_id: 79,
                context: restored.context.clone(),
                receipt: restored.receipt.clone(),
                request_sha256: vec![3; 32],
            },
        );
        restored_validation
            .metadata_mut()
            .insert("authorization", format!("Bearer {KEY}").parse().unwrap());
        let restored_message = restored_validation.get_ref().clone();
        assert_eq!(
            client
                .validate_service(restored_validation)
                .await
                .unwrap()
                .into_inner()
                .request_id,
            79
        );
        let mut changed_app = (**bound.services.snapshot.load()).clone();
        changed_app.generation += 1;
        bound.services.snapshot.store(Arc::new(changed_app));
        let mut changed_validation = tonic::Request::new(restored_message);
        changed_validation
            .metadata_mut()
            .insert("authorization", format!("Bearer {KEY}").parse().unwrap());
        assert_eq!(
            client
                .validate_service(changed_validation)
                .await
                .err()
                .unwrap()
                .code(),
            tonic::Code::PermissionDenied
        );
        assert_eq!(
            restored.context.unwrap().identity.unwrap().revision,
            saved.revision + 2
        );
        if let Some((mut child, mut stdin, mut stdout)) = external {
            use tokio::io::AsyncWriteExt;
            stdin.write_all(b"allow\n").await.unwrap();
            let row = tokio::time::timeout(Duration::from_secs(3), stdout.next_line())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            let row: serde_json::Value = serde_json::from_str(&row).unwrap();
            assert_eq!(row["allowed"], true);
            assert_eq!(row["revision"], saved.revision + 2);
            drop(stdin);
            assert!(
                tokio::time::timeout(Duration::from_secs(3), child.wait())
                    .await
                    .unwrap()
                    .unwrap()
                    .success()
            );
        }
        stop.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(3), running)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let response = router.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        assert!(
            response
                .extensions()
                .get::<Arc<crate::auth_gateway::receipt_issuer::CapturedService>>()
                .is_some()
        );
        assert!(
            !response
                .headers()
                .keys()
                .any(|key| key.as_str().contains("receipt"))
        );
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        assert!(body.is_empty());
        let denied = router
            .oneshot(
                axum::http::Request::builder()
                    .uri("/_hopae/verify")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(denied.status(), axum::http::StatusCode::FORBIDDEN);
        assert!(
            denied
                .extensions()
                .get::<Arc<crate::auth_gateway::receipt_issuer::CapturedService>>()
                .is_none()
        );
    }

    #[tokio::test]
    async fn missing_receipt_seed_refuses_bind_before_state_creation() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("uncreated");
        let name = format!(
            "HOPAE_MISSING_RECEIPT_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let public = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            key.verifying_key().to_bytes(),
        );
        let value = serde_json::json!({"state_dir":state,"portal":{"public_url":"https://auth.example.test"},"gateway":{"kind":"hangang","caller_key_env":"OWNED_CALLER_REFERENCE"},"apps":[{"app_id":"orders","hosts":["app.example.test"]}],"receipt_issuer":{"issuer_ref":"owned","key_epoch":1,"identity_authority_epoch":"epoch1","public_key":public,"seed_env":name,"scopes":[{"service":"orders","audience":"orders-api"}]}});
        let cfg = crate::config::parse(&value.to_string()).unwrap();
        let error = bind(&cfg)
            .await
            .err()
            .expect("missing receipt seed must refuse");
        assert_eq!(error.to_string(), "native receipt issuer unavailable");
        assert!(!state.exists());
    }

    #[tokio::test]
    async fn missing_external_verifier_key_refuses_bind_before_state_creation() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("uncreated");
        let name = format!(
            "HOPAE_MISSING_EXTERNAL_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let value = serde_json::json!({"state_dir":state,"portal":{"public_url":"https://auth.example.test"},"gateway":{"kind":"hangang","caller_key_env":"OWNED_CALLER_REFERENCE"},"external_verifiers":[{"factor":"push","configuration_revision":1,"url":"https://verifier.example.test/check","verifier_key_env":name,"timeout_ms":100}]});
        let cfg = crate::config::parse(&value.to_string()).unwrap();
        let error = bind(&cfg)
            .await
            .err()
            .expect("missing external verifier must refuse");
        assert_eq!(
            error.to_string(),
            "external_verifiers: unavailable or invalid verifier material"
        );
        assert!(!state.exists());
    }

    #[tokio::test]
    async fn missing_totp_key_refuses_bind_before_state_creation() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("uncreated");
        let name = format!(
            "HOPAE_MISSING_TOTP_KEY_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let value = serde_json::json!({"state_dir":state,"portal":{"public_url":"https://auth.example.test"},"gateway":{"kind":"hangang","caller_key_env":"OWNED_CALLER_REFERENCE"},"totp_keyring":{"active_key":"owned","keys":[{"id":"owned","key_env":name}]}});
        let cfg = crate::config::parse(&value.to_string()).unwrap();
        let error = bind(&cfg).await.err().expect("must refuse missing key");
        assert_eq!(
            error.to_string(),
            "totp_keyring: unavailable or invalid key material"
        );
        assert!(
            !state.exists(),
            "key failure created state or lock before refusal"
        );
    }

    fn keys(cur: Option<&str>, next: Option<&str>, unauth: bool) -> CallerKeys {
        CallerKeys::new(
            cur.map(|s| Secret::new(s.into())),
            next.map(|s| Secret::new(s.into())),
            unauth,
        )
    }

    #[test]
    fn current_and_next_keys_are_accepted_and_labelled() {
        let k = keys(Some("key-a"), Some("key-b"), false);
        assert_eq!(
            k.check(Some(b"key-a")),
            KeyVerdict::Accepted(KeySlot::Current)
        );
        assert_eq!(k.check(Some(b"key-b")), KeyVerdict::Accepted(KeySlot::Next));
        assert_eq!(k.check(Some(b"key-c")), KeyVerdict::Rejected);
        assert_eq!(k.check(Some(b"")), KeyVerdict::Rejected);
        assert_eq!(k.check(None), KeyVerdict::Rejected);
    }

    #[test]
    fn rotation_last_step_accepts_only_the_promoted_key() {
        let after = keys(Some("key-b"), None, false);
        assert_eq!(
            after.check(Some(b"key-b")),
            KeyVerdict::Accepted(KeySlot::Current)
        );
        assert_eq!(after.check(Some(b"key-a")), KeyVerdict::Rejected);
    }

    #[test]
    fn no_configured_key_is_open_only_when_explicitly_allowed() {
        assert_eq!(keys(None, None, true).check(None), KeyVerdict::NotRequired);
        assert_eq!(
            keys(None, None, false).check(Some(b"x")),
            KeyVerdict::Rejected
        );
        // An allowed-unauthenticated process that does have a key still checks it.
        let k = keys(Some("k"), None, true);
        assert_eq!(k.check(Some(b"nope")), KeyVerdict::Rejected);
    }

    #[test]
    fn verdicts_are_counted() {
        // A private counter: the process counters are shared by every test.
        let seen = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let sink = seen.clone();
        let k = keys(Some("count-a"), Some("count-b"), false).with_counter(Arc::new(
            move |name, labels| {
                let l: Vec<String> = labels.iter().map(|(k, v)| format!("{k}={v}")).collect();
                sink.lock()
                    .unwrap()
                    .push(format!("{name}{{{}}}", l.join(",")));
            },
        ));
        k.check(Some(b"count-a"));
        k.check(Some(b"count-b"));
        k.check(Some(b"zzz"));
        let got = seen.lock().unwrap().clone();
        assert_eq!(
            got,
            [
                "hopae_verify_caller_key_total{slot=current}",
                "hopae_verify_caller_key_total{slot=next}",
                "hopae_verify_unauthorized_total{}",
            ]
        );
    }
}
