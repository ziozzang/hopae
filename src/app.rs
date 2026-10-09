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
//! Startup order (scenario 013-5): lock → backup → store opened and migrated
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
use crate::store::{Directory, Events, Sessions, Store, StoreHooks};
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
        if self.current.is_none() && self.next.is_none() {
            return if self.unauthenticated_allowed {
                KeyVerdict::NotRequired
            } else {
                // No key configured and none allowed: nothing can match.
                (self.counter)(counters::VERIFY_UNAUTHORIZED_TOTAL, &[]);
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
        let given = presented.is_some_and(|p| !p.is_empty());
        match (given, cur, nxt) {
            (true, true, _) => {
                (self.counter)(counters::VERIFY_CALLER_KEY_TOTAL, &[("slot", "current")]);
                KeyVerdict::Accepted(KeySlot::Current)
            }
            (true, false, true) => {
                (self.counter)(counters::VERIFY_CALLER_KEY_TOTAL, &[("slot", "next")]);
                KeyVerdict::Accepted(KeySlot::Next)
            }
            _ => {
                (self.counter)(counters::VERIFY_UNAUTHORIZED_TOTAL, &[]);
                KeyVerdict::Rejected
            }
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

    fn set(&self, ready: bool) {
        self.0.store(ready, Ordering::SeqCst);
    }
}

/// Everything the routers and services are built from.
#[derive(Clone)]
pub struct Services {
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
}

impl Services {
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
}

/// Assemble both routers from `services`. The portal and the gateway share the
/// store, the provider registry and the emitter, never a route.
pub fn build_routers(services: &Services) -> anyhow::Result<Routers> {
    let gateway_state = http::gateway::GatewayState::new(
        crate::gateway::hangang::GatewayConfig::from_config(&services.config),
        services.verify_context(),
        services.caller_keys.clone(),
        services.config.limits.gateway_max_concurrent,
        Some(Arc::new(counters::inc)),
        Some(services.emitter.clone()),
    );
    let adapter = Adapter::new(
        services.session_service()?,
        services.registry.clone(),
        services.directory(),
        services.events(),
        services.emitter.clone(),
        services.readiness.clone(),
    );
    let portal_state = PortalState::new(
        PortalConfig::from_config(&services.config),
        Arc::new(adapter),
        services.clock.clone(),
        services.rng.clone(),
    );
    Ok(Routers {
        portal: http::portal::router(portal_state),
        gateway: http::gateway_router(gateway_state),
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
    portal: TcpListener,
    gateway: TcpListener,
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
    let real_env = |n: &str| std::env::var(n).ok();
    for w in cfg.warnings() {
        tracing::warn!("{w}");
    }
    for w in crate::config::env_warnings(cfg, real_env) {
        tracing::warn!("{w}");
    }
    let env = env();
    let store_path = cfg.store_path();

    // 1. One instance per store.
    let instance_lock = lock::acquire(&cfg.state_dir)?;

    // 2. A copy of an older database before it is migrated.
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
    let snapshot = cfg.snapshot(generation);
    let listeners_attr = format!(
        "portal={} gateway={}",
        cfg.portal_addr(),
        cfg.gateway_addr()
    );
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
    // The provider registry, from the rows the import just settled (the
    // database is authoritative). Its reporter writes `provider.error`.
    let rows = directory.providers().await.context("reading providers")?;
    let registry = Arc::new(Registry::from_snapshot(
        &rows,
        &|n| std::env::var(n).ok(),
        env.clock.clone(),
        Some(provider_reporter(emitter.clone())),
    ));
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
    let services = Services {
        config: Arc::new(cfg.clone()),
        store: store.clone(),
        clock: env.clock.clone(),
        rng: env.rng.clone(),
        emitter,
        snapshot: Arc::new(ArcSwap::from_pointee(snapshot)),
        caller_keys: Arc::new(CallerKeys::from_env(cfg, |n| std::env::var(n).ok())),
        readiness: Readiness::default(),
        store_hooks: env.store_hooks.clone(),
        registry,
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
    let gateway = TcpListener::bind(cfg.gateway_addr())
        .await
        .context("binding gateway listener")?;
    let gateway_addr = gateway.local_addr()?;
    tracing::info!("listeners bound: portal {portal_addr}, gateway {gateway_addr}");
    Ok(Bound {
        portal,
        gateway,
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
    pub fn portal_addr(&self) -> SocketAddr {
        self.portal_addr
    }

    pub fn gateway_addr(&self) -> SocketAddr {
        self.gateway_addr
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
        let servers = async { tokio::join!(portal, gateway, hooks) };
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

        if let Some((p, g, h)) = served {
            p.context("portal listener")?;
            g.context("gateway listener")?;
            h.context("test hooks listener")?;
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

#[cfg(test)]
mod tests {
    use super::*;

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
