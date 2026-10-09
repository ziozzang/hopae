//! Wiring: store, listeners and graceful shutdown.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context;
use tokio::net::TcpListener;
use tokio::sync::watch;

use crate::config::Config;
use crate::crypto::{Clock, Rng, SystemClock};
use crate::http;
use crate::store::{Store, StoreHooks};

/// Bound listeners and the open store; call [`Bound::run`] to serve.
pub struct Bound {
    portal: TcpListener,
    gateway: TcpListener,
    portal_addr: SocketAddr,
    gateway_addr: SocketAddr,
    store: Store,
    clock: Arc<dyn Clock>,
    rng: Arc<dyn Rng>,
    #[cfg(feature = "test-hooks")]
    hooks: Option<(TcpListener, SocketAddr, Arc<http::hooks::HooksState>)>,
}

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

/// Open the store, then bind both listeners. Failing here is a start failure.
pub async fn bind(cfg: &Config) -> anyhow::Result<Bound> {
    for w in cfg.warnings() {
        tracing::warn!("{w}");
    }
    let store_path = cfg.store_path();
    let env = env();
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
    let portal = TcpListener::bind(cfg.portal_addr())
        .await
        .context("binding portal listener")?;
    let gateway = TcpListener::bind(cfg.gateway_addr())
        .await
        .context("binding gateway listener")?;
    let portal_addr = portal.local_addr()?;
    let gateway_addr = gateway.local_addr()?;
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
            Some((l, a, state))
        }
        _ => None,
    };
    Ok(Bound {
        portal,
        gateway,
        portal_addr,
        gateway_addr,
        store,
        clock: env.clock,
        rng: env.rng,
        #[cfg(feature = "test-hooks")]
        hooks,
    })
}

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
        &self.store
    }

    pub fn clock(&self) -> &Arc<dyn Clock> {
        &self.clock
    }

    pub fn rng(&self) -> &Arc<dyn Rng> {
        &self.rng
    }

    /// Serve both listeners until `shutdown` completes, then drain gracefully.
    pub async fn run(
        self,
        shutdown: impl Future<Output = ()> + Send + 'static,
    ) -> anyhow::Result<()> {
        let (tx, rx) = watch::channel(false);
        tokio::spawn(async move {
            shutdown.await;
            let _ = tx.send(true);
        });
        let wait = |mut rx: watch::Receiver<bool>| async move {
            let _ = rx.wait_for(|stop| *stop).await;
        };
        let portal = axum::serve(self.portal, http::portal_router())
            .with_graceful_shutdown(wait(rx.clone()));
        let gateway = axum::serve(self.gateway, http::gateway_router())
            .with_graceful_shutdown(wait(rx.clone()));
        #[cfg(feature = "test-hooks")]
        let hooks = async {
            match self.hooks {
                Some((l, _, state)) => {
                    axum::serve(l, http::hooks::router(state))
                        .with_graceful_shutdown(wait(rx.clone()))
                        .await
                }
                None => Ok(()),
            }
        };
        #[cfg(not(feature = "test-hooks"))]
        let hooks = async { Ok::<(), std::io::Error>(()) };
        let (p, g, h) = tokio::join!(portal, gateway, hooks);
        p.context("portal listener")?;
        g.context("gateway listener")?;
        h.context("test hooks listener")?;
        Ok(())
    }
}

/// Completes on SIGINT or SIGTERM.
pub async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    let (Ok(mut term), Ok(mut int)) = (
        signal(SignalKind::terminate()),
        signal(SignalKind::interrupt()),
    ) else {
        tracing::error!("cannot install signal handlers");
        return;
    };
    tokio::select! {
        _ = term.recv() => {}
        _ = int.recv() => {}
    }
}
