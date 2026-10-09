//! Wiring: store, listeners and graceful shutdown.

use std::future::Future;
use std::net::SocketAddr;

use anyhow::Context;
use tokio::net::TcpListener;
use tokio::sync::watch;

use crate::config::Config;
use crate::http;
use crate::store::Store;

/// Bound listeners and the open store; call [`Bound::run`] to serve.
pub struct Bound {
    portal: TcpListener,
    gateway: TcpListener,
    portal_addr: SocketAddr,
    gateway_addr: SocketAddr,
    _store: Store,
}

/// Open the store, then bind both listeners. Failing here is a start failure.
pub async fn bind(cfg: &Config) -> anyhow::Result<Bound> {
    for w in cfg.warnings() {
        tracing::warn!("{w}");
    }
    let store_path = cfg.store_path();
    let store = {
        let p = store_path.clone();
        tokio::task::spawn_blocking(move || Store::open(&p))
            .await
            .context("store open task")?
            .with_context(|| format!("opening store {}", store_path.display()))?
    };
    let portal = TcpListener::bind(cfg.portal_addr())
        .await
        .context("binding portal listener")?;
    let gateway = TcpListener::bind(cfg.gateway_addr())
        .await
        .context("binding gateway listener")?;
    let portal_addr = portal.local_addr()?;
    let gateway_addr = gateway.local_addr()?;
    Ok(Bound {
        portal,
        gateway,
        portal_addr,
        gateway_addr,
        _store: store,
    })
}

impl Bound {
    pub fn portal_addr(&self) -> SocketAddr {
        self.portal_addr
    }

    pub fn gateway_addr(&self) -> SocketAddr {
        self.gateway_addr
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
        let gateway =
            axum::serve(self.gateway, http::gateway_router()).with_graceful_shutdown(wait(rx));
        let (p, g) = tokio::join!(portal, gateway);
        p.context("portal listener")?;
        g.context("gateway listener")?;
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
