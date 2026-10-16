//! The admin listener over mandatory mutual TLS. Same bounds as
//! `hangang_runtime::serve_https` (2,048 connections, 3 s handshake, 5 s
//! header read, 64 headers, 32 KiB buffer, 300 s per connection), and in
//! addition the verified leaf certificate's facts are put into the request
//! extensions as [`PeerCertificate`] for the service-credential binding.
//! Nothing a client sends can create either extension. Each handshake uses
//! the material current at that moment ([`crate::reload`]).
use crate::admin::service_credentials::PeerCertificate;
use hyper_util::{
    rt::{TokioIo, TokioTimer},
    service::TowerToHyperService,
};
use std::{future::Future, sync::Arc, time::Duration};
use tokio::{net::TcpListener, time::timeout};

pub async fn serve(
    listener: TcpListener,
    tls: Arc<crate::reload::ServerTls>,
    router: axum::Router,
    shutdown: impl Future<Output = ()> + Send,
) -> anyhow::Result<()> {
    hangang_runtime::serve_connections(
        listener,
        std::num::NonZeroUsize::new(2048).expect("nonzero"),
        Duration::from_secs(5),
        move |socket, peer| {
            // The material current at this handshake (live reload).
            let acceptor = tls.acceptor();
            let router = router
                .clone()
                .layer(axum::Extension(axum::extract::ConnectInfo(peer)));
            async move {
                let Ok(Ok(stream)) = timeout(Duration::from_secs(3), acceptor.accept(socket)).await
                else {
                    return;
                };
                let Some(leaf) = stream
                    .get_ref()
                    .1
                    .peer_certificates()
                    .and_then(|certs| certs.first())
                else {
                    return;
                };
                let mut router =
                    router.layer(axum::Extension(hangang_runtime::AuthenticatedTlsPeer));
                if let Some(facts) = PeerCertificate::from_der(leaf.as_ref()) {
                    router = router.layer(axum::Extension(facts));
                }
                let mut builder = hyper::server::conn::http1::Builder::new();
                builder
                    .timer(TokioTimer::new())
                    .header_read_timeout(Duration::from_secs(5))
                    .max_headers(64)
                    .max_buf_size(32 * 1024);
                let _ = timeout(
                    Duration::from_secs(300),
                    builder
                        .serve_connection(TokioIo::new(stream), TowerToHyperService::new(router)),
                )
                .await;
            }
        },
        shutdown,
    )
    .await?;
    Ok(())
}
