//! Mutual-TLS serving whose material follows its files ([`crate::reload`]):
//! every handshake takes the configuration current at that moment.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::service::TowerToHyperService;
use tokio::net::TcpListener;
use tokio::time::timeout;

use crate::reload::ServerTls;

/// The administrator listener over mandatory mTLS: the bounds of
/// `hangang_runtime::serve_https` (2048 connections, 3 s handshake, 5 s
/// header read, 300 s per connection), with the current material per
/// handshake. A client without a certificate is dropped.
pub async fn serve_https(
    listener: TcpListener,
    tls: Arc<ServerTls>,
    router: axum::Router,
    shutdown: impl Future<Output = ()> + Send,
) -> anyhow::Result<()> {
    hangang_runtime::serve_connections(
        listener,
        std::num::NonZeroUsize::new(2048).expect("non-zero"),
        Duration::from_secs(5),
        move |socket, peer| {
            let acceptor = tls.acceptor();
            let router = router
                .clone()
                .layer(axum::Extension(axum::extract::ConnectInfo(peer)));
            async move {
                let Ok(Ok(stream)) = timeout(Duration::from_secs(3), acceptor.accept(socket)).await
                else {
                    return;
                };
                if stream
                    .get_ref()
                    .1
                    .peer_certificates()
                    .is_none_or(|certs| certs.is_empty())
                {
                    return;
                }
                let router = router.layer(axum::Extension(hangang_runtime::AuthenticatedTlsPeer));
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

/// Accepted gRPC connections after their mTLS handshake with the current
/// material (3 s bound, handshakes concurrent), for
/// `Server::serve_with_incoming_shutdown`. Connections are admitted by
/// `hangang_runtime::incoming` (2048 at most, `TCP_NODELAY`).
pub fn grpc_incoming(
    listener: TcpListener,
    tls: Arc<ServerTls>,
) -> impl tokio_stream::Stream<
    Item = std::io::Result<tokio_rustls::server::TlsStream<hangang_runtime::Connection>>,
> {
    use tokio_stream::StreamExt;
    let (tx, rx) = tokio::sync::mpsc::channel(64);
    tokio::spawn(async move {
        let incoming = hangang_runtime::incoming(listener);
        tokio::pin!(incoming);
        loop {
            let next = tokio::select! {
                n = incoming.next() => n,
                _ = tx.closed() => return,
            };
            match next {
                Some(Ok(connection)) => {
                    let acceptor = tls.acceptor();
                    let tx = tx.clone();
                    tokio::spawn(async move {
                        if let Ok(Ok(stream)) =
                            timeout(Duration::from_secs(3), acceptor.accept(connection)).await
                        {
                            let _ = tx.send(Ok(stream)).await;
                        }
                    });
                }
                Some(Err(e)) => {
                    if tx.send(Err(e)).await.is_err() {
                        return;
                    }
                }
                None => return,
            }
        }
    });
    tokio_stream::wrappers::ReceiverStream::new(rx)
}
