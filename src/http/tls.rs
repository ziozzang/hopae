//! Mutual-TLS serving whose material follows its files ([`crate::reload`]):
//! every handshake takes the configuration current at that moment. (The
//! administrator listener is `http::admin_tls`.)

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::service::TowerToHyperService;
use tokio::net::TcpListener;
use tokio::time::timeout;

use crate::reload::ServerTls;

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
