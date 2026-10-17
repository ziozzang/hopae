//! An outbound mTLS gRPC channel whose material can be replaced while it is
//! in use ([`crate::reload`]): calls started on the old channel finish there,
//! every call after [`ReloadingChannel::replace`] uses the new one (and so a
//! new connection with the new client certificate and CA).
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use arc_swap::ArcSwap;
use tonic::codegen::http;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};
use tower::ServiceExt;

/// A lazily connecting mTLS channel to `address`, verifying `server_name`
/// against `ca` and presenting `certificate`/`key` (1 s connect and call
/// bounds, `TCP_NODELAY`), as the permission clients always built it.
pub(crate) fn channel(
    address: &str,
    server_name: &str,
    ca: &[u8],
    certificate: &[u8],
    key: &[u8],
) -> Result<Channel, ()> {
    let tls = ClientTlsConfig::new()
        .domain_name(server_name)
        .ca_certificate(Certificate::from_pem(ca))
        .identity(Identity::from_pem(certificate, key));
    Ok(Endpoint::from_shared(address.to_owned())
        .map_err(|_| ())?
        .connect_timeout(Duration::from_secs(1))
        .timeout(Duration::from_secs(1))
        .tcp_nodelay(true)
        .tls_config(tls)
        .map_err(|_| ())?
        .connect_lazy())
}

/// The current channel, replaceable.
#[derive(Clone)]
pub(crate) struct ReloadingChannel {
    current: Arc<ArcSwap<Channel>>,
    address: Arc<str>,
    server_name: Arc<str>,
}

impl ReloadingChannel {
    pub(crate) fn new(address: &str, server_name: &str, channel: Channel) -> Self {
        Self {
            current: Arc::new(ArcSwap::from_pointee(channel)),
            address: address.into(),
            server_name: server_name.into(),
        }
    }

    /// Build a channel from new material and use it for every later call.
    pub(crate) fn replace(&self, ca: &[u8], certificate: &[u8], key: &[u8]) -> Result<(), ()> {
        let next = channel(&self.address, &self.server_name, ca, certificate, key)?;
        self.current.store(Arc::new(next));
        Ok(())
    }
}

impl tower::Service<http::Request<tonic::body::Body>> for ReloadingChannel {
    type Response = http::Response<tonic::body::Body>;
    type Error = tonic::transport::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // Readiness is the chosen channel's, awaited in `call`.
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: http::Request<tonic::body::Body>) -> Self::Future {
        let channel = (**self.current.load()).clone();
        Box::pin(channel.oneshot(request))
    }
}
