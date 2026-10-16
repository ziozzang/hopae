//! Native client endpoint: fixed PEM material ([`EndpointConfig`]) or a
//! caller-owned, reloadable rustls client configuration
//! ([`ReloadableEndpointConfig`]).
//!
//! With a reloadable source, every new HTTP/2 connection asks the source for
//! the current [`rustls::ClientConfig`], so a rotated client certificate, key
//! or CA is used by the next connection without rebuilding the client or
//! restarting the process. Established connections keep the configuration
//! they were made with. The source is called on the connection path only and
//! must be cheap (for example an `ArcSwap` load).
use std::{sync::Arc, time::Duration};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};

/// Current client TLS configuration (client certificate, key and trust roots).
/// The SDK enforces the `h2` ALPN protocol and the configured server name.
pub type ClientConfigSource = Arc<dyn Fn() -> Arc<rustls::ClientConfig> + Send + Sync>;

/// Fixed PEM material, read once (the original constructor input).
pub struct EndpointConfig<'a> {
    pub address: &'a str,
    pub server_name: &'a str,
    pub ca: &'a [u8],
    pub certificate: &'a [u8],
    pub private_key: &'a [u8],
    pub caller_key: &'a str,
}

/// Reloadable TLS: `tls` is consulted for every new connection.
pub struct ReloadableEndpointConfig<'a> {
    pub address: &'a str,
    pub server_name: &'a str,
    pub tls: ClientConfigSource,
    pub caller_key: &'a str,
}

enum Tls<'a> {
    Pem {
        ca: &'a [u8],
        certificate: &'a [u8],
        private_key: &'a [u8],
    },
    Source(ClientConfigSource),
}

/// Constructor input of the observed clients; built from either config type.
pub struct ClientEndpoint<'a> {
    pub(crate) address: &'a str,
    pub(crate) server_name: &'a str,
    pub(crate) caller_key: &'a str,
    tls: Tls<'a>,
}
impl<'a> From<EndpointConfig<'a>> for ClientEndpoint<'a> {
    fn from(c: EndpointConfig<'a>) -> Self {
        Self {
            address: c.address,
            server_name: c.server_name,
            caller_key: c.caller_key,
            tls: Tls::Pem {
                ca: c.ca,
                certificate: c.certificate,
                private_key: c.private_key,
            },
        }
    }
}
impl<'a> From<ReloadableEndpointConfig<'a>> for ClientEndpoint<'a> {
    fn from(c: ReloadableEndpointConfig<'a>) -> Self {
        Self {
            address: c.address,
            server_name: c.server_name,
            caller_key: c.caller_key,
            tls: Tls::Source(c.tls),
        }
    }
}

impl ClientEndpoint<'_> {
    /// Shared address, server name, material and caller key bounds.
    pub(crate) fn valid(&self, concurrent: usize, timeout: Duration) -> bool {
        let Ok(uri) = self.address.parse::<tonic::codegen::http::Uri>() else {
            return false;
        };
        let material = match &self.tls {
            Tls::Pem {
                ca,
                certificate,
                private_key,
            } => [ca, certificate, private_key]
                .iter()
                .all(|b| !b.is_empty() && b.len() <= 128 * 1024),
            Tls::Source(_) => true,
        };
        self.address.len() <= 256
            && uri.scheme_str() == Some("https")
            && uri.authority().is_some_and(|a| !a.as_str().contains('@'))
            && uri.path_and_query().is_none_or(|p| p.as_str() == "/")
            && uri.port_u16() != Some(0)
            && !self.server_name.is_empty()
            && self.server_name.len() <= 253
            && self
                .server_name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".-".contains(&b))
            && material
            && (32..=256).contains(&self.caller_key.len())
            && self.caller_key.bytes().all(|b| b.is_ascii_graphic())
            && (1..=1024).contains(&concurrent)
            && timeout >= Duration::from_millis(1)
            && timeout <= Duration::from_secs(1)
    }
    /// Lazy channel; callers validate first.
    pub(crate) fn channel(&self, timeout: Duration) -> Result<Channel, ()> {
        match &self.tls {
            Tls::Pem {
                ca,
                certificate,
                private_key,
            } => {
                let tls = ClientTlsConfig::new()
                    .domain_name(self.server_name)
                    .ca_certificate(Certificate::from_pem(ca))
                    .identity(Identity::from_pem(certificate, private_key));
                Ok(Endpoint::from_shared(self.address.to_owned())
                    .map_err(|_| ())?
                    .connect_timeout(timeout)
                    .timeout(timeout)
                    .tls_config(tls)
                    .map_err(|_| ())?
                    .connect_lazy())
            }
            Tls::Source(source) => {
                let server_name =
                    rustls::pki_types::ServerName::try_from(self.server_name.to_owned())
                        .map_err(|_| ())?;
                // TLS is done by the connector; tonic refuses an `https` URI
                // without its own TLS config, so dial the `http` form and keep
                // `https` as the request origin.
                let origin: tonic::codegen::http::Uri = self.address.parse().map_err(|_| ())?;
                let dial = format!("http://{}", &self.address["https://".len()..]);
                Ok(Endpoint::from_shared(dial)
                    .map_err(|_| ())?
                    .origin(origin)
                    .connect_timeout(timeout)
                    .timeout(timeout)
                    .connect_with_connector_lazy(Connector {
                        source: source.clone(),
                        server_name,
                    }))
            }
        }
    }
}

/// TCP + TLS connector reading the current configuration per connection.
#[derive(Clone)]
struct Connector {
    source: ClientConfigSource,
    server_name: rustls::pki_types::ServerName<'static>,
}
type Stream = hyper_util::rt::TokioIo<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>;
impl tower_service::Service<tonic::codegen::http::Uri> for Connector {
    type Response = Stream;
    type Error = std::io::Error;
    type Future =
        std::pin::Pin<Box<dyn std::future::Future<Output = Result<Stream, std::io::Error>> + Send>>;
    fn poll_ready(
        &mut self,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        std::task::Poll::Ready(Ok(()))
    }
    fn call(&mut self, uri: tonic::codegen::http::Uri) -> Self::Future {
        let mut config = (self.source)();
        if config.alpn_protocols != [b"h2".to_vec()] {
            let mut owned = (*config).clone();
            owned.alpn_protocols = vec![b"h2".to_vec()];
            config = Arc::new(owned);
        }
        let server_name = self.server_name.clone();
        Box::pin(async move {
            let host = uri
                .host()
                .ok_or_else(|| std::io::Error::other("missing host"))?
                .trim_matches(['[', ']'])
                .to_owned();
            let port = uri.port_u16().unwrap_or(443);
            let tcp = tokio::net::TcpStream::connect((host.as_str(), port)).await?;
            tcp.set_nodelay(true)?;
            let tls = tokio_rustls::TlsConnector::from(config)
                .connect(server_name, tcp)
                .await?;
            if tls.get_ref().1.alpn_protocol() != Some(b"h2") {
                return Err(std::io::Error::other("server did not select h2"));
            }
            Ok(hyper_util::rt::TokioIo::new(tls))
        })
    }
}
