//! Outbound HTTP for the OIDC client: no redirects, a hard total timeout and
//! a response-size cap. Nothing here logs a URL query, a header value or a
//! body, so no secret or token can reach a log through this module.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use reqwest::redirect::Policy;

use crate::auth_gateway::breaker::{Breaker, Permit};
use crate::provider::types::ProviderError;

struct Circuits {
    started: Instant,
    by_origin: Mutex<HashMap<String, Breaker>>,
}
impl Circuits {
    fn now(&self) -> u64 {
        self.started.elapsed().as_millis().min(u64::MAX as u128) as u64
    }
    fn admit(self: &Arc<Self>, url: &url::Url) -> Result<Exchange, ProviderError> {
        // Origin excludes paths, queries, credentials and authorization codes.
        let origin = url.origin().ascii_serialization();
        let mut circuits = self
            .by_origin
            .lock()
            .map_err(|_| ProviderError::ProviderUnavailable)?;
        if !circuits.contains_key(&origin) {
            if circuits.len() >= 16 {
                return Err(ProviderError::ProviderUnavailable);
            }
            circuits.insert(
                origin.clone(),
                Breaker::new(3, 30_000).expect("constant circuit bounds"),
            );
        }
        let permit = circuits
            .get_mut(&origin)
            .unwrap()
            .admit(self.now())
            .ok_or(ProviderError::ProviderUnavailable)?;
        Ok(Exchange {
            circuits: self.clone(),
            origin,
            permit: Some(permit),
        })
    }
}
struct Exchange {
    circuits: Arc<Circuits>,
    origin: String,
    permit: Option<Permit>,
}
impl Exchange {
    fn finish(mut self, failed: bool) {
        self.record(failed);
    }
    fn record(&mut self, failed: bool) {
        if let Some(permit) = self.permit.take()
            && let Ok(mut circuits) = self.circuits.by_origin.lock()
            && let Some(circuit) = circuits.get_mut(&self.origin)
        {
            if failed {
                circuit.backend_failure(permit, self.circuits.now());
            } else {
                circuit.healthy(permit);
            }
        }
    }
}
impl Drop for Exchange {
    fn drop(&mut self) {
        // Cancellation and early transport/body errors release a half-open probe.
        self.record(true);
    }
}

/// Total time for one outbound request, body included.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// Largest response body accepted from a provider.
pub const MAX_BODY_BYTES: usize = 64 * 1024;

/// A completed exchange: status and the capped body.
pub struct Response {
    pub status: u16,
    pub content_type: Option<String>,
    pub body: Vec<u8>,
}

/// Resolves names itself and drops every address the policy forbids, so the
/// connection can only go to a vetted address: the answer used for the check
/// is the answer connected to (no second lookup to race, G7-IDP-03).
struct VettingResolver;

impl Resolve for VettingResolver {
    fn resolve(&self, name: Name) -> Resolving {
        Box::pin(async move {
            let found = tokio::net::lookup_host((name.as_str(), 0)).await?;
            let kept: Vec<SocketAddr> = found.filter(|a| addr_allowed(a.ip())).collect();
            if kept.is_empty() {
                return Err("no permitted address".into());
            }
            Ok(Box::new(kept.into_iter()) as Addrs)
        })
    }
}

#[derive(Clone)]
pub struct Fetcher {
    client: reqwest::Client,
    ready: bool,
    allow_private: bool,
    circuits: Arc<Circuits>,
}

impl Fetcher {
    /// `allow_private` lifts the address vetting (loopback, private, ...);
    /// redirects are never followed either way.
    pub fn new(allow_private: bool) -> Fetcher {
        // A failed TLS/client initialization fences every send. The fallback
        // only constructs request builders; it must never perform an exchange.
        let mut builder = reqwest::Client::builder()
            // No automatic environment proxy (HTTP_PROXY, HTTPS_PROXY, ALL_PROXY):
            // a proxy resolves the destination itself, which would bypass the
            // address vetting below (G7-IDP-03).
            .no_proxy()
            .redirect(Policy::none())
            .timeout(REQUEST_TIMEOUT)
            .connect_timeout(REQUEST_TIMEOUT)
            .user_agent(concat!("hopae/", env!("CARGO_PKG_VERSION")));
        if !allow_private {
            builder = builder.dns_resolver(std::sync::Arc::new(VettingResolver));
        }
        let (client, ready) = match builder.build() {
            Ok(client) => (client, true),
            Err(_) => (reqwest::Client::default(), false),
        };
        Fetcher {
            client,
            ready,
            allow_private,
            circuits: Arc::new(Circuits {
                started: Instant::now(),
                by_origin: Mutex::new(HashMap::new()),
            }),
        }
    }

    /// Dedicated HTTPS verifier client. Caller admission bounds active requests;
    /// idle connections are capped and expire. Optional roots add operator trust
    /// without disabling certificate or server-name verification.
    pub fn for_verifier(
        allow_private: bool,
        timeout: Duration,
        roots: Vec<reqwest::Certificate>,
    ) -> Result<Self, ProviderError> {
        let mut builder = reqwest::Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(Policy::none())
            .timeout(timeout)
            .connect_timeout(timeout)
            .pool_max_idle_per_host(64)
            .pool_idle_timeout(Duration::from_secs(30))
            .user_agent(concat!("hopae/", env!("CARGO_PKG_VERSION")));
        if !allow_private {
            builder = builder.dns_resolver(Arc::new(VettingResolver));
        }
        for root in roots {
            builder = builder.add_root_certificate(root);
        }
        Ok(Self {
            client: builder
                .build()
                .map_err(|_| ProviderError::ProviderUnavailable)?,
            ready: true,
            allow_private,
            circuits: Arc::new(Circuits {
                started: Instant::now(),
                by_origin: Mutex::new(HashMap::new()),
            }),
        })
    }

    pub fn get(&self, url: &url::Url) -> reqwest::RequestBuilder {
        self.client.get(url.clone())
    }

    pub fn post(&self, url: &url::Url) -> reqwest::RequestBuilder {
        self.client.post(url.clone())
    }

    /// Send and read at most [`MAX_BODY_BYTES`]. A 3xx answer is returned as
    /// is (never followed); the caller decides what it means.
    pub async fn send(&self, req: reqwest::RequestBuilder) -> Result<Response, ProviderError> {
        self.send_bounded(req, MAX_BODY_BYTES).await
    }

    /// Apply a stricter protocol-specific limit before buffering the body.
    pub async fn send_bounded(
        &self,
        req: reqwest::RequestBuilder,
        limit: usize,
    ) -> Result<Response, ProviderError> {
        if !self.ready || limit == 0 || limit > MAX_BODY_BYTES {
            return Err(ProviderError::ProviderUnavailable);
        }
        let request = req.build().map_err(classify)?;
        // An address literal bypasses name resolution, so it is vetted here.
        let literal = match request.url().host() {
            Some(url::Host::Ipv4(ip)) => Some(IpAddr::V4(ip)),
            Some(url::Host::Ipv6(ip)) => Some(IpAddr::V6(ip)),
            _ => None,
        };
        if !self.allow_private && literal.is_some_and(|ip| !addr_allowed(ip)) {
            return Err(ProviderError::ProviderUnavailable);
        }
        let exchange = self.circuits.admit(request.url())?;
        let mut resp = self.client.execute(request).await.map_err(classify)?;
        let status = resp.status().as_u16();
        let content_type = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_ascii_lowercase());
        if resp.content_length().is_some_and(|n| n > limit as u64) {
            return Err(ProviderError::ProviderResponseTooLarge);
        }
        let mut body = Vec::new();
        while let Some(chunk) = resp.chunk().await.map_err(classify)? {
            if body.len() + chunk.len() > limit {
                return Err(ProviderError::ProviderResponseTooLarge);
            }
            body.extend_from_slice(&chunk);
        }
        // Ordinary credential denial (400/401/403) is a reachable provider,
        // not a backend outage. Rate limiting and server errors trip the circuit.
        exchange.finish(status == 429 || status >= 500);
        Ok(Response {
            status,
            content_type,
            body,
        })
    }
}

/// Transport errors carry URLs in their `Display`; only the class is kept.
fn classify(e: reqwest::Error) -> ProviderError {
    if e.is_timeout() {
        ProviderError::ProviderTimeout
    } else if e.is_connect() || e.is_request() {
        ProviderError::ProviderUnavailable
    } else if e.is_body() || e.is_decode() {
        // A body that dies mid-stream is a malformed answer, not an outage.
        ProviderError::ProviderResponseInvalid
    } else {
        ProviderError::ProviderUnavailable
    }
}

/// Whether a destination address may be dialled. Refused unless the operator
/// opted in: loopback, private (RFC 1918, unique-local), link-local, CGNAT
/// (100.64/10), multicast, unspecified, broadcast and the other reserved
/// blocks that never hold a public identity provider. IPv4-mapped and NAT64
/// IPv6 addresses are judged by the IPv4 address they carry.
pub fn addr_allowed(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4_allowed(v4),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return v4_allowed(v4);
            }
            let seg = v6.segments();
            // 64:ff9b::/96 (NAT64) embeds an IPv4 address in its last 32 bits.
            if seg[0] == 0x64 && seg[1] == 0xff9b && seg[2..6].iter().all(|s| *s == 0) {
                let [a, b] = seg[6].to_be_bytes();
                let [c, d] = seg[7].to_be_bytes();
                return v4_allowed(Ipv4Addr::new(a, b, c, d));
            }
            !(v6.is_unspecified()
                || v6.is_loopback()
                || v6.is_multicast()
                || (seg[0] & 0xffc0) == 0xfe80 // link-local fe80::/10
                || (seg[0] & 0xfe00) == 0xfc00) // unique-local fc00::/7
        }
    }
}

fn v4_allowed(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || o[0] == 0
        || (o[0] == 100 && (o[1] & 0xc0) == 64) // CGNAT 100.64.0.0/10
        || (o[0] == 192 && o[1] == 0 && o[2] == 0) // IETF protocol assignments
        || (o[0] == 198 && (o[1] & 0xfe) == 18) // benchmarking 198.18.0.0/15
        || o[0] >= 240) // reserved 240.0.0.0/4
}

/// Which destinations the client may call (G7-IDP-03): the issuer's host and
/// the operator's `endpoint_hosts`, over `https`; loopback `http` and
/// private addresses only when the provider opts in with
/// `allow_private_endpoints` (or the `test-hooks` build default).
#[derive(Clone, Debug)]
pub struct EndpointPolicy {
    issuer_host: Option<String>,
    hosts: Vec<String>,
    allow_private: bool,
}

fn host_key(u: &url::Url) -> Option<String> {
    u.host_str()
        .map(|h| h.trim_matches(['[', ']']).to_ascii_lowercase())
}

impl EndpointPolicy {
    pub fn new(issuer: &str, endpoint_hosts: &[String], allow_private: bool) -> EndpointPolicy {
        EndpointPolicy {
            issuer_host: url::Url::parse(issuer).ok().as_ref().and_then(host_key),
            hosts: endpoint_hosts
                .iter()
                .map(|h| h.trim().trim_matches(['[', ']']).to_ascii_lowercase())
                .collect(),
            allow_private,
        }
    }

    pub fn allow_private(&self) -> bool {
        self.allow_private
    }

    /// The scheme and destination rules, without host membership: used for
    /// the issuer and for every endpoint. `https`, or `http` to a loopback
    /// host when private endpoints are allowed; no userinfo, no fragment;
    /// an address literal must be dialable.
    pub fn url_ok(&self, u: &url::Url) -> bool {
        if !u.username().is_empty() || u.password().is_some() || u.fragment().is_some() {
            return false;
        }
        let loopback = match u.host() {
            Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
            Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
            Some(url::Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
            None => return false,
        };
        let scheme_ok = match u.scheme() {
            "https" => true,
            "http" => self.allow_private && loopback,
            _ => false,
        };
        let literal_ok = match u.host() {
            Some(url::Host::Ipv4(ip)) => self.allow_private || addr_allowed(IpAddr::V4(ip)),
            Some(url::Host::Ipv6(ip)) => self.allow_private || addr_allowed(IpAddr::V6(ip)),
            _ => true,
        };
        scheme_ok && literal_ok
    }

    /// An endpoint taken from a discovery document: [`Self::url_ok`], and its
    /// host is the issuer's or listed by the operator.
    pub fn endpoint_ok(&self, u: &url::Url) -> bool {
        if !self.url_ok(u) {
            return false;
        }
        let Some(h) = host_key(u) else {
            return false;
        };
        self.issuer_host.as_deref() == Some(h.as_str()) || self.hosts.contains(&h)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn failed_client_initialization_never_uses_a_fallback_transport() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = url(&format!("http://{}/", listener.local_addr().unwrap()));
        let mut fetcher = Fetcher::new(true);
        fetcher.ready = false;
        assert!(matches!(
            fetcher.send(fetcher.get(&endpoint)).await,
            Err(ProviderError::ProviderUnavailable)
        ));
        assert!(
            tokio::time::timeout(Duration::from_millis(30), listener.accept())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn actual_provider_outages_trip_but_credential_denial_does_not() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        for (status, calls) in [(503, 3), (429, 3), (401, 5), (403, 5)] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let endpoint = url(&format!("http://{}/token", listener.local_addr().unwrap()));
            let server = tokio::spawn(async move {
                for _ in 0..calls {
                    let (mut stream, _) =
                        tokio::time::timeout(Duration::from_secs(2), listener.accept())
                            .await
                            .unwrap()
                            .unwrap();
                    let mut request = [0; 4096];
                    let received = stream.read(&mut request).await.unwrap();
                    assert!(received > 0, "owned client sent a request");
                    let response = format!(
                        "HTTP/1.1 {status} Test\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}"
                    );
                    stream.write_all(response.as_bytes()).await.unwrap();
                }
                listener
            });
            let fetcher = Fetcher::new(true);
            for _ in 0..calls {
                assert_eq!(
                    fetcher.send(fetcher.get(&endpoint)).await.unwrap().status,
                    status
                );
            }
            let listener = server.await.unwrap();
            if status == 503 || status == 429 {
                assert!(matches!(
                    fetcher.send(fetcher.get(&endpoint)).await,
                    Err(ProviderError::ProviderUnavailable)
                ));
                assert!(
                    tokio::time::timeout(Duration::from_millis(30), listener.accept())
                        .await
                        .is_err()
                );
            } else {
                let origin = endpoint.origin().ascii_serialization();
                assert_eq!(
                    fetcher.circuits.by_origin.lock().unwrap()[&origin].state(),
                    crate::auth_gateway::breaker::State::Closed
                );
            }
        }
    }

    #[test]
    fn cancelled_exchanges_count_failures_and_endpoint_state_is_bounded() {
        let circuits = Arc::new(Circuits {
            started: Instant::now(),
            by_origin: Mutex::new(HashMap::new()),
        });
        let endpoint = url("https://issuer.example.test/token?code=private");
        for _ in 0..3 {
            drop(circuits.admit(&endpoint).unwrap());
        }
        assert!(circuits.admit(&endpoint).is_err());
        assert_eq!(
            circuits.by_origin.lock().unwrap().keys().next().unwrap(),
            "https://issuer.example.test"
        );
        for port in 1..16 {
            circuits
                .admit(&url(&format!("https://issuer.example.test:{port}/")))
                .unwrap()
                .finish(false);
        }
        assert!(
            circuits
                .admit(&url("https://another.example.test/"))
                .is_err()
        );
    }

    fn url(s: &str) -> url::Url {
        url::Url::parse(s).unwrap()
    }

    #[test]
    fn address_classes() {
        let ok = |s: &str| addr_allowed(s.parse().unwrap());
        for public in [
            "8.8.8.8",
            "142.250.80.46",
            "2606:4700:4700::1111",
            "203.0.113.7",
        ] {
            assert!(ok(public), "{public}");
        }
        for blocked in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "100.127.255.255",
            "224.0.0.1",
            "0.0.0.0",
            "255.255.255.255",
            "198.18.0.1",
            "240.0.0.1",
            "::",
            "::1",
            "fe80::1",
            "fc00::1",
            "fd12:3456::1",
            "ff02::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "64:ff9b::7f00:1",
        ] {
            assert!(!ok(blocked), "{blocked}");
        }
        // Just outside the CGNAT and private blocks.
        assert!(ok("100.128.0.1") && ok("172.32.0.1") && ok("11.0.0.1"));
    }

    #[test]
    fn scheme_and_literal_rules() {
        let strict = EndpointPolicy::new("https://idp.example.test", &[], false);
        assert!(strict.url_ok(&url("https://accounts.google.com/o/oauth2/v2/auth")));
        assert!(!strict.url_ok(&url("http://127.0.0.1:9/token")));
        assert!(!strict.url_ok(&url("http://localhost/token")));
        assert!(!strict.url_ok(&url("https://127.0.0.1/token")));
        assert!(!strict.url_ok(&url("https://169.254.169.254/latest")));
        assert!(!strict.url_ok(&url("https://[::1]/token")));
        assert!(!strict.url_ok(&url("http://example.org/token")));
        assert!(!strict.url_ok(&url("https://user:pw@example.org/token")));
        assert!(!strict.url_ok(&url("https://example.org/token#frag")));
        assert!(!strict.url_ok(&url("ftp://example.org/token")));
        let dev = EndpointPolicy::new("http://127.0.0.1:9", &[], true);
        assert!(dev.url_ok(&url("http://127.0.0.1:9/token")));
        assert!(dev.url_ok(&url("http://localhost/token")));
        assert!(dev.url_ok(&url("https://10.0.0.5/token")));
        // http is for loopback only, whatever the opt-in.
        assert!(!dev.url_ok(&url("http://10.0.0.5/token")));
        assert!(!dev.url_ok(&url("http://example.org/token")));
    }

    #[test]
    fn endpoint_hosts_are_the_issuers_or_listed() {
        let p = EndpointPolicy::new(
            "https://accounts.example.test",
            &["Oauth2.Example.Test".to_string()],
            false,
        );
        assert!(p.endpoint_ok(&url("https://accounts.example.test/token")));
        assert!(p.endpoint_ok(&url("https://ACCOUNTS.example.test:8443/token")));
        assert!(p.endpoint_ok(&url("https://oauth2.example.test/certs")));
        assert!(!p.endpoint_ok(&url("https://evil.example.test/token")));
        assert!(!p.endpoint_ok(&url("https://sub.accounts.example.test/token")));
        assert!(!p.endpoint_ok(&url("http://accounts.example.test/token")));
    }

    #[tokio::test]
    async fn resolved_addresses_are_vetted_at_connect_time() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let u = url(&format!("http://localhost:{port}/"));
        // A name that resolves to loopback is not dialled by default ...
        let strict = Fetcher::new(false);
        let r = strict.send(strict.get(&u)).await;
        assert!(
            matches!(r, Err(ProviderError::ProviderUnavailable)),
            "{:?}",
            r.err()
        );
        assert!(listener.accept().is_err(), "no connection was made");
        // ... nor is a loopback literal.
        let lit = url(&format!("http://127.0.0.1:{port}/"));
        let r = strict.send(strict.get(&lit)).await;
        assert!(matches!(r, Err(ProviderError::ProviderUnavailable)));
        assert!(listener.accept().is_err(), "no connection was made");
        // The opt-in dials it.
        let open = Fetcher::new(true);
        let _ = tokio::time::timeout(Duration::from_millis(500), open.send(open.get(&lit))).await;
        assert!(listener.accept().is_ok(), "the allowed fetcher connected");
    }
}
