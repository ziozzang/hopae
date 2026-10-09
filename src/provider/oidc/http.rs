//! Outbound HTTP for the OIDC client: no redirects, a hard total timeout and
//! a response-size cap. Nothing here logs a URL query, a header value or a
//! body, so no secret or token can reach a log through this module.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use reqwest::redirect::Policy;

use crate::provider::types::ProviderError;

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
    allow_private: bool,
}

impl Fetcher {
    /// `allow_private` lifts the address vetting (loopback, private, ...);
    /// redirects are never followed either way.
    pub fn new(allow_private: bool) -> Fetcher {
        // A failure to build the client (TLS backend initialisation) is a
        // programming or platform error; fall back to a client that still
        // refuses redirects rather than panicking on the request path.
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
        let client = builder.build().unwrap_or_default();
        Fetcher {
            client,
            allow_private,
        }
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
        let mut resp = self.client.execute(request).await.map_err(classify)?;
        let status = resp.status().as_u16();
        let content_type = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_ascii_lowercase());
        if resp
            .content_length()
            .is_some_and(|n| n > MAX_BODY_BYTES as u64)
        {
            return Err(ProviderError::ProviderResponseTooLarge);
        }
        let mut body = Vec::new();
        while let Some(chunk) = resp.chunk().await.map_err(classify)? {
            if body.len() + chunk.len() > MAX_BODY_BYTES {
                return Err(ProviderError::ProviderResponseTooLarge);
            }
            body.extend_from_slice(&chunk);
        }
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
