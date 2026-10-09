//! Outbound HTTP for the OIDC client: no redirects, a hard total timeout and
//! a response-size cap. Nothing here logs a URL query, a header value or a
//! body, so no secret or token can reach a log through this module.

use std::time::Duration;

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

#[derive(Clone)]
pub struct Fetcher {
    client: reqwest::Client,
}

impl Fetcher {
    pub fn new() -> Fetcher {
        // A failure to build the client (TLS backend initialisation) is a
        // programming or platform error; fall back to a client that still
        // refuses redirects rather than panicking on the request path.
        let client = reqwest::Client::builder()
            .redirect(Policy::none())
            .timeout(REQUEST_TIMEOUT)
            .connect_timeout(REQUEST_TIMEOUT)
            .user_agent(concat!("hopae/", env!("CARGO_PKG_VERSION")))
            .build()
            .unwrap_or_default();
        Fetcher { client }
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
        let mut resp = req.send().await.map_err(classify)?;
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

impl Default for Fetcher {
    fn default() -> Self {
        Fetcher::new()
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

/// `https`, or `http` to a loopback host (a local test provider), without
/// userinfo or fragment. Applied to every endpoint taken from a discovery
/// document before it is called.
pub fn endpoint_allowed(u: &url::Url) -> bool {
    if !u.username().is_empty() || u.password().is_some() || u.fragment().is_some() {
        return false;
    }
    match (u.scheme(), u.host()) {
        ("https", Some(_)) => true,
        ("http", Some(url::Host::Ipv4(ip))) => ip.is_loopback(),
        ("http", Some(url::Host::Ipv6(ip))) => ip.is_loopback(),
        ("http", Some(url::Host::Domain("localhost"))) => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_rules() {
        let ok = |s: &str| endpoint_allowed(&url::Url::parse(s).unwrap());
        assert!(ok("https://accounts.google.com/o/oauth2/v2/auth"));
        assert!(ok("http://127.0.0.1:9/token"));
        assert!(ok("http://localhost/token"));
        assert!(!ok("http://example.org/token"));
        assert!(!ok("https://user:pw@example.org/token"));
        assert!(!ok("https://example.org/token#frag"));
        assert!(!ok("ftp://example.org/token"));
    }
}
