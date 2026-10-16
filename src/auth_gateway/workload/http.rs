//! The one HTTPS client shape every Kubernetes workload fetch uses: only the
//! configured CA roots, HTTPS only, no redirects, no environment proxies,
//! bounded bodies, and an optional bearer credential that is either fixed at
//! compile time or re-read from a (projected, rotating) token file per request.
use super::super::runtime::Error;
use anyhow::{Result, ensure};
use std::time::Duration;
use zeroize::Zeroizing;

/// Where the bearer credential for discovery/JWKS/watch requests comes from.
#[derive(Clone)]
pub(crate) enum Bearer {
    None,
    Fixed(reqwest::header::HeaderValue),
    /// Re-read per request: projected ServiceAccount tokens rotate on disk.
    File(std::path::PathBuf),
}

impl std::fmt::Debug for Bearer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Bearer::None => "Bearer::None",
            Bearer::Fixed(_) => "Bearer::Fixed(<redacted>)",
            Bearer::File(_) => "Bearer::File",
        })
    }
}

fn token_material(value: &str) -> bool {
    (16..=8192).contains(&value.len()) && value.bytes().all(|b| b.is_ascii_graphic())
}

impl Bearer {
    pub(crate) fn fixed(value: Zeroizing<String>) -> Result<Self> {
        let trimmed = value.trim();
        ensure!(token_material(trimmed), "invalid Kubernetes API credential");
        let mut header = reqwest::header::HeaderValue::from_str(&format!("Bearer {trimmed}"))?;
        header.set_sensitive(true);
        Ok(Bearer::Fixed(header))
    }
    pub(crate) fn file(path: &str) -> Result<Self> {
        let path = std::path::PathBuf::from(path);
        ensure!(
            path.is_absolute()
                && path.as_os_str().len() <= 512
                && path
                    .components()
                    .all(|c| !matches!(c, std::path::Component::ParentDir)),
            "Kubernetes API token file must be a normalized absolute path"
        );
        Ok(Bearer::File(path))
    }
    fn header(&self) -> Result<Option<reqwest::header::HeaderValue>, Error> {
        match self {
            Bearer::None => Ok(None),
            Bearer::Fixed(value) => Ok(Some(value.clone())),
            Bearer::File(path) => {
                let metadata = std::fs::metadata(path).map_err(|_| Error::Unavailable)?;
                if !metadata.is_file() || metadata.len() > 8192 {
                    return Err(Error::Unavailable);
                }
                let value =
                    Zeroizing::new(std::fs::read_to_string(path).map_err(|_| Error::Unavailable)?);
                let trimmed = value.trim();
                if !token_material(trimmed) {
                    return Err(Error::Unavailable);
                }
                let mut header =
                    reqwest::header::HeaderValue::from_str(&format!("Bearer {trimmed}"))
                        .map_err(|_| Error::Unavailable)?;
                header.set_sensitive(true);
                Ok(Some(header))
            }
        }
    }
}

/// HTTPS client trusting only `ca_pem`.
pub(crate) fn client(ca_pem: &[u8]) -> Result<reqwest::Client> {
    ensure!(
        !ca_pem.is_empty() && ca_pem.len() <= 65536,
        "invalid Kubernetes CA bundle"
    );
    let roots = reqwest::Certificate::from_pem_bundle(ca_pem)?;
    ensure!(
        !roots.is_empty() && roots.len() <= 16,
        "invalid Kubernetes CA bundle"
    );
    let mut builder = reqwest::Client::builder()
        .https_only(true)
        .tls_built_in_root_certs(false)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .pool_idle_timeout(Duration::from_secs(90));
    for root in roots {
        builder = builder.add_root_certificate(root);
    }
    Ok(builder.build()?)
}

/// An HTTPS URL without credentials, query or fragment.
pub(crate) fn https_url(value: &str) -> Result<url::Url> {
    let url = url::Url::parse(value)?;
    ensure!(
        url.scheme() == "https"
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
            && value.len() <= 1024,
        "Kubernetes endpoint must be an HTTPS URL without credentials, query or fragment"
    );
    Ok(url)
}

/// `scheme://host:port` of an URL, for origin allowlists.
pub(crate) fn origin(url: &url::Url) -> String {
    url.origin().ascii_serialization()
}

pub(crate) fn json_content_type(response: &reqwest::Response) -> bool {
    response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|v| {
            let v = v.trim();
            v.eq_ignore_ascii_case("application/json")
                || v.eq_ignore_ascii_case("application/jwk-set+json")
        })
}

/// GET `url` and return the body (status 200, JSON, at most `limit` bytes).
/// Errors are reason codes for metrics; no body is ever logged.
pub(crate) async fn get_json(
    client: &reqwest::Client,
    url: &url::Url,
    bearer: &Bearer,
    accept: &str,
    limit: usize,
    timeout: Duration,
) -> Result<Vec<u8>, &'static str> {
    let mut request = client
        .get(url.clone())
        .timeout(timeout)
        .header(reqwest::header::ACCEPT, accept);
    if let Some(header) = bearer.header().map_err(|_| "credential_unavailable")? {
        request = request.header(reqwest::header::AUTHORIZATION, header);
    }
    let mut response = request.send().await.map_err(|e| {
        if e.is_timeout() {
            "timeout"
        } else {
            "transport"
        }
    })?;
    match response.status().as_u16() {
        200 => {}
        401 | 403 => return Err("unauthorized"),
        404 => return Err("not_found"),
        410 => return Err("gone"),
        300..=399 => return Err("redirect"),
        _ => return Err("status"),
    }
    if !json_content_type(&response) {
        return Err("content_type");
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| "transport")? {
        if body.len() + chunk.len() > limit {
            return Err("too_large");
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Open a streaming GET (a watch). Returns the response after status checks.
pub(crate) async fn open_stream(
    client: &reqwest::Client,
    url: &url::Url,
    bearer: &Bearer,
    accept: &str,
) -> Result<reqwest::Response, &'static str> {
    let mut request = client
        .get(url.clone())
        .header(reqwest::header::ACCEPT, accept);
    if let Some(header) = bearer.header().map_err(|_| "credential_unavailable")? {
        request = request.header(reqwest::header::AUTHORIZATION, header);
    }
    let response = request.send().await.map_err(|_| "transport")?;
    match response.status().as_u16() {
        200 => {}
        401 | 403 => return Err("unauthorized"),
        410 => return Err("gone"),
        _ => return Err("status"),
    }
    if !json_content_type(&response) {
        return Err("content_type");
    }
    Ok(response)
}
