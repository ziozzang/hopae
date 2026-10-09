//! A browser cookie jar: host-only scoping, the `__Host-`/`__Secure-` prefix
//! rules, `Secure`, `Path`, expiry on a virtual clock and `SameSite` semantics
//! (default `Lax`: sent on cross-site requests only for top-level safe
//! navigations). It models what a conforming browser stores and sends, so a
//! test can assert on what a real browser would do with Hopae's cookies.
#![allow(dead_code)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Browsers cap one cookie's name + value at 4096 bytes and keep ~180 per host.
const MAX_COOKIE_BYTES: usize = 4096;
const MAX_COOKIES_PER_HOST: usize = 180;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SameSite {
    Strict,
    Lax,
    None,
}

#[derive(Clone, Debug)]
pub struct Cookie {
    pub name: String,
    pub value: String,
    /// The host the cookie was set from (and, for host-only cookies, is sent to).
    pub host: String,
    /// `Some(domain)` when the cookie carried a `Domain` attribute (not host-only).
    pub domain: Option<String>,
    pub path: String,
    pub secure: bool,
    pub http_only: bool,
    pub same_site: SameSite,
    /// Absolute virtual-clock expiry in ms; `None` = session cookie.
    pub expires_ms: Option<i64>,
    pub created_seq: u64,
}

/// How a request relates to the page that causes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Site {
    /// Same-site request (typed URL, link on the same site, subresource).
    Same,
    /// A top-level navigation arriving from another site (a redirect or link).
    CrossSiteNavigation,
    /// A cross-site subresource, form post or fetch.
    CrossSiteSubresource,
}

#[derive(Clone, Copy, Debug)]
pub struct SendContext {
    pub secure_transport: bool,
    pub site: Site,
    /// GET/HEAD/OPTIONS (safe methods).
    pub safe_method: bool,
}

impl SendContext {
    pub fn navigation(secure: bool) -> Self {
        SendContext {
            secure_transport: secure,
            site: Site::Same,
            safe_method: true,
        }
    }
}

#[derive(Clone, Default)]
pub struct Jar {
    inner: Arc<Mutex<JarState>>,
}

#[derive(Default)]
struct JarState {
    cookies: Vec<Cookie>,
    seq: u64,
    /// Virtual browser time in ms; `None` = the system clock.
    now_ms: Option<i64>,
    /// Set-Cookie headers the jar refused, with the reason (for assertions).
    rejected: Vec<(String, &'static str)>,
}

fn real_now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

impl JarState {
    fn now(&self) -> i64 {
        self.now_ms.unwrap_or_else(real_now_ms)
    }

    fn prune(&mut self) {
        let now = self.now();
        self.cookies
            .retain(|c| c.expires_ms.is_none_or(|e| e > now));
    }
}

fn domain_matches(host: &str, domain: &str) -> bool {
    host == domain || host.ends_with(&format!(".{domain}"))
}

fn path_matches(request_path: &str, cookie_path: &str) -> bool {
    request_path == cookie_path
        || (request_path.starts_with(cookie_path)
            && (cookie_path.ends_with('/') || request_path[cookie_path.len()..].starts_with('/')))
}

fn default_path(request_path: &str) -> String {
    match request_path.rfind('/') {
        Some(0) | None => "/".into(),
        Some(i) => request_path[..i].to_string(),
    }
}

impl Jar {
    pub fn new() -> Self {
        Self::default()
    }

    /// Pin the jar's clock (ms) so `Max-Age` follows a test clock.
    pub fn set_now_ms(&self, ms: i64) {
        self.inner.lock().unwrap().now_ms = Some(ms);
    }

    pub fn advance(&self, d: Duration) {
        let mut s = self.inner.lock().unwrap();
        let now = s.now();
        s.now_ms = Some(now + d.as_millis() as i64);
        s.prune();
    }

    /// Process one `Set-Cookie` header received from `host` for `request_path`.
    /// Returns whether the cookie was stored (a deletion counts as stored).
    pub fn store(
        &self,
        host: &str,
        request_path: &str,
        secure_transport: bool,
        set_cookie: &str,
    ) -> bool {
        let mut s = self.inner.lock().unwrap();
        match parse_and_validate(&s, host, request_path, secure_transport, set_cookie) {
            Err(why) => {
                s.rejected
                    .push((set_cookie.split('=').next().unwrap_or("").to_string(), why));
                false
            }
            Ok(mut c) => {
                s.seq += 1;
                c.created_seq = s.seq;
                // Same (name, host-scope, path) replaces; expiry in the past deletes.
                s.cookies.retain(|o| {
                    !(o.name == c.name
                        && o.host == c.host
                        && o.domain == c.domain
                        && o.path == c.path)
                });
                let now = s.now();
                if c.expires_ms.is_none_or(|e| e > now) {
                    s.cookies.push(c.clone());
                    let same_host: Vec<usize> = s
                        .cookies
                        .iter()
                        .enumerate()
                        .filter(|(_, o)| o.host == c.host)
                        .map(|(i, _)| i)
                        .collect();
                    if same_host.len() > MAX_COOKIES_PER_HOST {
                        let oldest = same_host
                            .into_iter()
                            .min_by_key(|i| s.cookies[*i].created_seq)
                            .unwrap();
                        s.cookies.remove(oldest);
                    }
                }
                true
            }
        }
    }

    /// The `Cookie` request header value for a request to `host` + `path`, if any.
    pub fn header_for(&self, host: &str, path: &str, ctx: SendContext) -> Option<String> {
        let mut s = self.inner.lock().unwrap();
        s.prune();
        let mut chosen: Vec<&Cookie> = s
            .cookies
            .iter()
            .filter(|c| match &c.domain {
                None => c.host == host,
                Some(d) => domain_matches(host, d),
            })
            .filter(|c| path_matches(path, &c.path))
            .filter(|c| !c.secure || ctx.secure_transport)
            .filter(|c| match (c.same_site, ctx.site) {
                (_, Site::Same) => true,
                (SameSite::None, _) => true,
                (SameSite::Lax, Site::CrossSiteNavigation) => ctx.safe_method,
                (SameSite::Lax, _) | (SameSite::Strict, _) => false,
            })
            .collect();
        if chosen.is_empty() {
            return None;
        }
        chosen.sort_by(|a, b| {
            b.path
                .len()
                .cmp(&a.path.len())
                .then(a.created_seq.cmp(&b.created_seq))
        });
        Some(
            chosen
                .iter()
                .map(|c| format!("{}={}", c.name, c.value))
                .collect::<Vec<_>>()
                .join("; "),
        )
    }

    /// A view of what the jar holds for `host` (host-only and matching domain cookies).
    pub fn for_host(&self, host: &str) -> HostJar {
        HostJar {
            jar: self.clone(),
            host: host.to_string(),
        }
    }

    /// Remove everything (a fresh browser profile).
    pub fn clear(&self) {
        self.inner.lock().unwrap().cookies.clear();
    }

    /// `(cookie name, reason)` for every `Set-Cookie` the jar refused so far.
    pub fn rejected(&self) -> Vec<(String, &'static str)> {
        self.inner.lock().unwrap().rejected.clone()
    }

    /// Plant a cookie as page script would (`document.cookie`): never `HttpOnly`,
    /// never `__Host-` unless it satisfies the prefix rules, always host-scoped.
    pub fn script_set(&self, host: &str, name: &str, value: &str, attrs: &str) -> bool {
        self.store(host, "/", true, &format!("{name}={value}; {attrs}"))
    }
}

pub struct HostJar {
    jar: Jar,
    host: String,
}

impl HostJar {
    fn matching(&self) -> Vec<Cookie> {
        let mut s = self.jar.inner.lock().unwrap();
        s.prune();
        s.cookies
            .iter()
            .filter(|c| match &c.domain {
                None => c.host == self.host,
                Some(d) => domain_matches(&self.host, d),
            })
            .cloned()
            .collect()
    }

    pub fn get(&self, name: &str) -> Option<Cookie> {
        self.matching().into_iter().find(|c| c.name == name)
    }

    pub fn value(&self, name: &str) -> Option<String> {
        self.get(name).map(|c| c.value)
    }

    pub fn all(&self) -> Vec<Cookie> {
        self.matching()
    }

    pub fn names(&self) -> Vec<String> {
        self.matching().into_iter().map(|c| c.name).collect()
    }

    /// Cookies page script could read (everything but `HttpOnly`).
    pub fn script_visible(&self) -> Vec<Cookie> {
        self.matching()
            .into_iter()
            .filter(|c| !c.http_only)
            .collect()
    }

    pub fn remove(&self, name: &str) {
        let mut s = self.jar.inner.lock().unwrap();
        s.cookies
            .retain(|c| !(c.name == name && c.host == self.host));
    }

    /// Overwrite a cookie's value in place (a user or script tampering with the jar).
    pub fn set_value(&self, name: &str, value: &str) {
        let mut s = self.jar.inner.lock().unwrap();
        for c in s
            .cookies
            .iter_mut()
            .filter(|c| c.name == name && c.host == self.host)
        {
            c.value = value.to_string();
        }
    }
}

fn parse_and_validate(
    s: &JarState,
    host: &str,
    request_path: &str,
    secure_transport: bool,
    header: &str,
) -> Result<Cookie, &'static str> {
    let mut parts = header.split(';');
    let first = parts.next().ok_or("empty")?;
    let (name, value) = first.split_once('=').ok_or("no name=value")?;
    let (name, value) = (name.trim(), value.trim());
    if name.is_empty() {
        return Err("empty name");
    }
    if name.len() + value.len() > MAX_COOKIE_BYTES {
        return Err("too large");
    }
    let mut c = Cookie {
        name: name.to_string(),
        value: value.to_string(),
        host: host.to_string(),
        domain: None,
        path: default_path(request_path),
        secure: false,
        http_only: false,
        same_site: SameSite::Lax,
        expires_ms: None,
        created_seq: 0,
    };
    let mut max_age: Option<i64> = None;
    for attr in parts {
        let (k, v) = attr
            .split_once('=')
            .map_or((attr.trim(), ""), |(k, v)| (k.trim(), v.trim()));
        match k.to_ascii_lowercase().as_str() {
            "domain" => {
                let d = v.trim_start_matches('.').to_ascii_lowercase();
                if !d.is_empty() {
                    c.domain = Some(d);
                }
            }
            "path" => {
                if v.starts_with('/') {
                    c.path = v.to_string();
                }
            }
            "secure" => c.secure = true,
            "httponly" => c.http_only = true,
            "samesite" => {
                c.same_site = match v.to_ascii_lowercase().as_str() {
                    "strict" => SameSite::Strict,
                    "none" => SameSite::None,
                    _ => SameSite::Lax,
                }
            }
            "max-age" => max_age = v.parse().ok(),
            // `Expires` is date-formatted; a past date is expressed as Max-Age=0 by Hopae.
            _ => {}
        }
    }
    if let Some(d) = &c.domain
        && !domain_matches(host, d)
    {
        return Err("domain does not match the setting host");
    }
    if c.secure && !secure_transport {
        return Err("Secure cookie from an insecure origin");
    }
    if c.same_site == SameSite::None && !c.secure {
        return Err("SameSite=None requires Secure");
    }
    let lower = name.to_ascii_lowercase();
    if lower.starts_with("__secure-") && !c.secure {
        return Err("__Secure- prefix requires Secure");
    }
    if lower.starts_with("__host-") && (!c.secure || c.domain.is_some() || c.path != "/") {
        return Err("__Host- prefix requires Secure, no Domain and Path=/");
    }
    if let Some(ma) = max_age {
        c.expires_ms = Some(s.now() + ma.saturating_mul(1000));
    }
    Ok(c)
}
