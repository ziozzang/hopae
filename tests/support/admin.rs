//! A client for the admin listener as the gateway presents requests for the
//! console host: the console `Host`, the forwarded address, protocol and
//! host, the handle cookie. It follows no redirects and keeps no jar: the
//! handle is given explicitly.
#![allow(dead_code)]

use std::net::IpAddr;
use std::time::Duration;

use serde_json::Value;

use super::Response;
use super::client::{RawReq, send, send_from};
use super::process::Hopae;

/// What a command-line run printed and returned.
#[derive(Debug, Clone)]
pub struct CliOutput {
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
}

impl CliOutput {
    /// Both streams, for failure messages.
    pub fn all(&self) -> String {
        format!(
            "status {}\nstdout:\n{}\nstderr:\n{}",
            self.status, self.stdout, self.stderr
        )
    }
}

pub struct AdminClient<'a> {
    hopae: &'a Hopae,
    handle: Option<String>,
    lang: Option<&'static str>,
    peer: Option<IpAddr>,
    client_ip: String,
}

impl<'a> AdminClient<'a> {
    pub fn new(hopae: &'a Hopae) -> Self {
        assert!(hopae.admin.is_some(), "the fixture has no admin listener");
        AdminClient {
            hopae,
            handle: None,
            lang: None,
            peer: None,
            client_ip: "192.0.2.10".into(),
        }
    }

    /// Present this handle as the console cookie.
    pub fn with_handle(mut self, h: &str) -> Self {
        self.handle = Some(h.to_string());
        self
    }

    /// Send `accept-language: <l>`.
    pub fn lang(mut self, l: &'static str) -> Self {
        self.lang = Some(l);
        self
    }

    #[allow(clippy::wrong_self_convention)]
    /// Connect from another loopback address than 127.0.0.1 (an untrusted peer).
    pub fn from_peer(mut self, peer: IpAddr) -> Self {
        self.peer = Some(peer);
        self
    }

    /// The client address the gateway forwards (default 192.0.2.10).
    pub fn client_ip(mut self, ip: &str) -> Self {
        self.client_ip = ip.to_string();
        self
    }

    fn base(&self, method: &str, path: &str) -> RawReq {
        let h = self.hopae;
        let host = h.console_host();
        let proto = if h.is_secure() { "https" } else { "http" };
        let mut r = RawReq::new(method, path, &host)
            .header("x-forwarded-host", &host)
            .header("x-forwarded-proto", proto)
            .header("x-forwarded-for", &self.client_ip)
            .timeout(Duration::from_secs(30));
        if let Some(handle) = &self.handle {
            r = r.header("cookie", &format!("{}={handle}", h.cookie_name()));
        }
        if let Some(l) = self.lang {
            r = r.header("accept-language", l);
        }
        r
    }

    fn dispatch(&self, r: RawReq) -> Response {
        let addr = self.hopae.admin.expect("admin listener");
        match self.peer {
            Some(p) => send_from(addr, p, r),
            None => send(addr, r),
        }
    }

    pub fn get(&self, path: &str) -> Response {
        self.get_with(path, &[])
    }

    pub fn get_with(&self, path: &str, extra: &[(&str, &str)]) -> Response {
        let mut r = self.base("GET", path);
        for (k, v) in extra {
            r = r.header(k, v);
        }
        self.dispatch(r)
    }

    /// A JSON mutation: `content-type: application/json` and `x-hopae-admin-request: 1`.
    pub fn post_json(&self, path: &str, body: Value) -> Response {
        self.post_json_raw(
            path,
            &[
                ("content-type", "application/json"),
                ("x-hopae-admin-request", "1"),
            ],
            body.to_string().as_bytes(),
        )
    }

    /// A POST with exactly these headers (besides the gateway's) and body.
    pub fn post_json_raw(&self, path: &str, headers: &[(&str, &str)], body: &[u8]) -> Response {
        let mut r = self.base("POST", path);
        for (k, v) in headers {
            r = r.header(k, v);
        }
        r.body = body.to_vec();
        self.dispatch(r)
    }

    /// An HTML form post; `origin` is sent as the `Origin` header when given.
    pub fn post_form(&self, path: &str, fields: &[(&str, &str)], origin: Option<&str>) -> Response {
        let mut ser = url::form_urlencoded::Serializer::new(String::new());
        for (k, v) in fields {
            ser.append_pair(k, v);
        }
        let mut r = self
            .base("POST", path)
            .header("content-type", "application/x-www-form-urlencoded");
        if let Some(o) = origin {
            r = r.header("origin", o);
        }
        r.body = ser.finish().into_bytes();
        self.dispatch(r)
    }

    /// The `csrf` form field value of a rendered page.
    pub fn csrf_from_page(html: &str) -> Option<String> {
        let at = html.find("name=\"csrf\"")?;
        let tag_start = html[..at].rfind('<')?;
        let tag_end = at + html[at..].find('>')?;
        let tag = &html[tag_start..tag_end];
        let v = tag.find("value=\"")? + "value=\"".len();
        let end = tag[v..].find('"')?;
        Some(tag[v..v + end].to_string())
    }

    /// Follow `next_cursor` to the end and return every item, asserting that
    /// the walk terminates (at most `MAX_WALK_PAGES`; use [`walk_rows`] for the
    /// `rows / limit + rows / window + 1` bound).
    pub fn walk(&self, path: &str) -> Vec<Value> {
        self.walk_bounded(path, MAX_WALK_PAGES)
    }

    /// As [`walk`], asserting at most `rows / limit + rows / 10000 + 1` pages
    /// (`limit` is the `limit=` parameter of `path`, default 50).
    pub fn walk_rows(&self, path: &str, rows: usize) -> Vec<Value> {
        let limit = path
            .split(['?', '&'])
            .find_map(|kv| kv.strip_prefix("limit="))
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(50)
            .max(1);
        self.walk_bounded(path, rows / limit + rows / 10_000 + 1)
    }

    fn walk_bounded(&self, path: &str, max_pages: usize) -> Vec<Value> {
        let mut items = Vec::new();
        let mut cursor: Option<String> = None;
        for page in 1.. {
            assert!(
                page <= max_pages,
                "the walk of {path} did not end within {max_pages} pages"
            );
            let url = match &cursor {
                None => path.to_string(),
                Some(c) => {
                    let sep = if path.contains('?') { '&' } else { '?' };
                    let enc =
                        url::form_urlencoded::byte_serialize(c.as_bytes()).collect::<String>();
                    format!("{path}{sep}cursor={enc}")
                }
            };
            let r = self.get(&url);
            assert_eq!(r.status, 200, "GET {url}: {}", r.body);
            let j = r.json();
            items.extend(j["items"].as_array().cloned().unwrap_or_default());
            match j["next_cursor"].as_str() {
                Some(c) => cursor = Some(c.to_string()),
                None => break,
            }
        }
        items
    }
}

/// Upper bound on pages of an unbounded [`AdminClient::walk`].
pub const MAX_WALK_PAGES: usize = 20_000;
