//! Shared helpers for integration tests: config writing and a tiny loopback
//! HTTP/1.1 client (no network beyond loopback, no extra dependencies).
#![allow(dead_code, unused_imports)]

use std::io::{Read, Write};
use std::net::SocketAddr;
use std::path::Path;

pub mod admin;
pub mod client;
pub mod echo;
pub mod gateway;
pub mod jar;
pub mod mock_idp;
pub mod process;
pub mod server;

pub use admin::{AdminClient, CliOutput};
pub use client::{Client, RawReq, Req};
pub use echo::Echo;
pub use jar::{Jar, SameSite, SendContext, Site};
pub use mock_idp::MockIdp;
pub use process::{Fixture, Hooks, Hopae, KeySlot, VerifyRequest};
pub use server::RecordedRequest;

pub const KEY_ENV: &str = "HOPAE_TEST_GATEWAY_KEY";

/// A valid configuration on ephemeral loopback ports inside `state`.
pub fn config_json(state: &Path) -> String {
    format!(
        r#"{{
  "listen": {{"portal": "127.0.0.1:0", "gateway": "127.0.0.1:0"}},
  "state_dir": {state:?},
  "portal": {{"public_url": "https://auth.example.test"}},
  "gateway": {{"kind": "hangang", "caller_key_env": "{KEY_ENV}"}}
}}"#,
        state = state.join("state").display().to_string()
    )
}

pub fn write_config(dir: &Path, json: &str) -> std::path::PathBuf {
    let p = dir.join("hopae.json");
    std::fs::write(&p, json).unwrap();
    p
}

pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl Response {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    /// Every value of a header that may repeat (`set-cookie`), in order.
    pub fn header_all(&self, name: &str) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
            .collect()
    }

    pub fn location(&self) -> Option<&str> {
        self.header("location")
    }

    pub fn set_cookies(&self) -> Vec<&str> {
        self.header_all("set-cookie")
    }

    /// The body parsed as JSON; panics (a test failure) when it is not.
    pub fn json(&self) -> serde_json::Value {
        serde_json::from_str(&self.body)
            .unwrap_or_else(|e| panic!("response body is not JSON ({e}): {:.200}", self.body))
    }
}

impl std::fmt::Debug for Response {
    /// Status and header names only: values can carry cookies, bodies can carry tokens.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Response")
            .field("status", &self.status)
            .field(
                "headers",
                &self
                    .headers
                    .iter()
                    .map(|(k, _)| k.as_str())
                    .collect::<Vec<_>>(),
            )
            .field("body_len", &self.body.len())
            .finish()
    }
}

/// Blocking GET with `Connection: close`.
pub fn get(addr: SocketAddr, path: &str) -> Response {
    let mut s = std::net::TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .unwrap();
    write!(
        s,
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut raw = String::new();
    s.read_to_string(&mut raw).unwrap();
    let (head, body) = raw.split_once("\r\n\r\n").unwrap();
    let mut lines = head.lines();
    let status = lines
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    Response {
        status,
        headers,
        body: body.to_string(),
    }
}
