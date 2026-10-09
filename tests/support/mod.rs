//! Shared helpers for integration tests: config writing and a tiny loopback
//! HTTP/1.1 client (no network beyond loopback, no extra dependencies).
#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::SocketAddr;
use std::path::Path;

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
