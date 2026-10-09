//! A blocking HTTP/1.1 client over a plain socket (loopback only), and a
//! browser-like `Client` that applies a cookie `Jar`, never follows redirects
//! and stamps the headers a trusted proxy would add.
#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use super::Response;
use super::jar::{Jar, SendContext, Site};

pub struct RawReq {
    pub method: String,
    pub path: String,
    /// Header lines to send; the caller supplies `host`.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub timeout: Duration,
}

impl RawReq {
    pub fn new(method: &str, path: &str, host: &str) -> Self {
        RawReq {
            method: method.into(),
            path: path.into(),
            headers: vec![("host".into(), host.into())],
            body: Vec::new(),
            timeout: Duration::from_secs(30),
        }
    }

    pub fn header(mut self, k: &str, v: &str) -> Self {
        self.headers.push((k.into(), v.into()));
        self
    }

    pub fn timeout(mut self, d: Duration) -> Self {
        self.timeout = d;
        self
    }
}

/// Send one request with `Connection: close` and read the whole response.
/// Panics on socket errors: a harness failure, not a test result.
pub fn send(addr: SocketAddr, req: RawReq) -> Response {
    try_send(addr, req).unwrap_or_else(|e| panic!("request to {addr} failed: {e}"))
}

pub fn try_send(addr: SocketAddr, req: RawReq) -> std::io::Result<Response> {
    try_send_from(addr, None, req)
}

/// As [`send`], connecting from the loopback address `source` (another peer
/// than the usual 127.0.0.1: every 127.0.0.0/8 address is local on Linux).
pub fn send_from(addr: SocketAddr, source: IpAddr, req: RawReq) -> Response {
    try_send_from(addr, Some(source), req)
        .unwrap_or_else(|e| panic!("request to {addr} from {source} failed: {e}"))
}

fn connect(addr: SocketAddr, source: Option<IpAddr>) -> std::io::Result<std::net::TcpStream> {
    let Some(source) = source else {
        return std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(10));
    };
    // A std socket cannot choose its source address before connecting; tokio's can.
    std::thread::spawn(move || -> std::io::Result<std::net::TcpStream> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        rt.block_on(async {
            let sock = if source.is_ipv4() {
                tokio::net::TcpSocket::new_v4()?
            } else {
                tokio::net::TcpSocket::new_v6()?
            };
            sock.bind(SocketAddr::new(source, 0))?;
            let stream = sock.connect(addr).await?;
            let std = stream.into_std()?;
            std.set_nonblocking(false)?;
            Ok(std)
        })
    })
    .join()
    .map_err(|_| std::io::Error::other("connect thread panicked"))?
}

pub fn try_send_from(
    addr: SocketAddr,
    source: Option<IpAddr>,
    req: RawReq,
) -> std::io::Result<Response> {
    let mut s = connect(addr, source)?;
    s.set_read_timeout(Some(req.timeout))?;
    s.set_write_timeout(Some(Duration::from_secs(10)))?;
    let mut head = format!("{} {} HTTP/1.1\r\n", req.method, req.path);
    for (k, v) in &req.headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    if !req.body.is_empty() || req.method == "POST" {
        head.push_str(&format!("content-length: {}\r\n", req.body.len()));
    }
    head.push_str("connection: close\r\n\r\n");
    s.write_all(head.as_bytes())?;
    s.write_all(&req.body)?;
    let mut raw = Vec::new();
    s.read_to_end(&mut raw)?;
    parse_response(&raw).ok_or_else(|| std::io::Error::other("malformed HTTP response"))
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn parse_response(raw: &[u8]) -> Option<Response> {
    let split = find(raw, b"\r\n\r\n")?;
    let head = std::str::from_utf8(&raw[..split]).ok()?;
    let mut body = raw[split + 4..].to_vec();
    let mut lines = head.lines();
    let status = lines.next()?.split_whitespace().nth(1)?.parse().ok()?;
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    if headers
        .iter()
        .any(|(k, v)| k == "transfer-encoding" && v.eq_ignore_ascii_case("chunked"))
    {
        body = dechunk(&body)?;
    }
    Some(Response {
        status,
        headers,
        body: String::from_utf8_lossy(&body).into_owned(),
    })
}

fn dechunk(mut b: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let eol = find(b, b"\r\n")?;
        let size = usize::from_str_radix(
            std::str::from_utf8(&b[..eol])
                .ok()?
                .split(';')
                .next()?
                .trim(),
            16,
        )
        .ok()?;
        b = &b[eol + 2..];
        if size == 0 {
            return Some(out);
        }
        out.extend_from_slice(b.get(..size)?);
        b = b.get(size + 2..)?;
    }
}

/// One request a `Client` sends.
pub struct Req {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub site: Site,
}

impl Req {
    pub fn get(path: &str) -> Self {
        Req {
            method: "GET".into(),
            path: path.into(),
            headers: vec![],
            body: vec![],
            site: Site::Same,
        }
    }

    pub fn post(path: &str) -> Self {
        Req {
            method: "POST".into(),
            ..Self::get(path)
        }
    }

    pub fn header(mut self, k: &str, v: &str) -> Self {
        self.headers.push((k.into(), v.into()));
        self
    }

    /// `application/x-www-form-urlencoded` body.
    pub fn form(mut self, fields: &[(&str, &str)]) -> Self {
        let mut ser = url::form_urlencoded::Serializer::new(String::new());
        for (k, v) in fields {
            ser.append_pair(k, v);
        }
        self.body = ser.finish().into_bytes();
        self.headers.push((
            "content-type".into(),
            "application/x-www-form-urlencoded".into(),
        ));
        self
    }

    pub fn site(mut self, site: Site) -> Self {
        self.site = site;
        self
    }

    /// The request arrives as a top-level navigation from another site (a redirect or link).
    pub fn cross_site_navigation(self) -> Self {
        self.site(Site::CrossSiteNavigation)
    }
}

/// A browser tab talking to one listener through the gateway's eyes: it sends
/// `host` as the Host header, the forwarded client IP and protocol, applies the
/// jar, and never follows redirects.
#[derive(Clone)]
pub struct Client {
    pub addr: SocketAddr,
    pub host: String,
    pub https: bool,
    pub jar: Jar,
    pub client_ip: IpAddr,
    pub timeout: Duration,
}

impl Client {
    pub fn new(addr: SocketAddr, host: &str, https: bool, jar: Jar) -> Self {
        Client {
            addr,
            host: host.to_string(),
            https,
            jar,
            client_ip: "192.0.2.10".parse().unwrap(),
            timeout: Duration::from_secs(30),
        }
    }

    pub fn with_ip(mut self, ip: &str) -> Self {
        self.client_ip = ip.parse().expect("client ip");
        self
    }

    pub fn with_timeout(mut self, d: Duration) -> Self {
        self.timeout = d;
        self
    }

    pub fn jar(&self) -> &Jar {
        &self.jar
    }

    pub fn get(&self, path: &str) -> Response {
        self.send(Req::get(path))
    }

    pub fn post_form(&self, path: &str, fields: &[(&str, &str)]) -> Response {
        self.send(Req::post(path).form(fields))
    }

    pub fn send(&self, req: Req) -> Response {
        let path_only = req.path.split('?').next().unwrap_or("/");
        let ctx = SendContext {
            secure_transport: self.https,
            site: req.site,
            safe_method: matches!(req.method.as_str(), "GET" | "HEAD" | "OPTIONS"),
        };
        let mut raw = RawReq::new(&req.method, &req.path, &self.host).timeout(self.timeout);
        raw = raw
            .header("x-forwarded-for", &self.client_ip.to_string())
            .header(
                "x-forwarded-proto",
                if self.https { "https" } else { "http" },
            )
            .header("accept-language", "en");
        if let Some(c) = self.jar.header_for(&self.host, path_only, ctx) {
            raw = raw.header("cookie", &c);
        }
        for (k, v) in &req.headers {
            raw = raw.header(k, v);
        }
        raw.body = req.body;
        let resp = send(self.addr, raw);
        for (k, v) in &resp.headers {
            if k == "set-cookie" {
                self.jar.store(&self.host, path_only, self.https, v);
            }
        }
        resp
    }
}
