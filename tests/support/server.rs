//! Run an axum router on its own thread and runtime, on a loopback port, so a
//! test can block on sockets freely while the server keeps answering.
#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::to_bytes;
use axum::extract::Request;

pub struct Served {
    pub addr: SocketAddr,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Served {
    pub fn start(router: Router) -> Served {
        let (addr_tx, addr_rx) = std::sync::mpsc::channel();
        let (stop, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let thread = std::thread::Builder::new()
            .name("test-server".into())
            .spawn(move || {
                let rt = tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .enable_all()
                    .build()
                    .expect("test server runtime");
                rt.block_on(async move {
                    let l = tokio::net::TcpListener::bind("127.0.0.1:0")
                        .await
                        .expect("bind test server");
                    addr_tx.send(l.local_addr().expect("addr")).ok();
                    // No graceful drain: a deliberately slow handler must not delay the test.
                    tokio::select! {
                        _ = axum::serve(l, router) => {}
                        _ = stop_rx => {}
                    }
                });
                // Handlers sleeping for a "slow" profile must not hold the test up.
                rt.shutdown_background();
            })
            .expect("spawn test server");
        let addr = addr_rx.recv().expect("test server address");
        Served {
            addr,
            stop: Some(stop),
            thread: Some(thread),
        }
    }
}

impl Drop for Served {
    fn drop(&mut self) {
        if let Some(s) = self.stop.take() {
            let _ = s.send(());
        }
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// What a test server saw.
#[derive(Clone)]
pub struct RecordedRequest {
    pub method: String,
    /// Path and query exactly as sent (still percent-encoded).
    pub raw_path: String,
    /// The path with `%XX` decoded, the way a typical application server sees it.
    pub decoded_path: String,
    pub query: Vec<(String, String)>,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl RecordedRequest {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    pub fn query_value(&self, name: &str) -> Option<&str> {
        self.query
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    /// The urlencoded form body as pairs.
    pub fn form(&self) -> Vec<(String, String)> {
        url::form_urlencoded::parse(self.body.as_bytes())
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect()
    }

    pub fn path(&self) -> &str {
        self.raw_path.split('?').next().unwrap_or("")
    }
}

impl std::fmt::Debug for RecordedRequest {
    /// Method and path only: query strings and bodies carry codes and secrets.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.method, self.path())
    }
}

pub type Log = Arc<Mutex<Vec<RecordedRequest>>>;

pub fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && let Some(h) = b.get(i + 1..i + 3)
            && let Ok(h) = std::str::from_utf8(h)
            && let Ok(v) = u8::from_str_radix(h, 16)
        {
            out.push(v);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Record a request (body capped at 2 MiB) and return it alongside the body bytes.
pub async fn record(req: Request, log: &Log) -> RecordedRequest {
    let (parts, body) = req.into_parts();
    let body = to_bytes(body, 2 * 1024 * 1024).await.unwrap_or_default();
    let raw_path = parts
        .uri
        .path_and_query()
        .map_or_else(|| parts.uri.path().to_string(), |p| p.as_str().to_string());
    let path = parts.uri.path();
    let query = parts
        .uri
        .query()
        .map(|q| {
            url::form_urlencoded::parse(q.as_bytes())
                .map(|(k, v)| (k.into_owned(), v.into_owned()))
                .collect()
        })
        .unwrap_or_default();
    let rec = RecordedRequest {
        method: parts.method.to_string(),
        decoded_path: percent_decode(path),
        raw_path,
        query,
        headers: parts
            .headers
            .iter()
            .map(|(k, v)| {
                (
                    k.as_str().to_string(),
                    String::from_utf8_lossy(v.as_bytes()).into_owned(),
                )
            })
            .collect(),
        body: String::from_utf8_lossy(&body).into_owned(),
    };
    log.lock().unwrap().push(rec.clone());
    rec
}
