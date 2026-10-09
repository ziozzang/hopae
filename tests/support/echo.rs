//! The upstream stand-in: records every request it receives and answers `200`.
//! Scenarios assert on what the application would have seen (identity headers,
//! absence of a handoff code, the decoded path).
#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::extract::{Request, State};
use axum::response::Response;

pub use super::server::RecordedRequest;
use super::server::{Log, Served, record};

pub struct Echo {
    pub addr: SocketAddr,
    log: Log,
    _server: Served,
}

impl Echo {
    pub fn start() -> Echo {
        let log: Log = Arc::new(Mutex::new(Vec::new()));
        let router = Router::new().fallback(handle).with_state(log.clone());
        let server = Served::start(router);
        Echo {
            addr: server.addr,
            log,
            _server: server,
        }
    }

    pub fn requests(&self) -> Vec<RecordedRequest> {
        self.log.lock().unwrap().clone()
    }

    pub fn clear(&self) {
        self.log.lock().unwrap().clear();
    }

    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }
}

async fn handle(State(log): State<Log>, req: Request) -> Response {
    let rec = record(req, &log).await;
    let mut r = Response::new(axum::body::Body::from(format!(
        "echo {}\n",
        rec.decoded_path
    )));
    r.headers_mut()
        .insert("content-type", "text/plain".parse().unwrap());
    r
}
