//! M0: the two listeners, their fixed routes and graceful shutdown.
mod support;

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use support::*;

async fn start(
    dir: &std::path::Path,
) -> (
    hopae::app::Bound,
    std::net::SocketAddr,
    std::net::SocketAddr,
) {
    let cfg = hopae::config::parse(&config_json(dir)).unwrap();
    let bound = hopae::app::bind(&cfg).await.unwrap();
    let (p, g) = (bound.portal_addr(), bound.gateway_addr());
    (bound, p, g)
}

#[tokio::test(flavor = "multi_thread")]
async fn serves_portal_and_gateway_routes_and_shuts_down() {
    let dir = tempfile::tempdir().unwrap();
    let (bound, portal, gateway) = start(dir.path()).await;
    assert!(portal.ip().is_loopback() && portal.port() != 0);
    assert!(gateway.ip().is_loopback() && gateway.port() != 0);
    assert_ne!(portal.port(), gateway.port());
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(bound.run(async {
        let _ = stop_rx.await;
    }));

    let checks = tokio::task::spawn_blocking(move || {
        let h = get(portal, "/healthz");
        assert_eq!(h.status, 200);

        let v = get(gateway, "/_hopae/verify");
        // No caller key: refused before anything else is read.
        assert_eq!(v.status, 403);
        assert_eq!(v.header("x-hopae-reason"), Some("caller_unauthorized"));
        assert_eq!(v.header("cache-control"), Some("no-store"));

        // Disjoint routers: nothing else exists on either listener.
        assert_eq!(get(portal, "/_hopae/verify").status, 404);
        assert_eq!(get(gateway, "/healthz").status, 404);
        assert_eq!(get(portal, "/login").status, 404);
        assert_eq!(get(gateway, "/").status, 404);
    });
    checks.await.unwrap();

    stop_tx.send(()).unwrap();
    server.await.unwrap().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn binding_a_taken_port_fails() {
    let dir = tempfile::tempdir().unwrap();
    let (_bound, portal, _g) = start(dir.path()).await;
    let json = config_json(dir.path()).replacen("127.0.0.1:0", &portal.to_string(), 1);
    let cfg = hopae::config::parse(&json).unwrap();
    assert!(hopae::app::bind(&cfg).await.is_err());
}

#[test]
fn binary_serves_and_exits_cleanly_on_sigterm() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = write_config(dir.path(), &config_json(dir.path()));
    let mut child = Command::new(env!("CARGO_BIN_EXE_hopae"))
        .env(KEY_ENV, "k")
        .arg("serve")
        .arg("--config")
        .arg(&cfg)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let mut addr_of = |prefix: &str| -> std::net::SocketAddr {
        let l = lines.next().unwrap().unwrap();
        l.strip_prefix(prefix)
            .unwrap_or_else(|| panic!("unexpected line {l:?}"))
            .parse()
            .unwrap()
    };
    let portal = addr_of("portal listening on ");
    let gateway = addr_of("gateway listening on ");
    assert_eq!(get(portal, "/healthz").status, 200);
    assert_eq!(get(gateway, "/_hopae/verify").status, 403);

    let status = Command::new("kill")
        .arg("-TERM")
        .arg(child.id().to_string())
        .status()
        .unwrap();
    assert!(status.success());
    let exit = child.wait().unwrap();
    assert!(exit.success(), "{exit:?}");
}
