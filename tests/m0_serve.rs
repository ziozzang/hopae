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
        // The portal serves `/login`; without a transaction it is a 400, not a 404.
        assert_eq!(get(portal, "/login").status, 400);
        assert_eq!(get(gateway, "/login").status, 404);
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
    // Another state directory: the second instance must fail on the port, not on the instance lock.
    let other = tempfile::tempdir().unwrap();
    let json = config_json(other.path()).replacen("127.0.0.1:0", &portal.to_string(), 1);
    let cfg = hopae::config::parse(&json).unwrap();
    let err = hopae::app::bind(&cfg).await.err().expect("bind must fail");
    assert!(
        format!("{err:#}").contains("binding portal listener"),
        "{err:#}"
    );
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

#[tokio::test(flavor = "multi_thread")]
async fn administrator_mtls_requires_certificate_and_preserves_authentication() {
    use std::process::{Command, Stdio};
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let run = |args: &[&str]| {
        assert!(
            Command::new("openssl")
                .current_dir(root)
                .args(args)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .unwrap()
                .success()
        );
    };
    run(&[
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        "ca.key",
        "-out",
        "ca.pem",
        "-days",
        "1",
        "-subj",
        "/CN=Owned HOP1 CA",
        "-addext",
        "basicConstraints=critical,CA:TRUE",
    ]);
    for (name, usage) in [("server", "serverAuth"), ("client", "clientAuth")] {
        let key = format!("{name}.key");
        let csr = format!("{name}.csr");
        let cert = format!("{name}.pem");
        let ext = format!("{name}.ext");
        run(&[
            "req",
            "-new",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            &key,
            "-out",
            &csr,
            "-subj",
            &format!("/CN={name}"),
        ]);
        std::fs::write(root.join(&ext),format!("basicConstraints=critical,CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage={usage}\nsubjectAltName=DNS:hopae.example.test,DNS:admin.example.test\n")).unwrap();
        run(&[
            "x509",
            "-req",
            "-in",
            &csr,
            "-CA",
            "ca.pem",
            "-CAkey",
            "ca.key",
            "-CAcreateserial",
            "-days",
            "1",
            "-extfile",
            &ext,
            "-out",
            &cert,
        ]);
    }

    let mut json: serde_json::Value = serde_json::from_str(&config_json(root)).unwrap();
    json["admin"] = serde_json::json!({"public_url":"https://admin.example.test"});
    json["listen"]["admin"] = serde_json::json!("127.0.0.1:0");
    json["listen"]["admin_tls"] = serde_json::json!({"certificate":root.join("server.pem"),"key":root.join("server.key"),"client_ca":root.join("ca.pem")});
    let cfg = hopae::config::parse(&json.to_string()).unwrap();
    let bound = hopae::app::bind(&cfg).await.unwrap();
    let address = bound.admin_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(bound.run(async {
        let _ = rx.await;
    }));
    let ca = reqwest::Certificate::from_pem(&std::fs::read(root.join("ca.pem")).unwrap()).unwrap();
    let mut pem = std::fs::read(root.join("client.pem")).unwrap();
    pem.extend(std::fs::read(root.join("client.key")).unwrap());
    let identity = reqwest::Identity::from_pem(&pem).unwrap();
    let url = format!("https://admin.example.test:{}/v1/status", address.port());
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .tls_built_in_root_certs(false)
        .add_root_certificate(ca.clone())
        .identity(identity)
        .resolve("admin.example.test", address)
        .timeout(std::time::Duration::from_secs(2))
        .build()
        .unwrap();
    let response = client
        .get(&url)
        .header("x-forwarded-host", "admin.example.test")
        .header("x-forwarded-proto", "https")
        .header("x-forwarded-port", "443")
        .header("x-forwarded-for", "192.0.2.8")
        .send()
        .await
        .unwrap();
    let status = response.status().as_u16();
    let body = response.text().await.unwrap();
    assert!(
        matches!(status, 401 | 403),
        "unexpected status {status}: {body}"
    );
    let anonymous = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .tls_built_in_root_certs(false)
        .add_root_certificate(ca)
        .resolve("admin.example.test", address)
        .timeout(std::time::Duration::from_secs(1))
        .build()
        .unwrap();
    assert!(anonymous.get(&url).send().await.is_err());
    drop(client);
    drop(anonymous);
    tx.send(()).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(10), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}
