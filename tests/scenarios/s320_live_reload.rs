//! Scenario 320: live reload without a restart — renewed TLS material on
//! every mTLS listener, and the configuration-authoritative authentication
//! profiles (`authentication.source = config`) reconciled from the file.
#![allow(dead_code)]

use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use super::s301_admin_users::kit::{CLIENT_IP, Console};
use super::s307_subject_directory::dkit::{self, API_HOST, console};
use crate::support::*;
use hopae::store::types::AdminRole;

fn openssl(dir: &Path, args: &[&str]) {
    let out = Command::new("openssl")
        .args(args)
        .current_dir(dir)
        .output()
        .expect("openssl");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// A CA `<ca>.pem` and, signed by it, `<name>.pem`/`<name>.key` for each of
/// `leaves` (DNS `hopae.example.test`).
fn issue(dir: &Path, ca: &str, leaves: &[(&str, &str)]) {
    if !dir.join(format!("{ca}.pem")).exists() {
        openssl(
            dir,
            &[
                "req",
                "-x509",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-nodes",
                "-days",
                "2",
                "-subj",
                &format!("/CN={ca}"),
                "-keyout",
                &format!("{ca}.key"),
                "-out",
                &format!("{ca}.pem"),
                "-addext",
                "basicConstraints=critical,CA:TRUE",
            ],
        );
    }
    for (name, usage) in leaves {
        openssl(
            dir,
            &[
                "req",
                "-new",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-nodes",
                "-subj",
                &format!("/CN={name}"),
                "-keyout",
                &format!("{name}.key"),
                "-out",
                &format!("{name}.csr"),
            ],
        );
        std::fs::write(
            dir.join(format!("{name}.ext")),
            format!("basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage={usage}\nsubjectAltName=DNS:hopae.example.test\n"),
        )
        .unwrap();
        openssl(
            dir,
            &[
                "x509",
                "-req",
                "-in",
                &format!("{name}.csr"),
                "-CA",
                &format!("{ca}.pem"),
                "-CAkey",
                &format!("{ca}.key"),
                "-CAcreateserial",
                "-days",
                "2",
                "-extfile",
                &format!("{name}.ext"),
                "-out",
                &format!("{name}.pem"),
            ],
        );
    }
}

/// Replace `to` with `from` atomically (write, then rename), as a secret
/// volume update does.
fn install(dir: &Path, from: &str, to: &str) {
    let tmp = dir.join(format!(".{to}.tmp"));
    std::fs::copy(dir.join(from), &tmp).unwrap();
    std::fs::rename(&tmp, dir.join(to)).unwrap();
}

fn certs(path: &Path) -> Vec<rustls::pki_types::CertificateDer<'static>> {
    rustls_pemfile::certs(&mut std::fs::read(path).unwrap().as_slice())
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
}

fn sha(der: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!(
        "sha256:{}",
        data_encoding::HEXLOWER.encode(&Sha256::digest(der))
    )
}

/// Handshake with `addr` offering `alpn`, trusting `ca`, presenting the
/// client certificate; the fingerprint of the server's leaf certificate.
fn handshake(dir: &Path, addr: &str, alpn: &[u8]) -> Result<String, String> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let mut roots = rustls::RootCertStore::empty();
        for c in certs(&dir.join("ca.pem")) {
            roots.add(c).unwrap();
        }
        let key = rustls_pemfile::private_key(
            &mut std::fs::read(dir.join("client.key")).unwrap().as_slice(),
        )
        .unwrap()
        .unwrap();
        let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_client_auth_cert(certs(&dir.join("client.pem")), key)
        .unwrap();
        config.alpn_protocols = vec![alpn.to_vec()];
        let tcp = tokio::net::TcpStream::connect(addr)
            .await
            .map_err(|e| e.to_string())?;
        let stream = tokio::time::timeout(
            Duration::from_secs(3),
            tokio_rustls::TlsConnector::from(Arc::new(config))
                .connect("hopae.example.test".try_into().unwrap(), tcp),
        )
        .await
        .map_err(|_| "timeout".to_string())?
        .map_err(|e| e.to_string())?;
        Ok(sha(
            stream.get_ref().1.peer_certificates().unwrap()[0].as_ref()
        ))
    })
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Wait until `f` holds (polling every 100 ms) or `limit` passes.
fn within(limit: Duration, mut f: impl FnMut() -> bool) -> Option<Duration> {
    let start = Instant::now();
    while start.elapsed() < limit {
        if f() {
            return Some(start.elapsed());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    None
}

#[test]
fn s320_1_renewed_tls_material_is_served_by_every_listener_without_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    issue(
        d,
        "ca",
        &[
            ("server-a", "serverAuth"),
            ("server-b", "serverAuth"),
            ("client", "clientAuth"),
        ],
    );
    install(d, "server-a.pem", "tls.crt");
    install(d, "server-a.key", "tls.key");
    let tls = json!({"certificate": d.join("tls.crt"), "key": d.join("tls.key"), "client_ca": d.join("ca.pem")});
    let (native, grpc) = (free_port(), free_port());
    let idp = MockIdp::start("default");
    let h = Hopae::spawn(
        Fixture::with(
            "m4-admin",
            json!({
                "listen": {
                    "admin_tls": tls, "native_gateway_tls": tls,
                    "native_gateway": format!("127.0.0.1:{native}"),
                    "grpc_gateway": format!("127.0.0.1:{grpc}")
                },
                "reload": {"tls_interval_secs": 1}
            }),
        ),
        &idp,
        &[],
    );
    let admin = h.admin.expect("admin listener").to_string();
    let listeners = [
        (admin.as_str(), b"http/1.1".as_slice()),
        (&*format!("127.0.0.1:{native}"), b"hop1".as_slice()),
        (&*format!("127.0.0.1:{grpc}"), b"h2".as_slice()),
    ]
    .map(|(a, p)| (a.to_string(), p));
    let first = sha(certs(&d.join("server-a.pem"))[0].as_ref());
    let renewed = sha(certs(&d.join("server-b.pem"))[0].as_ref());
    for (addr, alpn) in &listeners {
        assert_eq!(
            handshake(d, addr, alpn).as_deref(),
            Ok(first.as_str()),
            "{addr}"
        );
    }
    // cert-manager renews the secret.
    install(d, "server-b.pem", "tls.crt");
    install(d, "server-b.key", "tls.key");
    for (addr, alpn) in &listeners {
        let took = within(Duration::from_secs(5), || {
            handshake(d, addr, alpn).as_deref() == Ok(renewed.as_str())
        });
        assert!(took.is_some(), "{addr} still serves the old certificate");
    }
    let metrics = h.hooks.counters()["metrics"].clone();
    for name in ["admin", "native_gateway", "grpc_gateway"] {
        assert_eq!(
            metrics[format!("hopae_tls_reloads_total{{name=\"{name}\",result=\"reloaded\"}}")],
            1,
            "{metrics}"
        );
    }
    // A half-written rotation (a key that does not match): the renewed
    // material stays in force and the failure is visible.
    install(d, "server-a.key", "tls.key");
    assert!(
        within(Duration::from_secs(5), || {
            h.hooks.counters()["metrics"]["hopae_tls_reload_failing{name=\"admin\"}"] == 1
        })
        .is_some()
    );
    for (addr, alpn) in &listeners {
        assert_eq!(
            handshake(d, addr, alpn).as_deref(),
            Ok(renewed.as_str()),
            "{addr}"
        );
    }
    install(d, "server-b.key", "tls.key");
    assert!(
        within(Duration::from_secs(5), || {
            h.hooks.counters()["metrics"]["hopae_tls_reload_failing{name=\"admin\"}"] == 0
        })
        .is_some()
    );
}

fn status(k: &Console, a: &super::s301_admin_users::kit::Who) -> Value {
    let r = k.client(a).get("/v1/status");
    assert_eq!(r.status, 200, "{r:?}");
    r.json()["reload"]["config"].clone()
}

fn worker_status(k: &Console) -> u16 {
    k.h.verify(
        VerifyRequest::other(&format!("https://{API_HOST}/x"))
            .ip(CLIENT_IP)
            .header("authorization", &format!("Bearer {}", dkit::KEY)),
    )
    .status
}

#[test]
fn s320_2_a_revoked_key_stops_authenticating_within_two_seconds_without_a_restart() {
    let mut k = console(
        json!({"authentication": {"source": "config", "reload_interval_ms": 200}}),
        &[],
    );
    let a = k.admin("ha320", AdminRole::Admin);
    assert_eq!(worker_status(&k), 200);
    let pid_ports = (k.h.portal, k.h.gateway);
    // The ConfigMap update: `worker`'s key is removed.
    k.h.reconfigure(|v| {
        let keys = v["authentication_gateway"]["profiles"][0]["api_keys"]
            .as_array_mut()
            .unwrap();
        keys.retain(|key| key["subject"] != "worker");
    });
    let took = within(Duration::from_secs(5), || worker_status(&k) == 401)
        .expect("the revocation did not take effect");
    assert!(took <= Duration::from_secs(2), "revocation took {took:?}");
    assert_eq!((k.h.portal, k.h.gateway), pid_ports, "no restart");
    let s = status(&k, &a);
    assert_eq!(s["profiles_revision"], 2);
    assert_eq!(s["failing"], false);
    assert_eq!(s["restart_required"], false);
    let events = k.events("authentication.reconciled");
    let last = events.last().unwrap();
    assert_eq!(last["attrs"]["cause"], "reload");
    assert_eq!(last["attrs"]["revision"], 2);
    assert_eq!(last["attrs"]["actor"], "config");
    // An invalid file: the current profiles stay, the failure is visible.
    k.h.reconfigure(|v| {
        v["authentication_gateway"]["profiles"][0]["ports"] = json!(["https"]);
    });
    assert!(within(Duration::from_secs(5), || status(&k, &a)["failing"] == true).is_some());
    assert!(!status(&k, &a)["error"].as_str().unwrap().is_empty());
    assert_eq!(worker_status(&k), 401);
    assert_eq!(status(&k, &a)["profiles_revision"], 2);
    // The fix restores the key (a new revision) and clears the failure.
    k.h.reconfigure(|v| {
        v["authentication_gateway"]["profiles"][0]["ports"] = json!([443]);
        v["authentication_gateway"]["profiles"][0]["api_keys"]
            .as_array_mut()
            .unwrap()
            .push(json!({"token_env": dkit::KEY_ENV, "subject": "worker"}));
    });
    assert!(within(Duration::from_secs(5), || worker_status(&k) == 200).is_some());
    let s = status(&k, &a);
    assert_eq!(
        (s["failing"].clone(), s["profiles_revision"].clone()),
        (json!(false), json!(3))
    );
    // Another key changed: reported, applied at the next restart only.
    k.h.reconfigure(|v| v["log"]["level"] = json!("info"));
    assert!(
        within(
            Duration::from_secs(5),
            || status(&k, &a)["restart_required"] == true
        )
        .is_some()
    );
    assert_eq!(worker_status(&k), 200);
}
