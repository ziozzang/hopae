//! TLS reload: rotation, invalid material, CA rotation, end-to-end handshakes.
use super::*;
use std::process::Command;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

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

/// A CA `<ca>` and, signed by it, `<ca>-server` (DNS `hopae.example.test`)
/// and `<ca>-client`, as `.pem` / `.key` files in `dir`.
pub(crate) fn pki(dir: &Path, ca: &str) {
    let run = |args: Vec<String>| {
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        openssl(dir, &refs);
    };
    let ec = |mut v: Vec<String>| {
        v.extend(
            [
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-nodes",
            ]
            .map(String::from),
        );
        v
    };
    let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    let mut a = ec(s(&["req", "-x509"]));
    a.extend(s(&[
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
    ]));
    run(a);
    for (role, usage) in [("server", "serverAuth"), ("client", "clientAuth")] {
        let name = format!("{ca}-{role}");
        let mut r = ec(s(&["req", "-new"]));
        r.extend(s(&[
            "-subj",
            &format!("/CN={name}"),
            "-keyout",
            &format!("{name}.key"),
            "-out",
            &format!("{name}.csr"),
        ]));
        run(r);
        std::fs::write(
            dir.join(format!("{name}.ext")),
            format!("basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage={usage}\nsubjectAltName=DNS:hopae.example.test\n"),
        )
        .unwrap();
        run(s(&[
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
        ]));
    }
}

fn copy(dir: &Path, from: &str, to: &str) {
    // Write-then-rename, as a projected secret volume swaps its files.
    let tmp = dir.join(format!("{to}.tmp"));
    std::fs::copy(dir.join(from), &tmp).unwrap();
    std::fs::rename(&tmp, dir.join(to)).unwrap();
}

struct Fixture {
    dir: tempfile::TempDir,
    status: Arc<Status>,
}

impl Fixture {
    fn new() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        pki(dir.path(), "ca1");
        pki(dir.path(), "ca2");
        copy(dir.path(), "ca1-server.pem", "tls.crt");
        copy(dir.path(), "ca1-server.key", "tls.key");
        copy(dir.path(), "ca1.pem", "ca.crt");
        Fixture {
            dir,
            status: Arc::new(Status::default()),
        }
    }
    fn path(&self, f: &str) -> PathBuf {
        self.dir.path().join(f)
    }
    fn settings(&self) -> crate::config::NativeGatewayTls {
        crate::config::NativeGatewayTls {
            certificate: self.path("tls.crt"),
            key: self.path("tls.key"),
            client_ca: self.path("ca.crt"),
        }
    }
    fn print(&self, file: &str) -> String {
        fingerprint(&certificates(&std::fs::read(self.path(file)).unwrap()).unwrap()[0])
    }
    /// A client that trusts `trust` (the server's CA) and presents `client`.
    fn client(&self, trust: &str, client: &str) -> tokio_rustls::TlsConnector {
        let mut roots = RootCertStore::empty();
        for c in certificates(&std::fs::read(self.path(&format!("{trust}.pem"))).unwrap()).unwrap()
        {
            roots.add(c).unwrap();
        }
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_client_auth_cert(
            certificates(&std::fs::read(self.path(&format!("{client}.pem"))).unwrap()).unwrap(),
            private_key(&std::fs::read(self.path(&format!("{client}.key"))).unwrap()).unwrap(),
        )
        .unwrap();
        tokio_rustls::TlsConnector::from(Arc::new(config))
    }
}

/// Serve `tls` on a loopback port: every connection uses the current
/// configuration, as the listeners do.
async fn serve(tls: Arc<ServerTls>) -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            let acceptor = tls.acceptor();
            tokio::spawn(async move {
                if let Ok(mut s) = acceptor.accept(socket).await {
                    let _ = s.write_all(b"ok").await;
                    let _ = s.shutdown().await;
                }
            });
        }
    });
    addr
}

/// Handshake and return the fingerprint of the certificate the server showed.
async fn handshake(
    addr: std::net::SocketAddr,
    connector: &tokio_rustls::TlsConnector,
) -> Result<String, String> {
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let name = rustls::pki_types::ServerName::try_from("hopae.example.test").unwrap();
    let mut s = connector
        .connect(name, tcp)
        .await
        .map_err(|e| e.to_string())?;
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).await.map_err(|e| e.to_string())?;
    let print = fingerprint(&s.get_ref().1.peer_certificates().unwrap()[0]);
    if buf != b"ok" {
        return Err("no answer".into());
    }
    Ok(print)
}

#[tokio::test]
async fn a_renewed_certificate_is_served_to_new_handshakes_without_a_restart() {
    let f = Fixture::new();
    let tls = ServerTls::load("test", &f.settings(), &[], f.status.clone()).unwrap();
    let addr = serve(tls.clone()).await;
    let client = f.client("ca1", "ca1-client");
    assert_eq!(
        handshake(addr, &client).await.unwrap(),
        f.print("ca1-server.pem")
    );
    assert_eq!(tls.poll(), Outcome::Unchanged);
    // cert-manager renews: a new key pair from the same CA.
    let out = Command::new("openssl")
        .args([
            "req",
            "-new",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-nodes",
            "-subj",
            "/CN=renewed",
            "-keyout",
            "renewed.key",
            "-out",
            "renewed.csr",
        ])
        .current_dir(f.dir.path())
        .output()
        .unwrap();
    assert!(out.status.success());
    std::fs::write(f.path("renewed.ext"), "basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:hopae.example.test\n").unwrap();
    openssl(
        f.dir.path(),
        &[
            "x509",
            "-req",
            "-in",
            "renewed.csr",
            "-CA",
            "ca1.pem",
            "-CAkey",
            "ca1.key",
            "-CAcreateserial",
            "-days",
            "2",
            "-extfile",
            "renewed.ext",
            "-out",
            "renewed.pem",
        ],
    );
    let before = tls.config();
    copy(f.dir.path(), "renewed.pem", "tls.crt");
    copy(f.dir.path(), "renewed.key", "tls.key");
    let outcome = tls.poll();
    assert_eq!(outcome, Outcome::Reloaded(f.print("renewed.pem")));
    assert!(!Arc::ptr_eq(&before, &tls.config()));
    assert_eq!(
        handshake(addr, &client).await.unwrap(),
        f.print("renewed.pem")
    );
    assert_eq!(
        tls.poll(),
        Outcome::Unchanged,
        "an unchanged file is not reloaded"
    );
    let status = f.status.to_json();
    assert_eq!(status["tls"][0]["fingerprint"], f.print("renewed.pem"));
    assert_eq!(status["tls"][0]["reloads"], 1);
}

#[tokio::test]
async fn invalid_material_keeps_the_previous_configuration_until_fixed() {
    let f = Fixture::new();
    let tls = ServerTls::load("bad", &f.settings(), &[], f.status.clone()).unwrap();
    let addr = serve(tls.clone()).await;
    let client = f.client("ca1", "ca1-client");
    let served = tls.config();
    // A key that does not belong to the certificate (half-written rotation).
    copy(f.dir.path(), "ca2-server.key", "tls.key");
    assert!(matches!(tls.poll(), Outcome::Invalid(e) if e.contains("does not match")));
    assert!(Arc::ptr_eq(&served, &tls.config()));
    assert_eq!(
        handshake(addr, &client).await.unwrap(),
        f.print("ca1-server.pem")
    );
    assert_eq!(f.status.to_json()["tls"][0]["failing"], true);
    // Garbage and a missing file: still the old configuration.
    std::fs::write(f.path("tls.crt"), "not a certificate").unwrap();
    assert!(matches!(tls.poll(), Outcome::Invalid(_)));
    std::fs::remove_file(f.path("ca.crt")).unwrap();
    assert!(matches!(tls.poll(), Outcome::Invalid(e) if e.contains("unreadable")));
    std::fs::write(f.path("ca.crt"), "").unwrap();
    assert!(matches!(tls.poll(), Outcome::Invalid(_)));
    assert!(Arc::ptr_eq(&served, &tls.config()));
    // Reverting to the material in use clears the alert without a reload.
    copy(f.dir.path(), "ca1-server.pem", "tls.crt");
    copy(f.dir.path(), "ca1-server.key", "tls.key");
    copy(f.dir.path(), "ca1.pem", "ca.crt");
    assert_eq!(tls.poll(), Outcome::Unchanged);
    assert_eq!(f.status.to_json()["tls"][0]["failing"], false);
    copy(f.dir.path(), "ca2-server.key", "tls.key");
    // The complete new pair arrives: reloaded, the alert clears.
    copy(f.dir.path(), "ca2-server.pem", "tls.crt");
    copy(f.dir.path(), "ca1.pem", "ca.crt");
    assert!(matches!(tls.poll(), Outcome::Reloaded(_)));
    assert_eq!(f.status.to_json()["tls"][0]["failing"], false);
    assert_eq!(
        handshake(addr, &f.client("ca2", "ca1-client"))
            .await
            .unwrap(),
        f.print("ca2-server.pem")
    );
}

#[tokio::test]
async fn a_rotated_client_ca_admits_the_new_clients_and_refuses_the_old() {
    let f = Fixture::new();
    let tls = ServerTls::load("ca", &f.settings(), &[], f.status.clone()).unwrap();
    let addr = serve(tls.clone()).await;
    assert!(
        handshake(addr, &f.client("ca1", "ca1-client"))
            .await
            .is_ok()
    );
    assert!(
        handshake(addr, &f.client("ca1", "ca2-client"))
            .await
            .is_err()
    );
    copy(f.dir.path(), "ca2.pem", "ca.crt");
    assert!(matches!(tls.poll(), Outcome::Reloaded(_)));
    assert!(
        handshake(addr, &f.client("ca1", "ca2-client"))
            .await
            .is_ok()
    );
    assert!(
        handshake(addr, &f.client("ca1", "ca1-client"))
            .await
            .is_err()
    );
}

#[test]
fn client_material_is_applied_only_when_changed_and_valid() {
    let f = Fixture::new();
    let applied = Arc::new(Mutex::new(Vec::<String>::new()));
    let seen = applied.clone();
    let client = ClientTls::watch(
        "client",
        &f.path("ca.crt"),
        &f.path("tls.crt"),
        &f.path("tls.key"),
        f.status.clone(),
        Box::new(move |_, cert, _| {
            seen.lock()
                .unwrap()
                .push(fingerprint(&certificates(cert)?[0]));
            Ok(())
        }),
    )
    .unwrap();
    assert_eq!(client.poll(), Outcome::Unchanged);
    copy(f.dir.path(), "ca2-client.key", "tls.key");
    assert!(matches!(client.poll(), Outcome::Invalid(_)));
    assert!(
        applied.lock().unwrap().is_empty(),
        "invalid material is never applied"
    );
    copy(f.dir.path(), "ca2-client.pem", "tls.crt");
    assert!(matches!(client.poll(), Outcome::Reloaded(_)));
    assert_eq!(*applied.lock().unwrap(), [f.print("ca2-client.pem")]);
    assert_eq!(client.poll(), Outcome::Unchanged);
}
