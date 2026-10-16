#![cfg(feature = "native-client")]
//! A reloadable endpoint presents the caller's current client certificate on
//! every new connection: rotation needs no new client and no restart.
use hopae_grpc::{observed_client::*, receipt_time::ClockRates, service_epoch, v1};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use std::{
    path::Path,
    sync::{Arc, Mutex, RwLock},
    time::Duration,
};
use tonic::{Request, Response, Status};

const CALLER: &str = "reloadable-test-caller-at-least-thirty-two-bytes";

fn openssl(dir: &Path, args: &[&str]) {
    let out = std::process::Command::new("openssl")
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}
fn issue(dir: &Path, name: &str, usage: &str) {
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
        format!(
            "basicConstraints=CA:FALSE\nextendedKeyUsage={usage}\nsubjectAltName=DNS:hopae.test\n"
        ),
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
            "ca.pem",
            "-CAkey",
            "ca.key",
            "-CAcreateserial",
            "-days",
            "1",
            "-extfile",
            &format!("{name}.ext"),
            "-out",
            &format!("{name}.pem"),
        ],
    );
}
fn client_config(dir: &Path, name: &str) -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    for c in CertificateDer::pem_file_iter(dir.join("ca.pem")).unwrap() {
        roots.add(c.unwrap()).unwrap();
    }
    let chain = CertificateDer::pem_file_iter(dir.join(format!("{name}.pem")))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let key = PrivateKeyDer::from_pem_file(dir.join(format!("{name}.key"))).unwrap();
    // Deliberately no ALPN: the SDK enforces h2 itself.
    Arc::new(
        rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_client_auth_cert(chain, key)
        .unwrap(),
    )
}

/// Records the client certificate of each call, then refuses it.
struct Peer(Arc<Mutex<Vec<Vec<u8>>>>);
#[tonic::async_trait]
impl v1::authentication_receipts_server::AuthenticationReceipts for Peer {
    async fn issue_service(
        &self,
        _: Request<v1::ServiceReceiptRequest>,
    ) -> Result<Response<v1::ServiceReceiptReply>, Status> {
        Err(Status::unimplemented("unused"))
    }
    async fn validate_service(
        &self,
        _: Request<v1::ServiceReceiptValidationRequest>,
    ) -> Result<Response<v1::ServiceReceiptValidationReply>, Status> {
        Err(Status::unimplemented("unused"))
    }
    async fn issue_service_observed(
        &self,
        request: Request<v1::ServiceReceiptRequest>,
    ) -> Result<Response<v1::ServiceReceiptObservedReply>, Status> {
        let presented = request.peer_certs().unwrap()[0].as_ref().to_vec();
        self.0.lock().unwrap().push(presented);
        Err(Status::unavailable("recorded"))
    }
    async fn observe_service_time(
        &self,
        _: Request<v1::ServiceReceiptValidationRequest>,
    ) -> Result<Response<v1::ServiceReceiptTimeReply>, Status> {
        Err(Status::unimplemented("unused"))
    }
}

#[tokio::test]
async fn reloadable_endpoint_presents_rotated_client_certificate_on_new_connections() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    openssl(
        d,
        &[
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=test-ca",
            "-keyout",
            "ca.key",
            "-out",
            "ca.pem",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
        ],
    );
    issue(d, "server", "serverAuth");
    issue(d, "first", "clientAuth");
    issue(d, "second", "clientAuth");
    let der = |name: &str| {
        CertificateDer::from_pem_file(d.join(format!("{name}.pem")))
            .unwrap()
            .as_ref()
            .to_vec()
    };
    let read = |name: &str| std::fs::read(d.join(name)).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = format!("https://{}", listener.local_addr().unwrap());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let tls = tonic::transport::ServerTlsConfig::new()
        .identity(tonic::transport::Identity::from_pem(
            read("server.pem"),
            read("server.key"),
        ))
        .client_ca_root(tonic::transport::Certificate::from_pem(read("ca.pem")));
    tokio::spawn(
        tonic::transport::Server::builder()
            .tls_config(tls)
            .unwrap()
            // Connections are recycled, as a load balancer or restart would.
            .max_connection_age(Duration::from_millis(300))
            .max_connection_age_grace(Duration::from_millis(50))
            .add_service(
                v1::authentication_receipts_server::AuthenticationReceiptsServer::new(Peer(
                    seen.clone(),
                )),
            )
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener)),
    );
    let current = Arc::new(RwLock::new(client_config(d, "first")));
    let source: ClientConfigSource = {
        let current = current.clone();
        Arc::new(move || current.read().unwrap().clone())
    };
    let pinned = v1::AuthenticationReceiptContext {
        issuer_ref: "issuer".into(),
        key_epoch: 1,
        identity_authority_epoch: service_epoch::encode_clock(
            "owner",
            7,
            9,
            "11111111111111111111111111111111",
        )
        .unwrap(),
        identity: Some(v1::ReceiptIdentity {
            subject_ref: "worker".into(),
            kind: 2,
            aal: 0,
            revision: 7,
            credential_generation: 7,
        }),
        service: "orders".into(),
        audience: "api".into(),
        request_sha256: vec![],
    };
    let client = Client::new(
        ReloadableEndpointConfig {
            address: &address,
            server_name: "hopae.test",
            tls: source,
            caller_key: CALLER,
        },
        OwnerPin {
            context: pinned.clone(),
            verifying_key: ed25519_dalek::SigningKey::from_bytes(&[7; 32]).verifying_key(),
            key_registry_revision: 1,
        },
        Arc::new(hangang_runtime::time::ReceiverClock::new([7; 16]).unwrap()),
        ClockRates::new(50, 50).unwrap(),
        Limits {
            concurrent: 1,
            timeout: Duration::from_millis(500),
        },
    )
    .unwrap();
    let request = client
        .prepare(
            &hopae_grpc::request_binding::Request {
                service: "orders",
                audience: "api",
                method: "GET",
                target: "/",
                body_sha256: &[0; 32],
            },
            vec![],
        )
        .unwrap();
    let calls = || seen.lock().unwrap().len();
    assert!(client.issue(request.clone()).await.is_err());
    assert_eq!(seen.lock().unwrap().last(), Some(&der("first")));
    // Rotate: the source now returns the second certificate. The same client
    // presents it once its connection is replaced; no client is rebuilt.
    *current.write().unwrap() = client_config(d, "second");
    let mut rotated = false;
    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        let before = calls();
        let _ = client.issue(request.clone()).await;
        if calls() > before && seen.lock().unwrap().last() == Some(&der("second")) {
            rotated = true;
            break;
        }
    }
    assert!(
        rotated,
        "the rotated client certificate was never presented"
    );
    // The shared endpoint bounds still apply to reloadable endpoints.
    let path = d.to_path_buf();
    let refused = Client::new(
        ReloadableEndpointConfig {
            address: "http://127.0.0.1:1",
            server_name: "hopae.test",
            tls: Arc::new(move || client_config(&path, "first")),
            caller_key: CALLER,
        },
        OwnerPin {
            context: pinned,
            verifying_key: ed25519_dalek::SigningKey::from_bytes(&[7; 32]).verifying_key(),
            key_registry_revision: 1,
        },
        Arc::new(hangang_runtime::time::ReceiverClock::new([7; 16]).unwrap()),
        ClockRates::new(50, 50).unwrap(),
        Limits {
            concurrent: 1,
            timeout: Duration::from_millis(500),
        },
    );
    assert!(refused.is_err(), "non-https addresses stay refused");
}
