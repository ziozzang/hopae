//! Owned in-process fixtures for Kubernetes workload identity tests: a test
//! CA and server certificate, RSA and ECDSA signing keys with their JWKS,
//! a token minter, and a minimal HTTPS server that plays the issuer
//! discovery/JWKS endpoints and the ServiceAccount/Pod LIST/WATCH API. No
//! real cluster, no files, no external process.
#![cfg(test)]
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::x509::extension::{BasicConstraints, ExtendedKeyUsage, SubjectAlternativeName};
use openssl::x509::{X509, X509NameBuilder};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub(crate) const ISSUER_PATH: &str = "/issuer";
pub(crate) const AUDIENCE: &str = "world.hangang.dev/example-cluster";

/// A test CA and a server certificate for 127.0.0.1/localhost.
pub(crate) struct Pki {
    pub ca_pem: String,
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
}

fn name(cn: &str) -> openssl::x509::X509Name {
    let mut b = X509NameBuilder::new().unwrap();
    b.append_entry_by_text("CN", cn).unwrap();
    b.build()
}

pub(crate) fn pki() -> Pki {
    let ca_key = PKey::from_ec_key(
        EcKey::generate(&EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap()).unwrap(),
    )
    .unwrap();
    let mut ca = X509::builder().unwrap();
    ca.set_version(2).unwrap();
    ca.set_serial_number(&BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    ca.set_subject_name(&name("Owned workload fixture CA"))
        .unwrap();
    ca.set_issuer_name(&name("Owned workload fixture CA"))
        .unwrap();
    ca.set_pubkey(&ca_key).unwrap();
    ca.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    ca.set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    ca.append_extension(BasicConstraints::new().critical().ca().build().unwrap())
        .unwrap();
    ca.sign(&ca_key, MessageDigest::sha256()).unwrap();
    let ca = ca.build();

    let key = PKey::from_ec_key(
        EcKey::generate(&EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap()).unwrap(),
    )
    .unwrap();
    let mut cert = X509::builder().unwrap();
    cert.set_version(2).unwrap();
    cert.set_serial_number(&BigNum::from_u32(2).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    cert.set_subject_name(&name("localhost")).unwrap();
    cert.set_issuer_name(ca.subject_name()).unwrap();
    cert.set_pubkey(&key).unwrap();
    cert.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    cert.set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    let san = SubjectAlternativeName::new()
        .dns("localhost")
        .ip("127.0.0.1")
        .build(&cert.x509v3_context(Some(&ca), None))
        .unwrap();
    cert.append_extension(san).unwrap();
    cert.append_extension(BasicConstraints::new().build().unwrap())
        .unwrap();
    cert.append_extension(ExtendedKeyUsage::new().server_auth().build().unwrap())
        .unwrap();
    cert.sign(&ca_key, MessageDigest::sha256()).unwrap();
    let cert = cert.build();
    Pki {
        ca_pem: String::from_utf8(ca.to_pem().unwrap()).unwrap(),
        cert_pem: cert.to_pem().unwrap(),
        key_pem: key.private_key_to_pem_pkcs8().unwrap(),
    }
}

/// A signing key with its JWK.
#[derive(Clone)]
pub(crate) struct SigningKey {
    pub kid: String,
    pub alg: jsonwebtoken::Algorithm,
    pub encoding: Arc<jsonwebtoken::EncodingKey>,
    pub jwk: Value,
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub(crate) fn rsa_key(kid: &str) -> SigningKey {
    let rsa = Rsa::generate(2048).unwrap();
    let jwk = json!({"use":"sig","kty":"RSA","kid":kid,"alg":"RS256","n":b64(&rsa.n().to_vec()),"e":b64(&rsa.e().to_vec())});
    let der = rsa.private_key_to_der().unwrap();
    SigningKey {
        kid: kid.into(),
        alg: jsonwebtoken::Algorithm::RS256,
        encoding: Arc::new(jsonwebtoken::EncodingKey::from_rsa_der(&der)),
        jwk,
    }
}

pub(crate) fn ec_key(kid: &str) -> SigningKey {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let ec: EcKey<Private> = EcKey::generate(&group).unwrap();
    let mut ctx = BigNumContext::new().unwrap();
    let (mut x, mut y) = (BigNum::new().unwrap(), BigNum::new().unwrap());
    ec.public_key()
        .affine_coordinates(&group, &mut x, &mut y, &mut ctx)
        .unwrap();
    let pad = |n: &BigNum| {
        let v = n.to_vec();
        let mut out = vec![0u8; 32 - v.len()];
        out.extend_from_slice(&v);
        out
    };
    let jwk = json!({"use":"sig","kty":"EC","crv":"P-256","kid":kid,"alg":"ES256","x":b64(&pad(&x)),"y":b64(&pad(&y))});
    let der = PKey::from_ec_key(ec)
        .unwrap()
        .private_key_to_pkcs8()
        .unwrap();
    SigningKey {
        kid: kid.into(),
        alg: jsonwebtoken::Algorithm::ES256,
        encoding: Arc::new(jsonwebtoken::EncodingKey::from_ec_der(&der)),
        jwk,
    }
}

pub(crate) fn jwks(keys: &[&SigningKey]) -> String {
    json!({"keys": keys.iter().map(|k| k.jwk.clone()).collect::<Vec<_>>()}).to_string()
}

/// Claims of a Pod-bound projected token, as kube-apiserver mints them.
pub(crate) fn claims(issuer: &str, now_s: i64, pod: &str, pod_uid: &str) -> Value {
    json!({
        "iss": issuer,
        "sub": "system:serviceaccount:blue:worker",
        "aud": [AUDIENCE],
        "exp": now_s + 3600,
        "iat": now_s,
        "nbf": now_s,
        "jti": "7f1c0e2a-0000-4000-8000-000000000001",
        "kubernetes.io": {
            "namespace": "blue",
            "serviceaccount": {"name": "worker", "uid": "sa-uid-1"},
            "pod": {"name": pod, "uid": pod_uid},
            "node": {"name": "node-a", "uid": "node-uid-a"}
        }
    })
}

pub(crate) fn mint(key: &SigningKey, claims: &Value) -> String {
    let mut header = jsonwebtoken::Header::new(key.alg);
    header.kid = Some(key.kid.clone());
    header.typ = None;
    jsonwebtoken::encode(&header, claims, &key.encoding).unwrap()
}

/// What the fixture server answers; tests mutate it while it runs.
#[derive(Default)]
pub(crate) struct ServerState {
    pub issuer: String,
    /// `jwks_uri` advertised by discovery (defaults to this server).
    pub jwks_uri: Option<String>,
    pub jwks: String,
    pub requests: BTreeMap<String, usize>,
    /// name → uid
    pub service_accounts: BTreeMap<String, String>,
    pub pods: BTreeMap<String, (String, bool)>,
    pub resource_version: u64,
    /// Fail every request with 503 (outage).
    pub down: bool,
    /// Answer the next watch with a 410 ERROR event.
    pub expire_next_watch: bool,
    /// Every emitted watch event (resource, resourceVersion, line), replayed
    /// to a watch that resumes from an older resourceVersion.
    pub log: Vec<(String, u64, String)>,
}

pub(crate) struct Server {
    pub origin: String,
    pub state: Arc<Mutex<ServerState>>,
    pub events: tokio::sync::broadcast::Sender<(String, u64, String)>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Server {
    pub(crate) fn issuer(&self) -> String {
        format!("{}{}", self.origin, ISSUER_PATH)
    }
    pub(crate) fn count(&self, path_prefix: &str) -> usize {
        self.state
            .lock()
            .unwrap()
            .requests
            .iter()
            .filter(|(k, _)| k.starts_with(path_prefix))
            .map(|(_, v)| *v)
            .sum()
    }
    /// Push a watch event for `resource` (`serviceaccounts`/`pods`).
    pub(crate) fn emit(
        &self,
        resource: &str,
        kind: &str,
        name: &str,
        uid: &str,
        terminating: bool,
    ) {
        let mut s = self.state.lock().unwrap();
        s.resource_version += 1;
        let rv = s.resource_version;
        let mut metadata = json!({"name": name, "namespace": "blue", "uid": uid, "resourceVersion": rv.to_string()});
        if terminating {
            metadata["deletionTimestamp"] = json!("2026-01-01T00:00:00Z");
        }
        let line = json!({"type": kind, "object": {"kind":"PartialObjectMetadata","apiVersion":"meta.k8s.io/v1","metadata": metadata}}).to_string();
        s.log.push((resource.to_owned(), rv, line.clone()));
        let _ = self.events.send((resource.to_owned(), rv, line));
    }
}

fn list(resource: &str, s: &ServerState) -> Value {
    let items: Vec<Value> = match resource {
        "serviceaccounts" => s
            .service_accounts
            .iter()
            .map(|(n, u)| json!({"metadata": {"name": n, "namespace": "blue", "uid": u}}))
            .collect(),
        _ => s
            .pods
            .iter()
            .map(|(n, (u, t))| {
                let mut m = json!({"name": n, "namespace": "blue", "uid": u});
                if *t {
                    m["deletionTimestamp"] = json!("2026-01-01T00:00:00Z");
                }
                json!({"metadata": m})
            })
            .collect(),
    };
    json!({"kind":"PartialObjectMetadataList","apiVersion":"meta.k8s.io/v1","metadata":{"resourceVersion": s.resource_version.to_string()},"items": items})
}

pub(crate) async fn serve(pki: &Pki) -> Server {
    let certs = rustls_pemfile::certs(&mut pki.cert_pem.as_slice())
        .collect::<std::io::Result<Vec<_>>>()
        .unwrap();
    let key = rustls_pemfile::private_key(&mut pki.key_pem.as_slice())
        .unwrap()
        .unwrap();
    let tls = tokio_rustls::TlsAcceptor::from(Arc::new(
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap(),
    ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!(
        "https://127.0.0.1:{}",
        listener.local_addr().unwrap().port()
    );
    let state = Arc::new(Mutex::new(ServerState {
        issuer: format!("{origin}{ISSUER_PATH}"),
        ..Default::default()
    }));
    let (events, _) = tokio::sync::broadcast::channel::<(String, u64, String)>(256);
    let (st, ev, base) = (state.clone(), events.clone(), origin.clone());
    let task = tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let (tls, st, ev, base) = (tls.clone(), st.clone(), ev.clone(), base.clone());
            tokio::spawn(async move {
                let Ok(mut socket) = tls.accept(socket).await else {
                    return;
                };
                let mut bytes = Vec::new();
                loop {
                    let mut chunk = [0; 4096];
                    let n = socket.read(&mut chunk).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    bytes.extend_from_slice(&chunk[..n]);
                    if bytes.windows(4).any(|w| w == b"\r\n\r\n") || bytes.len() > 16384 {
                        break;
                    }
                }
                let head = String::from_utf8_lossy(&bytes).to_string();
                let target = head.split_whitespace().nth(1).unwrap_or("/").to_string();
                let (path, query) = target.split_once('?').unwrap_or((&target, ""));
                let watch = query.split('&').any(|p| p == "watch=1");
                let key = if watch {
                    format!("{path}?watch")
                } else {
                    path.to_string()
                };
                let reply = |status: &str, body: String, ctype: &str| {
                    format!(
                        "HTTP/1.1 {status}\r\ncontent-type: {ctype}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    )
                };
                let response = {
                    let mut s = st.lock().unwrap();
                    *s.requests.entry(key).or_default() += 1;
                    if s.down {
                        Some(reply(
                            "503 Service Unavailable",
                            "{}".into(),
                            "application/json",
                        ))
                    } else if path == format!("{ISSUER_PATH}/.well-known/openid-configuration") {
                        let jwks_uri = s
                            .jwks_uri
                            .clone()
                            .unwrap_or(format!("{base}/openid/v1/jwks"));
                        Some(reply("200 OK", json!({"issuer": s.issuer, "jwks_uri": jwks_uri, "response_types_supported":["id_token"], "subject_types_supported":["public"], "id_token_signing_alg_values_supported":["RS256","ES256"]}).to_string(), "application/json"))
                    } else if path == "/openid/v1/jwks" {
                        Some(reply("200 OK", s.jwks.clone(), "application/jwk-set+json"))
                    } else if let Some(resource) = path.strip_prefix("/api/v1/namespaces/blue/") {
                        if !watch {
                            Some(reply(
                                "200 OK",
                                list(resource, &s).to_string(),
                                "application/json",
                            ))
                        } else if s.expire_next_watch {
                            s.expire_next_watch = false;
                            Some(format!(
                                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nconnection: close\r\n\r\n{}\n",
                                json!({"type":"ERROR","object":{"kind":"Status","code":410}})
                            ))
                        } else {
                            None
                        }
                    } else {
                        Some(reply("404 Not Found", "{}".into(), "application/json"))
                    }
                };
                if let Some(response) = response {
                    let _ = socket.write_all(response.as_bytes()).await;
                    let _ = socket.shutdown().await;
                    return;
                }
                // A watch: stream events for this resource until the timeout.
                let resource = path.rsplit('/').next().unwrap_or("").to_string();
                let timeout = query
                    .split('&')
                    .find_map(|p| p.strip_prefix("timeoutSeconds="))
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(5);
                let mut rx = ev.subscribe();
                let from = query
                    .split('&')
                    .find_map(|p| p.strip_prefix("resourceVersion="))
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(0);
                let replay: Vec<(u64, String)> = st
                    .lock()
                    .unwrap()
                    .log
                    .iter()
                    .filter(|(r, rv, _)| *r == resource && *rv > from)
                    .map(|(_, rv, l)| (*rv, l.clone()))
                    .collect();
                let mut sent = from;
                if socket
                    .write_all(b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nconnection: close\r\n\r\n")
                    .await
                    .is_err()
                {
                    return;
                }
                let _ = socket.flush().await;
                for (rv, line) in replay {
                    if socket
                        .write_all(format!("{line}\n").as_bytes())
                        .await
                        .is_err()
                    {
                        return;
                    }
                    sent = sent.max(rv);
                }
                let _ = socket.flush().await;
                let deadline =
                    tokio::time::Instant::now() + std::time::Duration::from_secs(timeout);
                loop {
                    match tokio::time::timeout_at(deadline, rx.recv()).await {
                        Ok(Ok((r, rv, line))) if r == resource && rv > sent => {
                            sent = rv;
                            if socket
                                .write_all(format!("{line}\n").as_bytes())
                                .await
                                .is_err()
                            {
                                return;
                            }
                            let _ = socket.flush().await;
                        }
                        Ok(Ok(_)) => {}
                        _ => break,
                    }
                }
                let _ = socket.shutdown().await;
            });
        }
    });
    Server {
        origin,
        state,
        events,
        task,
    }
}
