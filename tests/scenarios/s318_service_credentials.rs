//! Scenario 318: route-scoped, read-only service credentials on the admin
//! listener (mTLS + bearer), the shape Pumgye policy v2 uses to read the
//! membership projection and the subject lifecycle feed.
//!
//! In-process: a generated CA, server and client certificates (openssl crate,
//! no files outside the temporary directory), the real `bind`/`run` of the
//! application with `listen.admin_tls`, and the real admin CLI.
#![allow(dead_code)]

use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::x509::extension::{BasicConstraints, ExtendedKeyUsage, SubjectAlternativeName};
use openssl::x509::{X509, X509NameBuilder};
use serde_json::{Value, json};
use std::path::Path;

use crate::support::*;
use hopae::app::{AdminCommand, ServiceCredentialCommand};

const ADMIN_HOST: &str = "hopae-admin.example.test";
const AUDIENCE: &str = "https://hopae-admin.example.test";
const SAN: &str = "spiffe://cluster.example.test/ns/world/sa/pumgye";

fn key() -> PKey<Private> {
    PKey::from_ec_key(
        EcKey::generate(&EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap()).unwrap(),
    )
    .unwrap()
}

fn name(cn: &str) -> openssl::x509::X509Name {
    let mut b = X509NameBuilder::new().unwrap();
    b.append_entry_by_text("CN", cn).unwrap();
    b.build()
}

fn cert(
    ca: Option<(&X509, &PKey<Private>)>,
    key: &PKey<Private>,
    cn: &str,
    serial: u32,
    san: Option<SubjectAlternativeName>,
    server: bool,
) -> X509 {
    let mut b = X509::builder().unwrap();
    b.set_version(2).unwrap();
    b.set_serial_number(&BigNum::from_u32(serial).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    b.set_subject_name(&name(cn)).unwrap();
    b.set_issuer_name(ca.map_or(&name(cn), |(c, _)| c.subject_name()))
        .unwrap();
    b.set_pubkey(key).unwrap();
    b.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    b.set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    match ca {
        None => b
            .append_extension(BasicConstraints::new().critical().ca().build().unwrap())
            .unwrap(),
        Some((issuer, _)) => {
            if let Some(s) = san {
                let ext = s.build(&b.x509v3_context(Some(issuer), None)).unwrap();
                b.append_extension(ext).unwrap();
            }
            b.append_extension(BasicConstraints::new().build().unwrap())
                .unwrap();
            let mut eku = ExtendedKeyUsage::new();
            if server {
                eku.server_auth();
            } else {
                eku.client_auth();
            }
            b.append_extension(eku.build().unwrap()).unwrap();
        }
    }
    b.sign(ca.map_or(key, |(_, k)| k), MessageDigest::sha256())
        .unwrap();
    b.build()
}

struct Pki {
    ca: X509,
    client: (X509, PKey<Private>),
    /// Same SAN, another key: matches a SAN binding, not an SPKI pin.
    other: (X509, PKey<Private>),
}

fn pki(dir: &Path) -> Pki {
    let ca_key = key();
    let ca = cert(None, &ca_key, "s318 CA", 1, None, false);
    let server_key = key();
    let mut san = SubjectAlternativeName::new();
    san.dns(ADMIN_HOST).dns("localhost").ip("127.0.0.1");
    let server = cert(
        Some((&ca, &ca_key)),
        &server_key,
        ADMIN_HOST,
        2,
        Some(san),
        true,
    );
    let client = |serial| {
        let k = key();
        let mut san = SubjectAlternativeName::new();
        san.uri(SAN);
        (
            cert(Some((&ca, &ca_key)), &k, "pumgye", serial, Some(san), false),
            k,
        )
    };
    std::fs::write(dir.join("ca.pem"), ca.to_pem().unwrap()).unwrap();
    std::fs::write(dir.join("server.pem"), server.to_pem().unwrap()).unwrap();
    std::fs::write(
        dir.join("server.key"),
        server_key.private_key_to_pem_pkcs8().unwrap(),
    )
    .unwrap();
    let (client, other) = (client(3), client(4));
    Pki { ca, client, other }
}

fn spki_sha256(c: &X509) -> String {
    use sha2::Digest as _;
    let der = c.public_key().unwrap().public_key_to_der().unwrap();
    data_encoding::HEXLOWER.encode(&sha2::Sha256::digest(&der))
}

struct Fx {
    dir: tempfile::TempDir,
    cfg: hopae::config::Config,
    pki: Pki,
    addr: std::net::SocketAddr,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<anyhow::Result<()>>>,
}

impl Fx {
    async fn start(tls: bool) -> Fx {
        let dir = tempfile::tempdir().unwrap();
        let pki = pki(dir.path());
        let mut json: Value = serde_json::from_str(&config_json(dir.path())).unwrap();
        json["admin"] = json!({"public_url": format!("https://{ADMIN_HOST}")});
        json["listen"]["admin"] = json!("127.0.0.1:0");
        if tls {
            json["listen"]["admin_tls"] = json!({"certificate": dir.path().join("server.pem"), "key": dir.path().join("server.key"), "client_ca": dir.path().join("ca.pem")});
        } else {
            json["admin"]["untrusted_peers"] = json!("as_client");
        }
        let cfg = hopae::config::parse(&json.to_string()).unwrap();
        let bound = hopae::app::bind(&cfg).await.unwrap();
        let addr = bound.admin_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(bound.run(async {
            let _ = rx.await;
        }));
        Fx {
            dir,
            cfg,
            pki,
            addr,
            stop: Some(tx),
            task: Some(task),
        }
    }

    async fn stop(mut self) {
        let _ = self.stop.take().unwrap().send(());
        let _ = self.task.take().unwrap().await;
    }

    async fn cli(&self, cmd: ServiceCredentialCommand) -> hopae::app::AdminCliOutput {
        hopae::app::admin_cli_with(&self.cfg, AdminCommand::ServiceCredential(cmd), false)
            .await
            .unwrap()
    }

    async fn create(&self, id: &str, edit: impl FnOnce(&mut ServiceCredentialCommand)) -> String {
        let mut cmd = ServiceCredentialCommand::Create {
            id: id.into(),
            routes: vec!["POST /v1/subjects/resolve".into()],
            preset: Some("pumgye-v2".into()),
            audiences: vec![],
            client_spki_sha256: Some(spki_sha256(&self.pki.client.0)),
            client_san: Some(SAN.into()),
            expires_in_days: 30,
            rate_per_minute: 600,
            burst: 100,
            note: Some("pumgye v2 owner reads".into()),
        };
        edit(&mut cmd);
        let out = self.cli(cmd).await;
        assert_eq!(out.code, 0, "{}", out.stderr);
        out.stdout.trim().to_string()
    }

    fn client(&self, which: Option<&(X509, PKey<Private>)>) -> reqwest::Client {
        let mut b = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .tls_built_in_root_certs(false)
            .add_root_certificate(
                reqwest::Certificate::from_pem(&self.pki.ca.to_pem().unwrap()).unwrap(),
            )
            .resolve(ADMIN_HOST, self.addr)
            .timeout(std::time::Duration::from_secs(5));
        if let Some((c, k)) = which {
            let mut pem = c.to_pem().unwrap();
            pem.extend(k.private_key_to_pem_pkcs8().unwrap());
            b = b.identity(reqwest::Identity::from_pem(&pem).unwrap());
        }
        b.build().unwrap()
    }

    async fn call(
        &self,
        client: &reqwest::Client,
        method: &str,
        path: &str,
        token: Option<&str>,
        audience: Option<&str>,
    ) -> (u16, Value) {
        let body = if path == "/v1/subjects/resolve" {
            r#"{"ids":["u_nobody"]}"#
        } else {
            "{}"
        };
        let scheme = if self.cfg.listen.admin_tls.is_some() {
            "https"
        } else {
            "http"
        };
        let url = format!("{scheme}://{ADMIN_HOST}:{}{path}", self.addr.port());
        let mut r = client
            .request(method.parse().unwrap(), &url)
            .header("content-type", "application/json")
            .header("x-hopae-admin-request", "1");
        if scheme == "http" {
            // Behind the (trusted loopback) proxy of a plain admin listener.
            r = r
                .header("x-forwarded-host", ADMIN_HOST)
                .header("x-forwarded-proto", "https")
                .header("x-forwarded-for", "192.0.2.8");
        }
        if let Some(t) = token {
            r = r.header("authorization", format!("Bearer {t}"));
        }
        if let Some(a) = audience {
            r = r.header("x-hopae-audience", a);
        }
        if method == "POST" {
            r = r.body(body);
        }
        let resp = r.send().await.unwrap();
        let status = resp.status().as_u16();
        let body = resp.json::<Value>().await.unwrap_or(Value::Null);
        (status, body)
    }

    fn sql(&self) -> rusqlite::Connection {
        rusqlite::Connection::open(self.cfg.store_path()).unwrap()
    }

    fn reads(&self, credential: &str) -> Vec<Value> {
        let c = self.sql();
        let mut st = c
            .prepare("SELECT attrs FROM events WHERE kind = 'admin.read' ORDER BY rowid")
            .unwrap();
        st.query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .map(|a| serde_json::from_str::<Value>(&a.unwrap()).unwrap())
            .filter(|a| a["credential_id"] == credential)
            .collect()
    }
}

/// S318-1: the Pumgye preset reads the lifecycle feed and snapshot with its
/// mTLS-bound bearer; every answered read is audited with the credential id.
#[tokio::test(flavor = "multi_thread")]
async fn s318_1_scoped_credential_reads_lifecycle_and_is_audited() {
    let fx = Fx::start(true).await;
    let token = fx.create("pumgye-v2", |_| {}).await;
    assert!(token.starts_with("hsc1.pumgye-v2.") && token.len() == "hsc1.pumgye-v2.".len() + 43);
    let c = fx.client(Some(&fx.pki.client));
    let (s, body) = fx
        .call(
            &c,
            "POST",
            "/v1/subjects/lifecycle",
            Some(&token),
            Some(AUDIENCE),
        )
        .await;
    assert_eq!(s, 200, "{body}");
    assert!(body["next_cursor"].is_string());
    let (s, body) = fx
        .call(
            &c,
            "POST",
            "/v1/subjects/resolve",
            Some(&token),
            Some(AUDIENCE),
        )
        .await;
    assert_eq!(s, 200, "{body}");
    let (s, body) = fx
        .call(
            &c,
            "POST",
            "/v1/subjects/lifecycle/snapshot",
            Some(&token),
            Some(AUDIENCE),
        )
        .await;
    assert_eq!(s, 200, "{body}");
    // The projection routes are admitted (the projection itself answers by
    // its own configuration: unconfigured signer → 503, never a 403).
    let (s, body) = fx
        .call(
            &c,
            "POST",
            "/v1/groups/projection/snapshot",
            Some(&token),
            Some(AUDIENCE),
        )
        .await;
    assert_ne!(s, 403, "{body}");
    assert_ne!(s, 401, "{body}");
    let reads = fx.reads("pumgye-v2");
    assert!(!reads.is_empty(), "admin.read with credential_id");
    assert!(
        reads
            .iter()
            .all(|r| r["actor"] == "service:pumgye-v2" && r["credential_slot"] == "current")
    );
    // The digest, never the secret, is stored.
    let secret = token.rsplit('.').next().unwrap();
    let stored: String = fx
        .sql()
        .query_row(
            "SELECT current_sha256 FROM service_credentials WHERE credential_id='pumgye-v2'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(!stored.contains(secret) && stored.len() == 64);
    let dump = std::fs::read(fx.cfg.store_path()).unwrap();
    assert!(!dump.windows(secret.len()).any(|w| w == secret.as_bytes()));
    fx.stop().await;
}

/// S318-2: wrong secret, other key, missing/foreign audience, unlisted route,
/// a mutation route even if stored by tampering, and the rate limit refuse.
#[tokio::test(flavor = "multi_thread")]
async fn s318_2_refusals_are_route_binding_audience_and_rate_scoped() {
    let fx = Fx::start(true).await;
    let token = fx
        .create("pumgye-v2", |c| {
            if let ServiceCredentialCommand::Create {
                burst,
                rate_per_minute,
                ..
            } = c
            {
                *burst = 6;
                *rate_per_minute = 1;
            }
        })
        .await;
    let good = fx.client(Some(&fx.pki.client));
    let other = fx.client(Some(&fx.pki.other));
    let path = "/v1/subjects/lifecycle";
    let forged = format!(
        "{}{}",
        &token[..token.len() - 1],
        if token.ends_with('A') { 'B' } else { 'A' }
    );
    assert_eq!(
        fx.call(&good, "POST", path, Some(&forged), Some(AUDIENCE))
            .await
            .0,
        401
    );
    assert_eq!(
        fx.call(
            &good,
            "POST",
            path,
            Some("hsc1.nobody-here.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            Some(AUDIENCE)
        )
        .await
        .0,
        401
    );
    let (s, b) = fx
        .call(&other, "POST", path, Some(&token), Some(AUDIENCE))
        .await;
    assert_eq!(
        (s, b["error"].as_str()),
        (403, Some("service_binding_mismatch"))
    );
    let (s, b) = fx.call(&good, "POST", path, Some(&token), None).await;
    assert_eq!(
        (s, b["error"].as_str()),
        (403, Some("service_audience_mismatch"))
    );
    let (s, b) = fx
        .call(
            &good,
            "POST",
            path,
            Some(&token),
            Some("https://other.example.test"),
        )
        .await;
    assert_eq!(
        (s, b["error"].as_str()),
        (403, Some("service_audience_mismatch"))
    );
    let (s, b) = fx
        .call(
            &good,
            "POST",
            "/v1/subjects/search",
            Some(&token),
            Some(AUDIENCE),
        )
        .await;
    assert_eq!(
        (s, b["error"].as_str()),
        (403, Some("service_route_forbidden"))
    );
    // Even a tampered row naming a mutation is refused.
    fx.sql()
        .execute(
            "UPDATE service_credentials SET routes='[\"POST /v1/groups/create\",\"POST /v1/subjects/lifecycle\"]' WHERE credential_id='pumgye-v2'",
            [],
        )
        .unwrap();
    let (s, b) = fx
        .call(
            &good,
            "POST",
            "/v1/groups/create",
            Some(&token),
            Some(AUDIENCE),
        )
        .await;
    assert_eq!(
        (s, b["error"].as_str()),
        (403, Some("service_route_forbidden"))
    );
    // Without a credential, the client certificate alone is no administrator.
    let (s, _) = fx.call(&good, "POST", path, None, Some(AUDIENCE)).await;
    assert!(matches!(s, 401 | 403 | 404), "{s}");
    // The per-credential bucket (burst 6, 1/min): refusals above did not
    // consume it; reads do.
    let mut statuses = Vec::new();
    for _ in 0..8 {
        statuses.push(
            fx.call(&good, "POST", path, Some(&token), Some(AUDIENCE))
                .await
                .0,
        );
    }
    assert!(statuses.contains(&429), "{statuses:?}");
    assert!(
        statuses.iter().filter(|s| **s == 200).count() >= 1,
        "{statuses:?}"
    );
    fx.stop().await;
}

/// S318-3: rotation keeps both secrets, promotion retires the old one,
/// revocation and expiry refuse, and the transport must be mTLS.
#[tokio::test(flavor = "multi_thread")]
async fn s318_3_rotation_promotion_revocation_expiry_and_transport() {
    let fx = Fx::start(true).await;
    let old = fx.create("pumgye-v2", |_| {}).await;
    let c = fx.client(Some(&fx.pki.client));
    let path = "/v1/subjects/lifecycle";
    let out = fx
        .cli(ServiceCredentialCommand::Rotate {
            id: "pumgye-v2".into(),
        })
        .await;
    assert_eq!(out.code, 0, "{}", out.stderr);
    let new = out.stdout.trim().to_string();
    assert_ne!(new, old);
    assert_eq!(
        fx.call(&c, "POST", path, Some(&old), Some(AUDIENCE))
            .await
            .0,
        200
    );
    assert_eq!(
        fx.call(&c, "POST", path, Some(&new), Some(AUDIENCE))
            .await
            .0,
        200
    );
    assert_eq!(
        fx.call(
            &c,
            "POST",
            "/v1/subjects/resolve",
            Some(&new),
            Some(AUDIENCE)
        )
        .await
        .0,
        200
    );
    assert!(
        fx.reads("pumgye-v2")
            .iter()
            .any(|r| r["credential_slot"] == "next")
    );
    let pending = fx
        .cli(ServiceCredentialCommand::Rotate {
            id: "pumgye-v2".into(),
        })
        .await;
    assert_ne!(pending.code, 0, "a second rotation waits for promote");
    assert_eq!(
        fx.cli(ServiceCredentialCommand::Promote {
            id: "pumgye-v2".into()
        })
        .await
        .code,
        0
    );
    assert_eq!(
        fx.call(&c, "POST", path, Some(&old), Some(AUDIENCE))
            .await
            .0,
        401
    );
    assert_eq!(
        fx.call(&c, "POST", path, Some(&new), Some(AUDIENCE))
            .await
            .0,
        200
    );
    // Expiry (shortened by SQL), then revocation.
    fx.sql()
        .execute(
            "UPDATE service_credentials SET expires_at=1 WHERE credential_id='pumgye-v2'",
            [],
        )
        .unwrap();
    assert_eq!(
        fx.call(&c, "POST", path, Some(&new), Some(AUDIENCE))
            .await
            .0,
        401
    );
    fx.sql()
        .execute(
            "UPDATE service_credentials SET expires_at=4000000000 WHERE credential_id='pumgye-v2'",
            [],
        )
        .unwrap();
    assert_eq!(
        fx.call(&c, "POST", path, Some(&new), Some(AUDIENCE))
            .await
            .0,
        200
    );
    assert_eq!(
        fx.cli(ServiceCredentialCommand::Revoke {
            id: "pumgye-v2".into()
        })
        .await
        .code,
        0
    );
    assert_eq!(
        fx.call(&c, "POST", path, Some(&new), Some(AUDIENCE))
            .await
            .0,
        401
    );
    assert_ne!(
        fx.cli(ServiceCredentialCommand::Rotate {
            id: "pumgye-v2".into()
        })
        .await
        .code,
        0
    );
    let list = fx.cli(ServiceCredentialCommand::List).await;
    assert!(
        list.stdout.contains("pumgye-v2  revoked"),
        "{}",
        list.stdout
    );
    assert!(!list.stdout.contains(new.rsplit('.').next().unwrap()));
    // Change events travel with the store change.
    let changes: Vec<String> = {
        let c = fx.sql();
        let mut st = c.prepare("SELECT json_extract(attrs,'$.change') FROM events WHERE kind='admin.service_credential' ORDER BY rowid").unwrap();
        st.query_map([], |r| r.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    };
    assert_eq!(changes, vec!["created", "rotated", "promoted", "revoked"]);
    fx.stop().await;

    // Off the mTLS listener a service token is never accepted.
    let plain = Fx::start(false).await;
    let token = plain.create("pumgye-v2", |_| {}).await;
    let c = plain.client(None);
    let (s, b) = plain
        .call(&c, "POST", path, Some(&token), Some(AUDIENCE))
        .await;
    assert_eq!(
        (s, b["error"].as_str()),
        (403, Some("service_transport_required")),
        "{b}"
    );
    plain.stop().await;
}

/// S318-A1: the CLI never creates a mutation-capable or unbound credential.
#[tokio::test(flavor = "multi_thread")]
async fn s318_a1_cli_refuses_mutations_unbound_and_malformed_credentials() {
    let fx = Fx::start(true).await;
    let base = |edit: &dyn Fn(&mut ServiceCredentialCommand)| {
        let mut c = ServiceCredentialCommand::Create {
            id: "pumgye-v2".into(),
            routes: vec![],
            preset: Some("pumgye-v2".into()),
            audiences: vec![],
            client_spki_sha256: None,
            client_san: Some(SAN.into()),
            expires_in_days: 30,
            rate_per_minute: 60,
            burst: 10,
            note: None,
        };
        edit(&mut c);
        c
    };
    type Edit = Box<dyn Fn(&mut ServiceCredentialCommand)>;
    let cases: Vec<(&str, Edit)> = vec![
        (
            "mutation route",
            Box::new(|c| {
                if let ServiceCredentialCommand::Create { routes, .. } = c {
                    routes.push("POST /v1/groups/members/add".into())
                }
            }),
        ),
        (
            "profile publication",
            Box::new(|c| {
                if let ServiceCredentialCommand::Create { routes, .. } = c {
                    routes.push("PUT /v1/authentication/profiles".into())
                }
            }),
        ),
        (
            "unknown route",
            Box::new(|c| {
                if let ServiceCredentialCommand::Create { routes, .. } = c {
                    routes.push("GET /v1/users".into())
                }
            }),
        ),
        (
            "no binding",
            Box::new(|c| {
                if let ServiceCredentialCommand::Create { client_san, .. } = c {
                    *client_san = None
                }
            }),
        ),
        (
            "bad id",
            Box::new(|c| {
                if let ServiceCredentialCommand::Create { id, .. } = c {
                    *id = "Pumgye".into()
                }
            }),
        ),
        (
            "too long",
            Box::new(|c| {
                if let ServiceCredentialCommand::Create {
                    expires_in_days, ..
                } = c
                {
                    *expires_in_days = 401
                }
            }),
        ),
        (
            "bad pin",
            Box::new(|c| {
                if let ServiceCredentialCommand::Create {
                    client_spki_sha256, ..
                } = c
                {
                    *client_spki_sha256 = Some("zz".into())
                }
            }),
        ),
        (
            "unknown preset",
            Box::new(|c| {
                if let ServiceCredentialCommand::Create { preset, .. } = c {
                    *preset = Some("all".into())
                }
            }),
        ),
    ];
    for (name, edit) in cases {
        let out = fx.cli(base(&*edit)).await;
        assert_ne!(out.code, 0, "{name}");
        assert!(out.stdout.is_empty(), "{name}: no token printed");
    }
    assert_eq!(fx.cli(base(&|_| {})).await.code, 0);
    assert_ne!(fx.cli(base(&|_| {})).await.code, 0, "ids are never reused");
    let n: i64 = fx
        .sql()
        .query_row("SELECT count(*) FROM service_credentials", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 1);
    fx.stop().await;
}
