//! A provider behind a private CA: an in-process HTTPS OIDC fixture whose
//! certificate a private CA signs (IP SAN 127.0.0.1), optionally requiring a
//! client certificate. Positive, wrong CA, built-in roots, host-name
//! mismatch, mutual TLS, reload, invalid reload, admin-API rows.
use super::*;
use crate::crypto::TestClock;
use crate::store::types::ManagedBy;
use std::path::Path;
use std::process::Command;

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

/// `ca1`/`ca2` with clients (from the reload tests' PKI), and `<ca>-ip`, a
/// server certificate for IP 127.0.0.1 signed by `<ca>`.
fn pki(dir: &Path) {
    for ca in ["ca1", "ca2"] {
        crate::reload::tests::pki(dir, ca);
        let name = format!("{ca}-ip");
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
            "basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1\n",
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

/// Serve discovery over HTTPS with `cert`/`key`; with `client_ca`, a client
/// certificate signed by it is mandatory. Returns the issuer.
async fn idp(dir: &Path, cert: &str, key: &str, client_ca: Option<&str>) -> String {
    let read = |f: &str| std::fs::read(dir.join(f)).unwrap();
    let config = match client_ca {
        Some(ca) => {
            crate::reload::server_config(
                &read(cert),
                &read(key),
                &read(ca),
                &[b"http/1.1".to_vec()],
            )
            .unwrap()
            .0
        }
        None => {
            let mut c = rustls::ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                crate::reload::certificates(&read(cert)).unwrap(),
                crate::reload::private_key(&read(key)).unwrap(),
            )
            .unwrap();
            c.alpn_protocols = vec![b"http/1.1".to_vec()];
            c
        }
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let issuer = format!(
        "https://127.0.0.1:{}",
        listener.local_addr().unwrap().port()
    );
    let doc = serde_json::json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/authorize"),
        "token_endpoint": format!("{issuer}/token"),
        "jwks_uri": format!("{issuer}/jwks"),
        "mtls_endpoint_aliases": {"token_endpoint": format!("{issuer}/mtls/token")},
    });
    let router = axum::Router::new().route(
        "/.well-known/openid-configuration",
        axum::routing::get(move || {
            let doc = doc.clone();
            async move { axum::Json(doc) }
        }),
    );
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            let router = router.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(
                        hyper_util::rt::TokioIo::new(tls),
                        hyper_util::service::TowerToHyperService::new(router),
                    )
                    .await;
            });
        }
    });
    issuer
}

fn row(issuer: &str, tls: serde_json::Value, managed_by: ManagedBy) -> ProviderRow {
    ProviderRow {
        provider_id: crate::provider::types::ProviderId::new("corp"),
        kind: ProviderKind::Oidc,
        display_name: "Corp".into(),
        enabled: true,
        managed_by,
        deleted_at: None,
        sort_order: 0,
        config: serde_json::json!({"client_id": "c", "issuer": issuer, "allow_private_endpoints": true, "tls": tls}),
        client_secret_env: None,
        allowed_email_domains: vec![],
        authoritative_domains: vec![],
        auto_link: false,
        trust_email: false,
    }
}

fn provider(row: &ProviderRow, clock: Arc<TestClock>) -> Arc<OidcProvider> {
    OidcProvider::from_row(row, &|_| None, clock, None)
}

async fn discovered(p: &OidcProvider, clock: &TestClock) -> bool {
    // Past any backoff of an earlier failure.
    clock.advance(Duration::from_secs(120));
    p.refresh_discovery().await;
    p.health().await == ProviderHealth::Ok
}

fn path(dir: &Path, f: &str) -> String {
    dir.join(f).to_string_lossy().into_owned()
}

fn copy(dir: &Path, from: &str, to: &str) {
    let tmp = dir.join(format!("{to}.tmp"));
    std::fs::copy(dir.join(from), &tmp).unwrap();
    std::fs::rename(&tmp, dir.join(to)).unwrap();
}

fn clock() -> Arc<TestClock> {
    Arc::new(TestClock::new(crate::crypto::Timestamp::from_secs(
        1_800_000_000,
    )))
}

#[tokio::test]
async fn a_private_ca_is_trusted_and_nothing_else() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    pki(d);
    let issuer = idp(d, "ca1-ip.pem", "ca1-ip.key", None).await;
    let c = clock();

    // The right CA: discovery succeeds; the status names the trust source.
    let p = provider(
        &row(
            &issuer,
            serde_json::json!({"ca_file": path(d, "ca1.pem")}),
            ManagedBy::File,
        ),
        c.clone(),
    );
    assert_eq!(p.disabled_reason(), None);
    assert!(discovered(&p, &c).await);
    let st = p.tls_status();
    assert_eq!(st["trust"], "ca_file");
    assert_eq!(st["client_certificate"], false);
    assert!(
        st["ca_fingerprint"]
            .as_str()
            .unwrap()
            .starts_with("sha256:")
    );
    assert_eq!(
        crate::telemetry::counters::get(
            trust::PROVIDER_TLS_TRUST,
            &[("provider", "corp"), ("source", "ca_file")]
        ),
        1
    );

    // Another CA, or the built-in roots: refused.
    let wrong = provider(
        &row(
            &issuer,
            serde_json::json!({"ca_file": path(d, "ca2.pem")}),
            ManagedBy::File,
        ),
        c.clone(),
    );
    assert!(!discovered(&wrong, &c).await);
    let mut system = row(&issuer, serde_json::Value::Null, ManagedBy::File);
    system.config.as_object_mut().unwrap().remove("tls");
    let system = provider(&system, c.clone());
    assert!(!discovered(&system, &c).await);
    assert_eq!(system.tls_status()["trust"], "system");

    // The host name is still verified: a certificate of the right CA for
    // another name (DNS hopae.example.test) is refused.
    let other = idp(d, "ca1-server.pem", "ca1-server.key", None).await;
    let mismatch = provider(
        &row(
            &other,
            serde_json::json!({"ca_file": path(d, "ca1.pem")}),
            ManagedBy::File,
        ),
        c.clone(),
    );
    assert!(!discovered(&mismatch, &c).await);
}

#[tokio::test]
async fn a_client_certificate_is_presented_and_the_mtls_alias_is_used() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    pki(d);
    let issuer = idp(d, "ca1-ip.pem", "ca1-ip.key", Some("ca2.pem")).await;
    let c = clock();
    let with = provider(
        &row(
            &issuer,
            serde_json::json!({"ca_file": path(d, "ca1.pem"), "client_certificate_file": path(d, "ca2-client.pem"), "client_key_file": path(d, "ca2-client.key")}),
            ManagedBy::File,
        ),
        c.clone(),
    );
    assert!(discovered(&with, &c).await);
    let st = with.tls_status();
    assert_eq!(st["client_certificate"], true);
    assert!(
        st["client_certificate_fingerprint"]
            .as_str()
            .unwrap()
            .starts_with("sha256:")
    );
    let disc = lock(&with.disc).valid(c.now()).unwrap();
    assert_eq!(with.token_endpoint(&disc).path(), "/mtls/token");

    // Without the certificate the IdP refuses the handshake.
    let without = provider(
        &row(
            &issuer,
            serde_json::json!({"ca_file": path(d, "ca1.pem")}),
            ManagedBy::File,
        ),
        c.clone(),
    );
    assert!(!discovered(&without, &c).await);

    // A key that does not match the certificate disables the provider.
    let mismatched = provider(
        &row(
            &issuer,
            serde_json::json!({"ca_file": path(d, "ca1.pem"), "client_certificate_file": path(d, "ca2-client.pem"), "client_key_file": path(d, "ca1-client.key")}),
            ManagedBy::File,
        ),
        c.clone(),
    );
    assert_eq!(mismatched.disabled_reason(), Some("tls_invalid"));
}

#[tokio::test]
async fn the_ca_file_is_reloaded_and_invalid_material_keeps_the_client() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    pki(d);
    let issuer = idp(d, "ca1-ip.pem", "ca1-ip.key", None).await;
    let c = clock();
    copy(d, "ca2.pem", "trust.pem");
    let p = provider(
        &row(
            &issuer,
            serde_json::json!({"ca_file": path(d, "trust.pem")}),
            ManagedBy::File,
        ),
        c.clone(),
    );
    assert!(!discovered(&p, &c).await, "the wrong CA first");
    assert_eq!(
        p.poll_tls_now().await,
        Some(crate::reload::Outcome::Unchanged)
    );

    // The right CA arrives: reloaded, and discovery succeeds.
    copy(d, "ca1.pem", "trust.pem");
    assert!(matches!(
        p.poll_tls_now().await,
        Some(crate::reload::Outcome::Reloaded(_))
    ));
    assert!(discovered(&p, &c).await);
    assert_eq!(p.tls_status()["reloads"], 1);

    // A broken file: the previous client stays, the failure is visible.
    std::fs::write(d.join("trust.pem"), b"not a certificate").unwrap();
    assert!(matches!(
        p.poll_tls_now().await,
        Some(crate::reload::Outcome::Invalid(_))
    ));
    assert_eq!(p.tls_status()["failing"], true);
    assert_eq!(
        crate::telemetry::counters::get(
            crate::reload::TLS_RELOAD_FAILING,
            &[("name", "provider:corp")]
        ),
        1
    );
    *lock(&p.disc) = Cache::empty();
    assert!(discovered(&p, &c).await, "still the previous trust");

    // Back to the material in use: no longer failing.
    copy(d, "ca1.pem", "trust.pem");
    assert_eq!(
        p.poll_tls_now().await,
        Some(crate::reload::Outcome::Unchanged)
    );
    assert_eq!(p.tls_status()["failing"], false);
}

#[test]
fn trust_files_are_only_from_the_configuration_file_and_well_formed() {
    let ok = serde_json::json!({"ca_file": "/etc/corp/ca.pem"});
    let file = row("https://idp.example.test", ok.clone(), ManagedBy::File);
    assert!(
        OidcSettings::from_row(&file, &|_| None)
            .trust_files
            .is_some()
    );
    // The admin API cannot name a file on Hopae's host.
    let api = row("https://idp.example.test", ok, ManagedBy::Api);
    assert_eq!(
        OidcSettings::from_row(&api, &|_| None).disabled_reason,
        Some("misconfigured")
    );
    for bad in [
        serde_json::json!({"ca_file": "relative.pem"}),
        serde_json::json!({"client_certificate_file": "/c.pem"}),
        serde_json::json!({"ca_file": "/ca.pem", "other": 1}),
        serde_json::json!("ca.pem"),
    ] {
        let r = row("https://idp.example.test", bad.clone(), ManagedBy::File);
        assert_eq!(
            OidcSettings::from_row(&r, &|_| None).disabled_reason,
            Some("misconfigured"),
            "{bad}"
        );
    }
    // A missing file disables the provider instead of falling back.
    let missing = row(
        "https://idp.example.test",
        serde_json::json!({"ca_file": "/nonexistent/ca.pem"}),
        ManagedBy::File,
    );
    let p = OidcProvider::from_row(&missing, &|_| None, clock(), None);
    assert_eq!(p.disabled_reason(), Some("tls_invalid"));
}
