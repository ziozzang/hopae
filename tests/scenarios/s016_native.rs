//! The native socket re-enters the same real caller/parse/session engine.
use super::s004_verify::fx::Fx;
use axum::{
    body::{Body, to_bytes},
    http::Request,
};
use hopae::{
    app::CallerKeys,
    crypto::Secret,
    gateway::{hangang::GatewayConfig, native_codec as wire},
    http::{
        gateway::{GatewayState, router},
        native_gateway,
    },
};
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::watch,
};
use tower::ServiceExt;
async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut S,
    id: u64,
    b: &[u8],
) -> (u64, Vec<u8>) {
    let mut out = wire::frame_header(id, b.len()).unwrap().to_vec();
    out.extend_from_slice(b);
    s.write_all(&out).await.unwrap();
    let mut h = [0; 16];
    s.read_exact(&mut h).await.unwrap();
    let (id, n) = wire::parse_header(h).unwrap();
    let mut b = vec![0; n];
    s.read_exact(&mut b).await.unwrap();
    (id, b)
}
fn context(path: &str) -> Vec<(String, Vec<u8>)> {
    vec![
        ("accept".into(), b"text/html".to_vec()),
        ("sec-fetch-mode".into(), b"navigate".to_vec()),
        ("sec-fetch-dest".into(), b"document".to_vec()),
        ("sec-fetch-site".into(), b"same-origin".to_vec()),
        ("x-hopae-contract".into(), b"1".to_vec()),
        ("x-forwarded-host".into(), b"app.example.test".to_vec()),
        ("x-forwarded-proto".into(), b"https".to_vec()),
        ("x-forwarded-port".into(), b"443".to_vec()),
        ("x-forwarded-for".into(), b"203.0.113.9".to_vec()),
        (
            "x-original-url".into(),
            format!("https://app.example.test{path}").into_bytes(),
        ),
        ("x-original-method".into(), b"GET".to_vec()),
        ("x-original-uri".into(), path.as_bytes().to_vec()),
    ]
}
#[tokio::test]
async fn native_http_parity_session_revocation_and_reserved_entries() {
    let fx = Fx::new("m1-basic");
    let keys = Arc::new(CallerKeys::new(
        Some(Secret::new("native-test-key".into())),
        None,
        false,
    ));
    let router = router(GatewayState::new(
        GatewayConfig::from_config(&fx.cfg),
        fx.ctx.clone(),
        keys.clone(),
        32,
        None,
        None,
    ));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (tx, rx) = watch::channel(false);
    let task = tokio::spawn(native_gateway::serve(listener, router.clone(), keys, rx));
    let mut s = TcpStream::connect(address).await.unwrap();
    assert_eq!(exchange(&mut s, 0, b"native-test-key").await.1, [1]);
    let user = fx.user("native@example.test", Some("native"), None).await;
    let session = fx.session(&user).await;
    let handle = fx.handle(&session, "app.example.test").await;
    for (i, path) in ["/private", "/_hopae/login", "/_hopae/logout"]
        .into_iter()
        .enumerate()
    {
        let mut hs = context(path);
        hs.push((
            "cookie".into(),
            format!("__Host-hopae={}", handle.expose()).into_bytes(),
        ));
        let mut req = Request::builder()
            .uri("/_hopae/verify")
            .body(Body::empty())
            .unwrap();
        for (n, v) in &hs {
            req.headers_mut().append(
                axum::http::HeaderName::from_bytes(n.as_bytes()).unwrap(),
                axum::http::HeaderValue::from_bytes(v).unwrap(),
            );
        }
        req.headers_mut()
            .insert("x-hopae-gateway-key", "native-test-key".parse().unwrap());
        let http = router.clone().oneshot(req).await.unwrap();
        let status = http.status();
        let reason = http.headers().get("x-hopae-reason").cloned();
        let _ = to_bytes(http.into_body(), wire::MAX_BODY).await.unwrap();
        let (id, payload) =
            exchange(&mut s, i as u64 + 1, &wire::encode_request(&hs).unwrap()).await;
        assert_eq!(id, i as u64 + 1);
        let reply = wire::decode_reply(&payload).unwrap();
        assert_eq!(reply.status, status.as_u16());
        let native_reason = reply
            .headers
            .iter()
            .find(|(n, _)| n == "x-hopae-reason")
            .map(|(_, v)| v.as_slice());
        assert_eq!(native_reason, reason.as_ref().map(|v| v.as_bytes()));
        if path == "/private" {
            assert_eq!(reply.status, 200);
        } else {
            assert_eq!(reply.status, 302);
        }
    }
    // Logout GET only starts the existing confirmation flow: the session remains valid.
    assert!(fx.session_state(&session).0.is_none());
    fx.exec("UPDATE sessions SET terminated_at=1800000000,terminated_reason='logout'");
    let mut hs = context("/private");
    hs.push((
        "cookie".into(),
        format!("__Host-hopae={}", handle.expose()).into_bytes(),
    ));
    let (_, payload) = exchange(&mut s, 4, &wire::encode_request(&hs).unwrap()).await;
    assert_ne!(wire::decode_reply(&payload).unwrap().status, 200);
    // Request-id replay closes the persistent connection rather than replaying a login/logout.
    let h = wire::frame_header(4, 2).unwrap();
    s.write_all(&h).await.unwrap();
    s.write_all(&[0, 0]).await.unwrap();
    let mut one = [0];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), s.read(&mut one))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    tx.send(true).unwrap();
    task.await.unwrap().unwrap();
}
#[tokio::test]
async fn native_wrong_key_and_injected_caller_key_are_rejected() {
    let fx = Fx::new("m1-basic");
    let keys = Arc::new(CallerKeys::new(
        Some(Secret::new("native-test-key".into())),
        None,
        false,
    ));
    let r = router(GatewayState::new(
        GatewayConfig::from_config(&fx.cfg),
        fx.ctx.clone(),
        keys.clone(),
        32,
        None,
        None,
    ));
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    let (tx, rx) = watch::channel(false);
    let task = tokio::spawn(native_gateway::serve(l, r, keys, rx));
    let mut s = TcpStream::connect(a).await.unwrap();
    assert_eq!(exchange(&mut s, 0, b"wrong").await.1, [0]);
    let mut s = TcpStream::connect(a).await.unwrap();
    assert_eq!(exchange(&mut s, 0, b"native-test-key").await.1, [1]);
    let mut hs = context("/");
    hs.push(("x-hopae-gateway-key".into(), b"injected".to_vec()));
    let b = wire::encode_request(&hs).unwrap();
    s.write_all(&wire::frame_header(1, b.len()).unwrap())
        .await
        .unwrap();
    s.write_all(&b).await.unwrap();
    let mut one = [0];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), s.read(&mut one))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    tx.send(true).unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn native_mtls_remote_listener_identity_revocation_and_client_certificate_required() {
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
        std::fs::write(root.join(&ext),format!("basicConstraints=critical,CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage={usage}\nsubjectAltName=DNS:hopae.example.test\n")).unwrap();
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
    let tls = native_gateway::tls_acceptor(&hopae::config::NativeGatewayTls {
        certificate: root.join("server.pem"),
        key: root.join("server.key"),
        client_ca: root.join("ca.pem"),
    })
    .unwrap();
    let fx = Fx::new("m1-basic");
    let keys = Arc::new(CallerKeys::new(
        Some(Secret::new("native-test-key".into())),
        None,
        false,
    ));
    let router = router(GatewayState::new(
        GatewayConfig::from_config(&fx.cfg),
        fx.ctx.clone(),
        keys.clone(),
        32,
        None,
        None,
    ));
    let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let address = format!("127.0.0.1:{port}");
    let (tx, rx) = watch::channel(false);
    let task = tokio::spawn(native_gateway::serve_with_tls(
        listener,
        router,
        keys,
        rx,
        Some(tls),
    ));
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut std::fs::read(root.join("ca.pem")).unwrap().as_slice()) {
        roots.add(cert.unwrap()).unwrap();
    }
    let certs =
        rustls_pemfile::certs(&mut std::fs::read(root.join("client.pem")).unwrap().as_slice())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
    let key = rustls_pemfile::private_key(
        &mut std::fs::read(root.join("client.key")).unwrap().as_slice(),
    )
    .unwrap()
    .unwrap();
    let mut client = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots.clone())
        .with_client_auth_cert(certs, key)
        .unwrap();
    client.alpn_protocols = vec![b"hop1".to_vec()];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client));
    assert!(
        connector
            .connect(
                "wrong.example.test".try_into().unwrap(),
                TcpStream::connect(&address).await.unwrap()
            )
            .await
            .is_err()
    );
    let mut s = connector
        .connect(
            "hopae.example.test".try_into().unwrap(),
            TcpStream::connect(&address).await.unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(exchange(&mut s, 0, b"native-test-key").await.1, [1]);
    let user = fx.user("native@example.test", Some("native"), None).await;
    let session = fx.session(&user).await;
    let handle = fx.handle(&session, "app.example.test").await;
    let mut hs = context("/private");
    hs.push((
        "cookie".into(),
        format!("__Host-hopae={}", handle.expose()).into_bytes(),
    ));
    let payload = wire::encode_request(&hs).unwrap();
    assert_eq!(
        wire::decode_reply(&exchange(&mut s, 1, &payload).await.1)
            .unwrap()
            .status,
        200
    );
    fx.exec("UPDATE sessions SET terminated_at=1800000000,terminated_reason='logout'");
    assert_ne!(
        wire::decode_reply(&exchange(&mut s, 2, &payload).await.1)
            .unwrap()
            .status,
        200
    );
    let mut anonymous = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    anonymous.alpn_protocols = vec![b"hop1".to_vec()];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(anonymous));
    if let Ok(mut anonymous) = connector
        .connect(
            "hopae.example.test".try_into().unwrap(),
            TcpStream::connect(&address).await.unwrap(),
        )
        .await
    {
        let mut byte = [0];
        assert!(anonymous.read(&mut byte).await.is_err());
    }
    tx.send(true).unwrap();
    task.await.unwrap().unwrap();
}

#[test]
fn native_remote_configuration_requires_complete_mtls_and_authenticated_callers() {
    let mut cfg = Fx::new("m1-basic").cfg;
    cfg.listen.native_gateway = Some("0.0.0.0:8703".into());
    assert!(cfg.validate().is_err());
    cfg.listen.native_gateway_tls = Some(hopae::config::NativeGatewayTls {
        certificate: "/etc/hopae/server.pem".into(),
        key: "/etc/hopae/server.key".into(),
        client_ca: "/etc/hopae/client-ca.pem".into(),
    });
    assert!(cfg.validate().is_ok());
    cfg.gateway.allow_unauthenticated_caller = true;
    assert!(cfg.validate().is_err());
    cfg.gateway.allow_unauthenticated_caller = false;
    cfg.listen.native_gateway_tls.as_mut().unwrap().key = "relative.key".into();
    assert!(cfg.validate().is_err());
    cfg.listen.native_gateway_tls.as_mut().unwrap().key = "/etc/hopae/server.key".into();
    cfg.listen.native_gateway = None;
    assert!(cfg.validate().is_err());
}

#[tokio::test]
async fn service_api_credential_http_native_parity_and_no_human_assurance() {
    let fx = Fx::new("m1-basic");
    let config:hopae::auth_gateway::runtime::Config=serde_json::from_value(serde_json::json!({"authority_id":"owned","profiles":[{"service_id":"app","host":"app.example.test","ports":[443],"realm":"services","api_keys":[{"token_env":"OWNED_KEY","subject":"scheduler"}],"networks":["203.0.113.0/24"],"session_fallback":true}]})).unwrap();
    let credential = "owned-service-credential-at-least-thirty-two-bytes";
    let runtime =
        hopae::auth_gateway::runtime::Runtime::compile(&config, &|_| Some(credential.into()))
            .unwrap();
    let keys = Arc::new(CallerKeys::new(
        Some(Secret::new("native-test-key".into())),
        None,
        false,
    ));
    let state = GatewayState::new(
        GatewayConfig::from_config(&fx.cfg),
        fx.ctx.clone(),
        keys.clone(),
        32,
        None,
        None,
    )
    .with_authentication_gateway(runtime)
    .unwrap();
    let router = router(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (tx, rx) = watch::channel(false);
    let task = tokio::spawn(native_gateway::serve(listener, router.clone(), keys, rx));
    let mut socket = TcpStream::connect(address).await.unwrap();
    assert_eq!(exchange(&mut socket, 0, b"native-test-key").await.1, [1]);
    let user = fx.user("mixed@example.test", Some("mixed"), None).await;
    let session = fx.session(&user).await;
    let handle = fx.handle(&session, "app.example.test").await;
    for (id, valid) in [(1, true), (2, false)] {
        let mut headers = context("/private");
        headers.push((
            "cookie".into(),
            format!("__Host-hopae={}", handle.expose()).into_bytes(),
        ));
        headers.push((
            "authorization".into(),
            format!(
                "Bearer {}",
                if valid {
                    credential
                } else {
                    "invalid-service-credential-thirty-two-bytes"
                }
            )
            .into_bytes(),
        ));
        let mut request = Request::builder()
            .uri("/_hopae/verify")
            .body(Body::empty())
            .unwrap();
        for (name, value) in &headers {
            request.headers_mut().append(
                axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                axum::http::HeaderValue::from_bytes(value).unwrap(),
            );
        }
        request
            .headers_mut()
            .insert("x-hopae-gateway-key", "native-test-key".parse().unwrap());
        let http = router.clone().oneshot(request).await.unwrap();
        let expected = http.status().as_u16();
        assert_eq!(expected, if valid { 200 } else { 401 });
        let (_, payload) =
            exchange(&mut socket, id, &wire::encode_request(&headers).unwrap()).await;
        let native = wire::decode_reply(&payload).unwrap();
        assert_eq!(native.status, expected);
        if valid {
            assert_eq!(http.headers()["x-hopae-aal"], "0");
            assert_eq!(http.headers()["x-hopae-service-id"], "app");
            assert_eq!(http.headers()["x-hopae-principal-kind"], "service");
            assert!(
                http.headers()["x-forwarded-user"]
                    .to_str()
                    .unwrap()
                    .starts_with("s_")
            );
            assert!(http.headers().get("x-forwarded-email").is_none());
            assert!(
                native
                    .headers
                    .iter()
                    .any(|(name, value)| name == "x-hopae-aal" && value == b"0")
            );
        }
    }
    // Only absence of the API credential selects the explicitly enabled session fallback.
    let mut headers = context("/private");
    headers.push((
        "cookie".into(),
        format!("__Host-hopae={}", handle.expose()).into_bytes(),
    ));
    let (_, payload) = exchange(&mut socket, 3, &wire::encode_request(&headers).unwrap()).await;
    let human = wire::decode_reply(&payload).unwrap();
    assert_eq!(human.status, 200);
    assert!(
        human
            .headers
            .iter()
            .any(|(name, value)| name == "x-hopae-aal" && value == b"1")
    );
    tx.send(true).unwrap();
    task.await.unwrap().unwrap();
}
