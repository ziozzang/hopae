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
    let mut db = rusqlite::Connection::open_in_memory().unwrap();
    db.execute_batch("CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT NOT NULL) STRICT")
        .unwrap();
    let mut authority = hopae::auth_gateway::authority::Authority::load(
        &mut db,
        Some(config),
        &|_| Some(credential.into()),
        &|_| Ok(()),
    )
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
    .with_authentication_authority(authority.reader())
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
    let original = fx.snapshot.load_full();
    let mut changed = (*original).clone();
    changed.apps[0]
        .step_up
        .push(hopae::policy::types::StepUpRule {
            path_prefix: Some("/mfa".into()),
            aal: hopae::session::Aal::Two,
            max_age: None,
        });
    fx.snapshot.store(Arc::new(changed));
    for (id, path, expected) in [
        (20, "/mfa/x", 403),
        (21, "/MFA/x", 403),
        (22, "/%6dfa/x", 403),
        (23, "/private", 200),
    ] {
        let mut headers = context(path);
        headers.push((
            "authorization".into(),
            format!("Bearer {credential}").into_bytes(),
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
        let (_, payload) =
            exchange(&mut socket, id, &wire::encode_request(&headers).unwrap()).await;
        let native = wire::decode_reply(&payload).unwrap();
        assert_eq!(http.status().as_u16(), expected, "{path}");
        assert_eq!(native.status, expected, "{path}");
        if expected == 403 {
            assert!(http.headers().get("x-hopae-principal-kind").is_none());
            assert!(
                native
                    .headers
                    .iter()
                    .all(|(name, _)| name != "x-hopae-principal-kind")
            );
        }
    }
    let mut disabled = (*original).clone();
    disabled.apps[0].enabled = false;
    fx.snapshot.store(Arc::new(disabled));
    let mut disabled_headers = context("/private");
    disabled_headers.push((
        "authorization".into(),
        format!("Bearer {credential}").into_bytes(),
    ));
    let (_, payload) = exchange(
        &mut socket,
        24,
        &wire::encode_request(&disabled_headers).unwrap(),
    )
    .await;
    assert_eq!(wire::decode_reply(&payload).unwrap().status, 403);
    fx.snapshot.store(original);
    authority
        .publish(
            &mut db,
            1,
            None,
            "admin",
            &|_| Some(credential.into()),
            &|_| Ok(()),
        )
        .unwrap();
    headers.push((
        "authorization".into(),
        format!("Bearer {credential}").into_bytes(),
    ));
    let (_, payload) = exchange(&mut socket, 25, &wire::encode_request(&headers).unwrap()).await;
    assert_eq!(
        wire::decode_reply(&payload).unwrap().status,
        401,
        "removed credential fell back to an existing human session"
    );
    tx.send(true).unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn external_api_verifier_http_native_parity_and_outage_classification() {
    use axum::{Json, http::StatusCode, routing::post};
    let fx = Fx::new("m1-basic");
    let expires = fx.ctx.clock.now().0 as u64 + 1000;
    let verifier = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = verifier.local_addr().unwrap();
    let app=axum::Router::new().route("/verify",post(move |headers:axum::http::HeaderMap,Json(body):Json<serde_json::Value>|async move {
        assert_eq!(body["service_id"],"app");
        let credential=headers["authorization"].to_str().unwrap();
        if credential.contains("unavailable"){return (StatusCode::BAD_GATEWAY,Json(serde_json::json!({"active":false})));}
        if credential.contains("invalid"){return (StatusCode::UNAUTHORIZED,Json(serde_json::json!({"active":false})));}
        (StatusCode::OK,Json(serde_json::json!({"active":true,"subject":"partner-worker","service_id":"app","expires_at":expires})))
    }));
    let verifier_task = tokio::spawn(async move { axum::serve(verifier, app).await.unwrap() });
    let config:hopae::auth_gateway::runtime::Config=serde_json::from_value(serde_json::json!({"authority_id":"owned","profiles":[{"service_id":"app","host":"app.example.test","ports":[443],"realm":"partner","api_relay":{"url":format!("http://{address}/verify"),"issuer":"https://partner.example.test","timeout_ms":100,"allow_private_endpoints":true},"networks":["203.0.113.0/24"]}]})).unwrap();
    let runtime = hopae::auth_gateway::runtime::Runtime::compile(&config, &|_| None).unwrap();
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
    let native_task = tokio::spawn(native_gateway::serve(listener, router.clone(), keys, rx));
    let mut socket = TcpStream::connect(address).await.unwrap();
    assert_eq!(exchange(&mut socket, 0, b"native-test-key").await.1, [1]);
    for (id, token, status) in [
        (1, "valid-partner-token-at-least-sixteen", 200),
        (2, "invalid-partner-token-at-least-sixteen", 401),
        (3, "unavailable-partner-token-at-least-sixteen", 503),
    ] {
        let mut headers = context("/private");
        headers.push((
            "authorization".into(),
            format!("Bearer {token}").into_bytes(),
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
        let response = router.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status().as_u16(), status);
        let (_, payload) =
            exchange(&mut socket, id, &wire::encode_request(&headers).unwrap()).await;
        let response = wire::decode_reply(&payload).unwrap();
        assert_eq!(response.status, status);
        if status == 200 {
            assert!(
                response
                    .headers
                    .iter()
                    .any(|(name, value)| name == "x-hopae-principal-kind" && value == b"service")
            );
            assert!(
                response
                    .headers
                    .iter()
                    .any(|(name, value)| name == "x-hopae-service-id" && value == b"app")
            );
        }
    }
    tx.send(true).unwrap();
    native_task.await.unwrap().unwrap();
    verifier_task.abort();
}

#[tokio::test]
async fn direct_password_challenge_binds_once_without_oauth_fields() {
    use hopae::crypto::{Clock, random_token, sha256};
    use hopae::provider::{
        Provider, ProviderId,
        credentials::{CredentialError, CredentialKind, CredentialProvider, PasswordInput},
    };
    use hopae::session::service::{
        Deps, PasswordCompletion, ProviderLookup, RequestCtx, Service, ServiceConfig, SessionError,
    };
    use hopae::store::{
        Sessions,
        types::{NewTransaction, TxnPurpose},
    };
    struct Direct {
        id: ProviderId,
        calls: std::sync::atomic::AtomicUsize,
        store: hopae::store::Store,
        disable: std::sync::atomic::AtomicBool,
    }
    #[async_trait::async_trait]
    impl CredentialProvider for Direct {
        fn id(&self) -> &ProviderId {
            &self.id
        }
        fn kind(&self) -> CredentialKind {
            CredentialKind::Ldap
        }
        fn enabled(&self) -> bool {
            true
        }
        fn matches_configuration(&self, configuration: &serde_json::Value) -> bool {
            configuration == &serde_json::json!({})
        }
        async fn verify_password(
            &self,
            input: PasswordInput<'_>,
        ) -> Result<hopae::provider::ProviderIdentity, CredentialError> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if input.password().expose() != "owned-correct-value" {
                return Err(CredentialError::Invalid);
            }
            if self.disable.load(std::sync::atomic::Ordering::SeqCst) {
                self.store
                    .conn()
                    .execute(
                        "UPDATE providers SET enabled=0 WHERE provider_id='directory'",
                        [],
                    )
                    .unwrap();
            }
            Ok(hopae::provider::ProviderIdentity {
                subject: "t:entryuuid:owned-user".into(),
                email: None,
                email_verified: false,
                email_authoritative: false,
                name: None,
                username: None,
                picture: None,
                raw_claims: serde_json::json!({}),
                auth_time: None,
            })
        }
    }
    struct Lookup {
        provider: Arc<Direct>,
    }
    impl ProviderLookup for Lookup {
        fn get(&self, _: &ProviderId) -> Option<Arc<dyn Provider>> {
            None
        }
        fn enabled_sorted(&self) -> Vec<Arc<dyn Provider>> {
            vec![]
        }
        fn enabled_credentials(&self) -> Vec<Arc<dyn CredentialProvider>> {
            vec![self.provider.clone()]
        }
        fn credential(&self, id: &ProviderId) -> Option<Arc<dyn CredentialProvider>> {
            (id == &self.provider.id).then(|| self.provider.clone() as Arc<dyn CredentialProvider>)
        }
    }
    let fx = Fx::new("m1-basic");
    fx.store.conn().execute("INSERT INTO providers(provider_id,kind,display_name,enabled,managed_by,created_at,updated_at)VALUES('directory','ldap','Owned',1,'file',0,0)",[]).unwrap();
    let (bus, _receiver) = hopae::event::bus::channel(64);
    let emitter = hopae::event::bus::Emitter::new(
        fx.clock.clone(),
        fx.rng.clone(),
        bus,
        Arc::new(hopae::event::sampling::Sampler::default()),
        Arc::new(hopae::event::prune::PruneTrigger::new(1000)),
        false,
    );
    let direct = Arc::new(Direct {
        id: ProviderId::new("directory"),
        calls: std::sync::atomic::AtomicUsize::new(0),
        store: fx.store.clone(),
        disable: std::sync::atomic::AtomicBool::new(false),
    });
    let service = Service::new(Deps {
        directory: fx.ctx.directory.clone(),
        sessions: fx.ctx.sessions.clone(),
        events: fx.store.events(),
        emitter: emitter.clone(),
        clock: fx.clock.clone(),
        rng: fx.rng.clone(),
        snapshot: fx.snapshot.clone(),
        providers: Arc::new(Lookup {
            provider: direct.clone(),
        }),
        config: ServiceConfig::from_config(&fx.cfg).unwrap(),
    });
    let token = random_token(fx.rng.as_ref(), 16);
    let cookie = random_token(fx.rng.as_ref(), 16);
    let now = fx.clock.now();
    let ip = "192.0.2.10".parse().unwrap();
    let transaction = NewTransaction {
        txn_sha256: token.digest(),
        created_at: now,
        expires_at: now.add(Duration::from_secs(60)),
        app_id: hopae::policy::types::AppId::new("app"),
        return_target: "https://app.example.test/".parse().unwrap(),
        bind_sha256: Some(sha256(b"owned-app")),
        portal_bind_sha256: None,
        retry_bind_sha256: None,
        client_ip: ip,
        ua_sha256: None,
        provider_id: None,
        state_sha256: None,
        nonce: None,
        pkce_verifier: None,
        portal_session_id: None,
        purpose: TxnPurpose::Login,
        conflicting_handle_sha256: None,
        pending_identity: None,
        recovery_depth: 0,
        reauth_max_age: None,
    };
    fx.store
        .create_transaction(transaction.clone(), vec![])
        .await
        .unwrap();
    let ctx = RequestCtx {
        client_ip: ip,
        user_agent: None,
        request_id: "owned".into(),
        client_request_id: None,
    };
    let id = ProviderId::new("directory");
    let hopae::session::service::LoginEntry::Chooser { providers } = service
        .sso_or_chooser(&ctx, &token, None, Some(&cookie), false)
        .await
        .unwrap()
    else {
        panic!("direct provider was missing from chooser")
    };
    assert_eq!(providers.len(), 1);
    assert_eq!(providers[0].provider_id, id);
    assert_eq!(providers[0].display_name, "Owned");

    assert!(
        service
            .begin_password(&ctx, &token, &id, None)
            .await
            .is_err()
    );
    fx.store
        .conn()
        .execute(
            "UPDATE providers SET enabled=0 WHERE provider_id='directory'",
            [],
        )
        .unwrap();
    assert!(matches!(
        service
            .begin_password(&ctx, &token, &id, Some(&cookie))
            .await,
        Err(SessionError::Refused(_))
    ));
    assert!(
        fx.store
            .transaction(&token.digest())
            .await
            .unwrap()
            .unwrap()
            .state_sha256
            .is_none()
    );
    fx.store
        .conn()
        .execute(
            "UPDATE providers SET enabled=1 WHERE provider_id='directory'",
            [],
        )
        .unwrap();
    let challenge = service
        .begin_password(&ctx, &token, &id, Some(&cookie))
        .await
        .unwrap();
    let bound = fx
        .store
        .transaction_by_state(&challenge.digest())
        .await
        .unwrap()
        .unwrap();
    assert!(bound.nonce.is_none() && bound.pkce_verifier.is_none());
    assert_eq!(bound.portal_bind_sha256, Some(cookie.digest()));
    assert!(matches!(
        service
            .begin_password(&ctx, &token, &id, Some(&cookie))
            .await,
        Err(SessionError::AlreadyBound)
    ));
    assert_eq!(direct.calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    fx.store
        .conn()
        .execute(
            "UPDATE providers SET config='{\"changed\":true}' WHERE provider_id='directory'",
            [],
        )
        .unwrap();
    let blocked = Secret::new("owned-correct-value".into());
    assert!(
        service
            .complete_password(
                &ctx,
                PasswordCompletion {
                    provider_id: &id,
                    challenge: &challenge,
                    input: PasswordInput::new("worker", &blocked).unwrap(),
                    portal_cookie: Some(&cookie),
                    portal_handle: None
                }
            )
            .await
            .is_err()
    );
    assert_eq!(
        direct.calls.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "stale connector received a credential"
    );
    fx.store
        .conn()
        .execute(
            "UPDATE providers SET config='{}' WHERE provider_id='directory'",
            [],
        )
        .unwrap();
    let wrong = Secret::new("owned-wrong-value".into());
    assert!(
        service
            .complete_password(
                &ctx,
                PasswordCompletion {
                    provider_id: &id,
                    challenge: &challenge,
                    input: PasswordInput::new("worker", &wrong).unwrap(),
                    portal_cookie: Some(&cookie),
                    portal_handle: None
                }
            )
            .await
            .is_err()
    );
    assert!(
        fx.store
            .transaction(&token.digest())
            .await
            .unwrap()
            .unwrap()
            .consumed_at
            .is_none()
    );
    let password = Secret::new("owned-correct-value".into());
    let result = service
        .complete_password(
            &ctx,
            PasswordCompletion {
                provider_id: &id,
                challenge: &challenge,
                input: PasswordInput::new("worker", &password).unwrap(),
                portal_cookie: Some(&cookie),
                portal_handle: None,
            },
        )
        .await
        .unwrap();
    let hopae::session::service::CallbackOutcome::LoggedIn { session_id, .. } = result else {
        panic!("direct authentication did not issue a session")
    };
    let session = fx.store.session(&session_id).await.unwrap().unwrap();
    assert_eq!(
        session.auth_time_source,
        hopae::store::types::AuthTimeSource::HopaeCompletion
    );
    assert_eq!(session.provider_id, id);
    assert_eq!(session.aal, hopae::session::types::Aal::One);
    assert!(
        service
            .complete_password(
                &ctx,
                PasswordCompletion {
                    provider_id: &id,
                    challenge: &challenge,
                    input: PasswordInput::new("worker", &password).unwrap(),
                    portal_cookie: Some(&cookie),
                    portal_handle: None
                }
            )
            .await
            .is_err()
    );
    assert_eq!(
        direct.calls.load(std::sync::atomic::Ordering::SeqCst),
        2,
        "replayed challenge called the credential backend"
    );
    let misplaced_token = random_token(fx.rng.as_ref(), 16);
    fx.store
        .create_transaction(
            NewTransaction {
                txn_sha256: misplaced_token.digest(),
                ..transaction.clone()
            },
            vec![],
        )
        .await
        .unwrap();
    let misplaced_challenge = service
        .begin_password(&ctx, &misplaced_token, &id, Some(&cookie))
        .await
        .unwrap();
    let other_browser = random_token(fx.rng.as_ref(), 16);
    assert!(
        service
            .complete_password(
                &ctx,
                PasswordCompletion {
                    provider_id: &id,
                    challenge: &misplaced_challenge,
                    input: PasswordInput::new("worker", &password).unwrap(),
                    portal_cookie: Some(&other_browser),
                    portal_handle: None
                }
            )
            .await
            .is_err()
    );
    assert_eq!(
        direct.calls.load(std::sync::atomic::Ordering::SeqCst),
        2,
        "browser mismatch reached credential verification"
    );
    assert!(
        fx.store
            .transaction(&misplaced_token.digest())
            .await
            .unwrap()
            .unwrap()
            .consumed_at
            .is_some()
    );
    let adapter = hopae::portal::adapter::Adapter::new(
        service.clone(),
        Arc::new(hopae::provider::Registry::empty()),
        fx.ctx.directory.clone(),
        fx.store.events(),
        emitter,
        hopae::app::Readiness::default(),
    );
    use hopae::portal::ports::PortalServices;
    let portal_ctx = hopae::portal::ports::RequestCtx {
        client_ip: ip,
        user_agent: None,
        request_id: "owned-portal".into(),
        client_request_id: None,
        https: true,
    };
    let portal_cookies = hopae::portal::ports::Cookies {
        bind: Some(cookie.clone()),
        handle: None,
    };
    let submitted_token = random_token(fx.rng.as_ref(), 16);
    fx.store
        .create_transaction(
            NewTransaction {
                txn_sha256: submitted_token.digest(),
                ..transaction.clone()
            },
            vec![],
        )
        .await
        .unwrap();
    let prepared = adapter
        .prepare_password(&portal_ctx, &submitted_token, &id, &portal_cookies)
        .await
        .unwrap();
    assert_eq!(prepared.provider, id);
    assert_eq!(prepared.provider_name, "Owned");
    let submitted_challenge = prepared.challenge;
    let result = adapter
        .password(
            &portal_ctx,
            hopae::portal::ports::PasswordSubmission {
                provider: &id,
                challenge: &submitted_challenge,
                username: "worker",
                password: &password,
            },
            &portal_cookies,
        )
        .await;
    assert!(
        matches!(result, hopae::portal::ports::CallbackOutcome::Redirect(_)),
        "portal credential adapter did not return the handoff"
    );
    let next_token = random_token(fx.rng.as_ref(), 16);
    fx.store
        .create_transaction(
            NewTransaction {
                txn_sha256: next_token.digest(),
                ..transaction
            },
            vec![],
        )
        .await
        .unwrap();
    let next_challenge = service
        .begin_password(&ctx, &next_token, &id, Some(&cookie))
        .await
        .unwrap();
    direct
        .disable
        .store(true, std::sync::atomic::Ordering::SeqCst);
    assert!(
        service
            .complete_password(
                &ctx,
                PasswordCompletion {
                    provider_id: &id,
                    challenge: &next_challenge,
                    input: PasswordInput::new("worker", &password).unwrap(),
                    portal_cookie: Some(&cookie),
                    portal_handle: None
                }
            )
            .await
            .is_err()
    );
    let sessions: i64 = fx
        .store
        .conn()
        .query_row("SELECT count(*) FROM sessions", [], |row| row.get(0))
        .unwrap();
    assert_eq!(
        sessions, 2,
        "provider disable during verification created a session"
    );
}

#[test]
fn owned_oidc_portal_totp_enrollment_then_bound_stepup_rotates_credentials_and_handoff() {
    use crate::support::*;
    use hmac::{Hmac, Mac};
    let idp = MockIdp::start("default");
    let key = data_encoding::BASE64URL_NOPAD.encode(&[7; 32]);
    let h = Hopae::spawn(
        Fixture::with(
            "m1-basic",
            serde_json::json!({"totp_keyring":{"active_key":"v1","keys":[{"id":"v1","key_env":"OTP_KEY"}]},"apps":[{"app_id":"app","hosts":["app.example.test"],"ports":[443],"step_up":[{"path_prefix":"/admin","require":{"aal":2,"max_age":300}}]}]}),
        ),
        &idp,
        &[("OTP_KEY", &key)],
    );
    let client = h.portal().with_ip("192.0.2.10");
    let origin = format!("https://{}", h.portal_host());
    let post = |path: &str, fields: &[(&str, &str)]| {
        client.send(Req::post(path).header("origin", &origin).form(fields))
    };

    assert_eq!(client.get("/security/totp").status, 403);
    let first =
        h.verify(VerifyRequest::document("https://app.example.test/admin/x").ip("192.0.2.10"));
    assert_eq!(first.status, 302);
    let target = url::Url::parse(first.location().unwrap()).unwrap();
    let txn = target
        .query_pairs()
        .find(|(k, _)| k == "txn")
        .unwrap()
        .1
        .into_owned();
    let page = client.get(&format!("/login?txn={txn}"));
    fn field(body: &str, name: &str) -> String {
        body.split(&format!("name=\"{name}\" value=\""))
            .nth(1)
            .and_then(|s| s.split('"').next())
            .expect("protected field absent")
            .into()
    }
    let go = if page.status == 302 {
        page
    } else {
        post(
            "/login/mock",
            &[("csrf", &field(&page.body, "csrf")), ("txn", &txn)],
        )
    };
    assert_eq!(go.status, 302);
    let callback = idp.follow_authorization(go.location().unwrap());
    let initial_handoff = client.get(&callback);
    assert_eq!(initial_handoff.status, 302);
    let app_bind = first
        .set_cookies()
        .iter()
        .find_map(|c| {
            c.split_once('=')
                .filter(|(name, _)| *name != h.cookie_name())
                .map(|(name, value)| (name.to_owned(), value.split(';').next().unwrap().to_owned()))
        })
        .expect("app binding absent");
    let redeemed = h.verify(
        VerifyRequest::document(initial_handoff.location().unwrap())
            .ip("192.0.2.10")
            .cookie(&app_bind.0, &app_bind.1),
    );
    assert_eq!(redeemed.status, 302);
    let old_app = cookie_value(&redeemed, &h.cookie_name());

    let unenrolled = h.verify(
        VerifyRequest::document("https://app.example.test/admin/x")
            .ip("192.0.2.10")
            .cookie(&h.cookie_name(), &old_app)
            .cookie(&app_bind.0, &app_bind.1),
    );
    assert_eq!(unenrolled.status, 302);
    let url = url::Url::parse(unenrolled.location().unwrap()).unwrap();
    let welcome = client.get(&format!("{}?{}", url.path(), url.query().unwrap()));
    assert_eq!(welcome.status, 200);
    assert!(welcome.body.contains("href=\"/security/totp\""));
    assert!(!welcome.body.contains("id=\"stepup-code\""));
    let cookie = client
        .jar()
        .header_for(
            &h.portal_host(),
            "/security/totp",
            SendContext {
                secure_transport: true,
                site: Site::Same,
                safe_method: true,
            },
        )
        .unwrap();
    let plain = crate::support::client::send(
        h.portal,
        RawReq::new("GET", "/security/totp", &h.portal_host())
            .header("x-forwarded-proto", "http")
            .header("x-forwarded-for", "192.0.2.10")
            .header("cookie", &cookie),
    );
    assert_eq!(plain.status, 403);
    let visit = client.get("/security/totp");
    assert_eq!(visit.status, 200);
    let initial_csrf = field(&visit.body, "csrf");
    assert_eq!(
        client
            .post_form("/security/totp/prepare", &[("csrf", &initial_csrf)])
            .status,
        403
    );
    let prepared = post("/security/totp/prepare", &[("csrf", &initial_csrf)]);
    assert_eq!(prepared.status, 200);
    assert_eq!(prepared.header("cache-control"), Some("no-store"));
    assert_eq!(prepared.header("referrer-policy"), Some("same-origin"));
    let enrollment = field(&prepared.body, "enrollment");
    let confirm_csrf = field(&prepared.body, "csrf");
    let setup = prepared
        .body
        .split("id=\"totp-key\" type=\"text\" readonly value=\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .expect("setup material absent");
    let secret = data_encoding::BASE32_NOPAD
        .decode(setup.as_bytes())
        .unwrap();
    let counter = (h.hooks.now_ms() as u64) / 30000;
    let mut mac = Hmac::<sha1::Sha1>::new_from_slice(&secret).unwrap();
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = usize::from(digest[digest.len() - 1] & 15);
    let binary = u32::from_be_bytes(digest[offset..offset + 4].try_into().unwrap()) & 0x7fffffff;
    let code = format!("{:06}", binary % 1000000);
    assert_eq!(
        post(
            "/security/totp/confirm",
            &[
                ("csrf", &initial_csrf),
                ("enrollment", &enrollment),
                ("code", &code)
            ]
        )
        .status,
        403
    );
    let done = post(
        "/security/totp/confirm",
        &[
            ("csrf", &confirm_csrf),
            ("enrollment", &enrollment),
            ("code", &code),
        ],
    );
    assert_eq!(done.status, 200);
    assert!(!done.body.contains(setup));
    assert_eq!(
        post(
            "/security/totp/confirm",
            &[
                ("csrf", &confirm_csrf),
                ("enrollment", &enrollment),
                ("code", &code)
            ]
        )
        .status,
        403
    );
    let refresh = client.get("/security/totp");
    assert_eq!(refresh.status, 200);
    assert!(!refresh.body.contains(setup));
    assert!(!refresh.body.contains("action=\"/security/totp/prepare\""));
    assert!(!h.log().contains(setup));
    let db = rusqlite::Connection::open(h.state_dir.path().join("state/hopae.db")).unwrap();
    assert_eq!(
        db.query_row(
            "SELECT count(*) FROM totp_enrollments WHERE state='active'",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        1
    );
    assert_eq!(
        db.query_row("SELECT max(aal) FROM sessions", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        1
    );
    fn cookie_value(response: &Response, name: &str) -> String {
        response
            .set_cookies()
            .iter()
            .find_map(|c| {
                c.strip_prefix(&format!("{name}="))
                    .map(|s| s.split(';').next().unwrap().to_owned())
            })
            .expect("cookie absent")
    }
    h.advance(Duration::from_secs(30));
    let required = h.verify(
        VerifyRequest::document("https://app.example.test/admin/x")
            .ip("192.0.2.10")
            .cookie(&h.cookie_name(), &old_app)
            .cookie(&app_bind.0, &app_bind.1),
    );
    assert_eq!(required.status, 302);
    let location = url::Url::parse(required.location().unwrap()).unwrap();
    assert_eq!(location.path(), "/stepup");
    let challenge = location
        .query_pairs()
        .find(|(k, _)| k == "txn")
        .unwrap()
        .1
        .into_owned();
    assert_eq!(client.get(&format!("/login?txn={challenge}")).status, 400);
    let stepup = client.get(&format!("/stepup?txn={challenge}"));
    assert_eq!(stepup.status, 200);
    assert_eq!(stepup.header("cache-control"), Some("no-store"));
    assert_eq!(
        client
            .get(&format!("/stepup?txn={challenge}&txn={challenge}"))
            .status,
        400
    );
    assert_eq!(
        h.portal()
            .with_ip("192.0.2.10")
            .get(&format!("/stepup?txn={challenge}"))
            .status,
        403
    );
    let stepup_csrf = field(&stepup.body, "csrf");
    let counter = (h.hooks.now_ms() as u64) / 30000;
    let mut mac = Hmac::<sha1::Sha1>::new_from_slice(&secret).unwrap();
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = usize::from(digest[digest.len() - 1] & 15);
    let code = format!(
        "{:06}",
        (u32::from_be_bytes(digest[offset..offset + 4].try_into().unwrap()) & 0x7fffffff) % 1000000
    );
    assert_eq!(
        client
            .post_form(
                "/stepup",
                &[("csrf", &stepup_csrf), ("txn", &challenge), ("code", &code)]
            )
            .status,
        403
    );
    assert_eq!(
        post(
            "/stepup",
            &[
                ("csrf", &confirm_csrf),
                ("txn", &challenge),
                ("code", &code)
            ]
        )
        .status,
        403
    );
    let completed = post(
        "/stepup",
        &[("csrf", &stepup_csrf), ("txn", &challenge), ("code", &code)],
    );
    assert_eq!(completed.status, 302);
    let elevated_handoff = h.verify(
        VerifyRequest::document(completed.location().unwrap())
            .ip("192.0.2.10")
            .cookie(&app_bind.0, &app_bind.1)
            .cookie(&h.cookie_name(), &old_app),
    );
    assert_eq!(elevated_handoff.status, 302);
    let new_app = cookie_value(&elevated_handoff, &h.cookie_name());
    let allow = h.verify(
        VerifyRequest::document("https://app.example.test/admin/x")
            .ip("192.0.2.10")
            .cookie(&h.cookie_name(), &new_app),
    );
    assert_eq!(allow.status, 200);
    assert_eq!(allow.header("x-hopae-aal"), Some("2"));
    assert_ne!(new_app, old_app);
    let old = h.verify(
        VerifyRequest::other("https://app.example.test/admin/x")
            .ip("192.0.2.10")
            .cookie(&h.cookie_name(), &old_app),
    );
    assert_eq!(old.status, 401);
    assert_eq!(
        post(
            "/stepup",
            &[("csrf", &stepup_csrf), ("txn", &challenge), ("code", &code)]
        )
        .status,
        403
    );
    assert_eq!(
        db.query_row("SELECT max(aal) FROM sessions", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        2
    );
    assert!(!h.log().contains(setup));
}
