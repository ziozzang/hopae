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
    let (_, payload) = exchange(&mut socket, 4, &wire::encode_request(&headers).unwrap()).await;
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
        Deps, ProviderLookup, RequestCtx, Service, ServiceConfig, SessionError,
    };
    use hopae::store::{
        Sessions,
        types::{NewTransaction, TxnPurpose},
    };
    struct Direct {
        id: ProviderId,
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
        async fn verify_password(
            &self,
            _: PasswordInput<'_>,
        ) -> Result<hopae::provider::ProviderIdentity, CredentialError> {
            panic!("challenge preparation must not authenticate")
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
    let service = Service::new(Deps {
        directory: fx.ctx.directory.clone(),
        sessions: fx.ctx.sessions.clone(),
        events: fx.store.events(),
        emitter,
        clock: fx.clock.clone(),
        rng: fx.rng.clone(),
        snapshot: fx.snapshot.clone(),
        providers: Arc::new(Lookup {
            provider: Arc::new(Direct {
                id: ProviderId::new("directory"),
            }),
        }),
        config: ServiceConfig::from_config(&fx.cfg).unwrap(),
    });
    let token = random_token(fx.rng.as_ref(), 16);
    let cookie = random_token(fx.rng.as_ref(), 16);
    let now = fx.clock.now();
    let ip = "192.0.2.10".parse().unwrap();
    fx.store
        .create_transaction(
            NewTransaction {
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
            },
            vec![],
        )
        .await
        .unwrap();
    let ctx = RequestCtx {
        client_ip: ip,
        user_agent: None,
        request_id: "owned".into(),
        client_request_id: None,
    };
    let id = ProviderId::new("directory");
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
}
