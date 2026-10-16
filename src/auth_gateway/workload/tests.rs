//! Offline workload verification against owned in-process fixtures
//! (scenario 500, `scenarios/500-kubernetes-workload-identity.md`).
use super::fixture::{self, AUDIENCE, Server, SigningKey};
use super::signals::{self, Signal};
use super::verify::{Connector, Profile};
use crate::auth_gateway::runtime::Error;
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}
fn now_s() -> i64 {
    (now_ms() / 1000) as i64
}

fn profile(server: &Server, extra: Value) -> Profile {
    let mut p = json!({
        "issuer": server.issuer(),
        "cluster_id": "example-cluster",
        "trust_domain": "cluster.example.test",
        "audience": AUDIENCE,
        "namespaces": ["blue"],
        "keys": {"source": "discovery", "ca_pem_env": "OWNED_CA", "kid_miss_min_interval_ms": 1000},
        "token_prefix": "k8s:"
    });
    if let (Some(base), Some(extra)) = (p.as_object_mut(), extra.as_object()) {
        for (k, v) in extra {
            if k == "keys" {
                for (kk, vv) in v.as_object().unwrap() {
                    base["keys"][kk] = vv.clone();
                }
            } else {
                base.insert(k.clone(), v.clone());
            }
        }
    }
    serde_json::from_value(p).unwrap()
}

fn compile(profile: &Profile, ca: &str) -> Arc<Connector> {
    let ca = ca.to_owned();
    Arc::new(
        profile
            .compile("orders", &move |name| {
                (name == "OWNED_CA" || name == "OWNED_WATCH_CA")
                    .then(|| ca.clone())
                    .or_else(|| {
                        (name == "OWNED_WATCH_TOKEN")
                            .then(|| "owned-watch-credential-0123456789".into())
                    })
            })
            .unwrap(),
    )
}

struct Fixture {
    pki: fixture::Pki,
    server: Server,
    rsa: SigningKey,
}

async fn fixture() -> Fixture {
    let pki = fixture::pki();
    let server = fixture::serve(&pki).await;
    let rsa = fixture::rsa_key("rsa-1");
    server.state.lock().unwrap().jwks = fixture::jwks(&[&rsa]);
    Fixture { pki, server, rsa }
}

fn token(f: &Fixture, edit: impl FnOnce(&mut Value)) -> String {
    let mut c = fixture::claims(
        &f.server.issuer(),
        now_s(),
        "worker-5d8f-abcde",
        "pod-uid-1",
    );
    edit(&mut c);
    fixture::mint(&f.rsa, &c)
}

/// S500-1, S500-2: offline verification, ServiceAccount principal stable
/// across a rollout, no API request on the hot path, positive cache.
#[tokio::test]
async fn s500_1_offline_verification_publishes_service_account_principal() {
    let f = fixture().await;
    let c = compile(&profile(&f.server, json!({})), &f.pki.ca_pem);
    let (sink, mut rx) = signals::channel();
    c.activate(Some(sink));
    let first = token(&f, |_| {});
    let e = c.authenticate(&first, now_ms()).await.unwrap();
    let w = e.workload().unwrap();
    assert_eq!(
        e.subject().kind,
        crate::auth_gateway::PrincipalKind::Workload
    );
    assert!(w.principal.starts_with("wk2:") && w.principal.len() == 68);
    assert_eq!(e.subject().subject, w.principal);
    assert_eq!(
        crate::auth_gateway::stable_subject(e.subject()),
        w.subject_ref
    );
    assert_eq!(
        w.spiffe_id.as_deref(),
        Some("spiffe://cluster.example.test/ns/blue/sa/worker")
    );
    assert_eq!(w.pod.as_ref().unwrap().name, "worker-5d8f-abcde");
    assert_eq!(w.node.as_deref(), Some("node-a"));
    assert_eq!(w.verification, "offline_jwks");
    assert!(e.expires_at_ms() <= now_ms() + 1000);
    assert_eq!(e.connector(), "kubernetes-workload");
    let fetched = f.server.count("/openid/v1/jwks") + f.server.count("/issuer/");
    assert_eq!(f.server.count("/openid/v1/jwks"), 1);

    // A rollout: another Pod of the same ServiceAccount, same principal.
    let rolled = token(&f, |c| {
        c["kubernetes.io"]["pod"] = json!({"name": "worker-7c9b-fghij", "uid": "pod-uid-2"});
    });
    let r = c.authenticate(&rolled, now_ms()).await.unwrap();
    assert_eq!(r.subject(), e.subject());
    assert_ne!(r.workload().unwrap().pod, w.pod.clone());
    // The Pod-bound legacy subjects differ (and are not the principal).
    assert_ne!(
        r.workload().unwrap().legacy_subject_ref,
        w.legacy_subject_ref
    );

    // Hot path: repeated authentications make no request at all.
    for _ in 0..50 {
        c.authenticate(&first, now_ms()).await.unwrap();
        c.authenticate(&rolled, now_ms()).await.unwrap();
    }
    assert_eq!(
        f.server.count("/openid/v1/jwks") + f.server.count("/issuer/"),
        fetched
    );
    assert_eq!(f.server.count("/api/"), 0);
    assert_eq!(c.status().cache_entries, 2);
    // One lifecycle observation per principal, not per Pod or request.
    assert!(matches!(rx.try_recv(), Ok(Signal::Observed(o)) if o.principal == w.principal));
    assert!(rx.try_recv().is_err());
}

/// S500-3: every claim rule refuses without contacting anything else.
#[tokio::test]
async fn s500_3_claims_signature_and_binding_rules_refuse() {
    let f = fixture().await;
    let c = compile(
        &profile(&f.server, json!({"service_accounts": ["blue/worker"]})),
        &f.pki.ca_pem,
    );
    let issuer = f.server.issuer();
    type Edit = Box<dyn Fn(&mut Value)>;
    let cases: Vec<(&str, Edit, Error)> = vec![
        (
            "wrong audience",
            Box::new(|c| c["aud"] = json!(["other"])),
            Error::Invalid,
        ),
        (
            "extra audience",
            Box::new(|c| c["aud"] = json!([AUDIENCE, "https://kubernetes.default.svc"])),
            Error::Invalid,
        ),
        (
            "api server audience",
            Box::new(|c| c["aud"] = json!(["https://kubernetes.default.svc"])),
            Error::Invalid,
        ),
        (
            "wrong issuer",
            Box::new(|c| c["iss"] = json!("https://other.example.test")),
            Error::Invalid,
        ),
        (
            "expired",
            Box::new(|c| {
                c["exp"] = json!(now_s() - 120);
                c["iat"] = json!(now_s() - 1000);
                c["nbf"] = json!(now_s() - 1000);
            }),
            Error::Expired,
        ),
        (
            "not yet valid",
            Box::new(|c| c["nbf"] = json!(now_s() + 300)),
            Error::Invalid,
        ),
        (
            "issued in future",
            Box::new(|c| c["iat"] = json!(now_s() + 300)),
            Error::Invalid,
        ),
        (
            "lifetime too long",
            Box::new(|c| c["exp"] = json!(now_s() + 30 * 86400)),
            Error::Invalid,
        ),
        (
            "legacy unbound",
            Box::new(|c| {
                c.as_object_mut().unwrap().remove("kubernetes.io");
                c["iss"] = json!("kubernetes/serviceaccount");
            }),
            Error::Invalid,
        ),
        (
            "unbound projected",
            Box::new(|c| {
                c["kubernetes.io"].as_object_mut().unwrap().remove("pod");
            }),
            Error::Invalid,
        ),
        (
            "secret bound when pod required",
            Box::new(|c| {
                c["kubernetes.io"].as_object_mut().unwrap().remove("pod");
                c["kubernetes.io"]["secret"] = json!({"name":"worker-token","uid":"sec-1"});
            }),
            Error::Invalid,
        ),
        (
            "sub mismatch",
            Box::new(|c| c["sub"] = json!("system:serviceaccount:blue:admin")),
            Error::Invalid,
        ),
        (
            "namespace not allowed",
            Box::new(|c| {
                c["kubernetes.io"]["namespace"] = json!("red");
                c["sub"] = json!("system:serviceaccount:red:worker");
            }),
            Error::Invalid,
        ),
        (
            "service account not allowed",
            Box::new(|c| {
                c["kubernetes.io"]["serviceaccount"]["name"] = json!("batch");
                c["sub"] = json!("system:serviceaccount:blue:batch");
            }),
            Error::Invalid,
        ),
        (
            "missing iat",
            Box::new(|c| {
                c.as_object_mut().unwrap().remove("iat");
            }),
            Error::Invalid,
        ),
    ];
    for (name, edit, expected) in cases {
        let mut claims = fixture::claims(&issuer, now_s(), "worker-pod", "pod-uid-1");
        edit(&mut claims);
        let t = fixture::mint(&f.rsa, &claims);
        assert_eq!(
            c.authenticate(&t, now_ms()).await.unwrap_err(),
            expected,
            "{name}"
        );
    }
    // Signature by a key the issuer never published (same kid).
    let mut forged = fixture::rsa_key("rsa-1");
    forged.kid = "rsa-1".into();
    let t = fixture::mint(
        &forged,
        &fixture::claims(&issuer, now_s(), "worker-pod", "pod-uid-1"),
    );
    assert_eq!(
        c.authenticate(&t, now_ms()).await.unwrap_err(),
        Error::Invalid
    );
    // Tampered payload, `none` and HMAC algorithms.
    let good = token(&f, |_| {});
    let mut parts: Vec<String> = good.split('.').map(str::to_owned).collect();
    let mut payload: Value = serde_json::from_slice(
        &base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &parts[1])
            .unwrap(),
    )
    .unwrap();
    payload["kubernetes.io"]["serviceaccount"]["uid"] = json!("sa-uid-9");
    parts[1] = base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        serde_json::to_vec(&payload).unwrap(),
    );
    assert_eq!(
        c.authenticate(&parts.join("."), now_ms())
            .await
            .unwrap_err(),
        Error::Invalid
    );
    for header in [
        json!({"alg":"none","kid":"rsa-1"}),
        json!({"alg":"HS256","kid":"rsa-1"}),
    ] {
        let h = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            header.to_string(),
        );
        let t = format!("{h}.{}.{}", parts[1], parts[2]);
        assert_eq!(
            c.authenticate(&t, now_ms()).await.unwrap_err(),
            Error::Invalid
        );
    }
    assert_eq!(f.server.count("/api/"), 0);
}

/// S500-4: key rotation is picked up on a `kid` miss; forged `kid` floods
/// are rate-limited; ECDSA keys work.
#[tokio::test]
async fn s500_4_rotation_kid_miss_refetch_is_rate_limited() {
    let f = fixture().await;
    let c = compile(&profile(&f.server, json!({})), &f.pki.ca_pem);
    c.authenticate(&token(&f, |_| {}), now_ms()).await.unwrap();
    assert_eq!(f.server.count("/openid/v1/jwks"), 1);
    // The issuer rotates to an ECDSA key (old key still published).
    let ec = fixture::ec_key("ec-2");
    f.server.state.lock().unwrap().jwks = fixture::jwks(&[&f.rsa, &ec]);
    let rotated = fixture::mint(
        &ec,
        &fixture::claims(&f.server.issuer(), now_s(), "worker-pod", "pod-uid-1"),
    );
    let e = c.authenticate(&rotated, now_ms()).await.unwrap();
    assert_eq!(e.workload().unwrap().service_account, "worker");
    assert_eq!(
        f.server.count("/openid/v1/jwks"),
        2,
        "one refetch for the new kid"
    );
    // Forged kids inside the interval do not reach the issuer.
    let mut forged = fixture::rsa_key("forged-1");
    for i in 0..20 {
        forged.kid = format!("forged-{i}");
        let t = fixture::mint(
            &forged,
            &fixture::claims(&f.server.issuer(), now_s(), "worker-pod", "pod-uid-1"),
        );
        assert_eq!(
            c.authenticate(&t, now_ms()).await.unwrap_err(),
            Error::Invalid
        );
    }
    assert_eq!(f.server.count("/openid/v1/jwks"), 2, "rate limited");
    tokio::time::sleep(Duration::from_millis(1100)).await;
    forged.kid = "forged-late".into();
    let t = fixture::mint(
        &forged,
        &fixture::claims(&f.server.issuer(), now_s(), "worker-pod", "pod-uid-1"),
    );
    assert_eq!(
        c.authenticate(&t, now_ms()).await.unwrap_err(),
        Error::Invalid
    );
    assert_eq!(
        f.server.count("/openid/v1/jwks"),
        3,
        "one refetch per interval"
    );
}

/// S500-5: pinned issuer and CA, allowed JWKS origins, last-known-good and
/// fail-closed beyond the staleness bound.
#[tokio::test]
async fn s500_5_pinned_issuer_ca_and_bounded_staleness() {
    let f = fixture().await;
    // Discovery naming another issuer is refused (keys unavailable → 503).
    f.server.state.lock().unwrap().issuer = "https://evil.example.test".into();
    let c = compile(&profile(&f.server, json!({})), &f.pki.ca_pem);
    assert_eq!(
        c.authenticate(&token(&f, |_| {}), now_ms())
            .await
            .unwrap_err(),
        Error::Unavailable
    );
    assert_eq!(f.server.count("/openid/v1/jwks"), 0);
    // A jwks_uri on an origin that is not allowed is refused.
    {
        let mut s = f.server.state.lock().unwrap();
        s.issuer = f.server.issuer();
        s.jwks_uri = Some("https://keys.example.test/openid/v1/jwks".into());
    }
    let c = compile(&profile(&f.server, json!({})), &f.pki.ca_pem);
    assert_eq!(
        c.authenticate(&token(&f, |_| {}), now_ms())
            .await
            .unwrap_err(),
        Error::Unavailable
    );
    f.server.state.lock().unwrap().jwks_uri = None;
    // Another CA: the TLS connection is refused.
    let other = fixture::pki();
    let c = compile(&profile(&f.server, json!({})), &other.ca_pem);
    assert_eq!(
        c.authenticate(&token(&f, |_| {}), now_ms())
            .await
            .unwrap_err(),
        Error::Unavailable
    );
    // Pinned jwks_url without discovery works.
    let c = compile(
        &profile(
            &f.server,
            json!({"keys": {"source": "jwks_url", "jwks_url": format!("{}/openid/v1/jwks", f.server.origin)}}),
        ),
        &f.pki.ca_pem,
    );
    c.authenticate(&token(&f, |_| {}), now_ms()).await.unwrap();

    // Last-known-good: a source outage keeps serving while younger than the bound.
    let source = super::keys::KeySource::new(
        &f.server.issuer(),
        "orders",
        super::keys::Source::Remote {
            client: super::http::client(f.pki.ca_pem.as_bytes()).unwrap(),
            discovery: None,
            jwks: Some(url::Url::parse(&format!("{}/openid/v1/jwks", f.server.origin)).unwrap()),
            jwks_origins: vec![],
            bearer: super::http::Bearer::None,
        },
        None,
        Duration::from_millis(100),
        Duration::from_millis(400),
        Duration::from_millis(1000),
        Duration::from_millis(1000),
    )
    .unwrap();
    assert!(source.keys().await.is_ok());
    f.server.state.lock().unwrap().down = true;
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(source.refresh_due());
    source.refresh().await;
    assert!(
        source.keys().await.is_ok(),
        "last good set within max_stale"
    );
    assert_eq!(source.status().consecutive_failures, 1);
    tokio::time::sleep(Duration::from_millis(1300)).await;
    assert!(source.keys().await.is_err(), "fail closed beyond max_stale");
    assert!(!source.status().fresh);
    f.server.state.lock().unwrap().down = false;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert!(source.keys().await.is_ok(), "recovers");
}

/// S500-6: watch-backed revocation: Pod deletion and ServiceAccount
/// re-creation refuse within the bound; a stale index fails closed.
#[tokio::test]
async fn s500_6_watch_revocation_with_bounded_staleness() {
    let f = fixture().await;
    {
        let mut s = f.server.state.lock().unwrap();
        s.service_accounts
            .insert("worker".into(), "sa-uid-1".into());
        s.pods
            .insert("worker-pod".into(), ("pod-uid-1".into(), false));
        s.resource_version = 10;
    }
    let p = profile(
        &f.server,
        json!({"revocation": {"mode": "watch", "api_origin": format!("{}/", f.server.origin), "token_env": "OWNED_WATCH_TOKEN", "max_staleness_seconds": 5}}),
    );
    let c = compile(&p, &f.pki.ca_pem);
    let (sink, mut rx) = signals::channel();
    c.activate(Some(sink));
    let t = fixture::mint(
        &f.rsa,
        &fixture::claims(&f.server.issuer(), now_s(), "worker-pod", "pod-uid-1"),
    );
    // Until the first LIST completes, the connector fails closed.
    let mut ok = false;
    for _ in 0..100 {
        match c.authenticate(&t, now_ms()).await {
            Ok(_) => {
                ok = true;
                break;
            }
            Err(Error::Unavailable) => tokio::time::sleep(Duration::from_millis(50)).await,
            Err(e) => panic!("{e:?}"),
        }
    }
    assert!(ok, "index became ready");
    let api_before = f.server.count("/api/");
    for _ in 0..20 {
        c.authenticate(&t, now_ms()).await.unwrap();
    }
    assert_eq!(
        f.server.count("/api/"),
        api_before,
        "no API request per authentication"
    );
    // Wait for both watches to be established, then delete the Pod.
    for _ in 0..100 {
        if f.server.count("/api/v1/namespaces/blue/pods?watch") > 0
            && f.server
                .count("/api/v1/namespaces/blue/serviceaccounts?watch")
                > 0
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    let started = std::time::Instant::now();
    f.server.state.lock().unwrap().pods.remove("worker-pod");
    f.server
        .emit("pods", "DELETED", "worker-pod", "pod-uid-1", false);
    let mut refused = false;
    while started.elapsed() < Duration::from_secs(2) {
        if matches!(c.authenticate(&t, now_ms()).await, Err(Error::Invalid)) {
            refused = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(refused, "pod deletion revoked within 2 s (cache included)");
    // ServiceAccount re-created with a new UID: retired signal and refusal.
    f.server
        .state
        .lock()
        .unwrap()
        .service_accounts
        .insert("worker".into(), "sa-uid-2".into());
    f.server
        .emit("serviceaccounts", "ADDED", "worker", "sa-uid-2", false);
    let mut retired = None;
    for _ in 0..100 {
        while let Ok(signal) = rx.try_recv() {
            if let Signal::Retired {
                workload,
                cause,
                replacement,
            } = signal
            {
                retired = Some((workload, cause, replacement));
            }
        }
        if retired.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let (workload, cause, replacement) = retired.expect("retired signal");
    assert_eq!(cause, "uid_changed");
    assert_eq!(workload.service_account_uid, "sa-uid-1");
    assert!(replacement.unwrap().starts_with("wk2:"));
    let other_pod = fixture::mint(
        &f.rsa,
        &fixture::claims(&f.server.issuer(), now_s(), "worker-pod-2", "pod-uid-2"),
    );
    assert_eq!(
        c.authenticate(&other_pod, now_ms()).await.unwrap_err(),
        Error::Invalid
    );
    let status = c.status();
    let revocation = status.revocation.unwrap();
    assert!(revocation.ready && revocation.objects >= 1);
    // API server outage: the index ages past the bound and fails closed.
    f.server.state.lock().unwrap().down = true;

    let deadline = std::time::Instant::now() + Duration::from_secs(9);
    let mut stale = false;
    let fresh_sa = {
        let mut cl = fixture::claims(&f.server.issuer(), now_s(), "worker-pod-3", "pod-uid-3");
        cl["kubernetes.io"]["serviceaccount"]["uid"] = json!("sa-uid-2");
        fixture::mint(&f.rsa, &cl)
    };
    while std::time::Instant::now() < deadline {
        if c.authenticate(&fresh_sa, now_ms()).await.unwrap_err() == Error::Unavailable {
            stale = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(stale, "stale revocation index fails closed");
}

/// S500-7: migration — legacy Pod subject only inside an expiring window,
/// mapping signals for Pumgye reconciliation.
#[tokio::test]
async fn s500_7_legacy_pod_subject_window_and_mapping_signals() {
    let f = fixture().await;
    let until = now_ms() + 60_000;
    let c = compile(
        &profile(
            &f.server,
            json!({"subject": "legacy_pod", "legacy_until_ms": until, "legacy_mapping_until_ms": until}),
        ),
        &f.pki.ca_pem,
    );
    let (sink, mut rx) = signals::channel();
    c.activate(Some(sink));
    let t = token(&f, |_| {});
    let e = c.authenticate(&t, now_ms()).await.unwrap();
    let w = e.workload().unwrap();
    assert!(
        e.subject().subject.starts_with("w_"),
        "legacy Pod-bound subject"
    );
    assert_eq!(
        crate::auth_gateway::stable_subject(e.subject()),
        w.legacy_subject_ref.clone().unwrap()
    );
    assert_ne!(w.subject_ref, w.legacy_subject_ref.clone().unwrap());
    let mut mapped = false;
    while let Ok(s) = rx.try_recv() {
        if let Signal::LegacyMapped {
            workload,
            legacy_subject_ref,
        } = s
        {
            assert_eq!(workload.principal, w.principal);
            assert_eq!(Some(legacy_subject_ref), w.legacy_subject_ref);
            mapped = true;
        }
    }
    assert!(mapped);
    // After the window the connector refuses (fails closed, never silently switches).
    assert_eq!(
        c.authenticate(&t, until + 1).await.unwrap_err(),
        Error::Unavailable
    );
    // Service-account mode with a mapping window still reports mappings.
    let c = compile(
        &profile(&f.server, json!({"legacy_mapping_until_ms": until})),
        &f.pki.ca_pem,
    );
    let (sink, mut rx) = signals::channel();
    c.activate(Some(sink));
    let e = c.authenticate(&t, now_ms()).await.unwrap();
    assert!(e.subject().subject.starts_with("wk2:"));
    let kinds: Vec<_> = std::iter::from_fn(|| rx.try_recv().ok())
        .map(|s| s.kind())
        .collect();
    assert_eq!(kinds, vec!["observed", "legacy_mapped"]);
}

#[test]
fn s500_a1_configuration_refuses_unsafe_profiles() {
    let base = json!({
        "issuer": "https://issuer.example.test/cluster",
        "cluster_id": "example-cluster",
        "trust_domain": "cluster.example.test",
        "audience": AUDIENCE,
        "namespaces": ["blue"],
        "keys": {"source": "discovery", "ca_pem_env": "OWNED_CA"},
        "token_prefix": "k8s:"
    });
    let ok: Profile = serde_json::from_value(base.clone()).unwrap();
    ok.validate().unwrap();
    let mut bad = Vec::new();
    for (path, value) in [
        ("audience", json!("https://issuer.example.test/cluster")),
        ("audience", json!("https://kubernetes.default.svc")),
        ("issuer", json!("http://issuer.example.test")),
        ("trust_domain", json!("Cluster.Example")),
        ("namespaces", json!([])),
        ("namespaces", json!(["blue", "blue"])),
        ("service_accounts", json!(["red/worker"])),
        ("max_token_lifetime_seconds", json!(60)),
        ("clock_skew_seconds", json!(3600)),
        ("subject", json!("legacy_pod")),
        ("token_prefix", json!("k8s")),
        ("cache", json!({"ttl_ms": 600000})),
        (
            "revocation",
            json!({"mode": "poll", "api_origin": "https://k.example.test/", "token_env": "T"}),
        ),
        (
            "revocation",
            json!({"mode": "watch", "api_origin": "https://k.example.test/", "token_env": "T", "resources": ["pods"]}),
        ),
        (
            "revocation",
            json!({"mode": "watch", "api_origin": "https://k.example.test/"}),
        ),
        ("keys", json!({"source": "static"})),
        ("keys", json!({"source": "discovery"})),
        (
            "keys",
            json!({"source": "discovery", "ca_pem_env": "OWNED_CA", "kid_miss_min_interval_ms": 10}),
        ),
        (
            "keys",
            json!({"source": "discovery", "ca_pem_env": "OWNED_CA", "token_file": "relative/token"}),
        ),
    ] {
        let mut v = base.clone();
        v[path] = value;
        match serde_json::from_value::<Profile>(v) {
            Ok(p) if p.validate().is_ok() => bad.push(path),
            _ => {}
        }
    }
    assert!(bad.is_empty(), "accepted: {bad:?}");
    let mut unknown = base.clone();
    unknown["ca_pem"] = json!("-----BEGIN CERTIFICATE-----");
    assert!(
        serde_json::from_value::<Profile>(unknown).is_err(),
        "inline material refused"
    );
}

/// Static JWKS (no network at all) for out-of-cluster deployments.
#[tokio::test]
async fn s500_8_static_jwks_needs_no_network() {
    let key = fixture::ec_key("static-1");
    let jwks = fixture::jwks(&[&key]);
    let p: Profile = serde_json::from_value(json!({
        "issuer": "https://kubernetes.default.svc.cluster.local",
        "cluster_id": "example-cluster",
        "trust_domain": "cluster.example.test",
        "audience": AUDIENCE,
        "namespaces": ["blue"],
        "keys": {"source": "static", "jwks_env": "OWNED_JWKS"},
        "token_prefix": "k8s:"
    }))
    .unwrap();
    let c = Arc::new(
        p.compile("orders", &|name| {
            (name == "OWNED_JWKS").then(|| jwks.clone())
        })
        .unwrap(),
    );
    let t = fixture::mint(
        &key,
        &fixture::claims(
            "https://kubernetes.default.svc.cluster.local",
            now_s(),
            "worker-pod",
            "pod-uid-1",
        ),
    );
    let e = c.authenticate(&t, now_ms()).await.unwrap();
    assert_eq!(
        e.workload().unwrap().spiffe_id.as_deref(),
        Some("spiffe://cluster.example.test/ns/blue/sa/worker")
    );
    assert!(c.status().keys.fresh);
}

fn runtime_config(
    jwks: &str,
) -> (
    crate::auth_gateway::runtime::Config,
    impl Fn(&str) -> Option<String> + use<>,
) {
    let config: crate::auth_gateway::runtime::Config = serde_json::from_value(json!({
        "authority_id": "owned",
        "profiles": [{
            "service_id": "orders", "host": "orders.example.test", "ports": [443],
            "realm": "example-cluster", "networks": ["192.0.2.0/24"],
            "api_keys": [{"token_env": "OWNED_LOCAL_KEY", "subject": "batch"}],
            "kubernetes_workload": {
                "issuer": "https://kubernetes.default.svc.cluster.local",
                "cluster_id": "example-cluster",
                "trust_domain": "cluster.example.test",
                "audience": AUDIENCE,
                "namespaces": ["blue"],
                "keys": {"source": "static", "jwks_env": "OWNED_JWKS"},
                "token_prefix": "k8s:"
            }
        }]
    }))
    .unwrap();
    let jwks = jwks.to_owned();
    (config, move |name: &str| match name {
        "OWNED_JWKS" => Some(jwks.clone()),
        "OWNED_LOCAL_KEY" => Some("owned-local-service-key-of-sufficient-length".into()),
        _ => None,
    })
}

/// S500-10: profile routing, network gate, status and explain through the
/// compiled runtime.
#[tokio::test]
async fn s500_10_runtime_routing_status_and_explain() {
    use crate::auth_gateway::runtime::{Runtime, WorkloadVerdict};
    let key = fixture::ec_key("static-1");
    let jwks = fixture::jwks(&[&key]);
    let (config, env) = runtime_config(&jwks);
    let runtime = Runtime::compile(&config, &env).unwrap();
    runtime.activate(None);
    let t = fixture::mint(
        &key,
        &fixture::claims(
            "https://kubernetes.default.svc.cluster.local",
            now_s(),
            "worker-pod",
            "pod-uid-1",
        ),
    );
    let inside: std::net::IpAddr = "192.0.2.7".parse().unwrap();
    let outside: std::net::IpAddr = "198.51.100.7".parse().unwrap();
    let e = runtime
        .authenticate_async(
            "orders.example.test",
            443,
            Some(&format!("k8s:{t}")),
            inside,
            now_ms(),
        )
        .await
        .unwrap();
    assert!(e.subject().subject.starts_with("wk2:"));
    assert_eq!(e.service(), Some("orders"));
    assert_eq!(
        runtime
            .authenticate_async(
                "orders.example.test",
                443,
                Some(&format!("k8s:{t}")),
                outside,
                now_ms()
            )
            .await
            .unwrap_err(),
        Error::NetworkDenied
    );
    // Unprefixed credentials never reach the workload verifier.
    assert_eq!(
        runtime
            .authenticate_async("orders.example.test", 443, Some(&t), inside, now_ms())
            .await
            .unwrap_err(),
        Error::Invalid
    );
    let local = runtime
        .authenticate_async(
            "orders.example.test",
            443,
            Some("owned-local-service-key-of-sufficient-length"),
            inside,
            now_ms(),
        )
        .await
        .unwrap();
    assert_eq!(
        local.subject().kind,
        crate::auth_gateway::PrincipalKind::Service
    );
    let status = runtime.connector_status();
    let row = status
        .iter()
        .find(|r| r.connector == "kubernetes-workload")
        .unwrap();
    assert_eq!(row.circuit, "closed");
    assert!(row.workload.as_ref().unwrap().keys.fresh);
    let json = serde_json::to_string(&status).unwrap();
    assert!(
        !json.contains("\"x\"") && !json.contains("OWNED_"),
        "no key material or references"
    );

    let explain = |subject: &str, ip: Option<std::net::IpAddr>| {
        runtime.admin_explain_workload("orders.example.test", 443, subject, ip, now_ms())
    };
    match explain(
        "spiffe://cluster.example.test/ns/blue/sa/worker",
        Some(inside),
    ) {
        WorkloadVerdict::Allowed {
            verification,
            network_evaluated,
            revocation_evaluated,
            spiffe_id,
            principal,
            ..
        } => {
            assert_eq!(verification, "offline_jwks");
            assert!(network_evaluated && !revocation_evaluated);
            assert_eq!(
                spiffe_id.as_deref(),
                Some("spiffe://cluster.example.test/ns/blue/sa/worker")
            );
            assert_eq!(principal, None, "UID unknown without a revocation index");
        }
        other => panic!("{other:?}"),
    }
    assert!(matches!(
        explain("system:serviceaccount:blue:worker", None),
        WorkloadVerdict::Allowed {
            network_evaluated: false,
            ..
        }
    ));
    assert_eq!(
        explain("spiffe://cluster.example.test/ns/red/sa/worker", None),
        WorkloadVerdict::NamespaceNotAllowed
    );
    assert_eq!(
        explain("spiffe://other.example.test/ns/blue/sa/worker", None),
        WorkloadVerdict::SubjectInvalid
    );
    assert_eq!(
        explain(
            "spiffe://cluster.example.test/ns/blue/sa/worker",
            Some(outside)
        ),
        WorkloadVerdict::NetworkDenied
    );
    assert_eq!(
        runtime.admin_explain_workload(
            "other.example.test",
            443,
            "system:serviceaccount:blue:worker",
            None,
            now_ms()
        ),
        WorkloadVerdict::NoProfile
    );
    // Republication with identical material keeps the connector (cache, keys, tasks).
    let resumed = Runtime::compile_resuming(&config, &env, Some(&runtime)).unwrap();
    let again = resumed
        .authenticate_async(
            "orders.example.test",
            443,
            Some(&format!("k8s:{t}")),
            inside,
            now_ms(),
        )
        .await
        .unwrap();
    assert_eq!(again.subject(), e.subject());
    // A profile cannot combine the offline connector with the deprecated one.
    let mut both = serde_json::to_value(&config).unwrap();
    both["profiles"][0]["kubernetes_tokenreview"] = json!({"connection":{"api_origin":"https://kubernetes.example.test/","issuer":"https://kubernetes.default.svc.cluster.local","cluster_id":"example-cluster","audience":"orders-workload","namespaces":["blue"],"timeout_ms":500},"ca_pem_env":"OWNED_CA","reviewer_token_env":"OWNED_REVIEWER","token_prefix":"tr:"});
    let both: crate::auth_gateway::runtime::Config = serde_json::from_value(both).unwrap();
    assert!(both.validate().is_err());
}
