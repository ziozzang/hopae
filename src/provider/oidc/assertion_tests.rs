//! `private_key_jwt` against the HTTPS fixture: its token endpoint verifies
//! the assertion with an independent JWT implementation (jsonwebtoken) under
//! the published JWK, and refuses a reused `jti`.
use super::trust_tests::{TokenCheck, clock, copy, discovered, idp_with, path, pki, provider};
use super::*;
use crate::crypto::TestClock;
use crate::store::types::ManagedBy;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::process::Command;

fn genpkey(dir: &Path, name: &str, args: &[&str]) {
    let out = Command::new("openssl")
        .arg("genpkey")
        .args(args)
        .args(["-out", name])
        .current_dir(dir)
        .output()
        .expect("openssl");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn keys(dir: &Path) {
    genpkey(
        dir,
        "ec256.pem",
        &["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"],
    );
    genpkey(
        dir,
        "ec384.pem",
        &["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-384"],
    );
    genpkey(
        dir,
        "rsa.pem",
        &["-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"],
    );
    genpkey(dir, "ed.pem", &["-algorithm", "ED25519"]);
}

/// What the token endpoint saw.
#[derive(Default)]
struct Seen {
    jtis: HashSet<String>,
    algs: Vec<String>,
    lifetimes: Vec<i64>,
}

/// A token endpoint verifying the assertion under `jwk` (shared, replaceable)
/// for client `c` and audience `aud`.
fn verifier(
    jwk: Arc<Mutex<serde_json::Value>>,
    aud: Arc<Mutex<String>>,
    seen: Arc<Mutex<Seen>>,
) -> TokenCheck {
    Arc::new(move |form: &HashMap<String, String>| {
        let refuse = |why: &str| {
            (
                401,
                serde_json::json!({"error": "invalid_client", "why": why}),
            )
        };
        if form.get("client_assertion_type").map(String::as_str)
            != Some("urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
            || form.get("client_id").map(String::as_str) != Some("c")
            || form.contains_key("client_secret")
        {
            return refuse("form");
        }
        let Some(token) = form.get("client_assertion") else {
            return refuse("missing");
        };
        let header = match jsonwebtoken::decode_header(token) {
            Ok(h) => h,
            Err(_) => return refuse("header"),
        };
        let jwk: jsonwebtoken::jwk::Jwk =
            serde_json::from_value(jwk.lock().unwrap().clone()).unwrap();
        if header.kid.as_deref() != jwk.common.key_id.as_deref() {
            return refuse("kid");
        }
        let key = jsonwebtoken::DecodingKey::from_jwk(&jwk).unwrap();
        let mut v = jsonwebtoken::Validation::new(header.alg);
        v.set_audience(&[aud.lock().unwrap().clone()]);
        v.set_issuer(&["c"]);
        v.sub = Some("c".into());
        v.set_required_spec_claims(&["exp", "iat", "aud", "iss", "sub"]);
        let claims = match jsonwebtoken::decode::<serde_json::Value>(token, &key, &v) {
            Ok(d) => d.claims,
            Err(e) => return refuse(&format!("{e:?}")),
        };
        let mut seen = seen.lock().unwrap();
        let jti = claims["jti"].as_str().unwrap_or_default().to_string();
        if jti.len() < 20 || !seen.jtis.insert(jti) {
            return refuse("jti");
        }
        seen.algs.push(format!("{:?}", header.alg));
        seen.lifetimes
            .push(claims["exp"].as_i64().unwrap() - claims["iat"].as_i64().unwrap());
        (
            200,
            serde_json::json!({"access_token": "a", "token_type": "Bearer", "id_token": "x"}),
        )
    })
}

fn assertion_row(issuer: &str, assertion: serde_json::Value) -> ProviderRow {
    let mut r = super::trust_tests::row(issuer, serde_json::Value::Null, ManagedBy::File);
    let c = r.config.as_object_mut().unwrap();
    c.remove("tls");
    c.insert("client_assertion".into(), assertion);
    r
}

struct Stage {
    _dir: tempfile::TempDir,
    issuer: String,
    jwk: Arc<Mutex<serde_json::Value>>,
    aud: Arc<Mutex<String>>,
    seen: Arc<Mutex<Seen>>,
}

impl Stage {
    async fn new(extra: serde_json::Value) -> Stage {
        let dir = tempfile::tempdir().unwrap();
        pki(dir.path());
        keys(dir.path());
        let jwk = Arc::new(Mutex::new(serde_json::Value::Null));
        let aud = Arc::new(Mutex::new(String::new()));
        let seen = Arc::new(Mutex::new(Seen::default()));
        let issuer = idp_with(
            dir.path(),
            "ca1-ip.pem",
            "ca1-ip.key",
            None,
            extra,
            Some(verifier(jwk.clone(), aud.clone(), seen.clone())),
        )
        .await;
        Stage {
            _dir: dir,
            issuer,
            jwk,
            aud,
            seen,
        }
    }
    fn d(&self) -> &Path {
        self._dir.path()
    }
    /// A provider with `key` (a file in the stage) and extra assertion settings.
    fn provider(&self, key: &str, extra: serde_json::Value) -> (Arc<OidcProvider>, Arc<TestClock>) {
        let mut a = serde_json::json!({"key_file": path(self.d(), key), "key_id": "hopae-1"});
        for (k, v) in extra.as_object().unwrap() {
            a[k] = v.clone();
        }
        let mut r = assertion_row(&self.issuer, a);
        r.config["tls"] = serde_json::json!({"ca_file": path(self.d(), "ca1.pem")});
        let c = clock();
        (provider(&r, c.clone()), c)
    }
    async fn exchange(&self, p: &OidcProvider, c: &TestClock) -> Result<Value, ProviderError> {
        assert!(discovered(p, c).await);
        let disc = lock(&p.disc).valid(c.now()).unwrap();
        *self.aud.lock().unwrap() = disc.token_endpoint.to_string();
        p.exchange(
            &disc,
            "code",
            "verifier",
            &url::Url::parse("https://hopae.example.test/cb").unwrap(),
        )
        .await
    }
    fn publish(&self, p: &OidcProvider) {
        *self.jwk.lock().unwrap() = p.client_assertion_jwks().unwrap()["keys"][0].clone();
    }
}

#[tokio::test]
async fn every_key_type_signs_an_assertion_the_idp_verifies() {
    let st = Stage::new(
        serde_json::json!({"token_endpoint_auth_methods_supported": ["private_key_jwt"]}),
    )
    .await;
    for (key, alg) in [
        ("ec256.pem", "ES256"),
        ("ec384.pem", "ES384"),
        ("rsa.pem", "RS256"),
        ("ed.pem", "EdDSA"),
    ] {
        let (p, c) = st.provider(key, serde_json::json!({}));
        assert_eq!(p.disabled_reason(), None, "{key}");
        st.publish(&p);
        assert!(st.exchange(&p, &c).await.is_ok(), "{key}");
        // Two requests: two distinct jti values (the IdP refuses a reuse).
        assert!(st.exchange(&p, &c).await.is_ok(), "{key} second");
        let jwk = &p.client_assertion_jwks().unwrap()["keys"][0];
        assert_eq!(
            (
                jwk["kid"].as_str(),
                jwk["alg"].as_str(),
                jwk["use"].as_str()
            ),
            (Some("hopae-1"), Some(alg), Some("sig"))
        );
        assert!(jwk.get("d").is_none(), "no private parameter is published");
        let status = p.tls_status();
        assert_eq!(status["client_assertion"]["method"], "private_key_jwt");
        assert_eq!(status["client_assertion"]["key_id"], "hopae-1");
    }
    let seen = st.seen.lock().unwrap();
    assert_eq!(seen.jtis.len(), 8);
    assert!(
        seen.lifetimes
            .iter()
            .all(|l| *l == assertion::LIFETIME_SECS)
    );
    assert_eq!(
        seen.algs,
        [
            "ES256", "ES256", "ES384", "ES384", "RS256", "RS256", "EdDSA", "EdDSA"
        ]
    );
}

#[tokio::test]
async fn the_algorithm_is_the_allowlist_intersected_with_discovery() {
    let st = Stage::new(serde_json::json!({
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "private_key_jwt"],
        "token_endpoint_auth_signing_alg_values_supported": ["PS256", "ES256"],
    }))
    .await;
    let (p, c) = st.provider("rsa.pem", serde_json::json!({}));
    st.publish(&p);
    assert!(st.exchange(&p, &c).await.is_ok());
    assert_eq!(st.seen.lock().unwrap().algs.last().unwrap(), "PS256");
    // An allowlist with nothing in common with discovery: no request.
    let (p, c) = st.provider("rsa.pem", serde_json::json!({"algorithms": ["RS256"]}));
    assert!(matches!(
        st.exchange(&p, &c).await,
        Err(ProviderError::ProviderUnavailable)
    ));
    // An allowlist the key cannot sign: the provider is disabled.
    let (p, _) = st.provider("ec256.pem", serde_json::json!({"algorithms": ["RS256"]}));
    assert_eq!(p.disabled_reason(), Some("client_assertion_invalid"));
}

#[tokio::test]
async fn discovery_without_private_key_jwt_and_the_issuer_audience() {
    let st = Stage::new(
        serde_json::json!({"token_endpoint_auth_methods_supported": ["client_secret_basic"]}),
    )
    .await;
    let (p, c) = st.provider("ec256.pem", serde_json::json!({}));
    st.publish(&p);
    assert!(matches!(
        st.exchange(&p, &c).await,
        Err(ProviderError::ProviderUnavailable)
    ));

    let st = Stage::new(serde_json::json!({})).await;
    let (p, c) = st.provider("ec256.pem", serde_json::json!({"audience": "issuer"}));
    st.publish(&p);
    // The IdP expects the token endpoint: the issuer audience is refused...
    assert!(st.exchange(&p, &c).await.is_err());
    // ...and accepted when it expects the issuer.
    assert!(discovered(&p, &c).await);
    let disc = lock(&p.disc).valid(c.now()).unwrap();
    *st.aud.lock().unwrap() = st.issuer.clone();
    assert!(
        p.exchange(
            &disc,
            "code",
            "v",
            &url::Url::parse("https://hopae.example.test/cb").unwrap()
        )
        .await
        .is_ok()
    );
}

#[tokio::test]
async fn the_key_file_is_reloaded_and_invalid_keys_keep_the_previous_one() {
    let st = Stage::new(serde_json::json!({})).await;
    copy(st.d(), "ec256.pem", "client.pem");
    let (p, c) = st.provider("client.pem", serde_json::json!({}));
    st.publish(&p);
    assert!(st.exchange(&p, &c).await.is_ok());
    let before = p.tls_status()["client_assertion"]["key_fingerprint"].clone();

    // A new key (registered at the IdP first): reloaded, then used.
    copy(st.d(), "ed.pem", "client.pem");
    assert!(matches!(
        p.poll_assertion_now(),
        Some(crate::reload::Outcome::Reloaded(_))
    ));
    assert!(
        st.exchange(&p, &c).await.is_err(),
        "the IdP still holds the old public key"
    );
    st.publish(&p);
    // The CLI's JWK set is the same public key.
    let cfg = p.s.client_assertion.clone().unwrap();
    assert_eq!(
        assertion::jwks_of(&cfg).unwrap(),
        p.client_assertion_jwks().unwrap()
    );
    assert!(st.exchange(&p, &c).await.is_ok());
    assert_ne!(
        p.tls_status()["client_assertion"]["key_fingerprint"],
        before
    );
    assert_eq!(p.tls_status()["client_assertion"]["reloads"], 1);

    // A broken file: the previous key stays and the failure is visible.
    std::fs::write(st.d().join("client.pem"), b"garbage").unwrap();
    assert!(matches!(
        p.poll_assertion_now(),
        Some(crate::reload::Outcome::Invalid(_))
    ));
    assert_eq!(p.tls_status()["client_assertion"]["failing"], true);
    assert!(st.exchange(&p, &c).await.is_ok());
}

#[test]
fn configuration_is_checked_and_the_poll_interval_is_followed() {
    let ok = serde_json::json!({"key_file": "/k.pem", "key_id": "k"});
    assert!(
        assertion::AssertionCfg::of_config(&serde_json::json!({"client_assertion": ok}))
            .unwrap()
            .is_some()
    );
    for bad in [
        serde_json::json!({"key_file": "k.pem", "key_id": "k"}),
        serde_json::json!({"key_file": "/k.pem"}),
        serde_json::json!({"key_file": "/k.pem", "key_id": "k", "algorithms": ["HS256"]}),
        serde_json::json!({"key_file": "/k.pem", "key_id": "k", "audience": "other"}),
        serde_json::json!({"key_file": "/k.pem", "key_id": "k", "x": 1}),
    ] {
        assert!(
            assertion::AssertionCfg::of_config(&serde_json::json!({"client_assertion": bad}))
                .is_err(),
            "{bad}"
        );
    }
    // Not with a client secret, not from the admin API.
    let mut r = super::trust_tests::row(
        "https://idp.example.test",
        serde_json::Value::Null,
        ManagedBy::File,
    );
    r.config["client_assertion"] = ok.clone();
    assert!(
        OidcSettings::from_row(&r, &|_| None)
            .client_assertion
            .is_some()
    );
    r.client_secret_env = Some("S".into());
    assert_eq!(
        OidcSettings::from_row(&r, &|_| Some("s".into())).disabled_reason,
        Some("misconfigured")
    );
    r.client_secret_env = None;
    r.managed_by = ManagedBy::Api;
    assert_eq!(
        OidcSettings::from_row(&r, &|_| None).disabled_reason,
        Some("misconfigured")
    );

    // `reload.tls_interval_secs`: 0 turns polling off.
    let next = Mutex::new(std::time::Instant::now());
    assert!(!trust::due_every(&next, None));
    assert!(trust::due_every(&next, Some(Duration::from_secs(10))));
    assert!(
        !trust::due_every(&next, Some(Duration::from_secs(10))),
        "the next poll is 10 s away"
    );
}
