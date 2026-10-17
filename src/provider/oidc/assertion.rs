//! `private_key_jwt` client authentication at the token endpoint (RFC 7523,
//! OpenID Connect Core 9): a short-lived JWT signed with the provider's own
//! key (`providers[].client_assertion`) instead of a client secret.
//!
//! - Keys: PEM, RSA (PKCS#1 or PKCS#8, at least 2048 bits), EC P-256 or
//!   P-384 (PKCS#8), Ed25519 (PKCS#8).
//! - Algorithm: the configured allowlist (default: what the key can do),
//!   intersected with discovery's
//!   `token_endpoint_auth_signing_alg_values_supported` when present.
//! - Claims: `iss` = `sub` = client id, `aud` = the token endpoint (or the
//!   issuer, per configuration), `iat`, `exp` = `iat` + 60 s, a random `jti`
//!   (128 bits) per request; header `kid` = `key_id`.
//! - The key file is re-read like the TLS material (content digest, invalid
//!   material keeps the previous key).
//! - `hopae providers jwk <id>` prints the public key as a JWK set for
//!   registration at the identity provider.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use arc_swap::ArcSwap;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{self, KeyPair};
use serde_json::{Value, json};

use crate::reload::{Outcome, note_metrics};

/// Lifetime of one assertion.
pub const LIFETIME_SECS: i64 = 60;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Alg {
    RS256,
    PS256,
    ES256,
    ES384,
    EdDSA,
}

impl Alg {
    pub fn as_str(self) -> &'static str {
        match self {
            Alg::RS256 => "RS256",
            Alg::PS256 => "PS256",
            Alg::ES256 => "ES256",
            Alg::ES384 => "ES384",
            Alg::EdDSA => "EdDSA",
        }
    }
    pub fn parse(s: &str) -> Option<Alg> {
        [Alg::RS256, Alg::PS256, Alg::ES256, Alg::ES384, Alg::EdDSA]
            .into_iter()
            .find(|a| a.as_str() == s)
    }
}

/// `aud` of the assertion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Audience {
    TokenEndpoint,
    Issuer,
}

/// `providers[].client_assertion` as stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssertionCfg {
    pub key_file: PathBuf,
    pub key_id: String,
    pub algorithms: Option<Vec<Alg>>,
    pub audience: Audience,
}

impl AssertionCfg {
    pub fn of_config(cfg: &Value) -> Result<Option<AssertionCfg>, &'static str> {
        let c = match cfg.get("client_assertion") {
            None | Some(Value::Null) => return Ok(None),
            Some(c @ Value::Object(_)) => c,
            Some(_) => return Err("client_assertion must be an object"),
        };
        if c.as_object().unwrap().keys().any(|k| {
            !matches!(
                k.as_str(),
                "key_file" | "key_id" | "algorithms" | "audience"
            )
        }) {
            return Err("unknown client_assertion key");
        }
        let key_file = c
            .get("key_file")
            .and_then(Value::as_str)
            .filter(|p| Path::new(p).is_absolute() && p.len() <= 4096)
            .ok_or("client_assertion.key_file must be an absolute path")?;
        let key_id = c
            .get("key_id")
            .and_then(Value::as_str)
            .filter(|k| !k.is_empty() && k.len() <= 128 && k.bytes().all(|b| b.is_ascii_graphic()))
            .ok_or("client_assertion.key_id must be 1 to 128 printable characters")?;
        let algorithms = match c.get("algorithms") {
            None | Some(Value::Null) => None,
            Some(Value::Array(a)) if !a.is_empty() && a.len() <= 5 => Some(
                a.iter()
                    .map(|v| v.as_str().and_then(Alg::parse))
                    .collect::<Option<Vec<_>>>()
                    .ok_or("client_assertion.algorithms: RS256, PS256, ES256, ES384 or EdDSA")?,
            ),
            Some(_) => return Err("client_assertion.algorithms must be a non-empty list"),
        };
        let audience = match c.get("audience").and_then(Value::as_str) {
            None | Some("token_endpoint") => Audience::TokenEndpoint,
            Some("issuer") => Audience::Issuer,
            Some(_) => return Err("client_assertion.audience must be token_endpoint or issuer"),
        };
        Ok(Some(AssertionCfg {
            key_file: PathBuf::from(key_file),
            key_id: key_id.to_string(),
            algorithms,
            audience,
        }))
    }
}

enum Kind {
    Rsa(signature::RsaKeyPair),
    Ec(signature::EcdsaKeyPair, Alg),
    Ed(signature::Ed25519KeyPair),
}

/// A parsed signing key.
pub struct Key {
    kind: Kind,
    fingerprint: String,
}

impl Key {
    /// Parse a PEM private key.
    pub fn parse(pem: &[u8]) -> anyhow::Result<Key> {
        use rustls::pki_types::PrivateKeyDer;
        let der = rustls_pemfile::private_key(&mut &pem[..])?
            .ok_or_else(|| anyhow::anyhow!("no private key in the key file"))?;
        let rng = SystemRandom::new();
        let kind = match &der {
            PrivateKeyDer::Pkcs1(k) => Kind::Rsa(
                signature::RsaKeyPair::from_der(k.secret_pkcs1_der())
                    .map_err(|e| anyhow::anyhow!("unusable RSA key: {e}"))?,
            ),
            PrivateKeyDer::Pkcs8(k) => {
                let b = k.secret_pkcs8_der();
                if let Ok(r) = signature::RsaKeyPair::from_pkcs8(b) {
                    Kind::Rsa(r)
                } else if let Ok(e) = signature::EcdsaKeyPair::from_pkcs8(
                    &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
                    b,
                    &rng,
                ) {
                    Kind::Ec(e, Alg::ES256)
                } else if let Ok(e) = signature::EcdsaKeyPair::from_pkcs8(
                    &signature::ECDSA_P384_SHA384_FIXED_SIGNING,
                    b,
                    &rng,
                ) {
                    Kind::Ec(e, Alg::ES384)
                } else if let Ok(e) = signature::Ed25519KeyPair::from_pkcs8_maybe_unchecked(b) {
                    Kind::Ed(e)
                } else {
                    anyhow::bail!(
                        "the key is not RSA (2048 bits or more), EC P-256/P-384 or Ed25519"
                    );
                }
            }
            _ => anyhow::bail!("EC keys must be PKCS#8 (BEGIN PRIVATE KEY)"),
        };
        let mut key = Key {
            kind,
            fingerprint: String::new(),
        };
        key.fingerprint = format!(
            "sha256:{}",
            data_encoding::HEXLOWER.encode(
                &crate::crypto::sha256(
                    serde_json::to_string(&key.public_jwk("", None))
                        .unwrap_or_default()
                        .as_bytes()
                )
                .0
            )
        );
        Ok(key)
    }

    /// The algorithms the key can sign with.
    pub fn algs(&self) -> Vec<Alg> {
        match &self.kind {
            Kind::Rsa(_) => vec![Alg::RS256, Alg::PS256],
            Kind::Ec(_, a) => vec![*a],
            Kind::Ed(_) => vec![Alg::EdDSA],
        }
    }

    fn sign(&self, alg: Alg, msg: &[u8]) -> anyhow::Result<Vec<u8>> {
        let rng = SystemRandom::new();
        Ok(match (&self.kind, alg) {
            (Kind::Rsa(k), Alg::RS256 | Alg::PS256) => {
                let mut sig = vec![0; k.public().modulus_len()];
                let pad: &dyn signature::RsaEncoding = if alg == Alg::RS256 {
                    &signature::RSA_PKCS1_SHA256
                } else {
                    &signature::RSA_PSS_SHA256
                };
                k.sign(pad, &rng, msg, &mut sig)
                    .map_err(|_| anyhow::anyhow!("RSA signing failed"))?;
                sig
            }
            (Kind::Ec(k, a), b) if *a == b => k
                .sign(&rng, msg)
                .map_err(|_| anyhow::anyhow!("EC signing failed"))?
                .as_ref()
                .to_vec(),
            (Kind::Ed(k), Alg::EdDSA) => k.sign(msg).as_ref().to_vec(),
            _ => anyhow::bail!("the key cannot sign {}", alg.as_str()),
        })
    }

    /// The public key as a JWK (`use: sig`).
    pub fn public_jwk(&self, kid: &str, alg: Option<Alg>) -> Value {
        let b = |v: &[u8]| URL_SAFE_NO_PAD.encode(v);
        let mut jwk = match &self.kind {
            Kind::Rsa(k) => {
                let c: ring::rsa::PublicKeyComponents<Vec<u8>> = k.public().into();
                let trim = |v: &[u8]| {
                    let i = v
                        .iter()
                        .position(|x| *x != 0)
                        .unwrap_or(v.len().saturating_sub(1));
                    v[i..].to_vec()
                };
                json!({"kty": "RSA", "n": b(&trim(&c.n)), "e": b(&trim(&c.e))})
            }
            Kind::Ec(k, a) => {
                let point = k.public_key().as_ref();
                let half = (point.len() - 1) / 2;
                json!({
                    "kty": "EC",
                    "crv": if *a == Alg::ES256 { "P-256" } else { "P-384" },
                    "x": b(&point[1..1 + half]),
                    "y": b(&point[1 + half..]),
                })
            }
            Kind::Ed(k) => json!({"kty": "OKP", "crv": "Ed25519", "x": b(k.public_key().as_ref())}),
        };
        if !kid.is_empty() {
            jwk["kid"] = json!(kid);
            jwk["use"] = json!("sig");
        }
        if let Some(a) = alg {
            jwk["alg"] = json!(a.as_str());
        }
        jwk
    }
}

/// The public key of a configuration as a JWK set, for registration at the
/// identity provider (`hopae providers jwk <id>`). No private material.
pub fn jwks_of(cfg: &AssertionCfg) -> anyhow::Result<Value> {
    let (key, _) = load(cfg)?;
    let alg = cfg
        .algorithms
        .as_ref()
        .and_then(|l| l.first().copied())
        .or_else(|| key.algs().first().copied());
    Ok(json!({"keys": [key.public_jwk(&cfg.key_id, alg)]}))
}

/// Read and check the key file against the configuration (for `--check`,
/// the start and the CLI).
pub fn load(cfg: &AssertionCfg) -> anyhow::Result<(Key, [u8; 32])> {
    let (bytes, digest) = crate::reload::snapshot(std::slice::from_ref(&cfg.key_file))?;
    let key = Key::parse(&bytes[0])?;
    check_algs(cfg, &key)?;
    Ok((key, digest))
}

fn check_algs(cfg: &AssertionCfg, key: &Key) -> anyhow::Result<()> {
    if let Some(list) = &cfg.algorithms {
        let can = key.algs();
        if let Some(a) = list.iter().find(|a| !can.contains(a)) {
            anyhow::bail!(
                "client_assertion.algorithms: the key cannot sign {}",
                a.as_str()
            );
        }
    }
    Ok(())
}

#[derive(Default)]
struct State {
    failing: bool,
    error: Option<String>,
    reloads: u64,
    last_reload_at: Option<i64>,
}

/// A provider's assertion key, followed.
pub struct ClientAssertion {
    name: String,
    cfg: AssertionCfg,
    key: ArcSwap<Key>,
    digest: Mutex<[u8; 32]>,
    next_poll: Mutex<Instant>,
    state: Mutex<State>,
}

/// Why no assertion could be made (logged; the request fails as unavailable).
#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    /// Discovery lists methods without `private_key_jwt`.
    MethodNotSupported,
    /// No allowed algorithm is in discovery's list.
    NoCommonAlgorithm,
    Signing,
}

impl ClientAssertion {
    pub fn new(provider: &str, cfg: AssertionCfg, key: Key, digest: [u8; 32]) -> Self {
        let name = format!("provider:{provider}:client_assertion");
        tracing::info!(name, kid = %cfg.key_id, fingerprint = %key.fingerprint, "client assertion key loaded");
        crate::telemetry::counters::set(crate::reload::TLS_RELOAD_FAILING, &[("name", &name)], 0);
        ClientAssertion {
            name,
            cfg,
            key: ArcSwap::from_pointee(key),
            digest: Mutex::new(digest),
            next_poll: Mutex::new(Instant::now()),
            state: Mutex::new(State {
                last_reload_at: Some(crate::reload::unix_now()),
                ..State::default()
            }),
        }
    }

    pub fn cfg(&self) -> &AssertionCfg {
        &self.cfg
    }

    pub fn due(&self) -> bool {
        super::trust::due(&self.next_poll)
    }

    /// Re-read the key file; swap the key when it changed and is valid.
    pub fn poll(&self) -> Outcome {
        let outcome = self.check();
        let mut st = self.state.lock().unwrap_or_else(|p| p.into_inner());
        note_metrics(&self.name, &outcome, st.failing);
        match &outcome {
            Outcome::Unchanged => {
                st.failing = false;
                st.error = None;
            }
            Outcome::Reloaded(_) => {
                *st = State {
                    reloads: st.reloads + 1,
                    last_reload_at: Some(crate::reload::unix_now()),
                    ..State::default()
                };
            }
            Outcome::Invalid(why) => {
                st.failing = true;
                st.error = Some(why.clone());
            }
        }
        outcome
    }

    fn check(&self) -> Outcome {
        let (bytes, digest) =
            match crate::reload::snapshot(std::slice::from_ref(&self.cfg.key_file)) {
                Ok(v) => v,
                Err(e) => return Outcome::Invalid(format!("unreadable: {e}")),
            };
        let mut last = self.digest.lock().unwrap_or_else(|p| p.into_inner());
        if *last == digest {
            return Outcome::Unchanged;
        }
        match Key::parse(&bytes[0]).and_then(|k| check_algs(&self.cfg, &k).map(|_| k)) {
            Ok(key) => {
                let print = key.fingerprint.clone();
                self.key.store(Arc::new(key));
                *last = digest;
                Outcome::Reloaded(print)
            }
            Err(e) => Outcome::Invalid(e.to_string()),
        }
    }

    /// Choose the algorithm: the allowlist (default: the key's), in order,
    /// intersected with discovery's list when it has one.
    pub fn choose(&self, key: &Key, advertised: Option<&[String]>) -> Option<Alg> {
        let allowed = self.cfg.algorithms.clone().unwrap_or_else(|| key.algs());
        allowed.into_iter().find(|a| {
            key.algs().contains(a) && advertised.is_none_or(|l| l.iter().any(|s| s == a.as_str()))
        })
    }

    /// A fresh assertion for `client_id` towards `audience`.
    pub fn assertion(
        &self,
        client_id: &str,
        audience: &str,
        advertised_methods: Option<&[String]>,
        advertised_algs: Option<&[String]>,
        now: i64,
    ) -> Result<String, Refusal> {
        if advertised_methods.is_some_and(|m| !m.iter().any(|x| x == "private_key_jwt")) {
            return Err(Refusal::MethodNotSupported);
        }
        let key = self.key.load_full();
        let alg = self
            .choose(&key, advertised_algs)
            .ok_or(Refusal::NoCommonAlgorithm)?;
        let mut jti = [0u8; 16];
        SystemRandom::new()
            .fill(&mut jti)
            .map_err(|_| Refusal::Signing)?;
        let header = json!({"alg": alg.as_str(), "typ": "JWT", "kid": self.cfg.key_id});
        let claims = json!({
            "iss": client_id,
            "sub": client_id,
            "aud": audience,
            "iat": now,
            "exp": now + LIFETIME_SECS,
            "jti": URL_SAFE_NO_PAD.encode(jti),
        });
        let signing_input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(claims.to_string())
        );
        let sig = key
            .sign(alg, signing_input.as_bytes())
            .map_err(|_| Refusal::Signing)?;
        Ok(format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig)))
    }

    /// The public key as a JWK set (for the CLI).
    pub fn jwks(&self) -> Value {
        let key = self.key.load_full();
        let alg = self.choose(&key, None);
        json!({"keys": [key.public_jwk(&self.cfg.key_id, alg)]})
    }

    pub fn status(&self) -> Value {
        let st = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let key = self.key.load_full();
        json!({
            "method": "private_key_jwt",
            "key_id": self.cfg.key_id,
            "key_fingerprint": key.fingerprint,
            "algorithms": key.algs().iter().filter(|a| self.cfg.algorithms.as_ref().is_none_or(|l| l.contains(a))).map(|a| a.as_str()).collect::<Vec<_>>(),
            "audience": match self.cfg.audience { Audience::TokenEndpoint => "token_endpoint", Audience::Issuer => "issuer" },
            "failing": st.failing,
            "error": st.error,
            "reloads": st.reloads,
            "last_reload_at": st.last_reload_at,
        })
    }
}
