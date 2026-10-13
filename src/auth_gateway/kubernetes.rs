//! Pod-bound workload authentication through a fixed trusted Kubernetes TokenReview API.
//! No result cache: bound-object validity is checked by the API on every invocation.
use super::{PrincipalKind, Subject, VerifiedEvidence, breaker::Circuit, runtime::Error};
use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, sync::Arc, time::Duration};
use zeroize::Zeroizing;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub api_origin: String,
    pub issuer: String,
    pub cluster_id: String,
    pub audience: String,
    pub timeout_ms: u64,
}
pub struct Connector {
    config: Config,
    client: reqwest::Client,
    endpoint: url::Url,
    authorization: reqwest::header::HeaderValue,
    capacity: tokio::sync::Semaphore,
    circuit: Arc<Circuit>,
}
#[derive(Deserialize)]
struct Claims {
    iss: String,
    sub: String,
    aud: Vec<String>,
    exp: u64,
    nbf: Option<u64>,
    #[serde(rename = "kubernetes.io")]
    kubernetes: PrivateClaims,
}
#[derive(Deserialize)]
struct PrivateClaims {
    namespace: String,
    serviceaccount: BoundObject,
    pod: BoundObject,
}
#[derive(Deserialize)]
struct BoundObject {
    name: String,
    uid: String,
}
#[derive(Deserialize)]
struct Reply {
    #[serde(rename = "apiVersion")]
    api_version: String,
    kind: String,
    status: Status,
}
#[derive(Deserialize)]
struct Status {
    #[serde(default)]
    authenticated: bool,
    #[serde(default)]
    audiences: Vec<String>,
    error: Option<String>,
    user: Option<User>,
}
#[derive(Deserialize)]
struct User {
    username: String,
    uid: String,
    #[serde(default)]
    extra: BTreeMap<String, Vec<String>>,
}
fn identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._".contains(&b))
}
impl Config {
    pub fn validate(&self) -> Result<()> {
        let url = url::Url::parse(&self.api_origin)?;
        ensure!(
            url.scheme() == "https"
                && url.host_str().is_some()
                && url.username().is_empty()
                && url.password().is_none()
                && url.path() == "/"
                && url.query().is_none()
                && url.fragment().is_none(),
            "Kubernetes API must be an HTTPS origin"
        );
        let issuer = url::Url::parse(&self.issuer)?;
        ensure!(
            issuer.scheme() == "https"
                && issuer.host_str().is_some()
                && issuer.username().is_empty()
                && issuer.password().is_none()
                && issuer.query().is_none()
                && issuer.fragment().is_none()
                && self.issuer.len() <= 256,
            "invalid Kubernetes issuer"
        );
        ensure!(
            identifier(&self.cluster_id)
                && !self.audience.is_empty()
                && self.audience.len() <= 256
                && !self.audience.chars().any(char::is_control)
                && (1..=1000).contains(&self.timeout_ms),
            "invalid Kubernetes authentication scope"
        );
        Ok(())
    }
}
impl Connector {
    /// Material is supplied by the native owner; it never appears in serialized Config.
    pub fn compile(
        config: &Config,
        ca_pem: &[u8],
        reviewer_token: Zeroizing<String>,
    ) -> Result<Self> {
        config.validate()?;
        ensure!(
            !ca_pem.is_empty()
                && ca_pem.len() <= 65536
                && (16..=4096).contains(&reviewer_token.len())
                && reviewer_token.bytes().all(|b| b.is_ascii_graphic()),
            "invalid Kubernetes reviewer material"
        );
        let roots = reqwest::Certificate::from_pem_bundle(ca_pem)?;
        ensure!(
            !roots.is_empty() && roots.len() <= 16,
            "invalid Kubernetes CA bundle"
        );
        let mut builder = reqwest::Client::builder()
            .https_only(true)
            .tls_built_in_root_certs(false)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_millis(config.timeout_ms));
        for root in roots {
            builder = builder.add_root_certificate(root);
        }
        let client = builder.build()?;
        let mut authorization =
            reqwest::header::HeaderValue::from_str(&format!("Bearer {}", &*reviewer_token))?;
        authorization.set_sensitive(true);
        Ok(Self {
            config: config.clone(),
            client,
            endpoint: url::Url::parse(&config.api_origin)?
                .join("apis/authentication.k8s.io/v1/tokenreviews")?,
            authorization,
            capacity: tokio::sync::Semaphore::new(64),
            circuit: Circuit::new(3, 30_000).expect("constant circuit bounds"),
        })
    }
    fn claims(&self, token: &str, now_ms: u64) -> Result<Claims, Error> {
        if !(32..=4096).contains(&token.len()) {
            return Err(Error::Invalid);
        }
        let mut parts = token.split('.');
        let header = parts.next().ok_or(Error::Invalid)?;
        let payload = parts.next().ok_or(Error::Invalid)?;
        let signature = parts
            .next()
            .filter(|s| !s.is_empty())
            .ok_or(Error::Invalid)?;
        if parts.next().is_some() || URL_SAFE_NO_PAD.decode(signature).is_err() {
            return Err(Error::Invalid);
        }
        let header: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header).map_err(|_| Error::Invalid)?)
                .map_err(|_| Error::Invalid)?;
        if !header["alg"].as_str().is_some_and(|s| {
            [
                "RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "EdDSA",
            ]
            .contains(&s)
        }) {
            return Err(Error::Invalid);
        }
        let bytes = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(payload)
                .map_err(|_| Error::Invalid)?,
        );
        let claims: Claims = serde_json::from_slice(&bytes).map_err(|_| Error::Invalid)?;
        let k = &claims.kubernetes;
        let expiry = claims.exp.checked_mul(1000).ok_or(Error::Invalid)?;
        if claims.iss != self.config.issuer
            || !claims.aud.iter().any(|a| a == &self.config.audience)
            || claims.aud.len() > 16
            || expiry <= now_ms
            || claims
                .nbf
                .is_some_and(|t| t.checked_mul(1000).is_none_or(|t| t > now_ms))
            || ![
                &k.namespace,
                &k.serviceaccount.name,
                &k.serviceaccount.uid,
                &k.pod.name,
                &k.pod.uid,
            ]
            .iter()
            .all(|s| identifier(s))
            || claims.sub
                != format!(
                    "system:serviceaccount:{}:{}",
                    k.namespace, k.serviceaccount.name
                )
        {
            return Err(Error::Invalid);
        }
        // Parsing is only a refusal precheck. These claims are not evidence until TokenReview succeeds.
        Ok(claims)
    }
    pub async fn authenticate(
        &self,
        service: &str,
        token: &str,
        now_ms: u64,
    ) -> Result<VerifiedEvidence, Error> {
        if !identifier(service) {
            return Err(Error::Invalid);
        }
        let claims = self.claims(token, now_ms)?;
        let _permit = self
            .capacity
            .try_acquire()
            .map_err(|_| Error::Unavailable)?;
        let lease = self.circuit.admit().ok_or(Error::Unavailable)?;
        let result = self.exchange(service, token, claims, now_ms).await;
        lease.finish(matches!(result, Err(Error::Unavailable)));
        result
    }
    async fn exchange(
        &self,
        service: &str,
        token: &str,
        claims: Claims,
        now_ms: u64,
    ) -> Result<VerifiedEvidence, Error> {
        let started = std::time::Instant::now();
        let future = async {
            let mut response = self.client.post(self.endpoint.clone()).header(reqwest::header::AUTHORIZATION,self.authorization.clone()).header(reqwest::header::ACCEPT,"application/json").json(&serde_json::json!({"apiVersion":"authentication.k8s.io/v1","kind":"TokenReview","spec":{"token":token,"audiences":[self.config.audience]}})).send().await.map_err(|_| Error::Unavailable)?;
            if ![200, 201].contains(&response.status().as_u16())
                || !response
                    .headers()
                    .get(reqwest::header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .is_some_and(|v| {
                        v.split(';')
                            .next()
                            .is_some_and(|v| v.trim() == "application/json")
                    })
            {
                return Err(Error::Unavailable);
            }
            let mut body = Zeroizing::new(Vec::new());
            while let Some(chunk) = response.chunk().await.map_err(|_| Error::Unavailable)? {
                if body.len() + chunk.len() > 65536 {
                    return Err(Error::Unavailable);
                }
                body.extend_from_slice(&chunk);
            }
            serde_json::from_slice::<Reply>(&body).map_err(|_| Error::Unavailable)
        };
        let reply = tokio::time::timeout(Duration::from_millis(self.config.timeout_ms), future)
            .await
            .map_err(|_| Error::Unavailable)??;
        let now_ms = now_ms
            .checked_add(
                u64::try_from(started.elapsed().as_millis()).map_err(|_| Error::Unavailable)?,
            )
            .ok_or(Error::Unavailable)?;
        self.evidence(service, claims, reply, now_ms)
    }
    fn evidence(
        &self,
        service: &str,
        claims: Claims,
        reply: Reply,
        now_ms: u64,
    ) -> Result<VerifiedEvidence, Error> {
        if reply.api_version != "authentication.k8s.io/v1" || reply.kind != "TokenReview" {
            return Err(Error::Unavailable);
        }
        if !reply.status.authenticated {
            return Err(Error::Invalid);
        }
        if reply.status.error.as_ref().is_some_and(|s| !s.is_empty()) {
            return Err(Error::Unavailable);
        }
        let user = reply.status.user.ok_or(Error::Unavailable)?;
        let k = &claims.kubernetes;
        let extra = |name: &str, expected: &str| {
            user.extra
                .get(name)
                .is_some_and(|v| v.len() == 1 && v[0] == expected)
        };
        if !reply
            .status
            .audiences
            .iter()
            .any(|a| a == &self.config.audience)
            || user.username != claims.sub
            || user.uid != k.serviceaccount.uid
            || !extra("authentication.kubernetes.io/pod-name", &k.pod.name)
            || !extra("authentication.kubernetes.io/pod-uid", &k.pod.uid)
        {
            return Err(Error::Unavailable);
        }
        let expires_at = claims
            .exp
            .checked_mul(1000)
            .ok_or(Error::Invalid)?
            .min(now_ms.checked_add(1000).ok_or(Error::Unavailable)?);
        if expires_at <= now_ms {
            return Err(Error::Invalid);
        }
        let mut digest = Sha256::new();
        digest.update(b"hopae:kubernetes:pod-subject:v1\0");
        for value in [
            &k.namespace,
            &k.serviceaccount.name,
            &k.serviceaccount.uid,
            &k.pod.name,
            &k.pod.uid,
        ] {
            digest.update((value.len() as u32).to_be_bytes());
            digest.update(value.as_bytes());
        }
        let subject = format!("w_{:x}", digest.finalize());
        Ok(VerifiedEvidence {
            subject: Subject {
                issuer: self.config.issuer.clone(),
                realm: self.config.cluster_id.clone(),
                subject,
                kind: PrincipalKind::Workload,
            },
            connector: "kubernetes-tokenreview".into(),
            expires_at,
            service: Some(service.to_owned()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config() -> Config {
        Config {
            api_origin: "https://kubernetes.example.test/".into(),
            issuer: "https://issuer.example.test".into(),
            cluster_id: "example-cluster".into(),
            audience: "example-workload".into(),
            timeout_ms: 500,
        }
    }
    fn token() -> String {
        format!("{}.{}.{}", URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256"}"#),URL_SAFE_NO_PAD.encode(serde_json::to_vec(&serde_json::json!({"iss":"https://issuer.example.test","sub":"system:serviceaccount:blue:worker","aud":["example-workload"],"exp":2,"kubernetes.io":{"namespace":"blue","serviceaccount":{"name":"worker","uid":"sa-1"},"pod":{"name":"worker-pod","uid":"pod-1"}}})).unwrap()),URL_SAFE_NO_PAD.encode([1;32]))
    }
    fn connector() -> Connector {
        let config = config();
        Connector {
            config,
            client: reqwest::Client::new(),
            endpoint: url::Url::parse("https://kubernetes.example.test/").unwrap(),
            authorization: reqwest::header::HeaderValue::from_static("Bearer fixture-only"),
            capacity: tokio::sync::Semaphore::new(64),
            circuit: Circuit::new(3, 30_000).unwrap(),
        }
    }
    fn reply() -> Reply {
        serde_json::from_value(serde_json::json!({"apiVersion":"authentication.k8s.io/v1","kind":"TokenReview","status":{"authenticated":true,"audiences":["example-workload"],"user":{"username":"system:serviceaccount:blue:worker","uid":"sa-1","extra":{"authentication.kubernetes.io/pod-name":["worker-pod"],"authentication.kubernetes.io/pod-uid":["pod-1"]}}}})).unwrap()
    }
    #[test]
    fn scope_and_bound_object_attestation_are_required() {
        let c = connector();
        let t = token();
        let e = c
            .evidence("orders", c.claims(&t, 100).unwrap(), reply(), 100)
            .unwrap();
        assert_eq!(e.subject.kind, PrincipalKind::Workload);
        assert_eq!(e.expires_at, 1100);
        assert_eq!(e.service(), Some("orders"));
        let stable = super::super::stable_subject(e.subject());
        let mut other = reply();
        other.status.user.as_mut().unwrap().uid = "sa-2".into();
        assert!(
            c.evidence("orders", c.claims(&t, 100).unwrap(), other, 100)
                .is_err()
        );
        let mut other = reply();
        other.status.user.as_mut().unwrap().extra.clear();
        assert!(
            c.evidence("orders", c.claims(&t, 100).unwrap(), other, 100)
                .is_err()
        );
        let mut other = reply();
        other.status.audiences = vec!["other".into()];
        assert!(
            c.evidence("orders", c.claims(&t, 100).unwrap(), other, 100)
                .is_err()
        );
        let mut other = reply();
        other.status.authenticated = false;
        other.status.error = Some("invalid fixture credential".into());
        assert!(matches!(
            c.evidence("orders", c.claims(&t, 100).unwrap(), other, 100),
            Err(Error::Invalid)
        ));
        let mut other = connector();
        other.config.cluster_id = "other-cluster".into();
        let e = other
            .evidence("orders", other.claims(&t, 100).unwrap(), reply(), 100)
            .unwrap();
        assert_ne!(super::super::stable_subject(e.subject()), stable);
        assert!(
            c.evidence("orders", c.claims(&t, 100).unwrap(), reply(), 2000)
                .is_err()
        );
    }
    #[test]
    fn token_parsing_never_accepts_wrong_issuer_audience_expiry_or_unbound_token() {
        let c = connector();
        assert!(c.claims(&token(), 2000).is_err());
        let mut c = connector();
        c.config.issuer = "https://other.example.test".into();
        assert!(c.claims(&token(), 100).is_err());
        let mut c = connector();
        c.config.audience = "other".into();
        assert!(c.claims(&token(), 100).is_err());
        for t in [
            "opaque-credential-without-jwt-claims".to_owned(),
            token() + ".extra",
            format!(
                "{}.{}.{}",
                URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#),
                URL_SAFE_NO_PAD.encode(b"{}"),
                URL_SAFE_NO_PAD.encode([1; 32])
            ),
        ] {
            assert!(connector().claims(&t, 100).is_err());
        }
    }
    #[test]
    fn api_origin_never_accepts_credentials_redirect_targets_or_http() {
        for origin in [
            "http://kubernetes.example.test/",
            "https://user:pass@kubernetes.example.test/",
            "https://kubernetes.example.test/path",
            "https://kubernetes.example.test/?token=value",
            "https://kubernetes.example.test/#x",
        ] {
            let mut c = config();
            c.api_origin = origin.into();
            assert!(c.validate().is_err());
        }
    }
}
