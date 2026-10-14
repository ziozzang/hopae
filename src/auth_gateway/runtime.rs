//! File-owned, compiled service authentication. No credential material enters snapshots or replies.
use super::{PrincipalKind, Subject, VerifiedEvidence};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, net::IpAddr};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub authority_id: String,
    pub profiles: Vec<Profile>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub service_id: String,
    pub host: String,
    pub ports: Vec<u16>,
    pub realm: String,
    #[serde(default)]
    pub api_keys: Vec<ApiKey>,
    #[serde(default)]
    pub api_relay: Option<super::relay::Config>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kubernetes_tokenreview: Option<super::kubernetes::Profile>,
    #[serde(default)]
    pub networks: Vec<String>,
    #[serde(default)]
    pub session_fallback: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub eligibility_lua: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_token_prefix: Option<String>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApiKey {
    pub token_env: String,
    pub subject: String,
    /// Absolute Unix milliseconds; no expiry means explicitly configured long-lived credential.
    #[serde(default)]
    pub expires_at: Option<u64>,
}
fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-.".contains(&b))
}
impl Config {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            identifier(&self.authority_id) && (1..=128).contains(&self.profiles.len()),
            "invalid authentication authority/profiles"
        );
        let mut scopes = std::collections::HashSet::new();
        let mut total = 0;
        for p in &self.profiles {
            if let Some(source) = &p.eligibility_lua {
                super::lua::Policy::compile(source).map_err(|_| {
                    anyhow::anyhow!("invalid service authentication eligibility script")
                })?;
            }
            ensure!(
                identifier(&p.service_id) && identifier(&p.realm),
                "invalid authentication service/realm"
            );
            let host = crate::policy::types::Host::parse(&p.host)?;
            ensure!(
                (1..=16).contains(&p.ports.len())
                    && p.api_keys.len() <= 256
                    && (p.api_relay.is_some()
                        || p.kubernetes_tokenreview.is_some()
                        || !p.api_keys.is_empty())
                    && p.networks.len() <= 256,
                "authentication profile exceeds bounds"
            );
            let mixed = p.api_relay.is_some()
                && (!p.api_keys.is_empty() || p.kubernetes_tokenreview.is_some());
            ensure!(
                !mixed || p.relay_token_prefix.is_some(),
                "mixed authentication requires an explicit relay token prefix"
            );
            ensure!(
                p.relay_token_prefix.is_none() || p.api_relay.is_some(),
                "relay token prefix requires a relay"
            );
            if let Some(prefix) = &p.relay_token_prefix {
                ensure!(
                    (2..=32).contains(&prefix.len())
                        && prefix.ends_with(':')
                        && prefix[..prefix.len() - 1]
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b)),
                    "invalid relay token prefix"
                );
            }
            if let Some(relay) = &p.api_relay {
                relay.validate()?;
                ensure!(
                    !mixed || relay.issuer != format!("hopae:{}", self.authority_id),
                    "mixed relay must use a distinct issuer namespace"
                );
            }
            if let Some(kubernetes) = &p.kubernetes_tokenreview {
                kubernetes.validate()?;
                ensure!(
                    kubernetes.connection.cluster_id == p.realm,
                    "Kubernetes cluster must match profile realm"
                );
                ensure!(
                    p.relay_token_prefix
                        .as_ref()
                        .is_none_or(|prefix| prefix != &kubernetes.token_prefix),
                    "credential routing prefixes must be distinct"
                );
            }
            total += p.api_keys.len();
            ensure!(total <= 4096, "authentication credential capacity exceeded");
            for port in &p.ports {
                ensure!(
                    *port != 0 && scopes.insert((host.as_str().to_owned(), *port)),
                    "duplicate or invalid authentication scope"
                );
            }
            for key in &p.api_keys {
                ensure!(
                    identifier(&key.subject)
                        && !key.token_env.is_empty()
                        && key.token_env.len() <= 128
                        && key
                            .token_env
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b == b'_'),
                    "invalid API credential reference/subject"
                );
                ensure!(
                    key.expires_at.is_none_or(|t| t > 0 && t <= i64::MAX as u64),
                    "invalid API credential expiry"
                );
            }
            for network in &p.networks {
                let _: ipnet::IpNet = network.parse()?;
            }
        }
        Ok(())
    }
}
#[derive(Default)]
struct Node {
    next: [Option<usize>; 2],
    terminal: bool,
}
struct Networks {
    v4: Vec<Node>,
    v6: Vec<Node>,
    unrestricted: bool,
}
impl Networks {
    fn compile(networks: &[String], budget: &mut usize) -> Result<Self> {
        let mut result = Self {
            v4: vec![Node::default()],
            v6: vec![Node::default()],
            unrestricted: networks.is_empty(),
        };
        for value in networks {
            let network: ipnet::IpNet = value.parse()?;
            ensure!(
                network.addr().to_canonical() == network.addr(),
                "use canonical IPv4 prefixes for mapped IPv6 networks"
            );
            let (nodes, number, width) = match network {
                ipnet::IpNet::V4(n) => (&mut result.v4, u32::from(n.network()) as u128, 32),
                ipnet::IpNet::V6(n) => (&mut result.v6, u128::from(n.network()), 128),
            };
            let mut index = 0;
            for bit in 0..network.prefix_len() {
                let branch = ((number >> (width - 1 - bit)) & 1) as usize;
                index = if let Some(next) = nodes[index].next[branch] {
                    next
                } else {
                    ensure!(
                        *budget < 65536,
                        "compiled authentication network capacity exceeded"
                    );
                    *budget += 1;
                    let next = nodes.len();
                    nodes.push(Node::default());
                    nodes[index].next[branch] = Some(next);
                    next
                };
            }
            nodes[index].terminal = true;
        }
        Ok(result)
    }
    fn permits(&self, ip: IpAddr) -> bool {
        if self.unrestricted {
            return true;
        }
        let (nodes, number, width) = match ip.to_canonical() {
            IpAddr::V4(ip) => (&self.v4, u32::from(ip) as u128, 32),
            IpAddr::V6(ip) => (&self.v6, u128::from(ip), 128),
        };
        let mut index = 0;
        for bit in 0..width {
            if nodes[index].terminal {
                return true;
            }
            let Some(next) = nodes[index].next[((number >> (width - 1 - bit)) & 1) as usize] else {
                return false;
            };
            index = next;
        }
        nodes[index].terminal
    }
}
struct Credential {
    subject: Subject,
    expires_at: Option<u64>,
}
struct Prepared {
    service_id: String,
    realm: String,
    keys: HashMap<[u8; 32], Credential>,
    networks: Networks,
    session_fallback: bool,
    relay: Option<std::sync::Arc<super::relay::Connector>>,
    kubernetes: Option<(std::sync::Arc<super::kubernetes::Connector>, String)>,
    eligibility: Option<super::lua::Policy>,
    eligibility_capacity: tokio::sync::Semaphore,
    relay_token_prefix: Option<String>,
}
pub struct Runtime {
    profiles: HashMap<String, HashMap<u16, std::sync::Arc<Prepared>>>,
    pub(crate) observed_time: std::sync::Arc<std::sync::atomic::AtomicU64>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Missing,
    Invalid,
    Expired,
    NetworkDenied,
    Unavailable,
}
impl Runtime {
    pub fn compile(config: &Config, env: &dyn Fn(&str) -> Option<String>) -> Result<Self> {
        Self::compile_resuming(config, env, None)
    }
    pub(crate) fn compile_resuming(
        config: &Config,
        env: &dyn Fn(&str) -> Option<String>,
        previous: Option<&Self>,
    ) -> Result<Self> {
        config.validate()?;
        let mut profiles: HashMap<String, HashMap<u16, std::sync::Arc<Prepared>>> = HashMap::new();
        let mut budget = 0;
        for p in &config.profiles {
            let mut keys = HashMap::new();
            for key in &p.api_keys {
                let value = env(&key.token_env)
                    .ok_or_else(|| anyhow::anyhow!("API credential reference unavailable"))?;
                ensure!(
                    (32..=1024).contains(&value.len())
                        && value.bytes().all(|b| b.is_ascii_graphic()),
                    "invalid API credential material"
                );
                ensure!(
                    p.relay_token_prefix
                        .as_ref()
                        .is_none_or(|prefix| !value.starts_with(prefix)),
                    "local credential collides with relay routing namespace"
                );
                ensure!(
                    p.kubernetes_tokenreview
                        .as_ref()
                        .is_none_or(|k| !value.starts_with(&k.token_prefix)),
                    "local credential collides with Kubernetes routing namespace"
                );
                let digest: [u8; 32] = Sha256::digest(value.as_bytes()).into();
                let subject = Subject {
                    issuer: format!("hopae:{}", config.authority_id),
                    realm: p.realm.clone(),
                    subject: key.subject.clone(),
                    kind: PrincipalKind::Service,
                };
                ensure!(
                    keys.insert(
                        digest,
                        Credential {
                            subject,
                            expires_at: key.expires_at
                        }
                    )
                    .is_none(),
                    "duplicate API credential in service scope"
                );
            }
            let relay = p
                .api_relay
                .as_ref()
                .map(|r| super::relay::Connector::compile(r, env))
                .transpose()?
                .map(std::sync::Arc::new);
            let relay = relay.map(|candidate| {
                previous
                    .and_then(|runtime| runtime.profiles.get(&p.host.to_ascii_lowercase()))
                    .and_then(|ports| p.ports.iter().find_map(|port| ports.get(port)))
                    .filter(|old| old.service_id == p.service_id && old.realm == p.realm)
                    .and_then(|old| old.relay.as_ref())
                    .filter(|old| old.same_binding(&candidate))
                    .cloned()
                    .unwrap_or(candidate)
            });
            let kubernetes = p
                .kubernetes_tokenreview
                .as_ref()
                .map(|k| {
                    let candidate = std::sync::Arc::new(k.compile(env)?);
                    let connector = previous
                        .and_then(|runtime| runtime.profiles.get(&p.host.to_ascii_lowercase()))
                        .and_then(|ports| p.ports.iter().find_map(|port| ports.get(port)))
                        .filter(|old| old.service_id == p.service_id && old.realm == p.realm)
                        .and_then(|old| old.kubernetes.as_ref())
                        .filter(|(old, prefix)| {
                            prefix == &k.token_prefix && old.same_binding(&candidate)
                        })
                        .map(|(old, _)| old.clone())
                        .unwrap_or(candidate);
                    Ok::<_, anyhow::Error>((connector, k.token_prefix.clone()))
                })
                .transpose()?;
            let prepared = std::sync::Arc::new(Prepared {
                service_id: p.service_id.clone(),
                realm: p.realm.clone(),
                keys,
                networks: Networks::compile(&p.networks, &mut budget)?,
                session_fallback: p.session_fallback,
                relay,
                kubernetes,
                eligibility: p
                    .eligibility_lua
                    .as_deref()
                    .map(super::lua::Policy::compile)
                    .transpose()
                    .map_err(|_| {
                        anyhow::anyhow!("invalid service authentication eligibility script")
                    })?,
                eligibility_capacity: tokio::sync::Semaphore::new(64),
                relay_token_prefix: p.relay_token_prefix.clone(),
            });
            for port in &p.ports {
                profiles
                    .entry(p.host.to_ascii_lowercase())
                    .or_default()
                    .insert(*port, prepared.clone());
            }
        }
        Ok(Self {
            profiles,
            observed_time: previous
                .map(|runtime| runtime.observed_time.clone())
                .unwrap_or_default(),
        })
    }
    pub fn handles(&self, host: &str, port: u16) -> bool {
        self.profiles
            .get(host)
            .is_some_and(|ports| ports.contains_key(&port))
    }
    pub fn session_fallback(&self, host: &str, port: u16) -> bool {
        self.profiles
            .get(host)
            .and_then(|ports| ports.get(&port))
            .is_some_and(|p| p.session_fallback)
    }
    pub async fn authenticate_async(
        &self,
        host: &str,
        port: u16,
        token: Option<&str>,
        ip: IpAddr,
        now: u64,
    ) -> Result<VerifiedEvidence, Error> {
        let profile = self
            .profiles
            .get(host)
            .and_then(|ports| ports.get(&port))
            .ok_or(Error::Invalid)?;
        if let Some((kubernetes, prefix)) = &profile.kubernetes {
            if !profile.networks.permits(ip) {
                return Err(Error::NetworkDenied);
            }
            let credential = token.ok_or(Error::Missing)?;
            if credential.len() > 4096 || !credential.bytes().all(|b| b.is_ascii_graphic()) {
                return Err(Error::Invalid);
            }
            if let Some(credential) = credential.strip_prefix(prefix) {
                self.observed_time
                    .fetch_max(now, std::sync::atomic::Ordering::AcqRel);
                let now = self
                    .observed_time
                    .load(std::sync::atomic::Ordering::Acquire);
                let started = std::time::Instant::now();
                let evidence = kubernetes
                    .authenticate(&profile.service_id, credential, now)
                    .await?;
                return profile.restrict(
                    evidence,
                    now.saturating_add(started.elapsed().as_millis().min(u64::MAX as u128) as u64),
                );
            }
        }
        if let Some(relay) = &profile.relay {
            if !profile.networks.permits(ip) {
                return Err(Error::NetworkDenied);
            }
            let token = token.ok_or(Error::Missing)?;
            let token = if let Some(prefix) = &profile.relay_token_prefix {
                if token.len() > 4096 || !token.bytes().all(|b| b.is_ascii_graphic()) {
                    return Err(Error::Invalid);
                }
                match token.strip_prefix(prefix) {
                    Some(credential) => credential,
                    None => return self.authenticate(host, port, Some(token), ip, now),
                }
            } else {
                token
            };
            self.observed_time
                .fetch_max(now, std::sync::atomic::Ordering::AcqRel);
            let now = self
                .observed_time
                .load(std::sync::atomic::Ordering::Acquire);
            let started = std::time::Instant::now();
            let evidence = relay
                .authenticate(&profile.service_id, &profile.realm, token, ip, now)
                .await?;
            profile.restrict(
                evidence,
                now.saturating_add(started.elapsed().as_millis().min(u64::MAX as u128) as u64),
            )
        } else {
            self.authenticate(host, port, token, ip, now)
        }
    }
    pub fn authenticate(
        &self,
        host: &str,
        port: u16,
        token: Option<&str>,
        ip: IpAddr,
        now: u64,
    ) -> Result<VerifiedEvidence, Error> {
        self.observed_time
            .fetch_max(now, std::sync::atomic::Ordering::AcqRel);
        let now = self
            .observed_time
            .load(std::sync::atomic::Ordering::Acquire);
        let p = self
            .profiles
            .get(host)
            .and_then(|ports| ports.get(&port))
            .ok_or(Error::Invalid)?;
        let token = token.ok_or(Error::Missing)?;
        if !(32..=1024).contains(&token.len()) || !token.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(Error::Invalid);
        }
        let digest: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        let key = p.keys.get(&digest).ok_or(Error::Invalid)?;
        if key.expires_at.is_some_and(|t| t <= now) {
            return Err(Error::Expired);
        }
        if !p.networks.permits(ip) {
            return Err(Error::NetworkDenied);
        }
        p.restrict(
            VerifiedEvidence {
                subject: key.subject.clone(),
                service: Some(p.service_id.clone()),
                connector: format!("api-key:{}", p.service_id),
                expires_at: now
                    .saturating_add(1000)
                    .min(key.expires_at.unwrap_or(u64::MAX)),
            },
            now,
        )
    }
}

impl Prepared {
    fn restrict(&self, evidence: VerifiedEvidence, now: u64) -> Result<VerifiedEvidence, Error> {
        let Some(policy) = &self.eligibility else {
            return Ok(evidence);
        };
        let _permit = self
            .eligibility_capacity
            .try_acquire()
            .map_err(|_| Error::Unavailable)?;
        let started = std::time::Instant::now();
        let permitted = policy
            .permits(super::lua::Context {
                service: &self.service_id,
                connector: &evidence.connector,
                subject: &evidence.subject.subject,
            })
            .map_err(|_| Error::Unavailable)?;
        if !permitted {
            return Err(Error::Invalid);
        }
        if evidence.expires_at <= now.saturating_add(started.elapsed().as_millis() as u64) {
            return Err(Error::Expired);
        }
        Ok(evidence)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn kubernetes_profile_requires_distinct_prefix_realm_and_reference_material() {
        let mut config: Config = serde_json::from_value(serde_json::json!({"authority_id":"owned","profiles":[{"service_id":"orders","host":"app.example.test","ports":[443],"realm":"example-cluster","api_keys":[{"token_env":"OWNED_KEY","subject":"worker"}],"kubernetes_tokenreview":{"connection":{"api_origin":"https://kubernetes.example.test/","issuer":"https://issuer.example.test","cluster_id":"example-cluster","audience":"orders-workload","timeout_ms":500},"ca_pem_env":"OWNED_CA","reviewer_token_env":"OWNED_REVIEWER","token_prefix":"k8s:"}}]})).unwrap();
        config.validate().unwrap();
        assert!(
            Runtime::compile(&config, &|name| (name == "OWNED_KEY")
                .then(|| "k8s:reserved-credential-at-least-thirty-two".into()))
            .is_err()
        );
        let original = config.clone();
        config.profiles[0].realm = "other-cluster".into();
        assert!(config.validate().is_err());
        config = original.clone();
        config.profiles[0]
            .kubernetes_tokenreview
            .as_mut()
            .unwrap()
            .token_prefix = "".into();
        assert!(config.validate().is_err());
        config = original.clone();
        config.profiles[0].api_relay = Some(super::super::relay::Config {
            url: "https://verifier.example.test/check".into(),
            issuer: "https://partner.example.test".into(),
            timeout_ms: 100,
            allow_private_endpoints: false,
            verifier_key_env: None,
        });
        assert!(config.validate().is_err());
        config.profiles[0].relay_token_prefix = Some("k8s:".into());
        assert!(config.validate().is_err());
        config.profiles[0].relay_token_prefix = Some("partner:".into());
        config.validate().unwrap();
    }
    fn config() -> Config {
        serde_json::from_value(serde_json::json!({"authority_id":"owned","profiles":[{"service_id":"orders","host":"api.example.test","ports":[443],"realm":"partner","api_keys":[{"token_env":"OWNED_API_TOKEN","subject":"scheduler","expires_at":5000}],"networks":["192.0.2.0/24","2001:db8::/32"]}]})).unwrap()
    }
    const KEY: &str = "owned-service-key-at-least-thirty-two-bytes";
    #[tokio::test]
    async fn mixed_routing_never_sends_local_credentials_to_relay() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        let calls = Arc::new(AtomicUsize::new(0));
        let counted = calls.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let router=axum::Router::new().route("/verify",axum::routing::post(move |headers:axum::http::HeaderMap| {
            let counted=counted.clone();
            async move {
                counted.fetch_add(1,Ordering::Relaxed);
                assert_eq!(headers["authorization"],"Bearer external-owned-credential-at-least-sixteen");
                axum::Json(serde_json::json!({"active":true,"subject":"partner-worker","service_id":"orders","expires_at":1100}))
            }
        }));
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let mut cfg = config();
        cfg.profiles[0].api_relay = Some(super::super::relay::Config {
            url: format!("http://{address}/verify"),
            issuer: "partner-authority".into(),
            timeout_ms: 500,
            allow_private_endpoints: true,
            verifier_key_env: None,
        });
        assert!(cfg.validate().is_err());
        cfg.profiles[0].relay_token_prefix = Some("partner:".into());
        let mut ambiguous = cfg.clone();
        ambiguous.profiles[0].api_relay.as_mut().unwrap().issuer = "hopae:owned".into();
        assert!(
            Runtime::compile(&ambiguous, &|_| panic!(
                "ambiguous namespace before secrets"
            ))
            .is_err()
        );
        let runtime = Runtime::compile(&cfg, &|_| Some(KEY.into())).unwrap();
        let ip = "192.0.2.8".parse().unwrap();
        let local = runtime
            .authenticate_async("api.example.test", 443, Some(KEY), ip, 100)
            .await
            .unwrap();
        assert_eq!(local.subject().issuer, "hopae:owned");
        assert_eq!(local.subject().subject, "scheduler");
        for token in [
            "unknown-local-key-at-least-thirty-two-bytes",
            "partner:",
            "partner:short",
        ] {
            assert_eq!(
                runtime
                    .authenticate_async("api.example.test", 443, Some(token), ip, 100)
                    .await
                    .unwrap_err(),
                Error::Invalid
            );
        }
        assert_eq!(calls.load(Ordering::Relaxed), 0);
        let external = runtime
            .authenticate_async(
                "api.example.test",
                443,
                Some("partner:external-owned-credential-at-least-sixteen"),
                ip,
                100,
            )
            .await
            .unwrap();
        assert_eq!(external.subject().issuer, "partner-authority");
        assert_eq!(external.subject().realm, "partner");
        assert_eq!(external.subject().subject, "partner-worker");
        assert_eq!(external.subject().kind, PrincipalKind::Service);
        assert_eq!(external.service(), Some("orders"));
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        assert_eq!(
            runtime
                .authenticate_async("api.example.test", 443, Some(KEY), ip, 5000)
                .await
                .unwrap_err(),
            Error::Expired
        );
        assert_eq!(
            calls.load(Ordering::Relaxed),
            1,
            "expired local credential leaked to relay"
        );
        assert!(
            Runtime::compile(&cfg, &|_| Some(
                "partner:local-key-at-least-thirty-two-bytes".into()
            ))
            .is_err()
        );
        cfg.profiles[0].api_keys.clear();
        let retired = Runtime::compile(&cfg, &|_| None).unwrap();
        assert_eq!(
            retired
                .authenticate_async("api.example.test", 443, Some(KEY), ip, 100)
                .await
                .unwrap_err(),
            Error::Invalid
        );
        assert_eq!(
            calls.load(Ordering::Relaxed),
            1,
            "retired local credential leaked to relay"
        );
        server.abort();
    }
    #[tokio::test]
    async fn service_lua_filters_only_verified_identity_and_preserves_scope() {
        let ip = "192.0.2.8".parse().unwrap();
        let mut cfg = config();
        cfg.profiles[0].eligibility_lua =
            Some("return context.subject == 'scheduler' and context.service == 'orders'".into());
        let runtime = Runtime::compile(&cfg, &|_| Some(KEY.into())).unwrap();
        for evidence in [
            runtime
                .authenticate("api.example.test", 443, Some(KEY), ip, 1)
                .unwrap(),
            runtime
                .authenticate_async("api.example.test", 443, Some(KEY), ip, 1)
                .await
                .unwrap(),
        ] {
            assert_eq!(evidence.subject().kind, PrincipalKind::Service);
            assert_eq!(evidence.subject().issuer, "hopae:owned");
            assert_eq!(evidence.subject().realm, "partner");
            assert_eq!(evidence.subject().subject, "scheduler");
            assert_eq!(evidence.service(), Some("orders"));
            assert_eq!(evidence.expires_at, 1001);
        }
        for (script, expected) in [
            ("return false", Error::Invalid),
            ("while true do end", Error::Unavailable),
            ("return 'true'", Error::Unavailable),
        ] {
            cfg.profiles[0].eligibility_lua = Some(script.into());
            let runtime = Runtime::compile(&cfg, &|_| Some(KEY.into())).unwrap();
            assert_eq!(
                runtime
                    .authenticate("api.example.test", 443, Some(KEY), ip, 1)
                    .unwrap_err(),
                expected
            );
            // Invalid credentials and network constraints are evaluated before Lua.
            assert_eq!(
                runtime
                    .authenticate(
                        "api.example.test",
                        443,
                        Some("invalid-key-at-least-thirty-two-bytes"),
                        ip,
                        1
                    )
                    .unwrap_err(),
                Error::Invalid
            );
            assert_eq!(
                runtime
                    .authenticate(
                        "api.example.test",
                        443,
                        Some(KEY),
                        "203.0.113.1".parse().unwrap(),
                        1
                    )
                    .unwrap_err(),
                Error::NetworkDenied
            );
        }
    }
    #[test]
    fn service_lua_capacity_expiry_and_startup_fail_closed() {
        let mut cfg = config();
        cfg.profiles[0].eligibility_lua = Some("return true".into());
        let runtime = Runtime::compile(&cfg, &|_| Some(KEY.into())).unwrap();
        let profile = &runtime.profiles["api.example.test"][&443];
        let ip = "192.0.2.8".parse().unwrap();
        let evidence = runtime
            .authenticate("api.example.test", 443, Some(KEY), ip, 1)
            .unwrap();
        assert_eq!(
            profile.restrict(evidence, 1001).unwrap_err(),
            Error::Expired
        );
        let _held = profile.eligibility_capacity.try_acquire_many(64).unwrap();
        assert_eq!(
            runtime
                .authenticate("api.example.test", 443, Some(KEY), ip, 1)
                .unwrap_err(),
            Error::Unavailable
        );
        cfg.profiles[0].eligibility_lua = Some("return (".into());
        assert!(Runtime::compile(&cfg, &|_| panic!("invalid syntax before secrets")).is_err());
        assert!(
            !serde_json::to_string(&config())
                .unwrap()
                .contains("eligibility_lua")
        );
    }
    #[tokio::test]
    async fn unchanged_verifier_keeps_open_circuit_across_publication() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        let calls = Arc::new(AtomicUsize::new(0));
        let counted = calls.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let router = axum::Router::new().route(
            "/verify",
            axum::routing::post(move || {
                let counted = counted.clone();
                async move {
                    counted.fetch_add(1, Ordering::Relaxed);
                    axum::http::StatusCode::SERVICE_UNAVAILABLE
                }
            }),
        );
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let mut config:Config=serde_json::from_value(serde_json::json!({"authority_id":"owned","profiles":[{"service_id":"orders","host":"app.example.test","ports":[443],"realm":"owned","api_relay":{"url":format!("http://{address}/verify"),"issuer":"owned","allow_private_endpoints":true}}]})).unwrap();
        let first = Runtime::compile(&config, &|_| None).unwrap();
        for _ in 0..3 {
            assert_eq!(
                first
                    .authenticate_async(
                        "app.example.test",
                        443,
                        Some(KEY),
                        "127.0.0.1".parse().unwrap(),
                        100
                    )
                    .await
                    .unwrap_err(),
                Error::Unavailable
            );
        }
        config.profiles[0].networks = vec!["127.0.0.1/32".into()];
        let next = Runtime::compile_resuming(&config, &|_| None, Some(&first)).unwrap();
        assert_eq!(
            next.authenticate_async(
                "app.example.test",
                443,
                Some(KEY),
                "127.0.0.1".parse().unwrap(),
                100
            )
            .await
            .unwrap_err(),
            Error::Unavailable
        );
        assert_eq!(
            calls.load(Ordering::Relaxed),
            3,
            "publication reset an open verifier circuit"
        );
        server.abort();
        let _ = server.await;
    }
    #[test]
    fn scope_expiry_network_and_namespace_are_authenticated() {
        let runtime = Runtime::compile(&config(), &|_| Some(KEY.into())).unwrap();
        let v4 = "::ffff:192.0.2.8".parse().unwrap();
        let evidence = runtime
            .authenticate("api.example.test", 443, Some(KEY), v4, 1)
            .unwrap();
        assert_eq!(evidence.subject().kind, PrincipalKind::Service);
        assert_eq!(evidence.subject().realm, "partner");
        assert_eq!(evidence.expires_at, 1001);
        assert!(
            runtime
                .authenticate(
                    "api.example.test",
                    443,
                    Some(KEY),
                    "2001:db8::8".parse().unwrap(),
                    1
                )
                .is_ok()
        );
        assert_eq!(
            runtime
                .authenticate("other.example.test", 443, Some(KEY), v4, 1)
                .unwrap_err(),
            Error::Invalid
        );
        assert_eq!(
            runtime
                .authenticate("api.example.test", 8443, Some(KEY), v4, 1)
                .unwrap_err(),
            Error::Invalid
        );
        assert_eq!(
            runtime
                .authenticate("api.example.test", 443, None, v4, 1)
                .unwrap_err(),
            Error::Missing
        );

        assert_eq!(
            runtime
                .authenticate(
                    "api.example.test",
                    443,
                    Some(KEY),
                    "198.51.100.8".parse().unwrap(),
                    1
                )
                .unwrap_err(),
            Error::NetworkDenied
        );
        assert_eq!(
            runtime
                .authenticate("api.example.test", 443, Some(KEY), v4, 5000)
                .unwrap_err(),
            Error::Expired
        );
        assert_eq!(
            runtime
                .authenticate("api.example.test", 443, Some(KEY), v4, 1)
                .unwrap_err(),
            Error::Expired,
            "observed expiration cannot be reversed by clock rollback"
        );
    }
    #[test]
    fn missing_duplicate_credentials_and_scope_confusion_fail_compilation() {
        assert!(Runtime::compile(&config(), &|_| None).is_err());
        let mut cfg = config();
        cfg.profiles.push(cfg.profiles[0].clone());
        assert!(cfg.validate().is_err());
        let mut cfg = config();
        let duplicate = cfg.profiles[0].api_keys[0].clone();
        cfg.profiles[0].api_keys.push(duplicate);
        assert!(Runtime::compile(&cfg, &|_| Some(KEY.into())).is_err());
    }
}
