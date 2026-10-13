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
    #[serde(default)]
    pub networks: Vec<String>,
    #[serde(default)]
    pub session_fallback: bool,
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
            ensure!(
                identifier(&p.service_id) && identifier(&p.realm),
                "invalid authentication service/realm"
            );
            let host = crate::policy::types::Host::parse(&p.host)?;
            ensure!(
                (1..=16).contains(&p.ports.len())
                    && p.api_keys.len() <= 256
                    && ((p.api_relay.is_some() && p.api_keys.is_empty())
                        || (p.api_relay.is_none() && !p.api_keys.is_empty()))
                    && p.networks.len() <= 256,
                "authentication profile exceeds bounds"
            );
            if let Some(relay) = &p.api_relay {
                relay.validate()?;
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
    relay: Option<super::relay::Connector>,
}
pub struct Runtime {
    profiles: HashMap<String, HashMap<u16, std::sync::Arc<Prepared>>>,
    observed_time: std::sync::atomic::AtomicU64,
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
            let prepared = std::sync::Arc::new(Prepared {
                service_id: p.service_id.clone(),
                realm: p.realm.clone(),
                keys,
                networks: Networks::compile(&p.networks, &mut budget)?,
                session_fallback: p.session_fallback,
                relay: p
                    .api_relay
                    .as_ref()
                    .map(|r| super::relay::Connector::compile(r, env))
                    .transpose()?,
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
            observed_time: std::sync::atomic::AtomicU64::new(0),
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
        if let Some(relay) = &profile.relay {
            if !profile.networks.permits(ip) {
                return Err(Error::NetworkDenied);
            }
            let token = token.ok_or(Error::Missing)?;
            self.observed_time
                .fetch_max(now, std::sync::atomic::Ordering::AcqRel);
            let now = self
                .observed_time
                .load(std::sync::atomic::Ordering::Acquire);
            relay
                .authenticate(&profile.service_id, &profile.realm, token, ip, now)
                .await
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
        Ok(VerifiedEvidence {
            subject: key.subject.clone(),
            service: Some(p.service_id.clone()),
            connector: format!("api-key:{}", p.service_id),
            expires_at: now
                .saturating_add(1000)
                .min(key.expires_at.unwrap_or(u64::MAX)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config() -> Config {
        serde_json::from_value(serde_json::json!({"authority_id":"owned","profiles":[{"service_id":"orders","host":"api.example.test","ports":[443],"realm":"partner","api_keys":[{"token_env":"OWNED_API_TOKEN","subject":"scheduler","expires_at":5000}],"networks":["192.0.2.0/24","2001:db8::/32"]}]})).unwrap()
    }
    const KEY: &str = "owned-service-key-at-least-thirty-two-bytes";
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
