//! Read-only administrative view of the compiled service authentication
//! runtime: what the subject directory and the authentication explain API
//! may disclose. No credential material, digest, environment reference,
//! endpoint or Lua source leaves this module; only the identifiers the
//! profile already publishes (service, realm, configured subject name) and
//! the evaluation of the same network predicate the live path uses.
use super::{Prepared, Runtime};
use crate::auth_gateway::{PrincipalKind, stable_subject};
use std::net::IpAddr;

/// A statically configured service principal (an API-key subject).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServicePrincipal {
    /// `s_` + 48 lowercase hex: the identifier every consumer sees.
    pub subject_ref: String,
    pub kind: PrincipalKind,
    /// The operator-chosen subject name of the credential (`api_keys[].subject`).
    pub name: String,
    pub service_id: String,
    pub realm: String,
    /// Absolute Unix milliseconds, when the credential is time-limited.
    pub expires_at_ms: Option<u64>,
}

/// The facts of the profile serving one host and port.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProfileFacts {
    pub service_id: String,
    pub realm: String,
    /// Connector families configured on the profile, in a fixed order.
    pub connectors: Vec<&'static str>,
    pub api_keys: usize,
    pub composed: bool,
    pub session_fallback: bool,
    pub networks_restricted: bool,
    pub eligibility_script: bool,
    /// The live network predicate for the asked address (`None` when none was given).
    pub client_ip_permitted: Option<bool>,
}

/// What the live API-key path would answer for a configured principal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyVerdict {
    /// No profile serves the host and port.
    NoProfile,
    /// The profile accepts only composed credentials (remote slots).
    Composition,
    /// The principal is not an API-key subject of this profile.
    NotConfigured,
    Expired,
    NetworkDenied,
    /// The profile's eligibility script refused the principal.
    Ineligible,
    /// The eligibility script could not run now (capacity, error).
    Unavailable,
    /// Authenticated; `network_evaluated` is false when no address was given.
    Allowed {
        network_evaluated: bool,
    },
}

fn principals_of(p: &Prepared) -> Vec<ServicePrincipal> {
    p.keys
        .values()
        .map(|credential| ServicePrincipal {
            subject_ref: stable_subject(&credential.subject),
            kind: credential.subject.kind,
            name: credential.subject.subject.clone(),
            service_id: p.service_id.clone(),
            realm: p.realm.clone(),
            expires_at_ms: credential.expires_at,
        })
        .collect()
}

impl Runtime {
    /// Every API-key principal of every profile, deduplicated by reference and
    /// sorted by it. Relay and Kubernetes subjects are minted by the remote
    /// verifier at authentication time and cannot be enumerated.
    pub(crate) fn admin_service_principals(&self) -> Vec<ServicePrincipal> {
        let mut seen = std::collections::HashSet::new();
        let mut rows = Vec::new();
        for ports in self.profiles.values() {
            for profile in ports.values() {
                if !seen.insert(std::sync::Arc::as_ptr(profile)) {
                    continue;
                }
                rows.extend(principals_of(profile));
            }
        }
        rows.sort_by(|a, b| a.subject_ref.cmp(&b.subject_ref));
        rows.dedup_by(|a, b| a.subject_ref == b.subject_ref);
        rows
    }

    /// The profile serving `host:port` (the lookup the live path makes), with
    /// the live network predicate applied to `ip`.
    pub(crate) fn admin_profile(
        &self,
        host: &str,
        port: u16,
        ip: Option<IpAddr>,
    ) -> Option<(ProfileFacts, Vec<ServicePrincipal>)> {
        let p = self.profiles.get(host)?.get(&port)?;
        let mut connectors = Vec::new();
        if p.composition.is_some() {
            connectors.push("composition");
        }
        if !p.keys.is_empty() {
            connectors.push("api_key");
        }
        if p.relay.is_some() {
            connectors.push("api_relay");
        }
        if p.kubernetes.is_some() {
            connectors.push("kubernetes_tokenreview");
        }
        if p.workload.is_some() {
            connectors.push("kubernetes_workload");
        }
        Some((
            ProfileFacts {
                service_id: p.service_id.clone(),
                realm: p.realm.clone(),
                connectors,
                api_keys: p.keys.len(),
                composed: p.composition.is_some(),
                session_fallback: p.session_fallback,
                networks_restricted: !p.networks.unrestricted,
                eligibility_script: p.eligibility.is_some(),
                client_ip_permitted: ip.map(|ip| p.networks.permits(ip)),
            },
            principals_of(p),
        ))
    }
}

/// What the live workload path would answer for a hypothetical
/// ServiceAccount caller holding a valid token (the token-dependent checks —
/// signature, audience, lifetime, bound objects — cannot be simulated).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WorkloadVerdict {
    NoProfile,
    /// The profile has no Kubernetes workload connector.
    NotConfigured,
    /// Not a canonical SPIFFE ID of this trust domain or a
    /// `system:serviceaccount:<ns>:<sa>` name.
    SubjectInvalid,
    NetworkDenied,
    NamespaceNotAllowed,
    ServiceAccountNotAllowed,
    KeysUnavailable,
    RevocationStale,
    ServiceAccountAbsent,
    LegacyWindowExpired,
    Allowed {
        verification: &'static str,
        network_evaluated: bool,
        revocation_evaluated: bool,
        spiffe_id: Option<String>,
        /// `wk2:` when the ServiceAccount UID is known (revocation index).
        principal: Option<String>,
        subject_ref: Option<String>,
    },
}

/// `(namespace, service account)` of an explain subject.
fn workload_name<'a>(trust_domain: Option<&str>, subject: &'a str) -> Option<(&'a str, &'a str)> {
    if let Some(rest) = subject.strip_prefix("system:serviceaccount:") {
        let (ns, sa) = rest.split_once(':')?;
        return (crate::auth_gateway::workload::identity::namespace(ns)
            && crate::auth_gateway::workload::identity::object_name(sa))
        .then_some((ns, sa));
    }
    crate::auth_gateway::workload::identity::parse_spiffe(trust_domain?, subject)
}

/// Whether an explain subject names a Kubernetes workload.
pub(crate) fn is_workload_subject(subject: &str) -> bool {
    subject.starts_with("spiffe://") || subject.starts_with("system:serviceaccount:")
}

impl Runtime {
    /// The live workload path for a hypothetical ServiceAccount caller: the
    /// same profile lookup, network predicate, namespace/ServiceAccount
    /// scope, key-source freshness, revocation index and migration window,
    /// in the live order. Nothing is fetched and no state changes.
    pub(crate) fn admin_explain_workload(
        &self,
        host: &str,
        port: u16,
        subject: &str,
        ip: Option<IpAddr>,
        now_ms: u64,
    ) -> WorkloadVerdict {
        use crate::auth_gateway::workload::{identity, verify::ExplainVerdict};
        let Some(p) = self.profiles.get(host).and_then(|ports| ports.get(&port)) else {
            return WorkloadVerdict::NoProfile;
        };
        let network_evaluated = ip.is_some() || p.networks.unrestricted;
        if let Some((workload, _)) = &p.workload {
            let profile = workload.profile();
            let Some((ns, sa)) = workload_name(Some(&profile.trust_domain), subject) else {
                return WorkloadVerdict::SubjectInvalid;
            };
            if let Some(ip) = ip
                && !p.networks.permits(ip)
            {
                return WorkloadVerdict::NetworkDenied;
            }
            return match workload.explain(ns, sa, now_ms) {
                ExplainVerdict::NamespaceNotAllowed => WorkloadVerdict::NamespaceNotAllowed,
                ExplainVerdict::ServiceAccountNotAllowed => {
                    WorkloadVerdict::ServiceAccountNotAllowed
                }
                ExplainVerdict::KeysUnavailable => WorkloadVerdict::KeysUnavailable,
                ExplainVerdict::RevocationStale => WorkloadVerdict::RevocationStale,
                ExplainVerdict::ServiceAccountAbsent => WorkloadVerdict::ServiceAccountAbsent,
                ExplainVerdict::LegacyWindowExpired => WorkloadVerdict::LegacyWindowExpired,
                ExplainVerdict::Allowed {
                    revocation_evaluated,
                } => {
                    let principal = workload.current_principal(ns, sa);
                    WorkloadVerdict::Allowed {
                        verification: "offline_jwks",
                        network_evaluated,
                        revocation_evaluated,
                        spiffe_id: Some(identity::spiffe_id(&profile.trust_domain, ns, sa)),
                        subject_ref: principal.as_ref().map(|principal| {
                            stable_subject(&identity::principal_subject(
                                &profile.issuer,
                                &profile.cluster_id,
                                principal,
                            ))
                        }),
                        principal,
                    }
                }
            };
        }
        if let Some((kubernetes, _)) = &p.kubernetes {
            let Some((ns, sa)) = workload_name(kubernetes.trust_domain(), subject) else {
                return WorkloadVerdict::SubjectInvalid;
            };
            if let Some(ip) = ip
                && !p.networks.permits(ip)
            {
                return WorkloadVerdict::NetworkDenied;
            }
            if !kubernetes.config().namespaces.iter().any(|n| n == ns) {
                return WorkloadVerdict::NamespaceNotAllowed;
            }
            return WorkloadVerdict::Allowed {
                verification: "tokenreview",
                network_evaluated,
                revocation_evaluated: false,
                spiffe_id: kubernetes
                    .trust_domain()
                    .map(|td| identity::spiffe_id(td, ns, sa)),
                principal: None,
                subject_ref: None,
            };
        }
        WorkloadVerdict::NotConfigured
    }

    /// The live API-key path (`authenticate`) for the credential of
    /// `subject_ref`, without the credential: the same profile lookup, expiry
    /// rule, network predicate and eligibility script, in the same order. The
    /// observed-time floor is not advanced.
    pub(crate) fn admin_explain_key(
        &self,
        host: &str,
        port: u16,
        subject_ref: &str,
        ip: Option<IpAddr>,
        now_ms: u64,
    ) -> KeyVerdict {
        let Some(p) = self.profiles.get(host).and_then(|ports| ports.get(&port)) else {
            return KeyVerdict::NoProfile;
        };
        if p.composition.is_some() {
            return KeyVerdict::Composition;
        }
        let Some(key) = p
            .keys
            .values()
            .find(|k| stable_subject(&k.subject) == subject_ref)
        else {
            return KeyVerdict::NotConfigured;
        };
        if key.expires_at.is_some_and(|expiry| expiry <= now_ms) {
            return KeyVerdict::Expired;
        }
        if let Some(ip) = ip
            && !p.networks.permits(ip)
        {
            return KeyVerdict::NetworkDenied;
        }
        let evidence = super::super::VerifiedEvidence {
            subject: key.subject.clone(),
            service: Some(p.service_id.clone()),
            connector: format!("api-key:{}", p.service_id),
            workload: None,
            expires_at: now_ms
                .saturating_add(1000)
                .min(key.expires_at.unwrap_or(u64::MAX)),
        };
        match p.restrict(evidence, now_ms) {
            Ok(_) => KeyVerdict::Allowed {
                network_evaluated: ip.is_some() || p.networks.unrestricted,
            },
            Err(super::Error::Invalid) => KeyVerdict::Ineligible,
            Err(_) => KeyVerdict::Unavailable,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::{Config, Runtime};

    fn runtime() -> Runtime {
        let config: Config = serde_json::from_value(serde_json::json!({
            "authority_id": "owned",
            "profiles": [{
                "service_id": "orders", "host": "app.example.test", "ports": [443, 8443],
                "realm": "services", "networks": ["192.0.2.0/24"],
                "api_keys": [
                    {"token_env": "OWNED_KEY_A", "subject": "worker"},
                    {"token_env": "OWNED_KEY_B", "subject": "batch", "expires_at": 4_000_000_000_000u64}
                ]
            }]
        }))
        .unwrap();
        Runtime::compile(&config, &|name| {
            Some(format!("{name}-credential-material-of-sufficient-length"))
        })
        .unwrap()
    }

    #[test]
    fn principals_are_enumerated_once_without_credential_material() {
        let r = runtime();
        let rows = r.admin_service_principals();
        assert_eq!(rows.len(), 2);
        for row in &rows {
            assert!(row.subject_ref.starts_with("s_") && row.subject_ref.len() == 50);
            assert_eq!(row.service_id, "orders");
            assert_eq!(row.realm, "services");
            assert!(!format!("{row:?}").contains("credential-material"));
        }
        let batch = rows.iter().find(|r| r.name == "batch").unwrap();
        assert_eq!(batch.expires_at_ms, Some(4_000_000_000_000));
        assert_eq!(
            batch.subject_ref,
            crate::auth_gateway::stable_subject(&crate::auth_gateway::Subject {
                issuer: "hopae:owned".into(),
                realm: "services".into(),
                subject: "batch".into(),
                kind: crate::auth_gateway::PrincipalKind::Service,
            })
        );
    }

    #[test]
    fn profile_facts_use_the_live_network_predicate() {
        let r = runtime();
        let (facts, principals) = r
            .admin_profile("app.example.test", 443, Some("192.0.2.7".parse().unwrap()))
            .unwrap();
        assert_eq!(facts.connectors, vec!["api_key"]);
        assert!(facts.networks_restricted);
        assert_eq!(facts.client_ip_permitted, Some(true));
        assert_eq!(principals.len(), 2);
        let (outside, _) = r
            .admin_profile(
                "app.example.test",
                8443,
                Some("198.51.100.1".parse().unwrap()),
            )
            .unwrap();
        assert_eq!(outside.client_ip_permitted, Some(false));
        assert!(r.admin_profile("app.example.test", 80, None).is_none());
        assert!(r.admin_profile("other.example.test", 443, None).is_none());
    }

    #[test]
    fn key_verdicts_follow_the_live_order() {
        use super::KeyVerdict;
        let r = runtime();
        let rows = r.admin_service_principals();
        let worker = rows.iter().find(|p| p.name == "worker").unwrap();
        let batch = rows.iter().find(|p| p.name == "batch").unwrap();
        let inside = Some("192.0.2.7".parse().unwrap());
        let outside = Some("198.51.100.1".parse().unwrap());
        let host = "app.example.test";
        assert_eq!(
            r.admin_explain_key(host, 443, &worker.subject_ref, inside, 1),
            KeyVerdict::Allowed {
                network_evaluated: true
            }
        );
        assert_eq!(
            r.admin_explain_key(host, 443, &worker.subject_ref, None, 1),
            KeyVerdict::Allowed {
                network_evaluated: false
            }
        );
        assert_eq!(
            r.admin_explain_key(host, 443, &worker.subject_ref, outside, 1),
            KeyVerdict::NetworkDenied
        );
        // Expiry is checked before the network, as the live path does.
        assert_eq!(
            r.admin_explain_key(host, 443, &batch.subject_ref, outside, 4_000_000_000_000),
            KeyVerdict::Expired
        );
        assert_eq!(
            r.admin_explain_key(host, 443, &format!("s_{}", "0".repeat(48)), inside, 1),
            KeyVerdict::NotConfigured
        );
        assert_eq!(
            r.admin_explain_key(host, 80, &worker.subject_ref, inside, 1),
            KeyVerdict::NoProfile
        );
    }
}
