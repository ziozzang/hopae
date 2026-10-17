//! Kubernetes workload identity (Hangang ADR 0021/0022).
//!
//! The principal of a Kubernetes workload is its ServiceAccount, not its Pod:
//!
//! * `wk2:<64 hex>` = SHA-256 over a domain separator and the length-prefixed
//!   issuer, cluster ID, namespace, ServiceAccount name and ServiceAccount UID.
//!   Every Pod of the ServiceAccount (every replica, every rollout) has the
//!   same principal. Re-creating a ServiceAccount with the same name gives it
//!   a new UID and therefore a **new** principal: grants pinned to the old
//!   principal do not transfer (documented re-creation policy).
//! * The canonical workload *name* shared with Hangang's workload mTLS is the
//!   SPIFFE ID `spiffe://<trust-domain>/ns/<namespace>/sa/<serviceaccount>`.
//!   It carries no UID: it names the ServiceAccount, the `wk2:` principal pins
//!   one incarnation of it.
//! * The wire subject (the forwarded user header) stays the existing stable
//!   `s_<48 hex>` encoding, applied to the `wk2:` principal, so the Hangang and
//!   Pumgye parsers are unchanged.
//!
//! Pod name/UID, the bound Secret and the Node are audit attributes only.
//! The pre-ADR-0022 Pod-bound subject (`w_` over namespace, ServiceAccount
//! name/UID, Pod name/UID) is still derivable for the migration window.
use super::super::{PrincipalKind, Subject, stable_subject};
use sha2::{Digest, Sha256};
use std::fmt::Write as _;

const PRINCIPAL_DOMAIN: &[u8] = b"hopae:kubernetes:workload-principal:v2\0";
const LEGACY_POD_DOMAIN: &[u8] = b"hopae:kubernetes:pod-subject:v1\0";

/// Which subject a connector publishes as the authenticated principal.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SubjectMode {
    /// ServiceAccount-scoped `wk2:` principal (default, ADR 0022).
    #[default]
    ServiceAccount,
    /// Deprecated Pod-bound subject; only inside an explicit compatibility window.
    LegacyPod,
}

/// A name/UID pair of a bound Kubernetes object (audit attribute).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct BoundRef {
    pub name: String,
    pub uid: String,
}

/// Facts a verifier established about one workload credential.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Workload {
    pub issuer: String,
    pub cluster_id: String,
    pub namespace: String,
    pub service_account: String,
    pub service_account_uid: String,
    pub pod: Option<BoundRef>,
    pub secret: Option<BoundRef>,
    pub node: Option<String>,
}

/// What the evidence of a workload caller carries beyond its subject. Never a
/// credential; identifiers only.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct WorkloadAttributes {
    /// `wk2:<64 hex>`.
    pub principal: String,
    /// `s_<48 hex>` of the ServiceAccount principal (the wire subject).
    pub subject_ref: String,
    /// `spiffe://<trust-domain>/ns/<ns>/sa/<sa>` when a trust domain is configured.
    pub spiffe_id: Option<String>,
    pub cluster_id: String,
    pub namespace: String,
    pub service_account: String,
    pub service_account_uid: String,
    /// Audit only: never part of the principal.
    pub pod: Option<BoundRef>,
    /// Audit only.
    pub secret: Option<BoundRef>,
    /// Audit only.
    pub node: Option<String>,
    /// `s_` of the deprecated Pod-bound subject (only for Pod-bound credentials).
    pub legacy_subject_ref: Option<String>,
    /// `offline_jwks` or `tokenreview`.
    pub verification: &'static str,
    /// The subject mode that produced the published subject.
    pub mode: SubjectMode,
}

fn length_prefixed(digest: &mut Sha256, values: &[&str]) {
    for value in values {
        digest.update((value.len() as u32).to_be_bytes());
        digest.update(value.as_bytes());
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(out, "{b:02x}").expect("string writer");
    }
    out
}

/// `wk2:<64 hex>` of one ServiceAccount incarnation.
pub fn principal_ref(
    issuer: &str,
    cluster_id: &str,
    namespace: &str,
    service_account: &str,
    service_account_uid: &str,
) -> String {
    let mut digest = Sha256::new();
    digest.update(PRINCIPAL_DOMAIN);
    length_prefixed(
        &mut digest,
        &[
            issuer,
            cluster_id,
            namespace,
            service_account,
            service_account_uid,
        ],
    );
    format!("wk2:{}", hex(&digest.finalize()))
}

/// Whether `value` is a well-formed `wk2:` principal reference.
pub fn is_principal_ref(value: &str) -> bool {
    value.len() == 68
        && value.starts_with("wk2:")
        && value.as_bytes()[4..]
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
}

/// The internal subject whose stable encoding is the wire subject.
pub fn principal_subject(issuer: &str, cluster_id: &str, principal: &str) -> Subject {
    Subject {
        issuer: issuer.to_owned(),
        realm: cluster_id.to_owned(),
        subject: principal.to_owned(),
        kind: PrincipalKind::Workload,
    }
}

/// The deprecated Pod-bound subject (pre-ADR-0022 `kubernetes-tokenreview`).
fn legacy_subject(w: &Workload, pod: &BoundRef) -> Subject {
    let mut digest = Sha256::new();
    digest.update(LEGACY_POD_DOMAIN);
    length_prefixed(
        &mut digest,
        &[
            &w.namespace,
            &w.service_account,
            &w.service_account_uid,
            &pod.name,
            &pod.uid,
        ],
    );
    Subject {
        issuer: w.issuer.clone(),
        realm: w.cluster_id.clone(),
        subject: format!("w_{}", hex(&digest.finalize())),
        kind: PrincipalKind::Workload,
    }
}

/// A SPIFFE trust domain: lowercase letters, digits, `.`, `-`, `_`; at most 255.
pub fn trust_domain(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
        && !value.starts_with('.')
        && !value.ends_with('.')
}

/// A Kubernetes namespace (DNS-1123 label).
pub fn namespace(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 63
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && s.as_bytes()[0].is_ascii_alphanumeric()
        && s.as_bytes()[s.len() - 1].is_ascii_alphanumeric()
}

/// A Kubernetes object name (DNS-1123 subdomain), as ServiceAccounts, Pods,
/// Secrets and Nodes use.
pub fn object_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.split('.').all(|label| {
            !label.is_empty()
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                && label.as_bytes()[0].is_ascii_alphanumeric()
                && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
        })
}

/// An object UID as the API server issues it (an RFC 4122 string); other
/// short opaque identifiers are tolerated for test clusters.
pub fn uid(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._".contains(&b))
}

/// `spiffe://<td>/ns/<ns>/sa/<sa>`.
pub fn spiffe_id(trust_domain: &str, namespace: &str, service_account: &str) -> String {
    format!("spiffe://{trust_domain}/ns/{namespace}/sa/{service_account}")
}

/// The namespace and ServiceAccount of a canonical Kubernetes SPIFFE ID in
/// `trust_domain`. Anything else (another trust domain, extra segments,
/// percent escapes, ports, queries) is refused.
pub fn parse_spiffe<'a>(trust_domain: &str, value: &'a str) -> Option<(&'a str, &'a str)> {
    let rest = value.strip_prefix("spiffe://")?;
    let (td, path) = rest.split_once('/')?;
    if td != trust_domain || value.len() > 2048 {
        return None;
    }
    let mut parts = path.split('/');
    let (Some("ns"), Some(ns), Some("sa"), Some(sa), None) = (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    ) else {
        return None;
    };
    (namespace(ns) && object_name(sa)).then_some((ns, sa))
}

impl Workload {
    pub fn principal(&self) -> String {
        principal_ref(
            &self.issuer,
            &self.cluster_id,
            &self.namespace,
            &self.service_account,
            &self.service_account_uid,
        )
    }

    /// The subject to publish and the attributes the evidence carries.
    pub fn resolve(
        &self,
        trust_domain: Option<&str>,
        mode: SubjectMode,
        verification: &'static str,
    ) -> Option<(Subject, WorkloadAttributes)> {
        let principal = self.principal();
        let current = principal_subject(&self.issuer, &self.cluster_id, &principal);
        let legacy = self.pod.as_ref().map(|pod| legacy_subject(self, pod));
        let subject = match mode {
            SubjectMode::ServiceAccount => current.clone(),
            // A credential without a Pod binding has no legacy subject.
            SubjectMode::LegacyPod => legacy.clone()?,
        };
        let attributes = WorkloadAttributes {
            subject_ref: stable_subject(&current),
            principal,
            spiffe_id: trust_domain.map(|td| spiffe_id(td, &self.namespace, &self.service_account)),
            cluster_id: self.cluster_id.clone(),
            namespace: self.namespace.clone(),
            service_account: self.service_account.clone(),
            service_account_uid: self.service_account_uid.clone(),
            pod: self.pod.clone(),
            secret: self.secret.clone(),
            node: self.node.clone(),
            legacy_subject_ref: legacy.as_ref().map(stable_subject),
            verification,
            mode,
        };
        Some((subject, attributes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn workload(pod: &str, pod_uid: &str) -> Workload {
        Workload {
            issuer: "https://issuer.example.test".into(),
            cluster_id: "example-cluster".into(),
            namespace: "blue".into(),
            service_account: "worker".into(),
            service_account_uid: "sa-1".into(),
            pod: Some(BoundRef {
                name: pod.into(),
                uid: pod_uid.into(),
            }),
            secret: None,
            node: None,
        }
    }

    #[test]
    fn principal_is_stable_across_pods_and_changes_with_service_account_uid() {
        let a = workload("worker-pod", "pod-1");
        let b = workload("worker-7d9f-x2", "pod-2");
        let (sa, attrs) = a
            .resolve(
                Some("cluster.example.test"),
                SubjectMode::ServiceAccount,
                "offline_jwks",
            )
            .unwrap();
        let (sb, _) = b
            .resolve(
                Some("cluster.example.test"),
                SubjectMode::ServiceAccount,
                "offline_jwks",
            )
            .unwrap();
        assert_eq!(sa, sb, "a rollout keeps the principal");
        assert!(is_principal_ref(&attrs.principal));
        assert_eq!(sa.subject, attrs.principal);
        assert_eq!(attrs.subject_ref, stable_subject(&sa));
        assert_eq!(
            attrs.spiffe_id.as_deref(),
            Some("spiffe://cluster.example.test/ns/blue/sa/worker")
        );
        // Shared ADR 0021 contract vector for `wk2:`.
        assert_eq!(
            attrs.principal,
            principal_ref(
                "https://issuer.example.test",
                "example-cluster",
                "blue",
                "worker",
                "sa-1"
            )
        );
        let mut recreated = a.clone();
        recreated.service_account_uid = "sa-2".into();
        assert_ne!(recreated.principal(), attrs.principal);
        let mut other_cluster = a.clone();
        other_cluster.cluster_id = "other".into();
        assert_ne!(other_cluster.principal(), attrs.principal);
        // Length prefixes keep field boundaries unambiguous.
        let mut shifted = a.clone();
        shifted.namespace = "blu".into();
        shifted.service_account = "eworker".into();
        assert_ne!(shifted.principal(), attrs.principal);
    }

    #[test]
    fn legacy_pod_subject_keeps_the_pre_adr_0022_contract_vector() {
        let (legacy, attrs) = workload("worker-pod", "pod-1")
            .resolve(None, SubjectMode::LegacyPod, "tokenreview")
            .unwrap();
        // Shared Pumgye workload-association contract vector (pre-ADR-0022).
        assert_eq!(
            stable_subject(&legacy),
            "s_529be5b595ab327853eabe2d1adf52256e262af036510607"
        );
        assert_eq!(
            attrs.legacy_subject_ref.as_deref(),
            Some("s_529be5b595ab327853eabe2d1adf52256e262af036510607")
        );
        assert_eq!(attrs.spiffe_id, None);
        let mut unbound = workload("x", "y");
        unbound.pod = None;
        assert!(
            unbound
                .resolve(None, SubjectMode::LegacyPod, "tokenreview")
                .is_none()
        );
        assert!(
            unbound
                .resolve(None, SubjectMode::ServiceAccount, "tokenreview")
                .unwrap()
                .1
                .legacy_subject_ref
                .is_none()
        );
    }

    #[test]
    fn spiffe_ids_are_parsed_only_in_canonical_form() {
        let td = "cluster.example.test";
        assert_eq!(
            parse_spiffe(td, "spiffe://cluster.example.test/ns/blue/sa/worker"),
            Some(("blue", "worker"))
        );
        for bad in [
            "spiffe://other.example.test/ns/blue/sa/worker",
            "spiffe://cluster.example.test/ns/blue/sa/worker/",
            "spiffe://cluster.example.test/ns/blue/sa/worker/x",
            "spiffe://cluster.example.test/ns/Blue/sa/worker",
            "spiffe://cluster.example.test/ns/blue/sa/wor%6Ber",
            "spiffe://cluster.example.test:443/ns/blue/sa/worker",
            "spiffe://cluster.example.test/sa/worker/ns/blue",
            "spiffe://cluster.example.test/ns/../sa/worker",
            "https://cluster.example.test/ns/blue/sa/worker",
        ] {
            assert_eq!(parse_spiffe(td, bad), None, "{bad}");
        }
        assert!(trust_domain("cluster.example.test"));
        for bad in ["", "Cluster", "a/b", ".a", "a.", "a:1"] {
            assert!(!trust_domain(bad), "{bad}");
        }
        assert!(object_name("worker.v2") && !object_name("Worker") && !object_name("a..b"));
    }
}
