//! Authentication gateway contracts. Connectors and Hangang wiring are implemented separately.
//! Evidence construction stays crate-private: request claims cannot authenticate themselves.
pub mod authority;
pub mod breaker;
pub mod kubernetes;
pub mod lua;
pub mod permission_live;
pub mod projection;
pub mod projection_admission;
pub mod projection_authority;
pub mod projection_receiver;
pub mod publication;
pub mod receipt;
pub mod receipt_authority;
pub mod receipt_binding;
pub mod receipt_issuer;
pub mod receipt_key_store;
pub mod receipt_keys;
pub mod receipt_replay;
pub mod relay;
pub mod request_binding;
pub mod runtime;

pub use hopae_grpc::PrincipalKind;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Subject {
    pub issuer: String,
    pub realm: String,
    pub subject: String,
    pub kind: PrincipalKind,
}
pub fn stable_subject(subject: &Subject) -> String {
    use sha2::{Digest as _, Sha256};
    let mut digest = Sha256::new();
    digest.update([match subject.kind {
        crate::auth_gateway::PrincipalKind::Human => 0,
        crate::auth_gateway::PrincipalKind::Service => 1,
        crate::auth_gateway::PrincipalKind::Workload => 2,
        crate::auth_gateway::PrincipalKind::Network => 3,
    }]);
    for value in [&subject.issuer, &subject.realm, &subject.subject] {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value.as_bytes());
    }
    let digest = digest.finalize();
    let mut output = String::from("s_");
    for byte in &digest[..24] {
        use std::fmt::Write;
        write!(&mut output, "{byte:02x}").expect("string writer");
    }
    output
}
#[derive(Clone, Debug)]
pub struct VerifiedEvidence {
    subject: Subject,
    connector: String,
    expires_at: u64,
    service: Option<String>,
}
impl VerifiedEvidence {
    pub fn service(&self) -> Option<&str> {
        self.service.as_deref()
    }
    pub fn subject(&self) -> &Subject {
        &self.subject
    }
    pub fn expires_at_ms(&self) -> u64 {
        self.expires_at
    }
    pub fn connector(&self) -> &str {
        &self.connector
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Composition {
    Any,
    All,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompositionError {
    InvalidPolicy,
    Missing,
    Expired,
    Conflict,
}
/// Joins only evidence for the same namespaced principal. Network factors describe
/// context and cannot be implicitly merged with a human/service subject; a connector
/// must supply an explicitly verified subject relationship before composition.
pub fn compose<'a>(
    mode: Composition,
    required: &[String],
    evidence: &'a [VerifiedEvidence],
    now: u64,
) -> Result<&'a Subject, CompositionError> {
    if required.is_empty() || required.len() > 16 || evidence.len() > 16 {
        return Err(CompositionError::InvalidPolicy);
    }
    if required
        .iter()
        .enumerate()
        .any(|(i, id)| id.is_empty() || id.len() > 128 || required[..i].contains(id))
    {
        return Err(CompositionError::InvalidPolicy);
    }
    let mut selected = None;
    let mut selected_service: Option<Option<&str>> = None;
    let mut supplied = 0u16;
    for item in evidence {
        let Some(index) = required.iter().position(|id| id == &item.connector) else {
            return Err(CompositionError::InvalidPolicy);
        };
        let bit = 1u16 << index;
        if supplied & bit != 0 {
            return Err(CompositionError::InvalidPolicy);
        }
        supplied |= bit;
        if item.expires_at <= now {
            return Err(CompositionError::Expired);
        }
        if selected.is_some_and(|subject| subject != &item.subject) {
            return Err(CompositionError::Conflict);
        }
        if selected_service.is_some_and(|service| service != item.service.as_deref()) {
            return Err(CompositionError::Conflict);
        }
        selected_service = Some(item.service.as_deref());
        selected = Some(&item.subject);
    }
    if mode == Composition::All && supplied.count_ones() as usize != required.len() {
        return Err(CompositionError::Missing);
    }
    selected.ok_or(CompositionError::Missing)
}
/// Composed evidence keeps the validated audience and shortest freshness lease.
/// It carries no assurance-level claim: several factors cannot manufacture human MFA.
#[derive(Clone, Debug)]
pub struct ComposedEvidence {
    subject: Subject,
    service: Option<String>,
    fresh_until: u64,
}
impl ComposedEvidence {
    pub fn subject(&self) -> &Subject {
        &self.subject
    }
    pub fn service(&self) -> Option<&str> {
        self.service.as_deref()
    }
    pub fn fresh_until(&self) -> u64 {
        self.fresh_until
    }
}
/// Preserve the earliest evidence deadline, capped to a one-second decision lease.
/// Evidence construction and subject relationship verification remain connector-owned.
pub fn compose_verified(
    mode: Composition,
    required: &[String],
    evidence: &[VerifiedEvidence],
    now: u64,
) -> Result<ComposedEvidence, CompositionError> {
    let subject = compose(mode, required, evidence, now)?.clone();
    let fresh_until = evidence
        .iter()
        .map(|item| item.expires_at)
        .min()
        .ok_or(CompositionError::Missing)?
        .min(now.saturating_add(1000));
    Ok(ComposedEvidence {
        subject,
        service: evidence.first().and_then(|item| item.service.clone()),
        fresh_until,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    fn evidence(connector: &str, subject: &str) -> VerifiedEvidence {
        VerifiedEvidence {
            connector: connector.into(),
            subject: Subject {
                issuer: "issuer".into(),
                realm: "external".into(),
                subject: subject.into(),
                kind: PrincipalKind::Human,
            },
            expires_at: 10,
            service: None,
        }
    }
    #[test]
    fn composed_service_evidence_preserves_audience_and_earliest_deadline() {
        let required = vec!["api".into(), "network".into()];
        let mut first = evidence("api", "worker");
        first.subject.kind = PrincipalKind::Service;
        first.service = Some("orders".into());
        first.expires_at = 9000;
        let mut second = first.clone();
        second.connector = "network".into();
        second.expires_at = 200;
        let result =
            compose_verified(Composition::All, &required, &[first.clone(), second], 100).unwrap();
        assert_eq!(result.fresh_until(), 200);
        assert_eq!(result.service(), Some("orders"));
        assert_eq!(result.subject().kind, PrincipalKind::Service);
        let result = compose_verified(Composition::Any, &required, &[first], 100).unwrap();
        assert_eq!(result.fresh_until(), 1100);
        assert!(matches!(
            compose_verified(
                Composition::Any,
                &required,
                &[evidence("api", "worker")],
                10
            ),
            Err(CompositionError::Expired)
        ));
    }
    #[test]
    fn composition_cannot_join_evidence_from_different_service_audiences() {
        let mut api = evidence("api", "scheduler");
        let mut network = evidence("network", "scheduler");
        api.subject.kind = PrincipalKind::Service;
        network.subject.kind = PrincipalKind::Service;
        api.service = Some("orders".into());
        network.service = Some("billing".into());
        let required = vec!["api".into(), "network".into()];
        assert_eq!(
            compose(
                Composition::All,
                &required,
                &[api.clone(), network.clone()],
                1
            ),
            Err(CompositionError::Conflict)
        );
        network.service = Some("orders".into());
        assert!(compose(Composition::All, &required, &[api, network], 1).is_ok());
    }
    #[test]
    fn composition_never_joins_conflicting_or_expired_subjects() {
        let required = vec!["oidc".into(), "directory".into()];
        let one = vec![evidence("oidc", "alice")];
        assert!(compose(Composition::Any, &required, &one, 1).is_ok());
        assert_eq!(
            compose(Composition::All, &required, &one, 1),
            Err(CompositionError::Missing)
        );
        assert_eq!(
            compose(Composition::Any, &required, &one, 10),
            Err(CompositionError::Expired)
        );
        let conflict = vec![evidence("oidc", "alice"), evidence("directory", "bob")];
        assert_eq!(
            compose(Composition::Any, &required, &conflict, 1),
            Err(CompositionError::Conflict)
        );
        let mut other_realm = evidence("directory", "alice");
        other_realm.subject.realm = "internal".into();
        assert_eq!(
            compose(
                Composition::All,
                &required,
                &[evidence("oidc", "alice"), other_realm],
                1
            ),
            Err(CompositionError::Conflict)
        );
    }
}

pub mod receipt_config;
