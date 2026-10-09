//! Email helpers for the identity service: allowlist evaluation and the
//! conversion of a provider's assertion into the store's identity row.

use crate::identity::types::NormalizedEmail;
use crate::provider::types::{ProviderId, ProviderIdentity};
use crate::store::types::NewIdentity;

/// `providers[].allowed_email_domains` (ADR-0011: evaluated before any linking
/// decision). An empty list allows everything. A non-empty list requires an
/// email whose domain is listed; a missing email is refused rather than
/// guessed at; callers pass only a verified address. Entries are compared case-insensitively.
pub fn domain_allowed(email: Option<&NormalizedEmail>, allowed: &[String]) -> bool {
    if allowed.is_empty() {
        return true;
    }
    let Some(email) = email else {
        return false;
    };
    let domain = email.domain();
    allowed.iter().any(|d| d.eq_ignore_ascii_case(domain))
}

/// The store row for a provider assertion.
pub fn new_identity(provider: &ProviderId, ident: &ProviderIdentity) -> NewIdentity {
    NewIdentity {
        provider_id: provider.clone(),
        subject: ident.subject.clone(),
        email: ident.email.clone(),
        email_verified: ident.email_verified,
        email_authoritative: ident.email_authoritative,
        name: ident.name.clone(),
        picture: ident.picture.clone(),
        raw_claims: ident.raw_claims.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(s: &str) -> NormalizedEmail {
        NormalizedEmail::parse(s).unwrap()
    }

    #[test]
    fn allowlist_semantics() {
        assert!(domain_allowed(None, &[]));
        assert!(domain_allowed(Some(&e("a@x.test")), &[]));
        let list = vec!["Example.Test".to_string()];
        assert!(domain_allowed(Some(&e("a@EXAMPLE.test")), &list));
        assert!(!domain_allowed(Some(&e("a@other.test")), &list));
        assert!(!domain_allowed(Some(&e("a@sub.example.test")), &list));
        assert!(!domain_allowed(None, &list));
    }
}
