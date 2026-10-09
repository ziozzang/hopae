//! The linking policy table of ADR-0011 as a pure function, so every row is a
//! unit test. Ownership of an existing account is proven only by
//! authenticating to it; a provider's claim alone never attaches an identity.

use crate::config::{LinkConflict, LinkMode};
use crate::event::types::{Reason, reasons};
use crate::provider::types::ProviderIdentity;
use crate::store::types::{ProviderRow, User};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinkingPolicy {
    pub mode: LinkMode,
    pub on_conflict: LinkConflict,
}

impl Default for LinkingPolicy {
    /// `link_required` is the default and the safe choice.
    fn default() -> Self {
        LinkingPolicy {
            mode: LinkMode::VerifiedEmail,
            on_conflict: LinkConflict::LinkRequired,
        }
    }
}

/// What to do with an identity the directory has never seen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkDecision {
    /// Create a user. `primary_email` says whether the assertion's email
    /// becomes `users.primary_email` (verified, and not held by another user).
    Create {
        primary_email: bool,
    },
    /// Create a user without a primary email and show the notice (`separate`).
    CreateSeparate,
    /// Refuse and require a fresh authentication to the existing account.
    LinkRequired,
    /// Attach to the existing user (authoritative opt-in only).
    AutoLink,
    Deny(Reason),
}

/// `email_owner` is the user whose `primary_email` equals the asserted email,
/// if any. The caller has already applied the domain allowlist.
pub fn decide_unknown_identity(
    policy: LinkingPolicy,
    provider: &ProviderRow,
    ident: &ProviderIdentity,
    email_owner: Option<&User>,
) -> LinkDecision {
    let verified_email = ident.email.is_some() && ident.email_verified;
    let Some(owner) = email_owner else {
        return LinkDecision::Create {
            primary_email: verified_email,
        };
    };
    if policy.mode == LinkMode::Off {
        // One user per identity; emails may repeat, but `primary_email` is unique.
        return LinkDecision::Create {
            primary_email: false,
        };
    }
    if auto_link_allowed(provider, ident, owner) {
        return LinkDecision::AutoLink;
    }
    match policy.on_conflict {
        LinkConflict::LinkRequired => LinkDecision::LinkRequired,
        LinkConflict::Separate => LinkDecision::CreateSeparate,
        LinkConflict::Deny => LinkDecision::Deny(reasons::EMAIL_IN_USE),
    }
}

/// The only automatic link: the provider opted in (`auto_link`), the assertion
/// is verified and authoritative for a domain the provider is authoritative
/// for, and the existing user's email is itself authoritative.
fn auto_link_allowed(provider: &ProviderRow, ident: &ProviderIdentity, owner: &User) -> bool {
    let Some(email) = ident.email.as_ref() else {
        return false;
    };
    provider.auto_link
        && ident.email_verified
        && ident.email_authoritative
        && owner.email_authoritative
        && provider
            .authoritative_domains
            .iter()
            .any(|d| d.eq_ignore_ascii_case(email.domain()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Timestamp;
    use crate::identity::types::{NormalizedEmail, UserId};
    use crate::provider::types::{ProviderId, ProviderKind};
    use crate::store::types::{ManagedBy, UserStatus};

    fn provider(auto_link: bool, domains: &[&str]) -> ProviderRow {
        ProviderRow {
            provider_id: ProviderId::new("mock"),
            kind: ProviderKind::Oidc,
            display_name: "mock".into(),
            enabled: true,
            managed_by: ManagedBy::File,
            deleted_at: None,
            sort_order: 0,
            config: serde_json::json!({}),
            client_secret_env: None,
            allowed_email_domains: vec![],
            authoritative_domains: domains.iter().map(|d| d.to_string()).collect(),
            auto_link,
            trust_email: false,
        }
    }

    fn ident(verified: bool, authoritative: bool) -> ProviderIdentity {
        ProviderIdentity {
            subject: "sub-1".into(),
            email: NormalizedEmail::parse("a@example.test").ok(),
            email_verified: verified,
            email_authoritative: authoritative,
            name: None,
            username: None,
            picture: None,
            raw_claims: serde_json::json!({}),
            auth_time: None,
        }
    }

    fn owner(authoritative: bool) -> User {
        User {
            user_id: UserId::new("u_1"),
            primary_email: NormalizedEmail::parse("a@example.test").ok(),
            email_verified: true,
            email_authoritative: authoritative,
            display_name: None,
            username: None,
            status: UserStatus::Active,
            authz_version: 1,
            groups: vec![],
            created_at: Timestamp(0),
            updated_at: Timestamp(0),
            last_login_at: None,
        }
    }

    const D: LinkingPolicy = LinkingPolicy {
        mode: LinkMode::VerifiedEmail,
        on_conflict: LinkConflict::LinkRequired,
    };

    #[test]
    fn no_owner_creates_a_user_and_sets_the_email_only_when_verified() {
        let p = provider(false, &[]);
        assert_eq!(
            decide_unknown_identity(D, &p, &ident(true, false), None),
            LinkDecision::Create {
                primary_email: true
            }
        );
        assert_eq!(
            decide_unknown_identity(D, &p, &ident(false, false), None),
            LinkDecision::Create {
                primary_email: false
            }
        );
        let mut no_email = ident(true, false);
        no_email.email = None;
        assert_eq!(
            decide_unknown_identity(D, &p, &no_email, None),
            LinkDecision::Create {
                primary_email: false
            }
        );
    }

    #[test]
    fn collision_requires_fresh_authentication_by_default_even_when_verified() {
        let p = provider(false, &[]);
        for verified in [true, false] {
            assert_eq!(
                decide_unknown_identity(D, &p, &ident(verified, false), Some(&owner(false))),
                LinkDecision::LinkRequired,
                "verified={verified}"
            );
        }
        // A verified, authoritative claim is still not enough without the opt-in.
        assert_eq!(
            decide_unknown_identity(D, &p, &ident(true, true), Some(&owner(true))),
            LinkDecision::LinkRequired
        );
    }

    #[test]
    fn auto_link_needs_every_condition() {
        let p = provider(true, &["example.test"]);
        let full = decide_unknown_identity(D, &p, &ident(true, true), Some(&owner(true)));
        assert_eq!(full, LinkDecision::AutoLink);
        // each missing condition falls back to link_required
        let cases = [
            (
                provider(false, &["example.test"]),
                ident(true, true),
                owner(true),
            ),
            (
                provider(true, &["other.test"]),
                ident(true, true),
                owner(true),
            ),
            (provider(true, &[]), ident(true, true), owner(true)),
            (p.clone(), ident(true, false), owner(true)),
            (p.clone(), ident(false, true), owner(true)),
            (p.clone(), ident(true, true), owner(false)),
        ];
        for (i, (p, id, o)) in cases.iter().enumerate() {
            assert_eq!(
                decide_unknown_identity(D, p, id, Some(o)),
                LinkDecision::LinkRequired,
                "case {i}"
            );
        }
    }

    #[test]
    fn separate_deny_and_off() {
        let p = provider(false, &[]);
        let sep = LinkingPolicy {
            on_conflict: LinkConflict::Separate,
            ..D
        };
        assert_eq!(
            decide_unknown_identity(sep, &p, &ident(true, false), Some(&owner(false))),
            LinkDecision::CreateSeparate
        );
        let deny = LinkingPolicy {
            on_conflict: LinkConflict::Deny,
            ..D
        };
        assert_eq!(
            decide_unknown_identity(deny, &p, &ident(true, false), Some(&owner(false))),
            LinkDecision::Deny(reasons::EMAIL_IN_USE)
        );
        let off = LinkingPolicy {
            mode: LinkMode::Off,
            ..D
        };
        // mode off never links and never reports a conflict, even for an opted-in provider
        let opted = provider(true, &["example.test"]);
        assert_eq!(
            decide_unknown_identity(off, &opted, &ident(true, true), Some(&owner(true))),
            LinkDecision::Create {
                primary_email: false
            }
        );
    }
}
