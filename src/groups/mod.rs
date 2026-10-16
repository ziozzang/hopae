//! Groups owned by Hopae (Hangang ADR 0021, ADR-0018): local groups managed
//! by administrators, LDAP groups (`memberOf` or a group search) and OIDC
//! groups (a configurable claim), their memberships, the provider sync rules
//! and the signed membership projection Pumgye consumes.
//!
//! Source of truth: a provider group and its memberships are written only by
//! that provider's sync; a local group and its memberships only by an
//! administrator. Every change is journaled for the projection
//! (`group_changes`) and recorded as a required `group.*` event in the same
//! store transaction.

pub mod config;
pub mod projection;
pub mod sync;

pub use config::{GroupsConfig, LdapGroupMode, LdapGroups, ProviderGroups, Rules};

/// Prefix of a GroupRef (Hangang ADR 0021: `grp1:<26 crockford>`).
pub const REF_PREFIX: &str = "grp1:";
/// Length of a GroupRef.
pub const REF_LEN: usize = 31;
/// Longest stable source key (a DN, a claim value or a local key), in bytes.
pub const MAX_KEY_BYTES: usize = 512;
/// Longest group name, in characters.
pub const MAX_NAME_CHARS: usize = 256;
/// Longest description, in characters.
pub const MAX_DESCRIPTION_CHARS: usize = 1024;
/// Longest administrator reason, in characters.
pub const MAX_REASON_CHARS: usize = 256;
/// Raw values one provider assertion may carry before it is refused outright.
pub const MAX_RAW_VALUES: usize = 4096;

/// A fresh, never reused GroupRef.
pub fn new_ref(rng: &dyn crate::crypto::Rng) -> String {
    crate::crypto::random_id(rng, REF_PREFIX)
}

/// Whether `s` has the exact GroupRef grammar.
pub fn valid_ref(s: &str) -> bool {
    s.len() == REF_LEN
        && s.starts_with(REF_PREFIX)
        && s[REF_PREFIX.len()..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b.is_ascii_lowercase() && !b"ilou".contains(&b)))
}

/// Where a group and its memberships come from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    Local,
    Ldap,
    Oidc,
}

impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Source::Local => "local",
            Source::Ldap => "ldap",
            Source::Oidc => "oidc",
        }
    }

    pub fn parse(s: &str) -> Option<Source> {
        match s {
            "local" => Some(Source::Local),
            "ldap" => Some(Source::Ldap),
            "oidc" => Some(Source::Oidc),
            _ => None,
        }
    }
}

/// A local group key: 1 to 128 of `[A-Za-z0-9._:-]`, starting with a letter
/// or digit (stable, safe in logs and URLs).
pub fn valid_local_key(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.as_bytes()[0].is_ascii_alphanumeric()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
}

/// A display text: 1..=`max` characters after trimming, no control characters.
pub fn valid_text(s: &str, max: usize) -> bool {
    let t = s.trim();
    !t.is_empty() && t.chars().count() <= max && !t.chars().any(char::is_control)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refs_have_the_adr_0021_grammar() {
        let r = new_ref(&crate::crypto::OsRng);
        assert!(valid_ref(&r), "{r}");
        assert_eq!(r.len(), REF_LEN);
        assert!(!valid_ref("grp1:0123456789ABCDEFGHJKMNPQRS"));
        assert!(!valid_ref("grp2:0123456789abcdefghjkmnpqrs"));
        assert!(!valid_ref("grp1:0123456789abcdefghjkmnpqr"));
        assert!(!valid_ref("grp1:0123456789abcdefghjkmnpqri"));
        assert!(valid_ref("grp1:0123456789abcdefghjkmnpqrs"));
    }

    #[test]
    fn local_keys_and_texts_are_bounded() {
        assert!(valid_local_key("eng.backend:oncall-1"));
        assert!(!valid_local_key("-leading"));
        assert!(!valid_local_key("has space"));
        assert!(!valid_local_key(&"a".repeat(129)));
        assert!(valid_text(" Backend ", 256));
        assert!(!valid_text("  ", 256));
        assert!(!valid_text("a\nb", 256));
        assert!(!valid_text(&"가".repeat(257), 256));
    }
}
