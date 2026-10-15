//! Identity identifiers: users and normalized email addresses.

use unicode_normalization::UnicodeNormalization;

string_newtype!(
    /// Opaque user identifier, `u_` + 26 Crockford base32 characters.
    UserId
);

/// RFC 5322 address normalized: domain lower-cased, local part NFC (ADR-0011).
///
/// Only dot-atom local parts are accepted (no quoted strings, no comments, no
/// display names); non-ASCII local parts are allowed and normalized to NFC.
/// The local part keeps its case. Anything else is rejected rather than
/// guessed at.
#[derive(
    Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(try_from = "String", into = "String")]
pub struct NormalizedEmail(String);

impl TryFrom<String> for NormalizedEmail {
    type Error = EmailError;

    fn try_from(s: String) -> Result<Self, EmailError> {
        Self::parse(&s)
    }
}

impl From<NormalizedEmail> for String {
    fn from(e: NormalizedEmail) -> String {
        e.0
    }
}

/// Why an address was refused. Carries no part of the input.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum EmailError {
    #[error("address is empty or too long")]
    Length,
    #[error("address must contain exactly one '@'")]
    At,
    #[error("local part is not a plain dot-atom")]
    LocalPart,
    #[error("domain is not a plain host name")]
    Domain,
}

const MAX_EMAIL_BYTES: usize = 254;
const MAX_LOCAL_BYTES: usize = 64;

fn is_atext(c: char) -> bool {
    c.is_ascii_alphanumeric()
        || "!#$%&'*+-/=?^_`{|}~".contains(c)
        || (!c.is_ascii() && !c.is_control() && !c.is_whitespace())
}

impl NormalizedEmail {
    pub(crate) fn heap_capacity(&self) -> usize {
        self.0.capacity()
    }

    /// Parse and normalize. Leading/trailing whitespace is not trimmed: it is an error.
    pub fn parse(input: &str) -> Result<Self, EmailError> {
        if input.is_empty() || input.len() > MAX_EMAIL_BYTES {
            return Err(EmailError::Length);
        }
        let mut parts = input.split('@');
        let (Some(local), Some(domain), None) = (parts.next(), parts.next(), parts.next()) else {
            return Err(EmailError::At);
        };
        let local: String = local.nfc().collect();
        if local.is_empty()
            || local.len() > MAX_LOCAL_BYTES
            || local.starts_with('.')
            || local.ends_with('.')
            || local.contains("..")
            || !local.chars().all(|c| c == '.' || is_atext(c))
        {
            return Err(EmailError::LocalPart);
        }
        let domain = domain.to_ascii_lowercase();
        if !valid_domain(&domain) {
            return Err(EmailError::Domain);
        }
        Ok(Self(format!("{local}@{domain}")))
    }

    /// Rebuild from a value the store wrote earlier (already normalized);
    /// re-normalizes, so a hand-edited row cannot smuggle a non-canonical form.
    pub fn from_stored(s: &str) -> Option<Self> {
        Self::parse(s).ok()
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The domain part (lower-case).
    pub fn domain(&self) -> &str {
        self.0.rsplit_once('@').map_or("", |(_, d)| d)
    }
}

impl std::fmt::Display for NormalizedEmail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Letters, digits and hyphens in dot-separated labels of 1-63 bytes; no
/// leading or trailing hyphen; at most 253 bytes. Shared with `policy::types::Host`.
pub(crate) fn valid_domain(d: &str) -> bool {
    !d.is_empty()
        && d.len() <= 253
        && d.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_is_lowered_local_part_is_nfc_and_case_kept() {
        let e = NormalizedEmail::parse("Alice.Kim@Example.TEST").unwrap();
        assert_eq!(e.as_str(), "Alice.Kim@example.test");
        assert_eq!(e.domain(), "example.test");
        // "é" decomposed (e + U+0301) becomes the single code point U+00E9.
        let e = NormalizedEmail::parse("cafe\u{0301}@example.test").unwrap();
        assert_eq!(e.as_str(), "caf\u{00e9}@example.test");
    }

    #[test]
    fn malformed_addresses_are_refused() {
        for bad in [
            "",
            "a",
            "a@",
            "@example.test",
            "a@@example.test",
            "a@b@example.test",
            ".a@example.test",
            "a.@example.test",
            "a..b@example.test",
            "a b@example.test",
            "a@exa mple.test",
            "a@example.test.",
            "a@-example.test",
            "\"a b\"@example.test",
            " a@example.test",
            "a@example.test\n",
            "a\u{0}@example.test",
        ] {
            assert!(NormalizedEmail::parse(bad).is_err(), "{bad:?}");
        }
        let long = format!("{}@example.test", "a".repeat(65));
        assert_eq!(NormalizedEmail::parse(&long), Err(EmailError::LocalPart));
        let huge = format!("a@{}.test", "a".repeat(260));
        assert_eq!(NormalizedEmail::parse(&huge), Err(EmailError::Length));
    }
}

#[cfg(test)]
mod retained_heap_tests {
    use super::*;
    #[test]
    fn retained_heap_email_reports_backing_capacity() {
        let mut email = NormalizedEmail::parse("a@example.test").unwrap();
        let len = email.0.len();
        email.0.reserve(256);
        assert_eq!(email.heap_capacity(), email.0.capacity());
        assert!(email.heap_capacity() > len);
    }
}
