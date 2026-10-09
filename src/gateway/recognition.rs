//! Reserved handoff parameter recognition (ADR-0004).
//!
//! One rule shared with the gateway's cache bypass: the query string is
//! parsed as `application/x-www-form-urlencoded` pairs (split on `&`, name
//! and value percent-decoded with `+` as a space); a pair whose decoded name
//! is exactly `_hopae_handoff` is the handoff parameter. More than one such
//! pair, or a candidate name containing a malformed percent escape, is
//! ambiguous. A name is a malformed candidate when it would equal the
//! reserved name if each malformed escape (a `%` and the two bytes after it)
//! stood for one character.

use crate::crypto::Secret;
use crate::verify::types::Handoff;

/// The reserved query parameter name.
pub const HANDOFF_PARAM: &str = "_hopae_handoff";

#[derive(PartialEq, Eq)]
enum NameKind {
    /// Some other parameter.
    Other,
    /// Decodes to exactly the reserved name.
    Exact,
    /// Would decode to the reserved name were its malformed escapes a character each.
    Malformed,
}

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn classify(raw_name: &str) -> NameKind {
    let bytes = raw_name.as_bytes();
    // None = a malformed escape standing for one unknown character.
    let mut decoded: Vec<Option<u8>> = Vec::with_capacity(bytes.len());
    let mut malformed = false;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                decoded.push(Some(b' '));
                i += 1;
            }
            b'%' => {
                match (
                    bytes.get(i + 1).copied().and_then(hex),
                    bytes.get(i + 2).copied().and_then(hex),
                ) {
                    (Some(hi), Some(lo)) => {
                        decoded.push(Some((hi << 4) | lo));
                        i += 3;
                    }
                    _ => {
                        malformed = true;
                        decoded.push(None);
                        i = (i + 3).min(bytes.len());
                    }
                }
            }
            b => {
                decoded.push(Some(b));
                i += 1;
            }
        }
    }
    let target = HANDOFF_PARAM.as_bytes();
    if decoded.len() != target.len()
        || !decoded
            .iter()
            .zip(target)
            .all(|(d, t)| d.is_none_or(|d| d == *t))
    {
        return NameKind::Other;
    }
    if malformed {
        NameKind::Malformed
    } else {
        NameKind::Exact
    }
}

fn split_pair(pair: &str) -> (&str, &str) {
    pair.split_once('=').unwrap_or((pair, ""))
}

fn decode_value(raw: &str) -> String {
    let spaced = raw.replace('+', " ");
    percent_encoding::percent_decode_str(&spaced)
        .decode_utf8_lossy()
        .into_owned()
}

/// Apply the recognition rule to a raw query string (without the leading `?`).
pub fn find_handoff(query: &str) -> Handoff {
    let mut found: Option<String> = None;
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (name, value) = split_pair(pair);
        match classify(name) {
            NameKind::Other => {}
            NameKind::Malformed => return Handoff::Ambiguous,
            NameKind::Exact => {
                if found.is_some() {
                    return Handoff::Ambiguous;
                }
                found = Some(decode_value(value));
            }
        }
    }
    match found {
        Some(code) => Handoff::Code(Secret::new(code)),
        None => Handoff::None,
    }
}

/// The URL as a string without any pair the rule recognizes (exact or
/// ambiguous): the `login` target of a `401` and the clean URL.
pub fn strip_handoff(url: &url::Url) -> String {
    let full = url.as_str();
    let Some(q) = url.query() else {
        return full.to_string();
    };
    let base = full.split('?').next().unwrap_or(full);
    let kept: Vec<&str> = q
        .split('&')
        .filter(|p| !p.is_empty() && classify(split_pair(p).0) == NameKind::Other)
        .collect();
    if kept.is_empty() {
        return base.to_string();
    }
    format!("{base}?{}", kept.join("&"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn code(q: &str) -> Option<String> {
        match find_handoff(q) {
            Handoff::Code(s) => Some(s.expose().to_string()),
            _ => None,
        }
    }

    fn ambiguous(q: &str) -> bool {
        matches!(find_handoff(q), Handoff::Ambiguous)
    }

    fn none(q: &str) -> bool {
        matches!(find_handoff(q), Handoff::None)
    }

    #[test]
    fn plain_and_encoded_names_are_the_same_parameter() {
        assert_eq!(code("_hopae_handoff=K1").as_deref(), Some("K1"));
        assert_eq!(code("q=1&_hopae_handoff=K1&z=2").as_deref(), Some("K1"));
        assert_eq!(code("q=1&%5Fhopae%5Fhandoff=K1&z=2").as_deref(), Some("K1"));
        assert_eq!(
            code("%5fhopae%5fHANDOFF=x").as_deref(),
            None,
            "case matters"
        );
        assert_eq!(code("_hopae_handoff=K1%2B").as_deref(), Some("K1+"));
        assert_eq!(code("_hopae_handoff=a+b").as_deref(), Some("a b"));
        assert_eq!(code("_hopae_handoff=").as_deref(), Some(""));
        assert_eq!(code("_hopae_handoff").as_deref(), Some(""));
    }

    #[test]
    fn repeated_or_malformed_candidates_are_ambiguous() {
        assert!(ambiguous("_hopae_handoff=K1&_hopae_handoff=K2"));
        assert!(ambiguous("_hopae_handoff=K1&%5Fhopae%5Fhandoff=K1"));
        assert!(ambiguous("%5Fhopae%ZZhandoff=K1"));
        assert!(ambiguous("_hopae%zzhandoff=K1"));
    }

    #[test]
    fn other_names_are_not_the_parameter() {
        assert!(none(""));
        assert!(none("q=1&z=2"));
        assert!(none("_hopae_handoff2=K1"));
        assert!(none("x_hopae_handoff=K1"));
        assert!(none("a=_hopae_handoff"));
        assert!(none("a=%ZZ&b=1"), "malformed escapes elsewhere are ignored");
        assert!(none("%ZZ=1"));
        assert!(none("&&"));
    }

    #[test]
    fn strip_removes_only_the_reserved_pairs() {
        let u = |s: &str| url::Url::parse(s).unwrap();
        assert_eq!(
            strip_handoff(&u("https://a.test/x?q=1&_hopae_handoff=K&z=2")),
            "https://a.test/x?q=1&z=2"
        );
        assert_eq!(
            strip_handoff(&u("https://a.test/x?_hopae_handoff=K")),
            "https://a.test/x"
        );
        assert_eq!(
            strip_handoff(&u("https://a.test/x?q=1%202&%5Fhopae%5Fhandoff=K")),
            "https://a.test/x?q=1%202"
        );
        assert_eq!(
            strip_handoff(&u("https://a.test/x?q=1")),
            "https://a.test/x?q=1"
        );
        assert_eq!(strip_handoff(&u("https://a.test/")), "https://a.test/");
    }
}
