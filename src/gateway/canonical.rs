//! Canonical request path (ADR-0013).
//!
//! A copy of the semantics of Hangang's `resource_policy::canonical_path`, so
//! that Hopae's path rules match the path the gateway selected the route with.
//! Percent escapes are decoded exactly once and must form valid UTF-8; a
//! decoded or raw backslash, percent, `?`, `#`, `;`, control byte or DEL, an
//! encoded slash, a `.`/`..` segment or a repeated slash makes the path
//! non-canonical.
use crate::verify::types::CanonicalPath;

/// Longest path accepted, in bytes (the gateway's limit).
const MAX_PATH: usize = 2048;

/// Canonicalize the path component (no query, no fragment) of a request.
#[allow(clippy::result_unit_err)] // the signature is pinned by the M1 plan
pub fn canonical_path(path: &str) -> Result<CanonicalPath, ()> {
    if !path.starts_with('/') || path.len() > MAX_PATH {
        return Err(());
    }
    let mut output = Vec::with_capacity(path.len());
    let mut input = path.bytes();
    while let Some(byte) = input.next() {
        let decoded = if byte == b'%' {
            let hi = input.next().and_then(hex_digit);
            let lo = input.next().and_then(hex_digit);
            match (hi, lo) {
                (Some(hi), Some(lo)) => (hi << 4) | lo,
                _ => return Err(()),
            }
        } else {
            byte
        };
        if matches!(decoded, b'\\' | b'%' | b'?' | b'#' | b';' | 0..=31 | 127)
            || (decoded == b'/' && byte != b'/')
        {
            return Err(());
        }
        output.push(decoded);
    }
    let output = String::from_utf8(output).map_err(|_| ())?;
    if output.chars().any(char::is_control)
        || output.contains("//")
        || output.split('/').any(|seg| seg == "." || seg == "..")
    {
        return Err(());
    }
    Ok(CanonicalPath::new(output))
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(p: &str) -> String {
        canonical_path(p)
            .unwrap_or_else(|()| panic!("{p} should be canonical"))
            .as_str()
            .to_string()
    }

    #[test]
    fn decodes_percent_escapes_exactly_once() {
        assert_eq!(ok("/"), "/");
        assert_eq!(ok("/ad%6din/x%7e"), "/admin/x~");
        assert_eq!(ok("/%61dmin/x"), "/admin/x");
        assert_eq!(
            ok("/한%EA%B8%80:a@b!$&'()*+,="),
            "/한글:a@b!$&'()*+,=",
            "ordinary unicode and punctuation stay usable"
        );
        assert_eq!(ok("/a/"), "/a/");
    }

    #[test]
    fn rejects_ambiguous_paths() {
        for path in [
            "admin",
            "",
            "/a/../b",
            "/admin/%2e%2e/x",
            "/./x",
            "/a/.",
            "/admin//x",
            "/%2561dmin/x",
            "/a%2fb",
            "/a%2Fb",
            "/a%5cb",
            "/a\\b",
            "/a;b",
            "/a%3Bb",
            "/a%00b",
            "/a\u{7f}b",
            "/a%7fb",
            "/a%3fb",
            "/a%23b",
            "/a?b",
            "/a#b",
            "/%zz",
            "/%4",
            "/%ED%A0%80",
            "/%C0%AF",
            "/a%0ab",
        ] {
            assert!(canonical_path(path).is_err(), "{path:?} must be refused");
        }
        assert!(canonical_path(&format!("/{}", "x".repeat(2048))).is_err());
        assert!(canonical_path(&format!("/{}", "x".repeat(2047))).is_ok());
    }
}
