//! Portal cookie rules: reading the browser's cookies and writing ours.
//!
//! Attributes are fixed: `Path=/`, `Secure` (unless development mode),
//! `HttpOnly`, `SameSite=Lax`, never `Domain`, never `Expires`.

use std::time::Duration;

use axum::http::HeaderMap;

use crate::config::CookieNames;
use crate::crypto::{Rng, Secret, is_well_formed_bind, is_well_formed_handle, random_token};

/// Largest total size of `cookie` headers the portal parses; beyond it the
/// request is refused.
pub const MAX_COOKIE_BYTES: usize = 8 * 1024;
/// `Max-Age` of the portal binding cookie.
pub const PORTAL_BIND_MAX_AGE: Duration = Duration::from_secs(600);

/// What the browser sent that the portal cares about.
#[derive(Debug, Default, Clone)]
pub struct Presented {
    /// First well-formed `<name>_portal` value.
    pub bind: Option<Secret>,
    /// First well-formed `<name>` (handle) value.
    pub handle: Option<Secret>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct TooLarge;

/// Read the portal binding cookie and the portal handle. Pairs with another
/// name are ignored (the development-mode names never match the secure ones),
/// the first well-formed pair of each name wins, and a malformed value counts
/// as absent. Parsing stops once both are found.
pub fn read(headers: &HeaderMap, names: &CookieNames) -> Result<Presented, TooLarge> {
    let total: usize = headers.get_all("cookie").iter().map(|v| v.len()).sum();
    if total > MAX_COOKIE_BYTES {
        return Err(TooLarge);
    }
    let mut out = Presented::default();
    'headers: for value in headers.get_all("cookie") {
        let Ok(text) = value.to_str() else { continue };
        for pair in text.split(';') {
            let Some((name, val)) = pair.trim().split_once('=') else {
                continue;
            };
            let (name, val) = (name.trim(), val.trim());
            if out.bind.is_none() && name == names.portal && is_well_formed_bind(val) {
                out.bind = Some(Secret::new(val.to_string()));
            } else if out.handle.is_none() && name == names.handle && is_well_formed_handle(val) {
                out.handle = Some(Secret::new(val.to_string()));
            }
            if out.bind.is_some() && out.handle.is_some() {
                break 'headers;
            }
        }
    }
    Ok(out)
}

fn attributes(secure: bool, max_age_secs: u64) -> String {
    format!(
        "Path=/;{} HttpOnly; SameSite=Lax; Max-Age={max_age_secs}",
        if secure { " Secure;" } else { "" }
    )
}

/// `Set-Cookie` value that plants or refreshes a cookie.
pub fn set_cookie(name: &str, value: &str, max_age: Duration, secure: bool) -> String {
    format!("{name}={value}; {}", attributes(secure, max_age.as_secs()))
}

/// `Set-Cookie` value that clears a cookie with the attributes it was set with.
pub fn clear_cookie(name: &str, secure: bool) -> String {
    format!("{name}=; {}", attributes(secure, 0))
}

/// A fresh portal binding value: 16 random bytes, 22 base64url characters.
pub fn new_bind(rng: &dyn Rng) -> Secret {
    random_token(rng, 16)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SeededRng;
    use axum::http::HeaderValue;

    fn names() -> CookieNames {
        CookieNames {
            handle: "__Host-hopae".into(),
            bind: "__Host-hopae_bind".into(),
            portal: "__Host-hopae_portal".into(),
        }
    }

    const P: &str = "AAAAAAAAAAAAAAAAAAAAAA";
    const H: &str = "v1.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    fn hdr(v: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.append("cookie", HeaderValue::from_str(v).unwrap());
        h
    }

    #[test]
    fn reads_portal_bind_and_handle() {
        let p = read(
            &hdr(&format!("__Host-hopae_portal={P}; __Host-hopae={H}")),
            &names(),
        )
        .unwrap();
        assert_eq!(p.bind.unwrap().expose(), P);
        assert_eq!(p.handle.unwrap().expose(), H);
    }

    #[test]
    fn malformed_values_are_absent_and_the_first_well_formed_wins() {
        let p = read(
            &hdr(&format!(
                "__Host-hopae_portal=short; __Host-hopae_portal={P}; __Host-hopae_portal=BBBBBBBBBBBBBBBBBBBBBB; __Host-hopae=v1.x"
            )),
            &names(),
        )
        .unwrap();
        assert_eq!(p.bind.unwrap().expose(), P);
        assert!(p.handle.is_none());
        let none = read(&hdr("__Host-hopae_portal=AAAAAAAAAAAAAAAAAAAA!!"), &names()).unwrap();
        assert!(none.bind.is_none());
    }

    #[test]
    fn other_names_are_ignored() {
        // Development-mode names never satisfy the secure names.
        let p = read(
            &hdr(&format!(
                "hopae_portal={P}; hopae={H}; __Host-hopae_bind={P}"
            )),
            &names(),
        )
        .unwrap();
        assert!(p.bind.is_none() && p.handle.is_none());
    }

    #[test]
    fn many_cookies_stay_bounded_and_oversized_headers_are_refused() {
        let many = (0..200)
            .map(|i| format!("__Host-hopae_portal=bad{i}"))
            .collect::<Vec<_>>()
            .join("; ");
        assert!(read(&hdr(&many), &names()).unwrap().bind.is_none());
        let huge = format!("a={}", "x".repeat(MAX_COOKIE_BYTES + 1));
        assert_eq!(read(&hdr(&huge), &names()).unwrap_err(), TooLarge);
        // Several headers count together.
        let mut h = HeaderMap::new();
        for _ in 0..3 {
            h.append(
                "cookie",
                HeaderValue::from_str(&format!("a={}", "x".repeat(4000))).unwrap(),
            );
        }
        assert_eq!(read(&h, &names()).unwrap_err(), TooLarge);
    }

    #[test]
    fn set_and_clear_use_the_documented_attributes() {
        assert_eq!(
            set_cookie("__Host-hopae_portal", P, Duration::from_secs(600), true),
            format!("__Host-hopae_portal={P}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=600")
        );
        assert_eq!(
            set_cookie("hopae_portal", P, Duration::from_secs(600), false),
            format!("hopae_portal={P}; Path=/; HttpOnly; SameSite=Lax; Max-Age=600")
        );
        assert_eq!(
            clear_cookie("__Host-hopae", true),
            "__Host-hopae=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0"
        );
        assert_eq!(
            clear_cookie("hopae", false),
            "hopae=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"
        );
        for v in [
            set_cookie("n", P, Duration::from_secs(1), true),
            clear_cookie("n", true),
        ] {
            assert!(!v.contains("Domain") && !v.contains("Expires"), "{v}");
        }
    }

    #[test]
    fn new_binds_are_well_formed_and_distinct() {
        let rng = SeededRng::new(9);
        let a = new_bind(&rng);
        let b = new_bind(&rng);
        assert!(is_well_formed_bind(a.expose()));
        assert_ne!(a.expose(), b.expose());
        assert!(is_well_formed_handle(H));
    }
}
