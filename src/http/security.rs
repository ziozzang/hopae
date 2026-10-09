//! Security headers for every portal response, and the `Origin` check.

use axum::http::{HeaderMap, HeaderValue};
use url::Origin;

/// The pinned base content security policy: no scripts, no inline styles, no
/// framing, forms to the portal itself. A page whose form is followed by a
/// redirect to another origin widens only `form-action`, per page
/// ([`with_form_action`]); the browser enforces `form-action` on that redirect.
pub const CONTENT_SECURITY_POLICY: &str =
    "default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'";

/// Response extension a handler sets to name the extra `form-action` origins
/// of its page; the portal's outer middleware turns it into the header.
#[derive(Clone, Debug)]
pub struct FormActionOrigins(pub Vec<Origin>);

/// The policy with `form-action 'self'` plus `origins` (tuple origins only,
/// each once, in a stable order). Origins come from configuration or
/// discovery, never from request input.
pub fn csp_with_form_action(origins: &[Origin]) -> String {
    let mut list: Vec<String> = origins
        .iter()
        .filter(|o| o.is_tuple())
        .map(Origin::ascii_serialization)
        .collect();
    list.sort();
    list.dedup();
    let mut form = String::from("'self'");
    for o in &list {
        form.push(' ');
        form.push_str(o);
    }
    format!("default-src 'none'; style-src 'self'; form-action {form}; frame-ancestors 'none'")
}

/// Replace the policy in `headers` with one whose `form-action` also lists `origins`.
pub fn with_form_action(headers: &mut HeaderMap, origins: &[Origin]) {
    if let Ok(v) = HeaderValue::from_str(&csp_with_form_action(origins)) {
        headers.insert("content-security-policy", v);
    }
}

/// Set the portal's security headers, replacing any value a handler chose.
pub fn apply(headers: &mut HeaderMap) {
    headers.insert("cache-control", HeaderValue::from_static("no-store"));
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    headers.insert(
        "content-security-policy",
        HeaderValue::from_static(CONTENT_SECURITY_POLICY),
    );
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
}

/// The origin string a browser sends for `public_url` (`https://auth.example.test`,
/// default ports elided). `None` when the URL has no tuple origin.
pub fn portal_origin(public_url: &str) -> Option<String> {
    let origin = url::Url::parse(public_url).ok()?.origin();
    origin.is_tuple().then(|| origin.ascii_serialization())
}

/// Whether the `Origin` header equals the portal origin exactly. An absent
/// header, `null` and anything else are refused.
pub fn origin_allowed(origin: Option<&str>, portal_origin: &str) -> bool {
    !portal_origin.is_empty()
        && origin.is_some_and(|o| crate::crypto::ct_eq(o.as_bytes(), portal_origin.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn headers_are_the_pinned_set_and_override_handlers() {
        let mut h = HeaderMap::new();
        h.insert("cache-control", HeaderValue::from_static("public"));
        h.insert("x-frame-options", HeaderValue::from_static("SAMEORIGIN"));
        apply(&mut h);
        let get = |n: &str| {
            h.get(n)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string()
        };
        assert_eq!(get("cache-control"), "no-store");
        assert_eq!(get("x-content-type-options"), "nosniff");
        assert_eq!(get("referrer-policy"), "no-referrer");
        assert_eq!(get("x-frame-options"), "DENY");
        assert_eq!(
            get("content-security-policy"),
            "default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'"
        );
        assert!(!get("content-security-policy").contains("unsafe"));
        assert_eq!(h.get_all("cache-control").iter().count(), 1);
    }

    #[test]
    fn form_action_is_per_page_and_lists_tuple_origins_once() {
        let o = |s: &str| url::Url::parse(s).unwrap().origin();
        let mut h = HeaderMap::new();
        apply(&mut h);
        with_form_action(
            &mut h,
            &[
                o("https://accounts.example.test/o/auth?x=1"),
                o("https://accounts.example.test/other"),
                o("http://127.0.0.1:9000/a"),
                Origin::new_opaque(),
            ],
        );
        let csp = h["content-security-policy"].to_str().unwrap().to_string();
        assert_eq!(
            csp,
            "default-src 'none'; style-src 'self'; form-action 'self' http://127.0.0.1:9000 https://accounts.example.test; frame-ancestors 'none'"
        );
        assert_eq!(csp_with_form_action(&[]), CONTENT_SECURITY_POLICY);
        assert_eq!(h["x-frame-options"], "DENY");
    }

    #[test]
    fn portal_origin_normalizes_default_ports() {
        assert_eq!(
            portal_origin("https://auth.example.test").as_deref(),
            Some("https://auth.example.test")
        );
        assert_eq!(
            portal_origin("https://auth.example.test:443/").as_deref(),
            Some("https://auth.example.test")
        );
        assert_eq!(
            portal_origin("http://127.0.0.1:8700").as_deref(),
            Some("http://127.0.0.1:8700")
        );
        assert_eq!(portal_origin("not a url"), None);
    }

    #[test]
    fn origin_must_match_exactly() {
        let o = "https://auth.example.test";
        assert!(origin_allowed(Some("https://auth.example.test"), o));
        for bad in [
            None,
            Some("null"),
            Some(""),
            Some("https://evil.example.org"),
            Some("https://auth.example.test.evil.org"),
            Some("http://auth.example.test"),
            Some("https://auth.example.test:8443"),
            Some("https://auth.example.test/"),
            Some("HTTPS://AUTH.EXAMPLE.TEST.evil"),
        ] {
            assert!(!origin_allowed(bad, o), "{bad:?}");
        }
    }
}
