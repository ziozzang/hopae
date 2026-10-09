//! Application resolution and return-target validation (ADR-0004).
//!
//! The return target is the only URL Hopae ever redirects an end user back
//! to. It is the original URL the gateway supplies, never a client value,
//! and its host and port must be an exact entry of the registered
//! applications: there is no suffix or wildcard mode.

use crate::event::types::{Reason, reasons};
use crate::policy::types::{AppPolicy, ConfigSnapshot, Host};

/// Longest accepted original URL, in bytes.
pub const MAX_URL_BYTES: usize = 2048;

/// The application registered for `host`: `unknown_app` when none, and
/// `app_disabled` when it is switched off. Both answer the same `403`; the
/// reason is only in the events (S005-A6).
pub fn resolve<'a>(snapshot: &'a ConfigSnapshot, host: &Host) -> Result<&'a AppPolicy, Reason> {
    match snapshot.app_for_host(host) {
        None => Err(reasons::UNKNOWN_APP),
        Some(app) if !app.enabled => Err(reasons::APP_DISABLED),
        Some(app) => Ok(app),
    }
}

/// Validate an original URL as a return target and return it normalized
/// (lower-case host, default port elided by the URL parser).
///
/// Checks, in this order: length (before any parsing), absoluteness, scheme
/// (`https`, or `http` only when `secure` is false), userinfo, fragment, host
/// in the allowlist, port in the application's ports, application enabled.
pub fn validate_return_target(
    url: &str,
    snapshot: &ConfigSnapshot,
    secure: bool,
) -> Result<url::Url, Reason> {
    if url.len() > MAX_URL_BYTES {
        return Err(reasons::TOO_LONG);
    }
    let parsed = url::Url::parse(url).map_err(|_| reasons::NOT_ABSOLUTE)?;
    match parsed.scheme() {
        "https" => {}
        "http" if !secure => {}
        "http" => return Err(reasons::INSECURE_TRANSPORT),
        _ => return Err(reasons::SCHEME),
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(reasons::USERINFO);
    }
    if parsed.fragment().is_some() {
        return Err(reasons::FRAGMENT);
    }
    let host = parsed
        .host_str()
        .and_then(|h| Host::parse(h).ok())
        .ok_or(reasons::UNKNOWN_APP)?;
    let app = snapshot.app_for_host(&host).ok_or(reasons::UNKNOWN_APP)?;
    let port = parsed.port_or_known_default().ok_or(reasons::SCHEME)?;
    // ADR-0004: the scheme's default port, plus every listed port. In
    // insecure development mode that default is 80 for `http`.
    let dev_default = !secure && parsed.scheme() == "http" && port == 80;
    if !app.ports.contains(&port) && !dev_default {
        return Err(reasons::PORT_NOT_ALLOWED);
    }
    if !app.enabled {
        return Err(reasons::APP_DISABLED);
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::types::AppId;

    fn snap(enabled: bool) -> ConfigSnapshot {
        ConfigSnapshot {
            generation: 1,
            apps: vec![AppPolicy {
                app_id: AppId::new("app"),
                hosts: vec![Host::parse("app.example.test").unwrap()],
                ports: vec![443],
                enabled,
                ..AppPolicy::default_app()
            }],
            default_app: AppPolicy::default_app(),
            providers: vec![],
        }
    }

    #[test]
    fn accepts_registered_origin_and_normalizes() {
        let s = snap(true);
        let u = validate_return_target("https://APP.example.test:443/a?x=1%202", &s, true).unwrap();
        assert_eq!(u.as_str(), "https://app.example.test/a?x=1%202");
    }

    #[test]
    fn rejects_in_documented_order() {
        let s = snap(true);
        let r = |u: &str| validate_return_target(u, &s, true).unwrap_err();
        assert_eq!(r("//app.example.test/"), reasons::NOT_ABSOLUTE);
        assert_eq!(r("javascript:alert(1)"), reasons::SCHEME);
        assert_eq!(r("http://app.example.test/"), reasons::INSECURE_TRANSPORT);
        assert_eq!(r("https://u@app.example.test/"), reasons::USERINFO);
        assert_eq!(r("https://app.example.test/#"), reasons::FRAGMENT);
        assert_eq!(r("https://app.example.test./"), reasons::UNKNOWN_APP);
        assert_eq!(r("https://[::1]/"), reasons::UNKNOWN_APP);
        assert_eq!(
            r("https://app.example.test:8443/"),
            reasons::PORT_NOT_ALLOWED
        );
        assert_eq!(
            validate_return_target("https://app.example.test/", &snap(false), true).unwrap_err(),
            reasons::APP_DISABLED
        );
    }

    #[test]
    fn http_is_accepted_only_without_secure_cookies() {
        let mut s = snap(true);
        s.apps[0].ports = vec![80];
        assert!(validate_return_target("http://app.example.test/", &s, false).is_ok());
        assert_eq!(
            validate_return_target("http://app.example.test/", &s, true).unwrap_err(),
            reasons::INSECURE_TRANSPORT
        );
    }

    #[test]
    fn insecure_mode_accepts_the_http_default_port_beside_listed_ports() {
        let s = snap(true); // ports = [443]
        assert!(validate_return_target("http://app.example.test/", &s, false).is_ok());
        assert_eq!(
            validate_return_target("http://app.example.test:8080/", &s, false).unwrap_err(),
            reasons::PORT_NOT_ALLOWED
        );
        // Secure mode never gets the exception.
        assert_eq!(
            validate_return_target("https://app.example.test:80/", &s, true).unwrap_err(),
            reasons::PORT_NOT_ALLOWED
        );
    }

    #[test]
    fn length_is_checked_before_parsing() {
        let s = snap(true);
        let long = format!("https://app.example.test/{}", "a".repeat(MAX_URL_BYTES));
        assert_eq!(
            validate_return_target(&long, &s, true).unwrap_err(),
            reasons::TOO_LONG
        );
    }
}
