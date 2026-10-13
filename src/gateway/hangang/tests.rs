//! Unit tests of the Hangang adapter: request parsing and decision rendering.
//! Scenario references: S001-4/5/A7, S004-2/6/7/11/A1/A5/A6/A8, S003-2.

use std::time::Duration;

use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::Response;

use super::*;
use crate::app::CallerKeys;
use crate::crypto::{Secret, Timestamp};
use crate::event::types::{Reason, reasons};
use crate::identity::types::{NormalizedEmail, UserId};
use crate::policy::types::Host;
use crate::provider::types::ProviderId;
use crate::session::types::{Aal, FactorEntry, FactorKind, Generations, SessionId};
use crate::verify::types::*;

const KEY: &str = "current-key-value";
const NEXT: &str = "next-key-value-xx";
const HANDLE: &str = "v1.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const BIND: &str = "BBBBBBBBBBBBBBBBBBBBBB";

fn cfg() -> GatewayConfig {
    GatewayConfig {
        cookies: CookieNames {
            handle: "__Host-hopae".into(),
            bind: "__Host-hopae_bind".into(),
            portal: "__Host-hopae_portal".into(),
        },
        portal_url: url::Url::parse("https://auth.example.test/").unwrap(),
        secure: true,
    }
}

fn keys() -> CallerKeys {
    CallerKeys::new(Some(Secret::new(KEY.into())), None, false)
        .with_counter(std::sync::Arc::new(|_, _| {}))
}

fn insecure_cfg() -> GatewayConfig {
    GatewayConfig {
        cookies: CookieNames {
            handle: "hopae".into(),
            bind: "hopae_bind".into(),
            portal: "hopae_portal".into(),
        },
        portal_url: url::Url::parse("http://auth.example.test/").unwrap(),
        secure: false,
    }
}

fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
    let mut h = HeaderMap::new();
    for (k, v) in pairs {
        h.append(
            HeaderName::from_bytes(k.as_bytes()).unwrap(),
            HeaderValue::from_str(v).unwrap(),
        );
    }
    h
}

fn base(url: &str) -> Vec<(&'static str, String)> {
    let u = url::Url::parse(url).unwrap();
    vec![
        ("x-hopae-gateway-key", KEY.to_string()),
        ("x-original-url", url.to_string()),
        ("x-forwarded-host", u.host_str().unwrap().to_string()),
        ("x-forwarded-proto", u.scheme().to_string()),
        ("x-forwarded-for", "203.0.113.9".to_string()),
        ("sec-fetch-dest", "document".to_string()),
    ]
}

fn hm(v: &[(&str, String)]) -> HeaderMap {
    let r: Vec<(&str, &str)> = v.iter().map(|(k, v)| (*k, v.as_str())).collect();
    headers(&r)
}

fn with(
    mut v: Vec<(&'static str, String)>,
    k: &'static str,
    val: &str,
) -> Vec<(&'static str, String)> {
    v.retain(|(n, _)| *n != k);
    v.push((k, val.to_string()));
    v
}

fn without(mut v: Vec<(&'static str, String)>, k: &str) -> Vec<(&'static str, String)> {
    v.retain(|(n, _)| *n != k);
    v
}

fn ok(v: &[(&str, String)]) -> Parsed {
    match parse_for_tests(&cfg(), &hm(v), "r1".into()) {
        Ok(p) => p,
        Err(r) => panic!("expected parse to succeed, got {:?}", denial(&r.decision)),
    }
}

fn denial(d: &Decision) -> (Reason, DenyKind) {
    match d {
        Decision::Deny { reason, kind } => (*reason, *kind),
        _ => panic!("not a denial"),
    }
}

fn refused(c: &GatewayConfig, h: &HeaderMap) -> Rejected {
    match parse_for_tests(c, h, "r1".into()) {
        Ok(_) => panic!("expected the request to be refused"),
        Err(r) => *r,
    }
}

fn reason_of(c: &GatewayConfig, v: &[(&str, String)]) -> (&'static str, DenyKind) {
    let r = refused(c, &hm(v));
    let (reason, kind) = denial(&r.decision);
    (reason.0, kind)
}

// ---- parse ---------------------------------------------------------------

#[test]
fn parse_builds_the_neutral_input() {
    let v = with(
        base("https://app.example.test/admin/x?q=1"),
        "user-agent",
        "UA1",
    );
    let v = with(v, "x-hangang-route-id", "app-example");
    let v = with(v, "x-original-method", "GET");
    let v = with(
        v,
        "cookie",
        &format!("a=b; __Host-hopae={HANDLE}; __Host-hopae_bind={BIND}; c=d"),
    );
    let p = ok(&v);
    let i = &p.input;
    assert_eq!(
        i.original_url.as_str(),
        "https://app.example.test/admin/x?q=1"
    );
    assert_eq!(i.canonical_path.as_str(), "/admin/x");
    assert_eq!(
        i.client_ip,
        "203.0.113.9".parse::<std::net::IpAddr>().unwrap()
    );
    assert_eq!(i.host, Host::parse("app.example.test").unwrap());
    assert_eq!(i.port, 443);
    assert_eq!(i.proto, Scheme::Https);
    assert_eq!(i.method, http::Method::GET);
    assert_eq!(i.route_id.as_deref(), Some("app-example"));
    assert_eq!(i.cookie_handle.as_ref().unwrap().expose(), HANDLE);
    assert_eq!(i.bind_cookie.as_ref().unwrap().expose(), BIND);
    assert_eq!(i.user_agent.as_deref(), Some("UA1"));
    assert!(matches!(i.navigation, Navigation::Document));
    assert!(matches!(i.handoff, Handoff::None));
    assert_eq!(i.contract, 1);
    assert!(matches!(
        i.caller,
        CallerAuth::Keyed {
            which: KeySlot::Current
        }
    ));
    assert_eq!(i.request_id, "r1");
    assert_eq!(p.env.bind_cookie.as_deref(), Some(BIND));
    assert!(!p.env.handoff_seen);
}

#[test]
fn parse_explicit_port_and_real_ip_fallback() {
    let v = base("https://app.example.test:8443/");
    let v = with(v, "x-forwarded-host", "app.example.test:8443");
    let v = without(v, "x-forwarded-for");
    let v = with(v, "x-real-ip", "2001:db8::1");
    let p = ok(&v);
    assert_eq!(p.input.port, 8443);
    assert_eq!(
        p.input.client_ip,
        "2001:db8::1".parse::<std::net::IpAddr>().unwrap()
    );
    // The default port is implied by the scheme.
    assert_eq!(ok(&base("https://app.example.test/")).input.port, 443);
}

/// Authenticate with `keys` the way the listener does, then parse.
fn authed(
    keys: &CallerKeys,
    c: &GatewayConfig,
    v: &[(&str, String)],
) -> Result<Parsed, Box<Rejected>> {
    let h = hm(v);
    let caller = authenticate(keys, &h, "r")?;
    parse(c, &h, "r".into(), caller)
}

#[test]
fn adapter_s004_a8_caller_key_is_checked_first_and_in_constant_time() {
    // No header at all besides a wrong key: the answer is the caller refusal,
    // not a contract violation.
    for h in [
        headers(&[]),
        headers(&[("x-hopae-gateway-key", "wrong")]),
        headers(&[("x-hopae-gateway-key", "")]),
    ] {
        let r = *authenticate(&keys(), &h, "r1").err().expect("refused");
        let (reason, kind) = denial(&r.decision);
        assert_eq!(reason, reasons::CALLER_UNAUTHORIZED);
        assert_eq!(kind, DenyKind::Forbidden);
    }
    // Right value twice is refused.
    let v = base("https://app.example.test/");
    let mut h = hm(&v);
    h.append("x-hopae-gateway-key", HeaderValue::from_static(KEY));
    assert_eq!(
        denial(&authenticate(&keys(), &h, "r").err().unwrap().decision).0,
        reasons::CALLER_UNAUTHORIZED
    );
    // Rotation: the next key is accepted when configured, a third value never.
    let both = CallerKeys::new(
        Some(Secret::new(KEY.into())),
        Some(Secret::new(NEXT.into())),
        false,
    )
    .with_counter(std::sync::Arc::new(|_, _| {}));
    let next = with(
        base("https://app.example.test/"),
        "x-hopae-gateway-key",
        NEXT,
    );
    let p = authed(&both, &cfg(), &next).ok().unwrap();
    assert!(matches!(
        p.input.caller,
        CallerAuth::Keyed {
            which: KeySlot::Next
        }
    ));
    let cur = authed(&both, &cfg(), &base("https://app.example.test/"))
        .ok()
        .unwrap();
    assert!(matches!(
        cur.input.caller,
        CallerAuth::Keyed {
            which: KeySlot::Current
        }
    ));
    let third = with(
        base("https://app.example.test/"),
        "x-hopae-gateway-key",
        "third",
    );
    assert!(authed(&both, &cfg(), &third).is_err());
    // Without a configured next key its value is refused.
    assert!(authed(&keys(), &cfg(), &next).is_err());
    // A configured key that is unset accepts nothing, not even the empty string.
    let none = CallerKeys::new(None, None, false).with_counter(std::sync::Arc::new(|_, _| {}));
    let empty = with(base("https://app.example.test/"), "x-hopae-gateway-key", "");
    assert!(authed(&none, &cfg(), &empty).is_err());
}

#[test]
fn adapter_s004_a8_unauthenticated_caller_is_a_development_switch() {
    let dev = CallerKeys::new(None, None, true).with_counter(std::sync::Arc::new(|_, _| {}));
    let v = without(base("https://app.example.test/"), "x-hopae-gateway-key");
    let p = authed(&dev, &cfg(), &v).ok().unwrap();
    assert!(matches!(p.input.caller, CallerAuth::Unauthenticated));
}

#[test]
fn adapter_s004_a8_key_compare_equal_length_inputs() {
    use crate::crypto::ct_eq;
    // The one comparison `CallerKeys` uses, on equal-length and unequal inputs.
    assert!(ct_eq(b"abcdefgh", b"abcdefgh"));
    assert!(!ct_eq(b"abcdefgh", b"abcdefgx"));
    assert!(!ct_eq(b"abcdefgh", b"xbcdefgh"));
    assert!(!ct_eq(b"abcdefgh", b"abcdefg"));
    assert!(!ct_eq(b"abcdefgh", b"abcdefghi"));
    assert!(!ct_eq(b"abcdefgh", b""));
}

#[test]
fn adapter_s004_6_contract_header_and_required_headers() {
    let b = || base("https://app.example.test/x");
    // Version: absent and 1 are v1; higher is unsupported; garbage is a violation.
    assert_eq!(ok(&with(b(), "x-hopae-contract", "1")).input.contract, 1);
    let (r, k) = reason_of(&cfg(), &with(b(), "x-hopae-contract", "2"));
    assert_eq!(
        (r, k),
        ("contract_unsupported", DenyKind::ContractViolation)
    );
    assert_eq!(
        reason_of(&cfg(), &with(b(), "x-hopae-contract", "one")).0,
        "contract_violation"
    );
    assert_eq!(
        reason_of(&cfg(), &with(b(), "x-hopae-contract", "")).0,
        "contract_violation"
    );
    // Missing required headers.
    for name in [
        "x-original-url",
        "x-forwarded-host",
        "x-forwarded-proto",
        "x-forwarded-for",
    ] {
        let (r, k) = reason_of(&cfg(), &without(b(), name));
        assert_eq!(
            (r, k),
            ("contract_violation", DenyKind::ContractViolation),
            "{name}"
        );
    }
    let rej = refused(&cfg(), &hm(&without(b(), "x-original-url")));
    assert_eq!(rej.env.detail, Some("x-original-url"));
}

#[test]
fn adapter_s004_7_and_a5_host_mismatch_and_duplicates() {
    let v = with(
        base("https://app.example.test/"),
        "x-forwarded-host",
        "other.example.org",
    );
    assert_eq!(reason_of(&cfg(), &v).0, "contract_violation");
    // Port in the forwarded host must agree.
    let v = with(
        base("https://app.example.test/"),
        "x-forwarded-host",
        "app.example.test:8443",
    );
    assert_eq!(reason_of(&cfg(), &v).0, "contract_violation");
    // Duplicated context headers.
    for name in [
        "x-forwarded-host",
        "x-original-url",
        "x-forwarded-proto",
        "x-forwarded-for",
    ] {
        let mut h = hm(&base("https://app.example.test/"));
        let first = h.get(name).unwrap().clone();
        h.append(
            HeaderName::from_bytes(name.as_bytes()).unwrap(),
            HeaderValue::from_static("other.example.org"),
        );
        assert_eq!(h.get_all(name).iter().count(), 2);
        let _ = first;
        assert_eq!(
            denial(&refused(&cfg(), &h).decision).0,
            reasons::CONTRACT_VIOLATION,
            "{name}"
        );
    }
    // Two different client address headers.
    let v = with(
        base("https://app.example.test/"),
        "x-real-ip",
        "203.0.113.10",
    );
    assert_eq!(reason_of(&cfg(), &v).0, "contract_violation");
    // A list is not a single address.
    let v = with(
        base("https://app.example.test/"),
        "x-forwarded-for",
        "203.0.113.9, 10.0.0.1",
    );
    assert_eq!(reason_of(&cfg(), &v).0, "contract_violation");
}

#[test]
fn adapter_s001_a7_and_s004_a6_plain_http_is_refused_when_secure() {
    let v = base("http://app.example.test/");
    let (r, k) = reason_of(&cfg(), &v);
    assert_eq!((r, k), ("insecure_transport", DenyKind::ContractViolation));
    // Proto and URL scheme must agree.
    let v = with(
        base("https://app.example.test/"),
        "x-forwarded-proto",
        "http",
    );
    assert_eq!(reason_of(&cfg(), &v).0, "insecure_transport");
    let v = with(
        base("http://app.example.test/"),
        "x-forwarded-proto",
        "https",
    );
    assert_eq!(reason_of(&cfg(), &v).0, "contract_violation");
    let v = with(
        base("https://app.example.test/"),
        "x-forwarded-proto",
        "ftp",
    );
    assert_eq!(reason_of(&cfg(), &v).0, "contract_violation");
    // Development mode accepts it.
    let p = parse_for_tests(
        &insecure_cfg(),
        &hm(&base("http://app.example.test/")),
        "r".into(),
    )
    .ok()
    .unwrap();
    assert_eq!(p.input.proto, Scheme::Http);
    assert_eq!(p.input.port, 80);
}

#[test]
fn original_url_must_be_a_plain_absolute_url() {
    let too_long = format!("https://app.example.test/{}", "a".repeat(2100));
    for bad in [
        too_long.as_str(),
        "https://user:pw@app.example.test/",
        "https://app.example.test/#frag",
        "/relative/path",
        "not a url",
        "https://app.example.test:99999/",
    ] {
        let mut v = base("https://app.example.test/");
        v = with(v, "x-original-url", bad);
        assert_eq!(reason_of(&cfg(), &v).0, "contract_violation", "{bad:.40}");
    }
}

#[test]
fn canonical_path_rules_and_agreement() {
    // Computed from the raw path, not from the URL parser's normalization.
    for (url, expect) in [
        ("https://app.example.test/%61dmin/x", "/admin/x"),
        ("https://app.example.test", "/"),
        ("https://app.example.test/?q=%2F..", "/"),
    ] {
        assert_eq!(
            ok(&base(url)).input.canonical_path.as_str(),
            expect,
            "{url}"
        );
    }
    for url in [
        "https://app.example.test/admin/%2e%2e/x",
        "https://app.example.test/admin//x",
        "https://app.example.test/%2561dmin/x",
        "https://app.example.test/a/../b",
        "https://app.example.test/a/./b",
    ] {
        let (r, k) = reason_of(&cfg(), &base(url));
        assert_eq!((r, k), ("path_not_canonical", DenyKind::Forbidden), "{url}");
    }
    // The gateway's own value must agree.
    let v = with(
        base("https://app.example.test/%61dmin/x"),
        "x-hangang-canonical-path",
        "/admin/x",
    );
    assert_eq!(ok(&v).input.canonical_path.as_str(), "/admin/x");
    let v = with(
        base("https://app.example.test/%61dmin/x"),
        "x-hangang-canonical-path",
        "/other",
    );
    assert_eq!(
        reason_of(&cfg(), &v),
        ("canonical_path_mismatch", DenyKind::Forbidden)
    );
}

#[test]
fn adapter_s001_5_navigation_from_fetch_metadata_then_accept() {
    let nav = |extra: &[(&'static str, &str)]| {
        let mut v = without(base("https://app.example.test/"), "sec-fetch-dest");
        for (k, val) in extra {
            v = with(v, k, val);
        }
        matches!(ok(&v).input.navigation, Navigation::Document)
    };
    assert!(nav(&[("sec-fetch-dest", "document")]));
    assert!(nav(&[
        ("sec-fetch-dest", "document"),
        ("sec-fetch-mode", "navigate")
    ]));
    assert!(!nav(&[
        ("sec-fetch-dest", "empty"),
        ("sec-fetch-mode", "cors"),
        ("accept", "application/json")
    ]));
    // Fetch metadata wins over accept.
    assert!(!nav(&[
        ("sec-fetch-dest", "empty"),
        ("accept", "text/html")
    ]));
    assert!(!nav(&[
        ("sec-fetch-dest", "image"),
        ("accept", "text/html")
    ]));
    // Fallback to accept.
    assert!(nav(&[("accept", "text/html,application/xhtml+xml")]));
    assert!(nav(&[("accept", "application/xhtml+xml;q=0.9,*/*;q=0.8")]));
    assert!(nav(&[("accept", "text/HTML; q=0.9")]));
    assert!(!nav(&[("accept", "*/*")]));
    assert!(!nav(&[("accept", "application/json")]));
    assert!(!nav(&[("accept", "text/htmlx")]));
    assert!(!nav(&[]));
}

#[test]
fn adapter_s003_2_handoff_parameter_is_recognized_by_the_adapter() {
    let p = ok(&base(
        "https://app.example.test/admin/x?q=1&%5Fhopae%5Fhandoff=K1%2B&z=2",
    ));
    match &p.input.handoff {
        Handoff::Code(c) => assert_eq!(c.expose(), "K1+"),
        _ => panic!("expected a code"),
    }
    assert!(p.env.handoff_seen);
    assert!(matches!(
        ok(&base(
            "https://app.example.test/?_hopae_handoff=a&_hopae_handoff=b"
        ))
        .input
        .handoff,
        Handoff::Ambiguous
    ));
    assert!(
        ok(&base(
            "https://app.example.test/?_hopae_handoff=a&_hopae_handoff=b"
        ))
        .env
        .handoff_seen
    );
}

#[test]
fn adapter_s004_a1_cookies_are_bounded_and_read_by_name() {
    // The first well-formed pair wins; later pairs are not consulted.
    let other = "v1.CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC";
    let c = format!("__Host-hopae=bad; __Host-hopae={HANDLE}; __Host-hopae={other}");
    let p = ok(&with(base("https://app.example.test/"), "cookie", &c));
    assert_eq!(p.input.cookie_handle.unwrap().expose(), HANDLE);
    // Only malformed values: the first one is passed on so the core can name it.
    let p = ok(&with(
        base("https://app.example.test/"),
        "cookie",
        "__Host-hopae=v1.short",
    ));
    assert_eq!(p.input.cookie_handle.unwrap().expose(), "v1.short");
    // Malformed binding values are never echoed back for refresh.
    let p = ok(&with(
        base("https://app.example.test/"),
        "cookie",
        "__Host-hopae_bind=short",
    ));
    assert_eq!(p.env.bind_cookie, None);
    // Other names, including prefixes of ours, are ignored.
    let p = ok(&with(
        base("https://app.example.test/"),
        "cookie",
        &format!("hopae={HANDLE}; x__Host-hopae={HANDLE}"),
    ));
    assert!(p.input.cookie_handle.is_none());
    // 8 KiB is the ceiling.
    let big = format!("a={}", "x".repeat(8200));
    let r = refused(
        &cfg(),
        &hm(&with(base("https://app.example.test/"), "cookie", &big)),
    );
    let (reason, kind) = denial(&r.decision);
    assert_eq!(
        (reason.0, kind),
        ("header_too_large", DenyKind::ContractViolation)
    );
    // Many repeated pairs stay within the ceiling and are cheap.
    let many = "__Host-hopae=v1.x; ".repeat(200);
    assert!(
        parse_for_tests(
            &cfg(),
            &hm(&with(base("https://app.example.test/"), "cookie", &many)),
            "r".into()
        )
        .is_ok()
    );
}

#[test]
fn user_agent_is_truncated_to_one_kib() {
    let long = "u".repeat(3000);
    let p = ok(&with(
        base("https://app.example.test/"),
        "user-agent",
        &long,
    ));
    assert_eq!(p.input.user_agent.unwrap().len(), 1024);
    let multibyte = "한".repeat(600);
    let p = ok(&with(
        base("https://app.example.test/"),
        "user-agent",
        &multibyte,
    ));
    let ua = p.input.user_agent.unwrap();
    assert!(ua.len() <= 1024 && ua.is_char_boundary(ua.len()));
}

// ---- render --------------------------------------------------------------

fn identity() -> Identity {
    Identity {
        receipt_seal: None,
        user_id: UserId::new("u_1"),
        email: Some(NormalizedEmail::parse("a@example.test").unwrap()),
        preferred_username: Some("alice".into()),
        groups: vec![],
        session_id: SessionId::new("s_1"),
        provider_id: ProviderId::new("mock"),
        auth_time: Timestamp(1_800_000_000_000),
        expires_at: Timestamp(1_800_043_200_000),
        aal: Aal::One,
        factors: vec![FactorEntry {
            kind: FactorKind::Oidc,
            provider: Some(ProviderId::new("mock")),
            at: Timestamp(1_800_000_000_000),
        }],
        generations: Generations {
            session: 2,
            user: 3,
            config: 5,
        },
    }
}

fn env() -> RenderEnv {
    RenderEnv {
        request_id: "r_test".into(),
        original_url: Some(
            url::Url::parse("https://app.example.test/admin/x?q=1&_hopae_handoff=K1").unwrap(),
        ),
        bind_cookie: None,
        handoff_seen: false,
        detail: None,
    }
}

fn r(d: Decision, nav: Navigation) -> Response {
    render(d, nav, &env(), &cfg())
}

fn h<'a>(resp: &'a Response, name: &str) -> Option<&'a str> {
    resp.headers().get(name).map(|v| v.to_str().unwrap())
}

fn all<'a>(resp: &'a Response, name: &str) -> Vec<&'a str> {
    resp.headers()
        .get_all(name)
        .iter()
        .map(|v| v.to_str().unwrap())
        .collect()
}

async fn body(resp: Response) -> String {
    let b = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    String::from_utf8(b.to_vec()).unwrap()
}

#[test]
fn adapter_s004_1_allow_emits_the_identity_headers() {
    let resp = r(
        Decision::Allow {
            identity: identity(),
            cache: Cacheability::NoStore,
        },
        Navigation::Document,
    );
    assert_eq!(resp.status(), StatusCode::OK);
    for (k, v) in [
        ("x-forwarded-user", "u_1"),
        ("x-forwarded-email", "a@example.test"),
        ("x-forwarded-preferred-username", "alice"),
        ("x-hopae-session", "s_1"),
        ("x-hopae-provider", "mock"),
        ("x-hopae-auth-time", "1800000000"),
        ("x-hopae-expires", "1800043200"),
        ("x-hopae-aal", "1"),
        ("x-hopae-factors", "oidc:mock"),
        ("x-hopae-contract", "1"),
        ("x-hopae-gen", "s2.u3.c5"),
        ("x-hopae-reason", "ok"),
        ("cache-control", "no-store"),
    ] {
        assert_eq!(h(&resp, k), Some(v), "{k}");
    }
    assert!(h(&resp, "x-forwarded-groups").is_none());
    assert!(h(&resp, "x-hopae-fresh-until").is_none());
    assert!(resp.headers().get("set-cookie").is_none());
    assert!(resp.headers().get("x-hangang-auth-terminal").is_none());
}

#[test]
fn adapter_s004_2_non_ascii_values_are_percent_encoded() {
    let mut id = identity();
    id.preferred_username = Some("Alice 김".into());
    id.groups = vec!["admin".into(), "ops team".into(), "a,b".into()];
    id.factors.push(FactorEntry {
        kind: FactorKind::Totp,
        provider: None,
        at: Timestamp(0),
    });
    let resp = r(
        Decision::Allow {
            identity: id,
            cache: Cacheability::NoStore,
        },
        Navigation::Document,
    );
    assert_eq!(
        h(&resp, "x-forwarded-preferred-username"),
        Some("Alice%20%EA%B9%80")
    );
    assert_eq!(
        h(&resp, "x-forwarded-groups"),
        Some("admin,ops%20team,a%2Cb")
    );
    assert_eq!(h(&resp, "x-hopae-factors"), Some("oidc:mock,totp"));
    for (_, v) in resp.headers() {
        assert!(v.as_bytes().iter().all(|b| (0x20..0x7f).contains(b)));
    }
}

#[test]
fn omitted_when_absent_and_aal2() {
    let mut id = identity();
    id.email = None;
    id.preferred_username = None;
    id.aal = Aal::Two;
    let resp = r(
        Decision::Allow {
            identity: id,
            cache: Cacheability::NoStore,
        },
        Navigation::Document,
    );
    assert!(h(&resp, "x-forwarded-email").is_none());
    assert!(h(&resp, "x-forwarded-preferred-username").is_none());
    assert_eq!(h(&resp, "x-hopae-aal"), Some("2"));
}

#[test]
fn adapter_s004_8_private_cacheability_carries_the_deadline() {
    let cache = Cacheability::Private {
        max_age: Duration::from_secs(5),
        fresh_until: Timestamp(1_800_000_065_000),
    };
    let resp = r(
        Decision::Allow {
            identity: identity(),
            cache,
        },
        Navigation::Document,
    );
    assert_eq!(h(&resp, "cache-control"), Some("private, max-age=5"));
    assert_eq!(h(&resp, "x-hopae-fresh-until"), Some("1800000065000"));
    // A request that matched the reserved-parameter rule is never cacheable.
    let mut e = env();
    e.handoff_seen = true;
    let cache = Cacheability::Private {
        max_age: Duration::from_secs(5),
        fresh_until: Timestamp(1),
    };
    let resp = render(
        Decision::Allow {
            identity: identity(),
            cache,
        },
        Navigation::Document,
        &e,
        &cfg(),
    );
    assert_eq!(h(&resp, "cache-control"), Some("no-store"));
    assert!(h(&resp, "x-hopae-fresh-until").is_none());
}

#[test]
fn oversized_identity_values_fail_closed() {
    let mut id = identity();
    id.groups = (0..400).map(|i| format!("group-number-{i:04}")).collect();
    let resp = r(
        Decision::Allow {
            identity: id,
            cache: Cacheability::NoStore,
        },
        Navigation::Document,
    );
    assert!(!resp.status().is_success());
    assert!(resp.headers().get("x-forwarded-user").is_none());
    let mut id = identity();
    id.user_id = UserId::new("u_".to_string() + &"x".repeat(80));
    let resp = r(
        Decision::Allow {
            identity: id,
            cache: Cacheability::NoStore,
        },
        Navigation::Document,
    );
    assert!(!resp.status().is_success());
    // A long username is truncated, never fatal; an over-long email is dropped.
    let mut id = identity();
    id.preferred_username = Some("é".repeat(300));
    let resp = r(
        Decision::Allow {
            identity: id,
            cache: Cacheability::NoStore,
        },
        Navigation::Document,
    );
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(h(&resp, "x-forwarded-preferred-username").unwrap().len() <= 256);
}

const BIND_ATTRS: &str = "Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=600";

#[test]
fn adapter_s001_1_document_login_is_a_302_to_the_portal_with_the_bind_cookie() {
    let d = Decision::Login {
        transaction: Some(Secret::new("T1".into())),
        bind: BindAction::Plant(Secret::new("B1".into())),
        kind: LoginKind::Login,
        clear_handle: false,
        cause: None,
    };
    let resp = r(d, Navigation::Document);
    assert_eq!(resp.status(), StatusCode::FOUND);
    assert_eq!(
        h(&resp, "location"),
        Some("https://auth.example.test/login?txn=T1")
    );
    assert_eq!(
        all(&resp, "set-cookie"),
        vec![format!("__Host-hopae_bind=B1; {BIND_ATTRS}").as_str()]
    );
    assert_eq!(h(&resp, "cache-control"), Some("no-store"));
    assert_eq!(h(&resp, "x-hopae-reason"), Some("login_required"));
    assert_eq!(h(&resp, "x-hopae-contract"), Some("1"));
}

#[test]
fn login_keep_refreshes_a_well_formed_bind_and_clear_handle_clears() {
    let keep = |clear| Decision::Login {
        transaction: Some(Secret::new("T2".into())),
        bind: BindAction::Keep,
        kind: LoginKind::Login,
        clear_handle: clear,
        cause: None,
    };
    // Nothing presented: nothing set.
    let resp = r(keep(false), Navigation::Document);
    assert!(resp.headers().get("set-cookie").is_none());
    // Presented: same value, fresh Max-Age.
    let mut e = env();
    e.bind_cookie = Some(BIND.into());
    let resp = render(keep(true), Navigation::Document, &e, &cfg());
    assert_eq!(
        all(&resp, "set-cookie"),
        vec![
            format!("__Host-hopae_bind={BIND}; {BIND_ATTRS}").as_str(),
            "__Host-hopae=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0",
        ]
    );
}

#[test]
fn step_up_login_goes_to_the_step_up_page() {
    let d = Decision::Login {
        transaction: Some(Secret::new("T3".into())),
        bind: BindAction::Keep,
        kind: LoginKind::StepUp,
        clear_handle: false,
        cause: None,
    };
    let resp = r(d, Navigation::Document);
    assert_eq!(resp.status(), StatusCode::FOUND);
    assert_eq!(
        h(&resp, "location"),
        Some("https://auth.example.test/stepup?txn=T3")
    );
    assert_eq!(h(&resp, "x-hopae-reason"), Some("step_up_required"));
}

#[tokio::test]
async fn adapter_s001_4_non_document_login_is_401_json_without_cookies() {
    for (kind, error) in [
        (LoginKind::Login, "login_required"),
        (LoginKind::StepUp, "step_up_required"),
    ] {
        let d = Decision::Login {
            transaction: None,
            bind: BindAction::Keep,
            kind,
            clear_handle: true,
            cause: None,
        };
        let resp = r(d, Navigation::Other);
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(h(&resp, "content-type"), Some("application/json"));
        assert_eq!(
            h(&resp, "www-authenticate"),
            Some("Hopae realm=\"auth.example.test\"")
        );
        assert_eq!(h(&resp, "cache-control"), Some("no-store"));
        assert!(resp.headers().get("set-cookie").is_none());
        assert!(resp.headers().get("location").is_none());
        let v: serde_json::Value = serde_json::from_str(&body(resp).await).unwrap();
        assert_eq!(v["error"], error);
        assert_eq!(
            v["login"], "https://app.example.test/admin/x?q=1",
            "handoff parameter removed"
        );
    }
}

#[test]
fn a_document_login_without_a_transaction_still_fails_closed() {
    let d = Decision::Login {
        transaction: None,
        bind: BindAction::Keep,
        kind: LoginKind::Login,
        clear_handle: false,
        cause: None,
    };
    let resp = r(d, Navigation::Document);
    assert!(!resp.status().is_success());
    assert!(resp.headers().get("location").is_none());
}

#[test]
fn entry_point_redirects_render_302_with_the_contract_headers() {
    // ADR-0015: the already-authenticated redirect names the target and sets no cookie.
    let resp = r(
        Decision::AlreadyAuthenticated {
            location: url::Url::parse("https://app.example.test/admin/x").unwrap(),
        },
        Navigation::Document,
    );
    assert_eq!(resp.status(), StatusCode::FOUND);
    assert_eq!(
        h(&resp, "location"),
        Some("https://app.example.test/admin/x")
    );
    assert!(resp.headers().get("set-cookie").is_none());
    assert_eq!(h(&resp, "cache-control"), Some("no-store"));
    assert_eq!(h(&resp, "x-hopae-reason"), Some("already_authenticated"));

    // The logout ticket goes to the portal and clears nothing...
    let resp = r(
        Decision::LogoutEntry {
            transaction: Secret::new("T1".into()),
            clear_handle: false,
            cause: None,
        },
        Navigation::Document,
    );
    assert_eq!(resp.status(), StatusCode::FOUND);
    assert_eq!(
        h(&resp, "location"),
        Some("https://auth.example.test/logout?txn=T1")
    );
    assert!(resp.headers().get("set-cookie").is_none());
    assert_eq!(h(&resp, "x-hopae-reason"), Some("logout_entry"));
    // ...except a refused handle, which is cleared as on every 302.
    let resp = r(
        Decision::LogoutEntry {
            transaction: Secret::new("T1".into()),
            clear_handle: true,
            cause: None,
        },
        Navigation::Document,
    );
    assert_eq!(
        all(&resp, "set-cookie"),
        vec!["__Host-hopae=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0"]
    );

    // The direct logout: the portal's signed-out page by reference, handle cleared,
    // the binding cookie untouched, no URL in the redirect.
    let resp = r(
        Decision::LoggedOut {
            transaction: Secret::new("T2".into()),
        },
        Navigation::Document,
    );
    assert_eq!(resp.status(), StatusCode::FOUND);
    assert_eq!(
        h(&resp, "location"),
        Some("https://auth.example.test/signed-out?txn=T2")
    );
    assert_eq!(
        all(&resp, "set-cookie"),
        vec!["__Host-hopae=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0"]
    );
    assert_eq!(h(&resp, "x-hopae-reason"), Some("logout"));

    // Both entry-point denials share one error name, with their own reason header.
    for reason in [reasons::RESERVED_PATH, reasons::ENTRY_POINT_NOT_DOCUMENT] {
        let resp = r(
            Decision::Deny {
                reason,
                kind: DenyKind::Forbidden,
            },
            Navigation::Document,
        );
        assert_eq!(resp.status(), StatusCode::FOUND.max(StatusCode::FORBIDDEN));
        assert_eq!(h(&resp, "x-hopae-reason"), Some(reason.0));
        assert!(resp.headers().get("set-cookie").is_none());
    }
}

#[test]
fn entry_point_return_is_resolved_by_the_adapter() {
    let url = |q: &str| format!("https://app.example.test/_hopae/logout?{q}");
    let ret = |q: &str| ok(&base(&url(q))).input.entry_return;
    assert_eq!(
        ok(&base("https://app.example.test/_hopae/logout"))
            .input
            .entry_return,
        EntryReturn::Absent
    );
    // A path-absolute reference is resolved against the request origin.
    match ret("return=%2Fdocs%2Fbye%3Fq%3D1") {
        EntryReturn::Candidate {
            url,
            canonical_path,
        } => {
            assert_eq!(url, "https://app.example.test/docs/bye?q=1");
            assert_eq!(canonical_path.as_str(), "/docs/bye");
        }
        other => panic!("{other:?}"),
    }
    // An absolute URL is kept as written; the core validates it.
    match ret("return=https%3A%2F%2Fother.example.org%2F") {
        EntryReturn::Candidate { url, .. } => assert_eq!(url, "https://other.example.org/"),
        other => panic!("{other:?}"),
    }
    for bad in [
        "return=%2F%2Fevil.example.org%2F",
        "return=%2F%5Cevil.example.org",
        "return=%2Fa%0Ab",
        "return=",
        "return=%2Fa&return=%2Fb",
        "return=%2Fx%3F_hopae_handoff%3DK",
        "return=%2Fa%2F..%2Fb",
        "return=%2Fa%252e%252e%2Fb%2F%2F",
    ] {
        assert_eq!(ret(bad), EntryReturn::Invalid, "{bad}");
    }
    // Other paths never carry a resolved return.
    let v = base("https://app.example.test/x?return=%2Fa");
    assert_eq!(ok(&v).input.entry_return, EntryReturn::Absent);
}

#[test]
fn fetch_site_is_parsed_and_a_repeat_is_a_contract_violation() {
    let fetch = |value: Option<&str>| {
        let v = match value {
            Some(x) => with(base("https://app.example.test/x"), "sec-fetch-site", x),
            None => base("https://app.example.test/x"),
        };
        ok(&v).input.fetch_site
    };
    assert_eq!(fetch(Some("same-origin")), FetchSite::SameOrigin);
    assert_eq!(fetch(Some("Same-Site")), FetchSite::SameSite);
    assert_eq!(fetch(Some("cross-site")), FetchSite::CrossSite);
    assert_eq!(fetch(Some("none")), FetchSite::UserInitiated);
    assert_eq!(fetch(Some("bogus")), FetchSite::Unknown);
    assert_eq!(fetch(None), FetchSite::Unknown);
    let mut twice = base("https://app.example.test/x");
    twice.push(("sec-fetch-site", "same-origin".into()));
    twice.push(("sec-fetch-site", "same-origin".into()));
    assert_eq!(
        reason_of(&cfg(), &twice),
        ("contract_violation", DenyKind::ContractViolation)
    );
}

#[test]
fn handoff_clean_and_switch_redirects() {
    let d = Decision::Handoff {
        location: url::Url::parse("https://app.example.test/admin/x?q=1").unwrap(),
        handle: Secret::new("H1".into()),
        issued_aal: Aal::One,
        max_age: Duration::from_secs(604_800),
    };
    let resp = r(d, Navigation::Document);
    assert_eq!(resp.status(), StatusCode::FOUND);
    assert_eq!(
        h(&resp, "location"),
        Some("https://app.example.test/admin/x?q=1")
    );
    assert_eq!(
        all(&resp, "set-cookie"),
        vec!["__Host-hopae=H1; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=604800"]
    );
    assert_eq!(h(&resp, "cache-control"), Some("no-store"));
    assert_eq!(h(&resp, "x-hopae-reason"), Some("handoff"));

    let d = Decision::CleanRedirect {
        location: url::Url::parse("https://app.example.test/admin/x").unwrap(),
    };
    let resp = r(d, Navigation::Document);
    assert_eq!(resp.status(), StatusCode::FOUND);
    assert_eq!(
        h(&resp, "location"),
        Some("https://app.example.test/admin/x")
    );
    assert!(resp.headers().get("set-cookie").is_none());
    assert_eq!(h(&resp, "x-hopae-reason"), Some("code_already_redeemed"));

    let resp = r(
        Decision::Switch {
            transaction: Secret::new("T9".into()),
        },
        Navigation::Document,
    );
    assert_eq!(resp.status(), StatusCode::FOUND);
    assert_eq!(
        h(&resp, "location"),
        Some("https://auth.example.test/switch?txn=T9")
    );
    assert!(resp.headers().get("set-cookie").is_none());
    assert_eq!(h(&resp, "x-hopae-reason"), Some("session_conflict"));
}

#[test]
fn development_mode_drops_secure_and_the_host_prefix_comes_from_config() {
    let c = insecure_cfg();
    let d = Decision::Login {
        transaction: Some(Secret::new("T1".into())),
        bind: BindAction::Plant(Secret::new("B1".into())),
        kind: LoginKind::Login,
        clear_handle: true,
        cause: None,
    };
    let resp = render(d, Navigation::Document, &env(), &c);
    assert_eq!(
        h(&resp, "location"),
        Some("http://auth.example.test/login?txn=T1")
    );
    assert_eq!(
        all(&resp, "set-cookie"),
        vec![
            "hopae_bind=B1; Path=/; HttpOnly; SameSite=Lax; Max-Age=600",
            "hopae=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0",
        ]
    );
}

#[tokio::test]
async fn adapter_s004_11_denials_have_the_contract_bodies() {
    let deny =
        |reason: Reason, kind: DenyKind, nav: Navigation| r(Decision::Deny { reason, kind }, nav);

    let resp = deny(
        reasons::UNKNOWN_APP,
        DenyKind::Forbidden,
        Navigation::Document,
    );
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(h(&resp, "x-hopae-reason"), Some("unknown_app"));
    assert_eq!(h(&resp, "content-type"), Some("application/json"));
    assert_eq!(h(&resp, "cache-control"), Some("no-store"));
    assert!(resp.headers().get("set-cookie").is_none());
    let v: serde_json::Value = serde_json::from_str(&body(resp).await).unwrap();
    assert_eq!(v, serde_json::json!({"error": "unknown_app"}));

    let resp = deny(
        reasons::TXN_RATE_LIMITED,
        DenyKind::RateLimited {
            retry_after: Duration::from_secs(60),
        },
        Navigation::Document,
    );
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(h(&resp, "x-hopae-reason"), Some("txn_rate_limited"));
    let v: serde_json::Value = serde_json::from_str(&body(resp).await).unwrap();
    assert_eq!(
        v,
        serde_json::json!({"error": "rate_limited", "retry_after": 60})
    );

    let resp = deny(
        reasons::HANDOFF_RECOVERY_EXHAUSTED,
        DenyKind::ForbiddenHtml,
        Navigation::Document,
    );
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert!(h(&resp, "content-type").unwrap().starts_with("text/html"));
    assert_eq!(
        h(&resp, "x-hopae-reason"),
        Some("handoff_recovery_exhausted")
    );
    let html = body(resp).await;
    assert!(html.contains("r_test") && !html.contains("<script"));
    // A non-document request gets the JSON form of the same denial.
    let resp = deny(
        reasons::HANDOFF_RECOVERY_EXHAUSTED,
        DenyKind::ForbiddenHtml,
        Navigation::Other,
    );
    assert_eq!(h(&resp, "content-type"), Some("application/json"));

    let resp = deny(
        reasons::CONTRACT_VIOLATION,
        DenyKind::ContractViolation,
        Navigation::Other,
    );
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(h(&resp, "x-hopae-reason"), Some("contract_violation"));
    let mut e = env();
    e.detail = Some("x-original-url");
    let resp = render(
        Decision::Deny {
            reason: reasons::CONTRACT_VIOLATION,
            kind: DenyKind::ContractViolation,
        },
        Navigation::Other,
        &e,
        &cfg(),
    );
    let v: serde_json::Value = serde_json::from_str(&body(resp).await).unwrap();
    assert_eq!(v["detail"], "x-original-url");

    let resp = deny(
        reasons::STORE_UNAVAILABLE,
        DenyKind::Unavailable {
            retry_after: Duration::from_secs(1),
        },
        Navigation::Document,
    );
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(h(&resp, "retry-after"), Some("1"));
    assert_eq!(h(&resp, "x-hopae-reason"), Some("store_unavailable"));
    // Sub-second retry hints round up to one second.
    let resp = deny(
        reasons::OVERLOADED,
        DenyKind::Unavailable {
            retry_after: Duration::from_millis(200),
        },
        Navigation::Other,
    );
    assert_eq!(h(&resp, "retry-after"), Some("1"));
}

#[test]
fn adapter_s004_11_only_allow_renders_to_a_2xx() {
    super::walk::assert_only_allow_is_2xx();
}

#[test]
fn return_target_limit_applies_to_the_cleaned_url_with_bounded_handoff_overhead() {
    let code = "c".repeat(43);
    let prefix = "https://app.example.test/p?q=";
    let target = |n: usize| format!("{prefix}{}", "a".repeat(n - prefix.len()));
    // 2048 bytes plus the appended handoff pair: accepted, and cleaned.
    let t = target(2048);
    let with_code = format!("{t}&_hopae_handoff={code}");
    let p = ok(&base(&with_code));
    assert_eq!(p.input.original_url.as_str(), t);
    // 2049 bytes once the pair is removed: refused.
    let t = target(2049);
    let with_code = format!("{t}&_hopae_handoff={code}");
    assert_eq!(reason_of(&cfg(), &base(&with_code)).0, "contract_violation");
    // A pair longer than the code Hopae mints does not widen the wire bound.
    let t = target(2048);
    let long_pair = format!("{t}&_hopae_handoff={}", "c".repeat(44));
    assert_eq!(reason_of(&cfg(), &base(&long_pair)).0, "contract_violation");
}
