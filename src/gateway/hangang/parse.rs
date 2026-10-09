//! Verify request parsing: the contract's request headers, in the order the
//! contract evaluates them, into a gateway-neutral `VerifyInput`.

use std::net::IpAddr;

use axum::http::{HeaderMap, HeaderValue};

use super::{CONTRACT_VERSION, GatewayConfig, Parsed, Rejected, RenderEnv};
use crate::app::{CallerKeys, KeyVerdict};
use crate::crypto::{Secret, is_well_formed_bind, is_well_formed_handle};
use crate::event::types::{Reason, reasons};
use crate::gateway::{canonical, recognition};
use crate::policy::types::Host;
use crate::telemetry::counters;
use crate::verify::types::Decision;
use crate::verify::types::{
    CallerAuth, DenyKind, EntryReturn, FetchSite, Handoff, Navigation, Reserved, Scheme,
    VerifyInput,
};

const H_KEY: &str = "x-hopae-gateway-key";
const H_CONTRACT: &str = "x-hopae-contract";
const H_URL: &str = "x-original-url";
const H_CANON: &str = "x-hangang-canonical-path";
const H_ROUTE: &str = "x-hangang-route-id";
const H_HOST: &str = "x-forwarded-host";
const H_PROTO: &str = "x-forwarded-proto";
const H_FOR: &str = "x-forwarded-for";
const H_REAL_IP: &str = "x-real-ip";
const H_METHOD: &str = "x-original-method";

/// Upper bound in bytes of the requested URL once the handoff pair is removed
/// (the return-target limit of ADR-0004).
const MAX_URL: usize = 2048;
/// Upper bound in bytes of the requested URL of the login entry point, which
/// carries a return target of up to `MAX_URL` bytes inside its `return`
/// parameter (ADR-0015: every handoff is delivered there). The target's own
/// separators are percent-encoded in it, so the bound is the worst case of
/// three bytes per target byte plus the origin and the fixed prefix.
const MAX_ENTRY_URL: usize = 3 * MAX_URL + 512;
/// Bytes of the handoff pair Hopae appends to a return target: `&`, the
/// reserved name, `=` and a 43-character code (32 random bytes, base64url).
const HANDOFF_OVERHEAD: usize = 1 + recognition::HANDOFF_PARAM.len() + 1 + 43;
/// All `cookie` header bytes together.
const MAX_COOKIE: usize = 8 * 1024;
/// `x-hangang-route-id` bytes kept.
const MAX_ROUTE: usize = 128;

fn refuse(
    request_id: &str,
    reason: Reason,
    kind: DenyKind,
    detail: Option<&'static str>,
    metric: Option<&'static str>,
) -> Box<Rejected> {
    Box::new(Rejected {
        decision: Decision::Deny { reason, kind },
        env: RenderEnv {
            request_id: request_id.to_string(),
            detail,
            ..RenderEnv::default()
        },
        metric,
    })
}

/// The value of a header that must occur at most once.
fn single<'a>(h: &'a HeaderMap, name: &str) -> Result<Option<&'a HeaderValue>, ()> {
    let mut it = h.get_all(name).iter();
    let first = it.next();
    if it.next().is_some() {
        return Err(());
    }
    Ok(first)
}

/// The caller key the request presents: `None` when the header is absent or
/// repeated (a repeated key header is never trusted).
pub fn presented_key(h: &HeaderMap) -> Option<&[u8]> {
    let mut values = h.get_all(H_KEY).iter();
    let first = values.next()?;
    if values.next().is_some() {
        return None;
    }
    Some(first.as_bytes())
}

/// Authenticate the caller before anything else is read or any resource is
/// taken (the concurrency permit included). `keys` compares in constant time
/// and counts the verdict.
pub fn authenticate(
    keys: &CallerKeys,
    h: &HeaderMap,
    request_id: &str,
) -> Result<CallerAuth, Box<Rejected>> {
    match keys.check(presented_key(h)) {
        KeyVerdict::Accepted(which) => Ok(CallerAuth::Keyed { which }),
        KeyVerdict::NotRequired => Ok(CallerAuth::Unauthenticated),
        KeyVerdict::Rejected => Err(refuse(
            request_id,
            reasons::CALLER_UNAUTHORIZED,
            DenyKind::Forbidden,
            None,
            None,
        )),
    }
}

fn parse_contract(h: &HeaderMap) -> Result<u8, Option<Reason>> {
    match single(h, H_CONTRACT) {
        Err(()) => Err(None),
        Ok(None) => Ok(CONTRACT_VERSION),
        Ok(Some(v)) => {
            let s = v.to_str().map_err(|_| None)?;
            if s.is_empty() || s.len() > 3 || !s.bytes().all(|b| b.is_ascii_digit()) {
                return Err(None);
            }
            match s.parse::<u16>() {
                Ok(0) | Err(_) => Err(None),
                Ok(n) if n == u16::from(CONTRACT_VERSION) => Ok(CONTRACT_VERSION),
                Ok(_) => Err(Some(reasons::CONTRACT_UNSUPPORTED)),
            }
        }
    }
}

/// The path component of `url` exactly as written (the URL parser would
/// resolve dot segments and hide the very thing the canonical check rejects).
fn raw_path(url: &str) -> &str {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let from_authority = rest.find(['/', '?']).map_or("", |i| &rest[i..]);
    let path = from_authority.split('?').next().unwrap_or("");
    if path.is_empty() { "/" } else { path }
}

fn raw_query(url: &str) -> &str {
    url.split_once('?').map_or("", |(_, q)| q)
}

fn client_ip(h: &HeaderMap) -> Result<IpAddr, &'static str> {
    let read = |name: &'static str| -> Result<Option<IpAddr>, &'static str> {
        match single(h, name) {
            Err(()) => Err(name),
            Ok(None) => Ok(None),
            Ok(Some(v)) => v
                .to_str()
                .ok()
                .and_then(|s| s.trim().parse::<IpAddr>().ok())
                .map(Some)
                .ok_or(name),
        }
    };
    match (read(H_FOR)?, read(H_REAL_IP)?) {
        (Some(a), Some(b)) if a != b => Err(H_REAL_IP),
        (Some(a), _) | (None, Some(a)) => Ok(a),
        (None, None) => Err(H_FOR),
    }
}

fn accepts_html(accept: &HeaderValue) -> bool {
    let Ok(s) = accept.to_str() else {
        return false;
    };
    s.split(',').any(|range| {
        let media = range.split(';').next().unwrap_or("").trim();
        media.eq_ignore_ascii_case("text/html")
            || media.eq_ignore_ascii_case("application/xhtml+xml")
    })
}

fn navigation(h: &HeaderMap) -> Navigation {
    let document = if let Some(dest) = h.get("sec-fetch-dest") {
        dest.as_bytes().eq_ignore_ascii_case(b"document")
    } else if let Some(mode) = h.get("sec-fetch-mode") {
        mode.as_bytes().eq_ignore_ascii_case(b"navigate")
    } else {
        h.get_all("accept").iter().any(accepts_html)
    };
    if document {
        Navigation::Document
    } else {
        Navigation::Other
    }
}

fn fetch_site(h: &HeaderMap) -> Result<FetchSite, ()> {
    let Some(v) = single(h, "sec-fetch-site")? else {
        return Ok(FetchSite::Unknown);
    };
    let b = v.as_bytes();
    Ok(if b.eq_ignore_ascii_case(b"same-origin") {
        FetchSite::SameOrigin
    } else if b.eq_ignore_ascii_case(b"same-site") {
        FetchSite::SameSite
    } else if b.eq_ignore_ascii_case(b"cross-site") {
        FetchSite::CrossSite
    } else if b.eq_ignore_ascii_case(b"none") {
        FetchSite::UserInitiated
    } else {
        FetchSite::Unknown
    })
}

/// The target an entry point was asked for: the `return` parameter resolved
/// against the request origin. A path-absolute reference (`/path?q`, a single
/// leading slash) becomes an absolute URL on the request's origin; an absolute
/// URL is kept as written. Anything the core should not even look at is
/// `Invalid`.
fn entry_return(original_url: &url::Url, raw_query: &str) -> EntryReturn {
    let value = match recognition::find_return(raw_query) {
        recognition::ReturnParam::Absent => return EntryReturn::Absent,
        recognition::ReturnParam::Ambiguous => return EntryReturn::Invalid,
        recognition::ReturnParam::Value(v) => v,
    };
    if value.is_empty() || value.chars().any(|c| c.is_control() || c == '\\') {
        return EntryReturn::Invalid;
    }
    let candidate = if value.starts_with("//") {
        return EntryReturn::Invalid;
    } else if value.starts_with('/') {
        format!("{}{value}", original_url.origin().ascii_serialization())
    } else {
        value
    };
    if url::Url::parse(&candidate).is_err()
        || !matches!(
            recognition::find_handoff(raw_query_of(&candidate)),
            Handoff::None
        )
    {
        return EntryReturn::Invalid;
    }
    match canonical::canonical_path(raw_path(&candidate)) {
        Ok(canonical_path) => EntryReturn::Candidate {
            url: candidate,
            canonical_path,
        },
        Err(()) => EntryReturn::Invalid,
    }
}

/// The query of a URL string, up to a fragment.
fn raw_query_of(url: &str) -> &str {
    let q = raw_query(url);
    q.split('#').next().unwrap_or("")
}

struct Cookies {
    handle: Option<String>,
    bind: Option<String>,
    bind_well_formed: Option<String>,
}

/// The handle and binding cookies by exact name. The first well-formed pair
/// of each wins and parsing stops once both are found; when none is well
/// formed the first pair is passed on so the core can name it.
fn read_cookies(cfg: &GatewayConfig, h: &HeaderMap) -> Result<Cookies, ()> {
    let total: usize = h.get_all("cookie").iter().map(|v| v.len()).sum();
    if total > MAX_COOKIE {
        return Err(());
    }
    let (mut handle, mut handle_ok) = (None::<String>, false);
    let (mut bind, mut bind_ok) = (None::<String>, false);
    'all: for value in h.get_all("cookie").iter() {
        let Ok(value) = value.to_str() else {
            continue;
        };
        for pair in value.split(';') {
            let Some((name, val)) = pair.trim().split_once('=') else {
                continue;
            };
            if name == cfg.cookies.handle && !handle_ok {
                if is_well_formed_handle(val) {
                    handle = Some(val.to_string());
                    handle_ok = true;
                } else if handle.is_none() {
                    handle = Some(val.to_string());
                }
            } else if name == cfg.cookies.bind && !bind_ok {
                if is_well_formed_bind(val) {
                    bind = Some(val.to_string());
                    bind_ok = true;
                } else if bind.is_none() {
                    bind = Some(val.to_string());
                }
            }
            if handle_ok && bind_ok {
                break 'all;
            }
        }
    }
    Ok(Cookies {
        bind_well_formed: if bind_ok { bind.clone() } else { None },
        handle,
        bind,
    })
}

fn truncate_utf8(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Parse a verify request from a caller that [`authenticate`] accepted. `Err`
/// carries a ready denial; nothing has been looked up by then.
pub fn parse(
    cfg: &GatewayConfig,
    h: &HeaderMap,
    request_id: String,
    caller: CallerAuth,
) -> Result<Parsed, Box<Rejected>> {
    let violation = |detail: &'static str| {
        refuse(
            &request_id,
            reasons::CONTRACT_VIOLATION,
            DenyKind::ContractViolation,
            Some(detail),
            None,
        )
    };

    // 1. The caller key was checked by `authenticate`, before any other header was read.

    // 2. Contract version.
    let contract = match parse_contract(h) {
        Ok(v) => v,
        Err(Some(reason)) => {
            return Err(refuse(
                &request_id,
                reason,
                DenyKind::ContractViolation,
                Some(H_CONTRACT),
                None,
            ));
        }
        Err(None) => return Err(violation(H_CONTRACT)),
    };

    // 3. The requested URL.
    let raw_url = match single(h, H_URL) {
        Ok(Some(v)) => v.to_str().map_err(|_| violation(H_URL))?,
        _ => return Err(violation(H_URL)),
    };
    // On the wire the URL may carry Hopae's own handoff pair on top of the
    // limit; the limit itself applies to the cleaned target below.
    // The reserved namespace carries a whole target in `return`: a longer bound,
    // only on a path that looks like it (the canonical decision comes later).
    let max_url = if raw_path(raw_url)
        .get(..8)
        .is_some_and(|p| p.eq_ignore_ascii_case("/_hopae/"))
    {
        MAX_ENTRY_URL
    } else {
        MAX_URL
    };
    if raw_url.len() > max_url + HANDOFF_OVERHEAD || raw_url.contains('#') {
        return Err(violation(H_URL));
    }
    let original_url = url::Url::parse(raw_url).map_err(|_| violation(H_URL))?;
    let clean_url = recognition::clean_target(&original_url);
    if clean_url.as_str().len() > max_url {
        return Err(violation(H_URL));
    }
    if !matches!(original_url.scheme(), "http" | "https")
        || !original_url.username().is_empty()
        || original_url.password().is_some()
    {
        return Err(violation(H_URL));
    }
    let Some(url_host) = original_url.host_str() else {
        return Err(violation(H_URL));
    };

    // 4. Transport.
    let proto = match single(h, H_PROTO) {
        Ok(Some(v)) => match v.as_bytes() {
            b"https" => Scheme::Https,
            b"http" => Scheme::Http,
            _ => return Err(violation(H_PROTO)),
        },
        _ => return Err(violation(H_PROTO)),
    };
    if proto == Scheme::Http && cfg.secure {
        return Err(refuse(
            &request_id,
            reasons::INSECURE_TRANSPORT,
            DenyKind::ContractViolation,
            Some(H_PROTO),
            None,
        ));
    }
    let scheme_matches = matches!(
        (proto, original_url.scheme()),
        (Scheme::Https, "https") | (Scheme::Http, "http")
    );
    if !scheme_matches {
        return Err(violation(H_PROTO));
    }

    // 5. Host agreement.
    let fwd_host = match single(h, H_HOST) {
        Ok(Some(v)) => v.to_str().map_err(|_| violation(H_HOST))?,
        _ => return Err(violation(H_HOST)),
    };
    let port = original_url
        .port_or_known_default()
        .ok_or_else(|| violation(H_URL))?;
    let (fwd_name, fwd_port) = match fwd_host.rsplit_once(':') {
        Some((n, p)) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => {
            (n, Some(p.parse::<u16>().map_err(|_| violation(H_HOST))?))
        }
        _ => (fwd_host, None),
    };
    if !fwd_name.eq_ignore_ascii_case(url_host) || fwd_port.is_some_and(|p| p != port) {
        return Err(violation(H_HOST));
    }
    let host = Host::parse(url_host).map_err(|_| violation(H_HOST))?;

    // 6. Client address.
    let client_ip = client_ip(h).map_err(violation)?;

    // 7. Canonical path, and agreement with the gateway's own value.
    let canonical_path = match canonical::canonical_path(raw_path(raw_url)) {
        Ok(p) => p,
        Err(()) => {
            return Err(refuse(
                &request_id,
                reasons::PATH_NOT_CANONICAL,
                DenyKind::Forbidden,
                None,
                None,
            ));
        }
    };
    match single(h, H_CANON) {
        Err(()) => return Err(violation(H_CANON)),
        Ok(None) => {}
        Ok(Some(v)) => {
            if v.as_bytes() != canonical_path.as_str().as_bytes() {
                return Err(refuse(
                    &request_id,
                    reasons::CANONICAL_PATH_MISMATCH,
                    DenyKind::Forbidden,
                    None,
                    Some(counters::VERIFY_CANONICAL_MISMATCH_TOTAL),
                ));
            }
        }
    }

    // 8. Optional context.
    let route_id = match single(h, H_ROUTE) {
        Err(()) => return Err(violation(H_ROUTE)),
        Ok(v) => v
            .and_then(|v| v.to_str().ok())
            .map(|s| truncate_utf8(s, MAX_ROUTE).to_string()),
    };
    let method = match single(h, H_METHOD) {
        Err(()) => return Err(violation(H_METHOD)),
        Ok(None) => http::Method::GET,
        Ok(Some(v)) => http::Method::from_bytes(v.as_bytes()).map_err(|_| violation(H_METHOD))?,
    };
    let cookies = read_cookies(cfg, h).map_err(|()| {
        refuse(
            &request_id,
            reasons::HEADER_TOO_LARGE,
            DenyKind::ContractViolation,
            Some("cookie"),
            None,
        )
    })?;
    let fetch_site = fetch_site(h).map_err(|()| violation("sec-fetch-site"))?;
    let user_agent = h
        .get("user-agent")
        .map(|v| crate::policy::binding::normalize_user_agent(v.as_bytes()));

    // 9. Reserved parameter, from the query exactly as written.
    let handoff = recognition::find_handoff(raw_query(raw_url));
    let handoff_seen = !matches!(handoff, Handoff::None);
    // The entry points' `return`, resolved here: the core never reads a query.
    let entry_return = if matches!(canonical_path.reserved(), Reserved::Entry(_)) {
        entry_return(&original_url, raw_query(raw_url))
    } else {
        EntryReturn::Absent
    };

    let env = RenderEnv {
        request_id: request_id.clone(),
        original_url: Some(original_url.clone()),
        bind_cookie: cookies.bind_well_formed,
        handoff_seen,
        detail: None,
    };
    let input = VerifyInput {
        // The core never looks at the query: it gets the URL with every
        // handoff pair removed (ADR-0013); `env` keeps the URL as received.
        original_url: clean_url,
        canonical_path,
        client_ip,
        host,
        port,
        proto,
        method,
        route_id,
        cookie_handle: cookies.handle.map(Secret::new),
        bind_cookie: cookies.bind.map(Secret::new),
        user_agent,
        navigation: navigation(h),
        fetch_site,
        entry_return,
        handoff,
        contract,
        caller,
        request_id,
    };
    Ok(Parsed { input, env })
}
