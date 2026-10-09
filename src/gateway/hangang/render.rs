//! Decision rendering: every `Decision` to the exact status, headers and body
//! of contract v1. `Decision::Allow` is the only variant that renders to a
//! `2xx`; every other outcome is `302`, `401`, `403`, `400` or `503`, and no
//! response carries the gateway's terminal-response marker.

use std::fmt::Write as _;
use std::time::Duration;

use axum::body::Body;
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header};
use axum::response::Response;

use super::{CONTRACT_VERSION, GatewayConfig, RenderEnv};
use crate::event::types::{Reason, reasons};
use crate::gateway::recognition::strip_handoff;
use crate::verify::types::{
    BindAction, Cacheability, Decision, DenyKind, Identity, LoginKind, Navigation,
};

/// Lifetime of the binding cookie.
const BIND_MAX_AGE: u64 = 600;

const MAX_USER: usize = 64;
const MAX_EMAIL: usize = 254;
const MAX_USERNAME: usize = 256;
const MAX_GROUPS: usize = 4096;
const MAX_SESSION: usize = 64;
const MAX_PROVIDER: usize = 64;
const MAX_FACTORS: usize = 256;
const MAX_TOTAL: usize = 8 * 1024;

const TOO_LARGE: Reason = reasons::HEADER_TOO_LARGE;

/// Short labels of a decision for counters: (decision, reason).
pub fn decision_label(decision: &Decision) -> (&'static str, &'static str) {
    match decision {
        Decision::Allow { .. } => ("allow", "ok"),
        // A reauthentication is its own decision label, not a missing login.
        Decision::Login {
            kind: LoginKind::Reauth,
            ..
        } => ("login", "reauth_required"),
        Decision::Login { .. } => ("login", "login_required"),
        Decision::Handoff { .. } => ("handoff", "handoff"),
        Decision::CleanRedirect { .. } => ("clean_redirect", "code_already_redeemed"),
        Decision::Switch { .. } => ("switch", "session_conflict"),
        Decision::AlreadyAuthenticated { .. } => ("redirect", "already_authenticated"),
        Decision::LogoutEntry { .. } => ("redirect", "logout_entry"),
        Decision::LoggedOut { .. } => ("redirect", "logout"),
        Decision::Deny { reason, .. } => ("deny", reason.0),
    }
}

/// A response under construction.
struct Out {
    status: StatusCode,
    headers: HeaderMap,
    body: String,
}

impl Out {
    fn new(status: StatusCode, reason: &str) -> Out {
        let mut o = Out {
            status,
            headers: HeaderMap::new(),
            body: String::new(),
        };
        o.set(header::CACHE_CONTROL.as_str(), "no-store");
        o.set("x-hopae-reason", reason);
        o.set("x-hopae-contract", &CONTRACT_VERSION.to_string());
        o
    }

    /// Set a header; a value that cannot be one is dropped (callers only pass visible ASCII).
    fn set(&mut self, name: &str, value: &str) {
        if let (Ok(n), Ok(v)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(value),
        ) {
            self.headers.insert(n, v);
        }
    }

    fn add(&mut self, name: &str, value: &str) {
        if let (Ok(n), Ok(v)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(value),
        ) {
            self.headers.append(n, v);
        }
    }

    fn json(mut self, value: &serde_json::Value) -> Out {
        self.set("content-type", "application/json");
        self.body = value.to_string();
        self
    }

    fn finish(self) -> Response {
        let mut resp = Response::new(Body::from(self.body));
        *resp.status_mut() = self.status;
        *resp.headers_mut() = self.headers;
        resp
    }
}

/// Render `decision`. `nav` selects the form of a login or HTML denial.
pub fn render(
    decision: Decision,
    nav: Navigation,
    env: &RenderEnv,
    cfg: &GatewayConfig,
) -> Response {
    let document = matches!(nav, Navigation::Document);
    match decision {
        Decision::Allow { identity, cache } => allow(&identity, &cache, env),
        Decision::Login {
            transaction,
            bind,
            kind,
            clear_handle,
            cause,
        } => login(
            transaction.as_ref().map(|t| t.expose()),
            bind,
            kind,
            clear_handle,
            cause,
            document,
            env,
            cfg,
        ),
        Decision::Handoff {
            location,
            handle,
            issued_aal: _,
            max_age,
        } => {
            let mut o = Out::new(StatusCode::FOUND, "handoff");
            o.set("location", location.as_str());
            match cookie(cfg, &cfg.cookies.handle, handle.expose(), max_age.as_secs()) {
                Some(c) => o.add("set-cookie", &c),
                None => return internal_error(env),
            }
            o.finish()
        }
        Decision::CleanRedirect { location } => {
            let mut o = Out::new(StatusCode::FOUND, reasons::CODE_ALREADY_REDEEMED.0);
            o.set("location", location.as_str());
            o.finish()
        }
        Decision::Switch { transaction } => match portal_url(cfg, "switch", transaction.expose()) {
            Some(u) => {
                let mut o = Out::new(StatusCode::FOUND, reasons::SESSION_CONFLICT.0);
                o.set("location", &u);
                o.finish()
            }
            None => internal_error(env),
        },
        Decision::AlreadyAuthenticated { location } => {
            let mut o = Out::new(StatusCode::FOUND, reasons::ALREADY_AUTHENTICATED.0);
            o.set("location", location.as_str());
            o.finish()
        }
        Decision::LogoutEntry {
            transaction,
            clear_handle,
            ..
        } => match portal_url(cfg, "logout", transaction.expose()) {
            Some(u) => {
                let mut o = Out::new(StatusCode::FOUND, reasons::LOGOUT_ENTRY.0);
                o.set("location", &u);
                if clear_handle && let Some(c) = cookie(cfg, &cfg.cookies.handle, "", 0) {
                    o.add("set-cookie", &c);
                }
                o.finish()
            }
            None => internal_error(env),
        },
        Decision::LoggedOut { transaction } => {
            match (
                portal_url(cfg, "signed-out", transaction.expose()),
                cookie(cfg, &cfg.cookies.handle, "", 0),
            ) {
                (Some(u), Some(c)) => {
                    let mut o = Out::new(StatusCode::FOUND, reasons::LOGOUT.0);
                    o.set("location", &u);
                    o.add("set-cookie", &c);
                    o.finish()
                }
                _ => internal_error(env),
            }
        }
        Decision::Deny { reason, kind } => deny(reason, kind, document, env),
    }
}

fn internal_error(env: &RenderEnv) -> Response {
    tracing::error!(request_id = %env.request_id, "internal_error: a decision could not be rendered");
    deny(
        reasons::INTERNAL_ERROR,
        DenyKind::Unavailable {
            retry_after: Duration::from_secs(1),
        },
        false,
        env,
    )
}

// ---- allow ---------------------------------------------------------------

/// Percent-encode as UTF-8: the RFC 3986 unreserved set and `@` are kept, so
/// the value is visible ASCII and an address stays readable.
fn encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~' | b'@') {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

/// `encode`, cut at a character boundary so the result fits `max` bytes.
fn encode_truncated(s: &str, max: usize) -> String {
    let mut out = String::new();
    for ch in s.chars() {
        let piece = encode(ch.encode_utf8(&mut [0; 4]));
        if out.len() + piece.len() > max {
            break;
        }
        out.push_str(&piece);
    }
    out
}

fn bounded(s: String, max: usize) -> Option<String> {
    (s.len() <= max).then_some(s)
}

fn allow(id: &Identity, cache: &Cacheability, env: &RenderEnv) -> Response {
    match identity_headers(id) {
        Some(headers) => {
            let mut o = Out::new(StatusCode::OK, reasons::OK.0);
            let mut total = 0;
            for (name, value) in &headers {
                total += name.len() + value.len();
                o.set(name, value);
            }
            if total > MAX_TOTAL {
                return deny(TOO_LARGE, DenyKind::Forbidden, false, env);
            }
            o.set("x-hopae-gen", &id.generations.to_string());
            if let Cacheability::Private {
                max_age,
                fresh_until,
            } = cache
                && !env.handoff_seen
            {
                o.set(
                    "cache-control",
                    &format!("private, max-age={}", max_age.as_secs()),
                );
                o.set("x-hopae-fresh-until", &fresh_until.0.to_string());
            }
            o.finish()
        }
        None => deny(TOO_LARGE, DenyKind::Forbidden, false, env),
    }
}

/// The identity header set; `None` when a value that identifies the caller
/// exceeds its bound (the request is then denied rather than truncated).
fn identity_headers(id: &Identity) -> Option<Vec<(&'static str, String)>> {
    let mut h: Vec<(&'static str, String)> = Vec::with_capacity(10);
    h.push((
        "x-forwarded-user",
        bounded(encode(id.user_id.as_str()), MAX_USER)?,
    ));
    if let Some(email) = &id.email {
        let e = encode(email.as_str());
        if !e.is_empty() && e.len() <= MAX_EMAIL {
            h.push(("x-forwarded-email", e));
        }
    }
    if let Some(name) = id.preferred_username.as_deref() {
        let n = encode_truncated(name, MAX_USERNAME);
        if !n.is_empty() {
            h.push(("x-forwarded-preferred-username", n));
        }
    }
    if !id.groups.is_empty() {
        let g = id
            .groups
            .iter()
            .map(|g| encode(g))
            .collect::<Vec<_>>()
            .join(",");
        h.push(("x-forwarded-groups", bounded(g, MAX_GROUPS)?));
    }
    h.push((
        "x-hopae-session",
        bounded(encode(id.session_id.as_str()), MAX_SESSION)?,
    ));
    h.push((
        "x-hopae-provider",
        bounded(encode(id.provider_id.as_str()), MAX_PROVIDER)?,
    ));
    h.push(("x-hopae-auth-time", id.auth_time.secs().to_string()));
    h.push(("x-hopae-expires", id.expires_at.secs().to_string()));
    h.push(("x-hopae-aal", id.aal.as_i64().to_string()));
    let factors = id
        .factors
        .iter()
        .map(|f| match &f.provider {
            Some(p) => format!("{}:{}", f.kind.as_str(), encode(p.as_str())),
            None => f.kind.as_str().to_string(),
        })
        .collect::<Vec<_>>()
        .join(",");
    if !factors.is_empty() {
        h.push(("x-hopae-factors", bounded(factors, MAX_FACTORS)?));
    }
    Some(h)
}

// ---- login and redirects -------------------------------------------------

/// A cookie value must be plain token characters; anything else is a bug in
/// the core and fails closed instead of producing a malformed `set-cookie`.
fn cookie_safe(v: &str) -> bool {
    v.bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~'))
}

fn cookie(cfg: &GatewayConfig, name: &str, value: &str, max_age: u64) -> Option<String> {
    cookie_safe(value).then(|| {
        let secure = if cfg.secure { " Secure;" } else { "" };
        format!("{name}={value}; Path=/;{secure} HttpOnly; SameSite=Lax; Max-Age={max_age}")
    })
}

fn portal_url(cfg: &GatewayConfig, page: &str, txn: &str) -> Option<String> {
    let mut u = cfg.portal_url.clone();
    u.set_path(&format!("/{page}"));
    u.query_pairs_mut().clear().append_pair("txn", txn);
    Some(u.to_string())
}

#[allow(clippy::too_many_arguments)] // the fields of `Decision::Login` plus the request context
fn login(
    transaction: Option<&str>,
    bind: BindAction,
    kind: LoginKind,
    clear_handle: bool,
    cause: Option<Reason>,
    document: bool,
    env: &RenderEnv,
    cfg: &GatewayConfig,
) -> Response {
    let (reason, error, page) = match kind {
        LoginKind::Login => (reasons::LOGIN_REQUIRED, "login_required", "login"),
        LoginKind::StepUp => (reasons::STEP_UP_REQUIRED, "step_up_required", "stepup"),
        // The portal's `login` page; the reauthentication requirement lives in the transaction.
        LoginKind::Reauth => (reasons::REAUTH_REQUIRED, "reauth_required", "login"),
    };
    // A non-document request starts nothing: the application URL itself is the
    // document bootstrap that plants the binding cookie.
    let target = transaction.filter(|_| document);
    let Some(txn) = target else {
        let login_url = env
            .original_url
            .as_ref()
            .map_or_else(|| cfg.portal_url.to_string(), strip_handoff);
        let mut o = Out::new(StatusCode::UNAUTHORIZED, reason.0)
            .json(&serde_json::json!({"error": error, "login": login_url}));
        if !document {
            let realm = cfg.portal_url.host_str().unwrap_or("");
            o.set("www-authenticate", &format!("Hopae realm=\"{realm}\""));
            return o.finish();
        }
        // A document navigation without a transaction cannot be sent anywhere.
        tracing::error!(request_id = %env.request_id, "internal_error: a document navigation had no transaction");
        return deny(
            reasons::INTERNAL_ERROR,
            DenyKind::Unavailable {
                retry_after: Duration::from_secs(1),
            },
            true,
            env,
        );
    };
    let Some(location) = portal_url(cfg, page, txn) else {
        return internal_error(env);
    };
    // The redirect says why the presented handle was refused (`session_terminated`,
    // `idle`, `unknown_handle`, ...); without a handle it is `login_required`.
    let mut o = Out::new(StatusCode::FOUND, cause.unwrap_or(reason).0);
    o.set("location", &location);
    let bind_value = match &bind {
        BindAction::Plant(secret) => Some(secret.expose()),
        BindAction::Keep => env.bind_cookie.as_deref(),
    };
    if let Some(v) = bind_value {
        match cookie(cfg, &cfg.cookies.bind, v, BIND_MAX_AGE) {
            Some(c) => o.add("set-cookie", &c),
            None => return internal_error(env),
        }
    }
    if clear_handle && let Some(c) = cookie(cfg, &cfg.cookies.handle, "", 0) {
        o.add("set-cookie", &c);
    }
    o.finish()
}

// ---- denials ---------------------------------------------------------------

fn seconds_ceil(d: Duration) -> u64 {
    d.as_secs() + u64::from(d.subsec_nanos() > 0)
}

fn html_escape(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '&' => "&amp;".to_string(),
            '<' => "&lt;".to_string(),
            '>' => "&gt;".to_string(),
            '"' => "&quot;".to_string(),
            '\'' => "&#39;".to_string(),
            c => c.to_string(),
        })
        .collect()
}

fn deny(reason: Reason, kind: DenyKind, document: bool, env: &RenderEnv) -> Response {
    // A non-document request to an entry point is answered like any other
    // reserved path: one error name for the whole namespace.
    let error_name = if reason == reasons::ENTRY_POINT_NOT_DOCUMENT {
        reasons::RESERVED_PATH.0
    } else {
        reason.0
    };
    let json_error = |status: StatusCode| {
        let mut body = serde_json::json!({"error": error_name});
        if let Some(d) = env.detail {
            body["detail"] = serde_json::json!(d);
        }
        Out::new(status, reason.0).json(&body)
    };
    let out = match kind {
        DenyKind::Forbidden => json_error(StatusCode::FORBIDDEN),
        DenyKind::ForbiddenHtml if !document => json_error(StatusCode::FORBIDDEN),
        DenyKind::ForbiddenHtml => {
            let mut o = Out::new(StatusCode::FORBIDDEN, reason.0);
            o.set("content-type", "text/html; charset=utf-8");
            o.set("content-security-policy", "default-src 'none'");
            o.set("x-content-type-options", "nosniff");
            o.body = format!(
                "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
<title>Sign-in could not be completed</title></head><body>\
<h1>Sign-in could not be completed</h1>\
<p>This site and the sign-in page could not agree on your browser. \
Close this tab and open the site again.</p>\
<p>Reference: {}</p></body></html>\n",
                html_escape(&env.request_id)
            );
            o
        }
        DenyKind::RateLimited { retry_after } => {
            let secs = seconds_ceil(retry_after);
            let mut o = Out::new(StatusCode::FORBIDDEN, reason.0)
                .json(&serde_json::json!({"error": "rate_limited", "retry_after": secs}));
            o.set("retry-after", &secs.to_string());
            o
        }
        DenyKind::ContractViolation => json_error(StatusCode::BAD_REQUEST),
        DenyKind::Unavailable { retry_after } => {
            let mut o = json_error(StatusCode::SERVICE_UNAVAILABLE);
            o.set("retry-after", &seconds_ceil(retry_after).max(1).to_string());
            o
        }
    };
    out.finish()
}
