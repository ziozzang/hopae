//! Authentication of the admin listener: every request is authenticated from
//! the console handle and the grant table, never from a header.
//!
//! Order: the TCP peer against `trusted_proxies` (an untrusted peer is
//! refused before any header is read, or treated as the client), the forwarded
//! (or `Host`) header against the console host, the handle cookie, the verify
//! engine for the implicit application `admin` (session, timers, binding,
//! status, authorization baseline, freshness), the grant, the assurance level.
//! The listener creates nothing and starts no login: the gateway's verify did.

use std::net::IpAddr;
use std::time::Duration;

use axum::http::{HeaderMap, Method, StatusCode, header};
use axum::response::Response;

use super::pages::{self, Extra};
use super::{AdminState, Ctx, Denial, Principal, ReqInfo, api};
use crate::config::UntrustedPeers;
use crate::crypto::{Secret, is_well_formed_handle};
use crate::event::types::{Event, EventKind, Outcome, Reason, reasons};
use crate::gateway::canonical::canonical_path;
use crate::gateway::forwarding::X_FORWARDED_HOST;
use crate::gateway::hangang::decision_label;
use crate::http::denials::{self, DenialCounters};
use crate::identity::types::UserId;
use crate::policy::types::Host;
use crate::portal::clientinfo::{self, Client};
use crate::session::types::SessionId;
use crate::telemetry::counters;
use crate::verify::types::{
    CallerAuth, CanonicalPath, Decision, DenyKind, EntryReturn, FetchSite, Handoff, KeySlot,
    LoginKind, Navigation, Scheme, VerifyInput,
};

/// Largest total size of the `cookie` headers the console reads.
const MAX_COOKIE_BYTES: usize = 8 * 1024;
/// One warning line per untrusted peer per this long.
const PEER_WARN_EVERY: Duration = Duration::from_secs(60);
/// Peers remembered for the warning rate limit.
const PEER_WARN_MAX: usize = 1024;

/// A refused request: why, and what is known of who asked.
#[derive(Debug)]
pub struct Refused {
    pub denial: Denial,
    pub client_ip: Option<IpAddr>,
    /// The user and session behind a refused handle, when they are known.
    pub requester: Option<(UserId, SessionId)>,
}

impl Refused {
    /// The concurrency cap was reached.
    pub fn overloaded() -> Refused {
        Refused {
            denial: Denial::Overloaded,
            client_ip: None,
            requester: None,
        }
    }
}

/// The route pattern of a path (`/v1/users/{id}/disable`), or `unmatched`.
/// Event attributes carry the pattern, never the raw path.
pub fn pattern_of(path: &str) -> &'static str {
    let segs: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    let (api, rest) = match segs.as_slice() {
        ["v1", rest @ ..] => (true, rest),
        rest => (false, rest),
    };
    macro_rules! p {
        ($page:literal, $api:literal) => {
            if api { $api } else { $page }
        };
    }
    match rest {
        [""] if !api => "/",
        ["assets", "admin.css"] if !api => "/assets/admin.css",
        ["status"] if api => "/v1/status",
        ["me"] if api => "/v1/me",
        ["users"] => p!("/users", "/v1/users"),
        ["users", _] => p!("/users/{id}", "/v1/users/{id}"),
        ["users", _, "disable"] => p!("/users/{id}/disable", "/v1/users/{id}/disable"),
        ["users", _, "enable"] => p!("/users/{id}/enable", "/v1/users/{id}/enable"),
        ["users", _, "sessions", "terminate"] => p!(
            "/users/{id}/sessions/terminate",
            "/v1/users/{id}/sessions/terminate"
        ),
        ["sessions"] => p!("/sessions", "/v1/sessions"),
        ["sessions", _] => p!("/sessions/{id}", "/v1/sessions/{id}"),
        ["sessions", _, "terminate"] => {
            p!("/sessions/{id}/terminate", "/v1/sessions/{id}/terminate")
        }
        ["events"] => p!("/events", "/v1/events"),
        _ => "unmatched",
    }
}

/// Whether a request is one of the console's mutations: a `POST` to a route
/// that changes state. The listener checks these (CSRF, then the role) before
/// the handler runs.
pub fn is_mutation(method: &Method, pattern: &str) -> bool {
    *method == Method::POST
        && matches!(
            pattern,
            "/users/{id}/disable"
                | "/users/{id}/enable"
                | "/users/{id}/sessions/terminate"
                | "/sessions/{id}/terminate"
                | "/v1/users/{id}/disable"
                | "/v1/users/{id}/enable"
                | "/v1/users/{id}/sessions/terminate"
                | "/v1/sessions/{id}/terminate"
        )
}

/// `host` or `host:port` against the console host (ASCII case-insensitive).
fn host_is_console(value: &str, console: &Host) -> bool {
    let value = value.trim();
    let name = match value.rsplit_once(':') {
        Some((h, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => h,
        _ => value,
    };
    name.eq_ignore_ascii_case(console.as_str())
}

/// The host the client addressed: the forwarded host of a trusted peer, the
/// `Host` header of one treated as the client. Several lines are ambiguous.
fn addressed_host(headers: &HeaderMap, trusted: bool) -> Option<&str> {
    let mut it = if trusted {
        headers.get_all(&X_FORWARDED_HOST).iter()
    } else {
        headers.get_all(header::HOST).iter()
    };
    match (it.next(), it.next()) {
        (Some(v), None) => v.to_str().ok(),
        _ => None,
    }
}

fn warn_untrusted_peer(st: &AdminState, peer: IpAddr) {
    let now = st.clock.now();
    let mut seen = st
        .peer_warned
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if seen
        .get(&peer)
        .is_some_and(|t| now.since(*t) < PEER_WARN_EVERY)
    {
        return;
    }
    if seen.len() >= PEER_WARN_MAX {
        seen.retain(|_, t| now.since(*t) < PEER_WARN_EVERY);
        if seen.len() >= PEER_WARN_MAX {
            return;
        }
    }
    seen.insert(peer, now);
    drop(seen);
    tracing::warn!(
        peer = %peer,
        "admin listener refused a connection from a peer outside trusted_proxies"
    );
}

/// Steps 1 and 2: the peer, the client address and scheme, the console host.
/// Nothing is read from the request but the forwarding headers and the host.
pub fn admit(
    st: &AdminState,
    peer: IpAddr,
    headers: &HeaderMap,
    rid: &str,
) -> Result<Client, Refused> {
    let trusted = st.cfg.trusted.iter().any(|n| n.contains(&peer));
    if !trusted && st.cfg.untrusted_peers == UntrustedPeers::Refuse {
        denials::record_refusal(
            st.emitter.as_ref(),
            &DenialCounters::ADMIN,
            reasons::UNTRUSTED_PEER,
            peer,
            Some(&st.cfg.policy.app_id),
            rid,
        );
        warn_untrusted_peer(st, peer);
        return Err(Refused {
            denial: Denial::UntrustedPeer,
            client_ip: Some(peer),
            requester: None,
        });
    }
    let client = clientinfo::resolve(peer, headers, &st.cfg.trusted);
    let right_host =
        addressed_host(headers, trusted).is_some_and(|h| host_is_console(h, &st.cfg.host));
    if !right_host {
        return Err(Refused {
            denial: Denial::WrongHost,
            client_ip: Some(client.ip),
            requester: None,
        });
    }
    Ok(client)
}

/// The handle cookie: the first well-formed one wins; when none is
/// well-formed the first pair is passed on so the engine can name it.
fn read_handle(headers: &HeaderMap, name: &str) -> Result<Option<String>, ()> {
    let total: usize = headers
        .get_all(header::COOKIE)
        .iter()
        .map(|v| v.len())
        .sum();
    if total > MAX_COOKIE_BYTES {
        return Err(());
    }
    let mut first: Option<String> = None;
    for value in headers.get_all(header::COOKIE) {
        let Ok(text) = value.to_str() else { continue };
        for pair in text.split(';') {
            let Some((n, v)) = pair.trim().split_once('=') else {
                continue;
            };
            if n != name {
                continue;
            }
            if is_well_formed_handle(v) {
                return Ok(Some(v.to_string()));
            }
            if first.is_none() {
                first = Some(v.to_string());
            }
        }
    }
    Ok(first)
}

fn count_decision(decision: &Decision) {
    let (name, reason) = decision_label(decision);
    counters::inc(
        counters::VERIFY_DECISIONS_TOTAL,
        &[("decision", name), ("reason", reason)],
    );
    if matches!(decision, Decision::Deny { reason: r, .. } if *r == reasons::STORE_UNAVAILABLE) {
        counters::inc(counters::STORE_ERRORS_TOTAL, &[]);
    }
}

/// Steps 3 to 8: handle, engine, grant, assurance level.
pub async fn authenticate(
    st: &AdminState,
    client: &Client,
    headers: &HeaderMap,
    path: &str,
    method: &Method,
    user_agent: Option<String>,
    rid: &str,
) -> Result<Principal, Refused> {
    let refused = |denial| Refused {
        denial,
        client_ip: Some(client.ip),
        requester: None,
    };
    let handle = match read_handle(headers, &st.cfg.cookie_names.handle) {
        Ok(h) => h,
        Err(()) => return Err(refused(Denial::HeaderTooLarge)),
    };
    // The engine only needs the path for the reserved namespace and step-up
    // rules; a path that is not canonical is matched as `/` (the router
    // answers it `404` and every handler validates its identifiers).
    let canonical = canonical_path(path).unwrap_or_else(|()| CanonicalPath::new("/".into()));
    let origin = st.cfg.origin.ascii_serialization();
    let original_url = url::Url::parse(&format!("{origin}{path}"))
        .or_else(|_| url::Url::parse(&format!("{origin}/")))
        .map_err(|_| refused(Denial::LoginRequired))?;
    let input = VerifyInput {
        original_url,
        canonical_path: canonical,
        client_ip: client.ip,
        host: st.cfg.host.clone(),
        port: st.cfg.port,
        proto: if client.https {
            Scheme::Https
        } else {
            Scheme::Http
        },
        method: method.clone(),
        route_id: None,
        cookie_handle: handle.clone().map(Secret::new),
        bind_cookie: None,
        user_agent,
        navigation: Navigation::Other,
        accepts_html: false,
        fetch_site: FetchSite::Unknown,
        entry_return: EntryReturn::Absent,
        handoff: Handoff::None,
        contract: 1,
        caller: CallerAuth::Keyed {
            which: KeySlot::Current,
        },
        request_id: rid.to_string(),
    };
    let ctx = st.verify.with_budget();
    let (decision, cause) = match tokio::time::timeout(
        ctx.limits.budget,
        crate::verify::decide_with_cause(&ctx, input),
    )
    .await
    {
        Ok(d) => d,
        Err(_) => (
            Decision::Deny {
                reason: reasons::BUDGET_EXCEEDED,
                kind: DenyKind::Unavailable {
                    retry_after: Duration::from_secs(1),
                },
            },
            None,
        ),
    };
    count_decision(&decision);
    let app = &st.cfg.policy.app_id;
    let deny = |denial: Denial| {
        denials::record_denial(
            st.emitter.as_ref(),
            &DenialCounters::ADMIN,
            &decision,
            cause,
            Some(client.ip),
            None,
            Some(app),
            rid,
        );
        denial
    };
    let identity = match &decision {
        Decision::Allow { identity, .. } => identity,
        Decision::Login { kind, cause: c, .. } => {
            // A freshness refusal is `auth_too_old`; the listener never maps a
            // reauthentication to `login_required`. Every kind that is not an
            // ordinary or step-up login is one (the engine's `Reauth`).
            let reauth = !matches!(kind, LoginKind::Login | LoginKind::StepUp);
            let denial = if reauth {
                Denial::AuthTooOld
            } else {
                Denial::LoginRequired
            };
            deny(denial.clone());
            if c.is_none() && !reauth {
                // No handle at all: still a counted, sampled refusal.
                denials::record_refusal(
                    st.emitter.as_ref(),
                    &DenialCounters::ADMIN,
                    reasons::LOGIN_REQUIRED,
                    client.ip,
                    Some(app),
                    rid,
                );
            }
            let mut r = refused(denial);
            if reauth {
                r.requester = requester_of(st, handle.as_deref()).await;
            }
            return Err(r);
        }
        Decision::Deny {
            kind: DenyKind::Unavailable { .. },
            ..
        } => {
            deny(Denial::StoreUnavailable);
            return Err(refused(Denial::StoreUnavailable));
        }
        _ => {
            deny(Denial::LoginRequired);
            return Err(refused(Denial::LoginRequired));
        }
    };
    let Some(handle) = handle else {
        // An allow without a presented handle cannot happen; fail closed.
        return Err(refused(Denial::LoginRequired));
    };
    let handle_value = Secret::new(handle);
    let digest = handle_value.digest();
    let unavailable = |e: crate::store::StoreError| {
        tracing::error!(error = %e, "admin authentication could not read the store");
        counters::inc(counters::STORE_ERRORS_TOTAL, &[]);
        refused(Denial::StoreUnavailable)
    };
    let grant = st
        .directory
        .admin_grant(&identity.user_id, api::deadline(st))
        .await
        .map_err(unavailable)?;
    let requester = Some((identity.user_id.clone(), identity.session_id.clone()));
    let Some(grant) = grant.filter(|g| g.revoked_at.is_none()) else {
        return Err(Refused {
            denial: Denial::NotAdmin {
                user_id: identity.user_id.clone(),
                email: identity.email.clone(),
            },
            client_ip: Some(client.ip),
            requester,
        });
    };
    if identity.aal < st.cfg.limits.require_aal {
        return Err(Refused {
            denial: Denial::AalInsufficient,
            client_ip: Some(client.ip),
            requester,
        });
    }
    let view = st
        .sessions
        .lookup_handle(&digest, &st.cfg.host)
        .await
        .map_err(unavailable)?;
    let Some(view) = view else {
        // The handle ended between the engine's check and this one.
        return Err(refused(Denial::LoginRequired));
    };
    let user = st
        .directory
        .user(&identity.user_id)
        .await
        .map_err(unavailable)?;
    Ok(Principal {
        user_id: identity.user_id.clone(),
        session_id: identity.session_id.clone(),
        handle_sha256: digest,
        handle_value,
        role: grant.role,
        email: identity.email.clone(),
        display_name: user.and_then(|u| u.display_name),
        auth_time: view.session.auth_time,
        auth_time_source: view.session.auth_time_source,
        aal: identity.aal,
        provider_id: view.session.provider_id.clone(),
    })
}

/// The user and session a refused handle belongs to, when the store knows it.
async fn requester_of(st: &AdminState, handle: Option<&str>) -> Option<(UserId, SessionId)> {
    let digest = Secret::new(handle?.to_string()).digest();
    let view = st
        .sessions
        .lookup_handle(&digest, &st.cfg.host)
        .await
        .ok()??;
    Some((view.session.user_id, view.session.session_id))
}

/// The status, error code and reason an `admin.denied` records for a denial.
fn describe(d: &Denial) -> (StatusCode, &'static str) {
    match d {
        Denial::UntrustedPeer => (StatusCode::FORBIDDEN, "untrusted_peer"),
        Denial::LoginRequired => (StatusCode::FORBIDDEN, "login_required"),
        Denial::AuthTooOld => (StatusCode::FORBIDDEN, "auth_too_old"),
        Denial::NotAdmin { .. } => (StatusCode::FORBIDDEN, "not_admin"),
        Denial::RoleInsufficient => (StatusCode::FORBIDDEN, "role_insufficient"),
        Denial::AalInsufficient => (StatusCode::FORBIDDEN, "aal_insufficient"),
        Denial::WrongHost => (StatusCode::NOT_FOUND, "not_found"),
        Denial::StoreUnavailable => (StatusCode::SERVICE_UNAVAILABLE, "store_unavailable"),
        Denial::Overloaded => (StatusCode::SERVICE_UNAVAILABLE, "overloaded"),
        Denial::HeaderTooLarge => (
            StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
            "header_too_large",
        ),
    }
}

/// The code a denial answers with (and counts under).
pub fn code_of(d: &Denial) -> &'static str {
    describe(d).1
}

/// The required `admin.denied` event of a refusal (`reason`), for the user and
/// session that made the request.
pub fn denied_event(
    st: &AdminState,
    req: &ReqInfo,
    who: Option<(&UserId, &SessionId)>,
    reason: Reason,
) -> Option<Event> {
    let em = st.emitter.as_ref()?;
    Some(em.required(
        EventKind::AdminDenied,
        Outcome::Failure,
        req.rid.clone(),
        |b| {
            let b = b
                .app(&st.cfg.policy.app_id)
                .ip(req.client_ip)
                .reason(reason)
                .attr("endpoint", req.pattern)
                .attr("method", req.method.as_str());
            match who {
                Some((u, s)) => b.user(u).session(s),
                None => b,
            }
        },
    ))
}

/// Write the `admin.denied` event of a refusal. A store failure is logged;
/// the refusal stands either way.
pub async fn record_denied(
    st: &AdminState,
    req: &ReqInfo,
    who: Option<(&UserId, &SessionId)>,
    reason: Reason,
) {
    if let Some(ev) = denied_event(st, req, who, reason)
        && let Err(e) = st.events.append_required(vec![ev]).await
    {
        tracing::warn!(error = %e, reason = reason.0, "admin.denied could not be recorded");
    }
}

/// A read-only administrator attempted a mutation: record it and refuse
/// (`403 role_insufficient`). Handlers call this before any store read.
pub async fn require_admin_role(st: &AdminState, ctx: &Ctx) -> Result<(), Response> {
    if ctx.principal.role == crate::store::AdminRole::Admin {
        return Ok(());
    }
    record_denied(
        st,
        &ctx.req,
        Some((&ctx.principal.user_id, &ctx.principal.session_id)),
        reasons::ROLE_INSUFFICIENT,
    )
    .await;
    Err(api::error(
        st,
        &ctx.req,
        &ctx.principal,
        StatusCode::FORBIDDEN,
        "role_insufficient",
    ))
}

/// Record what the listener owes a refusal (the `admin.denied` events; the
/// verify denials were recorded by the engine's caller) and render it.
pub async fn respond(st: &AdminState, req: &ReqInfo, refused: &Refused) -> Response {
    let (status, code) = describe(&refused.denial);
    let who = refused.requester.as_ref().map(|(u, s)| (u, s));
    match &refused.denial {
        Denial::NotAdmin { .. } => record_denied(st, req, who, reasons::NOT_ADMIN).await,
        Denial::AuthTooOld => record_denied(st, req, who, reasons::AUTH_TOO_OLD).await,
        Denial::AalInsufficient => record_denied(st, req, who, reasons::AAL_INSUFFICIENT).await,
        _ => {}
    }
    let login = pages::console_url(st);
    let mut resp = match &refused.denial {
        Denial::NotAdmin { user_id, email } => {
            if req.api {
                api::json_error(status, code)
            } else {
                let uid = user_id.to_string();
                let mail = email.as_ref().map(ToString::to_string);
                pages::denied_page(
                    req,
                    status,
                    code,
                    &Extra {
                        user_id: Some(&uid),
                        email: mail.as_deref(),
                        login_url: None,
                    },
                )
            }
        }
        Denial::LoginRequired | Denial::AuthTooOld => {
            if req.api {
                api::json(status, &serde_json::json!({"error": code, "login": login}))
            } else {
                pages::denied_page(
                    req,
                    status,
                    code,
                    &Extra {
                        user_id: None,
                        email: None,
                        login_url: Some(&login),
                    },
                )
            }
        }
        _ => api::bare_error(req, status, code),
    };
    if matches!(refused.denial, Denial::Overloaded) {
        resp.headers_mut()
            .insert(header::RETRY_AFTER, header::HeaderValue::from_static("1"));
    }
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_patterns() {
        assert_eq!(pattern_of("/"), "/");
        assert_eq!(pattern_of("/v1/me"), "/v1/me");
        assert_eq!(pattern_of("/me"), "unmatched");
        assert_eq!(pattern_of("/v1/"), "unmatched");
        assert_eq!(pattern_of("/users"), "/users");
        assert_eq!(pattern_of("/users/u_a"), "/users/{id}");
        assert_eq!(
            pattern_of("/v1/users/u_a/disable"),
            "/v1/users/{id}/disable"
        );
        assert_eq!(
            pattern_of("/v1/users/u_a/sessions/terminate"),
            "/v1/users/{id}/sessions/terminate"
        );
        assert_eq!(
            pattern_of("/sessions/s_x/terminate"),
            "/sessions/{id}/terminate"
        );
        assert_eq!(pattern_of("/v1/events"), "/v1/events");
        assert_eq!(pattern_of("/users/u_a/other"), "unmatched");
        assert_eq!(pattern_of("/assets/admin.css"), "/assets/admin.css");
    }

    #[test]
    fn the_console_host_is_matched_with_or_without_a_port() {
        let h = Host::parse("hopae-admin.example.test").unwrap();
        assert!(host_is_console("hopae-admin.example.test", &h));
        assert!(host_is_console("HOPAE-ADMIN.example.test:8443", &h));
        assert!(!host_is_console("app.example.test", &h));
        assert!(!host_is_console("hopae-admin.example.test.evil", &h));
        assert!(!host_is_console("", &h));
    }
}
