//! The admin listener's router: every route of `docs/ADMIN.md`, the request
//! id, the pinned response headers, the concurrency cap, the body and query
//! limits, authentication, and the `404`/`405` answers.
//!
//! Serve it with connect info so the trusted-proxy rule can see the TCP peer:
//! `axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>())`.
//!
//! Layers, outermost first: `outer` (request id, no `OPTIONS`, the security
//! headers on whatever comes back) → `limit` (the concurrency permit before
//! any authentication; the `413` limits) → `gate` (peer, host, handle, grant;
//! the stylesheet is the one thing served without a handle) → the routes.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{get, post};

use crate::admin::pages;
use crate::admin::{
    AdminState, Ctx, ReqInfo, api, auth, csrf, events, me, sessions, status, users,
};
use crate::crypto::random_id;
use crate::http::security;
use crate::portal::i18n::pick_lang;
use crate::telemetry::counters;

/// The console's content security policy: the portal's, plus `img-src 'self'`.
pub const CONTENT_SECURITY_POLICY: &str = "default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'";

/// The per-request id, put into the request extensions by `outer`.
#[derive(Clone, Debug)]
struct RequestId(String);

/// Router of the admin listener.
pub fn router(state: Arc<AdminState>) -> Router {
    let routes = Router::new()
        .route("/", get(status::page))
        .route("/v1/status", get(status::data))
        .route("/metrics", get(crate::admin::metrics::get))
        .route(
            "/v1/authentication/profiles",
            get(crate::admin::profiles::get).put(crate::admin::profiles::put),
        )
        .route(
            "/v1/authentication/projections",
            get(crate::admin::projections::get).put(crate::admin::projections::put),
        )
        .route(
            "/v1/authentication/profiles/validate",
            post(crate::admin::profiles::validate_api),
        )
        .route("/v1/me", get(me::get))
        .route("/assets/admin.css", get(stylesheet))
        .route("/users", get(users::list_page))
        .route("/v1/users", get(users::list_api))
        .route("/users/{id}", get(users::detail_page))
        .route("/v1/users/{id}", get(users::detail_api))
        .route("/users/{id}/disable", post(users::disable_page))
        .route("/v1/users/{id}/disable", post(users::disable_api))
        .route("/users/{id}/enable", post(users::enable_page))
        .route("/v1/users/{id}/enable", post(users::enable_api))
        .route(
            "/v1/users/{id}/factors",
            get(crate::admin::factors::list_api),
        )
        .route(
            "/v1/users/{id}/factors/reset",
            post(crate::admin::factors::reset_api),
        )
        .route("/v1/users/bulk/disable", post(users::bulk_disable_api))
        .route(
            "/users/{id}/sessions/terminate",
            post(users::terminate_sessions_page),
        )
        .route(
            "/v1/users/{id}/sessions/terminate",
            post(users::terminate_sessions_api),
        )
        .route("/sessions", get(sessions::list_page))
        .route("/v1/sessions", get(sessions::list_api))
        .route("/sessions/{id}", get(sessions::detail_page))
        .route("/v1/sessions/{id}", get(sessions::detail_api))
        .route("/sessions/{id}/terminate", post(sessions::terminate_page))
        .route("/v1/sessions/{id}/terminate", post(sessions::terminate_api))
        .route("/events", get(events::list_page))
        .route("/v1/events", get(events::list_api))
        .route(
            "/v1/subjects/resolve",
            post(crate::admin::subjects::resolve_api),
        )
        .route(
            "/v1/subjects/search",
            post(crate::admin::subjects::search_api),
        )
        .route(
            "/v1/subjects/lifecycle",
            post(crate::admin::subjects::lifecycle_api),
        )
        .route(
            "/v1/subjects/lifecycle/snapshot",
            post(crate::admin::subjects::snapshot_api),
        )
        .route(
            "/v1/subjects/workloads/snapshot",
            post(crate::admin::subjects::workloads_snapshot_api),
        )
        .route(
            "/v1/explain/authentication",
            post(crate::admin::explain::explain_api),
        )
        .route(
            "/v1/subjects/groups",
            post(crate::admin::groups::subject_groups_api),
        )
        .route("/v1/groups/search", post(crate::admin::groups::search_api))
        .route("/v1/groups/get", post(crate::admin::groups::get_api))
        .route("/v1/groups/create", post(crate::admin::groups::create_api))
        .route("/v1/groups/update", post(crate::admin::groups::update_api))
        .route("/v1/groups/delete", post(crate::admin::groups::delete_api))
        .route(
            "/v1/groups/members/add",
            post(crate::admin::groups::add_member_api),
        )
        .route(
            "/v1/groups/members/remove",
            post(crate::admin::groups::remove_member_api),
        )
        .route(
            "/v1/groups/projection/snapshot",
            post(crate::admin::groups::projection_snapshot_api),
        )
        .route(
            "/v1/groups/projection/changes",
            post(crate::admin::groups::projection_changes_api),
        )
        .fallback(not_found)
        .layer(middleware::from_fn_with_state(state.clone(), gate))
        .layer(middleware::from_fn_with_state(state.clone(), limit))
        .with_state(state.clone());
    // `outer` wraps the whole route set as one service: the router adds the
    // `allow` header of a `405` outside every layer applied to its routes.
    Router::new()
        .fallback_service(routes)
        .layer(middleware::from_fn_with_state(
            state.clone(),
            crate::admin::delegation::middleware,
        ))
        .layer(middleware::from_fn_with_state(state, outer))
}

/// The request id of `req` (set by `outer`).
fn request_id(req: &Request) -> String {
    req.extensions()
        .get::<RequestId>()
        .map_or_else(|| "r_unknown".to_string(), |r| r.0.clone())
}

/// Request facts for a refusal made before authentication finished.
fn facts(req: &Request, rid: &str, client_ip: std::net::IpAddr) -> ReqInfo {
    let path = req.uri().path();
    ReqInfo {
        rid: rid.to_string(),
        client_ip,
        user_agent: None,
        lang: pick_lang(
            req.headers()
                .get(header::ACCEPT_LANGUAGE)
                .and_then(|v| v.to_str().ok()),
        ),
        https: false,
        method: req.method().clone(),
        pattern: auth::pattern_of(path),
        api: path.starts_with("/v1/") || path == "/metrics",
    }
}

/// The fallback store deadline of a stage of the request (`admin.query_budget_ms`):
/// every store call made inside `fut` without a deadline of its own is bounded
/// by it (ADR-0016 decision 12; the calls the console makes also pass theirs
/// explicitly, and the earliest present one wins).
async fn scoped<F: std::future::Future>(st: &AdminState, fut: F) -> F::Output {
    crate::store::sqlite::with_deadline(tokio::time::Instant::now() + st.cfg.query_budget, fut)
        .await
}

/// Assign the request id, refuse `OPTIONS`, run the request, and stamp the
/// pinned headers and the id on whatever comes back, whatever produced it.
async fn outer(State(st): State<Arc<AdminState>>, mut req: Request, next: Next) -> Response {
    let rid = random_id(st.rng.as_ref(), "r_");
    req.extensions_mut().insert(RequestId(rid.clone()));
    // No `OPTIONS` handler exists anywhere: a preflight is a plain `404`
    // without CORS headers, so a browser never sends the real request.
    let mut resp = if req.method() == Method::OPTIONS {
        let info = facts(
            &req,
            &rid,
            std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
        );
        api::bare_error(&info, StatusCode::NOT_FOUND, "not_found")
    } else {
        let resp = next.run(req).await;
        // The router answers a known path with the wrong method itself, with no
        // body, and adds its `allow` header outside every layer: finish it here.
        if resp.status() == StatusCode::METHOD_NOT_ALLOWED
            && !resp.headers().contains_key(header::CONTENT_TYPE)
        {
            method_not_allowed(resp)
        } else {
            resp
        }
    };
    let h = resp.headers_mut();
    security::apply(h);
    h.insert(
        "content-security-policy",
        HeaderValue::from_static(CONTENT_SECURITY_POLICY),
    );
    h.insert("x-robots-tag", HeaderValue::from_static("noindex"));
    if let Ok(v) = HeaderValue::from_str(&rid) {
        h.insert("x-request-id", v);
    }
    resp
}

/// `limits.admin_max_concurrent`: the permit is taken before the peer check
/// and authentication, so refused and unauthenticated requests are bounded by
/// the cap; excess requests are refused at once, not queued. Also the body
/// (64 KiB) and query (4 KiB) limits, before anything is parsed.
async fn limit(State(st): State<Arc<AdminState>>, req: Request, next: Next) -> Response {
    let rid = request_id(&req);
    let Ok(permit) = st.in_flight.clone().try_acquire_owned() else {
        let info = facts(
            &req,
            &rid,
            std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
        );
        let refused = auth::Refused::overloaded();
        counters::inc(counters::ADMIN_DENIED_TOTAL, &[("reason", "overloaded")]);
        count(&st, "none", "overloaded");
        return scoped(&st, auth::respond(&st, &info, &refused)).await;
    };
    let declared = req
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok());
    let too_large = declared.is_some_and(|n| n > api::MAX_BODY_BYTES)
        || req
            .uri()
            .query()
            .is_some_and(|q| q.len() > api::MAX_QUERY_BYTES);
    let resp = if too_large {
        let info = facts(
            &req,
            &rid,
            std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
        );
        api::bare_error(&info, StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large")
    } else {
        next.run(req).await
    };
    drop(permit);
    resp
}

/// Authenticate every request but the stylesheet's, then run the handler with
/// the principal and the request facts in the extensions.
async fn gate(
    State(st): State<Arc<AdminState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    mut req: Request,
    next: Next,
) -> Response {
    let rid = request_id(&req);
    let path = req.uri().path().to_string();
    let admission = if crate::admin::service_credentials::presented(req.headers()).is_some()
        && req
            .extensions()
            .get::<hangang_runtime::AuthenticatedTlsPeer>()
            .is_some()
        && req
            .extensions()
            .get::<crate::admin::delegation::ValidatedDelegation>()
            .is_none()
    {
        auth::admit_service(&st, peer.ip(), req.headers())
    } else if req
        .extensions()
        .get::<crate::admin::delegation::ValidatedDelegation>()
        .is_some()
        && req
            .extensions()
            .get::<hangang_runtime::AuthenticatedTlsPeer>()
            .is_some()
    {
        auth::admit_delegated(&st, peer.ip(), req.headers(), &rid)
    } else {
        auth::admit(&st, peer.ip(), req.headers(), &rid)
    };
    let client = match admission {
        Ok(c) => c,
        Err(refused) => {
            let ip = refused.client_ip.unwrap_or_else(|| peer.ip());
            let info = facts(&req, &rid, ip);
            count(&st, "none", auth::code_of(&refused.denial));
            return scoped(&st, auth::respond(&st, &info, &refused)).await;
        }
    };
    let mut info = facts(&req, &rid, client.ip);
    info.https = client.https;
    // The stylesheet reveals nothing and the denial pages load it with a
    // cookie that may belong to a user without a grant.
    if path == "/assets/admin.css" && req.method() == Method::GET {
        return next.run(req).await;
    }
    let user_agent = req
        .headers()
        .get(header::USER_AGENT)
        .map(|v| crate::policy::binding::normalize_user_agent(v.as_bytes()));
    info.user_agent = user_agent.clone();
    // A route-scoped service credential (`Bearer hsc1.…`): mTLS-bound,
    // audience-checked, exact read routes only; never combined with a
    // delegation or a browser session.
    let mut service = None;
    let service_principal = if crate::admin::service_credentials::presented(req.headers()).is_some()
    {
        if req
            .extensions()
            .get::<crate::admin::delegation::ValidatedDelegation>()
            .is_some()
        {
            count(&st, "service", "denied");
            return crate::admin::service_credentials::Refusal::Credential.respond();
        }
        let peer = req
            .extensions()
            .get::<crate::admin::service_credentials::PeerCertificate>()
            .cloned();
        match scoped(
            &st,
            crate::admin::service_credentials::authenticate(
                &st,
                req.method(),
                &path,
                req.headers(),
                peer.as_ref(),
                &rid,
            ),
        )
        .await
        {
            Ok((p, caller)) => {
                service = Some(caller);
                Some(p)
            }
            Err(refusal) => {
                count(&st, "service", "denied");
                return refusal.respond();
            }
        }
    } else {
        None
    };
    let principal = if let Some(p) = service_principal {
        p
    } else if let Some(p) = req.extensions().get::<crate::admin::Principal>().cloned() {
        if !p.authority.as_ref().is_some_and(|v| v.valid()) {
            return api::json_error(StatusCode::FORBIDDEN, "delegation_rejected");
        }
        p
    } else {
        match scoped(
            &st,
            auth::authenticate(
                &st,
                &client,
                req.headers(),
                &path,
                req.method(),
                user_agent,
                &rid,
            ),
        )
        .await
        {
            Ok(p) => p,
            Err(refused) => {
                count(&st, "none", auth::code_of(&refused.denial));
                return scoped(&st, auth::respond(&st, &info, &refused)).await;
            }
        }
    };
    let delegated_actor = req
        .extensions()
        .get::<crate::admin::delegation::Actor>()
        .cloned();
    if delegated_actor.as_ref().is_some_and(|a| {
        a.expected_user_id
            .as_ref()
            .is_some_and(|id| id != principal.user_id.as_str())
    }) {
        return api::json_error(StatusCode::FORBIDDEN, "delegation_rejected");
    }
    let role = principal.role.as_str();
    let ctx = Ctx {
        delegated_actor,
        service,
        principal,
        req: info,
    };
    // Defense in depth: a service caller never reaches a mutation, whatever
    // its stored routes say.
    if ctx.service.is_some() && auth::is_mutation(req.method(), ctx.req.pattern) {
        count(&st, "service", "denied");
        return crate::admin::service_credentials::Refusal::Route.respond();
    }
    // A mutation is checked here, before its handler: the form token or the
    // API header first, then the role, so no handler can forget either and
    // none reads the body again (it receives `Mutation` in the extensions).
    if auth::is_mutation(req.method(), ctx.req.pattern) {
        let (mut parts, body) = req.into_parts();
        let mutation = match csrf::guard(&st, &ctx, &parts.headers, body).await {
            Ok(m) => m,
            Err(resp) => {
                count(&st, role, "denied");
                return resp;
            }
        };
        if let Err(resp) = scoped(&st, auth::require_admin_role(&st, &ctx)).await {
            count(&st, role, "denied");
            return resp;
        }
        parts.extensions.insert(mutation);
        req = Request::from_parts(parts, Body::empty());
    }
    req.extensions_mut().insert(ctx);
    let resp = scoped(&st, next.run(req)).await;
    let outcome = match resp.status().as_u16() {
        200..=399 => "ok",
        403 => "denied",
        400..=499 => "client_error",
        _ => "server_error",
    };
    count(&st, role, outcome);
    resp
}

/// The router's `405` has no body: give it the console's JSON error, keeping
/// the `allow` header.
fn method_not_allowed(resp: Response) -> Response {
    let (mut parts, _) = resp.into_parts();
    parts.headers.remove(header::CONTENT_LENGTH);
    // `HEAD` rides along with `GET` in the router; the console documents the
    // methods it serves.
    if let Some(allow) = parts
        .headers
        .get(header::ALLOW)
        .and_then(|v| v.to_str().ok())
        .map(|v| {
            v.split(',')
                .map(str::trim)
                .filter(|m| *m != "HEAD")
                .collect::<Vec<_>>()
                .join(", ")
        })
        && let Ok(v) = HeaderValue::from_str(&allow)
    {
        parts.headers.insert(header::ALLOW, v);
    }
    parts.headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    Response::from_parts(parts, Body::from(r#"{"error":"method_not_allowed"}"#))
}

fn count(st: &AdminState, role: &str, outcome: &str) {
    if st.cfg.insecure_mode {
        counters::inc(
            counters::ADMIN_REQUESTS_TOTAL,
            &[
                ("role", role),
                ("outcome", outcome),
                ("insecure_mode", "true"),
            ],
        );
    } else {
        counters::inc(
            counters::ADMIN_REQUESTS_TOTAL,
            &[("role", role), ("outcome", outcome)],
        );
    }
}

async fn stylesheet() -> Response {
    let mut r = Response::new(Body::from(pages::STYLESHEET));
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/css; charset=utf-8"),
    );
    r
}

/// An unknown path, for a caller who is authenticated and granted.
async fn not_found(State(st): State<Arc<AdminState>>, ctx: Ctx) -> Response {
    api::error(
        &st,
        &ctx.req,
        &ctx.principal,
        StatusCode::NOT_FOUND,
        "not_found",
    )
}
