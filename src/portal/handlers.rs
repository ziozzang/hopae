//! Portal route handlers.
//!
//! Every handler follows the same shape: read the request facts once
//! ([`prepare`]), check the transport-level guards (cookie size, form body,
//! `Origin`, CSRF token), call the services, and render. Handlers take the
//! whole request so that size limits, form parsing and error pages are ours
//! rather than an extractor's plain-text rejection.
//!
//! Early returns carry the finished `Response` as the error value, which is
//! large by design.
#![allow(clippy::result_large_err)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use askama::Template;
use axum::body::Body;
use axum::extract::{ConnectInfo, Path, Request, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header};
use axum::response::Response;

use super::clientinfo;
use super::cookies::{self, PORTAL_BIND_MAX_AGE, Presented};
use super::i18n::{Lang, Strings, pick_lang, strings};
use super::pages::{self, ChoiceView, ErrorPage};
use super::ports::*;
use super::{MAX_BODY_BYTES, PortalState};
use crate::crypto::Secret;
use crate::http::csrf::{self, Purpose};
use crate::http::security;
use crate::provider::types::{CallbackQuery, ProviderHealth, ProviderId};
use url::Origin;

/// Longest accepted query string.
const MAX_QUERY_BYTES: usize = 16 * 1024;
/// Longest accepted `state`, `code` or provider error value.
const MAX_PARAM_BYTES: usize = 2048;

/// The per-request id, put into the request extensions by the outer middleware.
#[derive(Clone, Debug)]
pub struct RequestId(pub String);

/// Request facts every handler needs.
struct Rq {
    ctx: RequestCtx,
    lang: Lang,
    presented: Presented,
}

impl Rq {
    fn t(&self) -> &'static Strings {
        strings(self.lang)
    }

    fn rid(&self) -> &str {
        &self.ctx.request_id
    }
}

fn header_str(headers: &HeaderMap, name: impl header::AsHeaderName) -> Option<&str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

fn request_id(parts: &Parts) -> String {
    parts
        .extensions
        .get::<RequestId>()
        .map_or_else(|| "r_unknown".to_string(), |r| r.0.clone())
}

/// Language and request id only (usable before the rest of the request is trusted).
pub(crate) fn lang_of(headers: &HeaderMap) -> Lang {
    pick_lang(header_str(headers, header::ACCEPT_LANGUAGE))
}

fn error_response(t: &Strings, rid: &str, page: ErrorPage) -> Response {
    let body = pages::error_html(page, t, rid);
    let status = StatusCode::from_u16(page.status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    html_response(status, body)
}

/// A bare error page for callers outside the handlers (middleware, fallback).
pub(crate) fn plain_error(headers: &HeaderMap, rid: &str, page: ErrorPage) -> Response {
    error_response(strings(lang_of(headers)), rid, page)
}

fn html_response(status: StatusCode, body: String) -> Response {
    let mut r = Response::new(Body::from(body));
    *r.status_mut() = status;
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    r
}

fn fail_response(rq: &Rq, f: Failure) -> Response {
    tracing::info!(
        request_id = rq.rid(),
        reason = f.reason.0,
        "portal request refused"
    );
    error_response(rq.t(), rq.rid(), ErrorPage::from_fail(f.kind))
}

fn add_cookie(r: &mut Response, set_cookie: &str) {
    if let Ok(v) = HeaderValue::from_str(set_cookie) {
        r.headers_mut().append(header::SET_COOKIE, v);
    }
}

fn render_page<T: Template>(rq: &Rq, page: T, cookies: &[String]) -> Response {
    render_page_status(rq, StatusCode::OK, page, cookies, &[])
}

/// A page with an explicit status and the extra `form-action` origins its
/// form needs (the browser enforces `form-action` on the redirect after the POST).
fn render_page_status<T: Template>(
    rq: &Rq,
    status: StatusCode,
    page: T,
    cookies: &[String],
    form_origins: &[Origin],
) -> Response {
    match page.render() {
        Ok(body) => {
            let mut r = html_response(status, body);
            for c in cookies {
                add_cookie(&mut r, c);
            }
            if !form_origins.is_empty() {
                r.extensions_mut()
                    .insert(security::FormActionOrigins(form_origins.to_vec()));
            }
            r
        }
        Err(_) => error_response(rq.t(), rq.rid(), ErrorPage::Unavailable),
    }
}

fn redirect_response(st: &PortalState, rq: &Rq, redirect: &Redirect, extra: &[String]) -> Response {
    let Ok(location) = HeaderValue::from_str(redirect.location.as_str()) else {
        return error_response(rq.t(), rq.rid(), ErrorPage::Unavailable);
    };
    let mut r = Response::new(Body::empty());
    *r.status_mut() = StatusCode::FOUND;
    r.headers_mut().insert(header::LOCATION, location);
    for c in extra {
        add_cookie(&mut r, c);
    }
    if let Some(h) = &redirect.set_handle {
        add_cookie(
            &mut r,
            &cookies::set_cookie(
                &st.cfg.cookie_names.handle,
                h.value.expose(),
                h.max_age,
                st.cfg.secure,
            ),
        );
    }
    r
}

fn portal_cookie_header(st: &PortalState, bind: &Secret) -> String {
    cookies::set_cookie(
        &st.cfg.cookie_names.portal,
        bind.expose(),
        PORTAL_BIND_MAX_AGE,
        st.cfg.secure,
    )
}

/// Read the request facts. Refuses oversized cookie headers.
fn prepare(st: &PortalState, parts: &Parts) -> Result<Rq, Response> {
    let rid = request_id(parts);
    let lang = lang_of(&parts.headers);
    let peer = parts
        .extensions
        .get::<ConnectInfo<SocketAddr>>()
        // Without connect info the peer is unknown: an address no trusted
        // network contains, so forwarding headers are ignored.
        .map_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED), |c| c.0.ip());
    let client = clientinfo::resolve(peer, &parts.headers, &st.cfg.trusted_proxies);
    let presented = match cookies::read(&parts.headers, &st.cfg.cookie_names) {
        Ok(p) => p,
        Err(_) => return Err(error_response(strings(lang), &rid, ErrorPage::BadRequest)),
    };
    let user_agent = parts
        .headers
        .get(header::USER_AGENT)
        .map(|v| crate::policy::binding::normalize_user_agent(v.as_bytes()));
    Ok(Rq {
        ctx: RequestCtx {
            request_id: rid,
            client_ip: client.ip,
            user_agent,
            https: client.https,
        },
        lang,
        presented,
    })
}

/// Query parameters, first occurrence of each name.
struct Params(Vec<(String, String)>);

impl Params {
    fn get(&self, name: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

fn query(parts: &Parts) -> Option<Params> {
    let q = parts.uri.query().unwrap_or("");
    if q.len() > MAX_QUERY_BYTES {
        return None;
    }
    Some(Params(
        form_urlencoded::parse(q.as_bytes())
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect(),
    ))
}

/// `[A-Za-z0-9_-]{1,max}`: the shape of transaction ids and provider ids.
fn simple_id(s: &str, max: usize) -> bool {
    !s.is_empty()
        && s.len() <= max
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
}

/// A POST body read within the limit.
struct Form(Params);

async fn read_form(st: &PortalState, rq: &Rq, parts: &Parts, body: Body) -> Result<Form, Response> {
    let _ = st;
    let is_form = header_str(&parts.headers, header::CONTENT_TYPE).is_some_and(|ct| {
        ct.split(';').next().is_some_and(|m| {
            m.trim()
                .eq_ignore_ascii_case("application/x-www-form-urlencoded")
        })
    });
    if !is_form {
        return Err(error_response(rq.t(), rq.rid(), ErrorPage::BadRequest));
    }
    if header_str(&parts.headers, header::CONTENT_LENGTH)
        .and_then(|v| v.parse::<usize>().ok())
        .is_some_and(|n| n > MAX_BODY_BYTES)
    {
        return Err(error_response(rq.t(), rq.rid(), ErrorPage::TooLarge));
    }
    let bytes = axum::body::to_bytes(body, MAX_BODY_BYTES)
        .await
        .map_err(|_| error_response(rq.t(), rq.rid(), ErrorPage::TooLarge))?;
    Ok(Form(Params(
        form_urlencoded::parse(&bytes)
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect(),
    )))
}

/// `Origin` and CSRF checks for a state-changing POST. `binding` is the value
/// the token must be bound to (`None`: the browser presented nothing to bind to).
async fn guard(
    st: &PortalState,
    rq: &Rq,
    parts: &Parts,
    form: &Form,
    purpose: Purpose,
    binding: Option<&str>,
) -> Result<(), Response> {
    let refuse = |cause: &'static str| async move {
        st.services
            .csrf_rejected(&rq.ctx, purpose.as_str(), cause)
            .await;
        tracing::info!(
            request_id = rq.rid(),
            purpose = purpose.as_str(),
            cause,
            "csrf check refused"
        );
        Err(error_response(rq.t(), rq.rid(), ErrorPage::Forbidden))
    };
    // A repeated `Origin` header is ambiguous: refuse it like a mismatch.
    let origin = if parts.headers.get_all(header::ORIGIN).iter().count() == 1 {
        header_str(&parts.headers, header::ORIGIN)
    } else {
        None
    };
    if !security::origin_allowed(origin, &st.cfg.origin) {
        return refuse("origin").await;
    }
    let (Some(binding), Some(token)) = (binding, form.0.get("csrf")) else {
        return refuse("token").await;
    };
    match csrf::verify(&st.csrf_key, binding, purpose, token, st.clock.now()) {
        Ok(()) => Ok(()),
        Err(e) => refuse(e.label()).await,
    }
}

fn token_for(st: &PortalState, binding: &str, purpose: Purpose) -> String {
    csrf::issue(
        &st.csrf_key,
        binding,
        purpose,
        st.clock.now(),
        st.rng.as_ref(),
    )
}

/// The portal binding value for a page that plants or refreshes it.
fn effective_bind(st: &PortalState, rq: &Rq) -> Secret {
    rq.presented
        .bind
        .clone()
        .unwrap_or_else(|| cookies::new_bind(st.rng.as_ref()))
}

// ---- routes ----------------------------------------------------------------

pub(crate) async fn login_get(State(st): State<PortalState>, req: Request) -> Response {
    let (parts, _) = req.into_parts();
    let rq = match prepare(&st, &parts) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let txn = match query(&parts)
        .as_ref()
        .and_then(|q| q.get("txn").map(str::to_owned))
    {
        Some(t) if simple_id(&t, 128) => t,
        _ => return error_response(rq.t(), rq.rid(), ErrorPage::BadRequest),
    };
    let bind = effective_bind(&st, &rq);
    let cookies = Cookies {
        bind: Some(bind.clone()),
        handle: rq.presented.handle.clone(),
    };
    let planted = [portal_cookie_header(&st, &bind)];
    match st
        .services
        .login_visit(&rq.ctx, &Secret::new(txn.clone()), &cookies)
        .await
    {
        LoginVisit::Chooser {
            providers,
            form_origins,
        } => {
            let views: Vec<ChoiceView> = providers.iter().map(ChoiceView::from).collect();
            let csrf = token_for(&st, bind.expose(), Purpose::Login);
            render_page_status(
                &rq,
                StatusCode::OK,
                pages::Chooser {
                    t: rq.t(),
                    request_id: rq.rid(),
                    csrf: &csrf,
                    txn: &txn,
                    providers: &views,
                },
                &planted,
                &form_origins,
            )
        }
        LoginVisit::Redirect(r) => redirect_response(&st, &rq, &r, &planted),
        LoginVisit::ConfirmNewHost { host, form_origin } => {
            let csrf = token_for(&st, bind.expose(), Purpose::Continue);
            render_page_status(
                &rq,
                StatusCode::OK,
                pages::Continue {
                    t: rq.t(),
                    request_id: rq.rid(),
                    csrf: &csrf,
                    txn: &txn,
                    host: &host,
                },
                &planted,
                &[form_origin],
            )
        }
        LoginVisit::Failed(f) => fail_response(&rq, f),
    }
}

pub(crate) async fn login_post(
    State(st): State<PortalState>,
    Path(provider): Path<String>,
    req: Request,
) -> Response {
    let (parts, body) = req.into_parts();
    let rq = match prepare(&st, &parts) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let form = match read_form(&st, &rq, &parts, body).await {
        Ok(f) => f,
        Err(resp) => return resp,
    };
    let binding = rq.presented.bind.as_ref().map(|b| b.expose().to_string());
    if let Err(resp) = guard(&st, &rq, &parts, &form, Purpose::Login, binding.as_deref()).await {
        return resp;
    }
    let txn = form.0.get("txn").filter(|t| simple_id(t, 128));
    let (Some(txn), true) = (txn, simple_id(&provider, 64)) else {
        return error_response(rq.t(), rq.rid(), ErrorPage::BadRequest);
    };
    let cookies = Cookies {
        bind: rq.presented.bind.clone(),
        handle: rq.presented.handle.clone(),
    };
    match st
        .services
        .begin_provider(
            &rq.ctx,
            &Secret::new(txn.to_string()),
            &ProviderId::new(provider),
            &cookies,
        )
        .await
    {
        Ok(r) => redirect_response(&st, &rq, &r, &[]),
        Err(f) => fail_response(&rq, f),
    }
}

pub(crate) async fn retry_post(State(st): State<PortalState>, req: Request) -> Response {
    let (parts, body) = req.into_parts();
    let rq = match prepare(&st, &parts) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let form = match read_form(&st, &rq, &parts, body).await {
        Ok(f) => f,
        Err(resp) => return resp,
    };
    let binding = rq.presented.bind.as_ref().map(|b| b.expose().to_string());
    if let Err(resp) = guard(&st, &rq, &parts, &form, Purpose::Retry, binding.as_deref()).await {
        return resp;
    }
    let Some(state) = form
        .0
        .get("state")
        .filter(|s| !s.is_empty() && s.len() <= MAX_PARAM_BYTES)
    else {
        return error_response(rq.t(), rq.rid(), ErrorPage::BadRequest);
    };
    let cookies = Cookies {
        bind: rq.presented.bind.clone(),
        handle: rq.presented.handle.clone(),
    };
    match st.services.retry(&rq.ctx, state, &cookies).await {
        Ok(r) => redirect_response(&st, &rq, &r, &[]),
        Err(f) => fail_response(&rq, f),
    }
}

pub(crate) async fn continue_post(State(st): State<PortalState>, req: Request) -> Response {
    let (parts, body) = req.into_parts();
    let rq = match prepare(&st, &parts) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let form = match read_form(&st, &rq, &parts, body).await {
        Ok(f) => f,
        Err(resp) => return resp,
    };
    let binding = rq.presented.bind.as_ref().map(|b| b.expose().to_string());
    if let Err(resp) = guard(
        &st,
        &rq,
        &parts,
        &form,
        Purpose::Continue,
        binding.as_deref(),
    )
    .await
    {
        return resp;
    }
    let Some(txn) = form.0.get("txn").filter(|t| simple_id(t, 128)) else {
        return error_response(rq.t(), rq.rid(), ErrorPage::BadRequest);
    };
    let cookies = Cookies {
        bind: rq.presented.bind.clone(),
        handle: rq.presented.handle.clone(),
    };
    match st
        .services
        .continue_sso(&rq.ctx, &Secret::new(txn.to_string()), &cookies)
        .await
    {
        Ok(r) => redirect_response(&st, &rq, &r, &[]),
        Err(f) => fail_response(&rq, f),
    }
}

pub(crate) async fn callback_get(
    State(st): State<PortalState>,
    Path(provider): Path<String>,
    req: Request,
) -> Response {
    let (parts, _) = req.into_parts();
    let rq = match prepare(&st, &parts) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let bad = || error_response(rq.t(), rq.rid(), ErrorPage::Failed);
    let Some(q) = query(&parts) else { return bad() };
    if !simple_id(&provider, 64) {
        return bad();
    }
    let param = |name: &str| -> Result<Option<String>, ()> {
        match q.get(name) {
            Some(v) if v.len() > MAX_PARAM_BYTES => Err(()),
            Some(v) => Ok(Some(v.to_string())),
            None => Ok(None),
        }
    };
    let (Ok(code), Ok(state), Ok(error), Ok(error_description)) = (
        param("code"),
        param("state"),
        param("error"),
        param("error_description"),
    ) else {
        return bad();
    };
    let cookies = Cookies {
        bind: rq.presented.bind.clone(),
        handle: rq.presented.handle.clone(),
    };
    let query = CallbackQuery {
        code,
        state: state.clone(),
        error,
        error_description,
    };
    match st
        .services
        .callback(&rq.ctx, &ProviderId::new(provider), query, &cookies)
        .await
    {
        CallbackOutcome::Redirect(r) => redirect_response(&st, &rq, &r, &[]),
        CallbackOutcome::LinkNotice { via_provider } => render_page(
            &rq,
            pages::LinkNotice {
                t: rq.t(),
                request_id: rq.rid(),
                via_provider: via_provider.as_deref(),
            },
            &[],
        ),
        CallbackOutcome::RetryOffer {
            can_retry: true,
            form_origin,
        } => {
            // The token is bound to the cookie the browser presented: the
            // replacement the retry must match. Nothing is planted here.
            // The interrupted page is a 400 (S002-7, S002-A5), with the form.
            match (&rq.presented.bind, state) {
                (Some(bind), Some(state)) => {
                    let csrf = token_for(&st, bind.expose(), Purpose::Retry);
                    let origins: Vec<Origin> = form_origin.into_iter().collect();
                    render_page_status(
                        &rq,
                        StatusCode::BAD_REQUEST,
                        pages::Retry {
                            t: rq.t(),
                            request_id: rq.rid(),
                            csrf: &csrf,
                            state: &state,
                        },
                        &[],
                        &origins,
                    )
                }
                _ => bad(),
            }
        }
        CallbackOutcome::RetryOffer {
            can_retry: false, ..
        } => {
            let page = pages::RetryExhausted {
                t: rq.t(),
                request_id: rq.rid(),
            };
            match page.render() {
                Ok(body) => html_response(StatusCode::BAD_REQUEST, body),
                Err(_) => error_response(rq.t(), rq.rid(), ErrorPage::Unavailable),
            }
        }
        CallbackOutcome::Failed(f) => fail_response(&rq, f),
    }
}

pub(crate) async fn switch_get(State(st): State<PortalState>, req: Request) -> Response {
    let (parts, _) = req.into_parts();
    let rq = match prepare(&st, &parts) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let txn = match query(&parts)
        .as_ref()
        .and_then(|q| q.get("txn").map(str::to_owned))
    {
        Some(t) if simple_id(&t, 128) => t,
        _ => return error_response(rq.t(), rq.rid(), ErrorPage::BadRequest),
    };
    let bind = effective_bind(&st, &rq);
    let cookies = Cookies {
        bind: Some(bind.clone()),
        handle: rq.presented.handle.clone(),
    };
    match st
        .services
        .switch_view(&rq.ctx, &Secret::new(txn.clone()), &cookies)
        .await
    {
        Ok(v) => {
            let csrf = token_for(&st, bind.expose(), Purpose::Switch);
            render_page_status(
                &rq,
                StatusCode::OK,
                pages::Switch {
                    t: rq.t(),
                    request_id: rq.rid(),
                    csrf: &csrf,
                    txn: &txn,
                    host: &v.host,
                    current_account: &v.current_account,
                    incoming_account: &v.incoming_account,
                },
                &[portal_cookie_header(&st, &bind)],
                std::slice::from_ref(&v.form_origin),
            )
        }
        Err(f) => fail_response(&rq, f),
    }
}

pub(crate) async fn switch_post(State(st): State<PortalState>, req: Request) -> Response {
    let (parts, body) = req.into_parts();
    let rq = match prepare(&st, &parts) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let form = match read_form(&st, &rq, &parts, body).await {
        Ok(f) => f,
        Err(resp) => return resp,
    };
    let binding = rq.presented.bind.as_ref().map(|b| b.expose().to_string());
    if let Err(resp) = guard(&st, &rq, &parts, &form, Purpose::Switch, binding.as_deref()).await {
        return resp;
    }
    let choice = match form.0.get("choice") {
        Some("switch") => SwitchChoice::Switch,
        Some("keep") => SwitchChoice::Keep,
        _ => return error_response(rq.t(), rq.rid(), ErrorPage::BadRequest),
    };
    let Some(txn) = form.0.get("txn").filter(|t| simple_id(t, 128)) else {
        return error_response(rq.t(), rq.rid(), ErrorPage::BadRequest);
    };
    let cookies = Cookies {
        bind: rq.presented.bind.clone(),
        handle: rq.presented.handle.clone(),
    };
    match st
        .services
        .switch_confirm(&rq.ctx, &Secret::new(txn.to_string()), choice, &cookies)
        .await
    {
        Ok(r) => redirect_response(&st, &rq, &r, &[]),
        Err(f) => fail_response(&rq, f),
    }
}

pub(crate) async fn logout_get(State(st): State<PortalState>, req: Request) -> Response {
    let (parts, _) = req.into_parts();
    let rq = match prepare(&st, &parts) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    // Bound to the portal handle when there is one; without a session the
    // token is bound to nothing and the POST is a no-op anyway.
    let binding = rq.presented.handle.as_ref().map_or("", |h| h.expose());
    let csrf = token_for(&st, binding, Purpose::Logout);
    render_page(
        &rq,
        pages::Logout {
            t: rq.t(),
            request_id: rq.rid(),
            csrf: &csrf,
        },
        &[],
    )
}

pub(crate) async fn logout_post(State(st): State<PortalState>, req: Request) -> Response {
    let (parts, body) = req.into_parts();
    let rq = match prepare(&st, &parts) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let clear = cookies::clear_cookie(&st.cfg.cookie_names.handle, st.cfg.secure);
    let signed_out = |rq: &Rq| {
        render_page(
            rq,
            pages::SignedOut {
                t: rq.t(),
                request_id: rq.rid(),
            },
            std::slice::from_ref(&clear),
        )
    };
    // Without a portal handle there is nothing to end and nothing to protect:
    // a silent no-op, identical to the success page.
    let Some(handle) = rq.presented.handle.clone() else {
        return signed_out(&rq);
    };
    let form = match read_form(&st, &rq, &parts, body).await {
        Ok(f) => f,
        Err(resp) => return resp,
    };
    if let Err(resp) = guard(
        &st,
        &rq,
        &parts,
        &form,
        Purpose::Logout,
        Some(handle.expose()),
    )
    .await
    {
        return resp;
    }
    // Only the handle in the cookie is ever acted on; form fields such as
    // `session` or `scope` are not read.
    match st.services.logout(&rq.ctx, &handle).await {
        Ok(_) => signed_out(&rq),
        Err(f) => fail_response(&rq, f),
    }
}

pub(crate) async fn healthz(State(st): State<PortalState>) -> Response {
    let h = st.services.health().await;
    let providers: serde_json::Map<String, serde_json::Value> = h
        .providers
        .iter()
        .map(|(id, health)| {
            let s = match health {
                ProviderHealth::Ok => "ok",
                ProviderHealth::Degraded(_) => "degraded",
                ProviderHealth::Disabled => "disabled",
            };
            (id.to_string(), serde_json::Value::from(s))
        })
        .collect();
    let body = serde_json::json!({
        "status": "ok",
        "ready": h.store_ok,
        "store": if h.store_ok { "ok" } else { "unavailable" },
        "providers": providers,
        "insecure_mode": st.cfg.insecure_mode,
        "unauthenticated_caller": st.cfg.unauthenticated_caller,
    });
    let mut r = Response::new(Body::from(body.to_string()));
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    r
}

pub(crate) async fn stylesheet() -> Response {
    let mut r = Response::new(Body::from(pages::STYLESHEET));
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/css; charset=utf-8"),
    );
    r
}

pub(crate) async fn not_found(req: Request) -> Response {
    let rid = request_id_of(&req);
    plain_error(req.headers(), &rid, ErrorPage::NotFound)
}

pub(crate) fn request_id_of(req: &Request) -> String {
    req.extensions()
        .get::<RequestId>()
        .map_or_else(|| "r_unknown".to_string(), |r| r.0.clone())
}

/// The response header carrying the request id.
pub(crate) fn request_id_header() -> HeaderName {
    HeaderName::from_static("x-request-id")
}
