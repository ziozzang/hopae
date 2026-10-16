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

#[path = "settings_handlers.rs"]
pub(crate) mod settings_handlers;

/// Longest accepted query string.
const MAX_QUERY_BYTES: usize = 16 * 1024;
/// Longest accepted `state`, `code` or provider error value.
const MAX_PARAM_BYTES: usize = 2048;

/// The per-request id, put into the request extensions by the outer middleware.
#[derive(Clone, Debug)]
pub struct RequestId(pub String);

/// The client-supplied `x-request-id` (bounded), kept apart from [`RequestId`].
#[derive(Clone, Debug)]
pub struct ClientRequestId(pub String);

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
            client_request_id: parts
                .extensions
                .get::<ClientRequestId>()
                .map(|c| c.0.clone()),
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

/// `Origin` and CSRF checks for a state-changing POST, without recording
/// anything: the cause of the first failed check, if any.
fn guard_check(
    st: &PortalState,
    parts: &Parts,
    form: &Form,
    purpose: Purpose,
    binding: Option<&str>,
) -> Result<(), &'static str> {
    // A repeated `Origin` header is ambiguous: refuse it like a mismatch.
    let origin = if parts.headers.get_all(header::ORIGIN).iter().count() == 1 {
        header_str(&parts.headers, header::ORIGIN)
    } else {
        None
    };
    if !security::origin_allowed(origin, &st.cfg.origin) {
        return Err("origin");
    }
    let (Some(binding), Some(token)) = (binding, form.0.get("csrf")) else {
        return Err("token");
    };
    csrf::verify(&st.csrf_key, binding, purpose, token, st.clock.now()).map_err(|e| e.label())
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
    match guard_check(st, parts, form, purpose, binding) {
        Ok(()) => Ok(()),
        Err(cause) => {
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
        }
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
            passkey,
        } => {
            let views: Vec<ChoiceView> = providers.iter().map(ChoiceView::from).collect();
            let csrf = token_for(&st, bind.expose(), Purpose::Login);
            let passkey_csrf = token_for(
                &st,
                &settings_handlers::login_binding(&txn, bind.expose()),
                Purpose::PasskeyLogin,
            );
            let error = settings_handlers::login_error(query(&parts).as_ref());
            let mut form_origins = form_origins;
            if let Some(p) = &passkey {
                form_origins.push(p.form_origin.clone());
            }
            let page = render_page_status(
                &rq,
                StatusCode::OK,
                pages::Chooser {
                    t: rq.t(),
                    request_id: rq.rid(),
                    csrf: &csrf,
                    txn: &txn,
                    providers: &views,
                    passkey: passkey
                        .as_ref()
                        .map(|p| (p.ceremony.expose(), p.options.as_str())),
                    passkey_csrf: &passkey_csrf,
                    passkey_error: error,
                    integrity: pages::script_integrity(),
                },
                &planted,
                &form_origins,
            );
            if passkey.is_some() {
                settings_handlers::ceremony_page(page)
            } else {
                page
            }
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
        LoginVisit::ReauthProviderUnavailable { provider, sign_out } => render_page_status(
            &rq,
            StatusCode::SERVICE_UNAVAILABLE,
            pages::ReauthProviderUnavailable {
                t: rq.t(),
                request_id: rq.rid(),
                provider: &provider,
                sign_out: &sign_out,
            },
            &[],
            &[],
        ),
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
    let selected = ProviderId::new(provider.clone());
    if st.services.password_provider(&selected) {
        if !rq.ctx.https {
            return error_response(rq.t(), rq.rid(), ErrorPage::Forbidden);
        }
        return match st
            .services
            .prepare_password(&rq.ctx, &Secret::new(txn.to_owned()), &selected, &cookies)
            .await
        {
            Ok(prepared) => {
                let Some(bind) = cookies.bind.as_ref() else {
                    return error_response(rq.t(), rq.rid(), ErrorPage::Forbidden);
                };
                let csrf = token_for(&st, bind.expose(), Purpose::Login);
                render_page_status(
                    &rq,
                    StatusCode::OK,
                    pages::PasswordForm {
                        t: rq.t(),
                        request_id: rq.rid(),
                        provider_id: prepared.provider.as_str(),
                        provider_name: &prepared.provider_name,
                        csrf: &csrf,
                        challenge: prepared.challenge.expose(),
                        rejected: false,
                    },
                    &[],
                    &[prepared.form_origin],
                )
            }
            Err(failure) => fail_response(&rq, failure),
        };
    }
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

pub(crate) async fn password_post(
    State(st): State<PortalState>,
    Path(provider): Path<String>,
    req: Request,
) -> Response {
    let (parts, body) = req.into_parts();
    let rq = match prepare(&st, &parts) {
        Ok(rq) => rq,
        Err(response) => return response,
    };
    if !rq.ctx.https {
        return error_response(rq.t(), rq.rid(), ErrorPage::Forbidden);
    }
    let form = match read_form(&st, &rq, &parts, body).await {
        Ok(form) => form,
        Err(response) => return response,
    };
    for name in ["csrf", "challenge", "username", "password"] {
        if form.0.0.iter().filter(|(key, _)| key == name).count() != 1 {
            return error_response(rq.t(), rq.rid(), ErrorPage::BadRequest);
        }
    }
    let binding = rq
        .presented
        .bind
        .as_ref()
        .map(|cookie| cookie.expose().to_owned());
    if let Err(response) = guard(&st, &rq, &parts, &form, Purpose::Login, binding.as_deref()).await
    {
        return response;
    }
    if !st.password_attempts.admit(rq.ctx.client_ip) {
        let mut response = error_response(rq.t(), rq.rid(), ErrorPage::Unavailable);
        *response.status_mut() = StatusCode::TOO_MANY_REQUESTS;
        response
            .headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("60"));
        return response;
    }
    let (Some(challenge), Some(username), Some(password)) = (
        form.0.get("challenge"),
        form.0.get("username"),
        form.0.get("password"),
    ) else {
        return error_response(rq.t(), rq.rid(), ErrorPage::BadRequest);
    };
    if !simple_id(&provider, 64)
        || challenge.len() > 128
        || username.len() > 256
        || password.len() > 4096
    {
        return error_response(rq.t(), rq.rid(), ErrorPage::BadRequest);
    }
    let provider = ProviderId::new(provider);
    let challenge = Secret::new(challenge.to_owned());
    let password = Secret::new(password.to_owned());
    let cookies = Cookies {
        bind: rq.presented.bind.clone(),
        handle: rq.presented.handle.clone(),
    };
    match st
        .services
        .password(
            &rq.ctx,
            super::ports::PasswordSubmission {
                provider: &provider,
                challenge: &challenge,
                username,
                password: &password,
            },
            &cookies,
        )
        .await
    {
        super::ports::CallbackOutcome::Redirect(redirect) => {
            redirect_response(&st, &rq, &redirect, &[])
        }
        super::ports::CallbackOutcome::Failed(failure) => fail_response(&rq, failure),
        _ => error_response(rq.t(), rq.rid(), ErrorPage::Failed),
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

/// The ticket named in a query or form, when it has the shape of an id.
fn ticket_of(params: Option<&Params>) -> Option<Secret> {
    params
        .and_then(|p| p.get("txn"))
        .filter(|t| simple_id(t, 128))
        .map(|t| Secret::new(t.to_string()))
}

pub(crate) async fn logout_get(State(st): State<PortalState>, req: Request) -> Response {
    let (parts, _) = req.into_parts();
    let rq = match prepare(&st, &parts) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    // A logout ticket (`/_hopae/logout`): live and bound to this browser, the
    // page names the application and carries the ticket. Anything else is
    // the plain confirmation.
    if let Some(txn) = ticket_of(query(&parts).as_ref()) {
        let bind = effective_bind(&st, &rq);
        let cookies = Cookies {
            bind: Some(bind.clone()),
            handle: rq.presented.handle.clone(),
        };
        if let Some(app) = st.services.logout_visit(&rq.ctx, &txn, &cookies).await {
            // Bound to the portal handle when there is one, otherwise to the
            // portal binding cookie planted or refreshed here.
            let binding = rq
                .presented
                .handle
                .as_ref()
                .map_or_else(|| bind.expose(), |h| h.expose());
            let csrf = token_for(&st, binding, Purpose::Logout);
            return render_page(
                &rq,
                pages::Logout {
                    t: rq.t(),
                    request_id: rq.rid(),
                    csrf: &csrf,
                    txn: Some(txn.expose()),
                    app_name: Some(&app),
                },
                &[portal_cookie_header(&st, &bind)],
            );
        }
    }
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
            txn: None,
            app_name: None,
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
    let signed_out = |rq: &Rq, page: Option<&SignedOutPage>| {
        let sign_in = page.and_then(|p| p.sign_in.as_ref().map(|u| u.as_str()));
        render_page(
            rq,
            pages::SignedOut {
                t: rq.t(),
                request_id: rq.rid(),
                app_name: page.map(|p| p.app_name.as_str()),
                sign_in,
            },
            std::slice::from_ref(&clear),
        )
    };
    let Some(handle) = rq.presented.handle.clone() else {
        // Without a portal handle the only thing that can act is a logout
        // ticket held by this very browser: its form, `Origin` and CSRF token
        // (bound to the portal binding cookie) must all check out. Anything
        // else is the silent no-op, identical to the success page.
        let Some(bind) = rq.presented.bind.clone() else {
            return signed_out(&rq, None);
        };
        let Ok(form) = read_form(&st, &rq, &parts, body).await else {
            return signed_out(&rq, None);
        };
        let Some(txn) = ticket_of(Some(&form.0)) else {
            return signed_out(&rq, None);
        };
        if let Err(cause) = guard_check(&st, &parts, &form, Purpose::Logout, Some(bind.expose())) {
            // A ticket-only confirmation that fails Origin or CSRF acts on
            // nothing, but the attempt is recorded like every refused POST.
            st.services
                .csrf_rejected(&rq.ctx, Purpose::Logout.as_str(), cause)
                .await;
            tracing::info!(
                request_id = rq.rid(),
                purpose = Purpose::Logout.as_str(),
                cause,
                "csrf check refused"
            );
            return signed_out(&rq, None);
        }
        let cookies = Cookies {
            bind: Some(bind),
            handle: None,
        };
        return match st
            .services
            .logout_with_ticket(&rq.ctx, &txn, &cookies)
            .await
        {
            Ok(page) => signed_out(&rq, page.as_ref()),
            Err(f) => fail_response(&rq, f),
        };
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
    // Only the handle in the cookie and a ticket this browser holds are ever
    // acted on; form fields such as `session` or `scope` are not read.
    if let Some(txn) = ticket_of(Some(&form.0)) {
        let cookies = Cookies {
            bind: rq.presented.bind.clone(),
            handle: Some(handle),
        };
        return match st
            .services
            .logout_with_ticket(&rq.ctx, &txn, &cookies)
            .await
        {
            Ok(page) => signed_out(&rq, page.as_ref()),
            Err(f) => fail_response(&rq, f),
        };
    }
    match st.services.logout(&rq.ctx, &handle).await {
        Ok(_) => signed_out(&rq, None),
        Err(f) => fail_response(&rq, f),
    }
}

/// `GET /signed-out?txn=`: the page of a completed logout from the consumed
/// ticket the no-confirmation mode redirects with.
pub(crate) async fn signed_out_get(State(st): State<PortalState>, req: Request) -> Response {
    let (parts, _) = req.into_parts();
    let rq = match prepare(&st, &parts) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let Some(txn) = ticket_of(query(&parts).as_ref()) else {
        return error_response(rq.t(), rq.rid(), ErrorPage::BadRequest);
    };
    match st.services.signed_out(&rq.ctx, &txn).await {
        Ok(page) => render_page(
            &rq,
            pages::SignedOut {
                t: rq.t(),
                request_id: rq.rid(),
                app_name: Some(&page.app_name),
                sign_in: page.sign_in.as_ref().map(|u| u.as_str()),
            },
            &[],
        ),
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

fn totp_response(
    st: &PortalState,
    rq: &Rq,
    enrollment: &str,
    key: &str,
    complete: bool,
) -> Response {
    let Some(handle) = rq.presented.handle.as_ref() else {
        return error_response(rq.t(), rq.rid(), ErrorPage::Forbidden);
    };
    let purpose = if enrollment.is_empty() {
        Purpose::TotpPrepare
    } else {
        Purpose::TotpConfirm
    };
    let csrf = token_for(st, handle.expose(), purpose);
    let page = pages::TotpPage {
        t: rq.t(),
        request_id: rq.rid(),
        csrf: &csrf,
        enrollment,
        manual_key: key,
        complete,
    };
    let mut response = html_response(StatusCode::OK, page.render().unwrap_or_default());
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("same-origin"),
    );
    response
}
pub(crate) async fn totp_get(State(st): State<PortalState>, req: Request) -> Response {
    let (parts, _) = req.into_parts();
    let rq = match prepare(&st, &parts) {
        Ok(rq) => rq,
        Err(r) => return r,
    };
    if !st.services.totp_enabled() {
        return error_response(rq.t(), rq.rid(), ErrorPage::NotFound);
    }
    let cookies = Cookies {
        handle: rq.presented.handle.clone(),
        bind: rq.presented.bind.clone(),
    };
    if !rq.ctx.https {
        return error_response(rq.t(), rq.rid(), ErrorPage::Forbidden);
    }
    match st.services.totp_access(&rq.ctx, &cookies).await {
        Ok(active) => totp_response(&st, &rq, "", "", active),
        Err(f) => fail_response(&rq, f),
    }
}
pub(crate) async fn totp_prepare_post(State(st): State<PortalState>, req: Request) -> Response {
    totp_post(st, req, false).await
}
pub(crate) async fn totp_confirm_post(State(st): State<PortalState>, req: Request) -> Response {
    totp_post(st, req, true).await
}
async fn totp_post(st: PortalState, req: Request, confirm: bool) -> Response {
    let (parts, body) = req.into_parts();
    let rq = match prepare(&st, &parts) {
        Ok(rq) => rq,
        Err(r) => return r,
    };
    if !st.services.totp_enabled() {
        return error_response(rq.t(), rq.rid(), ErrorPage::NotFound);
    }
    if !rq.ctx.https || rq.presented.handle.is_none() {
        return error_response(rq.t(), rq.rid(), ErrorPage::Forbidden);
    }
    let form = match read_form(&st, &rq, &parts, body).await {
        Ok(form) => form,
        Err(r) => return r,
    };
    let required = if confirm {
        &["csrf", "enrollment", "code"][..]
    } else {
        &["csrf"][..]
    };
    if required
        .iter()
        .any(|name| form.0.0.iter().filter(|(k, _)| k == name).count() != 1)
    {
        return error_response(rq.t(), rq.rid(), ErrorPage::BadRequest);
    }
    let purpose = if confirm {
        Purpose::TotpConfirm
    } else {
        Purpose::TotpPrepare
    };
    if let Err(r) = guard(
        &st,
        &rq,
        &parts,
        &form,
        purpose,
        rq.presented.handle.as_ref().map(|h| h.expose()),
    )
    .await
    {
        return r;
    }
    if !st.password_attempts.admit(rq.ctx.client_ip) {
        let mut r = error_response(rq.t(), rq.rid(), ErrorPage::Unavailable);
        *r.status_mut() = StatusCode::TOO_MANY_REQUESTS;
        r.headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("60"));
        return r;
    }
    let cookies = Cookies {
        handle: rq.presented.handle.clone(),
        bind: rq.presented.bind.clone(),
    };
    if confirm {
        let id = form.0.get("enrollment").unwrap_or("");
        let code = form.0.get("code").unwrap_or("");
        if !simple_id(id, 128) || code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) {
            return error_response(rq.t(), rq.rid(), ErrorPage::BadRequest);
        }
        match st
            .services
            .totp_confirm(&rq.ctx, &cookies, id, &Secret::new(code.into()))
            .await
        {
            Ok(()) => totp_response(&st, &rq, "", "", true),
            Err(f) => fail_response(&rq, f),
        }
    } else {
        match st.services.totp_prepare(&rq.ctx, &cookies).await {
            Ok(prepared) => totp_response(
                &st,
                &rq,
                &prepared.enrollment,
                prepared.material.setup_key(),
                false,
            ),
            Err(f) => fail_response(&rq, f),
        }
    }
}

/// The external-factor links of a step-up page.
fn external_choices(st: &PortalState, transaction: &str) -> Vec<pages::ExternalChoice> {
    st.services
        .external_factor_ids()
        .into_iter()
        .map(|id| {
            let query = url::form_urlencoded::Serializer::new(String::new())
                .append_pair("txn", transaction)
                .append_pair("factor", &id)
                .finish();
            pages::ExternalChoice {
                label: id,
                location: format!("/stepup/external?{query}"),
            }
        })
        .collect()
}

fn stepup_csrf_binding(rq: &Rq, transaction: &str) -> Option<zeroize::Zeroizing<String>> {
    Some(zeroize::Zeroizing::new(format!(
        "{}:{}:{}",
        transaction,
        rq.presented.bind.as_ref()?.expose(),
        rq.presented.handle.as_ref()?.expose()
    )))
}
pub(crate) async fn stepup_get(State(st): State<PortalState>, req: Request) -> Response {
    let (parts, _) = req.into_parts();
    let mut rq = match prepare(&st, &parts) {
        Ok(rq) => rq,
        Err(r) => return r,
    };
    if !st.services.totp_enabled()
        && st.services.external_factor_ids().is_empty()
        && st.settings.is_none()
    {
        return error_response(rq.t(), rq.rid(), ErrorPage::NotFound);
    }
    if !rq.ctx.https || rq.presented.handle.is_none() {
        return error_response(rq.t(), rq.rid(), ErrorPage::Forbidden);
    }
    let raw = parts.uri.query().unwrap_or("");
    if raw.len() > 512 {
        return error_response(rq.t(), rq.rid(), ErrorPage::BadRequest);
    }
    let pairs: Vec<_> = url::form_urlencoded::parse(raw.as_bytes())
        .filter(|(k, _)| k == "txn")
        .take(2)
        .collect();
    if pairs.len() != 1 || !crate::crypto::is_well_formed_bind(&pairs[0].1) {
        return error_response(rq.t(), rq.rid(), ErrorPage::BadRequest);
    }
    let transaction = pairs[0].1.to_string();
    let bind = effective_bind(&st, &rq);
    rq.presented.bind = Some(bind.clone());
    let cookies = Cookies {
        handle: rq.presented.handle.clone(),
        bind: Some(bind.clone()),
    };
    let factors: Vec<_> = url::form_urlencoded::parse(raw.as_bytes())
        .filter(|(k, _)| k == "factor")
        .collect();
    if factors.len() > 1
        || factors
            .first()
            .is_some_and(|(_, v)| v != "totp" && v != "webauthn")
    {
        return error_response(rq.t(), rq.rid(), ErrorPage::BadRequest);
    }
    let wants_totp = factors.first().is_some_and(|(_, v)| v == "totp");
    if st.settings.is_some() && !wants_totp {
        // A passkey first when the user has one (ADR-0017); otherwise the other methods.
        let choices = external_choices(&st, &transaction);
        if let Some(page) = settings_handlers::stepup_passkey_page(
            &st,
            &rq,
            &cookies,
            &transaction,
            &choices,
            &[portal_cookie_header(&st, &bind)],
            None,
        )
        .await
        {
            return page;
        }
        if !st.services.totp_enabled() && choices.is_empty() {
            return render_page_status(
                &rq,
                StatusCode::OK,
                pages::StepUpPage {
                    enrollment_required: true,
                    setup_any: true,
                    t: rq.t(),
                    request_id: rq.rid(),
                    transaction: &transaction,
                    csrf: "",
                },
                &[portal_cookie_header(&st, &bind)],
                &[],
            );
        }
    }
    let ids = st.services.external_factor_ids();
    if factors.is_empty() && !ids.is_empty() {
        if let Err(f) = st
            .services
            .stepup_options(&rq.ctx, &cookies, &Secret::new(transaction.clone()))
            .await
        {
            return fail_response(&rq, f);
        }
        let choices: Vec<_> = ids
            .into_iter()
            .map(|id| {
                let query = url::form_urlencoded::Serializer::new(String::new())
                    .append_pair("txn", &transaction)
                    .append_pair("factor", &id)
                    .finish();
                pages::ExternalChoice {
                    label: id,
                    location: format!("/stepup/external?{query}"),
                }
            })
            .collect();
        return render_page_status(
            &rq,
            StatusCode::OK,
            pages::StepUpChoicesPage {
                t: rq.t(),
                request_id: rq.rid(),
                transaction: &transaction,
                totp: st.services.totp_enabled(),
                choices: &choices,
            },
            &[portal_cookie_header(&st, &bind)],
            &[],
        );
    }
    let entry = match st
        .services
        .stepup_visit(&rq.ctx, &cookies, &Secret::new(transaction.clone()))
        .await
    {
        Ok(entry) => entry,
        Err(f) => return fail_response(&rq, f),
    };
    let binding = stepup_csrf_binding(&rq, &transaction).expect("validated portal cookies");
    let csrf = token_for(&st, &binding, Purpose::TotpStepUp);
    render_page_status(
        &rq,
        StatusCode::OK,
        pages::StepUpPage {
            enrollment_required: !entry.enrolled,
            setup_any: st.settings.is_some(),
            t: rq.t(),
            request_id: rq.rid(),
            transaction: &transaction,
            csrf: &csrf,
        },
        &[portal_cookie_header(&st, &bind)],
        &[entry.form_origin],
    )
}
pub(crate) async fn stepup_post(State(st): State<PortalState>, req: Request) -> Response {
    let (parts, body) = req.into_parts();
    let rq = match prepare(&st, &parts) {
        Ok(rq) => rq,
        Err(r) => return r,
    };
    if !st.services.totp_enabled() {
        return error_response(rq.t(), rq.rid(), ErrorPage::NotFound);
    }
    if !rq.ctx.https {
        return error_response(rq.t(), rq.rid(), ErrorPage::Forbidden);
    }
    let form = match read_form(&st, &rq, &parts, body).await {
        Ok(form) => form,
        Err(r) => return r,
    };
    if ["txn", "csrf", "code"]
        .iter()
        .any(|name| form.0.0.iter().filter(|(k, _)| k == name).count() != 1)
    {
        return error_response(rq.t(), rq.rid(), ErrorPage::BadRequest);
    }
    let txn = form.0.get("txn").unwrap_or("");
    let code = form.0.get("code").unwrap_or("");
    if !crate::crypto::is_well_formed_bind(txn)
        || code.len() != 6
        || !code.bytes().all(|b| b.is_ascii_digit())
    {
        return error_response(rq.t(), rq.rid(), ErrorPage::BadRequest);
    }
    let Some(binding) = stepup_csrf_binding(&rq, txn) else {
        return error_response(rq.t(), rq.rid(), ErrorPage::Forbidden);
    };
    if let Err(r) = guard(&st, &rq, &parts, &form, Purpose::TotpStepUp, Some(&binding)).await {
        return r;
    }
    if !st.password_attempts.admit(rq.ctx.client_ip) {
        let mut r = error_response(rq.t(), rq.rid(), ErrorPage::Unavailable);
        *r.status_mut() = StatusCode::TOO_MANY_REQUESTS;
        r.headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("60"));
        return r;
    }
    let cookies = Cookies {
        handle: rq.presented.handle.clone(),
        bind: rq.presented.bind.clone(),
    };
    match st
        .services
        .stepup_complete(
            &rq.ctx,
            &cookies,
            &Secret::new(txn.into()),
            &Secret::new(code.into()),
        )
        .await
    {
        Ok(redirect) => redirect_response(&st, &rq, &redirect, &[]),
        Err(f) => fail_response(&rq, f),
    }
}

fn external_csrf_binding(
    rq: &Rq,
    transaction: &str,
    factor: &str,
) -> Option<zeroize::Zeroizing<String>> {
    Some(zeroize::Zeroizing::new(format!(
        "{}:{}",
        stepup_csrf_binding(rq, transaction)?.as_str(),
        factor
    )))
}
pub(crate) async fn external_stepup_get(State(st): State<PortalState>, req: Request) -> Response {
    let (parts, _) = req.into_parts();
    let mut rq = match prepare(&st, &parts) {
        Ok(r) => r,
        Err(r) => return r,
    };
    if st.services.external_factor_ids().is_empty() {
        return error_response(rq.t(), rq.rid(), ErrorPage::NotFound);
    }
    if !rq.ctx.https || rq.presented.handle.is_none() {
        return error_response(rq.t(), rq.rid(), ErrorPage::Forbidden);
    }
    let raw = parts.uri.query().unwrap_or("");
    if raw.len() > 512 {
        return error_response(rq.t(), rq.rid(), ErrorPage::BadRequest);
    }
    let pairs: Vec<_> = url::form_urlencoded::parse(raw.as_bytes()).collect();
    if pairs.len() != 2
        || ["txn", "factor"]
            .iter()
            .any(|name| pairs.iter().filter(|(key, _)| key == name).count() != 1)
    {
        return error_response(rq.t(), rq.rid(), ErrorPage::BadRequest);
    }
    let txn = pairs.iter().find(|(k, _)| k == "txn").unwrap().1.as_ref();
    let factor = pairs
        .iter()
        .find(|(k, _)| k == "factor")
        .unwrap()
        .1
        .as_ref();
    if !crate::crypto::is_well_formed_bind(txn)
        || !st
            .services
            .external_factor_ids()
            .iter()
            .any(|id| id == factor)
    {
        return error_response(rq.t(), rq.rid(), ErrorPage::BadRequest);
    }
    let bind = effective_bind(&st, &rq);
    rq.presented.bind = Some(bind.clone());
    let cookies = Cookies {
        handle: rq.presented.handle.clone(),
        bind: Some(bind.clone()),
    };
    let entry = match st
        .services
        .external_stepup_visit(&rq.ctx, &cookies, &Secret::new(txn.into()), factor)
        .await
    {
        Ok(e) => e,
        Err(f) => return fail_response(&rq, f),
    };
    let binding = external_csrf_binding(&rq, txn, factor).expect("validated cookies");
    let csrf = token_for(&st, &binding, Purpose::ExternalStepUp);
    render_page_status(
        &rq,
        StatusCode::OK,
        pages::ExternalStepUpPage {
            t: rq.t(),
            request_id: rq.rid(),
            transaction: txn,
            factor,
            csrf: &csrf,
        },
        &[portal_cookie_header(&st, &bind)],
        &[entry.form_origin],
    )
}
pub(crate) async fn external_stepup_post(State(st): State<PortalState>, req: Request) -> Response {
    let (parts, body) = req.into_parts();
    let rq = match prepare(&st, &parts) {
        Ok(r) => r,
        Err(r) => return r,
    };
    if st.services.external_factor_ids().is_empty() {
        return error_response(rq.t(), rq.rid(), ErrorPage::NotFound);
    }
    if !rq.ctx.https {
        return error_response(rq.t(), rq.rid(), ErrorPage::Forbidden);
    }
    let form = match read_form(&st, &rq, &parts, body).await {
        Ok(f) => f,
        Err(r) => return r,
    };
    if form.0.0.len() != 4
        || ["txn", "csrf", "factor", "response"]
            .iter()
            .any(|name| form.0.0.iter().filter(|(key, _)| key == name).count() != 1)
    {
        return error_response(rq.t(), rq.rid(), ErrorPage::BadRequest);
    }
    let txn = form.0.get("txn").unwrap_or("");
    let factor = form.0.get("factor").unwrap_or("");
    let response = form.0.get("response").unwrap_or("");
    if !crate::crypto::is_well_formed_bind(txn)
        || !st
            .services
            .external_factor_ids()
            .iter()
            .any(|id| id == factor)
        || response.is_empty()
        || response.len() > 4096
    {
        return error_response(rq.t(), rq.rid(), ErrorPage::BadRequest);
    }
    let Some(binding) = external_csrf_binding(&rq, txn, factor) else {
        return error_response(rq.t(), rq.rid(), ErrorPage::Forbidden);
    };
    if let Err(r) = guard(
        &st,
        &rq,
        &parts,
        &form,
        Purpose::ExternalStepUp,
        Some(&binding),
    )
    .await
    {
        return r;
    }
    if !st.password_attempts.admit(rq.ctx.client_ip) {
        let mut r = error_response(rq.t(), rq.rid(), ErrorPage::Unavailable);
        *r.status_mut() = StatusCode::TOO_MANY_REQUESTS;
        r.headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("60"));
        return r;
    }
    let cookies = Cookies {
        handle: rq.presented.handle.clone(),
        bind: rq.presented.bind.clone(),
    };
    match st
        .services
        .external_stepup_complete(
            &rq.ctx,
            &cookies,
            &Secret::new(txn.into()),
            factor,
            &Secret::new(response.into()),
        )
        .await
    {
        Ok(r) => redirect_response(&st, &rq, &r, &[]),
        Err(f) => fail_response(&rq, f),
    }
}
