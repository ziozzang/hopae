//! What a console request that changes state must carry.
//!
//! * HTML forms: `application/x-www-form-urlencoded`, a `csrf` field issued on
//!   the page (bound to the presented handle, purpose `admin`, ten minutes)
//!   and an `Origin` equal to the console origin.
//! * JSON API: `content-type: application/json`, the header
//!   `x-hopae-admin-request: 1`, and, when present, `Origin` equal to the
//!   console origin and `sec-fetch-site` equal to `same-origin` or `none`.
//!
//! A refusal is `403 csrf_rejected` and a required `csrf.rejected` event
//! (`purpose=admin`, `cause=token|origin|expired`).

use axum::body::Body;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::Response;
use bytes::Bytes;

use super::{AdminState, Ctx, api};
use crate::crypto::ct_eq;
use crate::event::types::{EventKind, Outcome, reasons};
use crate::http::csrf::{self, CsrfKey, Purpose};

/// The request header every JSON mutation carries.
pub const API_HEADER: &str = "x-hopae-admin-request";

/// A parsed form body.
#[derive(Clone, Debug)]
pub struct Form(Vec<(String, String)>);

impl Form {
    /// The first value of a field.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

/// A mutation that passed the listener's checks (CSRF, then the role): put
/// into the request extensions for the handler, which must not read the body
/// again. Extract it with `axum::Extension<Mutation>`.
#[derive(Clone, Debug)]
pub struct Mutation {
    /// The parsed fields of an HTML form post (`None` for the JSON API).
    pub form: Option<Form>,
    /// The raw body of a JSON mutation (the console ignores its content).
    pub body: Bytes,
}

/// Check the mutation of `ctx` the way its route asks: a form for pages, the
/// API rule for `/v1/`.
pub async fn guard(
    st: &AdminState,
    ctx: &Ctx,
    headers: &HeaderMap,
    body: Body,
) -> Result<Mutation, Response> {
    if ctx.req.api {
        let body = guard_json(st, ctx, headers, body).await?;
        Ok(Mutation { form: None, body })
    } else {
        let form = guard_form(st, ctx, headers, body).await?;
        Ok(Mutation {
            form: Some(form),
            body: Bytes::new(),
        })
    }
}

/// A token for a form rendered for `ctx`'s handle.
pub fn issue(st: &AdminState, ctx: &Ctx) -> String {
    csrf::issue(
        &CsrfKey::new(st.key),
        ctx.principal.handle_value.expose(),
        Purpose::Admin,
        st.clock.now(),
        st.rng.as_ref(),
    )
}

fn media_type(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .map(|m| m.trim().to_ascii_lowercase())
}

/// The single `Origin` header, when exactly one is present.
fn origin_header(headers: &HeaderMap) -> Result<Option<&str>, ()> {
    let mut it = headers.get_all(header::ORIGIN).iter();
    match (it.next(), it.next()) {
        (None, _) => Ok(None),
        (Some(v), None) => v.to_str().map(Some).map_err(|_| ()),
        // A repeated `Origin` is ambiguous: refused like a mismatch.
        (Some(_), Some(_)) => Err(()),
    }
}

fn origin_matches(st: &AdminState, origin: &str) -> bool {
    let expected = st.cfg.origin.ascii_serialization();
    ct_eq(origin.as_bytes(), expected.as_bytes())
}

/// Record the refusal and answer `403 csrf_rejected`.
async fn reject(st: &AdminState, ctx: &Ctx, cause: &'static str) -> Response {
    let ev = st.emitter.as_ref().map(|em| {
        em.required(
            EventKind::CsrfRejected,
            Outcome::Failure,
            ctx.req.rid.clone(),
            |b| {
                b.user(&ctx.principal.user_id)
                    .session(&ctx.principal.session_id)
                    .app(&st.cfg.policy.app_id)
                    .ip(ctx.req.client_ip)
                    .reason(reasons::CSRF_REJECTED)
                    .attr("purpose", Purpose::Admin.as_str())
                    .attr("cause", cause)
            },
        )
    });
    if let Some(ev) = ev
        && let Err(e) = st.events.append_required(vec![ev]).await
    {
        tracing::warn!(error = %e, "csrf.rejected could not be recorded");
    }
    api::bare_error(&ctx.req, StatusCode::FORBIDDEN, "csrf_rejected")
}

fn declared_length(headers: &HeaderMap) -> Option<usize> {
    headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
}

/// Check an HTML form post and return its fields: content type, size, the
/// `Origin`, then the token bound to the presented handle.
pub async fn guard_form(
    st: &AdminState,
    ctx: &Ctx,
    headers: &HeaderMap,
    body: Body,
) -> Result<Form, Response> {
    if media_type(headers).as_deref() != Some("application/x-www-form-urlencoded") {
        return Err(reject(st, ctx, "token").await);
    }
    let bytes = api::read_body(&ctx.req, declared_length(headers), body).await?;
    let fields: Vec<(String, String)> = form_urlencoded::parse(&bytes)
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    let form = Form(fields);
    match origin_header(headers) {
        Ok(Some(o)) if origin_matches(st, o) => {}
        _ => return Err(reject(st, ctx, "origin").await),
    }
    let Some(token) = form.get("csrf") else {
        return Err(reject(st, ctx, "token").await);
    };
    match csrf::verify(
        &CsrfKey::new(st.key),
        ctx.principal.handle_value.expose(),
        Purpose::Admin,
        token,
        st.clock.now(),
    ) {
        Ok(()) => Ok(form),
        Err(e) => Err(reject(st, ctx, e.label()).await),
    }
}

/// Check a JSON mutation and return its body (the console ignores its content).
pub async fn guard_json(
    st: &AdminState,
    ctx: &Ctx,
    headers: &HeaderMap,
    body: Body,
) -> Result<Bytes, Response> {
    if media_type(headers).as_deref() != Some("application/json") {
        return Err(reject(st, ctx, "token").await);
    }
    let marked = headers.get_all(API_HEADER).iter().count() == 1
        && headers
            .get(API_HEADER)
            .is_some_and(|v| v.as_bytes() == b"1");
    if !marked {
        return Err(reject(st, ctx, "token").await);
    }
    match origin_header(headers) {
        Ok(None) => {}
        Ok(Some(o)) if origin_matches(st, o) => {}
        _ => return Err(reject(st, ctx, "origin").await),
    }
    if let Some(site) = headers.get("sec-fetch-site") {
        let ok = site
            .to_str()
            .is_ok_and(|s| matches!(s.trim(), "same-origin" | "none"));
        if !ok {
            return Err(reject(st, ctx, "origin").await);
        }
    }
    api::read_body(&ctx.req, declared_length(headers), body).await
}
