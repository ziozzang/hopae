//! Security settings and passkey routes (ADR-0017). A child of the portal
//! handlers: the same request preparation, form, CSRF and `Origin` guards and
//! error pages; the flows are behind [`SecurityServices`].
//!
//! Every route answers `404` without `webauthn`, `403` without HTTPS, and a
//! "sign in first" page without a live portal session. Every POST needs the
//! portal binding cookie and handle, a token of purpose `security` bound to
//! the action, the binding cookie and the handle, and the exact `Origin`.

use std::sync::Arc;

use super::*;
use crate::event::types::reasons;
use crate::portal::settings::{CeremonyPage, Refusal, SecurityServices, SecurityView};

/// Where a successful security confirmation continues (a fixed set; never a URL from the client).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Next {
    Security,
    Passkeys,
    NewPasskey,
    NewHighAssurance,
    Recovery,
}

impl Next {
    fn parse(s: Option<&str>) -> Next {
        match s {
            Some("passkeys") => Next::Passkeys,
            Some("passkeys_new") => Next::NewPasskey,
            Some("passkeys_new_high_assurance") => Next::NewHighAssurance,
            Some("recovery") => Next::Recovery,
            _ => Next::Security,
        }
    }
    fn as_str(self) -> &'static str {
        match self {
            Next::Security => "security",
            Next::Passkeys => "passkeys",
            Next::NewPasskey => "passkeys_new",
            Next::NewHighAssurance => "passkeys_new_high_assurance",
            Next::Recovery => "recovery",
        }
    }
    fn location(self, recovered: bool) -> &'static str {
        if recovered {
            return "/security?done=recovered";
        }
        match self {
            Next::Security => "/security?done=verified",
            Next::Passkeys => "/security/passkeys?done=verified",
            Next::NewPasskey => "/security/passkeys/new",
            Next::NewHighAssurance => "/security/passkeys/new?kind=high_assurance",
            Next::Recovery => "/security/recovery-codes",
        }
    }
}

/// Notices and errors a redirect may name (fixed keys; anything else is ignored).
fn notice_of(params: Option<&Params>) -> Option<&'static str> {
    match params.and_then(|p| p.get("done")) {
        Some("added") => Some("notice.added"),
        Some("removed") => Some("notice.removed"),
        Some("renamed") => Some("notice.renamed"),
        Some("verified") => Some("notice.verified"),
        Some("recovered") => Some("notice.recovered"),
        Some("codes") => Some("notice.codes"),
        _ => None,
    }
}

fn error_of(params: Option<&Params>) -> Option<&'static str> {
    match params.and_then(|p| p.get("error")) {
        Some("last_factor") => Some("passkeys.last_factor"),
        Some("invalid_label") => Some("passkeys.invalid_label"),
        Some("not_found") => Some("passkeys.not_found"),
        Some("expired") => Some("refusal.expired"),
        _ => None,
    }
}

fn refusal_key(r: Refusal) -> Option<&'static str> {
    Some(match r {
        Refusal::Rejected => "refusal.rejected",
        Refusal::Expired => "refusal.expired",
        Refusal::Duplicate => "webauthn.duplicate",
        Refusal::Capacity => "refusal.capacity",
        Refusal::NotAllowedAuthenticator => "refusal.not_allowed",
        Refusal::CloneSuspected => "refusal.clone",
        Refusal::InvalidCode => "refusal.invalid_code",
        Refusal::RateLimited => "refusal.rate_limited",
        Refusal::LastFactor => "passkeys.last_factor",
        Refusal::VerificationRequired | Refusal::Failure(_) => return None,
    })
}

fn csrf_binding(rq: &Rq, action: &str) -> Option<zeroize::Zeroizing<String>> {
    Some(zeroize::Zeroizing::new(format!(
        "security:{action}:{}:{}",
        rq.presented.bind.as_ref()?.expose(),
        rq.presented.handle.as_ref()?.expose()
    )))
}

fn token(st: &PortalState, rq: &Rq, action: &str) -> String {
    csrf_binding(rq, action)
        .map(|b| token_for(st, &b, Purpose::Security))
        .unwrap_or_default()
}

fn see_other(location: &str, cookies: &[String]) -> Response {
    let mut r = Response::new(Body::empty());
    *r.status_mut() = StatusCode::SEE_OTHER;
    if let Ok(v) = HeaderValue::from_str(location) {
        r.headers_mut().insert(header::LOCATION, v);
    }
    for c in cookies {
        add_cookie(&mut r, c);
    }
    r
}

/// A ceremony page: no caching, no referrer, the script policy.
fn ceremony_response(mut r: Response) -> Response {
    r.extensions_mut().insert(security::CeremonyScript);
    r
}

fn signin_page(rq: &Rq) -> Response {
    render_page_status(
        rq,
        StatusCode::FORBIDDEN,
        pages::SecuritySignInPage {
            t: rq.t(),
            request_id: rq.rid(),
            title_key: "security.signin.title",
            body_key: "security.signin.body",
            alert: false,
        },
        &[],
        &[],
    )
}

/// The clone signal ends the sessions the passkey elevated, possibly this
/// one: the explanation cannot depend on a live session.
fn clone_page(rq: &Rq) -> Response {
    render_page_status(
        rq,
        StatusCode::FORBIDDEN,
        pages::SecuritySignInPage {
            t: rq.t(),
            request_id: rq.rid(),
            title_key: "verify.title",
            body_key: "refusal.clone",
            alert: true,
        },
        &[],
        &[],
    )
}

fn refusal_page(rq: &Rq, r: Refusal) -> Response {
    match r {
        Refusal::CloneSuspected => clone_page(rq),
        Refusal::Failure(f) if f.kind == FailKind::Forbidden => signin_page(rq),
        Refusal::Failure(f) => fail_response(rq, f),
        _ => error_response(rq.t(), rq.rid(), ErrorPage::Failed),
    }
}

fn rate_limited(rq: &Rq) -> Response {
    let mut r = error_response(rq.t(), rq.rid(), ErrorPage::Unavailable);
    *r.status_mut() = StatusCode::TOO_MANY_REQUESTS;
    r.headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from_static("60"));
    r
}

/// Common entry of every settings route. GET plants the binding cookie when absent.
struct Entry {
    rq: Rq,
    settings: Arc<dyn SecurityServices>,
    cookies: Cookies,
    plant: Vec<String>,
}

fn enter(st: &PortalState, parts: &Parts, get: bool) -> Result<Entry, Response> {
    let mut rq = prepare(st, parts)?;
    let Some(settings) = st.settings.clone() else {
        return Err(error_response(rq.t(), rq.rid(), ErrorPage::NotFound));
    };
    if !rq.ctx.https {
        return Err(error_response(rq.t(), rq.rid(), ErrorPage::Forbidden));
    }
    if rq.presented.handle.is_none() {
        return Err(signin_page(&rq));
    }
    let mut plant = vec![];
    if get {
        let bind = effective_bind(st, &rq);
        if rq.presented.bind.is_none() {
            plant.push(portal_cookie_header(st, &bind));
        }
        rq.presented.bind = Some(bind);
    } else if rq.presented.bind.is_none() {
        return Err(error_response(rq.t(), rq.rid(), ErrorPage::Forbidden));
    }
    let cookies = Cookies {
        handle: rq.presented.handle.clone(),
        bind: rq.presented.bind.clone(),
    };
    Ok(Entry {
        rq,
        settings,
        cookies,
        plant,
    })
}

/// Read and guard a settings POST: exactly the named fields once each (plus
/// optional ones), CSRF for `action`, `Origin`.
async fn posted(
    st: &PortalState,
    e: &Entry,
    parts: &Parts,
    body: Body,
    action: &str,
    required: &[&str],
    optional: &[&str],
) -> Result<Form, Response> {
    let form = read_form(st, &e.rq, parts, body).await?;
    let allowed = |k: &str| k == "csrf" || required.contains(&k) || optional.contains(&k);
    if form.0.0.iter().any(|(k, _)| !allowed(k))
        || ["csrf"]
            .iter()
            .chain(required)
            .any(|n| form.0.0.iter().filter(|(k, _)| k == n).count() != 1)
        || optional
            .iter()
            .any(|n| form.0.0.iter().filter(|(k, _)| k == n).count() > 1)
    {
        return Err(error_response(e.rq.t(), e.rq.rid(), ErrorPage::BadRequest));
    }
    let binding = csrf_binding(&e.rq, action);
    guard(
        st,
        &e.rq,
        parts,
        &form,
        Purpose::Security,
        binding.as_ref().map(|b| b.as_str()),
    )
    .await?;
    Ok(form)
}

fn time(ts: crate::crypto::Timestamp) -> String {
    let full = crate::admin::users::common::time_str(ts.secs());
    // `YYYY-MM-DD HH:MM UTC`: seconds add nothing here.
    match (full.get(..16), full.get(19..)) {
        (Some(head), Some(tail)) => format!("{head}{tail}"),
        _ => full,
    }
}

fn verify_location(next: Next) -> String {
    format!("/security/verify?next={}", next.as_str())
}

// ---- GET /assets/webauthn.js ----------------------------------------------

pub(crate) async fn script(State(st): State<PortalState>) -> Response {
    if st.settings.is_none() {
        return not_found_plain();
    }
    let mut r = Response::new(Body::from(pages::CEREMONY_SCRIPT));
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/javascript; charset=utf-8"),
    );
    r
}

fn not_found_plain() -> Response {
    let mut r = Response::new(Body::empty());
    *r.status_mut() = StatusCode::NOT_FOUND;
    r
}

// ---- GET /security --------------------------------------------------------

pub(crate) async fn overview(State(st): State<PortalState>, req: Request) -> Response {
    let (parts, _) = req.into_parts();
    let e = match enter(&st, &parts, true) {
        Ok(e) => e,
        Err(r) => return r,
    };
    let params = query(&parts);
    match e.settings.overview(&e.rq.ctx, &e.cookies).await {
        Ok(view) => render_page_status(
            &e.rq,
            StatusCode::OK,
            pages::SecurityPage {
                t: e.rq.t(),
                request_id: e.rq.rid(),
                notice: notice_of(params.as_ref()),
                error: error_of(params.as_ref()),
                passkey_count: view.passkeys.len().to_string(),
                recovery_count: view.recovery_unused.to_string(),
                has_factor: !view.passkeys.is_empty() || view.totp_active,
                view: &view,
            },
            &e.plant,
            &[],
        ),
        Err(r) => refusal_page(&e.rq, r),
    }
}

// ---- GET /security/passkeys -----------------------------------------------

fn passkeys_page(
    st: &PortalState,
    e: &Entry,
    view: &SecurityView,
    notice: Option<&'static str>,
    error: Option<&'static str>,
) -> Response {
    let rows = view
        .passkeys
        .iter()
        .map(|p| pages::PasskeyRow {
            id: p.id.clone(),
            label: p.label.clone(),
            kind: if p.high_assurance {
                "passkeys.high_assurance"
            } else if p.synced {
                "passkeys.synced"
            } else {
                "passkeys.device"
            },
            created: time(p.created_at),
            last_used: p.last_used_at.map(time),
        })
        .collect();
    let rename = token(st, &e.rq, "rename");
    let remove = token(st, &e.rq, "remove");
    render_page_status(
        &e.rq,
        StatusCode::OK,
        pages::PasskeysPage {
            t: e.rq.t(),
            request_id: e.rq.rid(),
            notice,
            error,
            passkeys: rows,
            csrf_rename: &rename,
            csrf_remove: &remove,
            only_factor: view.passkeys.len() + usize::from(view.totp_active) <= 1,
            high_assurance: view.high_assurance_available,
        },
        &e.plant,
        &[],
    )
}

pub(crate) async fn passkeys(State(st): State<PortalState>, req: Request) -> Response {
    let (parts, _) = req.into_parts();
    let e = match enter(&st, &parts, true) {
        Ok(e) => e,
        Err(r) => return r,
    };
    let params = query(&parts);
    match e.settings.overview(&e.rq.ctx, &e.cookies).await {
        Ok(view) => passkeys_page(
            &st,
            &e,
            &view,
            notice_of(params.as_ref()),
            error_of(params.as_ref()),
        ),
        Err(r) => refusal_page(&e.rq, r),
    }
}

// ---- /security/passkeys/new -----------------------------------------------

async fn new_passkey_page(
    st: &PortalState,
    e: &Entry,
    high_assurance: bool,
    error: Option<&'static str>,
) -> Response {
    let next = if high_assurance {
        Next::NewHighAssurance
    } else {
        Next::NewPasskey
    };
    match e
        .settings
        .begin_registration(&e.rq.ctx, &e.cookies, high_assurance)
        .await
    {
        Ok(CeremonyPage { ceremony, options }) => {
            let csrf = token(st, &e.rq, "register");
            ceremony_response(render_page_status(
                &e.rq,
                StatusCode::OK,
                pages::PasskeyNewPage {
                    t: e.rq.t(),
                    request_id: e.rq.rid(),
                    notice: None,
                    error,
                    csrf: &csrf,
                    ceremony: ceremony.expose(),
                    options: &options,
                    high_assurance,
                    integrity: pages::script_integrity(),
                },
                &e.plant,
                &[],
            ))
        }
        Err(Refusal::VerificationRequired) => see_other(&verify_location(next), &e.plant),
        Err(Refusal::Capacity) => see_other("/security/passkeys?error=capacity", &e.plant),
        Err(r) => refusal_page(&e.rq, r),
    }
}

pub(crate) async fn new_passkey_get(State(st): State<PortalState>, req: Request) -> Response {
    let (parts, _) = req.into_parts();
    let e = match enter(&st, &parts, true) {
        Ok(e) => e,
        Err(r) => return r,
    };
    let high = query(&parts).is_some_and(|p| p.get("kind") == Some("high_assurance"));
    new_passkey_page(&st, &e, high, None).await
}

pub(crate) async fn new_passkey_post(State(st): State<PortalState>, req: Request) -> Response {
    let (parts, body) = req.into_parts();
    let e = match enter(&st, &parts, false) {
        Ok(e) => e,
        Err(r) => return r,
    };
    let form = match posted(
        &st,
        &e,
        &parts,
        body,
        "register",
        &["ceremony", "credential", "kind"],
        &["label"],
    )
    .await
    {
        Ok(f) => f,
        Err(r) => return r,
    };
    let high = form.0.get("kind") == Some("high_assurance");
    let credential = form.0.get("credential").unwrap_or("");
    if credential.is_empty() || credential.len() > 32 * 1024 {
        return new_passkey_page(&st, &e, high, Some("refusal.rejected")).await;
    }
    let t = e.rq.t();
    let defaults = (
        t.get("passkey_new.default"),
        t.get("passkey_new.default_key"),
    );
    let label = form.0.get("label").filter(|l| !l.trim().is_empty());
    let first = match e.settings.overview(&e.rq.ctx, &e.cookies).await {
        Ok(v) => v.passkeys.is_empty() && !v.totp_active && !v.recovery_generated,
        Err(r) => return refusal_page(&e.rq, r),
    };
    match e
        .settings
        .finish_registration(
            &e.rq.ctx,
            &e.cookies,
            &Secret::new(form.0.get("ceremony").unwrap_or("").into()),
            label,
            defaults,
            credential,
        )
        .await
    {
        Ok(()) if first => see_other("/security/recovery-codes?first=1", &[]),
        Ok(()) => see_other("/security/passkeys?done=added", &[]),
        Err(Refusal::VerificationRequired) => see_other(
            &verify_location(if high {
                Next::NewHighAssurance
            } else {
                Next::NewPasskey
            }),
            &[],
        ),
        Err(r @ Refusal::Failure(_)) => refusal_page(&e.rq, r),
        Err(r) => new_passkey_page(&st, &e, high, refusal_key(r)).await,
    }
}

// ---- POST /security/passkeys/rename, /remove ------------------------------

pub(crate) async fn rename_post(State(st): State<PortalState>, req: Request) -> Response {
    let (parts, body) = req.into_parts();
    let e = match enter(&st, &parts, false) {
        Ok(e) => e,
        Err(r) => return r,
    };
    let form = match posted(
        &st,
        &e,
        &parts,
        body,
        "rename",
        &["credential", "label"],
        &[],
    )
    .await
    {
        Ok(f) => f,
        Err(r) => return r,
    };
    match e
        .settings
        .rename(
            &e.rq.ctx,
            &e.cookies,
            form.0.get("credential").unwrap_or(""),
            form.0.get("label").unwrap_or(""),
        )
        .await
    {
        Ok(()) => see_other("/security/passkeys?done=renamed", &[]),
        Err(Refusal::Failure(f)) if f.reason == reasons::INVALID_ID => {
            see_other("/security/passkeys?error=invalid_label", &[])
        }
        Err(Refusal::Failure(f)) if f.reason == reasons::NOT_FOUND => {
            see_other("/security/passkeys?error=not_found", &[])
        }
        Err(r) => refusal_page(&e.rq, r),
    }
}

pub(crate) async fn remove_post(State(st): State<PortalState>, req: Request) -> Response {
    let (parts, body) = req.into_parts();
    let e = match enter(&st, &parts, false) {
        Ok(e) => e,
        Err(r) => return r,
    };
    let form = match posted(
        &st,
        &e,
        &parts,
        body,
        "remove",
        &["credential"],
        &["confirm"],
    )
    .await
    {
        Ok(f) => f,
        Err(r) => return r,
    };
    let id = form.0.get("credential").unwrap_or("").to_owned();
    if form.0.get("confirm") != Some("1") {
        // First press: show what will be removed.
        let view = match e.settings.overview(&e.rq.ctx, &e.cookies).await {
            Ok(v) => v,
            Err(r) => return refusal_page(&e.rq, r),
        };
        let Some(p) = view.passkeys.iter().find(|p| p.id == id) else {
            return see_other("/security/passkeys?error=not_found", &[]);
        };
        let csrf = token(&st, &e.rq, "remove");
        return render_page(
            &e.rq,
            pages::PasskeyRemovePage {
                t: e.rq.t(),
                request_id: e.rq.rid(),
                csrf: &csrf,
                id: &id,
                label: &p.label,
            },
            &[],
        );
    }
    match e.settings.remove(&e.rq.ctx, &e.cookies, &id).await {
        Ok(()) => see_other("/security/passkeys?done=removed", &[]),
        Err(Refusal::VerificationRequired) => see_other(&verify_location(Next::Passkeys), &[]),
        Err(Refusal::LastFactor) => see_other("/security/passkeys?error=last_factor", &[]),
        Err(Refusal::Failure(f))
            if f.reason == reasons::NOT_FOUND || f.reason == reasons::INVALID_ID =>
        {
            see_other("/security/passkeys?error=not_found", &[])
        }
        Err(r) => refusal_page(&e.rq, r),
    }
}

// ---- /security/verify -----------------------------------------------------

async fn verify_page(
    st: &PortalState,
    e: &Entry,
    next: Next,
    error: Option<&'static str>,
) -> Response {
    let view = match e.settings.overview(&e.rq.ctx, &e.cookies).await {
        Ok(v) => v,
        Err(r) => return refusal_page(&e.rq, r),
    };
    let passkey = match e.settings.begin_verify(&e.rq.ctx, &e.cookies).await {
        Ok(p) => {
            p.map(|CeremonyPage { ceremony, options }| (ceremony.expose().to_owned(), options))
        }
        Err(r) => return refusal_page(&e.rq, r),
    };
    let csrf = token(st, &e.rq, "verify");
    let has_ceremony = passkey.is_some();
    let r = render_page_status(
        &e.rq,
        StatusCode::OK,
        pages::VerifyPage {
            t: e.rq.t(),
            request_id: e.rq.rid(),
            notice: None,
            error,
            csrf: &csrf,
            next: next.as_str(),
            passkey,
            totp: view.totp_active && view.totp_available,
            recovery: view.recovery_unused > 0,
            integrity: pages::script_integrity(),
        },
        &e.plant,
        &[],
    );
    if has_ceremony {
        ceremony_response(r)
    } else {
        r
    }
}

pub(crate) async fn verify_get(State(st): State<PortalState>, req: Request) -> Response {
    let (parts, _) = req.into_parts();
    let e = match enter(&st, &parts, true) {
        Ok(e) => e,
        Err(r) => return r,
    };
    let next = Next::parse(query(&parts).as_ref().and_then(|p| p.get("next")));
    verify_page(&st, &e, next, None).await
}

async fn verify_post(st: PortalState, req: Request, method: &'static str) -> Response {
    let (parts, body) = req.into_parts();
    let e = match enter(&st, &parts, false) {
        Ok(e) => e,
        Err(r) => return r,
    };
    let required: &[&str] = if method == "passkey" {
        &["next", "ceremony", "credential"]
    } else {
        &["next", "code"]
    };
    let form = match posted(&st, &e, &parts, body, "verify", required, &[]).await {
        Ok(f) => f,
        Err(r) => return r,
    };
    let next = Next::parse(form.0.get("next"));
    if method != "passkey" && !st.password_attempts.admit(e.rq.ctx.client_ip) {
        return verify_page(&st, &e, next, refusal_key(Refusal::RateLimited)).await;
    }
    let result = match method {
        "passkey" => {
            let credential = form.0.get("credential").unwrap_or("");
            if credential.is_empty() || credential.len() > 32 * 1024 {
                return verify_page(&st, &e, next, Some("refusal.rejected")).await;
            }
            e.settings
                .verify_passkey(
                    &e.rq.ctx,
                    &e.cookies,
                    &Secret::new(form.0.get("ceremony").unwrap_or("").into()),
                    credential,
                )
                .await
        }
        "totp" => {
            let code = form.0.get("code").unwrap_or("").trim();
            if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) {
                return verify_page(&st, &e, next, Some("refusal.invalid_code")).await;
            }
            e.settings
                .verify_totp(&e.rq.ctx, &e.cookies, &Secret::new(code.into()))
                .await
        }
        _ => {
            let code = form.0.get("code").unwrap_or("");
            e.settings
                .verify_recovery(&e.rq.ctx, &e.cookies, &Secret::new(code.into()))
                .await
        }
    };
    match result {
        Ok(handle) => {
            let cookie = cookies::set_cookie(
                &st.cfg.cookie_names.handle,
                handle.value.expose(),
                handle.max_age,
                st.cfg.secure,
            );
            see_other(next.location(method == "recovery"), &[cookie])
        }
        Err(r @ (Refusal::Failure(_) | Refusal::CloneSuspected)) => refusal_page(&e.rq, r),
        Err(r) => verify_page(&st, &e, next, refusal_key(r)).await,
    }
}

pub(crate) async fn verify_passkey_post(State(st): State<PortalState>, req: Request) -> Response {
    verify_post(st, req, "passkey").await
}
pub(crate) async fn verify_totp_post(State(st): State<PortalState>, req: Request) -> Response {
    verify_post(st, req, "totp").await
}
pub(crate) async fn verify_recovery_post(State(st): State<PortalState>, req: Request) -> Response {
    verify_post(st, req, "recovery").await
}

// ---- /security/recovery-codes ---------------------------------------------

fn recovery_page(
    st: &PortalState,
    e: &Entry,
    view: &SecurityView,
    codes: Vec<String>,
    first: bool,
    error: Option<&'static str>,
) -> Response {
    let csrf = token(st, &e.rq, "recovery");
    render_page_status(
        &e.rq,
        StatusCode::OK,
        pages::RecoveryPage {
            t: e.rq.t(),
            request_id: e.rq.rid(),
            notice: None,
            error,
            csrf: &csrf,
            codes,
            first,
            generated: view.recovery_generated,
            unused: view.recovery_unused.to_string(),
            has_factor: !view.passkeys.is_empty() || view.totp_active,
        },
        &e.plant,
        &[],
    )
}

pub(crate) async fn recovery_get(State(st): State<PortalState>, req: Request) -> Response {
    let (parts, _) = req.into_parts();
    let e = match enter(&st, &parts, true) {
        Ok(e) => e,
        Err(r) => return r,
    };
    let first = query(&parts).is_some_and(|p| p.get("first") == Some("1"));
    match e.settings.overview(&e.rq.ctx, &e.cookies).await {
        Ok(view) => recovery_page(&st, &e, &view, vec![], first, None),
        Err(r) => refusal_page(&e.rq, r),
    }
}

pub(crate) async fn recovery_post(State(st): State<PortalState>, req: Request) -> Response {
    let (parts, body) = req.into_parts();
    let e = match enter(&st, &parts, false) {
        Ok(e) => e,
        Err(r) => return r,
    };
    if let Err(r) = posted(&st, &e, &parts, body, "recovery", &[], &[]).await {
        return r;
    }
    match e
        .settings
        .generate_recovery_codes(&e.rq.ctx, &e.cookies)
        .await
    {
        Ok(codes) => {
            let view = SecurityView::default();
            let codes = codes.iter().map(|c| c.to_string()).collect();
            recovery_page(&st, &e, &view, codes, false, None)
        }
        Err(Refusal::VerificationRequired) => see_other(&verify_location(Next::Recovery), &[]),
        Err(r) => refusal_page(&e.rq, r),
    }
}

// ---- Passkey step-up ------------------------------------------------------

/// Render the passkey step-up page, or `None` when the user has no passkey
/// (the caller falls back to the other methods).
pub(super) async fn stepup_passkey_page(
    st: &PortalState,
    rq: &Rq,
    cookies: &Cookies,
    transaction: &str,
    choices: &[pages::ExternalChoice],
    plant: &[String],
    error: Option<&'static str>,
) -> Option<Response> {
    let settings = st.settings.clone()?;
    match settings
        .begin_stepup(&rq.ctx, cookies, &Secret::new(transaction.into()))
        .await
    {
        Ok(entry) => {
            let page = entry.page?;
            let binding = stepup_csrf_binding(rq, transaction)?;
            let csrf = token_for(st, &binding, Purpose::PasskeyStepUp);
            Some(ceremony_response(render_page_status(
                rq,
                StatusCode::OK,
                pages::StepUpPasskeyPage {
                    t: rq.t(),
                    request_id: rq.rid(),
                    notice: None,
                    error,
                    csrf: &csrf,
                    transaction,
                    ceremony: page.ceremony.expose(),
                    options: &page.options,
                    totp: entry.totp,
                    choices,
                    integrity: pages::script_integrity(),
                },
                plant,
                &[entry.form_origin],
            )))
        }
        Err(r) => Some(refusal_page(rq, r)),
    }
}

pub(crate) async fn stepup_post(State(st): State<PortalState>, req: Request) -> Response {
    let (parts, body) = req.into_parts();
    let rq = match prepare(&st, &parts) {
        Ok(rq) => rq,
        Err(r) => return r,
    };
    let Some(settings) = st.settings.clone() else {
        return error_response(rq.t(), rq.rid(), ErrorPage::NotFound);
    };
    if !rq.ctx.https {
        return error_response(rq.t(), rq.rid(), ErrorPage::Forbidden);
    }
    let form = match read_form(&st, &rq, &parts, body).await {
        Ok(f) => f,
        Err(r) => return r,
    };
    if form.0.0.len() != 4
        || ["txn", "csrf", "ceremony", "credential"]
            .iter()
            .any(|n| form.0.0.iter().filter(|(k, _)| k == n).count() != 1)
    {
        return error_response(rq.t(), rq.rid(), ErrorPage::BadRequest);
    }
    let txn = form.0.get("txn").unwrap_or("").to_owned();
    if !crate::crypto::is_well_formed_bind(&txn) {
        return error_response(rq.t(), rq.rid(), ErrorPage::BadRequest);
    }
    let Some(binding) = stepup_csrf_binding(&rq, &txn) else {
        return error_response(rq.t(), rq.rid(), ErrorPage::Forbidden);
    };
    if let Err(r) = guard(
        &st,
        &rq,
        &parts,
        &form,
        Purpose::PasskeyStepUp,
        Some(&binding),
    )
    .await
    {
        return r;
    }
    if !st.password_attempts.admit(rq.ctx.client_ip) {
        return rate_limited(&rq);
    }
    let cookies = Cookies {
        handle: rq.presented.handle.clone(),
        bind: rq.presented.bind.clone(),
    };
    let credential = form.0.get("credential").unwrap_or("");
    let outcome = if credential.is_empty() || credential.len() > 32 * 1024 {
        Err(Refusal::Rejected)
    } else {
        settings
            .complete_stepup(
                &rq.ctx,
                &cookies,
                &Secret::new(txn.clone()),
                &Secret::new(form.0.get("ceremony").unwrap_or("").into()),
                credential,
            )
            .await
    };
    match outcome {
        Ok(redirect) => redirect_response(&st, &rq, &redirect, &[]),
        Err(r @ (Refusal::Failure(_) | Refusal::CloneSuspected)) => refusal_page(&rq, r),
        Err(r) => {
            let choices = external_choices(&st, &txn);
            stepup_passkey_page(&st, &rq, &cookies, &txn, &choices, &[], refusal_key(r))
                .await
                .unwrap_or_else(|| error_response(rq.t(), rq.rid(), ErrorPage::Failed))
        }
    }
}
