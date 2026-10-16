//! `/sessions` and `/v1/sessions` handlers (W1-B): the live-session listing,
//! one session with its handles, and termination of one session. The helpers
//! shared with the other W1-B files are in [`super::users::common`].

use std::sync::Arc;

use askama::Template;
use axum::Extension;
use axum::extract::{Path, State};
use axum::http::{StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};

use crate::config::valid_user_id;
use crate::event::types::{EventKind, Outcome, reasons};
use crate::identity::types::UserId;
use crate::session::types::{Aal, SessionId};
use crate::store::types::{AdminRole, Cursor, HandleRow, SessionSummary, SessionsQuery};
use crate::telemetry::counters;

use super::api::{self, Query};
use super::csrf::{self, Mutation};
use super::pages::{self, Chrome};
use super::users::common::{
    self, Fail, back_target, cursor_json, cursor_of, fail, invalid_filter, limit_of, next_url,
    session_json, store_failure, time_str, unix, valid_session_id, write_failure,
};
use super::{AdminState, Ctx};

/// One session as a table row.
pub(super) struct SessionRowView {
    pub session_id: String,
    pub user_id: String,
    pub email: String,
    pub provider: String,
    pub aal: i64,
    pub hosts: String,
    pub created: String,
    pub last_seen: String,
    pub expires: String,
    pub auth_time: String,
    pub auth_source: String,
    pub bound_ip: String,
    pub ua_prefix: String,
    pub ended: String,
    pub live: bool,
}

pub(super) fn session_row_views(items: &[SessionSummary]) -> Vec<SessionRowView> {
    items.iter().map(row_view).collect()
}

fn row_view(s: &SessionSummary) -> SessionRowView {
    let r = &s.session;
    SessionRowView {
        session_id: r.session_id.to_string(),
        user_id: r.user_id.to_string(),
        email: s
            .primary_email
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_default(),
        provider: r.provider_id.to_string(),
        aal: r.aal.as_i64(),
        hosts: s
            .hosts
            .iter()
            .map(|h| h.as_str())
            .collect::<Vec<_>>()
            .join(", "),
        created: time_str(unix(r.created_at)),
        last_seen: time_str(unix(r.last_seen_at)),
        expires: time_str(unix(r.absolute_expires_at)),
        auth_time: time_str(unix(r.auth_time)),
        auth_source: r.auth_time_source.as_str().to_string(),
        bound_ip: r.bound_ip.to_string(),
        ua_prefix: s.ua_prefix.clone().unwrap_or_default(),
        ended: match (r.terminated_at, &r.terminated_reason) {
            (Some(at), Some(why)) => format!("{} ({why})", time_str(unix(at))),
            (Some(at), None) => time_str(unix(at)),
            _ => String::new(),
        },
        live: r.terminated_at.is_none(),
    }
}

struct HandleView {
    host: String,
    aal: i64,
    created: String,
    last_seen: String,
    expires: String,
    revoked: String,
}

#[derive(Template)]
#[template(path = "admin/sessions.html")]
struct SessionsPage<'a> {
    c: &'a Chrome<'a>,
    csrf: String,
    is_admin: bool,
    user_id: String,
    rows: Vec<SessionRowView>,
    next: Option<String>,
}

#[derive(Template)]
#[template(path = "admin/session.html")]
struct SessionPage<'a> {
    c: &'a Chrome<'a>,
    csrf: String,
    is_admin: bool,
    row: SessionRowView,
    handles: Vec<HandleView>,
}

struct Params {
    user_id: Option<UserId>,
    aal: Option<Aal>,
    limit: usize,
    cursor: Option<Cursor>,
}

fn params(st: &AdminState, q: &Query) -> Result<Params, Fail> {
    let user_id = match q.get("user_id") {
        None | Some("") => None,
        Some(v) if valid_user_id(v) => Some(UserId::new(v)),
        Some(_) => return Err(invalid_filter()),
    };
    // The stored level: 1 or 2 (AAL 3 is a presentation, never stored).
    let aal = match q.get("aal") {
        None | Some("") => None,
        Some("1") => Some(Aal::One),
        Some("2") => Some(Aal::Two),
        Some(_) => return Err(invalid_filter()),
    };
    Ok(Params {
        user_id,
        aal,
        limit: limit_of(q)?,
        cursor: cursor_of(st, q)?,
    })
}

async fn load(
    st: &AdminState,
    c: &Ctx,
    p: Params,
) -> Result<crate::store::types::Page<SessionSummary>, Fail> {
    let page = st
        .sessions
        .list_live_sessions(
            SessionsQuery {
                user_id: p.user_id,
                aal: p.aal,
                limit: p.limit,
                cursor: p.cursor,
                now: st.clock.now(),
            },
            api::deadline(st),
        )
        .await
        .map_err(|e| store_failure(c, "sessions", &e))?;
    common::examined("sessions", page.examined);
    Ok(page)
}

pub async fn list_api(State(st): State<Arc<AdminState>>, c: Ctx, uri: Uri) -> Response {
    let run = async {
        let p = params(&st, &Query::parse(&uri))?;
        let page = load(&st, &c, p).await?;
        Ok::<_, Fail>(api::json(
            StatusCode::OK,
            &json!({
                "items": page.items.iter().map(session_json).collect::<Vec<_>>(),
                "next_cursor": cursor_json(&st, &page.next),
            }),
        ))
    };
    run.await.unwrap_or_else(|f| f.respond(&st, &c))
}

pub async fn list_page(State(st): State<Arc<AdminState>>, c: Ctx, uri: Uri) -> Response {
    let run = async {
        let p = params(&st, &Query::parse(&uri))?;
        let user_id = p
            .user_id
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_default();
        let aal = p.aal.map(|a| a.as_i64().to_string()).unwrap_or_default();
        let page = load(&st, &c, p).await?;
        let next = next_url(
            &st,
            "/sessions",
            &[("user_id", user_id.clone()), ("aal", aal)],
            &page.next,
        );
        let chrome = Chrome::signed_in(&st, &c.req, &c.principal, "sessions");
        Ok::<_, Fail>(pages::render(
            StatusCode::OK,
            &SessionsPage {
                c: &chrome,
                csrf: csrf::issue(&st, &c),
                is_admin: c.principal.role == AdminRole::Admin,
                user_id,
                rows: session_row_views(&page.items),
                next,
            },
        ))
    };
    run.await.unwrap_or_else(|f| f.respond(&st, &c))
}

async fn load_one(
    st: &AdminState,
    c: &Ctx,
    id: &str,
) -> Result<(SessionSummary, Vec<HandleRow>), Fail> {
    if !valid_session_id(id) {
        return Err(fail(StatusCode::BAD_REQUEST, "invalid_id"));
    }
    st.sessions
        .session_summary(&SessionId::new(id), api::deadline(st))
        .await
        .map_err(|e| store_failure(c, "sessions", &e))?
        .ok_or_else(|| fail(StatusCode::NOT_FOUND, "not_found"))
}

pub async fn detail_api(
    State(st): State<Arc<AdminState>>,
    c: Ctx,
    Path(id): Path<String>,
) -> Response {
    let run = async {
        let (s, handles) = load_one(&st, &c, &id).await?;
        let mut v = session_json(&s);
        if let Value::Object(m) = &mut v {
            m.entry("terminated_at").or_insert(Value::Null);
            m.entry("terminated_reason").or_insert(Value::Null);
            m.insert(
                "handles".into(),
                Value::Array(
                    handles
                        .iter()
                        .map(|h| {
                            json!({
                                "host": h.host.as_str(),
                                "issued_aal": h.issued_aal.as_i64(),
                                "created_at": h.created_at.secs(),
                                "last_seen_at": h.last_seen_at.secs(),
                                "absolute_expires_at": h.absolute_expires_at.secs(),
                                "revoked_at": h.revoked_at.map(|t| t.secs()),
                                "revoked_reason": h.revoked_reason,
                            })
                        })
                        .collect(),
                ),
            );
        }
        Ok::<_, Fail>(api::json(StatusCode::OK, &v))
    };
    run.await.unwrap_or_else(|f| f.respond(&st, &c))
}

pub async fn detail_page(
    State(st): State<Arc<AdminState>>,
    c: Ctx,
    Path(id): Path<String>,
) -> Response {
    let run = async {
        let (s, handles) = load_one(&st, &c, &id).await?;
        let chrome = Chrome::signed_in(&st, &c.req, &c.principal, "sessions");
        Ok::<_, Fail>(pages::render(
            StatusCode::OK,
            &SessionPage {
                c: &chrome,
                csrf: csrf::issue(&st, &c),
                is_admin: c.principal.role == AdminRole::Admin,
                row: row_view(&s),
                handles: handles
                    .iter()
                    .map(|h| HandleView {
                        host: h.host.to_string(),
                        aal: h.issued_aal.as_i64(),
                        created: time_str(unix(h.created_at)),
                        last_seen: time_str(unix(h.last_seen_at)),
                        expires: time_str(unix(h.absolute_expires_at)),
                        revoked: match (&h.revoked_at, &h.revoked_reason) {
                            (Some(at), Some(why)) => format!("{} ({why})", time_str(unix(*at))),
                            (Some(at), None) => time_str(unix(*at)),
                            _ => String::new(),
                        },
                    })
                    .collect(),
            },
        ))
    };
    run.await.unwrap_or_else(|f| f.respond(&st, &c))
}

/// Terminate one session; `Ok(changed)`. CSRF and the role were checked by the listener.
async fn terminate(st: &AdminState, c: &Ctx, id: &str, m: &Mutation) -> Result<bool, Fail> {
    if !valid_session_id(id) {
        return Err(fail(StatusCode::BAD_REQUEST, "invalid_id"));
    }
    let reason = common::reason_of(m)?;
    let actor = api::actor(&c.principal);
    let policy = api::actor_policy(st, &c.principal);
    let dl = api::deadline(st);
    let sid = SessionId::new(id);
    // The target's user is needed for both events; an unknown id is a 404.
    let (target, _) = st
        .sessions
        .session_summary(&sid, dl)
        .await
        .map_err(|e| store_failure(c, "sessions", &e))?
        .ok_or_else(|| fail(StatusCode::NOT_FOUND, "not_found"))?;
    let row = &target.session;
    let session_event = common::plain_event(st, c, EventKind::SessionTerminated, Outcome::Info)
        .user(&row.user_id)
        .session(&row.session_id)
        .provider(&row.provider_id)
        .reason(reasons::ADMIN)
        .build();
    let admin_event = super::users::with_note(
        common::admin_event(st, c, EventKind::AdminSessionTerminate, Outcome::Success),
        reason.as_deref(),
    )
    .user(&row.user_id)
    .session(&row.session_id)
    .build();
    let changed = match st
        .sessions
        .admin_terminate_session(&actor, &policy, &sid, dl, admin_event, session_event)
        .await
    {
        Ok(v) => v,
        Err(e) => return Err(write_failure(st, c, "sessions", &e).await),
    };
    if changed {
        common::count_event(EventKind::SessionTerminated, Outcome::Info);
        common::count_event(EventKind::AdminSessionTerminate, Outcome::Success);
        counters::inc(
            counters::ADMIN_MUTATIONS_TOTAL,
            &[("kind", "session_terminate")],
        );
    } else {
        tracing::info!(request_id = %c.req.rid, kind = "session_terminate", "console mutation changed nothing");
    }
    Ok(changed)
}

pub async fn terminate_api(
    State(st): State<Arc<AdminState>>,
    c: Ctx,
    Path(id): Path<String>,
    Extension(m): Extension<Mutation>,
) -> Response {
    match terminate(&st, &c, &id, &m).await {
        Ok(changed) => api::json(StatusCode::OK, &json!({ "changed": changed })),
        Err(f) => f.respond(&st, &c),
    }
}

pub async fn terminate_page(
    State(st): State<Arc<AdminState>>,
    c: Ctx,
    Path(id): Path<String>,
    Extension(m): Extension<Mutation>,
) -> Response {
    match terminate(&st, &c, &id, &m).await {
        Ok(_) => {
            let get = |n: &str| m.form.as_ref().and_then(|f| f.get(n));
            let mut r = StatusCode::SEE_OTHER.into_response();
            if let Ok(v) = axum::http::HeaderValue::from_str(&back_target(&get, "/sessions")) {
                r.headers_mut().insert(axum::http::header::LOCATION, v);
            }
            r
        }
        Err(f) => f.respond(&st, &c),
    }
}
