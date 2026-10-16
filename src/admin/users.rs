//! `/users` and `/v1/users` handlers (W1-B): list and search, detail, disable,
//! enable and "terminate every session of this user".
//!
//! The listener authenticates, applies the CSRF rule and the role check
//! before a mutation handler runs ([`super::csrf::Mutation`]); the handlers own
//! `self_target`, the fenced write and `actor_revoked`. [`common`] holds the
//! helpers the three W1-B handler files share.

// A refusal is a small value (`Fail`), rendered at the handler's edge.
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
use crate::store::types::{
    AdminRole, Cursor, EventsQuery, SessionRow, UserFilters, UserStatus, UserSummary, UsersQuery,
};
use crate::telemetry::counters;

use super::api::{self, Query};
use super::csrf::{self, Mutation};
use super::events::{EventRow, event_rows};
use super::pages::{self, Chrome};
use super::sessions::{SessionRowView, session_row_views};
use super::{AdminState, Ctx};
use common::{
    Fail, back_target, cursor_json, cursor_of, deny, fail, invalid_filter, limit_of, next_url,
    session_json, store_failure, time_str, unix, write_failure,
};

/// Helpers shared by the W1-B handler files.
pub mod common {
    use axum::http::StatusCode;
    use axum::response::Response;
    use serde_json::{Value, json};

    use crate::crypto::Timestamp;
    use crate::event::types::{EventBuilder, EventKind, Outcome, Reason};
    use crate::store::StoreError;
    use crate::store::types::{Cursor, IdentityRow, SessionSummary, User};
    use crate::telemetry::counters;

    use crate::admin::api::{self, InvalidFilter, Query};
    use crate::admin::{AdminState, Ctx, auth, cursor};

    /// A refusal: status and error code, rendered by [`Fail::respond`] as JSON
    /// for `/v1/` and as a page otherwise.
    #[derive(Clone, Copy, Debug)]
    pub struct Fail(pub StatusCode, pub &'static str);

    impl Fail {
        pub fn respond(self, st: &AdminState, c: &Ctx) -> Response {
            api::error(st, &c.req, &c.principal, self.0, self.1)
        }
    }

    pub fn fail(status: StatusCode, code: &'static str) -> Fail {
        Fail(status, code)
    }

    pub fn invalid_filter() -> Fail {
        Fail(StatusCode::BAD_REQUEST, "invalid_filter")
    }

    /// `limit`: 1 to 200, default 50.
    pub fn limit_of(q: &Query) -> Result<usize, Fail> {
        api::parse_limit(q.get("limit")).map_err(|InvalidFilter| invalid_filter())
    }

    /// The `cursor` parameter of a listing.
    pub fn cursor_of(st: &AdminState, q: &Query) -> Result<Option<Cursor>, Fail> {
        match q.get("cursor") {
            None => Ok(None),
            Some(v) => cursor::decode(&st.key, v)
                .map(Some)
                .map_err(|_| Fail(StatusCode::BAD_REQUEST, "invalid_cursor")),
        }
    }

    /// `next_cursor` of a page, `null` when the walk ends.
    pub fn cursor_json(st: &AdminState, next: &Option<Cursor>) -> Value {
        match next {
            Some(c) => Value::String(cursor::encode(&st.key, c)),
            None => Value::Null,
        }
    }

    /// A relative link to the next page: the current filters plus the cursor.
    pub fn next_url(
        st: &AdminState,
        path: &str,
        filters: &[(&str, String)],
        next: &Option<Cursor>,
    ) -> Option<String> {
        let c = next.as_ref()?;
        let mut ser = form_urlencoded::Serializer::new(String::new());
        for (k, v) in filters {
            if !v.is_empty() {
                ser.append_pair(k, v);
            }
        }
        ser.append_pair("cursor", &cursor::encode(&st.key, c));
        Some(format!("{path}?{}", ser.finish()))
    }

    /// A session id by shape: `s_` and up to 62 letters, digits, `_` or `-`.
    pub fn valid_session_id(s: &str) -> bool {
        s.len() >= 3
            && s.len() <= 64
            && s.starts_with("s_")
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    }

    // ---- time and shapes ----------------------------------------------------

    pub fn unix(t: Timestamp) -> i64 {
        t.secs()
    }

    /// `YYYY-MM-DD HH:MM:SS UTC` of unix seconds.
    pub fn time_str(secs: i64) -> String {
        let days = secs.div_euclid(86_400);
        let rem = secs.rem_euclid(86_400);
        // Howard Hinnant's civil_from_days.
        let z = days + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z.rem_euclid(146_097);
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let y = yoe + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let m = if mp < 10 { mp + 3 } else { mp - 9 };
        let y = if m <= 2 { y + 1 } else { y };
        format!(
            "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC",
            rem / 3600,
            rem % 3600 / 60,
            rem % 60
        )
    }

    fn opt_unix(t: Option<Timestamp>) -> Value {
        t.map_or(Value::Null, |t| json!(t.secs()))
    }

    pub fn user_json(u: &User) -> Value {
        json!({
            "user_id": u.user_id.as_str(),
            "primary_email": u.primary_email.as_ref().map(ToString::to_string),
            "email_verified": u.email_verified,
            "email_authoritative": u.email_authoritative,
            "display_name": u.display_name,
            "username": u.username,
            "status": u.status.as_str(),
            "authz_version": u.authz_version,
            "groups": u.groups,
            "created_at": u.created_at.secs(),
            "updated_at": u.updated_at.secs(),
            "last_login_at": opt_unix(u.last_login_at),
        })
    }

    /// Never `raw_claims` or the picture URL.
    pub fn identity_json(i: &IdentityRow) -> Value {
        json!({
            "provider_id": i.provider_id.as_str(),
            "subject": i.subject,
            "email": i.email.as_ref().map(ToString::to_string),
            "email_verified": i.email_verified,
            "name": i.name,
            "first_seen_at": i.first_seen_at.secs(),
            "last_seen_at": i.last_seen_at.secs(),
        })
    }

    /// The session summary of the API; a terminated session adds its end.
    pub fn session_json(s: &SessionSummary) -> Value {
        let r = &s.session;
        let mut v = json!({
            "session_id": r.session_id.as_str(),
            "user_id": r.user_id.as_str(),
            "primary_email": s.primary_email.as_ref().map(ToString::to_string),
            "provider_id": r.provider_id.as_str(),
            "aal": r.aal.as_i64(),
            "factors": r.factors,
            "hosts": s.hosts.iter().map(|h| h.as_str()).collect::<Vec<_>>(),
            "created_at": r.created_at.secs(),
            "last_seen_at": r.last_seen_at.secs(),
            "absolute_expires_at": r.absolute_expires_at.secs(),
            "auth_time": r.auth_time.secs(),
            "auth_time_source": r.auth_time_source.as_str(),
            "bound_ip": r.bound_ip.to_string(),
            "ua_prefix": s.ua_prefix,
        });
        if let (Some(at), Value::Object(m)) = (r.terminated_at, &mut v) {
            m.insert("terminated_at".into(), json!(at.secs()));
            m.insert("terminated_reason".into(), json!(r.terminated_reason));
        }
        v
    }

    // ---- store results ------------------------------------------------------

    fn error_kind(e: &StoreError) -> &'static str {
        match e {
            StoreError::Unavailable(_) => "unavailable",
            StoreError::Busy => "busy",
            StoreError::Conflict(_) => "conflict",
            StoreError::Corrupt(_) => "corrupt",
            _ => "other",
        }
    }

    /// A store failure as the console answers it: fail closed, `503`, no detail.
    pub fn store_failure(c: &Ctx, list: &str, e: &StoreError) -> Fail {
        match e {
            StoreError::Unavailable(why) if matches!(why.as_str(), "deadline" | "interrupted") => {
                tracing::warn!(list, request_id = %c.req.rid, "console store operation reached its deadline");
            }
            StoreError::Busy => {
                tracing::warn!(list, request_id = %c.req.rid, "console store operation found the store busy");
            }
            _ => {
                tracing::error!(list, request_id = %c.req.rid, error_kind = error_kind(e), "console store operation failed");
            }
        }
        Fail(StatusCode::SERVICE_UNAVAILABLE, "store_unavailable")
    }

    /// Count the candidates a page examined.
    pub fn examined(list: &str, n: u32) {
        counters::add(
            counters::ADMIN_ROWS_EXAMINED_TOTAL,
            &[("list", list)],
            u64::from(n),
        );
    }

    // ---- mutations ----------------------------------------------------------

    /// An `admin.*` event builder: the request id, the console application,
    /// the client address, `attrs.actor` and `attrs.actor_session`; the
    /// target's columns are the caller's.
    pub fn admin_event(
        st: &AdminState,
        c: &Ctx,
        kind: EventKind,
        outcome: Outcome,
    ) -> EventBuilder {
        let event = plain_event(st, c, kind, outcome)
            .attr("actor", c.principal.user_id.as_str())
            .attr("actor_session", c.principal.session_id.as_str());
        let event = match &c.service {
            Some(s) => event
                .attr("credential_id", s.credential_id.as_str())
                .attr("credential_slot", s.slot),
            None => event,
        };
        if let Some(actor) = &c.delegated_actor {
            event
                .attr("delegated_issuer", "hangang")
                .attr("delegated_actor", format!("{}:{}", actor.id, actor.name))
                .attr("delegated_operation", actor.nonce.as_str())
        } else {
            event
        }
    }

    /// An event builder with the request id, application and client address.
    pub fn plain_event(
        st: &AdminState,
        c: &Ctx,
        kind: EventKind,
        outcome: Outcome,
    ) -> EventBuilder {
        EventBuilder::new(
            st.clock.as_ref(),
            st.rng.as_ref(),
            kind,
            outcome,
            c.req.rid.clone(),
        )
        .app(&st.cfg.policy.app_id)
        .ip(c.req.client_ip)
    }

    /// Count a required event that was written.
    pub fn count_event(kind: EventKind, outcome: Outcome) {
        counters::inc(
            counters::EVENTS_TOTAL,
            &[("kind", kind.name()), ("outcome", outcome.as_str())],
        );
    }

    /// Refuse with `403 reason` and record `admin.denied` for the requester.
    pub async fn deny(st: &AdminState, c: &Ctx, reason: Reason) -> Fail {
        auth::record_denied(
            st,
            &c.req,
            Some((&c.principal.user_id, &c.principal.session_id)),
            reason,
        )
        .await;
        Fail(StatusCode::FORBIDDEN, reason.0)
    }

    /// The fenced write refused the actor (`403 actor_revoked`, recorded),
    /// named an unknown user, or failed.
    pub async fn write_failure(st: &AdminState, c: &Ctx, list: &str, e: &StoreError) -> Fail {
        match e {
            StoreError::Conflict("actor_revoked") => {
                deny(st, c, crate::event::types::reasons::ACTOR_REVOKED).await
            }
            StoreError::Conflict("unknown user") => Fail(StatusCode::NOT_FOUND, "not_found"),
            _ => store_failure(c, list, e),
        }
    }

    /// Where a form returns to: a server-chosen path, never a client value.
    /// `get` reads the form's fields (`back`, `user_id`, `session_id`).
    pub fn back_target<'a>(get: &dyn Fn(&str) -> Option<&'a str>, default: &str) -> String {
        match (get("back"), get("user_id"), get("session_id")) {
            (Some("user"), Some(u), _) if crate::config::valid_user_id(u) => {
                format!("/users/{u}")
            }
            (Some("session"), _, Some(s)) if valid_session_id(s) => format!("/sessions/{s}"),
            (Some("sessions"), Some(u), _) if crate::config::valid_user_id(u) => {
                format!("/sessions?user_id={u}")
            }
            (Some("sessions"), _, _) => "/sessions".to_string(),
            _ => default.to_string(),
        }
    }

    /// Longest `reason` a console mutation accepts (characters, trimmed).
    pub const MAX_REASON_CHARS: usize = 256;

    /// The optional `reason` of a console mutation: the form field `reason`,
    /// or `"reason"` in a JSON body (a body without it, or not a JSON object,
    /// has none: the console historically ignored mutation bodies). An empty
    /// reason is none; one longer than 256 characters or carrying control or
    /// invisible formatting characters is `400 invalid_reason`. Recorded as
    /// the `note` of the mutation's `admin.*` event.
    pub fn reason_of(m: &crate::admin::csrf::Mutation) -> Result<Option<String>, Fail> {
        let raw: Option<String> = match &m.form {
            Some(f) => f.get("reason").map(str::to_string),
            None => match serde_json::from_slice::<Value>(&m.body) {
                Ok(Value::Object(o)) => match o.get("reason") {
                    None | Some(Value::Null) => None,
                    Some(Value::String(s)) => Some(s.clone()),
                    Some(_) => return Err(Fail(StatusCode::BAD_REQUEST, "invalid_reason")),
                },
                _ => None,
            },
        };
        match raw {
            None => Ok(None),
            Some(r) if r.trim().is_empty() => Ok(None),
            Some(r) if crate::groups::valid_text(&r, MAX_REASON_CHARS) => {
                Ok(Some(r.trim().to_string()))
            }
            Some(_) => Err(Fail(StatusCode::BAD_REQUEST, "invalid_reason")),
        }
    }

    /// Unused-import guard for `Cursor` in this module's signatures.
    pub type Pos = Cursor;
}

// ---- views ------------------------------------------------------------------

pub struct UserRowView {
    user_id: String,
    email: String,
    display_name: String,
    username: String,
    status: String,
    role: String,
    live_sessions: u32,
    created: String,
    last_login: String,
}

fn user_row(s: &UserSummary) -> UserRowView {
    UserRowView {
        user_id: s.user.user_id.to_string(),
        email: s
            .user
            .primary_email
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_default(),
        display_name: s.user.display_name.clone().unwrap_or_default(),
        username: s.user.username.clone().unwrap_or_default(),
        status: s.user.status.as_str().to_string(),
        role: s.role.map(|r| r.as_str().to_string()).unwrap_or_default(),
        live_sessions: s.live_sessions,
        created: time_str(unix(s.user.created_at)),
        last_login: s
            .user
            .last_login_at
            .map(|t| time_str(unix(t)))
            .unwrap_or_default(),
    }
}

fn user_summary_json(s: &UserSummary) -> Value {
    let u = &s.user;
    json!({
        "user_id": u.user_id.as_str(),
        "primary_email": u.primary_email.as_ref().map(ToString::to_string),
        "email_verified": u.email_verified,
        "email_authoritative": u.email_authoritative,
        "display_name": u.display_name,
        "username": u.username,
        "status": u.status.as_str(),
        "authz_version": u.authz_version,
        "created_at": u.created_at.secs(),
        "last_login_at": u.last_login_at.map(|t| t.secs()),
        "live_sessions": s.live_sessions,
        "role": s.role.map(AdminRole::as_str),
    })
}

#[derive(Template)]
#[template(path = "admin/users.html")]
struct UsersPage<'a> {
    c: &'a Chrome<'a>,
    q: String,
    status: String,
    rows: Vec<UserRowView>,
    next: Option<String>,
}

pub struct IdentityView {
    provider: String,
    subject: String,
    email: String,
    name: String,
    first_seen: String,
    last_seen: String,
}

#[derive(Template)]
#[template(path = "admin/user.html")]
struct UserPage<'a> {
    c: &'a Chrome<'a>,
    csrf: String,
    is_admin: bool,
    user_id: String,
    email: String,
    email_flags: String,
    human_subject: String,
    display_name: String,
    username: String,
    status: String,
    active: bool,
    authz_version: u64,
    created: String,
    last_login: String,
    identities: Vec<IdentityView>,
    live: Vec<SessionRowView>,
    live_total: u32,
    terminated: Vec<SessionRowView>,
    events: Vec<EventRow>,
    grant: String,
    sessions_url: String,
    events_url: String,
}

// ---- reads ------------------------------------------------------------------

/// `q` for a `LIKE ... ESCAPE '\\'` match: wildcards and the escape itself are literal.
fn escape_like(v: &str) -> String {
    let mut out = String::with_capacity(v.len() + 4);
    for ch in v.chars() {
        if matches!(ch, '\\' | '%' | '_') {
            out.push('\\');
        }
        out.push(ch);
    }
    out
}

/// Parsed `/users` parameters.
struct UsersParams {
    q: Option<String>,
    status: Option<UserStatus>,
    filters: UserFilters,
    limit: usize,
    cursor: Option<Cursor>,
}

/// A provider id as configured: `[a-z0-9][a-z0-9_-]{0,31}`.
pub(crate) fn valid_provider_slug(v: &str) -> bool {
    let b = v.as_bytes();
    !b.is_empty()
        && b.len() <= 32
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'_' | b'-'))
}

/// `provider`, `mfa` (`enrolled` or `none`) and `group` (`grp1:` reference).
fn user_filters(q: &Query) -> Result<UserFilters, Fail> {
    let provider = match q.get("provider") {
        None | Some("") => None,
        Some(v) if valid_provider_slug(v) => Some(v.to_string()),
        Some(_) => return Err(invalid_filter()),
    };
    let mfa_enrolled = match q.get("mfa") {
        None | Some("") => None,
        Some("enrolled") => Some(true),
        Some("none") => Some(false),
        Some(_) => return Err(invalid_filter()),
    };
    let group = match q.get("group") {
        None | Some("") => None,
        Some(v) if crate::groups::valid_ref(v) => Some(v.to_string()),
        Some(_) => return Err(invalid_filter()),
    };
    Ok(UserFilters {
        provider,
        mfa_enrolled,
        group,
    })
}

fn users_params(st: &AdminState, q: &Query) -> Result<UsersParams, Fail> {
    let text = match q.get("q") {
        None | Some("") => None,
        Some(v) => {
            if v.chars().count() > 128 || v.chars().any(|ch| ch.is_control()) {
                return Err(invalid_filter());
            }
            Some(escape_like(v))
        }
    };
    let status = match q.get("status") {
        None | Some("") => None,
        Some(v) => Some(UserStatus::parse(v).ok_or_else(invalid_filter)?),
    };
    Ok(UsersParams {
        q: text,
        status,
        filters: user_filters(q)?,
        limit: limit_of(q)?,
        cursor: cursor_of(st, q)?,
    })
}

async fn users_page(
    st: &AdminState,
    c: &Ctx,
    p: UsersParams,
) -> Result<crate::store::types::Page<UserSummary>, Fail> {
    let page = st
        .directory
        .list_users(
            UsersQuery {
                q: p.q,
                status: p.status,
                filters: p.filters,
                limit: p.limit,
                cursor: p.cursor,
            },
            api::deadline(st),
        )
        .await
        .map_err(|e| store_failure(c, "users", &e))?;
    common::examined("users", page.examined);
    Ok(page)
}

pub async fn list_api(State(st): State<Arc<AdminState>>, c: Ctx, uri: Uri) -> Response {
    let run = async {
        let params = users_params(&st, &Query::parse(&uri))?;
        let page = users_page(&st, &c, params).await?;
        let subjects = if let Some(issuer) = st
            .profile_config
            .receipt_issuer
            .as_ref()
            .filter(|issuer| issuer.human_receipts.is_some())
        {
            st.profile_store
                .admin_human_subjects(
                    issuer.issuer_ref.clone(),
                    page.items
                        .iter()
                        .map(|item| item.user.user_id.to_string())
                        .collect(),
                    api::deadline(&st),
                )
                .await
                .map_err(|error| store_failure(&c, "human_subjects", &error))?
        } else {
            std::collections::BTreeMap::new()
        };
        let items = page
            .items
            .iter()
            .map(|item| {
                let mut value = user_summary_json(item);
                if let Some(subject) = subjects.get(item.user.user_id.as_str()) {
                    value["human_subject"] = json!(subject);
                }
                value
            })
            .collect::<Vec<_>>();
        Ok::<_, Fail>(api::json(
            StatusCode::OK,
            &json!({
                "items": items,
                "next_cursor": cursor_json(&st, &page.next),
            }),
        ))
    };
    run.await.unwrap_or_else(|f| f.respond(&st, &c))
}

pub async fn list_page(State(st): State<Arc<AdminState>>, c: Ctx, uri: Uri) -> Response {
    let run = async {
        let params = users_params(&st, &Query::parse(&uri))?;
        let page = users_page(&st, &c, params).await?;
        // Echo the filters as the user typed them (unescaped).
        let q = Query::parse(&uri);
        let (qs, status) = (
            q.get("q").unwrap_or_default().to_string(),
            q.get("status").unwrap_or_default().to_string(),
        );
        let raw = |n: &str| q.get(n).unwrap_or_default().to_string();
        let next = next_url(
            &st,
            "/users",
            &[
                ("q", qs.clone()),
                ("status", status.clone()),
                ("provider", raw("provider")),
                ("mfa", raw("mfa")),
                ("group", raw("group")),
            ],
            &page.next,
        );
        let chrome = Chrome::signed_in(&st, &c.req, &c.principal, "users");
        Ok::<_, Fail>(pages::render(
            StatusCode::OK,
            &UsersPage {
                c: &chrome,
                q: qs,
                status,
                rows: page.items.iter().map(user_row).collect(),
                next,
            },
        ))
    };
    run.await.unwrap_or_else(|f| f.respond(&st, &c))
}

/// Everything the detail answers with.
struct Detail {
    d: crate::store::types::UserDetail,
    events: Vec<crate::event::types::Event>,
}

async fn load_detail(st: &AdminState, c: &Ctx, id: &str) -> Result<Detail, Fail> {
    if !valid_user_id(id) {
        return Err(fail(StatusCode::BAD_REQUEST, "invalid_id"));
    }
    let uid = UserId::new(id);
    let dl = api::deadline(st);
    let d = st
        .directory
        .user_detail(&uid, st.clock.now(), dl)
        .await
        .map_err(|e| store_failure(c, "users", &e))?
        .ok_or_else(|| fail(StatusCode::NOT_FOUND, "not_found"))?;
    let events = st
        .events
        .query_page(
            EventsQuery {
                user_id: Some(uid),
                limit: 50,
                ..EventsQuery::default()
            },
            dl,
        )
        .await
        .map_err(|e| store_failure(c, "events", &e))?;
    common::examined("events", events.examined);
    Ok(Detail {
        d,
        events: events.items,
    })
}

async fn human_subject(
    st: &AdminState,
    c: &Ctx,
    user: &crate::identity::UserId,
) -> Result<Option<String>, Fail> {
    let Some(issuer) = st
        .profile_config
        .receipt_issuer
        .as_ref()
        .filter(|issuer| issuer.human_receipts.is_some())
    else {
        return Ok(None);
    };
    st.profile_store
        .admin_human_subject(
            issuer.issuer_ref.clone(),
            user.to_string(),
            api::deadline(st),
        )
        .await
        .map_err(|error| store_failure(c, "human_subject", &error))
}

pub async fn detail_api(
    State(st): State<Arc<AdminState>>,
    c: Ctx,
    Path(id): Path<String>,
) -> Response {
    let run = async {
        let Detail { d, events } = load_detail(&st, &c, &id).await?;
        let grant = d.grant.as_ref().map(|g| {
            json!({
                "role": g.role.as_str(),
                "managed_by": g.managed_by.as_str(),
                "granted_at": g.granted_at.secs(),
                "granted_by": g.granted_by,
                "note": g.note,
            })
        });
        Ok::<_, Fail>(api::json(
            StatusCode::OK,
            &json!({
                "user": common::user_json(&d.user),
                "human_subject": human_subject(&st, &c, &d.user.user_id).await?,
                "identities": d.identities.iter().map(common::identity_json).collect::<Vec<_>>(),
                "sessions_live": d.sessions_live.iter().map(session_json).collect::<Vec<_>>(),
                "sessions_live_total": d.sessions_live_total,
                "sessions_terminated": d.sessions_terminated.iter().map(session_json).collect::<Vec<_>>(),
                "events": events.iter().map(crate::event::types::Event::to_json).collect::<Vec<_>>(),
                "grant": grant,
                "sessions_url": format!("/sessions?user_id={}", d.user.user_id),
                "events_url": format!("/events?user_id={}", d.user.user_id),
            }),
        ))
    };
    run.await.unwrap_or_else(|f| f.respond(&st, &c))
}

pub async fn detail_page(
    State(st): State<Arc<AdminState>>,
    c: Ctx,
    Path(id): Path<String>,
) -> Response {
    let run = async {
        let Detail { d, events } = load_detail(&st, &c, &id).await?;
        let u = &d.user;
        let flags = [
            (u.email_verified, "verified"),
            (u.email_authoritative, "authoritative"),
        ]
        .iter()
        .filter(|(on, _)| *on)
        .map(|(_, n)| *n)
        .collect::<Vec<_>>()
        .join(", ");
        let chrome = Chrome::signed_in(&st, &c.req, &c.principal, "users");
        Ok::<_, Fail>(pages::render(
            StatusCode::OK,
            &UserPage {
                c: &chrome,
                csrf: csrf::issue(&st, &c),
                is_admin: c.principal.role == AdminRole::Admin,
                user_id: u.user_id.to_string(),
                email: u
                    .primary_email
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or_default(),
                email_flags: flags,
                human_subject: human_subject(&st, &c, &u.user_id)
                    .await?
                    .unwrap_or_default(),
                display_name: u.display_name.clone().unwrap_or_default(),
                username: u.username.clone().unwrap_or_default(),
                status: u.status.as_str().to_string(),
                active: u.status == UserStatus::Active,
                authz_version: u.authz_version,
                created: time_str(unix(u.created_at)),
                last_login: u
                    .last_login_at
                    .map(|t| time_str(unix(t)))
                    .unwrap_or_default(),
                identities: d
                    .identities
                    .iter()
                    .map(|i| IdentityView {
                        provider: i.provider_id.to_string(),
                        subject: i.subject.clone(),
                        email: i
                            .email
                            .as_ref()
                            .map(ToString::to_string)
                            .unwrap_or_default(),
                        name: i.name.clone().unwrap_or_default(),
                        first_seen: time_str(unix(i.first_seen_at)),
                        last_seen: time_str(unix(i.last_seen_at)),
                    })
                    .collect(),
                live: session_row_views(&d.sessions_live),
                live_total: d.sessions_live_total,
                terminated: session_row_views(&d.sessions_terminated),
                events: event_rows(&events),
                grant: d
                    .grant
                    .as_ref()
                    .map(|g| {
                        format!(
                            "{} ({}, {})",
                            g.role.as_str(),
                            g.managed_by.as_str(),
                            if g.revoked_at.is_some() {
                                "revoked"
                            } else {
                                "live"
                            }
                        )
                    })
                    .unwrap_or_default(),
                sessions_url: format!("/sessions?user_id={}", u.user_id),
                events_url: format!("/events?user_id={}", u.user_id),
            },
        ))
    };
    run.await.unwrap_or_else(|f| f.respond(&st, &c))
}

// ---- mutations --------------------------------------------------------------

/// What a mutation answered, before it is rendered as JSON or a redirect.
enum Done {
    Disable { changed: bool, terminated: u32 },
    Enable { changed: bool },
    Terminate { terminated: u32 },
}

impl Done {
    fn json(&self) -> Value {
        match self {
            Done::Disable {
                changed,
                terminated,
            } => json!({"changed": changed, "sessions_terminated": terminated}),
            Done::Enable { changed } => json!({"changed": changed}),
            Done::Terminate { terminated } => json!({"terminated": terminated}),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Action {
    Disable,
    Enable,
    TerminateSessions,
}

impl Action {
    fn kind_label(self) -> &'static str {
        match self {
            Action::Disable => "user_disable",
            Action::Enable => "user_enable",
            Action::TerminateSessions => "sessions_terminate",
        }
    }
}

/// One mutation from `self_target` to the store call. The listener already
/// checked CSRF and the role.
async fn mutate(
    st: &AdminState,
    c: &Ctx,
    action: Action,
    id: &str,
    reason: Option<&str>,
    bulk: bool,
) -> Result<Done, Fail> {
    if !valid_user_id(id) {
        return Err(fail(StatusCode::BAD_REQUEST, "invalid_id"));
    }
    let target = UserId::new(id);
    if action == Action::Disable && target == c.principal.user_id {
        return Err(deny(st, c, reasons::SELF_TARGET).await);
    }
    let actor = api::actor(&c.principal);
    let policy = api::actor_policy(st, &c.principal);
    let dl = api::deadline(st);
    let session_event = {
        let (clock, rng, rid) = (st.clock.clone(), st.rng.clone(), c.req.rid.clone());
        let reason = if action == Action::Disable {
            reasons::USER_DISABLED
        } else {
            reasons::ADMIN
        };
        move |s: &SessionRow| {
            crate::event::types::EventBuilder::new(
                clock.as_ref(),
                rng.as_ref(),
                EventKind::SessionTerminated,
                Outcome::Info,
                rid.clone(),
            )
            .user(&s.user_id)
            .session(&s.session_id)
            .provider(&s.provider_id)
            .reason(reason)
            .build()
        }
    };
    let done = match action {
        Action::Disable | Action::Enable => {
            let (kind, status) = if action == Action::Disable {
                (EventKind::AdminUserDisable, UserStatus::Disabled)
            } else {
                (EventKind::AdminUserEnable, UserStatus::Active)
            };
            let mut ev =
                with_note(common::admin_event(st, c, kind, Outcome::Success), reason).user(&target);
            if bulk {
                // Every item of one bulk call carries the call's request id.
                ev = ev.attr("bulk_operation", c.req.rid.as_str());
            }
            let ev = ev.build();
            let res = st
                .directory
                .set_user_status(&actor, &policy, &target, status, dl, ev, &session_event)
                .await;
            let (changed, n) = match res {
                Ok(v) => v,
                Err(e) => return Err(write_failure(st, c, "users", &e).await),
            };
            if changed {
                common::count_event(kind, Outcome::Success);
                for _ in 0..n {
                    common::count_event(EventKind::SessionTerminated, Outcome::Info);
                }
            }
            if action == Action::Disable {
                Done::Disable {
                    changed,
                    terminated: n,
                }
            } else {
                Done::Enable { changed }
            }
        }
        Action::TerminateSessions => {
            let ev = with_note(
                common::admin_event(st, c, EventKind::AdminSessionsTerminate, Outcome::Success),
                reason,
            )
            .user(&target)
            .build();
            let res = st
                .sessions
                .admin_terminate_user_sessions(&actor, &policy, &target, dl, ev, &session_event)
                .await;
            let n = match res {
                Ok(v) => v,
                Err(e) => return Err(write_failure(st, c, "users", &e).await),
            };
            if n > 0 {
                common::count_event(EventKind::AdminSessionsTerminate, Outcome::Success);
                for _ in 0..n {
                    common::count_event(EventKind::SessionTerminated, Outcome::Info);
                }
            }
            Done::Terminate { terminated: n }
        }
    };
    let changed = match &done {
        Done::Disable { changed, .. } | Done::Enable { changed } => *changed,
        Done::Terminate { terminated } => *terminated > 0,
    };
    if changed {
        counters::inc(
            counters::ADMIN_MUTATIONS_TOTAL,
            &[("kind", action.kind_label())],
        );
    } else {
        tracing::info!(request_id = %c.req.rid, kind = action.kind_label(), "console mutation changed nothing");
    }
    Ok(done)
}

/// The event with `attrs.note` set to the mutation's reason, when one was given.
pub(super) fn with_note(
    ev: crate::event::types::EventBuilder,
    reason: Option<&str>,
) -> crate::event::types::EventBuilder {
    match reason {
        Some(r) => ev.attr("note", r),
        None => ev,
    }
}

async fn api_action(
    st: Arc<AdminState>,
    c: Ctx,
    id: String,
    m: Mutation,
    action: Action,
) -> Response {
    let run = async {
        let reason = common::reason_of(&m)?;
        mutate(&st, &c, action, &id, reason.as_deref(), false).await
    };
    match run.await {
        Ok(done) => api::json(StatusCode::OK, &done.json()),
        Err(f) => f.respond(&st, &c),
    }
}

async fn page_action(
    st: Arc<AdminState>,
    c: Ctx,
    id: String,
    m: Mutation,
    action: Action,
) -> Response {
    let run = async {
        let reason = common::reason_of(&m)?;
        mutate(&st, &c, action, &id, reason.as_deref(), false).await
    };
    match run.await {
        Ok(_) => {
            let default = format!("/users/{id}");
            let get = |n: &str| m.form.as_ref().and_then(|f| f.get(n));
            let mut r = StatusCode::SEE_OTHER.into_response();
            r.headers_mut().insert(
                axum::http::header::LOCATION,
                axum::http::HeaderValue::from_str(&back_target(&get, &default))
                    .unwrap_or_else(|_| axum::http::HeaderValue::from_static("/users")),
            );
            r
        }
        Err(f) => f.respond(&st, &c),
    }
}

pub async fn disable_api(
    State(st): State<Arc<AdminState>>,
    c: Ctx,
    Path(id): Path<String>,
    Extension(m): Extension<Mutation>,
) -> Response {
    api_action(st, c, id, m, Action::Disable).await
}

pub async fn disable_page(
    State(st): State<Arc<AdminState>>,
    c: Ctx,
    Path(id): Path<String>,
    Extension(m): Extension<Mutation>,
) -> Response {
    page_action(st, c, id, m, Action::Disable).await
}

pub async fn enable_api(
    State(st): State<Arc<AdminState>>,
    c: Ctx,
    Path(id): Path<String>,
    Extension(m): Extension<Mutation>,
) -> Response {
    api_action(st, c, id, m, Action::Enable).await
}

pub async fn enable_page(
    State(st): State<Arc<AdminState>>,
    c: Ctx,
    Path(id): Path<String>,
    Extension(m): Extension<Mutation>,
) -> Response {
    page_action(st, c, id, m, Action::Enable).await
}

pub async fn terminate_sessions_api(
    State(st): State<Arc<AdminState>>,
    c: Ctx,
    Path(id): Path<String>,
    Extension(m): Extension<Mutation>,
) -> Response {
    api_action(st, c, id, m, Action::TerminateSessions).await
}

pub async fn terminate_sessions_page(
    State(st): State<Arc<AdminState>>,
    c: Ctx,
    Path(id): Path<String>,
    Extension(m): Extension<Mutation>,
) -> Response {
    page_action(st, c, id, m, Action::TerminateSessions).await
}

/// Most users one bulk call names.
pub const MAX_BULK: usize = 100;

/// `POST /v1/users/bulk/disable` with `{"ids": ["u_…", …], "reason": "…"}`:
/// up to 100 distinct users, each disabled in its own fenced transaction
/// exactly as `POST /v1/users/{id}/disable` would (its sessions end, its
/// `admin.user_disable` record carries the reason and `bulk_operation`, the
/// call's request id). The answer lists every item with its result:
/// `disabled`, `unchanged` (already disabled) or an error code
/// (`invalid_id`, `not_found`, `self_target`); after a refusal of the actor
/// (`actor_revoked`) or a store failure the remaining items are
/// `not_attempted`. Rate-limited per actor (`users.bulk`).
pub async fn bulk_disable_api(
    State(st): State<Arc<AdminState>>,
    c: Ctx,
    Extension(m): Extension<Mutation>,
) -> Response {
    if let Some(r) = super::reads::limit(&st, &c, super::reads::Op::Bulk) {
        return r;
    }
    let run = async {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Input {
            ids: Vec<String>,
            #[serde(default)]
            #[allow(dead_code)]
            reason: Option<Value>,
        }
        let input: Input = serde_json::from_slice(&m.body)
            .map_err(|_| fail(StatusCode::BAD_REQUEST, "invalid_request"))?;
        if input.ids.is_empty() || input.ids.len() > MAX_BULK {
            return Err(fail(StatusCode::BAD_REQUEST, "invalid_request"));
        }
        let mut seen = std::collections::HashSet::new();
        if !input.ids.iter().all(|id| seen.insert(id.as_str())) {
            return Err(fail(StatusCode::BAD_REQUEST, "duplicate_id"));
        }
        let reason = common::reason_of(&m)?;
        let mut items = Vec::with_capacity(input.ids.len());
        let (mut disabled, mut failed) = (0u32, 0u32);
        let mut halted: Option<&'static str> = None;
        for id in &input.ids {
            if halted.is_some() {
                items.push(json!({"id": id, "result": "not_attempted"}));
                continue;
            }
            match mutate(&st, &c, Action::Disable, id, reason.as_deref(), true).await {
                Ok(Done::Disable {
                    changed,
                    terminated,
                }) => {
                    if changed {
                        disabled += 1;
                    }
                    items.push(json!({
                        "id": id,
                        "result": if changed { "disabled" } else { "unchanged" },
                        "sessions_terminated": terminated,
                    }));
                }
                Ok(_) => unreachable!("disable answers Done::Disable"),
                Err(Fail(status, code)) => {
                    failed += 1;
                    if code == "actor_revoked" || status.is_server_error() {
                        halted = Some(code);
                    }
                    items.push(json!({"id": id, "result": "error", "error": code}));
                }
            }
        }
        Ok::<_, Fail>(api::json(
            StatusCode::OK,
            &json!({
                "bulk_operation": c.req.rid,
                "requested": input.ids.len(),
                "disabled": disabled,
                "failed": failed,
                "halted": halted,
                "items": items,
            }),
        ))
    };
    run.await.unwrap_or_else(|f| f.respond(&st, &c))
}

#[cfg(test)]
mod tests {
    use super::common::*;
    use super::escape_like;

    #[test]
    fn like_wildcards_and_the_escape_are_literal() {
        assert_eq!(escape_like("a%b_c\\d"), "a\\%b\\_c\\\\d");
        assert_eq!(escape_like("plain@x"), "plain@x");
    }

    #[test]
    fn time_is_formatted_in_utc() {
        assert_eq!(time_str(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(time_str(1_800_000_000), "2027-01-15 08:00:00 UTC");
        assert_eq!(time_str(951_782_400), "2000-02-29 00:00:00 UTC");
    }

    #[test]
    fn session_ids_are_checked_by_shape() {
        assert!(valid_session_id("s_abc-1_Z"));
        for bad in [
            "",
            "s_",
            "u_x",
            "s_%00",
            "s_a b",
            "s_a/b",
            &format!("s_{}", "a".repeat(63)),
        ] {
            assert!(!valid_session_id(bad), "{bad}");
        }
    }

    #[test]
    fn forms_return_only_to_server_chosen_paths() {
        let run = |pairs: &'static [(&'static str, &'static str)]| {
            let get = move |n: &str| pairs.iter().find(|(k, _)| *k == n).map(|(_, v)| *v);
            back_target(&get, "/d")
        };
        assert_eq!(run(&[("back", "user"), ("user_id", "u_x")]), "/users/u_x");
        assert_eq!(
            run(&[("back", "session"), ("session_id", "s_1")]),
            "/sessions/s_1"
        );
        assert_eq!(
            run(&[("back", "sessions"), ("user_id", "u_x")]),
            "/sessions?user_id=u_x"
        );
        assert_eq!(run(&[("back", "sessions")]), "/sessions");
        assert_eq!(run(&[("back", "https://evil/")]), "/d");
        assert_eq!(run(&[("back", "user"), ("user_id", "x/../y")]), "/d");
    }
}
