//! `/events` and `/v1/events` handlers (W1-B): the login history and audit
//! trail, newest first, one indexed window per request. The helpers shared
//! with the other W1-B files are in [`super::users::common`].

// A refusal is an HTTP response built once and returned; boxing it would only add noise.

use std::net::IpAddr;
use std::sync::Arc;

use askama::Template;
use axum::extract::State;
use axum::http::{StatusCode, Uri};
use axum::response::Response;
use serde_json::{Value, json};

use crate::config::valid_user_id;
use crate::crypto::Timestamp;
use crate::event::types::{Event, EventKind, Outcome};
use crate::identity::types::UserId;
use crate::session::types::SessionId;
use crate::store::types::{Cursor, EventsQuery};

use super::api::{self, Query};
use super::pages::{self, Chrome};
use super::users::common::{
    self, Fail, cursor_json, cursor_of, invalid_filter, limit_of, next_url, store_failure,
    time_str, valid_session_id,
};
use super::{AdminState, Ctx};

/// One event as a table row. Attributes are `key: value` text, never markup.
pub(super) struct EventRow {
    pub id: String,
    pub at: String,
    pub kind: String,
    pub outcome: String,
    pub reason: String,
    pub user_id: String,
    pub session_id: String,
    pub app: String,
    pub client_ip: String,
    pub ua_prefix: String,
    pub attrs: Vec<(String, String)>,
    /// `attrs.actor` when it names a user (linked to its page).
    pub actor: String,
}

pub(super) fn event_rows(items: &[Event]) -> Vec<EventRow> {
    items.iter().map(row).collect()
}

fn row(e: &Event) -> EventRow {
    let attrs: Vec<(String, String)> = e
        .attrs
        .iter()
        .map(|(k, v)| {
            let text = match v {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            (k.clone(), text)
        })
        .collect();
    let actor = e
        .attrs
        .get("actor")
        .and_then(Value::as_str)
        .filter(|a| valid_user_id(a))
        .unwrap_or_default()
        .to_string();
    EventRow {
        id: e.event_id.to_string(),
        at: time_str(e.at.secs()),
        kind: e.kind.name().to_string(),
        outcome: e.outcome.as_str().to_string(),
        reason: e.reason.map(|r| r.0.to_string()).unwrap_or_default(),
        user_id: e
            .user_id
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_default(),
        session_id: e
            .session_id
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_default(),
        app: e
            .app_id
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_default(),
        client_ip: e.client_ip.map(|i| i.to_string()).unwrap_or_default(),
        ua_prefix: e.ua_prefix.clone().unwrap_or_default(),
        attrs,
        actor,
    }
}

#[derive(Template)]
#[template(path = "admin/events.html")]
struct EventsPage<'a> {
    c: &'a Chrome<'a>,
    kind: String,
    outcome: String,
    user_id: String,
    session_id: String,
    client_ip: String,
    since: String,
    until: String,
    events: Vec<EventRow>,
    next: Option<String>,
}

/// The validated filters, with the text to echo back into the page's form.
struct Params {
    query: EventsQuery,
    echo: Vec<(&'static str, String)>,
}

fn secs_param(q: &Query, name: &str) -> Result<Option<Timestamp>, Fail> {
    match q.get(name) {
        None | Some("") => Ok(None),
        Some(v) => {
            if v.len() > 12 || !v.bytes().all(|b| b.is_ascii_digit()) {
                return Err(invalid_filter());
            }
            let n: i64 = v.parse().map_err(|_| invalid_filter())?;
            Ok(Some(Timestamp::from_secs(n)))
        }
    }
}

fn params(st: &AdminState, q: &Query) -> Result<Params, Fail> {
    let text = |name: &str| q.get(name).filter(|v| !v.is_empty()).map(str::to_string);
    let kind = match text("kind") {
        None => None,
        Some(v) => Some(EventKind::from_name(&v).ok_or_else(invalid_filter)?),
    };
    let outcome = match text("outcome") {
        None => None,
        Some(v) => Some(Outcome::parse(&v).ok_or_else(invalid_filter)?),
    };
    let user_id = match text("user_id") {
        None => None,
        Some(v) if valid_user_id(&v) => Some(UserId::new(v)),
        Some(_) => return Err(invalid_filter()),
    };
    let session_id = match text("session_id") {
        None => None,
        Some(v) if valid_session_id(&v) => Some(SessionId::new(v)),
        Some(_) => return Err(invalid_filter()),
    };
    // One exact address; an IPv4-mapped IPv6 address is the IPv4 address.
    let client_ip = match text("client_ip") {
        None => None,
        Some(v) => Some(
            v.parse::<IpAddr>()
                .map_err(|_| invalid_filter())?
                .to_canonical(),
        ),
    };
    // A kind prefix (`factor.`, `admin.user_`): lowercase letters, digits, `_` and `.`.
    let kind_prefix = match text("kind_prefix") {
        None => None,
        Some(v)
            if v.len() <= 64
                && v.bytes().all(|b| {
                    b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'.'
                }) =>
        {
            Some(v)
        }
        Some(_) => return Err(invalid_filter()),
    };
    let (since, until) = (secs_param(q, "since")?, secs_param(q, "until")?);
    if let (Some(s), Some(u)) = (since, until)
        && s > u
    {
        return Err(invalid_filter());
    }
    let limit = limit_of(q)?;
    let cursor: Option<Cursor> = cursor_of(st, q)?;
    let echo = vec![
        (
            "kind",
            kind.map(|k| k.name().to_string()).unwrap_or_default(),
        ),
        (
            "outcome",
            outcome.map(|o| o.as_str().to_string()).unwrap_or_default(),
        ),
        (
            "user_id",
            user_id
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_default(),
        ),
        (
            "session_id",
            session_id
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_default(),
        ),
        (
            "client_ip",
            client_ip.map(|i| i.to_string()).unwrap_or_default(),
        ),
        ("kind_prefix", kind_prefix.clone().unwrap_or_default()),
        (
            "since",
            since.map(|t| t.secs().to_string()).unwrap_or_default(),
        ),
        (
            "until",
            until.map(|t| t.secs().to_string()).unwrap_or_default(),
        ),
    ];
    Ok(Params {
        query: EventsQuery {
            kind,
            outcome,
            user_id,
            session_id,
            client_ip,
            kind_prefix,
            since,
            until,
            limit,
            cursor,
        },
        echo,
    })
}

async fn load(
    st: &AdminState,
    c: &Ctx,
    q: EventsQuery,
) -> Result<crate::store::types::Page<Event>, Fail> {
    let page = st
        .events
        .query_page(q, api::deadline(st))
        .await
        .map_err(|e| store_failure(c, "events", &e))?;
    common::examined("events", page.examined);
    Ok(page)
}

pub async fn list_api(State(st): State<Arc<AdminState>>, c: Ctx, uri: Uri) -> Response {
    let run = async {
        let p = params(&st, &Query::parse(&uri))?;
        let page = load(&st, &c, p.query).await?;
        Ok::<_, Fail>(api::json(
            StatusCode::OK,
            &json!({
                "items": page.items.iter().map(Event::to_json).collect::<Vec<_>>(),
                "next_cursor": cursor_json(&st, &page.next),
            }),
        ))
    };
    run.await.unwrap_or_else(|f| f.respond(&st, &c))
}

pub async fn list_page(State(st): State<Arc<AdminState>>, c: Ctx, uri: Uri) -> Response {
    let run = async {
        let p = params(&st, &Query::parse(&uri))?;
        let page = load(&st, &c, p.query).await?;
        let next = next_url(&st, "/events", &p.echo, &page.next);
        let echo = |name: &str| {
            p.echo
                .iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| v.clone())
                .unwrap_or_default()
        };
        let chrome = Chrome::signed_in(&st, &c.req, &c.principal, "events");
        Ok::<_, Fail>(pages::render(
            StatusCode::OK,
            &EventsPage {
                c: &chrome,
                kind: echo("kind"),
                outcome: echo("outcome"),
                user_id: echo("user_id"),
                session_id: echo("session_id"),
                client_ip: echo("client_ip"),
                since: echo("since"),
                until: echo("until"),
                events: event_rows(&page.items),
                next,
            },
        ))
    };
    run.await.unwrap_or_else(|f| f.respond(&st, &c))
}
