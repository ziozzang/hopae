//! Helpers shared by the console's handlers: JSON answers, the store
//! deadline, the actor and its fence policy, query and body reading.

use std::time::Duration;

use axum::body::Body;
use axum::http::{StatusCode, Uri, header};
use axum::response::Response;
use bytes::Bytes;

use super::pages::{self, Extra};
use super::{AdminState, Principal, ReqInfo};
use crate::provider::types::ReauthCapability;
use crate::store::{Actor, ActorPolicy, Deadline};

/// Largest request body the console reads.
pub const MAX_BODY_BYTES: usize = 64 * 1024;
/// Longest query string the console accepts.
pub const MAX_QUERY_BYTES: usize = 4 * 1024;
/// `limit` of a listing: default and maximum.
pub const DEFAULT_LIMIT: usize = 50;
pub const MAX_LIMIT: usize = 200;
/// Clock-skew tolerance of the freshness predicate and the fence.
pub const SKEW: Duration = Duration::from_secs(60);

/// A JSON answer.
pub fn json(status: StatusCode, value: &serde_json::Value) -> Response {
    let mut r = Response::new(Body::from(value.to_string()));
    *r.status_mut() = status;
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/json"),
    );
    r
}

/// `{"error": code}`.
pub fn json_error(status: StatusCode, code: &str) -> Response {
    json(status, &serde_json::json!({ "error": code }))
}

/// An error answer in the shape the request wants: JSON for `/v1/`, a page
/// (inside the layout of the signed-in administrator) otherwise.
pub fn error(
    st: &AdminState,
    req: &ReqInfo,
    principal: &Principal,
    status: StatusCode,
    code: &'static str,
) -> Response {
    if req.api {
        json_error(status, code)
    } else {
        pages::error_page(st, req, principal, status, code)
    }
}

/// An error answer for a request with no signed-in administrator.
pub fn bare_error(req: &ReqInfo, status: StatusCode, code: &'static str) -> Response {
    if req.api {
        json_error(status, code)
    } else {
        pages::denied_page(req, status, code, &Extra::NONE)
    }
}

/// The deadline of one store operation of this request (`admin.query_budget_ms`).
pub fn deadline(st: &AdminState) -> Deadline {
    Deadline::after(st.cfg.query_budget)
}

/// Who performs a mutation.
pub fn actor(p: &Principal) -> Actor {
    Actor {
        user_id: p.user_id.clone(),
        session_id: p.session_id.clone(),
        handle_sha256: p.handle_sha256,
    }
}

/// What the write fence needs besides the actor: the lifetimes and bounds of
/// the configuration snapshot current now, the clock reading, and whether the
/// provider of the actor's session makes the console demand a provider claim.
pub fn actor_policy(st: &AdminState, p: &Principal) -> ActorPolicy {
    let snap = st.snapshot.load();
    // The same authoritative map as verify and callback: a retained database
    // provider the file does not list keeps its stored capability.
    let capability = snap.reauth_capability(&p.provider_id);
    ActorPolicy {
        console_host: st.cfg.host.clone(),
        session: st.cfg.session,
        handle: st.cfg.policy.session,
        max_auth_age: st.cfg.limits.max_auth_age,
        capability_requires_claim: capability == ReauthCapability::MaxAge,
        require_aal: st.cfg.limits.require_aal,
        now: st.clock.now(),
        skew: SKEW,
    }
}

/// Query parameters, first occurrence of each name.
pub struct Query(Vec<(String, String)>);

impl Query {
    pub fn parse(uri: &Uri) -> Query {
        let mut out: Vec<(String, String)> = Vec::new();
        for (k, v) in form_urlencoded::parse(uri.query().unwrap_or("").as_bytes()) {
            if !out.iter().any(|(n, _)| *n == k) {
                out.push((k.into_owned(), v.into_owned()));
            }
        }
        Query(out)
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

/// A filter or `limit` value the console does not accept (`400 invalid_filter`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidFilter;

/// `limit`: 1 to 200, default 50.
pub fn parse_limit(raw: Option<&str>) -> Result<usize, InvalidFilter> {
    let Some(raw) = raw else {
        return Ok(DEFAULT_LIMIT);
    };
    if raw.is_empty() || raw.len() > 6 || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return Err(InvalidFilter);
    }
    match raw.parse::<usize>() {
        Ok(n) if (1..=MAX_LIMIT).contains(&n) => Ok(n),
        _ => Err(InvalidFilter),
    }
}

/// A request body within [`MAX_BODY_BYTES`]; a longer one is `413`.
pub async fn read_body(
    req: &ReqInfo,
    declared: Option<usize>,
    body: Body,
) -> Result<Bytes, Response> {
    let too_large = || bare_error(req, StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large");
    if declared.is_some_and(|n| n > MAX_BODY_BYTES) {
        return Err(too_large());
    }
    axum::body::to_bytes(body, MAX_BODY_BYTES)
        .await
        .map_err(|_| too_large())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limit_is_one_to_two_hundred_with_a_default() {
        assert_eq!(parse_limit(None), Ok(50));
        assert_eq!(parse_limit(Some("1")), Ok(1));
        assert_eq!(parse_limit(Some("200")), Ok(200));
        for bad in ["", "0", "201", "-1", "+5", "5x", "1000000", "٣"] {
            assert_eq!(parse_limit(Some(bad)), Err(InvalidFilter), "{bad}");
        }
    }

    #[test]
    fn query_keeps_the_first_occurrence() {
        let uri: Uri = "/x?a=1&b=%20&a=2".parse().unwrap();
        let q = Query::parse(&uri);
        assert_eq!(q.get("a"), Some("1"));
        assert_eq!(q.get("b"), Some(" "));
        assert_eq!(q.get("c"), None);
    }
}
