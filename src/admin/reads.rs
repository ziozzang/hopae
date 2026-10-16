//! Helpers of the audited administrative reads (the subject directory and the
//! authentication explain API): the JSON request rule, the per-actor rate
//! limit, the `admin.read` audit record, privacy masking and the sources the
//! reads draw on. Nothing here writes state other than the audit record.
//!
//! These reads are `POST` with a JSON body (a batch or a structured query)
//! but change nothing, so the listener's mutation guard does not run for
//! them; [`json_body`] applies the same JSON API rule (`application/json`,
//! `x-hopae-admin-request: 1`, same-origin `Origin`/`sec-fetch-site`), which a
//! cross-site form or a simple request can never satisfy.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::Response;
use bytes::Bytes;
use sha2::{Digest as _, Sha256};

use super::users::common::{self, Fail};
use super::{AdminState, Ctx, api, csrf};
use crate::event::types::{EventBuilder, EventKind, Outcome};

/// The read families, each with its own bucket per actor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Op {
    Resolve,
    Search,
    Lifecycle,
    Explain,
}

impl Op {
    /// The `purpose` attribute of the audit record.
    pub fn purpose(self) -> &'static str {
        match self {
            Op::Resolve => "subjects.resolve",
            Op::Search => "subjects.search",
            Op::Lifecycle => "subjects.lifecycle",
            Op::Explain => "explain.authentication",
        }
    }

    /// `(burst, refill per second)` of the per-actor token bucket.
    pub fn budget(self) -> (f64, f64) {
        match self {
            Op::Resolve => (60.0, 1.0),
            Op::Search => (60.0, 1.0),
            Op::Lifecycle => (120.0, 2.0),
            Op::Explain => (30.0, 0.5),
        }
    }
}

/// Most actors tracked per listener before idle (full) buckets are dropped.
const MAX_ACTORS: usize = 4096;

struct Bucket {
    tokens: f64,
    at: Instant,
}

type Buckets = HashMap<([u8; 8], String, Op), Bucket>;

fn buckets() -> &'static Mutex<Buckets> {
    static B: OnceLock<Mutex<Buckets>> = OnceLock::new();
    B.get_or_init(|| Mutex::new(HashMap::new()))
}

/// The actor a limit and an audit record are kept for: the Hangang console
/// actor when the request was delegated, else the signed-in administrator.
pub fn actor_key(c: &Ctx) -> String {
    match &c.delegated_actor {
        Some(a) => format!("hangang:{}", a.id),
        None => c.principal.user_id.to_string(),
    }
}

/// Take one token of `op` for the actor; `Err(retry_after)` when empty.
fn take(listener: [u8; 8], actor: String, op: Op, now: Instant) -> Result<(), Duration> {
    let (burst, rate) = op.budget();
    let mut map = buckets().lock().unwrap_or_else(|p| p.into_inner());
    if map.len() >= MAX_ACTORS && !map.contains_key(&(listener, actor.clone(), op)) {
        // Drop buckets that have refilled completely: they carry no state.
        map.retain(|(_, _, o), b| {
            let (burst, rate) = o.budget();
            b.tokens + now.saturating_duration_since(b.at).as_secs_f64() * rate < burst
        });
        if map.len() >= MAX_ACTORS {
            return Err(Duration::from_secs(1));
        }
    }
    let b = map.entry((listener, actor, op)).or_insert(Bucket {
        tokens: burst,
        at: now,
    });
    b.tokens = (b.tokens + now.saturating_duration_since(b.at).as_secs_f64() * rate).min(burst);
    b.at = now;
    if b.tokens >= 1.0 {
        b.tokens -= 1.0;
        Ok(())
    } else {
        Err(Duration::from_secs_f64(
            ((1.0 - b.tokens) / rate).ceil().max(1.0),
        ))
    }
}

/// `429 rate_limited` with `retry-after` when the actor's bucket is empty;
/// `None` when the read may proceed.
pub fn limit(st: &AdminState, c: &Ctx, op: Op) -> Option<Response> {
    let mut listener = [0u8; 8];
    listener.copy_from_slice(&st.key[..8]);
    take(listener, actor_key(c), op, Instant::now()).err().map(|wait| {
        tracing::warn!(request_id = %c.req.rid, purpose = op.purpose(), "administrative read rate limit reached");
        let mut r = api::json_error(StatusCode::TOO_MANY_REQUESTS, "rate_limited");
        if let Ok(v) = HeaderValue::from_str(&wait.as_secs().to_string()) {
            r.headers_mut().insert(header::RETRY_AFTER, v);
        }
        r
    })
}

/// The JSON body of an audited read, under the JSON API rule.
pub async fn json_body(
    st: &AdminState,
    c: &Ctx,
    headers: &HeaderMap,
    body: Body,
) -> Result<Bytes, Response> {
    csrf::guard_json(st, c, headers, body).await
}

/// `400 invalid_request`.
pub fn invalid() -> Fail {
    Fail(StatusCode::BAD_REQUEST, "invalid_request")
}

/// Lowercase hex SHA-256 of a request body, the audit record's query digest.
pub fn digest(bytes: &[u8]) -> String {
    data_encoding::HEXLOWER.encode(&Sha256::digest(bytes))
}

/// The audit record of a read, written before the answer leaves. A read whose
/// record cannot be written is refused (`503 audit_unavailable`): an
/// unaudited disclosure never happens.
pub async fn audit(
    st: &AdminState,
    c: &Ctx,
    op: Op,
    query: &[u8],
    fill: impl FnOnce(EventBuilder) -> EventBuilder,
) -> Result<(), Fail> {
    let ev = fill(
        common::admin_event(st, c, EventKind::AdminRead, Outcome::Success)
            .attr("purpose", op.purpose())
            .attr("endpoint", c.req.pattern)
            .attr("query_sha256", digest(query)),
    )
    .build();
    match st
        .events
        .append_required_within(vec![ev], api::deadline(st))
        .await
    {
        Ok(()) => {
            common::count_event(EventKind::AdminRead, Outcome::Success);
            Ok(())
        }
        Err(e) => {
            tracing::error!(request_id = %c.req.rid, error = %e, "admin.read could not be recorded");
            Err(Fail(StatusCode::SERVICE_UNAVAILABLE, "audit_unavailable"))
        }
    }
}

/// How much of a person's contact data a read discloses.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Privacy {
    /// Display name and a masked primary email (default).
    #[default]
    Standard,
    /// Display name only; no email in any form.
    Strict,
}

impl Privacy {
    pub fn as_str(self) -> &'static str {
        match self {
            Privacy::Standard => "standard",
            Privacy::Strict => "strict",
        }
    }

    /// The profile a read answers with: the requested one, raised to the
    /// operator's floor (`admin.directory_privacy`). A request can make the
    /// answer stricter, never less strict than the floor.
    pub fn at_least(self, floor: Privacy) -> Privacy {
        match (self, floor) {
            (Privacy::Strict, _) | (_, Privacy::Strict) => Privacy::Strict,
            _ => Privacy::Standard,
        }
    }

    pub fn email(self, email: Option<&str>) -> Option<String> {
        match self {
            Privacy::Standard => email.map(mask_email),
            Privacy::Strict => None,
        }
    }
}

/// `alice@example.test` → `a***@example.test`: the first character of the
/// local part and the whole domain; a value without `@` is fully masked.
pub fn mask_email(email: &str) -> String {
    match email.rsplit_once('@') {
        Some((local, domain)) if !local.is_empty() && !domain.is_empty() => {
            let first = local.chars().next().map(String::from).unwrap_or_default();
            format!("{first}***@{domain}")
        }
        _ => "***".to_string(),
    }
}

/// The receipt issuer under which Human subjects are derived, when Human
/// receipts are configured (the same condition as the user pages).
pub fn human_issuer(st: &AdminState) -> Option<String> {
    st.profile_config
        .receipt_issuer
        .as_ref()
        .filter(|issuer| issuer.human_receipts.is_some())
        .map(|issuer| issuer.issuer_ref.clone())
}

/// The live service authentication snapshot (the one the gateway reads).
pub fn service_snapshot(
    st: &AdminState,
) -> Option<std::sync::Arc<crate::auth_gateway::authority::Snapshot>> {
    let authority = st.profile_authority.as_ref()?;
    let guard = authority.lock().ok()?;
    Some(guard.snapshot())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn email_masking_keeps_the_first_character_and_the_domain() {
        assert_eq!(mask_email("alice@example.test"), "a***@example.test");
        assert_eq!(mask_email("b@example.test"), "b***@example.test");
        assert_eq!(mask_email("한글@example.test"), "한***@example.test");
        assert_eq!(mask_email("no-at-sign"), "***");
        assert_eq!(mask_email("@example.test"), "***");
        assert_eq!(Privacy::Strict.email(Some("alice@example.test")), None);
        assert_eq!(
            Privacy::Standard
                .email(Some("alice@example.test"))
                .as_deref(),
            Some("a***@example.test")
        );
    }

    #[test]
    fn the_operator_floor_can_only_be_raised_by_a_request() {
        use Privacy::{Standard, Strict};
        assert_eq!(Standard.at_least(Standard), Standard);
        assert_eq!(Strict.at_least(Standard), Strict);
        assert_eq!(Standard.at_least(Strict), Strict);
        assert_eq!(Strict.at_least(Strict), Strict);
    }

    #[test]
    fn buckets_refill_per_actor_and_operation() {
        let listener = *b"testlstn";
        let t0 = Instant::now();
        let (burst, _) = Op::Explain.budget();
        for _ in 0..burst as usize {
            assert!(take(listener, "u_bucket".into(), Op::Explain, t0).is_ok());
        }
        let wait = take(listener, "u_bucket".into(), Op::Explain, t0).unwrap_err();
        assert!(wait >= Duration::from_secs(1));
        // Another actor and another operation are independent.
        assert!(take(listener, "u_other".into(), Op::Explain, t0).is_ok());
        assert!(take(listener, "u_bucket".into(), Op::Resolve, t0).is_ok());
        // Two seconds refill one explain token.
        assert!(
            take(
                listener,
                "u_bucket".into(),
                Op::Explain,
                t0 + Duration::from_secs(2)
            )
            .is_ok()
        );
    }

    #[test]
    fn route_patterns_name_the_read_endpoints() {
        use crate::admin::auth::{is_mutation, pattern_of};
        for (path, pattern) in [
            ("/v1/subjects/resolve", "/v1/subjects/resolve"),
            ("/v1/subjects/search", "/v1/subjects/search"),
            ("/v1/subjects/lifecycle", "/v1/subjects/lifecycle"),
            (
                "/v1/subjects/lifecycle/snapshot",
                "/v1/subjects/lifecycle/snapshot",
            ),
            ("/v1/explain/authentication", "/v1/explain/authentication"),
            ("/subjects/resolve", "unmatched"),
        ] {
            assert_eq!(pattern_of(path), pattern);
            assert!(!is_mutation(&axum::http::Method::POST, pattern));
        }
    }
}
