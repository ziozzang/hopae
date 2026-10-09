//! Test-hooks listener (feature `test-hooks`): a loopback-only, unauthenticated
//! control surface for the harness. Never compiled into a release build; the
//! process starts it only when `HOPAE_TEST_HOOKS=<loopback addr>` is set.
//!
//! | Endpoint | Effect |
//! | --- | --- |
//! | `GET /counters` | store calls by method, verify decisions, metrics counters |
//! | `GET /clock`, `POST /clock {"now_ms"}` or `{"advance_ms"}` | read / set / advance the test clock |
//! | `POST /store/stall {"ms"}` or `{"off":true}` | every store call sleeps first |
//! | `POST /commit-gate {"label","hold"}` | hold / release the labelled transaction before commit |
//! | `POST /crash-at {"label"}` (`null` disarms) | abort when execution reaches the label |
//! | `POST /elevate {"session_id"}` | raise a session to AAL2 (gate label `elevate`) |
//! | `GET /events?kind=&limit=` | dump of the events table |
//! | `GET /deliveries?sink=` | dump of `event_deliveries` |

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::{Request, State};
use axum::http::{StatusCode, header};
use axum::response::Response;
use axum::routing::{get, post};
use serde_json::{Value, json};

use crate::crypto::{Clock, TestClock, Timestamp};
use crate::event::types::EventKind;
use crate::session::types::SessionId;
use crate::store::{Events, Store, StoreHooks, types::EventQuery};

/// Supplies the counters that live outside the store (verify decisions,
/// metrics): a JSON object, merged under `metrics` in `GET /counters`.
pub type CounterSource = Arc<dyn Fn() -> Value + Send + Sync>;

pub struct HooksState {
    clock: Arc<TestClock>,
    store_hooks: Arc<StoreHooks>,
    store: Store,
    counters: Mutex<Option<CounterSource>>,
}

impl HooksState {
    pub fn new(clock: Arc<TestClock>, store_hooks: Arc<StoreHooks>, store: Store) -> Self {
        Self {
            clock,
            store_hooks,
            store,
            counters: Mutex::new(None),
        }
    }

    /// Wire the process-wide counters (W1-F's `telemetry::counters`) into `GET /counters`.
    pub fn set_counter_source(&self, source: CounterSource) {
        *self.counters.lock().unwrap_or_else(|p| p.into_inner()) = Some(source);
    }
}

type Shared = Arc<HooksState>;

pub fn router(state: Shared) -> Router {
    Router::new()
        .route("/counters", get(counters))
        .route("/clock", get(clock_get).post(clock_set))
        .route("/store/stall", post(stall))
        .route("/commit-gate", post(gate))
        .route("/crash-at", post(crash_at))
        .route("/elevate", post(elevate))
        .route("/events", get(events))
        .route("/deliveries", get(deliveries))
        .with_state(state)
}

fn reply(status: StatusCode, body: Value) -> Response {
    let mut r = Response::new(Body::from(body.to_string()));
    *r.status_mut() = status;
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/json"),
    );
    r.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    r
}

fn bad(msg: &str) -> Response {
    reply(StatusCode::BAD_REQUEST, json!({"error": msg}))
}

async fn json_body(req: Request) -> Result<Value, Response> {
    let bytes = to_bytes(req.into_body(), 64 * 1024)
        .await
        .map_err(|_| bad("body too large"))?;
    serde_json::from_slice(&bytes).map_err(|_| bad("invalid JSON"))
}

fn query_param(req: &Request, name: &str) -> Option<String> {
    let q = req.uri().query()?;
    url::form_urlencoded::parse(q.as_bytes())
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.into_owned())
}

async fn counters(State(s): State<Shared>, _req: Request) -> Response {
    let source = s.counters.lock().unwrap_or_else(|p| p.into_inner()).clone();
    let metrics = source.map_or_else(|| json!({}), |f| f());
    reply(
        StatusCode::OK,
        json!({
            "store_calls": s.store_hooks.calls(),
            "metrics": metrics,
        }),
    )
}

async fn clock_get(State(s): State<Shared>) -> Response {
    reply(StatusCode::OK, json!({"now_ms": s.clock.now().0}))
}

async fn clock_set(State(s): State<Shared>, req: Request) -> Response {
    let body = match json_body(req).await {
        Ok(b) => b,
        Err(r) => return r,
    };
    if let Some(n) = body.get("now_ms").and_then(Value::as_i64) {
        s.clock.set(Timestamp(n));
    } else if let Some(n) = body.get("advance_ms").and_then(Value::as_u64) {
        s.clock.advance(Duration::from_millis(n));
    } else {
        return bad("expected now_ms or advance_ms");
    }
    reply(StatusCode::OK, json!({"now_ms": s.clock.now().0}))
}

async fn stall(State(s): State<Shared>, req: Request) -> Response {
    let body = match json_body(req).await {
        Ok(b) => b,
        Err(r) => return r,
    };
    if body.get("off").and_then(Value::as_bool) == Some(true) {
        s.store_hooks.set_stall(0);
    } else if let Some(ms) = body.get("ms").and_then(Value::as_u64) {
        s.store_hooks.set_stall(ms.min(60_000));
    } else {
        return bad("expected ms or off");
    }
    reply(StatusCode::OK, json!({"ok": true}))
}

async fn gate(State(s): State<Shared>, req: Request) -> Response {
    let body = match json_body(req).await {
        Ok(b) => b,
        Err(r) => return r,
    };
    let (Some(label), Some(hold)) = (
        body.get("label").and_then(Value::as_str),
        body.get("hold").and_then(Value::as_bool),
    ) else {
        return bad("expected label and hold");
    };
    s.store_hooks.set_gate(label, hold);
    reply(StatusCode::OK, json!({"ok": true}))
}

async fn crash_at(State(s): State<Shared>, req: Request) -> Response {
    let body = match json_body(req).await {
        Ok(b) => b,
        Err(r) => return r,
    };
    s.store_hooks.set_crash_at(
        body.get("label")
            .and_then(Value::as_str)
            .map(str::to_string),
    );
    reply(StatusCode::OK, json!({"ok": true}))
}

async fn elevate(State(s): State<Shared>, req: Request) -> Response {
    let body = match json_body(req).await {
        Ok(b) => b,
        Err(r) => return r,
    };
    let Some(id) = body.get("session_id").and_then(Value::as_str) else {
        return bad("expected session_id");
    };
    match s
        .store
        .elevate_session(&SessionId::new(id), s.clock.now(), vec![])
        .await
    {
        Ok(()) => reply(StatusCode::OK, json!({"ok": true})),
        Err(e) => reply(StatusCode::CONFLICT, json!({"error": e.to_string()})),
    }
}

async fn events(State(s): State<Shared>, req: Request) -> Response {
    let kind = match query_param(&req, "kind") {
        None => None,
        Some(k) => match EventKind::from_name(&k) {
            Some(k) => Some(k),
            None => return bad("unknown kind"),
        },
    };
    let limit = query_param(&req, "limit").and_then(|l| l.parse().ok());
    let q = EventQuery {
        kind,
        limit,
        ..Default::default()
    };
    match s.store.query(q).await {
        Ok(list) => reply(
            StatusCode::OK,
            json!({"events": list.iter().map(|e| e.to_json()).collect::<Vec<_>>()}),
        ),
        Err(e) => reply(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"error": e.to_string()}),
        ),
    }
}

async fn deliveries(State(s): State<Shared>, req: Request) -> Response {
    let sink = query_param(&req, "sink");
    match s.store.dump_deliveries(sink.as_deref()).await {
        Ok(list) => reply(
            StatusCode::OK,
            json!({"deliveries": list.iter().map(|d| json!({
                "sink": d.sink,
                "event_id": d.event_id.as_str(),
                "state": d.state,
                "attempts": d.attempts,
                "next_attempt_at": d.next_attempt_at.secs(),
                "last_error": d.last_error,
                "updated_at": d.updated_at.secs(),
            })).collect::<Vec<_>>()}),
        ),
        Err(e) => reply(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"error": e.to_string()}),
        ),
    }
}
