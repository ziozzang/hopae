//! Test-hooks listener (feature `test-hooks`): a loopback-only, unauthenticated
//! control surface for the harness. Never compiled into a release build; the
//! process starts it only when `HOPAE_TEST_HOOKS=<loopback addr>` is set.
//!
//! | Endpoint | Effect |
//! | --- | --- |
//! | `GET /counters` | store calls by method, verify decisions, metrics counters |
//! | `GET /clock`, `POST /clock {"now_ms"}` or `{"advance_ms"}` | read / set / advance the test clock |
//! | `POST /store/stall {"ms"}` or `{"off":true}` | every store call sleeps first; with `"target":"diagnostics"` only the diagnostic batch writer does |
//! | `POST /commit-gate {"label","hold"}` | hold / release the labelled transaction before commit |
//! | `POST /crash-at {"label"}` (`null` disarms) | abort when execution reaches the label |
//! | `POST /elevate {"session_id"}` | raise a session to AAL2 (gate label `elevate`) |
//! | `GET /events?kind=&limit=` | dump of the events table |
//! | `GET /deliveries?sink=` | dump of `event_deliveries` |
//! | `POST /bulk/users {n}` | insert `n` users (ids `u_blk…`, created now) |
//! | `POST /bulk/sessions {user_id, n}` | insert `n` live sessions for a user |
//! | `POST /bulk/events {n, hours}` | insert `n` events spread over the last `hours` hours |
//! | `POST /sessions/legacy {user_id, host?}` | insert a session with `auth_time_source = hopae_completion` (and, with `host`, a handle: the answer carries its cookie value) |
//! | `GET /explain?query=users\|sessions\|events&index=&cursor=<key>:<id>&stats=1` | the plan lines of a listing's window statement and, with `stats=1`, its `VM_STEP`, `FULLSCAN_STEP` and `SORT` |
//! | `GET /grants` | dump of `admin_grants`, tombstones included |
//! | `POST /store/slow_scan {ms}` | slow every interruptible scan and loop statement down |
//! | `POST /store/hold_write_lock {ms}` | a second connection holds the write lock for `ms` |
//! | `GET /store/last_deadline` | the deadline the last store job observed |

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
        .route("/bulk/users", post(bulk_users))
        .route("/bulk/sessions", post(bulk_sessions))
        .route("/bulk/events", post(bulk_events))
        .route("/sessions/legacy", post(legacy_session))
        .route("/explain", get(explain))
        .route("/grants", get(grants))
        .route("/store/slow_scan", post(slow_scan))
        .route("/store/hold_write_lock", post(hold_write_lock))
        .route("/store/last_deadline", get(last_deadline))
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
    let diagnostics = body.get("target").and_then(Value::as_str) == Some("diagnostics");
    let set = |ms: u64| {
        if diagnostics {
            s.store_hooks.set_diag_stall(ms);
        } else {
            s.store_hooks.set_stall(ms);
        }
    };
    if body.get("off").and_then(Value::as_bool) == Some(true) {
        set(0);
    } else if let Some(ms) = body.get("ms").and_then(Value::as_u64) {
        set(ms.min(60_000));
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

// ---- management console support (ADR-0016) ----------------------------------

/// Run blocking SQL on the store's utility connection.
async fn with_conn<T: Send + 'static>(
    s: &Shared,
    f: impl FnOnce(&rusqlite::Connection) -> rusqlite::Result<T> + Send + 'static,
) -> Result<T, Response> {
    let store = s.store.clone();
    tokio::task::spawn_blocking(move || f(&store.conn()))
        .await
        .map_err(|_| {
            reply(
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({"error": "task failed"}),
            )
        })?
        .map_err(|e| {
            reply(
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({"error": e.to_string()}),
            )
        })
}

/// `n` from the body, between 1 and 1,000,000.
fn count_of(body: &Value) -> Option<i64> {
    body.get("n")
        .and_then(Value::as_i64)
        .filter(|n| (1..=1_000_000).contains(n))
}

async fn bulk_users(State(s): State<Shared>, req: Request) -> Response {
    let body = match json_body(req).await {
        Ok(b) => b,
        Err(r) => return r,
    };
    let Some(n) = count_of(&body) else {
        return bad("expected n between 1 and 1000000");
    };
    let now = s.clock.now().secs();
    match with_conn(&s, move |c| {
        let base: i64 = c.query_row("SELECT COUNT(*) FROM users WHERE user_id LIKE 'u_blk%'", [], |r| r.get(0))?;
        c.execute(
            "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < ?1)
             INSERT INTO users (user_id, primary_email, email_verified, display_name, status, created_at, updated_at)
             SELECT printf('u_blk%09d', ?3 + i), printf('blk%d@bulk.test', ?3 + i), 1, printf('Bulk %d', ?3 + i), 'active', ?2, ?2 FROM n",
            rusqlite::params![n, now, base],
        )
    })
    .await
    {
        Ok(inserted) => reply(StatusCode::OK, json!({"inserted": inserted})),
        Err(r) => r,
    }
}

async fn bulk_sessions(State(s): State<Shared>, req: Request) -> Response {
    let body = match json_body(req).await {
        Ok(b) => b,
        Err(r) => return r,
    };
    let (Some(user), Some(n)) = (
        body.get("user_id")
            .and_then(Value::as_str)
            .map(str::to_string),
        count_of(&body),
    ) else {
        return bad("expected user_id and n");
    };
    let now = s.clock.now().secs();
    match with_conn(&s, move |c| {
        let base: i64 = c.query_row("SELECT COUNT(*) FROM sessions WHERE session_id LIKE 's_blk%'", [], |r| r.get(0))?;
        c.execute(
            "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < ?1)
             INSERT INTO sessions (session_id, user_id, provider_id, auth_time, aal, authz_version, cred_gen, bound_ip, created_at, last_seen_at, absolute_expires_at, authz_version_at_auth)
             SELECT printf('s_blk%09d', ?4 + i), ?2, 'mock', ?3, 1, (SELECT authz_version FROM users WHERE user_id = ?2), 1, '192.0.2.1', ?3, ?3, ?3 + 2592000, (SELECT authz_version FROM users WHERE user_id = ?2) FROM n",
            rusqlite::params![n, user, now, base],
        )
    })
    .await
    {
        Ok(inserted) => reply(StatusCode::OK, json!({"inserted": inserted})),
        Err(r) => r,
    }
}

async fn bulk_events(State(s): State<Shared>, req: Request) -> Response {
    let body = match json_body(req).await {
        Ok(b) => b,
        Err(r) => return r,
    };
    let Some(n) = count_of(&body) else {
        return bad("expected n between 1 and 1000000");
    };
    let hours = body
        .get("hours")
        .and_then(Value::as_f64)
        .filter(|h| *h > 0.0 && *h <= 87_600.0)
        .unwrap_or(24.0);
    let now = s.clock.now().0 as f64 / 1000.0;
    match with_conn(&s, move |c| {
        let base: i64 = c.query_row("SELECT COUNT(*) FROM events WHERE event_id LIKE 'e_blk%'", [], |r| r.get(0))?;
        c.execute(
            "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < ?1)
             INSERT INTO events (event_id, at, kind, outcome, request_id, attrs)
             SELECT printf('e_blk%020d', ?4 + i), ?2 - (?3 * 3600.0) * (?1 - i) / ?1, 'login.started', 'info', 'bulk', '{}' FROM n",
            rusqlite::params![n, now, hours, base],
        )
    })
    .await
    {
        Ok(inserted) => reply(StatusCode::OK, json!({"inserted": inserted})),
        Err(r) => r,
    }
}

async fn legacy_session(State(s): State<Shared>, req: Request) -> Response {
    let body = match json_body(req).await {
        Ok(b) => b,
        Err(r) => return r,
    };
    let Some(user) = body
        .get("user_id")
        .and_then(Value::as_str)
        .map(str::to_string)
    else {
        return bad("expected user_id");
    };
    let host = body.get("host").and_then(Value::as_str).map(str::to_string);
    let now = s.clock.now().secs();
    let id = format!("s_legacy{}", s.clock.now().0);
    let handle = host
        .as_ref()
        .map(|_| crate::crypto::handle_value(&crate::crypto::OsRng));
    let digest = handle.as_ref().map(|h| h.digest());
    let sid = id.clone();
    match with_conn(&s, move |c| {
        let n = c.execute(
            "INSERT INTO sessions (session_id, user_id, provider_id, auth_time, aal, authz_version, cred_gen, bound_ip, created_at, last_seen_at, absolute_expires_at, authz_version_at_auth, auth_time_source)
             SELECT ?1, user_id, 'mock', ?3, 1, authz_version, 1, '192.0.2.10', ?3, ?3, ?3 + 2592000, authz_version, 'hopae_completion' FROM users WHERE user_id = ?2",
            rusqlite::params![sid, user, now],
        )?;
        if n == 0 {
            return Err(rusqlite::Error::QueryReturnedNoRows);
        }
        if let (Some(h), Some(d)) = (&host, &digest) {
            c.execute(
                "INSERT INTO session_handles (handle_sha256, session_id, host, issued_aal, created_at, last_seen_at, absolute_expires_at) VALUES (?1, ?2, ?3, 1, ?4, ?4, ?4 + 604800)",
                rusqlite::params![&d.0[..], sid, h, now],
            )?;
        }
        Ok(())
    })
    .await
    {
        Ok(()) => reply(
            StatusCode::OK,
            json!({"session_id": id, "handle": handle.as_ref().map(|h| h.expose())}),
        ),
        Err(r) => r,
    }
}

async fn explain(State(s): State<Shared>, req: Request) -> Response {
    let shape = match (
        query_param(&req, "query").as_deref(),
        query_param(&req, "index").as_deref(),
    ) {
        (Some("users"), _) => crate::store::WindowShape::Users,
        (Some("sessions"), _) => crate::store::WindowShape::Sessions {
            by_user: query_param(&req, "by_user").is_some(),
        },
        (Some("events"), idx) => crate::store::WindowShape::Events(match idx {
            None | Some("time") => crate::store::EventsIndex::Time,
            Some("user") => crate::store::EventsIndex::User,
            Some("session") => crate::store::EventsIndex::Session,
            Some("ip") => crate::store::EventsIndex::Ip,
            Some("kind") => crate::store::EventsIndex::Kind,
            Some(_) => return bad("unknown index"),
        }),
        _ => return bad("expected query=users|sessions|events"),
    };
    // `cursor=<key>:<id>`; the key is seconds (milliseconds for events).
    let cursor = match query_param(&req, "cursor") {
        None => None,
        Some(c) => match c
            .split_once(':')
            .and_then(|(k, id)| Some((k.parse::<i64>().ok()?, id.to_string())))
        {
            Some(parsed) => Some(parsed),
            None => return bad("cursor must be <key>:<id>"),
        },
    };
    let stats = query_param(&req, "stats").as_deref() == Some("1");
    let store = s.store.clone();
    match tokio::task::spawn_blocking(move || store.explain_window(shape, cursor, stats)).await {
        Ok(Ok(v)) => reply(StatusCode::OK, v),
        Ok(Err(e)) => reply(
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({"error": e.to_string()}),
        ),
        Err(_) => reply(
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({"error": "task failed"}),
        ),
    }
}

async fn grants(State(s): State<Shared>) -> Response {
    match with_conn(&s, |c| {
        let mut st = c.prepare("SELECT user_id, role, managed_by, source_email, granted_at, granted_by, revoked_at, revoked_by, note FROM admin_grants ORDER BY granted_at, user_id")?;
        let rows = st
            .query_map([], |r| {
                Ok(json!({
                    "user_id": r.get::<_, String>(0)?, "role": r.get::<_, String>(1)?, "managed_by": r.get::<_, String>(2)?,
                    "source_email": r.get::<_, Option<String>>(3)?, "granted_at": r.get::<_, i64>(4)?, "granted_by": r.get::<_, String>(5)?,
                    "revoked_at": r.get::<_, Option<i64>>(6)?, "revoked_by": r.get::<_, Option<String>>(7)?, "note": r.get::<_, Option<String>>(8)?,
                }))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    })
    .await
    {
        Ok(rows) => reply(StatusCode::OK, json!({"grants": rows})),
        Err(r) => r,
    }
}

async fn slow_scan(State(s): State<Shared>, req: Request) -> Response {
    let body = match json_body(req).await {
        Ok(b) => b,
        Err(r) => return r,
    };
    if body.get("off").and_then(Value::as_bool) == Some(true) {
        s.store_hooks.set_slow_scan(0);
    } else if let Some(ms) = body.get("ms").and_then(Value::as_u64) {
        s.store_hooks.set_slow_scan(ms.min(10_000));
    } else {
        return bad("expected ms or off");
    }
    reply(StatusCode::OK, json!({"ok": true}))
}

async fn hold_write_lock(State(s): State<Shared>, req: Request) -> Response {
    let body = match json_body(req).await {
        Ok(b) => b,
        Err(r) => return r,
    };
    let Some(ms) = body.get("ms").and_then(Value::as_u64) else {
        return bad("expected ms");
    };
    let store = s.store.clone();
    match tokio::task::spawn_blocking(move || store.hold_write_lock(ms.min(60_000))).await {
        Ok(Ok(())) => reply(StatusCode::OK, json!({"ok": true})),
        _ => reply(
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({"error": "cannot hold the write lock"}),
        ),
    }
}

async fn last_deadline(State(s): State<Shared>) -> Response {
    let now = std::time::Instant::now();
    let v = match s.store_hooks.last_deadline() {
        None => json!({"seen": false}),
        Some(None) => json!({"seen": true, "deadline": false}),
        Some(Some(d)) => json!({
            "seen": true,
            "deadline": true,
            "remaining_ms": i128::try_from(d.saturating_duration_since(now).as_millis()).unwrap_or(0),
            "passed": d <= now,
        }),
    };
    reply(StatusCode::OK, v)
}
