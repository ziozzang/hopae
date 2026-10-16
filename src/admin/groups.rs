//! The groups API of the admin listener (ADR-0019, Hangang ADR 0021).
//!
//! Reads (any granted role, audited as `admin.read`, rate-limited per actor):
//!
//! * `POST /v1/groups/search` — groups by creation, filtered, cursor-paged;
//! * `POST /v1/groups/get` — one group and a page of its members;
//! * `POST /v1/subjects/groups` — one person's groups, cursor-paged;
//! * `POST /v1/groups/projection/snapshot` and `/changes` — the signed
//!   membership projection for Pumgye.
//!
//! Writes (the `admin` role; CSRF and the role are checked by the listener;
//! every write carries a `reason` and the group's `expected_revision`):
//!
//! * `POST /v1/groups/create`, `/update`, `/delete`;
//! * `POST /v1/groups/members/add`, `/members/remove`.
//!
//! Only local groups are written here; a provider group answers
//! `409 group_not_local` (its provider's sync is its only writer).

#[allow(unused_imports)]
use crate::store::core::{GroupStore as _, SubjectDirectoryStore as _};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use axum::Extension;
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use serde::Deserialize;
use serde_json::{Value, json};

use super::csrf::Mutation;
use super::reads::{self, Op, Privacy};
use super::subjects::{self, Ref, Sources};
use super::users::common::{Fail, store_failure, write_failure};
use super::{AdminState, Ctx, api, cursor};
use crate::event::types::{EventKind, Outcome};
use crate::groups::{self as g, Source};
use crate::store::sqlite::groups::{Cas, Edit, GroupRow, MemberRow};
use crate::store::{Cursor, StoreError};

/// `limit` of a group listing: default and maximum.
pub const LIST_DEFAULT: usize = 50;
pub const LIST_MAX: usize = 100;
/// Members per page of a group detail: default and maximum.
pub const MEMBERS_DEFAULT: usize = 50;
pub const MEMBERS_MAX: usize = 200;
/// A person's groups per page: default and maximum.
pub const SUBJECT_GROUPS_DEFAULT: usize = 100;
pub const SUBJECT_GROUPS_MAX: usize = 200;
/// Groups attached to each item of `subjects/resolve` with `include_groups`.
pub const RESOLVE_GROUPS: usize = 20;
/// Vocabulary bound of one projection request.
pub const VOCABULARY_MAX: usize = 1024;
/// People per projection snapshot page: default and maximum.
pub const SNAPSHOT_DEFAULT: usize = 200;
pub const SNAPSHOT_MAX: usize = 500;
/// Changes per projection feed page: default and maximum.
pub const CHANGES_DEFAULT: usize = 200;
pub const CHANGES_MAX: usize = 500;

fn parse<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, Fail> {
    serde_json::from_slice(bytes).map_err(|_| reads::invalid())
}

fn no_store(mut r: Response) -> Response {
    r.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    r
}

/// The console view of a group.
pub fn view(row: &GroupRow) -> Value {
    json!({
        "group_id": row.group_id,
        "source": row.source,
        "provider_id": row.provider_id,
        "key": row.external_key,
        "name": row.name,
        "description": row.description,
        "state": row.state,
        "revision": row.revision,
        "members": row.members,
        "created_at": row.created_at,
        "updated_at": row.updated_at,
        "last_seen_at": row.last_seen_at,
        "deleted_at": row.deleted_at,
    })
}

fn membership(m: &MemberRow) -> Value {
    json!({
        "source": m.source,
        "provider_id": m.provider_id,
        "first_seen_at": m.first_seen_at,
        "last_seen_at": m.last_seen_at,
        "expires_at": m.expires_at,
        "removal_pending_at": m.removal_pending_at,
        "added_by": m.added_by,
        "reason": m.reason,
        "stale_at": m.stale_at,
    })
}

/// A group reference without its `grp1:` prefix (cursor ids are `[A-Za-z0-9_-]`).
fn bare(id: &str) -> String {
    id.strip_prefix(g::REF_PREFIX).unwrap_or(id).to_string()
}

fn decode_cursor(st: &AdminState, v: &Option<String>) -> Result<Option<Cursor>, Fail> {
    match v {
        None => Ok(None),
        Some(v) => cursor::decode(&st.key, v)
            .map(Some)
            .map_err(|_| Fail(StatusCode::BAD_REQUEST, "invalid_cursor")),
    }
}

async fn run(
    st: Arc<AdminState>,
    c: Ctx,
    headers: HeaderMap,
    body: Body,
    op: Op,
    f: impl AsyncFnOnce(&AdminState, &Ctx, &[u8]) -> Result<Response, Fail>,
) -> Response {
    if let Some(r) = reads::limit(&st, &c, op) {
        return r;
    }
    let bytes = match reads::json_body(&st, &c, &headers, body).await {
        Ok(b) => b,
        Err(r) => return r,
    };
    no_store(
        f(&st, &c, &bytes)
            .await
            .unwrap_or_else(|fail| fail.respond(&st, &c)),
    )
}

// ---- reads -------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SearchRequest {
    #[serde(default)]
    q: Option<String>,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    provider_id: Option<String>,
    #[serde(default)]
    include_deleted: bool,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    cursor: Option<String>,
}

pub async fn search_api(
    State(st): State<Arc<AdminState>>,
    c: Ctx,
    headers: HeaderMap,
    body: Body,
) -> Response {
    run(st, c, headers, body, Op::Groups, async |st, c, bytes| {
        let req: SearchRequest = parse(bytes)?;
        let q = match req.q.as_deref().map(str::trim) {
            None | Some("") => None,
            Some(q) if q.chars().count() > 128 || q.chars().any(char::is_control) => {
                return Err(reads::invalid());
            }
            Some(q) => Some(q.to_string()),
        };
        let source = match req.source.as_deref() {
            None => None,
            Some(s) => Some(Source::parse(s).ok_or_else(reads::invalid)?),
        };
        if req
            .provider_id
            .as_ref()
            .is_some_and(|p| p.is_empty() || p.len() > 64)
        {
            return Err(reads::invalid());
        }
        let limit = req.limit.unwrap_or(LIST_DEFAULT);
        if !(1..=LIST_MAX).contains(&limit) {
            return Err(reads::invalid());
        }
        let after =
            decode_cursor(st, &req.cursor)?.map(|c| (c.key, format!("{}{}", g::REF_PREFIX, c.id)));
        let (rows, more) = st
            .groups
            .store
            .groups_list(
                q,
                source,
                req.provider_id.clone(),
                req.include_deleted,
                after,
                limit,
                api::deadline(st),
            )
            .await
            .map_err(|e| store_failure(c, "groups", &e))?;
        let next = more.then(|| rows.last()).flatten().map(|r| {
            cursor::encode(
                &st.key,
                &Cursor {
                    key: r.created_at,
                    id: bare(&r.group_id),
                },
            )
        });
        reads::audit(st, c, Op::Groups, bytes, |b| {
            b.attr("count", rows.len()).attr("kind", "search")
        })
        .await?;
        Ok(api::json(
            StatusCode::OK,
            &json!({"items": rows.iter().map(view).collect::<Vec<_>>(), "next_cursor": next}),
        ))
    })
    .await
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GetRequest {
    group_id: String,
    #[serde(default)]
    members_limit: Option<usize>,
    #[serde(default)]
    members_cursor: Option<String>,
    #[serde(default)]
    privacy_profile: Privacy,
}

/// Resolve user IDs to directory items (display data under `privacy`).
async fn people(
    st: &AdminState,
    c: &Ctx,
    users: Vec<String>,
    privacy: Privacy,
) -> Result<(Sources, HashMap<String, subjects::Item>), Fail> {
    let src = Sources::of(st)
        .await
        .map_err(|e| store_failure(c, "groups", &e))?;
    if users.is_empty() {
        return Ok((src, HashMap::new()));
    }
    let (items, _) = subjects::resolve(&src, &users, privacy)
        .await
        .map_err(|e| store_failure(c, "groups", &e))?;
    Ok((src, items.into_iter().map(|i| (i.id.clone(), i)).collect()))
}

pub async fn get_api(
    State(st): State<Arc<AdminState>>,
    c: Ctx,
    headers: HeaderMap,
    body: Body,
) -> Response {
    run(st, c, headers, body, Op::Groups, async |st, c, bytes| {
        let mut req: GetRequest = parse(bytes)?;
        req.privacy_profile = req.privacy_profile.at_least(st.cfg.privacy_floor);
        if !g::valid_ref(&req.group_id) {
            return Err(reads::invalid());
        }
        let limit = req.members_limit.unwrap_or(MEMBERS_DEFAULT);
        if limit > MEMBERS_MAX {
            return Err(reads::invalid());
        }
        let after = decode_cursor(st, &req.members_cursor)?.map(|c| c.id);
        let fail = |e: StoreError| store_failure(c, "groups", &e);
        let Some(group) = st
            .groups
            .store
            .group_get(req.group_id.clone(), api::deadline(st))
            .await
            .map_err(fail)?
        else {
            return Err(Fail(StatusCode::NOT_FOUND, "group_not_found"));
        };
        let (members, more) = if limit == 0 {
            (Vec::new(), group.members > 0)
        } else {
            st.groups
                .store
                .group_members(
                    req.group_id.clone(),
                    after,
                    limit,
                    st.clock.now().secs(),
                    api::deadline(st),
                )
                .await
                .map_err(fail)?
        };
        let ids: Vec<String> = members.iter().map(|m| m.user_id.clone()).collect();
        let (_, items) = people(st, c, ids, req.privacy_profile).await?;
        let next = (more && limit > 0)
            .then(|| members.last())
            .flatten()
            .map(|m| {
                cursor::encode(
                    &st.key,
                    &Cursor {
                        key: 0,
                        id: m.user_id.clone(),
                    },
                )
            });
        let members: Vec<Value> = members
            .iter()
            .map(|m| {
                let mut v = json!({"subject": items.get(&m.user_id)});
                v["membership"] = membership(m);
                v
            })
            .collect();
        reads::audit(st, c, Op::Groups, bytes, |b| {
            b.attr("count", members.len()).attr("kind", "detail")
        })
        .await?;
        Ok(api::json(
            StatusCode::OK,
            &json!({
                "group": view(&group),
                "members": members,
                "next_members_cursor": next,
                "privacy_profile": req.privacy_profile.as_str(),
            }),
        ))
    })
    .await
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SubjectGroupsRequest {
    id: String,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    cursor: Option<String>,
}

/// The user ID behind a user ID or Human subject reference (`Ok(None)`:
/// unknown or not a person).
async fn person(src: &Sources, id: &str) -> Result<Option<String>, StoreError> {
    match subjects::classify(id) {
        Ref::User => Ok(Some(id.to_string())),
        Ref::Human => match &src.issuer {
            Some(issuer) => {
                Ok(
                    subjects::human_users(&src.store, issuer, &[id.to_string()], src.budget)
                        .await?
                        .0
                        .remove(id),
                )
            }
            None => Ok(None),
        },
        _ => Ok(None),
    }
}

pub async fn subject_groups_api(
    State(st): State<Arc<AdminState>>,
    c: Ctx,
    headers: HeaderMap,
    body: Body,
) -> Response {
    run(st, c, headers, body, Op::Groups, async |st, c, bytes| {
        let req: SubjectGroupsRequest = parse(bytes)?;
        if req.id.is_empty() || req.id.len() > subjects::MAX_REF_BYTES {
            return Err(reads::invalid());
        }
        let limit = req.limit.unwrap_or(SUBJECT_GROUPS_DEFAULT);
        if !(1..=SUBJECT_GROUPS_MAX).contains(&limit) {
            return Err(reads::invalid());
        }
        let after = decode_cursor(st, &req.cursor)?.map(|c| format!("{}{}", g::REF_PREFIX, c.id));
        let fail = |e: StoreError| store_failure(c, "groups", &e);
        let src = Sources::of(st).await.map_err(fail)?;
        let user = person(&src, &req.id).await.map_err(fail)?;
        let (rows, more) = match &user {
            None => (Vec::new(), false),
            Some(u) => st
                .groups
                .store
                .groups_of_users(
                    vec![u.clone()],
                    after,
                    limit,
                    st.clock.now().secs(),
                    api::deadline(st),
                )
                .await
                .map_err(fail)?
                .remove(u)
                .unwrap_or_default(),
        };
        let next = more.then(|| rows.last()).flatten().map(|(_, gr)| {
            cursor::encode(
                &st.key,
                &Cursor {
                    key: 0,
                    id: bare(&gr.group_id),
                },
            )
        });
        let items: Vec<Value> = rows
            .iter()
            .map(|(m, gr)| {
                let mut v = view(gr);
                v["membership"] = membership(m);
                v
            })
            .collect();
        reads::audit(st, c, Op::Groups, bytes, |b| {
            b.attr("count", items.len()).attr("kind", "subject")
        })
        .await?;
        Ok(api::json(
            StatusCode::OK,
            &json!({
                "id": req.id,
                "user_id": user,
                "status": if user.is_some() { "resolved" } else { "unknown" },
                "items": items,
                "next_cursor": next,
            }),
        ))
    })
    .await
}

/// Up to [`RESOLVE_GROUPS`] groups of each person, for `subjects/resolve`
/// with `include_groups`.
pub(crate) async fn brief_groups(
    st: &AdminState,
    users: Vec<String>,
) -> Result<BTreeMap<String, (Vec<Value>, bool)>, StoreError> {
    if users.is_empty() {
        return Ok(BTreeMap::new());
    }
    let rows = st
        .groups
        .store
        .groups_of_users(
            users,
            None,
            RESOLVE_GROUPS,
            st.clock.now().secs(),
            api::deadline(st),
        )
        .await?;
    Ok(rows
        .into_iter()
        .map(|(u, (rows, more))| {
            let v = rows
                .iter()
                .map(|(m, gr)| {
                    json!({"group_id": gr.group_id, "name": gr.name, "source": gr.source, "stale": m.stale_at.is_some()})
                })
                .collect();
            (u, (v, more))
        })
        .collect())
}

// ---- writes ------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "op", rename_all = "snake_case")]
enum WriteBody {
    Create {
        key: String,
        name: String,
        #[serde(default)]
        description: Option<String>,
        reason: String,
    },
    Update {
        group_id: String,
        expected_revision: i64,
        #[serde(default)]
        name: Option<String>,
        /// An empty string clears the description.
        #[serde(default)]
        description: Option<String>,
        reason: String,
    },
    Delete {
        group_id: String,
        expected_revision: i64,
        /// Required to delete a group that still has members.
        #[serde(default)]
        force: bool,
        reason: String,
    },
    AddMember {
        group_id: String,
        expected_revision: i64,
        user_id: String,
        /// Unix seconds; at most a year ahead.
        #[serde(default)]
        expires_at: Option<i64>,
        reason: String,
    },
    RemoveMember {
        group_id: String,
        expected_revision: i64,
        user_id: String,
        reason: String,
    },
}

/// Parse the body of a write to `op` (the route names the operation; the
/// body must not name another).
fn write_body(op: &'static str, bytes: &[u8]) -> Result<WriteBody, Fail> {
    let mut v: Value = serde_json::from_slice(bytes).map_err(|_| reads::invalid())?;
    let obj = v.as_object_mut().ok_or_else(reads::invalid)?;
    if obj.contains_key("op") {
        return Err(reads::invalid());
    }
    obj.insert("op".into(), op.into());
    serde_json::from_value(v).map_err(|_| reads::invalid())
}

fn reason_ok(r: &str) -> bool {
    g::valid_text(r, g::MAX_REASON_CHARS)
}

fn conflict(code: &str, current: Option<i64>) -> Response {
    let mut body = json!({"error": code});
    if let Some(r) = current {
        body["current_revision"] = r.into();
    }
    api::json(StatusCode::CONFLICT, &body)
}

async fn write(st: &AdminState, c: &Ctx, op: &'static str, bytes: &[u8]) -> Result<Response, Fail> {
    let body = write_body(op, bytes)?;
    let now = st.clock.now().secs();
    let (edit, reason, kind) = match body {
        WriteBody::Create {
            key,
            name,
            description,
            reason,
        } => {
            if !g::valid_local_key(&key)
                || !g::valid_text(&name, g::MAX_NAME_CHARS)
                || description
                    .as_ref()
                    .is_some_and(|d| !g::valid_text(d, g::MAX_DESCRIPTION_CHARS))
                || !reason_ok(&reason)
            {
                return Err(reads::invalid());
            }
            (
                Edit::Create {
                    group_id: g::new_ref(st.rng.as_ref()),
                    key,
                    name: name.trim().to_string(),
                    description: description.map(|d| d.trim().to_string()),
                },
                reason,
                EventKind::GroupCreated,
            )
        }
        WriteBody::Update {
            group_id,
            expected_revision,
            name,
            description,
            reason,
        } => {
            if !g::valid_ref(&group_id)
                || expected_revision < 1
                || name
                    .as_ref()
                    .is_some_and(|n| !g::valid_text(n, g::MAX_NAME_CHARS))
                || description
                    .as_ref()
                    .is_some_and(|d| !d.is_empty() && !g::valid_text(d, g::MAX_DESCRIPTION_CHARS))
                || (name.is_none() && description.is_none())
                || !reason_ok(&reason)
            {
                return Err(reads::invalid());
            }
            (
                Edit::Update {
                    group_id,
                    expected: expected_revision,
                    name: name.map(|n| n.trim().to_string()),
                    description: description.map(|d| (!d.is_empty()).then(|| d.trim().to_string())),
                },
                reason,
                EventKind::GroupUpdated,
            )
        }
        WriteBody::Delete {
            group_id,
            expected_revision,
            force,
            reason,
        } => {
            if !g::valid_ref(&group_id) || expected_revision < 1 || !reason_ok(&reason) {
                return Err(reads::invalid());
            }
            (
                Edit::Delete {
                    group_id,
                    expected: expected_revision,
                    force,
                },
                reason,
                EventKind::GroupDeleted,
            )
        }
        WriteBody::AddMember {
            group_id,
            expected_revision,
            user_id,
            expires_at,
            reason,
        } => {
            if !g::valid_ref(&group_id)
                || expected_revision < 1
                || !crate::config::valid_user_id(&user_id)
                || expires_at.is_some_and(|e| e <= now || e > now + 366 * 86_400)
                || !reason_ok(&reason)
            {
                return Err(reads::invalid());
            }
            (
                Edit::AddMember {
                    group_id,
                    expected: expected_revision,
                    user_id,
                    expires_at,
                    reason: reason.trim().to_string(),
                },
                reason,
                EventKind::GroupMemberAdded,
            )
        }
        WriteBody::RemoveMember {
            group_id,
            expected_revision,
            user_id,
            reason,
        } => {
            if !g::valid_ref(&group_id)
                || expected_revision < 1
                || !crate::config::valid_user_id(&user_id)
                || !reason_ok(&reason)
            {
                return Err(reads::invalid());
            }
            (
                Edit::RemoveMember {
                    group_id,
                    expected: expected_revision,
                    user_id,
                },
                reason,
                EventKind::GroupMemberRemoved,
            )
        }
    };
    let template = super::users::common::admin_event(st, c, kind, Outcome::Success)
        .attr("note", reason.trim())
        .attr("cause", "admin")
        .build();
    let created = matches!(edit, Edit::Create { .. });
    let res = st
        .groups
        .store
        .groups_admin_edit(
            &api::actor(&c.principal),
            &api::actor_policy(st, &c.principal),
            edit,
            st.groups.policy(),
            template,
            api::deadline(st),
        )
        .await;
    let out = match res {
        Ok(v) => v,
        Err(e) => return Err(write_failure(st, c, "groups", &e).await),
    };
    Ok(match out {
        Cas::Done(row) => {
            crate::telemetry::counters::inc(
                crate::telemetry::counters::ADMIN_MUTATIONS_TOTAL,
                &[("kind", op)],
            );
            api::json(
                if created {
                    StatusCode::CREATED
                } else {
                    StatusCode::OK
                },
                &json!({"group": view(&row)}),
            )
        }
        Cas::NotFound => api::json_error(StatusCode::NOT_FOUND, "group_not_found"),
        Cas::Deleted => api::json_error(StatusCode::GONE, "group_deleted"),
        Cas::NotLocal => conflict("group_not_local", None),
        Cas::Stale(current) => conflict("revision_conflict", Some(current)),
        Cas::Conflict("unknown_user") => api::json_error(StatusCode::NOT_FOUND, "unknown_user"),
        Cas::Conflict(code) => conflict(code, None),
    })
}

async fn mutate(st: Arc<AdminState>, c: Ctx, m: Mutation, op: &'static str) -> Response {
    if let Some(r) = reads::limit(&st, &c, Op::GroupWrite) {
        return r;
    }
    no_store(
        write(&st, &c, op, &m.body)
            .await
            .unwrap_or_else(|f| f.respond(&st, &c)),
    )
}

pub async fn create_api(
    State(st): State<Arc<AdminState>>,
    c: Ctx,
    Extension(m): Extension<Mutation>,
) -> Response {
    mutate(st, c, m, "create").await
}

pub async fn update_api(
    State(st): State<Arc<AdminState>>,
    c: Ctx,
    Extension(m): Extension<Mutation>,
) -> Response {
    mutate(st, c, m, "update").await
}

pub async fn delete_api(
    State(st): State<Arc<AdminState>>,
    c: Ctx,
    Extension(m): Extension<Mutation>,
) -> Response {
    mutate(st, c, m, "delete").await
}

pub async fn add_member_api(
    State(st): State<Arc<AdminState>>,
    c: Ctx,
    Extension(m): Extension<Mutation>,
) -> Response {
    mutate(st, c, m, "add_member").await
}

pub async fn remove_member_api(
    State(st): State<Arc<AdminState>>,
    c: Ctx,
    Extension(m): Extension<Mutation>,
) -> Response {
    mutate(st, c, m, "remove_member").await
}

// ---- the signed membership projection -----------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectionRequest {
    groups: Vec<String>,
    #[serde(default)]
    cursor: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
}

fn vocabulary(groups: &[String]) -> Result<Vec<String>, Fail> {
    if groups.is_empty() || groups.len() > VOCABULARY_MAX || !groups.iter().all(|r| g::valid_ref(r))
    {
        return Err(reads::invalid());
    }
    let mut v = groups.to_vec();
    v.sort();
    v.dedup();
    Ok(v)
}

fn unavailable() -> Fail {
    Fail(StatusCode::SERVICE_UNAVAILABLE, "projection_unavailable")
}

fn expired() -> Fail {
    Fail(StatusCode::GONE, "cursor_expired")
}

/// The fields every signed page starts with.
async fn header(
    st: &AdminState,
    c: &Ctx,
    kind: &str,
    vocab: &[String],
) -> Result<serde_json::Map<String, Value>, Fail> {
    let signer = st.groups.signer.as_ref().ok_or_else(unavailable)?;
    let store = st
        .profile_store
        .admin_human_realm(api::deadline(st))
        .await
        .map_err(|e| store_failure(c, "groups", &e))?
        .unwrap_or_default();
    let h = g::projection::Header {
        kind: kind.into(),
        issuer_ref: signer.issuer_ref.clone(),
        key_epoch: signer.key_epoch,
        audience: signer.audience.clone(),
        store,
        vocabulary_sha256: g::projection::vocabulary_digest(vocab),
        issued_at: st.clock.now().0,
        max_aal: g::projection::MAX_AAL,
    };
    match serde_json::to_value(h) {
        Ok(Value::Object(m)) => Ok(m),
        _ => Err(unavailable()),
    }
}

fn seal(st: &AdminState, payload: serde_json::Map<String, Value>) -> Result<Response, Fail> {
    let signer = st.groups.signer.as_ref().ok_or_else(unavailable)?;
    let env = signer
        .seal(&Value::Object(payload))
        .map_err(|_| unavailable())?;
    let value = serde_json::to_value(env).map_err(|_| unavailable())?;
    Ok(api::json(StatusCode::OK, &value))
}

/// Snapshot cursor: `p1.<watermark>.<user id>`.
fn snapshot_cursor(v: &str) -> Option<(i64, String)> {
    let rest = v.strip_prefix("p1.")?;
    let (w, user) = rest.split_once('.')?;
    let w = (!w.is_empty() && w.len() <= 19 && w.bytes().all(|b| b.is_ascii_digit()))
        .then(|| w.parse().ok())
        .flatten()?;
    crate::config::valid_user_id(user).then(|| (w, user.to_string()))
}

pub async fn projection_snapshot_api(
    State(st): State<Arc<AdminState>>,
    c: Ctx,
    headers: HeaderMap,
    body: Body,
) -> Response {
    run(
        st,
        c,
        headers,
        body,
        Op::Projection,
        async |st, c, bytes| {
            let req: ProjectionRequest = parse(bytes)?;
            let vocab = vocabulary(&req.groups)?;
            let limit = req.limit.unwrap_or(SNAPSHOT_DEFAULT);
            if !(1..=SNAPSHOT_MAX).contains(&limit) {
                return Err(reads::invalid());
            }
            let mut payload = header(st, c, "snapshot", &vocab).await?;
            let fail = |e: StoreError| store_failure(c, "groups", &e);
            // The watermark is taken before the first page: every change after
            // it is in the feed even if the pages miss it.
            let (watermark, after) = match &req.cursor {
                None => (
                    st.groups
                        .store
                        .groups_journal_bounds(api::deadline(st))
                        .await
                        .map_err(fail)?
                        .0,
                    None,
                ),
                Some(v) => {
                    let (w, u) = snapshot_cursor(v)
                        .ok_or(Fail(StatusCode::BAD_REQUEST, "invalid_cursor"))?;
                    // A watermark beyond the journal head is not one this
                    // store issued: the page would attest a position that
                    // never existed.
                    let (head, _) = st
                        .groups
                        .store
                        .groups_journal_bounds(api::deadline(st))
                        .await
                        .map_err(fail)?;
                    if w > head {
                        return Err(expired());
                    }
                    (w, Some(u))
                }
            };
            let (entries, more) = st
                .groups
                .store
                .groups_projection_snapshot(
                    vocab.clone(),
                    after,
                    limit,
                    st.clock.now().secs(),
                    api::deadline(st),
                )
                .await
                .map_err(fail)?;
            let src = Sources::of(st).await.map_err(fail)?;
            let next = more
                .then(|| entries.last())
                .flatten()
                .map(|e| format!("p1.{watermark}.{}", e.user_id));
            let items: Vec<Value> = entries
                .iter()
                .map(|e| {
                    json!({
                        "principal": src.subject_of(&e.user_id),
                        "user_id": e.user_id,
                        "status": e.status,
                        "groups": e.groups,
                    })
                })
                .collect();
            reads::audit(st, c, Op::Projection, bytes, |b| {
                b.attr("count", items.len())
                    .attr("kind", "snapshot")
                    .attr("requested", vocab.len())
            })
            .await?;
            payload.insert("watermark".into(), watermark.into());
            // The request's cursor, so a page cannot stand in for another one.
            payload.insert("cursor".into(), req.cursor.clone().into());
            payload.insert("entries".into(), items.into());
            payload.insert("next_cursor".into(), next.into());
            payload.insert("more".into(), more.into());
            seal(st, payload)
        },
    )
    .await
}

pub async fn projection_changes_api(
    State(st): State<Arc<AdminState>>,
    c: Ctx,
    headers: HeaderMap,
    body: Body,
) -> Response {
    run(
        st,
        c,
        headers,
        body,
        Op::Projection,
        async |st, c, bytes| {
            let req: ProjectionRequest = parse(bytes)?;
            let vocab = vocabulary(&req.groups)?;
            let limit = req.limit.unwrap_or(CHANGES_DEFAULT);
            if !(1..=CHANGES_MAX).contains(&limit) {
                return Err(reads::invalid());
            }
            let after = match &req.cursor {
                None => 0,
                Some(v) => v
                    .strip_prefix("r")
                    .filter(|n| {
                        !n.is_empty() && n.len() <= 19 && n.bytes().all(|b| b.is_ascii_digit())
                    })
                    .and_then(|n| n.parse::<i64>().ok())
                    .ok_or(Fail(StatusCode::BAD_REQUEST, "invalid_cursor"))?,
            };
            let mut payload = header(st, c, "changes", &vocab).await?;
            let fail = |e: StoreError| store_failure(c, "groups", &e);
            let page = st
                .groups
                .store
                .groups_projection_changes(vocab.clone(), after, limit, api::deadline(st))
                .await
                .map_err(fail)?
                .map_err(|_| expired())?;
            let src = Sources::of(st).await.map_err(fail)?;
            let changes: Vec<Value> = page
                .changes
                .iter()
                .map(|r| {
                    json!({
                        "revision": r.revision,
                        "at": r.at,
                        "change": r.change,
                        "group_id": r.group_id,
                        "user_id": r.user_id,
                        "principal": r.user_id.as_deref().and_then(|u| src.subject_of(u)),
                    })
                })
                .collect();
            if !changes.is_empty() {
                reads::audit(st, c, Op::Projection, bytes, |b| {
                    b.attr("count", changes.len())
                        .attr("kind", "changes")
                        .attr("requested", vocab.len())
                })
                .await?;
            }
            payload.insert("from".into(), after.into());
            payload.insert("head".into(), page.head.into());
            payload.insert("changes".into(), changes.into());
            payload.insert("next_cursor".into(), format!("r{}", page.next).into());
            payload.insert("more".into(), (page.next < page.head).into());
            seal(st, payload)
        },
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_bodies_take_their_operation_from_the_route() {
        let b = br#"{"key":"eng","name":"Eng","reason":"setup"}"#;
        assert!(matches!(
            write_body("create", b),
            Ok(WriteBody::Create { .. })
        ));
        assert!(write_body("delete", b).is_err());
        assert!(
            write_body(
                "create",
                br#"{"op":"delete","key":"eng","name":"Eng","reason":"r"}"#
            )
            .is_err()
        );
        assert!(write_body("create", br#"{"key":"eng","name":"Eng"}"#).is_err());
        assert!(
            write_body(
                "create",
                br#"{"key":"eng","name":"Eng","reason":"r","x":1}"#
            )
            .is_err()
        );
        assert!(write_body("create", b"[]").is_err());
    }

    #[test]
    fn snapshot_cursors_parse_strictly() {
        assert_eq!(snapshot_cursor("p1.7.u_abc"), Some((7, "u_abc".into())));
        for bad in [
            "p1..u_abc",
            "p2.7.u_abc",
            "p1.7.",
            "p1.7.alice",
            "p1.-1.u_a",
            "p1.99999999999999999999.u_a",
        ] {
            assert_eq!(snapshot_cursor(bad), None, "{bad}");
        }
    }

    #[test]
    fn vocabularies_are_bounded_and_well_formed() {
        let r = "grp1:0123456789abcdefghjkmnpqrs".to_string();
        assert_eq!(vocabulary(&[r.clone(), r.clone()]).unwrap().len(), 1);
        assert!(vocabulary(&[]).is_err());
        assert!(vocabulary(&["grp1:x".into()]).is_err());
        assert!(vocabulary(&vec![r; VOCABULARY_MAX + 1]).is_err());
    }
}
