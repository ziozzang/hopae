//! The subject directory API (ADR-0020 subject resolution, ADR-0021 orphan
//! reconciliation): batch resolution of the opaque subject references used
//! across the stack, a search for subject pickers, and the subject lifecycle
//! feed with its reconcile snapshot.
//!
//! * `POST /v1/subjects/resolve` — up to 100 references (`u_…` user IDs,
//!   `human1:<64 hex>` Human subjects, `s_<48 hex>` service principals) to
//!   display data. Every reference gets an item; one that names nothing is
//!   `status: "unknown"` with a reason, never an error.
//! * `POST /v1/subjects/search` — prefix/substring search of people or of
//!   configured service principals, cursor-paginated.
//! * `POST /v1/subjects/lifecycle` — `created`, `disabled`, `enabled` changes
//!   after a durable cursor; `410 cursor_expired` when the position is gone.
//! * `POST /v1/subjects/lifecycle/snapshot` — every reserved user ID with its
//!   current status (`deleted` for a tombstone) and the feed watermark.
//!
//! All four are reads for any granted role, rate-limited per actor and
//! recorded as `admin.read` before the answer leaves.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, OnceLock};

use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::reads::{self, Op, Privacy};
use super::users::common::{Fail, store_failure};
use super::{AdminState, Ctx, api, cursor};
use crate::auth_gateway::PrincipalKind;
use crate::auth_gateway::runtime::ServicePrincipal;
use crate::store::sqlite::subject_directory::{
    self as dir, DirectoryRow, LedgerRow, OutboxPosition,
};
use crate::store::types::{Cursor, UserStatus, UsersQuery};
use crate::store::{Deadline, StoreError};

/// Most references one resolve call accepts (ADR-0020: ≤ 100).
pub const MAX_RESOLVE: usize = 100;
/// Longest reference echoed back; a longer one refuses the request.
pub const MAX_REF_BYTES: usize = 256;
/// `limit` of a search: default and maximum.
pub const SEARCH_DEFAULT: usize = 20;
pub const SEARCH_MAX: usize = 50;
/// `limit` of a lifecycle page: default and maximum.
pub const FEED_DEFAULT: usize = 100;
pub const FEED_MAX: usize = 200;

// ---- references -------------------------------------------------------------

/// What a reference string looks like.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ref {
    User,
    Human,
    Service,
    Unrecognized,
}

fn lower_hex(s: &str, n: usize) -> bool {
    s.len() == n && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

pub fn classify(id: &str) -> Ref {
    if let Some(hex) = id.strip_prefix("human1:")
        && lower_hex(hex, 64)
    {
        Ref::Human
    } else if let Some(hex) = id.strip_prefix("s_")
        && lower_hex(hex, 48)
    {
        Ref::Service
    } else if crate::config::valid_user_id(id) {
        Ref::User
    } else {
        Ref::Unrecognized
    }
}

// ---- items ------------------------------------------------------------------

/// One resolved (or unknown) reference. Every key is always present.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Item {
    pub id: String,
    /// `active`, `disabled`, `deleted` or `unknown`.
    pub status: &'static str,
    /// Why the status is `unknown` or `disabled` without a person's action.
    pub reason: Option<&'static str>,
    /// `human`, `service`, `workload`, or `null` when unknown.
    pub kind: Option<&'static str>,
    pub user_id: Option<String>,
    pub human_subject: Option<String>,
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub providers: Vec<String>,
    pub created_at: Option<i64>,
    pub last_login_at: Option<i64>,
    pub last_seen_at: Option<i64>,
    pub service_id: Option<String>,
    pub realm: Option<String>,
    pub expires_at: Option<i64>,
}

impl Item {
    fn unknown(id: &str, reason: &'static str) -> Item {
        Item {
            id: id.to_string(),
            status: "unknown",
            reason: Some(reason),
            kind: None,
            user_id: None,
            human_subject: None,
            display_name: None,
            email: None,
            providers: Vec::new(),
            created_at: None,
            last_login_at: None,
            last_seen_at: None,
            service_id: None,
            realm: None,
            expires_at: None,
        }
    }

    fn human(
        id: &str,
        user_id: &str,
        row: &DirectoryRow,
        subject: Option<String>,
        privacy: Privacy,
    ) -> Item {
        let mut item = Item::unknown(id, "not_found");
        item.reason = None;
        item.kind = Some("human");
        item.user_id = Some(user_id.to_string());
        item.human_subject = subject;
        match &row.user {
            None => item.status = "deleted",
            Some(u) => {
                item.status = match u.status {
                    UserStatus::Active => "active",
                    UserStatus::Disabled => "disabled",
                };
                item.display_name = u.display_name.clone().or_else(|| u.username.clone());
                item.email = privacy.email(u.primary_email.as_ref().map(|e| e.as_str()));
                item.providers = row.providers.clone();
                item.created_at = Some(u.created_at.secs());
                item.last_login_at = u.last_login_at.map(|t| t.secs());
                item.last_seen_at = row.last_seen_at;
            }
        }
        item
    }

    fn service(id: &str, p: &ServicePrincipal, now_ms: i64) -> Item {
        let mut item = Item::unknown(id, "not_found");
        item.reason = None;
        let expired = p
            .expires_at_ms
            .is_some_and(|t| i64::try_from(t).unwrap_or(i64::MAX) <= now_ms);
        item.status = if expired { "disabled" } else { "active" };
        item.reason = expired.then_some("credential_expired");
        item.kind = Some(kind_name(p.kind));
        item.display_name = Some(format!("{} ({})", p.name, p.service_id));
        item.service_id = Some(p.service_id.clone());
        item.realm = Some(p.realm.clone());
        item.expires_at = p
            .expires_at_ms
            .map(|t| i64::try_from(t).unwrap_or(i64::MAX));
        item
    }
}

pub fn kind_name(kind: PrincipalKind) -> &'static str {
    match kind {
        PrincipalKind::Human => "human",
        PrincipalKind::Service => "service",
        PrincipalKind::Workload => "workload",
        PrincipalKind::Network => "network",
    }
}

// ---- the Human subject index ------------------------------------------------

/// Reverse index from Human subject to reservation-ledger position. The
/// ledger is append-only, so the index only ever catches up; a candidate is
/// always re-derived from the ledger row before it is believed, so a stale or
/// colliding entry can cost a miss, never a wrong answer.
struct HumanIndex {
    store: usize,
    issuer: String,
    realm: String,
    after: i64,
    first: HashMap<u64, i64>,
    more: HashMap<u64, Vec<i64>>,
    entries: usize,
}

/// Rows read from the ledger per catch-up step.
const INDEX_CHUNK: usize = 10_000;
/// Most ledger positions indexed per store (a memory bound of ~40 MB).
const INDEX_MAX: usize = 1 << 21;

fn prefix(subject: &str) -> Option<u64> {
    let hex = subject.strip_prefix("human1:")?;
    let bytes = data_encoding::HEXLOWER
        .decode(hex.get(..16)?.as_bytes())
        .ok()?;
    Some(u64::from_be_bytes(bytes.try_into().ok()?))
}

impl HumanIndex {
    fn insert(&mut self, key: u64, position: i64) {
        match self.first.entry(key) {
            std::collections::hash_map::Entry::Vacant(v) => {
                v.insert(position);
            }
            std::collections::hash_map::Entry::Occupied(_) => {
                self.more.entry(key).or_default().push(position);
            }
        }
        self.entries += 1;
    }

    fn candidates(&self, key: u64) -> Vec<i64> {
        let mut out: Vec<i64> = self.first.get(&key).copied().into_iter().collect();
        if let Some(more) = self.more.get(&key) {
            out.extend(more);
        }
        out
    }
}

fn indexes() -> &'static tokio::sync::Mutex<Vec<HumanIndex>> {
    static I: OnceLock<tokio::sync::Mutex<Vec<HumanIndex>>> = OnceLock::new();
    I.get_or_init(|| tokio::sync::Mutex::new(Vec::new()))
}

/// Resolve Human subjects to user IDs. The second value is `false` when the
/// index could not catch up with the ledger within the request's budget.
pub(crate) async fn human_users(
    store: &crate::store::sqlite::Store,
    issuer: &str,
    subjects: &[String],
    budget: std::time::Duration,
) -> Result<(HashMap<String, String>, bool), StoreError> {
    let mut out = HashMap::new();
    if subjects.is_empty() {
        return Ok((out, true));
    }
    let stop = tokio::time::Instant::now() + budget / 2;
    let deadline = || Deadline::after(budget);
    let Some(realm) = store.admin_human_realm(deadline()).await? else {
        return Ok((out, true));
    };
    // Another request may be catching the index up: wait at most until this
    // request's own catch-up budget ends, then answer `index_incomplete`.
    let Ok(mut all) = tokio::time::timeout_at(stop, indexes().lock()).await else {
        return Ok((out, false));
    };
    let id = store.directory_identity();
    all.retain(|ix| !(ix.store == id && ix.issuer == issuer && ix.realm != realm));
    if all.len() >= 8 && !all.iter().any(|ix| ix.store == id && ix.issuer == issuer) {
        all.remove(0);
    }
    if !all.iter().any(|ix| ix.store == id && ix.issuer == issuer) {
        all.push(HumanIndex {
            store: id,
            issuer: issuer.to_string(),
            realm: realm.clone(),
            after: 0,
            first: HashMap::new(),
            more: HashMap::new(),
            entries: 0,
        });
    }
    let ix = all
        .iter_mut()
        .find(|ix| ix.store == id && ix.issuer == issuer)
        .ok_or(StoreError::Conflict("subject index"))?;
    let mut complete = true;
    loop {
        if ix.entries >= INDEX_MAX || tokio::time::Instant::now() >= stop {
            complete = store.admin_ledger_head(deadline()).await? <= ix.after;
            break;
        }
        let rows = store
            .admin_ledger_after(ix.after, INDEX_CHUNK, deadline())
            .await?;
        let n = rows.len();
        for row in rows {
            if let Some(key) = dir::human_subject(issuer, &realm, &row.user_id)
                .as_deref()
                .and_then(prefix)
            {
                ix.insert(key, row.position);
            }
            ix.after = row.position;
        }
        if n < INDEX_CHUNK {
            break;
        }
    }
    let mut asked: Vec<(String, Vec<i64>)> = Vec::new();
    for s in subjects {
        if let Some(key) = prefix(s) {
            asked.push((s.clone(), ix.candidates(key)));
        }
    }
    drop(all);
    let positions: Vec<i64> = asked
        .iter()
        .flat_map(|(_, p)| p.iter().copied())
        .collect::<HashSet<_>>()
        .into_iter()
        .take(dir::MAX_BATCH)
        .collect();
    let rows = store.admin_ledger_at(positions, deadline()).await?;
    for (subject, candidates) in asked {
        for p in candidates {
            if let Some(user) = rows.get(&p)
                && dir::human_subject(issuer, &realm, user).as_deref() == Some(subject.as_str())
            {
                out.insert(subject.clone(), user.clone());
            }
        }
    }
    Ok((out, complete))
}

// ---- resolution -------------------------------------------------------------

/// Everything a resolution draws on, gathered once per request.
pub(crate) struct Sources {
    pub store: crate::store::sqlite::Store,
    pub issuer: Option<String>,
    pub realm: Option<String>,
    pub services: Option<Vec<ServicePrincipal>>,
    pub budget: std::time::Duration,
    pub now_ms: i64,
}

impl Sources {
    pub(crate) async fn of(st: &AdminState) -> Result<Sources, StoreError> {
        let store = st.profile_store.clone();
        let issuer = reads::human_issuer(st);
        let realm = if issuer.is_some() {
            store.admin_human_realm(api::deadline(st)).await?
        } else {
            None
        };
        let services = reads::service_snapshot(st)
            .and_then(|s| s.runtime.as_ref().map(|r| r.admin_service_principals()));
        Ok(Sources {
            store,
            issuer,
            realm,
            services,
            budget: st.cfg.query_budget,
            now_ms: st.clock.now().0,
        })
    }

    fn subject_of(&self, user: &str) -> Option<String> {
        dir::human_subject(self.issuer.as_deref()?, self.realm.as_deref()?, user)
    }
}

/// Resolve references, one item per distinct reference in input order.
pub(crate) async fn resolve(
    src: &Sources,
    ids: &[String],
    privacy: Privacy,
) -> Result<(Vec<Item>, bool), StoreError> {
    let mut seen = HashSet::new();
    let ids: Vec<&String> = ids.iter().filter(|id| seen.insert(id.as_str())).collect();
    let humans: Vec<String> = ids
        .iter()
        .filter(|id| classify(id) == Ref::Human)
        .map(|id| (*id).clone())
        .collect();
    let (by_subject, complete) = match &src.issuer {
        Some(issuer) if !humans.is_empty() => {
            human_users(&src.store, issuer, &humans, src.budget).await?
        }
        _ => (HashMap::new(), true),
    };
    let mut wanted: Vec<String> = ids
        .iter()
        .filter(|id| classify(id) == Ref::User)
        .map(|id| (*id).clone())
        .collect();
    wanted.extend(by_subject.values().cloned());
    wanted.sort();
    wanted.dedup();
    let rows = if wanted.is_empty() {
        BTreeMap::new()
    } else {
        src.store
            .admin_directory_rows(wanted, Deadline::after(src.budget))
            .await?
    };
    let items = ids
        .iter()
        .map(|id| match classify(id) {
            Ref::Unrecognized => Item::unknown(id, "unrecognized"),
            Ref::User => match rows.get(id.as_str()) {
                Some(row) => Item::human(id, id, row, src.subject_of(id), privacy),
                None => Item::unknown(id, "not_found"),
            },
            Ref::Human => {
                if src.issuer.is_none() {
                    Item::unknown(id, "human_subjects_not_configured")
                } else if let Some(user) = by_subject.get(id.as_str())
                    && let Some(row) = rows.get(user)
                {
                    Item::human(id, user, row, Some((*id).clone()), privacy)
                } else if complete {
                    Item::unknown(id, "not_found")
                } else {
                    Item::unknown(id, "index_incomplete")
                }
            }
            Ref::Service => match src
                .services
                .as_ref()
                .and_then(|all| all.iter().find(|p| &p.subject_ref == *id))
            {
                Some(p) => Item::service(id, p, src.now_ms),
                None => Item::unknown(id, "not_enumerable"),
            },
        })
        .collect();
    Ok((items, complete))
}

fn tally(items: &[Item]) -> (usize, usize) {
    let unknown = items.iter().filter(|i| i.status == "unknown").count();
    (items.len() - unknown, unknown)
}

// ---- handlers ---------------------------------------------------------------

fn parse<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, Fail> {
    serde_json::from_slice(bytes).map_err(|_| reads::invalid())
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
    let mut r = f(&st, &c, &bytes)
        .await
        .unwrap_or_else(|fail| fail.respond(&st, &c));
    r.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    r
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResolveRequest {
    ids: Vec<String>,
    #[serde(default)]
    privacy_profile: Privacy,
}

pub async fn resolve_api(
    State(st): State<Arc<AdminState>>,
    c: Ctx,
    headers: HeaderMap,
    body: Body,
) -> Response {
    run(st, c, headers, body, Op::Resolve, async |st, c, bytes| {
        let mut req: ResolveRequest = parse(bytes)?;
        req.privacy_profile = req.privacy_profile.at_least(st.cfg.privacy_floor);
        if req.ids.is_empty()
            || req.ids.len() > MAX_RESOLVE
            || req
                .ids
                .iter()
                .any(|id| id.is_empty() || id.len() > MAX_REF_BYTES)
        {
            return Err(reads::invalid());
        }
        let src = Sources::of(st)
            .await
            .map_err(|e| store_failure(c, "subjects", &e))?;
        let (items, complete) = resolve(&src, &req.ids, req.privacy_profile)
            .await
            .map_err(|e| store_failure(c, "subjects", &e))?;
        let (resolved, unknown) = tally(&items);
        reads::audit(st, c, Op::Resolve, bytes, |b| {
            b.attr("requested", req.ids.len())
                .attr("count", resolved)
                .attr("status", if unknown == 0 { "resolved" } else { "partial" })
        })
        .await?;
        Ok(api::json(
            StatusCode::OK,
            &json!({
                "items": items,
                "privacy_profile": req.privacy_profile.as_str(),
                "resolved": resolved,
                "unknown": unknown,
                "complete": complete,
            }),
        ))
    })
    .await
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SearchRequest {
    q: String,
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    cursor: Option<String>,
    #[serde(default)]
    privacy_profile: Privacy,
}

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

pub async fn search_api(
    State(st): State<Arc<AdminState>>,
    c: Ctx,
    headers: HeaderMap,
    body: Body,
) -> Response {
    run(st, c, headers, body, Op::Search, async |st, c, bytes| {
        let mut req: SearchRequest = parse(bytes)?;
        req.privacy_profile = req.privacy_profile.at_least(st.cfg.privacy_floor);
        let q = req.q.trim();
        if q.is_empty() || q.chars().count() > 128 || q.chars().any(char::is_control) {
            return Err(reads::invalid());
        }
        let limit = req.limit.unwrap_or(SEARCH_DEFAULT);
        if !(1..=SEARCH_MAX).contains(&limit) {
            return Err(reads::invalid());
        }
        let status = match req.status.as_deref() {
            None => None,
            Some(s) => Some(UserStatus::parse(s).ok_or_else(reads::invalid)?),
        };
        let after = match &req.cursor {
            None => None,
            Some(v) => Some(
                cursor::decode(&st.key, v)
                    .map_err(|_| Fail(StatusCode::BAD_REQUEST, "invalid_cursor"))?,
            ),
        };
        let src = Sources::of(st)
            .await
            .map_err(|e| store_failure(c, "subjects", &e))?;
        let (items, next, examined) = match req.kind.as_deref().unwrap_or("human") {
            "human" => {
                // An exact reference is answered as a resolution: user IDs and
                // Human subjects are not text the directory's search matches.
                if matches!(classify(q), Ref::User | Ref::Human) {
                    if after.is_some() {
                        (Vec::new(), None, 0)
                    } else {
                        let (items, _) = resolve(&src, &[q.to_string()], req.privacy_profile)
                            .await
                            .map_err(|e| store_failure(c, "subjects", &e))?;
                        let items: Vec<Item> = items
                            .into_iter()
                            .filter(|i| i.status != "unknown")
                            .filter(|i| status.is_none_or(|s| i.status == s.as_str()))
                            .collect();
                        (items, None, 1)
                    }
                } else {
                    let page = st
                        .directory
                        .list_users(
                            UsersQuery {
                                q: Some(escape_like(q)),
                                status,
                                limit,
                                cursor: after,
                            },
                            api::deadline(st),
                        )
                        .await
                        .map_err(|e| store_failure(c, "subjects", &e))?;
                    let ids: Vec<String> = page
                        .items
                        .iter()
                        .map(|s| s.user.user_id.to_string())
                        .collect();
                    let items = if ids.is_empty() {
                        Vec::new()
                    } else {
                        resolve(&src, &ids, req.privacy_profile)
                            .await
                            .map_err(|e| store_failure(c, "subjects", &e))?
                            .0
                    };
                    (items, page.next, page.examined)
                }
            }
            "service" => {
                let needle = q.to_ascii_lowercase();
                let from = after.as_ref().map(|c| c.id.clone());
                let mut matched: Vec<&ServicePrincipal> = src
                    .services
                    .iter()
                    .flatten()
                    .filter(|p| {
                        from.as_ref()
                            .is_none_or(|f| p.subject_ref.as_str() > f.as_str())
                    })
                    .filter(|p| {
                        [&p.name, &p.service_id, &p.realm, &p.subject_ref]
                            .iter()
                            .any(|v| v.to_ascii_lowercase().contains(&needle))
                    })
                    .filter(|p| {
                        status.is_none_or(|s| {
                            Item::service(&p.subject_ref, p, src.now_ms).status == s.as_str()
                        })
                    })
                    .collect();
                let more = matched.len() > limit;
                matched.truncate(limit);
                let next = (more && !matched.is_empty()).then(|| Cursor {
                    key: 0,
                    id: matched[matched.len() - 1].subject_ref.clone(),
                });
                let examined = u32::try_from(matched.len()).unwrap_or(u32::MAX);
                let items = matched
                    .into_iter()
                    .map(|p| {
                        let mut item = Item::service(&p.subject_ref, p, src.now_ms);
                        item.id = p.subject_ref.clone();
                        item
                    })
                    .collect();
                (items, next, examined)
            }
            _ => return Err(reads::invalid()),
        };
        super::users::common::examined("subjects", examined);
        reads::audit(st, c, Op::Search, bytes, |b| {
            b.attr("count", items.len())
                .attr("kind", req.kind.clone().unwrap_or_else(|| "human".into()))
        })
        .await?;
        Ok(api::json(
            StatusCode::OK,
            &json!({
                "items": items,
                "next_cursor": next.as_ref().map(|n| cursor::encode(&st.key, n)),
                "privacy_profile": req.privacy_profile.as_str(),
            }),
        ))
    })
    .await
}

// ---- lifecycle --------------------------------------------------------------

/// A durable feed position: the reservation-ledger position and the outbox
/// position. Not a secret and not process-bound: a consumer keeps it across
/// restarts of either side.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeedCursor {
    pub ledger: i64,
    pub outbox: OutboxPosition,
}

impl FeedCursor {
    pub fn encode(&self) -> String {
        format!(
            "f1.{}.{}.{}",
            self.ledger,
            self.outbox.row,
            self.outbox.event_id.as_deref().unwrap_or("-")
        )
    }

    pub fn decode(s: &str) -> Option<FeedCursor> {
        if s.len() > 160 {
            return None;
        }
        let mut parts = s.split('.');
        if parts.next()? != "f1" {
            return None;
        }
        let num = |v: &str| {
            (!v.is_empty() && v.len() <= 19 && v.bytes().all(|b| b.is_ascii_digit()))
                .then(|| v.parse::<i64>().ok())
                .flatten()
        };
        let ledger = num(parts.next()?)?;
        let row = num(parts.next()?)?;
        let id = parts.next()?;
        if parts.next().is_some() {
            return None;
        }
        let event_id = match id {
            "-" if row == 0 => None,
            "-" => return None,
            id if (3..=64).contains(&id.len())
                && id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-') =>
            {
                Some(id.to_string())
            }
            _ => return None,
        };
        Some(FeedCursor {
            ledger,
            outbox: OutboxPosition { row, event_id },
        })
    }
}

#[derive(Serialize)]
struct Change {
    change: &'static str,
    user_id: String,
    human_subject: Option<String>,
    /// The subject's status when this page was read (consumers apply it,
    /// which makes replays and reordering harmless).
    status: &'static str,
    at: Option<i64>,
}

fn current_status(status: Option<&str>) -> &'static str {
    match status {
        Some("active") => "active",
        Some("disabled") => "disabled",
        Some(_) => "unknown",
        None => "deleted",
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FeedRequest {
    #[serde(default)]
    cursor: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
}

fn feed_limit(v: Option<usize>, default: usize) -> Result<usize, Fail> {
    let n = v.unwrap_or(default);
    if (1..=FEED_MAX).contains(&n) {
        Ok(n)
    } else {
        Err(reads::invalid())
    }
}

fn expired() -> Fail {
    Fail(StatusCode::GONE, "cursor_expired")
}

pub async fn lifecycle_api(
    State(st): State<Arc<AdminState>>,
    c: Ctx,
    headers: HeaderMap,
    body: Body,
) -> Response {
    run(st, c, headers, body, Op::Lifecycle, async |st, c, bytes| {
        let req: FeedRequest = parse(bytes)?;
        let limit = feed_limit(req.limit, FEED_DEFAULT)?;
        let from = match &req.cursor {
            None => FeedCursor {
                ledger: 0,
                outbox: OutboxPosition {
                    row: 0,
                    event_id: None,
                },
            },
            Some(v) => {
                FeedCursor::decode(v).ok_or(Fail(StatusCode::BAD_REQUEST, "invalid_cursor"))?
            }
        };
        let fail = |e: StoreError| store_failure(c, "subjects", &e);
        let src = Sources::of(st).await.map_err(fail)?;
        let ledger_head = src
            .store
            .admin_ledger_head(api::deadline(st))
            .await
            .map_err(fail)?;
        if from.ledger > ledger_head {
            return Err(expired());
        }
        let created: Vec<LedgerRow> = src
            .store
            .admin_ledger_after(from.ledger, limit, api::deadline(st))
            .await
            .map_err(fail)?;
        let mut next = from.clone();
        let mut changes: Vec<Change> = Vec::new();
        for row in &created {
            next.ledger = row.position;
            changes.push(Change {
                change: "created",
                human_subject: src.subject_of(&row.user_id),
                user_id: row.user_id.clone(),
                status: current_status(row.status.as_deref()),
                at: row.created_at,
            });
        }
        let room = limit - changes.len();
        let mut outbox_head = from.outbox.row;
        let mut ledger_more = created.len() == limit && next.ledger < ledger_head;
        if room > 0 {
            let page = src
                .store
                .admin_status_changes(from.outbox.clone(), room, api::deadline(st))
                .await
                .map_err(fail)?
                .map_err(|_| expired())?;
            outbox_head = page.head;
            let ids: Vec<String> = page.changes.iter().map(|ch| ch.user_id.clone()).collect();
            let rows = if ids.is_empty() {
                BTreeMap::new()
            } else {
                src.store
                    .admin_directory_rows(ids, api::deadline(st))
                    .await
                    .map_err(fail)?
            };
            for ch in page.changes {
                let status = rows
                    .get(&ch.user_id)
                    .and_then(|r| r.user.as_ref())
                    .map(|u| u.status.as_str());
                changes.push(Change {
                    change: ch.change,
                    human_subject: src.subject_of(&ch.user_id),
                    status: current_status(status),
                    at: Some(ch.at),
                    user_id: ch.user_id,
                });
            }
            next.outbox = page.next;
        } else {
            ledger_more = true;
        }
        let more = ledger_more || next.outbox.row < outbox_head;
        if !changes.is_empty() {
            reads::audit(st, c, Op::Lifecycle, bytes, |b| {
                b.attr("count", changes.len())
            })
            .await?;
        }
        Ok(api::json(
            StatusCode::OK,
            &json!({
                "changes": changes,
                "next_cursor": next.encode(),
                "more": more,
            }),
        ))
    })
    .await
}

pub async fn snapshot_api(
    State(st): State<Arc<AdminState>>,
    c: Ctx,
    headers: HeaderMap,
    body: Body,
) -> Response {
    run(st, c, headers, body, Op::Lifecycle, async |st, c, bytes| {
        let req: FeedRequest = parse(bytes)?;
        let limit = feed_limit(req.limit, FEED_MAX)?;
        let after = match &req.cursor {
            None => 0,
            Some(v) => v
                .strip_prefix("l1.")
                .filter(|n| !n.is_empty() && n.len() <= 19 && n.bytes().all(|b| b.is_ascii_digit()))
                .and_then(|n| n.parse::<i64>().ok())
                .ok_or(Fail(StatusCode::BAD_REQUEST, "invalid_cursor"))?,
        };
        let fail = |e: StoreError| store_failure(c, "subjects", &e);
        let src = Sources::of(st).await.map_err(fail)?;
        // The watermark is taken before the first page is read, so every
        // change after it is in the feed even if the pages miss it.
        let watermark = if req.cursor.is_none() {
            let outbox = src
                .store
                .admin_outbox_head(api::deadline(st))
                .await
                .map_err(fail)?;
            let ledger = src
                .store
                .admin_ledger_head(api::deadline(st))
                .await
                .map_err(fail)?;
            Some(FeedCursor { ledger, outbox }.encode())
        } else {
            None
        };
        let rows = src
            .store
            .admin_ledger_after(after, limit + 1, api::deadline(st))
            .await
            .map_err(fail)?;
        let more = rows.len() > limit;
        let rows = &rows[..rows.len().min(limit)];
        let items: Vec<_> = rows
            .iter()
            .map(|r| {
                json!({
                    "user_id": r.user_id,
                    "human_subject": src.subject_of(&r.user_id),
                    "status": current_status(r.status.as_deref()),
                    "created_at": r.created_at,
                })
            })
            .collect();
        let next = more
            .then(|| rows.last().map(|r| format!("l1.{}", r.position)))
            .flatten();
        reads::audit(st, c, Op::Lifecycle, bytes, |b| {
            b.attr("count", items.len()).attr("kind", "snapshot")
        })
        .await?;
        Ok(api::json(
            StatusCode::OK,
            &json!({
                "items": items,
                "next_cursor": next,
                "watermark": watermark,
            }),
        ))
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn references_are_classified_by_exact_grammar() {
        assert_eq!(classify(&format!("human1:{}", "a".repeat(64))), Ref::Human);
        assert_eq!(
            classify(&format!("human1:{}", "A".repeat(64))),
            Ref::Unrecognized
        );
        assert_eq!(
            classify(&format!("human1:{}", "a".repeat(63))),
            Ref::Unrecognized
        );
        assert_eq!(classify(&format!("s_{}", "0".repeat(48))), Ref::Service);
        // A session id is `s_` + 26 Crockford symbols: never a principal.
        assert_eq!(classify("s_0123456789ABCDEFGHJKMNPQRS"), Ref::Unrecognized);
        assert_eq!(classify("u_01HZY"), Ref::User);
        assert_eq!(classify("alice@example.test"), Ref::Unrecognized);
        assert_eq!(classify(""), Ref::Unrecognized);
    }

    #[test]
    fn feed_cursors_round_trip_and_reject_tampering() {
        let c = FeedCursor {
            ledger: 7,
            outbox: OutboxPosition {
                row: 42,
                event_id: Some("e_01ABC".into()),
            },
        };
        assert_eq!(FeedCursor::decode(&c.encode()), Some(c));
        let start = FeedCursor {
            ledger: 0,
            outbox: OutboxPosition {
                row: 0,
                event_id: None,
            },
        };
        assert_eq!(start.encode(), "f1.0.0.-");
        assert_eq!(FeedCursor::decode("f1.0.0.-"), Some(start));
        for bad in [
            "",
            "f2.0.0.-",
            "f1.0.5.-",
            "f1.-1.0.-",
            "f1.0.0.e_1.extra",
            "f1.0.1.e/1",
            "f1.99999999999999999999.0.-",
            "f1..0.-",
        ] {
            assert_eq!(FeedCursor::decode(bad), None, "{bad}");
        }
    }

    #[test]
    fn subject_prefixes_come_from_the_hash() {
        let s = format!("human1:{}{}", "0102030405060708", "0".repeat(48));
        assert_eq!(prefix(&s), Some(0x0102030405060708));
        assert_eq!(prefix("human1:zz"), None);
    }

    #[tokio::test]
    async fn the_index_resolves_live_and_deleted_subjects_and_misses_nothing_else() {
        use crate::crypto::{TestClock, Timestamp};
        let dir = tempfile::tempdir().unwrap();
        let store = crate::store::sqlite::Store::open(
            &dir.path().join("hopae.db"),
            Arc::new(TestClock::new(Timestamp(1_700_000_000_000))),
            vec![],
            None,
        )
        .unwrap();
        for id in ["u_one", "u_two", "u_three"] {
            store
                .conn()
                .execute(
                    "INSERT INTO users(user_id,created_at,updated_at) VALUES(?1,1,1)",
                    [id],
                )
                .unwrap();
        }
        store
            .conn()
            .execute("DELETE FROM users WHERE user_id='u_three'", [])
            .unwrap();
        let realm = store
            .admin_human_realm(Deadline::after(std::time::Duration::from_secs(5)))
            .await
            .unwrap()
            .unwrap();
        let s1 = dir::human_subject("owned", &realm, "u_one").unwrap();
        let s3 = dir::human_subject("owned", &realm, "u_three").unwrap();
        let other = dir::human_subject("other-issuer", &realm, "u_two").unwrap();
        let budget = std::time::Duration::from_secs(5);
        let (found, complete) = human_users(
            &store,
            "owned",
            &[s1.clone(), s3.clone(), other.clone()],
            budget,
        )
        .await
        .unwrap();
        assert!(complete);
        assert_eq!(found.get(&s1).map(String::as_str), Some("u_one"));
        assert_eq!(found.get(&s3).map(String::as_str), Some("u_three"));
        assert!(!found.contains_key(&other));
        // The index catches up with users created later.
        store
            .conn()
            .execute(
                "INSERT INTO users(user_id,created_at,updated_at) VALUES('u_four',2,2)",
                [],
            )
            .unwrap();
        let s4 = dir::human_subject("owned", &realm, "u_four").unwrap();
        let (found, _) = human_users(&store, "owned", std::slice::from_ref(&s4), budget)
            .await
            .unwrap();
        assert_eq!(found.get(&s4).map(String::as_str), Some("u_four"));
    }
}
