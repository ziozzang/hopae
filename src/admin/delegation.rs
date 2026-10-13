//! Optional trusted Hangang adapter. Native Hopae handle/grant/freshness/CSRF
//! and transactional mutation fences remain authoritative after translation.
use super::delegation_wire as wire;
use super::{AdminState, api};
use axum::{
    body::{Body, to_bytes},
    extract::{ConnectInfo, Request, State},
    http::{HeaderValue, Method, StatusCode, Uri, header},
    middleware::Next,
    response::Response,
};
use serde::Deserialize;
use std::{
    fs,
    io::Read,
    net::{IpAddr, SocketAddr},
    path::Path,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Explicit opt-in: Hangang is the console authority, not the native grant table.
    #[serde(default)]
    pub authority: Authority,
    pub key_env: String,
    #[serde(default)]
    pub sessions_file: Option<std::path::PathBuf>,
}
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Authority {
    #[default]
    Native,
    Hangang,
}

/// Only verified middleware can construct this proof; the write fence revalidates it.
#[derive(Clone)]
pub struct Proof {
    encoded: String,
    signature: String,
    key_env: String,
}
impl std::fmt::Debug for Proof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HangangAuthorityProof")
            .finish_non_exhaustive()
    }
}
impl Proof {
    fn verified(&self) -> Option<wire::Assertion> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
        let key = std::env::var(&self.key_env).ok()?;
        if !(32..=4096).contains(&key.len()) {
            return None;
        }
        let a = wire::verify(&self.encoded, &self.signature, key.as_bytes(), now)?;
        (a.authority.as_deref() == Some("hangang") && now >= a.timestamp && now - a.timestamp < 5)
            .then_some(a)
    }
    pub fn valid(&self) -> bool {
        self.verified().is_some()
    }
    pub fn valid_for(&self, actor: &crate::store::Actor) -> bool {
        self.verified().is_some_and(|a| {
            actor.user_id.as_str()
                == format!(
                    "u_{}",
                    &wire::digest(format!("hangang:{}", a.actor_id).as_bytes()).to_uppercase()
                        [..26]
                )
                && actor.session_id.as_str() == format!("s_{}", &a.nonce.to_uppercase()[..26])
                && actor.handle_sha256 == crate::crypto::Secret::new(a.nonce).digest()
        })
    }
}
#[derive(Clone, Debug)]
pub struct Actor {
    pub id: i64,
    pub name: String,
    pub nonce: String,
    pub expected_user_id: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Mapping {
    actor_id: i64,
    actor_name: String,
    user_id: String,
    handle: String,
    client_ip: IpAddr,
    #[serde(default)]
    user_agent: Option<String>,
}
pub struct Replay {
    path: std::path::PathBuf,
}
impl Replay {
    pub fn new(path: std::path::PathBuf) -> Self {
        Self { path }
    }
    fn admit(&self, nonce: &str, now: u64) -> bool {
        admit_nonce(&self.path, nonce, now).unwrap_or(false)
    }
}
fn admit_nonce(path: &Path, nonce: &str, now: u64) -> Option<bool> {
    let mut options = fs::OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let file = options.open(path).ok()?;
    let meta = file.metadata().ok()?;
    if !meta.is_file() {
        return None;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            return None;
        }
    }
    let mut db = rusqlite::Connection::open(path).ok()?;
    db.busy_timeout(Duration::from_millis(100)).ok()?;
    db.execute_batch("PRAGMA synchronous=FULL; CREATE TABLE IF NOT EXISTS delegation_nonces(nonce TEXT PRIMARY KEY,seen INTEGER NOT NULL); CREATE INDEX IF NOT EXISTS delegation_nonces_time ON delegation_nonces(seen);").ok()?;
    let tx = db
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .ok()?;
    tx.execute(
        "DELETE FROM delegation_nonces WHERE seen < ?1",
        [now.saturating_sub(30)],
    )
    .ok()?;
    let n: u64 = tx
        .query_row("SELECT count(*) FROM delegation_nonces", [], |r| r.get(0))
        .ok()?;
    if n >= 2048 {
        return Some(false);
    }
    let inserted = tx
        .execute(
            "INSERT OR IGNORE INTO delegation_nonces(nonce,seen) VALUES(?1,?2)",
            rusqlite::params![nonce, now],
        )
        .ok()?
        == 1;
    tx.commit().ok()?;
    Some(inserted)
}
fn mappings(path: &Path) -> Option<Vec<Mapping>> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let f = options.open(path).ok()?;
    let meta = f.metadata().ok()?;
    if !meta.is_file() || meta.len() > 65536 {
        return None;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            return None;
        }
    }
    let mut bytes = Vec::new();
    f.take(65537).read_to_end(&mut bytes).ok()?;
    if bytes.len() > 65536 {
        return None;
    }
    let rows: Vec<Mapping> = serde_json::from_slice(&bytes).ok()?;
    if rows.len() > 128 {
        return None;
    }
    Some(rows)
}
fn one<'a>(r: &'a Request, name: &str) -> Option<&'a str> {
    let mut values = r.headers().get_all(name).iter();
    let v = values.next()?;
    if values.next().is_some() {
        return None;
    }
    v.to_str().ok()
}
fn denied() -> Response {
    api::json_error(StatusCode::FORBIDDEN, "delegation_rejected")
}
pub async fn middleware(
    State(st): State<Arc<AdminState>>,
    mut req: Request,
    next: Next,
) -> Response {
    if !req.headers().contains_key("x-hopae-delegation")
        && !req.headers().contains_key("x-hopae-delegation-mac")
    {
        return next.run(req).await;
    }
    let Some(config) = &st.delegation else {
        return denied();
    };
    if !req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .is_some_and(|p| p.0.ip().is_loopback())
    {
        return denied();
    }
    let Ok(key) = std::env::var(&config.key_env) else {
        return denied();
    };
    if !(32..=4096).contains(&key.len()) {
        return denied();
    }
    let Some(now) = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
    else {
        return denied();
    };
    let Some(assertion) = one(&req, "x-hopae-delegation")
        .zip(one(&req, "x-hopae-delegation-mac"))
        .and_then(|(a, s)| wire::verify(a, s, key.as_bytes(), now))
    else {
        return denied();
    };
    if assertion.method != req.method().as_str()
        || assertion.path != req.uri().path()
        || req.uri().query().is_some()
    {
        return denied();
    }
    let unified = config.authority == Authority::Hangang;
    if (unified && assertion.authority.as_deref() != Some("hangang"))
        || (!unified && assertion.authority.is_some())
    {
        return denied();
    }
    let proof = unified.then(|| Proof {
        encoded: one(&req, "x-hopae-delegation").unwrap().into(),
        signature: one(&req, "x-hopae-delegation-mac").unwrap().into(),
        key_env: config.key_env.clone(),
    });
    if proof.as_ref().is_some_and(|p| !p.valid()) {
        return denied();
    }
    let (handle, expected_user_id, client_ip, user_agent) = if unified {
        let Ok(ip) = assertion.client_ip.parse::<IpAddr>() else {
            return denied();
        };
        (String::new(), None, ip, assertion.user_agent.clone())
    } else if let Some(path) = &config.sessions_file {
        let Some(rows) = mappings(path) else {
            return denied();
        };
        let matching = rows
            .iter()
            .filter(|m| m.actor_id == assertion.actor_id && m.actor_name == assertion.actor_name)
            .collect::<Vec<_>>();
        if matching.len() != 1 {
            return denied();
        }
        let mapping = matching[0];
        if !crate::config::valid_user_id(&mapping.user_id) {
            return denied();
        }
        (
            mapping.handle.clone(),
            Some(mapping.user_id.clone()),
            mapping.client_ip,
            mapping.user_agent.clone(),
        )
    } else {
        let Some(handle) = one(&req, "x-hopae-delegated-handle") else {
            return api::json_error(StatusCode::UNAUTHORIZED, "login_required");
        };
        if wire::digest(handle.as_bytes()) != assertion.handle_sha256 {
            return denied();
        }
        let Ok(ip) = assertion.client_ip.parse::<IpAddr>() else {
            return denied();
        };
        (handle.to_owned(), None, ip, assertion.user_agent.clone())
    };
    if !unified && !crate::crypto::is_well_formed_handle(&handle) {
        return denied();
    }
    let original_path = req.uri().path().to_owned();
    let method = req.method().clone();
    let (parts, body) = req.into_parts();
    let bytes =
        match tokio::time::timeout(Duration::from_secs(5), to_bytes(body, api::MAX_BODY_BYTES))
            .await
        {
            Ok(Ok(b)) => b,
            _ => return api::json_error(StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large"),
        };
    if wire::digest(&bytes) != assertion.body_sha256 {
        return denied();
    }
    let mut profile_publication: Option<(u64, Vec<u8>)> = None;
    let translated = match (method.as_str(), original_path.as_str()) {
        (
            "GET",
            "/v1/status"
            | "/v1/me"
            | "/v1/users"
            | "/v1/sessions"
            | "/v1/events"
            | "/v1/authentication/profiles"
            | "/v1/authentication/projections",
        ) if bytes.is_empty() => original_path.clone(),
        (
            "POST",
            path @ ("/v1/authentication/profiles/publish"
            | "/v1/authentication/projections/publish"),
        ) => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Publication {
                revision: u64,
                configuration: serde_json::Value,
            }
            let Ok(publication) = serde_json::from_slice::<Publication>(&bytes) else {
                return denied();
            };
            let Ok(body) =
                serde_json::to_vec(&serde_json::json!({"configuration":publication.configuration}))
            else {
                return denied();
            };
            profile_publication = Some((publication.revision, body));
            path.trim_end_matches("/publish").to_owned()
        }
        ("POST", path @ ("/v1/users/query" | "/v1/sessions/query" | "/v1/events/query")) => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Query {
                #[serde(default)]
                cursor: Option<String>,
                #[serde(default)]
                limit: Option<u16>,
            }
            let Ok(query) = serde_json::from_slice::<Query>(&bytes) else {
                return denied();
            };
            if query.limit.is_some_and(|n| n == 0 || n > 200)
                || query.cursor.as_ref().is_some_and(|v| v.len() > 2048)
            {
                return denied();
            }
            let mut params = form_urlencoded::Serializer::new(String::new());
            if let Some(cursor) = query.cursor {
                params.append_pair("cursor", &cursor);
            }
            if let Some(limit) = query.limit {
                params.append_pair("limit", &limit.to_string());
            }
            format!("{}?{}", path.trim_end_matches("/query"), params.finish())
        }
        ("POST", path) => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Target {
                id: String,
            }
            let Ok(target) = serde_json::from_slice::<Target>(&bytes) else {
                return denied();
            };
            match path {
                "/v1/users/disable" if crate::config::valid_user_id(&target.id) => {
                    format!("/v1/users/{}/disable", target.id)
                }
                "/v1/users/enable" if crate::config::valid_user_id(&target.id) => {
                    format!("/v1/users/{}/enable", target.id)
                }
                "/v1/users/sessions-terminate" if crate::config::valid_user_id(&target.id) => {
                    format!("/v1/users/{}/sessions/terminate", target.id)
                }
                "/v1/sessions/terminate" if super::users::common::valid_session_id(&target.id) => {
                    format!("/v1/sessions/{}/terminate", target.id)
                }
                _ => return denied(),
            }
        }
        _ => return denied(),
    };
    // Durable bounded nonce admission rejects replay across process restarts.
    let state = st.clone();
    let nonce = assertion.nonce.clone();
    if !matches!(
        tokio::task::spawn_blocking(move || state.delegation_replay.admit(&nonce, now)).await,
        Ok(true)
    ) {
        return denied();
    }
    let listing = original_path.ends_with("/query");
    req = Request::from_parts(
        parts,
        if let Some((_, body)) = &profile_publication {
            Body::from(body.clone())
        } else if method == Method::POST && !listing {
            Body::from("{}")
        } else {
            Body::empty()
        },
    );
    if profile_publication.is_some() {
        *req.method_mut() = Method::PUT;
    } else if listing {
        *req.method_mut() = Method::GET;
    }
    *req.uri_mut() = match translated.parse::<Uri>() {
        Ok(u) => u,
        Err(_) => return denied(),
    };
    let h = req.headers_mut();
    h.clear();
    let host = st.cfg.host.as_str().to_owned();
    for (name, value) in [
        (header::HOST, host.clone()),
        (crate::gateway::forwarding::X_FORWARDED_HOST.clone(), host),
        (
            crate::gateway::forwarding::X_FORWARDED_PROTO.clone(),
            if st.cfg.secure { "https" } else { "http" }.into(),
        ),
        (
            crate::gateway::forwarding::X_FORWARDED_FOR.clone(),
            client_ip.to_string(),
        ),
        (
            header::COOKIE,
            format!("{}={handle}", st.cfg.cookie_names.handle),
        ),
        (header::CONTENT_TYPE, "application/json".into()),
        (
            axum::http::HeaderName::from_static("x-hopae-admin-request"),
            "1".into(),
        ),
    ] {
        let Ok(mut value) = HeaderValue::from_str(&value) else {
            return denied();
        };
        if name == header::COOKIE {
            value.set_sensitive(true);
        }
        h.insert(name, value);
    }
    if let Some((revision, _)) = profile_publication {
        let Ok(value) = HeaderValue::from_str(&format!("\"{revision}\"")) else {
            return denied();
        };
        h.insert(header::IF_MATCH, value);
    }
    if let Some(ua) = &user_agent {
        let Ok(v) = HeaderValue::from_str(ua) else {
            return denied();
        };
        h.insert(header::USER_AGENT, v);
    }
    if let Some(proof) = proof {
        let user = format!(
            "u_{}",
            &wire::digest(format!("hangang:{}", assertion.actor_id).as_bytes()).to_uppercase()
                [..26]
        );
        let session = format!("s_{}", &assertion.nonce.to_uppercase()[..26]);
        req.extensions_mut().insert(super::Principal {
            authority: Some(proof),
            user_id: crate::identity::types::UserId::new(user),
            session_id: crate::session::types::SessionId::new(session),
            handle_sha256: crate::crypto::Secret::new(assertion.nonce.clone()).digest(),
            handle_value: crate::crypto::Secret::new(assertion.nonce.clone()),
            role: crate::store::AdminRole::Admin,
            email: None,
            display_name: Some(assertion.actor_name.clone()),
            auth_time: crate::crypto::Timestamp::from_secs(assertion.timestamp as i64),
            auth_time_source: crate::store::AuthTimeSource::HopaeCompletion,
            aal: crate::session::types::Aal::One,
            provider_id: crate::provider::types::ProviderId::new("hangang"),
        });
    }
    req.extensions_mut().insert(Actor {
        id: assertion.actor_id,
        name: assertion.actor_name,
        nonce: assertion.nonce,
        expected_user_id,
    });
    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    #[test]
    fn nonce_admission_survives_restart_and_expires() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("nonce.db");
        assert_eq!(admit_nonce(&p, "operation", 100), Some(true));
        assert_eq!(admit_nonce(&p, "operation", 100), Some(false));
        assert_eq!(admit_nonce(&p, "operation", 131), Some(true));
    }
    #[cfg(unix)]
    #[test]
    fn unsafe_nonce_and_mapping_files_are_refused() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("nonce.db");
        let q = d.path().join("link.db");
        std::fs::write(&p, "[]").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::os::unix::fs::symlink(&p, &q).unwrap();
        assert!(admit_nonce(&q, "op", 100).is_none());
        assert!(mappings(&p).is_none());
    }
}
