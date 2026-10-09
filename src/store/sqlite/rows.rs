//! Column lists and row decoding. Decoding failures are `Corrupt` and name the
//! column, never a value.

use std::net::IpAddr;

use rusqlite::Row;

use crate::crypto::{Digest, Secret, Timestamp};
use crate::event::types::{Event, EventId, EventKind, Outcome, reasons};
use crate::identity::types::{NormalizedEmail, UserId};
use crate::policy::types::{AppId, Host};
use crate::provider::types::{ProviderId, ProviderKind};
use crate::session::types::{Aal, FactorEntry, SessionId};
use crate::store::types::*;
use crate::store::{StoreError, StoreResult};

pub(super) fn corrupt(col: &str) -> StoreError {
    StoreError::Corrupt(format!("column {col}"))
}

/// `a.c1, a.c2, ...` for a column list under an optional table alias.
pub(super) fn cols(alias: &str, list: &[&str]) -> String {
    list.iter()
        .map(|c| {
            if alias.is_empty() {
                (*c).to_string()
            } else {
                format!("{alias}.{c}")
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

pub(super) const USER_COLS: &[&str] = &[
    "user_id",
    "primary_email",
    "email_verified",
    "email_authoritative",
    "display_name",
    "username",
    "status",
    "authz_version",
    "groups",
    "created_at",
    "updated_at",
    "last_login_at",
];
pub(super) const IDENTITY_COLS: &[&str] = &[
    "provider_id",
    "subject",
    "user_id",
    "email",
    "email_verified",
    "email_authoritative",
    "name",
    "picture",
    "first_seen_at",
    "last_seen_at",
];
pub(super) const PROVIDER_COLS: &[&str] = &[
    "provider_id",
    "kind",
    "display_name",
    "enabled",
    "managed_by",
    "deleted_at",
    "sort_order",
    "config",
    "client_secret_env",
    "allowed_email_domains",
    "authoritative_domains",
    "auto_link",
    "trust_email",
];
pub(super) const SESSION_COLS: &[&str] = &[
    "session_id",
    "user_id",
    "provider_id",
    "auth_time",
    "factors",
    "aal",
    "authz_version",
    "cred_gen",
    "snapshot",
    "bound_ip",
    "bound_ua_sha256",
    "created_at",
    "last_seen_at",
    "absolute_expires_at",
    "terminated_at",
    "terminated_reason",
    "authz_version_at_auth",
];
pub(super) const HANDLE_COLS: &[&str] = &[
    "handle_sha256",
    "session_id",
    "host",
    "issued_aal",
    "created_at",
    "last_seen_at",
    "absolute_expires_at",
    "revoked_at",
    "revoked_reason",
];
pub(super) const TXN_COLS: &[&str] = &[
    "txn_sha256",
    "created_at",
    "expires_at",
    "app_id",
    "return_target",
    "bind_sha256",
    "portal_bind_sha256",
    "retry_bind_sha256",
    "client_ip",
    "ua_sha256",
    "provider_id",
    "state_sha256",
    "nonce",
    "pkce_verifier",
    "portal_session_id",
    "purpose",
    "conflicting_handle_sha256",
    "pending_identity",
    "recovery_depth",
    "consumed_at",
    "consumed_reason",
];
pub(super) const CODE_COLS: &[&str] = &[
    "code_sha256",
    "session_id",
    "host",
    "return_target",
    "client_ip",
    "bind_sha256",
    "issued_aal",
    "cred_gen",
    "recovery_depth",
    "created_at",
    "expires_at",
    "consumed_at",
    "consumed_reason",
];
pub(super) const EVENT_COLS: &[&str] = &[
    "event_id",
    "at",
    "kind",
    "outcome",
    "reason",
    "user_id",
    "session_id",
    "app_id",
    "provider_id",
    "client_ip",
    "ua_sha256",
    "ua_prefix",
    "request_id",
    "attrs",
];

// ---- encoding helpers --------------------------------------------------

pub(super) fn blob(d: &Digest) -> &[u8] {
    &d.0[..]
}

pub(super) fn opt_blob(d: &Option<Digest>) -> Option<&[u8]> {
    d.as_ref().map(blob)
}

pub(super) fn json_str<T: serde::Serialize>(v: &T) -> StoreResult<String> {
    serde_json::to_string(v).map_err(|_| StoreError::Corrupt("unserializable value".into()))
}

// ---- decoding helpers --------------------------------------------------

pub(super) fn ts(row: &Row<'_>, i: usize, col: &str) -> StoreResult<Timestamp> {
    let s: i64 = row.get(i)?;
    let _ = col;
    Ok(Timestamp::from_secs(s))
}

pub(super) fn opt_ts(row: &Row<'_>, i: usize) -> StoreResult<Option<Timestamp>> {
    let s: Option<i64> = row.get(i)?;
    Ok(s.map(Timestamp::from_secs))
}

pub(super) fn digest(row: &Row<'_>, i: usize, col: &str) -> StoreResult<Digest> {
    let b: Vec<u8> = row.get(i)?;
    Digest::from_slice(&b).ok_or_else(|| corrupt(col))
}

pub(super) fn opt_digest(row: &Row<'_>, i: usize, col: &str) -> StoreResult<Option<Digest>> {
    let b: Option<Vec<u8>> = row.get(i)?;
    match b {
        None => Ok(None),
        Some(b) => Digest::from_slice(&b).map(Some).ok_or_else(|| corrupt(col)),
    }
}

pub(super) fn ip(row: &Row<'_>, i: usize, col: &str) -> StoreResult<IpAddr> {
    let s: String = row.get(i)?;
    s.parse().map_err(|_| corrupt(col))
}

pub(super) fn json<T: serde::de::DeserializeOwned>(
    row: &Row<'_>,
    i: usize,
    col: &str,
) -> StoreResult<T> {
    let s: String = row.get(i)?;
    serde_json::from_str(&s).map_err(|_| corrupt(col))
}

pub(super) fn u64_of(row: &Row<'_>, i: usize, col: &str) -> StoreResult<u64> {
    let n: i64 = row.get(i)?;
    u64::try_from(n).map_err(|_| corrupt(col))
}

pub(super) fn u32_of(row: &Row<'_>, i: usize, col: &str) -> StoreResult<u32> {
    let n: i64 = row.get(i)?;
    u32::try_from(n).map_err(|_| corrupt(col))
}

fn aal_of(row: &Row<'_>, i: usize, col: &str) -> StoreResult<Aal> {
    let n: i64 = row.get(i)?;
    Aal::from_i64(n).ok_or_else(|| corrupt(col))
}

fn host_of(row: &Row<'_>, i: usize, col: &str) -> StoreResult<Host> {
    let s: String = row.get(i)?;
    Host::parse(&s).map_err(|_| corrupt(col))
}

fn email_of(row: &Row<'_>, i: usize, col: &str) -> StoreResult<Option<NormalizedEmail>> {
    let s: Option<String> = row.get(i)?;
    match s {
        None => Ok(None),
        Some(s) => NormalizedEmail::from_stored(&s)
            .map(Some)
            .ok_or_else(|| corrupt(col)),
    }
}

// ---- row mappers (offset-based so joins can reuse them) ----------------

pub(super) fn user(row: &Row<'_>, o: usize) -> StoreResult<User> {
    Ok(User {
        user_id: UserId::new(row.get::<_, String>(o)?),
        primary_email: email_of(row, o + 1, "users.primary_email")?,
        email_verified: row.get(o + 2)?,
        email_authoritative: row.get(o + 3)?,
        display_name: row.get(o + 4)?,
        username: row.get(o + 5)?,
        status: UserStatus::parse(&row.get::<_, String>(o + 6)?)
            .ok_or_else(|| corrupt("users.status"))?,
        authz_version: u64_of(row, o + 7, "users.authz_version")?,
        groups: json(row, o + 8, "users.groups")?,
        created_at: ts(row, o + 9, "users.created_at")?,
        updated_at: ts(row, o + 10, "users.updated_at")?,
        last_login_at: opt_ts(row, o + 11)?,
    })
}

/// `status, authz_version, groups` starting at `o`.
pub(super) fn user_authz(row: &Row<'_>, o: usize) -> StoreResult<UserAuthz> {
    Ok(UserAuthz {
        status: UserStatus::parse(&row.get::<_, String>(o)?)
            .ok_or_else(|| corrupt("users.status"))?,
        authz_version: u64_of(row, o + 1, "users.authz_version")?,
        groups: json(row, o + 2, "users.groups")?,
    })
}

pub(super) fn identity(row: &Row<'_>, o: usize) -> StoreResult<IdentityRow> {
    Ok(IdentityRow {
        provider_id: ProviderId::new(row.get::<_, String>(o)?),
        subject: row.get(o + 1)?,
        user_id: UserId::new(row.get::<_, String>(o + 2)?),
        email: email_of(row, o + 3, "identities.email")?,
        email_verified: row.get(o + 4)?,
        email_authoritative: row.get(o + 5)?,
        name: row.get(o + 6)?,
        picture: row.get(o + 7)?,
        first_seen_at: ts(row, o + 8, "identities.first_seen_at")?,
        last_seen_at: ts(row, o + 9, "identities.last_seen_at")?,
    })
}

pub(super) fn provider(row: &Row<'_>, o: usize) -> StoreResult<ProviderRow> {
    Ok(ProviderRow {
        provider_id: ProviderId::new(row.get::<_, String>(o)?),
        kind: ProviderKind::parse(&row.get::<_, String>(o + 1)?)
            .ok_or_else(|| corrupt("providers.kind"))?,
        display_name: row.get(o + 2)?,
        enabled: row.get(o + 3)?,
        managed_by: ManagedBy::parse(&row.get::<_, String>(o + 4)?)
            .ok_or_else(|| corrupt("providers.managed_by"))?,
        deleted_at: opt_ts(row, o + 5)?,
        sort_order: row.get(o + 6)?,
        config: json(row, o + 7, "providers.config")?,
        client_secret_env: row.get(o + 8)?,
        allowed_email_domains: json(row, o + 9, "providers.allowed_email_domains")?,
        authoritative_domains: json(row, o + 10, "providers.authoritative_domains")?,
        auto_link: row.get(o + 11)?,
        trust_email: row.get(o + 12)?,
    })
}

pub(super) fn session(row: &Row<'_>, o: usize) -> StoreResult<SessionRow> {
    let snapshot_json: serde_json::Value = json(row, o + 8, "sessions.snapshot")?;
    let snapshot = IdentitySnapshot {
        email: match snapshot_json.get("email") {
            Some(serde_json::Value::String(s)) => {
                Some(NormalizedEmail::from_stored(s).ok_or_else(|| corrupt("sessions.snapshot"))?)
            }
            _ => None,
        },
        display_name: snapshot_json
            .get("display_name")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        username: snapshot_json
            .get("username")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        groups: snapshot_json
            .get("groups")
            .map(|g| serde_json::from_value(g.clone()))
            .transpose()
            .map_err(|_| corrupt("sessions.snapshot"))?
            .unwrap_or_default(),
    };
    Ok(SessionRow {
        session_id: SessionId::new(row.get::<_, String>(o)?),
        user_id: UserId::new(row.get::<_, String>(o + 1)?),
        provider_id: ProviderId::new(row.get::<_, String>(o + 2)?),
        auth_time: ts(row, o + 3, "sessions.auth_time")?,
        factors: json::<Vec<FactorEntry>>(row, o + 4, "sessions.factors")?,
        aal: aal_of(row, o + 5, "sessions.aal")?,
        authz_version: u64_of(row, o + 6, "sessions.authz_version")?,
        cred_gen: u64_of(row, o + 7, "sessions.cred_gen")?,
        snapshot,
        bound_ip: ip(row, o + 9, "sessions.bound_ip")?,
        bound_ua_sha256: opt_digest(row, o + 10, "sessions.bound_ua_sha256")?,
        created_at: ts(row, o + 11, "sessions.created_at")?,
        last_seen_at: ts(row, o + 12, "sessions.last_seen_at")?,
        absolute_expires_at: ts(row, o + 13, "sessions.absolute_expires_at")?,
        terminated_at: opt_ts(row, o + 14)?,
        terminated_reason: row.get(o + 15)?,
        authz_version_at_auth: u64_of(row, o + 16, "sessions.authz_version_at_auth")?,
    })
}

pub(super) fn snapshot_json(s: &IdentitySnapshot) -> serde_json::Value {
    serde_json::json!({
        "email": s.email.as_ref().map(|e| e.as_str()),
        "display_name": s.display_name,
        "username": s.username,
        "groups": s.groups,
    })
}

pub(super) fn handle(row: &Row<'_>, o: usize) -> StoreResult<HandleRow> {
    Ok(HandleRow {
        handle_sha256: digest(row, o, "session_handles.handle_sha256")?,
        session_id: SessionId::new(row.get::<_, String>(o + 1)?),
        host: host_of(row, o + 2, "session_handles.host")?,
        issued_aal: aal_of(row, o + 3, "session_handles.issued_aal")?,
        created_at: ts(row, o + 4, "session_handles.created_at")?,
        last_seen_at: ts(row, o + 5, "session_handles.last_seen_at")?,
        absolute_expires_at: ts(row, o + 6, "session_handles.absolute_expires_at")?,
        revoked_at: opt_ts(row, o + 7)?,
        revoked_reason: row.get(o + 8)?,
    })
}

pub(super) fn txn(row: &Row<'_>, o: usize) -> StoreResult<TransactionRow> {
    let target: String = row.get(o + 4)?;
    let pkce: Option<String> = row.get(o + 13)?;
    let pending: Option<String> = row.get(o + 17)?;
    Ok(TransactionRow {
        txn_sha256: digest(row, o, "login_txns.txn_sha256")?,
        created_at: ts(row, o + 1, "login_txns.created_at")?,
        expires_at: ts(row, o + 2, "login_txns.expires_at")?,
        app_id: AppId::new(row.get::<_, String>(o + 3)?),
        return_target: url::Url::parse(&target).map_err(|_| corrupt("login_txns.return_target"))?,
        bind_sha256: opt_digest(row, o + 5, "login_txns.bind_sha256")?,
        portal_bind_sha256: opt_digest(row, o + 6, "login_txns.portal_bind_sha256")?,
        retry_bind_sha256: opt_digest(row, o + 7, "login_txns.retry_bind_sha256")?,
        client_ip: ip(row, o + 8, "login_txns.client_ip")?,
        ua_sha256: opt_digest(row, o + 9, "login_txns.ua_sha256")?,
        provider_id: row.get::<_, Option<String>>(o + 10)?.map(ProviderId::new),
        state_sha256: opt_digest(row, o + 11, "login_txns.state_sha256")?,
        nonce: row.get(o + 12)?,
        pkce_verifier: pkce.map(Secret::new),
        portal_session_id: row.get::<_, Option<String>>(o + 14)?.map(SessionId::new),
        purpose: TxnPurpose::parse(&row.get::<_, String>(o + 15)?)
            .ok_or_else(|| corrupt("login_txns.purpose"))?,
        conflicting_handle_sha256: opt_digest(row, o + 16, "login_txns.conflicting_handle_sha256")?,
        pending_identity: pending
            .map(|p| serde_json::from_str(&p))
            .transpose()
            .map_err(|_| corrupt("login_txns.pending_identity"))?,
        recovery_depth: u32_of(row, o + 18, "login_txns.recovery_depth")?,
        consumed_at: opt_ts(row, o + 19)?,
        consumed_reason: row.get(o + 20)?,
    })
}

pub(super) fn code(row: &Row<'_>, o: usize) -> StoreResult<HandoffCodeRow> {
    let target: String = row.get(o + 3)?;
    Ok(HandoffCodeRow {
        code_sha256: digest(row, o, "handoff_codes.code_sha256")?,
        session_id: SessionId::new(row.get::<_, String>(o + 1)?),
        host: host_of(row, o + 2, "handoff_codes.host")?,
        return_target: url::Url::parse(&target)
            .map_err(|_| corrupt("handoff_codes.return_target"))?,
        client_ip: ip(row, o + 4, "handoff_codes.client_ip")?,
        bind_sha256: digest(row, o + 5, "handoff_codes.bind_sha256")?,
        issued_aal: aal_of(row, o + 6, "handoff_codes.issued_aal")?,
        cred_gen: u64_of(row, o + 7, "handoff_codes.cred_gen")?,
        recovery_depth: u32_of(row, o + 8, "handoff_codes.recovery_depth")?,
        created_at: ts(row, o + 9, "handoff_codes.created_at")?,
        expires_at: ts(row, o + 10, "handoff_codes.expires_at")?,
        consumed_at: opt_ts(row, o + 11)?,
        consumed_reason: row.get(o + 12)?,
    })
}

pub(super) fn event(row: &Row<'_>, o: usize) -> StoreResult<Event> {
    let at: f64 = row.get(o + 1)?;
    let kind: String = row.get(o + 2)?;
    let outcome: String = row.get(o + 3)?;
    let reason: Option<String> = row.get(o + 4)?;
    let client_ip: Option<String> = row.get(o + 9)?;
    let attrs: String = row.get(o + 13)?;
    Ok(Event {
        event_id: EventId::new(row.get::<_, String>(o)?),
        at: Timestamp((at * 1000.0).round() as i64),
        kind: EventKind::from_name(&kind).ok_or_else(|| corrupt("events.kind"))?,
        outcome: Outcome::parse(&outcome).ok_or_else(|| corrupt("events.outcome"))?,
        reason: reason.and_then(|r| reasons::parse(&r)),
        user_id: row.get::<_, Option<String>>(o + 5)?.map(UserId::new),
        session_id: row.get::<_, Option<String>>(o + 6)?.map(SessionId::new),
        app_id: row.get::<_, Option<String>>(o + 7)?.map(AppId::new),
        provider_id: row.get::<_, Option<String>>(o + 8)?.map(ProviderId::new),
        client_ip: client_ip
            .map(|s| s.parse().map_err(|_| corrupt("events.client_ip")))
            .transpose()?,
        ua_sha256: opt_digest(row, o + 10, "events.ua_sha256")?,
        ua_prefix: row.get(o + 11)?,
        request_id: row.get(o + 12)?,
        attrs: serde_json::from_str(&attrs).map_err(|_| corrupt("events.attrs"))?,
    })
}
