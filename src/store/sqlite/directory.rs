//! `Directory` for SQLite: users, identities, providers and the
//! configuration generation.

use async_trait::async_trait;
use rusqlite::{Connection, OptionalExtension, params};

use super::events::insert_events;
use super::rows::{self, IDENTITY_COLS, PROVIDER_COLS, USER_COLS, cols};
use super::{Store, commit};
use crate::crypto::{Timestamp, random_id};
use crate::event::types::Event;
use crate::identity::types::{NormalizedEmail, UserId};
use crate::provider::types::ProviderId;
use crate::store::types::*;
use crate::store::{Directory, StoreError, StoreResult};

/// Largest serialized `raw_claims` stored (ADR-0010: bounded 8 KiB).
const RAW_CLAIMS_MAX: usize = 8192;

fn bounded_claims(v: &serde_json::Value) -> String {
    match serde_json::to_string(v) {
        Ok(s) if s.len() <= RAW_CLAIMS_MAX => s,
        _ => r#"{"truncated":true}"#.to_string(),
    }
}

fn insert_identity(
    conn: &Connection,
    user: &UserId,
    i: &NewIdentity,
    now: Timestamp,
) -> StoreResult<()> {
    let exists: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM identities WHERE provider_id=?1 AND subject=?2",
            params![i.provider_id.as_str(), i.subject],
            |r| r.get(0),
        )
        .optional()?;
    if exists.is_some() {
        return Err(StoreError::Conflict("identity already exists"));
    }
    conn.execute(
        "INSERT INTO identities (provider_id, subject, user_id, email, email_verified, email_authoritative, name, picture, raw_claims, first_seen_at, last_seen_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?10)",
        params![
            i.provider_id.as_str(),
            i.subject,
            user.as_str(),
            i.email.as_ref().map(|e| e.as_str()),
            i.email_verified,
            i.email_authoritative,
            i.name,
            i.picture,
            bounded_claims(&i.raw_claims),
            now.secs(),
        ],
    )?;
    Ok(())
}

#[async_trait]
impl Directory for Store {
    async fn user(&self, id: &UserId) -> StoreResult<Option<User>> {
        let id = id.to_string();
        self.read("user", move |c| {
            let sql = format!("SELECT {} FROM users WHERE user_id=?1", cols("", USER_COLS));
            c.query_row(&sql, [&id], |r| Ok(rows::user(r, 0)))
                .optional()?
                .transpose()
        })
        .await
    }

    async fn user_authz(&self, id: &UserId) -> StoreResult<Option<UserAuthz>> {
        let id = id.to_string();
        self.read("user_authz", move |c| {
            c.query_row(
                "SELECT status, authz_version, groups FROM users WHERE user_id=?1",
                [&id],
                |r| Ok(rows::user_authz(r, 0)),
            )
            .optional()?
            .transpose()
        })
        .await
    }

    async fn identity(
        &self,
        provider: &ProviderId,
        subject: &str,
    ) -> StoreResult<Option<IdentityRow>> {
        let (p, s) = (provider.to_string(), subject.to_string());
        self.read("identity", move |c| {
            let sql = format!(
                "SELECT {} FROM identities WHERE provider_id=?1 AND subject=?2",
                cols("", IDENTITY_COLS)
            );
            c.query_row(&sql, params![p, s], |r| Ok(rows::identity(r, 0)))
                .optional()?
                .transpose()
        })
        .await
    }

    async fn user_by_email(&self, email: &NormalizedEmail) -> StoreResult<Option<User>> {
        let email = email.to_string();
        self.read("user_by_email", move |c| {
            let sql = format!(
                "SELECT {} FROM users WHERE primary_email=?1 ORDER BY created_at, user_id LIMIT 1",
                cols("", USER_COLS)
            );
            c.query_row(&sql, [&email], |r| Ok(rows::user(r, 0)))
                .optional()?
                .transpose()
        })
        .await
    }

    async fn create_user(
        &self,
        user: NewUser,
        identity: NewIdentity,
        events: Vec<Event>,
    ) -> StoreResult<User> {
        self.write("create_user", move |env| {
            let shared = env.shared.clone();
            let now = Timestamp::from_secs(shared.clock.now().secs());
            let tx = env.begin()?;
            let id = UserId::new(random_id(&*shared.rng(), "u_"));
            if let Some(name) = &user.username {
                let taken: Option<i64> = tx
                    .query_row("SELECT 1 FROM users WHERE username=?1", [name], |r| r.get(0))
                    .optional()?;
                if taken.is_some() {
                    return Err(StoreError::Conflict("username already taken"));
                }
            }
            super::require_provider_live(&tx, identity.provider_id.as_str())?;
            insert_identity_guard(&tx, &identity)?;
            tx.execute(
                "INSERT INTO users (user_id, primary_email, email_verified, email_authoritative, display_name, username, status, authz_version, groups, created_at, updated_at) VALUES (?1,?2,?3,?4,?5,?6,'active',1,'[]',?7,?7)",
                params![
                    id.as_str(),
                    user.primary_email.as_ref().map(|e| e.as_str()),
                    user.email_verified,
                    user.email_authoritative,
                    user.display_name,
                    user.username,
                    now.secs(),
                ],
            )?;
            insert_identity(&tx, &id, &identity, now)?;
            insert_events(&tx, &shared, &events)?;
            commit(tx, &shared, Some("create_user"))?;
            Ok(User {
                user_id: id,
                primary_email: user.primary_email,
                email_verified: user.email_verified,
                email_authoritative: user.email_authoritative,
                display_name: user.display_name,
                username: user.username,
                status: UserStatus::Active,
                authz_version: 1,
                groups: Vec::new(),
                created_at: now,
                updated_at: now,
                last_login_at: None,
            })
        })
        .await
    }

    async fn link_identity(
        &self,
        user: &UserId,
        identity: NewIdentity,
        events: Vec<Event>,
    ) -> StoreResult<()> {
        let user = user.clone();
        self.write("link_identity", move |env| {
            let shared = env.shared.clone();
            let now = shared.clock.now();
            let tx = env.begin()?;
            let exists: Option<i64> = tx
                .query_row(
                    "SELECT 1 FROM users WHERE user_id=?1",
                    [user.as_str()],
                    |r| r.get(0),
                )
                .optional()?;
            if exists.is_none() {
                return Err(StoreError::Conflict("unknown user"));
            }
            super::require_provider_live(&tx, identity.provider_id.as_str())?;
            insert_identity(&tx, &user, &identity, now)?;
            insert_events(&tx, &shared, &events)?;
            commit(tx, &shared, None)
        })
        .await
    }

    async fn touch_identity(
        &self,
        provider: &ProviderId,
        subject: &str,
        seen: &NewIdentity,
        at: Timestamp,
    ) -> StoreResult<()> {
        let (p, s, seen) = (provider.to_string(), subject.to_string(), seen.clone());
        self.write("touch_identity", move |env| {
            let n = env.conn.execute(
                "UPDATE identities SET email=?3, email_verified=?4, email_authoritative=?5, name=?6, picture=?7, last_seen_at=?8 WHERE provider_id=?1 AND subject=?2",
                params![
                    p,
                    s,
                    seen.email.as_ref().map(|e| e.as_str()),
                    seen.email_verified,
                    seen.email_authoritative,
                    seen.name,
                    seen.picture,
                    at.secs(),
                ],
            )?;
            if n == 0 {
                return Err(StoreError::Conflict("unknown identity"));
            }
            Ok(())
        })
        .await
    }

    async fn providers(&self) -> StoreResult<Vec<ProviderRow>> {
        self.read("providers", |c| {
            let sql = format!(
                "SELECT {} FROM providers ORDER BY sort_order, provider_id",
                cols("", PROVIDER_COLS)
            );
            let mut stmt = c.prepare(&sql)?;
            let mut q = stmt.query([])?;
            let mut out = Vec::new();
            while let Some(r) = q.next()? {
                out.push(rows::provider(r, 0)?);
            }
            Ok(out)
        })
        .await
    }

    async fn import_providers(
        &self,
        from_file: Vec<ProviderRow>,
        force: Option<&ProviderId>,
        events: Vec<Event>,
    ) -> StoreResult<ImportReport> {
        let force = force.cloned();
        self.write("import_providers", move |env| {
            let shared = env.shared.clone();
            let now = shared.clock.now().secs();
            if let Some(f) = &force
                && !from_file.iter().any(|r| &r.provider_id == f)
            {
                return Err(StoreError::Conflict(
                    "force names a provider the file does not list",
                ));
            }
            let tx = env.begin()?;
            let mut report = ImportReport::default();
            for r in &from_file {
                let existing: Option<(String, Option<i64>)> = tx
                    .query_row(
                        "SELECT managed_by, deleted_at FROM providers WHERE provider_id=?1",
                        [r.provider_id.as_str()],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .optional()?;
                let id = r.provider_id.clone();
                let forced = force.as_ref() == Some(&id);
                match existing {
                    None => {
                        write_provider(&tx, r, now, true)?;
                        report.inserted.push(id);
                    }
                    Some(_) if forced => {
                        write_provider(&tx, r, now, false)?;
                        report.forced.push(id);
                    }
                    Some((_, Some(_))) => report.skipped_deleted.push(id),
                    Some((managed, None)) if managed == "file" => {
                        write_provider(&tx, r, now, false)?;
                        report.updated.push(id);
                    }
                    Some(_) => report.skipped_api_managed.push(id),
                }
            }
            insert_events(&tx, &shared, &events)?;
            commit(tx, &shared, None)?;
            Ok(report)
        })
        .await
    }

    async fn bump_config_generation(&self) -> StoreResult<u64> {
        self.write("bump_config_generation", |env| {
            let n: i64 = env.conn.query_row(
                "INSERT INTO meta (key, value) VALUES ('config_generation', '1') ON CONFLICT(key) DO UPDATE SET value = CAST(CAST(value AS INTEGER) + 1 AS TEXT) RETURNING CAST(value AS INTEGER)",
                [],
                |r| r.get(0),
            )?;
            u64::try_from(n).map_err(|_| StoreError::Corrupt("column meta.value".into()))
        })
        .await
    }

    async fn config_generation(&self) -> StoreResult<u64> {
        self.read("config_generation", |c| {
            let v: Option<String> = c
                .query_row(
                    "SELECT value FROM meta WHERE key='config_generation'",
                    [],
                    |r| r.get(0),
                )
                .optional()?;
            match v {
                None => Ok(0),
                Some(s) => s
                    .parse()
                    .map_err(|_| StoreError::Corrupt("column meta.value".into())),
            }
        })
        .await
    }
}

/// Reject a duplicate (provider, subject) before touching `users`.
fn insert_identity_guard(conn: &Connection, i: &NewIdentity) -> StoreResult<()> {
    let exists: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM identities WHERE provider_id=?1 AND subject=?2",
            params![i.provider_id.as_str(), i.subject],
            |r| r.get(0),
        )
        .optional()?;
    if exists.is_some() {
        return Err(StoreError::Conflict("identity already exists"));
    }
    Ok(())
}

/// Insert (`insert = true`) or overwrite a provider row as file-managed and not deleted.
fn write_provider(conn: &Connection, r: &ProviderRow, now: i64, insert: bool) -> StoreResult<()> {
    let config = rows::json_str(&r.config)?;
    let allowed = rows::json_str(&r.allowed_email_domains)?;
    let authoritative = rows::json_str(&r.authoritative_domains)?;
    if insert {
        conn.execute(
            "INSERT INTO providers (provider_id, kind, display_name, enabled, managed_by, deleted_at, sort_order, config, client_secret_env, allowed_email_domains, authoritative_domains, auto_link, trust_email, created_at, updated_at) VALUES (?1,?2,?3,?4,'file',NULL,?5,?6,?7,?8,?9,?10,?11,?12,?12)",
            params![
                r.provider_id.as_str(), r.kind.as_str(), r.display_name, r.enabled, r.sort_order,
                config, r.client_secret_env, allowed, authoritative, r.auto_link, r.trust_email, now,
            ],
        )?;
    } else {
        conn.execute(
            "UPDATE providers SET kind=?2, display_name=?3, enabled=?4, managed_by='file', deleted_at=NULL, sort_order=?5, config=?6, client_secret_env=?7, allowed_email_domains=?8, authoritative_domains=?9, auto_link=?10, trust_email=?11, updated_at=?12 WHERE provider_id=?1",
            params![
                r.provider_id.as_str(), r.kind.as_str(), r.display_name, r.enabled, r.sort_order,
                config, r.client_secret_env, allowed, authoritative, r.auto_link, r.trust_email, now,
            ],
        )?;
    }
    Ok(())
}

impl Store {
    /// Mirror the configured applications into the `apps` table (informational:
    /// verify reads the in-memory snapshot, never this table).
    pub async fn mirror_apps(&self, apps: &[crate::policy::types::AppPolicy]) -> StoreResult<()> {
        let apps = apps.to_vec();
        self.write("mirror_apps", move |env| {
            let shared = env.shared.clone();
            let now = shared.clock.now().secs();
            let tx = env.begin()?;
            let keep: Vec<String> = apps.iter().map(|a| a.app_id.to_string()).collect();
            for a in &apps {
                let hosts: Vec<&str> = a.hosts.iter().map(|h| h.as_str()).collect();
                let session = serde_json::json!({"idle_secs": a.session.idle.as_secs(), "absolute_secs": a.session.absolute.as_secs()});
                let binding = serde_json::json!({
                    "ip": format!("{:?}", a.binding.ip),
                    "ua": format!("{:?}", a.binding.ua),
                    "on_mismatch": format!("{:?}", a.binding.on_mismatch),
                });
                let step_up: Vec<serde_json::Value> = a.step_up.iter().map(|r| serde_json::json!({
                    "path_prefix": r.path_prefix, "aal": r.aal.as_i64(), "max_age_secs": r.max_age.map(|d| d.as_secs()),
                })).collect();
                tx.execute(
                    "INSERT INTO apps (app_id, display_name, hosts, ports, enabled, session_policy, binding_policy, step_up, on_authz_change, created_at, updated_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?10) ON CONFLICT(app_id) DO UPDATE SET display_name=excluded.display_name, hosts=excluded.hosts, ports=excluded.ports, enabled=excluded.enabled, session_policy=excluded.session_policy, binding_policy=excluded.binding_policy, step_up=excluded.step_up, on_authz_change=excluded.on_authz_change, updated_at=excluded.updated_at",
                    params![
                        a.app_id.as_str(), a.display_name, rows::json_str(&hosts)?, rows::json_str(&a.ports)?, a.enabled,
                        session.to_string(), binding.to_string(), rows::json_str(&step_up)?,
                        match a.on_authz_change { crate::policy::types::AuthzChange::Refresh => "refresh", crate::policy::types::AuthzChange::Terminate => "terminate" },
                        now,
                    ],
                )?;
            }
            // Applications removed from the file disappear from the mirror.
            let mut stmt = tx.prepare("SELECT app_id FROM apps")?;
            let existing: Vec<String> = stmt.query_map([], |r| r.get(0))?.collect::<Result<_, _>>()?;
            drop(stmt);
            for id in existing.into_iter().filter(|e| !keep.contains(e)) {
                tx.execute("DELETE FROM apps WHERE app_id=?1", [&id])?;
            }
            commit(tx, &shared, None)
        })
        .await
    }
}
