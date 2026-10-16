//! Route-scoped, read-only service credentials of the admin listener
//! (`service_credentials`, schema 15). Only digests of secrets are stored;
//! every change commits with its `admin.service_credential` event.
use rusqlite::{OptionalExtension, params};

use super::events::insert_events;
use super::{Store, commit};
use crate::event::types::Event;
use crate::store::{Deadline, StoreError, StoreResult};

/// One credential row. `routes` are `"METHOD /path"` strings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceCredentialRow {
    pub credential_id: String,
    pub routes: Vec<String>,
    pub audiences: Vec<String>,
    pub client_spki_sha256: Option<String>,
    pub client_san: Option<String>,
    pub current_sha256: String,
    pub current_since: i64,
    pub next_sha256: Option<String>,
    pub next_since: Option<i64>,
    pub expires_at: i64,
    pub rate_per_minute: u32,
    pub burst: u32,
    pub note: Option<String>,
    pub created_at: i64,
    pub revoked_at: Option<i64>,
    pub revision: i64,
}

const COLS: &str = "credential_id,routes,audiences,client_spki_sha256,client_san,current_sha256,current_since,next_sha256,next_since,expires_at,rate_per_minute,burst,note,created_at,revoked_at,revision";

fn corrupt(c: &str) -> StoreError {
    StoreError::Corrupt(format!("service_credentials.{c}"))
}

fn row(r: &rusqlite::Row<'_>) -> StoreResult<ServiceCredentialRow> {
    let list = |i: usize, c: &str| -> StoreResult<Vec<String>> {
        let s: String = r.get(i)?;
        serde_json::from_str(&s).map_err(|_| corrupt(c))
    };
    Ok(ServiceCredentialRow {
        credential_id: r.get(0)?,
        routes: list(1, "routes")?,
        audiences: list(2, "audiences")?,
        client_spki_sha256: r.get(3)?,
        client_san: r.get(4)?,
        current_sha256: r.get(5)?,
        current_since: r.get(6)?,
        next_sha256: r.get(7)?,
        next_since: r.get(8)?,
        expires_at: r.get(9)?,
        rate_per_minute: r.get(10)?,
        burst: r.get(11)?,
        note: r.get(12)?,
        created_at: r.get(13)?,
        revoked_at: r.get(14)?,
        revision: r.get(15)?,
    })
}

/// What a change did, for the CLI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Change {
    Rotate,
    Promote,
    Revoke,
}

impl Store {
    /// One credential (tombstones included).
    pub async fn service_credential_get(
        &self,
        id: String,
        deadline: Deadline,
    ) -> StoreResult<Option<ServiceCredentialRow>> {
        self.read_checked("service_credential_get", Some(deadline), move |c, _| {
            c.prepare_cached(&format!(
                "SELECT {COLS} FROM service_credentials WHERE credential_id = ?1"
            ))?
            .query_row([id], |r| Ok(row(r)))
            .optional()?
            .transpose()
        })
        .await
    }

    /// Every credential, by id.
    pub async fn service_credential_list(&self) -> StoreResult<Vec<ServiceCredentialRow>> {
        self.read_checked("service_credential_list", None, move |c, _| {
            let mut st = c.prepare(&format!(
                "SELECT {COLS} FROM service_credentials ORDER BY credential_id LIMIT 1024"
            ))?;
            let rows = st
                .query_map([], |r| Ok(row(r)))?
                .collect::<Result<Vec<_>, _>>()?;
            rows.into_iter().collect()
        })
        .await
    }

    /// Insert a new credential; an existing id (live or revoked) is a conflict.
    pub async fn service_credential_create(
        &self,
        r: ServiceCredentialRow,
        events: Vec<Event>,
    ) -> StoreResult<()> {
        self.write("service_credential_create", move |env| {
            let shared = env.shared.clone();
            let tx = env.begin()?;
            let exists: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM service_credentials WHERE credential_id = ?1)",
                [&r.credential_id],
                |q| q.get(0),
            )?;
            if exists {
                return Err(StoreError::Conflict("service credential exists"));
            }
            tx.execute(
                &format!("INSERT INTO service_credentials ({COLS}) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,NULL,1)"),
                params![
                    r.credential_id,
                    serde_json::to_string(&r.routes).map_err(|_| corrupt("routes"))?,
                    serde_json::to_string(&r.audiences).map_err(|_| corrupt("audiences"))?,
                    r.client_spki_sha256,
                    r.client_san,
                    r.current_sha256,
                    r.current_since,
                    r.next_sha256,
                    r.next_since,
                    r.expires_at,
                    r.rate_per_minute,
                    r.burst,
                    r.note,
                    r.created_at,
                ],
            )?;
            insert_events(&tx, &shared, &events)?;
            commit(tx, &shared, None)
        })
        .await
    }

    /// Rotate (`next` = `digest`; refused while a rotation is pending),
    /// promote (`current` = `next`) or revoke. Revoked credentials refuse
    /// every change.
    pub async fn service_credential_change(
        &self,
        id: String,
        change: Change,
        digest: Option<String>,
        events: Vec<Event>,
    ) -> StoreResult<ServiceCredentialRow> {
        self.write("service_credential_change", move |env| {
            let shared = env.shared.clone();
            let now = shared.clock.now().secs();
            let tx = env.begin()?;
            let current = tx
                .prepare(&format!(
                    "SELECT {COLS} FROM service_credentials WHERE credential_id = ?1"
                ))?
                .query_row([&id], |r| Ok(row(r)))
                .optional()?
                .transpose()?
                .ok_or(StoreError::Conflict("no such service credential"))?;
            if current.revoked_at.is_some() {
                return Err(StoreError::Conflict("service credential revoked"));
            }
            let changed = match change {
                Change::Rotate => {
                    if current.next_sha256.is_some() {
                        return Err(StoreError::Conflict("rotation pending"));
                    }
                    let digest = digest.ok_or(StoreError::Conflict("missing digest"))?;
                    tx.execute(
                        "UPDATE service_credentials SET next_sha256=?2,next_since=?3,revision=revision+1 WHERE credential_id=?1",
                        params![id, digest, now],
                    )?
                }
                Change::Promote => {
                    if current.next_sha256.is_none() {
                        return Err(StoreError::Conflict("no rotation pending"));
                    }
                    tx.execute(
                        "UPDATE service_credentials SET current_sha256=next_sha256,current_since=next_since,next_sha256=NULL,next_since=NULL,revision=revision+1 WHERE credential_id=?1",
                        [&id],
                    )?
                }
                Change::Revoke => tx.execute(
                    "UPDATE service_credentials SET revoked_at=?2,next_sha256=NULL,next_since=NULL,revision=revision+1 WHERE credential_id=?1",
                    params![id, now],
                )?,
            };
            if changed != 1 {
                return Err(StoreError::Conflict("service credential changed"));
            }
            insert_events(&tx, &shared, &events)?;
            let after = tx
                .prepare(&format!(
                    "SELECT {COLS} FROM service_credentials WHERE credential_id = ?1"
                ))?
                .query_row([&id], |r| Ok(row(r)))?
                ?;
            commit(tx, &shared, None)?;
            Ok(after)
        })
        .await
    }
}
