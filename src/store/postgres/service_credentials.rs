//! Route-scoped, read-only service credentials on PostgreSQL (schema 8), as
//! SQLite's `store::sqlite::service_credentials`: digests only, every change
//! committed with its `admin.service_credential` event; a change locks the
//! credential's row, so concurrent rotations on two replicas serialize.
use super::admin::deadline_err;
use super::{PgStore, pg, retry};
use crate::event::types::Event;
use crate::store::sqlite::service_credentials::{Change, ServiceCredentialRow};
use crate::store::{Deadline, StoreError, StoreResult};

const COLS: &str = "credential_id, routes, audiences, client_spki_sha256, client_san, current_sha256, current_since, next_sha256, next_since, expires_at, rate_per_minute, burst, note, created_at, revoked_at, revision";

fn corrupt(c: &str) -> StoreError {
    StoreError::Corrupt(format!("service_credentials.{c}"))
}

fn row(r: &tokio_postgres::Row) -> StoreResult<ServiceCredentialRow> {
    let list = |i: usize, c: &str| -> StoreResult<Vec<String>> {
        serde_json::from_str(&r.get::<_, String>(i)).map_err(|_| corrupt(c))
    };
    let small = |i: usize, c: &str| u32::try_from(r.get::<_, i64>(i)).map_err(|_| corrupt(c));
    Ok(ServiceCredentialRow {
        credential_id: r.get(0),
        routes: list(1, "routes")?,
        audiences: list(2, "audiences")?,
        client_spki_sha256: r.get(3),
        client_san: r.get(4),
        current_sha256: r.get(5),
        current_since: r.get(6),
        next_sha256: r.get(7),
        next_since: r.get(8),
        expires_at: r.get(9),
        rate_per_minute: small(10, "rate_per_minute")?,
        burst: small(11, "burst")?,
        note: r.get(12),
        created_at: r.get(13),
        revoked_at: r.get(14),
        revision: r.get(15),
    })
}

impl PgStore {
    /// One credential (tombstones included).
    pub async fn service_credential_get(
        &self,
        id: String,
        deadline: Deadline,
    ) -> StoreResult<Option<ServiceCredentialRow>> {
        let out = async {
            let mut client = self.client().await?;
            let tx = self.read_within(&mut client, deadline).await?;
            let found = tx
                .query_opt(
                    &format!("SELECT {COLS} FROM service_credentials WHERE credential_id = $1"),
                    &[&id],
                )
                .await
                .map_err(pg)?
                .map(|r| row(&r))
                .transpose()?;
            tx.commit().await.map_err(pg)?;
            Ok(found)
        }
        .await;
        out.map_err(deadline_err)
    }

    /// Every credential, by id.
    pub async fn service_credential_list(&self) -> StoreResult<Vec<ServiceCredentialRow>> {
        let client = self.client().await?;
        client
            .query(
                &format!(
                    "SELECT {COLS} FROM service_credentials ORDER BY credential_id COLLATE \"C\" LIMIT 1024"
                ),
                &[],
            )
            .await
            .map_err(pg)?
            .iter()
            .map(row)
            .collect()
    }

    /// Insert a new credential; an existing id (live or revoked) is a conflict.
    pub async fn service_credential_create(
        &self,
        r: ServiceCredentialRow,
        events: Vec<Event>,
    ) -> StoreResult<()> {
        let routes = serde_json::to_string(&r.routes).map_err(|_| corrupt("routes"))?;
        let audiences = serde_json::to_string(&r.audiences).map_err(|_| corrupt("audiences"))?;
        retry(|| async {
            let mut client = self.client().await?;
            let tx = self.begin(&mut client).await?;
            let n = tx
                .execute(
                    &format!(
                        "INSERT INTO service_credentials ({COLS}) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,NULL,1) \
                         ON CONFLICT (credential_id) DO NOTHING"
                    ),
                    &[
                        &r.credential_id,
                        &routes,
                        &audiences,
                        &r.client_spki_sha256,
                        &r.client_san,
                        &r.current_sha256,
                        &r.current_since,
                        &r.next_sha256,
                        &r.next_since,
                        &r.expires_at,
                        &i64::from(r.rate_per_minute),
                        &i64::from(r.burst),
                        &r.note,
                        &r.created_at,
                    ],
                )
                .await
                .map_err(pg)?;
            if n != 1 {
                return Err(StoreError::Conflict("service credential exists"));
            }
            self.insert_events(&tx, &events).await?;
            tx.commit().await.map_err(pg)
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
        retry(|| async {
            let mut client = self.client().await?;
            let tx = self.begin(&mut client).await?;
            let now = self.now().secs();
            let current = tx
                .query_opt(
                    &format!(
                        "SELECT {COLS} FROM service_credentials WHERE credential_id = $1 FOR UPDATE"
                    ),
                    &[&id],
                )
                .await
                .map_err(pg)?
                .map(|r| row(&r))
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
                    let digest = digest
                        .clone()
                        .ok_or(StoreError::Conflict("missing digest"))?;
                    tx.execute(
                        "UPDATE service_credentials SET next_sha256 = $2, next_since = $3, revision = revision + 1 WHERE credential_id = $1",
                        &[&id, &digest, &now],
                    )
                    .await
                }
                Change::Promote => {
                    if current.next_sha256.is_none() {
                        return Err(StoreError::Conflict("no rotation pending"));
                    }
                    tx.execute(
                        "UPDATE service_credentials SET current_sha256 = next_sha256, current_since = next_since, \
                         next_sha256 = NULL, next_since = NULL, revision = revision + 1 WHERE credential_id = $1",
                        &[&id],
                    )
                    .await
                }
                Change::Revoke => {
                    tx.execute(
                        "UPDATE service_credentials SET revoked_at = $2, next_sha256 = NULL, next_since = NULL, revision = revision + 1 \
                         WHERE credential_id = $1",
                        &[&id, &now],
                    )
                    .await
                }
            }
            .map_err(pg)?;
            if changed != 1 {
                return Err(StoreError::Conflict("service credential changed"));
            }
            self.insert_events(&tx, &events).await?;
            let after = row(
                &tx.query_one(
                    &format!("SELECT {COLS} FROM service_credentials WHERE credential_id = $1"),
                    &[&id],
                )
                .await
                .map_err(pg)?,
            )?;
            tx.commit().await.map_err(pg)?;
            Ok(after)
        })
        .await
    }
}
