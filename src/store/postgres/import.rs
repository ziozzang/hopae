//! One-way migration of a SQLite store into an empty PostgreSQL store
//! (ADR-0020 slice 4).
//!
//! * The SQLite file is opened read-only, inside one read transaction (a
//!   consistent snapshot), and is never written: it stays as the rollback
//!   artefact.
//! * The target must be empty: no row in any store table and no realm. A
//!   non-empty target is refused before anything is written.
//! * Every SQLite table with rows must have a PostgreSQL counterpart holding
//!   every one of its columns; otherwise the migration is refused (never a
//!   silent loss).
//! * The copy runs in one PostgreSQL transaction. Before it commits, each
//!   table's row count and a SHA-256 digest of its canonical rows are taken
//!   on both sides and must be equal; a `store.migrated` event (with every
//!   delivery row) commits with the data.
//!
//! Trigger-maintained tables (the reservation ledger, provider and material
//! owners, the external proof budget) are copied as they are: the triggers
//! that would recompute them are disabled for the duration of the
//! transaction only. Positions that PostgreSQL numbers itself (ledger and
//! lifecycle-feed positions, claim order) follow SQLite's insertion order;
//! feed consumers take a new snapshot after a migration.
use std::collections::BTreeMap;
use std::path::Path;

use deadpool_postgres::Transaction;
use rusqlite::types::Value;
use sha2::{Digest as _, Sha256};
use tokio_postgres::types::{ToSql, Type};

use super::{PgStore, pg};
use crate::event::types::{EventBuilder, EventKind, Outcome};
use crate::store::{StoreError, StoreResult};

/// Copy order (foreign keys first). Tables not named here and not internal
/// must be empty in the source.
const TABLES: &[&str] = &[
    "providers",
    "human_user_ids",
    "users",
    "identities",
    "admin_grants",
    "apps",
    "sessions",
    "session_handles",
    "login_txns",
    "txn_admissions",
    "handoff_codes",
    "events",
    "event_deliveries",
    "totp_enrollments",
    "external_factor_authorities",
    "external_factor_sessions",
    "external_factor_proofs",
    "external_factor_budget",
    "session_totp_provenance",
    "webauthn_credentials",
    "webauthn_challenges",
    "recovery_codes",
    "session_webauthn_elevations",
    "session_webauthn_provenance",
    "webauthn_login_challenges",
    "directory_groups",
    "group_members",
    "group_changes",
    "group_sync_state",
    "human_authority_realm",
    "human_provider_owners",
    "human_provider_material_owners",
    "session_primary_provenance",
    "meta",
];
/// SQLite bookkeeping that is not store data.
const INTERNAL: &[&str] = &["schema_migrations", "sqlite_sequence"];
/// Triggers that recompute copied state; off for the import transaction only.
const DISABLED_TRIGGERS: &[(&str, &str)] = &[
    ("users", "human_user_identity_reserve"),
    ("providers", "human_provider_owner"),
    ("human_provider_material_owners", "human_material_owner"),
    ("external_factor_proofs", "external_factor_proof_budget"),
];
/// `meta` keys SQLite uses for replay ledgers; they become `replay_nonces` rows.
const NONCE_PREFIX: &str = "nonce:";
/// `pg_advisory_xact_lock` key: one import at a time.
const IMPORT_LOCK: i64 = 7050;

/// One table's outcome: rows and canonical digest on both sides.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TableReport {
    pub table: String,
    pub rows: u64,
    pub digest: String,
}

#[derive(Clone, Debug, Default)]
pub struct ImportReport {
    pub tables: Vec<TableReport>,
    pub nonces: u64,
    pub realm: Option<String>,
    pub source_schema: u32,
}

impl ImportReport {
    /// A digest over every table digest (the audit event carries it).
    pub fn summary_digest(&self) -> String {
        let mut h = Sha256::new();
        for t in &self.tables {
            h.update(t.table.as_bytes());
            h.update([0]);
            h.update(t.rows.to_be_bytes());
            h.update(t.digest.as_bytes());
        }
        data_encoding::HEXLOWER.encode(&h.finalize())
    }
}

fn refused(why: impl Into<String>) -> StoreError {
    StoreError::Unavailable(format!("migration refused: {}", why.into()))
}

fn sq(e: rusqlite::Error) -> StoreError {
    StoreError::Unavailable(format!("reading the SQLite store: {e}"))
}

/// The column types the copy converts to.
#[derive(Clone, Copy, Debug)]
enum Kind {
    Text,
    Int8,
    Int4,
    Bool,
    Bytes,
    Float,
    Json,
}

fn kind_of(t: &Type) -> Option<Kind> {
    Some(match *t {
        Type::TEXT | Type::VARCHAR => Kind::Text,
        Type::INT8 => Kind::Int8,
        Type::INT4 | Type::INT2 => Kind::Int4,
        Type::BOOL => Kind::Bool,
        Type::BYTEA => Kind::Bytes,
        Type::FLOAT8 => Kind::Float,
        Type::JSONB | Type::JSON => Kind::Json,
        _ => return None,
    })
}

/// A value bound for PostgreSQL and its canonical digest encoding.
fn convert(v: &Value, k: Kind, col: &str) -> StoreResult<(Box<dyn ToSql + Sync + Send>, Vec<u8>)> {
    let bad = || {
        refused(format!(
            "column {col}: value does not fit its PostgreSQL type"
        ))
    };
    Ok(match (v, k) {
        (Value::Null, Kind::Text | Kind::Json) => (Box::new(None::<String>), vec![0]),
        (Value::Null, Kind::Int8) => (Box::new(None::<i64>), vec![0]),
        (Value::Null, Kind::Int4) => (Box::new(None::<i32>), vec![0]),
        (Value::Null, Kind::Bool) => (Box::new(None::<bool>), vec![0]),
        (Value::Null, Kind::Bytes) => (Box::new(None::<Vec<u8>>), vec![0]),
        (Value::Null, Kind::Float) => (Box::new(None::<f64>), vec![0]),
        (Value::Text(s), Kind::Text) => (Box::new(s.clone()), canon_text(s)),
        (Value::Text(s), Kind::Json) => {
            let parsed: serde_json::Value = serde_json::from_str(s).map_err(|_| bad())?;
            (Box::new(s.clone()), canon_text(&canonical_json(&parsed)))
        }
        (Value::Integer(i), Kind::Int8) => (Box::new(*i), canon_int(*i)),
        (Value::Integer(i), Kind::Int4) => (
            Box::new(i32::try_from(*i).map_err(|_| bad())?),
            canon_int(*i),
        ),
        (Value::Integer(i), Kind::Bool) if *i == 0 || *i == 1 => (Box::new(*i == 1), canon_int(*i)),
        (Value::Integer(i), Kind::Float) => (Box::new(*i as f64), canon_float(*i as f64)),
        (Value::Real(f), Kind::Float) => (Box::new(*f), canon_float(*f)),
        (Value::Blob(b), Kind::Bytes) => (Box::new(b.clone()), canon_bytes(b)),
        _ => return Err(bad()),
    })
}

fn canon_text(s: &str) -> Vec<u8> {
    let mut out = vec![2];
    out.extend((s.len() as u64).to_be_bytes());
    out.extend(s.as_bytes());
    out
}
fn canon_bytes(b: &[u8]) -> Vec<u8> {
    let mut out = vec![3];
    out.extend((b.len() as u64).to_be_bytes());
    out.extend(b);
    out
}
fn canon_int(i: i64) -> Vec<u8> {
    let mut out = vec![1];
    out.extend(i.to_be_bytes());
    out
}
fn canon_float(f: f64) -> Vec<u8> {
    let mut out = vec![4];
    out.extend(f.to_bits().to_be_bytes());
    out
}
/// JSON with object keys sorted (jsonb reorders keys on the way in).
fn canonical_json(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            let inner: Vec<String> = keys
                .into_iter()
                .map(|k| {
                    format!(
                        "{}:{}",
                        serde_json::Value::String(k.clone()),
                        canonical_json(&m[k])
                    )
                })
                .collect();
            format!("{{{}}}", inner.join(","))
        }
        serde_json::Value::Array(a) => {
            format!(
                "[{}]",
                a.iter().map(canonical_json).collect::<Vec<_>>().join(",")
            )
        }
        other => other.to_string(),
    }
}

/// The canonical encoding of a value read back from PostgreSQL.
fn canon_pg(r: &tokio_postgres::Row, i: usize, k: Kind) -> StoreResult<Vec<u8>> {
    let corrupt = || StoreError::Corrupt("migrated value".into());
    Ok(match k {
        Kind::Text => r
            .get::<_, Option<String>>(i)
            .map_or(vec![0], |s| canon_text(&s)),
        Kind::Json => match r.get::<_, Option<String>>(i) {
            None => vec![0],
            Some(s) => {
                let v: serde_json::Value = serde_json::from_str(&s).map_err(|_| corrupt())?;
                canon_text(&canonical_json(&v))
            }
        },
        Kind::Int8 => r.get::<_, Option<i64>>(i).map_or(vec![0], canon_int),
        Kind::Int4 => r
            .get::<_, Option<i32>>(i)
            .map_or(vec![0], |v| canon_int(v.into())),
        Kind::Bool => r
            .get::<_, Option<bool>>(i)
            .map_or(vec![0], |b| canon_int(b.into())),
        Kind::Bytes => r
            .get::<_, Option<Vec<u8>>>(i)
            .map_or(vec![0], |b| canon_bytes(&b)),
        Kind::Float => r.get::<_, Option<f64>>(i).map_or(vec![0], canon_float),
    })
}

struct Column {
    name: String,
    kind: Kind,
}

/// The copy plan of one table: the SQLite columns with their target kinds.
async fn plan(
    tx: &Transaction<'_>,
    src: &rusqlite::Connection,
    table: &str,
) -> StoreResult<Vec<Column>> {
    let names: Vec<String> = src
        .prepare(&format!(
            "SELECT name FROM pragma_table_info('{table}') ORDER BY cid"
        ))
        .map_err(sq)?
        .query_map([], |r| r.get(0))
        .map_err(sq)?
        .collect::<Result<_, _>>()
        .map_err(sq)?;
    // The target's types, from a statement that names every column.
    let list = names
        .iter()
        .map(|n| format!("\"{n}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let stmt = tx
        .prepare(&format!("SELECT {list} FROM {table} LIMIT 0"))
        .await
        .map_err(|_| {
            refused(format!(
                "{table}: a SQLite column has no PostgreSQL counterpart"
            ))
        })?;
    stmt.columns()
        .iter()
        .zip(names)
        .map(|(c, name)| {
            let kind = kind_of(c.type_())
                .ok_or_else(|| refused(format!("{table}.{name}: unsupported target type")))?;
            Ok(Column { name, kind })
        })
        .collect()
}

/// The primary-key columns (digest order); `rowid` for tables without one.
fn key_columns(src: &rusqlite::Connection, table: &str) -> StoreResult<Vec<String>> {
    let mut keys: Vec<(i64, String)> = src
        .prepare(&format!(
            "SELECT pk, name FROM pragma_table_info('{table}') WHERE pk > 0"
        ))
        .map_err(sq)?
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .map_err(sq)?
        .collect::<Result<_, _>>()
        .map_err(sq)?;
    keys.sort();
    Ok(keys.into_iter().map(|(_, n)| n).collect())
}

/// The order both digests read a table in: its key, or for the one keyless
/// table every column (equal rows encode equally, so ties do not matter).
fn digest_keys(src: &rusqlite::Connection, table: &str) -> StoreResult<Vec<String>> {
    let keys = key_columns(src, table)?;
    if !keys.is_empty() {
        return Ok(keys);
    }
    match table {
        "txn_admissions" => Ok(vec!["ip".into(), "at".into()]),
        _ => Err(refused(format!("{table}: no key to verify by"))),
    }
}

fn has_rowid(src: &rusqlite::Connection, table: &str) -> bool {
    src.prepare(&format!("SELECT rowid FROM {table} LIMIT 0"))
        .is_ok()
}

impl PgStore {
    /// Copy the SQLite store at `path` into this (empty) store. See the module
    /// documentation for the guarantees; `actor` names who ran it (audit).
    pub async fn import_sqlite(&self, path: &Path, actor: &str) -> StoreResult<ImportReport> {
        let schema = crate::store::precheck(path)?;
        if schema != crate::store::LATEST_SCHEMA_VERSION {
            return Err(refused(format!(
                "the SQLite store is at schema {schema}, this binary expects {}: start it once on SQLite with this version first",
                crate::store::LATEST_SCHEMA_VERSION
            )));
        }
        let src = rusqlite::Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(sq)?;
        // One snapshot for the whole copy.
        src.execute_batch("BEGIN").map_err(sq)?;
        let result = self.import_from(&src, schema, actor).await;
        let _ = src.execute_batch("ROLLBACK");
        result
    }

    async fn import_from(
        &self,
        src: &rusqlite::Connection,
        schema: u32,
        actor: &str,
    ) -> StoreResult<ImportReport> {
        // Every SQLite table with rows must be one the copy knows.
        let present: Vec<String> = src
            .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            .map_err(sq)?
            .query_map([], |r| r.get(0))
            .map_err(sq)?
            .collect::<Result<_, _>>()
            .map_err(sq)?;
        let mut unknown = Vec::new();
        for t in &present {
            if TABLES.contains(&t.as_str()) || INTERNAL.contains(&t.as_str()) {
                continue;
            }
            let n: i64 = src
                .query_row(&format!("SELECT count(*) FROM \"{t}\""), [], |r| r.get(0))
                .map_err(sq)?;
            if n > 0 {
                unknown.push(format!("{t} ({n} rows)"));
            }
        }
        if !unknown.is_empty() {
            return Err(refused(format!(
                "tables without a PostgreSQL counterpart hold data: {}",
                unknown.join(", ")
            )));
        }
        let mut client = self.client().await?;
        let tx = self.begin(&mut client).await?;
        // A copy may take minutes: no statement timeout, one import at a time.
        tx.batch_execute("SET LOCAL statement_timeout = 0")
            .await
            .map_err(pg)?;
        tx.execute(super::ADVISORY_XACT_LOCK, &[&IMPORT_LOCK])
            .await
            .map_err(pg)?;
        // The target must be empty.
        let mut occupied = Vec::new();
        for t in TABLES.iter().chain(["replay_nonces", "outbox_feed"].iter()) {
            let sql = if *t == "external_factor_budget" {
                "SELECT count(*) FROM external_factor_budget WHERE used <> 0".to_string()
            } else {
                format!("SELECT count(*) FROM {t}")
            };
            let n: i64 = tx.query_one(&sql, &[]).await.map_err(pg)?.get(0);
            if n > 0 {
                occupied.push(format!("{t} ({n} rows)"));
            }
        }
        if !occupied.is_empty() {
            return Err(refused(format!(
                "the PostgreSQL store is not empty: {}",
                occupied.join(", ")
            )));
        }
        for (table, trigger) in DISABLED_TRIGGERS {
            tx.batch_execute(&format!("ALTER TABLE {table} DISABLE TRIGGER {trigger}"))
                .await
                .map_err(pg)?;
        }
        let mut report = ImportReport {
            source_schema: schema,
            ..ImportReport::default()
        };
        for table in TABLES {
            let cols = plan(&tx, src, table).await?;
            let rows = self.copy_table(&tx, src, table, &cols, &mut report).await?;
            let (n, digest) = source_digest(src, table, &cols)?;
            let (m, back) = target_digest(&tx, src, table, &cols).await?;
            if n != m || digest != back || n != rows {
                return Err(refused(format!(
                    "{table}: verification failed (source {n} rows, target {m} rows)"
                )));
            }
            report.tables.push(TableReport {
                table: (*table).to_string(),
                rows: n,
                digest,
            });
        }
        // The lifecycle feed positions of the copied events, in outbox order.
        tx.execute(
            "INSERT INTO outbox_feed (event_id) SELECT event_id FROM events \
             WHERE kind IN ('admin.user_disable', 'admin.user_enable') OR kind LIKE 'group.%' ORDER BY at, event_id",
            &[],
        )
        .await
        .map_err(pg)?;
        for (table, trigger) in DISABLED_TRIGGERS {
            tx.batch_execute(&format!("ALTER TABLE {table} ENABLE TRIGGER {trigger}"))
                .await
                .map_err(pg)?;
        }
        report.realm = tx
            .query_opt(
                "SELECT realm FROM human_authority_realm WHERE singleton = 1",
                &[],
            )
            .await
            .map_err(pg)?
            .map(|r| r.get(0));
        let rows: u64 = report.tables.iter().map(|t| t.rows).sum();
        let event = EventBuilder::new(
            self.clock.as_ref(),
            self.rng.as_ref(),
            EventKind::StoreMigrated,
            Outcome::Success,
            "r_store_migration",
        )
        .attr("source", "sqlite")
        .attr("actor", actor)
        .attr("schema", u64::from(schema))
        .attr("tables", report.tables.len() as u64)
        .attr("rows", rows)
        .attr("count", report.nonces)
        .attr("digest", report.summary_digest())
        .build();
        self.insert_events(&tx, &[event]).await?;
        tx.commit().await.map_err(pg)?;
        Ok(report)
    }

    async fn copy_table(
        &self,
        tx: &Transaction<'_>,
        src: &rusqlite::Connection,
        table: &str,
        cols: &[Column],
        report: &mut ImportReport,
    ) -> StoreResult<u64> {
        let list = cols
            .iter()
            .map(|c| format!("\"{}\"", c.name))
            .collect::<Vec<_>>()
            .join(", ");
        // Insertion order as SQLite's (claim order, ledger and feed positions).
        let order = if has_rowid(src, table) {
            "rowid".to_string()
        } else {
            key_columns(src, table)?.join(", ")
        };
        let mut st = src
            .prepare(&format!("SELECT {list} FROM \"{table}\" ORDER BY {order}"))
            .map_err(sq)?;
        let mut q = st.query([]).map_err(sq)?;
        let placeholders: Vec<String> = cols
            .iter()
            .enumerate()
            .map(|(i, c)| match c.kind {
                Kind::Json => format!("CAST(${}::text AS jsonb)", i + 1),
                _ => format!("${}", i + 1),
            })
            .collect();
        let insert = match table {
            // The seed row exists already: take the source's value.
            "external_factor_budget" => format!(
                "INSERT INTO external_factor_budget ({list}) VALUES ({}) ON CONFLICT (singleton) DO UPDATE SET used = excluded.used",
                placeholders.join(", ")
            ),
            _ => format!(
                "INSERT INTO {table} ({list}) VALUES ({})",
                placeholders.join(", ")
            ),
        };
        let stmt = tx.prepare(&insert).await.map_err(pg)?;
        let nonce_stmt = tx
            .prepare("INSERT INTO replay_nonces (scope, nonce, expires_at) VALUES ($1, $2, $3)")
            .await
            .map_err(pg)?;
        let mut n = 0u64;
        while let Some(row) = q.next().map_err(sq)? {
            if table == "meta" {
                let key: String = row.get(0).map_err(sq)?;
                if let Some(rest) = key.strip_prefix(NONCE_PREFIX) {
                    // `nonce:<scope>:<nonce>` → a replay ledger row (expired ones are dropped).
                    let value: String = row.get(1).map_err(sq)?;
                    let expires: i64 = value
                        .parse()
                        .map_err(|_| refused("a replay ledger entry is malformed"))?;
                    let (scope, nonce) = rest
                        .split_once(':')
                        .ok_or_else(|| refused("a replay ledger entry is malformed"))?;
                    if expires > self.now().secs() {
                        tx.execute(&nonce_stmt, &[&scope, &nonce, &expires])
                            .await
                            .map_err(pg)?;
                        report.nonces += 1;
                    }
                    continue;
                }
            }
            let mut params: Vec<Box<dyn ToSql + Sync + Send>> = Vec::with_capacity(cols.len());
            for (i, c) in cols.iter().enumerate() {
                let v: Value = row.get(i).map_err(sq)?;
                params.push(convert(&v, c.kind, &format!("{table}.{}", c.name))?.0);
            }
            let refs: Vec<&(dyn ToSql + Sync)> = params
                .iter()
                .map(|b| b.as_ref() as &(dyn ToSql + Sync))
                .collect();
            tx.execute(&stmt, &refs).await.map_err(pg)?;
            n += 1;
        }
        Ok(n)
    }
}

/// Rows and digest of a SQLite table (replay entries excluded from `meta`).
fn source_digest(
    src: &rusqlite::Connection,
    table: &str,
    cols: &[Column],
) -> StoreResult<(u64, String)> {
    let list = cols
        .iter()
        .map(|c| format!("\"{}\"", c.name))
        .collect::<Vec<_>>()
        .join(", ");
    let order = digest_keys(src, table)?.join(", ");
    let filter = if table == "meta" {
        format!(" WHERE key NOT LIKE '{NONCE_PREFIX}%'")
    } else {
        String::new()
    };
    let mut st = src
        .prepare(&format!(
            "SELECT {list} FROM \"{table}\"{filter} ORDER BY {order}"
        ))
        .map_err(sq)?;
    let mut q = st.query([]).map_err(sq)?;
    let mut h = Sha256::new();
    let mut n = 0u64;
    while let Some(row) = q.next().map_err(sq)? {
        for (i, c) in cols.iter().enumerate() {
            let v: Value = row.get(i).map_err(sq)?;
            h.update(convert(&v, c.kind, &c.name)?.1);
        }
        n += 1;
    }
    Ok((n, data_encoding::HEXLOWER.encode(&h.finalize())))
}

/// Rows and digest of the copied PostgreSQL table, in SQLite's key order
/// (text keys compared bytewise, as SQLite's BINARY collation does).
async fn target_digest(
    tx: &Transaction<'_>,
    src: &rusqlite::Connection,
    table: &str,
    cols: &[Column],
) -> StoreResult<(u64, String)> {
    let list = cols
        .iter()
        .map(|c| match c.kind {
            Kind::Json => format!("\"{}\"::text", c.name),
            _ => format!("\"{}\"", c.name),
        })
        .collect::<Vec<_>>()
        .join(", ");
    let kinds: BTreeMap<&str, Kind> = cols.iter().map(|c| (c.name.as_str(), c.kind)).collect();
    let order = digest_keys(src, table)?
        .iter()
        .map(|k| match kinds.get(k.as_str()) {
            Some(Kind::Text) => format!("\"{k}\" COLLATE \"C\""),
            _ => format!("\"{k}\""),
        })
        .collect::<Vec<_>>()
        .join(", ");
    let filter = if table == "meta" {
        format!(" WHERE key NOT LIKE '{NONCE_PREFIX}%'")
    } else {
        String::new()
    };
    let rows = tx
        .query(
            &format!("SELECT {list} FROM {table}{filter} ORDER BY {order}"),
            &[],
        )
        .await
        .map_err(pg)?;
    let mut h = Sha256::new();
    for r in &rows {
        for (i, c) in cols.iter().enumerate() {
            h.update(canon_pg(r, i, c.kind)?);
        }
    }
    Ok((
        rows.len() as u64,
        data_encoding::HEXLOWER.encode(&h.finalize()),
    ))
}
