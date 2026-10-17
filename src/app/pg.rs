//! PostgreSQL store wiring (ADR-0020): connection options from the
//! configuration and the one-way SQLite migration command.
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;

use crate::config::{Config, StoreKind};
use crate::crypto::{OsRng, SystemClock};
use crate::store::postgres::import::ImportReport;
use crate::store::postgres::{PgOptions, PgStore};

/// Connection options from `store.postgres`; the URL is read from the named
/// environment variable and never logged.
pub fn options(cfg: &Config, env: &dyn Fn(&str) -> Option<String>) -> anyhow::Result<PgOptions> {
    anyhow::ensure!(
        cfg.store.kind == StoreKind::Postgres,
        "store.kind is not \"postgres\""
    );
    let pg = cfg
        .store
        .postgres
        .as_ref()
        .context("store.postgres is required")?;
    let url = env(&pg.url_env)
        .filter(|u| !u.is_empty())
        .with_context(|| format!("environment variable {} is not set", pg.url_env))?;
    let ca_pem = pg
        .ca_file
        .as_ref()
        .map(|p| std::fs::read(p).with_context(|| format!("reading {}", p.display())))
        .transpose()?;
    Ok(PgOptions {
        url,
        ca_pem,
        pool_size: pg.pool_size,
        connect_timeout: Duration::from_millis(pg.connect_timeout_ms),
        statement_timeout: Duration::from_millis(pg.statement_timeout_ms),
        search_path: None,
    })
}

/// `hopae store migrate-to-postgres`: copy the SQLite store into the empty
/// PostgreSQL store the configuration names. The instance lock is taken so
/// no Hopae runs on the SQLite file meanwhile; the file is opened read-only
/// and kept as the rollback artefact.
pub async fn migrate_to_postgres(
    cfg: &Config,
    from: Option<&Path>,
) -> anyhow::Result<(PathBuf, ImportReport)> {
    let source = from.map_or_else(|| cfg.state_dir.join("hopae.db"), Path::to_path_buf);
    anyhow::ensure!(
        source.is_file(),
        "SQLite store {} not found",
        source.display()
    );
    let _lock = super::lock::acquire(&cfg.state_dir)?;
    let options = options(cfg, &|n| std::env::var(n).ok())?;
    let store = PgStore::connect(
        options,
        Arc::new(SystemClock),
        Arc::new(OsRng),
        cfg.event_sinks(),
    )
    .await
    .context("connecting to PostgreSQL")?;
    let report = store
        .import_sqlite(&source, "cli")
        .await
        .with_context(|| format!("migrating {}", source.display()))?;
    Ok((source, report))
}
