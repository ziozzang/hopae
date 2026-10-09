//! The `hopae` binary: CLI entry point.
//!
//! Exit status: `0` success; `2` an invalid or unsafe configuration, a
//! refused start (second instance on one store) or a `--strict` failure; `1`
//! any other runtime failure.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use hopae::app::{self, EXIT_CONFIG, preflight, state};
use hopae::config::{self, Config};
use hopae::crypto::{Clock, SystemClock};
use hopae::telemetry;

/// Largest configuration file read (CONFIG.md: 1 MiB).
const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

#[derive(Parser)]
#[command(name = "hopae", version, about = "Hopae identity provider")]
struct Cli {
    /// Path to the JSON configuration file.
    #[arg(long, global = true, env = "HOPAE_CONFIG", value_name = "PATH")]
    config: Option<PathBuf>,

    /// Validate the configuration and the referenced environment variables, then exit.
    #[arg(long)]
    check: bool,

    /// With --check: treat warnings as errors.
    #[arg(long, requires = "check")]
    strict: bool,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run the portal and gateway listeners (the default command).
    #[command(alias = "serve")]
    Run,
    /// Operate on provider definitions.
    Providers {
        #[command(subcommand)]
        action: ProviderAction,
    },
}

#[derive(Subcommand)]
enum ProviderAction {
    /// Import the providers of the configuration file into the store by the
    /// ADR-0010 rule; `--force <id>` reasserts one file entry over the
    /// database (a disabled, API-managed or removed provider).
    Import {
        #[arg(long, value_name = "PROVIDER_ID")]
        force: Option<String>,
    },
}

fn config_failure(msg: impl std::fmt::Display) -> ExitCode {
    eprintln!("config error: {msg}");
    ExitCode::from(EXIT_CONFIG)
}

/// Read, parse and validate; the size is checked before the file is read.
fn load(path: &Path) -> Result<Config, String> {
    if let Ok(meta) = std::fs::metadata(path)
        && meta.len() > MAX_CONFIG_BYTES
    {
        return Err(format!(
            "configuration too large (limit {} MiB)",
            MAX_CONFIG_BYTES / (1024 * 1024)
        ));
    }
    config::load(path).map_err(|e| e.to_string())
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let Some(path) = cli.config.clone() else {
        eprintln!("error: --config <path> is required (or set HOPAE_CONFIG)");
        return ExitCode::from(EXIT_CONFIG);
    };
    let cfg = match load(&path) {
        Ok(cfg) => cfg,
        Err(e) => return config_failure(e),
    };
    let env_problems = config::check_env(&cfg, |name| std::env::var(name).ok());
    if !env_problems.is_empty() {
        for p in &env_problems {
            eprintln!("config error: {p}");
        }
        return ExitCode::from(EXIT_CONFIG);
    }
    if cli.check {
        return check(&cfg, cli.strict);
    }
    match cli.command {
        Some(Command::Providers {
            action: ProviderAction::Import { force },
        }) => providers_import(&cfg, force.as_deref()),
        Some(Command::Run) | None => serve(cfg),
    }
}

/// Phase 0 of ADR-0012: with `gateway.admin_url` and the read-only token, ask
/// the gateway which hosts have routes. Read-only; a failure to ask is a warning.
fn drift(cfg: &Config) -> Vec<String> {
    let (Some(url), Some(token_env)) = (&cfg.gateway.admin_url, &cfg.gateway.readonly_token_env)
    else {
        return Vec::new();
    };
    let Some(token) = std::env::var(token_env).ok().filter(|t| !t.is_empty()) else {
        return Vec::new();
    };
    let hosts: Vec<String> = cfg
        .apps
        .iter()
        .flat_map(|a| a.hosts.iter().cloned())
        .collect();
    match runtime() {
        Ok(rt) => rt.block_on(hopae::app::drift::drift_warnings(url, &token, &hosts)),
        Err(_) => Vec::new(),
    }
}

fn check(cfg: &Config, strict: bool) -> ExitCode {
    let now = SystemClock.now().secs();
    let since = state::read_meta(&cfg.store_path(), state::CALLER_KEY_NEXT_SINCE)
        .and_then(|v| v.parse::<i64>().ok());
    let mut warnings = preflight::warnings(cfg, |n| std::env::var(n).ok(), since, now);
    warnings.extend(drift(cfg));
    for w in &warnings {
        eprintln!("{}", preflight::render_warning(w));
    }
    if strict && !warnings.is_empty() {
        eprintln!(
            "config error: --strict: {} warning(s) treated as errors",
            warnings.len()
        );
        return ExitCode::from(EXIT_CONFIG);
    }
    print!("{}", preflight::report(cfg));
    ExitCode::SUCCESS
}

fn runtime() -> std::io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
}

fn providers_import(cfg: &Config, force: Option<&str>) -> ExitCode {
    telemetry::init(&cfg.log.level);
    let result = runtime()
        .map_err(anyhow::Error::from)
        .and_then(|rt| rt.block_on(app::import_providers_cli(cfg, force)));
    match result {
        Ok(r) => {
            let list = |v: &[hopae::provider::types::ProviderId]| {
                v.iter()
                    .map(|p| p.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            println!("providers imported");
            println!("  inserted: {}", list(&r.inserted));
            println!("  updated: {}", list(&r.updated));
            println!("  forced: {}", list(&r.forced));
            println!(
                "  skipped (database authoritative): {}",
                list(&r.skipped_api_managed)
            );
            println!(
                "  skipped (removed at run time): {}",
                list(&r.skipped_deleted)
            );
            println!("restart hopae for a running instance to pick up the change");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(EXIT_CONFIG)
        }
    }
}

fn serve(cfg: Config) -> ExitCode {
    telemetry::init(&cfg.log.level);
    let rt = match runtime() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };
    match rt.block_on(run(cfg)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            if e.downcast_ref::<app::StoreLocked>().is_some() {
                eprintln!("error: {e}");
                return ExitCode::from(EXIT_CONFIG);
            }
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cfg: Config) -> anyhow::Result<()> {
    // Handlers first: a signal that arrives during start is not the default action.
    let signals = app::Signals::install()?;
    let bound = app::bind(&cfg).await?;
    // Stable, machine-readable lines so supervisors and tests can find the ports.
    println!("portal listening on {}", bound.portal_addr());
    println!("gateway listening on {}", bound.gateway_addr());
    if let Some(h) = bound.hooks_addr() {
        println!("hooks listening on {h}");
    }
    bound.run(signals.shutdown()).await
}
