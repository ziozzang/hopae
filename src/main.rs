//! The `hopae` binary: CLI entry point.
//!
//! Exit status: `0` success; `2` an invalid or unsafe configuration, a
//! refused start (second instance on one store) or a `--strict` failure; `1`
//! any other runtime failure.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
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
    /// Administrator grants for the management console, straight against the
    /// store (safe while an instance runs).
    Admin {
        #[command(subcommand)]
        action: AdminAction,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum RoleArg {
    Admin,
    Viewer,
}

#[derive(Subcommand)]
enum AdminAction {
    /// Grant a role to an existing user (by user id, or by verified primary
    /// email) and print the user it resolved.
    Grant {
        /// A user id (u_...) or an email address.
        #[arg(value_name = "TARGET", allow_hyphen_values = false)]
        target: String,
        #[arg(long, value_enum, default_value = "admin")]
        role: RoleArg,
        /// At most 256 characters.
        #[arg(long)]
        note: Option<String>,
        /// The user id an email that is not authoritative resolves to.
        #[arg(long, value_name = "USER_ID")]
        confirm: Option<String>,
    },
    /// Revoke a grant; the row stays as a tombstone.
    Revoke {
        #[arg(value_name = "TARGET")]
        target: String,
    },
    /// List live grants (`--all`: revoked rows too).
    List {
        #[arg(long)]
        all: bool,
    },
    /// Apply `admin.users[]` of the configuration file to the store.
    Import {
        #[arg(long, value_name = "USER_ID_OR_EMAIL")]
        force: Option<String>,
    },
    /// A user's second factors (passkeys, authenticator app, recovery codes).
    Factors {
        #[command(subcommand)]
        action: FactorsAction,
    },
    /// Route-scoped, read-only service credentials for machine callers of
    /// the admin listener (mTLS + bearer).
    #[command(name = "service-credentials")]
    ServiceCredentials {
        #[command(subcommand)]
        action: ServiceCredentialAction,
    },
}

#[derive(Subcommand)]
enum ServiceCredentialAction {
    /// Create a credential and print its token once.
    Create {
        /// 3-48 lowercase letters, digits and inner '-'.
        #[arg(value_name = "ID")]
        id: String,
        /// An allowed route, "METHOD /path" (repeatable); only read routes.
        #[arg(long = "route", value_name = "ROUTE")]
        routes: Vec<String>,
        /// `pumgye-v2`: the membership projection and subject lifecycle reads.
        #[arg(long)]
        preset: Option<String>,
        /// An allowed audience (repeatable; default the console origin).
        #[arg(long = "audience", value_name = "AUDIENCE")]
        audiences: Vec<String>,
        /// SHA-256 (hex) of the client certificate's SubjectPublicKeyInfo.
        #[arg(long)]
        client_spki_sha256: Option<String>,
        /// An exact subject alternative name of the client certificate.
        #[arg(long)]
        client_san: Option<String>,
        #[arg(long, default_value_t = 90)]
        expires_in_days: u32,
        #[arg(long, default_value_t = 120)]
        rate_per_minute: u32,
        #[arg(long, default_value_t = 30)]
        burst: u32,
        #[arg(long)]
        note: Option<String>,
    },
    /// Issue the next secret and print it once (current and next both work).
    Rotate {
        #[arg(value_name = "ID")]
        id: String,
    },
    /// Make the next secret current; the previous one stops working.
    Promote {
        #[arg(value_name = "ID")]
        id: String,
    },
    /// Revoke a credential; the row stays as a tombstone.
    Revoke {
        #[arg(value_name = "ID")]
        id: String,
    },
    /// List credentials without secrets or digests.
    List,
}

#[derive(Subcommand)]
enum FactorsAction {
    /// Show a user's factors: labels, kinds, classes and times, never key material.
    List {
        #[arg(value_name = "TARGET")]
        target: String,
    },
    /// Revoke every passkey, authenticator app and recovery code of a user and
    /// end every session; the user enrolls again after a fresh sign-in.
    Reset {
        #[arg(value_name = "TARGET")]
        target: String,
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
        Some(Command::Admin { action }) => admin(&cfg, action),
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
    let apps: Vec<(String, Vec<String>)> = cfg
        .apps
        .iter()
        .filter(|a| !a.hosts.is_empty())
        .map(|a| (a.app_id.clone(), a.hosts.clone()))
        .collect();
    let console = cfg.admin_host().map(|(h, _)| h.to_string());
    match runtime() {
        Ok(rt) => rt.block_on(hopae::app::drift::drift_warnings_with_console(
            url,
            &token,
            &apps,
            console.as_deref(),
        )),
        Err(_) => Vec::new(),
    }
}

fn check(cfg: &Config, strict: bool) -> ExitCode {
    let now = SystemClock.now().secs();
    let since = state::read_meta(&cfg.store_path(), state::CALLER_KEY_NEXT_SINCE)
        .and_then(|v| v.parse::<i64>().ok());
    let mut warnings = preflight::warnings(cfg, |n| std::env::var(n).ok(), since, now);
    warnings.extend(drift(cfg));
    if let Ok(rt) = runtime() {
        warnings.extend(rt.block_on(app::admin_check_warnings(cfg)));
    }
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
    let stored = runtime()
        .map(|rt| rt.block_on(app::check_stored_providers(cfg)))
        .unwrap_or_default();
    print!("{}", preflight::report_with(cfg, &stored));
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
    telemetry::output::Output::global().flush(std::time::Duration::from_secs(2));
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

/// A database the pre-check refuses (a pre-release schema, a missing
/// structure, a newer or older version) is refused like an unsafe
/// configuration.
fn store_refused(e: &anyhow::Error) -> bool {
    e.chain().any(|c| {
        matches!(
            c.downcast_ref::<hopae::store::StoreError>(),
            Some(
                hopae::store::StoreError::DevelopmentSchema
                    | hopae::store::StoreError::Corrupt(_)
                    | hopae::store::StoreError::SchemaTooNew { .. }
                    | hopae::store::StoreError::SchemaTooOld { .. }
            )
        )
    })
}

fn admin(cfg: &Config, action: AdminAction) -> ExitCode {
    use hopae::store::AdminRole;
    telemetry::init(&cfg.log.level);
    let cmd = match action {
        AdminAction::Grant {
            target,
            role,
            note,
            confirm,
        } => app::AdminCommand::Grant {
            target,
            role: match role {
                RoleArg::Admin => AdminRole::Admin,
                RoleArg::Viewer => AdminRole::Viewer,
            },
            note,
            confirm,
        },
        AdminAction::Revoke { target } => app::AdminCommand::Revoke { target },
        AdminAction::List { all } => app::AdminCommand::List { all },
        AdminAction::Import { force } => app::AdminCommand::Import { force },
        AdminAction::Factors {
            action: FactorsAction::List { target },
        } => app::AdminCommand::FactorsList { target },
        AdminAction::Factors {
            action: FactorsAction::Reset { target },
        } => app::AdminCommand::FactorsReset { target },
        AdminAction::ServiceCredentials { action } => {
            use app::ServiceCredentialCommand as C;
            app::AdminCommand::ServiceCredential(match action {
                ServiceCredentialAction::Create {
                    id,
                    routes,
                    preset,
                    audiences,
                    client_spki_sha256,
                    client_san,
                    expires_in_days,
                    rate_per_minute,
                    burst,
                    note,
                } => C::Create {
                    id,
                    routes,
                    preset,
                    audiences,
                    client_spki_sha256,
                    client_san,
                    expires_in_days,
                    rate_per_minute,
                    burst,
                    note,
                },
                ServiceCredentialAction::Rotate { id } => C::Rotate { id },
                ServiceCredentialAction::Promote { id } => C::Promote { id },
                ServiceCredentialAction::Revoke { id } => C::Revoke { id },
                ServiceCredentialAction::List => C::List,
            })
        }
    };
    let result = runtime()
        .map_err(anyhow::Error::from)
        .and_then(|rt| rt.block_on(app::admin_cli_with(cfg, cmd, true)));
    telemetry::output::Output::global().flush(std::time::Duration::from_secs(2));
    match result {
        Ok(out) => {
            // A closed or full stdout is not a panic (the evidence step reports it).
            let _ = std::io::Write::write_all(&mut std::io::stdout(), out.stdout.as_bytes());
            eprint!("{}", out.stderr);
            ExitCode::from(out.code)
        }
        Err(e) if store_refused(&e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(EXIT_CONFIG)
        }
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
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
    let result = rt.block_on(run(cfg));
    // Lines still queued for the output thread are written (bounded wait).
    telemetry::output::Output::global().flush(std::time::Duration::from_secs(2));
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            if e.downcast_ref::<app::StoreLocked>().is_some() {
                eprintln!("error: {e}");
                return ExitCode::from(EXIT_CONFIG);
            }
            // A database the pre-check refuses (a pre-release schema, a missing
            // structure, a newer or older version) is refused like an unsafe
            // configuration: exit status 2.
            if store_refused(&e) {
                eprintln!("error: {e:#}");
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
    if let Some(a) = bound.admin_addr() {
        println!("admin listening on {a}");
    }
    if let Some(h) = bound.hooks_addr() {
        println!("hooks listening on {h}");
    }
    bound.run(signals.shutdown()).await
}
