//! The `hopae` binary: CLI entry point.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use hopae::{app, config, telemetry};

#[derive(Parser)]
#[command(name = "hopae", version, about = "Hopae identity provider")]
struct Cli {
    /// Path to the JSON configuration file.
    #[arg(long, global = true, env = "HOPAE_CONFIG", value_name = "PATH")]
    config: Option<PathBuf>,

    /// Validate the configuration and the referenced environment variables, then exit.
    #[arg(long)]
    check: bool,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run the portal and gateway listeners (the default command).
    Serve,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let Some(path) = cli.config else {
        eprintln!("error: --config <path> is required (or set HOPAE_CONFIG)");
        return ExitCode::from(2);
    };
    let cfg = match config::load(&path) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("config error: {e}");
            return ExitCode::FAILURE;
        }
    };
    let env_problems = config::check_env(&cfg, |name| std::env::var(name).ok());
    if cli.check {
        for w in cfg.warnings() {
            eprintln!("warning: {w}");
        }
        if env_problems.is_empty() {
            println!("config ok");
            return ExitCode::SUCCESS;
        }
        for p in &env_problems {
            eprintln!("config error: {p}");
        }
        return ExitCode::FAILURE;
    }
    if !env_problems.is_empty() {
        for p in &env_problems {
            eprintln!("config error: {p}");
        }
        return ExitCode::FAILURE;
    }
    let _ = cli.command; // `serve` is the only command and the default.
    telemetry::init(&cfg.log.level);
    match run(cfg) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(cfg: config::Config) -> anyhow::Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(async {
        let bound = app::bind(&cfg).await?;
        // Stable, machine-readable lines so supervisors and tests can find the ports.
        println!("portal listening on {}", bound.portal_addr());
        println!("gateway listening on {}", bound.gateway_addr());
        if let Some(h) = bound.hooks_addr() {
            println!("hooks listening on {h}");
        }
        bound.run(app::shutdown_signal()).await
    })
}
