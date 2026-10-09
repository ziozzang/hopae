//! Typed configuration (M0): schema, loading, environment references and
//! validation. JSON only in M0; ARCHITECTURE also mentions `hopae.yaml`, which
//! is not implemented yet. Unknown keys are rejected everywhere. Secrets are
//! referenced by environment variable name only and never appear in output.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;

/// Largest configuration file accepted, in bytes.
const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub listen: Listen,
    /// Writable directory for runtime state (created with mode 0700).
    pub state_dir: PathBuf,
    #[serde(default)]
    pub store: Store,
    pub portal: Portal,
    pub gateway: Gateway,
    #[serde(default)]
    pub log: Log,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Listen {
    #[serde(default = "default_portal_addr")]
    pub portal: String,
    #[serde(default = "default_gateway_addr")]
    pub gateway: String,
}

impl Default for Listen {
    fn default() -> Self {
        Self {
            portal: default_portal_addr(),
            gateway: default_gateway_addr(),
        }
    }
}

fn default_portal_addr() -> String {
    "127.0.0.1:8700".into()
}
fn default_gateway_addr() -> String {
    "127.0.0.1:8701".into()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Store {
    #[serde(default)]
    pub kind: StoreKind,
    /// Database file; defaults to `<state_dir>/hopae.db`.
    #[serde(default)]
    pub path: Option<PathBuf>,
}

impl Default for Store {
    fn default() -> Self {
        Self {
            kind: StoreKind::Sqlite,
            path: None,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StoreKind {
    #[default]
    Sqlite,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Portal {
    /// Externally visible portal origin, used for every emitted `Location`.
    pub public_url: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gateway {
    pub kind: GatewayKind,
    /// Name of the environment variable holding the shared caller key.
    #[serde(default)]
    pub caller_key_env: Option<String>,
    /// Development only: skip caller-key authentication.
    #[serde(default)]
    pub allow_unauthenticated_caller: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GatewayKind {
    Hangang,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Log {
    #[serde(default = "default_level")]
    pub level: String,
}

impl Default for Log {
    fn default() -> Self {
        Self {
            level: default_level(),
        }
    }
}

fn default_level() -> String {
    "info".into()
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("cannot read {path}: {source}")]
    Read {
        path: String,
        source: std::io::Error,
    },
    #[error("{path} is larger than {MAX_CONFIG_BYTES} bytes")]
    TooLarge { path: String },
    #[error("cannot parse configuration: {0}")]
    Parse(#[from] serde_json::Error),
    #[error("invalid configuration: {}", .0.join("; "))]
    Invalid(Vec<String>),
}

/// Read, parse and validate a JSON configuration file.
pub fn load(path: &Path) -> Result<Config, ConfigError> {
    let display = path.display().to_string();
    let io = |source| ConfigError::Read {
        path: display.clone(),
        source,
    };
    let meta = std::fs::metadata(path).map_err(io)?;
    if meta.len() > MAX_CONFIG_BYTES {
        return Err(ConfigError::TooLarge { path: display });
    }
    let text = std::fs::read_to_string(path).map_err(io)?;
    parse(&text)
}

/// Parse and validate configuration text.
pub fn parse(text: &str) -> Result<Config, ConfigError> {
    let cfg: Config = serde_json::from_str(text)?;
    cfg.validate()?;
    Ok(cfg)
}

const LEVELS: [&str; 5] = ["error", "warn", "info", "debug", "trace"];

fn valid_env_name(s: &str) -> bool {
    let mut chars = s.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

impl Config {
    /// Check every constraint that does not need the environment.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let mut errs = Vec::new();
        let portal = self.listen.portal.parse::<SocketAddr>();
        let gateway = self.listen.gateway.parse::<SocketAddr>();
        if portal.is_err() {
            errs.push("listen.portal must be a socket address such as 127.0.0.1:8700".to_string());
        }
        if gateway.is_err() {
            errs.push("listen.gateway must be a socket address such as 127.0.0.1:8701".to_string());
        }
        if let (Ok(p), Ok(g)) = (portal, gateway)
            && p == g
            && p.port() != 0
        {
            errs.push("listen.portal and listen.gateway must differ".to_string());
        }
        if self.state_dir.as_os_str().is_empty() {
            errs.push("state_dir must not be empty".to_string());
        }
        if let Some(p) = &self.store.path
            && p.as_os_str().is_empty()
        {
            errs.push("store.path must not be empty".to_string());
        }
        if let Err(e) = check_public_url(&self.portal.public_url) {
            errs.push(format!("portal.public_url {e}"));
        }
        match (&self.gateway.caller_key_env, self.gateway.allow_unauthenticated_caller) {
            (Some(name), _) if !valid_env_name(name) => {
                errs.push("gateway.caller_key_env must be an environment variable name ([A-Za-z_][A-Za-z0-9_]*)".to_string());
            }
            (None, false) => errs.push(
                "gateway.caller_key_env is required unless gateway.allow_unauthenticated_caller is true".to_string(),
            ),
            _ => {}
        }
        if !LEVELS.contains(&self.log.level.as_str()) {
            errs.push(format!("log.level must be one of {}", LEVELS.join(", ")));
        }
        if errs.is_empty() {
            Ok(())
        } else {
            Err(ConfigError::Invalid(errs))
        }
    }

    /// Parsed portal listen address. Only valid after `validate`.
    pub fn portal_addr(&self) -> SocketAddr {
        self.listen.portal.parse().expect("validated listen.portal")
    }

    /// Parsed gateway listen address. Only valid after `validate`.
    pub fn gateway_addr(&self) -> SocketAddr {
        self.listen
            .gateway
            .parse()
            .expect("validated listen.gateway")
    }

    /// Effective database path.
    pub fn store_path(&self) -> PathBuf {
        self.store
            .path
            .clone()
            .unwrap_or_else(|| self.state_dir.join("hopae.db"))
    }

    /// Non-fatal findings shown by `--check` and at start.
    pub fn warnings(&self) -> Vec<String> {
        let mut w = Vec::new();
        if self.gateway.allow_unauthenticated_caller {
            w.push("gateway.allow_unauthenticated_caller is true: development only".to_string());
        }
        if !self.gateway_addr().ip().is_loopback() {
            w.push(
                "listen.gateway is not a loopback address: it must not be publicly reachable"
                    .to_string(),
            );
        }
        w
    }
}

fn check_public_url(u: &str) -> Result<(), &'static str> {
    let rest = u
        .strip_prefix("https://")
        .or_else(|| u.strip_prefix("http://"))
        .ok_or("must start with https:// or http://")?;
    if rest.is_empty() || rest.starts_with('/') {
        return Err("must include a host");
    }
    if rest.contains(['?', '#', ' ']) || rest.trim_end_matches('/').contains('/') {
        return Err("must be an origin without path, query or fragment");
    }
    Ok(())
}

/// Verify that every environment variable the configuration references exists
/// and is non-empty. Returns messages naming only the variable, never a value.
pub fn check_env(cfg: &Config, lookup: impl Fn(&str) -> Option<String>) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(name) = &cfg.gateway.caller_key_env
        && !cfg.gateway.allow_unauthenticated_caller
        && lookup(name).is_none_or(|v| v.is_empty())
    {
        out.push(format!(
            "environment variable {name} (gateway.caller_key_env) is not set or is empty"
        ));
    }
    out
}
