//! Typed configuration: schema, loading, environment references and
//! validation. JSON only. Unknown keys are rejected everywhere (with their
//! path and the nearest known key). Secrets are referenced by environment
//! variable name only and never appear in output.

mod keys;

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

use crate::identity::types::valid_domain;
use crate::policy::types::{
    AppId, AppPolicy, AuthzChange, BindingPolicy, ConfigSnapshot, Host, IpBinding, Lifetimes,
    OnMismatch, ProviderConfig, SessionPolicy, StepUpRule, UaBinding,
};
use crate::provider::presets;
use crate::provider::types::{ProviderId, ProviderKind, ReauthCapability, ReauthPrompt};
use crate::session::types::Aal;
use crate::verify::types::VerifyLimits;

/// Largest configuration file accepted, in bytes.
const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Dedicated canonical base64url32-byte key reference for private Human
    /// compiled-material qualification; absent/invalid material disables only it.
    #[serde(default)]
    pub human_material_key_env: Option<String>,
    #[serde(default)]
    pub receipt_issuer: Option<crate::auth_gateway::receipt_config::NativeIssuer>,
    #[serde(default)]
    pub receipt_permit_keys: Vec<crate::auth_gateway::receipt_config::PermitKey>,
    #[serde(default)]
    pub projection_receiver: Option<crate::auth_gateway::projection_resources::Configuration>,
    #[serde(default)]
    pub external_verifiers: Vec<crate::factor::external_transport::Config>,
    #[serde(default)]
    pub totp_keyring: Option<crate::factor::keyring::Configuration>,
    /// WebAuthn passkeys (ADR-0017); absent: disabled.
    #[serde(default)]
    pub webauthn: Option<crate::factor::webauthn::Configuration>,
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
    /// Session-wide timers (`session.idle`, `session.absolute`).
    #[serde(default)]
    pub session: SessionTimers,
    #[serde(default)]
    pub cookie: Cookie,
    #[serde(default)]
    pub apps: Vec<AppEntry>,
    #[serde(default)]
    pub providers: Vec<ProviderEntry>,
    #[serde(default)]
    pub authentication_gateway: Option<crate::auth_gateway::runtime::Config>,
    #[serde(default)]
    pub credential_projection: Option<crate::auth_gateway::projection::Configuration>,
    /// Which side owns the authentication profiles and the credential
    /// projection plan: the store (default, console/API edits) or this file
    /// (`config`: reconciled at every start, console edits refused).
    #[serde(default)]
    pub authentication: AuthenticationCfg,
    /// Polling of mounted material that changes while Hopae runs.
    #[serde(default)]
    pub reload: ReloadCfg,
    /// Console operators (ADR-0021): the application a management console
    /// (the Hangang console) signs its operators in through, the
    /// phishing-resistant factor it requires and the signed operator
    /// assertion verify answers with.
    #[serde(default)]
    pub console_operators: Option<ConsoleOperatorsCfg>,
    /// The gateway's signed risk context (ADR-0023).
    #[serde(default)]
    pub risk: Option<crate::policy::risk::RiskCfg>,
    /// The file this configuration was read from (set by [`load`]; never
    /// configured). Live reconciliation polls it.
    #[serde(skip)]
    pub source_path: Option<PathBuf>,
    #[serde(default)]
    pub linking: Linking,
    #[serde(default)]
    pub txn: Txn,
    #[serde(default)]
    pub handoff: HandoffCfg,
    #[serde(default)]
    pub events: EventsCfg,
    #[serde(default = "default_trusted_proxies")]
    pub trusted_proxies: Vec<String>,
    #[serde(default)]
    pub limits: Limits,
    #[serde(default)]
    pub sessions: SessionsCfg,
    /// The management console (ADR-0016); enabled by `admin.public_url`.
    #[serde(default)]
    pub admin: AdminCfg,
    /// Groups and the signed membership projection (ADR-0019).
    #[serde(default)]
    pub groups: Option<crate::groups::GroupsConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Listen {
    #[serde(default = "default_portal_addr")]
    pub portal: String,
    #[serde(default = "default_gateway_addr")]
    pub gateway: String,
    /// Authenticated persistent verification; remote transport requires mTLS.
    #[serde(default)]
    pub native_gateway: Option<String>,
    /// Additional gRPC verification endpoint; mandatory shared gateway mTLS.
    #[serde(default)]
    pub grpc_gateway: Option<String>,
    #[serde(default)]
    pub native_gateway_tls: Option<NativeGatewayTls>,
    /// Admin listener; `127.0.0.1:8702` when `admin.public_url` is set.
    #[serde(default)]
    pub admin: Option<String>,
    /// Optional mandatory mTLS for the administrator listener.
    #[serde(default)]
    pub admin_tls: Option<NativeGatewayTls>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeGatewayTls {
    pub certificate: PathBuf,
    pub key: PathBuf,
    pub client_ca: PathBuf,
}

impl Default for Listen {
    fn default() -> Self {
        Self {
            portal: default_portal_addr(),
            gateway: default_gateway_addr(),
            native_gateway: None,
            grpc_gateway: None,
            native_gateway_tls: None,
            admin: None,
            admin_tls: None,
        }
    }
}

fn default_admin_addr() -> String {
    "127.0.0.1:8702".into()
}

/// What the admin listener does with a TCP peer outside `trusted_proxies`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UntrustedPeers {
    /// `403 untrusted_peer` before any header is read.
    #[default]
    Refuse,
    /// Treat the peer as the client, as the portal does.
    AsClient,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdminRoleCfg {
    Admin,
    Viewer,
}

/// `authentication` (configuration ownership of the authentication profiles
/// and the credential projection plan).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticationCfg {
    #[serde(default)]
    pub source: AuthenticationSource,
    /// `source = config`: how often the configuration file is polled for a
    /// changed profile or projection plan (milliseconds; `0` turns live
    /// reconciliation off, so only a restart applies a change).
    #[serde(default)]
    pub reload_interval_ms: Option<u64>,
}

/// `console_operators.require_factor`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorFactorCfg {
    /// A passkey (default): phishing resistant.
    #[default]
    Webauthn,
    /// Any second factor (TOTP, external, passkey).
    Any,
}

/// `console_operators` (ADR-0021).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsoleOperatorsCfg {
    /// The application (`apps[].app_id`) whose host the console runs on.
    pub app_id: String,
    /// `2` (default) or `3` (needs `webauthn.high_assurance`).
    #[serde(default)]
    pub require_aal: Option<u8>,
    #[serde(default)]
    pub require_factor: OperatorFactorCfg,
    /// The console path a sensitive action re-authenticates on (default
    /// `/ui/step-up`): it requires the factor used within `step_up_max_age_secs`.
    #[serde(default)]
    pub step_up_path: Option<String>,
    /// Freshness of the factor on `step_up_path` (default 300, 30 to 3600).
    #[serde(default)]
    pub step_up_max_age_secs: Option<u64>,
    /// Until this time (unix seconds) an operator without a passkey is
    /// admitted to the console without the factor (and the assertion says
    /// `grace: true`); `step_up_path` is never waived.
    #[serde(default)]
    pub enrollment_grace_until: Option<i64>,
    /// The variable holding the Ed25519 seed (base64, 32 bytes) the operator
    /// assertion is signed with; dedicated to the assertion.
    pub assertion_seed_env: String,
    /// The public key of that seed (base64, 32 bytes); a mismatch refuses the
    /// configuration. The console pins it.
    pub assertion_public_key: String,
    /// The key id the assertion names (`kid`) so the console can pin the
    /// current and the next key during a rotation (1 to 64 of `A-Za-z0-9._-`).
    pub assertion_key_id: String,
}

impl ConsoleOperatorsCfg {
    pub fn require_aal(&self) -> Aal {
        if self.require_aal == Some(3) {
            Aal::Three
        } else {
            Aal::Two
        }
    }
    pub fn step_up_path(&self) -> String {
        self.step_up_path
            .clone()
            .unwrap_or_else(|| "/ui/step-up".into())
    }
    pub fn step_up_max_age(&self) -> Duration {
        Duration::from_secs(self.step_up_max_age_secs.unwrap_or(300))
    }
    fn factor(&self) -> Option<crate::session::types::FactorKind> {
        match self.require_factor {
            OperatorFactorCfg::Webauthn => Some(crate::session::types::FactorKind::Webauthn),
            OperatorFactorCfg::Any => None,
        }
    }
    /// The step-up rules the console application gets: the whole host at the
    /// required level and factor (waived during the enrollment grace for an
    /// operator without a passkey), and the step-up path with freshness.
    pub fn rules(&self) -> Vec<StepUpRule> {
        vec![
            StepUpRule {
                path_prefix: None,
                aal: self.require_aal(),
                max_age: None,
                factor: self.factor(),
                enrollment_grace: true,
            },
            StepUpRule {
                path_prefix: Some(self.step_up_path()),
                aal: self.require_aal(),
                max_age: Some(self.step_up_max_age()),
                factor: self.factor(),
                enrollment_grace: false,
            },
        ]
    }
    fn validate(&self, cfg: &Config, errs: &mut Vec<String>) {
        if self.app_id == "default" || !cfg.apps.iter().any(|a| a.app_id == self.app_id) {
            errs.push(format!(
                "console_operators.app_id {:?} must name a configured application (not default)",
                self.app_id
            ));
        }
        match self.require_aal {
            None | Some(2) => {}
            Some(3)
                if cfg
                    .webauthn
                    .as_ref()
                    .is_some_and(|w| w.high_assurance.is_some()) => {}
            Some(3) => {
                errs.push("console_operators.require_aal 3 needs webauthn.high_assurance".into())
            }
            Some(_) => errs.push("console_operators.require_aal must be 2 or 3".into()),
        }
        if self.require_factor == OperatorFactorCfg::Webauthn && cfg.webauthn.is_none() {
            errs.push("console_operators.require_factor webauthn needs webauthn".into());
        }
        if !self.step_up_path().starts_with('/') || self.step_up_path().len() > 256 {
            errs.push("console_operators.step_up_path must start with '/'".into());
        }
        if !(30..=3600).contains(&self.step_up_max_age().as_secs()) {
            errs.push("console_operators.step_up_max_age_secs must be between 30 and 3600".into());
        }
        if !valid_env_name(&self.assertion_seed_env) {
            errs.push(
                "console_operators.assertion_seed_env must be an environment variable name".into(),
            );
        }
        let pk = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            self.assertion_public_key.trim(),
        );
        if !pk.is_ok_and(|k| {
            k.as_slice()
                .try_into()
                .is_ok_and(|k| ed25519_dalek::VerifyingKey::from_bytes(k).is_ok())
        }) {
            errs.push(
                "console_operators.assertion_public_key must be a base64 Ed25519 public key".into(),
            );
        }
        if self.assertion_key_id.is_empty()
            || self.assertion_key_id.len() > 64
            || !self
                .assertion_key_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        {
            errs.push("console_operators.assertion_key_id must be 1 to 64 of A-Za-z0-9._-".into());
        }
    }
}

/// Default poll of the configuration file in `authentication.source = config`.
pub const AUTH_RELOAD_DEFAULT_MS: u64 = 1000;
/// Default poll of TLS certificate, key and CA files.
pub const TLS_RELOAD_DEFAULT_SECS: u64 = 10;

/// `reload`: polling of TLS material (no file-system notifications: a
/// Kubernetes secret volume swaps a symlink, which inotify watches miss).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReloadCfg {
    /// Seconds between polls of every TLS certificate, key and CA file
    /// (listeners and outbound mTLS clients); `0` turns reloading off.
    #[serde(default)]
    pub tls_interval_secs: Option<u64>,
}

impl Config {
    /// The TLS poll interval, `None` when reloading is off.
    pub fn tls_reload_interval(&self) -> Option<Duration> {
        match self
            .reload
            .tls_interval_secs
            .unwrap_or(TLS_RELOAD_DEFAULT_SECS)
        {
            0 => None,
            n => Some(Duration::from_secs(n)),
        }
    }

    /// The configuration poll interval in `authentication.source = config`,
    /// `None` in store mode or when turned off.
    pub fn auth_reload_interval(&self) -> Option<Duration> {
        if self.authentication.source != AuthenticationSource::Config {
            return None;
        }
        match self
            .authentication
            .reload_interval_ms
            .unwrap_or(AUTH_RELOAD_DEFAULT_MS)
        {
            0 => None,
            n => Some(Duration::from_millis(n)),
        }
    }
}

/// `authentication.source`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthenticationSource {
    /// The store is authoritative; the file only bootstraps an empty store.
    #[default]
    Store,
    /// The file is authoritative: every start reconciles the store to it
    /// through the validated CAS publication; console/API edits are refused.
    Config,
}

impl AuthenticationSource {
    pub fn as_str(self) -> &'static str {
        match self {
            AuthenticationSource::Store => "store",
            AuthenticationSource::Config => "config",
        }
    }
}

/// `admin` (ADR-0016): the console's address, policy and seeded grants.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminCfg {
    #[serde(default)]
    pub hangang_delegation: Option<crate::admin::delegation::Config>,
    /// Externally visible origin of the console; enables the listener.
    #[serde(default)]
    pub public_url: Option<String>,
    #[serde(default)]
    pub session: Option<AppSessionCfg>,
    #[serde(default)]
    pub binding: Option<BindingCfg>,
    #[serde(default)]
    pub max_auth_age: Option<ConfigDuration>,
    #[serde(default)]
    pub require_aal: Option<u8>,
    #[serde(default)]
    pub untrusted_peers: Option<UntrustedPeers>,
    #[serde(default)]
    pub query_budget_ms: Option<u64>,
    /// The least private profile the subject directory and the explain API
    /// may answer with; a request may only ask for a stricter one.
    #[serde(default)]
    pub directory_privacy: Option<DirectoryPrivacy>,
    #[serde(default)]
    pub users: Vec<AdminUserEntry>,
    /// The audience route-scoped service credentials must name
    /// (`x-hopae-audience`); default the console origin.
    #[serde(default)]
    pub service_audience: Option<String>,
}

/// `admin.directory_privacy`: the operator's floor for the privacy profile of
/// the audited directory reads. `strict` > `standard`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectoryPrivacy {
    #[default]
    Standard,
    Strict,
}

/// One seeded grant: at least one of `user_id` and `email`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminUserEntry {
    #[serde(default)]
    pub user_id: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    /// `admin` when absent.
    #[serde(default)]
    pub role: Option<AdminRoleCfg>,
    #[serde(default)]
    pub note: Option<String>,
}

/// The console's numbers, with defaults applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdminLimits {
    pub max_auth_age: Duration,
    pub require_aal: Aal,
    pub untrusted_peers: UntrustedPeers,
    pub query_budget: Duration,
    /// `admin.directory_privacy` (default `standard`).
    pub directory_privacy: DirectoryPrivacy,
}

const ADMIN_MAX_AUTH_AGE_DEFAULT: Duration = Duration::from_secs(12 * 3600);

/// A user id as the console and the commands accept it: `u_` and up to 62
/// letters, digits, `_` or `-`.
pub fn valid_user_id(s: &str) -> bool {
    s.len() >= 3
        && s.len() <= 64
        && s.starts_with("u_")
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn default_portal_addr() -> String {
    "127.0.0.1:8700".into()
}
fn default_gateway_addr() -> String {
    "127.0.0.1:8701".into()
}
fn default_trusted_proxies() -> Vec<String> {
    vec!["127.0.0.1/32".into()]
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Store {
    /// `sqlite` (default) or `postgres` (ADR-0020; `backend` is an alias).
    #[serde(default, alias = "backend")]
    pub kind: StoreKind,
    /// Database file; defaults to `<state_dir>/hopae.db`.
    #[serde(default)]
    pub path: Option<PathBuf>,
    /// PostgreSQL connection (required with `kind = "postgres"`).
    #[serde(default)]
    pub postgres: Option<PostgresStore>,
}

/// `store.postgres` (ADR-0020). The connection string is read from the
/// environment variable `url_env`, never from the file.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostgresStore {
    pub url_env: String,
    /// PEM CA bundle for TLS (`verify-full`); without it only loopback or a
    /// Unix socket is allowed.
    #[serde(default)]
    pub ca_file: Option<PathBuf>,
    #[serde(default = "default_pg_pool")]
    pub pool_size: usize,
    #[serde(default = "default_pg_connect")]
    pub connect_timeout_ms: u64,
    #[serde(default = "default_pg_statement")]
    pub statement_timeout_ms: u64,
}

fn default_pg_pool() -> usize {
    16
}
fn default_pg_connect() -> u64 {
    5000
}
fn default_pg_statement() -> u64 {
    2000
}

impl Default for Store {
    fn default() -> Self {
        Self {
            kind: StoreKind::Sqlite,
            path: None,
            postgres: None,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StoreKind {
    #[default]
    Sqlite,
    /// ADR-0020 slice 1: store library and conformance tests only; `serve`
    /// refuses it until the remaining slices land.
    Postgres,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Portal {
    /// Externally visible portal origin, used for every emitted `Location`.
    pub public_url: String,
    /// One-click confirmation before the first handoff of a session to a host.
    #[serde(default)]
    pub sso_confirm_new_host: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gateway {
    pub kind: GatewayKind,
    /// Name of the environment variable holding the shared caller key.
    #[serde(default)]
    pub caller_key_env: Option<String>,
    /// Name of the variable holding the second accepted key during rotation.
    #[serde(default)]
    pub caller_key_next_env: Option<String>,
    /// Development only: skip caller-key authentication.
    #[serde(default)]
    pub allow_unauthenticated_caller: bool,
    /// Total verify budget in milliseconds (default 400).
    #[serde(default = "default_budget_ms")]
    pub verify_budget_ms: u64,
    /// Read-only gateway credential, used only by `hopae --check`.
    #[serde(default)]
    pub readonly_token_env: Option<String>,
    /// Base URL of the gateway's admin API, used only by `hopae --check`
    /// (with `readonly_token_env`) to warn about application hosts without a route.
    #[serde(default)]
    pub admin_url: Option<String>,
}

fn default_budget_ms() -> u64 {
    400
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
    /// Log every allowed verify individually.
    #[serde(default)]
    pub verify_allow: bool,
    /// Record a client-supplied `x-request-id` (truncated) in `attrs.client_request_id`.
    #[serde(default)]
    pub accept_client_request_id: bool,
}

impl Default for Log {
    fn default() -> Self {
        Self {
            level: default_level(),
            verify_allow: false,
            accept_client_request_id: false,
        }
    }
}

fn default_level() -> String {
    "info".into()
}

/// A duration written as an integer and a unit: `30s`, `10m`, `12h`, `7d`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfigDuration(pub Duration);

impl ConfigDuration {
    pub fn parse(s: &str) -> Option<Duration> {
        let (num, unit) = s.split_at(s.len().checked_sub(1)?);
        let n: u64 = num.parse().ok().filter(|n| *n > 0)?;
        let secs = match unit {
            "s" => 1,
            "m" => 60,
            "h" => 3600,
            "d" => 86400,
            _ => return None,
        };
        n.checked_mul(secs).map(Duration::from_secs)
    }
}

impl<'de> Deserialize<'de> for ConfigDuration {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        ConfigDuration::parse(&s)
            .map(ConfigDuration)
            .ok_or_else(|| serde::de::Error::custom("duration must look like 30s, 10m, 12h or 7d"))
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionTimers {
    #[serde(default)]
    pub idle: Option<ConfigDuration>,
    #[serde(default)]
    pub absolute: Option<ConfigDuration>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cookie {
    /// Handle cookie name; the binding and portal cookies append `_bind` and `_portal`.
    /// Default `__Host-hopae` (`hopae` when `secure` is false).
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default = "default_true")]
    pub secure: bool,
}

impl Default for Cookie {
    fn default() -> Self {
        Self {
            name: None,
            secure: true,
        }
    }
}

fn default_true() -> bool {
    true
}

/// The three cookie names derived from `cookie.name`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CookieNames {
    pub handle: String,
    pub bind: String,
    pub portal: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppEntry {
    pub app_id: String,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub hosts: Vec<String>,
    /// Default `[443]` (`[80]` when `cookie.secure` is false).
    #[serde(default)]
    pub ports: Option<Vec<u16>>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub session: Option<AppSessionCfg>,
    #[serde(default)]
    pub binding: Option<BindingCfg>,
    #[serde(default)]
    pub on_authz_change: Option<AuthzChangeCfg>,
    #[serde(default)]
    pub verify_cache_seconds: Option<u32>,
    /// `/_hopae/logout` goes through the portal's confirmation page (default
    /// `true`); `false` ends the session at once for a same-origin navigation.
    #[serde(default)]
    pub logout_confirm: Option<bool>,
    #[serde(default)]
    pub step_up: Vec<StepUpEntry>,
    /// Highest assurance level presented to this application (ADR-0018):
    /// `2` (default) or `3`. `3` needs `webauthn.high_assurance`.
    #[serde(default)]
    pub max_emitted_aal: Option<u8>,
    /// Risk-based step-up rules (ADR-0023); needs the top-level `risk`.
    #[serde(default)]
    pub risk: Option<crate::policy::risk::AppRiskCfg>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppSessionCfg {
    #[serde(default)]
    pub idle: Option<ConfigDuration>,
    #[serde(default)]
    pub absolute: Option<ConfigDuration>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BindingCfg {
    #[serde(default)]
    pub ip: Option<IpMode>,
    #[serde(default)]
    pub ip_prefix_v4: Option<u8>,
    #[serde(default)]
    pub ip_prefix_v6: Option<u8>,
    #[serde(default)]
    pub ua: Option<UaMode>,
    #[serde(default)]
    pub on_mismatch: Option<OnMismatchCfg>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpMode {
    Strict,
    Prefix,
    Off,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UaMode {
    Strict,
    Off,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnMismatchCfg {
    TerminateSession,
    DropHandle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthzChangeCfg {
    Refresh,
    Terminate,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StepUpEntry {
    #[serde(default)]
    pub path_prefix: Option<String>,
    pub require: StepUpRequire,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StepUpRequire {
    pub aal: u8,
    /// Seconds.
    #[serde(default)]
    pub max_age: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderEntry {
    pub provider_id: String,
    pub kind: ProviderKind,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub client_id: String,
    #[serde(default)]
    pub ldap: Option<crate::provider::ldap::Config>,
    /// Environment variable *name* holding the client secret.
    #[serde(default)]
    pub client_secret_env: Option<String>,
    #[serde(default)]
    pub issuer: Option<String>,
    #[serde(default = "default_scope")]
    pub scope: String,
    /// Hosts, besides the issuer's own, that the provider's discovery document
    /// may point to (G7-IDP-03). The `google` preset carries its own.
    #[serde(default)]
    pub endpoint_hosts: Vec<String>,
    /// Allow loopback and private destinations (and `http` to a loopback
    /// issuer). Unset is `false`; development only.
    #[serde(default)]
    pub allow_private_endpoints: Option<bool>,
    /// A private CA and a client certificate for this provider (OIDC).
    #[serde(default)]
    pub tls: Option<crate::policy::types::ProviderTls>,
    /// `private_key_jwt` client authentication (OIDC).
    #[serde(default)]
    pub client_assertion: Option<crate::policy::types::ProviderClientAssertion>,
    #[serde(default)]
    pub allowed_email_domains: Vec<String>,
    #[serde(default)]
    pub authoritative_domains: Vec<String>,
    #[serde(default)]
    pub auto_link: bool,
    #[serde(default)]
    pub trust_email: bool,
    /// Group sync rules (ADR-0019); absent: the provider syncs no groups.
    #[serde(default)]
    pub groups: Option<crate::groups::ProviderGroups>,
}

fn default_scope() -> String {
    "openid email profile".into()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Linking {
    #[serde(default)]
    pub on_conflict: LinkConflict,
    #[serde(default)]
    pub mode: LinkMode,
}

impl Default for Linking {
    fn default() -> Self {
        Self {
            on_conflict: LinkConflict::LinkRequired,
            mode: LinkMode::VerifiedEmail,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkConflict {
    #[default]
    LinkRequired,
    Separate,
    Deny,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkMode {
    #[default]
    VerifiedEmail,
    Off,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Txn {
    #[serde(default = "d_txn_max_rows")]
    pub max_rows: u32,
    #[serde(default = "d_txn_per_ip")]
    pub per_ip_per_minute: u32,
}

impl Default for Txn {
    fn default() -> Self {
        Self {
            max_rows: d_txn_max_rows(),
            per_ip_per_minute: d_txn_per_ip(),
        }
    }
}

fn d_txn_max_rows() -> u32 {
    1000
}
fn d_txn_per_ip() -> u32 {
    30
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HandoffCfg {
    #[serde(default = "d_handoff_failures")]
    pub per_ip_failures_per_minute: u32,
    #[serde(default = "d_handoff_recoveries")]
    pub max_recoveries: u32,
}

impl Default for HandoffCfg {
    fn default() -> Self {
        Self {
            per_ip_failures_per_minute: d_handoff_failures(),
            max_recoveries: d_handoff_recoveries(),
        }
    }
}

fn d_handoff_failures() -> u32 {
    10
}
fn d_handoff_recoveries() -> u32 {
    3
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventsCfg {
    #[serde(default = "d_ev_retention")]
    pub retention_days: u32,
    #[serde(default = "d_ev_max_rows")]
    pub max_rows: u64,
    #[serde(default = "d_ev_prune")]
    pub prune_every: u64,
    #[serde(default = "d_ev_pending")]
    pub max_pending_per_sink: u64,
    #[serde(default = "d_ev_terminal")]
    pub delivery_terminal_retention_days: u32,
}

impl Default for EventsCfg {
    fn default() -> Self {
        Self {
            retention_days: d_ev_retention(),
            max_rows: d_ev_max_rows(),
            prune_every: d_ev_prune(),
            max_pending_per_sink: d_ev_pending(),
            delivery_terminal_retention_days: d_ev_terminal(),
        }
    }
}

fn d_ev_retention() -> u32 {
    90
}
fn d_ev_max_rows() -> u64 {
    1_000_000
}
fn d_ev_prune() -> u64 {
    1000
}
fn d_ev_pending() -> u64 {
    10_000
}
fn d_ev_terminal() -> u32 {
    7
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    #[serde(default = "d_gw_max")]
    pub gateway_max_concurrent: u32,
    #[serde(default = "d_portal_max")]
    pub portal_max_concurrent: u32,
    #[serde(default = "d_admin_max")]
    pub admin_max_concurrent: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            gateway_max_concurrent: d_gw_max(),
            portal_max_concurrent: d_portal_max(),
            admin_max_concurrent: d_admin_max(),
        }
    }
}

fn d_admin_max() -> u32 {
    16
}

fn d_gw_max() -> u32 {
    64
}
fn d_portal_max() -> u32 {
    256
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionsCfg {
    #[serde(default = "d_sessions_retention")]
    pub retention_days: u32,
}

impl Default for SessionsCfg {
    fn default() -> Self {
        Self {
            retention_days: d_sessions_retention(),
        }
    }
}

fn d_sessions_retention() -> u32 {
    30
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
    let mut cfg = parse(&text)?;
    cfg.source_path = Some(path.to_path_buf());
    Ok(cfg)
}

/// Parse and validate configuration text.
pub fn parse(text: &str) -> Result<Config, ConfigError> {
    let value: serde_json::Value = serde_json::from_str(text)?;
    let unknown = keys::check(&value);
    if !unknown.is_empty() {
        return Err(ConfigError::Invalid(unknown));
    }
    let cfg: Config = serde_json::from_value(value)?;
    cfg.validate()?;
    Ok(cfg)
}

const LEVELS: [&str; 5] = ["error", "warn", "info", "debug", "trace"];

fn valid_env_name(s: &str) -> bool {
    let mut chars = s.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// `[a-z0-9][a-z0-9_-]{0,31}`: safe in a URL path segment and a log line.
fn valid_slug(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 32
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_' || *c == b'-')
}

fn valid_cookie_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
}

fn parse_proxy(s: &str) -> Option<ipnet::IpNet> {
    s.parse::<ipnet::IpNet>()
        .ok()
        .or_else(|| s.parse::<std::net::IpAddr>().ok().map(ipnet::IpNet::from))
}

impl Config {
    /// Check every constraint that does not need the environment.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let mut errs = Vec::new();
        if let Some(c) = &self.console_operators {
            c.validate(self, &mut errs);
        }
        if let Some(n) = self.reload.tls_interval_secs
            && n > 3600
        {
            errs.push("reload.tls_interval_secs must be between 0 (off) and 3600".to_string());
        }
        if let Some(n) = self.authentication.reload_interval_ms
            && n != 0
            && !(200..=60_000).contains(&n)
        {
            errs.push(
                "authentication.reload_interval_ms must be 0 (off) or between 200 and 60000"
                    .to_string(),
            );
        }
        let portal = self.listen.portal.parse::<SocketAddr>();
        let gateway = self.listen.gateway.parse::<SocketAddr>();
        if portal.is_err() {
            errs.push("listen.portal must be a socket address such as 127.0.0.1:8700".to_string());
        }
        if gateway.is_err() {
            errs.push("listen.gateway must be a socket address such as 127.0.0.1:8701".to_string());
        }
        let (portal, gateway) = (portal.ok(), gateway.ok());
        if let (Some(p), Some(g)) = (portal, gateway)
            && p == g
            && p.port() != 0
        {
            errs.push("listen.portal and listen.gateway must differ".to_string());
        }
        if let Some(tls) = &self.listen.native_gateway_tls
            && ((self.listen.native_gateway.is_none() && self.listen.grpc_gateway.is_none())
                || [&tls.certificate, &tls.key, &tls.client_ca]
                    .iter()
                    .any(|p| !p.is_absolute()))
        {
            errs.push("native gateway TLS requires a listener and absolute certificate/key/client_ca paths".into());
        }
        if let Some(value) = &self.listen.native_gateway {
            match value.parse::<SocketAddr>() {
                Ok(address) if (address.ip().is_loopback() || self.listen.native_gateway_tls.is_some()) && !address.ip().is_multicast() => {
                    if address.port() != 0
                        && (Some(address) == portal
                            || Some(address) == gateway
                            || self
                                .listen
                                .admin
                                .as_ref()
                                .and_then(|a| a.parse::<SocketAddr>().ok())
                                == Some(address))
                    {
                        errs.push("listen.native_gateway must have a distinct address".into());
                    }
                    if self.gateway.allow_unauthenticated_caller {
                        errs.push("native gateway requires authenticated callers".into());
                    }
                }
                _ => errs
                    .push("listen.native_gateway must be a literal socket address; outside loopback mTLS is required".into()),
            }
        }
        if let Some(value) = &self.listen.grpc_gateway {
            match value.parse::<SocketAddr>() {
                Ok(address) if !address.ip().is_multicast() && self.listen.native_gateway_tls.is_some() && !self.gateway.allow_unauthenticated_caller => {
                    if address.port() != 0 && [self.listen.portal.as_str(), self.listen.gateway.as_str(), self.listen.native_gateway.as_deref().unwrap_or(""), self.listen.admin.as_deref().unwrap_or("")].iter().any(|v| v.parse::<SocketAddr>().ok() == Some(address)) {
                        errs.push("listen.grpc_gateway must have a distinct address".into());
                    }
                }
                _ => errs.push("listen.grpc_gateway requires a literal address, mTLS and authenticated callers".into()),
            }
        }
        if let Some(tls) = &self.listen.admin_tls
            && (!self.admin_enabled()
                || [&tls.certificate, &tls.key, &tls.client_ca]
                    .iter()
                    .any(|p| !p.is_absolute()))
        {
            errs.push("listen.admin_tls requires an enabled console and absolute TLS paths".into());
        }
        if let Some(a) = &self.admin.service_audience
            && (a.is_empty() || a.len() > 256 || !a.bytes().all(|b| b.is_ascii_graphic()))
        {
            errs.push("admin.service_audience must be 1-256 visible ASCII characters".into());
        }
        if let Some(a) = &self.listen.admin {
            match a.parse::<SocketAddr>() {
                Err(_) => errs.push(
                    "listen.admin must be a socket address such as 127.0.0.1:8702".to_string(),
                ),
                Ok(a) if a.port() != 0 => {
                    for (name, other) in [("listen.portal", portal), ("listen.gateway", gateway)] {
                        if other == Some(a) {
                            errs.push(format!("listen.admin and {name} must differ"));
                        }
                    }
                }
                Ok(_) => {}
            }
        }
        if self.state_dir.as_os_str().is_empty() {
            errs.push("state_dir must not be empty".to_string());
        }
        if let Some(p) = &self.store.path
            && p.as_os_str().is_empty()
        {
            errs.push("store.path must not be empty".to_string());
        }
        match (self.store.kind, &self.store.postgres) {
            (StoreKind::Sqlite, Some(_)) => {
                errs.push("store.postgres requires store.kind = \"postgres\"".to_string())
            }
            (StoreKind::Postgres, None) => {
                errs.push("store.kind = \"postgres\" requires store.postgres".to_string())
            }
            (StoreKind::Postgres, Some(pg)) => {
                if !cfg!(feature = "postgres") {
                    errs.push(
                        "store.kind = \"postgres\" needs a binary built with the postgres feature"
                            .to_string(),
                    );
                }
                if pg.url_env.is_empty()
                    || pg.url_env.len() > 128
                    || !pg
                        .url_env
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'_')
                {
                    errs.push(
                        "store.postgres.url_env must be an environment variable name".to_string(),
                    );
                }
                if pg.ca_file.as_ref().is_some_and(|p| !p.is_absolute()) {
                    errs.push("store.postgres.ca_file must be an absolute path".to_string());
                }
                if !(1..=128).contains(&pg.pool_size)
                    || !(100..=60_000).contains(&pg.connect_timeout_ms)
                    || !(10..=600_000).contains(&pg.statement_timeout_ms)
                {
                    errs.push("store.postgres: pool_size 1-128, connect_timeout_ms 100-60000, statement_timeout_ms 10-600000".to_string());
                }
            }
            (StoreKind::Sqlite, None) => {}
        }
        if let Err(e) = check_public_url(&self.portal.public_url) {
            errs.push(format!("portal.public_url {e}"));
        }
        self.validate_gateway(&mut errs);
        if !LEVELS.contains(&self.log.level.as_str()) {
            errs.push(format!("log.level must be one of {}", LEVELS.join(", ")));
        }
        self.validate_cookie(&mut errs);
        self.validate_apps(&mut errs);
        if let Some(r) = &self.risk {
            r.validate(&mut errs, valid_env_name);
        }
        self.validate_admin(&mut errs);
        self.validate_providers(&mut errs);
        self.validate_bounds(&mut errs);
        if self.external_verifiers.len() > 64 {
            errs.push("external_verifiers: capacity exceeded".into());
        }
        let mut external_ids = std::collections::BTreeSet::new();
        for (index, verifier) in self.external_verifiers.iter().enumerate() {
            if verifier.validate().is_err() || !external_ids.insert(verifier.factor.as_str()) {
                errs.push(format!(
                    "external_verifiers[{index}]: invalid or duplicate configuration"
                ));
            }
        }
        if !self.external_verifiers.is_empty() && self.gateway.allow_unauthenticated_caller {
            errs.push("external_verifiers requires authenticated gateway callers".into());
        }
        if self
            .human_material_key_env
            .as_ref()
            .is_some_and(|name| name.len() > 128 || !valid_env_name(name))
        {
            errs.push(
                "human_material_key_env must be a bounded environment variable reference".into(),
            );
        }
        if let Some(webauthn) = &self.webauthn {
            errs.extend(webauthn.validate(&self.portal.public_url));
            if self.gateway.allow_unauthenticated_caller {
                errs.push("webauthn requires authenticated gateway callers".into());
            }
            if !self.portal.public_url.starts_with("https://") || !self.cookie.secure {
                errs.push("webauthn requires an https portal and secure cookies".into());
            }
        }
        if let Some(keys) = &self.totp_keyring {
            if keys.validate_references().is_err() {
                errs.push("totp_keyring: invalid key references".into());
            }
            if self.gateway.allow_unauthenticated_caller {
                errs.push("totp_keyring requires authenticated gateway callers".into());
            }
        }

        if crate::auth_gateway::receipt_config::receiver_keys(
            self.receipt_issuer.as_ref(),
            &self.receipt_permit_keys,
        )
        .is_err()
        {
            errs.push("receipt_permit_keys: invalid native receiver keys".into());
        }
        if let Some(receiver) = &self.projection_receiver
            && (self.receipt_issuer.is_none()
                || self.receipt_permit_keys.is_empty()
                || (self.authentication_gateway.is_none()
                    && receiver.human_observed_scopes.is_empty())
                || self.listen.grpc_gateway.is_none()
                || self.listen.native_gateway_tls.is_none()
                || self.gateway.allow_unauthenticated_caller
                || self
                    .credential_projection
                    .as_ref()
                    .is_none_or(|plans| receiver.validate_plans(plans).is_err()))
        {
            errs.push("projection_receiver requires valid native issuer, permit keys, profiles, declared plans and mTLS gRPC".into());
        }
        if let Some(receiver) = &self.projection_receiver {
            for scope in &receiver.human_observed_scopes {
                if !self
                    .receipt_issuer
                    .as_ref()
                    .and_then(|i| i.human_receipts.as_ref())
                    .is_some_and(|human| {
                        human
                            .scopes
                            .iter()
                            .filter(|native| {
                                native.service == scope.service
                                    && native.audience == scope.audience
                                    && native.application == scope.application
                                    && native.route == scope.route
                            })
                            .count()
                            > 0
                    })
                {
                    errs.push("projection_receiver human_observed_scopes requires exact declared native Human scope".into());
                }
            }
            for scope in &receiver.workload_observed_scopes {
                if !self
                    .receipt_issuer
                    .as_ref()
                    .and_then(|i| i.workload_receipts.as_ref())
                    .is_some_and(|w| {
                        w.scopes
                            .iter()
                            .any(|s| s.service == scope.service && s.audience == scope.audience)
                    })
                {
                    errs.push("projection_receiver workload_observed_scopes requires declared native Workload issuer scopes".into());
                }
            }
        }
        if let Some(config) = &self.receipt_issuer {
            if let Some(workloads) = &config.workload_receipts
                && (self.listen.grpc_gateway.is_none()
                    || self.listen.native_gateway_tls.is_none()
                    || workloads.scopes.iter().any(|scope| {
                        self.authentication_gateway.as_ref().is_none_or(|gateway| {
                            !gateway.profiles.iter().any(|profile| {
                                profile.service_id == scope.service
                                    && (profile.kubernetes_tokenreview.is_some()
                                        || profile.kubernetes_workload.is_some())
                            })
                        })
                    }))
            {
                errs.push("workload_receipts requires mTLS gRPC and native Kubernetes workload profiles for every scope".into());
            }
            if let Some(humans) = &config.human_receipts {
                if self.listen.grpc_gateway.is_none() || self.listen.native_gateway_tls.is_none() {
                    errs.push("human_receipts requires authenticated mTLS gRPC".into());
                }
                if humans.scopes.iter().any(|scope| {
                    !self
                        .apps
                        .iter()
                        .any(|app| app.app_id.as_str() == scope.application)
                }) {
                    errs.push(
                        "human_receipts application must match a configured application".into(),
                    );
                }
            }
            if config.validate().is_err() {
                errs.push("receipt_issuer: invalid native resources".into());
            }
            if self.gateway.allow_unauthenticated_caller {
                errs.push("receipt_issuer requires authenticated gateway callers".into());
            }
            if config.scopes.iter().any(|scope| {
                !self
                    .apps
                    .iter()
                    .any(|app| app.app_id.as_str() == scope.service)
                    && !config.human_receipts.as_ref().is_some_and(|humans| {
                        humans.scopes.iter().any(|human| {
                            human.service == scope.service
                                && human.audience == scope.audience
                                && self
                                    .apps
                                    .iter()
                                    .any(|app| app.app_id.as_str() == human.application)
                        })
                    })
            }) {
                errs.push("receipt_issuer service must match a configured application".into());
            }
        }
        if let Some(config) = &self.credential_projection {
            if config.revision != 1
                || crate::auth_gateway::projection::Projector::compile(config.clone()).is_err()
            {
                errs.push("credential_projection: invalid bootstrap plans/revision".into());
            }
            if self.gateway.allow_unauthenticated_caller {
                errs.push("credential_projection requires authenticated gateway callers".into());
            }
            if config.plans.iter().any(|plan| {
                let legacy = self
                    .apps
                    .iter()
                    .any(|app| app.app_id.as_str() == plan.service);
                let human = matches!(plan.minimum_aal, 1 | 2)
                    && self.projection_receiver.as_ref().is_some_and(|receiver| {
                        receiver.human_observed_scopes.iter().any(|scope| {
                            scope.service == plan.service
                                && scope.audience == plan.audience
                                && self
                                    .apps
                                    .iter()
                                    .any(|app| app.app_id.as_str() == scope.application)
                                && self
                                    .receipt_issuer
                                    .as_ref()
                                    .and_then(|issuer| issuer.human_receipts.as_ref())
                                    .is_some_and(|human| {
                                        human.scopes.iter().any(|native| {
                                            native.service == scope.service
                                                && native.audience == scope.audience
                                                && native.application == scope.application
                                                && native.route == scope.route
                                        })
                                    })
                        })
                    });
                !(legacy || human)
            }) {
                errs.push(
                    "credential_projection service must match a configured application".into(),
                );
            }
        }
        if let Some(config) = &self.authentication_gateway {
            if let Err(error) = config.validate() {
                errs.push(format!("authentication_gateway: {error}"));
            }
            if self.gateway.allow_unauthenticated_caller {
                errs.push("authentication_gateway requires authenticated gateway callers".into());
            }
            for profile in &config.profiles {
                if !self.apps.iter().any(|app| {
                    app.app_id.as_str() == profile.service_id
                        && app
                            .hosts
                            .iter()
                            .any(|host| host.eq_ignore_ascii_case(&profile.host))
                        && profile.ports.iter().all(|port| {
                            app.ports.as_ref().map_or(
                                *port == if self.cookie.secure { 443 } else { 80 },
                                |ports| ports.contains(port),
                            )
                        })
                }) {
                    errs.push("authentication_gateway profile must match a configured application host/port".into());
                }
            }
        }
        if errs.is_empty() {
            Ok(())
        } else {
            Err(ConfigError::Invalid(errs))
        }
    }

    fn validate_gateway(&self, errs: &mut Vec<String>) {
        let g = &self.gateway;
        match (&g.caller_key_env, g.allow_unauthenticated_caller) {
            (Some(name), _) if !valid_env_name(name) => {
                errs.push("gateway.caller_key_env must be an environment variable name ([A-Za-z_][A-Za-z0-9_]*)".to_string());
            }
            (None, false) => errs.push(
                "gateway.caller_key_env is required unless gateway.allow_unauthenticated_caller is true".to_string(),
            ),
            _ => {}
        }
        if let Some(next) = &g.caller_key_next_env {
            if !valid_env_name(next) {
                errs.push("gateway.caller_key_next_env must be an environment variable name ([A-Za-z_][A-Za-z0-9_]*)".to_string());
            }
            if g.caller_key_env.is_none() {
                errs.push(
                    "gateway.caller_key_next_env requires gateway.caller_key_env".to_string(),
                );
            }
            if g.caller_key_env.as_ref() == Some(next) {
                errs.push(
                    "gateway.caller_key_next_env must differ from gateway.caller_key_env"
                        .to_string(),
                );
            }
        }
        if let Some(name) = &g.readonly_token_env
            && !valid_env_name(name)
        {
            errs.push("gateway.readonly_token_env must be an environment variable name ([A-Za-z_][A-Za-z0-9_]*)".to_string());
        }
        if let Some(u) = &g.admin_url {
            match url::Url::parse(u) {
                Ok(p)
                    if matches!(p.scheme(), "http" | "https")
                        && p.host_str().is_some()
                        && p.username().is_empty()
                        && p.password().is_none() => {}
                _ => errs.push(
                    "gateway.admin_url must be an http(s) URL without credentials".to_string(),
                ),
            }
        }
        if !(1..=10_000).contains(&g.verify_budget_ms) {
            errs.push("gateway.verify_budget_ms must be between 1 and 10000".to_string());
        }
    }

    fn validate_cookie(&self, errs: &mut Vec<String>) {
        let name = self.cookie_names().handle;
        if !valid_cookie_name(&name) {
            errs.push(
                "cookie.name must be 1-64 characters of letters, digits, '_' and '-'".to_string(),
            );
        } else if self.cookie.secure && !name.starts_with("__Host-") {
            errs.push("cookie.name must start with __Host- when cookie.secure is true".to_string());
        } else if !self.cookie.secure && name.starts_with("__Host-") {
            errs.push("cookie.name must not start with __Host- when cookie.secure is false (browsers refuse such cookies)".to_string());
        }
    }

    fn validate_apps(&self, errs: &mut Vec<String>) {
        let high_assurance = self
            .webauthn
            .as_ref()
            .is_some_and(|w| w.high_assurance.is_some());
        let mut ids = HashSet::new();
        let mut hosts: HashMap<String, String> = HashMap::new();
        for (i, a) in self.apps.iter().enumerate() {
            let at = format!("apps[{i}]");
            if !valid_slug(&a.app_id) {
                errs.push(format!("{at}.app_id must match [a-z0-9][a-z0-9_-]{{0,31}}"));
            } else if !ids.insert(a.app_id.clone()) {
                errs.push(format!(
                    "{at}.app_id {:?} is used by more than one application",
                    a.app_id
                ));
            }
            match a.max_emitted_aal {
                None | Some(2) => {}
                Some(3) if self.webauthn.as_ref().is_some_and(|w| w.high_assurance.is_some()) => {}
                Some(3) => errs.push(format!(
                    "{at}.max_emitted_aal 3 needs webauthn.high_assurance (only an attested, allowlisted security key yields AAL 3)"
                )),
                Some(_) => errs.push(format!("{at}.max_emitted_aal must be 2 or 3")),
            }
            let is_default = a.app_id == "default";
            if is_default && !a.hosts.is_empty() {
                errs.push(format!("{at}.hosts: the default application carries policy defaults only and must not list hosts"));
            }
            if !is_default && a.hosts.is_empty() {
                errs.push(format!("{at}.hosts must list at least one host"));
            }
            for (j, h) in a.hosts.iter().enumerate() {
                match Host::parse(h) {
                    Ok(host) => {
                        if let Some(first) = hosts.insert(host.to_string(), a.app_id.clone()) {
                            errs.push(format!(
                                "{at}.hosts[{j}]: host {host} is already claimed by application {first:?}"
                            ));
                        }
                    }
                    Err(_) => errs.push(format!(
                        "{at}.hosts[{j}]: hosts must be exact lower-case host names (no scheme, wildcard, port, path or trailing dot)"
                    )),
                }
            }
            if let Some(ports) = &a.ports {
                if ports.is_empty() {
                    errs.push(format!("{at}.ports must not be empty when set"));
                }
                if ports.contains(&0) {
                    errs.push(format!("{at}.ports must not contain 0"));
                }
            }
            if let Some(n) = a.verify_cache_seconds
                && n > 30
            {
                errs.push(format!("{at}.verify_cache_seconds must be at most 30"));
            }
            if let Some(b) = &a.binding {
                for (name, v) in [
                    ("ip_prefix_v4", b.ip_prefix_v4.map(|v| (v, 32))),
                    ("ip_prefix_v6", b.ip_prefix_v6.map(|v| (v, 128))),
                ] {
                    if let Some((v, max)) = v
                        && !(1..=max).contains(&v)
                    {
                        errs.push(format!("{at}.binding.{name} must be between 1 and {max}"));
                    }
                }
            }
            if let Some(r) = &a.risk {
                if self.risk.is_none() {
                    errs.push(format!("{at}.risk needs the top-level risk section"));
                }
                r.compile(&at, high_assurance, errs);
            }
            for (k, rule) in a.step_up.iter().enumerate() {
                match rule.require.aal {
                    1 | 2 => {}
                    3 if high_assurance => {}
                    3 => errs.push(format!(
                        "{at}.step_up[{k}].require.aal 3 needs webauthn.high_assurance (only an attested, allowlisted security key yields AAL 3)"
                    )),
                    _ => errs.push(format!("{at}.step_up[{k}].require.aal must be 1, 2 or 3")),
                }
                if let Some(p) = &rule.path_prefix
                    && !p.starts_with('/')
                {
                    errs.push(format!("{at}.step_up[{k}].path_prefix must start with '/'"));
                }
                if rule.require.max_age == Some(0) {
                    errs.push(format!(
                        "{at}.step_up[{k}].require.max_age must be positive seconds"
                    ));
                }
            }
        }
    }

    fn validate_admin(&self, errs: &mut Vec<String>) {
        let a = &self.admin;
        for (i, app) in self.apps.iter().enumerate() {
            if app.app_id == "admin" {
                errs.push(format!(
                    "apps[{i}].app_id \"admin\" is reserved for the management console"
                ));
            }
        }
        if let Some(u) = &a.public_url {
            match check_admin_origin(u, self.cookie.secure) {
                Err(e) => errs.push(format!("admin.public_url {e}")),
                Ok(host) => {
                    for (i, app) in self.apps.iter().enumerate() {
                        for (j, h) in app.hosts.iter().enumerate() {
                            if h.eq_ignore_ascii_case(host.as_str()) {
                                errs.push(format!(
                                    "apps[{i}].hosts[{j}]: {host} is the console host, which is registered implicitly"
                                ));
                            }
                        }
                    }
                }
            }
        }
        if a.public_url.is_none() {
            // Settings that only apply to a console that exists are an error
            // only when they are wrong; a configuration without a console may carry them.
        }
        if a.session
            .as_ref()
            .and_then(|s| s.idle)
            .is_some_and(|d| d.0 < Duration::from_secs(60))
        {
            errs.push("admin.session.idle must be at least 60s".to_string());
        }
        if let Some(b) = &a.binding {
            for (name, v) in [
                ("ip_prefix_v4", b.ip_prefix_v4.map(|v| (v, 32))),
                ("ip_prefix_v6", b.ip_prefix_v6.map(|v| (v, 128))),
            ] {
                if let Some((v, max)) = v
                    && !(1..=max).contains(&v)
                {
                    errs.push(format!("admin.binding.{name} must be between 1 and {max}"));
                }
            }
        }
        if let Some(n) = a.max_auth_age
            && n.0 < crate::policy::freshness::MIN_MAX_AUTH_AGE
        {
            errs.push("admin.max_auth_age must be at least 30m".to_string());
        }
        match a.require_aal {
            None | Some(1 | 2) => {}
            Some(3) if self.webauthn.as_ref().is_some_and(|w| w.high_assurance.is_some()) => {}
            Some(3) => errs.push(
                "admin.require_aal 3 needs webauthn.high_assurance (only an attested, allowlisted security key yields AAL 3)"
                    .to_string(),
            ),
            Some(_) => errs.push("admin.require_aal must be 1, 2 or 3".to_string()),
        }
        if let Some(ms) = a.query_budget_ms
            && !(100..=30_000).contains(&ms)
        {
            errs.push("admin.query_budget_ms must be between 100 and 30000".to_string());
        }
        if let Some(delegation) = &a.hangang_delegation
            && (a.public_url.is_none()
                || (delegation.authority == crate::admin::delegation::Authority::Hangang
                    && delegation.sessions_file.is_some())
                || delegation.key_env.is_empty()
                || delegation.key_env.len() > 128
                || !delegation
                    .key_env
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_')
                || delegation
                    .sessions_file
                    .as_ref()
                    .is_some_and(|p| !p.is_absolute()))
        {
            errs.push("admin.hangang_delegation requires an admin origin, key_env and absolute sessions_file".into());
        }
        for (i, e) in a.users.iter().enumerate() {
            let at = format!("admin.users[{i}]");
            if e.user_id.is_none() && e.email.is_none() {
                errs.push(format!("{at} needs a user_id or an email"));
            }
            if let Some(id) = &e.user_id
                && !valid_user_id(id)
            {
                errs.push(format!("{at}.user_id is not a well-formed user id"));
            }
            if let Some(m) = &e.email
                && crate::identity::types::NormalizedEmail::parse(m).is_err()
            {
                errs.push(format!("{at}.email is not a valid address"));
            }
            if e.note.as_ref().is_some_and(|n| n.chars().count() > 256) {
                errs.push(format!("{at}.note must be at most 256 characters"));
            }
        }
    }

    fn validate_providers(&self, errs: &mut Vec<String>) {
        let mut ids = HashSet::new();
        if let Some(g) = &self.groups {
            g.validate(errs);
        }
        for (i, p) in self.providers.iter().enumerate() {
            let at = format!("providers[{i}]");
            if let Some(g) = &p.groups {
                g.validate(&i.to_string(), p.kind == ProviderKind::Ldap, errs);
                let staleness = self.groups.as_ref().map_or(
                    crate::groups::GroupsConfig::default().max_staleness_secs,
                    |c| c.max_staleness_secs,
                );
                if g.sync_interval_secs.is_some_and(|s| s >= staleness) {
                    errs.push(format!(
                        "{at}.groups.sync_interval_secs must be shorter than groups.max_staleness_secs"
                    ));
                }
            }
            if !valid_slug(&p.provider_id) {
                errs.push(format!(
                    "{at}.provider_id must match [a-z0-9][a-z0-9_-]{{0,31}}"
                ));
            } else if !ids.insert(p.provider_id.clone()) {
                errs.push(format!(
                    "{at}.provider_id {:?} is used more than once",
                    p.provider_id
                ));
            }
            if p.kind == ProviderKind::Ldap {
                if let Some(ldap) = &p.ldap {
                    if let Err(error) = ldap.validate() {
                        errs.push(format!("{at}.ldap: {error}"));
                    }
                } else {
                    errs.push(format!("{at}.ldap is required"));
                }
                if !p.client_id.is_empty()
                    || p.client_secret_env.is_some()
                    || p.issuer.is_some()
                    || p.auto_link
                    || p.trust_email
                {
                    errs.push(format!(
                        "{at}: LDAP cannot use OIDC credentials or implicit account linking"
                    ));
                }
            } else if p.ldap.is_some() {
                errs.push(format!("{at}.ldap requires kind ldap"));
            }
            if !matches!(p.kind, ProviderKind::Oidc | ProviderKind::Ldap) {
                errs.push(format!(
                    "{at}.kind {:?} is not supported before M3; use oidc or ldap",
                    p.kind.as_str()
                ));
            }
            if p.kind == ProviderKind::Oidc && p.client_id.is_empty() {
                errs.push(format!("{at}.client_id must not be empty"));
            }
            if let Some(env) = &p.client_secret_env
                && !valid_env_name(env)
            {
                errs.push(format!("{at}.client_secret_env must be an environment variable name ([A-Za-z_][A-Za-z0-9_]*)"));
            }
            if let Some(issuer) = &p.issuer
                && let Err(e) = check_issuer(issuer)
            {
                errs.push(format!("{at}.issuer {e}"));
            }
            if p.scope.trim().is_empty() {
                errs.push(format!("{at}.scope must not be empty"));
            }
            if let Some(issuer) = &p.issuer
                && issuer.starts_with("http://")
                && p.allow_private_endpoints != Some(true)
                && !cfg!(feature = "test-hooks")
            {
                errs.push(format!(
                    "{at}.issuer uses http://: set {at}.allow_private_endpoints to true (development only)"
                ));
            }
            if let Some(tls) = &p.tls {
                if p.kind != ProviderKind::Oidc {
                    errs.push(format!("{at}.tls requires kind oidc (LDAP has ldap.ca)"));
                }
                let paths = [
                    &tls.ca_file,
                    &tls.client_certificate_file,
                    &tls.client_key_file,
                ];
                if paths.iter().all(|p| p.is_none()) {
                    errs.push(format!(
                        "{at}.tls must name ca_file or a client certificate"
                    ));
                }
                if paths
                    .iter()
                    .any(|p| p.as_ref().is_some_and(|p| !p.is_absolute()))
                {
                    errs.push(format!("{at}.tls file paths must be absolute"));
                }
                if tls.client_certificate_file.is_some() != tls.client_key_file.is_some() {
                    errs.push(format!(
                        "{at}.tls.client_certificate_file and client_key_file go together"
                    ));
                }
            }
            if let Some(a) = &p.client_assertion {
                if p.kind != ProviderKind::Oidc {
                    errs.push(format!("{at}.client_assertion requires kind oidc"));
                }
                if p.client_secret_env.is_some() {
                    errs.push(format!(
                        "{at}.client_assertion and client_secret_env are exclusive"
                    ));
                }
                if let Err(e) = crate::provider::oidc::assertion::AssertionCfg::of_config(
                    &serde_json::json!({ "client_assertion": a }),
                ) {
                    errs.push(format!("{at}: {e}"));
                }
            }
            for h in &p.endpoint_hosts {
                let h = h.to_ascii_lowercase();
                if !valid_domain(&h) && h.parse::<std::net::IpAddr>().is_err() {
                    errs.push(format!(
                        "{at}.endpoint_hosts entries must be host names or IP addresses without scheme or port"
                    ));
                    break;
                }
            }
            for (name, list) in [
                ("allowed_email_domains", &p.allowed_email_domains),
                ("authoritative_domains", &p.authoritative_domains),
            ] {
                for d in list {
                    if !valid_domain(&d.to_ascii_lowercase()) {
                        errs.push(format!("{at}.{name} entries must be plain domain names"));
                        break;
                    }
                }
            }
        }
    }

    fn validate_bounds(&self, errs: &mut Vec<String>) {
        let positive: [(&str, u64); 12] = [
            ("txn.max_rows", u64::from(self.txn.max_rows)),
            (
                "txn.per_ip_per_minute",
                u64::from(self.txn.per_ip_per_minute),
            ),
            (
                "handoff.per_ip_failures_per_minute",
                u64::from(self.handoff.per_ip_failures_per_minute),
            ),
            (
                "events.retention_days",
                u64::from(self.events.retention_days),
            ),
            ("events.max_rows", self.events.max_rows),
            ("events.prune_every", self.events.prune_every),
            (
                "events.max_pending_per_sink",
                self.events.max_pending_per_sink,
            ),
            (
                "events.delivery_terminal_retention_days",
                u64::from(self.events.delivery_terminal_retention_days),
            ),
            (
                "limits.gateway_max_concurrent",
                u64::from(self.limits.gateway_max_concurrent),
            ),
            (
                "limits.portal_max_concurrent",
                u64::from(self.limits.portal_max_concurrent),
            ),
            (
                "limits.admin_max_concurrent",
                u64::from(self.limits.admin_max_concurrent),
            ),
            (
                "sessions.retention_days",
                u64::from(self.sessions.retention_days),
            ),
        ];
        for (name, v) in positive {
            if v == 0 {
                errs.push(format!("{name} must be at least 1"));
            }
        }
        // Whole-second activity writes are only safe against idle timers of a
        // minute or more (the touch window is half the timer, G7 C03).
        const MIN_IDLE: Duration = Duration::from_secs(60);
        if self.session.idle.is_some_and(|d| d.0 < MIN_IDLE) {
            errs.push("session.idle must be at least 60s".to_string());
        }
        for (i, a) in self.apps.iter().enumerate() {
            if a.session
                .as_ref()
                .and_then(|s| s.idle)
                .is_some_and(|d| d.0 < MIN_IDLE)
            {
                errs.push(format!("apps[{i}].session.idle must be at least 60s"));
            }
        }
        for (i, p) in self.trusted_proxies.iter().enumerate() {
            if parse_proxy(p).is_none() {
                errs.push(format!(
                    "trusted_proxies[{i}] must be an IP address or CIDR such as 127.0.0.1/32"
                ));
            }
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

    /// The console listener exists: `admin.public_url` is set.
    pub fn admin_enabled(&self) -> bool {
        self.admin.public_url.is_some()
    }

    /// Parsed admin listen address (`127.0.0.1:8702` by default); `None` when
    /// the console is not enabled. Only valid after `validate`.
    pub fn admin_addr(&self) -> Option<SocketAddr> {
        if !self.admin_enabled() {
            return None;
        }
        self.listen
            .admin
            .clone()
            .unwrap_or_else(default_admin_addr)
            .parse()
            .ok()
    }

    /// The tuple origin of `admin.public_url`.
    pub fn admin_origin(&self) -> Option<url::Origin> {
        let u = url::Url::parse(self.admin.public_url.as_deref()?).ok()?;
        Some(u.origin())
    }

    /// The console host and the port browsers use for it.
    pub fn admin_host(&self) -> Option<(Host, u16)> {
        let u = url::Url::parse(self.admin.public_url.as_deref()?).ok()?;
        let host = Host::parse(u.host_str()?).ok()?;
        Some((host, u.port_or_known_default()?))
    }

    /// The console's numbers with defaults applied.
    pub fn admin_limits(&self) -> Option<AdminLimits> {
        if !self.admin_enabled() {
            return None;
        }
        let a = &self.admin;
        Some(AdminLimits {
            max_auth_age: a.max_auth_age.map_or(ADMIN_MAX_AUTH_AGE_DEFAULT, |d| d.0),
            require_aal: a.require_aal.and_then(aal_requirement).unwrap_or(Aal::One),
            untrusted_peers: a.untrusted_peers.unwrap_or_default(),
            query_budget: Duration::from_millis(a.query_budget_ms.unwrap_or(2000)),
            directory_privacy: a.directory_privacy.unwrap_or_default(),
        })
    }

    /// The seeded grants of `admin.users[]`.
    pub fn admin_user_entries(&self) -> &[AdminUserEntry] {
        &self.admin.users
    }

    /// The implicit application `admin` (ADR-0016): the console host with its
    /// own lifetimes, binding and freshness bound. `None` without a console.
    pub fn admin_policy(&self) -> Option<AppPolicy> {
        let (host, port) = self.admin_host()?;
        let limits = self.admin_limits()?;
        let session = self.admin.session.clone().unwrap_or_default();
        let base = AppPolicy::default_app();
        let binding_cfg = self.admin.binding.clone().unwrap_or_default();
        let secure = self.cookie.secure;
        let _ = secure;
        Some(AppPolicy {
            app_id: AppId::new("admin"),
            display_name: "admin".into(),
            hosts: vec![host],
            ports: vec![port],
            enabled: true,
            session: Lifetimes {
                idle: session.idle.map_or(Duration::from_secs(30 * 60), |d| d.0),
                absolute: session
                    .absolute
                    .map_or(Duration::from_secs(12 * 3600), |d| d.0),
            },
            binding: resolve_binding(&binding_cfg, &base.binding),
            on_authz_change: AuthzChange::Terminate,
            verify_cache_seconds: 0,
            logout_confirm: true,
            step_up: if limits.require_aal >= Aal::Two {
                vec![StepUpRule {
                    path_prefix: Some("/".into()),
                    aal: limits.require_aal,
                    max_age: None,
                    factor: None,
                    enrollment_grace: false,
                }]
            } else {
                Vec::new()
            },
            max_auth_age: Some(limits.max_auth_age),
            // The console never presents AAL 3 (ADR-0018).
            max_emitted_aal: Aal::Two,
            risk: None,
        })
    }

    /// Effective database path.
    pub fn store_path(&self) -> PathBuf {
        self.store
            .path
            .clone()
            .unwrap_or_else(|| self.state_dir.join("hopae.db"))
    }

    /// Event sinks that get a delivery row per required event: the structured log.
    pub fn event_sinks(&self) -> Vec<String> {
        vec!["log".to_string()]
    }

    /// The handle, binding and portal cookie names derived from `cookie.name`.
    pub fn cookie_names(&self) -> CookieNames {
        let handle = self.cookie.name.clone().unwrap_or_else(|| {
            if self.cookie.secure {
                "__Host-hopae"
            } else {
                "hopae"
            }
            .to_string()
        });
        CookieNames {
            bind: format!("{handle}_bind"),
            portal: format!("{handle}_portal"),
            handle,
        }
    }

    /// Trusted proxy networks. Only valid after `validate`.
    pub fn trusted_proxy_nets(&self) -> Vec<ipnet::IpNet> {
        self.trusted_proxies
            .iter()
            .filter_map(|s| parse_proxy(s))
            .collect()
    }

    /// Session-wide timers with defaults (24 h idle, 30 d absolute).
    pub fn session_policy(&self) -> SessionPolicy {
        let d = SessionPolicy::default();
        SessionPolicy {
            idle: self.session.idle.map_or(d.idle, |v| v.0),
            absolute: self.session.absolute.map_or(d.absolute, |v| v.0),
        }
    }

    /// The numbers the verify engine needs.
    pub fn verify_limits(&self) -> VerifyLimits {
        VerifyLimits {
            stepup_enabled: self.totp_keyring.is_some()
                || !self.external_verifiers.is_empty()
                || self.webauthn.is_some(),
            max_recoveries: self.handoff.max_recoveries,
            txn_per_ip_per_minute: self.txn.per_ip_per_minute,
            txn_max_rows: self.txn.max_rows,
            handoff_failures_per_minute: self.handoff.per_ip_failures_per_minute,
            txn_lifetime: Duration::from_secs(600),
            budget: Duration::from_millis(self.gateway.verify_budget_ms),
            session: self.session_policy(),
            touch_coalesce: Duration::from_secs(30),
            secure: self.cookie.secure,
        }
    }

    /// Providers as the snapshot and the import carry them, in file order.
    pub fn provider_configs(&self) -> Vec<ProviderConfig> {
        self.providers
            .iter()
            .enumerate()
            .map(|(i, p)| ProviderConfig {
                provider_id: ProviderId::new(p.provider_id.clone()),
                kind: p.kind,
                display_name: p
                    .display_name
                    .clone()
                    .unwrap_or_else(|| p.provider_id.clone()),
                enabled: p.enabled,
                client_id: p.client_id.clone(),
                ldap: p.ldap.clone(),
                groups: p.groups.clone(),
                client_secret_env: p.client_secret_env.clone(),
                issuer: p.issuer.clone(),
                scope: p.scope.clone(),
                endpoint_hosts: lowered(&p.endpoint_hosts),
                allow_private_endpoints: p.allow_private_endpoints,
                tls: p.tls.clone(),
                client_assertion: p.client_assertion.clone(),
                allowed_email_domains: lowered(&p.allowed_email_domains),
                authoritative_domains: lowered(&p.authoritative_domains),
                auto_link: p.auto_link,
                trust_email: p.trust_email,
                sort_order: i32::try_from(i).unwrap_or(i32::MAX),
                // The preset's capability, else `max_age`; a stored setting
                // overrides both where the provider is built from its row.
                reauth: if p.kind == ProviderKind::Ldap {
                    ReauthCapability::Unsupported
                } else {
                    presets::by_name(&p.provider_id)
                        .or_else(|| p.issuer.as_deref().and_then(presets::by_issuer))
                        .map_or(ReauthCapability::MaxAge, |preset| preset.reauth)
                },
                reauth_prompt: if p.kind == ProviderKind::Ldap {
                    ReauthPrompt::None
                } else {
                    ReauthPrompt::Login
                },
            })
            .collect()
    }

    /// The immutable policy snapshot. Applications inherit unset policy from
    /// the reserved `default` application, which inherits from the built-in
    /// defaults (ADR-0007). Only valid after `validate`.
    pub fn snapshot(&self, generation: u64) -> ConfigSnapshot {
        let default_entry = self.apps.iter().find(|a| a.app_id == "default");
        let default_app = resolve_app(default_entry, &AppPolicy::default_app(), self, "default");
        let mut apps: Vec<AppPolicy> = self
            .apps
            .iter()
            .filter(|a| a.app_id != "default")
            .map(|a| resolve_app(Some(a), &default_app, self, &a.app_id))
            .collect();
        // The implicit console application sits beside the configured ones.
        apps.extend(self.admin_policy());
        ConfigSnapshot {
            generation,
            apps,
            default_app,
            providers: self.provider_configs(),
            retained_reauth: Default::default(),
        }
    }

    /// Non-fatal findings shown by `--check` and at start.
    pub fn warnings(&self) -> Vec<String> {
        let mut w = Vec::new();
        if self.gateway.allow_unauthenticated_caller {
            w.push("gateway.allow_unauthenticated_caller is true: development only".to_string());
            w.push("WARNING: verify caller authentication disabled (development only)".to_string());
        }
        if !self.cookie.secure {
            w.push("WARNING: insecure cookie mode (development only)".to_string());
        }
        if !self.gateway_addr().ip().is_loopback() {
            w.push(
                "listen.gateway is not a loopback address: it must not be publicly reachable"
                    .to_string(),
            );
            if self.gateway.caller_key_env.is_some() {
                w.push("a non-loopback listen.gateway relies on the caller key alone".to_string());
            }
        }
        if let Some(a) = self.admin_addr()
            && !a.ip().is_loopback()
        {
            w.push(
                "listen.admin is not a loopback address: it must not be publicly reachable"
                    .to_string(),
            );
        }
        if self.listen.admin.is_some() && !self.admin_enabled() {
            w.push(
                "listen.admin is set but admin.public_url is not: the admin listener is not bound"
                    .to_string(),
            );
        }
        if self.admin_enabled()
            && self.admin.require_aal == Some(2)
            && self.totp_keyring.is_none()
            && self.external_verifiers.is_empty()
            && self.webauthn.is_none()
        {
            w.push(
                "admin.require_aal: no second factor exists yet; every console request will be refused"
                    .to_string(),
            );
        }
        for (i, a) in self.apps.iter().enumerate() {
            if a.logout_confirm == Some(false) {
                w.push(format!(
                    "apps[{i}].logout_confirm is false: /_hopae/logout ends the session on any same-origin navigation without confirmation, so a navigation gadget in the application (a script that assigns a URL taken from its own query to location) can log users out; keep the default unless that is accepted (ADR-0015)"
                ));
            }
            for (j, h) in a.hosts.iter().enumerate() {
                if h.as_str() != h.to_ascii_lowercase() {
                    w.push(format!(
                        "apps[{i}].hosts[{j}]: {h:?} normalized to lower case"
                    ));
                }
            }
        }
        w
    }

    /// Whether the insecure development modes are on (reported by the health body).
    pub fn insecure_mode(&self) -> bool {
        !self.cookie.secure
    }
}

fn lowered(v: &[String]) -> Vec<String> {
    v.iter().map(|s| s.to_ascii_lowercase()).collect()
}

fn resolve_app(entry: Option<&AppEntry>, base: &AppPolicy, cfg: &Config, id: &str) -> AppPolicy {
    let default_ports = if cfg.cookie.secure {
        vec![443]
    } else {
        vec![80]
    };
    let Some(a) = entry else {
        return AppPolicy {
            app_id: AppId::new(id),
            ..base.clone()
        };
    };
    let binding_cfg = a.binding.clone().unwrap_or_default();
    let session = a.session.clone().unwrap_or_default();
    AppPolicy {
        app_id: AppId::new(id),
        display_name: a.display_name.clone().unwrap_or_else(|| id.to_string()),
        hosts: a.hosts.iter().filter_map(|h| Host::parse(h).ok()).collect(),
        ports: a.ports.clone().unwrap_or(default_ports),
        enabled: a.enabled,
        session: Lifetimes {
            idle: session.idle.map_or(base.session.idle, |d| d.0),
            absolute: session.absolute.map_or(base.session.absolute, |d| d.0),
        },
        binding: resolve_binding(&binding_cfg, &base.binding),
        on_authz_change: match a.on_authz_change {
            None => base.on_authz_change,
            Some(AuthzChangeCfg::Refresh) => AuthzChange::Refresh,
            Some(AuthzChangeCfg::Terminate) => AuthzChange::Terminate,
        },
        verify_cache_seconds: a.verify_cache_seconds.unwrap_or(base.verify_cache_seconds),
        logout_confirm: a.logout_confirm.unwrap_or(base.logout_confirm),
        step_up: a
            .step_up
            .iter()
            .filter_map(|r| {
                Some(StepUpRule {
                    path_prefix: r.path_prefix.clone(),
                    aal: aal_requirement(r.require.aal)?,
                    max_age: r.require.max_age.map(Duration::from_secs),
                    factor: None,
                    enrollment_grace: false,
                })
            })
            .chain(
                cfg.console_operators
                    .iter()
                    .filter(|c| c.app_id == id)
                    .flat_map(ConsoleOperatorsCfg::rules),
            )
            .collect(),
        max_auth_age: None,
        // Never inherited from `default`: AAL 3 is opted in per application (review F11).
        max_emitted_aal: match a.max_emitted_aal {
            Some(3) => Aal::Three,
            _ => Aal::Two,
        },
        risk: match &a.risk {
            Some(r) => Some(r.compile(id, true, &mut Vec::new())),
            None => base.risk.clone(),
        },
    }
}

/// A binding section over its base policy (apps and the console share it).
fn resolve_binding(cfg: &BindingCfg, base: &BindingPolicy) -> BindingPolicy {
    let ip = match cfg.ip {
        None => base.ip,
        Some(IpMode::Strict) => IpBinding::Strict,
        Some(IpMode::Off) => IpBinding::Off,
        Some(IpMode::Prefix) => {
            let (b4, b6) = match base.ip {
                IpBinding::Prefix { v4, v6 } => (v4, v6),
                _ => (24, 64),
            };
            IpBinding::Prefix {
                v4: cfg.ip_prefix_v4.unwrap_or(b4),
                v6: cfg.ip_prefix_v6.unwrap_or(b6),
            }
        }
    };
    BindingPolicy {
        ip,
        ua: match cfg.ua {
            None => base.ua,
            Some(UaMode::Strict) => UaBinding::Strict,
            Some(UaMode::Off) => UaBinding::Off,
        },
        on_mismatch: match cfg.on_mismatch {
            None => base.on_mismatch,
            Some(OnMismatchCfg::TerminateSession) => OnMismatch::TerminateSession,
            Some(OnMismatchCfg::DropHandle) => OnMismatch::DropHandle,
        },
    }
}

/// `admin.public_url`: a tuple origin (no path, query, fragment or userinfo),
/// `https://`, or `http://` only with `cookie.secure = false`. Returns the host.
fn check_admin_origin(u: &str, secure: bool) -> Result<Host, String> {
    let url = url::Url::parse(u).map_err(|_| "must be an absolute URL".to_string())?;
    match (url.scheme(), secure) {
        ("https", _) => {}
        ("http", false) => {}
        ("http", true) => {
            return Err("must use https:// (http:// only with cookie.secure set to false)".into());
        }
        _ => return Err("must start with https://".into()),
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("must not contain credentials".into());
    }
    if url.query().is_some() || url.fragment().is_some() || !matches!(url.path(), "" | "/") {
        return Err("must be an origin without path, query or fragment".into());
    }
    let host = match url.host() {
        Some(url::Host::Domain(d)) => d.to_string(),
        _ => return Err("must name a host (not an IP address)".into()),
    };
    Host::parse(&host).map_err(|_| "must name a lower-case host".to_string())
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

/// An issuer is an absolute `https://` URL without query or fragment;
/// `http://` is accepted only for a loopback host (a local test provider).
fn check_issuer(u: &str) -> Result<(), &'static str> {
    let url = url::Url::parse(u).map_err(|_| "must be an absolute URL")?;
    if url.query().is_some() || url.fragment().is_some() {
        return Err("must not contain a query or fragment");
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("must not contain credentials");
    }
    match (url.scheme(), url.host()) {
        ("https", Some(_)) => Ok(()),
        ("http", Some(url::Host::Ipv4(ip))) if ip.is_loopback() => Ok(()),
        ("http", Some(url::Host::Ipv6(ip))) if ip.is_loopback() => Ok(()),
        ("http", Some(url::Host::Domain("localhost"))) => Ok(()),
        _ => Err("must use https:// (http:// only for a loopback host)"),
    }
}

/// Verify that every environment variable the configuration references
/// exists and is non-empty, for the caller keys. Returns messages naming only
/// the variable, never a value. A missing provider secret is a warning, not an
/// error: see [`env_warnings`].
pub fn check_env(cfg: &Config, lookup: impl Fn(&str) -> Option<String>) -> Vec<String> {
    let mut out = Vec::new();
    // Provider TLS files: readable, parseable, the key matching the certificate;
    // client assertion keys: readable, a supported key for the algorithms.
    for p in cfg.providers.iter().filter(|p| p.enabled) {
        if let Some(a) = &p.client_assertion
            && let Ok(Some(c)) = crate::provider::oidc::assertion::AssertionCfg::of_config(
                &serde_json::json!({ "client_assertion": a }),
            )
            && let Err(e) = crate::provider::oidc::assertion::load(&c)
        {
            out.push(format!("provider {} client_assertion: {e}", p.provider_id));
        }
        if let Some(tls) = &p.tls
            && let Ok(Some(files)) = crate::provider::oidc::trust::TrustFiles::of_config(
                &serde_json::json!({ "tls": tls }),
            )
            && let Err(e) = crate::provider::oidc::trust::load(&files)
        {
            out.push(format!("provider {} tls: {e}", p.provider_id));
        }
    }
    if let Some(r) = &cfg.risk {
        for (key, name) in [
            ("risk.context_key_env", Some(&r.context_key_env)),
            ("risk.context_key_next_env", r.context_key_next_env.as_ref()),
        ] {
            if let Some(name) = name
                && lookup(name).is_none_or(|v| !(32..=4096).contains(&v.len()))
            {
                out.push(format!(
                    "environment variable {name} ({key}) is not set or is not 32 to 4096 bytes"
                ));
            }
        }
    }
    if !cfg.gateway.allow_unauthenticated_caller {
        for (key, name) in [
            ("gateway.caller_key_env", &cfg.gateway.caller_key_env),
            (
                "gateway.caller_key_next_env",
                &cfg.gateway.caller_key_next_env,
            ),
        ] {
            if let Some(name) = name
                && lookup(name).is_none_or(|v| v.is_empty())
            {
                out.push(format!(
                    "environment variable {name} ({key}) is not set or is empty"
                ));
            }
        }
    }
    if crate::factor::external_registry::Registry::compile(&cfg.external_verifiers, &lookup, None)
        .is_err()
    {
        out.push("external_verifiers: unavailable or invalid verifier material".into());
    }
    if let Some(keys) = &cfg.totp_keyring
        && crate::factor::keyring::Keyring::compile(keys, &lookup).is_err()
    {
        out.push("totp_keyring: unavailable or invalid key material".into());
    }
    if let Some(webauthn) = &cfg.webauthn
        && let Err(error) =
            crate::factor::webauthn::RelyingParty::compile(webauthn, &cfg.portal.public_url)
    {
        out.push(error);
    }
    if let Some(config) = &cfg.authentication_gateway
        && let Err(error) = crate::auth_gateway::runtime::Runtime::compile(config, &lookup)
    {
        out.push(format!("authentication_gateway: {error}"));
    }
    if let Some(c) = &cfg.console_operators
        && let Err(error) = crate::verify::operator::signing_key(c, &lookup)
    {
        out.push(error);
    }
    out
}

/// Warnings about referenced variables that only disable a provider
/// (`provider mock disabled: HOPAE_TEST_MOCK_SECRET unset`).
pub fn env_warnings(cfg: &Config, lookup: impl Fn(&str) -> Option<String>) -> Vec<String> {
    cfg.providers
        .iter()
        .filter(|p| p.enabled)
        .filter_map(|p| {
            let name = if p.kind == ProviderKind::Ldap {
                &p.ldap.as_ref()?.bind_password_env
            } else {
                p.client_secret_env.as_ref()?
            };
            lookup(name)
                .is_none_or(|v| v.is_empty())
                .then(|| format!("provider {} disabled: {name} unset", p.provider_id))
        })
        .collect()
}

/// A configured requirement level: 1, 2, or 3 (AAL 3 is a requirement and a
/// presentation, never a stored level; ADR-0018).
fn aal_requirement(n: u8) -> Option<Aal> {
    match n {
        3 => Some(Aal::Three),
        n => Aal::from_i64(i64::from(n)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = r#"{
      "state_dir": "/tmp/x",
      "portal": {"public_url": "https://auth.example.test"},
      "gateway": {"kind": "hangang", "caller_key_env": "K"}
    }"#;

    /// ADR-0020 slice 1: `store.kind`/`store.backend = "postgres"` parses and
    /// validates; serving refuses it (see `app::refuse_incomplete_backend`).
    #[test]
    fn s600_6_postgres_store_configuration_is_validated() {
        let mut value: serde_json::Value = serde_json::from_str(BASE).unwrap();
        value["store"] =
            serde_json::json!({"backend": "postgres", "postgres": {"url_env": "HOPAE_PG_URL"}});
        let cfg: Config = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(cfg.store.kind, StoreKind::Postgres);
        let r = cfg.validate();
        if cfg!(feature = "postgres") {
            r.unwrap();
        } else {
            assert!(format!("{}", r.unwrap_err()).contains("postgres feature"));
        }
        for bad in [
            serde_json::json!({"kind": "postgres"}),
            serde_json::json!({"kind": "sqlite", "postgres": {"url_env": "X"}}),
            serde_json::json!({"kind": "postgres", "postgres": {"url_env": "postgres://inline"}}),
            serde_json::json!({"kind": "postgres", "postgres": {"url_env": "X", "pool_size": 0}}),
            serde_json::json!({"kind": "postgres", "postgres": {"url_env": "X", "ca_file": "relative.pem"}}),
        ] {
            value["store"] = bad.clone();
            let cfg: Config = serde_json::from_value(value.clone()).unwrap();
            assert!(cfg.validate().is_err(), "{bad}");
        }
        value["store"] = serde_json::json!({"kind": "postgres", "postgres": {"url_env": "X", "password": "inline"}});
        assert!(
            serde_json::from_value::<Config>(value).is_err(),
            "unknown keys refused"
        );
    }

    #[test]
    fn root_kubernetes_profile_loads_references_and_refuses_inline_secret() {
        let mut value: serde_json::Value = serde_json::from_str(BASE).unwrap();
        value["apps"] =
            serde_json::json!([{"app_id":"orders","hosts":["app.example.test"],"ports":[443]}]);
        value["authentication_gateway"] = serde_json::json!({"authority_id":"owned","profiles":[{"service_id":"orders","host":"app.example.test","ports":[443],"realm":"example-cluster","kubernetes_tokenreview":{"connection":{"api_origin":"https://kubernetes.example.test/","issuer":"https://issuer.example.test","cluster_id":"example-cluster","audience":"orders-workload","namespaces":["blue"],"timeout_ms":500},"ca_pem_env":"OWNED_CA","reviewer_token_env":"OWNED_REVIEWER","token_prefix":"k8s:","subject":"service_account"}}]});
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), serde_json::to_vec(&value).unwrap()).unwrap();
        let loaded = load(file.path()).unwrap();
        assert_eq!(
            loaded.authentication_gateway.unwrap().profiles[0]
                .kubernetes_tokenreview
                .as_ref()
                .unwrap()
                .token_prefix,
            "k8s:"
        );
        value["authentication_gateway"]["profiles"][0]["kubernetes_tokenreview"]["reviewer_token"] =
            "do-not-display-fixture".into();
        std::fs::write(file.path(), serde_json::to_vec(&value).unwrap()).unwrap();
        let error = load(file.path()).unwrap_err().to_string();
        assert!(
            error.contains("environment variable name")
                && !error.contains("do-not-display-fixture")
        );
    }
    /// ADR 0022 migration: an existing TokenReview profile without an explicit
    /// `subject` fails at load (before deploy) with a pointer to the migration,
    /// instead of silently changing the published subject.
    #[test]
    fn s900_11_tokenreview_profile_without_subject_fails_loud_at_load() {
        let mut value: serde_json::Value = serde_json::from_str(BASE).unwrap();
        value["apps"] =
            serde_json::json!([{"app_id":"orders","hosts":["app.example.test"],"ports":[443]}]);
        value["authentication_gateway"] = serde_json::json!({"authority_id":"owned","profiles":[{"service_id":"orders","host":"app.example.test","ports":[443],"realm":"example-cluster","kubernetes_tokenreview":{"connection":{"api_origin":"https://kubernetes.example.test/","issuer":"https://issuer.example.test","cluster_id":"example-cluster","audience":"orders-workload","namespaces":["blue"],"timeout_ms":500},"ca_pem_env":"OWNED_CA","reviewer_token_env":"OWNED_REVIEWER","token_prefix":"k8s:"}}]});
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), serde_json::to_vec(&value).unwrap()).unwrap();
        let error = load(file.path()).unwrap_err().to_string();
        assert!(
            error.contains("kubernetes_tokenreview.subject is required")
                && error.contains("legacy_pod")
                && error.contains("KUBERNETES_WORKLOAD.md#migration-from-pod-bound-subjects"),
            "{error}"
        );
        let tr = &mut value["authentication_gateway"]["profiles"][0]["kubernetes_tokenreview"];
        tr["subject"] = "legacy_pod".into();
        std::fs::write(file.path(), serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(
            load(file.path())
                .unwrap_err()
                .to_string()
                .contains("legacy_until_ms")
        );
        let tr = &mut value["authentication_gateway"]["profiles"][0]["kubernetes_tokenreview"];
        tr["legacy_until_ms"] = 4_000_000_000_000u64.into();
        tr["legacy_mapping_until_ms"] = 4_000_000_000_000u64.into();
        std::fs::write(file.path(), serde_json::to_vec(&value).unwrap()).unwrap();
        load(file.path()).unwrap();
        let tr = &mut value["authentication_gateway"]["profiles"][0]["kubernetes_tokenreview"];
        tr["subject"] = "service_account".into();
        tr.as_object_mut().unwrap().remove("legacy_until_ms");
        std::fs::write(file.path(), serde_json::to_vec(&value).unwrap()).unwrap();
        load(file.path()).unwrap();
        // New offline profiles default to the ServiceAccount principal.
        value["authentication_gateway"]["profiles"][0]
            .as_object_mut()
            .unwrap()
            .remove("kubernetes_tokenreview");
        value["authentication_gateway"]["profiles"][0]["kubernetes_workload"] = serde_json::json!({"issuer":"https://kubernetes.default.svc.cluster.local","cluster_id":"example-cluster","trust_domain":"cluster.example.test","audience":"world.hangang.dev/example-cluster","namespaces":["blue"],"keys":{"source":"static","jwks_env":"OWNED_JWKS"},"token_prefix":"k8s:"});
        std::fs::write(file.path(), serde_json::to_vec(&value).unwrap()).unwrap();
        let loaded = load(file.path()).unwrap();
        assert_eq!(
            loaded.authentication_gateway.unwrap().profiles[0]
                .kubernetes_workload
                .as_ref()
                .unwrap()
                .subject,
            crate::auth_gateway::workload::SubjectMode::ServiceAccount
        );
    }
    #[test]
    fn external_verifier_configuration_validates_references_and_redacts_material_errors() {
        let verifier = serde_json::json!({"factor":"push","configuration_revision":1,"url":"https://verifier.example.test/check","verifier_key_env":"OWNED_FACTOR_KEY","timeout_ms":100});
        let config =
            with(&serde_json::json!({"external_verifiers":[verifier.clone()]}).to_string())
                .unwrap();
        assert_eq!(config.external_verifiers.len(), 1);
        let mut scripted = verifier.clone();
        scripted["eligibility_lua"] = serde_json::json!("return context.service == 'orders'");
        assert!(
            with(&serde_json::json!({"external_verifiers":[scripted.clone()]}).to_string()).is_ok()
        );
        scripted["eligibility_lua"] = serde_json::json!("return (");
        assert!(with(&serde_json::json!({"external_verifiers":[scripted]}).to_string()).is_err());
        assert!(
            !serde_json::to_string(&config.external_verifiers[0])
                .unwrap()
                .contains("eligibility_lua")
        );
        let raw = "not-a-valid-verifier-secret";
        let errors = check_env(&config, |_| Some(raw.into()));
        assert!(errors.iter().any(|e| e.contains("external_verifiers")));
        assert!(!errors.join(" ").contains(raw));
        assert!(
            with(
                &serde_json::json!({"external_verifiers":[verifier.clone(),verifier.clone()]})
                    .to_string()
            )
            .is_err()
        );
        assert!(with(&serde_json::json!({"external_verifiers":[verifier],"gateway":{"kind":"hangang","allow_unauthenticated_caller":true}}).to_string()).is_err());
    }

    #[test]
    fn human_material_reference_is_bounded_and_not_a_literal_key() {
        assert!(with(r#"{"human_material_key_env":"OWNED_HUMAN_MATERIAL_KEY"}"#).is_ok());
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        let mut raw: serde_json::Value = serde_json::from_str(BASE).unwrap();
        raw["human_material_key_env"] = serde_json::json!("OWNED_HUMAN_MATERIAL_KEY");
        std::fs::write(&path, raw.to_string()).unwrap();
        assert_eq!(
            load(&path).unwrap().human_material_key_env.as_deref(),
            Some("OWNED_HUMAN_MATERIAL_KEY")
        );
        for name in ["", "literal-key-with-hyphen", &"A".repeat(129)] {
            let raw = serde_json::json!({"human_material_key_env":name}).to_string();
            let error = with(&raw).unwrap_err().to_string();
            assert!(!error.contains("literal-key-with-hyphen"));
        }
    }

    #[test]
    fn max_emitted_aal_is_per_application_and_never_inherited() {
        let cfg = with(r#"{"webauthn":{"high_assurance":{"attestation_ca_files":["/x.pem"],"aaguids":["cb69481e-8ff7-4039-93ec-0a2729a154a8"]}},"apps":[{"app_id":"default","max_emitted_aal":3},{"app_id":"a","hosts":["a.example.test"]},{"app_id":"b","hosts":["b.example.test"],"max_emitted_aal":3}]}"#).unwrap();
        let snap = cfg.snapshot(1);
        let get = |id: &str| {
            snap.apps
                .iter()
                .find(|a| a.app_id.as_str() == id)
                .unwrap()
                .max_emitted_aal
        };
        assert_eq!(get("a"), Aal::Two);
        assert_eq!(get("b"), Aal::Three);
    }

    #[test]
    fn webauthn_is_off_by_default_and_validated_when_present() {
        let base = with("{}").unwrap();
        assert!(base.webauthn.is_none());
        assert!(!base.verify_limits().stepup_enabled);
        let on = with(r#"{"webauthn":{}}"#).unwrap();
        assert!(on.webauthn.is_some());
        assert!(on.verify_limits().stepup_enabled);
        assert!(with(r#"{"webauthn":{"rp_id":"example.test","rp_name":"Example"}}"#).is_ok());
        assert!(invalid(r#"{"webauthn":{"rp_id":"other.test"}}"#).contains("webauthn.rp_id"));
        assert!(invalid(r#"{"webauthn":{"origin":"https://x.example.test"}}"#).contains("origin"));
        assert!(invalid(r#"{"webauthn":{"rp_name":""}}"#).contains("rp_name"));
        assert!(
            invalid(
                r#"{"webauthn":{"high_assurance":{"attestation_ca_files":[],"aaguids":["nope"]}}}"#
            )
            .contains("high_assurance")
        );
        let missing = with(r#"{"webauthn":{"high_assurance":{"attestation_ca_files":["/nonexistent/ca.pem"],"aaguids":["cb69481e-8ff7-4039-93ec-0a2729a154a8"]}}}"#).unwrap();
        assert!(
            check_env(&missing, |_| Some("x".into()))
                .iter()
                .any(|p| p.contains("cannot read"))
        );
    }

    #[test]
    fn totp_key_references_validate_and_material_errors_are_redacted() {
        let config=with(r#"{"totp_keyring":{"active_key":"owned","keys":[{"id":"owned","key_env":"OWNED_FACTOR_KEY"}]}}"#).unwrap();
        assert!(config.totp_keyring.is_some());
        let secret = "raw-secret-not-an-encryption-key";
        let problems = check_env(&config, |name| {
            Some(if name == "K" {
                "caller-value".into()
            } else {
                secret.into()
            })
        });
        assert!(problems.iter().any(|p| p.contains("totp_keyring")));
        assert!(!problems.join(" ").contains(secret));
        assert!(with(r#"{"totp_keyring":{"active_key":"missing","keys":[]}}"#).is_err());
        assert!(with(r#"{"totp_keyring":{"active_key":"owned","keys":[{"id":"owned","key_env":"OWNED_FACTOR_KEY","secret":"forbidden"}]}}"#).is_err());
    }

    fn with(extra: &str) -> Result<Config, ConfigError> {
        let mut v: serde_json::Value = serde_json::from_str(BASE).unwrap();
        let add: serde_json::Value = serde_json::from_str(extra).unwrap();
        for (k, val) in add.as_object().unwrap() {
            v[k] = val.clone();
        }
        parse(&v.to_string())
    }

    fn invalid(extra: &str) -> String {
        match with(extra) {
            Err(ConfigError::Invalid(e)) => e.join("; "),
            Err(e) => e.to_string(),
            Ok(_) => panic!("expected an error for {extra}"),
        }
    }

    #[test]
    fn reload_intervals_default_turn_off_and_are_bounded() {
        let c = with("{}").unwrap();
        assert_eq!(c.tls_reload_interval(), Some(Duration::from_secs(10)));
        assert_eq!(c.auth_reload_interval(), None, "store mode never polls");
        let c = with(r#"{"authentication": {"source": "config"}}"#).unwrap();
        assert_eq!(c.auth_reload_interval(), Some(Duration::from_millis(1000)));
        let c = with(r#"{"authentication": {"source": "config", "reload_interval_ms": 0}, "reload": {"tls_interval_secs": 0}}"#).unwrap();
        assert_eq!(
            (c.auth_reload_interval(), c.tls_reload_interval()),
            (None, None)
        );
        assert!(
            invalid(r#"{"reload": {"tls_interval_secs": 3601}}"#)
                .contains("reload.tls_interval_secs")
        );
        assert!(
            invalid(r#"{"authentication": {"reload_interval_ms": 50}}"#)
                .contains("reload_interval_ms")
        );
        assert!(invalid(r#"{"reload": {"inotify": true}}"#).contains("inotify"));
    }

    #[test]
    fn directory_configuration_is_reference_only_and_import_preserves_typed_settings() {
        let entry:ProviderEntry=serde_json::from_value(serde_json::json!({"provider_id":"owned-directory","kind":"ldap","ldap":{
            "endpoint":"ldaps://directory.example.test/","ca":"/owned/ca.pem","base_dn":"dc=example,dc=test","bind_dn":"cn=reader,dc=example,dc=test","bind_password_env":"OWNED_LDAP_KEY","username_attribute":"uid","subject_attribute":"entryUUID","timeout_ms":1000}})).unwrap();
        assert!(entry.client_id.is_empty());
        let mut config = with("{}").unwrap();
        config.providers = vec![entry.clone()];
        let snapshots = config.provider_configs();
        assert_eq!(snapshots[0].reauth, ReauthCapability::Unsupported);
        let row = crate::store::types::ProviderRow::from_config(&snapshots[0]);
        assert_eq!(row.config["ldap"]["bind_password_env"], "OWNED_LDAP_KEY");
        assert_eq!(row.kind, ProviderKind::Ldap);
        assert!(
            env_warnings(&config, |_| None)
                .iter()
                .any(|warning| warning.contains("OWNED_LDAP_KEY"))
        );
        assert!(
            config.validate().is_ok(),
            "typed LDAP configuration is accepted after owned runtime qualification"
        );
        config.providers[0].kind = ProviderKind::Oidc;
        config.providers[0].client_id = "owned".into();
        assert!(
            config.validate().is_err(),
            "OIDC cannot accept LDAP settings"
        );
    }
    #[test]
    fn m0_config_still_parses_with_defaults() {
        let c = parse(BASE).unwrap();
        assert_eq!(c.cookie_names().handle, "__Host-hopae");
        assert_eq!(c.cookie_names().bind, "__Host-hopae_bind");
        assert_eq!(c.cookie_names().portal, "__Host-hopae_portal");
        assert_eq!(c.gateway.verify_budget_ms, 400);
        assert_eq!(c.session_policy(), SessionPolicy::default());
        assert_eq!(c.events.max_rows, 1_000_000);
        assert_eq!(c.trusted_proxies, ["127.0.0.1/32"]);
        let snap = c.snapshot(1);
        assert!(snap.apps.is_empty());
        assert_eq!(snap.default_app.session, Lifetimes::default());
    }

    #[test]
    fn app_policy_inherits_from_default_and_applies_overrides() {
        let c = with(
            r#"{"apps": [
              {"app_id": "default", "session": {"idle": "2h", "absolute": "30d"}},
              {"app_id": "app", "hosts": ["App.Example.Test"], "binding": {"ip": "prefix", "on_mismatch": "drop_handle"}, "verify_cache_seconds": 5,
               "step_up": [{"path_prefix": "/admin", "require": {"aal": 2, "max_age": 900}}]},
              {"app_id": "short", "hosts": ["short.example.test"], "session": {"idle": "1h", "absolute": "1d"}, "ports": [443, 8443]}
            ]}"#,
        )
        .unwrap();
        let snap = c.snapshot(7);
        assert_eq!(snap.generation, 7);
        assert_eq!(snap.default_app.session.idle, Duration::from_secs(7200));
        let app = snap
            .app_for_host(&Host::parse("app.example.test").unwrap())
            .unwrap();
        assert_eq!(app.session.idle, Duration::from_secs(7200));
        assert_eq!(app.binding.ip, IpBinding::Prefix { v4: 24, v6: 64 });
        assert_eq!(app.binding.on_mismatch, OnMismatch::DropHandle);
        assert_eq!(app.verify_cache_seconds, 5);
        assert_eq!(app.ports, vec![443]);
        assert_eq!(app.step_up.len(), 1);
        assert_eq!(app.step_up[0].aal, Aal::Two);
        assert_eq!(app.step_up[0].max_age, Some(Duration::from_secs(900)));
        let short = snap
            .app_for_host(&Host::parse("short.example.test").unwrap())
            .unwrap();
        assert_eq!(short.session.idle, Duration::from_secs(3600));
        assert_eq!(short.session.absolute, Duration::from_secs(86400));
        assert!(snap.return_origin_allowed(&Host::parse("short.example.test").unwrap(), 8443));
        assert!(c.warnings().iter().any(|w| w.contains("apps[1].hosts[0]")));
    }

    #[test]
    fn logout_confirm_defaults_to_true_and_inherits_from_default() {
        let host = |s: &str| Host::parse(s).unwrap();
        let c = with(
            r#"{"apps": [
              {"app_id": "app", "hosts": ["a.example.test"]},
              {"app_id": "direct", "hosts": ["d.example.test"], "logout_confirm": false}
            ]}"#,
        )
        .unwrap();
        let snap = c.snapshot(1);
        assert!(snap.default_app.logout_confirm);
        assert!(
            snap.app_for_host(&host("a.example.test"))
                .unwrap()
                .logout_confirm
        );
        assert!(
            !snap
                .app_for_host(&host("d.example.test"))
                .unwrap()
                .logout_confirm
        );
        let c = with(
            r#"{"apps": [
              {"app_id": "default", "logout_confirm": false},
              {"app_id": "app", "hosts": ["a.example.test"]},
              {"app_id": "asks", "hosts": ["b.example.test"], "logout_confirm": true}
            ]}"#,
        )
        .unwrap();
        let snap = c.snapshot(1);
        assert!(!snap.default_app.logout_confirm);
        assert!(
            !snap
                .app_for_host(&host("a.example.test"))
                .unwrap()
                .logout_confirm
        );
        assert!(
            snap.app_for_host(&host("b.example.test"))
                .unwrap()
                .logout_confirm
        );
    }

    #[test]
    fn idle_policies_below_a_minute_are_rejected() {
        // Activity is persisted in whole seconds; a shorter idle timer could
        // expire between two writes of continuous activity (G7 C03).
        for extra in [
            r#"{"session": {"idle": "59s"}}"#,
            r#"{"apps": [{"app_id": "a", "hosts": ["a.example.test"], "session": {"idle": "30s"}}]}"#,
            r#"{"apps": [{"app_id": "default", "session": {"idle": "1s"}}]}"#,
        ] {
            let e = invalid(extra);
            assert!(e.contains("idle must be at least 60s"), "{extra}: {e}");
        }
        assert!(with(r#"{"session": {"idle": "60s"}}"#).is_ok());
        assert!(
            with(r#"{"apps": [{"app_id": "a", "hosts": ["a.example.test"], "session": {"idle": "1m"}}]}"#)
                .is_ok()
        );
    }

    #[test]
    fn invalid_values_are_rejected_with_key_paths() {
        assert!(
            invalid(r#"{"apps": [{"app_id": "a", "hosts": ["*.example.test"]}]}"#)
                .contains("apps[0].hosts[0]")
        );
        assert!(
            invalid(r#"{"apps": [{"app_id": "a", "hosts": ["https://a.example.test/x"]}]}"#)
                .contains("exact lower-case host names")
        );
        assert!(
            invalid(r#"{"apps": [{"app_id": "a", "hosts": ["a.example.test:8443"]}]}"#)
                .contains("apps[0].hosts[0]")
        );
        assert!(invalid(r#"{"apps": [{"app_id": "a", "hosts": ["x.example.test"]}, {"app_id": "b", "hosts": ["X.example.test"]}]}"#).contains("already claimed"));
        assert!(invalid(r#"{"apps": [{"app_id": "a", "hosts": ["x.example.test"], "verify_cache_seconds": 60}]}"#).contains("verify_cache_seconds"));
        assert!(
            invalid(r#"{"apps": [{"app_id": "default", "hosts": ["x.example.test"]}]}"#)
                .contains("must not list hosts")
        );
        assert!(invalid(r#"{"cookie": {"name": "hopae"}}"#).contains("__Host-"));
        assert!(
            invalid(r#"{"cookie": {"secure": false, "name": "__Host-hopae"}}"#)
                .contains("must not start with __Host-")
        );
        assert!(invalid(r#"{"cookie": {"same_site": "none"}}"#).contains("cookie.same_site"));
        assert!(invalid(r#"{"session": {"idle": "soon"}}"#).contains("duration"));
        assert!(invalid(r#"{"trusted_proxies": ["not-an-ip"]}"#).contains("trusted_proxies[0]"));
        assert!(invalid(r#"{"events": {"max_rows": 0}}"#).contains("events.max_rows"));
        assert!(invalid(r#"{"providers": [{"provider_id": "g", "kind": "oidc", "client_id": "c", "client_secret": "literal"}]}"#).contains("environment variable name"));
        assert!(!invalid(r#"{"providers": [{"provider_id": "g", "kind": "oidc", "client_id": "c", "client_secret": "literal"}]}"#).contains("literal\""));
        assert!(invalid(r#"{"providers": [{"provider_id": "g", "kind": "oidc", "client_id": "c", "issuer": "http://example.org"}]}"#).contains("providers[0].issuer"));
        // A periodic group sync must refresh before memberships go stale.
        assert!(invalid(r#"{"groups": {"max_staleness_secs": 3600}, "providers": [{"provider_id": "d", "kind": "ldap", "groups": {"sync_interval_secs": 3600}}]}"#).contains("must be shorter than groups.max_staleness_secs"));
        assert!(
            invalid(
                r#"{"providers": [{"provider_id": "g", "kind": "password", "client_id": "c"}]}"#
            )
            .contains("not supported before M3")
        );
        assert!(invalid(r#"{"gateway": {"kind": "hangang"}}"#).contains("caller_key_env"));
        assert!(invalid(r#"{"gateway": {"kind": "hangang", "caller_key_env": "K", "caller_key_next_env": "K"}}"#).contains("must differ"));
    }

    #[test]
    fn insecure_modes_warn_loudly_and_allow_dev_cookie_name() {
        let c = with(r#"{"cookie": {"name": "hopae", "secure": false}}"#).unwrap();
        assert!(
            c.warnings()
                .iter()
                .any(|w| w.contains("insecure cookie mode"))
        );
        assert!(c.insecure_mode());
        assert_eq!(c.cookie_names().bind, "hopae_bind");
        let c = with(r#"{"cookie": {"secure": false}}"#).unwrap();
        assert_eq!(c.cookie_names().handle, "hopae");
        assert_eq!(c.snapshot(1).default_app.ports, Vec::<u16>::new());
    }

    #[test]
    fn env_checks_name_variables_only() {
        let c = with(
            r#"{"gateway": {"kind": "hangang", "caller_key_env": "A", "caller_key_next_env": "B"},
                "providers": [{"provider_id": "mock", "kind": "oidc", "client_id": "c", "client_secret_env": "S", "issuer": "http://127.0.0.1:9", "allow_private_endpoints": true}]}"#,
        )
        .unwrap();
        let env = |n: &str| (n == "A").then(|| "value-a".to_string());
        let problems = check_env(&c, env);
        assert_eq!(problems.len(), 1);
        assert!(problems[0].contains("B") && !problems[0].contains("value-a"));
        let w = env_warnings(&c, env);
        assert_eq!(w, ["provider mock disabled: S unset"]);
    }

    #[test]
    fn provider_tls_files_are_validated_and_checked() {
        let p = |tls: &str| {
            format!(
                r#"{{"providers": [{{"provider_id": "corp", "kind": "oidc", "client_id": "c", "issuer": "https://idp.corp.test", "tls": {tls}}}]}}"#
            )
        };
        assert!(invalid(&p(r#"{"ca_file": "ca.pem"}"#)).contains("absolute"));
        assert!(invalid(&p(r#"{}"#)).contains("must name ca_file"));
        assert!(invalid(&p(r#"{"client_certificate_file": "/c.pem"}"#)).contains("go together"));
        assert!(invalid(&p(r#"{"ca": "/c.pem"}"#)).contains("unknown"));
        // `--check` reads the files: a missing one is a problem.
        let c = with(&p(r#"{"ca_file": "/nonexistent/hopae-ca.pem"}"#)).unwrap();
        let problems = check_env(&c, |_| None);
        assert!(
            problems.iter().any(|e| e.starts_with("provider corp tls:")),
            "{problems:?}"
        );
        let dir = tempfile::tempdir().unwrap();
        crate::reload::tests::pki(dir.path(), "ca1");
        let ca = dir.path().join("ca1.pem");
        let c = with(&p(&format!(r#"{{"ca_file": {:?}}}"#, ca.to_str().unwrap()))).unwrap();
        assert!(check_env(&c, |_| None).iter().all(|e| !e.contains("tls")));
        std::fs::write(&ca, b"garbage").unwrap();
        assert!(
            check_env(&c, |_| None)
                .iter()
                .any(|e| e.contains("provider corp tls:"))
        );
    }

    #[test]
    fn provider_client_assertion_is_validated_and_checked() {
        let p = |a: &str, secret: bool| {
            format!(
                r#"{{"providers": [{{"provider_id": "corp", "kind": "oidc", "client_id": "c", "issuer": "https://idp.corp.test", {}"client_assertion": {a}}}]}}"#,
                if secret {
                    r#""client_secret_env": "S", "#
                } else {
                    ""
                }
            )
        };
        assert!(
            invalid(&p(r#"{"key_file": "/k.pem", "key_id": "k"}"#, true)).contains("exclusive")
        );
        assert!(invalid(&p(r#"{"key_file": "k.pem", "key_id": "k"}"#, false)).contains("absolute"));
        assert!(
            invalid(&p(
                r#"{"key_file": "/k.pem", "key_id": "k", "algorithms": ["HS256"]}"#,
                false
            ))
            .contains("algorithms")
        );
        let c = with(&p(
            r#"{"key_file": "/nonexistent/hopae-key.pem", "key_id": "k"}"#,
            false,
        ))
        .unwrap();
        assert!(
            check_env(&c, |_| None)
                .iter()
                .any(|e| e.starts_with("provider corp client_assertion:"))
        );
    }

    // ---- the management console (ADR-0016) -------------------------------

    const ADMIN: &str = r#"{"admin": {"public_url": "https://hopae-admin.example.test"}}"#;

    fn admin_with(extra: &str) -> Result<Config, ConfigError> {
        let mut v: serde_json::Value = serde_json::from_str(ADMIN).unwrap();
        let add: serde_json::Value = serde_json::from_str(extra).unwrap();
        for (k, val) in add.as_object().unwrap() {
            if k == "admin" {
                for (k2, v2) in val.as_object().unwrap() {
                    v["admin"][k2] = v2.clone();
                }
            } else {
                v[k] = val.clone();
            }
        }
        with(&v.to_string())
    }

    fn admin_invalid(extra: &str) -> String {
        match admin_with(extra) {
            Err(ConfigError::Invalid(e)) => e.join("; "),
            Err(e) => e.to_string(),
            Ok(_) => panic!("expected an error for {extra}"),
        }
    }

    #[test]
    fn without_admin_public_url_there_is_no_console_and_nothing_changes() {
        let c = parse(BASE).unwrap();
        assert!(!c.admin_enabled());
        assert!(c.admin_addr().is_none() && c.admin_origin().is_none());
        assert!(c.admin_policy().is_none() && c.admin_limits().is_none());
        assert!(c.admin_user_entries().is_empty());
        assert_eq!(c.limits.admin_max_concurrent, 16);
        assert!(c.snapshot(1).apps.is_empty(), "no implicit application");
    }

    #[test]
    fn the_console_defaults_and_the_implicit_application() {
        let c = admin_with("{}").unwrap();
        assert!(c.admin_enabled());
        assert_eq!(c.admin_addr(), Some("127.0.0.1:8702".parse().unwrap()));
        assert_eq!(
            c.admin_origin(),
            Some(
                url::Url::parse("https://hopae-admin.example.test")
                    .unwrap()
                    .origin()
            )
        );
        let l = c.admin_limits().unwrap();
        assert_eq!(l.max_auth_age, Duration::from_secs(12 * 3600));
        assert_eq!(
            (l.require_aal, l.untrusted_peers),
            (Aal::One, UntrustedPeers::Refuse)
        );
        assert_eq!(l.query_budget, Duration::from_millis(2000));
        let p = c.admin_policy().unwrap();
        assert_eq!(p.app_id.as_str(), "admin");
        assert_eq!(
            p.hosts,
            vec![Host::parse("hopae-admin.example.test").unwrap()]
        );
        assert_eq!(p.ports, vec![443]);
        assert_eq!(p.session.idle, Duration::from_secs(30 * 60));
        assert_eq!(p.session.absolute, Duration::from_secs(12 * 3600));
        assert_eq!(p.binding, BindingPolicy::default());
        assert_eq!(p.on_authz_change, AuthzChange::Terminate);
        assert_eq!(p.verify_cache_seconds, 0);
        assert!(p.logout_confirm && p.step_up.is_empty());
        assert_eq!(p.max_auth_age, Some(Duration::from_secs(12 * 3600)));
        // The snapshot appends it beside the configured applications.
        let snap = c.snapshot(3);
        assert_eq!(snap.apps.len(), 1);
        let console = snap
            .app_for_host(&Host::parse("hopae-admin.example.test").unwrap())
            .unwrap();
        assert_eq!(console.app_id.as_str(), "admin");
        assert_eq!(console.max_auth_age, Some(Duration::from_secs(12 * 3600)));
        assert!(snap.return_origin_allowed(&Host::parse("hopae-admin.example.test").unwrap(), 443));
        // Configured applications never carry a freshness bound (not a key).
        let with_app =
            admin_with(r#"{"apps": [{"app_id": "a", "hosts": ["a.example.test"]}]}"#).unwrap();
        let snap = with_app.snapshot(1);
        assert_eq!(snap.apps.len(), 2);
        assert!(
            snap.apps
                .iter()
                .filter(|a| a.app_id.as_str() != "admin")
                .all(|a| a.max_auth_age.is_none())
        );
    }

    #[test]
    fn console_settings_override_the_defaults() {
        let c = admin_with(
            r#"{"listen": {"admin": "127.0.0.1:9999"},
                "admin": {"session": {"idle": "10m", "absolute": "2h"}, "binding": {"ip": "prefix", "ua": "strict", "on_mismatch": "drop_handle"},
                          "max_auth_age": "45m", "untrusted_peers": "as_client", "query_budget_ms": 750,
                          "directory_privacy": "strict",
                          "public_url": "https://hopae-admin.example.test:8443"}}"#,
        )
        .unwrap();
        assert_eq!(c.admin_addr(), Some("127.0.0.1:9999".parse().unwrap()));
        let p = c.admin_policy().unwrap();
        assert_eq!(p.ports, vec![8443]);
        assert_eq!(
            (p.session.idle, p.session.absolute),
            (Duration::from_secs(600), Duration::from_secs(7200))
        );
        assert_eq!(p.binding.ip, IpBinding::Prefix { v4: 24, v6: 64 });
        assert_eq!(
            (p.binding.ua, p.binding.on_mismatch),
            (UaBinding::Strict, OnMismatch::DropHandle)
        );
        let l = c.admin_limits().unwrap();
        assert_eq!(l.max_auth_age, Duration::from_secs(45 * 60));
        assert_eq!(l.untrusted_peers, UntrustedPeers::AsClient);
        assert_eq!(l.query_budget, Duration::from_millis(750));
        assert_eq!(l.directory_privacy, DirectoryPrivacy::Strict);
        let d = admin_with(r#"{"admin": {}}"#).unwrap();
        assert_eq!(
            d.admin_limits().unwrap().directory_privacy,
            DirectoryPrivacy::Standard
        );
        assert!(admin_with(r#"{"admin": {"directory_privacy": "open"}}"#).is_err());
    }

    #[test]
    fn require_aal_2_adds_the_step_up_rule_and_warns() {
        let c = admin_with(r#"{"admin": {"require_aal": 2}}"#).unwrap();
        let p = c.admin_policy().unwrap();
        assert_eq!(
            p.step_up,
            vec![StepUpRule {
                path_prefix: Some("/".into()),
                aal: Aal::Two,
                max_age: None,
                factor: None,
                enrollment_grace: false,
            }]
        );
        assert!(c.warnings().iter().any(|w| w == "admin.require_aal: no second factor exists yet; every console request will be refused"), "{:?}", c.warnings());
        assert!(
            admin_with("{}")
                .unwrap()
                .warnings()
                .iter()
                .all(|w| !w.contains("require_aal"))
        );
    }

    #[test]
    fn aal3_requirements_need_high_assurance_and_map_to_aal3_rules() {
        let ha = r#""webauthn": {"high_assurance": {"attestation_ca_files": ["/x.pem"], "aaguids": ["cb69481e-8ff7-4039-93ec-0a2729a154a8"]}}"#;
        let c = admin_with(&format!(r#"{{"admin": {{"require_aal": 3}}, {ha}}}"#)).unwrap();
        assert_eq!(c.admin_limits().unwrap().require_aal, Aal::Three);
        assert_eq!(c.admin_policy().unwrap().step_up[0].aal, Aal::Three);
        assert_eq!(c.admin_policy().unwrap().max_emitted_aal, Aal::Two);
        let refused = admin_invalid(r#"{"admin": {"require_aal": 3}}"#);
        assert!(
            refused.contains("admin.require_aal 3 needs webauthn.high_assurance"),
            "{refused}"
        );
        assert!(admin_invalid(r#"{"admin": {"require_aal": 4}}"#).contains("must be 1, 2 or 3"));
    }

    #[test]
    fn console_validation_names_the_key_path() {
        assert!(
            admin_invalid(
                r#"{"admin": {"public_url": "https://hopae-admin.example.test/console"}}"#
            )
            .contains("admin.public_url")
        );
        for bad in [
            "https://hopae-admin.example.test/?q=1",
            "https://hopae-admin.example.test/#f",
            "https://user@hopae-admin.example.test",
            "ftp://hopae-admin.example.test",
            "hopae-admin.example.test",
            "https://127.0.0.1",
            "https://Hopae-Admin.example.test.:",
        ] {
            if bad == "https://Hopae-Admin.example.test.:" {
                continue;
            }
            assert!(
                admin_invalid(&format!(r#"{{"admin": {{"public_url": "{bad}"}}}}"#))
                    .contains("admin.public_url"),
                "{bad}"
            );
        }
        // http:// only with cookie.secure = false.
        assert!(
            admin_invalid(r#"{"admin": {"public_url": "http://hopae-admin.example.test"}}"#)
                .contains("https://")
        );
        assert!(admin_with(r#"{"cookie": {"secure": false, "name": "hopae"}, "admin": {"public_url": "http://hopae-admin.example.test"}}"#).is_ok());
        let e = admin_invalid(r#"{"apps": [{"app_id": "admin", "hosts": ["x.example.test"]}]}"#);
        assert!(
            e.contains("apps[0].app_id") && e.contains("reserved"),
            "{e}"
        );
        let e = admin_invalid(
            r#"{"apps": [{"app_id": "a", "hosts": ["x.example.test", "hopae-admin.example.test"]}]}"#,
        );
        assert!(
            e.contains("apps[0].hosts[1]") && e.contains("registered implicitly"),
            "{e}"
        );
        assert!(admin_invalid(r#"{"listen": {"portal": "127.0.0.1:8700", "gateway": "127.0.0.1:8701", "admin": "127.0.0.1:8701"}}"#).contains("listen.admin and listen.gateway must differ"));
        assert!(admin_invalid(r#"{"listen": {"portal": "127.0.0.1:8700", "gateway": "127.0.0.1:8701", "admin": "127.0.0.1:8700"}}"#).contains("listen.admin and listen.portal must differ"));
        assert!(
            admin_invalid(r#"{"listen": {"admin": "nowhere"}}"#)
                .contains("listen.admin must be a socket address")
        );
        assert!(
            admin_invalid(r#"{"admin": {"session": {"idle": "59s"}}}"#)
                .contains("admin.session.idle must be at least 60s")
        );
        assert!(admin_invalid(r#"{"admin": {"require_aal": 3}}"#).contains("admin.require_aal"));
        assert!(admin_invalid(r#"{"admin": {"require_aal": 0}}"#).contains("admin.require_aal"));
        assert!(
            admin_invalid(r#"{"admin": {"query_budget_ms": 99}}"#)
                .contains("admin.query_budget_ms")
        );
        assert!(
            admin_invalid(r#"{"admin": {"query_budget_ms": 30001}}"#)
                .contains("admin.query_budget_ms")
        );
        assert!(
            admin_with(r#"{"admin": {"query_budget_ms": 100}}"#).is_ok()
                && admin_with(r#"{"admin": {"query_budget_ms": 30000}}"#).is_ok()
        );
        assert!(
            admin_invalid(r#"{"admin": {"untrusted_peers": "sometimes"}}"#).contains("sometimes")
        );
        assert!(
            admin_invalid(r#"{"limits": {"admin_max_concurrent": 0}}"#)
                .contains("limits.admin_max_concurrent")
        );
        assert!(
            admin_invalid(r#"{"admin": {"binding": {"ip_prefix_v4": 33}}}"#)
                .contains("admin.binding.ip_prefix_v4")
        );
        assert!(admin_invalid(r#"{"admin": {"bogus": 1}}"#).contains("admin.bogus"));
    }

    #[test]
    fn the_freshness_bound_has_a_floor_of_thirty_minutes() {
        for bad in ["60s", "29m", "1799s"] {
            let e = admin_invalid(&format!(r#"{{"admin": {{"max_auth_age": "{bad}"}}}}"#));
            assert!(
                e.contains("admin.max_auth_age must be at least 30m"),
                "{bad}: {e}"
            );
        }
        for ok in ["30m", "1801s", "12h", "7d"] {
            assert!(
                admin_with(&format!(r#"{{"admin": {{"max_auth_age": "{ok}"}}}}"#)).is_ok(),
                "{ok}"
            );
        }
    }

    #[test]
    fn seeded_grants_are_validated_entry_by_entry() {
        let e = admin_invalid(r#"{"admin": {"users": [{"role": "admin"}]}}"#);
        assert!(
            e.contains("admin.users[0] needs a user_id or an email"),
            "{e}"
        );
        let e = admin_invalid(r#"{"admin": {"users": [{"user_id": "u_a; DROP"}]}}"#);
        assert!(e.contains("admin.users[0].user_id"), "{e}");
        let e = admin_invalid(r#"{"admin": {"users": [{"email": "a@b@c"}]}}"#);
        assert!(e.contains("admin.users[0].email"), "{e}");
        let long = "x".repeat(257);
        let e = admin_invalid(&format!(
            r#"{{"admin": {{"users": [{{"user_id": "u_a", "note": "{long}"}}]}}}}"#
        ));
        assert!(e.contains("admin.users[0].note"), "{e}");
        let e = admin_invalid(r#"{"admin": {"users": [{"user_id": "u_a", "role": "root"}]}}"#);
        assert!(e.contains("root"), "{e}");
        let ok = admin_with(
            r#"{"admin": {"users": [{"user_id": "u_a", "role": "admin", "note": "seed"}, {"email": "V@Example.test", "role": "viewer"}, {"email": "n@example.test", "user_id": "u_n"}]}}"#,
        )
        .unwrap();
        let entries = ok.admin_user_entries();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].role, Some(AdminRoleCfg::Admin));
        assert_eq!(entries[1].role, Some(AdminRoleCfg::Viewer));
        assert_eq!(
            entries[2].role, None,
            "role defaults to admin where the grant is made"
        );
        assert!(valid_user_id("u_a") && valid_user_id("u_01HZZZZZZZZZZZZZZZZZZZZZZZ"));
        for bad in ["", "u_", "x_abc", "u_a b", "u_a;", "u_é"] {
            assert!(!valid_user_id(bad), "{bad:?}");
        }
    }

    #[test]
    fn providers_carry_their_resolved_reauth_capability() {
        let c = with(
            r#"{"providers": [
                 {"provider_id": "google", "kind": "oidc", "client_id": "c"},
                 {"provider_id": "corp", "kind": "oidc", "client_id": "c", "issuer": "https://accounts.google.com"},
                 {"provider_id": "other", "kind": "oidc", "client_id": "c", "issuer": "https://idp.example.test"}]}"#,
        )
        .unwrap();
        let caps: Vec<_> = c
            .snapshot(1)
            .providers
            .iter()
            .map(|p| (p.reauth, p.reauth_prompt))
            .collect();
        assert_eq!(
            caps,
            vec![
                (ReauthCapability::Unsupported, ReauthPrompt::Login),
                (ReauthCapability::Unsupported, ReauthPrompt::Login),
                (ReauthCapability::MaxAge, ReauthPrompt::Login),
            ]
        );
    }

    #[test]
    fn the_admin_fixtures_are_accepted_or_rejected_as_documented() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/config");
        let load = |name: &str| load(&dir.join(format!("{name}.json")));
        let rejected = |name: &str, needle: &str| match load(name) {
            Err(e) => assert!(e.to_string().contains(needle), "{name}: {e}"),
            Ok(_) => panic!("{name} must be rejected"),
        };
        rejected("admin_reserved_app_id", "reserved");
        rejected(
            "admin_listener_clash",
            "listen.admin and listen.gateway must differ",
        );
        rejected("admin_public_url_path", "admin.public_url");
        rejected("admin_host_in_apps", "registered implicitly");
        rejected("admin_untrusted_peers_bad", "sometimes");
        rejected(
            "admin_users_bad_entry",
            "admin.users[0] needs a user_id or an email",
        );
        rejected(
            "admin_max_auth_age_60s",
            "admin.max_auth_age must be at least 30m",
        );
        rejected(
            "admin_max_auth_age_29m",
            "admin.max_auth_age must be at least 30m",
        );
        let c = load("admin_require_aal_2").unwrap();
        assert!(
            c.warnings()
                .iter()
                .any(|w| w.contains("no second factor exists yet"))
        );
        for name in ["../m4-admin", "../m4-admin-unsupported"] {
            let c = load(name).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert!(c.admin_enabled(), "{name}");
        }
    }

    #[test]
    fn durations_parse_strictly() {
        assert_eq!(
            ConfigDuration::parse("12h"),
            Some(Duration::from_secs(43200))
        );
        assert_eq!(
            ConfigDuration::parse("7d"),
            Some(Duration::from_secs(604800))
        );
        for bad in ["", "h", "0h", "-1h", "1w", "1.5h", "12", " 1h"] {
            assert_eq!(ConfigDuration::parse(bad), None, "{bad:?}");
        }
    }
}
