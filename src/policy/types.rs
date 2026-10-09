//! Application policy and the immutable configuration snapshot (exact mirror
//! of the `apps[]` configuration, ADR-0004/0007).

use std::time::Duration;

use crate::identity::types::valid_domain;
use crate::provider::types::{ProviderId, ProviderKind};
use crate::session::types::Aal;

string_newtype!(
    /// Application identifier from the configuration (`app`, `default`, ...).
    AppId
);

/// Lower-case exact host name (ADR-0004: no patterns).
///
/// `Host::parse` rejects wildcards, ports, userinfo, trailing dots, paths,
/// schemes and anything that is not letters, digits, hyphens and dots; upper
/// case is folded. Internationalized names must be given in punycode.
#[derive(
    Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(try_from = "String", into = "String")]
pub struct Host(String);

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum HostError {
    #[error("host must not be empty")]
    Empty,
    #[error(
        "host must be an exact host name without wildcard, port, userinfo, path or trailing dot"
    )]
    Invalid,
}

impl Host {
    pub fn parse(input: &str) -> Result<Host, HostError> {
        if input.is_empty() {
            return Err(HostError::Empty);
        }
        let lower = input.to_ascii_lowercase();
        if !lower.is_ascii() || !valid_domain(&lower) {
            return Err(HostError::Invalid);
        }
        Ok(Host(lower))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Host {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for Host {
    type Error = HostError;

    fn try_from(s: String) -> Result<Self, HostError> {
        Host::parse(&s)
    }
}

impl From<Host> for String {
    fn from(h: Host) -> String {
        h.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpBinding {
    Strict,
    /// Same prefix of the recorded address (defaults /24 and /64).
    Prefix {
        v4: u8,
        v6: u8,
    },
    Off,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UaBinding {
    Strict,
    Off,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OnMismatch {
    TerminateSession,
    DropHandle,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BindingPolicy {
    pub ip: IpBinding,
    pub ua: UaBinding,
    pub on_mismatch: OnMismatch,
}

impl Default for BindingPolicy {
    fn default() -> Self {
        BindingPolicy {
            ip: IpBinding::Strict,
            ua: UaBinding::Off,
            on_mismatch: OnMismatch::TerminateSession,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthzChange {
    Refresh,
    Terminate,
}

/// Per-handle timers (`apps[].session`): defaults 12 h idle, 7 d absolute.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lifetimes {
    pub idle: Duration,
    pub absolute: Duration,
}

impl Default for Lifetimes {
    fn default() -> Self {
        Lifetimes {
            idle: Duration::from_secs(12 * 3600),
            absolute: Duration::from_secs(7 * 86400),
        }
    }
}

/// Parsed and validated in M1, enforced in M5; a non-empty list forces `no-store` (ADR-0006).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StepUpRule {
    pub path_prefix: Option<String>,
    pub aal: Aal,
    pub max_age: Option<Duration>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppPolicy {
    pub app_id: AppId,
    pub display_name: String,
    pub hosts: Vec<Host>,
    pub ports: Vec<u16>,
    pub enabled: bool,
    pub session: Lifetimes,
    pub binding: BindingPolicy,
    pub on_authz_change: AuthzChange,
    /// 0..=30.
    pub verify_cache_seconds: u32,
    /// `/_hopae/logout` asks for confirmation at the portal (`true`, the
    /// default) or ends a same-origin navigation's session at once (`false`).
    pub logout_confirm: bool,
    pub step_up: Vec<StepUpRule>,
    /// Freshness bound of the session's `auth_time` (ADR-0016). Set only for
    /// the implicit console application in M4-min; not a configuration key.
    pub max_auth_age: Option<Duration>,
}

impl AppPolicy {
    /// The reserved `default` application: policy defaults, no hosts.
    pub fn default_app() -> AppPolicy {
        AppPolicy {
            app_id: AppId::new("default"),
            display_name: "default".into(),
            hosts: Vec::new(),
            ports: Vec::new(),
            enabled: true,
            session: Lifetimes::default(),
            binding: BindingPolicy::default(),
            on_authz_change: AuthzChange::Refresh,
            verify_cache_seconds: 0,
            logout_confirm: true,
            step_up: Vec::new(),
            max_auth_age: None,
        }
    }
}

/// Session-wide timers (`session`): defaults 24 h idle, 30 d absolute.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionPolicy {
    pub idle: Duration,
    pub absolute: Duration,
}

impl Default for SessionPolicy {
    fn default() -> Self {
        SessionPolicy {
            idle: Duration::from_secs(24 * 3600),
            absolute: Duration::from_secs(30 * 86400),
        }
    }
}

/// A provider as written in the configuration file (`providers[]`); mirrored
/// into the `providers` table by the import rule of ADR-0010.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderConfig {
    pub provider_id: ProviderId,
    pub kind: ProviderKind,
    pub display_name: String,
    pub enabled: bool,
    pub client_id: String,
    /// Environment variable *name*; the value is never held here.
    pub client_secret_env: Option<String>,
    pub issuer: Option<String>,
    pub scope: String,
    /// Extra hosts the discovery document may point to (lower-case).
    pub endpoint_hosts: Vec<String>,
    /// `None` = unset (the build default applies).
    pub allow_private_endpoints: Option<bool>,
    pub allowed_email_domains: Vec<String>,
    pub authoritative_domains: Vec<String>,
    pub auto_link: bool,
    pub trust_email: bool,
    /// Position in the file; the chooser order.
    pub sort_order: i32,
    /// Resolved reauthentication capability (the preset's, else `max_age`).
    pub reauth: crate::provider::types::ReauthCapability,
    /// Whether a reauthentication request also carries `prompt=login`.
    pub reauth_prompt: crate::provider::types::ReauthPrompt,
}

/// Immutable snapshot of apps + providers + config generation; swapped with arc_swap on change.
#[derive(Clone, Debug)]
pub struct ConfigSnapshot {
    pub generation: u64,
    pub apps: Vec<AppPolicy>,
    pub default_app: AppPolicy,
    pub providers: Vec<ProviderConfig>,
}

impl ConfigSnapshot {
    /// Exact match only (no suffix, no wildcard). A disabled application is
    /// still returned so the caller can answer `app_disabled`.
    pub fn app_for_host(&self, host: &Host) -> Option<&AppPolicy> {
        self.apps.iter().find(|a| a.hosts.contains(host))
    }

    /// Host listed AND port in its ports, for an enabled application: the
    /// return-origin allowlist of ADR-0004.
    pub fn return_origin_allowed(&self, host: &Host, port: u16) -> bool {
        self.apps
            .iter()
            .any(|a| a.enabled && a.hosts.contains(host) && a.ports.contains(&port))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app(id: &str, hosts: &[&str], ports: &[u16], enabled: bool) -> AppPolicy {
        AppPolicy {
            app_id: AppId::new(id),
            hosts: hosts.iter().map(|h| Host::parse(h).unwrap()).collect(),
            ports: ports.to_vec(),
            enabled,
            ..AppPolicy::default_app()
        }
    }

    #[test]
    fn host_parse_folds_case_and_rejects_everything_else() {
        assert_eq!(
            Host::parse("APP.Example.Test").unwrap().as_str(),
            "app.example.test"
        );
        assert_eq!(Host::parse(""), Err(HostError::Empty));
        for bad in [
            "*.example.test",
            "app.example.test:443",
            "user@app.example.test",
            "app.example.test.",
            "app.example.test/",
            "https://app.example.test",
            ".example.test",
            "app..example.test",
            "-app.example.test",
            "app example.test",
            "[::1]",
            "ap\u{00e9}.example.test",
        ] {
            assert!(Host::parse(bad).is_err(), "{bad:?}");
        }
        assert!(serde_json::from_str::<Host>("\"*.x.test\"").is_err());
    }

    #[test]
    fn snapshot_lookup_is_exact_and_origin_needs_port() {
        let snap = ConfigSnapshot {
            generation: 1,
            apps: vec![
                app("app", &["app.example.test"], &[443], true),
                app("off", &["off.example.test"], &[443], false),
            ],
            default_app: AppPolicy::default_app(),
            providers: vec![],
        };
        let h = |s: &str| Host::parse(s).unwrap();
        assert_eq!(
            snap.app_for_host(&h("app.example.test"))
                .unwrap()
                .app_id
                .as_str(),
            "app"
        );
        assert!(snap.app_for_host(&h("new.example.test")).is_none());
        assert!(snap.app_for_host(&h("example.test")).is_none());
        assert!(snap.app_for_host(&h("off.example.test")).is_some());
        assert!(snap.return_origin_allowed(&h("app.example.test"), 443));
        assert!(!snap.return_origin_allowed(&h("app.example.test"), 8443));
        assert!(!snap.return_origin_allowed(&h("off.example.test"), 443));
        assert!(!snap.return_origin_allowed(&h("old.example.test"), 443));
    }
}
