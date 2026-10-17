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
    pub(crate) fn heap_capacity(&self) -> usize {
        self.0.capacity()
    }

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
    /// Highest level verify and receipts present for this application
    /// (ADR-0018): `Two` (default) or `Three`.
    pub max_emitted_aal: crate::session::types::Aal,
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
            max_emitted_aal: crate::session::types::Aal::Two,
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

/// `providers[].tls`: absolute paths of a private CA bundle (replacing the
/// built-in roots) and of a client certificate and key presented to the
/// provider (mutual TLS); reloaded when they change.
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderTls {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_file: Option<std::path::PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_certificate_file: Option<std::path::PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_key_file: Option<std::path::PathBuf>,
}

/// `providers[].client_assertion`: `private_key_jwt` client authentication
/// (RFC 7523) with a key file instead of a client secret.
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderClientAssertion {
    pub key_file: std::path::PathBuf,
    pub key_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithms: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
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
    pub ldap: Option<crate::provider::ldap::Config>,
    /// `providers[].groups` (ADR-0019).
    pub groups: Option<crate::groups::ProviderGroups>,
    /// Environment variable *name*; the value is never held here.
    pub client_secret_env: Option<String>,
    pub issuer: Option<String>,
    pub scope: String,
    /// Extra hosts the discovery document may point to (lower-case).
    pub endpoint_hosts: Vec<String>,
    /// `None` = unset (the build default applies).
    pub allow_private_endpoints: Option<bool>,
    /// `providers[].tls`: a private CA and a client certificate (OIDC).
    pub tls: Option<ProviderTls>,
    /// `providers[].client_assertion`: `private_key_jwt` (OIDC).
    pub client_assertion: Option<ProviderClientAssertion>,
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
    /// The stored capability of every retained database provider the file no
    /// longer lists (ADR-0016 decision 15); see [`ConfigSnapshot::reauth_capability`].
    pub retained_reauth: std::collections::HashMap<
        crate::provider::types::ProviderId,
        crate::provider::types::ReauthCapability,
    >,
}

impl ConfigSnapshot {
    /// The one authoritative reauthentication capability of a provider, read
    /// by verify, callback, the write fence and the status page: the file's
    /// entry (a stored setting already applied), else the stored capability
    /// of a retained database provider, else `max_age`.
    pub fn reauth_capability(
        &self,
        id: &crate::provider::types::ProviderId,
    ) -> crate::provider::types::ReauthCapability {
        self.providers
            .iter()
            .find(|p| &p.provider_id == id)
            .map(|p| p.reauth)
            .or_else(|| self.retained_reauth.get(id).copied())
            .unwrap_or(crate::provider::types::ReauthCapability::MaxAge)
    }

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
            retained_reauth: Default::default(),
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

impl AppPolicy {
    #[allow(dead_code)] // Used by the additive native Human retained-record quota.
    pub(crate) fn owned_heap_bytes(&self) -> crate::store::StoreResult<usize> {
        use crate::store::types::{heap_sum, heap_vec};
        let mut total = heap_sum([
            self.app_id.heap_capacity(),
            self.display_name.capacity(),
            heap_vec::<Host>(self.hosts.capacity())?,
            heap_vec::<u16>(self.ports.capacity())?,
            heap_vec::<StepUpRule>(self.step_up.capacity())?,
        ])?;
        for host in &self.hosts {
            total = heap_sum([total, host.heap_capacity()])?;
        }
        for rule in &self.step_up {
            total = heap_sum([total, rule.path_prefix.as_ref().map_or(0, String::capacity)])?;
        }
        Ok(total)
    }
}

#[cfg(test)]
mod retained_heap_tests {
    use super::*;
    #[test]
    fn retained_heap_app_counts_vectors_and_nested_spare_capacity() {
        let mut app = AppPolicy::default_app();
        let before = app.owned_heap_bytes().unwrap();
        let mut hosts = Vec::with_capacity(8);
        let mut host = Host::parse("app.test").unwrap();
        host.0.reserve(128);
        let delta = hosts.capacity() * std::mem::size_of::<Host>() + host.heap_capacity();
        hosts.push(host);
        app.hosts = hosts;
        assert_eq!(app.owned_heap_bytes().unwrap(), before + delta);
        let before = app.owned_heap_bytes().unwrap();
        let mut prefix = String::with_capacity(256);
        prefix.push('/');
        let mut rules = Vec::with_capacity(6);
        let delta = rules.capacity() * std::mem::size_of::<StepUpRule>() + prefix.capacity();
        rules.push(StepUpRule {
            path_prefix: Some(prefix),
            aal: Aal::Two,
            max_age: None,
        });
        app.step_up = rules;
        assert_eq!(app.owned_heap_bytes().unwrap(), before + delta);
        let before = app.owned_heap_bytes().unwrap();
        app.ports = Vec::with_capacity(13);
        assert_eq!(
            app.owned_heap_bytes().unwrap(),
            before + app.ports.capacity() * std::mem::size_of::<u16>()
        );
    }
}
