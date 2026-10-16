//! Configuration of groups: the instance-wide `groups` section and the
//! per-provider `providers[].groups` sync rules, and the compiled mapping
//! rules every provider assertion goes through.

use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};

use super::{MAX_KEY_BYTES, MAX_NAME_CHARS, MAX_RAW_VALUES};
use crate::provider::types::RawGroup;

fn default_max_groups_per_user() -> usize {
    256
}
fn default_retention_days() -> u32 {
    30
}
fn default_maintenance_secs() -> u64 {
    300
}
fn default_stale_group_days() -> u32 {
    30
}
fn default_max_staleness_secs() -> u64 {
    7 * 86_400
}

/// `groups`: instance-wide settings. Absent means every default.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupsConfig {
    /// Most groups (all sources together) one person may belong to; a sync
    /// that would exceed it is refused and changes nothing.
    #[serde(default = "default_max_groups_per_user")]
    pub max_groups_per_user: usize,
    /// Age after which projection journal rows are pruned; a projection
    /// cursor older than the oldest kept row is `410 cursor_expired`.
    #[serde(default = "default_retention_days")]
    pub change_retention_days: u32,
    /// Interval of the maintenance pass: expired local memberships, provider
    /// memberships past their removal grace, stale provider groups, journal
    /// retention and the periodic LDAP sync.
    #[serde(default = "default_maintenance_secs")]
    pub maintenance_interval_secs: u64,
    /// A provider group that has had no member and no sync report for this
    /// many days is deleted (a tombstone stays).
    #[serde(default = "default_stale_group_days")]
    pub stale_group_days: u32,
    /// A provider membership that no successful assertion (sign-in or
    /// periodic sync) refreshed for this long is suspended: kept, but left
    /// out of the projection and the gateway mirror until it is asserted
    /// again (fail-static with a bound).
    #[serde(default = "default_max_staleness_secs")]
    pub max_staleness_secs: u64,
    /// Mirror a person's group references into `users.groups`, so that the
    /// gateway contract's `x-forwarded-groups` carries them (ADR-0018
    /// decision 6). Off by default.
    #[serde(default)]
    pub gateway_header: bool,
    /// The signing key of the membership projection. Without it the
    /// projection endpoints answer `503 projection_unavailable`.
    #[serde(default)]
    pub projection: Option<ProjectionKey>,
}

impl Default for GroupsConfig {
    fn default() -> Self {
        GroupsConfig {
            max_groups_per_user: default_max_groups_per_user(),
            change_retention_days: default_retention_days(),
            maintenance_interval_secs: default_maintenance_secs(),
            stale_group_days: default_stale_group_days(),
            max_staleness_secs: default_max_staleness_secs(),
            gateway_header: false,
            projection: None,
        }
    }
}

/// Most group references mirrored into `x-forwarded-groups`.
pub const GATEWAY_HEADER_MAX: usize = 32;

/// `groups.projection`: an Ed25519 key loaded the way the receipt issuer's
/// is (public key in the file, seed by environment reference), with its own
/// purpose and domain separation.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectionKey {
    pub issuer_ref: String,
    pub key_epoch: u64,
    pub public_key: String,
    pub seed_env: String,
    /// The consumer the projection is bound to (Pumgye's identifier).
    pub audience: String,
}

fn ident(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
}

impl GroupsConfig {
    pub fn validate(&self, errs: &mut Vec<String>) {
        if !(1..=1024).contains(&self.max_groups_per_user) {
            errs.push("groups.max_groups_per_user must be between 1 and 1024".into());
        }
        if !(1..=3650).contains(&self.change_retention_days) {
            errs.push("groups.change_retention_days must be between 1 and 3650".into());
        }
        if !(10..=86_400).contains(&self.maintenance_interval_secs) {
            errs.push("groups.maintenance_interval_secs must be between 10 and 86400".into());
        }
        if !(1..=3650).contains(&self.stale_group_days) {
            errs.push("groups.stale_group_days must be between 1 and 3650".into());
        }
        if !(3600..=31_536_000).contains(&self.max_staleness_secs) {
            errs.push("groups.max_staleness_secs must be between 3600 and 31536000".into());
        }
        if let Some(p) = &self.projection {
            if !ident(&p.issuer_ref) || !ident(&p.audience) {
                errs.push(
                    "groups.projection.issuer_ref and audience must be 1 to 128 of [A-Za-z0-9_.:-]"
                        .into(),
                );
            }
            if !(1..=9_007_199_254_740_991).contains(&p.key_epoch) {
                errs.push("groups.projection.key_epoch must be at least 1".into());
            }
            if super::projection::public_key(&p.public_key).is_none() {
                errs.push("groups.projection.public_key must be a base64 Ed25519 key".into());
            }
            if p.seed_env.is_empty()
                || p.seed_env.len() > 128
                || !p
                    .seed_env
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_')
            {
                errs.push("groups.projection.seed_env must be an environment variable name".into());
            }
        }
    }
}

// ---- provider sync rules -----------------------------------------------------

fn default_max_groups() -> usize {
    100
}
fn default_sync_batch() -> usize {
    200
}
fn default_member_of() -> String {
    "memberOf".into()
}
fn default_object_class() -> String {
    "groupOfNames".into()
}
fn default_member_attribute() -> String {
    "member".into()
}
fn default_name_attribute() -> String {
    "cn".into()
}

/// How an LDAP provider finds a person's groups.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LdapGroupMode {
    /// Read the person entry's `memberOf` (or the configured attribute).
    #[default]
    MemberOf,
    /// Search group entries whose member attribute holds the person's DN.
    Search,
}

/// `providers[].groups.ldap`.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LdapGroups {
    #[serde(default)]
    pub mode: LdapGroupMode,
    #[serde(default = "default_member_of")]
    pub member_of_attribute: String,
    /// Search base of `search` mode (defaults to the provider's `base_dn`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub search_base_dn: Option<String>,
    #[serde(default = "default_object_class")]
    pub object_class: String,
    #[serde(default = "default_member_attribute")]
    pub member_attribute: String,
    #[serde(default = "default_name_attribute")]
    pub name_attribute: String,
}

impl Default for LdapGroups {
    fn default() -> Self {
        LdapGroups {
            mode: LdapGroupMode::MemberOf,
            member_of_attribute: default_member_of(),
            search_base_dn: None,
            object_class: default_object_class(),
            member_attribute: default_member_attribute(),
            name_attribute: default_name_attribute(),
        }
    }
}

/// A rewrite of a group's display name (`$1`-style replacement).
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Rewrite {
    pub pattern: String,
    pub replacement: String,
}

/// `providers[].groups`: whether and how a provider's groups are synced.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderGroups {
    /// OIDC: the claim holding an array of group names, as a dotted path
    /// (`groups`, `realm_access.roles`). Default `groups`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim: Option<String>,
    /// LDAP: how groups are found. Default `member_of`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ldap: Option<LdapGroups>,
    /// Only source values (claim values, group DNs) matching this pattern are kept.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub include: Option<String>,
    /// Source values matching this pattern are dropped (after `include`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exclude: Option<String>,
    /// Rewrites the display name of a kept group.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rewrite: Option<Rewrite>,
    /// Most groups one person may have from this provider after filtering; an
    /// assertion with more is refused and changes nothing.
    #[serde(default = "default_max_groups")]
    pub max_groups: usize,
    /// How long a membership the provider stopped reporting stays before it
    /// is removed (0: removed by the sync that no longer reports it).
    #[serde(default)]
    pub removal_grace_secs: u64,
    /// LDAP: refresh linked people's groups periodically, at most this often
    /// per person. Absent: groups are refreshed at sign-in only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sync_interval_secs: Option<u64>,
    /// LDAP: people refreshed per maintenance pass.
    #[serde(default = "default_sync_batch")]
    pub sync_batch: usize,
}

fn ldap_attribute(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.as_bytes()[0].is_ascii_alphabetic()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

fn claim_path(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.split('.').count() <= 4
        && value.split('.').all(|seg| {
            !seg.is_empty()
                && seg
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-:/".contains(&b))
        })
}

fn pattern(p: &str) -> Result<Regex, String> {
    if p.is_empty() || p.len() > 512 {
        return Err("pattern must be 1 to 512 bytes".into());
    }
    // The regex crate matches in linear time; the size limits bound memory.
    RegexBuilder::new(p)
        .size_limit(1 << 20)
        .dfa_size_limit(1 << 20)
        .build()
        .map_err(|_| "invalid pattern".to_string())
}

impl ProviderGroups {
    /// Problems of this section for a provider of `kind` (`oidc`/`ldap`).
    pub fn validate(&self, provider: &str, ldap: bool, errs: &mut Vec<String>) {
        let at = format!("providers[{provider}].groups");
        if ldap && self.claim.is_some() {
            errs.push(format!("{at}.claim applies to OIDC providers only"));
        }
        if !ldap && (self.ldap.is_some() || self.sync_interval_secs.is_some()) {
            errs.push(format!(
                "{at}.ldap and sync_interval_secs apply to LDAP providers only"
            ));
        }
        if let Some(c) = &self.claim
            && !claim_path(c)
        {
            errs.push(format!(
                "{at}.claim must be a dotted path of at most 4 segments"
            ));
        }
        if let Some(l) = &self.ldap {
            for a in [
                &l.member_of_attribute,
                &l.object_class,
                &l.member_attribute,
                &l.name_attribute,
            ] {
                if !ldap_attribute(a) {
                    errs.push(format!(
                        "{at}.ldap attribute names must be LDAP attribute descriptions"
                    ));
                    break;
                }
            }
            if let Some(dn) = &l.search_base_dn
                && (dn.is_empty() || dn.len() > 2048 || dn.chars().any(char::is_control))
            {
                errs.push(format!("{at}.ldap.search_base_dn is invalid"));
            }
        }
        for (name, p) in [("include", &self.include), ("exclude", &self.exclude)] {
            if let Some(p) = p
                && let Err(e) = pattern(p)
            {
                errs.push(format!("{at}.{name}: {e}"));
            }
        }
        if let Some(r) = &self.rewrite {
            if let Err(e) = pattern(&r.pattern) {
                errs.push(format!("{at}.rewrite.pattern: {e}"));
            }
            if r.replacement.len() > 256 || r.replacement.chars().any(char::is_control) {
                errs.push(format!(
                    "{at}.rewrite.replacement must be at most 256 bytes"
                ));
            }
        }
        if !(1..=1024).contains(&self.max_groups) {
            errs.push(format!("{at}.max_groups must be between 1 and 1024"));
        }
        if self.removal_grace_secs > 7 * 86_400 {
            errs.push(format!("{at}.removal_grace_secs must be at most 604800"));
        }
        if let Some(s) = self.sync_interval_secs
            && !(300..=7 * 86_400).contains(&s)
        {
            errs.push(format!(
                "{at}.sync_interval_secs must be between 300 and 604800"
            ));
        }
        if !(1..=1000).contains(&self.sync_batch) {
            errs.push(format!("{at}.sync_batch must be between 1 and 1000"));
        }
    }

    /// The OIDC claim path (default `groups`).
    pub fn claim_path(&self) -> &str {
        self.claim.as_deref().unwrap_or("groups")
    }

    /// The sync rules of a stored provider row, when it has a valid section.
    pub fn of_row(config: &serde_json::Value) -> Option<ProviderGroups> {
        serde_json::from_value(config.get("groups")?.clone()).ok()
    }

    /// Compile the rules (already validated at configuration load; a stored
    /// row that no longer compiles syncs nothing).
    pub fn compile(&self) -> Option<Rules> {
        Some(Rules {
            include: self.include.as_deref().map(pattern).transpose().ok()?,
            exclude: self.exclude.as_deref().map(pattern).transpose().ok()?,
            rewrite: match &self.rewrite {
                Some(r) => Some((pattern(&r.pattern).ok()?, r.replacement.clone())),
                None => None,
            },
            max_groups: self.max_groups,
            removal_grace_secs: self.removal_grace_secs,
        })
    }
}

/// Compiled mapping rules of one provider.
#[derive(Clone, Debug)]
pub struct Rules {
    include: Option<Regex>,
    exclude: Option<Regex>,
    rewrite: Option<(Regex, String)>,
    pub max_groups: usize,
    pub removal_grace_secs: u64,
}

/// One group a provider asserted, after the rules: its stable key and name.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Mapped {
    pub key: String,
    pub name: String,
}

/// Why an assertion was not applied (the previous memberships stay).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// More groups than `max_groups` (or the raw bound) after filtering.
    TooMany,
}

impl Refusal {
    pub fn as_str(self) -> &'static str {
        match self {
            Refusal::TooMany => "too_many_groups",
        }
    }
}

fn clean(s: &str, max_bytes: usize) -> bool {
    !s.trim().is_empty() && s.len() <= max_bytes && !s.chars().any(super::hidden)
}

fn cut_chars(s: &str, max: usize) -> String {
    s.trim().chars().take(max).collect()
}

impl Rules {
    /// Apply include/exclude to each source key, rewrite the kept names,
    /// drop invalid values and duplicates. `Err` when more than
    /// `max_groups` remain: a truncated set would remove memberships the
    /// provider still asserts, so nothing is applied.
    pub fn map(&self, raw: &[RawGroup]) -> Result<Vec<Mapped>, Refusal> {
        if raw.len() > MAX_RAW_VALUES {
            return Err(Refusal::TooMany);
        }
        let mut out: std::collections::BTreeMap<String, String> = Default::default();
        for g in raw {
            if !clean(&g.key, MAX_KEY_BYTES) || !clean(&g.name, MAX_KEY_BYTES) {
                continue;
            }
            if self.include.as_ref().is_some_and(|r| !r.is_match(&g.key)) {
                continue;
            }
            if self.exclude.as_ref().is_some_and(|r| r.is_match(&g.key)) {
                continue;
            }
            let name = match &self.rewrite {
                Some((re, rep)) if re.is_match(&g.name) => {
                    re.replace(&g.name, rep.as_str()).into_owned()
                }
                _ => g.name.clone(),
            };
            let name = cut_chars(&name, MAX_NAME_CHARS);
            if name.is_empty() || name.chars().any(super::hidden) {
                continue;
            }
            out.entry(g.key.clone()).or_insert(name);
            if out.len() > self.max_groups {
                return Err(Refusal::TooMany);
            }
        }
        Ok(out
            .into_iter()
            .map(|(key, name)| Mapped { key, name })
            .collect())
    }
}

/// The values of the claim at `path` (dotted) in `claims`: `None` when the
/// claim is absent or not an array of strings (not asserted: nothing
/// changes), `Some` otherwise. Non-string elements make the whole claim
/// malformed. More than [`MAX_RAW_VALUES`] values are kept so that the
/// rules refuse the assertion rather than apply a truncated set.
pub fn claim_values(claims: &serde_json::Value, path: &str) -> Option<Vec<RawGroup>> {
    let mut v = claims;
    for seg in path.split('.') {
        v = v.as_object()?.get(seg)?;
    }
    let arr = v.as_array()?;
    let mut out = Vec::with_capacity(arr.len().min(MAX_RAW_VALUES + 1));
    for item in arr.iter().take(MAX_RAW_VALUES + 1) {
        let s = item.as_str()?;
        out.push(RawGroup {
            key: s.to_string(),
            name: s.to_string(),
        });
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn raw(v: &[&str]) -> Vec<RawGroup> {
        v.iter()
            .map(|s| RawGroup {
                key: s.to_string(),
                name: s.to_string(),
            })
            .collect()
    }

    fn rules(v: serde_json::Value) -> Rules {
        let g: ProviderGroups = serde_json::from_value(v).unwrap();
        let mut errs = vec![];
        g.validate("p", false, &mut errs);
        assert!(errs.is_empty(), "{errs:?}");
        g.compile().unwrap()
    }

    #[test]
    fn claims_are_read_by_dotted_path_and_malformed_claims_are_not_asserted() {
        let c = json!({"groups": ["a", "b"], "realm_access": {"roles": ["r1"]}, "bad": ["a", 1], "s": "a"});
        assert_eq!(claim_values(&c, "groups").unwrap().len(), 2);
        assert_eq!(claim_values(&c, "realm_access.roles").unwrap()[0].key, "r1");
        assert!(claim_values(&c, "missing").is_none());
        assert!(claim_values(&c, "bad").is_none());
        assert!(claim_values(&c, "s").is_none());
        assert!(
            claim_values(&json!({"groups": []}), "groups")
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn include_exclude_and_rewrite_map_names_but_keep_source_keys() {
        let r = rules(json!({
            "include": "^/eng/",
            "exclude": "-legacy$",
            "rewrite": {"pattern": "^/eng/(.+)$", "replacement": "eng-$1"}
        }));
        let m = r
            .map(&raw(&[
                "/eng/backend",
                "/eng/old-legacy",
                "/sales/x",
                "/eng/backend",
                " ",
                "a\nb",
                "/eng/x\u{202E}y",
            ]))
            .unwrap();
        assert_eq!(
            m,
            vec![Mapped {
                key: "/eng/backend".into(),
                name: "eng-backend".into()
            }]
        );
    }

    #[test]
    fn more_groups_than_the_limit_refuse_the_whole_assertion() {
        let r = rules(json!({"max_groups": 2}));
        assert_eq!(r.map(&raw(&["a", "b"])).unwrap().len(), 2);
        assert_eq!(r.map(&raw(&["a", "b", "c"])), Err(Refusal::TooMany));
        // Duplicates and filtered values do not count.
        assert_eq!(r.map(&raw(&["a", "a", "b"])).unwrap().len(), 2);
        let many: Vec<String> = (0..=MAX_RAW_VALUES).map(|i| format!("g{i}")).collect();
        let many: Vec<&str> = many.iter().map(String::as_str).collect();
        assert_eq!(
            rules(json!({"max_groups": 1024})).map(&raw(&many)),
            Err(Refusal::TooMany)
        );
    }

    #[test]
    fn invalid_sections_are_reported() {
        let mut errs = vec![];
        let g: ProviderGroups = serde_json::from_value(json!({
            "claim": "a.b.c.d.e", "include": "(", "max_groups": 0,
            "removal_grace_secs": 700000, "sync_interval_secs": 10, "sync_batch": 0,
            "ldap": {"member_of_attribute": "memberOf)(x"}
        }))
        .unwrap();
        g.validate("p", false, &mut errs);
        assert!(errs.len() >= 6, "{errs:?}");
        let mut errs = vec![];
        g.validate("p", true, &mut errs);
        assert!(errs.iter().any(|e| e.contains("OIDC providers only")));
        assert!(serde_json::from_value::<ProviderGroups>(json!({"unknown": 1})).is_err());
    }

    #[test]
    fn instance_settings_are_bounded() {
        let mut errs = vec![];
        GroupsConfig::default().validate(&mut errs);
        assert!(errs.is_empty());
        let c: GroupsConfig = serde_json::from_value(json!({
            "max_groups_per_user": 0, "change_retention_days": 0,
            "maintenance_interval_secs": 1, "stale_group_days": 0, "max_staleness_secs": 60,
            "projection": {"issuer_ref": "bad ref", "key_epoch": 0, "public_key": "x", "seed_env": "a b", "audience": "pumgye"}
        }))
        .unwrap();
        c.validate(&mut errs);
        assert_eq!(errs.len(), 9, "{errs:?}");
    }
}
