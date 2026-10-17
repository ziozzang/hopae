//! Risk-based step-up from gateway network evidence (ADR-0023).
//!
//! The gateway (Hangang, from Sumunjang's network evidence) sends a signed,
//! bounded risk context on verify (`x-hopae-risk-context`). Per-application
//! rules turn it into a step-up with freshness or a denial, evaluated by the
//! step-up engine; a bounded in-process memory remembers each session's
//! country and ASN and each user's countries.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha256;

use crate::crypto::Timestamp;
use crate::policy::types::StepUpRule;
use crate::session::types::Aal;

/// The verify request header carrying the context.
pub const HEADER: &str = "x-hopae-risk-context";
/// Largest header value.
pub const MAX_VALUE: usize = 1024;
const DOMAIN: &str = "hopae-risk-context.v1\n";

/// Decisions by application, level and action.
pub const DECISIONS_TOTAL: &str = "hopae_risk_decisions_total";
/// Refused contexts by cause.
pub const INVALID_TOTAL: &str = "hopae_risk_context_invalid_total";
/// Memory entries (`store` = `sessions`, `users`).
pub const MEMORY_ENTRIES: &str = "hopae_risk_memory_entries";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Level {
    Low,
    Elevated,
    High,
}

impl Level {
    pub fn as_str(self) -> &'static str {
        match self {
            Level::Low => "low",
            Level::Elevated => "elevated",
            Level::High => "high",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Enforce,
    Observe,
}

/// A verified context.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Context {
    pub iat: i64,
    pub level: Level,
    pub source: String,
    pub mode: Mode,
    pub reason: String,
    #[serde(default)]
    pub score: Option<u8>,
    #[serde(default)]
    pub asn: Option<u32>,
    #[serde(default)]
    pub country: Option<String>,
    #[serde(default)]
    pub zones: Vec<String>,
    #[serde(default)]
    pub rev: Option<u64>,
}

fn token_ok(s: &str, max: usize) -> bool {
    !s.is_empty()
        && s.len() <= max
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
}

fn country_ok(s: &str) -> bool {
    s.len() == 2 && s.bytes().all(|b| b.is_ascii_uppercase())
}

impl Context {
    fn validate(&self) -> bool {
        self.source == "sumunjang"
            && token_ok(&self.reason, 64)
            && self.score.is_none_or(|s| s <= 100)
            && self.country.as_deref().is_none_or(country_ok)
            && self.zones.len() <= 8
            && self.zones.iter().all(|z| token_ok(z, 64))
    }
}

/// What the verify request carried.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub enum Input {
    /// Risk is not configured: the header is not read.
    #[default]
    NotConfigured,
    Absent,
    /// A present context that was refused (cause for the metric and event).
    Invalid(&'static str),
    Valid(Box<Context>),
}

/// The keys contexts are accepted under (current, then next).
#[derive(Clone)]
pub struct Keys {
    keys: Vec<zeroize::Zeroizing<Vec<u8>>>,
    max_skew: i64,
}

impl std::fmt::Debug for Keys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Keys")
            .field("count", &self.keys.len())
            .finish()
    }
}

impl Keys {
    pub fn new(keys: Vec<Vec<u8>>, max_skew: Duration) -> Keys {
        Keys {
            keys: keys.into_iter().map(zeroize::Zeroizing::new).collect(),
            max_skew: max_skew.as_secs() as i64,
        }
    }

    fn mac(key: &[u8], payload: &str, method: &str, ip: IpAddr, url: &str) -> Hmac<Sha256> {
        let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC takes any key");
        for part in [DOMAIN, payload, "\n", method, "\n"] {
            m.update(part.as_bytes());
        }
        m.update(ip.to_string().as_bytes());
        m.update(b"\n");
        m.update(url.as_bytes());
        m
    }

    /// Sign a context (the gateway's side; tests and the reference).
    pub fn sign(
        key: &[u8],
        claims: &serde_json::Value,
        method: &str,
        ip: IpAddr,
        url: &str,
    ) -> String {
        let payload = URL_SAFE_NO_PAD.encode(claims.to_string());
        let tag = Self::mac(key, &payload, method, ip, url)
            .finalize()
            .into_bytes();
        format!("v1.{payload}.{}", URL_SAFE_NO_PAD.encode(tag))
    }

    /// Verify a header value bound to this request.
    pub fn verify(
        &self,
        value: &[u8],
        method: &str,
        ip: IpAddr,
        url: &str,
        now: Timestamp,
    ) -> Result<Context, &'static str> {
        if value.len() > MAX_VALUE {
            return Err("oversized");
        }
        let value = std::str::from_utf8(value).map_err(|_| "malformed")?;
        let mut parts = value.split('.');
        let (Some("v1"), Some(payload), Some(tag), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err("malformed");
        };
        let tag = URL_SAFE_NO_PAD.decode(tag).map_err(|_| "malformed")?;
        if !self.keys.iter().any(|k| {
            Self::mac(k, payload, method, ip, url)
                .verify_slice(&tag)
                .is_ok()
        }) {
            return Err("signature");
        }
        let bytes = URL_SAFE_NO_PAD.decode(payload).map_err(|_| "malformed")?;
        let ctx: Context = serde_json::from_slice(&bytes).map_err(|_| "malformed")?;
        if !ctx.validate() {
            return Err("malformed");
        }
        if (now.secs() - ctx.iat).abs() > self.max_skew {
            return Err("stale");
        }
        Ok(ctx)
    }
}

// ---- configuration ----------------------------------------------------------

/// Top-level `risk`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RiskCfg {
    pub context_key_env: String,
    #[serde(default)]
    pub context_key_next_env: Option<String>,
    #[serde(default)]
    pub max_skew_secs: Option<u64>,
    #[serde(default)]
    pub memory: MemoryCfg,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryCfg {
    #[serde(default)]
    pub max_sessions: Option<usize>,
    #[serde(default)]
    pub session_ttl_secs: Option<u64>,
    #[serde(default)]
    pub max_users: Option<usize>,
    #[serde(default)]
    pub user_ttl_secs: Option<u64>,
    #[serde(default)]
    pub countries_per_user: Option<usize>,
}

impl RiskCfg {
    pub fn max_skew(&self) -> Duration {
        Duration::from_secs(self.max_skew_secs.unwrap_or(30))
    }
    pub fn validate(&self, errs: &mut Vec<String>, valid_env: impl Fn(&str) -> bool) {
        for (k, v) in [
            ("risk.context_key_env", Some(&self.context_key_env)),
            (
                "risk.context_key_next_env",
                self.context_key_next_env.as_ref(),
            ),
        ] {
            if let Some(v) = v
                && !valid_env(v)
            {
                errs.push(format!("{k} must be an environment variable name"));
            }
        }
        if !(5..=120).contains(&self.max_skew().as_secs()) {
            errs.push("risk.max_skew_secs must be between 5 and 120".into());
        }
        let m = &self.memory;
        let bounded = |v: Option<usize>, lo, hi| v.is_none_or(|v| (lo..=hi).contains(&v));
        let bounded64 = |v: Option<u64>, lo, hi| v.is_none_or(|v| (lo..=hi).contains(&v));
        if !bounded(m.max_sessions, 1, 1_000_000) || !bounded(m.max_users, 1, 1_000_000) {
            errs.push("risk.memory.max_sessions and max_users must be 1 to 1000000".into());
        }
        if !bounded64(m.session_ttl_secs, 60, 30 * 86_400)
            || !bounded64(m.user_ttl_secs, 3600, 365 * 86_400)
        {
            errs.push("risk.memory TTLs: session 60 s to 30 days, user 1 hour to 365 days".into());
        }
        if !bounded(m.countries_per_user, 1, 32) {
            errs.push("risk.memory.countries_per_user must be 1 to 32".into());
        }
    }
    pub fn memory(&self) -> Memory {
        let m = &self.memory;
        Memory::new(MemoryBounds {
            max_sessions: m.max_sessions.unwrap_or(100_000),
            session_ttl: Duration::from_secs(m.session_ttl_secs.unwrap_or(86_400)),
            max_users: m.max_users.unwrap_or(100_000),
            user_ttl: Duration::from_secs(m.user_ttl_secs.unwrap_or(30 * 86_400)),
            countries_per_user: m.countries_per_user.unwrap_or(8),
        })
    }
}

/// `apps[].risk`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppRiskCfg {
    #[serde(default)]
    pub missing: Option<ActionCfg>,
    #[serde(default)]
    pub rules: Vec<RuleCfg>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleCfg {
    #[serde(default)]
    pub path_prefix: Option<String>,
    pub when: When,
    pub then: ActionCfg,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct When {
    #[serde(default)]
    pub level_at_least: Option<Level>,
    #[serde(default)]
    pub country_in: Option<Vec<String>>,
    #[serde(default)]
    pub country_not_in: Option<Vec<String>>,
    #[serde(default)]
    pub zone_in: Option<Vec<String>>,
    #[serde(default)]
    pub outside_zones: Option<Vec<String>>,
    #[serde(default)]
    pub reason_in: Option<Vec<String>>,
    #[serde(default)]
    pub country_changed: Option<bool>,
    #[serde(default)]
    pub asn_changed: Option<bool>,
    #[serde(default)]
    pub new_country: Option<bool>,
}

impl When {
    fn is_empty(&self) -> bool {
        *self == When::default()
    }
    /// Whether the condition reads the session memory.
    pub fn needs_session(&self) -> bool {
        self.country_changed.is_some() || self.asn_changed.is_some() || self.new_country.is_some()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
pub enum ActionCfg {
    Word(String),
    StepUp { step_up: StepUpCfg },
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StepUpCfg {
    pub aal: u8,
    pub max_age_secs: u64,
}

/// What a matching rule does.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    Ignore,
    Deny,
    StepUp { aal: Aal, max_age: Duration },
}

impl Action {
    fn compile(c: &ActionCfg, at: &str, aal3_ok: bool, errs: &mut Vec<String>) -> Action {
        match c {
            ActionCfg::Word(w) if w == "deny" => Action::Deny,
            ActionCfg::Word(w) if w == "ignore" => Action::Ignore,
            ActionCfg::Word(_) => {
                errs.push(format!("{at} must be deny, ignore or {{\"step_up\": ...}}"));
                Action::Deny
            }
            ActionCfg::StepUp { step_up } => {
                let aal = match step_up.aal {
                    2 => Aal::Two,
                    3 if aal3_ok => Aal::Three,
                    3 => {
                        errs.push(format!("{at}.step_up.aal 3 needs webauthn.high_assurance"));
                        Aal::Three
                    }
                    _ => {
                        errs.push(format!("{at}.step_up.aal must be 2 or 3"));
                        Aal::Two
                    }
                };
                if !(30..=86_400).contains(&step_up.max_age_secs) {
                    errs.push(format!("{at}.step_up.max_age_secs must be 30 to 86400"));
                }
                Action::StepUp {
                    aal,
                    max_age: Duration::from_secs(step_up.max_age_secs),
                }
            }
        }
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            Action::Ignore => "ignore",
            Action::Deny => "deny",
            Action::StepUp { .. } => "step_up",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    pub path_prefix: Option<String>,
    pub when: When,
    pub action: Action,
}

/// An application's compiled risk policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    pub missing: Action,
    pub rules: Vec<Rule>,
}

impl AppRiskCfg {
    pub fn compile(&self, at: &str, aal3_ok: bool, errs: &mut Vec<String>) -> Policy {
        let missing = match &self.missing {
            None => Action::Ignore,
            Some(c) => Action::compile(c, &format!("{at}.risk.missing"), aal3_ok, errs),
        };
        if self.rules.len() > 32 {
            errs.push(format!("{at}.risk.rules: at most 32 rules"));
        }
        let rules = self
            .rules
            .iter()
            .enumerate()
            .map(|(k, r)| {
                let rat = format!("{at}.risk.rules[{k}]");
                if r.when.is_empty() {
                    errs.push(format!("{rat}.when needs at least one condition"));
                }
                for list in [
                    &r.when.country_in,
                    &r.when.country_not_in,
                ]
                .into_iter()
                .flatten()
                {
                    if list.is_empty() || list.len() > 256 || !list.iter().all(|c| country_ok(c)) {
                        errs.push(format!("{rat}.when: countries are 1 to 256 ISO 3166-1 alpha-2 codes (upper case)"));
                    }
                }
                for list in [&r.when.zone_in, &r.when.outside_zones, &r.when.reason_in]
                    .into_iter()
                    .flatten()
                {
                    if list.is_empty() || list.len() > 64 || !list.iter().all(|z| token_ok(z, 64)) {
                        errs.push(format!("{rat}.when: zone and reason lists are 1 to 64 ids of [a-z0-9._-]"));
                    }
                }
                if r.path_prefix.as_ref().is_some_and(|p| !p.starts_with('/')) {
                    errs.push(format!("{rat}.path_prefix must start with '/'"));
                }
                Rule {
                    path_prefix: r.path_prefix.clone(),
                    when: r.when.clone(),
                    action: Action::compile(&r.then, &format!("{rat}.then"), aal3_ok, errs),
                }
            })
            .collect();
        Policy { missing, rules }
    }
}

// ---- evaluation -------------------------------------------------------------

/// What the memory knows about this session and user (none: not evaluated).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Seen {
    pub session_country: Option<String>,
    pub session_asn: Option<u32>,
    pub user_countries: Vec<String>,
}

/// The result of one evaluation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outcome {
    /// The index of every matching rule.
    pub matched: Vec<usize>,
    /// `Deny` wins, then step-ups (as extra step-up rules), else `Ignore`.
    pub action: Action,
    /// The rule (index) or `missing` that decided, for events and explain.
    pub deciding: Option<usize>,
    /// Extra step-up rules for the engine.
    pub step_up: Vec<StepUpRule>,
    /// The context was absent and `missing` applied.
    pub missing: bool,
}

fn path_matches(prefix: &Option<String>, path: &str) -> bool {
    crate::policy::step_up::rule_matches(
        &StepUpRule {
            path_prefix: prefix.clone(),
            aal: Aal::One,
            max_age: None,
        },
        path,
    )
}

fn holds(w: &When, c: &Context, seen: Option<&Seen>) -> bool {
    let in_list = |v: &Option<String>, l: &Vec<String>| v.as_ref().is_some_and(|v| l.contains(v));
    let changed = |was: Option<&String>, now: &Option<String>| matches!((was, now), (Some(a), Some(b)) if a != b);
    w.level_at_least.is_none_or(|l| c.level >= l)
        && w.country_in.as_ref().is_none_or(|l| in_list(&c.country, l))
        && w.country_not_in
            .as_ref()
            .is_none_or(|l| c.country.is_some() && !in_list(&c.country, l))
        && w.zone_in
            .as_ref()
            .is_none_or(|l| c.zones.iter().any(|z| l.contains(z)))
        && w.outside_zones
            .as_ref()
            .is_none_or(|l| !c.zones.iter().any(|z| l.contains(z)))
        && w.reason_in.as_ref().is_none_or(|l| l.contains(&c.reason))
        && w.country_changed.is_none_or(|want| {
            want == seen.is_some_and(|s| changed(s.session_country.as_ref(), &c.country))
        })
        && w.asn_changed.is_none_or(|want| {
            want == seen
                .is_some_and(|s| matches!((s.session_asn, c.asn), (Some(a), Some(b)) if a != b))
        })
        && w.new_country.is_none_or(|want| {
            want == seen.is_some_and(|s| {
                !s.user_countries.is_empty()
                    && c.country
                        .as_ref()
                        .is_some_and(|c| c != "XX" && !s.user_countries.contains(c))
            })
        })
}

/// Evaluate `policy` for `input` on `path`. `seen` is `None` before
/// authentication: rules reading the session memory are then skipped.
pub fn evaluate(policy: &Policy, input: &Input, path: &str, seen: Option<&Seen>) -> Outcome {
    let mut out = Outcome {
        matched: Vec::new(),
        action: Action::Ignore,
        deciding: None,
        step_up: Vec::new(),
        missing: false,
    };
    let ctx = match input {
        Input::Valid(c) => c,
        Input::Absent | Input::NotConfigured => {
            out.missing = true;
            out.action = policy.missing.clone();
            if let Action::StepUp { aal, max_age } = &policy.missing {
                out.step_up.push(StepUpRule {
                    path_prefix: None,
                    aal: *aal,
                    max_age: Some(*max_age),
                });
            }
            return out;
        }
        Input::Invalid(_) => {
            out.action = Action::Deny;
            return out;
        }
    };
    for (i, r) in policy.rules.iter().enumerate() {
        if seen.is_none() && r.when.needs_session() {
            continue;
        }
        if !path_matches(&r.path_prefix, path) || !holds(&r.when, ctx, seen) {
            continue;
        }
        out.matched.push(i);
        match &r.action {
            Action::Deny => {
                out.action = Action::Deny;
                out.deciding = Some(i);
            }
            Action::StepUp { aal, max_age } => {
                out.step_up.push(StepUpRule {
                    path_prefix: r.path_prefix.clone(),
                    aal: *aal,
                    max_age: Some(*max_age),
                });
                if out.action != Action::Deny {
                    if out.deciding.is_none() {
                        out.deciding = Some(i);
                    }
                    out.action = r.action.clone();
                }
            }
            Action::Ignore => {}
        }
    }
    out
}

// ---- session memory ---------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct MemoryBounds {
    pub max_sessions: usize,
    pub session_ttl: Duration,
    pub max_users: usize,
    pub user_ttl: Duration,
    pub countries_per_user: usize,
}

impl Default for MemoryBounds {
    fn default() -> Self {
        MemoryBounds {
            max_sessions: 100_000,
            session_ttl: Duration::from_secs(86_400),
            max_users: 100_000,
            user_ttl: Duration::from_secs(30 * 86_400),
            countries_per_user: 8,
        }
    }
}

struct Lru<V> {
    map: HashMap<String, (Timestamp, V)>,
    order: VecDeque<(String, Timestamp)>,
}

impl<V> Lru<V> {
    fn new() -> Self {
        Lru {
            map: HashMap::new(),
            order: VecDeque::new(),
        }
    }
    fn get(&self, k: &str, now: Timestamp, ttl: Duration) -> Option<&V> {
        self.map
            .get(k)
            .filter(|(at, _)| now.since(*at) <= ttl && *at <= now)
            .map(|(_, v)| v)
    }
    fn put(&mut self, k: String, v: V, now: Timestamp, max: usize, ttl: Duration) {
        self.map.insert(k.clone(), (now, v));
        self.order.push_back((k, now));
        // Expired and over-capacity entries go first; stale order slots of
        // keys written again later are skipped.
        while let Some((key, at)) = self.order.front().cloned() {
            let current = self.map.get(&key).map(|(t, _)| *t);
            let stale_slot = current != Some(at);
            if stale_slot {
                self.order.pop_front();
                continue;
            }
            if self.map.len() > max || now.since(at) > ttl {
                self.order.pop_front();
                self.map.remove(&key);
                continue;
            }
            break;
        }
        // Bound the order queue itself (rewrites of the same keys).
        if self.order.len() > max.saturating_mul(4).max(16) {
            let map = &self.map;
            self.order
                .retain(|(k, at)| map.get(k).is_some_and(|(t, _)| t == at));
        }
    }
    fn len(&self) -> usize {
        self.map.len()
    }
}

/// Coarse, bounded memory: per session the last country and ASN of an
/// allowed request, per user the countries seen. No address is kept.
pub struct Memory {
    bounds: MemoryBounds,
    sessions: Mutex<Lru<(Option<String>, Option<u32>)>>,
    users: Mutex<Lru<Vec<String>>>,
}

impl Default for Memory {
    fn default() -> Self {
        Memory::new(MemoryBounds::default())
    }
}

impl std::fmt::Debug for Memory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Memory")
            .field("bounds", &self.bounds)
            .finish()
    }
}

impl Memory {
    pub fn new(bounds: MemoryBounds) -> Memory {
        Memory {
            bounds,
            sessions: Mutex::new(Lru::new()),
            users: Mutex::new(Lru::new()),
        }
    }

    pub fn seen(&self, session: &str, user: &str, now: Timestamp) -> Seen {
        let s = self.sessions.lock().unwrap_or_else(|p| p.into_inner());
        let u = self.users.lock().unwrap_or_else(|p| p.into_inner());
        let (country, asn) = s
            .get(session, now, self.bounds.session_ttl)
            .cloned()
            .unwrap_or((None, None));
        Seen {
            session_country: country,
            session_asn: asn,
            user_countries: u
                .get(user, now, self.bounds.user_ttl)
                .cloned()
                .unwrap_or_default(),
        }
    }

    /// Remember an allowed request's coarse network.
    pub fn observe(&self, session: &str, user: &str, ctx: &Context, now: Timestamp) {
        let country = ctx.country.clone().filter(|c| c != "XX");
        {
            let mut s = self.sessions.lock().unwrap_or_else(|p| p.into_inner());
            s.put(
                session.to_string(),
                (country.clone(), ctx.asn),
                now,
                self.bounds.max_sessions,
                self.bounds.session_ttl,
            );
            crate::telemetry::counters::set(
                MEMORY_ENTRIES,
                &[("store", "sessions")],
                s.len() as i64,
            );
        }
        if let Some(country) = country {
            let mut u = self.users.lock().unwrap_or_else(|p| p.into_inner());
            let mut list = u
                .get(user, now, self.bounds.user_ttl)
                .cloned()
                .unwrap_or_default();
            list.retain(|c| *c != country);
            list.push(country);
            while list.len() > self.bounds.countries_per_user {
                list.remove(0);
            }
            u.put(
                user.to_string(),
                list,
                now,
                self.bounds.max_users,
                self.bounds.user_ttl,
            );
            crate::telemetry::counters::set(MEMORY_ENTRIES, &[("store", "users")], u.len() as i64);
        }
    }
}

#[cfg(test)]
#[path = "risk_tests.rs"]
mod tests;
