//! Explicit service-only relationships over actual independently verified factors.
use super::{
    Composition, PrincipalKind, Subject, VerifiedEvidence,
    runtime::{Error, Profile},
};
use anyhow::{Result, ensure};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
#[derive(Clone, Copy)]
pub(crate) enum Credential<'a> {
    Bearer(&'a str),
    Composite(&'a str),
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub mode: Mode,
    pub timeout_ms: u64,
    pub slots: Vec<Slot>,
    pub identities: Vec<Identity>,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Any,
    All,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Slot {
    pub id: String,
    pub provider: Provider,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Provider {
    ApiKey,
    ApiRelay,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub subject: String,
    pub bindings: Vec<Binding>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub slot: String,
    pub issuer: String,
    pub realm: String,
    pub subject: String,
    pub kind: String,
}
fn id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-.:".contains(&b))
}
impl Config {
    pub(crate) fn validate(&self, authority: &str, p: &Profile) -> Result<()> {
        ensure!(
            (1..=1000).contains(&self.timeout_ms)
                && self.slots.len() == 2
                && (1..=128).contains(&self.identities.len()),
            "invalid composition bounds"
        );
        ensure!(
            !p.api_keys.is_empty()
                && p.api_relay.is_some()
                && p.kubernetes_tokenreview.is_none()
                && p.kubernetes_workload.is_none()
                && !p.session_fallback
                && p.relay_token_prefix.is_none(),
            "composition requires isolated service API key and relay slots"
        );
        ensure!(
            url::Url::parse(&p.api_relay.as_ref().unwrap().url)?.scheme() == "https",
            "composition requires an HTTPS verifier"
        );
        let mut slots = BTreeSet::new();
        let mut providers = Vec::new();
        for slot in &self.slots {
            ensure!(
                id(&slot.id)
                    && slot.id.len() <= 32
                    && slots.insert(slot.id.as_str())
                    && !providers.contains(&slot.provider),
                "duplicate or invalid composition slot/provider"
            );
            providers.push(slot.provider);
        }
        let mut canonical = BTreeSet::new();
        let mut sources = BTreeSet::new();
        for identity in &self.identities {
            ensure!(
                id(&identity.subject)
                    && canonical.insert(&identity.subject)
                    && p.api_keys.iter().any(|key| key.subject == identity.subject)
                    && identity.bindings.len() == self.slots.len(),
                "invalid canonical composition identity"
            );
            let mut used = BTreeSet::new();
            for binding in &identity.bindings {
                let slot = self
                    .slots
                    .iter()
                    .find(|slot| slot.id == binding.slot)
                    .ok_or_else(|| anyhow::anyhow!("unknown composition binding slot"))?;
                ensure!(
                    used.insert(&binding.slot)
                        && binding.kind == "service"
                        && binding.realm == p.realm
                        && !binding.subject.is_empty()
                        && binding.subject.len() <= 128
                        && !binding.subject.chars().any(char::is_control),
                    "invalid composition service relationship"
                );
                let issuer = match slot.provider {
                    Provider::ApiKey => format!("hopae:{authority}"),
                    Provider::ApiRelay => p.api_relay.as_ref().unwrap().issuer.clone(),
                };
                ensure!(
                    binding.issuer == issuer
                        && (slot.provider != Provider::ApiKey
                            || p.api_keys.iter().any(|key| key.subject == binding.subject)),
                    "composition relationship does not match configured provider"
                );
                ensure!(
                    sources.insert((
                        &binding.slot,
                        &binding.issuer,
                        &binding.realm,
                        &binding.subject
                    )),
                    "ambiguous composition relationship"
                );
            }
        }
        Ok(())
    }
}
pub(crate) struct Compiled {
    config: Config,
    issuer: String,
    realm: String,
    service: String,
    relationships: BTreeMap<(String, String, String, String), String>,
    pub(crate) capacity: tokio::sync::Semaphore,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    version: u8,
    credentials: Vec<Entry>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    slot: String,
    credential: String,
}
impl Drop for Entry {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.credential.zeroize();
    }
}
pub(crate) struct Presented {
    pub provider: Provider,
    pub slot: String,
    pub credential: zeroize::Zeroizing<String>,
}
impl Compiled {
    pub(crate) fn new(config: &Config, authority: &str, p: &Profile) -> Self {
        let mut relationships = BTreeMap::new();
        for identity in &config.identities {
            for binding in &identity.bindings {
                relationships.insert(
                    (
                        binding.slot.clone(),
                        binding.issuer.clone(),
                        binding.realm.clone(),
                        binding.subject.clone(),
                    ),
                    identity.subject.clone(),
                );
            }
        }
        Self {
            config: config.clone(),
            issuer: format!("hopae:{authority}"),
            realm: p.realm.clone(),
            service: p.service_id.clone(),
            relationships,
            capacity: tokio::sync::Semaphore::new(32),
        }
    }
    pub(crate) fn timeout_ms(&self) -> u64 {
        self.config.timeout_ms
    }
    pub(crate) fn parse(&self, encoded: &str) -> std::result::Result<Vec<Presented>, Error> {
        if encoded.is_empty() || encoded.len() > 4096 {
            return Err(Error::Invalid);
        }
        let bytes = zeroize::Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(encoded)
                .map_err(|_| Error::Invalid)?,
        );
        let envelope: Envelope = serde_json::from_slice(&bytes).map_err(|_| Error::Invalid)?;
        if envelope.version != 1
            || envelope.credentials.is_empty()
            || envelope.credentials.len() > 2
            || matches!(self.config.mode, Mode::All) && envelope.credentials.len() != 2
        {
            return Err(Error::Invalid);
        }
        let mut used = BTreeSet::new();
        let mut presented = Vec::new();
        for entry in &envelope.credentials {
            let slot = self
                .config
                .slots
                .iter()
                .find(|slot| slot.id == entry.slot)
                .ok_or(Error::Invalid)?;
            if !used.insert(&entry.slot)
                || entry.credential.is_empty()
                || entry.credential.len() > 1024
                || !entry.credential.bytes().all(|b| b.is_ascii_graphic())
            {
                return Err(Error::Invalid);
            }
            presented.push(Presented {
                provider: slot.provider,
                slot: slot.id.clone(),
                credential: zeroize::Zeroizing::new(entry.credential.clone()),
            });
        }
        // Fixed local-before-remote order, independent of caller JSON order.
        presented.sort_by_key(|entry| match entry.provider {
            Provider::ApiKey => 0,
            Provider::ApiRelay => 1,
        });
        Ok(presented)
    }
    pub(crate) fn map(
        &self,
        slot: &str,
        mut evidence: VerifiedEvidence,
    ) -> std::result::Result<VerifiedEvidence, Error> {
        if evidence.subject.kind != PrincipalKind::Service
            || evidence.service.as_deref() != Some(&self.service)
        {
            return Err(Error::Invalid);
        }
        let subject = self
            .relationships
            .get(&(
                slot.to_owned(),
                evidence.subject.issuer.clone(),
                evidence.subject.realm.clone(),
                evidence.subject.subject.clone(),
            ))
            .ok_or(Error::Invalid)?;
        evidence.subject = Subject {
            issuer: self.issuer.clone(),
            realm: self.realm.clone(),
            subject: subject.clone(),
            kind: PrincipalKind::Service,
        };
        evidence.connector = slot.to_owned();
        Ok(evidence)
    }
    pub(crate) fn compose(
        &self,
        evidence: &[VerifiedEvidence],
        now: u64,
        deadline: u64,
    ) -> std::result::Result<VerifiedEvidence, Error> {
        let required = self
            .config
            .slots
            .iter()
            .map(|slot| slot.id.clone())
            .collect::<Vec<_>>();
        let mode = match self.config.mode {
            Mode::Any => Composition::Any,
            Mode::All => Composition::All,
        };
        let composed =
            super::compose_verified(mode, &required, evidence, now).map_err(|_| Error::Invalid)?;
        let expires_at = composed.fresh_until().min(deadline);
        if expires_at <= now {
            return Err(Error::Expired);
        }
        let factors = evidence
            .iter()
            .map(|item| item.connector.as_str())
            .collect::<Vec<_>>()
            .join("+");
        Ok(VerifiedEvidence {
            subject: composed.subject().clone(),
            service: Some(self.service.clone()),
            connector: format!("composition:{factors}"),
            workload: None,
            expires_at,
        })
    }
}

/// Native clock and original suspend-inclusive admission anchor travel together.
/// No numeric constructor or caller header can manufacture a composed deadline.
pub(crate) struct EntryTime<'a> {
    clock: &'a dyn crate::crypto::Clock,
    started: hangang_runtime::time::ElapsedStamp,
    entry_ms: u64,
}
impl<'a> EntryTime<'a> {
    pub(crate) fn capture(clock: &'a dyn crate::crypto::Clock) -> std::result::Result<Self, Error> {
        let started = hangang_runtime::time::ElapsedStamp::now().map_err(|_| Error::Unavailable)?;
        let entry_ms = u64::try_from(clock.now().0)
            .ok()
            .filter(|v| (1..=9_007_199_254_740_991).contains(v))
            .ok_or(Error::Unavailable)?;
        Ok(Self {
            clock,
            started,
            entry_ms,
        })
    }
    pub(crate) fn entry_ms(&self) -> u64 {
        self.entry_ms
    }
    pub(crate) fn current(
        &self,
        floor: &std::sync::atomic::AtomicU64,
        deadline: u64,
    ) -> std::result::Result<u64, Error> {
        // Sample elapsed after the external clock dependency, charging suspend or
        // scheduling gaps during that callback before checking the deadline.
        let wall = u64::try_from(self.clock.now().0)
            .ok()
            .filter(|v| (1..=9_007_199_254_740_991).contains(v))
            .ok_or(Error::Unavailable)?;
        let elapsed = u64::try_from(
            self.started
                .elapsed()
                .map_err(|_| Error::Unavailable)?
                .as_nanos()
                .div_ceil(1_000_000),
        )
        .map_err(|_| Error::Unavailable)?;
        // Round the millisecond wall phase upward before exporting TTLs.
        let now = self
            .entry_ms
            .checked_add(elapsed)
            .and_then(|v| v.checked_add(1))
            .ok_or(Error::Unavailable)?
            .max(wall.checked_add(1).ok_or(Error::Unavailable)?);
        // The shared UTC floor records native wall samples only. Admission's
        // upward rounding is a private upper bound, not a fabricated issuer UTC
        // sample (strict receipt signing must not inherit a future verified_ms).
        let wall_floor = floor
            .fetch_max(wall, std::sync::atomic::Ordering::AcqRel)
            .max(wall);
        let now = now.max(wall_floor.checked_add(1).ok_or(Error::Unavailable)?);
        if now >= deadline {
            return Err(Error::Expired);
        }
        Ok(now)
    }
}
