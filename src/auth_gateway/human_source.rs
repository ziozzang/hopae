//! Actual native Human records. Affine process ownership, not a replay ledger.
//! No signature-only reconstruction and no public numeric capability constructor.
#![allow(dead_code)] // Native Human owners are explicit and default-off.
use crate::{
    auth_gateway::{
        human_request, receipt_authority,
        receipt_config::NativeIssuer,
        receipt_issuer::{Issued, Issuer},
        receipt_keys::Refused,
    },
    verify::human::{Checked, Owner, SourcePublication, SourceTime},
};
use sha2::{Digest as _, Sha256};
use std::{
    cmp::Reverse,
    collections::{BinaryHeap, HashMap, HashSet},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};
const SHARDS: usize = 256;
const SAFE: u64 = 9_007_199_254_740_991;
const CLEANUP: usize = 8;
// Explicit retained context backing-capacity ceiling, checked after creation.
const CONTEXT_RESERVATION: usize = 1024;
fn default_capacity() -> usize {
    131072
}
fn default_bytes() -> u64 {
    256 * 1024 * 1024
}
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Configuration {
    pub source_revision: u64,
    #[serde(default = "default_capacity")]
    pub capacity: usize,
    #[serde(default = "default_bytes")]
    pub retained_bytes: u64,
    pub scopes: Vec<ScopeConfiguration>,
}
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeConfiguration {
    pub service: String,
    pub audience: String,
    pub application: String,
    pub route: String,
    pub route_revision: u64,
    pub destination_sha256: String,
    pub header_revision: u64,
    pub headers: Vec<String>,
    pub reserved_headers: Vec<String>,
    pub maximum_entity_bytes: u64,
}
impl ScopeConfiguration {
    fn compile(&self) -> Result<Arc<human_request::Scope>, Refused> {
        if self.headers.len() > 16
            || self.reserved_headers.len() > 64
            || self
                .headers
                .iter()
                .chain(&self.reserved_headers)
                .any(|s| s.len() > 128)
            || self.destination_sha256.len() != 64
            || !self
                .destination_sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(Refused);
        }
        let mut destination = [0; 32];
        for (i, pair) in self
            .destination_sha256
            .as_bytes()
            .chunks_exact(2)
            .enumerate()
        {
            let digit = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
            destination[i] = (digit(pair[0]) << 4) | digit(pair[1]);
        }
        let headers = self.headers.iter().map(String::as_str).collect::<Vec<_>>();
        let reserved = self
            .reserved_headers
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        human_request::Scope::compile(human_request::Configuration {
            service: &self.service,
            audience: &self.audience,
            application: &self.application,
            route: &self.route,
            route_revision: self.route_revision,
            destination,
            header_revision: self.header_revision,
            headers: &headers,
            reserved_headers: &reserved,
            maximum_entity_bytes: self.maximum_entity_bytes,
        })
        .map_err(|_| Refused)
    }
}
impl Configuration {
    pub(crate) fn validate(&self, issuer: &NativeIssuer) -> Result<(), Refused> {
        if !(1..=SAFE).contains(&self.source_revision)
            || !(1..=1048576).contains(&self.capacity)
            || self.retained_bytes == 0
            || self.retained_bytes > 16 * 1024 * 1024 * 1024
            || usize::try_from(self.retained_bytes).is_err()
            || self.scopes.is_empty()
            || self.scopes.len() > 128
            || issuer.identity_authority_epoch.len() > 40
        {
            return Err(Refused);
        }
        let mut seen = HashSet::new();
        for scope in &self.scopes {
            if !issuer
                .scopes
                .iter()
                .any(|s| s.service == scope.service && s.audience == scope.audience)
                || !seen.insert((
                    &scope.service,
                    &scope.audience,
                    &scope.route,
                    &scope.destination_sha256,
                ))
            {
                return Err(Refused);
            }
            scope.compile()?;
        }
        Ok(())
    }
}
struct Quota {
    count: AtomicUsize,
    bytes: AtomicUsize,
    maximum_count: usize,
    maximum_bytes: usize,
}
struct Reservation {
    quota: Arc<Quota>,
    bytes: usize,
}
impl Quota {
    fn acquire(self: &Arc<Self>, bytes: usize) -> Result<Reservation, Refused> {
        self.count
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                n.checked_add(1).filter(|n| *n <= self.maximum_count)
            })
            .map_err(|_| Refused)?;
        if self
            .bytes
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                n.checked_add(bytes).filter(|n| *n <= self.maximum_bytes)
            })
            .is_err()
        {
            self.count.fetch_sub(1, Ordering::AcqRel);
            return Err(Refused);
        }
        Ok(Reservation {
            quota: self.clone(),
            bytes,
        })
    }
}
impl Drop for Reservation {
    fn drop(&mut self) {
        self.quota.bytes.fetch_sub(self.bytes, Ordering::AcqRel);
        self.quota.count.fetch_sub(1, Ordering::AcqRel);
    }
}
#[derive(Default)]
struct Shard {
    records: HashMap<[u8; 32], Arc<Record>>,
    expiry: BinaryHeap<Reverse<(u64, [u8; 32])>>,
}
impl Shard {
    fn can_insert(&self, key: &[u8; 32], capacity: usize) -> bool {
        self.records.len() < capacity
            && self.expiry.len() < capacity
            && !self.records.contains_key(key)
    }
}
/// Only actual native Checked and validated fixed-scope Binding enter this owner.
pub(crate) struct Source {
    active: AtomicBool,
    publication: SourcePublication,
    owner: Arc<Owner>,
    issuer: Arc<Issuer>,
    verifier: receipt_authority::Verifier,
    keys: Arc<receipt_authority::Current>,
    revision: u64,
    scopes: Vec<Arc<human_request::Scope>>,
    quota: Arc<Quota>,
    shards: [Mutex<Shard>; SHARDS],
    cursor: AtomicUsize,
    shard_capacity: usize,
    #[cfg(test)]
    final_publication_gate: Option<(Arc<AtomicBool>, Arc<AtomicBool>, AtomicBool)>,
}
pub(crate) struct Record {
    checked: Checked,
    binding: human_request::Binding,
    issued: Issued,
    keys: Arc<receipt_authority::Current>,
    expires: u64,
    domain: String,
    _reservation: Reservation,
}
/// Issuer-affine actual local record handle, not yet paired projection admission.
/// Only Source lookup can create it; signature/numeric input alone is insufficient.
pub(crate) struct RetainedRecord {
    source: Arc<Source>,
    record: Arc<Record>,
}
impl RetainedRecord {
    pub(crate) fn scope_sha256(&self) -> [u8; 32] {
        self.record.binding.scope_sha256()
    }
    pub(crate) fn application(&self) -> &str {
        self.record.binding.application()
    }
    pub(crate) fn route(&self) -> &str {
        self.record.binding.route()
    }
    pub(crate) fn context(&self) -> super::receipt_binding::Context<'_> {
        self.record.issued.context()
    }
    pub(crate) fn receipt(&self) -> &[u8] {
        self.record.issued.bytes()
    }
    pub(crate) fn require_publication(&self) -> Result<(), Refused> {
        self.source
            .publication
            .require_current()
            .map_err(|_| Refused)?;
        if !self.source.publication.accepts(&self.record.checked)
            || !Arc::ptr_eq(&self.source.keys, &self.record.keys)
            || !self.record.keys.current()
        {
            return Err(Refused);
        }
        self.record
            .checked
            .require_pure_current()
            .map_err(|_| Refused)?;
        if !self.source.active.load(Ordering::Acquire) {
            return Err(Refused);
        }
        Ok(())
    }
    pub(crate) async fn require_current(&self) -> Result<(), Refused> {
        self.require_publication()?;
        self.record
            .checked
            .require_current_retained()
            .await
            .map_err(|_| Refused)?;
        self.require_publication()
    }
    pub(crate) fn prepare_current(
        &self,
    ) -> Result<crate::verify::human::ProjectionCurrent, Refused> {
        self.require_publication()?;
        let prepared = self
            .record
            .checked
            .prepare_projection_current()
            .map_err(|_| Refused)?;
        self.require_publication()?;
        Ok(prepared)
    }
    pub(crate) fn current_on(
        &self,
        prepared: &crate::verify::human::ProjectionCurrent,
        ledger: &crate::store::sqlite::human_owner::LedgerSnapshot<'_>,
    ) -> Result<(), Refused> {
        self.require_publication()?;
        prepared
            .current_on(&self.record.checked, ledger)
            .map_err(|_| Refused)?;
        self.require_publication()
    }
    pub(crate) async fn observe(
        &self,
        constraint: &(dyn Fn(&SourceTime) -> Result<u64, Refused> + Send + Sync),
    ) -> Result<Observation, Refused> {
        let context = self.record.issued.context();
        self.source
            .observe_with_final(
                &context,
                self.record.issued.bytes(),
                &self.record.binding.sha256(),
                constraint,
            )
            .await
    }
}
pub(crate) struct Observation {
    pub owner_now_ms: u64,
    pub remaining_ms: u32,
    pub receipt_sha256: [u8; 32],
    pub scope_sha256: [u8; 32],
    pub clock_domain: String,
    pub source_revision: u64,
    pub application_generation: u64,
    pub key_registry_revision: u64,
}
impl Source {
    /// Resolve explicit startup metadata only; this does not create a proof.
    pub(crate) fn projection_fingerprints(
        &self,
        service: &str,
        audience: &str,
        application: &str,
        route: &str,
    ) -> Result<Vec<[u8; 32]>, Refused> {
        self.publication.require_current().map_err(|_| Refused)?;
        if !self.active.load(Ordering::Acquire) || !self.keys.current() {
            return Err(Refused);
        }
        let fingerprints = self
            .scopes
            .iter()
            .filter_map(|scope| scope.projection_fingerprint(service, audience, application, route))
            .collect::<Vec<_>>();
        if fingerprints.is_empty() {
            return Err(Refused);
        }
        Ok(fingerprints)
    }
    pub(crate) fn belongs_to(&self, owner: &Arc<Owner>) -> bool {
        Arc::ptr_eq(&self.owner, owner)
    }

    pub(crate) fn new(
        owner: Arc<Owner>,
        issuer: Arc<Issuer>,
        verifier: receipt_authority::Verifier,
        native: &NativeIssuer,
    ) -> Result<Self, Refused> {
        let configuration = native.human_receipts.as_ref().ok_or(Refused)?;
        configuration.validate(native)?;
        if !issuer.matches_human_configuration(native) {
            return Err(Refused);
        }
        let scopes = configuration
            .scopes
            .iter()
            .map(ScopeConfiguration::compile)
            .collect::<Result<Vec<_>, _>>()?;
        let keys = Arc::new(verifier.capture()?);
        let publication = owner.source_publication().map_err(|_| Refused)?;
        let scope_vector = scopes
            .capacity()
            .checked_mul(std::mem::size_of::<Arc<human_request::Scope>>())
            .ok_or(Refused)?;
        let base = publication
            .retained_bytes()
            .map_err(|_| Refused)?
            .checked_add(scope_vector)
            .ok_or(Refused)?;
        let base = scopes.iter().try_fold(base, |n, scope| {
            n.checked_add(scope.retained_bytes().map_err(|_| Refused)?)
                .and_then(|n| {
                    n.checked_add(
                        2 * std::mem::size_of::<usize>()
                            + std::mem::align_of::<human_request::Scope>(),
                    )
                })
                .ok_or(Refused)
        })?;
        let maximum_bytes = usize::try_from(configuration.retained_bytes).map_err(|_| Refused)?;
        if base >= maximum_bytes {
            return Err(Refused);
        }
        Ok(Self {
            publication,
            keys,
            active: AtomicBool::new(true),
            owner,
            issuer,
            verifier,
            revision: configuration.source_revision,
            scopes,
            quota: Arc::new(Quota {
                count: AtomicUsize::new(0),
                bytes: AtomicUsize::new(base),
                maximum_count: configuration.capacity,
                maximum_bytes,
            }),
            shards: std::array::from_fn(|_| Mutex::new(Shard::default())),
            cursor: AtomicUsize::new(0),
            shard_capacity: configuration.capacity.div_ceil(SHARDS) * 2,
            #[cfg(test)]
            final_publication_gate: None,
        })
    }
    pub(crate) fn retire(&self) {
        self.active.store(false, Ordering::Release);
    }
    pub(crate) fn validate(
        &self,
        service: &str,
        audience: &str,
        request: &hopae_grpc::v1::HumanFinalRequest,
    ) -> Result<human_request::Binding, Refused> {
        let mut matches = self
            .scopes
            .iter()
            .filter_map(|s| s.validate(service, audience, request).ok());
        let binding = matches.next().ok_or(Refused)?;
        if matches.next().is_some() {
            return Err(Refused);
        }
        Ok(binding)
    }
    fn cleanup(&self, index: usize, now: u64) -> Result<(), Refused> {
        let mut removed: [Option<Arc<Record>>; CLEANUP] = std::array::from_fn(|_| None);
        {
            let mut shard = self.shards[index].lock().map_err(|_| Refused)?;
            for slot in &mut removed {
                let Some(Reverse((expiry, key))) = shard.expiry.peek().copied() else {
                    break;
                };
                if expiry > now {
                    break;
                }
                shard.expiry.pop();
                *slot = shard.records.remove(&key);
            }
        }
        drop(removed);
        Ok(())
    }
    fn reserve(&self, bytes: usize, now: u64) -> Result<Reservation, Refused> {
        let cursor = self.cursor.fetch_add(1, Ordering::Relaxed) % SHARDS;
        self.cleanup(cursor, now)?;
        if let Ok(reservation) = self.quota.acquire(bytes) {
            return Ok(reservation);
        }
        // Pressure-only bounded sweep. Never evict live evidence or renew it.
        for offset in 1..SHARDS {
            self.cleanup((cursor + offset) % SHARDS, now)?;
            if let Ok(reservation) = self.quota.acquire(bytes) {
                return Ok(reservation);
            }
        }
        Err(Refused)
    }
    pub(crate) async fn issue(
        &self,
        checked: Checked,
        binding: human_request::Binding,
    ) -> Result<Arc<Record>, Refused> {
        if !self.active.load(Ordering::Acquire)
            || !self.publication.accepts(&checked)
            || !checked.belongs_to(&self.owner)
            || !self.scopes.iter().any(|scope| binding.belongs_to(scope))
        {
            return Err(Refused);
        }
        checked
            .require_current_retained()
            .await
            .map_err(|_| Refused)?;
        let stamp = checked.source_time().map_err(|_| Refused)?;
        // Reserve before signing/context/record allocations. The small fixed
        // context allowance covers all bounded issuer/subject/epoch strings.
        let bytes = checked
            .retained_bytes()
            .map_err(|_| Refused)?
            .checked_add(binding.retained_bytes().map_err(|_| Refused)?)
            .and_then(|n| {
                n.checked_add(
                    std::mem::size_of::<Record>()
                        + CONTEXT_RESERVATION
                        + 2 * std::mem::size_of::<usize>()
                        + std::mem::align_of::<Record>(),
                )
            })
            .ok_or(Refused)?;
        let reservation = self.reserve(bytes, stamp.owner_now_ms)?;
        let keys = self.keys.clone();
        if !keys.current() {
            return Err(Refused);
        }
        let issued = self
            .issuer
            .issue_native_human(&checked, &binding, self.revision)
            .await?;
        let signature =
            self.verifier
                .verify_observed_signature(&issued.context(), None, issued.bytes())?;
        if signature.revision() != keys.revision() || !keys.current() {
            return Err(Refused);
        }
        let expires = signature.evidence().claims().expires_ms;
        let domain = stamp
            .clock_domain
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        if issued
            .human_owned_heap_bytes()?
            .checked_add(domain.capacity())
            .ok_or(Refused)?
            > CONTEXT_RESERVATION
        {
            return Err(Refused);
        }
        checked
            .require_current_retained()
            .await
            .map_err(|_| Refused)?;
        let now = checked.source_time().map_err(|_| Refused)?;
        if now.clock_domain != stamp.clock_domain || now.owner_now_ms >= expires || !keys.current()
        {
            return Err(Refused);
        }
        let record = Arc::new(Record {
            checked,
            binding,
            issued,
            keys,
            expires,
            domain,
            _reservation: reservation,
        });
        let hash: [u8; 32] = Sha256::digest(record.issued.bytes()).into();
        let index = hash[0] as usize;
        self.cleanup(index, now.owner_now_ms)?;
        {
            let mut shard = self.shards[index].lock().map_err(|_| Refused)?;
            if !shard.can_insert(&hash, self.shard_capacity) {
                return Err(Refused);
            }
            shard.records.try_reserve(1).map_err(|_| Refused)?;
            shard.expiry.try_reserve(1).map_err(|_| Refused)?;
            shard.records.insert(hash, record.clone());
            shard.expiry.push(Reverse((expires, hash)));
        }
        // No external callback/await remains under the shard lock.
        let final_check = (|| {
            record
                .checked
                .require_publication_current()
                .map_err(|_| Refused)?;
            let now = record.checked.source_time().map_err(|_| Refused)?;
            self.publication.require_current().map_err(|_| Refused)?;
            if now.owner_now_ms >= record.expires
                || !record.keys.current()
                || !self.active.load(Ordering::Acquire)
            {
                return Err(Refused);
            }
            Ok(())
        })();
        if final_check.is_err() {
            self.remove(&hash, &record)?;
            return Err(Refused);
        }
        Ok(record)
    }
    fn remove(&self, key: &[u8; 32], expected: &Arc<Record>) -> Result<(), Refused> {
        let removed = {
            let mut shard = self.shards[key[0] as usize].lock().map_err(|_| Refused)?;
            if shard
                .records
                .get(key)
                .is_some_and(|r| Arc::ptr_eq(r, expected))
            {
                shard.records.remove(key)
            } else {
                None
            }
        };
        drop(removed);
        Ok(())
    }
    fn lookup_record(
        &self,
        context: &super::receipt_binding::Context<'_>,
        receipt: &[u8],
        request_sha256: &[u8; 32],
    ) -> Result<([u8; 32], Arc<Record>, receipt_authority::ObservedChecked), Refused> {
        if !self.active.load(Ordering::Acquire)
            || receipt.len() != super::receipt::LENGTH
            || context.request_sha256 != *request_sha256
        {
            return Err(Refused);
        }
        let signature = self
            .verifier
            .verify_observed_signature(context, None, receipt)?;
        let hash: [u8; 32] = Sha256::digest(receipt).into();
        let record = self.shards[hash[0] as usize]
            .lock()
            .map_err(|_| Refused)?
            .records
            .get(&hash)
            .cloned()
            .ok_or(Refused)?;
        if record.issued.bytes().as_slice() != receipt
            || record.binding.sha256() != *request_sha256
            || super::receipt_binding::digest(&record.issued.context(), None)
                .map_err(|_| Refused)?
                != super::receipt_binding::digest(context, None).map_err(|_| Refused)?
            || signature.revision() != record.keys.revision()
            || !signature.current()
            || !record.keys.current()
        {
            return Err(Refused);
        }
        if !self.publication.accepts(&record.checked) {
            return Err(Refused);
        }
        self.publication.require_current().map_err(|_| Refused)?;
        Ok((hash, record, signature))
    }
    pub(crate) fn retain(
        self: &Arc<Self>,
        context: &super::receipt_binding::Context<'_>,
        receipt: &[u8],
        request_sha256: &[u8; 32],
    ) -> Result<RetainedRecord, Refused> {
        let (_, record, _) = self.lookup_record(context, receipt, request_sha256)?;
        Ok(RetainedRecord {
            source: self.clone(),
            record,
        })
    }
    pub(crate) async fn observe(
        &self,
        context: &super::receipt_binding::Context<'_>,
        receipt: &[u8],
        request_sha256: &[u8; 32],
    ) -> Result<Observation, Refused> {
        self.observe_with_final(context, receipt, request_sha256, &|_| Ok(u64::MAX))
            .await
    }
    pub(crate) async fn observe_with_final(
        &self,
        context: &super::receipt_binding::Context<'_>,
        receipt: &[u8],
        request_sha256: &[u8; 32],
        // Must be a known callback-free owner/caller fence. Counted or external
        // callbacks run before this method's durable current read, never here.
        // The borrowed native sample is the final sample. A numeric return can
        // only shorten admission; it cannot extend the retained proof/record.
        final_check: &(dyn Fn(&SourceTime) -> Result<u64, Refused> + Send + Sync),
    ) -> Result<Observation, Refused> {
        let (hash, record, signature) = self.lookup_record(context, receipt, request_sha256)?;
        record
            .checked
            .require_current_retained()
            .await
            .map_err(|_| Refused)?;
        let mut observation = Observation {
            owner_now_ms: 0,
            remaining_ms: 0,
            receipt_sha256: hash,
            scope_sha256: record.binding.scope_sha256(),
            clock_domain: record.domain.clone(),
            source_revision: self.revision,
            application_generation: hopae_grpc::human_epoch::decode(
                context.identity_authority_epoch,
            )
            .map_err(|_| Refused)?
            .application_generation,
            key_registry_revision: signature.revision(),
        };
        record
            .checked
            .require_publication_current()
            .map_err(|_| Refused)?;
        let now = record.checked.source_time().map_err(|_| Refused)?;
        let constraint = final_check(&now)?;
        let remaining = record
            .expires
            .min(now.expires_ms)
            .checked_sub(now.owner_now_ms)
            .and_then(|n| n.checked_sub(1))
            .map(|n| n.min(constraint))
            .filter(|n| *n > 0 && *n <= 1000)
            .ok_or(Refused)?;
        observation.owner_now_ms = now.owner_now_ms;
        observation.remaining_ms = u32::try_from(remaining).map_err(|_| Refused)?;
        self.publication.require_current().map_err(|_| Refused)?;
        #[cfg(test)]
        if let Some((entered, release, claimed)) = &self.final_publication_gate
            && !claimed.swap(true, Ordering::AcqRel)
        {
            entered.store(true, Ordering::Release);
            while !release.load(Ordering::Acquire) {
                std::thread::yield_now();
            }
        }
        if !signature.current() || !record.keys.current() {
            return Err(Refused);
        }
        record.checked.require_pure_current().map_err(|_| Refused)?;
        if !self.active.load(Ordering::Acquire) {
            return Err(Refused);
        }
        Ok(observation)
    }
}
impl Record {
    pub(crate) fn issued(&self) -> &Issued {
        &self.issued
    }
}

#[cfg(test)]
impl Source {
    pub(crate) fn final_publication_gate_for_test(
        &mut self,
        entered: Arc<AtomicBool>,
        release: Arc<AtomicBool>,
    ) {
        self.final_publication_gate = Some((entered, release, AtomicBool::new(false)));
    }
    pub(crate) fn usage_for_test(&self) -> (usize, usize) {
        (
            self.quota.count.load(Ordering::Acquire),
            self.quota.bytes.load(Ordering::Acquire),
        )
    }
    pub(crate) fn forget_for_test(&self, record: &Arc<Record>) -> Result<(), Refused> {
        self.remove(&Sha256::digest(record.issued.bytes()).into(), record)
    }
}
#[cfg(test)]
mod quota_tests {
    use super::*;
    #[test]
    fn native_human_source_expiry_index_cap_holds_when_record_index_is_empty() {
        let mut shard = Shard::default();
        assert!(shard.can_insert(&[3; 32], 2));
        shard.expiry.push(Reverse((100, [1; 32])));
        shard.expiry.push(Reverse((100, [2; 32])));
        assert!(shard.records.is_empty());
        assert!(!shard.can_insert(&[3; 32], 2));
        shard.expiry.pop();
        assert!(shard.can_insert(&[3; 32], 2));
    }
    #[test]
    fn native_human_quota_exact_bound_rollback_and_held_reservation() {
        let quota = Arc::new(Quota {
            count: AtomicUsize::new(0),
            bytes: AtomicUsize::new(13),
            maximum_count: 2,
            maximum_bytes: 33,
        });
        let one = quota.acquire(10).unwrap();
        let two = quota.acquire(10).unwrap();
        assert!(quota.acquire(0).is_err());
        assert_eq!(quota.count.load(Ordering::Acquire), 2);
        drop(two);
        assert!(quota.acquire(11).is_err());
        assert_eq!(quota.count.load(Ordering::Acquire), 1);
        assert_eq!(quota.bytes.load(Ordering::Acquire), 23);
        drop(one);
        assert_eq!(quota.count.load(Ordering::Acquire), 0);
        assert_eq!(quota.bytes.load(Ordering::Acquire), 13);
        assert!(quota.acquire(usize::MAX).is_err());
        assert_eq!(quota.count.load(Ordering::Acquire), 0);
    }
}
