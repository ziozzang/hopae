//! Native Workload original-age records. Not a replay ledger or permission grant.
use super::{authority, receipt_authority, receipt_issuer::Scope, receipt_keys::Refused};
use crate::{crypto::Clock, policy::types::ConfigSnapshot};
use hangang_runtime::time::ReceiverClock;
use std::{
    cmp::Reverse,
    collections::{BinaryHeap, HashMap, HashSet},
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
const SHARDS: usize = 256;
const MAXIMUM: u64 = 9_007_199_254_740_991;
fn default_capacity() -> usize {
    131072
}
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Configuration {
    pub scopes: Vec<Scope>,
    #[serde(default = "default_capacity")]
    pub capacity: usize,
}
impl Configuration {
    pub(crate) fn validate(&self, authority: &str, declared: &[Scope]) -> Result<(), Refused> {
        if authority.len() > 40
            || !(1..=1048576).contains(&self.capacity)
            || self.scopes.is_empty()
            || self.scopes.len() > 128
        {
            return Err(Refused);
        }
        let mut seen = HashSet::new();
        for s in &self.scopes {
            if !declared
                .iter()
                .any(|d| d.service == s.service && d.audience == s.audience)
                || !seen.insert((&s.service, &s.audience))
            {
                return Err(Refused);
            }
        }
        Ok(())
    }
}
#[derive(Default)]
struct Shard {
    records: HashMap<[u8; 32], Arc<Record>>,
    expiry: BinaryHeap<Reverse<(u64, [u8; 32])>>,
}
pub(crate) struct Owner {
    clock: ReceiverClock,
    domain: String,
    failed: AtomicBool,
    floor: AtomicU64,
    cursor: AtomicUsize,
    capacity: Arc<Semaphore>,
    shards: [Mutex<Shard>; SHARDS],
    expiry_hints: [AtomicU64; SHARDS],
    scopes: HashSet<(String, String)>,
    shard_capacity: usize,
    #[cfg(test)]
    read: Option<Arc<dyn Fn() -> Result<u64, Refused> + Send + Sync>>,
}
impl Owner {
    pub(crate) fn new(
        configuration: Configuration,
        generation: [u8; 16],
    ) -> Result<Arc<Self>, Refused> {
        Ok(Arc::new(Self {
            clock: ReceiverClock::new(generation).map_err(|_| Refused)?,
            domain: generation.iter().map(|b| format!("{b:02x}")).collect(),
            failed: AtomicBool::new(false),
            floor: AtomicU64::new(0),
            cursor: AtomicUsize::new(0),
            capacity: Arc::new(Semaphore::new(configuration.capacity)),
            shards: std::array::from_fn(|_| Mutex::new(Shard::default())),
            expiry_hints: std::array::from_fn(|_| AtomicU64::new(MAXIMUM)),
            shard_capacity: configuration.capacity.div_ceil(SHARDS) * 2,
            scopes: configuration
                .scopes
                .into_iter()
                .map(|s| (s.service, s.audience))
                .collect(),
            #[cfg(test)]
            read: None,
        }))
    }
    pub(crate) fn domain(&self) -> &str {
        &self.domain
    }
    pub(crate) fn permits(&self, service: &str, audience: &str) -> bool {
        self.scopes
            .iter()
            .any(|(s, a)| s == service && a == audience)
    }
    fn fail(&self) -> Refused {
        self.failed.store(true, Ordering::Release);
        self.clock.retire();
        Refused
    }
    pub(crate) fn ticks(&self) -> Result<u64, Refused> {
        if self.failed.load(Ordering::Acquire) {
            return Err(Refused);
        }
        // Compare against the floor published BEFORE this backend read. A delayed
        // earlier reader must not mistake a later reader's completion for reversal.
        let floor = self.floor.load(Ordering::Acquire);
        #[cfg(test)]
        let sample = self.read.as_ref().map_or_else(
            || self.clock.sample_ticks().map_err(|_| Refused),
            |read| read(),
        );
        #[cfg(not(test))]
        let sample = self.clock.sample_ticks().map_err(|_| Refused);
        let now = sample.map_err(|_| self.fail())?;
        if !(1..=MAXIMUM).contains(&now) || now < floor {
            return Err(self.fail());
        }
        if now > floor {
            self.floor.fetch_max(now, Ordering::AcqRel);
        }
        if self.failed.load(Ordering::Acquire) {
            return Err(Refused);
        }
        Ok(now)
    }
    fn cleanup(&self, now: u64) -> Result<(), Refused> {
        let index = self.cursor.fetch_add(1, Ordering::Relaxed) % SHARDS;
        self.cleanup_index(index, now)
    }
    fn cleanup_index(&self, index: usize, now: u64) -> Result<(), Refused> {
        if self.expiry_hints[index].load(Ordering::Acquire) > now {
            return Ok(());
        }
        let mut shard = self.shards[index].lock().map_err(|_| self.fail())?;
        for _ in 0..8 {
            let Some(Reverse((expiry, key))) = shard.expiry.peek().copied() else {
                break;
            };
            if now < expiry {
                break;
            }
            shard.expiry.pop();
            // No provider/sign/clock/current-owner callback runs under this lock.
            shard.records.remove(&key);
        }
        self.expiry_hints[index].store(
            shard.expiry.peek().map_or(MAXIMUM, |entry| entry.0.0),
            Ordering::Release,
        );
        Ok(())
    }
    fn reserve(&self, now: u64) -> Result<OwnedSemaphorePermit, Refused> {
        if let Ok(permit) = self.capacity.clone().try_acquire_owned() {
            return Ok(permit);
        }
        // Pressure-only bounded sweep of atomic HEAD hints. No whole-map scan;
        // unexpired shards need no lock, and we stop as soon as a permit is free.
        for index in 0..SHARDS {
            self.cleanup_index(index, now)?;
            if let Ok(permit) = self.capacity.clone().try_acquire_owned() {
                return Ok(permit);
            }
        }
        Err(Refused)
    }
    pub(crate) fn begin(self: &Arc<Self>, clock: &dyn Clock) -> Result<Arc<Attempt>, Refused> {
        let entry = self.ticks()?;
        self.cleanup(entry)?;
        let permit = self.reserve(entry)?;
        let wall = u64::try_from(clock.now().0)
            .ok()
            .filter(|v| (1..=MAXIMUM).contains(v))
            .ok_or(Refused)?;
        let expires = entry
            .checked_add(1000)
            .filter(|v| *v <= MAXIMUM)
            .ok_or(Refused)?;
        if self.ticks()? >= expires {
            return Err(Refused);
        }
        Ok(Arc::new(Attempt {
            owner: Arc::downgrade(self),
            entry,
            wall,
            expires: AtomicU64::new(expires),
            retired: AtomicBool::new(false),
            published: AtomicBool::new(false),
            _capacity: permit,
        }))
    }
    pub(crate) fn insert(&self, record: Arc<Record>) -> Result<(), Refused> {
        // One reserved original attempt can publish at most one record. Even an
        // internal retry cannot multiply records under a single capacity permit.
        if record.attempt.published.swap(true, Ordering::AcqRel) {
            return Err(record.attempt.retire());
        }
        let key = record.hash;
        let mut shard = self.shards[usize::from(key[0])]
            .lock()
            .map_err(|_| self.fail())?;
        if shard.records.len() >= self.shard_capacity || shard.records.contains_key(&key) {
            return Err(Refused);
        }
        shard.expiry.push(Reverse((record.attempt.expiry(), key)));
        shard.records.insert(key, record);
        self.expiry_hints[usize::from(key[0])].store(
            shard.expiry.peek().map_or(MAXIMUM, |entry| entry.0.0),
            Ordering::Release,
        );
        Ok(())
    }
    pub(crate) fn lookup(&self, hash: &[u8; 32]) -> Result<Arc<Record>, Refused> {
        let record = self.shards[usize::from(hash[0])]
            .lock()
            .map_err(|_| self.fail())?
            .records
            .get(hash)
            .cloned();
        record.ok_or(Refused) // Missing/evicted/restarted record is never reconstructed.
    }
}
/// Private transport extension. Reserved before provider work; cancellation
/// drops its capacity unless an actually published receipt record retains it.
pub(crate) struct Attempt {
    owner: Weak<Owner>,
    entry: u64,
    wall: u64,
    expires: AtomicU64,
    retired: AtomicBool,
    published: AtomicBool,
    _capacity: OwnedSemaphorePermit,
}
impl Attempt {
    pub(crate) fn owner(&self) -> Result<Arc<Owner>, Refused> {
        self.owner.upgrade().ok_or_else(|| self.retire())
    }
    pub(crate) fn expiry(&self) -> u64 {
        self.expires.load(Ordering::Acquire)
    }
    pub(crate) fn retire(&self) -> Refused {
        self.retired.store(true, Ordering::Release);
        Refused
    }
    pub(crate) fn restrict(&self, native_expiry: u64) -> Result<(), Refused> {
        let duration = native_expiry
            .checked_sub(self.wall)
            .filter(|v| *v > 0)
            .ok_or_else(|| self.retire())?
            .min(1000)
            .checked_sub(1)
            .filter(|v| *v > 0)
            .ok_or_else(|| self.retire())?;
        let bound = self
            .entry
            .checked_add(duration)
            .ok_or_else(|| self.retire())?;
        self.expires.fetch_min(bound, Ordering::AcqRel);
        Ok(())
    }
    pub(crate) fn now(&self, clock: &dyn Clock) -> Result<u64, Refused> {
        if self.retired.load(Ordering::Acquire) {
            return Err(Refused);
        }
        let wall = u64::try_from(clock.now().0).map_err(|_| self.retire())?;
        let now = self.owner()?.ticks().map_err(|_| self.retire())?;
        let utc_bound = self
            .wall
            .checked_add(self.expiry() - self.entry)
            .ok_or_else(|| self.retire())?;
        if wall < self.wall
            || wall >= utc_bound
            || now.checked_add(1).is_none_or(|now| now >= self.expiry())
        {
            return Err(self.retire());
        }
        if self.retired.load(Ordering::Acquire) {
            return Err(Refused);
        }
        Ok(now)
    }
}
pub(crate) struct Record {
    pub(crate) hash: [u8; 32],
    pub(crate) binding: [u8; 32],
    pub(crate) attempt: Arc<Attempt>,
    pub(crate) profile: Arc<authority::Snapshot>,
    pub(crate) application: Arc<ConfigSnapshot>,
    pub(crate) profiles: Arc<arc_swap::ArcSwap<authority::Snapshot>>,
    pub(crate) applications: Arc<arc_swap::ArcSwap<ConfigSnapshot>>,
    pub(crate) keys: Arc<receipt_authority::ObservedChecked>,
}
impl Record {
    pub(crate) fn current(&self, clock: &dyn Clock) -> Result<u64, Refused> {
        let now = self.attempt.now(clock)?;
        let profile = self.profiles.load_full();
        let claims = self.keys.evidence().claims();
        if now < claims.issued_ms
            || now >= claims.expires_ms
            || !profile.available()
            || !Arc::ptr_eq(&profile, &self.profile)
            || !Arc::ptr_eq(&self.applications.load_full(), &self.application)
            || !self.keys.current()
        {
            return Err(self.attempt.retire());
        }
        Ok(now)
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::crypto::{SystemClock, Timestamp};
    struct Fixed;
    impl Clock for Fixed {
        fn now(&self) -> Timestamp {
            Timestamp(10000)
        }
    }
    fn controlled(
        capacity: usize,
        read: Arc<dyn Fn() -> Result<u64, Refused> + Send + Sync>,
    ) -> Arc<Owner> {
        let mut owner = Owner::new(
            Configuration {
                scopes: vec![Scope {
                    service: "orders".into(),
                    audience: "orders-api".into(),
                }],
                capacity,
            },
            [7; 16],
        )
        .unwrap();
        Arc::get_mut(&mut owner).unwrap().read = Some(read);
        owner
    }
    #[test]
    fn source_deadline_is_original_and_clock_failure_never_recovers() {
        let ticks = Arc::new(AtomicU64::new(100));
        let read = ticks.clone();
        let owner = controlled(1, Arc::new(move || Ok(read.load(Ordering::Acquire))));
        let attempt = owner.begin(&Fixed).unwrap();
        ticks.store(900, Ordering::Release); // 800ms provider work already charged
        attempt.restrict(11000).unwrap();
        assert_eq!(attempt.expiry(), 1099);
        assert_eq!(attempt.now(&Fixed).unwrap(), 900);
        attempt.restrict(13000).unwrap(); // cannot renew original budget
        assert_eq!(attempt.expiry(), 1099);
        ticks.store(1100, Ordering::Release);
        assert!(attempt.now(&Fixed).is_err());
        ticks.store(1200, Ordering::Release);
        assert!(attempt.now(&Fixed).is_err());
        drop(attempt);
        assert!(owner.begin(&Fixed).is_ok());
        let calls = AtomicUsize::new(0);
        let owner = controlled(
            1,
            Arc::new(move || {
                if calls.fetch_add(1, Ordering::Relaxed) == 0 {
                    Err(Refused)
                } else {
                    Ok(200)
                }
            }),
        );
        assert!(owner.begin(&Fixed).is_err());
        assert!(owner.begin(&Fixed).is_err());
    }
    #[test]
    fn ordered_reads_with_reversed_completion_do_not_falsely_retire_domain() {
        let (entered, wait) = std::sync::mpsc::channel();
        let (release, resume) = std::sync::mpsc::channel();
        let resume = Mutex::new(resume);
        let count = AtomicUsize::new(0);
        let owner = controlled(
            1,
            Arc::new(move || match count.fetch_add(1, Ordering::SeqCst) {
                0 => {
                    entered.send(()).unwrap();
                    resume.lock().unwrap().recv().unwrap();
                    Ok(100)
                }
                1 => Ok(101),
                2 => Ok(99),
                _ => Ok(200),
            }),
        );
        let slow = owner.clone();
        let task = std::thread::spawn(move || slow.ticks());
        wait.recv().unwrap();
        assert_eq!(owner.ticks().unwrap(), 101);
        release.send(()).unwrap();
        assert_eq!(task.join().unwrap().unwrap(), 100);
        assert!(!owner.failed.load(Ordering::Acquire));
        assert!(owner.ticks().is_err()); // real read below already-published floor
        assert!(owner.ticks().is_err());
    }
    #[test]
    fn canceled_unpublished_work_releases_capacity_and_missing_records_refuse() {
        let owner = controlled(1, Arc::new(|| Ok(100)));
        let attempt = owner.begin(&Fixed).unwrap();
        assert!(owner.begin(&Fixed).is_err());
        drop(attempt);
        assert!(owner.begin(&Fixed).is_ok());
        assert!(owner.lookup(&[1; 32]).is_err());
        let next = controlled(1, Arc::new(|| Ok(100)));
        assert!(next.lookup(&[1; 32]).is_err());
        let attempt = next.begin(&Fixed).unwrap();
        let weak = Arc::downgrade(&next);
        drop(next);
        assert!(weak.upgrade().is_none());
        assert!(attempt.now(&Fixed).is_err()); // no attempt/owner reference cycle
    }
    #[test]
    fn original_native_expiry_and_wall_rollback_can_only_retire_capture() {
        struct Wall(AtomicU64);
        impl Clock for Wall {
            fn now(&self) -> Timestamp {
                Timestamp(self.0.load(Ordering::Acquire) as i64)
            }
        }
        let owner = controlled(2, Arc::new(|| Ok(100)));
        let clock = Wall(AtomicU64::new(10000));
        let attempt = owner.begin(&clock).unwrap();
        attempt.restrict(10050).unwrap();
        assert_eq!(attempt.expiry(), 149);
        clock.0.store(9999, Ordering::Release);
        assert!(attempt.now(&clock).is_err());
        clock.0.store(10000, Ordering::Release);
        assert!(attempt.now(&clock).is_err());
        drop(attempt);
        let attempt = owner.begin(&clock).unwrap();
        clock.0.store(11000, Ordering::Release);
        assert!(attempt.now(&clock).is_err());
        drop(attempt);
        assert!(owner.begin(&SystemClock).is_ok());
    }
    #[test]
    fn hundred_thousand_resident_records_are_not_evicted_and_cleanup_is_bounded() {
        use super::super::{PrincipalKind, receipt, receipt_binding, receipt_keys};
        let ticks = Arc::new(AtomicU64::new(100));
        let read = ticks.clone();
        let owner = controlled(
            default_capacity(),
            Arc::new(move || Ok(read.load(Ordering::Acquire))),
        );
        let mut db = rusqlite::Connection::open_in_memory().unwrap();
        db.execute_batch("CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT NOT NULL)")
            .unwrap();
        let mut keys = receipt_authority::Authority::load(&db, 0).unwrap();
        let signer = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        keys.reconcile(
            &mut db,
            &[receipt_keys::Key {
                issuer_ref: "owned".into(),
                purpose: receipt::Purpose::Authentication,
                epoch: 1,
                public_key: signer.verifying_key().to_bytes(),
            }],
            "fixture",
            &|_| Ok(()),
        )
        .unwrap();
        let epoch = hopae_grpc::workload_epoch::encode("owned", 1, 1, owner.domain()).unwrap();
        let context = receipt_binding::Context {
            issuer_ref: "owned",
            key_epoch: 1,
            identity_authority_epoch: &epoch,
            identity: receipt_binding::Identity {
                subject_ref: "s_529be5b595ab327853eabe2d1adf52256e262af036510607",
                kind: PrincipalKind::Workload,
                aal: 0,
                revision: 1,
                credential_generation: 1,
            },
            service: "orders",
            audience: "orders-api",
            request_sha256: [9; 32],
        };
        let binding = receipt_binding::digest(&context, None).unwrap();
        let proof = receipt::sign(
            &signer,
            &receipt::Claims {
                purpose: receipt::Purpose::Authentication,
                issued_ms: 100,
                expires_ms: 1100,
                binding,
                nonce: [1; 32],
            },
        )
        .unwrap();
        let checked = Arc::new(
            keys.verifier()
                .verify_observed_signature(&context, None, &proof)
                .unwrap(),
        );
        let profile = Arc::new(authority::Snapshot {
            publication: Arc::new(AtomicBool::new(false)),
            revision: 1,
            runtime: None,
        });
        let cfg=crate::config::parse(r#"{"state_dir":"owned","portal":{"public_url":"https://auth.example.test"},"gateway":{"kind":"hangang","caller_key_env":"OWNED_CALLER"}}"#).unwrap();
        let application = Arc::new(cfg.snapshot(1));
        let profiles = Arc::new(arc_swap::ArcSwap::from(profile.clone()));
        let applications = Arc::new(arc_swap::ArcSwap::from(application.clone()));
        // Infrastructure capacity test ONLY: immutable registry evidence is
        // shared as a template, not a claim of100k native authentications.
        for i in 0u64..100000 {
            let mut hash = [0; 32];
            hash[0] = (i % 256) as u8;
            hash[1..9].copy_from_slice(&i.to_be_bytes());
            owner
                .insert(Arc::new(Record {
                    hash,
                    binding,
                    attempt: owner.begin(&Fixed).unwrap(),
                    profile: profile.clone(),
                    application: application.clone(),
                    profiles: profiles.clone(),
                    applications: applications.clone(),
                    keys: checked.clone(),
                }))
                .unwrap();
        }
        let total = || {
            owner
                .shards
                .iter()
                .map(|shard| shard.lock().unwrap().records.len())
                .sum::<usize>()
        };
        assert_eq!(total(), 100000);
        assert_eq!(
            owner.capacity.available_permits(),
            default_capacity() - 100000
        );
        assert!(owner.lookup(&[0; 32]).is_ok());
        assert!(owner.insert(owner.lookup(&[0; 32]).unwrap()).is_err());
        assert_eq!(total(), 100000);
        for _ in 0..512 {
            owner.cleanup(1099).unwrap();
        }
        assert_eq!(total(), 100000);
        // One cleanup examines/removes at most8 heap entries, never a whole map.
        let before = total();
        owner.cleanup(1100).unwrap();
        assert!(before - total() <= 8);
        for _ in 0..13000 {
            owner.cleanup(1100).unwrap();
        }
        assert_eq!(total(), 0);
        assert_eq!(owner.capacity.available_permits(), default_capacity());
        assert!(owner.lookup(&[0; 32]).is_err());
        let pressure_ticks = Arc::new(AtomicU64::new(100));
        let read = pressure_ticks.clone();
        let pressure = controlled(1, Arc::new(move || Ok(read.load(Ordering::Acquire))));
        let distant = [200; 32];
        pressure
            .insert(Arc::new(Record {
                hash: distant,
                binding,
                attempt: pressure.begin(&Fixed).unwrap(),
                profile: profile.clone(),
                application: application.clone(),
                profiles: profiles.clone(),
                applications: applications.clone(),
                keys: checked.clone(),
            }))
            .unwrap();
        pressure_ticks.store(1090, Ordering::Release);
        assert!(pressure.begin(&Fixed).is_err()); // still live: no early eviction under pressure
        assert!(pressure.lookup(&distant).is_ok());
        pressure_ticks.store(1100, Ordering::Release);
        assert!(pressure.begin(&Fixed).is_ok()); // next request, not256 later cursor visits
        assert!(pressure.lookup(&distant).is_err());
        eprintln!(
            "record={} attempt={} checked={} shard={} heap_entry={} map_entry={} (bytes excluding allocator/Arc/hashmap slack/shared owners)",
            std::mem::size_of::<Record>(),
            std::mem::size_of::<Attempt>(),
            std::mem::size_of::<receipt_authority::ObservedChecked>(),
            std::mem::size_of::<Shard>(),
            std::mem::size_of::<Reverse<(u64, [u8; 32])>>(),
            std::mem::size_of::<([u8; 32], Arc<Record>)>()
        );
    }
}
