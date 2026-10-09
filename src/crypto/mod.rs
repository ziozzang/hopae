//! Time, identifiers, digests, secrets and randomness.
//!
//! Everything that touches a bearer value goes through this module: values are
//! wrapped in [`Secret`] (never printed), stored as [`Digest`]s, compared with
//! [`ct_eq`], and drawn from an [`Rng`] that is the operating system's CSPRNG
//! in production and a seeded stream only under the `test-hooks` feature or in
//! unit tests.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq;

/// Unix time in milliseconds. All store columns named *_at hold seconds; convert at the boundary.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub struct Timestamp(pub i64);

impl Timestamp {
    /// Whole seconds, rounded toward negative infinity.
    pub fn secs(self) -> i64 {
        self.0.div_euclid(1000)
    }

    /// Saturating addition.
    #[allow(clippy::should_implement_trait)]
    pub fn add(self, d: Duration) -> Timestamp {
        Timestamp(self.0.saturating_add(millis_i64(d)))
    }

    /// Saturating subtraction.
    #[allow(clippy::should_implement_trait)]
    pub fn sub(self, d: Duration) -> Timestamp {
        Timestamp(self.0.saturating_sub(millis_i64(d)))
    }

    /// Elapsed time since `earlier`; zero when `earlier` is not earlier (saturating).
    pub fn since(self, earlier: Timestamp) -> Duration {
        let ms = self.0.saturating_sub(earlier.0);
        Duration::from_millis(u64::try_from(ms).unwrap_or(0))
    }

    /// The timestamp for a whole-seconds store column.
    pub fn from_secs(secs: i64) -> Timestamp {
        Timestamp(secs.saturating_mul(1000))
    }
}

fn millis_i64(d: Duration) -> i64 {
    i64::try_from(d.as_millis()).unwrap_or(i64::MAX)
}

pub trait Clock: Send + Sync + 'static {
    fn now(&self) -> Timestamp;
}

/// The wall clock.
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Timestamp {
        let ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, millis_i64);
        Timestamp(ms)
    }
}

/// Test clock: settable and advanceable; shared via Arc.
pub struct TestClock(std::sync::Arc<std::sync::atomic::AtomicI64>);

impl TestClock {
    pub fn new(start: Timestamp) -> Self {
        TestClock(Arc::new(AtomicI64::new(start.0)))
    }

    pub fn set(&self, t: Timestamp) {
        self.0.store(t.0, Ordering::SeqCst);
    }

    pub fn advance(&self, d: Duration) {
        // Saturating, via a compare-exchange loop so concurrent advances add up.
        let add = millis_i64(d);
        let mut cur = self.0.load(Ordering::SeqCst);
        loop {
            let next = cur.saturating_add(add);
            match self
                .0
                .compare_exchange(cur, next, Ordering::SeqCst, Ordering::SeqCst)
            {
                Ok(_) => return,
                Err(actual) => cur = actual,
            }
        }
    }
}

impl Clock for TestClock {
    fn now(&self) -> Timestamp {
        Timestamp(self.0.load(Ordering::SeqCst))
    }
}

/// 32-byte SHA-256 digest; Display is lower-case hex; Debug prints the first 8 hex chars only.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Digest(pub [u8; 32]);

impl Digest {
    /// Lower-case hex of the whole digest.
    pub fn to_hex(&self) -> String {
        data_encoding::HEXLOWER.encode(&self.0)
    }

    /// Parse 64 lower- or upper-case hex characters.
    pub fn from_hex(s: &str) -> Option<Digest> {
        let bytes = data_encoding::HEXLOWER_PERMISSIVE
            .decode(s.as_bytes())
            .ok()?;
        let arr: [u8; 32] = bytes.try_into().ok()?;
        Some(Digest(arr))
    }

    /// Rebuild from a 32-byte BLOB; `None` for any other length.
    pub fn from_slice(b: &[u8]) -> Option<Digest> {
        let arr: [u8; 32] = b.try_into().ok()?;
        Some(Digest(arr))
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Digest({})",
            data_encoding::HEXLOWER.encode(&self.0[..4])
        )
    }
}

pub fn sha256(bytes: &[u8]) -> Digest {
    let mut h = Sha256::new();
    h.update(bytes);
    Digest(h.finalize().into())
}

/// A bearer value. Debug/Display print "<redacted>". Compared only through `ct_eq`.
#[derive(Clone)]
pub struct Secret(String);

impl Secret {
    pub fn new(s: String) -> Self {
        Secret(s)
    }

    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn digest(&self) -> Digest {
        sha256(self.0.as_bytes())
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// Constant-time equality. Lengths differ -> false, after a full compare of the shorter.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    let n = a.len().min(b.len());
    let prefix_equal: bool = a[..n].ct_eq(&b[..n]).into();
    let same_len = a.len() == b.len();
    prefix_equal & same_len
}

/// Random source: OsRng in production; a ChaCha20 stream seeded from HOPAE_TEST_SEED under the `test-hooks` feature.
pub trait Rng: Send + Sync + 'static {
    fn fill(&self, buf: &mut [u8]);
}

/// The operating system CSPRNG. A failure of the OS source is unrecoverable:
/// the process aborts rather than continue with predictable bytes.
pub struct OsRng;

impl Rng for OsRng {
    fn fill(&self, buf: &mut [u8]) {
        use rand::TryRngCore;
        if rand::rngs::OsRng.try_fill_bytes(buf).is_err() {
            eprintln!("fatal: operating system random source failed");
            std::process::abort();
        }
    }
}

/// Deterministic stream for tests (`test-hooks` feature or unit tests only).
#[cfg(any(test, feature = "test-hooks"))]
pub struct SeededRng(std::sync::Mutex<rand_chacha::ChaCha20Rng>);

#[cfg(any(test, feature = "test-hooks"))]
impl SeededRng {
    pub fn new(seed: u64) -> Self {
        use rand::SeedableRng;
        SeededRng(std::sync::Mutex::new(
            rand_chacha::ChaCha20Rng::seed_from_u64(seed),
        ))
    }
}

#[cfg(any(test, feature = "test-hooks"))]
impl Rng for SeededRng {
    fn fill(&self, buf: &mut [u8]) {
        use rand::RngCore;
        let mut g = self.0.lock().unwrap_or_else(|p| p.into_inner());
        g.fill_bytes(buf);
    }
}

/// Production RNG, or (with `test-hooks`) the seeded stream when the named
/// environment variable holds a `u64`. Without the feature the argument is
/// ignored and the OS source is always used.
pub fn rng_from_env(seed: Option<&str>) -> Arc<dyn Rng> {
    #[cfg(feature = "test-hooks")]
    if let Some(seed) = seed.and_then(|s| s.trim().parse::<u64>().ok()) {
        return Arc::new(SeededRng::new(seed));
    }
    let _ = seed;
    Arc::new(OsRng)
}

const CROCKFORD: &str = "0123456789abcdefghjkmnpqrstvwxyz";

fn crockford() -> &'static data_encoding::Encoding {
    static ENC: std::sync::OnceLock<data_encoding::Encoding> = std::sync::OnceLock::new();
    ENC.get_or_init(|| {
        let mut spec = data_encoding::Specification::new();
        spec.symbols.push_str(CROCKFORD);
        // The specification above is a fixed, valid 32-symbol alphabet.
        spec.encoding().unwrap_or(data_encoding::BASE32_NOPAD)
    })
}

/// `<prefix>` + 26 Crockford base32 chars from 128 random bits (ids: "u_", "s_", "a_", "p_", "e_", "t_").
pub fn random_id(rng: &dyn Rng, prefix: &'static str) -> String {
    let mut b = [0u8; 16];
    rng.fill(&mut b);
    format!("{prefix}{}", crockford().encode(&b))
}

/// Like [`random_id`] but the first 48 bits are `at` in milliseconds, so ids
/// sort by time (ADR-0009: event ids are time-ordered).
///
/// Within one millisecond ids stay ordered by creation (the ULID monotonic
/// rule): a second id for the same millisecond is the previous one plus one,
/// so events built in order sort in order even when the clock does not move
/// (a test clock, or a burst inside one tick).
pub fn time_ordered_id(rng: &dyn Rng, prefix: &'static str, at: Timestamp) -> String {
    use std::collections::BTreeMap;
    use std::sync::{Mutex, OnceLock};
    /// Milliseconds remembered; older ones are forgotten (ids are only ever
    /// generated for the present, so a few recent milliseconds are enough).
    const KEEP: usize = 64;
    static LAST: OnceLock<Mutex<BTreeMap<u64, [u8; 10]>>> = OnceLock::new();
    let ms = u64::try_from(at.0).unwrap_or(0) & 0xFFFF_FFFF_FFFF;
    let mut fresh = [0u8; 10];
    rng.fill(&mut fresh);
    let mut last = LAST
        .get_or_init(|| Mutex::new(BTreeMap::new()))
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let rand = match last.get(&ms) {
        Some(prev) => {
            // Increment the 80-bit value; on the (practically impossible) wrap keep the fresh one.
            let mut next = *prev;
            let mut carry = true;
            for byte in next.iter_mut().rev() {
                if carry {
                    let (v, c) = byte.overflowing_add(1);
                    *byte = v;
                    carry = c;
                }
            }
            if carry { fresh } else { next }
        }
        None => fresh,
    };
    last.insert(ms, rand);
    while last.len() > KEEP {
        last.pop_first();
    }
    drop(last);
    let mut b = [0u8; 16];
    b[..6].copy_from_slice(&ms.to_be_bytes()[2..]);
    b[6..].copy_from_slice(&rand);
    format!("{prefix}{}", crockford().encode(&b))
}

/// base64url without padding of `bytes` random bytes (handles 32 -> "v1." + 43 chars via `handle_value`, binds 16 -> 22 chars, codes 32 -> 43 chars).
pub fn random_token(rng: &dyn Rng, bytes: usize) -> Secret {
    let mut b = vec![0u8; bytes];
    rng.fill(&mut b);
    Secret(data_encoding::BASE64URL_NOPAD.encode(&b))
}

pub fn handle_value(rng: &dyn Rng) -> Secret {
    Secret(format!("v1.{}", random_token(rng, 32).expose()))
}

fn is_base64url(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
}

/// Exactly 22 base64url chars.
pub fn is_well_formed_bind(s: &str) -> bool {
    is_base64url(s, 22)
}

/// "v1." + 43 base64url chars.
pub fn is_well_formed_handle(s: &str) -> bool {
    s.strip_prefix("v1.")
        .is_some_and(|rest| is_base64url(rest, 43))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_arithmetic_saturates() {
        let t = Timestamp(1_500);
        assert_eq!(t.secs(), 1);
        assert_eq!(Timestamp(-1).secs(), -1);
        assert_eq!(t.add(Duration::from_secs(2)), Timestamp(3_500));
        assert_eq!(t.sub(Duration::from_secs(2)), Timestamp(-500));
        assert_eq!(t.since(Timestamp(500)), Duration::from_secs(1));
        assert_eq!(Timestamp(500).since(t), Duration::ZERO);
        assert_eq!(Timestamp(i64::MAX).add(Duration::MAX), Timestamp(i64::MAX));
    }

    #[test]
    fn test_clock_sets_and_advances() {
        let c = TestClock::new(Timestamp(10));
        c.advance(Duration::from_millis(5));
        assert_eq!(c.now(), Timestamp(15));
        c.set(Timestamp(1_000));
        assert_eq!(c.now(), Timestamp(1_000));
    }

    #[test]
    fn digest_formats() {
        let d = sha256(b"abc");
        assert_eq!(
            d.to_string(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(format!("{d:?}"), "Digest(ba7816bf)");
        assert_eq!(Digest::from_hex(&d.to_string()), Some(d));
        assert_eq!(Digest::from_slice(&d.0), Some(d));
        assert_eq!(Digest::from_slice(&d.0[..5]), None);
    }

    #[test]
    fn secret_never_prints() {
        let s = Secret::new("hunter2".into());
        assert_eq!(format!("{s}"), "<redacted>");
        assert_eq!(format!("{s:?}"), "<redacted>");
        assert_eq!(s.expose(), "hunter2");
        assert_eq!(s.digest(), sha256(b"hunter2"));
    }

    #[test]
    fn ct_eq_handles_lengths() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"abcd"));
        assert!(!ct_eq(b"abcd", b"abc"));
        assert!(ct_eq(b"", b""));
    }

    #[test]
    fn seeded_rng_is_deterministic_and_ids_have_shape() {
        let a = SeededRng::new(7);
        let b = SeededRng::new(7);
        let c = SeededRng::new(8);
        let id = random_id(&a, "u_");
        assert_eq!(id, random_id(&b, "u_"));
        assert_ne!(id, random_id(&c, "u_"));
        assert!(id.starts_with("u_"));
        assert_eq!(id.len(), 2 + 26);
        assert!(id[2..].bytes().all(|c| CROCKFORD.as_bytes().contains(&c)));
    }

    #[test]
    fn tokens_binds_and_handles_have_exact_shape() {
        let r = SeededRng::new(1);
        let bind = random_token(&r, 16);
        assert_eq!(bind.expose().len(), 22);
        assert!(is_well_formed_bind(bind.expose()));
        let code = random_token(&r, 32);
        assert_eq!(code.expose().len(), 43);
        let h = handle_value(&r);
        assert_eq!(h.expose().len(), 46);
        assert!(is_well_formed_handle(h.expose()));
        assert!(!is_well_formed_handle(code.expose()));
        assert!(!is_well_formed_bind(code.expose()));
        assert!(!is_well_formed_bind("short"));
        assert!(!is_well_formed_bind(&format!("{}!", &bind.expose()[..21])));
        assert!(!is_well_formed_handle(
            "v2.0123456789012345678901234567890123456789012"
        ));
    }

    #[test]
    fn ids_within_one_millisecond_stay_in_creation_order() {
        let r = SeededRng::new(9);
        let ids: Vec<String> = (0..200)
            .map(|_| time_ordered_id(&r, "e_", Timestamp(7_000_000)))
            .collect();
        let mut sorted = ids.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), ids.len(), "unique");
        // Other threads may interleave ids of the same millisecond, so check
        // order only: each id sorts after the one before it.
        assert!(ids.windows(2).all(|w| w[0] < w[1]), "monotonic");
    }

    #[test]
    fn time_ordered_ids_sort_by_time() {
        let r = SeededRng::new(3);
        let early = time_ordered_id(&r, "e_", Timestamp(1_000));
        let late = time_ordered_id(&r, "e_", Timestamp(1_001));
        let much_later = time_ordered_id(&r, "e_", Timestamp(1 << 40));
        assert!(early < late);
        assert!(late < much_later);
        assert_eq!(early.len(), 28);
    }

    #[test]
    fn os_rng_produces_distinct_values() {
        let r = OsRng;
        assert_ne!(random_id(&r, "s_"), random_id(&r, "s_"));
    }
}
