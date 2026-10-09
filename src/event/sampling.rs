//! `verify.denied` sampling (ADR-0009): at most one event per (session or
//! client IP, reason) per window. The first denial of a window is held; every
//! further one only counts. When the window closes the held event is emitted
//! once with `attrs.sampled_count` = the number of denials in the window, so
//! the single row carries the true volume. The `hopae_verify_denied_total`
//! counter still counts every denial.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Duration;

use crate::crypto::Timestamp;
use crate::event::types::{Event, Reason};
use crate::session::types::SessionId;

/// Window length from ADR-0009.
pub const SAMPLE_WINDOW: Duration = Duration::from_secs(60);
/// Most buckets kept at once; a denial for a new key beyond this is dropped
/// (and reported as dropped by the caller).
pub const MAX_BUCKETS: usize = 16_384;

/// Who a denial is attributed to: the session when there is one, else the client IP.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Scope {
    Session(SessionId),
    Ip(IpAddr),
    None,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct Key {
    scope: Scope,
    reason: &'static str,
}

struct Bucket {
    first: Event,
    count: u64,
    started: Timestamp,
}

/// What `observe` did with a denial.
#[derive(Debug, PartialEq, Eq)]
pub enum Observed {
    /// First of its window: held until the window closes.
    Held,
    /// Folded into the held event of the window.
    Counted,
    /// The bucket table is full and the key is new: the event is lost.
    Overflow,
}

pub struct Sampler {
    window: Duration,
    cap: usize,
    buckets: Mutex<HashMap<Key, Bucket>>,
}

impl Default for Sampler {
    fn default() -> Self {
        Self::new(SAMPLE_WINDOW, MAX_BUCKETS)
    }
}

fn finish(mut b: Bucket) -> Event {
    b.first.attrs.insert("sampled_count".into(), b.count.into());
    b.first
}

impl Sampler {
    pub fn new(window: Duration, cap: usize) -> Self {
        Sampler {
            window,
            cap,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Record one denial. `make` runs only when the denial opens a window (the
    /// held event); events whose previous window already closed are returned
    /// for emission.
    pub fn observe(
        &self,
        scope: Scope,
        reason: Reason,
        now: Timestamp,
        make: impl FnOnce() -> Event,
    ) -> (Observed, Vec<Event>) {
        let key = Key {
            scope,
            reason: reason.0,
        };
        let mut map = self.buckets.lock().unwrap_or_else(|p| p.into_inner());
        let mut ready = Vec::new();
        if let Some(b) = map.get_mut(&key) {
            if now.since(b.started) < self.window {
                b.count += 1;
                return (Observed::Counted, ready);
            }
            if let Some(old) = map.remove(&key) {
                ready.push(finish(old));
            }
        }
        if map.len() >= self.cap {
            return (Observed::Overflow, ready);
        }
        map.insert(
            key,
            Bucket {
                first: make(),
                count: 1,
                started: now,
            },
        );
        (Observed::Held, ready)
    }

    /// Windows that have closed by `now`, as events ready to be written.
    pub fn drain_due(&self, now: Timestamp) -> Vec<Event> {
        let mut map = self.buckets.lock().unwrap_or_else(|p| p.into_inner());
        let due: Vec<Key> = map
            .iter()
            .filter(|(_, b)| now.since(b.started) >= self.window)
            .map(|(k, _)| k.clone())
            .collect();
        due.into_iter()
            .filter_map(|k| map.remove(&k))
            .map(finish)
            .collect()
    }

    /// Everything held, window closed or not (shutdown).
    pub fn drain_all(&self) -> Vec<Event> {
        let mut map = self.buckets.lock().unwrap_or_else(|p| p.into_inner());
        map.drain().map(|(_, b)| finish(b)).collect()
    }

    pub fn len(&self) -> usize {
        self.buckets.lock().unwrap_or_else(|p| p.into_inner()).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{SeededRng, TestClock};
    use crate::event::types::{EventBuilder, EventKind, Outcome, reasons};

    fn ev(clock: &TestClock) -> Event {
        EventBuilder::new(
            clock,
            &SeededRng::new(1),
            EventKind::VerifyDenied,
            Outcome::Failure,
            "r",
        )
        .reason(reasons::UNKNOWN_HANDLE)
        .build()
    }

    #[test]
    fn one_row_per_key_and_window_carries_the_count() {
        let clock = TestClock::new(Timestamp(1_000_000));
        let s = Sampler::default();
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        let mut held = 0;
        for _ in 0..100 {
            let (o, ready) = s.observe(
                Scope::Ip(ip),
                reasons::UNKNOWN_HANDLE,
                crate::crypto::Clock::now(&clock),
                || ev(&clock),
            );
            assert!(ready.is_empty());
            if o == Observed::Held {
                held += 1;
            }
        }
        assert_eq!(held, 1);
        assert!(s.drain_due(Timestamp(1_000_000 + 59_999)).is_empty());
        let out = s.drain_due(Timestamp(1_000_000 + 60_000));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].attrs["sampled_count"], 100);
        assert!(s.is_empty());
    }

    #[test]
    fn different_reasons_scopes_and_windows_are_separate() {
        let clock = TestClock::new(Timestamp(0));
        let s = Sampler::default();
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        let other: IpAddr = "192.0.2.2".parse().unwrap();
        let sid = SessionId::new("s_1");
        for (scope, reason) in [
            (Scope::Ip(ip), reasons::UNKNOWN_HANDLE),
            (Scope::Ip(ip), reasons::IDLE),
            (Scope::Ip(other), reasons::UNKNOWN_HANDLE),
            (Scope::Session(sid), reasons::UNKNOWN_HANDLE),
        ] {
            let (o, _) = s.observe(scope, reason, Timestamp(0), || ev(&clock));
            assert_eq!(o, Observed::Held);
        }
        assert_eq!(s.len(), 4);
        // A denial after the window closes flushes the old bucket and opens a new one.
        let (o, ready) = s.observe(Scope::Ip(ip), reasons::IDLE, Timestamp(61_000), || {
            ev(&clock)
        });
        assert_eq!(o, Observed::Held);
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].attrs["sampled_count"], 1);
    }

    #[test]
    fn the_bucket_table_is_bounded() {
        let clock = TestClock::new(Timestamp(0));
        let s = Sampler::new(SAMPLE_WINDOW, 2);
        for i in 0..3u8 {
            let ip: IpAddr = std::net::Ipv4Addr::new(10, 0, 0, i).into();
            let (o, _) = s.observe(Scope::Ip(ip), reasons::UNKNOWN_HANDLE, Timestamp(0), || {
                ev(&clock)
            });
            assert_eq!(
                o,
                if i < 2 {
                    Observed::Held
                } else {
                    Observed::Overflow
                }
            );
        }
        assert_eq!(s.drain_all().len(), 2);
    }
}
