//! Test-only control points inside the store: stall, commit gates, crash
//! points and call counters. The type is always compiled (the `Store::open`
//! signature names it) but is inert unless an instance is passed in; the
//! production binary only creates one under the `test-hooks` feature.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Condvar, Mutex, MutexGuard};
use std::time::Duration;

#[derive(Default)]
struct GateState {
    /// Labels currently held closed.
    held: HashSet<String>,
    /// How many transactions have reached each label, ever.
    reached: HashMap<String, u64>,
}

#[derive(Default)]
pub struct StoreHooks {
    stall_ms: AtomicU64,
    /// The diagnostic batch writer sleeps this long before each event (0 = off).
    diag_stall_ms: AtomicU64,
    gates: Mutex<GateState>,
    gate_cv: Condvar,
    crash: Mutex<Option<String>>,
    calls: Mutex<BTreeMap<String, u64>>,
    /// Diagnostic batches that fail before commit (G7-P03 tests).
    fail_diag_batches: AtomicU64,
    /// Milliseconds each progress callback and each loop statement sleeps (0 = off).
    slow_scan_ms: AtomicU64,
    /// The deadline the most recent store job observed (`Some(None)` = it had none).
    last_deadline: Mutex<Option<Option<std::time::Instant>>>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

impl StoreHooks {
    pub fn new() -> Self {
        Self::default()
    }

    /// Every store call sleeps this long before executing (0 = off).
    pub fn set_stall(&self, ms: u64) {
        self.stall_ms.store(ms, Ordering::SeqCst);
    }

    /// Stall only the diagnostic batch writer (S014-5), not the store.
    pub fn set_diag_stall(&self, ms: u64) {
        self.diag_stall_ms.store(ms, Ordering::SeqCst);
    }

    pub fn diag_stall(&self) -> Duration {
        Duration::from_millis(self.diag_stall_ms.load(Ordering::SeqCst))
    }

    /// Slow every interruptible scan and every loop statement down (`store/slow_scan`).
    pub fn set_slow_scan(&self, ms: u64) {
        self.slow_scan_ms.store(ms, Ordering::SeqCst);
    }

    pub fn slow_scan(&self) -> Duration {
        Duration::from_millis(self.slow_scan_ms.load(Ordering::SeqCst))
    }

    pub(crate) fn record_deadline(&self, d: Option<std::time::Instant>) {
        *lock(&self.last_deadline) = Some(d);
    }

    /// The deadline the last job observed: `None` before any job, `Some(None)` for a job without one.
    pub fn last_deadline(&self) -> Option<Option<std::time::Instant>> {
        *lock(&self.last_deadline)
    }

    pub fn stall(&self) -> Duration {
        Duration::from_millis(self.stall_ms.load(Ordering::SeqCst))
    }

    /// Hold (`true`) or release (`false`) the transaction labelled `label` just before commit.
    pub fn set_gate(&self, label: &str, hold: bool) {
        let mut g = lock(&self.gates);
        if hold {
            g.held.insert(label.to_string());
        } else {
            g.held.remove(label);
        }
        drop(g);
        self.gate_cv.notify_all();
    }

    /// Called by the store on its writer thread right before commit; blocks while the label is held.
    pub fn pass_gate(&self, label: &str) {
        let mut g = lock(&self.gates);
        *g.reached.entry(label.to_string()).or_insert(0) += 1;
        self.gate_cv.notify_all();
        while g.held.contains(label) {
            g = self.gate_cv.wait(g).unwrap_or_else(|p| p.into_inner());
        }
    }

    /// Block (up to `timeout`) until `n` transactions have reached `label`.
    pub fn wait_reached(&self, label: &str, n: u64, timeout: Duration) -> bool {
        let deadline = std::time::Instant::now() + timeout;
        let mut g = lock(&self.gates);
        while g.reached.get(label).copied().unwrap_or(0) < n {
            let now = std::time::Instant::now();
            if now >= deadline {
                return false;
            }
            let (ng, _) = self
                .gate_cv
                .wait_timeout(g, deadline - now)
                .unwrap_or_else(|p| p.into_inner());
            g = ng;
        }
        true
    }

    /// Arm a crash point; `None` disarms.
    pub fn set_crash_at(&self, label: Option<String>) {
        *lock(&self.crash) = label;
    }

    /// `std::process::abort()` when `label` is the armed crash point.
    pub fn crash_point(&self, label: &str) {
        let hit = lock(&self.crash).as_deref() == Some(label);
        if hit {
            eprintln!("test-hooks: crash at {label}");
            std::process::abort();
        }
    }

    /// The next `n` diagnostic batch transactions fail (storage trouble).
    pub fn fail_diag_batches(&self, n: u64) {
        self.fail_diag_batches.store(n, Ordering::SeqCst);
    }

    pub(crate) fn take_diag_failure(&self) -> bool {
        self.fail_diag_batches
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_ok()
    }

    pub(crate) fn count_call(&self, method: &'static str) {
        *lock(&self.calls).entry(method.to_string()).or_insert(0) += 1;
    }

    /// Store calls by method name.
    pub fn calls(&self) -> BTreeMap<String, u64> {
        lock(&self.calls).clone()
    }
}
