//! Per-endpoint circuits. Time is monotonic; callbacks carry generation-bound permits.
//! Client credential denial is not a backend failure. Quarantine is never auto-reset.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Closed,
    Open,
    HalfOpen,
    Quarantined,
}
#[derive(Debug)]
pub struct Permit {
    epoch: u64,
}
#[derive(Debug)]
pub struct Breaker {
    state: State,
    threshold: u16,
    failures: u16,
    retry_ms: u64,
    retry_at: u64,
    probe: bool,
    epoch: u64,
}
impl Breaker {
    pub fn new(threshold: u16, retry_ms: u64) -> Option<Self> {
        if !(1..=100).contains(&threshold) || !(100..=60_000).contains(&retry_ms) {
            return None;
        }
        Some(Self {
            state: State::Closed,
            threshold,
            failures: 0,
            retry_ms,
            retry_at: 0,
            probe: false,
            epoch: 0,
        })
    }
    pub fn state(&self) -> State {
        self.state
    }
    fn advance(&mut self) {
        if let Some(next) = self.epoch.checked_add(1) {
            self.epoch = next;
        } else {
            self.state = State::Quarantined;
        }
    }
    pub fn admit(&mut self, now_ms: u64) -> Option<Permit> {
        if self.state == State::Quarantined {
            return None;
        }
        // A cancelled or lost half-open probe cannot occupy the circuit forever.
        // Fence its completion before allowing a later probe.
        if self.state == State::HalfOpen && self.probe && now_ms >= self.retry_at {
            self.state = State::Open;
            self.probe = false;
            self.retry_at = now_ms.saturating_add(self.retry_ms);
            self.advance();
        }
        if self.state == State::Open {
            if now_ms < self.retry_at {
                return None;
            }
            self.state = State::HalfOpen;
            self.advance();
        }
        if self.state == State::Quarantined {
            return None;
        }
        if self.state == State::HalfOpen {
            if self.probe {
                return None;
            }
            self.probe = true;
            self.retry_at = now_ms.saturating_add(self.retry_ms);
        }
        Some(Permit { epoch: self.epoch })
    }
    pub fn healthy(&mut self, permit: Permit) {
        if self.state == State::Quarantined || permit.epoch != self.epoch {
            return;
        }
        if self.state == State::HalfOpen {
            self.advance();
        }
        if self.state == State::Quarantined {
            return;
        }
        self.state = State::Closed;
        self.failures = 0;
        self.probe = false;
    }
    pub fn backend_failure(&mut self, permit: Permit, now_ms: u64) {
        if self.state == State::Quarantined || permit.epoch != self.epoch {
            return;
        }
        self.failures = self.failures.saturating_add(1);
        if self.state == State::HalfOpen || self.failures >= self.threshold {
            self.state = State::Open;
            self.retry_at = now_ms.saturating_add(self.retry_ms);
            self.probe = false;
            self.advance();
        }
    }
    pub fn quarantine(&mut self) {
        self.state = State::Quarantined;
        self.probe = false;
    }
}
/// Monotonic shared endpoint circuit with cancellation-safe admission leases.
pub struct Circuit {
    started: std::time::Instant,
    state: std::sync::Mutex<Breaker>,
}
impl Circuit {
    pub fn new(threshold: u16, retry_ms: u64) -> Option<std::sync::Arc<Self>> {
        Some(std::sync::Arc::new(Self {
            started: std::time::Instant::now(),
            state: std::sync::Mutex::new(Breaker::new(threshold, retry_ms)?),
        }))
    }
    fn now(&self) -> u64 {
        self.started.elapsed().as_millis().min(u64::MAX as u128) as u64
    }
    pub fn state(&self) -> Option<State> {
        self.state.lock().ok().map(|breaker| breaker.state())
    }
    pub fn admit(self: &std::sync::Arc<Self>) -> Option<CircuitLease> {
        let permit = self.state.lock().ok()?.admit(self.now())?;
        Some(CircuitLease {
            circuit: self.clone(),
            permit: Some(permit),
        })
    }
}
pub struct CircuitLease {
    circuit: std::sync::Arc<Circuit>,
    permit: Option<Permit>,
}
impl CircuitLease {
    /// A rejected credential is a healthy backend response; only backend faults are failures.
    pub fn finish(mut self, failed: bool) {
        self.record(failed);
    }
    fn record(&mut self, failed: bool) {
        if let Some(permit) = self.permit.take()
            && let Ok(mut breaker) = self.circuit.state.lock()
        {
            if failed {
                breaker.backend_failure(permit, self.circuit.now());
            } else {
                breaker.healthy(permit);
            }
        }
    }
}
impl Drop for CircuitLease {
    fn drop(&mut self) {
        self.record(true);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn shared_circuit_credential_denial_is_healthy_and_cancellation_opens() {
        let circuit = Circuit::new(3, 30_000).unwrap();
        for _ in 0..10 {
            circuit.admit().unwrap().finish(false);
        }
        assert_eq!(circuit.state(), Some(State::Closed));
        for _ in 0..3 {
            drop(circuit.admit().unwrap());
        }
        assert_eq!(circuit.state(), Some(State::Open));
        assert!(circuit.admit().is_none());
    }
    #[test]
    fn abandoned_probe_expires_and_cannot_close_a_new_generation() {
        let mut b = Breaker::new(1, 100).unwrap();
        let first = b.admit(0).unwrap();
        b.backend_failure(first, 0);
        let abandoned = b.admit(100).unwrap();
        assert!(b.admit(200).is_none());
        b.healthy(abandoned);
        assert_eq!(b.state(), State::Open);
        let fresh = b.admit(300).unwrap();
        b.healthy(fresh);
        assert_eq!(b.state(), State::Closed);
    }
    #[test]
    fn stale_success_cannot_reset_an_open_circuit() {
        let mut b = Breaker::new(2, 1000).unwrap();
        let old = b.admit(0).unwrap();
        let p = b.admit(0).unwrap();
        b.backend_failure(p, 0);
        let p = b.admit(1).unwrap();
        b.backend_failure(p, 1);
        b.healthy(old);
        assert_eq!(b.state(), State::Open);
        assert!(b.admit(1000).is_none());
        let p = b.admit(1001).unwrap();
        assert!(b.admit(1001).is_none());
        b.backend_failure(p, 1001);
        assert!(b.admit(2000).is_none());
        let p = b.admit(2001).unwrap();
        b.healthy(p);
        assert_eq!(b.state(), State::Closed);
        let p = b.admit(2001).unwrap();
        b.quarantine();
        b.healthy(p);
        assert!(b.admit(u64::MAX).is_none());
        assert_eq!(b.state(), State::Quarantined);
    }
}
