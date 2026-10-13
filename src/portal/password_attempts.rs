//! Bounded monotonic password-attempt admission; session verification does not use this state.
use std::{collections::HashMap, net::IpAddr, sync::Mutex, time::Instant};
const CAPACITY: usize = 4096;
const WINDOW_MS: u64 = 60_000;
const ATTEMPTS: u8 = 10;
struct Window {
    started: u64,
    count: u8,
}
pub struct PasswordAttempts {
    started: Instant,
    windows: Mutex<HashMap<IpAddr, Window>>,
}
impl Default for PasswordAttempts {
    fn default() -> Self {
        Self {
            started: Instant::now(),
            windows: Mutex::new(HashMap::new()),
        }
    }
}
impl PasswordAttempts {
    /// Count every CSRF-valid submission, including rejected credentials. Saturation fails closed.
    pub fn admit(&self, ip: IpAddr) -> bool {
        self.admit_at(
            ip,
            self.started.elapsed().as_millis().min(u64::MAX as u128) as u64,
        )
    }
    fn admit_at(&self, ip: IpAddr, now: u64) -> bool {
        let Ok(mut windows) = self.windows.lock() else {
            return false;
        };
        let ip = ip.to_canonical();
        if let Some(window) = windows.get_mut(&ip) {
            if now.saturating_sub(window.started) >= WINDOW_MS {
                window.started = now;
                window.count = 0;
            }
            if window.count >= ATTEMPTS {
                return false;
            }
            window.count += 1;
            return true;
        }
        if windows.len() >= CAPACITY {
            windows.retain(|_, window| now.saturating_sub(window.started) < WINDOW_MS);
            if windows.len() >= CAPACITY {
                return false;
            }
        }
        windows.insert(
            ip,
            Window {
                started: now,
                count: 1,
            },
        );
        true
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn simultaneous_alias_requests_cannot_exceed_one_ip_budget() {
        let attempts = std::sync::Arc::new(PasswordAttempts::default());
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(32));
        let admitted = std::sync::atomic::AtomicUsize::new(0);
        std::thread::scope(|scope| {
            for index in 0..32 {
                let attempts = attempts.clone();
                let barrier = barrier.clone();
                let admitted = &admitted;
                scope.spawn(move || {
                    barrier.wait();
                    let ip = if index % 2 == 0 {
                        "192.0.2.1"
                    } else {
                        "::ffff:192.0.2.1"
                    }
                    .parse()
                    .unwrap();
                    if attempts.admit_at(ip, 100) {
                        admitted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    }
                });
            }
        });
        assert_eq!(
            admitted.load(std::sync::atomic::Ordering::SeqCst),
            usize::from(ATTEMPTS)
        );
    }
    #[test]
    fn poisoned_admission_state_fails_closed() {
        let attempts = std::sync::Arc::new(PasswordAttempts::default());
        let worker = attempts.clone();
        let _ = std::thread::spawn(move || {
            let _guard = worker.windows.lock().unwrap();
            panic!("owned admission poison test");
        })
        .join();
        assert!(!attempts.admit_at("192.0.2.2".parse().unwrap(), 0));
    }
    #[test]
    fn mapped_ip_cannot_reset_quota_and_wall_clock_is_not_used() {
        let attempts = PasswordAttempts::default();
        let ip = "192.0.2.1".parse().unwrap();
        for _ in 0..ATTEMPTS {
            assert!(attempts.admit_at(ip, 100));
        }
        assert!(!attempts.admit_at("::ffff:192.0.2.1".parse().unwrap(), 100));
        assert!(!attempts.admit_at(ip, 0));
        assert!(attempts.admit_at(ip, 100 + WINDOW_MS));
    }
    #[test]
    fn saturation_preserves_active_windows_and_expiry_releases_capacity() {
        let attempts = PasswordAttempts::default();
        for index in 0..CAPACITY {
            assert!(attempts.admit_at(IpAddr::V4((index as u32).into()), 0));
        }
        let extra = "203.0.113.9".parse().unwrap();
        assert!(!attempts.admit_at(extra, 1));
        assert_eq!(attempts.windows.lock().unwrap().len(), CAPACITY);
        assert!(attempts.admit_at(extra, WINDOW_MS));
        assert_eq!(attempts.windows.lock().unwrap().len(), 1);
    }
}
