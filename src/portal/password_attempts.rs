//! Password and code attempt admission (`password_attempts.per_ip`,
//! `password_attempts.per_account`): fixed windows counted on every
//! CSRF-valid submission, rejected credentials included. Session
//! verification does not use this state.
//!
//! On SQLite (one instance) the windows live in this process (bounded, on
//! the monotonic clock). With a shared [`AttemptLedger`] (the PostgreSQL
//! store) they live in the store, so the limits hold across replicas.
//! Every failure fails closed.
use std::{
    collections::HashMap, net::IpAddr, sync::Arc, sync::Mutex, time::Duration, time::Instant,
};

use sha2::{Digest as _, Sha256};

/// Process-local windows kept at most (saturation fails closed).
const CAPACITY: usize = 4096;

/// One limit: at most `burst` submissions per `window`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limit {
    pub burst: u32,
    pub window: Duration,
}

impl Limit {
    fn window_ms(&self) -> u64 {
        u64::try_from(self.window.as_millis()).unwrap_or(u64::MAX)
    }
}

/// The scope of a counted key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Scope {
    Ip,
    Account,
}

impl Scope {
    pub fn as_str(self) -> &'static str {
        match self {
            Scope::Ip => "ip",
            Scope::Account => "account",
        }
    }
}

/// One window to count: scope, opaque key digest (never a raw address or
/// username) and its limit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Check {
    pub scope: Scope,
    pub key: [u8; 32],
    pub limit: Limit,
}

/// A store shared by every replica that counts the windows (PostgreSQL).
#[async_trait::async_trait]
pub trait AttemptLedger: Send + Sync {
    /// Count one submission in every window; true when each is within its
    /// burst. An error is a refusal.
    async fn admit_attempts(&self, checks: &[Check]) -> crate::store::StoreResult<bool>;
}

struct Window {
    started: u64,
    count: u32,
}

pub struct PasswordAttempts {
    per_ip: Limit,
    per_account: Limit,
    started: Instant,
    windows: Mutex<HashMap<(Scope, [u8; 32]), Window>>,
    shared: Option<Arc<dyn AttemptLedger>>,
}

impl Default for PasswordAttempts {
    fn default() -> Self {
        Self::new(
            Limit {
                burst: 10,
                window: Duration::from_secs(60),
            },
            Limit {
                burst: 10,
                window: Duration::from_secs(60),
            },
            None,
        )
    }
}

fn digest(scope: Scope, text: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"hopae-password-attempts\0");
    h.update(scope.as_str().as_bytes());
    h.update(b"\0");
    h.update(text);
    h.finalize().into()
}

impl PasswordAttempts {
    pub fn new(per_ip: Limit, per_account: Limit, shared: Option<Arc<dyn AttemptLedger>>) -> Self {
        Self {
            per_ip,
            per_account,
            started: Instant::now(),
            windows: Mutex::new(HashMap::new()),
            shared,
        }
    }

    /// The longer of the two windows: what a refused client is told to wait.
    pub fn retry_after(&self) -> Duration {
        self.per_ip.window.max(self.per_account.window)
    }

    /// The windows one submission counts in: its client address (mapped
    /// IPv4 folded) and, for a password login, the account it names.
    fn checks(&self, ip: IpAddr, account: Option<&str>) -> Vec<Check> {
        let mut out = vec![Check {
            scope: Scope::Ip,
            key: digest(Scope::Ip, ip.to_canonical().to_string().as_bytes()),
            limit: self.per_ip,
        }];
        if let Some(account) = account {
            out.push(Check {
                scope: Scope::Account,
                key: digest(Scope::Account, account.as_bytes()),
                limit: self.per_account,
            });
        }
        out
    }

    /// Count a submission from `ip` (and the account it names, if any).
    pub async fn admit(&self, ip: IpAddr, account: Option<&str>) -> bool {
        let checks = self.checks(ip, account);
        match &self.shared {
            Some(ledger) => ledger.admit_attempts(&checks).await.unwrap_or(false),
            None => self.admit_local(
                &checks,
                self.started.elapsed().as_millis().min(u64::MAX as u128) as u64,
            ),
        }
    }

    /// The account key of a password login: provider and the username as
    /// typed, case-folded (a provider's username comparison is not ours to
    /// weaken, and folding only merges more attempts into one window).
    pub fn account(provider: &str, username: &str) -> String {
        format!("{provider}\0{}", username.trim().to_lowercase())
    }

    fn admit_local(&self, checks: &[Check], now: u64) -> bool {
        let Ok(mut windows) = self.windows.lock() else {
            return false;
        };
        let mut admitted = true;
        for check in checks {
            let id = (check.scope, check.key);
            let span = check.limit.window_ms();
            if !windows.contains_key(&id) && windows.len() >= CAPACITY {
                windows.retain(|(scope, _), w| {
                    let span = match scope {
                        Scope::Ip => self.per_ip.window_ms(),
                        Scope::Account => self.per_account.window_ms(),
                    };
                    now.saturating_sub(w.started) < span
                });
                if windows.len() >= CAPACITY {
                    return false;
                }
            }
            let window = windows.entry(id).or_insert(Window {
                started: now,
                count: 0,
            });
            if now.saturating_sub(window.started) >= span {
                window.started = now;
                window.count = 0;
            }
            window.count = window.count.saturating_add(1);
            if window.count > check.limit.burst {
                admitted = false;
            }
        }
        admitted
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const ATTEMPTS: u32 = 10;
    const WINDOW_MS: u64 = 60_000;
    fn ip_only(a: &PasswordAttempts, ip: IpAddr, now: u64) -> bool {
        a.admit_local(&a.checks(ip, None), now)
    }
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
                    if ip_only(&attempts, ip, 100) {
                        admitted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    }
                });
            }
        });
        assert_eq!(
            admitted.load(std::sync::atomic::Ordering::SeqCst),
            ATTEMPTS as usize
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
        assert!(!ip_only(&attempts, "192.0.2.2".parse().unwrap(), 0));
    }
    #[test]
    fn mapped_ip_cannot_reset_quota_and_wall_clock_is_not_used() {
        let attempts = PasswordAttempts::default();
        let ip = "192.0.2.1".parse().unwrap();
        for _ in 0..ATTEMPTS {
            assert!(ip_only(&attempts, ip, 100));
        }
        assert!(!ip_only(
            &attempts,
            "::ffff:192.0.2.1".parse().unwrap(),
            100
        ));
        assert!(!ip_only(&attempts, ip, 0));
        assert!(ip_only(&attempts, ip, 100 + WINDOW_MS));
    }
    #[test]
    fn saturation_preserves_active_windows_and_expiry_releases_capacity() {
        let attempts = PasswordAttempts::default();
        for index in 0..CAPACITY {
            assert!(ip_only(&attempts, IpAddr::V4((index as u32).into()), 0));
        }
        let extra = "203.0.113.9".parse().unwrap();
        assert!(!ip_only(&attempts, extra, 1));
        assert_eq!(attempts.windows.lock().unwrap().len(), CAPACITY);
        assert!(ip_only(&attempts, extra, WINDOW_MS));
        assert_eq!(attempts.windows.lock().unwrap().len(), 1);
    }
    #[test]
    fn the_account_limit_holds_across_addresses_and_is_configurable() {
        let attempts = PasswordAttempts::new(
            Limit {
                burst: 100,
                window: Duration::from_secs(60),
            },
            Limit {
                burst: 3,
                window: Duration::from_secs(300),
            },
            None,
        );
        let account = PasswordAttempts::account("ldap", " Alice ");
        assert_eq!(account, PasswordAttempts::account("ldap", "alice"));
        for i in 0..3u8 {
            let ip = IpAddr::V4([198, 51, 100, i].into());
            assert!(attempts.admit_local(&attempts.checks(ip, Some(&account)), 0));
        }
        let fresh = IpAddr::V4([198, 51, 100, 9].into());
        assert!(!attempts.admit_local(&attempts.checks(fresh, Some(&account)), 1));
        // Another account from the same address is still admitted.
        let other = PasswordAttempts::account("ldap", "bob");
        assert!(attempts.admit_local(&attempts.checks(fresh, Some(&other)), 2));
        // The account window (300 s), not the address window, releases it.
        assert!(!attempts.admit_local(&attempts.checks(fresh, Some(&account)), 60_001));
        assert!(attempts.admit_local(&attempts.checks(fresh, Some(&account)), 300_001));
        assert_eq!(attempts.retry_after(), Duration::from_secs(300));
    }
}
