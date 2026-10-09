//! Context binding (ADR-0007): the client IP and, when enabled, the user
//! agent of a request are compared with what the session recorded at login.
//! Pure functions; the engine decides what a mismatch does.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::crypto::{Digest, sha256};
use crate::event::types::{Reason, reasons};
use crate::policy::types::{BindingPolicy, IpBinding, OnMismatch, UaBinding};

/// User-agent bytes kept before hashing or recording (one KiB).
pub const MAX_USER_AGENT_BYTES: usize = 1024;

/// The one User-Agent normalization every entry point applies before the
/// value is hashed, bound or recorded: lossy UTF-8, then at most
/// [`MAX_USER_AGENT_BYTES`] bytes cut at a character boundary. The portal and
/// the gateway adapter must agree on these bytes (G7-C04).
pub fn normalize_user_agent(raw: &[u8]) -> String {
    let s = String::from_utf8_lossy(raw);
    if s.len() <= MAX_USER_AGENT_BYTES {
        return s.into_owned();
    }
    let mut end = MAX_USER_AGENT_BYTES;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

/// Which signal disagreed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BindSignal {
    Ip,
    Ua,
}

impl BindSignal {
    /// The termination / revocation reason for this signal.
    pub fn reason(self) -> Reason {
        match self {
            BindSignal::Ip => reasons::BINDING_IP,
            BindSignal::Ua => reasons::BINDING_UA,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            BindSignal::Ip => "ip",
            BindSignal::Ua => "ua",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BindingVerdict {
    Ok,
    Mismatch {
        signal: BindSignal,
        action: OnMismatch,
    },
}

/// IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) compare as the IPv4 address.
pub fn normalize_ip(ip: IpAddr) -> IpAddr {
    ip.to_canonical()
}

fn prefix_v4(a: Ipv4Addr, b: Ipv4Addr, bits: u8) -> bool {
    let bits = u32::from(bits.min(32));
    let mask = if bits == 0 {
        0
    } else {
        u32::MAX << (32 - bits)
    };
    (u32::from(a) & mask) == (u32::from(b) & mask)
}

fn prefix_v6(a: Ipv6Addr, b: Ipv6Addr, bits: u8) -> bool {
    let bits = u32::from(bits.min(128));
    let mask = if bits == 0 {
        0
    } else {
        u128::MAX << (128 - bits)
    };
    (u128::from(a) & mask) == (u128::from(b) & mask)
}

/// True when both addresses agree under `mode`. An IPv4 and a native IPv6
/// address never agree.
pub fn ip_matches(mode: IpBinding, bound: IpAddr, observed: IpAddr) -> bool {
    let (bound, observed) = (normalize_ip(bound), normalize_ip(observed));
    match mode {
        IpBinding::Off => true,
        IpBinding::Strict => bound == observed,
        IpBinding::Prefix { v4, v6 } => match (bound, observed) {
            (IpAddr::V4(a), IpAddr::V4(b)) => prefix_v4(a, b, v4),
            (IpAddr::V6(a), IpAddr::V6(b)) => prefix_v6(a, b, v6),
            _ => false,
        },
    }
}

/// Evaluate the application's binding policy for one request. The IP signal
/// is checked first, then the user agent. A strict user-agent policy with no
/// recorded digest or no observed header fails closed unless both are absent.
pub fn check(
    policy: &BindingPolicy,
    bound_ip: IpAddr,
    bound_ua_sha256: Option<&Digest>,
    observed_ip: IpAddr,
    observed_ua: Option<&str>,
) -> BindingVerdict {
    let action = policy.on_mismatch;
    if !ip_matches(policy.ip, bound_ip, observed_ip) {
        return BindingVerdict::Mismatch {
            signal: BindSignal::Ip,
            action,
        };
    }
    if policy.ua == UaBinding::Strict {
        let observed = observed_ua.map(|u| sha256(u.as_bytes()));
        if observed.as_ref() != bound_ua_sha256 {
            return BindingVerdict::Mismatch {
                signal: BindSignal::Ua,
                action,
            };
        }
    }
    BindingVerdict::Ok
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn policy(ip: IpBinding) -> BindingPolicy {
        BindingPolicy {
            ip,
            ..BindingPolicy::default()
        }
    }

    #[test]
    fn strict_prefix_and_off() {
        let b = ip("203.0.113.9");
        let strict = policy(IpBinding::Strict);
        assert_eq!(check(&strict, b, None, b, None), BindingVerdict::Ok);
        assert_eq!(
            check(&strict, b, None, ip("203.0.113.10"), None),
            BindingVerdict::Mismatch {
                signal: BindSignal::Ip,
                action: OnMismatch::TerminateSession
            }
        );
        let prefix = policy(IpBinding::Prefix { v4: 24, v6: 64 });
        assert_eq!(
            check(&prefix, b, None, ip("203.0.113.200"), None),
            BindingVerdict::Ok
        );
        assert!(matches!(
            check(&prefix, b, None, ip("203.0.114.1"), None),
            BindingVerdict::Mismatch { .. }
        ));
        let off = policy(IpBinding::Off);
        assert_eq!(
            check(&off, b, None, ip("198.51.100.7"), None),
            BindingVerdict::Ok
        );
    }

    #[test]
    fn ipv6_prefix_and_mapped_forms() {
        let prefix = policy(IpBinding::Prefix { v4: 24, v6: 64 });
        let b = ip("2001:db8:1:2::1");
        assert_eq!(
            check(&prefix, b, None, ip("2001:db8:1:2:ffff::9"), None),
            BindingVerdict::Ok
        );
        assert!(matches!(
            check(&prefix, b, None, ip("2001:db8:1:3::1"), None),
            BindingVerdict::Mismatch { .. }
        ));
        let strict = policy(IpBinding::Strict);
        assert_eq!(
            check(
                &strict,
                ip("::ffff:203.0.113.9"),
                None,
                ip("203.0.113.9"),
                None
            ),
            BindingVerdict::Ok
        );
        assert!(matches!(
            check(&prefix, ip("203.0.113.9"), None, ip("2001:db8::1"), None),
            BindingVerdict::Mismatch { .. }
        ));
    }

    #[test]
    fn user_agent_binding_compares_digests_and_fails_closed() {
        let p = BindingPolicy {
            ua: UaBinding::Strict,
            ip: IpBinding::Off,
            on_mismatch: OnMismatch::DropHandle,
        };
        let d = sha256(b"UA1");
        let a = ip("192.0.2.1");
        assert_eq!(check(&p, a, Some(&d), a, Some("UA1")), BindingVerdict::Ok);
        assert_eq!(
            check(&p, a, Some(&d), a, Some("UA2")),
            BindingVerdict::Mismatch {
                signal: BindSignal::Ua,
                action: OnMismatch::DropHandle
            }
        );
        assert!(matches!(
            check(&p, a, Some(&d), a, None),
            BindingVerdict::Mismatch { .. }
        ));
        assert!(matches!(
            check(&p, a, None, a, Some("UA1")),
            BindingVerdict::Mismatch { .. }
        ));
        assert_eq!(check(&p, a, None, a, None), BindingVerdict::Ok);
    }
}
