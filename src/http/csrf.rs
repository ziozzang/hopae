//! CSRF tokens for the portal's forms.
//!
//! A token is `<nonce>.<issued-at>.<mac>` where the MAC is HMAC-SHA-256 over a
//! domain tag, the SHA-256 of the value the token is bound to (the portal
//! binding cookie, or the portal handle for logout), the purpose, the nonce and
//! the issue time. Tokens live ten minutes. The key is random per process, so a
//! restart invalidates outstanding tokens (they are 10 minutes old at most).

use std::time::Duration;

use data_encoding::BASE64URL_NOPAD;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::crypto::{Rng, Timestamp};

/// How long a token is accepted.
pub const TOKEN_TTL: Duration = Duration::from_secs(600);
/// Tolerated clock difference for a token stamped in the future.
const FUTURE_SKEW_SECS: i64 = 5;
const DOMAIN_TAG: &[u8] = b"hopae-csrf-v1";

/// What a token authorizes; a token for one purpose is refused for another.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Purpose {
    TotpStepUp,
    TotpPrepare,
    TotpConfirm,
    Login,
    Retry,
    Switch,
    Continue,
    Logout,
    /// A console form (ADR-0016), bound to the handle value.
    Admin,
}

impl Purpose {
    pub fn as_str(self) -> &'static str {
        match self {
            Purpose::TotpStepUp => "totp_stepup",
            Purpose::TotpPrepare => "totp_prepare",
            Purpose::TotpConfirm => "totp_confirm",
            Purpose::Login => "login",
            Purpose::Retry => "retry",
            Purpose::Switch => "switch",
            Purpose::Continue => "continue",
            Purpose::Logout => "logout",
            Purpose::Admin => "admin",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CsrfError {
    /// Absent, wrong shape or not decodable.
    Malformed,
    /// MAC mismatch: another binding, another purpose, another key or a forged token.
    Invalid,
    /// Authentic but older than [`TOKEN_TTL`] (or stamped in the future).
    Expired,
}

impl CsrfError {
    pub fn label(self) -> &'static str {
        match self {
            CsrfError::Malformed | CsrfError::Invalid => "token",
            CsrfError::Expired => "expired",
        }
    }
}

/// The process-wide MAC key. Never printed.
#[derive(Clone)]
pub struct CsrfKey([u8; 32]);

impl CsrfKey {
    pub fn new(bytes: [u8; 32]) -> Self {
        CsrfKey(bytes)
    }

    pub fn random(rng: &dyn Rng) -> Self {
        let mut b = [0u8; 32];
        rng.fill(&mut b);
        CsrfKey(b)
    }
}

impl std::fmt::Debug for CsrfKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CsrfKey(<redacted>)")
    }
}

type HmacSha256 = Hmac<Sha256>;

fn mac_for(key: &CsrfKey, binding: &str, purpose: Purpose, nonce: &[u8], ts: i64) -> HmacSha256 {
    // HMAC accepts keys of any length, so construction cannot fail for a 32-byte key.
    let mut mac = <HmacSha256 as Mac>::new_from_slice(&key.0)
        .unwrap_or_else(|_| unreachable!("HMAC accepts any key length"));
    mac.update(DOMAIN_TAG);
    mac.update(&[0]);
    mac.update(&crate::crypto::sha256(binding.as_bytes()).0);
    mac.update(&[0]);
    mac.update(purpose.as_str().as_bytes());
    mac.update(&[0]);
    mac.update(nonce);
    mac.update(&[0]);
    mac.update(&ts.to_be_bytes());
    mac
}

/// Issue a token for `binding` (the value the browser must also present).
pub fn issue(
    key: &CsrfKey,
    binding: &str,
    purpose: Purpose,
    now: Timestamp,
    rng: &dyn Rng,
) -> String {
    let mut nonce = [0u8; 16];
    rng.fill(&mut nonce);
    let ts = now.secs();
    let tag = mac_for(key, binding, purpose, &nonce, ts)
        .finalize()
        .into_bytes();
    format!(
        "{}.{}.{}",
        BASE64URL_NOPAD.encode(&nonce),
        ts,
        BASE64URL_NOPAD.encode(&tag)
    )
}

/// Check a presented token against the binding and purpose it must carry.
pub fn verify(
    key: &CsrfKey,
    binding: &str,
    purpose: Purpose,
    token: &str,
    now: Timestamp,
) -> Result<(), CsrfError> {
    if token.len() > 256 {
        return Err(CsrfError::Malformed);
    }
    let mut parts = token.split('.');
    let (Some(n), Some(t), Some(m), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(CsrfError::Malformed);
    };
    let nonce = BASE64URL_NOPAD
        .decode(n.as_bytes())
        .map_err(|_| CsrfError::Malformed)?;
    let tag = BASE64URL_NOPAD
        .decode(m.as_bytes())
        .map_err(|_| CsrfError::Malformed)?;
    let ts: i64 = t.parse().map_err(|_| CsrfError::Malformed)?;
    if nonce.len() != 16 || tag.len() != 32 {
        return Err(CsrfError::Malformed);
    }
    // Constant-time MAC comparison first; only an authentic token reveals its age.
    mac_for(key, binding, purpose, &nonce, ts)
        .verify_slice(&tag)
        .map_err(|_| CsrfError::Invalid)?;
    let age = now.secs().saturating_sub(ts);
    let ttl = i64::try_from(TOKEN_TTL.as_secs()).unwrap_or(i64::MAX);
    if age > ttl || age < -FUTURE_SKEW_SECS {
        return Err(CsrfError::Expired);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SeededRng;

    fn key() -> CsrfKey {
        CsrfKey::new([7u8; 32])
    }

    const P1: &str = "AAAAAAAAAAAAAAAAAAAAAA";
    const P2: &str = "BBBBBBBBBBBBBBBBBBBBBB";

    #[test]
    fn roundtrip_accepts_matching_binding_and_purpose() {
        let rng = SeededRng::new(1);
        let now = Timestamp(1_800_000_000_000);
        let t = issue(&key(), P1, Purpose::Login, now, &rng);
        assert_eq!(verify(&key(), P1, Purpose::Login, &t, now), Ok(()));
        // Just inside the lifetime.
        let later = now.add(Duration::from_secs(599));
        assert_eq!(verify(&key(), P1, Purpose::Login, &t, later), Ok(()));
    }

    #[test]
    fn token_is_bound_to_the_cookie() {
        let rng = SeededRng::new(1);
        let now = Timestamp(1_800_000_000_000);
        let t = issue(&key(), P1, Purpose::Login, now, &rng);
        assert_eq!(
            verify(&key(), P2, Purpose::Login, &t, now),
            Err(CsrfError::Invalid)
        );
        assert_eq!(
            verify(&key(), "", Purpose::Login, &t, now),
            Err(CsrfError::Invalid)
        );
    }

    #[test]
    fn token_is_bound_to_the_purpose() {
        let rng = SeededRng::new(1);
        let now = Timestamp(1_800_000_000_000);
        let t = issue(&key(), P1, Purpose::Logout, now, &rng);
        for other in [
            Purpose::Login,
            Purpose::Retry,
            Purpose::Switch,
            Purpose::Continue,
            Purpose::Admin,
        ] {
            assert_eq!(
                verify(&key(), P1, other, &t, now),
                Err(CsrfError::Invalid),
                "{other:?}"
            );
        }
    }

    #[test]
    fn an_admin_token_is_its_own_purpose_bound_to_the_handle() {
        let rng = SeededRng::new(2);
        let now = Timestamp(1_800_000_000_000);
        assert_eq!(Purpose::Admin.as_str(), "admin");
        let t = issue(&key(), P1, Purpose::Admin, now, &rng);
        assert_eq!(verify(&key(), P1, Purpose::Admin, &t, now), Ok(()));
        assert_eq!(
            verify(&key(), P2, Purpose::Admin, &t, now),
            Err(CsrfError::Invalid)
        );
        for other in [
            Purpose::Login,
            Purpose::Retry,
            Purpose::Switch,
            Purpose::Continue,
            Purpose::Logout,
        ] {
            assert_eq!(
                verify(&key(), P1, other, &t, now),
                Err(CsrfError::Invalid),
                "{other:?}"
            );
        }
    }

    #[test]
    fn token_expires_after_ten_minutes() {
        let rng = SeededRng::new(1);
        let now = Timestamp(1_800_000_000_000);
        let t = issue(&key(), P1, Purpose::Switch, now, &rng);
        let late = now.add(Duration::from_secs(601));
        assert_eq!(
            verify(&key(), P1, Purpose::Switch, &t, late),
            Err(CsrfError::Expired)
        );
        // A token stamped far in the future is not accepted either.
        let early = now.sub(Duration::from_secs(60));
        assert_eq!(
            verify(&key(), P1, Purpose::Switch, &t, early),
            Err(CsrfError::Expired)
        );
    }

    #[test]
    fn another_key_or_a_tampered_token_is_invalid() {
        let rng = SeededRng::new(1);
        let now = Timestamp(1_800_000_000_000);
        let t = issue(&key(), P1, Purpose::Login, now, &rng);
        assert_eq!(
            verify(&CsrfKey::new([8u8; 32]), P1, Purpose::Login, &t, now),
            Err(CsrfError::Invalid)
        );
        // Flip the last character of the MAC.
        let mut bad = t.clone();
        let last = bad.pop().unwrap();
        bad.push(if last == 'A' { 'B' } else { 'A' });
        assert_eq!(
            verify(&key(), P1, Purpose::Login, &bad, now),
            Err(CsrfError::Invalid)
        );
        // Moving the issue time forward to dodge expiry breaks the MAC.
        let parts: Vec<&str> = t.split('.').collect();
        let ts: i64 = parts[1].parse().unwrap();
        let forged = format!("{}.{}.{}", parts[0], ts + 1000, parts[2]);
        assert_eq!(
            verify(
                &key(),
                P1,
                Purpose::Login,
                &forged,
                now.add(Duration::from_secs(1000))
            ),
            Err(CsrfError::Invalid)
        );
    }

    #[test]
    fn malformed_tokens_are_rejected_without_panicking() {
        let now = Timestamp(1_800_000_000_000);
        for t in [
            "",
            ".",
            "..",
            "a.b.c",
            "AAAA.notanumber.AAAA",
            "AAAA.1800000000.",
            &"x".repeat(10_000),
            "é.é.é",
        ] {
            assert!(
                matches!(
                    verify(&key(), P1, Purpose::Login, t, now),
                    Err(CsrfError::Malformed | CsrfError::Invalid)
                ),
                "{t:.20}"
            );
        }
    }

    #[test]
    fn tokens_carry_fresh_nonces_and_do_not_leak_the_binding() {
        let rng = SeededRng::new(1);
        let now = Timestamp(1_800_000_000_000);
        let a = issue(&key(), P1, Purpose::Login, now, &rng);
        let b = issue(&key(), P1, Purpose::Login, now, &rng);
        assert_ne!(a, b);
        assert!(!a.contains(P1));
        assert_eq!(format!("{:?}", key()), "CsrfKey(<redacted>)");
    }
}
