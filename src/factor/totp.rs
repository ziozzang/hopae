//! RFC 6238 TOTP arithmetic; a counter match is not authentication evidence.
//! The caller must atomically consume the counter and challenge under the DB authority.
use crate::crypto::{Secret, Timestamp};
use hmac::{Hmac, Mac};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub struct Seed(Zeroizing<Vec<u8>>);
impl Seed {
    pub(super) fn bytes(&self) -> &[u8] {
        &self.0
    }
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        (20..=128)
            .contains(&bytes.len())
            .then(|| Self(Zeroizing::new(bytes.to_vec())))
    }
}
impl std::fmt::Debug for Seed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Seed(<redacted>)")
    }
}
#[derive(Clone, Copy, Debug)]
pub enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}
#[derive(Clone, Copy, Debug)]
pub struct Parameters {
    algorithm: Algorithm,
    digits: usize,
}
impl Default for Parameters {
    fn default() -> Self {
        Self {
            algorithm: Algorithm::Sha1,
            digits: 6,
        }
    }
}
impl Parameters {
    pub fn new(algorithm: Algorithm, digits: usize) -> Option<Self> {
        matches!(digits, 6 | 8).then_some(Self { algorithm, digits })
    }
    fn code(&self, seed: &Seed, counter: u64) -> Vec<u8> {
        let message = counter.to_be_bytes();
        macro_rules! digest {
            ($hash:ty) => {{
                let mut mac =
                    Hmac::<$hash>::new_from_slice(&seed.0).expect("HMAC accepts bounded seed");
                mac.update(&message);
                mac.finalize().into_bytes().to_vec()
            }};
        }
        let hash = Zeroizing::new(match self.algorithm {
            Algorithm::Sha1 => digest!(sha1::Sha1),
            Algorithm::Sha256 => digest!(sha2::Sha256),
            Algorithm::Sha512 => digest!(sha2::Sha512),
        });
        let offset = usize::from(hash[hash.len() - 1] & 15);
        let value = u32::from_be_bytes(
            hash[offset..offset + 4]
                .try_into()
                .expect("HMAC truncation fits"),
        ) & 0x7fff_ffff;
        let mut value = value % 10u32.pow(self.digits as u32);
        let mut code = vec![b'0'; self.digits];
        for byte in code.iter_mut().rev() {
            *byte += (value % 10) as u8;
            value /= 10;
        }
        code
    }
    /// Check a 30-second step with at most one adjacent step on each side.
    /// The watermark must be durable; the returned counter still needs atomic CAS.
    /// A caller must not issue a session or AAL directly from this result.
    pub fn matching_counter(
        &self,
        seed: &Seed,
        now: Timestamp,
        code: &Secret,
        last_accepted: Option<u64>,
    ) -> Option<u64> {
        if now.0 < 0
            || code.expose().len() != self.digits
            || !code.expose().bytes().all(|b| b.is_ascii_digit())
        {
            return None;
        }
        let current = (now.0 as u64) / 30_000;
        let mut matched = None;
        for counter in [
            current.checked_sub(1),
            Some(current),
            current.checked_add(1),
        ]
        .into_iter()
        .flatten()
        {
            let expected = Zeroizing::new(self.code(seed, counter));
            let equal = bool::from(expected.as_slice().ct_eq(code.expose().as_bytes()));
            if equal && last_accepted.is_none_or(|last| counter > last) {
                matched = Some(counter);
            }
        }
        matched
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rfc6238_vectors_all_algorithms_and_large_times() {
        // RFC 6238 Appendix B, using its algorithm-specific public test keys.
        let sha1 = Seed::from_bytes(b"12345678901234567890").unwrap();
        let sha256 = Seed::from_bytes(b"12345678901234567890123456789012").unwrap();
        let sha512 =
            Seed::from_bytes(b"1234567890123456789012345678901234567890123456789012345678901234")
                .unwrap();
        for (time, codes) in [
            (59, ["94287082", "46119246", "90693936"]),
            (1111111109, ["07081804", "68084774", "25091201"]),
            (1111111111, ["14050471", "67062674", "99943326"]),
            (1234567890, ["89005924", "91819424", "93441116"]),
            (2000000000, ["69279037", "90698825", "38618901"]),
            (20000000000, ["65353130", "77737706", "47863826"]),
        ] {
            for ((algorithm, seed), expected) in [
                (Algorithm::Sha1, &sha1),
                (Algorithm::Sha256, &sha256),
                (Algorithm::Sha512, &sha512),
            ]
            .into_iter()
            .zip(codes)
            {
                let parameters = Parameters::new(algorithm, 8).unwrap();
                assert_eq!(parameters.code(seed, time / 30), expected.as_bytes());
                assert_eq!(
                    parameters.matching_counter(
                        seed,
                        Timestamp((time * 1000) as i64),
                        &Secret::new(expected.into()),
                        None
                    ),
                    Some(time / 30)
                );
            }
        }
    }
    #[test]
    fn bounds_input_window_and_replay_watermark() {
        let seed = Seed::from_bytes(b"12345678901234567890").unwrap();
        let parameters = Parameters::default();
        let code = Secret::new("287082".into());
        assert_eq!(
            parameters.matching_counter(&seed, Timestamp(59_000), &code, None),
            Some(1)
        );
        assert_eq!(
            parameters.matching_counter(&seed, Timestamp(60_000), &code, None),
            Some(1)
        );
        assert_eq!(
            parameters.matching_counter(&seed, Timestamp(90_000), &code, None),
            None
        );
        assert_eq!(
            parameters.matching_counter(&seed, Timestamp(59_000), &code, Some(1)),
            None
        );
        assert_eq!(
            parameters.matching_counter(&seed, Timestamp(29_000), &code, Some(1)),
            None
        );
        assert_eq!(
            parameters.matching_counter(&seed, Timestamp(-1), &code, None),
            None
        );
        for malformed in ["", "28708", "0287082", "28708x", "２８７０８２", "287082 "] {
            assert_eq!(
                parameters.matching_counter(
                    &seed,
                    Timestamp(59_000),
                    &Secret::new(malformed.into()),
                    None
                ),
                None
            );
        }
        assert!(Seed::from_bytes(&[0; 19]).is_none());
        assert!(Seed::from_bytes(&[0; 129]).is_none());
        assert!(Parameters::new(Algorithm::Sha1, 7).is_none());
        assert_eq!(format!("{seed:?}"), "Seed(<redacted>)");
    }
}
