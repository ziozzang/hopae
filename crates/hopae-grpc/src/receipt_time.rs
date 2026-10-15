//! ADR 0018 interval arithmetic only, not authenticated transport or authorization.
//! Native adapters must bind owner role, request/client identity and live generation
//! before using this result. No caller-provided time value may grant access.
use crate::receipt::{SignatureEvidence, VerifiedReceipt};
use subtle::ConstantTimeEq;
const MAXIMUM: u64 = 9_007_199_254_740_991;
// Independent millisecond clocks may have different fractional tick phases.
const QUANTUM_MS: u64 = 1;
const PARTS: u128 = 1_000_000;
#[derive(Debug, PartialEq, Eq)]
pub struct Refused;
/// Independently established oscillator error bounds in parts per million.
/// This numeric model does not cover suspension, restore or a source clock step;
/// an observation remains point-in-time evidence, never a revocation lease.
pub struct ClockRates {
    source_ppm: u32,
    receiver_ppm: u32,
}
impl ClockRates {
    /// Explicit equal-rate assumption used by the original arithmetic API.
    pub const EQUAL: Self = Self {
        source_ppm: 0,
        receiver_ppm: 0,
    };
    pub fn new(source_ppm: u32, receiver_ppm: u32) -> Result<Self, Refused> {
        if u128::from(source_ppm) >= PARTS || u128::from(receiver_ppm) >= PARTS {
            return Err(Refused);
        }
        Ok(Self {
            source_ppm,
            receiver_ppm,
        })
    }
    /// Convert an already authenticated output owner's remaining budget into a
    /// conservative receiver-local lower expiry. This numeric result does not
    /// authenticate the report, authorize access, or establish replay retention.
    /// Anchor the exchange before sending the RPC, never after receiving it.
    pub fn remaining_admission_until(
        &self,
        remaining_ms: u32,
        exchange: &Exchange,
    ) -> Result<u64, Refused> {
        let wall_elapsed = exchange
            .after_ms
            .checked_sub(exchange.before_ms)
            .ok_or(Refused)?;
        if !(1..=1000).contains(&remaining_ms)
            || exchange.before_ms == 0
            || exchange.elapsed_ms > 1000
            || wall_elapsed > 1000
            || wall_elapsed.abs_diff(exchange.elapsed_ms) > 1
        {
            return Err(Refused);
        }
        let finish = exchange.after_ms.max(
            exchange
                .before_ms
                .checked_add(exchange.elapsed_ms)
                .ok_or(Refused)?,
        );
        let until = exchange
            .before_ms
            .checked_add(self.admission_delta(remaining_ms)?)
            .ok_or(Refused)?;
        if until <= finish || until > MAXIMUM {
            return Err(Refused);
        }
        Ok(until)
    }
    fn admission_delta(&self, remaining: u32) -> Result<u64, Refused> {
        let source_ticks = u64::from(remaining)
            .checked_sub(QUANTUM_MS)
            .ok_or(Refused)?;
        let delta = u128::from(source_ticks)
            .checked_mul(PARTS - u128::from(self.receiver_ppm))
            .ok_or(Refused)?
            / (PARTS + u128::from(self.source_ppm));
        u64::try_from(delta).map_err(|_| Refused)
    }
    fn retention_delta(&self, remaining: u64) -> Result<u64, Refused> {
        let delta = u128::from(remaining)
            .checked_mul(PARTS + u128::from(self.receiver_ppm))
            .ok_or(Refused)?
            .div_ceil(PARTS - u128::from(self.source_ppm));
        u64::try_from(delta)
            .map_err(|_| Refused)?
            .checked_add(QUANTUM_MS)
            .ok_or(Refused)
    }
}
/// Owner-domain values from an authenticated, request-bound native response.
pub struct Report {
    pub owner_now_ms: u64,
    /// May be shortened by other live prerequisites; never renews signed lifetime.
    pub remaining_ms: u32,
    pub receipt_sha256: [u8; 32],
}
/// Samples around one bounded RPC, in the receiving process's own clock domain.
pub struct Exchange {
    pub before_ms: u64,
    pub after_ms: u64,
    pub elapsed_ms: u64,
}
/// Numeric bounds, never a receipt-admission or secret-release capability.
/// Intentionally no Clone/Debug/serde. The original cryptographic proof is required.
pub struct Bounds {
    digest: [u8; 32],
    admit_until_ms: u64,
    retain_until_ms: u64,
}
impl Bounds {
    pub fn from_receipt(
        proof: &VerifiedReceipt,
        report: &Report,
        exchange: &Exchange,
    ) -> Result<Self, Refused> {
        Self::from_signature(proof.evidence(), report, exchange)
    }
    /// Numeric conversion of signature evidence plus a separately authenticated
    /// source report. Neither argument authenticates transport or grants access.
    pub fn from_signature(
        proof: &SignatureEvidence,
        report: &Report,
        exchange: &Exchange,
    ) -> Result<Self, Refused> {
        Self::from_signature_with_rates(proof, report, exchange, &ClockRates::EQUAL)
    }
    /// Conservative numeric bounds under explicit source/receiver oscillator
    /// limits. Admission rounds down; retention rounds up. Native adapters own
    /// qualification of those limits and authentication of the source report.
    pub fn from_signature_with_rates(
        proof: &SignatureEvidence,
        report: &Report,
        exchange: &Exchange,
        rates: &ClockRates,
    ) -> Result<Self, Refused> {
        let claims = proof.claims();
        let signed_remaining = claims
            .expires_ms
            .checked_sub(report.owner_now_ms)
            .ok_or(Refused)?;
        let wall_elapsed = exchange
            .after_ms
            .checked_sub(exchange.before_ms)
            .ok_or(Refused)?;
        if !bool::from(proof.sha256().ct_eq(&report.receipt_sha256))
            || report.owner_now_ms < claims.issued_ms
            || claims.expires_ms > MAXIMUM
            || !(1..=1000).contains(&signed_remaining)
            || report.remaining_ms == 0
            || u64::from(report.remaining_ms) > signed_remaining
            || exchange.before_ms == 0
            || exchange.elapsed_ms > 1000
            || wall_elapsed > 1000
            // Millisecond sampling can round by one; larger discontinuity closes.
            || wall_elapsed.abs_diff(exchange.elapsed_ms) > 1
        {
            return Err(Refused);
        }
        let finish = exchange.after_ms.max(
            exchange
                .before_ms
                .checked_add(exchange.elapsed_ms)
                .ok_or(Refused)?,
        );
        let admit_until_ms = exchange
            .before_ms
            .checked_add(rates.admission_delta(report.remaining_ms)?)
            .ok_or(Refused)?;
        // Retain for the complete signed proof, not a shorter current observation.
        // A later owner query may report a longer prerequisite bound while the
        // same signed nonce is still alive. Cleaning at admit_until opens replay.
        let retain_until_ms = finish
            .checked_add(rates.retention_delta(signed_remaining)?)
            .ok_or(Refused)?;
        if admit_until_ms <= finish || retain_until_ms > MAXIMUM {
            return Err(Refused);
        }
        Ok(Self {
            digest: *proof.sha256(),
            admit_until_ms,
            retain_until_ms,
        })
    }
    pub fn admit_until_ms(&self) -> u64 {
        self.admit_until_ms
    }
    pub fn retain_until_ms(&self) -> u64 {
        self.retain_until_ms
    }
    /// Revalidation never extends prior admission or shortens nonce retention.
    pub fn intersect(self, previous: Self) -> Result<Self, Refused> {
        if !bool::from(self.digest.ct_eq(&previous.digest)) {
            return Err(Refused);
        }
        Ok(Self {
            digest: self.digest,
            admit_until_ms: self.admit_until_ms.min(previous.admit_until_ms),
            retain_until_ms: self.retain_until_ms.max(previous.retain_until_ms),
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::receipt::{self, Claims, Purpose};
    use ed25519_dalek::SigningKey;
    fn proof(issued_ms: u64, nonce: u8) -> receipt::VerifiedReceipt {
        let key = SigningKey::from_bytes(&[7; 32]);
        let raw = receipt::sign(
            &key,
            &Claims {
                purpose: Purpose::Authentication,
                issued_ms,
                expires_ms: issued_ms + 1000,
                binding: [3; 32],
                nonce: [nonce; 32],
            },
        )
        .unwrap();
        receipt::verify(
            &key.verifying_key(),
            &raw,
            Purpose::Authentication,
            &[3; 32],
            issued_ms + 100,
        )
        .unwrap()
    }
    fn report(proof: &VerifiedReceipt, remaining_ms: u32) -> Report {
        Report {
            owner_now_ms: proof.claims().issued_ms + 100,
            remaining_ms,
            receipt_sha256: *proof.sha256(),
        }
    }
    #[test]
    fn independent_owner_offsets_do_not_change_local_bounds() {
        for issued in [1, 1_000_000, MAXIMUM - 1000] {
            let proof = proof(issued, 1);
            let bounds = Bounds::from_receipt(
                &proof,
                &report(&proof, 900),
                &Exchange {
                    before_ms: 10000,
                    after_ms: 10005,
                    elapsed_ms: 5,
                },
            )
            .unwrap();
            assert_eq!(
                (bounds.admit_until_ms(), bounds.retain_until_ms()),
                (10899, 10906)
            );
        }
    }
    #[test]
    fn shortened_admission_cannot_shorten_full_signed_nonce_retention() {
        let proof = proof(1000, 1);
        let bounds = Bounds::from_receipt(
            &proof,
            &report(&proof, 300),
            &Exchange {
                before_ms: 10000,
                after_ms: 10040,
                elapsed_ms: 40,
            },
        )
        .unwrap();
        assert_eq!(bounds.admit_until_ms(), 10299);
        assert_eq!(bounds.retain_until_ms(), 10941);
        // Actual owner sample can fall anywhere inside the RPC. Its signed
        // expiry at local 10920 remains protected after admission ends at 10299.
        assert!(bounds.admit_until_ms() < 10920 && bounds.retain_until_ms() >= 10920);
    }
    #[test]
    fn latency_asymmetry_brackets_real_expiry_in_an_independent_clock_domain() {
        let proof = proof(1_000_000, 1);
        let observation = report(&proof, 300);
        // The source's observation happens at local 99,100, irrespective of
        // the source's absolute clock. Its original proof expires at 100,000;
        // a shorter live prerequisite ends at 99,400.
        for outbound in 0..=50 {
            for inbound in 0..=50 {
                let bounds = Bounds::from_receipt(
                    &proof,
                    &observation,
                    &Exchange {
                        before_ms: 99_100 - outbound,
                        after_ms: 99_100 + inbound,
                        elapsed_ms: outbound + inbound,
                    },
                )
                .unwrap();
                assert!(bounds.admit_until_ms() <= 99_400);
                assert!(bounds.retain_until_ms() >= 100_000);
            }
        }
    }

    #[test]
    fn independent_submillisecond_phases_cannot_extend_admission_or_erase_replay() {
        for phase_us in [0_i64, 1, 100, 500, 999] {
            let observation_us = 10_000_000 + phase_us;
            for offset_us in [-2001_i64, -999, -501, -1, 0, 1, 501, 999, 2001] {
                let owner_now_ms = ((observation_us + offset_us) / 1000) as u64;
                let proof = proof(owner_now_ms - 100, 1);
                let observation = report(&proof, 300);
                for outbound_us in [0_i64, 1, 999] {
                    for inbound_us in [0_i64, 1, 999] {
                        let bounds = Bounds::from_receipt(
                            &proof,
                            &observation,
                            &Exchange {
                                before_ms: ((observation_us - outbound_us) / 1000) as u64,
                                after_ms: ((observation_us + inbound_us) / 1000) as u64,
                                elapsed_ms: ((outbound_us + inbound_us) / 1000) as u64,
                            },
                        )
                        .unwrap();
                        let actual_admission_us = (owner_now_ms as i64 + 300) * 1000 - offset_us;
                        let actual_signed_expiry_us =
                            (owner_now_ms as i64 + 900) * 1000 - offset_us;
                        assert!(bounds.admit_until_ms() * 1000 <= actual_admission_us as u64);
                        assert!(bounds.retain_until_ms() * 1000 >= actual_signed_expiry_us as u64);
                    }
                }
            }
        }
    }

    #[test]
    fn hostile_report_discontinuity_expiry_and_overflow_refuse() {
        let proof = proof(1000, 1);
        for attack in 0..9 {
            let mut report = report(&proof, 900);
            let mut exchange = Exchange {
                before_ms: 10000,
                after_ms: 10005,
                elapsed_ms: 5,
            };
            match attack {
                0 => report.receipt_sha256[0] ^= 1,
                1 => report.owner_now_ms = 999,
                2 => report.owner_now_ms = 2000,
                3 => report.remaining_ms = 901,
                4 => report.remaining_ms = 0,
                5 => exchange.after_ms = 9999,
                6 => exchange.after_ms = 11000,
                7 => report.remaining_ms = 5,
                _ => {
                    exchange.before_ms = MAXIMUM - 10;
                    exchange.after_ms = MAXIMUM - 5;
                }
            }
            assert!(
                Bounds::from_receipt(&proof, &report, &exchange).is_err(),
                "attack {attack}"
            );
        }
    }
    #[test]
    fn refresh_intersects_admission_preserves_retention_and_rejects_swaps() {
        let proof = proof(1000, 1);
        let first = || {
            Bounds::from_receipt(
                &proof,
                &report(&proof, 300),
                &Exchange {
                    before_ms: 10000,
                    after_ms: 10040,
                    elapsed_ms: 40,
                },
            )
            .unwrap()
        };
        let second = Bounds::from_receipt(
            &proof,
            &Report {
                owner_now_ms: 1200,
                remaining_ms: 400,
                receipt_sha256: *proof.sha256(),
            },
            &Exchange {
                before_ms: 10100,
                after_ms: 10110,
                elapsed_ms: 10,
            },
        )
        .unwrap();
        let merged = second.intersect(first()).unwrap();
        assert_eq!(
            (merged.admit_until_ms(), merged.retain_until_ms()),
            (10299, 10941)
        );
        let other = super::tests::proof(1000, 2);
        let swapped = Bounds::from_receipt(
            &other,
            &report(&other, 900),
            &Exchange {
                before_ms: 10000,
                after_ms: 10005,
                elapsed_ms: 5,
            },
        )
        .unwrap();
        assert!(swapped.intersect(first()).is_err());
    }
}

#[cfg(test)]
mod remaining_tests {
    use super::*;
    #[test]
    fn output_budget_charges_whole_exchange_and_rejects_exact_expiry() {
        let exchange = Exchange {
            before_ms: 100,
            after_ms: 108,
            elapsed_ms: 8,
        };
        assert_eq!(
            ClockRates::EQUAL.remaining_admission_until(10, &exchange),
            Ok(109)
        );
        for remaining in [0, 1, 9, 1001] {
            assert!(
                ClockRates::EQUAL
                    .remaining_admission_until(remaining, &exchange)
                    .is_err()
            );
        }
    }
    #[test]
    fn malformed_and_overflowing_exchanges_close() {
        for (before_ms, after_ms, elapsed_ms) in [
            (0, 1, 1),
            (10, 9, 0),
            (10, 14, 1),
            (10, 1011, 1001),
            (u64::MAX - 1, u64::MAX, 2),
            (MAXIMUM - 1, MAXIMUM, 1),
        ] {
            let exchange = Exchange {
                before_ms,
                after_ms,
                elapsed_ms,
            };
            assert!(
                ClockRates::EQUAL
                    .remaining_admission_until(1000, &exchange)
                    .is_err()
            );
        }
    }
    #[test]
    fn lower_expiry_precedes_physical_expiry_at_independent_tick_phases() {
        // Nanosecond rational model: fastest source and slowest receiver.
        // Allow a full source quantization tick of report overstatement.
        for (source_ppm, receiver_ppm) in [(0, 0), (100, 200), (200_000, 300_000)] {
            let rates = ClockRates::new(source_ppm, receiver_ppm).unwrap();
            for phase in [0_u128, 1, 499_999, 999_999] {
                for outward_ms in [0_u64, 1, 7] {
                    let exchange = Exchange {
                        before_ms: 100,
                        after_ms: 110,
                        elapsed_ms: 10,
                    };
                    let until = rates.remaining_admission_until(100, &exchange).unwrap();
                    let receiver_deadline = u128::from(until - 100) * 1_000_000;
                    let actual_source_remaining = 99_u128 * 1_000_000 + phase;
                    let physical_remaining_receiver = actual_source_remaining
                        * (PARTS - u128::from(receiver_ppm))
                        / (PARTS + u128::from(source_ppm));
                    assert!(
                        receiver_deadline
                            <= physical_remaining_receiver + u128::from(outward_ms) * 1_000_000
                    );
                }
            }
        }
    }
}
