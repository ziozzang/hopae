//! Numeric rate qualification only: these fixtures do not authenticate an owner
//! observation or grant permission. Physical-time comparisons use exact integers.
use ed25519_dalek::SigningKey;
use hopae_grpc::{
    receipt::{self, Claims, Purpose, SignatureEvidence},
    receipt_time::{Bounds, ClockRates, Exchange, Report},
};

const PARTS: i128 = 1_000_000;
const LOCAL: i128 = 10_000;
const SIGNED_REMAINING: i128 = 900;

fn evidence() -> SignatureEvidence {
    let key = SigningKey::from_bytes(&[7; 32]);
    let bytes = receipt::sign(
        &key,
        &Claims {
            purpose: Purpose::Authentication,
            issued_ms: 1000,
            expires_ms: 2000,
            binding: [3; 32],
            nonce: [9; 32],
        },
    )
    .unwrap();
    receipt::verify_signature(
        &key.verifying_key(),
        &bytes,
        Purpose::Authentication,
        &[3; 32],
    )
    .unwrap()
}

fn report(proof: &SignatureEvidence, remaining_ms: u32) -> Report {
    Report {
        owner_now_ms: 1100,
        remaining_ms,
        receipt_sha256: *proof.sha256(),
    }
}

// Source observation is at physical time zero. Clock phases are millionths of
// one millisecond; latency is physical microseconds. Rates have denominator 1e6.
fn exchange(
    receiver_rate: i128,
    receiver_phase: i128,
    outbound_us: i128,
    inbound_us: i128,
) -> Exchange {
    let origin = (LOCAL * PARTS + receiver_phase) * 1000;
    let denominator = PARTS * 1000;
    Exchange {
        before_ms: u64::try_from((origin - receiver_rate * outbound_us) / denominator).unwrap(),
        after_ms: u64::try_from((origin + receiver_rate * inbound_us) / denominator).unwrap(),
        elapsed_ms: u64::try_from(receiver_rate * (outbound_us + inbound_us) / denominator)
            .unwrap(),
    }
}

// Compare physical times by cross multiplication. This does not recompute the
// implementation's outward-rounded delta formulas.
fn brackets_physical_expiry(
    bounds: &Bounds,
    remaining_ms: u32,
    source_rate: i128,
    receiver_rate: i128,
    source_phase: i128,
    receiver_phase: i128,
) -> (bool, bool) {
    let receiver_origin = LOCAL * PARTS + receiver_phase;
    let admission = i128::from(bounds.admit_until_ms()) * PARTS - receiver_origin;
    let retention = i128::from(bounds.retain_until_ms()) * PARTS - receiver_origin;
    let prerequisite = i128::from(remaining_ms) * PARTS - source_phase;
    let signed_expiry = SIGNED_REMAINING * PARTS - source_phase;
    (
        admission * source_rate <= prerequisite * receiver_rate,
        retention * source_rate >= signed_expiry * receiver_rate,
    )
}

#[test]
fn explicit_rate_limits_validate_denominators_and_keep_equal_rate_compatibility() {
    for (source, receiver) in [(0, 0), (1, 1), (999_999, 0), (0, 999_999)] {
        assert!(ClockRates::new(source, receiver).is_ok());
    }
    for (source, receiver) in [(1_000_000, 0), (0, 1_000_000), (u32::MAX, 1), (1, u32::MAX)] {
        assert!(ClockRates::new(source, receiver).is_err());
    }
    let proof = evidence();
    let observation = report(&proof, 300);
    let samples = exchange(PARTS, 999_999, 2000, 3000);
    let original = Bounds::from_signature(&proof, &observation, &samples).unwrap();
    let explicit = Bounds::from_signature_with_rates(
        &proof,
        &observation,
        &samples,
        &ClockRates::new(0, 0).unwrap(),
    )
    .unwrap();
    assert_eq!(original.admit_until_ms(), explicit.admit_until_ms());
    assert_eq!(original.retain_until_ms(), explicit.retain_until_ms());
}

#[test]
fn equal_rate_rounding_alone_has_physical_counterexamples_with_oscillator_error() {
    let proof = evidence();
    let observation = report(&proof, 900);
    let rates = ClockRates::new(1000, 2000).unwrap();
    // Fast source plus slow receiver extends the old admission budget.
    // Slow source plus fast receiver ends the old replay retention too soon.
    for (source_rate, receiver_rate, source_phase, receiver_phase, admission_failure) in [
        (PARTS + 1000, PARTS - 2000, PARTS - 1, 0, true),
        (PARTS - 1000, PARTS + 2000, 0, PARTS - 1, false),
    ] {
        let samples = exchange(receiver_rate, receiver_phase, 0, 0);
        let old = Bounds::from_signature(&proof, &observation, &samples).unwrap();
        let old_safety = brackets_physical_expiry(
            &old,
            900,
            source_rate,
            receiver_rate,
            source_phase,
            receiver_phase,
        );
        assert!(
            !(if admission_failure {
                old_safety.0
            } else {
                old_safety.1
            })
        );
        let bounded =
            Bounds::from_signature_with_rates(&proof, &observation, &samples, &rates).unwrap();
        assert_eq!(
            brackets_physical_expiry(
                &bounded,
                900,
                source_rate,
                receiver_rate,
                source_phase,
                receiver_phase
            ),
            (true, true),
        );
    }
}

#[test]
fn independent_oscillator_limits_bracket_exact_physical_expiries_and_latency() {
    let proof = evidence();
    let mut accepted = 0;
    for (source_ppm, receiver_ppm) in [(0_u32, 0_u32), (1, 7), (1000, 2000), (25_000, 50_000)] {
        let rates = ClockRates::new(source_ppm, receiver_ppm).unwrap();
        for source_rate in [
            PARTS - i128::from(source_ppm),
            PARTS + i128::from(source_ppm),
        ] {
            for receiver_rate in [
                PARTS - i128::from(receiver_ppm),
                PARTS + i128::from(receiver_ppm),
            ] {
                for source_phase in [0, 1, PARTS - 1] {
                    for receiver_phase in [0, 1, PARTS - 1] {
                        for outbound in [0, 1, 999, 2500] {
                            for inbound in [0, 1, 999, 2500] {
                                let samples =
                                    exchange(receiver_rate, receiver_phase, outbound, inbound);
                                for remaining in [100, 300, 900] {
                                    let bounds = Bounds::from_signature_with_rates(
                                        &proof,
                                        &report(&proof, remaining),
                                        &samples,
                                        &rates,
                                    )
                                    .unwrap();
                                    assert_eq!(
                                        brackets_physical_expiry(
                                            &bounds,
                                            remaining,
                                            source_rate,
                                            receiver_rate,
                                            source_phase,
                                            receiver_phase,
                                        ),
                                        (true, true),
                                        "source={source_rate}, receiver={receiver_rate}, phases={source_phase}/{receiver_phase}, latency={outbound}/{inbound}, remaining={remaining}",
                                    );
                                    accepted += 1;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    assert_eq!(accepted, 6912);
}

#[test]
fn rounding_shortens_admission_and_keeps_full_signed_retention() {
    let proof = evidence();
    let rates = ClockRates::new(1000, 2000).unwrap();
    let samples = exchange(PARTS, 0, 0, 0);
    let short =
        Bounds::from_signature_with_rates(&proof, &report(&proof, 300), &samples, &rates).unwrap();
    let full =
        Bounds::from_signature_with_rates(&proof, &report(&proof, 900), &samples, &rates).unwrap();
    assert_eq!(short.admit_until_ms(), 10_298);
    assert_eq!(short.retain_until_ms(), 10_904);
    assert!(short.admit_until_ms() < full.admit_until_ms());
    assert_eq!(short.retain_until_ms(), full.retain_until_ms());
    for remaining in [0, 1] {
        assert!(
            Bounds::from_signature_with_rates(&proof, &report(&proof, remaining), &samples, &rates)
                .is_err()
        );
    }
    let near_stopped = ClockRates::new(999_999, 999_999).unwrap();
    assert!(
        Bounds::from_signature_with_rates(&proof, &report(&proof, 900), &samples, &near_stopped)
            .is_err()
    );
}

#[test]
fn rate_adjusted_deadlines_refuse_precision_limit_and_integer_overflow() {
    let proof = evidence();
    let observation = report(&proof, 900);
    let rates = ClockRates::new(1000, 2000).unwrap();
    for before in [9_007_199_254_740_991 - 902, u64::MAX - 10, u64::MAX] {
        let samples = Exchange {
            before_ms: before,
            after_ms: before,
            elapsed_ms: 0,
        };
        assert!(Bounds::from_signature_with_rates(&proof, &observation, &samples, &rates).is_err());
    }
}
