//! Consumer-facing checks: these primitives establish numeric/cryptographic
//! facts, not transport authentication, live ownership, or atomic replay admission.
use ed25519_dalek::SigningKey;
use hopae_grpc::{
    PrincipalKind, receipt,
    receipt_binding::{self, Context, Identity, Permit},
    receipt_time::{Bounds, Exchange, Report},
    service_epoch,
};

const MAXIMUM: u64 = 9_007_199_254_740_991;
const CLOCK_A: &str = "123456789abcdef0123456789abcdef0";
const CLOCK_B: &str = "223456789abcdef0123456789abcdef0";

fn proof(issued: u64, expires: u64, nonce: u8) -> receipt::VerifiedReceipt {
    let key = SigningKey::from_bytes(&[7; 32]);
    let raw = receipt::sign(
        &key,
        &receipt::Claims {
            purpose: receipt::Purpose::Authentication,
            issued_ms: issued,
            expires_ms: expires,
            binding: [3; 32],
            nonce: [nonce; 32],
        },
    )
    .unwrap();
    receipt::verify(
        &key.verifying_key(),
        &raw,
        receipt::Purpose::Authentication,
        &[3; 32],
        issued,
    )
    .unwrap()
}

fn report(proof: &receipt::VerifiedReceipt, now: u64, remaining: u32) -> Report {
    Report {
        owner_now_ms: now,
        remaining_ms: remaining,
        receipt_sha256: *proof.sha256(),
    }
}

fn context(epoch: &str) -> Context<'_> {
    Context {
        issuer_ref: "issuer",
        key_epoch: 1,
        identity_authority_epoch: epoch,
        identity: Identity {
            subject_ref: "worker",
            kind: PrincipalKind::Service,
            aal: 0,
            revision: 7,
            credential_generation: 7,
        },
        service: "orders",
        audience: "orders-api",
        request_sha256: [4; 32],
    }
}

#[test]
fn clock_epoch_round_trips_at_exact_wire_and_revision_limits() {
    for (base, profile, application) in [
        ("owner:service:old:app:realm".to_owned(), 7, 11),
        ("x".repeat(72), 1, 1),
        ("x".repeat(42), MAXIMUM, MAXIMUM),
    ] {
        let wire = service_epoch::encode_clock(&base, profile, application, CLOCK_A).unwrap();
        let decoded = service_epoch::decode_clock(&wire).unwrap();
        assert_eq!(decoded.epoch.authority, base);
        assert_eq!(decoded.epoch.profile_revision, profile);
        assert_eq!(decoded.epoch.application_generation, application);
        assert_eq!(decoded.clock_domain, CLOCK_A);
        assert_eq!(
            service_epoch::encode_clock(
                decoded.epoch.authority,
                decoded.epoch.profile_revision,
                decoded.epoch.application_generation,
                decoded.clock_domain,
            )
            .unwrap(),
            wire
        );
        if base.starts_with('x') {
            assert_eq!(wire.len(), 128);
            assert!(
                service_epoch::encode_clock(&(base.clone() + "x"), profile, application, CLOCK_A)
                    .is_err()
            );
            assert!(service_epoch::decode_clock(&(wire + "0")).is_err());
        }
    }
}

#[test]
fn hostile_clock_epoch_encodings_have_no_accepted_aliases() {
    for clock in [
        "",
        "0",
        "00000000000000000000000000000000",
        "123456789ABCDEF0123456789ABCDEF0",
        "123456789abcdef0123456789abcdefg",
        "123456789abcdef0123456789abcdef01",
        "１２３４５６７８９abcdef0123456789abcdef0",
    ] {
        assert!(service_epoch::encode_clock("owner", 1, 1, clock).is_err());
        assert!(
            service_epoch::decode_clock(&format!("clock1:{clock}:owner:service:1:app:1")).is_err()
        );
    }
    for suffix in [
        "owner:service:01:app:1",
        "owner:service:1:app:01",
        "owner:service:0:app:1",
        "owner:service:1:app:0",
        "owner:service:+1:app:1",
        "owner:service:1:app:-1",
        "owner:service:9007199254740992:app:1",
        "owner:service:1:app:9007199254740992",
        "owner:service:18446744073709551616:app:1",
        "owner:service:1:app:1\0",
        "owner:service:1:app:1\n",
        "owner:service:1:app:1:extra",
        ":service:1:app:1",
        "bad owner:service:1:app:1",
    ] {
        assert!(service_epoch::decode_clock(&format!("clock1:{CLOCK_A}:{suffix}")).is_err());
    }
    let canonical = service_epoch::encode_clock("owner", 1, 1, CLOCK_A).unwrap();
    for wire in [
        canonical.replacen("clock1:", "clock2:", 1),
        canonical.replacen("clock1:", "Clock1:", 1),
        format!(" {canonical}"),
        service_epoch::encode("owner", 1, 1).unwrap(),
    ] {
        assert!(service_epoch::decode_clock(&wire).is_err());
    }
}

#[test]
fn process_clock_change_invalidates_authentication_and_permit_bindings() {
    let first = service_epoch::encode_clock("owner", 7, 11, CLOCK_A).unwrap();
    let restarted = service_epoch::encode_clock("owner", 7, 11, CLOCK_B).unwrap();
    let legacy = service_epoch::encode("owner", 7, 11).unwrap();
    let key = SigningKey::from_bytes(&[8; 32]);
    let permit = Permit {
        authentication_receipt_sha256: [9; 32],
        decision_ref: "decision",
        resource: "orders",
        action: "read",
        authority_epoch: "policy-owner",
        catalog_revision: 1,
        policy_revision: 1,
        network_revision: 1,
        route_revision: 1,
        plan_revision: 1,
    };
    for (purpose, permit) in [
        (receipt::Purpose::Authentication, None),
        (receipt::Purpose::Permit, Some(&permit)),
    ] {
        let binding = receipt_binding::digest(&context(&first), permit).unwrap();
        let bytes = receipt::sign(
            &key,
            &receipt::Claims {
                purpose,
                issued_ms: 1000,
                expires_ms: 2000,
                binding,
                nonce: [1; 32],
            },
        )
        .unwrap();
        assert!(receipt::verify(&key.verifying_key(), &bytes, purpose, &binding, 1001).is_ok());
        for changed in [&restarted, &legacy] {
            let changed_binding = receipt_binding::digest(&context(changed), permit).unwrap();
            assert_ne!(binding, changed_binding);
            assert!(
                receipt::verify(
                    &key.verifying_key(),
                    &bytes,
                    purpose,
                    &changed_binding,
                    1001
                )
                .is_err()
            );
        }
    }
}

#[test]
fn physical_expiry_is_bracketed_under_independent_offsets_phases_and_asymmetry() {
    // Model physical time in microseconds, independently of the SDK's interval
    // algorithm. Owner expiry is the physical instant its integer clock reaches
    // the signed expiry; a shorter prerequisite has its own earlier instant.
    for phase_us in [0_i64, 1, 499, 998, 999] {
        let sample_us = 20_000_000 + phase_us;
        for owner_offset_us in [-9_000_999_i64, -1, 0, 1, 900_000_999] {
            let owner_now = ((sample_us + owner_offset_us) / 1000) as u64;
            let proof = proof(owner_now - 100, owner_now + 900, 1);
            let observation = report(&proof, owner_now, 200);
            let prerequisite_ends_us = (owner_now as i64 + 200) * 1000 - owner_offset_us;
            let signed_expires_us = (proof.claims().expires_ms as i64) * 1000 - owner_offset_us;
            for outbound_us in [0_i64, 1, 999, 47_001] {
                for inbound_us in [0_i64, 1, 999, 63_999] {
                    let bounds = Bounds::from_receipt(
                        &proof,
                        &observation,
                        &Exchange {
                            before_ms: ((sample_us - outbound_us) / 1000) as u64,
                            after_ms: ((sample_us + inbound_us) / 1000) as u64,
                            elapsed_ms: ((outbound_us + inbound_us) / 1000) as u64,
                        },
                    )
                    .unwrap();
                    assert!(bounds.admit_until_ms() * 1000 <= prerequisite_ends_us as u64);
                    assert!(bounds.retain_until_ms() * 1000 >= signed_expires_us as u64);
                }
            }
        }
    }
}

#[test]
fn reports_cannot_invent_lifetime_or_borrow_another_signed_receipt() {
    let proof = proof(1000, 2000, 1);
    let other = self::proof(1000, 2000, 2);
    let exchange = Exchange {
        before_ms: 10_000,
        after_ms: 10_005,
        elapsed_ms: 5,
    };
    assert!(Bounds::from_receipt(&proof, &report(&proof, 1100, 900), &exchange).is_ok());
    for (now, remaining) in [
        (999, 900),
        (2000, 1),
        (2001, 1),
        (1100, 901),
        (1100, 0),
        (1100, u32::MAX),
        (1999, 1),
    ] {
        assert!(Bounds::from_receipt(&proof, &report(&proof, now, remaining), &exchange).is_err());
    }
    assert!(Bounds::from_receipt(&proof, &report(&other, 1100, 900), &exchange).is_err());
    // The generic crypto format permits larger integers; clock conversion must
    // still enforce its interoperable integer ceiling on signed owner time.
    let oversized = self::proof(MAXIMUM - 100, MAXIMUM + 1, 3);
    assert!(
        Bounds::from_receipt(&oversized, &report(&oversized, MAXIMUM - 50, 50), &exchange).is_err()
    );
}

#[test]
fn hostile_local_clock_samples_refuse_instead_of_extending_admission() {
    let proof = proof(1000, 2000, 1);
    let observation = report(&proof, 1100, 900);
    for (before, after, elapsed) in [
        (0, 5, 5),
        (10_000, 9999, 0),
        (10_000, 10_005, 3),
        (10_000, 10_005, 7),
        (10_000, 11_001, 1001),
        (10_000, 10_000, 1001),
        (10_000, 10_899, 899),
        (MAXIMUM - 1, MAXIMUM, 1),
        (u64::MAX - 1, u64::MAX, 2),
    ] {
        assert!(
            Bounds::from_receipt(
                &proof,
                &observation,
                &Exchange {
                    before_ms: before,
                    after_ms: after,
                    elapsed_ms: elapsed,
                }
            )
            .is_err(),
            "accepted ({before}, {after}, {elapsed})"
        );
    }
    // One tick of quantization disagreement is expected in either direction.
    for elapsed in [4, 5, 6] {
        assert!(
            Bounds::from_receipt(
                &proof,
                &observation,
                &Exchange {
                    before_ms: 10_000,
                    after_ms: 10_005,
                    elapsed_ms: elapsed,
                }
            )
            .is_ok()
        );
    }
}

#[test]
fn revalidation_cannot_reopen_admission_or_erase_a_replay_horizon() {
    let proof = proof(1000, 2000, 1);
    let samples = [
        (1100, 80, 10_000, 10_020),
        (1150, 700, 10_040, 10_090),
        (1200, 500, 10_080, 10_085),
    ];
    let make = |index: usize| {
        let (now, remaining, before, after) = samples[index];
        Bounds::from_receipt(
            &proof,
            &report(&proof, now, remaining),
            &Exchange {
                before_ms: before,
                after_ms: after,
                elapsed_ms: after - before,
            },
        )
        .unwrap()
    };
    let earliest_admission = (0..3).map(|i| make(i).admit_until_ms()).min().unwrap();
    let latest_retention = (0..3).map(|i| make(i).retain_until_ms()).max().unwrap();
    for order in [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ] {
        let merged = make(order[2])
            .intersect(make(order[1]).intersect(make(order[0])).unwrap())
            .unwrap();
        assert_eq!(merged.admit_until_ms(), earliest_admission);
        assert_eq!(merged.retain_until_ms(), latest_retention);
        assert!(merged.retain_until_ms() > merged.admit_until_ms() + 700);
    }
    let short = make(0);
    let full = Bounds::from_receipt(
        &proof,
        &report(&proof, 1100, 900),
        &Exchange {
            before_ms: 10_000,
            after_ms: 10_020,
            elapsed_ms: 20,
        },
    )
    .unwrap();
    assert!(short.admit_until_ms() < full.admit_until_ms());
    assert_eq!(short.retain_until_ms(), full.retain_until_ms());
    let other = self::proof(1000, 2000, 2);
    let swapped = Bounds::from_receipt(
        &other,
        &report(&other, 1100, 80),
        &Exchange {
            before_ms: 10_000,
            after_ms: 10_020,
            elapsed_ms: 20,
        },
    )
    .unwrap();
    assert!(swapped.intersect(short).is_err());
}
