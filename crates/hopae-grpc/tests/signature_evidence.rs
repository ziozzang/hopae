//! Signature evidence is deliberately time-neutral. Numeric observations below
//! stand in for independently authenticated owner reports, not caller authority.
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use hopae_grpc::{
    receipt::{self, Claims, Purpose},
    receipt_time::{Bounds, Exchange, Report},
};
use sha2::{Digest, Sha256};

const BINDING: [u8; 32] = [3; 32];

#[test]
fn canonical_receipt_matches_independent_python_ed25519_vector() {
    // Generated independently with Python cryptography's Ed25519PrivateKey,
    // using seed [7; 32] and the version-one domain-prefixed wire payload.
    let hex = "01020000000000000064000000000000044c090909090909090909090909090909090909090909090909090909090909090908080808080808080808080808080808080808080808080808080808080808086ce76c370f64b735e06cf19424b45d1db18121a727f929476b454348778dedb7c37d0ad5687765cb9df43c26948a4a31632beecb003754c09bbffce74c326a09";
    let vector: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).unwrap())
        .collect();
    assert_eq!(vector.len(), receipt::LENGTH);
    let key = SigningKey::from_bytes(&[7; 32]);
    let emitted = receipt::sign(
        &key,
        &Claims {
            purpose: Purpose::Permit,
            issued_ms: 100,
            expires_ms: 1100,
            binding: [9; 32],
            nonce: [8; 32],
        },
    )
    .unwrap();
    assert_eq!(emitted.as_slice(), vector);
    let evidence =
        receipt::verify_signature(&key.verifying_key(), &vector, Purpose::Permit, &[9; 32])
            .unwrap();
    let strict = receipt::verify(
        &key.verifying_key(),
        &vector,
        Purpose::Permit,
        &[9; 32],
        101,
    )
    .unwrap();
    let expected_digest: [u8; 32] = Sha256::digest(&vector).into();
    assert_eq!(evidence.sha256(), &expected_digest);
    assert_eq!(strict.sha256(), &expected_digest);
    assert_eq!(evidence.claims().issued_ms, 100);
    assert_eq!(evidence.claims().expires_ms, 1100);
}

fn signed(key: &SigningKey, purpose: Purpose, issued: u64, expires: u64) -> [u8; receipt::LENGTH] {
    receipt::sign(
        key,
        &Claims {
            purpose,
            issued_ms: issued,
            expires_ms: expires,
            binding: BINDING,
            nonce: [9; 32],
        },
    )
    .unwrap()
}

#[test]
fn foreign_wall_offsets_need_no_invented_time_to_check_a_signature() {
    let key = SigningKey::from_bytes(&[7; 32]);
    let bytes = signed(&key, Purpose::Authentication, 1_000_000, 1_000_800);
    let evidence = receipt::verify_signature(
        &key.verifying_key(),
        &bytes,
        Purpose::Authentication,
        &BINDING,
    )
    .unwrap();
    let report = Report {
        owner_now_ms: 1_000_100,
        remaining_ms: 300,
        receipt_sha256: *evidence.sha256(),
    };
    // These are receiver-domain samples, respectively before and far after the
    // owner's signed numeric range. Neither is a valid strict issuer sample.
    for local_start in [20_u64, 9_000_000_000] {
        assert!(
            receipt::verify(
                &key.verifying_key(),
                &bytes,
                Purpose::Authentication,
                &BINDING,
                local_start,
            )
            .is_err()
        );
        let bounds = Bounds::from_signature(
            &evidence,
            &report,
            &Exchange {
                before_ms: local_start,
                after_ms: local_start + 20,
                elapsed_ms: 20,
            },
        )
        .unwrap();
        assert!(bounds.admit_until_ms() > local_start + 20);
        // If the source sample occurs anywhere in the round trip, no admitted
        // instant can outlive the short prerequisite, and no possible signed
        // expiry can outlive the retained nonce horizon.
        for source_sample in local_start..=local_start + 20 {
            assert!(bounds.admit_until_ms() <= source_sample + 300);
            assert!(bounds.retain_until_ms() >= source_sample + 700);
        }
    }
}

#[test]
fn strict_verification_still_enforces_issuer_time_and_preserves_exact_evidence() {
    let key = SigningKey::from_bytes(&[7; 32]);
    for purpose in [Purpose::Authentication, Purpose::Permit] {
        let bytes = signed(&key, purpose, 1000, 1800);
        let evidence =
            receipt::verify_signature(&key.verifying_key(), &bytes, purpose, &BINDING).unwrap();
        let exact_digest: [u8; 32] = Sha256::digest(bytes).into();
        assert_eq!(evidence.sha256(), &exact_digest);
        assert_eq!(evidence.claims().issued_ms, 1000);
        assert_eq!(evidence.claims().expires_ms, 1800);
        assert!(evidence.claims().purpose == purpose);
        for owner_now in [0, 999, 1800, u64::MAX] {
            assert!(
                receipt::verify(&key.verifying_key(), &bytes, purpose, &BINDING, owner_now)
                    .is_err()
            );
        }
        for owner_now in [1000, 1799] {
            let strict =
                receipt::verify(&key.verifying_key(), &bytes, purpose, &BINDING, owner_now)
                    .unwrap();
            assert_eq!(strict.sha256(), evidence.sha256());
            assert_eq!(strict.evidence().sha256(), evidence.sha256());
            assert_eq!(strict.evidence().claims().nonce, evidence.claims().nonce);
        }
    }
}

// A hostile authorized signer can produce structurally invalid wire claims.
// Construct its bytes independently: public sign() correctly refuses these
// values and therefore cannot exercise the receiving verifier's rejection.
fn externally_signed(
    key: &SigningKey,
    version: u8,
    purpose: u8,
    issued: u64,
    expires: u64,
    nonce: [u8; 32],
) -> Vec<u8> {
    let mut payload = vec![version, purpose];
    payload.extend_from_slice(&issued.to_be_bytes());
    payload.extend_from_slice(&expires.to_be_bytes());
    payload.extend_from_slice(&BINDING);
    payload.extend_from_slice(&nonce);
    let mut message = b"hangang-zerotrust:projection-receipt:v1\0".to_vec();
    message.extend_from_slice(&payload);
    let signature = key.sign(&message);
    key.verifying_key()
        .verify_strict(&message, &signature)
        .unwrap();
    payload.extend_from_slice(&signature.to_bytes());
    payload
}

#[test]
fn a_correct_signature_cannot_excuse_malformed_lifetime_nonce_or_wire_tags() {
    let key = SigningKey::from_bytes(&[7; 32]);
    let control = externally_signed(&key, 1, 1, 1000, 2000, [9; 32]);
    assert!(
        receipt::verify_signature(
            &key.verifying_key(),
            &control,
            Purpose::Authentication,
            &BINDING
        )
        .is_ok()
    );
    for (version, purpose, issued, expires, nonce) in [
        (1, 1, 0, 800, [9; 32]),
        (1, 1, 1000, 1000, [9; 32]),
        (1, 1, 1000, 999, [9; 32]),
        (1, 1, 1000, 2001, [9; 32]),
        (1, 1, 1, u64::MAX, [9; 32]),
        (1, 1, u64::MAX, 0, [9; 32]),
        (1, 1, 1000, 1800, [0; 32]),
        (2, 1, 1000, 1800, [9; 32]),
        (1, 0, 1000, 1800, [9; 32]),
        (1, 3, 1000, 1800, [9; 32]),
    ] {
        let bytes = externally_signed(&key, version, purpose, issued, expires, nonce);
        assert!(
            receipt::verify_signature(
                &key.verifying_key(),
                &bytes,
                Purpose::Authentication,
                &BINDING
            )
            .is_err()
        );
    }
}

#[test]
fn evidence_requires_exact_signature_key_purpose_binding_and_frame() {
    let key = SigningKey::from_bytes(&[7; 32]);
    let bytes = signed(&key, Purpose::Permit, 1000, 1800);
    assert!(
        receipt::verify_signature(&key.verifying_key(), &bytes, Purpose::Permit, &BINDING).is_ok()
    );
    assert!(
        receipt::verify_signature(
            &key.verifying_key(),
            &bytes,
            Purpose::Authentication,
            &BINDING
        )
        .is_err()
    );
    assert!(
        receipt::verify_signature(&key.verifying_key(), &bytes, Purpose::Permit, &[4; 32]).is_err()
    );
    let other_key = SigningKey::from_bytes(&[8; 32]);
    assert!(
        receipt::verify_signature(
            &other_key.verifying_key(),
            &bytes,
            Purpose::Permit,
            &BINDING
        )
        .is_err()
    );
    let mut identity_point = [0; 32];
    identity_point[0] = 1;
    let weak_key = VerifyingKey::from_bytes(&identity_point).unwrap();
    assert!(weak_key.is_weak());
    assert!(receipt::verify_signature(&weak_key, &bytes, Purpose::Permit, &BINDING).is_err());
    // Distinct payload fields and both ends of the signature must be checked.
    for index in [0, 1, 2, 10, 18, 50, 81, 82, receipt::LENGTH - 1] {
        let mut altered = bytes;
        altered[index] ^= 1;
        assert!(
            receipt::verify_signature(&key.verifying_key(), &altered, Purpose::Permit, &BINDING)
                .is_err()
        );
    }
    for length in [0, 1, 82, receipt::LENGTH - 1] {
        assert!(
            receipt::verify_signature(
                &key.verifying_key(),
                &bytes[..length],
                Purpose::Permit,
                &BINDING
            )
            .is_err()
        );
    }
    let mut appended = bytes.to_vec();
    appended.push(0);
    assert!(
        receipt::verify_signature(&key.verifying_key(), &appended, Purpose::Permit, &BINDING)
            .is_err()
    );
}

#[test]
fn time_neutral_evidence_cannot_revive_an_expired_or_unbound_owner_report() {
    let key = SigningKey::from_bytes(&[7; 32]);
    let bytes = signed(&key, Purpose::Authentication, 1_000_000, 1_000_800);
    let evidence = receipt::verify_signature(
        &key.verifying_key(),
        &bytes,
        Purpose::Authentication,
        &BINDING,
    )
    .unwrap();
    let exchange = Exchange {
        before_ms: 20_000,
        after_ms: 20_010,
        elapsed_ms: 10,
    };
    for (owner_now, remaining) in [
        (999_999, 100),
        (1_000_800, 1),
        (1_000_801, 1),
        (1_000_100, 701),
        (1_000_100, 0),
        (1_000_100, u32::MAX),
        (1_000_799, 1),
    ] {
        assert!(
            Bounds::from_signature(
                &evidence,
                &Report {
                    owner_now_ms: owner_now,
                    remaining_ms: remaining,
                    receipt_sha256: *evidence.sha256(),
                },
                &exchange
            )
            .is_err()
        );
    }
    let other_bytes = signed(&key, Purpose::Authentication, 1_000_000, 1_000_700);
    let other = receipt::verify_signature(
        &key.verifying_key(),
        &other_bytes,
        Purpose::Authentication,
        &BINDING,
    )
    .unwrap();
    assert!(
        Bounds::from_signature(
            &evidence,
            &Report {
                owner_now_ms: 1_000_100,
                remaining_ms: 300,
                receipt_sha256: *other.sha256(),
            },
            &exchange
        )
        .is_err()
    );
    let report = Report {
        owner_now_ms: 1_000_100,
        remaining_ms: 300,
        receipt_sha256: *evidence.sha256(),
    };
    assert!(Bounds::from_signature(&evidence, &report, &exchange).is_ok());
    let exhausted = Exchange {
        before_ms: 20_000,
        after_ms: 20_300,
        elapsed_ms: 300,
    };
    assert!(Bounds::from_signature(&evidence, &report, &exhausted).is_err());
}

#[test]
fn signature_and_strict_paths_agree_when_an_actual_issuer_sample_is_available() {
    let key = SigningKey::from_bytes(&[7; 32]);
    let bytes = signed(&key, Purpose::Authentication, 1000, 1800);
    let evidence = receipt::verify_signature(
        &key.verifying_key(),
        &bytes,
        Purpose::Authentication,
        &BINDING,
    )
    .unwrap();
    let owner_now = 1100;
    let strict = receipt::verify(
        &key.verifying_key(),
        &bytes,
        Purpose::Authentication,
        &BINDING,
        owner_now,
    )
    .unwrap();
    let report = Report {
        owner_now_ms: owner_now,
        remaining_ms: 500,
        receipt_sha256: *evidence.sha256(),
    };
    let exchange = Exchange {
        before_ms: 900_000,
        after_ms: 900_020,
        elapsed_ms: 20,
    };
    let numeric = Bounds::from_signature(&evidence, &report, &exchange).unwrap();
    let legacy = Bounds::from_receipt(&strict, &report, &exchange).unwrap();
    assert_eq!(numeric.admit_until_ms(), legacy.admit_until_ms());
    assert_eq!(numeric.retain_until_ms(), legacy.retain_until_ms());
}
