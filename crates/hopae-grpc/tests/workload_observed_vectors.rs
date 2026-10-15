//! Deterministic foreign-clock vectors are numeric/cryptographic facts only.
//! Opaque SDK observations are tested separately over authenticated typed RPC.
use hopae_grpc::{
    PrincipalKind, receipt, receipt_binding,
    receipt_time::{Bounds, ClockRates, Exchange, Report},
    workload_epoch,
};
fn binding(kind: PrincipalKind) -> [u8; 32] {
    let epoch = workload_epoch::encode(
        "authority:p:realm",
        7,
        9,
        "11111111111111111111111111111111",
    )
    .unwrap();
    receipt_binding::digest(
        &receipt_binding::Context {
            issuer_ref: "issuer",
            key_epoch: 1,
            identity_authority_epoch: &epoch,
            identity: receipt_binding::Identity {
                subject_ref: &format!("s_{}", "a".repeat(48)),
                kind,
                aal: 0,
                revision: 7,
                credential_generation: 7,
            },
            service: "orders",
            audience: "api",
            request_sha256: [4; 32],
        },
        None,
    )
    .unwrap()
}
fn evidence() -> receipt::SignatureEvidence {
    let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
    let raw = receipt::sign(
        &key,
        &receipt::Claims {
            purpose: receipt::Purpose::Authentication,
            issued_ms: 1_000_000,
            expires_ms: 1_001_000,
            binding: binding(PrincipalKind::Workload),
            nonce: [3; 32],
        },
    )
    .unwrap();
    assert!(
        receipt::verify_signature(
            &key.verifying_key(),
            &raw,
            receipt::Purpose::Authentication,
            &binding(PrincipalKind::Service)
        )
        .is_err()
    );
    receipt::verify_signature(
        &key.verifying_key(),
        &raw,
        receipt::Purpose::Authentication,
        &binding(PrincipalKind::Workload),
    )
    .unwrap()
}
#[test]
fn foreign_absolute_offsets_do_not_change_local_budget_and_retention_is_distinct() {
    let evidence = evidence();
    let rates = ClockRates::new(1000, 2000).unwrap();
    let report = Report {
        owner_now_ms: 1_000_100,
        remaining_ms: 700,
        receipt_sha256: *evidence.sha256(),
    };
    for before in [1, 1000, 9_000_000_000] {
        let exchange = Exchange {
            before_ms: before,
            after_ms: before + 20,
            elapsed_ms: 20,
        };
        let bounds =
            Bounds::from_signature_with_rates(&evidence, &report, &exchange, &rates).unwrap();
        assert_eq!(bounds.admit_until_ms() - before, 696);
        assert!(bounds.retain_until_ms() > before + 900);
    }
}
#[test]
fn delay_quantum_malformed_signed_lifetime_and_report_cannot_mint_admission() {
    let evidence = evidence();
    let rates = ClockRates::new(500, 500).unwrap();
    for (owner, remaining, before, after, elapsed, digest) in [
        (1_000_100, 0, 100, 101, 1, *evidence.sha256()),
        (1_000_100, 1, 100, 101, 1, *evidence.sha256()),
        (1_000_100, 901, 100, 101, 1, *evidence.sha256()),
        (1_001_001, 700, 100, 101, 1, *evidence.sha256()),
        (999_999, 700, 100, 101, 1, *evidence.sha256()),
        (1_000_100, 700, 100, 900, 800, *evidence.sha256()),
        (1_000_100, 700, 100, 101, 3, *evidence.sha256()),
        (1_000_100, 700, 100, 101, 1, [9; 32]),
    ] {
        assert!(
            Bounds::from_signature_with_rates(
                &evidence,
                &Report {
                    owner_now_ms: owner,
                    remaining_ms: remaining,
                    receipt_sha256: digest
                },
                &Exchange {
                    before_ms: before,
                    after_ms: after,
                    elapsed_ms: elapsed
                },
                &rates
            )
            .is_err()
        );
    }
}
