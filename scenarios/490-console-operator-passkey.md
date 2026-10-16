# S490 — A console operator signs in with a passkey and the console receives a signed assertion

<!-- scenario-status: draft -->

- Area: 2fa
- Milestone: M5
- ADRs: 0021, 0017
- Threat model: TM-78
- Gateway contract: `x-hopae-operator-assertion` (console application only)

## Goal

The console's application admits an operator only after a passkey use
(fresh on the step-up path), sends an operator without a passkey to add one,
admits operators without any passkey during a configured grace without the
factor, and every admission carries a signed assertion of the level and
factor.

## Preconditions and fixtures

- `tests/fixtures/m1-basic.json` with `webauthn` and `console_operators` on `app` (`require_factor: webauthn`, default step-up path and 300 s), the key in `HOPAE_TEST_OPERATOR_KEY`; a `webauthn-authenticator-rs` software passkey; for S490-2 an enrollment grace far in the future.

## Main flow

### S490-1 Passkey required, assertion signed, step-up path fresh

- Given: an operator signed in with the provider, no passkey.
- When: the console's host is requested as a document and as the console's own check; a passkey is registered and used to step up; the host is requested again; the step-up path is requested, then again after 301 s.
- Then: the document lands on the "add a passkey" page (`403`, link to `/security/passkeys/new`); the check is `401`; after the passkey step-up the answer is `200` with an assertion verifying under the key with `aal: 2`, `factor: webauthn`, `factor_at`, `satisfied: true`, `grace: false`; one `operator.console_admitted` for the session even after another request; the step-up path is allowed, then stepped up again after 301 s.

## Alternative flows

### S490-2 The enrollment grace admits without the factor, never on the step-up path

- Given: the grace; an operator without a passkey.
- When: the host, then the step-up path.
- Then: `200` with `satisfied: false`, `grace: true`, no factor; the step-up path still requires a passkey (the "add a passkey" page); the admission is recorded with `cause: enrollment_grace`.

## Abuse cases

| Category | Case | Applies |
| --- | --- | --- |
| Replay | — | covered by unit test `assertions_are_signed_short_lived_and_state_the_factor` (60 s lifetime) |
| Tampering | — | covered by the same unit test (a changed byte or another key is refused) |
| Race / timing | S490-1 | yes: the step-up path needs a fresh passkey |
| Resource exhaustion | — | no: one extra read per console admission, during the grace only |
| Confused deputy | S490-1 | yes: a TOTP-elevated session does not meet the policy (unit test `a_factor_rule_is_met_only_by_that_factor`) |
| Spoofed or duplicated headers | — | the console verifies the signature, never a header alone |
| Downgrade | S490-2 | yes: the grace never applies to the step-up path or to an operator who has a passkey |
| Enumeration | — | no |

### S490-A1 The operator policy configuration is checked

- Given: `console_operators` without `webauthn`; an unknown application; `require_aal: 3` without high assurance; a 5 s step-up age; a short key.
- When: `hopae --check`.
- Then: a non-zero exit for each.

## Observability expectations

- Audit: `operator.console_admitted` (`aal`, `kind`, `assurance`, `cause`); `factor.webauthn_used` for the step-up.

## Test mapping

| Case | Test | File | Kind | Status |
| --- | --- | --- | --- | --- |
| S490-1 | `s490_1_an_operator_needs_a_passkey_and_gets_a_signed_assertion` | `tests/scenarios/s480_passkeys.rs` | integration | passing |
| S490-2 | `s490_2_the_enrollment_grace_admits_without_the_factor_but_not_for_sensitive_actions` | `tests/scenarios/s480_passkeys.rs` | integration | passing |
| S490-A1 | `s490_a1_operator_policy_configuration_is_checked` | `tests/scenarios/s480_passkeys.rs` | integration | passing |

## Live verification

| Date | Hopae version | Gateway version | Provider | Environment label | Result | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| 2026-10-17 | 0.0.10 (feat/operator-aal) | Hangang console feat/operator-aal (emulated gateway) | mock | local G8, Chrome 152, virtual authenticator | pass (10/10) | `tools/browser-qual/run-operator.sh`: provider sign-in, passkey required before the first console grant, registration, passkey step-up, console SSO with `AAL2 · Passkey` in the header, stale-factor re-authentication for a sensitive change and recovery after the step-up, console audit records. Emulated gateway: ceiling `implemented`. |

## Open questions

- An asymmetric assertion signature (Ed25519) for consoles that must not hold a shared key.
