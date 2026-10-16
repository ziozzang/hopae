# S488 — An opted-in application sees AAL 3 for a high-assurance key

<!-- scenario-status: draft -->

- Area: 2fa
- Milestone: M5
- ADRs: 0018, 0017
- Threat model: TM-53
- Gateway contract: `x-hopae-aal` value `3` (opted-in applications only)

## Goal

An application with `max_emitted_aal = 3` sees AAL 3 after a step-up with an attested, allowlisted, non-synchronized security key; nothing else ever sees 3, and the stored level stays 2.

## Preconditions and fixtures

- `tests/fixtures/m1-basic.json` plus `webauthn.high_assurance` naming the CA of a `webauthn-authenticator-rs` software token (generated per test) and its AAGUID, and `apps[app].max_emitted_aal` as each case states; `/admin` requires AAL 2.

## Main flow

### S488-1 An opted-in application sees AAL 3

- Given: `max_emitted_aal = 3`; a high-assurance registration with the software token.
- When: the user steps up on `/admin` with that key.
- Then: one credential classed `aal3`, attested, not backup-eligible; verify answers `200` with `x-hopae-aal: 3`.

## Alternative flows

### S488-2 Without opt-in the same key stays at AAL 2

- Given: `max_emitted_aal = 2`.
- When: the same registration and step-up.
- Then: `x-hopae-aal: 2`.

## Abuse cases

| Category | Case | Applies |
| --- | --- | --- |
| Replay | — | covered by S481-A2 (same elevation) |
| Tampering | — | covered by store test `aal3_use_requires_an_aal3_credential_without_backup_flags` |
| Race / timing | — | covered by store test `aal3_evidence_follows_the_current_high_assurance_elevation` (a later elevation ends the evidence) |
| Resource exhaustion | — | no: one indexed read, only for opted-in applications |
| Confused deputy | S488-A1 | yes: a synchronized passkey on an opted-in application |
| Spoofed or duplicated headers | — | covered by S007 (identity headers are the gateway's) |
| Downgrade | S488-2 | yes: applications that did not opt in |
| Enumeration | — | no |

### S488-A1 A synchronized passkey never yields AAL 3

- Given: `max_emitted_aal = 3`; an ordinary passkey.
- When: the step-up.
- Then: `x-hopae-aal: 2`.

### S488-A2 AAL 3 needs high-assurance configuration

- Given: `max_emitted_aal = 3` without `webauthn.high_assurance`, without `webauthn`, or `max_emitted_aal = 4`.
- When: `hopae --check`.
- Then: a non-zero exit for each.

## Observability expectations

- Audit: `factor.webauthn_used` with `assurance = aal3`.
- Log: none beyond request ids.

## Test mapping

| Case | Test | File | Kind | Status |
| --- | --- | --- | --- | --- |
| S488-1 | `s488_1_an_opted_in_application_sees_aal3_for_a_high_assurance_key` | `tests/scenarios/s480_passkeys.rs` | integration | passing |
| S488-2 | `s488_2_without_opt_in_the_same_key_stays_aal2` | `tests/scenarios/s480_passkeys.rs` | integration | passing |
| S488-A1 | `s488_a1_a_synced_passkey_never_yields_aal3` | `tests/scenarios/s480_passkeys.rs` | integration | passing |
| S488-A2 | `s488_a2_aal3_needs_high_assurance_configuration` | `tests/scenarios/s480_passkeys.rs` | integration | passing |

## Live verification

| Date | Hopae version | Gateway version | Provider | Environment label | Result | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| — | — | — | — | — | — | Not run in a browser: a high-assurance key needs an attesting authenticator (hardware or the software token). |

## Open questions

- Requiring AAL 3 in step-up rules and Pumgye plans (ADR-0018 decision 6).
