# S485 — Recovery codes let a user back in at AAL 1 to enroll again

<!-- scenario-status: draft -->

- Area: 2fa
- Milestone: M5
- ADRs: 0017, 0008
- Threat model: TM-51
- Gateway contract: n/a (no contract change)

## Goal

Ten single-use codes are shown once; a used code confirms the user for factor management without raising the assurance level and requires a new factor.

## Preconditions and fixtures

- `tests/fixtures/m1-basic.json` plus `webauthn: {}` and the `app` step-up rule `{"path_prefix": "/admin", "require": {"aal": 2, "max_age": 900}}`; mock provider profile `default`; a `webauthn-authenticator-rs` software passkey (user verification reported, zero AAGUID, counter from 1) plays the browser; clock from the test-hook process clock.
- Identifiers and random values come from the process; the test reads the store read-only except where a case says it alters a row.
- Unit tests in `src/store/sqlite/webauthn_tests.rs` and `src/factor/webauthn_tests.rs` cover the same rules below the HTTP layer.

## Main flow

### S485-1 Codes are shown once and a used code keeps AAL 1

- Given: one passkey.
- When: create codes, reload the page, use a code (in lower case) on `/security/verify`, then request `/admin`.
- Then: ten 17-character codes with `no-store`; ten Argon2id hashes stored; the reloaded page shows no code; `303 /security?done=recovered`; no AAL 2 session; the overview shows the re-enrollment banner; after single sign-on the application still asks for a step-up.

## Abuse cases

| Category | Case | Applies |
| --- | --- | --- |
| Replay | S485-A1 | yes |
| Tampering | S485-A1 | yes: a wrong code |
| Race / timing | — | covered by the store: a code is consumed by a conditional update |
| Resource exhaustion | — | covered by the per-address attempt admission; Argon2id runs off the async runtime |
| Confused deputy | — | no: codes are looked up only for the session's own user |
| Spoofed or duplicated headers | — | covered by S480-A2 |
| Downgrade | S485-1 | yes: a code never satisfies an AAL 2 rule |
| Enumeration | — | covered by a constant-cost dummy verification for unknown lookup ids |

### S485-A1 A code works once and wrong codes are refused

- Given: a fresh set of codes.
- When: a wrong code, a right code, the same right code again.
- Then: "That code didn't work"; `303`; "That code didn't work"; exactly one code marked used.

## Observability expectations

- Audit: `factor.recovery_codes_generated` (`count`), `factor.recovery_code_used` (success with the remaining `count`, or failure `invalid_credentials`).
- Log: request id and reason codes only.

## Test mapping

| Case | Test | File | Kind | Status |
| --- | --- | --- | --- | --- |
| S485-1 | `s485_1_codes_are_shown_once_and_a_used_code_keeps_aal1` | `tests/scenarios/s480_passkeys.rs` | integration | passing |
| S485-A1 | `s485_a1_a_code_works_once_and_wrong_codes_are_refused` | `tests/scenarios/s480_passkeys.rs` | integration | passing |

## Live verification

| Date | Hopae version | Gateway version | Provider | Environment label | Result | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| — | — | — | — | — | — | Not yet run (G8 pending). The software authenticator is the ceiling of evidence until a browser run. |

## Open questions

- Should using a recovery code also end the user's other sessions (the lost device may hold one)?
