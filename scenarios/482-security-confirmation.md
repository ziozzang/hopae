# S482 — The portal confirms it is the user before factor changes

<!-- scenario-status: draft -->

- Area: 2fa
- Milestone: M5
- ADRs: 0017, 0008
- Threat model: TM-23, TM-47, TM-48
- Gateway contract: n/a (no contract change)

## Goal

`/security/verify` proves a second factor, rotates the session's handles and opens factor management for five minutes; an assertion for another relying party is refused.

## Preconditions and fixtures

- `tests/fixtures/m1-basic.json` plus `webauthn: {}` and the `app` step-up rule `{"path_prefix": "/admin", "require": {"aal": 2, "max_age": 900}}`; mock provider profile `default`; a `webauthn-authenticator-rs` software passkey (user verification reported, zero AAGUID, counter from 1) plays the browser; clock from the test-hook process clock.
- Identifiers and random values come from the process; the test reads the store read-only except where a case says it alters a row.
- Unit tests in `src/store/sqlite/webauthn_tests.rs` and `src/factor/webauthn_tests.rs` cover the same rules below the HTTP layer.

## Main flow

### S482-1 Portal confirmation rotates handles and opens management

- Given: a passkey exists.
- When: the verification page, the assertion, `POST /security/verify/passkey`.
- Then: `303` to the `next` page; a new portal handle cookie; the old portal and application handles revoked with reason `elevation`; the overview says the user confirmed recently.

## Abuse cases

| Category | Case | Applies |
| --- | --- | --- |
| Replay | — | covered by S481-A2 (same ceremony store) |
| Tampering | S482-A1 | yes |
| Race / timing | — | covered by S481-A3 |
| Resource exhaustion | — | covered by the ceremony cap |
| Confused deputy | S482-A1 | yes: another RP ID |
| Spoofed or duplicated headers | — | covered by S480-A2 |
| Downgrade | — | no: the confirmation never lowers a level |
| Enumeration | — | no |

### S482-A1 An assertion for another RP ID is refused

- Given: the request options are altered to RP ID `example.test` before the authenticator signs.
- When: the assertion is posted.
- Then: the page is shown again with "couldn't verify"; no AAL 2 session.

## Observability expectations

- Audit: `factor.webauthn_used` (`purpose = verify`), `factor.totp_consumed` (`purpose = verify`) or `factor.recovery_code_used`, and `handle.revoked` per handle.
- Log: request id and reason codes only.

## Test mapping

| Case | Test | File | Kind | Status |
| --- | --- | --- | --- | --- |
| S482-1 | `s482_1_portal_verification_rotates_handles_and_opens_management` | `tests/scenarios/s480_passkeys.rs` | integration | passing |
| S482-A1 | `s482_a1_assertion_for_another_rp_id_is_refused` | `tests/scenarios/s480_passkeys.rs` | integration | passing |

## Live verification

| Date | Hopae version | Gateway version | Provider | Environment label | Result | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| — | — | — | — | — | — | Not yet run (G8 pending). The software authenticator is the ceiling of evidence until a browser run. |

## Open questions

- Five minutes is fixed; should it become configurable (`webauthn.management_window`)?
