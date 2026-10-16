# S483 — A sign-count regression disables the passkey

<!-- scenario-status: draft -->

- Area: 2fa
- Milestone: M5
- ADRs: 0017, 0008
- Threat model: TM-49
- Gateway contract: n/a (no contract change)

## Goal

A signature-verified assertion whose counter does not exceed the stored one revokes that credential and ends the sessions it elevated, and the user is told why.

## Preconditions and fixtures

- `tests/fixtures/m1-basic.json` plus `webauthn: {}` and the `app` step-up rule `{"path_prefix": "/admin", "require": {"aal": 2, "max_age": 900}}`; mock provider profile `default`; a `webauthn-authenticator-rs` software passkey (user verification reported, zero AAGUID, counter from 1) plays the browser; clock from the test-hook process clock.
- Identifiers and random values come from the process; the test reads the store read-only except where a case says it alters a row.
- Unit tests in `src/store/sqlite/webauthn_tests.rs` and `src/factor/webauthn_tests.rs` cover the same rules below the HTTP layer.

## Main flow

### S483-1 Counter regression revokes the passkey and ends its sessions

- Given: the stored counter is far above what the authenticator reports next; the current session was elevated with that passkey.
- When: a portal confirmation with the passkey.
- Then: `403` page explaining the passkey was turned off; credential `revoked` with reason `counter_regression`; the session ended with reason `counter_regression`; `factor.webauthn_clone_suspected` recorded.

## Abuse cases

| Category | Case | Applies |
| --- | --- | --- |
| Replay | — | no: the signal needs a fresh signature over a fresh challenge |
| Tampering | — | covered by unit test `a_counter_that_does_not_advance_is_a_clone_signal` |
| Race / timing | — | covered by store test `counter_moves_forward_only_and_stale_counters_are_refused_without_revocation`: out-of-order tabs are refused without revocation |
| Resource exhaustion | — | no |
| Confused deputy | — | covered by store test `clone_signal_revokes_the_credential_and_ends_the_sessions_it_elevated`: another user's ceremony cannot revoke this credential |
| Spoofed or duplicated headers | — | no |
| Downgrade | — | no |
| Enumeration | — | no |

## Observability expectations

- Audit: `factor.webauthn_clone_suspected` (failure, `counter_regression`, `factor_id`), `session.terminated` (`counter_regression`), a warning log line with the request id.
- Log: request id and reason codes only.

## Test mapping

| Case | Test | File | Kind | Status |
| --- | --- | --- | --- | --- |
| S483-1 | `s483_1_counter_regression_revokes_the_passkey_and_ends_its_sessions` | `tests/scenarios/s480_passkeys.rs` | integration | passing |

## Live verification

| Date | Hopae version | Gateway version | Provider | Environment label | Result | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| — | — | — | — | — | — | Not yet run (G8 pending). The software authenticator is the ceiling of evidence until a browser run. |

## Open questions

- Should the user (or an administrator) be notified out of band once webhooks exist (M5)?
