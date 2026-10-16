# S484 — Users manage passkeys and administrators reset factors

<!-- scenario-status: draft -->

- Area: 2fa
- Milestone: M5
- ADRs: 0017, 0008
- Threat model: TM-50
- Gateway contract: n/a (no contract change)

## Goal

Users rename and remove passkeys with a confirmation; removal needs a recent second factor and never removes the last one; an administrator can reset every factor from the command line.

## Preconditions and fixtures

- `tests/fixtures/m1-basic.json` plus `webauthn: {}` and the `app` step-up rule `{"path_prefix": "/admin", "require": {"aal": 2, "max_age": 900}}`; mock provider profile `default`; a `webauthn-authenticator-rs` software passkey (user verification reported, zero AAGUID, counter from 1) plays the browser; clock from the test-hook process clock.
- Identifiers and random values come from the process; the test reads the store read-only except where a case says it alters a row.
- Unit tests in `src/store/sqlite/webauthn_tests.rs` and `src/factor/webauthn_tests.rs` cover the same rules below the HTTP layer.

## Main flow

### S484-1 Rename, then remove with confirmation

- Given: two passkeys, a recent confirmation.
- When: rename to `Work laptop`, an empty rename, the first removal press, the confirmed removal.
- Then: `303 ?done=renamed`; `303 ?error=invalid_label`; a confirmation page naming the passkey; `303 ?done=removed`; one active passkey; `factor.webauthn_revoked`.

## Alternative flows

### S484-2 The last factor cannot be removed

- Given: one passkey; then two.
- When: the list; a removal of one; a crafted removal of the other.
- Then: no removal form while one factor remains; the first removal succeeds; the second answers `303 ?error=last_factor` and the store keeps the passkey.

### S484-3 Administrator reset

- Given: a passkey and a live session.
- When: `hopae admin factors list <user>` then `hopae admin factors reset <user>`.
- Then: the list shows the hashed id, label and class; reset reports one passkey revoked, ends every session and records `admin.factor_reset`; an unknown user is refused.

## Abuse cases

| Category | Case | Applies |
| --- | --- | --- |
| Replay | — | no: removal is idempotent and audited once |
| Tampering | S484-2 | yes: a crafted removal of the last factor |
| Race / timing | — | covered by the store: the last-factor check runs in the revocation transaction |
| Resource exhaustion | — | no |
| Confused deputy | — | covered by store test `last_factor_cannot_be_removed_and_removal_needs_recent_verification` (a foreign credential is not found) |
| Spoofed or duplicated headers | — | covered by S480-A2 |
| Downgrade | S484-A1 | yes: an old confirmation does not authorize removal |
| Enumeration | — | no |

### S484-A1 Removal needs a recent second factor

- Given: two passkeys; the last confirmation is older than five minutes.
- When: a confirmed removal.
- Then: `303` to `/security/verify?next=passkeys`; both passkeys remain.

## Observability expectations

- Audit: `factor.webauthn_renamed`, `factor.webauthn_revoked` (`passkey_removed`), `session.terminated` for other sessions the passkey elevated, `admin.factor_reset` with `actor = cli`.
- Log: request id and reason codes only.

## Test mapping

| Case | Test | File | Kind | Status |
| --- | --- | --- | --- | --- |
| S484-1 | `s484_1_rename_and_remove_with_confirmation` | `tests/scenarios/s480_passkeys.rs` | integration | passing |
| S484-2 | `s484_2_the_last_factor_cannot_be_removed` | `tests/scenarios/s480_passkeys.rs` | integration | passing |
| S484-3 | `s484_3_administrator_reset_revokes_factors_and_ends_sessions` | `tests/scenarios/s480_passkeys.rs` | integration | passing |
| S484-A1 | `s484_a1_removal_needs_a_recent_second_factor` | `tests/scenarios/s480_passkeys.rs` | integration | passing |

## Live verification

| Date | Hopae version | Gateway version | Provider | Environment label | Result | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| — | — | — | — | — | — | Not yet run (G8 pending). The software authenticator is the ceiling of evidence until a browser run. |

## Open questions

- Should an administrator reset also be offered in the console (deferred with console factor management)?
