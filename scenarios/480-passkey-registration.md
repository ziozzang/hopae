# S480 — A signed-in user registers a passkey on the portal

<!-- scenario-status: draft -->

- Area: 2fa
- Milestone: M5
- ADRs: 0017, 0008
- Threat model: TM-47, TM-48, TM-50, TM-52
- Gateway contract: n/a (no contract change)

## Goal

A user with a live portal session adds a passkey; the credential is verified, stored once and named, and nobody else can complete or replay the ceremony.

## Preconditions and fixtures

- `tests/fixtures/m1-basic.json` plus `webauthn: {}` and the `app` step-up rule `{"path_prefix": "/admin", "require": {"aal": 2, "max_age": 900}}`; mock provider profile `default`; a `webauthn-authenticator-rs` software passkey (user verification reported, zero AAGUID, counter from 1) plays the browser; clock from the test-hook process clock.
- Identifiers and random values come from the process; the test reads the store read-only except where a case says it alters a row.
- Unit tests in `src/store/sqlite/webauthn_tests.rs` and `src/factor/webauthn_tests.rs` cover the same rules below the HTTP layer.

## Main flow

### S480-1 First passkey from a fresh session

- Given: the user signed in less than five minutes ago and has no second factor.
- When: `GET /security/passkeys/new`, then the authenticator response posted to `POST /security/passkeys/new` with the page token and `Origin: https://auth.example.test`.
- Then: `303` to `/security/recovery-codes?first=1`; one active row in `webauthn_credentials` (`user_verified = 1`, `assurance = aal2`, label `Passkey`); `factor.webauthn_registered` recorded with a hashed `factor_id`; the list shows a device-bound passkey.

## Alternative flows

### S480-2 A second passkey needs a security confirmation

- Given: the user has one passkey and no second factor in the last five minutes.
- When: `GET /security/passkeys/new`.
- Then: `303` to `/security/verify?next=passkeys_new`; after a passkey confirmation the portal handle is reissued and the second registration ends in `303 /security/passkeys?done=added`.

## Abuse cases

| Category | Case | Applies |
| --- | --- | --- |
| Replay | S480-A1 | yes |
| Tampering | S480-A2 | yes |
| Race / timing | S480-A1 | yes: the ceremony row is consumed in the registration transaction, so two submissions cannot both register |
| Resource exhaustion | — | covered by unit tests: at most 8 live ceremony rows per session (`ceremony_rows_are_capped_per_session`), 20 passkeys per user |
| Confused deputy | S480-A4 | yes |
| Spoofed or duplicated headers | S480-A2 | yes: a foreign `Origin` is refused |
| Downgrade | S480-A3 | yes: plain HTTP and a missing session are refused |
| Enumeration | — | no: the routes reveal nothing without the user's own session |

### S480-A1 A replayed registration is refused

- Given: the first POST succeeded.
- When: the identical form is posted again.
- Then: no second row; the spent ceremony is unavailable and, a factor now existing, the user is sent to the security confirmation.

### S480-A2 Missing token, foreign Origin or another action's token

- Given: a valid registration page.
- When: the POST lacks `csrf`, carries `Origin: https://app.example.test`, or a `register` token is used for `rename`.
- Then: `400`, `403`, `403`; no row; `csrf.rejected` recorded.

### S480-A3 No session or no HTTPS

- Given: a browser without a portal handle, or a request over HTTP.
- When: `GET /security/passkeys/new`.
- Then: `403` "Sign in first" (or `403`); no ceremony row is written.

### S480-A4 The ceremony belongs to the browser that started it

- Given: the portal handle is copied into another browser with another binding cookie.
- When: the other browser posts the first browser's ceremony.
- Then: `403` (the token is bound to the first binding cookie); the store would refuse the binding digest as well; no row.

## Observability expectations

- Audit: `factor.webauthn_registered` (success, `factor_id`, `kind`, `assurance`); `factor.webauthn_failed` (failure, `purpose`, `cause`) for a refused response; `csrf.rejected` for a refused token. No credential id, client data or signature in any record.
- Log: request id and reason codes only.

## Test mapping

| Case | Test | File | Kind | Status |
| --- | --- | --- | --- | --- |
| S480-1 | `s480_1_register_passkey_from_a_fresh_session` | `tests/scenarios/s480_passkeys.rs` | integration | passing |
| S480-2 | `s480_2_a_second_passkey_needs_verification_first` | `tests/scenarios/s480_passkeys.rs` | integration | passing |
| S480-A1 | `s480_a1_replayed_registration_is_refused` | `tests/scenarios/s480_passkeys.rs` | integration | passing |
| S480-A2 | `s480_a2_missing_token_or_foreign_origin_is_refused` | `tests/scenarios/s480_passkeys.rs` | integration | passing |
| S480-A3 | `s480_a3_without_a_session_or_https_nothing_is_offered` | `tests/scenarios/s480_passkeys.rs` | integration | passing |
| S480-A4 | `s480_a4_ceremony_is_bound_to_the_browser_that_started_it` | `tests/scenarios/s480_passkeys.rs` | integration | passing |

## Live verification

| Date | Hopae version | Gateway version | Provider | Environment label | Result | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| 2026-10-16 | 0.0.10 (branch `feat/webauthn-passkeys`) | emulated by `tools/browser-qual` (verify-driven forward auth, TLS terminator) | mock OIDC | local loopback; headless Chrome 152 with the CDP WebAuthn virtual authenticator (internal and USB); 1280 px EN and 390 px KO | pass (25 checks) | Registration, duplicate authenticator (`InvalidStateError` message), recovery codes after the first passkey. Not a live Hangang gateway or a hardware authenticator: ceiling `implemented`. |

## Open questions

- Should registration offer `residentKey: preferred` now, so that passkeys created today are usable for the later passwordless sign-in without re-registration?
