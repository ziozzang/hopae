# S481 — An application step-up is satisfied with a passkey

<!-- scenario-status: draft -->

- Area: 2fa
- Milestone: M5
- ADRs: 0017, 0008
- Threat model: TM-23, TM-47, TM-48, TM-52, TM-53
- Gateway contract: n/a (no contract change)

## Goal

A document request that hits an AAL 2 rule is completed with a passkey on the portal and reaches the application at AAL 2, never above, and an assertion cannot be relayed, replayed or reused after expiry.

## Preconditions and fixtures

- `tests/fixtures/m1-basic.json` plus `webauthn: {}` and the `app` step-up rule `{"path_prefix": "/admin", "require": {"aal": 2, "max_age": 900}}`; mock provider profile `default`; a `webauthn-authenticator-rs` software passkey (user verification reported, zero AAGUID, counter from 1) plays the browser; clock from the test-hook process clock.
- Identifiers and random values come from the process; the test reads the store read-only except where a case says it alters a row.
- Unit tests in `src/store/sqlite/webauthn_tests.rs` and `src/factor/webauthn_tests.rs` cover the same rules below the HTTP layer.

## Main flow

### S481-1 Passkey step-up yields AAL 2

- Given: the user has a passkey and an AAL 1 session; `/admin` requires AAL 2.
- When: verify for `https://app.example.test/admin/x` (document), then the portal step-up page, the assertion and `POST /stepup/webauthn`.
- Then: `302` to the portal `/stepup`; the page runs the ceremony script with `script-src 'self'` and Trusted Types and lists the application origin in `form-action`; the POST answers `302` to the application with a handoff code; after redemption verify answers `200` with `x-hopae-aal: 2` and `x-hopae-factors` naming `webauthn`; `factor.webauthn_used` with `assurance = aal2`.

## Alternative flows

### S481-2 A user without a passkey is sent to set one up

- Given: no second factor enrolled, no authenticator app configured.
- When: the step-up page.
- Then: `200` with a link to `/security`, no script.

## Abuse cases

| Category | Case | Applies |
| --- | --- | --- |
| Replay | S481-A2 | yes |
| Tampering | S481-A1 | yes |
| Race / timing | S481-A3 | yes: expiry |
| Resource exhaustion | — | covered by the per-address attempt admission on the POST and the ceremony cap |
| Confused deputy | S481-A1 | yes: a relaying origin |
| Spoofed or duplicated headers | — | covered by S480-A2 (same guard) |
| Downgrade | — | no: an AAL 1 handle cannot satisfy the rule, and recovery codes are not AAL 2 evidence (S485-1) |
| Enumeration | — | no: the page exists only for the user's own step-up transaction |

### S481-A1 An assertion from another origin is refused

- Given: the assertion is produced for `https://evil.auth.example.test` (a subdomain of the RP ID, which an authenticator accepts).
- When: it is posted to `/stepup/webauthn`.
- Then: the page is shown again with "couldn't verify"; `factor.webauthn_failed`; no AAL 2 session.

### S481-A2 A replayed assertion is refused

- Given: a completed step-up.
- When: the same form is posted again.
- Then: not a redirect; exactly one live AAL 2 handle.

### S481-A3 An expired ceremony is refused

- Given: a verification page older than five minutes.
- When: its assertion is posted.
- Then: the page explains that the request expired; no elevation.

## Observability expectations

- Audit: `factor.webauthn_used` (success, `aal = 2`, `assurance`, `purpose = stepup`), `handle.revoked` per rotated handle, `session.handoff`; `factor.webauthn_failed` on refusal.
- Log: request id and reason codes only.

## Test mapping

| Case | Test | File | Kind | Status |
| --- | --- | --- | --- | --- |
| S481-1 | `s481_1_passkey_stepup_yields_aal2_identity` | `tests/scenarios/s480_passkeys.rs` | integration | passing |
| S481-2 | `s481_2_user_without_passkey_is_sent_to_setup` | `tests/scenarios/s480_passkeys.rs` | integration | passing |
| S481-A1 | `s481_a1_assertion_from_another_origin_is_refused` | `tests/scenarios/s480_passkeys.rs` | integration | passing |
| S481-A2 | `s481_a2_replayed_assertion_is_refused` | `tests/scenarios/s480_passkeys.rs` | integration | passing |
| S481-A3 | `s481_a3_an_expired_ceremony_is_refused` | `tests/scenarios/s480_passkeys.rs` | integration | passing |

## Live verification

| Date | Hopae version | Gateway version | Provider | Environment label | Result | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| 2026-10-16 | 0.0.10 (branch `feat/webauthn-passkeys`) | emulated by `tools/browser-qual` (verify-driven forward auth, TLS terminator) | mock OIDC | local loopback; headless Chrome 152 with the CDP WebAuthn virtual authenticator (internal and USB); 1280 px EN and 390 px KO | pass (25 checks) | Step-up through `/stepup` to `x-hopae-aal: 2` with `webauthn`; refused prompt message. Ceiling `implemented` (emulated gateway, mock provider). |

## Open questions

- The step-up path requires a primary sign-in at most five minutes old (existing TOTP behavior); should a passkey alone be allowed to refresh an older session?
