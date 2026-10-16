# S487 — A user signs in with a passkey alone

<!-- scenario-status: draft -->

- Area: 2fa
- Milestone: M5
- ADRs: 0017
- Threat model: TM-47, TM-48, TM-54
- Gateway contract: `x-hopae-provider` value `hopae.passkey`

## Goal

With passwordless sign-in configured, a user with a discoverable passkey signs in without a provider or username and reaches applications at AAL 2; nobody learns which accounts or passkeys exist, and a ceremony cannot be replayed, transferred or flooded.

## Preconditions and fixtures

- `tests/fixtures/m1-basic.json` plus `webauthn: {passwordless: true}` and the `app` step-up rule `/admin` → AAL 2; mock provider `default`; a software passkey registered in a first browser. The software key cannot discover credentials, so the test names its credential in the request options and adds the user handle a discoverable authenticator would return (the handle is not signed; the server's logic is exercised unchanged).

## Main flow

### S487-1 Passwordless sign-in creates an AAL 2 passkey session

- Given: a registered passkey; a second browser without cookies.
- When: the application redirects to the portal, the chooser page is answered, the assertion is posted to `POST /login/passkey`.
- Then: the chooser carries `autocomplete="username webauthn"` and the ceremony script policy; the POST answers `302` with a handoff and a portal handle; verify answers `200` with `x-hopae-aal: 2`, `x-hopae-provider: hopae.passkey` and `x-hopae-factors` naming `webauthn`; the security pages and the `/admin` rule are satisfied; `login.succeeded` with `kind = webauthn`.

## Alternative flows

### S487-2 Without passwordless the chooser is unchanged

- Given: `webauthn: {}`.
- When: the sign-in page with one provider.
- Then: `302` straight to the provider; no sign-in ceremony row.

## Abuse cases

| Category | Case | Applies |
| --- | --- | --- |
| Replay | S487-A2 | yes |
| Tampering | S487-A1 | yes: a foreign user handle |
| Race / timing | S487-A2 | yes: the ceremony and the login transaction are consumed with the session |
| Resource exhaustion | S487-A4 | yes |
| Confused deputy | S487-A3 | yes |
| Spoofed or duplicated headers | — | covered by S480-A2 (same Origin guard) |
| Downgrade | S487-A5 | yes: a removed passkey cannot keep its session |
| Enumeration | S487-A1 | yes |

### S487-A1 Unknown or foreign user handles fail uniformly

- Given: an assertion carrying an unknown handle, and one carrying another user's handle with this user's credential.
- When: each is posted.
- Then: both answer the same `303 /login?…passkey_error=rejected`; no passkey session; the page says it couldn't sign in with that passkey.

### S487-A2 A replayed sign-in is refused

- Given: a completed passwordless sign-in.
- When: the same form is posted again.
- Then: `303 …passkey_error=expired`; exactly one passkey session.

### S487-A3 Another browser cannot complete the ceremony

- Given: a ceremony started in browser B.
- When: browser C (another binding cookie) posts it.
- Then: `403` (token bound to B's binding); no session.

### S487-A4 Ceremonies per address are bounded

- Given: one address.
- When: the sign-in page is loaded repeatedly.
- Then: the passkey option is offered 30 times per minute; afterwards the page behaves as without passkeys.

### S487-A5 Removing the passkey ends its passwordless sessions

- Given: a passwordless session.
- When: an administrator resets the user's factors (the same path as removal and clone revocation).
- Then: no live `hopae.passkey` session remains.

### S487-A6 A slower tab is stale, not a clone

- Given: two sign-in tabs; the assertion signed first is posted last.
- When: the late assertion arrives after the other tab signed in.
- Then: the same refusal; the passkey stays active and the other session lives.

### S487-A7 Removing the establishing passkey ends the acting session

- Given: a passwordless session and a second passkey.
- When: that session removes the passkey it was established with.
- Then: no live passwordless session remains.

## Observability expectations

- Audit: `login.succeeded` and `session.created` (`aal = 2`) with `kind = webauthn`, `factor.webauthn_used` (`purpose = login`); `login.failed` (`ceremony_invalid`, `cause`) for refusals; `factor.webauthn_clone_suspected` for a counter regression.
- Log: request id and reason codes only.

## Test mapping

| Case | Test | File | Kind | Status |
| --- | --- | --- | --- | --- |
| S487-1 | `s487_1_passwordless_sign_in_creates_an_aal2_passkey_session` | `tests/scenarios/s480_passkeys.rs` | integration | passing |
| S487-2 | `s487_2_without_passwordless_the_chooser_is_unchanged` | `tests/scenarios/s480_passkeys.rs` | integration | passing |
| S487-A1 | `s487_a1_unknown_or_foreign_user_handles_fail_uniformly` | `tests/scenarios/s480_passkeys.rs` | integration | passing |
| S487-A2 | `s487_a2_a_replayed_sign_in_is_refused` | `tests/scenarios/s480_passkeys.rs` | integration | passing |
| S487-A3 | `s487_a3_another_browser_cannot_complete_the_ceremony` | `tests/scenarios/s480_passkeys.rs` | integration | passing |
| S487-A4 | `s487_a4_ceremonies_per_address_are_bounded` | `tests/scenarios/s480_passkeys.rs` | integration | passing |
| S487-A5 | `s487_a5_removing_the_passkey_ends_its_passwordless_sessions` | `tests/scenarios/s480_passkeys.rs` | integration | passing |
| S487-A6 | `s487_a6_a_slower_tab_is_stale_not_a_clone` | `tests/scenarios/s480_passkeys.rs` | integration | passing |
| S487-A7 | `s487_a7_removing_the_establishing_passkey_ends_the_acting_session` | `tests/scenarios/s480_passkeys.rs` | integration | passing |

## Live verification

| Date | Hopae version | Gateway version | Provider | Environment label | Result | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| 2026-10-16 | 0.0.10 (branch `feat/webauthn-passkeys`) | emulated by `tools/browser-qual` (verify-driven forward auth, TLS terminator) | mock OIDC | local loopback; headless Chrome 152 with the CDP WebAuthn virtual authenticator (internal and USB); 1280 px EN and 390 px KO | pass (25 checks) | Conditional (autofill) mediation answered by the virtual authenticator, passwordless session at AAL 2 with `hopae.passkey`, no-passkey message in Korean. Found and fixed: the chooser's `form-action` lacked the application origin, so Chrome blocked the redirect after sign-in. |

## Open questions

- Should reauthentication (`max_auth_age`) accept a passkey for passkey sessions?
