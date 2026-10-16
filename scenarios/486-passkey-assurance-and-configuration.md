# S486 — Passkeys change nothing until configured and never emit AAL 3

<!-- scenario-status: draft -->

- Area: 2fa
- Milestone: M5
- ADRs: 0017, 0008
- Threat model: TM-52, TM-53
- Gateway contract: n/a (no contract change)

## Goal

Without `webauthn` every route is absent; with it, the only portal script is static and integrity-pinned, and invalid relying-party settings stop the start.

## Preconditions and fixtures

- `tests/fixtures/m1-basic.json` plus `webauthn: {}` and the `app` step-up rule `{"path_prefix": "/admin", "require": {"aal": 2, "max_age": 900}}`; mock provider profile `default`; a `webauthn-authenticator-rs` software passkey (user verification reported, zero AAGUID, counter from 1) plays the browser; clock from the test-hook process clock.
- Identifiers and random values come from the process; the test reads the store read-only except where a case says it alters a row.
- Unit tests in `src/store/sqlite/webauthn_tests.rs` and `src/factor/webauthn_tests.rs` cover the same rules below the HTTP layer.

## Main flow

### S486-1 Without webauthn nothing changes

- Given: the configuration has no `webauthn` object.
- When: every security route, the script and `POST /stepup/webauthn`.
- Then: `404` each; no `script-src` on any page; no ceremony row.

## Alternative flows

### S486-2 The ceremony script is static and integrity-pinned

- Given: `webauthn: {}`.
- When: `GET /assets/webauthn.js` and a registration page.
- Then: `text/javascript`; no HTML sink, `eval` or `fetch`; the page names the file's SHA-384 integrity and has no inline script or handler; `script-src 'self'`, Trusted Types and the `Permissions-Policy`; the overview keeps the no-script policy.

### S486-3 Invalid relying-party settings are refused

- Given: `webauthn.rp_id` outside the portal domain, or an unknown key.
- When: `hopae --check`.
- Then: a non-zero exit.

## Abuse cases

| Category | Case | Applies |
| --- | --- | --- |
| Replay | — | no |
| Tampering | S486-2 | yes: the script cannot be altered without failing the integrity check |
| Race / timing | — | no |
| Resource exhaustion | — | no |
| Confused deputy | S486-3 | yes: an RP ID that is not the portal's |
| Spoofed or duplicated headers | — | no |
| Downgrade | S486-1 | yes: absent configuration is the pre-change behavior |
| Enumeration | — | no |

## Observability expectations

- Audit: None beyond the start-up error.
- Log: request id and reason codes only.

## Test mapping

| Case | Test | File | Kind | Status |
| --- | --- | --- | --- | --- |
| S486-1 | `s486_1_without_webauthn_nothing_changes` | `tests/scenarios/s480_passkeys.rs` | integration | passing |
| S486-2 | `s486_2_ceremony_script_is_static_and_integrity_pinned` | `tests/scenarios/s480_passkeys.rs` | integration | passing |
| S486-3 | `s486_3_insecure_or_unauthenticated_deployments_are_refused_at_start` | `tests/scenarios/s480_passkeys.rs` | integration | passing |

## Live verification

| Date | Hopae version | Gateway version | Provider | Environment label | Result | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| — | — | — | — | — | — | Not yet run (G8 pending). The software authenticator is the ceiling of evidence until a browser run. |

## Open questions

- AAL 3 emission is deferred (ADR-0017 wire analysis); its own ADR decides the per-application `max_emitted_aal`.
