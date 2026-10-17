# S489 — A step-up rule of AAL 3 is met only by a high-assurance security key

<!-- scenario-status: draft -->

- Area: 2fa
- Milestone: M5
- ADRs: 0018, 0017, 0008
- Threat model: TM-53
- Gateway contract: `step_up_required` for an unmet rule of 3; `x-hopae-aal` stays as `max_emitted_aal` decides

## Goal

An application can require AAL 3 on a path: only a step-up with an attested,
allowlisted, device-bound security key meets it; users without such a key are
told so instead of being offered methods that cannot satisfy it.

## Preconditions and fixtures

- `tests/fixtures/m1-basic.json` plus `webauthn.high_assurance` naming the CA of a `webauthn-authenticator-rs` software token (generated per test) and its AAGUID; `app` requires AAL 3 under `/admin` with `max_age` 900 and presents at most 2.

## Main flow

### S489-1 An AAL 3 rule is met only by a high-assurance key

- Given: a high-assurance registration with the software token.
- When: the user requests `/admin/x`, steps up with that key, then requests `/admin/y`.
- Then: the step-up page offers only that key; verify answers `200` with `x-hopae-aal: 2`; the second request is allowed without another step-up.

## Alternative flows

### S489-2 Without a high-assurance key the user is told

- Given: only a synced passkey registered.
- When: `/admin/x`, then the step-up page, then the authenticator-app route of the same transaction.
- Then: the step-up page is `403`, links to `/security/passkeys`, contains no ceremony and no authenticator-app link; the authenticator-app route is refused.

## Abuse cases

| Category | Case | Applies |
| --- | --- | --- |
| Replay | — | covered by S481-A2 (the same elevation) |
| Tampering | — | covered by unit test `aal3_rules_need_evidence_a_fresh_passkey_and_an_aal2_handle` (no evidence, a TOTP refresh, an AAL 1 handle, a stale passkey) |
| Race / timing | — | covered by store test `an_aal3_console_requirement_needs_live_high_assurance_evidence_in_the_fence` (a revoked key stops console changes at once) |
| Resource exhaustion | — | no: one indexed read per matching request |
| Confused deputy | S489-2 | yes: a synced passkey or an authenticator app cannot meet the rule |
| Spoofed or duplicated headers | — | covered by S007 |
| Downgrade | S489-2 | yes: no weaker method is offered |
| Enumeration | — | no |

### S489-A1 AAL 3 requirements need high-assurance configuration

- Given: a rule of `aal: 3` with `webauthn` but no `high_assurance`; a rule of `aal: 4`.
- When: `hopae --check`.
- Then: a non-zero exit naming `require.aal` for each (`admin.require_aal = 3` is covered by the configuration unit test `aal3_requirements_need_high_assurance_and_map_to_aal3_rules`).

## Observability expectations

- Audit: `factor.webauthn_used` with `assurance = aal3` for the step-up; `login.failed` with `high_assurance_required` is not written (the refusal is a page).
- Log: none beyond request ids.

## Test mapping

| Case | Test | File | Kind | Status |
| --- | --- | --- | --- | --- |
| S489-1 | `s489_1_an_aal3_rule_is_met_only_by_a_high_assurance_key` | `tests/scenarios/s480_passkeys.rs` | integration | passing |
| S489-2 | `s489_2_without_a_high_assurance_key_the_user_is_told_and_nothing_else_is_offered` | `tests/scenarios/s480_passkeys.rs` | integration | passing |
| S489-A1 | `s489_a1_aal3_requirements_need_high_assurance_configuration` | `tests/scenarios/s480_passkeys.rs` | integration | passing |

## Live verification

| Date | Hopae version | Gateway version | Provider | Environment label | Result | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| — | — | — | — | — | — | Not run in a browser: a high-assurance key needs an attesting authenticator. |

## Open questions

- Pumgye plans of `minimum_aal: 3` (ADR-0018 decision 11).

## 한국어 요약

애플리케이션은 경로에 AAL 3을 요구할 수 있습니다. 증명되고 허용 목록에 있으며 기기에 묶인
보안 키로 단계 상승해야만 충족되고, 그런 키가 없는 사용자에게는 충족할 수 없는 다른 방법을
권하는 대신 고보증 보안 키가 필요하다고 알립니다.
