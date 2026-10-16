# S316 — Console changes carry a reason, and a bulk disable answers per item

<!-- scenario-status: draft -->

- Area: management
- Milestone: M4
- ADRs: 0016, 0009
- Threat model: TM-44, TM-65
- Gateway contract: none (admin listener)

## Goal

Every console change can carry an operator's reason, which is recorded with the
change; an administrator disables up to 100 users in one call and gets a result
for every one of them, each change recorded and findable as one batch.

## Preconditions and fixtures

- `tests/fixtures/m4-admin.json`; an administrator and a viewer signed in; the people of scenario 315.
- For the delegated parts, `admin.hangang_delegation.authority = hangang`.

## Main flow

### S316-1 Reasons are recorded as the note

- Given: the administrator.
- When: disable `u_c` with a reason; enable with a reason padded by spaces; terminate `s_a1` with a reason; terminate every session of `u_a` without one; reasons too long, with a control character, with a bidirectional override, or not a string; the user page's disable form with a `reason` field; a Hangang disable and session termination with reasons, and an unknown field.
- Then: `admin.user_disable`, `admin.user_enable` (trimmed) and `admin.session_terminate` carry `note`; `admin.sessions_terminate` has none; each bad reason is `400 invalid_reason` and `u_c` stays active; the form post redirects (`303`) and records its note; the delegated records carry the note and `delegated_actor`; the unknown field is `403`.

### S316-2 A bulk disable answers per item

- Given: the administrator and the viewer.
- When: the viewer, then the administrator, disables `[u_a, u_b (already disabled), u_nobody, "bad id", <self>, u_c]` with a reason; empty, 101-id, duplicate and non-list bodies; a Hangang `users/bulk-disable`.
- Then: `403 role_insufficient` for the viewer; for the administrator the items in order are `disabled` (two sessions ended), `unchanged`, `error/not_found`, `error/invalid_id`, `error/self_target`, `disabled`, with `disabled: 2`, `failed: 3`; two `admin.user_disable` records carry the call's `bulk_operation` and the note; `400` for each bad body; the delegated call disables both users.

## Alternative flows

- None beyond the cases above.

## Abuse cases

| Category | Case | Applies |
| --- | --- | --- |
| Replay | — | covered by S306 (signed nonce admission) |
| Tampering | S316-1 | yes: hidden characters in a reason are refused, not stored |
| Race / timing | — | covered by S301 (each disable is its own fenced transaction) |
| Resource exhaustion | S316-2 | yes: at most 100 ids per call, a per-actor bucket |
| Confused deputy | S316-2 | yes: the viewer, and the administrator's own id inside the batch |
| Spoofed or duplicated headers | — | covered by S300 |
| Downgrade | — | no |
| Enumeration | S316-2 | yes: unknown ids answer `not_found` only to an administrator |

## Observability expectations

- Audit: `attrs.note` on every console change with a reason; `attrs.bulk_operation` on each item of a bulk call.
- Metrics: `hopae_admin_mutations_total{kind="user_disable"}` per changed user.

## Test mapping

| Case | Test | File | Kind | Status |
| --- | --- | --- | --- | --- |
| S316-1 | `s316_1_mutation_reasons_are_recorded_as_the_note` | `tests/scenarios/s314_admin_api_gaps.rs` | integration | passing |
| S316-2 | `s316_2_bulk_disable_answers_per_item_and_records_each_change` | `tests/scenarios/s314_admin_api_gaps.rs` | integration | passing |

## Live verification

| Date | Hopae version | Gateway version | Provider | Environment label | Result | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| — | — | — | — | — | — | Not yet run against a live Hangang console. |

## Open questions

- Should a reason become mandatory for disables (a configuration switch), as groups require it?

## 한국어 요약

모든 콘솔 변경은 운영자의 사유를 실을 수 있고 그 사유는 변경과 함께 `note`로 기록됩니다.
숨은 문자나 너무 긴 사유는 거부되고 아무것도 바뀌지 않습니다. 관리자는 한 번에 최대
100명을 비활성화하고 항목마다 결과를 받으며, 각 변경은 같은 `bulk_operation`으로 묶여
다시 찾을 수 있습니다.
