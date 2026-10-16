# S313 — Group lifecycle and membership changes in the subject lifecycle feed

<!-- scenario-status: implemented -->

- Area: management
- Milestone: M4
- ADRs: 0018; Hangang ADR 0021 (lifecycle feed)
- Threat model: TM-60, TM-64
- Gateway contract: n/a

## Goal

A consumer of the subject lifecycle feed can opt in to group lifecycle and
membership changes from the same durable cursor, while the default answer
stays exactly as before.

## Preconditions and fixtures

- `m4-admin`; a user `u_lf`; the lifecycle snapshot's watermark taken first.

## Main flow

### S313-1 The lifecycle feed reports group changes only when asked

- Given: the watermark.
- When: create a group and add `u_lf`; read the feed from the watermark without and with `include_groups: true`.
- Then: without it, no change; with it, `group_created` (no user, `status: active` of the group) then `member_added` for `u_lf`, both with `group_id`.

## Alternative flows

None.

## Abuse cases

| Category | Case | Applies |
| --- | --- | --- |
| Replay | — | no: as scenario 308 |
| Tampering | — | no: as scenario 308-A1 |
| Race / timing | — | no |
| Resource exhaustion | — | no: the feed's bounds of 308 apply |
| Confused deputy | — | no |
| Spoofed or duplicated headers | — | no |
| Downgrade | S313-1 | yes: a consumer that does not ask sees the unchanged contract |
| Enumeration | — | no |

## Observability expectations

- Audit: as scenario 308.

## Test mapping

| Case | Test | File | Kind | Status |
| --- | --- | --- | --- | --- |
| S313-1 | `s313_1_lifecycle_feed_reports_group_changes_only_when_asked` | `tests/scenarios/s310_groups.rs` | integration | passing |

## Live verification

| Date | Hopae version | Gateway version | Provider | Environment label | Result | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| — | — | — | — | — | — | Not yet run. |

## Open questions

None.

## 한국어 요약

주체 생명주기 피드의 소비자는 같은 커서로 그룹 생명주기와 멤버십 변경을 선택적으로 받을
수 있으며, 기본 응답은 이전과 똑같이 유지됩니다.
