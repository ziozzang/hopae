# S308 — Subject lifecycle feed: a policy authority learns which subjects were created, disabled, enabled or deleted

<!-- scenario-status: implemented -->

- Area: management
- Milestone: M4
- ADRs: 0009, 0016; Hangang ADR 0021 (orphan reconciliation)
- Threat model: TM-60
- Gateway contract: n/a

## Goal

A consumer that holds subject references (Pumgye bindings) reconciles them
with Hopae: a snapshot lists every subject ever reserved with its current
status and a watermark, and a durable feed after that watermark reports every
creation and status change Hopae recorded atomically with the change, so that
no change is missed silently — a position Hopae can no longer honor is
refused, never skipped.

## Preconditions and fixtures

- Configuration and administrators as in scenario 307.
- Users laid down with SQL (the reservation ledger records them through its trigger); status changes through the console's own `POST /v1/users/{id}/disable|enable` so the outbox rows are the production ones.

## Main flow

### S308-1 The snapshot lists every reserved subject with a watermark

- Given: five users, one disabled, one deleted, and the signed-in viewer.
- When: `POST /v1/subjects/lifecycle/snapshot` with `limit: 2`, following `next_cursor`; then `POST /v1/subjects/lifecycle` with the first page's `watermark`.
- Then: every reserved user ID exactly once with `active`, `disabled` or `deleted`; only the first page carries `watermark` (`f1.…`); no name or e-mail address; the feed from the watermark is empty with `more: false` and that empty poll writes no `admin.read` record.

### S308-2 The feed reports creation and status changes after the watermark

- Given: `u_before`; a watermark taken; then `u_new` created, `u_before` disabled, `u_new` disabled and enabled, and an idempotent second enable.
- When: the feed is drained from the watermark with `limit: 1`.
- Then: exactly `created u_new (active)`, `disabled u_before (disabled)`, `disabled u_new (active)`, `enabled u_new (active)` — creations first, each change with its time and the subject's current status — and nothing for the idempotent enable; a further poll is empty with `more: false`; a non-empty page writes an `admin.read` record with `purpose: subjects.lifecycle`.

## Alternative flows

None: the feed has one shape; a consumer starting without a cursor reads from
the oldest retained change.

## Abuse cases

| Category | Case | Applies |
| --- | --- | --- |
| Replay | — | no: a replayed page is harmless by design (`status` is current, consumers apply it); a delegated replay is refused as in 307-5 |
| Tampering | S308-A1 | yes |
| Race / timing | S308-1 | yes: the watermark is taken before the first snapshot page, so a change during the walk is in the feed |
| Resource exhaustion | S308-A1 | yes: `limit` is bounded to 200 and one page examines at most 20,000 outbox rows |
| Confused deputy | — | no: the reads are the same for every grant holder; authorization is 307-A4 |
| Spoofed or duplicated headers | — | no: the request rule is 307-A2 |
| Downgrade | — | no: no negotiation |
| Enumeration | — | no: the snapshot is the deliberate enumeration for grant holders; ungranted callers are 307-A4 |

### S308-A1 Tampered, foreign or pruned positions are refused

- Given: a watermark.
- When: malformed feed cursors (`garbage`, `f1.0.5.-`, `f2.0.0.-`, `f1.-1.0.-`, five parts); malformed snapshot cursors; `limit` 0 or 201 or an unknown field; a cursor whose ledger position lies beyond the store's; a cursor naming the watermark's outbox row with another event id; the watermark after its outbox rows were pruned.
- Then: `400 invalid_cursor` resp. `400 invalid_request` for the malformed ones; `410 cursor_expired` for the foreign, forged and pruned positions — never a page that silently skips; a new snapshot answers `200` with a watermark the feed accepts.

## Observability expectations

- Log: none beyond the console's request logs.
- Audit: `admin.read` (`purpose: subjects.lifecycle`, `attrs.count`) for every snapshot page and every non-empty feed page.
- Metrics: `hopae_events_total{kind="admin.read"}`.

## Test mapping

| Case | Test | File | Kind | Status |
| --- | --- | --- | --- | --- |
| S308-1 | `s308_1_snapshot_lists_every_reserved_subject_with_watermark` | `tests/scenarios/s308_subject_lifecycle.rs` | integration | passing |
| S308-2 | `s308_2_feed_reports_creation_and_status_changes_after_watermark` | `tests/scenarios/s308_subject_lifecycle.rs` | integration | passing |
| S308-A1 | `s308_a1_tampered_or_pruned_positions_are_refused` | `tests/scenarios/s308_subject_lifecycle.rs` | integration | passing |

## Live verification

| Date | Hopae version | Gateway version | Provider | Environment label | Result | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| — | — | — | — | — | — | Not yet run. |

## Open questions

- Hangang ADR 0021 also asks for group lifecycle, membership changes and `merged`; Hopae has no groups and no merge operation yet.
- Should Hopae add a hard-delete operation that records `deleted` in the feed, rather than leaving out-of-band deletions to the snapshot?

## 한국어 요약

정책 기관은 워터마크가 붙은 스냅숏으로 예약된 모든 주체와 현재 상태(`deleted` 포함)를
받고, 그 뒤로는 사용자 생성과 상태 변경을 변경과 같은 트랜잭션에 기록된 원천에서 읽는
지속 피드로 따라갑니다. 핵심 남용 사례는 위조되거나 정리된 위치이며, 이를 조용히
건너뛰지 않고 `410 cursor_expired`로 거부하여 새 스냅숏을 받게 합니다.
