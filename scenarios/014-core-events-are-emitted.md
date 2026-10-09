# S014 — Core flows emit events with the fixed schema

<!-- scenario-status: draft -->

- Area: core
- Milestone: M1
- ADRs: 0009
- Threat model: TM-12, TM-17, TM-28, TM-32
- Gateway contract: n/a

## Goal

Every M1 flow records typed events with the schema of ADR-0009 in the
`events` table and delivers them to the structured log; events carry
identifiers and reason codes only; required events and their per-sink
delivery rows are committed in the same transaction as the state change they
describe, so no login, session, handle or handoff outcome can exist without
its record (or the reverse) and no sink can skip one; delivery is
at-least-once with deduplication by `event_id`; a stalled sink never removes
the storage bound.

## Preconditions and fixtures

- Configuration `tests/fixtures/m1-basic.json` with `events.retention_days = 1`, `events.max_rows = 500`, `events.max_pending_per_sink = 100`; the log sink enabled.
- A log capture on the spawned process; a direct read of the `events` table through the harness.
- Injected clock and ids.

## Main flow

### S014-1 Login flow emits the expected sequence

- Given: scenarios 001–003 executed once.
- When: the `events` table is read in order.
- Then: `login.started` (app, client_ip, navigation), `login.succeeded` (provider, user_id, session_id), `session.created`, `session.handoff` (host), each with `event_id` unique and time-ordered, `request_id` present, `attrs` keys from the allowlist only.

### S014-2 Denials are sampled

- Given: 100 verify calls with the same unknown handle from one IP within 60 s.
- When: table read.
- Then: exactly one `verify.denied` row with `reason=unknown_handle` and `attrs.sampled_count ≥ 99`; the metric counts 100.

### S014-3 Log line shape

- Given: any event.
- When: the log is captured.
- Then: one JSON line per event with the same fields as the row; the line never contains a cookie value, handoff code, `state`, token, password or client secret (asserted by a denylist of the harness's known secret strings).

### S014-4 Retention

- Given: 600 events; the clock advanced past one day for 100 of them.
- When: the hourly prune runs.
- Then: rows older than one day are deleted, then the oldest beyond 500 rows; `login.*`/`session.*` are pruned by the same rules (retention is a policy, loss-prevention is about the write path).

## Alternative flows

### S014-5 Required events are committed with their state change

- Given: the diagnostic batch writer stalled by the harness (1 s per batch, queue of 100).
- When: 1,000 logins (success and failure mixed) and 1,000 denied verifies are produced quickly.
- Then: for every `sessions` row there is exactly one `session.created` row and one `login.succeeded` row with the same `request_id`, each with an `event_deliveries(log, event_id, pending)` row created in the same transaction, and for every `login.failed` attempt a row and a delivery row exist, independent of the stalled writer (they are written through `Events::append_in` in the login transaction); `verify.denied` rows may be fewer, have no delivery rows, and one `events.dropped` row records the count by kind; the stalled writer never delays a login response by more than its store transaction.

### S014-6 Crash atomicity between state and record

- Given: harness crash points (a) after the login transaction commits and (b) inside it, before commit.
- When: the process is killed at each point and restarted.
- Then: (a) both the session and its `session.created`/`login.succeeded` rows are present; (b) neither the session nor the rows exist and the transaction is unconsumed. WAL durability with `synchronous=NORMAL` is accepted to lose only the last transactions on an OS crash; this case covers process crash only.

### S014-7 Delivery is at-least-once from per-sink rows; late commits are never skipped

- Given: fifty events committed while the log sink was stopped, each with a `pending` delivery row; additionally transaction A allocated `e_100` and is held open by the harness while transaction B commits `e_101` and the sink delivers it; then A commits.
- When: the process restarts and the sink runs; separately the harness crashes the process between writing a log line and marking its delivery row `delivered`.
- Then: the sink delivers every `pending` row regardless of id order, including `e_100` after `e_101` (no cursor exists to skip it); every delivered row becomes `delivered` with `attempts ≥ 1`; after the crash the same line appears a second time and the receiver-side deduplication in the harness (by `event_id`) counts it once; no event is delivered zero times. "Exactly once" is not claimed.

### S014-8 A stalled sink never removes the storage bound

- Given: the log sink is held by the harness (never acknowledges); `events.max_pending_per_sink = 100`, `events.max_rows = 500`.
- When: 2,000 required events are produced.
- Then: at most 100 deliveries for the sink are `pending`; older ones are `failed` with `last_error = backlog_overflow` and one `sink.backlog_overflow` event is recorded per overflow batch (metric `hopae_event_deliveries_failed_total{sink="log",reason="backlog_overflow"}`); the `events` table never exceeds 500 rows plus one batch; pruning removes the oldest rows and marks their non-terminal deliveries `failed` (`pruned`); authentication transactions keep succeeding throughout; once the sink is released, the remaining `pending` rows are delivered and `failed` rows are listed for administrator re-queue (M4).

## Abuse cases

| Category | Case | Applies |
| --- | --- | --- |
| Replay | — | no: events are not inputs |
| Tampering | S014-A1 | yes |
| Race / timing | S014-A2 | yes |
| Resource exhaustion | S014-A3 | yes |
| Confused deputy | — | no |
| Spoofed or duplicated headers | S014-A4 | yes |
| Downgrade | — | no |
| Enumeration | — | no |

### S014-A1 User-controlled strings are not stored raw

- Given: a `user-agent` of 10 KiB containing control characters and a JSON-breaking sequence; a provider `name` claim with 5 KiB of text.
- When: events are emitted.
- Then: `ua_sha256` plus a 64-byte sanitized prefix only; `attrs` bounded to 2 KiB with truncation marked; the JSON log line parses.

### S014-A2 Event ordering under concurrency

- Given: 100 concurrent logins.
- When: table read.
- Then: `event_id` values are unique; `session.created` for each session follows its `login.succeeded` in `at` order; no interleaving corrupts a batch.

### S014-A3 Events cannot fill the disk

- Given: `events.max_rows = 500` and a 10,000-event burst of diagnostic kinds, then a 10,000-event burst of required kinds through the login path with the sink stalled.
- When: run.
- Then: the table never exceeds 500 + one batch in either burst; the SQLite file size stays bounded after a checkpoint; the diagnostic burst is recorded as `events.dropped`/`events.pruned`; the required burst is bounded by the transaction-rate limits of scenario 001 and by the per-sink backlog cap of S014-8, never by dropping a required row before commit.

### S014-A4 Spoofed request id

- Given: a client sends `x-request-id: evil`.
- When: a portal request is handled.
- Then: Hopae generates its own `request_id`; the client value is logged, truncated, under `attrs.client_request_id` only if `log.accept_client_request_id = true` (default false).

## Observability expectations

- Log: every event as one JSON line at `info` (`login.failed`, `handoff.rejected` at `warn`).
- Audit: the `events` table is the audit record.
- Metrics: `hopae_events_total{kind,outcome}`, `hopae_events_dropped_total{kind}`, `hopae_events_pruned_total`.

## Test mapping

| Case | Test | File | Kind | Status |
| --- | --- | --- | --- | --- |
| S014-1 | `s014_1_login_flow_event_sequence` | `tests/scenarios/s014_events.rs` | integration | planned |
| S014-2 | `s014_2_denials_sampled` | `tests/scenarios/s014_events.rs` | integration | planned |
| S014-3 | `s014_3_log_line_shape_no_secrets` | `tests/scenarios/s014_events.rs` | integration | planned |
| S014-4 | `s014_4_retention` | `tests/scenarios/s014_events.rs` | integration | planned |
| S014-5 | `s014_5_required_events_committed_with_state` | `tests/scenarios/s014_events.rs` | integration | planned |
| S014-6 | `s014_6_crash_atomicity_state_and_record` | `tests/scenarios/s014_events.rs` | integration | planned |
| S014-7 | `s014_7_at_least_once_delivery_no_skips` | `tests/scenarios/s014_events.rs` | integration | planned |
| S014-8 | `s014_8_stalled_sink_keeps_storage_bound` | `tests/scenarios/s014_events.rs` | integration | planned |
| S014-A1 | `s014_a1_user_strings_not_stored_raw` | `tests/scenarios/s014_events.rs` | unit | planned |
| S014-A2 | `s014_a2_ordering_under_concurrency` | `tests/scenarios/s014_events.rs` | integration | planned |
| S014-A3 | `s014_a3_events_cannot_fill_disk` | `tests/scenarios/s014_events.rs` | integration | planned |
| S014-A4 | `s014_a4_spoofed_request_id` | `tests/scenarios/s014_events.rs` | integration | planned |

## Live verification

| Date | Hopae version | Gateway version | Provider | Environment label | Result | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| — | — | — | — | — | — | The G9 smoke test inspects the `events` table for the smoke login. |

## Open questions

- Is storing `client_ip` for `retention_days` acceptable by default, or should a privacy mode hash it (ADR-0009 reviewer question)?

## 한국어 요약

M1의 모든 흐름은 ADR-0009의 스키마대로 이벤트를 `events` 테이블에 남기고
구조화 로그로 전달합니다. 이벤트에는 식별자와 사유 코드만 있고 쿠키·코드·토큰은
절대 없습니다. 필수 이벤트와 싱크별 전달 행은 상태 변경과 같은 트랜잭션에서
커밋되어 세션과 기록이 어긋나거나 전달이 건너뛰어질 수 없고, 전달은 최소 1회이며
수신자가 `event_id`로 중복을 제거합니다. 싱크가 멈춰도 적체 상한과 보존 정책이
저장소 상한을 지킵니다.
