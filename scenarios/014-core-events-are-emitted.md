# S014 — Core flows emit events with the fixed schema

<!-- scenario-status: draft -->

- Area: core
- Milestone: M1
- ADRs: 0009
- Threat model: TM-12, TM-17
- Gateway contract: n/a

## Goal

Every M1 flow emits typed events with the schema of ADR-0009 to the
structured log and the `events` table; events carry identifiers and reason
codes only; the store sink never loses `login.*` or `session.*` events and
bounds everything else.

## Preconditions and fixtures

- Configuration `tests/fixtures/m1-basic.json` with `events.retention_days = 1`, `events.max_rows = 500`.
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

### S014-5 Queue pressure never drops login or session events

- Given: the store sink slowed to 1 s per batch and a bounded queue of 100.
- When: 1,000 `login.failed` and 1,000 `verify.denied` events are produced quickly.
- Then: all 1,000 `login.failed` rows exist (synchronous fallback); `verify.denied` rows may be fewer and one `events.dropped` row records the count by kind.

### S014-6 Events survive a crash after the write

- Given: the process is killed right after a `login.succeeded` write returns.
- When: restarted.
- Then: the row is present (WAL durability with `synchronous=NORMAL` is accepted to lose only the last transactions on OS crash; this case covers process crash only).

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

- Given: `events.max_rows = 500` and a 10,000-event burst.
- When: run.
- Then: the table never exceeds 500 + one batch; the SQLite file size stays bounded after a checkpoint; the burst cost is recorded as `events.dropped`/`events.pruned`.

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
| S014-5 | `s014_5_queue_pressure_keeps_login_events` | `tests/scenarios/s014_events.rs` | integration | planned |
| S014-6 | `s014_6_events_survive_process_crash` | `tests/scenarios/s014_events.rs` | integration | planned |
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

M1의 모든 흐름은 ADR-0009의 스키마대로 이벤트를 구조화 로그와 `events`
테이블에 남깁니다. 이벤트에는 식별자와 사유 코드만 있고 쿠키·코드·토큰은 절대
없습니다. `login.*`과 `session.*`은 큐 압력에서도 유실되지 않고, 거부 사건은
샘플링되며, 보존 기간과 최대 행 수로 디스크 사용을 제한합니다.
