# ADR-0009: One typed event model feeds logs, login history, throttling and webhooks

- Status: Accepted
- Date: 2026-10-09
- Deciders: designer, orchestrator
- Scenarios: 014 (M1); 1xx (history, throttling, M2); 440–469 (webhooks, M5)
- Threat model: TM-12, TM-17
- Supersedes: none

## Context

- Login history, blacklisting, login-attempt blocking, login-notification webhooks and the administrator audit all consume the same facts: who tried what, from where, with which outcome and reason.
- The roadmap forces the event model into M0/M1 so M2 and M5 consume it rather than invent parallel records.
- Logs must carry identifiers only, never credentials ([security rules](../PROCESS.md#security-rules)).

## Decision

Every security-relevant occurrence is an `Event`:

| Field | Type | Notes |
| --- | --- | --- |
| `event_id` | `e_` + 26 chars (time-ordered random) | Unique; also the webhook idempotency key |
| `at` | unix seconds with millisecond fraction | Clock of the emitting instance |
| `kind` | string, dotted | See the catalogue below |
| `outcome` | `success`, `failure`, `info` | |
| `reason` | string code | Stable identifiers such as `invalid_state`, `binding_ip`, `provider_unavailable`; never free text with user input |
| `user_id`, `session_id`, `app_id`, `provider_id` | optional ids | Session id, never the handle |
| `client_ip`, `ua_sha256` | optional | UA stored only as a digest plus a 64-byte sanitized prefix for display |
| `request_id` | string | Correlates with the structured log |
| `attrs` | JSON object ≤ 2 KiB | Kind-specific, allowlisted keys; never tokens, codes, cookies, passwords, emails of third parties |

Kinds in M1: `login.started`, `login.succeeded`, `login.failed`,
`session.created`, `session.handoff`, `handoff.rejected`,
`session.terminated`, `verify.denied` (sampled: at most one per
(session or client IP, reason) per 60 s), `provider.error`,
`config.loaded`, `txn.evicted`. Reserved for later: `factor.enrolled`,
`factor.verified`, `factor.failed`, `block.created`, `lockout.started`,
`admin.*`, `webhook.delivery`, `update.*`.

Delivery is a **transactional outbox**, not a bus (review finding R10):

- Required kinds — `login.*`, `session.*`, `handle.*`, `handoff.*`, `identity.*`, `factor.*`, `block.*`, `admin.*`, `config.loaded` — are written to the `events` table **in the same store transaction** as the state change they describe (`Events::append_in(tx, event)`). A session exists only if its `session.created` event exists. A crash after commit loses nothing; a crash before commit loses both consistently.
- In that same transaction, one `event_deliveries(sink, event_id, state, attempts, next_attempt_at, last_error)` row with `state = pending` is inserted for every enabled sink subscribed to the kind (the structured log; webhook destinations in M5). Delivery workers claim `pending` rows (`SELECT … FOR UPDATE SKIP LOCKED` in PostgreSQL, the single writer in SQLite); there is **no cursor** over event ids, so a transaction that commits late can never be skipped (review finding N04).
- Delivery is **at-least-once**: a worker may crash between sending and marking `delivered`, so a line or a webhook may be repeated; receivers deduplicate by `event_id`, which every payload and log line carries. Exactly-once is not claimed anywhere.
- Diagnostic kinds — `verify.denied` (sampled), `provider.error`, `txn.evicted`, `events.dropped` — are written by a bounded best-effort batch writer without delivery rows; drops are counted and reported as `events.dropped`.
- Security counters are **not** derived from events: throttling and lockout (M2) update their counters synchronously and atomically (an SQL `UPDATE … RETURNING` or a Redis script, as the gateway's counters do) before an attempt is admitted; the `login.failed` event is written in the same transaction for history.

Backlog and retention are bounded, and the storage bound wins (review
findings N05, N14):

- Per sink, `events.max_pending_per_sink` (default 10,000) pending or retrying deliveries are kept; beyond that the oldest are moved to `state = failed` with `last_error = backlog_overflow`, and a `sink.backlog_overflow` event (one per overflow batch) plus metric `hopae_event_deliveries_failed_total{sink,reason}` report it. Retries use exponential backoff capped at 24 h total, after which a delivery is `failed` (`retries_exhausted`).
- Pruning runs whenever `events.prune_every` (default 1,000) rows have been inserted since the last prune or 60 s have elapsed, whichever comes first. It deletes event rows older than `events.retention_days` (default 90) and then the oldest rows beyond `events.max_rows` (default 1,000,000), **regardless of delivery state**; a row with a non-terminal delivery has it marked `failed` (`pruned`) and counted before deletion. The event table therefore never exceeds `events.max_rows + events.prune_every` rows.
- Delivery rows are deleted with their parent event in the same prune statement (foreign key with cascade), terminal rows included. Independently, `delivered` and `failed` delivery rows older than `events.delivery_terminal_retention_days` (default 7) are deleted even while their event remains, so a stalled sink accumulates at most the pending cap plus seven days of terminal rows. Failure visibility survives deletion through the metric and the `sink.*` events, which are ordinary events under the same retention.
- `failed` deliveries are visible in the console (M4) and can be re-queued by an administrator while the event row still exists.

Consumers defined now, implemented later: login history queries (M2) read
the table; webhooks (M5) deliver HMAC-signed JSON per destination from the
durable rows, `event_id` as the idempotency key, per-destination delivery
rows and retry state as above; the administrator audit (M4) is `admin.*`
events in the same table.

Out of scope: event schemas as a public API (webhook payloads are versioned
separately in M5), log shipping.

## Consequences

### Positive

- One vocabulary of reasons across logs, history, webhooks and the console; one place to enforce "no secrets".
- Audit rows and state changes cannot disagree; a sink can never skip an event; a stalled sink can never exhaust the disk.

### Negative

- Every login or session write carries an extra row per subscribed sink in its transaction; the batching writer only exists for diagnostics.
- At-least-once delivery means receivers must deduplicate; the log may contain a repeated line after a crash.
- Sampling `verify.denied` hides repeated denials of one client; the counter metric keeps the volume visible.

### Neutral

- Field names are fixed now; adding kinds or `attrs` keys is a minor change; renaming is major.

## Alternatives considered

| Alternative | Why not |
| --- | --- |
| Log lines as the only record, parsed later | Not queryable for lockouts and history; schema drift. |
| Separate tables per consumer (history, audit, webhook outbox) | Three write paths and three vocabularies for one fact. |
| In-process broadcast bus with a store subscriber and a synchronous fallback (the G1 draft) | Rejected after review finding R10: a lagging receiver is overwritten before the fallback can see it; counters derived from events undercount. |
| Per-sink cursor over time-ordered event ids (the pass-1 revision) | Rejected after review finding N04: an event whose transaction commits after a later id was delivered is skipped forever; cursor-protected retention also made storage unbounded (N05). |
| External message broker | A new runtime dependency for a single process; Redis pub/sub (M2) is for invalidation, not durable events. |

## Adversarial review

| Pass | Date | S1 | S2 | S3 | S4 | Outcome |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | 2026-10-09 | 0 | 1 | 0 | 0 | 1 × FIX_FIRST applied (R10) |
| 2 | 2026-10-09 | 1 | 1 | 0 | 0 | R10 PARTIAL → N04, N05 FIX_FIRST applied (per-sink delivery rows, at-least-once with dedup, bounded backlog with dead-letter) |
| 3 | 2026-10-09 | 0 | 1 | 0 | 0 | R10, N04 CLOSED; N05 PARTIAL → N14 FIX applied (delivery rows die with their event, terminal-row retention, quantified prune cadence). Awaiting confirmation pass. |
| 4 | 2026-10-09 | 0 | 0 | 0 | 0 | N05, N14 CLOSED. Accepted pending confirmation pass. |

Findings and dispositions:

- N14 (S2, pass 3): terminal delivery rows had no collection rule and the hourly sweep contradicted the scenario's instantaneous cap. FIX: cascade deletion with the parent event, `delivery_terminal_retention_days`, prune every `prune_every` inserts or 60 s, bound stated as `max_rows + prune_every`; scenario 014-8 restated.

- N04 (S1, pass 2): a time-ordered id cursor could skip a late-committing event, and "exactly once" was unachievable. FIX_FIRST: `event_deliveries` rows in the event's transaction, claimed by workers; at-least-once with `event_id` deduplication; scenario 014-7 rewritten.
- N05 (S2, pass 2): cursor-protected retention let a stalled sink grow the table without bound. FIX_FIRST: `max_pending_per_sink`, retry cap, dead-letter `failed` state, pruning regardless of delivery state; scenario 014-8.

- R10 (S2): the broadcast bus could lose `login.failed` events and undercount throttling. FIX_FIRST: transactional outbox for required kinds, durable sink cursors, synchronous atomic counters; scenario 014-5 and 014-6 rewritten.

Open for the reviewer: does storing `client_ip` for 90 days need a privacy
switch?

## References

- [Architecture — Data model](../ARCHITECTURE.md#data-model)

## 한국어 요약

보안 관련 모든 사건은 하나의 `Event` 타입으로 표현합니다. 식별자와 사유
코드만 담고 자격 증명은 절대 담지 않습니다. 필수 이벤트와 싱크별 전달 행은
상태 변경과 같은 트랜잭션에서 커밋되어 세션과 기록이 어긋나거나 전달이 건너뛰어
질 수 없습니다. 전달은 최소 1회이며 수신자는 `event_id`로 중복을 제거합니다.
싱크가 멈추면 전달 적체는 상한에서 실패 상태로 옮겨지고 보존 정책이 저장소 상한을
지킵니다. 시도 차단 카운터는 이벤트가 아니라 동기 원자 연산으로 갱신합니다.
