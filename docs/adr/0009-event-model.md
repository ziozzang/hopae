# ADR-0009: One typed event model feeds logs, login history, throttling and webhooks

- Status: Proposed
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
- Diagnostic kinds — `verify.denied` (sampled), `provider.error`, `txn.evicted`, `events.dropped` — are written by a bounded best-effort batch writer; drops are counted and reported as `events.dropped`.
- An in-process notification channel carries only event ids after commit; sinks (the structured log, webhooks in M5) read the durable rows by id and keep a durable cursor (`event_sinks(sink, last_event_id)`), so a slow or restarted sink resumes without loss. The log sink may fall behind; the table is the record.
- Security counters are **not** derived from events: throttling and lockout (M2) update their counters synchronously and atomically (an SQL `UPDATE … RETURNING` or a Redis script, as the gateway's counters do) before an attempt is admitted; the `login.failed` event is written in the same transaction for history.

Retention: `events.retention_days` (default 90) and `events.max_rows`
(default 1,000,000), pruned hourly oldest-first; pruning never removes rows
newer than any sink's cursor.

Consumers defined now, implemented later: login history queries (M2) read
the table; webhooks (M5) deliver HMAC-signed JSON per destination from the
durable rows with `event_id` as the idempotency key and a per-destination
cursor and retry state; the administrator audit (M4) is `admin.*` events in
the same table.

Out of scope: event schemas as a public API (webhook payloads are versioned
separately in M5), log shipping.

## Consequences

### Positive

- One vocabulary of reasons across logs, history, webhooks and the console; one place to enforce "no secrets".
- Audit rows and state changes cannot disagree; webhooks replay from durable rows after a restart.

### Negative

- Every login or session write carries an extra row in its transaction; the batching writer only exists for diagnostics.
- Sampling `verify.denied` hides repeated denials of one client; the counter metric keeps the volume visible.

### Neutral

- Field names are fixed now; adding kinds or `attrs` keys is a minor change; renaming is major.

## Alternatives considered

| Alternative | Why not |
| --- | --- |
| Log lines as the only record, parsed later | Not queryable for lockouts and history; schema drift. |
| Separate tables per consumer (history, audit, webhook outbox) | Three write paths and three vocabularies for one fact. |
| In-process broadcast bus with a store subscriber and a synchronous fallback (the G1 draft) | Rejected after review finding R10: a lagging receiver is overwritten before the fallback can see it; counters derived from events undercount. |
| External message broker | A new runtime dependency for a single process; Redis pub/sub (M2) is for invalidation, not durable events. |

## Adversarial review

| Pass | Date | S1 | S2 | S3 | S4 | Outcome |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | 2026-10-09 | 0 | 1 | 0 | 0 | 1 × FIX_FIRST applied (R10) |

Findings and dispositions:

- R10 (S2): the broadcast bus could lose `login.failed` events and undercount throttling. FIX_FIRST: transactional outbox for required kinds, durable sink cursors, synchronous atomic counters; scenario 014-5 and 014-6 rewritten.

Open for the reviewer: does storing `client_ip` for 90 days need a privacy
switch?

## References

- [Architecture — Data model](../ARCHITECTURE.md#data-model)

## 한국어 요약

보안 관련 모든 사건은 하나의 `Event` 타입으로 표현합니다. 식별자와 사유
코드만 담고 자격 증명은 절대 담지 않습니다. M1에서는 구조화 로그와 `events`
테이블에 기록하고, M2의 로그인 기록·시도 차단, M4의 관리자 감사, M5의 웹훅은
같은 버스를 구독하는 소비자로 구현합니다. `login.*`과 `session.*`은 유실하지
않습니다.
