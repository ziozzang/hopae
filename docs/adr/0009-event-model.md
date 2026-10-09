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

Delivery: emitters publish on an in-process `tokio::sync::broadcast` bus;
sinks subscribe. M1 sinks: the structured log (every event, one line, JSON)
and the `events` table (every event except sampled-out `verify.denied`),
written by a batching task with a bounded queue; when the queue is full,
`login.*` and `session.*` events are written synchronously (never dropped)
and the drop count of other kinds is itself an event. Retention: `events.
retention_days` (default 90) and `events.max_rows` (default 1,000,000),
pruned hourly oldest-first.

Consumers defined now, implemented later: login history queries (M2) read
the table; throttling (M2) counts `login.failed` per account and per IP in
the store or Redis; webhooks (M5) subscribe to the bus with per-destination
kind filters and deliver HMAC-signed JSON with `event_id` as the idempotency
key; the administrator audit (M4) is `admin.*` events in the same table.

Out of scope: event schemas as a public API (webhook payloads are versioned
separately in M5), log shipping.

## Consequences

### Positive

- One vocabulary of reasons across logs, history, webhooks and the console; one place to enforce "no secrets".
- Webhooks and throttling are subscribers, not new write paths.

### Negative

- A broadcast bus is lossy under slow subscribers by design; the store sink mitigates for the kinds that matter and counts the rest.
- Sampling `verify.denied` hides repeated denials of one client; the counter metric keeps the volume visible.

### Neutral

- Field names are fixed now; adding kinds or `attrs` keys is a minor change; renaming is major.

## Alternatives considered

| Alternative | Why not |
| --- | --- |
| Log lines as the only record, parsed later | Not queryable for lockouts and history; schema drift. |
| Separate tables per consumer (history, audit, webhook outbox) | Three write paths and three vocabularies for one fact. |
| External message broker | A new runtime dependency for a single process; Redis pub/sub (M2) is for invalidation, not durable events. |

## Adversarial review

| Pass | Date | S1 | S2 | S3 | S4 | Outcome |
| --- | --- | --- | --- | --- | --- | --- |
| — | — | — | — | — | — | Pending G2. |

Questions for the reviewer: is the synchronous fallback for `login.*` under
queue pressure a denial-of-service lever against the portal? Does storing
`client_ip` for 90 days need a privacy switch?

## References

- [Architecture — Data model](../ARCHITECTURE.md#data-model)

## 한국어 요약

보안 관련 모든 사건은 하나의 `Event` 타입으로 표현합니다. 식별자와 사유
코드만 담고 자격 증명은 절대 담지 않습니다. M1에서는 구조화 로그와 `events`
테이블에 기록하고, M2의 로그인 기록·시도 차단, M4의 관리자 감사, M5의 웹훅은
같은 버스를 구독하는 소비자로 구현합니다. `login.*`과 `session.*`은 유실하지
않습니다.
