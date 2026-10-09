# ADR-0002: SQLite is the primary store; PostgreSQL for shared deployments; Redis is cache and bus only

- Status: Proposed
- Date: 2026-10-09
- Deciders: designer, orchestrator
- Scenarios: 004, 010, 013, 014
- Threat model: TM-07, TM-12, TM-18, TM-20
- Supersedes: none

## Context

- Verify runs on every protected request; the lookup path must cost microseconds locally and must never widen access when a dependency fails ([process security rules](../PROCESS.md#security-rules): fail closed).
- The gateway embeds SQLite (`rusqlite` 0.37, bundled) for its account and configuration stores and also supports PostgreSQL (`tokio-postgres`) and Redis (`redis` 1 with `connection-manager`, TLS rules, 900 ms timeouts, fail closed) — a proven dependency set and operational pattern to copy.
- The brief asks for a shared login-state cache across several instances using Redis/Valkey.
- Multi-instance correctness needs one shared directory: a user id minted on instance A must be the id instance B emits in `x-forwarded-user`; blocks and account linking must be visible everywhere. A session record alone cannot carry that.
- Operators of a single gateway should not need a database server to run an identity provider.

## Decision

Hopae stores all durable state in a primary relational store behind three
traits — `Directory` (users, identities, providers, apps, blocks, admins,
webhooks), `Sessions` (sessions, handles, transactions, handoff codes,
attempts) and `Events` (append-only events) — with two backends:

| `store.kind` | Backend | Deployment |
| --- | --- | --- |
| `sqlite` (default) | `rusqlite` bundled, WAL, `synchronous=NORMAL`, `foreign_keys=ON`, one writer task fed by a channel, readers on a blocking pool; embedded migrations keyed by `user_version` | Single instance; restart is the HA story; M1 |
| `postgres` | `tokio-postgres` with rustls; the same migrations in SQL dialect files; advisory lock for migrations | Two or more instances sharing one directory; M2 |

Redis/Valkey is never a source of truth. From M2 it serves as: a write-through
cache of session lookups keyed by handle digest with the session's remaining
lifetime as TTL; the pub/sub invalidation channel; and the home of throttling
counters (`attempts`) when configured, following the gateway's atomic-script
pattern. A cache miss, timeout or error falls back to the primary store; a
Redis outage disables the local cache (TTL 0) and logs `cache_degraded`.

Hot-path bounds: a verify does one `session_handles` lookup joined with
`sessions` (indexed by digest), one `users` lookup for `status` and
`authz_version` (identity and authorization state are never served from a
timed snapshot), one `apps` lookup from an in-memory **configuration**
snapshot that is replaced when configuration changes (and publishes an `all`
invalidation), and a coalesced `last_seen_at` write at most every 30 s per
handle.

Deadline budget: a verify has a total budget `gateway.verify_budget_ms`
(default 400, below the recommended gateway timeout of 500 ms). Each cache
operation gets `cache.op_timeout_ms` (default 50); on timeout the lookup
falls through to the primary store with the remaining budget. Three
consecutive cache timeouts open a breaker that bypasses the cache for 5 s and
logs `cache_degraded`. A stalled connection (accepted, never answering) is
the test case, not only a refused connection.

Durable events: the `Events` trait exposes `append_in(&mut tx, event)` so
that required audit events are committed in the same transaction as the
state change they describe ([ADR-0009](0009-event-model.md)).

Out of scope: distributed SQLite (replication, shared filesystems),
MySQL, embedded key-value stores.

## Consequences

### Positive

- Zero external dependencies for the common single-gateway deployment; a file copy of a checkpointed database is a backup.
- The multi-instance path is explicit and correct (shared directory) rather than "sessions in Redis and hope the ids agree".
- Reuses dependencies and patterns already audited in the gateway.

### Negative

- Two SQL dialects to keep in step; every migration ships twice and is tested on both backends from M2.
- SQLite deployments have no active-active HA; the micro-cache TTL (HC-1) and fast restart are the only buffers.
- Trait-shaped stores forbid ad hoc SQL in handlers; every query is a named method, which is more code up front.

### Neutral

- Roadmap M2 gains the PostgreSQL backend (moved up from the backlog) so that its multi-instance exit criterion is honest.
- M7 adds backup and restore for SQLite and documents PostgreSQL operations.

## Alternatives considered

| Alternative | Why not |
| --- | --- |
| PostgreSQL only | Forces a database server on the simplest deployment, contrary to the single-binary positioning; the gateway proves SQLite is sufficient for this class of data. |
| SQLite only, sessions in Redis for multi-instance | User ids, identities, blocks and linking would diverge between instances; sessions self-contained in Redis cannot answer "is this user disabled" consistently. Fails the correctness requirement. |
| Redis/Valkey as the only store | No relational queries for login history and management; durability depends on AOF configuration; a cache eviction would be data loss. |
| `sqlx` or an ORM | Compile-time query checking needs a live database in the build; the gateway's `rusqlite` + `tokio-postgres` pair is lighter and already in the dependency set. |
| Embedded key-value store (sled, redb) | No SQL for history queries and management filters; a third dialect of persistence to maintain. |

## Adversarial review

| Pass | Date | S1 | S2 | S3 | S4 | Outcome |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | 2026-10-09 | 1 | 3 | 0 | 0 | 4 × FIX_FIRST applied (shared findings R06, R08, R10, R11) |

Findings and dispositions:

- R06 (S1, shared with ADR-0009): a 5 s directory snapshot would serve stale user status and groups. FIX_FIRST: verify reads `users.status` and `users.authz_version` on every call; the in-memory snapshot holds configuration only.
- R08 (S2, shared with ADR-0006): directory staleness contributed to an unbounded freshness claim. FIX_FIRST: identity state is read per verify; configuration changes publish `all`.
- R10 (S2, shared with ADR-0009): an in-process bus cannot guarantee audit delivery. FIX_FIRST: `append_in(tx, event)` commits required events with the state change.
- R11 (S2): copying the gateway's 900 ms Redis timeout would exceed the gateway's verify timeout. FIX_FIRST: 400 ms verify budget, 50 ms cache operations, breaker, stalled-connection test (scenario 004-9).

Open for the reviewer: is the coalesced `last_seen_at` write (30 s) acceptable
given per-handle idle expiry (ADR-0007)?

## References

- [Architecture — Storage](../ARCHITECTURE.md#storage)
- Gateway `src/security_redis.rs` (connection manager, TLS rules, fail-closed counters), `Cargo.toml` (rusqlite 0.37, tokio-postgres 0.7, redis 1), reviewed 2026-10-09.

## 한국어 요약

기본 저장소는 SQLite(rusqlite, WAL)이며 단일 인스턴스 배포의 기본값입니다.
여러 인스턴스가 사용자 ID, 연결 정보, 차단 목록을 공유해야 하므로 다중 인스턴스
배포는 PostgreSQL을 사용합니다(M2). Redis/Valkey는 세션 조회 캐시, 무효화
pub/sub, 시도 횟수 카운터로만 쓰며 절대 진실의 원천이 아닙니다. 캐시 장애는
기본 저장소로 폴백하고, 접근을 넓히는 일은 없습니다.
