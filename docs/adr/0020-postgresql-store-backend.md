# ADR-0020: PostgreSQL backend for the primary store, delivered in vertical slices behind one store contract

- Status: Proposed
- Date: 2026-10-17
- Deciders: designer, orchestrator
- Scenarios: 600 (dual-backend store contract, slice 1)
- Threat model: TM-02, TM-10, TM-40 (session state integrity), TM-60 (directory reads); new rows deferred to slice 2 (replay ledgers across replicas)
- Supersedes: none (implements the PostgreSQL half of [ADR-0002](0002-primary-store-sqlite-with-postgres-for-shared-deployments.md); refines ROADMAP M2)

## Context

- Hangang ADR 0022 (Kubernetes-native World package) needs an HA Helm profile:
  Hopae replicas (N ≥ 2) sharing users, identities, sessions, credentials,
  groups and the audit outbox. ADR-0002 already decided "SQLite primary,
  PostgreSQL for shared deployments, Redis/Valkey cache and bus only"; ROADMAP
  M2 lists the PostgreSQL backend and its exit test (two instances share
  sessions and invalidate each other's caches).
- Store layer today (`src/store/`, about 24,700 lines):
  - Contract: the `Directory`, `Sessions`, `Events`, `Factors` and `Passkeys`
    traits, implemented only by `sqlite::Store`. Many subsystems also take the
    concrete `sqlite::Store` or a raw `rusqlite::Connection`: groups, the
    subject directory, the authentication-gateway publication and receipt
    owners (`auth_gateway::{publication, receipt_*, projection_*,
    workload_owner}`), the Hangang delegation nonce file, backups and the
    Human owners.
  - Execution model: WAL; **one writer thread** fed by a channel; readers on
    the blocking pool. Every mutation is one `BEGIN IMMEDIATE` transaction
    carrying its required events and their `event_deliveries` rows
    (transactional outbox, ADR-0009). Deadlines are checked after the lock is
    won and again before `COMMIT`; SQLite is interrupted at the deadline.
  - Invariants from serialization: because there is exactly one writer, every
    read-then-write inside a transaction is race-free without row locks:
    - administrator fences (`begin_fenced`: actor grant, session and
      credential generation checked inside the write);
    - compare-and-swap revisions (groups, profiles, projections, material
      owners);
    - "consume exactly once" updates (`login_txns`, `handoff_codes`, logout
      tickets);
    - `cred_gen` increments;
    - the Human user-ID reservation ledger `human_user_ids` (schema 10):
      triggers reserve every new `users.user_id` forever and refuse reuse.
  - Schema: migrations 0001–0014 (0011–0013 reserved by the passkey branch;
    0015 is taken by the service-credential branch), all tables `STRICT`,
    `CHECK` constraints for enumerations, 0/1 booleans and 32-byte digests.
    Further triggers enforce immutability (Human realm, material owners,
    provider identity) and a capacity budget. Times are integer UTC seconds
    from the injected `Clock`, except `events.at` (seconds with a millisecond
    fraction).
- Per-process state that a second replica would not see:
  - the console's per-actor read buckets (`admin::reads`);
  - the service-credential buckets;
  - touch coalescing (`verify::engine`);
  - the Hangang delegation nonce file;
  - provider discovery/JWKS caches;
  - the Kubernetes workload caches and watches;
  - the receipt replay index (kept in the SQLite `meta` table).
  `txn_admissions` and the handoff and receipt replay rows are already in the
  store.
- Rollback constraints: [HOPAE_STATE_ROLLOUT](https://github.com/ziozzang/hangang-zerotrust/blob/main/docs/HOPAE_STATE_ROLLOUT.md)
  forbids an older binary from opening a newer schema (schema 10 rollback is a
  sealed, stopped-state restore of a prepared old copy; never merge
  databases, never delete tombstones or replay rows). Any PostgreSQL path must
  keep the same "refuse newer schema, never down-migrate in place" rule, and the
  SQLite → PostgreSQL move must be an explicit, audited, one-way migration
  with the SQLite file kept as the rollback artifact.

## Decision

Hopae gains a PostgreSQL backend selected by `store.kind = "postgres"` (alias
`store.backend`), compiled behind the cargo feature `postgres`, delivered in
vertical slices. SQLite stays the default and its behavior is unchanged. Every
slice is defined by a backend-neutral contract and a conformance suite that runs
against both backends.

1. **Trait boundary.**
   - Slices are carved out of the existing traits as narrow contracts.
     Slice 1 is `store::core::CoreStore`:
     - users and identities: `user`, `user_authz`, `user_by_email`,
       `identity`, `create_user` (with the user-ID ledger), `link_identity`,
       `touch_identity`;
     - providers: `ensure_provider` (bootstrap/import subset);
     - sessions: `create_session` (including consumption of its login
       transaction), `session`, `lookup_handle`, `touch_handle`,
       `revoke_handle`, `terminate_session`;
     - the outbox: `append_required` and an ordered `recent_events` read.
   - `sqlite::Store` implements it by delegation; `postgres::PgStore`
     implements it natively.
   - Later slices move the remaining trait methods, then the concrete-`Store`
     and raw-`Connection` owners, behind traits. Until a subsystem has moved,
     `kind = "postgres"` refuses the configuration that enables it at
     preflight; a partial deployment never starts.
2. **Transactions and isolation.**
   - PostgreSQL runs `READ COMMITTED` with explicit locking. This mirrors
     what the single SQLite writer guarantees.
   - Every read-then-write invariant takes `SELECT … FOR UPDATE` on the rows
     it depends on: the session row before `cred_gen` changes and handle
     revocation, the handle row on revocation, the actor grant and session
     rows in fences (slice 2).
   - Consume-once updates stay single conditional `UPDATE … WHERE
     consumed_at IS NULL` statements that must affect exactly one row.
   - CAS revisions stay `UPDATE … WHERE revision = $expected`.
   - Uniqueness is enforced by constraints, never by read-then-insert alone.
     Unique-violation `23505` maps to `Conflict`; `40001` and `40P01` map to
     `Busy` and are retried at most twice by the store with jitter.
   - `SERIALIZABLE` is used only for multi-row decisions that cannot be
     expressed as row locks: the grant import's four phases and group
     membership replacement, from slice 2.
   - Deadlines become `SET LOCAL statement_timeout` from the remaining
     budget plus a client-side timeout that cancels the query. A deadline
     never commits late: the deadline check runs before `COMMIT`.
3. **Ledger and replay uniqueness across replicas.**
   - The user-ID reservation ledger, consumed codes and tickets, receipt and
     delegation nonces, and replay rows are primary keys in PostgreSQL. The
     ledger keeps triggers equivalent to schema 10 (reserve on user insert;
     refuse reuse, update and delete).
   - A replica therefore cannot accept what another replica has consumed.
     The Hangang delegation nonce file and the `meta`-table replay index move
     into store tables (slice 2) instead of per-process files.
4. **Schema and migrations.**
   - PostgreSQL has its own embedded, versioned migration set
     (`src/store/postgres/migrations/NNNN_*.sql`). Its numbering is
     independent of SQLite, and both record into `schema_migrations`.
   - Types:
     - `STRICT` → native types;
     - 0/1 → `boolean`;
     - digests → `bytea` with `CHECK (octet_length(x) = 32)`;
     - JSON → `jsonb` only where queried, `text` otherwise (identical
       round-trip);
     - times stay `bigint` seconds from the injected clock and `events.at`
       stays `double precision`, so both backends produce identical rows and
       tests share clocks.
   - Migrations run under `pg_advisory_xact_lock` in one transaction, so
     concurrent replicas cannot race. A database newer than the binary is
     refused at start (`SchemaTooNew`), as in SQLite. Down-migrations do not
     exist: rollback is restore from backup or PITR, with the rollout tool's
     sealing rules.
5. **Migration tooling and dual-backend tests.**
   - `hopae store migrate-to-postgres --from <sqlite> --to-env <URL_ENV>`
     (slice 4) runs against a stopped instance holding its lock. It copies
     table by table in ledger and foreign-key order inside one PostgreSQL
     transaction and verifies row counts and digests per table. It refuses a
     non-empty target. It writes an audited `store.migrated` event and leaves
     the SQLite file untouched as the rollback artifact (never merged back).
   - Every slice's conformance suite (`store::conformance`) runs against
     SQLite always and against PostgreSQL when `HOPAE_TEST_POSTGRES_URL` is
     set. Each PostgreSQL run uses a fresh schema dropped at the end.
     `make test-postgres` (`tools/test_postgres.sh`) runs it locally against an
     ephemeral `postgres:17-alpine` container on tmpfs that is removed on
     exit; hosted CI stays disabled while the project's handoff is paused.
6. **Connection pooling and failover.**
   - `deadpool-postgres` sizes the pool by `store.postgres.pool_size`
     (default 16, at most 128) with a connect timeout and recycling checks.
   - The URL is read from an environment reference (`url_env`), never inline.
   - TLS uses rustls with `ca_file` (`sslmode` equivalent `verify-full`).
     Plain TCP is allowed only to loopback and Unix sockets.
   - Failover follows the cluster: a connection error or `57P01`/`57P03`
     (admin shutdown, read-only standby) maps to `Unavailable`, so requests
     fail closed (verify answers 503, never allow). The pool reconnects.
   - Writers require a primary. Every write transaction asserts
     `transaction_read_only = off`, and a standby refuses writes rather than
     silently queuing them.
   - Read replicas are not used for decisions (no stale-read allow).
7. **Shared caches and limits.**
   - Correctness state lives in PostgreSQL: replay ledgers, nonces,
     consume-once rows, lockout state that must be exact (M2 throttling
     `synchronous atomic counters` use `INSERT … ON CONFLICT … RETURNING`
     counters).
   - Advisory rate limits stay per process, with the multiplication by
     replica count documented: console read buckets and service-credential
     buckets.
   - The generation-stamped invalidation channel and best-effort throttling
     counters use Redis/Valkey per ADR-0002, with PostgreSQL
     `LISTEN/NOTIFY` as the fallback invalidation bus when Redis is not
     configured.
   - Provider, JWKS and workload caches remain per process (their staleness
     bounds are per process by design).

**Slice plan.**

| Slice | Scope |
| --- | --- |
| 1 | `CoreStore`, PostgreSQL schema v1 (users, identities, providers, the user-ID ledger, sessions, handles, login transactions, handoff codes, events, deliveries), the conformance harness, config `store.kind = postgres` validated at preflight and refused by `serve` as incomplete |
| 2a | Login transactions (cap, eviction bound, binding, consume-once) and the ADR-0004 handoff redemption (`HandoffStore`; code and session rows locked `FOR UPDATE`; the transaction count/evict/insert serialized by an advisory lock) — implemented |
| 2b | Administrator fences and grants, factors and passkeys, the delegation and replay nonces moved into the store |
| 3 | Groups, subject directory and console listings (window queries rewritten without `INDEXED BY`), the event relay and pruning |
| 4 | Authentication-gateway owners (publication, receipts, projections), the migration tool, `serve` enabled, two-replica qualification (ROADMAP M2 exit) |

## Consequences

### Positive

- One correctness contract for both backends, enforced by the same tests.
- Uniqueness, consume-once and fences become database guarantees across
  replicas instead of artifacts of a single writer thread.
- SQLite deployments are unaffected: default backend, no new runtime
  dependency unless the `postgres` feature is compiled.

### Negative

- Two schemas to maintain. Every migration lands twice, reviewed together.
- `READ COMMITTED` plus explicit locks puts a burden on reviewers: each new
  write must name the rows it locks. The conformance suite catches lost
  updates only where a test races them.
- Until slice 4, `store.kind = postgres` is a library and test capability, not
  a deployable mode.

### Neutral

- New config keys: `store.kind = postgres` (alias `store.backend`) and
  `store.postgres.{url_env, ca_file, pool_size, connect_timeout_ms,
  statement_timeout_ms}`.
- Follow-up scenarios 601–604 (slices 2–4, two-replica qualification).

## Alternatives considered

| Alternative | Why not |
| --- | --- |
| `SERIALIZABLE` everywhere | Simplest reasoning, but every conflicting transaction on hot rows (handle touch, session revocation) retries. Under load the retry storm would raise verify latency above the gateway budget. Explicit locks give the same invariants with predictable waits. |
| `sqlx` with compile-time checked queries | Needs a live database (or offline metadata) at build time for both backends and a second async runtime layer. `tokio-postgres` matches ADR-0002's reference stack and keeps queries explicit like the SQLite code. |
| One generic SQL layer for both backends | SQLite and PostgreSQL differ exactly where the invariants live: locking, `INDEXED BY`, `RETURNING`, trigger syntax. A shared layer would hide those differences, and they are what the review must see. |
| Big-bang port of all store code | About 24,700 lines plus raw-connection owners. One PR could not be reviewed against the fences and outbox rules. Slices keep each review at one contract. |
| Redis for replay and nonce ledgers | ADR-0002: Redis is never a source of truth; an eviction or failover would re-admit a consumed nonce. |

## Adversarial review

| Pass | Date | S1 | S2 | S3 | S4 | Outcome |
| --- | --- | --- | --- | --- | --- | --- |
| — | — | — | — | — | — | Not yet reviewed (Proposed) |

## References

- [ADR-0002](0002-primary-store-sqlite-with-postgres-for-shared-deployments.md), [ADR-0009](0009-event-model.md), [ADR-0006](0006-verify-caching-and-invalidation.md)
- Hangang ADR 0022 (Kubernetes-native World package, Decision 6: HA and state)
- [ROADMAP M2](../ROADMAP.md)
- PostgreSQL documentation: transaction isolation, explicit locking, advisory locks

## 한국어 요약

HA 배포(한강 ADR 0022)를 위해 호패 저장소에 PostgreSQL 백엔드를 `store.kind = "postgres"`(별칭 `store.backend`)와 cargo feature `postgres` 뒤에 추가합니다. 슬라이스 단위로 진행하며 SQLite는 기본값으로 동작이 바뀌지 않습니다.

- **격리 수준:** PostgreSQL은 READ COMMITTED에 명시적 행 잠금(`FOR UPDATE`), 조건부 1회 소비 UPDATE, 제약 조건 기반 고유성을 씁니다. 한 번에 하나의 쓰기만 하는 SQLite의 보장을 재현하고, SERIALIZABLE은 다중 행 결정에만 씁니다.
- **복제본 간 고유성:** 사용자 ID 원장, 재사용 방지 행, nonce를 기본 키와 트리거로 강제합니다.
- **마이그레이션:** 별도의 버전 관리 마이그레이션을 advisory lock 아래에서 실행합니다. 더 새로운 스키마는 거부하고 하향 마이그레이션은 없습니다. SQLite에서 PostgreSQL로의 이전은 감사되는 일방향 도구이며 SQLite 파일을 롤백 산출물로 남깁니다.
- **연결:** deadpool 풀과 rustls TLS를 쓰고, 장애 조치 중에는 503(실패 시 닫힘)으로 응답합니다.
- **공유 상태:** 정확해야 하는 상태는 PostgreSQL에, 무효화 버스와 best-effort 카운터는 Redis(대체로 LISTEN/NOTIFY)에 둡니다. 권고성 비율 제한은 프로세스별로 남기고, 복제본 수만큼 곱해지는 점을 문서화합니다.
- **슬라이스 1:** 사용자, 신원, 세션, 핸들, 이벤트의 `CoreStore` 계약과 양쪽 백엔드 적합성 테스트입니다.
