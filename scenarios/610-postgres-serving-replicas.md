# S610 — Two serving replicas on one PostgreSQL store

<!-- scenario-status: implemented -->

- Area: scale-out
- Milestone: M2
- ADRs: 0002, 0004, 0020
- Threat model: TM-02, TM-10, TM-40
- Gateway contract: verify, handoff

## Goal

Two real `hopae serve` processes on one PostgreSQL database, behind a plain
TCP round-robin, behave as one deployment over HTTP. A login can start on one
replica and finish on the other. A handoff code is redeemed exactly once even
when the same code races to both replicas. Concurrent administrator writes
through both consoles take effect once. A revoked administrator is fenced on
both replicas. Killing one replica with SIGKILL during verify traffic loses no
request that the balancer can route to the survivor, and leaves no duplicate
effect in the store.

## Preconditions and fixtures

- Built with `--features postgres,test-hooks`; `HOPAE_TEST_POSTGRES_URL`
  names a server (key/value form). `make qualify-postgres` provides an
  ephemeral `postgres:17-alpine` with tmpfs data and removes it on exit. The
  case creates its own database `hopae_q_<pid>` and drops it afterwards.
  Without the URL the case is skipped.
- The m4-admin fixture with `store.kind = postgres` (`url_env`, pool 8), the
  same caller key and mock provider secret for both replicas, a mock OIDC
  provider and two in-process round-robin balancers (gateway and portal)
  that skip a backend that refuses connections.

## Main flow

### S610-1 Logins, handoffs, console writes and a killed replica

- Given: replicas A and B started from the same configuration on one empty
  database; the portal CSRF key and the console MAC key are created once in
  the store (`replica_key:*`, insert-if-absent) and shared.
- When:
  1. eight users log in through the balancers, each request landing on
     whichever replica the round-robin picks;
  2. for four fresh logins the same handoff code is sent concurrently to A
     and to B;
  3. an administrator logs in on the console host, is granted `admin`, and
     sends the same session termination and the same user disable to A's and
     B's admin listeners at once; the grant is then revoked and the
     administrator tries another disable on each replica;
  4. verify traffic runs from several threads while B is killed with
     SIGKILL; one more user logs in afterwards.
- Then:
  1. every login completes and verify allows it on either replica;
  2. exactly one redemption per code mints a session, the other is refused
     (4 minted, 4 refused);
  3. one termination reports a change and one `session.terminated` event and
     one `admin.user_disable` event exist; the revoked administrator is
     refused on both replicas and the user stays active;
  4. verify traffic keeps succeeding with no failed request; the store holds
     ten users, unique identities, a complete and unique user-ID ledger, and
     no duplicate event or delivery.

## Abuse cases

| Category | Case | Applies |
| --- | --- | --- |
| Replay | S610-1 | yes: a handoff code raced to two replicas mints one session |
| Race / timing | S610-1 | yes: concurrent console writes on two replicas take effect once; a replica killed mid-traffic leaves no partial effect |
| Confused deputy | S610-1 | yes: a revoked administrator is refused by both replicas, not only the one that saw the revocation |
| Tampering | S610-1 | yes: CSRF and console MAC keys are shared through the store, so a token minted by one replica verifies on the other and nowhere else |
| Spoofed or duplicated headers | — | no: the forwarded headers are those of the existing gateway scenarios |
| Downgrade | — | no: schema checks are S600-5 |
| Enumeration | — | no: no new listing surface |
| Resource exhaustion | — | no: limits are per process (ADR-0020 decision 7) |

## Observability expectations

- Log: unchanged; a replica that loses the database fails closed (verify 503).
- Audit: one `admin.user_disable` and one `session.terminated` event per fenced write, written in the same transaction as the change.
- Metrics: none new.

## Test mapping

| Case | Test | File | Kind | Status |
| --- | --- | --- | --- | --- |
| S610-1 | `s610_1_two_replicas_share_logins_handoffs_fences_and_survive_a_killed_replica` | `tests/scenarios/s610_postgres_replicas.rs` | integration | passing |

## Live verification

| Date | Hopae version | Gateway version | Provider | Environment label | Result | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| 2026-10-17 | 0.0.10 | — | mock OIDC | local-postgres-17-alpine | pass | `make qualify-postgres` step 3: two `hopae serve` processes behind TCP round-robin; 4 of 8 raced handoffs minted; one termination and one disable; revoked administrator refused on both; B killed with SIGKILL under verify load with no failed request. |

## Open questions

- Profile and projection publications are loaded per process. A publication made through one replica is not seen by the other until it restarts, and until then the other replica fails closed on the newer state. A shared invalidation channel (ADR-0020 decision 7) closes this gap.
- The native Human owners (Human snapshot and ledger, native primary sessions, TOTP and WebAuthn provenance) are not on PostgreSQL yet: `human_material_key_env` and `receipt_issuer.human_receipts` are refused at start, and a native primary provider fails closed.

## 한국어 요약

PostgreSQL 데이터베이스 하나에 실제 `hopae serve` 프로세스 두 개를 띄우고 TCP 라운드로빈 뒤에 둡니다. HTTP로 보면 두 복제본은 하나의 배포처럼 동작합니다. 로그인은 한 복제본에서 시작해 다른 복제본에서 끝낼 수 있습니다. 같은 핸드오프 코드를 두 복제본에 동시에 보내도 세션은 한 번만 발급됩니다. 두 콘솔로 동시에 보낸 관리자 쓰기는 한 번만 적용되고, 권한을 회수당한 관리자는 두 복제본 모두에서 거부됩니다. verify 트래픽 중에 한 복제본을 SIGKILL로 죽여도 남은 복제본이 요청을 받고, 저장소에는 중복된 효과가 남지 않습니다. CSRF 키와 콘솔 MAC 키는 저장소에 한 번 만들어 공유합니다. 남은 한계는 두 가지입니다. 게시(프로필·프로젝션) 스냅샷은 프로세스별이라 다른 복제본은 재시작할 때까지 새 상태에서 닫힌 쪽으로 실패합니다. 네이티브 Human 소유자는 아직 이식되지 않아 해당 설정은 시작할 때 거부됩니다.
