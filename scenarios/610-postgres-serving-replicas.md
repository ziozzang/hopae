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
both replicas. A profile or projection publication made through one replica
is enforced by the other within two seconds, also when the other replica's
`LISTEN` connection was dropped and it missed the notification. Killing one
replica with SIGKILL during verify traffic loses no
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
- `human_material_key_env` on both replicas: the native Human owners are
  active, so every login records its native primary provenance.
- A service application `svc.example.test` with a bootstrap authentication
  profile (one API key from the environment of both replicas) and bootstrap
  credential-projection plans (revision 1).

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
  4. before that revocation, the administrator publishes profiles: a
     tombstone through A; then, with every `hopae-listen` connection
     terminated (`pg_terminate_backend`), the profile again through A; then
     a tombstone through B and the profile through A; and projection plans:
     a tombstone through A, new plans through B, a tombstone through A;
  5. verify traffic runs from several threads while B is killed with
     SIGKILL; one more user logs in afterwards.
- Then:
  1. every login completes and verify allows it on either replica;
  2. exactly one redemption per code mints a session, the other is refused
     (4 minted, 4 refused);
  3. one termination reports a change and one `session.terminated` event and
     one `admin.user_disable` event exist; the revoked administrator is
     refused on both replicas and the user stays active;
  4. the API-key service call on the other replica follows each profile
     publication in under two seconds, whether by `NOTIFY` or (listeners
     dropped, none connected at publish time) by the one-second poll; the
     publishing replica enforces its own publication at once; a stale
     `If-Match` revision is refused (409) on either replica; five profile
     audit rows exist (bootstrap and four publications); a projection PUT on
     the other replica succeeds within two seconds of the previous one,
     that is, once it followed;
  5. verify traffic keeps succeeding with no failed request; the store holds
     ten users, unique identities, a complete and unique user-ID ledger, and
     no duplicate event or delivery; every live session has exactly one
     primary provenance row, bound to its identity link and to the one
     compiled-material revision both replicas published.

### S610-2 Replicas share one configuration generation

- Given: two configurations that differ only in placement (state directory,
  listener addresses), and one that also differs in policy (a provider).
- When: their configuration digests are computed.
- Then: placement does not change the digest; policy does. A replica
  starting with the same policy does not move the shared generation, so the
  other replica's prepared native owners stay current.

## Abuse cases

| Category | Case | Applies |
| --- | --- | --- |
| Replay | S610-1 | yes: a handoff code raced to two replicas mints one session |
| Race / timing | S610-1 | yes: concurrent console writes on two replicas take effect once; a replica killed mid-traffic leaves no partial effect |
| Confused deputy | S610-1 | yes: a revoked administrator is refused by both replicas, not only the one that saw the revocation; a removed profile stops admitting its API key on every replica within the bound |
| Tampering | S610-1 | yes: CSRF and console MAC keys are shared through the store, so a token minted by one replica verifies on the other and nowhere else |
| Spoofed or duplicated headers | — | no: the forwarded headers are those of the existing gateway scenarios |
| Downgrade | — | no: schema checks are S600-5 |
| Enumeration | — | no: no new listing surface |
| Resource exhaustion | — | no: login-transaction and handoff-failure limits are counted in the store (shared); console read buckets, service-credential buckets and gateway concurrency are per replica (ADR-0020 decision 7) |

## Observability expectations

- Log: unchanged; a replica that loses the database fails closed (verify 503). A follower logs `followed a publication from another replica` when it installs one, and a warning when its listener disconnects (it keeps polling).
- Audit: one `admin.user_disable` and one `session.terminated` event per fenced write, written in the same transaction as the change.
- Metrics: none new.

## Test mapping

| Case | Test | File | Kind | Status |
| --- | --- | --- | --- | --- |
| S610-1 | `s610_1_two_replicas_share_logins_handoffs_fences_and_survive_a_killed_replica` | `tests/scenarios/s610_postgres_replicas.rs` | integration | passing |
| S610-2 | `s610_2_replicas_differing_only_in_placement_share_the_configuration_digest` | `src/app.rs` | unit | passing |

## Live verification

| Date | Hopae version | Gateway version | Provider | Environment label | Result | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| 2026-10-17 | 0.0.10 | — | mock OIDC | local-postgres-17-alpine | pass | `make qualify-postgres` step 3: two `hopae serve` processes behind TCP round-robin; 4 of 8 raced handoffs minted; one termination and one disable; revoked administrator refused on both; B killed with SIGKILL under verify load with no failed request. |
| 2026-10-17 | 0.0.10 | — | mock OIDC | local-postgres-17-alpine | pass | Publication following: profile and projection publications enforced by the other replica in under two seconds, by `NOTIFY` and, with the listeners terminated, by poll. With the follower disabled the case fails (mutation check). |

## Open questions

- Human receipts over the gRPC gateway are not driven over the network here (they need the gateway's mTLS listener); the native Human suite runs them on PostgreSQL in-process (`make test-postgres`).
- During a rolling configuration change, a replica still on the older policy no longer matches the shared generation: its new logins are unqualified for native Human receipts (fail closed) until it restarts on the new configuration.

## 한국어 요약

PostgreSQL 데이터베이스 하나에 실제 `hopae serve` 프로세스 두 개를 띄우고 TCP 라운드로빈 뒤에 둡니다. HTTP로 보면 두 복제본은 하나의 배포처럼 동작합니다. 로그인은 한 복제본에서 시작해 다른 복제본에서 끝낼 수 있습니다. 같은 핸드오프 코드를 두 복제본에 동시에 보내도 세션은 한 번만 발급됩니다. 두 콘솔로 동시에 보낸 관리자 쓰기는 한 번만 적용되고, 권한을 회수당한 관리자는 두 복제본 모두에서 거부됩니다. verify 트래픽 중에 한 복제본을 SIGKILL로 죽여도 남은 복제본이 요청을 받고, 저장소에는 중복된 효과가 남지 않습니다. CSRF 키와 콘솔 MAC 키는 저장소에 한 번 만들어 공유합니다. 한 복제본에서 게시한 프로필이나 프로젝션은 다른 복제본이 2초 안에 적용합니다. 다른 복제본의 `LISTEN` 연결이 끊겨 알림을 놓쳤어도 1초 주기 폴링으로 따라잡습니다. 네이티브 Human 소유자도 PostgreSQL에서 동작하므로 두 복제본의 모든 로그인이 기본 인증 출처를 한 번씩 기록합니다. 상태 디렉터리나 리스너 주소처럼 배치만 다른 복제본은 같은 구성 세대를 공유합니다.
