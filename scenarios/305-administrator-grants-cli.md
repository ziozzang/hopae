# S305 — Administrator grants from the command line: bootstrap, revoke, list, recovery

<!-- scenario-status: draft -->

- Area: management, security
- Milestone: M4
- ADRs: 0016, 0009, 0011
- Threat model: TM-15, TM-43, TM-44
- Gateway contract: n/a

## Goal

An operator makes the first administrator, adds a viewer, revokes a
compromised administrator and lists the grants with `hopae admin`, against the
store and while the instance runs; every change takes effect on the next
console request without a restart and is recorded as an `admin.*` event in
the same transaction as the row; a grant can only name a user who exists,
resolved by id or by a verified primary email, and never a disabled one.

## Preconditions and fixtures

- Configuration `tests/fixtures/m4-admin.json`; a running instance (the CLI runs against the same `state_dir` in a second process); users `u_a` (`a@example.test`, verified), `u_v` (`v@example.test`), `u_d` (`status = disabled`), `u_u` (`u@example.test` with `email_verified = false`); user `u_a` holds a console handle `Ha` obtained before any grant (300-3 answered `not_admin`).
- Injected clock; the harness captures the CLI's stdout, stderr and exit status.

## Main flow

### S305-1 Bootstrap: the first grant by user id

- Given: an empty `admin_grants` table; `GET /v1/me` with `Ha` is `403 not_admin`.
- When: `hopae admin grant u_a --config <path>`.
- Then: exit `0`; stdout `granted admin to u_a (a@example.test)`; row `admin_grants(u_a, role=admin, granted_at=now, granted_by=cli, revoked_at=NULL)`; event `admin.grant` (`user_id=u_a`, `attrs.actor=cli`, `attrs.role=admin`, `attrs.previous_role` absent) with a delivery row for the log sink, in the same transaction as the row (crash point `after_grant_row` leaves neither); the very next `GET /v1/me` with the same `Ha` is `200` with `role: admin` and no restart happened.

### S305-2 Grant by email resolves the verified primary email

- Given: `u_v` with verified `v@example.test`; `u_u` unverified; `nobody@example.test` unknown.
- When: `hopae admin grant v@example.test --role viewer --note "ops rotation"`; `hopae admin grant nobody@example.test`; `hopae admin grant u@example.test`; `hopae admin grant V@Example.test --role viewer`.
- Then: the first exits `0` with `granted viewer to u_v (v@example.test)` and the row carries `note`; the second exits `2` with `no such user: sign in once first` and writes nothing; the third exits `2` with `email not verified` and writes nothing; the fourth normalizes the address (ADR-0011) and is the same user as the first (a no-op, 305-A1).

### S305-3 Revoke takes effect on the next request

- Given: `u_a` granted and using the console (`Ha`).
- When: `hopae admin revoke u_a`.
- Then: exit `0`, `revoked admin from u_a`; the row has `revoked_at = now`, `revoked_by = cli`; event `admin.revoke` (`attrs.actor=cli`, `attrs.previous_role=admin`); `GET /v1/me` with `Ha` is `403 not_admin` (300-5); the session itself is live and other hosts are unaffected.

### S305-4 List shows live grants only

- Given: 305-1 to 305-3 (`u_a` revoked, `u_v` viewer).
- When: `hopae admin list`; then `hopae admin list --all`.
- Then: the first prints one line, `u_v  v@example.test  viewer  <granted_at>  cli  ops rotation`, in a fixed column order with a header; `--all` also prints `u_a … admin … revoked <revoked_at> by cli`; no password, token or handle exists to print.

### S305-5 Re-grant clears the revocation and may change the role

- Given: `u_a` revoked.
- When: `hopae admin grant u_a --role viewer`; then `hopae admin grant u_a` (default role `admin`).
- Then: both exit `0`; after the first the row is `role=viewer, revoked_at=NULL, granted_at=now`; the event `admin.grant` has `attrs.previous_role=admin` (the role before, even though revoked); after the second `role=admin` with `previous_role=viewer`; the console reflects each on the next request.

### S305-6 The command works beside a running instance

- Given: the instance serving verifies at 50 per second while the writer is busy (test hook `store/stall 200ms` on the instance's writes).
- When: `hopae admin grant u_v --role admin`.
- Then: exit `0` within 5 s (SQLite busy handling with a bounded wait), the instance keeps serving, the instance lock in `state_dir` is not taken by the CLI (`run` is the only lock holder) and the next console request of `u_v` sees the new role.

## Alternative flows

### S305-7 Recovery when every administrator is gone

- Given: `u_a` disabled by another administrator who was then revoked; no live `admin` grant remains (`hopae admin list` prints nothing).
- When: `hopae admin grant u_a`; then `hopae admin grant u_b` for a user who has signed in but never been granted.
- Then: the first exits `2` with `user is disabled: enable first` (a disabled user never receives a grant, and enabling is a console action, not a command); the second exits `0`, `u_b` opens the console and enables `u_a` (301-5), after which `u_a` can be granted again; no step needed a password, a token or a restart.

## Abuse cases

| Category | Case | Applies |
| --- | --- | --- |
| Replay | S305-A1 | yes |
| Tampering | S305-A2 | yes |
| Race / timing | S305-A3 | yes |
| Resource exhaustion | — | no: an operator command against the local store; the console's limits are 300-A4 |
| Confused deputy | S305-A4 | yes |
| Spoofed or duplicated headers | — | no: no HTTP involved |
| Downgrade | — | no: no negotiation |
| Enumeration | S305-A5 | yes |

### S305-A1 Repeating a grant is a no-op

- Given: `u_v` granted `viewer`.
- When: `hopae admin grant u_v --role viewer` again; `hopae admin revoke u_v` twice.
- Then: the repeated grant exits `0` with `unchanged` and writes no row change and no event; the first revoke exits `0` and records `admin.revoke`; the second exits `0` with `already revoked` and writes nothing.

### S305-A2 Malformed identifiers and addresses

- Given: the store.
- When: `hopae admin grant 'u_a; DROP TABLE users'`, `hopae admin grant ''`, `hopae admin grant 'a@example.test@evil.example.org'`, `hopae admin grant u_a --role root`, `hopae admin grant u_a --note` + 2 KiB.
- Then: every one exits `2` with a message that names the argument and never echoes a database error; nothing is written; `--role` accepts exactly `admin` and `viewer`; `--note` is capped at 256 characters and sanitized like event attributes.

### S305-A3 Grant and revoke racing each other and the console

- Given: `u_a` granted; a console mutation by `u_a` in flight (300-A3's gate).
- When: `hopae admin revoke u_a` and `hopae admin grant u_a` run concurrently with the release of the gate.
- Then: SQLite's single writer serializes the three transactions; the final row state equals the last committed command and the event order equals the commit order; the console mutation succeeds only if its fenced re-check saw a live `admin` grant, else `403 actor_revoked`; no partial row and no event without its row.

### S305-A4 A grant by email cannot be hijacked through a provider's claim

- Given: `u_v` with `v@example.test` from `mock`; a new login through `mock2` asserting `email: v@example.test`, `email_verified: true` for subject `sub-99` (ADR-0011 `link_required`).
- When: the operator runs `hopae admin grant v@example.test` after that login attempt.
- Then: the grant resolves to `u_v` (the existing user with that primary email), never to a new user created for `sub-99` (none was created: the login stopped at the link notice, 002); `primary_email` is unique, so an address resolves to at most one user; a disabled user with that email is refused (`user is disabled`).

### S305-A5 The command reveals nothing beyond the operator's own store

- Given: the operator shell.
- When: `hopae admin grant unknown@example.test`, `hopae admin grant u_doesnotexist`.
- Then: both exit `2` with `no such user: sign in once first`; an unverified email keeps its distinct message (305-2) because the operator already holds the store, so enumeration against the local database is not a threat; the messages are operator-facing and never reach a network client.

## Observability expectations

- Log: the CLI prints one line per change to stdout and errors to stderr; the instance logs nothing for CLI grants (it sees the row on the next request).
- Audit: `admin.grant` / `admin.revoke` with `attrs.actor=cli`, `role`, `previous_role`, written with the row; delivered by the instance's log sink at-least-once (014).
- Metrics: none for the CLI; `hopae_admin_requests_total{role}` on the instance reflects the new role.

## Test mapping

| Case | Test | File | Kind | Status |
| --- | --- | --- | --- | --- |
| S305-1 | `s305_1_bootstrap_first_grant_by_user_id` | `tests/scenarios/s305_admin_grants.rs` | integration | planned |
| S305-2 | `s305_2_grant_by_email_resolves_verified_primary_email` | `tests/scenarios/s305_admin_grants.rs` | integration | planned |
| S305-3 | `s305_3_revoke_takes_effect_on_next_request` | `tests/scenarios/s305_admin_grants.rs` | integration | planned |
| S305-4 | `s305_4_list_shows_live_grants_only` | `tests/scenarios/s305_admin_grants.rs` | integration | planned |
| S305-5 | `s305_5_regrant_clears_revocation_and_changes_role` | `tests/scenarios/s305_admin_grants.rs` | integration | planned |
| S305-6 | `s305_6_command_works_beside_running_instance` | `tests/scenarios/s305_admin_grants.rs` | integration | planned |
| S305-7 | `s305_7_recovery_when_every_administrator_is_gone` | `tests/scenarios/s305_admin_grants.rs` | integration | planned |
| S305-A1 | `s305_a1_repeating_a_grant_is_a_noop` | `tests/scenarios/s305_admin_grants.rs` | integration | planned |
| S305-A2 | `s305_a2_malformed_identifiers_and_addresses` | `tests/scenarios/s305_admin_grants.rs` | integration | planned |
| S305-A3 | `s305_a3_grant_and_revoke_racing_each_other_and_console` | `tests/scenarios/s305_admin_grants.rs` | integration | planned |
| S305-A4 | `s305_a4_grant_by_email_cannot_be_hijacked_via_provider_claim` | `tests/scenarios/s305_admin_grants.rs` | integration | planned |
| S305-A5 | `s305_a5_command_reveals_nothing_beyond_own_store` | `tests/scenarios/s305_admin_grants.rs` | integration | planned |

## Live verification

| Date | Hopae version | Gateway version | Provider | Environment label | Result | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| — | — | — | — | — | — | Not yet run. |

## Open questions

- Should a grant require `email_authoritative` (not only `email_verified`) when resolved by email, so that a mailbox reassigned at a non-authoritative provider can never inherit a grant? (Also asked in ADR-0016 for the reviewer.)
- Should grants be seedable from the configuration file at start (an import like providers, with `managed_by`), for deployments that want administrators declared in version control?

## 한국어 요약

`hopae admin grant|revoke|list`는 실행 중인 인스턴스 옆에서 저장소에 직접 동작하며,
첫 관리자 부트스트랩, viewer 추가, 침해된 관리자 취소, 복구를 비밀번호나 토큰이나
재시작 없이 처리합니다. 부여는 존재하는 사용자(id 또는 검증된 기본 이메일)만 가리킬
수 있고 비활성화된 사용자는 거부되며, 모든 변경은 행과 같은 트랜잭션에서 `admin.grant`
/ `admin.revoke` 이벤트로 기록되고 다음 콘솔 요청부터 바로 적용됩니다. 핵심 남용
사례는 제공자의 이메일 주장으로 부여를 가로챌 수 없다는 것입니다.
