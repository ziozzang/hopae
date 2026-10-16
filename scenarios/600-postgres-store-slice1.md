# S600 — PostgreSQL store, slice 1: both backends keep the same store contract

<!-- scenario-status: implemented -->

- Area: scale-out
- Milestone: M2
- ADRs: 0002, 0020
- Threat model: TM-02, TM-10, TM-40
- Gateway contract: n/a

## Goal

The slice-1 store contract (users, identities and the user-ID ledger, provider
bootstrap, sessions and handles, the transactional outbox) behaves identically
on SQLite and PostgreSQL, including under concurrent writers, so that several
replicas on one PostgreSQL database keep the invariants a single SQLite writer
guaranteed; a PostgreSQL configuration is never served by an incomplete binary.

## Preconditions and fixtures

- SQLite: a temporary store per case. PostgreSQL: built with `--features
  postgres` and `HOPAE_TEST_POSTGRES_URL` set; `make test-postgres` starts an
  ephemeral local `postgres:17-alpine` with tmpfs data, runs the suite and
  removes the container; each case runs in a fresh schema dropped afterwards.
- Test clock at `1_700_000_000_000` ms, seeded RNG; sinks `["log"]`.

## Main flow

### S600-1 Users, identities, ledger and outbox agree

- Given: providers `mock` (enabled) and `off` (disabled).
- When: a user is created with an identity and an event; reads by id, email and identity; duplicate identity, username and primary email; a user on `off`; links and touches.
- Then: identical rows on both backends; the event has one `pending` delivery per sink; every duplicate is `Conflict`; `off` is `ProviderDisabled`; unknown user and identity are `Conflict`; `touch_identity` updates name and `last_seen_at`.

### S600-2 Sessions, handles and termination agree

- Given: a user and a session with a portal handle.
- When: the session and handle are read; a session whose login transaction does not exist is created; handles are touched forward and backward; a handle is revoked twice; an unknown handle is revoked; the session is terminated twice.
- Then: the joined handle view matches; the failed creation leaves nothing; touch is monotonic; one revocation moves `cred_gen` once; unknown handle is `Conflict`; termination revokes every handle (`session_terminated`), moves `cred_gen` once and records one event.

### S600-3 Concurrent writers keep the invariants

- Given: one handle, one identity subject, one live session.
- When: eight revocations, eight user creations with the same identity and eight terminations race.
- Then: one `cred_gen` move and one revocation event; exactly one user owns the identity; one termination event.

## Alternative flows

### S600-4 Outbox rules agree

- Given: the outbox.
- When: a diagnostic kind is appended as required; a required event with address, user-agent digest and attributes is appended and read back; the same event is appended again.
- Then: `Conflict`; an identical round trip (`to_json`) with one pending delivery; the duplicate is `Conflict`.

### S600-7 Login transactions agree (slice 2a)

- Given: the per-address cap 2 and a table bound of 3 rows.
- When: three transactions from one address; four from others with the bound; a transaction is bound twice, read by state, retried twice; eight consumers race.
- Then: the third is `OverCap` with nothing written; the oldest row is evicted; the second binding is `Conflict`; the state lookup returns the PKCE verifier; `use_retry` answers true then false; exactly one consumer wins.

### S600-8 Handoff redemption agrees (slice 2a)

- Given: a session and its codes.
- When: a code with a stale generation is minted; a valid code is redeemed, then replayed with and without the minted handle; a code is redeemed on the wrong host; an unknown code is redeemed; eight redemptions of one code race.
- Then: `Conflict`; `Minted` with a lookup-able handle; `AlreadyRedeemed` and `Rejected(code_consumed)`; `Rejected(code_host_mismatch)` with the code burned; `Rejected(code_unknown)`; failures counted per address; exactly one redemption mints, the others see `code_consumed`.

### S600-9 Administrator grants agree (slice 2b)

- Given: a user and an unknown user id.
- When: the unknown user is granted; the user is granted `viewer` through an address; the same grant is repeated; a grant through another address; a role change to `admin`; two revocations; listings of live and all grants; a re-grant.
- Then: `Conflict(unknown user)`; `(None, true)`; `(Some(viewer), false)` with no event; `Conflict(source_email_bound)`; `(Some(viewer), true)` with `previous_role = viewer` and the binding kept; the first revocation is true and the second false; no live grant but one audited row; the re-grant revives the row with `revoked_at` cleared.

### S600-10 Fenced console mutations agree (slice 2b)

- Given: an administrator session and handle on `auth.example.test`, a target user with two sessions.
- When: the target is disabled without a grant; with a grant but a policy that requires a provider claim or another console host; with an expired deadline; then within policy; repeated; an unknown user; the disabled user is granted; the target is enabled; a session is terminated twice; the actor's grant is revoked; the actor's own session ends.
- Then: `Conflict(actor_revoked)` with nothing written; again refused; `Unavailable(deadline)`; `(true, 2)` with both sessions ended as `user_disabled`, one session event each and the administrator event carrying `count = 2`, `authz_version` moved; `(false, 0)`; `Conflict(unknown user)`; `Conflict(user_disabled)`; `(true, 0)`; true then false with reason `admin`; the next mutation is `Conflict(actor_revoked)` and the session stays live; once re-granted it succeeds, and after the actor's session ends it is refused.

### S600-11 Replay ledger admits each nonce once (slice 2b)

- Given: scopes `delegation`, `other`, `cap` (capacity 2) and `race`.
- When: a nonce is admitted twice; the same nonce in another scope; malformed scopes and nonces; a full scope before and after expiry; sixteen concurrent admissions of one nonce.
- Then: true then false; true; `Conflict` and nothing stored; refused while full and while the entry is live (expiry is exclusive), admitted at expiry; exactly one admission wins.

### S600-5 PostgreSQL ledger, migrations and newer schema

- Given: a PostgreSQL store.
- When: a user row is removed by hand and its id reinserted; the ledger is deleted; four replicas migrate concurrently; a newer schema version is recorded.
- Then: the reinsert and the delete fail; the migrations apply once; the newer schema is refused (`SchemaTooNew`).

### S600-6 Configuration and serving

- Given: `store.backend = "postgres"` with `store.postgres`.
- When: the configuration is validated and a serve/store command starts.
- Then: invalid or inline settings are refused; without the feature the configuration is refused; with it, validation passes but serving and store commands refuse with a slice message and never fall back to SQLite.

## Abuse cases

| Category | Case | Applies |
| --- | --- | --- |
| Replay | S600-5, S600-11 | yes: a reserved user ID is never reused, and a nonce is admitted once, whichever replica inserts |
| Tampering | S600-6 | yes: credentials only by environment reference; unknown keys refused |
| Race / timing | S600-3, S600-10, S600-11 | yes: racing writers on two backends; the fence locks the actor's rows so a revocation orders before or after a mutation, never inside it |
| Resource exhaustion | — | no: pool bounds and statement timeouts are configuration (validated in S600-6); load is slice 4 |
| Confused deputy | S600-6, S600-10 | yes: no silent fallback from PostgreSQL to a local SQLite file; a revoked or out-of-policy administrator cannot mutate |
| Spoofed or duplicated headers | — | no: no HTTP surface in this slice |
| Downgrade | S600-5 | yes: a newer schema is refused, never down-migrated |
| Enumeration | — | no: no external surface |

## Observability expectations

- Log: none new in slice 1 (store errors carry SQLSTATE classes only, never values).
- Audit: required events and deliveries are written in the same transaction on both backends.
- Metrics: none new in slice 1.

## Test mapping

| Case | Test | File | Kind | Status |
| --- | --- | --- | --- | --- |
| S600-1 | `s600_1_users_identities_ledger_and_outbox_agree_on_both_backends` | `src/store/conformance.rs` | unit | passing |
| S600-2 | `s600_2_sessions_handles_and_termination_agree_on_both_backends` | `src/store/conformance.rs` | unit | passing |
| S600-3 | `s600_3_concurrent_writers_keep_invariants_on_both_backends` | `src/store/conformance.rs` | unit | passing |
| S600-4 | `s600_4_outbox_rules_agree_on_both_backends` | `src/store/conformance.rs` | unit | passing |
| S600-7 | `s600_7_login_transactions_agree_on_both_backends` | `src/store/conformance.rs` | unit | passing |
| S600-8 | `s600_8_handoff_redemption_agrees_on_both_backends` | `src/store/conformance.rs` | unit | passing |
| S600-9 | `s600_9_admin_grants_agree_on_both_backends` | `src/store/conformance.rs` | unit | passing |
| S600-10 | `s600_10_fenced_console_mutations_agree_on_both_backends` | `src/store/conformance.rs` | unit | passing |
| S600-11 | `s600_11_replay_ledger_admits_each_nonce_once_on_both_backends` | `src/store/conformance.rs` | unit | passing |
| S600-11 | `s600_11_store_backed_delegation_nonces_match_the_file_window_across_replicas` | `src/admin/delegation.rs` | unit | passing |
| S600-5 | `s600_5_postgres_ledger_migrations_and_newer_schema` | `src/store/conformance.rs` | unit | passing |
| S600-6 | `s600_6_postgres_store_configuration_is_validated` | `src/config/mod.rs` | unit | passing |
| S600-6 | `s600_6_serving_refuses_the_incomplete_postgres_backend` | `src/app.rs` | unit | passing |

## Live verification

| Date | Hopae version | Gateway version | Provider | Environment label | Result | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| 2026-10-17 | 0.0.10 | — | — | local-postgres-17-alpine | pass | Conformance against an ephemeral container (tmpfs data, removed afterwards). |

## Open questions

- Slice 2c–4 scope (ADR-0020). Hosted CI stays disabled; `make test-postgres` is the PostgreSQL run.

## 한국어 요약

슬라이스 1 저장소 계약(사용자·신원·사용자 ID 원장, 제공자 부트스트랩, 세션·핸들, 아웃박스)이 SQLite와 PostgreSQL에서 동시 쓰기 상황을 포함해 똑같이 동작하는지 확인합니다. 예약된 사용자 ID는 어느 복제본에서도 재사용되지 않고, 더 새로운 스키마는 거부되며, 미완성 PostgreSQL 설정은 서비스되지 않고 SQLite로 대체되지도 않습니다. 슬라이스 2b는 관리자 권한 부여·회수, 행 잠금(`FOR SHARE`)으로 재평가하는 관리자 펜스와 그 아래의 사용자 상태 변경·세션 종료, 복제본 간에 공유되는 재사용 방지 논스 원장을 두 저장소에서 같은 결과로 검증합니다.
