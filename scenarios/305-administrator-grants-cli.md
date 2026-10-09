# S305 — Administrator grants from the command line and the configuration file: bootstrap, revoke, list, import, recovery and the migration guard

<!-- scenario-status: approved -->

- Area: management, security
- Milestone: M4
- ADRs: 0016, 0009, 0010, 0011
- Threat model: TM-15, TM-43, TM-44, TM-46
- Gateway contract: n/a

## Goal

An operator makes the first administrator, adds a read-only administrator,
revokes a compromised administrator and lists the grants with `hopae admin`
or `admin.users[]`, against the store and while the instance runs; every
change takes effect on the next console request without a restart and is
recorded as an `admin.*` event in the same transaction as the row; a grant
binds once to a user who exists, resolved by id or by a verified primary
email with the resolved user shown and, for a non-authoritative address,
confirmed by id, never to a disabled one, and is never re-resolved; the file
can seed and revoke grants but never resurrect a runtime revocation, never
re-bind an email entry to a new mailbox holder, and never revoke an entry that
is still present; and the schema that holds grants is applied only on a
validated foundation, with no backup written before the validation.

## Preconditions and fixtures

- Configuration `tests/fixtures/m4-admin.json`; a running instance (the CLI runs against the same `state_dir` in a second process); users `u_a` (`a@example.test`, verified, **not** authoritative: the mock sends no `hd`), `u_h` (`h@example.test`, verified and authoritative through the mock's `hd_example_test` profile with `authoritative_domains: ["example.test"]` on the provider), `u_v` (`v@example.test`, verified, not authoritative), `u_d` (`status = disabled`), `u_u` (`u@example.test` with `email_verified = false`); user `u_a` holds a console handle `Ha` obtained before any grant (300-3 answered `not_admin`); `u_a` has two identities (`mock:sub-1`, `mock2:sub-77`).
- `tests/fixtures/m4-admin-seeded.json` for the seeding cases (catalogue row).
- Injected clock; the harness captures the CLI's stdout, stderr and exit status.

## Main flow

### S305-1 Bootstrap: the first grant by user id prints the resolved user

- Given: an empty `admin_grants` table; `GET /v1/me` with `Ha` is `403 not_admin`.
- When: `hopae admin grant u_a --config <path>`.
- Then: exit `0`; stdout shows the resolution block — `user_id u_a`, `display_name`, `created_at`, `last_login_at`, `primary_email a@example.test (verified, not authoritative)`, `identities mock:sub-1, mock2:sub-77` — and then `granted admin to u_a`; row `admin_grants(u_a, role=admin, managed_by=api, source_email=NULL, granted_at=now, granted_by=cli, revoked_at=NULL)`; event `admin.grant` (`user_id=u_a`, `attrs.actor=cli`, `attrs.role=admin`, `attrs.managed_by=api`, `attrs.previous_role` absent) with a delivery row for the log sink, in the same transaction as the row (crash point `after_grant_row` leaves neither); the very next `GET /v1/me` with the same `Ha` is `200` with `role: admin` and no restart happened.

### S305-2 Grant by email resolves once, shows the user and needs confirmation unless authoritative

- Given: `u_h` (authoritative), `u_v` (not authoritative), `u_u` unverified, `nobody@example.test` unknown.
- When: (a) `hopae admin grant h@example.test --role viewer --note "ops rotation"`; (b) `hopae admin grant v@example.test`; (c) `hopae admin grant v@example.test --confirm u_v`; (d) `hopae admin grant v@example.test --confirm u_h`; (e) `hopae admin grant nobody@example.test`; (f) `hopae admin grant u@example.test`; (g) `hopae admin grant V@Example.test --confirm u_v`.
- Then: (a) exits `0` after printing `u_h`'s block (`authoritative`) and `granted viewer to u_h`; the row has `source_email = h@example.test`, `note`; (b) prints `u_v`'s block, then `refusing: v@example.test is verified but not authoritative; re-run with --confirm u_v if this is the intended person`, exit `2`, nothing written; (c) exits `0`, `granted admin to u_v`, `source_email = v@example.test`; (d) exits `2` with `--confirm names u_h but the address resolves to u_v`, nothing written; (e) exits `2` with `no such user: sign in once first`; (f) exits `2` with `email not verified`; (g) normalizes the address (ADR-0011) to the same user as (c) and is a no-op (305-A1). In every case the row, when written, stores the `user_id` resolved at that moment; a later change of `users.primary_email` never moves the grant.

### S305-3 Revoke takes effect on the next request and leaves a tombstone

- Given: `u_a` granted and using the console (`Ha`).
- When: `hopae admin revoke u_a`.
- Then: exit `0`, `revoked admin from u_a`; the row has `revoked_at = now`, `revoked_by = cli`, `managed_by = api`; event `admin.revoke` (`attrs.actor=cli`, `attrs.previous_role=admin`); `GET /v1/me` with `Ha` is `403 not_admin` (300-5); the session itself is live and other hosts are unaffected.

### S305-4 List shows live grants, `--all` the tombstones too

- Given: 305-1 to 305-3 (`u_a` revoked, `u_h` viewer, `u_v` admin).
- When: `hopae admin list`; then `hopae admin list --all`.
- Then: the first prints two lines in a fixed column order with a header — `u_h  h@example.test  viewer  api  <granted_at>  cli  ops rotation` and `u_v  v@example.test  admin  api  <granted_at>  cli  -`; `--all` also prints `u_a … admin … revoked <revoked_at> by cli`; no password, token or handle exists to print.

### S305-5 Re-grant clears the revocation and may change the role

- Given: `u_a` revoked.
- When: `hopae admin grant u_a --role viewer`; then `hopae admin grant u_a` (default role `admin`).
- Then: both exit `0`; after the first the row is `role=viewer, revoked_at=NULL, granted_at=now`; the event `admin.grant` has `attrs.previous_role=admin` (the role before, even though revoked); after the second `role=admin` with `previous_role=viewer`; the console reflects each on the next request.

### S305-6 The command works beside a running instance

- Given: the instance serving verifies at 50 per second while the writer is busy (test hook `store/stall 200ms` on the instance's writes).
- When: `hopae admin grant u_v --role admin`.
- Then: exit `0` within 5 s (SQLite busy handling with a bounded wait), the instance keeps serving, the instance lock in `state_dir` is not taken by the CLI (`run` is the only lock holder) and the next console request of `u_v` sees the new role.

### S305-8 Grants are seeded from the file under the import rule, by their original keys

- Given: an empty `admin_grants` table; `m4-admin-seeded.json` (`u_a` by id as `admin`; `v@example.test` by email alone as `viewer`; `n@example.test` with `user_id = u_n` as `viewer`); `u_v`'s address is verified but not authoritative; `u_n`'s address matches `u_n`.
- When: (a) the instance starts (or `hopae admin import` runs); (b) `hopae admin import` runs again with no change; (c) the file is changed so that `u_a`'s entry says `role: viewer` and the `n@example.test` entry is removed, then `hopae admin import`; (d) `hopae admin revoke u_a` (runtime), then `hopae admin import` with the file still listing `u_a`; (e) `hopae admin import --force u_a`; (f) `hopae admin grant u_n --role admin` (runtime change of a file row), then the file restored with `u_n` as `viewer` and `hopae admin import`; (g) the `n@example.test` entry edited to `{user_id: "u_n", email: "x@example.test"}` (a mismatch) with the `u_n` file row live, then `hopae admin import`; (h) the mismatch corrected back, then `hopae admin import`.
- Then: (a) rows `u_a (admin, managed_by=file, source_email=NULL)` and `u_n (viewer, file, source_email=n@example.test)` are inserted with `admin.grant` events (`attrs.actor=file`, `attrs.managed_by=file`); the `v@example.test` entry is **skipped** with the preflight warning `admin.users[1]: email_not_authoritative; add user_id to apply` and `hopae --check` prints the same warning; (b) prints `unchanged` for both rows and writes no event; (c) `u_a` becomes `viewer` (`admin.grant` with `previous_role=admin`), `u_n` is revoked with `revoked_by=file` and `admin.revoke` (`actor=file`); (d) the runtime revocation turned `u_a` into an `api` tombstone, the import prints `skipped (revoked at run time): u_a` and the row stays revoked; (e) the file entry is reasserted: `u_a` live again as `viewer`, `managed_by=file`, event `admin.grant` with `attrs.actor=file`, `attrs.forced=true`; (f) the CLI grant flips `u_n` to `managed_by=api, role=admin`, and the subsequent import prints `skipped (changed at run time): u_n` and leaves it `admin`; (g) the entry is matched by its `user_id` to the live `u_n` file row, skipped with `user_email_mismatch`, and the row is **left untouched and not revoked** — a present entry is never treated as removed; (h) the corrected entry updates the row normally; the whole import is one write transaction in every run (crash point `after_import_match` leaves nothing changed).

### S305-9 Schema version 3 is applied only on a validated foundation, and nothing is backed up before that

- Given: three databases: a current version-2 database written by the released M1 schema, beside which an older `hopae.db.bak-v2` from a previous run already exists with known content; the pre-release version-2 fixture `tests/fixtures/pre_release_0002_m1_schema.sql` (missing `sessions.authz_version_at_auth` and the other version-2 structures), also beside a pre-existing `hopae.db.bak-v2` with known content; a version-3 database from which the test deletes the `admin_grants` table by hand.
- When: `hopae run` (the binary, not only the store's `open`) on each; then `hopae admin list` on the second.
- Then: the first validates the version-2 foundation, **then** writes the backup to a temporary name and renames it over the old `hopae.db.bak-v2` (the old content is gone only after the new copy exists), migrates to version 3, the post-migration structural check passes, and `admin_grants`, `sessions.bound_ua_prefix`, `sessions.auth_time_source`, `login_txns.reauth_max_age` and the new indexes exist; the second is refused with `DevelopmentSchema` **before** any backup and any migration: `schema_migrations` still records 2, no `admin_grants` table and no `events_session_at_id` index exist, the pre-existing `hopae.db.bak-v2` is byte-for-byte unchanged and no temporary file remains, exit `2`; `hopae admin list` on it is refused the same way with the same unchanged files; the third is refused at open with a structural error naming `admin_grants` (version stays 3), exit `2`; in no case does a refused database get its version changed or a backup touched.

## Alternative flows

### S305-7 Recovery when every administrator is gone

- Given: `u_a` disabled by another administrator who was then revoked; no live `admin` grant remains (`hopae admin list` prints nothing); `admin.users[]` is empty.
- When: `hopae admin grant u_a`; then `hopae admin grant u_b` for a user who has signed in but never been granted.
- Then: the first exits `2` with `user is disabled: enable first` (a disabled user never receives a grant, and enabling is a console action, not a command); the second exits `0`, `u_b` opens the console and enables `u_a` (301-5), after which `u_a` can be granted again; no step needed a password, a token or a restart.

## Abuse cases

| Category | Case | Applies |
| --- | --- | --- |
| Replay | S305-A1 | yes |
| Tampering | S305-A2 | yes |
| Race / timing | S305-A3 | yes |
| Resource exhaustion | — | no: an operator command against the local store; the console's limits are 300-A4 and the import's deadline is the plan's writer-job rule |
| Confused deputy | S305-A4, S305-A6 | yes |
| Spoofed or duplicated headers | — | no: no HTTP involved |
| Downgrade | — | no: no negotiation |
| Enumeration | S305-A5 | yes |

### S305-A1 Repeating a grant is a no-op

- Given: `u_v` granted `admin` (305-2 c).
- When: `hopae admin grant v@example.test --confirm u_v` again; `hopae admin revoke u_v` twice.
- Then: the repeated grant exits `0` with `unchanged` and writes no row change and no event; the first revoke exits `0` and records `admin.revoke`; the second exits `0` with `already revoked` and writes nothing.

### S305-A2 Malformed identifiers, addresses and entries

- Given: the store; a file with `admin.users: [{role: "admin"}]`, `[{user_id: "u_a", email: "h@example.test"}]`, `[{user_id: "u_a", role: "root"}]`, `[{email: "a@b@c"}]`.
- When: `hopae admin grant 'u_a; DROP TABLE users'`, `hopae admin grant ''`, `hopae admin grant 'a@example.test@evil.example.org'`, `hopae admin grant u_a --role root`, `hopae admin grant u_a --note` + 2 KiB, `hopae admin grant u_a --confirm 'u_a OR 1=1'`; then `hopae --check` and `hopae admin import` on each file.
- Then: every command exits `2` with a message that names the argument and never echoes a database error; nothing is written; `--role` accepts exactly `admin` and `viewer`; `--note` is capped at 256 characters and sanitized like event attributes; `--confirm` must be a well-formed user id; the files are rejected by `--check` (exit `2`): an entry without `user_id` and `email`, an entry whose `user_id` and `email` name different users (`user_email_mismatch`, a warning and a skip at import, an error under `--strict`), an unknown role, a malformed address.

### S305-A3 Grant and revoke racing each other and the console

- Given: `u_a` granted; a console mutation by `u_a` in flight (300-A3's gate).
- When: `hopae admin revoke u_a` and `hopae admin grant u_a` run concurrently with the release of the gate.
- Then: SQLite's single writer serializes the three transactions; the final row state equals the last committed command and the event order equals the commit order; the console mutation succeeds only if its fenced re-check saw a live `admin` grant, else `403 actor_revoked`; no partial row and no event without its row.

### S305-A4 A grant by email cannot be hijacked through a provider's claim, a stale account, a reassigned mailbox or a revoked binding — by the CLI or by the file

- Given: (a) `u_v` with `v@example.test` from `mock`; a new login through `mock2` asserting `email: v@example.test`, `email_verified: true` for subject `sub-99` (ADR-0011 `link_required`); (b) user `u_old` created through `mock2` with `primary_email = ops@example.test` (verified, not authoritative) whose provider account still asserts that address although the mailbox now belongs to a person who has not signed in; (c) `u_h` granted by `h@example.test` through the file entry `{email: "h@example.test", role: "admin"}` (its row has `source_email = h@example.test`), after which the provider's address for `u_h` changes and a new user `u_h2` later obtains `h@example.test` as a verified, **authoritative** primary email.
- When: (a) `hopae admin grant v@example.test --confirm u_v` after that login attempt; (b) `hopae admin grant ops@example.test` intending the new mailbox owner; (c) `hopae admin import` with the unchanged file, `hopae --check`, then `hopae admin import --force h@example.test`; (d) **the pass-3 state**: `hopae admin revoke u_h` (the row is now an `api` tombstone still carrying `source_email = h@example.test`), then `hopae admin import` with the unchanged email entry, then `hopae admin import --force h@example.test`, then `--force u_h`; (e) a second row bound through the same address: `hopae admin grant h@example.test --confirm u_h2` succeeds for the CLI (the operator confirmed), after which the file's email entry is imported again and `--force h@example.test` is tried.
- Then: (a) the grant resolves to `u_v` (the existing user with that primary email), never to a new user created for `sub-99` (none was created: the login stopped at the link notice, 002); (b) the command prints `u_old`'s block — its `mock2:sub-…` identity, `created_at` long before today, `not authoritative` — and refuses without `--confirm u_old`; the operator can see the account is not the new owner; with `--confirm u_old` the grant goes, as confirmed, to `u_old` (the residual of TM-46: the operator decided); (c) the import matches the entry **by `source_email` first**, to the row bound to `u_h`, and leaves it bound to `u_h` with its role updated; `u_h2` receives nothing although the address now resolves to it and is authoritative; `--check` warns `admin.users[0]: h@example.test now belongs to u_h2; the grant stays bound to u_h`; `--force h@example.test` selects the **same** existing row (the binding, not a fresh resolution) and reasserts the file's role on `u_h`; only an entry that names `u_h2` by `user_id` can grant `u_h2`; (d) the import matches the entry to the **tombstone** bound to `u_h` (bindings are matched in every state, `api` and revoked included), reports `skipped (revoked at run time): h@example.test → u_h`, creates **no** grant for `u_h2`, and the tombstone stays; `--force h@example.test` reasserts the file entry on `u_h` (live again, `managed_by=file`) — never on `u_h2`; `--force u_h` does the same by id; (e) with two rows bound through the address (`u_h` and `u_h2`), the email entry is an ambiguous binding: `skipped (email_binding_ambiguous): h@example.test → u_h, u_h2`, nothing changes, and `--force h@example.test` is refused with `ambiguous binding; use --force <user_id>` (exit `2`).

### S305-A5 The command reveals nothing beyond the operator's own store

- Given: the operator shell.
- When: `hopae admin grant unknown@example.test`, `hopae admin grant u_doesnotexist`.
- Then: both exit `2` with `no such user: sign in once first`; an unverified email keeps its distinct message (305-2) because the operator already holds the store, so enumeration against the local database is not a threat; the messages are operator-facing and never reach a network client.

### S305-A6 The file cannot resurrect a revoked grant, cannot revoke a present entry, and an ambiguous address grants nobody

- Given: `u_a` revoked at run time (`api` tombstone) while the file still lists `u_a`; two users `u_p` and `u_q` whose identities both carry `p@example.test` but only `u_p` holds it as `primary_email` (the unique index), and a third user `u_r` whose `primary_email` is `r@example.test` with `email_verified = 0`; file entries `{email: "p@example.test"}`, `{email: "r@example.test"}`, `{user_id: "u_s", email: "p@example.test"}` (a present but mismatched entry for a live file row `u_s`).
- When: the instance restarts (import at start) and `hopae --check` runs.
- Then: `u_a` stays revoked (`skipped (revoked at run time)`), no event; `p@example.test` resolves to the single `primary_email` holder `u_p` only if that address is authoritative — here it is not, so the entry is skipped with `email_not_authoritative` (an entry with `user_id: u_p` added would apply); `r@example.test` is skipped with `email_unverified`; the `u_s` entry is skipped with `user_email_mismatch` and the live `u_s` row is **neither updated nor revoked** (present entries are never treated as removed); all warnings appear in `--check` and at start; no grant was written for any of them; `--strict` turns the warnings into exit `2`.

## Observability expectations

- Log: the CLI prints one line per change to stdout and errors to stderr, plus the resolution block before every grant; the instance logs the import summary at start (`admin.users: inserted n, updated n, revoked n, skipped n`) and warns per skipped entry; the migration runner logs `schema foundation validated (vN)` before any backup and before applying, and the refusal reason otherwise.
- Audit: `admin.grant` / `admin.revoke` with `attrs.actor` ∈ {`cli`, `file`}, `role`, `previous_role`, `managed_by`, `forced`, written with the row; delivered by the instance's log sink at-least-once (014).
- Metrics: none for the CLI; `hopae_admin_requests_total{role}` on the instance reflects the new role; `hopae_admin_grants_imported_total{outcome}` at start.

## Test mapping

| Case | Test | File | Kind | Status |
| --- | --- | --- | --- | --- |
| S305-1 | `s305_1_bootstrap_first_grant_by_user_id_prints_resolution` | `tests/scenarios/s305_admin_grants.rs` | integration | passing |
| S305-2 | `s305_2_grant_by_email_resolves_once_and_needs_confirm_unless_authoritative` | `tests/scenarios/s305_admin_grants.rs` | integration | passing |
| S305-3 | `s305_3_revoke_takes_effect_and_leaves_tombstone` | `tests/scenarios/s305_admin_grants.rs` | integration | passing |
| S305-4 | `s305_4_list_shows_live_grants_and_all_shows_tombstones` | `tests/scenarios/s305_admin_grants.rs` | integration | passing |
| S305-5 | `s305_5_regrant_clears_revocation_and_changes_role` | `tests/scenarios/s305_admin_grants.rs` | integration | passing |
| S305-6 | `s305_6_command_works_beside_running_instance` | `tests/scenarios/s305_admin_grants.rs` | integration | passing |
| S305-7 | `s305_7_recovery_when_every_administrator_is_gone` | `tests/scenarios/s305_admin_grants.rs` | integration | passing |
| S305-8 | `s305_8_grants_seeded_from_file_by_original_keys` | `tests/scenarios/s305_admin_grants.rs` | integration | passing |
| S305-9 | `s305_9_schema_v3_only_on_validated_foundation_and_no_backup_before` | `tests/scenarios/s305_admin_grants.rs` | integration | passing |
| S305-A1 | `s305_a1_repeating_a_grant_is_a_noop` | `tests/scenarios/s305_admin_grants.rs` | integration | passing |
| S305-A2 | `s305_a2_malformed_identifiers_addresses_and_entries` | `tests/scenarios/s305_admin_grants.rs` | integration | passing |
| S305-A3 | `s305_a3_grant_and_revoke_racing_each_other_and_console` | `tests/scenarios/s305_admin_grants.rs` | integration | passing |
| S305-A4 | `s305_a4_email_grant_not_hijacked_by_claim_stale_account_reassigned_mailbox_or_revoked_binding` | `tests/scenarios/s305_admin_grants.rs` | integration | passing |
| S305-A5 | `s305_a5_command_reveals_nothing_beyond_own_store` | `tests/scenarios/s305_admin_grants.rs` | integration | passing |
| S305-A6 | `s305_a6_file_cannot_resurrect_revoke_present_or_grant_ambiguous` | `tests/scenarios/s305_admin_grants.rs` | integration | passing |

The migration-guard case (305-9) also keeps scenario 013-6's pre-release
rejection test green: `s013_6_*` asserts the refusal, 305-9 additionally
asserts the unchanged version, the absence of version-3 structures and the
untouched backup file.

## Live verification

| Date | Hopae version | Gateway version | Provider | Environment label | Result | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| — | — | — | — | — | — | Not yet run. |

## Open questions

- Should `--confirm` also be required for a grant by user id when the user's only identity is from a provider marked `trust_email` (the weakest evidence)? The user id is already an explicit choice; the ADR says no.

## 한국어 요약

`hopae admin grant|revoke|list|import`와 `admin.users[]`는 실행 중인 인스턴스
옆에서 저장소에 직접 동작하며, 첫 관리자 부트스트랩, 읽기 전용 관리자 추가, 침해된
관리자 취소, 복구를 비밀번호나 토큰이나 재시작 없이 처리합니다. 부여는 존재하는
사용자(id 또는 검증된 기본 이메일)에 한 번만 묶이고, 명령은 해결된 사용자의 신원과
주소의 권위 여부를 출력하며 권위적이지 않은 이메일에는 `--confirm <user_id>`를
요구합니다. 파일 심기는 항목의 원래 키로 기존 행을 먼저 대조하므로 이메일 항목은
새 메일함 보유자에게 다시 묶이지 않고, 존재하는(어긋난) 항목은 취소되지 않으며,
실행 중 취소는 되살아나지 않습니다. 마이그레이션 `0003`은 기존 버전의 구조가
검증된 뒤에만 적용되고, 거부는 버전도 백업 파일도 바꾸지 않습니다.
