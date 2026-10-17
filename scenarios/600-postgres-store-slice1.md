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

### S600-12 TOTP lifecycle and native step-up agree (slice 2c)

- Given: a user with a portal session on `auth.example.test`, a sealed enrollment envelope.
- When: an actor whose generation changed prepares an enrollment; the actor prepares, a second pending enrollment is attempted, the enrollment is activated at counter 10; counters 10 (same), 11 with a stale revision, 11, and eight racing 20s are consumed; the configuration generation is bumped and a step-up transaction is bound, rebound by the same browser and by another; the elevation runs with a changed generation, a replayed counter, then a fresh one, then again on the consumed challenge; the factor is removed with the old view and with the elevated one.
- Then: `factor authorization revoked`; one pending enrollment only; activation moves the revision to 2; only strictly greater counters on the current revision are accepted and exactly one racer wins; the rebinding is idempotent and the other browser is refused; `step-up configuration changed`, `factor proof unavailable`, then the session is at AAL 2 with a new generation, primary time kept and the old handle revoked; the replay is refused; the old view is revoked and the elevated one ends every session with `factor_revoked`.

### S600-13 External factor registry agrees (slice 2c)

- Given: a configuration generation and an empty registry.
- When: two authorities are published; a stale expected revision, a duplicate id and a binding change without a new revision are published; one authority is dropped; four publishers race on one expected revision.
- Then: revision 1; each refusal names its rule; the dropped authority becomes a tombstone and the revision moves once; exactly one racer wins.

### S600-14 Passkeys and recovery codes agree (slice 2c)

- Given: a user with a portal session.
- When: the WebAuthn user handle is set twice; a passkey is registered, the ceremony replayed, a second passkey registered without a recent second factor; the portal is verified with the passkey and again with an unmoved counter; the only passkey is removed and renamed; an application step-up with the passkey runs and is replayed; ten recovery codes are minted, one is used twice; a clone signal arrives; the factors are reset.
- Then: the first handle stays; registration consumes the ceremony once, the replay is `ceremony unavailable` and the second registration `recent verification required`; verification raises the session and rotates its credentials, the stale counter is `counter stale`; `last second factor`, rename succeeds; the step-up consumes ceremony, transaction and counter together and the replay is refused; the used code is gone, `recovery_required_at` is set and the second use is refused; the clone signal revokes the credential and ends the sessions it elevated (`counter_regression`); the reset reports what it revoked and ends the remaining session.

### S600-15 Passwordless sign-in agrees (slice 2c)

- Given: a user with a registered passkey and a login transaction from one address.
- When: a sign-in ceremony is started, read, failed; thirty more are started and one beyond; a verified sign-in creates the passkey session and a second sign-in reuses the ceremony; passwordless sign-in is turned off.
- Then: the failed ceremony is gone; the thirty-first is `passkey sign-in busy`; the session is at AAL 2 on `hopae.passkey` and the reuse is `ceremony unavailable`; exactly the passkey session ends.

### S600-16 External factor step-up agrees (slice 2c)

- Given: a published external authority and a step-up transaction of the portal session.
- When: the challenge is bound with another authority, then with the published one; a proof for another session, a valid proof and the same proof again are presented; the authority's binding is rotated.
- Then: `external factor disabled or changed`; the binding succeeds; `external proof context unavailable`; the session is at AAL 2 with an external factor; the replay is refused; the elevated session ends with `factor_revoked`.

### S600-17 Event relay agrees (slice 3)

- Given: six required events, one diagnostic event, sink `log`.
- When: a required kind is appended as diagnostic; an append runs past its deadline; two relays claim four each at once; the leased rows are claimed again; one delivery is acknowledged, one retried, one failed for good; the lease expires; history and status are read; a prune runs with a count bound of 5 and a backlog cap of 2, then after the retention.
- Then: `Conflict`; `Unavailable(deadline)` and nothing written; every delivery is handed out exactly once; nothing is due while leased; only the retried one comes back (attempt 2), then the four expired leases; history is oldest first and status counts 4 pending and 1 failed; the prune deletes the two oldest events, dead-letters the backlog overflow with one `sink.backlog_overflow` event and records `last_prune_at`; the age pass empties the outbox.

### S600-18 Console listings agree (slice 3)

- Given: five users created a second apart, three sessions (one ended), three `login.failed` events of one user.
- When: users are listed two per page with cursors and searched in another case; live sessions are listed for all and per user; a user's detail and a session summary are read; events are listed by user and kind two per page; a listing runs past its deadline.
- Then: newest first across pages, the window size reported, the cursor ending the listing; the search ignores ASCII case; only live sessions with their hosts and owner address; the detail counts identities and live and ended sessions; the summary carries the handles; events newest first with a final page; `Unavailable(deadline)`.

### S600-19 Local groups and projection agree (slice 3)

- Given: an administrator and a person.
- When: a group is created twice with one key; the person is added, added again and added on a stale revision; the group is renamed; groups are searched, members and a person's groups read; the projection journal and snapshot are read; the group is deleted without and with force; the administrator's grant is revoked.
- Then: `key_in_use`; revisions move 1→2→3 with `already_member` and `Stale(2)`; the person's `groups` mirror and `authz_version` follow; the search ignores case; the journal is gapless and ordered, a revision beyond the head is lost; the snapshot lists the person; `group_not_empty`, then a tombstone with the mirror cleared; `actor_revoked`.

### S600-20 Provider groups and journal order agree (slice 3)

- Given: eight people and provider `mock`.
- When: a sync asserts two groups, then four (over the bound), then one; maintenance runs with a zero grace; seven syncs race; the periodic-sync cursor is taken twice and results recorded.
- Then: two groups created and joined; the over-bound assertion changes nothing; the dropped membership is pending, then removed; the racing syncs leave a gapless journal whose every revision is listed; the cursor returns all eight people once, then nothing until the interval.

### S600-21 Subject directory feeds agree (slice 3)

- Given: an administrator; eight people created at once.
- When: the ledger and directory rows are read; three people are disabled and a group created; the lifecycle feed is read without and with group changes, resumed, and read from a forged and a negative position; the explain reads run.
- Then: the ledger lists every person in increasing position with the head last; the feed reports the three disables in order (and the group creation when asked) and its next position is the head; resuming yields nothing; both bad positions are lost; the live handle and TOTP state are reported; a batch over 200 is refused.

### S600-22 Human realm and subjects agree (slice 4)

- Given: a store with one user.
- When: the realm is read twice; Human subjects are asked for the user, an unknown ID and a malformed one; more than 200 are asked.
- Then: 64 lowercase hex, stable; one subject, the canonical derivation over the store realm; `Conflict`.

### S600-23 PostgreSQL owner triggers match SQLite (slice 4)

- Given: a PostgreSQL store.
- When: the realm is seeded twice, updated and deleted; a provider row's timestamp, then its `enabled`, then its id change; material owners are inserted at 2 and at 1, moved by two, moved by one, deleted.
- Then: the first realm stays and both changes are refused; the owner revision moves only for the material change and the id change is refused; only the start at one and the move by one succeed and the delete is refused.

### S600-24 A SQLite store migrates to an empty PostgreSQL store (slice 4)

- Given: a SQLite store with users, a disabled user, sessions, a passkey, an active TOTP enrollment, a group with a member, a login transaction, a handoff code, a live replay nonce and outbox events; an empty PostgreSQL store.
- When: the store is migrated; the migration runs again; a SQLite table the migration does not know gets a row and the migration runs into another empty store.
- Then: the SQLite file is byte for byte unchanged; users, passkeys, TOTP, the configuration generation, groups and the mirror, the realm and the lifecycle feed read the same on PostgreSQL; the migrated nonce is still refused; one `store.migrated` event carries the report digest and has its delivery row; the second run is refused (not empty); the unknown table is refused by name and nothing is written.

### S600-25 The Directory trait agrees (slice 5)

- Given: providers `mock` and `two` in the file; users with grants.
- When: providers are imported, a file row changed and re-imported, an import forces a provider the file does not list; users are read under an expired deadline; grant targets are resolved by address and by an unknown ID; `admin.users[]` is imported (by ID, an unknown ID, by address), re-imported, imported after a runtime grant with a file row dropped, and forced.
- Then: inserted, then updated, the forced unknown refused; `Unavailable(deadline)`; the user with every identity, `None`; one insert and `no_such_user`, then unchanged, then `changed_at_run_time` with the dropped file row revoked (with its `admin.revoke` event), then the forced row rewritten as file-managed.

### S600-26 The Sessions trait agrees (slice 5)

- Given: a user with portal sessions and handles.
- When: a handle is minted replacing another, and with a handle of another session; a snapshot is refreshed forward then backward; switch, logout and login transactions are bound, retry-bound, consumed for a disabled then a live provider; a logout ticket ends its session twice; a session is reauthenticated with the wrong provider, then right, then again on the spent transaction; an administrator ends a user's sessions twice; transactions are evicted and the store swept.
- Then: the old handle revoked as `replaced` and the new one capped at the session level, the foreign one refused; only the forward refresh applies; each binding once, the wrong purpose refused, the retry bind once; `ProviderDisabled`, then consumed once; the ticket and its session end once; `provider_mismatch`, then one handle event, `provider_claim` and a new factor, then `Conflict`; 2 then 0; the oldest rows evicted and expired rows swept.

### S600-27 The application store handle dispatches (slice 5)

- Given: the application's `Store` handle over either backend.
- When: providers are imported, a user and a session are read, an event is appended and counted through the handle and through the trait objects it hands out; an operation not available on PostgreSQL (the delivery dump) is asked for.
- Then: every answer comes from the backend it wraps; on PostgreSQL the unported operation is refused by name (no fallback).

### S600-28 The native meta owners agree (slice 5)

- Given: the store's meta handle on either backend.
- When: the receipt key history is published, published again on a stale revision, read under a higher minimum, and published with a guard that refuses after the writes; the receipt key owner reconciles an unchanged and a changed set; a profile is published, republished on a stale revision and published with a late refusing guard; a projection tombstone is published; six publishers race on one revision; eight consumers race to admit one receipt (PostgreSQL, next to the replay code).
- Then: revision 1, the stale one refused, the minimum refused, the late refusal rolls back; 1 then 2 with a live verifier; revision 1, `Conflict`, `Denied` with no audit row; revision 1 disabled; exactly one publisher and exactly one consumer win.

### S600-29 Provider and compiled-material owners agree (slice 5)

- Given: providers `mock` and `two` imported through the application handle.
- When: providers are prepared for a generation that is not in force, then for the current one; the preparation is required whole and per provider; compiled material fingerprints are published twice, then with another fingerprint for `mock`; `mock`'s configuration changes; the generation moves; another store is asked to accept the preparation.
- Then: `Conflict`; both rows in order; both requirements pass; both fingerprints recorded and the republish stable; the changed fingerprint is `mock`'s next revision and `two` keeps its own (an upsert of an existing owner row is accepted on PostgreSQL too); the stale preparation is refused whole, for `mock` and for a material publication while `two` still passes; refused after the new generation; refused by the foreign store.

### S600-5 PostgreSQL ledger, migrations and newer schema

- Given: a PostgreSQL store.
- When: a user row is removed by hand and its id reinserted; the ledger is deleted; four replicas migrate concurrently; a newer schema version is recorded.
- Then: the reinsert and the delete fail; the migrations apply once; the newer schema is refused (`SchemaTooNew`).

### S600-6 Configuration and serving

- Given: `store.backend = "postgres"` with `store.postgres`.
- When: the configuration is validated and a serve/store command starts.
- Then: invalid or inline settings are refused; without the feature the configuration is refused; with it, `serve` and the store commands run on PostgreSQL (slice 5; two serving replicas are S610), the native Human owners included; nothing falls back to SQLite.

### S600-30 Published snapshots follow other replicas

- Given: two profile owners and two projection owners on one store, standing for two replicas.
- When: one publishes; the other refreshes; one publishes a profile revision the other cannot compile; a PostgreSQL listener is dropped.
- Then: the follower installs the newer durable revision and never an older one, and its own publication on the old revision conflicts until it followed; a revision it cannot compile installs as unavailable (verify answers unavailable) and a failed publication leaves it so; projection plans that exceed the follower's declared capabilities are not installed; on PostgreSQL a committed publication wakes the listener (`NOTIFY` on commit) and a dropped listener reconnects and wakes once more so the follower catches up.

### S600-31 Native Human snapshot and primary owner agree

- Given: a native OIDC provider with published compiled material, on each backend.
- When: a user logs in, a native witness is captured and checked; a second session is captured; the provider row moves (disabled and enabled); the registry is prepared and published again and a fresh login is captured; the user is disabled.
- Then: the login records exactly one primary provenance row in its own transaction; the capture is current; the provider move retires both captures; after re-preparation a new login is qualified again; the disabled user retires it.

### S600-32 Native factor provenance agrees

- Given: a native session elevated by TOTP, and one elevated by a passkey, on each backend.
- When: the TOTP counter moves, then the enrollment is revoked; the passkey's counter and revision move, then it is revoked.
- Then: a counter move keeps the capture current (another use of the same factor); a revocation retires it.

### S600-33 The native Human ledger checks inside its own transaction

- Given: a captured Human check prepared for the ledger, on each backend.
- When: another store's ledger runs the check; the same store's ledger runs it, disables the user inside the same transaction and runs it again; the transaction rolls back.
- Then: the other store is refused; the first check passes, the second is refused; the user is still active afterwards.

## Abuse cases

| Category | Case | Applies |
| --- | --- | --- |
| Replay | S600-5, S600-11, S600-12, S600-14, S600-16 | yes: a reserved user ID, a nonce, an OTP counter, a ceremony, a recovery code and an external proof are each accepted once, whichever replica writes |
| Tampering | S600-6 | yes: credentials only by environment reference; unknown keys refused |
| Race / timing | S600-3, S600-10 to S600-13, S600-17, S600-20, S600-21 | yes: racing writers on two backends; the fence locks the actor's rows so a revocation orders before or after a mutation, never inside it |
| Resource exhaustion | S600-17, S600-18 | yes: bounded backlog per sink, bounded listing windows and deadlines; load is slice 4 |
| Confused deputy | S600-6, S600-10 | yes: no silent fallback from PostgreSQL to a local SQLite file; a revoked or out-of-policy administrator cannot mutate |
| Spoofed or duplicated headers | — | no: no HTTP surface in this slice |
| Downgrade | S600-5 | yes: a newer schema is refused, never down-migrated |
| Enumeration | S600-21 | yes: directory batches are bounded (200) |

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
| S600-12 | `s600_12_totp_lifecycle_and_native_stepup_agree_on_both_backends` | `src/store/conformance.rs` | unit | passing |
| S600-13 | `s600_13_external_factor_registry_agrees_on_both_backends` | `src/store/conformance.rs` | unit | passing |
| S600-14 | `s600_14_passkeys_and_recovery_codes_agree_on_both_backends` | `src/store/conformance.rs` | unit | passing |
| S600-15 | `s600_15_passwordless_sign_in_agrees_on_both_backends` | `src/store/conformance.rs` | unit | passing |
| S600-16 | `s600_16_external_factor_stepup_agrees_on_both_backends` | `src/store/conformance.rs` | unit | passing |
| S600-17 | `s600_17_event_relay_agrees_on_both_backends` | `src/store/conformance.rs` | unit | passing |
| S600-18 | `s600_18_console_listings_agree_on_both_backends` | `src/store/conformance.rs` | unit | passing |
| S600-19 | `s600_19_local_groups_and_projection_agree_on_both_backends` | `src/store/conformance.rs` | unit | passing |
| S600-20 | `s600_20_provider_groups_and_journal_order_agree_on_both_backends` | `src/store/conformance.rs` | unit | passing |
| S600-21 | `s600_21_subject_directory_feeds_agree_on_both_backends` | `src/store/conformance.rs` | unit | passing |
| S600-22 | `s600_22_human_realm_and_subjects_agree_on_both_backends` | `src/store/conformance.rs` | unit | passing |
| S600-23 | `s600_23_postgres_owner_triggers_match_sqlite` | `src/store/conformance.rs` | unit | passing |
| S600-24 | `s600_24_sqlite_store_migrates_to_an_empty_postgres_store` | `src/store/conformance.rs` | unit | passing |
| S600-25 | `s600_25_directory_trait_agrees_on_both_backends` | `src/store/conformance.rs` | unit | passing |
| S600-26 | `s600_26_sessions_trait_agrees_on_both_backends` | `src/store/conformance.rs` | unit | passing |
| S600-27 | `s600_27_the_application_store_handle_dispatches_on_both_backends` | `src/store/conformance.rs` | unit | passing |
| S600-28 | `s600_28_native_meta_owners_agree_on_both_backends` | `src/store/conformance.rs` | unit | passing |
| S600-28 | `s600_28_postgres_connections_admit_exactly_one_concurrent_consumer` | `src/auth_gateway/receipt_replay.rs` | unit | passing |
| S600-29 | `s600_29_provider_and_material_owners_agree_on_both_backends` | `src/store/conformance.rs` | unit | passing |
| S600-30 | `s600_30_published_snapshots_follow_other_replicas_on_both_backends` | `src/store/conformance.rs` | unit | passing |
| S600-31 | `s600_31_native_human_snapshot_and_primary_owner_agree_on_both_backends` | `src/verify/human_tests.rs` | unit | passing |
| S600-32 | `s600_32_native_human_factor_provenance_agrees_on_both_backends` | `src/verify/human_tests.rs` | unit | passing |
| S600-33 | `s600_33_native_human_ledger_checks_inside_its_own_transaction_on_both_backends` | `src/verify/human_tests.rs` | unit | passing |
| S600-5 | `s600_5_postgres_ledger_migrations_and_newer_schema` | `src/store/conformance.rs` | unit | passing |
| S600-6 | `s600_6_postgres_store_configuration_is_validated` | `src/config/mod.rs` | unit | passing |
| S600-6 | `s600_6_serving_accepts_postgres_only_in_a_postgres_build` | `src/app.rs` | unit | passing |

## Live verification

| Date | Hopae version | Gateway version | Provider | Environment label | Result | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| 2026-10-17 | 0.0.10 | — | — | local-postgres-17-alpine | pass | Conformance against an ephemeral container (tmpfs data, removed afterwards). |
| 2026-10-17 | 0.0.10 | — | — | local-postgres-17-alpine | pass | `make qualify-postgres`: CLI migration (second run refused, SQLite file unchanged); replicas a and b on 1,500 shared transactions and codes, 400 shared sign-ups, 1,500 nonces, 80 sessions and 40 users under fenced administrator writes and 2,000 relay deliveries; b killed with SIGKILL after 1,991 logged effects and replaced by c; every check passed (one transaction committed by b before its log line was lost was still consumed exactly once). |

## Open questions

- Slice 5 (ADR-0020): `serve` runs on PostgreSQL and the HTTP two-replica qualification is S610. The native Human owners run on PostgreSQL too (S600-31 to S600-33, and the whole native Human suite with `HOPAE_TEST_HUMAN_BACKEND=postgres` in `make test-postgres`). Hosted CI stays disabled; `make test-postgres` and `make qualify-postgres` are the PostgreSQL runs.

## 한국어 요약

슬라이스 1 저장소 계약(사용자·신원·사용자 ID 원장, 제공자 부트스트랩, 세션·핸들, 아웃박스)이 SQLite와 PostgreSQL에서 동시 쓰기 상황을 포함해 똑같이 동작하는지 확인합니다. 예약된 사용자 ID는 어느 복제본에서도 재사용되지 않고, 더 새로운 스키마는 거부되며, 미완성 PostgreSQL 설정은 서비스되지 않고 SQLite로 대체되지도 않습니다. 슬라이스 2b는 관리자 권한 부여·회수, 행 잠금(`FOR SHARE`)으로 재평가하는 관리자 펜스와 그 아래의 사용자 상태 변경·세션 종료, 복제본 간에 공유되는 재사용 방지 논스 원장을 두 저장소에서 같은 결과로 검증합니다. 슬라이스 2c는 TOTP 등록·카운터·단계 상승, 외부 인증 요소 레지스트리와 일회용 증명, 패스키 등록·검증·제거, 복구 코드, 비밀번호 없는 로그인, 요소 초기화를 같은 방식으로 검증합니다. 슬라이스 3은 이벤트 전달(동시 claim, 임대, 재시도, 정리), 콘솔 목록, 그룹과 프로젝션 저널, 주체 디렉터리 피드를 검증하며, 저널과 피드의 위치가 커밋 순서대로 보이는지(소비자가 건너뛰지 않는지)를 확인합니다. 슬라이스 4는 realm과 Human 소유자 기반, SQLite에서 빈 PostgreSQL로의 단방향 이전(행 수·다이제스트 비교, 감사 이벤트, SQLite 파일 보존)을 검증하고, `make qualify-postgres`로 두 프로세스 중 하나를 작업 중에 강제 종료해도 효과가 중복되지 않음을 확인합니다.
