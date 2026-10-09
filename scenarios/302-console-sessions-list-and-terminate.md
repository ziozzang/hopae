# S302 — Console sessions: list live sessions, terminate one, terminate all of a user

<!-- scenario-status: approved -->

- Area: management
- Milestone: M4
- ADRs: 0016, 0004, 0007, 0008, 0009
- Threat model: TM-13, TM-23, TM-44, TM-45
- Gateway contract: Verify endpoint (denial and cookie clearing after termination), Cross-domain handoff (codes consumed by termination)

## Goal

An administrator sees every live session with its user, hosts, timing,
client address, user-agent prefix and level, listed in an immutable order so
that a walk neither skips nor repeats a session however active it is, ends
one session or every session of a user, the ended sessions are denied on
every host from the next request and their outstanding handoff codes die
with them, and each termination has its audit record in the same
transaction.

## Preconditions and fixtures

- Configuration `tests/fixtures/m4-admin.json`; administrator `u_a` (`Ha`), read-only administrator `u_v` (`Hv`).
- User `u_x` with three live sessions: `s_1` (provider `mock`, handles on the portal, `app.example.test` and `other.example.org`, bound to `203.0.113.9`, `user-agent: Mozilla/5.0 (X11; Linux) Alpha`), `s_2` (handle on `app.example.test` only, bound to `198.51.100.7`, created after migration `0003` so `bound_ua_prefix` is set), `s_3` (expired by its absolute lifetime but not yet swept); one terminated session `s_0`; `s_1` has an unconsumed handoff code `K1` for `other.example.org`.
- 40 other users with one live session each, created at distinct times; injected clock; `AdminClient` with the mutation requirements of 300-9.

## Main flow

### S302-1 Live sessions are listed by creation with their context

- Given: the sessions above.
- When: `GET /v1/sessions`, `GET /v1/sessions?user_id=u_x`, `GET /sessions`.
- Then: the unfiltered list has 42 items (`s_1`, `s_2` and the 40 others), ordered by `created_at DESC, session_id DESC`, never `s_0` (terminated) nor `s_3` (`absolute_expires_at` in the past); each item carries `session_id`, `user_id`, `primary_email`, `provider_id`, `aal`, `factors`, `hosts` (the non-revoked handles' hosts, `auth.example.test` included), `created_at`, `last_seen_at`, `absolute_expires_at`, `auth_time`, `bound_ip`, `ua_prefix` (`Mozilla/5.0 (X11; Linux) Alpha` for `s_1`, cut to 64 bytes; `null` for a session created before `0003`); the filter returns `s_1` and `s_2`; the page shows the same rows, `last_seen_at` as a column, and a terminate form per row for an administrator; the unfiltered query is one range scan of the partial index `sessions(created_at, session_id) WHERE terminated_at IS NULL`, the filtered one of `sessions(user_id, created_at, session_id) WHERE terminated_at IS NULL` (test-hooks `/explain`).

### S302-2 A session's detail shows its handles

- Given: `s_1`.
- When: `GET /v1/sessions/s_1` and `GET /sessions/s_1`.
- Then: the summary plus `handles` with one entry per host (`issued_aal`, `created_at`, `last_seen_at`, `absolute_expires_at`, `revoked_at`, `revoked_reason`), at most 100 of them, `terminated_at: null`; never a handle digest, a handoff code or the user agent beyond the prefix; `GET /v1/sessions/s_0` answers the terminated session with `terminated_reason`.

### S302-3 Terminating one session ends it on every host with its record

- Given: `s_1` live with `K1` outstanding; `cred_gen = 2`.
- When: `POST /v1/sessions/s_1/terminate` with `Ha`.
- Then: `200 {"changed":true}`; `s_1.terminated_at = now`, `terminated_reason = admin`, `cred_gen = 3`, every handle revoked (`reason=session_terminated`), `K1` consumed (`reason=session_terminated`); events in the same transaction: `session.terminated` (`reason=admin`, `session_id=s_1`, `user_id=u_x`) and `admin.session_terminate` (`session_id=s_1`, `user_id=u_x`, `attrs.actor=u_a`, `attrs.actor_session`); the next verify on `app.example.test` and on `other.example.org` with `s_1`'s handles is the unauthenticated `302` with the cookie cleared (006-3); redeeming `K1` is `code_consumed` (003); `s_2` is untouched; the crash point `after_admin_terminate_write` leaves `s_1` live and no event.

### S302-4 Terminating every session of a user

- Given: `u_x` with `s_1` and `s_2` live (`s_3` expired, `s_0` terminated).
- When: `POST /v1/users/u_x/sessions/terminate`.
- Then: `200 {"terminated":2}`; `s_1` and `s_2` terminated with `reason=admin`; `s_3` is left to the sweep (already unusable) and `s_0` untouched; events: two `session.terminated` and one `admin.sessions_terminate` (`user_id=u_x`, `attrs.count=2`) in one transaction; `u_x` stays `active` and can log in again at once.

### S302-5 An administrator may end their own session

- Given: `Ha` for `u_a`'s session `s_a`.
- When: `POST /v1/sessions/s_a/terminate` with `Ha`.
- Then: `200 {"changed":true}` and the events of 302-3 with actor and target both `u_a`; the next request with `Ha` is `403 login_required`; this is the API form of sign-out and is not `self_target`.

## Alternative flows

### S302-6 The HTML forms do the same

- Given: `Ha`; `s_2` live.
- When: `POST /sessions/s_2/terminate` with the page's `csrf` field and `Origin`; then `POST /users/u_x/sessions/terminate` likewise.
- Then: `303` back to the referring list, state and events exactly as 302-3 and 302-4.

## Abuse cases

| Category | Case | Applies |
| --- | --- | --- |
| Replay | S302-A1 | yes |
| Tampering | S302-A2 | yes |
| Race / timing | S302-A3, S302-A7 | yes |
| Resource exhaustion | S302-A4 | yes |
| Confused deputy | S302-A5 | yes |
| Spoofed or duplicated headers | — | no: covered by 300-A2 and 300-A6; every request here carries a valid administrator handle |
| Downgrade | — | no: no negotiation; transport is 300-A7 |
| Enumeration | S302-A6 | yes |

### S302-A1 Terminating an ended session changes nothing

- Given: `s_1` terminated by 302-3.
- When: `POST /v1/sessions/s_1/terminate` again; `POST /v1/sessions/s_0/terminate`; `POST /v1/sessions/s_3/terminate` (expired, unswept).
- Then: `200 {"changed":false}` for the first two with no event and no `cred_gen` change; the expired `s_3` is terminated now with `reason=admin` (`changed: true`) so that the list and the sweep agree, one event pair.

### S302-A2 Identifiers are validated before the store is touched

- Given: `Ha`.
- When: `POST /v1/sessions/u_x/terminate` (a user id), `/v1/sessions/s_%00/terminate`, `/v1/sessions/s_1/terminate?session_id=s_2` (a query parameter that must be ignored), a JSON body `{"session_id":"s_2"}`.
- Then: `400 invalid_id` for the first two before any store call; the third and fourth act on `s_1` from the path only; the body of a terminate request is ignored beyond its size limit.

### S302-A3 Termination racing a handoff redemption and a step-up

- Given: `s_1` with `K1` outstanding; the commit gate holds the `redeem` transaction of `K1` before commit while `POST /v1/sessions/s_1/terminate` commits; and the reverse order.
- When: the gate is released.
- Then: in the first order the redemption fails with `code_stale_generation` (the terminate bumped `cred_gen` and consumed the code) and no handle is minted; in the second the handle minted by the redemption is revoked by the termination that follows and its next verify is denied; in both exactly one `session.terminated` event exists for `s_1` (003-A11's ordering machinery, reused).

### S302-A4 Terminate-all is one bounded transaction and listings examine a bounded window

- Given: a user with 500 live sessions (bulk-created by the test hooks); 100,000 live sessions of other users.
- When: `POST /v1/users/<id>/sessions/terminate` while 16 verifies of those sessions run concurrently; then `GET /v1/sessions?user_id=<a user with no live session>`; then `GET /v1/sessions` paged with `limit=200`.
- Then: `{"terminated":500}` within the request budget; the store's single writer serializes the verifies, which either precede the termination (allow) or follow it (deny); the events table gains 500 `session.terminated` and one `admin.sessions_terminate`; the empty user filter answers at once with an empty page and no cursor (the partial index range is empty: zero candidates examined); each unfiltered page examines at most 10,000 candidates and returns 200 items with a cursor (`hopae_admin_rows_examined_total{list="sessions"}` grows by at most 10,000 per request), and a page deep in the walk costs the same VM work as the first (row-value seek on `(created_at, session_id)`). Under `admin.query_budget_ms = 100` with the store stalled 1 ms per statement, the terminate-all of the 500 sessions is interrupted between statements, rolled back (no session terminated, no event) and answered `503 store_unavailable`; the writer thread serves the next job at once.

### S302-A5 A read-only administrator cannot terminate; an administrator cannot be stopped by the target

- Given: `Hv`; `Ha`; `u_x`'s session `s_2`.
- When: `POST /v1/sessions/s_2/terminate` with `Hv`; then with `Ha` while `u_x` keeps verifying on `app.example.test` every 10 ms.
- Then: `403 role_insufficient` and `admin.denied` for the viewer, `s_2` live; with `Ha` the termination commits between two verifies and every verify after it is `302` with the cookie cleared; nothing `u_x` does (verify, logout entry, handoff) can keep the session alive past the commit.

### S302-A6 Session identifiers reveal nothing to the unauthorized

- Given: no handle; `Hn` (no grant).
- When: `GET /v1/sessions/s_1`, `POST /v1/sessions/s_1/terminate`.
- Then: `403 login_required` resp. `403 not_admin`, identical for existing and unknown ids; session ids are 128-bit random values and appear only to grant holders; the console never shows a handle value or digest.

### S302-A7 Activity during a walk neither skips nor repeats a session

- Given: sessions `A`, `B`, `C` created at `t=100`, `90`, `80` (and nothing else live); `limit=2`.
- When: page 1 (`A`, `B`); then `C` becomes very active (`last_seen_at` advanced to `110`) and a new session `D` is created at `t=120`; then page 2 with page 1's cursor; then page 3.
- Then: page 2 contains exactly `C` (creation order is immutable; the cursor `(90, B)` excludes nothing that existed), page 3 is empty without a cursor; `D` is on no page of this walk and on page 1 of a fresh walk; terminating `B` between page 1 and page 2 removes nothing but `B` itself, and `C` is still found; the displayed `last_seen_at` of `C` is `110` on page 2.

## Observability expectations

- Log: `admin.session_terminate`, `admin.sessions_terminate` with `attrs.actor`; `session.terminated` with `reason=admin`.
- Audit: the pairs above in one transaction (crash point tested); `admin.denied` for viewers.
- Metrics: `hopae_admin_mutations_total{kind="session_terminate"|"sessions_terminate"}`, `hopae_session_terminated_total{reason="admin"}`, `hopae_admin_rows_examined_total{list="sessions"}`.

## Test mapping

| Case | Test | File | Kind | Status |
| --- | --- | --- | --- | --- |
| S302-1 | `s302_1_live_sessions_listed_by_creation_with_context` | `tests/scenarios/s302_admin_sessions.rs` | integration | passing |
| S302-2 | `s302_2_session_detail_shows_handles` | `tests/scenarios/s302_admin_sessions.rs` | integration | passing |
| S302-3 | `s302_3_terminate_one_ends_it_everywhere_with_record` | `tests/scenarios/s302_admin_sessions.rs` | integration | passing |
| S302-4 | `s302_4_terminate_every_session_of_a_user` | `tests/scenarios/s302_admin_sessions.rs` | integration | passing |
| S302-5 | `s302_5_administrator_may_end_own_session` | `tests/scenarios/s302_admin_sessions.rs` | integration | passing |
| S302-6 | `s302_6_html_forms_do_the_same` | `tests/scenarios/s302_admin_sessions.rs` | integration | passing |
| S302-A1 | `s302_a1_terminating_ended_session_changes_nothing` | `tests/scenarios/s302_admin_sessions.rs` | integration | passing |
| S302-A2 | `s302_a2_identifiers_validated_before_store` | `tests/scenarios/s302_admin_sessions.rs` | integration | passing |
| S302-A3 | `s302_a3_termination_racing_redemption_and_step_up` | `tests/scenarios/s302_admin_sessions.rs` | integration | passing |
| S302-A4 | `s302_a4_terminate_all_bounded_and_listings_examine_bounded_window` | `tests/scenarios/s302_admin_sessions.rs` | integration | passing |
| S302-A5 | `s302_a5_viewer_cannot_terminate_target_cannot_resist` | `tests/scenarios/s302_admin_sessions.rs` | integration | passing |
| S302-A6 | `s302_a6_session_ids_reveal_nothing_to_unauthorized` | `tests/scenarios/s302_admin_sessions.rs` | integration | passing |
| S302-A7 | `s302_a7_activity_during_walk_neither_skips_nor_repeats` | `tests/scenarios/s302_admin_sessions.rs` | integration | passing |

## Live verification

| Date | Hopae version | Gateway version | Provider | Environment label | Result | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| — | — | — | — | — | — | Not yet run. |

## Open questions

- Should the list offer terminated sessions behind a filter (`include_terminated`) in M4-min, or is the user detail's "20 most recent terminated" preview enough?

## 한국어 요약

관리자는 살아 있는 세션을 사용자, 호스트, 시각, 클라이언트 주소, user-agent 접두사,
수준과 함께 불변인 생성 순서로 보고(마지막 활동은 열로 표시) 하나 또는 사용자의
전부를 종료합니다. 종료는 `cred_gen`을 올리고 모든 핸들을 취소하며 미소비 핸드오프
코드를 소비하므로 모든 호스트의 다음 요청이 거부되고, `session.terminated`와
`admin.session_terminate`가 같은 트랜잭션에 기록됩니다. 핵심 남용 사례는 순회 중의
활동이 세션을 건너뛰게 하지 못하는 것과, 종료와 핸드오프 교환의 경합에서 어느
순서든 세션이 되살아나지 않는 것입니다.
