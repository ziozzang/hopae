# S301 — Console users: list, search, detail, disable and enable

<!-- scenario-status: draft -->

- Area: management
- Milestone: M4
- ADRs: 0016, 0009, 0011
- Threat model: TM-24, TM-44, TM-45
- Gateway contract: Verify endpoint (`user_disabled` denial on every host); `n/a` otherwise

## Goal

An administrator finds a user, sees everything Hopae knows about them, and
disables or enables them; disabling ends every live session of the user in
the same transaction as the status change and the audit record, the user is
denied on every host from the next request, enabling never revives a session,
and no page or query lets a grant holder pull the directory without bounds.

## Preconditions and fixtures

- Configuration `tests/fixtures/m4-admin.json`; administrator `u_a` with console handle `Ha`; viewer `u_v` with `Hv` (scenario 300).
- 230 users created through the mock provider (subjects `sub-1` … `sub-230`, emails `user1@example.test` …), 12 of them with `display_name` containing `Kim`, 3 with `status = disabled`; user `u_x` (`sub-7`, `x@example.test`) has two identities (`mock` and a second provider `mock2`), four live sessions with handles on `app.example.test` and `other.example.org`, two terminated sessions and 80 events.
- Injected clock; `AdminClient` with the API requirements of 300-9 for mutations.

## Main flow

### S301-1 Users are listed newest first in bounded pages

- Given: the 230 users.
- When: `GET /v1/users`, then `GET /v1/users?cursor=<next_cursor>` until `next_cursor` is absent; then `GET /v1/users?limit=200`; then `GET /users` (the page).
- Then: the first page has 50 items ordered by `created_at DESC, user_id DESC`, each with `user_id`, `primary_email`, `email_verified`, `display_name`, `username`, `status`, `authz_version`, `created_at`, `last_login_at`, `live_sessions` and `role` (`null` for users without a grant); the pages together contain every user exactly once; `limit=200` yields 200 then 30; the HTML page shows the same first 50 rows and a "next" link carrying the cursor.

### S301-2 Search matches prefixes on the indexed columns and substrings on the display name

- Given: the users above.
- When: `GET /v1/users?q=user1` ; `?q=x@example.test` ; `?q=kim` ; `?q=Kim` ; `?q=user1&status=disabled` ; `?q=%40example` (an `@` prefix that matches no email start).
- Then: `user1` returns `user1@example.test` and `user10…user199` by email prefix (bounded by `limit`); the exact email returns one user; `kim` and `Kim` both return the 12 `display_name` matches (ASCII case-insensitive); the status filter narrows to the disabled ones among them; the `@example` query returns nothing (no infix match on email); every answer is one query with the users' unique indexes for the prefixes and a scan bounded by `limit` for the display name (EXPLAIN QUERY PLAN unit test).

### S301-3 The detail page shows identities, sessions, recent events and the grant

- Given: `u_x`.
- When: `GET /v1/users/u_x` and `GET /users/u_x`.
- Then: `user` with the row's fields; `identities` with both providers' `subject`, `email`, `email_verified`, `name`, `first_seen_at`, `last_seen_at` (never `raw_claims`); `sessions` with the four live sessions first (hosts of their handles, `bound_ip`, `ua_prefix`, `aal`, `last_seen_at`) and then the two terminated ones with `terminated_reason`; `grant: null`; the page additionally lists the user's 50 most recent events (newest first) with a link to `/events?user_id=u_x`, and the disable and terminate-all forms for an administrator.

### S301-4 Disabling a user ends every live session with the audit record in one transaction

- Given: `u_x` active with four live sessions, `authz_version = 3`.
- When: `POST /v1/users/u_x/disable` with `Ha` (and, separately, the HTML form of 300-9 a).
- Then: `200 {"changed":true,"sessions_terminated":4}`; `users.status = disabled`, `authz_version = 4`, `updated_at = now`; the four sessions have `terminated_at = now`, `terminated_reason = user_disabled`, `cred_gen` incremented, every handle revoked, every outstanding handoff code consumed; events in the same store transaction: one `admin.user_disable` (`user_id=u_x`, `attrs.actor=u_a`, `attrs.actor_session=<u_a's session>`, `attrs.count=4`) and four `session.terminated` (`reason=user_disabled`); the test-hooks crash point `after_admin_status_write` (before the commit) leaves nothing changed and no event; a verify on `app.example.test` with any of `u_x`'s former handles is `302` to the portal with the cookie cleared, and a new login by `u_x` is refused at the callback with `user_disabled` (`login.failed`).

### S301-5 Enabling a user restores sign-in and revives nothing

- Given: `u_x` disabled by 301-4.
- When: `POST /v1/users/u_x/enable`.
- Then: `200 {"changed":true}`; `status = active`, `authz_version = 5`; the four sessions stay terminated and their handles revoked; event `admin.user_enable` with the actor; `u_x` can log in again (002) and gets a new session.

### S301-6 Changing nothing writes nothing

- Given: `u_x` disabled.
- When: `POST /v1/users/u_x/disable` again; then after 301-5 `POST /v1/users/u_x/enable` again.
- Then: `200 {"changed":false,"sessions_terminated":0}` resp. `{"changed":false}`; `authz_version` unchanged; no event; the log notes the no-op at `info` with the request id.

## Alternative flows

### S301-7 A disabled administrator loses the console too

- Given: a second administrator `u_b` with console handle `Hb`.
- When: `u_a` disables `u_b`; then `GET /v1/me` with `Hb`.
- Then: `u_b`'s console session is terminated with the others (`reason=user_disabled`), the request is `403 login_required`; `u_b`'s grant row is untouched (re-enabling restores the console after a new login); `admin.user_disable` names `u_b` as target and `u_a` as actor.

## Abuse cases

| Category | Case | Applies |
| --- | --- | --- |
| Replay | S301-A1 | yes |
| Tampering | S301-A2 | yes |
| Race / timing | S301-A3 | yes |
| Resource exhaustion | S301-A4 | yes |
| Confused deputy | S301-A5 | yes |
| Spoofed or duplicated headers | — | no: the console's header and cookie cases are scenario 300 (300-A2, 300-A6); this scenario's requests all carry a valid administrator handle |
| Downgrade | — | no: no negotiation; transport is 300-A7 |
| Enumeration | S301-A6 | yes |

### S301-A1 A replayed disable is a no-op and a replayed token is refused

- Given: 301-4 completed; the HTML form token used in 300-9 a.
- When: the same JSON `POST` again; the same form `POST` with the already-used token within 10 minutes.
- Then: the JSON replay is `200 {"changed":false,...}` with no event (301-6); the form replay is accepted by the token check (tokens are not single-use) but is the same no-op; neither revives or terminates anything; the user's `authz_version` is unchanged.

### S301-A2 Malformed and unknown identifiers, and parameter abuse

- Given: `Ha`.
- When: `GET /v1/users/u_doesnotexist`, `GET /v1/users/u_x%27%20OR%201=1`, `GET /v1/users/` + 300 characters, `POST /v1/users/s_x/disable` (a session id), `GET /v1/users?limit=0`, `?limit=201`, `?limit=abc`, `?status=banned`, `?cursor=AAAA`, `?q=` + 129 characters, `?q=%00`.
- Then: unknown but well-formed id → `404 not_found`; every malformed id → `400 invalid_id` before any store call; `limit` out of range or non-numeric and `status` unknown → `400 invalid_filter`; a forged cursor → `400 invalid_cursor`; an over-long or non-printable `q` → `400 invalid_filter`; every query is parameterized (the `OR 1=1` form is an id lookup that finds nothing) and no error body echoes the input.

### S301-A3 Concurrent administrators and an in-flight login

- Given: `u_x` active; the commit gate holds the first `disable` transaction before commit while a second administrator sends the same request; separately, a login of `u_x` is at the callback (session not yet committed) when a disable commits.
- When: the gate is released; the callback commits.
- Then: exactly one `admin.user_disable` event and one `status` change; the second request answers `changed: false`; in the login race the session created after the disable is denied by its first verify (`user_disabled`, the engine terminates it, 004) and the callback itself refuses once the status is visible, so `u_x` never obtains a usable handle; `authz_version` moved exactly once per actual change.

### S301-A4 Listing and search are bounded

- Given: 100,000 users (bulk-inserted by the test hooks); `Ha`.
- When: `GET /v1/users?q=kim` (display-name substring over the whole table), `GET /v1/users?limit=200` paged 10 times, 16 concurrent searches.
- Then: every answer is at most 200 items and returns within the request budget (the display-name scan stops at `limit` matches or at the end of a bounded window and reports `next_cursor` for the remainder); memory stays under the harness limit; the concurrency cap (300-A4) refuses the 17th request rather than queuing it.

### S301-A5 An administrator cannot disable themselves, and a viewer cannot disable anyone

- Given: `Ha` for `u_a`; `Hv` for `u_v`.
- When: `POST /v1/users/u_a/disable` with `Ha`; `POST /v1/users/u_x/disable` with `Hv`; the HTML forms of both.
- Then: `403 self_target` with `admin.denied` (`reason=self_target`): the deployment cannot lock itself out through the console (recovery stays the CLI, 305); `403 role_insufficient` for the viewer with `admin.denied`; nothing changed in either case; another administrator may disable `u_a` (301-7).

### S301-A6 Directory enumeration needs a grant and stays bounded

- Given: `Hn` (no grant) and no handle.
- When: `GET /v1/users?q=a`, `GET /users?q=a`.
- Then: `403 not_admin` resp. `403 login_required`, no query executed (the store call counter is unchanged); with a grant the bounds of A4 apply; emails never appear in URLs the console emits (user pages are linked by `user_id`).

## Observability expectations

- Log: `admin.user_disable`, `admin.user_enable` with `attrs.actor`; no-ops at `info` with the request id.
- Audit: the events above and the per-session `session.terminated` (`reason=user_disabled`) in the same transaction as the status change; `admin.denied` with `reason=self_target` or `role_insufficient`.
- Metrics: `hopae_admin_mutations_total{kind="user_disable"|"user_enable"}`, `hopae_session_terminated_total{reason="user_disabled"}`.

## Test mapping

| Case | Test | File | Kind | Status |
| --- | --- | --- | --- | --- |
| S301-1 | `s301_1_users_listed_newest_first_in_pages` | `tests/scenarios/s301_admin_users.rs` | integration | planned |
| S301-2 | `s301_2_search_prefix_on_indexed_columns_substring_on_name` | `tests/scenarios/s301_admin_users.rs` | integration | planned |
| S301-3 | `s301_3_detail_shows_identities_sessions_events_grant` | `tests/scenarios/s301_admin_users.rs` | integration | planned |
| S301-4 | `s301_4_disable_ends_sessions_with_audit_in_one_transaction` | `tests/scenarios/s301_admin_users.rs` | integration | planned |
| S301-5 | `s301_5_enable_restores_sign_in_and_revives_nothing` | `tests/scenarios/s301_admin_users.rs` | integration | planned |
| S301-6 | `s301_6_changing_nothing_writes_nothing` | `tests/scenarios/s301_admin_users.rs` | integration | planned |
| S301-7 | `s301_7_disabled_administrator_loses_the_console` | `tests/scenarios/s301_admin_users.rs` | integration | planned |
| S301-A1 | `s301_a1_replayed_disable_is_noop_and_token_rules` | `tests/scenarios/s301_admin_users.rs` | integration | planned |
| S301-A2 | `s301_a2_malformed_ids_and_parameters_rejected` | `tests/scenarios/s301_admin_users.rs` | integration | planned |
| S301-A3 | `s301_a3_concurrent_admins_and_in_flight_login` | `tests/scenarios/s301_admin_users.rs` | integration | planned |
| S301-A4 | `s301_a4_listing_and_search_are_bounded` | `tests/scenarios/s301_admin_users.rs` | integration | planned |
| S301-A5 | `s301_a5_no_self_disable_and_viewer_cannot_disable` | `tests/scenarios/s301_admin_users.rs` | integration | planned |
| S301-A6 | `s301_a6_directory_enumeration_needs_grant_and_is_bounded` | `tests/scenarios/s301_admin_users.rs` | integration | planned |

## Live verification

| Date | Hopae version | Gateway version | Provider | Environment label | Result | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| — | — | — | — | — | — | Not yet run. |

## Open questions

- Should disabling also tombstone the user's identities for linking purposes (a disabled account's email stays reserved today, which is the safer default)?
- Is a display-name substring scan acceptable up to the sizes expected before M7, or should `0003` add a lower-cased search column now?

## 한국어 요약

관리자는 사용자를 목록·검색·상세 조회하고 비활성화·활성화합니다. 비활성화는 상태
변경, `authz_version` 증가, 살아 있는 모든 세션 종료, `admin.user_disable` 이벤트를
한 트랜잭션에서 수행하므로 그 사용자는 모든 호스트의 다음 요청에서 거부되고, 활성화는
어떤 세션도 되살리지 않습니다. 자기 자신은 비활성화할 수 없고 viewer는 아무것도
바꿀 수 없으며, 목록과 검색은 페이지 크기와 인덱스로 제한됩니다.
