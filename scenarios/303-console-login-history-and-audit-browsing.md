# S303 — Console login history and audit browsing

<!-- scenario-status: draft -->

- Area: management
- Milestone: M4
- ADRs: 0016, 0009
- Threat model: TM-12, TM-28, TM-44, TM-45
- Gateway contract: n/a

## Goal

A grant holder browses the `events` table newest first with filters on kind,
outcome, user, session, client address and time range, pages through it with
cursors that neither skip nor repeat rows while new events arrive, sees
administrative actions with their actor, and every page is one bounded,
indexed query that never exposes a credential.

## Preconditions and fixtures

- Configuration `tests/fixtures/m4-admin.json`; administrator `u_a` (`Ha`), viewer `u_v` (`Hv`).
- 5,000 events generated through real flows and the test hooks over 48 simulated hours: `login.started`, `login.succeeded`, `login.failed` (reasons `invalid_state`, `provider_unavailable`), `session.created`, `session.handoff`, `handoff.rejected`, `session.terminated`, `verify.denied` (sampled), `csrf.rejected`, plus the `admin.*` events of scenarios 301, 302 and 305; 300 of them belong to `u_x`, 120 carry `client_ip = 203.0.113.9`, 40 belong to session `s_1`.
- Injected clock; `events.retention_days = 90`.

## Main flow

### S303-1 Unfiltered browsing, newest first, in pages

- Given: the events.
- When: `GET /v1/events`, then follow `next_cursor` until absent; `GET /events` (the page).
- Then: pages of 50 ordered by `at DESC, event_id DESC`; the union is all 5,000 events exactly once; each item is the event's JSON as the log sink writes it (`event_id`, `at`, `kind`, `outcome`, `reason`, `user_id`, `session_id`, `app_id`, `provider_id`, `client_ip`, `ua_prefix`, `ua_sha256`, `request_id`, `attrs`); the page shows kind, outcome, reason, user (linked), session (linked), application, client address, user-agent prefix, time, and the `attrs` keys; the query uses `events(at)`.

### S303-2 Filters combine with AND and use their indexes

- Given: the events.
- When: `GET /v1/events?user_id=u_x`; `?client_ip=203.0.113.9`; `?kind=login.failed`; `?kind=login.failed&outcome=failure&user_id=u_x`; `?session_id=s_1`; `?since=<t1>&until=<t2>` (a 6-hour window); `?kind=admin.user_disable`; `?outcome=failure`.
- Then: 300, 120, the number of failed logins, the intersection, 40, the window's events and the disable records respectively, each page newest first; EXPLAIN QUERY PLAN (unit test over the same SQL) shows `events_user_at` for the user filter, `events_ip_at` for the address, `events_kind_at` for the kind, `events_at` for the window and the outcome-only filter; `outcome` alone is applied over rows read in `at` order and reads at most 10,000 rows per page, returning a possibly short page with a cursor; `reason` is not a filter in M4-min (visible in the rows).

### S303-3 Cursors are stable under concurrent inserts

- Given: `GET /v1/events?limit=50` returned page 1 with `next_cursor`.
- When: 200 new events are inserted (logins through the mock provider), then page 2 is fetched with the cursor, and so on to the end.
- Then: no event from page 1 reappears, no event older than page 1's last row is skipped, and the new events are not on any page of this walk (they are newer than the cursor); a fresh unfiltered `GET` shows them first.

### S303-4 Administrative actions show their actor

- Given: 301-4 (`u_a` disabled `u_x`) and 305-1 (CLI grant).
- When: `GET /v1/events?user_id=u_x&kind=admin.user_disable`; `GET /v1/events?kind=admin.grant`; `GET /users/u_x` (recent events section).
- Then: the disable record has `user_id=u_x`, `attrs.actor=u_a`, `attrs.actor_session`, `attrs.count=4`; the grant record has `attrs.actor=cli`, `attrs.role=admin`; the user page's recent events include the disable with "by u_a" rendered from `attrs.actor` and links to `/users/u_a`.

### S303-5 What a row never contains

- Given: every event in the fixture, including `csrf.rejected`, `handoff.rejected`, `login.failed` with provider errors and `config.loaded`.
- When: the whole table is paged through the API and the page.
- Then: no item contains a handle value, a handoff code, a transaction id, a `state`, `nonce`, PKCE verifier, ID token, access token, client secret value, caller key value or a cookie header (the harness greps every body for every secret it generated); user agents appear only as the 64-byte sanitized prefix and the digest.

## Alternative flows

### S303-6 Time filters accept unix seconds and refuse nonsense

- Given: `Ha`.
- When: `?since=<t2>&until=<t1>` with `t2 > t1`; `?since=abc`; `?since=-1`; `?until=<now + 1 year>`.
- Then: `400 invalid_filter` for the first three; the fourth is accepted (an upper bound in the future is a no-op).

## Abuse cases

| Category | Case | Applies |
| --- | --- | --- |
| Replay | S303-A1 | yes |
| Tampering | S303-A2 | yes |
| Race / timing | S303-A3 | yes |
| Resource exhaustion | S303-A4 | yes |
| Confused deputy | S303-A5 | yes |
| Spoofed or duplicated headers | — | no: covered by 300-A2 and 300-A6 |
| Downgrade | — | no: no negotiation; transport is 300-A7 |
| Enumeration | S303-A6 | yes |

### S303-A1 A cursor outlives the rows it points past

- Given: a cursor from the middle of a walk; the prune task deletes events older than retention and the oldest beyond `max_rows` (014-8).
- When: the cursor is used after the prune.
- Then: `200` with the next rows that still exist (a cursor is a position, not a row reference); never `500`; a cursor from one filter used with another filter is still a valid position (it only encodes `at` and `event_id`).

### S303-A2 Forged cursors and filter injection

- Given: `Ha`.
- When: `?cursor=` + random base64url, a cursor with a tampered `at`, a cursor of 5 KiB, `?kind=login.failed%27%20OR%201=1`, `?kind=` + 200 characters, `?user_id=u_x;DROP`, `?client_ip=203.0.113.0/24`, `?client_ip=::ffff:203.0.113.9`.
- Then: `400 invalid_cursor` for the cursor forms (the cursor carries a MAC under the process CSRF key, so a tampered position is detected and never parsed into SQL); `400 invalid_filter` for an unknown kind, an over-long kind, a malformed user id and a CIDR (exact addresses only in M4-min); the IPv4-mapped form is normalized to `203.0.113.9` and matches the 120 rows; every value is a bound parameter.

### S303-A3 Reading while the prune runs

- Given: a walk in progress; the prune task deletes 1,000 rows between two pages.
- When: the next page is fetched.
- Then: the page contains only rows that exist at read time, in order, with no duplicate; the test asserts the walk still terminates and counts match the table at the end.

### S303-A4 Pages are bounded whatever the filter

- Given: 1,000,000 events (`events.max_rows`, bulk-inserted); `Ha`.
- When: `GET /v1/events?outcome=info&limit=200` (the least selective filter), `?kind=verify.denied&limit=200`, `?client_ip=192.0.2.1` (an address with no rows), 16 concurrent walks.
- Then: every page answers within the request budget: the outcome-only page reads at most 10,000 rows and may return fewer than 200 items with a cursor; the kind filter uses its index; the empty address answers at once with an empty page; memory stays under the harness limit; the concurrency cap refuses the 17th caller.

### S303-A5 A viewer reads the same history, nobody else reads any

- Given: `Hv`; `Hn`; no handle.
- When: `GET /v1/events?user_id=u_x` with each.
- Then: `200` for the viewer (by design; TM-45 residual), `403 not_admin` for `Hn`, `403 login_required` without a handle; no query executed in the refused cases.

### S303-A6 The history does not become a user directory

- Given: `Ha`.
- When: `GET /v1/events?user_id=u_x`, the page `/events?user_id=u_x`.
- Then: rows carry `user_id` and never the user's email (the page links the id to the user page, where the email is shown to grant holders anyway); there is no filter by email or email prefix on this endpoint; the `client_ip` filter requires an exact address, so the history cannot be swept by prefix.

## Observability expectations

- Log: nothing per read (reads are not audited; documented residual); `400`s at `debug` with the request id.
- Audit: none for reads.
- Metrics: `hopae_admin_requests_total{role,outcome}`; `hopae_admin_events_rows_scanned_total` (rows read by the outcome-only path, to size the cap).

## Test mapping

| Case | Test | File | Kind | Status |
| --- | --- | --- | --- | --- |
| S303-1 | `s303_1_unfiltered_newest_first_in_pages` | `tests/scenarios/s303_admin_events.rs` | integration | planned |
| S303-2 | `s303_2_filters_combine_and_use_indexes` | `tests/scenarios/s303_admin_events.rs` | integration | planned |
| S303-3 | `s303_3_cursors_stable_under_inserts` | `tests/scenarios/s303_admin_events.rs` | integration | planned |
| S303-4 | `s303_4_admin_actions_show_their_actor` | `tests/scenarios/s303_admin_events.rs` | integration | planned |
| S303-5 | `s303_5_rows_never_contain_credentials` | `tests/scenarios/s303_admin_events.rs` | integration | planned |
| S303-6 | `s303_6_time_filters_accept_seconds_refuse_nonsense` | `tests/scenarios/s303_admin_events.rs` | integration | planned |
| S303-A1 | `s303_a1_cursor_outlives_pruned_rows` | `tests/scenarios/s303_admin_events.rs` | integration | planned |
| S303-A2 | `s303_a2_forged_cursors_and_filter_injection` | `tests/scenarios/s303_admin_events.rs` | integration | planned |
| S303-A3 | `s303_a3_reading_while_prune_runs` | `tests/scenarios/s303_admin_events.rs` | integration | planned |
| S303-A4 | `s303_a4_pages_bounded_whatever_the_filter` | `tests/scenarios/s303_admin_events.rs` | integration | planned |
| S303-A5 | `s303_a5_viewer_reads_nobody_else_does` | `tests/scenarios/s303_admin_events.rs` | integration | planned |
| S303-A6 | `s303_a6_history_is_not_a_user_directory` | `tests/scenarios/s303_admin_events.rs` | integration | planned |

The index assertions of 303-2 are a unit test over the store's SQL
(`src/store/sqlite/tests.rs`, `s303_2_filters_combine_and_use_indexes` calls
it through the test hooks' `GET /explain?query=events&...`).

## Live verification

| Date | Hopae version | Gateway version | Provider | Environment label | Result | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| — | — | — | — | — | — | Not yet run. |

## Open questions

- Should `reason` be a filter in M4-min (it would need `events(kind, reason, at)` or a scan)? Deferred to M2's history API.
- Is the 10,000-row scan cap for the outcome-only filter the right order of magnitude, or should `outcome` require another filter?

## 한국어 요약

부여 보유자는 `events` 테이블을 종류, 결과, 사용자, 세션, 클라이언트 주소, 시간
범위로 필터하고 커서로 최신순 페이지를 넘기며, 새 이벤트가 들어와도 행이 건너뛰어
지거나 반복되지 않습니다. 모든 페이지는 인덱스를 쓰는 제한된 조회 하나이고, 어떤
행도 핸들·코드·토큰·비밀을 담지 않으며, 관리 작업은 `attrs.actor`로 행위자를
보여 줍니다. 핵심 남용 사례는 위조된 커서와 필터 주입이 SQL에 닿기 전에 `400`으로
거부되는 것입니다.
