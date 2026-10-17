# S315 — The console filters users, sessions and events and reads a user's linked identities

<!-- scenario-status: draft -->

- Area: management
- Milestone: M4
- ADRs: 0016, 0019
- Threat model: TM-45
- Gateway contract: none (admin listener)

## Goal

The Identities section narrows the user list by provider, second-factor
enrollment and group, the session list by stored assurance level and the event
list by kind prefix and time range, natively and through the Hangang console
adapter, and reads a user's detail with the provider subject and first and last
sight of every linked identity — all within the bounded candidate window.

## Preconditions and fixtures

- `tests/fixtures/m4-admin.json`; a viewer signed in.
- With SQL: `u_a` (identities at `mock` and `corp`, an authenticator app, member of `grp1:aaaa…`), `u_b` (a synced passkey, disabled), `u_c` (`mock` only); sessions `s_a1` (AAL 1), `s_a2` (AAL 2), `s_c1`; events `factor.webauthn_used` and `login.succeeded` for `u_a`, `admin.user_disable` for `u_b`.
- For S315-3 and the second half of S315-4, `admin.hangang_delegation.authority = hangang`.

## Main flow

### S315-1 User filters

- Given: the viewer.
- When: `provider=corp`; `mfa=enrolled`; `mfa=none&q=c`; `group=grp1:aaaa…`; `mfa=enrolled&status=disabled`; malformed values; the page with `mfa=enrolled&limit=1`.
- Then: `[u_a]`; `[u_a, u_b]`; `[u_c]`; `[u_a]`; `[u_b]`; `400 invalid_filter` for `Corp`, `hopae.passkey`, `yes`, `eng`, `grp1:short`; the page's next link keeps `mfa=enrolled`.

### S315-2 Session and event filters

- Given: the viewer.
- When: `aal=2`; `aal=1&user_id=u_a`; `aal` of `3`, `0`, `two`; events with `kind_prefix=factor.`, `kind_prefix=admin.user_`, a `since`/`until` window; malformed prefixes and an inverted window.
- Then: `[s_a2]`; `[s_a1]`; `400 invalid_filter`; the matching kinds only; `400 invalid_filter`.

## Alternative flows

### S315-3 The Hangang console filters and reads the user detail

- Given: the Hangang authority.
- When: `users/query` with `provider` and `limit`, with `mfa` and `status`; `sessions/query` with `user_id` and `aal`; `events/query` with `user_id` and `kind_prefix`; a refused value; unknown fields and a non-scalar value; `users/get` for `u_a`, an unknown user and a malformed id.
- Then: the same selections as natively; the native `400` for the refused value; `403` for unknown fields and the non-scalar value; the detail with both identities, `subject` and `first_seen_at`/`last_seen_at`, without raw claims; `404`; `403`.

### S315-4 Status reports the portal and the console authority

- When: `GET /v1/status` natively and `status` through the Hangang authority.
- Then: `portal.public_url` equals the configuration, `portal.passkeys: false`; `console.authority` is `{mode: local, delegation: none}`, and `{mode: hangang, delegation: hangang}` with the Hangang authority.

## Abuse cases

| Category | Case | Applies |
| --- | --- | --- |
| Replay | — | covered by S306 (signed nonce admission) |
| Tampering | S315-1, S315-3 | yes: malformed values and unknown fields |
| Race / timing | — | no: reads |
| Resource exhaustion | — | covered by store tests `user_listing_filters_by_provider_second_factor_and_group` and `session_listing_filters_by_stored_level_and_events_by_kind_prefix`: the filters are residual within the 10,000-row window |
| Confused deputy | — | no |
| Spoofed or duplicated headers | — | covered by S300 |
| Downgrade | — | no |
| Enumeration | S315-3 | yes: the adapter refuses fields the native listing does not know |

## Observability expectations

- Metrics: `hopae_admin_rows_examined_total{list}`.

## Test mapping

| Case | Test | File | Kind | Status |
| --- | --- | --- | --- | --- |
| S315-1 | `s315_1_user_listing_filters_by_provider_factor_and_group` | `tests/scenarios/s314_admin_api_gaps.rs` | integration | passing |
| S315-2 | `s315_2_session_and_event_filters` | `tests/scenarios/s314_admin_api_gaps.rs` | integration | passing |
| S315-3 | `s315_3_hangang_console_filters_listings_and_reads_the_user_detail` | `tests/scenarios/s314_admin_api_gaps.rs` | integration | passing |
| S315-4 | `s315_4_status_reports_the_portal_and_the_console_authority` | `tests/scenarios/s314_admin_api_gaps.rs` | integration | passing |

## Live verification

| Date | Hopae version | Gateway version | Provider | Environment label | Result | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| — | — | — | — | — | — | Not yet run against a live Hangang console. |

## Open questions

- None.

## 한국어 요약

Identities 화면은 사용자를 제공자·2차 인증 등록·그룹으로, 세션을 저장된 보증 수준으로,
이벤트를 종류 접두사와 시간 범위로 거르며, 네이티브와 Hangang 어댑터 양쪽에서 같은 결과를
얻습니다. 사용자 상세는 연결된 신원마다 제공자 주체와 처음·마지막 확인 시각을 보여 주고
원시 클레임은 보이지 않습니다. 모든 필터는 1만 행 후보 창 안에서 적용됩니다.
