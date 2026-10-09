# S015 — Application-host entry points never reach the upstream, and Hopae cookies are stripped from upstream requests

<!-- scenario-status: draft -->

- Area: core, security
- Milestone: M1
- ADRs: 0015, 0004, 0005, 0013
- Threat model: TM-01, TM-03, TM-38, TM-39, TM-40, TM-41
- Gateway contract: Application-host entry points, Verify endpoint (`302`/`403`), Portal entry points (`/logout` with `txn`), Proposed gateway changes (HC-12), Hangang route fragments (`site-hopae`)

## Goal

A user signs in or out from a link on the application host itself:
`/_hopae/login` and `/_hopae/logout` are answered by Hopae through the verify
call with a relayed `302` or `403` and never a `2xx`, the only state change of
a logout is the portal's CSRF-protected `POST` (after which the portal shows
its signed-out page with a "Sign in again" link instead of redirecting to the
protected target), the return target can only be the same registered origin, no case or encoding variant of the reserved
namespace leaks to the upstream, and with gateway change HC-12 the upstream
never sees `__Host-hopae` or `__Host-hopae_bind`.

## Preconditions and fixtures

- Configuration `tests/fixtures/m1-two-domains.json` (application `app` on `app.example.test`, `other` on `other.example.org`); cases that need `logout_confirm: false` state the override (`tests/fixtures/m1-logout-direct.json`: `m1-basic.json` with `apps[app].logout_confirm: false`).
- Session `s_1` of user A with handles `H0` (portal) and `H1` (`app.example.test`); binding cookie `B1` on `app.example.test`; portal binding cookie `P1`.
- Every verify request carries the caller key, `x-forwarded-host: app.example.test`, `x-forwarded-proto: https`, `x-forwarded-for: 203.0.113.9`, `user-agent: UA1` and, unless stated, `sec-fetch-dest: document`, `sec-fetch-mode: navigate`, `sec-fetch-site: same-origin`.
- Gateway layer: the whole-host fragment from the contract page (with `strip_request_cookies`), an echo upstream that records every request header, and a verify tap that records what the verify call received. HC-12 is detected by the gateway accepting the route field; cases marked "HC-12" assert the exposure, as 008-A1 does for HC-10, when it is absent.
- Injected clock and randomness: the ticket id is `T1`.

## Main flow

### S015-1 Logout entry creates a ticket and redirects to the portal confirmation

- Given: cookie `__Host-hopae=H1; __Host-hopae_bind=B1`.
- When: verify with `x-original-url: https://app.example.test/_hopae/logout`.
- Then: `302`; `location: https://auth.example.test/logout?txn=T1`; **no** `set-cookie`; `cache-control: no-store`; `x-hopae-reason: logout_entry`; one `login_txns` row with `purpose = logout`, `return_target = https://app.example.test/`, `app_id = app`, `portal_session_id = s_1`, `client_ip = 203.0.113.9`, `bind_sha256 = sha256(B1)`, `portal_bind_sha256` empty, `expires_at = now + 600`; `H1` still valid; no event. Through the gateway: zero upstream requests.

### S015-2 Portal confirmation page with the ticket

- Given: S015-1; cookies `__Host-hopae=H0; __Host-hopae_portal=P1` on the portal host.
- When: `GET /logout?txn=T1`.
- Then: `200` form naming application `app`, hidden field `txn=T1`, CSRF token bound to `H0`; `T1.portal_bind_sha256 = sha256(P1)`; no other state change; `cache-control: no-store`. Without `__Host-hopae_portal` the response plants one and records its digest instead.

### S015-3 Confirmed logout terminates the session and offers a sign-in link

- Given: S015-2.
- When: `POST /logout` with the CSRF token, `txn=T1`, `origin: https://auth.example.test`, cookies `H0`, `P1`.
- Then: `200` (the portal's signed-out page; **no redirect to the protected target**, which would start a login that a provider with a live session answers silently); the page shows a "Sign in again to app" link whose `href` is `https://app.example.test/` (the ticket's `return_target`, validated again at render time); `set-cookie: __Host-hopae=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Lax` (portal host); `sessions.terminated_at = now`, `terminated_reason = logout`, `H0` and `H1` revoked; `T1.consumed_at = now`; event `session.terminated` with `reason=logout`. The next document navigation to `https://app.example.test/` with `H1` is `302` to the portal with the stale cookie cleared (006-3) and requires login again; the portal's `/login?txn=` offers the provider, not single sign-on.

### S015-4 Ticket ends the session when the browser has no valid portal handle

- Given: `H0` revoked by its idle timer (or absent); `H1` valid; S015-1 completed.
- When: `GET /logout?txn=T1` with `P1` only, then `POST /logout` with the page's token, `txn=T1`, `Origin`, `P1`.
- Then: the form's CSRF token is bound to `P1`; the `POST` terminates `s_1` (named by the ticket's `portal_session_id`) with `reason=logout`; `200` signed-out page with the link to `https://app.example.test/`; the next verify with `H1` is denied (`session_terminated`) and clears it.

### S015-5 `return` on the same origin

- Given: cookie `H1`.
- When: verify with `x-original-url: https://app.example.test/_hopae/logout?return=%2Fdocs%2Fbye%3Fq%3D1`, and separately with `return=https%3A%2F%2Fapp.example.test%2Fdocs%2Fbye` and `return=https%3A%2F%2Fapp.example.test%3A443%2Fdocs%2Fbye`.
- Then: each creates a ticket with `return_target = https://app.example.test/docs/bye?q=1` (respectively `…/docs/bye`); after S015-3 the signed-out page's "Sign in again" link is that target byte for byte.

### S015-6 Login entry without a session starts a login for the target

- Given: no cookie.
- When: verify with `x-original-url: https://app.example.test/_hopae/login?return=%2Fadmin%2Fx`.
- Then: `302` to `https://auth.example.test/login?txn=…`; `set-cookie: __Host-hopae_bind=…` as in 001-1; the transaction's `return_target = https://app.example.test/admin/x` (not the entry URL); after login the handoff `location` is `https://app.example.test/admin/x?_hopae_handoff=…` and redemption plants `H1` (003). Without `return`, the target is `https://app.example.test/`.

### S015-7 Login entry with a session redirects to the target

- Given: cookie `H1`.
- When: verify with `x-original-url: https://app.example.test/_hopae/login?return=%2Fadmin%2Fx`.
- Then: `302`; `location: https://app.example.test/admin/x`; no `set-cookie`; `cache-control: no-store`; `x-hopae-reason: already_authenticated`; `H1.last_seen_at` touched as a `200` would; through the gateway, zero upstream requests. A handle that an ordinary verify would refuse (terminated session, binding mismatch under `terminate_session`) yields that verify's `302` to the portal with the same side effects.

## Alternative flows

### S015-8 No-confirmation mode ends the session at verify for same-origin navigations only

- Given: fixture `m1-logout-direct.json`; cookie `H1; __Host-hopae_bind=B1`.
- When: verify for `https://app.example.test/_hopae/logout` with `sec-fetch-site: same-origin`; then the same with `sec-fetch-site: same-site`, `cross-site`, `none`, and with the header absent; then `same-origin` without a valid handle.
- Then: the first answers `302 Location: https://auth.example.test/signed-out?txn=<ticket>` (the ticket is a logout ticket created and consumed in the same call, the opaque reference to `https://app.example.test/`; the query carries no URL) with `set-cookie: __Host-hopae=; Max-Age=0; …`, no change to `__Host-hopae_bind`, `x-hopae-reason: logout`; `s_1` is terminated with `reason=logout` and event `session.terminated`; the portal's `GET /signed-out?txn=<ticket>` answers `200` with the "Sign in again to app" link to `https://app.example.test/`, while an unconsumed ticket or an unknown id gets the expired-link page (`400`). Every other variant answers S015-1 (a ticket and `302` to the portal confirmation; nothing terminated).

### S015-9 Case and encoding variants of the namespace stay with Hopae

- Given: cookie `H1`.
- When: verify for `/_HOPAE/Logout`, `/_hopae/%6Cogout`, then for `/_hopae`, `/_hopae/`, `/_hopae/logout/`, `/_hopae/verify`, `/_hopae/report`, `/_HOPAE/x`.
- Then: the first two are the logout entry (S015-1); each of the rest is `403 {"error":"reserved_path"}` with `x-hopae-reason: reserved_path`, no `set-cookie`, no transaction, event `verify.denied` with `reason=reserved_path`. `/_hopae//logout` and `/_hopae/%2e%2e/logout` are `path_not_canonical` as everywhere. Through the gateway, zero upstream requests for every variant.

### S015-10 Path-scoped host needs the `site-hopae` route

- Given: gateway layer; the two-route path-scoped fragment of the contract page (`/admin` protected); cookie `H1`.
- When: `GET /_hopae/logout` through the gateway; then the same after adding the contract's `site-hopae` route; then `GET /_HOPAE/logout` with the three routes.
- Then: without the route the echo upstream records `/_hopae/logout` and Hopae is not called (the documented limitation); with the route Hopae answers S015-1 and the upstream records nothing; `/_HOPAE/logout` still reaches the upstream on a gateway without HC-10 (TM-39) — the test asserts exactly this until HC-10 flips it, as 008-A1 does.

### S015-11 HC-12 removes Hopae cookies from the upstream request only

- Given: gateway layer with the whole-host fragment including `strip_request_cookies`; cookie `theme=dark; __Host-hopae=H1; __Host-hopae_bind=B1; lang=ko`.
- When: `GET /x` through the gateway; then the same with only `__Host-hopae=H1; __Host-hopae_bind=B1`.
- Then: the verify tap saw the full `cookie` header; the echo upstream saw `cookie: theme=dark; lang=ko` (order kept) and the identity headers; in the second request the upstream saw no `cookie` header at all. On a gateway that rejects the field (no HC-12) the test asserts the exposure instead: the upstream records both Hopae cookies.

## Abuse cases

| Category | Case | Applies |
| --- | --- | --- |
| Replay | S015-A1 | yes |
| Tampering | S015-A2 | yes |
| Race / timing | S015-A3 | yes |
| Resource exhaustion | S015-A4 | yes |
| Confused deputy | S015-A5, S015-A7 | yes |
| Spoofed or duplicated headers | S015-A6 | yes |
| Downgrade | — | no: no negotiation; `x-forwarded-proto: http` is `insecure_transport` as in 001 |
| Enumeration | — | no: non-document requests get one answer for the whole namespace; a document navigation's outcome is visible only to the navigating browser |

### S015-A1 Replayed or foreign ticket is harmless

- Given: S015-3 completed (`T1` consumed).
- When: `GET /logout?txn=T1` and `POST /logout` with `txn=T1` again; then with an unknown `txn`, an expired ticket, and a login transaction's id.
- Then: the ticket is treated as absent: the page is the plain confirmation, the `POST` acts only on a presented portal handle (none left: `200` signed-out page as 006-4), nothing else is terminated, no new event; the login transaction is neither consumed nor altered (`txn_purpose_mismatch` in the log). `/login?txn=T1` answers the ordinary invalid-transaction page without consuming the ticket.

### S015-A2 `return` cannot leave the origin

- Given: cookie `H1`.
- When: verify for `/_hopae/logout` and `/_hopae/login` with each `return`: `https://evil.example.org/`, `//evil.example.org/`, `/\evil.example.org`, `https://other.example.org/` (registered, different origin), `https://app.example.test:8443/`, `http://app.example.test/`, `https://app.example.test@evil.example.org/`, `https://app.example.test/#f`, `javascript:alert(1)`, `/x?_hopae_handoff=K`, `/_hopae/login`, `/_HOPAE/logout`, a 2100-character path, and two `return` pairs.
- Then: each is `403 {"error":"return_not_allowed"}`, `x-hopae-reason: return_not_allowed`, no transaction, no `set-cookie`, event `verify.denied`; every `location` emitted anywhere in this scenario names `app.example.test` or the portal.

### S015-A3 Ticket racing termination

- Given: `T1` unconsumed; `s_1` reaches its idle limit between the page and the `POST`.
- When: `POST /logout` with `txn=T1`.
- Then: the ticket is consumed; termination is a no-op on the already terminated session; `200` signed-out page; exactly one `session.terminated` event exists for `s_1`. With the no-confirmation mode, a direct logout racing an ordinary verify in another tab leaves the other tab denied on its next request.

### S015-A4 Entry-point floods write nothing or are capped

- Given: no cookie.
- When: 100 non-document requests to `/_hopae/logout` from one IP; then 40 document navigations to it within a minute.
- Then: the non-document requests are `403 entry_point_not_document` and write nothing; document navigations past `txn.per_ip_per_minute` answer `403 {"error":"rate_limited","retry_after":60}` (`txn_rate_limited`), as login does; `txn.max_rows` eviction counts `txn.evicted`.

### S015-A5 Cross-site and sibling requests cannot log the user out

- Given: cookie `H1` on `app.example.test`; a page on `https://evil.example.org` and one on the sibling `https://sib.example.test`.
- When: (a) `<img src="https://app.example.test/_hopae/logout">` and `fetch()` from either page (`sec-fetch-dest: image`/`empty`; cookies not sent cross-site under `Lax`); (b) a top-level navigation to the same URL from either page (`sec-fetch-site: cross-site` and `same-site`, cookie sent); (c) the same with `logout_confirm: false`.
- Then: (a) `403 entry_point_not_document` with no `set-cookie`, even when a cookie is present; (b) and (c) S015-1: a ticket and the confirmation page; `H1` untouched; nothing terminated. Only a confirmed `POST` on the portal ends the session.

### S015-A6 Spoofed metadata and canonical-path tricks

- Given: cookie `H1`; `logout_confirm: false`.
- When: a non-browser client sends `sec-fetch-site: same-origin` on a navigation that a browser would mark `cross-site`; a client adds `x-hangang-canonical-path: /_hopae/logout` to a request for `/other`; a client sends two `sec-fetch-site` values.
- Then: the first ends only the sender's own session (browsers never let script set the header; a client can only log itself out); the second is not forwarded by the gateway (not a listed header) and, when injected by the harness, is `canonical_path_mismatch`; the duplicated header is a contract violation (`400`), as for every duplicated context header.

### S015-A7 Attacker-minted ticket cannot be redeemed by the victim

- Given: the attacker's browser performs S015-1 and S015-2 (ticket `Ta`, digest of the attacker's portal cookie recorded) and lures the victim to `https://auth.example.test/logout?txn=Ta`.
- When: the victim's browser (`P1`, `H0`) loads the page and the victim clicks confirm.
- Then: `Ta`'s digest does not match `P1`, so the ticket is treated as absent: the page is the plain confirmation, and the `POST` ends only the victim's own portal session, which the victim consented to on the portal's page (006-A4 applies); the attacker's session is untouched; no `location` names any origin the victim did not come from (the signed-out page is rendered, without a link from the foreign ticket).

## Observability expectations

- Log: `verify.denied` with `reason` ∈ {`reserved_path`, `entry_point_not_document`, `return_not_allowed`, `txn_rate_limited`}; `x-hopae-reason` ∈ {`logout_entry`, `already_authenticated`, `logout`} on the `302`s; `txn_purpose_mismatch` at the portal.
- Audit: `session.terminated` with `reason=logout` (both modes); no event for ticket creation. `txn.evicted` counts rows removed by the synchronous `txn.max_rows` eviction.
- Metrics: `hopae_verify_decisions_total{decision,reason}` for every outcome above; `hopae_session_terminated_total{reason="logout"}`.

## Test mapping

| Case | Test | File | Kind | Status |
| --- | --- | --- | --- | --- |
| S015-1 | `s015_1_logout_entry_creates_ticket_and_redirects` | `tests/scenarios/s015_app_host_entry_points.rs` | integration | planned |
| S015-2 | `s015_2_confirmation_page_with_ticket` | `tests/scenarios/s015_app_host_entry_points.rs` | integration | planned |
| S015-3 | `s015_3_confirmed_logout_terminates_and_returns` | `tests/scenarios/s015_app_host_entry_points.rs` | integration | planned |
| S015-4 | `s015_4_ticket_ends_session_without_portal_handle` | `tests/scenarios/s015_app_host_entry_points.rs` | integration | planned |
| S015-5 | `s015_5_return_on_same_origin` | `tests/scenarios/s015_app_host_entry_points.rs` | integration | planned |
| S015-6 | `s015_6_login_entry_starts_login_for_target` | `tests/scenarios/s015_app_host_entry_points.rs` | integration | planned |
| S015-7 | `s015_7_login_entry_with_session_redirects` | `tests/scenarios/s015_app_host_entry_points.rs` | integration | planned |
| S015-8 | `s015_8_direct_logout_same_origin_only` | `tests/scenarios/s015_app_host_entry_points.rs` | integration | planned |
| S015-9 | `s015_9_namespace_variants_never_reach_upstream` | `tests/scenarios/s015_app_host_entry_points.rs` | gateway | planned |
| S015-10 | `s015_10_path_scoped_host_needs_hopae_route` | `tests/scenarios/s015_app_host_entry_points.rs` | gateway | planned |
| S015-11 | `s015_11_hc12_strips_hopae_cookies_upstream` | `tests/scenarios/s015_app_host_entry_points.rs` | gateway | planned |
| S015-A1 | `s015_a1_replayed_or_foreign_ticket_harmless` | `tests/scenarios/s015_app_host_entry_points.rs` | integration | planned |
| S015-A2 | `s015_a2_return_cannot_leave_origin` | `tests/scenarios/s015_app_host_entry_points.rs` | integration | planned |
| S015-A3 | `s015_a3_ticket_racing_termination` | `tests/scenarios/s015_app_host_entry_points.rs` | integration | planned |
| S015-A4 | `s015_a4_entry_floods_capped` | `tests/scenarios/s015_app_host_entry_points.rs` | integration | planned |
| S015-A5 | `s015_a5_cross_site_cannot_log_out` | `tests/scenarios/s015_app_host_entry_points.rs` | integration | planned |
| S015-A6 | `s015_a6_spoofed_metadata_and_canonical_tricks` | `tests/scenarios/s015_app_host_entry_points.rs` | integration | planned |
| S015-A7 | `s015_a7_attacker_ticket_not_redeemable_by_victim` | `tests/scenarios/s015_app_host_entry_points.rs` | integration | planned |

Scenario 004-11 (`s004_11_no_non_allow_path_is_2xx`) gains the outcomes
`reserved_path`, `entry_point_not_document`, `return_not_allowed`,
`logout_entry`, `already_authenticated` and the direct `logout` in its
enumeration; the unit walk over `Decision` variants covers the new redirect
with `clear_handle`.

## Live verification

| Date | Hopae version | Gateway version | Provider | Environment label | Result | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| — | — | — | — | — | — | Not yet run. The reference deployment showed both Hopae cookies on the upstream before HC-12. |

## Open questions

- Should `sec-purpose` be added to the listed request headers so that prefetch and prerender never count as a document navigation at the entry points (and elsewhere)? Recorded in the roadmap backlog; it changes every route fragment.
- A `return` too long for the verify URL limit (2048 bytes) never reaches Hopae's return check: the gateway-facing parser refuses the whole call (`400 contract_violation`) and nothing is created; S015-A2 asserts that for its 2100-character case.

## 한국어 요약

애플리케이션 호스트의 `/_hopae/logout`과 `/_hopae/login`은 verify 호출 안에서
Hopae가 처리하며, 응답은 중계되는 `302`나 `403`뿐이고 업스트림에는 어떤
변형(`/_HOPAE/logout`, `/_hopae/%6Cogout`, `/_hopae/x`)도 도달하지 않습니다.
로그아웃은 쿠키를 지우지 않고 서버 측 티켓과 함께 포털 확인 페이지로 보내며,
CSRF로 보호된 `POST`만이 세션을 끝내고, 이어서 포털이 보호된 대상으로 리디렉션하는
대신(제공자가 조용히 다시 로그인시키므로) 같은 출처로 제한된 돌아갈 대상으로 가는
"다시 로그인" 링크가 있는 로그아웃 완료 페이지를 보여 줍니다. 교차 사이트 `<img>`나 탐색, 형제 서브도메인, 공격자가 만든
티켓은 아무것도 끝내지 못하고, `return`은 다른 출처를 가리킬 수 없습니다.
HC-12가 있으면 업스트림은 `__Host-hopae`와 `__Host-hopae_bind`를 보지 못합니다.
