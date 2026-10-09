# S300 — Administrator access to the console: handle authentication, grants, roles, freshness, CSRF and direct connections

<!-- scenario-status: draft -->

- Area: management, security
- Milestone: M4
- ADRs: 0016, 0004, 0007, 0008, 0013, 0015
- Threat model: TM-15, TM-42, TM-43, TM-45
- Gateway contract: Hangang route fragments (the console route without `strip_request_cookies`), Application-host entry points (`/_hopae/logout` on the console host)

## Goal

A user with a live grant reaches the console on its own host after the
ordinary login, Hopae authenticates every console request from the
`__Host-hopae` handle and the grant table and never from a header, a user
without a grant, a viewer attempting a change, a stale sign-in, a cross-site
request or a connection that bypasses the gateway gets a `403` that changes
nothing, and every refusal is recorded.

## Preconditions and fixtures

- Configuration `tests/fixtures/m4-admin.json` (console host `hopae-admin.example.test`, implicit application `admin`; application `app` on `app.example.test`); mock provider profile `default`.
- Users: `u_a` (granted `admin`), `u_v` (granted `viewer`), `u_n` (no grant), each with a live session and a handle on the console host (`Ha`, `Hv`, `Hn`) obtained through the login and handoff flows of scenarios 002 and 003 with the console host as the target; `u_n` additionally holds a handle `Hn_app` on `app.example.test`.
- Requests to the admin listener come from the loopback peer (in `trusted_proxies`) with `x-forwarded-host: hopae-admin.example.test`, `x-forwarded-proto: https`, `x-forwarded-for: 203.0.113.9`, `user-agent: UA1`, unless a case says otherwise. The harness's `AdminClient` sends them.
- Gateway layer: the console route fragment of the administration page (protected, standard `auth`, no `strip_request_cookies`) with the admin listener as backend, plus the `app` route of the contract page.
- Injected clock; grants written with `hopae admin grant` (scenario 305) before the case starts.

## Main flow

### S300-1 First visit through the gateway goes through the ordinary login and lands with a console handle

- Given: gateway layer; a browser with no cookies.
- When: `GET https://hopae-admin.example.test/users` through the gateway, then the portal login, then the handoff.
- Then: the gateway's verify call answers the unauthenticated `302` to the portal with `__Host-hopae_bind` planted on the console host (001-1); after login the handoff lands on `https://hopae-admin.example.test/_hopae/login?return=/users&_hopae_handoff=K` and plants `__Host-hopae=Ha` (003); the next `GET /users` is proxied to the admin listener with the cookie present (no stripping); the admin listener records no request before that. The transaction's `app_id` is `admin`.

### S300-2 A granted user is served from the handle, not from the headers

- Given: `Ha` for `u_a` (role `admin`).
- When: `GET /v1/me` with `cookie: __Host-hopae=Ha` and, forged by the harness, `x-forwarded-user: u_n`, `x-forwarded-email: n@example.test`, `x-hopae-session: s_n`.
- Then: `200 {"user_id":"u_a","role":"admin","session_id":"<u_a's session>","aal":1,...}`; the forged headers had no effect; `GET /` is `200` with the status page; the console handle's `last_seen_at` is touched as a verify would; counter `hopae_admin_requests_total{role=admin,outcome=ok}` incremented.

### S300-3 A user without a grant is refused and told who they are

- Given: `Hn` for `u_n`.
- When: `GET /users` (document navigation) and `GET /v1/users`.
- Then: both `403`; the page names `u_n` and `n@example.test` and nothing else of the console; the JSON body is `{"error":"not_admin"}`; one required event `admin.denied` per request with `user_id=u_n`, the session id, `reason=not_admin`, `attrs.endpoint` = `/users` resp. `/v1/users`, `attrs.method=GET`; no `set-cookie`; `Hn` stays valid for the console host (a later grant makes the same cookie work, 305-1).

### S300-4 A viewer reads but cannot change

- Given: `Hv` for `u_v` (role `viewer`).
- When: `GET /v1/users`, `GET /v1/sessions`, `GET /v1/events`, `GET /v1/status`, then `POST /v1/users/u_n/disable` with the API requirements of 300-9.
- Then: every `GET` is `200` with the same bodies an administrator gets (addresses and emails included); the `POST` is `403 {"error":"role_insufficient"}`, `u_n` stays `active`, event `admin.denied` with `reason=role_insufficient`, `attrs.endpoint=/v1/users/{id}/disable`; the HTML user page for a viewer renders no disable, enable or terminate form.

### S300-5 A revoked grant stops the next request without a restart

- Given: `Ha` valid; `hopae admin revoke u_a` runs while the instance serves (305-3).
- When: `GET /v1/me` with `Ha`.
- Then: `403 not_admin` and `admin.denied`; the session itself is untouched (`Ha` still verifies on the gateway listener as an ordinary allow for the console host, which then proxies to the listener's `403`); re-granting makes the next request `200`.

### S300-6 An old sign-in is refused until the person signs in again

- Given: `Ha`; `admin.max_auth_age = 12h`; the clock advanced 12 h 1 s past `sessions.auth_time` while the handle is kept alive (idle refreshed every 10 minutes, absolute lifetime of the console handle raised to `13h` for this case).
- When: `GET /` and `GET /v1/me`.
- Then: `403`; the page says the sign-in is too old and links to `https://hopae-admin.example.test/_hopae/logout`; the JSON body is `{"error":"auth_too_old"}`; event `admin.denied` with `reason=auth_too_old`; after the logout confirmation (015-3) and a new login the request is `200` with a new `auth_time`.

### S300-7 The console application's own policy applies to the console handle

- Given: `Ha`; `admin.session.idle = 30m`, `admin.binding.ip = strict`, `on_authz_change = terminate` (implicit).
- When: (a) 31 minutes pass with no request, then `GET /v1/me`; (b) a fresh `Ha'`, then `GET /v1/me` with `x-forwarded-for: 198.51.100.7`; (c) a fresh `Ha''`, then `u_a`'s `groups` changed in the store (`authz_version` bumped), then `GET /v1/me`.
- Then: (a) `403 login_required` and the gateway-side verify for the same request would be the unauthenticated `302` (010-2); the handle idle timer of the `admin` application is what ran out, not `session.idle`; (b) `403 login_required`, the session is terminated with `reason=binding_ip` (011-1), event `session.terminated`; (c) `403 login_required`, the session is terminated with `reason=authz_change` because the implicit application is `terminate`; a verify on `app.example.test` for the same user is unaffected by (a) and refreshed by (c) under `app`'s `refresh` policy.

### S300-8 Preflight prints the console route and refuses the reserved id

- Given: `m4-admin.json`; then the same file with an extra `apps[]` entry `app_id: "admin"`; then with `admin.require_aal: 2`; then with `listen.admin` equal to `listen.portal`; then with `admin.public_url: "https://hopae-admin.example.test/path"`.
- When: `hopae --check` on each.
- Then: the first prints, after the application fragments, a route fragment with `"id": "hopae-admin"`, `"host": "hopae-admin.example.test"`, the standard `auth` block and **no** `strip_request_cookies`, lists the implicit application `admin` with its hosts, lifetimes and binding, and ends in `config ok`; the second exits `2` naming `apps[1].app_id` and "reserved"; the third exits `0` with a warning naming `admin.require_aal` and that every console request will be refused before M5 (`--strict` exits `2`); the fourth exits `2` ("listeners must differ"); the fifth exits `2` ("origin without path").

### S300-9 State-changing requests carry the form token or the API header

- Given: `Ha`.
- When: (a) `GET /users/u_n` (the page), then `POST /users/u_n/disable` with the page's `csrf` field, `content-type: application/x-www-form-urlencoded`, `origin: https://hopae-admin.example.test`; (b) `POST /v1/users/u_n/enable` with `content-type: application/json`, `x-hopae-admin-request: 1`, no `Origin`; (c) the same with `origin: https://hopae-admin.example.test` and `sec-fetch-site: same-origin`.
- Then: (a) `303` back to the user page with `u_n` disabled (301-4); (b) and (c) `200 {"changed":true}`; the token in (a) was bound to `Ha` (purpose `admin`) and is refused with another handle (300-A1).

### S300-10 Sign-out from the console ends the session everywhere

- Given: `Ha`; gateway layer.
- When: the page's sign-out link `https://hopae-admin.example.test/_hopae/logout` is followed and the portal confirmation posted (015-1 to 015-3).
- Then: `u_a`'s session is terminated with `reason=logout`; the next `GET /` through the gateway is the unauthenticated `302` and never reaches the admin listener; a stale `Ha` sent directly to the listener is `403 login_required`.

## Alternative flows

### S300-11 Pages are rendered in Korean on request and carry the pinned headers

- Given: `Ha`.
- When: `GET /` with `accept-language: ko`, then with `accept-language: en`, then `GET /v1/status` with `accept-language: ko`.
- Then: the first page is Korean, the second English, the JSON unchanged; every response (pages, JSON, `403`s, `404`s, `503`s) carries `cache-control: no-store`, `x-content-type-options: nosniff`, `referrer-policy: same-origin`, `x-frame-options: DENY`, `x-robots-tag: noindex` and `content-security-policy: default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'`; no page body contains `<script`.

### S300-12 The console host without the gateway's `auth` is a `403`, not a login loop

- Given: gateway layer with the console route configured as `access_mode: public` (operator mistake).
- When: a browser with no cookies opens `https://hopae-admin.example.test/`.
- Then: the admin listener answers `403 login_required` with the console URL as the link and starts no login; no transaction row exists; `hopae --check` with `gateway.readonly_token_env` set warns `console_route_without_auth` for the host (phase-0 drift query).

## Abuse cases

| Category | Case | Applies |
| --- | --- | --- |
| Replay | S300-A1 | yes |
| Tampering | S300-A2 | yes |
| Race / timing | S300-A3 | yes |
| Resource exhaustion | S300-A4 | yes |
| Confused deputy | S300-A5 | yes |
| Spoofed or duplicated headers | S300-A6 | yes |
| Downgrade | S300-A7 | yes |
| Enumeration | S300-A8 | yes |

### S300-A1 A terminated session's handle and a foreign token are useless

- Given: `Ha` whose session was terminated (302-3 by another administrator); a `csrf` token issued on a page rendered for `Hv`.
- When: `GET /v1/me` with `Ha`; `POST /users/u_n/disable` with `Ha'` (a fresh handle of `u_a`) and the token issued for `Hv`; the same with a token older than 10 minutes.
- Then: `403 login_required` for the first; `403 csrf_rejected` for the second and third with `csrf.rejected` events (`purpose=admin`, `cause=token`, respectively `expired`); `u_n` unchanged.

### S300-A2 Forged identity, tampered cookie, wrong host

- Given: `Hn` for `u_n`; `Ha` for `u_a`.
- When: (a) `GET /v1/me` with `Hn` and `x-forwarded-user: u_a`, `x-forwarded-groups: hopae-admins`, `x-hopae-aal: 2`; (b) `GET /v1/me` with the cookie value `Ha` altered in one character, with `v1.` stripped, with a 9 KiB cookie header; (c) `GET /v1/me` with `Ha` and `x-forwarded-host: app.example.test`; (d) `GET /v1/me` with `u_n`'s `Hn_app` (a handle for `app.example.test`) on the console host.
- Then: (a) `403 not_admin` for `u_n` (the forged headers never read; `aal` in the answer would be the handle's); (b) `403 login_required`, no handle touched, the oversized header `431`; (c) `404 not_found`, no state read; (d) `403 login_required` (`handle_host_mismatch` in the sampled `verify.denied`) and the handle is not cleared on another host.

### S300-A3 A revocation committed between the check and the write wins

- Given: `Ha`; the store commit gate holds the `admin_mutation` transaction of `POST /v1/users/u_n/disable` after the request check and before the write; meanwhile `hopae admin revoke u_a` commits.
- When: the gate is released.
- Then: the write is refused inside its transaction: `403 actor_revoked`, `u_n` unchanged, no `admin.user_disable` event, one `admin.denied` with `reason=actor_revoked`; the same with the actor's session terminated instead of the grant revoked.

### S300-A4 Unauthenticated traffic creates nothing and the cap holds

- Given: no cookie; `limits.admin_max_concurrent = 4`; the store stalled by the test hook for 2 s.
- When: 200 requests to `/`, `/v1/users` and `/v1/users/u_n/disable` from one address without a handle; then 8 concurrent `GET /v1/status` with `Ha`.
- Then: every unauthenticated request is `403 login_required` within the budget, the `login_txns` and `events` tables gain no required rows (only sampled `verify.denied`), RSS stays under the harness limit; of the 8 concurrent requests at most 4 are in flight and the rest are `503 overloaded` with `retry-after: 1` immediately; a `POST` body of 65 KiB is `413 payload_too_large` before any parsing; a 5 KiB query string is `413`.

### S300-A5 Cross-site requests cannot act as the administrator

- Given: `Ha` in a browser; a page on `https://evil.example.org`.
- When: (a) that page submits `<form method=post action="https://hopae-admin.example.test/users/u_n/disable">` (top-level, `sec-fetch-site: cross-site`; under `SameSite=Lax` the cookie is not sent on a cross-site `POST`; the harness also sends the variant with the cookie present); (b) `fetch('https://hopae-admin.example.test/v1/users/u_n/disable', {method:'POST', credentials:'include'})` without and with `content-type: application/json` (the latter triggers a preflight `OPTIONS`); (c) a top-level `GET` navigation from that page to `https://hopae-admin.example.test/users/u_n` (cookie sent under `Lax`); (d) `origin: null`.
- Then: (a) `403 csrf_rejected` (`cause=origin` when the cookie is present; `login_required` without it), `u_n` unchanged; (b) the plain `POST` lacks `x-hopae-admin-request` and the JSON content type: `403 csrf_rejected`; the `OPTIONS` preflight is `404` with no CORS headers so the browser never sends the real request; (c) the page renders (a read, by design) with the pinned headers and no state change; (d) `403 csrf_rejected` (`cause=origin`).

### S300-A6 Forwarding headers are believed only from the gateway, and the residual is recorded

- Given: `Ha` bound to `203.0.113.9`.
- When: (a) a connection from a peer outside `trusted_proxies` (the harness binds a second loopback address not listed) sends `x-forwarded-for: 203.0.113.9` and `x-forwarded-proto: https` with `Ha`; (b) a trusted peer sends two `x-forwarded-for` lines and `cookie` split over two header lines; (c) a trusted peer sends `x-forwarded-for: 198.51.100.7` with `Ha` (a direct connection from a local process presenting a different address).
- Then: (a) the client is the peer address itself, `https` is false, and the request is `403 login_required` (`insecure_transport` in the sampled `verify.denied`): a peer the gateway did not vouch for cannot claim the bound address; (b) the chain is joined exactly as the portal joins it (009, 011) and the request is `200`; (c) the session is terminated with `reason=binding_ip` as the gateway's verify would do — the documented residual (TM-42) is that the **same** local process could instead present the bound address and pass; the test records that a trusted peer's forwarded address is believed.

### S300-A7 Plain HTTP never carries the console

- Given: `Ha`.
- When: `GET /v1/me` with `x-forwarded-proto: http` from a trusted peer; then with `cookie.secure = false` in a development fixture (`m1-dev-insecure.json` plus the `admin` block with `http://`).
- Then: the first is `403 login_required` (`insecure_transport`): a `__Host-` handle is never accepted over `http`; the second works only with the loud insecure-mode warning of 013 and `hopae_admin_requests_total{...,insecure_mode=true}`; there is no negotiation between the two.

### S300-A8 An outsider learns nothing about who is an administrator

- Given: no valid handle; `Hn` for `u_n`.
- When: `GET /v1/users/u_a`, `GET /users/u_a`, `GET /v1/me` without a handle; then the same with `Hn`.
- Then: without a handle every path is the same `403 login_required` (identical body, headers and timing class, unknown ids included; `404` is reserved for authenticated callers); with `Hn` every path is `403 not_admin` naming only `u_n` itself; nothing reveals whether `u_a` exists or is granted.

## Observability expectations

- Log: `admin.denied` with `reason` ∈ {`not_admin`, `role_insufficient`, `auth_too_old`, `aal_insufficient`, `actor_revoked`}; sampled `verify.denied` for `login_required` outcomes with the engine's reason (`unknown_handle`, `malformed_handle`, `handle_host_mismatch`, `insecure_transport`, `idle`, `binding_ip`, `authz_change`); `csrf.rejected` with `purpose=admin`.
- Audit: `admin.denied` is a required event (outbox) carrying `user_id`, `session_id`, `attrs.endpoint`, `attrs.method`; a console sign-in is the ordinary `session.handoff` with `app_id=admin`.
- Metrics: `hopae_admin_requests_total{role,outcome}`, `hopae_admin_denied_total{reason}`, `hopae_verify_decisions_total{decision,reason}` for the engine's part.

## Test mapping

| Case | Test | File | Kind | Status |
| --- | --- | --- | --- | --- |
| S300-1 | `s300_1_first_visit_logs_in_and_lands_with_console_handle` | `tests/scenarios/s300_admin_access.rs` | gateway | planned |
| S300-2 | `s300_2_granted_user_served_from_handle_not_headers` | `tests/scenarios/s300_admin_access.rs` | integration | planned |
| S300-3 | `s300_3_user_without_grant_is_refused_and_named` | `tests/scenarios/s300_admin_access.rs` | integration | planned |
| S300-4 | `s300_4_viewer_reads_but_cannot_change` | `tests/scenarios/s300_admin_access.rs` | integration | planned |
| S300-5 | `s300_5_revoked_grant_stops_next_request` | `tests/scenarios/s300_admin_access.rs` | integration | planned |
| S300-6 | `s300_6_old_sign_in_is_refused_until_reauth` | `tests/scenarios/s300_admin_access.rs` | integration | planned |
| S300-7 | `s300_7_console_app_policy_applies_to_console_handle` | `tests/scenarios/s300_admin_access.rs` | integration | planned |
| S300-8 | `s300_8_preflight_prints_console_route_and_refuses_reserved_id` | `tests/scenarios/s300_admin_access.rs` | integration | planned |
| S300-9 | `s300_9_mutations_carry_form_token_or_api_header` | `tests/scenarios/s300_admin_access.rs` | integration | planned |
| S300-10 | `s300_10_sign_out_from_console_ends_session_everywhere` | `tests/scenarios/s300_admin_access.rs` | gateway | planned |
| S300-11 | `s300_11_korean_pages_and_pinned_headers` | `tests/scenarios/s300_admin_access.rs` | integration | planned |
| S300-12 | `s300_12_console_route_without_auth_is_403_not_a_loop` | `tests/scenarios/s300_admin_access.rs` | gateway | planned |
| S300-A1 | `s300_a1_terminated_handle_and_foreign_token_useless` | `tests/scenarios/s300_admin_access.rs` | integration | planned |
| S300-A2 | `s300_a2_forged_identity_tampered_cookie_wrong_host` | `tests/scenarios/s300_admin_access.rs` | integration | planned |
| S300-A3 | `s300_a3_revocation_between_check_and_write_wins` | `tests/scenarios/s300_admin_access.rs` | integration | planned |
| S300-A4 | `s300_a4_unauthenticated_traffic_creates_nothing_and_cap_holds` | `tests/scenarios/s300_admin_access.rs` | integration | planned |
| S300-A5 | `s300_a5_cross_site_requests_cannot_act` | `tests/scenarios/s300_admin_access.rs` | integration | planned |
| S300-A6 | `s300_a6_forwarding_headers_believed_only_from_gateway` | `tests/scenarios/s300_admin_access.rs` | integration | planned |
| S300-A7 | `s300_a7_plain_http_never_carries_the_console` | `tests/scenarios/s300_admin_access.rs` | integration | planned |
| S300-A8 | `s300_a8_outsider_learns_nothing_about_administrators` | `tests/scenarios/s300_admin_access.rs` | integration | planned |

Scenario 004-11's enumeration is unaffected: the admin listener is not the
gateway listener and its `200` pages are not verify answers.

## Live verification

| Date | Hopae version | Gateway version | Provider | Environment label | Result | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| — | — | — | — | — | — | Not yet run. |

## Open questions

- Should the admin listener refuse peers outside `trusted_proxies` outright (instead of treating them as the client) so that a misconfigured deployment fails loudly? Today it mirrors the portal.
- Is the `403` for an unknown user id to an unauthenticated caller (A8) worth the loss of a distinct `404` for scripts? The ADR chose uniformity.

## 한국어 요약

콘솔은 자체 호스트의 Hopae 애플리케이션이며 관리 리스너는 모든 요청을 게이트웨이가
주입한 헤더가 아니라 `__Host-hopae` 핸들과 `admin_grants` 행으로 인증합니다. 부여가
없는 사용자, 변경을 시도하는 viewer, 오래된 로그인, 교차 사이트 요청, 게이트웨이를
우회한 연결은 모두 아무것도 바꾸지 않는 `403`을 받고 `admin.denied`로 기록됩니다.
핵심 남용 사례는 위조된 `x-forwarded-user`가 무시되는 것과, 검사와 쓰기 사이에
커밋된 취소가 쓰기를 거부하는 것입니다.
