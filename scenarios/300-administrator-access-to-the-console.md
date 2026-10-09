# S300 — Administrator access to the console: handle authentication, grants, roles, freshness, CSRF, peers and direct connections

<!-- scenario-status: draft -->

- Area: management, security
- Milestone: M4
- ADRs: 0016, 0004, 0007, 0008, 0010, 0013, 0015
- Threat model: TM-15, TM-42, TM-43, TM-45
- Gateway contract: Hangang route fragments (the console route without `strip_request_cookies`), Verify endpoint (`302`/`401` with `reauth_required`), Application-host entry points (`/_hopae/logout` on the console host)

## Goal

A user with a live grant reaches the console on its own host after the
ordinary login, Hopae authenticates every console request from the
`__Host-hopae` handle and the grant table and never from a header, a session
whose provider authentication is older than `admin.max_auth_age` is sent to a
reauthentication the provider actually performs, a user without a grant, a
read-only administrator attempting a change, a cross-site request, an
unexpected peer or a connection that bypasses the gateway gets a `403` that
changes nothing, every mutation re-checks its actor inside the write, and
every refusal is recorded.

## Preconditions and fixtures

- Configuration `tests/fixtures/m4-admin.json` (console host `hopae-admin.example.test`, implicit application `admin`; application `app` on `app.example.test`); mock provider profile `auth_time_present` unless a case says otherwise.
- Users: `u_a` (granted `admin`), `u_v` (granted `viewer`), `u_n` (no grant), each with a live session and a handle on the console host (`Ha`, `Hv`, `Hn`) obtained through the login and handoff flows of scenarios 002 and 003 with the console host as the target; `u_n` additionally holds a handle `Hn_app` on `app.example.test`.
- Requests to the admin listener come from the loopback peer (in `trusted_proxies`) with `x-forwarded-host: hopae-admin.example.test`, `x-forwarded-proto: https`, `x-forwarded-for: 203.0.113.9`, `user-agent: UA1`, unless a case says otherwise. The harness's `AdminClient` sends them; `AdminClient::from_peer` binds a second loopback address that is **not** in `trusted_proxies`.
- Gateway layer: the console route fragment of the administration page (protected, standard `auth`, no `strip_request_cookies`) with the admin listener as backend, plus the `app` route of the contract page.
- Injected clock; grants written with `hopae admin grant` (scenario 305) before the case starts.

## Main flow

### S300-1 First visit through the gateway goes through the ordinary login and lands with a console handle

- Given: gateway layer; a browser with no cookies.
- When: `GET https://hopae-admin.example.test/users` through the gateway, then the portal login, then the handoff.
- Then: the gateway's verify call answers the unauthenticated `302` to the portal with `__Host-hopae_bind` planted on the console host (001-1); after login the handoff lands on `https://hopae-admin.example.test/_hopae/login?return=/users&_hopae_handoff=K` and plants `__Host-hopae=Ha` (003); the next `GET /users` is proxied to the admin listener with the cookie present (no stripping); the admin listener records no request before that. The transaction's `app_id` is `admin`; the session's `auth_time` equals the mock's `auth_time` claim (`attrs.auth_time_source = token` on `session.created`).

### S300-2 A granted user is served from the handle, not from the headers

- Given: `Ha` for `u_a` (role `admin`).
- When: `GET /v1/me` with `cookie: __Host-hopae=Ha` and, forged by the harness, `x-forwarded-user: u_n`, `x-forwarded-email: n@example.test`, `x-hopae-session: s_n`.
- Then: `200 {"user_id":"u_a","role":"admin","session_id":"<u_a's session>","aal":1,"auth_time":<claim>,...}`; the forged headers had no effect; `GET /` is `200` with the status page; the console handle's `last_seen_at` is touched as a verify would; counter `hopae_admin_requests_total{role=admin,outcome=ok}` incremented.

### S300-3 A user without a grant is refused and told who they are

- Given: `Hn` for `u_n`.
- When: `GET /users` (document navigation) and `GET /v1/users`.
- Then: both `403`; the page names `u_n` and `n@example.test` and nothing else of the console; the JSON body is `{"error":"not_admin"}`; one required event `admin.denied` per request with `user_id=u_n`, the session id, `reason=not_admin`, `attrs.endpoint` = `/users` resp. `/v1/users`, `attrs.method=GET`; no `set-cookie`; `Hn` stays valid for the console host (a later grant makes the same cookie work, 305-1).

### S300-4 A read-only administrator reads but cannot change

- Given: `Hv` for `u_v` (role `viewer`).
- When: `GET /v1/users`, `GET /v1/sessions`, `GET /v1/events`, `GET /v1/status`, then `POST /v1/users/u_n/disable` with the API requirements of 300-9.
- Then: every `GET` is `200` with the same bodies an administrator gets (addresses and emails included); the `POST` is `403 {"error":"role_insufficient"}`, `u_n` stays `active`, event `admin.denied` with `reason=role_insufficient`, `attrs.endpoint=/v1/users/{id}/disable`; the HTML user page for a viewer renders no disable, enable or terminate form.

### S300-5 A revoked grant stops the next request without a restart

- Given: `Ha` valid; `hopae admin revoke u_a` runs while the instance serves (305-3).
- When: `GET /v1/me` with `Ha`.
- Then: `403 not_admin` and `admin.denied`; the session itself is untouched (`Ha` still verifies on the gateway listener as an ordinary allow for the console host, which then proxies to the listener's `403`); re-granting makes the next request `200`.

### S300-6 An old provider authentication is sent to a real reauthentication

- Given: `u_a` with a session whose `auth_time` (from the claim) is 12 h 1 s in the past while the console handle is kept alive (idle refreshed every 10 minutes; `admin.session.absolute` raised to `13h` for this case); gateway layer or the harness's verify call for the console host.
- When: (a) verify for `https://hopae-admin.example.test/users` as a document navigation with `Ha`; (b) the same as a non-document request; (c) the portal `/login?txn=` of the transaction from (a), with the portal handle `H0` still valid; (d) the provider round trip and the callback.
- Then: (a) `302` to `https://auth.example.test/login?txn=T`, `x-hopae-reason: reauth_required`, `cache-control: no-store`, the handle is **not** cleared, and the transaction row has `reauth_max_age = 43200`, `purpose = login`, `return_target = https://hopae-admin.example.test/users`, `portal_session_id` = the live session; (b) `401 {"error":"reauth_required","login":"https://hopae-admin.example.test/users"}` creating nothing; (c) the portal does **not** single-sign-on (no immediate handoff although `H0` is valid), the chooser (or the one-provider auto-redirect) sends the browser to the mock's authorize endpoint and the mock records `max_age=43200` and `prompt=login` on that request; (d) the mock's ID token carries `auth_time` = the moment the code was issued; the callback accepts it, the existing session is reauthenticated in one transaction: `sessions.auth_time` = that claim, `factors` gains a second `{kind: oidc, provider: mock, at: <claim>}`, `cred_gen` incremented, every handle revoked with `reason=reauth`, outstanding codes consumed, a new portal handle set, a handoff code for the console host minted at the new generation; events `login.succeeded` with `attrs.reauth = true` and `handle.revoked` per handle; after the handoff the next `GET /v1/me` is `200` with the new `auth_time`; a verify on `app.example.test` with the old handle is `302` to the portal and single sign-on re-plants it without a provider visit (003).

### S300-7 The console application's own policy applies to the console handle

- Given: `Ha`; `admin.session.idle = 30m`, `admin.binding.ip = strict`, `on_authz_change = terminate` (implicit).
- When: (a) 31 minutes pass with no request, then `GET /v1/me`; (b) a fresh `Ha'`, then `GET /v1/me` with `x-forwarded-for: 198.51.100.7`; (c) a fresh `Ha''`, then `u_a`'s `groups` changed in the store (`authz_version` bumped), then `GET /v1/me`.
- Then: (a) `403 login_required` and the gateway-side verify for the same request would be the unauthenticated `302` (010-2); the handle idle timer of the `admin` application is what ran out, not `session.idle`; (b) `403 login_required`, the session is terminated with `reason=binding_ip` (011-1), event `session.terminated`; (c) `403 login_required`, the session is terminated with `reason=authz_change` because the implicit application is `terminate`; a verify on `app.example.test` for the same user is unaffected by (a) and refreshed by (c) under `app`'s `refresh` policy.

### S300-8 Preflight prints the console route and refuses the reserved id

- Given: `m4-admin.json`; then the same file with an extra `apps[]` entry `app_id: "admin"`; then with `admin.require_aal: 2`; then with `listen.admin` equal to `listen.portal`; then with `admin.public_url: "https://hopae-admin.example.test/path"`; then with the console host also listed in `apps[app].hosts`; then with `admin.untrusted_peers: "maybe"`.
- When: `hopae --check` on each.
- Then: the first prints, after the application fragments, a route fragment with `"id": "hopae-admin"`, `"host": "hopae-admin.example.test"`, the standard `auth` block and **no** `strip_request_cookies`, lists the implicit application `admin` with its hosts, lifetimes, binding and `max_auth_age`, prints `admin.untrusted_peers refuse`, and ends in `config ok`; the second exits `2` naming `apps[1].app_id` and "reserved"; the third exits `0` with a warning naming `admin.require_aal` and that every console request will be refused before M5 (`--strict` exits `2`); the fourth exits `2` ("listeners must differ"); the fifth exits `2` ("origin without path"); the sixth exits `2` ("console host is registered implicitly"); the seventh exits `2` naming the allowed values.

### S300-9 State-changing requests carry the form token or the API header

- Given: `Ha`.
- When: (a) `GET /users/u_n` (the page), then `POST /users/u_n/disable` with the page's `csrf` field, `content-type: application/x-www-form-urlencoded`, `origin: https://hopae-admin.example.test`; (b) `POST /v1/users/u_n/enable` with `content-type: application/json`, `x-hopae-admin-request: 1`, no `Origin`; (c) the same with `origin: https://hopae-admin.example.test` and `sec-fetch-site: same-origin`.
- Then: (a) `303` back to the user page with `u_n` disabled (301-4); (b) and (c) `200 {"changed":true}`; the token in (a) was bound to `Ha` (purpose `admin`) and is refused with another handle (300-A1).

### S300-10 Sign-out from the console ends the session everywhere

- Given: `Ha`; gateway layer.
- When: the page's sign-out link `https://hopae-admin.example.test/_hopae/logout` is followed and the portal confirmation posted (015-1 to 015-3).
- Then: `u_a`'s session is terminated with `reason=logout`; the next `GET /` through the gateway is the unauthenticated `302` and never reaches the admin listener; a stale `Ha` sent directly to the listener is `403 login_required`.

### S300-13 A peer that is not the gateway is refused by default

- Given: `Ha`; `admin.untrusted_peers = refuse` (default); then a fixture override `as_client`.
- When: `AdminClient::from_peer(<address outside trusted_proxies>).get("/v1/me")` with `Ha` and the forwarding headers; then the same under `as_client`.
- Then: under `refuse`: `403 {"error":"untrusted_peer"}` before any cookie is read (the store call counter is unchanged), one `warn` log line naming the peer address (rate limited to one per minute per peer), `hopae_admin_denied_total{reason="untrusted_peer"}` incremented, a sampled `verify.denied` with `reason=untrusted_peer` and the peer as `client_ip`; under `as_client`: the peer itself is the client, `https` is false, so the request is `403 login_required` (`insecure_transport`), as on the portal (300-A6).

### S300-14 Denials at the listener are recorded like denials at the gateway

- Given: no grant check reached; a trusted peer.
- When: 50 requests to `/v1/me` with an unknown handle `v1.…` from `203.0.113.9`; 50 with a malformed cookie; 50 with no cookie; then 50 with the forged identity headers of 300-2 and no cookie.
- Then: each series is counted in `hopae_verify_decisions_total{decision="login",reason=...}` and `hopae_admin_denied_total{reason="login_required"}`, and recorded as **one sampled** `verify.denied` per (client address, reason) per 60 s with `reason` ∈ {`unknown_handle`, `malformed_handle`, `login_required`}, `app_id = admin`, `client_ip = 203.0.113.9` and the request id — through the same helper the gateway listener uses (`http::denials`), so the test-hooks event dump shows the same shape as 004's denials; no required event is written.

## Alternative flows

### S300-11 Pages are rendered in Korean on request and carry the pinned headers

- Given: `Ha`.
- When: `GET /` with `accept-language: ko`, then with `accept-language: en`, then `GET /v1/status` with `accept-language: ko`.
- Then: the first page is Korean, the second English, the JSON unchanged; every response (pages, JSON, `403`s, `404`s, `503`s) carries `cache-control: no-store`, `x-content-type-options: nosniff`, `referrer-policy: same-origin`, `x-frame-options: DENY`, `x-robots-tag: noindex` and `content-security-policy: default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'`; no page body contains `<script`.

### S300-12 The console host without the gateway's `auth` is a `403`, not a login loop

- Given: gateway layer with the console route configured as `access_mode: public` (operator mistake).
- When: a browser with no cookies opens `https://hopae-admin.example.test/`.
- Then: the admin listener answers `403 login_required` with the console URL as the link and starts no login; no transaction row exists; `hopae --check` with `gateway.readonly_token_env` set warns `console_route_without_auth` for the host (phase-0 drift query).

### S300-15 Freshness is evaluated at every console verify, and recent sessions enter without a challenge

- Given: `u_a` signed in on `app.example.test` 5 minutes ago (session `auth_time` from the claim); then the clock advanced to 11 h 59 min and to 12 h 1 min after `auth_time`.
- When: the first navigation to the console host at each time, then, inside the console, a navigation one second after crossing the bound.
- Then: at 5 min and at 11 h 59 min the console is entered by single sign-on without a provider visit (the mock records no authorize request) and the gateway's verify is `200`; at 12 h 1 min the first navigation is the `302 reauth_required` of 300-6; a session already inside the console gets the same `302` on its first navigation after crossing the bound; the admin listener, asked directly with a handle whose session aged between the gateway's check and its own, answers `403 auth_too_old` with the console link and `admin.denied` (`reason=auth_too_old`).

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
| Silent reauthentication | S300-A9 | yes |

### S300-A1 A terminated session's handle and a foreign token are useless

- Given: `Ha` whose session was terminated (302-3 by another administrator); a `csrf` token issued on a page rendered for `Hv`.
- When: `GET /v1/me` with `Ha`; `POST /users/u_n/disable` with `Ha'` (a fresh handle of `u_a`) and the token issued for `Hv`; the same with a token older than 10 minutes.
- Then: `403 login_required` for the first; `403 csrf_rejected` for the second and third with `csrf.rejected` events (`purpose=admin`, `cause=token`, respectively `expired`); `u_n` unchanged.

### S300-A2 Forged identity, tampered cookie, wrong host

- Given: `Hn` for `u_n`; `Ha` for `u_a`.
- When: (a) `GET /v1/me` with `Hn` and `x-forwarded-user: u_a`, `x-forwarded-groups: hopae-admins`, `x-hopae-aal: 2`; (b) `GET /v1/me` with the cookie value `Ha` altered in one character, with `v1.` stripped, with a 9 KiB cookie header; (c) `GET /v1/me` with `Ha` and `x-forwarded-host: app.example.test`; (d) `GET /v1/me` with `u_n`'s `Hn_app` (a handle for `app.example.test`) on the console host.
- Then: (a) `403 not_admin` for `u_n` (the forged headers never read; `aal` in the answer would be the handle's); (b) `403 login_required`, no handle touched, the oversized header `431`; (c) `404 not_found`, no state read; (d) `403 login_required` (`handle_host_mismatch` in the sampled `verify.denied`) and the handle is not cleared on another host.

### S300-A3 A change committed between the request check and the write wins

- Given: `Ha`; the store commit gate holds the `admin_mutation` transaction of `POST /v1/users/u_n/disable` **after** the request check passed and **before** its first statement; meanwhile one of the following commits, each in its own run of the case: (1) `hopae admin revoke u_a`; (2) `u_a`'s role changed to `viewer` (`grant --role viewer`); (3) `u_a`'s session terminated (302-3); (4) the handle `Ha` revoked (a `/switch` confirmation on the console host, 003); (5) the clock advanced past the console handle's idle deadline without a sweep (`revoked_at` still null); (6) the clock advanced past the session's absolute deadline without a sweep (`terminated_at` still null); (7) `u_a` disabled by another administrator (which also terminates the session; the fence sees `status`); (8) `u_a`'s `groups` changed (`users.authz_version` moved past `authz_version_at_auth`, no sweep yet); (9) the clock advanced past `admin.max_auth_age` from the session's `auth_time`; (10) the actor's handle replaced by one for `app.example.test` with the same digest injected by the test hooks (host mismatch).
- When: the gate is released.
- Then: in every run the write is refused inside its transaction: `403 actor_revoked`, `u_n` unchanged, no `admin.user_disable` event, one `admin.denied` with `reason=actor_revoked`; the fence SQL pinned in the plan evaluates deadlines against `now`, `users.status = 'active'`, `users.authz_version = sessions.authz_version_at_auth`, `session_handles.host` = the console host, `sessions.auth_time > now − max_auth_age`, `issued_aal ≥ require_aal`, and the live `admin` grant; a control run with no intervening change commits the write.

### S300-A4 Unauthenticated traffic creates nothing and the cap holds

- Given: no cookie; `limits.admin_max_concurrent = 4`; the store stalled by the test hook for 2 s.
- When: 200 requests to `/`, `/v1/users` and `/v1/users/u_n/disable` from one address without a handle; then 8 concurrent `GET /v1/status` with `Ha`.
- Then: every unauthenticated request is `403 login_required` within the budget, the `login_txns` and `events` tables gain no required rows (only sampled `verify.denied`), RSS stays under the harness limit; of the 8 concurrent requests at most 4 are in flight and the rest are `503 overloaded` with `retry-after: 1` immediately; a `POST` body of 65 KiB is `413 payload_too_large` before any parsing; a 5 KiB query string is `413`.

### S300-A5 Cross-site requests cannot act as the administrator

- Given: `Ha` in a browser; a page on `https://evil.example.org`.
- When: (a) that page submits `<form method=post action="https://hopae-admin.example.test/users/u_n/disable">` (top-level, `sec-fetch-site: cross-site`; under `SameSite=Lax` the cookie is not sent on a cross-site `POST`; the harness also sends the variant with the cookie present); (b) `fetch('https://hopae-admin.example.test/v1/users/u_n/disable', {method:'POST', credentials:'include'})` without and with `content-type: application/json` (the latter triggers a preflight `OPTIONS`); (c) a top-level `GET` navigation from that page to `https://hopae-admin.example.test/users/u_n` (cookie sent under `Lax`); (d) `origin: null`.
- Then: (a) `403 csrf_rejected` (`cause=origin` when the cookie is present; `login_required` without it), `u_n` unchanged; (b) the plain `POST` lacks `x-hopae-admin-request` and the JSON content type: `403 csrf_rejected`; the `OPTIONS` preflight is `404` with no CORS headers so the browser never sends the real request; (c) the page renders (a read, by design) with the pinned headers and no state change; (d) `403 csrf_rejected` (`cause=origin`).

### S300-A6 Forwarding headers are believed only from the gateway, and the residual is recorded

- Given: `Ha` bound to `203.0.113.9`; `admin.untrusted_peers = as_client` for (a).
- When: (a) a connection from a peer outside `trusted_proxies` sends `x-forwarded-for: 203.0.113.9` and `x-forwarded-proto: https` with `Ha`; (b) a trusted peer sends two `x-forwarded-for` lines and `cookie` split over two header lines; (c) a trusted peer sends `x-forwarded-for: 198.51.100.7` with `Ha` (a direct connection from a local process presenting a different address); (d) a trusted peer sends `x-forwarded-for: 203.0.113.9` with `Ha` from a process that is not the gateway.
- Then: (a) the client is the peer address itself, `https` is false, and the request is `403 login_required` (`insecure_transport` in the sampled `verify.denied`): a peer the gateway did not vouch for cannot claim the bound address; under the default `refuse` the same connection is `403 untrusted_peer` (300-13); (b) the chain is joined exactly as the portal joins it (009, 011) and the request is `200`; (c) the session is terminated with `reason=binding_ip` as the gateway's verify would do; (d) `200`: the documented residual (TM-42) — a trusted peer's forwarded address is believed, and Hopae cannot tell a local process on the gateway's address from the gateway; the test records it.

### S300-A7 Plain HTTP never carries the console

- Given: `Ha`.
- When: `GET /v1/me` with `x-forwarded-proto: http` from a trusted peer; then with `cookie.secure = false` in a development fixture (`m1-dev-insecure.json` plus the `admin` block with `http://`).
- Then: the first is `403 login_required` (`insecure_transport`): a `__Host-` handle is never accepted over `http`; the second works only with the loud insecure-mode warning of 013 and `hopae_admin_requests_total{...,insecure_mode=true}`; there is no negotiation between the two.

### S300-A8 An outsider learns nothing about who is an administrator

- Given: no valid handle; `Hn` for `u_n`.
- When: `GET /v1/users/u_a`, `GET /users/u_a`, `GET /v1/me` without a handle; then the same with `Hn`.
- Then: without a handle every path is the same `403 login_required` (identical body, headers and timing class, unknown ids included; `404` is reserved for authenticated callers); with `Hn` every path is `403 not_admin` naming only `u_n` itself; nothing reveals whether `u_a` exists or is granted.

### S300-A9 A provider that completes silently or returns a stale time cannot satisfy the console

- Given: 300-6 (a) performed; the mock profile switched to `auth_time_stale` for one run and `auth_time_missing` for another; in a third run the mock is `auth_time_present` but the harness replays a callback for a transaction **without** `reauth_max_age` (an ordinary login) while the user's session is old.
- When: the callback of the reauthentication transaction; then the console navigation.
- Then: `auth_time_stale`: `login.failed` with `reauth_not_fresh`, nothing created or changed, the session keeps its old `auth_time`, the console still answers `302 reauth_required`; `auth_time_missing`: `login.failed` with `reauth_auth_time_missing`, same consequences, the event names the provider; the ordinary-login run: the callback creates or reuses a session with `auth_time` from the claim, never `now`, so a provider that completed silently from its own live session yields the provider's old `auth_time` and the console keeps refusing; the portal's authorize request for an ordinary transaction carries neither `max_age` nor `prompt`.

## Observability expectations

- Log: `admin.denied` with `reason` ∈ {`not_admin`, `role_insufficient`, `auth_too_old`, `aal_insufficient`, `actor_revoked`}; sampled `verify.denied` for `login_required` and `untrusted_peer` outcomes with the engine's reason (`unknown_handle`, `malformed_handle`, `handle_host_mismatch`, `insecure_transport`, `idle`, `binding_ip`, `authz_change`, `untrusted_peer`) through the shared helper; `csrf.rejected` with `purpose=admin`; `login.failed` with `reauth_not_fresh` or `reauth_auth_time_missing`; the gateway verify's `x-hopae-reason: reauth_required`.
- Audit: `admin.denied` is a required event (outbox) carrying `user_id`, `session_id`, `attrs.endpoint`, `attrs.method`; a console sign-in is the ordinary `session.handoff` with `app_id=admin`; a reauthentication is `login.succeeded` with `attrs.reauth = true` plus `handle.revoked` (`reason=reauth`) per handle; `session.created` carries `attrs.auth_time_source`.
- Metrics: `hopae_admin_requests_total{role,outcome}`, `hopae_admin_denied_total{reason}`, `hopae_verify_decisions_total{decision,reason}` for the engine's part (`reason="reauth_required"` included).

## Test mapping

| Case | Test | File | Kind | Status |
| --- | --- | --- | --- | --- |
| S300-1 | `s300_1_first_visit_logs_in_and_lands_with_console_handle` | `tests/scenarios/s300_admin_access.rs` | gateway | planned |
| S300-2 | `s300_2_granted_user_served_from_handle_not_headers` | `tests/scenarios/s300_admin_access.rs` | integration | planned |
| S300-3 | `s300_3_user_without_grant_is_refused_and_named` | `tests/scenarios/s300_admin_access.rs` | integration | planned |
| S300-4 | `s300_4_read_only_administrator_reads_but_cannot_change` | `tests/scenarios/s300_admin_access.rs` | integration | planned |
| S300-5 | `s300_5_revoked_grant_stops_next_request` | `tests/scenarios/s300_admin_access.rs` | integration | planned |
| S300-6 | `s300_6_old_provider_authentication_is_sent_to_real_reauthentication` | `tests/scenarios/s300_admin_access.rs` | integration | planned |
| S300-7 | `s300_7_console_app_policy_applies_to_console_handle` | `tests/scenarios/s300_admin_access.rs` | integration | planned |
| S300-8 | `s300_8_preflight_prints_console_route_and_refuses_reserved_id` | `tests/scenarios/s300_admin_access.rs` | integration | planned |
| S300-9 | `s300_9_mutations_carry_form_token_or_api_header` | `tests/scenarios/s300_admin_access.rs` | integration | planned |
| S300-10 | `s300_10_sign_out_from_console_ends_session_everywhere` | `tests/scenarios/s300_admin_access.rs` | gateway | planned |
| S300-11 | `s300_11_korean_pages_and_pinned_headers` | `tests/scenarios/s300_admin_access.rs` | integration | planned |
| S300-12 | `s300_12_console_route_without_auth_is_403_not_a_loop` | `tests/scenarios/s300_admin_access.rs` | gateway | planned |
| S300-13 | `s300_13_peer_that_is_not_the_gateway_is_refused_by_default` | `tests/scenarios/s300_admin_access.rs` | integration | planned |
| S300-14 | `s300_14_listener_denials_recorded_like_gateway_denials` | `tests/scenarios/s300_admin_access.rs` | integration | planned |
| S300-15 | `s300_15_freshness_evaluated_at_every_console_verify` | `tests/scenarios/s300_admin_access.rs` | integration | planned |
| S300-A1 | `s300_a1_terminated_handle_and_foreign_token_useless` | `tests/scenarios/s300_admin_access.rs` | integration | planned |
| S300-A2 | `s300_a2_forged_identity_tampered_cookie_wrong_host` | `tests/scenarios/s300_admin_access.rs` | integration | planned |
| S300-A3 | `s300_a3_change_between_check_and_write_wins` | `tests/scenarios/s300_admin_access.rs` | integration | planned |
| S300-A4 | `s300_a4_unauthenticated_traffic_creates_nothing_and_cap_holds` | `tests/scenarios/s300_admin_access.rs` | integration | planned |
| S300-A5 | `s300_a5_cross_site_requests_cannot_act` | `tests/scenarios/s300_admin_access.rs` | integration | planned |
| S300-A6 | `s300_a6_forwarding_headers_believed_only_from_gateway` | `tests/scenarios/s300_admin_access.rs` | integration | planned |
| S300-A7 | `s300_a7_plain_http_never_carries_the_console` | `tests/scenarios/s300_admin_access.rs` | integration | planned |
| S300-A8 | `s300_a8_outsider_learns_nothing_about_administrators` | `tests/scenarios/s300_admin_access.rs` | integration | planned |
| S300-A9 | `s300_a9_silent_or_stale_provider_authentication_cannot_satisfy_console` | `tests/scenarios/s300_admin_access.rs` | integration | planned |

Scenario 004-11's enumeration gains the `reauth_required` outcomes (`302` for
a document navigation, `401` otherwise); the admin listener is not the gateway
listener and its `200` pages are not verify answers.

## Live verification

| Date | Hopae version | Gateway version | Provider | Environment label | Result | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| — | — | — | — | — | — | Not yet run. Live run must include 300-6 against the real provider (`max_age`, `prompt=login`, `auth_time`). |

## Open questions

- Should `apps[].max_auth_age` be exposed for ordinary applications in the same change, since the engine rule and the portal path now exist? The key stays scheduled; the roadmap backlog lists it.
- Is the `403` for an unknown user id to an unauthenticated caller (A8) worth the loss of a distinct `404` for scripts? The ADR chose uniformity.

## 한국어 요약

콘솔은 자체 호스트의 Hopae 애플리케이션이며 관리 리스너는 모든 요청을 게이트웨이가
주입한 헤더가 아니라 `__Host-hopae` 핸들과 `admin_grants` 행으로 인증하고,
`trusted_proxies` 밖의 피어는 기본적으로 거부합니다. 제공자 인증이
`admin.max_auth_age`보다 오래된 세션은 `max_age`와 `prompt=login`을 보내고
`auth_time` 클레임을 검사하는 실제 재인증으로 보내지며, 조용히 끝난 로그인이나
오래된 `auth_time`은 콘솔을 만족시키지 못합니다. 부여가 없는 사용자, 변경을 시도하는
읽기 전용 관리자, 교차 사이트 요청, 우회 연결은 모두 아무것도 바꾸지 않는 `403`을
받고 기록되며, 검사와 쓰기 사이에 커밋된 어떤 변화(취소, 만료, 인가 버전 변경,
신선도)도 쓰기 트랜잭션 안의 울타리가 거부합니다.
