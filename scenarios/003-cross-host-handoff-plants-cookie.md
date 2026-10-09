# S003 — Cross-host handoff plants a host-only cookie on the application host

<!-- scenario-status: draft -->

- Area: sessions
- Milestone: M1
- ADRs: 0004, 0005, 0008
- Threat model: TM-02, TM-04, TM-05, TM-22, TM-23, TM-31, TM-33, TM-36, TM-38
- Gateway contract: Cross-domain handoff, Reserved parameter recognition, Cookies, Verify endpoint (`302` with `set-cookie`)

## Goal

After login, the single-use handoff code appended to the return target is
consumed by the verify call on the application host — but only by the
browser that holds the binding cookie planted there when that login started
— which plants `__Host-hopae` for that host and redirects to the clean URL;
the same mechanism works for a second application on a different registrable
domain, and a replayed, expired, moved, stolen or NAT-neighbour's code never
yields a session handle and never replaces another user's session.

## Preconditions and fixtures

- Configuration `tests/fixtures/m1-two-domains.json`: applications `app` (`app.example.test`) and `other` (`other.example.org`); every host registered by exact name.
- The browser holds `__Host-hopae_bind=B1` on `app.example.test` (planted in scenario 001); session `s_1` (`aal=1`, `cred_gen=1`) with portal handle `H0`; handoff code `K1` for `(s_1, app.example.test, /admin/x, 203.0.113.9, sha256(B1), issued_aal=1, cred_gen=1)` created at `t0`.
- Every verify request carries the caller key.
- Gateway route fragments for both hosts (gateway layer).
- Injected clock and randomness (`H1` for the new handle).

## Main flow

### S003-1 Valid code with the binding cookie plants the handle and redirects to the clean URL

- Given: `K1` unconsumed, `now = t0 + 5 s`.
- When: `GET /_hopae/verify` (document navigation) with `x-original-url: https://app.example.test/admin/x?_hopae_handoff=K1`, `x-forwarded-host: app.example.test`, `x-forwarded-proto: https`, `x-forwarded-for: 203.0.113.9`, `cookie: __Host-hopae_bind=B1`.
- Then: `302 location: https://app.example.test/admin/x`; `set-cookie: __Host-hopae=H1; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=<handle absolute remaining>`; **no** `set-cookie` for `__Host-hopae_bind` (it stays); `cache-control: no-store`; `x-hopae-reason: handoff`; `handoff_codes.consumed_at` set; `session_handles` row `(sha256(H1), s_1, app.example.test, issued_aal=1)`; event `session.handoff` in the same transaction.

### S003-2 Other query parameters are preserved and encoded aliases are recognized

- Given: as S003-1 with `x-original-url: https://app.example.test/admin/x?q=1&_hopae_handoff=K1&z=2`, then with `?q=1&%5Fhopae%5Fhandoff=K1&z=2`, then with `?q=1&_hopae_handoff=K1%2B&z=2` (value percent-encoded).
- When: verify.
- Then: in each case `location: https://app.example.test/admin/x?q=1&z=2`; parameter order preserved; no double `?`; the encoded name is recognized as the same parameter and the value is percent-decoded before lookup.

### S003-3 Next request on the host is allowed

- Given: S003-1 completed.
- When: verify with `cookie: __Host-hopae=H1` and `x-original-url: https://app.example.test/admin/x`.
- Then: `200` with identity headers (scenario 004 details).

### S003-4 Second domain via single sign-on

- Given: the browser holds `H0` on the portal host; no cookie on `other.example.org`.
- When: verify for `https://other.example.org/` → `302` to `/login?txn=T2` planting `__Host-hopae_bind=B2` on `other.example.org` → `GET /login?txn=T2` with `H0` and the portal binding cookie → `302` with `?_hopae_handoff=K2` (bound to `sha256(B2)`) → verify for `other.example.org` with `K2` and `cookie: __Host-hopae_bind=B2`.
- Then: a handle `H2` for `(s_1, other.example.org)`; `session_handles` now has three rows for `s_1`; no provider interaction; `B2` stays. With `portal.sso_confirm_new_host = true` the portal first answers `200` with a one-click confirmation naming `other.example.org` and continues after `POST /login/continue` with the CSRF token.

## Alternative flows

### S003-5 Handoff through the live gateway

- Given: gateway layer with both routes; the harness holds a browser-like cookie jar.
- When: the full chain from the portal `302` to the final `200` on `app.example.test` and `other.example.org`.
- Then: the upstream never receives a request containing `_hopae_handoff`; the browser receives `set-cookie` only on responses from the respective host; `referrer-policy: no-referrer` present on the relayed `302`.

### S003-6 Already-redeemed code with its own handle answers the clean redirect

- Given: a prefetch redeemed `K1` and the browser now holds `H1`; the user's navigation still carries `?_hopae_handoff=K1`.
- When: verify (document navigation) with `cookie: __Host-hopae=H1; __Host-hopae_bind=B1` and the consumed `K1`.
- Then: `302 location: https://app.example.test/admin/x`; no `set-cookie` at all; `x-hopae-reason: code_already_redeemed`; no event beyond a sampled diagnostic; the following `GET /admin/x` is `200`.

### S003-7 Non-document requests carrying the parameter are terminated without touching code or cookies

- Given: `K1` unconsumed; the browser holds `B1`; in the second half it also holds a valid handle `H1` for the same session (another tab finished first).
- When: verify with `sec-fetch-dest: empty`, `sec-fetch-mode: cors` and `x-original-url` carrying `K1`: first without a handle, then with `cookie: __Host-hopae=H1; __Host-hopae_bind=B1`, then with an invalid code and the valid handle.
- Then: all three answer `403` with body `{"error":"handoff_parameter_not_allowed"}` and `x-hopae-reason: handoff_parameter_not_allowed` — the valid handle does **not** turn it into a `200`, so the gateway never forwards the query to the upstream (gateway-layer assertion: the echo upstream records no request); `K1` stays unconsumed; no `set-cookie`; `B1` and `H1` are untouched; the user's later document navigation with `K1` succeeds as S003-1 (or as S003-6 if already redeemed).

### S003-8 Concurrent transactions share the binding cookie

- Given: tab A started a login on `app.example.test` (transaction `TA`, bind `B1`) and its `302` has arrived; then tab B starts another (`TB`).
- When: tab B's unauthenticated verify arrives with `cookie: __Host-hopae_bind=B1`.
- Then: the `302` keeps `B1` (refreshes `Max-Age`, no new value); `TB.bind_sha256 = sha256(B1)`; both `KA` and `KB` redeem successfully in either order, the second replacing the handle of the same session; at the portal both transactions coexist under the same `__Host-hopae_portal` value.

### S003-9 Two tabs start before either cookie arrives and recover

- Given: no cookie on `app.example.test`; tabs A and B send their first document navigations concurrently; the harness delivers the `302` responses in the order A (`B1`) then B (`B2`), so the jar ends with `B2`; `TA.bind_sha256 = sha256(B1)`, `TB.bind_sha256 = sha256(B2)`; tab A completes the provider login first (session `s_1`, portal handle `H0`), producing `KA` bound to `sha256(B1)`.
- When: tab A navigates to `…?_hopae_handoff=KA` with `cookie: __Host-hopae_bind=B2` and no handle.
- Then: `KA` is burned (`handoff.rejected`, `reason=bind_mismatch`); the response is the ordinary unauthenticated `302` to `/login?txn=TA2` **keeping `B2`** (no new bind value), with `TA2.recovery_depth = 1` and `TA2.bind_sha256 = sha256(B2)`; the portal holds `H0`, so it hands off immediately with `KA2` bound to `sha256(B2)`; the next navigation plants `H1`; the user saw two extra redirects and no error. Tab B's callback then completes with the same portal cookie: because the browser already holds `H0` for the same user, no second session is created and `KB` (bound to `sha256(B2)`) redeems normally, replacing `H1` with a handle of the same session. The same test with the response order reversed ends identically.

## Abuse cases

| Category | Case | Applies |
| --- | --- | --- |
| Replay | S003-A1 | yes |
| Tampering | S003-A2, S003-A12 | yes |
| Race / timing | S003-A3, S003-A11 | yes |
| Resource exhaustion | S003-A4, S003-A13 | yes |
| Confused deputy | S003-A5, S003-A9, S003-A10 | yes |
| Spoofed or duplicated headers | S003-A6 | yes |
| Downgrade | S003-A7 | yes |
| Enumeration | S003-A8 | yes |

### S003-A1 Replayed code is rejected without state change

- Given: `K1` consumed by S003-1.
- When: the same verify request again from a browser without `H1` (another browser holding `B1`'s digest is impossible; the harness replays without any handle).
- Then: `302` to the portal with a new transaction (as scenario 001); no second handle; existing cookies untouched; `handoff.rejected` with `reason=code_consumed`; the existing session is untouched.

### S003-A2 Code moved to another host or path is rejected

- Given: `K1` bound to `app.example.test` `/admin/x`.
- When: verify with `x-original-url: https://other.example.org/?_hopae_handoff=K1` and, separately, `https://app.example.test/other?_hopae_handoff=K1`.
- Then: `302` to the portal; `handoff.rejected` with `reason=code_host_mismatch` / `code_path_mismatch`; `K1` is consumed by the failed attempt (burned).

### S003-A3 Two simultaneous redemptions produce one handle

- Given: `K1` unconsumed.
- When: two identical verify calls race.
- Then: exactly one `302` with `set-cookie`; the other answers the portal redirect; one `session_handles` row.

### S003-A4 Code guessing is bounded

- Given: `handoff.per_ip_failures_per_minute = 10`.
- When: 11 verify calls with random `_hopae_handoff` values from one IP.
- Then: the 11th answers `403` with body `{"error":"rate_limited","retry_after":60}` (`429` with `retry-after` once gateway change HC-8 is configured); `handoff.rejected` events are sampled after the 10th; constant-time digest comparison (unit test on the compare function).

### S003-A5 A compromised application cannot mint a handoff for another host

- Given: application `app`'s upstream constructs `https://other.example.org/?_hopae_handoff=<K1 observed in its own logs>`; `K1` was never sent to the upstream (S003-5), so the attacker only has codes it created itself through its own login.
- When: a code created for `app.example.test` is redeemed on `other.example.org`.
- Then: as S003-A2; and the threat model records that the upstream never sees codes.

### S003-A6 Client-supplied handoff on the portal listener is ignored

- Given: portal listener.
- When: `GET /login?_hopae_handoff=K1`.
- Then: `400` (no `txn`); `K1` not consumed.

### S003-A7 Plain HTTP target cannot receive a cookie

- Given: `cookie.secure = true`.
- When: verify with `x-forwarded-proto: http` and a valid `K1`.
- Then: `400 insecure_transport`; `K1` not consumed; the gateway maps it to `503`.

### S003-A8 Expired code answers the same as an unknown code

- Given: `now = t0 + 61 s`.
- When: verify with `K1` and `B1`.
- Then: identical response bytes (except transaction id and the new binding cookie value) to an unknown code; `reason=code_expired` only in the event.

### S003-A9 Two browsers behind one IP cannot swap sessions

- Given: attacker browser X and victim browser Y share `203.0.113.9`. X started a login on `app.example.test` (binding cookie `Bx`), completed it, and captured its unconsumed code `Kx` (bound to `sha256(Bx)`) from the portal's redirect. Y holds no cookie on `app.example.test`, or holds its own binding cookie `By` from a login it started, or holds a valid handle of user V.
- When: Y navigates to `https://app.example.test/admin/x?_hopae_handoff=Kx` within 60 s (verify sees Y's cookies only).
- Then: `302` to the portal with a new transaction; Y's existing binding cookie, if any, is kept (a fresh one is planted only if Y had none); **no** `set-cookie` for `__Host-hopae`; `Kx` is burned; event `handoff.rejected` with `reason=bind_mismatch`; X's own later navigation with `Kx` is also refused (`code_consumed`) and X recovers through single sign-on with a new code.

### S003-A10 A valid handle of another user is never replaced silently; the switch is explicit

- Given: browser Y holds a valid `__Host-hopae=Hy` for user V on `app.example.test` and a binding cookie `By`; a code `Ka` for user A exists whose `bind_sha256 = sha256(By)` (constructed by the harness through the store to test the invariant directly; naturally this arises when the portal session changed to A while the application still holds V).
- When: verify (document navigation) with `x-original-url: https://app.example.test/admin/x?_hopae_handoff=Ka`, `cookie: __Host-hopae=Hy; __Host-hopae_bind=By`.
- Then: `302 location: https://auth.example.test/switch?txn=Ts` with **no** `set-cookie` (every cookie stays); `Ka` burned; transaction `Ts` of purpose `switch` stores `conflicting_handle_sha256 = sha256(Hy)` and the clean target; event `handoff.rejected` with `reason=session_conflict`. `GET /switch?txn=Ts` shows host, user V and user A. `POST /switch` with `choice=switch`, the CSRF token and the portal binding cookie revokes `Hy` (`handle.revoked` with `reason=switch`), mints a fresh code for A bound to `sha256(By)` and redirects to the clean target with it; the next verify plants A's handle. `POST /switch` with `choice=keep` redirects to the clean target and the next verify with `Hy` is `200` as user V. With `Hy` belonging to A's own session instead, the code is redeemed directly and `Hy` is replaced (re-handoff of the same session).

### S003-A11 A code minted before elevation never mints an elevated handle

- Given: session `s_1` at `aal=1`, `cred_gen=1`; an unconsumed code `K0` (`issued_aal=1`, `cred_gen=1`) bound to the attacker's binding cookie `Bx` on `other.example.org` (obtained through single sign-on with a stolen portal handle); the victim completes a second factor, which in one transaction sets `aal=2`, `cred_gen=2`, revokes every handle and consumes every outstanding code.
- When: (a) the attacker redeems `K0` after the elevation committed; (b) the attacker's redemption and the elevation race, with the redemption committing first.
- Then: (a) `302` to the portal, `handoff.rejected` with `reason=code_consumed` (consumed by the elevation) or `code_stale_generation`, no handle. (b) the redemption mints a handle with `issued_aal = min(1, 1) = 1`, and the elevation that commits next revokes it (`reason=elevation`); the attacker's following verify is denied. In no interleaving does any handle with `issued_aal=2` exist for `other.example.org` unless minted from a code with `issued_aal=2` and `cred_gen=2`. The test runs both orders deterministically with harness-controlled commit points and additionally 200 unordered iterations.

### S003-A12 Ambiguous reserved parameters are refused without consuming anything

- Given: `K1` unconsumed and `B1` held.
- When: verify (document navigation) with `x-original-url` carrying `?_hopae_handoff=K1&_hopae_handoff=K2`, then `?_hopae_handoff=K1&%5Fhopae%5Fhandoff=K1`, then `?%5Fhopae%ZZhandoff=K1`.
- Then: `403` with `x-hopae-reason: handoff_ambiguous` for the first two (duplicate decoded name) and the third (malformed escape in a candidate name); `K1` remains unconsumed; no cookie changes; event `handoff.rejected` with `reason=handoff_ambiguous`. A later well-formed navigation with `K1` succeeds as S003-1.

### S003-A13 Binding-race recovery cannot loop

- Given: a harness client that discards every `set-cookie` for `__Host-hopae_bind` and always presents a bind that matches no code (a browser with a broken cookie jar, or an attacker trying to make Hopae redirect forever); the portal holds a valid `H0`.
- When: the client follows the redirects: navigation with a code → unauthenticated `302` (depth 1) → portal SSO → code → `302` (depth 2) → … 
- Then: each recovery transaction's `recovery_depth` is the burned code's depth plus one (depths 1, 2, 3 are observed on the codes the portal mints); when the burned code's depth equals `handoff.max_recoveries` (default: the fourth mismatching navigation) Hopae creates no transaction and answers **`403`** with a small HTML body, `content-type: text/html`, `cache-control: no-store` and `x-hopae-reason: handoff_recovery_exhausted` — never a `2xx` — which the live gateway relays to the client; the echo upstream records **zero requests** during the whole chain; the event records the depth; the client's existing cookies are untouched; a fresh navigation without a code starts over at depth 0. A client that tampers with nothing but presents a crafted depth anywhere (query, cookie, header) has no effect, because depth is read only from the code's row. The redirect count per browser is therefore bounded by `3 × (portal round trip)` and the store writes per recovery are one transaction and one code.

## Observability expectations

- Log: `session.handoff` with `session_id`, `host`, `sso`; `handoff.rejected` with `reason`, `client_ip`, `host`.
- Audit: `events` rows for both.
- Metrics: `hopae_handoff_total{outcome,reason}`.

## Test mapping

| Case | Test | File | Kind | Status |
| --- | --- | --- | --- | --- |
| S003-1 | `s003_1_valid_code_plants_cookie` | `tests/scenarios/s003_handoff.rs` | integration | planned |
| S003-2 | `s003_2_other_query_parameters_preserved` | `tests/scenarios/s003_handoff.rs` | unit | planned |
| S003-3 | `s003_3_next_request_allowed` | `tests/scenarios/s003_handoff.rs` | integration | planned |
| S003-4 | `s003_4_second_domain_via_sso` | `tests/scenarios/s003_handoff.rs` | integration | planned |
| S003-5 | `s003_5_handoff_through_live_gateway` | `tests/scenarios/s003_handoff.rs` | gateway | planned |
| S003-6 | `s003_6_already_redeemed_code_clean_redirect` | `tests/scenarios/s003_handoff.rs` | integration | planned |
| S003-7 | `s003_7_non_document_with_parameter_terminated` | `tests/scenarios/s003_handoff.rs` | gateway | planned |
| S003-8 | `s003_8_concurrent_transactions_share_bind` | `tests/scenarios/s003_handoff.rs` | integration | planned |
| S003-9 | `s003_9_first_use_tab_race_recovers` | `tests/scenarios/s003_handoff.rs` | integration | planned |
| S003-A1 | `s003_a1_replayed_code_rejected` | `tests/scenarios/s003_handoff.rs` | integration | planned |
| S003-A2 | `s003_a2_moved_code_rejected_and_burned` | `tests/scenarios/s003_handoff.rs` | integration | planned |
| S003-A3 | `s003_a3_concurrent_redemption_single_handle` | `tests/scenarios/s003_handoff.rs` | integration | planned |
| S003-A4 | `s003_a4_code_guessing_bounded` | `tests/scenarios/s003_handoff.rs` | integration | planned |
| S003-A5 | `s003_a5_upstream_never_sees_code` | `tests/scenarios/s003_handoff.rs` | gateway | planned |
| S003-A6 | `s003_a6_portal_ignores_handoff_param` | `tests/scenarios/s003_handoff.rs` | integration | planned |
| S003-A7 | `s003_a7_plain_http_target_refused` | `tests/scenarios/s003_handoff.rs` | integration | planned |
| S003-A8 | `s003_a8_expired_code_uniform_response` | `tests/scenarios/s003_handoff.rs` | integration | planned |
| S003-A9 | `s003_a9_two_browsers_same_ip_cannot_swap_sessions` | `tests/scenarios/s003_handoff.rs` | gateway | planned |
| S003-A10 | `s003_a10_other_users_handle_requires_explicit_switch` | `tests/scenarios/s003_handoff.rs` | integration | planned |
| S003-A11 | `s003_a11_pre_elevation_code_never_elevated` | `tests/scenarios/s003_handoff.rs` | integration | planned |
| S003-A12 | `s003_a12_ambiguous_parameter_refused` | `tests/scenarios/s003_handoff.rs` | integration | planned |
| S003-A13 | `s003_a13_recovery_bounded_no_upstream` | `tests/scenarios/s003_handoff.rs` | gateway | planned |

## Live verification

| Date | Hopae version | Gateway version | Provider | Environment label | Result | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| — | — | — | — | — | — | Requires two hosts on different registrable domains in the reference environment. |

## Open questions

- Confirm with real browsers at G8 that a prefetch-redeemed code followed by the navigation (S003-6) is invisible to the user.
- Should the IP binding of the code follow the application's `binding.ip` mode (`prefix`) rather than always `strict`, now that the binding cookie is the primary secret?

## 한국어 요약

로그인 후 돌아갈 URL에 붙은 일회용 핸드오프 코드는 로그인을 시작할 때 그
애플리케이션 호스트에 심어 둔 브라우저별 바인딩 쿠키를 가진 브라우저만, 문서
탐색으로만 소비할 수 있으며, 소비하면 그 호스트 전용 `__Host-hopae` 쿠키를
심고 깨끗한 URL로 `302`합니다. 바인딩 쿠키는 여러 탭이 공유하고 어떤 응답도
지우지 않습니다. 같은 IP의 다른 브라우저는 코드를 쓸 수 없고, 다른 사용자의
유효한 핸들은 확인 페이지를 거쳐야만 바뀌며, 단계 상승 전에 만든 코드는 상승된
핸들을 만들 수 없습니다. 인코딩된 매개변수 별칭은 같은 매개변수로 인식하고
중복·모호한 형태는 거부합니다.
