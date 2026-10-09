# S003 — Cross-host handoff plants a host-only cookie on the application host

<!-- scenario-status: draft -->

- Area: sessions
- Milestone: M1
- ADRs: 0004, 0005
- Threat model: TM-02, TM-04, TM-05
- Gateway contract: Cross-domain handoff, Cookies, Verify endpoint (`302` with `set-cookie`)

## Goal

After login, the single-use handoff code appended to the return target is
consumed by the verify call on the application host, which plants
`__Host-hopae` for that host and redirects to the clean URL; the same
mechanism works for a second application on a different registrable domain,
and a replayed, expired, moved or stolen code never yields a session handle.

## Preconditions and fixtures

- Configuration `tests/fixtures/m1-two-domains.json`: applications `app` (`app.example.test`) and `other` (`other.example.org`).
- Session `s_1` with portal handle `H0`; handoff code `K1` for `(s_1, app.example.test, /admin/x, 203.0.113.9)` created at `t0`.
- Gateway route fragments for both hosts (gateway layer).
- Injected clock and randomness (`H1` for the new handle).

## Main flow

### S003-1 Valid code plants the cookie and redirects to the clean URL

- Given: `K1` unconsumed, `now = t0 + 5 s`.
- When: `GET /_hopae/verify` with `x-original-url: https://app.example.test/admin/x?_hopae_handoff=K1`, `x-forwarded-host: app.example.test`, `x-forwarded-proto: https`, `x-forwarded-for: 203.0.113.9`, no cookie.
- Then: `302 location: https://app.example.test/admin/x`; `set-cookie: __Host-hopae=H1; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=<absolute remaining>`; `cache-control: no-store`; `x-hopae-reason: handoff`; `handoff_codes.consumed_at` set; `session_handles` row `(sha256(H1), s_1, app.example.test)`; event `session.handoff`.

### S003-2 Other query parameters are preserved

- Given: as S003-1 with `x-original-url: https://app.example.test/admin/x?q=1&_hopae_handoff=K1&z=2`.
- When: verify.
- Then: `location: https://app.example.test/admin/x?q=1&z=2`; parameter order preserved; no double `?`.

### S003-3 Next request on the host is allowed

- Given: S003-1 completed.
- When: verify with `cookie: __Host-hopae=H1` and `x-original-url: https://app.example.test/admin/x`.
- Then: `200` with identity headers (scenario 004 details).

### S003-4 Second domain via single sign-on

- Given: the browser holds `H0` on the portal host; no cookie on `other.example.org`.
- When: verify for `https://other.example.org/` → `302` to `/login?txn=T2` → `GET /login?txn=T2` with `H0` → `302` with `?_hopae_handoff=K2` → verify for `other.example.org` with `K2`.
- Then: a handle `H2` for `(s_1, other.example.org)`; `session_handles` now has three rows for `s_1`; no provider interaction.

## Alternative flows

### S003-5 Handoff through the live gateway

- Given: gateway layer with both routes; the harness holds a browser-like cookie jar.
- When: the full chain from the portal `302` to the final `200` on `app.example.test` and `other.example.org`.
- Then: the upstream never receives a request containing `_hopae_handoff`; the browser receives `set-cookie` only on responses from the respective host; `referrer-policy: no-referrer` present on the relayed `302`.

## Abuse cases

| Category | Case | Applies |
| --- | --- | --- |
| Replay | S003-A1 | yes |
| Tampering | S003-A2 | yes |
| Race / timing | S003-A3 | yes |
| Resource exhaustion | S003-A4 | yes |
| Confused deputy | S003-A5 | yes |
| Spoofed or duplicated headers | S003-A6 | yes |
| Downgrade | S003-A7 | yes |
| Enumeration | S003-A8 | yes |

### S003-A1 Replayed code is rejected without state change

- Given: `K1` consumed by S003-1.
- When: the same verify request again (no cookie).
- Then: `302` to the portal with a new transaction (as scenario 001); no second handle; `handoff.rejected` with `reason=code_consumed`; the existing session is untouched.

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
- Then: the 11th answers `429` with `retry-after`; `handoff.rejected` events are sampled after the 10th; constant-time digest comparison (unit test on the compare function).

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
- When: verify with `K1`.
- Then: identical response bytes (except transaction id) to an unknown code; `reason=code_expired` only in the event.

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
| S003-A1 | `s003_a1_replayed_code_rejected` | `tests/scenarios/s003_handoff.rs` | integration | planned |
| S003-A2 | `s003_a2_moved_code_rejected_and_burned` | `tests/scenarios/s003_handoff.rs` | integration | planned |
| S003-A3 | `s003_a3_concurrent_redemption_single_handle` | `tests/scenarios/s003_handoff.rs` | integration | planned |
| S003-A4 | `s003_a4_code_guessing_bounded` | `tests/scenarios/s003_handoff.rs` | integration | planned |
| S003-A5 | `s003_a5_upstream_never_sees_code` | `tests/scenarios/s003_handoff.rs` | gateway | planned |
| S003-A6 | `s003_a6_portal_ignores_handoff_param` | `tests/scenarios/s003_handoff.rs` | integration | planned |
| S003-A7 | `s003_a7_plain_http_target_refused` | `tests/scenarios/s003_handoff.rs` | integration | planned |
| S003-A8 | `s003_a8_expired_code_uniform_response` | `tests/scenarios/s003_handoff.rs` | integration | planned |

## Live verification

| Date | Hopae version | Gateway version | Provider | Environment label | Result | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| — | — | — | — | — | — | Requires two hosts on different registrable domains in the reference environment. |

## Open questions

- Should a browser prefetch that consumes `K1` before the user's navigation be mitigated by allowing one SSO retry automatically (it is: the next verify starts a transaction and the portal hands off again without the provider)? Confirm the user-visible effect is a single extra redirect.
- Should the IP binding of the code follow the application's `binding.ip` mode (`prefix`) rather than always `strict`?

## 한국어 요약

로그인 후 돌아갈 URL에 붙은 일회용 핸드오프 코드를 애플리케이션 호스트의
verify 호출이 소비하여 그 호스트 전용 `__Host-hopae` 쿠키를 심고 깨끗한 URL로
`302`합니다. 다른 등록 도메인의 두 번째 애플리케이션도 포털 핸들로 제공자 없이
같은 방식으로 처리됩니다. 재사용·이동·만료·추측된 코드는 핸들을 만들지 못하며
업스트림은 코드를 절대 보지 못합니다.
