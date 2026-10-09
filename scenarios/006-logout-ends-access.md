# S006 — Logout ends access on every host

<!-- scenario-status: approved -->

- Area: sessions
- Milestone: M1
- ADRs: 0004, 0006, 0009
- Threat model: TM-03, TM-18, TM-33
- Gateway contract: Portal entry points (`/logout`), Verify endpoint (`302` with cookie clear)

## Goal

A user who confirms logout at the portal ends the session so that the next
verify on any host denies, stale cookies are cleared as they are seen, and a
cross-site request cannot log a user out.

## Preconditions and fixtures

- Configuration `tests/fixtures/m1-two-domains.json`.
- Session `s_1` with handles `H0` (portal), `H1` (`app.example.test`), `H2` (`other.example.org`).
- Injected clock.

## Main flow

### S006-1 Confirmation page

- Given: cookie `__Host-hopae=H0` on the portal host.
- When: `GET /logout`.
- Then: `200` HTML form with a CSRF token bound to `H0`; no state change; `cache-control: no-store`.

### S006-2 Confirmed logout terminates the session

- Given: S006-1.
- When: `POST /logout` with the CSRF token, cookie `H0`, `origin: https://auth.example.test`.
- Then: `200` "signed out" page; `set-cookie: __Host-hopae=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Lax`; `sessions.terminated_at = now`, `terminated_reason = logout`; all three handles revoked (`revoked_at`); event `session.terminated` with `reason=logout`.

### S006-3 Next request on an application host is denied and its cookie cleared

- Given: S006-2.
- When: verify with `cookie: __Host-hopae=H1` for `https://app.example.test/x` as a document navigation.
- Then: `302` to the portal with a new transaction; `set-cookie: __Host-hopae=; Max-Age=0; …`; `x-hopae-reason: session_terminated`.

### S006-4 Logout without a session

- Given: no cookie.
- When: `GET /logout` then `POST /logout` with the page's token.
- Then: `200` "signed out" page for both; no event; no error leaked.

## Alternative flows

### S006-5 Application-host sign-out of a different account through the switch page

- Given: the application holds user V's handle `Hy` while the portal session now belongs to user A (V's portal handle expired and A signed in); a handoff for A reached `session_conflict` and produced the switch transaction `Ts` (scenario 003-A10); fixture `tests/fixtures/m1-two-domains.json`.
- When: `POST /switch` with `choice=switch`, the CSRF token and the portal binding cookie.
- Then: `Hy` is revoked with `reason=switch` (event `handle.revoked`, session of V otherwise untouched); a fresh code for A is minted and the browser is redirected to the clean target; the next verify on that host is `200` as A. With `choice=keep`: nothing is revoked and the next verify is `200` as V. Without the CSRF token or from a cross-site `Origin`: `403`, nothing revoked.

## Abuse cases

| Category | Case | Applies |
| --- | --- | --- |
| Replay | S006-A1 | yes |
| Tampering | S006-A2 | yes |
| Race / timing | S006-A3 | yes |
| Resource exhaustion | — | no: logout is cheaper than verify and requires a valid session or does nothing |
| Confused deputy | S006-A4 | yes |
| Spoofed or duplicated headers | S006-A5 | yes |
| Downgrade | — | no: no negotiation |
| Enumeration | — | no: the response is identical with or without a session |

### S006-A1 Replayed logout POST is harmless

- Given: S006-2 completed.
- When: the same `POST /logout` again.
- Then: `200` signed-out page; no new event; no error.

### S006-A2 CSRF token mismatch

- Given: cookie `H0`.
- When: `POST /logout` with a token from another session or no token.
- Then: `403`; session unchanged; event `csrf.rejected`.

### S006-A3 Logout racing a handoff

- Given: handoff code `K3` for `s_1` unconsumed.
- When: `POST /logout` and the redemption of `K3` race.
- Then: either the code is consumed before termination (handle created and then revoked by termination) or after (redemption fails); in both orders the next verify with the new handle is denied.

### S006-A4 Cross-site logout attempt

- Given: cookie `H0`; a page on `https://evil.example.org` submits a form to `POST /logout`.
- When: the browser sends it with `origin: https://evil.example.org` (and, with `SameSite=Lax`, without the cookie for a cross-site POST).
- Then: `403` for origin mismatch when the cookie is present; `200` no-op when the cookie is absent; the session survives in both cases. `GET /logout` from an `<img>` tag changes nothing (S006-1).

### S006-A5 Logout cannot target another session by id

- Given: cookie `H0` for `s_1`.
- When: `POST /logout` with a form field `session=s_2`.
- Then: the field is ignored; only `s_1` is terminated.

## Observability expectations

- Log: `session.terminated` with `reason`, `session_id`, `user_id`, handle count.
- Audit: `events` row per session.
- Metrics: `hopae_session_terminated_total{reason}`.

## Test mapping

| Case | Test | File | Kind | Status |
| --- | --- | --- | --- | --- |
| S006-1 | `s006_1_confirmation_page` | `tests/scenarios/s006_logout.rs` | integration | planned |
| S006-2 | `s006_2_confirmed_logout_terminates_session` | `tests/scenarios/s006_logout.rs` | integration | planned |
| S006-3 | `s006_3_next_request_denied_cookie_cleared` | `tests/scenarios/s006_logout.rs` | integration | planned |
| S006-4 | `s006_4_logout_without_session` | `tests/scenarios/s006_logout.rs` | integration | planned |
| S006-5 | `s006_5_switch_page_signs_out_other_account` | `tests/scenarios/s006_logout.rs` | integration | planned |
| S006-A1 | `s006_a1_replayed_logout_harmless` | `tests/scenarios/s006_logout.rs` | integration | planned |
| S006-A2 | `s006_a2_csrf_mismatch_rejected` | `tests/scenarios/s006_logout.rs` | integration | planned |
| S006-A3 | `s006_a3_logout_racing_handoff` | `tests/scenarios/s006_logout.rs` | integration | planned |
| S006-A4 | `s006_a4_cross_site_logout_rejected` | `tests/scenarios/s006_logout.rs` | integration | planned |
| S006-A5 | `s006_a5_cannot_target_other_session` | `tests/scenarios/s006_logout.rs` | integration | planned |

## Live verification

| Date | Hopae version | Gateway version | Provider | Environment label | Result | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| — | — | — | — | — | — | Logout is part of the G9 smoke test. |

## Open questions

- Should applications get a documented link target (`https://auth.example.test/logout`) and an optional `?app=<id>` to show which application the user came from (display only)? Answered by ADR-0015 and scenario 015: the link target is `/_hopae/logout` on the application host itself, and the logout ticket names the application on the confirmation page.
- Logout everywhere (`scope=all`, one `session.terminated` per session, reason `logout_all`) and the invalidation message on termination are specified in ADR-0004/ADR-0006 and are exercised by M2 scenarios in the 100–199 range, not here.

## 한국어 요약

포털에서 CSRF 토큰과 Origin 검사를 거쳐 로그아웃을 확인하면 세션이 종료되어
모든 호스트의 핸들이 무효가 되고, 이후 verify는 거부하면서 남은 쿠키를
지웁니다. 교차 사이트 요청이나 `<img>` 태그로는 로그아웃이 일어나지 않으며,
다른 세션 ID를 지정해도 무시됩니다.
