# S009 — Cookie attributes and host scope

<!-- scenario-status: approved -->

- Area: security
- Milestone: M1
- ADRs: 0004
- Threat model: TM-02, TM-04, TM-13, TM-31
- Gateway contract: Cookies

## Goal

Every cookie Hopae sets carries the documented attributes, is host-only, is
never readable by scripts, and a cookie set by a sibling host or by the
client cannot be adopted as a session.

## Preconditions and fixtures

- Configuration `tests/fixtures/m1-two-domains.json`; a variant `tests/fixtures/m1-dev-insecure.json` with `cookie.secure = false`.
- Session `s_1`; handoff code `K1` for `app.example.test`.
- A cookie-jar client in the harness that implements `__Host-` prefix rules and `SameSite`.

## Main flow

### S009-1 Session cookie attributes

- Given: valid `K1`.
- When: redemption through verify.
- Then: `set-cookie` parses to name `__Host-hopae`, value `v1.` + 43 base64url characters, `Path=/`, `Secure`, `HttpOnly`, `SameSite=Lax`, `Max-Age` equal to the **handle's** remaining absolute lifetime (`apps[].session.absolute`, 7 d by default, counted from the handle's creation, never the session's 30 d), no `Domain`, no `Expires`.

### S009-2 Portal binding cookie attributes

- Given: a transaction; the browser has never visited the portal.
- When: `GET /login?txn=T1`, then again 10 minutes later with the cookie still present.
- Then: `__Host-hopae_portal` with `Path=/`, `Secure`, `HttpOnly`, `SameSite=Lax`, `Max-Age=600`, no `Domain`, value of 22 base64url characters; the second response re-sends the **same** value with a fresh `Max-Age` (stable per browser); a malformed value is replaced.

### S009-3 Clearing uses matching attributes

- Given: a terminated session.
- When: verify with the stale handle (document navigation) and `POST /logout`.
- Then: `set-cookie: __Host-hopae=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0`; the cookie-jar client removes the cookie.

### S009-4 Cookie jar isolation across hosts

- Given: handles planted on `auth.example.test`, `app.example.test`, `other.example.org`.
- When: the jar prepares requests for each host.
- Then: each request carries exactly its own host's cookie; `app.example.test` requests never include the portal's cookie.

## Alternative flows

### S009-5 Development mode drops the prefix

- Given: `cookie.secure = false`.
- When: redemption on `http://app.example.test/`.
- Then: cookie name `hopae`, no `Secure`, other attributes unchanged; preflight output contains `insecure cookie mode`; the `events` row carries `insecure_mode=true`.

### S009-6 Custom cookie name

- Given: `cookie.name = __Host-corp_sso`.
- When: redemption.
- Then: that name is used for the handle and `__Host-corp_sso_bind` / `__Host-corp_sso_txn` for the others; preflight rejects names without the `__Host-` prefix when `cookie.secure = true`.

### S009-7 Binding cookie attributes

- Given: no cookie on `app.example.test`.
- When: the unauthenticated document navigation of scenario 001, a second unauthenticated navigation with the cookie present, then the redemption of scenario 003, then an unauthenticated navigation after a failed redemption.
- Then: the first `302` to the portal sets `__Host-hopae_bind` with `Path=/`, `Secure`, `HttpOnly`, `SameSite=Lax`, `Max-Age=600`, no `Domain`, value of 22 base64url characters; the second re-sends the same value with a fresh `Max-Age`; the redemption response carries no `set-cookie` for it; the post-failure `302` keeps it; a `401` for a non-document request sets no binding cookie; a malformed value (wrong length or alphabet) is replaced.

## Abuse cases

| Category | Case | Applies |
| --- | --- | --- |
| Replay | — | no: covered by 004/011 |
| Tampering | S009-A1 | yes |
| Race / timing | — | no |
| Resource exhaustion | S009-A2 | yes |
| Confused deputy | S009-A3 | yes |
| Spoofed or duplicated headers | S009-A4 | yes |
| Downgrade | S009-A5 | yes |
| Enumeration | — | no |

### S009-A1 Client-chosen cookie value is never adopted (fixation)

- Given: the client sets `__Host-hopae=v1.<attacker chosen 43 chars>` before login.
- When: the full login and handoff flow runs.
- Then: the planted handle differs from the attacker's value; verify with the attacker's value answers the unknown-handle path; no row ever matches a client-chosen value.

### S009-A2 Many cookies with the Hopae name

- Given: `cookie: __Host-hopae=A; __Host-hopae=B; … (200 pairs)`.
- When: verify.
- Then: Hopae evaluates the first well-formed pair only, then stops parsing; `400 header_too_large` beyond 8 KiB; bounded CPU.

### S009-A3 Sibling subdomain cookie tossing

- Given: the cookie-jar client receives from `evil.example.test` a `set-cookie: __Host-hopae=X; Domain=example.test; Path=/; Secure` and a `set-cookie: hopae=X; Domain=example.test; Path=/; Secure`.
- When: the jar prepares a request to `app.example.test`.
- Then: the `__Host-` cookie with `Domain` is rejected by the jar (never stored); the `hopae` cookie is sent but Hopae reads only `__Host-hopae` in secure mode, so it is ignored. In development mode the `hopae` name is read, which the documentation marks as the accepted development-only risk.

### S009-A4 Cookie attributes cannot be weakened by the gateway relay

- Given: the gateway layer.
- When: the `set-cookie` passes through the relayed `302`.
- Then: the client receives the attributes byte for byte (the gateway appends `set-cookie` unchanged).

### S009-A5 `SameSite` cannot be weakened or tightened by configuration

- Given: configuration containing `cookie.same_site = none` and, separately, `cookie.same_site = strict`.
- When: `hopae --check`.
- Then: both rejected as an unknown key (`cookie.same_site` does not exist); every cookie Hopae sets (`__Host-hopae`, `__Host-hopae_bind`, `__Host-hopae_portal`) carries `SameSite=Lax`, which the cross-site portal → application navigation and the provider callback require.

## Observability expectations

- Log: preflight warnings for insecure mode.
- Audit: none.
- Metrics: none.

## Test mapping

| Case | Test | File | Kind | Status |
| --- | --- | --- | --- | --- |
| S009-1 | `s009_1_session_cookie_attributes` | `tests/scenarios/s009_cookies.rs` | integration | planned |
| S009-2 | `s009_2_portal_binding_cookie_attributes` | `tests/scenarios/s009_cookies.rs` | integration | planned |
| S009-3 | `s009_3_clearing_matches_attributes` | `tests/scenarios/s009_cookies.rs` | integration | planned |
| S009-4 | `s009_4_jar_isolation_across_hosts` | `tests/scenarios/s009_cookies.rs` | integration | planned |
| S009-5 | `s009_5_dev_mode_drops_prefix` | `tests/scenarios/s009_cookies.rs` | integration | planned |
| S009-6 | `s009_6_custom_cookie_name` | `tests/scenarios/s009_cookies.rs` | integration | planned |
| S009-7 | `s009_7_binding_cookie_attributes` | `tests/scenarios/s009_cookies.rs` | integration | planned |
| S009-A1 | `s009_a1_client_value_never_adopted` | `tests/scenarios/s009_cookies.rs` | integration | planned |
| S009-A2 | `s009_a2_many_cookies_bounded` | `tests/scenarios/s009_cookies.rs` | integration | planned |
| S009-A3 | `s009_a3_sibling_cookie_tossing_ineffective` | `tests/scenarios/s009_cookies.rs` | integration | planned |
| S009-A4 | `s009_a4_attributes_survive_gateway_relay` | `tests/scenarios/s009_cookies.rs` | gateway | planned |
| S009-A5 | `s009_a5_samesite_not_configurable` | `tests/scenarios/s009_cookies.rs` | unit | planned |

## Live verification

| Date | Hopae version | Gateway version | Provider | Environment label | Result | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| — | — | — | — | — | — | Not yet run. |

## Open questions

- None open; `Strict` was removed after review finding R16.

## 한국어 요약

Hopae가 설정하는 모든 쿠키는 `__Host-` 접두사, `Path=/`, `Secure`, `HttpOnly`,
`SameSite=Lax`를 갖고 `Domain`이 없어 호스트 전용입니다. 클라이언트가 고른
값이나 형제 서브도메인이 던진 쿠키는 세션으로 채택되지 않습니다. 개발 모드는
접두사를 떼며 그 위험을 문서화합니다.
