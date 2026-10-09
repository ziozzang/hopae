# S001 — Unauthenticated request on a protected host is sent to the portal

<!-- scenario-status: approved -->

- Area: core
- Milestone: M1
- ADRs: 0004, 0005
- Threat model: TM-01, TM-14, TM-20, TM-21
- Gateway contract: Verify endpoint (request headers, `302`/`401`), Portal entry points

## Goal

A browser without a Hopae cookie that requests a protected application is
redirected to the portal with a server-side login transaction that remembers
where to return; no client-supplied value can choose the return target, and
an unauthenticated flood cannot exhaust the store.

## Preconditions and fixtures

- Configuration `tests/fixtures/m1-basic.json`: portal `https://auth.example.test`, application `app` with host `app.example.test`, provider `mock` (kind `oidc`), the `default` application with no host patterns, `gateway.caller_key_env = HOPAE_TEST_GATEWAY_KEY`.
- Every verify request in this scenario carries `x-hopae-gateway-key` with the configured value unless a case says otherwise.
- Mock provider profile `default`.
- Gateway route fragment: the protected whole-host route from the contract page (including `static_request_headers`).
- Injected clock at `2026-10-09T00:00:00Z`; injected randomness so the transaction id is `T1`, the binding cookie value is `B1` and the portal binding cookie value is `P1`.

## Main flow

### S001-1 Document navigation receives a 302 to the portal

- Given: no `__Host-hopae` cookie; no transaction rows.
- When: `GET /_hopae/verify` on the gateway listener with `x-original-url: https://app.example.test/admin/x?q=1`, `x-forwarded-host: app.example.test`, `x-forwarded-proto: https`, `x-forwarded-for: 203.0.113.9`, `sec-fetch-dest: document`, `user-agent: UA1`.
- Then: `302`; `location: https://auth.example.test/login?txn=T1`; `set-cookie: __Host-hopae_bind=B1; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=600` (planted on `app.example.test` through the relayed response); `cache-control: no-store`; `x-hopae-reason: login_required`; one `login_txns` row with `return_target = https://app.example.test/admin/x?q=1`, `app_id = app`, `client_ip = 203.0.113.9`, `ua_sha256 = sha256(UA1)`, `bind_sha256 = sha256(B1)`, `expires_at = now + 600`; event `login.started` written in the same transaction.

### S001-2 Portal renders the chooser for the transaction

- Given: S001-1 completed.
- When: `GET https://auth.example.test/login?txn=T1` through the portal listener from `203.0.113.9` with `user-agent: UA1`.
- Then: `200 text/html` listing the enabled provider; `set-cookie: __Host-hopae_portal=P1; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=600` (an existing well-formed value would be kept and refreshed instead); the transaction row's `portal_bind_sha256` is still empty — it is recorded only when the provider redirect is issued (`POST /login/<provider>` in S002-1, or the auto-redirect of S001-3) and is immutable afterwards (ADR-0004); response security headers present (`cache-control: no-store`, `x-content-type-options: nosniff`, `referrer-policy: no-referrer`, `content-security-policy` without `unsafe-inline` scripts).

### S001-3 Single enabled provider redirects immediately

- Given: exactly one enabled provider.
- When: as S001-2.
- Then: `302` to the provider's authorization endpoint with `state`, `nonce`, `code_challenge`, `code_challenge_method=S256`, `redirect_uri=https://auth.example.test/callback/mock`; the portal binding cookie is set on the same response and its digest is recorded in the transaction at this moment.

## Alternative flows

### S001-4 Non-document request receives 401 JSON

- Given: no cookie.
- When: verify with `sec-fetch-dest: empty`, `sec-fetch-mode: cors`, `accept: application/json`.
- Then: `401`; `content-type: application/json`; body `{"error":"login_required","login":"https://app.example.test/admin/x?q=1"}` — the `login` target is the application URL itself, the document bootstrap that plants the binding cookie; `www-authenticate: Hopae realm="auth.example.test"`; `cache-control: no-store`; **no** `set-cookie`; **no** transaction row is created; a following document navigation to that URL behaves exactly as S001-1.

### S001-5 Missing fetch metadata falls back to `accept`

- Given: no `sec-fetch-*` headers.
- When: verify with `accept: text/html,application/xhtml+xml`.
- Then: `302` as S001-1. With `accept: */*` only: `401` as S001-4.

### S001-6 Host outside every application pattern is denied

- Given: no application lists `unknown.example.test` or a pattern covering it.
- When: verify with `x-forwarded-host: unknown.example.test` and matching `x-original-url`.
- Then: `403`; `x-hopae-reason: unknown_app`; no transaction row; no `set-cookie`; event `verify.denied` with `reason=unknown_app`.

## Abuse cases

| Category | Case | Applies |
| --- | --- | --- |
| Replay | S001-A1 | yes |
| Tampering | S001-A2 | yes |
| Race / timing | S001-A3 | yes |
| Resource exhaustion | S001-A4 | yes |
| Confused deputy | S001-A5 | yes |
| Spoofed or duplicated headers | S001-A6 | yes |
| Downgrade | S001-A7 | yes |
| Enumeration | — | no: the response is identical for every unknown cookie value and reveals no user data |

### S001-A1 Expired or consumed transaction cannot be reopened

- Given: transaction `T1` with `expires_at` in the past, or `consumed_at` set.
- When: `GET /login?txn=T1`.
- Then: `400` generic "sign-in link expired" page; no cookie set; no new transaction; event `login.failed` with `reason=txn_expired` or `txn_consumed`.

### S001-A2 Return target cannot be supplied by the client

- Given: no cookie.
- When: `GET /login?txn=T1&return=https://evil.example.org/` and, separately, `GET /login?rd=https://evil.example.org/` without `txn`.
- Then: unknown query parameters are ignored; without `txn` the portal answers `400` with no redirect; the stored `return_target` of `T1` is unchanged.

### S001-A3 Transaction from one client cannot be continued by another

- Given: `T1` created from `203.0.113.9` with `binding.ip = strict`; separately, `T1` already visited once by a browser whose portal cookie digest is recorded.
- When: `GET /login?txn=T1` from `198.51.100.7`; separately, `GET /login?txn=T1` from the right IP but with a different (or no) `__Host-hopae_portal` cookie.
- Then: `400` expired-link page; `reason=txn_binding` or `portal_bind_mismatch`; no new cookie; the transaction is marked consumed so the original client must restart as well.

### S001-A4 Transaction flood is bounded

- Given: `txn.max_rows = 1000` and `txn.per_ip_per_minute = 30` in the fixture.
- When: 31 document-navigation verify calls without cookies from one IP within a minute, then 2,000 from distinct IPs (non-document `401` calls are not counted because they create nothing).
- Then: the 31st from the same IP answers `403` with body `{"error":"rate_limited","retry_after":60}` and `x-hopae-reason: txn_rate_limited` (an unmodified gateway relays `403` with its body but maps `429` to `503` and drops `retry-after`; with gateway change HC-8 and `gateway.rate_limit_status = 429` the same case answers `429` with `retry-after: 60`); beyond `max_rows` the oldest unconsumed transactions are evicted and `txn.evicted` events carry the count; the process RSS stays under the harness limit; store row count ≤ 1000.

### S001-A5 Gateway listener path on the portal listener is not served

- Given: portal listener.
- When: `GET /_hopae/verify` with full gateway context headers on the portal listener.
- Then: `404`; no transaction row; event `verify.denied` with `reason=wrong_listener` is not emitted (plain 404) but the access log records the path.

### S001-A6 Client-supplied gateway context is ignored on the portal listener

- Given: portal listener, `trusted_proxies = [127.0.0.1/32]`, request from a non-trusted peer.
- When: `GET /login?txn=T1` with `x-forwarded-for: 203.0.113.9` from peer `10.0.0.5`.
- Then: the client IP used for binding is `10.0.0.5`; the request fails S001-A3's binding check; the header value never appears in events.

### S001-A7 Plain HTTP original URL is refused

- Given: `cookie.secure = true` (default).
- When: verify with `x-forwarded-proto: http` and `x-original-url: http://app.example.test/`.
- Then: `400`; `x-hopae-reason: insecure_transport`; no transaction; the gateway maps it to `503`.

## Observability expectations

- Log: `login.started` with `txn_id` (digest prefix), `app_id`, `client_ip`, `navigation`.
- Audit: `events` row `login.started`.
- Metrics: `hopae_verify_decisions_total{decision="login",navigation}`, `hopae_txn_created_total`, `hopae_txn_evicted_total`, `hopae_txn_rate_limited_total`.

## Test mapping

| Case | Test | File | Kind | Status |
| --- | --- | --- | --- | --- |
| S001-1 | `s001_1_document_navigation_redirects_to_portal` | `tests/scenarios/s001_unauthenticated_redirect.rs` | integration | planned |
| S001-2 | `s001_2_portal_renders_chooser_and_sets_txn_cookie` | `tests/scenarios/s001_unauthenticated_redirect.rs` | integration | planned |
| S001-3 | `s001_3_single_provider_redirects_immediately` | `tests/scenarios/s001_unauthenticated_redirect.rs` | integration | planned |
| S001-4 | `s001_4_non_document_request_gets_401_json` | `tests/scenarios/s001_unauthenticated_redirect.rs` | integration | planned |
| S001-5 | `s001_5_accept_header_fallback` | `tests/scenarios/s001_unauthenticated_redirect.rs` | unit | planned |
| S001-6 | `s001_6_unregistered_host_denied` | `tests/scenarios/s001_unauthenticated_redirect.rs` | integration | planned |
| S001-A1 | `s001_a1_expired_or_consumed_txn_rejected` | `tests/scenarios/s001_unauthenticated_redirect.rs` | integration | planned |
| S001-A2 | `s001_a2_client_return_target_ignored` | `tests/scenarios/s001_unauthenticated_redirect.rs` | integration | planned |
| S001-A3 | `s001_a3_txn_bound_to_client` | `tests/scenarios/s001_unauthenticated_redirect.rs` | integration | planned |
| S001-A4 | `s001_a4_txn_flood_bounded` | `tests/scenarios/s001_unauthenticated_redirect.rs` | integration | planned |
| S001-A5 | `s001_a5_verify_not_served_on_portal_listener` | `tests/scenarios/s001_unauthenticated_redirect.rs` | integration | planned |
| S001-A6 | `s001_a6_untrusted_forwarded_for_ignored` | `tests/scenarios/s001_unauthenticated_redirect.rs` | integration | planned |
| S001-A7 | `s001_a7_plain_http_refused` | `tests/scenarios/s001_unauthenticated_redirect.rs` | integration | planned |

## Live verification

| Date | Hopae version | Gateway version | Provider | Environment label | Result | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| — | — | — | — | — | — | Not yet run. |

## Open questions

- Is `txn.per_ip_per_minute = 30` a reasonable default behind corporate NAT?

## 한국어 요약

쿠키 없는 브라우저가 보호된 호스트를 문서 탐색으로 요청하면 verify가 서버 측
로그인 트랜잭션을 만들고 바인딩 쿠키를 심은 뒤 포털로 `302`를 보냅니다. 문서가
아닌 요청은 `401`과 함께 애플리케이션 URL 자체를 돌려주며 아무것도 만들지
않습니다. 돌아갈 URL은 게이트웨이가 만든 `x-original-url`에서만 가져오며
클라이언트 값은 무시합니다. 핵심 남용 사례는 트랜잭션 홍수 제한과 다른
클라이언트가 트랜잭션을 이어받지 못하게 하는 바인딩입니다.
