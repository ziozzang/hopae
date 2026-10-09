# S004 — Verify returns identity headers for a valid session and fails closed otherwise

<!-- scenario-status: draft -->

- Area: core
- Milestone: M1
- ADRs: 0002, 0003, 0005, 0006, 0008, 0013
- Threat model: TM-07, TM-12, TM-14, TM-18, TM-19, TM-24, TM-29, TM-35, TM-38
- Gateway contract: Verify endpoint, Identity headers, Cache semantics, Versioning

## Goal

The gateway's verify call for a request carrying a valid handle answers
`200` with the complete, bounded identity header set in well under a
millisecond of Hopae work, and every failure of a dependency or of the
contract answers a status the gateway treats as denial.

## Preconditions and fixtures

- Configuration `tests/fixtures/m1-basic.json`; `apps.app.verify_cache_seconds = 0` (default); `gateway.caller_key_env = HOPAE_TEST_GATEWAY_KEY`; `gateway.verify_budget_ms = 400`.
- Every verify request carries `x-hopae-gateway-key` with the configured value unless a case says otherwise.
- User `u_1` (`primary_email = a@example.test`, `username = alice`, display name `Alice 김`, `status = active`, `authz_version = 3`); session `s_1` with `aal=1`, `factors=[{"kind":"oidc","provider":"mock","at":t0}]`, `authz_version = 3`, `cred_gen = 2`; configuration generation `5`; handle `H1` for `app.example.test` with `issued_aal = 1`, `created_at = t0`, `last_seen_at = t0`.
- Injected clock `now = t0 + 60 s`.

## Main flow

### S004-1 Valid handle yields the identity header set

- Given: as above.
- When: `GET /_hopae/verify` with `cookie: __Host-hopae=H1`, `x-original-url: https://app.example.test/admin/x`, `x-forwarded-host: app.example.test`, `x-forwarded-proto: https`, `x-forwarded-for: 203.0.113.9`, `user-agent: UA1`.
- Then: `200`; headers `x-forwarded-user: u_1`, `x-forwarded-email: a@example.test`, `x-forwarded-preferred-username: alice`, `x-hopae-session: s_1`, `x-hopae-provider: mock`, `x-hopae-auth-time: <t0>`, `x-hopae-expires: <t0+12h>` (the handle's idle deadline, the earliest timer), `x-hopae-aal: 1`, `x-hopae-factors: oidc:mock`, `x-hopae-contract: 1`, `x-hopae-gen: s2.u3.c5`, `x-hopae-reason: ok`, `cache-control: no-store` (no `x-hopae-fresh-until` because `N = 0`); no `set-cookie`; `x-forwarded-groups` absent; total identity header bytes ≤ 8 KiB; the store recorded one handle/session read and one `users(status, authz_version)` read.

### S004-2 Non-ASCII values are percent-encoded

- Given: `username` is null so the display name `Alice 김` is used.
- When: verify.
- Then: `x-forwarded-preferred-username: Alice%20%EA%B9%80`; header value is visible ASCII only.

### S004-3 Other cookies are ignored

- Given: `cookie: a=b; __Host-hopae=H1; c=d`.
- When: verify.
- Then: `200` as S004-1; the values `a=b` and `c=d` never appear in logs or events.

### S004-4 Decision is computed from core types without HTTP

- Given: a `VerifyInput` constructed directly.
- When: the decision function runs with an in-memory store.
- Then: `Decision::Allow` with the same `Identity`; `Decision::Login` for an unknown handle; this case pins the adapter boundary (ADR-0013).

## Alternative flows

### S004-5 Store unavailable fails closed

- Given: the store connection is closed by the harness (SQLite file made unreadable, or the writer task stopped).
- When: verify with `H1`.
- Then: `503`; `retry-after: 1`; `x-hopae-reason: store_unavailable`; no identity headers; event `verify.denied` (sampled); metric `hopae_store_errors_total` incremented.

### S004-6 Contract violation fails closed

- Given: a verify request without `x-original-url`, and separately with `x-hopae-contract: 2`.
- When: verify.
- Then: `400`; `x-hopae-reason: contract_violation` naming `x-original-url`, or `contract_unsupported`; no store access for the first.

### S004-7 Host mismatch between context headers is rejected

- Given: `x-forwarded-host: other.example.org`, `x-original-url: https://app.example.test/`.
- When: verify.
- Then: `400 contract_violation`; no session lookup.

### S004-8 Cacheability is declared only when configured and safe

- Given: `apps.app.verify_cache_seconds = 5` and no `step_up` rule.
- When: verify with `H1`.
- Then: `cache-control: private, max-age=5`, `x-hopae-fresh-until: <authoritative read time + 5 s>` in unix milliseconds and `x-hopae-gen: s2.u3.c5`; with the handle 2 s from its idle deadline the deadline is `read time + 2 s`. With `cache.local_ttl_ms = 3000` a second verify within 3 s is served from the local cache with the **same** `x-hopae-fresh-until` (not renewed) and the same `x-hopae-gen`; after a `session` invalidation with `gen=3` the local entry is discarded and the next verify reads the store. With a `step_up` rule for `/admin` configured: `cache-control: no-store` and no deadline. With `verify_cache_seconds = 60`: preflight rejects the configuration (`> 30`). A request matching the reserved parameter recognition rule always answers `no-store`.

### S004-9 A stalled dependency stays within the verify budget and never serves stale state

- Given: (M2) Redis configured with `cache.op_timeout_ms = 50`, and the harness replaces it with a listener that accepts connections and never answers; (M1) alternatively the primary store is stalled by the harness.
- When: verify with `H1`, repeated five times; then (M2) a login attempt that needs a throttling counter; then (M2) a session termination whose invalidation must be published.
- Then (stalled Redis): every verify answers `200` from the primary store without waiting on Redis at all (verify never reads Redis); the login attempt is refused after one 50 ms counter timeout (`403 rate_limited` with `reason=counter_unavailable`, fail closed) and after three timeouts the breaker refuses for 5 s without waiting; the termination's publish times out, is logged `invalidation_publish_failed` and counted, and the terminated session is still denied on the next verify because the store is authoritative. Then (stalled store): `503` with `x-hopae-reason: budget_exceeded` within 400 ms, never later; the gateway's 500 ms timeout is not reached. A harness that answers Redis requests with a stale, previously valid session payload has no effect because no such lookup exists (asserted by the Redis stub's request log containing no `GET`/`HGET` on session keys).

### S004-10 An authorization change is seen on the next verify

- Given: `u_1` has `groups = ["admin"]` in the session snapshot; an administrator removes the group (`users.authz_version` becomes 4, a `user` invalidation is published in M2).
- When: verify with `H1`.
- Then: with the default `apps.app.on_authz_change = refresh`, `200` without `x-forwarded-groups` and the session snapshot now carries `authz_version = 4`; with `terminate`, `302` login with cookie clear and `session.terminated` with `reason=authz_change`. With `users.status = disabled` instead: `302`/`401` with `reason=user_disabled` and the session terminated. In every case the change is visible on the very next verify, not after a timer.

### S004-11 No non-allow path answers 2xx on the gateway listener

- Given: fixtures that drive every non-allow outcome: no cookie (document and non-document), unknown handle, terminated session, expired handle, binding mismatch, disabled user, unknown host, caller key missing, contract violation, stalled store, overload, non-document request with the reserved parameter, ambiguous parameter, every handoff failure reason, recovery exhaustion, `session_conflict`, a step-up rule unmet (schema-level), rate limit.
- When: each is sent to `GET /_hopae/verify`.
- Then: every response status is in `{302, 401, 403, 400, 503}`; none is `2xx`; none carries `x-hangang-auth-terminal`; the only `200` in the whole table is the authenticated allow of S004-1, which carries the identity headers. A unit test additionally walks every `Decision` variant through the adapter's `render` and asserts that only `Decision::Allow` yields a `2xx`.

## Abuse cases

| Category | Case | Applies |
| --- | --- | --- |
| Replay | — | no: a valid handle is meant to be presented repeatedly; replay from another context is scenario 011 |
| Tampering | S004-A1 | yes |
| Race / timing | S004-A2 | yes |
| Resource exhaustion | S004-A3 | yes |
| Confused deputy | S004-A4 | yes |
| Spoofed or duplicated headers | S004-A5, S004-A8 | yes |
| Downgrade | S004-A6 | yes |
| Enumeration | S004-A7 | yes |

### S004-A1 Malformed or oversized handle is rejected before hashing

- Given: cookie values `v1.` + 10 chars, `v9.` + 43 chars, 9 KiB of cookie header.
- When: verify.
- Then: `302` login (unknown handle) for the first two without a store query (unit-observable via the store call counter); `400 header_too_large` for the 9 KiB cookie header; no event per request beyond sampled `verify.denied`.

### S004-A2 Last-seen writes are coalesced and never block the decision

- Given: 1,000 verify calls for `H1` within 10 s with the writer task slowed by 500 ms per write.
- When: run.
- Then: at most one `last_seen_at` write; p99 verify latency under 20 ms in the harness; all `200`.

### S004-A3 Concurrency limit fails closed and recovers

- Given: `listen.gateway.max_concurrent = 64`; the store is slowed to 200 ms per read.
- When: 200 concurrent verify calls.
- Then: at most 64 in flight; the rest answer `503 overloaded` immediately with `retry-after`; after the store recovers, calls answer `200`; metric `hopae_verify_overloaded_total`.

### S004-A4 Handle from one host is not accepted on another

- Given: `H1` bound to `app.example.test`.
- When: verify with `cookie: __Host-hopae=H1` and `x-forwarded-host: other.example.org` (matching URL).
- Then: `302` login for `other.example.org`; `reason=handle_host_mismatch`; the session is not terminated.

### S004-A5 Duplicate context headers are rejected

- Given: two `x-forwarded-host` headers with different values.
- When: verify.
- Then: `400 contract_violation`; no session lookup. (The gateway itself replaces generated headers; this case protects other adapters and direct misuse.)

### S004-A6 Downgraded proto is refused

- Given: valid `H1`, `x-forwarded-proto: http`.
- When: verify.
- Then: `400 insecure_transport` with the default `cookie.secure = true`.

### S004-A7 Unknown handles are indistinguishable from expired ones

- Given: a random handle and a terminated session's handle.
- When: verify for each.
- Then: identical responses except the transaction id and binding cookie value; reasons differ only in the sampled event.

### S004-A8 Missing or wrong caller key is refused before any state is touched

- Given: valid `H1`; `gateway.allow_unauthenticated_caller` unset; `gateway.caller_key_next_env` unset.
- When: verify without `x-hopae-gateway-key`, then with a wrong value, then with the right value but also a second copy of the header.
- Then: `403` with `x-hopae-reason: caller_unauthorized` for all three; no store read (store call counter stays at zero); no transaction; no binding cookie; metric `hopae_verify_unauthorized_total = 3`; the comparison is constant-time (unit test on the compare function with equal-length inputs). With `gateway.allow_unauthenticated_caller = true` the first request is processed as S004-1 and preflight had printed the warning. With `gateway.caller_key_next_env` set to a second variable, a verify presenting either the current or the next value is processed as S004-1 and a verify presenting a third value is refused; the metric labels the accepted key (`current`, `next`) so the operator can see when the gateway has switched.

## Observability expectations

- Log: one line per denial reason change; allowed decisions are not logged individually (metrics only) unless `log.verify_allow = true`.
- Audit: sampled `verify.denied` rows.
- Metrics: `hopae_verify_decisions_total{decision,reason}`, `hopae_verify_seconds` histogram, `hopae_store_errors_total`, `hopae_verify_overloaded_total`.

## Test mapping

| Case | Test | File | Kind | Status |
| --- | --- | --- | --- | --- |
| S004-1 | `s004_1_valid_handle_yields_identity_headers` | `tests/scenarios/s004_verify.rs` | integration | planned |
| S004-2 | `s004_2_non_ascii_percent_encoded` | `tests/scenarios/s004_verify.rs` | unit | planned |
| S004-3 | `s004_3_other_cookies_ignored` | `tests/scenarios/s004_verify.rs` | integration | planned |
| S004-4 | `s004_4_core_decision_without_http` | `tests/scenarios/s004_verify.rs` | unit | planned |
| S004-5 | `s004_5_store_unavailable_fails_closed` | `tests/scenarios/s004_verify.rs` | integration | planned |
| S004-6 | `s004_6_contract_violation_fails_closed` | `tests/scenarios/s004_verify.rs` | integration | planned |
| S004-7 | `s004_7_host_mismatch_rejected` | `tests/scenarios/s004_verify.rs` | integration | planned |
| S004-8 | `s004_8_cacheability_declared_safely` | `tests/scenarios/s004_verify.rs` | integration | planned |
| S004-9 | `s004_9_stalled_dependency_within_budget` | `tests/scenarios/s004_verify.rs` | integration | planned |
| S004-10 | `s004_10_authz_change_seen_on_next_verify` | `tests/scenarios/s004_verify.rs` | integration | planned |
| S004-11 | `s004_11_no_non_allow_path_is_2xx` | `tests/scenarios/s004_verify.rs` | integration | planned |
| S004-A1 | `s004_a1_malformed_handle_rejected_early` | `tests/scenarios/s004_verify.rs` | integration | planned |
| S004-A2 | `s004_a2_last_seen_coalesced` | `tests/scenarios/s004_verify.rs` | integration | planned |
| S004-A3 | `s004_a3_concurrency_limit_fails_closed` | `tests/scenarios/s004_verify.rs` | integration | planned |
| S004-A4 | `s004_a4_handle_not_valid_on_other_host` | `tests/scenarios/s004_verify.rs` | integration | planned |
| S004-A5 | `s004_a5_duplicate_context_headers_rejected` | `tests/scenarios/s004_verify.rs` | integration | planned |
| S004-A6 | `s004_a6_downgraded_proto_refused` | `tests/scenarios/s004_verify.rs` | integration | planned |
| S004-A7 | `s004_a7_unknown_and_expired_uniform` | `tests/scenarios/s004_verify.rs` | integration | planned |
| S004-A8 | `s004_a8_caller_key_required` | `tests/scenarios/s004_verify.rs` | integration | planned |

## Live verification

| Date | Hopae version | Gateway version | Provider | Environment label | Result | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| — | — | — | — | — | — | Not yet run. |

## Open questions

- Should `x-hopae-session` be emitted to upstreams at all (threat model residual risk)?
- Is `max_concurrent = 64` per listener a sane default for a single-core container?

## 한국어 요약

호출자 키가 맞는 verify 요청에 유효한 핸들이 있으면 `200`과 함께 완전한 신원
헤더 집합을 돌려주고, 사용자 상태와 권한 버전은 매번 읽어 변경이 다음 요청에
바로 반영됩니다. 호출자 키 누락, 저장소 장애, 계약 위반, 과부하, 프로토콜
다운그레이드는 모두 게이트웨이가 거부로 처리하는 상태 코드로 답하며, 멈춘
캐시 의존성은 50 ms 타임아웃과 400 ms 예산 안에서 처리됩니다.
