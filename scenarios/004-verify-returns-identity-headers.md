# S004 — Verify returns identity headers for a valid session and fails closed otherwise

<!-- scenario-status: draft -->

- Area: core
- Milestone: M1
- ADRs: 0002, 0003, 0005, 0006, 0008, 0013
- Threat model: TM-07, TM-12, TM-14, TM-18, TM-19
- Gateway contract: Verify endpoint, Identity headers, Cache semantics, Versioning

## Goal

The gateway's verify call for a request carrying a valid handle answers
`200` with the complete, bounded identity header set in well under a
millisecond of Hopae work, and every failure of a dependency or of the
contract answers a status the gateway treats as denial.

## Preconditions and fixtures

- Configuration `tests/fixtures/m1-basic.json`; `apps.app.verify_cache_seconds = 0` (default).
- Session `s_1` for user `u_1` (`primary_email = a@example.test`, `username = alice`, display name `Alice 김`), `aal=1`, `factors=[{"kind":"oidc","provider":"mock","at":t0}]`, `absolute_expires_at = t0 + 7d`, `idle_expires_at = t0 + 12h`; handle `H1` for `app.example.test`.
- Injected clock `now = t0 + 60 s`.

## Main flow

### S004-1 Valid handle yields the identity header set

- Given: as above.
- When: `GET /_hopae/verify` with `cookie: __Host-hopae=H1`, `x-original-url: https://app.example.test/admin/x`, `x-forwarded-host: app.example.test`, `x-forwarded-proto: https`, `x-forwarded-for: 203.0.113.9`, `user-agent: UA1`.
- Then: `200`; headers `x-forwarded-user: u_1`, `x-forwarded-email: a@example.test`, `x-forwarded-preferred-username: alice`, `x-hopae-session: s_1`, `x-hopae-provider: mock`, `x-hopae-auth-time: <t0>`, `x-hopae-expires: <t0+12h>`, `x-hopae-aal: 1`, `x-hopae-factors: oidc:mock`, `x-hopae-contract: 1`, `x-hopae-reason: ok`, `cache-control: no-store`; no `set-cookie`; `x-forwarded-groups` absent; total identity header bytes ≤ 8 KiB.

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
- Then: `cache-control: private, max-age=5`. With a `step_up` rule for `/admin` configured: `cache-control: no-store`. With `verify_cache_seconds = 60`: preflight rejects the configuration (`> 30`).

## Abuse cases

| Category | Case | Applies |
| --- | --- | --- |
| Replay | — | no: a valid handle is meant to be presented repeatedly; replay from another context is scenario 011 |
| Tampering | S004-A1 | yes |
| Race / timing | S004-A2 | yes |
| Resource exhaustion | S004-A3 | yes |
| Confused deputy | S004-A4 | yes |
| Spoofed or duplicated headers | S004-A5 | yes |
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
- Then: identical responses except the transaction id; reasons differ only in the sampled event.

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
| S004-A1 | `s004_a1_malformed_handle_rejected_early` | `tests/scenarios/s004_verify.rs` | integration | planned |
| S004-A2 | `s004_a2_last_seen_coalesced` | `tests/scenarios/s004_verify.rs` | integration | planned |
| S004-A3 | `s004_a3_concurrency_limit_fails_closed` | `tests/scenarios/s004_verify.rs` | integration | planned |
| S004-A4 | `s004_a4_handle_not_valid_on_other_host` | `tests/scenarios/s004_verify.rs` | integration | planned |
| S004-A5 | `s004_a5_duplicate_context_headers_rejected` | `tests/scenarios/s004_verify.rs` | integration | planned |
| S004-A6 | `s004_a6_downgraded_proto_refused` | `tests/scenarios/s004_verify.rs` | integration | planned |
| S004-A7 | `s004_a7_unknown_and_expired_uniform` | `tests/scenarios/s004_verify.rs` | integration | planned |

## Live verification

| Date | Hopae version | Gateway version | Provider | Environment label | Result | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| — | — | — | — | — | — | Not yet run. |

## Open questions

- Should `x-hopae-session` be emitted to upstreams at all (threat model residual risk)?
- Is `max_concurrent = 64` per listener a sane default for a single-core container?

## 한국어 요약

유효한 핸들로 verify를 호출하면 `200`과 함께 완전한 신원 헤더 집합을 돌려주고,
저장소 장애·계약 위반·과부하·프로토콜 다운그레이드는 모두 게이트웨이가 거부로
처리하는 상태 코드로 답합니다. 핸들은 호스트에 묶여 있어 다른 호스트에서는
쓸 수 없고, 알 수 없는 핸들과 만료된 핸들은 응답으로 구분되지 않습니다.
