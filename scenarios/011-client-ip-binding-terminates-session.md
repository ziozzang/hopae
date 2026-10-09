# S011 — Client-IP binding terminates the session on mismatch

<!-- scenario-status: draft -->

- Area: sessions
- Milestone: M1
- ADRs: 0006, 0007, 0009
- Threat model: TM-13, TM-18
- Gateway contract: Verify endpoint (`x-forwarded-for`), Invalidation channel

## Goal

A session created from one client IP is terminated the moment a request
presents its handle from a different IP under the default policy; the policy
is configurable per application (`strict`, `prefix`, `off`; `terminate_session`
or `drop_handle`), the termination is recorded, and a stolen cookie cannot be
used from elsewhere.

## Preconditions and fixtures

- Configuration `tests/fixtures/m1-binding.json`: application `app` with `binding = {ip: strict, ua: off, on_mismatch: terminate_session}`; application `relaxed` (`relaxed.example.test`) with `{ip: prefix, on_mismatch: drop_handle}`; application `open` (`open.example.test`) with `{ip: off}`.
- Session `s_1` created from `203.0.113.9` with `user-agent: UA1`; handles `H0` (portal), `H1` (`app`), `H2` (`relaxed`), `H3` (`open`).

## Main flow

### S011-1 Same IP is allowed

- Given: `H1`.
- When: verify from `203.0.113.9`.
- Then: `200`.

### S011-2 Different IP terminates the whole session

- Given: `H1`.
- When: verify from `198.51.100.7` (document navigation).
- Then: `302` login with cookie clear; `sessions.terminated_reason = binding_ip`; all handles revoked; event `session.terminated` with `reason=binding_ip`, `bound_ip=203.0.113.9`, `observed_ip=198.51.100.7`; a following verify from the original IP with `H1` is also denied.

### S011-3 Prefix mode tolerates the same /24

- Given: `H2` on `relaxed`.
- When: verify from `203.0.113.200`.
- Then: `200`. From `203.0.114.1`: handle `H2` revoked (`drop_handle`), session alive, `H1` still valid from the original IP; event `handle.revoked` with `reason=binding_ip`.

### S011-4 Off mode ignores IP

- Given: `H3` on `open`.
- When: verify from `198.51.100.7`.
- Then: `200`.

## Alternative flows

### S011-5 UA binding when enabled

- Given: application `app` with `ua: strict`.
- When: verify with `user-agent: UA2`.
- Then: terminated with `reason=binding_ua`; events carry digests only, never the UA strings.

### S011-6 Transaction inherits the policy

- Given: transaction started from `203.0.113.9` for `app`.
- When: `GET /login?txn=T1` from `198.51.100.7`.
- Then: `400` expired-link page; `reason=txn_binding` (see 001-A3).

### S011-7 Invalidation is published on termination (M2)

- Given: Redis configured.
- When: S011-2.
- Then: one `session` invalidation message.

## Abuse cases

| Category | Case | Applies |
| --- | --- | --- |
| Replay | S011-A1 | yes |
| Tampering | S011-A2 | yes |
| Race / timing | S011-A3 | yes |
| Resource exhaustion | S011-A4 | yes |
| Confused deputy | — | no |
| Spoofed or duplicated headers | S011-A5 | yes |
| Downgrade | S011-A6 | yes |
| Enumeration | — | no |

### S011-A1 Stolen cookie replayed from the attacker's network

- Given: `H1` exfiltrated.
- When: the attacker's verify from `198.51.100.7` precedes the victim's next request.
- Then: the session is terminated; the victim is sent to log in again; the event shows both IPs; the attacker's request is denied.

### S011-A2 IPv6 and IPv4-mapped forms are normalized

- Given: bound `::ffff:203.0.113.9`.
- When: verify from `203.0.113.9`.
- Then: treated as equal; prefix mode uses `/64` for native IPv6.

### S011-A3 Concurrent requests from two IPs

- Given: `H1`.
- When: a request from the bound IP and one from another IP race.
- Then: the session ends up terminated regardless of order; at most one `200` is observed (the bound-IP request, only if it was decided first).

### S011-A4 Forced-termination denial of service under `drop_handle`

- Given: `relaxed` with `drop_handle`; the attacker holds `H2` and sends from a far IP repeatedly.
- When: 100 attempts.
- Then: `H2` is revoked once; subsequent attempts are unknown-handle denials; the victim's other handles and the portal session are unaffected; the attacker cannot terminate the session. Under `terminate_session` the attacker can log the victim out once per login, which the threat model records as accepted.

### S011-A5 Client-supplied `x-forwarded-for` on a direct call

- Given: direct call to the gateway listener (test harness) with two `x-forwarded-for` headers.
- When: verify.
- Then: `400 contract_violation` (duplicate); with a single header containing a list `203.0.113.9, 10.0.0.1` the first address is used only if `gateway.kind = forward_auth` with a profile that says so; for `hangang` a list is a contract violation (the gateway sends one address).

### S011-A6 Policy cannot be relaxed by the request

- Given: a request header `x-hopae-binding: off`.
- When: verify.
- Then: ignored; the policy comes from configuration only.

## Observability expectations

- Log: `session.terminated` / `handle.revoked` with `reason`, `bound_ip`, `observed_ip`, `app_id`.
- Audit: `events` rows.
- Metrics: `hopae_binding_mismatch_total{signal,action,app}`.

## Test mapping

| Case | Test | File | Kind | Status |
| --- | --- | --- | --- | --- |
| S011-1 | `s011_1_same_ip_allowed` | `tests/scenarios/s011_ip_binding.rs` | integration | planned |
| S011-2 | `s011_2_different_ip_terminates_session` | `tests/scenarios/s011_ip_binding.rs` | integration | planned |
| S011-3 | `s011_3_prefix_mode_and_drop_handle` | `tests/scenarios/s011_ip_binding.rs` | integration | planned |
| S011-4 | `s011_4_off_mode_ignores_ip` | `tests/scenarios/s011_ip_binding.rs` | integration | planned |
| S011-5 | `s011_5_ua_binding_when_enabled` | `tests/scenarios/s011_ip_binding.rs` | integration | planned |
| S011-6 | `s011_6_txn_inherits_policy` | `tests/scenarios/s011_ip_binding.rs` | integration | planned |
| S011-7 | `s011_7_invalidation_published` | `tests/scenarios/s011_ip_binding.rs` | integration | planned (M2) |
| S011-A1 | `s011_a1_stolen_cookie_from_other_network` | `tests/scenarios/s011_ip_binding.rs` | integration | planned |
| S011-A2 | `s011_a2_ip_forms_normalized` | `tests/scenarios/s011_ip_binding.rs` | unit | planned |
| S011-A3 | `s011_a3_concurrent_requests_two_ips` | `tests/scenarios/s011_ip_binding.rs` | integration | planned |
| S011-A4 | `s011_a4_drop_handle_dos_bounded` | `tests/scenarios/s011_ip_binding.rs` | integration | planned |
| S011-A5 | `s011_a5_forwarded_for_list_rejected` | `tests/scenarios/s011_ip_binding.rs` | integration | planned |
| S011-A6 | `s011_a6_policy_not_relaxable_by_request` | `tests/scenarios/s011_ip_binding.rs` | integration | planned |

## Live verification

| Date | Hopae version | Gateway version | Provider | Environment label | Result | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| — | — | — | — | — | — | Live run requires two egress addresses (for example a phone on mobile data). |

## Open questions

- Under `terminate_session`, an attacker with a stolen cookie can log the victim out (S011-A4). Is that acceptable as the default, or should the default be `drop_handle` with re-authentication?

## 한국어 요약

세션은 생성 시의 클라이언트 IP에 묶이며, 기본 정책(`strict`,
`terminate_session`)에서는 다른 IP가 핸들을 제시하는 즉시 세션 전체가
종료되고 사건이 기록됩니다. 애플리케이션마다 `prefix`/`off`와 `drop_handle`로
완화할 수 있고, 요청 헤더로는 정책을 바꿀 수 없습니다. 탈취된 쿠키는 다른
네트워크에서 쓸 수 없습니다.
