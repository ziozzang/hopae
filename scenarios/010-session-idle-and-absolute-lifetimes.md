# S010 — Session idle and absolute lifetimes

<!-- scenario-status: draft -->

- Area: sessions
- Milestone: M1
- ADRs: 0002, 0004, 0007
- Threat model: TM-13
- Gateway contract: Identity headers (`x-hopae-expires`), Cookies (`Max-Age`)

## Goal

A session ends when it is idle for the application's idle lifetime or when
its absolute lifetime passes, regardless of activity; expiry is enforced at
verify with an injected clock, `x-hopae-expires` tells the application when,
and a stale cookie cannot extend or revive a session.

## Preconditions and fixtures

- Configuration `tests/fixtures/m1-basic.json` with `apps.app.session = {idle: "12h", absolute: "7d"}` and the `default` application `{idle: "1h", absolute: "1d"}`.
- Session `s_1` created at `t0` with handle `H1`; injected clock.

## Main flow

### S010-1 Active session stays alive and reports expiry

- Given: `now = t0 + 11h`.
- When: verify with `H1`.
- Then: `200`; `x-hopae-expires = t0 + 11h + 12h` capped at `t0 + 7d`, so `t0 + 23h`; `last_seen_at` updated (coalesced).

### S010-2 Idle expiry

- Given: last seen at `t0 + 1h`; `now = t0 + 13h + 1s`.
- When: verify.
- Then: `302` login (or `401`); `set-cookie` clear; session `terminated_reason = idle`; event `session.terminated` with `reason=idle`.

### S010-3 Absolute expiry despite activity

- Given: verify every hour from `t0`; `now = t0 + 7d + 1s`.
- When: verify.
- Then: denied; `terminated_reason = absolute`; the preceding verify at `t0 + 7d − 30m` returned `x-hopae-expires = t0 + 7d`.

### S010-4 Portal session uses the strictest handed-off policy

- Given: `s_1` handed off to `app` (12h/7d) and `other` (`default`: 1h/1d).
- When: verify on the portal handle at `t0 + 2h` after no activity since `t0`.
- Then: the portal handle is denied (`idle` by the 1h policy); the `app` handle at the same instant is still allowed (its own 12h policy applies to its host); the session itself is terminated only when every handle's policy has expired or the absolute cap (`min` of the handed-off absolutes, 1d) passes.

## Alternative flows

### S010-5 Cookie `Max-Age` mirrors absolute lifetime

- Given: handoff at `t0 + 1h`.
- When: cookie planted.
- Then: `Max-Age = 7d − 1h` in seconds.

### S010-6 Expiry sweep prunes terminated rows

- Given: 1,000 expired sessions.
- When: the hourly sweep runs (triggered by the harness).
- Then: rows older than `sessions.retention_days` (default 30) are deleted; handles cascade; events remain.

## Abuse cases

| Category | Case | Applies |
| --- | --- | --- |
| Replay | S010-A1 | yes |
| Tampering | S010-A2 | yes |
| Race / timing | S010-A3 | yes |
| Resource exhaustion | S010-A4 | yes |
| Confused deputy | — | no |
| Spoofed or duplicated headers | — | no: covered by 004 |
| Downgrade | — | no |
| Enumeration | — | no: covered by 004-A7 |

### S010-A1 Expired handle cannot be revived by a later handoff code

- Given: `s_1` terminated by `idle`; a handoff code created before termination.
- When: redemption.
- Then: rejected (`code_session_terminated`); no handle; the code is burned.

### S010-A2 Client cannot extend lifetimes

- Given: a client sends `cookie: __Host-hopae=H1; Max-Age=999999` or a crafted `x-hopae-expires` header.
- When: verify.
- Then: attributes in `cookie` are ignored by the parser; the request header is stripped by the gateway and, if present on a direct call, ignored; expiry unchanged.

### S010-A3 Clock skew tolerance

- Given: the store's `created_at` is 61 s in the future relative to `now` (skew).
- When: verify.
- Then: denied with `reason=clock_skew`; at 59 s it is allowed; preflight reports NTP status when available.

### S010-A4 Keep-alive flooding does not grow the store

- Given: 100,000 verify calls on `H1` within the coalescing window.
- When: run.
- Then: one `last_seen_at` write; no row growth; no event per call.

## Observability expectations

- Log: `session.terminated` with `reason` in `idle`, `absolute`; sweep summary.
- Audit: `events` rows.
- Metrics: `hopae_session_terminated_total{reason}`, `hopae_sessions_active` gauge.

## Test mapping

| Case | Test | File | Kind | Status |
| --- | --- | --- | --- | --- |
| S010-1 | `s010_1_active_session_reports_expiry` | `tests/scenarios/s010_lifetimes.rs` | integration | planned |
| S010-2 | `s010_2_idle_expiry` | `tests/scenarios/s010_lifetimes.rs` | integration | planned |
| S010-3 | `s010_3_absolute_expiry_despite_activity` | `tests/scenarios/s010_lifetimes.rs` | integration | planned |
| S010-4 | `s010_4_portal_uses_strictest_policy` | `tests/scenarios/s010_lifetimes.rs` | integration | planned |
| S010-5 | `s010_5_cookie_max_age_mirrors_absolute` | `tests/scenarios/s010_lifetimes.rs` | integration | planned |
| S010-6 | `s010_6_sweep_prunes_terminated_rows` | `tests/scenarios/s010_lifetimes.rs` | integration | planned |
| S010-A1 | `s010_a1_expired_session_not_revived_by_code` | `tests/scenarios/s010_lifetimes.rs` | integration | planned |
| S010-A2 | `s010_a2_client_cannot_extend_lifetime` | `tests/scenarios/s010_lifetimes.rs` | integration | planned |
| S010-A3 | `s010_a3_clock_skew_tolerance` | `tests/scenarios/s010_lifetimes.rs` | unit | planned |
| S010-A4 | `s010_a4_keepalive_flood_no_growth` | `tests/scenarios/s010_lifetimes.rs` | integration | planned |

## Live verification

| Date | Hopae version | Gateway version | Provider | Environment label | Result | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| — | — | — | — | — | — | Lifetimes are verified with the injected clock; live runs confirm `x-hopae-expires` only. |

## Open questions

- S010-4 defines per-handle idle evaluation and a session-level absolute cap; is per-handle idle the intended semantics, or should one idle timer cover the whole session?

## 한국어 요약

세션은 애플리케이션별 유휴 수명과 절대 수명으로 끝나며, 활동이 있어도 절대
수명은 연장되지 않습니다. 만료는 verify에서 주입된 시계로 검사하고
`x-hopae-expires`로 애플리케이션에 알립니다. 만료된 세션은 이전에 만든
핸드오프 코드로도 되살릴 수 없고, 클라이언트는 수명을 늘릴 수 없습니다.
