# S010 — Session idle and absolute lifetimes

<!-- scenario-status: draft -->

- Area: sessions
- Milestone: M1
- ADRs: 0002, 0004, 0007
- Threat model: TM-13
- Gateway contract: Identity headers (`x-hopae-expires`), Cookies (`Max-Age`)

## Goal

Each handle expires on its own idle and absolute timers set by its
application's policy, and the whole session ends on the session-wide timers
regardless of per-host activity; expiry is enforced at verify with an
injected clock, `x-hopae-expires` tells the application the earliest
deadline, and a stale cookie or an old handoff code cannot extend or revive
anything.

## Preconditions and fixtures

- Configuration `tests/fixtures/m1-lifetimes.json`: application `app` (`app.example.test`) with `session = {idle: "12h", absolute: "7d"}`; application `short` (`short.example.test`) with `{idle: "1h", absolute: "1d"}`; the `default` application (portal handle) with `{idle: "2h", absolute: "3d"}`; session-wide `session.idle = 24h`, `session.absolute = 30d`.
- Session `s_1` created at `t0` with portal handle `H0`, handle `H1` on `app` and handle `H2` on `short`, all created at `t0`; injected clock.

## Main flow

### S010-1 Active handle stays alive and reports the earliest deadline

- Given: `H1` last seen at `t0 + 11h`; `now = t0 + 11h`.
- When: verify with `H1`.
- Then: `200`; `x-hopae-expires = t0 + 23h` (idle deadline `last_seen + 12h`, earlier than the handle's absolute `t0 + 7d` and the session's `t0 + 30d`); `session_handles.last_seen_at` updated (coalesced to 30 s).

### S010-2 Handle idle expiry revokes that handle only

- Given: `H2` last seen at `t0`; `H1` last seen at `t0 + 1h30m`; `now = t0 + 1h + 1s`.
- When: verify with `H2`, then with `H1`.
- Then: `H2`: `302` login (or `401`) with cookie clear, `session_handles.revoked_reason = idle`, event `handle.revoked` with `reason=idle`; `H1`: `200`; the session is not terminated; the portal handle is unaffected.

### S010-3 Handle absolute expiry despite activity

- Given: `H1` seen every hour; `now = t0 + 7d + 1s`.
- When: verify with `H1`.
- Then: denied; `revoked_reason = absolute`; the preceding verify at `t0 + 7d − 30m` returned `x-hopae-expires = t0 + 7d`; a new handoff through the still-valid portal session issues a fresh handle on `app`.

### S010-4 Session idle expiry terminates every handle

- Given: no handle of `s_1` (portal included) seen since `t0`; `now = t0 + 24h + 1s`.
- When: verify with `H1`.
- Then: `sessions.terminated_reason = idle`; every handle revoked with `session_terminated`; event `session.terminated` with `reason=idle`; the portal handle is also refused and the next login consults the provider.

### S010-5 Activity on one host does not extend another host's handle

- Given: `H1` seen every 10 minutes; `H2` last seen at `t0`; `now = t0 + 2h`.
- When: verify with `H2`.
- Then: `H2` revoked (`idle`, 1 h policy) although the session's newest activity is 10 minutes old; `H1` remains valid; the session's idle clock (`newest last_seen_at + 24h`) is `t0 + 2h + 24h`.

### S010-6 Session absolute expiry

- Given: all handles active hourly; `now = t0 + 30d + 1s`.
- When: verify with any handle.
- Then: `terminated_reason = absolute`; every handle revoked; `x-hopae-expires` of the last successful verify was `min(handle deadline, t0 + 30d)`.

## Alternative flows

### S010-7 Portal handle follows the default policy

- Given: `H0` last seen at `t0`; `now = t0 + 2h + 1s`; `H1` seen at `t0 + 2h`.
- When: `GET /login?txn=T2` for a new host with cookie `H0`.
- Then: `H0` is revoked (`idle`, 2 h policy); no single sign-on: the portal shows the provider chooser; the session itself continues and `H1` still verifies `200`.

### S010-8 Cookie `Max-Age` mirrors the handle's absolute lifetime

- Given: handoff on `app` at `t0 + 1h`.
- When: cookie planted.
- Then: `Max-Age = 7d − 0` for a handle created at `t0 + 1h` (the handle's own absolute timer starts at its creation), expressed in seconds.

### S010-9 Expiry sweep prunes terminated rows

- Given: 1,000 terminated sessions and their handles.
- When: the hourly sweep runs (triggered by the harness).
- Then: rows older than `sessions.retention_days` (default 30) are deleted; handles cascade; events remain and are pruned only by their own retention.

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

### S010-A1 Terminated session cannot be revived by an older handoff code

- Given: `s_1` terminated by `idle`; a handoff code created before termination with a matching binding cookie.
- When: redemption.
- Then: rejected (`code_session_terminated`); no handle; the code is burned.

### S010-A2 Client cannot extend lifetimes

- Given: a client sends `cookie: __Host-hopae=H1; Max-Age=999999` or a crafted `x-hopae-expires` request header.
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

- Log: `handle.revoked` with `reason` in `idle`, `absolute`; `session.terminated` with `reason` in `idle`, `absolute`; sweep summary.
- Audit: `events` rows.
- Metrics: `hopae_handle_revoked_total{reason}`, `hopae_session_terminated_total{reason}`, `hopae_sessions_active` gauge.

## Test mapping

| Case | Test | File | Kind | Status |
| --- | --- | --- | --- | --- |
| S010-1 | `s010_1_active_handle_reports_earliest_deadline` | `tests/scenarios/s010_lifetimes.rs` | integration | planned |
| S010-2 | `s010_2_handle_idle_expiry_revokes_handle_only` | `tests/scenarios/s010_lifetimes.rs` | integration | planned |
| S010-3 | `s010_3_handle_absolute_expiry_despite_activity` | `tests/scenarios/s010_lifetimes.rs` | integration | planned |
| S010-4 | `s010_4_session_idle_expiry_terminates_all` | `tests/scenarios/s010_lifetimes.rs` | integration | planned |
| S010-5 | `s010_5_activity_does_not_extend_other_host` | `tests/scenarios/s010_lifetimes.rs` | integration | planned |
| S010-6 | `s010_6_session_absolute_expiry` | `tests/scenarios/s010_lifetimes.rs` | integration | planned |
| S010-7 | `s010_7_portal_handle_follows_default_policy` | `tests/scenarios/s010_lifetimes.rs` | integration | planned |
| S010-8 | `s010_8_cookie_max_age_mirrors_handle_absolute` | `tests/scenarios/s010_lifetimes.rs` | integration | planned |
| S010-9 | `s010_9_sweep_prunes_terminated_rows` | `tests/scenarios/s010_lifetimes.rs` | integration | planned |
| S010-A1 | `s010_a1_terminated_session_not_revived_by_code` | `tests/scenarios/s010_lifetimes.rs` | integration | planned |
| S010-A2 | `s010_a2_client_cannot_extend_lifetime` | `tests/scenarios/s010_lifetimes.rs` | integration | planned |
| S010-A3 | `s010_a3_clock_skew_tolerance` | `tests/scenarios/s010_lifetimes.rs` | unit | planned |
| S010-A4 | `s010_a4_keepalive_flood_no_growth` | `tests/scenarios/s010_lifetimes.rs` | integration | planned |

## Live verification

| Date | Hopae version | Gateway version | Provider | Environment label | Result | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| — | — | — | — | — | — | Lifetimes are verified with the injected clock; live runs confirm `x-hopae-expires` only. |

## Open questions

- Is a 24 h session-wide idle default too long next to a 12 h per-handle default, or should the session-wide idle simply equal the longest handle idle among registered applications?

## 한국어 요약

핸들마다 애플리케이션 정책의 유휴·절대 타이머가 따로 돌고, 만료되면 그 핸들만
취소됩니다. 세션 전체는 세션 단위 유휴(모든 핸들의 최신 활동 기준)와 절대
수명으로만 종료되며, 한 호스트의 활동이 다른 호스트의 핸들 수명을 늘리지
않습니다. 만료는 verify에서 주입된 시계로 검사하고 `x-hopae-expires`로 가장
이른 마감을 알립니다. 종료된 세션은 이전 핸드오프 코드로 되살릴 수 없고,
클라이언트는 수명을 늘릴 수 없습니다.
