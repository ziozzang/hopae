# ADR-0007: Sessions are bound to client context under a per-application policy; mismatch terminates by default

- Status: Proposed
- Date: 2026-10-09
- Deciders: designer, orchestrator
- Scenarios: 010, 011
- Threat model: TM-13
- Supersedes: none

## Context

- The maintainer's direction: if the client IP changes, kill the session; make this configurable per application; consider UA, geography, idle and absolute timeouts as well.
- The gateway resolves the client IP through `trusted_proxy_cidrs` and sends it as `x-forwarded-for`/`x-real-ip` on every verify call, so the signal is available on every request without extra cost.
- Mobile networks and carrier-grade NAT change client IPs frequently; a strict policy is a usability trade the operator must be able to make per application.
- Binding decisions must be evaluated at verify (every request), not only at login.

## Decision

Each session records its binding context at creation: `bound_ip`,
`bound_ua_sha256`, and (later) `bound_country`. Each application carries a
binding policy evaluated at verify against the request's context; the
reserved application `default` supplies defaults.

| Key | Values | Default | Semantics |
| --- | --- | --- | --- |
| `binding.ip` | `strict`, `prefix`, `off` | `strict` | `strict`: exact match. `prefix`: same `/24` (IPv4) or `/64` (IPv6) as recorded; `binding.ip_prefix_v4`/`_v6` override lengths. `off`: not evaluated. |
| `binding.ua` | `strict`, `off` | `off` | `strict`: SHA-256 of the `user-agent` header equals the recorded digest. |
| `binding.country` (later) | `strict`, `off` | `off` | Requires a country source (gateway header or local database); not evaluated in M1. |
| `binding.on_mismatch` | `terminate_session`, `drop_handle` | `terminate_session` | `terminate_session`: the whole session ends (reason `binding_ip`/`binding_ua`), every host loses access, an invalidation is published. `drop_handle`: only the presenting host's handle is revoked; the portal session, if its own policy still passes, can hand off again. |
| `apps[].session.idle` | duration | `12h` | Per-handle idle timer; see the state machine below. `last_seen_at` has 30 s granularity. |
| `apps[].session.absolute` | duration | `7d` | Per-handle absolute timer; cookie `Max-Age` mirrors it. |
| `session.idle`, `session.absolute` | duration | `24h`, `30d` | Session-wide timers; expiry terminates the session and every handle. |
| `session.max_auth_age` (later) | duration | none | Requires a fresh first-factor authentication when `now − auth_time` exceeds it. |

Evaluation order at verify: lifetimes → binding → user status and
`authz_version` → application policy → step-up. The portal applies the
`default` application's policy to its own handle. A mismatch is an event
(`session.terminated` or `handle.revoked` with the reason, the recorded and
observed values' digests, never raw UA strings) and answers the
unauthenticated path (`302`/`401`) with a cookie clear. The login transaction
inherits the policy: a transaction started from IP A cannot be completed from
IP B when `binding.ip = strict` (reason `txn_binding`).

**Lifetime state machine.** Handles and sessions have separate timers; a
handle timer revokes that handle only, a session timer terminates the session
and therefore every handle (review finding R15):

| Timer | Scope and clock | Effect on expiry |
| --- | --- | --- |
| `apps[].session.idle` (default 12 h) | Per handle, from `session_handles.last_seen_at` | Revoke that handle (`handle.revoked`, reason `idle`); the session and other handles continue |
| `apps[].session.absolute` (default 7 d) | Per handle, from `session_handles.created_at`; the cookie `Max-Age` mirrors it | Revoke that handle (reason `absolute`); a new handoff may issue a new handle while the session lives |
| `default` application's idle and absolute | The portal handle | Revoke the portal handle; the next login consults the provider again (no SSO) |
| `session.idle` (default 24 h) | Per session, from the newest `last_seen_at` of any of its handles | Terminate the session (reason `idle`) |
| `session.absolute` (default 30 d) | Per session, from `sessions.created_at`; `x-hopae-expires` reports the earliest of the handle's and the session's deadlines | Terminate the session (reason `absolute`) |
| Binding mismatch | Per request | `terminate_session` or `drop_handle` as configured |
| Elevation ([ADR-0008](0008-second-factor-extension-point.md)) | Per session | Revoke every handle (reason `elevation`) and reissue through browser-bound handoffs |

Activity on one host never extends another host's handle timer; only the
session-wide idle timer sees all hosts.

Out of scope: device fingerprinting, TLS fingerprinting, risk scoring.

## Consequences

### Positive

- A stolen cookie replayed from another network is useless under the default policy; the operator can trade that per application.
- Policy lives with the application, matching the per-route mental model of the gateway.
- All signals are already on the verify request; evaluation is a comparison.

### Negative

- Strict IP binding logs mobile users out on network changes; `prefix` and `off` exist for that, and the documentation says so plainly.
- Clients behind rotating egress pools may fail even `prefix`; the event record makes the cause visible.
- UA binding breaks on browser auto-updates (UA string changes); hence `off` by default.

### Neutral

- Geographic binding waits for a country source; the column exists so M-later adds a rule, not a migration.
- Step-up (ADR-0008) may later require `strict` for the duration of an elevated session.

## Alternatives considered

| Alternative | Why not |
| --- | --- |
| Evaluate binding only at login | Does nothing against cookie theft after login, the threat this addresses. |
| Global policy only | Contradicts the per-application direction; APIs and browser applications need different settings. |
| Soft signal (re-authenticate instead of terminate) | Available as `drop_handle`, which forces a new handoff; full re-authentication would need `max_auth_age` semantics that are later work. The maintainer asked for termination as the default. |
| Default `off` for IP | Contradicts the direction; strict by default, relax by choice. |

## Adversarial review

| Pass | Date | S1 | S2 | S3 | S4 | Outcome |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | 2026-10-09 | 0 | 1 | 0 | 0 | 1 × FIX_FIRST applied (R15, shared with ADR-0004) |
| 2 | 2026-10-09 | 0 | 1 | 0 | 0 | R15 PARTIAL → N10 (scenario contradictions) FIX_FIRST applied in scenarios 009 and 010; the state machine itself stands |

Findings and dispositions:

- R15 (S2): per-host idle expiry and session-wide termination contradicted each other, and session-wide activity would let one host keep another's shorter policy alive. FIX_FIRST: the lifetime state machine above separates handle timers from session timers; scenario 010 rewritten.

Reviewer confirmation recorded: the strict-IP default with its cookie-thief
logout and mobile-churn costs is the maintainer's explicit choice; shared NAT
does not make an IP a browser identity, which is why the handoff is bound to
a browser cookie (ADR-0004) rather than to the IP alone.

## References

- [Architecture — Flow 8](../ARCHITECTURE.md#flow-8--revocation-by-binding-mismatch-client-ip-changed)
- Gateway `src/proxy.rs` `forward_auth_context` (client IP from trusted-proxy resolution), reviewed 2026-10-09.

## 한국어 요약

세션은 생성 시 클라이언트 IP와 UA 다이제스트를 기록하고, verify마다
애플리케이션별 바인딩 정책과 비교합니다. 기본값은 IP `strict`이며 불일치 시
세션 전체를 종료합니다(`terminate_session`). 운영자는 애플리케이션마다
`prefix`/`off`, `drop_handle`로 완화할 수 있습니다. 유휴·절대 수명은 같은
정책에 속하며, 지리 바인딩은 열(column)만 미리 두고 나중에 규칙을 추가합니다.
