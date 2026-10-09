# ADR-0006: Zero-trust by default; Hopae declares decision cacheability; invalidation is push plus TTL

- Status: Proposed
- Date: 2026-10-09
- Deciders: designer, orchestrator
- Scenarios: 004, 006, 011 (M1); 1xx (M2 cache); gateway HC-1/HC-2 tasks
- Threat model: TM-07, TM-18
- Supersedes: none

## Context

- The gateway calls Hopae on every protected request and caches nothing (verified 2026-10-09). This is what makes revocation immediate, and it makes Hopae's availability the availability of every application (agreed risk 1).
- The brief allows a native per-route micro-cache with a configurable TTL, or no cache at all (zero trust), and instant invalidation through Redis pub/sub.
- Some decisions depend only on the session (whole-host applications); others depend on the path (step-up on `/admin`, path rules in M2). A cache that ignores this is a bypass.
- Multiple Hopae instances (M2) also cache session lookups locally and must drop them on revocation.

## Decision

1. **Default is zero trust.** `apps[].verify_cache_seconds` defaults to `0` and the proposed gateway option `auth.decision_cache_ms` defaults to `0`. Every request reaches Hopae unless an operator raises both.
2. **Hopae declares cacheability per response.** `200` responses carry `cache-control: private, max-age=N` only when `N > 0` and the decision for that application is independent of path and method; otherwise, and on every non-`200` response, `cache-control: no-store`. `N ≤ 30`.
3. **The gateway honors, never decides.** With HC-1 the gateway caches only `2xx` responses that carry `max-age`, for `min(max-age, decision_cache_ms)`, keyed on (route id, SHA-256 of the listed request headers and static headers), tagged with `x-hopae-session` and `x-forwarded-user`. `no-store` is a veto. Responses with `set-cookie` are never cached.
4. **Invalidation is push plus TTL.** Hopae publishes `{"v":1,"kind":"session"|"user"|"all","id":…,"at":…}` on channel `hopae:<namespace>:invalidate` (M2) whenever a session is terminated, a user is disabled or blocked, or keys rotate. Subscribers purge by tag. The TTL is the guarantee; push is the optimization. Maximum staleness after a revocation is `max(N, decision_cache_ms/1000)` seconds, documented per deployment.
5. **Hopae's own caches obey the same rule.** The local session cache (M2) holds entries no longer than the smaller of 5 s and the session's remaining lifetime, is purged by the same messages, and is disabled (TTL 0) while the pub/sub connection is down.
6. **Negative decisions are never cached** in v1 on either side.

## Consequences

### Positive

- Revocation stays immediate for everyone who keeps the default, and bounded for everyone who does not; the bound is a documented number, not a hope.
- The cacheability signal lives where the knowledge is (Hopae knows whether a path rule exists for an application).
- The micro-cache gives a short buffer across a Hopae restart without a second verify path.

### Negative

- Operators get a knob that trades security for latency; the documentation must present it as such.
- Tagging entries requires the gateway to parse two identity headers it otherwise treats as opaque.
- Two caches (gateway and Hopae) with two TTLs make the staleness bound a formula; it is printed by `hopae --check` when caching is enabled.

### Neutral

- HC-1 and HC-2 are gateway tasks; Hopae M1 ships with `N = 0` and emits `no-store` everywhere, which is already correct against an unmodified gateway.

## Alternatives considered

| Alternative | Why not |
| --- | --- |
| Cache in the gateway keyed on the full URL | Correct for path-dependent decisions but near-zero hit rate for SPAs and APIs; the per-application signal achieves correctness with useful hit rates. |
| Signed short-lived tokens the gateway verifies locally (no verify call) | The gateway's JWT verifier is bearer-header only (RFC 9068 `at+jwt`), not cookie based; and it reintroduces the revocation gap as a design feature rather than an operator choice. |
| Push-only invalidation without TTL | A lost message would be a permanent bypass; TTL bounds the damage of any bus failure. |
| Cache negative decisions to absorb unauthenticated floods | Delays login completion and creates a confusing state after handoff; the gateway's failure bans and rate limits exist for floods. Revisit with data. |
| No cache ever, rely on Hopae HA only | Rejected as the only option: a short, operator-chosen buffer is cheap and the default stays zero. |

## Adversarial review

| Pass | Date | S1 | S2 | S3 | S4 | Outcome |
| --- | --- | --- | --- | --- | --- | --- |
| — | — | — | — | — | — | Pending G2. |

Questions for the reviewer: can a cached `200` be replayed for a request
whose listed headers digest collides because the client controls those
headers? Does caching by (route id, cookie digest) leak across two
applications on one route? Is `max-age` the right carrier versus a dedicated
`x-hopae-cache` header that proxies between gateway and Hopae could not
misinterpret?

## References

- [Gateway contract — Cache semantics, Invalidation channel](../GATEWAY_CONTRACT.md#cache-semantics-hc-1)
- Gateway `src/proxy.rs` (no auth-decision cache; auth routes excluded from response cache), reviewed 2026-10-09.

## 한국어 요약

기본값은 제로 트러스트입니다. 모든 요청이 Hopae에 도달하며, 캐시 TTL은
애플리케이션과 게이트웨이 라우트 양쪽에서 운영자가 명시적으로 올려야만
동작합니다. 캐시 가능 여부는 Hopae가 응답의 `cache-control`로 선언하고,
경로에 따라 달라지는 결정과 거부 결정은 항상 `no-store`입니다. 무효화는 Redis
pub/sub 푸시와 TTL을 함께 쓰며, TTL이 보장이고 푸시는 최적화입니다.
