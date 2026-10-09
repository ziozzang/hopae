# ADR-0006: Zero-trust by default; Hopae declares cacheability and an absolute freshness deadline; the cache key carries every decision input

- Status: Accepted
- Date: 2026-10-09
- Deciders: designer, orchestrator
- Scenarios: 004, 006, 011 (M1); 1xx (M2 cache); gateway HC-1/HC-2 tasks
- Threat model: TM-07, TM-18
- Supersedes: none

## Context

- The gateway calls Hopae on every protected request and caches nothing (verified 2026-10-09). This is what makes revocation immediate, and it makes Hopae's availability the availability of every application (agreed risk 1).
- The brief allows a native per-route micro-cache with a configurable TTL, or no cache at all (zero trust), and instant invalidation through Redis pub/sub.
- A decision depends on more than the listed client headers: the resolved client IP (binding), the external scheme and authority (application and handle host), the route, the policy generation, and whether the request carries a handoff parameter. A cache key that omits any of them is a bypass (review finding R03).
- Staleness composes across tiers: a Hopae-local entry can be served just before it expires and then cached again by the gateway for a full TTL, so a "maximum" of the two TTLs is not a bound (review finding R08).

## Decision

1. **Default is zero trust.** `apps[].verify_cache_seconds`, `cache.local_ttl_ms` and the proposed gateway option `auth.decision_cache_ms` all default to `0`. Every request reaches Hopae and the primary store unless an operator raises them.
2. **Hopae declares cacheability per response.** A `200` carries `cache-control: private, max-age=N` and `x-hopae-fresh-until: <unix ms>` only when `N > 0` and the decision for that application depends on nothing outside the cache key below; otherwise, and on every non-`200` response, `cache-control: no-store`. `N ≤ 30`. `x-hopae-fresh-until` = `min(now + N, handle expiry, session expiry)`, an absolute deadline that every tier obeys.
3. **The gateway honors, never decides.** With HC-1 the gateway caches only `2xx` responses that carry `max-age`, for `min(max-age, decision_cache_ms, fresh-until − now)`, keyed on **(gateway configuration generation, route id, resolved client IP, normalized external scheme and authority, SHA-256 of the listed request headers and static request headers)**, tagged with `x-hopae-session` and `x-forwarded-user` and stamped with the response's `x-hopae-gen`. `no-store` is a veto. Responses with `set-cookie` are never cached. Lookup and fill are both skipped when the request matches the **reserved parameter recognition rule** of [ADR-0004](0004-session-model-and-cross-domain-handoff.md): a query pair whose percent-decoded name is `_hopae_handoff`, a malformed escape in a candidate name, a duplicate, or the raw or encoded name anywhere in the path all bypass. A route whose matched applications differ by host still gets separate entries because the authority is in the key.
4. **Invalidation is push plus deadline, with generations carried end to end.** Hopae publishes `{"v":1,"kind":"session"|"user"|"all","id":…,"gen":…,"at":…}` on channel `hopae:<namespace>:invalidate` (M2) whenever a session is terminated or a handle revoked (which also increments the session's `cred_gen`), a user is disabled, blocked or has `authz_version` bumped, policy or configuration changes (`all`), or keys rotate. Every `200` carries `x-hopae-gen: s<cred_gen>.u<authz_version>.c<config gen>` taken from the **authoritative read** that produced it. A subscriber records the highest generation it has seen per tag and discards any fill whose `x-hopae-gen` component is lower, so neither an in-flight old response nor an instance that has not yet processed the invalidation can repopulate a purged entry. Subscribers purge by tag; a subscriber that reconnects purges everything.
5. **There is no Redis tier for session state.** Redis never holds a positive session or decision entry ([ADR-0002](0002-primary-store-sqlite-with-postgres-for-shared-deployments.md)): a successfully answering stale Redis entry would outlive a revocation without triggering any timeout or breaker. Hopae's only cache is the opt-in local cache (`cache.local_ttl_ms`, default 0, max 5000), keyed by handle digest plus the same decision inputs; each entry stores the authoritative read time and the generations observed then. `x-hopae-fresh-until` is computed from the authoritative read time, never from a cache hit, and a hit is served only while that deadline holds and the entry's generations are current. The local cache is purged by the same messages and disabled while the pub/sub connection is down. The configuration snapshot (applications, providers) is not a cache of identity state; it is replaced on change and publishes `all`.
6. **The declared staleness bound is a sum.** After a revocation, an allow can persist at most `decision_cache_ms + local_ttl_ms + stale_if_error_ms` milliseconds, each term defaulting to `0`, and never past `x-hopae-fresh-until`; there is no other tier. `hopae --check` prints the bound whenever any term is non-zero.
7. **Negative decisions are never cached** in v1 on either side.
8. **Generations live inside a database epoch** (deferred to the milestone that ships any cache: M2 for the local cache and the channel, HC-1/HC-2 on the gateway side). `meta.epoch` is 128 random bits created at bootstrap and regenerated by `hopae store mark-restored`, which the restore procedure runs after a backup is restored or a database is re-seeded. `x-hopae-gen` becomes `e<first 8 hex of epoch>.s<cred_gen>.u<authz_version>.c<config gen>` and every invalidation message carries `epoch`. Subscribers keep their high-water marks **per epoch**: a response or message with an epoch they have not seen purges everything tagged by that Hopae and resets the marks; marks of an older epoch are discarded; responses still in flight from before the restore carry the old epoch and can never fill a new-epoch entry. Without this, a restore to lower generations would suppress caching (never widen access) until counters overtook the remembered marks (review finding N15).

## Consequences

### Positive

- Revocation stays immediate for everyone who keeps the defaults, and bounded by a printed number for everyone who does not.
- The key contains every input the decision used, so a cache hit is exactly the decision Hopae would make again within the deadline.
- The micro-cache still gives a short buffer across a Hopae restart without a second verify path.

### Negative

- Including the client IP in the key lowers hit rates behind NAT; that is the correct trade for strict IP binding.
- Generations and an absolute deadline are more state for the gateway's cache module than a plain TTL.
- Operators get a knob that trades security for latency; the documentation must present it as such.

### Neutral

- HC-1 and HC-2 are gateway tasks; Hopae M1 ships with every TTL at `0` and emits `no-store` everywhere, which is already correct against an unmodified gateway.

## Alternatives considered

| Alternative | Why not |
| --- | --- |
| Key on (route id, listed headers digest) only (the G1 draft) | Rejected after review finding R03: a cookie thief at another IP, or a second application on a multi-host route, hits the victim's entry; a handoff parameter would be forwarded upstream. |
| Cache in the gateway keyed on the full URL | Correct for path-dependent decisions but near-zero hit rate for SPAs and APIs; the per-application `no-store` signal achieves correctness with useful hit rates. |
| Relative TTLs per tier with a `max()` bound (the G1 draft) | Rejected after review finding R08: tiers compose additively and an entry can be refilled from a nearly-expired one; an absolute deadline plus generations is the bound. |
| Signed short-lived tokens the gateway verifies locally | The gateway's JWT verifier is bearer-header only (RFC 9068 `at+jwt`), not cookie based; and it reintroduces the revocation gap as a design feature. |
| Push-only invalidation without a deadline | A lost message would be a permanent bypass; the deadline bounds the damage of any bus failure. |
| Redis as a write-through session cache with the session lifetime as TTL (the pass-1 revision) | Rejected after review finding N02: a stale entry that still answers is invisible to timeouts and breakers and can outlive a revocation for hours while every declared TTL is zero. |
| Cache negative decisions to absorb unauthenticated floods | Delays login completion and creates a confusing state after handoff; the gateway's failure bans and rate limits exist for floods. Revisit with data. |

## Adversarial review

| Pass | Date | S1 | S2 | S3 | S4 | Outcome |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | 2026-10-09 | 1 | 1 | 0 | 0 | 2 × FIX_FIRST applied (R03, R08) |
| 2 | 2026-10-09 | 1 | 0 | 1 | 0 | R03 CLOSED; R08 PARTIAL → N02 FIX_FIRST applied; N12 (shared) FIX_FIRST applied |
| 3 | 2026-10-09 | 0 | 0 | 1 | 0 | R08, N02, N12 CLOSED; new N15 DEFERRED (epoch recorded in decision 8; tracking scenario in the 1xx range when the local cache ships; HC-1/HC-2 acceptance criteria extended). Accepted pending confirmation pass. |
| 4 | 2026-10-09 | 0 | 0 | 0 | 0 | N15 deferral judged adequate; the tracking scenario must test epoch fencing against delayed old-epoch work before any cache ships. Accepted pending confirmation pass. |

Findings and dispositions:

- N15 (S3, pass 3): a restore to lower generations has no recovery protocol. DEFERRED: M1 has no cache; decision 8 records the database epoch and the restore procedure; the scenario lands with the local cache (M2) and the gateway tasks HC-1/HC-2 carry the criteria.

- N02 (S1, pass 2): the Redis session cache was outside the bound and generations were not carried through tiers. FIX_FIRST: no Redis session tier at all; `x-hopae-gen` provenance on every allow; `fresh-until` anchored to the authoritative read; subscribers reject fills with older generations.
- N12 (S3, pass 2): a raw-substring detector could miss `%5Fhopae%5Fhandoff`. FIX_FIRST: the shared recognition rule (decoded names, ambiguity rejected) is the bypass rule; HC-1 gains a primed-cache regression case.

- R03 (S1): the HC-1 key omitted the resolved client IP, the external authority and the policy generation, and did not bypass handoff requests. FIX_FIRST: key expanded as in decision 3; handoff bypass; HC-1 acceptance criteria updated.
- R08 (S2): the staleness bound was stated as a maximum and ignored refills and uncapped TTLs near expiry. FIX_FIRST: absolute `x-hopae-fresh-until`, generation-checked fills, local cache opt-in, bound stated as a sum including `stale_if_error_ms`.

Open for the reviewer: is `max-age` still the right carrier next to
`x-hopae-fresh-until`, or should the gateway read only the Hopae header so
that intermediaries cannot misinterpret `cache-control`?

## References

- [Gateway contract — Cache semantics, Invalidation channel](../GATEWAY_CONTRACT.md#cache-semantics-hc-1)
- Gateway `src/proxy.rs` (no auth-decision cache; auth routes excluded from response cache), reviewed 2026-10-09.

## 한국어 요약

기본값은 제로 트러스트입니다. 모든 TTL이 0이며 운영자가 명시적으로 올려야만
캐시가 동작합니다. 캐시 가능 여부는 Hopae가 `cache-control`과 절대 마감
`x-hopae-fresh-until`로 선언하고, 게이트웨이의 캐시 키에는 설정 세대, 라우트
ID, 해석된 클라이언트 IP, 외부 스킴과 호스트, 나열된 요청 헤더 다이제스트가
모두 들어갑니다. 핸드오프 매개변수가 있으면 캐시를 우회합니다. 무효화는
세대 번호가 붙은 pub/sub 푸시와 절대 마감의 조합이며, 취소 후 최대 지연은 각
TTL의 합으로 선언합니다.
