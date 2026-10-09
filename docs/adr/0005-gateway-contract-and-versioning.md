# ADR-0005: The gateway contract is versioned, header-based and fails closed

- Status: Accepted
- Date: 2026-10-09
- Deciders: designer, orchestrator
- Scenarios: 001, 004, 007, 008, 013
- Threat model: TM-06, TM-14, TM-19
- Supersedes: none
- Extended by: [ADR-0015](0015-app-host-entry-points-and-upstream-cookie-stripping.md) (contract v1.1: application-host entry points, reserved `/_hopae/` namespace, gateway change HC-12)

## Context

- The gateway's external check is `GET <url>` with no body; context arrives only in headers; only listed client headers are copied; `2xx` allows, `3xx`/`401`/`403` are relayed with `forward_response`, everything else is `503` (verified in `src/proxy.rs` `authorize`, 2026-10-09).
- Identity header names declared in any route's `response_headers` are stripped from every incoming request gateway-wide (`src/config.rs` `authentication_identity_headers`; `src/proxy.rs` request path). Names under `x-forwarded-` are accepted only for `user`, `email`, `groups`, `preferred-username`, `access-token`.
- Two products co-evolve; a silent mismatch is a security defect (agreed risk 2 in the brief).
- Many applications already consume `x-forwarded-user`/`x-forwarded-email` from other forward-auth products.

## Decision

The wire contract is defined in [`GATEWAY_CONTRACT.md`](../GATEWAY_CONTRACT.md)
as **contract v1** with these fixed points:

| Point | Decision |
| --- | --- |
| Verify endpoint | `GET /_hopae/verify` on a dedicated gateway listener (`listen.gateway`, default `127.0.0.1:8701`), never served by the portal listener |
| Caller authentication | Required in M1: the gateway sends `x-hopae-gateway-key` (gateway change HC-3, implemented alongside M1); Hopae compares it in constant time with the value of `gateway.caller_key_env` and, when set, `gateway.caller_key_next_env`, before reading any other header; mismatch or absence → `403` `caller_unauthorized` with no state touched. Loopback binding is a defense in depth, not the authentication: on a host-network gateway any local process can reach loopback (review finding R09). `gateway.allow_unauthenticated_caller = true` exists for development only and makes preflight print a warning. |
| Caller key rotation | Hopae accepts two keys during an overlap: current and next. Sequence: (1) set `caller_key_next_env` on every Hopae instance and restart them; (2) switch the gateway route's static header to the new value (one activation); (3) move the new value to `caller_key_env`, unset `caller_key_next_env`, restart Hopae instances. The gateway side stays a single value per header (review finding N11). Preflight warns when a next key has been configured for more than 7 days (`gateway.caller_key_next_since`, written by preflight on first sight). |
| Unauthenticated non-document requests | `401` with `{"error":"login_required","login":"<the application URL as requested>"}`: the `login` target is the application URL itself, because only a document navigation on the application host can plant the binding cookie and start a usable transaction; the `401` creates no transaction and sets no cookie (review finding N06). Step-up uses the same shape with `step_up_required`. |
| Generation provenance | Every `200` carries `x-hopae-gen: s<session cred_gen>.u<user authz_version>.c<configuration generation>` next to `x-hopae-fresh-until`; a caching gateway (HC-1) stores both and discards a fill whose generations are older than the last invalidation it saw for the entry's tags ([ADR-0006](0006-verify-caching-and-invalidation.md)). |
| Required request context | `x-original-url`, `x-forwarded-host`, `x-forwarded-proto`, `x-forwarded-for` (or `x-real-ip`); any missing → `400` `contract_violation` → gateway `503` |
| Optional gateway context | `x-hangang-canonical-path` and `x-hangang-route-id` (gateway change HC-6): the decoded, normalized path the gateway used for route selection and the selected route id. Until present, Hopae computes the canonical path itself with the gateway's rules ([ADR-0013](0013-gateway-adapter-boundary.md)). |
| Listed client headers | `cookie`, `user-agent`, `accept`, `sec-fetch-dest`, `sec-fetch-mode`, `sec-fetch-site` |
| Gateway-listener status invariant | On the gateway listener Hopae answers `2xx` **only** for an authenticated allow that carries the identity headers; every other outcome — login or step-up redirect, handoff success or failure, recovery exhaustion, account switch, denial, rate limit, ambiguity, contract violation, overload — is `302`, `401`, `403`, `400` or `503`. Terminal pages for a browser on the gateway listener are relayed `403` bodies, never `200`, because an unmodified gateway treats any `2xx` as an allow unless `terminal_response` is configured, which Hopae does not require (review finding N16). The adapter enforces it by construction: only `Decision::Allow` renders to `2xx`, and `x-hangang-auth-terminal` is never emitted. |
| Status semantics | `200` allow with identity headers; `302` for document navigations needing login, step-up or handoff; `401` JSON for non-document requests; `403` denied, including rate limiting (`{"error":"rate_limited","retry_after":N}` in the body, because an unmodified gateway maps `429` to `503` and drops `retry-after`; `429` + `retry-after` becomes available with gateway change HC-8); `400` contract violation; `503` cannot decide |
| Portal listener inputs | Every `x-original-*` and `x-forwarded-*` header on the portal listener is browser input unless the peer is a configured trusted proxy, and `x-original-*` is never used there at all: the gateway regenerates `x-forwarded-*` but passes `x-original-*` through unchanged on routes without external authorization (review finding R18). |
| Identity headers | `x-forwarded-user`, `x-forwarded-email`, `x-forwarded-preferred-username`, `x-forwarded-groups`, `x-hopae-session`, `x-hopae-provider`, `x-hopae-auth-time`, `x-hopae-expires`, `x-hopae-aal`, `x-hopae-factors`; visible ASCII with percent-encoded UTF-8; per-header limits; total ≤ 8 KiB |
| Diagnostics | `x-hopae-reason` on every response; never declared in `response_headers` |
| Version signal | `x-hopae-contract: 1` on responses; the gateway sends the same header once HC-3 exists; unknown major on the request → `400` |
| Compatibility | A matrix in the contract page lists Hopae version × gateway version × required HC; updated per release |
| Semver | Adding headers or reason codes is minor; renaming, removing, changing cookie names or the handoff parameter is major; before 1.0 a major contract change is allowed in a minor Hopae release with a `Changed` entry and migration note |

Applications that need more than these headers wait for `x-hopae-claims`
(a base64url JSON document, later) rather than ad hoc headers.

## Consequences

### Positive

- The contract is testable in isolation: scenario 004 drives the verify endpoint with raw headers; scenario 007 proves stripping through a live gateway.
- `x-forwarded-user`/`email` compatibility with existing applications; `x-hopae-*` carries what those cannot.
- Fail-closed by construction on every unexpected input from the gateway.

### Negative

- The required-context rule means a misconfigured gateway produces `503`s rather than a degraded login; this is intended but must be obvious in logs (`contract_violation` names the missing header).
- Two listeners complicate the deployment template slightly.

### Neutral

- Generic forward-auth gateways will express the same decisions through their own adapter (ADR-0013); the contract page is Hangang's instance of it.

## Alternatives considered

| Alternative | Why not |
| --- | --- |
| Network isolation only, no shared-secret header in M1 (the G1 draft) | Rejected after review finding R09: the reference gateway runs with host networking, so loopback admits any local process; HC-3 is small and is now part of M1. |
| A single listener with path-based separation | A route misconfiguration could expose `/_hopae/verify` publicly; separate listeners make the boundary a bind address. |
| JSON body on the verify response | The gateway copies headers, not bodies, into upstream requests; a body would need a second mechanism. |
| Only `x-hopae-*` headers (no `x-forwarded-*`) | Loses drop-in compatibility with applications written for other forward-auth products. |
| Encode all claims in one signed JWT header | Larger per-request payload; applications would need JWT parsing for a user id; kept as the later `x-hopae-claims` option. |

## Adversarial review

| Pass | Date | S1 | S2 | S3 | S4 | Outcome |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | 2026-10-09 | 1 | 1 | 2 | 0 | 4 × FIX_FIRST applied (R04 shared, R09, R17, R18) |
| 2 | 2026-10-09 | 0 | 1 | 1 | 0 | R04, R09, R17, R18 CLOSED; new N06 (shared), N11: FIX_FIRST applied |
| 3 | 2026-10-09 | 0 | 0 | 0 | 0 | N06, N11 CLOSED (a `401` from a POST/PUT API call recovers through a GET document navigation; the client replays its own operation). Accepted pending confirmation pass. |
| 4 | 2026-10-09 | 1 | 0 | 0 | 0 | N16 (shared with ADR-0004) FIX_FIRST applied: the gateway-listener status invariant above; scenario 004-11. Accepted pending confirmation pass. |

Findings and dispositions:

- N06 (S2, pass 2, shared with ADR-0004): the `401` login URL could not complete a login. FIX_FIRST: `login` names the application URL (document bootstrap); no transaction on `401`; scenario 001-4.
- N11 (S3, pass 2): single caller key made rotation an outage. FIX_FIRST: `caller_key_next_env` overlap and the documented sequence; scenario 004-A8 and 013-7 extended. Nothing further is needed from HC-3.

- R04 (S1, shared with ADR-0008 and ADR-0013): the gateway selects routes on a canonical path but sends the raw path. FIX_FIRST: optional `x-hangang-canonical-path`/`x-hangang-route-id` (HC-6) and Hopae-side canonicalization with the gateway's rules until then; scenario 008-A5.
- R09 (S2): loopback is not caller authentication and container loopback differs from host loopback. FIX_FIRST: `x-hopae-gateway-key` required in M1 (HC-3 implemented in the gateway); the deployment template runs Hopae in the gateway's network namespace or publishes the port on the host loopback only; scenario 013-A1 and 004-6.
- R17 (S3): `429` cannot pass through an unmodified gateway. FIX_FIRST: rate limiting answers `403` with a `rate_limited` body in M1; HC-8 adds `429` relay; scenarios 001-A4 and 003-A4.
- R18 (S3): `x-original-*` survives ordinary proxying on the portal route. FIX_FIRST: documented as browser input; scenario 007-A3 corrected; optional HC-9 strips it gateway-wide.

Reviewer confirmation recorded: navigation metadata selects presentation only
and confers no authorization; `Accept: */*` clients get `401`; `x-hopae-session`
is a correlation identifier, not a usable handle.

## References

- [Gateway contract](../GATEWAY_CONTRACT.md)
- Gateway `src/proxy.rs` (`authorize`, `forward_auth_context`), `src/config.rs` (`ExternalAuth`, `is_identity_forwarded_header`), reviewed 2026-10-09.

## 한국어 요약

게이트웨이와의 계약은 `GATEWAY_CONTRACT.md`의 v1로 고정합니다. verify는 전용
리스너의 `GET /_hopae/verify`이며, 필수 맥락 헤더가 빠지면 `400`으로 답해
게이트웨이가 `503`으로 거부하도록 합니다. 신원 헤더는 `x-forwarded-user` 등
호환 헤더와 `x-hopae-*` 헤더로 구성하고 크기를 제한합니다. 응답마다
`x-hopae-contract` 버전을 실어 보내고, 릴리스마다 호환성 매트릭스를 갱신합니다.
