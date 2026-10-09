# ADR-0005: The gateway contract is versioned, header-based and fails closed

- Status: Proposed
- Date: 2026-10-09
- Deciders: designer, orchestrator
- Scenarios: 001, 004, 007, 008, 013
- Threat model: TM-06, TM-14, TM-19
- Supersedes: none

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
| Required request context | `x-original-url`, `x-forwarded-host`, `x-forwarded-proto`, `x-forwarded-for` (or `x-real-ip`); any missing → `400` `contract_violation` → gateway `503` |
| Listed client headers | `cookie`, `user-agent`, `accept`, `sec-fetch-dest`, `sec-fetch-mode`, `sec-fetch-site` |
| Status semantics | `200` allow with identity headers; `302` for document navigations needing login, step-up or handoff; `401` JSON for non-document requests; `403` denied; `400` contract violation; `503` cannot decide |
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
| Shared-secret header required in M1 | The gateway cannot add static headers today; HC-3 adds it. Network isolation is the M1 boundary. |
| A single listener with path-based separation | A route misconfiguration could expose `/_hopae/verify` publicly; separate listeners make the boundary a bind address. |
| JSON body on the verify response | The gateway copies headers, not bodies, into upstream requests; a body would need a second mechanism. |
| Only `x-hopae-*` headers (no `x-forwarded-*`) | Loses drop-in compatibility with applications written for other forward-auth products. |
| Encode all claims in one signed JWT header | Larger per-request payload; applications would need JWT parsing for a user id; kept as the later `x-hopae-claims` option. |

## Adversarial review

| Pass | Date | S1 | S2 | S3 | S4 | Outcome |
| --- | --- | --- | --- | --- | --- | --- |
| — | — | — | — | — | — | Pending G2. |

Questions for the reviewer: is `401` for non-document requests detectable
reliably from `sec-fetch-dest`/`accept`, and what happens with old clients
that send neither? Should `x-hopae-session` be omitted from the upstream set?

## References

- [Gateway contract](../GATEWAY_CONTRACT.md)
- Gateway `src/proxy.rs` (`authorize`, `forward_auth_context`), `src/config.rs` (`ExternalAuth`, `is_identity_forwarded_header`), reviewed 2026-10-09.

## 한국어 요약

게이트웨이와의 계약은 `GATEWAY_CONTRACT.md`의 v1로 고정합니다. verify는 전용
리스너의 `GET /_hopae/verify`이며, 필수 맥락 헤더가 빠지면 `400`으로 답해
게이트웨이가 `503`으로 거부하도록 합니다. 신원 헤더는 `x-forwarded-user` 등
호환 헤더와 `x-hopae-*` 헤더로 구성하고 크기를 제한합니다. 응답마다
`x-hopae-contract` 버전을 실어 보내고, 릴리스마다 호환성 매트릭스를 갱신합니다.
