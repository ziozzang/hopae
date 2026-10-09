# ADR-0013: The core decides in gateway-neutral types; adapters own every gateway-specific name

- Status: Proposed
- Date: 2026-10-09
- Deciders: designer, orchestrator
- Scenarios: 004 (core decision types exercised without a gateway); 6xx or backlog for other adapters
- Threat model: TM-06, TM-19
- Supersedes: none

## Context

- Hangang is the first-class gateway with the deepest integration (HC-1…HC-5). Other environments come later: nginx `auth_request`, Traefik ForwardAuth, Caddy `forward_auth`, Envoy `ext_authz`, and an OIDC-provider mode for applications that speak OIDC themselves.
- Agreed risk 4: do not generalize adapters early. The boundary must exist in M1 so Hangang names do not leak into the core, but only one adapter is implemented.
- Forward-auth gateways differ in: how the original URL is conveyed (`X-Original-URL`, `X-Forwarded-Uri` + `X-Forwarded-Host` + `X-Forwarded-Proto`, or the full request in `ext_authz`), whether a `302` can be relayed (nginx needs `error_page 401 = @login`), how identity headers are relayed upstream (`auth_request_set` for nginx, automatic for Traefik and Caddy), and how a handoff on the application host can be intercepted.

## Decision

The core exposes two gateway-neutral types and one trait:

```text
VerifyInput  { original_url: Url, canonical_path: CanonicalPath, client_ip: IpAddr,
               host: String, proto: Scheme, method: Method, route_id: Option<String>,
               cookie_handle: Option<String>, bind_cookie: Option<String>,
               user_agent: Option<String>, navigation: Navigation (Document | Other),
               contract: ContractVersion, caller: CallerAuth (Keyed | Unauthenticated) }
Decision     { Allow { identity: Identity, cache: Cacheability }
             | Login { transaction_url: Url, clear_cookie: bool }
             | Handoff { location: Url, set_cookie: CookieSpec }
             | StepUp { transaction_url: Url }
             | Deny { reason: Reason, status_hint: DenyKind }
             | Error { reason: Reason } }
trait GatewayAdapter { fn parse(&self, req: &http::Request) -> Result<VerifyInput, ContractViolation>;
                       fn render(&self, decision: Decision, nav: Navigation) -> http::Response; }
```

`CanonicalPath` is the path every policy rule (step-up, M2 path rules)
matches against; `original_url` is only ever a return target. The adapter
supplies it from a gateway header when one exists (`x-hangang-canonical-path`,
HC-6) and otherwise computes it with the gateway's own rules, which are part
of this boundary (review finding R04): percent escapes are decoded exactly
once and must form valid UTF-8; a decoded or raw backslash, percent, `?`,
`#`, `;`, control byte or DEL, a `.`/`..` segment, or a repeated slash makes
the path non-canonical. A non-canonical path is `Decision::Deny { reason:
path_not_canonical }` — the gateway itself answers `400` for such paths on
guarded routes, so the Hopae check is a second line for other adapters.
When both a gateway header and a computed value exist and differ, the
request is denied (`canonical_path_mismatch`) and counted.

The adapter also applies the reserved parameter recognition rule of
[ADR-0004](0004-session-model-and-cross-domain-handoff.md) (decoded query
names, ambiguity rejected) and sets `VerifyInput.handoff` to `None`,
`Some(code)` or `Ambiguous`; the core never parses a query string.

Rules:

- `verify/`, `session/`, `policy/`, `identity/` and `provider/` never mention a gateway header name, a status code to send to a gateway, or a cookie attribute. A compile-time test in `gateway/` asserts the core modules do not import `gateway::*`, and a `grep`-based check in `make check-docs`' sibling target `make check-boundary` fails on the strings `x-original-`, `x-forwarded-` and `x-hangang` outside `gateway/` and `tests/`.
- `gateway::hangang` implements contract v1 ([ADR-0005](0005-gateway-contract-and-versioning.md)). It is the only adapter in M1 and the only one with gateway-layer scenarios.
- `gateway::forward_auth` (later) implements the generic forward-auth form with per-gateway profiles (`nginx`, `traefik`, `caddy`, `envoy`) that differ only in header names and in whether redirects are relayed; profiles are data, not code paths.
- The OIDC-provider mode (later) is a different kind of adapter: it issues tokens and does not use `Decision`; it is listed here only so it is not mistaken for a forward-auth profile.
- Identity header values are produced once by the core (`Identity`); adapters choose names and encoding. The Hangang adapter's names are the contract; a generic adapter may map `Identity.user` to `Remote-User` if a profile says so.
- Deep Hangang features (HC-1 cacheability, HC-2 invalidation, HC-3 static headers) are expressed through `Cacheability` and the invalidation bus, which are gateway-neutral; the Hangang adapter and the Hangang gateway are the only consumers in the foreseeable future.

Out of scope: writing any non-Hangang adapter in M1–M6; a plugin ABI.

## Consequences

### Positive

- The core is testable with plain structs (scenario 004 drives `Decision` directly).
- A second gateway is an adapter plus a verification run, not a rewrite; nothing in the data model changes.
- Hangang-specific optimizations stay possible because `Cacheability` and invalidation are neutral concepts with one rich consumer.

### Negative

- Two layers for every change to the contract (adapter and contract page).
- The boundary check is a lint, not a type-system guarantee; a reviewer must still read.

### Neutral

- The generic adapter's profiles will be verified against each gateway's documentation when they are built; nothing here claims they work today.

## Alternatives considered

| Alternative | Why not |
| --- | --- |
| Hangang headers directly in the core | Fast now, every later gateway becomes a fork or a special case; the agreed risk is precisely this. |
| Full generic forward-auth adapter in M1 with profiles for four gateways | Premature generalization: no verification environment for them, and their differences (redirect relay, handoff interception) are not yet measured. |
| Separate crates (`hopae-core`, `hopae-hangang`) | Workspace overhead for one binary; the module boundary plus the lint gives the same discipline at lower cost. Revisit when a second adapter exists. |

## Adversarial review

| Pass | Date | S1 | S2 | S3 | S4 | Outcome |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | 2026-10-09 | 1 | 0 | 0 | 0 | 1 × FIX_FIRST applied (R04, shared) |
| 2 | 2026-10-09 | 0 | 0 | 1 | 0 | R04 CLOSED; N12 (shared) FIX_FIRST applied: the recognition rule lives in the adapter and `VerifyInput.handoff` carries the result |

Findings and dispositions:

- R04 (S1): `VerifyInput` carried only the raw URL, so path rules diverged from the gateway's canonical route selection. FIX_FIRST: `canonical_path` with the gateway's decoding rules, `route_id`, and the mismatch rule above; HC-6 proposed.

Reviewer confirmation recorded: neutral decision types are a viable
boundary; the lint alone cannot prove isolation, so a reviewer still reads.
Open: does `Navigation` belong in `VerifyInput`?

## References

- [Architecture — Components, Crate layout](../ARCHITECTURE.md#components)
- nginx `auth_request`, Traefik ForwardAuth, Caddy `forward_auth`, Envoy `ext_authz` documentation to be reviewed when the generic adapter is scheduled.

## 한국어 요약

핵심 모듈은 게이트웨이 중립적인 `VerifyInput`과 `Decision` 타입으로만 결정을
내리고, 헤더 이름·상태 코드·쿠키 속성 같은 게이트웨이 세부 사항은 어댑터가
전담합니다. M1에는 Hangang 어댑터만 구현하고, 범용 forward-auth 어댑터는
나중에 프로필(데이터)로 추가합니다. 핵심 모듈에 `x-original-`, `x-forwarded-`,
`x-hangang` 문자열이 들어가면 검사에서 실패하도록 경계를 강제합니다.
