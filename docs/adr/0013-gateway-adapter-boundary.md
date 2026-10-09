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
VerifyInput  { original_url: Url, client_ip: IpAddr, host: String, proto: Scheme,
               method: Method, cookie_handle: Option<String>, user_agent: Option<String>,
               navigation: Navigation (Document | Other), contract: ContractVersion }
Decision     { Allow { identity: Identity, cache: Cacheability }
             | Login { transaction_url: Url, clear_cookie: bool }
             | Handoff { location: Url, set_cookie: CookieSpec }
             | StepUp { transaction_url: Url }
             | Deny { reason: Reason, status_hint: DenyKind }
             | Error { reason: Reason } }
trait GatewayAdapter { fn parse(&self, req: &http::Request) -> Result<VerifyInput, ContractViolation>;
                       fn render(&self, decision: Decision, nav: Navigation) -> http::Response; }
```

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
| — | — | — | — | — | — | Pending G2. |

Questions for the reviewer: does `Navigation` (document versus other)
belong in `VerifyInput` or is it already a gateway-specific notion? Is the
`grep` lint theater?

## References

- [Architecture — Components, Crate layout](../ARCHITECTURE.md#components)
- nginx `auth_request`, Traefik ForwardAuth, Caddy `forward_auth`, Envoy `ext_authz` documentation to be reviewed when the generic adapter is scheduled.

## 한국어 요약

핵심 모듈은 게이트웨이 중립적인 `VerifyInput`과 `Decision` 타입으로만 결정을
내리고, 헤더 이름·상태 코드·쿠키 속성 같은 게이트웨이 세부 사항은 어댑터가
전담합니다. M1에는 Hangang 어댑터만 구현하고, 범용 forward-auth 어댑터는
나중에 프로필(데이터)로 추가합니다. 핵심 모듈에 `x-original-`, `x-forwarded-`,
`x-hangang` 문자열이 들어가면 검사에서 실패하도록 경계를 강제합니다.
