# ADR-0003: HTTP stack is axum on hyper 1, tokio and rustls

- Status: Proposed
- Date: 2026-10-09
- Deciders: designer, orchestrator
- Scenarios: 004, 013
- Threat model: TM-07, TM-12, TM-16
- Supersedes: none

## Context

- The gateway is built on `hyper` 1, `hyper-util`, `tokio`, `rustls` 0.23 (ring), `tokio-rustls`, `reqwest` with rustls, and hand-written routing (`src/admin.rs` is about 4,600 lines of path matching and JSON handling). Sharing the runtime family keeps one TLS stack, one async runtime and one set of audited crates across both products.
- Hopae is an application server, not a proxy: it renders HTML forms, parses cookies and form bodies, validates query strings, serves a JSON management API with OpenAPI (M4) and has three listeners with disjoint routers. The gateway's needs (streaming bodies, raw control over framing, hop-by-hop handling) do not apply.
- Verify must be cheap: routing overhead for one fixed path is negligible in either stack; the cost is in the store lookup.
- Dependency surface matters for `cargo audit` and for the review burden.

## Decision

Hopae uses **axum 0.8** (on `hyper` 1, `hyper-util`, `tower`) with `tokio`,
`rustls` 0.23 (ring) and `tokio-rustls` for optional TLS on listeners, and
`reqwest` 0.12 with rustls for outbound provider calls. Templates are
compiled with `askama`. Cookies are parsed and serialized with the `cookie`
crate; URLs with `url`.

Rules that bound the choice:

- Three separate `axum::Router`s, one per listener (portal, gateway, management), served with `axum::serve` over hyper-util's connection builder with explicit limits: header size 16 KiB, body size 64 KiB on the portal, 0 on the gateway listener, request timeout 10 s, concurrency limit per listener.
- Extractors do not perform security decisions; handlers call the core (`verify`, `session`, `portal`) which are plain functions over typed inputs so that unit tests run without HTTP.
- No `tower-http` middleware for security headers; a 40-line layer in `http/` sets `cache-control`, `x-content-type-options`, `referrer-policy`, `content-security-policy` and `x-frame-options` on every portal response so the behavior is reviewable in one place.
- Outbound HTTP uses one `reqwest::Client` with timeouts (connect 5 s, total 10 s), response size caps (discovery 64 KiB, JWKS 256 KiB, token 64 KiB, user info 64 KiB), no redirects for token and user-info calls, and system roots via `webpki-roots` as the gateway does.

## Consequences

### Positive

- Routing, extraction, form and JSON handling are declarative and well-trodden; fewer hand-written parsers to review (the class of bug that dominated the gateway's admin surface reviews).
- Same runtime, TLS and client stack as the gateway: shared operational knowledge, shared vulnerability tracking.
- Handlers stay thin; the decision logic is testable without a socket.

### Negative

- About fifteen additional crates (`axum`, `axum-core`, `tower`, `tower-layer`, `tower-service`, `matchit`, `askama`, `cookie`, `url`, `mime`, `serde_urlencoded`, `form_urlencoded`, `percent-encoding`, `sync_wrapper`, `futures-util`), each in scope for `cargo audit` and each pinned by `--locked`.
- axum major versions move faster than hyper's; an upgrade is a review item, not a routine bump.

### Neutral

- Plain-hyper fallback remains possible for the gateway listener alone if profiling ever shows framework overhead on verify; nothing in the design assumes axum types below `http/`.

## Alternatives considered

| Alternative | Why not |
| --- | --- |
| Plain `hyper` with a hand-written router, as the gateway | The gateway needed raw control over proxied bodies; Hopae needs forms, cookies, query parsing and a JSON API, where hand-written parsing has repeatedly cost review time. Estimated at several thousand lines of avoidable code. |
| `actix-web` | Different runtime integration and TLS story from the gateway; no shared crates. |
| `warp` or `poem` | Smaller communities; no clear advantage over axum, which shares `tower` with the ecosystem the gateway already uses. |
| Server-side rendering with a JavaScript framework | Out of scope; the portal is a handful of forms and must work without JavaScript. |

## Adversarial review

| Pass | Date | S1 | S2 | S3 | S4 | Outcome |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | 2026-10-09 | 0 | 0 | 0 | 0 | No finding against this record in pass 1. |
| 2 | 2026-10-09 | 0 | 0 | 0 | 0 | No finding against this record in pass 2. |
| 3 | 2026-10-09 | 0 | 0 | 0 | 0 | No finding; the reviewer notes that the frame-security headers this record requires must be verified by an explicit browser framing test (scenario 9xx). Accepted pending confirmation pass. |

## References

- Gateway `Cargo.toml` (hyper 1, hyper-util 0.1, rustls 0.23 ring, tokio-rustls 0.26, reqwest 0.12), reviewed 2026-10-09.
- [Architecture — Crate layout](../ARCHITECTURE.md#crate-layout)

## 한국어 요약

HTTP 계층은 hyper 1 위의 axum 0.8을 사용하고, 런타임·TLS·아웃바운드 클라이언트는
게이트웨이와 같은 tokio, rustls(ring), reqwest(rustls)를 사용합니다. Hopae는
프록시가 아니라 폼, 쿠키, JSON API를 다루는 애플리케이션 서버이므로 선언적
라우팅이 수작업 파서보다 검토 부담을 줄입니다. 리스너마다 별도 라우터와 명시적
크기·시간 제한을 두고, 보안 결정은 HTTP와 무관한 순수 함수에 둡니다.
