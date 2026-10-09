# S007 — Identity headers reach the upstream only from Hopae; client copies are stripped

<!-- scenario-status: draft -->

- Area: security
- Milestone: M1
- ADRs: 0005, 0013
- Threat model: TM-06
- Gateway contract: Identity headers, Hangang route fragments, Header-spoofing protection

## Goal

Through a live gateway, an upstream application receives exactly the identity
headers Hopae emitted for the session, and a client that sends its own copies
of those headers, or gateway context headers, never gets them delivered.

## Preconditions and fixtures

- Gateway layer (`HOPAE_E2E_GATEWAY_BINARY`) with a temporary configuration: the protected whole-host route from the contract page pointing `auth.url` at the spawned Hopae's gateway listener, `backends` at an echo upstream started by the harness that records request headers.
- Hopae configuration `tests/fixtures/m1-basic.json`; session `s_1` with handle `H1` for `app.example.test`.
- The harness sends requests to the gateway with `host: app.example.test`.

## Main flow

### S007-1 Upstream receives the identity set

- Given: cookie `H1`.
- When: `GET /admin/x` through the gateway.
- Then: the echo upstream saw `x-forwarded-user: u_1`, `x-forwarded-email`, `x-forwarded-preferred-username`, `x-hopae-session`, `x-hopae-provider`, `x-hopae-auth-time`, `x-hopae-expires`, `x-hopae-aal`, `x-hopae-factors`; it did not see `x-hopae-reason` or `x-hopae-contract`; the client response is the upstream's.

### S007-2 Unauthenticated request never reaches the upstream

- Given: no cookie.
- When: `GET /admin/x` through the gateway.
- Then: the client receives the `302` to the portal with `referrer-policy: no-referrer`; the echo upstream recorded no request.

### S007-3 Gateway configuration validates

- Given: the route fragment from the contract page.
- When: `hangang --check` (or the gateway's config validation endpoint) runs on the temporary configuration.
- Then: accepted; every identity header name is in `response_headers`.

## Alternative flows

### S007-4 Header values survive the gateway unchanged

- Given: `x-forwarded-preferred-username: Alice%20%EA%B9%80`.
- When: S007-1.
- Then: the upstream saw the identical bytes.

## Abuse cases

| Category | Case | Applies |
| --- | --- | --- |
| Replay | — | no: covered by 003/011 |
| Tampering | S007-A1 | yes |
| Race / timing | — | no: stateless per request |
| Resource exhaustion | S007-A2 | yes |
| Confused deputy | S007-A3 | yes |
| Spoofed or duplicated headers | S007-A4, S007-A5 | yes |
| Downgrade | — | no |
| Enumeration | — | no |

### S007-A1 Client-supplied identity header with a valid session is replaced

- Given: cookie `H1`; client sends `x-forwarded-user: admin`, `x-forwarded-groups: root`.
- When: `GET /admin/x` through the gateway.
- Then: the upstream saw `x-forwarded-user: u_1` and **no** `x-forwarded-groups` (Hopae did not emit it; the client copy was stripped).

### S007-A2 Oversized identity response is refused by the gateway

- Given: a test hook making Hopae emit a 20 KiB `x-forwarded-groups`.
- When: request through the gateway.
- Then: the client receives `503` (gateway 16 KiB cap); Hopae's own 4 KiB cap makes this unreachable in production (unit test on the emitter).

### S007-A3 Spoofed gateway context on the portal route

- Given: the portal route; client sends `x-forwarded-for: 203.0.113.9`, `x-original-url: https://app.example.test/`.
- When: `GET https://auth.example.test/login?txn=T1` through the gateway.
- Then: Hopae's portal saw `x-forwarded-for` equal to the harness client address as resolved by the gateway, not `203.0.113.9`; `x-original-url` absent or regenerated.

### S007-A4 Unauthenticated client with identity headers

- Given: no cookie; client sends every identity header name.
- When: `GET /admin/x` through the gateway.
- Then: `302` to the portal; the upstream saw nothing; the verify call Hopae received contained none of the identity names (recorded by a Hopae test hook).

### S007-A5 Duplicate `cookie` fields (HTTP/2 style) are joined

- Given: the harness sends two `cookie` header fields over HTTP/2 (`a=b` and `__Host-hopae=H1`).
- When: request through the gateway.
- Then: `200`; the verify call received one `cookie` header `a=b; __Host-hopae=H1`.

## Observability expectations

- Log: none specific; the gateway logs the authorization decision.
- Audit: none.
- Metrics: `hopae_verify_decisions_total`.

## Test mapping

| Case | Test | File | Kind | Status |
| --- | --- | --- | --- | --- |
| S007-1 | `s007_1_upstream_receives_identity_set` | `tests/scenarios/s007_header_contract.rs` | gateway | planned |
| S007-2 | `s007_2_unauthenticated_never_reaches_upstream` | `tests/scenarios/s007_header_contract.rs` | gateway | planned |
| S007-3 | `s007_3_gateway_configuration_validates` | `tests/scenarios/s007_header_contract.rs` | gateway | planned |
| S007-4 | `s007_4_values_survive_gateway` | `tests/scenarios/s007_header_contract.rs` | gateway | planned |
| S007-A1 | `s007_a1_client_identity_header_replaced` | `tests/scenarios/s007_header_contract.rs` | gateway | planned |
| S007-A2 | `s007_a2_oversized_identity_refused` | `tests/scenarios/s007_header_contract.rs` | gateway | planned |
| S007-A3 | `s007_a3_spoofed_context_on_portal_route` | `tests/scenarios/s007_header_contract.rs` | gateway | planned |
| S007-A4 | `s007_a4_unauthenticated_identity_headers_stripped` | `tests/scenarios/s007_header_contract.rs` | gateway | planned |
| S007-A5 | `s007_a5_duplicate_cookie_fields_joined` | `tests/scenarios/s007_header_contract.rs` | gateway | planned |

## Live verification

| Date | Hopae version | Gateway version | Provider | Environment label | Result | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| — | — | — | — | — | — | Spoof test is part of the G9 smoke test. |

## Open questions

- Does the gateway's config validation endpoint accept a configuration without a live listener in the test environment, or must the harness start a full gateway for S007-3?

## 한국어 요약

실제 게이트웨이를 통해 업스트림은 Hopae가 세션에 대해 내보낸 신원 헤더만
받습니다. 클라이언트가 같은 이름의 헤더나 게이트웨이 맥락 헤더를 보내도
게이트웨이 전체에서 제거되어 업스트림이나 Hopae에 도달하지 않습니다.
인증되지 않은 요청은 업스트림에 전혀 전달되지 않습니다.
