# S008 — Path-scoped protection through gateway routes

<!-- scenario-status: draft -->

- Area: core
- Milestone: M1
- ADRs: 0005, 0012
- Threat model: TM-06, TM-19
- Gateway contract: Hangang route fragments (path-scoped), Proposed gateway changes (none required)

## Goal

An operator protects only `/admin` of a host with a higher-priority route,
leaves the rest public, and the handoff still works on the protected prefix;
the documented route fragments are proven against the gateway, and the
manual registration of phase 0 (ADR-0012) is checked by preflight.

## Preconditions and fixtures

- Gateway layer with the two-route fragment from the contract page (`site-public` priority 0, `site-admin` priority 10, `path_match: segment_prefix`).
- Hopae configuration `tests/fixtures/m1-basic.json`; application `app` with host `app.example.test`.
- Echo upstream.

## Main flow

### S008-1 Public prefix needs no session

- Given: no cookie.
- When: `GET /` and `GET /admin-tools/x` through the gateway.
- Then: both reach the upstream without a verify call (`/admin-tools` is not a segment match for `/admin`); no identity headers; no transaction created.

### S008-2 Protected prefix redirects to the portal

- Given: no cookie.
- When: `GET /admin` and `GET /admin/x` through the gateway.
- Then: `302` to the portal; transaction `return_target` is `https://app.example.test/admin` and `/admin/x` respectively.

### S008-3 Handoff lands on the protected prefix

- Given: login completed for the transaction of `/admin/x`.
- When: the browser follows `https://app.example.test/admin/x?_hopae_handoff=K1`.
- Then: the `site-admin` route matches, the verify call consumes `K1`, the cookie is planted with `Path=/`, and the following `GET /admin/x` returns the upstream response with identity headers.

### S008-4 Cookie is sent on public paths but not used

- Given: cookie `H1` planted (`Path=/`).
- When: `GET /` through the gateway.
- Then: the public route does not call Hopae; the upstream receives the request with the `cookie` header (the application may ignore it) and without identity headers.

## Alternative flows

### S008-5 Preflight reports a missing route (phase 0 check)

- Given: `gateway.readonly_token_env` configured and the gateway's `GET /v1/routes/http` reachable; application `other` registered in Hopae with no route protecting `other.example.org`.
- When: `hopae --check`.
- Then: a warning `app other: no gateway route with auth.url pointing at this instance for host other.example.org`; exit status 0 (warning), or 2 with `--strict`.

### S008-6 Fragment validation

- Given: both fragments from the contract page.
- When: validated by the gateway's configuration validation.
- Then: accepted; a fragment with `forward_response: false` is accepted by the gateway but flagged by Hopae's drift check (phase 1, M2) as `forward_response_disabled`.

## Abuse cases

| Category | Case | Applies |
| --- | --- | --- |
| Replay | — | no: covered by 003 |
| Tampering | S008-A1 | yes |
| Race / timing | — | no |
| Resource exhaustion | — | no: route matching is the gateway's concern |
| Confused deputy | S008-A2 | yes |
| Spoofed or duplicated headers | S008-A3 | yes |
| Downgrade | S008-A4 | yes |
| Enumeration | — | no |

### S008-A1 Path tricks do not escape the protected prefix

- Given: no cookie.
- When: `GET /admin%2Fx`, `GET /ADMIN/x`, `GET /admin/../admin/x`, `GET //admin/x` through the gateway.
- Then: each either matches `site-admin` (→ `302`) or is rejected by the gateway's path normalization; none reaches the upstream under `/admin` without a session. The exact outcome per form is recorded from the gateway's behavior at G8 and fed back into this case.

### S008-A2 Identity headers on the public route are stripped too

- Given: client sends `x-forwarded-user: admin` to `GET /`.
- When: through the gateway.
- Then: the upstream saw no `x-forwarded-user` (gateway-wide stripping because the name is declared on `site-admin`).

### S008-A3 Host header games

- Given: `host: app.example.test` with `x-forwarded-host: other.example.org` from the client.
- When: `GET /admin/x` through the gateway.
- Then: the verify call carries `x-forwarded-host: app.example.test` (regenerated); the transaction targets `app.example.test`.

### S008-A4 Route without `access_mode: protected`

- Given: a variant fragment with `auth` present but `access_mode: legacy`.
- When: validated and exercised.
- Then: behavior is identical for verify (the gateway still calls `auth`); the drift check flags `access_mode_not_protected` as a warning because `protected` is the documented invariant.

## Observability expectations

- Log: preflight warnings as structured lines with `check=gateway_route`.
- Audit: none.
- Metrics: none.

## Test mapping

| Case | Test | File | Kind | Status |
| --- | --- | --- | --- | --- |
| S008-1 | `s008_1_public_prefix_no_session` | `tests/scenarios/s008_path_scope.rs` | gateway | planned |
| S008-2 | `s008_2_protected_prefix_redirects` | `tests/scenarios/s008_path_scope.rs` | gateway | planned |
| S008-3 | `s008_3_handoff_on_protected_prefix` | `tests/scenarios/s008_path_scope.rs` | gateway | planned |
| S008-4 | `s008_4_cookie_unused_on_public_paths` | `tests/scenarios/s008_path_scope.rs` | gateway | planned |
| S008-5 | `s008_5_preflight_reports_missing_route` | `tests/scenarios/s008_path_scope.rs` | integration | planned |
| S008-6 | `s008_6_fragment_validation` | `tests/scenarios/s008_path_scope.rs` | gateway | planned |
| S008-A1 | `s008_a1_path_tricks_do_not_escape` | `tests/scenarios/s008_path_scope.rs` | gateway | planned |
| S008-A2 | `s008_a2_identity_headers_stripped_on_public_route` | `tests/scenarios/s008_path_scope.rs` | gateway | planned |
| S008-A3 | `s008_a3_host_header_games` | `tests/scenarios/s008_path_scope.rs` | gateway | planned |
| S008-A4 | `s008_a4_route_without_protected_mode_flagged` | `tests/scenarios/s008_path_scope.rs` | gateway | planned |

## Live verification

| Date | Hopae version | Gateway version | Provider | Environment label | Result | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| — | — | — | — | — | — | Not yet run. |

## Open questions

- Is S008-5 (read-only gateway credential in Hopae) acceptable in M1, or does it wait for the phase-1 ADR review (ADR-0012 reviewer question)?

## 한국어 요약

호스트의 `/admin`만 우선순위가 높은 라우트로 보호하고 나머지는 공개로 두는
구성을 실제 게이트웨이로 증명합니다. 핸드오프는 보호된 접두사 위에서 그대로
동작하고, 공개 라우트에서도 신원 헤더 이름은 게이트웨이 전체에서 제거됩니다.
사전 점검은 라우트가 없는 애플리케이션을 경고합니다.
