# S600 — Prometheus metrics: a scraper reads bounded, subject-free series over mutual TLS

<!-- scenario-status: draft -->

- Area: scale-out
- Milestone: M7
- ADRs: 0016; Hangang ADR 0022 (Kubernetes-native package)
- Threat model: TM-75
- Gateway contract: n/a

## Goal

A Prometheus scraper reads `GET /metrics` on the admin listener with a
route-scoped service credential (`--preset metrics`) over mutual TLS and gets
the OpenMetrics exposition. The credential opens nothing else, and no series
names a subject, a user, an email or an address.

## Preconditions and fixtures

- S600-1, S600-2: the S318 fixture (`listen.admin_tls` with a generated CA, server and client certificates; the real `bind`/`run` and the real admin CLI).
- S600-1: a credential `prometheus` created with `--preset metrics`, bound to the client certificate's SPKI and SAN.
- S600-2: the same credential and a `pumgye-v2` credential.

## Main flow

### S600-1 The metrics preset scrapes the exposition

- Given: the `prometheus` credential.
- When: `GET /metrics` with its bearer and the client certificate, with `x-hopae-audience`, then without it, then with a foreign audience.
- Then:
  - `200` with `application/openmetrics-text; version=1.0.0`, ending in `# EOF`.
  - The body includes the families `hopae_auth_outcomes`, `hopae_verify_duration_seconds`, `hopae_grpc_requests`, `hopae_sessions_created`, `hopae_stepup_results`, `hopae_passkey_ceremonies`, `hopae_rate_limited` and `hopae_store_failures`.
  - The body includes the gauges `hopae_store_up 1`, `hopae_sessions_active`, `hopae_projection_feed_rows`, `hopae_lifecycle_feed_head` and `hopae_event_relay_backlog`.
  - `hopae_tls_leaf_expiry_seconds{name="admin"}` is about one day.
  - Each family is declared once, and the body holds neither the client SAN, nor an address, nor an `@`.
  - Without the audience header the scrape is still `200`; a foreign audience is `403`.

### S600-2 The route and the credential stay scoped

- Given: both credentials.
- When: `GET /metrics` without a bearer; with the `pumgye-v2` bearer; and `GET /v1/status` with the metrics bearer.
- Then:
  - Without a bearer, the console's unauthenticated answer and no metrics.
  - With the `pumgye-v2` bearer, `403 service_route_forbidden`.
  - The metrics bearer on `/v1/status` is `403`.

## Abuse cases

| Category | Case | Applies |
| --- | --- | --- |
| Replay | — | no: the bearer is bound to the client certificate (S318) |
| Tampering | — | no: the exposition is read-only |
| Race / timing | — | covered by unit tests: recording is atomic and lock-free |
| Resource exhaustion | — | covered by unit tests: each family has a fixed capacity and an overflow counter |
| Confused deputy | S600-2 | yes: the metrics credential opens no other route |
| Spoofed or duplicated headers | S600-1 | yes: a foreign audience is refused; only `GET /metrics` may omit it |
| Downgrade | — | no: mutual TLS is required as for every service credential |
| Enumeration | S600-1 | yes: no subject, user, email or address in any label |

## Observability expectations

- Log: none added.
- Audit: none (the scrape writes no `admin.read`).
- Metrics: the families listed in [operations](../docs/OPERATIONS.md#counters).

## Test mapping

| Case | Test | File | Kind | Status |
| --- | --- | --- | --- | --- |
| S600-1 | `s600_1_metrics_preset_scrapes_openmetrics_over_mtls` | `tests/scenarios/s600_metrics.rs` | integration | passing |
| S600-2 | `s600_2_metrics_needs_the_route_and_the_credential_opens_nothing_else` | `tests/scenarios/s600_metrics.rs` | integration | passing |

## Live verification

| Date | Hopae version | Gateway version | Provider | Environment label | Result | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| — | — | — | — | — | — | Not yet scraped by a Prometheus Operator on k3s. |

## Open questions

- Should a dedicated plaintext metrics port exist for clusters without a scraper client certificate? Today it does not: metrics stay on the mTLS admin listener.

## 한국어 요약

Prometheus 스크레이퍼는 관리 리스너의 `GET /metrics`를 상호 TLS로 읽습니다. 자격 증명은
`--preset metrics`로 만든 라우트 한정 서비스 자격 증명이며, 응답은 OpenMetrics 형식입니다.
이 자격 증명으로는 다른 경로를 열 수 없고, 어떤 시계열에도 주체, 사용자, 이메일, 주소가
나오지 않습니다.
