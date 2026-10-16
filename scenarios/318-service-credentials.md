# S318 — Service credentials: a machine caller reads its exact routes over mTLS and nothing else

<!-- scenario-status: implemented -->

- Area: management, security
- Milestone: M4
- ADRs: 0016; Hangang ADR 0021 (Pumgye consumes the membership projection and subject lifecycle)
- Threat model: TM-75, TM-76, TM-77
- Gateway contract: n/a (admin listener)

## Goal

Pumgye (or another machine caller) authenticates to the admin listener with
its pinned client certificate and a route-scoped bearer, reads exactly the
projection and lifecycle routes it was granted toward this instance's
audience, and can never reach another route, a mutation, or work without the
certificate, while every read is audited with the credential id.

## Preconditions and fixtures

- In-process instance (`hopae::app::bind`) with `admin.public_url =
  https://hopae-admin.example.test`, `listen.admin` on loopback and
  `listen.admin_tls` with a generated CA, server certificate and two client
  certificates (same SAN `spiffe://cluster.example.test/ns/world/sa/pumgye`,
  different keys), all generated in the test with the `openssl` crate.
- A second instance without `admin_tls` (`untrusted_peers = as_client`) for the
  transport case.
- Credentials created through the real CLI entry point
  (`app::admin_cli_with`): preset `pumgye-v2` plus `POST /v1/subjects/resolve`,
  SPKI pin of the first client certificate and the SAN.

## Main flow

### S318-1 The granted reads succeed and are audited

- Given: credential `pumgye-v2`.
- When: `POST /v1/subjects/lifecycle`, `/v1/subjects/lifecycle/snapshot`, `/v1/subjects/resolve` and `/v1/groups/projection/snapshot` with the token, `x-hopae-audience` and the pinned certificate.
- Then: `200` for the lifecycle and resolve reads; the projection route is admitted (its own configuration answers, never `401`/`403`); the `admin.read` records carry `actor = service:pumgye-v2`, `credential_id` and `credential_slot = current`; the store holds a 64-hex digest and never the secret.

### S318-2 Every other combination is refused

- Given: credential `pumgye-v2` with burst 6.
- When: a forged secret; an unknown id; the right token with the other client key; no audience; a foreign audience; an ungranted read (`/v1/subjects/search`); a mutation (`/v1/groups/create`) after the stored routes were tampered to include it; the certificate without a token; then eight reads.
- Then: `401 service_credential_rejected`, `401`, `403 service_binding_mismatch`, `403 service_audience_mismatch` twice, `403 service_route_forbidden` twice, a refusal without administrator rights, and `429 rate_limited` once the bucket is empty.

## Alternative flows

### S318-3 Rotation, promotion, expiry, revocation and transport

- Given: credential `pumgye-v2`.
- When: `rotate`; both secrets read; a second `rotate`; `promote`; reads with the old and new secret; expiry moved into the past and back; `revoke`; `rotate` after revocation; `list`; and the token on an instance without admin mTLS.
- Then: both secrets work during the rotation (`credential_slot = next` recorded), the second rotation is refused, after promotion the old secret is `401`, expiry and revocation are `401`, a revoked credential refuses changes, `list` shows `revoked` without any secret, the change events are `created, rotated, promoted, revoked`, and the plain listener answers `403 service_transport_required`.

## Abuse cases

| Category | Case | Applies |
| --- | --- | --- |
| Replay | S318-2 | yes: the token is useless without the pinned certificate and toward another audience |
| Tampering | S318-2 | yes: a stored mutation route is still refused |
| Race / timing | S318-3 | yes: rotation keeps both secrets; promotion and revocation apply on the next request |
| Resource exhaustion | S318-2 | yes: per-credential bucket |
| Confused deputy | S318-2 | yes: the certificate alone grants nothing; a delegation cannot be combined |
| Spoofed or duplicated headers | S318-2 | yes: duplicate `Authorization`/`x-hopae-audience` refuse; forwarding headers are not trusted on the mTLS path |
| Downgrade | S318-3 | yes: a plain listener never accepts a service token |
| Enumeration | S318-2 | yes: unknown id, wrong secret, revoked and expired give one answer |

### S318-A1 The CLI never creates a mutation-capable or unbound credential

- Given: the CLI.
- When: create with a mutation route, a profile publication, an unknown route, no binding, a malformed id, a lifetime of 401 days, a malformed pin, an unknown preset; then a valid create twice.
- Then: each invalid create fails without printing a token; the first valid create succeeds and the second is refused (ids are never reused); one row exists.

## Observability expectations

- Log: `service credential refused` warnings with the refusal code and path, never the token.
- Audit: `admin.read` with `credential_id`, `credential_slot`, `actor = service:<id>`; `admin.service_credential` with `change` and `credential_id`.
- Metrics: `hopae_admin_service_credentials_total{result}`.

## Test mapping

| Case | Test | File | Kind | Status |
| --- | --- | --- | --- | --- |
| S318-1 | `s318_1_scoped_credential_reads_lifecycle_and_is_audited` | `tests/scenarios/s318_service_credentials.rs` | integration | passing |
| S318-2 | `s318_2_refusals_are_route_binding_audience_and_rate_scoped` | `tests/scenarios/s318_service_credentials.rs` | integration | passing |
| S318-3 | `s318_3_rotation_promotion_revocation_expiry_and_transport` | `tests/scenarios/s318_service_credentials.rs` | integration | passing |
| S318-A1 | `s318_a1_cli_refuses_mutations_unbound_and_malformed_credentials` | `tests/scenarios/s318_service_credentials.rs` | integration | passing |

## Live verification

| Date | Hopae version | Gateway version | Provider | Environment label | Result | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| — | — | — | — | — | not run | Pumgye interop against a real Pumgye binary is the next step (its relay becomes unnecessary). |

## Open questions

- Pumgye client changes: send `x-hopae-audience` and present the pinned client certificate directly (replacing the interop relay).

## 한국어 요약

기계 호출자는 고정된 클라이언트 인증서와 경로 범위 bearer로 관리 리스너에 인증하며, 이 인스턴스의 audience를 향한 허용된 읽기 경로만 읽을 수 있고 모든 읽기는 자격 증명 id와 함께 감사됩니다. 인증서 없는 토큰, 다른 키, 다른 audience, 허용되지 않은 경로, 변조로 저장된 변경 경로, 평문 리스너는 모두 거부됩니다.
