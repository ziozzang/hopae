# S317 — Profile and projection publications are audited, and profiles can be validated without publishing

<!-- scenario-status: draft -->

- Area: management
- Milestone: M4
- ADRs: 0016, 0009
- Threat model: TM-44
- Gateway contract: none (admin listener)

## Goal

Every console publication of the service authentication profiles or the
credential projection plans leaves an `admin.*` record with its revision,
status and reason in its own transaction, and an operator learns every problem
of a candidate profile document, with the path of each, before publishing it.

## Preconditions and fixtures

- `tests/fixtures/m4-admin.json` with an authentication gateway profile for `app.example.test` (an API key declared by variable) and, for the delegated parts, a credential projection plan and `admin.hangang_delegation.authority = hangang`.

## Main flow

### S317-1 Publications are recorded with their reason

- Given: an administrator.
- When: `PUT /v1/authentication/profiles` with `If-Match` and a reason; the same revision again; a reason with a NUL; delegated `authentication/projections/publish` and `authentication/profiles/publish` with reasons.
- Then: `admin.profiles_publish` with `note`, the new `revision`, `status: disabled` and the actor; the stale publication is `409` and records nothing; `400 invalid_reason`; `admin.projections_publish` and `admin.profiles_publish` with the notes and `delegated_actor`.

### S317-2 Profile validation reports paths without publishing

- Given: a viewer.
- When: `POST /v1/authentication/profiles/validate` with a valid document; `null`; a port that is a string; an unknown field; an undeclared API key variable; a second profile for a host no application serves; a request without the JSON API header; an unknown top-level field; a delegated validation.
- Then: `valid: true` with no errors; `valid: true`; `invalid_document` at `profiles[0].ports[1]`; at `profiles[0].colour`; `undeclared_reference` at `profiles[0].api_keys[0].token_env`; a finding at `profiles[1]`; the published revision is unchanged; the last `admin.read` has `purpose: profiles.validate`; `403`; `400`; `valid: true`.

## Alternative flows

- None beyond the cases above.

## Abuse cases

| Category | Case | Applies |
| --- | --- | --- |
| Replay | — | covered by S306 |
| Tampering | S317-1 | yes: a conflicting publication leaves no record |
| Race / timing | S317-1 | yes: the record is in the publication's transaction |
| Resource exhaustion | — | no: validation runs on the bounded profile worker pool and a per-actor bucket |
| Confused deputy | S317-2 | yes: a viewer can validate but not publish |
| Spoofed or duplicated headers | S317-2 | yes: the JSON API rule |
| Downgrade | — | no |
| Enumeration | — | no: messages name variables, never values |

## Observability expectations

- Audit: `admin.profiles_publish`, `admin.projections_publish`, `admin.read` (`profiles.validate`).

## Test mapping

| Case | Test | File | Kind | Status |
| --- | --- | --- | --- | --- |
| S317-1 | `s317_1_publications_are_recorded_with_their_reason` | `tests/scenarios/s314_admin_api_gaps.rs` | integration | passing |
| S317-2 | `s317_2_profile_validation_reports_paths_without_publishing` | `tests/scenarios/s314_admin_api_gaps.rs` | integration | passing |

## Live verification

| Date | Hopae version | Gateway version | Provider | Environment label | Result | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| — | — | — | — | — | — | Not yet run against a live Hangang console. |

## Open questions

- A dry run for projection plans is not offered yet.

## 한국어 요약

서비스 인증 프로필과 자격 증명 투영 계획의 콘솔 게시는 같은 트랜잭션 안에서 리비전,
상태, 사유가 담긴 `admin.*` 기록을 남기고, 충돌한 게시는 아무것도 기록하지 않습니다.
운영자는 게시 전에 후보 프로필 문서의 모든 문제를 경로와 함께 받아 볼 수 있습니다.
