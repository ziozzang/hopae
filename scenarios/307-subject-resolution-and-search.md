# S307 — Subject resolution and search: the console shows people, not hashes

<!-- scenario-status: implemented -->

- Area: management
- Milestone: M4
- ADRs: 0016; Hangang ADR 0020 (subject resolution), Hangang ADR 0021 (display names)
- Threat model: TM-45, TM-60
- Gateway contract: n/a

## Goal

A grant holder or a Hangang delegated console actor turns up to 100 opaque
subject references into display data in one audited read, and searches
people and service principals for a picker, while personal data stays masked
by default, unknown references are answered explicitly, credential material
never leaves and no read goes unrecorded or unbounded.

## Preconditions and fixtures

- Configuration `tests/fixtures/m4-admin.json` plus the overrides of `dkit::overrides` (`tests/scenarios/s307_subject_directory.rs`): application `api` on `api.example.test`, a service profile `api` (realm `svc`, networks `192.0.2.0/24`) with API-key subjects `worker` and `retired` (expired), and step-up rules on `app`.
- Users laid down with SQL: `u_live` (active, identity on `mock`, one session), `u_off` (disabled), `u_gone` (created, then its row deleted: a tombstone in the reservation ledger).
- Administrators signed in through the real portal flow and granted with the store (`kit` of scenario 301).

## Main flow

### S307-1 User IDs resolve with status, tombstones and masking

- Given: the users above.
- When: `POST /v1/subjects/resolve` with `{"ids":["u_live","u_off","u_gone","u_never","alice","u_live"]}`, then with `"privacy_profile":"strict"`.
- Then: `200`, `cache-control: no-store`; five items in first-occurrence order; `u_live` is `active`, `kind: human`, its display name, `email: "a***@example.test"`, `providers: ["mock"]`, creation and last-seen times; `u_off` is `disabled`; `u_gone` is `deleted` with no display name or e-mail; `u_never` is `unknown`/`not_found`; `alice` is `unknown`/`unrecognized`; `resolved: 3`, `unknown: 2`; no unmasked address appears; under `strict` the display name stays and no e-mail is returned.

### S307-2 Service and unconfigured references resolve explicitly

- Given: the service profile above; Human receipts not configured.
- When: resolve `s_` of `worker`, `s_` of `retired`, an unconfigured `s_<48 hex>`, a `human1:<64 hex>` and a session ID.
- Then: `worker` is `active`, `kind: service`, `display_name: "worker (api)"`, `service_id: api`, `realm: svc`; `retired` is `disabled`/`credential_expired`; the stranger is `unknown`/`not_enumerable`; the Human subject is `unknown`/`human_subjects_not_configured`; the session ID is `unrecognized`; no credential value or environment variable name appears in the answer.

## Alternative flows

### S307-3 Search people and service principals with a cursor

- Given: five users `dana0`…`dana4` and `erin`.
- When: `POST /v1/subjects/search` with `{"q":"dana","limit":2}` following `next_cursor`; `q: "NUMBER3"`; `q: "u_other"`; `q: "u_srch1"` with `status: disabled`; `kind: service` with `q: "work"` and with `q: "svc", limit: 1` following the cursor.
- Then: the walk returns each `dana` once with masked addresses; the display-name match is case-insensitive; an exact user ID is answered as a resolution and filtered by status; the service search returns `worker` alone for `work` and both principals one per page for `svc`.

### S307-4 Every read is audited without identifiers

- Given: the users of 307-1.
- When: one resolution of two references and one search.
- Then: two `admin.read` events, `outcome: success`, with `attrs.actor`, `attrs.purpose` (`subjects.resolve`, `subjects.search`), `attrs.endpoint`, `attrs.query_sha256` (64 hex), `attrs.requested: 2`, `attrs.count: 1`, `attrs.status: partial`; neither event contains a reference, the search text or an e-mail domain.

### S307-5 A delegated console actor resolves through the signed adapter

- Given: `admin.hangang_delegation` with a sessions file mapping actor `7:operator` to a viewer's console handle.
- When: a signed `POST /v1/subjects/resolve` (the assertion covers the exact body); the same nonce again; a fresh nonce over a body that differs from the signed one.
- Then: `200` with `u_live` `active`; the replay and the altered body are `403 delegation_rejected`; the `admin.read` record carries `attrs.delegated_actor: "7:operator"`.

## Abuse cases

| Category | Case | Applies |
| --- | --- | --- |
| Replay | S307-5 | yes: a replayed delegated read is refused by the durable nonce admission |
| Tampering | S307-A1, S307-5 | yes |
| Race / timing | — | no: reads take no lock other than the Human index's, bounded by the request budget (`index_incomplete`) |
| Resource exhaustion | S307-A1, S307-A3 | yes |
| Confused deputy | S307-A2 | yes |
| Spoofed or duplicated headers | S307-A2 | yes |
| Downgrade | — | no: no negotiation; the transport is 300-A7 |
| Enumeration | S307-A4 | yes |

### S307-A1 Batch and reference bounds are enforced before any read

- Given: an administrator.
- When: resolve 101 references, none, a 257-byte reference, an empty reference, an unknown field, a non-list, an unknown privacy profile; search with an empty, a 129-character or a control-character query, `limit` 0 or 51, an unknown kind or status, a forged cursor.
- Then: `400 invalid_request` (`invalid_cursor` for the cursor) for each, no `admin.read` record; 100 references are accepted.

### S307-A2 Reads require the JSON API rule

- Given: an administrator's console handle.
- When: the resolution posted as `text/plain`, without `x-hopae-admin-request`, as a form, with a foreign `Origin`, with `sec-fetch-site: cross-site`; `GET /v1/subjects/resolve`.
- Then: `403 csrf_rejected` for each post, `405` for the `GET`, no `admin.read` record.

### S307-A3 Reads are rate-limited per actor

- Given: two administrators.
- When: the first resolves repeatedly.
- Then: after the burst (60 plus what refilled meanwhile) `429 rate_limited` with `retry-after` between 1 and 60; the second administrator and the first administrator's searches are unaffected.

### S307-A4 Unauthenticated and ungranted callers learn nothing

- Given: no handle; a signed-in user without a grant.
- When: the four directory reads and the explain API.
- Then: `403 login_required` resp. `403 not_admin` without any directory data and without an `admin.read` record.

## Observability expectations

- Log: `administrative read rate limit reached` (warn) with the request id and purpose; `admin.read could not be recorded` (error) when the audit append fails.
- Audit: `admin.read` (required) per answered read, attributes as in 307-4.
- Metrics: `hopae_events_total{kind="admin.read"}`, `hopae_admin_requests_total{outcome}`, `hopae_admin_rows_examined_total{list="subjects"}`.

## Test mapping

| Case | Test | File | Kind | Status |
| --- | --- | --- | --- | --- |
| S307-1 | `s307_1_user_ids_resolve_with_status_tombstone_and_masking` | `tests/scenarios/s307_subject_directory.rs` | integration | passing |
| S307-2 | `s307_2_service_and_unconfigured_references_resolve_explicitly` | `tests/scenarios/s307_subject_directory.rs` | integration | passing |
| S307-3 | `s307_3_search_people_and_service_principals_with_cursor` | `tests/scenarios/s307_subject_directory.rs` | integration | passing |
| S307-4 | `s307_4_every_read_is_audited_without_identifiers` | `tests/scenarios/s307_subject_directory.rs` | integration | passing |
| S307-5 | `s307_5_delegated_console_actor_resolves` | `tests/scenarios/s307_subject_directory.rs` | integration | passing |
| S307-A1 | `s307_a1_batch_and_reference_bounds` | `tests/scenarios/s307_subject_directory.rs` | integration | passing |
| S307-A2 | `s307_a2_reads_require_the_json_api_rule` | `tests/scenarios/s307_subject_directory.rs` | integration | passing |
| S307-A3 | `s307_a3_per_actor_rate_limit` | `tests/scenarios/s307_subject_directory.rs` | integration | passing |
| S307-A4 | `s307_a4_unauthenticated_and_ungranted_callers_learn_nothing` | `tests/scenarios/s307_subject_directory.rs` | integration | passing |

Human subject resolution (`human1:` with Human receipts configured) is covered
by the unit test `admin::subjects::tests::the_index_resolves_live_and_deleted_subjects_and_misses_nothing_else`
because the integration fixture cannot configure an authenticated mTLS Human
issuer.

## Live verification

| Date | Hopae version | Gateway version | Provider | Environment label | Result | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| — | — | — | — | — | — | Not yet run. |

## Open questions

- Should an operator be able to set a minimum privacy profile (for example `strict` only) in the configuration rather than per request?

## 한국어 요약

콘솔은 최대 100개의 불투명한 주체 참조(`u_…`, `human1:…`, `s_…`)를 한 번의 감사된
읽기로 표시 이름, 가린 이메일, 종류, 상태(묘비 포함)로 해석하고, 알 수 없는 참조는
오류가 아니라 `unknown`과 사유로 답합니다. 핵심 남용 사례는 JSON API 규칙을 지키지
않은 교차 출처 요청과 행위자별 속도 제한 초과이며, 둘 다 기록 없이 거부됩니다.
