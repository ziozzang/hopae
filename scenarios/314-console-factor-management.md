# S314 — An administrator lists a user's factors and resets one or all of them

<!-- scenario-status: draft -->

- Area: management
- Milestone: M5
- ADRs: 0016, 0017
- Threat model: TM-50, TM-65
- Gateway contract: none (admin listener)

## Goal

Support staff see which second factors a user has — each passkey by a `pk_`
factor id with the authenticator's name from its AAGUID, whether it is synced
or backed up, when it was last used; the authenticator app; the recovery codes
left — without any credential material, and an administrator removes all of
them, one passkey, the authenticator app or the recovery codes, ending exactly
the sessions the removed factor vouched for, with the reason recorded.

## Preconditions and fixtures

- `tests/fixtures/m4-admin.json`; administrators signed in through the real flow (scenario 301 kit).
- `u_f` laid down with SQL: a Titan security key (`42b4fb4a-…`, attested, `aal3`, last used two minutes ago) and a synced passkey (all-zero AAGUID); an active authenticator app; three recovery codes, one used, so re-enrollment is required; sessions `s_key` (elevated by the Titan key), `s_totp` (a TOTP factor entry) and `s_plain`.
- For S314-3, `admin.hangang_delegation.authority = hangang` and signed requests of Hangang actor 7.

## Main flow

### S314-1 The factor listing names authenticators without secrets

- Given: a viewer.
- When: `GET /v1/users/u_f/factors`.
- Then: `200`, `cache-control: no-store`; `second_factors: 3`, the authenticator app active, two recovery codes remaining and `reenrollment_required_at` set; the Titan key with its AAGUID, the name `Google Titan Security Key`, `kind: device_bound`, `assurance: aal3`, `backup_state: false`, `last_used_at` and transports; the synced passkey with `aaguid` and `authenticator` `null`, `kind: synced`, `backup_state: true`; no credential id, serialized key or code hash anywhere; an `admin.read` record with `purpose: users.factors`; a malformed id is `400 invalid_id`, an unknown user `404 not_found`.

### S314-2 A reset removes its scope and the sessions that factor vouched for

- Given: an administrator and a viewer.
- When: the viewer resets; malformed requests; a reason with a bidirectional override; an unknown `pk_` id; the Titan key with a reason; the authenticator app; the recovery codes twice; everything; the administrator's own factors; a request without the JSON API header.
- Then: `403 role_insufficient`; `400 invalid_request` for each malformed body; `400 invalid_reason`; `404 factor_not_found`; the passkey reset ends `s_key` only and records `admin.factor_reset` with `scope`, `factor_id`, `note` and the actor; the TOTP reset ends `s_totp` only; the recovery-code reset ends nothing and its repetition answers `changed: false` without a record; `all` ends `s_plain` and clears the re-enrollment requirement; `403 self_target`; `403 csrf_rejected`.

## Alternative flows

### S314-3 The Hangang console lists and resets factors

- Given: the Hangang authority.
- When: `users/factors` and `users/factors/reset` (passkey scope, reason) as signed requests; a replayed nonce, a malformed id, an unknown field, a reset without `id`.
- Then: `200` with the same answers; the record carries `delegated_actor: 7:operator` and the note; each refusal is `403`.

## Abuse cases

| Category | Case | Applies |
| --- | --- | --- |
| Replay | S314-3 | yes: a replayed signed reset is refused |
| Tampering | S314-2 | yes: malformed scopes, ids and reasons change nothing |
| Race / timing | — | covered by store test `console_factor_reset_removes_what_its_scope_names_and_the_sessions_it_vouched_for` (the fence and the reset in one transaction) |
| Resource exhaustion | — | no: one user per request, listings rate-limited per actor |
| Confused deputy | S314-2 | yes: a viewer cannot reset; one's own factors cannot be reset |
| Spoofed or duplicated headers | S314-2 | yes: the JSON API rule |
| Downgrade | — | no |
| Enumeration | S314-1 | yes: an unknown user is `404` only to a grant holder, who can list users anyway |

## Observability expectations

- Audit: `admin.read` (`users.factors`) per listing; `admin.factor_reset` per change with `scope`, `factor_id`, `count`, `note`; `session.terminated` (`reason=factor_reset`) per ended session.
- Metrics: `hopae_admin_mutations_total{kind="factor_reset"}`.

## Test mapping

| Case | Test | File | Kind | Status |
| --- | --- | --- | --- | --- |
| S314-1 | `s314_1_factor_listing_names_authenticators_without_secrets` | `tests/scenarios/s314_admin_api_gaps.rs` | integration | passing |
| S314-2 | `s314_2_a_reset_removes_its_scope_and_the_sessions_that_factor_vouched_for` | `tests/scenarios/s314_admin_api_gaps.rs` | integration | passing |
| S314-3 | `s314_3_hangang_console_lists_and_resets_factors_with_its_actor_recorded` | `tests/scenarios/s314_admin_api_gaps.rs` | integration | passing |

## Live verification

| Date | Hopae version | Gateway version | Provider | Environment label | Result | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| — | — | — | — | — | — | Not yet run against a live Hangang console. |

## Open questions

- Should a reset also require the target to complete a fresh primary sign-in before enrolling (it does today only through the existing factor-management freshness rule)?

## 한국어 요약

지원 담당자는 사용자의 2차 인증 요소를 자격 증명 자료 없이 봅니다. 패스키는 `pk_` ID,
AAGUID에서 얻은 인증기 이름, 동기화·백업 여부, 마지막 사용 시각으로, 인증 앱과 남은 복구
코드와 함께 보입니다. 관리자는 전부·패스키 하나·인증 앱·복구 코드를 초기화하며, 제거한
요소가 보증한 세션만 끝나고 사유가 기록됩니다. 자기 인증 요소 초기화와 viewer의 초기화는
거부됩니다.
