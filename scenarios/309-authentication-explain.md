# S309 — Authentication explain: an operator learns what the gateway would answer and why, without side effects

<!-- scenario-status: implemented -->

- Area: management
- Milestone: M4
- ADRs: 0004, 0007, 0008, 0016; Hangang ADR 0019 (explain/simulate), Hangang ADR 0020
- Threat model: TM-45, TM-61
- Gateway contract: Verify endpoint (status codes the explain answer predicts)

## Goal

A grant holder asks, for a URL and a session, a subject or nobody, which
application policy or service profile applies, which providers, factors,
assurance level, step-up rule and freshness bound are involved and what the
gateway's authentication check would answer, and gets the same answer the
live verify endpoint gives on the same state, with stable reason codes and
English and Korean messages — while the simulation writes nothing but its
audit record.

## Preconditions and fixtures

- Configuration and administrators as in scenario 307: application `app` with step-up rules (AAL 2 under `/admin`, a 600 s sign-in age under `/fresh`), no second factor configured; application `api` behind the API-key profile `api` (networks `192.0.2.0/24`, subjects `worker` and the expired `retired`, no session fallback) with an AAL 2 rule under `/admin`.
- Sessions laid down with SQL, each with a handle on `app.example.test` bound to `192.0.2.10`; the instance's injected clock.

## Main flow

### S309-1 Explain matches live verify for every session state

- Given: sessions `s_live` (60 s old), `s_old` (one hour), `s_idle` (13 hours without activity), `s_term` (terminated), `s_bind`, `s_off` (its user disabled).
- When: each case is explained (`POST /v1/explain/authentication` with `url`, `session_id`, `client_ip`, `navigation`) and then sent to the live verify endpoint with the session's handle: `/x` as document and fetch; `/admin/x` as document and fetch; `/fresh` with `s_live`; `/fresh/x` with `s_old` as document and fetch; `/x` with `s_idle`, `s_term`, `s_off`; `/x` with `s_bind` from `198.51.100.1`; `/_hopae/other`; an unknown host; a port the application does not list.
- Then: the explain outcome and reason are `allow/allowed`, `deny/step_up_unavailable` (document, no factor configured), `login/step_up_required` (fetch), `reauth/reauth_required` (document) and `login/step_up_required` (fetch) for the stale sign-in, `login/idle`, `login/session_terminated`, `login/binding_ip`, `login/user_disabled`, `deny/reserved_path`, `deny/unknown_app`, `deny/port_not_allowed`; in every case `status_code` equals the live answer's status.

### S309-2 Anonymous and hypothetical subjects explain the requirements

- Given: `u_h` (identity on `mock`), the disabled `u_off`, a session `s_portal` with a handle on the portal host only.
- When: anonymous `/admin/x`; `u_h` with `hypothetical: {aal: 2, factors: ["totp"]}`; `u_h` at `/fresh` with `auth_age_seconds: 900`; `u_off`; `u_never` and a `human1:` subject; `s_portal` at `/x`; anonymous with `at` one day ahead.
- Then: anonymous is `login` (`302`) with `required_aal: 2`, `achievable_aal: 1`, the provider list and `after_login` `deny/step_up_unavailable` deciding by rule 0; the AAL 2 hypothesis is `allow` after sign-in with `u_h`'s masked display data, linked provider and default provider `mock`; the 900 s sign-in needs `reauth` with `max_age_seconds: 600`; `u_off` signs in to `deny/user_disabled`; unknown subjects are `indeterminate/subject_unknown`; `s_portal` is `login/handle_absent` and `allow` after the handoff (`basis: handoff`); `evaluated_at` is the requested time.

## Alternative flows

### S309-3 Explain changes no state

- Given: `u_q` with an idle-expired session `s_q` and a live session `s_r`.
- When: explain `s_q`, `s_r` from another address, `s_r` at `/fresh`, and `u_q` at `/admin`.
- Then: every answer has `simulated: true`; the sessions' termination, `last_seen_at` and credential generation, the handles' revocation and `last_seen_at`, the login transactions, the handoff codes and `u_q`'s events are unchanged; four `admin.read` records exist; the idle handle is not revoked.

### S309-4 Service profiles are explained with the live predicates

- Given: the `api` profile.
- When: each case is explained as a fetch and then sent to the live verify endpoint with the matching bearer credential: `worker` from inside and outside the networks; `retired`; `worker` at `/admin`; an unconfigured `s_` principal (unknown credential); a user without a credential; `worker` without a client address; `worker` on `app.example.test`.
- Then: `allow/allowed`, `deny/network_denied`, `deny/credential_expired`, `deny/machine_step_up`, `deny/service_principal_unknown`, `deny/service_credential_required`, each with `service_profile` (`service_id: api`, `connectors: ["api_key"]`) and a `status_code` equal to the live status (`200`, `401`, `401`, `403`, `401`, `401`); without an address the trace says `network_not_evaluated` and the assurance is AAL 0; on a host without a profile the answer is `service_profile_absent` (`401`); no credential value or variable name appears.

### S309-5 Reasons carry stable codes and localized messages

- Given: the anonymous `/admin` request.
- When: explained with no `accept-language` and with `accept-language: ko-KR,ko;q=0.9`.
- Then: both answers carry `code: hopae.step_up_unavailable` and `message_key: hopae.explain.step_up_unavailable`; the message is English in the first and Korean in the second; every trace step names its check and result and every reason has a message.

## Abuse cases

| Category | Case | Applies |
| --- | --- | --- |
| Replay | — | no: a simulation has no effect to repeat; delegated replay is 307-5 |
| Tampering | S309-A1 | yes |
| Race / timing | S309-3 | yes: the simulation never terminates, revokes or touches what it evaluates, so it cannot race the live path |
| Resource exhaustion | S309-A2 | yes |
| Confused deputy | S309-3 | yes: the simulation cannot be used to create a session, handle, transaction or handoff code |
| Spoofed or duplicated headers | — | no: the request rule is 307-A2; the simulated client address is data, never the caller's |
| Downgrade | — | no: no negotiation |
| Enumeration | — | no: ungranted callers are 307-A4 |

### S309-A1 Malformed simulations are refused

- Given: an administrator.
- When: no URL, an unparsable URL, both `session_id` and `subject`, a malformed session ID, a time more than 30 days away in either direction, `aal: 5`, an unknown factor kind or `auth_time_source`, an unknown navigation, a malformed address, an unknown field, a URL over 2,048 bytes; then a URL with an encoded slash.
- Then: `400 invalid_request` without an `admin.read` record for each malformed request; the encoded slash is explained as `deny/path_not_canonical` and recorded.

### S309-A2 Explain is rate-limited and audited

- Given: `u_t` with a live session `s_t`.
- When: `s_t` is explained, then anonymous requests repeat.
- Then: the first record is `admin.read` with `purpose: explain.authentication`, `status: allow`, `host`, `app`, `user_id: u_t`, `session_id: s_t`; after the burst (30 plus what refilled) `429 rate_limited` with `retry-after`; one record per answered explain.

## Observability expectations

- Log: `administrative read rate limit reached` (warn).
- Audit: `admin.read` per answered explain with the outcome, target host, application, and the evaluated user and session in the event's columns.
- Metrics: `hopae_events_total{kind="admin.read"}`, `hopae_admin_requests_total{outcome}`.

## Test mapping

| Case | Test | File | Kind | Status |
| --- | --- | --- | --- | --- |
| S309-1 | `s309_1_explain_matches_live_verify_for_session_states` | `tests/scenarios/s309_authentication_explain.rs` | integration | passing |
| S309-2 | `s309_2_anonymous_and_hypothetical_subjects_explain_requirements` | `tests/scenarios/s309_authentication_explain.rs` | integration | passing |
| S309-3 | `s309_3_explain_changes_no_state` | `tests/scenarios/s309_authentication_explain.rs` | integration | passing |
| S309-4 | `s309_4_service_profiles_are_explained_with_live_predicates` | `tests/scenarios/s309_authentication_explain.rs` | integration | passing |
| S309-5 | `s309_5_reasons_carry_stable_codes_and_localized_messages` | `tests/scenarios/s309_authentication_explain.rs` | integration | passing |
| S309-A1 | `s309_a1_malformed_simulations_are_refused` | `tests/scenarios/s309_authentication_explain.rs` | integration | passing |
| S309-A2 | `s309_a2_explain_is_rate_limited_and_audited` | `tests/scenarios/s309_authentication_explain.rs` | integration | passing |

## Live verification

| Date | Hopae version | Gateway version | Provider | Environment label | Result | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| — | — | — | — | — | — | Not yet run. |

## Open questions

- The parity cases run with no second factor configured; a step-up start (`step_up`, `302`) with a configured TOTP keyring is evaluated by the same code but not yet compared live.
- Should Hangang's orchestrated explain pass a candidate application policy (what-if) rather than the published one?

## 한국어 요약

운영자는 URL과 세션·주체·익명 요청에 대해 어떤 애플리케이션 정책이나 서비스 프로필,
제공자, 인증 수단, 보증 수준, 단계 상향 규칙, 신선도 한도가 적용되어 게이트웨이가 무엇을
답할지를 안정적인 사유 코드와 영어·한국어 메시지로 받습니다. 같은 상태에서 실제 verify
엔드포인트와 상태 코드가 일치함을 비교하며, 핵심 남용 사례는 모의가 세션·핸들·트랜잭션을
만들거나 종료·갱신하는 부작용이고 이는 일어나지 않습니다.
