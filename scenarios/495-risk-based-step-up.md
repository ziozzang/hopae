# S495 — The gateway's network evidence drives a fresh step-up or a denial

<!-- scenario-status: draft -->

- Area: 2fa
- Milestone: M5
- ADRs: 0023, 0008, 0018
- Threat model: TM-79, TM-80
- Gateway contract: `x-hopae-risk-context` ([risk context](../docs/GATEWAY_CONTRACT.md#risk-context)); `risk_denied`, `risk_context_invalid`, `risk_context_missing`

## Goal

An application can require a fresh second factor when the gateway reports
elevated risk or the session's country changes, and can deny high risk. A
risk context that is not the gateway's, or that belongs to another request,
is refused.

## Preconditions and fixtures

- `tests/fixtures/m1-basic.json` with `risk.context_key_env` (`HOPAE_TEST_RISK_KEY`).
- `app` has three risk rules:
  1. `/admin` and `level_at_least: elevated` → step-up AAL 2 within 600 s.
  2. `country_changed` → step-up AAL 2 within 300 s.
  3. `level_at_least: high` → deny.
- An AAL 2 session whose TOTP is an hour old, or 10 s old for the "fresh" cases.
- Contexts are signed with `hopae::policy::risk::Keys::sign`.

## Main flow

### S495-1 Elevated risk asks for a fresh factor; high risk is denied

- Given: the session with an hour-old factor.
- When: `/admin/x` is requested with a `low`, an `elevated` and a `high`
  context, and also anonymously with `high`. A session with a fresh factor
  then requests `/admin/x` with an `elevated` context.
- Then:
  - `low` is allowed.
  - `elevated` requires a step-up.
  - `high` is `risk_denied`, with or without a session.
  - The fresh factor satisfies the elevated rule.
  - `hopae_risk_decisions_total{action="step_up"}` is counted.

## Alternative flows

### S495-2 A change of country steps up once

- Given: the session.
- When: `/public` is requested from `KR` twice, then from `JP`, then from
  `KR` again. A fresh-factor session moves `KR`, then `JP`, then `JP`.
- Then:
  - The first session: `KR` is allowed and remembered, `JP` requires a
    step-up, and `KR` is allowed again because a step-up records nothing.
  - The fresh session: allowed throughout; after the move `JP` is
    remembered.

### S495-4 A missing context follows the application

- Given: `risk.missing` of `ignore` (the default), `deny`, and a step-up.
- When: a request carries no context.
- Then: allowed; `risk_context_missing`; a step-up.

### S495-5 Through the gateway listener

- Given: a running Hopae with the key in the environment.
- When: verify calls carry each of the following, in order:
  1. no context;
  2. a client-typed value;
  3. a value signed with another key;
  4. a context signed for another client address;
  5. two headers;
  6. a signed `low` context;
  7. a signed `high` context.
- Then:
  - No context and the signed `low` context start a sign-in (`302`).
  - Cases 2 to 5 are each `403 risk_context_invalid`.
  - The signed `high` context is `403 risk_denied`.

### S495-6 Explain shows the risk inputs and decision

- Given: the console with the same rules.
- When: `explain/authentication` is called three times with hypothetical
  inputs: a `high` context; a `JP` context with a `KR` session memory and a
  factor 900 s old; no context.
- Then:
  - The `high` context: `after_login` is `deny` with `risk_denied`.
  - The `JP` context: `step_up.risk` shows `matched_rules` `[1]`, the
    context, the memory, and a 300 s requirement.
  - No context: `missing: true`, and the outcome is `allow`.

## Abuse cases

| Category | Case | Applies |
| --- | --- | --- |
| Replay | S495-3 | yes: a stale `iat` is refused |
| Tampering | S495-3 | yes: another key, a changed payload or unknown claims are refused; also the unit test `contexts_are_signed_bound_to_the_request_and_fresh` |
| Race / timing | — | no: one in-memory read per verify |
| Resource exhaustion | — | covered by unit test `the_memory_is_bounded_coarse_and_expires` |
| Confused deputy | S495-3 | yes: a context signed for another client address is refused |
| Spoofed or duplicated headers | S495-5 | yes: a client-typed header and two headers are refused |
| Downgrade | S495-4 | yes: `risk.missing` can deny or step up without a context |
| Enumeration | — | no |

### S495-3 Forged, stale, moved and duplicate contexts are refused

- Given: the session with a fresh factor.
- When: each of the following is presented: a context signed with another
  key; a stale context; a context signed for another client; a plain value;
  a duplicate header.
- Then: each is `risk_context_invalid`.

### S495-A1 The risk configuration is checked

- Given: each of the following:
  - `apps[].risk` without the top-level `risk`;
  - a rule without conditions;
  - `max_skew_secs: 1`;
  - a key shorter than 32 bytes;
  - a step-up without `max_age_secs`.
- When: `hopae --check`.
- Then: a non-zero exit for each.

## Observability expectations

- Events:
  - `risk.step_up_required` (diagnostic): `level`, `risk_reason`, `country`,
    `asn`, `rule`, `missing`.
  - `verify.denied` with `risk_denied`, `risk_context_invalid` or
    `risk_context_missing`.
- Metrics: `hopae_risk_decisions_total`, `hopae_risk_context_invalid_total`,
  `hopae_risk_memory_entries`.

## Test mapping

| Case | Test | File | Kind | Status |
| --- | --- | --- | --- | --- |
| S495-1 | `s495_1_an_elevated_context_requires_a_fresh_factor_and_high_is_denied` | `tests/scenarios/s495_risk_step_up.rs` | integration | passing |
| S495-2 | `s495_2_a_change_of_country_within_the_session_steps_up_once` | `tests/scenarios/s495_risk_step_up.rs` | integration | passing |
| S495-3 | `s495_3_forged_stale_moved_and_duplicate_contexts_are_refused` | `tests/scenarios/s495_risk_step_up.rs` | integration | passing |
| S495-4 | `s495_4_a_missing_context_follows_the_application` | `tests/scenarios/s495_risk_step_up.rs` | integration | passing |
| S495-5 | `s495_5_the_gateway_refuses_spoofed_and_accepts_signed_contexts` | `tests/scenarios/s495_risk_step_up.rs` | integration | passing |
| S495-6 | `s495_6_explain_shows_risk_inputs_and_decisions` | `tests/scenarios/s495_risk_step_up.rs` | integration | passing |
| S495-A1 | `s495_a1_risk_configuration_is_checked` | `tests/scenarios/s495_risk_step_up.rs` | integration | passing |

## Live verification

| Date | Hopae version | Gateway version | Provider | Environment label | Result | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| — | — | — | — | — | — | Hangang does not send the context yet (the Hangang side of the contract is a separate change). |

## Open questions

- A shared store for the session memory across replicas.
- Whether the gateway should also bind the context to Hangang's request id.

## 한국어 요약

게이트웨이가 위험을 `elevated`로 알리거나 세션의 국가가 바뀌면 애플리케이션은 최근 2차
인증을 요구할 수 있고, `high`는 거부할 수 있습니다. 게이트웨이의 키로 서명되지 않았거나
다른 요청·클라이언트에 묶인 컨텍스트, 오래되었거나 반복된 컨텍스트는 거부합니다.
explain은 가정한 컨텍스트와 메모리로 일치한 규칙과 결정을 보여 줍니다.
