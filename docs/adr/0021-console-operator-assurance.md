# ADR-0021: Console operators sign in through Hopae with a passkey, and the console checks a signed operator assertion

- Status: Proposed
- Date: 2026-10-17
- Deciders: designer, orchestrator (maintainer decision pending)
- Scenarios: 490
- Threat model: TM-78
- Supersedes: none
- Related: [ADR-0017](0017-webauthn-passkeys.md), [ADR-0018](0018-aal3-emission.md); Hangang console SSO (`src/console_sso.rs`), hangang-zerotrust `IDENTITY.md` (delegated management)

## Context

- The Hangang console signs operators in with Hopae (console SSO): the console calls Hopae's native verify for its own origin and maps the Hopae user to a Hangang account. Nothing required the operator to have used a phishing-resistant factor, and the console could not tell which factor was used or when.
- An end-user application that wants a passkey can already write a step-up rule, but step-up rules accept any second factor at AAL 2, a console that is not behind Hopae's gateway sees no verify headers it can trust beyond the authenticated native channel, and there is no way to admit operators who have not enrolled yet during a rollout.
- The console must enforce its own minimum (it owns the mutation endpoints) and re-check freshness before sensitive actions (publish, activate, factor reset).

## Decision

1. **Policy.** `console_operators` names the application the console runs on (`app_id`), the required level (`require_aal`: 2 by default, 3 with `webauthn.high_assurance`), the required factor (`require_factor`: `webauthn` by default, or `any`), a step-up path (`step_up_path`, default `/ui/step-up`) with its freshness (`step_up_max_age_secs`, default 300) and an optional enrollment grace (`enrollment_grace_until`). It becomes two step-up rules on that application: the whole host at the level and factor, and the step-up path with the freshness.
2. **Factor rules.** A step-up rule may require a factor kind. A `webauthn` rule is met and refreshed only by a passkey use; TOTP, external factors and recovery codes never meet it. For such a rule (and for AAL 3) the portal's step-up offers only passkeys and no other method; a user without a passkey gets a page sending them to add one (`403`, EN/KO), and the TOTP and external routes refuse the transaction.
3. **Enrollment before the first grant, with an optional grace.** Without a passkey an operator cannot be admitted: the console's check is refused and a document navigation lands on the "add a passkey" page. Until `enrollment_grace_until`, an operator **without any passkey** is admitted without the whole-host rule (never on the step-up path); the assertion says `grace: true`. An operator who has a passkey must use it.
4. **Signed operator assertion.** Every allowed verify for the console application carries `x-hopae-operator-assertion`: `v1.<base64url JSON>.<base64url HMAC-SHA256>` over the domain `hopae-operator-assertion.v1.`, keyed by `console_operators.assertion_key_env` (32 to 4096 bytes, shared with the console). Claims: audience `hangang-console`, application and host, user and session, the presented level (3 only with the high-assurance evidence of ADR-0018), the latest second factor and its time, `high_assurance`, `auth_time`, the policy (`require_aal`, `require_factor`), `satisfied`, `grace`, `iat`, `exp` (60 s). The console verifies it on every request (it re-verifies anyway), so a replayed or forged header is refused and the freshness of the factor is visible without trusting the transport.
5. **Audit.** `operator.console_admitted` (required) records each admission once per session and credential generation per process with the level, factor, assurance and whether the grace applied. Step-up completions are the existing `factor.*` records; refusals are `verify.denied`.
6. **The console's part** (Hangang, separate change): verify the assertion, enforce its configured minimum at sign-in and on every mutation, require a fresh factor (`max_age`) for sensitive actions by sending the operator to the step-up path, show the operator's level, and keep the break-glass local administrator path audited and disableable.

## Consequences

### Positive

- A stolen password or a phished provider session no longer opens the console; the console sees what the operator proved and when, signed; operators can be migrated with a bounded grace.

### Negative

- The console must hold a shared HMAC key; an operator without a passkey cannot use the console after the grace; the step-up path relies on the console being behind the gateway (document navigation through Hopae), as console SSO already does for `/_hopae/login`.

### Neutral

- The rules are ordinary step-up rules, so explain, status and the native Human path see them like any other.

## Alternatives considered

| Alternative | Why not |
| --- | --- |
| Rely on `x-hopae-aal` and `x-hopae-factors` only | Unsigned at the HTTP layer, no factor time, no grace or policy state; the console could not tell a stale factor from a fresh one. |
| Asymmetric (Ed25519) assertion | Possible later; the console already shares a gateway key with Hopae, and HMAC needs no key distribution beyond it. |
| Enforce only in the console | The console cannot run a WebAuthn ceremony; Hopae owns factors and step-up. |

## Adversarial review

| Pass | Date | S1 | S2 | S3 | S4 | Outcome |
| --- | --- | --- | --- | --- | --- | --- |
| — | — | — | — | — | — | Pending: reviewed together with the Hangang console change. |

## References

- [ADR-0017](0017-webauthn-passkeys.md), [ADR-0018](0018-aal3-emission.md), [WebAuthn passkeys](../WEBAUTHN.md), [Gateway contract](../GATEWAY_CONTRACT.md), [Configuration](../CONFIG.md#console-operators)

## 한국어 요약

콘솔 운영자는 Hopae를 통해 패스키로 로그인합니다. `console_operators` 정책은 콘솔이
돌아가는 애플리케이션에 단계 상승 규칙 두 개(호스트 전체에 요구 수준과 `webauthn` 요소,
step-up 경로에 신선도)를 붙이고, 이런 규칙은 패스키 사용으로만 충족됩니다. 패스키가 없는
운영자는 등록부터 하도록 안내되며, 선택적 등록 유예 기간에는 패스키가 전혀 없는 운영자만
요소 없이 들어올 수 있습니다(step-up 경로는 유예 없음). 콘솔 애플리케이션의 허용 응답에는
공유 키로 HMAC 서명한 60초짜리 운영자 단언(`x-hopae-operator-assertion`)이 붙어 수준, 마지막
2차 요소와 그 시각, 고보증 여부, 정책 충족과 유예 여부를 알려 주고, Hangang 콘솔은 이를
매 요청 검증해 로그인·변경·민감 작업을 통제합니다. 감사는 `operator.console_admitted`입니다.
