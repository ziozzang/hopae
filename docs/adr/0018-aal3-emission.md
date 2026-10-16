# ADR-0018: AAL 3 is presented per application as a qualifier of AAL 2 sessions, never stored as a level, and only to applications that opt in

- Status: Proposed
- Date: 2026-10-16
- Deciders: designer, orchestrator (maintainer decision pending)
- Scenarios: 488, 489
- Threat model: TM-53 (rewritten)
- Supersedes: none. Completes [ADR-0017](0017-webauthn-passkeys.md) decision 7 ("AAL 3 is recorded, not emitted"); ADR-0017 stays Proposed and links here.

## Context

- ADR-0017 classifies high-assurance passkeys (`aal3`: attestation chained to an operator CA, allowlisted AAGUID, not backup-eligible, not backed up, user verified per assertion) and records the class on the credential, on each use and in `session_webauthn_provenance` (migration 12).
- Its wire analysis lists every reader of AAL: `CHECK (aal IN (1, 2))` on `sessions`, `session_handles` and `handoff_codes`; the gateway contract documents `x-hopae-aal` as `1` or `2`; Hopae's Human gRPC server and the published `hopae-grpc` Human observed client accept 1 or 2; the Human permission path parses permits with 1 or 2; step-up rules, `admin.require_aal` and Human projection plans validate 1 or 2; the signed receipt binding already admits Human 1–3 and seals the byte.
- The maintainer asked for AAL 3 emission behind configuration, default off, so that nothing emits 3 unless enabled per application, and old peers keep receiving at most 2.

## Decision

1. **No stored level 3.** The stored `aal` columns keep `CHECK (aal IN (1, 2))`; no table is rebuilt. Rebuilding `sessions` would cascade through every table that references it (an SQLite `DROP TABLE` with foreign keys enabled deletes children), and a rolled-back binary would read an unknown level. A session elevated with a high-assurance passkey stays `aal = 2`; AAL 3 is a **presentation** of that evidence.
2. **Evidence.** A request qualifies for 3 when its handle was issued at 2 and the session's **current** elevation (the provenance row of its current credential generation) is a passkey use classed `aal3`, the credential is still active, classed `aal3`, not backup-eligible and not backed up. Elevation revokes every earlier handle and consumes every outstanding code (ADR-0008), so every live AAL 2 handle of that generation post-dates the evidence; any later elevation (an authenticator code, an AAL 2 passkey, a recovery code) changes the generation and ends the qualification. A passwordless sign-in with a high-assurance key records the same row.
3. **Opt-in per application.** `apps[].max_emitted_aal` is `2` (default, never inherited from the `default` application) or `3`; `3` requires `webauthn.high_assurance` (preflight refuses otherwise). Only an application with `3` sees `x-hopae-aal: 3` and only its receipts seal 3; for every other application the same session presents 2. The console never presents 3. Hopae reads the evidence only for opted-in applications; a store failure presents the stored level, never more. A decision presenting 3 is never cached (`no-store`): the evidence can end without a generation change (a passkey removed by the session it elevated).
4. **Native Human path.** The native owner presents 3 only when the application opted in and its exact current establishing factor (ADR-0017 decision 15) is a high-assurance passkey; otherwise its existing level.
5. **Readers in this repository** accept 1–3 for Human identities: Hopae's Human gRPC server, the Human permission parser, and the `hopae-grpc` Human observed client (a new revision for peers). Receipt binding already did. Peers on an older `hopae-grpc` revision refuse 3 and fail closed for opted-in applications only.
6. **Requiring 3** (amendment, 2026-10-16): step-up rules and `admin.require_aal` accept 3; see [AAL 3 requirements](#aal-3-requirements). Human projection plans (`minimum_aal`) still validate 1 or 2 until Pumgye evaluates 3.

### AAL 3 requirements

7. **Configuration.** `apps[].step_up[].require.aal` and `admin.require_aal` may be `3`; both need `webauthn.high_assurance` (preflight refuses otherwise). A rule of 3 is independent of `max_emitted_aal`: an application can require 3 and still be presented 2.
8. **Evaluation.** A rule of 3 is met when the handle is AAL 2, the evidence of decision 2 holds, and its freshness bound (`max_age`) is measured from the latest passkey use — which is that elevation's, since any later elevation replaces the evidence. A TOTP code, an external factor, an AAL 2 passkey or a recovery code never meets or refreshes it. The verify engine reads the evidence once per request, only when a matching rule requires 3 or the application opted into seeing it; a failed read is no evidence. The native Human path uses its exact establishing factor (decision 4) for the same rule. The authentication explain API reports `aal3_evidence` and the `presented_aal` and accepts a hypothesis of `aal: 3`.
9. **Step-up.** The step-up transaction does not record a level; the portal derives the requirement from the transaction's return target and its application's rules (canonical path, as verify matches it) at the start and again at completion. For 3 the passkey page offers only the user's high-assurance, device-bound keys and lists no other method; a user without one gets a page saying so with a link to Security settings (`403`), and the authenticator-app and external-factor routes refuse the transaction (`high_assurance_required`). An assertion that does not qualify as AAL 3 at completion (its flags re-checked) consumes the ceremony and is refused.
10. **Console.** `admin.require_aal = 3` adds a rule of 3 for the whole console host. The console authentication requires the evidence after the handle lookup, and the write fence of every console change re-checks it inside the store transaction (provenance of the current generation, credential active, `aal3`, not backup-eligible, not backed up), so revoking the key or a later elevation stops changes at once. The console is still presented 2. With `admin.hangang_delegation.authority = hangang`, Hangang is the authority and these checks do not apply.
11. **Pumgye.** Hopae passes a plan's `minimum_aal` through unchanged and its receipts seal the presented level, so a Pumgye that compares numerically treats a receipt of 3 as meeting plans of 1, 2 and 3. Hopae still refuses Human projection plans of `minimum_aal: 3`; enabling them needs Pumgye to evaluate 3 (a separate Pumgye change) and an opted-in application for the plan's scope, since only such an application's receipts can carry 3.

### Peer changes required before opting in an application

| Peer | Change |
| --- | --- |
| Applications behind the gateway | Treat `x-hopae-aal` as a number (`>= 2`), not `== "2"` |
| Hangang (native Human observed client) | Upgrade to the `hopae-grpc` revision that accepts AAL 3 |
| Pumgye | Accept permission contexts and receipts with AAL 3 (Hopae's parser accepts them) and compare levels numerically; plans of `minimum_aal: 3` are a separate Pumgye change (decision 11) |

## Consequences

### Positive

- Applications that need hardware-bound phishing resistance can tell it apart without any schema migration, and a rollback to an older binary is safe (it ignores the new key and presents 2).
- Nothing changes for any application that does not opt in.

### Negative

- One extra indexed read per allowed request for opted-in applications (none for others).
- A rule of 3 can only be met by users who registered a high-assurance key; others are told so and cannot proceed until they do (by design).
- One extra indexed read per request that matches a rule of 3, and one in the console's authentication and in each console change's fence when `admin.require_aal = 3`.

### Neutral

- `Aal::Three` exists in code as an emission value only; the store never reads or writes it.

## Alternatives considered

| Alternative | Why not |
| --- | --- |
| Rebuild the three tables with `aal IN (1, 2, 3)` | Cascading deletes through dependent tables during the rebuild, a large migration on the hottest tables, and an unreadable level after rollback. |
| Emit 3 globally behind one flag | Breaks every application and peer that compares `== 2` or accepts only 1–2; the request was per application. |
| Clamp 3 to 2 inside receipts for old peers | The level is sealed into the receipt; a per-consumer value already exists as the per-application setting. |

## Adversarial review

| Pass | Date | S1 | S2 | S3 | S4 | Outcome |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | 2026-10-16 | 0 | 0 | 0 | 2 | F10, F11 fixed; reviewed together with ADR-0017. A confirmation pass is pending. |

- F10 (S4): a cached allow could present 3 for up to 30 s after the evidence ended. FIX: decisions presenting 3 are `no-store`.
- F11 (S4): `max_emitted_aal` was inherited from the `default` application. FIX: never inherited; configuration test `max_emitted_aal_is_per_application_and_never_inherited`.

## References

- [ADR-0017](0017-webauthn-passkeys.md), [ADR-0008](0008-second-factor-extension-point.md), [WebAuthn passkeys](../WEBAUTHN.md), [Gateway contract](../GATEWAY_CONTRACT.md)

## 한국어 요약

AAL 3은 저장하는 수준이 아니라 AAL 2 세션의 표시입니다. 세션의 현재 상승이 고보증
패스키(증명된 허용 목록 AAGUID, 백업 불가, 백업되지 않음, 사용자 확인)이면, 옵트인한
애플리케이션(`apps[].max_emitted_aal = 3`, `webauthn.high_assurance` 필요)에만
`x-hopae-aal: 3`과 3을 봉인한 영수증을 보여 줍니다. 다른 애플리케이션과 콘솔은 같은
세션을 2로 봅니다. 테이블 재구성은 하지 않으며(종속 테이블 연쇄 삭제 위험, 롤백 시 읽을
수 없는 수준), 롤백한 바이너리는 2를 보입니다. 저장소 안의 판독자(Human gRPC 서버,
권한 파서, `hopae-grpc` 관측 클라이언트)는 1–3을 받습니다. 개정(2026-10-16): 단계 상승
규칙과 `admin.require_aal`은 3을 요구할 수 있고(`webauthn.high_assurance` 필요), 이때
단계 상승 페이지는 고보증 키만 제시하며 인증 앱·외부 요소·복구 코드로는 충족되지
않습니다. 콘솔이 3을 요구하면 인증과 모든 변경의 쓰기 펜스가 근거를 다시 확인합니다.
Pumgye는 수준을 숫자로 비교하면 3을 받을 수 있으며, `minimum_aal: 3` 계획은 Pumgye가
3을 평가하게 된 뒤에 Hopae가 허용합니다.
