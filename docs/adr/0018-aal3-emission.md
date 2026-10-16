# ADR-0018: AAL 3 is presented per application as a qualifier of AAL 2 sessions, never stored as a level, and only to applications that opt in

- Status: Proposed
- Date: 2026-10-16
- Deciders: designer, orchestrator (maintainer decision pending)
- Scenarios: 488
- Threat model: TM-53 (rewritten)
- Supersedes: none. Completes [ADR-0017](0017-webauthn-passkeys.md) decision 7 ("AAL 3 is recorded, not emitted"); ADR-0017 stays Proposed and links here.

## Context

- ADR-0017 classifies high-assurance passkeys (`aal3`: attestation chained to an operator CA, allowlisted AAGUID, not backup-eligible, not backed up, user verified per assertion) and records the class on the credential, on each use and in `session_webauthn_provenance` (migration 12).
- Its wire analysis lists every reader of AAL: `CHECK (aal IN (1, 2))` on `sessions`, `session_handles` and `handoff_codes`; the gateway contract documents `x-hopae-aal` as `1` or `2`; Hopae's Human gRPC server and the published `hopae-grpc` Human observed client accept 1 or 2; the Human permission path parses permits with 1 or 2; step-up rules, `admin.require_aal` and Human projection plans validate 1 or 2; the signed receipt binding already admits Human 1–3 and seals the byte.
- The maintainer asked for AAL 3 emission behind configuration, default off, so that nothing emits 3 unless enabled per application, and old peers keep receiving at most 2.

## Decision

1. **No stored level 3.** The stored `aal` columns keep `CHECK (aal IN (1, 2))`; no table is rebuilt. Rebuilding `sessions` would cascade through every table that references it (an SQLite `DROP TABLE` with foreign keys enabled deletes children), and a rolled-back binary would read an unknown level. A session elevated with a high-assurance passkey stays `aal = 2`; AAL 3 is a **presentation** of that evidence.
2. **Evidence.** A request qualifies for 3 when its handle was issued at 2 and the session's **current** elevation (the provenance row of its current credential generation) is a passkey use classed `aal3`, the credential is still active, classed `aal3`, not backup-eligible and not backed up. Elevation revokes every earlier handle and consumes every outstanding code (ADR-0008), so every live AAL 2 handle of that generation post-dates the evidence; any later elevation (an authenticator code, an AAL 2 passkey, a recovery code) changes the generation and ends the qualification. A passwordless sign-in with a high-assurance key records the same row.
3. **Opt-in per application.** `apps[].max_emitted_aal` is `2` (default) or `3`; `3` requires `webauthn.high_assurance` (preflight refuses otherwise). Only an application with `3` sees `x-hopae-aal: 3` and only its receipts seal 3; for every other application the same session presents 2. The console never presents 3. Hopae reads the evidence only for opted-in applications; a store failure presents the stored level, never more.
4. **Native Human path.** The native owner presents 3 only when the application opted in and its exact current establishing factor (ADR-0017 decision 15) is a high-assurance passkey; otherwise its existing level.
5. **Readers in this repository** accept 1–3 for Human identities: Hopae's Human gRPC server, the Human permission parser, and the `hopae-grpc` Human observed client (a new revision for peers). Receipt binding already did. Peers on an older `hopae-grpc` revision refuse 3 and fail closed for opted-in applications only.
6. **Not changed:** step-up rules (`require.aal`), `admin.require_aal` and Human projection plans (`minimum_aal`) still validate 1 or 2. Requiring 3 needs a step-up page that offers only high-assurance keys and a transaction that records the required level; Pumgye plans of 3 need Pumgye to evaluate them. These are follow-ups; they are not needed for emission.

### Peer changes required before opting in an application

| Peer | Change |
| --- | --- |
| Applications behind the gateway | Treat `x-hopae-aal` as a number (`>= 2`), not `== "2"` |
| Hangang (native Human observed client) | Upgrade to the `hopae-grpc` revision that accepts AAL 3 |
| Pumgye | Accept permission contexts and receipts with AAL 3 (Hopae's parser accepts them); plans of `minimum_aal: 3` are a separate Pumgye change |

## Consequences

### Positive

- Applications that need hardware-bound phishing resistance can tell it apart without any schema migration, and a rollback to an older binary is safe (it ignores the new key and presents 2).
- Nothing changes for any application that does not opt in.

### Negative

- One extra indexed read per allowed request for opted-in applications (none for others).
- An application cannot yet **require** 3 through Hopae's step-up rules; it enforces `x-hopae-aal >= 3` itself.

### Neutral

- `Aal::Three` exists in code as an emission value only; the store never reads or writes it.

## Alternatives considered

| Alternative | Why not |
| --- | --- |
| Rebuild the three tables with `aal IN (1, 2, 3)` | Cascading deletes through dependent tables during the rebuild, a large migration on the hottest tables, and an unreadable level after rollback. |
| Emit 3 globally behind one flag | Breaks every application and peer that compares `== 2` or accepts only 1–2; the request was per application. |
| Clamp 3 to 2 inside receipts for old peers | The level is sealed into the receipt; a per-consumer value already exists as the per-application setting. |

## Adversarial review

Not yet reviewed (G2 pending). Questions: can a handle issued before a high-assurance elevation present 3 (decision 2 relies on ADR-0008 revocation); can a cached allow present 3 after a later AAL 2 elevation (the cache key includes the credential generation through `x-hopae-gen`).

## References

- [ADR-0017](0017-webauthn-passkeys.md), [ADR-0008](0008-second-factor-extension-point.md), [WebAuthn passkeys](../WEBAUTHN.md), [Gateway contract](../GATEWAY_CONTRACT.md)

## 한국어 요약

AAL 3은 저장하는 수준이 아니라 AAL 2 세션의 표시입니다. 세션의 현재 상승이 고보증
패스키(증명된 허용 목록 AAGUID, 백업 불가, 백업되지 않음, 사용자 확인)이면, 옵트인한
애플리케이션(`apps[].max_emitted_aal = 3`, `webauthn.high_assurance` 필요)에만
`x-hopae-aal: 3`과 3을 봉인한 영수증을 보여 줍니다. 다른 애플리케이션과 콘솔은 같은
세션을 2로 봅니다. 테이블 재구성은 하지 않으며(종속 테이블 연쇄 삭제 위험, 롤백 시 읽을
수 없는 수준), 롤백한 바이너리는 2를 보입니다. 저장소 안의 판독자(Human gRPC 서버,
권한 파서, `hopae-grpc` 관측 클라이언트)는 1–3을 받습니다. 단계 상승 규칙,
`admin.require_aal`, Pumgye 계획은 여전히 1 또는 2이며 후속 작업입니다.
