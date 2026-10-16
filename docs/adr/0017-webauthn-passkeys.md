# ADR-0017: WebAuthn passkeys are a portal-only second factor with persisted one-time ceremonies, a pinned origin, recovery codes at AAL 1, and AAL 3 recorded but not emitted

- Status: Proposed
- Date: 2026-10-16
- Deciders: designer, orchestrator (maintainer decision pending on the open questions below)
- Scenarios: 480, 481, 482, 483, 484, 485, 486
- Threat model: TM-47, TM-48, TM-49, TM-50, TM-51, TM-52, TM-53; flow 9 updated; new flow S
- Supersedes: none. Amends [ADR-0008](0008-second-factor-extension-point.md): recovery codes no longer count as AAL 2 evidence (decision 9); ADR-0008 stays Accepted and links here.

## Context

- [ADR-0008](0008-second-factor-extension-point.md) reserved `FactorKind::Webauthn` and `FactorKind::Recovery`, the session factor list and `x-hopae-aal`. Native TOTP enrollment and browser step-up exist ([second-factor extensions](../SECOND_FACTOR_EXTENSIONS.md)); WebAuthn, recovery codes, a factor overview and factor removal do not.
- The portal is server-rendered without script; its content security policy forbids every script (`default-src 'none'`). WebAuthn cannot be used without calling `navigator.credentials.create()` and `navigator.credentials.get()` from script.
- Sessions, handles and handoff codes store `aal` in columns constrained to `1` or `2`; the gateway contract documents `x-hopae-aal` as `1` or `2`; the native Human observed protocol (Hopae's server and the published `hopae-grpc` client used by peers) accepts only AAL 1 or 2; configuration accepts step-up `aal`, `admin.require_aal` and Human projection `minimum_aal` of 1 or 2. The signed native receipt binding (`hopae-grpc` `receipt_binding`) already admits Human AAL 1–3 and seals the AAL byte into the receipt hash.
- The maintainer asked for a WebAuthn relying party built on `webauthn-rs`, with AAL 3 for attested, non-synchronized, allowlisted authenticators, recovery codes, a rule that the last factor cannot be removed, administrator reset and default-off configuration.

## Decision

1. **Relying party.** One relying party per deployment, configured by the optional top-level `webauthn` object (absent: disabled, every WebAuthn route answers `404`, no schema row is written, nothing else changes). `webauthn.rp_id` defaults to the **portal host** and may be set to a parent domain of it on a label boundary (`auth.example.test` → `example.test`); preflight refuses any other value, IP literals and single-label names. The allowed origin is exactly the portal origin from `portal.public_url` (scheme, host and port); subdomains and other ports are refused (`webauthn-rs` `allow_subdomains(false)`, `allow_any_port(false)`). `webauthn.rp_name` is the display name shown by authenticators (default `Hopae`). As for TOTP, the feature requires authenticated gateway callers and HTTPS.
   - Deviation from the brief, recorded for the maintainer: the brief asked for the registrable domain as the default. A registrable-domain RP ID lets **every** sibling host request assertions for these credentials; a dangling or compromised sibling then becomes a phishing-resistant-credential oracle (the same reasoning that rejected `Domain=` cookies and suffix host patterns in the roadmap backlog). Because every ceremony runs on the portal, the portal host loses nothing; widening later is possible only by operator choice and invalidates nothing already registered under the narrower ID only if the operator never changes it (changing `rp_id` orphans every credential — preflight documents this).
2. **Ceremonies only on the portal.** Registration and assertion happen only under `/security/…` and `/stepup/webauthn` on the portal listener. Application hosts, `/_hopae` entry points, the handoff and the gateway contract are unchanged. A WebAuthn step-up ends with the same elevation transaction shape as TOTP (ADR-0008): proof, challenge and transaction consumed, `aal` raised, `cred_gen` incremented, every handle revoked and every outstanding code consumed (reason `elevation`), the portal handle reissued and the browser handed off again with a code minted at the new level.
3. **Script exception, limited to WebAuthn pages.** Pages that run a ceremony load exactly one same-origin static asset, `/assets/webauthn.js`, with a Subresource Integrity hash computed at build time. Only those responses widen the policy to `script-src 'self'` and add `require-trusted-types-for 'script'` plus a `Permissions-Policy` that grants `publickey-credentials-create` and `publickey-credentials-get` to the portal origin only. There is no inline script, no inline handler, no `eval`, no network request from script (`connect-src` stays `'none'`): the script reads server-rendered, HTML-escaped `data-` attributes, runs the ceremony on a user gesture, writes the JSON result into a hidden field and submits an ordinary CSRF-protected form. Every other portal page keeps the pinned no-script policy byte for byte. Without script the page explains that a browser with JavaScript is required for passkeys and links the other methods.
4. **Ceremony state.** `webauthn-rs` state (`PasskeyRegistration`, `PasskeyAuthentication`) is persisted server-side in `webauthn_challenges`, never sent to the browser. A row is keyed by the SHA-256 of a 32-byte random bearer that the form carries, and is bound to the purpose, user, live session, the exact portal handle digest, the portal binding cookie digest, the session's credential generation and, for step-up, the step-up transaction digest. It expires after 5 minutes, is single use (consumed by the first completion attempt, successful or not), and a session holds at most 8 live rows (the oldest is discarded). A failed attempt renders a new challenge and a specific, non-enumerating error.
5. **Credentials.** `webauthn_credentials` stores the serialized `webauthn-rs` credential (public key, counter, flags, attestation) plus queryable copies: AAGUID, transports, backup eligibility and state, user verification at registration, attestation format, whether the attestation chain verified against an operator CA, the assurance class, label, timestamps, `active`/`revoked` state and a revision. A credential ID is globally unique; registering an ID that exists for any user is refused. A user holds at most 20 active passkeys. The WebAuthn user handle is a per-user random UUID (`users.webauthn_user_handle`), never the user ID or email.
   - Deviation from the brief: the brief asked for a 64-byte handle. `webauthn-rs` 0.5 takes a UUID (`user_unique_id: Uuid`) on its supported API, and its discoverable-credential API returns one; a random v4 UUID carries 122 random bits, enough to be uncorrelatable, and keeps the later passwordless pass on the library's supported path.
6. **User verification and phishing resistance.** Registration and assertion require user verification (`userVerification: required`, enforced by `webauthn-rs`). A successful assertion appends `{kind: "webauthn", at}` to the session factors and yields AAL 2. Hopae records the credential's assurance class: `aal2` (user-verified passkey, phishing-resistant by origin binding) or `aal3` (see 7).
7. **AAL 3 is recorded, not emitted.** A credential is classed `aal3` only when all hold at registration: attestation verified against a CA listed in `webauthn.high_assurance.attestation_ca_files`, the attested AAGUID is in `webauthn.high_assurance.aaguids`, `backup_eligible = false`, user verified; and at each assertion `backup_eligible = false`, `backup_state = false`, user verified. High-assurance registration is a separate, explicitly chosen ceremony (`attestation: direct`, packed or TPM formats, synchronized authenticators refused). The class is stored on the credential and in the `factor.*` audit events. **No wire, header, column, receipt or configuration value carries AAL 3 in this change**: the session and handles stay at 2. Emission is deferred because every existing reader would break or fail closed (analysis below); turning it on later needs no re-registration.
8. **Sign-count regression.** `webauthn-rs` refuses an assertion whose counter is not greater than the stored counter (when either is non-zero) only after the signature verified, which is evidence of a cloned authenticator. Hopae then, in one transaction: consumes the challenge, revokes that credential (reason `counter_regression`), terminates every live session of the user that was elevated with it and records `factor.webauthn_clone_suspected` (failure). The current request is refused. A counter that is merely stale because two of the user's own tabs finished out of order (the store's conditional update fails although the library check passed) is refused without revocation.
9. **Recovery codes are AAL 1.** Ten codes of the form `XXXXX-XXXXX-XXXXX` (Crockford base32, 75 bits): the first group is a per-user lookup id, the remaining 50 bits are hashed with Argon2id (19 MiB, 2 passes, 1 lane) and the plaintext is shown once (`no-store`). A code is single use (conditional update on `used_at IS NULL`). Using one on `/security/verify` appends `{kind: "recovery", at}`, leaves the session's `aal` unchanged, sets `users.factor_recovery_required_at` and permits factor management for 5 minutes; the portal then requires enrolling a new factor (banner on every security page, the step-up page names the requirement). The flag clears when a passkey or TOTP is enrolled. ADR-0008 counted `recovery` as AAL 2 evidence in step-up evaluation; this ADR removes it, so a recovery code can never satisfy or refresh an AAL 2 rule. (No recovery entry existed before this change, so no stored session changes meaning.) Generation and regeneration (which invalidates the previous set) require recent multi-factor verification, except the first set immediately after the first enrollment, which requires only the same freshness as enrollment.
10. **Freshness and the security confirmation.** Factor management (add passkey, remove passkey, generate codes) requires a live portal session and either: (a) the user has no active second factor and the primary sign-in is at most 5 minutes old; or (b) a WebAuthn, TOTP or external factor entry, or a recovery entry, at most 5 minutes old. `/security/verify` provides (b): it verifies a passkey, a TOTP code or a recovery code and elevates the **portal** session in the ADR-0008 transaction shape (handles rotated, portal handle reissued), without a handoff. Renaming a passkey requires only a live session.
11. **The last factor cannot be removed.** Removing a passkey is refused when it is the user's only active second factor (passkeys plus active TOTP; recovery codes do not count). The page explains how to add another factor first. An administrator reset is the only path to zero factors. Removing a passkey terminates the user's other live sessions that were elevated with it (`session_webauthn_elevations`); the acting session continues.
12. **Administrator reset.** `hopae admin factors reset <user>` revokes every passkey, TOTP enrollment and unused recovery code, clears the recovery flag, terminates every live session of the user and records `admin.factor_reset` in the same transaction. `hopae admin factors list <user>` shows labels, classes and timestamps, never key material. Console UI for factors is deferred.
13. **Events (ADR-0009).** Required, in the transaction of the change: `factor.webauthn_registered`, `factor.webauthn_used` (attrs `factor_id`, `kind`, `aal`, `assurance`), `factor.webauthn_renamed`, `factor.webauthn_revoked`, `factor.webauthn_clone_suspected`, `factor.recovery_codes_generated` (`count`), `factor.recovery_code_used` (`count` remaining), `admin.factor_reset`. A failed ceremony records `factor.webauthn_failed` with a reason, never the client data or signature. Credential IDs appear in events only as `factor_id` = `pk_` plus the first 16 hex digits of SHA-256 over the ID.
14. **Dependency.** `webauthn-rs` 0.5.5 (MPL-2.0, MSRV 1.88; the 0.6 line is `-dev` only). Its core links OpenSSL; Hopae enables `openssl/vendored` so release binaries stay static and do not use a system OpenSSL. Tests use `webauthn-authenticator-rs` 0.5.5 software authenticators (development dependency only).

15. **Native Human owner provenance (phase 2).** Migration 12 adds `session_webauthn_provenance`, the counterpart of `session_totp_provenance` ([native TOTP provenance](../HUMAN_TOTP_PROVENANCE.md)): one row per session, written only in the elevation transaction of an application passkey step-up or a portal passkey confirmation, naming the user, the new credential generation, the credential id, the recorded class, the factor index and time, and the configuration generation (the step-up's, or the one in force for a portal confirmation). A portal confirmation with an authenticator code records the TOTP row the same way. The native Human owner accepts an AAL 2 handle only when exactly the row of the current credential generation exists (TOTP or WebAuthn), its factor entry is unchanged, the passkey is still active for the same user, and the configuration generation is current; freshness rules use that factor's time. Another use of the same passkey does not retire the owner; revocation does. Receipts are unchanged: they seal AAL 2 as before and carry no factor kind, so no peer changes.

16. **Passwordless sign-in (phase 2).** With `webauthn.passwordless = true` the login chooser offers a passkey beside the providers: an input with `autocomplete="username webauthn"` for conditional mediation (autofill) and a button for the modal prompt; registrations then request `residentKey: preferred` so new passkeys are discoverable. The ceremony is discoverable (`allowCredentials` empty, user verification required) and lives in `webauthn_login_challenges` (migration 13), bound to the login transaction, the portal binding cookie and the client address, single use, five minutes, at most 30 per address per minute and 10,000 in total (beyond that the passkey option is simply not offered and a single provider is used directly). The response's user handle selects the account (`users.webauthn_user_handle`); unknown handles, foreign credentials, disabled users and bad signatures all produce the same "couldn't sign you in" redirect (enumeration resistance) and a `login.failed` record. Success creates, in one transaction with the ceremony, the login transaction and the passkey counter, a session with the reserved provider id `hopae.passkey` (not a slug, so no configured provider can take it; no `providers` row), factor `webauthn` and **AAL 2** — a user-verified passkey is a multi-factor cryptographic authenticator. The session lives while that passkey is active: removal, a clone signal or an administrator reset end it. Reauthentication transactions (`max_auth_age`) are not completed by a passkey; such a session is asked to sign out and in. The native Human owner refuses passkey sessions (no primary provenance), as before for any session without it.

### AAL 3 wire analysis

| Reader | Today | Effect of emitting 3 |
| --- | --- | --- |
| `sessions.aal`, `session_handles.issued_aal`, `handoff_codes.issued_aal` | `CHECK (… IN (1, 2))` in STRICT tables | Insert fails; widening needs a table rebuild of `sessions` and its dependants. A rolled-back binary maps 3 to "corrupt" (`rows.rs`) and fails every request of those sessions. |
| `x-hopae-aal` (gateway contract) | Documented as `1` or `2` | Applications that test `== "2"` deny AAL 3 users; needs a contract minor and an application opt-in. |
| Native Human observed gRPC (`grpc_human.rs`, `hopae-grpc` `human_observed_client`) | Refuses AAL ∉ {1, 2} | Peers on the published client fail closed for AAL 3 sessions until they upgrade. |
| Signed native receipt (`receipt_binding`, `receipt_issuer` seal) | Human 1–3 admitted, AAL byte sealed | Compatible; receivers on older `hopae-grpc` revisions must be checked. |
| Pumgye `minimum_aal` (projection plans) | Human plans validated as 1 or 2; comparison `scope.aal < minimum_aal` | Numerically compatible (3 satisfies ≤ 2); plans of 3 need Pumgye and configuration changes. |
| Step-up rules, `admin.require_aal` | Configuration admits 1 or 2 | Cannot require 3. |
| Native Human owner (`human_owner.rs`) | Special-cases `issued_aal == Two` and requires TOTP provenance | An AAL 3 handle falls into the AAL 1 branch and is refused by AAL 2 rules. |

Emission therefore needs, in order: a schema migration that rebuilds the three tables with `aal IN (1, 2, 3)`; a gateway-contract minor with an explicit per-application `max_emitted_aal` (default 2) so `x-hopae-aal` and receipts clamp to what each consumer declared; a Human observed protocol revision and peer upgrades; configuration that admits 3 in step-up rules and Pumgye plans; native owner provenance for WebAuthn. That is a separate ADR; this one only stores the evidence it will need.

## Consequences

### Positive

- Phishing-resistant step-up for every protected application without changing the gateway contract, the handoff or any peer.
- Users can see, name and remove their factors, and recover from a lost device without an administrator.
- Operators can start enrolling high-assurance keys now; AAL 3 later needs no re-enrollment.

### Negative

- The portal gains script on four pages, which widens the XSS impact on those pages (mitigated by a static same-origin file with SRI, Trusted Types, no `connect-src`, and server-side CSRF and Origin checks on the submitted form).
- `webauthn-rs` brings OpenSSL (vendored) into a Rust-crypto binary: larger build, a C toolchain and Perl at build time, OpenSSL advisories to track in `cargo audit`.
- Phase 2 (decision 15) lets WebAuthn-elevated AAL 2 sessions on the native Human owner path through an exact provenance record; sessions elevated before migration 12 have none and stay refused there (fail closed, legacy verify unaffected).
- Factor management requires a primary sign-in at most 5 minutes old for users without a factor; the portal can only offer "sign out and sign in again" for that case.

### Neutral

- Console factor management and a passkey requirement for console operators are deferred (roadmap). Passwordless sign-in arrived in phase 2 (decision 16).

## Alternatives considered

| Alternative | Why not |
| --- | --- |
| Registrable-domain RP ID by default | Sibling-host assertion oracle (decision 1). |
| Ceremony state in a signed cookie or hidden field | Replay and fixation need server-side single use; state size grows with the credential list. |
| Inline script with a nonce | A nonce policy differs per response and invites future inline additions; a static file with SRI is reviewable and cacheable. |
| Recovery codes as AAL 2 | A printable bearer secret is not a phishing-resistant or possession factor; it would let a stolen code satisfy every AAL 2 rule. |
| Emit AAL 3 behind a flag now | Breaks the schema constraint, the published gateway contract and peers (analysis above); a flag cannot make an old reader accept 3. |
| A pure-Rust WebAuthn library | Requested library is `webauthn-rs`; it is the most reviewed Rust relying-party implementation. |
| Auto-revoke on any stale counter | Two tabs of the same user finishing out of order would revoke a legitimate key. |

## Adversarial review

Not yet reviewed (G2 pending). Questions for the reviewer:

- Decision 4: is binding the ceremony row to the portal handle digest and the binding cookie digest sufficient against a stolen portal handle on another device?
- Decision 8: can an attacker without the private key make a legitimate key look cloned (forcing revocation and session termination)?
- Decision 10: does the portal elevation (no handoff) let a pre-elevation application handle gain AAL 2 (ADR-0008 R05)?
- Decision 11: is there a race where two concurrent removals leave zero factors?

## References

- W3C Web Authentication Level 3; NIST SP 800-63B-4 (AAL 2 and AAL 3, phishing resistance, syncable authenticators); FIDO Alliance AAGUID guidance.
- [ADR-0008](0008-second-factor-extension-point.md), [ADR-0009](0009-event-model.md), [ADR-0016](0016-management-console-minimum.md)
- [WebAuthn passkeys](../WEBAUTHN.md), [Threat model](../THREAT_MODEL.md)

## 한국어 요약

패스키(WebAuthn)는 포털에서만 등록·사용하는 2차 인증 요소입니다. RP ID는 기본값이
포털 호스트이고 상위 도메인으로만 넓힐 수 있으며, origin은 포털 origin으로 고정합니다.
WebAuthn 페이지에만 같은 origin의 정적 스크립트 하나(SRI, Trusted Types)를 허용합니다.
의식(ceremony) 상태는 서버에 1회용·5분 만료로 저장하고 세션·포털 핸들·바인딩 쿠키에
묶습니다. 사용자 확인(UV) 패스키는 AAL 2이며, 증명(attestation)된 비동기화·허용 목록
인증기는 AAL 3 등급으로 **기록만** 하고 내보내지 않습니다(스키마·게이트웨이 계약·피어가
1 또는 2만 허용). 서명 카운터 역행은 복제 증거로 보고 해당 자격 증명을 폐기합니다.
복구 코드는 Argon2id로 해시한 1회용 코드이며 AAL 1만 부여하고 재등록을 요구합니다.
마지막 2차 요소는 삭제할 수 없고, 관리자 초기화는 명령줄로 수행합니다.
