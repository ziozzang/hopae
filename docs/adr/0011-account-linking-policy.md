# ADR-0011: Identities link to an existing user only after fresh authentication to that user; automatic linking is an opt-in for authoritative emails

- Status: Proposed
- Date: 2026-10-09
- Deciders: designer, orchestrator
- Scenarios: 002 (M1 creation and conflict rules); 2xx (M3 explicit linking flow)
- Threat model: TM-09
- Supersedes: none

## Context

- Several providers can assert the same email. Linking by email is the classic account-takeover path (TM-09), and a provider's `email_verified` flag proves that the provider once verified the address, not that the person who holds it today is the person who created the Hopae account: Google documents that a third-party mailbox can change hands while the claim stays `true`; Kakao's `is_email_valid` excludes stale assertions but still describes the mailbox's current holder (review finding R01).
- Applications receive `x-forwarded-user`, a Hopae user id; whether two provider logins are "the same person" is Hopae's decision and must be deliberate.
- A user who legitimately has several providers needs a way to join them that does not depend on a provider's claim alone.

## Decision

An identity is `(provider_id, subject)`. Ownership of an existing Hopae
account is proven only by authenticating to it. On a successful provider
login:

| Case | Action |
| --- | --- |
| Identity exists | Use its user; update `identities.email`, `name`, `picture`, `last_seen_at`. An email change at the provider never moves the identity to another user and never changes `users.primary_email`; a changed authoritative email is recorded as `identity.email_changed` for the user to confirm later (M3). Mailbox reassignment is an account-recovery matter, never identity equality. |
| Identity unknown; no user has this email, or the identity has no email | Create a new user with this identity; `primary_email` set only when `email_verified`. |
| Identity unknown; a user has this email; `linking.on_conflict = link_required` (default) | Do not create a user and do not link. Store the pending identity in the transaction (purpose `link`), show "this email already belongs to an account; sign in with <existing method> to connect", and require a **fresh** authentication with one of the existing user's methods in the same browser within 10 minutes. On success attach the identity (`identity.linked`, `reason=fresh_auth`); otherwise discard the pending identity. M1 ships the refusal and the notice; M3 ships the completion flow. |
| Same case with `linking.on_conflict = separate` | Create a new user whose `primary_email` is empty and show the notice. |
| Same case with `linking.on_conflict = deny` | Reject with `email_in_use`. |
| Identity unknown; a user has this email; the provider has `auto_link: true` **and** the assertion is `email_authoritative` (ADR-0010: Google with `hd` in `authoritative_domains`, or Hopae's own email link) **and** the existing user's email is itself authoritative from the same domain | Link automatically (`identity.linked`, `reason=authoritative_email`). `auto_link` defaults to `false` for every provider and the configuration reference states the risk. Kakao and Naver cannot satisfy this case. |
| `linking.mode = off` | Never link and never report conflicts (one user per identity, emails may repeat). |

Explicit linking from a signed-in session (M3): the user starts a transaction
of purpose `link`, authenticates with the second provider in the same browser
within 10 minutes, and the identity is attached; the existing session must be
at least the `default` application's required `aal`. Unlinking requires at
least one remaining first-factor identity or a password.

Email domain allowlists (`providers[].allowed_email_domains`, `apps[].
allowed_email_domains` later) are evaluated before any of the above; a
disallowed domain rejects the login with `email_domain_not_allowed`.

`users.primary_email` is unique when present; comparison is case-insensitive
on the domain and exact on the local part after Unicode NFC normalization.

Out of scope: merging two existing users (administrator action, M4),
provider account recovery.

## Consequences

### Positive

- No provider claim alone can attach a new identity to an existing account; a takeover needs the existing account's credentials.
- The authoritative-email opt-in keeps the Workspace-style "same company domain" convenience available where the provider really is the mailbox authority.
- The policy is one table of cases, testable with the mock provider's `email_verified`, `hd` and subject switches.

### Negative

- A user with two providers on the same email must sign in twice once (M3 completes the flow; until then M1 refuses with a notice).
- `link_required` leaves the user without an account until they link; the notice must be clear and localized.

### Neutral

- `separate` and `deny` remain for operators who prefer them; both are weaker in usability, not in security.

## Alternatives considered

| Alternative | Why not |
| --- | --- |
| Always link by email | The takeover path TM-09 describes. |
| Link on `email_verified` from a trusted provider list (the G1 draft) | Rejected after review finding R01: verification is not ownership; a reassigned Google third-party mailbox or Kakao address satisfies every flag. |
| Never link automatically, no opt-in | The authoritative-domain case (Google Workspace `hd`) is a real deployment pattern with a real authority; it is an opt-in with a stated risk rather than a prohibition. |
| Use the provider's `sub` as the Hopae user id | Different per provider; linking needs an independent id. |

## Adversarial review

| Pass | Date | S1 | S2 | S3 | S4 | Outcome |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | 2026-10-09 | 1 | 0 | 0 | 0 | 1 × FIX_FIRST applied (R01) |

Findings and dispositions:

- R01 (S1): automatic linking on `email_verified` allowed takeover through mailbox reassignment. FIX_FIRST: default `link_required` with fresh authentication to the existing account; auto-link only as an opt-in for authoritative emails; scenario 002-4 and 002-5 rewritten.

Open for the reviewer: is the authoritative-domain opt-in itself too
permissive when a Workspace administrator can recreate a deleted account
with the same address?

## References

- [ADR-0010](0010-provider-abstraction.md) for `email_verified` and `email_authoritative` per provider.
- [Threat model TM-09](../THREAT_MODEL.md#threat-catalogue).
- Google Identity, HTML API reference (`email_verified` caveat for third-party mailboxes), reviewed 2026-10-09.

## 한국어 요약

신원은 (제공자, subject) 쌍이며, 기존 계정에 새 신원을 연결하려면 기본적으로
그 계정의 기존 방법으로 다시 인증해야 합니다. 제공자의 이메일 검증 플래그는
"한때 검증했다"는 뜻이지 지금 그 계정의 주인이라는 뜻이 아니므로, 자동
연결은 제공자가 메일함의 권위자인 경우(예: Google Workspace의 `hd` 도메인)에만
운영자가 옵트인으로 켤 수 있습니다. Kakao와 Naver는 자동 연결 대상이 아닙니다.
