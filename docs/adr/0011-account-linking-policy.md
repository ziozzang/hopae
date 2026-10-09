# ADR-0011: Identities link to a user automatically only on a verified email from a trusted provider; otherwise explicitly

- Status: Proposed
- Date: 2026-10-09
- Deciders: designer, orchestrator
- Scenarios: 002 (M1 creation rules); 2xx (M3 explicit linking)
- Threat model: TM-09
- Supersedes: none

## Context

- Several providers can assert the same email. Automatic linking by email is the classic account-takeover path when a provider does not verify ownership (TM-09).
- Provider trust differs: Google and Kakao expose a verified flag; Naver exposes none (ADR-0010).
- Applications receive `x-forwarded-user`, a Hopae user id; whether two provider logins are "the same person" is therefore Hopae's decision and must be deliberate.

## Decision

An identity is `(provider_id, subject)`. On a successful provider login:

| Case | Action |
| --- | --- |
| Identity exists | Use its user; update `identities.email`, `name`, `picture`, `last_seen_at`. An email change at the provider never moves the identity to another user and never changes `users.primary_email` unless the new email is verified and `linking.follow_provider_email` is `true` (default `false`). |
| Identity unknown; no user has this email, or the identity has no email | Create a new user with this identity; `primary_email` set only when verified. |
| Identity unknown; a user has this email; `linking.mode = verified_email` (default) **and** the asserting provider reports `email_verified = true` **and** the provider is in `linking.trusted_providers` (default: `google`, `kakao`) **and** the existing user's `email_verified` is `true` | Link: attach the identity to that user; event `identity.linked` with `reason=verified_email`. |
| Identity unknown; a user has this email; any condition above fails | `linking.on_conflict = separate` (default): create a new user whose `primary_email` is empty (the email stays with the existing user) and show "this email is already in use with another sign-in method" on the portal, offering the explicit link flow (M3). `on_conflict = deny`: reject with `email_in_use`. |
| `linking.mode = manual` | Never auto-link; every unknown identity creates a new user; explicit linking only. |
| `linking.mode = off` | Never link and never report conflicts (one user per identity, emails may repeat). |

Explicit linking (M3): a signed-in user starts a transaction of purpose
`link`, authenticates with the second provider in the same browser within 10
minutes, and the identity is attached; the portal requires the existing
session to be at least `aal` of the application `default` policy. Unlinking
requires at least one remaining first-factor identity or a password.

Email domain allowlists (`providers[].allowed_email_domains`, `apps[].
allowed_email_domains` later) are evaluated before linking; a disallowed
domain rejects the login with `email_domain_not_allowed`.

`users.primary_email` is unique when present; comparison is case-insensitive
on the domain and exact on the local part after Unicode NFC normalization.

Out of scope: merging two existing users (administrator action, M4),
provider account recovery.

## Consequences

### Positive

- A Naver login can never take over a Google-created account by email; Kakao can only when Kakao says the email is verified and valid.
- The policy is one table of cases, testable with the mock provider's `email_verified` switch.

### Negative

- Users who sign in with an untrusted provider for an existing email get a second account until they link explicitly (M3); the portal must explain this clearly.
- `separate` leaves users without a primary email, which applications may not expect; `x-forwarded-email` is simply omitted.

### Neutral

- `trusted_providers` is configuration, so an operator who trusts Naver's emails for an internal deployment can add it with the risk documented.

## Alternatives considered

| Alternative | Why not |
| --- | --- |
| Always link by email | The takeover path TM-09 describes. |
| Never link automatically (`manual` for everyone) | Pushes every multi-provider user through an extra flow; verified-email linking from trusted providers is the accepted industry compromise and is explicitly bounded here. |
| Link when either side is verified | A verified existing account can still be taken over by an unverified assertion; both sides must be verified. |
| Use the provider's `sub` as the Hopae user id | Different per provider; linking needs an independent id. |

## Adversarial review

| Pass | Date | S1 | S2 | S3 | S4 | Outcome |
| --- | --- | --- | --- | --- | --- | --- |
| — | — | — | — | — | — | Pending G2. |

Questions for the reviewer: is Kakao's `is_email_verified` strong enough to
be in the default trusted list given that Kakao emails can be reassigned
(`is_email_valid`)? Is `separate` (silent second account) worse for users
than `deny`?

## References

- [ADR-0010](0010-provider-abstraction.md) for the verified flag per provider.
- [Threat model TM-09](../THREAT_MODEL.md#threat-catalogue).

## 한국어 요약

신원은 (제공자, subject) 쌍이며, 기존 사용자와 이메일로 자동 연결되는 경우는
제공자가 이메일을 검증했다고 보고하고, 그 제공자가 신뢰 목록(기본 Google,
Kakao)에 있으며, 기존 사용자의 이메일도 검증된 경우뿐입니다. 그 외에는 별도
사용자를 만들고 M3의 명시적 연결 흐름을 안내합니다. Naver는 검증 플래그가 없어
기본적으로 자동 연결되지 않습니다.
