# ADR-0008: Second factors are pluggable; the session records satisfied factors and an assurance level; step-up is a per-application rule evaluated at verify

- Status: Proposed
- Date: 2026-10-09
- Deciders: designer, orchestrator
- Scenarios: 002, 004 (schema and headers in M1); 470–499 (M5)
- Threat model: TM-18, flow 9
- Supersedes: none

## Context

- The brief requires an extensible second-factor mechanism (TOTP, WebAuthn, later others), sessions that record which factors were satisfied and when, and per-application step-up requirements.
- The roadmap forces the extension point into M0/M1 so that M5 adds rows and handlers, not columns: the session schema and the verify headers must already carry the information.
- Step-up decisions depend on the path (for example `/admin`), which interacts with the caching rule of ADR-0006.

## Decision

**Factor interface.** A `Factor` is a trait with `kind()` (`totp`,
`webauthn`, `recovery`, later `email_code`, `push`), `enroll(user) →
EnrollmentChallenge`, `confirm_enrollment(user, response)`,
`challenge(session, factor_row) → Challenge`, `verify(session, factor_row,
response) → Verified | Rejected { retry_after }`, `reset_by_admin(user)`.
Factors never read provider secrets; secrets they own (TOTP seeds) are
encrypted at rest with a key from the environment (`HOPAE_FACTOR_KEY`),
public keys (WebAuthn) are stored plain.

**Session record.** `sessions.factors` is a JSON array of
`{"kind": "oidc", "provider": "google", "at": 1760000000}` entries in
satisfaction order; `sessions.aal` is `1` when only a first factor is
present and `2` when at least one second factor is present. First factors
are `oidc`, `oauth2`, `email_link`, `password`; second factors are the
`Factor` kinds. Entries are append-only for the life of the session.

**Headers.** Verify emits `x-hopae-aal` and `x-hopae-factors`
(`kind[:provider]` comma list) on every `200` from M1, so applications can
act on them before Hopae itself enforces step-up.

**Step-up rule.** `apps[].step_up` is a list of rules evaluated in order at
verify after binding and application policy:

```json
{"path_prefix": "/admin", "require": {"aal": 2, "max_age": 900}}
```

`aal` is the minimum level; `max_age` (seconds) bounds how old the newest
satisfying second factor may be. A rule with `path_prefix` makes the
application's `200` responses `no-store` (ADR-0006). An unmet rule on a
document navigation answers `302` to `/stepup?txn=…` with a transaction of
purpose `stepup` bound to the session; a non-document request answers `401`
with `{"error": "step_up_required", "aal": 2}`. Satisfying the challenge
appends the factor to the same session; no new handles are issued.

**Enrollment policy.** Per application or group (M5): `require_enrolled:
true` denies `403 enrollment_required` with a link to the enrollment page
when the user has no second factor. Recovery codes are a `Factor` of kind
`recovery`, single use, counted.

Out of scope here: the user interface of enrollment, WebAuthn relying-party
details (origin is the portal origin), push factors.

## Consequences

### Positive

- M5 implements factors without touching the session schema, the verify headers or the gateway contract.
- Applications can enforce their own policy from `x-hopae-aal` on day one.
- Step-up never issues new cookies, so the handoff is unaffected.

### Negative

- Path-scoped step-up disables decision caching for that application; the operator sees that in `hopae --check`.
- Encrypted-at-rest factor secrets add a key to manage (`HOPAE_FACTOR_KEY`) and a rotation procedure (M7).

### Neutral

- `aal` follows NIST SP 800-63B vocabulary loosely (1: single factor, 2: two factors); level 3 is not modeled.

## Alternatives considered

| Alternative | Why not |
| --- | --- |
| Separate "elevated session" with its own cookie | Two cookies per host and a second handoff; the single session with appended factors is simpler and equally revocable. |
| Encode factors as a bitmask column | Loses the time of satisfaction, which `max_age` needs. |
| Step-up evaluated by the application only | Applications cannot drive the portal challenge; the gateway would allow the request before the application denies it. |
| Enforce step-up in the gateway via a second route | Possible for whole prefixes with the path-scoped route pattern, but the rule still needs the session's `aal`, which only Hopae has. The gateway route pattern may be used to narrow which requests call Hopae. |

## Adversarial review

| Pass | Date | S1 | S2 | S3 | S4 | Outcome |
| --- | --- | --- | --- | --- | --- | --- |
| — | — | — | — | — | — | Pending G2. |

Questions for the reviewer: should the handle be rotated when `aal` rises,
so that a cookie stolen at `aal=1` does not inherit the elevation? Does the
`stepup` transaction need its own binding?

## References

- [Architecture — Flow 9](../ARCHITECTURE.md#flow-9--step-up-second-factor-m5-surface-m1-schema)
- NIST SP 800-63B (AAL definitions); RFC 6238 (TOTP); W3C WebAuthn Level 2.

## 한국어 요약

2차 인증 요소는 `Factor` 트레이트로 추가하며, 세션은 충족한 요소와 시각을
`factors` 배열에, 수준을 `aal`(1 또는 2)에 기록합니다. verify는 M1부터
`x-hopae-aal`과 `x-hopae-factors`를 내보냅니다. 단계 상승은 애플리케이션별
규칙(`path_prefix`, `aal`, `max_age`)으로 verify에서 평가하고, 미충족 시
포털의 `/stepup`으로 보냅니다. 경로 범위 규칙이 있는 애플리케이션의 결정은
캐시하지 않습니다.
