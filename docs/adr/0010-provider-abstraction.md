# ADR-0010: One `Provider` trait with a generic OIDC client; Kakao and Naver as declared quirks; secrets by environment reference

- Status: Proposed
- Date: 2026-10-09
- Deciders: designer, orchestrator
- Scenarios: 002, 012 (M1 generic OIDC); 200–299 (M3)
- Threat model: TM-08, TM-09, TM-12, TM-17
- Supersedes: none

## Context

- Required providers: Google, Kakao, Naver, email (magic link and/or password); providers must be addable and removable at run time from the console (Keycloak-like management).
- Provider facts checked on 2026-10-09:
  - Google: standard OIDC with discovery, PKCE, `nonce`, `email_verified` claim.
  - Kakao: OIDC is available (discovery `https://kauth.kakao.com/.well-known/openid-configuration`, JWKS `https://kauth.kakao.com/.well-known/jwks.json`, `iss` fixed to `https://kauth.kakao.com`, `aud` is the REST API key, `sub` is the service user id, `nonce` echoed when sent); the client secret is enabled by default for REST API keys and then required at the token endpoint; the ID token carries `email` but **not** `email_verified`; `is_email_verified`, `is_email_valid` and `email_needs_agreement` come from `GET https://kapi.kakao.com/v2/user/me` under `kakao_account` and need the `account_email` scope and user consent. Source: Kakao Developers, REST API and Common pages.
  - Naver: OAuth 2.0 only, no ID token; authorize `https://nid.naver.com/oauth2.0/authorize`, token `https://nid.naver.com/oauth2.0/token`, profile `GET https://openapi.naver.com/v1/nid/me` with a Bearer token; `state` is used on the authorize request and sent again on the token request; profile fields are under `response` (`id`, `email`, `name`, `nickname`, `profile_image`, …); no email-verification flag is exposed. Source: the official page could not be fetched in this session; facts cross-checked against two independent integration references (Ory community provider page; a 2025 integration guide). **Re-verify against the official page at M3 G1.**
- Secrets must come from the environment at run time; the gateway references environment variables by name (`url_env`) rather than storing values.

## Decision

**Trait.** `Provider` has `id()`, `kind()`, `display()`, `enabled()`,
`begin(txn, redirect_uri) → AuthorizationRequest { url, state, nonce?,
pkce? }`, `complete(txn, callback_query) → ProviderIdentity` and
`health()`. `ProviderIdentity` is `{ subject, email: Option<String>,
email_verified: bool, name, username, picture, raw_claims (bounded) }`.
Only `complete` may perform outbound calls, and only to endpoints derived
from the provider's configuration or its discovery document.

**Kinds.**

| Kind | Implementation | Notes |
| --- | --- | --- |
| `oidc` | Generic authorization-code client: discovery (cached, hard deadline 24 h, refreshed at half-life), JWKS (cached with rotation, refetch on unknown `kid` at most once per 60 s), PKCE S256 always, `nonce` always, `state` always, `iss`/`aud`/`exp`/`iat`/`nonce`/signature checks with 60 s leeway, `response_type=code`, `scope` configurable (default `openid email profile`), optional user-info call | Google and Kakao are `oidc` instances |
| `oauth2` | Authorization-code client without ID token; `state` always; token exchange; a declared user-info mapping (JSON pointers for subject, email, name, username, picture; a `verified_pointer` or `trust_email` flag) | Naver is an `oauth2` instance |
| `email_link` (M3) | Magic link: single use, 15 min, bound to the requesting transaction and client IP policy; SMTP configured by reference | First factor; `email_verified = true` by construction |
| `password` (M3) | Argon2id (m=19 MiB, t=2, p=1 as the gateway), dummy-hash timing, reset flow by email link | First factor |

**Quirks are configuration, not code paths.** Provider rows carry a
`config` JSON validated against the kind's schema; built-in presets
(`google`, `kakao`, `naver`) fill defaults the operator can override:

| Preset | Kind | Preset values |
| --- | --- | --- |
| `google` | `oidc` | issuer `https://accounts.google.com`; `email_verified` from the ID token; `hd` claim optional domain restriction |
| `kakao` | `oidc` | issuer `https://kauth.kakao.com`; `client_secret_required: true`; `userinfo: {"url": "https://kapi.kakao.com/v2/user/me", "email": "/kakao_account/email", "email_verified": "/kakao_account/is_email_verified", "email_valid": "/kakao_account/is_email_valid"}`; `scope` `openid account_email profile_nickname`; `email_verified` is `true` only when both `is_email_verified` and `is_email_valid` are `true` |
| `naver` | `oauth2` | authorize/token/profile URLs as above; `state_in_token_request: true`; `userinfo` pointers `/response/id`, `/response/email`, `/response/name`, `/response/nickname`, `/response/profile_image`; `email_verified: false` always unless the operator sets `trust_email: true` |

**Secrets.** `client_secret_env` names the environment variable; the value
is read at start and on reload, never stored, never shown. A provider whose
variable is absent is loaded as `disabled` with a preflight warning and an
event. An optional encrypted-at-rest mode for console-entered secrets is
deferred to M4 and recorded there if adopted.

**Runtime management.** Providers live in the `providers` table from M1 and
are mirrored from the configuration file at start (file wins on conflict,
with a warning). M4 adds create, update, enable, disable and delete through
the management API; a disabled provider rejects callbacks with
`provider_disabled`. Per-provider `allowed_email_domains` and `sort_order`
are columns from M1.

**Redirect URIs.** `https://auth.example.test/callback/<provider_id>`; one
per provider; printed by `hopae --check` for registration at the provider.

Out of scope: SAML, device flow, provider-initiated logout (back-channel),
token refresh for application use.

## Consequences

### Positive

- One audited OIDC path covers Google, Kakao and any standard provider; Naver is a mapping, not a fork.
- Runtime add/remove is a table operation; the file remains the bootstrap.
- Email trust is explicit per provider, which ADR-0011 depends on.

### Negative

- Two user-info retrieval paths (ID token versus endpoint) must be tested with the mock provider's misbehavior profiles.
- Secrets by environment reference make "add a provider from the console" a two-step operation (set the variable, then add the row).

### Neutral

- The mock provider in `tests/support/mock_idp` implements `oidc` and `oauth2` kinds with misbehavior switches (wrong `state`, wrong `nonce`, expired token, mismatched `aud`, slow responses, invalid signature, oversized responses, missing `email_verified`).

## Alternatives considered

| Alternative | Why not |
| --- | --- |
| One hand-written client per provider | Duplicates the security-critical parts (state, PKCE, token validation) four times. |
| Treat Kakao as plain OAuth 2.0 | Loses the signed ID token (`nonce`, `aud`) that Kakao provides; the extra user-info call is needed either way for `is_email_verified`. |
| Store client secrets in the database | Contradicts the no-secrets-in-files rule and the gateway's precedent; deferred as an explicit encrypted mode. |
| `openidconnect` crate | Heavy generic types; the required subset (discovery, JWKS, code exchange, ID token validation) is small and must be auditable line by line; `jsonwebtoken` 11 (as the gateway) suffices for signature verification. |

## Adversarial review

| Pass | Date | S1 | S2 | S3 | S4 | Outcome |
| --- | --- | --- | --- | --- | --- | --- |
| — | — | — | — | — | — | Pending G2. |

Questions for the reviewer: are the Naver facts (no verified flag, `state`
on the token request) correct as of the official documentation? Is reading
`email_verified` from a user-info endpoint rather than the ID token a
mix-up risk when the access token and ID token come from the same exchange?

## References

- Kakao Developers, "Kakao Login — REST API" and "Common" (reviewed 2026-10-09).
- Ory, "Sign in with Naver" (community provider; reviewed 2026-10-09); the official Naver Developers login API specification is to be re-verified at M3 G1.
- OpenID Connect Core 1.0; RFC 7636 (PKCE); RFC 6749.

## 한국어 요약

모든 제공자는 하나의 `Provider` 트레이트로 구현하며, Google과 Kakao는 범용
OIDC 클라이언트의 설정 인스턴스이고 Naver는 ID 토큰이 없는 `oauth2` 종류에
프로필 매핑을 선언한 인스턴스입니다. Kakao의 이메일 검증 여부는 ID 토큰이 아니라
`/v2/user/me`의 `is_email_verified`에서 읽고, Naver는 검증 플래그가 없어
기본적으로 미검증으로 취급합니다. 클라이언트 비밀은 환경 변수 이름으로만
참조하고, 제공자 추가·삭제는 M4의 관리 API에서 테이블 조작으로 처리합니다.
