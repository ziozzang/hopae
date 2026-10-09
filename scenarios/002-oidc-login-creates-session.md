# S002 — Login with an OIDC provider creates a session

<!-- scenario-status: draft -->

- Area: providers
- Milestone: M1
- ADRs: 0004, 0008, 0010, 0011
- Threat model: TM-03, TM-04, TM-08, TM-09, TM-12
- Gateway contract: Portal entry points (`/login/<p>`, `/callback/<p>`), Cookies

## Goal

A user completes the authorization-code flow with PKCE and nonce at the
portal; Hopae validates the ID token, creates or finds the user, records a
session with its first factor and binding context, plants the portal handle
and redirects to the application with a handoff code. A forged, replayed or
mixed-up callback never creates a session.

## Preconditions and fixtures

- Configuration `tests/fixtures/m1-basic.json`; provider `mock` (`oidc`, issuer from the mock's discovery document, `client_secret_env = HOPAE_TEST_MOCK_SECRET`).
- Mock provider profile `default`; profiles `wrong_state`, `wrong_nonce`, `expired_token`, `wrong_aud`, `invalid_signature`, `unverified_email`, `oversized` for abuse and failure cases.
- Transaction `T1` from scenario 001 with `return_target = https://app.example.test/admin/x`, cookie `__Host-hopae_txn=T1` held by the browser.
- Injected clock; injected randomness for `state=S1`, `nonce=N1`, PKCE verifier `V1`, session id `s_1`, handle `H0`, handoff code `K1`.

## Main flow

### S002-1 Starting the provider flow stores state, nonce and PKCE

- Given: `T1` unconsumed; chooser page loaded (CSRF token `C1` bound to the transaction cookie).
- When: `POST /login/mock` with form `csrf=C1`, cookie `__Host-hopae_txn=T1`, `origin: https://auth.example.test`.
- Then: `302` to the mock authorization endpoint with `response_type=code`, `client_id`, `redirect_uri=https://auth.example.test/callback/mock`, `scope=openid email profile`, `state=S1`, `nonce=N1`, `code_challenge=S256(V1)`; the transaction row holds `provider_id=mock`, `state_sha256`, `nonce`, `pkce_verifier`; event `login.started` is not duplicated (already emitted in 001).

### S002-2 Callback exchanges the code and validates the ID token

- Given: the mock issued `code=AC1` for `S1` with `nonce=N1`.
- When: `GET /callback/mock?code=AC1&state=S1` with cookie `__Host-hopae_txn=T1`.
- Then: Hopae `POST`s the mock token endpoint with `grant_type=authorization_code`, `code=AC1`, `code_verifier=V1`, `redirect_uri`, client authentication; the ID token passes `iss`, `aud`, `exp`, `iat` (60 s leeway), `nonce=N1`, signature (`kid` from JWKS); no redirects followed on the token call; `users` row created with `primary_email` from the token (verified), `identities` row `(mock, sub)`; `sessions` row `s_1` with `provider_id=mock`, `factors=[{"kind":"oidc","provider":"mock","at":now}]`, `aal=1`, `bound_ip=203.0.113.9`, `bound_ua_sha256`, `idle_expires_at`, `absolute_expires_at`; `session_handles` row for `(s_1, auth.example.test)`; `handoff_codes` row for `(s_1, app.example.test, /admin/x, 203.0.113.9)` expiring in 60 s; transaction `consumed_at` set.
- Then (response): `302 location: https://app.example.test/admin/x?_hopae_handoff=K1`; `set-cookie: __Host-hopae=H0; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=<absolute remaining>`; `set-cookie: __Host-hopae_txn=; Max-Age=0; …`; `cache-control: no-store`; events `login.succeeded`, `session.created`.

### S002-3 Returning user maps to the existing identity

- Given: `identities(mock, sub)` exists for user `u_1` with an old `name`.
- When: S002-2 again with a new name in the token.
- Then: no new user; `identities.name` and `last_seen_at` updated; `users.primary_email` unchanged; a second session row.

## Alternative flows

### S002-4 Verified email from a trusted provider links to an existing user

- Given: user `u_1` has `primary_email = a@example.test` (verified) from provider `trusted1`; provider `mock` is in `linking.trusted_providers`; the token asserts `a@example.test` with `email_verified=true`.
- When: callback for a new `sub`.
- Then: identity attached to `u_1`; event `identity.linked` with `reason=verified_email`; session belongs to `u_1`.

### S002-5 Unverified email never links

- Given: as S002-4 but profile `unverified_email` (`email_verified=false`) or `mock` not in `linking.trusted_providers`.
- When: callback.
- Then: a new user with empty `primary_email`; portal shows the "already in use" notice on the chooser the next time; `x-forwarded-email` omitted for this session; event `identity.conflict` with `reason=unverified_email` or `untrusted_provider`.

### S002-6 Single sign-on from a valid portal handle skips the provider

- Given: the browser holds portal handle `H0` for session `s_1` whose binding passes; a new transaction `T2` for `other.example.org`.
- When: `GET /login?txn=T2` with cookie `__Host-hopae=H0`.
- Then: `302` directly to `https://other.example.org/?_hopae_handoff=K2`; no provider call; `auth_time` unchanged; event `session.handoff` with `sso=true`.

## Abuse cases

| Category | Case | Applies |
| --- | --- | --- |
| Replay | S002-A1 | yes |
| Tampering | S002-A2 | yes |
| Race / timing | S002-A3 | yes |
| Resource exhaustion | S002-A4 | yes |
| Confused deputy | S002-A5 | yes |
| Spoofed or duplicated headers | S002-A6 | yes |
| Downgrade | S002-A7 | yes |
| Enumeration | S002-A8 | yes |

### S002-A1 Replayed callback is rejected

- Given: S002-2 completed (transaction consumed).
- When: the same `GET /callback/mock?code=AC1&state=S1` again, with or without the (now cleared) transaction cookie.
- Then: `400` expired-link page; no token endpoint call; no new session; event `login.failed` with `reason=txn_consumed`.

### S002-A2 Tampered state, nonce, audience, signature or expiry is rejected

- Given: profiles `wrong_state`, `wrong_nonce`, `wrong_aud`, `invalid_signature`, `expired_token`, each in turn.
- When: callback.
- Then: `400` generic failure page; no session; `login.failed` with `reason` in `invalid_state`, `invalid_nonce`, `invalid_audience`, `invalid_signature`, `token_expired`; the mock records exactly one token request for `wrong_nonce`/`wrong_aud`/`invalid_signature`/`expired_token` and zero for `wrong_state`.

### S002-A3 Concurrent callbacks for one transaction create one session

- Given: `T1` unconsumed.
- When: two identical callback requests race.
- Then: exactly one session row and one handoff code; the loser answers `400 txn_consumed`; the store's conditional consume is the arbiter.

### S002-A4 Oversized or slow provider responses are bounded

- Given: profile `oversized` (JWKS 1 MiB, token response 1 MiB) and profile `slow` (15 s).
- When: callback.
- Then: `400` with `reason=provider_response_too_large` or `provider_timeout`; memory stays bounded; the transaction remains usable until its own expiry.

### S002-A5 Login CSRF: a victim cannot complete the attacker's transaction

- Given: attacker started `T9` in their browser and obtained `state=S9`; victim's browser holds no `__Host-hopae_txn` cookie (or holds `T1`).
- When: the victim's browser is sent to `GET /callback/mock?code=AC9&state=S9`.
- Then: `400`; `reason=txn_cookie_mismatch` (or `txn_missing`); no token exchange; no session for the victim.

### S002-A6 Provider mix-up: artifacts from provider A cannot complete a transaction for provider B

- Given: `T1` chose provider `mock`; a second provider `mock2` with a different issuer.
- When: `GET /callback/mock2?code=AC1&state=S1` with the `T1` cookie; separately, a token from `mock2`'s issuer presented on `/callback/mock`.
- Then: `400 provider_mismatch` without any token exchange for the first; `invalid_issuer` for the second; no session.

### S002-A7 Missing PKCE or nonce support cannot be negotiated away

- Given: a provider configuration whose discovery document omits `code_challenge_methods_supported`.
- When: start the flow.
- Then: Hopae still sends `code_challenge` (S256) and `nonce`; a token response without `id_token` is rejected with `reason=id_token_missing` for kind `oidc`.

### S002-A8 Failure pages do not reveal whether an account exists

- Given: profiles `unverified_email` for an email that exists and one that does not.
- When: callback.
- Then: identical status, page body (except a per-request id) and timing within the harness tolerance; the distinction exists only in the `events` row.

## Observability expectations

- Log: `login.succeeded`/`login.failed` with `provider_id`, `reason`, `txn` digest prefix, `user_id`, `session_id`; never tokens, codes, `state` values or emails of conflicting accounts.
- Audit: `events` rows for `login.*`, `session.created`, `identity.linked`, `identity.conflict`.
- Metrics: `hopae_login_total{provider,outcome,reason}`, `hopae_provider_request_seconds{provider,endpoint}`.

## Test mapping

| Case | Test | File | Kind | Status |
| --- | --- | --- | --- | --- |
| S002-1 | `s002_1_start_stores_state_nonce_pkce` | `tests/scenarios/s002_oidc_login.rs` | integration | planned |
| S002-2 | `s002_2_callback_validates_and_creates_session` | `tests/scenarios/s002_oidc_login.rs` | integration | planned |
| S002-3 | `s002_3_returning_identity_reused` | `tests/scenarios/s002_oidc_login.rs` | integration | planned |
| S002-4 | `s002_4_verified_trusted_email_links` | `tests/scenarios/s002_oidc_login.rs` | integration | planned |
| S002-5 | `s002_5_unverified_email_never_links` | `tests/scenarios/s002_oidc_login.rs` | integration | planned |
| S002-6 | `s002_6_sso_from_portal_handle` | `tests/scenarios/s002_oidc_login.rs` | integration | planned |
| S002-A1 | `s002_a1_replayed_callback_rejected` | `tests/scenarios/s002_oidc_login.rs` | integration | planned |
| S002-A2 | `s002_a2_tampered_token_artifacts_rejected` | `tests/scenarios/s002_oidc_login.rs` | integration | planned |
| S002-A3 | `s002_a3_concurrent_callbacks_single_session` | `tests/scenarios/s002_oidc_login.rs` | integration | planned |
| S002-A4 | `s002_a4_oversized_and_slow_provider_bounded` | `tests/scenarios/s002_oidc_login.rs` | integration | planned |
| S002-A5 | `s002_a5_login_csrf_rejected` | `tests/scenarios/s002_oidc_login.rs` | integration | planned |
| S002-A6 | `s002_a6_provider_mixup_rejected` | `tests/scenarios/s002_oidc_login.rs` | integration | planned |
| S002-A7 | `s002_a7_pkce_nonce_not_negotiable` | `tests/scenarios/s002_oidc_login.rs` | integration | planned |
| S002-A8 | `s002_a8_failure_pages_uniform` | `tests/scenarios/s002_oidc_login.rs` | integration | planned |

## Live verification

| Date | Hopae version | Gateway version | Provider | Environment label | Result | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| — | — | — | — | — | — | Main flow to run against the Google test tenant at G8. |

## Open questions

- Should S002-6 (SSO) refresh the portal handle to rotate the cookie value?
- Does a `prefers-fresh-login` per application belong in M1 (`max_auth_age`), given SSO exists from M1?

## 한국어 요약

포털에서 PKCE와 nonce를 사용하는 authorization-code 흐름으로 로그인하면 ID
토큰을 검증하고 사용자·신원·세션(첫 요소, 바인딩 맥락 포함)을 만들며, 포털
핸들을 심고 핸드오프 코드와 함께 애플리케이션으로 돌려보냅니다. 재사용된
콜백, 변조된 state/nonce/aud/서명, 로그인 CSRF, 제공자 혼동은 모두 세션을
만들지 못합니다.
