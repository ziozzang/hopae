# S012 — Provider failure modes

<!-- scenario-status: draft -->

- Area: providers
- Milestone: M1
- ADRs: 0003, 0010
- Threat model: TM-08, TM-12, TM-17
- Gateway contract: n/a

## Goal

When the identity provider is down, slow, returns malformed data, rotates
keys or changes its discovery document, Hopae fails the login attempt with a
clear reason, keeps existing sessions working, never skips a validation step,
and never leaks provider secrets or tokens.

## Preconditions and fixtures

- Configuration `tests/fixtures/m1-basic.json`; provider `mock`.
- Mock profiles: `discovery_down`, `discovery_changed_issuer`, `jwks_rotated`, `jwks_unknown_kid`, `token_500`, `token_slow`, `token_malformed`, `userinfo_500`, `id_token_missing`, `oversized`.
- Injected clock for cache deadlines.

## Main flow

### S012-1 Discovery unavailable at start is retried, not fatal

- Given: `discovery_down` at process start.
- When: `hopae run`.
- Then: the process starts; the provider is marked `degraded`; `/login` shows the provider as temporarily unavailable; `healthz` body reports `providers.mock = degraded`; discovery is retried with backoff (1 s … 60 s); existing sessions verify normally.

### S012-2 Token endpoint error fails the attempt cleanly

- Given: `token_500`.
- When: callback.
- Then: `502`-class portal page "sign-in failed, try again"; `login.failed` with `reason=provider_error`, `provider_status=500`; the transaction stays valid for a retry until its expiry; no session.

### S012-3 Slow token endpoint is bounded

- Given: `token_slow` (15 s).
- When: callback.
- Then: Hopae aborts at 10 s; `reason=provider_timeout`; the portal page returns within 11 s.

### S012-4 Key rotation is handled

- Given: `jwks_rotated` (new `kid` published, old removed).
- When: callback with a token signed by the new key.
- Then: Hopae refetches JWKS once on unknown `kid` (rate limited to once per 60 s), validates, creates the session. With `jwks_unknown_kid` (kid never published): `reason=invalid_signature`, no second refetch within 60 s.

## Alternative flows

### S012-5 Discovery document changes issuer

- Given: `discovery_changed_issuer` after the cache half-life.
- When: refresh.
- Then: the new document is rejected (`issuer` must equal the configured issuer); the previous document stays in use until its hard deadline; event `provider.error` with `reason=discovery_issuer_mismatch`.

### S012-6 User-info failure for providers that need it

- Given: a provider configured with a user-info mapping (Kakao preset in M3; the mock in M1) and `userinfo_500`.
- When: callback.
- Then: `reason=provider_error` at the user-info step; no session (email verification status is required for linking decisions).

### S012-7 Existing sessions are unaffected by any provider failure

- Given: any failing profile.
- When: verify with a valid handle.
- Then: `200`; no provider call is made by verify (asserted by the mock's request log).

## Abuse cases

| Category | Case | Applies |
| --- | --- | --- |
| Replay | — | no: covered by 002 |
| Tampering | S012-A1 | yes |
| Race / timing | S012-A2 | yes |
| Resource exhaustion | S012-A3 | yes |
| Confused deputy | S012-A4 | yes |
| Spoofed or duplicated headers | — | no |
| Downgrade | S012-A5 | yes |
| Enumeration | — | no |

### S012-A1 Malformed token response does not crash or leak

- Given: `token_malformed` (invalid JSON, then JSON with `id_token` as a number, then a 3-part JWT with invalid base64).
- When: callback.
- Then: `reason=provider_response_invalid` for each; the process keeps serving; the log line contains the provider id and the parse error class, never the body.

### S012-A2 Hard deadline on cached discovery and keys

- Given: discovery and JWKS cached; the provider is down past the 24 h hard deadline.
- When: callback at `t_cache + 24h + 1s`.
- Then: `reason=provider_unavailable`; the stale keys are not used to validate.

### S012-A3 Backoff prevents a retry storm

- Given: `discovery_down`; 1,000 `/login` requests in a minute.
- When: run.
- Then: at most the backoff-scheduled number of discovery fetches (≤ 7 in the first minute); the portal answers quickly with the unavailable notice.

### S012-A4 Token endpoint redirect is not followed

- Given: the mock's token endpoint answers `302` to another host.
- When: callback.
- Then: `reason=provider_response_invalid`; no request to the redirect target (mock asserts).

### S012-A5 Algorithm or type downgrade in the ID token is rejected

- Given: tokens with `alg: none`, `alg: HS256`, missing `kid` with multiple keys, `typ: JWT` where the provider is configured to require a specific `typ`.
- When: callback.
- Then: `reason=invalid_signature` or `invalid_token_header`; no session.

## Observability expectations

- Log: `provider.error` with `provider_id`, `endpoint`, `reason`, `status`, elapsed; never bodies or secrets.
- Audit: `events` rows for `login.failed` and `provider.error`.
- Metrics: `hopae_provider_request_seconds{provider,endpoint}`, `hopae_provider_errors_total{provider,endpoint,reason}`, `hopae_provider_state{provider}` gauge.

## Test mapping

| Case | Test | File | Kind | Status |
| --- | --- | --- | --- | --- |
| S012-1 | `s012_1_discovery_down_at_start_degraded` | `tests/scenarios/s012_provider_failures.rs` | integration | planned |
| S012-2 | `s012_2_token_error_fails_cleanly` | `tests/scenarios/s012_provider_failures.rs` | integration | planned |
| S012-3 | `s012_3_slow_token_bounded` | `tests/scenarios/s012_provider_failures.rs` | integration | planned |
| S012-4 | `s012_4_key_rotation_handled` | `tests/scenarios/s012_provider_failures.rs` | integration | planned |
| S012-5 | `s012_5_discovery_issuer_change_rejected` | `tests/scenarios/s012_provider_failures.rs` | integration | planned |
| S012-6 | `s012_6_userinfo_failure_no_session` | `tests/scenarios/s012_provider_failures.rs` | integration | planned |
| S012-7 | `s012_7_sessions_unaffected_by_provider` | `tests/scenarios/s012_provider_failures.rs` | integration | planned |
| S012-A1 | `s012_a1_malformed_token_response_safe` | `tests/scenarios/s012_provider_failures.rs` | integration | planned |
| S012-A2 | `s012_a2_hard_deadline_on_caches` | `tests/scenarios/s012_provider_failures.rs` | integration | planned |
| S012-A3 | `s012_a3_backoff_prevents_storm` | `tests/scenarios/s012_provider_failures.rs` | integration | planned |
| S012-A4 | `s012_a4_token_redirect_not_followed` | `tests/scenarios/s012_provider_failures.rs` | integration | planned |
| S012-A5 | `s012_a5_algorithm_downgrade_rejected` | `tests/scenarios/s012_provider_failures.rs` | unit | planned |

## Live verification

| Date | Hopae version | Gateway version | Provider | Environment label | Result | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| — | — | — | — | — | — | Failure injection is mock-only; the live run records the ceiling of evidence. |

## Open questions

- Should a degraded provider be hidden from the chooser or shown as unavailable? (Shown, so users understand why; confirm with the maintainer.)

## 한국어 요약

제공자가 다운되거나 느리거나 잘못된 응답을 보내거나 키를 교체해도 Hopae는
사유 코드와 함께 로그인 시도만 실패시키고 기존 세션은 계속 동작합니다.
디스커버리·JWKS 캐시는 하드 데드라인이 있어 오래된 키로 검증하지 않으며,
토큰 엔드포인트의 리디렉션과 알고리즘 다운그레이드는 거부합니다. 로그에 토큰이나
비밀은 남지 않습니다.
