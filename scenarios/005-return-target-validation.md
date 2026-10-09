# S005 — Return targets are validated and never taken from the client

<!-- scenario-status: approved -->

- Area: security
- Milestone: M1
- ADRs: 0004, 0005
- Threat model: TM-01, TM-26, TM-30
- Gateway contract: Verify endpoint (`x-original-url`), Cross-domain handoff

## Goal

Every `Location` Hopae emits toward an application is derived from the
gateway-generated original URL, validated against the explicit return-origin
allowlist (exactly the registered application host names and ports) and
bounds, and an attacker cannot turn the portal or the handoff into an open
redirector, not even by choosing the `Host` header on a host-neutral route
or by controlling an unregistered sibling host.

## Preconditions and fixtures

- Configuration `tests/fixtures/m1-two-domains.json`: application `app` with host `app.example.test`, application `other` with host `other.example.org`; the `default` application carries policy defaults and no hosts; no `ports` listed (443 only).
- Unit fixtures: a table of URLs and expected validation outcomes in `tests/fixtures/return-targets.json`.

## Main flow

### S005-1 Valid original URL is stored and emitted unchanged

- Given: no cookie.
- When: verify with `x-original-url: https://app.example.test:443/a/b?x=1%202&y=%2F` and `x-forwarded-host: app.example.test`.
- Then: transaction `return_target = https://app.example.test:443/a/b?x=1%202&y=%2F`; after login the handoff `location` is that string plus `&_hopae_handoff=…`; after redemption the final `location` equals the stored target byte for byte.

### S005-2 Validation table

- Given: each row of the fixture.
- When: validated by the pure function.
- Then: outcomes as listed:

| Original URL | Outcome |
| --- | --- |
| `https://app.example.test/` | accept |
| `https://app.example.test/path?q=1` | accept |
| `http://app.example.test/` with `cookie.secure=true` | reject `insecure_transport` |
| `https://evil.example.org/` | reject `unknown_app` |
| `https://app.example.test@evil.example.org/` | reject `userinfo` |
| `https://app.example.test/#frag` | reject `fragment` |
| `https://app.example.test/` + 2,100 chars | reject `too_long` |
| `//app.example.test/` | reject `not_absolute` |
| `https://app.example.test.evil.example.org/` | reject `unknown_app` |
| `https://APP.example.test/` | accept (host compared case-insensitively; emitted lower-case) |
| `https://app.example.test/..%2fadmin` | accept as a return target (the path is the application's URL); the canonical path for policy is computed separately and this one is non-canonical, so policy rules deny it |
| `https://app.example.test:8443/` | reject `port_not_allowed` (no `apps[].ports` entry) |
| `https://app.example.test:443/` | accept |
| `https://new.example.test/` | reject `unknown_app` (sibling of a registered host; no suffix matching exists) |
| `https://old.example.test/` | reject `unknown_app` (a formerly used host that was removed from `apps[].hosts`) |
| `javascript:alert(1)` | reject `scheme` |

## Alternative flows

### S005-3 Only exact registered hosts are credential destinations

- Given: a configuration that tries `hosts = ["*.example.test"]` and one that tries `hosts = ["App.Example.Test"]`.
- When: `hopae --check`, then verify with `x-forwarded-host: new.example.test` against the valid fixture.
- Then: the wildcard configuration is rejected by preflight (`hosts must be exact lower-case host names`); the mixed-case entry is normalized to lower-case with a warning; the verify answers `403 unknown_app` with no transaction and no cookie. There is no configuration that accepts every host or a suffix of hosts; with the read-only gateway credential (phase 1) `hopae --check` warns for every registered host whose DNS does not resolve to the gateway's addresses.

## Abuse cases

| Category | Case | Applies |
| --- | --- | --- |
| Replay | — | no: targets are not secrets; replay is covered in 003 |
| Tampering | S005-A1 | yes |
| Race / timing | — | no: pure validation |
| Resource exhaustion | S005-A2 | yes |
| Confused deputy | S005-A3 | yes |
| Spoofed or duplicated headers | S005-A4, S005-A7 | yes |
| Downgrade | S005-A5 | yes |
| Enumeration | S005-A6 | yes |

### S005-A1 Portal query parameters cannot alter the target

- Given: transaction `T1` with target `https://app.example.test/a`.
- When: `GET /login?txn=T1&redirect_uri=https://evil.example.org/`, `POST /login/mock` with a form field `return=https://evil.example.org/`, and a callback with `state=S1&return=…`.
- Then: every `location` emitted during the flow is the stored target or the provider's authorization endpoint; the extra parameters are ignored; a `warn` log notes unexpected parameters once per minute.

### S005-A2 Pathological URLs are bounded

- Given: a 64 KiB `x-original-url`, a URL with 10,000 query parameters.
- When: verify.
- Then: `400 contract_violation` (`too_long`) before parsing beyond the length check; CPU time bounded (unit benchmark under 1 ms).

### S005-A3 Provider-supplied redirect cannot be used as target

- Given: the mock's token response includes a `redirect_to` field and the callback carries `next=…`.
- When: callback completes.
- Then: the handoff `location` is the stored target; provider JSON fields other than the known set are ignored.

### S005-A4 Host spoofing through case or trailing dot

- Given: `x-forwarded-host: app.example.test.` and `App.Example.Test`.
- When: verify.
- Then: the trailing-dot form is rejected (`unknown_app`) unless registered; the case variant is accepted and normalized.

### S005-A5 Scheme downgrade in the stored target

- Given: `cookie.secure=false` (development).
- When: `http://app.example.test/` target.
- Then: accepted only in this mode; the cookie is set without `Secure`; preflight has printed the insecure-mode warning; the event carries `insecure_mode=true`.

### S005-A6 Registered host list is not enumerable through error differences

- Given: unknown host and a registered but disabled application.
- When: verify for each.
- Then: both answer `403` with the same body; reasons differ only in events (`unknown_app` versus `app_disabled`).

### S005-A7 Attacker-chosen `Host` on a host-neutral route cannot become a return origin

- Given: gateway layer; a protected route **without** `host`/`hosts` (host-neutral) whose `auth` points at Hopae; the gateway validates the syntax of a client `Host` and generates `x-original-url` from it.
- When: a client sends `GET /admin/x` with `Host: evil.example.org` through that route, then with `Host: app.example.test`.
- Then: for `evil.example.org`: `403` relayed to the client, `x-hopae-reason: unknown_app`, no transaction, no binding cookie; for `app.example.test`: the normal `302` to the portal with a transaction whose `return_target` host is `app.example.test`. No `Location` emitted by Hopae in this scenario ever names a host outside the allowlist.

## Observability expectations

- Log: `verify.denied` with `reason` for rejected targets; `warn` for ignored client parameters (rate limited).
- Audit: `events` rows as sampled.
- Metrics: `hopae_return_target_rejected_total{reason}`.

## Test mapping

| Case | Test | File | Kind | Status |
| --- | --- | --- | --- | --- |
| S005-1 | `s005_1_valid_target_round_trips_unchanged` | `tests/scenarios/s005_return_target.rs` | integration | planned |
| S005-2 | `s005_2_validation_table` | `tests/scenarios/s005_return_target.rs` | unit | planned |
| S005-3 | `s005_3_only_exact_hosts_are_destinations` | `tests/scenarios/s005_return_target.rs` | integration | planned |
| S005-A1 | `s005_a1_portal_parameters_cannot_alter_target` | `tests/scenarios/s005_return_target.rs` | integration | planned |
| S005-A2 | `s005_a2_pathological_urls_bounded` | `tests/scenarios/s005_return_target.rs` | unit | planned |
| S005-A3 | `s005_a3_provider_redirect_ignored` | `tests/scenarios/s005_return_target.rs` | integration | planned |
| S005-A4 | `s005_a4_host_case_and_trailing_dot` | `tests/scenarios/s005_return_target.rs` | unit | planned |
| S005-A5 | `s005_a5_scheme_downgrade_only_in_dev_mode` | `tests/scenarios/s005_return_target.rs` | integration | planned |
| S005-A6 | `s005_a6_no_host_enumeration` | `tests/scenarios/s005_return_target.rs` | integration | planned |
| S005-A7 | `s005_a7_host_neutral_route_attacker_host_denied` | `tests/scenarios/s005_return_target.rs` | gateway | planned |

## Live verification

| Date | Hopae version | Gateway version | Provider | Environment label | Result | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| — | — | — | — | — | — | Not yet run. |

## Open questions

- Should a port in `x-original-url` other than 443 be allowed when the application's registered host has no port?

## 한국어 요약

Hopae가 애플리케이션으로 보내는 모든 `Location`은 게이트웨이가 만든
`x-original-url`에서만 나오며, 정확히 등록된 애플리케이션 호스트 이름과 포트로만
이루어진 허용 목록과 스킴·길이·userinfo·fragment 검사를 통과해야 합니다.
와일드카드나 접미사 패턴은 없으므로, 호스트 중립 라우트에서 공격자가 `Host`를
골라도, 등록되지 않은 형제 호스트를 장악해도 돌아갈 출처가 될 수 없고 오픈
리디렉션이 성립하지 않습니다.
