# S304 — Console status is read-only and shows no secret

<!-- scenario-status: approved -->

- Area: management
- Milestone: M4
- ADRs: 0016, 0010, 0012
- Threat model: TM-12, TM-45
- Gateway contract: n/a (the console route is scenario 300-8)

## Goal

A grant holder sees the applications, providers (with their health and
whether their secret variable is set), the store, the build and the
configuration generation on one page and one endpoint, nothing on that page
can change anything, no provider secret, caller key or cookie key value ever
appears, and the page is served from state Hopae already holds without
contacting a provider.

## Preconditions and fixtures

- Configuration `tests/fixtures/m4-admin.json` with two providers: `mock` (secret variable set) and `mock2` (`client_secret_env` naming an unset variable, so the provider is disabled at start, 013-3) and `mock3` (`managed_by = api`, disabled through the store by the test hooks to stand in for a later runtime change); applications `app`, `default` and the implicit `admin`.
- Administrator `u_a` (`Ha`), read-only administrator `u_v` (`Hv`); events and sessions from earlier scenarios; the `log` sink with 3 `failed` deliveries injected by the test hooks.
- The mock provider's discovery document is reachable at start and then switched to `discovery_down`.

## Main flow

### S304-1 Applications

- Given: `Ha`.
- When: `GET /v1/status` and `GET /`.
- Then: `apps` lists `app`, `default` and `admin` with `display_name`, `hosts`, `ports`, `enabled`, `session` (idle, absolute), `binding` (ip, ua, on_mismatch), `on_authz_change`, `verify_cache_seconds`, `logout_confirm`, `max_auth_age` and the count of `step_up` rules; `admin` shows `hosts: ["hopae-admin.example.test"]`, `session: {idle: "30m", absolute: "12h"}`, `binding.ip: strict`, `on_authz_change: terminate`, `max_auth_age: "12h"`; `app` and `default` show `max_auth_age: null`; `default` shows no hosts; the page renders the same as a table.

### S304-2 Providers with health and secret presence

- Given: as above; then the `discovery_down` switch and the discovery cache's hard deadline passed by the clock.
- When: `GET /v1/status` before and after.
- Then: before: `mock` (`kind: oidc`, `enabled: true`, `managed_by: file`, `health: ok`, `reauth: max_age`, `client_secret_env: "HOPAE_TEST_MOCK_SECRET"`, `secret_present: true`), `mock2` (`enabled: false`, `health: disabled`, `client_secret_env` naming the unset variable, `secret_present: false`), `mock3` (`managed_by: api`, `enabled: false`, `reauth: unsupported` from its stored setting); after: `mock.health` is `degraded` with reason `provider_unavailable` taken from the registry's cached discovery state; the status request itself made no outbound call (the mock records none); no field of any provider contains the secret's value (the harness greps the body for the generated value).

### S304-3 Store, build and configuration

- Given: as above.
- When: `GET /v1/status`.
- Then: `store`: `kind: sqlite`, `schema_version: 3`, `users`, `live_sessions`, `events` counts equal to the table counts, `deliveries: {log: {pending: n, failed: 3}}`, `last_prune_at`; `build`: `version` equal to `hopae --version`, `contract: "1.1"`, `started_at`; `config`: `generation` equal to the store's configuration generation, `digest` equal to the `config.loaded` event's `config_digest`, `insecure_mode: false`, `unauthenticated_caller: false`, `listeners` (the three bound addresses); no path of the state directory beyond what `/healthz` already shows.

### S304-4 The page and the endpoint change nothing

- Given: `Ha`.
- When: `POST /v1/status`, `POST /`, `POST /v1/providers/mock/disable`, `PUT /v1/apps/app`, `DELETE /v1/providers/mock2`.
- Then: `405` for the first two (`allow: GET`), `404 not_found` for the rest (no such endpoint in M4-min); no row changed; no event beyond the request log; the status page contains no form.

## Alternative flows

### S304-5 Read-only administrators see the status too

- Given: `Hv`.
- When: `GET /v1/status`, `GET /`.
- Then: `200` with the same body as for an administrator (the secret variable name and presence included: a name is not a secret); the page renders no form for either role.

## Abuse cases

| Category | Case | Applies |
| --- | --- | --- |
| Replay | — | no: a read with no state; replaying it is reading it again |
| Tampering | S304-A1 | yes |
| Race / timing | S304-A2 | yes |
| Resource exhaustion | S304-A3 | yes |
| Confused deputy | S304-A4 | yes |
| Spoofed or duplicated headers | — | no: covered by 300-A2 and 300-A6 |
| Downgrade | — | no: no negotiation; transport is 300-A7 |
| Enumeration | S304-A5 | yes |

### S304-A1 Query strings and bodies are ignored

- Given: `Ha`.
- When: `GET /v1/status?provider=mock&reveal=secret`, `GET /?x=` + 4 KiB, `GET /v1/status` with a 1 KiB body.
- Then: the same body as without; a query string over 4 KiB is `413`; no parameter is reflected anywhere in the page (the harness injects `<script>` and `"` in parameter values and asserts they do not appear).

### S304-A2 A consistent snapshot while things change

- Given: `Ha`; a configuration reload is not possible before M6, so the generation cannot change; the registry's health flips between two requests.
- When: 50 `GET /v1/status` while the mock switches between `default` and `discovery_down` every 10 ms and sessions are created and terminated concurrently.
- Then: every response is well-formed, `generation` and `digest` are constant, counts are non-negative integers, and `health` is one of the three values; nothing panics (counters and health are read from the registry's current state without locking the store's writer).

### S304-A3 Status is cheap

- Given: 1,000,000 events and 50,000 sessions (bulk); `Ha`.
- When: 16 concurrent `GET /v1/status` ten times.
- Then: each answers within the request budget (the counts come from `count(*)` over indexed columns or from maintained counters, pinned in the plan), no outbound request to any provider, memory under the harness limit, the 17th concurrent caller `503 overloaded`.

### S304-A4 The page cannot be used to trigger a provider or a gateway call

- Given: `Ha`; `gateway.admin_url` and `gateway.readonly_token_env` configured.
- When: `GET /v1/status` and `GET /`.
- Then: no request reaches the mock provider or the harness's fake gateway admin endpoint: the console does not run the drift query (that stays `hopae --check`'s), and health comes from cached state only.

### S304-A5 Nothing leaks to the unauthorized

- Given: no handle; `Hn`.
- When: `GET /v1/status`, `GET /`.
- Then: `403 login_required` resp. `403 not_admin`; the bodies name no application host, provider, version or listener; `/healthz` on the portal remains the only unauthenticated status surface and keeps its M1 content.

## Observability expectations

- Log: nothing per read.
- Audit: none (read-only).
- Metrics: `hopae_admin_requests_total{role,outcome}`; the status body itself is not a metrics exposition (M7).

## Test mapping

| Case | Test | File | Kind | Status |
| --- | --- | --- | --- | --- |
| S304-1 | `s304_1_applications_listed_with_policy` | `tests/scenarios/s304_admin_status.rs` | integration | planned |
| S304-2 | `s304_2_providers_with_health_and_secret_presence` | `tests/scenarios/s304_admin_status.rs` | integration | planned |
| S304-3 | `s304_3_store_build_and_configuration` | `tests/scenarios/s304_admin_status.rs` | integration | planned |
| S304-4 | `s304_4_page_and_endpoint_change_nothing` | `tests/scenarios/s304_admin_status.rs` | integration | planned |
| S304-5 | `s304_5_read_only_administrators_see_the_status_too` | `tests/scenarios/s304_admin_status.rs` | integration | planned |
| S304-A1 | `s304_a1_query_strings_and_bodies_ignored` | `tests/scenarios/s304_admin_status.rs` | integration | planned |
| S304-A2 | `s304_a2_consistent_snapshot_while_things_change` | `tests/scenarios/s304_admin_status.rs` | integration | planned |
| S304-A3 | `s304_a3_status_is_cheap` | `tests/scenarios/s304_admin_status.rs` | integration | planned |
| S304-A4 | `s304_a4_page_cannot_trigger_provider_or_gateway_call` | `tests/scenarios/s304_admin_status.rs` | integration | planned |
| S304-A5 | `s304_a5_nothing_leaks_to_the_unauthorized` | `tests/scenarios/s304_admin_status.rs` | integration | planned |

## Live verification

| Date | Hopae version | Gateway version | Provider | Environment label | Result | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| — | — | — | — | — | — | Not yet run. |

## Open questions

- Should the status page show the phase-0 drift findings (`hopae --check`'s read-only gateway query) when a read-only credential is configured, or stay free of outbound calls as decided here?

## 한국어 요약

상태 페이지와 `GET /v1/status`는 애플리케이션, 제공자(상태와 비밀 변수의 이름·존재
여부), 저장소, 빌드, 설정 세대를 읽기 전용으로 보여 줍니다. 어떤 비밀 값도 나타나지
않고, 제공자 상태는 캐시된 디스커버리 상태에서 오므로 아웃바운드 호출이 없으며,
`POST`나 매개변수는 아무것도 바꾸거나 반영하지 않습니다. M4-min에는 제공자 변경
엔드포인트가 없고, 나중에 추가되면 `managed_by = api`가 여기서 보입니다.
