# S013 — Configuration preflight and startup

<!-- scenario-status: approved -->

- Area: lifecycle
- Milestone: M1
- ADRs: 0002, 0003, 0005, 0010, 0012
- Threat model: TM-12, TM-14, TM-19, TM-34, TM-35
- Gateway contract: Prerequisites and configuration

## Goal

`hopae --check` validates the whole configuration, resolves secrets by
reference without printing them, reports the gateway integration facts the
operator must register, and `hopae run` refuses to start on any invalid or
unsafe configuration.

## Preconditions and fixtures

- Fixtures under `tests/fixtures/config/`: `valid.json`, `unknown_key.json`, `missing_secret.json`, `insecure_cookie.json`, `missing_caller_key.json`, `unauthenticated_caller.json`, `public_gateway_listener.json`, `cache_too_long.json`, `bad_app_host.json`, `duplicate_host.json`.
- Environment variables set by the harness per case; never real values.

## Main flow

### S013-1 Valid configuration passes

- Given: `valid.json` and `HOPAE_TEST_MOCK_SECRET`, `HOPAE_TEST_GATEWAY_KEY` set.
- When: `hopae --check --config valid.json`.
- Then: exit 0; stdout lists listeners, store kind and path, applications with host patterns, ports and binding policy, the return-origin allowlist, providers with their `redirect_uri` and `managed_by`, identity header set, the verify budget, the declared cache staleness bound (`0` here), and the gateway route `auth` fragment to register including `static_request_headers` with the **name** of the caller-key variable; no secret value appears (asserted by grepping for both env vars' values).

### S013-2 Unknown key is rejected

- Given: `unknown_key.json`.
- When: `--check`.
- Then: exit 2; message names the key path (`apps[0].bindng`) and suggests the nearest known key.

### S013-3 Missing provider secret degrades with a warning, not a failure

- Given: `missing_secret.json` (provider references an unset variable).
- When: `--check` and `run`.
- Then: `--check` exit 0 with `warning: provider mock disabled: HOPAE_TEST_MOCK_SECRET unset`; `run` starts with the provider disabled; `/login` lists no providers and shows the unavailable notice; `--check --strict` exits 2.

### S013-4 `run` refuses an invalid configuration

- Given: any failing fixture.
- When: `hopae run`.
- Then: exit 2 before binding any listener; the error is identical to `--check`'s.

## Alternative flows

### S013-5 Startup order and readiness

- Given: `valid.json`.
- When: `hopae run`.
- Then: store opened and migrated → configuration mirrored into `providers`/`apps` → listeners bound (gateway listener last) → `healthz` answers `200` with `ready=true`; on `SIGTERM` listeners close, in-flight verify calls complete within 5 s, the store checkpoints, exit 0.

### S013-6 Migration from an older schema and provider authority on restart

- Given: a store at schema version 1 (fixture file); separately, a store whose `providers` row `google` is `enabled = false, managed_by = api` while the configuration file lists `google` as enabled; separately, a store where `google` was **removed** through the management API (tombstone row with `deleted_at` set) while the file still lists it.
- When: `run`, then a callback for `google`.
- Then: migrated to the current version inside a transaction; `meta.schema_version` updated; a backup copy `hopae.sqlite.bak-v1` is written first for SQLite. For the disabled case: `google` stays disabled after start, the log says `provider google: database authoritative (managed_by=api); file entry ignored`, callbacks answer `provider_disabled`. For the removed case: the tombstone is kept, the provider is absent from the chooser, the log says `provider google: removed at run time; file entry ignored`, and the callback answers `provider_disabled`. `hopae providers import --force google` is the only way to reassert the file in either case and it logs an `admin.*` event.

### S013-7 Reload is not supported in M1; caller-key rotation uses restarts without an outage

- Given: running process with `gateway.caller_key_env = HOPAE_GW_KEY_A`.
- When: `SIGHUP`; then the rotation sequence: restart with `gateway.caller_key_next_env = HOPAE_GW_KEY_B` added, switch the harness gateway to key B, restart with `caller_key_env = HOPAE_GW_KEY_B` and `caller_key_next_env` removed.
- Then: `SIGHUP` is logged `reload not supported; restart` with no change (configuration reload arrives in M6). During the rotation, verifies presenting key A or key B are accepted at every step except the last, where only B is accepted; no verify in the sequence is refused; `hopae --check` warns `caller_key_next_env configured since <date>` once the overlap exceeds 7 days.

## Abuse cases

| Category | Case | Applies |
| --- | --- | --- |
| Replay | — | no |
| Tampering | S013-A1 | yes |
| Race / timing | S013-A2 | yes |
| Resource exhaustion | S013-A3 | yes |
| Confused deputy | S013-A4 | yes |
| Spoofed or duplicated headers | — | no |
| Downgrade | S013-A5 | yes |
| Enumeration | — | no |

### S013-A1 Unsafe values are rejected, not warned

- Given: `missing_caller_key.json` (`gateway.kind = hangang` without `gateway.caller_key_env` and without `gateway.allow_unauthenticated_caller`), `public_gateway_listener.json` (`listen.gateway = 0.0.0.0:8701`), `cache_too_long.json` (`verify_cache_seconds = 60`), `bad_app_host.json` (host with scheme or path), `duplicate_host.json` (two applications claim one host), and a variant where `gateway.caller_key_env` names an unset variable.
- When: `--check`.
- Then: exit 2 for each with a specific message; the public-listener case passes only with a configured caller key **and** a warning that a non-loopback bind relies on the key alone; the unset-variable case exits 2 (a missing caller key is never a warning).

### S013-A2 Two processes on one SQLite file

- Given: an instance running on `state/hopae.sqlite`.
- When: a second `hopae run` with the same store.
- Then: the second exits 2 with `store locked by another instance` (advisory lock file next to the database); no corruption.

### S013-A3 Huge configuration files are bounded

- Given: a 50 MiB configuration file.
- When: `--check`.
- Then: exit 2 `configuration too large (limit 4 MiB)` without reading it fully.

### S013-A4 Secrets are not read from the configuration file

- Given: a configuration with `client_secret: "literal"` instead of `client_secret_env`.
- When: `--check`.
- Then: exit 2 `secrets must be referenced by environment variable name`; the literal is not echoed in the error.

### S013-A5 Insecure modes must be explicit and loud

- Given: `insecure_cookie.json` (`cookie.secure = false`) and `unauthenticated_caller.json` (`gateway.allow_unauthenticated_caller = true`).
- When: `--check` and `run`.
- Then: both print `WARNING: insecure cookie mode (development only)` or `WARNING: verify caller authentication disabled (development only)` to stderr; the health body reports `insecure_mode=true` or `unauthenticated_caller=true`; `--strict` exits 2 for either.

## Observability expectations

- Log: `config.loaded` event with a digest of the configuration (not its content), counts of applications and providers, listener addresses.
- Audit: `events` row `config.loaded`.
- Metrics: `hopae_build_info`, `hopae_config_loaded_timestamp`.

## Test mapping

| Case | Test | File | Kind | Status |
| --- | --- | --- | --- | --- |
| S013-1 | `s013_1_valid_configuration_passes` | `tests/scenarios/s013_preflight.rs` | integration | planned |
| S013-2 | `s013_2_unknown_key_rejected` | `tests/scenarios/s013_preflight.rs` | integration | planned |
| S013-3 | `s013_3_missing_secret_degrades` | `tests/scenarios/s013_preflight.rs` | integration | planned |
| S013-4 | `s013_4_run_refuses_invalid_config` | `tests/scenarios/s013_preflight.rs` | integration | planned |
| S013-5 | `s013_5_startup_order_and_readiness` | `tests/scenarios/s013_preflight.rs` | integration | planned |
| S013-6 | `s013_6_schema_migration_and_provider_authority` | `tests/scenarios/s013_preflight.rs` | integration | planned |
| S013-7 | `s013_7_reload_unsupported_and_key_rotation_by_restart` | `tests/scenarios/s013_preflight.rs` | integration | planned |
| S013-A1 | `s013_a1_unsafe_values_rejected` | `tests/scenarios/s013_preflight.rs` | integration | planned |
| S013-A2 | `s013_a2_second_process_same_store_refused` | `tests/scenarios/s013_preflight.rs` | integration | planned |
| S013-A3 | `s013_a3_huge_config_bounded` | `tests/scenarios/s013_preflight.rs` | integration | planned |
| S013-A4 | `s013_a4_literal_secret_rejected` | `tests/scenarios/s013_preflight.rs` | integration | planned |
| S013-A5 | `s013_a5_insecure_modes_loud` | `tests/scenarios/s013_preflight.rs` | integration | planned |

## Live verification

| Date | Hopae version | Gateway version | Provider | Environment label | Result | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| — | — | — | — | — | — | `hopae --check` against the reference configuration is part of G9. |

## Open questions

- Should `--check` attempt to reach the configured gateway's read-only API (phase 0 drift warning, scenario 008-5) or stay offline by default?

## 한국어 요약

`hopae --check`는 설정 전체를 검증하고 비밀 값은 출력하지 않으며, 운영자가
게이트웨이에 등록해야 할 사실(redirect URI, 신원 헤더, 호출자 키 변수 이름을
포함한 라우트 조각)을 출력합니다. 호출자 키 누락, 알 수 없는 키, 과도한 캐시
TTL, 파일에 적힌 비밀 값은 거부하고, 안전하지 않은 쿠키 모드와 호출자 인증
해제는 명시적 경고와 함께만 허용합니다. API로 비활성화한 제공자는 재시작 후에도
파일 설정에 의해 다시 켜지지 않습니다.
