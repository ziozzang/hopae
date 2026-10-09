# S013 — Configuration preflight and startup

<!-- scenario-status: draft -->

- Area: lifecycle
- Milestone: M1
- ADRs: 0002, 0003, 0005, 0010, 0012
- Threat model: TM-12, TM-14, TM-19
- Gateway contract: Prerequisites and configuration

## Goal

`hopae --check` validates the whole configuration, resolves secrets by
reference without printing them, reports the gateway integration facts the
operator must register, and `hopae run` refuses to start on any invalid or
unsafe configuration.

## Preconditions and fixtures

- Fixtures under `tests/fixtures/config/`: `valid.json`, `unknown_key.json`, `missing_secret.json`, `insecure_cookie.json`, `public_gateway_listener.json`, `cache_too_long.json`, `bad_app_host.json`, `duplicate_host.json`.
- Environment variables set by the harness per case; never real values.

## Main flow

### S013-1 Valid configuration passes

- Given: `valid.json` and `HOPAE_TEST_MOCK_SECRET` set.
- When: `hopae --check --config valid.json`.
- Then: exit 0; stdout lists listeners, store kind and path, applications with hosts and binding policy, providers with their `redirect_uri`, identity header set, and the gateway route `auth` fragment to register; no secret value appears (asserted by grepping for the env var's value).

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

### S013-6 Migration from an older schema

- Given: a store at schema version 1 (fixture file).
- When: `run`.
- Then: migrated to the current version inside a transaction; `meta.schema_version` updated; a backup copy `hopae.sqlite.bak-v1` is written first for SQLite.

### S013-7 Reload is not supported in M1

- Given: running process.
- When: `SIGHUP`.
- Then: logged `reload not supported; restart`; no change; configuration reload arrives in M6.

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

- Given: `public_gateway_listener.json` (`listen.gateway = 0.0.0.0:8701` without `gateway.caller_key_env`), `cache_too_long.json` (`verify_cache_seconds = 60`), `bad_app_host.json` (host with scheme or path), `duplicate_host.json` (two applications claim one host).
- When: `--check`.
- Then: exit 2 for each with a specific message; the public-listener case passes only when a caller key is configured, with a warning that the key is defense in depth.

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

### S013-A5 Insecure cookie mode must be explicit and loud

- Given: `insecure_cookie.json` (`cookie.secure = false`).
- When: `--check` and `run`.
- Then: both print `WARNING: insecure cookie mode (development only)` to stderr; the health body reports `insecure_mode=true`; `--strict` exits 2.

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
| S013-6 | `s013_6_schema_migration` | `tests/scenarios/s013_preflight.rs` | integration | planned |
| S013-7 | `s013_7_reload_unsupported_in_m1` | `tests/scenarios/s013_preflight.rs` | integration | planned |
| S013-A1 | `s013_a1_unsafe_values_rejected` | `tests/scenarios/s013_preflight.rs` | integration | planned |
| S013-A2 | `s013_a2_second_process_same_store_refused` | `tests/scenarios/s013_preflight.rs` | integration | planned |
| S013-A3 | `s013_a3_huge_config_bounded` | `tests/scenarios/s013_preflight.rs` | integration | planned |
| S013-A4 | `s013_a4_literal_secret_rejected` | `tests/scenarios/s013_preflight.rs` | integration | planned |
| S013-A5 | `s013_a5_insecure_cookie_mode_loud` | `tests/scenarios/s013_preflight.rs` | integration | planned |

## Live verification

| Date | Hopae version | Gateway version | Provider | Environment label | Result | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| — | — | — | — | — | — | `hopae --check` against the reference configuration is part of G9. |

## Open questions

- Should `--check` attempt to reach the configured gateway's read-only API (phase 0 drift warning, scenario 008-5) or stay offline by default?

## 한국어 요약

`hopae --check`는 설정 전체를 검증하고 비밀 값은 출력하지 않으며, 운영자가
게이트웨이에 등록해야 할 사실(redirect URI, 신원 헤더, 라우트 조각)을
출력합니다. 알 수 없는 키, 공개 게이트웨이 리스너, 과도한 캐시 TTL, 파일에 적힌
비밀 값은 거부하고, 안전하지 않은 쿠키 모드는 명시적 경고와 함께만 허용합니다.
