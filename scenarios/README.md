# Scenario specifications

Scenarios are the executable contract between a design and its tests. The
[development process](../docs/PROCESS.md#scenario-based-tdd) defines when they
are written and how they map to tests; [`000-template.md`](000-template.md) is
the template.

## Numbering

| Range | Area | Roadmap milestone |
| --- | --- | --- |
| 000 | Template | — |
| 001–099 | Core vertical slice: OIDC login, session, verify endpoint, portal, logout, path scope, header contract | M1 |
| 100–199 | Sessions and abuse controls: login history, blacklists, attempt throttling, shared cache, revocation | M2 |
| 200–299 | Providers: Kakao, Naver, email magic link, email and password, account linking | M3 |
| 300–399 | Management console and API | M4 |
| 400–439 | Lua hooks | M5 |
| 440–469 | Login-notification webhooks | M5 |
| 470–499 | Second-factor mechanism and factors | M5 |
| 500–599 | Lifecycle: signed self-update, configuration reload, release verification | M6 |
| 600–699 | Scale-out and operations: multi-instance, metrics, backup, key rotation | M7 |
| 900–999 | Cross-cutting security: cookie attributes, CSRF, response headers, crypto hygiene | all |

Allocate the next free number in the range. Numbers are never reused; a
withdrawn scenario keeps its file with status `withdrawn` and a reason.

## Status

| Status | Meaning | Set at |
| --- | --- | --- |
| `draft` | Being written; may change freely | G1–G3 |
| `approved` | Reviewed; tests may be written; coverage check enforces mapping | G3 exit |
| `implemented` | All mapped tests pass in `cargo test` | G6 |
| `verified-live` | Main flow and top abuse case ran against a live gateway and, where applicable, a real provider | G8 |
| `withdrawn` | No longer applies; reason recorded in the file | any |

## Test naming

Scenario `012`, case `012-3` → `fn s012_3_<slug>()`; abuse case `012-A2` →
`fn s012_a2_<slug>()`. Files live in `tests/scenarios/`. `make scenario-coverage`
enforces the mapping in both directions once a scenario is `approved`.

## Fixture catalogue (M1)

Scenarios refer to fixtures by file name. Their content is fixed here so that
a test and its implementation cannot read a scenario differently. Every
fixture uses loopback listeners on ephemeral ports (`127.0.0.1:0`) and a
temporary `state_dir`; the harness rewrites `portal.public_url` only when a
case says so. Secrets are environment variable names only.

| File | Content |
| --- | --- |
| `tests/fixtures/m1-basic.json` | Portal `https://auth.example.test`; application `app` with `hosts: ["app.example.test"]`, `ports: [443]`, `session: {idle: "12h", absolute: "7d"}`, `binding: {ip: "strict", ua: "off", on_mismatch: "terminate_session"}`, `on_authz_change: "refresh"`, `verify_cache_seconds: 0`; application `default` with policy defaults and no hosts; provider `mock` (`kind: "oidc"`, issuer and endpoints from the mock's discovery document, `client_id: "hopae-test"`, `client_secret_env: "HOPAE_TEST_MOCK_SECRET"`, `scope: "openid email profile"`, `auto_link: false`); `gateway: {kind: "hangang", caller_key_env: "HOPAE_TEST_GATEWAY_KEY", verify_budget_ms: 400}`; `session: {idle: "24h", absolute: "30d"}`; `cookie: {name: "__Host-hopae", secure: true}`; `linking: {on_conflict: "link_required"}`; `txn: {max_rows: 1000, per_ip_per_minute: 30}`; `handoff: {per_ip_failures_per_minute: 10, max_recoveries: 3}`; `events: {retention_days: 90, max_rows: 1000000, prune_every: 1000, max_pending_per_sink: 10000, delivery_terminal_retention_days: 7}`; `trusted_proxies: ["127.0.0.1/32"]`; `log: {level: "debug"}`. Cases that need a different value state the override. |
| `tests/fixtures/m1-two-domains.json` | `m1-basic.json` plus application `other` with `hosts: ["other.example.org"]` and the same policies as `app`. |
| `tests/fixtures/m1-binding.json` | `m1-basic.json` plus applications `relaxed` (`relaxed.example.test`, `binding: {ip: "prefix", on_mismatch: "drop_handle"}`) and `open` (`open.example.test`, `binding: {ip: "off"}`). |
| `tests/fixtures/m1-lifetimes.json` | `m1-basic.json` plus application `short` (`short.example.test`, `session: {idle: "1h", absolute: "1d"}`); `default` with `session: {idle: "2h", absolute: "30d"}`. |
| `tests/fixtures/m1-dev-insecure.json` | `m1-basic.json` with `cookie: {name: "hopae", secure: false}` and `portal.public_url: "http://auth.example.test"`. |
| `tests/fixtures/return-targets.json` | The table of scenario 005-2 as `[{"url": "...", "expect": "accept" \| "<reason>"}]`, in the order printed there. |
| `tests/fixtures/m4-admin.json` | `m1-basic.json` plus `listen.admin: "127.0.0.1:0"` and `admin: {public_url: "https://hopae-admin.example.test", session: {idle: "30m", absolute: "12h"}, binding: {ip: "strict", ua: "off", on_mismatch: "terminate_session"}, max_auth_age: "12h", require_aal: 1, untrusted_peers: "refuse", query_budget_ms: 2000, users: []}`; the implicit application `admin` therefore exists beside `app`. Cases that need another value state the override (M4-min, scenarios 300–305). |
| `tests/fixtures/m4-admin-unsupported.json` | `m4-admin.json` with the provider `mock` carrying the stored setting `reauth: "unsupported"` (standing in for the `google` preset), so console freshness is Hopae login age (scenario 300-16). |
| `tests/fixtures/m4-admin-seeded.json` | `m4-admin.json` with `admin.users: [{user_id: "<u_a>", role: "admin", note: "seed"}, {email: "v@example.test", role: "viewer"}, {email: "n@example.test", user_id: "<u_n>", role: "viewer"}]`; the harness substitutes the ids it created (scenario 305). |
| `tests/fixtures/config/*.json` | One file per case of scenario 013, named as the case lists them (`valid.json`, `unknown_key.json`, `missing_secret.json`, `insecure_cookie.json`, `missing_caller_key.json`, `unauthenticated_caller.json`, `public_gateway_listener.json`, `cache_too_long.json`, `bad_app_host.json`, `duplicate_host.json`), each `valid.json` plus the one deviation the case names. |

Mock provider (`tests/support/mock_idp`) profiles. `default` is a standard
OIDC provider with discovery, JWKS (RS256, rotating `kid`), PKCE S256
enforcement, `nonce` echo, a user-info endpoint and an ID token for subject
`sub-1` with `email: a@example.test`, `email_verified: true`, `name: Alice 김`.
Every other profile changes exactly one thing:

| Profile | Deviation |
| --- | --- |
| `wrong_state` | The callback redirect carries a `state` that was never issued |
| `wrong_nonce` | ID token `nonce` differs from the request's |
| `expired_token` | ID token `exp` is 120 s in the past |
| `wrong_aud` | ID token `aud` is another client id |
| `invalid_signature` | ID token signed by a key not in the JWKS |
| `unverified_email` | `email_verified: false` |
| `userinfo_wrong_sub` | User-info `sub` is `sub-2` while the ID token says `sub-1`, with `sub-2`'s email |
| `hd_example_test` | ID token carries `hd: example.test` |
| `oversized` | Discovery, JWKS and token responses are 1 MiB |
| `slow` | Every endpoint delays 15 s |
| `discovery_down` | Discovery answers `503` |
| `discovery_changed_issuer` | Discovery `issuer` differs from the configured one after the first fetch |
| `jwks_rotated` | A new `kid` replaces the old one after the first fetch |
| `jwks_unknown_kid` | ID token `kid` never appears in the JWKS |
| `token_500` | Token endpoint answers `500` |
| `token_slow` | Token endpoint delays 15 s |
| `token_malformed` | Token endpoint answers invalid JSON, then JSON with a numeric `id_token`, then a JWT with invalid base64 (cycling) |
| `userinfo_500` | User-info endpoint answers `500` |
| `id_token_missing` | Token response has no `id_token` |
| `auth_time_stale` | ID token carries `auth_time` two hours in the past whatever `max_age` was requested (M4-min, scenario 300) |
| `auth_time_missing` | ID token omits `auth_time` even when `max_age` was requested (M4-min, scenario 300) |
| `auth_time_present` | ID token carries `auth_time` equal to the moment the mock issued the code; the mock records `max_age` and `prompt` of every authorize request (M4-min, scenario 300) |

Environment variable names used by tests: `HOPAE_TEST_MOCK_SECRET`,
`HOPAE_TEST_GATEWAY_KEY`, `HOPAE_GW_KEY_A`, `HOPAE_GW_KEY_B` (values are
generated by the harness per run), `HOPAE_E2E_GATEWAY_BINARY` (path of a
gateway binary for the gateway layer; absent → gateway cases are skipped).
