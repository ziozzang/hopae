# Configuration reference

<!-- doc-rev: 3 -->

[Documentation](README.md) · [한국어](ko/CONFIG.md)

This page lists every configuration key Hopae reads, with its type, default,
constraints and the milestone that introduced it. Keys marked *later* are
decided in an ADR but not yet implemented; they are listed so that operators
and implementers share one vocabulary, and each one moves to the main table
in the change that implements it.

## Prerequisites and configuration

- One JSON file, passed as `--config <path>` to `hopae run` and `hopae --check`. YAML is not supported in M0/M1 (later work, if ever).
- The file is at most 1 MiB. Unknown keys are rejected at every level (`deny_unknown_fields`).
- Secrets never appear in the file: keys ending in `_env` name an environment variable that holds the value. `hopae --check` reports a missing variable by name and never prints a value.
- `hopae --check --config <path>` validates the file and the referenced environment, prints the derived facts an operator must register elsewhere (listeners, the gateway route `auth` fragment, redirect URIs) and exits `0`, or `2` with one message per error. Warnings are printed to stderr; `--strict` turns them into errors.
- Configuration is read once at start. Reload is not supported before M6; change the file and restart.

### Keys (M0)

| Key | Type | Default | Constraints and meaning |
| --- | --- | --- | --- |
| `listen.portal` | string, socket address | `127.0.0.1:8700` | Portal listener (login, callback, logout, health). Proxied by the gateway's portal route. |
| `listen.gateway` | string, socket address | `127.0.0.1:8701` | Gateway listener (`/_hopae/verify`). Must differ from `listen.portal`. A non-loopback address produces a warning: the listener must never be publicly reachable ([gateway contract](GATEWAY_CONTRACT.md#prerequisites-and-configuration)). |
| `state_dir` | string, path | required | Writable directory for runtime state, created with mode `0700`. Must not be empty. |
| `store.kind` | `sqlite` | `sqlite` | Primary store backend ([ADR-0002](adr/0002-primary-store-sqlite-with-postgres-for-shared-deployments.md)). `postgres` arrives in M2. |
| `store.path` | string, path | `<state_dir>/hopae.db` | SQLite database file. Must not be empty when set. |
| `portal.public_url` | string, origin | required | Externally visible portal origin, `https://auth.example.test`; used for every `Location` Hopae emits. Must be `https://` or `http://` plus a host, without path, query or fragment. |
| `gateway.kind` | `hangang` | required | Gateway adapter ([ADR-0013](adr/0013-gateway-adapter-boundary.md)). Other kinds are later work. |
| `gateway.caller_key_env` | string, environment variable name | none | Variable holding the caller key the gateway sends in `x-hopae-gateway-key` (gateway change HC-3). Required unless `gateway.allow_unauthenticated_caller` is `true`; the variable must be set and non-empty at start. Name pattern `[A-Za-z_][A-Za-z0-9_]*`. |
| `gateway.allow_unauthenticated_caller` | boolean | `false` | Development only: skip caller-key authentication. Produces a warning at `--check` and at start; `--strict` rejects it. |
| `log.level` | `error`, `warn`, `info`, `debug`, `trace` | `info` | Log verbosity. |

### Keys decided and scheduled

These keys exist in the ADRs and the gateway contract and are implemented in
the milestone shown. Until then `hopae --check` rejects them as unknown.

| Key | Milestone | Default | Decided in |
| --- | --- | --- | --- |
| `gateway.caller_key_next_env` | M1 | none | Second accepted caller key during rotation ([ADR-0005](adr/0005-gateway-contract-and-versioning.md)) |
| `gateway.verify_budget_ms` | M1 | `400` | Total verify budget, below the gateway's `auth.timeout_ms` ([ADR-0002](adr/0002-primary-store-sqlite-with-postgres-for-shared-deployments.md)) |
| `gateway.rate_limit_status` | after HC-8 | `403` | `429` once the gateway relays it ([ADR-0005](adr/0005-gateway-contract-and-versioning.md)) |
| `apps[]` (`app_id`, `display_name`, `hosts`, `ports`, `enabled`, `session.idle`, `session.absolute`, `binding.ip`, `binding.ua`, `binding.on_mismatch`, `on_authz_change`, `verify_cache_seconds`) | M1 | see ADRs | Application registry; exact host names only ([ADR-0004](adr/0004-session-model-and-cross-domain-handoff.md), [ADR-0007](adr/0007-context-binding-policy.md)) |
| `session.idle`, `session.absolute` | M1 | `24h`, `30d` | Session-wide timers ([ADR-0007](adr/0007-context-binding-policy.md)) |
| `cookie.name`, `cookie.secure` | M1 | `__Host-hopae`, `true` | Cookie names derive from `cookie.name`; `secure=false` is development only ([ADR-0004](adr/0004-session-model-and-cross-domain-handoff.md)) |
| `providers[]` (`provider_id`, `kind`, `display_name`, `enabled`, `client_id`, `client_secret_env`, `issuer`, `scope`, `endpoint_hosts`, `allow_private_endpoints`, `allowed_email_domains`, `authoritative_domains`, `auto_link`, `trust_email`) | M1 (Google), M3 (others) | see ADR | Provider definitions mirrored into the store ([ADR-0010](adr/0010-provider-abstraction.md)) |
| `providers[].endpoint_hosts`, `providers[].allow_private_endpoints` | M1 | `[]`, unset (`false`) | Where a provider's discovery document may send the client (outbound request forgery control, [ADR-0010](adr/0010-provider-abstraction.md)). Every endpoint it publishes (authorization, token, user info, keys) must use `https` and name the issuer's host or a host listed in `endpoint_hosts` (host names or IP addresses, no scheme or port; the `google` preset lists its own). Resolved addresses that are loopback, private, link-local, CGNAT or multicast are refused at connect time, and the connection goes only to a vetted address. `allow_private_endpoints: true` lifts the address rule and permits `http` to a loopback issuer; development and private identity providers only. An unset value is `false` (a `test-hooks` build treats it as `true`; an explicit `false` always wins). |
| `linking.on_conflict`, `linking.mode` | M1 | `link_required`, `verified_email` | Account linking policy ([ADR-0011](adr/0011-account-linking-policy.md)) |
| `txn.max_rows`, `txn.per_ip_per_minute`, `handoff.per_ip_failures_per_minute`, `handoff.max_recoveries` | M1 | `1000`, `30`, `10`, `3` | Transaction and handoff bounds ([ADR-0004](adr/0004-session-model-and-cross-domain-handoff.md)) |
| `portal.sso_confirm_new_host` | M1 | `false` | One-click confirmation before the first handoff of a session to a host ([ADR-0004](adr/0004-session-model-and-cross-domain-handoff.md)) |
| `events.retention_days`, `events.max_rows`, `events.prune_every`, `events.max_pending_per_sink`, `events.delivery_terminal_retention_days` | M1 | `90`, `1000000`, `1000`, `10000`, `7` | Event retention and delivery bounds ([ADR-0009](adr/0009-event-model.md)) |
| `trusted_proxies` | M1 | `["127.0.0.1/32"]` | Peers whose `x-forwarded-for`/`x-forwarded-proto` the portal listener trusts |
| `limits.gateway_max_concurrent`, `limits.portal_max_concurrent` | M1 | `64`, `256` | In-flight request caps per listener; excess answers `503` (gateway) or `503` (portal) immediately ([ADR-0003](adr/0003-http-stack-axum-on-hyper.md)) |
| `log.verify_allow`, `log.accept_client_request_id` | M1 | `false`, `false` | Log every allowed verify individually; record a client-supplied `x-request-id` (truncated) in `attrs.client_request_id` ([ADR-0009](adr/0009-event-model.md)) |
| `sessions.retention_days` | M1 | `30` | Age after which terminated sessions and their handles are deleted by the session-retention sweep ([ADR-0007](adr/0007-context-binding-policy.md)) |
| `gateway.admin_url` | M1 (optional) | none | Base URL of the gateway's admin API (`http(s)`, no credentials); with `gateway.readonly_token_env`, `hopae --check` asks it for the routes and warns about application hosts that have none (phase 0 of [ADR-0012](adr/0012-service-registration-and-gateway-config-ownership.md)). Never used by `run` |
| `gateway.readonly_token_env` | M1 (optional) | none | Read-only gateway credential used only by `hopae --check` to warn about application hosts without a route (phase 0 of [ADR-0012](adr/0012-service-registration-and-gateway-config-ownership.md)); the full drift report is M2 |
| `cache.local_ttl_ms`, `cache.op_timeout_ms`, `cache.redis_url_env`, `cache.namespace` | M2 | `0`, `50`, none, none | Local cache and Redis bus ([ADR-0006](adr/0006-verify-caching-and-invalidation.md)) |
| `store.kind = postgres`, `store.url_env` | M2 | — | Shared primary store ([ADR-0002](adr/0002-primary-store-sqlite-with-postgres-for-shared-deployments.md)) |

## Behavior

- Validation runs in `hopae --check` and at the start of `hopae run` with identical rules; `run` refuses to bind any listener on an invalid file.
- Errors are collected and reported together, each naming the key path.
- Environment references are checked for presence only; values are never logged, printed or echoed in error messages.
- Warnings (non-fatal): `gateway.allow_unauthenticated_caller` set; `listen.gateway` not on a loopback address.
- The database path, when unset, is derived as `<state_dir>/hopae.db`.

## Limitations and compatibility

- JSON only; comments are not allowed.
- Before 1.0 a minor release may rename or remove a key; each such change is listed in the CHANGELOG under `Changed` with a migration note.
- No reload before M6.

## Examples, verification and related pages

The repository example (`examples/hopae.example.json`):

```json
{
  "listen": {
    "portal": "127.0.0.1:8700",
    "gateway": "127.0.0.1:8701"
  },
  "state_dir": "/var/lib/hopae",
  "store": {
    "kind": "sqlite"
  },
  "portal": {
    "public_url": "https://auth.example.test"
  },
  "gateway": {
    "kind": "hangang",
    "caller_key_env": "HOPAE_GATEWAY_KEY",
    "allow_unauthenticated_caller": false
  },
  "log": {
    "level": "info"
  }
}
```

Verify with:

```sh
HOPAE_GATEWAY_KEY=<redacted> hopae --check --config examples/hopae.example.json
```

Related pages: [architecture](ARCHITECTURE.md), [gateway contract](GATEWAY_CONTRACT.md), scenario 013 (preflight and startup).
