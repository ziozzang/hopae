# Configuration reference

<!-- doc-rev: 12 -->

[Documentation](README.md) · [한국어](ko/CONFIG.md)

This page lists every configuration key Hopae reads, with its type, default,
constraints and the milestone that introduced it. The tables below describe
what milestone M1 implements; the last table lists keys that are decided in an
ADR but rejected as unknown today. Each of those moves to the main tables in
the change that implements it.

## Prerequisites and configuration

- One JSON file, passed as `--config <path>` (or the `HOPAE_CONFIG` environment variable) to `hopae run` and `hopae --check`. YAML is not supported in M1 (later work, if ever).
- The file is at most 1 MiB. Unknown keys are rejected at every level (`deny_unknown_fields`); the message names the key path and, when one is close, the nearest known key. A key whose name looks like a literal secret (`secret`, `password`, `token`, `api_key`, `private_key`, without an `_env` suffix) is rejected without echoing its value.
- Secrets never appear in the file: keys ending in `_env` name an environment variable that holds the value. `hopae --check` reports a missing variable by name and never prints a value.
- Configuration is read once at start. Reload is not supported before M6: change the file and restart. `SIGHUP` is logged and ignored.
- Durations (`session.idle`, `apps[].session.idle`, and so on) are a positive integer and one unit: `30s`, `10m`, `12h`, `7d`.

### Command line

| Invocation | Meaning |
| --- | --- |
| `hopae run --config <path>` | Start both listeners and serve. `run` is the default command (`hopae --config <path>` is the same); `serve` is an alias. |
| `hopae --check --config <path>` | Validate the file and the referenced environment, print the derived facts an operator must register elsewhere (listeners, return origins, provider redirect URIs, the gateway route `auth` fragment) ending in `config ok`, and exit `0`. Warnings go to stderr. Nothing is bound, written or contacted, except the optional read-only drift query below. |
| `hopae --check --strict --config <path>` | As `--check`, but any warning is an error (exit `2`). `--strict` is valid only with `--check`. |
| `hopae providers import --config <path>` | Import the `providers[]` of the file into the store by the ADR-0010 rule (a file entry inserts or updates a `managed_by = file` row; a database-managed or removed provider is left alone) and print what was inserted, updated and skipped. Safe while an instance runs; restart that instance to pick up the change. |
| `hopae providers import --force <provider_id> --config <path>` | As above, and additionally reassert the named file entry over the database (a disabled, API-managed or removed provider). The id must be listed in the file. Records an `admin.providers_import` event. |
| `hopae --version` | Print the version and exit `0`; needs no configuration. |

Exit status: `0` success; `2` an invalid or unsafe configuration (including a
missing or empty caller-key variable), a missing `--config`, a refused start
because another instance holds the state directory lock, a `--strict`
failure, or a failed `providers import`; `1` any other runtime failure (for
example a store that cannot be opened or a listener that cannot bind).

With `gateway.admin_url` and `gateway.readonly_token_env` both set and the
variable non-empty, `hopae --check` asks the gateway's admin API which hosts
have routes and warns about application hosts that have none (phase 0 of
[ADR-0012](adr/0012-service-registration-and-gateway-config-ownership.md)). A
failure to ask is a warning, never an error. `hopae run` never uses either key.

### Keys (M0 and M1)

All keys below are implemented. "Optional" means the key may be omitted and the
default applies.

#### Process and store

| Key | Type | Default | Constraints and meaning |
| --- | --- | --- | --- |
| `listen.portal` | string, socket address | `127.0.0.1:8700` | Portal listener (login, callback, logout, `/healthz`). Proxied by the gateway's portal route. |
| `listen.gateway` | string, socket address | `127.0.0.1:8701` | Gateway listener (`/_hopae/verify`). Must differ from `listen.portal`. A non-loopback address produces a warning: the listener must never be publicly reachable ([gateway contract](GATEWAY_CONTRACT.md#prerequisites-and-configuration)). |
| `state_dir` | string, path | required | Writable directory for runtime state (database, instance lock, backups), created with mode `0700`. Must not be empty. |
| `store.kind` | `sqlite` | `sqlite` | Primary store backend ([ADR-0002](adr/0002-primary-store-sqlite-with-postgres-for-shared-deployments.md)). `postgres` arrives in M2. |
| `store.path` | string, path | `<state_dir>/hopae.db` | SQLite database file. Must not be empty when set. |
| `log.level` | `error`, `warn`, `info`, `debug`, `trace` | `info` | Verbosity of the process log on stderr. |
| `log.verify_allow` | boolean | `false` | Log every allowed verify individually (denials are always counted and sampled). |
| `log.accept_client_request_id` | boolean | `false` | Record a client-supplied `x-request-id` (truncated) in `attrs.client_request_id` of the events of verify and portal requests ([ADR-0009](adr/0009-event-model.md)). |
| `trusted_proxies` | array of IP address or CIDR strings | `["127.0.0.1/32"]` | Peers whose `x-forwarded-for` and `x-forwarded-proto` the portal listener trusts. Each entry must parse as an address or a CIDR. A forwarded chain of more than 64 hops (all header lines together) is not believed: the peer itself is then the client address. |
| `limits.gateway_max_concurrent` | integer, at least 1 | `64` | In-flight request cap on the gateway listener; excess requests are answered `503` with `reason=overloaded` immediately ([ADR-0003](adr/0003-http-stack-axum-on-hyper.md)). The caller key is checked before a permit is taken. |
| `limits.portal_max_concurrent` | integer, at least 1 | `256` | In-flight request cap on the portal listener; excess requests are answered `503` immediately. |
| `sessions.retention_days` | integer, at least 1 | `30` | Age after which terminated sessions and their handles are deleted by the session-retention sweep ([ADR-0007](adr/0007-context-binding-policy.md)). |

#### Portal, cookies and sessions

| Key | Type | Default | Constraints and meaning |
| --- | --- | --- | --- |
| `portal.public_url` | string, origin | required | Externally visible portal origin, `https://auth.example.test`; used for every `Location` Hopae emits and for provider redirect URIs (`<public_url>/callback/<provider_id>`). Must be `https://` or `http://` plus a host, without path, query or fragment. |
| `portal.sso_confirm_new_host` | boolean | `false` | One-click confirmation before the first handoff of a session to a host ([ADR-0004](adr/0004-session-model-and-cross-domain-handoff.md)). |
| `cookie.name` | string | `__Host-hopae` (`hopae` when `cookie.secure` is `false`) | 1 to 64 characters of letters, digits, `_` and `-`. The binding and portal cookies append `_bind` and `_portal`. Must start with `__Host-` when `cookie.secure` is `true` and must not when it is `false`. |
| `cookie.secure` | boolean | `true` | `false` is development only: a loud warning at `--check` and at start, `insecure_mode` in the health body, default application port `80`. |
| `session.idle` | duration | `24h` | Session-wide idle timeout: a session unused through any of its handles for this long is terminated. At least `60s` (activity is recorded in whole seconds). |
| `session.absolute` | duration | `30d` | Session-wide absolute lifetime; the session is terminated at this age. |
| `linking.on_conflict` | `link_required`, `separate`, `deny` | `link_required` | What happens when a sign-in's verified email matches an existing user through another provider ([ADR-0011](adr/0011-account-linking-policy.md)). |
| `linking.mode` | `verified_email`, `off` | `verified_email` | Account linking policy. |
| `txn.max_rows` | integer, at least 1 | `1000` | Cap on live login transactions ([ADR-0004](adr/0004-session-model-and-cross-domain-handoff.md)). The transaction lifetime is a constant 600 s and has no key. |
| `txn.per_ip_per_minute` | integer, at least 1 | `30` | Login transactions one client IP may start per minute. |
| `handoff.per_ip_failures_per_minute` | integer, at least 1 | `10` | Handoff-code failures one client IP may cause per minute before it is rate limited. |
| `handoff.max_recoveries` | integer | `3` | How many times a browser is sent back to the portal to recover from a rejected known handoff code (first-use binding-cookie race and similar) before a relayed `403` page ends the loop ([ADR-0014](adr/0014-handoff-recovery-on-any-rejected-code.md)). Not range-checked. |

#### Gateway

| Key | Type | Default | Constraints and meaning |
| --- | --- | --- | --- |
| `gateway.kind` | `hangang` | required | Gateway adapter ([ADR-0013](adr/0013-gateway-adapter-boundary.md)). Other kinds are later work. |
| `gateway.caller_key_env` | string, environment variable name | none | Variable holding the caller key the gateway sends in `x-hopae-gateway-key` (gateway change HC-3). Required unless `gateway.allow_unauthenticated_caller` is `true`; the variable must be set and non-empty at start (otherwise exit `2`). Name pattern `[A-Za-z_][A-Za-z0-9_]*`. |
| `gateway.caller_key_next_env` | string, environment variable name | none | Second accepted caller key during rotation ([ADR-0005](adr/0005-gateway-contract-and-versioning.md)). Requires `caller_key_env`, must differ from it, and the variable must be non-empty at start. `--check` warns when it has been configured for more than 7 days. |
| `gateway.allow_unauthenticated_caller` | boolean | `false` | Development only: skip caller-key authentication. Produces a warning at `--check` and at start (and `unauthenticated_caller` in the health body); `--strict` rejects it. |
| `gateway.verify_budget_ms` | integer | `400` | Total time one verify call may take, 1 to 10000. Keep it below the gateway route's `auth.timeout_ms`; `--check` prints `auth.timeout_ms` as budget plus 100, capped at 5000. |
| `gateway.admin_url` | string, URL | none | Base URL of the gateway's admin API (`http` or `https`, with a host, no credentials). Used only by `hopae --check`, together with `gateway.readonly_token_env`. |
| `gateway.readonly_token_env` | string, environment variable name | none | Variable holding a read-only gateway credential. Used only by `hopae --check` to warn about application hosts without a route; the full drift report is M2. |

#### Applications

`apps[]` is the application registry: the exact hosts Hopae may send a browser
to after login. The union of all enabled hosts and ports is the return-origin
allowlist, and each entry is a credential destination the operator vouches
for. A host not listed is denied (`unknown_app`).

| Key | Type | Default | Constraints and meaning |
| --- | --- | --- | --- |
| `apps[].app_id` | string | required | `[a-z0-9][a-z0-9_-]{0,31}`, unique. The id `default` is reserved: that entry carries policy defaults for every other application and must not list hosts. |
| `apps[].display_name` | string | the `app_id` | Shown on the portal. |
| `apps[].hosts` | array of strings | required (except `default`) | Exact lower-case host names: no scheme, wildcard, port, path or trailing dot. A host may belong to one application only. Upper-case input is normalized with a warning. |
| `apps[].ports` | array of integers | `[443]` (`[80]` when `cookie.secure` is `false`) | Non-empty when set, no `0`. |
| `apps[].enabled` | boolean | `true` | A disabled application is denied (`app_disabled`). |
| `apps[].session.idle`, `apps[].session.absolute` | duration | `12h`, `7d` (inherited from the `default` application when it sets them) | Per-handle timers: a handle idle for `idle` or older than `absolute` is revoked; the session and its other handles continue; `idle` must be at least `60s` ([ADR-0007](adr/0007-context-binding-policy.md)). |
| `apps[].binding.ip` | `strict`, `prefix`, `off` | `strict` | Client IP binding of a handle ([ADR-0007](adr/0007-context-binding-policy.md)). |
| `apps[].binding.ip_prefix_v4`, `apps[].binding.ip_prefix_v6` | integer | `24`, `64` | Prefix length for `prefix` mode: 1 to 32 and 1 to 128. |
| `apps[].binding.ua` | `strict`, `off` | `off` | User-agent binding. |
| `apps[].binding.on_mismatch` | `terminate_session`, `drop_handle` | `terminate_session` | What a binding mismatch does. |
| `apps[].on_authz_change` | `refresh`, `terminate` | `refresh` | What happens to live sessions when authorization data changes. |
| `apps[].verify_cache_seconds` | integer | `0` | Staleness bound the gateway may cache an allow for; at most `30`. `hopae --check` prints the value per application and **warns when it is `false`**: `sec-fetch-site: same-origin` proves only that a document of the application's own origin started the navigation, so a navigation gadget in the application (a page that assigns a URL from its own query to `location`, such as `/continue?next=/_hopae/logout`) can end a user's session without a click. Keep `true` unless that is accepted. |
| `apps[].logout_confirm` | boolean | `true` (inherited from the `default` application when it sets it) | `true`: `/_hopae/logout` on the application host redirects to the portal's confirmation page. `false`: a document navigation with `sec-fetch-site: same-origin` that presents a valid handle ends the session at once and is redirected to the portal's signed-out page; every other request still goes through the confirmation. After either, the portal shows a "Sign in again" link instead of redirecting to the protected target ([ADR-0015](adr/0015-app-host-entry-points-and-upstream-cookie-stripping.md), [gateway contract](GATEWAY_CONTRACT.md#application-host-entry-points)). Reported by `--check`. |
| `apps[].step_up[]` | array of `{path_prefix, require: {aal, max_age}}` | none | Step-up rules. In M1 they are parsed and validated (`aal` is 1 or 2, `path_prefix` starts with `/`, `max_age` is positive seconds) and force `no-store`; enforcement arrives in M5. |

#### Providers

`providers[]` defines sign-in providers. Entries are mirrored into the store at
start by the ADR-0010 import rule; after that the database is authoritative for
providers that were changed at run time. M1 supports `kind = oidc` only (Google
is the tested provider).

| Key | Type | Default | Constraints and meaning |
| --- | --- | --- | --- |
| `providers[].provider_id` | string | required | `[a-z0-9][a-z0-9_-]{0,31}`, unique. Appears in the redirect URI `<portal.public_url>/callback/<provider_id>`. An id equal to a preset name (`google`) selects that preset when `issuer` is unset. |
| `providers[].kind` | `oidc` | required | `oauth2`, `email_link` and `password` parse but are rejected before M3. |
| `providers[].display_name` | string | the `provider_id` | Chooser label. |
| `providers[].enabled` | boolean | `true` | A disabled provider is not offered. |
| `providers[].client_id` | string | required | Must not be empty. Not a secret. |
| `providers[].client_secret_env` | string, environment variable name | none | Variable holding the client secret. When it is set and the variable is unset or empty at start, the provider is disabled (reported by `--check` as a warning, by `/healthz` as `disabled`); Hopae still starts. |
| `providers[].issuer` | string, URL | the preset's issuer | `https://` (`http://` only for a loopback host and only with `allow_private_endpoints: true`), no query, fragment or credentials. Required unless a preset applies. |
| `providers[].scope` | string | `openid email profile` | Must not be empty. |
| `providers[].endpoint_hosts` | array of hosts | `[]` | Hosts, besides the issuer's own, that the provider's discovery document may point to (authorization, token, user info and key endpoints must use `https` and name the issuer's host or one listed here; host names or IP addresses, no scheme or port). The `google` preset lists its own. |
| `providers[].allow_private_endpoints` | boolean | unset (`false`) | Development and private identity providers only: lifts the connect-time refusal of loopback, private, link-local, CGNAT and multicast addresses and permits `http://` to a loopback issuer. Without it such addresses are refused and the connection goes only to a vetted address. An explicit `false` always wins, even in a `test-hooks` build. Provider requests never use `HTTP_PROXY`, `HTTPS_PROXY` or `ALL_PROXY`. |
| `providers[].allowed_email_domains` | array of domains | `[]` | Plain domain names; non-empty restricts sign-in to those email domains. Enforced by the identity layer; only a verified email address is considered. |
| `providers[].authoritative_domains` | array of domains | `[]` | Domains for which this provider is authoritative for email ([ADR-0011](adr/0011-account-linking-policy.md)). |
| `providers[].auto_link` | boolean | `false` | Link a sign-in to an existing user without confirmation when the policy allows it. |
| `providers[].trust_email` | boolean | `false` | Treat the provider's email claim as verified. |

Provider settings `preset`, `userinfo` and `id_token_typ` are read by the OIDC
provider from the provider row's stored `config`, not from the configuration
file: in M1 the file importer writes only `client_id`, `issuer` and `scope` into
that row, and `hopae --check` rejects the three names as unknown keys. They
take effect when a row carrying them exists in the database.

| Stored setting | Type | Default | Meaning |
| --- | --- | --- | --- |
| `preset` | string | the preset named like the `provider_id`, else the preset whose issuer matches | Built-in defaults for a well-known provider. Only `google` exists in M1 (issuer `https://accounts.google.com`, scope `openid email profile`, no user-info call). |
| `userinfo` | boolean | the preset's value, `true` without a preset | Call the user-info endpoint after the ID token is validated; the subject must match the ID token. |
| `id_token_typ` | string | none | Required `typ` header of the ID token, for providers that set one. |

#### Events

| Key | Type | Default | Constraints and meaning |
| --- | --- | --- | --- |
| `events.retention_days` | integer, at least 1 | `90` | Age after which events are pruned ([ADR-0009](adr/0009-event-model.md)). |
| `events.max_rows` | integer, at least 1 | `1000000` | Hard cap on stored events; the oldest are pruned first. |
| `events.prune_every` | integer, at least 1 | `1000` | Inserted rows between prune passes (a pass also runs at least every 60 s). |
| `events.max_pending_per_sink` | integer, at least 1 | `10000` | Undelivered rows kept per sink; beyond it the oldest pending rows become `failed` with `backlog_overflow`. |
| `events.delivery_terminal_retention_days` | integer, at least 1 | `7` | How long delivered or failed delivery rows are kept. |

### Keys decided and scheduled

These keys exist in the ADRs and the gateway contract and are implemented in
the milestone shown. Until then `hopae --check` rejects them as unknown.

| Key | Milestone | Default | Decided in |
| --- | --- | --- | --- |
| `gateway.rate_limit_status` | after HC-8 | `403` | `429` once the gateway relays it ([ADR-0005](adr/0005-gateway-contract-and-versioning.md)) |
| `providers[].kind` other than `oidc` | M3 | — | Kakao, Naver, email link, password ([ADR-0010](adr/0010-provider-abstraction.md)) |
| `cache.local_ttl_ms`, `cache.op_timeout_ms`, `cache.redis_url_env`, `cache.namespace` | M2 | `0`, `50`, none, none | Local cache and Redis bus ([ADR-0006](adr/0006-verify-caching-and-invalidation.md)) |
| `store.kind = postgres`, `store.url_env` | M2 | — | Shared primary store ([ADR-0002](adr/0002-primary-store-sqlite-with-postgres-for-shared-deployments.md)) |
| `listen.admin` | M4-min | `127.0.0.1:8702` | Admin listener, bound only when `admin.public_url` is set; must differ from the other listeners; non-loopback warns ([ADR-0016](adr/0016-management-console-minimum.md), [administration](ADMIN.md)) |
| `admin.public_url` | M4-min | none | Externally visible origin of the console; registers the implicit application `admin` (reserved id) with the policy below ([ADR-0016](adr/0016-management-console-minimum.md)) |
| `admin.session.idle`, `admin.session.absolute`, `admin.binding.ip`, `admin.binding.ip_prefix_v4`, `admin.binding.ip_prefix_v6`, `admin.binding.ua`, `admin.binding.on_mismatch` | M4-min | `30m`, `12h`, `strict`, `24`, `64`, `off`, `terminate_session` | Lifetimes and binding of the console host, same types and constraints as `apps[].session.*` and `apps[].binding.*` |
| `admin.max_auth_age` | M4-min | `12h` | Oldest provider authentication (`sessions.auth_time`) a console session may rely on, evaluated at every console verify; an older session is sent to reauthenticate at the provider with `max_age` and `prompt=login`, and the returned `auth_time` is checked ([ADR-0016](adr/0016-management-console-minimum.md) decision 15) |
| `admin.require_aal` | M4-min | `1` | Minimum assurance level of the console handle (`1` or `2`); `2` also sets the implicit application's step-up rule and, before M5, makes `--check` warn that every request will be refused |
| `admin.untrusted_peers` | M4-min | `refuse` | What the admin listener does with a TCP peer outside `trusted_proxies`: `refuse` answers `403 untrusted_peer` before reading a cookie (logged, counted); `as_client` treats the peer as the client, as the portal does |
| `admin.query_budget_ms` | M4-min | `2000` | Deadline of one console listing or search (100 to 30000); a query that reaches it is interrupted inside the store and answered `503` |
| `admin.users[]` | M4-min | `[]` | Grants seeded from the file at start and by `hopae admin import`: entries `{user_id?, email?, role?, note?}` with at least one of `user_id` and `email`, `role` `admin` (default) or `viewer`; an entry given by email alone applies only when exactly one user holds the verified address and it is authoritative; imported under the provider rule with `managed_by` and tombstones ([administration](ADMIN.md)) |
| `limits.admin_max_concurrent` | M4-min | `16` | In-flight cap of the admin listener |
| `hopae admin grant <user_id or email> [--role admin\|viewer] [--note <text>] [--confirm <user_id>]`, `hopae admin revoke <user_id or email>`, `hopae admin list [--all]`, `hopae admin import [--force <user_id or email>]` (commands) | M4-min | — | Administrator grants from the command line and the file against the store; `grant` prints the resolved user and, for a non-authoritative email, requires `--confirm` naming the resolved id; a grant binds to that user id and is never re-resolved; records `admin.grant` / `admin.revoke` ([administration](ADMIN.md)) |

## Behavior

- Validation runs in `hopae --check` and at the start of `hopae run` with identical rules; `run` refuses to bind any listener on an invalid file (exit `2`).
- Errors are collected and reported together, each naming the key path.
- Environment references are checked for presence only; values are never logged, printed or echoed in error messages.
- Referenced environment variables: a missing or empty caller-key variable is an error; a missing provider secret is a warning that disables that provider.
- Warnings (non-fatal): `gateway.allow_unauthenticated_caller` set; `cookie.secure` false; `listen.gateway` not on a loopback address; a provider disabled because its secret variable is unset; `gateway.caller_key_next_env` configured for more than 7 days; an application host without a gateway route (only with `gateway.admin_url`); an upper-case host name that was normalized.
- The database path, when unset, is derived as `<state_dir>/hopae.db`.

## Limitations and compatibility

- JSON only; comments are not allowed.
- Before 1.0 a minor release may rename or remove a key; each such change is listed in the CHANGELOG under `Changed` with a migration note.
- No reload before M6.
- `apps[].step_up` is parsed but not enforced before M5.
- Provider settings `preset`, `userinfo` and `id_token_typ` cannot be set from the file in M1 (see Providers).

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

A fuller template with one application and the Google provider is
`deploy/hopae.example.json`; see [operations](OPERATIONS.md).

Verify with:

```sh
HOPAE_GATEWAY_KEY=<redacted> hopae --check --config examples/hopae.example.json
```

Related pages: [operations](OPERATIONS.md), [architecture](ARCHITECTURE.md), [gateway contract](GATEWAY_CONTRACT.md), scenario 013 (preflight and startup).
