# Configuration reference

<!-- doc-rev: 33 -->

[Documentation](README.md) · [한국어](ko/CONFIG.md)

This page lists every configuration key Hopae reads, with its type, default,
constraints and the milestone that introduced it. The tables below describe
what milestones M1 and M4-min implement; the last table lists keys that are
decided in an ADR but rejected as unknown today. Each of those moves to the
main tables in the change that implements it.

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
| `hopae admin grant <user_id or email> [--role admin\|viewer] [--note <text>] [--confirm <user_id>] --config <path>` | Grant a console role (default `admin`) to an existing user and print the user it resolved. An email must be the user's verified primary email; one that is not authoritative needs `--confirm` naming the resolved user id. At most 256 characters of `--note`. The grant binds to that user id and is never re-resolved. Records `admin.grant` ([administration](ADMIN.md#command-line-reference)). |
| `hopae admin revoke <user_id or email> --config <path>` | Revoke the grant; the row stays as a tombstone. Records `admin.revoke`. |
| `hopae admin list [--all] --config <path>` | Print the live grants; `--all` adds revoked rows. |
| `hopae admin import [--force <user_id or email>] --config <path>` | Apply `admin.users[]` of the file to the store (the same import runs at start) and print what was inserted, updated, revoked, unchanged, forced and skipped. |
| `hopae --version` | Print the version and exit `0`; needs no configuration. |

Exit status: `0` success; `2` an invalid or unsafe configuration (including a
missing or empty caller-key variable), a missing `--config`, a refused start
because another instance holds the state directory lock, a `--strict`
failure, a failed `providers import`, or a refused `hopae admin` command (an
unknown or unsuitable user, a bad argument, a database the precheck refuses:
newer than the binary, pre-release, damaged, or older than the binary, in
which case the message says to start the instance once to migrate); `1` any
other runtime failure (for example a store that cannot be opened or a listener
that cannot bind). The `hopae admin` commands never create, migrate or back up
the database and do not take the instance lock; they wait at most 5 seconds for
a busy database.

With `gateway.admin_url` and `gateway.readonly_token_env` both set and the
variable non-empty, `hopae --check` asks the gateway's admin API which hosts
have routes and warns about application hosts that have none (phase 0 of
[ADR-0012](adr/0012-service-registration-and-gateway-config-ownership.md)). A
failure to ask is a warning, never an error. `hopae run` never uses either key.

### Keys (M0, M1 and M4-min)

All keys below are implemented. "Optional" means the key may be omitted and the
default applies. The management console keys (milestone M4-min) have their own
table, [Management console](#management-console).

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
| `listen.admin` | string, socket address | `127.0.0.1:8702` | Admin listener of the management console. Bound only when `admin.public_url` is set (with `listen.admin` set and no `admin.public_url`, a warning says the listener is not bound). Must differ from `listen.portal` and `listen.gateway` (checked whenever the key is set). A non-loopback address produces a warning: the listener must never be publicly reachable. |
| `limits.gateway_max_concurrent` | integer, at least 1 | `64` | In-flight request cap on the gateway listener; excess requests are answered `503` with `reason=overloaded` immediately ([ADR-0003](adr/0003-http-stack-axum-on-hyper.md)). The caller key is checked before a permit is taken. |
| `limits.portal_max_concurrent` | integer, at least 1 | `256` | In-flight request cap on the portal listener; excess requests are answered `503` immediately. |
| `limits.admin_max_concurrent` | integer, at least 1 | `16` | In-flight request cap on the admin listener; excess requests are answered `503` (`overloaded`) at once, before the peer check and authentication. |
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
| `apps[].step_up[]` | array of `{path_prefix, require: {aal, max_age}}` | none | Enforced session assurance rules (`aal` is 1 or 2, `path_prefix` starts with `/`, `max_age` is positive seconds). AAL 2 requires actual second-factor evidence; freshness uses its satisfaction time. Rules force `no-store`. An AAL 0 service credential cannot satisfy a matching rule. With a configured TOTP keyring, document requests start native OTP step-up; without one they fail closed. |

#### Providers

`providers[]` defines sign-in providers. Entries are mirrored into the store at
start by the ADR-0010 import rule; after that the database is authoritative for
providers that were changed at run time. Source configuration supports `kind = oidc` and `kind = ldap` together. Google
is the existing OIDC provider; LDAP has owned LDAPS/StartTLS runtime qualification.

| Key | Type | Default | Constraints and meaning |
| --- | --- | --- | --- |
| `providers[].provider_id` | string | required | `[a-z0-9][a-z0-9_-]{0,31}`, unique. Appears in the redirect URI `<portal.public_url>/callback/<provider_id>`. An id equal to a preset name (`google`) selects that preset when `issuer` is unset. |
| `providers[].kind` | `oidc` or `ldap` | required | `oauth2`, `email_link` and `password` parse but are rejected before M3. |
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

Provider settings `preset`, `userinfo`, `id_token_typ`, `reauth` and
`reauth_prompt` are read by the OIDC provider from the provider row's stored
`config`, not from the configuration file: the file importer writes only
`client_id`, `issuer` and `scope` into that row, and `hopae --check` rejects the
five names as unknown keys. They take effect when a row carrying them exists in
the database. For `reauth` and `reauth_prompt` the stored value wins over the
default the file resolves, at start and in the `hopae --check` report; a stored
value that is not one of the listed ones is ignored.

| Stored setting | Type | Default | Meaning |
| --- | --- | --- | --- |
| `preset` | string | the preset named like the `provider_id`, else the preset whose issuer matches | Built-in defaults for a well-known provider. Only `google` exists in M1 (issuer `https://accounts.google.com`, scope `openid email profile`, no user-info call). |
| `userinfo` | boolean | the preset's value, `true` without a preset | Call the user-info endpoint after the ID token is validated; the subject must match the ID token. |
| `id_token_typ` | string | none | Required `typ` header of the ID token, for providers that set one. |
| `reauth` | `max_age`, `unsupported` | the preset's value; `max_age` without a preset | Whether the provider honors the OpenID Connect `max_age` parameter and returns `auth_time`, so that a console reauthentication is a provider-verified challenge; the `google` preset is `unsupported` (Google documents that it does not support reauthentication requests), and console freshness with such a provider is Hopae login age ([ADR-0016](adr/0016-management-console-minimum.md) decision 15, [administration](ADMIN.md#freshness-and-reauthentication)). |
| `reauth_prompt` | `login`, `none` | `login` | Whether a reauthentication authorize request to a `max_age` provider also carries `prompt=login`. A provider with `reauth` set to `unsupported` receives an ordinary authorize request with neither `max_age` nor `prompt`. |

#### Management console

The console is enabled by `admin.public_url`; without it no admin listener is
bound and every other `admin.*` key is validated but has no effect. The
background is in [administration](ADMIN.md).

| Key | Type | Default | Constraints and meaning |
| --- | --- | --- | --- |
| `admin.public_url` | string, origin | none | Externally visible origin of the console, `https://hopae-admin.example.test`. `https://`, or `http://` only when `cookie.secure` is `false`; a lower-case host **name** (not an IP address) with an optional port; no path, query, fragment or credentials. Setting it registers the implicit application `admin` (hosts `[host]`, ports `[its port, else 443 (80 for http)]`, `on_authz_change = terminate`, `verify_cache_seconds = 0`, `logout_confirm = true`) and binds `listen.admin`. The id `admin` is reserved: an `apps[]` entry with it, or listing the console host, is an error. |
| `admin.session.idle` | duration | `30m` | Per-handle idle timer of the console host; at least `60s`. |
| `admin.session.absolute` | duration | `12h` | Per-handle absolute lifetime of the console host. |
| `admin.binding.ip` | `strict`, `prefix`, `off` | `strict` | Client IP binding of the console handle, as `apps[].binding.ip`. |
| `admin.binding.ip_prefix_v4`, `admin.binding.ip_prefix_v6` | integer | `24`, `64` | Prefix length for `prefix` mode: 1 to 32 and 1 to 128. |
| `admin.binding.ua` | `strict`, `off` | `off` | User-agent binding. |
| `admin.binding.on_mismatch` | `terminate_session`, `drop_handle` | `terminate_session` | What a binding mismatch does. |
| `admin.max_auth_age` | duration | `12h` | Freshness bound of a console session, at least `30m`: a smaller value is a configuration error (`admin.max_auth_age must be at least 30m`), because the bound keeps a 600 s headroom between a reauthentication callback and the console verify that follows. One predicate at every console verify: `auth_time ≤ now + 60 s` and `now − auth_time < N`. With a provider whose `reauth` capability is `max_age` the session must carry a provider-verified `auth_time` and a stale one is sent to a reauthentication that the session's own provider performs; with an `unsupported` provider (the `google` preset) the bound is Hopae login age only ([ADR-0016](adr/0016-management-console-minimum.md) decision 15, [administration](ADMIN.md#freshness-and-reauthentication)). |
| `admin.require_aal` | `1`, `2` | `1` | Minimum assurance level of the console handle. `2` also sets the implicit application's step-up rule for the whole host. Without a TOTP keyring, `--check` warns that console requests will be refused. |
| `admin.untrusted_peers` | `refuse`, `as_client` | `refuse` | What the admin listener does with a TCP peer outside `trusted_proxies`: `refuse` answers `403 untrusted_peer` before reading a cookie (counted, a rate-limited warning); `as_client` treats the peer as the client, as the portal does. |
| `admin.query_budget_ms` | integer, 100 to 30000 | `2000` | Deadline of one console store operation (listing, search or mutation). The deadline is handed to the store job, which interrupts the statement inside SQLite, rolls back and answers `503`. |
| `admin.users[]` | array of `{user_id?, email?, role?, note?}` | `[]` | Administrator grants seeded from the file at start and by `hopae admin import`. Each entry needs at least one of `user_id` (`u_` followed by letters, digits, `_` or `-`, at most 64 characters) and `email` (a valid address); `role` is `admin` (default) or `viewer`; `note` at most 256 characters; unknown keys are rejected. An entry given by email alone applies only when exactly one user holds that verified address and it is authoritative. A defective entry is a warning at start (skipped, never a start failure) and an error under `--check --strict`. Imported under the provider rule with `managed_by` and tombstones ([administration](ADMIN.md#grants-in-the-configuration-file)). |

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
| `providers[].kind` other than `oidc` or `ldap` | M3 | — | Kakao, Naver, email link, password ([ADR-0010](adr/0010-provider-abstraction.md)) |
| `cache.local_ttl_ms`, `cache.op_timeout_ms`, `cache.redis_url_env`, `cache.namespace` | M2 | `0`, `50`, none, none | Local cache and Redis bus ([ADR-0006](adr/0006-verify-caching-and-invalidation.md)) |
| `store.kind = postgres`, `store.url_env` | M2 | — | Shared primary store ([ADR-0002](adr/0002-primary-store-sqlite-with-postgres-for-shared-deployments.md)) |

## Behavior

- Validation runs in `hopae --check` and at the start of `hopae run` with identical rules; `run` refuses to bind any listener on an invalid file (exit `2`).
- Errors are collected and reported together, each naming the key path.
- Environment references are checked for presence only; values are never logged, printed or echoed in error messages.
- Referenced environment variables: a missing or empty caller-key variable is an error; a missing provider secret is a warning that disables that provider.
- Warnings (non-fatal): `gateway.allow_unauthenticated_caller` set; `cookie.secure` false; `listen.gateway` not on a loopback address; a provider disabled because its secret variable is unset; `gateway.caller_key_next_env` configured for more than 7 days; an application host without a gateway route (only with `gateway.admin_url`); an upper-case host name that was normalized; `listen.admin` not on a loopback address; `listen.admin` set without `admin.public_url`; `admin.require_aal` set to `2`; an `admin.users[]` entry that cannot be applied (reported against the store when it exists); a missing console route or one that strips cookies (only with `gateway.admin_url`: `console_route_without_auth`, `console_route_strips_cookies`).
- The database path, when unset, is derived as `<state_dir>/hopae.db`.

## Limitations and compatibility

- JSON only; comments are not allowed.
- Before 1.0 a minor release may rename or remove a key; each such change is listed in the CHANGELOG under `Changed` with a migration note.
- No reload before M6.
- `apps[].step_up` is enforced. Unmet session rules return `step_up_required`: configured native OTP completion starts a bound browser challenge; without a keyring, document navigation returns 403. API/session requests return 401 without clearing the handle. `admin.require_aal = 2` requires actual second-factor evidence; enrollment alone does not provide it.
- Provider settings `preset`, `userinfo`, `id_token_typ`, `reauth` and `reauth_prompt` cannot be set from the file (see Providers).
- `apps[].max_auth_age` is not a key: only the implicit console application has a freshness bound, `admin.max_auth_age`.

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

## Native console and transport integration

`listen.native_gateway` optionally enables authenticated loopback HOP1 verification.
`admin.hangang_delegation` optionally enables signed host-console delegation with
`key_env` and an optional absolute private `sessions_file`. See
[Native integration](HANGANG_NATIVE.md) for bounds, browser/paired sessions and grants.


## LDAP configuration

The providers[].ldap object is parsed, validated and preserved in provider import.
Its fields are endpoint, starttls, absolute ca path, base_dn, bind_dn,
bind_password_env, username_attribute, subject_attribute, subject_encoding
(text or binary_hex), and timeout_ms (1–2000). The client_id requirement applies
to OIDC; LDAP cannot use OIDC credentials or implicit account linking. LDAP portal
activation is accepted by source configuration validation; production LDAP is not configured. See
[LDAP implementation status](LDAP_AUTHENTICATION.md).

## TOTP keyring bootstrap

Optional `totp_keyring` is a reference-only startup setting. Example:

```json
{"totp_keyring":{"active_key":"v1","keys":[{"id":"v1","key_env":"TOTP_KEY"}]}}
```

One active ID must name one of 1–16 unique key entries; each environment name must
be conventional and unique. Referenced material is 32 high-entropy bytes encoded as
43 unpadded Base64url characters. Startup rejects unavailable, malformed, zero or
reused material before opening state/listeners. Keys remain in memory for the process;
configuration does not contain their values. Authenticated gateway callers are required.
Retained IDs permit decryption of prior envelopes; retirement needs rewrapping first.
This setting enables encrypted enrollment and native browser OTP step-up. See [authentication gateway](AUTH_GATEWAY.md).

The keyring now also enables initial owner enrollment at `/security/totp`: only a
recent authenticated HTTPS portal session can create and confirm a pending factor.
With no keyring, these routes return 404. Enrollment alone does not raise AAL. A matching assurance rule starts `/stepup`; a valid new OTP atomically rotates credentials and issues AAL 2. Rules are explicit and unchanged by registration.
The deployment must expose the portal through its existing trusted HTTPS ingress.

AAL 1 primary-freshness rules use provider reauthentication even without a keyring.

## External verifier startup configuration

Optional `external_verifiers` is an array, default `[]`, of at most 64 unique
operator-approved independent second-factor verifiers. Each entry contains
`factor`, `configuration_revision` (1..i64::MAX), fixed HTTPS `url`,
`verifier_key_env`, `timeout_ms` (1..1000), optional `allow_private_endpoints`
(default false) and optional absolute `ca` path. Inline secrets and unknown keys
are refused. Authenticated gateway callers are mandatory.

All verifier credentials, CA contents and clients are compiled before state
creation, migration or listeners. Missing/invalid material fails startup with a
redacted category; `--check` reports the same material problem. After config
import and epoch selection, startup atomically publishes the complete desired
registry, including removal tombstones/session revocation, before exposing it
through Services or binding listeners. Revision/material conflicts refuse startup.
Removal plus restart disables the old authority; retain or increase revision as
required by [the factor lifecycle](SECOND_FACTOR_EXTENSIONS.md).

This config publishes verifier authority and its native connection registry.
Configured external factors now appear in the native step-up chooser. Either
a configured TOTP keyring or a nonempty external registry enables document step-up;
API requests still fail closed without elevated evidence. External factors use
the native HTTPS/CSRF/browser-bound response form and atomic owner completion.
An optional `eligibility_lua` text script can restrict a factor by native owner
context in unreleased source (not in tagged 0.0.3 artifacts). The internal
`0.0.3-mixed-f14287a` candidate includes the runtime; production external factors
and scripts remain unconfigured.
For example, `return context.service == 'orders'` allows verification
only for that service. The environment contains only `context.service`,
`context.connector` and `context.subject`; these are server-owned identifiers,
not browser claims. Scripts have no standard libraries, credentials, network,
filesystem, session writers, permission or assurance authority. Never place
secrets in scripts. Only a boolean is accepted; false rejects before any API call,
and errors/budget exhaustion fail closed. True still requires authenticated HTTPS
proof validation and atomic native owner completion.

Limits are 16 KiB source, 256 KiB Lua heap, at most 20,100 instructions (100
instruction hook interval), five milliseconds including VM setup, and the existing
64 concurrent calls per connector. Each evaluation uses a fresh VM. Syntax and
text-only mode are checked at startup. The source is included in the immutable
verifier binding; changes require a newer configuration revision and revoke
affected factor sessions through the existing publication path. With no script,
serialized binding material is unchanged. This adds eligibility execution, not
general Lua connector orchestration, credential translation or recovery; those
remain implementation work.

## Service authentication Lua eligibility (unreleased)

`authentication_gateway` in the startup JSON bootstraps an empty authority only.
Once the DB contains an authentication-profile document (including a disable
tombstone), the DB/PAP document takes precedence. Editing startup JSON and
restarting does not replace it. Publish changes through the authenticated owner
API. Offline qualification uses the native owner transaction on an independent
`profile-publication-candidate.db`; never modify live state through that tool.

`authentication_gateway.profiles[].eligibility_lua` optionally applies the same
bounded boolean runtime after native API-key or external API-relay authentication.
For example, `return context.subject == 'scheduler' and context.service == 'orders'`.
Context contains the verified subject, native service and connector identifier;
no bearer token or caller-supplied identity is exposed. Invalid/expired credentials
and disallowed networks are refused before script execution. False denies the
verified credential; errors or the 64-evaluation profile capacity limit fail closed.
True preserves issuer/realm/subject/principal kind, service scope and absolute
evidence expiry. Relay transport and script execution cannot extend freshness.
Service identity remains AAL 0 and Pumgye retains authorization ownership.

Omitting the option preserves serialized configuration and the indexed native
path without VM execution. Syntax is validated before secret resolution. Script
limits match external-factor eligibility above. General credential translation,
connector orchestration and human first-factor hooks remain unfinished. Tagged
0.0.3 artifacts do not contain this later service-profile extension. Internal
`0.0.3-mixed-f14287a` includes it with production scripts unconfigured.
Earlier JSON-only private candidates tested the durable profiles, not the proposed
service Lua policy, because their DB copy already contained an authority document.
The corrected offline-publication candidate checks the stored desired document
before startup and verifies an upstream-approved identity denied by Lua over both
HTTP and pooled mTLS. Mixed/native/relay and Chromium MFA/TOTP checks pass;
native macOS runtime tests and live internal regressions also pass. Existing
configuration/keys and consistent v6 rollback backups are preserved.

## Mixed native and external service credentials (unreleased)

A service profile can contain both `api_keys` and `api_relay` when it explicitly
sets `relay_token_prefix`, for example `partner:`. The prefix is 2–32 printable
ASCII bytes: letters/digits/underscore/hyphen followed by one colon. Matching
Bearer credentials route only to the configured relay; Hopae removes exactly one
prefix before forwarding the upstream credential. All other credentials route
only to the native key index. Neither rejection, expiry, outage nor Lua denial
tries another connector or a human session. Local secret material that starts
with the prefix refuses compilation to prevent routing collisions.

Keep the prefix when retiring the last native key; it remains valid for relay-only
profiles and prevents retired native keys being forwarded. Prefixes require a
relay; mixed profiles without a prefix refuse startup. Existing single-connector
profiles with no prefix retain their behavior and serialized configuration.
Issuer/realm/subject/service/kind remain connector-verified, AAL 0, and separately
namespaced. A mixed relay cannot reuse the native `hopae:<authority_id>` issuer;
linking identities requires explicit authorization mapping, not issuer collision.
The routing marker grants no identity. The complete presented mixed
credential is capped at 4096 printable ASCII bytes. This is deterministic service
credential routing/unwrapping, not general connector composition or human identity
translation. Internal `0.0.3-mixed-f14287a` includes this feature; its authoritative
production profile document retains native-only credentials without scripts or
mixed routing. Existing configuration, keys and consistent owner/delegation v6
rollback backups are preserved; live gateway/console regressions pass. Tagged
0.0.3 assets do not include this later feature.

### Credential projection plans (unreleased)

Optional `credential_projection` declares bootstrap revision `1` and up to 128
reference-only plans. Each plan names a configured application `service`, fixed
`audience`, `resource`, `action`, `minimum_aal` (0–3), and `credential`: either
`{"type":"identity_header"}` or
`{"type":"bearer_reference","secret_ref":"vault:example-token"}`. No secret
value is embedded or resolved by configuration checking or the management API.
Authenticated gateway callers are required. These plans do not activate a
projection endpoint or send credentials through ordinary auth responses.

Startup imports these plans only when the owner DB row is absent. DB publication
—including a disabled tombstone—takes precedence on restart. Stored enabled plans
must remain within the startup declaration: same service/audience/resource/action
and credential capability/reference, with an equal or higher minimum AAL. Removal
of a required declaration refuses readiness rather than silently granting another
capability. A database restore still needs an external rollback/version fence.

The protected admin API exposes `GET /v1/authentication/projections` (reference-only
JSON, ETag and no-store) and `PUT /v1/authentication/projections`. PUT requires the
existing admin/CSRF checks, exactly one quoted numeric `If-Match`, and an explicit
`configuration` field. `null` publishes disable; an enabled configuration must use
the next revision. New scopes/references or weaker assurance return 422; stale
revision returns 409. Publication rechecks the native actor inside the transaction
and commits reference-only audit with the document, then installs the prepared
memory snapshot. Delegated Hangang requests use signed
`POST /v1/authentication/projections/publish` with `revision` and `configuration`.
The Hangang module UI and gateway projection transport still need integration.

### gRPC verification listener

`listen.grpc_gateway` is an optional literal socket address. It requires `listen.native_gateway_tls` and authenticated gateway callers, even on loopback. HOP1 may be disabled. See [gRPC verification](GRPC.md).
