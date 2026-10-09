# Administration

<!-- doc-rev: 2 -->

[Documentation](README.md) · [한국어](ko/ADMIN.md)

The administration console and its JSON API let an operator list and search
users, inspect a user's identities, sessions and recent events, disable and
enable a user, end one session or every session of a user, browse the login
history and the audit trail, and read the status of applications, providers,
the store and the build. This page is the G1 specification of milestone
**M4-min** ([roadmap](ROADMAP.md#m4-min--management-console-minimum-020)),
revised after design review pass 1; the decisions are recorded in
[ADR-0016](adr/0016-management-console-minimum.md) (Proposed). The console is
a Hopae application served by Hopae itself: administrators sign in with the
ordinary login flow, and Hopae authenticates every console request from its
own session handle.

## Prerequisites and configuration

| Item | Requirement |
| --- | --- |
| Console host | A dedicated host name for the console (`hopae-admin.example.test` in examples) with DNS and TLS on the gateway, like any application host |
| Gateway route | A protected whole-host route for the console host whose backend is the admin listener, with the contract's standard `auth` block and **without** `strip_request_cookies` (the fragment is below; `hopae --check` prints it) |
| Configuration | `admin.public_url` set; the admin listener binds `listen.admin` only then |
| First administrator | A user who has signed in at least once, granted with `hopae admin grant` or listed in `admin.users[]` ([bootstrap](#bootstrap-and-recovery)) |
| Provider | An `oidc` provider that honors `max_age` and returns `auth_time` (Google does): console freshness is a provider challenge |
| Provider second factor | Until milestone M5 a console session is single-factor; require a second factor at the provider for administrator accounts |

Keys (all under the top-level `admin` object unless stated; details in the
[configuration reference](CONFIG.md#keys-decided-and-scheduled)):

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `listen.admin` | string, socket address | `127.0.0.1:8702` | Admin listener; bound only when `admin.public_url` is set; must differ from the other listeners; a non-loopback address produces a warning |
| `admin.public_url` | string, origin | none | Externally visible origin of the console, `https://hopae-admin.example.test`; `https://` or `http://` plus a host and optional port, no path. Setting it registers the implicit application `admin` |
| `admin.session.idle`, `admin.session.absolute` | duration | `30m`, `12h` | Per-handle timers of the console host (`idle` at least `60s`) |
| `admin.binding.ip`, `admin.binding.ip_prefix_v4`, `admin.binding.ip_prefix_v6`, `admin.binding.ua`, `admin.binding.on_mismatch` | as `apps[].binding.*` | `strict`, `24`, `64`, `off`, `terminate_session` | Client binding of the console handle |
| `admin.max_auth_age` | duration | `12h` | Oldest provider authentication (`sessions.auth_time`) a console session may rely on; an older one is sent to reauthenticate at the provider ([freshness](#freshness-and-reauthentication)) |
| `admin.require_aal` | `1` or `2` | `1` | Minimum assurance level of the presented handle; `2` also sets the implicit application's step-up rule for the whole host. Before M5 no second factor exists and `hopae --check` warns that `2` refuses every request |
| `admin.untrusted_peers` | `refuse`, `as_client` | `refuse` | What the listener does with a TCP peer outside `trusted_proxies`: refuse it loudly (`403 untrusted_peer`, a warning, a counter) or treat the peer as the client as the portal does |
| `admin.query_budget_ms` | integer, 100 to 30000 | `2000` | Deadline of one listing or search; a query that reaches it is interrupted inside the store and answered `503` |
| `admin.users[]` | array of `{user_id?, email?, role?, note?}` | `[]` | Grants seeded from the file at start and by `hopae admin import` ([seeding](#grants-in-the-configuration-file)); `role` is `admin` (default) or `viewer`; at least one of `user_id` and `email` |
| `limits.admin_max_concurrent` | integer, at least 1 | `16` | In-flight request cap on the admin listener; excess requests are answered `503` at once |

The implicit application `admin` is reserved: an `apps[]` entry with that id
is a configuration error, and the console host must not appear in any
`apps[].hosts`. It is registered with `hosts = [host of admin.public_url]`,
`ports = [its port, or 443]`, the lifetimes and binding above,
`max_auth_age = admin.max_auth_age`, `on_authz_change = terminate`,
`verify_cache_seconds = 0` and `logout_confirm = true`. It appears in
`hopae --check` and in the status page like any other application.

Gateway route fragment for the console host (Hangang; the `auth` block is the
contract's standard one; the one difference from an application route is that
`strip_request_cookies` is absent, because the upstream is Hopae and needs the
handle):

```json
{
  "id": "hopae-admin",
  "access_mode": "protected",
  "host": "hopae-admin.example.test",
  "path_prefix": "/",
  "backends": ["http://127.0.0.1:8702"],
  "auth": {
    "url": "http://127.0.0.1:8701/_hopae/verify",
    "request_headers": ["cookie", "user-agent", "accept", "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site"],
    "response_headers": [
      "x-forwarded-user", "x-forwarded-email", "x-forwarded-preferred-username", "x-forwarded-groups",
      "x-hopae-session", "x-hopae-provider", "x-hopae-auth-time", "x-hopae-expires",
      "x-hopae-aal", "x-hopae-factors"
    ],
    "static_request_headers": {
      "x-hopae-contract": "1",
      "x-hopae-gateway-key": {"env": "HANGANG_HOPAE_KEY"}
    },
    "timeout_ms": 500,
    "forward_response": true
  }
}
```

The gateway's own route-level controls (client address policy, country policy)
may be added in front of the console host as a second layer; Hopae does not
depend on them.

Command line (runs against the store directly, safe while an instance runs; a
running instance reads grants on every request, so no restart is needed):

| Invocation | Meaning |
| --- | --- |
| `hopae admin grant <user_id or email> [--role admin\|viewer] [--note <text>] [--confirm <user_id>] --config <path>` | Grant the role (default `admin`) to an existing user and print the user it resolved: `user_id`, `display_name`, `created_at`, `last_login_at`, `primary_email` with its `verified` and `authoritative` flags, and every linked identity as `provider:subject`. An email must be the user's verified `primary_email`; a user who never signed in does not exist (exit `2`, "sign in once first"). An email that is **not authoritative** is granted only with `--confirm <user_id>` naming the resolved id (exit `2` otherwise, after printing the resolution). The grant binds to the resolved `user_id` and is never re-resolved. A second grant updates the role and clears a revocation; a file-managed row becomes `managed_by = api`. Records `admin.grant` with `attrs.actor = cli`. |
| `hopae admin revoke <user_id or email> --config <path>` | Revoke the grant; the user's next console request is `403 not_admin`. The row becomes a tombstone (`managed_by = api`) that the file import never resurrects. Records `admin.revoke`. |
| `hopae admin list [--all] --config <path>` | Print every live grant: user id, email, role, `managed_by`, granted at, granted by, note; `--all` adds revoked rows with their revocation. |
| `hopae admin import [--force <user_id or email>] --config <path>` | Apply `admin.users[]` of the file to the store by the [seeding rule](#grants-in-the-configuration-file) (the same import runs at start) and print what was inserted, updated, revoked and skipped with the reason; `--force` reasserts one file entry over an `api`-managed or revoked row. Records `admin.grant` / `admin.revoke` with `attrs.actor = file`. |

### Bootstrap and recovery

1. Register the console route on the gateway and set `admin.public_url`; restart Hopae.
2. Open `https://hopae-admin.example.test/` in a browser and sign in with the provider. The console answers `403 not_admin` and shows the user id and email of the signed-in user.
3. Run `hopae admin grant <that user id>` (or list the user in `admin.users[]` and restart or run `hopae admin import`). The command prints the resolved user; check that the identities are the expected person's. Reload: the console opens.
4. Recovery is the same command: a lost or compromised administrator is revoked with `hopae admin revoke`, and another user is granted. There is no password, bootstrap token or break-glass credential.

### Grants in the configuration file

`admin.users[]` is imported at start and by `hopae admin import`, with the
provider import rule adapted to grants:

- An entry matches an existing row by `user_id` when it has one, else by `source_email` (the address a row was created from) among `managed_by = file` rows. An address is **never re-resolved** for a row that exists.
- A matched live file row has its `role` and `note` updated. An unmatched entry is resolved once: by `user_id` (the user must exist); by `email` alone only when exactly one user holds that verified address **and** it is authoritative; by both only when they name the same user. Anything else is skipped with a preflight warning naming the entry and the reason (`unknown_user`, `email_unverified`, `email_not_authoritative`, `email_ambiguous`, `user_email_mismatch`).
- A live file row whose entry is no longer in the file is revoked (`revoked_by = file`): removing an administrator from the file removes the authority at the next start or import.
- Rows created or last changed by the CLI (`managed_by = api`) and tombstones (revoked rows) are never touched by the import, so a runtime revocation survives restarts. `hopae admin import --force <user_id or email>` reasserts one file entry over such a row and records it.
- Preflight warns when a file entry's email now belongs to a different user than the row it is bound to; the grant stays bound.

## Behavior

### Signing in and authorization

```text
 Browser                    GW (route hopae-admin)              HP gateway listener         HP admin listener
   │ GET https://hopae-admin.example.test/users                 │                            │
   ├──────────────────────────▶│ GET /_hopae/verify (cookie, …) │                            │
   │                           ├───────────────────────────────▶│ no handle, or auth_time too old
   │                           │                                │ → 302 portal (reauth_max_age set)
   │ … portal login with max_age and prompt=login, auth_time checked, handoff to /_hopae/login on the console host …
   │ GET /users (cookie: __Host-hopae=Ha)                       │                            │
   ├──────────────────────────▶│ verify → 200 [id-hdrs]          │                            │
   │                           ├── proxied request: cookie Ha, x-forwarded-*, [id-hdrs] ──────▶│ peer trusted? → handle Ha → engine:
   │                           │                                │                            │ session, timers, binding, status,
   │                           │                                │                            │ freshness → grant(user) → role → page
   │ 200 page                  │◀─────────────────────────────────────────────────────────────┤ ([id-hdrs] never read)
```

The admin listener authenticates every request itself:

1. The TCP peer is checked against `trusted_proxies`: a peer outside it is refused (`403 untrusted_peer`) under the default `admin.untrusted_peers = refuse`, or treated as the client under `as_client`. For a trusted peer the client address and scheme come from the forwarding headers, as on the portal listener. The forwarded host must be the console host (`404` otherwise).
2. The configured handle cookie (`__Host-hopae`) is read and the verify engine evaluates it for the console host exactly as the gateway's verify would: session, handle and session timers, binding policy, `users.status` and `authz_version`, the implicit application's policy including `max_auth_age`. Only an allow proceeds. Any other outcome is `403 login_required` with the console URL as the `login` link; nothing is created, no cookie is set, and no login is started (the gateway's verify already handled the login, the reauthentication and the handoff before proxying). The denial is counted and recorded with the same sampled `verify.denied` helper the gateway listener uses.
3. The user's grant is read from the store on every request. No grant, or a revoked one, is `403 not_admin`; the page shows the user id and email. Then the role and `admin.require_aal` are checked.
4. The identity headers the gateway injects and every gateway context header other than the forwarding headers are never read. A request that reaches the listener without going through the gateway therefore yields nothing without a valid console handle.

### Roles

| Role | May | May not |
| --- | --- | --- |
| `viewer` (read-only administrator) | Open every page; every `GET` of the API; see the same data as an administrator, client addresses and emails included | Any mutation (`403 role_insufficient`, recorded) |
| `admin` | Everything a viewer may, plus disable and enable users, terminate sessions | Disable their own user (`403 self_target`); grant or revoke (command line and file only in M4-min) |

### Freshness and reauthentication

- `admin.max_auth_age` bounds the age of the session's provider authentication (`sessions.auth_time`). The verify engine evaluates it on **every** verify for the console host: when the bound is exceeded, a document navigation is sent to the portal with a transaction that carries the reauthentication requirement (`reason=reauth_required`), and a non-document request receives `401 {"error":"reauth_required"}`. A session that authenticated recently enters without a new challenge; one that signed in long ago on another host is challenged on its first console entry; one that ages past the bound inside the console is challenged on its next navigation.
- For such a transaction the portal offers no single sign-on and the provider's authorize request carries `max_age=<seconds>` and `prompt=login` (unless the provider's stored configuration sets `reauth_prompt: "none"`). The returned ID token must carry `auth_time`, no older than the bound plus 60 seconds of leeway; otherwise the login fails (`reauth_auth_time_missing`, `reauth_not_fresh`) and nothing is created.
- On success the existing session of the same user is reauthenticated: `auth_time` becomes the provider's claim, a factor entry is appended, the credential generation advances, every handle is revoked and reissued through the ordinary handoff (other applications re-handoff silently by single sign-on). A different user, or no live session, gets an ordinary new session.
- Every OIDC login records the ID token's `auth_time` claim as the session's `auth_time` when the provider sends one, and the callback time otherwise (`attrs.auth_time_source` on `session.created`); `x-hopae-auth-time` reports it.
- `admin.require_aal = 2` requires a handle issued at level 2 ([ADR-0008](adr/0008-second-factor-extension-point.md)). Until second factors exist (M5) this refuses every request; the default is `1`. Require a second factor at the provider for administrator accounts meanwhile.
- The console handle has its own lifetimes (`30m` idle, `12h` absolute by default) and strict client-address binding; `on_authz_change = terminate` ends the console session when the user's authorization data changes. The admin listener keeps an `auth_too_old` check of its own for the race in which a session ages between the gateway's verify and the listener's; its page links to the console URL, where the next navigation starts the reauthentication.

### Sign-out

Every page links to `https://hopae-admin.example.test/_hopae/logout`, the application-host logout entry point ([gateway contract](GATEWAY_CONTRACT.md#application-host-entry-points)): the portal's confirmation page ends the session, which also ends access on every other host.

### Denials

| Code | Status | When | Event |
| --- | --- | --- | --- |
| `untrusted_peer` | `403` | The TCP peer is outside `trusted_proxies` and `admin.untrusted_peers = refuse`; answered before any cookie is read | sampled `verify.denied` (`reason=untrusted_peer`), a rate-limited warning |
| `login_required` | `403` | No valid console handle (direct connection, misconfigured route, session ended between the gateway's check and this one); JSON body carries `login` = the console URL | sampled `verify.denied` with the engine's reason |
| `not_admin` | `403` | Valid session, no live grant | `admin.denied` (`reason=not_admin`) |
| `role_insufficient` | `403` | A read-only administrator attempted a mutation | `admin.denied` |
| `auth_too_old` | `403` | `auth_time` older than `admin.max_auth_age` at the listener (a race; the gateway's verify normally redirected to reauthenticate first) | `admin.denied` |
| `aal_insufficient` | `403` | Handle level below `admin.require_aal` | `admin.denied` |
| `self_target` | `403` | An administrator disabling their own user | `admin.denied` |
| `csrf_rejected` | `403` | Form token or `Origin` check failed | `csrf.rejected` (`purpose=admin`, `cause=token` or `origin`) |
| `actor_revoked` | `403` | The actor's session, handle, user status, authorization baseline, freshness, level or grant no longer satisfied the fence when the write ran (refused inside its transaction) | `admin.denied` |
| `invalid_cursor`, `invalid_filter`, `invalid_id` | `400` | Malformed pagination cursor, filter value or identifier | none |
| `not_found` | `404` | Unknown user or session id; unknown path; a forwarded host other than the console host | none |
| `payload_too_large` | `413` | Body over 64 KiB or query string over 4 KiB | none |
| `overloaded` | `503` | `limits.admin_max_concurrent` reached | none |
| `store_unavailable` | `503` | The primary store cannot answer, or a listing reached `admin.query_budget_ms` and was interrupted: fail closed | none |

### Failure behavior

| Condition | Console | What the operator sees |
| --- | --- | --- |
| Primary store unavailable | Every request `503 store_unavailable`; nothing is cached | Log at error, `hopae_store_errors_total` |
| Console route missing or without `auth` | Browsers reach the listener without a handle: `403 login_required` with the console link; no login starts | `hopae --check` prints the fragment; the phase-1 drift report flags the host |
| Console route strips Hopae cookies | The listener never sees the handle: `403 login_required` on every request after a successful login | Drift report: `strip_request_cookies_on_console_route` |
| A peer other than the gateway connects | `403 untrusted_peer` by default; nothing read, nothing created | A rate-limited warning naming the peer address, `hopae_admin_denied_total{reason="untrusted_peer"}` |
| Admin listener reached directly through a trusted address | Nothing is trusted from the request but a valid handle; without one, `403 login_required` and no state | Counter `hopae_admin_denied_total{reason}` |
| Provider ignores `max_age` or omits `auth_time` | Reauthentication fails (`reauth_auth_time_missing`); the console cannot be entered with that provider | `login.failed` naming the provider |
| Grant revoked, user disabled, session terminated | Next request refused; no restart or cache flush needed | `admin.denied` or `verify.denied` |

## Management API, console and observability

### Pages

| Path | Content |
| --- | --- |
| `/` | Status: applications, providers, store, build, configuration generation |
| `/users?q=&status=&cursor=` | User list with search |
| `/users/{user_id}` | User detail: identities, previews of live and recently terminated sessions with totals and links, the 50 most recent events with a link, the grant; disable, enable and terminate-all forms |
| `/sessions?user_id=&cursor=` | Live sessions |
| `/sessions/{session_id}` | Session detail with its handles per host; terminate form |
| `/events?kind=&outcome=&user_id=&session_id=&client_ip=&since=&until=&cursor=` | Login history and audit trail |
| `/assets/admin.css` | The stylesheet (the only static asset) |

Pages are rendered in English or Korean by `Accept-Language`. Every response
carries `cache-control: no-store`, `x-content-type-options: nosniff`,
`referrer-policy: same-origin`, `x-frame-options: DENY`, `x-robots-tag:
noindex` and `content-security-policy: default-src 'none'; style-src 'self';
img-src 'self'; form-action 'self'; frame-ancestors 'none'`. No page contains
or loads a script.

### API

All endpoints are on the admin listener under `/v1/`, authenticated by the
console handle exactly like the pages, and answer JSON. Times are unix seconds;
identifiers are the `u_`, `s_`, `e_` forms.

| Method and path | Role | Answer |
| --- | --- | --- |
| `GET /v1/me` | viewer | `{user_id, email, display_name, role, session_id, auth_time, aal}` |
| `GET /v1/users?q=&status=&limit=&cursor=` | viewer | `{items: [{user_id, primary_email, email_verified, email_authoritative, display_name, username, status, authz_version, created_at, last_login_at, live_sessions, role}], next_cursor}` |
| `GET /v1/users/{user_id}` | viewer | `{user, identities: [≤ 50 of {provider_id, subject, email, email_verified, name, first_seen_at, last_seen_at}], sessions_live: [≤ 20 summaries, newest created first], sessions_live_total, sessions_terminated: [≤ 20 most recent], events: [≤ 50 most recent], grant: {role, managed_by, granted_at, granted_by, note} or null}`; `sessions_url` and `events_url` carry the filtered listings |
| `POST /v1/users/{user_id}/disable` | admin | `{changed, sessions_terminated}`; disables, bumps `authz_version`, terminates every live session |
| `POST /v1/users/{user_id}/enable` | admin | `{changed}`; no session is revived |
| `POST /v1/users/{user_id}/sessions/terminate` | admin | `{terminated}` |
| `GET /v1/sessions?user_id=&limit=&cursor=` | viewer | `{items: [{session_id, user_id, primary_email, provider_id, aal, factors, hosts, created_at, last_seen_at, absolute_expires_at, auth_time, bound_ip, ua_prefix}], next_cursor}` (live sessions only, newest created first) |
| `GET /v1/sessions/{session_id}` | viewer | The summary plus `handles: [≤ 100 of {host, issued_aal, created_at, last_seen_at, absolute_expires_at, revoked_at, revoked_reason}]`, `terminated_at`, `terminated_reason` |
| `POST /v1/sessions/{session_id}/terminate` | admin | `{changed}` |
| `GET /v1/events?kind=&outcome=&user_id=&session_id=&client_ip=&since=&until=&limit=&cursor=` | viewer | `{items: [event JSON as the log sink writes it], next_cursor}` newest first |
| `GET /v1/status` | viewer | See [status](#status) |

Error bodies are `{"error": "<code>"}` with the codes of the denial table.

### Pagination and filters

- `limit` is 1 to 200 (default 50). `next_cursor` is an opaque, tamper-evident position; pass it back as `cursor` to continue; a forged or stale one is `400 invalid_cursor`. The walk ends when `next_cursor` is absent.
- Every page examines at most **10,000 candidate rows**: one range scan of one index, followed by the remaining filters inside that window. When the window was full, `next_cursor` points past the last candidate examined, even if the page returned fewer than `limit` items or none; a sparse filter over a large table therefore yields short pages and several requests, never a scan of the whole table in one request. A page that reaches `admin.query_budget_ms` is interrupted and answered `503`.
- Ordering is fixed and immutable: users by creation (newest first), sessions by creation (newest first, with `last_seen_at` displayed), events by time (newest first). A walk neither skips nor repeats a row that existed when it started, whatever activity happens meanwhile; rows created after the walk started are not part of it.
- Users: `q` (at most 128 characters) matches `primary_email` and `username` by prefix and `display_name` by substring, within the window; `status` is `active` or `disabled`.
- Sessions: `user_id` narrows to one user; only live sessions are listed (terminated ones are previewed on the user detail).
- Events: `kind` is an exact event kind (`login.failed`, `admin.user_disable`, …), `outcome` is `success`, `failure` or `info`, `client_ip` is one exact address (IPv4-mapped IPv6 normalized), `since` and `until` are unix seconds (`since` must not exceed `until`). Filters combine with AND. The index is chosen by `session_id`, else `user_id`, else `client_ip`, else `kind`, else time; the other filters are applied inside the window.

### Requests that change state

- HTML forms: `POST` with `application/x-www-form-urlencoded`, a `csrf` field issued on the page (bound to the presented handle, purpose `admin`, valid 10 minutes) and an `Origin` header equal to `admin.public_url`'s origin. The handle cookie is `SameSite=Lax`, so cross-site form posts do not carry it in the first place.
- JSON API: `POST` with `content-type: application/json`, the header `x-hopae-admin-request: 1`, and, when present, `Origin` equal to the console origin and `sec-fetch-site` equal to `same-origin` or `none`. A cross-origin browser cannot send these without a preflight that nothing answers.
- Every mutation re-evaluates the actor as the first statement of its store transaction: session live and within its deadlines, handle for the console host unrevoked and within its deadlines and at the required level, user `active` with its authorization baseline unchanged, `auth_time` within `admin.max_auth_age`, grant live with role `admin`. A change committed first refuses the write (`403 actor_revoked`) and changes nothing.
- A mutation that changes nothing (disabling a disabled user, terminating an ended session) answers `200` with `changed: false` and writes no event.

### Audit events

Every state change writes its `admin.*` event in the same transaction as the
change ([ADR-0009](adr/0009-event-model.md)). The first-class columns name the
target; `attrs.actor` names the acting user (or `cli`, or `file`) and
`attrs.actor_session` their session.

| Kind | Columns | `attrs` | Written with |
| --- | --- | --- | --- |
| `admin.user_disable` | `user_id` = target | `actor`, `actor_session`, `count` (sessions terminated) | `users.status`, `authz_version`, one `session.terminated` (`reason=user_disabled`) per session |
| `admin.user_enable` | `user_id` = target | `actor`, `actor_session` | `users.status`, `authz_version` |
| `admin.session_terminate` | `session_id`, `user_id` = target | `actor`, `actor_session` | `session.terminated` (`reason=admin`) |
| `admin.sessions_terminate` | `user_id` = target | `actor`, `actor_session`, `count` | one `session.terminated` (`reason=admin`) per session |
| `admin.grant`, `admin.revoke` | `user_id` = granted user | `actor` (`cli` or `file`), `role`, `previous_role`, `managed_by` | the `admin_grants` row |
| `admin.denied` | `user_id`, `session_id` = the requester | `endpoint` (route pattern), `method`; `reason` ∈ `not_admin`, `role_insufficient`, `auth_too_old`, `aal_insufficient`, `self_target`, `actor_revoked` | nothing (required event on its own) |
| `csrf.rejected` | `user_id`, `session_id` = the requester | `purpose=admin`, `cause` | nothing |

Reads are not audited. A console sign-in is visible as the ordinary
`session.handoff` event with `app_id = admin`; a reauthentication as
`login.succeeded` with `attrs.reauth = true`.

### Status

`GET /v1/status` and the front page show, read-only:

| Section | Fields |
| --- | --- |
| `apps` | `app_id`, `display_name`, `hosts`, `ports`, `enabled`, `session`, `binding`, `on_authz_change`, `verify_cache_seconds`, `logout_confirm`, `max_auth_age`, `step_up` count; the implicit `admin` application included |
| `providers` | `provider_id`, `kind`, `display_name`, `enabled`, `managed_by`, `health` (`ok`, `degraded` with a reason code, `disabled`), `client_secret_env` (the variable **name**) and `secret_present`; never a value |
| `store` | `kind`, `schema_version`, `users`, `live_sessions`, `events`, `deliveries` per sink (`pending`, `failed`), `last_prune_at` |
| `build` | `version`, `contract` (`1.1`), `started_at` |
| `config` | `generation`, `digest`, `insecure_mode`, `unauthenticated_caller`, `listeners` |

Runtime changes to providers and applications are not part of M4-min. When
they are added, a provider changed through the API becomes `managed_by = api`
([ADR-0010](adr/0010-provider-abstraction.md)) and this page is where the
operator sees that the configuration file no longer owns the row.

### Counters

`hopae_admin_requests_total{role,outcome}`, `hopae_admin_denied_total{reason}`,
`hopae_admin_mutations_total{kind}`, `hopae_admin_rows_examined_total{list}`;
exposition is M7, the test hooks expose them meanwhile.

## Limitations and compatibility

- The console requires the gateway's protected route for its host; a route without `auth` or with `strip_request_cookies` makes every request `403 login_required`.
- Administrator sessions are single-factor until M5; the mitigations are provider-side second factors, the reauthentication after `admin.max_auth_age`, the short lifetimes and strict binding of the implicit application.
- Reauthentication needs an `oidc` provider that honors `max_age` and returns `auth_time`; a provider that does not cannot sign administrators into the console.
- Non-browser API clients need a cookie obtained by a browser; API tokens are later work.
- Providers, applications and blacklists are not managed from the console in M4-min; grants come from the command line and the configuration file only.
- Reads are not audited; there is no export; a session's user-agent prefix exists only for sessions created after migration `0003`.
- Listings examine at most 10,000 rows per request; sparse searches over a large directory return short pages and need several requests.
- Read-only administrators see the same personal data as administrators.

## Examples, verification and related pages

Configuration fragment enabling the console with one seeded administrator:

```json
{
  "listen": {"portal": "127.0.0.1:8700", "gateway": "127.0.0.1:8701", "admin": "127.0.0.1:8702"},
  "admin": {
    "public_url": "https://hopae-admin.example.test",
    "session": {"idle": "30m", "absolute": "12h"},
    "max_auth_age": "12h",
    "untrusted_peers": "refuse",
    "users": [{"user_id": "u_01hzexampleexampleexample0", "role": "admin", "note": "on-call"}]
  }
}
```

Terminating a session from a script with a browser-obtained cookie:

```sh
curl -sS -X POST https://hopae-admin.example.test/v1/sessions/s_<redacted>/terminate \
  -H 'content-type: application/json' -H 'x-hopae-admin-request: 1' \
  -H 'cookie: __Host-hopae=<redacted>' -d '{}'
```

Verification: scenarios [300](../scenarios/300-administrator-access-to-the-console.md)
(access, roles, freshness, CSRF, peers and direct connections),
[301](../scenarios/301-console-users-list-search-disable-enable.md)
(users), [302](../scenarios/302-console-sessions-list-and-terminate.md)
(sessions), [303](../scenarios/303-console-login-history-and-audit-browsing.md)
(history and audit), [304](../scenarios/304-console-status-is-read-only.md)
(status), [305](../scenarios/305-administrator-grants-cli.md) (grants, seeding,
bootstrap and the migration guard).

Related pages: [configuration reference](CONFIG.md), [architecture](ARCHITECTURE.md),
[threat model](THREAT_MODEL.md#threat-catalogue) (TM-15, TM-42 to TM-46),
[gateway contract](GATEWAY_CONTRACT.md), [operations](OPERATIONS.md),
[ADR-0016](adr/0016-management-console-minimum.md).
