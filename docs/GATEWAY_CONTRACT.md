# Gateway contract

<!-- doc-rev: 2 -->

[Documentation](README.md) · [한국어](ko/GATEWAY_CONTRACT.md)

This page is the exact wire contract between a gateway's forward-
authentication check and Hopae: endpoints, request headers consumed, response
codes, identity headers emitted, cache semantics, the invalidation channel and
the portal entry points. It is versioned as **contract v1** and is part of
Hopae's public API for versioning purposes ([process](PROCESS.md#changelog-and-versioning)).
The Hangang gateway is the first-class integration; the second half of the
page states what works on an unmodified Hangang 0.2.6 and which gateway
changes are proposed. Decisions are recorded in
[ADR-0005](adr/0005-gateway-contract-and-versioning.md) and
[ADR-0006](adr/0006-verify-caching-and-invalidation.md).

## Prerequisites and configuration

| Side | Setting | Value |
| --- | --- | --- |
| Hopae | `listen.gateway` | Address of the gateway listener, default `127.0.0.1:8701`; must not be publicly reachable |
| Hopae | `listen.portal` | Address of the portal listener, default `127.0.0.1:8700`; the gateway proxies the portal host to it |
| Hopae | `portal.public_url` | `https://auth.example.test`; used for every `Location` the contract emits |
| Hopae | `gateway.kind` | `hangang` (M1); `forward_auth` (later) |
| Hopae | `gateway.caller_key_env` | Required for `gateway.kind = hangang`: the environment variable holding the shared caller key the gateway sends in `x-hopae-gateway-key` (gateway change HC-3, implemented together with M1). `gateway.allow_unauthenticated_caller = true` disables the check for development only and makes preflight warn. |
| Hopae | `gateway.verify_budget_ms` | Total time Hopae allows itself per verify, default `400`; must be below the gateway's `auth.timeout_ms` |
| Hopae | `apps[]` | Application hosts (exact names or `*.suffix` patterns), `ports` (default `[443]`) and policies; the union is the return-origin allowlist; a host matching no pattern is denied (`unknown_app`) |
| Gateway | route `auth.url` | `http://127.0.0.1:8701/_hopae/verify` |
| Gateway | route `auth.static_request_headers` | `{"x-hopae-contract": "1", "x-hopae-gateway-key": {"env": "HANGANG_HOPAE_KEY"}}` (HC-3) |
| Gateway | route `auth.request_headers` | `cookie`, `user-agent`, `accept`, `sec-fetch-dest`, `sec-fetch-mode`, `sec-fetch-site` |
| Gateway | route `auth.response_headers` | The identity header set listed below |
| Gateway | route `auth.forward_response` | `true` (mandatory: login redirects and cookie planting travel through it) |
| Gateway | route `auth.timeout_ms` | `500` recommended (gateway default `1000`, maximum `5000`) |

### Hangang route fragments

Protected application (whole host):

```json
{
  "id": "app-example",
  "access_mode": "protected",
  "host": "app.example.test",
  "path_prefix": "/",
  "backends": ["http://127.0.0.1:3000"],
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

`static_request_headers` is gateway change HC-3. An unmodified gateway
rejects the key (`deny_unknown_fields`); such a gateway can be used only in
development with `gateway.allow_unauthenticated_caller = true` on the Hopae
side.

Path-scoped protection uses two routes on one host: a public route for the
host and a higher-priority protected route for the prefix.

```json
[
  {"id": "site-public", "access_mode": "public", "host": "app.example.test",
   "path_prefix": "/", "priority": 0, "backends": ["http://127.0.0.1:3000"]},
  {"id": "site-admin", "access_mode": "protected", "host": "app.example.test",
   "path_prefix": "/admin", "path_match": "segment_prefix", "priority": 10,
   "backends": ["http://127.0.0.1:3000"],
   "auth": {"url": "http://127.0.0.1:8701/_hopae/verify",
            "request_headers": ["cookie", "user-agent", "accept", "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site"],
            "response_headers": ["x-forwarded-user", "x-forwarded-email", "x-forwarded-preferred-username",
                                 "x-forwarded-groups", "x-hopae-session", "x-hopae-provider",
                                 "x-hopae-auth-time", "x-hopae-expires", "x-hopae-aal", "x-hopae-factors"],
            "static_request_headers": {"x-hopae-contract": "1",
                                       "x-hopae-gateway-key": {"env": "HANGANG_HOPAE_KEY"}},
            "timeout_ms": 500, "forward_response": true}}
]
```

Portal host (public route; Hopae authenticates its own pages):

```json
{"id": "hopae-portal", "access_mode": "public", "host": "auth.example.test",
 "path_prefix": "/", "backends": ["http://127.0.0.1:8700"]}
```

The identity header names must appear in at least one route's
`response_headers`: the gateway strips every such name from every incoming
request gateway-wide. The fragments above are validated against the gateway's
schema (`deny_unknown_fields`) in scenario 008.

## Behavior

### Verify endpoint

`GET /_hopae/verify` on the gateway listener. No body. The response decides
one request.

Request headers consumed, in the order Hopae evaluates them:

| Header | Source | Required | Use |
| --- | --- | --- | --- |
| `x-hopae-gateway-key` | Gateway (HC-3) | yes | Compared in constant time with the caller key **before any other header is read**; mismatch or absence → `403` (`caller_unauthorized`), no state touched, counted. Only `gateway.allow_unauthenticated_caller = true` (development) waives it. |
| `x-hopae-contract` | Gateway (HC-3) or absent | no | Contract major version the gateway speaks; `1` or absent means v1. A higher major is answered `400` (`contract_unsupported`). |
| `x-original-url` | Gateway | yes | Absolute URL of the client request (`proto://host[:port]/path?query`). Return target, handoff parameter. ≤ 2048 bytes, scheme `https` (or `http` only when `cookie.secure=false`), no userinfo, no fragment. Its authority is client-selected on host-neutral routes and is therefore checked against the return-origin allowlist. |
| `x-hangang-canonical-path` | Gateway (HC-6) | no | The decoded, normalized path the gateway used for route selection. Without it Hopae computes the canonical path with the gateway's rules ([ADR-0013](adr/0013-gateway-adapter-boundary.md)); when both exist and differ the request is denied (`canonical_path_mismatch`). Every path rule matches the canonical path, never the raw one. |
| `x-hangang-route-id` | Gateway (HC-6) | no | Selected route id; logged and used as the application hint. |
| `x-forwarded-host` | Gateway | yes | Application host; must equal the host of `x-original-url`. |
| `x-forwarded-proto` | Gateway | yes | `https` required to plant `__Host-` cookies. |
| `x-forwarded-for` or `x-real-ip` | Gateway (trusted-proxy resolved) | yes | Client IP for binding, throttling and events. Hangang sets both to the single resolved client IP. |
| `x-original-method` | Gateway | no | Logged; method-dependent rules are later work. |
| `cookie` | Client (listed) | no | The Hopae cookies only (`__Host-hopae`, `__Host-hopae_bind`); other cookies are ignored. ≤ 8 KiB total. |
| `user-agent` | Client (listed) | no | UA binding (`sha256`), events. ≤ 1 KiB, truncated for storage. |
| `sec-fetch-dest`, `sec-fetch-mode`, `sec-fetch-site`, `accept` | Client (listed) | no | Decides `302` versus `401` for unauthenticated requests. |

A missing required header is a contract violation: `400` with
`x-hopae-reason: contract_violation`; Hangang maps it to `503`
(fail closed). Any client-supplied `x-forwarded-*`/`x-original-*` is
already replaced by the gateway; Hopae additionally rejects a request on the
gateway listener whose `x-forwarded-host` and `x-original-url` host differ.

Response codes:

| Status | Meaning | Headers | Gateway behavior (Hangang) |
| --- | --- | --- | --- |
| `200` | Allowed | Identity headers; `cache-control: no-store` (or `private, max-age=N` when HC-1 applies); `x-hopae-reason: ok` | Injects listed headers into the upstream request. |
| `302` | Login, step-up or handoff redirect for a document navigation | `location` (portal URL or handoff target); `set-cookie` (plant the binding cookie or the handle, or clear them); `cache-control: no-store`; `x-hopae-reason` | Relayed to the client with `referrer-policy: no-referrer`; upstream not contacted. |
| `401` | Authentication required, non-document request | `content-type: application/json`, body `{"error":"login_required","login":"https://auth.example.test/login?txn=…"}`; `www-authenticate: Hopae realm="auth.example.test"`; `cache-control: no-store` | Relayed to the client. |
| `403` | Denied: caller key missing or wrong (`caller_unauthorized`), host outside the allowlist (`unknown_app`), blocked user or IP, application disabled, group rule, step-up impossible, **or rate limited** (`{"error":"rate_limited","retry_after":30}`) | JSON body with `error`; `x-hopae-reason` | Relayed to the client with its body. Rate limiting uses `403` because an unmodified gateway maps `429` to `503` and drops `retry-after`; with gateway change HC-8 Hopae answers `429` with `retry-after` instead (`gateway.rate_limit_status`). |
| `400` | Contract violation | `x-hopae-reason` | `503` to the client (fail closed). |
| `503` | Hopae cannot decide (store unavailable, overload, verify budget exceeded) | `retry-after`; `x-hopae-reason` | `503` to the client (fail closed). |

`x-hopae-reason` is a diagnostic header for the gateway's logs; it is not in
`response_headers` and never reaches the upstream or the client.

Decision order inside Hopae: caller key → contract checks → canonical path
→ handoff parameter (may plant a new handle; requires the binding cookie)
→ cookie handle → session lookup → handle and session timers → binding
policy → user status and `authz_version` → application policy (enabled,
blocks, groups) → step-up rule → identity headers. All of it runs inside
the verify budget (`gateway.verify_budget_ms`, default 400 ms); exhaustion
answers `503`.

### Identity headers

Emitted on `200` only. Values are visible ASCII; non-ASCII characters are
percent-encoded as UTF-8 (RFC 3986 unreserved set kept). Headers without a
value are omitted rather than sent empty.

| Header | Value | Limit |
| --- | --- | --- |
| `x-forwarded-user` | Hopae user id, stable for the user's lifetime (`u_` + 26 base32 chars) | 64 B |
| `x-forwarded-email` | Primary email; omitted when none | 254 B |
| `x-forwarded-preferred-username` | Username or display name | 256 B |
| `x-forwarded-groups` | Comma-separated group names (M2); omitted when none | 4 KiB |
| `x-hopae-session` | Session id (`s_` + 26 chars), not the cookie handle | 64 B |
| `x-hopae-provider` | Provider id of the first factor (`google`) | 64 B |
| `x-hopae-auth-time` | Unix seconds of the first-factor authentication | 20 B |
| `x-hopae-expires` | Unix seconds of the earlier of idle and absolute expiry | 20 B |
| `x-hopae-aal` | `1` or `2`: the level the presented handle was issued at ([ADR-0008](adr/0008-second-factor-extension-point.md)); elevation reissues handles | 1 B |
| `x-hopae-factors` | Comma list of satisfied factors `kind[:provider]`, e.g. `oidc:google,totp` | 256 B |

Total identity header bytes ≤ 8 KiB (the gateway rejects more than 16 KiB).
The set is the whole of contract v1; adding a header is a minor change,
renaming or removing one is a major change.

### Cookies

| Cookie | Host | Attributes | Content |
| --- | --- | --- | --- |
| `__Host-hopae` | Each application host and the portal host | `Path=/; Secure; HttpOnly; SameSite=Lax`; no `Domain`; `Max-Age` equals the handle's remaining absolute lifetime | `v1.` + base64url of 32 random bytes: a handle bound to one session, one host and one issued level |
| `__Host-hopae_bind` | The application host, planted by the unauthenticated `302` that starts a login or a step-up | `Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=600` | base64url of 16 random bytes: the browser secret a handoff code is bound to; cleared by the redemption response |
| `__Host-hopae_txn` | Portal host | `Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=600` | Login transaction id; cleared on completion |

Clearing uses the same name and attributes with `Max-Age=0`. `SameSite` is
always `Lax`: the portal → application redirect is a cross-site top-level
navigation, so `Strict` would break single sign-on and the callback; there is
no configuration key for it. With `cookie.secure=false` (development only)
the `__Host-` prefix is dropped and `Secure` is omitted; preflight prints a
warning and the threat model entry TM-02 applies.

### Cross-domain handoff

After login (or when the portal already has a valid session), Hopae redirects
the browser to the stored return target with one extra query parameter:

```text
https://app.example.test/admin/x?_hopae_handoff=<code>
```

The gateway's forward-auth call for that request carries the parameter in
`x-original-url` and the host's cookies. Hopae consumes the code only when
all of the following hold: single use and within 60 s; host and path match;
the client IP matches; the request carries `__Host-hopae_bind` whose SHA-256
equals the digest stored with the code (the cookie was planted on this host
by the `302` that started this login, so only that browser holds it); and
the request carries no valid `__Host-hopae` of a **different** user (a valid
handle of the same user is replaced, which is how elevation reissues
handles). It then answers `302` to the same URL without the parameter,
plants `__Host-hopae` for that host and clears `__Host-hopae_bind`. The
upstream never sees the parameter: the `302` is relayed by the gateway
without contacting the upstream, and any decision cache is bypassed for
requests carrying the parameter. Any failure burns the code, answers the
unauthenticated `302` to the portal (which plants a fresh binding cookie)
and emits `handoff.rejected` with the reason (`code_consumed`,
`code_expired`, `code_host_mismatch`, `code_path_mismatch`, `bind_mismatch`,
`session_conflict`).

The parameter name `_hopae_handoff` is reserved; an application that uses
the same name is not supported.

### Portal entry points

All on the portal host, served by the portal listener.

| Method and path | Purpose | Protection |
| --- | --- | --- |
| `GET /login?txn=<id>` | Provider chooser; immediate redirect when one provider is enabled | `txn` must exist, be unexpired and match the client IP policy; sets `__Host-hopae_txn` |
| `POST /login/<provider>` | Start the provider flow | CSRF token bound to the `txn` cookie; `Origin` must be the portal origin |
| `GET /callback/<provider>` | Provider redirect URI | `state` ↔ `txn` cookie ↔ provider; PKCE; nonce; issuer |
| `GET /logout` | Confirmation page | Shows the form only; no state change |
| `POST /logout` | Terminate this session (`scope=this`, default) or every session of the user (`scope=all`, M2) | CSRF token; `Origin` check; requires a valid portal handle |
| `GET /stepup?txn=<id>` (M5) | Second-factor challenge | As `/login` |
| `GET /healthz` | Liveness (`200` when the process serves; store status in the body) | None; no secrets |
| `GET /_hopae/verify` | Not served here | `404` |

The portal never accepts a return URL from the client. The return target
comes from `x-original-url` of the verify call that created the transaction.
On the portal listener every `x-original-*` header is browser input and is
never consulted: the gateway regenerates `x-forwarded-*` on proxied requests
but passes `x-original-*` through unchanged on routes without external
authorization.

### Cache semantics (HC-1)

Hopae decides cacheability; the gateway only honors it.

| Response | `cache-control` and `x-hopae-fresh-until` | Gateway with HC-1 |
| --- | --- | --- |
| `200`, decision independent of path and method for this application | `private, max-age=N` where `N = min(app.verify_cache_seconds, 30)`; `x-hopae-fresh-until` = `min(now + N, handle expiry, session expiry)` in unix milliseconds; default `N = 0`, which emits `no-store` and no deadline | Caches the identity headers keyed on **(gateway configuration generation, route id, resolved client IP, normalized external scheme and authority, SHA-256 of the listed and static request headers)**, tagged with `x-hopae-session` and `x-forwarded-user`, for `min(N, route decision_cache_ms, fresh-until − now)`; never when the response carries `set-cookie` |
| `200`, path- or method-dependent (step-up rule, path rule) | `no-store` | Never cached |
| Any request whose path or query contains `_hopae_handoff` | `no-store` | Neither looked up nor filled: the handoff must always reach Hopae |
| `302`, `401`, `403`, `400`, `503` | `no-store` | Never cached |

The zero-trust default is `N = 0` on both sides: every request reaches Hopae.
The operator opts into bounded staleness per application and per route. The
maximum time an allow can outlive a revocation is the **sum**
`decision_cache_ms + cache.local_ttl_ms + stale_if_error_ms`, each term
defaulting to `0`, and never past `x-hopae-fresh-until`; `hopae --check`
prints the bound when any term is non-zero. The invalidation channel (HC-2)
usually purges much earlier but is not the guarantee.

### Invalidation channel (HC-2)

Redis/Valkey pub/sub channel `hopae:<namespace>:invalidate`. Messages are
JSON, ≤ 512 bytes:

```json
{"v": 1, "kind": "session", "id": "s_01hz…", "gen": 7, "at": 1760000000}
{"v": 1, "kind": "user", "id": "u_01hz…", "gen": 3, "at": 1760000000}
{"v": 1, "kind": "all", "gen": 42, "at": 1760000000}
```

Hopae publishes on session termination and handle revocation, logout
everywhere, user disable or block, any `authz_version` change (group or role
removal), any policy or configuration change (`all`) and key rotation. `gen`
is the session's, user's or configuration's generation after the change; a
subscriber discards any cache fill whose read started before the generation
it last saw for that tag, so an in-flight old response cannot repopulate a
purged entry. Subscribers (other Hopae instances, the gateway with HC-2)
purge entries tagged with the id. Delivery is best effort; the freshness
deadline is the guarantee. A subscriber that loses its connection purges its
whole cache on reconnect.

### Versioning

| Change | Contract version | Notes |
| --- | --- | --- |
| Add an identity header, a reason code or an optional request header | Minor (`1.x`) | Gateways ignore unknown headers |
| Change a cookie name or attribute, rename or remove a header, change a status code's meaning, change the handoff parameter | Major (`2.0`) | Hopae answers `x-hopae-contract: 2`; a gateway configured for v1 is detected by HC-3's request header or by the operator's compatibility matrix |

Compatibility matrix (updated with each release):

| Hopae | Contract | Hangang 0.2.6 (unmodified) | Hangang with HC-3 |
| --- | --- | --- | --- |
| 0.1.x | 1.0 | Development only (`gateway.allow_unauthenticated_caller = true`); rate limiting surfaces as `403` | Production: caller key verified; all M1 scenarios |

## What works on an unmodified Hangang 0.2.6

Verified against the gateway source on 2026-10-09 (`src/proxy.rs`
`authorize`, `forward_auth_context`; `src/config.rs` `ExternalAuth`
validation and `authentication_identity_headers`).

| Need | Unmodified Hangang | Mechanism |
| --- | --- | --- |
| Verify on every request, fail closed on timeout or unexpected status | Yes | `GET auth.url`, `timeout_ms`, `503` for anything other than `2xx`/`3xx`/`401`/`403` |
| Login redirect with cookie planting | Yes | `forward_response: true` relays `3xx`/`401`/`403` with `location`, `set-cookie`, `www-authenticate`, `content-type`, `cache-control`; adds `referrer-policy: no-referrer` |
| Identity header injection and gateway-wide stripping | Yes | `response_headers` copied into the upstream request; the union of all declared names is removed from every incoming request before routing |
| Original URL, client IP, host, proto | Yes | Generated `x-original-url`, `x-original-uri`, `x-original-method`, `x-forwarded-{method,uri,proto,port,for,host}`, `x-real-ip`, `x-original-client-ip`; client copies replaced |
| Cross-domain handoff | Yes | Hopae intercepts the `_hopae_handoff` parameter through the verify call; `302` + `set-cookie` relayed, upstream not contacted |
| HTTP/2 split `cookie` fields | Yes | Joined per RFC 9113 before authorization |
| Path scoping | Yes, per route | `path_prefix`, `path_match`, `priority`; no excludes |
| Outer-layer login throttling | Partial | `settings.path_failure_bans` on the portal's `/login` and `/callback/*` by client IP; `settings.path_rate_limits` global budget |
| Session refresh cookies on `200` | Yes | Up to 16 `set-cookie` values relayed with `forward_response` |
| Browser binding cookie on the unauthenticated `302` | Yes | `set-cookie` on relayed `3xx` responses |
| Caller authentication of the verify endpoint | **No** | Static request headers cannot be configured; loopback admits any local process on a host-network gateway. HC-3 is therefore part of M1. |
| Canonical path on the verify call | No | Routes are selected on `resource_policy::canonical_path` (decoded once, traversal and encoded separators rejected) but `x-original-url` carries the raw path; Hopae canonicalizes with the same rules until HC-6 |
| `429` relay with `retry-after` | No | Only `3xx`/`401`/`403` are relayed; `429` becomes `503` and `retry-after` is dropped. Hopae answers rate limits as `403` with a `rate_limited` body until HC-8 |
| `x-original-*` stripped on routes without external authorization | No | `strip_forwarding_headers` removes `forwarded`, `x-real-ip` and `x-forwarded-*` only; Hopae's portal ignores `x-original-*` (HC-9 optional) |
| Decision caching | No | Every request calls Hopae (HC-1) |
| Push invalidation | Not needed without caching | HC-2 once HC-1 exists |
| Cookie filtering before the verify call | No | The whole `cookie` header is copied (HC-4) |
| Native login/logout entry points on application hosts | No | Lua has `header`, `method`, `path`, `select_backend`, `select_member`, `set_header`, `reject` only: no redirect, no response headers, no `set-cookie` (HC-5) |
| Field-scoped route writes for configuration ownership phase 2 | No | Only whole-route `PUT` with a revision; HC-7 is a prerequisite for phase 2 |

## Proposed gateway changes

Each change is small, independently shippable in a gateway worktree, and
has acceptance criteria. Recommended order: **HC-3 (required by M1)**, HC-6,
HC-8, HC-4, HC-1, HC-2, HC-9, HC-5, HC-7. Identifiers are stable; the order
is the recommendation.

| ID | Change | Gateway surface | Acceptance criteria |
| --- | --- | --- | --- |
| HC-3 (M1) | Static request headers on the external-auth call: `auth.static_request_headers: {"x-hopae-contract": "1", "x-hopae-gateway-key": {"env": "HANGANG_HOPAE_KEY"}}` | `ExternalAuth` (config validation, `authorize`) | Values are literal or environment references resolved at activation; names cannot collide with generated context or listed client headers; a client-supplied header of the same name is dropped; the env value never appears in config dumps, logs or the admin API; unit test for collision rejection; a gateway-layer test shows the header on the verify call; the Hopae scenarios 004-A8 and 013-A1 pass against the built gateway. |
| HC-6 | Canonical path context: generated headers `x-hangang-canonical-path` (the `canonical_path` result used for route selection, or absent when the route was selected on the raw path) and `x-hangang-route-id` on the external-auth call | `forward_auth_context` | Present exactly when the gateway used a canonical path; equals the value route selection used; client-supplied copies replaced; unit test with `/%61dmin/x`; the names are reserved like `x-original-*`. |
| HC-8 | Relay `429` from the external-auth service with `forward_response`, including `retry-after`, `content-type`, `cache-control` and a bounded body | `authorize` response handling | Only when `forward_response` is on; `retry-after` relayed only on `429`; still `503` for every other unexpected status; `path_failure_bans` can count `429`; test for relay and for the unchanged `503` mapping. |
| HC-4 | Cookie filtering: `auth.request_cookies: ["__Host-hopae", "__Host-hopae_bind"]` forwards only the named cookies in the `cookie` header to the auth service | `authorize` request construction | Only listed cookie names are sent; the upstream still receives all cookies; HTTP/2 split cookies are joined first; malformed cookie pairs are dropped, not forwarded; test covering ordering and absence. |
| HC-1 | Per-route decision micro-cache: `auth.decision_cache_ms` (default `0` = off, max `30000`); caches `2xx` only, keyed on **(configuration generation, route id, resolved client IP, normalized external scheme and authority, SHA-256 of the listed and static request headers)**, honoring `cache-control: max-age` and `x-hopae-fresh-until` as upper bounds and `no-store` as a veto; neither lookup nor fill when the request path or query contains `_hopae_handoff`; entries tagged with `x-hopae-session` and `x-forwarded-user` and stamped with the generation of the last invalidation seen for those tags; bounded entry count per route; optional `stale_if_error_ms` (default `0`) | `authorize`, new cache module, metrics | Off by default; zero behavior change when off; `no-store` never cached; a hit replays identical identity headers and never replays refresh cookies; `set-cookie` responses never cached; handoff requests always reach the auth service (test); a request from another client IP or another authority never hits an entry (tests); entries expire by the smaller of TTL and `x-hopae-fresh-until`; a fill started before a later invalidation for its tag is discarded (test); memory bound enforced; metrics `auth_cache_hits`, `auth_cache_misses`, `auth_cache_evictions`, `auth_cache_stale_fills_rejected`; config activation drops the cache. |
| HC-2 | Invalidation subscriber: `auth.invalidation: {"redis_env": "HANGANG_HOPAE_REDIS_URL", "channel": "hopae:prod:invalidate"}` purging HC-1 entries by tag and recording the message's `gen` per tag | New subscriber task using the `security_redis` connection pattern | Subscribes with TLS rules identical to `security_redis`; a `session`/`user`/`all` message purges matching entries within 100 ms in a loopback test and raises the tag's generation; reconnect purges all entries; malformed messages are counted and ignored; the subscriber failing never affects request handling beyond losing early purges. |
| HC-9 | Strip `x-original-*` from client requests on every route, as `x-forwarded-*` already is | Ingress header handling | Client-supplied `x-original-*` never reaches an upstream or an auth service; generated values unaffected; test on a route without external authorization. |
| HC-5 | Native entry points on application hosts: `auth.entrypoints: {"login": "/_hopae/login", "logout": "/_hopae/logout"}` answered by the gateway with a `302` to the portal carrying the original URL as the return target through a verify call with `x-hopae-phase: login \| logout` | `authorize` call site | Optional; identical observable behavior to the Hopae-side implementation, including the binding cookie; the verify call for a logout entry point carries the cookie; no gateway-side state; tests for both entry points and for a path collision with an application route. |
| HC-7 | Field-scoped route writes: `PUT /v1/routes/http/<id>/auth` accepting only the `auth` block, and an API credential scope limited to that endpoint and to a list of route ids | Admin API, credential scopes | A scoped credential cannot call any other write endpoint or touch any other route or field (tests); revision CAS applies; audit records the scope; prerequisite for configuration-ownership phase 2 ([ADR-0012](adr/0012-service-registration-and-gateway-config-ownership.md)). |

Changes that were considered and not proposed: a Lua `redirect`/`set_cookie`
API (widens the sandbox's output surface for little gain over HC-5); auth
decision caching keyed on the full URL (defeats the purpose for SPAs);
negative-decision caching (delays login completion; revisit if unauthenticated
floods are observed).

## Verification

- Scenario 007 proves identity-header injection and client-copy stripping through a live gateway.
- Scenario 008 validates the route fragments above against the gateway's configuration schema, proves path scoping and exercises the percent-encoded prefix case (`/%61dmin/x`).
- Scenario 003 proves the handoff on two hosts of different registrable domains through the gateway, including the two-browser same-IP refusal.
- Scenario 004 proves the caller-key check and the verify budget under a stalled dependency.
- Each HC lands with its own gateway tests; Hopae adds a gateway-layer scenario per HC when the first Hopae release that uses it ships.
