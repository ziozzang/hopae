# Architecture

<!-- doc-rev: 3 -->

[Documentation](README.md) · [한국어](ko/ARCHITECTURE.md)

Hopae is a single-binary identity provider that answers a gateway's
forward-authentication check. This page describes the components, trust
boundaries, request flows, data model, storage, crate layout and failure
behavior that milestones M0 and M1 build. Decisions are recorded in the
[ADRs](adr/); the wire contract with the gateway lives in the
[gateway contract](GATEWAY_CONTRACT.md); threats and mitigations in the
[threat model](THREAT_MODEL.md). Sections marked *later* describe the shape
later milestones fill in; the data model is designed for them now so that
nothing is retrofitted.

## Prerequisites and configuration

| Item | M1 requirement |
| --- | --- |
| Gateway | Hangang with an external-authorization route (`auth`) whose `forward_response` is `true` and whose static request headers carry the caller key (gateway change HC-3, implemented together with M1); see the [gateway contract](GATEWAY_CONTRACT.md) for the exact route fragment |
| Caller key | A random secret shared by the gateway route and Hopae, referenced by `gateway.caller_key_env`; every verify call must present it in `x-hopae-gateway-key` |
| Portal host | A dedicated host name for the login portal (`auth.example.test` in examples), served as a public route on the same gateway |
| Transport | HTTPS between browser and gateway; the gateway terminates TLS; Hopae's gateway listener is reachable only from the gateway's network namespace (host loopback in the reference deployment) and still requires the caller key |
| Primary store | SQLite file in a writable state directory (default); PostgreSQL for multi-instance deployments from M2 ([ADR-0002](adr/0002-primary-store-sqlite-with-postgres-for-shared-deployments.md)) |
| Redis/Valkey | Optional, from M2, for the invalidation channel and throttling counters only; it never holds session or decision state |
| Provider | One OIDC provider (Google in M1) with a client ID and a client secret read from the environment |

Hopae is configured by one file (`hopae.json` or `hopae.yaml`, reference in
`docs/CONFIG.md` from M1) plus environment variables for secrets. Every
configuration key is validated at start and by `hopae --check`; unknown keys
are rejected.

## Components

```text
                       ┌──────────────────────────── trust boundary: public internet ────────┐
   Browser ───HTTPS───▶│ Gateway (Hangang)                                                  │
                       │  route app.example.test  ──auth──▶ GET http://hopae:8701/_hopae/verify │
                       │  route other.example.org ──auth──▶ (same)                            │
                       │  route auth.example.test ──proxy─▶ http://hopae:8700/ (portal)       │
                       └────────────────────────────────────────────────────────────────────┘
                                   │ private network / loopback (trust boundary: gateway ↔ Hopae)
                       ┌───────────┴────────────────────────────────────────────────────────┐
                       │ Hopae process                                                      │
                       │  portal listener :8700   gateway listener :8701   mgmt listener (M4) │
                       │  ┌────────┐ ┌────────┐ ┌─────────┐ ┌────────┐ ┌───────┐ ┌───────┐  │
                       │  │ portal │ │ verify │ │ session │ │identity│ │policy │ │ event │  │
                       │  └────────┘ └────────┘ └─────────┘ └────────┘ └───────┘ └───────┘  │
                       │  ┌──────────┐ ┌──────────┐ ┌─────────┐ ┌────────┐ ┌──────┐ ┌─────┐ │
                       │  │ provider │ │ gateway  │ │ factor  │ │ store  │ │cache │ │ lua │ │
                       │  │ (oidc…)  │ │ adapter  │ │ (M5)    │ │sqlite/ │ │redis │ │(M5) │ │
                       │  └──────────┘ └──────────┘ └─────────┘ │postgres│ └──────┘ └─────┘ │
                       │                                        └────────┘                  │
                       └──────────┬───────────────────────────────┬─────────────────────────┘
                                  │ HTTPS (outbound only)         │ private network
                                  ▼                               ▼
                         Identity providers               SQLite file / PostgreSQL / Redis
                         (Google, Kakao, Naver, SMTP)
```

| Component | Responsibility | Milestone |
| --- | --- | --- |
| Portal | Login chooser, provider redirect, provider callback, step-up pages, logout confirmation, health. Served on the portal host only. | M1 |
| Verify | Answers the gateway's check: cookie handle → session → binding policy → application policy → step-up rule → identity headers. No provider calls on this path. | M1 |
| Gateway adapter | Maps the gateway's wire form (headers, status codes, cookies) to the core decision types and back. Hangang adapter in M1; generic forward-auth and OIDC-provider adapters are *later* ([ADR-0013](adr/0013-gateway-adapter-boundary.md)). | M1 |
| Session | Sessions, per-host handles, login transactions, handoff codes, lifetimes, revocation, logout everywhere. | M1 |
| Identity | Users, provider identities, linking policy, groups. | M1 (linking M3) |
| Policy | Applications (hosts), binding policy, lifetimes, step-up requirements, blocks (M2), path rules (M2). | M1 |
| Provider | `Provider` trait; generic OIDC client (PKCE, nonce, discovery, JWKS cache); Kakao, Naver, email magic link, password *later*. | M1 (others M3) |
| Event | Typed events committed with their state change, one delivery row per subscribed sink; sinks: structured log, webhooks *later*; at-least-once delivery with `event_id` deduplication. | M1 (webhooks M5) |
| Factor | `Factor` trait for second factors; TOTP, WebAuthn, recovery codes *later*; the session schema records satisfied factors from M1. | M5 (schema M1) |
| Store | `Directory`, `Sessions`, `Events` traits; SQLite backend (M1), PostgreSQL backend (M2); embedded migrations. | M1 |
| Cache | Opt-in bounded local cache of authoritative reads carrying generation provenance; Redis/Valkey for pub/sub invalidation and throttling counters only (never session state) *later*. | M2 |
| Lua | Sandboxed worker processes copied from the gateway's model *later*. | M5 |
| Management | Management API and console *later*; own listener. | M4 |
| Update | Signed self-update *later*. | M6 |

## Trust boundaries

| Boundary | What crosses it | What Hopae trusts | What Hopae never trusts |
| --- | --- | --- | --- |
| Browser ↔ gateway | HTTPS requests with cookies; redirects; provider round trips | Nothing. Every browser input is validated. | Any `x-forwarded-*`, `x-original-*`, identity header or handoff parameter supplied by a browser; the gateway strips or regenerates them ([contract](GATEWAY_CONTRACT.md#what-works-on-an-unmodified-hangang-026)). |
| Gateway ↔ Hopae gateway listener | The verify request with gateway-generated context headers, the listed client headers and the caller key | The gateway's generated context (`x-original-url`, `x-forwarded-for`, `x-forwarded-host`, `x-forwarded-proto`) **only after** `x-hopae-gateway-key` has matched `gateway.caller_key_env` in constant time; a request without the key touches no state. Network isolation is defense in depth, not the boundary: with a host-network gateway any local process can reach loopback. | The copied client headers (`cookie`, `user-agent`, `sec-fetch-*`): they are inputs to validate, never assertions. The authority in `x-original-url` is client-selected on host-neutral routes, so it is checked against the return-origin allowlist. |
| Gateway ↔ Hopae portal listener | Ordinary proxied requests on the portal host | `x-forwarded-for` and `x-forwarded-proto` only from configured `trusted_proxies` | Everything else is browser input, including every `x-original-*` header: the gateway regenerates `x-forwarded-*` but passes `x-original-*` through unchanged on routes without external authorization. |
| Hopae ↔ identity provider | Discovery, JWKS, token exchange, user info (outbound HTTPS only) | The provider's signed ID token after full validation; user-info fields per provider rules ([ADR-0010](adr/0010-provider-abstraction.md)) | Unsigned claims, email addresses without a verified flag, anything in the callback query other than `code` and `state`. |
| Hopae ↔ stores | SQL and Redis protocols on a private network | The primary store's content; every verify reads it | Redis: it carries invalidation messages and counters only and never holds session or decision state, so a stale Redis answer cannot widen access; the local cache serves an entry only while its authoritative-read deadline and generations are current. |
| Hopae ↔ Lua workers (M5) | Length-framed JSON over pipes | Nothing; outputs are validated as if they came from the network | Scripts; they have no network, no secrets and no filesystem. |
| Hopae ↔ management clients (M4) | Management API on its own listener | Administrator sessions created through the console with CSRF protection | Static tokens outside break-glass use. |

The gateway listener and the portal listener are separate TCP listeners with
disjoint routers: `GET /_hopae/verify` on the portal listener answers 404,
and the portal pages do not exist on the gateway listener. The gateway
listener must not be reachable from the public internet. Because the
reference gateway runs with host networking, the deployment template runs
Hopae in the same network namespace (`network_mode: host`) bound to
`127.0.0.1:8701`, or publishes the container port on the host loopback only
(`127.0.0.1:8701:8701`); a container-internal loopback bind would be
unreachable by the gateway. In every arrangement the caller key is required.

## Request flows

Conventions: `GW` is the gateway, `HP` is Hopae, `IdP` is the identity
provider. `txn` is a login transaction id, `code` a single-use handoff code,
`handle` the opaque cookie value for one host, `bind` the browser binding
cookie planted on an application host when a login starts. Every verify call
also carries `x-hopae-gateway-key`, omitted from the diagrams. Identity
headers are abbreviated as `[id-hdrs]`. Portal host `auth.example.test`;
application hosts `app.example.test` and `other.example.org` (a different
registrable domain).

### Flow 1 — First visit, unauthenticated

```text
 Browser                      GW                                 HP
   │ GET https://app.example.test/admin/x                         │
   ├────────────────────────────▶│ GET /_hopae/verify              │
   │                             │  cookie: (none)                 │
   │                             │  x-original-url: https://app.example.test/admin/x
   │                             │  x-forwarded-for: 203.0.113.9   │
   │                             │  sec-fetch-dest: document       │
   │                             ├────────────────────────────────▶│ no handle → create txn
   │                             │ 302 Location: https://auth.example.test/login?txn=T
   │                             │ Set-Cookie: __Host-hopae_bind=B (app host; kept if already present)
   │                             │ Cache-Control: no-store         │ (txn: target, host, ip, ua, H(B))
   │ 302 (relayed, forward_response)◀───────────────────────────────┤
   │◀────────────────────────────┤                                 │
```

A non-document request (`sec-fetch-dest` other than `document`, or
`accept` without `text/html`) receives `401` with a JSON body whose `login`
field is the application URL itself: opening it as a document navigation is
the bootstrap that plants the binding cookie and starts a transaction. The
`401` creates no transaction and sets no cookie; the gateway relays it
because `forward_response` is enabled.

### Flow 2 — Login at the portal

```text
 Browser                      GW                   HP (portal)                     IdP
   │ GET auth.example.test/login?txn=T                 │                              │
   ├───────────────────────────▶├─────────────────────▶│ txn valid, not expired        │
   │                            │                      │ Set-Cookie: __Host-hopae_portal=P (stable; txn stores H(P))
   │ 200 chooser (or 302 when one provider)            │ page lists enabled providers  │
   │◀───────────────────────────┴──────────────────────┤                              │
   │ POST /login/google  (csrf token, portal cookie P) │                              │
   ├───────────────────────────▶├─────────────────────▶│ state,nonce,pkce stored in txn│
   │ 302 IdP authorize?client_id&redirect_uri=https://auth.example.test/callback/google
   │        &state=S&nonce=N&code_challenge=C&scope=openid email profile             │
   │◀───────────────────────────┴──────────────────────┤                              │
   ├──────────────────────────────── authenticate, consent ───────────────────────────▶│
```

### Flow 3 — Provider callback

```text
 Browser                      GW                   HP (portal)                     IdP
   │ GET /callback/google?code=AC&state=S  (cookie: __Host-hopae_portal=P)           │
   ├───────────────────────────▶├─────────────────────▶│ state S → txn T; H(P) ok; provider ok
   │                            │                      ├─ POST token (code, verifier) ─▶│
   │                            │                      │◀─ id_token, access_token ──────┤
   │                            │                      │ validate iss/aud/exp/nonce/sig │
   │                            │                      │ identity → user (create/link)  │
   │                            │                      │ session created (factors, bind)│
   │                            │                      │ portal handle H0; handoff code │
   │                            │                      │ K (app.example.test, H(B), aal 1, gen g)
   │ 302 Location: https://app.example.test/admin/x?_hopae_handoff=K                  │
   │ Set-Cookie: __Host-hopae=H0 (portal host; portal binding cookie P kept)          │
   │◀───────────────────────────┴──────────────────────┤                              │
```

### Flow 4 — Cross-domain handoff

```text
 Browser                      GW                                 HP (verify)
   │ GET https://app.example.test/admin/x?_hopae_handoff=K  (cookie: __Host-hopae_bind=B)
   ├────────────────────────────▶│ GET /_hopae/verify (document; cookie; x-original-url with K)
   │                             ├────────────────────────────────▶│ K: single use, ≤60 s, bound to
   │                             │                                 │ host+path+ip+H(B); gen g current;
   │                             │                                 │ no other user's valid handle
   │                             │ 302 Location: https://app.example.test/admin/x
   │                             │ Set-Cookie: __Host-hopae=H1 (issued_aal = min(K.aal, session.aal) = 1); bind B kept
   │                             │ Cache-Control: no-store          │ handle H1 → session
   │◀────────────────────────────┤ (relayed; upstream not contacted)│
   │ GET /admin/x  (cookie: __Host-hopae=H1)                        │
   ├────────────────────────────▶│ → Flow 5                         │
```

The same flow serves a second application on `other.example.org`: its first
request yields Flow 1 (which plants that host's own binding cookie), the
portal finds a valid portal handle `H0`, skips the provider (single sign-on)
and immediately answers Flow 3's redirect with a new code for
`other.example.org` bound to that cookie. A code can therefore be redeemed
only by the browser that started the login on that host, and only by a
document navigation; another browser behind the same IP is refused, and a
browser already holding a different user's valid handle is sent to the
portal's `/switch` confirmation instead of being switched silently. A
consumed code presented again together with the handle it produced (a
prefetch redeemed it) answers the clean redirect without changing cookies.
The binding cookie is shared by every transaction of that browser on that
host, so concurrent tabs do not invalidate each other, and no response ever
clears it.

### Flow 5 — Steady-state verify

```text
 Browser                      GW                                 HP (verify)
   │ GET /admin/x  (cookie: __Host-hopae=H1)                        │
   ├────────────────────────────▶│ GET /_hopae/verify (cookie, x-original-url, x-forwarded-for, user-agent)
   │                             ├────────────────────────────────▶│ H1 → session S
   │                             │                                 │ handle+session timers ok
   │                             │                                 │ binding: ip/ua ok
   │                             │                                 │ user active, authz_version ok
   │                             │                                 │ app policy, step-up: ok
   │                             │ 200 [id-hdrs] Cache-Control: no-store (or max-age, HC-1)
   │                             │◀────────────────────────────────┤ last_seen (coalesced)
   │                             ├── upstream request + [id-hdrs] ──▶ application
   │◀────────────────────────────┤ (client copies of [id-hdrs] were stripped)
```

### Flow 6 — Logout (this browser)

```text
 Browser                      GW                   HP (portal)
   │ GET auth.example.test/logout  (cookie: __Host-hopae=H0)
   ├───────────────────────────▶├─────────────────────▶│ 200 confirmation form (csrf)
   │ POST /logout  (csrf, cookie H0)                   │
   ├───────────────────────────▶├─────────────────────▶│ session S → terminated(reason=logout)
   │                            │                      │ all handles of S invalid; event
   │ 200 "signed out" + Set-Cookie: __Host-hopae=; Max-Age=0 (portal host)
   │◀───────────────────────────┴──────────────────────┤ publish invalidate(S) (M2)
   │ GET app.example.test/admin/x (stale cookie H1)    │
   ├───────────────────────────▶│ verify: H1 unknown → 302 login + Set-Cookie clear (app host)
```

### Flow 7 — Logout everywhere (M2 surface, M1 semantics)

```text
   │ POST /logout  scope=all  (csrf, cookie H0)        │
   ├───────────────────────────▶├─────────────────────▶│ every session of user U → terminated(reason=logout_all)
   │                            │                      │ publish invalidate(user U)
   │ 200 "signed out everywhere"                       │ event per session
```

Administrator revocation (M2) uses the same termination path with
`reason=admin`.

### Flow 8 — Revocation by binding mismatch (client IP changed)

```text
 Browser (new IP 198.51.100.7)  GW                              HP (verify)
   │ GET /admin/x  (cookie: __Host-hopae=H1)                        │
   ├────────────────────────────▶│ verify: x-forwarded-for: 198.51.100.7
   │                             ├────────────────────────────────▶│ session.ip=203.0.113.9 ≠
   │                             │                                 │ app.binding.ip=strict
   │                             │                                 │ → terminate S (reason=binding_ip)
   │                             │ 302 login + Set-Cookie clear     │ event session.terminated
   │◀────────────────────────────┤                                 │ publish invalidate(S)
```

With `on_mismatch: drop_handle` only `H1` is invalidated and the portal
session survives; the next portal visit re-binds the new IP after the
provider is consulted again ([ADR-0007](adr/0007-context-binding-policy.md)).

### Flow 9 — Step-up second factor (M5 surface, M1 schema)

```text
 Browser                      GW                                 HP
   │ GET https://app.example.test/admin/x  (cookie H1, issued_aal=1)
   ├────────────────────────────▶│ verify ──────────────────────────▶│ rule: canonical path /admin needs aal 2
   │                             │ 302 Location: https://auth.example.test/stepup?txn=T2
   │◀────────────────────────────┤ (bind B kept if present, else planted); no-store
   │ GET /stepup?txn=T2 → TOTP challenge → POST /stepup/totp (csrf, portal cookie P, code)
   ├───────────────────────────▶├─────────────────────▶│ factor ok, one transaction: factors += totp@now; aal=2;
   │                            │                      │ cred_gen g→g+1; ALL handles revoked; ALL outstanding
   │                            │                      │ codes consumed; new portal handle
   │ 302 https://app.example.test/admin/x?_hopae_handoff=K2 (aal 2, gen g+1) + Set-Cookie (portal)
   │ GET …?_hopae_handoff=K2 (cookie bind=B; stale H1 is revoked, same session → replaced)
   ├────────────────────────────▶│ verify → 302 + Set-Cookie: __Host-hopae=H1' (issued_aal=2)
   │ GET /admin/x (H1') → verify → 200 [id-hdrs incl. x-hopae-aal: 2, x-hopae-factors: oidc:google,totp]
```

A copy of `H1` taken before the challenge stays at level 1 and is revoked by
the elevation, so it never inherits the second factor. A handoff code minted
before the challenge (for example through single sign-on with a stolen portal
handle) is consumed by the elevation; if its redemption commits first it
mints a level-1 handle that the elevation then revokes, because redemption
issues `min(code.issued_aal, session.aal)` and checks the generation.

## Data model

Identifiers are random, URL-safe and prefixed by kind (`u_`, `s_`, `a_`,
`p_`, `e_`). Bearer values (handles, handoff codes, transaction ids, magic
link tokens) are stored only as SHA-256 digests. Times are UTC seconds.
Columns marked *later* are present from M1 so that later milestones add rows,
not columns.

| Table | Key | Columns (summary) | Notes |
| --- | --- | --- | --- |
| `users` | `user_id` | `primary_email`, `email_verified`, `email_authoritative`, `display_name`, `username`, `status` (active, disabled), `authz_version`, `groups` (JSON array, *later*), `created_at`, `updated_at`, `last_login_at` | One row per person. `username` is unique when present. `authz_version` increments on every change to status, groups or roles; verify reads `status` and `authz_version` on every call. |
| `identities` | (`provider_id`, `subject`) | `user_id`, `email`, `email_verified`, `email_authoritative`, `name`, `picture`, `raw_claims` (JSON, bounded 8 KiB), `first_seen_at`, `last_seen_at` | Links a provider subject to a user ([ADR-0011](adr/0011-account-linking-policy.md)). Created only after the subject consistency check of [ADR-0010](adr/0010-provider-abstraction.md). |
| `providers` | `provider_id` | `kind` (oidc, oauth2, email_link, password), `display_name`, `enabled`, `managed_by` (file, api), `deleted_at`, `sort_order`, `config` (JSON: issuer, endpoints, scopes, quirks), `client_secret_env`, `allowed_email_domains`, `authoritative_domains`, `auto_link`, `trust_email`, `created_at`, `updated_at` | File entries are imported at start only for rows that are absent or `managed_by = file` and not deleted; a row changed or removed through the management API (M4) is a tombstone the file never overwrites, so a runtime disable or removal survives restarts. Secrets are referenced by environment variable name, never stored. |
| `apps` | `app_id` | `display_name`, `hosts` (JSON array of exact lower-case host names; no patterns), `ports` (JSON array, default `[443]`), `enabled`, `session_policy` (idle, absolute), `binding_policy` (ip, ua, on_mismatch), `step_up` (JSON rules, *later*), `allowed_groups` (*later*), `on_authz_change` (refresh, terminate), `gateway_ref` (informational route id), `created_at`, `updated_at` | Verify resolves the app from `x-forwarded-host`; the union of all `hosts` and `ports` is the return-origin allowlist and every entry is an exact credential destination the operator vouches for. A host that is not listed is denied; there is no "any host" and no suffix mode. The reserved app `default` carries policy defaults only. |
| `sessions` | `session_id` | `user_id`, `provider_id`, `auth_time`, `factors` (JSON array of `{kind, provider?, at}`), `aal` (1 or 2), `authz_version` (of the user at snapshot time), `cred_gen`, `bound_ip`, `bound_ua_sha256`, `bound_country` (*later*), `created_at`, `last_seen_at`, `absolute_expires_at`, `terminated_at`, `terminated_reason` | One row per browser login. Self-contained identity snapshot (`snapshot` JSON: email, name, username, groups) refreshed when `users.authz_version` moves. `cred_gen` increments in the same transaction as any handle revocation or elevation, which also consumes the session's outstanding handoff codes; it is reported in `x-hopae-gen` and in invalidation messages. |
| `session_handles` | `handle_sha256` | `session_id`, `host`, `issued_aal`, `created_at`, `last_seen_at`, `absolute_expires_at`, `revoked_at`, `revoked_reason` | One per (session, host). The cookie carries the handle; different hosts never share a handle. `issued_aal` is the level the handle grants; elevation revokes and reissues handles. Idle and absolute timers are per handle ([ADR-0007](adr/0007-context-binding-policy.md)). |
| `login_txns` | `txn_sha256` | `created_at`, `expires_at` (10 min), `app_id`, `return_target` (absolute URL from the gateway, an exact entry of the return-origin allowlist), `bind_sha256` (digest of the browser's stable binding cookie on the application host), `portal_bind_sha256` (digest of the browser's stable portal binding cookie, set at first portal visit), `client_ip`, `ua_sha256`, `provider_id`, `state_sha256` (the callback locates the transaction by it), `nonce`, `pkce_verifier`, `portal_session_id` (when SSO), `purpose` (login, stepup, link, switch), `conflicting_handle_sha256` (for `switch`), `pending_identity` (JSON, for `link_required`), `consumed_at` | Server-side state for one login attempt; several may be open per browser. |
| `handoff_codes` | `code_sha256` | `session_id`, `host`, `return_target`, `client_ip`, `bind_sha256`, `issued_aal`, `cred_gen`, `created_at`, `expires_at` (60 s), `consumed_at`, `consumed_reason` | Single use; consumption is an atomic conditional update that also checks the binding cookie, the session's current `cred_gen` and the absence of another user's valid handle; the handle it mints gets `min(issued_aal, session.aal)`. |
| `events` | `event_id` | `at`, `kind`, `outcome`, `reason`, `user_id`, `session_id`, `app_id`, `provider_id`, `client_ip`, `ua_sha256`, `request_id`, `attrs` (JSON, bounded) | Append-only login history and audit source ([ADR-0009](adr/0009-event-model.md)). Required kinds and their delivery rows are written in the same transaction as the state change (transactional outbox); retention pruned by age and count regardless of delivery state. |
| `event_deliveries` | (`sink`, `event_id`) | `state` (pending, delivered, failed), `attempts`, `next_attempt_at`, `last_error`, `updated_at` | One row per subscribed sink per required event, inserted in the event's transaction and claimed by delivery workers; at-least-once delivery, bounded backlog per sink with dead-lettering. |
| `blocks` (*M2*) | `block_id` | `kind` (user, email, email_domain, ip_cidr), `value`, `reason`, `created_by`, `created_at`, `expires_at` | Checked at login and at verify. |
| `attempts` (*M2*) | (`scope`, `key`) | `failures`, `window_started_at`, `locked_until` | Per-account and per-IP throttling counters; in Redis when configured. |
| `factors` (*M5*) | `factor_id` | `user_id`, `kind` (totp, webauthn, recovery), `label`, `secret_env_or_encrypted`, `public_key`, `counter`, `created_at`, `last_used_at`, `disabled_at` | Enrollments ([ADR-0008](adr/0008-second-factor-extension-point.md)). |
| `webhooks` (*M5*) | `webhook_id` | `url`, `event_kinds`, `secret_env`, `enabled`, `created_at`, `last_delivery_at`, `last_status` | Destinations; deliveries are events with `kind=webhook.delivery`. |
| `admins` (*M4*) | `admin_id` | `username`, `password_hash` (Argon2id), `role`, `status`, `created_at` | Management accounts, separate from `users`. |
| `meta` | `key` | `value` | Schema version, instance id, key ids. |

Indexes: `identities(user_id)`, `identities(email)` (for linking),
`sessions(user_id, terminated_at)`, `session_handles(session_id)`,
`events(at)`, `events(user_id, at)`, `events(client_ip, at)`,
`event_deliveries(sink, state, next_attempt_at)`,
`handoff_codes(session_id, consumed_at)`, `handoff_codes(expires_at)`,
`login_txns(state_sha256)`, `login_txns(expires_at)`.

Relations: a user has many identities and many sessions; a session has one
handle per host and a snapshot of the user at login; an application has a
policy; events reference everything by id and survive deletions.

## Storage

[ADR-0002](adr/0002-primary-store-sqlite-with-postgres-for-shared-deployments.md)
records the decision; the summary:

| Concern | SQLite (rusqlite, bundled) | PostgreSQL (tokio-postgres) | Redis/Valkey |
| --- | --- | --- | --- |
| Role | Primary store, default, single instance | Primary store for active-active deployments (M2) | Pub/sub invalidation channel and throttling counters (M2) only; never holds session or decision state and is never a source of truth |
| Durability | WAL, `synchronous=NORMAL`, one writer task; required audit events and their delivery rows committed in the same transaction as the state change; backup by file copy of a checkpointed database (M7) | Managed by the operator; same transactional rule | Loss of Redis loses in-flight counters and early purges; nothing a verify depends on |
| Verify latency and budget | Tens of microseconds per lookup on loopback; the verify budget is 400 ms in total (`gateway.verify_budget_ms`) | Sub-millisecond on a private network; optional local cache of authoritative reads in front | A verify never waits on Redis; counter and publish operations elsewhere are capped at 50 ms (`cache.op_timeout_ms`), three consecutive timeouts open a 5 s breaker, and a timed-out counter fails closed for the login attempt it guards |
| Why | Matches the gateway's proven embedded choice; zero operational dependency for the common single-gateway deployment; schema migrations embedded | Multi-instance needs one shared directory: user ids, identities and blocks must agree between instances; SQLite cannot be shared safely over a network | The gateway's `security_redis` pattern (connection manager, 900 ms timeouts, fail closed on counters) is reused |

All three sit behind the same traits (`Directory`, `Sessions`, `Events`),
so a deployment chooses with one key: `store.kind = sqlite | postgres`.

## Crate layout

One crate, `hopae`, with a library and one binary. The HTTP layer is axum 0.8
on hyper 1, tokio and rustls, the same runtime family the gateway uses;
[ADR-0003](adr/0003-http-stack-axum-on-hyper.md) weighs axum against plain
hyper.

```text
src/
  main.rs            CLI: run, --check, hash-password, gateway render (M2), update (M6)
  lib.rs             re-exports for integration tests
  config/            schema (serde, deny_unknown_fields), load, env references, validate
  app.rs             wiring: stores, caches, listeners, graceful shutdown
  http/              routers per listener; middleware: request id, security headers, body and header limits
  portal/            login, callback, logout, step-up (M5) handlers; askama templates; csrf
  verify/            decision engine (pure functions over VerifyInput → Decision)
  gateway/           Adapter trait; hangang/ (contract v1); generic forward-auth (later)
  session/           sessions, handles, transactions, handoff codes, lifetimes, termination
  identity/          users, identities, linking policy, snapshot
  policy/            apps, binding, step-up rules, blocks (M2), path rules (M2)
  provider/          Provider trait; oidc/ (discovery, jwks, token, idtoken); kakao/ naver/ email/ password/ (M3)
  factor/            Factor trait; totp/ webauthn/ recovery/ (M5)
  event/             Event, EventKind, bus (broadcast), sinks: log, store; webhook/ (M5)
  store/             traits; sqlite/ (M1); postgres/ (M2); migrations/
  cache/             local bounded cache; redis/ (M2): write-through, pub/sub
  crypto/            ids, digests, constant-time compare, key material from env
  lua/               worker protocol and sandbox (M5), vendored from the gateway's model
  update/            signed updater (M6), vendored from the gateway
  telemetry/         tracing setup, metrics (M7)
tests/
  support/           spawn-and-probe harness, mock_idp (OIDC with misbehavior profiles)
  scenarios/         sNNN_*.rs, one file per scenario
```

Dependency policy: crates already in the gateway's tree are preferred
(`hyper`, `hyper-util`, `tokio`, `rustls`, `tokio-rustls`, `reqwest` with
rustls, `redis`, `rusqlite`, `tokio-postgres`, `jsonwebtoken`, `argon2`,
`sha2`, `subtle`, `base64`, `serde`, `clap`, `tracing`, `arc-swap`,
`semver`, `ed25519-dalek`, `tempfile`). New dependencies for M1: `axum`,
`tower`, `askama`, `cookie`, `url`. Each new dependency is justified in the
commit that adds it.

## Behavior under failure

| Condition | Verify (`/_hopae/verify`) | Portal | What the operator sees |
| --- | --- | --- | --- |
| Hopae process down or unreachable | The gateway times out (`auth.timeout_ms`, 500 ms recommended) and answers `503` to the client: fail closed. With the proposed micro-cache (HC-1) cached positive decisions continue until their TTL; no new logins. | Unavailable | Gateway `503` counters; Hopae health check failing. Mitigation: two instances behind a gateway hairpin route (M7) and the micro-cache TTL as a bounded buffer. |
| Primary store unavailable | `503` with `reason=store_unavailable`; never allow | `503` | Log at error, metric `hopae_store_errors_total`; the gateway relays `503`. |
| Redis unavailable or stalled (M2) | Unaffected: verify never reads Redis; the local cache is disabled while the pub/sub connection is down, so every verify reads the primary store | Login attempts whose throttling counter times out (50 ms) are refused (fail closed); after three timeouts the breaker refuses them for 5 s | Warning log, metric `hopae_cache_degraded`; invalidation messages are not published, so the gateway micro-cache relies on its absolute freshness deadline (bounded staleness). |
| Gateway without the caller key (misconfigured route, unmodified gateway in production) | `403 caller_unauthorized` on every verify, which the gateway relays; no state is read or written | n/a | `hopae --check` shows the expected static header; metric `hopae_verify_unauthorized_total`. |
| Identity provider unreachable or slow | Unaffected (verify never calls providers) | Login attempt fails with `reason=provider_unavailable`; retry page; transaction kept until expiry | Event `login.failed`; metric per provider. Discovery and JWKS caches have a hard deadline; expired keys reject tokens rather than skipping signature checks. |
| Clock skew beyond leeway (60 s) | Sessions appear expired or future-dated: deny | ID token validation fails (`iat`/`exp`) | `reason=clock_skew`; preflight warns when the system clock is unsynchronized. |
| Gateway sends an unexpected contract (missing `x-original-url`, unknown contract version) | `400` for the verify call, which the gateway maps to `503`: fail closed | n/a | `reason=contract_violation` with the missing field name; never a secret. |
| Lua worker saturation (M5) | Hook result unavailable → deny the decision that needed it | Login step that needed the hook fails | Same as the gateway: saturation fails closed. |

Operator-visible effects common to all failures: a reason code in the log,
a counter per reason, and no secret in any message.

## Limitations and compatibility

- One gateway family is supported in M1 (Hangang through the versioned contract, including gateway change HC-3 for the caller key). Other forward-auth gateways share the core but need their adapter and their own verification run.
- A login must be started and finished in the same browser on the same application host (binding cookie); browsers that block cookies on the application host cannot sign in.
- Every protected host is registered by its exact name; wildcard or suffix hosts cannot receive a session. Clients that cannot perform a document navigation cannot obtain a session until the API-client mode (M7).
- Cookies are host-only. A cookie shared across sibling subdomains (`Domain=`) is deliberately not offered in M1 because of cookie tossing; the handoff covers that case ([ADR-0004](adr/0004-session-model-and-cross-domain-handoff.md)).
- Verify is called on every request. Until the gateway micro-cache (HC-1) exists, Hopae's per-request budget is the whole budget: no provider calls, no unbounded queries, and a bounded local cache.
- Multi-instance deployments require PostgreSQL (M2) and Redis for invalidation; SQLite deployments are single-instance with fast restart.

## Related pages

- [Gateway contract](GATEWAY_CONTRACT.md) — the wire protocol, route fragments, proposed gateway changes
- [Threat model](THREAT_MODEL.md) — assets, actors, STRIDE per flow, mitigations
- [Roadmap](ROADMAP.md) — milestones and the M1 scenario list
- [ADR index](adr/) — ADR-0002 to ADR-0013
