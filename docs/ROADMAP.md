# Roadmap

<!-- doc-rev: 15 -->

[Documentation](README.md) · [한국어](ko/ROADMAP.md)

This page orders the work. It derives from the project brief and from a survey
of the gateway's existing capabilities, and it is updated whenever a milestone's
scope or order changes. Completed items move to the [CHANGELOG](../CHANGELOG.md).
Scenario ranges are defined in [`scenarios/README.md`](../scenarios/README.md).
The design the milestones implement is in the [architecture](ARCHITECTURE.md),
the [gateway contract](GATEWAY_CONTRACT.md), the [threat model](THREAT_MODEL.md)
and ADR-0002 to ADR-0016.

## Shape of the product

Hopae is packaged **around** the Hangang gateway rather than in front of it.
The gateway already performs external authentication checks, injects verified
identity headers into upstream requests and strips client-supplied copies;
Hopae supplies what the gateway lacks: the login portal, the providers, the
sessions and the policy.

```text
 Browser                Hangang (gateway)                    Hopae                      Provider
   │  GET app.example.test/admin  │                              │                          │
   ├─────────────────────────────▶│  forward-auth GET /_hopae/verify                        │
   │                              ├─────────────────────────────▶│ no session               │
   │  302 auth.example.test/login │◀─────────────────────────────┤ 302 + transaction        │
   │◀─────────────────────────────┤                              │                          │
   │  GET auth.example.test/login (a route on the same gateway)  │                          │
   ├─────────────────────────────▶├─────────────────────────────▶│ 302 to provider          │
   │◀─────────────────────────────┴──────────────────────────────┤                          │
   ├──────────────────────────────── authorize, consent ────────────────────────────────────▶│
   │◀─────────────────────────────── 302 /callback?code ────────────────────────────────────┤
   ├─────────────────────────────▶├─────────────────────────────▶│ code → tokens, session   │
   │  302 app.example.test/admin?_hopae_handoff=K                │ Set-Cookie (portal host) │
   │◀─────────────────────────────┴──────────────────────────────┤                          │
   ├─────────────────────────────▶│  forward-auth GET /_hopae/verify (handoff)              │
   │  302 app.example.test/admin + Set-Cookie (app host)         │ code consumed, handle    │
   │◀─────────────────────────────┤◀─────────────────────────────┤                          │
   ├─────────────────────────────▶│  forward-auth GET /_hopae/verify                        │
   │                              ├─────────────────────────────▶│ session ok               │
   │                              │  200 + identity headers      │                          │
   │                              │◀─────────────────────────────┤                          │
   │                              ├── upstream request with x-forwarded-user, … ──▶ app    │
   │                              │   (client copies of those headers stripped)              │
```

Facts the roadmap depends on, observed in the gateway on 2026-10-09 and
re-confirmed at the M0/M1 design gate on the same date against the gateway
source (`src/proxy.rs`, `src/config.rs`):

- The gateway's external check is a `GET` to a fixed URL with no body; only listed client headers (the session cookie among them) are forwarded, plus gateway-generated context headers such as the original URL, method and client IP; HTTP/2 split `cookie` fields are joined first.
- A `2xx` answer allows the request and the listed response headers are injected upstream; a `302`/`401`/`403` answer can be relayed to the browser with `Location` and `Set-Cookie` when `forward_response` is on; anything else, including a timeout, fails closed.
- Identity header names declared in any route's response list are stripped from every incoming request gateway-wide.
- The gateway does not cache authentication decisions: the verify endpoint is called on every request and must be fast; revocation works because of this. A micro-cache is a proposed gateway change (HC-1), off by default.
- Path scoping is per route (`path_prefix`, match mode, priority); finer rules live in Hopae using the original URL header.
- Login throttling, blacklists and login history are not gateway features; the gateway's per-URL failure bans can be an outer layer.
- The gateway's Lua policy API cannot set response headers, cookies or redirects; login and logout entry points on application hosts therefore live in Hopae (or in a native gateway change, HC-5).
- The gateway cannot add static headers to the external check, so the verify endpoint has no caller authentication beyond network reach; on a host-network gateway loopback admits any local process. Gateway change HC-3 is therefore implemented together with M1.
- Routes are selected on a canonical (decoded, normalized) path while the external check receives the raw path; a `429` from the external check becomes `503`; `x-original-*` headers pass through unchanged on routes without the external check.

## Milestones

Each milestone ends with every scenario in its range `verified-live` (or
`implemented` with a recorded reason), documentation in both languages, a
threat-model update, a CHANGELOG section and a deployment per G9. Versions are
indicative.

### M0 — Foundation (0.0.x)

Goal: the process can run end to end on an empty crate.

- [ ] Cargo workspace, `Makefile` with the [named targets](PROCESS.md#make-targets), pre-commit hook (secret scan, publication check), CI running `make gates`.
- [ ] `tools/check_docs.py` and `tools/scenario_coverage.py` as specified in the [documentation system](DOCUMENTATION.md#validation); `make check-boundary` lint from ADR-0013.
- [ ] Mock OAuth/OIDC provider in `tests/support/mock_idp` with the misbehavior profiles listed in the process and in scenarios 002 and 012 (`oidc` and `oauth2` kinds).
- [ ] Spawn-and-probe integration harness for the Hopae binary; gateway layer behind `HOPAE_E2E_GATEWAY_BINARY`; echo upstream; cookie-jar client with `__Host-` and `SameSite` rules.
- [x] `docs/ARCHITECTURE.md`, `docs/GATEWAY_CONTRACT.md` and `docs/THREAT_MODEL.md` v0 drafted (G1).
- [ ] ADR-0002 to ADR-0013 accepted after adversarial design review (G2): storage, HTTP stack, session model and cross-domain handoff, gateway contract and versioning, verify caching and invalidation, context binding, second-factor extension point, event model, provider abstraction, account linking, service registration and gateway configuration ownership, adapter boundary.
- [x] `docs/CONFIG.md` listing the M0 keys and every key scheduled by the ADRs.

Exit: `make gates` green on the empty crate; one template scenario runs against the harness; ADRs accepted.

### M1 — Vertical slice (0.1.0)

Goal: one real user signs in through the live gateway with one real provider,
and an upstream application receives verified identity headers. This milestone
is deliberately narrow and lands before any breadth.

Scope (scenarios 001–099):

- [ ] Generic OIDC authorization-code client with PKCE and nonce and the user-info subject consistency check; Google as the first configured provider (ADR-0010).
- [ ] Server-side sessions in the SQLite store; per-host opaque handles in `__Host-hopae` with per-handle timers and issued level; login transactions located by `state`; stable per-browser binding cookies on application hosts (`__Host-hopae_bind`) and on the portal (`__Host-hopae_portal`) with depth-bounded recovery from the first-use race; single-use cross-domain handoff codes carrying their issuance level and the session's credential generation; document-only redemption with the idempotent already-redeemed case and a relayed `403` for non-document requests carrying the parameter; the `/switch` account-switch confirmation; lifetime state machine (ADR-0002, ADR-0004, ADR-0007).
- [ ] Two listeners: gateway (`/_hopae/verify`, caller key required, current-plus-next key rotation) and portal (login, provider callback, switch, logout, health) (ADR-0005).
- [ ] Gateway change HC-3 (static request headers with the caller key) implemented in the gateway's repository and verified by scenarios 004-A8 and 013-A1 against the built gateway.
- [ ] `GET /_hopae/verify` per the contract: `200` with the identity header set plus `x-hopae-fresh-until` and `x-hopae-gen`; `302` with a return target that is an exact registered origin; `401` naming the application URL as the document bootstrap and creating nothing; `403` for denials and rate limits; `400`/`503` fail closed; `cache-control: no-store` everywhere (ADR-0006 default); 400 ms verify budget.
- [ ] Application registry (`apps[]`) with exact host names, ports, lifetimes and binding policy; client-IP binding with session termination on mismatch, configurable per application (ADR-0007); canonical path and the reserved parameter recognition rule in the decision input (ADR-0013).
- [ ] Account creation rules with explicit linking by default: an email collision refuses with a notice (ADR-0011); the completion flow is M3.
- [ ] Session schema records factors and `aal`; handles record `issued_aal`; verify emits `x-hopae-aal` and `x-hopae-factors`; users carry `authz_version` read at every verify (ADR-0008 schema only).
- [ ] Event model as a transactional outbox: required events and per-sink delivery rows committed with their state change, at-least-once delivery with `event_id` deduplication, bounded per-sink backlog with dead-lettering, delivery rows that die with their event, quantified prune cadence, structured log sink (ADR-0009).
- [ ] Header-injection contract: the identity header set, their declaration in the gateway route so client copies are stripped gateway-wide, and a gateway-layer test proving a spoofed header never reaches the upstream.
- [ ] Path-scoped protection via gateway routes (public prefix, protected prefix, higher-priority `/admin`) documented with a working route example; phase-0 manual registration (ADR-0012); Hopae-side per-path rules deferred to M2.
- [ ] JSON configuration file documented in `docs/CONFIG.md`, `hopae --check` preflight, structured logs with reason codes.
- [ ] `deploy/` Compose template placing Hopae behind the gateway; deployment to the reference environment.
- [ ] After the first live deployment (ADR-0015, Proposed): application-host entry points `/_hopae/login` and `/_hopae/logout` answered by Hopae inside the verify call with the reserved `/_hopae/` namespace, the logout ticket and `apps[].logout_confirm`; gateway change HC-12 (`auth.strip_request_cookies`) so the session handle no longer reaches the upstream; contract v1.1.

Scenarios (draft at G1, approved at G3):

| ID | Title |
| --- | --- |
| 001 | Unauthenticated request on a protected host is sent to the portal |
| 002 | Login with an OIDC provider creates a session |
| 003 | Cross-host handoff plants a host-only cookie on the application host |
| 004 | Verify returns identity headers for a valid session and fails closed otherwise |
| 005 | Return targets are validated and never taken from the client |
| 006 | Logout ends access on every host |
| 007 | Identity headers reach the upstream only from Hopae; client copies are stripped |
| 008 | Path-scoped protection through gateway routes |
| 009 | Cookie attributes and host scope |
| 010 | Session idle and absolute lifetimes |
| 011 | Client-IP binding terminates the session on mismatch |
| 012 | Provider failure modes |
| 013 | Configuration preflight and startup |
| 014 | Core flows emit events with the fixed schema |
| 015 | Application-host entry points never reach the upstream, and Hopae cookies are stripped from upstream requests |

Exit: a browser on a protected route of the live gateway completes login with
the real provider, the upstream sees the identity headers, a client-supplied
identity header is stripped, a verify call without the caller key is refused,
a second application on another registrable domain is reached without a
second provider login, a second browser behind the same IP cannot redeem the
first browser's handoff, and logout ends access on the next request.

### M4-min — Management console, minimum (0.2.0)

Pulled ahead of M2 at the maintainer's request after the first live
deployment: an administration page is needed before breadth. Designed in
[ADR-0016](adr/0016-management-console-minimum.md) (Proposed) and specified
on the [administration page](ADMIN.md); the rest of M4 stays in its place
below. Later versions shift by one minor accordingly.

Scope (scenarios 300–305 of the 300–399 range):

- [ ] Third listener `listen.admin` serving the console host, which is the implicit application `admin` registered by `admin.public_url` behind the gateway's protected route (standard `auth` block, no `strip_request_cookies`); every request authenticated by Hopae from the `__Host-hopae` handle through the verify engine with the gateway listener's denial observation; injected identity headers never read; peers outside `trusted_proxies` refused by default (`admin.untrusted_peers`).
- [ ] Administrators as granted users: table `admin_grants` (roles `admin`, `viewer` as read-only administrator; `managed_by`, `source_email`) in migration `0003`; `hopae admin grant|revoke|list|import` and `admin.users[]` seeded under the provider import rule with tombstones; a grant binds once to the resolved user id, the CLI prints the resolved user and requires `--confirm` for a non-authoritative email; grant read on every request; `admin.require_aal`.
- [ ] Console freshness (`admin.max_auth_age`) with one predicate at every console verify, the listener and the fence; providers declare a `reauth` capability (`max_age` for a generic OpenID provider, `unsupported` for the `google` preset): with `max_age` the login transaction carries `reauth_max_age`, the provider receives `max_age` and `prompt=login`, the ID token's `auth_time` is required and checked, and the session is reauthenticated through the elevation transaction; with `unsupported` the bound is honestly Hopae login age; every session records `auth_time_source`, an invalid claim fails the login (amends ADR-0010).
- [ ] Mutations fenced inside their write transaction (deadlines, host, user status, authorization baseline, freshness, level, grant); listings bounded to 10,000-row index windows in immutable order with cursors past the last candidate examined, interrupted at `admin.query_budget_ms`; the migration runner validates the recorded version's structures before applying `0003`.
- [ ] Users: list and search, detail with identities, sessions and recent events; disable (status, `authz_version`, every live session terminated) and enable.
- [ ] Sessions: live sessions with user, hosts, created, last seen, client address, user-agent prefix (`sessions.bound_ua_prefix`), level; terminate one; terminate every session of a user.
- [ ] Login history and audit: `events` browsing with filters (kind, outcome, user, session, client address, time range), keyset pagination, indexes `events(kind, at)`, `sessions(terminated_at, last_seen_at)`, `users(created_at)`.
- [ ] Status, read-only: applications, providers (enabled, `managed_by`, health, secret variable name and presence), store, build, configuration generation.
- [ ] Every mutation audited as an `admin.*` event in the same transaction, with the actor re-checked inside the write; `admin.denied` for every refusal.
- [ ] Server-rendered pages in English and Korean without scripts, the portal's CSP and security headers, CSRF tokens bound to the handle plus `Origin`; JSON `/v1` API with the custom-header and content-type rule.
- [ ] `hopae --check` prints the console route fragment; the deployment template gains the listener and the route example.

| ID | Title |
| --- | --- |
| 300 | Administrator access to the console: handle authentication, grants, roles, freshness, CSRF, direct connections |
| 301 | Console users: list, search, detail, disable and enable |
| 302 | Console sessions: list live sessions, terminate one, terminate all of a user |
| 303 | Console login history and audit browsing |
| 304 | Console status is read-only and shows no secret |
| 305 | Administrator grants from the command line: bootstrap, revoke, list, recovery |

Exit: through the live gateway, a granted user opens the console on its own
host, a user without a grant is refused, a disabled user's session is denied
on the next request on every host, a terminated session is denied, every
action has its `admin.*` record, and a request that bypasses the gateway with a
forged identity header is refused.

### Proposed next: second factor for administrators (TOTP)

Proposed after design review pass 2 of ADR-0016, not scheduled and not
implemented here: pull the TOTP factor of M5 forward as the milestone that
follows M4-min, limited to administrators. Reason: with the reference
provider, console freshness is Hopae login age (Google does not support
reauthentication requests), so a real step-up for the console needs Hopae's
own second factor. Shape, if accepted: the `Factor` trait and the TOTP factor
of [ADR-0008](adr/0008-second-factor-extension-point.md), enrollment from the
portal for granted users only, `admin.require_aal = 2` becoming usable, the
step-up rule of the implicit application enforced at verify, recovery codes,
and the administrator reset through `hopae admin`. The rest of M5 (WebAuthn,
Lua, webhooks) stays where it is. Decided by its own ADR.

### M2 — Sessions, abuse controls and shared state (0.3.0)

Scope (scenarios 100–199):

- [ ] Login history API over the `events` table: filters by user, IP, provider, outcome, time; bounded retention. The console view, the `/v1/events` query and the exact-address and time filters ship in M4-min; M2 adds the provider and CIDR filters and the retention controls.
- [ ] Blacklists: subject, email, email domain and client IP (CIDR); checked at login and at verify; administrator-managed.
- [ ] Login-attempt throttling and lockout per account and per client IP with synchronous atomic counters and constant-work responses; interaction with the gateway's failure bans documented.
- [ ] PostgreSQL backend for the primary store (ADR-0002) so two instances share one directory.
- [ ] Redis/Valkey for the generation-stamped invalidation channel and the throttling counters only (50 ms operations, breaker, counters fail closed); no session or decision state in Redis; opt-in bounded Hopae-local cache of authoritative reads with generation provenance (ADR-0006); `verify_cache_seconds`, `x-hopae-fresh-until` and `x-hopae-gen` per application; `authz_version` and `cred_gen` invalidation on group, status, revocation or elevation change; database epoch and `hopae store mark-restored` so a restore to lower generations is recovered by every cache (ADR-0006 decision 8).
- [ ] Logout everywhere for the user (`scope=all`); administrator revocation and the session listing per subject ship in M4-min.
- [ ] Hopae-side path and host policy rules evaluated from the original URL (allow, require login, require group); such rules mark the application's decisions `no-store`.
- [ ] Phase 1 of gateway configuration ownership (ADR-0012): `hopae gateway render` and the read-only drift report.

Exit: two Hopae instances on PostgreSQL behind the gateway share sessions and
invalidate each other's caches; lockout, blacklist and revocation are verified
live.

### M3 — Providers (0.3.0)

Scope (scenarios 200–299):

- [ ] Kakao (OIDC preset with the user-info verification quirk) and Naver (`oauth2` preset with the profile mapping and no verified flag), per ADR-0010; official documentation re-verified at G1.
- [ ] Email magic link: single-use, short-lived, bound to the requesting browser; SMTP configuration; rate limits.
- [ ] Email and password: Argon2id, dummy-hash timing for unknown accounts, reset flow, password policy.
- [ ] Provider enable/disable and ordering at run time; per-provider allowed email domains.
- [ ] Explicit account-linking flow and the conflict notice, per ADR-0011.

Exit: each provider verified live against a test tenant where one exists; email flows verified against a loopback SMTP sink and one real mailbox.

### M4 — Management console and API, remainder (0.5.0)

Scope (scenarios 306–399; the listener, grants, users, sessions, history,
audit and status are M4-min):

- [ ] Management API with OpenAPI: applications, providers (runtime add, disable, remove with `managed_by = api`, ADR-0010), policies, blacklists.
- [ ] Grants from the console (grant, revoke, role change, with their own abuse cases); API tokens for non-browser clients.
- [ ] Web console in English and Korean covering the whole API; no secrets displayed after creation; provider secrets by environment reference (encrypted-at-rest mode decided here if adopted).
- [ ] Audit of reads and export of the audit trail (backlog candidates, decided here).

Exit: every management operation reachable from the console and the API; audit records verified for each.

### M5 — Extension points (0.5.0)

Scope (scenarios 400–499):

- [ ] Lua hooks (400–439) in isolated worker processes following the gateway's model: claims mapping after authentication, additional authorization input, header mapping; explicit list of what Lua cannot do (no network, no secrets, no update control).
- [ ] Login-notification webhooks (440–469): events from ADR-0009 (login success, failure, new device, lockout, logout, revocation) delivered from the per-destination delivery rows, at-least-once with `event_id` as the idempotency key; HMAC-signed deliveries; bounded retries and backlog with dead-lettering; per-endpoint secrets from the environment; destination restrictions against internal address ranges by default.
- [ ] Second-factor mechanism (470–499) per ADR-0008: `Factor` trait (enroll, challenge, verify, recover, administrator reset); step-up rules per application evaluated at verify; TOTP first, WebAuthn second, recovery codes.
  - WebAuthn passkeys ([ADR-0017](adr/0017-webauthn-passkeys.md), scenarios 480–486, [design](WEBAUTHN.md)): first pass in source behind the default-off `webauthn` configuration — portal-only registration and step-up, security overview and passkey management, portal security confirmation, recovery codes (AAL 1, forced re-enrollment), last-factor rule, sign-count regression handling, administrator reset from the command line. AAL 3 is classified and recorded, not emitted. Phase 2: native Human owner provenance for passkey elevations (migration 12).
  - Phase 2 (in source): passwordless (discoverable) sign-in with conditional UI on the login page (scenario 487). Console factor management API (list, reset by scope; scenario 314) and AAL 3 requirements in step-up rules and `admin.require_aal` (scenario 489, ADR-0018 decisions 7–11) are in source. Deferred: Pumgye plans of `minimum_aal: 3` (needs Pumgye to evaluate 3); a passkey requirement for console operators short of AAL 3 (`admin.require_aal = 2` accepts any second factor).

Exit: a route requiring a second factor denies a first-factor-only session live; a webhook delivery is verified against a loopback receiver and one real endpoint.

### M6 — Lifecycle and releases (0.6.0)

Scope (scenarios 500–599):

- [ ] Signed self-update adopting the gateway's verified design: Ed25519 manifest envelope, GitHub release discovery, downgrade refusal, size and redirect bounds, atomic activation with rollback; `hopae update`, `hopae --check-update`, daily check cache with an opt-out; container deployments replace the image instead.
- [ ] Release pipeline: CI build matrix, static Linux binaries, release assets and `SHA256SUMS`, offline signing procedure, `release-public-key.txt`.
- [ ] Configuration reload semantics and preflight on reload.

Exit: an instance updates itself from a signed pre-release and rolls back a deliberately broken one.

### M7 — Scale-out and operations (0.7.0)

Scope (scenarios 600–699):

- [ ] Multi-instance operation documented end to end: what is shared, what is instance-local, required PostgreSQL and Redis/Valkey settings; high availability of verify through a gateway hairpin route over two instances.
- [ ] Prometheus metrics, health and readiness endpoints, structured audit export.
- [ ] Backup and restore of the SQLite store; key rotation for cookie and session keys, factor keys and webhook secrets.
- [ ] Phase 2 of gateway configuration ownership (ADR-0012), only by a new ADR and only after gateway change HC-7 (field-scoped route writes) exists.
- [ ] API-client mode (stretch): issue RFC 9068 access tokens with JWKS and discovery so the gateway's native JWT verifier can protect APIs with the same identities.

Exit: a rolling replacement of two instances keeps sessions; metrics and backups verified live.

### 1.0

After M7, a full adversarial review pass over the threat model, the gateway
contract and the configuration schema, with no open S1/S2 finding, produces
1.0.0. From 1.0, configuration and the gateway contract change only with a
major version.

## Gateway changes

Proposed changes to the gateway are listed with acceptance criteria in the
[gateway contract](GATEWAY_CONTRACT.md#proposed-gateway-changes). They are
separate tasks in the gateway's repository, done in a worktree. HC-3 (static
request headers carrying the caller key) is required by M1 and is built with
it; HC-12 (Hopae cookies stripped from the upstream request) follows
immediately, after the live finding that the session handle reached the
upstream (ADR-0015). Recommended order afterwards: HC-6 (canonical path and route id on the
verify call), HC-8 (`429` relay with `retry-after`), HC-4 (cookie
filtering), HC-1 (decision micro-cache with the full key), HC-2
(generation-stamped invalidation subscriber), HC-9 (strip `x-original-*`
gateway-wide), HC-5 (native entry points, optional), HC-7 (field-scoped
route writes, prerequisite for configuration-ownership phase 2). Hopae adds a
gateway-layer scenario for each change in the first release that relies on it
and records the pairing in the contract's compatibility matrix.

## Cross-cutting scenarios (900–999)

Allocated at any milestone: cookie attributes, CSRF on portal and console
forms, response security headers, constant-time comparisons, CSPRNG use, secret
handling in logs, and dependency audit policy. Each security-relevant change in
any milestone checks this range for an existing scenario before adding one.

## Backlog

Not scheduled; recorded so they are not re-discussed from scratch:

- OIDC provider mode for third-party applications; SAML.
- **P2 — SCIM provisioning of users and groups** (inbound SCIM 2.0 `/Users`
  and `/Groups`): refreshes provider memberships of people who no longer sign
  in, which today only the periodic LDAP sync does; until then such OIDC
  memberships are suspended after `groups.max_staleness_secs`
  ([groups](GROUPS.md), [ADR-0019](adr/0019-groups-and-membership-projection.md)).
- Generic forward-auth adapter profiles (nginx `auth_request`, Traefik, Caddy, Envoy `ext_authz`) behind the ADR-0013 boundary.
- Device authorization flow. (Passkey-first sign-in moved to the next WebAuthn pass of M5.)
- `Domain=` cookie mode for sibling subdomains (rejected in M1 because of cookie tossing).
- Suffix host patterns (`*.example.test`) for applications (rejected: a dangling subdomain becomes a credential destination).
- Redis as a positive session cache (rejected: a stale entry that still answers outlives every revocation bound).
- Negative-decision caching in the gateway micro-cache.
- Geographic and new-device risk signals feeding step-up; `max_auth_age` per application.
- Forwarding `sec-purpose` on the verify call so prefetch and prerender never count as a document navigation (relevant to `apps[].logout_confirm = false`); a contract minor that changes every route fragment.
- Encrypted-at-rest provider secrets entered from the console.
