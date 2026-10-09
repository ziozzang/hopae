# Roadmap

<!-- doc-rev: 2 -->

[Documentation](README.md) · [한국어](ko/ROADMAP.md)

This page orders the work. It derives from the project brief and from a survey
of the gateway's existing capabilities, and it is updated whenever a milestone's
scope or order changes. Completed items move to the [CHANGELOG](../CHANGELOG.md).
Scenario ranges are defined in [`scenarios/README.md`](../scenarios/README.md).
The design the milestones implement is in the [architecture](ARCHITECTURE.md),
the [gateway contract](GATEWAY_CONTRACT.md), the [threat model](THREAT_MODEL.md)
and ADR-0002 to ADR-0013.

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
- [ ] `docs/CONFIG.md` skeleton listing every key named in the ADRs.

Exit: `make gates` green on the empty crate; one template scenario runs against the harness; ADRs accepted.

### M1 — Vertical slice (0.1.0)

Goal: one real user signs in through the live gateway with one real provider,
and an upstream application receives verified identity headers. This milestone
is deliberately narrow and lands before any breadth.

Scope (scenarios 001–099):

- [ ] Generic OIDC authorization-code client with PKCE and nonce; Google as the first configured provider (ADR-0010).
- [ ] Server-side sessions in the SQLite store; per-host opaque handles in `__Host-hopae`; login transactions; single-use cross-domain handoff; idle and absolute lifetimes (ADR-0002, ADR-0004).
- [ ] Two listeners: gateway (`/_hopae/verify`) and portal (login, provider callback, logout, health) (ADR-0005).
- [ ] `GET /_hopae/verify` per the contract: `200` with the identity header set; `302`/`401` with a validated return target otherwise; `400`/`503` fail closed; `cache-control: no-store` everywhere (ADR-0006 default).
- [ ] Application registry (`apps[]`) with hosts, lifetimes and binding policy; client-IP binding with session termination on mismatch, configurable per application (ADR-0007).
- [ ] Session schema records factors and `aal`; verify emits `x-hopae-aal` and `x-hopae-factors` (ADR-0008 schema only).
- [ ] Event model: typed events to the structured log and the `events` table with retention (ADR-0009).
- [ ] Header-injection contract: the identity header set, their declaration in the gateway route so client copies are stripped gateway-wide, and a gateway-layer test proving a spoofed header never reaches the upstream.
- [ ] Path-scoped protection via gateway routes (public prefix, protected prefix, higher-priority `/admin`) documented with a working route example; phase-0 manual registration (ADR-0012); Hopae-side per-path rules deferred to M2.
- [ ] Configuration file, `hopae --check` preflight, structured logs with reason codes.
- [ ] `deploy/` Compose template placing Hopae behind the gateway; deployment to the reference environment.

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

Exit: a browser on a protected route of the live gateway completes login with
the real provider, the upstream sees the identity headers, a client-supplied
identity header is stripped, a second application on another registrable
domain is reached without a second provider login, and logout ends access on
the next request.

### M2 — Sessions, abuse controls and shared state (0.2.0)

Scope (scenarios 100–199):

- [ ] Login history API over the `events` table: filters by user, IP, provider, outcome, time; bounded retention.
- [ ] Blacklists: subject, email, email domain and client IP (CIDR); checked at login and at verify; administrator-managed.
- [ ] Login-attempt throttling and lockout per account and per client IP with constant-work responses; interaction with the gateway's failure bans documented.
- [ ] PostgreSQL backend for the primary store (ADR-0002) so two instances share one directory.
- [ ] Redis/Valkey session cache (write-through, bounded local cache, fail to the primary store), throttling counters, and the invalidation channel (ADR-0006); `verify_cache_seconds` per application.
- [ ] Logout everywhere and administrator revocation; session listing per subject.
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

### M4 — Management console and API (0.4.0)

Scope (scenarios 300–399):

- [ ] Management API with OpenAPI: users, sessions, applications, providers, policies, blacklists, login history, audit.
- [ ] Administrator accounts and roles; bootstrap procedure; management surface on its own listener.
- [ ] Web console in English and Korean covering the API; CSRF and origin checks; no secrets displayed after creation; provider secrets by environment reference (encrypted-at-rest mode decided here if adopted).
- [ ] Durable administrator audit log as `admin.*` events.

Exit: every management operation reachable from the console and the API; audit records verified for each.

### M5 — Extension points (0.5.0)

Scope (scenarios 400–499):

- [ ] Lua hooks (400–439) in isolated worker processes following the gateway's model: claims mapping after authentication, additional authorization input, header mapping; explicit list of what Lua cannot do (no network, no secrets, no update control).
- [ ] Login-notification webhooks (440–469): events from ADR-0009 (login success, failure, new device, lockout, logout, revocation); HMAC-signed deliveries; bounded retries; per-endpoint secrets from the environment; destination restrictions against internal address ranges by default.
- [ ] Second-factor mechanism (470–499) per ADR-0008: `Factor` trait (enroll, challenge, verify, recover, administrator reset); step-up rules per application evaluated at verify; TOTP first, WebAuthn second, recovery codes.

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
- [ ] Phase 2 of gateway configuration ownership (ADR-0012), only by a new ADR.
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
separate tasks in the gateway's repository, done in a worktree, and none is
required by M1. Recommended order: HC-3 (static request headers and caller
key), HC-4 (cookie filtering), HC-1 (decision micro-cache), HC-2
(invalidation subscriber), HC-5 (native entry points, optional). Hopae adds a
gateway-layer scenario for each change in the first release that relies on it
and records the pairing in the contract's compatibility matrix.

## Cross-cutting scenarios (900–999)

Allocated at any milestone: cookie attributes, CSRF on portal and console
forms, response security headers, constant-time comparisons, CSPRNG use, secret
handling in logs, and dependency audit policy. Each security-relevant change in
any milestone checks this range for an existing scenario before adding one.

## Backlog

Not scheduled; recorded so they are not re-discussed from scratch:

- OIDC provider mode for third-party applications; SAML; SCIM provisioning.
- Generic forward-auth adapter profiles (nginx `auth_request`, Traefik, Caddy, Envoy `ext_authz`) behind the ADR-0013 boundary.
- Device authorization flow; passkey-first sign-in.
- `Domain=` cookie mode for sibling subdomains (rejected in M1 because of cookie tossing).
- Negative-decision caching in the gateway micro-cache.
- Geographic and new-device risk signals feeding step-up; `max_auth_age` per application.
- Encrypted-at-rest provider secrets entered from the console.
