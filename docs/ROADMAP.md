# Roadmap

<!-- doc-rev: 1 -->

[Documentation](README.md) · [한국어](ko/ROADMAP.md)

This page orders the work. It derives from the project brief and from a survey
of the gateway's existing capabilities, and it is updated whenever a milestone's
scope or order changes. Completed items move to the [CHANGELOG](../CHANGELOG.md).
Scenario ranges are defined in [`scenarios/README.md`](../scenarios/README.md).

## Shape of the product

Hopae is packaged **around** the Hangang gateway rather than in front of it.
The gateway already performs external authentication checks, injects verified
identity headers into upstream requests and strips client-supplied copies;
Hopae supplies what the gateway lacks: the login portal, the providers, the
sessions and the policy.

```text
 Browser                Hangang (gateway)                    Hopae                      Provider
   │  GET app.example.test/admin  │                              │                          │
   ├─────────────────────────────▶│  forward-auth GET /verify     │                          │
   │                              ├─────────────────────────────▶│ no session               │
   │  302 auth.example.test/login │◀─────────────────────────────┤ 302 + return URL         │
   │◀─────────────────────────────┤                              │                          │
   │  GET auth.example.test/login (a route on the same gateway)  │                          │
   ├─────────────────────────────▶├─────────────────────────────▶│ 302 to provider          │
   │◀─────────────────────────────┴──────────────────────────────┤                          │
   ├──────────────────────────────── authorize, consent ────────────────────────────────────▶│
   │◀─────────────────────────────── 302 /callback?code ────────────────────────────────────┤
   ├─────────────────────────────▶├─────────────────────────────▶│ code → tokens, session   │
   │  302 app.example.test/admin  │                              │ Set-Cookie               │
   │◀─────────────────────────────┴──────────────────────────────┤                          │
   ├─────────────────────────────▶│  forward-auth GET /verify     │                          │
   │                              ├─────────────────────────────▶│ session ok               │
   │                              │  2xx + identity headers      │                          │
   │                              │◀─────────────────────────────┤                          │
   │                              ├── upstream request with x-forwarded-user, … ──▶ app    │
   │                              │   (client copies of those headers stripped)              │
```

Facts the roadmap depends on, observed in the gateway as of 2026-10-09 and to be
re-confirmed at G1 of each milestone that relies on them:

- The gateway's external check is a `GET` to a fixed URL with no body; only listed client headers (the session cookie among them) are forwarded, plus gateway-generated context headers such as the original URL, method and client IP.
- A `2xx` answer allows the request and the listed response headers are injected upstream; a `302`/`401`/`403` answer can be relayed to the browser with `Location` and `Set-Cookie`; anything else, including a timeout, fails closed.
- Identity header names declared in any route's response list are stripped from every incoming request gateway-wide.
- The gateway does not cache authentication decisions: `/verify` is called on every request and must be fast; revocation works because of this.
- Path scoping is per route (`path_prefix`, match mode, priority); finer rules live in Hopae using the original URL header.
- Login throttling, blacklists and login history are not gateway features; the gateway's per-URL failure bans can be an outer layer.

## Milestones

Each milestone ends with every scenario in its range `verified-live` (or
`implemented` with a recorded reason), documentation in both languages, a
threat-model update, a CHANGELOG section and a deployment per G9. Versions are
indicative.

### M0 — Foundation (0.0.x)

Goal: the process can run end to end on an empty crate.

- [ ] Cargo workspace, `Makefile` with the [named targets](PROCESS.md#make-targets), pre-commit hook (secret scan, publication check), CI running `make gates`.
- [ ] `tools/check_docs.py` and `tools/scenario_coverage.py` as specified in the [documentation system](DOCUMENTATION.md#validation).
- [ ] Mock OAuth/OIDC provider in `tests/support/mock_idp` with the misbehavior profiles listed in the process.
- [ ] Spawn-and-probe integration harness for the Hopae binary; gateway layer behind `HOPAE_E2E_GATEWAY_BINARY`.
- [ ] `docs/THREAT_MODEL.md` v0: assets, trust boundaries, attacker model, entry points.
- [ ] Core ADRs accepted after adversarial design review: runtime and crate choices; storage engine; session model and cookie scope across the portal host and application hosts; verify endpoint and portal paths; identity header names and the gateway contract; return-URL validation; **the event model** (consumed later by login history and webhooks); **the second-factor extension point** (session records which factors were satisfied and when) so M5 does not retrofit the session schema.
- [ ] `docs/GATEWAY_CONTRACT.md` and `docs/CONFIG.md` skeletons.

Exit: `make gates` green on the empty crate; one template scenario runs against the harness.

### M1 — Vertical slice (0.1.0)

Goal: one real user signs in through the live gateway with one real provider,
and an upstream application receives verified identity headers. This milestone
is deliberately narrow and lands before any breadth.

Scope (scenarios 001–099):

- [ ] Generic OIDC authorization-code client with PKCE and nonce; Google as the first configured provider.
- [ ] Server-side sessions in the embedded store; opaque session cookie with attributes decided in M0; idle and absolute lifetimes.
- [ ] `GET /verify` for the gateway: `2xx` with identity headers for a valid session; `302` to the portal with a validated return URL otherwise; fail closed on store errors.
- [ ] Portal on its own host (`auth.example.test` in docs), served as a route on the same gateway: login, provider callback, logout, health.
- [ ] Header-injection contract: the identity header set, their declaration in the gateway route so client copies are stripped gateway-wide, and a gateway-layer test proving a spoofed header never reaches the upstream.
- [ ] Path-scoped protection via gateway routes (public prefix, protected prefix, higher-priority `/admin`) documented with a working route example; Hopae-side per-path rules deferred to M2.
- [ ] Configuration file, `hopae --check` preflight, structured logs with reason codes.
- [ ] `deploy/` Compose template placing Hopae behind the gateway; deployment to the reference environment.

Indicative scenarios: 001 login through gateway redirect; 002 verify with valid
session; 003 verify without session; 004 return-URL validation; 005 logout;
006 path scope via routes; 007 header injection and spoof stripping; 008 cookie
attributes and cross-host scope; 009 provider failure modes; 010 preflight and
startup. Final allocation happens at G3.

Exit: a browser on a protected route of the live gateway completes login with
the real provider, the upstream sees the identity headers, a client-supplied
identity header is stripped, and logout ends access on the next request.

### M2 — Sessions and abuse controls (0.2.0)

Scope (scenarios 100–199):

- [ ] Login history: persisted events (success, failure, logout, revocation) with provider, subject, client IP, user agent, decision and reason code; bounded retention.
- [ ] Blacklists: subject, email, email domain and client IP (CIDR); checked at login and at `/verify`; administrator-managed.
- [ ] Login-attempt throttling and lockout per account and per client IP with constant-work responses; interaction with the gateway's failure bans documented.
- [ ] Redis/Valkey shared session cache for multi-instance deployments: write-through, bounded local cache, fail-closed semantics, namespace isolation.
- [ ] Logout everywhere and administrator revocation; session listing per subject.
- [ ] Hopae-side path and host policy rules evaluated from the original URL header (allow, require login, require group).

Exit: two Hopae instances behind the gateway share sessions; lockout, blacklist and revocation are verified live.

### M3 — Providers (0.3.0)

Scope (scenarios 200–299):

- [ ] Kakao and Naver (OAuth 2.0 with provider-specific user-info mapping and verified-email rules).
- [ ] Email magic link: single-use, short-lived, bound to the requesting browser; SMTP configuration; rate limits.
- [ ] Email and password: Argon2id, dummy-hash timing for unknown accounts, reset flow, password policy.
- [ ] Provider enable/disable and ordering at run time; per-provider allowed email domains.
- [ ] Account linking policy (when two providers may map to one account) recorded in an ADR before implementation.

Exit: each provider verified live against a test tenant where one exists; email flows verified against a loopback SMTP sink and one real mailbox.

### M4 — Management console and API (0.4.0)

Scope (scenarios 300–399):

- [ ] Management API with OpenAPI: users, sessions, providers, policies, blacklists, login history, audit.
- [ ] Administrator accounts and roles; bootstrap procedure; management surface on its own listener or host.
- [ ] Web console in English and Korean covering the API; CSRF and origin checks; no secrets displayed after creation.
- [ ] Durable administrator audit log.

Exit: every management operation reachable from the console and the API; audit records verified for each.

### M5 — Extension points (0.5.0)

Scope (scenarios 400–499):

- [ ] Lua hooks (400–439) in isolated worker processes following the gateway's model: claims mapping after authentication, additional authorization input, header mapping; explicit list of what Lua cannot do (no network, no secrets, no update control).
- [ ] Login-notification webhooks (440–469): events from the M0 event model (login success, failure, new device, lockout, logout, revocation); HMAC-signed deliveries; bounded retries; per-endpoint secrets from the environment; destination restrictions against internal address ranges by default.
- [ ] Second-factor mechanism (470–499): factor interface (enroll, challenge, verify, recover, administrator reset); session records satisfied factors and time; step-up policy per host, path or group evaluated at `/verify`; TOTP first, WebAuthn second, recovery codes.

Exit: a route requiring a second factor denies a first-factor-only session live; a webhook delivery is verified against a loopback receiver and one real endpoint.

### M6 — Lifecycle and releases (0.6.0)

Scope (scenarios 500–599):

- [ ] Signed self-update adopting the gateway's verified design: Ed25519 manifest envelope, GitHub release discovery, downgrade refusal, size and redirect bounds, atomic activation with rollback; `hopae update`, `hopae --check-update`, daily check cache with an opt-out; container deployments replace the image instead.
- [ ] Release pipeline: CI build matrix, static Linux binaries, release assets and `SHA256SUMS`, offline signing procedure, `release-public-key.txt`.
- [ ] Configuration reload semantics and preflight on reload.

Exit: an instance updates itself from a signed pre-release and rolls back a deliberately broken one.

### M7 — Scale-out and operations (0.7.0)

Scope (scenarios 600–699):

- [ ] Multi-instance operation documented end to end: what is shared, what is instance-local, required Redis/Valkey settings.
- [ ] Prometheus metrics, health and readiness endpoints, structured audit export.
- [ ] Backup and restore of the embedded store; key rotation for cookie and session keys and webhook secrets.
- [ ] API-client mode (stretch): issue RFC 9068 access tokens with JWKS and discovery so the gateway's native JWT verifier can protect APIs with the same identities.

Exit: a rolling replacement of two instances keeps sessions; metrics and backups verified live.

### 1.0

After M7, a full adversarial review pass over the threat model, the gateway
contract and the configuration schema, with no open S1/S2 finding, produces
1.0.0. From 1.0, configuration and the gateway contract change only with a
major version.

## Cross-cutting scenarios (900–999)

Allocated at any milestone: cookie attributes, CSRF on portal and console
forms, response security headers, constant-time comparisons, CSPRNG use, secret
handling in logs, and dependency audit policy. Each security-relevant change in
any milestone checks this range for an existing scenario before adding one.

## Backlog

Not scheduled; recorded so they are not re-discussed from scratch:

- OIDC provider mode for third-party applications; SAML; SCIM provisioning.
- Device authorization flow; passkey-first sign-in.
- PostgreSQL store.
- Geographic and new-device risk signals feeding step-up.
