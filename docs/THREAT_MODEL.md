# Threat model

<!-- doc-rev: 1 -->

[Documentation](README.md) · [한국어](ko/THREAT_MODEL.md)

This is version 0 of the living threat model for Hopae: the assets, the
actors, the entry points, a STRIDE pass over each request flow of the
[architecture](ARCHITECTURE.md#request-flows), and the mitigations the design
relies on. Every security-relevant change updates this page in the same
change. Threat identifiers (`TM-nn`) are stable and are referenced from
scenarios and ADRs.

## Assets

| Asset | Where | Loss means |
| --- | --- | --- |
| Session handles (cookie values) and portal transactions | Browser cookies; store as digests | Impersonation on one host (handle) or completion of someone else's login (transaction) |
| Handoff codes | URL for ≤ 60 s; store as digests | Impersonation on the target host if replayable |
| Identity headers | Gateway → upstream only | Any application trusting a forged header is fully compromised |
| Provider credentials (client secrets), SMTP credentials, webhook secrets, caller key | Environment at run time | Impersonation of Hopae toward providers; forged webhooks |
| User directory and login history (personal data) | Primary store | Privacy breach; account takeover via linking |
| Policy (apps, binding, blocks, step-up) | Primary store and configuration | Silent loosening of access |
| Release signing seed and update manifests (M6) | Offline with the maintainer | Supply-chain compromise of every instance |
| Availability of verify | Hopae process, store | Every protected application is unreachable (fail closed) |

## Actors

| Actor | Capability | Not assumed |
| --- | --- | --- |
| Anonymous internet client | Any HTTP request to the gateway's public listeners; many IPs; chosen `Host`, cookies, headers, query strings | Breaking TLS; reading another user's browser |
| Authenticated user | A valid session; a browser that can be scripted by a malicious page on another origin | Access to the gateway network |
| Malicious sibling site | Control of a host on a sibling subdomain or on the same registrable domain as an application | Control of the application host itself |
| Compromised application | Full control of one upstream and its responses | Access to Hopae's listeners or the store |
| Network attacker between gateway and Hopae | Only if the private network is misconfigured; the design treats it as out of scope but limits damage with HC-3 | — |
| Malicious identity provider or a confused one | Returns arbitrary claims, mixes up clients, is slow or down | Forging another provider's signatures |
| Administrator with console access (M4) | Any management action, including loosening policy | — |
| Lua script author (M5) | Arbitrary scripts within the sandbox | Escaping the process sandbox |
| Supply chain | Malicious crate update, malicious release asset | Possession of the signing seed |

## Entry points

| Entry point | Listener | Reachable by | Notes |
| --- | --- | --- | --- |
| `GET /_hopae/verify` | Gateway listener | Gateway only (network); caller key with HC-3 | Highest request rate; every protected request |
| `GET /login`, `POST /login/<p>`, `GET /callback/<p>`, `GET/POST /logout`, `GET /stepup*` | Portal listener via the portal route | Internet | Browser input only |
| `GET /healthz` | Portal listener | Internet via the gateway | No secrets |
| Management API and console (M4) | Management listener | Operators | CSRF, origin checks, roles |
| Outbound: provider discovery, JWKS, token, user info; SMTP; webhooks | Hopae → internet | — | SSRF and response-size controls |
| Store connections | Hopae → SQLite file, PostgreSQL, Redis | — | Private network; TLS for remote Redis/PostgreSQL |
| Configuration file and environment | Process start, reload (M6) | Operators | Validated; secrets by reference |
| Update manifests and assets (M6) | Hopae → GitHub releases | — | Signed envelope |

## Threat catalogue

Severity follows the process scale (S1 bypass of a security boundary … S4
cosmetic). "Scenario" names the scenario that exercises the threat.

| ID | Threat | Flow | STRIDE | Mitigation relied on | Scenario |
| --- | --- | --- | --- | --- | --- |
| TM-01 | Open redirect through return URLs: an attacker crafts a login link whose return target points off-site | 1, 3, 4 | Tampering, Spoofing | The portal never reads a return URL from the client. The target is taken from the gateway-generated `x-original-url` of the verify call, stored in the transaction, validated (absolute, allowed scheme, host registered or default-allowed, ≤ 2 KiB, no userinfo, no fragment) and only ever emitted as `Location` to that host. The handoff `302` targets the exact URL the gateway reported minus the parameter. | 005 |
| TM-02 | Cookie tossing: a sibling subdomain sets a cookie that the application host presents as its session | 4, 5 | Spoofing | `__Host-` prefix: browsers reject such cookies with a `Domain` attribute and never send a sibling's host-only cookie. Unknown handles are never adopted; handles are minted server-side only at handoff. Development mode without the prefix is documented as insecure. | 009 |
| TM-03 | CSRF on login and logout: a malicious page starts a login as the attacker (login CSRF) or logs the victim out | 2, 3, 6 | Spoofing, Tampering | `POST /login/<p>` and `POST /logout` require a CSRF token bound to the `__Host-hopae_txn` or `__Host-hopae` cookie and an `Origin` equal to the portal origin. The callback requires `state` ↔ transaction cookie ↔ provider agreement, so a victim cannot be made to complete an attacker's transaction. `GET /logout` only renders a form. `SameSite=Lax` cookies. | 002, 006 |
| TM-04 | Session fixation: the attacker fixes a known handle or transaction in the victim's browser before login | 2, 3, 4 | Spoofing | Handles are created only by Hopae at handoff and stored as digests; a client-presented unknown handle is ignored. The transaction cookie is replaced at `/login` and cleared at completion. A new session gets fresh handles on every host; the portal handle is reissued at login. | 002, 003 |
| TM-05 | Handoff code replay or theft (history, logs, Referer, shoulder surfing) | 4 | Spoofing, Repudiation | Single use with an atomic conditional consume; 60 s lifetime; bound to the target host, path and the client IP that started the login; consumed through the gateway only (the gateway sets `referrer-policy: no-referrer` on the relayed `302`); rejection emits `handoff.rejected` and counts toward per-IP throttling (M2). The code never reaches the upstream. | 003 |
| TM-06 | Identity header spoofing: a client sends `x-forwarded-user` or a gateway context header | 5 | Spoofing | The gateway strips every declared identity name from every incoming request and regenerates `x-forwarded-*`/`x-original-*`. Hopae's gateway listener is unreachable from clients; its portal listener ignores `x-forwarded-*` from non-trusted proxies. Scenario 007 proves a spoofed header never reaches the upstream. | 007 |
| TM-07 | Verify endpoint denial of service: floods of random handles or long cookies; slow store | 5 | Denial of service | Verify does no provider calls and one indexed lookup; cookie header ≤ 8 KiB and handle format checked before hashing; bounded negative cache for unknown handles; concurrency limit on the gateway listener with `503` when exceeded (fail closed, counted); store timeouts; the gateway's `timeout_ms` bounds the client's wait; the gateway's rate limits and failure bans as outer layers. | 004 |
| TM-08 | Provider mix-up: the callback for provider A is completed with artifacts from provider B, or a token endpoint is chosen from attacker data | 3 | Spoofing, Elevation | Each transaction records the chosen provider; the callback path names the provider and must match; `state` is bound to (transaction, provider); endpoints come only from the provider's own configuration or discovery document fetched from the configured issuer; ID token `iss` and `aud` are checked against the provider's configuration; distinct `redirect_uri` per provider. | 002, 012 |
| TM-09 | Account takeover by email collision: provider B asserts the email of a user created through provider A | 3 | Spoofing, Elevation | Linking policy ([ADR-0011](adr/0011-account-linking-policy.md)): automatic linking only when the asserting provider reports the email as verified and is in the trusted list, and the existing email was itself verified; Naver never auto-links (no verified flag); otherwise a separate user is created or an explicit link flow (M3) is required. Email changes at a provider never move an identity between users. | 002 (M1), 2xx (M3) |
| TM-10 | Webhook SSRF (M5): a destination points at an internal address or redirects there | — | Information disclosure, Elevation | Destinations must be `https`; the resolved address is checked against loopback, private, link-local and multicast ranges and pinned for the connection (no DNS rebinding); redirects are not followed; bounded body and timeouts; HMAC-signed payloads; destination list is administrator-only. | 44x (M5) |
| TM-11 | Lua sandbox escape (M5) | — | Elevation | Scripts run in separate worker processes with the gateway's model: `env_clear`, rlimits, seccomp allowlist, string/table/math libraries only, instruction and memory budgets, hard timeout with `SIGKILL` and respawn; inputs are copies, outputs validated; no network, secrets or filesystem. | 40x (M5) |
| TM-12 | Secret or token leakage in logs, events, error pages or the configuration API | all | Information disclosure | Logs and events carry identifiers only; handles, codes, tokens and passwords are never logged; the configuration references secrets by environment variable name; error pages are generic; `hopae --check` prints no secret values. | 013, 014 |
| TM-13 | Stolen cookie reuse from another network or device | 5 | Spoofing | Context binding ([ADR-0007](adr/0007-context-binding-policy.md)): per-application IP and UA binding with session termination on mismatch; idle and absolute lifetimes; `HttpOnly`; `Secure`. | 010, 011 |
| TM-14 | Direct access to the gateway listener (verify, invalidation) from a client | 5 | Spoofing, Elevation | Separate listener bound to loopback or a private interface; the deployment template never publishes it; HC-3 caller key as defense in depth; the portal listener answers `404` for `/_hopae/verify`. | 004, 013 |
| TM-15 | Management plane abuse (M4): weak bootstrap, CSRF on console forms, role escalation | — | Elevation | Own listener; bootstrap requires a one-time token from the environment; Argon2id with dummy-hash timing; CSRF and origin checks; durable audit; no secrets displayed after creation. | 3xx (M4) |
| TM-16 | Supply chain: malicious dependency or release asset (M6) | — | Tampering | `cargo audit` in G6, `--locked` builds, dependency justification; Ed25519-signed manifests, downgrade refusal, size and redirect bounds, offline signing seed. | 5xx (M6) |
| TM-17 | Enumeration and brute force: user existence from timing or messages; password or code guessing (M3) | 2, 3 | Information disclosure, Spoofing | Constant-work responses (dummy hash); uniform messages; per-account and per-IP throttling with lockout (M2); magic-link and TOTP rate limits. The portal's `txn` id is a 128-bit random value. | 1xx, 2xx |
| TM-18 | Stale allow after revocation when a decision cache exists (HC-1) | 5, 6, 7, 8 | Elevation | Default TTL `0` (zero trust); operator-bounded TTL ≤ 30 s; `no-store` on every path-dependent and negative decision; push invalidation (HC-2) with TTL as the guarantee; documented maximum staleness. | 1xx (M2) |
| TM-19 | Gateway and Hopae version mismatch producing a silently wrong contract | 5 | Tampering, Repudiation | Contract version header (HC-3) and a published compatibility matrix; unknown major → `400` → gateway `503` (fail closed); missing required context headers → `400`. | 004, 013 |
| TM-20 | Transaction or handoff flooding exhausting the store | 1, 4 | Denial of service | Transactions and codes have short TTLs and are pruned; per-IP creation caps; bounded table sizes with oldest-first eviction counted as `txn.evicted`. | 001, 004 |
| TM-21 | Unauthenticated `401` JSON leaking a login URL that fixes a transaction for a cross-site caller | 1 | Information disclosure | The login URL carries only a `txn` id bound to the originating client IP and UA; the transaction cannot be completed by a different client when binding is strict; no user data in the body. | 001 |

## STRIDE per flow

| Flow | Spoofing | Tampering | Repudiation | Information disclosure | Denial of service | Elevation |
| --- | --- | --- | --- | --- | --- | --- |
| 1 First visit | TM-06, TM-21 | TM-01 | events `login.started` | TM-21 | TM-07, TM-20 | TM-14 |
| 2 Login | TM-03, TM-04, TM-17 | TM-01 | events | TM-12 | provider slowness bounded by timeouts | TM-08 |
| 3 Callback | TM-08, TM-09, TM-04 | token validation (`iss`, `aud`, `exp`, `nonce`, signature) | events `login.succeeded/failed` | TM-12 | TM-20 | TM-09 |
| 4 Handoff | TM-02, TM-05 | TM-01 | events `session.handoff` | code in URL for ≤ 60 s | TM-20 | TM-05 |
| 5 Verify | TM-06, TM-13, TM-14 | TM-19 | sampled `verify.denied` | TM-12 | TM-07 | TM-18 |
| 6 Logout | TM-03 | — | events `session.terminated` | — | — | — |
| 7 Logout everywhere | TM-03 | — | one event per session | — | — | — |
| 8 Binding kill | TM-13 | — | `session.terminated(binding_ip)` | — | mobile IP churn causes re-login (policy choice) | — |
| 9 Step-up (M5) | factor replay (TOTP window), WebAuthn origin binding | — | `factor.verified` | — | rate limits | step-up bypass via cached decision: TM-18 |

## Residual risks and open questions

- A compromised application can read its users' identity headers and `x-hopae-session`; it cannot mint sessions. Whether `x-hopae-session` should be hashed per application is open for review.
- Strict IP binding terminates sessions for mobile users on network change; the default is strict as directed, and the operator may relax it per application. The threat model treats relaxation as an accepted risk, not a defect.
- The handoff code appears in the gateway's access log for its lifetime. The log is an operator asset; the code is single use.
- Until HC-3 ships, verify caller authentication is purely network isolation.

## Related pages

- [Architecture](ARCHITECTURE.md), [gateway contract](GATEWAY_CONTRACT.md), [ADRs](adr/), [scenarios](../scenarios/README.md)
