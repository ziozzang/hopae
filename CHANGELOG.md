# Changelog

[Project overview](README.md) · [Documentation](docs/README.md)

All notable changes to this project are documented in this file. The format is
based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/) and the
project adheres to [Semantic Versioning 2.0.0](https://semver.org/).

## Unreleased

### Added

- Embedded bounded Lua 5.4 eligibility for external second factors. Operator-approved scripts can restrict native verifier use, with isolated context, heap/instruction/time limits and strict boolean results; native proof/session authority remains mandatory. General connector orchestration and credential translation remain unfinished.

### Fixed

- Native macOS qualification harness: actual process RSS, portable failed-evidence output, bounded loopback verifier startup and complete-frame handling after HTTP connection reset. Truncated/ambiguous responses remain errors; release authentication behavior is unchanged.

## 0.0.3 — 2026-10-14

### Added

- Native encrypted TOTP enrollment and browser step-up, external HTTPS MFA verifier configuration/chooser/forms, atomic proof consumption, elevated handoff and prior credential revocation.
- Mixed OIDC/LDAP login and password reauthentication with owned LDAPS/mandatory-StartTLS qualification and bounded malformed-response handling.
- Authenticated persistent mTLS HOP1, service API key/HTTPS relay profiles with circuit breaking and DB-owned delegated administration; service credentials remain AAL 0.
- Signed release manifests and a published Ed25519 verification key. Automatic self-update remains unimplemented.

### Security and migration

- Schema v6 adds encrypted factor state, immutable verifier authorities, indexed session revocation and durable scoped proof hashes. Existing schema-v5 tables are preserved; backups must include owner/delegation state, configuration and keys.
- A v5 binary refuses v6 state. Downgrade requires the consistent pre-upgrade backup; never point an old binary at an upgraded database.
- The native internal v6 deployment preserves existing keys and assurance rules. Owned Chromium, static-candidate HTTP/mTLS and upgrade/restore qualification pass; production Google/organization MFA and distributed/full-stack throughput are not claimed.

### Validation and remaining scope

- 856 serial tests pass, 42 ignored; scoped dependency audit, owned OIDC/LDAP/HTTPS and actual Chromium TOTP/external MFA qualification pass.
- Lua, local human passwords, general credential translation, enrollment/recovery/account limits, memory followers, existing-stream revocation and full-stack 10k/100k performance remain unfinished.

## Earlier implementation history

### Added

- HOP1 authenticated persistent loopback verification and native Hangang pool support, retaining the same provider/session engine.
- Trusted Hopae console package with paginated users/sessions/events/status and management actions; signed scoped Hangang actor delegation preserves native handles, grants, assurance, CSRF, fences and audit.

- Milestone M1 (vertical slice; version 0.1.0 is not cut yet): Google OIDC sign-in (authorization code with PKCE, discovery and JWKS caching, ID-token validation), server-side sessions in SQLite with per-host handles, browser-bound cross-domain handoff with depth-bounded recovery, per-application timers and IP/User-Agent binding, logout, and explicit account linking by verified email.
- Hangang forward-authentication adapter: `/_hopae/verify` per gateway contract v1 with caller-key authentication (current and next key for rotation), fail-closed decisions, identity headers, a verify budget (`gateway.verify_budget_ms`), concurrency caps (`limits.*`) and a login portal with English and Korean pages.
- Command line: `hopae run` (alias `serve`), `hopae --check` (and `--strict`) with the route fragment and redirect URIs to register and an optional read-only drift query (`gateway.admin_url`, `gateway.readonly_token_env`), `hopae providers import [--force <id>]`; exit status `2` for configuration and instance errors, `1` for runtime failures.
- Operations: single-instance lock on the state directory, `hopae.db.bak-vN` backup before a schema migration, graceful shutdown with a 5 s drain, `/healthz`, transactional audit events with a structured log sink, event and session retention (`events.*`, `sessions.retention_days`), in-process counters (exposition is M7).
- Provider settings read from stored provider rows: `preset`, `userinfo`, `id_token_typ` (not yet settable from the configuration file).
- Deployment: multi-stage `Dockerfile` (static musl binary on an empty base image), `.dockerignore`, and `deploy/` with a hardened Docker Compose template, example configuration, environment variable names and Hangang route examples.
- Documentation: `docs/OPERATIONS.md` (with Korean translation); `docs/CONFIG.md` now lists every implemented M1 key with its default.
- Milestone M4-min (administration console, ADR-0016): a third listener (`listen.admin`, `admin.public_url`) that authenticates every request from the `__Host-hopae` console handle and the administrator grant table, never from a header; read-only status, users, sessions and events pages with JSON twins under `/v1`; disabling and enabling a user and ending one or all sessions of a user, each with an `admin.*` audit event written in the same store transaction and an actor fence that re-reads the grant at the write; signed cursors, a bounded candidate window and a query budget (`admin.query_budget_ms`) for every list; Korean and English pages with the pinned security headers.
- Command line `hopae admin grant|revoke|list|import` (`--role`, `--note`, `--confirm`, `--all`, `--force`) over the store without taking the instance lock, and `admin.users[]` grants imported at start (after the provider import, under a 30 s deadline; a defective entry is a warning, never a start failure). `hopae --check` prints the console route fragment (no `strip_request_cookies`), `admin.untrusted_peers`, the per-provider `reauth` capability (including a stored override) and warns for `console_route_without_auth`, `console_route_strips_cookies` and entries that cannot be resolved.
- Migration `0003` (`admin_grants`, `sessions.auth_time` and `auth_time_source`, `sessions.bound_ua_prefix`, `login_txns.reauth_max_age`, replaced events indexes), preceded by a precheck of the foundation.
- Freshness of the console (`admin.max_auth_age`): a provider that honors `max_age` gets a provider-verified reauthentication (`max_age`/`prompt=login`, `auth_time` validated, the same session reauthenticated); a provider that cannot (`reauth: unsupported`, the Google preset) is judged by Hopae login age and says so. The engine answers a stale console navigation `302`/`401 reauth_required`; the listener answers `403 auth_too_old`.
- Gateway-layer scenarios for the console (300-1, 300-10, 300-12) run through the real gateway with a `hopae-admin` route in `make e2e`; the test harness gains `GatewayRoutes::with_console` and `with_public_console`.
- Development process, documentation system, ADR and scenario templates, and roadmap.
- Architecture design, gateway contract v1 (with proposed gateway changes HC-1 to HC-9), threat model v0, ADR-0002 to ADR-0013 (Proposed), and draft scenarios 001–014 for milestone M1.
- `docs/CONFIG.md` configuration reference (M0 keys and the keys scheduled by the ADRs).
- Application-host entry points (ADR-0015, Proposed; implemented): `/_hopae/login` and `/_hopae/logout` answered by Hopae inside the verify call with a relayed `302` or `403` (never `2xx`), the reserved `/_hopae/` namespace, a server-side logout ticket (transaction purpose `logout`) so a browser without a valid portal handle can still end its session, the `apps[].logout_confirm` key, the portal's `GET /signed-out`, and `strip_request_cookies` (gateway change HC-12) in the `hopae --check` route fragment; gateway contract v1.1 (rev 9), threat model entries TM-40 and TM-41, and draft scenario 015.
- After a confirmed logout the portal shows a signed-out page with a "Sign in again to <application>" link to the validated return target instead of redirecting to the protected target, which a provider with a live session would answer by signing the user straight back in.

### Changed

- Gateway contract v1.1 reserves the `/_hopae/` namespace on every protected application host: an application route under it is no longer supported and is answered `403 reserved_path` once ADR-0015 is implemented. The route fragments in the contract, `deploy/hangang-routes.example.json` and the `hopae --check` output gain `strip_request_cookies`; a gateway without HC-12 rejects the key.

### Changed (M4-min)

- `sessions.auth_time` comes from a valid provider `auth_time` claim with `auth_time_source = provider_claim`; an absent claim records the completion time as `hopae_completion`; an invalid claim fails the login (`invalid_auth_time`). A reauthentication never changes `session_id`, `bound_ip`, `created_at`, `absolute_expires_at` or `aal`.
- The backup before a schema migration is written (to a temporary file, then renamed) only after the store passed the precheck.
- Handoff codes still outstanding when an administrator ends the session are consumed with `consumed_reason = session_terminated` (other endings keep their own reason).

### Changed (review pass 1 of ADR-0015)

- Every handoff is delivered to `https://<host>/_hopae/login?return=<clean target>&_hopae_handoff=<code>` instead of the target itself, so redemption no longer depends on the target's route: on a path-scoped host a default or public target used to carry the code to the upstream unredeemed. The scenario 002, 003, 005 and 008 expectations read the new wire (see their wire notes); the adapter's URL bound for the reserved namespace is `3 × 2048 + 512` bytes.
- `strip_request_cookies` (HC-12) is a route-level field that also applies to public routes (`auth.strip_request_cookies` stays an alias); criteria add last-step stripping, rejecting `cookie` as an identity output, quoted-value-aware parsing and dropping the header on ambiguity. `hopae --check` prints it as its own route field. The HC-1 criteria and the cache section bypass the whole `/_hopae` namespace.
- `hopae --check` warns when an application sets `logout_confirm = false`; the same-origin navigation-gadget residual and the transferable logout ticket are documented (ADR-0015, threat model, configuration reference, scenario 015-A8 and A9).
- Migration `0002` was edited in place for the last time; later schema changes are new numbered migrations (operations guide).

### Fixed (code review G7 pass 2 of the M4-min console, ADR-0016)

- Nested store deadline scopes keep the earliest, so the engine's larger verify budget cannot extend the console's `admin.query_budget_ms`; the detached handle touch carries its own 2 s deadline; engine session termination checks its deadline before commit.
- `hopae admin grant` by an address records a binding the row lacked (a change, audited), and `hopae admin import` records the missing binding of a row an email-only entry resolves to, so a reassigned mailbox is never granted later; the grant aborts (exit `2`) when the resolution evidence cannot be written.

### Fixed (code review G7 of the M4-min console, ADR-0016)

- A database provider the file no longer lists keeps its stored reauthentication capability in verify, the callback, the write fence and the status page (one capability map); a present JSON `null` `auth_time` fails the login like any other invalid claim; a reauthentication's `handle.revoked` events list the handles revoked in its own transaction, not a truncated preview.
- `hopae_admin_denied_total` counts `not_admin`, `role_insufficient`, `aal_insufficient` and `auth_too_old` once where `admin.denied` is written, and a freshness challenge is labelled `reauth_required` in `hopae_verify_decisions_total`. ADR-0016 decision 3 now states that the engine's own lifetime and binding consequences apply on the admin listener while the listener itself initiates no termination.
- The actor fence tests refresh `auth_time` in the handle-idle case and gain isolated session-idle, session-created-in-the-future, `auth_time`-in-the-future and handle-digest cases.
- `hopae admin grant` by a new address never replaces an existing `source_email` (it is refused: `already bound to <old>`), so an unchanged file import cannot grant the old address's new holder; the address fallback across local-part case is removed (only the domain is normalized); `import --force <user_id>` works inside an ambiguous binding set; the resolution block is printed and flushed before the grant is written and lists every identity.
- The inline event-retention prune can no longer swallow a deadline or an interrupted statement and commit late; the console's authentication reads and its required refusal records (`admin.denied`, `csrf.rejected`) carry the query budget, with a fallback deadline scope in the admin middleware.

### Fixed (code review G7 pass 2 of ADR-0015)

- An `Accept` range with quality 0 (`text/html;q=0`) is not accepted HTML for the entry points.
- Switch and link transaction inserts report their evictions as `txn.evicted`, like login and retry.
- A ticket-only logout confirmation that fails the `Origin` or CSRF check is recorded as `csrf.rejected` (purpose `logout`) before the existing no-op answer.

### Fixed (code review G7 pass 1 of ADR-0015)

- A logout ticket is consumed and the session it names is terminated in one store transaction (a crash in between no longer loses the logout).
- An absolute `return` must use the standard authority form and its normalized destination is checked against the reserved namespace (`https:///h/_hopae/logout` was accepted as a target).
- `txn.max_rows` also bounds switch and link transactions (eviction applies; the per-address cap does not).
- The URL-length limit of the login entry point is chosen from the canonical path, so encoded spellings of `/_hopae/login` carry targets of the full length.
- Entry points require an HTML `Accept` (ADR-0015 decision 2); a logout entry that refuses a presented handle is recorded as `verify.denied` like the ordinary login.

### Fixed

- `txn.max_rows` is a hard bound: the eviction now happens inside the same store write as the capped transaction insert (login, retry and logout ticket) instead of in a detached task, and the per-address `txn.per_ip_per_minute` cap is enforced in that write for the verify engine too, so concurrent callers can no longer overshoot either limit.

### Security

- Console authentication is handle based and bound to the console host, address and timers of the implicit `admin` application; a peer outside `trusted_proxies` is refused (`untrusted_peer`) before any header is read, forwarding headers are believed only from a trusted peer, and plain HTTP never carries the console. Mutations need the form token or the `x-hopae-admin-request` header, and the fenced write refuses an actor whose grant, role, status or freshness changed after the request check (`actor_revoked`). Lists examine at most a constant candidate window and are interruptible at the query budget.
- Design revised after adversarial design review pass 1: browser-bound cross-domain handoff, gateway caller key required in M1, explicit account linking by default, user-info subject consistency, per-handle assurance level with rotation on elevation, authorization version checked at every verify, canonical path for policy rules, explicit return-origin allowlist, transactional event outbox, verify deadline budget, full decision-cache key with an absolute freshness deadline.
- Design revised after adversarial design review pass 2: handoff codes carry issuance level and credential generation and are consumed on elevation; Redis never caches session state and allows carry generation provenance; credential destinations are exact registered hosts only; per-sink delivery rows with at-least-once delivery and bounded backlog; the `401` names the application URL as the document bootstrap; stable per-browser binding and portal cookies; explicit account-switch confirmation; provider deletion tombstones; caller-key rotation overlap; one reserved-parameter recognition rule.
- Design revised after adversarial design review pass 3: depth-bounded recovery from the first-use binding-cookie race on both hosts; non-document requests carrying the reserved parameter are terminated with a relayed `403`; delivery rows die with their event and terminal rows have their own retention, with a quantified prune cadence; a database epoch for generation rollback after restore (deferred to the first cache milestone).
- Design revised after adversarial design review pass 4: on the gateway listener only an authenticated allow is ever `2xx` (recovery exhaustion is a relayed `403`); recovery depth travels on handoff codes and is never read from the client; the portal retry matches the replacement cookie recorded on the interrupted transaction.
- Live finding on the reference deployment: the session handle and the binding cookie reached the application in the `cookie` header of every authenticated request. Mitigation designed as gateway change HC-12 (threat TM-40); until it ships the exposure is same-host trust and the route fragments document it.
