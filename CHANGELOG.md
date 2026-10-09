# Changelog

[Project overview](README.md) · [Documentation](docs/README.md)

All notable changes to this project are documented in this file. The format is
based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/) and the
project adheres to [Semantic Versioning 2.0.0](https://semver.org/).

## Unreleased

### Added

- Milestone M1 (vertical slice; version 0.1.0 is not cut yet): Google OIDC sign-in (authorization code with PKCE, discovery and JWKS caching, ID-token validation), server-side sessions in SQLite with per-host handles, browser-bound cross-domain handoff with depth-bounded recovery, per-application timers and IP/User-Agent binding, logout, and explicit account linking by verified email.
- Hangang forward-authentication adapter: `/_hopae/verify` per gateway contract v1 with caller-key authentication (current and next key for rotation), fail-closed decisions, identity headers, a verify budget (`gateway.verify_budget_ms`), concurrency caps (`limits.*`) and a login portal with English and Korean pages.
- Command line: `hopae run` (alias `serve`), `hopae --check` (and `--strict`) with the route fragment and redirect URIs to register and an optional read-only drift query (`gateway.admin_url`, `gateway.readonly_token_env`), `hopae providers import [--force <id>]`; exit status `2` for configuration and instance errors, `1` for runtime failures.
- Operations: single-instance lock on the state directory, `hopae.db.bak-vN` backup before a schema migration, graceful shutdown with a 5 s drain, `/healthz`, transactional audit events with a structured log sink, event and session retention (`events.*`, `sessions.retention_days`), in-process counters (exposition is M7).
- Provider settings read from stored provider rows: `preset`, `userinfo`, `id_token_typ` (not yet settable from the configuration file).
- Deployment: multi-stage `Dockerfile` (static musl binary on an empty base image), `.dockerignore`, and `deploy/` with a hardened Docker Compose template, example configuration, environment variable names and Hangang route examples.
- Documentation: `docs/OPERATIONS.md` (with Korean translation); `docs/CONFIG.md` now lists every implemented M1 key with its default.
- Development process, documentation system, ADR and scenario templates, and roadmap.
- Architecture design, gateway contract v1 (with proposed gateway changes HC-1 to HC-9), threat model v0, ADR-0002 to ADR-0013 (Proposed), and draft scenarios 001–014 for milestone M1.
- `docs/CONFIG.md` configuration reference (M0 keys and the keys scheduled by the ADRs).
- Application-host entry points (ADR-0015, Proposed; implemented): `/_hopae/login` and `/_hopae/logout` answered by Hopae inside the verify call with a relayed `302` or `403` (never `2xx`), the reserved `/_hopae/` namespace, a server-side logout ticket (transaction purpose `logout`) so a browser without a valid portal handle can still end its session, the `apps[].logout_confirm` key, the portal's `GET /signed-out`, and `strip_request_cookies` (gateway change HC-12) in the `hopae --check` route fragment; gateway contract v1.1 (rev 9), threat model entries TM-40 and TM-41, and draft scenario 015.
- After a confirmed logout the portal shows a signed-out page with a "Sign in again to <application>" link to the validated return target instead of redirecting to the protected target, which a provider with a live session would answer by signing the user straight back in.

### Changed

- Gateway contract v1.1 reserves the `/_hopae/` namespace on every protected application host: an application route under it is no longer supported and is answered `403 reserved_path` once ADR-0015 is implemented. The route fragments in the contract, `deploy/hangang-routes.example.json` and the `hopae --check` output gain `strip_request_cookies`; a gateway without HC-12 rejects the key.

### Changed (review pass 1 of ADR-0015)

- Every handoff is delivered to `https://<host>/_hopae/login?return=<clean target>&_hopae_handoff=<code>` instead of the target itself, so redemption no longer depends on the target's route: on a path-scoped host a default or public target used to carry the code to the upstream unredeemed. The scenario 002, 003, 005 and 008 expectations read the new wire (see their wire notes); the adapter's URL bound for the reserved namespace is `3 × 2048 + 512` bytes.
- `strip_request_cookies` (HC-12) is a route-level field that also applies to public routes (`auth.strip_request_cookies` stays an alias); criteria add last-step stripping, rejecting `cookie` as an identity output, quoted-value-aware parsing and dropping the header on ambiguity. `hopae --check` prints it as its own route field. The HC-1 criteria and the cache section bypass the whole `/_hopae` namespace.
- `hopae --check` warns when an application sets `logout_confirm = false`; the same-origin navigation-gadget residual and the transferable logout ticket are documented (ADR-0015, threat model, configuration reference, scenario 015-A8 and A9).
- Migration `0002` was edited in place for the last time; later schema changes are new numbered migrations (operations guide).

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

- Design revised after adversarial design review pass 1: browser-bound cross-domain handoff, gateway caller key required in M1, explicit account linking by default, user-info subject consistency, per-handle assurance level with rotation on elevation, authorization version checked at every verify, canonical path for policy rules, explicit return-origin allowlist, transactional event outbox, verify deadline budget, full decision-cache key with an absolute freshness deadline.
- Design revised after adversarial design review pass 2: handoff codes carry issuance level and credential generation and are consumed on elevation; Redis never caches session state and allows carry generation provenance; credential destinations are exact registered hosts only; per-sink delivery rows with at-least-once delivery and bounded backlog; the `401` names the application URL as the document bootstrap; stable per-browser binding and portal cookies; explicit account-switch confirmation; provider deletion tombstones; caller-key rotation overlap; one reserved-parameter recognition rule.
- Design revised after adversarial design review pass 3: depth-bounded recovery from the first-use binding-cookie race on both hosts; non-document requests carrying the reserved parameter are terminated with a relayed `403`; delivery rows die with their event and terminal rows have their own retention, with a quantified prune cadence; a database epoch for generation rollback after restore (deferred to the first cache milestone).
- Design revised after adversarial design review pass 4: on the gateway listener only an authenticated allow is ever `2xx` (recovery exhaustion is a relayed `403`); recovery depth travels on handoff codes and is never read from the client; the portal retry matches the replacement cookie recorded on the interrupted transaction.
- Live finding on the reference deployment: the session handle and the binding cookie reached the application in the `cookie` header of every authenticated request. Mitigation designed as gateway change HC-12 (threat TM-40); until it ships the exposure is same-host trust and the route fragments document it.
