# ADR-0016: The management console is a Hopae application on its own listener, authenticated from the session handle, with administrators as granted users

- Status: Proposed
- Date: 2026-10-09
- Deciders: designer, orchestrator, maintainer
- Scenarios: 300, 301, 302, 303, 304, 305
- Threat model: TM-15 (rewritten), TM-42, TM-43, TM-44, TM-45; new flow C
- Supersedes: none (narrows the M4 sketch in the [architecture](../ARCHITECTURE.md#data-model): the `admins` table with its own passwords is not built)

## Context

- M1 is live behind the reference gateway with a real provider. The maintainer wants an administration page next, before M2 and M3: list and search users, see a user's identities, sessions and recent events, disable and enable a user, end one session or every session of a user, browse the login history and audit trail with filters, and see the status of applications, providers, the store and the build. Everything else of the M4 scope (provider and application management, blacklists, OpenAPI, API tokens) stays later. This milestone is **M4-min** in the [roadmap](../ROADMAP.md#m4-min--management-console-minimum-020).
- The architecture sketched a management listener (M4) with its own `admins` table (username, Argon2id password hash, role) and the threat model's TM-15 assumed a bootstrap token from the environment. Nothing of that exists yet; the data model is free to change now and frozen migration `0002` cannot be edited (every schema change is a new migration).
- Hopae already has everything an administrator's session needs: a login flow with a real provider, server-side sessions with per-host handles, per-application timers and client binding ([ADR-0004](0004-session-model-and-cross-domain-handoff.md), [ADR-0007](0007-context-binding-policy.md)), `users.status` and `authz_version` read on every verify, the assurance level per handle ([ADR-0008](0008-second-factor-extension-point.md)), application-host entry points for sign-in and sign-out ([ADR-0015](0015-app-host-entry-points-and-upstream-cookie-stripping.md)), and a transactional audit outbox with `admin.*` kinds reserved ([ADR-0009](0009-event-model.md)).
- The gateway injects identity headers into upstream requests. They are trustworthy for an upstream **only** when the upstream is reachable solely through the gateway. Hopae's listeners run on the gateway host's loopback (`network_mode: host` in the reference deployment), where any local process can connect; the verify endpoint needs the caller key for that reason (HC-3, TM-14). The gateway cannot add a static header to an upstream request (HC-3 covers the external-auth call only), so a caller key for an upstream listener is not available.
- The gateway strips the Hopae cookies from upstream requests on routes that set `strip_request_cookies` (HC-12). A route whose upstream is Hopae itself must not strip them, or the upstream cannot see the credential it would validate.
- The portal is server-rendered with askama templates, English and Korean strings in TOML, a content security policy without scripts, CSRF tokens bound to a cookie plus an `Origin` check ([integration ruling R-5](../PROCESS.md#adversarial-review-protocol) is recorded internally). The project's dependency policy prefers crates already present; a JavaScript build chain is not in the tree.
- `events` is indexed on `(at)`, `(user_id, at)` and `(client_ip, at)`; `sessions` on `(user_id, terminated_at)`; `session_handles` on `(session_id)`; there is no index for a kind filter, for "active sessions by last activity" or for listing users by creation time. The session row stores the user agent as a digest only; events keep a 64-byte sanitized prefix for display.
- Second factors arrive in M5; today every session is single-factor (`aal = 1`), and `apps[].step_up` is parsed but not enforced.

## Decision

The console and its API are **a Hopae application served by Hopae**: a third listener, a reserved application registered like any other, the ordinary login and sign-out flows through the gateway, and an administrator check that Hopae performs on every request from its own session handle. Administrators are ordinary users with a grant row.

1. **Where it runs.** A third TCP listener, `listen.admin` (default `127.0.0.1:8702`), with a router disjoint from the portal's and the gateway's ([ADR-0003](0003-http-stack-axum-on-hyper.md)). It exists only when `admin.public_url` is set (the console's externally visible origin, `https://hopae-admin.example.test` in examples); without it nothing binds and `hopae --check` prints nothing about it. It is bound to loopback like the other listeners and must not be publicly reachable except through the gateway.
2. **The console host is a registered application.** `admin.public_url` registers the implicit application `admin` (a reserved `app_id`, like `default`; an `apps[]` entry with that id is a configuration error) with `hosts = [its host]`, `ports = [its port or 443]`, `session = admin.session` (defaults `idle: 30m`, `absolute: 12h`), `binding = admin.binding` (defaults `ip: strict`, `ua: off`, `on_mismatch: terminate_session`), `on_authz_change = terminate`, `verify_cache_seconds = 0`, `logout_confirm = true`, and `step_up = [{"path_prefix": "/", "require": {"aal": admin.require_aal}}]` when `admin.require_aal` is `2`. Being an application makes the console host a credential destination the operator vouches for, puts it in the return-origin allowlist, and gives it the whole M1 machinery unchanged: the unauthenticated `302` to the portal, the browser-bound handoff to `/_hopae/login`, the host-only `__Host-hopae` handle, the `/_hopae/logout` ticket. The gateway route for the host is the contract's protected whole-host fragment with one difference: **no `strip_request_cookies`** (the upstream is Hopae and needs the handle). `hopae --check` prints that fragment; the phase-1 drift report flags a console route that strips.
3. **Every request is authenticated by Hopae from the handle, never from headers.** The admin listener reads the configured handle cookie, the client address and scheme through the `trusted_proxies` rule the portal uses, and the request's own path, builds a `VerifyInput` for the console host (`navigation: Other`, no handoff, internal caller) and runs the verify engine (`verify::decide`, [ADR-0013](0013-gateway-adapter-boundary.md)): handle → session → timers → binding → user status and `authz_version` → application policy → identity. Only `Decision::Allow` proceeds; every other outcome is `403 {"error":"login_required","login":"<admin.public_url>"}` (an HTML page with that link for a document navigation), creates nothing and sets no cookie. The listener never starts a login, never redeems a handoff and never ends a session on its own initiative: the gateway's verify call for the same host already did that before the request was proxied, so a non-allow outcome at the listener means a direct connection, a misconfigured route or a session that ended between the two checks. The identity headers the gateway injects (`x-forwarded-user`, `x-hopae-*`) and the gateway context headers other than the forwarding headers are **never read** (the boundary lint keeps their names out of the admin module). A request whose forwarded host is not the console host is `404`. A direct connection to the listener therefore gains nothing without a valid handle for the console host; a local process that holds a stolen console handle can present a chosen `x-forwarded-for` and defeat IP binding, which is the same residual the portal listener has (TM-42).
4. **Administrators are granted users.** A new table `admin_grants(user_id PRIMARY KEY REFERENCES users, role IN ('admin','viewer'), granted_at, granted_by, revoked_at, revoked_by, note)` (migration `0003`). After the engine allows, the listener reads the grant of `identity.user_id` from the primary store on **every** request (no cache); a missing or revoked row is `403 not_admin` with the user id and email on the page so the person can hand them to an operator, and a required event `admin.denied` (`reason=not_admin`). `viewer` may read every page and every `GET`; `admin` may also mutate. A viewer's mutation is `403 role_insufficient` with `admin.denied`. There are no passwords, no separate accounts and no bootstrap token: the `admins` table of the architecture sketch is not built.
5. **Bootstrap and recovery are a command.** `hopae admin grant <user_id|email> [--role admin|viewer] [--note <text>]`, `hopae admin revoke <user_id|email>` and `hopae admin list` run against the store directly (like `providers import`, safe while an instance runs; the instance reads grants per request, so no restart). An email resolves through `users.primary_email` and requires `email_verified`; a user who never signed in does not exist and the command exits `2` with "sign in once first": the first administrator signs in through the console host (or any application), reads the user id from the `403 not_admin` page, and an operator runs `grant`. Every CLI change writes an `admin.grant` or `admin.revoke` event with `attrs.actor = "cli"` in the same transaction as the row. Granting and revoking from the console itself is not in M4-min (it is an elevation path with its own abuse cases; the user detail page shows the grant read-only).
6. **Freshness before second factors exist.** `admin.max_auth_age` (duration, default `12h`): a console request whose session's first-factor `auth_time` is older is `403 auth_too_old` with a sign-out link (`/_hopae/logout` on the console host) and an `admin.denied` event; the person signs out and in again. `admin.require_aal` (`1` or `2`, default `1`): `2` requires `identity.aal = 2` on the presented handle (`403 aal_insufficient` otherwise) and sets the implicit application's step-up rule so the gateway's verify sends the browser to the portal's challenge once M5 exists; before M5 `hopae --check` warns that `2` denies every console request. Operators are told to require a second factor at the provider for administrator accounts (Google 2-step verification, for example) until M5.
7. **UI: server-rendered pages, no scripts, plus a JSON API.** Pages are askama templates in English and Korean selected by `Accept-Language` (strings in the portal's TOML files under `admin.*` keys), styled by one static stylesheet, with the portal's security headers on every response (`cache-control: no-store`, `x-content-type-options: nosniff`, `referrer-policy: same-origin`, `x-frame-options: DENY`, `x-robots-tag: noindex`) and the content security policy `default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'` — no script of any origin, so inline scripts are not a question. Forms are plain `POST`s. The same handlers serve JSON under `/v1/` for scripts: `GET /v1/me`, `GET /v1/users`, `GET /v1/users/{id}`, `POST /v1/users/{id}/disable`, `POST /v1/users/{id}/enable`, `POST /v1/users/{id}/sessions/terminate`, `GET /v1/sessions`, `GET /v1/sessions/{id}`, `POST /v1/sessions/{id}/terminate`, `GET /v1/events`, `GET /v1/status`. Errors are `{"error":"<code>"}`. The API is authenticated exactly like the pages (the handle cookie); API tokens are later work, so a non-browser client needs a cookie obtained by a browser.
8. **CSRF.** HTML forms carry a token issued by the portal's CSRF module with a new purpose `admin`, bound to the presented handle value (as the logout form binds to the portal handle), and require `Origin` equal to `admin.public_url`'s origin; a failure is `403 csrf_rejected` with a `csrf.rejected` event (`purpose=admin`, `cause=token|origin`) and no change. JSON mutations require `content-type: application/json`, the header `x-hopae-admin-request: 1`, `Origin` equal to the console origin when present, and `sec-fetch-site` equal to `same-origin` or `none` when present; a cross-origin browser cannot send that header or content type without a preflight that no handler answers. `SameSite=Lax` on the handle is the layer beneath both.
9. **Mutations are fenced and audited in one transaction.** Each mutating store method takes the actor (`user_id`, `session_id`, handle digest) and, inside its write transaction, re-reads the actor's session (live, handle not revoked) and grant (live, role `admin`); a revocation committed first makes the write fail with `403` and no change. The change and its `admin.*` event are committed together (outbox, ADR-0009). Events name the **target** in the first-class columns (`user_id`, `session_id`) and the **actor** in `attrs.actor` (a user id or `cli`) and `attrs.actor_session`:

   | Action | State change | Events in the same transaction |
   | --- | --- | --- |
   | Disable user | `users.status = disabled`, `authz_version += 1`, every live session of the user terminated (`cred_gen += 1`, handles revoked, codes consumed) | `admin.user_disable` (attrs `actor`, `actor_session`, `count`) and one `session.terminated` (`reason=user_disabled`) per session |
   | Enable user | `users.status = active`, `authz_version += 1`; no session revived | `admin.user_enable` |
   | Terminate one session | `terminate_session(reason=admin)` | `admin.session_terminate` and `session.terminated` (`reason=admin`) |
   | Terminate every session of a user | one `terminate_session(reason=admin)` per live session | `admin.sessions_terminate` (attrs `count`) and one `session.terminated` per session |
   | Grant, revoke (CLI) | `admin_grants` row written | `admin.grant` / `admin.revoke` (attrs `actor=cli`, `role`, `previous_role`) |
   | Denied console request | none | `admin.denied` (`reason` ∈ `not_admin`, `role_insufficient`, `auth_too_old`, `aal_insufficient`, `self_target`; attrs `endpoint`, `method`) |

   An action that changes nothing (disabling a disabled user, terminating a terminated session) answers `200 {"changed": false}` and writes no event. An administrator cannot disable their own user (`403 self_target`); terminating their own session is allowed and acts as a sign-out. Reads are not audited.
10. **Queries and indexes.** Listing is keyset-paginated, newest first, `limit` 1–200 (default 50), with an opaque cursor (`base64url` of the sort key and the id; a forged cursor is `400 invalid_cursor`). Users: order `created_at DESC`; search `q` (≤ 128 characters) matches `primary_email` and `username` by prefix (the unique indexes) and `display_name` by substring (a bounded scan, documented); filter `status`. Sessions: live rows only (`terminated_at IS NULL AND absolute_expires_at > now`), order `last_seen_at DESC`, filter `user_id`; each row shows the user's email, the handles' hosts, `created_at`, `last_seen_at`, `bound_ip`, the user-agent prefix, `aal`, `provider_id`. Events: filters `kind`, `outcome`, `user_id`, `session_id`, `client_ip` (exact), `since`, `until`, combined with AND; the planner uses `events(user_id, at)`, `events(client_ip, at)`, the new `events(kind, at)` or `events(at)`; `outcome` is applied to rows read in `at` order with a scan cap of 10,000 rows per page, after which a short page with a cursor is returned. Migration `0003` adds `admin_grants`, the column `sessions.bound_ua_prefix` (filled from then on; `NULL` for older rows), and the indexes `events(kind, at)`, `sessions(terminated_at, last_seen_at)`, `users(created_at)`. Migration `0002` is not touched.
11. **Status is read-only.** `GET /v1/status` and the front page show: applications (id, hosts, ports, enabled, lifetimes, binding, `logout_confirm`), providers (id, kind, display name, enabled, `managed_by`, health from the registry's cached discovery state, the secret's environment variable **name** and whether it is set), the store (kind, schema version, counts of users, live sessions and events, pending and failed deliveries per sink), the build (version, contract version), the configuration generation and digest, `started_at`, and the `insecure_mode` and `unauthenticated_caller` flags of `/healthz`. No value of any secret is ever rendered. Runtime provider changes are not in M4-min; when they come, a `POST /v1/providers/{id}` handler sets `managed_by = api` on the row by the [ADR-0010](0010-provider-abstraction.md) rule and the status page's `managed_by` column is where the operator sees that the file no longer owns the row.
12. **Limits and privacy.** `limits.admin_max_concurrent` (default `16`) refuses excess requests with `503` before any work; bodies are capped at 64 KiB, query strings at 4 KiB. Unauthenticated requests to the listener create nothing (no transaction, no event except the sampled `verify.denied`). Client addresses and the 64-byte sanitized user-agent prefix are shown to every grant holder; the full user agent is never stored. Retention is the existing `events.retention_days` and `sessions.retention_days`; there is no export. Viewers see the same personal data as administrators (a read-only role, not a reduced-data role).

Out of scope for M4-min: managing providers, applications, blacklists or grants from the console; OpenAPI; API tokens or break-glass credentials; audit of reads; CSV export; a session's geolocation; per-page rate limits beyond the concurrency cap.

## Consequences

### Positive

- No second authentication system: no passwords, hashes, bootstrap tokens, lockout logic or account store for administrators; the console inherits every M1 guarantee (binding, lifetimes, revocation on `authz_version`, logout everywhere) and every M5 one (second factors, step-up) without changes.
- The trust boundary is the handle, not the gateway: a request that bypasses the gateway, a route without `auth`, or a forged identity header never yields an administrator; the console fails closed to `403`.
- One mechanism for bootstrap, recovery and revocation (the CLI against the store), taking effect without a restart.
- No JavaScript, no build chain, no new dependency; the portal's templates, i18n, CSRF and security headers are reused as they are.
- Every administrative change has its record in the same transaction, attributable to a user or to the CLI.

### Negative

- The console is only reachable after the gateway's protected route for the console host exists, with the standard `auth` block and **without** `strip_request_cookies`; copying the default application fragment breaks it (the drift report and `--check` say so).
- Before M5 an administrator session is single-factor; the mitigations are the provider's own second factor, `admin.max_auth_age`, the short lifetimes and strict binding of the implicit application.
- Non-browser API clients need a browser-obtained cookie until API tokens exist.
- A grant is a user id: an administrator who loses their provider account loses the console; recovery is the CLI granting another user.
- Listing by `display_name` substring scans the users table (bounded by `limit` and documented); a large directory would need a dedicated index or a search column later.

### Neutral

- Contract: the gateway contract gains one sentence (the console route must not strip Hopae cookies) and no new header, status or cookie; the contract version stays 1.1.
- Follow-ups recorded in the roadmap: grants and provider management from the console (M4), API tokens (M4), read audit and export (backlog), `hopae gateway render` printing the console fragment (M2 phase 1).
- The architecture's data model replaces the `admins` sketch with `admin_grants`; the threat model's TM-15 is rewritten and TM-42 to TM-45 are added with flow C.

## Alternatives considered

| Alternative | Why not |
| --- | --- |
| A path on the portal host (`https://auth.example.test/admin/`) using the portal handle | The portal is the highest-exposure origin Hopae has; administrator pages would share its origin, cookie jar and CSP with the login flow, and the portal handle carries the `default` policy (24 h idle, no per-host binding choice). A separate host gets its own `__Host-` cookie, its own route (and whatever the gateway can put in front of a route: address policy, country policy) and its own lifetimes. The maintainer also asked for a host. |
| Trust the gateway's injected identity headers at the admin listener | Trustworthy only if the listener is reachable solely through the gateway; on the reference deployment (host network) any local process can connect, and the gateway cannot add a static secret to an upstream request. A caller key for upstreams does not exist (HC-3 is auth-call only). The handle is a credential the listener can verify itself. |
| A public route (no `auth`) with the admin listener running its own login start, handoff redemption and entry points | Duplicates the gateway adapter's rendering of `Login`, `Handoff`, `Switch` and the entry points for one host, with a second set of transaction-creating paths exposed to the internet; the protected route gives all of it for free and the listener only confirms. |
| Separate administrator accounts with passwords (the M4 sketch; the gateway's model) | A second credential system with its own bootstrap token, hashing, lockout, reset and lockout-recovery story, weaker than the provider login it would sit next to (no second factor at all); the project would audit two login paths. |
| Administrator allowlist in the configuration file (`admin.users: [emails]`) | Read at start only (no reload before M6): revocation would need a restart, and a file and a table would be two writers of one fact (ADR-0012's rule). Seeding grants from the file at start, like providers, is possible later as an import with `managed_by`; the CLI covers bootstrap now. |
| Authorization by group membership (`users.groups` contains `hopae-admins`) | Groups come from providers or policy in M2+ and are not operator-managed today; a grant row is explicit, attributable and revocable on its own. Groups can map to grants later. |
| Static SPA plus JSON API | Needs a build chain or vendored scripts, a `script-src` in the CSP, a second i18n mechanism and a CSRF token round trip; the pages needed are tables and confirmation forms, which the portal's server-rendered pattern already does. The JSON API exists anyway for scripts. |
| Password or TOTP re-prompt at the console for step-up | A second factor is M5 (`Factor` trait); building a one-off here would be a parallel path. `admin.max_auth_age` plus provider-side second factors bridge the gap. |
| Audit every read | Floods the event table with one row per page view, under the same retention as security events; reads are bounded to grant holders and left unaudited in M4-min, recorded as a residual. |
| Disable only changes status and lets `on_authz_change` decide about sessions | A `refresh` application would keep the disabled user's sessions listed as live until their next verify denies them; terminating them with the status change keeps the session list truthful and makes re-enable require a fresh login. |

## Adversarial review

Not yet reviewed; this ADR is Proposed. The review context file will be recorded internally.

| Pass | Date | S1 | S2 | S3 | S4 | Outcome |
| --- | --- | --- | --- | --- | --- | --- |
| — | — | — | — | — | — | Pending |

Questions for the reviewer:

- Is the direct-connection residual (TM-42: a local process with a stolen console handle can present a chosen client address) acceptable, or must the admin listener refuse peers that are not the gateway even though it cannot authenticate the gateway?
- Is a `viewer` that sees every client address and email a reduced role or a mislabeled one?
- Should a grant also require `email_authoritative`, so that a mailbox reassigned at a non-authoritative provider cannot inherit a grant through `primary_email`?

## References

- [Administration](../ADMIN.md) — user guide and specification of the console and the API
- [Architecture — components, trust boundaries, data model](../ARCHITECTURE.md#data-model)
- [Threat model — TM-15, TM-42 to TM-45, flow C](../THREAT_MODEL.md#threat-catalogue)
- [Configuration reference — keys decided and scheduled](../CONFIG.md#keys-decided-and-scheduled)
- [Gateway contract — Hangang route fragments](../GATEWAY_CONTRACT.md#hangang-route-fragments)
- [ADR-0004](0004-session-model-and-cross-domain-handoff.md), [ADR-0007](0007-context-binding-policy.md), [ADR-0008](0008-second-factor-extension-point.md), [ADR-0009](0009-event-model.md), [ADR-0010](0010-provider-abstraction.md), [ADR-0013](0013-gateway-adapter-boundary.md), [ADR-0015](0015-app-host-entry-points-and-upstream-cookie-stripping.md)
- Scenarios 300–305

## 한국어 요약

관리 콘솔과 API는 세 번째 리스너(`listen.admin`, 기본 `127.0.0.1:8702`)에서
Hopae 자신이 제공하는 애플리케이션입니다. `admin.public_url`로 등록되는 예약
애플리케이션 `admin`은 게이트웨이의 보호 라우트(표준 `auth` 블록, 단
`strip_request_cookies` 없음)를 통해 M1의 로그인·핸드오프·로그아웃 흐름을 그대로
씁니다. 관리 리스너는 게이트웨이가 주입한 신원 헤더를 절대 읽지 않고 모든 요청을
`__Host-hopae` 핸들로 verify 엔진을 통해 직접 인증합니다. 관리자는 별도 계정이
아니라 `admin_grants` 테이블(역할 `admin`/`viewer`)에 행이 있는 일반 사용자이며,
부트스트랩과 복구는 `hopae admin grant|revoke|list` 명령으로 합니다. 페이지는
스크립트 없는 askama 템플릿(영어/한국어)이고 같은 핸들러가 `/v1` JSON API를
제공하며, 모든 변경은 행위자 재검사와 함께 같은 트랜잭션에서 `admin.*` 이벤트로
기록됩니다. M5 이전에는 `admin.max_auth_age`와 제공자 측 2단계 인증으로 보완합니다.
