# ADR-0004: Server-side sessions, host-only handle cookies and a browser-bound single-use cross-domain handoff

- Status: Accepted
- Date: 2026-10-09
- Deciders: designer, orchestrator
- Scenarios: 001, 002, 003, 005, 006, 009, 010
- Threat model: TM-01, TM-02, TM-03, TM-04, TM-05, TM-13, TM-20, TM-21, TM-22, TM-26
- Supersedes: none
- Amended by: [ADR-0014](0014-handoff-recovery-on-any-rejected-code.md) (recovery depth on every rejected known code; codes carry the transaction's client IP)

## Context

- The portal lives on its own host (`auth.example.test`). Protected applications may live on other registrable domains (`other.example.org`), so no cookie set by the portal is ever presented to those hosts.
- The gateway's verify call copies the application host's `cookie` header to Hopae and can relay a `302` with `set-cookie` to the browser without contacting the upstream (`forward_response`, verified in `src/proxy.rs` `authorize`, 2026-10-09). It cannot run code on the application host.
- Revocation must be immediate and global (logout everywhere, administrator revocation, binding mismatch) — a self-contained signed cookie cannot provide that without a denylist.
- Return URLs are a classic open-redirect vector; the gateway supplies the original URL on every verify call, but its authority is still client-selected on host-neutral routes (review finding R14).
- A handoff code bound only to host, path and client IP can be redeemed by any browser behind the same NAT, which allows login CSRF by session swapping (review finding R02). The handoff needs a secret that only the browser that started the login holds on the target host.
- The portal cannot observe an application host's cookies, so it can never prove that the browser finishing a transaction is the one that started it on the application host; the only defense against a code being delivered to a hostile destination is that destinations are exactly the hosts the operator registered and serves through the gateway (review finding N03). Suffix patterns admit dangling subdomains.
- Browsers open several tabs; a transaction or binding cookie that each new login replaces makes concurrent logins fail each other (review finding N07). Elevation that leaves earlier handoff codes alive lets a pre-elevation code mint an elevated handle (review finding N01).

## Decision

Sessions are server-side. The browser holds only opaque **handles**, one per
host, and the portal transfers a session to a new host with a single-use
**handoff code** that can be redeemed only by the browser that holds the
matching **binding cookie** on that host.

| Element | Definition |
| --- | --- |
| Session | One row per browser login: user, provider, `auth_time`, satisfied factors, `aal`, binding context, lifetimes, termination reason, `authz_version` of the user at snapshot time. Carries an identity snapshot so verify needs no joins beyond the user status check. |
| Handle | `v1.` + base64url(32 CSPRNG bytes); stored as SHA-256; bound to exactly one (session, host); carries `issued_aal`, `created_at`, `last_seen_at`, `absolute_expires_at`. Cookie `__Host-hopae` with `Path=/; Secure; HttpOnly; SameSite=Lax`; `Max-Age` = remaining handle lifetime. The portal host holds a handle too (the "portal handle"). |
| Binding cookie | `__Host-hopae_bind` = base64url(16 CSPRNG bytes), a **stable per-browser secret on the application host**: planted by the unauthenticated `302` that starts a login (document navigations only) when the request carries no well-formed bind, otherwise the existing value is kept and its `Max-Age=600` refreshed. `Path=/; Secure; HttpOnly; SameSite=Lax`. Every transaction for that host stores the same `bind_sha256`, so concurrent tabs share it. It is never cleared or replaced by a redemption, a failure or a non-document response; it expires by `Max-Age`. "Well-formed" means length and alphabet; Hopae cannot tell a server-issued value from one pre-seeded by script on the same host, which is same-host trust. |
| First-use race and recovery | Two tabs that start before either response arrives receive different binds and the last response wins, so one tab's code no longer matches the jar. Recovery is graceful and bounded: when a document navigation presents a code whose `bind_sha256` does not match the presented bind **and** the browser holds no valid handle for that host, Hopae burns the code and answers the ordinary unauthenticated `302` to a new transaction that keeps the presented bind, with `recovery_depth = code.recovery_depth + 1`; the portal completes it by single sign-on and mints a code bound to the current bind. **Depth provenance is server-side only:** a transaction's depth is copied into every code it mints (`handoff_codes.recovery_depth`), a recovery transaction takes its depth from the failed code's row, and no client input is ever read for it. When `code.recovery_depth` already equals `handoff.max_recoveries` (default 3), Hopae creates no transaction and answers a relayed **`403`** with a small HTML body and `x-hopae-reason: handoff_recovery_exhausted` that asks the user to retry once their cookies settle; on the gateway listener this is never a `2xx`, because an unmodified gateway treats any `2xx` as an allow ([ADR-0005](0005-gateway-contract-and-versioning.md), review finding N16). No loop can form. The portal cookie has the same race: when a callback presents a well-formed `__Host-hopae_portal` that differs from the transaction's recorded digest, the transaction is consumed, the presented cookie's digest is stored on it as `retry_bind_sha256`, and a CSRF-protected "sign-in was interrupted" page offers one `POST /login/retry` that starts a new transaction for the same return target at depth + 1 (the provider round trip repeats, normally instantly). A callback that completes while the browser already holds a valid portal handle for the same user reuses that session instead of creating a second one. |
| Portal binding cookie | `__Host-hopae_portal` = base64url(16 CSPRNG bytes), a stable per-browser secret on the portal host, planted at first portal contact and refreshed (`Max-Age=600`). Each transaction records `portal_bind_sha256` **at the moment its provider redirect is issued** (the chooser `POST` or the single-provider auto-redirect) and the digest is immutable afterwards, so a later lure visit cannot re-bind an attacker's transaction to a victim's browser; the provider callback and every portal `POST` require the cookie to match the digest of the transaction they act on. The one deliberate exception is `POST /login/retry`: it acts on a transaction already consumed by `portal_bind_mismatch` and must match that transaction's `retry_bind_sha256` (the replacement cookie the interrupted page was rendered to) together with the CSRF token issued on that page; the new transaction it creates records the replacement cookie at its own provider redirect. There is no per-transaction portal cookie, so several transactions can be open in several tabs. |
| Login transaction | 128-bit random id carried in the `txn` query parameter only; stores the return target from `x-original-url`, the application, client IP, UA digest, `bind_sha256`, `portal_bind_sha256`, chosen provider, `state` digest, `nonce`, PKCE verifier, purpose (`login`, `stepup`, `link`, `switch`), `conflicting_handle_sha256` (for `switch`), `recovery_depth`. The callback locates the transaction by `state`. Consumed once. |
| Handoff code | 32 CSPRNG bytes, stored as SHA-256; bound to (session, target host, target path, client IP, `bind_sha256`); records `issued_aal` (the session's level when the code was minted), `cred_gen` (the session's credential generation at that time) and `recovery_depth` (copied from the minting transaction); 60 s lifetime; consumed by an atomic conditional update. Delivered as `?_hopae_handoff=<code>` appended to the return target. |
| Reserved parameter recognition | The query is parsed as `application/x-www-form-urlencoded` pairs; a pair whose **decoded** name equals `_hopae_handoff` (so `%5Fhopae%5Fhandoff` is the same parameter) is the handoff parameter. More than one such pair, or a pair with a malformed percent escape in its name, makes the request ambiguous: nothing is redeemed and the request is denied (`handoff_ambiguous`). The same rule is the gateway's cache-bypass rule ([ADR-0006](0006-verify-caching-and-invalidation.md)). |
| Redemption rule | Only a document navigation redeems. A **non-document** request that carries the reserved parameter is terminated before any upstream dispatch with `403 {"error":"handoff_parameter_not_allowed"}`, whatever cookies it carries, and leaves the code and every cookie untouched (the gateway would otherwise forward the query, code included, to the upstream — review finding N13). Verify redeems when: the code is unexpired and unconsumed; host and path match; the client IP matches; `__Host-hopae_bind`'s SHA-256 equals the code's `bind_sha256`; `cred_gen` equals the session's current generation (checked inside the consuming update); and the request carries **no** valid `__Host-hopae` of a different user. The new handle's `issued_aal` is `min(code.issued_aal, session.aal)`: redemption never raises a grant. A valid handle of the same session is replaced. A valid handle of another user answers `302` to the portal's `/switch` page (purpose `switch`, below) and burns the code. If the request carries a **consumed** code together with a valid handle of the same session (a prefetch or a retried navigation redeemed it already), verify answers the clean `302` without touching cookies (`code_already_redeemed`). Any other failure burns the code and answers the unauthenticated `302` (which keeps the existing bind). |
| Account switch | On `session_conflict` the portal shows a CSRF-protected confirmation naming the host and both accounts. Confirming revokes the presented handle (possession of a handle authorizes revoking it, as logout does), mints a fresh code for the new session and redirects; declining returns to the clean URL as the existing user. Nothing switches silently. |
| Lifetimes | Per handle: `apps[].session.idle` (default 12 h) and `apps[].session.absolute` (default 7 d). Per session: `session.idle` (default 24 h, measured from the newest `last_seen_at` of any handle including the portal's) and `session.absolute` (default 30 d). The state machine is in [ADR-0007](0007-context-binding-policy.md). `last_seen_at` writes are coalesced to one per 30 s per handle. |
| Termination, revocation and generations | Session reasons: `logout`, `logout_all`, `idle`, `absolute`, `binding_ip`, `binding_ua`, `admin`, `user_disabled`, `blocked`, `key_rotation`, `authz_change`. Handle reasons: `idle`, `absolute`, `binding_ip`, `binding_ua`, `elevation`, `switch`, `session_terminated`. Every revocation and every elevation increments `sessions.cred_gen` and marks all outstanding handoff codes of the session consumed, in one transaction; termination revokes every handle and publishes an invalidation message (M2). |
| Single sign-on | When the portal holds a valid portal handle whose session passes the portal's binding policy, `/login?txn=` skips the provider and mints a handoff code for the transaction's host and `bind_sha256` immediately; `auth_time` is not refreshed. With `portal.sso_confirm_new_host = true` (default `false`) the portal first shows a one-click confirmation naming the destination host the first time this session is handed off to it. |
| Return target | Only from `x-original-url` of the verify call that created the transaction; validated: absolute; scheme `https` (or `http` only with `cookie.secure=false`); host equals `x-forwarded-host`; **host and port are an exact entry of the return-origin allowlist**; ≤ 2048 bytes; no userinfo; no fragment. Emitted only as `Location` toward that origin. |
| Return-origin allowlist | Exactly the registered applications' `hosts` entries, which are **exact host names only** (lower-case, no wildcard, no pattern), with port 443 (or 80 in insecure mode) and any `apps[].ports` listed explicitly. Registering a host asserts that it is served through the gateway; a registered host whose DNS no longer points at the gateway is an open credential destination, which the phase-1 drift check reports ([ADR-0012](0012-service-registration-and-gateway-config-ownership.md)). There is no "any host" mode and no suffix mode: a host that is not listed is denied with `unknown_app` before any transaction is created. The `default` application carries policy defaults, not hosts. |
| Cookie scope | Host-only. `SameSite=Lax` for every cookie; no `Domain=` mode; no `Strict` option (the portal → application redirect is a cross-site top-level navigation). |

Handoff on an application host, step by step:

1. Verify recognizes the handoff parameter under the recognition rule and strips it to obtain the target. Caching, if any, is bypassed before this step (ADR-0006). A non-document request is answered `403 handoff_parameter_not_allowed` here and goes no further.
2. It consumes the code atomically under the redemption rule above (one conditional update that also checks `cred_gen`; in PostgreSQL both this update and the elevation transaction lock the session row). On failure: the unauthenticated `302` to a new transaction, which keeps the existing bind and carries the recovery depth; event `handoff.rejected` with the reason.
3. It mints a handle for (session, host) with `issued_aal = min(code.issued_aal, session.aal)`, answers `302 Location: <target>` with `Set-Cookie: __Host-hopae=<handle>` and `Cache-Control: no-store`. The bind cookie is left as it is.

Clients that cannot perform a document navigation (the `401` path) receive the
application URL itself as the `login` target: opening it in a browser is the
document bootstrap that plants the bind and starts a transaction. No
transaction is created for a `401`. Browserless clients are out of scope
until the API-client mode (M7).

Out of scope for this ADR: step-up policy (ADR-0008), binding evaluation
rules and the lifetime state machine (ADR-0007), the wire details (ADR-0005).

## Consequences

### Positive

- Immediate, global revocation by construction: verify consults the session on every request.
- A leaked cookie from one host is useless on another; a leaked portal cookie is useless on application hosts.
- A handoff code is useless to anyone but the browser that started that login on that host, so NAT neighbours cannot swap sessions; an existing session of another user is never silently replaced.
- `__Host-` prefix eliminates cookie tossing from sibling subdomains; no return URL is ever accepted from a client; no return origin exists without an operator-written pattern.
- Works on an unmodified gateway: the binding cookie and the handoff ride on the verify call and the relayed `302`.

### Negative

- Every new host costs one extra redirect pair, and a login started in one browser cannot be finished in another (by design).
- A browser that blocks cookies on the application host cannot log in; the failure page says so.
- Every protected host must be registered by exact name; wildcard hosts are not supported for login.
- The code is visible in the URL for up to 60 s and appears in the gateway's access log; mitigated by single use, binding and `referrer-policy: no-referrer` on the relayed response.
- A reserved query parameter name exists on every protected application.

### Neutral

- Logout everywhere, administrator revocation and session listing (M2) are termination of rows; no new mechanism.
- A `Domain=` cookie mode for sibling subdomains is recorded in the backlog, not planned.

## Alternatives considered

| Alternative | Why not |
| --- | --- |
| Signed or encrypted cookie carrying the identity (stateless) | No immediate revocation without a denylist that is itself server state; larger cookies on every request; key rotation invalidates everyone. |
| One `Domain=example.test` cookie | Fails for applications on other registrable domains; exposes the session to every sibling subdomain (TM-02). |
| Handoff bound to host, path and client IP only (the G1 draft) | Rejected after review finding R02: any browser behind the same NAT can redeem the code within 60 s and have the victim's cookie replaced by the attacker's session. |
| Per-host callback path `/_hopae/callback` instead of a query parameter | Requires every protected route to include that path; a route protecting only `/admin` would need a second route; the query-parameter form rides on the already-protected URL. Native interception (HC-5) can add a path form later. |
| Code delivered in a URL fragment and planted by JavaScript | The portal must work without JavaScript; the gateway cannot see fragments. |
| Same handle on every host | A leak on one host compromises all hosts; per-host revocation impossible. |
| Trusting `x-original-url`'s host because the gateway generated it | Rejected after review finding R14: on host-neutral routes the authority is still chosen by the client's `Host` header. |
| `*.suffix` host patterns in the return-origin allowlist (the pass-1 revision) | Rejected after review finding N03: a dangling subdomain under the suffix becomes a credential destination; the portal cannot verify bind possession across hosts, so destination trust must be exact. |
| Per-transaction bind and portal cookies replaced on every login (the pass-1 revision) | Rejected after review finding N07: concurrent tabs invalidate each other; a stable per-browser secret per host supports many transactions. |
| Proving bind possession at the portal | Impossible without a round trip through the destination, which is the handoff itself; replaced by exact destinations and the optional first-handoff confirmation. |

## Adversarial review

| Pass | Date | S1 | S2 | S3 | S4 | Outcome |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | 2026-10-09 | 1 | 2 | 1 | 0 | 4 × FIX_FIRST applied (R02, R14, R15, R16) |
| 2 | 2026-10-09 | 2 | 3 | 1 | 0 | R02, R16 CLOSED; R14, R15 PARTIAL → N03, N10; new N01 (shared), N06, N07, N08, N12 (shared): all FIX_FIRST applied |
| 3 | 2026-10-09 | 0 | 2 | 0 | 0 | R14, R15, N01, N03, N06, N08, N12 CLOSED; N07 PARTIAL (first-use race) → FIX applied; new N13 → FIX applied. Awaiting confirmation pass. |
| 4 | 2026-10-09 | 1 | 0 | 2 | 0 | N13 CLOSED; new N16 FIX_FIRST applied (exhaustion is a relayed `403`, never `2xx`); S3 residuals specified (retry-cookie rule, depth provenance on codes); "burning a known live code forces one retry" accepted as residual availability exposure. Awaiting confirmation pass. |

Findings and dispositions:

- N16 (S1, pass 4): the recovery-exhaustion page was a `200` on the gateway listener, which an unmodified gateway treats as an allow. FIX_FIRST: exhaustion is a relayed `403` with a small HTML body; the gateway-listener status invariant of ADR-0005 forbids any non-allow `2xx`; scenario 003-A13 is a gateway-layer case asserting zero upstream requests; scenario 004-11 asserts the invariant across every non-allow path.
- Residual (S3, pass 4): `POST /login/retry` now matches the consumed transaction's `retry_bind_sha256` plus its page's CSRF token, the one stated exception to "every portal `POST` matches the transaction's digest"; recovery depth is carried on codes and never read from the client.

- N07 (S2, pass 3, first-use race): two tabs starting before either cookie response arrives receive different binds and the last one wins; the same at first portal contact. FIX: depth-bounded graceful recovery on both hosts (`bind_mismatch` without a valid handle → ordinary unauthenticated `302` keeping the presented bind, portal SSO re-hands-off; `portal_bind_mismatch` → retry page starting a new transaction); `handoff.max_recoveries`; portal digest recorded at provider-redirect time; scenarios 003-9, 003-A13, 002-7.
- N13 (S2, pass 3): a non-document request with a valid handle and the reserved parameter was allowed, so the gateway forwarded the code upstream. FIX: terminated with a relayed `403 handoff_parameter_not_allowed` before upstream dispatch; code and cookies untouched; scenario 003-7 gains the valid-handle variant.

- N01 (S1, pass 2, shared with ADR-0008): a code minted before elevation redeemed afterwards received the elevated level. FIX_FIRST: codes carry `issued_aal` and `cred_gen`; elevation consumes outstanding codes; redemption never raises a grant; scenario 003-A11 races both orders.
- N03 (S1, pass 2): a dangling host under a `*.suffix` pattern could receive a victim's code; the portal cannot prove bind possession. FIX_FIRST: exact registered hosts only; optional first-handoff confirmation; drift check for registered hosts not served by the gateway; scenario 005 rewritten.
- N06 (S2, pass 2): the `401` login URL started a transaction that could never hand off. FIX_FIRST: `401` creates nothing and names the application URL as the document bootstrap; scenario 001-4.
- N07 (S2, pass 2): per-transaction cookies broke concurrent tabs; failures reset binds; prefetch left a consumed code in the navigated URL. FIX_FIRST: stable per-host bind and stable portal binding cookie, transactions located by `state`, document-only redemption, binds never cleared by responses, idempotent `code_already_redeemed`; scenarios 003-6, 003-7, 002-A1/A5.
- N08 (S2, pass 2): `session_conflict` had no legitimate exit. FIX_FIRST: CSRF-protected `/switch` confirmation that revokes the presented handle on consent; scenario 003-A10 and 006-7.
- N10 (S2, pass 2): scenario contradictions on cookie lifetime and portal validity. FIX_FIRST: scenarios 009-1 and 010 fixtures corrected.
- N12 (S3, pass 2, shared with ADR-0006): encoded parameter aliases escaped recognition. FIX_FIRST: one decoded-name recognition rule with ambiguity rejection, used by redemption and by HC-1 bypass; scenarios 003-2 and 003-A12.

- R02 (S1): handoff codes allowed session swapping between browsers behind one IP. FIX_FIRST: browser binding cookie on the application host, `bind_sha256` in the code, never replace another user's valid handle; scenarios 003-A9 and 003-A10.
- R14 (S2): `allow_default` let a host-neutral route redirect to an attacker-chosen authority. FIX_FIRST: explicit return-origin allowlist from application host patterns and ports; `allow_default` removed; scenario 005-3 rewritten.
- R15 (S2, shared with ADR-0007): per-host expiry contradicted session-wide termination. FIX_FIRST: handles carry their own timers; session timers are separate; state machine in ADR-0007; scenario 010 rewritten.
- R16 (S3): `SameSite=Strict` would break the cross-site SSO navigation. FIX_FIRST: no `same_site` option; `Lax` fixed.

Open for the reviewer: whether `portal.sso_confirm_new_host` should default
to `true`; whether binding the code to the client IP in addition to the bind
cookie should follow the application's `binding.ip` mode; whether
`handoff.max_recoveries = 3` is the right bound for slow networks.

## References

- [Architecture — Flows 1–8](../ARCHITECTURE.md#request-flows)
- [Gateway contract — Cookies, Cross-domain handoff](../GATEWAY_CONTRACT.md#cookies)
- RFC 6265bis (`__Host-` prefix, `SameSite`), RFC 9113 §8.2.3 (cookie joining).

## 한국어 요약

세션은 서버에만 저장하고, 브라우저는 호스트마다 하나씩 발급되는 불투명 핸들만
`__Host-hopae` 쿠키로 보관합니다. 로그인을 시작하는 미인증 `302`가
애플리케이션 호스트에 브라우저별로 안정적인 바인딩 쿠키(`__Host-hopae_bind`)를
심고, 로그인이 끝나면 돌아갈 URL에 붙인 일회용 핸드오프 코드는 그 바인딩
쿠키를 가진 브라우저만, 문서 탐색으로만 소비할 수 있습니다. 코드는 발급 시점의
인증 수준과 세션의 자격 증명 세대를 기록하므로 단계 상승 전에 만든 코드로
상승된 핸들을 얻을 수 없습니다. 돌아갈 URL은 게이트웨이가 만든
`x-original-url`에서만 가져오되, 정확히 등록된 호스트와 포트로만 이루어진 허용
목록 안에 있어야 하며 와일드카드는 없습니다. 다른 사용자의 세션은 조용히
바꿔치기되지 않고 확인 페이지를 거칩니다.
