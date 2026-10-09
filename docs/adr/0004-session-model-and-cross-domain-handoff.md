# ADR-0004: Server-side sessions, host-only handle cookies and a browser-bound single-use cross-domain handoff

- Status: Proposed
- Date: 2026-10-09
- Deciders: designer, orchestrator
- Scenarios: 001, 002, 003, 005, 006, 009, 010
- Threat model: TM-01, TM-02, TM-03, TM-04, TM-05, TM-13, TM-20, TM-21, TM-22, TM-26
- Supersedes: none

## Context

- The portal lives on its own host (`auth.example.test`). Protected applications may live on other registrable domains (`other.example.org`), so no cookie set by the portal is ever presented to those hosts.
- The gateway's verify call copies the application host's `cookie` header to Hopae and can relay a `302` with `set-cookie` to the browser without contacting the upstream (`forward_response`, verified in `src/proxy.rs` `authorize`, 2026-10-09). It cannot run code on the application host.
- Revocation must be immediate and global (logout everywhere, administrator revocation, binding mismatch) — a self-contained signed cookie cannot provide that without a denylist.
- Return URLs are a classic open-redirect vector; the gateway supplies the original URL on every verify call, but its authority is still client-selected on host-neutral routes (review finding R14).
- A handoff code bound only to host, path and client IP can be redeemed by any browser behind the same NAT, which allows login CSRF by session swapping (review finding R02). The handoff needs a secret that only the browser that started the login holds on the target host.

## Decision

Sessions are server-side. The browser holds only opaque **handles**, one per
host, and the portal transfers a session to a new host with a single-use
**handoff code** that can be redeemed only by the browser that holds the
matching **binding cookie** on that host.

| Element | Definition |
| --- | --- |
| Session | One row per browser login: user, provider, `auth_time`, satisfied factors, `aal`, binding context, lifetimes, termination reason, `authz_version` of the user at snapshot time. Carries an identity snapshot so verify needs no joins beyond the user status check. |
| Handle | `v1.` + base64url(32 CSPRNG bytes); stored as SHA-256; bound to exactly one (session, host); carries `issued_aal`, `created_at`, `last_seen_at`, `absolute_expires_at`. Cookie `__Host-hopae` with `Path=/; Secure; HttpOnly; SameSite=Lax`; `Max-Age` = remaining handle lifetime. The portal host holds a handle too (the "portal handle"). |
| Binding cookie | `__Host-hopae_bind` = base64url(16 CSPRNG bytes), planted on the **application host** by the unauthenticated `302` that starts a login (document navigations only), `Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=600`. The transaction stores `bind_sha256` for that host. Cleared by the redemption response. |
| Login transaction | 128-bit random id in cookie `__Host-hopae_txn` on the portal host (`Max-Age=600`) and in the `txn` query parameter; stores the return target from `x-original-url`, the application, client IP, UA digest, `bind_sha256`, chosen provider, `state`, `nonce`, PKCE verifier, purpose (`login`, `stepup`, `link`). Consumed once. |
| Handoff code | 32 CSPRNG bytes, stored as SHA-256; bound to (session, target host, target path, client IP, `bind_sha256`); 60 s lifetime; consumed by an atomic conditional update. Delivered as `?_hopae_handoff=<code>` appended to the return target. |
| Redemption rule | Verify redeems a code only when: the code is unexpired and unconsumed; host and path match; the client IP matches; the request carries `__Host-hopae_bind` whose SHA-256 equals the code's `bind_sha256`; and the request carries **no** valid `__Host-hopae` for a different user. A valid handle of the same user is replaced (re-handoff after elevation); a valid handle of another user rejects the code with `session_conflict` and leaves the existing cookie untouched. Any failure burns the code. |
| Lifetimes | Per handle: `apps[].session.idle` (default 12 h) and `apps[].session.absolute` (default 7 d). Per session: `session.idle` (default 24 h, measured from the newest `last_seen_at` of any handle including the portal's) and `session.absolute` (default 30 d). The state machine is in [ADR-0007](0007-context-binding-policy.md). `last_seen_at` writes are coalesced to one per 30 s per handle. |
| Termination and revocation | Session reasons: `logout`, `logout_all`, `idle`, `absolute`, `binding_ip`, `binding_ua`, `admin`, `user_disabled`, `blocked`, `key_rotation`, `authz_change`. Handle reasons: `idle`, `absolute`, `binding_ip`, `binding_ua`, `elevation`, `session_terminated`. Termination revokes every handle and publishes an invalidation message (M2). |
| Single sign-on | When the portal holds a valid portal handle whose session passes the portal's binding policy, `/login?txn=` skips the provider and mints a handoff code for the transaction's host and `bind_sha256` immediately; `auth_time` is not refreshed. |
| Return target | Only from `x-original-url` of the verify call that created the transaction; validated: absolute; scheme `https` (or `http` only with `cookie.secure=false`); host equals `x-forwarded-host`; **host and port are in the return-origin allowlist**; ≤ 2048 bytes; no userinfo; no fragment. Emitted only as `Location` toward that origin. |
| Return-origin allowlist | The set of origins Hopae may redirect to: every registered application's `hosts` entries (exact host names or `*.suffix` patterns such as `*.example.test`) with port 443 (or 80 in insecure mode) and any `apps[].ports` listed explicitly. There is no "any host" mode: the former `apps.unregistered = allow_default` is replaced by explicit patterns on the `default` application, and a host that matches no pattern is denied with `unknown_app` before any transaction is created. |
| Cookie scope | Host-only. `SameSite=Lax` for every cookie; no `Domain=` mode; no `Strict` option (the portal → application redirect is a cross-site top-level navigation). |

Handoff on an application host, step by step:

1. Verify sees `_hopae_handoff` in `x-original-url`. It strips the parameter to obtain the target. Caching, if any, is bypassed before this step (ADR-0006).
2. It consumes the code atomically under the redemption rule above. On failure: unauthenticated `302` to a new transaction (which plants a fresh binding cookie), event `handoff.rejected` with the reason.
3. It mints a handle for (session, host) with `issued_aal` = the session's current `aal`, answers `302 Location: <target>` with `Set-Cookie: __Host-hopae=<handle>`, `Set-Cookie: __Host-hopae_bind=; Max-Age=0` and `Cache-Control: no-store`.

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

## Adversarial review

| Pass | Date | S1 | S2 | S3 | S4 | Outcome |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | 2026-10-09 | 1 | 2 | 1 | 0 | 4 × FIX_FIRST applied (R02, R14, R15, R16) |

Findings and dispositions:

- R02 (S1): handoff codes allowed session swapping between browsers behind one IP. FIX_FIRST: browser binding cookie on the application host, `bind_sha256` in the code, never replace another user's valid handle; scenarios 003-A9 and 003-A10.
- R14 (S2): `allow_default` let a host-neutral route redirect to an attacker-chosen authority. FIX_FIRST: explicit return-origin allowlist from application host patterns and ports; `allow_default` removed; scenario 005-3 rewritten.
- R15 (S2, shared with ADR-0007): per-host expiry contradicted session-wide termination. FIX_FIRST: handles carry their own timers; session timers are separate; state machine in ADR-0007; scenario 010 rewritten.
- R16 (S3): `SameSite=Strict` would break the cross-site SSO navigation. FIX_FIRST: no `same_site` option; `Lax` fixed.

Open for the reviewer: a browser prefetch that consumes the handoff code
before the user's navigation now fails closed (the bind cookie travels with
prefetches too, so the prefetch succeeds and the navigation sees the planted
handle — confirm with real browsers at G8). Binding the code to the client IP
in addition to the bind cookie is kept; it can be relaxed per application later.

## References

- [Architecture — Flows 1–8](../ARCHITECTURE.md#request-flows)
- [Gateway contract — Cookies, Cross-domain handoff](../GATEWAY_CONTRACT.md#cookies)
- RFC 6265bis (`__Host-` prefix, `SameSite`), RFC 9113 §8.2.3 (cookie joining).

## 한국어 요약

세션은 서버에만 저장하고, 브라우저는 호스트마다 하나씩 발급되는 불투명 핸들만
`__Host-hopae` 쿠키로 보관합니다. 로그인을 시작하는 미인증 `302`가
애플리케이션 호스트에 바인딩 쿠키(`__Host-hopae_bind`)를 심고, 로그인이 끝나면
돌아갈 URL에 붙인 일회용 핸드오프 코드는 그 바인딩 쿠키를 가진 브라우저만
소비할 수 있습니다. 같은 IP의 다른 브라우저는 코드를 쓸 수 없고, 다른
사용자의 유효한 세션을 조용히 바꿔치기할 수도 없습니다. 돌아갈 URL은
게이트웨이가 만든 `x-original-url`에서만 가져오되, 등록된 애플리케이션 호스트
패턴과 포트로 이루어진 명시적 허용 목록 안에 있어야 합니다.
