# ADR-0004: Server-side sessions, host-only handle cookies and a single-use cross-domain handoff

- Status: Proposed
- Date: 2026-10-09
- Deciders: designer, orchestrator
- Scenarios: 001, 002, 003, 005, 006, 009, 010
- Threat model: TM-01, TM-02, TM-03, TM-04, TM-05, TM-13, TM-20, TM-21
- Supersedes: none

## Context

- The portal lives on its own host (`auth.example.test`). Protected applications may live on other registrable domains (`other.example.org`), so no cookie set by the portal is ever presented to those hosts.
- The gateway's verify call copies the application host's `cookie` header to Hopae and can relay a `302` with `set-cookie` to the browser without contacting the upstream (`forward_response`, verified in `src/proxy.rs` `authorize`, 2026-10-09). It cannot run code on the application host.
- Revocation must be immediate and global (logout everywhere, administrator revocation, binding mismatch) — a self-contained signed cookie cannot provide that without a denylist.
- Return URLs are a classic open-redirect vector; the gateway supplies the original URL on every verify call.

## Decision

Sessions are server-side. The browser holds only opaque **handles**, one per
host, and the portal transfers a session to a new host with a single-use
**handoff code** carried through the gateway's verify call.

| Element | Definition |
| --- | --- |
| Session | One row per browser login: user, provider, `auth_time`, satisfied factors, `aal`, binding context, idle and absolute expiry, termination reason. Carries an identity snapshot so verify needs no joins. |
| Handle | `v1.` + base64url(32 CSPRNG bytes); stored as SHA-256; bound to exactly one (session, host). Cookie `__Host-hopae` with `Path=/; Secure; HttpOnly; SameSite=Lax`; `Max-Age` = remaining absolute lifetime. The portal host holds a handle too (the "portal handle"). |
| Login transaction | 128-bit random id in cookie `__Host-hopae_txn` on the portal host (`Max-Age=600`) and in the `txn` query parameter; stores the return target from `x-original-url`, the application, client IP, UA digest, chosen provider, `state`, `nonce`, PKCE verifier, purpose (`login`, `stepup`, `link`). Consumed once. |
| Handoff code | 32 CSPRNG bytes, stored as SHA-256; bound to (session, target host, target path, client IP); 60 s lifetime; consumed by an atomic conditional update. Delivered as `?_hopae_handoff=<code>` appended to the return target. |
| Lifetimes | Per application: `idle` (default 12 h) and `absolute` (default 7 d); the portal session uses the strictest values among the applications it has handed off to, never longer than the global maximum (30 d). `last_seen_at` writes are coalesced to one per 30 s. |
| Termination | Reasons: `logout`, `logout_all`, `idle`, `absolute`, `binding_ip`, `binding_ua`, `admin`, `user_disabled`, `blocked`, `key_rotation`. Termination invalidates every handle of the session and publishes an invalidation message (M2). |
| Single sign-on | When the portal already holds a valid portal handle whose session passes the portal's binding policy, `/login?txn=` skips the provider and mints a handoff code immediately; `auth_time` is not refreshed. An application may require a fresh authentication (`max_auth_age`) and then the provider is consulted (later work). |
| Return target | Only from `x-original-url` of the verify call that created the transaction; validated: absolute, scheme `https` (or `http` only with `cookie.secure=false`), host equals `x-forwarded-host` and is a registered application host (or `apps.unregistered=allow_default`), ≤ 2048 bytes, no userinfo, no fragment. Emitted only as `Location` toward that host. |
| Cookie scope | Host-only in M1. No `Domain=` mode. |

Handoff on an application host, step by step:

1. Verify sees `_hopae_handoff` in `x-original-url`. It strips the parameter to obtain the target.
2. It consumes the code atomically; the row must be unexpired and match host, path and client IP. Otherwise: unauthenticated `302` to a new transaction, event `handoff.rejected`.
3. It mints a handle for (session, host), answers `302 Location: <target>` with `Set-Cookie: __Host-hopae=<handle>` and `Cache-Control: no-store`.

Out of scope for this ADR: step-up policy (ADR-0008), binding evaluation
rules (ADR-0007), the wire details (ADR-0005).

## Consequences

### Positive

- Immediate, global revocation by construction: verify consults the session on every request.
- A leaked cookie from one host is useless on another; a leaked portal cookie is useless on application hosts.
- `__Host-` prefix eliminates cookie tossing from sibling subdomains; no return URL is ever accepted from a client.
- Works on an unmodified gateway: the handoff rides on the verify call and the relayed `302`.

### Negative

- Every new host costs one extra redirect pair (portal → target with code → target).
- The code is visible in the URL for up to 60 s and appears in the gateway's access log; mitigated by single use, binding and `referrer-policy: no-referrer` on the relayed response.
- A reserved query parameter name exists on every protected application.
- Applications on plain HTTP cannot use `__Host-` cookies; development mode drops the prefix and documents the risk.

### Neutral

- Logout everywhere, administrator revocation and session listing (M2) are termination of rows; no new mechanism.
- A `Domain=` cookie mode for sibling subdomains is recorded in the backlog, not planned.

## Alternatives considered

| Alternative | Why not |
| --- | --- |
| Signed or encrypted cookie carrying the identity (stateless) | No immediate revocation without a denylist that is itself server state; larger cookies on every request; key rotation invalidates everyone. |
| One `Domain=example.test` cookie | Fails for applications on other registrable domains; exposes the session to every sibling subdomain (TM-02). |
| Per-host callback path `/_hopae/callback` instead of a query parameter | Requires every protected route to include that path; a route protecting only `/admin` would need a second route; the query-parameter form rides on the already-protected URL. Native interception (HC-5) can add a path form later. |
| Code delivered in a URL fragment and planted by JavaScript | The portal must work without JavaScript; the gateway cannot see fragments. |
| Same handle on every host | A leak on one host compromises all hosts; per-host revocation impossible. |
| Longer handoff lifetime or multi-use codes | Enlarges the replay window (TM-05) for no functional gain; prefetchers that consume the code are handled by the SSO path (a second transaction completes without the provider). |

## Adversarial review

| Pass | Date | S1 | S2 | S3 | S4 | Outcome |
| --- | --- | --- | --- | --- | --- | --- |
| — | — | — | — | — | — | Pending G2. |

Questions for the reviewer: can a browser prefetch or a link-preview bot
consume the handoff code before the user's navigation, and is the SSO
fallback sufficient? Is binding the code to the client IP too strict behind
carrier-grade NAT with rotating egress? Should the handle be rotated on
step-up?

## References

- [Architecture — Flows 1–8](../ARCHITECTURE.md#request-flows)
- [Gateway contract — Cookies, Cross-domain handoff](../GATEWAY_CONTRACT.md#cookies)
- RFC 6265bis (`__Host-` prefix, `SameSite`), RFC 9113 §8.2.3 (cookie joining).

## 한국어 요약

세션은 서버에만 저장하고, 브라우저는 호스트마다 하나씩 발급되는 불투명 핸들만
`__Host-hopae` 쿠키로 보관합니다. 포털 호스트에서 로그인이 끝나면 돌아갈 URL에
일회용 핸드오프 코드를 붙여 보내고, 게이트웨이의 verify 호출이 그 코드를
소비해 해당 호스트 전용 쿠키를 심습니다. 코드는 60초, 1회, 호스트·경로·IP에
바인딩됩니다. 돌아갈 URL은 클라이언트가 아니라 게이트웨이가 만든
`x-original-url`에서만 가져오므로 오픈 리디렉션이 성립하지 않습니다.
