# ADR-0015: Application-host entry points are served by Hopae through the verify call, and the gateway strips Hopae cookies from upstream requests

- Status: Proposed
- Date: 2026-10-09
- Deciders: designer, orchestrator
- Scenarios: 015, 006 (link target answered), 004 (11 extended)
- Threat model: TM-01, TM-03, TM-38, TM-39, TM-40, TM-41
- Supersedes: none (extends the contract of [ADR-0005](0005-gateway-contract-and-versioning.md) to v1.1; ADR-0005 stays Accepted and links here)

## Context

- M1 is deployed behind the reference gateway and a real provider login works end to end. Two live findings follow.
- An application has no way to offer "sign in" or "sign out" on its own host: `https://app.example.test/_hopae/logout` is an ordinary protected URL today and reaches the upstream, which answers `404`. The only logout surface is the portal's `GET /logout` on `auth.example.test`, and scenario 006 left "a documented link target for applications" as an open question. The gateway cannot host the entry points itself: its Lua API has no redirect, response header or `set-cookie` ([contract](../GATEWAY_CONTRACT.md#what-works-on-an-unmodified-hangang-026)), and the native change HC-5 is optional and not built. Every verify call already carries what an entry point needs: the canonical path, `x-original-url`, the host's cookies and the fetch metadata.
- The upstream receives `Cookie: __Host-hopae_bind=…; __Host-hopae=…` on every authenticated request (seen on the reference deployment's echo upstream). The handle is a replayable credential for that host that outlives the request; an application that logs request headers, or a compromised one, holds it. The gateway copies the whole `cookie` header upstream and has no cookie filter on the upstream side (HC-4 filters the auth call only).
- Two invariants bound the design: on the gateway listener Hopae answers `2xx` only for an authenticated allow ([ADR-0005](0005-gateway-contract-and-versioning.md), TM-38), and the portal never accepts a return URL from the client (TM-01). Logout CSRF is a tracked threat (TM-03): `GET /logout` only renders a form and a cross-site `<img>` changes nothing (scenario 006-A4).
- The gateway matches route prefixes byte-exactly (TM-39); Hopae's own path rules compare the canonical path ASCII-case-insensitively.

## Decision

Hopae serves two entry points on every protected application host from inside the verify call, reserves the `/_hopae/` namespace on those hosts, and the gateway change HC-12 removes Hopae's cookies from the request it forwards upstream.

1. **Reserved namespace.** On the gateway listener, a request whose canonical path ([ADR-0013](0013-gateway-adapter-boundary.md)) equals `/_hopae` or starts with `/_hopae/`, compared ASCII-case-insensitively, is reserved. Exactly `/_hopae/login` and `/_hopae/logout` (same comparison; no trailing slash) are the entry points. Every other reserved path is answered `403 {"error":"reserved_path"}` (`x-hopae-reason: reserved_path`) without touching state or cookies, so `/_HOPAE/logout`, `/_hopae/%6Cogout` (canonicalized), `/_hopae/logout/` and `/_hopae/verify` never reach the upstream. Reserved-path recognition runs after the return-target and application checks (an unlisted host is still `unknown_app`) and before reserved-parameter recognition; on a reserved path the handoff parameter is not redeemed and not consulted. An application route under `/_hopae/` is unsupported. The namespace exists only on protected application hosts: the portal host answers `404` as for any unknown path.
2. **Entry points never answer `2xx`.** A non-document request (any `sec-fetch-dest` other than `document`, or no HTML `accept`) to either entry point is `403 {"error":"reserved_path"}` with `x-hopae-reason: entry_point_not_document`, no `set-cookie`, no transaction. A document navigation is answered by a relayed `302` or a `403`. The upstream is never contacted (TM-38; scenario 004-11's enumeration gains these paths).
3. **Return target.** The target of an entry point is the request origin's `/`, or the single query parameter `return` (recognized like the reserved parameter: form-urlencoded pairs, decoded name exactly `return`; two such pairs are ambiguous). `return` is either a path-absolute reference (`/path?q`, resolved against the request origin) or an absolute URL; the result must pass the ordinary return-target validation **and** have exactly the request's scheme, host and port (the same registered origin, not merely a registered one), must not carry the reserved handoff parameter, and its canonical path must not be reserved. Anything else is `403 {"error":"return_not_allowed"}` (`return_not_allowed`), with no transaction created. The target is stored in a transaction and travels to the portal as `txn=<id>`; no URL is ever passed to the portal in the clear (TM-01).
4. **Login entry point.** `GET /_hopae/login[?return=]` as a document navigation is evaluated exactly as a verify of the target URL would be (handle, timers, binding policy, user status, application policy). An outcome that would be `200` is answered `302 Location: <target>` with no cookie change (`x-hopae-reason: already_authenticated`); every other outcome is the ordinary one for a document navigation — the unauthenticated `302` to the portal with the binding cookie planted and the transaction's `return_target` set to the target, a denial `403`, a step-up `302` — so the handoff after login lands on the target, never on the entry point.
5. **Logout entry point, confirmation mode (default).** `GET /_hopae/logout[?return=]` as a document navigation evaluates the presented handle as an ordinary verify would (a binding mismatch terminates as usual; an invalid handle is cleared as on every `302`), then creates a transaction with purpose `logout` — the **logout ticket**: `return_target`, `app_id`, `client_ip`, `ua_sha256`, `bind_sha256` (informational) and `portal_session_id` = the session of the valid handle presented, or none — under the same per-IP and table caps as login transactions, and answers `302 Location: https://auth.example.test/logout?txn=<id>` (`x-hopae-reason: logout_entry`). **The handle is not cleared and nothing is revoked at this step.** The portal's `GET /logout?txn=` renders the existing confirmation form naming the application, plants or refreshes `__Host-hopae_portal`, records its digest on the ticket at this first visit (immutable afterwards, as login transactions do at their provider redirect) and binds the CSRF token to the portal handle when one is presented, otherwise to the portal binding cookie. `POST /logout` with `txn` requires `Origin`, the CSRF token, and that the presented portal binding cookie match the ticket's digest; it consumes the ticket (single use; `expires_at` is the transaction lifetime, 600 s) and terminates both the session of the valid portal handle, when one is presented, and the ticket's `portal_session_id` session, when it names one — usually the same session — with `reason=logout`, clears the portal cookie and answers `200` with the portal's signed-out page. **It does not redirect to the protected return target**: that would start a login, and a provider with a live session would sign the user straight back in. The page instead shows a "Sign in again to <application display name>" link to the ticket's `return_target`, which passes the ordinary return-target validation again when the page is rendered (no link is shown if it no longer validates). The page's form posts to the portal itself, so its `form-action` stays `'self'`. A ticket that is unknown, consumed, expired, of another purpose, or whose digest does not match the presented cookie is treated as absent: the page and the `POST` behave as the portal's plain `/logout` does today. `/login?txn=` rejects a logout ticket and `/logout?txn=` rejects any other purpose (`txn_purpose_mismatch`). The stale application-host cookie is cleared by the next verify on that host (scenario 006-3), which then requires login again.
6. **Why the `302` does not clear `__Host-hopae`.** Clearing the handle at the entry point would give no durable effect: the session stays alive at the portal, and the next document navigation on the host goes through the ordinary unauthenticated `302` and the portal's single sign-on, which plants a new handle without a click. It would, however, make a `GET` reachable by any cross-site top-level navigation (`SameSite=Lax` sends the cookie on those) and by speculative loads that present as document navigations (a prerender carries `sec-fetch-dest: document`; `sec-purpose` is not among the listed request headers) change the browser's state, and a user who abandons the confirmation would be bounced through the portal on their next visit. The only state change stays on the CSRF-protected `POST`, as for the portal's own `/logout` (TM-03, scenario 006-A4). The `403` for non-document requests carries no `set-cookie`, so a cross-site `<img src="/_hopae/logout">` changes nothing even though a `Set-Cookie` on such a response would be honored.
7. **No-confirmation mode.** `apps[].logout_confirm` (boolean, default `true`, inherited from `default`). With `false`, a document navigation to `/_hopae/logout` whose `sec-fetch-site` is exactly `same-origin` and that presents a valid handle terminates that handle's session at verify (`reason=logout`, event `session.terminated`), creates a logout ticket under the same caps and consumes it at once, and answers `302 Location: https://auth.example.test/signed-out?txn=<ticket>` with `Set-Cookie: __Host-hopae=; Max-Age=0` (`x-hopae-reason: logout`); the binding cookie is left as it is. The consumed ticket is the opaque, short-lived (600 s) reference to the return target for the portal's `GET /signed-out?txn=` page, which renders the same "Sign in again" link; the query never carries a URL (TM-01), and the page only answers for a ticket of purpose `logout` that a logout consumed. The session is terminated before the ticket is written, so a rate-limited ticket (`txn_rate_limited`) cannot keep a logout from taking effect. Any other request to the entry point — `sec-fetch-site` absent, `none`, `same-site` or `cross-site`, or no valid handle — takes the confirmation flow of decision 5. This is CSRF-safe because `sec-fetch-site` is a forbidden header name that browsers compute over the whole redirect chain, so only a document on the application origin itself can produce `same-origin`, which is same-host trust; `same-site` is excluded because a malicious sibling subdomain is an actor in the threat model. The mode only reduces access and never mints anything.
8. **HC-12.** Route-level field `strip_request_cookies: ["__Host-hopae", "__Host-hopae_bind"]` (the configured handle and binding cookie names), set on every route that reaches an application upstream, public routes of a path-scoped host included, because the browser sends `Path=/` cookies to those too (review pass 1, F1); `auth.strip_request_cookies` stays accepted as an alias. After the external-authorization call, which still receives the unmodified `cookie` header, and after every other header change (the last step before dispatch), the gateway removes every `name=value` pair whose name equals a listed name byte-exactly from the joined `cookie` header of the upstream request, keeps every other pair unchanged and in order, and drops the header when nothing remains or when the header is ambiguous (quoted values, whitespace-only separators); `cookie` is rejected as an identity output. Acceptance criteria are in the [contract](../GATEWAY_CONTRACT.md#proposed-gateway-changes). HC-12 is required on production routes like HC-3; `hopae --check` prints it in the route fragment; an unmodified gateway rejects the key.
9. **Path-scoped protection.** A host whose protected route covers only a prefix never sends `/_hopae/*` to Hopae. The contract's path-scoped fragment gains a third route, `site-hopae` (`path_prefix: "/_hopae"`, `segment_prefix`, higher priority, same `auth` block; its backends are never reached). Until HC-10, case variants such as `/_HOPAE/logout` on such a host fall through to the public route like any other prefix (TM-39); whole-host protection has no such gap. Operators who do not add the route rely on the portal's own `/logout`.

10. **Handoff delivery (review pass 1, F2).** Every handoff Hopae mints is delivered to `https://<host>/_hopae/login?return=<clean target path and query>&_hopae_handoff=<code>`, for every flow (the ordinary login `302`, single sign-on, the account switch, recovery). Delivery to the target itself depended on the target's path being routed to Hopae: on a path-scoped host a default `/` or an explicit public target selects the public route, where the code is never redeemed and reaches the upstream. `/_hopae/login` is always answered by Hopae (whole-host route, or `site-hopae`). Redemption there applies the unchanged ADR-0004 rules with the validated `return` as target (the code records the target's path; a mismatch is `code_path_mismatch`), plants the handle and answers `302` to the clean target. In `return` only `%`, `&`, `+`, `#` and space are percent-encoded; the adapter's URL bound for the reserved namespace is `3 × 2048 + 512` bytes (plus the 46-byte handoff pair, as before), so a target of the full 2048 bytes still fits and one over it is `return_not_allowed`. The handoff parameter stays ignored on every other reserved path, including `/_hopae/logout`. Redemption on a protected route's own path remains accepted but is no longer minted.
11. **Residual risks accepted explicitly (review pass 1, F3, F6).** `logout_confirm = false` is opt-in and trusts the application's own origin: a same-origin navigation gadget in the application (a page that assigns a URL from its own query to `location`, for example `/continue?next=/_hopae/logout`) starts a new same-origin navigation that presents `sec-fetch-site: same-origin` and ends the session without a click; fetch metadata does not preserve the provenance of navigations a loaded document starts. The mode stays, `hopae --check` warns for every application that sets it, and the default keeps the confirmation. The logout ticket is a transferable revocation capability: a ticket nobody opened can be handed to another person, whose first visit binds it to their browser; their confirmation ends the session the ticket names (the creator's own) and their own portal session, nothing else, only reducing access (scenario 015-A9).
12. **Cache bypass (review pass 1, F5, future HC-1).** The decision cache key excludes the path, so with HC-1 lookup and fill must be bypassed for the whole canonical, ASCII-case-insensitive `/_hopae` namespace, or an ordinary cached allow would forward `/_hopae/logout` upstream without Hopae answering it.

Contract version: the entry points add reason codes, a reserved namespace on application hosts and an optional route field; this is contract **v1.1** (minor) with a `Changed` note in the CHANGELOG for the reserved namespace.

Out of scope: a native gateway implementation (HC-5 stays optional and must match this behavior), per-application entry-point paths, an application-branded logout landing page (the portal's signed-out page is fixed), listing `sec-purpose` among the forwarded headers.

## Consequences

### Positive

- Every application gets `href="/_hopae/logout"` and `href="/_hopae/login?return=/where"` without a gateway change or any application code beyond the link; the behavior is identical on every host and never reaches the upstream.
- The session handle and the binding cookie stop reaching applications; a request log or a compromised upstream no longer holds a replayable credential (TM-40).
- The logout ticket lets a browser whose portal handle expired still end the session it holds on the application host, without a new credential: the ticket is single use, browser-bound at the portal and only ever reduces access.
- Both invariants hold by construction: no new `2xx` on the gateway listener; the portal still never reads a return URL from the client.

### Negative

- `/_hopae/*` is unusable by applications on protected hosts; an existing route under it breaks (`403 reserved_path`).
- After logout the user lands on the portal's signed-out page, not in the application; one more click ("Sign in again to <application>") starts a login. The alternative, a redirect to the return target, would start the login at once and a provider with a live session would re-authenticate silently. The signed-out page is on the portal host, so an application cannot brand it.
- With `logout_confirm=false`, an application that prerenders its own logout URL (speculation rules with `eagerness: moderate` or broader) logs its users out on hover: Hopae cannot distinguish a same-origin prerender from a click until `sec-purpose` is forwarded. The default stays `true`.
- Route fragments change again (HC-12) on every protected route; the preflight fragment and the deployment template follow.

### Neutral

- The `login_txns` purpose set gains `logout`; the portal gains a `txn`-aware confirmation page and `POST` and the read-only `GET /signed-out`; scenario 015 maps the tests; 004-11 enumerates the new non-allow outcomes.
- Every handoff is delivered to `/_hopae/login`, which makes path-scoped hosts depend on the `site-hopae` route for login completion, not only for the entry points: without it a handoff reaches the public route. The redirect pair (one extra hop on the application host) is the price of never depending on the target's route.
- Direct mode (`logout_confirm = false`) accepts same-origin navigation gadgets (decision 11); an unopened logout ticket can be passed to another person (decision 11).
- The logout ticket's consumption and the termination of the session it names (with its event) are one store write: a failure or crash between them leaves the ticket unconsumed and the session live, and the retry still logs out (code review G7 pass 1, F1).
- Transaction admission is one store write: the per-address cap, the eviction down to `txn.max_rows` and the insert happen together (login, retry, logout tickets, and the post-authentication switch and link transactions, which skip only the per-address cap), so `txn.max_rows` is a hard bound and the cap cannot be overshot by concurrent callers.
- Forwarding `sec-purpose` (to ignore prefetch and prerender at every entry point) is a candidate contract minor for a later release, recorded in the roadmap backlog.
- HC-5, if ever built, must reproduce decisions 1–7 exactly; its acceptance criteria already say so.

## Alternatives considered

| Alternative | Why not |
| --- | --- |
| Clear `__Host-hopae` on the logout entry's `302` (the brief's recommendation) | No durable effect (single sign-on re-plants the handle on the next navigation); a state change on a `GET` reachable by cross-site top-level navigation and by prerender; a user who abandons the confirmation is bounced through the portal. Decision 6. |
| Revoke the handle server-side at the logout entry | Same reachability as above with a durable, unconfirmed effect on a `GET`; contradicts scenario 006-A4. The no-confirmation mode offers this deliberately and only for `same-origin`. |
| Pass the return URL to the portal as a query parameter | Breaks the TM-01 invariant that the portal never reads a return URL from the client; the ticket carries it server-side like every login transaction. |
| Accept `same-site` for the no-confirmation mode | A malicious sibling subdomain is an actor in the threat model; `same-origin` keeps the trust boundary at the host the `__Host-` cookie already draws. |
| No-confirmation mode as a one-time portal hop that logs out on the portal's `GET` | A state-changing `GET` at the portal keyed only by a ticket; more moving parts than terminating at verify, where the valid handle already proves possession. |
| A separate `logout_tickets` table | `login_txns` already has every column, the caps, the pruning and the portal-binding digest; purpose `logout` is one enum value. |
| Answer `401 login_required` to non-document requests on `/_hopae/login` | Invites scripts to treat an entry point as an API; one deterministic `403` for both entry points and the rest of the namespace is simpler and creates nothing. |
| Ignore an invalid `return` and fall back to `/` | Hides application bugs and still writes a transaction; the project fails closed everywhere else. |
| Redirect to the return target after the confirmed logout (the first design) | Starts a login at once; a provider with a live session signs the user back in silently, so the logout looks like it did nothing (orchestrator ruling, applied before implementation). The portal's signed-out page with a link replaces it. |
| Pass the return target to the signed-out page as a query parameter | Breaks TM-01; the consumed logout ticket is the opaque reference. |
| Wait for HC-5 (native gateway entry points) | Optional, not built, and would still need this ADR's rules to be identical; the verify call already has every input. |
| HC-4 instead of HC-12 | HC-4 filters what the auth service receives; the upstream still gets every cookie. Both can coexist. |

## Adversarial review

Not yet reviewed; this ADR is Proposed. The review context file will be recorded internally.

| Pass | Date | S1 | S2 | S3 | S4 | Outcome |
| --- | --- | --- | --- | --- | --- | --- |
| — | — | — | — | — | — | Pending |

## References

- [Gateway contract — Application-host entry points, Proposed gateway changes (HC-12)](../GATEWAY_CONTRACT.md#application-host-entry-points)
- [Threat model — TM-40, TM-41](../THREAT_MODEL.md#threat-catalogue)
- [ADR-0004](0004-session-model-and-cross-domain-handoff.md) (transactions, handles, single sign-on), [ADR-0005](0005-gateway-contract-and-versioning.md) (status invariant), [ADR-0013](0013-gateway-adapter-boundary.md) (canonical path)
- Fetch Metadata Request Headers (`Sec-Fetch-Site`, `Sec-Fetch-Dest`; forbidden header names), RFC 6265bis (`SameSite=Lax`, `__Host-`), RFC 9113 §8.2.3 (cookie joining)

## 한국어 요약

보호된 애플리케이션 호스트마다 `/_hopae/login`과 `/_hopae/logout`을 Hopae가
verify 호출 안에서 직접 처리하고, `/_hopae/` 이름 공간을 예약하여 어떤
변형(대소문자, 인코딩, 하위 경로)도 업스트림에 도달하지 않게 합니다. 응답은
언제나 중계되는 `302`나 `403`이며 `2xx`는 없습니다. 로그아웃 진입점은 쿠키를
지우지 않고 서버 측 로그아웃 티켓(목적 `logout`인 트랜잭션)과 함께 포털의
확인 페이지로 보내며, CSRF로 보호된 `POST`만이 세션을 끝낸 뒤 같은 출처로
제한된 돌아갈 대상 대신 포털의 로그아웃 완료 페이지를 보여 주며(보호된 대상으로
리디렉션하면 로그인이 바로 시작되어, 살아 있는 세션을 가진 제공자가 사용자를 조용히
다시 로그인시키기 때문), 페이지에는 검증된 대상으로 가는 "다시 로그인" 링크가
있습니다. `apps[].logout_confirm=false`는
`sec-fetch-site: same-origin`인 문서 탐색에 한해 확인 없이 verify에서 바로
세션을 종료하고, 소비된 티켓을 불투명한 참조로 삼아 포털의 로그아웃 완료 페이지로
리디렉션합니다(쿼리에 URL 없음). 모든 핸드오프는 대상 경로의 라우팅에 의존하지 않도록 항상
`/_hopae/login?return=<대상>&_hopae_handoff=<코드>`로 전달되고 거기서 교환됩니다.
`logout_confirm=false`는 옵트인이며 애플리케이션 자신의 같은 출처 탐색 가젯을 위험으로
받아들이고(`--check`가 경고), 열어 보지 않은 로그아웃 티켓은 다른 사람에게 넘길 수
있는 취소 권한입니다. 게이트웨이 변경 HC-12는 인증 호출 뒤에 업스트림 요청의
`cookie` 헤더에서 Hopae 쿠키만 제거합니다.
