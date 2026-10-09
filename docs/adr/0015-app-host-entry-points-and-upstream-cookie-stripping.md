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
5. **Logout entry point, confirmation mode (default).** `GET /_hopae/logout[?return=]` as a document navigation evaluates the presented handle as an ordinary verify would (a binding mismatch terminates as usual; an invalid handle is cleared as on every `302`), then creates a transaction with purpose `logout` — the **logout ticket**: `return_target`, `app_id`, `client_ip`, `ua_sha256`, `bind_sha256` (informational) and `portal_session_id` = the session of the valid handle presented, or none — under the same per-IP and table caps as login transactions, and answers `302 Location: https://auth.example.test/logout?txn=<id>` (`x-hopae-reason: logout_entry`). **The handle is not cleared and nothing is revoked at this step.** The portal's `GET /logout?txn=` renders the existing confirmation form naming the application, plants or refreshes `__Host-hopae_portal`, records its digest on the ticket at this first visit (immutable afterwards, as login transactions do at their provider redirect) and binds the CSRF token to the portal handle when one is presented, otherwise to the portal binding cookie. `POST /logout` with `txn` requires `Origin`, the CSRF token, and that the presented portal binding cookie match the ticket's digest; it consumes the ticket (single use; `expires_at` is the transaction lifetime, 600 s) and terminates both the session of the valid portal handle, when one is presented, and the ticket's `portal_session_id` session, when it names one — usually the same session — with `reason=logout`, then answers `302 Location: <return_target>` with the portal cookie cleared. A ticket that is unknown, consumed, expired, of another purpose, or whose digest does not match the presented cookie is treated as absent: the page and the `POST` behave as the portal's plain `/logout` does today. `/login?txn=` rejects a logout ticket and `/logout?txn=` rejects any other purpose (`txn_purpose_mismatch`). The stale application-host cookie is cleared by the next verify on that host (scenario 006-3), which then requires login again.
6. **Why the `302` does not clear `__Host-hopae`.** Clearing the handle at the entry point would give no durable effect: the session stays alive at the portal, and the next document navigation on the host goes through the ordinary unauthenticated `302` and the portal's single sign-on, which plants a new handle without a click. It would, however, make a `GET` reachable by any cross-site top-level navigation (`SameSite=Lax` sends the cookie on those) and by speculative loads that present as document navigations (a prerender carries `sec-fetch-dest: document`; `sec-purpose` is not among the listed request headers) change the browser's state, and a user who abandons the confirmation would be bounced through the portal on their next visit. The only state change stays on the CSRF-protected `POST`, as for the portal's own `/logout` (TM-03, scenario 006-A4). The `403` for non-document requests carries no `set-cookie`, so a cross-site `<img src="/_hopae/logout">` changes nothing even though a `Set-Cookie` on such a response would be honored.
7. **No-confirmation mode.** `apps[].logout_confirm` (boolean, default `true`, inherited from `default`). With `false`, a document navigation to `/_hopae/logout` whose `sec-fetch-site` is exactly `same-origin` and that presents a valid handle terminates that handle's session at verify (`reason=logout`, event `session.terminated`) and answers `302 Location: <target>` with `Set-Cookie: __Host-hopae=; Max-Age=0` (`x-hopae-reason: logout`); the binding cookie is left as it is. Any other request to the entry point — `sec-fetch-site` absent, `none`, `same-site` or `cross-site`, or no valid handle — takes the confirmation flow of decision 5. This is CSRF-safe because `sec-fetch-site` is a forbidden header name that browsers compute over the whole redirect chain, so only a document on the application origin itself can produce `same-origin`, which is same-host trust; `same-site` is excluded because a malicious sibling subdomain is an actor in the threat model. The mode only reduces access and never mints anything.
8. **HC-12.** Route field `auth.strip_request_cookies: ["__Host-hopae", "__Host-hopae_bind"]` (the configured handle and binding cookie names). After the external-authorization call, which still receives the unmodified `cookie` header, the gateway removes every `name=value` pair whose name equals a listed name byte-exactly from the joined `cookie` header of the upstream request, keeps every other pair unchanged and in order, and drops the header when nothing remains. Acceptance criteria are in the [contract](../GATEWAY_CONTRACT.md#proposed-gateway-changes). HC-12 is required on production routes like HC-3; `hopae --check` prints it in the route fragment; an unmodified gateway rejects the key.
9. **Path-scoped protection.** A host whose protected route covers only a prefix never sends `/_hopae/*` to Hopae. The contract's path-scoped fragment gains a third route, `site-hopae` (`path_prefix: "/_hopae"`, `segment_prefix`, higher priority, same `auth` block; its backends are never reached). Until HC-10, case variants such as `/_HOPAE/logout` on such a host fall through to the public route like any other prefix (TM-39); whole-host protection has no such gap. Operators who do not add the route rely on the portal's own `/logout`.

Contract version: the entry points add reason codes, a reserved namespace on application hosts and an optional route field; this is contract **v1.1** (minor) with a `Changed` note in the CHANGELOG for the reserved namespace.

Out of scope: a native gateway implementation (HC-5 stays optional and must match this behavior), per-application entry-point paths, a logout landing page, listing `sec-purpose` among the forwarded headers.

## Consequences

### Positive

- Every application gets `href="/_hopae/logout"` and `href="/_hopae/login?return=/where"` without a gateway change or any application code beyond the link; the behavior is identical on every host and never reaches the upstream.
- The session handle and the binding cookie stop reaching applications; a request log or a compromised upstream no longer holds a replayable credential (TM-40).
- The logout ticket lets a browser whose portal handle expired still end the session it holds on the application host, without a new credential: the ticket is single use, browser-bound at the portal and only ever reduces access.
- Both invariants hold by construction: no new `2xx` on the gateway listener; the portal still never reads a return URL from the client.

### Negative

- `/_hopae/*` is unusable by applications on protected hosts; an existing route under it breaks (`403 reserved_path`).
- After logout the browser is redirected to the return target, which immediately asks for login again; with a provider that re-authenticates silently the user may land back in the application within seconds. Applications that want a landing page return to a public route of a path-scoped host or link the portal's `/logout` instead.
- With `logout_confirm=false`, an application that prerenders its own logout URL (speculation rules with `eagerness: moderate` or broader) logs its users out on hover: Hopae cannot distinguish a same-origin prerender from a click until `sec-purpose` is forwarded. The default stays `true`.
- Route fragments change again (HC-12) on every protected route; the preflight fragment and the deployment template follow.

### Neutral

- The `login_txns` purpose set gains `logout`; the portal gains a `txn`-aware confirmation page and `POST`; scenario 015 maps the tests; 004-11 enumerates the new non-allow outcomes.
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
제한된 돌아갈 대상으로 리디렉션합니다. `apps[].logout_confirm=false`는
`sec-fetch-site: same-origin`인 문서 탐색에 한해 확인 없이 verify에서 바로
세션을 종료합니다. 게이트웨이 변경 HC-12는 인증 호출 뒤에 업스트림 요청의
`cookie` 헤더에서 Hopae 쿠키만 제거합니다.
