# Native Hangang verification and delegated console

<!-- doc-rev: 3 -->

[한국어](ko/HANGANG_NATIVE.md) · [Documentation](README.md)

Provider-independent integration now includes a native verification listener and
an operator-installed console package. Providers, OIDC state/code exchange,
credentials, identity/session decisions and native administration remain in Hopae.
The optional unified console mode delegates console authority to Hangang.
Hangang owns the console shell and request enforcement; no Lua is required for
native login/logout entry handling.

## HOP1 verification

Optional `listen.native_gateway` enables a literal loopback TCP address, distinct
from other bound listeners. Unauthenticated caller mode is refused. Keep the
ordinary HTTP gateway available for existing clients and diagnostics.

Each frame has `HOP1` (4 bytes), request ID (u64 big endian) and payload length
(u32 big endian). Maximum payload is 128 KiB. Handshake ID zero carries the
configured gateway caller key (up to 4096 bytes); its one-byte reply is 1/0.
After authentication, request IDs are positive and strictly increasing per
connection. A request carries u16 header count and repeated u16 name length,
u32 value length, name bytes and value bytes. A response adds u16 HTTP status
before that block and u32 body length plus body after it. Header/body bytes and
duplicate cookies are preserved; limits are 64 headers, 64 KiB header block,
128-byte names, 16 KiB values and 64 KiB body.

No supplied caller-key header is accepted inside request frames. Hopae injects
the authenticated key and invokes the existing verify router, including its
current caller check, canonical parsing, session/app/binding/assurance checks,
concurrency/verify deadline and rendering. Bad versions, sizes, framing, keys or
replayed IDs close the connection. Handshake is bounded to 2 s, idle reads to
30 s and response writes to 5 s, with at most 256 admitted connections.

Hangang's `auth.native` prepares a persistent bounded pool and shares its normal
HTTP result processing. Saturation rejects immediately, canceled exchanges close
the socket and failures do not fall back to HTTP or retry an ambiguous entry.
This removes repeated connection/header serialization overhead; it does not
remove authoritative session checks or establish a 100k-QPS identity claim.

## Trusted console package

Run `python3 tools/build_console_plugin.py`. Install `plugins/hopae` into the
Hangang registry with reviewed manifest SHA-256, a fixed Hopae admin origin,
`delegate_actor:true` and a dedicated `token_env` key. The package provides
status, paginated users/sessions/events, user enable/disable, user session recall
and individual session termination. Native theme tokens and host authentication
are used; package code receives no backend key or raw Hangang credential.

Enable `admin.hangang_delegation` explicitly:

```json
{"key_env":"HOPAE_CONSOLE_DELEGATION_KEY"}
```

The key (32–4096 bytes) is dedicated to this trusted issuer/backend pair. It is
not the verification caller key. Delegated requests must originate from loopback
and carry an HMAC-SHA256 assertion with operator ID/name, timestamp (10 s window),
random nonce, exact method/path, body digest, native handle digest and signed
client IP/User-Agent. Unknown assertion fields, duplicates, tampering and queries
are rejected. A bounded durable nonce database in `state_dir` rejects replay
across restarts; full/unavailable admission fails closed.

### Browser session mode

Set the Hopae admin public origin to the Hangang console origin and configure the
host package's `delegation_cookie` to the Hopae handle cookie name. Configure the
reserved `/_hopae/` routes through native forward-auth; the package's login link
uses `/_hopae/login?return=/ui/`. Providers perform authentication through Hopae.
A signed Hangang actor and an independently valid Hopae admin handle/grant are
both required. Hangang admin status never automatically grants Hopae access.
Signed client context must come from a trusted transport/relay; it does not come
from plugin JavaScript. Keep direct plaintext adapter access restricted.

### Explicit paired-session mode

Optional `sessions_file` points to an absolute private regular file (0600, no
symlink) with at most 128 mappings. Each entry has `actor_id`, `actor_name`,
`user_id`, native Hopae `handle`, `client_ip` and optional `user_agent`.
Operators pair an existing Hopae admin session; the file contains a credential
and must never be published. Replacing it can revoke a mapping immediately.
There is no automatic session creation or copied user/session database. Native
session expiry requires renewed pairing. Browser mode avoids this private file.

## Authorization and audit

The adapter translates only registered reads and bounded `{id}` mutations into
existing native admin routes. Paginated reads accept only cursor/limit with native
cursor validation. It reconstructs trusted headers, then enters the existing
peer/host/handle/grant/freshness/assurance and CSRF middleware. Native role and
transactional actor fence/self-target checks are retained. Provider secrets and
raw handles are never returned to the package.

Native mutation audit records the Hopae actor/session plus `delegated_issuer`,
`delegated_actor` and `delegated_operation`. Hangang separately records durable
intent/outcome. Parent revocation is checked before dispatch and disclosure,
but a separately accepted operation can finish; no cross-service atomic revocation
claim is made. Ambiguous writes need state inspection before retry.

## Qualification

Codec truncation/trailing/size tests, native/HTTP parity against real SQLite
sessions, native login/logout confirmation behavior, revoked sessions, wrong keys,
caller injection, replayed IDs, pool cancellation/reconnect/saturation and duplicate
cookies are covered. Real provider-login tests cover delegated reads/mutations,
self-target rejection, actor audit, native grant revocation, browser handles and
bounded pagination. Privacy, durable nonce replay and unsafe files are checked.
Deployments still need their own network restrictions, provider/grant configuration,
full end-to-end load evidence and recovery checks before broad automatic rollout.

Native release qualification covers static Linux amd64/arm64 and macOS Intel/Apple Silicon. Release artifacts include the reviewed console package. Hopae currently has no signed supervised auto-updater; release packaging does not imply that capability.

SQLite jobs bound lock retries against an absolute monotonic deadline. OS sleep overshoot cannot accumulate into extra retries; handlers and default busy state are restored after bounded jobs, including panic unwinding.

## Unified console authority (explicit opt-in)

Configure `admin.hangang_delegation.authority: "hangang"` and the host binding's
`delegation_authority: "hangang"`; omit the binding's `delegation_cookie` and any
`sessions_file`. This mode follows Hangang's enabled administrator session and
role instead of requiring a second Hopae administrator login. The pinned package
uses host authentication metadata to hide its separate login/logout controls.
Default `native` mode and standalone Hopae routes keep existing native grants.
Unified mode follows Hangang assurance policy rather than imposing the native
Hopae administrator grant/AAL/freshness policy on local Hangang logins. Its `me`
response marks Hangang authority and does not invent native login time or AAL.

The signed assertion must explicitly contain `authority: "hangang"`; native
assertions cannot be interpreted as unified authority. The broker rechecks the
Hangang account before dispatch/disclosure. Hopae accepts only loopback, dedicated
HMAC-key authentication, exact allowed method/path/body, durable single-use nonce,
and a proof younger than five seconds. The store transaction verifies the proof
and synthetic actor/session binding again, including current key availability.
An external actor is represented by a stable issuer-derived synthetic user ID and
per-request synthetic session ID; audit also records the actual Hangang actor
ID/name and issuer. These IDs create no Hopae user/session/grant rows. Self-target
checks refer to that issuer identity; external administrators can manage Hopae
identities without pretending to be a native Hopae user. Changes already accepted
by another authority cannot provide atomic cross-system revocation.

Hangang's optional `--hopae-sso` broker adds an SSO button beneath ID/PW. Hopae
keeps Google/OIDC credentials and login flows. Stable Hopae IDs are explicitly
mapped to existing enabled Hangang accounts; Hangang applies their current role.
Every SSO request verifies the native Hopae cookie and client binding. Browser
bearers are opaque and cannot authenticate directly at the parent admin API;
private parent leases last five seconds and are reused for at most one second.
No account/grant is automatically created. See Hangang's `CONSOLE_PLUGINS.md` for
configuration, callback/CSRF checks and restart/logout behavior.

## Authentication gateway implementation status

The OIDC outbound client now owns bounded per-provider-origin circuits shared across cloned fetchers. Three backend failures open a circuit for 30 seconds; a single half-open exchange probes recovery. Transport/timeouts, incomplete or oversized responses, HTTP 429 and HTTP 5xx count as backend failures. Ordinary HTTP 400/401/403 credential denial does not count as an outage. A cancelled exchange records failure and releases its probe; generation-bound, non-copyable permits prevent a stale completion from closing a newer circuit. Abandoned probes expire. At most 16 origins are retained per provider client; capacity and poisoned state fail closed. Paths, query strings, credentials and authorization codes never form circuit keys. Failed HTTP/TLS client initialization also fences exchanges rather than sending through an unrestricted fallback.

This protects actual discovery, JWKS, token and user-info exchanges. Cached discovery/JWKS continue to obey their existing hard validity deadlines; a circuit never authenticates a request or extends credential validity. Circuit state is process-local and resets when the provider client is rebuilt; dedicated console controls, persistent quarantine and fleet coordination remain pending.

The authentication-gateway core also defines namespaced human/service/workload/network subjects and bounded Any/All evidence composition. It rejects expired, duplicate, unknown and conflicting evidence, including equal subject strings from different realms. Evidence is not constructible from public request claims. These composition types are a foundation, not a wired connector or new login method. LDAP, local passwords, API relay/introspection, network identity, explicit cross-provider links and service-bound credential translation remain implementation work. Multiple OIDC providers remain the currently working external authentication connectors.
