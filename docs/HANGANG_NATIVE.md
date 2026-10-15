# Native Hangang verification and delegated console

<!-- doc-rev: 6 -->

[한국어](ko/HANGANG_NATIVE.md) · [Documentation](README.md)

Console package 0.1.4 adds an authentication-profile overview from the active
DB document: service, realm, native-key count/relay, issuer namespaces, relay
prefix, Lua eligibility and missing-credential session fallback. The JSON editor
updates a local preview; saving still uses the existing revision-checked owner
publication. The preview is not server validation. Read-only users cannot edit
or save, and all displayed values use text nodes. Credential material is never
part of the overview. English/Korean guidance explains DB-over-bootstrap priority
and deterministic mixed routing without changing native authorization checks.

Provider-independent integration now includes a native verification listener and
an operator-installed console package. Providers, OIDC state/code exchange,
credentials, identity/session decisions and native administration remain in Hopae.
The optional unified console mode delegates console authority to Hangang.
Hangang owns the console shell and request enforcement; no Lua is required for
native login/logout entry handling.

## HOP1 verification

Optional `listen.native_gateway` enables a literal TCP address, distinct
from other bound listeners. Remote addresses require the mTLS configuration below. Unauthenticated caller mode is refused. Keep the
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

## Native remote mTLS listener

`listen.native_gateway_tls` takes absolute `certificate`, `key` and `client_ca` PEM paths. Outside loopback, `listen.native_gateway` requires this configuration; `0.0.0.0` can bind an authenticated remote listener. TLS material is limited to 1 MiB per file and loaded before readiness. An empty client CA or invalid certificate/key rejects startup. The server requires a certificate chaining to the configured client CA, negotiates ALPN `hop1`, disables TLS early data, and still requires the existing gateway caller-key handshake. TLS never replaces caller authorization.

TLS handshakes have a 3-second bound within the existing 256-connection limit. Persistent connections expire after 300 seconds; frame and verification bounds remain unchanged. Plaintext remains available only on literal loopback for migration. Hangang's remote TLS client configuration and deployment qualification are follow-up work; this server-side change does not by itself enable remote Hangang use.

[Service authentication gateway](AUTH_GATEWAY.md) documents the opt-in API-key/network runtime and remaining connector/authorization work.

## Request-bound final dispatch candidate

`tools/service_stack_smoke.py --grpc --resource-catalog --native-resource
--durable-restart` qualifies Hangang's opt-in `auth.native_resource` with actual
Hopae/Pumgye/Sumunjang debug processes and an HTTP origin. Ephemeral issuer/trust
and native live-validation resources are fixture owned. The origin receives
composed `/api/secure` and nonempty bytes without the API credential. Wrong
pin/issuer/audience and an exceeded body budget refuse before origin dispatch;
configuration restoration, network/permission/class/AAL/service refusal, outages
and durable permission/authentication withdrawal pass. The old gRPC resource
fixture without this option passes too. These are local candidate functional
gates; signed release, Kubernetes/operating adoption, signed permission/projection
and throughput remain separate qualifications.

## Live gateway route owner qualification

The owned four-process fixture supports `--route-owner` together with `--grpc
--resource-catalog --native-resource`. It starts the private Hangang observation
listener and configures Pumgye's fixed mTLS client. Actual native references and
destination hashes reach Pumgye, whose before/after queries validate owner scope
and IP. Wrong server identity and wrong caller credential refuse without origin
effects; recovery succeeds. Optional `--legacy-pumgye-binary` replaces only the
owned permission process with a compatible older executable and proves that a
missing route acknowledgement cannot silently downgrade gateway enforcement.

The complete debug four-server case passes with durable permission/profile
withdrawal and authority outages. Existing no-owner mode also passes. All keys,
identities and state are generated in private owned temporary directories. These
are local source functional checks, not static release, Kubernetes, operating
adoption, signed permit/projection/replay or throughput qualification.

## Native projection-plan observation

`ProjectionPlans/Observe` shares the mandatory-mTLS gateway gRPC listener and
requires an accepted gateway caller credential. It reports only the native
compiled plan's service, audience, resource, action, minimum AAL and revision.
It never resolves or returns a secret reference or credential. The reply has
zero cache TTL and grants no access. Pumgye's signed permission issuance still
needs its own authenticated owner client and final retirement checks.

The service captures an ArcSwap reader at startup. Requests use memory only,
with shared bounded admission and 512/1024-byte request/reply transport limits.
Publication fences the previous snapshot before SQL mutation; exact rollback
can reopen it, successful replacement retires it, and uncertain commit leaves
it fenced until durable reload. Native owner and handler tests cover these
boundaries. An owned real mTLS socket also proves absent-plan refusal, native
publication, successful observation, wrong caller refusal and withdrawal on the
same retained channel. This alone does not qualify cross-process permit or projection.

The owned fixture also supports `--projection-owner` with `--native-resource`.
It bootstraps an owned native plan, enables Pumgye's fixed mTLS plan client,
and passes actual four-server final dispatch with route ownership, durable
permission/profile withdrawal and authority outages. Wrong Hopae server name
and caller credential refuse without origin effects; restoration succeeds.
This mode cannot be combined with a legacy Pumgye binary. It exercises native
plan checks, not signed projection permits or upstream credential issuance.

`--permit-issuance` requires both `--route-owner` and `--projection-owner`. It
creates an independent owned Pumgye permit-purpose key and explicitly starts the
gateway configuration at revision 1. The key seed stays in the private fixture
environment; the route carries only the public pin. The fixture exercises actual
`ProjectionPermits/Issue` and gateway verification, including wrong public key,
issuer and epoch refusal/restoration. This mode does not exercise Hopae paired
replay admission or projected upstream credentials.

The complete local permit-issuance case passes with actual final URI/entity
routing, independent signature pins, recovery and durable withdrawal/outages.
It qualifies signed evidence issuance and gateway checks; receiver consumption
and upstream credential projection remain open. The no-permit plan-owner mode
is checked separately for compatibility.

Hangang b326f03 now requires Pumgye b4b7f18's `ProjectionPermits/Validate` after
local permit signature checks in this mode. It reuses the same admitted mTLS
channel and original elapsed timeout budget and adopts the shorter verified
owner deadline. The actual four-server permit and no-permit modes both pass,
including durable withdrawal and trust/outage refusals. Hopae receiver paired
replay and credential projection remain open; this validation is not consumption.
