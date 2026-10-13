# Second-factor extensions

<!-- doc-rev: 13 -->

[Documentation](README.md) · [한국어](ko/SECOND_FACTOR_EXTENSIONS.md)

## Implementation status

Native TOTP enrollment and confirmation exist, including encrypted seeds,
owner authorization and durable counter fencing. The profile uses six digits,
SHA-1 and a 30-second period. Manual setup is available; QR provisioning,
recovery remain unfinished. Native browser TOTP step-up is implemented in source. Enrollment does not
raise a session's assurance. Google/OIDC login is separate from an authenticator
application generating a TOTP code.

`src/factor/external.rs` validates an external factor response against a trusted
challenge context. It is a parsing boundary, not an enabled connector, a
signature verifier or a replay store. No external factor HTTP route or Lua
factor runtime is enabled by this module. Existing external service API verifier
relays in [Authentication gateway](AUTH_GATEWAY.md) continue to issue service
identity at AAL 0; they cannot count as human second-factor evidence.

The native `external_transport` and `external_service` modules now provide an
HTTPS-authenticated receipt and schema-v6 atomic owner completion. Root configuration now compiles and publishes verifiers at startup;
external portal forms are now implemented; Lua runtime remains unavailable. Earlier
sections below record implementation stages; the latest owner section supersedes
their statement that durable external completion is absent.

## Native authority and extension boundary

Hopae owns challenge creation, identity binding, credential generations,
provider/configuration revisions, admission, expiry and final session issuance.
A connector can verify one configured factor. It cannot choose a user, service,
role, permission, AAL, response header or redirect destination. Pumgye owns
service access policy; Sumunjang network evidence can constrain authentication
but an IP allowlist alone is not a second factor.

Supported extension targets are native TOTP, future WebAuthn and external
verification APIs (push, organization MFA or other approved factors). The same
lifecycle must support enrollment, confirmation, challenge, verification,
revocation, recovery and circuit breaking. These targets are implementation
requirements, not a statement that all are currently available.

## External API contract

A configured HTTPS verifier receives only the server-owned challenge ID,
opaque user/session, exact service/factor, configuration revision and credential
generation, plus the response required by that factor. Endpoint, trusted CA,
authentication credential references and timeouts are administrator-owned.
Browser input cannot select a URL, issuer, header or secret reference. Disable
redirects and environment proxies; apply the existing relay destination and
DNS validation controls. Keep a dedicated bounded connection pool and circuit
per verifier/configuration revision. Neither OTP values nor authorization
credentials enter logs, traces, audit attributes or analytics exports.

The response has exactly these fields:

```json
{"active":true,"challenge":"c_test","user":"u_test","session":"s_test","service":"orders","factor":"partner-push","configuration_revision":7,"credential_generation":3,"proof_id":"proof_once","expires_at":4000}
```

Times are absolute Unix milliseconds; the example is not a live request.
Validation requires exact context matches, a nonzero configuration revision,
bounded identifiers, no duplicate/unknown fields and an 8 KiB maximum body.
Expiry must be after receipt, within the challenge lifetime and no later than
five seconds after exchange start. A separate monotonic elapsed duration also
must not exceed five seconds, including transport time. A clock rollback,
malformed response, wrong context or claimed assurance is an unavailable/error
result, not successful evidence. A context-valid `active:false` is rejection.
Network transport still needs to enforce its own total deadline and body limit
before buffering. Five seconds is an evidence bound, not a recommended timeout;
fast verifier profiles should use materially shorter deadlines.

The private, nonserializable `Evidence` value has no session authority. The
caller must authenticate the verifier transport and use the server's durable
challenge context. Parsing a browser-supplied JSON response is never sufficient.
Final commit must recheck the current context and enforce unique proof consumption
scoped to verifier authority/configuration, including replay across processes.
The validator does not implement those durable controls.

## Atomic completion and failures

One owner transaction must consume the pending challenge and TOTP counter or
external proof, check enrollment/provider/configuration/user revisions and
credential generation, append factor evidence, raise assurance under native
policy, advance credential generation, revoke old handles and outstanding
handoff codes, and create a replacement portal handle and audience-bound
handoff. An audit/outbox failure rolls back all state changes. A pre-elevation
handle never inherits assurance. Binding to the existing portal browser and
validated application return target is mandatory; arbitrary return URLs are
refused. Concurrent proof/counter use has exactly one winner.

Use process-wide and identity/challenge admission limits before provider calls.
Timeouts, malformed responses, overload and open circuits fail closed without
trying a weaker provider. Valid credential rejection is distinct from provider
failure. Recovery must be explicit, audited and rate limited, and cannot turn
an outage into an authentication bypass. Do not cache OTP decisions. Any future
external evidence cache is bounded by proof/challenge lifetime and policy
revision and must preserve single-use semantics.

## Lua extension design

Lua may orchestrate allowlisted connector calls and return a typed factor
outcome. It does not receive a database/session writer, environment lookup,
arbitrary filesystem/network access or raw upstream credential namespace.
Host functions supply only approved verifier references and bounded input.
Use instruction, memory, concurrency and total-time budgets; script errors,
exhaustion and cancellation deny completion. Scripts cannot mint `Evidence`,
set AAL or bypass native commit checks. Publish validated scripts as immutable,
revisioned snapshots and fence an in-flight challenge against policy changes.
An extension's factor independence and permitted assurance contribution are
native configuration, not a script assertion.

## Required qualification before activation

- Actual browser login to a protected service, step-up, elevated handoff and
  rejection of every previous handle/code.
- Concurrent OTP/proof use, enrollment revocation, user/provider disablement,
  configuration change and audit rollback during completion.
- Owned HTTPS verifier fixtures for accepted/rejected evidence, replay,
  cross-user/service challenges, malformed bodies, redirects, timeouts,
  overload, circuit recovery and cancellation.
- Lua budget escape attempts and forbidden host capabilities, plus publication
  races; recovery and key retention/rotation tests.
- Hangang console navigation and clear registration/step-up status without
  forwarding OTP seeds through the console delegation broker.

See [ADR-0008](adr/0008-second-factor-extension-point.md) for handle rotation
and [Authentication gateway](AUTH_GATEWAY.md) for existing relay behavior.

## Native atomic TOTP completion

The native `elevate_authorized` service now verifies a real TOTP code without
first consuming it and calls one owner transaction. This transaction consumes
an unexpired `stepup` transaction and the revision-fenced TOTP counter, appends
factor evidence, sets session/portal-handle AAL 2, advances credential generation,
revokes all old handles and outstanding handoffs, and inserts the new portal
handle and exact-target handoff. Primary provider authentication time is preserved.
Required proof/revocation/handoff audit and outbox writes share the transaction.

For native `stepup` transactions only, `conflicting_handle_sha256` binds the
initiating portal handle; it retains its existing meaning for other purposes.
The challenge must name the same session, application return target, browser
binding digest, client IP and recovery depth as the new handoff. OAuth provider,
state, nonce, PKCE and reauthentication metadata must be absent. Replacement
credentials cannot exceed the existing handle/session lifetime or a 60-second
handoff lifetime. The actor is refreshed by the session service and its provider
kind/configuration is rechecked under the owner write lock. Native enrollment
and removal also receive this provider configuration fence.

Tests use real TOTP arithmetic and actual SQLite writes. They cover the atomic
success state, two concurrent challenges with exactly one winner, invalid code,
audit uniqueness failure, wrong challenge/generation/target/handle, disabled or
changed provider, stale actor, expired challenge and revoked enrollment. Each
refusal preserves proof/challenge and credential state. This is service/storage
qualification, not an actual browser step-up qualification.

The browser challenge creation/CSRF and portal/application binding flow, live
application-policy/configuration epoch fencing, recovery/navigation and rollout
are still required before activation. The caller must validate both browser
bindings and the return target against live application policy; the storage
command does not independently decide application permissions. Structural
provider configuration equality is not a monotonic publication epoch or a
fingerprint of environment secret/CA contents. No runtime route is enabled by
this primitive, and the internally deployed image remains unchanged.

## Request assurance enforcement

Session verification now applies every matching canonical-path rule before
issuing identity. AAL 2 requires both the session and issued handle to have the
level and an actual TOTP/WebAuthn/recovery factor record. `max_age` measures that
factor's latest satisfaction time, not the primary authentication time. Missing,
expired or future factor timestamps and old level-1 handles cannot pass. AAL 1
freshness rules use primary authentication time. Nonmatching paths retain
ordinary authentication behavior; any configured rule still disables caching.

While browser challenge creation/completion remains unfinished, an unmet rule
returns a document 403 or API/session 401 `step_up_required`; no unsupported
redirect, handle clearing or incomplete challenge is issued. These denials must
be replaced with the bound browser step-up flow before claiming complete MFA.

Service API credentials remain AAL 0. After authentication, the shared HTTP/HOP1
pipeline checks the current application snapshot: a matching human assurance
rule or disabled/unknown application is refused without service identity headers.
A valid API key cannot bypass a human assurance rule or use a human session as
fallback after refusal. Pumgye independently enforces service permissions.
Tests cover canonical/uppercase prefixes, absent/number-only/OIDC-only evidence,
old/future OTP, old issued handles, fresh OTP with old primary authentication,
nonmatching paths, and HTTP/native service denial after snapshot changes.

The native admin listener maps assurance refusal to its existing
`aal_insufficient` response, metric and required audit event, rather than
misreporting a missing login. Prefix matching compares ASCII bytes without
allocating lowercase strings on each request; existing UTF-8 and segment
semantics are preserved. This is not a full-stack throughput qualification.

## Durable portal challenge binding

The native `bind_stepup` service now validates transaction/portal-cookie shape
and authorizes one owner write against a fresh native factor actor. The owner
selects the user's active TOTP enrollment and binds an unexpired `stepup`
transaction to the same live session, exact portal handle, portal-cookie digest,
client IP, credential generation, enrollment ID and enrollment revision.
Application binding must already be present. OAuth and reauthentication fields
must be absent. No seed, cookie or bearer value is written to this context.

For `stepup` only, `pending_identity` contains the native generation/enrollment
context; other transaction purposes retain their existing semantics. Repeated
preparation succeeds only for an identical live binding and does not add a
second binding audit event. A different browser cookie/handle/IP, changed
credential generation or active enrollment revision cannot replace it. Binding
and required audit/outbox insertions commit together. The final OTP elevation
transaction compares the portal-cookie digest and exact recorded context before
consuming either the challenge or counter; its new handoff IP must also match
the native actor's current request IP. Refusal leaves both proofs usable by the
correct browser until their normal expiry.

Owned SQLite/service tests cover initial binding, idempotent refresh, cookie and
handle transfer, IP changes, refreshed actors after generation changes,
enrollment revision changes, wrong purpose, expiry, missing application binding,
consumed challenges, malformed portal cookies, audit rollback and successful
retry. Final completion also rejects wrong cookie/context/IP without elevation
or counter/challenge consumption. These tests do not exercise an actual browser
step-up. The request engine still refuses unmet rules; browser challenge
creation, portal page/CSRF, validated target/policy epoch checks and operational
activation remain mandatory before enabling the workflow.

## Native browser OTP workflow

A configured TOTP keyring now enables `GET /stepup?txn=...` and `POST /stepup`.
A document request with an unmet AAL 2 rule starts a capped, same-session
challenge and keeps the existing handle; API requests remain 401 without a
challenge. Without a keyring, AAL 2 documents retain fail-closed refusal. AAL 1
primary-freshness requirements use provider reauthentication instead of looping
through OTP. If primary authentication is older than five minutes, native AAL 2
bootstrap reauthenticates before offering second-factor completion.

The portal requires HTTPS and the live owner handle, validates the target against
current application configuration, and binds the challenge through the owner
store. An unenrolled owner gets setup/continue links without a code form; enrollment
still does not elevate a session. The completion form has a distinct CSRF purpose
bound to transaction, portal cookie and handle, plus exact Origin checking,
unique fields, a six-digit code, bounded body and the existing IP admission budget.
Its temporary combined bearer binding is zeroized. Ordinary login/provider entry
points refuse a step-up transaction; refresh cannot send it through a weaker flow.

Native portal preparation and completion carry the current configuration generation.
The owner transaction compares it with persisted `meta.config_generation` under
the writer lock and records it in the challenge context. Publication/restart
configuration changes therefore invalidate completion before challenge/counter
consumption. The generic trusted service/storage primitives retain optional
unfenced generation for internal callers/tests; HTTP portal calls always provide
one. Target validation is repeated before completion. Native assurance issuance
is authentication evidence; Pumgye still owns service permissions.

A valid new OTP atomically consumes proof/challenge, elevates/rotates credentials
and mints the exact-target handoff. The portal installs the replacement cookie
and redirects through the existing application-host handoff redemption. Store
outages/corruption return unavailable rather than a credential rejection. No seed
or code enters a redirect or audit payload; responses retain no-store and CSP.

The owned OIDC/real-process HTTP fixture now covers unenrolled setup guidance,
encrypted enrollment, non-elevating confirmation, document step-up, actual OTP,
Origin/cross-purpose/anonymous/duplicate-query refusal, wrong ordinary login entry,
new handoff redemption, AAL 2 protected access, old-handle refusal and completion
replay. This uses the test browser client/cookie jar, not a Chromium/mobile-app
qualification. Owner tests cover configuration changes/mismatch/zero generation
without proof consumption. Recovery, cancel/removal UI, QR/mobile qualification,
account/distributed admission, key lifecycle, Hangang navigation and internal
MFA deployment still remain. Earlier notes about missing browser wiring describe
prior source stages; the deployed `owner-v5-d876909` image is unchanged.

## Browser redirect CSP qualification

An actual Chromium candidate test found that `form-action 'self'` blocked the
post-OTP cross-origin handoff even after the owner transaction succeeded. The
step-up service now returns only the current-configuration-validated target
origin; the GET form's existing per-page CSP helper adds exactly that origin.
No wildcard or request-selected destination is allowed. The HTTP fixture checks
the exact origin allowance. `tools/qualify_browser_totp.py` exercises the real
browser's form Origin, cookie updates, CSP redirect and handoff on an isolated
loopback candidate with a private owner-state copy and an owned first-factor
session fixture. It does not authenticate a real Google user or measure TLS
ingress behavior: CDP forwards the HTTPS browser origins to the candidate HTTP
listeners, while native mTLS is qualified separately.

## Internal runtime and Chromium evidence

The corrected static candidate now passes actual Chromium enrollment, browser
step-up/redirect/handoff and old-handle refusal. Its private state copy contains
an owned first-factor session fixture; this does not prove real Google login.
The proxy shim preserves separate Set-Cookie headers, browser Origin and fetch
metadata, and never follows the application's 302 on behalf of the browser.
The screenshot is captured before code entry and contains no setup seed.

The internally deployed image is now `0.0.2-native-mfa-791719a` at schema v5.
An optional `v1` TOTP keyring uses a newly generated private environment key.
Existing provider selection and service assurance rules are unchanged; no test
users/sessions were inserted into operational state. Before rollout, the image
booted a consistent owner-state copy and passed HTTP/pooled-mTLS HOP1 service
acceptance/guest/invalid-credential checks. After rollout, live service matrix
rights/denials/credential stripping, module menus, independent Pumgye matrix,
SSO entry/logout/origin isolation and native transport regressions passed.
Consistent owner/delegation databases and original image/configuration/secret
files are retained privately for rollback. Earlier deployed-image notes describe
prior runtime stages. Production-user MFA, recovery, account/distributed
admission, key retirement/rewrapping, navigation and full-stack performance are
still unqualified or unfinished; do not treat optional runtime activation as
completion of the authentication gateway or the full zero-trust backbone.

## External HTTPS transport primitive — 2026-10-14

`src/factor/external_transport.rs` now executes fixed, authenticated HTTPS factor
requests and validates the replies using the existing context parser. This is a
native library primitive, not an enabled portal/provider setting. Durable proof
consumption, owner elevation, runtime publication and Lua orchestration remain
required before external MFA can authenticate an operational user.

The typed configuration contains factor, nonzero configuration_revision, fixed
HTTPS url, verifier_key_env, timeout_ms (1–1000), allow_private_endpoints and an
optional absolute CA path. HTTP is refused even for opted-in private endpoints;
CA and hostname verification stay enabled. Environment proxies and redirects
are disabled. Public destinations use vetted DNS/address selection. The resolved
verifier key and custom CA bytes participate in the immutable binding, so reuse
must not preserve a connector across material changes at the same reference.

Each connector admits at most 64 concurrent exchanges without waiting. Its idle
pool retains at most 64 connections per origin for 30 seconds. The total deadline
covers TLS, request and response body; declared and streamed bodies exceeding
8 KiB are rejected before buffering the complete response. Factor response input
is bounded to 4096 bytes. No retry, cache or weaker-provider fallback exists.
The server-owned `started_at` denotes preparation of this verification exchange,
not the creation time of a browser challenge. The five-second evidence window
includes time since that preparation; the challenge's independent expiry also
applies. A wall-clock rollback observed during exchange refuses completion.

Only HTTP 200 with a context-bound typed JSON reply is a valid factor decision.
A valid `active:false` is healthy credential rejection. Bare 401/403, redirects,
wrong context, extra assurance claims, malformed responses, timeouts and cancelled
calls are verifier failures; three failures open the circuit for 30 seconds.
No secret, response body, proof or URL-bearing transport error is reported.

Owned TLS tests generate an isolated CA and server certificate with OpenSSL.
They exercise accepted/rejected evidence, actual connection reuse, wrong CA,
cross-user/assurance injection, malformed/content-type/status responses,
header and chunked body limits with a server holding the stream open, body and
exchange deadlines, capacity rejection, cancellation, circuit refusal/recovery,
clock rollback and resolved secret/CA binding changes. These tests do not prove
browser external MFA, durable replay fencing or distributed session elevation.

## Native external proof consumption and elevation — 2026-10-14

The HTTPS connector now returns a private, nonserializable, noncloneable
`VerifiedProof`, carrying the exact verified context and immutable authority.
Raw proof IDs are hashed before leaving the transport. A generic JSON parser
result cannot be passed to owner completion. The receipt has both wall expiry
and a monotonic deadline bounded by the exchange's five-second budget; owner
queueing and write time cannot extend it when the wall clock stops advancing.

`external_service::elevate_authorized` first binds the pending native transaction
to the live actor, portal cookie digest, initiating portal handle, credential
generation, configured factor/revision/binding and current configuration epoch.
Only then does it call the fixed verifier with owner-derived user/session/service
and a transaction digest instead of the browser's transaction bearer token.
The owner repeats these checks after the exchange, inside its write transaction.
It refuses disabled/changed authority, primary-provider or user changes, stale
actor/handle/generation, wrong service/target/browser binding and expired proof.
Expiry and clock rollback are checked again immediately before commit.

Schema v6 adds approved external factor authority records, an indexed factor to
session mapping, a permanent hashed proof ledger and a capacity counter/trigger.
Proof uniqueness is scoped to factor authority and its configuration revision,
including different users, sessions and challenges. One owner transaction consumes
the proof and challenge, appends a native `external` factor, sets AAL 2, advances
credential generation, revokes every old handle/outstanding code, issues a new
portal handle and exact-target elevated handoff, and writes required
`factor.external_consumed`/revocation/handoff events with outbox rows. Audit or
capacity failure rolls back the entire completion. Primary authentication time
is preserved. Only a native operator-approved independent second-factor verifier
may be published; an AAL 0 service API relay is not such an authority.

Publication retains at most 64 factor identifiers, including disable tombstones.
A revision or previously published global epoch cannot decrease; resolved secret/CA or verifier setting changes cannot
reuse the same revision. The identical authority may follow a newer global
configuration epoch without erasing its proof history. Revision/material changes
or disable atomically terminate sessions elevated by that factor and revoke their
handles/codes, using the factor/session index rather than scanning every session's
JSON. Existing native TOTP enrollment removal accepts recent native external MFA.

The proof ledger retains consumed hashes across owner reopen and ordinary session
cleanup. No automatic proof pruning exists. Its hard capacity is 1,000,000 rows;
full capacity denies new completion rather than forgetting replay history. Safe
archival/retirement and operational capacity telemetry remain required lifecycle
work. Startup precheck validates exact v6 constraints/guard and counter consistency
read-only. A v5 binary cannot open v6 state; rollback requires the consistent
pre-upgrade owner/delegation backup and matching configuration/keys. The internal
runtime remains schema v5; this source change has not migrated it.

Owned TLS-to-owner tests cover successful elevated handoff, previous credential
revocation, concurrent and cross-session proof reuse, owner reopen persistence,
factor disable, context/generation/browser/application errors, provider/user/
authority/configuration changes, wall/monotonic expiry, capacity and audit rollback.
Foundation tests refuse missing structures/guards and counter corruption. These
are native service and SQLite-owner tests, not actual browser external MFA or
proof of replay protection across independent follower databases. Root snapshot
publication, service-scoped factor choice/enrollment, browser UI/CSRF/rate limits,
process-wide admission, Lua orchestration and fleet qualification remain open.

## Immutable verifier registry

The native external_registry compiles at most 64 unique, validated factor configurations
before returning a new snapshot. Missing secrets or invalid CA/client configuration
refuse the complete candidate. Unchanged material reuses the same connector Arc,
preserving its pool and circuit; rotation replaces it. Removing a registry entry
does not itself disable owner authority: atomic owner reconciliation and root/portal
integration remain required before runtime activation.

## Atomic complete verifier publication

The registry can now publish its complete operator-approved desired set in one
owner transaction. A durable snapshot revision supplies compare-and-swap;
changed single-factor publication advances it too, preventing a stale batch
from overwriting an intervening disable or rotation. The current global
configuration epoch is required independently of this publication revision.
Activate the in-memory registry only after owner publication succeeds.

Missing previously enabled authorities become revision-advanced disable
tombstones and their elevated sessions/handles/codes are revoked using the
existing factor/session index. Already-disabled entries retain their revision
on repeated omission. Retained tombstones and proof history preserve anti-replay
and prevent lower-revision reactivation. All additions, removals, session
revocations, publication revision and required audit/outbox commit together;
late conflict, capacity/exhaustion or audit failure rolls them all back.

Owned TLS-to-owner tests cover concurrent removal, old proof retention, stale
batch rejection after a single-factor change, invalid global epoch, late
per-factor conflict and final audit rollback with a previously elevated session.
This native publication primitive does not enable root configuration, browser
factor selection or Lua. It does not prove distributed follower propagation.

## Startup registry activation — 2026-10-14

The typed `external_verifiers` root setting now connects compilation and atomic
owner publication to server startup. Missing material is refused before any
state directory is created. Successful publication precedes Services activation
and listener binding. An empty desired set reconciles existing authorities on
restart. `factor.registry_published` is a required event committing with its
snapshot; it is distinct from the application `config.loaded` event. There are
now 33 registered event kinds, 28 required and five diagnostic kinds.

Real-process qualification starts Hopae with an owned verifier reference,
checks its published authority/revision without making a remote call, removes
the config and restarts to verify the disable tombstone. Unit tests cover missing
material before state creation, duplicate references, caller authentication and
redacted validation. This supersedes historical missing-root-wiring notes;
external browser execution, factor enrollment/selection, Lua and fleet rollout
remain unqualified. Internal deployment remains the existing schema-v5 image.

Individual authority publication uses required `factor.authority_published`;
whole-registry publication uses `factor.registry_published`. Both commit with
owner state and are refused by standalone event append.

## Native external browser response path — 2026-10-14

A configured external registry now enables native document step-up alongside
TOTP. `/stepup?txn=...` validates the HTTPS live portal session/transaction before
showing approved factor identifiers and the optional TOTP method. Selecting an
external method visits `/stepup/external?txn=...&factor=...`, which binds that
factor to the owner challenge. The selection cannot switch an already bound
challenge to a different factor. TOTP remains selectable explicitly; no weaker
provider fallback is attempted after external failure.

The external form POST requires exactly transaction, factor, CSRF and response.
Its separate CSRF purpose is bound to transaction/portal-cookie/handle/factor,
with the same exact-Origin, HTTPS, request-body and shared process IP admission
controls as native password/TOTP paths. Responses are nonempty and at most
4096 bytes. Browser input cannot choose URLs, identities, role or AAL fields.
The form CSP allows only the current validated application origin for handoff.
Neither responses nor verifier credentials are logged or echoed.

The adapter verifies using owner-derived context, then mints fresh replacement
credentials through the shared TOTP/external issuance helper and commits the
opaque receipt atomically. Credential creation time must not be future or more
than five seconds old; handle activity and handoff creation times agree. This
avoids artificial failure when asynchronous verification crosses a wall-second
boundary while retaining actor, proof wall/monotonic and pre-commit fences.
Verifier requests now include server-owned `verification_started_at` milliseconds
in addition to challenge expiry so implementations can respect the short proof
window; the strict response schema is unchanged.

The owned OIDC/HTTPS runtime test exercises real first-factor login, chooser,
external form, Origin/CSRF and extra-field refusal before backend calls,
context-valid rejection, cross-user and assurance injection refusal, successful
AAL-2 handoff, protected request and previous-handle refusal. Timing tests cover
second boundaries and stale/future credential rejection. This uses an HTTP
browser client with real cookies and process boundaries, not Chromium or an
operational organization's MFA account. Actual browser/fleet/performance rollout,
service-specific factor eligibility, enrollment/recovery, account admission and
Lua remain required qualification and implementation work. Internal v5 is unchanged.
