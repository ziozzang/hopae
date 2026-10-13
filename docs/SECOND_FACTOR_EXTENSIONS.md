# Second-factor extensions

<!-- doc-rev: 4 -->

[Documentation](README.md) · [한국어](ko/SECOND_FACTOR_EXTENSIONS.md)

## Implementation status

Native TOTP enrollment and confirmation exist, including encrypted seeds,
owner authorization and durable counter fencing. The profile uses six digits,
SHA-1 and a 30-second period. Manual setup is available; QR provisioning,
recovery and browser sign-in step-up wiring remain unfinished. Enrollment does not
raise a session's assurance. Google/OIDC login is separate from an authenticator
application generating a TOTP code.

`src/factor/external.rs` validates an external factor response against a trusted
challenge context. It is a parsing boundary, not an enabled connector, a
signature verifier or a replay store. No external factor HTTP route or Lua
factor runtime is enabled by this module. Existing external service API verifier
relays in [Authentication gateway](AUTH_GATEWAY.md) continue to issue service
identity at AAL 0; they cannot count as human second-factor evidence.

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
